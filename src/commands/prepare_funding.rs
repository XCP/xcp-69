//! Prepare funding command: scan fee wallet and build funding PSBT
use anyhow::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bitcoin::{address::{Address, NetworkUnchecked}, Network, OutPoint};
use reqwest::blocking::Client;
use secp256k1::{PublicKey, Secp256k1};

use crate::bitcoin_utils::*;
use crate::types::*;

#[derive(clap::Parser, Debug)]
pub struct PrepareFundingOpts {
    #[arg(long)] pub bundle: String,
    #[arg(long)] pub fee_key: String,
    #[arg(long)] pub rpc_url: Option<String>,
    #[arg(long)] pub utxos: Option<String>,
    #[arg(long, default_value="mainnet")] pub network: String,
    #[arg(long, default_value="bundle_with_funding.json")] pub out: String,
}

pub fn run_prepare_funding(o: PrepareFundingOpts) -> Result<()> {
    let json = std::fs::read_to_string(&o.bundle)?;
    let mut bundle: Bundle = serde_json::from_str(&json)?;

    let network = match o.network.as_str(){
        "mainnet"=>Network::Bitcoin,
        "testnet"=>Network::Testnet,
        "signet" =>Network::Signet,
        _=>bail!("--network must be mainnet|testnet|signet"),
    };

    ensure!(bundle.network == o.network, "Bundle network mismatch: bundle has {}, you specified {}", bundle.network, o.network);

    let secp = Secp256k1::new();
    let fee_sk = parse_private_key(&o.fee_key, network)?;
    let fee_pk = PublicKey::from_secret_key(&secp, &fee_sk);
    let fee_addr = derive_address_from_pubkey(&fee_pk, network)?;

    eprintln!("Fee wallet address: {}", fee_addr);

    let utxos = if let Some(utxo_csv) = &o.utxos {
        eprintln!("Using manually specified UTXOs");
        parse_utxos(utxo_csv, fee_addr.script_pubkey())?
    } else if let Some(rpc_url) = &o.rpc_url {
        eprintln!("Scanning UTXOs via Bitcoin Core RPC...");
        scan_utxos_from_rpc(rpc_url, &fee_addr)?
    } else {
        bail!("Must provide either --rpc-url for automatic UTXO scanning or --utxos for manual specification");
    };

    ensure!(!utxos.is_empty(), "No UTXOs found for fee wallet");
    eprintln!("Found {} UTXO(s)", utxos.len());

    let total_input: u64 = utxos.iter().map(|u| u.value).sum();
    eprintln!("Total input: {} sats ({:.8} BTC)", total_input, total_input as f64 / 1e8);

    let need_outputs = bundle.funding_outputs;
    let each_value = bundle.funding_output_value;
    let total_out = (need_outputs as u64) * each_value;
    let fee_budget = 3_000;

    ensure!(total_input >= total_out + fee_budget,
        "Insufficient funds: need {} sats (outputs) + {} sats (fee) = {} sats, have {} sats",
        total_out, fee_budget, total_out + fee_budget, total_input);

    let vault_addr: Address = bundle.nums_proof.address.parse::<Address<NetworkUnchecked>>()?.require_network(network)?;

    let funding_type = detect_address_type(&fee_addr);
    eprintln!("Detected address type: {}", funding_type);

    let funding_psbt = build_funding_psbt(
        network,
        &utxos,
        &fee_addr,
        &vault_addr,
        need_outputs,
        each_value,
        &funding_type
    )?;

    bundle.funding_psbt_b64 = B64.encode(funding_psbt.serialize());
    bundle.funding_change_addr = fee_addr.to_string();

    std::fs::write(&o.out, serde_json::to_vec_pretty(&bundle)?)?;

    eprintln!("\nFunding PSBT created successfully!");
    eprintln!("  Inputs: {} UTXO(s) totaling {} sats", utxos.len(), total_input);
    eprintln!("  Outputs: {} vault UTXOs @ {} sats each", need_outputs, each_value);
    eprintln!("  Change: {} sats back to {}", total_input - total_out - fee_budget, fee_addr);
    eprintln!("\nNext steps:");
    eprintln!("  1. Extract and sign funding PSBT with your wallet");
    eprintln!("  2. Broadcast the funding transaction");
    eprintln!("  3. Run: patch-funding-txid --bundle {} --funding-txid <TXID>", o.out);
    eprintln!("\nWrote {}", o.out);

    Ok(())
}

fn scan_utxos_from_rpc(rpc_url: &str, addr: &Address) -> Result<Vec<InUtxo>> {
    #[derive(serde::Deserialize)]
    struct RpcResponse {
        result: Option<Vec<RpcUtxo>>,
        error: Option<RpcError>,
    }

    #[derive(serde::Deserialize)]
    struct RpcUtxo {
        txid: String,
        vout: u32,
        amount: f64,
        confirmations: u32,
    }

    #[derive(serde::Deserialize)]
    struct RpcError {
        message: String,
    }

    let client = Client::new();

    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "xcp69_setup",
        "method": "listunspent",
        "params": [1, 9999999, [addr.to_string()]]
    });

    let resp: RpcResponse = client
        .post(rpc_url)
        .json(&body)
        .send()?
        .error_for_status()?
        .json()?;

    if let Some(err) = resp.error {
        bail!("RPC error: {}", err.message);
    }

    let rpc_utxos = resp.result.ok_or_else(|| anyhow!("No result from RPC"))?;

    let mut utxos = Vec::new();
    for u in rpc_utxos {
        ensure!(u.confirmations >= 1, "UTXO {}:{} has 0 confirmations, need at least 1", u.txid, u.vout);

        utxos.push(InUtxo {
            outpoint: OutPoint {
                txid: u.txid.parse()?,
                vout: u.vout,
            },
            value: (u.amount * 1e8) as u64,
            script_pubkey: addr.script_pubkey(),
        });
    }

    Ok(utxos)
}