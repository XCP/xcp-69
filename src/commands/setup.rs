//! Setup command: NUMS vanity grind + tapscript + unsigned PSBTs
//!
//! This command implements Design A (NUMS + tapscript) for trustless vault operation:
//! 1. Generate P_script (tapscript signing key)
//! 2. Build 4-leaf tapscript tree (T0, T1, T2a, T2b)
//! 3. Grind NUMS vanity on tweaked output key Q
//! 4. Build unsigned PSBT templates for all parent transactions
//! 5. Output bundle (signing occurs later in finalize-parents after funding confirms)

use anyhow::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bitcoin::{address::{Address, NetworkUnchecked}, hashes::Hash, Network, OutPoint, XOnlyPublicKey};
use hex::ToHex;
use reqwest::blocking::Client;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::bitcoin_utils::psbt::{build_parent_psbt, build_funding_psbt, parse_utxos};
use crate::bitcoin_utils::*;
use crate::counterparty::*;
use crate::types::*;

#[derive(clap::Parser, Debug)]
pub struct SetupOpts {
    // Networks & endpoints
    #[arg(long, default_value="mainnet")] pub network: String,
    #[arg(long, default_value="https://api.counterparty.io:4000/v2")] pub cp_base: String,

    // Asset & lifecycle
    #[arg(long)] pub asset: String,
    #[arg(long)] pub mend: u32,
    #[arg(long, default_value_t=20)] pub gap: u32,
    #[arg(long, default_value_t=8064)] pub expiration: u32,

    // Fees & anchors (updated defaults for NUMS+tapscript)
    #[arg(long, default_value_t=2500)] pub anchor_sats: u64,  // Increased for CPFP headroom
    #[arg(long, default_value_t=150)] pub base_fee_sats: u64,  // 1 sat/vbyte for ~150 vbyte tx

    // Platform fee destination (XCP address string as Counterparty expects)
    #[arg(long)] pub platform_xcp_dest: String,

    // Delay (in blocks) after T2b before sweeps can execute
    #[arg(long, default_value_t=100)] pub sweep_delay: u32,

    // Vanity grind
    #[arg(long, default_value="suffix")] pub mode: String, // prefix|suffix
    #[arg(long)] pub pattern: String,
    #[arg(long, default_value_t=std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4))] pub threads: usize,
    #[arg(long, default_value_t=0u64)] pub max_attempts: u64,

    // Funding inputs (your fee wallet) to fan out N exact-value UTXOs to the vault
    // Format: "txid:vout:value_sat,txid:vout:value_sat,..."
    #[arg(long)] pub funding_utxos: String,
    #[arg(long)] pub funding_change: String,

    // Optional: descriptor or address type hint for funding inputs (for witness_utxo)
    // Supported: "p2wpkh", "p2tr", "p2sh-p2wpkh". If omitted, defaults to p2wpkh.
    #[arg(long, default_value="p2wpkh")] pub funding_type: String,

    // Optional: export P_script secret to file (for signing ceremony)
    #[arg(long)] pub export_secret: Option<String>,

    // Output bundle path
    #[arg(long, default_value="bundle.json")] pub out: String,
}

pub fn run_setup(o: SetupOpts) -> Result<()> {
    let network = match o.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        _ => bail!("--network must be mainnet|testnet|signet"),
    };
    ensure!(o.expiration >= 8064, "--expiration must be ≥ 8064");

    // Phase gates
    let t0 = o.mend.checked_add(1).context("t0 overflow")?;
    let t1 = o.mend.checked_add(o.gap).context("t1 overflow")?;
    let t2a = t1.checked_add(8064 + o.gap).context("t2a overflow")?;
    let t2b = t2a.checked_add(o.gap).context("t2b overflow")?;

    eprintln!("=== XCP-69 NUMS Vault Setup ===\n");
    eprintln!("Phase schedule:");
    eprintln!("  T0  (fairminter): {}", t0);
    eprintln!("  T1  (orders): {}", t1);
    eprintln!("  T2a (fees + destroys): {}", t2a);
    eprintln!("  T2b (dividends): {}", t2b);
    eprintln!();

    // ────────────────────────────────────────────────────────────────────────────
    // STEP 1: Generate P_script (tapscript signing key)
    // ────────────────────────────────────────────────────────────────────────────
    eprintln!("[1/7] Generating tapscript signing key (P_script)...");
    let secp = Secp256k1::new();
    let mut p_script_bytes = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut p_script_bytes);
    let p_script = SecretKey::from_slice(&p_script_bytes)?;
    let p_script_pk = PublicKey::from_secret_key(&secp, &p_script);
    let p_script_xonly = p_script_pk.x_only_public_key().0;

    eprintln!("  P_script pubkey: {}", p_script_xonly.serialize().encode_hex::<String>());
    eprintln!("  ⚠️  Keep this key secure! Needed for signing ceremony.");

    if let Some(secret_path) = &o.export_secret {
        std::fs::write(secret_path, p_script.secret_bytes().encode_hex::<String>())?;
        eprintln!("  ✓ Secret exported to: {}", secret_path);
    } else {
        eprintln!("  Secret (one-time display): {}", p_script.secret_bytes().encode_hex::<String>());
        eprintln!("  (Use --export-secret to save to file)");
    }
    eprintln!();

    // ────────────────────────────────────────────────────────────────────────────
    // STEP 2: Build tapscript tree (4 CLTV leaves)
    // ────────────────────────────────────────────────────────────────────────────
    eprintln!("[2/7] Building tapscript tree (4 CLTV leaves)...");
    let tapscript_tree = TapscriptTree::new(t0, t1, t2a, t2b, &p_script_xonly)?;
    eprintln!("  Merkle root: {}", hex::encode(tapscript_tree.merkle_root.as_byte_array()));
    eprintln!("  ✓ Tree built: T0 leaf, T1 leaf, T2a leaf, T2b leaf");
    eprintln!();

    // ────────────────────────────────────────────────────────────────────────────
    // STEP 3: NUMS vanity grind on tweaked output key Q
    // ────────────────────────────────────────────────────────────────────────────
    eprintln!("[3/7] Grinding NUMS vanity address (pattern: '{}')...", o.pattern);
    eprintln!("  This grinds on OUTPUT KEY Q = K_int + tweak*G");
    eprintln!("  NUMS internal key ensures no keypath spend possible");

    let pattern = o.pattern.to_ascii_lowercase();
    ensure!(
        pattern.chars().all(|c| BECH32_ALPH.contains(c)),
        "pattern has non-bech32 chars"
    );

    let nums_proof = grind_nums_vanity(
        network,
        &o.mode,
        &pattern,
        tapscript_tree.merkle_root,
        o.threads,
        o.max_attempts,
    )?;

    eprintln!("  ✓ Vault address: {}", nums_proof.address);
    eprintln!();

    // Parse addresses
    let vault_addr: Address = nums_proof
        .address
        .parse::<Address<NetworkUnchecked>>()?
        .require_network(network)?;

    // Parse keys (not needed for building unsigned PSBTs, but kept for potential future use)
    let _q_xonly = XOnlyPublicKey::from_slice(&hex::decode(&nums_proof.q_xonly)?)?;
    let _k_int_xonly = XOnlyPublicKey::from_slice(&hex::decode(&nums_proof.k_int_xonly)?)?;

    // ────────────────────────────────────────────────────────────────────────────
    // STEP 4: Derive anchor key from P_script
    // ────────────────────────────────────────────────────────────────────────────
    eprintln!("[4/7] Deriving CPFP anchor key...");
    let mut anchor_derive = Vec::new();
    anchor_derive.extend_from_slice(&p_script.secret_bytes());
    anchor_derive.extend_from_slice(b"ANCHOR");
    let anchor_sk_bytes = Sha256::digest(&anchor_derive);
    let anchor_sk = SecretKey::from_slice(&anchor_sk_bytes)?;
    let anchor_pk = PublicKey::from_secret_key(&secp, &anchor_sk);
    let anchor_addr = Address::p2tr(&secp, anchor_pk.x_only_public_key().0, None, network);
    let anchor_spk = anchor_addr.script_pubkey();

    eprintln!("  Anchor address: {}", anchor_addr);
    eprintln!("  (Derived from P_script, can be used for CPFP)");
    eprintln!();

    // ────────────────────────────────────────────────────────────────────────────
    // STEP 5: Build funding PSBT
    // ────────────────────────────────────────────────────────────────────────────
    eprintln!("[5/7] Building funding transaction...");
    let need_outputs = 1 + // fairminter
        1 + ORDER_REMAINDER_LADDER_XCP.len() + // orders
        FEE_RUNGS_XCP.len() +                  // fees
        BURN_RUNGS_TOK.len() +                 // destroys
        DIV_QPU_RUNGS_SATS.len() +             // dividends (per-unit rungs)
        1; // sweeps (single Counterparty balance-only sweep)
    let each_value = o.anchor_sats + o.base_fee_sats;

    eprintln!("  Creating {} vault UTXOs @ {} sats each", need_outputs, each_value);
    eprintln!("  Total needed: {} sats", need_outputs as u64 * each_value);

    let funding_change: Address = o
        .funding_change
        .parse::<Address<NetworkUnchecked>>()?
        .require_network(network)?;
    let funding_inputs = parse_utxos(&o.funding_utxos, funding_change.script_pubkey())?;
    let funding_psbt = build_funding_psbt(
        network,
        &funding_inputs,
        &funding_change,
        &vault_addr,
        need_outputs,
        each_value,
        &o.funding_type,
    )?;
    let funding_b64 = B64.encode(funding_psbt.serialize());
    eprintln!("  ✓ Funding PSBT created");
    eprintln!();

    // ────────────────────────────────────────────────────────────────────────────
    // STEP 6: Compose CP blobs & build unsigned parent PSBT templates
    // ────────────────────────────────────────────────────────────────────────────
    eprintln!("[6/7] Building unsigned parent PSBT templates...");

    let http = Client::new();
    let mut utxo_index = 0u32;
    let funding_placeholder_txid = "0000000000000000000000000000000000000000000000000000000000000000";

    let mut next_utxo = |value: u64| -> (OutPoint, u64) {
        let op = OutPoint {
            txid: funding_placeholder_txid.parse().expect("Invalid placeholder txid"),
            vout: utxo_index,
        };
        utxo_index += 1;
        (op, value)
    };

    // Fairminter @ T0 (ends at t1-1 so orders can start at T1)
    eprintln!("  Building fairminter...");
    let fm_data = cp_compose_fairminter(&http, &o.cp_base, &nums_proof.address, &o.asset, t0, t1 - 1)?;
    let (fm_utxo, fm_val) = next_utxo(each_value);

    // Build unsigned PSBT (no signing here)
    let fm_psbt = build_parent_psbt(
        fm_utxo,
        fm_val,
        fm_data.clone(),
        &anchor_spk,
        o.anchor_sats,
        o.base_fee_sats,
        t0,
    )?;
    let fm_psbt_b64 = B64.encode(fm_psbt.serialize());

    let fairminter = PsbtEntry {
        name: "fairminter".into(),
        phase: "T0".into(),
        lock_height: t0,
        purpose: "fairminter".into(),
        opret_hex: fm_data.encode_hex::<String>(),
        psbt_b64: fm_psbt_b64,
        utxo: format!("{}:{}", funding_placeholder_txid, 0),
        value_sat: fm_val,
    };

    // Orders @ T1
    eprintln!("  Building orders...");
    let mut orders = vec![];

    // Fixed 6900 order
    let data = cp_compose_order_asset(
        &http,
        &o.cp_base,
        &nums_proof.address,
        ORDER_FIXED_SC_XCP,
        &o.asset,
        ORDER_FIXED_SC_XCP * 10_000,
        o.expiration,
    )?;
    let (u, v) = next_utxo(each_value);
    let psbt = build_parent_psbt(u, v, data.clone(), &anchor_spk, o.anchor_sats, o.base_fee_sats, t1)?;

    orders.push(PsbtEntry {
        name: "order_6900".into(),
        phase: "T1".into(),
        lock_height: t1,
        purpose: "order".into(),
        opret_hex: data.encode_hex::<String>(),
        psbt_b64: B64.encode(psbt.serialize()),
        utxo: format!("{}:{}", funding_placeholder_txid, 1),
        value_sat: v,
    });

    // Remainder ladder orders
    for (i, &r) in ORDER_REMAINDER_LADDER_XCP.iter().enumerate() {
        let give = r;
        let get = r * 10_000;
        let data = cp_compose_order_asset(&http, &o.cp_base, &nums_proof.address, give, &o.asset, get, o.expiration)?;
        let (u, v) = next_utxo(each_value);
        let psbt = build_parent_psbt(u, v, data.clone(), &anchor_spk, o.anchor_sats, o.base_fee_sats, t1)?;

        orders.push(PsbtEntry {
            name: format!("order_rem_{}xcp", r),
            phase: "T1".into(),
            lock_height: t1,
            purpose: "order".into(),
            opret_hex: data.encode_hex::<String>(),
            psbt_b64: B64.encode(psbt.serialize()),
            utxo: format!("{}:{}", funding_placeholder_txid, 2 + i as u32),
            value_sat: v,
        });
    }

    // Fees @ T2a
    eprintln!("  Building platform fee sends...");
    let mut fees = vec![];
    for (i, &fx) in FEE_RUNGS_XCP.iter().enumerate() {
        let data = cp_compose_send_xcp(&http, &o.cp_base, &nums_proof.address, &o.platform_xcp_dest, fx)?;
        let (u, v) = next_utxo(each_value);
        let psbt = build_parent_psbt(u, v, data.clone(), &anchor_spk, o.anchor_sats, o.base_fee_sats, t2a)?;

        fees.push(PsbtEntry {
            name: format!("fee_{}xcp", fx),
            phase: "T2a".into(),
            lock_height: t2a,
            purpose: "fee_send".into(),
            opret_hex: data.encode_hex::<String>(),
            psbt_b64: B64.encode(psbt.serialize()),
            utxo: format!("{}:{}", funding_placeholder_txid, (2 + ORDER_REMAINDER_LADDER_XCP.len()) as u32 + i as u32),
            value_sat: v,
        });
    }

    // Destroys @ T2a
    eprintln!("  Building token destroys...");
    let mut destroys = vec![];
    for (i, &q) in BURN_RUNGS_TOK.iter().enumerate() {
        let data = cp_compose_destroy(&http, &o.cp_base, &nums_proof.address, &o.asset, q, "burn")?;
        let (u, v) = next_utxo(each_value);
        let psbt = build_parent_psbt(u, v, data.clone(), &anchor_spk, o.anchor_sats, o.base_fee_sats, t2a)?;

        destroys.push(PsbtEntry {
            name: format!("burn_{}tok", q),
            phase: "T2a".into(),
            lock_height: t2a,
            purpose: "destroy_token".into(),
            opret_hex: data.encode_hex::<String>(),
            psbt_b64: B64.encode(psbt.serialize()),
            utxo: format!("{}:{}", funding_placeholder_txid, (2 + ORDER_REMAINDER_LADDER_XCP.len() + FEE_RUNGS_XCP.len()) as u32 + i as u32),
            value_sat: v,
        });
    }

    // Dividends @ T2b (per-unit 2^n rungs; NO supply assumptions here)
    eprintln!("  Building dividends (per-unit rungs, 2^n)...");
    let mut dividends = vec![];

    eprintln!("    Per-unit ladder: {} rungs (max 0.0001 XCP per TOKEN)", DIV_QPU_RUNGS_SATS.len());
    eprintln!("    Greedy selection at broadcast time handles unknown issuer fee");

    for (i, &qpu_sats) in DIV_QPU_RUNGS_SATS.iter().enumerate() {
        // Pay XCP per TOKEN unit, quantity_per_unit = qpu_sats (atomic)
        let div_data = cp_compose_dividend(&http, &o.cp_base, &nums_proof.address, &o.asset, qpu_sats)?;
        let (u, v) = next_utxo(each_value);
        let psbt = build_parent_psbt(u, v, div_data.clone(), &anchor_spk, o.anchor_sats, o.base_fee_sats, t2b)?;

        dividends.push(PsbtEntry {
            name: format!("div_qpu_{}sats", qpu_sats),
            phase: "T2b".into(),
            lock_height: t2b,
            purpose: "dividend".into(),
            opret_hex: div_data.encode_hex::<String>(),
            psbt_b64: B64.encode(psbt.serialize()),
            utxo: format!("{}:{}", funding_placeholder_txid, (2 + ORDER_REMAINDER_LADDER_XCP.len() + FEE_RUNGS_XCP.len() + BURN_RUNGS_TOK.len()) as u32 + i as u32),
            value_sat: v,
        });
    }

    // Sweeps @ (T2b + sweep_delay): single Counterparty balance-only sweep
    eprintln!("  Building post-dividend sweep (Counterparty balance-only sweep, delay {} blocks)...", o.sweep_delay);
    ensure!(o.sweep_delay >= 1, "--sweep-delay must be ≥ 1");

    let sweep_lock = t2b.checked_add(o.sweep_delay).context("t2b + sweep_delay overflow")?;

    // Compose Counterparty sweep: FLAG_BALANCES (1), memo "00"
    let sweep_data = cp_compose_sweep(
        &http,
        &o.cp_base,
        &nums_proof.address,
        &o.platform_xcp_dest,
        1,      // FLAG_BALANCES
        "00",   // tiny memo in hex
    )?;

    // Consume one placeholder vault UTXO for the sweep parent
    let (u, v) = next_utxo(each_value);
    let sweep_psbt = build_parent_psbt(
        u,
        v,
        sweep_data.clone(),
        &anchor_spk,
        o.anchor_sats,
        o.base_fee_sats,
        sweep_lock,
    )?;

    // A single sweep entry
    let sweeps = vec![
        PsbtEntry {
            name: "sweep_balances".into(),
            phase: "T2b".into(),       // same leaf as dividends, later lock for delay
            lock_height: sweep_lock,
            purpose: "sweep_balances".into(),
            opret_hex: sweep_data.encode_hex::<String>(),
            psbt_b64: B64.encode(sweep_psbt.serialize()),
            utxo: format!("{}:{}", funding_placeholder_txid,
                (2 + ORDER_REMAINDER_LADDER_XCP.len() + FEE_RUNGS_XCP.len() + BURN_RUNGS_TOK.len() + DIV_QPU_RUNGS_SATS.len()) as u32),
            value_sat: v,
        }
    ];

    eprintln!("  Sweep locked until height {} (T2b {} + delay {})", sweep_lock, t2b, o.sweep_delay);

    let total_entries = 1 + orders.len() + fees.len() + destroys.len() + dividends.len() + sweeps.len();
    eprintln!("  ✓ Built {} unsigned PSBT templates", total_entries);

    // Sanity check: ensure we consumed exactly the right number of placeholder vouts
    ensure!(
        utxo_index as usize == need_outputs,
        "Placeholder vout count mismatch: consumed {} but expected {}",
        utxo_index,
        need_outputs
    );
    eprintln!();

    // ────────────────────────────────────────────────────────────────────────────
    // STEP 7: Emit bundle (parent_txs_hex and cpfp_txs_hex will be filled by finalize-parents)
    // ────────────────────────────────────────────────────────────────────────────
    eprintln!("[7/7] Writing bundle...");
    eprintln!("  Note: Signing will occur in finalize-parents command after funding confirms");

    let bundle = Bundle {
        network: o.network,
        nums_proof,
        tapscript_pubkey: p_script_xonly.serialize().encode_hex::<String>(),
        merkle_root: hex::encode(tapscript_tree.merkle_root.to_byte_array()),
        anchor_address: anchor_addr.to_string(),
        t0,
        t1,
        t2a,
        t2b,
        expiration_blocks: o.expiration,
        anchor_sats: o.anchor_sats,
        base_fee_sats: o.base_fee_sats,
        asset: o.asset,
        platform_xcp_dest: o.platform_xcp_dest.clone(),
        fairminter,
        orders,
        fees,
        destroys,
        dividends,
        sweeps,
        parent_txs_hex: vec![],        // Will be filled by finalize-parents
        cpfp_txs_hex: vec![],          // Will be filled by finalize-parents
        commitment_hash: String::new(), // Will be computed by finalize-parents
        funding_psbt_b64: funding_b64,
        funding_output_value: each_value,
        funding_outputs: need_outputs,
        funding_change_addr: o.funding_change,
    };

    std::fs::write(&o.out, serde_json::to_vec_pretty(&bundle)?)?;
    eprintln!("  ✓ Wrote {}", &o.out);
    eprintln!();
    eprintln!("=== Setup Complete ===");
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  1. Sign and broadcast funding transaction");
    eprintln!("  2. Run: finalize-parents --bundle {} --funding-txid <TXID> --p-script-file <KEY_FILE>", o.out);
    eprintln!("  3. Verify bundle and broadcast parent txs at appropriate heights");
    eprintln!();
    eprintln!("Security notes:");
    eprintln!("  • Vault has NO keypath spend (NUMS internal key)");
    eprintln!("  • All spends via CLTV-locked tapscript leaves");
    eprintln!("  • Signing occurs AFTER funding confirms (no pre-signed txs yet)");
    eprintln!("  • Community can verify finalized bundle with verify-bundle command");

    Ok(())
}
