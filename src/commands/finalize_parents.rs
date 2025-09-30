//! Finalize parent transactions after funding confirms
//!
//! This command takes a bundle with placeholder txids and:
//! 1. Replaces placeholder with real funding txid
//! 2. Re-computes sighash for each parent with correct prevout
//! 3. Re-signs with P_script
//! 4. Finalizes PSBTs → extracts raw tx hex
//! 5. Rebuilds CPFP children with real parent txids
//! 6. Recomputes commitment hash
//! 7. Writes finalized bundle

use anyhow::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bitcoin::{
    address::Address,
    consensus::encode::serialize,
    hashes::Hash,
    psbt::Psbt,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::LeafVersion,
    Amount, Network, Transaction, TxOut, Witness, XOnlyPublicKey,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::bitcoin_utils::psbt::{build_cpfp_child, compute_commitment_hash};
use crate::bitcoin_utils::tapscript::{TapLeafPhase, TapscriptTree};
use crate::types::{Bundle, PsbtEntry, XCP_DEC, TOK_DEC, DIV_QPU_RUNGS_SATS, DIV_ISSUER_FEE_PER_ADDR_SATS};

/// Convert XCP (whole units) to sats (atomic)
fn xcp_to_sats(xcp: f64) -> u64 {
    (xcp * XCP_DEC as f64).floor() as u64
}

#[derive(clap::Parser, Debug)]
pub struct FinalizeOpts {
    /// Path to bundle JSON with placeholder txids
    #[arg(long)]
    pub bundle: String,

    /// Real funding transaction ID (hex)
    #[arg(long)]
    pub funding_txid: String,

    /// P_script secret key (hex) for signing
    #[arg(long)]
    pub p_script_hex: Option<String>,

    /// Path to file containing P_script secret key (hex)
    #[arg(long)]
    pub p_script_file: Option<String>,

    /// Output path for finalized bundle
    #[arg(long, default_value = "finalized_bundle.json")]
    pub out: String,

    /// Safety margin to reserve for dividend issuer-fee (unknown holder count), in XCP
    #[arg(long, default_value_t = 10.0)]
    pub dividend_fee_margin_xcp: f64,

    /// Maximum outstanding supply (whole TOKEN units) for planning per-unit dividend cost
    #[arg(long, default_value_t = 100_000_000u64)]
    pub max_outstanding_supply: u64,

    /// Estimated number of addresses that will receive any dividend (issuer-fee estimate)
    #[arg(long)]
    pub est_dividend_holders: Option<u64>,

    /// Upper bound on how many dividend rungs you might actually broadcast at T2b
    #[arg(long)]
    pub max_dividends_to_broadcast: Option<usize>,

    /// Extra headroom (in XCP) on top of (issuer-fee-estimate + margin)
    #[arg(long, default_value_t = 0.0)]
    pub extra_dividend_headroom_xcp: f64,
}

pub fn run_finalize_parents(o: FinalizeOpts) -> Result<()> {
    eprintln!("=== Finalize Parent Transactions ===\n");

    // Load P_script
    let p_script_hex = if let Some(hex) = o.p_script_hex {
        hex
    } else if let Some(path) = o.p_script_file {
        std::fs::read_to_string(&path)?.trim().to_string()
    } else {
        bail!("Must provide either --p-script-hex or --p-script-file");
    };

    let p_script = SecretKey::from_slice(&hex::decode(&p_script_hex)?)?;
    eprintln!("✓ Loaded P_script");

    // Load bundle
    let json = std::fs::read_to_string(&o.bundle)?;
    let mut bundle: Bundle = serde_json::from_str(&json)?;
    eprintln!("✓ Loaded bundle: {}", o.bundle);

    let funding_txid: bitcoin::Txid = o.funding_txid.parse()?;
    let placeholder_txid: bitcoin::Txid =
        "0000000000000000000000000000000000000000000000000000000000000000".parse()?;
    eprintln!("✓ Funding txid: {}\n", funding_txid);

    // Parse network and keys
    let network = match bundle.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        _ => bail!("Unknown network: {}", bundle.network),
    };

    let secp = Secp256k1::new();
    let p_script_pk = secp256k1::PublicKey::from_secret_key(&secp, &p_script);
    let p_script_xonly = p_script_pk.x_only_public_key().0;

    // Verify P_script matches bundle
    let bundle_p_script = XOnlyPublicKey::from_slice(&hex::decode(&bundle.tapscript_pubkey)?)?;
    ensure!(
        p_script_xonly.serialize() == bundle_p_script.serialize(),
        "P_script does not match bundle tapscript_pubkey"
    );
    eprintln!("✓ P_script matches bundle\n");

    // Parse vault address and keys
    let vault_addr: Address = bundle
        .nums_proof
        .address
        .parse::<Address<_>>()?
        .require_network(network)?;
    let q_xonly = XOnlyPublicKey::from_slice(&hex::decode(&bundle.nums_proof.q_xonly)?)?;
    let k_int_xonly = XOnlyPublicKey::from_slice(&hex::decode(&bundle.nums_proof.k_int_xonly)?)?;

    // Rebuild tapscript tree
    eprintln!("Rebuilding tapscript tree...");
    let tapscript_tree = TapscriptTree::new(
        bundle.t0,
        bundle.t1,
        bundle.t2a,
        bundle.t2b,
        &bundle_p_script,
    )?;
    eprintln!("✓ Tapscript tree rebuilt\n");

    // Derive anchor key
    let mut anchor_derive = Vec::new();
    anchor_derive.extend_from_slice(&p_script.secret_bytes());
    anchor_derive.extend_from_slice(b"ANCHOR");
    let anchor_sk_bytes = Sha256::digest(&anchor_derive);
    let anchor_sk = SecretKey::from_slice(&anchor_sk_bytes)?;
    let anchor_pk = secp256k1::PublicKey::from_secret_key(&secp, &anchor_sk);
    let anchor_addr = Address::p2tr(&secp, anchor_pk.x_only_public_key().0, None, network);

    // Parse funding change address
    let funding_change: Address = bundle
        .funding_change_addr
        .parse::<Address<_>>()?
        .require_network(network)?;

    eprintln!("Finalizing {} parent transactions...\n", 1 + bundle.orders.len() + bundle.fees.len() + bundle.destroys.len() + bundle.dividends.len());

    let mut parent_txs_hex = Vec::new();
    let mut cpfp_txs_hex = Vec::new();

    // Process fairminter
    eprint!("  [1] Fairminter... ");
    let (fm_tx, fm_txid) = finalize_parent_entry(
        &bundle.fairminter,
        placeholder_txid,
        funding_txid,
        &vault_addr,
        &q_xonly,
        &k_int_xonly,
        &tapscript_tree,
        TapLeafPhase::T0,
        &p_script,
        &secp,
    )?;
    parent_txs_hex.push(hex::encode(serialize(&fm_tx)));

    // Build CPFP
    let fm_cpfp = build_cpfp_child(
        fm_txid,
        1,
        bundle.anchor_sats,
        &anchor_sk,
        &anchor_addr,
        &funding_change,
        1000,
    )?;
    cpfp_txs_hex.push(hex::encode(serialize(&fm_cpfp)));
    eprintln!("✓");

    // Process orders
    for (i, entry) in bundle.orders.iter().enumerate() {
        eprint!("  [{}] {}... ", i + 2, entry.name);
        let (tx, txid) = finalize_parent_entry(
            entry,
            placeholder_txid,
            funding_txid,
            &vault_addr,
            &q_xonly,
            &k_int_xonly,
            &tapscript_tree,
            TapLeafPhase::T1,
            &p_script,
            &secp,
        )?;
        parent_txs_hex.push(hex::encode(serialize(&tx)));

        let cpfp = build_cpfp_child(
            txid,
            1,
            bundle.anchor_sats,
            &anchor_sk,
            &anchor_addr,
            &funding_change,
            1000,
        )?;
        cpfp_txs_hex.push(hex::encode(serialize(&cpfp)));
        eprintln!("✓");
    }

    // Process fees
    for (i, entry) in bundle.fees.iter().enumerate() {
        eprint!("  [{}] {}... ", i + 2 + bundle.orders.len(), entry.name);
        let (tx, txid) = finalize_parent_entry(
            entry,
            placeholder_txid,
            funding_txid,
            &vault_addr,
            &q_xonly,
            &k_int_xonly,
            &tapscript_tree,
            TapLeafPhase::T2a,
            &p_script,
            &secp,
        )?;
        parent_txs_hex.push(hex::encode(serialize(&tx)));

        let cpfp = build_cpfp_child(
            txid,
            1,
            bundle.anchor_sats,
            &anchor_sk,
            &anchor_addr,
            &funding_change,
            1000,
        )?;
        cpfp_txs_hex.push(hex::encode(serialize(&cpfp)));
        eprintln!("✓");
    }

    // Process destroys
    for (i, entry) in bundle.destroys.iter().enumerate() {
        eprint!("  [{}] {}... ", i + 2 + bundle.orders.len() + bundle.fees.len(), entry.name);
        let (tx, txid) = finalize_parent_entry(
            entry,
            placeholder_txid,
            funding_txid,
            &vault_addr,
            &q_xonly,
            &k_int_xonly,
            &tapscript_tree,
            TapLeafPhase::T2a,
            &p_script,
            &secp,
        )?;
        parent_txs_hex.push(hex::encode(serialize(&tx)));

        let cpfp = build_cpfp_child(
            txid,
            1,
            bundle.anchor_sats,
            &anchor_sk,
            &anchor_addr,
            &funding_change,
            1000,
        )?;
        cpfp_txs_hex.push(hex::encode(serialize(&cpfp)));
        eprintln!("✓");
    }

    // ── Dividend planning (greedy, conservative) ────────────────────────────────
    eprintln!("\nDividend Planning:");

    let safety_fee_sats = xcp_to_sats(o.dividend_fee_margin_xcp);
    eprintln!("  Safety fee margin reserved: {} XCP ({} sats)", o.dividend_fee_margin_xcp, safety_fee_sats);

    // Issuer-fee headroom (per recipient PER dividend)
    let est_holders = o.est_dividend_holders.unwrap_or(0);
    let total_dividend_rungs = bundle.dividends.len();
    let max_divs = o.max_dividends_to_broadcast.unwrap_or(total_dividend_rungs);
    let issuer_fee_per_div_xcp = DIV_ISSUER_FEE_PER_ADDR_SATS as f64 / XCP_DEC as f64; // 0.0002
    let issuer_fee_est_xcp = (est_holders as f64) * issuer_fee_per_div_xcp * (max_divs as f64);
    let headroom_target_xcp = issuer_fee_est_xcp + o.dividend_fee_margin_xcp + o.extra_dividend_headroom_xcp;

    if est_holders > 0 {
        eprintln!("  Issuer-fee est: ~{:.8} XCP (holders={}, per-div={:.8}, max_divs={})",
            issuer_fee_est_xcp, est_holders, issuer_fee_per_div_xcp, max_divs);
        eprintln!("  Headroom target: ~{:.8} XCP", headroom_target_xcp);
    } else {
        eprintln!("  (No est. holder count provided; using margin only)");
    }

    // Maximum outstanding supply in atomic units
    let max_supply_atomic: u128 = (o.max_outstanding_supply as u128) * TOK_DEC as u128;
    eprintln!("  Maximum outstanding supply: {} TOKEN", o.max_outstanding_supply);

    // Target cap: 0.0001 XCP per TOKEN = 10000 sats
    let max_qpu_cap_sats: u64 = 10_000;
    eprintln!("  Max per-unit target: 0.0001 XCP per TOKEN");

    // Greedy selection: choose largest rungs whose sum ≤ cap
    let mut planned_rungs: Vec<u64> = Vec::new();
    let mut qpu_sum: u64 = 0;

    for &qpu in DIV_QPU_RUNGS_SATS.iter() {
        // Respect user cap (0.0001 XCP per TOKEN)
        if qpu_sum + qpu > max_qpu_cap_sats {
            continue;
        }
        planned_rungs.push(qpu);
        qpu_sum += qpu;
    }

    eprintln!("  Planned rungs (largest first): {:?}", planned_rungs);
    eprintln!("  Planned per-unit total: {} sats ({:.8} XCP per TOKEN)", qpu_sum, qpu_sum as f64 / XCP_DEC as f64);

    // Estimate worst-case total cost
    let worst_div_cost = (qpu_sum as u128 * max_supply_atomic) / TOK_DEC as u128;
    eprintln!("  Worst-case div cost: ~{:.4} XCP", worst_div_cost as f64 / XCP_DEC as f64);
    eprintln!("\n  NOTE: At broadcast time (T2b), select rungs largest→smallest");
    eprintln!("        until actual XCP remaining - fee margin is exhausted.\n");

    // Process dividends (sign ALL rungs; operator selects subset at broadcast)
    for (i, entry) in bundle.dividends.iter().enumerate() {
        eprint!("  [{}] {}... ", i + 2 + bundle.orders.len() + bundle.fees.len() + bundle.destroys.len(), entry.name);
        let (tx, txid) = finalize_parent_entry(
            entry,
            placeholder_txid,
            funding_txid,
            &vault_addr,
            &q_xonly,
            &k_int_xonly,
            &tapscript_tree,
            TapLeafPhase::T2b,
            &p_script,
            &secp,
        )?;
        parent_txs_hex.push(hex::encode(serialize(&tx)));

        let cpfp = build_cpfp_child(
            txid,
            1,
            bundle.anchor_sats,
            &anchor_sk,
            &anchor_addr,
            &funding_change,
            1000,
        )?;
        cpfp_txs_hex.push(hex::encode(serialize(&cpfp)));
        eprintln!("✓");
    }

    // Process sweeps (post-dividend drain at t2b + delay)
    for (i, entry) in bundle.sweeps.iter().enumerate() {
        eprint!("  [{}] {}... ",
            i + 2 + bundle.orders.len() + bundle.fees.len() + bundle.destroys.len() + bundle.dividends.len(),
            entry.name);
        let (tx, txid) = finalize_parent_entry(
            entry,
            placeholder_txid,
            funding_txid,
            &vault_addr,
            &q_xonly,
            &k_int_xonly,
            &tapscript_tree,
            TapLeafPhase::T2b, // Same leaf; higher lock_time enforces delay
            &p_script,
            &secp,
        )?;
        parent_txs_hex.push(hex::encode(serialize(&tx)));

        let cpfp = build_cpfp_child(
            txid,
            1,
            bundle.anchor_sats,
            &anchor_sk,
            &anchor_addr,
            &funding_change,
            1000,
        )?;
        cpfp_txs_hex.push(hex::encode(serialize(&cpfp)));
        eprintln!("✓");
    }

    eprintln!();

    // Compute commitment hash
    eprintln!("Computing commitment hash...");
    let commitment_hash = compute_commitment_hash(&parent_txs_hex);
    eprintln!("✓ Commitment hash: {}\n", commitment_hash);

    // Update bundle
    bundle.parent_txs_hex = parent_txs_hex;
    bundle.cpfp_txs_hex = cpfp_txs_hex;
    bundle.commitment_hash = commitment_hash;

    // Write finalized bundle
    std::fs::write(&o.out, serde_json::to_vec_pretty(&bundle)?)?;
    eprintln!("=== Finalization Complete ===");
    eprintln!("✓ Wrote finalized bundle: {}", o.out);
    eprintln!("\nNext steps:");
    eprintln!("  1. Verify bundle: cargo run --bin verify_bundle -- --bundle {}", o.out);
    eprintln!("  2. Broadcast parent transactions at appropriate heights");

    Ok(())
}

/// Finalize a single parent transaction
fn finalize_parent_entry(
    entry: &PsbtEntry,
    placeholder_txid: bitcoin::Txid,
    real_txid: bitcoin::Txid,
    vault_addr: &Address,
    _vault_output_key: &XOnlyPublicKey,
    internal_key: &XOnlyPublicKey,
    tapscript_tree: &TapscriptTree,
    phase: TapLeafPhase,
    p_script: &SecretKey,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<(Transaction, bitcoin::Txid)> {
    // Decode PSBT
    let psbt_bytes = B64.decode(&entry.psbt_b64)?;
    let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes)?;

    // Replace placeholder txid with real funding txid
    ensure!(
        psbt.unsigned_tx.input.len() == 1,
        "Expected exactly 1 input in PSBT"
    );
    if psbt.unsigned_tx.input[0].previous_output.txid == placeholder_txid {
        psbt.unsigned_tx.input[0].previous_output.txid = real_txid;
    }

    // Extract unsigned transaction
    let mut tx = psbt.unsigned_tx.clone();

    // Get the leaf script for this phase
    let leaf_script = match phase {
        TapLeafPhase::T0 => &tapscript_tree.t0_leaf,
        TapLeafPhase::T1 => &tapscript_tree.t1_leaf,
        TapLeafPhase::T2a => &tapscript_tree.t2a_leaf,
        TapLeafPhase::T2b => &tapscript_tree.t2b_leaf,
    };

    let leaf_hash = tapscript_tree.get_leaf_hash(phase);

    // Rebuild the taproot spend info to get control block
    let taproot_spend_info = tapscript_tree
        .taproot_builder
        .clone()
        .finalize(&secp, *internal_key)
        .expect("Failed to finalize taproot");

    let control_block = taproot_spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .context("Failed to get control block")?;

    // Create prevouts for sighash
    let prevouts = vec![TxOut {
        value: Amount::from_sat(entry.value_sat),
        script_pubkey: vault_addr.script_pubkey(),
    }];

    // Compute sighash for tapscript spend
    let prevouts_array = Prevouts::All(&prevouts);
    let mut sighash_cache = SighashCache::new(&tx);

    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(0, &prevouts_array, leaf_hash, TapSighashType::Default)
        .context("Failed to compute sighash")?;

    // Sign with P_script using schnorr signature
    let msg = Message::from_digest(sighash.to_byte_array());
    let keypair = secp256k1::Keypair::from_secret_key(&secp, p_script);
    let mut rng = rand::thread_rng();
    let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut rng);

    // Build witness: [signature, script, control_block]
    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());

    tx.input[0].witness = witness;

    let txid = tx.txid();
    Ok((tx, txid))
}
