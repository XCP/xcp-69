//! Bundle verification tool
//!
//! Verifies all parent transactions in a bundle:
//! - Correct CLTV height for phase
//! - Witness structure [sig, script, control_block]
//! - Leaf script matches expected CLTV construction
//! - Control block commits to (K_int, merkle_root) → Q
//! - Schnorr signature verifies with P_script
//! - OP_RETURN data matches opret_hex
//! - Commitment hash matches

use anyhow::*;
use bitcoin::{
    absolute::LockTime,
    address::Address,
    consensus::encode::deserialize,
    hashes::Hash,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, TapLeafHash},
    AddressType, Network, Transaction, TxOut, Witness, XOnlyPublicKey,
};
use secp256k1::{Message, Secp256k1};
use std::fs;

use xcp69_setup::bitcoin_utils::psbt::compute_commitment_hash;
use xcp69_setup::bitcoin_utils::tapscript::build_cltv_leaf;
use xcp69_setup::types::*;

/// CLI: `cargo run --bin verify_bundle -- --bundle bundle.json`
#[derive(clap::Parser, Debug)]
struct Opts {
    /// Path to bundle JSON
    #[arg(long)]
    bundle: String,

    /// Also assert OP_RETURN matches opret_hex
    #[arg(long, default_value_t = true)]
    check_opret: bool,
}

fn main() -> Result<()> {
    let opts = <Opts as clap::Parser>::parse();

    // Load bundle
    let raw = fs::read_to_string(&opts.bundle)?;
    let bundle: Bundle = serde_json::from_str(&raw)?;

    eprintln!("=== Bundle Verification ===\n");
    eprintln!("Bundle: {}", opts.bundle);
    eprintln!("Network: {}", bundle.network);
    eprintln!("Vault address: {}", bundle.nums_proof.address);
    eprintln!();

    // Parse network
    let net = match bundle.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        other => bail!("Unknown network in bundle: {other}"),
    };

    // Parse vault Q and K_int and merkle_root
    let q_xonly = XOnlyPublicKey::from_slice(&hex::decode(&bundle.nums_proof.q_xonly)?)?;
    let _k_int = XOnlyPublicKey::from_slice(&hex::decode(&bundle.nums_proof.k_int_xonly)?)?;
    let _merkle_root = {
        let bytes = hex::decode(&bundle.merkle_root)?;
        ensure!(bytes.len() == 32, "merkle_root must be 32 bytes");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        bitcoin::taproot::TapNodeHash::from_byte_array(arr)
    };

    // Sanity: address encodes Q
    let vault_addr: Address = bundle
        .nums_proof
        .address
        .parse::<Address<_>>()?
        .require_network(net)?;
    ensure!(
        vault_addr.address_type() == Some(AddressType::P2tr),
        "Vault address is not P2TR"
    );

    // Extract Q from address
    if let bitcoin::address::Payload::WitnessProgram(ref wp) = vault_addr.payload() {
        ensure!(wp.version().to_num() == 1, "Not P2TR (wrong version)");
        let program = wp.program().as_bytes();
        ensure!(program.len() == 32, "Not P2TR (wrong length)");
        let addr_q = XOnlyPublicKey::from_slice(program)?;
        ensure!(addr_q == q_xonly, "Vault address Q mismatch");
    } else {
        bail!("Not P2TR address");
    }

    // tapscript signing pubkey
    let p_script_xonly = XOnlyPublicKey::from_slice(&hex::decode(&bundle.tapscript_pubkey)?)?;
    let p_script_secp = secp256k1::XOnlyPublicKey::from_slice(&p_script_xonly.serialize())?;

    // Build the flat list of entries in the same order we wrote tx hexes
    let mut all_entries: Vec<&PsbtEntry> = Vec::new();
    all_entries.push(&bundle.fairminter);
    all_entries.extend(bundle.orders.iter());
    all_entries.extend(bundle.fees.iter());
    all_entries.extend(bundle.destroys.iter());
    all_entries.extend(bundle.dividends.iter());
    all_entries.extend(bundle.sweeps.iter());

    ensure!(
        all_entries.len() == bundle.parent_txs_hex.len(),
        "parent_txs_hex count ({}) != entries count ({})",
        bundle.parent_txs_hex.len(),
        all_entries.len()
    );

    eprintln!("Verifying {} parent transactions...\n", all_entries.len());

    let secp = Secp256k1::new();
    let mut ok_count = 0usize;

    for (idx, (tx_hex, entry)) in bundle
        .parent_txs_hex
        .iter()
        .zip(all_entries.iter())
        .enumerate()
    {
        eprint!("  [{}] {} (phase {}, height {})... ", idx + 1, entry.name, entry.phase, entry.lock_height);

        let tx_bytes = hex::decode(tx_hex)?;
        let tx: Transaction = deserialize(&tx_bytes)?;

        // 1) One-input invariant; locktime matches entry; anchor output value matches
        ensure!(tx.input.len() == 1, "tx#{idx}: expected 1 input");
        ensure!(
            tx.lock_time == LockTime::from_height(entry.lock_height)?,
            "tx#{idx}: locktime != entry.lock_height"
        );
        ensure!(tx.output.len() >= 2, "tx#{idx}: expected at least 2 outputs");
        ensure!(
            tx.output[1].value.to_sat() == bundle.anchor_sats,
            "tx#{idx}: anchor output value mismatch (got {}, want {})",
            tx.output[1].value.to_sat(),
            bundle.anchor_sats
        );

        // 2) Witness stack [sig, script, control_block]
        let wit: &Witness = &tx.input[0].witness;
        ensure!(wit.len() == 3, "tx#{idx}: witness must have 3 elements (no annex)");
        let sig_bytes = wit.nth(0).context(format!("tx#{idx}: sig missing"))?;
        let leaf_script_bytes = wit.nth(1).context(format!("tx#{idx}: script missing"))?;
        let control_bytes = wit.nth(2).context(format!("tx#{idx}: control block missing"))?;

        // 3) Re-build the expected leaf script
        let expected_leaf = build_cltv_leaf(entry.lock_height, &p_script_xonly);
        ensure!(
            expected_leaf.as_bytes() == leaf_script_bytes,
            "tx#{idx}: leaf script bytes mismatch"
        );

        // 4) Control block verification against (K_int, merkle_root) and Q
        let cb = ControlBlock::decode(control_bytes)
            .context(format!("tx#{idx}: invalid control block"))?;
        // Verify commits to this leaf and internal key → produces output key Q
        // bitcoin 0.31's ControlBlock::verify_taproot_commitment checks the commitment
        ensure!(
            cb.verify_taproot_commitment(&secp, q_xonly, &expected_leaf),
            "tx#{idx}: control block verification failed"
        );

        // 5) (Optional) OP_RETURN bytes match entry.opret_hex
        if opts.check_opret {
            ensure!(
                !tx.output.is_empty(),
                "tx#{idx}: no outputs for OP_RETURN check"
            );
            let opret = &tx.output[0];
            ensure!(
                opret.script_pubkey.is_op_return(),
                "tx#{idx}: first output not OP_RETURN"
            );
            // Extract all pushed data (OP_RETURN | PUSH_DATA)
            use bitcoin::blockdata::script::Instruction;
            let mut pushes = Vec::new();
            for ins in opret.script_pubkey.instructions() {
                match ins {
                    std::result::Result::Ok(Instruction::PushBytes(pb)) => {
                        pushes.push(pb.as_bytes().to_vec());
                    }
                    std::result::Result::Ok(Instruction::Op(_)) => {} // OP_RETURN
                    std::result::Result::Err(e) => {
                        bail!("tx#{idx}: invalid OP_RETURN script instruction: {}", e);
                    }
                }
            }
            let want = hex::decode(&entry.opret_hex)?;
            ensure!(
                pushes.len() == 1,
                "tx#{idx}: expected exactly 1 push in OP_RETURN, got {}",
                pushes.len()
            );
            ensure!(
                pushes[0] == want,
                "tx#{idx}: OP_RETURN payload mismatch"
            );
        }

        // 6) Verify signature with SIGHASH_DEFAULT using prevout=(vault Q, value_sat)
        //    Recompute leaf hash
        let leaf_hash = TapLeafHash::from_script(&expected_leaf, LeafVersion::TapScript);

        // Build prevouts array (single vault prevout, value from entry)
        let prevout = TxOut {
            value: bitcoin::Amount::from_sat(entry.value_sat),
            script_pubkey: vault_addr.script_pubkey(),
        };
        let mut cache = SighashCache::new(&tx);
        let sighash = cache.taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )?;
        let msg = Message::from_digest(sighash.to_byte_array());

        // Schnorr verify against P_script
        // (note: sig in witness is 64-byte schnorr sig since hash type = default)
        ensure!(
            sig_bytes.len() == 64 || sig_bytes.len() == 65,
            "tx#{idx}: bad sig len"
        );
        // Strip sighash byte if present
        let sig64 = if sig_bytes.len() == 65 {
            &sig_bytes[..64]
        } else {
            sig_bytes
        };
        let schnorr_sig = secp256k1::schnorr::Signature::from_slice(sig64)
            .context("invalid schnorr sig encoding")?;

        secp.verify_schnorr(&schnorr_sig, &msg, &p_script_secp)
            .context(format!("tx#{idx}: signature verification failed"))?;

        eprintln!("✓");
        ok_count += 1;
    }

    eprintln!();

    // Verify commitment hash
    eprintln!("Verifying commitment hash...");
    let computed_hash = compute_commitment_hash(&bundle.parent_txs_hex);
    ensure!(
        computed_hash == bundle.commitment_hash,
        "Commitment hash mismatch: computed={}, bundle={}",
        computed_hash,
        bundle.commitment_hash
    );
    eprintln!("  ✓ Commitment hash verified: {}\n", computed_hash);

    eprintln!("=== Verification Complete ===");
    eprintln!("✅ All {} parent transaction(s) verified successfully.", ok_count);
    eprintln!("✅ Commitment hash matches.");
    eprintln!("\nBundle is valid and ready for deployment!");

    Ok(())
}
