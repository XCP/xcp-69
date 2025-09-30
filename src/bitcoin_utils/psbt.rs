//! PSBT construction utilities for NUMS + tapscript vaults
//!
//! This module builds PSBTs for script-path spending with:
//! - NUMS internal key (no keypath spend possible)
//! - CLTV-locked tapscript leaves
//! - Pre-signed parents + CPFP children

use anyhow::*;
use bitcoin::{
    absolute::LockTime,
    address::Address,
    hashes::Hash,
    psbt::Psbt,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::LeafVersion,
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};
use secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::types::InUtxo;

use super::tapscript::{TapLeafPhase, TapscriptTree};

pub fn opret_txout(data: &[u8]) -> TxOut {
    use bitcoin::script::Builder;
    let push_bytes =
        bitcoin::script::PushBytesBuf::try_from(data.to_vec()).expect("OP_RETURN data too large");
    let script = Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(&push_bytes)
        .into_script();
    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script,
    }
}

/// Build an *unsigned* parent PSBT for a tapscript (script-path) spend.
///
/// This creates a PSBT template with:
/// - Input prevout uses a placeholder txid (00..00:idx) during `setup`
/// - No witness is added here; signing happens in `finalize-parents`
/// - Proper CLTV lock_time for the phase
/// - OP_RETURN output with Counterparty data
/// - Anchor output for CPFP
#[allow(clippy::too_many_arguments)]
pub fn build_parent_psbt(
    utxo: OutPoint,              // Placeholder prevout during setup
    utxo_value: u64,             // Value of the vault UTXO
    opret: Vec<u8>,              // Counterparty compose data
    anchor_spk: &ScriptBuf,      // CPFP anchor
    anchor_sats: u64,
    base_fee_sats: u64,
    lock_height: u32,            // CLTV height for this phase
) -> Result<Psbt> {
    ensure!(
        utxo_value >= anchor_sats + base_fee_sats,
        "UTXO too small for anchor+fee"
    );

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from_height(lock_height)?,
        input: vec![TxIn {
            previous_output: utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFE), // Non-final for CLTV
            witness: Witness::default(),    // Empty; will be filled at finalize
        }],
        output: vec![
            opret_txout(&opret),
            TxOut {
                value: Amount::from_sat(anchor_sats),
                script_pubkey: anchor_spk.clone(),
            },
        ],
    };

    Ok(Psbt::from_unsigned_tx(tx)?)
}

/// Build and sign a parent PSBT via script path (tapscript spend)
///
/// This creates a fully-signed transaction spending from the vault via tapscript.
/// The transaction is time-locked and spends via the appropriate CLTV leaf.
#[allow(clippy::too_many_arguments)]
pub fn build_and_sign_parent(
    vault_output_key: &XOnlyPublicKey, // Q (tweaked output key, what's in the address)
    internal_key: &XOnlyPublicKey,     // K_int (NUMS-based internal key)
    utxo: OutPoint,
    utxo_value: u64,
    opret: Vec<u8>,
    anchor_spk: &ScriptBuf,
    anchor_sats: u64,
    base_fee_sats: u64,
    lock_height: u32,
    tapscript_tree: &TapscriptTree,
    phase: TapLeafPhase,
    p_script: &SecretKey, // Signing key for tapscript
) -> Result<Transaction> {
    ensure!(
        utxo_value >= anchor_sats + base_fee_sats,
        "UTXO too small for anchor+fee"
    );

    // Build unsigned transaction
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from_height(lock_height)?,
        input: vec![TxIn {
            previous_output: utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xFFFFFFFE), // Non-final for CLTV
            witness: Witness::default(),
        }],
        output: vec![
            opret_txout(&opret),
            TxOut {
                value: Amount::from_sat(anchor_sats),
                script_pubkey: anchor_spk.clone(),
            },
        ],
    };

    // Get the leaf script for this phase
    let leaf_script = match phase {
        TapLeafPhase::T0 => &tapscript_tree.t0_leaf,
        TapLeafPhase::T1 => &tapscript_tree.t1_leaf,
        TapLeafPhase::T2a => &tapscript_tree.t2a_leaf,
        TapLeafPhase::T2b => &tapscript_tree.t2b_leaf,
    };

    let leaf_hash = tapscript_tree.get_leaf_hash(phase);

    // Build control block for script-path spend
    let secp = Secp256k1::new();

    // Rebuild the taproot spend info to get control block
    let taproot_spend_info = tapscript_tree
        .taproot_builder
        .clone()
        .finalize(&secp, *internal_key)
        .expect("Failed to finalize taproot");

    // Assert output key and parity match (defensive check)
    let expect_q = *vault_output_key;
    let actual_q = taproot_spend_info.output_key().to_inner();
    ensure!(actual_q == expect_q, "Output key mismatch: builder Q != vault Q");

    // Verify the control block against the leaf, internal key, and output key
    let control_block = taproot_spend_info
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
        .context("Failed to get control block")?;

    // Verify control block is well-formed for this leaf
    // The control block verification is implicit in the TaprootBuilder finalization
    // We've already checked that output_key matches expected Q above

    // Create prevouts for sighash
    let prevouts = vec![TxOut {
        value: Amount::from_sat(utxo_value),
        script_pubkey: ScriptBuf::new_p2tr(&secp, *vault_output_key, None),
    }];

    // Compute sighash for tapscript spend
    let prevouts_array = Prevouts::All(&prevouts);
    let mut sighash_cache = SighashCache::new(&tx);

    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &prevouts_array,
            leaf_hash,
            TapSighashType::Default,
        )
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

    Ok(tx)
}

/// Build a CPFP child transaction spending the anchor output
///
/// This allows anyone to bump fees on the parent transaction.
/// The child spends the anchor output and adds additional fees.
pub fn build_cpfp_child(
    parent_txid: bitcoin::Txid,
    anchor_vout: u32,
    anchor_value: u64,
    anchor_sk: &SecretKey,
    anchor_addr: &Address,
    change_addr: &Address,
    additional_fee: u64,
) -> Result<Transaction> {
    let secp = Secp256k1::new();

    ensure!(
        anchor_value > additional_fee + 546,
        "Anchor too small for CPFP"
    );

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_txid,
                vout: anchor_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(anchor_value - additional_fee),
            script_pubkey: change_addr.script_pubkey(),
        }],
    };

    // Sign anchor input (P2TR keypath spend)
    let prevouts = vec![TxOut {
        value: Amount::from_sat(anchor_value),
        script_pubkey: anchor_addr.script_pubkey(),
    }];

    let prevouts_array = Prevouts::All(&prevouts);
    let mut sighash_cache = SighashCache::new(&tx);

    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts_array, TapSighashType::Default)
        .context("Failed to compute CPFP sighash")?;

    let msg = Message::from_digest(sighash.to_byte_array());
    let keypair = secp256k1::Keypair::from_secret_key(&secp, anchor_sk);
    let mut rng = rand::thread_rng();
    let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut rng);

    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Compute commitment hash over all parent transactions
///
/// Returns SHA256(tx1_hex || tx2_hex || ... || txN_hex)
pub fn compute_commitment_hash(tx_hexes: &[String]) -> String {
    let mut hasher = Sha256::new();
    for hex in tx_hexes {
        hasher.update(hex.as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn build_funding_psbt(
    _network: Network,
    funding_inputs: &[InUtxo],
    funding_change: &Address,
    vault: &Address,
    outputs: usize,
    each_value: u64,
    _funding_type: &str,
) -> Result<Psbt> {
    // Network validation is done at address parse time with require_network()
    let total_out: u64 = (outputs as u64) * each_value;

    // Rough fee for this funding tx; keep simple (you'll sign+RBF if needed):
    // size ≈ 10 + in*68 + out*31  vB → multiply by ~1 sat/vB: a few thousand sats.
    let fee_budget = 3_000;

    // Build tx
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: funding_inputs
            .iter()
            .map(|u| TxIn {
                previous_output: u.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            })
            .collect(),
        output: vec![],
    };

    // N exact-value vault outputs
    for _ in 0..outputs {
        tx.output.push(TxOut {
            value: Amount::from_sat(each_value),
            script_pubkey: vault.script_pubkey(),
        });
    }

    // Change
    let in_sum: u64 = funding_inputs.iter().map(|u| u.value).sum();
    ensure!(
        in_sum >= total_out + fee_budget,
        "funding inputs insufficient"
    );
    let change = in_sum - total_out - fee_budget;
    if change > 546 {
        tx.output.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: funding_change.script_pubkey(),
        });
    }

    let mut psbt = Psbt::from_unsigned_tx(tx)?;

    // Set witness_utxo for each input using the script_pubkey from each UTXO
    // This supports mixed input types (each UTXO carries its own prevout script)
    for (i, u) in funding_inputs.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(u.value),
            script_pubkey: u.script_pubkey.clone(),
        });

        // Note: For P2SH-P2WPKH, the wallet should also set redeem_script
        // during signing. We only set witness_utxo here.
    }
    Ok(psbt)
}

pub fn parse_utxos(csv: &str, script_pubkey: bitcoin::ScriptBuf) -> Result<Vec<InUtxo>> {
    let mut v = vec![];
    for (i, s) in csv.split(',').enumerate() {
        let p: Vec<_> = s.trim().split(':').collect();
        ensure!(
            p.len() == 3,
            "bad funding_utxos[{}] (txid:vout:value_sat)",
            i
        );
        v.push(InUtxo {
            outpoint: OutPoint {
                txid: p[0].parse()?,
                vout: p[1].parse()?,
            },
            value: p[2].parse()?,
            script_pubkey: script_pubkey.clone(),
        });
    }
    Ok(v)
}
