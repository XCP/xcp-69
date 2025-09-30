//! Patch funding txid command

use anyhow::*;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bitcoin::psbt::Psbt;

use crate::types::{Bundle, PsbtEntry};

#[derive(clap::Parser, Debug)]
pub struct PatchOpts {
    /// Path to the original bundle JSON
    #[arg(long)] pub bundle: String,
    /// Real funding transaction ID (hex)
    #[arg(long)] pub funding_txid: String,
    /// Output path for patched bundle
    #[arg(long, default_value="patched_bundle.json")] pub out: String,
}

pub fn run_patch_funding_txid(o: PatchOpts) -> Result<()> {
    let json = std::fs::read_to_string(&o.bundle)?;
    let mut bundle: Bundle = serde_json::from_str(&json)?;

    let funding_txid: bitcoin::Txid = o.funding_txid.parse()
        .context("Invalid funding txid hex")?;
    let placeholder_txid: bitcoin::Txid = "0000000000000000000000000000000000000000000000000000000000000000".parse()?;

    bundle.fairminter = patch_psbt_entry(&bundle.fairminter, placeholder_txid, funding_txid)?;
    for entry in &mut bundle.orders {
        *entry = patch_psbt_entry(entry, placeholder_txid, funding_txid)?;
    }
    for entry in &mut bundle.fees {
        *entry = patch_psbt_entry(entry, placeholder_txid, funding_txid)?;
    }
    for entry in &mut bundle.destroys {
        *entry = patch_psbt_entry(entry, placeholder_txid, funding_txid)?;
    }

    std::fs::write(&o.out, serde_json::to_vec_pretty(&bundle)?)?;
    eprintln!("Patched {} parent PSBTs with funding txid {}",
        1 + bundle.orders.len() + bundle.fees.len() + bundle.destroys.len(),
        funding_txid);
    eprintln!("Wrote {}", &o.out);
    Ok(())
}

fn patch_psbt_entry(entry: &PsbtEntry, old_txid: bitcoin::Txid, new_txid: bitcoin::Txid) -> Result<PsbtEntry> {
    let psbt_bytes = B64.decode(&entry.psbt_b64)?;
    let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes)?;

    ensure!(psbt.unsigned_tx.input.len() == 1, "Expected exactly 1 input");
    let input = &mut psbt.unsigned_tx.input[0];

    if input.previous_output.txid == old_txid {
        input.previous_output.txid = new_txid;
    }

    let parts: Vec<&str> = entry.utxo.split(':').collect();
    ensure!(parts.len() == 2, "Invalid utxo format");
    let new_utxo = format!("{}:{}", new_txid, parts[1]);

    let new_psbt_b64 = B64.encode(psbt.serialize());

    Ok(PsbtEntry {
        name: entry.name.clone(),
        phase: entry.phase.clone(),
        lock_height: entry.lock_height,
        purpose: entry.purpose.clone(),
        opret_hex: entry.opret_hex.clone(),
        psbt_b64: new_psbt_b64,
        utxo: new_utxo,
        value_sat: entry.value_sat,
    })
}
