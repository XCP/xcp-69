//! Shared data structures and types

use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

pub const XCP_DEC: u64 = 100_000_000;
pub const TOK_DEC: u64 = 100_000_000;
pub const ORDER_FIXED_SC_XCP: u64 = 6_900;
pub const ORDER_REMAINDER_LADDER_XCP: &[u64] = &[2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1];
pub const FEE_RUNGS_XCP: &[u64] = &[512, 256, 128, 64, 32];
pub const BURN_RUNGS_TOK: &[u64] = &[64_000_000, 32_000_000, 16_000_000, 8_000_000, 4_000_000, 2_000_000, 1_000_000];

// Dividend per-unit ladder (2^n in XCP sats per TOKEN unit)
// Max target: 0.0001 XCP per TOKEN = 10,000 sats
// Greedy selection at broadcast time handles unknown issuer fee
pub const DIV_QPU_RUNGS_SATS: &[u64] = &[8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1];

// Counterparty issuer fee for dividends (per recipient, per dividend), in XCP "sats" (atomic)
pub const DIV_ISSUER_FEE_PER_ADDR_SATS: u64 = 20_000; // 0.0002 XCP * 1e8

// Optional post-dividend sweep (rungs in whole XCP)
// These recover leftover XCP after dividends, time-locked to T2b + sweep_delay
pub const SWEEP_RUNGS_XCP: &[u64] = &[1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1];

// Bech32 character set (alphanumeric minus "1", "b", "i", "o")
// Used for vanity address validation
pub const BECH32_ALPH: &str = "0123456789acdefghjklmnpqrstuvwxyz";

// ── Bundle Types ─────────────────────────────────────────────────────────────

/// NUMS proof for trustless vault verification
/// Proves that the internal key K_int = H + r*G has no known private key
#[derive(Serialize, Deserialize)]
pub struct NumsProof {
    pub network: String,
    pub address: String,
    pub h_xonly: String,      // BIP-341 NUMS point
    pub r_hex: String,         // Random grind parameter
    pub k_int_xonly: String,   // Internal key (NUMS + r*G)
    pub q_xonly: String,       // Output key (tweaked, appears in address)
}

#[derive(Serialize, Deserialize)]
pub struct PsbtEntry {
    pub name: String,
    pub phase: String,
    pub lock_height: u32,
    pub purpose: String,
    pub opret_hex: String,
    pub psbt_b64: String,
    pub utxo: String,
    pub value_sat: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub network: String,
    pub nums_proof: NumsProof,
    pub tapscript_pubkey: String,     // P_script xonly (signing key for tapscript)
    pub merkle_root: String,           // Tapscript tree merkle root
    pub anchor_address: String,        // CPFP anchor address
    pub t0: u32,
    pub t1: u32,
    pub t2a: u32,
    pub t2b: u32,
    pub expiration_blocks: u32,
    pub anchor_sats: u64,
    pub base_fee_sats: u64,
    pub asset: String,
    pub platform_xcp_dest: String,     // Platform fee/sweep destination (XCP address)
    pub fairminter: PsbtEntry,
    pub orders: Vec<PsbtEntry>,
    pub fees: Vec<PsbtEntry>,
    pub destroys: Vec<PsbtEntry>,
    pub dividends: Vec<PsbtEntry>,
    pub sweeps: Vec<PsbtEntry>,        // Post-dividend XCP recovery (t2b + delay)
    pub parent_txs_hex: Vec<String>,   // All pre-signed parent transactions (for verification)
    pub cpfp_txs_hex: Vec<String>,     // All pre-signed CPFP child transactions
    pub commitment_hash: String,        // SHA256 hash of all parent txs (for commitment)
    pub funding_psbt_b64: String,
    pub funding_output_value: u64,
    pub funding_outputs: usize,
    pub funding_change_addr: String,
}

// ── UTXO Types ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct InUtxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: bitcoin::ScriptBuf, // Prevout script for witness_utxo
}
