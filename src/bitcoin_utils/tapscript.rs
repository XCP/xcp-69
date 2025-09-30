//! Tapscript utilities for NUMS-based vault construction
//!
//! This module implements the tapscript structure for trustless XCP-69 vaults:
//! - NUMS internal key (provably no keypath spend)
//! - 3 leaves with CLTV time locks (T0, T2a, T2b)
//! - Script-path spending only

use anyhow::*;
use bitcoin::{
    blockdata::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_DROP},
    hashes::Hash,
    script::Builder,
    taproot::{TapLeafHash, TapNodeHash, TaprootBuilder},
    ScriptBuf, XOnlyPublicKey,
};
use secp256k1::{Secp256k1, SecretKey};

/// Build a CLTV-locked tapscript leaf: <height> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG
pub fn build_cltv_leaf(lock_height: u32, pubkey: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(lock_height as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build 4-leaf tapscript tree for T0, T1, T2a, T2b phases
pub struct TapscriptTree {
    pub t0_leaf: ScriptBuf,
    pub t1_leaf: ScriptBuf,
    pub t2a_leaf: ScriptBuf,
    pub t2b_leaf: ScriptBuf,
    pub merkle_root: TapNodeHash,
    pub taproot_builder: TaprootBuilder,
}

impl TapscriptTree {
    /// Create tapscript tree with 4 CLTV leaves
    pub fn new(t0: u32, t1: u32, t2a: u32, t2b: u32, p_script: &XOnlyPublicKey) -> Result<Self> {
        let t0_leaf = build_cltv_leaf(t0, p_script);
        let t1_leaf = build_cltv_leaf(t1, p_script);
        let t2a_leaf = build_cltv_leaf(t2a, p_script);
        let t2b_leaf = build_cltv_leaf(t2b, p_script);

        // Build taproot tree with all 4 leaves
        let builder = TaprootBuilder::new()
            .add_leaf(0, t0_leaf.clone())?
            .add_leaf(0, t1_leaf.clone())?
            .add_leaf(0, t2a_leaf.clone())?
            .add_leaf(0, t2b_leaf.clone())?;

        // Get merkle root (we can't finalize without internal key, but we can get the tree)
        // We'll compute merkle root manually from the builder
        let merkle_root = builder
            .clone()
            .finalize(&Secp256k1::new(), get_nums_point())
            .expect("Tree finalization failed")
            .merkle_root()
            .expect("No merkle root");

        Ok(TapscriptTree {
            t0_leaf,
            t1_leaf,
            t2a_leaf,
            t2b_leaf,
            merkle_root,
            taproot_builder: builder,
        })
    }

    /// Get the leaf hash for a specific phase
    pub fn get_leaf_hash(&self, phase: TapLeafPhase) -> TapLeafHash {
        let script = match phase {
            TapLeafPhase::T0 => &self.t0_leaf,
            TapLeafPhase::T1 => &self.t1_leaf,
            TapLeafPhase::T2a => &self.t2a_leaf,
            TapLeafPhase::T2b => &self.t2b_leaf,
        };
        TapLeafHash::from_script(script, bitcoin::taproot::LeafVersion::TapScript)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TapLeafPhase {
    T0,
    T1,
    T2a,
    T2b,
}

/// Get BIP-341 NUMS point (hash of generator, no known discrete log)
/// H = hash_to_curve("secp256k1_XMD:SHA-256_SSWU_RO_", "BIP-0341 NUMS point")
/// This returns the standard NUMS point from BIP-341
pub fn get_nums_point() -> XOnlyPublicKey {
    // BIP-341 NUMS point: lift_x(H) where H is the 32-byte hash
    // Standard NUMS = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
    XOnlyPublicKey::from_slice(
        &hex::decode("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
            .expect("Valid NUMS point"),
    )
    .expect("Valid x-only pubkey")
}

/// Tweak NUMS point by adding r*G: K_int = H + r*G
pub fn tweak_nums_point(r: &SecretKey) -> Result<XOnlyPublicKey> {
    let secp = Secp256k1::new();
    let nums = get_nums_point();

    // Convert NUMS to point, add r*G
    let nums_point = secp256k1::PublicKey::from_x_only_public_key(nums, secp256k1::Parity::Even);
    let r_point = secp256k1::PublicKey::from_secret_key(&secp, r);

    // Add points: K_int = H + r*G
    let k_int = nums_point.combine(&r_point).context("Point addition failed")?;

    Ok(k_int.x_only_public_key().0)
}

/// Apply tap tweak to get output key: Q = K_int + t*G
/// Uses BIP-341 tagged hash for TapTweak
pub fn apply_tap_tweak(
    internal_key: &XOnlyPublicKey,
    merkle_root: Option<TapNodeHash>,
) -> Result<XOnlyPublicKey> {
    use crate::bitcoin_utils::tagged::tap_tweak;
    let secp = Secp256k1::new();

    let mut root32: Option<[u8; 32]> = None;
    if let Some(root) = merkle_root {
        root32 = Some(root.to_byte_array());
    }
    let tweak = tap_tweak(&internal_key.serialize(), root32.as_ref());

    // Q = K_int + t*G
    let k_point = secp256k1::PublicKey::from_x_only_public_key(*internal_key, secp256k1::Parity::Even);
    let t_sk = SecretKey::from_slice(&tweak)?;
    let t_point = secp256k1::PublicKey::from_secret_key(&secp, &t_sk);
    let q = k_point.combine(&t_point).context("Tweak application failed")?;
    Ok(q.x_only_public_key().0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cltv_leaf_construction() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let xonly = pk.x_only_public_key().0;

        let leaf = build_cltv_leaf(100000, &xonly);
        assert!(leaf.len() > 0);
        assert!(leaf.is_p2pk() == false); // It's a custom script
    }

    #[test]
    fn test_nums_point() {
        let nums = get_nums_point();
        assert_eq!(
            hex::encode(nums.serialize()),
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        );
    }

    #[test]
    fn test_tweak_nums() {
        let r = SecretKey::from_slice(&[42u8; 32]).unwrap();
        let k_int = tweak_nums_point(&r).unwrap();
        // Should produce a different point than NUMS
        assert_ne!(k_int, get_nums_point());
    }

    #[test]
    fn test_tagged_leaf_hash_matches_bitcoin_crate() {
        use crate::bitcoin_utils::tagged::tap_leaf_hash;
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .x_only_public_key()
            .0;
        let script = build_cltv_leaf(123_456, &pk);
        let our = tap_leaf_hash(
            bitcoin::taproot::LeafVersion::TapScript.to_consensus(),
            script.as_bytes(),
        );
        let theirs = TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript)
            .to_byte_array();
        assert_eq!(our, theirs);
    }
}
