//! BIP340/341 tagged-hash utilities

use bitcoin::hashes::{sha256, Hash};
use sha2::{Digest, Sha256};

/// Generic tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
pub fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut s = Sha256::new();
    s.update(tag_hash);
    s.update(tag_hash);
    s.update(msg);
    s.finalize().into()
}

/// TapTweak(internal_key || merkle_root_opt)
pub fn tap_tweak(internal_xonly: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 32);
    buf.extend_from_slice(internal_xonly);
    if let Some(root) = merkle_root {
        buf.extend_from_slice(root);
    }
    tagged_hash("TapTweak", &buf)
}

/// TapLeaf(version || compact_size(script.len) || script)
pub fn tap_leaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(1 + 9 + script.len());
    msg.push(leaf_version);
    write_compact_size(&mut msg, script.len() as u64);
    msg.extend_from_slice(script);
    tagged_hash("TapLeaf", &msg)
}

/// CompactSize (Bitcoin varint)
fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=252 => out.push(n as u8),
        253..=0xFFFF => {
            out.push(253);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(254);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(255);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}
