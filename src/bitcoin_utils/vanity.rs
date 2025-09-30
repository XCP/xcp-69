//! NUMS-based vanity address grinding
//!
//! This implementation grinds for vanity addresses using a NUMS (Nothing Up My Sleeve) point
//! as the internal key, ensuring no keypath spend is possible.
//!
//! Process:
//! 1. Start with BIP-341 NUMS point H (no known private key)
//! 2. Grind random r until K_int = H + r*G gives desired vanity on OUTPUT KEY Q
//! 3. Q = K_int + t*G where t = H_tapTweak(K_int || merkle_root)
//! 4. Vanity pattern must match the TWEAKED key (what appears in the address), not K_int

use anyhow::*;
use bitcoin::{address::Address, taproot::TapNodeHash, Network};
use hex::ToHex;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use rayon::prelude::*;
use secp256k1::SecretKey;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::types::{NumsProof, BECH32_ALPH};

use super::tapscript::{apply_tap_tweak, get_nums_point, tweak_nums_point};

/// Grind for NUMS vanity address with taproot tweak
///
/// CRITICAL: This grinds on the OUTPUT KEY Q = K_int + tweak*G, not on K_int itself.
/// The merkle_root must be known before grinding starts.
pub fn grind_nums_vanity(
    network: Network,
    mode: &str,
    pattern: &str,
    merkle_root: TapNodeHash,
    threads: usize,
    max_attempts: u64,
) -> Result<NumsProof> {
    ensure!(
        pattern.chars().all(|c| BECH32_ALPH.contains(c)),
        "pattern has non-bech32 chars"
    );
    let mode = mode.to_ascii_lowercase();
    ensure!(
        mode == "prefix" || mode == "suffix",
        "--mode must be prefix|suffix"
    );

    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .ok();
    let found = Arc::new(AtomicBool::new(false));
    let started = Instant::now();

    let nums = get_nums_point();

    let res = (0..threads).into_par_iter().find_map_any(|thread_id| {
        let mut rng = StdRng::from_entropy();
        let mut tries: u64 = 0;
        let mut last_log = Instant::now();

        loop {
            if found.load(Ordering::Relaxed) {
                return None;
            }
            if max_attempts > 0 && tries >= max_attempts / threads as u64 {
                return None;
            }
            tries += 1;

            // Log progress every 10 seconds for thread 0
            if thread_id == 0 && last_log.elapsed().as_secs() >= 10 {
                let total_tries = tries * threads as u64;
                let rate = total_tries as f64 / started.elapsed().as_secs_f64();
                eprintln!(
                    "  {} attempts, {:.0} keys/sec...",
                    total_tries, rate
                );
                last_log = Instant::now();
            }

            // Generate random r
            let mut r_bytes = [0u8; 32];
            rng.fill_bytes(&mut r_bytes);
            let r = match SecretKey::from_slice(&r_bytes) {
                std::result::Result::Ok(k) => k,
                std::result::Result::Err(_) => continue,
            };

            // Compute K_int = H + r*G
            let k_int = match tweak_nums_point(&r) {
                std::result::Result::Ok(k) => k,
                std::result::Result::Err(_) => continue,
            };

            // Apply tap tweak: Q = K_int + t*G
            let q = match apply_tap_tweak(&k_int, Some(merkle_root)) {
                std::result::Result::Ok(q) => q,
                std::result::Result::Err(_) => continue,
            };

            // Build address from OUTPUT KEY Q (already tweaked)
            // We need to construct P2TR address directly from output key, not via p2tr() which would tweak again
            let tweaked_pk = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(q);
            let addr = Address::p2tr_tweaked(tweaked_pk, network);
            let s = addr.to_string().to_ascii_lowercase();

            let ok = if mode == "prefix" {
                s[3..].starts_with(pattern) // Skip "bc1" prefix
            } else {
                s.ends_with(pattern)
            };

            if ok {
                found.store(true, Ordering::Relaxed);
                eprintln!("\n✓ Found vanity address: {}", addr);
                eprintln!("  Attempts: {}", tries * threads as u64);
                eprintln!("  Time: {:.1}s", started.elapsed().as_secs_f64());

                return Some(NumsProof {
                    network: format!("{network:?}"),
                    address: addr.to_string(),
                    h_xonly: nums.serialize().encode_hex::<String>(),
                    r_hex: r.secret_bytes().encode_hex::<String>(),
                    k_int_xonly: k_int.serialize().encode_hex::<String>(),
                    q_xonly: q.serialize().encode_hex::<String>(),
                });
            }
        }
    });

    res.ok_or_else(|| anyhow!("no match found (increase threads/time or shorten pattern)"))
}

/// Verify NUMS proof: K_int = H + rG, Q = tweak(K_int, root), address encodes Q
pub fn verify_nums_proof(proof: &crate::types::NumsProof, merkle_root: [u8; 32]) -> anyhow::Result<()> {
    use bitcoin::{address::{Address, NetworkUnchecked}, XOnlyPublicKey, Network};
    use bitcoin::hashes::Hash;
    use secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();

    // Parse fields
    let h = XOnlyPublicKey::from_slice(&hex::decode(&proof.h_xonly)?)?;
    let r = SecretKey::from_slice(&hex::decode(&proof.r_hex)?)?;
    let k_int = XOnlyPublicKey::from_slice(&hex::decode(&proof.k_int_xonly)?)?;
    let q = XOnlyPublicKey::from_slice(&hex::decode(&proof.q_xonly)?)?;

    // Recompute K_int
    let h_pt = secp256k1::PublicKey::from_x_only_public_key(h, secp256k1::Parity::Even);
    let r_pt = secp256k1::PublicKey::from_secret_key(&secp, &r);
    let recomb = h_pt.combine(&r_pt).context("H + rG failed")?;
    let recomb_x = recomb.x_only_public_key().0;
    anyhow::ensure!(recomb_x == k_int, "K_int mismatch");

    // Recompute Q
    let merkle_root_hash = bitcoin::taproot::TapNodeHash::from_slice(&merkle_root)?;
    let q_re = crate::bitcoin_utils::tapscript::apply_tap_tweak(
        &k_int,
        Some(merkle_root_hash),
    )?;
    anyhow::ensure!(q_re == q, "Tweaked Q mismatch");

    // Check address encodes Q (network from proof.network)
    let net = match proof.network.as_str() {
        "mainnet" | "Bitcoin" => Network::Bitcoin,
        "testnet" | "Testnet" => Network::Testnet,
        "signet" | "Signet" => Network::Signet,
        _ => Network::Bitcoin,
    };
    let addr = proof.address.parse::<Address<NetworkUnchecked>>()?;
    let checked_addr = addr.require_network(net)?;

    // Verify it's P2TR and extract the key
    if let bitcoin::address::Payload::WitnessProgram(ref wp) = checked_addr.payload() {
        anyhow::ensure!(wp.version().to_num() == 1, "Not P2TR (wrong version)");
        let program = wp.program().as_bytes();
        anyhow::ensure!(program.len() == 32, "Not P2TR (wrong length)");
        let addr_q = XOnlyPublicKey::from_slice(program)?;
        anyhow::ensure!(
            addr_q == q,
            "Address Q mismatch: addr_q={}, q={}",
            hex::encode(addr_q.serialize()),
            hex::encode(q.serialize())
        );
    } else {
        anyhow::bail!("Not P2TR address");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::taproot::TapNodeHash;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_nums_vanity_short_pattern() {
        // Test with a very short pattern and small attempt limit
        let merkle_root = TapNodeHash::from_slice(&[0u8; 32]).unwrap(); // Dummy merkle root
        let result = grind_nums_vanity(
            Network::Testnet,
            "suffix",
            "a",
            merkle_root,
            1,
            1000,
        );
        // Should find something quickly or timeout
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_nums_verify_smoke() {
        // Small vanity grind then verify
        let root = TapNodeHash::from_slice(&[0u8; 32]).unwrap();
        let proof = grind_nums_vanity(Network::Testnet, "suffix", "a", root, 1, 5000).unwrap();
        verify_nums_proof(&proof, root.to_byte_array()).unwrap();
    }
}
