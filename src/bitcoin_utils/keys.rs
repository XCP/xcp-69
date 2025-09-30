//! Key management and address derivation

use anyhow::*;
use bitcoin::{address::Address, Network};
use secp256k1::{PublicKey, SecretKey};

/// Parse private key from WIF or raw hex
pub fn parse_private_key(key_str: &str, _network: Network) -> Result<SecretKey> {
    let key_str = key_str.trim();

    // Try WIF format first (most common: starts with K, L, 5, c, 9)
    if key_str.len() == 51 || key_str.len() == 52 {
        // Attempt to parse as WIF
        match bitcoin::PrivateKey::from_wif(key_str) {
            std::result::Result::Ok(wif) => return Ok(wif.inner),
            std::result::Result::Err(_) => {}
        }
    }

    // Try raw hex (64 chars)
    if key_str.len() == 64 {
        match hex::decode(key_str) {
            std::result::Result::Ok(bytes) => {
                match SecretKey::from_slice(&bytes) {
                    std::result::Result::Ok(sk) => return Ok(sk),
                    std::result::Result::Err(_) => {}
                }
            }
            std::result::Result::Err(_) => {}
        }
    }

    // If we get here, unsupported format
    bail!(
        "Unsupported key format. Supported formats:\n\
           - WIF (Bitcoin private key, e.g., L1a2b3c4d5...)\n\
           - Raw hex (64 characters)\n\
           Note: Extended keys (xprv) and mnemonics require bip39/bip32 crates (not yet implemented)"
    )
}

/// Derive P2WPKH address from pubkey
pub fn derive_address_from_pubkey(pk: &PublicKey, network: Network) -> Result<Address> {
    // Use P2WPKH (native segwit) as default for fee wallet
    // Convert secp256k1::PublicKey to bitcoin::PublicKey
    let btc_pk = bitcoin::PublicKey::new(*pk);
    Ok(Address::p2wpkh(&btc_pk, network)?)
}

/// Detect address type for witness_utxo construction
pub fn detect_address_type(addr: &Address) -> String {
    let spk = addr.script_pubkey();

    // Check if P2TR (witness v1)
    if spk.is_witness_program()
        && spk.witness_version() == Some(bitcoin::WitnessVersion::V1)
    {
        return "p2tr".to_string();
    }

    // Check if P2WPKH (witness v0, 20 bytes)
    if spk.is_witness_program()
        && spk.witness_version() == Some(bitcoin::WitnessVersion::V0)
    {
        return "p2wpkh".to_string();
    }

    // Check if P2SH (could be P2SH-P2WPKH)
    if spk.is_p2sh() {
        return "p2sh-p2wpkh".to_string();
    }

    // Default to p2wpkh
    "p2wpkh".to_string()
}