//! Counterparty API integration

use anyhow::*;
use reqwest::blocking::Client;

use crate::types::*;

// ── API Helpers ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct ComposeResp {
    result: ComposeInner,
}

#[derive(serde::Deserialize)]
struct ComposeInner {
    data: String,
}

fn cp_get(client: &Client, base: &str, path: &str, qs: &[(&str, String)]) -> Result<Vec<u8>> {
    let url = format!("{base}{path}");
    // Build query params with verbose=true automatically added
    let mut params = qs.to_vec();
    params.push(("verbose", "true".into()));

    let resp: ComposeResp = client
        .get(&url)
        .query(&params)
        .send()?
        .error_for_status()?
        .json()?;
    Ok(hex::decode(resp.result.data)?)
}

// ── Compose Functions ────────────────────────────────────────────────────────

pub fn cp_compose_fairminter(
    client: &Client,
    base: &str,
    addr: &str,
    asset: &str,
    start_block: u32,
    end_block: u32,
) -> Result<Vec<u8>> {
    let soft_cap_deadline = end_block.checked_sub(1)
        .ok_or_else(|| anyhow!("end_block must be > start_block"))?;

    // Fill with your exact XCP-69 params; core ones shown.
    cp_get(
        client,
        base,
        &format!("/addresses/{addr}/compose/fairminter"),
        &[
            ("asset", asset.into()),
            ("price", ((0.1_f64 * XCP_DEC as f64) as u64).to_string()), // 0.1 XCP
            ("quantity_by_price", (1_000_u64 * TOK_DEC).to_string()),   // 1000 tokens
            ("hard_cap", (100_000_000_u64 * TOK_DEC).to_string()),      // 100M
            ("soft_cap", (69_000_000_u64 * TOK_DEC).to_string()),       // 69M
            ("start_block", start_block.to_string()),
            ("end_block", end_block.to_string()),
            ("soft_cap_deadline_block", soft_cap_deadline.to_string()), // XCP-420: must be < end_block
            ("burn_payment", "false".into()),
            ("lock_quantity", "true".into()),
            ("divisible", "true".into()),
            ("premint_quantity", "0".into()),
            ("minted_asset_commission", "0".into()),
            ("return_only_data", "true".into()),
            ("validate", "false".into()),
        ],
    )
}

pub fn cp_compose_order_asset(
    client: &Client,
    base: &str,
    addr: &str,
    give_xcp: u64,
    asset: &str,
    get_tok: u64,
    expiration: u32,
) -> Result<Vec<u8>> {
    cp_get(
        client,
        base,
        &format!("/addresses/{addr}/compose/order"),
        &[
            ("give_asset", "XCP".into()),
            ("give_quantity", (give_xcp * XCP_DEC).to_string()),
            ("get_asset", asset.into()),
            ("get_quantity", (get_tok * TOK_DEC).to_string()),
            ("expiration", expiration.to_string()),
            ("fee_required", "0".into()),
            ("return_only_data", "true".into()),
            ("validate", "false".into()),
        ],
    )
}

pub fn cp_compose_destroy(
    client: &Client,
    base: &str,
    addr: &str,
    asset: &str,
    qty_tokens: u64,
    tag: &str,
) -> Result<Vec<u8>> {
    cp_get(
        client,
        base,
        &format!("/addresses/{addr}/compose/destroy"),
        &[
            ("asset", asset.into()),
            ("quantity", (qty_tokens * TOK_DEC).to_string()),
            ("tag", tag.into()),
            ("return_only_data", "true".into()),
            ("validate", "false".into()),
        ],
    )
}

pub fn cp_compose_send_xcp(
    client: &Client,
    base: &str,
    addr: &str,
    dest: &str,
    qty_xcp: u64,
) -> Result<Vec<u8>> {
    cp_get(
        client,
        base,
        &format!("/addresses/{addr}/compose/send"),
        &[
            ("destination", dest.into()),
            ("asset", "XCP".into()),
            ("quantity", (qty_xcp * XCP_DEC).to_string()),
            ("return_only_data", "true".into()),
            ("validate", "false".into()),
        ],
    )
}

pub fn cp_compose_dividend(
    client: &Client,
    base: &str,
    addr: &str,
    holder_asset: &str,       // Token holders who receive the dividend
    quantity_per_unit: u64,   // XCP-per-unit (atomic)
) -> Result<Vec<u8>> {
    cp_get(
        client,
        base,
        &format!("/addresses/{}/compose/dividend", addr),
        &[
            ("asset", holder_asset.into()),          // Holders of YOUR TOKEN
            ("dividend_asset", "XCP".into()),        // Paid in XCP
            ("quantity_per_unit", quantity_per_unit.to_string()),
            ("return_only_data", "true".into()),
            ("validate", "false".into()),
        ],
    )
}

pub fn cp_compose_sweep(
    client: &Client,
    base: &str,
    addr: &str,          // source (the vault address)
    destination: &str,   // where to sweep to (your platform/destination address)
    flags: u32,          // bitmask (1 = FLAG_BALANCES; 2 = FLAG_OWNERSHIP; 4 = FLAG_BINARY_MEMO)
    memo_hex: &str,      // hex-encoded memo (Counterparty marks it as required; "00" is fine)
) -> Result<Vec<u8>> {
    cp_get(
        client,
        base,
        &format!("/addresses/{addr}/compose/sweep"),
        &[
            ("destination", destination.into()),
            ("flags", flags.to_string()),
            ("memo", memo_hex.into()),
            ("return_only_data", "true".into()),
            ("validate", "false".into()),
        ],
    )
}

