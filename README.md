# XCP-69 NUMS Vault (Taproot script-path) — README

> Trustless, time-phased issuance & distribution for Counterparty assets using a Taproot vault with a NUMS internal key, fully auditable and broadcastable by anyone. Includes a **sweep-fallback** path with a published, deterministic policy.

---

## What this is

This toolchain builds and operates an **XCP-69** vault:

* **Vault type:** Taproot P2TR output with **no keypath spend** (NUMS internal key), **script-path only** via CLTV leaves.
* **Phases:**

  * **T0**: Fairminter create
  * **T1**: Order ladder
  * **T2a**: Fees & destroys
  * **T2b**: Dividends (per-unit rungs)
* **Publication model:** You publish a complete **bundle** (manifest) with *all* parent transactions and pre-signed CPFP children. Anyone can verify and broadcast.
* **Fallback:** If dividend is griefed (e.g., Sybil dust), you execute a **Counterparty `sweep`** to your platform address and do a **manual distribution** from there under a **published rule** (see “Fallback policy” below).

---

## Why NUMS + Taproot?

* **No keypath spend:** The internal key is a standard BIP-341 **NUMS point** `H`, tweaked by a random `r` you disclose (`K_int = H + r·G`), so nobody has a private key for `H`. All spends must go through the tapscripts you published.
* **Tapscript leaves (CLTV):** Four leaves (T0, T1, T2a, T2b) each enforce height gates. The witness for every parent is `[schnorr_sig, leaf_script, control_block]`.
* **Auditable control:** Anyone can recompute the Taproot commit `(K_int, merkle_root) → Q` and match `Q` to the vault address.

---

## Threat model, grievances & defenses

### Can someone “make their own” UTXOs to get into the flow?

No. Every parent spend here **consumes a single vault UTXO** controlled by `Q`. Outsiders can’t produce alternative inputs that satisfy the spend. They **can** rebroadcast the exact transactions you already signed (see “Broadcast & fee bumping”).

### Dividend grief via dust Sybils (XCP issuer fee)

Counterparty charges an issuer fee **per recipient** for dividends. An attacker could scatter dust balances across many new addresses to inflate that fee and sabotage the dividend.

**Defense used here:**

1. You **pre-publish** all dividend rungs *and* a **fallback sweep plan**.
2. At T2b you evaluate a **deterministic rule**. If griefed, you **broadcast a Counterparty `sweep`** of balances to your platform address and **manually distribute** XCP from there.

**Fallback policy (published and binding):**

* **Eligibility threshold:** Holders must have **more than 1,000 whole units** of the token (strict `> 1000`) to receive the fallback distribution.
* **Rationale:** This caps “dust recipient” explosion while preserving fairness for real holders.
* **Transparency:** You publish the block-height snapshot, the filtered recipient list, and the distribution transactions.

### “Commit but not reveal” risk

We eliminate selective reveal by **publishing everything** (PSBTs, fully signed parents, and CPFP children) up-front. The bundle is hashed and (optionally) pinned on-chain.

---

## What anyone can do vs. what only you can do

* **Anyone can broadcast** any of the **published** parent transactions at/after their CLTV height.
* **Anyone can fee-bump** by rebroadcasting the **pre-signed CPFP children** you published.
* **Only you** (holder of the **anchor key**) can author **new** CPFP transactions beyond the published ones. (Design choice: we publish ready-to-use children, but keep the anchor key controlled to avoid abuse.)

---

## Install

* Rust toolchain (edition 2021)
* Build:

  ```bash
  cargo build --release
  ```
* Binaries:

  * `xcp69_setup` (main CLI)
  * `verify_bundle` (bundle auditor)

---

## Quick start (end-to-end)

1. **Setup** — grind NUMS vanity, build tapscripts & unsigned parent PSBTs, and create a funding PSBT template:

   ```bash
   xcp69_setup setup \
     --network mainnet \
     --cp-base https://api.counterparty.io:4000/v2 \
     --asset YOURTOKEN \
     --mend <block> \
     --gap 20 \
     --expiration 8064 \
     --platform-xcp-dest <XCP_ADDR> \
     --mode suffix --pattern <bech32-suffix> --threads <N> \
     --funding-utxos "txid:vout:value_sat,..." \
     --funding-change <FEE_RETURN_ADDR> \
     --funding-type p2wpkh \
     --export-secret p_script.hex \
     --out bundle.json
   ```

2. **Fund** — sign and broadcast the funding PSBT from your fee wallet (external wallet). Wait for confirmation.

3. **Prepare funding (optional helper)** — discover fee wallet UTXOs and build a funding PSBT automatically:

   ```bash
   xcp69_setup prepare-funding \
     --bundle bundle.json \
     --fee-key <WIF_or_hex> \
     --rpc-url http://user:pass@127.0.0.1:8332 \
     --network mainnet \
     --out bundle_with_funding.json
   ```

4. **Patch/Finalize** — patch the real funding txid and produce **fully signed parents + CPFP children**, plus a **commitment hash**:

   ```bash
   xcp69_setup finalize-parents \
     --bundle bundle_with_funding.json \
     --funding-txid <FUNDING_TXID> \
     --p-script-file p_script.hex \
     --out finalized_bundle.json
   ```

5. **Publish** — share `finalized_bundle.json` (the manifest). Optionally publish `sha256(finalized_bundle.json)` via OP_RETURN or a Git tag and sign with PGP.

6. **Verify (community / you)**:

   ```bash
   cargo run --bin verify_bundle -- --bundle finalized_bundle.json
   ```

7. **Operate** — at each phase height, **anyone may broadcast** the relevant parent + (if needed) **rebroadcast** the matching CPFP child to bump fees.

8. **Dividend vs. Sweep decision at T2b** — follow the **published rule**:

   * If holder set looks clean: broadcast pre-published **dividend rungs** (largest→smallest within budget).
   * If griefed or fee-infeasible: broadcast the **published Counterparty `sweep`** (see below) and perform **manual distribution** using the eligibility rule `> 1000` units.

---

## The bundle (what you publish)

Fields include:

* **Vault & tapscript**

  * Network, vault address, `nums_proof` (`H`, `r`, `K_int`, `Q`)
  * `tapscript_pubkey` (`P_script` xonly), `merkle_root`
  * Phase heights `t0, t1, t2a, t2b`
* **Funding**

  * `funding_psbt_b64`, number/value of intended vault UTXOs
* **Entries** (per parent)

  * `{name, phase, lock_height, purpose, opret_hex, psbt_b64, utxo, value_sat}`
* **Finalized artifacts**

  * `parent_txs_hex[]` (all signed parents)
  * `cpfp_txs_hex[]` (all signed children)
  * `commitment_hash` (SHA256 of the ordered parents)
* **Sweep fallback**

  * The **composed `sweep` data** (see below) and the **published policy** text you include with the release.

The `verify_bundle` tool checks:

* CLTV heights and scripts match the phase
* Control blocks commit to `(K_int, merkle_root) → Q`
* Schnorr sigs verify against `P_script`
* OP_RETURN bytes equal `opret_hex`
* `commitment_hash` matches the included `parent_txs_hex[]`

---

## Counterparty sweep (fallback lane)

When dividend griefing (or fee infeasibility) is detected by the published rule, execute a **balance sweep** of the vault’s address to your platform address.

**Compose (documented by CP API):**

* Endpoint: `GET /v2/addresses/{address}/compose/sweep`
* Required params:

  * `destination=<YOUR_PLATFORM_P2TR_or_P2WSH_or_P2WPKH>`
  * `flags=<FLAG_BALANCES or FLAG_BALANCES|FLAG_OWNERSHIP>`
    (For balance-only: `flags=1`)
  * `memo=<hex>` (you can use a short tag, e.g., `DEADBEAF`)
* Suggested params:

  * `return_only_data=true`
  * `segwit=true`
  * `verbose=true`

You include the returned `data` blob (hex) as `opret_hex` for a **single** T2b parent that performs the sweep via the vault UTXO, analogous to other parents. (In this design we replace multi-rung XCP “sweeps” with **one** Counterparty Sweep instruction.)

> Note: the codebase includes a `compose_sweep` helper (mirrors other `cp_compose_*` helpers) and swaps the prior “post-dividend sweep rungs” with a single sweep entry.

---

## Fallback manual distribution policy (published & deterministic)

When the sweep path is triggered, you will **manually distribute XCP** from the platform address to **eligible holders** only.

**Policy:**

* **Eligibility:** token balance **strictly greater than 1,000 whole units** (`balance > 1000 * 10^8` atomic).
* **Snapshot height:** `t2b - 1` (published).
* **Exclusions:** known Sybil/dust patterns may be excluded if they evade the threshold.
* **Transparency:** publish

  * the snapshot (address, balance),
  * the filtered list (≥ 1,000 units),
  * the distribution amounts & transaction IDs.

**Why `> 1000`?** It removes cost-effective dust attacks while keeping real holders in scope.

> If you prefer, you can commit to a hard cap on recipients (e.g., ≤ 25k) or a quality metric (median balance floor) — but the explicit `> 1000` rule is simple, verifiable, and already sufficient to blunt dust Sybils.

---

## Broadcast & fee bumping

* **Broadcast:** Any observer can push any included **parent tx hex** once CLTV is met.
* **Fee bumping:** Any observer can push the matching **pre-signed CPFP child** you published to raise effective fee.

  * Only the anchor key can author *new* CPFPs, but this is not required for liveness if you publish viable children.

---

## CLI reference

### `setup`

Creates tapscript tree, grinds a vanity Taproot vault using NUMS, composes all Counterparty messages, builds unsigned PSBTs, and emits `bundle.json`.

Key options:

* `--network mainnet|testnet|signet`
* `--asset YOURTOKEN`
* `--mend <block>` (end of minting window)
* `--gap 20` (phase spacing)
* `--expiration 8064` (order expiration blocks)
* `--platform-xcp-dest <ADDR>`
* Vanity grind: `--mode prefix|suffix --pattern <bech32>`
* Funding: `--funding-utxos "txid:vout:value,..." --funding-change <ADDR> --funding-type p2wpkh`
* `--export-secret p_script.hex`
* `--out bundle.json`

### `prepare-funding`

Optionally finds fee wallet UTXOs and builds a funding PSBT automatically.

### `finalize-parents`

Injects the real funding txid, recomputes every parent sighash with the proper prevout, signs with `P_script`, builds CPFP children, and writes `finalized_bundle.json` with `commitment_hash`.

### `verify_bundle`

Audits a bundle: addresses, Taproot commitments, CLTV leaves, OP_RETURN payloads, Schnorr signatures, and the commitment hash.

---

## Operational tips

* **Anchors:** Keep `anchor_sats` generous (we default higher than bare minimum) so the pre-signed CPFP child has meaningful bump headroom at a wide fee range.
* **Per-unit dividend rungs:** The tool includes a 2^n “qpu” ladder capped at **0.0001 XCP per unit**. You broadcast largest→smallest until budget is consumed **only when the clean dividend path is chosen**.
* **Publication:** Always publish the full bundle + signature before phase heights. That’s your anti-“selective reveal” guarantee.

---

## FAQ

**Q:** What exactly proves “no keypath spend”?
**A:** You publish `H` (the BIP-341 NUMS point), your random `r`, and show `K_int = H + r·G`. Because `H` has no known discrete log and you only disclose `r` (not `r + x_H`), no key exists for `K_int + tweak·G` (the output key `Q`) other than the tapscripts you published.

**Q:** Why not let anyone author new CPFPs?
**A:** That invites anchor theft & grief. We publish ready-to-use children so **anyone can bump fees** without granting new signing power.

**Q:** How do I prove I followed the fallback policy?
**A:** Publish the block-indexed snapshot (hash the CSV), the filtered list (`balance > 1000 * 10^8`), and the outgoing payments from the platform address. Third parties can reproduce the filter from chain data.

---

## License & safety

* No warranty. Test on **signet/testnet** first.
* Review the bundle with `verify_bundle` and independent tooling.
* Counterparty server semantics (fees, flags) may evolve; pin the API version you use in production documentation.
