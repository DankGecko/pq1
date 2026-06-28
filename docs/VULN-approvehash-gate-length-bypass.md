# VULN — Safe `approveHash` mandatory-clear-sign gate bypassed by a trailing calldata byte

**Severity:** HIGH (WYSIWYS) — automated 4-agent adversarial consensus rated MEDIUM; see *Severity* below.
**Status:** FIXED 2026-06-28 (working tree). Found via the multi-agent WYSIWYS audit workflow (`wysiwys-adversarial-audit`), region `single-tx-misc`, 3/3 REAL after adversarial verification.
**Class:** Parser differential (firmware gate vs on-chain ABI decoder) → mandatory clear-sign control downgraded to generic blind-sign.

## Summary

A malicious companion could make the device **blind-sign** a Gnosis Safe `approveHash(bytes32)`
call — invisibly pre-authorizing an **arbitrary, never-displayed SafeTx** — by appending a single
padding byte to the inner calldata. Present in **both** the single-tx (`cmd_sign_userop.rs`) and
batch (`cmd_sign_userop_batch.rs`) sign handlers.

A Gnosis Safe treats an owner's recorded `approveHash` as that owner's **full signature** on the
entire SafeTx (the pre-approved-hash signature type `{r: ownerAddress, s: 0, v: 1}`). So obtaining
the wallet's `approveHash` over an attacker-chosen `safeTxHash` is equivalent to obtaining the
wallet's signature on a complete, attacker-authored SafeTx — a full drain of any Safe the PQ1
wallet co-signs.

## Mechanism (confirmed end-to-end in source)

The mandatory gate that forces `approveHash` to clear-sign keyed on an **exact** calldata length:

```rust
// cmd_sign_userop.rs:1010-1012 (and the identical twin at cmd_sign_userop_batch.rs:728-731)
let safe_selector  = inner_data.len() >= 4 && inner_data[..4] == APPROVE_HASH_SELECTOR;
let safe_calldata_len = inner_data.len() == APPROVE_HASH_CALLDATA_LEN;   // == 36
if safe_selector && safe_calldata_len && safe_v1_verified.is_none() {
    ui::show_status("Safe sign", "safe_v1 required");
    return NscStatus::InvalidPointer as u32;                            // refuse
}
```

`safe::verify::verify_and_bind_trailer` also bails on `inner_data.len() != APPROVE_HASH_CALLDATA_LEN`
(`verify.rs:113`), so an over-long `approveHash` has **no clear-sign path at all**.

On-chain, `Safe.approveHash(bytes32 hashToApprove)` reads calldata word `[4..36]` and **ignores
trailing calldata** — Solidity external dispatch never reverts on extra bytes. So:

```
inner_data = 0xd4d9bdcd ‖ maliciousSafeTxHash(32 B) ‖ 0x00      // length 37
```

- `safe_calldata_len = (37 == 36) = false` → **gate skipped**
- `verify_and_bind_trailer` → `None` (len 37 ≠ 36) → `safe_v1_verified = None`
- `pick_sign_pages_inner` → no Safe/CoW/erc7730/erc20 match → `render_blind_sign_pages`

The blind-sign page shows only `! BLIND SIGN / Unknown call / Verify on dapp`, `To: <Safe>`,
`Sel: 0xd4d9bdcd`, the data length, and `sha256(data)`. The selectors DB has **no** entry for
`0xd4d9bdcd`, so the user gets no hint this is a Safe approval, and the 32-byte `safeTxHash` is
**never decoded**. On-chain the wallet executes `Safe.approveHash(maliciousSafeTxHash)` (trailing
byte ignored), recording the wallet's approval of an attacker-authored SafeTx.

The sibling CoW `setPreSignature` gate (`cmd_sign_userop.rs:964`) and the Safe `execTransaction`
gate (`:1025`) key on the **selector** (and `>=` length) and were never length-bypassable.
`approveHash` was the only `==`-length gate, bypassable in exactly the over-long direction the
on-chain function tolerates.

## Reachability

PRODUCTION_REACHABLE. PQ1 wallets co-signing Gnosis Safes is a first-class supported scenario (the
entire Safe clear-signing feature exists for it). No special data, no shipped descriptor — just a
37-byte inner calldata from the (untrusted) companion and a target Safe the wallet co-owns.

## Severity

The automated consensus (finder + 3 adversarial skeptics, 3/3 REAL) rated **MEDIUM**: the device
shows a *loud* blind-sign warning (not a fake-benign screen), so a disciplined user could refuse,
and the drain is conditional on Safe co-ownership + the user blind-signing + the attacker then
executing the SafeTx.

Rated **HIGH** here because: (1) it silently defeats a *mandatory-by-design* security control
(CLAUDE.md: "the companion never gets to substitute a hash") via a trivial one-byte craft; (2) the
blind-sign warning is *generic* — identical to every routine DeFi blind-sign — so it carries no
signal that THIS sign is a full SafeTx pre-approval, which is exactly the distinction the gate
exists to preserve (the codebase already hard-gates the identical CoW case for this reason); and
(3) the impact is total loss of a co-signed Safe.

## Fix

Key the gate on the **selector alone**, via a shared host-testable predicate (the repo's
"one decision, two handlers can't drift" idiom, like `is_multisend_claim`):

```rust
// secure/src/tx/eip712/safe/mod.rs
#[must_use]
pub fn is_approve_hash_claim(inner_data: &[u8]) -> bool {
    inner_data.len() >= 4 && inner_data[..4] == APPROVE_HASH_SELECTOR
}
```

Both handlers now:

```rust
if crate::tx::eip712::safe::is_approve_hash_claim(inner_data) && safe_v1_verified.is_none() {
    ui::show_status("Safe sign", "safe_v1 required");
    return NscStatus::InvalidPointer as u32;
}
```

Any `approveHash`-selectored inner call that did not produce a verified `safe_v1` canonical is now
refused, never blind-signed. A well-formed clear-signable `approveHash` is exactly 36 B and always
arrives with its verifying trailer, so legitimate flows are unaffected. The `verify.rs:113` exact-36
check on the clear-signable *canonical* is retained (correct — that path requires the canonical
SafeTx).

## Tests / evidence

- New unit regression `tx::eip712::safe::...::approve_hash_claim_keys_on_selector_not_length` —
  pins selector-only claim for exact-36, 37 (the bypass), long, and selector-only calldata; rejects
  non-approveHash and sub-selector.
- `negative_slice_pins_safe_downgrade_mitigation_gate` updated to pin `is_approve_hash_claim` and
  **guard against regressing** to an exact-length test (`!contains("APPROVE_HASH_CALLDATA_LEN")`).
- `cargo test -p sphincs-tz-secure --tests --release` → **2142 passed, 0 failed**.
- `make secure` (thumbv8m firmware) → builds clean.
- `make e2e` (QEMU) → all scenarios pass (Safe / batch / multiSend included).
