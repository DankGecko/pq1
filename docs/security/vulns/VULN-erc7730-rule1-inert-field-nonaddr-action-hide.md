# VULN — ERC-7730 WYSIWYS gate: rule-1 "effect-bearing field" accepted INERT fields → a clear-sign banner over a fully-hidden action

> **2026-07-10 follow-up:** this report preserves the narrower 2026-07-01
> remediation history. Its decision to defer Rule 3 is superseded: dbgen now
> rejects every hidden non-address operand and all semantic signature/path
> exemptions. See
> [`clear-signing-2026-07-10.md`](../adversarial-review/findings/clear-signing-2026-07-10.md#f8--hidden-material-and-semantic-exemptions-could-conceal-signed-action-bytes).

- **Severity:** HIGH (integrity / trusted-display boundary). **Latent** (the one live shipping witness is impotent against a PQ1 EIP-1271 wallet by an *external* contract property — Rarible verifies `from` via `ecrecover`, not by any PQ1 control), rated HIGH on the same basis the sibling `VULN-erc7730-visible-never-noparam-clearsign` used: the control was simply absent and the auto-vendored corpus can grow the affected set unchecked.
- **Class:** WYSIWYS / clear-sign supply-chain gate hole. Sibling of the FIXED `visible:"never"` (address-recipient) and `eip712-nested-struct` (address-in-struct) findings.
- **Status:** **FIXED (2026-07-01)** — build-time **Rule 1** now requires a genuinely effect-bearing shown field. Corpus regenerated (**784 → 783 leaves**; new `ERC7730_DESCRIPTORS_ROOT` `0xaa64b785…`). The Rule-3 half (gating hidden *non-address values*) was **deliberately NOT taken** — see **§Scope: why Rule 1 only**. Found by exhaustive adversarial hunt (2 multi-agent workflows + manual verification).
- **Reachability:** software-triggerable by an untrusted companion after one ordinary PIN unlock; no fault injection; rides descriptors auto-vendored from a mutable third-party registry. The current corpus is still `dev-unattested`; production is quarantined until the missing authenticated ERC-8176 verifier and external attestation population exist.

## The gap in one sentence

The build-time visibility gate's **rule 1** was supposed to guarantee "a clear-signed known shape surfaces at least one *effect-bearing* field" (its own comment and error string said exactly that), but its **implementation accepted *any* shown argument** — including inert identity / nonce / salt / deadline fields — so a descriptor could render an inert field (`from`, `nonce`) and mark its **sole effect-bearing operand** `visible:"never"`, painting a trusted, reassuring intent banner while the actual action stayed invisible.

## Root cause (code)

`dbgen/src/erc7730.rs`, `check_field_visibility` rule 1 (pre-fix) accepted `path_top_param_index(p, parsed).is_some()` for ANY shown arg. `path_top_param_index("from", …)` is `Some` for a Rarible `MetaTransaction`'s `from` field even though `from` is the signer's own address (`== msg.sender`, inert) and `nonce` is a replay counter — neither tells the user *what the call does*.

## Live shipping witness

`secure/data/erc7730-registry/registry/rarible/eip712-rarible-exchange-v2-meta-tx.json` shipped in the compiled prod corpus (chain 137, verifying contract `0x7f19564c…aa53`):

```
MetaTransaction(uint256 nonce, address from, bytes functionSignature)
  from               : "User Address"            visible=always   (INERT — == the signer)
  nonce              : "Meta Transaction Nonce"  visible=always   (INERT — replay counter)
  functionSignature  : "Function Signature"      visible=never    (THE ENTIRE meta-executed action — HIDDEN)
```

The device clear-signed `Meta Transaction` → `User Address` → `Meta Transaction Nonce` → fingerprint → confirm, with `functionSignature` (an arbitrary call executed *as the user* by the meta-tx forwarder) never surfaced and **zero** on-screen signal that anything was hidden. Impotent for a PQ1 *contract* wallet only because Rarible's `NativeMetaTransaction` verifies `from` via `ecrecover` (an external property, not a PQ1 control); the firmware would happily clear-sign + EIP-1271-sign the shape.

## Fix applied (2026-07-01) — Rule 1

`dbgen/src/erc7730.rs::check_field_visibility`. A visible field now satisfies rule 1 only when it resolves to the native tx value **or** to a calldata argument whose top-level name is **not an inert self-identity / replay role** (`is_inert_role_name`: `from`/`sender`/`owner`/`holder`/`nonce`/`salt`/`deadline`/`validAfter`/`validUntil`/`validBefore`/`expiry`/`expiration`). The inert set is deliberately narrow — it **excludes** `signer`/`to`/`spender`/`recipient`/`target`/`account` (the address a call *acts on* is a genuine effect; Celo `authorizeVoteSigner(address signer)` legitimately shows exactly `signer`).

**Corpus impact (verified):** exactly **1** descriptor refused — the Rarible `MetaTransaction` witness (chain 137), which drops to loud blind-sign. **Zero** legitimate false positives across the 784-leaf corpus. New `ERC7730_DESCRIPTORS_ROOT 0xaa64b785…`. 3 new dbgen regression tests (inert-only refuse, `signer` pass, shown-amount pass). dbgen 130/130, roundtrip 10/10, `gen-erc7730-descriptors --check` in sync, secure host 2035/2035.

## Scope: why Rule 1 only (Rule 3 deferred to a documented team decision)

The original write-up also proposed a **Rule 3** to gate a hidden *non-address* effect-bearing operand (a `bytes` action-payload / `bytes32` recipient / `uint256[]`) and an on-device dynamic-leaf belt. Both were **intentionally not taken here**, for two independent reasons established the same day:

1. **The on-device belt is not viable.** A corpus check found **54** shipping descriptors that legitimately hide a dynamic `bytes`/`string` (ECDSA `permit`/`signature`, opaque `r`/`s`, economically-bounded executor blobs). A blanket "decline any hidden dynamic leaf" belt would regress 1inch/paraswap/aave/lido/celo/lens/safe clear-signs to blind-sign. The build gate is the load-bearing layer (same stance as rule 2's hidden-address check).

2. **A structural Rule-3 gate for hidden non-address VALUES is net-negative — a deliberate, measured decision.** `VULN-erc7730-visible-never-noparam-clearsign.md` §"Non-address hidden-value residual" (commit `28fa14a7`, 2026-07-01) records an empirical pass: a `bytes`/`string`/array gate → 0 true positives / 2 false positives (Ondo `bytes signature`); an arrays-only gate → 0 TP / 5 FP (Lido `_hints`, 1inch `makerTraits`, celo `dataLengths`). Unlike an `address` (rare-to-hide + always fund-routing), a hidden non-address value is **type-indistinguishable** from a benign one, so a structural gate over-fires with no true positive. There is a code NOTE at the `check_field_visibility` tail recording this "no rule-3 gate" decision so it is not re-litigated.

Rule 1 asks a **different** question than Rule 3 — "is anything effect-bearing SHOWN?" rather than "is a specific hidden value dangerous?" — so it is complementary to that decision, not a reversal of it: it closes the one live witness (the Rarible meta-tx, which shows *only* inert fields and which the residual analysis — assuming "the recipient/intent IS shown" — did not cover) with zero corpus false positives.

**Residual (accepted for development, MEDIUM; ERC-8176 backstop still
missing):** a descriptor that hides an effect-bearing scalar value /
executable-calldata payload **while a non-inert field (recipient/intent) IS
shown** — e.g. a hypothetical `execute(address target, bytes data)` that shows
`target` and hides `data`. Rule 1 does not catch this and none ship today. The
current corpus remains `dev-unattested`; production stays quarantined until the
separate authenticated ERC-8176 verifier and external evidence exist. Tracked
in the residual section above.
