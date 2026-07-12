# VULN — ERC-7730 `visible:"never"` lets a shipping descriptor clear-sign with **no parameters shown** (WYSIWYS break)

> **2026-07-10 follow-up:** the original address/all-hidden fix below was
> tightened. Every hidden non-address operand is now excluded too, semantic
> hidden-address allowlists were deleted, and a verified/registry-declared call
> that cannot render hard-refuses rather than falling through to blind-sign.
> The historical “non-address residual accepted” and fallback wording below no
> longer describes current behavior. See
> [`clear-signing-2026-07-10.md`](../adversarial-review/findings/clear-signing-2026-07-10.md#f8--hidden-material-and-semantic-exemptions-could-conceal-signed-action-bytes).

**Severity:** HIGH (WYSIWYS / trusted-display integrity — software-triggerable by an untrusted companion against a correctly-provisioned, unlocked device; breaks the product's core "you see exactly what you sign" guarantee for *known shapes*).
**Status:** **FIXED 2026-07-01** (found 2026-06-30). Closed with BOTH recommended layers — a build-time visibility gate that refuses to compile an offending descriptor (fixes 1) + an on-device WYSIWYS belt that refuses to clear-sign a parameter-less known shape (fix 2). See [§ Fix applied](#fix-applied). Firmware *logic* was clean; this was a firmware-**image** defect — the offending descriptors were compiled into the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`.
**Class:** Display↔intent mismatch ("show nothing / sign arbitrary params"). Not memory-safety, not key-theft. Whether a given hidden-param descriptor is a direct fund drain is protocol-dependent; the *guarantee* that a clear-signed known shape surfaces its effect-bearing parameters is broken regardless.
**Not previously known:** distinct from the documented ERC-7730 findings (walker slot-confusion, faithless/truncating formatters, encrypted-formatter, decimals inflation, erc20 metadata mis-attribution, CoW/Safe truncation). Prior audits *praised* the H-3 completeness lint; none noted that it explicitly permits hiding **every** parameter, nor that the production corpus is now an **auto-vendored** upstream registry compiled without per-field semantic review.

## Summary

The 2026-06-30 "corpus switch" made the production `ERC7730_DESCRIPTORS_ROOT` an **auto-vendored, tolerantly-compiled** copy of the upstream Ledger ERC-7730 registry (`xtask/src/main.rs:229` — `ERC7730_DEFAULT_INPUT = "secure/data/erc7730-registry/registry"`; 278/361 descriptors compile into **573** Merkle leaves). For those descriptors the on-device WYSIWYS guarantee rests **only** on per-field `visible` flags, and there is **no firmware or build rule that effect-bearing parameters must be displayed**:

- The build-time completeness lint `check_contract_field_completeness` (`dbgen/src/erc7730.rs:1657`, audit H-3) **explicitly counts `visible:"never"` fields as "accounted for"** — `dbgen/src/erc7730.rs:1669`: *"`visible:"never"` fields are included — an explicit hide is a conscious author decision."* A format therefore passes completeness even when **every** parameter is hidden.
- The device **silently skips** hidden fields: `should_render_with_mode` returns `Action::Skip` for `Visibility::Never` (`pqsigner-erc7730/src/render/visibility.rs:80`), and `render_fields` just `continue`s (`secure/src/tx/display/erc7730/mod.rs:339`) — it does **not** abort or fall through to blind-sign.

A descriptor can thus hide all (or the security-critical) parameters, still compile + ship, and the device renders it as a **trusted clear-sign**: intent banner (`mod.rs:138`) + envelope pages (chain / max-fee / worst-case / nonce) + confirm — with the parameters invisible. The user sees a reassuring "known shape" screen and signs whatever calldata the companion supplied.

## Proof it is live (not theoretical)

`cargo run -p pqsigner-xtask -- scan-registry --registry-root secure/data/erc7730-registry` → **278/361 descriptors compile = 573 prod leaves.** Cross-referencing the *compiling* formats against `address`-typed args that are `visible:"never"` yields **26 compiling formats that hide a routing-address argument.** The unambiguous witness:

```jsonc
// secure/data/erc7730-registry/registry/flyingtulip/calldata-SessionManager.json
"setAllowedTarget(address target, bool allowed)": {
  "fields": [
    { "path": "target",  "label": "Target",  "visible": "never" },   // ← HIDDEN
    { "path": "allowed", "label": "Allowed", "visible": "never" }     // ← HIDDEN
  ]
}
```

Both parameters are `visible:"never"`. The format **compiles** and **ships** in 7 deployments — `secure/data/erc7730.review.txt` entries `[0046] [0262] [0347] [0416] [0421] [0422] [0662]`, chains 1 / 56 / 146 / 43114, `descriptor_hash = 0x7670c505...`.

Attack (untrusted USB companion, device correctly provisioned + PIN-unlocked once):
1. Companion sets the inner-tx `to` = a shipped SessionManager address and supplies calldata `setAllowedTarget(<attacker target>, true)`, plus the (Merkle-verified) descriptor bundle.
2. `cross_check_contract` passes (`to` == descriptor contract, chain matches). ERC-7730 render engages.
3. `render_erc7730_pages_inner`: banner "Set Allowed Target" → `render_fields` skips **both** fields → envelope pages → confirm. `tx.value == 0`, so the dispatcher's `enforce_native_value_page` splices nothing.
4. The trusted display shows: **"Set Allowed Target" + Chain + Max fee + Worst-case + Nonce + Confirm** — **no target, no allow/deny**. The user confirms an arbitrary session-target authorization blind, behind a screen the product promises is "the exact intent."

Same family: `createSessionBySig` (delegate + per-token spend limits all hidden), `validateAndConsume` (`spendToken` / `executor` hidden), `invalidateNonceBySig`.

This directly violates the headline invariant (`CLAUDE.md`, "Trusted-display clear-signing"): *"Every signable artifact is decoded and rendered inside the secure world before the user presses confirm — no blind-sign path for known shapes … the user sees the exact intent."* Here a **known shape** is clear-signed with its parameters invisible — a blind-sign wearing a trusted clear-sign banner, which is worse than an honest loud blind-sign because the intent banner *reassures* the user.

## Honest scope of the current corpus

Of the 26 compiling routing-address-hiding formats, most are **mitigated** and I could not turn them into a direct drain:
- **1inch / ParaSwap `swap*`** hide `executor` / `srcReceiver`, but **show** the output recipient (`dstReceiver` / `beneficiary`) + amount + min-return, and the on-chain router enforces "lose ≤ amount, recipient gains ≥ min-return" — so the shown fields are the economically-binding ones.
- **Ondo `subscribe` / `redeem`** hide `depositToken` / `receivingToken`, but those are the `tokenPath` of the shown amount, so the token identity is surfaced in the amount's symbol/decimals (and the device fails **loud** — `! raw, dec=?` + an "UNVERIFIED token" page — when a `tokenAmount` token can't be Merkle-bound; `formatters.rs render_token_amount`).

The **session-management family (FlyingTulip) is not mitigated** — its hidden parameters *are* the security-relevant ones, and `setAllowedTarget` hides **all** of them. More importantly, the mitigation of the others is **upstream-curation luck, not a PQ1 guarantee**: nothing in the firmware or build stops the *next* registry resync (or a compromised/rogue registry entry) from shipping a hidden-recipient transfer/withdraw descriptor. The control is simply absent.

## Why HIGH

For a hardware wallet the trusted display is the entire security boundary; "you see exactly what you sign" for known shapes is the product's core promise (and an explicit non-negotiable in `CLAUDE.md`). A confirmed, currently-shipping code path where the device presents a **trusted, reassuring clear-sign that reveals none of a state-changing call's parameters** defeats that boundary for the affected descriptors, with **zero user-visible signal** that anything is hidden. It is software-reachable by an untrusted companion after one ordinary PIN unlock, requires no fault injection, and rides descriptors that are **auto-vendored from a mutable third party** — so the population of affected shapes can grow with any corpus update, unchecked. The direct end-to-end fund loss is protocol-dependent (session-key escalation for the FlyingTulip witness; a future recipient-hiding descriptor would be an outright drain), which is why this is HIGH (integrity/trusted-display) rather than a flatly CRITICAL universal drain.

## Root cause

The clear-sign trust pipeline delegates *"which fields the user must see"* entirely to per-descriptor `visible` flags, and:
1. the build lint (H-3) treats `visible:"never"` as satisfying completeness for **any** field (`dbgen/src/erc7730.rs:1669`), including all-hidden and recipient-hidden formats;
2. the on-device visibility evaluator silently drops `Never` fields (`visibility.rs:80`) without ever declining-to-blind (`mod.rs:339`);
3. the production corpus was switched to the auto-vendored upstream registry (`xtask:229`) and compiled *tolerantly* — descriptors that fail to compile are dropped to safe blind-sign, but a descriptor that compiles with all-hidden params is shipped as a trusted clear-sign.

There is no invariant anywhere that "a compiled contract-context format must surface at least its effect-bearing parameters."

## Suggested fixes (design choice for the owner)

1. **Build-time gate (primary).** In `compile_one_format`, after collecting field visibility, **reject** a contract-context format that (a) ends up with **zero** visible fields, or (b) marks any `address`-typed argument (top-level or rendered-tuple member) or the sole/primary value argument as `visible:"never"` — unless the `(contract, selector, path)` is on a reviewed allowlist of non-routing roles (relayer / fee-collector / router-executor-behind-min-output, with a written rationale). This makes "every state-changing known shape surfaces its security-critical parameters" a hard invariant the auto-vendored corpus cannot silently violate; offending descriptors drop to loud blind-sign instead of a reassuring empty clear-sign.
2. **On-device belt (defense in depth).** In `render_erc7730_pages_inner`, if `render_fields` produced **zero** field pages for a contract-context format, return `RenderErr::Reject("7730 no visible fields")` so `pick_sign_pages_inner` falls through to the honest blind-sign ladder (which shows the raw target/selector loudly) instead of a parameter-less clear-sign.
3. **Corpus governance.** Treat the vendored registry as untrusted input: run the gate in (1) as a CI check on every `vendor-registry` / resync, and record per-descriptor per-field visibility diffs in the review file so an auditor reconciles every hidden effect-bearing field.

Recommended: (1) + (2) together — (1) prevents shipping the offending descriptors, (2) fails safe even if a future descriptor slips the allowlist or a non-contract shape hits the same path.

## Fix applied

**Commit (2026-07-01).** Both recommended layers landed; a refused format drops to loud blind-sign (tolerant registry corpus) or hard-errors a hand-authored strict descriptor.

### 1. Build-time visibility gate (primary) — `dbgen/src/erc7730.rs`

New `check_field_visibility(sig, fmt, parsed, context_kind, allow)`, called inside `compile_one_format` for **every** contract- and EIP-712-context format (unavoidable code path). It sits beside the completeness lints: completeness proves every argument is *declared* (rendered OR `visible:"never"`); this proves the effect-bearing ones are *shown*. Two fail-safe rules:

1. **No parameter-less clear-sign.** A function with ≥1 argument must surface at least one of them — a visible field whose path resolves to a calldata/typed argument, OR the native transaction value (`@.value`, so a payable `submit`/stake whose ETH is the intent still clear-signs). Refuses the all-`visible:"never"` witnesses (`setAllowedTarget`, `transferOwnership`, `createSessionBySig`, …).
2. **No hidden fund-routing address.** Every `address`-typed argument (top-level, and — contract path — each individually-addressable static-tuple member) must be shown, directly or as the `tokenPath` of a shown amount (which surfaces the token identity, so Ondo-style token-address args pass). A hidden address is refused unless a reviewed `hidden_address_allow` policy entry re-permits it **with a written rationale** (router-executor-behind-min-output / relayer / linked-list hint). `type_contains_address` is a token-exact scan (no `uint256`/`bytes32` false hit).

Allowlist mechanism: `Policy.hidden_address_allow: Vec<HiddenAddressAllow{ signature, path, rationale }>` in `secure/data/erc7730/policy.toml`. Ships with ONE reviewed entry — Lido `submit(address _referral)`/`_referral` (a referral tag that routes no funds; the effect is the staked `msg.value`, shown loud). An entry with an empty rationale is ignored (fails safe). Everything else that hides an address drops to blind-sign.

### 2. On-device belt (defense in depth) — `secure/src/tx/display/erc7730/mod.rs`

In both `render_erc7730_pages_inner` (calldata) and `render_erc7730_eip712_pages_inner` (typed-data): if the format DECLARES fields (`field_count > 0`) but `render_fields` appended ZERO field pages (every field skipped as `visible:"never"`), return `RenderErr::Reject(...)` so `pick_sign_pages_inner` falls through to the honest blind-sign / raw-digest ladder instead of a banner-only clear-sign. Zero-field formats (`deposit()`) are unaffected; payable stakes (`submit`) render their `@.value` field and pass. This is the structural guarantee that holds even if a bad descriptor ever reaches the Merkle-pinned root.

### Corpus regenerated

`cargo run -p dbgen` re-emitted `erc7730_db.bin` / `erc7730.review.txt` / `db_roots.rs` — the offending formats dropped: prod leaves **776 → 688**, and the FlyingTulip `SessionManager` IR shrank **468 → 196 B** (only the all-visible `createSession` survives; `setAllowedTarget` et al. blind-sign). Only the prod `ERC7730_DESCRIPTORS_ROOT` changed (`2762c6ce… → 66dde735…`); the e2e root and all other DB roots are unchanged. `gen-erc7730-descriptors --check` reports **in sync**.

### Tests

- `dbgen`: 12 new unit tests (`type_contains_address_is_token_exact`, `visibility_all_hidden_rejected` [the live `setAllowedTarget` witness], `visibility_hidden_recipient_rejected`, `visibility_all_shown_transfer_ok`, `visibility_zero_arg_ok`, `visibility_hidden_nonaddress_ok`, `visibility_tokenpath_surfaced_address_ok`, `visibility_tuple_member_hidden_address_rejected`, `visibility_allowlist_requires_rationale`, `visibility_eip712_hidden_address_member_rejected`, `visibility_gate_runs_inside_compile_one_format`) + the seed corpus still compiles.
- `secure`: `belt_rejects_all_hidden_contract_format` drives the on-device belt end-to-end (compile a valid `optional`-field descriptor, flip its visibility TLV to `never`, render → `Reject`).
- Full suites green: `dbgen` (all), `pqsigner-erc7730` (78), `sphincs-tz-secure --tests --release` (2025), QEMU + `stm32u585` firmware builds.

### Residual / follow-up

- ~88 registry leaves now blind-sign (fail-safe UX regression). Curators can restore specific clear-sign UX by adding reviewed `hidden_address_allow` entries (with rationale) and re-running `dbgen` — a deliberate, logged human decision, not a silent default.
- The gate is now a CI-enforceable invariant on every `vendor-registry` resync (`gen-erc7730-descriptors --check`), so a future corpus update cannot silently re-introduce a hidden-recipient descriptor.
- **EIP-712 sibling — CLOSED** (`2f4cc810`, `VULN-erc7730-eip712-nested-struct-address-hide`): rule 2 now descends nested EIP-712 struct members (`check_eip712_member_addresses`) + a `PARAM_NESTED_STRUCT` on-device belt.

## Non-address hidden-value residual (analysed 2026-07-01 — DECISION: no structural gate; attestation-backstopped)

Rule 1/rule 2 force every **`address`** argument (and static-tuple / nested-struct address member) to be shown. They deliberately do **not** cover a hidden **non-address** effect-bearing value (a `uint256 amount`, a `bytes` payload, a `uint256[]` batch). This section records why closing that with a structural gate is **not** the right move, so it is not re-litigated.

**Why addresses are special (and non-address values are not).** A hidden `address` is *rare-to-hide-legitimately* and *always fund-routing*, giving rule 2 a favourable true-positive / false-positive ratio (the live FlyingTulip witness above). A hidden non-address value has neither property: it is **type-indistinguishable** from a benign hide (a `uint256` amount vs a `uint256` deadline; a `bytes` executed-call vs an opaque attestation `signature`; a `uint256[]` batch of amounts vs a `uint256[]` batch of gas hints), and the corpus hides such values **legitimately at scale**.

**Empirical measurement (the decisive evidence).** Two candidate rule-3 gates were implemented and measured against the live vendored corpus:
- **`bytes`/`string`/array variant** → dropped 2 leaves (Ondo `GMTokenManager.{mint,redeem}WithAttestation`), both hiding a `bytes signature` — an **opaque attestation signature** the user cannot validate by eye and which routes no funds. **0 true positives, 2 false positives.**
- **arrays-only variant** → dropped 0 leaves but silently refused **5 formats** inside multi-format descriptors: Lido `claimWithdrawals`/`claimWithdrawalsTo` (hidden `_hints:uint256[]` — gas-traversal hints), 1inch `cancelOrders` (hidden `makerTraits:uint256[]`, with `orderHashes` shown), celo `governance.propose`/`executeHotfix` (hidden `dataLengths:uint256[]` — packed-call split lengths, with `destinations`/`values` shown). **0 true positives, 5 false positives.**

Both variants catch **no real threat** in the corpus and only tax benign descriptors — the inverse of rule 2's ratio. A hidden non-address value is therefore left to blind-sign only if a descriptor *also* fails rule 1 (nothing shown) or rule 2 (a hidden address); a descriptor that shows the recipient/intent and hides an auxiliary value stays clear-signed.

**What already covers the high-severity cases** (so the residual is genuinely narrow):
- **Native `@.value`** is *always* spliced on-device by the FI-hardened `enforce_native_value_page` whenever `tx.value != 0`, regardless of the descriptor — a hidden payable value is shown.
- **Bare ERC-20 `transfer`/`approve`** render via the native ERC-20 decoder (`erc20_known`/`erc20_unknown`), which shows amount + recipient independent of any descriptor.

**The residual, scoped honestly:** a descriptor that hides an effect-bearing **scalar calldata value or payload** (e.g. a non-ERC-20 contract's amount, or an executed `bytes`) *while the recipient/intent IS shown*. Severity **MEDIUM** — funds go to a shown party, bounded by balance/allowance; it needs a malicious/careless descriptor in the Merkle-pinned root, not attacker calldata. Because it is type-indistinguishable from the benign hides the corpus makes constantly, the real backstop is **ERC-8176 attestation** (`allow_unattested_dev_descriptors = false` + real `trusted_attesters`), which makes the corpus trusted-*and*-attested — a content control, not a shape control. This mirrors the HARD-slice decision (`docs/erc7730-coverage-blocker-analysis-2026-07.md`): where a structural gate would over-fire with no true positives, the honest close is native coverage + documented residual + attestation, not a net-negative gate.
