# Clear-signing / trusted-display adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for running an adversarial code-review pass over PQSigner's trusted-display clear-signing surface — the on-device decoders that turn companion-supplied calldata / typed-data into the pages the user confirms. The one property everything here defends:

> **WYSIWYS — "what you see is what you sign."** The rendered page must bind to the *exact bytes that get signed*, or the renderer must decline **loudly** (fall down the blind-sign ladder / refuse). The cardinal sin is a page that renders cleanly but does not constrain the signed bytes — the display-≠-calldata break. The second sin is a decoder that fails **open** (shows a clear-sign banner over something it did not actually decode) instead of failing **loud**.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) enumerates *silicon / bench pass-fail bars* (Claim 9 trusted-UI, §9). **This playbook is the code-review counterpart**: it walks the *source* of each decoder against its asserted WYSIWYS property, hunting claim-vs-code drift and fail-open/vacuity — the same job the [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md) does for the Lean tree, transposed onto the render path. The FV playbook's vacuity catalog has a direct analog here: a render-faithfulness test that passes but is *not bound to the canonical signed bytes* is exactly a vacuous proof. Use the two documents together; do not re-run red-teaming.md's bench checks here.

> **Honesty note (this catalog's own discipline).** The `Status` column distinguishes **defended-by-construction** (with the evidence) from **relies-on-build-time-gate** from **reasoned-latent**. As of the 2026-07 survey this surface is *largely closed* — most rows below are "defended, here is the test that proves it." Do **not** manufacture findings to fill the catalog; a row that says "closed, evidence X" is the honest and valuable output. CS10's lower-trust self-attested label remains an explicit reviewed residual; no owner risk-acceptance receipt is recorded.

---

## Part A — The clear-signing failure catalog (CS1–CS10)

The ways an on-device decoder can render a page that does not mean what it signs. For each: what it looks like, the current status in *this* tree with evidence, how to detect it, and whether detection is automated.

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| CS1 | **Display ≠ signed bytes** | the page renders a value/recipient/order that is not the one the C10 signature commits to | **DEFENDED.** CoW binds via `cross_check_setpresig_calldata` (rebuild struct_hash, byte-compare vs `calldata[100..132]` — `cowswap/verify.rs:189`); Safe binds `keccak256(raw_data)==canonical.data_hash` + `compute_safe_tx_hash==inner_data[4..36]` (`safe/verify.rs:145,151`); ERC-7730 EIP-712 requires **exact** `encoded_data` length. ERC-7730 contract calldata runs `validate_contract_calldata_framing` before visibility: exact all-static EOF or one exact sole C1 whole tail, including hidden fields/tokenPaths; C2/C3, aliases, dirty padding, gaps, and suffixes reject. **Known tolerance (2026-07-17 sweep, LOW):** the Safe `execTransaction` decoder (`tx/eip712/safe/exec_decode.rs:241-285`) only lower-bounds dynamic offsets — non-canonical framing (gaps, overlap, trailing garbage) decodes identically and is signed unshown; inert today (Safe reads via offsets) but diverges from this row's exactness standard. Fix: require canonical offsets + exact end-of-calldata, or record the deliberate tolerance here. | **Render-faithfulness test bound to canonical bytes + flip→decline non-vacuity**: assert the rendered page equals the expectation AND that flipping one signed byte changes the render or forces decline. Include static-suffix, hidden-dynamic, padding, alias, trailing-byte, and C2/C3 refusal witnesses. | ✅ host render harness |
| CS2 | **Silent fail-open to blind-sign** | a known shape whose proof is stripped, malformed, or fails to render downgrades to generic pages | **DEFENDED in the current tree; controlling boundary for the optional forced tier.** `dbgen` emits a pinned Bloom filter over every parsable registry-declared `(chain, contract, selector)`, including formats strict WYSIWYS policy refuses to compile; `pick_sign_pages` refuses a known tuple without a verified descriptor, and every `RenderErr` from a verified descriptor is fatal. Bloom false positives refuse safely. Forced blind is not clear signing or an ordinary blind fallback: only cleanly absent metadata for an exact member of the separately authenticated refused-known set `F = K \ C` may produce the private forced candidate for its separate ceremony. A tuple in the accepted clear set `C` whose descriptor is omitted still fatal-refuses, and any present descriptor's validation, binding, or render failure remains fatal. ERC-8176 does not authorize this runtime route or give forced raw pages semantic trust. Feature-off and rollback behavior remain refusal. | Omit/corrupt each known proof and force `NoFormat`/`PageBudget`/`Reject`; assert dispatcher `Err`, never the ordinary `! BLIND SIGN` ladder. Pin `C`-omission and all present-evidence failures as fatal; permit only clean absence plus exact `F` membership to reach the separate ceremony. Keep genuinely unknown and Bloom-collision controls. | ✅ current host dispatcher harness + generated-filter round trip; forced-tier evidence is a merge gate |
| CS3 | **Unpinned descriptor / metadata accepted** | a Merkle bundle verify accepts a descriptor or token entry not under the firmware-pinned root | **DEFENDED.** `verify_erc7730_bundle` walks to `ERC7730_DESCRIPTORS_ROOT`; leaf `sha256(0x00‖ir)`, node `sha256(0x01‖L‖R)` are domain-separated and trailing bytes reject. The secure binding proofs independently re-verify the exact bundle/root twice, require each parsed IR to equal the caller's IR, then re-check context under caller-owned CFI + duplicated reject gates; a skipped Merkle reject cannot launder forged IR. | Mutate descriptor/proof/root and assert failure; inspect optimized secure call sites for two membership+binding computations, caller-owned FAIL publication, and two final reject gates | ✅ bundle tests + secure FI source/Thumb checks |
| CS4 | **Magnitude / precision hiding** | value truncated (low bytes dropped), decimals inflated to scale a drain toward 0.000…, or an array clamped by truncation | **DEFENDED.** The dispatcher rejects non-exact or overwide known-native values before page/CFI publication. Ordinary ERC-7730 `amount` and descriptor-pinned native `tokenAmount` enforce the same pre-publication exactness rule. `render_raw` still renders the full 32-byte word (4 rows); `MAX_DISPLAY_DECIMALS=36` remains the WYSIWYS floor; `MAX_ARRAY_RENDER=8` remains **Reject, not truncate**. Primitive dynamic arrays are accepted only as the sole exact C1 whole tail, and dynamic `tokenPath` arrays validate every word, including unselected elements, for canonical padding. Host atomic-refusal regressions and bounded unmutated Kani harnesses are green; exact-target mutant execution remains a Phase-D evidence gate. | Concrete atomic-refusal, exactness, full-width render, over-cap array, dirty unselected `tokenPath`, suffix, and noncanonical-tail regressions | ✅ Kani + render tests |
| CS5 | **Partial-hide via `visibility`** | a **single material** field (a `uint256` amount, a `bytes` blob) marked `visibility:"never"` on a top-level format is hidden silently on-device | **DEFENDED (strict build-time exclusion + runtime belts).** `check_field_visibility` rejects every hidden non-address terminal, including scalar, dynamic/composite, array, and EIP-712 hash words. A hidden terminal `address` survives only when another visible field/tokenPath structurally surfaces that exact signed address. Semantic signature-only exemptions were deleted, so an unrelated deployment cannot inherit one. Runtime still rejects all-hidden formats and uncovered nested addresses. **Latent footgun (2026-07-17 sweep):** dbgen treats `visibility:"optional"` as *shown* for Rules 1–3, but the renderer skips Optional fields under the deferred `COMPACT_MODE` toggle — when that toggle ships, a format whose material coverage depends on Optional fields would sign them unshown. Fix on toggle-day: dbgen treats Optional as hidden, or the renderer refuses such formats under compact mode. | Compile `execute(address target,bytes payload)` with hidden payload, hidden scalar, hidden nested member, and same-signature/different-deployment probes; each must be absent from the generated root. Corpus exclusion guards and exact-address/tokenPath positive control pin the narrow exception. | ✅ dbgen unit + corpus round trip |
| CS6 | **Nested / recursive binding incomplete** | a nested-struct hash binding that does not cover every element (empty array binds `keccak("")`, a tail element rides in unbound) | **DEFENDED.** Binding enforced **before** any sub-field renders: `keccak(type_hash‖nested_ed)==committed` (single) / `keccak(concat of per-element hashStructs)==committed` (array), constant-time (`pqsigner-erc7730/src/display/render/mod.rs:836-839` array bind, `:871-875` single bind); `hash_struct_array` folds **every** element (`render/nested.rs:45`); `elem_count==0` rejected (`render/mod.rs:813-815`); `MAX_NESTED_ARRAY=6`; E1 pin `records_consumed==nested_descent_count && cursor==blob.len()` (`render/mod.rs:450-455`) | Flip→decline over the nested blob: per-element and elem_count mutations must force decline. Nested Permit2 array tests; pinned Permit2 vectors `render/nested.rs:83-137` | ✅ host render harness + Kani |
| CS7 | **Canonical-target / operation bypass** | a multiSend record with `operation=1` (DELEGATECALL) to a non-canonical target, or `operation!=0` accepted outside the allowlist | **DEFENDED.** `is_multisend_claim` = `operation==1` **AND** target ∈ `MULTISEND_CALL_ONLY_ADDRESSES` **AND** selector `0x8d80ff0a` (`multi_send.rs:58,78`); per-record `operation==0` in the Kani-bounded `pqsigner_tx::multisend::summarize`; Safe op-gate `verify.rs:138-142`; a malformed claim **refuses loudly** rather than dropping to blind-sign (`multi_send.rs:159`, test `claim_fires_even_for_malformed_tail:346`) | multiSend record-walk differential vs real MultiSendCallOnly bytecode in revm (`fuzz/tests/multisend_record_walk_differential.rs`); canonical-framing tests `:389-438` | ✅ fuzz differential + Kani |
| CS8 | **Page-budget truncation** | a Safe/CoW/batch render whose page count exceeds `MAX_PAGES` silently drops pages instead of refusing | **DEFENDED.** `total_pages > MAX_PAGES` → refuse (`safe_display.rs:495-503`, replacing the historic `min(.., MAX_PAGES)` clamp); `push_blank` returns `Err` → `RenderErr::PageBudget` → decline (`pqsigner-erc7730/src/display/render/mod.rs:196`); `MultisendGate` counts pages in lockstep with the renderer | A test that overflows the budget and asserts decline (not a clamped page set). `enforce_native_value_page`/`enforce_gas_pages` splice-or-refuse (`tx/display/dispatch.rs:212,261`, helper `value_page.rs:267`) | ✅ host render harness |
| CS9 | **Legacy / dual-path desync** | a second walker/decoder with a different encoding gets onto the confirm path, so confirm ≠ execute | **DEFENDED in the current tree; forced-tier routing remains a merge gate.** The legacy `walker.rs` and its fuzz/export surface were deleted; the live resolver is `render/resolve.rs`. Contract rendering has one private `render_fields` entry, preceded by `validate_contract_calldata_framing`; low-level resolver arithmetic cannot bypass that format gate. C2/C3 support is retired rather than split across competing runtime paths. The optional forced tier must not add a semantic decoder or return to any clear/ordinary blind ladder: a private handler-owned candidate may be minted only from clean absence plus exact `F = K \ C` membership, then its separate raw ceremony binds directly to the canonical signed request. `C` omission and every present-descriptor failure remain fatal. **Footgun:** reintroducing a second walker, calling `render_fields` without preflight, or letting a forced candidate re-enter another dispatcher recreates desync. | Pin that the legacy module stays absent, preflight immediately precedes the sole contract `render_fields` call, and C2/C3 exclusion regressions stay green. For the forced tier, pin the sole typed route, exact signed-request/raw-transcript binding, fatal `C` omission and present-render failures, and no return to another dispatcher. | ⚠ discipline + host regressions; forced-tier evidence is a merge gate |
| CS10 | **Trust-label confusion** | a `SelfAttest` selector whose companion-supplied `text_sig` collides on the 4-byte selector renders under a *named* "GUESS:" banner; a homoglyph name on the LCD | **⚠ LIVE-by-design (lower trust).** `SelfAttest` verified only by `keccak256(text_sig)[..4]==calldata[..4]` + ABI shape (`selectors/bundle.rs:52-64`) — a crafted collision shows a named function under a louder "GUESS:" banner (still not blind-sign); names ASCII-gated anti-homoglyph (`ir.rs:696-712`) | Confirm the "GUESS:"/"UNVERIFIED" banner copy is loud enough that a named-but-attested function is not mistaken for a curated one; review the trust ladder (banner copy now at `tx/display/blind_sign.rs:49-62` and `typed_call/mod.rs:86-108`) | ⚠ disclosure (banner copy is the defense) |

**Read this catalog as the answer to "can the companion make the device sign something other than what it shows?"** For CS1–CS9 the covered paths are fail-closed, and each row names the test that proves it. CS5's strict build-time exclusion is load-bearing and deliberately costs catalogue coverage; CS10 is a deliberate lower-trust rung whose defense is banner copy. CS9 is closed by deletion but remains a standing architectural footgun. Do not let "the surface is largely closed" become overconfidence: the closure is only as strong as the flip→decline non-vacuity of each render test — a render test that binds to a *derived* value instead of the *signed* bytes is green and hollow.

---

## Part B — The existing defenses (Layer 1: what already fails closed)

The mechanical backbone this surface already ships — anchor every catalog claim to one of these, exactly as the FV playbook anchors V1–V11 to real gates:

1. **Host render-faithfulness harness (the CS1/CS2/CS6/CS8 gate).** `secure/src/display_under_test/mod.rs` `#[path]`-mounts the *real* renderers; `tx/mod.rs:31` re-points `crate::tx::display → display_under_test` under `#[cfg(test)]` so absolute paths resolve. Every binding test asserts (a) the rendered page equals the expectation **bound to the canonical signed bytes** and (b) **flip→decline non-vacuity** — flipping a signed byte changes the render or forces decline. This is the direct analog of the FV `*_nonvacuous` witness discipline: a render test without the flip leg is a vacuous test.
2. **Kani decode kernels.** `decode_flags` / `validate_data_len` (`aa/src/userop.rs:738/755`, harnesses `:777/789`); the erc7730-crate harnesses (`ir`/`params`/`array`/`resolve`/`nested`/`enums`); the tx-crate harnesses (`multisend`/`erc20`/`safe_tx`/`typed_call`). Each carries **non-vacuity controls** (e.g. `resolve_array_rejects_over_cap`, `params rejects-unknown-tag`) so the harness proves the reject path fires, not just the accept path.
3. **Fuzz + differential.** `fuzz/fuzz_targets/{erc7730_ir_parse,erc7730_render_dispatch,erc7730_verify_bundle,multisend_decode,tx_erc20_verify_bundle}`; `fuzz/tests/multisend_record_walk_differential.rs` diffs the record walk against **real** MultiSendCallOnly bytecode in revm (a model-≠-artifact check, the FV V9 analog).
4. **Fail-closed structural invariants in the dispatcher.** `pick_sign_pages` with `enforce_native_value_page`/`enforce_gas_pages` refuses on no room, and any verified/known-call render error is fatal. Contract formats run `validate_contract_calldata_framing` before visibility or field rendering: exact static EOF or one exact sole C1 whole tail. Unknown TLV tags, unsupported `$` roots, and `Encrypted` formatters reject.
5. **Build-time `dbgen` gates (the CS5 correctness root — off-device).** `dbgen::erc7730::check_field_visibility` + `static_head_words` computation. Every hidden non-address operand is excluded; a hidden address is permitted only when the same signed address is structurally surfaced elsewhere. The on-device belts remain defense in depth, but the compiler gate is load-bearing for deciding which formats enter the root. **If `dbgen` is in scope for a review, its visibility gate is a first-class target.**

---

## Part C — THE MASTER PROMPT (copy-paste / workflow brief)

Paste to a fresh agent (or use as the per-agent brief in an N-way swarm; rotate models). Fill the `{{…}}` slots.

```
ROLE: You are an adversarial reviewer of PQSigner_OS's trusted-display clear-signing.
Your job is to BREAK the "what you see is what you sign" property, NOT to confirm it.
Default to "this page does NOT bind to the signed bytes until I prove it does." A
passing render test, a clean corpus round-trip, and a confident docstring are
CONSISTENCY signals, not WYSIWYS — treat them as the thing to attack. The most
dangerous bug is a page that renders cleanly but leaves the signed bytes unconstrained;
the second is a decoder that fails OPEN to a clear banner instead of loud blind-sign.

TARGET (read first, in this order):
  - docs/security/adversarial-review/clear-signing-adversarial-review.md §A — the
    CS1–CS10 catalog that is your ATTACK SURFACE.
  - pqsigner-erc7730/src/{ir,render/resolve,render/array,render/params,render/nested,
    render/enums}.rs — the IR parser + live resolvers; the legacy walker was deleted.
  - secure/src/tx/eip712/{cowswap,safe}/*.rs — CoW / Safe / multiSend binding.
  - secure/src/tx/display/{mod,erc7730/mod,blind_sign}.rs + display_under_test/ — the
    dispatcher, nested render, blind-sign ladder, and the test mount.
  - tx/src/{erc20,selectors,names}/ + secure/src/db_roots.rs — Merkle bundles + pins.
SCOPE THIS RUN: {{e.g. "the CoW/Safe binding" | "the ERC-7730 nested-struct render"
  | "the visibility evaluator + dbgen gate (CS5)" | "the whole render dispatcher"}}.

ATTACK PROTOCOL — walk EVERY CS1–CS10 mode against each decoder in scope:
  CS1 display≠signed-bytes · CS2 silent fail-open-to-blind · CS3 unpinned descriptor ·
  CS4 magnitude/precision hiding · CS5 partial-hide via visibility:never ·
  CS6 nested/recursive binding incomplete · CS7 canonical-target/operation bypass ·
  CS8 page-budget truncation · CS9 legacy/dual-path desync · CS10 trust-label confusion.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a host render test (mount via display_under_test) where the rendered page does NOT
    change when a SIGNED byte is flipped (proves the render is not bound), OR a decode
    failure that yields a clear banner instead of BlindSign/Reject;
  - a descriptor/bundle that reaches the pinned root yet hides or mis-renders a material
    field (CS3/CS5);
  - a Kani counterexample or a fuzz input that decodes a non-canonical shape as canonical;
  - a diff between what a docstring/CLAUDE.md CLAIMS the decoder enforces and what the
    source actually checks.
  No PoC ⇒ list under "suspicions, unverified" — do not report as a finding.

RULES:
  - Verify against the CURRENT tree; re-read the cited source — do not trust quotes or
    this catalog's "DEFENDED" labels without re-checking the flip→decline test exists
    AND binds to the SIGNED bytes (a test bound to a derived value is vacuous).
  - The live resolver is render/resolve.rs; the legacy walker is deleted. Reintroducing
    it, or any second decoder that can reach confirmation, is a CS9 finding.
  - Distinguish an on-device belt from a build-time dbgen gate (CS5): a property enforced
    only at build time is a different assurance than one enforced on-device.
  - For each candidate give: CS-mode, exact file:line, the PoC, provisional
    severity, proposed fix, and a stable candidate ID — flagging
    if the fix would weaken a binding, regress a render test, or "fix" correct code.
    Do not assign a finding disposition.

OUTPUT — return an external candidate packet to the coordinator. Do not modify
the repository, write a canonical findings report, or update catalogue/status
fields. Include every candidate and the honest residual. The coordinator freezes
the raw packet and gives the complete union to the exact Partner-A/Partner-B
pair; only their symmetric cross-adjudication may assign dispositions. An
authorized maintainer records the adjudicated result afterward.

FILING — the coordinator files every kept adversarial-review candidate as a
GitHub issue on EthereumPhone/PQ1 (labels `finding`, `priority:*`, `surface:*`;
`ship-blocker` when the candidate gates production). The issue is the
actionable record; any report under findings/ remains the frozen evidence.
Phase-D merge-review outcomes are never filed as issues. Do not file issues
yourself unless the coordinator's brief says so.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — the bindings that survived, and the strongest
     single flip→decline PoC-attempt that failed, per decoder.
  2. "What I did NOT look at" — decoders not walked, CS-modes not exhausted, the dbgen
     build-time gate if out of scope. This is the next round's target list.
  3. "PROVENANCE — did this pass RUN the render harness / Kani / fuzz, or read source
     only?" A source-only pass cannot see a test that is green-but-vacuous.
  Never imply "the rest is fine." Absence of a finding is not evidence of WYSIWYS.
```

**Running it as a swarm.** Fan out ≥3 independent reviewers per scope and use
quorum only to prioritize or corroborate discovery; quorum does not set a
finding's disposition and never overrides the exact Partner-A/Partner-B
protocol in [`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md).
Rotate discovery across two model backends so one model's blind spot does not
become yours. The required pair must personally reproduce/refute/narrow every
finding and preserve disagreement—never majority-vote it away. The
`contracts/verification/adversarial-review/` kit (`run_review.py`) already
drives discovery backend-agnostically—add a clear-signing angle to its
`protocol.json` mirroring `kani-decoder-vacuity`, or drive `parallel()` plus a
`phase('CrossCheck')` from a `Workflow`.

---

## Part D — Cadence + honest boundary

- **Per-PR touching a decoder / descriptor / display renderer:** the Layer-1 gates (render harness + Kani + fuzz), and a scoped Part-C pass on the changed decoder. A new decoder ships with a flip→decline render test or it does not ship.
- **Per-descriptor-corpus change:** re-run the `dbgen` visibility gate (CS5 root) + the corpus render tests.
- **Per-milestone:** full-scope Part-C swarm + a genuine external red-team pairing this code review with red-teaming.md's bench Claim-9 checks.
- **The one-line gut check before you say "this decoder is safe":** *if I flip one byte of what the signature commits to, does the rendered page change or the device decline?* If you don't **know** the answer is yes (and have a flip→decline test that proves it), the decoder is not safe — it is merely green.

**The boundary, stated on purpose.** This playbook can tell you that no *covered* decoder on the render path lets the display drift from the signed bytes as of the last executing pass. CS5 still rests on the off-device `dbgen` exclusion gate, and the pass cannot prove that CS10's lower-trust banner copy is humanly loud enough or that an unwalked decoder is bound. Those and the bench-silicon Claim-9 checks in `red-teaming.md` are outside this document.
