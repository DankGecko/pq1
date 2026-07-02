# Clear-signing / trusted-display adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for running an adversarial code-review pass over PQSigner's trusted-display clear-signing surface — the on-device decoders that turn companion-supplied calldata / typed-data into the pages the user confirms. The one property everything here defends:

> **WYSIWYS — "what you see is what you sign."** The rendered page must bind to the *exact bytes that get signed*, or the renderer must decline **loudly** (fall down the blind-sign ladder / refuse). The cardinal sin is a page that renders cleanly but does not constrain the signed bytes — the display-≠-calldata break. The second sin is a decoder that fails **open** (shows a clear-sign banner over something it did not actually decode) instead of failing **loud**.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) enumerates *silicon / bench pass-fail bars* (Claim 9 trusted-UI, §9). **This playbook is the code-review counterpart**: it walks the *source* of each decoder against its asserted WYSIWYS property, hunting claim-vs-code drift and fail-open/vacuity — the same job the [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md) does for the Lean tree, transposed onto the render path. The FV playbook's vacuity catalog has a direct analog here: a render-faithfulness test that passes but is *not bound to the canonical signed bytes* is exactly a vacuous proof. Use the two documents together; do not re-run red-teaming.md's bench checks here.

> **Honesty note (this catalog's own discipline).** The `Status` column distinguishes **defended-by-construction** (with the evidence) from **relies-on-build-time-gate** from **reasoned-latent**. As of the 2026-07 survey this surface is *largely closed* — most rows below are "defended, here is the test that proves it." Do **not** manufacture findings to fill the catalog; a row that says "closed, evidence X" is the honest and valuable output. The remaining live hazards (CS5 partial-hide, CS10 trust-label) are named as such.

---

## Part A — The clear-signing failure catalog (CS1–CS10)

The ways an on-device decoder can render a page that does not mean what it signs. For each: what it looks like, the current status in *this* tree with evidence, how to detect it, and whether detection is automated.

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| CS1 | **Display ≠ signed bytes** | the page renders a value/recipient/order that is not the one the C10 signature commits to | **DEFENDED.** CoW binds via `cross_check_setpresig_calldata` (rebuild struct_hash, byte-compare vs `calldata[100..132]` — `cowswap/verify.rs:189`); Safe binds `keccak256(raw_data)==canonical.data_hash` + `compute_safe_tx_hash==inner_data[4..36]` (`safe/verify.rs:145,151`); ERC-7730 EIP-712 requires **exact** `encoded_data` length (`display/erc7730/mod.rs:340`) | **Render-faithfulness test bound to canonical bytes + flip→decline non-vacuity**: assert the rendered page equals the expectation AND that flipping one signed byte changes the render or forces decline. `cowswap_render_pure_tests.rs:92/130`, `safe_display_render_pure_tests.rs:137`, ERC-20 amount/recipient `pure_tests.rs:575` | ✅ host render harness |
| CS2 | **Silent fail-open to blind-sign** | a known shape that fails to decode presents a clear-sign banner (or a partial page) instead of the loud `! BLIND SIGN` / refuse | **DEFENDED.** "No visible fields" belt: a known shape rendering **zero** fields Rejects, not banners (`display/erc7730/mod.rs:169` calldata / `:385` typed-data). Loud blind-sign path shows `! BLIND SIGN` + calldata SHA-256 for dapp cross-check (`display/blind_sign.rs:32,123`) | Flip→decline tests that drive a decode failure and assert the render is `BlindSign`/`Reject`, never a clear banner. blind-sign data-hash flip `pure_tests.rs:999,1177` | ✅ host render harness |
| CS3 | **Unpinned descriptor / metadata accepted** | a Merkle bundle verify accepts a descriptor or token entry not under the firmware-pinned root | **DEFENDED.** `verify_erc7730_bundle` walks to `ERC7730_DESCRIPTORS_ROOT` (`db_roots.rs:92`); leaf `sha256(0x00‖ir)`, node `sha256(0x01‖L‖R)` domain-separated (`erc20/merkle.rs:9-14`); trailing-bytes rejected (`erc20/bundle.rs:173`, `ir.rs:344-355` exact layout) | A test that mutates the descriptor/leaf and asserts the walk fails to reach the pinned root; confirm every `verify_*_bundle` takes the pinned `root` and no caller passes an attacker root | ✅ bundle-verify tests + Kani `ir.rs:845` |
| CS4 | **Magnitude / precision hiding** | value truncated (low bytes dropped), decimals inflated to scale a drain toward 0.000…, or an array clamped by truncation | **DEFENDED.** `render_raw` renders the full 32-byte word (4 rows) — the old form dropped the low 16 bytes, fixed 2026-06-26 (`formatters.rs:243-267`); `MAX_DISPLAY_DECIMALS=36` WYSIWYS floor (`erc20/bundle.rs:96`); `MAX_ARRAY_RENDER=8` → **Reject, not truncate** (`array.rs:43,223`) | Concrete Kani `resolve_array_rejects_over_cap` (`array.rs:451`, the symbolic harness can't reach the cap); render tests over full-width values | ✅ Kani + render tests |
| CS5 | **Partial-hide via `visibility`** | a **single material** field (a `uint256` amount, a `bytes` blob) marked `visibility:"never"` on a top-level format is hidden silently on-device | **⚠ LIVE (relies-on-build-time-gate).** On-device belts catch only (a) **all** fields hidden ("no visible fields" belt) and (b) uncovered **address** words in nested structs (`render/nested.rs:264-268`). A hidden material *scalar* is caught only by the build-time `dbgen::erc7730::check_field_visibility` gate — the correctness root | Probe: can a descriptor with a hidden material scalar reach the pinned root? Audit `dbgen`'s visibility gate + `static_head_words` honesty. `IfNotIn` currently fail-*shows* (value-list sub-TLV unimplemented, `visibility.rs:92-101`) — safe but not the intended suppression | ⚠ partial (build-time dbgen, not on-device) |
| CS6 | **Nested / recursive binding incomplete** | a nested-struct hash binding that does not cover every element (empty array binds `keccak("")`, a tail element rides in unbound) | **DEFENDED.** Binding enforced **before** any sub-field renders: `keccak(type_hash‖nested_ed)==committed` (single) / `keccak(concat of per-element hashStructs)==committed` (array), constant-time (`display/erc7730/mod.rs:617-620/642-645`); `hash_struct_array` folds **every** element (`render/nested.rs:45`); `elem_count==0` rejected (`mod.rs:594`); `MAX_NESTED_ARRAY=6`; E1 pin `records_consumed==nested_descent_count && cursor==blob.len()` (`mod.rs:373-378`) | Flip→decline over the nested blob: per-element and elem_count mutations must force decline. Nested Permit2 array tests; pinned Permit2 vectors `render/nested.rs:83-137` | ✅ host render harness + Kani |
| CS7 | **Canonical-target / operation bypass** | a multiSend record with `operation=1` (DELEGATECALL) to a non-canonical target, or `operation!=0` accepted outside the allowlist | **DEFENDED.** `is_multisend_claim` = `operation==1` **AND** target ∈ `MULTISEND_CALL_ONLY_ADDRESSES` **AND** selector `0x8d80ff0a` (`multi_send.rs:58,78`); per-record `operation==0` in the Kani-bounded `pqsigner_tx::multisend::summarize`; Safe op-gate `verify.rs:138-142`; a malformed claim **refuses loudly** rather than dropping to blind-sign (`multi_send.rs:159`, test `claim_fires_even_for_malformed_tail:346`) | multiSend record-walk differential vs real MultiSendCallOnly bytecode in revm (`fuzz/tests/multisend_record_walk_differential.rs`); canonical-framing tests `:389-438` | ✅ fuzz differential + Kani |
| CS8 | **Page-budget truncation** | a Safe/CoW/batch render whose page count exceeds `MAX_PAGES` silently drops pages instead of refusing | **DEFENDED.** `total_pages > MAX_PAGES` → refuse (`safe_display.rs:494`, replacing the historic `min(.., MAX_PAGES)` clamp); `push_blank` returns `Err` → `RenderErr::PageBudget` → decline (`display/erc7730/mod.rs:191`); `MultisendGate` counts pages in lockstep with the renderer | A test that overflows the budget and asserts decline (not a clamped page set). `enforce_native_value_page`/`enforce_gas_pages` splice-or-refuse (`mod.rs:290,314`) | ✅ host render harness |
| CS9 | **Legacy / dual-path desync** | a second walker/decoder with a different encoding gets onto the confirm path, so confirm ≠ execute | **DEFENDED (by exclusion).** `pqsigner-erc7730/src/walker.rs` is legacy with an incompatible `ArrayIdx=u32` encoding and is **deliberately not re-exported** to the secure crate (`secure/src/tx/erc7730.rs:26-32`); the live path is `render/resolve.rs`. **Footgun**: any future re-export of the legacy walker onto the firmware surface reintroduces the desync | Grep the secure re-export shim for the legacy walker; a source-text test pinning that `walker` is not on the render path | ⚠ discipline (grep, no gate yet) |
| CS10 | **Trust-label confusion** | a `SelfAttest` selector whose companion-supplied `text_sig` collides on the 4-byte selector renders under a *named* "GUESS:" banner; a homoglyph name on the LCD | **⚠ LIVE-by-design (lower trust).** `SelfAttest` verified only by `keccak256(text_sig)[..4]==calldata[..4]` + ABI shape (`selectors/bundle.rs:52-64`) — a crafted collision shows a named function under a louder "GUESS:" banner (still not blind-sign); names ASCII-gated anti-homoglyph (`ir.rs:696-712`) | Confirm the "GUESS:"/"UNVERIFIED" banner copy is loud enough that a named-but-attested function is not mistaken for a curated one; review the trust ladder in `display/mod.rs:206-241` | ⚠ disclosure (banner copy is the defense) |

**Read this catalog as the answer to "can the companion make the device sign something other than what it shows?"** For CS1–CS4, CS6–CS8 the answer is *no*, and each row names the test that proves it. **CS5 (a single hidden material scalar) and CS10 (trust-label collision) are the live residuals** — CS5 rests on the build-time `dbgen` gate rather than an on-device belt, and CS10 is a deliberate lower-trust rung whose defense is banner copy. CS9 is closed by exclusion but is a standing footgun. Do not let "the surface is largely closed" become overconfidence: the closure is only as strong as the flip→decline non-vacuity of each render test — a render test that binds to a *derived* value instead of the *signed* bytes is green and hollow.

---

## Part B — The existing defenses (Layer 1: what already fails closed)

The mechanical backbone this surface already ships — anchor every catalog claim to one of these, exactly as the FV playbook anchors V1–V11 to real gates:

1. **Host render-faithfulness harness (the CS1/CS2/CS6/CS8 gate).** `secure/src/display_under_test/mod.rs` `#[path]`-mounts the *real* renderers; `tx/mod.rs:31` re-points `crate::tx::display → display_under_test` under `#[cfg(test)]` so absolute paths resolve. Every binding test asserts (a) the rendered page equals the expectation **bound to the canonical signed bytes** and (b) **flip→decline non-vacuity** — flipping a signed byte changes the render or forces decline. This is the direct analog of the FV `*_nonvacuous` witness discipline: a render test without the flip leg is a vacuous test.
2. **Kani decode kernels.** `decode_flags` / `validate_data_len` (`aa/src/userop.rs:738/755`, harnesses `:777/789`); the erc7730-crate harnesses (`ir`/`params`/`array`/`resolve`/`nested`/`enums`); the tx-crate harnesses (`multisend`/`erc20`/`safe_tx`/`typed_call`). Each carries **non-vacuity controls** (e.g. `resolve_array_rejects_over_cap`, `params rejects-unknown-tag`) so the harness proves the reject path fires, not just the accept path.
3. **Fuzz + differential.** `fuzz/fuzz_targets/{erc7730_ir_parse,erc7730_render_dispatch,erc7730_verify_bundle,erc7730_walker,multisend_decode,tx_erc20_verify_bundle}`; `fuzz/tests/multisend_record_walk_differential.rs` diffs the record walk against **real** MultiSendCallOnly bytecode in revm (a model-≠-artifact check, the FV V9 analog).
4. **Fail-closed structural invariants in the dispatcher.** `pick_sign_pages` (`display/mod.rs:252`) with `enforce_native_value_page`/`enforce_gas_pages` refuse-on-no-room; `head_bounded_body` clamps calldata to the static head; unknown TLV tag → Reject (`params.rs:292`); `$`-root metadata unsupported → Reject (`formatters.rs:131`); `Encrypted` → Reject (`formatters.rs:1291`).
5. **Build-time `dbgen` gates (the CS5 correctness root — off-device).** `dbgen::erc7730::check_field_visibility` + `static_head_words` computation. Because CS5's on-device belt covers only *all-hidden* and *nested-address*, the build-time gate is load-bearing for the partial-hide case. **If `dbgen` is in scope for a review, its visibility gate is a first-class target.**

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
    render/enums}.rs — the IR parser + LIVE resolvers (NOT walker.rs, which is legacy).
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
  - The live walker is render/resolve.rs; walker.rs is legacy and NOT on the path — if
    you find it re-exported to the secure crate, that is a CS9 finding.
  - Distinguish an on-device belt from a build-time dbgen gate (CS5): a property enforced
    only at build time is a different assurance than one enforced on-device.
  - For each finding give: CS-mode, exact file:line, the PoC, disposition (CONFIRMED_REAL
    / FALSE_POSITIVE / ALREADY_FIXED / OPEN_RESEARCH), severity, proposed fix — flagging
    if the fix would weaken a binding, regress a render test, or "fix" correct code.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — the bindings that survived, and the strongest
     single flip→decline PoC-attempt that failed, per decoder.
  2. "What I did NOT look at" — decoders not walked, CS-modes not exhausted, the dbgen
     build-time gate if out of scope. This is the next round's target list.
  3. "PROVENANCE — did this pass RUN the render harness / Kani / fuzz, or read source
     only?" A source-only pass cannot see a test that is green-but-vacuous.
  Never imply "the rest is fine." Absence of a finding is not evidence of WYSIWYS.
```

**Running it as a swarm.** Fan out ≥3 independent reviewers per scope and cross-vote (a finding ≥quorum reviewers raise is "confirmed"); rotate across two model backends so one model's blind spot doesn't become yours. The `contracts/verification/adversarial-review/` kit (`run_review.py`) already drives this shape backend-agnostically — add a clear-signing angle to its `protocol.json` mirroring the existing `kani-decoder-vacuity` angle, or drive `parallel()` + a `phase('CrossCheck')` from a `Workflow`.

---

## Part D — Cadence + honest boundary

- **Per-PR touching a decoder / descriptor / display renderer:** the Layer-1 gates (render harness + Kani + fuzz), and a scoped Part-C pass on the changed decoder. A new decoder ships with a flip→decline render test or it does not ship.
- **Per-descriptor-corpus change:** re-run the `dbgen` visibility gate (CS5 root) + the corpus render tests.
- **Per-milestone:** full-scope Part-C swarm + a genuine external red-team pairing this code review with red-teaming.md's bench Claim-9 checks.
- **The one-line gut check before you say "this decoder is safe":** *if I flip one byte of what the signature commits to, does the rendered page change or the device decline?* If you don't **know** the answer is yes (and have a flip→decline test that proves it), the decoder is not safe — it is merely green.

**The boundary, stated on purpose.** This playbook can tell you that no *covered* decoder on the render path lets the display drift from the signed bytes as of the last executing pass. It **cannot** tell you that a hidden material scalar can't reach the pinned root (that rests on the off-device `dbgen` gate — CS5), that the trust-label ladder's banner copy is loud enough (CS10), or that a decoder you did not walk is bound. Those, and the bench-silicon Claim-9 checks in `red-teaming.md`, are outside this document.
