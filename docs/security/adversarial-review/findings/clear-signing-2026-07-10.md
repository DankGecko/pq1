---
surface: clear-signing
run_date: 2026-07-10
reviewer: GPT-5 Codex multi-agent adversarial review
scope: ERC-7730 registry compiler, authenticated IR/binding, calldata and EIP-712 renderers, direct/Safe dispatch, UserOp context pages, FI permission gates, and catalogue provenance
status: resolved
---

# Adversarial-review findings — clear-signing — 2026-07-10

## Summary

12 handled findings: **10 confirmed-real and fixed in the current working tree,
1 deferred production ship blocker, and 1 accepted lower-trust mode**. The review
found exploitable display/binding ambiguities in dynamic EIP-712 fields, ABI
framing, hidden operands, identity/number formatting, duplicate bindings, and
Safe classification; it also found fail-open downgrade and fault-injection gaps
around descriptor membership and route selection, plus a verified-name display
collision. The fixes are present but their commit SHA is **pending**.

The pass combined adversarial source review with targeted execution. The
executed boundary was: ERC-7730 183/183; the tx/AA/core crates green; dbgen
169/169, round-trip 17/17, phase-5 18/18, and xtask suites green;
generated-descriptor sync green; the full secure suite had 2,124 passed, 0
failed, and 1 diagnostic test ignored; `make secure` green; four array Kani harnesses green;
and `resolve_structured_panic_free_and_in_bounds` successful. `make prod-check`
reached and enforced the expected `dev-unattested` provenance failure. The
remaining structured/full Kani sweep, hardware, and fuzzing were not run.

## Findings

### F1 — Known registry calls could downgrade when their descriptor was omitted

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 · MED
- **Location:** `dbgen/src/erc7730.rs:680-691,951-1027`; `secure/src/tx/display/dispatch.rs:185-355`; `secure/src/tx/display/safe_display.rs:145-280,503-576`
- **What:** the omission filter covered emitted formats, not every parsable call declared by the vendored registry. A strict-policy rejection could therefore turn a registry-known call back into an “unknown” call, and a verified descriptor's `Reject`, `NoFormat`, or `PageBudget` could fall through to a weaker rendering rung.
- **PoC (falsifiable):** 1inch AggregationRouterV5 on mainnet, contract `0x1111111254eeb25477b68fb85ed929f73a960582`, selector `0x12aa3caf`, is intentionally uncompiled yet must remain Bloom-positive (`dbgen/tests/erc7730_roundtrip.rs:103`). A broken include and a context+display descriptor stored under a non-catalogue filename must likewise retain all raw parsable declarations in the omission filter (`dbgen/tests/erc7730_phase5_policy_and_includes.rs:407,541`). Stripping the proof for WETH `deposit()` must refuse in direct and Safe/MultiSend paths (`secure/src/display_under_test/wysiwys_dispatch_differential_tests.rs:780-812`; `safe_display_render_pure_tests.rs:293-296,378-390`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** build the firmware-pinned omission filter from every parsable registry declaration before compilation, make all verified-render failures fatal, and run the exact-tuple proof on direct Safe calls and every accepted MultiSend record.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). `collect_declared_contract_calls` scans raw descriptors before include resolution and scans otherwise-unrecognised context+display JSON files, so strict rejection, broken includes, or filename mistakes cannot erase a declared call. Direct and Safe dispatch refuse Bloom-positive calls without independently authenticated semantics; all verified-render errors are fatal.

### F2 — Flat dynamic EIP-712 fields rendered opaque hash words as values

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS5 · HIGH
- **Location:** `dbgen/src/erc7730.rs:2311-2327,2623-2644`
- **What:** EIP-712 `encodeData` stores `string`, `bytes`, arrays, and structs as hashes. Treating the corresponding 32-byte word as the descriptor's human value can label a keccak digest as an amount, destination, or other meaningful content that the device never decoded.
- **PoC (falsifiable):** the real Hyperliquid Withdraw type uses dynamic strings for `hyperliquidChain`, `destination`, and `amount`; it must be absent from the authenticated runtime catalogue. Regression coverage is `dbgen/src/erc7730.rs:6402-6500` and `dbgen/tests/erc7730_roundtrip.rs:57-101`.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** permit flat EIP-712 rendering only for static scalar terminals; dynamic/composite content needs a separately authenticated nested decoder or must be excluded.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). dbgen now rejects visible flat hash-word terminals and hidden dynamic members, including the Hyperliquid witness and nested hidden children.

### F3 — Calldata fields were not bound to one canonical ABI frame

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS9 · HIGH
- **Location:** `pqsigner-erc7730/src/display/render/mod.rs:113-150`; `pqsigner-erc7730/src/display/render/formatters.rs:1088-1160`; `pqsigner-erc7730/src/render/resolve.rs:147-224,346-445`
- **What:** field-local resolution was insufficient to prove whole-calldata canonicality. Aliased offsets, extra suffixes, dirty padding, hidden dynamic fields, and unsupported C2/C3 tail topology could leave signed bytes outside the trusted display's interpretation.
- **PoC (falsifiable):** append a static suffix; add trailing bytes or dirty right-padding to a hidden sole-dynamic field; alias a second dynamic tail; or use a C2 dynamic tuple. Each must decline rather than preserve the same trusted pages (`display/render/formatters.rs:3948-4085`; `render/resolve.rs:615-863`; corpus exclusions in `secure/src/display_under_test/erc7730_render_pure_tests.rs:1911-1925,2906-3025`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** perform a format-wide framing preflight before visibility or page emission; support only exact all-static EOF or one sole C1 whole tail until the IR can authenticate more topology.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). The renderer validates all fields, including hidden fields and token paths, and rejects C2, multi-tail, alias, gap, padding, and suffix ambiguity. Unsupported catalogue formats are excluded fail-closed.

### F4 — Display formatting was non-injective or omitted token identity

- **Status:** ✅ FIXED
- **Mode / severity:** CS4 · HIGH
- **Location:** `pqsigner-erc7730/src/display/primitives.rs:337-412,518-600`; `pqsigner-erc7730/src/display/render/amount_decision.rs:90-186`; `pqsigner-erc7730/src/display/render/formatters.rs:417-552,1414-1485`; `pqsigner-erc7730/src/display/render/mod.rs:824-884,982-1031`
- **What:** truncation/rounding and identity-free amount fallbacks could make distinct signed addresses, token contracts, chain IDs, fees, or 256-bit values share a reassuring display. A symbol or decimal scale is not sufficient token identity unless it is Merkle-bound to the exact chain and contract.
- **PoC (falsifiable):** flip one token address while preserving the amount/symbol; use an unverified token with the same ticker; vary fee words below a rounded display unit; or supply a value too wide for the page. The render must show the full identity/exact integer or reject (`amount_decision.rs:308-410,557-802`; `formatters.rs:3748-3806,3872-3915,4091-4170`; `display/render/mod.rs:1134-1237`; `secure/src/display_under_test/pure_tests.rs:874-965`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** make every security-relevant sink injective: full EIP-55 addresses, exact raw integers, exact chain IDs and fee base units, plus an explicit full token-identity page whenever exact verified metadata is unavailable.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). Exact rendering or refusal now replaces truncation/rounding. Raw and overflow fallbacks show full addresses and integers; Merkle-verified names use the separately collision-gated name/fingerprint transform recorded in F12. Token amount decisions bind native/metadata cases and retain full contract identity on every raw or overflow fallback.

### F5 — Domain, duplicate-leaf, and IR canonicality admitted competing interpretations

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS3 / CS9 · HIGH
- **Location:** `pqsigner-erc7730/src/binding.rs:52-104`; `dbgen/src/erc7730.rs:705-783,903-948,1433-1445`; `pqsigner-erc7730/src/ir.rs:300-510`; `pqsigner-erc7730/src/render/params.rs:198-375`; `tx/src/erc20/merkle.rs:41-72`
- **What:** accepting explicit descriptor-supplied domain separators, non-identical duplicate bindings, non-canonical IR/TLV suffixes, or proof-index aliases can let the companion select competing trusted displays for one signed payload or reinterpret authenticated bytes.
- **PoC (falsifiable):** construct two distinct EIP-712 leaves with the same `(chain_id, domain_separator, full type_hash)`; append malformed/unreachable format or TLV bytes; duplicate a singleton TLV; or set leaf-index bits above the proof depth. All must reject (`dbgen/src/erc7730.rs:6505-6575,8623-8648`; IR/params unit tests; `tx/src/erc20/merkle.rs:103`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** compute the domain separator canonically from the declared domain with deployment-bound chain and verifying contract; reject competing full binding keys; require exact-EOF canonical IR/TLV parsing and consume the complete Merkle index.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). Canonical DS generation, duplicate-binding rejection, strict schema/IR/TLV parsing, and `idx == 0` proof completion now make the authenticated interpretation unique.

### F6 — Merkle/binding and omission permissions were not FI-recomputed

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 / CS3 · HIGH
- **Location:** `secure/src/tx/erc7730.rs:49-218`; `secure/src/nsc/cmd_sign_userop.rs:561-650`; `secure/src/nsc/cmd_sign_userop_batch.rs:578-659`; `secure/src/nsc/cmd_sign_offchain.rs:452-526`; `secure/src/tx/display/dispatch.rs:223-355`; `secure/src/tx/display/safe_display.rs:256-280,540-576`
- **What:** the prior secure flow verified Merkle membership once, cached a context-binding boolean, and then sentinel-checked that cached result. One skipped Merkle reject could therefore launder unrooted IR. The first omission-gate draft also put proof calls behind outer route branches / `?` propagation, so skipping the route could bypass both inner checks.
- **PoC (falsifiable):** structural mutation removing either membership recomputation, caller-owned volatile FAIL publication, caller CFI bump, or either final reject gate must fail `secure/src/nsc_erc7730_binding_fi_pure_tests.rs:67-206`; equivalent direct/Safe route-order regressions are pinned in `safe_display_render_pure_tests.rs:427-475`.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** independently recompute exact bundle/root membership and context binding twice around a randomized gap, require each parse to equal the caller's IR, publish to a caller-owned volatile FAIL slot, and consume it with caller CFI plus two final gates. Route omission proofs unconditionally with fail-initialized evidence.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). Single, batch, and off-chain binding surfaces now use the full proof contract; direct and Safe/MultiSend omission checks have unconditional A/B route proofs and duplicated final refusals.

### F7 — UserOp clear-sign pages omitted or compressed signed context

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS4 · HIGH
- **Location:** `secure/src/tx/display/value_page.rs:61-209`; `secure/src/nsc/cmd_sign_userop.rs:807-823,1332-1360`; `secure/src/nsc/cmd_sign_userop_batch.rs:841-857,1018-1046`; `tx-core/src/eip1559.rs:388-410`; `pqsigner-erc7730/src/display/render/mod.rs:758-1031`
- **What:** a rich ERC-7730 inner-call display was not sufficient to identify the signing account, execution target, full chain, fee envelope, all three UserOp gas components, and full nonce. Totals, rounded fees, or truncated nonce/chain representations are non-injective over signed UserOps.
- **PoC (falsifiable):** change only the account/sender, target, high nonce bits, chain ID, or permute call/verification/pre-verification gas while preserving the total. Trusted pages must differ or signing must decline (`secure/src/tx/display/value_page.rs:483-616`; `display/render/mod.rs:1134-1308`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** splice FI-proven full signer/account and target pages around every rich renderer; display exact numeric chain/fees, each UserOp gas component separately, and the full 256-bit nonce.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). Single and batch UserOp paths enforce/prove the context pages; the shared renderer now exposes all signed gas, fee, chain, and nonce operands without lossy compression.

### F8 — Hidden material and semantic exemptions could conceal signed action bytes

- **Status:** ✅ FIXED
- **Mode / severity:** CS5 · HIGH
- **Location:** `dbgen/src/erc7730.rs:3785-4128`
- **What:** the old policy treated hidden non-address values as plausibly benign and allowed signature/path-based hidden-address exceptions. A descriptor could show a recipient or intent while hiding a scalar, packed routing word, deadline, or arbitrary `bytes` action; an ABI-name exemption was not bound to one authenticated deployment.
- **PoC (falsifiable):** compile `execute(address target,bytes payload)` with the payload hidden, hide an effect-bearing scalar, define a custom EIP-712 struct named `address`, or reuse an exempted signature on another deployment. Each must be absent from the authenticated root (`dbgen/src/erc7730.rs:7930-8133`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** reject every hidden terminal except an elementary scalar address that another visible field or tokenPath structurally surfaces exactly; delete semantic signature-only exemptions.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). Rule 3 now excludes all hidden non-address material and ambiguous composite types; recursive address coverage remains, with only the exact structurally surfaced address exception.

### F9 — Safe could classify an ERC-721 `approve` as ERC-20

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS2 · HIGH
- **Location:** `secure/src/tx/display/safe_display.rs:145-244,503-576`
- **What:** ERC-20 and ERC-721 share `approve(address,uint256)`. Exempting a Bloom-positive Safe inner call merely because its calldata matched the ERC-20 ABI could present an NFT token ID as a fungible amount and bypass the required ERC-7730 descriptor.
- **PoC (falsifiable):** Lido WithdrawalQueue ERC-721 `approve(address,uint256)` must reject without an exact descriptor, directly and inside MultiSend; genuine ERC-20 remains accepted only with Merkle-verified metadata for the exact chain and contract (`secure/src/display_under_test/safe_display_render_pure_tests.rs:301-407`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** treat verified ERC-20 metadata as an exact capability bound to `(chain, contract)` and require strict ERC-20 decoding; otherwise a known tuple needs its descriptor. Check every MultiSend record before classification.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). The Safe route now grants the native ERC-20 exemption only with exact authenticated metadata, while ERC-721 and other ABI-identical known calls refuse without their own proof.

### F10 — Real ERC-8176 catalogue provenance is unavailable

- **Status:** ⏸ DEFERRED
- **Mode / severity:** CS3 / production provenance · MED ship blocker
- **Location:** `secure/data/erc7730/policy.toml:1-48`; `dbgen/src/erc7730.rs:471-515`; `dbgen/src/main.rs:299-318,526-574`; `secure/src/db_roots.rs:117-130`; `Makefile:2176-2190`
- **What:** the current catalogue is explicitly `dev-unattested`. There are no trusted ERC-8176 attestations for the shipped descriptor hashes and dbgen deliberately has no production EAS snapshot signature/identity verifier. Structural WYSIWYS gates cannot prove that descriptor prose is semantically honest about the real contract.
- **PoC (falsifiable):** `make prod-check` must fail unless generated provenance is exactly `erc8176-verified`; obsolete embedded `attestations` arrays must never satisfy production policy (`dbgen/tests/erc7730_phase5_policy_and_includes.rs:40-67,85+`). Current measured coverage is 0 of 250 descriptor hashes (`docs/erc8176-attestation-status.md:57-71`).
- **Disposition:** OPEN_RESEARCH
- **Proposed fix:** once trusted auditors publish real ERC-8176 records, take a reproducible offline EAS snapshot, authenticate signatures and attester identity, bind every accepted record to the exact JCS descriptor hash, and exclude unattested leaves.
- **Resolution:** Deferred, 2026-07-10. Production remains fail-closed behind `make prod-check`; this review executed the target and observed the intended failure after descriptor-sync verification: catalogue provenance `dev-unattested`, required `erc8176-verified`. Tracked in `docs/work-todo.md:2585-2597` and `docs/erc8176-attestation-status.md`; unblock requires both real trusted attestations/identities and the production snapshot verifier.

### F11 — SelfAttest names have only 4-byte selector provenance

- **Status:** ☑️ ACCEPTED
- **Mode / severity:** CS10 · LOW / UX trust boundary
- **Location:** `tx/src/selectors/bundle.rs:52-64`; `secure/src/tx/display/mod.rs:206-241`
- **What:** SelfAttest proves only that `keccak256(text_signature)[0..4]` equals the calldata selector. A chosen-prefix/same-selector signature can therefore provide a misleading function name; it is not curated semantic provenance.
- **PoC (falsifiable):** supply a different ASCII text signature with the same four-byte selector. It may appear only under the lower-trust `GUESS:` / unverified blind-sign presentation and must never gain a curated `FUNCTION:` or ERC-7730 clear-sign label.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** retain the explicit trust-tier separation; any promotion would require stronger authenticated metadata rather than selector equality.
- **Resolution:** Accepted by design, 2026-07-10. SelfAttest remains a loud lower-trust aid inside the blind-sign ladder; its banner is the defense and it is not treated as clear-sign provenance.

### F12 — Verified-name truncation and short address fingerprints could collide

- **Status:** ✅ FIXED
- **Mode / severity:** CS4 · MED
- **Location:** `pqsigner-erc7730/src/display/primitives.rs:349-451`; `dbgen/src/names.rs:284-320`
- **What:** a Merkle-verified name longer than the LCD line was silently truncated, while the adjacent mixed-case address fingerprint exposed only the first and last three address bytes. Two distinct catalogue entries could therefore produce identical trusted identity pages if their names were equal after truncation and their short fingerprints collided. Separately, wildcard and exact-chain proofs could bind the same address to different names; because the companion chooses which proofs to attach, omitting the exact proof selected the wildcard label. The Merkle proof authenticated each record but did not make the human-visible projection or proof-subset semantics unique.
- **PoC (falsifiable):** create two distinct addresses with equal first/last three bytes and names that differ only after the first 28 displayed bytes, only by ASCII case, or only by trailing spaces that the LCD already paints as padding. Compilation must reject them on the same chain, and a wildcard-chain record must collide with every matching concrete chain; disjoint concrete chains remain valid. An exact/wildcard pair for one address must paint one normalized name, otherwise it too is rejected (`dbgen/src/names.rs:645-766`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** define the name truncation and address-fingerprint projection once in the shared renderer crate, mark truncation explicitly, make dbgen reject case-insensitive display collisions for distinct addresses across every overlapping exact/wildcard chain scope, and require overlapping entries for one address to paint one normalized name.
- **Resolution:** Working-tree fix, 2026-07-10 (**commit pending**). The LCD and dbgen now share `verified_name_display_bytes` and `verified_name_address_fingerprint`; long names render as the first 28 bytes plus `~`, catalogue generation rejects colliding padded, ASCII-case-folded visible projections, and exact/wildcard aliases for one address cannot carry competing displayed names.

## Suspicions (unverified — no PoC)

None recorded. Potential hardware/compiler-fault behavior and broad fuzz outcomes
remain validation residuals, not source findings without a falsifiable witness.

## Honest residual

1. **What I tried to break and COULDN'T.** After the working-tree fixes, the reviewed paths resisted: proof stripping for compiled, policy-rejected, broken-include, and misnamed registry calls; dynamic EIP-712 hash-word substitution; ABI aliases, dirty padding, suffixes, and unsupported C2/C3 layouts; address/token/amount/fee/name collisions; domain/duplicate/IR ambiguity; hidden-action fields; Safe ERC-721-as-ERC20 classification; signer/target/chain/gas/nonce substitution; and one-instruction omission of the reviewed binding/route gates. The strongest concrete controls are the uncompiled 1inch known-call witness, Hyperliquid dynamic-string exclusion, Lido WithdrawalQueue ERC-721 witness, named-address collision generator tests, and the secure FI source regressions.
2. **What I did NOT look at.** The remaining structured/full Kani sweep is pending. No hardware execution, fault-injection bench campaign, UI-on-device review, or fuzz target was run. This pass did not re-audit unrelated Safe/CoW cryptographic verifiers, the smart-wallet contracts, secure elements, USB transport, or firmware update paths. It also did not manually prove the semantic honesty of all **431** compiled leaves; the still-unavailable ERC-8176 provenance is why production stays blocked. The **3,620**-tuple known-call Bloom filter can create false positives (liveness refusal only), and future saturation/growth needs governance. Generic non-ERC-7730 Safe/CoW envelope pages still use their existing lossy aggregate gas presentation rather than the exact per-component UserOp presentation added to the ERC-7730 path. Loud opaque/off-chain signing modes remain intentionally separate trust tiers.
3. **Provenance.** Executed in this review: ERC-7730 crate tests **183/183**; tx, AA, and tx-core tests green; dbgen unit **169/169**, registry round-trip **17/17**, phase-5 policy/include **18/18**, and xtask tests green; generated-descriptor sync green; full secure tests **2,124 passed, 0 failed, 1 diagnostic ignored**; `make secure` green; `make prod-check` reached its expected provenance refusal; four targeted array Kani harnesses **4/4**; and `resolve_structured_panic_free_and_in_bounds` **SUCCESSFUL** with **0/198 failed**, **4 unreachable**, verification time **561.55 s**. That is five targeted resolver harnesses green in total. `git diff --check` is green. The repo-wide `cargo fmt --all -- --check` gate is not currently green and reports broad formatting drift, including untouched files; no mass reformat was applied. The remaining Kani suite, hardware, and fuzz claims are explicitly not covered.
