---
surface: clear-signing
run_date: 2026-07-10
reviewer: GPT-5 Codex multi-agent adversarial review
scope: ERC-7730 registry compiler, authenticated IR/binding, calldata and EIP-712 renderers, direct/Safe dispatch, UserOp context pages, FI permission gates, and catalogue provenance
status: fixes-landed-production-blocked
---

# Adversarial-review findings — clear-signing — 2026-07-10

## Summary

30 handled findings: **28 confirmed-real with fixes landed on the integration branch,
1 deferred production ship blocker, and 1 accepted lower-trust mode**. The review
found exploitable display/binding ambiguities in dynamic EIP-712 fields, ABI
framing, hidden operands, identity/number formatting, duplicate bindings, and
Safe classification; it also found fail-open downgrade and fault-injection gaps
around descriptor membership and route selection, plus a verified-name display
collision. A 2026-07-12 validation continuation added five findings covering
endpoint-only token paths, survivor-bound EIP-712 discriminators, invisible
partial-format omissions, runtime-dead opaque bytes, and selector-only ABI
grammar. The fixes are carried by the integration change under review; they
remain explicitly blocked from production authority.

The pass combined adversarial source review with targeted execution. The
executed boundary was: ERC-7730 184/184; the tx/AA/core crates green; dbgen
171/171, DB-trailer 2/2, round-trip 18/18, phase-5 29/29; xtask 38 unit
and 10 CLI tests green; generated-descriptor sync green; the full secure
suite had 2,125 passed, 0 failed, and 1 diagnostic test ignored; the fuzz
workspace had 68 tests pass and one corpus seeder ignored; the complete QEMU
E2E assertion set passed; and hardened secure/non-secure ARM links passed their
explicit flash/RAM checks. Four array Kani harnesses were green, with
`resolve_structured_panic_free_and_in_bounds` also successful (0/198
failed, 4 unreachable, 545.57 s).
`make prod-erc7730-provenance-check` reached and enforced the expected
`dev-unattested` provenance failure without masking the independent rollback
quarantine. At that original integration checkpoint, the remaining full Kani
sweep, hardware, and sustained fuzz campaigns had not been run; the later
source-tree continuation evidence is scoped explicitly in the Honest residual.

After the continuation fixes were merged, deterministic regeneration produced
**420 authenticated leaves**, root
`048fd2f1ff61942027ffa248f7d26fdbe9d8e2f02e9ad6478ad6714cb96ab142`,
**4,542 exact known-call tuples**, tuple-set SHA-256
`96ea46d23d2f321a81030b77a61a243a003c1ceb6d0dca8df32ba838bcc0c88b`,
and Bloom occupancy **28,235 / 131,072 bits**. The committed review records all
**274** descriptor/format omissions by exact reason. These are generated-artifact
receipts, not a claim that a catalogue-entry membership self-check proves parser
completeness; parser/ABI completeness is covered by independent grammar tests,
raw/resolved declaration tests, and exact tuple-set drift receipts. The completed
merged-tree validation is recorded separately below; no earlier run is silently
attributed to this regenerated root.

## Findings

### F1 — Known registry calls could downgrade when their descriptor was omitted

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 · MED
- **Location:** `dbgen/src/erc7730.rs:680-691,951-1027`; `secure/src/tx/display/dispatch.rs:185-355`; `secure/src/tx/display/safe_display.rs:145-280,503-576`
- **What:** the omission filter covered emitted formats, not every parsable call declared by the vendored registry. A strict-policy rejection could therefore turn a registry-known call back into an “unknown” call, and a verified descriptor's `Reject`, `NoFormat`, or `PageBudget` could fall through to a weaker rendering rung.
- **PoC (falsifiable):** 1inch AggregationRouterV5 on mainnet, contract `0x1111111254eeb25477b68fb85ed929f73a960582`, selector `0x12aa3caf`, is intentionally uncompiled yet must remain Bloom-positive (`dbgen/tests/erc7730_roundtrip.rs:103`). A broken include and a context+display descriptor stored under a non-catalogue filename must likewise retain all raw parsable declarations in the omission filter (`dbgen/tests/erc7730_phase5_policy_and_includes.rs:407,541`). Stripping the proof for WETH `deposit()` must refuse in direct and Safe/MultiSend paths (`secure/src/display_under_test/wysiwys_dispatch_differential_tests.rs:780-812`; `safe_display_render_pure_tests.rs:293-296,378-390`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** build the firmware-pinned omission filter from every parsable registry declaration before compilation, make all verified-render failures fatal, and run the exact-tuple proof on direct Safe calls and every accepted MultiSend record.
- **Resolution:** Integration-branch fix, 2026-07-12. Known-call collection is a mandatory fail-closed preflight for every selected or otherwise-unscanned lowercase JSON file: semantic JSON parsing and include resolution occur before tolerant compilation, and failures abort the whole catalogue. Context+display `common-*` files and escaped semantic keys are no longer exempt; uppercase `.JSON`, symlink entries, and non-UTF-8 regular filenames are rejected rather than silently omitted. Selector derivation is independent of the stricter WYSIWYS renderer parser, so a render-invalid but ABI-derivable declaration (including duplicate parameter names) remains in the filter. Direct and Safe dispatch refuse Bloom-positive calls without independently authenticated semantics; all verified-render errors are fatal.

### F2 — Flat dynamic EIP-712 fields rendered opaque hash words as values

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS5 · HIGH
- **Location:** `dbgen/src/erc7730.rs:2311-2327,2623-2644`
- **What:** EIP-712 `encodeData` stores `string`, `bytes`, arrays, and structs as hashes. Treating the corresponding 32-byte word as the descriptor's human value can label a keccak digest as an amount, destination, or other meaningful content that the device never decoded.
- **PoC (falsifiable):** the real Hyperliquid Withdraw type uses dynamic strings for `hyperliquidChain`, `destination`, and `amount`; it must be absent from the authenticated runtime catalogue. Regression coverage is `dbgen/src/erc7730.rs:6402-6500` and `dbgen/tests/erc7730_roundtrip.rs:57-101`.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** permit flat EIP-712 rendering only for static scalar terminals; dynamic/composite content needs a separately authenticated nested decoder or must be excluded.
- **Resolution:** Integration-branch fix, 2026-07-10. dbgen now rejects visible flat hash-word terminals and hidden dynamic members, including the Hyperliquid witness and nested hidden children.

### F3 — Calldata fields were not bound to one canonical ABI frame

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS9 · HIGH
- **Location:** `pqsigner-erc7730/src/display/render/mod.rs:113-150`; `pqsigner-erc7730/src/display/render/formatters.rs:1088-1160`; `pqsigner-erc7730/src/render/resolve.rs:147-224,346-445`
- **What:** field-local resolution was insufficient to prove whole-calldata canonicality. Aliased offsets, extra suffixes, dirty padding, hidden dynamic fields, and unsupported C2/C3 tail topology could leave signed bytes outside the trusted display's interpretation.
- **PoC (falsifiable):** append a static suffix; add trailing bytes or dirty right-padding to a hidden sole-dynamic field; alias a second dynamic tail; or use a C2 dynamic tuple. Each must decline rather than preserve the same trusted pages (`display/render/formatters.rs:3948-4085`; `render/resolve.rs:615-863`; corpus exclusions in `secure/src/display_under_test/erc7730_render_pure_tests.rs:1911-1925,2906-3025`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** perform a format-wide framing preflight before visibility or page emission; support only exact all-static EOF or one sole C1 whole tail until the IR can authenticate more topology.
- **Resolution:** Integration-branch fix, 2026-07-10. The renderer validates all fields, including hidden fields and token paths, and rejects C2, multi-tail, alias, gap, padding, and suffix ambiguity. Unsupported catalogue formats are excluded fail-closed.

### F4 — Display formatting was non-injective or omitted token identity

- **Status:** ✅ FIXED
- **Mode / severity:** CS4 · HIGH
- **Location:** `pqsigner-erc7730/src/display/primitives.rs:337-412,518-600`; `pqsigner-erc7730/src/display/render/amount_decision.rs:90-186`; `pqsigner-erc7730/src/display/render/formatters.rs:417-552,1414-1485`; `pqsigner-erc7730/src/display/render/mod.rs:824-884,982-1031`
- **What:** truncation/rounding and identity-free amount fallbacks could make distinct signed addresses, token contracts, chain IDs, fees, or 256-bit values share a reassuring display. A symbol or decimal scale is not sufficient token identity unless it is Merkle-bound to the exact chain and contract.
- **PoC (falsifiable):** flip one token address while preserving the amount/symbol; use an unverified token with the same ticker; vary fee words below a rounded display unit; or supply a value too wide for the page. The render must show the full identity/exact integer or reject (`amount_decision.rs:308-410,557-802`; `formatters.rs:3748-3806,3872-3915,4091-4170`; `display/render/mod.rs:1134-1237`; `secure/src/display_under_test/pure_tests.rs:874-965`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** make every security-relevant sink injective: full EIP-55 addresses, exact raw integers, exact chain IDs and fee base units, plus an explicit full token-identity page whenever exact verified metadata is unavailable.
- **Resolution:** Integration-branch fix, 2026-07-12. Exact rendering or refusal now replaces truncation/rounding. Raw and overflow fallbacks show full addresses and integers; Merkle-verified names use the separately collision-gated name/fingerprint transform recorded in F12. Every bound non-native scalar `tokenAmount`, token array, and `tokenTicker` adds a full contract-address page even when authenticated amount/ticker text fits. Same-symbol different-contract differentials and page-exhaustion regressions prove identity is either shown or signing refuses.

### F5 — Domain, duplicate-leaf, and IR canonicality admitted competing interpretations

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS3 / CS9 · HIGH
- **Location:** `pqsigner-erc7730/src/binding.rs:52-104`; `dbgen/src/erc7730.rs:705-783,903-948,1433-1445`; `pqsigner-erc7730/src/ir.rs:300-510`; `pqsigner-erc7730/src/render/params.rs:198-375`; `tx/src/erc20/merkle.rs:41-72`
- **What:** accepting explicit descriptor-supplied domain separators, non-identical duplicate bindings, non-canonical IR/TLV suffixes, or proof-index aliases can let the companion select competing trusted displays for one signed payload or reinterpret authenticated bytes.
- **PoC (falsifiable):** construct two distinct EIP-712 leaves with the same `(chain_id, domain_separator, full type_hash)`; append malformed/unreachable format or TLV bytes; duplicate a singleton TLV; or set leaf-index bits above the proof depth. All must reject (`dbgen/src/erc7730.rs:6505-6575,8623-8648`; IR/params unit tests; `tx/src/erc20/merkle.rs:103`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** compute the domain separator canonically from the declared domain with deployment-bound chain and verifying contract; reject competing full binding keys; require exact-EOF canonical IR/TLV parsing and consume the complete Merkle index.
- **Resolution:** Integration-branch fix, 2026-07-10. Canonical DS generation, duplicate-binding rejection, strict schema/IR/TLV parsing, and `idx == 0` proof completion now make the authenticated interpretation unique.

### F6 — Merkle/binding and omission permissions were not FI-recomputed

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 / CS3 · HIGH
- **Location:** `secure/src/tx/erc7730.rs:49-218`; `secure/src/nsc/cmd_sign_userop.rs:561-650`; `secure/src/nsc/cmd_sign_userop_batch.rs:578-659`; `secure/src/nsc/cmd_sign_offchain.rs:452-526`; `secure/src/tx/display/dispatch.rs:223-355`; `secure/src/tx/display/safe_display.rs:256-280,540-576`
- **What:** the prior secure flow verified Merkle membership once, cached a context-binding boolean, and then sentinel-checked that cached result. One skipped Merkle reject could therefore launder unrooted IR. The first omission-gate draft also put proof calls behind outer route branches / `?` propagation, so skipping the route could bypass both inner checks.
- **PoC (falsifiable):** structural mutation removing either membership recomputation, caller-owned volatile FAIL publication, caller CFI bump, or either final reject gate must fail `secure/src/nsc_erc7730_binding_fi_pure_tests.rs:67-206`; equivalent direct/Safe route-order regressions are pinned in `safe_display_render_pure_tests.rs:427-475`.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** independently recompute exact bundle/root membership and context binding twice around a randomized gap, require each parse to equal the caller's IR, publish to a caller-owned volatile FAIL slot, and consume it with caller CFI plus two final gates. Route omission proofs unconditionally with fail-initialized evidence.
- **Resolution:** Integration-branch fix, 2026-07-10. Single, batch, and off-chain binding surfaces now use the full proof contract; direct and Safe/MultiSend omission checks have unconditional A/B route proofs and duplicated final refusals.

### F7 — UserOp clear-sign pages omitted or compressed signed context

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS4 · HIGH
- **Location:** `secure/src/tx/display/value_page.rs:61-209`; `secure/src/nsc/cmd_sign_userop.rs:807-823,1332-1360`; `secure/src/nsc/cmd_sign_userop_batch.rs:841-857,1018-1046`; `tx-core/src/eip1559.rs:388-410`; `pqsigner-erc7730/src/display/render/mod.rs:758-1031`
- **What:** a rich ERC-7730 inner-call display was not sufficient to identify the signing account, execution target, full chain, fee envelope, all three UserOp gas components, and full nonce. Totals, rounded fees, or truncated nonce/chain representations are non-injective over signed UserOps.
- **PoC (falsifiable):** change only the account/sender, target, high nonce bits, chain ID, or permute call/verification/pre-verification gas while preserving the total. Trusted pages must differ or signing must decline (`secure/src/tx/display/value_page.rs:483-616`; `display/render/mod.rs:1134-1308`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** splice FI-proven full signer/account and target pages around every rich renderer; display exact numeric chain/fees, each UserOp gas component separately, and the full 256-bit nonce.
- **Resolution:** Integration-branch fix, 2026-07-10. Single and batch UserOp paths enforce/prove the context pages; the shared renderer now exposes all signed gas, fee, chain, and nonce operands without lossy compression.

### F8 — Hidden material and semantic exemptions could conceal signed action bytes

- **Status:** ✅ FIXED
- **Mode / severity:** CS5 · HIGH
- **Location:** `dbgen/src/erc7730.rs:3785-4128`
- **What:** the old policy treated hidden non-address values as plausibly benign and allowed signature/path-based hidden-address exceptions. A descriptor could show a recipient or intent while hiding a scalar, packed routing word, deadline, or arbitrary `bytes` action; an ABI-name exemption was not bound to one authenticated deployment.
- **PoC (falsifiable):** compile `execute(address target,bytes payload)` with the payload hidden, hide an effect-bearing scalar, define a custom EIP-712 struct named `address`, or reuse an exempted signature on another deployment. Each must be absent from the authenticated root (`dbgen/src/erc7730.rs:7930-8133`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** reject every hidden terminal except an elementary scalar address that another visible field or tokenPath structurally surfaces exactly; delete semantic signature-only exemptions.
- **Resolution:** Integration-branch fix, 2026-07-10. Rule 3 now excludes all hidden non-address material and ambiguous composite types; recursive address coverage remains, with only the exact structurally surfaced address exception.

### F9 — Safe could classify an ERC-721 `approve` as ERC-20

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS2 · HIGH
- **Location:** `secure/src/tx/display/safe_display.rs:145-244,503-576`
- **What:** ERC-20 and ERC-721 share `approve(address,uint256)`. Exempting a Bloom-positive Safe inner call merely because its calldata matched the ERC-20 ABI could present an NFT token ID as a fungible amount and bypass the required ERC-7730 descriptor.
- **PoC (falsifiable):** Lido WithdrawalQueue ERC-721 `approve(address,uint256)` must reject without an exact descriptor, directly and inside MultiSend; genuine ERC-20 remains accepted only with Merkle-verified metadata for the exact chain and contract (`secure/src/display_under_test/safe_display_render_pure_tests.rs:301-407`).
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** treat verified ERC-20 metadata as an exact capability bound to `(chain, contract)` and require strict ERC-20 decoding; otherwise a known tuple needs its descriptor. Check every MultiSend record before classification.
- **Resolution:** Integration-branch fix, 2026-07-10. The Safe route now grants the native ERC-20 exemption only with exact authenticated metadata, while ERC-721 and other ABI-identical known calls refuse without their own proof.

### F10 — Real ERC-8176 catalogue provenance is unavailable

- **Status:** ⏸ DEFERRED
- **Mode / severity:** CS3 / production provenance · MED ship blocker
- **Location:** `secure/data/erc7730/policy.toml:1-48`; `dbgen/src/erc7730.rs:471-515`; `dbgen/src/main.rs:299-318,526-574`; `secure/src/db_roots.rs:117-130`; `Makefile:2176-2190`
- **What:** the current catalogue is explicitly `dev-unattested`. There are no trusted ERC-8176 attestations for the shipped descriptor hashes and dbgen deliberately has no production EAS snapshot signature/identity verifier. Structural WYSIWYS gates cannot prove that descriptor prose is semantically honest about the real contract.
- **PoC (falsifiable):** `make prod-erc7730-provenance-check` must fail unless generated provenance is exactly `erc8176-verified`; obsolete embedded `attestations` arrays must never satisfy production policy (`dbgen/tests/erc7730_phase5_policy_and_includes.rs:40-67,85+`). The current 420-leaf catalogue contains 224 unique descriptor hashes, with measured trusted coverage 0 of 224 (`docs/erc8176-attestation-status.md:57-71`).
- **Disposition:** OPEN_RESEARCH
- **Proposed fix:** once trusted auditors publish real ERC-8176 records, take a reproducible offline EAS snapshot, authenticate signatures and attester identity, bind every accepted record to the exact JCS descriptor hash, and exclude unattested leaves.
- **Resolution:** Deferred, 2026-07-10. Production provenance remains fail-closed behind `make prod-erc7730-provenance-check`; the target observes the intended failure after descriptor-sync verification: catalogue provenance `dev-unattested`, required `erc8176-verified`. The independent `make prod-check-ship` rollback refusal remains separately observable. Tracked in `docs/work-todo.md:2585-2597` and `docs/erc8176-attestation-status.md`; unblock requires both real trusted attestations/identities and the production snapshot verifier.

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
- **Resolution:** Integration-branch fix, 2026-07-10. The LCD and dbgen now share `verified_name_display_bytes` and `verified_name_address_fingerprint`; long names render as the first 28 bytes plus `~`, catalogue generation rejects colliding padded, ASCII-case-folded visible projections, and exact/wildcard aliases for one address cannot carry competing displayed names.

### F13 — Root-only registry vendoring could drop refused known calls

- **Status:** ✅ FIXED
- **Mode / severity:** CS3 · MED
- **Location:** `xtask/src/main.rs` (`vendor-registry`); `dbgen/src/erc7730.rs` (`known_call_set_hash`)
- **What:** the old vendor command selected project directories only from descriptors that emitted at least one Merkle leaf and then compared only the rebuilt root. A project containing exclusively rejected/unsupported descriptors could disappear while the accepted root remained identical. Its parsable call declarations would then also disappear from the known-call Bloom, restoring the lower generic/blind ladder for a call the upstream registry identifies but the strict renderer refuses.
- **PoC (falsifiable):** a live fixture plus a separate dead-only descriptor produces one accepted root and a larger known-call set. Delete only the dead project: the root stays equal, while the canonical tuple-set digest/count and Bloom change. A faithful vendor operation must preserve the file and all receipts; `xtask/tests/cli.rs::vendor_registry_preserves_dead_only_known_calls_not_just_merkle_leaves` pins the differential.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** integration-branch fix, 2026-07-12. Vendoring copies the complete non-fixture `registry/**/*.json` + `ercs/**/*.json` corpus and parses every excluded `tests/` / `.tests.` JSON before omission scanning, rejecting includes, any deployment declaration, or a fully-specified domain-only EIP-712 binding, and emitting a separate deterministic excluded-inventory receipt. The frozen upstream fixture receipt is 272 files / 687,949 bytes / SHA-256 `689a0904b10841fbd5d9ead4a6b8e049f04a5146eac88b6d8f2faa565abd685f`. A post-review independent run against a clean checkout of `ethereum/clear-signing-erc7730-registry` at exact commit `784c87c925e8438e7b4736b2af85a501f8d2a265` reproduced all three values; the current vendor command also parsed every excluded fixture and reproduced the 4,542-tuple receipt. It rejects traversal errors/symlinked roots or entries/non-UTF-8 regular filenames, hashes the exact sorted copied corpus, compares the byte-identical catalogue/review plus root/leaf/provenance and exact tuple-set/count/Bloom receipts, and verifies in a staging tree before a checked two-directory transaction. Every rollback operation is checked; an uncertain restore reports `ROLLBACK INCOMPLETE`, retains the backup path, and never claims success. Eleven files missing from the recorded upstream commit were restored; after the continuation gates, the catalogue is 420 leaves and 4,542 known calls.

### F14 — Make provenance policy was command-line overrideable

- **Status:** ✅ FIXED
- **Mode / severity:** release-process · LOW
- **Location:** `Makefile`; `fsbl-tests/tests/erc7730_provenance_fences.rs`
- **What:** GNU make command-line precedence could rewrite the review path, observed provenance, or required provenance and make the advertised process gate print PASS. This did not bypass the independent generated Rust production fence, but it made the release-process evidence false-green.
- **PoC (falsifiable):** pass `ERC7730_CATALOGUE_PROVENANCE=erc8176-verified`, `PROD_ERC7730_PROVENANCE=dev-unattested`, or a forged review path to the negative gate. All must still fail for the exact dev-vs-verified reason, including under `make -i`.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** the three values are `override :=` policy inputs, with a separately enrolled and executed negative-test target in CI.

### F15 — Typed-data E2E test could pass without reaching typed rendering

- **Status:** ✅ FIXED
- **Mode / severity:** test assurance · LOW
- **Location:** `secure/data/erc7730-e2e/eip712-delegation.json`; `nonsecure/{build.rs,src/e2e_test.rs}`
- **What:** the previous scenario supplied a contract-context WETH proof, placeholder domain/type hashes, and empty encoded data, then accepted either the intended binding rejection or an earlier unregistered-slot rejection. It proved neither a valid EIP-712 leaf nor the typed renderer/sign path.
- **PoC (falsifiable):** the replacement fixture derives domain separator, primary type hash, and trailer from a real synthetic EIP-712 leaf; it must return `Ok` and increment the off-chain count. Flipping one domain bit must return exactly `InvalidPointer`. A separate known-call WETH Sepolia `deposit()` with a valid mainnet proof must return exactly `InternalError`, proving misbinding cannot restore blind signing.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** integration-branch fix, 2026-07-12; host round-trip also requires a nonzero, verifiable EIP-712 leaf in the E2E catalogue.

### F16 — Generated-root drift checking accepted cfg-disabled security items

- **Status:** ✅ FIXED
- **Mode / severity:** release assurance · MED
- **Location:** `xtask/src/main.rs` (`diff_root_in_db_roots`); `dbgen/src/{lib,main}.rs`
- **What:** the drift checker searched for expected Rust snippets while lexically excluding comments and strings, but it did not evaluate attributes. An expected root or provenance fence under an additional `#[cfg(any())]` therefore counted as present even though rustc removed it; a different active definition could compile in its place.
- **PoC (falsifiable):** insert `#[cfg(any())]` immediately before the otherwise-exact production root and provide a forged active definition elsewhere. The old marker scan returned green. `erc7730_codegen_requires_the_complete_exact_security_suffix` pins this exact mutation plus comment, raw-string, enclosing-module, swapped-root, swapped-filter, and deleted-fence variants.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** dbgen now owns one canonical generated security suffix through EOF: inert anchor, both roots, both Bloom paths, both provenance constants, and every associated compile fence. xtask and its mutation tests use the same production matcher and require exactly one sentinel plus a byte-identical complete suffix. The inert first item absorbs any attribute placed before the suffix, while an attribute inside or an enclosing construct changes the checked bytes. The suffix imports the real extern-prelude `core` under the collision-sensitive `__pqsigner_erc7730_core` alias, then invokes `include_bytes!` and `compile_error!` through that alias. A prior `extern crate self as core` can no longer shadow those macros, while a prior definition of the private alias becomes a duplicate-name compile failure. An executed compile-fail regression pins both attacks.

### F17 — Known-call preflight swallowed include and raw-scan failures

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 · MED
- **Location:** `dbgen/src/erc7730.rs`; `dbgen/tests/erc7730_phase5_policy_and_includes.rs`
- **What:** tolerant catalogue generation discarded `collect_declared_contract_calls` errors and classified unscanned files through raw string substrings. A child descriptor could carry deployments while an included template supplied every format; if that include was broken, raw scanning found no selector and resolved scanning failed silently, so the tuple vanished from the omission filter and could regain the generic/blind ladder. Escaped keys, `common-*` filenames, uppercase extensions, and non-UTF-8 names supplied adjacent omission paths. Separately, selector extraction reused the renderer's stricter parameter-name parser and silently dropped selectors that remained ABI-derivable, such as `f(address to,uint256 to)`.
- **PoC (falsifiable):** `child_deployments_with_all_formats_in_broken_include_fail_closed` constructs the exact split descriptor; the whole build must now fail before compilation. `unscanned_child_with_deployments_and_included_formats_is_known` combines an escaped context key with include-supplied formats. `duplicate_parameter_names_are_unrenderable_but_selector_remains_known`, `deployed_common_descriptor_is_flagged_and_covered_by_omission_filter`, `uppercase_json_extension_is_rejected_not_silently_omitted`, and `non_utf8_regular_file_name_fails_collectors_closed` pin the adjacent paths.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** include-resolved semantic known-call collection is now a mandatory fail-closed preflight for selected and all otherwise-unscanned JSON files, including sibling `ercs/` and fixture-named paths. Nested includes resolve relative to the immediate including file. ABI selector canonicalization is intentionally separate from renderer validation: render-invalid declarations remain known whenever their selector is derivable; the selector-only parser normalizes standard Solidity aliases while the stricter trusted-render compiler may still reject the source format. Invalid widths, custom/ambiguous types, malformed arrays/tuples, selector-only hex keys, and every other underivable deployed format abort generation. No tolerant per-format compilation starts after a scan failure; diagnostics are catalogue-relative and do not leak checkout paths. The resulting set contains 4,542 exact `(chain, contract, selector)` tuples.

### F18 — Vendor rollback errors were discarded while reporting restoration

- **Status:** ✅ FIXED
- **Mode / severity:** release tooling / availability · LOW
- **Location:** `xtask/src/main.rs` (`install_vendored_subdirs`)
- **What:** the two managed directories were renamed sequentially. If installing the second directory failed, every reverse rename used `let _ = ...` and the command unconditionally said the prior corpus was restored, even if rollback itself failed. That could leave a mixed local catalogue behind a false-success diagnostic.
- **PoC (falsifiable):** `vendor_install_second_move_failure_restores_both_prior_directories` removes the staged `ercs/` directory so the second install move fails after the first succeeds, then byte-checks both prior directories and the returned new staging directory.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** the operation is documented as a checked two-directory transaction, not an atomic pair swap. Every rollback move is checked; uncertainty retains and prints the backup path with `ROLLBACK INCOMPLETE`, and only a complete restoration may claim that the prior corpus was restored.

### F19 — Positive ERC-7730 QEMU coverage was not a merge gate

- **Status:** ✅ FIXED
- **Mode / severity:** test assurance · LOW
- **Location:** `.github/workflows/ci.yml`; `scripts/gate_enforcement.json`
- **What:** the full `make e2e` suite passed locally, including positive typed-data rendering and cross-deployment refusal, but no CI workflow invoked it. The gate manifest instead attributed nonsecure E2E files to the provenance check, which did not execute those scenarios.
- **PoC (falsifiable):** removing or making the new `make e2e` step non-blocking must make `make verify-gate-enforcement` fail for the declared runtime surface.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** CI now installs the ARM linker and QEMU, boots the combined secure/nonsecure image with `make e2e`, and requires its explicit all-assertions sentinel. The manifest has a separate per-PR `e2e` gate; provenance and runtime paths are no longer conflated. The suite now exercises positive and mis-bound ERC-7730 bundles on both the single and atomic-batch UserOp commands, plus positive EIP-712/off-chain binding; a batch-path claim can no longer pass on single-command coverage alone.

### F20 — Canonical companion lookup selected the wrong duplicate deployment leaf

- **Status:** ✅ FIXED
- **Mode / severity:** companion availability / integration · LOW
- **Location:** `tools/companion-stub/erc7730_trailer.py`; `dbgen/tests/erc7730_roundtrip.rs`; `docs/companion/companion-erc7730-implementation-guide.md`
- **What:** the reference Python helper selected the first `(chain_id, contract)` entry. The production catalogue contains LBTC deployments with both contract-context and EIP-712 leaves at the same address, so typed-data lookup selected the contract leaf and hard-refused. The guide also had incorrect IR-pool offset, chain-width, implicit leaf-index, intent, and empty-names examples.
- **PoC (falsifiable):** `companion_stub_context_and_full_type_hash_lookup_verify_on_device` exercises both duplicated LBTC deployment groups, requires explicit EIP-712 context plus the full authenticated-IR primary type hash, preserves contract-context default compatibility only when unique, and rejects wrong or ambiguous hashes.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** the helper validates catalogue bounds, authenticated IR, format entries, and padding; selects by explicit `contract|eip712` context; requires and uniquely matches the full 32-byte EIP-712 primary type hash; and rejects malformed/zero/ambiguous matches. The guide derives that hash from canonical EIP-712 `encodeType`, standardizes helper output as the unframed inner bundle so each command adds exactly one length prefix, documents dynamic/struct/array `encodeData` hash words, and matches the actual 17-byte off-chain header and EOF-encoded empty-names framing. It no longer invents a names section for RAW32/PersonalSign or uses v0.7 `PackedUserOperation` terminology for this frozen v0.6 target; fixture-only render claims are labelled as such.

### F21 — Endpoint-only token paths could hide intermediate swap-route addresses

- **Status:** ✅ FIXED
- **Mode / severity:** CS1 / CS5 · HIGH
- **Location:** `dbgen/src/erc7730.rs` (`check_contract_field_completeness`, `check_field_visibility`, `token_path_surfaces_exact_scalar_address`)
- **What:** an indexed `tokenPath` such as `path.[0]` or `path.[-1]` counted as coverage for the entire signed `address[] path`. Changing a three-hop route's middle address left every renderer-read source unchanged: the device still showed the same input/output tokens, amounts, recipient, and deadline while the router executed a different path. Packed-`bytes` endpoint slices had the same completeness flaw.
- **PoC (falsifiable):** the pre-fix catalogue admitted endpoint-only QuickSwap, ParaSwap, and Router02 formats. In the existing three-hop resolver vector, changing only `TOKEN_MID` changes calldata/signature but not either endpoint page. Regression tests now reject indexed `address[]` and sliced packed-`bytes` coverage while full `path.[]` rendering remains eligible.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** let a token path satisfy whole-operand completeness/visibility only when it resolves to one exact scalar address; composite routes must render in full or be excluded.
- **Resolution:** integration-branch fix, 2026-07-12. The compiler distinguishes token identification from complete signed-operand coverage. Endpoint-only formats are absent from the regenerated 420-leaf root, while their selectors remain in the omission filter.

### F22 — EIP-712 catalogue lookup could advertise an absent or incomplete type key

- **Status:** ✅ FIXED
- **Mode / severity:** CS3 · LOW / liveness and metadata consistency
- **Location:** `dbgen/src/erc7730.rs` (`compile_descriptor`, `resolve_per_deployment`); `tools/companion-stub/erc7730_trailer.py`
- **What:** `primary_type_hash` was derived from the lexicographically first source format before tolerant filtering. A leaf could therefore advertise a type hash absent from its emitted IR. In addition, one entry-level field can name only one format in a multi-format leaf, so using it as the EIP-712 security lookup key made surviving secondary formats unreachable.
- **PoC (falsifiable):** Lens descriptors previously indexed a rejected source format while emitting different survivors; multi-format leaves expose the same failure when the requested type is not the entry-level hint. The helper must find the exact full type hash inside authenticated IR, not trust a four-byte prefix or first-source hint.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** derive the entry hint from the first surviving emitted format, then perform companion lookup by exact domain separator and full 32-byte type hash across the authenticated format table.
- **Resolution:** integration-branch fix, 2026-07-12. The entry field is explicitly a non-load-bearing first-survivor sort/diagnostic hint. Source-to-IR tests reject orphan hints, and the executable helper scans candidate IR by exact domain separator plus full type hash.

### F23 — Partially rejected source formats were absent from the audit receipt

- **Status:** ✅ FIXED
- **Mode / severity:** CS3 / auditability · LOW
- **Location:** `dbgen/src/erc7730.rs` (`compile_formats_reporting`, `build_db_inner`, `render_review`); `secure/data/erc7730.review.txt`
- **What:** tolerant compilation accumulated exact per-format errors but discarded them whenever a sibling format survived. A source could therefore contribute a leaf while silently omitting other signatures, making source-to-runtime coverage impossible to reconcile from the committed review. The known-call filter still failed closed; the impact was evidence quality, not a blind-sign downgrade.
- **PoC (falsifiable):** compare source `display.formats` keys with the generated review. Every non-emitted source format must now have a full-signature omission row and an exact reason.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** retain full signatures and compiler errors for every tolerant rejection, including cap overflow and partial descriptors, and drift-gate the receipt.
- **Resolution:** integration-branch fix, 2026-07-12. The regenerated review records **274** omissions by category and includes one `PARTIAL FORMAT DROP` row for every rejected sibling format; the review and catalogue are regenerated and checked together.

### F24 — Opaque dynamic-bytes formats were authenticated but runtime-dead

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 / coverage truth · LOW
- **Location:** `dbgen/src/erc7730.rs` (`compile_one_field`); `pqsigner-erc7730/src/display/render/formatters.rs` (`render_dynamic_bytes`)
- **What:** arbitrary semantic `bytes` formats could enter the authenticated catalogue even though runtime deliberately rejected every opaque-bytes payload. This failed closed but overstated clear-sign coverage and created unusable catalogue entries.
- **PoC (falsifiable):** TBTC, Wormhole/NTT, Morpho callback, and Celo formats previously emitted the opaque dynamic-bytes kind but could never reach confirmation for any payload.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** reject arbitrary semantic `bytes` during generation until an injective semantic decoder exists, and retain every rejected selector in omission protection.
- **Resolution:** integration-branch fix, 2026-07-12. The compiler no longer emits runtime-dead opaque-bytes fields; dropped declarations remain covered by the exact known-call tuple set.

### F25 — Selector-only Solidity grammar could escape omission protection

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 · MED
- **Location:** `dbgen/src/erc7730.rs` (`contract_selector_signature`, `SelectorSignatureParser`, `collect_contract_calls_from_json`, `known_call_set_hash`); selector and round-trip regression tests
- **What:** coupling selector derivation to renderer field-name/topology policy dropped valid renderer-dead ABI declarations, including canonical tuple arrays. A first repair still risked future gaps through ABI aliases, whitespace, `$` identifiers, nested tuple arrays, or selector-only hex keys. Silently skipping any underivable deployed format would let a firmware-known call look unknown and regain the lower display ladder.
- **PoC (falsifiable):** Safe BatchExecutor `batchExecute((address,uint256,bytes)[])` and other tuple-array calls must remain known even when their formats cannot render. `$foo(uint)` must hash as `$foo(uint256)`. The selector-only parser normalizes `uint`, `int`, `byte`, `fixed`, and `ufixed`, accepts Solidity `$` identifiers and whitespace/nested tuple arrays, and rejects unknown/custom/malformed or hex-only keys instead of guessing.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** use an independent types-only Solidity ABI parser; canonicalize aliases exactly, parse complete tuple/array suffixes, and propagate every derivation failure so catalogue generation aborts. Commit an exact sorted tuple-set count/hash as an external drift receipt.
- **Resolution:** integration-branch fix, 2026-07-12. Known-call collection has no `continue` path for selector derivation. Renderer-invalid but ABI-derivable declarations enter the set; ambiguous declarations abort generation. The regenerated omission filter is built from **4,542** exact tuples with tuple-set SHA-256 `96ea46d23d2f321a81030b77a61a243a003c1ceb6d0dca8df32ba838bcc0c88b`. Bloom insertion/membership is not presented as proof of parser completeness: independent grammar vectors, real tuple-array witnesses, raw/resolved declaration tests, and the exact tuple-set receipt are the assurance boundary.

### F26 — Unverified Safe trailer could launder ERC-20 metadata into a direct batch member

- **Status:** ✅ FIXED
- **Mode / severity:** CS4 · HIGH
- **Location:** `secure/src/nsc/cmd_sign_userop_batch.rs`; `secure/src/tx/display/dispatch.rs`; `pqsigner-erc7730/src/display/render/formatters.rs`
- **What:** batch metadata routing scanned raw MultiSend bytes from any parsed Safe trailer before Safe verification. A direct ERC-7730 call could therefore consume attacker-selected authenticated metadata, while normal bound-token formatting omitted the exact contract.
- **PoC (falsifiable):** mainnet FlyingTulip `PositionsManager.deposit(address,uint256)` with an invalid Safe trailer whose raw MultiSend names one of two real six-decimal `USDT` contracts (`0x1CDD…B7C`, `0xdAC1…ec7`). Before the fix, different signed assets could share the same intent/amount/ticker pages.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** handlers retain only Merkle+chain authority. Final attribution is repeated at dispatch against the signed direct target, exact ERC-7730 `tokenPath`, verified Safe direct target, or a record inside a verified pinned MultiSend context. Raw invalid Safe bytes grant no authority. Every bound non-native display includes the full contract. The Safe helper regression, real FlyingTulip host differential, and full batch QEMU scenario pin the exploit.

### F27 — Non-string `includes` could erase known-call declarations

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 · MED
- **Location:** `dbgen/src/erc7730.rs::load_resolved_descriptor_json`
- **What:** `json.get("includes").and_then(as_str)` treated a present array/object as if no include existed, permitting split declarations to disappear from omission protection.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** a present non-string `includes` is a catalogue-fatal error in the shared resolver used by selected and unscanned JSON. `non_string_include_fails_split_declaration_closed` pins the deployment-in-child/formats-in-template witness.

### F28 — Known-call and renderer selector parsers could disagree

- **Status:** ✅ FIXED
- **Mode / severity:** CS2 · MED
- **Location:** `dbgen/src/erc7730.rs::compile_one_format`
- **What:** the independent canonical parser normalized aliases/arrays while the renderer parser could hash a different types string, permitting a bogus authenticated selector leaf while the correct selector remained only in the refusal filter.
- **PoC (falsifiable):** `aliasCall(uint value)` versus `aliasCall(uint256)`, and `arrayCall(uint256 [2] value)` versus `arrayCall(uint256[2])`.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** contract leaf emission requires exact equality between both independently-derived canonical signatures and hashes the canonical result. A mismatch is a visible tolerant skip but its correct canonical selector remains known/Bloom-positive.

### F29 — Vendor ownership marker carried stale unchecked receipts

- **Status:** ✅ FIXED
- **Mode / severity:** provenance · LOW
- **Location:** `xtask/src/main.rs`; `secure/data/erc7730-registry/.pqsigner-erc7730-vendor`
- **What:** re-vendoring replaced the managed directories without validating hand-maintained receipt text in the ownership marker.
- **Disposition:** CONFIRMED_REAL
- **Resolution:** the marker is an exact one-line regular-file sentinel validated before replacement. Upstream and generated receipts remain in reviewed/generated artifacts. A stale-marker CLI regression fails before either managed directory moves.

## Suspicions (unverified — no PoC)

None recorded. Potential physical hardware/compiler-fault behavior remains a
validation residual. Completed fuzz/Kani outcomes are evidence, not source
findings without a falsifiable witness.

## Honest residual

1. **What I tried to break and COULDN'T.** After the working-tree fixes, the reviewed paths resisted: proof stripping for compiled, policy-rejected, broken-include, and misnamed registry calls; dynamic EIP-712 hash-word substitution; ABI aliases, dirty padding, suffixes, and unsupported C2/C3 layouts; address/token/amount/fee/name collisions; domain/duplicate/IR ambiguity; hidden-action fields; Safe ERC-721-as-ERC20 classification; signer/target/chain/gas/nonce substitution; and one-instruction omission of the reviewed binding/route gates. The strongest concrete controls are the uncompiled 1inch known-call witness, Hyperliquid dynamic-string exclusion, Lido WithdrawalQueue ERC-721 witness, named-address collision generator tests, and the secure FI source regressions.
2. **What I did NOT look at.** No hardware execution, physical fault-injection campaign, or NV3007-on-device review was performed. This pass did not re-audit unrelated Safe/CoW cryptographic verifiers, the smart-wallet contracts, secure elements, USB transport beyond its framing/companion contract, or firmware-update paths. It did not prove semantic honesty of all **420** leaves against deployed bytecode/ABIs or trusted token metadata. Real ERC-8176 provenance remains unavailable, so production stays blocked. The **4,542**-tuple Bloom can create false positives (liveness refusal only); its 25% occupancy gate bounds growth, but does not prove selector-parser completeness. Generic non-ERC-7730 Safe/CoW envelope pages retain their existing aggregate gas presentation. Loud opaque/off-chain modes remain separate trust tiers. Two Kani encodings remain computationally unclosed: `erc7730_ir_parse_panic_free` and `fmt_p0_const_value_chunks_bind_rows` each reached the **900 s** bound without a counterexample or verdict; neither timeout is a proof or a failure.
3. **Validation provenance.** Three evidence sets remain deliberately distinct:

   - **Original integration checkpoint:** ERC-7730 **184/184**, dbgen unit **171/171**, DB-trailer **2/2**, round-trip **18/18**, phase-5 **29/29**, xtask unit **38/38** and CLI **10/10**, secure **2,125 passed / 0 failed / 1 diagnostic ignored**, fuzz-workspace **68/68**, full QEMU E2E, ARM link/resource gates, and the expected production-provenance and rollback refusals.
   - **Pre-transplant 2026-07-12 primary source tree:** `make test-all` passed **1,715 workspace + 2,124 secure + 68 fuzz + 115 Forge tests**; full QEMU E2E, Miri **225**, codegen, thumb secure, and **30/30** golden frames passed. All 12 fuzz targets completed artifact-free; the repaired dual-entry renderer campaign ran **5,989,862** inputs in 120 seconds. Its Kani census was **58/60 successful, 0 failed, 2 bounded no-verdict timeouts**. These remain dated source-tree evidence, not evidence for the regenerated merged root.
   - **Current merged 420-leaf tree:** after applying the final canonical-index/fuzz-profile regressions, the Rust phases of `make test-all` passed **1,744 workspace + 2,125 secure + 69 fuzz-workspace tests** (plus **3 workspace + 1 fuzz diagnostic tests ignored**). The aggregate command then reached the Forge phase, but compilation failed before any Forge test executed because this isolated recovery worktree did not contain `contracts/smart-wallet/lib`. Forge was therefore run separately after temporarily linking that dependency directory: **115 passed / 0 failed / 1 skipped**, and the temporary link was removed immediately afterward. Full `make e2e` QEMU, Miri **225**, secure and nonsecure `thumbv8m` compile checks, codegen sync, and **30/30** golden frames all passed. All **12 fuzz targets** completed 30-second campaigns against the existing local per-target corpora, and the fail-closed artifact sweep found **zero files of any kind**; the renderer completed **21,470,422 executions** at `cov: 108` / `ft: 167`. The fuzz gate checks successful non-empty target enumeration, uses a working versioned LLVM symbolizer, propagates every target's nonzero exit, and rejects every artifact; it cannot green-wash a list/symbolizer startup failure. A nonshipping production-like STM32U585/NV3007 release link also passed with the development vendor key, `dev-unattested` descriptor root, and explicit legacy rollback quarantine. The secure image occupied a **335,936-byte physical flash span** against the **475,136-byte update-slot limit** (**139,200 bytes free**); secure static SRAM ended at `0x3000cf48`, leaving **143,544 bytes** before the configured stack start at `0x30030000`. These are link/static-layout receipts only, not a bound on worst-case dynamic stack use or permission to ship that feature set. The diagnostic `size-report` target now consumes the strict shared `fwmeasure`/`fwsign` physical flattener instead of `.text + .data`; non-empty `PT_LOAD` segments outside or crossing the measurement envelope are rejected, and fixed secure/NS capacities are enforced inside host signing/verification as well as by the updater/FSBL. Its negative controls cover the prior 28,320-vs-28,316 undercount, late/crossing segments, cap+1, a missing required artifact, and an attempted command-line capacity override. Kani was **not rerun on this merged snapshot**. The latest pre-transplant census was **58/60 successful with zero counterexamples** and exactly two **900 s no-verdict timeouts**, `erc7730_ir_parse_panic_free` and `fmt_p0_const_value_chunks_bind_rows`; those inherited results are not proof of this final tree, and the timeouts are neither proofs nor failures. The expected `dev-unattested` production-provenance refusal and independent rollback quarantine were both reached, the provenance-fence test passed, and `git diff --check` was clean. This validation does not lift the independent production provenance or hardware blockers.
   The final strict-flattener pass additionally anchors the envelope to the linked `__vector_table`, rejects early as well as late/crossing non-empty `PT_LOAD` segments, and makes `size-report` reject `make --ignore-errors`; these controls prevent a stray segment from shifting the package base or an ignored recipe failure from becoming a green receipt.
4. **Operational residual outside the 30 clear-signing findings.** Wire v2 can emit a Type-1 slot-rotation signature but omits the exact 64-byte new-slot public key needed to construct the signed `addOwnerBytes` calldata. Seedless companions must keep `FLAG_REGISTER_SLOT` clear, reject a nonzero Type-1 response, and never retry it; first deployment remains the separate slot-0 factory path. A reviewed protocol bump returning the exact public key or complete bound calldata is tracked in `docs/work-todo.md`.
5. **Explicit off-chain RAW32 remains a semantic downgrade tier.** Replay-safe nesting prevents a RAW32 request from becoming a bare UserOp-signature oracle, but firmware cannot tell whether the companion obtained the supplied hash from otherwise-supported EIP-712 data. A hostile companion can therefore suppress structured semantic pages by submitting that final hash as RAW32. The device now labels this path `! BLIND RAW32` and renders the complete hash; companion guidance forbids typed-data downgrade. Production should disable RAW32 unless an explicit compatibility decision accepts the residual.
