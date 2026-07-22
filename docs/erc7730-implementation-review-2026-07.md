# ERC-7730 implementation — critical review & improvement candidates (2026-07-02)

**What this is:** an adversarial *engineering* review (not a security audit) of the full
ERC-7730 clear-signing stack — `pqsigner-erc7730`, the secure-world renderer
(`secure/src/tx/display/erc7730/`), and the `dbgen` registry→TLV→Merkle pipeline — measured
against the upstream clear-signing registry (vendored at `secure/data/erc7730-registry/`,
upstream SHA `784c87c`) and the ERC-7730 spec (`specs/` in the registry checkout).
Six independent review lenses (coverage, spec conformance, architecture, rendering UX,
pipeline/tooling, dbgen trust boundary); findings below are merged, deduped, and ranked.
Items marked **[verified]** were re-checked by hand against the code; others carry the
reviewer's file:line evidence.

Companion docs (do not duplicate): `docs/erc7730-coverage-blocker-analysis-2026-07.md`
(historical resolver-capability histogram; the current policy accepts only an exact, sole
C1 dynamic tail and retired C2/C3 on 2026-07-10),
`docs/erc7730-registry-coverage-2026-06.md` (stale counts), the three
`VULN-erc7730-*.md` postmortems.

> **Current-state router (2026-07-18).** This document preserves a dated
> engineering review and point-in-time corrections. Any "current", "pending
> V4", catalogue identity, test count, or review-state statement below is
> historical unless repeated by the live owners: [STATUS.md](STATUS.md) and the
> [PQ1 campaign ledger](work-todo.md#pq1-erc-7730-productization-campaign--owner-direction-2026-07-16).
> Those owners record the V5 no-go and V6 remediation/pre-freeze state. Nothing
> in this dated review grants merge, production, shipment, or forced-blind
> authority.

---

## Tier 1 — Correctness of what already ships (fix first)

### 1.1 Field-level `$ref` → `$.display.definitions` is unresolved and FAILS OPEN (HIGH)
`FieldDef` (dbgen/src/erc7730.rs:290-319) has no `$ref` member and nothing in dbgen uses
`deny_unknown_fields`, so a spec-conformant field reference deserializes with `$ref`
silently dropped → `format=None → "raw"`, `label=None → ""`, and the referenced definition's
`params` (including `tokenPath`) discarded (`compile_params` dispatches on the resolved op,
so under `FMT_RAW` the field's own params are also dropped, erc7730.rs:2242-2246).

**This is live in the pinned root** (`0x7d6249…`): 8 vendored descriptors — 1inch
AggregationRouterV3/V4/V5/V6, ParaSwap AugustusSwapper v5/v6.2 — compile to formats whose
fields render as **blank-labeled 64-char raw-hex dumps under a reassuring "Swap" intent
banner**. The registry-authored rendering (labeled `tokenAmount`s, `path.[0]`/`path.[-1]`
token identity, `date` deadline) never reaches the screen. ~21 empty-label raw fields exist
across the pinned DB.

Aggravator: `check_contract_field_completeness` (erc7730.rs:2383-2390) credits
`params.tokenPath` coverage **from the JSON** while compile drops that tokenPath from the IR —
the H-3 "signed-but-not-shown" lint is satisfied by a field that never renders.

**Fix:** resolve `$ref` by merging the referenced definition (field-local keys win, per spec
merge rules) before `compile_one_field`; hard-error on unresolvable refs; make the
completeness lint credit only what the *IR* carries. Effort M. This single fix also converts
the 1inch/ParaSwap router family from degraded to genuinely clear-signed — likely the largest
single coverage-quality win available.

### 1.2 Array-element `Raw` re-introduces the fixed hex-truncation bug **[verified]** (latent WYSIWYS)
`render_array_element`'s Raw arm (secure/src/tx/display/erc7730/formatters.rs:1064-1069)
passes 16-byte slices to `write_hex_word`, which clamps at `DISPLAY_COLS/2 = 8` bytes
(formatters.rs:1349) — bytes 8..16 and 24..32 of every raw array element are silently
dropped; a BE uint256 < 2^64 renders as all zeros. This is byte-for-byte the magnitude-hiding
bug fixed in scalar `render_raw` on 2026-06-26 (the fix's own comment at formatters.rs:243-251
describes the failure) — the fix never reached the cloned arm. Latent today only because
current corpus Raw arrays are `visible:"never"`, but the arm is in the render-guard `HANDLED`
list and one corpus unlock away from user-visible.
**Fix:** render like scalar `render_raw` (or 4 hex rows); add a value-fidelity host render
test for Raw array elements (none exists); sweep all `write_hex_word` call sites for slices
> 8 bytes; fix the wrong doc comment ("Write 16 bytes … into a 16-col row" is impossible).
Effort S.

### 1.3 Unknown-key / untyped-params silent-drop surface (root enabler of the 1.1 class)
No `deny_unknown_fields` anywhere in dbgen's serde model; `params` is raw `serde_json::Value`
read with `as_u64()/as_str()` guards — a typo'd key (`"decimls"`), a float `6.0`, a future
spec key (v2 `interpolatedIntent`, object-form `visible` rules, `metadata.token`,
`senderAddress`, `nativeCurrencyAddress`) all compile to *something* silently instead of
skipping loudly. On-device fallbacks are fail-safe, but the curator's build-time signal is
lost — this is how 1.1 shipped.
**Fix:** (a) enumerate unconsumed keys in `FieldDef`/`Format`/params and skip-with-reason in
tolerant mode; (b) CI step validating every vendored descriptor against the pinned upstream
JSON schema (`specs/erc7730-v2.schema.json`). Effort M. Files: dbgen/src/erc7730.rs:188-314,
2060+, CI workflow.

**STATUS (2026-07-02): top-level field/format keys DONE** (c87dcb70) — `#[serde(flatten)]`
catch-all + per-format gate; `encryption`/`iteration` gated, `$id`/`interpolatedIntent`/`separator`
ignored (data-driven, 0 corpus false positives). An **adversarial-verify pass found + I fixed**
a def-body bypass (4ff2a120): an unmodeled key on a `$.display.definitions` body slipped the
gate through the `$ref` merge — now gated in `resolve_display_refs`. **REMAINING follow-ups:**
(i) params SUB-key gating (a `decimls` typo silently drops decimals — params is a raw `Value`,
needs per-format valid-key allowlists); (ii) the CI JSON-schema step (b).

**DATED CORRECTION (2026-07-18):** `interpolatedIntent` is no longer ignored.
PQ1 enrolls only the authenticated, one-terminal-scalar subset whose placeholder
resolves to an always-visible static unsigned `amount`/`tokenAmount` field and
whose trusted formatter can produce an exact signed-value witness. Other valid
interpolation shapes retain the independent static `intent` and emit no runtime
program; malformed or ambiguous shapes still fail closed. This correction does
not rewrite the 2026-07-02 historical status or close the remaining params
sub-key/schema-validation follow-ups above.

**PHASE-D CORRECTION (2026-07-18):** enrollment is evaluated independently for
each deployment. A non-native `tokenAmount` program additionally requires a
statically resolved `(chainId, token)` in the exact generated ERC-20 capability
set after all device wire-size/proof-depth/name/symbol checks; a runtime token
path cannot borrow another deployment's metadata. Of 78 reviewed candidate
deployment formats, six retain interpolation and 72 retain static intent only.
Every per-deployment IR is then reparsed by the device parser before the leaf is
accepted. The current production catalogue is 428 leaves / 340,215 bytes / root
`c785f90c…b054d4`.

### 1.4 The skip report is discarded; the review file lists no fields and no skips
`dbgen/src/main.rs:304` does `let (erc7730_res, _skips) = build_db_tolerant(…)` — in the
shipping path the only record of dropped/degraded descriptors is thrown away.
`erc7730.review.txt` (CI-drift-gated) lists leaf headers only — a curator reconciling it sees
neither dropped descriptors nor per-field formats/labels, so 1.1-class degradation is
invisible by construction.
**Fix:** append a `## skips (N, by category)` section (the categorizer already exists:
`skip_category`, xtask/src/main.rs:1417) and per-field `format/label/params` lines to the
committed review file; since review.txt is already inside the CI drift gate, skip/coverage
regressions become reviewable diffs for free. Effort S. Files: dbgen/src/erc7730.rs:689,4723,
dbgen/src/main.rs:304.

**DATED CORRECTION (2026-07-18):** the generated, drift-gated review artifact
now retains the complete tolerant-build skip ledger and an emitted-IR breakdown
for every format and field. Each format records its selector, decoded intent,
exact intent bytes, static-head width and nested-descent count; each field
records its ordinal, opcode, escaped label, exact compiled path bytes, exact raw
parameter TLVs and a canonical decode of every parameter meaning exposed by the
device parser. This closes the specific discarded-skip and opaque-field-review
defect above. It does not by itself prove source-to-IR faithfulness or registry
provenance; reviewers must still reconcile the generated diff against the
source descriptor, policy and upstream identity.

**PHASE-D SIGNING-PATH CORRECTION (2026-07-18):** contract and EIP-712
clear-signing no longer authorize confirmation from one published transcript
or a cached display witness. The handler renders a complete first pass, hashes
its exact state/count/relative indices and all 64 bytes of every page, poisons
and resets the volatile page buffer, applies the delay boundary, then performs
a fresh second render from authoritative signed inputs. It accepts only equal
independent receipts and proves the exact second-pass page range immediately
before confirmation. The contract and EIP-712 domains use distinct CFI states;
raw one-pass helpers are private to the checked dispatcher path. This is source
and host-test evidence pending the fresh V4 Phase-D cross-adjudication and
hardware resource/FI evidence; it is not production authority.

The two-pass source shape establishes one logical `Pages` display authority,
not one physical stack slot. Optimized Thumb disassembly shows that constructing
the caller-owned value currently materializes an additional `Pages`-sized
temporary before copying it into the working slot. The linked prologue/map and
available SRAM must therefore be reported directly. They do not replace the
still-open whole-call stack high-water, exception-headroom, `MSPLIM`, or
hardware-FI evidence.

---

## Tier 2 — Pipeline sustainability (the resync ceremony)

### 2.1 Curations were in-place edits to the vendored registry — hidden-field edits retired
`xtask vendor-registry` does `remove_dir_all` + re-copy (xtask/src/main.rs:1297-1318); the
old Tier-A curations hid Uniswap `sqrtPriceLimitX96` and Permit2 `nonce`. The 2026-07-10
adversarial pass removed that policy entirely: every hidden non-address operand is now
rejected, and the vendored formats are omitted instead of receiving semantic exceptions.
Any future curation overlay must make a field faithfully renderable (not hidden), bind the
patch to the exact upstream content hash, and pass the strict visibility/corpus gates.

**Phase-C provenance-overlay implementation (2026-07-18):** the 14 current
curations are now complete replacement files under
`secure/data/erc7730/curations/files/`, with a strict manifest binding the
pinned upstream repository/commit/tree, v2 schema, pristine and excluded-
fixture corpus receipts, curated corpus receipt, policy, selected compiler/tool
inputs, and every replacement's before/after length and SHA-256. The vendor
path verifies the relevant upstream Git working tree, applies only declared
replacements in staging, rejects additions/deletions/undeclared diffs, and
requires pristine-versus-curated known-call count, tuple-set hash, and Bloom
bytes to remain identical before install. The normal descriptor `--check` gate
also verifies the checked-in manifest/replacements/tool inputs/curated tree.
This mechanizes the first §2.1/§2.3 slice only; deterministic `diff-registry`,
signed-release-manifest binding, and ERC-8176 production provenance remain
separately gated work.

**Phase-C deterministic registry-diff implementation (2026-07-19):**
`xtask diff-registry` now verifies a manifest-pinned official base checkout and
an arbitrary clean official candidate checkout, snapshots both against the
same manifest-bound policy/compiler and exact production ERC-20 capability
input, and emits stable review-only JSON. It reports complete included and
excluded file deltas, leaves gained/lost/IR-changed, all six exact contract-call
transitions among `clear`, `refused_known` and `unregistered`, skip-category
deltas, and removed/modified/upstreamed curation preimages. The host build now
retains the sorted exact known-call tuple inventory used for the Bloom, so the
comparison never tries to invert or infer authority from Bloom membership.
Both inputs are re-verified after building to catch concurrent drift. The
command applies no curations, writes no registry or generated artifact, and
labels `unregistered` as catalogue absence rather than claiming a runtime blind
path. The recurring ceremony is recorded in the root-rotation owner document.
This closes only the deterministic `diff-registry` + runbook sub-slice; the
remaining non-authority §2.3 bookkeeping moved to the next bounded slice, while
signed-release-manifest binding and ERC-8176 production provenance remain
separately gated.

**Phase-C remaining §2.3 provenance gates (2026-07-19):** the drift-gated
`erc7730.review.txt` header now receives the upstream commit/tree and exact
curation-manifest SHA-256 automatically from the same verified manifest
snapshot used by generation. The generator's existing production-policy
refusal now runs before any catalogue write. A source audit also confirmed that
exact recorded-SHA re-vendoring, the filename-convention/omission tripwire, and
the dev-unattested production CI quarantine were already implemented; the
bullets below were stale, not additional missing mechanisms. This closes the
non-authority-changing §2.3 batch without changing catalogue bytes, signing
eligibility, release authority, or ERC-8176 status.

### 2.2 Duplicate-leaf precedence is alphabetical-filename (registry-squatting surface)
Dedup on `(chain, contract, primary_type_hash, ctx)` keeps the lexicographically-first source
path (dbgen/src/erc7730.rs:554-590); for contract ctx `primary_type_hash` is always 0. An
upstream PR adding `1inch/aaa-router.json` would silently swap which descriptor the device
trusts for a covered contract on the next resync — recorded only in the discarded skip list.
**Fix:** hard-error (or require a policy.toml precedence entry) when duplicate IRs are not
byte-identical; keep silent-drop only for byte-identical dups. Effort S.

### 2.3 Provenance + resync workflow gaps (batch of S items)
- Auto-stamp the upstream SHA: **implemented 2026-07-19.** Default production
  generation stamps manifest-derived commit/tree/manifest SHA-256 into the
  drift-gated review header; the README's managed receipt is the single
  machine-owned copy rather than hand-maintained prose.
- Re-vendor at the *recorded* SHA: **implemented by the strict overlay gate.**
  `vendor-registry` accepts only the official checkout whose commit/tree match
  the manifest, so renderer-only and upstream-movement diffs can remain
  separate commits. The runbook records the detached-worktree invocation.
- `xtask diff-registry`: **implemented in the bounded 2026-07-19 Phase-C
  slice** — A/B tolerant builds at two registry revisions report leaves
  gained/lost/IR-changed, exact clear/refused-known/unregistered transitions by
  category, and curated-file collisions. `unregistered` deliberately replaces
  the imprecise historical “blind” label because runtime policy may still
  refuse.
- A short `docs/` runbook for the resync ceremony: **implemented in
  `docs/erc7730-root-rotation-and-update-policy.md`**; the command runs before
  manifest replacement, followed by reviewed collision resolution, vendoring,
  overlays, dbgen, review diff and commit.
- `--policy production`: **hard-refused for the canonical catalogue until the
  ERC-8176 flip.** The CLI refusal occurs before any generator output is
  written. The library can verify a separately pinned offline snapshot and
  production policy, but no such canonical evidence/root rotation exists.
- Filename-convention tripwire: **implemented.** Every unselected JSON is
  conservatively parsed/include-resolved for omission protection, and concrete
  misnamed descriptors receive a drift-gated `UNSCANNED` skip receipt.
- Dev-mode production quarantine: **implemented.** Generated Rust fences, the
  `prod-erc7730-provenance-check` negative gate, fsbl regression tests, and CI
  require the exact `dev-unattested` refusal until verified provenance lands.

### 2.4 Whole-corpus render smoke (close the parse-vs-render parity gap)
CI round-trips every leaf through `ir.rs::parse` + Merkle verify, but **render** is tested
only on curated samples. The gap is real today: dbgen emits PermitBatch array anchors the
device deliberately declines, and nothing corpus-wide records which leaves are render-live
vs emit-only.
**Fix:** host harness that synthesizes minimal well-formed calldata/typed-data per leaf from
the format's type signature, drives the actual render dispatch, and asserts (a) no panic,
(b) an expected classification (renders/declines) recorded in a committed manifest — the
manifest diff becomes the render-coverage regression gate. Effort M-L.

### 2.5 Root-rotation ADR
The root ships compiled-in; the only update channel is a signed FW update — deliberate, but
documented only in *archived* handoffs, while observed churn is 4 root rotations in ~2 weeks.
Write a current ADR: post-ship resync cadence, companion↔firmware root compatibility policy,
and an evaluated-or-roadmapped lighter channel (e.g. a C10-signed descriptor-root artifact
through the existing fw-update trust chain — same single primitive, keeps invariant #5).
Effort S (ADR) / L (signed-root channel).

---

## Tier 3 — Coverage unlocks (fail-closed → clear-sign conversions)

### 3.0 Measured coverage baseline (upstream `784c87c`, full pipeline run 2026-07-02)

**1,243 formats** declared across 372 real upstream descriptors → **1,000 net renderable
today (80.4%)**; 241 fail (per-format isolation compile, first-error attribution — some
formats have 2+ blockers, so bucket sums slightly overstate independent unlocks). Split:
calldata 870/1,086 (80.1%), EIP-712 130/157 (82.8%). 45/51 projects have ≥1 renderable
format; zero-coverage projects: okx, lifi, dispatch, figment, kyberswap, opensea. Ranked
unlocks by formats gained:

1. **Completeness-lint curation overlay — 82 formats** (category: curation, not code).
   Upstream descriptors omit params that the H-3 / EIP-712 HIGH-1 completeness lints require
   rendered-or-`visible:"never"`; Ledger's tooling is laxer. Blocks paraswap 25, **safe 24
   (all six Safe eip712 `SafeTx` descriptors are 100% dead today**, plus execTransaction/
   setup/createProxy), quickswap 6, threshold 5, aave/lifi/uniswap 3 each. Mechanism exists
   but the former Permit2-nonce hidden-field precedent is retired: parameters must be
   faithfully rendered or the format stays omitted. Effort S/descriptor, M for the review
   across 82. A future overlay mechanism may improve rendering, never suppress operands.
2. **Array index/slice on rendered-value paths — ~53 formats, 49 of them 1inch** (`pools.[-1]`).
   **CORRECTED 2026-07-02 (design pass): this is NOT a clean unlock.** A rendered-value
   single-index (`arr.[-1]`) is the array-tail-hiding HIGH (see
   `docs/erc7730-dynamic-array-walker-design.md` §"v2 design", and v1 Deep-dive #1) — a
   value-slice resolver would REOPEN it, so it is correctly declined by the `is_token_path`
   guard. The safe unlocks are: (a) legs whose token identity is a `tokenPath: pools.[-1]`
   already compile once finding 1.1 ($ref) lands (the Tier-B extractor shipped) — free;
   (b) for the remaining addressName-value `pools.[-1]` volume, a min-return-gated
   per-descriptor **curation + hidden-route marker** (policy-driven, not a resolver), design-doc-first.
   Effort: 0 for (a); M + review for (b). Do NOT build a value-single-index resolver.
3. **Hidden-address `policy.toml` allowlist entries — 39 formats** (pure curation with
   required rationales; 14 entries exist today). safe 12, 1inch 11, aave 4 (WrappedTokenGatewayV3
   `pool` — also needs 3.4), uniswap 4. Effort S per entry.
4. **Array-of-tuple top-level calldata args — 26 formats** (the calldata analog of EIP-712
   v2 §11): okx 12, lifi 4, flare 4, morpho `multicall(bundle)` 2 (the only morpho gap).
   `parse_format_key` can't parse `(...)[] name` (error message is misleading — the tuple IS
   named). Effort L, design-doc-first. This is the one large engineering item for the
   aggregator/bundler tail.
5. **Whole-dynamic-array render — 21 formats**: (i) bare array path with no `.[]` → implicit
   render-all (S-M); (ii) `[]` over dynamic elements (`bytes[]`/`string[]`) → per-element
   FollowOffset (M; limited display value for bytes without nested-calldata render).
6. **EIP-712 v3 — ~13 formats**: array ops on elementary members (lens, flyingtulip) + depth-≥2
   witness structs — **all 4 UniswapX order descriptors** (already the named v2 follow-up).
   Effort L, design-doc-first.
7. **Land the in-flight v2 array-of-struct device render — 4 formats** (PermitBatch, rarible 2,
   safe 1): emission landed in `93fbec79` with device declining; the working tree already
   implements the array binding — finishing/review only.
8. Rule-1 "inert-only" exemptions (14 formats, deliberate policy, low fund-safety payoff) and
   micro-curations (flyingtulip enum-key `"True"` upstream bug; aave-lpv3 duplicate Linea
   deployment).

Items 1-3 are mostly curation-plus-one-medium-feature and take format coverage from 1,000 to
~1,170 of 1,243 (**~94%**). Also fix: `xtask scan-registry`'s `skip_category` regexes
mis-bucket completeness messages containing "hidden" as "attestation policy"/"visibility"
(xtask/src/main.rs:1417) — future scans self-report wrong.

### 3.x Spec-posture conversions (fail-closed → clear-sign)

The implementation is consistently *stricter* than the spec's fallback-display posture; each
divergence converts a partial clear-sign into a full blind-sign. Cheap conversions, in
leverage order:

- **3.1 `calldata` format** declines the whole tx (calldata_nested.rs:37-43) — 16 live pinned
  fields are dead formats. Spec sanctions a fallback: hash-of-embedded-calldata page +
  `calleePath` resolved via trusted names, keeping sibling fields clear. Effort M (fallback),
  L (true nested recursion — deliberately deferred per the blocker analysis; the native Safe
  path already covers the high-value cases).
- **3.2 `nftName`** rejects unconditionally (formatters.rs:417-435) — 12 live pinned fields.
  Spec mandates fallback to raw int token ID; collection-address page + "Token ID: N" needs
  no NFT DB and beats blind-sign. Effort M.
- **3.3 `enum` unknown value** declines the whole format (formatters.rs:1098-1099). Render
  `Mode: 7 (!unknown)` loud instead, or document as intentional. Effort S.
- **3.4 `tokenAmount.nativeCurrencyAddress`** dropped (13 upstream files: 1inch, ParaSwap,
  Aave WrappedTokenGatewayV3, Safe common) — native legs render as `Token (UNVERIFIED)
  0xeeee…` + raw integer instead of `0.19 ETH`. New TLV (address list) + sentinel compare +
  route through the `amount` path. Effort M.
- **3.5 `amount` hardcodes ETH/18** on every chain (formatters.rs:286-288) — Polygon/BNB
  deployments display native value as "ETH". Add a chain→native-ticker table (device already
  has `chain_name()`); also feeds 3.4. Effort S.

  **Resolved 2026-07-17 (3.4/3.5):** tag `0x42` now authenticates either the
  byte-identical 20-byte scalar or a bounded two-address list in descriptor
  order. Dbgen and the device reject empty, malformed, duplicate, or larger
  lists. Runtime membership is exact; known chains use the firmware-pinned
  native ticker and 18-decimal scale, unknown chains remain raw, and a list
  miss follows the verified-ERC-20/unverified-address path. The real 1inch V4
  ETH `clipperSwap`/`clipperSwapTo` formats now form one additional production
  leaf and exercise both `0xEeee…` and zero sentinels.

  **Phase-D correction 2026-07-18:** known 18-decimal native values now refuse
  unless the complete signed 256-bit word is exactly representable at the
  shared six-fractional-digit display precision. Values such as one wei or one
  ETH plus one wei cannot share a trusted page/proof with one ETH. The renderer
  and interpolation witness use the same bounded decimal exactness predicate.
- **3.6 tokenAmount `message` param** compiled + parsed but never rendered (hardcoded
  "unlimited"); threshold check only in the metadata-bound branch (see also 4.5). Effort S.
- **3.7 `metadata.token` fallback** ignored (`_token`, erc7730.rs:270-271) — 2 upstream files
  (tether, walletconnect). Emit as bound-to-`@.to` token params. Effort S.
- **3.8 `senderAddress` / `@.from`** dropped at compile; `@.from` unresolvable on-device
  (F4 reject, formatters.rs:163-176) — 5 upstream files. Needs the wallet address threaded
  into the display layer. Effort M.
- **3.9 EIP-712 domain over-pinning:** `resolve_per_deployment` (erc7730.rs:1029-1037) always
  injects `chainId`+`verifyingContract` into the computed separator even when the protocol's
  `EIP712Domain` omits them → such protocols can never clear-sign (silent dead leaves). Respect
  the declared domain field set; deployments still bind chain/contract in the IR header.
  Effort S. (Binding the full `encodeType` hash instead of spec's schema check is *stronger*
  than spec — document, don't change.)
- **3.10 Object-form v2 `visible` rules** fail serde → whole descriptor silently skipped
  (0 upstream today, first user vanishes); `MustMatch` always rejects / `IfNotIn` always
  renders because the value-list sub-TLV was never wire-encoded (visibility.rs:92-111).
  Land the value list or document as reserved. Effort M.
- **3.11 Remaining resolver levers:** see the measured ranking in 3.0 (supersedes the
  earlier histogram in `erc7730-coverage-blocker-analysis-2026-07.md` for current state).
  **Current policy (2026-07-10):** exact all-static framing or one sole C1 dynamic
  string/bytes/primitive-array/tokenPath whole tail; C2 dynamic-tuple descent and C3
  multiple-tail layouts are intentionally excluded. The **attestation flip** (dev-mode
  `allow_unattested` → enforced
  ERC-8176) remains the orthogonal lever. Its bounded authenticated offline
  verifier code half exists, but the EAS ecosystem still has ~0 usable real
  attestations and no approved canonical production snapshot/root rotation
  (`docs/erc8176-attestation-status.md`).

Documented-deviation candidates (write down, don't change): date blockheight shows
`block #N` not approximate time (no block-time oracle); duration `Xd Yh Zm` vs spec HH:MM:ss;
string raw restricted to printable ASCII (anti-homoglyph); selector-form/types-only format
keys unsupported (names are load-bearing since `abi` is ignored).

---

## Tier 4 — Rendering UX fidelity (what the user actually sees)

Display model: 16 cols × 4 rows, `MAX_PAGES = 31`. Every UserOp confirmation
includes the mandatory outer-signer and exact target-contract pages; a nonzero
EntryPoint nonce lane adds one exact high-192-bit lane page. Golden fixtures,
not historical page-count prose, are authoritative for individual flows.
Quick-win bundle (all S unless noted):

- **4.1 Intent banner truncates at 10 chars, no marker** (intent.rs:61-67): **330 of 561**
  unique registry intents exceed 10 chars — "Withdraw Collateral from Morpho Market" →
  `Sign: Withdraw C`. Drop the `Sign: ` prefix, wrap intent across rows 0-1.
- **4.2 Field labels clip at 16 chars, no marker** (formatters.rs:1326-1339): **378 of 1914**
  registry labels overflow — "Minimum to Receive" → `Minimum to Recei`. Wrap when the value
  fits 2 rows; visible `~` marker otherwise; optionally dbgen short-label overrides. Effort M
  (marker-only: S).
- **4.3 Amounts never use the single-row form** — pinned test shows `"0" / ".5 ETH"` split
  across rows. Native paths already try `try_write_amount_single_row` first
  (primitives.rs:425-439); do the same in the 3 ERC-7730 amount formatters (formatters.rs:289,
  352, 1138).
- **4.4 Dust amounts render `!AMOUNT OVERFLOW`** — the F14#3 zero-collapse guard fires on
  1-wei-class values and shows an alarming banner with *no value*. Retry at full precision
  (fits two rows) and reserve the banner for genuinely-too-wide. Preserves the never-show-0
  property. (primitives.rs:169-247)
- **4.5 "unlimited" only recognized for Merkle-bound tokens** (formatters.rs:336-377) — an
  infinite approve of an unknown token renders as `!AMOUNT OVERFLOW` instead of "unlimited",
  exactly when trust is lowest. Hoist the threshold check above the bound-match; also fix the
  silent ticker clip in `write_unlimited_row` and unify wording/casing with erc20_known.rs.
- **4.6 `raw` small ints as decimal** (1 page) when high 24 bytes are zero, keep 2-page hex
  otherwise (formatters.rs:227-268) — kills the wall-of-zeros pages and buys page budget.
  **DEFERRED (2026-07-02):** attempted, reverted. `raw` is the opaque catch-all format;
  "raw == hex" is an invariant other code + tests rely on (the Morpho/static-tuple render
  tests probe a raw member's *hex*), and a decimal could read as a meaningful count for a genuinely
  opaque word. Revisit only with a descriptor-level signal that the word is numeric — a
  readability nicety, not worth breaking the invariant + churning tests I don't own.
- **4.7 EIP-55 checksum casing** in `write_addr_full` (primitives.rs:265-294) — every wallet
  UI the user compares against is checksummed; one keccak per address page, shared across
  erc20/Safe/CoW paths too.
- **4.8 Chain-name table covers 9 chains; registry ships ~15+** (Avalanche 38 descriptors,
  Sonic 34, Linea 27, Scroll 10, …) — all render `(UNVERIFIED)`, diluting that word's alarm
  value. Extend table; change fallback to `(unknown chain)` so UNVERIFIED keeps one meaning.
- **4.9 Envelope compression — SUPERSEDED by WYSIWYS hardening (2026-07-10).** UserOp-backed
  ERC-7730 renders now show exact fee operands, all three gas limits independently, and the
  full 256-bit nonce. They deliberately spend extra pages rather than merge distinct signed
  fields into a lossy aggregate. Revisit layout only with an injective render proof.
- **4.10 PageBudget overflow — CLOSED (2026-07-10):** every render failure for a
  firmware-known/verified call, including `RenderErr::PageBudget`, is fatal and refuses the
  signature; it cannot fall through to typed or blind signing. The dormant compact-mode idea
  must not skip `Optional` signed operands: under the strict material-field policy every
  accepted operand is display-relevant, so compact rendering needs a new authenticated
  materiality model before it can be enabled.
- **4.11 Two visual languages for the same ERC-20 transfer** (ERC-7730 rung: trimmed `100`
  vs erc20_known: fixed `100.000000 USDT`, different page order/headers) — pick one amount
  policy (trimming is injective post-round; M-6 only forbade progressive width shrink).
  Effort S-M.
- **4.12 Reject strings are developer tags shown to users** (`7730 nested blob trailing` on
  the status banner, several > 16 cols) — map to one user string, keep tags in debug log;
  add a test asserting all Reject literals fit the display.
- **4.13 Verified-name sentinel `+ ` is too subtle** and the row-3 `0x112233.aabbcc`
  single-dot ellipsis reads as a typo — use `..`, document the sentinel.
- **4.14 (Strategic, L)** the 16×4 grid is the root constraint — a 2×-scale font (~25×8)
  would fit full intents/labels and halve page counts; UI-driver rework + FI/side-channel
  review, flag for a design pass.

---

## Tier 5 — Architecture / maintainability

- **5.1 Keystone refactor: extract `Pages` + formatters into a host-compilable crate.** The
  formatter layer is pure (bytes → 4×16 ASCII) but trapped under `#[cfg(not(test))]`
  (secure/src/tx/mod.rs:22), forcing (a) the hand-mirrored `display_under_test` scaffold with
  source-grep pin tests, (b) a main.rs ui stub, (c) `fuzz_targets/erc7730_render_dispatch.rs`
  which *documents itself* as unable to reach the dispatch. Moving `Pages`/primitives/
  formatters into `pqsigner-erc7730` (or a render crate) deletes the mirror, makes every
  formatter fuzzable end-to-end, and gives the companion exact-page preview parity. Effort
  M-L; highest structural leverage.
- **5.2 Formatter-mechanics dedup** — the resolve-word prologue (~10×), the
  amount-page + AmountFit footer block (6×), three hand-rolled decimal writers, and
  `render_array_element` re-implementing scalar bodies are exactly how 1.2 survived a fix to
  its sibling. Dedup the mechanics (`resolve_word`, `write_amount_page`, …), keep per-op
  semantics. Effort S-M; do during 5.1.
- **5.3 Wire vocabulary defined three times** — dbgen redefines `PATHOP_*/FMT_*/PARAM_*/VIS_*`
  as local consts "mirrored by comment discipline" (erc7730.rs:80-185) despite already
  depending on the crate; `ir::PathOp` doc comments teach the **legacy walker widths**
  (4-byte ArrayIdx — the live encoding is u16, resolve.rs); the roundtrip validator hardcodes
  the same wrong widths a third time (erc7730_roundtrip.rs:403-406). Import discriminants /
  static-assert pairs; rewrite the PathOp doc table for both encodings. Effort S — this is
  the confirm-vs-execute desync class seeded by documentation.
- **5.4 Retire or feature-gate the legacy walker + abi.rs** (~800 lines of dead, misleading,
  audited surface; wasted fuzz budget; a public `resolve()` stub that always errors). Carve
  out `path_bytes` (still imported by render/nested.rs:41 and re-implemented inline twice in
  formatters.rs) into `render::resolve` first. Also remove the `resolve_field_index` 16-bit
  hash fallback (dbgen erc7730.rs:4229-4233) — unknown names should fail, not become
  never-resolving hash slots. Effort S-M.
- **5.5 dbgen decomposition + independent oracle** — split the 6.5k-line file along its
  existing section banners (`model/db/compile/paths/types/lints/jcs/includes/policy`); add a
  host-only differential test comparing `static_head_words`/selector/`eip712_encode_type`
  against `alloy-json-abi`/`alloy-dyn-abi` for every format key in the corpus. The hand-rolled
  type engine computes the head-slot arithmetic the slot-confusion defense rests on; today
  it's tested but not cross-checked. Effort M + S.
- **5.6 Institutionalize "no formatter ships without a host render test"** — generalize the
  excellent array-specific guard (`all_compiled_registry_array_leaves_render`) to every
  `(format_op, param-shape)` in the prod root, cross-checked against a fixture manifest; a
  FormatOp-enum-driven checklist test; a written "adding a formatter / bumping SCHEMA_VER"
  checklist (touch-points: ir::FormatOp, dispatch, dbgen parse/compile, render fixture, root
  rotation, companion blob). Effort S-M.
- **5.7 Small batch:** stale wire-format docs (ir.rs:16 says `schema_ver (0x02)` vs
  SCHEMA_VER=0x03; ir.rs:40 says 16 formats vs MAX_FORMATS=32; surviving "OLED" references);
  test-helper triplication (`synth_bundle`/`extract_proof`/`find_leaf`) → export a dbgen
  test-support module; `e2e-erc7730-hw` Makefile stub stays a visible fail-loud item.

---

## What's already strong (don't churn)

- Fail-loud WYSIWYS discipline on-device: every magnitude-hiding path from the 2026-06 audits
  is closed and pinned by named regression tests; round-half-up display; full 40-hex raw
  addresses (with Merkle-verified named identities separately collision-gated); loud
  unbound-token pages; the no-visible-fields belt.
- The verified/known-call refusal decision lives in exactly one place with a documented
  contract on `RenderErr`; renderer failure cannot downgrade to a typed or blind-sign rung.
- Committed vendored corpus + faithfulness proof + CI drift gate = genuine root
  reproducibility from the repo alone; whole-registry *parse* round-trip in CI is real.
- Strict `schema_ver` equality + co-shipped root makes lockstep versioning deliberate and
  safe; the v2→v3 bump note in ir.rs is exemplary.
- Curation is already data-driven (policy.toml allowlist with required rationales; no
  per-protocol Rust in dbgen) — the gap is overlay mechanics (2.1), not design.
- The `secure/src/tx/erc7730_render/` mirror-drift concern in CLAUDE.md is **already
  resolved** — it is a 17-line re-export shim now.

## Suggested sequencing

1. **Now:** 1.1 ($ref, incl. lint fix) · 1.2 (Raw array arm) · 1.4 (skip report) · 2.2 (dedup
   hard-error) — all small-to-medium, all correcting what the pinned root already claims.
2. **Next resync cycle:** 1.3 (unknown-key tripwire + schema CI) · 2.1 (curation overlay) ·
   2.3 batch (SHA stamp, diff-registry, runbook) · 2.4 (render-smoke manifest).
3. **Coverage sprint:** 3.0 items 1+3+7 (completeness curation, policy entries, finish v2
   array render — curation-heavy, → ~94% format coverage) and 3.1-3.5 (calldata/nftName/enum
   fallbacks, native-currency, ticker table); then 3.0 #2 (value-path slices) and #4
   (calldata array-of-tuple) as design-doc-first features.
4. **UX sprint:** the 4.x quick-win bundle (intent wrap, label wrap, single-row amounts,
   dust, unlimited, decimal raw, EIP-55, chain table, envelope merge, compact retry).
5. **Structural:** 5.1 render-crate extraction (with 5.2 dedup), 5.3 wire-vocab
   single-sourcing, 5.4 walker retirement, 5.5 dbgen split + differential oracle.

---

## Follow-up status (2026-07-04)

Post-5.1-refactor pass over the "tractable remaining" set:

- **3.2 nftName — DONE for the raw fallback.** `NftName = 0x04` now renders the
  exact token ID as decimal when it fits and otherwise as the full raw word;
  the original finding above is retained as dated review input.
- **3.2 NFT collection identity — DONE (2026-07-17 bounded follow-up).**
  Dedicated IR tags bind exactly one literal collection or static-address path.
  The device always shows the exact token ID and complete collection address;
  a friendly name requires matching authenticated descriptor identity or exact
  chain+address metadata, never a chain-zero wildcard. The first container-path
  slice accepts only frozen `@.to`, independently of ABI argument names. Seven
  real deployments / 12 formats now exercise this path. This closes the
  deferred §12.4/PQ1 NFT identity item without broadening blind-sign policy.
- **3.6 message param — DONE.** `render_token_amount`'s unlimited path uses the
  descriptor's `message` param (validated printable) instead of hardcoded
  "unlimited"; render test on a synthetic `message="Max"` descriptor.
- **5.4 legacy walker — DONE (retired).** `walker.rs` (588 lines) deleted; its
  one live export `path_bytes` moved to `Erc7730Ir::path_bytes`; the
  `erc7730_walker` fuzz target + Makefile/Cargo.toml entries removed. `abi.rs`
  KEPT — contrary to the review's premise it is LIVE (`AbiValue` used by
  visibility/array/resolve/formatters).
- **3.7 metadata.token — DEFERRED.** Wiring `metadata.token.decimals` as a
  binding source touches the M-4 "verified decimals" security boundary (only the
  curated Merkle ERC-20 DB is trusted for scaling today) and rotates the root.
  Attested-safe in principle but wants design-first/adversarial review, not a
  rushed landing during active root-churn. (Broader coverage than the review's
  "2 files": ethena/midas/ondo/aave/… declare it; USDT etc. already Merkle-covered.)
- **5.5 dbgen split + alloy oracle — DEFERRED.** The split (7,361-line file →
  modules) is conflict-guaranteed against the active swarm. The alloy
  differential oracle needs a heavy new dependency (`alloy-json-abi`/`-dyn-abi`,
  not in the workspace) + a Cargo.lock change — a deliberate dependency decision,
  not an end-of-session add. Existing coverage (whole-registry roundtrip + render
  tests + Kani) already exercises the type engine; the oracle would strengthen it.
- **2.4 render-smoke manifest — DEFERRED.** Now feasible post-5.1 (render is
  host-crate), but a proper harness needs cross-crate calldata synthesis (dbgen
  holds the format signatures; pqsigner-erc7730 renders) to record the
  per-leaf renders/declines classification — a real M-L build. The panic-freedom
  half is already covered by the swarm's `erc7730_render_dispatch` fuzz target.

---

> **Adverse architecture-review result (frozen candidate below).** The exact
> candidate below was reviewed at HEAD `9647b793…` with tracked-diff SHA-256
> `b8e27074…`. Accepted A/B first passes (`4b34ae5f…`, `bcb8a52e…`) and
> symmetric cross passes (`d11bf34…`, `8f231060…`), followed by the two bounded
> responses (`d6617979…`, `ff7eb9ea…`), produced **NO-GO**. The complete matrix
> is SHA-256 `214763b8…` and is filed with the canonical findings. This section
> remains unchanged as historical reviewed input; it is not implementation
> authority. The material v2 redline after it supersedes its candidate wording
> and requires fresh mutually withheld review.

## PQ1 productization plan freeze (2026-07-16)

**Stage:** Phase B candidate selection. This packet records the user's new
known-call blind-review requirement and the Ambire/registry comparison. It does
not authorize a signing-behavior change. The selected escape-hatch architecture
and the gas-page FI change must receive the workflow's exact favorable dual
architecture review, symmetric cross-adjudication, and a recorded owner stage
decision before production-shared implementation.

### 1. Objective and observable outcome

PQ1 keeps clear signing as the default and retains every existing production
quarantine, while gaining: (a) mechanically current catalogue documentation;
(b) exactly one exact UserOp gas-triple page with an independent handler proof;
(c) test/provenance foundations that make registry updates reviewable; and,
only after the gates above, (d) a transaction-local, device-selected way to
review and accept a known call as unmistakable blind signing when clear signing
cannot complete. No host message, cached setting, failed descriptor text or
heuristic may grant that permission.

### 2. Baseline identity and preserved work

- Repository `/home/nicola/repos/PQSigner_OS`; branch
  `fix/fv-review-2026-07-15`; HEAD
  `9647b79374d5e2e10445254492308101b8be708b`.
- Pre-plan tracked-diff receipt: SHA-256
  `8ae9921ec0e4aec00f97aeafcb3925d19ff9482d8330fe8ceaa746233c7fe65f`.
  It contains unrelated, user-owned formal-verification edits in the root and
  contracts Makefiles/config/check scripts. The exact starting status also had
  four untracked, user-owned FV inputs:
  `contracts/verification/easycrypt/axiom_pins.txt`,
  `contracts/verification/extracted/Extracted/AxiomCheckNegativeControl.lean`,
  `contracts/verification/extracted/axiom_closure_manifest.txt`, and
  `contracts/verification/scripts/ec_axioms.py`. This campaign must not edit,
  stage or clean them.
- Clean comparison inputs (reference-only):
  `/home/nicola/repos/ambire-common` at
  `348591fb1c1b1f05b71f06cd509cc5be143309e4`; and
  `/home/nicola/repos/clear-signing-erc7730-registry` at
  `784c87c925e8438e7b4736b2af85a501f8d2a265`.
- Generated catalogue receipts at freeze: production blob SHA-256
  `d5ed95960a3c84dc65b534dbe1dfd8d6e6b1e766605bdd45a8f332b26f995099`,
  334,827 bytes, 420 leaves, root `048fd2f1…6ab142`; E2E blob SHA-256
  `5d6ee030da3bb5d1c65192badeb5378aab44d8cd60303b5836e53a52c90ad486`,
  3,917 bytes, 8 leaves, root `cbd0b771…0238e9`.

### 3. Sources-of-truth preflight and conflict

The following files were read in full before selection. Digests bind the
pre-plan versions; later review receipts must bind the post-plan target again.

| Input | Pre-plan SHA-256 | Authority used here |
|---|---|---|
| `CLAUDE.md` | `0289d493…3b3ae5` | Product/security invariants and frozen interfaces |
| `docs/STATUS.md` | `3a8c2ac7…a36c1` | Current evidence and ship frontier/router |
| `docs/planning-and-review-workflow.md` | `64c7e849…d86a` | Plan, exact dual review and convergence owner |
| `docs/companion/companion-erc7730-implementation-guide.md` | `21f3d072…e9f83` | Normative companion and known-call behavior |
| `docs/erc7730-root-rotation-and-update-policy.md` | `3150ce10…73864` | Root/corpus update decision owner |
| `docs/erc8176-attestation-status.md` | `a6ae68f9…d9c97` | Provenance ecosystem status |
| `docs/security/adversarial-review/findings/clear-signing-2026-07-10.md` | `08576785…5d99` | Last canonical clear-signing findings/evidence |
| `docs/work-todo.md` | `134f38f0…5f56a` | Reversible backlog and completion records |

Applicable playbooks are additive: clear signing
`da91244a…c438`, hostile USB/companion `4244da86…00e9`, trusted UI
`c906f444…0144`, SCA/FI `4d5be4f5…3b6e`, lifecycle/persistent state
`2c607980…18d74`, secure runtime/resources `67f04bd6…77068`, production
configuration/prodtest `27ae6f22…c08`, and build/release/provenance
`d87c8a83…1392`.

**Material conflict carried as an open stage decision:** the user explicitly
requested an option to accept blind signing after a warning. `CLAUDE.md`, the
current companion guide and clear-signing CS2 currently require a known shape,
missing proof or verified-render failure to hard-refuse and never downgrade.
The user direction is a legitimate new product candidate, but it does not
silently rewrite those owners. They may be amended only after favorable exact
architecture review and the subsequent owner/maintainer stage decision. Wire
v2 remains frozen; ERC-8176 and rollback remain independent ship blockers.

### 4. Invariants, threats and selected mechanisms

- **Signed bytes remain visibly bound.** Target, value, chain, selector and
  length, signer, gas triple and the complete ERC-8213 calldata digest must
  change or the device must refuse when a signed input changes. Failed
  descriptor text is never shown as authenticated meaning.
- **The hostile companion cannot select a weaker trust tier.** It may trigger
  the warning by withholding/corrupting a proof, but only an on-device first
  confirmation can enter forced-blind review, and only a second independent
  confirmation can release a signature.
- **Default and faults fail closed.** Typed outcome/state discriminants default
  to fatal. A skipped branch, stuck permission, corrupt page, missed warning,
  skipped confirmation or reused sentinel must not convert fatal/refusal to
  eligible/sign.
- **No hidden durable authority.** The permission is a stack-local event scoped
  to one handler call and dies on success, cancel, idle wipe or error. This
  avoids power-cut, migration, RMA, wear and stale-enable states.
- **Resource exhaustion does not remove facts.** Page/stack/FLASH/RAM overflow
  refuses. The warning page buffer is dropped before the raw transcript buffer
  is built; no two `Pages` buffers should coexist at the high-water point.

Concrete threats include malicious proof omission/misbinding, Bloom false
positives, retry/interleaving, warning habituation, typed/ERC-20 fallback after
a known failure, selector-name spoofing, truncated hashes, page-budget pressure,
FI bypass of either consent, and batch-summary ambiguity.

### 5. Scope, non-goals, assumptions and alternatives

The selected PQ1 candidate is **single-UserOp, per-request, on-device forced
blind review**. Only a known tuple with absent/bad/mis-bound ERC-7730 evidence,
or a verified descriptor that cannot render completely, may be considered
eligible. Safe `approveHash`, CoW `setPreSignature`, malformed Safe/MultiSend,
delegatecall, malformed envelope/pointer, mandatory-page overflow, batches and
all off-chain/EIP-712 paths remain fatal.

Alternatives:

- Keep unconditional refusal: remains the default and rollback behavior.
- Volatile session toggle: credible but deferred; it needs a new CMD/INS/CMSE/
  router surface and an FI-hardened secure-SRAM permission merely to save one
  warning interaction.
- Persistent setting: rejected for PQ1 because it creates unsafe-on lifecycle,
  torn-write/migration/default/wear/RMA semantics and collides with tightly
  owned flash pages.
- Companion flag/trailer or companion-only preference: rejected because the
  companion is fully hostile.
- Automatic fallback: rejected; clear-sign failure and blind review are two
  separately consented trust tiers.

Verified facts are the current routing, UI, artefact counts and absence of a
settings/status command. Product choices are the warning copy and exact
eligible classes. Human resistance to warning habituation and physical-panel
legibility remain hardware/UX evidence questions, not source-proven facts.

### 6. Authority, compatibility and resource envelope

This plan authorizes only reversible repository edits and non-destructive host/
QEMU checks. It authorizes no flashing, fault injection on hardware, release,
deployment, signing-key use, OTP/option-byte/SE lifecycle change or external
publication. Those need their own owner instruction and playbook evidence.

The chosen blind path changes no wire/schema or persistent state. `Pages`
remains bounded by `MAX_PAGES=31` (31×64 bytes of page storage); conservative
gas and fingerprint reservations remain. Any candidate that exceeds current
FLASH/update-slot, static SRAM/stack, latency, confirmation-page or frozen-wire
limits is rejected or separately re-planned. A future catalogue-status command
is a distinct protocol project, not smuggled into this slice.

### 7. Implementation slices

1. Correct both stale E2E catalogue statements and make the existing xtask
   drift check fail on root/count/size mismatch.
2. After architecture approval, make handler gas enforcement idempotent while
   independently proving either the existing exact canonical page or the
   deterministic inserted page; close the F10 page-budget evidence.
3. Introduce an explicit `BlindEligible(reason)` versus `Fatal` outcome with a
   fatal default and prove all non-eligible paths remain fatal.
4. Add the first warning confirmation, then a separate forced-blind renderer
   that ignores failed semantic metadata, followed by the existing final
   confirmation; keep the permit local to that control flow.
5. Run the full software/FI/resource campaign and physical trusted-UI campaign
   before considering batch/off-chain expansion.
6. Independently sequence the test-only upstream fixture/negative corpus,
   provenance overlays/receipts, status design, bounded native-currency list,
   NFT collection identity and constrained intent. Nested calldata and
   multi-tail ABI remain design-first.

### 8. Validation matrix

| Requirement / cut | Required evidence |
|---|---|
| Guide matches generated artefacts | xtask positive check plus stale-root, stale-count and stale-size negative tests |
| Exactly one exact gas page | existing-page, near-match, full-buffer, permutation and single/batch regressions; F10 E2E page-budget case |
| Fatal never becomes eligible | dispatcher table tests for every proof/render/fatal class; fatal-default mutation control |
| Host cannot auto-downgrade | stripped, malformed, wrong-chain/target proofs reach warning only; no signature without both confirms |
| Both consents are mandatory | cancel/idle at warning; confirm warning then cancel final; sentinel-skip/stuck-at optimized-ELF sweeps |
| Raw transcript binds signature | independent byte-flips over target/value/calldata/chain/gas/signer change a full page/digest or refuse |
| No reused permission | retry, interleaving, error, idle wipe, lock and return tests; permission is not stored |
| Resource and UI fit | Thumb release link; physical FLASH span; static SRAM and worst-stack receipt; MAX_PAGES boundaries; QEMU and golden grids |
| Shipping panel behaves | production-like NV3007 frame/button capture, clipping/stale-row/scroll-to-end checks |
| Registry updates are honest | upstream fixture transcript/waiver lane, generated negatives, deterministic overlay/diff and digest receipts |

Host tests and source FI structure do not replace physical UI/FI evidence.
Conversely, bench evidence does not replace parser, byte-binding or drift tests.

### 9. Review, convergence, preservation and rollback

Freeze the post-plan tree/diff, ignored/untracked inventory, prompt and input
digests before review. Run the exact Partner A (Claude Code Opus 4.8, 1M,
`ultracode`, `xhigh`) and Partner B (literal `gpt-5.6-sol`, effort `ultra`)
architecture legs with the required pre/post runtime receipts, neutral mutual
disclosure, immutable target and every applicable playbook Part-C attack list.
The clear-signing scope also requires at least three independent discovery
reviewers; discovery never substitutes for the exact pair. Freeze both first
reports before disclosure, cross-adjudicate symmetrically, preserve every
unresolved blocker, then record the owner stage decision. Repeat the protocol
on implementation before any merge/production recommendation.

Each slice must be independently revertible. Do not modify, stage or overwrite
the preserved FV work. A failed blind-path experiment is removed by reverting
only its isolated files; the current hard-refusal routing remains the rollback
state. Bank reversible residuals in `docs/work-todo.md`; hardware/production
residuals stay with their existing owners. No completion row or shipment claim
is written until its named executable evidence actually ran on the frozen
target.

---

## PQ1 architecture review outcome — frozen candidate

The exact review completed with **NO-GO**:

- accepted Partner A first pass:
  `4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c`;
- accepted Partner B first pass:
  `bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f`;
- Partner A cross:
  `d11bf34e8b6ece6eac442ef26674ea7604c816bbc8dd50804539327f32186e70`;
- Partner B cross:
  `8f2310602fbd36f09994ed1de794c332f0bf1ea85dbd98f6dc1a0f00c6a2e193`;
- one-turn bounded responses:
  `d6617979ec0c877e7501c8921beb37041c03db5aef3f53732f96ab32f3311aa7`
  and
  `ff7eb9eab04c8090329349023da7f786e99b9dc172a171a7db3b9d90d9e746e1`;
- complete 27-row matrix:
  `214763b83d44fbd2d6c278edbfef625076a3a99a0d3aa326b28de012e09c6415`.

The [canonical findings](security/adversarial-review/findings/clear-signing-pq1-forced-blind-architecture-2026-07-16.md)
and [cross matrix](security/adversarial-review/findings/clear-signing-pq1-forced-blind-architecture-2026-07-16-cross-matrix.md)
are the durable review record. The matrix preserves three unresolved items:
the prompt-abuse policy, Partner A's incomplete independent reproduction of the
handler-gas differential gap, and the stage-impact disagreement for the
two-receipt mechanism. None may be converted into approval by reviewer count.

## PQ1 forced-blind material redline candidate v2 — ARCHITECTURE GO / PHASE C AUTHORIZED

**Status:** selected Phase-C architecture. The owner selected the
remaining prompt-abuse semantics on 2026-07-22, including the fail-closed host
denial-of-service residual. Review of commit `76c01227` returned GPT-5.6 SOL
**FIX** and Claude Opus 4.8 **GO**; Kimi K3 hit the 15-minute hard limit without
a report, which remains an honest gap rather than a retry. The coordinator
reproduced GPT's two concrete hardware-boundary traces: the current
non-secure-addressable IWDG can be reloaded without tick progress, and a
non-secure DMA bus master can observe response writes before post-write scrub.
This correction requires Secure-only IWDG ownership, defines the reserved
pre-write check as the irreversible release point, limits eligibility to the
refused-known set `F = K \ C`, and closes the PIN-arm, complete-grid,
combined-cap, and rate-preflight ambiguities from the same wave. The exact
corrected identity `6bda0faef0a75d312eefb4999adc6a2c536a0004` / tree
`2135ad340a81c32117e0f6a4d6e027292f30f622` then received **GO with no
blockers from GPT-5.6 SOL, Claude Opus 4.8, and Kimi K3** in one simultaneous
bounded wave. Their remaining items are implementation/release evidence gaps,
not unresolved architecture questions.

The owner/maintainer stage decision recorded on 2026-07-22 authorizes the
bounded Phase-C implementation campaign defined here: (C1) P73K/catalogue
binding and exact runtime proof; (C2) PIN-only volatile attempt state,
tick/IWDG, deadline-aware UI, receipts, and deterministic capacity preflight;
and (C3) terminal handler/transcript/sign/release integration. The cumulative
envelope is the default-off `erc7730-forced-blind` feature, 32,528-byte
production `F` artifact, fixed 29-page transcript, no persistent grant or wire
schema migration, and preserved hard refusal whenever the feature or any gate
is absent. The next boundary is one combined Phase-D implementation review.
This decision authorizes implementation and testing only—not merge,
production, shipment, flashing, or irreversible action. Current hard refusal
remains the default and rollback until the implementation phase lands through
its own gates.

### 1. Product decision and conservative closures

The user's direction selects continued design of an on-device option: when
clear signing is unavailable in one narrowly defined case, the user may enter
an unmistakable forced-blind ceremony after a severe warning. It does not
authorize a companion-selected downgrade, persistent preference, reusable
session permission, current-owner rewrite, implementation start, merge, or
shipment.

This v2 candidate closes the reviewed ambiguities conservatively:

| Decision | PQ1 v2 selection |
|---|---|
| Trust tier | Separate forced blind; explicitly **not clear signing** |
| Default / rollback | Existing hard refusal |
| Host influence | The companion can omit the trailer and thereby request the ceremony only for an independently firmware-eligible refused-known tuple. It cannot make a tuple eligible, downgrade a clear-capable tuple, or authorize signing; there is no flag, preference, cached grant, or automatic fallback |
| Membership authority | Exact membership in the firmware-embedded refused-known set `F = K \ C`; the all-known Bloom is only a fail-closed consistency prefilter and never authorizes forced blind |
| Sole eligible metadata cause | Structurally clean absence of the complete ERC-7730 trailer |
| Invalid/bad/root-mismatched/chain- or target-misbound evidence | Fatal |
| Verified render failure | Every current `RenderErr`, including `NoFormat`, `Reject`, and `PageBudget`, is fatal |
| Paymaster | Any nonempty `paymasterAndData` is fatal |
| EntryPoint | Exact canonical v0.6 only; hostile wire value is checked then discarded |
| Lifecycle | Deployment/initCode and slot registration/rotation are fatal |
| Other commands | Batch (including one element), off-chain, EIP-712, and rotation/deployment are fatal |
| Semantic exclusions | Safe, CoW, MultiSend, delegatecall, `approveHash`, `setPreSignature`, contract creation, and malformed/short protected selectors are fatal |
| Friendly formatting | None in the first forced tier; raw representation is authoritative |
| Feature activation | New positive `erc7730-forced-blind` secure-firmware feature, default off; no dev/test alias or missing flag enables it. The production bundle omits it pending favorable architecture/implementation review and independent release gates |

The native ERC-20 shortcut mentioned by the old candidate is not part of
forced blind and is deferred to a separate design. It cannot broaden this
eligible set.

`secure/src/nsc/mod.rs` owns a compile-time feature fence. A production build
with `erc7730-forced-blind` is rejected unless the production IWDG, Secure IWDG
attribution, physical-button trusted UI, and fixed catalogue artifacts are all
selected. Turning the feature off restores today's refusal without changing
persistent state or wire interpretation.

### 2. Closed handler-owned state and routing

The cause must remain typed at the first site that can still distinguish it:

```text
RequestMode =
    SingleSteadyType2
  | FatalMode(reason)

MetadataEvidence =
    Absent
  | Verified(descriptor)
  | InvalidBundle
  | RootMismatch
  | BindingMismatch
  | FatalEvidenceFault(reason)

DispatchOutcome =
    Clear(pages)
  | GenericUnknown(pages)
  | ForcedCandidate(RefusedKnownDescriptorAbsent)
  | Fatal(reason)
```

These are closed, fatal-default representations: no wildcard security arm,
permissive `From`, `Default` to eligible, invalid-discriminant recovery, or
`Option`-collapse. Unknown future reasons are fatal. `ForcedCandidate` is
private, non-`Copy`, bound to the request digest and consumed once.

The handler mints `ForcedCandidate` only after two independent positive checks:

1. strict parsing proves the trailer is structurally cleanly absent (not
   malformed, truncated, nonempty, bad, root-mismatched, or misbound); and
2. independent FI-protected evaluation proves the exact
   `(chain, target, selector)` tuple is present in the canonical refused-known
   set `F` embedded in the signed secure image.

The generated catalogue defines three exact tuple sets:

- `K` is every registry-known call after the current authenticated inventory
  policy, including every clear-capable tuple;
- `C` is every tuple recovered by strict parsing of the final accepted
  `CTX_CONTRACT` IR in the exact `P730` catalogue; and
- `F = K \ C` is the refused-known set: registry-known tuples for which this
  firmware has no accepted clear-signing format.

`dbgen` emits `secure/data/erc7730-forced-eligible.set` (and the e2e
counterpart) as a canonical compact encoding of `F`. Its 16-byte big-endian
header is
`"P73K" || schema_u16(1) || header_len_u16(16) || group_count_u32 ||
tuple_count_u32`. Each strictly sorted, unique `(chain, target)` group is a
36-byte record
`chain_id_be64 || target_20 || selector_start_be32 || selector_count_be16 ||
reserved_be16(0)`, followed by one pool containing every four-byte selector,
strictly sorted and unique within its group. Group ranges must be contiguous,
non-overlapping, cover the pool exactly, and make the total artifact length
exactly `16 + 36 * group_count + 4 * tuple_count`; malformed arithmetic,
reserved fields, ordering, duplicates, gaps, trailing bytes, or out-of-range
indices are fatal.

No `P73S` schema change is required. The authenticated receipt already binds
the exact `P730` bytes/root/leaf count and the count and canonical hash of `K`.
Before generating `db_roots.rs`, `dbgen` and `xtask` independently and strictly
recover `C` from that final `P730`, decode `P73K` as `F`, prove
`C intersect F = empty`, canonically merge `C union F`, and require that union
to equal the in-memory `K` vector byte-for-byte and to reproduce the existing
`known_call_count` and `known_call_set_sha256` in `P73S`. They additionally
prove every union tuple is positive in the all-known Bloom and bind that
Bloom's size and digest to `P73S`. The signed secure image authenticates the
co-embedded `P73K` and `P73S`; the release proof prevents substitution,
overlap, omission, or a mismatched prod/e2e pair.

The current production shapes are `K = 4,580 tuples / 777 groups / 46,308
bytes`, `C = 1,366 / 346 / 17,936 bytes`, and `F = 3,214 / 546 / 32,528 bytes`
under this compact encoding. Only the final `F` artifact is linked for forced
eligibility. The final linked QEMU and U585 images must still measure the actual
delta and remain inside their respective FLASH envelopes.

At runtime the device strictly validates the complete `P73K` magic, schema,
header length, exact total length, range arithmetic, contiguity, coverage,
ordering, uniqueness, reserved fields, and absence of gaps/trailing bytes
before lookup. A non-inlined parser/prover publishes its own fail-initialized
verdict and CFI sentinel. The positive proof performs two independently
initialized complete parse-and-lookup passes, requiring agreement, then uses
one bounded binary search over groups and one over the selected selector
slice. The all-known Bloom must independently be positive. The positive path
uses a new `prove_forced_eligible_contract_call` primitive with its own CFI
constants and fail-preinitialized caller verdict. Reusing, negating, or
interpreting failure from `prove_unknown_contract_call` is fatal.

Failure of either check, disagreement between redundant checks, or failure to
produce the expected positive sentinel is fatal. Eligibility is never inferred
from `prove_unknown != OK`, missing verification, skipped binding, renderer
failure, or a generic `None`.

The direct single handler consumes the candidate immediately. It must not
return to the ordinary ERC-20, typed-call, selector-name, Safe/CoW, or generic
blind ladder. A tuple in `C` whose descriptor was omitted is absent from `F`
but positive in the all-known Bloom, so it hard-refuses: the companion cannot
downgrade a clear-capable call. A genuinely unknown/Bloom-negative call
continues through today's ordinary routing and gains no forced option.
`F`-negative/Bloom-positive calls, including Bloom collisions, and every
lookup/artifact disagreement retain hard refusal. Any present verified
descriptor that later fails to render is fatal and never falls through to `F`.
Catalogue drift treats every `C -> F` movement as an authority expansion that
must be reported and owner-gated.

### 3. Exhaustive fatal preflight

Before any warning, the handler completes and FI-proves every deterministic
check, including:

- fixed header, pointers, lengths, version, cursor, padding and trailing bytes;
- direct target, selector-width calldata, and non-creation semantics;
- `include_init_code == false`, `register_slot == false`, and exactly one
  steady-state Type-2 output artifact, using the FI-re-read flags;
- single command only: no batch, off-chain, EIP-712, lifecycle, or other
  signing mode;
- exact `ENTRY_POINT_V06` equality;
- no Safe/CoW/MultiSend/delegatecall/protected-selector claim, including
  selector-only and short malformed `execTransaction`;
- empty `paymasterAndData`;
- clean absence plus the affirmative exact forced-eligible receipt;
- double-read page-123 counters, an FI-protected read-only storage-capacity
  receipt, exact `newOffchainCount`, reconstructed steady-state Type-2
  calldata, the complete transcript, numeric widths and final digest;
- the existing independently repeated combined few-time-key gate
  `userop_cap_ok(max(local_offchain, last_userop), userop_sigs)`, with every
  input frozen for the final recheck;
- `sign_rate::signs_this_session() < sign_rate::MAX_SIGNS_PER_SESSION`
  (`250`), with the observed count frozen for an independent pre-sign recheck,
  and completion of the current minimum-sign-interval wait before the attempt
  is charged;
- exactly-one handler-owned canonical gas page and complete two-page ERC-8213
  digest;
- stack/page/resource preflight and all CFI stage initialization.

Any failure returns the existing refusal/error path without showing the severe
warning. This prevents a hostile companion from training the user on a warning
that predictably ends in a later resource or routing refusal.

No flash repair, counter promotion, or other persistent write occurs during
preflight. The handler freezes those counter values and re-reads them after the
second consent; any disagreement is fatal. The new read-only page-123 capacity
API has hardware and mock implementations and returns a request-bound receipt
only after a cap-conforming full parse/projection proves the slot is admitted
under `offchain_state::MAX_DISTINCT_SLOTS = 128` and that either the current
blank extent or a safe compaction has room for the forced steady-state path's
at most two required journal appends. In particular it proves
`projected_live_qws + 2 <= OFFCHAIN_CAPACITY`; merely checking
`already_present || distinct_live < 128` is insufficient for inherited or
corrupt page shapes. The handler freezes and independently rechecks that
receipt and the rate-count receipt immediately before
`c10_sign_verified_with_progress` calls `sign_rate::pre_sign()`. Hardware write
failures remain fail closed, but a predictable cap or compaction-capacity miss
cannot occur after warning. A bounded `sign_rate` preflight helper performs the
existing minimum-interval wait and returns without charging the sign counter;
the later `pre_sign()` remains the sole counter charge and rechecks both the
frozen count and elapsed interval. Thus the severe warning is not followed by
a predictable rate wait or cap refusal. Any tick disagreement in either helper
is fatal and, in production, stops the now-Secure IWDG refresh.

A non-inlined preflight helper owns the 4,352-byte reconstructed
`ExecuteCallData`, returns only its digest and the fixed transcript inputs, and
ends before the 1,988-byte `Pages` value is built. After consent, a separate
reconstruction must reproduce the frozen digest.

The forced request digest is the SHA-256 of the fixed domain
`PQSigner/forced-blind/request/v1` followed by this exact concatenation:
`account_index_be32 || slot_index_be32 || owner_index_be64 || signer_20 ||
target_20 || chain_id_be64 || ENTRY_POINT_V06_20 || selector_4 ||
calldata_len_be32 || new_offchain_count_be64 || value_32 || nonce_32 ||
max_fee_32 || max_priority_fee_32 || call_gas_32 || verification_gas_32 ||
pre_verification_gas_32 || SHA256_EMPTY_initcode_32 ||
SHA256_EMPTY_paymaster_32 || erc8213_calldata_digest_32 ||
final_type2_digest_32`. Both receipts bind this exact digest. The handler
recomputes it independently before signing.

### 4. Fixed forced transcript and page budget

The transcript accepts one canonical raw `ForcedTranscriptInput` already used
to compute the final Type-2 signing digest. It performs no ABI, descriptor,
resolver, token, selector-name, or host-string parsing. Every fixed-size signed
field is displayed injectively. Variable-length calldata is bound by its exact
length plus the collision-resistant ERC-8213 digest rather than misdescribed as
a raw injective display. Each 32-byte word uses 64 lowercase hexadecimal
digits, split without truncation. The exact final order is:

| Final page(s) | Content and owner |
|---:|---|
| 0 | Persistent `! FORCED BLIND` / `UNVERIFIED CALL` banner |
| 1 | Account index, slot owner index, and full device-derived signer |
| 2 | Exact `newOffchainCount` encoded as all 16 lowercase hexadecimal digits |
| 3 | Full raw target |
| 4 | Exact chain ID as all 16 lowercase hexadecimal digits |
| 5 | One canonical exact gas-triple page, produced only by the handler |
| 6 | Full pinned EntryPoint v0.6 address |
| 7 | `Single Type-2`, `initCode = EMPTY`, raw selector, and exact calldata length |
| 8–9 | Full raw `value` word |
| 10–11 | Full raw nonce word; forced-flow replacement for the compact conditional nonce-lane page, independently handler-proven |
| 12–13 | Full raw `maxFeePerGas` word |
| 14–15 | Full raw `maxPriorityFeePerGas` word |
| 16–17 | Full raw `callGasLimit` word |
| 18–19 | Full raw `verificationGasLimit` word |
| 20–21 | Full raw `preVerificationGas` word |
| 22–23 | `paymasterAndData = EMPTY` plus full SHA-256 of the empty value |
| 24–25 | Complete ERC-8213 inner-calldata digest |
| 26–27 | Complete final Type-2 SPHINCS signing digest |
| 28 | `FORCED BLIND / UNVERIFIED`, cancel/sign instructions, final consent |

The previously ambiguous compact pages have these exact 16-column by four-row
layouts; every unused cell is an ASCII space and any width failure is a fatal
pre-warning preflight result:

- page 0 is exactly `! FORCED BLIND`, `UNVERIFIED CALL`, `RAW DATA ONLY`, and
  `> inspect` on rows 0..3.
- page 1 row 0 is `A{account_index} O{owner_index}` in decimal. The wire bounds
  are account `0..=255` and owner `1..=4,194,304`, so the maximum row occupies
  13 cells. Rows 1, 2, and 3 contain respectively the first 7, next 8, and last
  5 signer bytes as 14, 16, and 10 lowercase hexadecimal characters; row 1 is
  prefixed `S:`. This displays all 20 device-derived signer bytes without
  truncation.
- page 2 is `OFFCHAIN COUNT` on row 0 and all 16 big-endian lowercase
  hexadecimal count digits on row 1.
- pages 3 and 6 use row 0 labels `TARGET` and `ENTRYPOINT`; rows 1, 2, and 3
  contain the first 8, next 8, and last 4 address bytes as 16, 16, and 8
  lowercase hexadecimal characters.
- page 4 is `CHAIN ID HEX` on row 0 and all 16 big-endian lowercase
  hexadecimal chain-ID digits on row 1.
- page 5 is exactly the existing canonical handler gas page: `Call:{decimal}`,
  `Verify:{decimal}`, `PreVer:{decimal}`, and `Total:{decimal}` on rows 0..3.
  The canonical gas helper returns failure if any exact decimal does not fit;
  preflight turns that into refusal before warning.
- page 7 is exactly `SINGLE TYPE-2`, `INITCODE: EMPTY`,
  `Sel: 0x????????`, and `Data: {decimal} B` on rows 0..3. The selector uses
  eight lowercase hexadecimal characters and the decimal data length is at
  most `MAX_TX_LEN = 4,096`.
- each pair 8–9, 10–11, 12–13, 14–15, 16–17, 18–19, and 20–21 uses labels
  `VALUE`, `NONCE`, `MAX FEE`, `MAX PRIORITY`, `CALL GAS`, `VERIFY GAS`, and
  `PREVER GAS` respectively. The first page row 0 is `{LABEL} 1/2`, rows 1 and
  2 contain bytes 0..8 and 8..16 as 16 lowercase hexadecimal characters, and
  row 3 is `> next`. The second page uses `{LABEL} 2/2`, bytes 16..24 and
  24..32 on rows 1 and 2, and `> next` on row 3.
- page 22 uses `PAYMASTER EMPTY` on row 0 and bytes 0..16 of
  `SHA256_EMPTY_paymaster` on rows 1 and 2. Page 23 uses `PAY HASH 2/2`, the
  remaining bytes on rows 1 and 2, and `> next` on row 3. The empty-state
  sentinel and all 32 digest bytes are independently proved.
- pairs 24–25 and 26–27 use the same exact four-chunk scheme with labels
  `ERC8213` and `FINAL DIGEST` for the complete ERC-8213 and final Type-2
  digests.
- page 28 is exactly `FORCED BLIND`, `UNVERIFIED`, `L=Cancel`, and
  `R=Hold to Sign` on rows 0..3.

The 29-page fixed set leaves two pages of the 31-page bound unused. There are
no friendly decimal or semantic summary pages in PQ1. If any exact value,
label, digest, or final page cannot fit exactly, the request is fatal before
warning. Every page participates in scroll-to-end; the final page repeats the
weaker trust tier.

The forced flow does not also insert the ordinary conditional nonce-lane page:
pages 10–11 display and bind the complete 256-bit nonce and are strictly
stronger than the compact high-192-only lane page. The handler independently
proves those two exact pages from the signed nonce with a forced-flow-specific
completion/final-set proof. Failure to preserve that FI structure is fatal;
silent duplication, compact-lane substitution, re-budgeting, or a skipped
nonce proof is not permitted by this frozen schema.

Only one `Pages` value may exist at a time. The warning uses a fixed read-only
`&'static [Page]` in flash, while the complete final transcript is already
built in the one `Pages` value. No security argument relies on lexical
`drop`. If the compiler cannot keep this construction within the secure stack,
use explicit non-inlined page-owning phases and re-review the data lifetime.

### 5. Two request-bound physical receipts

The sequence is:

1. freeze and strictly parse the request;
2. complete the fatal preflight and build/prove the 29-page transcript;
3. check/charge the owner-selected prompt-abuse control;
4. display at least two fixed severe-warning pages from flash, including
   `CLEAR SIGNING UNAVAILABLE` and `BLIND SIGN CAN DRAIN WALLET`;
5. require scroll-to-end plus physical long confirmation;
6. publish
   `WarningReceipt { WARNING_DOMAIN, request_digest }` into its own
   fail-initialized caller-owned slot and CFI stage;
7. display the already-built raw transcript and require scroll-to-end plus a
   distinct physical long confirmation;
8. publish
   `FinalReceipt { FINAL_DOMAIN, request_digest }` into a separate
   fail-initialized slot and CFI stage;
9. independently recompute/recheck the request digest, eligible reason, both
   receipts, exact order and CFI transcript;
10. consume the private permit, durably reserve the frozen `useropSigs + 1`,
    verify that reservation, and recheck deadline/CFI; and
11. sign exactly once.

The durable use reservation deliberately precedes every possible key-use call.
A later rate, RNG, signing, cache, verification, or deadline failure may consume
one phantom use, but cannot leave a generated signature unjournaled. This
fail-closed availability tradeoff is permitted only after both physical receipts
have been consumed; no persistent write may occur earlier.

Cancel, decline, idle wipe, lock, reset, exception, parse/resource
error, CFI/FI disagreement, or any return path invalidates the permit and both
receipts. Neither receipt is stored in flash or exposed on the wire. The
implementation must prove this across `SecureState`, handler guards, reset,
panic/zeroize and interleaving paths; a stack-local claim by itself is not
evidence.

The current synchronous CMSE command has no authenticated secure-world USB
disconnect signal, so this architecture makes no false promise that unplugging
aborts an already-running ceremony. Disconnect grants no authority: both
physical confirmations remain mandatory, and every possible signature use after
an unplug is already durably reserved before key use. Adding a
disconnect-sensitive abort would be a separate trust-boundary change.

### 6. Owner-selected prompt-abuse policy

The owner selected the following exact volatile policy on 2026-07-22:

1. Each successful PIN unlock arms exactly one forced-blind attempt. This is
   SRAM-only session state, not a saved preference or reusable permission. A
   dedicated two-word `ForcedAttemptState` has exactly these valid encodings:
   `Disarmed = (0x0000_0000, 0x0000_0000)`,
   `Armed = (0xA55A_A55A, 0x5AA5_5AA5)`, and
   `Spent = (0x3CC3_3CC3, 0xC33C_C33C)`. `Armed` and `Spent` are complement-
   coded; all three codewords have pairwise 64-bit Hamming distance 32. The
   all-zero BSS value is the explicitly enumerated fail-closed `Disarmed`
   exception. Every other pair, including either single word stuck at zero,
   is fatal. Zeroize selects `Disarmed`. Generic `mark_unlocked` does not arm
   forced blind because it is also used by the physically attended first-boot
   auto-unlock path, which has not completed a PIN unlock. A separate private
   `arm_forced_attempt_after_pin` transition is called only after successful
   PIN verification and is the sole `Armed` writer. First boot, provisioning,
   test helpers, and every non-PIN unlock remain `Disarmed`; source-call-graph
   tests pin that exclusivity.
2. The handler charges the attempt only after every deterministic preflight,
   transcript construction, resource check, and CFI initialization succeeds,
   immediately before it displays the first severe-warning page. Charging is
   one voted, CFI-checked `Armed -> Spent` transition followed by an
   independent readback; a skipped or forged transition refuses.
3. There is no separate cooldown. Once charged, no second forced warning may
   be displayed during that unlock session, regardless of whether the first
   flow signs, is cancelled, or fails.
4. A 300,000 ms forced-flow deadline starts when the attempt is charged and
   covers the warning, raw transcript, both receipts, all final rechecks, and
   signature release. Physical-button activity does not extend it. The source
   is the secure software millisecond counter, not the hardware `SYST_CVR`
   down-counter. `timeout` replaces the single word with the exact complement
   pair `TICKS` and `TICKS_INV`, initialized to `(0, !0)`. The SysTick ISR is
   reordered to call a non-inlined `timeout::tick_verified()` first. That
   helper rejects an invalid old pair without repairing it, computes exactly
   `(old + 1, !(old + 1))`, publishes and independently reads back both words,
   and only then publishes success into caller-owned tick-health and CFI slots
   that the ISR fail-initialized before the call.

   The tick-health verdict becomes a mandatory argument to both feature
   variants of `hw::iwdg::systick_watch_and_kick`. A non-OK verdict or CFI
   mismatch returns before every `kick()`, including the boot-grace kick. Thus
   a stuck primary/check bit, skipped update, frozen valid pair, or skipped
   helper call cannot be refreshed indefinitely by a still-running SysTick;
   the independent LSI-clocked production IWDG resets and disarms the attempt.
   Tick faults are sticky, not self-healed. Builds without production IWDG must
   refuse forced authority on bad tick health and remain test evidence only.

   Forced authority additionally requires **Secure-only watchdog ownership**.
   Before non-secure boot, the production register image adds IWDG to
   `GTZC1_TZSC_SECCFGR1` bit 7, verifies the write, locks the TZSC image, and
   accesses the peripheral only through its Secure alias. A compile-time fence
   rejects any production forced-blind build without `iwdg` and that exact
   Secure attribution. Silicon evidence must show that both non-secure CPU
   writes and a preconfigured non-secure GPDMA channel cannot reload IWDG.
   After `hw::iwdg::init`, every `KEY_RELOAD` site routes through the verified
   tick-advance gate; the one initialization reload occurs before NS boot and
   before any forced attempt can exist. This makes the existing
   [#79](https://github.com/EthereumPhone/PQ1/issues/79) IWDG-attribution
   closure a forced-blind prerequisite rather than a deferrable production
   nicety. Missing attribution, lock, alias, or call-site census keeps forced
   authority compile-disabled; missing silicon denial evidence keeps it
   production-release-disabled.

   Thread-mode forced snapshots read and validate both words with an
   interrupt-free or equivalently retry-safe primitive so a legitimate SysTick
   update between loads cannot create a false mismatch. Each of at most three
   bounded snapshot attempts accepts three monotone pair-valid samples only
   when each wrapping delta is at most one tick; exhausted retries,
   disagreement, or backward movement is fatal. Elapsed time uses wrapping
   subtraction against the charged start and expires at `elapsed >= 300_000`.
   Tests cover primary/check stuck bits, skipped updates, invalid-old-pair
   stickiness, wraparound, and the rule that watchdog refresh never precedes a
   verified advance.

   This is precisely a **SysTick-elapsed** bound, not a claim of perfect wall-
   clock accounting while interrupts are masked. Short interrupt-masked
   flash/critical sections may under-count wall time; each such window must be
   measured below the minimum production IWDG bite interval and is an
   explicitly accepted bounded residual. Signing and release checks occur
   outside those windows.

   A forced-confirm variant factors the existing navigation core and carries
   the deadline predicate through both `wait_button` and the GPIO
   `wait_release` loop, so holding a button cannot suspend expiry. The device
   checks it in every warning/transcript wait iteration, before each receipt
   publication, immediately before the durable use reservation, again after that
   reservation and before signing, and after verified signature generation but
   before output release. The
   existing inactivity policy also remains active: its current comparator
   expires just after 120,000 inactive ticks. Real physical input resets only
   that idle timer, never the charged forced deadline. Consequently an active
   user can use at most 300,000 ms, while an idle user is wiped earlier.
5. Forced steady-state output has one fixed length: `8 + 4 + 0 + 4 + 0 + 4 +
   SIG_WRAPPER_LEN(4,128) = 4,148` bytes. Define
   `FORCED_RELEASE_RESERVE_MS = 1,000`. After the durable pre-key reservation
   and verified signature generation, but before the first non-secure write,
   retain the full `MAX_SIGN_RESPONSE_LEN` pointer validation and independently
   bind the exact 4,148-byte forced extent, tick pair/health, deadline/CFI, and
   require elapsed `< 299,000`. That final pre-write gate is the explicit **irreversible release
   authorization point**: the design assumes a hostile non-secure bus master
   may observe each byte as it is written and makes no synchronous-CMSE or
   post-write-revocation claim. The fixed publication loop must have a
   release-shaped post-LTO disassembly, cycle measurement, and hardware bound
   below 1,000 ms from that gate through the final byte, proving the complete
   usable response appears before 300,000 ms.

   Expiry at any check before this irreversible gate withholds output while
   retaining the durable pre-key reservation. A post-write deadline check is a
   diagnostic only. On an unexpected overrun the handler scrubs the exact
   current buffer extent, records a fatal error, and resets, but documentation
   and tests must not claim that scrub revokes bytes already copied by DMA. If
   the fixed publication cannot be bounded below the reserve, the feature stays
   disabled and the reserve/schema must be re-reviewed.
6. Cancel, decline, idle wipe, lock, reset, exception, parse or
   resource failure, CFI/FI disagreement, or any other return path destroys the
   request permit and both consent receipts. The attempt remains spent for that
   unlock session. Ordinary clear signing may continue after a cancellation.
7. Lock, idle wipe, reset, and power loss preserve no grant. Only a new
   successful PIN unlock re-arms one attempt.

The accepted residual is fail-closed host denial of service: a hostile or
faulty companion can consume the sole warning opportunity and force the user
to lock and enter the PIN again before another forced-blind request. It cannot
obtain a signature, bypass either consent, create persistent authority, or
train the user with repeated forced warnings in one unlock session.

### 7. Gas ownership and independent hardenings

The ERC-7730 renderer no longer emits a gas-triple page. The single and batch
handlers are the only producers for all existing confirmation sets:

1. independently recompute the canonical page from the signed gas words;
2. A/B scan the entire pre-append set and require zero exact copies and no
   near-shaped conflict;
3. for forced blind, build pages 0–4, require `len == 5`, append the canonical
   gas page as page 5, immediately run
   `userop_gas_page_proof(prior_len = 5)` while `len == 6`, and only then append
   pages 6–28 without shifting or rewriting an existing semantic page; raw
   gas-word pages must not use the canonical `Call:`, `Verify:`, `PreVer:`, or
   `Total:` row prefixes;
4. on the completed 29-page set, independently recompute and A/B scan the
   entire set with `userop_gas_final_set_proof(expected_index = 5)`;
5. require exactly one exact match, index 5, and total length 29;
6. bind completion to caller-owned CFI after append and again immediately
   before confirmation.

The differential harness must model the full handler transformation, not only
the dispatcher.

Two existing fail-closed gaps are separate PQ1 hardenings, not authority for
forced blind:

- reserve every `execTransaction` selector claim regardless of calldata length;
  a claimed-but-unverified single or batch member is fatal; and
- FI-pin the wire EntryPoint to exact v0.6, discard the wire value after the
  gate, and use the firmware constant in every T1/T2 digest.

They need implementation-stage tests/review but do not depend on resolving the
forced-tier product decision.

#### Independent P0 implementation status — scoped update 2026-07-16

The first exact implementation identity (`HEAD=64f059ffed804ebb509d8e42ed724922a1feefe8`,
tracked-diff SHA-256 `1b032b4f…9ddbf`) completed the workflow-required mutually
withheld dual first passes, same-session symmetric cross-review and bounded
responses. Its frozen 18-row matrix (`39ad7be3…0eb0`) converged on **NO-GO for
implementation acceptance and merge**: 7 confirmed, 7 narrowed, 1 refuted and
3 unresolved. The optimized and QEMU receipts cited by the earlier paragraph
belong to that pre-remediation/gas snapshot; they are not evidence for the
materially changed live tree.

The live remediation keeps the handler-owned gas page and now also moves both
EntryPoint gates before request parsing, publishes Safe strict-decoder results
directly into fail-initialized caller storage, deletes `insert_blank`, converts
all seven legacy page sites to append-only suffix construction, completion-
proves mandatory pages and every actual ERC-8213 fingerprint, renders slot
indices injectively, completion-proves the batch-banner copy, and adds an
ordered confirmed-member receipt plus an independently recomputed full-batch
digest before the final summary. A subsequent source audit also separated
adjacent sentinel-returning checks under the F-15.r1 rule. Focused and combined
evidence is recorded in `docs/work-todo.md`. The current tree now passes the
2,183/0 secure host suite (one diagnostic ignored), 194/0 ERC-7730 tests, 54/0
xtask tests, deterministic codegen, and all current QEMU assertions. A
canonical optimized dev/mock Thumb artifact preserves the EntryPoint-before-
parse gates, direct Safe publication, append/proof calls, batch copy/member/
digest gates, fingerprint proofs and 0/1 sentinel-call composition. That
artifact is E3 development evidence only: no honest production ELF is currently
linkable, its 47,952-byte batch frame is not a whole-call/on-target stack bound,
and executable FI remains open. The tree still needs a new six-component frozen
identity and the current workflow review. No prior favorable subfinding
transfers merge, release or shipment authority to this new identity.

Forced-blind v2 remains unimplemented and has not passed its architecture
gate. None of these independent fail-closed hardenings grants forced-blind
eligibility or changes the current default refusal.

### 8. Falsifiable acceptance evidence

Architecture review must first receive this exact completed decision set and
owner amendments. A later implementation/merge packet must include:

- exhaustive tables for every metadata, render, mode, exclusion and fatal enum
  variant, including a future-variant-fatal mutation control;
- canonical compact exact-set magic/schema/header/range/length/order/reserved/
  gap/trailing-byte controls; independently recovered and pinned shapes
  `K = 4,580/777/46,308`, `C = 1,366/346/17,936`, and
  `F = 3,214/546/32,528`; `C intersect F = empty`; `C union F = K`; P73S
  count/hash and Bloom reconstruction; prod/e2e substitution failures; and two
  independently initialized full runtime parse-and-lookup passes;
- `F` positive, clear-capable `C` negative, genuinely unknown/Bloom-negative,
  and adversarial `F`-negative/Bloom-positive cases, with descriptor omission
  for `C` and every Bloom collision retaining hard refusal;
- absent versus malformed/nonempty/bad/root/misbound/FI-fault separation;
- selector-only/short Safe, Safe/CoW/MultiSend/delegatecall, one-element batch,
  off-chain, deployment and rotation rejection;
- nonempty paymaster and noncanonical EntryPoint rejection;
- every-signed-field byte flips over signer, EntryPoint, chain, nonce, target,
  value, calldata, fees, all gas words and paymaster state;
- transcript/full final-digest differential and exact 29-page golden grids;
- gas zero/one/two/near-match/full-buffer/permutation tests in the complete
  handler glue;
- frozen/rechecked session-rate, minimum-interval, combined few-time-key, and
  page-123 capacity receipts, including the 249/250 boundary, present/new
  slots, full but safely compactable pages, corrupt/over-cap projections, and
  proof of room for both required appends;
- warning/final cancel, idle, replay, out-of-order, stale-receipt, exception
  and reset cleanup, plus explicit evidence that USB disconnect is not an
  authority signal;
- call-graph evidence that only successful PIN verification can arm the
  attempt; first-boot auto-unlock, provisioning and test helpers stay Disarmed;
- a scripted non-auto-confirm UI configuration;
- selected prompt-policy exhaustion, deadline and reset tests, including
  complement-pair wraparound, stuck primary/check bits, skipped/frozen tick
  advance, no watchdog kick on bad health, SysTick-stall-to-IWDG reset, the
  independent idle/forced timers, and measured interrupt-masked undercount
  windows below the production watchdog minimum;
- exact production GTZC IWDG bit-7 attribution, Secure-alias access, locked
  readback, complete post-init `KEY_RELOAD` census, compile fences, and silicon
  denial receipts for both non-secure CPU and preconfigured GPDMA reloads;
- the exact 4,148-byte forced response, pre-release `< 299,000` gate,
  explicit irreversible-release semantics under hostile DMA observation,
  diagnostic post-write check and non-revoking scrub behavior, plus a
  release-shaped fixed-publication hardware bound below
  `FORCED_RELEASE_RESERVE_MS = 1,000`;
- release-shaped Thumb link/map, post-LTO disassembly, MSPLIM/exception
  headroom and hardware stack high-water;
- FI skip/stuck-at campaigns over classifier, exact-membership receipt,
  attempt-state transition, both consent receipts, deadline, gas proof and
  final release;
- production-like NV3007 clipping/stale-row/scroll-to-end and two-real-button
  captures;
- production configuration/prodtest parity, authenticated ERC-8176 offline
  verifier/snapshot, release provenance, rollback and signing-key custody
  closure.

Source tests do not replace target/hardware evidence. Hardware evidence does
not replace byte-binding, parser, routing, provenance or configuration gates.

### 9. Authority, owner amendments and convergence

The favorable fresh architecture review and 2026-07-22 owner/maintainer Phase-C
decision are accompanied by the minimum controlling amendments to `CLAUDE.md`,
clear-signing CS2/CS9, the companion guide and integration contract,
root-rotation policy, `docs/STATUS.md`, production feature/configuration
documentation, and the ERC-8176 status owner. Those amendments select this
candidate for implementation but do not claim that its currently absent code
or evidence exists. Controlling language:

> Forced blind is not clear signing. A registry-known call never silently
> reaches the ordinary ERC-20, typed-call, selector-name, or generic blind
> ladder. A tuple in the firmware's accepted clear set either clear-signs or
> fatal-refuses; descriptor omission cannot downgrade it. Only an exact member
> of the separately authenticated refused-known set, with cleanly absent
> metadata in the enumerated single steady-state Type-2 case, may enter the
> on-device forced-blind ceremony. Default and rollback remain refusal.

This plan authorizes no flashing, hardware fault injection, release,
publication, deployment, signing-key use, OTP/option-byte/secure-element
lifecycle change, or shipment. The independent ERC-8176, rollback,
production-configuration, hardware UI/FI, resource, provenance and release
gates remain unchanged.
