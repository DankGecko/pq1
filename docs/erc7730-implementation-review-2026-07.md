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
(resolver-capability histogram; C1/C2/C3 have since landed), `docs/erc7730-registry-coverage-2026-06.md`
(stale counts), the three `VULN-erc7730-*.md` postmortems.

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

---

## Tier 2 — Pipeline sustainability (the resync ceremony)

### 2.1 Curations are in-place edits to the vendored registry — re-vendor clobbers them by construction
`xtask vendor-registry` does `remove_dir_all` + re-copy (xtask/src/main.rs:1297-1318); the
Tier-A curations (Uniswap `sqrtPriceLimitX96` hide, Permit2 `nonce`) are unmarked edits to
vendored JSON (exactly 2 files diff vs upstream today). Guard tests fail loudly on reversion,
but recovery is git archaeology, guards are keyed to *outcome* (format still compiles) not
*content* (upstream can edit a curated descriptor without tripping them), and the curation
count will grow.
**Fix:** curation overlay dir (`secure/data/erc7730-curations/`, JSON-merge patches, each
pinned to the **sha256 of the upstream base file** + required `rationale`, same shape as
`HiddenAddressAllow` in policy.toml). `vendor-registry` applies overlays after copy;
base-hash mismatch fails loud ("upstream edited a curated descriptor — re-review"). Vendored
tree returns to byte-identical-to-upstream, so the faithfulness check becomes exact. Effort M.

### 2.2 Duplicate-leaf precedence is alphabetical-filename (registry-squatting surface)
Dedup on `(chain, contract, primary_type_hash, ctx)` keeps the lexicographically-first source
path (dbgen/src/erc7730.rs:554-590); for contract ctx `primary_type_hash` is always 0. An
upstream PR adding `1inch/aaa-router.json` would silently swap which descriptor the device
trusts for a covered contract on the next resync — recorded only in the discarded skip list.
**Fix:** hard-error (or require a policy.toml precedence entry) when duplicate IRs are not
byte-identical; keep silent-drop only for byte-identical dups. Effort S.

### 2.3 Provenance + resync workflow gaps (batch of S items)
- Auto-stamp the upstream SHA: `vendor-registry` runs `git rev-parse HEAD` into the vendored
  README **and** the `render_review` header, so the drift-gated artifact carries provenance
  (today it's hand-typed with an in-file TODO). (xtask/src/main.rs:1224, dbgen erc7730.rs:4723)
- Support re-vendoring at the *recorded* SHA so "renderer unlocked more descriptors" and
  "upstream moved" are separate commits with single-cause root diffs.
- `xtask diff-registry`: A/B tolerant builds at two registry revisions → leaves
  gained/lost/IR-changed + clear↔blind transitions by category + curated-file collisions.
- A short `docs/` runbook for the resync ceremony (vendor → overlays → dbgen → review diff →
  commit) — it's currently implicit in guard-test failure messages.
- `--policy production` is silently inert for the registry corpus (`let _ = force_production`,
  dbgen/src/main.rs:303) — make it a hard error until the ERC-8176 attestation flip lands.
- Filename-convention tripwire: scanner only sees `calldata-*.json`/`eip712-*.json`
  (erc7730.rs:484-498); count unscanned JSONs containing a `context` key and warn/fail.
- The review-file "dev mode — CI MUST reject" banner has no corresponding CI assertion yet;
  track so it doesn't ride to ship.

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
   (vendored-copy patching, the Permit2-nonce precedent) but each hidden param needs review —
   some (price-affecting ones) should be *rendered*, not hidden. Effort S/descriptor, M for
   the review across 82. Strong amplifier for the 2.1 curation-overlay mechanism.
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
  earlier histogram in `erc7730-coverage-blocker-analysis-2026-07.md` for current state —
  C1/C2/C3 landed since). The **attestation flip** (dev-mode `allow_unattested` → enforced
  ERC-8176) remains the orthogonal lever, blocked on the EAS ecosystem (~0 real
  attestations, `docs/erc8176-attestation-status.md`), not code.

Documented-deviation candidates (write down, don't change): date blockheight shows
`block #N` not approximate time (no block-time oracle); duration `Xd Yh Zm` vs spec HH:MM:ss;
string raw restricted to printable ASCII (anti-homoglyph); selector-form/types-only format
keys unsupported (names are load-bearing since `abi` is ignored).

---

## Tier 4 — Rendering UX fidelity (what the user actually sees)

Display model: 16 cols × 4 rows, `MAX_PAGES = 28`; a simple USDT transfer is 8 pages.
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
  "raw == hex" is an invariant other code + tests rely on (the C2/Morpho tuple-render tests
  probe a raw member's *hex*), and a decimal could read as a meaningful count for a genuinely
  opaque word. Revisit only with a descriptor-level signal that the word is numeric — a
  readability nicety, not worth breaking the invariant + churning tests I don't own.
- **4.7 EIP-55 checksum casing** in `write_addr_full` (primitives.rs:265-294) — every wallet
  UI the user compares against is checksummed; one keccak per address page, shared across
  erc20/Safe/CoW paths too.
- **4.8 Chain-name table covers 9 chains; registry ships ~15+** (Avalanche 38 descriptors,
  Sonic 34, Linea 27, Scroll 10, …) — all render `(UNVERIFIED)`, diluting that word's alarm
  value. Extend table; change fallback to `(unknown chain)` so UNVERIFIED keeps one meaning.
- **4.9 Envelope is 4 pages on every tx** (mod.rs:689-717) — merge to 2 (chain+nonce /
  fee+tip+worst-case). Page fatigue is a security cost. Effort S-M (pinned-test churn).
- **4.10 PageBudget overflow → straight to blind-sign**: `COMPACT_MODE` is `const false`
  (mod.rs:56). On `RenderErr::PageBudget`, retry once with compact mode (spec-sanctioned:
  optional fields may hide) before declining — unlocks the largest batch/array descriptors.
  Effort M.
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
  is closed and pinned by named regression tests; round-half-up display; full 40-hex
  addresses; loud unbound-token pages; the no-visible-fields belt.
- The decline-to-blind ladder decision lives in exactly one place with a documented contract
  on `RenderErr` — the policy is centralized even though the Reject strings need polish.
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
