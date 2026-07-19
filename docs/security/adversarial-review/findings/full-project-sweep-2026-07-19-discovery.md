---
report_kind: supplemental-discovery-pre-cross-adjudication
surface: multi
run_date: 2026-07-19
target_identity: "repo HEAD 47b407f1d986f7d932ac945b936280521b1d2060 (master at sweep time, sweep date 2026-07-19; master has since advanced; tree clean for the sweep's scope)"
cross_adjudication_sha256: "none — this report has not been cross-adjudicated; no cross-adjudication matrix exists for it"
scope: "second full-project discovery sweep: 7 parallel adversarial lanes over (a) the erc7730-campaign diff 89c60063..HEAD (+27.5k/−9.5k, 185 files), (b) the 2026-07-19 security fix batches a48ba092/2ce50ca1/86d6afb2 as new code, and (c) the first sweep's documented blind spots; source/config review evidence only, existing test suites executed only where stated"
status: open
---

# Full-project adversarial sweep 2 — discovery report — 2026-07-19

> **SUPPLEMENTAL DISCOVERY EVIDENCE — PRE-CROSS, NON-CANONICAL.** This file is
> the output of a **single-coordinator discovery sweep** (7 parallel
> adversarial lanes). It has **NOT** been cross-adjudicated. Every finding
> below is `🔲 OPEN`; this report contains **no CONFIRMED / REFUTED / NARROWED /
> UNRESOLVED dispositions**. It grants **no merge, shipment, hardware, or
> adjudication authority**. Canonical recording requires the Partner-A /
> Partner-B exact-pair cross-adjudication per
> [`docs/planning-and-review-workflow.md`](../../../planning-and-review-workflow.md);
> until that runs, nothing in this file is a canonical finding.

## Sweep metadata

- **Target:** repository HEAD `47b407f1d986f7d932ac945b936280521b1d2060`
  (branch `master` at sweep time, sweep date 2026-07-19; master has since
  advanced; tree clean for the sweep's scope).
- **Method:** second sweep, 7 parallel adversarial lanes over
  (a) the erc7730-campaign diff `89c60063..HEAD` (+27.5k/−9.5k, 185 files)
  (lanes CAMPAIGN-CORE, CAMPAIGN-RENDER, SEMANTIC-EVIDENCE),
  (b) the 2026-07-19 security fix batches `a48ba092` / `2ce50ca1` / `86d6afb2`
  as new code (lane FIXBATCH), and
  (c) the first sweep's documented blind spots (lanes BLIND-SE,
  BLIND-RENDER-BULK, BLIND-INFRA).
- **Known-issue exclusion:** the full GitHub tracker (425 issues, dumped to the
  lanes) plus `docs/STATUS.md` §A–§D plus the findings catalogue. Every lane
  read the full 425-line inventory. Result: **26 kept candidates** (22 KEEP +
  4 KEEP-NOTE; covers 27 raw candidates via one cross-lane merge) and
  **2 dropped as already-tracked** (#378, #372). Cross-lane merge:
  SEMEV-1 ≡ CORE-1 — one entry kept, both lane IDs noted.
- **Evidence level:** source/config review; lanes executed existing test
  suites where stated (per-finding and in the per-lane verdicts below); no
  fuzz campaigns, no Kani, no silicon.
- **Regressions of the 2026-07-19 fix batches (#146/#147/#148/#165/#172
  etc.):** none found among kept candidates. The FIXBATCH lane explicitly
  re-verified those fixes and traced the touched state machines. FIXBATCH-1/2/3
  are doc/version residuals left behind by the #143/#136-class changes —
  incomplete-fix leftovers, not re-breaks. FIXBATCH-4 is a *new instance* of
  the #163 pattern class in new code, not a regression (the pre-fix code was
  equally skippable).

## Coordinator verification

The following lane claim was independently **re-verified by the coordinator
directly from source on HEAD `47b407f1`** — not merely lane-claimed.

- **BLIND-SE-1 (→ S2-F14):** the first-boot ceremony ordering defect was
  re-traced link by link:
  1. `main.rs:1347` `run_post_lock_provisioning` runs **before** `load_pbs` at
     `main.rs:1362/1366` (in-file comment: "This is the FIRST SE traffic");
  2. first_boot step 5 calls `hw.trng_salt()` (`first_boot/state.rs:213`)
     **before** `optiga_rotate_pbs`;
  3. `trng_salt` → `rng_strong::fill` (`first_boot/mod.rs:257`);
  4. the production OPTIGA RNG leg MUST traverse the Shielded Connection per
     CRIT-8 and fails closed otherwise (`optiga/mod.rs:235-254`, "no silent
     plaintext downgrade");
  5. the shield is keyed with the transport PBS only inside
     `rotate_pbs_to_salted` (`optiga/mod.rs:~622` `shield.load_pbs(&tr_pbs)`),
     i.e. AFTER the salt draw.
- **Conclusion:** in the `rdp2-self-lock + dual-se` ship combo the first-boot
  ceremony halts at the OptigaPbs step on real hardware. Host/mock paths
  cannot reach the `stm32u585`-only cfg, so this remains a source-trace PoC
  whose falsification path is booting RELEASE_FEATURES on silicon or host-sim.

## Findings

26 kept candidates, numbered S2-F1–S2-F26, grouped by lane. Each entry keeps
its original lane ID, the lane's own severity and PoC/suspicion label, the
`overlap-check:` reference where one exists, and the full evidence block
transcribed from the deduped candidate record. **Every finding is
`🔲 OPEN`** — open does not mean confirmed; it means unadjudicated.

## Findings — lane CAMPAIGN-CORE — S2-F1–S2-F6

### S2-F1 — [CORE-1 / SEMEV-1] Include-reach escapes every corpus receipt — plantable JSON at the vendored root feeds the pinned build behind a green CI
- **Severity:** medium (CORE assessment) / low (SEMEV assessment — see mitigants)
- **Evidence label:** PoC (reasoning trace, source-verified; no live repro under the no-write rule)
- **Lane verdict:** KEEP — merged cross-lane duplicate (reported independently by lanes CAMPAIGN-CORE and SEMANTIC-EVIDENCE; one entry, both lanes credited).
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `resolve_include_path` bounds `includes` to the whole `registry_root`
  (`dbgen/src/erc7730.rs:7465-7473`, `canonical.starts_with(registry_root)`), and for the
  production build `registry_root` = `secure/data/erc7730-registry` (`xtask/src/main.rs:676`,
  `dbgen/src/main.rs`). But every receipt/verification walks only the `registry/` + `ercs/`
  subtrees (`xtask/src/erc7730_curation.rs:854-860` `collect_curated_corpus_files`;
  `xtask/src/main.rs:3323-3325`). A JSON-parseable file planted at
  `secure/data/erc7730-registry/planted.json` plus `"includes": "../../planted.json"` in any
  corpus descriptor is consumed by `load_resolved_descriptor_json`
  (`dbgen/src/erc7730.rs:2003-2011`) yet is invisible to `verify_checked_in_tree`, the
  corpus receipts, and the whole CI drift chain (fresh build == committed artifacts,
  self-consistent). `scripts/gate_enforcement.json:318` declares the
  `prod-erc7730-provenance-check` gate responsible for `secure/data/erc7730-registry/**` —
  an overclaim, since the executed check never reads root-level files there. Vendor-time is
  fail-closed (staging rebuild refuses escapes), so this needs a repo-side PR + reviewer
  miss, but it silently defeats the campaign's core claim ("complete… faithfulness proof",
  main.rs:3617).
- SEMEV-1 adds: the omission scan (`dbgen/src/erc7730.rs:962-983`) likewise walks only
  `input_dir` + `ercs/`, never other top-level dirs; extra top-level dirs are silently
  ignored (no error), so `verify_checked_in_tree` (371-395) stays green with an added
  `specs/` dir. Mitigants SEMEV verified: the known-call scan does resolve includes
  (`collect_declared_contract_calls` → `load_resolved_descriptor_json`,
  dbgen/src/erc7730.rs:1388), so declared tuples still Bloom-register; and any content
  effect changes the Merkle root / `erc7730.review.txt`, which the CI drift gate
  (`gen-erc7730-descriptors --check`, ci.yml:207) forces into the reviewed diff. SEMEV's
  net: this breaks the receipt's completeness claim ("files: 387 is the whole curated
  corpus"), not silently the firmware root.
- Breaks: build-release provenance / receipt-completeness invariant for the device-pinned
  descriptor corpus. Related (kept separately): CORE-3 — same "include-reach > covered
  set" design flaw in the clean-checkout gate's pathspec.

### S2-F2 — [CORE-2] Manifest `TOOL_INPUT_PATHS` under-covers the root/bloom construction — leaf-hash/bloom/tail-emission code is not hash-bound
- **Severity:** medium
- **Evidence label:** PoC (source-verified)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

The curation manifest pins exactly 12 tool files (`xtask/src/erc7730_curation.rs:30-43`)
and claims to bind "the host compiler entry point, descriptor compiler/parser, dependency
resolution, and pinned toolchain". Not pinned but consumed by the pinned-root pipeline:
`pqsigner-erc7730/src/bundle.rs` (`leaf_hash`, :184 — defines `ERC7730_DESCRIPTORS_ROOT`;
imported at `dbgen/src/erc7730.rs:56`), `pqsigner-erc7730/src/known_calls.rs`
(`BLOOM_BYTES`/`DOMAIN`/`insert`, :21-66 — defines the firmware `include_bytes!`'d omission
filter), `pqsigner-erc7730/src/abi.rs` (`dbgen/src/erc7730.rs:6513-6517`), `render/*` +
`display/primitives.rs` (:57,66), `dbgen/src/lib.rs` (`render_erc7730_security_tail`/
`emit_generated_root` — the `db_roots.rs` writer, lib.rs:55-95), `dbgen/src/erc20.rs`
(capability compiler). A malicious PR altering the Merkle domain separation, bloom scheme,
or tail emission keeps every automated gate green (self-consistent rebuild; manifest
tool-input check untouched; `gate_enforcement.json:299-313` trigger coverage satisfied).
Only human review catches it — the exact gap the manifest binding exists to close.

### S2-F3 — [CORE-3] `diff-registry` cleanliness gate pathspec ⊂ include-reachable set — dirty include inputs escape "clean provenance"
- **Severity:** low-medium
- **Evidence label:** PoC (reasoning trace, source-verified)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`verify_official_clean_checkout` runs `git status --porcelain -- registry ercs
specs/erc7730-v2.schema.json` only (`xtask/src/erc7730_curation.rs:435-446`), but snapshot
builds resolve includes anywhere under the checkout root. A dirty or untracked
include-reachable file outside that pathspec (e.g. checkout-root `common.json` pulled via
`includes: "../../common.json"`) is consumed by `capture_snapshot`
(`xtask/src/erc7730_diff.rs:179-216`) while the report asserts clean, commit/tree-pinned
provenance; the before/after anti-TOCTOU re-check can't see it either (corpus receipts and
file maps cover only `registry/`+`ercs/`). Committed content stays tree-pinned, so the hole
is working-tree dirt only; vendor-registry has the staging-rebuild backstop, diff-registry
has none — it is the final review evidence for registry updates. Same root-cause family as
CORE-1/SEMEV-1 (include-reach exceeds the covered set), different gate and different fix.

### S2-F4 — [CORE-4] Committed review artifact injectable via upstream filenames — forged leaf rows / provenance lines
- **Severity:** low
- **Evidence label:** PoC (reasoning trace; per constraints no files written)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

All descriptor *content* in the review is escaped via `review_ascii`
(`dbgen/src/erc7730.rs:7599-7609`), but entry rows print the raw
`e.source.file_name().unwrap().to_string_lossy()` (:7934) and skip lines print
`review_relative_path(...)` with only backslash replacement (:7971, :7984-7992). Only
non-UTF-8 names are refused (:925-932); `\n` is legal UTF-8 and passes the `.json` suffix
checks. A malicious upstream filename/dirname like `calldata-x\n[0007] ctx=contract
chain_id=1 contract=0x… source=calldata-victim.json\n.json` injects arbitrary forged lines
(fake leaf rows, fake `# Root:`/`# Curation manifest SHA-256:` lines) into the committed,
drift-gated `erc7730.review.txt` — the artifact auditors are told to reconcile against.
Additive-only (can't delete real rows; the Makefile provenance gate at `Makefile:108`
takes the first awk match and can't be pre-empted; hash bindings unaffected). Breaks the
integrity/auditability expectation for a committed provenance artifact. (F12/#157 is
device-side truncation, unrelated.)

### S2-F5 — [CORE-5] `cargo run -p dbgen` stamps manifest provenance into the review header without verifying the manifest shape or the corpus↔manifest binding
- **Severity:** low
- **Evidence label:** PoC (source-verified)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`load_registry_review_source` (`dbgen/src/erc7730.rs`) parses a lenient projection — no
`deny_unknown_fields`, no `manifest_version`/`mode` checks (contrast the strict
`validate_manifest_shape`, `xtask/src/erc7730_curation.rs:507-613`) — and dbgen stamps
`# Upstream registry commit/tree` + manifest SHA-256 without ever verifying the checked-in
corpus against the manifest; that verification exists only in the xtask `--check` CI gate.
A drifted worktree yields authoritative-looking stamped artifacts on the primary developer
regeneration path. Documented ("Full manifest/corpus verification remains owned by the
curation gate") and CI-backstopped, so low — but the stamp's claim exceeds what dbgen
checked. (Distinct from #345, which is signed-release-manifest binding.)

### S2-F6 — [CORE-6] `--no-curation-overlay` production-path guard defeated by a final-component symlink
- **Severity:** low
- **Evidence label:** PoC (reasoning trace, source-verified)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`canonical_named_destination` (`xtask/src/main.rs:3033-3058`) canonicalizes only the
parent and joins the final name, so `--out secure/data/<symlink→erc7730-registry>`
compares unequal to the production path and the "cannot replace the checked-in production
corpus" guard passes; `vendor_registry` then installs through the symlink into the
production corpus with the overlay disabled. Requires operator-side symlink setup
(upstream content can't create it) and CI `verify_checked_in_tree` catches the result at
PR time. (#404 covers only the gen-probe isolation guard, which the lane verified holds.)

## Findings — lane CAMPAIGN-RENDER — 0 kept

No kept candidates. Both lane findings fold into tracked items: `[RENDER-1]`
dropped as already tracked by #378 (descriptor↔deployed-semantics
reconciliation; the lane's own recommendation is to log the newly-admitted
Lido "Unlimited"-over-≥2^255 threshold instance as a #378 receipt item, not a
new defect class — threshold arm pre-existing and reviewed; economically
inert); `[RENDER-2]` dropped as already tracked by #372 (Date/Enum arms
missing from device `render_array_element`; dbgen admits ops the device
hard-refuses — same root cause/code path, fail-closed availability/bloat
only). The lane reproduced no WYSIWYS break in the new schema-v5 render code;
it executed `pqsigner-erc7730 --lib` (251/251) and dbgen `erc7730_roundtrip`
(36/36); integer-canonicality, TLV pairing, interpolation fail-closure, and
root/count integrity all verified held.

## Findings — lane SEMANTIC-EVIDENCE — S2-F7–S2-F9

### S2-F7 — [SEMEV-2] Lido source-binding tripwires are insertion/reorder-tolerant, and selector-in-runtime assertions are asymmetric
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `dbgen/tests/erc7730_semantic_evidence.rs:615-629`: the "archived upstream lines present
  in verified flattened source" check is a `BTreeSet` line-subset over the *whole*
  flattened file — order-insensitive, duplicate-collapsing, and satisfied by a match in
  any contract section. `assert_fragments_in_order` (76-84) tolerates arbitrary insertions
  between fragments. The permit/wrap bodies are additionally fragment-pinned, but the rest
  of the deployed file (e.g. `unwrap`, `transferFrom`, storage layout) is only
  sha256-pinned via the manifest — a future re-capture that regenerated the manifest over
  drifted source would not trip these semantic checks.
- Asymmetry: the Lido test asserts the permit selector occurs in the archived runtime
  (483-488) but never the wrap selector; the StakeWise test never asserts `0x8697d2c2`
  occurs in `EthVault.{mainnet,hoodi}.hex`. The lane verified the bytes themselves:
  `0x8697d2c2` present ×1 in both EthVault runtimes, `0xea598cb0` present in WstETH
  runtime — evidence is internally consistent today; the gap is only in what a
  regenerated-green manifest would catch.
- Lane confirmed not materially covered by any listed issue (#378 is the
  descriptor-semantics audit, not the evidence-check machinery).

### S2-F8 — [SEMEV-3] Fixture receipt collector silently skips non-`.tests.json` files under the fixtures tree
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`dbgen/tests/erc7730_upstream_conformance.rs:85-93` (`collect_regular_files`): files not
ending in `.tests.json` are neither receipted nor rejected (the `else` panic covers only
non-file entries). A stray `registry/lido/tests/notes.json` under
`tests/erc7730-upstream-fixtures/` would leave the corpus receipt, file count (272), byte
count (687,949), and every stat green — the README's "byte-for-byte test-only import"
posture is only enforced for the `.tests.json` subset. Lane verified no such strays exist
today (own walk) and the corpus is inert test-only input, so impact is provenance hygiene
only. (#424 concerns transcript rows, not file inventory.)

### S2-F9 — [SEMEV-4] Recorded hash fields that no check ever asserts
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`tests/erc7730-semantic-evidence/lido-wsteth-permit/manifest.json:57`
(`explorer_source_code_sha256_decoded_crlf`), `:78` (`full_verified_abi_canonical_sha256`),
and `stakewise-claim-exited-assets/manifest.json:112` (`full_verified_abi_canonical_sha256`)
present themselves as pins, but grepping the consumer
(`dbgen/tests/erc7730_semantic_evidence.rs`) shows no assertion reads them; the green
result is independent of their values. Either assert them (cheap: they are derivable at
capture time only, so make them documentation-named, e.g. `*_informational`) or drop them
— as-is they invite a reader to over-trust the receipt. Breaks the "a green gate depends
on the artifact it claims to cover" prodtest/assurance-fidelity invariant.

## Findings — lane FIXBATCH — S2-F10–S2-F13

### S2-F10 — [FIXBATCH-1] companion-app-integration.md still documents the deleted 3-byte GET_STATUS format
- **Severity:** low
- **Evidence label:** PoC (verified doc-vs-code)
- **Lane verdict:** KEEP-NOTE — a leftover of the #143 (X17-UC2) fix — plausibly in scope of that issue's fix-completeness, but the stale canonical section (lines 264-270) is a distinct artifact the inventory entry does not name; #149 covered three *other* USB doc-drift spots. Kept for the coordinator to decide whether it rides #143 or stands alone.
- **Overlap-check:** #143 (also adjacent to closed doc-drift finding #149)
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

The X17-UC2 fix (`a48ba092`) updated the flow summary at
`docs/companion/companion-app-integration.md:782` but missed the canonical format section
in the same file: lines 264-270 still specify "**Response (3 bytes + SW):** offset 0
`provisioned`, 1 `locked`, 2 `pin_remaining`". The wire now returns 2 bytes
`[locked][pin_remaining]` (`nonsecure/src/usb/commands.rs:460-467`). A companion built
from this doc reads `locked` as `provisioned` — on an *unlocked live wallet* it computes
`provisioned=0` ("not provisioned") and `pin_remaining` as `locked` — steering the user
toward the first-boot/setup flow, which is precisely the F24 (#169)
wizard-misfire-destroys-live-wallet trigger class.

### S2-F11 — [FIXBATCH-2] GET_STATUS wire change shipped without bumping PROTOCOL_VERSION
- **Severity:** low
- **Evidence label:** PoC (verified)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`proto/src/lib.rs:1765` keeps `PROTOCOL_VERSION = 0x0200` (pinned by
`proto/tests/positive_layout.rs:440`) despite the response-layout change. Companions have
no negotiation signal: old companions misparse new firmware (FIXBATCH-1 shape), new ones
misparse old. No tracked issue covers a version bump for this change (#353 is the
unrelated slot-rotation wire bump). Low because pre-production with an in-lockstep
companion — but the version field exists exactly for wire evolution. Breaks the
usb-companion wire-evolution contract.

### S2-F12 — [FIXBATCH-3] New hard bounds (30 s chain lifetime, 30 s/120 s drain deadlines, F11 lease refusal, 5 s reassembly timeout) are absent from the companion wire contract
- **Severity:** low
- **Evidence label:** PoC (verified doc-vs-code)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`docs/companion/usb-protocol-v2.md` §Command Chaining (:40-51) and §Response Chaining
(:53-67) document none of the new bounds. Trace: companion drips a chained SIGN_USEROP
over >30 s → `ChainState::tick_timeout` resets (`apdu_framing.rs:187-198`) → the owner's
next chunk (P1=0x80, same INS) hits `step` with `ins==0` and is acked **SW_OK as a
brand-new chain at pos=0** (`:216-218`) → final P1=0x00 Executes a truncated payload →
late, unexplained failure (secure parsers reject truncation, so availability-only, no
mis-signing). Same doc's FW_CHUNK row (:90, "Chained? Yes") contradicts the code comment
the same commit rewrote ("CHUNK is not in the chained-INS set", `commands.rs:293-299`);
pre-existing row, but the commit edited this exact doc. (#428 is the FNSOF-freeze clock
issue, not this documentation gap; #149 is closed. The post-timeout re-welcome behavior
itself was traced by the lane as availability-only and is not a #146 regression.)

### S2-F13 — [FIXBATCH-4] The new rng_strong production SE-failure gate is a plain bool, not a sentinel
- **Severity:** low
- **Evidence label:** suspicion, unverified (pattern-class, new instance)
- **Lane verdict:** KEEP-NOTE — #163 is scoped to `read_entropy_blob` ×3 and does not name this new site; kept because this instance is new code introduced by this batch. Not a regression (the pre-fix `map_err(...)?` was equally skippable).
- **Overlap-check:** #163
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`secure/src/rng_strong.rs:88-92`: `if !fold_se_blocks(buf, |b| unsafe {
crate::se_random(b) }.is_ok()) { return Err(()); }` — the "absent SE contribution is
fatal" claim rides on a single-skippable `!bool` branch plus a plain `.is_ok()` in the
closure (`rng_strong_fold.rs:30-47`). Under the project's own F-15/F-18 doctrine
(attacker-bypass-target gates must be Hamming-distant sentinels), brand-new code had the
chance to use `check_true_into_sentinel` and didn't. Same pattern class as tracked #163
(F18, plain-bool gates on `read_entropy_blob`). Consequence narrowed: residual entropy is
still the hardware TRNG.

## Findings — lane BLIND-SE — S2-F14–S2-F17

### S2-F14 — [BLIND-SE-1] First-boot ceremony deterministically halts at E0851 — `trng_salt` needs the OPTIGA shield before `load_pbs()` ever runs
- **Severity:** high
- **Evidence label:** PoC (source call-chain trace) — independently re-verified by the coordinator (see Coordinator verification above)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

In the only combo where the ceremony exists (`rdp2-self-lock + dual-se`, the
RELEASE_FEATURES combo at `Makefile:2190/2244`), Phase B's OPTIGA step can never complete:

- `secure/src/first_boot/mod.rs:255-259` — `FirstBootHwImpl::trng_salt` draws the salt via
  `crate::rng_strong::fill`.
- `secure/src/rng_strong.rs:87-95` — production build mandates the SE contribution;
  `main.rs:493-503` → `DualSecureElement::random` (`dual_se.rs:559-563`) makes the
  **OPTIGA leg mandatory**.
- `optiga/mod.rs:307-309` → `ensure_shield` → `optiga/mod.rs:493-496`: `if
  !self.shield.pbs_loaded { return Err(OptigaError::Shield) }`. `pbs_loaded` is set only
  by `shield.load_pbs` (`optiga/shield.rs:136-138`), called from
  `load_pbs()`/`load_pbs_from_device_root()`/`rotate_pbs_to_salted`.
- Boot order in `main.rs`: `run_post_lock_provisioning` at **1344-1348** runs BEFORE
  `load_pbs()` at **1362-1367**. Steps 2–4 (BHK, SE050 legs) never touch the OPTIGA, and
  within step 5 `trng_salt` precedes `optiga_rotate_pbs` (which would have loaded a PBS).
  So on first entry to step 5, `pbs_loaded == false` → OPTIGA random fails → `rng_strong`
  fails → `FirstBootError::OptigaSaltPersistFailed` → `halt_first_boot(E0851)`
  (`first_boot/mod.rs:94-114`), WFI forever; every resume re-halts at the same step (salt
  is never committed).

Consequence: the load-bearing transport→final rotation (invariant #3's accepted Grover
residual depends on it) can never reach `ALL_DONE`; every field unit bricks at first boot
(fail-closed, E0851 RMA). All "journaled, resumable" evidence is host-test-only: the 22
`first_boot` tests pass (`cargo test -p sphincs-tz-secure first_boot`, lane ran it) but
use `FakeHw` — the real `trng_salt` is `#[cfg(all(not(test), feature =
"rdp2-self-lock"))]` and unreachable by any host test. No silicon run of the full ceremony
has happened (docs/provisioning/first-boot-provisioning.md:4 "silicon and
protocol-closure gates pending"). Distinct from #192/F47 (`rdp-enforce-halt` combo blocks
Phase A; this blocks Phase B in the normal ship combo) and from #268 (the ship-blocker
work item to close provisioning — this is a concrete boot-order defect inside it).

### S2-F15 — [BLIND-SE-2] SE050 `send_apdu` mangles payload-less (Case-2) read commands — `get_version_ext` goes on the wire with no Le
- **Severity:** medium (latent)
- **Evidence label:** PoC (construction trace; silicon verdict pending)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`se050/apdu.rs:932-933` — `get_version_ext` builds `ApduBuf::new(0x80, INS_MGMT, 0,
P2_VERSION_EXT).finish(true)` with **no payload** → 5-byte Case-2 APDU `80 04 00 21 00`.
In `send_apdu` (`apdu.rs:314-323`) the Le/Lc heuristic: `apdu.len() >= 7` is false →
short-Lc branch gives `hdr_len=5, lc_val=apdu[4]=0` → `has_le = 5 > 5+0 = false`.
`wrap_apdu` (`scp03.rs:411-419`) then sees no data, emits `84 04 00 21 08 <CMAC×8>`, and
the Le re-append (`apdu.rs:333-344`) is skipped — the chip receives a Case-1/3-form
GetVersionExt with no Le. Every other read command (check_exists, create_session,
get_random, read_authed) has a payload and is handled correctly; `get_version_ext` is the
only payload-less `finish(true)` caller (lane verified by grep). Today only the bench
harness calls it (`se050_stress/ctx.rs:505`), but the tracked production plan is to wire
exactly this function into the boot-time anti-substitution variant assertion (#61/#206) —
the assertion would sit on a malformed wire shape (fail-closed DoS or, if error-tolerated,
a bypassed gate). Cross-reference (not overlap): #61/#206 track adding the gate, not the
APDU defect; #115 (SE17-12) is latent *panic* windows in APDU wrapping — different
mechanism.

### S2-F16 — [BLIND-SE-3] `factory_provisioning` power-cut between dummy-provision and wipe strands the unit with zero-PIN user objects and refuses re-run
- **Severity:** low
- **Evidence label:** PoC (reasoning trace)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`factory_provisioning.rs:577-597` provisions both SEs with all-zero entropy/master/VK and
PIN `00000000`; step 5 (`:600-623`) wipes via `factory_reset_admin`. A power cut in that
window leaves a provisioned-looking chip: on re-run, step 3's gate (`:524-526`) returns
`AlreadyUserProvisioned` and halts — no in-ceremony resume, operator must manually wipe.
Availability-only, and the path is quarantined + compile-fenced
(`factory-production-irreversible-im-sure`), so exposure is limited to the
deliberately-opted-in factory build. (#263 covers ceremony phases B-F tooling, not this
crash window.)

### S2-F17 — [BLIND-SE-4] `flash.rs` page-125 layout comment declares the duress-wipe-mode QW "unused"
- **Severity:** low
- **Evidence label:** PoC (doc-vs-code)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`secure/src/hw/flash.rs:567-571` documents page 125 as "QW 0: admin PIN; QW 1: wipe flag;
bytes 32..8192: unused, 0xFF" — but `DURESS_WIPE_MODE_OFFSET = 32` (`flash.rs:668`) places
the armed wipe-on-duress marker exactly there, and QW 0's "admin PIN" is also retired
(derived now). A maintainer trusting the comment could allocate offset 32 and collide with
the duress flag (arm reads as garbage → decoy/wipe confusion, F26-class). (#171/F26 is the
wipe-on-duress behavior downgrade, not this stale layout comment.)

## Findings — lane BLIND-RENDER-BULK — S2-F18–S2-F20

### S2-F18 — [BRB-1] Nested EIP-712 completeness is top-level only — a nested non-address effect-bearing member (Permit2 details.amount) can be omitted from a compiling, pinnable descriptor
- **Severity:** high
- **Evidence label:** PoC (source trace + corpus evidence; compile not executed under the WRITE NOTHING rule)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `dbgen/src/erc7730.rs:5148-5179` (`check_eip712_field_completeness`) iterates
  `parsed.top_names` only and credits an entire struct member when ANY child path resolves
  to it (`path_top_param_index` :5214 — `details.token` "covers" `details`). Rule 2
  descends for *addresses only* (`check_eip712_member_addresses` :5579; non-address
  returns `Ok(())` :5654-5657). Rule 3 constrains only explicitly-hidden fields
  (:5539-5558). `compile_nested_block`'s E2 self-check enforces only address-word coverage
  (:4369-4373). Device side is identical: `validate_nested_structure` only enforces
  `addr_word_bmp` (`pqsigner-erc7730/src/render/nested.rs:392-396`) and
  `render_nested_subfields` renders only declared sub-fields
  (`display/render/mod.rs:1450-1496`).
- Concrete chain: `PermitSingle(PermitDetails details,address spender,uint256
  sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)`
  with visible fields `details.token`, `spender`, `sigDeadline` and NO `details.amount`
  field passes completeness (via `details.token`), Rule 1 (`spender` shown), Rule 2
  (`token` shown), Rule 3 (nothing hidden), and the E2 self-check — then compiles to a
  nested anchor with one sub-field. The device renders "Token / Spender / Deadline" and
  hash-binds `amount = 2^160-1` into the signed structHash, never displayed. Same gap one
  level down for v2 arrays-of-struct (`details.[].amount` omitted).
- Corpus evidence that nested omissions are routine and unflagged: the shipping source
  descriptors omit nested non-address members pervasively (lane scan: 69 omitted nested
  elementary members across ~7 registry files, incl. Permit2 `details.nonce`); those
  particular formats happen to be refused at build only because of unrelated
  hidden-uint256 Rule-3 violations (`sigDeadline`/`nonce` = `visible:"never"`), so no
  *currently compiling* descriptor exploits the gap — it fires on the next nested-format
  admission (the #405-#411/#425 campaign is admitting exactly these shapes now; HEAD
  commit 84e260c6 touched the same function for narrow-int canonicality and did not
  address member presence).
- Breaks CS5 (partial-hide) / the H-3 completeness invariant at nested granularity;
  H-3/HIGH-1 were rated HIGH for the top-level twins. Checked against inventory:
  #340/PA-S4-005 is the FormatterRoute manifest wildcard (different), #372/#346/#378/#424
  unrelated.

### S2-F19 — [BRB-2] Contract fixed-size tuple-array descent compiles with element-0-only coverage — calls[1..N-1] signed but never rendered
- **Severity:** medium
- **Evidence label:** PoC (source trace; compile not executed)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `dbgen/src/erc7730.rs:6705-6725` (`compile_structured_contract_path`): descent is
  refused only for `HeadWidth::Dynamic`; a fixed tuple array `(address to,uint256
  value)[2] calls` is `Words(4)`, so `calls.to` compiles to `[Root, FieldIdx(0),
  FieldIdx(0)]` = ABI word 0 = `calls[0].to` (device `resolve_structured` sums FieldIdx
  args — `pqsigner-erc7730/src/render/resolve.rs:78-87`).
- Both tuple-member-granularity gates test `top_ty.starts_with('(') &&
  top_ty.ends_with(')')` (`check_contract_field_completeness` :5060; Rule 2 :5460-5461) —
  the `[2]` suffix fails `ends_with(')')`, so the param falls to the whole-param branch
  where `calls.to` covers it and satisfies the address rule. Terminal multi-word rejection
  (:6675-6681) never fires because the descent ends on a scalar. The all-static framing
  gate passes; the device shows one leg's target/address and signs all legs.
- Not in known-issues; `VULN-erc7730-walker-slot-confusion` fixed head-width summation
  but left this array-descent partial-coverage case ungated. No corpus descriptor uses
  fixed tuple arrays today — latent, same build-gate threat model as BRB-1. Breaks the
  same CS5/H-3 WYSIWYS completeness invariant.

### S2-F20 — [BRB-3] resolve_field_index keccak-16 fallback silently compiles unknown path names (EIP-712 tokenPath reachable)
- **Severity:** low
- **Evidence label:** suspicion, partially verified
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`dbgen/src/erc7730.rs:7019-7023`: a path name absent from the format key is encoded as
`u16(keccak256(name)[..2])` ("Phase 5 runtime introspection" leftover) instead of a hard
error. Value paths are saved later by `rendered_path_terminal_type` (:3752), but
`compile_token_path` on EIP-712 has no such check — a bogus tokenPath compiles. On device
the aliased word index is ≥ member_count with overwhelming probability (out-of-head reject
→ documented M-4 raw-amount degradation), but with probability ≈ member_count/65536 it
aliases a real member's word and looks up token metadata for it (wrong symbol/decimals if
that word is a listed token address). The build gate should error rather than emit a
random word.

## Findings — lane BLIND-INFRA — S2-F21–S2-F26

### S2-F21 — [BLIND-INFRA-1] The F13 unsafe-ban exclude-list guard and the whole semgrep/deny/vet gate family are absent from CI steps and from the G1 manifest — the ERROR gates are silently weakenable
- **Severity:** medium
- **Evidence label:** PoC (reasoning trace, verified by reading every workflow)
- **Lane verdict:** KEEP-NOTE — same gate-enrollment under-coverage class as #195/F50 + #389, but those name only `verify-hw-assumptions`/`verify-mmio-addresses`; this candidate covers different artifacts (semgrep config, deny, vet, F13 guard) plus the undetectable YAML-weakening dimension. Kept for coordinator adjudication.
- **Overlap-check:** #195, #389
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `ci.yml:61-64` runs only `semgrep --config .semgrep/pqsigner-invariants.yml --severity
  ERROR --error` directly. The F13 guard `check_unsafe_exclude_allowlist.py` — whose sole
  purpose is to catch an over-broad `exclude:` list in `no-unsafe-in-pure-logic-crates` —
  is invoked only by the *local* `make invariant-gates` (`Makefile:3889-3890`); no
  workflow references it (grep: `invariant-gates|check_unsafe` across
  `.github/workflows/` → only the CI job *name*).
- `scripts/gate_enforcement.json` (the G1 lint that exists to catch "gate never fires")
  has no entry at all for semgrep, cargo-deny, cargo-vet, or the F13 guard (full gate id
  list dumped — only `verify-*`, kani, miri, checkct, make, prod-check-ship).
- PoC: a PR adding `- 'secure/src/'` (or any path) to the rule's `exclude:` list, or
  flipping a rule ERROR→WARNING, or deleting the `ecrecover`/`reset*` pattern, leaves
  every CI job green — the semgrep run succeeds with 0 findings and nothing else inspects
  the YAML. The unsafe-taxonomy rule has no second gate (unlike invariant #5, which
  cargo-deny backs).

### S2-F22 — [BLIND-INFRA-2] fuzz/ workspace is outside cargo-vet AND cargo-deny (322-crate lockfile, bigger than the product's), and its drift/smoke/differential test suites run in no CI job
- **Severity:** medium
- **Evidence label:** PoC
- **Lane verdict:** KEEP-NOTE — #308 tracks the thin cargo-vet audit posture (the blanket-exemption remediation target); #187/F42 is the same "suites green-when-run but in no CI job" class for FSBL/measurement suites. This candidate is the fuzz-workspace instance of both — excluded entirely from vet/deny (not just thin) and with its own unenrolled suites.
- **Overlap-check:** #308, #187
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `deny.toml:83` `exclude = ["fuzz"]`; `cargo vet --locked` (ci.yml:106) runs at the root
  only; `fuzz/Cargo.lock` has 322 packages (incl. the `revm = "41"` tree) vs 222 in the
  product lockfile. A CVE/yank/malicious crate there trips no gate; it builds inside
  ClusterFuzzLite CI and on every dev fuzz run.
- `harness_structure.rs` (the file whose own header calls orphan-target drift "the single
  highest-value negative test", and which already caught two real orphans),
  `parser_smoke.rs`, and the revm-oracle `multisend_record_walk_differential.rs` run only
  via local `make test-all` — no workflow invokes `cd fuzz && cargo test --tests` (grep
  across all 8 workflows).
- PoC: delete one `[[bin]]` from `fuzz/Cargo.toml` → `cargo fuzz list` (the only
  enumeration `build.sh`/CFLite uses) silently drops the target; parser ships with zero
  coverage-guided testing; all CI green.
- Also noted: stale comment at `fuzz/tests/harness_structure.rs:442-446` claiming the
  orphan test "is left `#[ignore]`" while it is active. (#309 tracks standing up CFLite —
  done; #359 tracks the corpus commit; #417 is the Kani census.)

### S2-F23 — [BLIND-INFRA-3] SAES driver returns from every mid-op error path with the software key still in SAES_KEYR0..7, never zeroizes its k0..k7 stack copies, and the global wipe doesn't touch the peripheral
- **Severity:** low
- **Evidence label:** PoC (source-level)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `secure/src/hw/saes.rs`: key load at 458-465; error exits at 504-509 (`KeyInvalid`),
  526-535 and 566-579 (`BusError`/`CcfTimeout`) all `return Err` *before* the exit wipe at
  602-611. A later op's `CR_IPRST` (415) is asserted-but-unverified to clear KEYR (RM0456
  semantics not checked anywhere in-repo; #246 tracks bit-field confirmation only).
- `k0..k7` (450-457) hold the full 256-bit key as u32 locals and are never zeroized, while
  the *output* scratch `d0..d3` is explicitly zeroized (614-621) — inverted priority.
  `zeroize_sensitive_state()` (`nsc/mod.rs:1297-1312`) wipes SRAM + SE caches but issues
  no SAES reset, so a panic/lock after a Software-key op leaves the key engine-resident
  until the next op or reset.
- Mitigating: today the only `KeySel::Software` caller is the boot/prodtest self-test with
  a fixed non-secret ASCII key (saes.rs:311, prodtest.rs:220) — **no secret is currently
  exposed**; this is a latent API hazard for the documented "host-compatible fallback
  path". (OP17-9/#124, SE17-5/#108, F15/#160, LCR-F4/#419 are different residue sites;
  #246 is bit-field confirmation, not key residue.)

### S2-F24 — [BLIND-INFRA-4] Prodtest button-test release-wait loops are unbounded — a welded-shorted button (the canonical factory defect) wedges the S-world handler forever, and the runner reports runner-error instead of FAIL
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

- `secure/src/nsc/prodtest.rs:587-597` (`loop { … if !still { break; }
  busy_wait_ms(POLL) }`) and 624-627 have no elapsed cap, contradicting the file's own
  "Each step has a 10 s budget" (519-529, `BUTTON_TEST_TIMEOUT_MS`). The elapsed timer
  doesn't advance during the release wait.
- Compounding: the prodtest boot branch starts SysTick but never calls `hw::iwdg::init()`
  (`main.rs:1436-1452`; playbook RT6/RT9 confirm), so nothing resets the wedged unit; the
  host runner sees only a 60 s HID timeout → `TimeoutError` → exit 2 "runner failure", not
  a unit FAIL verdict (factory-prodtest-runner.py:372-380, 879-902).
- (#140/X17-TZ2 is the prodtest pointer-validation shape; #176/F31 is IWDG coverage on
  the main boot path. The no-IWDG-in-prodtest posture is playbook-documented, but this
  concrete unbounded loop + verdict-confusion instance is not.) Breaks prodtest
  assurance-fidelity: a real factory defect is reported as harness failure.

### S2-F25 — [BLIND-INFRA-5] tools/ob-configurator wait_bsy() silently continues on timeout — proceeds to OPTSTRT/OBL_LAUNCH against a wedged flash controller
- **Severity:** low
- **Evidence label:** PoC (source)
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`tools/ob-configurator/src/main.rs:47-56`: after 10M nops it plain `return`s with no error
marker; main then writes `SECCR1=OPTSTRT` (119), waits (silently timing out again), and
fires `OBL_LAUNCH` (135). Option-byte commit state is then whatever it is; only operator
eyeballing of markers [8]/[9]/[10] catches it. The tool is not bench trivia:
`shared/src/lockdown.rs:38-70,258` and `secure/src/hw/flash.rs:51-383` cite it as the
empirical authority for option-byte bit positions/values. A silent miscommit on a ceremony
unit is exactly the class the (tracked) BOOT_LOCK inconsistency (#214) warns about, but
this continue-on-timeout defect is not listed.

### S2-F26 — [BLIND-INFRA-6] Generated PqsignerProto.sol embeds a developer's home-directory path
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP
- **Status:** 🔲 OPEN

Evidence (transcribed from the deduped candidate record):

`xtask/src/main.rs:183` bakes `// Reference:
/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md` into the AUTO-GENERATED
`contracts/smart-wallet/src/generated/PqsignerProto.sol`, which CI (ci.yml:217
`check-solidity-constants`) pins byte-for-byte — so the leak is *enforced* into every
regeneration. Dev-machine username in a shipped, on-chain-adjacent artifact; also evidence
the "pure function" render embeds non-source state.

## Per-lane verdicts

One subsection per lane — the 7 lanes of this second sweep. Each gives the
kept-findings count, what executed, and the lane's own net assessment. These
are lane-level discovery verdicts, not adjudicated outcomes.

### CAMPAIGN-CORE
6 kept / 0 dropped (CORE-1 merged with SEMEV-1) → S2-F1–S2-F6. Executed existing xtask suites (curation 5/5, diff 5/5, cli 12/12, all green); all PoCs are reasoning traces over cited code, not executed repros. Strongest: CORE-1, CORE-2 (both medium) — receipt-completeness and tool-input-binding gaps in the pinned-corpus supply chain.

### CAMPAIGN-RENDER
0 kept / 2 dropped. No WYSIWYS break reproduced in the new schema-v5 render code; both findings were instances of already-tracked items (#378, #372). Lane executed `pqsigner-erc7730 --lib` (251/251) and dbgen `erc7730_roundtrip` (36/36); integer-canonicality, TLV pairing, interpolation fail-closure, and root/count integrity all verified held.

### SEMANTIC-EVIDENCE
3 kept / 0 dropped / 1 merged (SEMEV-1 → CORE-1) → S2-F7–S2-F9. Executed both dbgen evidence suites (5/5, 19/19) plus an independent Python re-implementation of both corpus receipts that reproduced the pinned aggregates exactly. All kept items low severity (evidence-machinery honesty gaps).

### FIXBATCH
2 kept + 2 keep-note / 0 dropped → S2-F10–S2-F13. Executed `sphincs-tz-shared` tests and the full `sphincs-tz-secure --release` host suite (2262/2262 green) plus full state-machine traces of framing/transport/timeout. Nothing above low survived; no regressions of the 2026-07-19 fixes found. Theme: companion-contract drift (FIXBATCH-1/2/3) + one new plain-bool FI gate (FIXBATCH-4).

### BLIND-SE
4 kept / 0 dropped → S2-F14–S2-F17. Executed `first_boot` host tests (22/22, FakeHw seam only); otherwise exhaustive source tracing — no thumbv8m release build, no silicon. Produced the sweep's highest-severity candidate (BLIND-SE-1, high, deterministic first-boot halt) and one latent medium (BLIND-SE-2).

### BLIND-RENDER-BULK
3 kept / 0 dropped → S2-F18–S2-F20. Ran `gen-solidity-constants --check` (byte-identical) and two dbgen lib test filters (19/0, 24/0 — green, consistent with the gaps being untested); hostile-descriptor compiles NOT executed (write-nothing rule), so BRB-1/BRB-2 are static traces with corpus corroboration. BRB-1 rated high.

### BLIND-INFRA
4 kept + 2 keep-note / 0 dropped → S2-F21–S2-F26. Cheap checks only (source-level `INIT_SEQ` parse, JSON gate-id counts, grep archaeology); no builds, fuzzers, or hardware. No critical/high; the two mediums are gate-*enrollment* gaps, not logic defects (both keep-note against the #195/#389/#308/#187 tracked classes).

## Honest residual

Mandatory, per playbook convention. Aggregated across all 7 lanes from the
sweep's condensed residuals; nothing here is adjudicated.

### What survived dedupe
26 kept entries: 2 high (BLIND-SE-1 first-boot E0851 halt; BRB-1 nested-EIP-712 completeness gap), 6 medium (CORE-1/SEMEV-1 receipt escape, CORE-2 tool-input under-binding, BRB-2 tuple-array element-0 coverage, BLIND-SE-2 Case-2 APDU Le mangling, BLIND-INFRA-1 semgrep/deny/vet enrollment, BLIND-INFRA-2 fuzz-workspace exclusion — the last two keep-note), 1 low-medium (CORE-3), and the remainder low — of which only FIXBATCH-4 and BRB-3 are labeled "suspicion, unverified"; all others carry a PoC (mostly reasoning traces / doc-vs-code / source-verified constructions; none are executed end-to-end exploits). Both highs are latent-in-production-shape issues: BLIND-SE-1 fires only in the `rdp2-self-lock + dual-se` ship combo (never silicon-run), BRB-1 fires on the next nested-format corpus admission (no currently compiling descriptor exploits it).

### What was NOT looked at (union of lane residuals)
dbgen/tests internals (~3.2k added lines) beyond existence; the e2e catalogue path; the ERC-8176 checker; the 510-case transcript projection internals and the EIP-712 fixture leg; Kani harnesses, fuzz targets, and thumbv8m builds across all lanes; `erc7730_render_pure_tests.rs` (+1719) reviewed by test names only; CI workflow YAML semantics; docs-only edits in the fix batches; `shield.rs` internals (owned by OP17-2/11, F13, SE5), SCP03 KDF vectors, page-124 counter internals (#216), `store_objects`/provision AC call sites, `se050_stress`, `hw/otp.rs`; `safe/verify.rs` approveHash internals, `mgmt_decode.rs`, `multisend records_pages_total`, the 14 FormatOp dispatchers, `ir.rs`/`params.rs`/`policy.rs`/`render/enums.rs`, names/selectors bundle verifiers, `blind_sign`/`typed_call` ladder, EIP-1271/offchain display paths, corpus JSONs beyond uniswap/permit; `fw-manifest/fuzz` second workspace, `tools/sca`, `tools/sbom_firmware.py`, `tools/companion-stub`, untracked `contracts/verification/{crux,verus}/Cargo.lock` (same out-of-vet class as BLIND-INFRA-2), `.cargo/config.toml` RUSTFLAGS, NS-side APDU→SW mapping table. Offline-unverifiable trust anchors stand as recorded: block hashes/state roots, EIP-1967 slots, "two independent RPC observations" (tests assert only that two endpoint *strings* exist), explorer-bytecode and upstream commit/tree pins.

### Executed checkers vs source-only
Every lane read the full 425-line inventory and CLAUDE.md invariants. Lanes that executed existing checkers: CAMPAIGN-CORE (xtask suites), CAMPAIGN-RENDER (lib + roundtrip suites), SEMANTIC-EVIDENCE (both dbgen evidence suites + independent receipt re-computation), FIXBATCH (full secure host suite, 2262 tests), BLIND-SE (first_boot host tests), BLIND-RENDER-BULK (constants sync check + two targeted dbgen filters). Source-only with cheap scripts: BLIND-INFRA. No lane ran fuzzers, Kani, Miri, or hardware. No lane wrote files; all "PoC"s are traces/constructions, and the strongest confirmations still available are: feed dbgen the two crafted descriptors (BRB-1/BRB-2) and boot the RELEASE_FEATURES combo (BLIND-SE-1).

### Properties needing silicon/bench evidence
BLIND-SE-1 is falsifiable on silicon: the ship combo must halt at E0851 at the OPTIGA step (host tests can't reach the real `trng_salt`). BLIND-SE-2's live impact depends on real SE050 behavior toward a Case-1-form GetVersionExt. E140 SetDataObject NVM atomicity under power cut and TAMP BHKLOCK persistence (BLIND-SE residuals). AIRCR read-back has never been boot-tested on real U585 (FIXBATCH residual — CMSIS says correct, silicon is the receipt). The 5 s/30 s/120 s chain/drain bounds have no runtime tests (nonsecure not host-compilable). Whether `CR_IPRST` clears SAES_KEYR and whether KEYR is write-only (BLIND-INFRA-3 residual — RM0456 §SAES). The 20 ms SDIS hold timing and NV3007 stuck-SPI behavior (BLIND-INFRA residuals). Standing ship gates unchanged: #374 (stack bound on production feature set), #375 (physical NV3007 WYSIWYS), #376 (descriptor-authority FI).

### Regressions of the 2026-07-19 fixes: none
FIXBATCH verified the deadline-disarm invariant (`rx_start_frame.is_some() ⟺ rx_expected != 0`) on all ten drop paths, rx_expected-keyed liveness, `cmd_fw_commit` context drops, rng_strong_fold semantics (F27/#172 shape genuinely closed), AIRCR bit positions against vendored CMSIS (#132), REQUEST_UNLOCK idempotence (#148), and chain/timeout state machines (#146/#147/#165 surfaces). BLIND-SE re-encountered but did not re-report the heavily tracked SE classes (SE17/OP17/F23-F26/S-1/S-2, #114, #394).

*An executing pass may report that it reproduced no break within its recorded scope, configuration, and evidence level; it cannot establish that every covered or uncovered path is sound, that silicon matches source assumptions, or that a source-only pass executed the claimed behavior.*

## Action cross-link

Every finding in this report is filed as a GitHub issue (labels `finding`,
`priority:*`, `surface:*`); this report is the evidence record, not the
tracking surface. A coordinator decision is pending on which items the new
workflow §7b deep-gear trigger covers — the BLIND-SE pile qualifies under
trigger 2. Nothing in this report is canonical until it has been through the
Partner-A / Partner-B exact-pair cross-adjudication per
`docs/planning-and-review-workflow.md` — until then every item above remains
`🔲 OPEN` discovery evidence with no merge, shipment, hardware, or
adjudication authority.
