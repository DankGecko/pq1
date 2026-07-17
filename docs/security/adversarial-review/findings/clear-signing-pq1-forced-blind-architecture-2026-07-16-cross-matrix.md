---
report_kind: symmetric-cross-adjudication
surface: multi
workflow_stage: architecture
run_date: 2026-07-16
target_identity: "HEAD 9647b79374d5e2e10445254492308101b8be708b; binary tracked diff b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25; two expected modified docs; no untracked or ignored files"
partner_a_first_sha256: 4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c
partner_b_first_sha256: bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f
partner_a_cross_sha256: d11bf34e8b6ece6eac442ef26674ea7604c816bbc8dd50804539327f32186e70
partner_b_cross_sha256: 8f2310602fbd36f09994ed1de794c332f0bf1ea85dbd98f6dc1a0f00c6a2e193
status: complete
---

# Symmetric cross-adjudication — PQ1 ERC-7730 forced-blind architecture — 2026-07-16

> This worksheet records the adverse review of the frozen first candidate. It
> preserves evidence and disagreement; it does not authorize implementation,
> merge, shipment, risk acceptance, release, or irreversible action. Any
> materially revised candidate needs fresh mutually withheld first passes and
> symmetric cross-adjudication.

## Frozen inputs and runtime receipts

| Artifact | Partner/model/effort | Frozen path | SHA-256 |
|---|---|---|---|
| First pass A | Claude Code Opus 4.8, 1M, `ultracode`, `xhigh`, read-only | `/tmp/pq1-erc7730-partner-a-first-pass-v5.md` | `4b34ae5f1459d2d6dbfe21a1a9019235b74344cb0440aac76551efe6823a884c` |
| First pass B | OpenAI `gpt-5.6-sol`, `ultra`, read-only | `/tmp/pq1-erc7730-partner-b-first-pass-v4.md` | `bcb8a52e7dba0ecf49e651467615a9c47da2a2a0756563d4362252dde5f1110f` |
| A reviews B | Same accepted A session; counterpart cross withheld | `/tmp/pq1-erc7730-partner-a-cross-v1.md` | `d11bf34e8b6ece6eac442ef26674ea7604c816bbc8dd50804539327f32186e70` |
| B reviews A | Same accepted B session; counterpart cross withheld | `/tmp/pq1-erc7730-partner-b-cross-v1.md` | `8f2310602fbd36f09994ed1de794c332f0bf1ea85dbd98f6dc1a0f00c6a2e193` |
| A bounded response | One response to B-origin `XB-001`; no recursion | `/tmp/pq1-erc7730-partner-a-bounded-v1.md` | `d6617979ec0c877e7501c8921beb37041c03db5aef3f53732f96ab32f3311aa7` |
| B bounded response | One response to A-origin raw `XB-1`/`XB-2`; no recursion | `/tmp/pq1-erc7730-partner-b-bounded-v1.md` | `ff7eb9eab04c8090329349023da7f786e99b9dc172a171a7db3b9d90d9e746e1` |

Runtime receipts are frozen at
`/tmp/pq1-erc7730-partner-{a,b}-postlaunch-v{5,4}.txt`,
`/tmp/pq1-erc7730-partner-{a,b}-cross-{pre,post}launch-v1.txt`, and
`/tmp/pq1-erc7730-partner-{a,b}-bounded-postlaunch-v1.txt`. The B cross CLI
recorded `task_complete` before its wrapper stopped waiting; one coordinator
SIGINT then returned exit 0 and emitted the already-completed report. No report
content was reconstructed or merged.

Both first passes used three discovery lanes and personal adjudication. The
cross passes were personal source/document analysis. The only executed security
artifact during cross was the independently reproduced Bloom collision; no
build, QEMU, Kani, Miri, optimized ELF, FI campaign, hardware UI, live EAS
query, or production configuration run occurred.

## Target identity and drift checks

- Initial target: `/tmp/pq1-erc7730-arch-review-9647b79`, recursively
  non-writable, HEAD `9647b79374d5e2e10445254492308101b8be708b`.
- Expected status: modified
  `docs/erc7730-implementation-review-2026-07.md` and
  `docs/work-todo.md` only.
- Binary tracked-diff SHA-256:
  `b8e270747a5c16eafde0b74fe94f34be9ab4504d91559234fb2a1ca056d59c25`.
- Untracked and ignored inventories: empty (SHA-256 of each empty inventory
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
- Both first passes, both cross passes, and both bounded responses rechecked
  the applicable target/report identity. Final result: **MATCH / NO DRIFT**.

## Complete disposition matrix

The 27 rows below cover all 24 first-pass candidates and all three new cross
candidates. Aggregate counts are 13 `CONFIRMED`, 10 `NARROWED`, 3
`UNRESOLVED`, and 1 `REFUTED`. A coordinator did not vote through a reviewer
disagreement.

| Stable ID / raw origin | Initial claim | Partner A cross evidence | Partner B cross evidence | Cross disposition | Required correction or residual | Stage impact |
|---|---|---|---|---|---|---|
| `PA5-1` | Absent metadata, bad proof, and detected binding/CFI failure collapse to the same `None`. | **CONFIRMED** at `secure/src/nsc/cmd_sign_userop.rs:563-577`; four causes become `None`. | **CONFIRMED**; cause is destroyed in the handler before dispatch. | **CONFIRMED** | Preserve a closed handler-owned evidence type. Only an affirmative FI-protected clean-absence reason may be eligible; every FI/CFI disagreement is fatal. | Blocks architecture and later stages. |
| `PA5-2` | Broad “cannot render” eligibility contradicts the current fatal `RenderErr` doctrine. | **CONFIRMED**; `Reject`, `NoFormat`, and `PageBudget` are fatal in `dispatch.rs:211-240`; proposed exploit lever remained unverified. | **CONFIRMED**; only an explicitly owner-authorized unsupported capability could ever differ. | **CONFIRMED** | For PQ1 keep every `RenderErr`, including `NoFormat`, fatal. Any future unsupported-capability class is a separate material decision. | Blocks frozen architecture. |
| `PA5-3` | Moving a structural refusal into ordinary dispatcher data flow risks reaching generic fallbacks. | **CONFIRMED**; five refusal sites precede the generic ladder. | **NARROWED**; a typed outcome is viable only if terminally returned to the handler. | **NARROWED** | Consume eligibility immediately in a direct forced-flow return. It must never reach ERC-20, typed-call, selector-name, or generic blind dispatch. | Frozen wording blocks architecture; corrected structure remains reviewable. |
| `PA5-4` | Unlimited uncharged warning prompts and post-warning deterministic refusal create habituation. | **NARROWED**; mechanism is real, but a budget creates host-DoS/new-state trade-offs and is an owner choice. | **CONFIRMED**; preflight before warning plus a secure-side abuse control is an architecture redline. | **UNRESOLVED** | Preflight is mandatory. Exact budget/cooldown/lock policy and accepted DoS remain an explicit owner decision; no favorable architecture recommendation while unresolved. | Architecture/UX disagreement; implementation and production evidence required. |
| `PA5-5` | Companion-supplied EntryPoint is signed but neither displayed nor production-pinned. | **CONFIRMED**; wire field flows into digest and has no display use. | **CONFIRMED**; exact v0.6 pin is the conservative PQ1 correction. | **CONFIRMED** | FI-harden equality to `ENTRY_POINT_V06`, then use the firmware constant in every digest; mismatch fatal. | Implementation/merge/production gate and forced transcript invariant. |
| `PA5-6` | `e2e-test` auto-confirm cannot prove two physical consents. | **CONFIRMED** at `secure/src/ui/confirm.rs:59-65`. | **NARROWED**; it is not a shipping bypass because production fences exclude the feature, but it cannot discharge consent evidence. | **NARROWED** | Add a non-auto-confirm scripted UI/state-machine lane with cancel, idle, replay, and ordering tests; label e2e auto-confirm evidence non-authoritative for consent. | Implementation/merge assurance and production configuration gate. |
| `PA5-7` | Duplicate gas producers should simplify to one owner. | **CONFIRMED**; handler and ERC-7730 renderer both produce the page. | **CONFIRMED**; current proof shows local insertion, not global uniqueness. | **CONFIRMED** | Remove renderer emission. Handler pre-proves zero exact copies, inserts once, and independently proves exactly one canonical page globally before every confirmation. | Architecture mechanism and implementation/merge/production gate. |
| `PA5-8` | Proposed catalogue drift checks omit tuple/hash/Bloom/omission facts. | **CONFIRMED + strengthened** by the stale `NftName` opcode instance. | **CONFIRMED**; integration facts were not guarded. | **CONFIRMED** | Generate/check root, size, leaves, tuple count/SHA, Bloom occupancy, omissions, opcode/renderer semantics, and mandatory digest behavior from owned inputs. | Documentation/assurance and provenance gate. |
| `PA5-9` | Specific stale-`r0` exploit is doubtful, but two confirmations lack independently typed receipts. | **NARROWED**; direct stale-register story refuted, request binding added as missing. | **NARROWED**; honest physical separation exists, FI-independent stage authorization does not. | **NARROWED** | Separate fail-initialized warning/final slots, domain/stage tags, ordered CFI, request-digest binding, single consumption, and optimized-ELF/FI evidence. | Architecture redline; physical/FI proof is later-stage evidence. |
| `PA5-10` | Warning-button activity can extend the unlocked window. | **CONFIRMED** from `confirm.rs:81-118`, but uncorroborated in A's first cross table. | **NARROWED**; requires a physically present user and amplifies habituation rather than recreating host-only HIGH-13. | **NARROWED** | Preserve legitimate activity semantics; bound the forced flow with the owner-selected abuse/deadline policy. | UX architecture control, not an independent critical blocker. |
| `PA5-11` | A forced renderer is necessarily a second CS9 decoder. | **NARROWED**; separate renderer is acceptable with shared primitives and differential tests. | **NARROWED**; a typed raw renderer is not a second decoder if it performs no ABI/metadata walk. | **NARROWED** | Accept only canonical parsed `ForcedTranscriptInput`; structurally deny descriptor, resolver, selector-label, and ABI parsing; byte-flip every signed field. | Architecture redline and implementation/merge test gate. |
| `PB-AR-001` | Eligibility derives from ambiguous negative evidence. | **CONFIRMED**, but A narrowed B's proposed `NoFormat` member. | **NARROWED**; correction must begin in the handler and B's original eligible set was too broad. | **NARROWED** | Closed fatal-default handler evidence; PQ1 eligibility is clean structural absence plus positive filter receipt only. Bad/misbound/root/render failures are fatal. | Blocks architecture and later stages. |
| `PB-AR-002` | Bloom positivity is probabilistic, not exact registry membership. | **CONFIRMED** by independently recomputing all seven positions and observing all bits set for the non-registry tuple. | **CONFIRMED** by the executed collision witness. | **CONFIRMED** | Say `filter-positive`, never “known member”; use a positive FI-protected receipt. Exact membership would need a separate authenticated set/witness. | Architecture terminology/proof block and owner policy decision. |
| `PB-AR-003` | Two dialogs sharing one sentinel do not prove two independent authorizations. | **NARROWED**; specification gap survives while direct stale-register exploit is refuted; A disputes blocker framing. | **NARROWED**; stage-separated request-bound receipts and ordered release remain missing. | **NARROWED** | Implement distinct warning/final receipt domains or equivalently independently stage-tagged slots, separate CFI, request binding, and target evidence. Preserve the stage-impact disagreement. | Architecture redline; A says fix-now, B says blocker. |
| `PB-AR-004` | Friendly decimal formatting and omitted fields make the forced transcript non-injective. | **CONFIRMED** by source-level rounding collision and missing fee/EntryPoint fields. | **CONFIRMED**; also identified paymaster and final-digest treatment. | **CONFIRMED** | Freeze a raw fixed schema: signer, target, pinned EntryPoint, chain, value, nonce, both fees, gas triple, selector/length, paymaster state, full ERC-8213 digest, and final signing digest. | Blocks architecture and later stages. |
| `PB-AR-005` | Fatal exclusions are not exhaustive; short Safe `execTransaction` can fall through. | **CONFIRMED** at `cmd_sign_userop.rs:1105-1110`; length conjunct contradicts refusal intent. | **CONFIRMED** in single/batch routing. | **CONFIRMED** | Selector-shaped malformed Safe, all Safe/CoW/MultiSend/delegatecall, batch/off-chain, one-element batch, and every forced-ineligible mode must be classified fatal before generic dispatch. | Existing fail-closed vulnerability plus architecture/implementation/merge/production gate. |
| `PB-AR-006` | Exactly-one gas-page mechanism is underdefined. | **CONFIRMED**; current proof is prior-length-plus-one, not global uniqueness. | **CONFIRMED**; one handler owner, global content/count proof, no provenance tag required. | **CONFIRMED** | Handler-only production; independent pre/post scans and CFI completion immediately before every confirmation. | Blocks frozen mechanism; later-stage evidence required. |
| `PB-AR-007` | Lexical `drop` does not prove secure-stack reuse. | **NARROWED**; `Pages` is exactly 1,988 bytes on ARM32, overflow remains unverified. | **NARROWED**; architecture can mandate one buffer while target stack evidence moves later. | **NARROWED** | One cleared reusable `Pages` or non-inlined page-owning phases; no lexical-lifetime claim; require map/MSPLIM/high-water/exception evidence. | Construction redline; implementation/production evidence gate. |
| `PB-AR-008` | Proposed tier conflicts with current owner contracts. | **CONFIRMED**; B's owner list was more complete. | **CONFIRMED** across `CLAUDE.md`, guide, integration, CS2, root policy, and ERC-8176 status. | **CONFIRMED** | Explicitly authorize and amend owners: “Forced blind is not clear signing”; default/rollback remain refusal. Root mismatch stays fatal in PQ1. | Blocks architecture and every later stage pending owner action. |
| `PB-AS-009` | Dispatcher differential glue omits actual handler gas insertion. | **UNRESOLVED**; A found the corrected file and plausible gap but did not inspect `drive_glue` deeply enough. | **CONFIRMED** at `secure/src/display_under_test/wysiwys_dispatch_differential_tests.rs:16-23,278,294-336`. | **UNRESOLVED** | Do not vote through A's non-reproduction. Conservatively update the differential model to the complete handler page set and exact uniqueness boundary, then re-review. | Implementation/merge gate; no favorable evidence claim from current harness. |
| `PB-BR-010` | ERC-8176 readiness checker can false-green one attester against a two-attester policy. | A confirmed the one-attester mechanism but initially narrowed it after missing the policy source. | **CONFIRMED**; bounded response refuted A-origin `XB-2` with `policy.toml:15-17,35` and status `:73-88`. | **CONFIRMED** | Enforce distinct trusted attesters per descriptor at policy threshold and bind to authenticated reproducible snapshot; never authorize a production flip from advisory CLI input. | Production provenance blocker; not a forced-blind architecture blocker. |
| `PB-DOC-011` | Documentation and semantic drift guards are too narrow. | **CONFIRMED** (`NftName` is `0x04`, not guide's `0x09`). | **CONFIRMED**; also stale `nftName`, ERC-8213 comment, and obsolete `td-2`. | **CONFIRMED** | Fix claims and add semantic manifest/corpus guards. Preserve mandatory full ERC-8213 pages. | Documentation/assurance gate. |
| `PB-UX-012` | Warning fatigue is a bounded residual and a session toggle is worse. | **CONFIRMED** as a real residual; A does not make a budget mandatory and notes its DoS/state cost. | **NARROWED**; B's original “later UX” treatment was too weak and now requires preflight plus device-local abuse control. | **UNRESOLVED** | Per-request only is agreed. Exact prompt control and accepted habituation/DoS consequence need an owner decision and fresh review. | Architecture/UX policy disagreement and production usability evidence. |
| `PB-PROC-013` | B could not self-attest required backend coverage. | **NARROWED**; coordinator receipts establish the pair while self-report is not attestation. | **NARROWED**; cured for this exact pair, historical limitation retained. | **NARROWED** | Bind identities/effort from launcher/control-plane receipts; no technical finding is discarded. | No remaining architecture/merge/production impact for this pair. |
| `X-A-1` / raw `XB-1` (origin Partner A) | Partner B's first-pass citations systematically used stale/nonexistent paths. | A identified the path defect; underlying symbols largely existed elsewhere. | B bounded response **CONFIRMED** eight unique missing paths / 9 of 11 affected location blocks and supplied a complete corrigendum. | **CONFIRMED** | Canonical records use corrected paths; raw B report remains immutable and requires the corrigendum. This is not fabrication and does not reopen technical merits. | Evidence traceability/editorial gate, not a product vulnerability. |
| `X-A-2` / raw `XB-2` (origin Partner A) | PB-BR-010's two-attester premise was allegedly unsourced. | A raised the challenge after not finding the source. | B bounded response **REFUTED** it: `secure/data/erc7730/policy.toml:15-17,35` plus `docs/erc8176-attestation-status.md:73-88` explicitly bind `min_attesters = 2`. | **REFUTED** | Preserve PB-BR-010 and correct its citations. The threshold could change only through a future owner policy change. | No separate stage impact. |
| `X-B-1` / raw `XB-001` (origin Partner B) | “Single UserOp” failed to exclude deployment and slot rotation/multiple signature artifacts. | A bounded response **CONFIRMED (NARROWED)**: flags and dual Type-1/Type-2 rotation are real; current rotation already has its own consent and production companion quarantine. | B raised the source-only High architecture candidate. | **NARROWED** | Forced tier requires FI-re-read `include_init_code == false`, `register_slot == false`, and exactly one steady-state Type-2 signature. Lifecycle support is deferred to a separate design. | Sharpens the existing fatal-classifier architecture block and adds implementation/merge route tests. |

## Explicit disagreements

1. **Prompt-abuse control (`PA5-4`, `PB-UX-012`).** Partner B requires a
   device-local budget/cooldown/lock control as architecture. Partner A
   confirms the threat but treats the exact control as an owner trade-off
   because host exhaustion creates fail-closed DoS and new state. Preflight
   before warning is agreed. The policy remains unresolved.
2. **Receipt stage impact (`PB-AR-003`).** Both narrow the direct stale-`r0`
   attack and require request-bound stage receipts. B treats the missing
   mechanism as an architecture blocker; A treats it as a mandatory redline.
   No stage promotion follows either framing because other blockers remain.
3. **`NoFormat`/unsupported capability.** B left an owner-authorized
   unsupported-capability class conceptually open; A requires all existing
   `RenderErr` values to remain fatal under current doctrine. The conservative
   PQ1 redline chooses fatal for every current `RenderErr`; future expansion is
   separate and material.
4. **Differential gas glue (`PB-AS-009`).** B reproduced omission; A did not
   finish the inspection. It remains `UNRESOLVED`, with a conservative
   implementation/merge gate rather than a coordinator vote.
5. **Bloom policy.** Both prove the filter is probabilistic. Exact authenticated
   membership remains a legitimate alternative, but the recommended PQ1
   candidate explicitly says filter-positive and grants no additional
   authority beyond the stricter forced review.

## Revised stage recommendations

- Partner A: frozen architecture **NO-GO**; a materially redlined clean-absence,
  filter-positive, direct forced path could be reviewed, but implementation,
  merge, production, and irreversible action remain unavailable.
- Partner B: frozen architecture **NO-GO**; revised direction is conditionally
  viable only after owner decisions, closed redlines, and a fresh exact review.
  Implementation/merge/production are unavailable.
- Coordinator: frozen architecture **NO-GO**. Common ground supports drafting,
  not implementing, a materially revised candidate with refusal as
  default/rollback; clean absence only; filter-positive terminology; all bad,
  root-misbound, render, paymaster, lifecycle, batch/off-chain, Safe/CoW and
  fault paths fatal; fixed raw transcript; request-bound dual receipts;
  handler-only gas. The prompt policy remains unresolved. Fresh mutually
  withheld review is mandatory for the new digest.

No owner risk acceptance, merge, shipment, release, signing, flashing,
publication, OTP/option-byte/secure-element lifecycle action, or other
irreversible action is authorized by this matrix.

## Final evidence boundary

Both cross legs were source/document reviews against the frozen target. They
did not establish implementation behavior for the unimplemented tier,
optimized Thumb register/spill behavior, stack high-water or exception
headroom, physical NV3007 legibility/scroll behavior, two real consents,
fault-injection resistance, production configuration/prodtest parity,
authenticated ERC-8176 snapshots, registry/release provenance, rollback
closure, or release-key custody/distribution. Current default refusal and all
independent production blockers remain in force.
