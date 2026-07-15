---
surface: fv
run_date: 2026-07-15
reviewer_role: supplemental
reviewer_identity: "Codex coordinator synthesis of Claude Code Opus 4.8 and GPT-5.6 SOL"
effort: "executing full-stack review plus required mutually withheld first passes and symmetric cross-adjudication"
backend: "Codex CLI 0.144.4; Claude Code 2.1.209; Lean 4/Aeneas/EasyCrypt/protocol repository toolchains named below"
scope: "Nine-surface FV/assurance stack; theorem intent, source correspondence, closure/gate integrity, claim fidelity, missing surfaces, and c10-eufcma-port continuation"
stage: multi-stage
frozen_identity: "sha256:ad0de135a1f043d31bf7f9d73648ad813f9a45ed42192a5bb0b59fc20b9be3d0"
status: open
---

# Formal-verification full-stack adversarial review — coordinator synthesis — 2026-07-15

## Summary

The core Lean theorem tree still kernel-checks, and this review did **not**
establish a deployed signing mismatch, current-Rust Merkle acceptance defect,
wallet bypass, rogue axiom in the restored tree, cryptographic forgery, or
hardware/release failure. It did establish serious defects in the assurance
system around those proofs: current Rust can diverge from committed extraction
without turning the advertised gates red; a headline extracted theorem proves
the tooling `compute_user_op_hash` rather than the digest the firmware signs;
the extracted closure gate accepts a consumed arbitrary `False` axiom; protocol
and EasyCrypt drivers can turn failed or incomplete work into success; and the
imported EasyCrypt WOTS theorem cannot instantiate shipped C10 parameters.

The calibrated conclusion is therefore:

- **kernel/model architecture:** individual scoped results remain usable under
  their recorded assumptions;
- **current end-to-end assurance promotion:** **NO-GO** until the correspondence
  and gate-integrity findings below close;
- **merge:** unavailable—there was no implementation candidate;
- **production shipment:** unavailable/no authority, with independent project
  fences still open.

This is a documentation and research result. No Lean, Rust, Solidity,
EasyCrypt, model, gate, workflow, or build implementation was changed.

## Reviewer and frozen-target receipt

- **Partner A first pass:** Claude Code Opus 4.8, `max` effort (the workflow's
  `ultracode` label is unavailable in Claude Code 2.1.209),
  [`partner-a-first-pass`](./fv-full-stack-2026-07-15-partner-a-first-pass.md),
  SHA-256 `5afe1f48de1847281bdbb3e10e5ce2f9e18e4faff95c34599a1c755be19722f8`.
- **Partner B first pass:** GPT-5.6 SOL, `ultra`, Codex CLI 0.144.4,
  [`partner-b-first-pass`](./fv-full-stack-2026-07-15-partner-b-first-pass.md),
  SHA-256 `9b8a4264ee8430075466ab43e60904496408df67e0563d16a48906b2eb8e9cef`.
- **Partner A symmetric cross:**
  [`partner-a-cross`](./fv-full-stack-2026-07-15-partner-a-cross.md), SHA-256
  `339c2d98bad1b5198e7fcdeef42961c94b23f4fb1024868571fcdfeb472a89e1`.
- **Partner B symmetric cross:**
  [`partner-b-cross`](./fv-full-stack-2026-07-15-partner-b-cross.md), SHA-256
  `ac2ed51b2c386f80237819e8ebed2d83b615b5ef289b21d4a35c21e45763fb27`.
- **Neutral packet:** SHA-256
  `74f9716f744dbab0d376096a05fc75db28e008d389ff2ddb749df8e1c54ead82`.
  The first passes were mutually withheld.
- **Cross packet:** SHA-256
  `cf2bdc6c1e911019155c007f9a34c8f275fc109f4c7ea7a31aa20cbbfef49972`.
  It included both frozen first passes and the same supplemental evidence for
  both reviewers.
- **Primary target:** branch `fix/sweep-2026-07-14-findings`, HEAD
  `ddc7cefc35cb54e324dac94330c6ee86f9383c90`, tracked-diff SHA-256
  `6d9a66f6832ce47fa20762480433349ff0b2b9831e9adb2991199ff3278422a4`,
  status SHA-256
  `d1b72a5c68dc2488479f847e1c20eab770b1b545fba81e23eaeaaa169a9589cd`.
- **EasyCrypt targets:** `c10-eufcma-port` HEAD
  `70974e90723153a0af151626b5921dd33a025773`; MM45 SPHINCS+ HEAD
  `a28e4c53897a4bb57b575a177225862d48f824b7`; MM45 XMSS HEAD
  `fa90ebc250be32262bf88f9bcf7b9375dc04dc11`. The corrected MM45
  SPHINCS+ tracked-diff digest is
  `7b019433601404906510abf06771c837c88c6aa6bd9d85282429021231f3bdf3`;
  an earlier packet value was a transcription error, not target drift.
- **Drift:** both reviewers reported no drift in their read-only targets. The
  separately frozen copies remained unchanged through adjudication. Repository
  cataloguing occurred only afterward and is recorded in the separate receipt.

One Opus cross attempt ended with `API Error: Connection closed mid-response`.
Its invalid JSON receipt is retained outside the reviewed tree with SHA-256
`86d662c02d8d4f9455872da3654942a4146a91b63e219570a886b52c620a457d`;
it contributed no conclusions. The successful replacement used the unchanged
cross packet and is the Partner A cross report above.

## Commands, environment, and evidence level

| Command / inspection | Result | Evidence level | Executed? |
|---|---|---|---|
| `make verify-build`, `verify-audit`, `verify-ledger-consistency`, `verify-fv-lints` | PASS; 17 declared axioms, 18 closures, 5 signature pins, 5 witnesses | host/kernel + repository gates | RUN on frozen execution copy |
| `make verify-proof-mutation` | PASS 8/8 default mutations | mutation evidence for its enrolled claims | RUN |
| `make verify-extracted`, `verify-extract-differential` | PASS; six signed-preimage and 55 decimal vectors | committed-artifact build/corpus only | RUN |
| focused current Tx-Merkle regeneration | FAIL in Aeneas; committed model retains older semantics | source/extraction freshness negative | RUN; log SHA-256 `d0abb9ad7695b361bc0ef64abb7b4318d2769271ac1fa1617f6a193380947ff9` |
| arbitrary extracted-axiom canary | both extracted and FV-lint targets stayed green with a consumed `False` axiom | mutation-verified gate defect | RUN; log SHA-256 `3ea1e0d4330317294a46d1f38a38f39223a25ea339d5eedfd8dcc70a2c979362` |
| independent `lean4checker` replay | exit 0; all 58 modules accepted | independent kernel/environment replay, not project closure policy | RUN |
| ProVerif/Tamarin/CryptoVerif unmodified models | PASS; CryptoVerif required the installed `bin/default` library path | host model execution | RUN |
| protocol exit-42 and same-count tautology negatives | both accepted by the family driver | mutation-verified driver defect | RUN |
| EasyCrypt pins/margin | PASS; eight axioms, two admitted files; 130.6-bit query work factor; about `2^-2.6` at `q_h=2^128` | arithmetic/ledger evidence, not a reduction | RUN |
| EasyCrypt full wrapper against corrected frozen root | exit 0 after compiling 10/21 and skipping 11/21 | mutation/provenance evidence | RUN; log SHA-256 `367ff8c538e898386ee7fef749d9cf6b60808d5449d6d2a151a41581cfed9056` |
| Kani source census and mutation-manifest census | 148 harnesses/25 files; 140 harnesses/19 files in mutation-enrolled files; eight harnesses/six files outside; 28/31 groups default/nightly, three full-only | source census, not a fresh full Kani campaign | RUN as deterministic census; Kani proofs not rerun |
| LeanLoop mutation/vetting | seven of 17 FW-domain-tag theorem mutants survived; an unsolved-goal error was classified `NEGATION PROVED` | tool-validation negative | RUN in scratch; no PQ proof claim promoted |

## Stage recommendations

| Stage | Recommendation | Evidence and remaining gate |
|---|---|---|
| Architecture / theorem decomposition | **APPROVE WITH RED-LINES for the scoped kernel/model results** | No V-class inconsistency was reproduced in `theft_free`; do not extend that result to current source, shipping artifacts, or concrete C10 cryptographic evidence. |
| Implementation evidence / current assurance | **NO-GO for promotion** | F1–F7 below break freshness, exact-property, closure, protocol, or EasyCrypt truthfulness. |
| Merge | **Unavailable** | No implementation or PR candidate was reviewed. |
| Production shipment | **NO-GO / no authority** | This source-and-host pass has no binary, silicon, release, custody, or distribution authority; independent ship fences remain. |

## Findings

### F1 — Current Rust can diverge from committed extraction while extraction gates stay green

- **Status:** 🔲 OPEN
- **Mode / severity:** V9/G1 · **HIGH assurance-correspondence**
- **Location:** `contracts/verification/extracted/Extracted/TxMerkleSpec.lean`,
  `sphincs-c10/src/merkle.rs`, extraction Make targets and workflow triggers.
- **Mechanism:** the green gates build and compare committed artifacts; they do
  not require deterministic regeneration from every mirrored current Rust
  source. The current Merkle implementation added checked multiplication and
  residual-index rejection, while the committed extracted theorem proves the
  older behavior.
- **Consequence:** a real theorem can be correct about an old implementation
  while being reported as current evidence. Current Rust is stricter here, so
  no product acceptance bypass was demonstrated.
- **PoC:** depth-one index `2` aliases index `0` in the old extracted behavior
  but current Rust rejects it; focused regeneration fails. Independently,
  changing the live FW manifest tag from V1 to V2 leaves both advertised
  extraction gates green.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW**.
- **Dedup:** reopens the claimed closure of `ADVERSARIAL_REVIEW_2026-07-02`
  extracted findings F1/F3.
- **Required correction:** total source-symbol→generated-file→theorem registry;
  pinned clean regeneration; source/tool/output receipts; every mirrored path
  triggers it; Rust-only semantic mutations must fail.

### F2 — The extracted firmware↔chain headline proves the tooling hash, not the digest signed

- **Status:** 🔲 OPEN
- **Mode / severity:** V9/V11 · **HIGH assurance / no demonstrated implementation mismatch**
- **Location:** `UserOpEquivByteLayout.lean::compute_user_op_hash_spec`,
  `aa/src/userop.rs::{compute_user_op_hash,compute_sphincs_digest_v06}`,
  `secure/src/nsc/cmd_sign_userop.rs`, `PQSmartWallet.sol::sphincsDigest`.
- **Mechanism:** the extracted theorem labels `compute_user_op_hash`—the
  EntryPoint-style double-keccak tooling helper—as the firmware side. The
  signing path instead signs `compute_sphincs_digest_v06`, which the contract
  recomputes with SHA-256.
- **Consequence:** the advertised machine-checked production correspondence is
  missing. A Rust/Solidity vector and the handwritten Lean wallet model agree,
  so this is a wrong-property/missing-universal-bridge defect, not evidence that
  deployed implementations disagree.
- **PoC:** caller and preimage trace; the two functions have different hash
  constructions and layouts, and the proven helper has no production signing
  caller.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW**.
- **Required correction:** relabel the existing theorem tooling-only; extract
  the actual digest plus parser-to-signing-argument flow; connect exact Rust,
  Lean, and Solidity layouts; require per-field mutations and current-source
  freshness negatives.

### F3 — Extracted theorem gates accept a consumed arbitrary project axiom

- **Status:** 🔲 OPEN
- **Mode / severity:** V5/V7/G1/G4 · **HIGH gate integrity, scoped away from the strict `theft_free` closure**
- **Location:** extracted and decimal/audit gate recipes; their `sorryAx`-only
  checks versus the stricter Claim-4 closure allowlist.
- **Mechanism:** kernel replay correctly accepts declared axioms. The affected
  project gates reject `sorryAx` but do not apply an exact project-axiom policy
  to each advertised extracted theorem.
- **Consequence:** an extracted correspondence theorem can silently become
  conditional on any new proposition while still receiving a green result.
  The separate strict `theft_free` closure allowlist prevented this PoC from
  reaching the flagship safety theorem.
- **PoC:** add and consume `axiom unmodeled_assumption_canary : False`; both
  extracted and FV-lint targets return success and print the new dependency.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW**.
- **Required correction:** exact per-headline closure identities and
  cardinalities; declaration inventory; fail missing/duplicate/zero records;
  permanent `axiom Evil : False` negative. Relabel lean4checker as independent
  kernel/environment replay, not closure authorization.

### F4 — Legacy V1 firmware evidence is promoted as current while V4 and V6 owners conflict

- **Status:** 🔲 OPEN
- **Mode / severity:** G2/G3/V9/V11 · **MED**
- **Location:** assurance case G10, threat/claim map, `CLAUDE.md`, firmware
  adversarial playbook, Draft 1.1 architecture, and work-todo.
- **Mechanism:** the theorem is explicitly about `PQFW_V1`/75 bytes, but a live
  assurance row presents it as new/current. Historical V4/80-byte normative
  text conflicts with the more-specific V6/121-byte research candidate, which
  grants no implementation authority.
- **Consequence:** current update coverage is overstated. The production update
  backend is already fenced, so no deployed downgrade path was established.
- **PoC:** exact tags, lengths, and status labels disagree across the named
  owner documents.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW for claim truth;
  DEFER new proof until owner decision**.
- **Required correction:** label every V1 theorem/row LEGACY/NONSHIPPING. Do not
  select V4 or V6 silently; owner reconciliation must precede a new exact
  tag/version/length/field/state theorem.

### F5 — EasyCrypt “full verification” succeeds on a partial build and count-only axiom pins

- **Status:** 🔲 OPEN
- **Mode / severity:** G1/G2/G4/V5/V7 · **HIGH assurance-gate integrity**
- **Location:** `contracts/verification/scripts/check_easycrypt.sh`, EasyCrypt
  README/provenance, and `scripts/gate_enforcement.json`.
- **Mechanism:** missing MM45 dependencies become skips; full success can mean
  10/21 compiled. Prebuilt dependency artifacts lack causal source/toolchain
  attestation. The pin checks aggregate axiom count rather than normalized name
  and full type. EasyCrypt is absent from the enforcement manifest.
- **Consequence:** incomplete or materially changed assumptions can be reported
  as a successful full proof run.
- **PoC:** corrected frozen-root run exits 0 with 11 skips; replacing
  `dmkey_ll : is_lossless dmkey` by `dmkey_ll : false` preserves the count and
  stays green. The earlier `MM45_ROOT` receipt variable was inert; the corrected
  rerun closes that provenance limb but confirms the defect.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW**.
- **Required correction:** distinct partial/full targets; full means exactly
  21/21, zero skips, source-built or causally attested dependencies, exact
  tool/dependency hashes, semantic axiom/admit pins, negative controls, and
  explicit enforcement enrollment.

### F6 — Imported EasyCrypt WOTS results cannot instantiate shipped C10; capstone remains conditional

- **Status:** 🔲 OPEN
- **Mode / severity:** V8/V9/V11/G5 · **MED while honestly research-only; HIGH if promoted as concrete C10 evidence**
- **Location:** MM45 `WOTS_TW_ES.ec`, C10 `params.rs`, WOTS/FORS/capstone drafts.
- **Mechanism:** MM45 restricts `log2_w` to `{2,4,8}` and uses standard checksum
  WOTS. C10 uses `w=8`, `log2_w=3`, 43 checksum-free target-sum chains. No legal
  current instantiation exists. The top file also composes conditional/free
  probability terms without one concrete C10 scheme/common adversary.
- **Consequence:** local reductions may be internally useful but are not a
  concrete C10 EUF-CMA theorem. This does not falsify MM45 or C10 and does not
  enter the substantive `theft_free` safety conjunct; A5 remains cited-TCB.
- **PoC:** parameter-domain contradiction plus checksum/chain-count mismatch;
  the capstone remains unchanged when C10-specific FORS files are absent.
- **Disposition / classification:** CONFIRMED gap · **OPEN RESEARCH**.
- **Required correction:** apply the staged EasyCrypt stop/go decision below;
  do not resume abstract capstone work before a C10 representability result.

### F7 — Protocol-model driver ignores subprocess failure and pins verdict counts, not query meaning

- **Status:** 🔲 OPEN
- **Mode / severity:** G1/G4/V2/V11 · **MED**
- **Location:** `scripts/check_protocol_models.py` and CryptoVerif launcher.
- **Mechanism:** combined stdout/stderr is parsed without checking the child
  return code; family gates compare counts/text tokens, allowing same-count
  semantic substitution. The canonical CryptoVerif path assumes
  `libexec/default` while the installed supported layout used `bin/default`.
- **Consequence:** a failed prover or tautological replacement can receive the
  same success banner. The unmodified models themselves passed and were not
  thereby falsified.
- **PoC:** a synthetic exit 42 emitting expected text passes all families; an
  `Install ⇒ Sign` query changed to `Install ⇒ Install` passes with the same
  count.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW**.
- **Dedup:** reopens/extends protocol PM-2 and query-body count-only residuals.
- **Required correction:** preserve and require zero exit; avoid status-masking
  pipelines; pin normalized query/lemma identities and results; fail missing or
  duplicate results; test both documented CryptoVerif layouts.

### F8 — Evidence registries and checker labels are deletion-tolerant or stale

- **Status:** 🔲 OPEN
- **Mode / severity:** G1/G2/G3/G4 · **MED**
- **Location:** ledger consistency, surface map, provenance, claim counts, and
  LeanLoop configuration.
- **Mechanism:** checks iterate declared collections, so deleting an entire
  required collection can pass. Narratives retain historical counts. Kernel
  replay is described as exact closure. The LeanLoop whitelist/config no longer
  matches live closures and has no configured KAT section.
- **Consequence:** missing proof/evidence rows and stale scope can look
  complete. Flagship closure has a separate hard pin, which narrows impact.
- **PoC:** empty witness collection validates; live checker replay is 58 modules
  while prose says 55; EasyCrypt is absent from the eight-row surface map.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW / SIMPLIFY**.
- **Required correction:** one required-ID registry from which counts/maps are
  generated; deletion negatives; distinguish kernel replay from authorization;
  record all nine surfaces and every indexed playbook without hard-coded stale
  prose.

### F9 — Public claim precision exceeds the exact evidence in several places

- **Status:** 🔲 OPEN
- **Mode / severity:** G2/G5/V9/V11 · **MED**
- **Location:** `THE_CLAIM.md`, assurance prose, README release policy,
  CryptoVerif header, cross-hash prose, EasyCrypt README, and stale signer docs.
- **Mechanism:** examples include calling all Kontrol bridges
  transcription-free despite concrete wrappers; calling SHA-256/keccak images
  structurally disjoint although separation is computational; describing an
  ideal full-space share theorem as deployed-equivalent; saying proof after
  release automatically applies because formats are frozen; and calling the
  now-complete Lean model signer a stub.
- **Consequence:** valid scoped results are promoted beyond their assumptions,
  artifact, or current status. No product bypass follows from these wording
  defects.
- **PoC:** direct contradiction among current source, scoped records, and the
  named prose.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW / SIMPLIFY**.
- **Required correction:** property-by-property evidence labels; explicit
  computational games/conditioned-distribution transfer; accurate signer and
  digest wording; retrospective verification must bind the exact shipped
  artifact, source, config, generated files, tools, closure, and receipt.

### F10 — LeanLoop `vet` can call an unsolved-goal error a proved negation

- **Status:** 🔲 OPEN
- **Mode / severity:** G4 · **MED**
- **Location:** external LeanLoop `spec_vet.py` error classification and PQ
  `leanloop.toml`/goal configuration.
- **Mechanism:** a failing Lean process with unsolved goals enters the RED
  `NEGATION PROVED` bucket rather than ERROR/UNRESOLVED.
- **Consequence:** an invalid adversarial spec check can be reported as strong
  negative evidence. No PQ theorem was changed or invalidated.
- **PoC:** scratch false proposition leaves unsolved goals; `vet` reports
  `NEGATION PROVED`.
- **Disposition / classification:** CONFIRMED tool defect · **FIX NOW before
  citing `vet`; external implementation deferred**.
- **Required correction:** RED only after zero exit and named declaration
  kernel acceptance; regress syntax/type/unsolved/timeout cases end-to-end;
  refresh or mark historical the PQ configuration.

### F11 — Kani mutation coverage and published census are incomplete/stale

- **Status:** 🔲 OPEN
- **Mode / severity:** G1/G3/V11 · **MED assurance coverage**
- **Location:** Kani harness inventory, mutation manifest, surface/status prose.
- **Mechanism:** source has 148 harnesses in 25 files. Mutation-enrolled files
  contain 140 harnesses in 19 files, leaving eight harnesses in six files with
  no enrolled mutation; default/nightly omits three full-only groups.
- **Consequence:** the main nightly Kani run still reaches all current
  harnesses, but anti-vacuity/statement-strength coverage is narrower than
  published and can miss future weak harnesses.
- **PoC:** deterministic source/manifest census; no fresh full Kani execution
  was claimed.
- **Disposition / classification:** CONFIRMED_REAL · **FIX NOW registry, DEFER
  broad mutation execution until higher-priority gate repairs**.
- **Dedup:** reopens the prior Kani mutation-gate scope finding; it is not a new
  current firmware behavior defect.
- **Required correction:** generated source census and load-bearing mutation or
  reviewed waiver per security-bearing harness; explicit default/full
  exclusions and receipts.

## Cross-adjudication and deduplication

Both cross reports map every first-pass item. Their factual mechanisms converge.
The main calibration differences are preserved:

- Opus rates the missing actual-digest bridge and extracted closure defect MED
  because current implementations agree by vector/inspection and the strict
  flagship closure is separate. GPT rates them HIGH because the advertised
  production correspondence/gate can prove the wrong or unauthorized property.
  The coordinator records **HIGH assurance impact with explicitly narrowed
  product consequence**.
- Both reduce the V1/current-format and proof-after-release items to MED.
- Both treat the EasyCrypt WOTS mismatch as decisive. The coordinator calls it
  MED in its honest research state and HIGH only if promoted as concrete C10
  evidence.
- Partner A's pending lean4checker premise is resolved by the completed 58/58
  run; stale count/labeling remains in F8. The inert EasyCrypt root receipt was
  corrected and rerun; it no longer survives as an independent blocker.

Mapping: A-F1→F5; A-F2→F8 (pending premise resolved); A-F3/B-F1→F4;
A-F4/B-F9→F7; A-F5/A-F6→F9; A-F7→F5 receipt correction;
B-F2→F1; B-F3→F2; B-F4→F9; B-F5/B-F13→F3/F8;
B-F6/B-F7→F6; B-F8→F5; B-F10/B-F11/B-F12→F9; B-F14→F8/F11.

Inherited items reopened rather than refiled are named in F1, F7, F9, and F11.
The disclosed adaptive-WOTS/common-adversary work is open research, not a newly
discovered product defect.

## EasyCrypt and `c10-eufcma-port` decision

**Preserve the work, pause adaptive/top-level continuation, and require a C10
representability stop/go gate.** The separate repository and vendored drafts
were byte-identical at the frozen snapshot, so the separate tree supplies no
independent evidence; retain one canonical research history.

Stages:

1. Reproducible fail-closed 21/21 build, exact dependency/tool receipts,
   semantic axiom/admit pins, stale-cache negatives.
2. C10 representability: a checksum-free WOTS theory for `w=8`, `log_w=3`,
   `l=43`, target sum 205; and a faithful conditioned fresh-`R`, bounded-grinder
   FORS model. Stop and preserve the work if either requires a foundational
   rewrite that does not retire a named trusted assumption.
3. Concrete/adaptive WOTS interface and exact address/serialization/count
   conditions.
4. Concrete FORS routing/range/pool/keygen/sign/verify model and production
   grinder transfer.
5. Tree reductions and one common-adversary concrete SPHINCS+C10 theorem.
6. Optional direct `ITSRC10` quantitative work only after stages 1–5.

Do not spend effort completing the existing abstract capstone while stage 2 is
unknown. The work is several expert-months and can reach person-year scale; it
is research value, not release credit. The FORS 130.6 figure is a query work
factor from checked arithmetic, not a proved advantage bound.

## Ranked assurance-surface expansion

The detailed sourced roadmap is
[`formal-verification-assurance-expansion-2026-07-15.md`](../../../verification/formal-verification-assurance-expansion-2026-07-15.md).
The order is:

1. assurance meta-integrity: freshness, closures, semantic identities, exits,
   skip behavior, registries, and durable receipts;
2. actual parser→`compute_sphincs_digest_v06`→Solidity digest and signed-intent
   display-policy projection;
3. release artifact/source/configuration/generated-proof correspondence;
4. composable durable generated/charged/released accounting and crash recovery;
5. owner-selected firmware update/rollback and lifecycle state models;
6. exact EntryPoint/deployed-bytecode boundary and selected TrustZone/linker /
   shipping-profile binary properties;
7. staged C10-native cryptographic reductions after representability.

Small pilots are preferred over framework migrations: TLC first and Apalache
where symbolic/invariant checking adds value; one Verus/PoWER-style pure journal
kernel; Vest or Crux only on a stable narrow target with an independent spec;
selected-symbol binary analysis only after Cortex-M33 instruction support is
demonstrated. Miri/fuzz/differential evidence remains assurance, not formal
verification.

## Honest residual

### Strong attacks that failed

- No current rogue axiom, `sorry`, false detonation, vacuous `theft_free`, or
  kernel rejection was found in the restored tree; independent replay accepted
  all 58 modules.
- Current Rust and Solidity signing-digest logic agree on the available exact
  vector, and the handwritten Lean wallet model has the same 360-byte layout.
  F2 is missing universal/current-source correspondence, not a demonstrated
  digest mismatch.
- Current Rust Tx-Merkle is stricter than the stale extraction; no current
  acceptance bypass was shown.
- Unmodified ProVerif/Tamarin/CryptoVerif models passed; F7 concerns driver
  truthfulness and model scope.
- MM45's generic theorem was not shown false and no C10 forgery was produced.

### Not executed or not reviewed

- No successful full current Aeneas regeneration, fresh full Kani campaign,
  full Halmos/Kontrol campaign, long fuzz/Miri run, full EasyCrypt 21/21 build,
  constant-time/assembly campaign, physical SCA/FI, target boot, or silicon
  experiment.
- No release candidate, ELF, reproducible release, source-to-binary theorem,
  release signature, branch-protection, key-custody, or distribution evidence.
- No hardware TRNG/SE/fuse/flash-atomicity/display-legibility claim follows from
  this source-and-host review.

### Provenance limits

The coordinator executed host/model gates and scratch mutations against isolated
copies, inspected primary source, and used two exact mutually withheld partner
passes plus symmetric cross-adjudication. Reviewers did not execute every tool;
their reports label receipt-based conclusions. The frozen snapshot included a
pre-existing dirty worktree. Cataloguing this report and its pointers is a
post-freeze repository mutation and cannot retroactively change the reviewed
identity.
