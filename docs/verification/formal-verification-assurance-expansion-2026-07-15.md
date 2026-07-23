# Formal-verification assurance expansion and refinement research — 2026-07-15

> Assembled from the frozen 2026-07-15 review snapshot after the mandated
> mutually withheld dual review and symmetric cross-adjudication. This is
> research and planning, not authority to implement, merge, ship, mutate
> hardware, or contact external parties.

## Executive decision

PQSigner should expand formal verification, but the first increment is to make
the existing assurance system truthful and fail-closed. Adding another prover
while extraction can stay stale, EasyCrypt can skip its capstone, protocol
queries are identified only by verdict counts, and retired protocol versions
are promoted as current evidence would increase proof volume without increasing
trust.

After that closure, the highest-value new proof surface is not another crypto
primitive. It is exact proof-to-release correspondence plus the security-state
and human-intent boundaries:

1. source, model, configuration, generated artifact, binary, and release identity
   as a checked correspondence chain;
2. composable lifecycle models for durable counters/crash recovery, firmware
   rollback, and provisioning/wipe/recovery/RMA;
3. wire bytes to canonical intent to exact signed digest to trusted-display
   pages;
4. exact current firmware-manifest/update semantics and every signature-release
   route;
5. exact shipping-artifact linkage for contract bytecode, TrustZone placement,
   constant-time code, and selected fault-hardening gates.

The current Lean, Aeneas, Kani, Tamarin, ProVerif, CryptoVerif, Halmos/Kontrol,
and EasyCrypt mix is broadly sensible. New tools should enter only through
small comparison pilots with explicit stop conditions.

## Evidence boundary

This research combines:

- source and fresh host execution against the frozen PQSigner and C10/MM45
  trees;
- primary tool/project documentation and peer-reviewed papers;
- explicit inference where a technique has not been demonstrated on PQSigner.

It does not establish linked-target, silicon, physical leakage, physical fault,
factory, release, or operational evidence. A bounded search is not a universal
proof unless paired with induction or a justified completeness bound. A source
proof is not a binary proof. A binary control-flow constant-time result is not a
power/EM leakage result.

## Current assurance/verification surface: use nine rows, not eight

This is deliberately an assurance map, not a claim that every row is formal
verification. Miri, fuzzing, differential testing, and physical/tool receipts
are complementary evidence and must retain their own evidence tier.

| # | Surface | Strongest honest evidence | Main residual to close |
|---|---|---|---|
| 1 | Lean on-chain safety and SPHINCS+C verifier model | Kernel-built theorem tree, exact axiom ledger, proof mutations, external `lean4checker` replay | theorem intent, current public-claim fidelity, and model-to-shipping bridges |
| 2 | A3.1/A3.x Solidity/Yul/bytecode correspondence | Lean interpreter refinement, transcription checks, KAT/mutation evidence, Halmos/Kontrol sessions | exact source-to-deployed-bytecode R1b and durable versioned proof receipts |
| 3 | Aeneas-extracted Rust | Functional theorems and axiom closure over committed extraction; differential corpus | fail-closed current-Rust regeneration, source pins, broader construct/KAT coverage, independent signer bridge |
| 4 | Firmware Kani | 148 bounded harnesses in the reviewed snapshot | statement-strength/mutation coverage, current census, architecture-width and environment assumptions |
| 5 | Firmware Miri/unsafe | host-reachable unsafe checks | target-only unsafe/MMIO/concurrency and production configuration |
| 6 | ProVerif/Tamarin/CryptoVerif | symbolic/computational models with positive controls | exact query identity, deployed directional semantics, lifecycle/recovery composition, tool portability |
| 7 | CT/SCA/FI | source/manual binary CT and other tooling receipts | exact shipping ELF/profile, secret classification, FI model, physical TVLA/EM/laser/voltage evidence |
| 8 | Differential/fuzz | committed corpora and continuous fuzzing on selected parsers | corpus provenance/coverage and unsupported paths; no universal claim |
| 9 | EasyCrypt C10 EUF-CMA research | valuable partial reductions and arithmetic guardrails | full fail-closed dependency build, correct adaptive WOTS interface, concrete FORS/tree/scheme model, common-adversary composition |

EasyCrypt is a formal-verification surface even while it remains a research
track. Omitting it from the surface map makes its assumptions, skips, admits,
dependency state, and review provenance invisible to the G1–G5 controls.

## Priority 0: repair assurance fidelity before expanding theorem count

### P0.1 — current-source freshness and statement identity

Acceptance target:

- every generated/extracted artifact is regenerated from the exact current
  source in a clean environment, or the gate fails;
- generator, Charon/Aeneas, Rust toolchain, input-source digests, generated-file
  digests, and command line are captured in one receipt;
- Rust paths trigger the gate;
- the gate has a semantic mutation in Rust that must turn it red;
- security-policy constants and theorem statements are pinned independently of
  the implementation definition they are intended to constrain.

The committed extracted differential is useful corpus evidence, but it cannot
establish current-source freshness when neither Rust nor the vectors are
regenerated. It should remain as the independent translation/KAT layer after a
real regeneration gate is added.

### P0.2 — exact claim/artifact/version ledger

Every public claim should resolve mechanically through:

`claim ID → exact statement → theorem/query → complete assumption closure →
source/model/artifact digest → tool/version/profile → gate/trigger → mutation or
reachability witness → last dual review`.

Reject a row if the model proves V1 while the owner target is V4/V6, if prose
names canonical `userOpHash` while code/theorem uses a project-specific digest,
or if a local historical session is presented as a current standing gate.

### P0.3 — fail closed on skip and pin semantic identities

- EasyCrypt full-build mode must fail on any skipped unit or dependency and
  rebuild the upstream source closure rather than trust stale `.eco` artifacts.
- Pin EasyCrypt axiom names, full types, defining files, consumers, and concrete
  realizations—not just a count.
- Pin ProVerif query and Tamarin lemma identities plus normalized verdicts, not
  per-file counts.
- Generate the Kani census and mutation-coverage set from source; fail on stale
  manual counts.
- A gate manifest needs a completeness owner: an unenrolled formal surface must
  be a failure or an explicit, reviewed local-only residual.

### P0.4 — durable proof receipts

For Halmos, Kontrol, EasyCrypt, Lean external checking, CryptoVerif, binary CT,
and other local/heavy gates, retain a machine-readable receipt binding:

- source, model, dependency, compiler, bytecode/ELF, and configuration digests;
- exact tool/solver versions and command line;
- query/theorem/harness identity and result;
- execution environment and evidence tier;
- start/end identity and drift result.

A prose statement that a session once passed is historical evidence, not a
replayable proof artifact.

## Priority 1: expand the property boundary

### P1.1 — composable lifecycle and durable-state models (highest value)

Build small, linked state machines with frozen interfaces rather than one
monolithic end-to-end model. Separate at least durable usage accounting,
firmware-update/rollback state, and provisioning/wipe/recovery authority; compose
only the stable cross-model invariants. Their combined scope includes:

- page-123/page-124 records, compaction, erase/program ordering, torn writes,
  corruption, ECC/error handling, reset, and reboot recovery;
- per-slot, bootstrap, off-chain, on-chain, and aggregate per-public-key usage
  counters across every signature-release route;
- A/B firmware state, pending/committed manifests, OTP/version floor, rollback,
  abort, and recovery;
- factory, transit, first boot, provisioning, SE pairing, BHK/RDP/option-byte
  transitions, and production configuration;
- wipe, seed recovery, re-pairing, key rotation, abnormal reset, and RMA;
- interrupts/exceptions/resource exhaustion that can cut a security transition.

Candidate invariants:

1. Recovery yields the old committed security state, the new committed security
   state, or fail-closed—never a security-relevant mixture.
2. No reset/power-cut trace decreases an accepted firmware version or durable
   usage count.
3. No partially provisioned or partly wiped state releases a signature or key.
4. Wipe/recovery/RMA cannot resurrect an older key, pairing, counter, or policy.
5. Every generated cryptographic signing query consumes the correct aggregate
   lifetime budget; release implies a prior durable charge; at most one release
   is associated with a charge; and the counters never decrease. A power loss
   after charging but before transport may legitimately lose capacity, so
   charged-but-unreleased attempts are allowed and explicitly accounted for.
6. Fault recovery may sacrifice availability but not authentication, rollback,
   or usage-cap safety.

Recommended split:

- TLA+ with TLC/Apalache for rapid state exploration, counterexamples, and
  inductive-invariant checking;
- Tamarin for adversarial ordering, replay, compromise timing, and authority;
- a small pure Rust transition kernel linked to code with existing Kani/Aeneas
  or a targeted Verus pilot.

[Apalache] is a symbolic bounded checker; checking all executions only up to a
bound must not be reported as an all-length proof. Its inductive-invariant path
is the relevant universal step. [PoWER, OSDI 2025] is a strong methodology for
verified persistent Rust, but its persistent-memory model must be adapted to
STM32 flash program/erase/ECC/brownout behavior rather than copied unchanged.

### P1.2 — signed intent to trusted display

Extract a pure semantic pipeline:

`wire bytes → canonical decoded intent → exact signed preimage/digest → display
page model → confirmation decision`.

Prove for every supported single, batch, deployment, rotation, Safe, CoW,
MultiSend, ERC-7730, EIP-712, and off-chain route:

- each authority/value/recipient/chain/nonce/gas/operation field displayed is
  bound to the bytes signed;
- the frozen display-policy projection exposes the fields required for an
  informed authorization decision; every deliberately excluded field is covered
  by an explicit policy rule or triggers the loud blind-sign path;
- pagination, truncation, aliases, duplicate names, dynamic offsets, trailing
  bytes, overflow, metadata lookup, and batch ordering cannot create
  show-one/sign-another behavior;
- the digest theorem uses the exact project digest actually checked by the
  deployed contract, with EntryPoint semantics stated separately.

Start with the shared pure kernels and known high-risk bindings (including CoW
owner/order UID and gas-lane disambiguation). Use mutations that alter a field
binding or hide a page and require the theorem/harness to fail. Aeneas/Lean or
Kani around an existing no-heap kernel is lower risk than a wholesale parser
rewrite.

Residuals that remain non-formal are metadata truth, pixels/panel delivery,
human comprehension, and physical confirmation hardware; those need separate
evidence.

### P1.3 — exact current firmware update and rollback

Retain V1 evidence as a named legacy/bench result only. Specify and verify the
owner-selected current format and state machine, including:

- exact domain tag/version/length/field order;
- signed bytes versus hashed bytes;
- target partition/component identity;
- rollback/version floor and A/B journal transitions;
- power cut at every erase/program/commit boundary;
- abort/retry/recovery and cross-version compatibility;
- key/authority rotation and release configuration.

The ProVerif authenticity model should use the same current message structure
at the abstraction boundary; the persistent update state belongs in the
lifecycle model, not in ProVerif alone.

### P1.4 — entropy and signing-randomness lifecycle

Model and test the assumptions around `opt_rand`, secret-keyed `R` grinding,
TRNG/KDF failure or bias, reuse, conditioning, domain separation, and failure
handling. Connect the ideal distributions used in reductions to the exact
production derivation and make every fallback or retry policy explicit. This is
especially important for the EasyCrypt FORS work: the C10 draft correctly
recognizes that shipped C10 grinds and carries `R` rather than a FORS counter,
but the conditioned ideal draw is not yet a proved refinement of the bounded
production grinder.

### P1.5 — query-budget/lifetime theorem

Compose every signature-producing path—including bootstrap, counterfactual,
off-chain, cross-chain reuse, batch, and recovery—with an aggregate
per-public-key lifetime counter. The result should state which threat curve and
which cryptographic assumption requires the cap, then prove the operational
system enforces that premise.

NIST's initial public draft of SP 800-230 is useful corroboration that lifetime
signature counts can be load-bearing proof premises: its limited-use SLH-DSA
variants include a `2^24` cap. It does not validate C10 or PQSigner's chosen
`2^16` cap.

### P1.6 — deployed directional PIN, provisioning, wipe, and recovery

Replace the symmetric PIN model with the exact deployed directional reconcile,
then add compromise-before/after provisioning, partial counter reset, wipe,
re-pairing, and recovery traces. Each correspondence premise needs a positive
existence witness and a negative mutation. Keep silicon counter behavior and
physical reset properties as explicit assumptions tied to hardware receipts.

## Priority 1: strengthen source-to-shipping span

### P1.7 — exact deployed contract bytecode and EntryPoint boundary

Continue the compositional Lean interpreter/KEVM/Kontrol route for the remaining
source-to-bytecode residual. Also state or prove the exact EntryPoint v0.6
nonce/replay boundary and the production `compute_sphincs_digest_v06` ↔
`PQSmartWallet.sphincsDigest` bridge; otherwise retain them as named cited-TCB
leaves. Do not add a generic Solidity verifier that proves another source model
while leaving solc/Yul/deployed bytecode unrelated. Bind every local proof
session to codehash, compiler, solver, harness, and deployed-bytecode receipts.

### P1.8 — selected shipping-profile binary constant-time and fault models

Run the existing checkct/BINSEC route on selected load-bearing Thumb symbols or
objects produced by the shipping compiler/profile (`opt=s`, LTO/codegen-unit
settings, features, linker script), with pinned entry points, bytes, and
secret/public classifications. First demonstrate that the analyzer semantics
cover the emitted Cortex-M33 instruction subset. Do not call this a whole
post-LTO shipping-ELF theorem while symbol extraction, relocation, or unsupported
M-profile instructions remain outside the checked artifact.

For fault resistance, prefer the existing exact-Thumb rainbow/FI route and only
add a new binary engine after a pilot demonstrates the required M-profile and
fault semantics. Bound every result to its explicit instruction-skip/data-fault
model and budget. Do not infer voltage/clock/EM/laser resistance from it.
Preserve post-LTO disassembly and physical campaigns as separate evidence.

### P1.9 — TrustZone configuration and linker-map proof

A tractable formal target is generated interval/configuration evidence, not a
whole STM32U5 semantics:

- SAU/IDAU/GTZC regions and permissions;
- linker-map placement of secrets, NSC veneers, vector tables, stacks, and
  shared buffers;
- cross-world pointer range/overflow rules and gateway contracts;
- interrupt/exception ownership;
- exact production register images and feature combinations.

Bind the generated proof facts to the exact linker map/register artifact.
Peripheral behavior, CMSE instruction semantics not modeled, and silicon
errata remain assumptions/target evidence.

## Priority 2: narrow tool pilots

| Pilot | Use only for | Value test | Stop condition |
|---|---|---|---|
| TLC, then Apalache where useful | one finite durable-counter or rollback-journal model | TLC finds concrete crash traces; Apalache adds value only for symbolic bounds or inductive-invariant checking | stop if both merely duplicate the same finite exploration or unstable design |
| Verus + PoWER methodology | one stable, pure flash-journal/page-state kernel with explicit STM32 flash assumptions | proves crash invariants and links to usable Rust with acceptable annotation cost | stop if duplicate implementation or solver/toolchain maintenance exceeds the assurance gain |
| Crux-MIR + Cryptol/SAW | one NS-pointer/parser or crypto primitive against an independently written spec | implementation diversity finds a mismatch existing Kani/Aeneas misses | stop if it merely duplicates existing bounded assertions |
| RefinedRust (deferred) | only a small pure raw-pointer helper, not CMSE/MMIO veneers | ownership/aliasing/lifetime property cannot be expressed by current host checks | do not start while CMSE ABI, volatile/MMIO semantics, or annotation cost dominate |
| Vest | fixed-buffer parser feasibility only | `no_std` output and its `alloc`/link behavior fit the shipping environment and improve canonical framing | stop if zero-allocation/runtime assumptions do not fit the firmware |
| Nanoda/Lean comparator | highest-value Lean challenge statements | a genuinely independent checker accepts the pinned export format | stop if it is not compatible with the pinned Lean format; it does not validate intent |
| Existing rainbow/FI tooling | one precisely stated one/two-fault selected-binary property | finds a final-binary path missed by source FI checks | add another engine only after an M-profile/fault-semantics feasibility proof |

Do not launch multiple Rust proof-framework migrations at once. Use one shared,
high-value comparison target and retain only a tool that provides evidence the
current stack cannot express.

## EasyCrypt and `/home/nicola/repos/c10-eufcma-port`

### What is worth preserving

The shelved work has real research value:

- batch WOTS+C and several reduction/combinatorial components are
  machine-checked;
- the DarkSide combinatorial work and FORS arithmetic guardrail expose
  parameter-sensitive assumptions;
- named games make previously informal gaps reviewable;
- past adversarial passes already found non-vacuity, memoization, target-list,
  and abstract-model defects that prose review missed.

The PQSigner vendored drafts and the external repository's `drafts/` were
byte-identical in the frozen review. The external repository additionally has
an explicitly ungated pending capstone rewire. That rewire does not close the
adaptive WOTS mismatch or the concrete scheme/tree/model gaps.

### What is not proved

- The full gate can report success while skipping the MM45-dependent WOTS,
  XMSS-MT, and SPHINCS capstone files.
- The capstone uses a batch WOTS+C game where the MM45 chain produces an
  adaptive interactive game; the development itself records that the batch
  advantage does not upper-bound the adaptive one.
- The interactive WOTS file contains an admitted first hop and lacks the
  remaining hop/full theorem.
- The FORS+C index/router model lacks important concrete range/order/pool
  invariants, and the multi scheme leaves keygen/sign/verify abstract.
- The capstone still carries major reductions as premises/free bounds and is
  not one concrete SPHINCS+C10 scheme theorem over a common adversary.
- `ITSRC10` and quantitative/random-oracle/finite-grinding bridges remain
  conditional research assumptions.
- Exact dependency revisions, source rebuilds, and stale `.eco` exclusion are
  not yet a reproducible cryptographic proof artifact.

### Conditional continuation plan

Continue only as a staged research track, not a release blocker:

1. **Reproducibility and honesty gate.** Pin repository URLs/commits, toolchain,
   solvers, dependency hashes, and container/environment; rebuild every source
   dependency; fail on skip/admit/stale cache; pin axiom identities/types and
   add inconsistency mutations.
2. **C10 representability stop/go gate.** Demonstrate that the imported WOTS
   foundation can express shipped `w=8`, `log2_w=3`, `l=43`, target-sum
   grinding, and the no-standard-checksum encoding without an effectively new
   foundational proof. Demonstrate that the conditioned fresh-`R`, no-FORS-
   counter model refines the shipped bounded `R` grinder and signature layout.
   Stop and preserve the work if either requires a foundational rewrite that
   does not retire a named trusted assumption.
3. **Concrete WOTS+C10 and adaptive interface.** Instantiate parameters,
   serialization/address embedding/target count, bounded-grind tail, and exact
   adversary well-formedness; close both adaptive hops and the full interactive
   D.1 theorem that MM45 consumes.
4. **Concrete FORS+C10 model.** Define exact `g` range/order/instance mapping,
   pool sizes, conditioned key/randomizer distribution, keygen, signer, and
   verifier; eliminate unchecked `nth witness` paths or prove their bounds;
   connect bounded production grinding to the ideal distribution.
5. **Tree reductions.** Refactor the keygen/coupling model needed to prove the
   OpenPRE/TCR/root-compression legs over the concrete scheme.
6. **Common-adversary capstone.** Instantiate the actual SPHINCS+C10 scheme and
   compose the adaptive WOTS, FORS, XMSS-MT, and FX terms without free
   probability placeholders.
7. **Optional direct `ITSRC10` work.** Only after stages 1–6, decide whether the
   original ROM/binomial reduction is worth its cost; retain it as a named
   assumption otherwise.

At each stage require a negative control and an independent expert review.
Stop and preserve the repository if a stage does not materially reduce a
claim's trusted assumptions. The remaining program is several expert-months
and can plausibly reach person-year scale; presenting it as a nearly finished
capstone would be misleading. Its payoff is stronger cryptographic-assumption
assurance, not a stronger substantive `theft_free` safety conjunct.

## Explicit no-go items

- A wholesale firmware rewrite in Verus, Creusot, RefinedRust, Vest, Jasmin, or
  another proof-oriented language.
- Treating whole Cortex-M33/TrustZone/STM32U5 binary verification as a near-term
  deliverable.
- Treating Alive2 as Rust-source-to-shipping-ARM correspondence.
- Treating bounded Apalache/Kani/KEVM/BINSEC results as universal without an
  induction/completeness argument.
- Treating binary constant-time as physical SCA resistance.
- Treating EasyCrypt file compilation, arithmetic margins, or a capstone with
  admitted/free premises as a full C10 EUF-CMA proof.
- Treating a second Lean checker, mutation score, KAT, or LLM review as evidence
  that the theorem states the intended real-world property.
- Adding another Solidity source verifier while leaving the exact deployed
  bytecode bridge open.
- Formalizing unstable lifecycle/production decisions before their authority
  owner freezes the transition semantics.

## Primary sources

- Lean proof validation and independent checking: [Lean reference — Validating
  Proofs](https://lean-lang.org/doc/reference/latest/ValidatingProofs/), [Lean
  comparator/Nanoda](https://github.com/leanprover/comparator).
- Aeneas scope and translation approach: [Aeneas repository](https://github.com/AeneasVerif/aeneas).
- Persistent Rust methodology: [PoWER, OSDI 2025](https://www.usenix.org/conference/osdi25/presentation/leblanc),
  [verified-storage artifact](https://github.com/microsoft/verified-storage).
- Symbolic bounded/inductive state checking: [Apalache documentation](https://apalache-mc.org/).
- Unbounded symbolic protocol reasoning: [Tamarin manual](https://tamarin-prover.com/manual/master/book/001_introduction.html),
  [property specification](https://tamarin-prover.com/manual/master/book/007_property-specification.html).
- Binary relational analysis: [BINSEC](https://binsec.github.io/),
  [BINSEC/Rel](https://binsec.github.io/nutshells/sp-20.html).
- Rust verification pilots: [Verus](https://github.com/verus-lang/verus),
  [Verus guide](https://verus-lang.github.io/verus/guide/overview.html),
  [RefinedRust](https://plv.mpi-sws.org/refinedrust/),
  [Crux](https://github.com/GaloisInc/crux), [SAW](https://tools.galois.com/saw).
- Parser-generation pilot: [Vest, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/cai-yi).
- EasyCrypt and C10 foundations: [EasyCrypt](https://easycrypt.gitlab.io/easycrypt-web/),
  [formal SPHINCS+ proof, ePrint 2024/910](https://eprint.iacr.org/2024/910.pdf),
  [SPHINCS+C, ePrint 2022/778](https://eprint.iacr.org/2022/778.pdf).
- Lifetime-use corroboration (not C10 validation): [NIST Initial Public Draft SP
  800-230](https://csrc.nist.gov/pubs/sp/800/230/ipd).

[Apalache]: https://apalache-mc.org/
[PoWER, OSDI 2025]: https://www.usenix.org/conference/osdi25/presentation/leblanc
