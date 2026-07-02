# A3.1 — the verifier ∀-signature ceiling: a corrected closure path

**TL;DR (2026-06-16).** The standing framing — *"the ∀-signature
`SPHINCsC10Asm.verify` ↔ spec equivalence is intractable under uninterpreted
SHA-256; closing it needs an interpreted-hash reachability engine or verified
compilation; Kontrol/KEVM does not qualify"* — is **correct about symbolic-
execution engines but incomplete about the problem.** It omits a third path that
the *upstream* SPHINCS- repo already **demonstrates**: a **deductive
interpreter-refinement proof in Lean**, which proves `∀ inputs, execModel = spec`
**without** an interpreted-hash engine, because it never does symbolic search —
the digit-branch explosion is an artifact of Halmos/KEVM (symbolic *search*),
not of the theorem. This doc records that finding, what it does and does not buy,
and the concrete remaining residuals.

This **supplements** (does not retract) `A3_1_VERIFIER_GAP.md` (the resolved
reconstruction-bug postmortem) and the scoping notes in `KONTROL_SCOPING.md` /
`THE_CLAIM.md`; see the dated note appended to `A3_1_VERIFIER_GAP.md` §"The
deeper ∀-signature ceiling".

## 1. Why symbolic engines explode (the part that's right)

`SPHINCsC10Asm.verify` branches on base-`w` digits of
`sha256(seed‖adrs‖node‖count)` (WOTS+C chain lengths, the FORS forced-zero gate,
the digit-sum target). Halmos and KEVM are symbolic-**search** engines: each
data-dependent branch *forks* the path set. With SHA-256 an uninterpreted
function, every digit is unconstrained, so the fork count is ~`8^43` — no
UF-based symbolic engine closes it. KEVM is no better: its `0x02` precompile is
the SMT-uninterpreted `Sha256raw` on symbolic input, so the digit branches fork
exactly as under Halmos (confirmed 2026-06-15). **All true.**

## 2. The omitted path: deductive interpreter-refinement (no symbolic search)

A proof assistant does not search paths — it does **induction**. Model the Yul as
an executable Lean interpreter `execVerify` and prove `∀ inputs, execVerify inputs
= Spec.verify inputs` by **induction on loop-iteration count**, with the hash as
an **opaque pure function threaded through** the per-step invariant and **never
unfolded**. The explosion never happens because:

- **Induction is on the count, not the content.** A climb of `n` steps yields an
  induction with **two** cases (base + successor), *for any* `n` — not `8^n`. The
  hash output appears only inside the per-step hypothesis; the climb induction is
  **hash-agnostic** (it only needs "the hash is a pure function of its inputs").
- **Both sides compute identically.** `execVerify` and `Spec.verify` extract the
  same digit from the same opaque hash and drive the same data-dependent loop
  bound, so they step in lockstep; the equivalence is **structural**, proved once
  per loop shape, not enumerated over digit values.
- **Branchless control flow.** Merkle sibling selection is arithmetic (address
  XOR), not an `if`; the WOTS digit-sum / FORS forced-zero guards are
  per-layer/per-tree checks, not per-digit forks.

### This is demonstrated upstream (SPHINCS- `/verity`)

The upstream repo (`/home/nicola/repos/SPHINCS-/verity`, the C10 origin) proves
exactly this shape for its C13 and SLH-DSA verifiers:

- `SphincsMinusVerifiers/Proofs.lean:12158` —
  `c13_refines_spec : ∀ pkSeed pkRoot message sig, execC13 … = verifySpec …`
  (the executable interpreter model equals the abstract spec **for all inputs**).
- The machinery: `ClimbLoop.lean:254-270` `foldLoop_invariant_cond` (induction on
  iteration count, two cases); `ClimbMemFrameMerkle.lean:56-102` (the per-step
  keccak is **bound symbolically and never evaluated** — `rfl`-bound `kv`, the
  next statement is independent of it); branchless parity at `ClimbKit.lean:74-107`.
- **For C13/Keccak the proof carries ZERO hash axioms** — Keccak is concrete
  (`C13Concrete.lean keccakWords`), so the model↔spec equivalence rests on Lean's
  logic alone (modulo the model↔bytecode bridge in §4).

So the digit explosion is *genuinely solved*, not relocated: total climb-proof
size is `O(loop count)` (~1152 steps for C13), **linear**, not exponential.

## 3. PQSigner is already part-way down this path

`contracts/verity/PQSigner/` is a **half-built interpreter-refinement scaffold**
for the C10 verifier (started 2026-05-12):

- `Verifier/{Top,Wots,Fors,Merkle,Hash,Hypertree,Address,Params}.lean` — Lean
  ports of the verifier stages, with per-phase invariants already closeable
  (length enforcement, WOTS target-sum, FORS forced-zero, branchless swap, the
  H_msg domain separator literal).
- `Verifier/Top.lean` keeps `verify_byte_equivalent_to_rust` as an **axiom**
  (the model↔code bridge, KAT-witnessed); `PQSigner/Theorems.lean` is
  `sorry`-stubbed skeleton.

The main `SphincsCVerify` project independently has the *spec-internal* ∀
refinement `verifyRefined_eq_spec : verifyYulModel = Spec.verify` closing by
`rfl` — i.e. the spec side of §2 is already done. What is missing is a **faithful
executable interpreter** of the deployed Yul and the `execModel = Spec.verify`
loop-induction proof over it.

## 4. The genuine residuals (NOT the digit explosion)

Deductive interpreter-refinement closes the ∀-signature **model↔spec** equality.
Two residuals remain — and they are the *same* ceiling the upstream hits, not the
explosion:

- **(R1) MODEL ↔ deployed bytecode.** The interpreter model is a
  hand-transcription of the Yul; relating it to the *deployed EVM bytecode* is an
  axiom in both projects (PQSigner `verify_byte_equivalent_to_rust`; upstream
  `c13_refines_byte_spec` / `MODEL-EXEC-BRIDGE`, `Proofs.lean:12250`). This is a
  transcription-TCB element — mechanically checkable by review + the existing
  three-way Rust↔Yul↔Lean differential — **not** a symbolic-search wall. Eliminating
  it entirely needs verified compilation (Verity stops at Yul; KEVM-to-spec is
  multi-person-year), which is why even the full deductive proof leaves a cited
  bridge — but a *much smaller* one (see §5). **Complementary bytecode-level
  check (SOTA 2026-06, `docs/verification/security-tooling-sota-2026-06.md` §2):** `hevm`
  equivalence (and Kontrol/KEVM) can prove the *deployed bytecode* ≡ a reference
  Solidity verifier over all inputs with SHA-256 uninterpreted — a *different*
  equivalence than model↔spec, attacking R1 from the bytecode side; it bounds the
  transcription TCB without replacing the deductive model↔spec proof. (Same
  symbolic-SHA-256 caveat applies to the verifier's crypto-heavy core; use it for
  the structural/reference equivalence, not to reason inside the hash.)
- **(R2) SHA-256 needs byte-addressed interpreter memory.** The upstream
  machinery is built for native `keccak256`. The Keccak→SHA-256 bridge is
  otherwise mechanically identical (`KeccakBridge`→`Sha256Bridge`, one
  engine swap), but the SHA-256 path uses the `0x02` precompile fed by **sub-word
  `mstore`s** that alias within a word (`Model.lean:258-275`). The upstream's
  **word-keyed** memory model cannot represent that aliasing; a faithful SHA-256
  interpreter needs a **byte-addressed** memory. This is a refactor, not a wall —
  but it is real, SHA-256-specific work that the Keccak proof never had to do.

**Framing (SOTA 2026-06 §2): A3.1 closure is one leg of a tripod, not the whole
proof.** Deductive interpreter-refinement gives *implementation correctness* (the
bytecode computes the verifier algorithm's verdict for all inputs). It does NOT
give EUF-CMA / collision-resistance (that is A5, the separate cited crypto leg,
shadowed quantitatively by `Crypto/Quantitative.lean`), and it does NOT by itself
discharge the model↔deployed-bytecode transcription fidelity (R1, the review/
differential/hevm leg). The three legs together = the full verifier assurance;
this doc is the plan for the implementation-correctness leg.

## 5. What closure would actually buy (and the corrected status)

Today A3.1's functional layer is discharged **empirically**: the deployed
bytecode is validated equal to the spec on the 10-vector KAT + ~250-mutant
near-miss corpus + an executable Rust↔Yul↔Lean differential (hard checks). The
∀-quantifier is carried by that corpus, not by proof.

A completed deductive interpreter-refinement would move the line to: the
∀-signature functional behavior is **proven** equal to the spec, and the only
empirical/cited element is the **line-by-line Yul→interpreter transcription**
(R1) — diff-checkable, far smaller than "the entire verifier semantics." That is
the real prize: it shrinks A3.1's empirical surface from *the whole functional
behavior* to *the transcription faithfulness*.

**Corrected status line:** A3.1's ∀-signature verifier↔spec equivalence is **not
fundamentally intractable.** The intractability is specific to symbolic-execution
engines (Halmos/KEVM); a deductive Lean interpreter-refinement (Verity-style,
demonstrated upstream) closes the model↔spec ∀ with the hash kept opaque and
**no** interpreted-hash engine. The standing residuals are the model↔bytecode
hand-transcription (R1, shared with upstream) and SHA-256 byte-addressed memory
(R2, SHA-256-specific) — not the digit-branch explosion.

## 6. Closure path + effort

1. **Complete the `contracts/verity/` interpreter** of `SPHINCsC10Asm.verify`
   (faithful executable Lean over a **byte-addressed** memory model — R2).
2. **Prove `execC10Asm = Spec.verify` ∀-input** by loop-induction, porting the
   upstream `ClimbLoop`/`ClimbKit`/`ClimbMemFrameMerkle` pattern (Keccak→SHA-256
   via a `Sha256Bridge`; the climb/guard/branchless machinery is hash-agnostic
   and ports unchanged). The hash stays an opaque pure function — **zero** new
   crypto axioms beyond the existing A1 (SHA-256 = FIPS-180-4).
3. **R1 stays a cited bridge** (`verify_byte_equivalent_to_rust`), now backed by
   the proven model↔spec equality + the differential — or eliminated later via
   verified compilation (multi-person-year, out of scope).

Effort for 1+2: ~3-6 months (the upstream took a comparable multi-week effort per
variant, plus the byte-addressed-memory refactor for SHA-256). It is the right
"convert tested→proven" investment for A3.1; it is **not** required for any
claim currently made (which honestly scopes A3.1 as corpus-validated).

## 7. References

- Upstream: `/home/nicola/repos/SPHINCS-/verity/SphincsMinusVerifiers/{Proofs,ClimbLoop,ClimbKit,ClimbMemFrameMerkle,ClimbKeccakStep,KeccakBridge}.lean`, `SphincsMinusVerifierSpec/{Spec,C13Concrete}.lean`, `Model.lean`, `AXIOMS.md`.
- PQSigner scaffold: `contracts/verity/PQSigner/Verifier/*.lean`.
- This repo: `A3_1_VERIFIER_GAP.md` (reconstruction postmortem), `KONTROL_SCOPING.md` (symbolic-engine scoping), `THE_CLAIM.md` (claim ledger), `MISSING_FOR_FULL_BYTECODE_PROOF.md`.

## 8. Progress

- **2026-06-16 — R2 foundation landed.** `SphincsCVerify/Interpreter/Memory.lean`
  (in the `lean/` project — same v4.22 mathlib-free home as `Spec.verify`, the
  refinement target): a **true byte-granularity** EVM memory (`Nat → UInt8`) with
  `mstore32`/`mload32`/`slice`/`staticcallSha256` and the **frame/disjointness**
  lemmas the climb proofs need (`writeRegion_frame`, `writeRegion_comm` for
  disjoint writes, `mstore32_get`/`_frame`, `staticcallSha256_get`/`_frame`,
  `writeRegion_get_of_disjoint`). It models the sub-word `mstore` aliasing
  faithfully (vs the upstream's word-valued cells + `linear_memory_aliasing`
  *assumed* obligation), so R2 is no longer an open design question. **Mathlib-free,
  kernel-only closures, NO new content axiom** (the precompile hash is a parameter;
  the concrete `Sha256Impl` wires in at the bridge). Decision recorded: build the
  C10 interpreter-refinement in the `lean/` `SphincsCVerify` project (reuses
  `Spec.verify` + `Spec.Sha256Impl`, no external Verity git dep) rather than the
  `contracts/verity/` scaffold.
- **2026-06-16 — per-step climb characterized.** `SphincsCVerify/Interpreter/Climb.lean`
  models the hash-pair step shared by every C10 climb (WOTS chain / FORS tree /
  hypertree Merkle): `hashPairStep` + `hashPair_assembled` (the precompile input is
  exactly `node‖sibling` big-endian, byte for byte), `hashPairStep_frame` (touches
  only the pair + digest windows — the locality climb-induction needs),
  `hashPairStep_out`, `slice_writeRegion_frame`. Kernel-only, mathlib-free, hash
  abstract → no axiom. So the memory layer + the per-step memory effect are now
  fully proven; the symbolic-execution digit-explosion is structurally avoided
  (the step is frame-characterized, not symbolically searched).
- **2026-06-16 — `mload32` BE round-trip DONE.** `mload32 (mstore32 mem off w) off
  = w % 2^256` (`Interpreter/Memory.lean`, `mload32_mstore32_self`) — the
  mathlib-free Horner/base-256 reassembly (proved via `split_mod_aux`
  = `Nat.mul_mod_mul_left` carry step, folded by induction; `Nat.shiftRight_add`
  / `_eq_div_pow` / `Nat.two_pow_pos`). Plus the climb capstone
  `mload32_hashPairStep` (`Interpreter/Climb.lean`): reading a step's digest back
  as a word recovers the hash word. So a climb step is now FULLY characterized at
  the word level (input-assembly + frame + digest-readback). Kernel-only, no new
  axiom. The one finicky arithmetic piece is behind us.
- **2026-06-16 — loop-induction transfer-PoC DONE.** `Interpreter/ClimbLoop.lean`:
  `climbMem_eq_specClimb` — the memory-realized climb (per step: lay the pair into
  scratch, run the `0x02` precompile, read the new node back) over an
  arbitrary-length auth path equals the pure spec fold, proved by **induction on
  path length (two cases), hash opaque, no 8ⁿ digit-branch explosion**. The C10
  analogue of verity's `foldLoop_invariant_cond`. **This answers the load-bearing
  question — "does the deductive interpreter-refinement technique transfer to C10's
  byte-addressed-SHA-256 setting?" — with a kernel-checked YES.** Kernel-only, no
  axiom. So foundation (memory) → per-step (climb, fully word-characterized) →
  loop-induction are all proven; what remains is wiring + scale, not open questions.
- **2026-06-16 — Sha256Bridge step 1: byte-array ↔ big-endian-word iso.**
  `Interpreter/Sha256Bridge.lean`: `beByte_mload32` — load a 32-byte word with
  `mload32`, extract big-endian byte `i` with `beByte`, recover the stored byte
  `mem(off+i)` (the *inverse* of `mload32_mstore32_self`; mathlib-free Horner
  positional extraction: `beNat`/`foldl_horner_acc`/`beNat_append`/`beNat_lt`/
  `beNat_getByte`). Lifted to the spec via `memOfBytes`/`wordOf` +
  `beByte_wordOf : beByte (wordOf v) i = v.get i` for `v : ByteVec 32`. Both
  results `[propext, Quot.sound]` only. **This is the representation boundary**
  between the word-threaded interpreter (`Nat`) and the byte-oriented declarative
  spec (`ByteVec 32`): `mstore32 mem off (wordOf seg)` lays down exactly `seg`'s
  bytes for the precompile, and a `mload`ed digest word maps back to a spec node.
  `verify-build` 40/40, `verify-audit` 0 sorry, `theft_free` closure unchanged.

### Landscape pinned (orientation workflow, 2026-06-16)

- **Where the axiom sits.** The verifier leg of `theft_free` is
  `Spec.verify ←(rfl) Verifier.Refined.verifyRefined ←(rfl)
  Bridge.SolidityVerifier.verifyYulModel ←(A3.1 axiom
  `solidityVerifier_compiles_correctly`) DeployedBytecode.SPHINCsC10Asm_verify
  (opaque)`. The top three layers collapse by `rfl` — `verifyYulModel` **is**
  `Spec.verify`. The *only* verifier axiom is the bottom one, equating the opaque
  deployed-bytecode symbol to `verifyYulModel`.
- **What the interpreter can / cannot do.** `DeployedBytecode.SPHINCsC10Asm_verify`
  is opaque — `solidityVerifier_compiles_correctly` is **not** provable as stated
  (nothing to compute). The verity move (their `c13_refines_spec`) is to introduce
  a *concrete* interpreter `execC10Asm`, **prove** `execC10Asm = verifyYulModel`
  (loop-induction, SHA-256 opaque), and **replace** the big axiom with a *narrower*
  `DeployedBytecode.SPHINCsC10Asm_verify = execC10Asm` (their residual
  `assembly_refinement`, `.assumed`). Net: trade one large semantic axiom
  ("bytecode = structured verifier") for one narrow transcription axiom
  ("bytecode = my opcode interpreter", = R1) + a proven refinement theorem.
- **C10's Yul is fully word-aligned** (every `mstore` at a `0x20` multiple; the
  branchless swap only lands on `0x40`/`0x60`). The byte-addressed model is a
  faithful *superset* — it closes R2 **without** verity's `.assumed`
  `linear_memory_aliasing`. Note: verity's own SHA-2 instance
  (`slhDsaSha2_128_24`) is **axiom-blocked** (`slhDsaSha2_128_24_refines_byte_spec`
  is unproven) precisely because its word-valued memory can't model SHA-2 packing —
  i.e. **we are past the upstream frontier for SHA-2, not porting a finished result.**
- **The 8 real hash sites** (`SPHINCsC10Asm.sol`, all `inOff=0x00, outOff=0x600`):
  H_msg (160 B, **unmasked**), FORS-leaf (96, masked), FORS-Merkle-pair (128,
  masked, parity swap), FORS-root-compress (480, masked), WOTS-digit (128,
  **unmasked** — full 32 B feeds base-8 digit extraction), WOTS-chain (96, masked),
  WOTS-PK-compress (1440, masked), HT-Merkle-pair (128, masked, parity swap).
  `seed` persists at `0x00` across FORS, re-set before the hypertree. **The two
  unmasked sites (H_msg, WOTS-digit) must NOT be truncated.** Padding confirmed:
  `pad16 v = v ‖ zero 16` (trailing zeros) and `truncate16 = take 16` (top/MSB 16)
  match `N_MASK` exactly, so the chained child `pad16 node = node16 ‖ zeros16` is
  byte-sound. (The current `hashPairStep`/`climbMem` are a 2-input PoC; the real
  step is 4 segments seed‖adrs‖left‖right with the parity swap + mask.)

### DECISION (2026-06-16, RESOLVED) — full-(a), executable-first

User chose **maximum correctness, time no constraint** ⇒ **full-(a)**: a scoped
Yul-statement interpreter over a C10 opcode-subset AST (verity's
`execStmt`/`evalExpr` architecture), NOT pragmatic-(a) (hand-function, eyeball
transcription) nor (b) (bespoke fn, no reduction). Rationale: only full-(a)
factors the residual into (i) reusable EVM-subset semantics + (ii) a *mechanizable*
Yul-transcription, and reuses for A3.2/A3.3/A3.4. Advisor endorsed — **conditionally**.

**THE CONDITION (advisor, load-bearing) — executable validation BEFORE phase proofs.**
The refinement proof connects `Spec.verify ↔ interpreter` (both Lean); it does
**not** check that `execStmt`+AST match the *real* EVM/Yul (both mine — a
mis-modeled `staticcall` + a compensating AST could prove `execC10Asm = Spec.verify`
while matching neither bytecode nor reality). So full-(a) is "more correct" **iff**
`execStmt`+AST are validated against ground truth. ⇒ **NEXT MILESTONE, ahead of
finishing the Sha256Bridge:** make the interpreter *executable* (real computable
`Spec.Sha256Impl` as the `0x02` oracle — execution needs NO bridge lemmas),
transcribe the **entire** Yul, and **reproduce KAT 10/10 + bulk 384/384 +
mutant/near-miss rejection THROUGH `execC10Asm`**, asserting agreement with BOTH
the spec AND the deployed-bytecode KAT results. That agreement *is* the empirical
interpreter↔bytecode bridge and gives the eventual transcription axiom the same
backing the current A3.1 axiom has. Only then prove vertically (H_msg first).

**De-risking the verity bog (advisor):** verity's residual cutpoint axioms
(`..._beforeAuthOff_wotsPk_..._cutpoint`) are all at **loop↔straight-line seams**
(re-establishing the loop invariant vs ambient state at entry/exit), never inside
loops. Mitigation: (1) prove **binding frame/locality lemmas FIRST** (distinct-var
reads/writes commute; unmentioned vars preserved) — their absence caused the grind;
(2) design each phase's pre/postcondition so the loop touches ONLY its scratch
window + accumulator (the `climbMem_eq_specClimb` discipline — nothing ambient), so
each cutpoint collapses to one clean "scratch holds X" hypothesis. Binding rep
(string-keyed-faithful vs typed) matters far less than having these frame lemmas.

**Honesty nudges (advisor, keep in docs as the artifact grows):** (1) the interpreter
models Yul **source**, not deployed bytecode — the optimizer gap remains, covered by
KAT-against-the-codehash-pinned-bytecode; keep running KATs against BOTH and assert
agreement. (2) C10's full word-alignment means the byte-addressed memory, while
strictly more faithful (no `linear_memory_aliasing` assumption — a real gain), was
**not strictly required** for C10. Honest significance = "first *completed* SHA-2
on-chain verifier refinement," NOT "byte-memory was the unlock." Do not let that
drift into overclaim.

### (historical) the (a) vs (b) fork — interpreter shape

The honesty of "narrower residual axiom" depends entirely on **how `execC10Asm` is
structured** (advisor, 2026-06-16):

- **(a) interpreter over a faithful Yul-statement representation** (verity's
  `execStmtList`/`evalExpr` over an AST that visibly mirrors `SPHINCsC10Asm.sol`).
  Then `DeployedBytecode = execC10Asm` is a *mechanical opcode-by-opcode*
  transcription check — **a real trust-base reduction** (R1-only residual). The
  climb lemmas (`hashPairStep`/`climbMem`/`Sha256Bridge`) become loop-body
  refinement lemmas *underneath* the statement-interpreter.
- **(b) bespoke byte-memory Lean function** (what `climbMem` currently is). Still
  provably `= Spec.verify`, but the residual axiom `DeployedBytecode = execC10Asm`
  is **no narrower than today's** — it's a second independent deductive ∀-model
  (defense-in-depth), **not** a trust-base reduction.

The current building blocks are shaped like (b). **This fork must be settled before
committing to the top-level `execC10Asm` shape** — under (a), the climb lemmas must
be wired as lemmas, not as the top-level def. A *pragmatic-(a)* middle path: write
`execC10Asm` in deliberately Yul-mirroring straight-line style (one Lean line per
Yul statement, loops as `foldLoop` mirroring the Yul `for`), so the transcription
axiom is a line-by-line visual check (as narrow as verity's `assembly_refinement`),
with the climb lemmas as the loop-refinement engine.

- **2026-06-16 — EXECUTABLE-VALIDATION MILESTONE DONE (steps 1–3). The advisor's
  load-bearing condition is satisfied.** Three modules + a runner:
  * `Interpreter/Yul.lean` — the executable, mathlib-free Yul-subset interpreter
    (AST + faithful EVM word semantics mod 2^256, two's-comp sub, Yul shl/shr
    operand order, bitwise ops; `ByteMemory`; calldata via `loadWord32`;
    precompile ORACLE param; `ifnz`/`forRange`=fold/`block`/`revert`/`ret` with
    short-circuit halt; `revert`→false, `ret`→`mem[0x00]==1`). 16 `#guard`
    smoke-tests; all total computable. EVM semantics reviewed line-by-line.
  * `Interpreter/C10Program.lean` — `c10Program : List Stmt`, the ENTIRE deployed
    `SPHINCsC10Asm.sol` Yul transcribed statement-for-statement (inline `-- L<n>`
    source refs; masks copied verbatim), + `execC10Asm` running it under the real
    computable `Spec.Sha256Impl` oracle (no new axiom).
  * `InterpMain.lean` + `make verify-interp` (`lake exe verify-interp`) — replays
    the KAT + bulk corpus THROUGH `execC10Asm`. **RESULT: `execC10Asm` reproduces
    `Spec.Signature.verify` AND the Rust-oracle `expectValid` verdict on
    ALL 12 KAT (4 valid + 6 negatives + NM1/NM2 near-miss) + 384 bulk = 396/396
    (NB corrected 2026-07-02: the `expectValid` field is the RUST-signer verdict,
    so this leg is interpreter-vs-Rust-oracle — NOT interpreter-vs-deployed-bytecode;
    and the `==Spec.verify` leg is now a consistency corollary of the proven
    `execC10Asm_eq` on the N-masked corpus. The bytecode ground-truth for A3.1 is
    `verify-test-vectors` (forge KAT) + the ~250-mutant screen, not this runner)
    on BOTH checks.** HARD CHECK (non-zero exit on any mismatch). This empirically
    pins (i) AST-transcription faithfulness and (ii) `execStmt`↔EVM semantics
    against ground truth, and is the empirical interpreter↔bytecode bridge that
    makes the upcoming `execC10Asm = verifyYulModel` a genuine trust-base
    reduction. `verify-build` green (43/43), `verify-audit` 0-sorry, `theft_free`
    closure UNCHANGED (the interpreter modules are leaves).

- **UPDATE 2026-07-02 — STEPS 5 & 6 LANDED; this progress log below is SUPERSEDED.**
  The entries below (dated ≤ 2026-06-17) say the proof phase is "well underway" and
  step 6 is "USER-GATED / keep the old axiom in place" — **both are stale.** The
  grand composition landed **2026-06-18** and is now the shipped state, confirmed by
  a live `#print axioms` probe (2026-07-02):
  - `Interpreter.C10.execC10Asm_eq` (`C10Refine.lean:414`) is a COMPLETE kernel proof
    for **all** 4008-byte signatures — `execC10Asm = nMaskedB pkSeed && nMaskedB pkRoot
    && verifyYulModel` — with closure **exactly `[propext, Classical.choice, Quot.sound]`**
    (no `sorry`, no bytecode axiom on this leg). So the **model↔spec ∀-signature
    equivalence — the part historically flagged "intractable" — is DEDUCTIVELY CLOSED**,
    hash kept opaque, no symbolic engine.
  - Step 6 is done, not user-gated: the axiom was swapped to `= execC10Asm`
    (`Bridge/Refinement.lean:202`), `deployedVerifier := execC10Asm`
    (`Bridge/EntryPoint.lean:82`), and **`theft_free` already threads it** via
    `deployed_verifier_refines_spec` (`Refinement.lean:484` = the R1 axiom `.trans
    execC10Asm_eq`). `#print axioms deployed_verifier_refines_spec` = kernel triple +
    `solidityVerifier_compiles_correctly` only.
  - **R2 (SHA-256 byte-addressed-memory bridge) is CLOSED** (`Sha256Bridge.lean`
    `beByte_mload32`/`slice_toArray_eq_flatten`, all `theorem`) — not an open design
    question. **`contracts/verity/` is a DEAD scaffold** (pins an unlanded Verity
    version); the proof was done in `lean/SphincsCVerify/Interpreter/`, not there.
  - **The sole remaining A3.1 residual is R1** — the deployed-bytecode ↔ hand-
    transcribed-AST (`c10Program`) equality, backed by the positional lint
    `check_c10_transcription.py` + the 396-vector corpus. R1 is a deliberate cited-TCB
    of the kind every verified contract carries (the only ways to shrink it further —
    a Lean Yul-subset parser, or KEVM-in-Lean — are multi-week / upstream-gated).
  Read the log below as HISTORY, not current status.

- **2026-06-17 — PROOF PHASE (step 5) WELL UNDERWAY.** All reusable interpreter-
  refinement infrastructure + the first phase + the hardest climb shape are PROVEN
  (Phases.lean / Yul.lean / Sha256Bridge.lean; all `[propext, Classical.choice,
  Quot.sound]`, mathlib-free, 0 sorry, `theft_free` closure UNCHANGED, verify-build
  green, verify-interp 396/396):
  * **Composition + loop engine** (Yul.lean): `execList_append` (phase split),
    `execFor_invariant` (the loop-induction engine — thread `R:Nat→VM→Prop` through
    a halt-free `forRange`; the D=2 layer loop is unfolded since its body reverts),
    `setVar_get_eq/_ne`.
  * **Hash-site bridges** (Sha256Bridge.lean + C10Program.lean): `slice_toArray_eq_flatten`
    (`holdsSegs`→slice=`ByteSeg.flatten`), `c10Oracle_holdsSegs` (assembled mem →
    the precompile computes the real `Spec.sha256`), `beByte_and_nmask`, `natToB32_wordOf`,
    `mload_masked_eq_wordOf_pad16` (`and(mload,N_MASK)=wordOf(pad16(truncate16 d))`),
    `climbMem_thPair` (4-seg + branchless parity swap via `mstore32_comm`),
    `cl_masked_eq_wordOf` (masked calldata read-back), `reconstructRoot_eq_foldl`
    (forIn→foldl via `@[simp] forIn_eq_forIn_range'` + `List.forIn_pure_yield_eq_foldl`).
  * **Phases proven** (Phases.lean): `hmsg_digest` (H_msg phase → `env "digest" =
    wordOf(Spec.hMsg …)`, the template); `fors_climb` (the canonical A=11 Merkle
    climb → `wordOf(pad16(Spec.Fors.reconstructRoot …))`, reused by the hypertree);
    `fors_tree_body` (one full FORS tree: leaf `th` + climb + store →
    `mem(0x80+32t)=pad16(reconstructRoot …)`, with the real `loadValue16` secret).
  * **REMAINING FORS** (next): the `Adrs.make` word-layout bridge `wordOf (make …)
    = Σ field<<<pos = ||| field<<<pos` (discharges `fors_tree_body`'s forsNode
    obligations; reusable for `treeNode`/`wotsPk`) → i-loop wrapper (`execFor_invariant`
    over 12 trees) → last-tree → root-compress (`thMulti`=`computeForsPk`) →
    `fors_phase` (forced-zero `ifnz`→revert, else `env "forsPk"=wordOf(pad16 r)`,
    `reconstructForsPk … = some r`). **THEN** the hypertree phase (reuse the climb +
    `mload_masked` for the 9-level Merkle; NEW: WOTS digit-sum accumulate loop, the
    43-chain loop with a variable-length inner step loop, PK-compress; ×D=2 layers
    unfolded) → final `eq` compare → `execC10Asm = verifyYulModel`. **THEN** step 6
    (USER-GATED: the N-mask reconciliation).

- **NEXT (precise), in order — steps 1–3 DONE (above); proof phase next:**
  4. Finish `Sha256Bridge`: input-assembly (`slice = ByteSeg.flatten [seed,adrs,…]`
     from frame lemmas + `beByte_wordOf`) + masked/unmasked output
     (`and(mload32,N_MASK) = truncate16 (sha256 …)` = a spec node; H_msg/WOTS-digit
     unmasked) at the real `Spec.Sha256Impl`/`thPair`, real 4-seg step (parity swap).
     **Binding frame/locality lemmas FIRST** (distinct-var read/write commute;
     unmentioned vars preserved) — their absence caused verity's grind.
  5. Prove vertically, **H_msg phase first** (straight-line, unmasked → the digest
     `verifyWithDigest` consumes), then FORS/WOTS/hypertree phases via the
     loop-induction (each loop touches only scratch+accumulator), composing to
     `execC10Asm = Spec.Signature.verify` (= `verifyYulModel`).
  6. Replace `solidityVerifier_compiles_correctly` with the narrow
     `DeployedBytecode.SPHINCsC10Asm_verify = execC10Asm` transcription axiom
     (empirically backed by step 3 / `make verify-interp`) + re-derive the old
     statement as a theorem. **See the N-mask finding below — this step touches
     `theft_free` and is USER-GATED.**

### FINDING (2026-06-17, surfaced by the refinement) — N-mask gate: bytecode strict, model lenient

The deployed Yul (`SPHINCsC10Asm.sol` L58–65) rejects (`return false`) any
`pkSeed`/`pkRoot` not in N-mask shape (`and(key, N_MASK) != key`). The Lean model
`verifyYulModel = Verifier.Refined.verifyRefined` (confirmed at `Refined.lean:143`)
takes `ByteVec 32` keys and does `pkSeed.take 16` — **silently discarding the
bottom 16 bytes, with NO N-mask check.** So `execC10Asm = verifyYulModel` is **not
literally true**: on a non-N-masked key, `execC10Asm = false` (gate) while
`verifyYulModel` uses the top 16 and can be `true`. (Deductively certain;
`verify-interp` 396/396 is consistent because every KAT/bulk key is N-masked.)

- **It is a precision WIN, not a bug.** The bytecode is strictly *more* restrictive
  (`bytecode true → model true` always; divergence only at `bytecode false, model
  true`, reachable only by inputs the factory/`addOwner` never produce — they
  N-mask). `DeployedBytecode` is opaque, so the old axiom is unfaithful-to-reality,
  NOT provably-false (no soundness fire). The project already covers the gate via
  **Halmos input-gates, separately** from the Lean equiv; the interpreter folds
  *core + gate* into ONE kernel statement, subsuming the Halmos check.
- **True target theorem (step 5/6 end-state):**
  `execC10Asm pkS pkR m sig = nMaskedB pkS && nMaskedB pkR && verifyYulModel pkS pkR m sig`,
  with `nMaskedB key := (wordOf key) &&& N_MASK == wordOf key` (Bool, matching the
  bytecode) + a small lemma to `Wallet.Factory.nMasked` (Prop). The phase proofs
  (H_msg→FORS→WOTS→hypertree) are UNAFFECTED — they prove the both-N-masked branch
  computes `verifyYulModel`; the gate is the top-level `ifnz` wrapper.
- **`theft_free` interaction (step 6, USER-GATED):** `theft_free` (Theorems.lean
  :350-352) uses the A3.1 axiom in the LIVENESS direction (`rw [hbridge]; exact
  hverify`: `verifyYulModel true → DeployedBytecode true`). Under the faithful
  characterization that needs the stored keys N-masked — modeled
  (`Factory.nMasked`/`Storage.hasNMaskLayout`) and enforced by the factory/addOwner,
  so threadable, but it edits `theft_free`. **KEEP the old axiom in place for now;
  bring the swap (transcription axiom + characterization + threading the N-mask
  invariant) to the user at step 6, with the characterization already proven.**

- **(historical) the original executable-first NEXT list (now steps 1–3 done):**
  1. **`Interpreter/Yul.lean`** — the C10 opcode-subset AST (`Expr`:
     `calldataload`/`mload`/`add`/`mul`/`sub`/`div`/`mod`/`and`/`or`/`xor`/`shl`/`shr`/
     `lt`/`eq`/`iszero`/`var`/`lit`; `Stmt`: `let`/`assign`/`mstore`/`staticcall0x02`/
     `if`/`for`/`block`/`funcall`/`leave`) over `Interpreter.Memory` + a calldata
     model + a bindings env, with the `0x02` precompile as an oracle parameter.
     `for`-semantics = a fold (wires into `climbMem`/loop-induction). **Computable**
     (so KATs run). Plus binding **frame/locality lemmas** (de-risk) + a `#eval`/
     `decide` shake-out of a 3-stmt fragment.
  2. **Transcribe the ENTIRE `SPHINCsC10Asm.sol` Yul → the AST** (`execC10Asm`),
     instantiating the oracle with the computable `Spec.Sha256Impl`.
  3. **Empirical validation milestone:** run KAT 10/10 (incl. 6 negatives + NM1/NM2
     near-miss) + bulk 384/384 + the mutant battery THROUGH `execC10Asm`; assert it
     agrees with `Spec.verify` AND the deployed-bytecode KAT results. (No bridge
     lemmas needed — hash is computable.) This empirically pins AST-faithfulness +
     `execStmt`↔EVM before any proof.
  4. Finish `Sha256Bridge`: input-assembly (`slice = ByteSeg.flatten [seed,adrs,…]`
     from frame lemmas + `beByte_wordOf`) + masked/unmasked output
     (`and(mload32,N_MASK) = truncate16 (sha256 …)` = a spec node; H_msg/WOTS-digit
     unmasked) at the real `Spec.Sha256Impl`/`thPair`, real 4-seg step (parity swap).
  5. Prove vertically, **H_msg phase first** (straight-line, unmasked → the digest
     `verifyWithDigest` consumes), then FORS/WOTS/hypertree phases via the
     loop-induction, composing to `execC10Asm = verifyYulModel`.
  6. Replace `solidityVerifier_compiles_correctly` with the narrow
     `DeployedBytecode.SPHINCsC10Asm_verify = execC10Asm` transcription axiom
     (empirically backed by step 3) + re-derive the old statement as a theorem.
