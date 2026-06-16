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
  bridge — but a *much smaller* one (see §5).
- **(R2) SHA-256 needs byte-addressed interpreter memory.** The upstream
  machinery is built for native `keccak256`. The Keccak→SHA-256 bridge is
  otherwise mechanically identical (`KeccakBridge`→`Sha256Bridge`, one
  engine swap), but the SHA-256 path uses the `0x02` precompile fed by **sub-word
  `mstore`s** that alias within a word (`Model.lean:258-275`). The upstream's
  **word-keyed** memory model cannot represent that aliasing; a faithful SHA-256
  interpreter needs a **byte-addressed** memory. This is a refactor, not a wall —
  but it is real, SHA-256-specific work that the Keccak proof never had to do.

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
