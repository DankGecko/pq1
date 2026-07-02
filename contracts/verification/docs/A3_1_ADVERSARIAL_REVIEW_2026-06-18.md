# A3.1 interpreter-refinement — adversarial faithfulness review (2026-06-18)

Heavy adversarial double-check of the A3.1 claim that the deployed on-chain
SPHINCS+C10 verifier refines its Lean declarative spec, on master `940d43e8`.

**Subject of trust.** `theft_free` carries A3.1 as
`solidityVerifier_compiles_correctly : DeployedBytecode.SPHINCsC10Asm_verify =
execC10Asm` (the *faithful* form landed 2026-06-18), with `execC10Asm_eq`
(Lean kernel) giving `execC10Asm = nMaskedB pkSeed && nMaskedB pkRoot &&
verifyYulModel`. `execC10Asm` runs `c10Program` (a hand-transcription of
`SPHINCsC10Asm.sol`'s Yul) under a real computable SHA-256 (`Spec.Sha256Impl`).

## Method

The Lean **kernel already proves** `execC10Asm = spec` pointwise on all inputs
(`execC10Asm_eq`, kernel-clean). So any transcription/interpreter bug that
*changes a computed result* is already caught. The review therefore attacks only
the four judgments the kernel cannot see, plus hygiene:

1. transcription fidelity: `c10Program` == the real `.sol` Yul;
2. interpreter fidelity: `Interpreter.Yul`/`Memory` == real EVM/Yul;
3. codehash parity: the transcribed `.sol` == the deployed pinned bytecode;
4. `Sha256Impl` == FIPS-180-4;
plus axiom hygiene / vacuity.

Cheap dispositive gates were run inline; then a multi-agent fan-out diffed the
transcription region-by-region, the interpreter vs EVM, codehash parity, and an
independent vacuity audit, each followed by an adversarial verify pass.

## Verdict: **holds up.** No bucket-i (soundness) defect found.

### Machine-checked now (on master 940d43e8)

| Check | Result |
|---|---|
| `execC10Asm_eq` axioms | kernel-clean `[propext, Classical.choice, Quot.sound]` |
| phase capstones `hmsg_digest` / `fors_phase` / `verifyHypertree_refine` | all kernel-clean |
| `deployed_verifier_refines_spec` | kernel + A3.1 only |
| `theft_free` axioms | exactly the documented 11 (kernel³ + A1 + A2 + A3.1 + A5×4); no `sorryAx`/`native_decide` |
| `make verify-extracted` (§33) | no `sorryAx` in any closure |
| **`verify-interp`** (corpus *through* `execC10Asm`) | 12 KAT + 384 bulk: `interp==spec` AND `interp==expectValid` perfect; **rejects all 8 negatives** (note: the negatives keep N-masked keys and mutate the body, so this exercises the *verify body*, not the N-mask-guard rejection path — that path is covered by the kernel `false` arms of `execC10Asm_eq` + the Halmos N-mask input-gate rule) |
| `verify-test-vectors` | digest/htIdx/full-verify 12/12, rejects negatives |
| `verify-bulk` | 384/384 vs Rust oracle (192 valid + 192 neg) |
| `verify-cavp` | `Sha256Impl` == FIPS-180-4, 229/229 NIST CAVP |
| `PinnedCodehashes.t.sol` + `DeployedBytecodeReproCheck.t.sol` | [PASS] deploy profile: pinned `SPHINCsC10Asm` codehash == live Base Mainnet `0xeb1e3fcd…2cc5` (verifier has no immutables → exact reproduction) |

### Per-judgment findings

1. **Transcription (`c10Program` ↔ `.sol`): faithful, byte-for-byte.** Six
   regions line-matched (prefix+guards+H_msg / FORS forced-zero+12 trees / FORS
   last+roots-compress+HT-setup / WOTS digest+digit-sum+chains / WOTS PK-compress
   +Merkle auth / final compare + whole-program tables). All four masks (NMASK,
   ALLFF, CHAINBASE_MASK, TREEADRS_MASK), every memory & calldata offset, all loop
   bounds (12/11/13/2/43/9), the digit-sum=205 gate and `steps=7−digit`, every
   shift amount with the convention-critical `shl(amt,val)` operand order, both
   branchless Merkle swaps, the ADRS field packings, and the `0x200 = 0x80+12·0x20`
   last-root slot all match. Calldata layout independently recomputed tiles
   `[0,4008)` with no gap/overlap. Only T6 "findings" are bucket-ii boundaries
   (elided revert error-strings; the dead sig-length branch; the `.sol`'s latent
   memory-safe annotation note) — none are defects.

2. **Interpreter (`Interpreter.Yul`/`Memory`) ↔ EVM: faithful.** (a) Missing `%W`
   on `band/bor/bxor/shr` is *sound* — all reachable values stay `< 2^256` by
   structural induction (literals ≤ 256-bit masks; `mload32`/`calldataload` fold
   32 bytes; loop indices `< 43`; `add/sub/mul/shl` carry `%W`; bitwise/shr can't
   exceed their inputs). (b) `sub` is correct two's-complement. (c) `calldataload`
   = big-endian 32-byte read, zero-padded past end — the last Merkle sibling read
   genuinely runs 16 bytes past offset 4008 into zero-pad, masked off by `N_MASK`,
   exactly as EVM. (d) Big-endian memory; `mload32(mstore32 …) = w%2^256`
   kernel-proven; swap windows `{0x40,0x60}` disjoint (`writeRegion_comm`); `OUT
   =0x600` above the highest live write `0x5C0`. (e) Flat `VarEnv` is faithful:
   c10's Yul is single-declaration / assign-before-read with no post-scope
   loop-local reads, so it can't diverge from lexical scoping. (f) `execFrom` Bool
   maps `returned w→w==1`, revert/fall-through→false, matching the `.sol`'s
   `return(mem[0]∈{0,1})`.

3. **Codehash parity: established, empirically.** `PinnedCodehashes.t.sol`
   L88/L116-117 pins `SPHINCsC10Asm` specifically to the value the live source
   compiles to; `DeployedBytecodeReproCheck.t.sol` CREATE2-replays the verifier
   creation code to the byte-identical on-chain codehash. No constructor
   immutables → no immutable-window caveat for the verifier. The deserialise/offset
   bridge in `C10Refine.lean` (`SigForsTotal=2336`, `SigHtLayer=836`, `L=43`,
   `N=16`) is arithmetically correct.

4. **`Sha256Impl` == FIPS-180-4:** 229/229 NIST CAVP (ShortMsg 65 + LongMsg 64 +
   Monte 100).

### Vacuity / hygiene

No load-bearing lemma is vacuous: `nMaskedB` has both true and false models;
both `by_cases` arms of the N-mask guards, the FORS revert/pass and hypertree
none/some branches all have real proofs; `htLayers_satisfy_Hbind`'s count premise
is discharged unconditionally via `count_bridge`. `theft_free`'s conclusion
genuinely requires `execC10Asm…=true` (closed by `rw [hbridge]; exact hverify`
against an `opaque` symbol — not trivialisable).

## Residual trust base (honest statement)

**Trusted by assertion (not machine-checked against each other):**
- **The hand transcription `.sol` Yul → `c10Program`.** This *is* the content of
  the A3.1 axiom; the kernel relates `c10Program`↔spec, never `c10Program`↔`.sol`.
  Backed by: the region-by-region human diff above + the 396-vector corpus run
  *through* `execC10Asm` (rejecting negatives) + the bytecode-side KAT/mutant
  differential + (NEW 2026-06-18) the **positional transcription lint**
  `scripts/check_c10_transcription.py` (`make verify-transcription`, wired into CI),
  which converts the one-time human diff into a re-runnable regression gate:
  per-`-- L<n>`-anchor constant cross-check (catches a constant in the *wrong*
  fragment — a cross-fragment swap), global constant-set equality, and a
  statement-kind histogram. It is a **regression gate, not a proof**: an
  *intra-fragment* swap (two constants both present in the same `.sol` line-range)
  is NOT caught by the lint and remains covered by the corpus + `execC10Asm_eq`.
  Negative controls (a mutated constant; a cross-fragment 143↔132 swap) were
  verified to make the lint fail. Still: not a single machine-checked equality.
- **`Interpreter.Yul`/`Memory` == real EVM/Yul** (~600 lines, audited above; the
  corpus exercises it against the Rust oracle, but a result-invariant mis-model on
  corpus inputs would not show — closed here by construction-level argument).
- **A1** (uninterpreted/precompile SHA-256; the ∀-verify-body symbolic-equivalence
  ceiling, `discharged-bytecode-partial`), **A4** (EVM execution), **A5** (EUF-CMA).
- `Sha256Impl`'s CAVP coverage (empirical, not a proof of the algorithm).

These are the *expected* A3.1 boundaries, correctly labelled in the repo.

**Precise statement of A3.1's discharge (the concrete-hash composition).** The Lean
axiom equates the opaque `DeployedBytecode.SPHINCsC10Asm_verify` (which runs on the
EVM `0x02` precompile) to `execC10Asm` (which runs on the **concrete** `Sha256Impl`).
That equality holds ∀-inputs only if `precompile == Sha256Impl`, so the axiom's
discharge *composes three things*: Halmos structural-equivalence over the deployed
bytecode with SHA **uninterpreted** ∘ **A1** (`precompile == FIPS-180-4`) ∘ **CAVP**
(`Sha256Impl == FIPS-180-4`) — with the 396-vector KAT/bulk differential checking
concrete-vs-concrete directly *on-corpus*, and **A1 carrying the ∀ off-corpus**. This
is precisely why A1 appears in `theft_free`'s `#print axioms` closure: it is a
*discharge dependency of A3.1*, not an independently-consumed Lean premise (the
"non-consumed marker" language elsewhere is about the Lean derivation, not about
real-world necessity). A reader should NOT conclude "Halmos alone discharges the Lean
axiom as written" — Halmos discharges it modulo an uninterpreted SHA, and A1+CAVP
close the concrete-hash gap.

## Defense-in-depth follow-ups (CI gating, NOT soundness holes) — IMPLEMENTED 2026-06-18

- **H-1 ✅** `wots_pkfromsig_nonvacuous` **and** its sibling `fors_tree_body_nonvacuous`
  (`Phases.lean`) restated from `: True := by … trivial` to a content-bearing
  `∃ (witness), <full refinement conclusion>` (`exact ⟨witness, …⟩`). The TYPE now
  carries the non-vacuity, so a regressed/garbage body can no longer pass. Both
  re-verified kernel-clean (`[propext, Classical.choice, Quot.sound]`). Aside logged:
  `lint_axioms.sh`'s `True`-typed-theorem scan matches only the literal `:= trivial`
  form and *evades* `:= by … trivial` (which is why these passed despite an empty
  allowlist) — a real hole in that lint, tracked for a follow-up.
- **H-2 ✅** `lint_fv_invariants.sh` (c.2) upgraded from subset (missing-only) to an
  **EXACT-set** compare — a newly-added content-bearing axiom (or one flipped
  false→true) entering `theft_free`'s closure now FAILS the gate (the automated-gate
  analogue of "`#print axioms` shows names not types"). Negative control (injecting
  `solidityMultiOwnable_compiles_correctly` into the closure) verified to trip it. The
  sibling subset weakness in the (c.1) offchain/Gap-3 check is flagged in-script for a
  follow-up; the kernel `#print axioms` remains the backstop.
- **H-3 ✅** `execC10Asm_eq` + `deployed_verifier_refines_spec` added to
  `dump_axioms.lean`'s `#print axioms` list — the A3.1 kernel keystone is now
  *directly* CI-gated (was caught only indirectly by the full rebuild).

## Transcription residual hardened — `make verify-transcription` (the headline of this pass)

`scripts/check_c10_transcription.py` (`make verify` / `verify-transcription`, and run
in CI by the dedicated `.github/workflows/a31-transcription.yml` — a POSITIVE-`paths:`
workflow on the `.sol`, `C10Program.lean`, the lint, and the Makefile — plus the
`ci.yml` `invariant-gates` step) is a **positional** regression gate over the one
residual the kernel cannot see — `c10Program` vs `SPHINCsC10Asm.sol`. Three checks:
(A) per-`-- L<n>`-anchor constant cross-check — the key one: catches a constant placed
in the *wrong* fragment (a cross-fragment swap), which a flat/global check misses and
the corpus catches only behaviourally; (B) global constant-set equality (38/38 distinct
constants, error-string revert elided); (C) statement-kind histogram (no dropped/added
statement). Negative controls confirmed it FAILS on (1) a mutated constant and (2) a
cross-fragment `143↔132` swap (global passes, positional fails). It is explicitly a
**regression gate, not a proof**: an intra-fragment swap (two constants both in one
`.sol` line-range) stays covered by the 396-vector `verify-interp` corpus + `execC10Asm_eq`.

## CI enforcement — honest scope

The Lean `verify-*` suite (`lake`/`elan`: `verify-build`/`verify-interp`/`verify-fv-lints`/
`verify-audit`/`verify-extracted`/`verify-bulk`/`verify-cavp`) is **not** wired into any
GitHub Actions workflow today — it is run locally / in review. The **only** CI-enforced
piece of this A3.1 pass is the **positional transcription lint** (pure Python, no Lean
toolchain) via `a31-transcription.yml` + the `ci.yml` `invariant-gates` step. So the H-2
(`lint_fv_invariants.sh`) and H-3 (`dump_axioms.lean`) hardenings, and the kernel
axiom-cleanliness checks, are **review-time gates, not CI gates** — the kernel itself
(rejecting any `sorry`/bad axiom at build time) remains the true backstop, and a full
`lake build` is the catch-all. Wiring the Lean suite into CI (elan + mathlib-cache job)
is a separate, larger follow-up, out of scope here.

## Adversarial coverage characterization (two finders; one finding actioned)

Two finders were launched to try to construct a transcription mutation the lint
*misses*. The parser-robustness finder timed out (stream-idle); its analysis was done
**inline** (see the lint header's "KNOWN COVERAGE LIMITS" — no false-PASS hole: the
global check is exact, the positional is ⊆-per-fragment, the histogram is exact). The
bypass-construction finder completed and produced one genuinely useful finding:

- **RANK 1 — N-mask gate variable-swap (actioned).** A `var`-swap making the first
  N-mask gate check `pkRoot` instead of `pkSeed` (leaving `pkSeed`'s shape ungated)
  changes no constant and no statement kind, so checks (A)/(B)/(C) miss it; and the
  corpus misses it because all 792 corpus keys are already N-masked (so the gate never
  fires either way). The finder claimed this was *also* invisible to the kernel proof.
  **That claim is empirically false** — I applied the swap and rebuilt: `lake build`
  FAILS at `c10Program_decompose`'s `by rfl` (C10Refine.lean:64), which pins the exact
  gate structure including which key each gate checks. So the full build is a definitive
  backstop. But the finder's core point stands for the *CI-enforced* lint (var-blind)
  and the corpus (no malformed keys). **Closed:** added lint **check (D)** pinning both
  N-mask gates to `(pkSeed, pkRoot)` in order, cross-checked against the `.sol`; the
  RANK-1 swap now FAILS the lint (negative control verified).
- Other bypass classes (operand-order swaps using present constants, `var`-refs
  elsewhere, intra-fragment constant swap, same-kind reorder) are all **behaviour-
  changing → caught by the `verify-interp` corpus**; the broad-anchor weakness (a
  constant misplaced within a wide anchor like `L149-226`) is a documented positional
  limit. The key invariant is airtight: any mutation bypassing *both* the lint and the
  corpus is behaviour-preserving, hence not a real fault — and the full `lake build`
  (c10Program_decompose + execC10Asm_eq) pins the entire structure besides.

**UPDATE 2026-07-02 — those "bypass classes" now have a SOURCE-LEVEL CI gate.** The
operand-order-swap / var-ref-elsewhere / same-kind-reorder classes above (previously
"caught by the `verify-interp` corpus" — a *local* run, not CI-enforced) are now caught
directly at the source level by the **structural** transcription check
`check_c10_transcription_ast.py` (in `make verify-transcription` + the
`a31-transcription.yml` CI gate). It parses `SPHINCsC10Asm.sol` and the `c10Program`
literal into the `Interpreter.Yul` AST and asserts **tree equality**, so a reorder /
var-swap / operand-swap flips the tree and FAILS — with three such mutants proven
invisible to the statistical lint yet caught here (`test_c10_transcription_ast_negative.py`).
Honest scope: this upgrades the **R1a source↔AST** leg from statistical to structural in
CI; R1b (solc source→bytecode) is untouched and the parser + its two normalization rules
are the new TCB. See `A3_1_CLOSURE_PATH.md` §8 (2026-07-02 entry).

## Reproduce

```
make -C contracts/verification verify-build verify-transcription verify-interp verify-test-vectors verify-bulk verify-cavp verify-extracted verify-fv-lints
FOUNDRY_PROFILE=deploy forge test --match-path 'test/PinnedCodehashes.t.sol' -vv  # in contracts/smart-wallet
FOUNDRY_PROFILE=deploy forge test --match-path 'test/DeployedBytecodeReproCheck.t.sol' -vv
```
