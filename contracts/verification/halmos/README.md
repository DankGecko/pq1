# Bytecode-level discharge (Halmos)

This directory turns the `solidity*_compiles_correctly` bridge axioms from
*pending* (codehash pin + 10 KAT vectors only) into **symbolic proofs over
the deployed runtime bytecode**. Halmos compiles the contracts with the
pinned `solc` settings and symbolically executes the resulting **EVM
bytecode**, so each passing `check_*` rule is a proof for *all* inputs in its
envelope (not the 10 concrete KAT vectors), modulo the SMT solver and the
SHA-256-as-uninterpreted-function abstraction (= axiom A1).

## What is proved (38 rules, all PASS — on BOTH compiler profiles)

> **Scope note.** These rules discharge the wallet/factory/owner-table
> **control flow** on bytecode, with the verifier modeled as an
> uninterpreted function. They do **not** prove the verifier's own
> functional correctness — see `HalmosVerifier.t.sol` (input gates only)
> and `docs/A3_1_VERIFIER_GAP.md` for why A3.1 is `-partial`.

| Harness (`test/halmos/`) | Axiom surface | Rules |
|---|---|---|
| `HalmosValidateUserOpEquiv.t.sol` | A3.2 — **pointwise equivalence** of `validateUserOp` to the Lean model (+ symbolic-index sweep over installed slots) | 4 |
| `HalmosValidateUserOp.t.sol` | A3.2 — `validateUserOp` per-property rules | 8 |
| `HalmosExecuteEquiv.t.sol` | A3.2-exec — **pointwise equivalence** of `execute{,Batch}WithOffchainCount` to the Lean `Execute` model, **symbolic ∀ `ownerIndex`** | 5 |
| `HalmosExecute.t.sol` | A3.2-exec — `execute*WithOffchainCount` per-property rules | 6 |
| `HalmosMultiOwnable.t.sol` | A3.4 — `addOwnerBytes`/`removeOwnerAtIndex`/`initialize` pointwise + `ownerAtIndex` read parity (replaces stale Certora) | 7 |
| `HalmosVerifier.t.sol` | A3.1 — `SPHINCsC10Asm.verify` **input gates** | 3 |
| `HalmosFactory.t.sol` | A3.3 — `createAccount` ⟺ `createAccountPrecondition` | 5 |

The full suite is executed against **both** the `default` (runs=200) and
`deploy` (runs=999999, production) profile bytecode — the production codehash
is symbolically discharged directly, not transported by a control-flow
argument. The emitted external CALL's faithful byte-delivery on the execute
path is axiom **A4** (EVM executes per spec), not A3.2-exec.

### A3.2 — full pointwise equivalence (the headline strengthening)

`HalmosValidateUserOpEquiv.t.sol` proves the axiom at the equality it actually
states, not selected corollaries: the deployed `validateUserOp` runtime
bytecode returns the **same `(result, post-storage)`** as a clause-for-clause
Solidity transcription of the Lean model
(`LeanValidateUserOpModel.sol` ↔ `Wallet/ValidateUserOp.lean`), over a
**symbolic envelope** —

* signature-wrapper bytes `[32..4128)` symbolic (offset word, innerLen word,
  4008 sig bytes, 24 pad bytes), plus a sweep over wrong total lengths. The
  wrapper `ownerIndex` word `[0..32)` coverage: rule 1 **enumerates** the
  entire installed set `{0,1,2}` (finite — exhaustive, not sampling) plus
  concrete reps `{3, 2^200, max}` for the unset partition (on which the
  wallet's reject behaviour is uniform), and rule 1c
  (`check_validateUserOp_pointwise_installed_indices`) **adds a symbolic
  sweep over the installed slots `{1,2}`**. The **unset partition cannot be
  swept symbolically** — a symbolic non-installed key `NotConcreteError`s on
  the `mapping(uint=>bytes)` `ownerAtIndex` getter (Halmos can't resolve the
  default-empty return length for a symbolic key). This is a **disclosed
  hard engine ceiling**: the prior "six concrete reps" is *reduced* (installed
  slots now symbolic), not eliminated. (The EXECUTE path is genuinely ∀-index
  because it reads word-typed counters + the transient credit, never the
  bytes getter.)
* `callData` symbolic at lengths `{0,3,4,35,36,68}`; `initCode` /
  `paymasterAndData` symbolic at `{0,32}` (empty exercises the
  `sha256("")` path); all scalar UserOp fields, `userOpHash`,
  `missingAccountFunds` symbolic;
* counters symbolic under the kernel-proven combined-cap invariant; owner
  bytes symbolic at the installed indices;

under a **generic input-dependent uninterpreted verifier**
(`OracleSPHINCSVerifier`): the verifier's answer is an uninterpreted function
of the full `(pkSeed, pkRoot, digest, sig)` tuple, so any path where the
wallet hands the verifier different bytes than the model yields a
counterexample — a pass therefore also certifies the exact verifier-call
arguments, byte-for-byte. This is strictly more general than instantiating the
deployed verifier (the deployed verifier is *one* admissible interpretation).

### A3.2-exec — execute pointwise equivalence (symbolic ∀ ownerIndex)

`HalmosExecuteEquiv.t.sol` proves `executeWithOffchainCount` /
`executeBatchWithOffchainCount` return the **same `(success?, post-storage)`**
as the Lean `Execute` model (`LeanExecuteModel.sol` ↔ `Wallet/Execute.lean`)
over a **symbolic `ownerIndex`** (the money path reads only word-typed
counters + the transient-credit `tload`, so it admits a genuine ∀-index
sweep), symbolic `newOffchainCount`, symbolic `value`, symbolic `data`, and
symbolic counters under the combined-cap invariant; the execution credit is
stamped by a *real* `validateUserOp` call on the same bytecode. The axiom is
the **success direction** (the only one theft-freedom needs): the Lean model
is the all-dispatch-succeeds model, so conditioning on the bytecode returning
`some σ'` restricts to the `callOk≡true` world where the equality holds. The
atomicity arm (a reverting target reverts the whole execute) and the
∀-index no-credit-reverts arm are separate rules. The emitted external CALL's
faithful byte-delivery is **A4**, not A3.2-exec.

### A3.4 — owner table on bytecode (replaces stale Certora)

`HalmosMultiOwnable.t.sol` proves `addOwnerBytes` / `removeOwnerAtIndex` /
`initialize` pointwise-equal to the Lean `Storage` model (length + N-mask +
duplicate gates; install/remove/init verbatim), each asserting `ownerAtIndex`
**read parity** (the A3.4 equality proper) after the mutation, plus
bootstrap-unremovable (Claim 2) for every `expected`-bytes value and the
unset-index reject for every index `>= 2`. This replaces the prior Certora
artifact, which had gone stale (pinned to a PQSmartWallet codehash that no
longer matched the embedding bytecode, never re-run).

The per-property harnesses (`HalmosValidateUserOp`, `HalmosExecute`) remain as
the bytecode analogues of the named Lean invariants — non-bypass (I-1) over a
symbolic verifier result, the validation-phase few-time-cap bump (the
`PQBootstrapCapEvasion` fix), role-split, tail-pad, EntryPoint-only, and the
execute gate (Claim 4: no money-move without a prior verifier-true validate,
one-shot, self-target rejected).

### A3.3 — createAccount iff

`HalmosFactory.t.sol` proves `createAccount` succeeds **⟺** the Lean
`Factory.createAccountPrecondition` holds (verifier accepts over
`addSlot0Digest` — symbolic verifier answer, so over EVERY answer — AND right
chain), over symbolic chainId + symbolic signature, with the success arm
proving the deploy postconditions; plus the already-deployed top-up
early-return and three reject rules witnessing the precondition's install-gate
conjuncts (non-N-masked master, non-N-masked slot-0, duplicate slot-0). Keys
are concrete in the iff (a symbolic owner half would make Halmos havoc the
proxy's owner storage on the phantom already-deployed CREATE2 fork).

## Reachable-state hypothesis (A3.2)

The A3.2 axiom and `theft_free_bytecode` carry the hypothesis
`∀ i, slotUses[i] + offchainSigCount[i] ≤ MaxSlotUses` — the kernel-proven
`combinedCap_inductive` reachable-state invariant. It is **load-bearing**:
outside it the deployed bytecode REVERTS (Solidity-0.8 checked add) where the
ℕ-valued Lean model returns `failure`, so the *unconditional* pointwise
equality is false. Conditioning on the invariant makes the axiom exactly what
the bytecode satisfies on every reachable state.

## Scope / honest ceiling

* The verifier's **full functional behaviour** (FORS/WOTS/Merkle/hypertree
  over a 4008-byte signature with thousands of `staticcall(0x02)`) is **not**
  symbolically tractable and is **not** attempted here. That part of A3.1
  stays `discharged-bytecode-partial`, and the evidence is **empirical**, not
  a Lean proof: the positive direction is the **bytecode-side** 10-vector KAT
  (`test_verifyAllKatVectors`, Rust signer ↔ deployed Solidity verifier — a
  real matched-pair differential) and the negative direction is the
  ≈250-mutant adversarial wrong-accept screen
  (`test/SPHINCsC10AsmAdversarial.t.sol`). **Important (2026-06-11):** the
  *Lean* leg of the differential is real only on the **digest/htIdx
  sub-layers** (`lake exe verify-test-vectors`); the Lean verifier spec is
  **not** executably faithful on the reconstruction layer — it returns
  `false` on the valid vectors — so the A3.1 *equality* axiom is currently
  **false as stated**. Do not cite `verifyRefined_eq_spec` as faithfulness;
  it is `rfl` over an unfaithful model. See `docs/A3_1_VERIFIER_GAP.md`.
  Halmos here proves only the verifier's **input-validation gates**
  (boundary-swept length revert / N-mask reject), which run before any hash.
* SHA-256 is an **uninterpreted function** in Halmos — the proofs bottom out
  at A1 (`precompile_0x02_is_FIPS_180_4`) exactly as the Lean closure does.
* Halmos output is **not** a Lean proof term — it is a cited solver session
  (TCB: Halmos + z3 soundness + the human-written harness↔property match and,
  for the equivalence session, the `LeanValidateUserOpModel.sol` ↔
  `Wallet/ValidateUserOp.lean` transcription correspondence — a side-by-side
  syntactic check over ~60 lines of first-order code). This is inherent to
  post-hoc bytecode equivalence and is named in `AXIOM_STATUS.json`.

## The Halmos patch

`0001-sha256-precompile-sort.patch` fixes two genuine issues in halmos 0.3.3's
SHA-256 precompile model:

1. **Sort mismatch.** The uninterpreted function was declared with a domain
   sort keyed on the CALL's **byte** size (`f_sha256_32 : BitVec 32`) but
   applied to the argument's **bit** width (`BitVec 256`), so z3 aborted on
   every success path reaching `sphincsDigest`. The fix keys the function on
   the argument bit-width (mirroring how KECCAK is handled in the same file).
2. **Empty input.** `sha256("")` (0-byte input — e.g. an empty
   `initCode`/`paymasterAndData`/signature field) produced a `BitVec(0)`,
   which z3 has no sort for. The fix models the empty-input digest as a
   nullary uninterpreted constant `f_sha256_empty : BitVec 256`.

Both corrections only fix the declared sorts — the function stays
**uninterpreted**, so the patch cannot make a false property pass; it can only
stop a crash. (The true digest is one admissible interpretation.)

## Reproduce

```bash
cd contracts/verification
make verify-bytecode-setup   # clone + patch + install the patched halmos (once)
make verify-bytecode         # certify codehashes (both profiles) + immutable lemma, then run all 38 rules on BOTH profiles
```

`run_halmos.sh` first runs `PinnedCodehashes.t.sol` **and**
`PinnedBytecodeImmutableLemma.t.sol` (Foundry) under BOTH compiler profiles
(default `runs=200` and deploy `runs=999999`) to certify the compiled runtime
codehashes equal the pins in `PINNED_CODEHASHES.md` and that each runtime
differs from its pinned instance only inside the certified immutable windows —
i.e. the bytecode Halmos executes is the bytecode the Lean `theft_free`
closure names, on both the dev and production builds — then runs the full
symbolic suite against **each** profile's bytecode and fails if any rule does
not pass. Session output is archived under `sessions/`. Set
`PQ1_HALMOS_SKIP_DEPLOY_SYMBOLIC=1` to skip the (slow) deploy-profile symbolic
re-run during fast local iteration.
