# Bytecode-level discharge (Halmos)

This directory turns the `solidity*_compiles_correctly` bridge axioms from
*pending* (codehash pin + 10 KAT vectors only) into **symbolic proofs over
the deployed runtime bytecode**. Halmos compiles the contracts with the
pinned `solc` settings and symbolically executes the resulting **EVM
bytecode**, so each passing `check_*` rule is a proof for *all* inputs (not
the 10 concrete KAT vectors), modulo the SMT solver and the
SHA-256-as-uninterpreted-function abstraction (= axiom A1).

## What is proved (19 rules, all PASS)

| Harness (`test/halmos/`) | Axiom surface | Rules |
|---|---|---|
| `HalmosValidateUserOp.t.sol` | A3.2 — `validateUserOp` / `_validateSignature` | 8 |
| `HalmosExecute.t.sol` | A3.2 — `execute*WithOffchainCount` (the money-mover) | 6 |
| `HalmosVerifier.t.sol` | A3.1 — `SPHINCsC10Asm.verify` **input gates** | 3 |
| `HalmosFactory.t.sol` | A3.3 — `createAccount` squat-defence (I-8) | 2 |

Highlights — each is the bytecode analogue of a kernel-checked Lean theorem:

* **Non-bypass (Lean I-1).** `check_nonbypass_{bootstrap,slot}`: the verifier
  result is a *symbolic* boolean (the same abstraction as the Lean model's
  arbitrary `verify_fn`); Halmos proves there is **no** path where
  `validateUserOp` returns SUCCESS while the verifier returned false.
* **Validation-phase few-time-cap bump (the `PQBootstrapCapEvasion` fix).**
  `check_{bootstrap,slot}_bumps_cap_at_validation`: an accepted signature
  bumps `bootstrapUses` / `slotUses[i]` inside `validateUserOp` itself,
  with no execution-phase step — proving the fix on bytecode.
* **Execute gate (Lean Claim 4).** `check_execute_*`: no money-moving call
  without a prior verifier-true validate stamping the matching owner-index
  credit; one-shot (no replay); self-target rejected (single + batch).
* **Squat-defence (Lean I-8).** `check_createAccount_requires_bootstrap_sig`:
  no wallet is deployed unless the bootstrap signature verifies.

## Scope / honest ceiling

* The verifier's **full functional behaviour** (FORS/WOTS/Merkle/hypertree
  over a 4008-byte signature with thousands of `staticcall(0x02)`) is **not**
  symbolically tractable and is **not** attempted here. That part of A3.1
  stays discharged by the Lean refinement
  (`Verifier/Equivalence.lean::verifyRefined_eq_spec`, including the FORS
  `htIdx` ADRS binding) + the 10-vector Rust ↔ Solidity ↔ Lean differential
  (`test_verifyAllKatVectors`). Halmos here proves only the verifier's
  **input-validation gates** (length / N-mask), which run before any hash.
* SHA-256 is an **uninterpreted function** in Halmos — the proofs bottom out
  at A1 (`precompile_0x02_is_FIPS_180_4`) exactly as the Lean closure does.
* The wallet verifier is the controllable `MockSPHINCSVerifier`: the same
  abstraction the Lean model uses (an arbitrary external verifier). The
  verifier↔model equality is A3.1, proved separately as above.
* Halmos output is **not** a Lean proof term — it is a cited solver session
  (TCB: Halmos + z3 soundness + the human-written harness matching the Lean
  property). This is inherent to post-hoc bytecode equivalence and is named
  in `AXIOM_STATUS.json`.

## The Halmos patch

`0001-sha256-precompile-sort.patch` fixes a genuine bug in halmos 0.3.3:
the SHA-256 precompile's uninterpreted function was declared with a domain
sort keyed on the CALL's **byte** size (`f_sha256_32 : BitVec 32`) but
applied to the argument's **bit** width (`BitVec 256`), so z3 aborted with a
sort mismatch on every success path reaching `sphincsDigest`. The fix keys
the function on the argument bit-width (mirroring how KECCAK is handled in
the same file). It corrects only the declared sort — the function stays
uninterpreted, so it cannot make a false property pass; it can only stop the
crash. Reported upstream-shaped as a minimal diff.

## Reproduce

```bash
cd contracts/verification
make verify-bytecode-setup   # clone halmos v0.3.3, apply the patch, install (once)
make verify-bytecode         # certify codehashes == pins, then run all 19 rules
```

`run_halmos.sh` first runs `test/PinnedCodehashes.t.sol` (Foundry) to certify
the compiled runtime codehashes equal the pins in `PINNED_CODEHASHES.md` —
i.e. the bytecode Halmos executes is the bytecode the Lean `theft_free`
closure names — then fails if any symbolic rule does not pass. Session
output is archived under `sessions/`.
