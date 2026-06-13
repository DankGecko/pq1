# Pinned bytecode codehashes

> ## ✅ Build-reproducibility repaired + re-pinned + re-discharged (2026-06-13)
>
> `contracts/smart-wallet/foundry.lock` was repaired this date: its
> account-abstraction pin (v0.7.0, `7af70c8`) **did not compile** — the code
> imports `account-abstraction/legacy/v06/*`, a layout that only exists in
> **v0.8.0+**. The lock now pins AA **v0.8.0** (`4cbc060`); the project
> compiles from a clean checkout again.
>
> Because the wallet/factory pins had been bound to a dev build whose exact
> solady/AA commits were **never recorded in `foundry.lock`** (the lock had
> been stale w.r.t. the code since the v0.9→v0.6 retarget; the relevant solady
> files froze 2025-12-04, so the old `0x43c654…`/`0xfa2922…` are not
> reproducible from any public solady commit), the wallet + factory codehashes
> were **RE-PINNED 2026-06-13 to the reproducible foundry.lock build** (AA
> v0.8.0 + solady `90db92ce` + solc 0.8.28/via_ir, forge 1.7.1) — see the
> pinned values below — and the **full Halmos A3.2/A3.3/A3.4 discharge was
> RE-RUN against the new codehashes** (`make -C contracts/verification
> verify-bytecode`, patched halmos `v0.3.3` + z3 `4.12.6`): **38/38 rules
> PASS on BOTH the default-profile and deploy-profile bytecode** (0 fail, 0
> error). So the lock → reproducible build → pinned codehash → symbolic proof
> chain is internally consistent again.
>
> **Notes:**
> * **SPHINCsC10Asm (verifier) pins UNCHANGED** — it imports no libraries, so
>   it is lib-version-independent. Default-profile `0xf1ef…fef5` matches; the
>   deploy-profile `0xeb1e3fcd…` matches the **on-chain Base Mainnet** verifier
>   (`0xdDE4D290…`), confirming the toolchain is deployment-faithful.
> * **⚠️ The deployed Base Mainnet wallet/factory are NOT byte-reproducible**
>   from the repaired lock. Rebuilding with the **exact deployed immutables**
>   (`_entryPoint = 0x5FF1…`, `c10Verifier = 0xdDE4…`, deploy profile) gives
>   wallet `0x1333ed8a…` vs on-chain `0xdc9a082f…` and factory `0x23a69d2e…`
>   vs on-chain `0x045bb5e4…` — immutables identical, so the difference is
>   **purely library bytecode** (solady/AA): the deployed contracts used the
>   original, now-lost lib commits. Consequence: the A3.2/A3.3/A3.4 rules
>   discharge a **reproducible re-build**, not the live wallet/factory
>   bytecode (`PinnedBytecodeImmutableLemma` bridges instances only WITHIN a
>   lib set). What still holds for the live contracts is the **logic-level**
>   argument (the rules are control-flow over PQSigner's own source with the
>   verifier uninterpreted — independent of the solady regions that differ);
>   the verifier itself is byte-identical to deployed. **This needs a
>   maintainer decision (recover deploy-time libs vs accept logic-level) —
>   see [`DEPLOYED_BYTECODE_PIN_CAVEAT.md`](DEPLOYED_BYTECODE_PIN_CAVEAT.md).**

Each `solidity*_compiles_correctly` axiom in `Bridge/Refinement.lean`
is bound to a specific runtime codehash. When that codehash changes,
the corresponding discharge artifact (Halmos session, Certora
rule-set, or differential test) must be re-run before the pin is
updated.

This file is the canonical pinning record. It is parity-tested at CI
by `contracts/smart-wallet/test/PinnedCodehashes.t.sol`, which
asserts that the deployed `address(<contract>).codehash` equals the
pinned value below. Any drift fails CI.

## Pinned values (re-pinned 2026-06-10)

> **Re-pinned 2026-06-10** after the bootstrap few-time-cap fix:
> `PQSmartWallet._validateSignature` now bumps `bootstrapUses` in the
> VALIDATION phase (mirroring the slot path) instead of the deferred,
> credit-gated bump in `addOwnerBytes`. Every accepted Type-1 signature is
> therefore counted revert-proof under ERC-4337 v0.6, closing the
> `PQBootstrapCapEvasion` under-count (CLAUDE.md invariant #7). The Lean
> model (`Wallet/ValidateUserOp.lean::bumpForOwner`) already encoded this
> behaviour, so the model-level proof is faithful; only the deployed
> bytecode moved. The verifier `SPHINCsC10Asm` hash is the 2026-05-31
> fcee705a FORS-htIdx value (unchanged by this edit); the factory moved
> only because it imports the edited wallet into its compilation unit.
>
> **Discharge status (updated 2026-06-10, strengthened).** The A3.*
> bytecode discharges are **run** with a patched Halmos (`halmos/` — see its
> README; stock 0.3.x has a SHA-256 precompile sort bug, fixed by a one-line
> uninterpreted-function-sort patch). The full symbolic suite PASSES over all
> inputs against these exact codehashes, certified in the same flow by
> `PinnedCodehashes.t.sol`, on BOTH profiles:
>   * **A3.2 (wallet validate)** — `discharged-bytecode`: pointwise
>     equivalence to the Lean model (`HalmosValidateUserOpEquiv`) + 8
>     per-property rules (`HalmosValidateUserOp`) on `0x43c654…a06a`, incl.
>     non-bypass (I-1 analogue) and the validation-phase cap bump.
>   * **A3.2-exec (wallet execute)** — `discharged-bytecode`: pointwise
>     equivalence of `executeWithOffchainCount` /
>     `executeBatchWithOffchainCount` to the Lean `Execute` model over a
>     **symbolic ownerIndex** (`HalmosExecuteEquiv`, 6 rules) + the 6
>     per-property rules (`HalmosExecute`). The emitted external CALL's
>     delivery is A4, not A3.2 (see the harness header).
>   * **A3.3 (factory)** — `discharged-bytecode`: 5 rules (createAccount ⟺
>     precondition iff + postconditions, already-deployed early-return, 3
>     install-gate rejects) on `0xfa2922…7c3c`.
>   * **A3.4 (owner table)** — `discharged-bytecode`: `HalmosMultiOwnable`
>     (7 rules) — `addOwnerBytes`/`removeOwnerAtIndex`/`initialize` pointwise
>     vs the Lean `Storage` model + `ownerAtIndex` read parity, on the
>     current embedding wallet codehash. (Replaces the prior stale Certora
>     artifact, which had not been re-run after the codehash moved.)
>   * **A3.1 (verifier)** — `discharged-bytecode-partial`: 3 input-gate rules
>     (length/N-mask) on `0xf1ef…fef5` by Halmos; an executable
>     Lean↔FIPS↔bytecode KAT on the digest/htIdx sub-layers (`lake exe
>     verify-test-vectors`, 10/10); the full SHA-256-heavy functional
>     equivalence is EMPIRICAL only (bytecode 10-vector KAT + ~250-mutant
>     screen). The Lean refinement (`verifyRefined_eq_spec`) is `rfl` over a
>     spec that is NOT executably faithful on reconstruction — the A3.1
>     equality is currently false as stated; see `docs/A3_1_VERIFIER_GAP.md`.
> Reproduce: `make -C contracts/verification verify-bytecode`. SHA-256 is an
> uninterpreted function in every Halmos run (the named A1 boundary).

**default profile (`runs=200`)** — the dev/test build the symbolic suite runs against (wallet/factory RE-PINNED 2026-06-13 to the reproducible foundry.lock build; verifier unchanged):

```
PQSmartWallet         0xaa85654b8bcd6e63983907bfe3332d6f543e7a32839f7afd9f22b69ba1983730
PQSmartWalletFactory  0xa2cfb800ea3766f03da2288ee31dc7e470edf3a1f39e3dbca50104f6079ee6aa
SPHINCsC10Asm         0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
```

**deploy profile (`runs=999999`)** (wallet/factory RE-PINNED 2026-06-13; verifier unchanged and matches on-chain Base Mainnet):

```
PQSmartWallet         0x8c6baad3e5ddbb132d3d26d81ad35a85f608fdb2b8a2f5980171839539c4f490
PQSmartWalletFactory  0x4d1e1edfdd55f0a9021d3f8406ba27540c7373d4019b49759b5e8e8c5e058a02
SPHINCsC10Asm         0xeb1e3fcd38c7cd5f7b08352c298b34bd114d83f7dbd755b122c41eda2aab2cc5
```

**deploy profile (`runs=999999`)** — the production build (pinned + certified 2026-06-10):

```
PQSmartWallet         0x551c4e03bbd433a5929828ab19caac13a94ca9e2be6074cf3e18c7d926034c22
PQSmartWalletFactory  0x5feb7955252e54bcbbf44062295bdeb45f3dea13c4ef7fb1ba579196d84da4b9
SPHINCsC10Asm         0xeb1e3fcd38c7cd5f7b08352c298b34bd114d83f7dbd755b122c41eda2aab2cc5
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
```

Both profile sets live in `contracts/smart-wallet/test/PinnedCodehashSelector.sol`
(picked by `$FOUNDRY_PROFILE`) and are certified by `PinnedCodehashes.t.sol`
under each profile. **The symbolic suite is executed against BOTH profiles'
bytecode** (`run_halmos.sh` runs `default` then `deploy`; set
`PQ1_HALMOS_SKIP_DEPLOY_SYMBOLIC=1` only for fast local iteration) — so the
production `runs=999999` bytecode is symbolically discharged directly, not by
a "control flow is identical across profiles" argument.

Within a single profile, an **immutable-window lemma**
(`PinnedBytecodeImmutableLemma.t.sol`) additionally proves, exhaustively over
every byte, that each contract's runtime differs from its pinned instance
**only inside 32-byte windows holding the two constructor immutables**
(`_entryPoint`/`implementation` and `c10Verifier`, plus the wallet's Solady
EIP-712 `_cachedThis`/`_cachedDomainSeparator`). So a symbolic rule proved
against one instance transports to every OTHER instance of that same compiled
artifact — e.g. the harness's mock-verifier/test-EntryPoint instance to a real
deployment with the production verifier + EntryPoint addresses — modulo those
certified-located immutables. (This lemma is an intra-profile instance bridge;
the cross-profile coverage comes from actually running both profiles, above.)

## EntryPoint v0.6 (cited-TCB)

```
EntryPoint v0.6 address (mainnet)  0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
```

Discharge for this is cited (OpenZeppelin / ChainSecurity / Spearbit
audits + 18+ months mainnet operation). The Lean axiom
`Bridge.EntryPoint.entrypoint_honest` (A2) is left as-is per user
decision.

## EVM SHA-256 precompile (cited universal Ethereum TCB)

```
EVM precompile address  0x0000000000000000000000000000000000000002
```

Discharge is cited universal Ethereum TCB (consensus-client
conformance: geth, reth, erigon, nethermind). Empirically backed by
`test/PinnedCodehashes.t.sol::test_sha256_precompile_{abc,empty}_kat`
which verifies the precompile against NIST CAVS KAT vectors.

## Compiler / optimiser pin

These codehashes are produced by:

```
solc 0.8.28
optimizer = true
optimizer_runs = 200
via_ir = true
evm_version = "prague"
```

The `[profile.deploy]` profile uses `optimizer_runs = 999999` which
produces different bytecode; those production codehashes are pinned in
the **deploy profile** block above (captured + certified 2026-06-10) and
covered by the same symbolic discharge via the immutable-window lemma.
`make verify-bytecode` certifies BOTH profiles; set
`PQ1_HALMOS_BOTH_PROFILES=1` to additionally re-run the symbolic suite
under the deploy profile (the control flow is profile-independent).

## Re-pinning procedure

When a legitimate source change requires the bytecode to drift:

1. Run `forge test --match-test test_codehash_pinned_or_print -vv` to
   capture the new codehash(es) from the log output.
2. Update the constants in `test/PinnedCodehashes.t.sol`.
3. Update this file.
4. For each changed codehash, re-run the corresponding discharge
   artifact (all via `make -C contracts/verification verify-bytecode`,
   which runs the whole suite on both profiles):
   - PQSmartWallet     → `HalmosValidateUserOpEquiv` + `HalmosValidateUserOp`
                         (validate) and `HalmosExecuteEquiv` + `HalmosExecute`
                         (execute); `HalmosMultiOwnable` (the embedded
                         owner-table, A3.4)
   - PQSmartWalletFactory → `HalmosFactory`
   - SPHINCsC10Asm     → `HalmosVerifier` (input gates) + `cross_validation/`
                         Lean ↔ Rust ↔ Solidity differential +
                         `SPHINCsC10AsmAdversarial`
5. Record the new discharge artifact ID (session hash / rule-set hash)
   in `AXIOM_STATUS.json`.
6. Re-run `lint_axioms.sh` and `make verify-audit` to confirm no
   regression.
