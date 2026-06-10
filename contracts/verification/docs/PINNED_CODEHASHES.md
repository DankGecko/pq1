# Pinned bytecode codehashes

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
> **Discharge status (updated 2026-06-10).** The A3.* bytecode discharges
> have now been **run** with a patched Halmos (`halmos/` — see its README;
> stock 0.3.3 has a SHA-256 precompile sort bug, fixed by a one-line
> uninterpreted-function-sort patch). 19 symbolic rules PASS over all inputs
> against these exact codehashes, certified in the same flow by
> `PinnedCodehashes.t.sol`:
>   * **A3.2 (wallet)** — `discharged-bytecode`: 14 rules (8 validate + 6
>     execute) on `0x43c654…a06a`, incl. non-bypass (I-1 analogue) and the
>     validation-phase cap bump.
>   * **A3.3 (factory)** — `discharged-bytecode`: 2 rules (squat-defence I-8,
>     wrong-chainId) on `0xfa2922…7c3c`.
>   * **A3.1 (verifier)** — `discharged-bytecode-partial`: 3 input-gate rules
>     (length/N-mask) on `0xf1ef…fef5` by Halmos; the full SHA-256-heavy
>     functional equivalence stays on the Lean refinement
>     (`verifyRefined_eq_spec`, incl. htIdx) + the 10 KAT vectors.
> Reproduce: `make -C contracts/verification verify-bytecode`. SHA-256 is an
> uninterpreted function in every Halmos run (the named A1 boundary). A3.4
> (multiownable) logic is unchanged.

**default profile (`runs=200`)** — the dev/test build the symbolic suite runs against:

```
PQSmartWallet         0x43c65420691792d7f0f63dab95f47ab7adb649df4c83f432bd3cf2c95db3a06a
PQSmartWalletFactory  0xfa2922b4fadb81b4475307504890d68f2e3d9be97c7e5e9aeeba6e84110d7c3c
SPHINCsC10Asm         0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
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
under each profile. Because the two builds differ only in the optimiser's
instruction selection — not control flow — an **immutable-window lemma**
(`PinnedBytecodeImmutableLemma.t.sol`) additionally proves, exhaustively over
every byte, that each contract's runtime differs from its pinned instance
**only inside 32-byte windows holding the two constructor immutables**
(`_entryPoint`/`implementation` and `c10Verifier`, plus the wallet's Solady
EIP-712 `_cachedThis`/`_cachedDomainSeparator`). So a symbolic rule proved
against one instance transports to every instance (and across profiles) modulo
those certified-located immutables.

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
   artifact:
   - PQSmartWallet     → `halmos --contract HalmosValidateUserOp` and `halmos --contract HalmosExecute`
   - PQSmartWalletFactory → `certoraRun certora/confs/PQSmartWalletFactory.conf`
   - PQMultiOwnable    → `certoraRun certora/confs/PQMultiOwnable.conf`
   - SPHINCsC10Asm     → `cross_validation/` Lean ↔ Rust ↔ Solidity differential
5. Record the new discharge artifact ID (session hash / rule-set hash)
   in `AXIOM_STATUS.json`.
6. Re-run `lint_axioms.sh` and `make verify-audit` to confirm no
   regression.
