# The claim — exactly what is and isn't proven (2026-06-14)

This file is the single source of truth for **what you may publicly claim**
about the PQSmartWallet formal-verification stack. It is deliberately
conservative. If a marketing line is not derivable from the "✅ Claimable"
section below, do not ship it.

> ## 🛑 CRITICAL — `theft_free` is currently VACUOUS (2026-06-14)
>
> An adversarial audit found and **reproduced (kernel-checked, no `sorryAx`)**
> a derivation of `False` from the `lean/` crypto axiom set: the
> `EUF_CMA_SPHINCSplusC` axiom (`∀ vk transcript m s, isForgery … → False`)
> is **inconsistent**. A genuine valid KAT signature at the *empty transcript*
> satisfies `isForgery` (since `verify` now accepts valid sigs, post commit
> `5055d66`), so `cannot_forge_without_breaking_SHA256 … : False`. **Because
> `theft_free` / `theft_free_bytecode` / `cannot_forge_without_breaking_SHA256`
> / `theft_free_with_calldata_binding` depend on this axiom set, they are
> currently VACUOUSLY TRUE and establish NOTHING about wallet safety.** DO NOT
> claim theft-freedom until `EUF_CMA` is restated to a consistent shape and
> `theft_free` is re-derived. Root cause + fix options:
> [`EUF_CMA_INCONSISTENCY.md`](EUF_CMA_INCONSISTENCY.md). Scope: the
> *component* proofs below (wallet-model invariants, §33 extracted functional
> proofs, Halmos bytecode-equivalence, A3.1 verifier KAT) do **not** depend on
> the crypto axioms and remain valid; only the top-level theft-freedom
> composition is hollow. (Secondary: `sha256_injective_on_fixed_length` is also
> a false axiom — latent, non-detonatable only because `lean/` is mathlib-free.)

---

## ✅ Claimable (true, reproduced) — SEE THE 🛑 BANNER: #1 below is SUSPENDED

> **The PQSmartWallet's on-chain control flow is formally verified, and the
> verification is connected to the deployed bytecode.** A Lean 4
> kernel-checked theorem (`theft_free`, 0 `sorry`, an explicit 11-axiom
> base) proves theft-freedom over a faithful model of the wallet; and the
> **wallet `validateUserOp` / `executeWithOffchainCount` /
> `executeBatchWithOffchainCount`, the factory `createAccount`, and the
> `PQMultiOwnable` owner table** are each proven, by symbolic execution of
> the **deployed runtime bytecode** (Halmos + z3, both compiler profiles,
> pinned codehashes), to be **pointwise-equal to those Lean models** over
> symbolic inputs — including a genuinely ∀-quantified owner index on every
> money-moving path.**

Specifically and defensibly:

1. **Kernel proof. 🛑 SUSPENDED 2026-06-14 — see the banner above.**
   `theft_free` is `sorry`-free and kernel-checked, BUT its 11-axiom closure
   includes the **inconsistent** `EUF_CMA_SPHINCSplusC` (+ the three `∀_,True`
   crypto shapes), so the theorem is **vacuously true and carries no force**
   until A5 is restated. The kernel-checked *component* proofs that do NOT
   depend on the crypto axioms (the wallet-model invariants — `combinedCap_inductive`,
   `bootstrap_unremovable`, `eip1271_forbids_bootstrap`, `factory_requires_bootstrap_sig`,
   `create2_*`, etc.; verified via `#print axioms` to close over only
   `propext`/`Classical.choice`/`Quot.sound`) remain valid. The theft-freedom
   *composition* is reinstated only after the EUF-CMA fix.
2. **Control-flow bytecode discharge.** 38 Halmos rules pass on **both** the
   `default` (runs=200) and `deploy` (runs=999999) profiles' deployed
   bytecode, against pinned codehashes — validate (pointwise + per-property;
   the wrapper ownerIndex is covered by enumerating the installed set
   `{0,1,2}` + concrete reps for the unset partition + a symbolic sweep over
   the installed slots `{1,2}` — the unset partition cannot be swept
   symbolically, a disclosed Halmos dynamic-bytes-getter ceiling), execute
   (pointwise over a genuinely symbolic ∀ ownerIndex + atomicity), factory
   (`createAccount ⟺ precondition` iff), owner-table (add/remove/initialize
   pointwise + read-parity). Reproduced 2026-06-11 (`make verify-bytecode`).
3. **The bootstrap-cap bug is really fixed.** The few-time-cap under-count
   (`PQBootstrapCapEvasion`) is closed in the validation phase and locked by
   tests; `forge test` 108/108. Reproduced 2026-06-11.
4. **Verifier executable Lean↔bytecode KAT (full functional, 2026-06-13).**
   `lake exe verify-test-vectors` runs the executable Lean
   `Spec.Signature.verify` over the byte-decoded signature and reports
   **full-verify 10/10** — the Lean spec **accepts the 4 valid vectors and
   rejects the 6 negatives**, matching the deployed verifier, alongside the
   digest + hypertree-index layers (all hard checks, non-zero exit on drift).
   The Lean verifier model is now **executably faithful** to the deployed
   bytecode on the KAT corpus. Reproduced 2026-06-13.
5. **Verifier negative direction.** The deployed verifier bytecode rejects a
   ≈250-mutant wrong-accept battery and the 6 negative KAT vectors, and
   accepts the 4 valid vectors (`forge test`). Reproduced 2026-06-11.
6. **Byte-bound to the deployed Base Mainnet contracts.** The bytecode the
   control-flow discharge runs against is the bytecode on chain. The
   deploy-time lib set is recorded in `foundry.lock` (account-abstraction
   `f54584e` = ERC-4337 v0.9 release; solady `90db92ce`, bytecode-irrelevant),
   and `test/DeployedBytecodeReproCheck.t.sol` replays the production CREATE2
   deploy (Arachnid `0x4e59…`, salt 0, chain id 8453, deploy profile),
   reproducing the live verifier `0xdDE4…`, wallet impl `0x31e49D24…`, and
   factory `0xe8CE78CD…` — both **addresses and full runtime codehashes**
   (`0xeb1e3fcd…`, `0xdc9a082f…`, `0x045bb5…`). The Halmos discharges
   (pinned harness instances) transport to these via
   `PinnedBytecodeImmutableLemma`, whose immutable-window premise is grounded
   against the actual on-chain bytecode (the only deployed-vs-rebuild deltas
   are the EIP-712 immutable cache and the implementation-address immutable).
   Reproduced 2026-06-13.

The honest trust base for (1)–(2): the Lean kernel; that a Halmos+z3 rule is
a sound solver session (the harness↔property and `LeanModel.sol`↔Lean-file
transcriptions are in the TCB, not Lean proof terms); SHA-256 modeled as an
uninterpreted function; and the verifier modeled as an uninterpreted function
inside the wallet rules (which is exactly what makes them tractable and what
A5/A3.1 are supposed to discharge separately).

---

## ❌ NOT claimable (the named gaps)

Do **not** say any of the following:

* ~~"The smart contracts are fully mathematically proven to the bytecode."~~
  The verifier's **∀-signature** functional equivalence is still carried by
  testing + the executable Lean KAT differential, not a symbolic ∀ proof —
  see below.
* **(RESOLVED 2026-06-13 — was a gap, now claimable.)** "The A3.2/A3.3/A3.4
  Halmos proofs are byte-bound to the *deployed* wallet/factory bytecode." A
  brief interim finding (lost-libs) was **overturned**: the deploy-time lib
  was recovered (`foundry.lock` pins account-abstraction `f54584e`, the
  ERC-4337 v0.9 release, whose `legacy/v06` differs from the v0.8.0 tag), and
  `test/DeployedBytecodeReproCheck.t.sol` replays the production CREATE2
  deploy (Arachnid, salt 0, chain id 8453, deploy profile) to reproduce the
  live impl `0x31e49D24…`/`0xdc9a082f…`, factory `0xe8CE78CD…`/`0x045bb5…`,
  and verifier `0xeb1e3fcd…` **exactly — addresses and codehashes**. See
  Claimable #6 and `DEPLOYED_BYTECODE_PIN_CAVEAT.md`.
* ~~"The SPHINCS+C10 verifier's functional equivalence to bytecode is proven
  for all signatures."~~ It is validated on the **10-vector KAT** (executable
  Lean↔bytecode, both directions) + the ~250-mutant wrong-accept screen, not
  by a symbolic ∀-signature proof (intractable under uninterpreted SHA-256).

The three-way **Rust↔Solidity↔Lean** differential IS now real on the full
functional verify (the Lean leg was made executably faithful 2026-06-13 —
see Claimable #4), not just the digest/index sub-layers.

### The remaining ceiling (no longer a *defect*)

`solidityVerifier_compiles_correctly` (A3.1) asserts the deployed verifier
equals the Lean `verifyYulModel` for all inputs. As of **2026-06-13 this
axiom is no longer contradicted by any tested vector**: the two Lean-spec
reconstruction bugs (`chainHash` ADRS field; `loadWord32` tail zero-padding)
are fixed, `Spec.Signature.verify` accepts/rejects all 10 KAT vectors
identically to the bytecode, and `verifyRefined_eq_spec` stays `rfl` over the
now-faithful spec. What remains is **not** a falsity but a *coverage* limit:
the equality is quantified over all 4008-byte signatures, and that ∀ is
discharged by the KAT + mutant screen + executable Lean differential, **not**
by a symbolic ∀ proof — which is intractable while SHA-256 is uninterpreted
(= A1). So A3.1 is `discharged-bytecode` on the corpus, with the ∀-symbolic
equivalence as the standing ceiling (needs Kontrol/KEVM or verified
compilation). History: [`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md).

Also still cited-TCB by decision (not "proven to bytecode"): **A2** EntryPoint
v0.6 honesty, **A4** EVM-executes-per-spec (incl. the emitted-CALL byte
delivery on the execute path), **A5** SPHINCS+C10 EUF-CMA (Barbosa et al.;
the `+C` transition is a cited argument), **A1** SHA-256 precompile = FIPS.

---

## What it takes to reach "fully proven to bytecode"

In dependency order:

1. ~~**Make the Lean verifier executably faithful.**~~ **DONE 2026-06-13.**
   The WOTS+C / hypertree reconstruction layer now byte-matches the deployed
   Yul: `lake exe verify-test-vectors` reports full-verify 10/10 and
   `requireFullVerify` is `true`. A3.1's equality is no longer contradicted by
   any tested vector, and the Lean refinement (`verifyRefined_eq_spec`, still
   `rfl`) carries real faithfulness over the corpus. The remaining work is the
   ∀-signature equivalence as a *citation* to the executable KAT + EUF-CMA,
   not yet a symbolic bytecode proof (step 2).
2. **Discharge the verifier's ∀-signature equivalence on bytecode.** Not
   possible under uninterpreted SHA-256 (the digit branches fork on
   unconstrained symbolic values). Needs an **interpreted-hash reachability**
   engine (Kontrol/KEVM) or **verified compilation** (Verity,
   [`PATH_TO_VERIFIED_BYTECODE.md`](PATH_TO_VERIFIED_BYTECODE.md)). Even Verity
   stops at Yul, leaving A1/A2/A4 as cited-TCB.
3. **Optionally** reduce A2/A4 from cited-TCB to bytecode (Kontrol against the
   deployed EntryPoint) — a large, separate engagement.

Until step 1 lands, the maximal honest headline is the **✅ Claimable**
block above — "control flow proven to bytecode; verifier validated by
testing" — not "fully proven to bytecode."
