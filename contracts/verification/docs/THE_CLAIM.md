# The claim — exactly what is and isn't proven (2026-06-14)

This file is the single source of truth for **what you may publicly claim**
about the PQSmartWallet formal-verification stack. It is deliberately
conservative. If a marketing line is not derivable from the "✅ Claimable"
section below, do not ship it.

> ## ✅ EUF-CMA inconsistency RESOLVED for `theft_free` (2026-06-14)
>
> The `EUF_CMA_SPHINCSplusC` inconsistency (a kernel-checked `False` from a
> valid KAT at the empty transcript) is **fixed**. The axiom was restated to a
> consistent **reduction shape** — conclusion is an *opaque* `BreaksHash`
> (never `False`, never assumed false), and `isForgery` now carries a key-bound
> `KeyHistory` so the empty-transcript witness is unformable. Two compiled-in
> guard lemmas (`keyHistory_empty_signs_nothing`, `honest_sig_not_forgery`,
> closure `{propext, Quot.sound}`) fence it. **The old detonator no longer
> type-checks** (`cannot_forge … : BreaksHash`, not `False` — verified). So
> **`theft_free` / `theft_free_bytecode` are SOUND again** (kernel-checked,
> closure = the 11 cited axioms, no `sorryAx`). Details:
> [`EUF_CMA_INCONSISTENCY.md`](EUF_CMA_INCONSISTENCY.md).
>
> **The two faithfulness follow-ups are now ALSO fixed (2026-06-14):** (1) the
> false `sha256_injective_on_fixed_length` was replaced by
> `sha256_collision_resistance` (a consistent disjunctive reduction:
> `equal preimages ∨ BreaksHash`); `theft_free_with_calldata_binding` /
> `sphincsDigest_field_binding` now conclude the honest `∨ BreaksHash` form and
> close over the consistent axiom. (2) the three SHA-256 hardness shapes were
> upgraded from `∀_,True` placeholders to `opaque` Props. So the trust base now
> has **no false / vacuous / inconsistent axioms** — only honest cited
> assumptions (`BreaksHash` shared in `Assumptions.lean`). The dangling+latent-false
> `entrypoint_no_replay` was deleted.

---

## ✅ Claimable (true, reproduced)

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
> money-moving path. The same four control-flow bridges are now **independently
> re-discharged transcription-free by Kontrol/KEVM** — proven directly on the
> deployed bytecode with no hand-written model mirror (30 KEVM proofs; see #2).**

Specifically and defensibly:

1. **Kernel proof (REINSTATED 2026-06-14 after the EUF-CMA fix).** `theft_free`
   and its claim corollaries are `sorry`-free and kernel-checked, with the
   11-axiom closure now **consistent** (the restated `EUF_CMA_SPHINCSplusC`
   concludes the opaque `BreaksHash` reduction, not `False`). What `theft_free`
   actually says: it is a **conjunction** — conjunct 1 (the safety guarantee:
   no wallet balance decrease without the deployed verifier accepting an
   installed-owner C10 signature over the op's `sphincsDigest`) is **EUF-CMA-free**,
   resting on A2 (`entrypoint_honest`) + A3.1 (`solidityVerifier_compiles_correctly`)
   + A1/A4; conjunct 2 (producing such a signature for an un-signed message
   would break SHA-256) is the **cited** Barbosa-et-al. reduction. So the
   substantive theft-freedom content is conjunct 1 (control-flow, discharged
   to bytecode); the cryptographic infeasibility is cited, not mechanised.
   Reproduced 2026-06-14 (`make verify-audit`). (The variant
   `theft_free_with_calldata_binding` now closes over the consistent
   `sha256_collision_resistance` and concludes the honest `preimage eq ∨
   BreaksHash` form — the false `sha256_injective` axiom is gone.)
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
   **Transcription-free Kontrol/KEVM re-discharge (2026-06-15).** The same four
   control-flow bridge axioms (A3.2 validate, A3.2-exec, A3.3 factory, A3.4
   owner-table) are now ALSO proven directly on the deployed bytecode by **KEVM
   symbolic execution via Kontrol** — an engine independent of Halmos, with **no
   hand-written `LeanModel.sol` mirror in the loop** — so the property is stated
   once and checked against the bytecode itself. 30 KEVM proofs across 5
   harnesses (`contracts/verification/kontrol/`): A3.4 = 12/12, A3.2-exec = 8/8,
   A3.3 = 6/6, A3.2-validate (the non-bypass I-1) = 4/4. This **retires the
   `LeanModel.sol` hand-transcription element from the TCB** for all four
   control-flow axioms (Halmos stays as the fast CI gate; the two engines agree).
   Reproduced 2026-06-15 (`make verify-kontrol`; needs a Nix-installed K backend).
   The verifier's ∀-signature equivalence (A3.1) is **not** a Kontrol target —
   it is intractable under symbolic SHA-256 in both engines (KEVM models the
   `0x02` precompile as the SMT-uninterpreted `Sha256raw`), so it stays
   KAT-validated (see #4/#5). See [`KONTROL_SCOPING.md`](KONTROL_SCOPING.md).
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

The honest trust base for (1)–(2): the Lean kernel; and that the bytecode
discharge is a sound symbolic-execution session. For the four control-flow
bridge axioms (A3.2/A3.2-exec/A3.3/A3.4) that discharge now exists in **two
forms**: (a) a Halmos+z3 session — the fast CI gate — whose harness↔property
correspondence AND the `LeanModel.sol`↔Lean-file **transcription** are in the
TCB; and (b) a transcription-free **Kontrol/KEVM** session that proves the
property directly against the bytecode with **no `LeanModel.sol` mirror**, so the
transcription element drops out and the residual is KEVM-soundness (the canonical
EVM semantics) + the Kontrol session. The two engines agree, so the
hand-transcription is no longer a load-bearing trust assumption for the
control-flow axioms. Still in the TCB regardless of engine: SHA-256 modeled as an
uninterpreted function, and the verifier modeled as an uninterpreted function
inside the wallet rules (which is what makes them tractable and what A5/A3.1
discharge separately — the verifier's ∀-signature equivalence stays out of both
engines under symbolic SHA-256).

---

## ⚠️ Scope of the proof (read before quoting "theft_free proven")

A faithfulness audit (2026-06-14, mutation testing + coverage matrix +
per-axiom falsifiability — [`FAITHFULNESS_AUDIT_2026-06-14.md`](FAITHFULNESS_AUDIT_2026-06-14.md))
confirms the verification is **faithful within its declared scope** (8/9
injected real defects were caught, most at compile time), but the scope is the
**on-chain contract + the SPHINCS+C10 spec only**:

- **5 of the 9 CLAUDE.md non-negotiable invariants are NOT formally proven.**
  #1 dual-chip XOR seed split, #2 hardware PIN three-way lockstep, #3 E2E SE
  tunnels, #4 TrustZone secret isolation, and the trusted-display clear-signing
  pipeline are firmware/secure-world/hardware properties with **zero Lean
  coverage** — they rest on silicon E2E tests + the security-review docs. Do not
  let "theft_free proven" be read as a device-wide guarantee.
- **The P1 bootstrap-cap proof-coverage hole is now CLOSED (2026-06-14).**
  `capOk_bootstrap_implies_strict` + `validateSignature_bootstrap_cap_strict`
  give the bootstrap few-time cap (`bootstrapUses < MAX_BOOTSTRAP_USES`,
  invariant #7) the same proof coverage the slot path had — the `<`→`≤`
  mutation now fails to compile. Two-gate parity.
- **`replaySafeHash` domain separation is now MODELED (Gap-3, 2026-06-14).**
  `Wallet/OffchainBinding.lean` proves an off-chain-nested value is never any
  UserOp `sphincsDigest` (the RAW32 forgery-oracle defense), reducing it to one
  new cited axiom `keccak_sha256_cross_separation` (cross-hash separation,
  `∨ BreaksHash`; `keccak256` opaque). `theft_free`'s closure is unchanged.
- **A4 was made content-bearing (2026-06-14).** `evm_bytecode_executes_correctly`
  is now `∀ c, evmDeliversCall c` (opaque predicate) instead of `: True` — it
  *names* the EVM-delivery assumption it always stood for. **Honest scope
  (corrected by faithfulness-audit pass-2):** A4 (and A1) are present in
  `theft_free`'s 11-name closure as NON-CONSUMED TCB markers (surfaced via
  `have` bindings so `#print axioms` self-documents the on-chain TCB), NOT
  semantic premises — `theft_free`'s genuine 9 premises are A2 + A3.1 + A5(×4)
  + kernel (deleting the markers leaves it proven). A4's content-bearing *type*
  is the real gain; the earlier "load-bearing in theft_free" wording was an
  over-claim. The `lint_axioms` gate now reports zero `: True`-typed axioms.
  `keccak256_pure`
  (extracted) remains an uninterpreted total-function postulate — benign and
  standard for Aeneas hash boundaries, carrying the keccak binding by external
  citation (Rust KATs + EVM conformance), not in-Lean content.

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
equivalence as the standing ceiling. **Confirmed 2026-06-15: Kontrol/KEVM does
NOT close this** — although Kontrol is now installed and used for the four
control-flow axioms (A3.2/A3.3/A3.4, see #2), KEVM models the `0x02` precompile
as the SMT-uninterpreted `Sha256raw` on symbolic input, so the verifier's digit
branches fork exactly as under Halmos — *symbolic* engines fork on every digit.
But that is not the only path: a **deductive interpreter-refinement proof in
Lean** closes the ∀-signature model↔spec equality with the hash kept **opaque**
(induction on loop-iteration count, no symbolic search, no interpreted-hash
engine) — the upstream SPHINCS- `/verity` demonstrates it (`c13_refines_spec`,
zero hash axioms for Keccak), and PQSigner already has a half-built
`contracts/verity/` scaffold for it. The genuine residuals are then the
model↔deployed-bytecode hand-transcription + SHA-256 byte-addressed memory, not
the digit explosion. Corrected analysis + closure path + effort in
[`A3_1_CLOSURE_PATH.md`](A3_1_CLOSURE_PATH.md); history in
[`A3_1_VERIFIER_GAP.md`](A3_1_VERIFIER_GAP.md).

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
   engine or **verified compilation** (Verity,
   [`PATH_TO_VERIFIED_BYTECODE.md`](PATH_TO_VERIFIED_BYTECODE.md)). **NOTE:
   Kontrol/KEVM does NOT qualify** — despite now being installed and used for the
   control-flow axioms, KEVM's `0x02` precompile is SMT-uninterpreted on symbolic
   input (`Sha256raw`), so it hits the same wall as Halmos (confirmed
   2026-06-15). Even Verity stops at Yul, leaving A1/A2/A4 as cited-TCB.
3. **Optionally** reduce A2/A4 from cited-TCB to bytecode (Kontrol against the
   deployed EntryPoint) — a large, separate engagement.

Until step 1 lands, the maximal honest headline is the **✅ Claimable**
block above — "control flow proven to bytecode; verifier validated by
testing" — not "fully proven to bytecode."
