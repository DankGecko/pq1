# FV state of the art and newly-possible verifications — 2026-07-19

> Companion to the 2026-07-19 deep adversarial review
> ([`fv-deep-review-2026-07-19-coordinator.md`](../security/adversarial-review/findings/fv-deep-review-2026-07-19-coordinator.md)).
> Supplements — does not replace — the ranked roadmap in
> [`formal-verification-assurance-expansion-2026-07-15.md`](formal-verification-assurance-expansion-2026-07-15.md)
> and the closures asserted in
> [`hardware-formalization-survey-2026-07-17.md`](hardware-formalization-survey-2026-07-17.md).
> This is research and planning, not authority to implement, merge, ship, or
> mutate hardware.

**Method.** Four parallel web-research lanes (Rust toolchains; crypto/protocol
FV; hardware/binary/FI; AI-proving + lifecycle/quantitative) against primary
sources (papers, repos, changelogs, cert registries, vendor docs), accessed
2026-07-19. Each claim is marked **[V]** verified against a primary source,
**[I]** inference from those sources, or **[U]** found but unverifiable.
Known hallucination traps were probed and are listed in §6 — including one
attribution this project has repeated that is **disproven** below.

---

## 1. The "we thought it was impossible" scoreboard

Each row: a closure this repo's own documents assert, and what 2026 SOTA says.

| # | Closure asserted in-repo | 2026-07 verdict | What changed |
|---|---|---|---|
| 1 | ARMv8-M/CMSE ISA semantics — "permanently closed, no public M-profile spec in any framework" | **Still closed at ISA level; open at design level** | Sail/L3/HOL4 remain A-profile only; Arm's public ASL/MRA is A-profile only; the internal v8-M ASL (Reid, FMCAD'16/OOPSLA'17) is still unreleased [V]. But design-level formal work on TrustZone-M exists: Umbra, a formally verified TEE caching framework for TZ-M microcontrollers, model-checked in mCRL2 (DATE 2026), which *found* replay + timing side-channel attacks [V]. SAU region-window logic and NSC-veneer entry rules are small, public, and formalizable from prose docs (CMSE toolchain CVEs 2024-0151 / LLVM 2024-7883 show the entry rules are a live bug area) [V/I]. |
| 2 | Whole shipping-ELF binary verification — NO-GO | **Still closed as whole-ELF; newly practical at region level** | FirmWall (IEEE TIFS 2025): directed symbolic execution of ARM Trusted Firmware-M *binaries*, real CVEs [V]. angr's `pypcode` engine lifts anything Ghidra SLEIGH decodes (Cortex-M33), bypassing VEX's M-profile gaps [V]. Bounded property checks (overflow, layout, veneer placement) on *regions* of the shipping ELF are now feasible. |
| 3 | "BINSEC thumb mode fails uniformly on-box" ⇒ binary CT is dead | **The premise is externally false; the option surface is bigger than the closed framing** | BINSEC has an ARM/Thumb (ARMv7) decoder via unisim_archisec since 0.4.0 (2021); `checkct` gained configurable leakage features (multiplication/dividend/divisor operands) in 0.10.0 (2025-02); current 0.11.2 (2026-06) [V]. The on-box uniform failure therefore likely reflects loader/decoder-selection or v8-M-only encodings (SG/TT/MSPLIM) rather than "no Thumb decoder" [I]. Independently: **CT-PROVER** (FSE 2024) verifies constant-time soundly on **LLVM IR** — Rust emits LLVM bitcode, so the signing path can be CT-checked at IR level today [V]. Rust-industry practice is otherwise source-level secret-independence proofs (libcrux/hax→F\*) + statistical dudect/ctgrind [V]. |
| 4 | OPTIGA/SE050 internals — no RTL, ever | **Still closed** | No RTL exists; certification scope remains IC-platform (PP-0084), which excludes LcsO/APDU behavior. Correction to the survey's cert row: the OPTIGA Trust M lineage is **current** — BSI-DSZ-CC-0961 V7-2024 (EAL6+) valid to 2027-03-23; citing the expired V4-2019 understates it [V]. Keep silicon-E2E + scoped assumptions; nothing new to adopt. |
| 5 | Formal fault-injection verification on M33 | **Still closed at RTL/ISA level; open at software level** | Formal FI verification 2023–2026 is RTL-level and RISC-V-centric (µArchiFI, ARCHIFI, k-FRP, FIVER, VerFI) — not portable to a proprietary M33 core [V]. But software-level formal FI is LLVM-IR-shaped and Rust-compatible in principle: Lazart (Verimag, multi-fault symbolic robustness on LLVM IR) and the CEA/Verimag model-checked countermeasure lineage [V/I]. On-box falsification: ARCHIE (Fraunhofer AISEC) is alive and runs arch-independent fault campaigns on QEMU M-class machines — our own mps2-an505 target [V]. A LLVM-IR multi-fault robustness check of the double-compute→byte-compare→verify chain is a concrete new pilot. |
| 6 | TRNG formal verification | **Still closed for the source; citable scoped evidence exists** | No verified AIS-31/SP800-90B health monitor exists anywhere [V-absence]. But NIST ESV **Certificate #11** names "STM32U5x TRNG" — SP 800-90B Rev B, physical, *full entropy*, 128-bit, vetted AES-CMAC conditioning (CAVP A1729), "Open for Reuse" [V, fetched live]. This is scoped-T evidence, not a proof; the honest framing is "certified entropy source + verified software conditioning path". |
| 7 | Full C10 EUF-CMA machine-checked — person-year research | **Partially unblocked** | The base is stronger than the in-repo framing: MM45's FV-SPHINCSPLUS-EC (ePrint 2024/910) is a *complete* tight SPHINCS+ proof — `FORS_ES.ec` mechanizes standard FORS; the repo is maintained to EasyCrypt r2026.02 with CI [V]. formosa-xmss demonstrates the implementation↔security bridge pattern for hash-based signatures (76 EasyCrypt files incl. `XMSS_Security_RFCAbs.ec`) [V]. C10's deviations remain new work: target-sum/checksum-free WOTS+C has paper-level backing (CRYPTO 2023 constant-sum Winternitz) but no mechanization; FORS+C (ITSRC10) likewise [V]. **Open question to settle first:** whether `WOTS_TW_ES.ec`'s parameter constraints can express `w=8`/`log2_w=3`/checksum-free without forking — unverified [U]. |
| 8 | ITSRC10 binomial/concentration bound — "no stdlib concentration inequalities in EasyCrypt" | **Unblocked in principle, three routes** | Confirmed EasyCrypt stdlib has zero concentration machinery (full-tarball grep) [V]. Routes: (a) **exact finite counting in EasyCrypt**, the same idiom `FORS_ES.ec` uses for the FORS bound — precedent lives in the dependency we already vendor [V]; (b) Coq **mathcomp-analysis** (generic Chernoff + `binomial_distribution.v`) via ssprove [V]; (c) Isabelle/HOL-Probability + AFP concentration entries (Hoeffding, Bennett, Bernstein, McDiarmid) [V]. Note: Coq **infotheo does NOT contain Hoeffding/Chernoff** (Pinsker/Jensen/log-sum only) — do not cite it for this [V]. Cheapest interim: numeric validation of the concrete bound at C10's parameters (days), converting ITSRC10 from an unexamined analytic claim into a parameter-validation statement [I]. |
| 9 | keccak256 must stay an opaque Lean axiom | **Fully unblocked — by this repo's own sibling** | `AlexeyMilovanov/lean-keccak-unrolled`: formally verified, fully computable Keccak-256 + SHA-3 family in Lean 4; golden theorem `keccakF1600_correct` proves the unrolled engine bit-for-bit equal to the spec engine for **all 2^1600 states** (kernel-checked via `bv_decide` + induction); `@[implemented_by]` fast runtime [V]. Its README states it was built for **Verity** — `contracts/verity/` in this repo — to eliminate cryptographic axioms. Caveat: its *test vectors* use `native_decide`; the equivalence theorem itself is kernel-clean [V]. Adoption is days–2 weeks of integration, not research. |
| 10 | Protocol models are hand-written ⇒ permanent model≠artifact risk (SE drivers) | **Unblocked on the Rust side** | hax's ProVerif backend has been used end-to-end: Bertie (post-quantum TLS 1.3 in Rust) — ProVerif (forward secrecy, authentication, HNDL; 1,723 Rust LoC → 20s), F\* (safety/formats), SSProve (key schedule) from one artifact (ePrint 2025/980; OpenSSL-conf 2025) [V]. Industrial use: Signal (PQ libsignal), Nym, SandboxAQ [V]. Reality check: for Signal's SPQR (2025), Cryspen kept **hand-written ProVerif models** and hax→F\*-verified only the implementation core — the backend is real but experimental [V]. A pilot extracting SCP03 / OPTIGA Shielded Connection from our Rust drivers is now a 1–3 person-month, bounded experiment with a demonstrated precedent — the direct follow-up to the M3 vendor re-derivation lesson. |
| 11 | EntryPoint v0.6 boundary stays a cited assumption | **Own-contract FV demonstrated; canonical EntryPoint still unverified** | Certora formally verified Coinbase's ERC-4337 account + factory + MultiOwnable (2024) — the exact codebase family `PQSmartWallet` derives from [V]. No published mechanized verification of the canonical EntryPoint itself exists (KEVM or otherwise) [U-absence]. So the EntryPoint boundary stays cited-TCB, but the wallet-side Halmos/Kontrol route has a mature commercial sibling. |
| 12 | Grover-2⁶⁴ residual formalization | **Stays a cited assumption** | Grover *correctness* is mechanized in QHL/SQIR/QBRICKS/CoqQ; Grover *optimality* (BBBV/adversary/polynomial method) is mechanized nowhere [V/U-absence]. Formalizing it would be a publishable novelty, not an adoption. |
| 13 | Real-valued `Pr[forge]≤ε` half — open, mathlib-free tree | **Newly feasible via a two-project split** | mathlib4 now carries `PMF` (incl. binomial PMF), Hoeffding's lemma, sub-Gaussian machinery, mgf/cgf Chernoff machinery [V]. The mathlib-free firewall is preserved by an interface project (zero deps) defining a ℚ-valued finite-distribution monad + theorem *statements*; a mathlib-enabled project proves the bound against it; the ship tree restates only the statement text, machine-compared in CI, and the proof side is replayed by an external checker [I — engineering pattern, no canonical precedent]. |
| 14 | Independent Lean kernel checking — lean4checker manual, `#print axioms` under-reports | **Cheap hardening available now** | lean4checker is deprecated, merged into the toolchain as `leanchecker` from v4.28.0 [V]. True external checkers exist: **Lean4Lean** (Carneiro; checks mathlib) and **nanoda_lib** (Rust; consumes lean4export; explicit `permitted_axioms` allowlist with hard-error semantics) [V]. The under-report itself (`collectAxioms` missing types; `native_decide` smuggling `Lean.trustCompiler`) was fixed in lean4 #8842, merged 2025-07 [V]; our pinned v4.22.0 likely contains it — verifiable locally by diffing `#print axioms` against a nanoda_lib run [I]. |
| 15 | ARMv8-M/CMSE + SE-internal models (rows 1, 4) | See rows 1/4 | Row 4 unchanged; row 1's *useful subset* is the design-level opening. |

---

## 2. Toolchain upgrades that materially change cost (not "impossible", just cheaper)

- **Aeneas→Lean is now a documented production recipe for crypto primitives.**
  Microsoft reports complete Lean proofs of SymCrypt's Rust **ML-KEM and SHA-3**
  shipping in Windows Insider builds (July 2026): executable standard-derived
  Lean specs validated against official vectors, per-target model merging,
  AI-agent-written proofs gated by the Lean kernel [V]. Field notes for the
  exact blockers we hit (Signal SPQR extraction, BAIF 2026-03): iterator
  combinators, early `return`/`?` inside loops, interior mutability, and —
  critically for our `compute_sphincs_digest_v06` — the generic `Digest` trait
  graph (`hkdf`→`sha2`→`generic-array`→`typenum`) **hangs Charon**; concrete
  one-shot functions over fixed buffers extract fine [V]. ⇒ The F2-full bridge
  is no longer "blocked on a refactor into the unknown"; the recipe and its
  constraints are published.
- **Kani contracts matured**: function+loop contracts composable (0.63 fix),
  `for`-loop contracts (0.66), quantifiers (experimental), SMT backend choice;
  the verify-rust-std campaign runs 16k+ harnesses per change; documented
  production bugs found in s2n-quic/Firecracker/Cedar [V]. Loop contracts make
  verification time iteration-count-independent — the class of our two
  900 s-no-verdict harnesses is the target. Contracts remain `-Z`-gated.
- **hax/libcrux**: hax's actively used backends are F\*/Rocq/SSProve (ProVerif
  experimental); **libcrux-sha2 is HACL\*-verified, `no_std`, alloc-free** — a
  free independent verified reference to differentially cross-check our custom
  SHA-256/HMAC today [V].
- **Creusot 0.9–0.12** added `#![no_std]` compatibility (2026); **Flux** verified
  process/MPU isolation in the production Tock embedded OS (TickTock, SOSP
  2025) — the strongest no_std embedded production verification to date [V].
- **Verus**: `vstd` no_std features landed; PoWER (OSDI 2025) crash-safe
  persistent-state patterns (corruption-detecting writes, atomic multi-log
  commit) are the live reference for deepening our flash-journal pilot [V].
- **TLA+ ecosystem**: TLC remains the right bounded checker; **Quint** adds
  Rust model-based testing via Quint Connect (replay spec traces against the
  Rust implementation) [V]; Apalache's development slowed after the Informal
  Systems spin-out — do not make inductive-invariant checking load-bearing [V].
- **AI provers**: Leanstral 1.5 (Apache-2.0, the local model) is SOTA-tier and
  the only top model built as a Lean compiler-loop code agent; Mistral's own
  Rust→Lean pipeline flagged 47 violated properties / 11 real bugs across 57
  OSS repos [V-vendor]. Nobody publishes mathlib-free embedded-style benchmark
  numbers — **run a ~50-goal internal eval before any model swap** [I]. The
  leverage is the agent layer: Goedel-Architect blueprint decomposition,
  Numina-Lean-Agent loops, Aristotle API escalation for stuck lemmas [V].

## 3. Ranked adoption proposals (research output; each needs its own plan packet)

Ordered by assurance-per-cost against the gaps named in the companion review:

1. **nanoda_lib axiom-allowlist in CI** (days). Permits exactly
   `{propext, Classical.choice, Quot.sound}`; kills the `#print-axioms`
   under-report class (our C5) with an external checker, not another manual
   gate. Highest ratio on this page.
2. **lean-keccak-unrolled integration** (days–2 weeks). Replaces the opaque
   keccak axiom with a kernel-concrete function; shrinks the
   `keccak_sha256_cross_separation` surface from "opaque-function assumption"
   to "concrete-function hardness assumption". Check license + the
   `native_decide` test-vector caveat against our lint rules first.
3. **Fix-then-harden CT assurance** (1–2 weeks): define `make checkct`'s pass
   signal (the survey found it undefined); re-probe the shipping slice on
   BINSEC 0.11.2 via the unisim path with v8-M-free functions; pilot CT-PROVER
   on the signing path's LLVM bitcode as the IR-level leg.
4. **Aeneas extraction of `compute_sphincs_digest_v06`** (2–4 weeks): the
   behaviour-preserving refactor (concrete one-shot SHA-256 over the fixed
   360-byte layout; no `Digest` trait, no iterator combinators, hoisted early
   returns) is now constrained by published field notes; proof target is
   materially easier than Microsoft's completed SHA-3/ML-KEM proofs. Add
   libcrux-sha2 as a zero-cost differential oracle. Closes F2-full + C6 with a
   Lean def *generated from Rust* instead of hand-mirrored.
5. **hax→ProVerif extraction pilot for one SE tunnel** (1–3 p-m, experimental):
   SCP03 first (smaller). Success criterion: the extracted model reproduces the
   hand model's pinned verdicts; failure mode to watch: APDU-framing annotation
   cost. This is the structural fix for the M3 class (driver-derived models
   proving self-consistency).
6. **ITSRC10 exact-counting mechanization** (2–6 p-m): port the `FORS_ES.ec`
   finite-combinatorics idiom to the C10 conditioned game; interim numeric
   validation at concrete parameters (days) downgrades the assumption's
   blast radius immediately.
7. **Two-project mathlib split for the real-valued bound** (1–2 eng-weeks
   scaffolding): ℚ-valued interface + statement-hash CI + external replay.
8. **LLVM-IR fault-robustness pilot** (1–2 weeks): Lazart-class multi-fault
   symbolic check of the FI signing chain (double-compute → byte-compare →
   verify-before-release) on Rust bitcode; complement the source-level FI
   discipline with an executable fault-model counterexample search.
9. **SAU/NSC-veneer config model** (1–2 weeks): hand-model the SAU region
   window logic + CMSE entry rules (Flux/Kani-shaped) from public prose;
   validates our `sau.rs` against the *documented* semantics rather than
   silicon-only receipts. Row-1's feasible subset — do not attempt ISA-level.
10. **Kani contract upgrades for the two no-verdict harnesses** (days each):
    loop contracts to make `erc7730_ir_parse_panic_free` and
    `fmt_p0_const_value_chunks_bind_rows` converge; then enroll both in the
    mutation manifest (they currently have neither a verdict nor a pin).

Deferred/NO-GO unchanged: wholesale rewrites (Verus/Creusot/RefinedRust/Vest);
whole-ELF proofs; Grover optimality; Apalache-dependent inductiveness as a
load-bearing gate; Tamarin-from-code (nothing exists).

## 4. What the review's findings need from this research

- C4/C2 (stale extractions): item 4 gives the durable fix path for the
  aa-userop drift; the tx-merkle waiver can likewise be re-attacked with the
  published refactor constraints rather than waiting on an Aeneas bump.
- C6 (hand-mirrored Lean digest): item 4 replaces the mirrored def with an
  extracted one; item 2 removes the last opaque-hash objection to doing so.
- C10 (format_decimal): Kani contracts (item 2's quantifiers + loop contracts)
  make a symbolic-value formatter proof tractable; enroll it in the mutation
  manifest regardless.
- C5 (lean4checker decorative): item 1 supersedes it.

## 5. Things checked and *disproven* (anti-hallucination ledger)

- **"SampCert verified SHA-256"** — **disproven**: SampCert (leanprover) is a
  differential-privacy library; full-tree grep finds no SHA-256 or hash code.
  Do not cite it for verified hashing. (What exists for Lean SHA-256-shaped
  work: zkgolf's verified *circuits*, and our own kernel `Sha256Impl` +
  CAVP lane; lean-keccak-unrolled for Keccak.)
- **"DeepSeek-Prover-V3"** — no evidence it exists as of 2026-07 [U-absence].
- **"FISSA" / "microct" tools** — not found under those names; nearest real
  artifacts are FIVER/VerFI/Lazart and Microwalk respectively. Do not cite.
- **SideTrail** — both candidate repos 404 (2026-07-19); paper-only, treat as
  unavailable. CT-PROVER is the live LLVM-IR alternative.
- **TN1545** (STM32U5 SESIP technical note) — not publicly findable; UM3387
  Rev (2024-11) is the public guidance.
- **Coq infotheo for Hoeffding** — absent (grep-verified); use
  mathcomp-analysis instead.

## 6. Confidence and boundary

- High confidence (multi-source, primary): rows 3, 7, 8, 9, 13, 14; toolchain
  items in §2.
- Medium: row 1's design-level subset cost; row 10's annotation burden on our
  driver code shape (one public case study); Aristotle API practicality.
- Not established here: whether MM45's `WOTS_TW_ES.ec` accepts `log2_w=3`
  without a fork (settle by a direct instantiation attempt before quoting the
  6–18 p-m estimate further); any silicon/physical claim — this is a
  source-and-literature review; every adoption still needs its plan packet,
  negative controls, and the workflow's gates.
