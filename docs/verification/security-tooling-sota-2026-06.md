# Security Tooling SOTA — adoption guide for PQ-Signer (June 2026)

> **Scope.** What exists, in mid-2026, that PQ-Signer could **adopt or build** to harden
> the firmware, the contracts/Yul verifier, the SCA/FI posture, and the formal-verification
> track — across LLM/agentic tooling, classical verification, and hardware. Produced from a
> three-pass deep-research sweep (~250 systems) plus a local read of the `SPHINCS-` and
> `LeanLoop` repos and PQ-Signer's own `secure/src/crypto.rs`.
>
> **How to read.** Each item is rated **adopt-now · pilot · reference-architecture ·
> build-in-house · skip**, and marked **[validated]** (a primary source was fetched and
> quoted, or confirmed in-repo) vs **[unverified]** (search-snippet only — confirm before
> relying). The honest meta-conclusion: **no off-the-shelf autonomous system targets
> PQ-Signer's stack** (no_std Rust on Cortex-M33 + a hand-written Yul SPHINCS+ verifier +
> SCA/FI + Lean/Aeneas). The wins below are an *assembled* toolchain, not a product you buy.

---

## 0. The load-bearing finding: SPHINCS+ FI countermeasure — already handled [validated]

Three independently-fetched sources — **Genêt, "On Protecting SPHINCS+ Against Fault Attacks"
(TCHES 2023/2, eprint 2023/042)**, **eShard Expert Review #3**, and **SLasH-DSA (arXiv
2509.13048, 2025)** — converge on one hard lesson:

> For SPHINCS+/SLH-DSA, **verify-before-release is necessary but NOT sufficient** against
> grafting/WOTS+-reuse faults. A random faulted signature is *more* likely to still verify
> than to fail verification, so verify-after-sign catches only a minority of faults. The only
> literature-endorsed countermeasure is **full redundant recomputation of the signature with
> byte-compare + abort-on-mismatch.** Randomized signing (`opt_rand`) is **not** a fault
> countermeasure (SLasH-DSA forged the randomized parameter set).

**PQ-Signer already implements exactly this**, and cites the paper. `secure/src/crypto.rs::
c10_sign_verified_with_progress` is a 7-step CFI-guarded chain: rate-limit → fresh 3-source
`opt_rand` → DPA shuffle seed → **SIGN_A → SIGN_B (independent recompute) → constant-time
byte-equality of both 4008-B sigs (abort on mismatch)** → verify-before-release (FI sentinel)
→ CFI step-counter. The comment at `crypto.rs:87` reads *"Verify-after-sign alone is
insufficient… Two signs over identical inputs MUST be byte-identical"* and cites
**"RFC 9814 §A.2 / Genêt TCHES 2023."**

**Status: closed.** The deepest concern the entire literature sweep could raise is mitigated
correctly. Three follow-ups (filed in work-todo):

1. **Doc gap (fixed 2026-06-16):** CLAUDE.md previously undersold this as "double-evaluated
   verify." Corrected to "double-compute → byte-compare → verify."
2. **Residual to prove empirically:** A and B use the *same* shuffle seed (required for
   byte-equality), so they are register-level identical — a fault that reproduces identically
   across both (permanent stuck-at / clock-locked repeating glitch) could pass `ct_eq`; the
   verify gate is the backstop. **Run the rainbow `fault_skip` sweep over `tools/sca/fi_target`
   + `c10_sign_target`** (which mirror this function bit-for-bit) to prove no single fault both
   corrupts the sig and skips the abort.
3. **SHA-2 PRF DPA** (Kannwischer, COSADE 2018 — recovers ≥32 sk bits from the
   secret-seed→WOTS+-leaf PRF): the F-16 shuffle targets this; confirm sufficiency with a
   `lascar`/`scared` CPA pass over rainbow-emulated `hw/hash.rs` traces during secret-seed load
   before considering anything more expensive (masked SHA-2 stays rejected — see §18 work-todo).

---

## 1. Adopt-now shortlist (the spine)

| Tool | What it buys PQ-Signer | Status |
|---|---|---|
| **`cargo-checkct`** (Ledger Donjon) | **Proves the 4 kdf/fors/th/saes DRIVERS' secret paths compile to constant-time `thumbv8m` machine code** at the shipped `opt-level="s"`+`overflow-checks` (aligned 2026-07-02, CT-1; cross-crate LTO not exercised — single-crate drivers, documented residual). Narrows — does NOT close — the gap `subtle` + source review leaves: the `subtle` compares themselves (the c10 double-compute `ct_eq`, PIN pre-commit) are NOT among the 4 drivers. thumbv8m explicitly supported — the **only** tool that proves CT on the shipped M33 ISA (Binsec/Rel has no ARMv8-M decoder; see §4). The single best find of the sweep. | [validated — 4 drivers, local-only gate] |
| **Kani** (AWS) + **Miri** | Bounded model-checking of NSC pointer-validation/TOCTOU, cap-monotonicity, parser panic-freedom (Kani, verifies MIR incl. `unsafe`) + UB detection in the CMSE veneers/MMIO/FI-volatile (Miri). Both run on the host-extracted crates today. | [validated] |
| **hevm equivalence** + **halmos** | Bytecode-level → they **see the compiled Yul** that Slither/CodeQL cannot. hevm proves `SPHINCsC10Asm` ≡ a reference Solidity verifier (SHA-256 as uninterpreted precompile); halmos proves the surrounding invariants (caps monotonic, `ownerIndex` dispatch, bootstrap-key-forbidden-in-1271, `replaySafeHash` ⊥ `sphincsDigest`). | [validated] |
| **dudect-style DWT t-test** on real STM32U585 | Closes the "rainbow models a generic ARM core, not the exact M33 + SAES/flash-wait timing" last mile for `verify()`/KDF constant-time. Cheap. | [validated] |
| **`cargo-deny [bans]`** | **Machine-enforces invariant #5** by banning any classical-signer crate (`secp256k1`/`ed25519`/`p256`/ECDSA) from the dependency tree. Plus `cargo-vet`/`cargo-audit`, `--offline --locked`, reproducible-byte-diff. | [validated] |
| **Custom Semgrep rules** | Machine-enforce invariants #5/#6/#7 + the unsafe taxonomy as a hard CI gate (ban classical signers; ban `rotateMasterKeys`/`reset*`/`increaseMax*` selectors; ban `from_utf8_unchecked` outside `ui::ascii_str`; ban raw MMIO outside `hw::mmio`; require `// SAFETY:` on every `unsafe`; ban new flash state beyond page 123). | [validated] |
| **lean-lsp MCP → LeanLoop frontier** | Already mounted in the dev harness; wire the interactive `queue`/`/leanloop-frontier` tier to `lean_goal`/`lean_multi_attempt`/`lean_hammer_premise`/`lean_verify` for live kernel grounding + the no-`sorryAx` gate. | [validated] |
| **Port `SPHINCsC10Asm.sol` into `SPHINCS-/verity`** | The on-chain verifier's Lean refinement proof — *already prototyped for C13/SLH-DSA-SHA2*; the C10 SHA-256 port inherits exactly the residual you're already discharging. See §2. | [validated] |

---

## 2. The on-chain Yul verifier — you already have `verity` [validated]

The recommendation from the first report ("prove the hand-written Yul verifier") is **already
underway** in your own `SPHINCS-` upstream (`/home/nicola/repos/SPHINCS-/verity/`):

- **`verity`** is a Lean 4 workbench that hand-transcribes the production Yul verifiers into a
  Verity interpreter model and proves each **refines a functional byte-spec**.
- **`c13_refines_spec` is PROVED** (keccak C13 verifier), resting on Lean's core axioms
  (`propext`/`Classical.choice`/`Quot.sound`) + exactly **3 residual assembly axioms** (a
  WOTS-pk lightweight-chain cutpoint; tracked in issue #7 on `wip/axiom-discharge`). The
  model→byte-spec bridge is discharged; C13's keccak is concrete (no opaque-hash axiom).
- The **`SLH-DSA-SHA2-128-24` model** keeps **2 axioms**: the SHA-256-precompile model-exec
  bridge + an opaque SHA-256 primitives constant.

**Why this matters for C10.** PQ-Signer's `SPHINCsC10Asm.sol` is **SHA-256-based and NOT
modeled in verity** (verity covers only C13 + SLH-DSA-SHA2; C7/C9/C10 are unmodeled). Porting
it inherits **exactly** the SHA-256-precompile-bridge + opaque-hash residual — i.e. the same
"model↔bytecode + SHA-256 byte-memory" residual the §33/LeanLoop track is already tackling.
**Caveat:** verity proves *implementation correctness* (the model computes the algorithm's
verdict), **not** EUF-CMA/collision-resistance and **not** model↔deployed-bytecode transcription
fidelity (that rests on review). So it's one leg of a tripod, not the whole proof.

**Complement verity with the bytecode-level EVM tools** (the only ones that see hand-written Yul):

| Tool | Level | Yul? | Role | Status |
|---|---|---|---|---|
| **hevm** (equivalence) | bytecode | ✅ | Prove `SPHINCsC10Asm` ≡ a reference Solidity verifier over all inputs (SHA-256 uninterpreted). *"…equally to hand-written assembly/Yul versus reference implementations—the tool doesn't distinguish."* | adopt-now [validated] |
| **halmos** (a16z) | bytecode | ✅ | Foundry-native symbolic invariants on the surrounding contract, valid sigs supplied from firmware test vectors. | adopt-now [validated] |
| **Kontrol / KEVM** | bytecode | ✅ | Already in use. Keep for the deepest discharge. | in use [validated] |
| **ityfuzz**, **Medusa**, **Echidna** | real EVM | ✅ (fuzz) | Fuzz the surrounding invariants; **won't** reach the verify-accept path (needs a valid 4008-B sig). | pilot/skip |
| Slither, CodeQL, SMTChecker, Pyrometer, Wake | AST/source | ❌ (HAVOC inline asm) | Useful on the `.sol`, **blind to the Yul.** | — |

**Decomposition (do NOT symbolically execute the crypto):** (a) hevm/Kontrol equivalence of the
Yul vs a reference, SHA-256 as an uninterpreted precompile; (b) halmos/Medusa for the contract
invariants with valid sigs from firmware vectors. Solver blowup is guaranteed if you try to
reason *inside* the hash/WOTS/FORS math.

**Gas benchmarks (residual fetch #2, finalized).** PQ-Signer's C10 is **byte-identical to
`SPHINCS-`'s C10 row** (h=18,d=2,a=11,k=13,w=8, target_sum=205, 4008-B sig, **~115 K verify**,
104.5-bit @2^20). In-family: C13 ~105 K asm / 188 K tx / 293 K 4337. The contrast that *validates
the whole "minus" design*: the independent **poqeth** verifier (AsiaCCS'25, `ruslan-ilesik/poqeth`)
at the **full NIST 2^64 budget** (h=63,d=10) costs **~5.2–13.4 M gas** for a full on-chain SPHINCS+
verify (keccak) — ~100× C10. The reduced signature budget (2^16–2^20 cap) is exactly what buys the
~115 K. poqeth also has **no audit and no machine-checked verification** (only paper protocol
proofs) → PQ-Signer's verity + Kontrol/KEVM track is a real differentiator. *Caveats:* poqeth hashes
with the keccak opcode vs PQ-Signer's SHA-256 precompile (expect a higher per-hash constant), and
its Naysayer/optimistic mode (~694 K) conflicts with the fully-on-chain `validateUserOp` model.
**Licensing:** the `SPHINCS-` main repo has **no LICENSE = all-rights-reserved** (source-visible,
*ask nconsigny before vendoring*); the `Verity` framework it builds on is `lfglabs-dev/verity`
(MIT — a Lean-4-verified EDSL→Yul compiler, 283 thms / 0 sorry / 0 axioms); poqeth's license is
ambiguous (paper says MIT, repo headers say `UNLICENSED`).

**KAT / differential oracle (adopt-now):** `SPHINCS-/signers/*/crosscheck.py` +
`signer-wasm/tests/cross_validate.rs` + the Foundry `*-JsonKAT.t.sol` tests are the exact
"KAT + differential-vs-reference-signer" harness shape. **C10 is a custom, non-FIPS-205
parameter set**, so generate **C10-specific** vectors from the `SPHINCS-` reference signers and
feed the *same* vector set to three consumers: the Rust `sphincs-c10` crate, the Lean spec via
**`leanloop kat`**, and the Yul verifier via a Foundry JsonKAT test. One oracle, three legs.

---

## 3. Firmware formal verification — Rust FV + LeanLoop

> **UPDATE 2026-07-01 — currency re-check + wall-closure.** Web-researched whether newer versions/tools close the walls the firmware-FV track hit. Verdict: **we are current, not behind** — Kani 0.67.0 is the latest release, CBMC 6.8.0 is pinned-by-Kani + irrelevant, Aeneas is ~3 wk behind (low value). The real lever is three experimental Kani `-Z` features **already in 0.67.0**: `-Z function-contracts` (closes the `records_pages_total` composition wall via modular contract+`stub_verified` proofs — the top actionable finding) and `-Z loop-contracts` (reopens the big-`.any()`/CRC scans — empirically feasible: a 3995-B scan verified in 0.05 s with no unwind bound), both unstable → run under the existing anti-vacuity gates. The **crypto-opacity wall (SHA-256/SPHINCS+C10) is FUNDAMENTAL** — every tool below reproduces the `--opaque` boundary (even hax, the crypto specialist, axiomatizes SHA-256), so it correctly stays a Lean/Aeneas hardness axiom + fuzz. **Don't chase:** Verus wholesale (invasive `verus!{}` on `#![no_std]`), Prusti (unmaintained), RefinedRust (Coq/Iris ≥ Aeneas), any tool "that handles crypto" (all hit the same boundary). One genuinely-new future capability: **hax→ProVerif/F\*** for verifying the *actual Rust* of the protocol code (OPTIGA-Shield/SCP03/PIN-lockstep) against the secrecy props we hand-model — a partial down-payment on the invariant #1-#4 model→Rust span, but heavy + crypto-boundary-limited. Full prioritized roadmap (P1-P7 + F1-F3 + don't-chase) is tracked in **`docs/work-todo.md` §35**.

### Rust verifiers beyond Aeneas→Lean

| Tool | Proves | unsafe? | PQ-Signer fit | Rec |
|---|---|---|---|---|
| **Kani** | bounded: panic/overflow-freedom, assertions, pointer/TOCTOU, cap-monotonicity | ✅ (MIR) | NSC pointer-validation, parser panic-freedom, cap monotonicity | **adopt-now** |
| **Miri** | UB in `unsafe` | ✅ | CMSE veneers, MMIO, FI-volatile helpers; runs on host crates | **adopt-now** |
| **Flux** | refinement types (slice/length) | partial | near-zero-annotation length refinement on wire formats | pilot |
| **MIRAI** | abstract-interp taint | — | secret-taint → NS/I2C sink for invariant #4 | pilot |
| **Verus** | SMT deductive (arithmetic/state-machine) | ✅ | invariants where Lean is heavy | pilot |
| **hax** (Cryspen) | Rust → F*/ProVerif/Coq | safe-only | cross-extract one `sphincs-c10` module as a check of the Aeneas→Lean work; ProVerif-model the PIN/SCP03 handshakes | pilot |
| Creusot, Prusti, RefinedRust, Gillian-Rust, ESBMC | deductive/MC | mixed | each dominated by a better-fitting choice above | skip |

**Hard limit:** *none* of these verify constant-time / SCA / FI — that stays with rainbow +
lascar + scared + `cargo-checkct` (§4). Safe-only deductive tools can't touch the CMSE
veneers/MMIO; only Kani/Miri/Verus/MIRAI reach `unsafe` at all.

### LeanLoop — already ahead of the prior recommendations [validated, local read]

`/home/nicola/repos/LeanLoop` already implements several things the first report suggested:

- **Already runs Goedel-Prover-V2-8B** (+ a **32B capacity tier** on iGPU/APU via Vulkan, or
  6950 XT partial-offload). The "swap to Goedel-V2-8B" rec is **done**.
- **Already has the fail-closed `#print axioms` audit gate** (no `sorry`/`admit`, no
  non-whitelisted axioms, no `native_decide`, statement-pinning) — the real soundness gate.
- **Already has spec assurance**: `leanloop vet` (CEX/HYP/NEG probes), `leanloop mutate`
  (mCoq-style spec-strength), and **`leanloop kat`** (grounds the executable Lean spec
  byte-for-byte against official NIST SLH-DSA/SPHINCS+ vectors) — covering all four spec-error
  classes (false/vacuous/weak/wrong-property). **⚠ Caveat (FV review F10, 2026-07-16): the
  `vet` NEG probe's RED verdict is NOT yet citable as assurance** — it misclassifies a failing
  Lean run with unsolved goals as `NEGATION PROVED` instead of `ERROR/UNRESOLVED` (RED must
  require a zero Lean exit + named-declaration kernel acceptance). Until the external
  `spec_vet.py` fix + negative regressions land (work-todo FV15-F10), read `vet` as a design
  reference, not a delivered verdict; PQSigner's shipped non-vacuity gate is the kernel-checked
  `verify-ledger-consistency` C9 hand-witness gate, which does not rest on `vet`.
- **Free frontier** via interactive Claude Code (`queue` backend + `/leanloop-frontier`).

**Remaining adoptable** (LeanLoop's own roadmap, with concrete prior art to implement from):

| Roadmap item | Concrete reference | Why |
|---|---|---|
| per-theorem goal splitting + lemma harvesting | **APOLLO** (arXiv:2505.05758) | the sample-efficiency win (25,600 → hundreds) for the 6950 XT budget |
| prover ensembling (fast tier) | **DeepSeek-Prover-V2-7B** (recursive `have`-decomposition; 6950-XT-runnable) + **Kimina-RL distills** | escalation diversity; `have`-decomposition fits Aeneas proof chains |
| Kimina Lean Server backend | leanprover-community | 1.5–2× faster batched kernel checking |
| live kernel grounding in the frontier session | **lean-lsp MCP** (already mounted) | reason against goal state, not guesses |

**Two halves of the same proof:** `SPHINCS-/verity` proves the *on-chain Yul verifier*;
LeanLoop proves the *firmware signer* (Rust→Charon→Aeneas→Lean). KAT-ground **both** against the
same C10 vectors (§2) and you have the full Type-1/Type-2 path covered end to end. **No prior
formally-verified SLH-DSA *implementation* exists anywhere** — this track is ahead-of-field.

---

## 4. Constant-time · side-channel · fault-injection

### Software CT / FV
- **`cargo-checkct`** (Donjon) — adopt-now, thumbv8m machine-code CT proof (§1).
- **dudect** DWT Welch t-test on real U585 — adopt-now, cheap last-mile.
- **Binsec/Rel** — **NO-GO for the shipped binary** (residual fetch #3, confirmed): Binsec's ARM
  front-end is **ARMv7-A + ARMv8-A AArch64 only — there is no ARMv8-M / Cortex-M / M-profile
  decoder**, so the `thumbv8m.main-none-eabi` ELF is undecodable. The NIST-PQDSS study (arXiv
  2509.04010) ran on **x86**, not Cortex-M. Binsec/Rel can at best CT-check an **x86/ARMv7-A
  re-target of the source** (different ISA, not the shipped object code), per-subroutine + bounded.
  → For the real M33 binary, **`cargo-checkct` + rainbow + on-device dudect are the constant-time
  stack**; Binsec/Rel is reference-only.
- **haybale-pitchfork** — per-line CT verdicts on `sphincs-c10` LLVM bitcode (native Rust) — pilot.
- Source-level CT (Rust `subtle`, hax secret-types, FaCT) does **not** guarantee the compiled
  M33 binary is CT (backend passes can reintroduce branches) — that's why `cargo-checkct` /
  Binsec/Rel / dudect are the load-bearing layer, not `subtle` alone.

### The SPHINCS+ SCA/FI literature (defensive map)
- **Genêt TCHES 2023** + **eShard #3** + **SLasH-DSA 2025** → the redundant-recomputation
  countermeasure (§0; already implemented). **`AymericGenet/SPHINCSplus-FA`** is the Python
  fault-attack tooling to run against C10 params as a rejection corpus.
- **Grafting Trees** (Castelnovi/Martinelli/Prest) — the original grafting fault.
- **Kannwischer COSADE 2018** (DPA of XMSS/SPHINCS) → the SHA-2 PRF leakage to CPA-test (§0.3).
- Attribution note: there is **no Ledger-Donjon-authored SPHINCS+ attack paper** — cite Genêt
  (EPFL/Nagra), not Donjon. Donjon's PQC presence is tooling + the TROPIC01 laser-FI case study
  (whose single-`BRZ`-branch FI bypass is a textbook justification for the double-sentinel verify).

### Ledger Donjon's full toolset (26 tools — most unadopted) [validated]
You already use **rainbow** + **lascar**, but Donjon now calls **lascar "legacy."** Highest-value
unadopted:
- **`cargo-checkct`** — §1 (the headline).
- **Muscat** (current-gen Rust SCA) + **dtw** (jitter-resync) + **Turboplot** — a multithreaded
  pipeline that scales to SPHINCS+ trace sizes far better than lascar — pilot.
- **Scadl** (deep-learning SCA), **`erc7730-analyzer`** (lints your ERC-7730 descriptor bundle —
  pilot), **laserstudio**, **fuzzwizard**/**absolution**/**arocc** — reference.
- **Scaffold** + **Silicon Toaster** (open FI/SCA + EMFI boards) — the bridge from
  emulation-only to measured-on-silicon — pilot.

### Hardware bench (physical complement to rainbow) [validated]
The same `lascar`/`scared` selection functions you run on rainbow traces work on **silicon**
traces with only the capture front-end swapped — the emulation investment transfers directly.
- **ChipWhisperer-Husky / Husky-Plus** (NewAE) + shunt — **adopt-now** entry rig.
- **ChipSHOUTER-PicoEMP** — **adopt-now** cheap EMFI smoke-test of the verify + PIN-gate FI guards.
- **Scaffold** (Donjon) — pilot; can also instrument the OPTIGA/SE050 I2C buses.
- **FiSim** (Keysight, ex-Riscure) — pilot, a 2nd independent Unicorn-based FI-sim to corroborate
  rainbow before silicon time.
- Keysight/Riscure Inspector/FJ2/laser — **skip internally**; reserve for an external CC/EMVCo lab.
- **Open empirical gap:** *every* public STM32 RDP/voltage-glitch result targets F1/F2/F4/L0/L5,
  **not the STM32U5** family. Whether a U585 RDP/TrustZone downgrade is achievable is an
  **unanswered question only your bench can settle** — and it governs how much trust the dual-SE
  XOR split must carry independent of the MCU. SECGlitcher (SEC Consult) is the right starting
  methodology.

---

## 5. Protocol verification — novel, publishable assurance [validated]

**Nobody has formally modeled a multi-SE hardware-wallet PIN lockstep.** EMVerify
(`github.com/EMVrace/EMVerify` — found real Visa/Mastercard PIN bypasses) is the closest template
and the modeling style demonstrably catches exactly the PIN-bypass/counter-bypass class your
S-1/S-6 ship-blockers describe.

Priority (skeptic's ranking):
1. **ProVerif** on the SE channel protocols (OPTIGA Shielded Connection, SCP03) — fastest path,
   gentle curve.
2. **Tamarin** for the stateful properties no other tool covers. The existing
   three-counter PIN model is an idealized symmetric research contrast, not a
   deployed proof; a faithful model must encode the directional page124/E120
   boot check and the absence of an SE050 attempt-count input. Tamarin's XOR
   equational theory also fits the XOR seed-split secrecy question.
3. **EMVerify** as the structural template; **SAPIC+** to write each model once and target
   ProVerif+Tamarin; **CryptoVerif** (now PQ-sound) / **PQ-Squirrel** for computational
   seed-split guarantees if you want quantum-soundness, not just symbolic.

The legacy/nonshipping FW-update signature chain (75-B PQFW_V1 bench preimage) is a near-trivial authenticity lemma —
a warm-up, low value relative to the lockstep/channel work.

---

## 6. Peer teams & where PQ-Signer stands

- **ZKNOX** (`github.com/ZKNoxHQ`) — leading on-chain-PQ shop, but **lattice-only** (ETHFALCON,
  ETHDILITHIUM, NTT-in-Yul) — **no SPHINCS+/hash-based verifier**, and **zero formal
  verification** ("No audit completed; experimental, not audited"). Their KAT + differential
  harness shape is the reference; PQKINGS (hybrid ECDSA+PQ 7702) contradicts invariants #5/#6.
  **PQ-Signer's Kontrol/KEVM + Lean/verity track is strictly more rigorous than theirs.**
- **`SPHINCS-`** (your own upstream) — the genuine EVM twin (Keccak hash-sig family, WOTS+C/FORS+C,
  bounded budget, `verity` Lean proofs). See §2.
- **On-chain hash-based landscape:** `poqeth` (independent Solidity SPHINCS+/WOTS/XMSS verifiers —
  differential oracle), **leanSig** (EF generalized-XMSS, Rust), opus-lux WOTS-39 (live WOTS+
  4337/7702 wallet). All unaudited/research-grade.
- **Trezor** — practices to adopt: **ClusterFuzzLite** in-CI fuzzing + **golden-screenshot UI
  tests** (wire your `ui-capture` frame hashes into golden CI gates) + reproducible build. **No
  formal methods** in their Rust — you are ahead. **Ledger Donjon broke Trezor Safe 3/5 via
  voltage glitch (Mar 2025)** — empirical validation of the dual-SE XOR-split thesis and of why
  the S-1/S-2/S-3 OPTIGA lockdown must close before any unit ships.

---

## 7. Offensive / agentic + MCP harness

- **Validated frontier:** DARPA **AIxCC** CRSes (Aug 2025; all 7 open-sourced — Atlantis/MIT,
  Buttercup/AGPL, RoboDuck/AGPL, ARTIPHISHELL/MIT). **C/Java/OSS-Fuzz only — no Rust target, no
  Solidity/Yul.** Reuse the *architecture* (fuzz+symexec+LLM-patch) host-side over the pure-logic
  crates, not the tool.
- **2026 agentic systems** (XBOW, Big Sleep, OpenAI Aardvark, HexStrike-AI, Villager, Strix,
  CAI) — **overwhelmingly web/network/host-app**; none target firmware/Yul/SCA. XBOW's "#1
  HackerOne" is real but the "1,060 vulns" is *submitted*, 130 resolved. The "mythos" reference ≈
  **Anthropic "Claude Mythos / Claude Security"** — flagged **hype** (no named benchmark). AISLE
  (not Big Sleep) found the 12/12 OpenSSL 0-days.
- **No public agentic system/benchmark targets SLH-DSA firmware on Cortex-M or a Yul PQ-verifier**
  (CREBench/CrackMeBench explicitly exclude them) → **build an in-house CREBench-shaped red-team
  eval** against your own thumbv8m binaries, reusing rainbow+lascar+scared for the SCA half.
- **Security MCP servers for the red-team loop** (find→verify→patch): Slither-MCP (contracts),
  Semgrep-MCP (Rust+Solidity custom rules), Foundry/`forge` (Yul fuzz), Echidna-MCP, GhidraMCP
  (closed-SE-blob RE), lean-lsp-MCP (proofs), Z3/`mcp-solver`. **CodeQL = useless** (no Rust, no
  Solidity). **Data-egress/prompt-injection discipline (mandatory for a key-holding repo):**
  per-subagent MCP allowlists in `.mcp.json`; **deny outbound network** for binary/fuzzing tools;
  never give one agent both repo-secret read access and a network tool; sandbox any
  code-exec MCP (Sage/Z3/radare2-ESIL); audit the existing untracked `.mcp.json`. Keep
  HexStrike/CAI-SSE (network-capable) **off** this repo.

---

## 8. Defensive CI + supply chain

**Layer deterministic-first (hard gate), LLM-as-advisory.**
- **Deterministic base (fail-hard, near-zero noise):** `cargo-deny` (advisories+bans+licenses;
  **`[bans]` enforces invariant #5**) + `cargo-vet --locked` + hermetic `cargo build --offline
  --locked` + reproducible-byte-diff + one SBOM (`cargo-cyclonedx`) + **SLSA provenance /
  `in-toto` / `cosign`→Rekor** on the release. ~4 gates that run in seconds.
- **Custom Semgrep rules** (§1) as the invariant gate.
- **LLM advisory layer:** **`anthropics/claude-code-security-review`** (MIT GH Action) — reads
  *both* Rust and Solidity/Yul, tunable FP-exclusion list, your own key. ⚠️ **not hardened
  against prompt injection** — gate behind "require approval for external contributors," never
  auto-merge. Pair with the local `/security-review` skill for pre-commit runs (no diff egress
  until you choose). The right gating asymmetry (Semgrep-validated): *suppress to backlog, never
  silently drop.*
- **Embedded caveat:** `cargo-auditable` should **not** embed the manifest in size-critical
  secure-world firmware — use an external SBOM sidecar keyed to the FSBL-measured hash.
- **Skip:** CodeQL/Copilot Autofix (no Solidity, narrow Rust); stacking SaaS reviewers
  (CodeRabbit+Greptile+Semgrep-Assistant — re-creates fatigue + multiplies firmware-diff egress).
  Malicious-crate "AI detectors" have **no published precision/recall** — treat as hype.

---

## 9. Hype flags (don't chase)
- "XBOW found 1,060 bugs" → *submitted*; 130 resolved.
- Strix, Anthropic "Claude Mythos" ("thousands of vulns"), Alias "alias3 leads Cybench 85%",
  Greptile "82% catch rate", HexStrike "98.7%/2.1% FP" → vendor marketing, no named benchmark.
- "LLM-SmartAudit shows SAST = 0%" → stacked comparison (logic corpus vs fixed-taxonomy tools);
  keep Slither.
- AIxCC CRSes / XBOW / Big Sleep as drop-ins → wrong stack; reuse architecture, not tool.

---

## 10. Filed work items
See `docs/work-todo.md` §34 ("Security-tooling adoption — 2026-06 SOTA research") and the FI items
folded into §18b. The Completion Log records this research (2026-06-16).

---

## 11. Trail of Bits skills marketplace — `trailofbits/skills` (Claude Code)

`/plugin marketplace add trailofbits/skills` (CC-BY-SA-4.0, ~40 plugins, actively maintained, 5.7k★).
These are **assistive** Claude Code skills (structured prompts + some Python helpers like `ct_analyzer`)
— they orchestrate Claude over tooling, they are **not** standalone proven analyzers, so treat output
as *triage to verify*, not ground truth. They sit *above* the real assurance (Lean/verity/Kontrol +
rainbow/lascar/scared), not in place of it, and are **source/IR-level** (not M33 machine code — they
complement `cargo-checkct`/dudect/rainbow, §4). High-value subset, mapped to this report:

- **`zeroize-audit`** [adopt-now] — Rust-aware; **assembly/LLVM-IR detection of zeroization removed by
  compiler optimization (dead-store elimination)** + control-flow path coverage + register-spill
  analysis. Directly audits whether PQ-Signer's `zeroize::ZeroizeOnDrop` + compiler-fence discipline
  *survives `opt-level="s"`+LTO* on the real translation units — a check **nothing else in this report
  performs.** The best fit in the marketplace.
- **`constant-time-analysis`** (`ct_analyzer`) [adopt-now] — Rust-supporting source/IR CT pre-filter
  (secret-dependent branches, `/`/`%` on secrets, `sign`/`verify`/`derive_key`). Cheap front-end to the
  §4 CT stack; does **not** replace `cargo-checkct` (shipped-binary level).
- **`semgrep-rule-creator` + `semgrep-rule-variant-creator`** [adopt-now] — author the custom invariant
  Semgrep ruleset (§1/§8: inv #5/#6/#7 + the unsafe taxonomy) instead of hand-writing it.
- **`mutation-testing` + `property-based-testing`** [pilot] — Foundry/Echidna invariant testing;
  complements LeanLoop `mutate`/`kat` (§3).
- **`differential-review`** [pilot] — the C10 differential cross-impl review (§2) + security-diff review.
- **`variant-analysis`** [pilot] — find every other instance of a confirmed bug (Big-Sleep-style).
- **`entry-point-analyzer`** [pilot] — state-changing entry-point map for the contract surface
  (`validateUserOp`/`execute`) and conceptually the NSC gateway.
- **`building-secure-contracts`** [reference] — guidelines-advisor / audit-prep / code-maturity /
  token-integration for the `.sol`. **Caveat:** its vuln *scanners* are 6 **non-EVM** chains
  (Solana/Cairo/Cosmos/Substrate/TON/Algorand) — **no Solidity scanner**; the Solidity spine stays
  Slither-MCP + halmos/hevm/Kontrol (§2).
- **`supply-chain-risk-auditor`** [pilot] — the §8 supply-chain layer.
- **`agentic-actions-auditor` + `seatbelt-sandboxer` + `fp-check`/`second-opinion`** [pilot] — exactly
  the MCP/CI **data-egress + prompt-injection + alert-fatigue** hardening flagged in §7/§8 (audit the GH
  Actions incl. the `claude-code-security-review` Action, sandbox tool exec, suppress false positives).
- **`c-review`** (SARIF) + **`debug-buttercup`** [reference] — the C reference signers / SHA-256 hooks;
  debugging Buttercup if adopted (§7).

**Caveats:** assistive-not-proven (above); **no EVM scanner**; source/IR-not-binary; CC-BY-SA-4.0
share-alike if you fork-and-publish; same data-egress discipline as any agentic tool on a key-holding
repo (scope what they read).

---

## Appendix — residual fetches & key citations

**Residual fetch status (all 3 closed):**
1. *SPHINCS- ethresear.ch / Verity* → **[validated]** Thread posted 2026-06-12 by nconsigny
   (`ethresear.ch/t/…/25165`, "SPHINCS minus: Efficient Stateless PQ Signature Verification on the
   EVM"); verifier source public at `github.com/nconsigny/SPHINCS-/src` but **all-rights-reserved
   (no LICENSE)**. "Verity" = `lfglabs-dev/verity` (MIT) — a Lean-4-verified EDSL→Yul compiler (283
   thms, 0 sorry, 0 axioms; Lean 4.22.0); the SPHINCS-`/verity` workbench uses it to prove the
   C13/SLH-DSA-SHA2 refinements (hand-transcribed, **no Aeneas/Rust**). C10 param set byte-identical
   to PQ-Signer's.
2. *poqeth gas* → **[validated]** Full on-chain SPHINCS+ verify ~5.2–13.4 M gas (keccak, NIST 2^64
   budget); Naysayer ~694 K; no audit/FV. Validates the "minus" budget reduction (§2). License
   ambiguous (paper MIT / repo UNLICENSED).
3. *Binsec/Rel ARMv8-M* → **[validated] NO-GO** for the shipped M33 binary — no M-profile decoder
   (ARMv7-A/v8-A only); x86/ARMv7-A source re-target only (§4).

**Primary citations:** Genêt TCHES 2023 (eprint 2023/042) · SLasH-DSA arXiv 2509.13048 · eShard
Expert Review #3 · Kannwischer COSADE 2018 · EasyCrypt SPHINCS+ EUF-CMA (eprint 2024/910) ·
ePrint 2025/2203 (WOTS+C/FORS+C) · NIST PQDSS timing study arXiv 2509.04010 · DARPA AIxCC
(darpa.mil/news/2025/aixcc-results) · `SPHINCS-/docs/SECURITY-ANALYSIS.md` (Avenue B) ·
`SPHINCS-/verity/SphincsMinusVerifiers/AXIOMS.md` · LeanLoop README · Ledger Donjon Tools Suite
(donjon.ledger.com/tools-suite). Full per-system tables + [validated]/[unverified] marks are in
the three workflow transcripts under `…/tasks/`.
