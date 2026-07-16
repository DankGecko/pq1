# Can the hardware surfaces be formally verified? — external survey + verdict

**Snapshot date: 2026-07-17.** Program/research layer. This is the **survey and verdict**
deliverable: ~45 external tool/paper claims adjudicated against primary sources (every one
fetched, not recalled), plus what applies, what does not exist, and what we would have to
build ourselves.

**Evidence tier of this document — read the marker before anything here becomes load-bearing.**
Almost everything below is **`[survey]`**: sourced by a research agent, then adversarially
re-checked by an independent agent that fetched the primary source itself. Rigorous, but **not
author-verified**. The exceptions are marked **`[tool]`** (a binary was run on this box) and
**`[code]`** (read from this tree). **Where `[tool]` and `[survey]` disagree, `[tool]` wins** —
§5.6 records one such case, where the author's own BINSEC probe **withdrew** a survey correction.
The tier convention is the boundary doc's; this doc adopts it rather than minting a second one.

Companion — **read it, this doc does not repeat it**:
[`hardware-assumption-boundary-2026-07-17.md`](./hardware-assumption-boundary-2026-07-17.md)
carries the epistemology in full: the falsifiability criterion that separates a hardware model
from proof theatre (§2), the entitled-vs-overclaim claim table (§3), the per-invariant silicon
weight (§4), and the RDP-2 / dual-SE-split trace (§5). Where this report needs those, it points.

Other companions: [`fv-surface-expansion-inventory-2026-07-16.md`](./fv-surface-expansion-inventory-2026-07-16.md)
(the 47 surfaces — §9 below states only the **delta**);
[`formal-verification-assurance-expansion-2026-07-15.md`](./formal-verification-assurance-expansion-2026-07-15.md)
§P1.9 (which already declares peripheral behaviour, CMSE semantics and errata out of scope —
this report is the sourced justification for that call);
[`security-tooling-sota-2026-06.md`](./security-tooling-sota-2026-06.md) (which §9 **corrects**).

---

## 1. Bottom line

**No. Not one of the six surfaces can be formally verified — and that is not a local failure;
nobody verifies silicon they did not design.** What *is* achievable, on four of the six, is
strictly weaker and genuinely valuable: **machine-checked proofs of driver logic against a
hardware contract we write down**, each contract pinned by a test that can fail.

- **(c) ARMv8-M/CMSE/SAU-GTZC and (e) OPTIGA/SE050 internals are closed permanently** — (c) on an
  ARM business decision (no public M-profile spec exists, in any framework), (e) on RTL we will
  never obtain. Record both as **closed questions, not backlog**.
- **(a) OTP, (b) flash, (d) framing, (f) peripherals reach `C` + `M` + `silicon-E2E`**, over
  premises that stay `bare-TCB` forever.

**Single most valuable move: wire the `hal/` seam** (§6/P5). Not as a Kani enabler — as the
mechanism that makes the contract *falsifiable at all*. `secure/Cargo.toml` has no dependency on
`hal/`, and the two live specs contradict each other with nothing detecting it.

**Cheapest move, hours not weeks: read TN1545 + UM3387** (§4.6). ST published half the assumption
ledger, addressed to us; we ship **deliberately outside** the certified configuration.

---

## 2. The frame: why "formally verify the OTP" is the wrong question

The right question is: **which half of each claim is software, and what pins the other half?**

> Verify software AGAINST a hardware contract you wrote down. Then validate the contract
> empirically. **The contract stays an assumption forever.**

This is not a counsel of despair; it is the published frontier, and every serious effort says so
in its own words. seL4, ~20 person-years, assumes "the hardware works correctly… run within its
operating conditions" and assumes DMA away
([assumptions](https://sel4.systems/Verification/assumptions.html)) — an assumption we cannot
inherit, since fault injection is inside our threat model. Pancake, the 2025 SOTA in verified
device drivers, states "we trust the device not to malfunction"
([arXiv:2501.08249v2](https://arxiv.org/html/2501.08249v2)). Veld found a *complete* hardware
model infeasible and shipped a partial one
([KISV'24](https://mars-research.github.io/doc/2024-kisv-veld.pdf)). TickTock's ARM hardware spec
is **60 trusted, unchecked lines** ([SOSP'25](https://css.csail.mit.edu/6.5660/2026/readings/ticktock.pdf)).
Termite — the flagship model-driven effort — never implemented the spec↔RTL check that would
have validated its model, and could not have: both evaluated devices were proprietary
([SOSP'09](https://www.sigops.org/s/conferences/sosp/2009/papers/ryzhyk-sosp09.pdf)).

Two consequences that do real work below:

**Modelling can be negative-value.** If the model is written by the driver's author from the same
datasheet reading and nothing can contradict it, you have produced a second copy of the belief and
a certificate that the copies agree — worse than honest prose, because it looks like evidence.
PERRY is the canonical demonstration: it infers the peripheral model **from the driver**, i.e. it
encodes the belief in doubt ([USENIX Sec'24](https://www.usenix.org/system/files/sec24summer-prepub-600-lei.pdf)).
Full criterion: boundary doc §2.

**Granularity is the trap, and we already fell in it once.** The pretty OTP abstraction is a
monotone bit-lattice — and on STM32U585 it is *true*, and the design built on it was *invalid*.
The rejected legacy anti-rollback tally counted cleared bits, which requires clearing one more bit
in an already-programmed quad-word; silicon forbids exactly that (`otp.rs:4-12`). A bit-lattice
model would have issued a clean green for an operation that bricks parts. **Model at the commit
granularity — quad-word, one APDU, one bus transaction — or do not model.**

Tiers below use the existing [`THREAT_CLAIM_MAP.md`](../../contracts/verification/docs/THREAT_CLAIM_MAP.md)
legend (`K` kernel-proof / `C` bounded / `silicon-E2E` / `T` cited-TCB), plus **`M`** =
model + a differential test that runs and can fail.

---

## 3. Per-surface verdict

| Surface | Does a tool exist? | What it proves | Covers M33? | Verdict | Effort | What stays assumption |
|---|---|---|---|---|---|---|
| **(a) OTP one-way / monotone fuse** | **No tool models fuse physics.** Kani (installed) + Ariadne's crash-contract shape ([F*, arXiv:1707.02466](https://arxiv.org/pdf/1707.02466)) apply to the *logic*. OpenTitan's A/B lifecycle encoding ([lc_ctrl](https://opentitan.org/book/hw/ip/lc_ctrl/doc/theory_of_operation.html)) is **not portable** — it needs the tapeout | Driver logic vs a written `Otp` model: floor monotonicity, half-burn detection, crash recovery | Kani: no (host MIR) | **`C` + `silicon-E2E`** | 1–2 wk post-seam; probe 2–3 d | Fuse irreversibility; ECC line semantics; that a brownout-torn burn is detectable |
| **(b) Flash atomicity / torn write / ECC / brownout** | **Partially.** PoWER/Verus ([OSDI'25](https://people.csail.mit.edu/nickolai/papers/leblanc-power.pdf)) is the framework match; TLA+/TLC installed + piloted; Kani installed | Crash consistency vs a chunked model. PoWER's chunk param = 16 B QW; **1→0-only, page erase, ECC-lock must be ADDED** — and ECC-lock is not additive (see below) | PoWER: no (x86 PM) | **`K`/`C` logic; `M` + `silicon-E2E` contract** | mo (Verus) / wks (TLC+Kani) | Chunk atomicity itself; ECC on a torn QW; marginal-cell read stability after brownout |
| **(c) ARMv8-M ISA / CMSE / SAU-IDAU-GTZC** | **No. Structurally, permanently.** See §5.1 | Nothing. The config **logic** is bit-packing (Flux/TickTock shape, `C`-tier); enforcement is `make gtzc-enforcement-hw` | — | **`C` config + `silicon-E2E`. `K` unreachable** | n/a | CMSE instruction semantics; SAU/IDAU as ST wired it; **the entire GTZC block**; unpublished errata |
| **(d) I2C + IFX-I2C / T=1′ framing, retry, guard time** | **Nothing to reuse** — literature is empty (§5.3). Build with installed TLA+/TLC + Kani | Framing/CRC purity (`C`, today, no seam). FSM: no lost/dup apply, progress (`M`) | Kani yes (pure fns); TLC n/a | **`C` + `M`** | 3–5 d (Kani) / 3–4 wk (TLC) | Bus electricals; SE-side timing; that a 50 µs guard-time violation is benign-or-detected |
| **(e) OPTIGA / SE050 black box + LcsO** | **No, and none will appear.** Every technique that could ([HIVE](https://arxiv.org/html/2309.08002v2), [OpenTitan FPV](https://opentitan.org/book/doc/contributing/dv/sec_cm_dv_framework.html), [Silveroak](https://github.com/project-oak/silveroak), Termite) needs RTL | Nothing. Certificates attest **bounded expert effort**, and their scope excludes what we rely on (§4.5) | — | **`silicon-E2E` + scoped `T`. Nothing above, ever** | per-property days | Everything inside the die |
| **(f) SAES/DHUK/BHK, TAMP, TRNG, HASH, RCC** | **Partially, and non-uniformly.** [NIST EA suite](https://github.com/usnistgov/SP800-90B_EntropyAssessment) (statistical, not proof); [stm32-rs SVD](https://stm32-rs.github.io/stm32-rs/) (layout only); KAT self-tests | TRNG min-entropy *estimate*; transcription conformance; DHUK per-die distinctness (n=2) | SVD yes; EA n/a | **`silicon-E2E` + `C` gates** | days each | DHUK unextractability; TRNG entropy; SAES leakage; every unpublished erratum |

Three points the table cannot carry:

**(b) — ECC-lock breaks PoWER's core.** `can_result_from_partial_write` is a strict **two**-outcome
disjunction (chunk == pre ∨ chunk == post). A torn STM32 quad-word admits a **third**: an ECC fault
on read, neither old nor new. That touches PoWER's central disjunction, not its parameters. Also:
Verus is absent from this box, and PoWER's own limitations rule out quantifier-weak tools — so
Kani is likely **not** a PoWER host. Genuine install-and-pilot.

**(b) — do NOT cite Tseng (DAC 2011) as refuting our flash premise.** Its retroactive-corruption
finding is explicitly MLC-scoped ("This assumption is incorrect for MLC devices"), structurally
requires two logical pages sharing a cell, and all 11 DUTs are raw NAND with **no NOR and no ECC**.
Its own §5 *preserves* log-structured recovery for SLC. Cite it for its real lesson — fault models
need real-hardware measurement ([PDF](https://cseweb.ucsd.edu/~swanson/papers/DAC2011PowerCut.pdf)).

**(f) — DHUK's certificate claim is conditioned on TAMP, which we never validated.** We treat
DHUK (strongest row) and TAMP (untested row) as independent. The vendor does not: UM3387 §4.2.1 —
"To meet the platform resistance against physical attackers, the Integrator **should configure the
TAMP peripheral** with anti-tamper methods … when using the following functions: • **Nonvolatile
derived hardware unique key (DHUK) usage** • Volatile key storage in backup register (TAMP_BKPxR)
… • Cryptographic functions in hardware engines (SAES, AES, HASH, PKA, OTFDEC)" — and "When a
tamper flag raises … the Integrator **must** implement a security response." We use DHUK, use
`TAMP_BKP0R..7R` (the BHK latch), ship `tamp` log-only by default, force `tamp-wipe` on only for
shipping images, have **no TAMP silicon test**, and once had TAMP based at the wrong address long
enough that `tamp.rs:129` records it "went unnoticed". **Merge these into one ledger row with one
falsifying test.**

---

## 4. What exists and applies

### 4.1 Already installed, already CI-wired — use it more
- **Kani 0.67** ([docs](https://model-checking.github.io/kani/rust-feature-support.html),
  [ASE'26](https://arxiv.org/html/2607.01504v1)). MMIO-behind-a-trait was **demonstrated on this
  box** twice: the author's minimal seam proof (`0/52 checks, 0.18 s`, `[tool]`) and an
  independent fuller re-run with `kani::any()` over the whole backing array (242 checks, 62 s) —
  both VERIFICATION SUCCESSFUL. Hard bounds, empirically probed: `--target` is **rejected outright**
  (`CARGO_BUILD_TARGET` is *silently ignored* — a footgun); inline asm fails loudly; concurrency is
  **silently sequentialized**; volatile is `Partial`, i.e. modelled as plain memory — so Kani
  reaching MMIO code would be **silently unsound**, not refused. Kani models a non-faulting machine:
  it says nothing about the F-15.r5 FI double-scan. Kani and the FI argument are complementary;
  neither subsumes the other.
- **Miri** — structurally cannot reach MMIO, verified by probe: `0x40022000[noalloc] … has no
  provenance`, surviving both `-Zmiri-permissive-provenance` and `-Zmiri-disable-isolation`. It is
  the **provenance model**, not volatile and not isolation. `make miri` already covers four crates
  including the `ns_ptr_validate` primitives. Correct scope; do not expand.
- **TLA+/TLC** — installed, page-123 pilot done. The obvious next targets are (b)'s torn-QW action
  and (d)'s framing FSM.
- **cargo-checkct** ([repo](https://github.com/Ledger-Donjon/cargo-checkct)) — genuinely *formal*
  by design (relational symbolic execution + taint, not dudect statistics), **wired here with
  `target = ["thumbv8m.main-none-eabi"]` and six drivers**. Three caveats, and the first two are
  unresolved: **(i)** the author's own on-box BINSEC probe (boundary doc follow-up #6, `[tool]`)
  found that in `thumb` mode BINSEC emits `unimplemented` **uniformly — including on plain
  `adds`/`eors`/`bx`** — then dies in `disasm_core.ml`; so it is **not established** that anything
  in our tree is actually being proven, and it is **not established** whether cargo-checkct even
  drives a BINSEC frontend. **(ii)** `make checkct` **has no defined pass signal** — it
  deliberately includes a by-design-INSECURE `fisher_yates` driver, so exit code ≠ verdict.
  **(iii)** its stated axiom is that "all instructions have data-independent timing" — a bare
  silicon premise for the U585. Repo is **dormant** (last commit 2025-05-07, zero releases).
  **Resolve (i) and (ii) before citing `make checkct` as evidence of anything.**

### 4.2 Applies, absent from this box
- **Flux** ([repo](https://github.com/flux-rs/flux), actively maintained) — the only Rust verifier
  with a **published Cortex-M deployment**: TickTock (SOSP'25) verified Tock's process isolation,
  3.5 KLOC annotations over ~17.5 KLOC, and found **5 previously-unknown bugs in MPU-configuring
  code** + 2 in interrupt handling. Direct analogue of our 572-line `sau.rs`. Caveats: ARMv7-M only;
  FluxArm models **no** security extension; the hardware spec is 60 trusted lines validated by
  differential testing. **Only the method transfers** — but the method is exactly right.
- **Verus** ([repo](https://github.com/verus-lang/verus)) — real raw-pointer/provenance model, but
  **no volatile/MMIO vocabulary at all**, and **no published embedded/Cortex-M case study** (VeriSMo
  is bare-metal but x86_64, and reaches hardware via `external_body` + a bespoke ghost permission
  model — i.e. each register access becomes a trusted axiom). Note for the inventory: the
  `verus-power-flash-journal-pilot` row's tool choice is weaker-evidenced than Flux.

### 4.3 The seam pattern is mainstream, and our mocks already exist
`embedded-hal-mock` ([repo](https://github.com/rust-embedded/embedded-hal-mock)) is the ecosystem
proof that trait-based DI is standard practice. **Do not adopt embedded-hal itself** — 8 of our 13
traits (`Rng`, `Sha256`, `Saes`, `Flash`, `Otp`, `BootState`, `Tamp`, `ConsumptionMask`) have no
counterpart there, and those 8 are precisely surfaces (a), (b), (f). Wire the traits we already
have; `MockFlash`/`MockOtp`/`MockSaes`/`MockI2c` already exist in `hal/tests/positive_mock_platform.rs`.

### 4.4 External artifacts we should be consuming and are not
- **stm32-rs patched U585 SVD** ([index](https://stm32-rs.github.io/stm32-rs/)) — 3.7 MB, 202
  peripherals (100 NS + 100 `SEC_*` aliases), covering SAES/HASH/RNG/PKA/FLASH/GTZC/TAMP/RCC/I2C/
  SPI/TIM/USART/ICACHE/PWR. `saes.rs:31-32` **already cites the generated PAC as authoritative** —
  the artifact is not missing, the automated diff is. Scope honestly: **no SAU/MPU/NVIC/SCB/UID/OTP**
  (the `<cpu>` block has no `sauRegionsConfig`), and it is **layout, not behaviour** — `KEYSEL` is
  present at bitOffset 28/width 3 with a tautological description and **no** enumeratedValues, i.e.
  the SVD does not know KEYSEL selects Software/DHUK/BHK. It does cover `FLASH_OPTSR`, which makes
  `lockdown.rs`'s BENCH-CONFIRM'd `OEM1LOCK`/`OEM2LOCK` bit positions machine-checkable **today**.
- **Infineon I2C Protocol v2.03** ([PDF](https://raw.githubusercontent.com/Infineon/optiga-trust-m-overview/main/docs/pdf/Infineon_I2C_Protocol_v2.03.pdf))
  — **public and wire-complete**: §6 specifies PVER negotiation, TLS-PRF-SHA256 → 40-byte keyblock,
  PCTR/SCTR, finished messages, record encryption. This matters because our
  `optiga_shield_handshake.pv` says in its own docstring that it was derived from `shield.rs` and
  abstracts the framing — **a model derived from our driver can only prove we modelled ourselves
  consistently.** Re-deriving from the spec makes driver-vs-spec divergence detectable.
- **NIST EA suite** v1.1.8 ([repo](https://github.com/usnistgov/SP800-90B_EntropyAssessment)) —
  self-runnable over our own TRNG samples. Statistical estimation, `silicon-E2E` tier, never a proof.
- **ANSSI Open-ISO7816-Stack** ([repo](https://github.com/ANSSI-FR/Open-ISO7816-Stack)) — MIT, but
  **archived 2025-11-24** (last commit 2022-12-05), and usable only as an *abstract block-layer*
  oracle: our wire framing diverges (CRC-16 GP1.0 reflected poly 0x8408, 2-byte LEN, fixed NAD 0x5A,
  fixed IFSC=254 with no IFS negotiation, UM11225 `0xCF` interface-reset instead of ABORT/RESYNCH).

### 4.5 Certificates — real evidence, sharply bounded
- **SCP03 has a published proof** (Sabt & Traoré, [ePrint 2017/032](https://eprint.iacr.org/2017/032))
  — for the protocol **as specified**. The SCP02 break was a **padding oracle**, i.e. implementation
  behaviour outside any spec-level model. Our driver's padding/timing/error handling is outside the
  proof. **OPTIGA's Shielded Connection has no public security analysis at all** — that asymmetry
  belongs in a `THREAT_CLAIM_MAP` row.
- **OPTIGA CC**: BSI-DSZ-CC-0961 EAL6+ covers the **IC platform** (hardware + IC dedicated software
  + Infineon crypto libraries) on a 16-bit Intel-80251-compatible core. The Trust M **applet**,
  object/OID model, LcsO and Shielded Connection are IC *Embedded Software*, **above** the boundary
  (`OE.Resp-Appl` assigns application data handling to the environment). **V4-2019 expired
  2024-12-17**; cite V7-2024. ([V4 report](https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/0961V4a_pdf.pdf))
- **SE050 CC**: [NSCIB-CC-180212-CR5](http://www.commoncriteriaportal.org/files/epfiles/NSCIB-CC-180212-CR5-1.0.pdf)
  is genuinely stronger — the TOE **includes** JCVM/JCRE/JCAPI + the GP Framework, the layer
  enforcing our UserID PIN policy. Two caveats bite exactly where we want it: **"The strength of the
  cryptographic algorithms and protocols was not rated in the course of this evaluation"** (so it
  does **not** discharge SCP03), and "Not all key sizes … satisfy the AVA_VAN.5 'high attack
  potential'". Covers only JCOP 4 SE050 v4.7 R2.00.11/R2.03.11 — **we have not confirmed our part
  matches**. SecureBox permits "execution of non-certified native software within the TOE".
- **EUCLEAK is the ceiling-setter** ([NinjaLab](https://ninjalab.io/wp-content/uploads/2024/09/20240903_eucleak.pdf)):
  a non-constant-time modular inversion in the Infineon cryptolib that "went unnoticed for **14 years
  and about 80 highest-level Common Criteria certification evaluations**". Scope it precisely: the
  attack was demonstrated on a **YubiKey 5Ci (SLE78)**; NinjaLab states the vulnerability "extends to
  the more recent Infineon Optiga Trust M" — for our part it is **tested-and-suspected, not
  demonstrated**, and it is **not a live break of our path** (C10-only per invariant #5; our OPTIGA
  driver implements exactly six APDUs and never invokes ECDSA signing). Its value is absolute and
  epistemic: **any row saying "discharged by EAL6+" is wrong.** CVE-2024-45678 is a *Yubico* CVE and
  does **not** cover OPTIGA — cite the paper, not the CVE.

### 4.6 **NEW, and the most under-used source we have: the SESIP silicon certificate**

The earlier read checked PSA Certified only, found TOE = "STM32U585 **TFM** v1.3.0", and correctly
concluded it transfers nothing (we don't run TF-M). **That was the wrong certificate.** A second,
**silicon-scoped** one exists and nothing in this repo cites it:

> **SESIP-2400133-01**, issued 2025-05-22, **valid to 2027-03-28**. TOE: "STM32U5/STM32WBA5 series
> Arm®-based 32-bit MCUs". Sponsor STMicroelectronics; lab **SGS Brightsight**. **SESIP3 + Physical
> Attacker Resistance + Software Attacker Resistance: Isolation of Platform**, under the "SESIP
> Profile for PSA Certified **RoT Component** Level 3 v1.0 REL 02".
> ST reference: **TN1545 — STM32U5x-STM32WBA5x Product Family SESIP Security Target, Rev 3** (public, 23 pp).

Why it applies where the TFM cert does not — **TN1545 §3.3.2: "The platform does not include any
firmware component and the implemented hardware is not reprogrammable."**

Four things it gives us immediately:

1. **A die pin.** TN1545 §3.3.1: DEV_ID `0x482` @ `0xE004_4000`, **REV_ID `0x3003` @ `0xE004_4002`
   = "STM32U585x version 3.3 (rev U)"**. Named errata: **ES0499**. Our anti-counterfeit probe
   (`docs/security/production-security.md:387`) checks DEV_ID only. **The certificate covers rev U
   and nothing else** — add the REV_ID check and record what our bench dies are.
2. **RDP-2 evidence, correctly scoped.** UM3387 §4.2.1: "**In its certified configuration, the
   platform is deployed in RDP level 2.**" So SESIP3 Physical Attacker Resistance — TN1545 §3.3.3:
   "**Redundancy checks to prevent RDP and HDP deconfiguration by physical tampering or
   perturbation**", plus transient-perturbation detection in SAES/PKA — was evaluated **at RDP-2, on
   rev U, by SGS Brightsight, currently valid**. That is better `T`-tier evidence than the
   absence-argument the boundary doc §5 currently leans on. It is still **bounded expert effort, not
   proof** — EUCLEAK is the standing refutation of reading it as more.
3. **We ship deliberately OUTSIDE the certified configuration, and that is correct.** TN1545 §3.5.1:
   "In the certified configuration, the Integrator allows the platform to regress to RDP Level 1 when
   the TOE secret **OEM2KEY** is successfully provisioned, and the **OEM2LOCK** option bit is set."
   `shared/src/lockdown.rs:99-104` mandates the **opposite**, on purpose — "A shipped unit must have
   **NO OEM key provisioned** — otherwise a transit attacker could pre-plant an OEM2 password
   enabling a later RDP-2 → RDP-1 regression" — enforced by `oem_locks_absent()`. So the certificate's
   "Field return of platform" SFR does **not** hold for us (no RMA path), and we must never claim
   blanket conformance. **This is a ledger row, not silent inheritance**, and it collides with the
   inventory's OWNER-GATED `provisioning-wipe-rma-authority` row.
4. **A supply-chain finding, previously unknown.** UM3387 records that ST's CubeIDE init script sets
   the **OEM2 default password `0xFACEB00C 0xDEADBABE`**, which "allows regression from RDP level 2".
   **Any board ever initialized by that script carries a known RDP2→RDP1 regression password.** This
   independently vindicates the `lockdown.rs` check — cite it there — and warrants a bench probe of
   our own boards' OEM2LOCK state.

And one that lands on our weakest row: **UM3387: "For the device to generate random numbers as
specified in NIST SP800-90B, the Integrator must use the TRNG peripheral with the *configuration A*.
Refer to the *validation conditions* subsection of the RNG section in [RM_U5]."** Our
`RNG_CR_NIST_DEFAULT = 0x00F0_0D00` (`rng.rs:44-47`) is sourced from **ST's LL driver**, not from
RM0456's validation-conditions table, and has never been compared to configuration A. That converts
the TRNG row from "bare-TCB, no ST statement" into **a falsifiable afternoon-sized check with a
section anchor**. Either answer is worth having: match ⇒ cite it, and ESV cert E11 ("STM32U5x TRNG")
plausibly applies; mismatch ⇒ `hal/src/lib.rs`'s SP 800-90B obligation is **false today**, and the
**irreversible** OTP master burn draws from a non-validated configuration.

### 4.7 Ledger patterns worth stealing (methodology, not tools)
- **OpenTitan** ([countermeasure.py](https://raw.githubusercontent.com/lowRISC/opentitan/master/util/reggen/countermeasure.py))
  — a closed 21-asset/30-type vocabulary with a **bidirectional** RTL↔Hjson cross-check: an RTL
  `// SEC_CM:` tag with no entry errors, *and* an entry absent from RTL errors. Only the **ledger**
  half transfers — they FPV silicon they designed; we never can.
- **seL4** — states machine-interface assumptions **in formal logic** and discharges them one at a
  time as tooling allows ("we do not need to trust the compiler and linker any more on architectures
  supported by our binary verification"). The precedent is *discharge progressively*, not *assume and
  stop*.
- **TF-M** ([threat model](https://trustedfirmware-m.readthedocs.io/en/latest/security/threat_models/generic_threat_model.html))
  — has **no** hardware-assumption ledger and **no** formal isolation proof, for our exact core class,
  with a port for our exact dev board. Its "**Transferred**" marker ("the threat … must be handled by
  downstream users") is a free primitive worth adopting for our `T` rows.
- **GSN** ([SCSC-141C](https://scsc.uk/r141C:1)) — with the caveat that a GSN `A` node is
  *definitionally unsubstantiated*, so a premise validated by test is a **Goal+Solution**, not an
  Assumption. Do that split explicitly or the diagram lies.

---

## 5. What does not exist — the negative results

These are results, not gaps in the search. Each was probed with multiple phrasings against primary
sources.

### 5.1 No public formal ARMv8-M model, in any framework. **Closed.**
- ARM's public machine-readable/ASL releases are **A-profile only**
  ([release note](https://alastairreid.github.io/ARM-v8a-xml-release/): "version 8.2 of the ARM
  **v8-A** processor specification"; [mra_tools](https://github.com/alastairreid/mra_tools) documents
  exactly three v8-A tarballs and is ~6.5 y stale).
- ARM's **internal** v8-M ASL exists and was validated to a high standard — Reid, OOPSLA 2017: 59
  properties, 315 VCs, **299 proved**, **12 bugs found incl. 2 security bugs, all fixed by ARM**
  ([paper](https://alastairreid.github.io/papers/OOPSLA_17/)). **Never released.** *Corrections to
  earlier readings*: it is **single-authored**; **13** VCs timed out (not "6–7"), so Reid states "our
  proofs are not yet sound"; and **SAU/IDAU/CMSE/SG appear zero times** — it validated reset,
  exceptions, lockup, debug and S/NS register banking, not the mechanisms we depend on.
- [`rems-project/sail-arm`](https://github.com/rems-project/sail-arm) is A-profile only
  (`arm-v8.5-a`, `arm-v9.3-a`, `arm-v9.4-a`), auto-translated from ARM's *internal* ASL under
  bilateral agreement. **Therefore [Isla](https://github.com/rems-project/isla) and
  [Islaris](https://people.mpi-sws.org/~dg/papers/pldi2022.pdf) have nothing to consume** — one
  missing input, three dead tools.
- Binary tooling agrees: BINSEC has no M-profile decoder; angr/VEX has a v8-M-aware *arch description*
  (incl. `msp_s/_ns`, `msplim_s/_ns`) but **zero** v8-M security-extension **decode** in
  `guest_arm_toIR.c`; Ghidra decodes M-profile, but implements the stack-limit registers as
  **uninterpreted pcodeops** and has **no SG/TT definition at all**; ARMORY stops at ARMv7-M; FiSim
  hardcodes `UC_MODE_ARM` and never selects M-class; Corana's "M33" model is the Cortex-M7 model plus
  six acquire/release ops, with **zero** CMSE.
- **Even a hypothetical Sail v8-M model would only be half.** The IDAU is IMPLEMENTATION DEFINED
  (ST's), and **GTZC is an ST peripheral appearing in no ARM specification** — and GTZC is where
  `sau.rs` puts our enforcement.
- **The blocker is availability, not effort.** Two routes exist (license the internal ASL — the exact
  route sail-arm took for A-profile; or hand-author from DDI0553 prose, precedented by Sail's own
  handwritten Armv8-A fragment) and both are person-years yielding a **bespoke, unvalidated model
  whose own correctness becomes a new cited-TCB axiom**. Record as **permanently blocked upstream**.

### 5.2 No formal verification of TF-M, and no M-profile TrustZone isolation proof anywhere.
The reference SPE for our exact silicon has none — assurance is threat models, review, testing, MISRA
static analysis (BUGSENG ECLAIR in Open CI — a real formal method, but coding-standard/UB compliance,
not SPM/PSA/isolation correctness) and PSA/SESIP evaluation. **We are at the industry norm, and
`make gtzc-enforcement-hw`'s 7/7 RAZ-fault test is arguably stronger evidence than TF-M publishes.**
Scope the negative correctly: MPU-based M-profile isolation **has** been proven —
[Pip-MPU](https://arxiv.org/abs/2301.04546) (Coq, ~10 kLOP, found a critical isolation bug) — but it
is **MPU, not CMSE/SAU/IDAU**, is **partial** (3 of 15 services), proves an ownership invariant that
is explicitly "not concerned about the read, write, and execution rights", and its model is
architecture-neutral. The surviving true statement: **every TrustZone-M/CMSE isolation proof is
A-profile — i.e. there are none.**

### 5.3 No formal model of T=1 / T=1′ / IFX-I2C framing.
The only formal T=1 work found (Chouali et al., PLTL/SPIN, [arXiv:cs/0602040](https://arxiv.org/abs/cs/0602040))
models block/last-block/ack alternation **only** — grep yields zero occurrences of I/R/S-blocks,
sequence numbers, EDC, chaining, resynch, retry, WTX or guard timing. **It is not a head start.**
Nothing exists for NXP's T=1′ or Infineon's IFX-I2C. No verified I2C **driver** exists in any
language (the I2C formal work is **RTL** verification, requiring design source).

### 5.4 No embedded flash/OTP litmus suite exists.
The tradition exists in two **disconnected** halves and nobody joined them: the
model-validated-by-generated-tests **method** ([Ferrite, ASPLOS'16](https://homes.cs.washington.edu/~mernst/pubs/crash-consistency-asplos2016.pdf);
herd7/litmus7), and the power-cut **rig on real flash** (Tseng, DAC'11). Joining them for STM32U5
appears **unprecedented** — which makes it a genuine research contribution and a bad first project.
Ferrite is **not** a hardware-contract validator: §5.1 says it "abstracts the behavior of storage
hardware with a disk model", having rejected interposing on hardware as "expensive and imprecise";
its disk model is an assumed input, never validated. Repo is 9+ y stale, pinned to Rosette 2.0.

### 5.5 No SVD → formal-model generator; no ARM/STM32 errata corpus; no errata-vs-usage checker.
[RemembERR](https://comsec.ethz.ch/wp-content/files/rememberr_micro22.pdf) is "the first large-scale
database of microprocessor errata" — **Intel/AMD only**, 2,563 entries, built by **manual four-eyes
annotation**, because errata sheets "are not machine-readable" and contain errors about their own
errata. **No tool anywhere machine-checks errata-vs-usage, for any architecture.** Its schema
(trigger ∧ / context ∨ / observation ∨) is portable; its data is not. Its sharpest result — **>40% of
errata need two combined triggers** — is a direct warning that our single-condition bench tests
systematically under-detect.

### 5.6 Refuted or corrected claims — checked and found wanting
Recorded so they are not re-litigated:

| Claim | Verdict |
|---|---|
| "CompCert doesn't reach Thumb/M-profile" | **False.** `configure -arch armv7m` = "ARMv7-M + VFPv3-d16"; `-mthumb` is the default for that profile. It's still reference-only for us — CompCert compiles **C**; our secure world is Rust. No `armv8m` target exists, so no CMSE/SAU. |
| "The ARMv8-M ASL doesn't exist / ARM never built one" | **False.** It exists, was validated (Reid), and is unreleased. The blocker is *publication*, not existence. |
| "Tseng (DAC'11) refutes flash chunk-atomicity" | **Refuted for us.** MLC-scoped, raw NAND, no ECC, no NOR; its own §5 preserves SLC log recovery. |
| "The ST forum thread proves STM32U5 OTP half-QWs are silicon-stranded" | **Refuted.** ST confirmed the issue and fixed it **in STM32CubeProgrammer v2.19.0**, stating no root cause; a tool-side fix is consistent with "never latched" *and* with "silicon strands them". It is also the **host SWD path**, not our firmware path. **Cite it as silicon semantics in neither direction.** |
| "Ferrite is the template for validating a hardware crash contract" | **Refuted.** It validates *software* against an *assumed* disk model and explicitly excludes "disk corruption caused by … broken hardware". |
| "PERRY/SEmu/Fuzzware models can serve as our hardware contract" | **Refuted.** PERRY infers from the driver (circular); Fuzzware's "model" describes firmware *value consumption*, not the device; SEmu is manual-prose NLP that empirically **cannot model clock peripherals or I2C**. |
| "EAL6 means nobody built a formal model" | **Inverted.** ADV_SPM.1 is **mandatory** in the EAL6/EAL7 packages. But its scope was an ST-author *assignment* (CC 3.1), and the JIL/EUCC CC:2022 minimum is a named sub-TSF (MPU/MMU + code loader for ICs; the application firewall for Java Card). **None of that covers OPTIGA's LcsO or SE050's APDU/policy behaviour** — and the artifact is confidential regardless. |
| "Trezor Safe 5 / STM32U5 is unaffected by the Donjon RDP glitch" | **Stale, and it's Trezor's wording, not Ledger's.** Ledger said only that no U5 FI attack was public "at the time of this writing". Šimoník (Masaryk, 2025) reports **76% voltage-glitch PIN-check bypass on the STM32U5A9**. |
| "No published break on a Cortex-M33 STM32" | **False.** µ-Glitch (USENIX Sec'23) **disables TrustZone-M on the STM32L5** (M33) by faulting SAU + Global TZ Configuration, and cites ST's joint L5/U5 TrustZone app note. |
| "BINSEC decodes plain Thumb-2 fine; only CMSE (`sg`/`bxns`/`tt`) fails, so the real boundary is CMSE, not thumbv8m" — *this survey's own G1 correction* | **WITHDRAWN by the author's on-box probe** (boundary doc follow-up #6, `[tool]` — which outranks `[survey]`). BINSEC does expose `-arm-supported-modes {both\|thumb\|arm}`, so the SOTA doc's flat "no M-profile decoder" is imprecise about the *option surface*. But in `thumb` mode BINSEC emits `unimplemented` **uniformly, including on a plain `adds`/`eors`/`bx` function**, then dies with an assertion failure in `disasm_core.ml`; plain and CMSE probes are **indistinguishable**. **The SOTA doc's operational verdict — BINSEC NO-GO for our thumbv8m ELF — stands.** The inventory row is still wrong, but for the *original* reason. Recorded here as a caught error, not deleted. |

---

## 6. What we could build

Ranked by (value to a **live claim**) × tractability. Read as a **pipeline, not a menu** — the
dependency order is forced: **pin+resolve the contract → ledger it → wire the seam → prove logic
against it; silicon tests validate the leaf.**

### Tier 1

**P1. RM0456/ES0499 §-anchor pass + kill the false HAL claim.**
*Property:* every prose hardware premise in `hw/otp.rs`, `hw/flash.rs`, `hal/src/lib.rs` traces to a
§/page anchor, and the two contradictory flash claims resolve to one. *Not established:* anything
about silicon — this is claim-truth hygiene (unsourced prose → cited-TCB, a real tier change).
*Refactor:* none. *Artifact:* §-anchored doc comments + a resolution note. *Negative control:* n/a
(not a gate). *Stop condition:* if RM0456 does not settle partial-QW reprogramming, **stop and record
it as an open silicon question** → P6b's first target. Do not guess. *Effort:* **2–4 d.** TN1545/UM3387
now name the exact anchors (RM0456 §48 RNG validation conditions, §3.10.1 OEM2 unlock sequence B, §50
SAES wrapped keys), so this is a targeted lookup, not a 3000-page search.

**P2. Hardware-assumption ledger — as an *extension*, not a third ledger.**
*Property:* every silicon premise a claim depends on has an ID, owner, primary-source anchor, status,
a named falsifying test, and the consuming claim. Gate fails if a claim names an unledgered assumption
or overstates a tier. *Not established:* anything about hardware — this is **enumeration discipline**.
*Refactor:* **extend `TRUST_ASSUMPTIONS.md`'s scope (its §Out-of-scope excludes firmware — that is the
actual defect) and reuse `AXIOM_STATUS.json`'s schema + `check_ledger_consistency.py --self-test`.** Do
not mint a third ledger. *Reframed by §4.6:* **half of this already exists and is addressed to us** —
TN1545 §2.1 Table 6 publishes four operational-environment objectives (`KEY_MANAGEMENT`,
`TRUSTED_INTEGRATOR`, `UNIQUE_ID`, `LIFECYCLE`) and UM3387 §4.2.4 enumerates the measures to discharge
them. **Import ST's objectives and answer each with our evidence + a named test** — cheaper and more
defensible than inventing a novel artifact, and it makes the OEM2 deviation a visible row.
*Negative control:* `--self-test` feeds corrupted ledgers — a row with no cite; a claim referencing an
unledgered ID; a row claiming `status: validated` whose named test target does not exist in the
Makefile. *The trap:* the `falsifying_test` column **must distinguish `wired` (a real passing target)
from `asserted`**. A ledger where every row says `TODO` is theatre with a schema — print the
wired/asserted ratio and fail on `validated` without a wired target. Today the honest ratio is poor.
*Effort:* **1–2 wk** after P1.

**P3. SVD-derived register-transcription gate.**
*Property:* every hand-transcribed peripheral base/offset in `secure/src/hw/*` matches the patched
U585 SVD — **plus** `lockdown.rs`'s BENCH-CONFIRM'd `OEM1LOCK`/`OEM2LOCK` positions in `FLASH_OPTSR`,
which given §4.6 is the highest-value single use of the SVD in the repo (it guards a ship gate).
*Not established:* **behaviour, ES0499, or SAU/SCB/NVIC/OTP** (absent from the SVD). *Refactor:* none;
vendor the SVD + a digest pin. *Artifact:* `make verify-svd-transcription`. *Negative control:* flip a
base address in a fixture → RED. *Why:* the repo is **3-for-3 on transcription failures** — TAMP at the
wrong address (silent, never exercised), GTZC TZSC writes landing on the TZIC base and silently
no-op'ing, ICACHE off by `0x400`. CompCert's `TargetPrinter` failure mode exactly. *Effort:* **3–5 d.**

**P4. Gate + de-cruft the page-123 TLA+ pilot.**
*Property:* the banked "SIGS-first ordering CONFIRMED (1M states)" claim becomes **re-runnable by
someone other than its author**. *Artifact:* `make verify-tla-page123`; pin `tla2tools.jar` with a
digest + fetch step; `.gitignore` the 29 untracked `_TTrace_*` files. *Negative control:* a mutated
spec reversing SIGS-first must make TLC report a violation. *Why:* an already-cited claim with no
executable evidence is, by our own definition, theatre. *Effort:* **1–2 d.**

**P4b. Read TN1545 + UM3387; add the REV_ID check.** *(§4.6 — folded here because it is hours.)*
*Property:* four bare-TCB rows gain a vendor+lab anchor; the OEM2 deviation becomes explicit; the
config-A question becomes answerable; rev-U coverage becomes checkable. *Artifact:* REV_ID `0x3003`
probe beside the existing DEV_ID `0x482` probe; ledger rows. *Effort:* **1 d.**

### Tier 2 — real proofs, gated on the seam

**P5. Wire the `hal/` seam + promote the mock to `hal-mock/`.** ← **the structural move**
*Property:* driver **logic** (journal append, compaction, counter scan, burn-completion predicate,
framing) becomes host-linkable — hence Kani/Miri-reachable — and the hardware contract becomes a
**compile-time-enforced object** rather than prose that has already silently drifted false.
*Not established:* anything about MMIO or silicon. **The model-vs-silicon gap does not close — it
moves.** Answering directly: this is **progress, not theatre, iff** (a) the contract is a ledgered
assumption (P2) **and** (b) it has an empirical leg (P6b / P8a / `gtzc-enforcement-hw`). Untethered
from both, it *is* theatre. Tethered, it is exactly Pancake's and Veld's posture — i.e. the 2025 SOTA.
*The live defect it fixes:*

> `hal/src/lib.rs:104-113` declares itself the specification and asserts that programming an
> already-cleared bit is a **no-op**. `secure/src/hw/flash.rs:723-729` asserts ECC **locks** the value
> and forbids re-programming. **Both cannot be true.** The page-124 PIN-counter design depends on
> which. `secure/Cargo.toml` has **no dependency on `hal/`** — so nothing, not the compiler, not CI,
> not a reviewer, detects it. **An unsound axiom with no gate** — Kobeissi's *Verification Theatre*
> ([ePrint 2026/192](https://eprint.iacr.org/2026/192)) live in-repo.

*Refactor (cheaper than assumed):* `MockFlash`/`MockOtp`/`MockSaes`/`MockI2c` **already exist** in
`hal/tests/positive_mock_platform.rs`. (1) add `pqsigner-hal` to `secure/Cargo.toml`; (2) promote the
test mocks into the already-named-but-deferred `hal-mock/`; (3) carve driver **logic** behind traits,
leaving raw MMIO in the leaf (`hw/mmio.rs` stays exactly where it is — Miri can never reach it).
***THE TRAP — scope the seam away from page 124.*** Trait monomorphization is in tension with the
`#[inline(never)]` at `flash.rs:862`, which exists **specifically** so `nsc::gated_unlock`'s FI FAIL-IN
sees a real `bl` at the call site; an inlined body lets a glitch skip the program with no branch for
the sentinel to catch. **A generic refactor of the PIN path could silently weaken FI hardening.** Take
the seam through `offchain_state`/journal/OTP-predicate logic; leave page-124 alone or preserve the
`bl` explicitly and re-verify. *Stop condition:* if carving a driver forces the FI `bl` to disappear,
stop on that driver and record why. *Effort:* **3–4 wk** (does not include flash.rs's 2243 lines
wholesale — carve incrementally).

**P6a. OTP monotone-lattice model + half-burn refutation (Kani, post-seam).**
*Property:* over a `MockOtp` encoding **quad-word program-once** (not a bit-lattice — see §2), that the
version floor never depends on a non-monotone read, and — the real payload — that
**`is_device_master_burned()` is wrong**: it returns `true` on any non-`0xFF` word (`otp.rs:503-513`),
so a crash between the two quad-words of `burn_device_master` yields a device reporting "burned" while
holding a **128-bit-entropy master key** that roots every SE pairing secret. Decidable; Kani refutes it.
Fix = require both QWs + a completion marker. This is Ariadne's crash contract exactly ("if it crashes,
the counter may or may not have been incremented" — recovery must be safe under that ambiguity; today
it isn't). *Not established:* fuse physics. **Model the third outcome** (torn QW → ECC-uncorrectable,
neither old nor new) explicitly or the proof is optimistic. *Negative control:* a mutant accepting a
single-QW burn must fail; a mutant allowing 0→1 must fail. *Effort:* **1–2 wk** post-P5. **Value: a
live bug in an irreversible path.**

**P6b. OTP one-wayness silicon probe — *and it does NOT need a sacrificial board*.**
Earlier costing said "buy a board to destroy". Wrong: `otp.rs:32`'s region map shows
`176..512 | 336 B | **Unallocated**` — **21 free quad-words**, with the device master at 128..160. Probe
an unallocated QW (e.g. `OTP_BASE+0xB0`); the master region stays virgin, the board stays usable, and
you get **~21 shots on one board** at swept delays. Only blocker: `program_otp_qw`'s
`debug_assert!(addr + 16 <= OTP_BASE + OTP_RESERVED_BYTES)` (=176), which a test-only path must widen.
*Property:* whether a second program of a burned QW is rejected on **our** silicon, and what a
half-burn actually does. Validates P2's OTP row and P6a's contract; settles the C-10 ambiguity that
prose cannot. *Negative control:* the test must **observe** PGSERR/PGSERR-class SR bits, not merely
not-crash — assert the specific bit. *Effort:* **2–3 d, one non-sacrificial board.** → **promote to
Tier 1.**

**P7. Kani over T=1′ pure framing functions — no seam needed, do it now.**
*Property:* `se050/t1oi2c.rs`'s `crc16`/`build_frame`/`validate_frame` are **pure functions over byte
slices** — panic-freedom, framing round-trip, no accept-of-malformed. Zero refactor, zero silicon.
*Adjacent cheap win:* our `crc16` claims byte-compatibility with NXP's
`phNxpEseProto7816_ComputeCRC`, but that reference is **not vendored and not differentially tested**,
and no public KAT for this variant exists — build our own. *Negative control:* a mutant polynomial /
off-by-one LEN must fail. *Effort:* **3–5 d. The cheapest real proof in the set.**

### Tier 3 — worth doing, honestly bounded

**P8a. Flash recovery-logic stress (no new hardware).** The naive framing — "power-cut mid-program on
real silicon" — **must be split, and the LA1010 cannot do it: it is read-only; it observes, it does not
glitch.** P8a fires a sysreset/IWDG timeout at a **swept delay** after a firmware trigger-GPIO placed
mid-journal-write, via probe-rs. **Zero extra hardware.** Validates exactly the obligation the TLA+
model states — recovery yields old-or-new-or-fail-closed, counters never decrease — against real flash
and real ICACHE. *Negative control:* **a build with SIGS-first ordering deliberately reversed must
produce an observed violation** — otherwise the harness proves nothing. *Effort:* **1–2 wk. Tier-1-grade
value; listed here only to sit beside P8b.**

**P8b. Analog torn-write-granularity bounding — defer, don't cancel.** Needs a load switch on the IDD
break + a fine delay generator (ChipWhisperer/PicoEMP-class — **not in inventory**). The only genuinely
hardware-gated item. It validates **one** assumption that P8a and the existing
`write_quadword_verified` read-back largely cover. Tseng proves such rigs *change answers* — but that
was NAND, not our embedded ECC NOR, so the transfer is unlicensed. **Months + procurement.**

**P9. T=1′ / IFX-I2C framing FSM model (TLA+, from scratch).**
*Property, framed correctly:* **the PIN accounting, not the tunnel.** No bus loss/dup/reorder may
desync the SCP03 session **or miscount the three-way per-attempt consumption**. Invariant #2 crosses
this layer, and `pin-gate-hw-counter-e2e` explicitly has **no reboot/reconcile coverage** — that is
the untested leg. `t1oi2c.rs` is a textbook **alternating-bit protocol** (`PCB_I_SEQ = 0x40`, `ns`/`nr`
toggling, R-block acks, `MAX_WTX_RETRIES = 500`); that 1-bit sequence number is precisely how a lost
response could cause a **duplicate apply** — a double-charged PIN attempt or a re-issued PUT KEY.
*The OPTIGA half is cheaper and better:* Infineon I2C v2.03 §6 is public and wire-complete, so
re-deriving `optiga_shield_handshake.pv` from the **vendor spec** instead of from `shield.rs` is a real
upgrade, buildable now. *Negative control:* a spec permitting a dropped R-block ack must violate the
counting invariant. *Effort:* **3–4 wk.**

**P10. ES0499 read (days) + an errata-coverage table (manual, forever).**
*First action, feeds P1/P2/P6:* **read ES0499 for a flash/OTP/ECC erratum.** It is the certificate's own
named errata document (TN1545 §3.3.1 cites rev 9), which makes this a certification-scope check, not
hygiene. The repo has already been bitten once (ES0499 SPI EOT truncation, found by crashing rather than
reading). *The gate:* `erratum × do-we-use-the-feature × mitigated-with-cite / explicitly-accepted`,
with a script asserting no unclassified row. **This is manual curation — no tool exists (§5.5), for any
architecture.** *Negative control:* an unclassified row → RED. *Effort:* **1 wk + ongoing manual
maintenance — price that honestly.**

### Rejected — do not build
- **Any ARMv8-M/CMSE formalization.** §5.1. Ledger it as blocked upstream; don't carry it as backlog.
- **A "device model" without P2 + an empirical leg.** That combination is theatre, by our own criterion.
- **Errata *automation*.** RemembERR was built by manual four-eyes annotation for exactly this reason.
- **Modelling OPTIGA/SE050 internals.** Pure relocation; no test can reach inside the die.
- **Adopting Verus for the flash journal *as currently rowed*.** Flux has a published Cortex-M
  deployment; Verus has none. Revisit that row's tool choice. Either way it is post-seam, and Kani is
  already installed and CI-wired.

---

## 7. Ranked recommendation

Sequence, each tied to a live claim, each with a stop condition — matching the roadmap's P2 pilot
discipline.

| # | Do | Claim/row it moves | Stop condition | Effort |
|---|---|---|---|---|
| 1 | **P4b** — read TN1545 + UM3387; add the REV_ID `0x3003` probe; record OEM2LOCK state on our boards | `HW-ASSUME-RDP2` (bare-TCB → scoped `T`); `HW-ASSUME-TRNG-ENTROPY`; anti-counterfeit probe | If our dies are **not** rev U, the certificate covers nothing we ship — say so and stop citing it | **1 d** |
| 2 | **P1** — RM0456/ES0499 anchors; resolve `hal` vs `flash.rs` | `HW-ASSUME-QW-ATOMIC`, `HW-ASSUME-OTP-ONEWAY` | If RM0456 doesn't settle partial-QW reprogramming, record as open → P6b. **Do not guess** | **2–4 d** |
| 3 | **P4** — gate the TLA+ pilot | The already-cited page-123 crash-atomicity claim | Mutant must go RED, else the pilot proves nothing | **1–2 d** |
| 4 | **P7** — Kani the T=1′ framing/CRC | inv #2 (framing under the PIN path); `firmware-bounded-verification-coverage` | Mutant CRC must fail | **3–5 d** |
| 5 | **P6b** — OTP probe on an unallocated QW | `HW-ASSUME-OTP-ONEWAY`; S-DHUK-OTP-EXTRACT context | Must observe the SR bit, not just "no crash" | **2–3 d, 1 board** |
| 6 | **P3** — SVD gate, incl. `FLASH_OPTSR` OEM bits | `lockdown.rs` BENCH-CONFIRM (a **ship gate**); 3 historical bugs | Fixture flip must go RED | **3–5 d** |
| 7 | **P2** — ledger, importing TN1545's four objectives | Every `T` row in `THREAT_CLAIM_MAP`; `TRUST_ASSUMPTIONS.md` firmware hole | If the wired/asserted ratio can't be printed, it's theatre with a schema — don't ship it | **1–2 wk** |
| 8 | **P10** — ES0499 read | `HW-ASSUME-CMSE-SAU`, flash rows | If ES0499 names a flash/OTP/ECC erratum, it **preempts** P1's resolution | **1 wk** |
| 9 | **P5** — wire the seam (journal/OTP logic; **not** page 124) | The live unsound axiom; unblocks P6a; `target-only-unsafe-mmio-concurrency` | **Stop on any driver whose FI `bl` disappears** | **3–4 wk** |
| 10 | **P6a** — Kani OTP half-burn | `is_device_master_burned()` — a live bug in an **irreversible** path | If Kani can't express the ECC third outcome, say so rather than proving the optimistic model | **1–2 wk** |
| 11 | **P8a** — flash recovery stress | `durable-counter-crash-recovery`'s silicon leg; inv #9 | Reversed-ordering build must show a violation | **1–2 wk** |
| 12 | **P9** — framing FSM + spec-derived `.pv` | inv #2 reconcile leg; `HW-ASSUME-PUTKEY-ATOMIC` | If the model can't express duplicate-apply, it's the wrong abstraction | **3–4 wk** |

**Not in this list, and it should keep you up at night more than any of it:** against an attacker who
takes the device, modifies it, and returns it, the dual-SE split is worth **nothing** — the user types
the PIN into the attacker's code — and everything rests on RDP-2 plus eight words the user has to
actually check, on an FSBL that is explicitly *not yet an immutable trust root*. Boundary doc §5.

**Two ship-blocker adjacencies:** S-1/S-2/S-3 (OPTIGA lockdown) are **untouched** by this report and
correctly remain deferred-by-design; nothing here is a substitute. But P4b's OEM2 finding and P6b's OTP
probe both feed the first-boot ceremony's named open gate ("atomic durable old/new/KVN recovery proof"),
and `HW-ASSUME-PUTKEY-ATOMIC` (boundary §6) is its sharpest statement.

---

## 8. No-gos and overclaim traps

Full matched entitled/overclaim table: **boundary doc §3**. It is not repeated here. Three permanent
bans stand: **"formally verified" with no object**; **"certified therefore secure"** (EUCLEAK is the
standing refutation); **"proven" applied to any silicon behaviour** — we never prove silicon, we test it.

New traps this survey creates, with the exact dishonest language:

| Do not write | Why |
|---|---|
| "Our platform is SESIP3 / PSA Level 3 certified." | The TFM cert's TOE is **TF-M v1.3.0**, which we do not run. The silicon cert (SESIP-2400133-01) covers **rev U** dies, which we have not matched, **in its certified configuration** — and we ship **deliberately outside** it (no OEM2KEY, no RDP-1 regression path, no field return). Entitled: *"The STM32U5 silicon holds SESIP3 + Physical Attacker Resistance (SESIP-2400133-01, valid to 2027-03-28, evaluated at RDP-2 on rev U). We deviate from its certified configuration by refusing OEM2 provisioning — deliberately, per `lockdown.rs`, and therefore the field-return SFR does not apply to us."* |
| "RDP-2 is evaluated, therefore RDP-2 holds." | It is **bounded expert effort**, and its own scheme's ceiling is EUCLEAK. U5 is **proven** glitch-vulnerable at the core level; its M33 sibling has a **proven** TrustZone-M disable. |
| "Our TRNG is SP 800-90B compliant." | No ESV cert names the U585; E11 covers "STM32U5x" but has **no PUD**; **no health tests are implemented**; and our `RNG_CR` constant has never been compared to **configuration A**. |
| "DHUK is per-die and physically protected." | Per-die: **n=2**, at RDP1, ours. Physical protection: the vendor **conditions** it on a TAMP configuration we never validated. |
| "`make checkct` proves our crypto leaves constant-time on the shipped M33 ISA." | **Unestablished in both directions.** It is *wired* at thumbv8m — but the author's BINSEC probe fails uniformly in thumb mode, it is unresolved whether cargo-checkct drives BINSEC at all, and the target has **no defined pass signal** (it deliberately contains an insecure driver, so exit code ≠ verdict). Do not cite it as green until (i) and (ii) in §4.1 are closed. Equally, do not write the opposite ("CT is unprovable on M33") — that is also unestablished. |
| "We verified the driver against a device model." | Verified *what*, against *what model*, at *what granularity*, pinned by *what test*? Without a falsifying test the model is a second copy of your belief (§2). |
| "Our OPTIGA is EUCLEAK-vulnerable." | Overstated. NinjaLab **demonstrated** on a YubiKey 5Ci and states the vulnerability **extends** to Trust M. Write what NinjaLab wrote. And note it is not on our path (C10-only; six APDUs; no ECDSA sign). |
| "Neither chip alone reveals any bit of the seed." | Strictly true **chip-locally**; misleading system-level. `masterPkRoot` is a public on-chain commitment, so the split is **computational, not information-theoretic** — by construction. Never use "information-theoretic split". Boundary §4. |

---

## 9. Delta vs the 47-surface inventory

**Rows this research CHANGES:**

| Row | Change |
|---|---|
| `shipping-thumb-ct-binsec` | **Row still wrong; the survey's proposed fix is WITHDRAWN.** Its premise ("first prove BINSEC decodes the emitted M33 subset") remains wrong — but the author's on-box probe (`[tool]`, boundary follow-up #6) shows BINSEC's thumb mode fails **uniformly, including on plain non-CMSE instructions**, so the SOTA doc's operational NO-GO **stands** and the "boundary is CMSE" refinement is retracted. The only correction the SOTA doc needs is precision about the *option surface* (`-arm-supported-modes` exists). **New first step, replacing both framings: resolve (i) whether `cargo-checkct` drives a BINSEC frontend at all, and (ii) whether `make checkct` runs green — it has no defined pass signal today. Do not edit the SOTA doc or the inventory until both are answered.** |
| `trustzone-linker-map-proof` (P1.9) | **Confirmed and externally sourced.** Its out-of-scope declaration ("CMSE instruction semantics not modeled") is not conservatism — it is arithmetic (§5.1). **Fold P3's SVD diff into it** (it already proposes a generated-fact checker over `.map` + SECCFGR images). Add: the GTZC receipt is taken on a **non-shipping** feature combo while `sau.rs` has 12 `cfg(feature)` gates inside the peripheral security config. |
| `verus-power-flash-journal-pilot` | **Tool choice weakened.** Verus has **no** published embedded case study; Flux has one on Cortex-M. Row already carries the right caveat (PoWER must be *adapted*, not copied) — add that the ECC third outcome breaks PoWER's **core disjunction**, and that Verus is absent from this box while Kani is likely not a PoWER host. |
| `durable-counter-crash-recovery` | **Two sub-items, not new IDs.** Its First-step is *literally* the TLA+ spec that the page-123 pilot already delivered — so **P4 is this row's missing gate** and **P8a is its silicon leg**. |
| `target-only-unsafe-mmio-concurrency` | **P5 is this row's decision.** Its First-step ("per block, decide extractable-to-host vs cited-TCB-with-on-target-test") *is* the seam carve. Add the FI `bl` trap as a constraint. |
| `firmware-bounded-verification-coverage` | **P7 lands inside it** (decoders + counters). |
| `provisioning-wipe-rma-authority` (OWNER-GATED) | **Collides with the certified configuration.** TN1545's field-return SFR presumes OEM2KEY + RDP-1 regression; `lockdown.rs` forbids it. Whatever the owner decides, it is now a *documented deviation from a live certificate*, not an open design question. |
| `directional-pin-reconcile-model` | **P9 is its missing layer.** The crypto is modelled; the framing that carries every PIN attempt is not, and `pin-gate-hw-counter-e2e` has no reboot/reconcile coverage. |

**Rows this research does NOT affect:** everything chain-side (`K`/`B`-tier — invariants #5–#7 are
proven and silicon-independent); the OPTIGA ship-blockers S-1/S-2/S-3 (deferred by design; nothing here
substitutes); the Lean/Aeneas track; the EasyCrypt track; the ERC-7730 surfaces.

**NEW surfaces this adds** (candidate rows — 8, all falsifiable):
1. **`hw-assumption-ledger`** — extend `TRUST_ASSUMPTIONS.md` past its firmware exclusion; import
   TN1545's four operational-environment objectives (P2).
2. **`t1oi2c-framing-fsm-model`** — TLA+ alternating-bit/duplicate-apply model (P9). No prior art (§5.3).
3. **`optiga-shield-spec-derived-model`** — re-derive the `.pv` from Infineon I2C v2.03 §6 rather than
   from `shield.rs`.
4. **`svd-register-transcription-gate`** — incl. `FLASH_OPTSR` OEM-lock bits (P3).
5. **`trng-configuration-a-conformance`** — is `0x00F0_0D00` == RM0456 configuration A? (P4b/§4.6.)
6. **`otp-halfburn-refutation`** — `is_device_master_burned()` accepts a single-QW burn (P6a) + the
   21-free-QW silicon probe (P6b).
7. **`tamp-dhuk-conditioning`** — merge TAMP and DHUK into one row: the vendor **conditions** DHUK's
   physical-resistance claim on a TAMP configuration we never validated, and `tamp-wipe` is forced ON
   for shipping and never silicon-tested.
8. **`rev-u-die-match`** — REV_ID `0x3003` probe; the certificate covers rev U and nothing else.

**Open, unresolved, and cheap:** RM0456 §48 / §3.10.1 / §50 and **ES0499** are still unfetched. TN1545
and UM3387 now name the exact anchors, so these are targeted lookups (P1/P10), no longer a search.

---

## 10. Sources

All URLs below were fetched and verified during the survey. Grouped by bucket.

**ARMv8-M ISA / CMSE (surface c) — all negative**
- ARM MRA release (A-profile only): https://alastairreid.github.io/ARM-v8a-xml-release/
- mra_tools (three v8-A tarballs; ~6.5 y stale): https://github.com/alastairreid/mra_tools
- Reid, OOPSLA 2017 (v8-M spec validation; unreleased artifact): https://alastairreid.github.io/papers/OOPSLA_17/
- Reid, FMCAD 2016 (A-class **and** M-class ASL exist internally): https://alastairreid.github.io/papers/FMCAD_16/
- Reid, validating specs (methodology): https://alastairreid.github.io/validating-specs/
- sail-arm (A-profile only): https://github.com/rems-project/sail-arm · contents API: https://api.github.com/repos/rems-project/sail-arm/contents
- Sail: https://github.com/rems-project/sail · Isla: https://github.com/rems-project/isla · isla-snapshots: https://github.com/rems-project/isla-snapshots
- Islaris (PLDI'22, A-profile + RISC-V, 64-bit LE only): https://people.mpi-sws.org/~dg/papers/pldi2022.pdf
- TF-M security (no formal-methods content): https://tf-m.docs.trustedfirmware.org/en/latest/security/
- TF-M FF-M isolation ("fully enumerated and audited"): https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/ff_isolation.html
- seL4 verified configurations (no M-profile): https://docs.sel4.systems/projects/sel4/verified-configurations.html
- seL4 FAQ (MMU-fundamental): https://sel4.systems/About/FAQ.html
- Pip-MPU (MPU-based M-profile isolation proof — **not** CMSE): https://arxiv.org/abs/2301.04546
- Ghidra ARM SLEIGH msplim issue (**closed**, fixed in 11.4 — 2025-06-24): https://github.com/NationalSecurityAgency/ghidra/issues/5255
- angr archinfo (v8-M-aware arch description; VEX has no v8-M decode): https://api.angr.io/archinfo.html

**Device models / drivers (surfaces b, d)**
- Pancake, "Verifying Device Drivers with Pancake" (hand-written model, explicitly trusted): https://arxiv.org/html/2501.08249v2
- Veld (Rust+Verus, partial hardware model, x86 MSR): https://mars-research.github.io/doc/2024-kisv-veld.pdf
- Termite-1 (SOSP'09; spec↔RTL check never implemented): https://www.sigops.org/s/conferences/sosp/2009/papers/ryzhyk-sosp09.pdf
- Termite-2 (OSDI'14; no timed behaviour; abandonware since 2017): https://www.usenix.org/system/files/conference/osdi14/osdi14-paper-ryzhyk.pdf
- seL4 Device Formalisation / sDDF (requires Verilog RTL): https://trustworthy.systems/projects/drivers/
- PERRY (infers the model **from the driver** — circular): https://www.usenix.org/system/files/sec24summer-prepub-600-lei.pdf
- SEmu (chip-manual NLP; cannot model clock or I2C): https://guanle.org/pdf/ccs22.pdf
- Fuzzware (rehosting/fuzzing; M3/M4 only; "model" = firmware value consumption): https://github.com/fuzzware-fuzzer/fuzzware
- HIVE (firmware/RTL co-verification — needs RTL): https://arxiv.org/html/2309.08002v2
- Silveroak/Cava (Bedrock2 driver ↔ Cava device over MMIO; **archived 2022**; RISC-V): https://github.com/project-oak/silveroak
- Miri (provenance blocks MMIO): https://github.com/rust-lang/miri
- Rust UCG #33, volatile/MMIO (**closed 2023**; raw pointers are fine): https://github.com/rust-lang/unsafe-code-guidelines/issues/33
- stm32-rs patched U585 SVD: https://stm32-rs.github.io/stm32-rs/
- ANSSI Open-ISO7816-Stack (**archived 2025-11-24**): https://github.com/ANSSI-FR/Open-ISO7816-Stack

**Flash / OTP / crash consistency (surfaces a, b)**
- PoWER + CapybaraKV (OSDI'25; chunked crash model in Verus): https://people.csail.mit.edu/nickolai/papers/leblanc-power.pdf · artifact: https://github.com/microsoft/verified-storage
- FSCQ / Crash Hoare Logic (SOSP'15; atomic sector writes **assumed**): https://people.csail.mit.edu/nickolai/papers/chen-fscq.pdf
- Flashix (MTD = the hardware contract, written down): https://www.uni-augsburg.de/en/fakultaet/fai/isse/projects/flashix/
- Ferrite (ASPLOS'16; validates software vs an **assumed** disk model): https://homes.cs.washington.edu/~mernst/pubs/crash-consistency-asplos2016.pdf
- Tseng et al., DAC'11 power-cut rig (**MLC/NAND-scoped** — do not over-transfer): https://cseweb.ucsd.edu/~swanson/papers/DAC2011PowerCut.pdf
- Ariadne mechanized in F* (crash-nondeterministic `incr` + ghost recovery FSM): https://arxiv.org/pdf/1707.02466
- OpenTitan lc_ctrl (A/B ECC-preserving incremental OTP — **needs the tapeout**): https://opentitan.org/book/hw/ip/lc_ctrl/doc/theory_of_operation.html
- OpenTitan FPV / sec_cm framework: https://opentitan.org/book/doc/contributing/dv/sec_cm_dv_framework.html
- ST community thread, U5 OTP half-QW (**tool bug, fixed in CubeProgrammer 2.19.0; no root cause**): https://community.st.com/t5/stm32-mcus-products/stm32u5-otp-programming-issue/td-p/682384

**Secure elements (surface e)**
- Sabt & Traoré, SCP03 proof / SCP02 theoretical attack: https://eprint.iacr.org/2017/032
- Avoine & Ferreira, SCP02 padding oracle (the **practical** break): https://tches.iacr.org/index.php/TCHES/article/view/7391
- EUCLEAK (14 years, ~80 CC evaluations): https://ninjalab.io/wp-content/uploads/2024/09/20240903_eucleak.pdf
- BSI-DSZ-CC-0961-V4-2019 (OPTIGA IC platform; **expired 2024-12-17**): https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/0961V4a_pdf.pdf
- NSCIB-CC-180212-CR5 (SE050/JCOP 4 P71; "strength … not rated"): http://www.commoncriteriaportal.org/files/epfiles/NSCIB-CC-180212-CR5-1.0.pdf
- JIL/SOG-IS ADV_SPM.1 interpretation (minimum formal-model scope): https://scsc.uk/r141C:1 *(and the SOG-IS note itself; superseded by ENISA/ECCG EUCC SotA v1.1, Oct 2025)*
- JIL composite product evaluation (**v1.6, 2024** supersedes v1.5.1): https://www.sogis.eu/documents/cc/domains/sc/JIL-Composite-product-evaluation-for-Smartcards-and-similar-devices-v1-5-1.pdf
- Djoudi/Hána/Kosmatov, JCVM in Frama-C (**Thales**, not NXP; ~3 person-years, 52k VCs, EAL6+): https://nikolai-kosmatov.eu/publications/djoudi_hk_fm_2021.pdf
- Infineon I2C Protocol v2.03 (**public, wire-complete**): https://raw.githubusercontent.com/Infineon/optiga-trust-m-overview/main/docs/pdf/Infineon_I2C_Protocol_v2.03.pdf
- OPTIGA Shielded Connection wiki (**no proof, no threat model**): https://github.com/Infineon/optiga-trust-m/wiki/Shielded-Connection-101
- Ledger Donjon, Trezor Safe 3 (**MCU glitched; OPTIGA untouched; attestation intact**): https://www.ledger.com/blog/ledger-donjons-trezor-safe-3-evaluation

**STM32 certification + FI (surfaces c, f) — the new bucket**
- TrustCB SESIP certificates index: https://www.trustcb.com/iot/sesip/sesip-certificates/
- **SESIP-2400133-01** (STM32U5 silicon; SESIP3 + Physical Attacker Resistance; 2025-05-22 → 2027-03-28): https://trustcb.com/download/?wpdmdl=5180
- **TN1545 Rev 3** — STM32U5x/WBA5x SESIP Security Target (**"does not include any firmware component"**; REV_ID `0x3003` = rev U; OEM2KEY field-return): https://trustcb.com/download/?wpdmdl=5181
- **UM3387 Rev 3** — SESIP L3 security guidance (**RDP-2 certified config; TRNG "configuration A"; TAMP conditions DHUK; OEM2 default password `0xFACEB00C 0xDEADBABE`**): https://www.st.com.cn/resource/en/user_manual/um3387-stm32u5xstm32wba5x-security-guidance-for-sesip-level-3-certification-stmicroelectronics.pdf
- SESIP-2300021-01 (the **other** cert — TOE = STM32U585 **TFM** 1.3.0): https://trustcb.com/download/?wpdmdl=3158
- PSA Certified listing, STM32U585 TFM: https://products.psacertified.org/products/stm32u585-tfm
- PSA Level 3 methodology (35-day white-box evaluation): https://www.psacertified.org/getting-certified/silicon-vendor/overview/level-3/
- NIST SP 800-90B ESV certificates (**none names the U585**; E11 = "STM32U5x TRNG"): https://csrc.nist.gov/projects/cryptographic-module-validation-program/entropy-validations/certificate/11
- NIST EA suite v1.1.8: https://github.com/usnistgov/SP800-90B_EntropyAssessment
- SySS, STM32L051 RDP glitch (**Cortex-M0+**, 2025-06): https://blog.syss.com/posts/glitching-the-stm32l051/
- µ-Glitch, USENIX Sec'23 (**TrustZone-M disabled on the STM32L5 — a Cortex-M33**): https://www.usenix.org/system/files/usenixsecurity23-sass.pdf
- Šimoník, MU thesis 2025 (**76% voltage-glitch PIN bypass on the STM32U5A9**): https://is.muni.cz/th/nysvv/thesis.pdf
- cargo-checkct (BINSEC/RelSE; **dormant**, last commit 2025-05-07): https://github.com/Ledger-Donjon/cargo-checkct
- BINSEC: https://binsec.github.io/ · Binsec/Rel (bounded verification): https://arxiv.org/pdf/1912.08788
- BINSEC-ASE / Adversarial Reachability (ESOP'23; **x86-32 eval; instruction skips out of reach**): https://binsec.github.io/assets/publications/papers/2023-esop.pdf
- SAMVA (COSADE'23; ARMv7-M; **heuristic, no proof; tool not public**): https://hal.science/hal-03980128
- ARMORY (**ARMv6-M/ARMv7-M only**; unmaintained since 2021): https://github.com/emsec/arm-fault-simulator
- FiSim (**hardcodes `UC_MODE_ARM`**; abandoned 2020): https://github.com/Keysight/FiSim
- ARCHIE (QEMU-based; **Cortex-M0/RISC-V validated**): https://github.com/Fraunhofer-AISEC/archie

**Rust / embedded FV (methodology)**
- Kani docs: https://model-checking.github.io/kani/rust-feature-support.html · paper (ASE'26): https://arxiv.org/html/2607.01504v1
- Kani on AWS Firecracker (**the stub/abstraction precedent**; 7 mo, 27 harnesses): https://model-checking.github.io/kani-verifier-blog/2023/08/31/using-kani-to-validate-security-boundaries-in-aws-firecracker.html
- Flux: https://github.com/flux-rs/flux
- TickTock (SOSP'25; **5 unknown bugs in MPU-config code**; 60 trusted spec lines): https://css.csail.mit.edu/6.5660/2026/readings/ticktock.pdf
- Verus (raw_ptr provenance; **no volatile/MMIO**): https://github.com/verus-lang/verus
- RefinedRust (PLDI'24; foundational — but **no traits, no concurrency, no ptr-int casts**): https://iris-project.org/pdfs/2024-pldi-refinedrust.pdf
- Surveying the Rust Verification Landscape (**a workshop research proposal**; omits Flux and Miri): https://arxiv.org/html/2410.01981v1
- embedded-hal-mock: https://github.com/rust-embedded/embedded-hal-mock
- RTIC book (**SRP claimed correct-by-construction; not mechanized**): https://rtic.rs/2/book/en/
- Ferrocene (**tool qualification ≠ proof**; thumbv8m is *supported, not qualified*): https://ferrous-systems.com/blog/officially-qualified-ferrocene/ · targets: https://public-docs.ferrocene.dev/main/user-manual/targets/index.html

**Methodology / assurance-case**
- seL4, "What the Proofs Assume": https://sel4.systems/Verification/assumptions.html
- OpenTitan countermeasure taxonomy (**bidirectional RTL↔Hjson cross-check**): https://raw.githubusercontent.com/lowRISC/opentitan/master/util/reggen/countermeasure.py
- TF-M generic threat model (**"Transferred"** marker): https://trustedfirmware-m.readthedocs.io/en/latest/security/threat_models/generic_threat_model.html
- Monniaux & Boulmé, CompCert's TCB (**bugs live in the unverified last mile**): https://arxiv.org/pdf/2201.10280
- RemembERR (**Intel/AMD only; >40% need two triggers**): https://comsec.ethz.ch/wp-content/files/rememberr_micro22.pdf
- GSN Community Standard v3 (SCSC-141C): https://scsc.uk/r141C:1
- Kobeissi, "Verification Theatre" (**cite the June 2025 revision**): https://eprint.iacr.org/2026/192 · companion, "Verification Facade": https://eprint.iacr.org/2026/670
- EverCrypt (**hardware contract = 3,269 LOC of Vale specs; RNG scoped OUT**): https://project-everest.github.io/assets/evercrypt.pdf
- herdtools7 / diy7 / litmus7 (**the model-validation-by-falsification method**; A-profile, multiprocessor): https://diy.inria.fr/doc/index.html
