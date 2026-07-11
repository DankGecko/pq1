# PQ1 Hardware Wallet — Hardened Secure-Configuration & Provisioning Reference (STM32U585 + OPTIGA Trust M V3 + NXP SE050)

> **QUARANTINE OVERRIDE (2026-07-11).** This is research input, not an
> executable ceremony. The repository's legacy factory receipt is invalid for
> STM32U585 write-once OTP QWs; all factory build/flash targets and RDP2
> authority are blocked. Hardware encoding facts below do not make the ordering
> or receipt safe. Do not run any OTP, option-byte, lifecycle, or RDP command
> from this document until a replacement ceremony is independently approved.

> **Provenance & repo notes (2026-05-29).** Output of a deep-research run against
> `docs/archive/provisioning-research-brief.md`. It is a research *synthesis*, not
> vendor-authoritative: treat specific constants (OPTIGA TLV codes, the "~600k
> monotonic-counter updates" cap, the PSA cert number) as **TO-VERIFY against the
> primary vendor doc + a sacrificial read-back**, per its own Phase 0/4 gates.
> The encodings `RDP=0xCC` and SE050 `P1=0x33` were cross-checked; using them in
> this project's ceremony is **not** currently authorized or declared safe.
>
> **Two findings reconciled against our own code/silicon — act on these:**
> 1. **S-2 trust anchor is mis-targeted and our current mitigation is a silent
>    no-op.** Our `secure/src/optiga/reset.rs` provisions a "trust anchor" at
>    `0xE0E3`, but our 2026-04-22 bench dump (memory `project_optiga_reset_oids`)
>    shows E0E3 is `e8 01 12` = `DataType 0x12` (device cert), already full — the
>    chip won't retype it. The real Protected-Update anchors are the type-0x11
>    slots (this doc: `E0E8/E0E9/E0EF`), which our code never touches. Resolution
>    + bench dump queued in `docs/production-todo.md` S-2.
> 2. **S-1 F1D0:** our code *actively writes* `Change=ALW` (`apdu.rs:934`) — worse
>    than the chip default this doc assumed. Fix is a change to our provisioning
>    code, not "stop leaving a default."

**Note on completeness:** The full per-chip configuration matrices, the consolidated dependency-ordered provisioning ceremony, and the residual-immutability-gap analysis were assembled section-by-section during research and are summarized below in their entirety, followed by the per-chip misconfiguration-pitfalls lists, the secondary self-protection measures, the sources list, and caveats.

---

## TL;DR
- **STM32U585:** Burn `RDP=0xCC` (Level 2), `WRP1A UNLOCK=0` over the ~18 KB FSBL pages, `HDP1EN=1` + `HDP1_ACCDIS` at boot-exit, `BOOT_LOCK=1` with `SECBOOTADD0` inside the secure/WRP/HDP region, `TZEN=1`, and provisioned/finalized OEM1/OEM2 debug-authentication keys so JTAG/SWD is permanently closed in the field. WRP+RDP2+HDP+BOOT_LOCK gets a *flash* FSBL functionally ROM-equivalent against rewrite/readout; the only residual gap is a *successful* fault-injection RDP2→RDP1 downgrade (the wallet.fail/Kraken class), mitigated by the U5's glitch-aware silicon, FSBL self-checking its own option bytes every boot, and the fact that a flash read-out reveals neither the SPHINCS+ key (TrustZone SRAM only) nor the seed (XOR-split across two SEs).
- **OPTIGA Trust M V3 & SE050 (dual, independently hardened to the same bar):** OPTIGA — write a chip-unique 64-byte Platform Binding Secret to `0xE140`, ratchet every used secret/anchor/counter object to `LcsO=operational (0x07)`, set AuthRef `0xF1D0` to `Change=Conf(0xE140)&&Auto(0xF1D0)`/`Read=NEV`, enable monotonic counter `0xE120`, and neutralize the `0xE0E0` Infineon sample certificate + close all empty anchor slots. SE050 — **rotate the AN12436-published default Platform SCP03 keys** (the #1 ship-blocker), negotiate **full security level `P1=0x33` (C-MAC+C-DEC+R-MAC+R-ENC)**, set per-object policies to the minimum (no ALLOW_WRITE/DELETE except one provisioning-admin object), set UserID PIN `max_attempts`, bind UserID delete to the admin AuthID only, and disable unused AppletConfig features. OPTIGA PBS is rooted on STM32 **DHUK**; SE050 SCP03 on STM32 **BHK** — so a single-vendor break or single-key extraction yields only one XOR half, never the seed.
- **Future ceremony constraint, not an instruction:** any replacement must stage
  and verify reversible state first, then order one-way transitions last. Exact
  steps, receipt semantics, and authorization remain OPEN; this research does
  not define an executable RDP2 sequence.

> **Two corrections to the brief, established from Infineon's own published V3 object dump and Configuration Guide:** (1) On a *standard* OPTIGA Trust M V3, AuthRef slot **0xF1D0 ships with `Change=LcsO<operational`, `Read=ALW`, untyped** — *not* `Change=ALW`; it only becomes the typed AUTOREF secret (`Change=Conf(0xE140)&&Auto(0xF1D0)`, `Read=NEV`) in Express/MTR configs. S-1 is therefore "F1D0 left at default `Change=LcsO<op` and un-ratcheted" — at LcsO=creation a desoldered chip can still rewrite it; fix (ratchet to operational + `Change=Conf&&Auto`) is unchanged. (2) Only **0xE0E0** ships with an Infineon ECC P-256 *sample* end-device cert (issuer "Infineon OPTIGA(TM) Trust M CA 300") + chip-unique key in **0xE0F0**; slots **0xE0E1/E0E2/E0E3/E0E8/E0E9/E0EF** ship *empty* at `LcsO=creation, Change=LcsO<op`. S-2 is therefore "don't trust the 0xE0E0 sample cert as an anchor, and fill-and-lock or ratchet-closed the empty anchor slots so no attacker can install their own anchor."

---

## Key Findings

**1. The decisive lock set is small and each item is independently fatal if missed.** ST's SESIP/CC guidance UM3387 §3.2.3 defines the *certified* lockdown as exactly: `TZEN=1`, `SWAP_BANK=0`, `SECBOOTADD0` into the secure HDP/WRP area, `BOOT_LOCK=1`, `SECWM1` set, `HDP1EN=1` with `HDP1_PEND` covering the FSBL, `WRP1A` over the immutable area with `UNLOCK=0`, and `RDP=0xCC`. This is the most authoritative "correct config" checklist; PQ1 must replicate this exact primitive set by hand even though it does not use ST's image format. UM3387 also notes the fail behavior that doubles as a verification signal: misconfigured option bytes cause "Reset … except for the case of RDP option bytes value for which infinite loop is executed."

**2. The flash-FSBL-vs-ROM immutability gap is real but bounded.** STiRoT achieves true ROM immutability. PQ1's flash FSBL is immutable only via WRP1A (un-removable only while RDP=2 — AN5156: WRP "can be unset when RDP level ≠ 2") + RDP2 + HDP1 + BOOT_LOCK. Residual surface: a successful fault-injection RDP2→RDP1 downgrade (wallet.fail/Kraken on older STM32F2/F4). Mitigations: U5 is glitch-hardened (Ledger Donjon: "no fault injection attack has been made public" on U5); FSBL self-verifies option bytes every boot and halts on mismatch (AN5156 secure-boot FSM); and a full flash read-out yields no usable secret by design.

**3. The SE050's published default keys are the highest-probability self-inflicted hole.** AN12436: default Platform SCP03 keys are in NXP's own Table 6 and the OP-TEE source tree; "users are required to rotate/provision those keys." Un-rotated = anyone opens an authenticated channel to half_E.

**4. Object lifecycle, not encryption, is the OPTIGA control.** One-way LcsO: creation `0x01` → initialization `0x03` → operational `0x07` → termination `0x0F`; "Once LcsO is set to higher value, it is not reversible." At creation, an attacker with physical access "could change the Read access permission from NEV to ALW." Ratcheting every used object to `0x07` makes the config self-enforcing.

**5. Vendor diversity is validated by the audit literature.** Coinkite's Mk4 uses the same philosophy; when Ledger Donjon laser-fault-injected its DS28C36B "SE2," the secret held because it "requires full compromise [of] three chips." Trezor's historical no-SE stance (NDA/open-source conflict) was overtaken by Trezor itself adopting the *same* OPTIGA Trust M V3 (chosen for "no Non-Disclosure Agreements") — validating PQ1's auditable, NDA-free SE choice.

---

## Matrix 1 — STM32U585 MCU (custom FSBL root of trust, by-hand primitive lockdown)

Delivered in RDP0 with no NVM protection (UM3387 §4.1). Each row: **Setting → Hardened value → Rationale → Source → Verification before burn.**

| # | Setting | Hardened value | Rationale | Source | Verify before burn |
|---|---|---|---|---|---|
| M-1 | TZEN (FLASH_OPTR) | `TZEN=1` (0xB4) | Secure/non-secure split; FSBL, SPHINCS+ SRAM signing, SE host keys in secure world; DHUK differs Open vs closed | RM0456 §3; UM3387 §3.2.3 | Read FLASH_OPTR.TZEN=1; SAU/GTZC regions match map |
| M-2 | SECBOOTADD0 | `0x0C00_X000` inside WRP+HDP | Forces reset vector into FSBL | UM3387 §3.2.3 | Confirm address ∈ WRP1A range and HDP1 region |
| M-3 | BOOT_LOCK | `=1` | No alternate boot entry (RAM/sys bootloader) | UM3387 §3.2.3; AN5156 (UBE) | Read=1; attempt boot-source change → rejected |
| M-4 | SECWM1 | `PSTRT=0`, `PEND`=last secure page (>WRP1A_PEND) | Defines secure region enclosing FSBL+app | UM3387 §3.2.3; RM0456 §3.6 | Read FLASH_SECWM1R1 range |
| M-5 | HDP1EN/HDP1_PEND | `HDP1EN=1`; PEND covers FSBL; `<SECWM1_PEND` | Hides FSBL code+secrets after boot | RM0456 §3.6.1; UM3387; AN5156 | Read HDP1EN=1, PEND covers FSBL |
| M-6 | HDP1_ACCDIS | FSBL sets it in FLASH_SECHDPCR at boot-exit | Engages the hide for the session | UM3387 §4.2.1 | FSBL self-test reads back verification value ≠0 → halt |
| M-7 | WRP1A | FSBL pages; PEND=HDP1_PEND; **UNLOCK=0** | Makes flash FSBL immutable (with RDP2) | UM3387 §3.2.3; AN5156 §6 | Read FLASH_WRP1AR; erase an FSBL page → "write protected" |
| M-8 | RDP | `0xCC` (Level 2) | Kills JTAG/SWD, RAM/bootloader boot, locks option bytes **EXCEPT SWAP_BANK** (DS Table 4 note 6 — see SWAP_BANK ship-blocker in production-todo), no mass-erase-open; keeps WRP un-removable | UM3387 §4.2; RM0456 §3.10; DS Table 4 | **LAST** verification; sacrificial: JTAG dead + FSBL boots |
| M-9 | OEM2 DA key (OBKeys) | Provision secret; no default; prefer no field regression | RDP2+OEM2 disables debug; default password = hole | AN6008; STM32U5 Sec Overview | DA challenge with default password → rejected |
| M-10 | OEM1KEY / RDP0 regression | Absent (no path) or PQ1-secret one-way control | RDP1→0 mass-erases; close or gate; "reset in RDP0 only" | STM32U5 Sec Overview; AN4992 | Confirm state before raising RDP |
| M-11 | BHK (→ SE050 SCP03 root) | FSBL writes BHK into TAMP backup regs once at boot; `SAES_CR.KEYSEL=010` (BHK) / `100` (DHUK^BHK); **write-once, never SW-readable** — `TAMP_SECCFGR.BHKLOCK` makes it SAES-only until reset | Tier-isolation root for half_E; cleared on tamper / RDP-regression | RM0456 §SAES; ES0499; production-security.md:479 | Verify via a SAES-CMAC(BHK) known check-value (NOT a register read-back — BHK is unreadable); confirm BHKLOCK set |
| M-12 | DHUK (→ OPTIGA PBS root) | Per-die only after RDP0→1 (constant in Open) | Gates SE injection until DHUK is per-die | ST Community; RM0456 §SAES; Sensitive-key-protection wiki | Confirm DHUK-wrapped value changes pre/post transition |
| M-13 | OTP (rollback ctr + secrets) | Program + set OTP lock bits | OTP unaffected by mass erase; one-way; A/B rollback + page-124 PIN counter | RM0456 §OTP; Stm32World | Read OTP + lock bits; counter init; lock set |
| M-14 | TAMP + RNG | Internal tamper on; TRNG "config A"; tamper erases BHK | Protects BHK-wrapped SE050 transport; certified RNG | UM3387 §4.2.1; RM0456 §TAMP/RNG | Sacrificial tamper → BHK erase + reset; RNG health pass |
| M-15 | FI software countermeasures | Redundancy / inverse-check, timing jitter, control-flow integrity around SPHINCS+ verify + option-byte self-check | Software half of closing RDP2-downgrade residual gap | UM3387 §4.2.1 | Rainbow single-fault simulation of verify/lock path |

**Residual-gap statement:** With M-1…M-15 set, the flash FSBL reaches functional ROM-equivalence against rewrite/readout/debug/bypass. The irreducible delta vs. true ROM is that RDP2 is option-byte/state-machine logic, theoretically susceptible to a *successful* FI RDP2→RDP1 downgrade. Mitigated by: (a) FSBL self-verifies option bytes every boot; (b) U5 glitch-hardening (no public U5 FI attack); (c) a full flash read-out reveals neither the SPHINCS+ key nor the seed. The gap is non-fatal by design.

---

## Matrix 2 — Infineon OPTIGA Trust M V3 (half_O; rooted on STM32 DHUK)

Tags: RD/CHA/EXE/MUPD. Codes: `ALW=0x00`, `NEV=0xFF`, `LcsO(X)` (`E1 FC 07`="LcsO<operational"), `Conf(X)` (shielded), `Auto(X)` (auth-ref). LcsO ratchet TLV = `C0 01 07` (framed `20 03 C0 01 07`).

| # | OID | Hardened value | Rationale | Source | Verify before LcsO burn |
|---|---|---|---|---|---|
| O-1 | 0xE140 PBS | Chip-unique 64-byte (TRNG, DHUK-rooted); `Read=NEV`, `Change=Conf(0xE140)`, type 0x22; ratchet op | Roots shielded conn (AES-128-CCM8) protecting half_O; default PBS non-unique | SRM Shielded Conn §; Shielded-Connection-101 wiki; KBA235350 | `Read=NEV`,`LcsO=0x07`; shielded works w/ unique PBS, fails w/ default |
| O-2 | 0xF1D0 AuthRef | Chip-unique; `Change=Conf(0xE140)&&Auto(0xF1D0)`, `Read=NEV`, AUTOREF; ratchet op | Default `Change=LcsO<op`,`Read=ALW`,untyped → creation-state rewritable (S-1) | V3 object dump; OPTIGA Config Guide | `trustm_metadata -r 0xF1D0`: `LcsO:0x07,R:NEV,C:Conf&&Auto`; unauthorized change → `0x8007` |
| O-3 | 0xE0E0/0xE0F0 | On PRODUCTION parts `0xE0E0` is a **chip-unique Infineon device cert** (`Change=NEV`, leaf key sealed at `0xE0F0 Read=NEV`) — do NOT neutralize; it's an anti-counterfeit primitive. Just don't anchor *wallet* trust on it (wrong type: device-identity 0x12, not TA) | NOT "a public sample anyone can reproduce" — that's the engineering-sample *Test* cert; our eval shield (TRUSTMV3SHIELDTOBO1) may carry the test cert | Keys&Certificates v3.10; SRM Table 68 | Confirm whether our part carries the production chip-unique cert vs the eval test cert; never anchor wallet trust on E0E0 |
| O-4 | 0xE0E1/E0E2/E0E3 | Fill PQ1 anchor + ratchet, or ratchet op to make `Change=LcsO<op` unsatisfiable | Empty at creation → attacker installs own anchor, signs SetObjectProtected manifest (S-2) | V3 object dump; SRM Protected Update | `LcsO:0x07`; metadata change refused |
| O-5 | 0xE0E8/E0E9/E0EF (type 0x11) | Fill-and-lock if used (PQ1 Protected-Update anchor) else ratchet op | Type-0x11 anchors authorize manifests; attacker anchor = worst case | V3 object dump; SRM | PQ1 anchor + `LcsO:0x07` or empty+ratcheted |
| O-6 | 0xF1D1–F1DB, F1E0, F1E1 | Ratchet every unused slot to op | Creation-state slots are writable footholds | V3 object dump; SRM | All unused slots `LcsO:0x07` |
| O-7 | 0xE120 counter | Init counter+threshold (8-byte ctr‖thr); link as PIN/usage limiter; ratchet op | Silicon leg of three-way lockstep; mandatory (S-3) | KBA235409; SRM; linux-optiga-trust-m | `trustm_monotonic_counter -r 0xE120`; sacrificial: reaches threshold→error |
| O-8 | 0xE200 AES | If used: write key, `Change=NEV`, Execute gated by `Conf(0xE140)`, ratchet op; else leave uninstantiated | Not present by default; CHA=ALW only *during* keygen, re-close after | V3 object dump; linux-optiga-trust-m note | If used: `LcsO:0x07` + shielded-gated; else absent |
| O-9 | Shielded enforcement | All half_O objects: `Read/Execute=Conf(0xE140)` | I²C probe sees only ciphertext | SRM §Comm Protection; discussion #103 | Sacrificial: bypass shielded (`-X`) → Access Condition Not Satisfied |
| O-10 | Protected Update policy | Restrict to PQ1 anchor; manifest `Conf(secret)&&Int(anchor)` | Without locked anchor, anyone signs a manifest (S-2 core) | SRM §Protected Update; Infineon blog | Non-PQ1 manifest → rejected |
| O-11 | Security Monitor | Hardened default; do not disable | Throttles after security events (lockout silicon) | OPTIGA datasheet §Security monitor | Active; sacrificial repeated failed auth → back-off |
| O-12 | Inherit CC/PSA config | Chip-unique keys, locked secrets, shielded conn, no creation-state secrets in field | EAL6+ (high), **BSI-DSZ-CC-0961 / IFX_CCI_00000Bh** (datasheet-confirmed); **PSA Certified L3** (datasheet-confirmed). ⚠️ the cert **number/HW-ver/date** (0632793519409-10300 / V3.00.2440 / 27-07-2024) are NOT in the Infineon docs — TO-VERIFY against products.psacertified.org before citing as fact | OPTIGA datasheet v3.70 | Confirm genuine V3 (UID/cert chain); no object at LcsO=creation |

---

## Matrix 3 — NXP SE050 (half_E; rooted on STM32 BHK)

**Dev-board variant: EdgeLock SE050E2, OEF ID `0xA921`** (the OM-SE050ARD-E carries SE050E; NXP docs map SE050E2 → OEF 0xA921). Implications baked into the rows below: **CC EAL6+ to OS level (yes), FIPS 140-2 (NO — that's SE050F only), platform SCP03 forced by default (NO — SE050E defaults `SCP_NOT_REQUIRED`; we rely on per-object `REQUIRE_SM`).** ⚠️ **The PRODUCTION part is not yet selected** — the custom board is in early ID (2026-05); working assumption is the same SE050E2/`0xA921` as the dev board. The `GetVersion`/OEF boot assertion (work-todo) ENFORCES this (fail-closed on mismatch). **The one variant that would move this matrix is SE050F** (would add FIPS + force SCP03); any other SE050E-class OEF only changes the expected OEF value, not the security properties. Pin the variant requirement into the hardware spec during ID so it's locked, not discovered at bring-up.

Policies = per-object `POLICY_OBJ_ALLOW_*` bitmask; rule: deny all not needed; never leave WRITE/DELETE except one admin object. SCP03 level via EXTERNAL AUTHENTICATE `P1`. HW = CC EAL6+ (to OS level); FIPS 140-2 (SL3 OS/Applet, SL4 physical) is **SE050F-only**, NOT our SE050E.

| # | Setting | Hardened value | Rationale | Source | Verify before SCP03-rotation burn |
|---|---|---|---|---|---|
| S-A | Platform SCP03 keys | **Rotate** AN12436 defaults to chip-unique BHK-derived (PUT KEY in ISD) | Defaults published (AN12436 Table 6 + OP-TEE source); #1 ship-blocker | AN12436; foundries.io/u-boot | INIT UPDATE w/ defaults → fail; w/ new keys → success (**the gate**) |
| S-B | SCP03 level (P1) | **`P1=0x33`** (C-MAC+C-DEC+R-MAC+R-ENC) (S-5) | Anything less leaves bus data exposed one/both directions | GlobalPlatform SCP03 Table 7-3; AN12413 | Sniff I²C: cmd+rsp ciphertext+MAC; refuse downgrade |
| S-C | half_E object | Persistent Binary File, REQUIRE_SM, bound to the UserID AuthID (no anonymous/AuthID-0 grant). **READ + DELETE are present (SM-gated) and design-mandatory** (READ = seed reconstruction `mod.rs:2478`; DELETE = admin-wipe/S-6). **WRITE is present today but droppable** — drop it at provisioning (write-once policy; work-todo) so a PIN-session can't re-seed half_E. IMPORT_EXPORT N/A to a Binary File | Verifiable denials are IMPORT_EXPORT=False, ATTESTATION=False, no AuthID-0 grant — NOT R/D (those can never be False by design) | AN12413 Table 11, §3.7.1.1 | non-admin delete → `0x6985`; attested-read (S-G) confirms I-E/ATTESTATION=False (NOT R/D=False) |
| S-D | UserID delete policy (S-6) | Delete bound to admin SCP03 AuthID only | UserID "only be deleted and created new" → delete-recreate resets lockout | NXP Community | Non-admin delete of UserID → fail |
| S-E | UserID max_attempts (S-7) | =10; permanent fail on exhaustion; status mapped to MCU strictest-of-three | SE050 leg of three-way lockstep; mis-mapped status = false success | AN12413; AN13483 | Sacrificial: exhaust → permanent lockout; verify status map |
| S-F | RESERVED_ID_FACTORY_RESET | PQ1-secret or unprovisioned; never default | `DeleteAll` only in this session; default/known = wipe+reprovision/clone path | AN12543; NXP Community | DeleteAll in default/none session → fail |
| S-G | Attestation (ECKey) | If used: `ALLOW_ATTESTATION`, **`ALLOW_SIGN=0`, `ALLOW_DECRYPT=0`**. NOT implemented in the driver today — either build it as provisioning/QA tooling or down-scope | Signed read-back proof primitive; asserts the *verifiable* denials only | AN13254 Table 1 | Attested read confirms half_E I-E/ATTESTATION=False, no AuthID-0 (lockstep with S-C — NOT R/D=False) |
| S-H | AppletConfig (variant) | **Not field-configurable** — `SetAppletFeatures` needs the NXP-owned `RESERVED_ID_FEATURE`; the feature set is fixed by the **ordered OEF variant**. This is a PROCUREMENT lever (choose variant at order time), not a provisioning step. Per invariant #5 the SE050 crypto engine is unused anyway | AppletConfig is NXP-owned | AN12436 §4.6.3, §3.2.5.4 | `GetVersion`/OEF — confirm the variant we ORDERED (anti-substitution), not "minimized" |
| S-I | Provisioning-admin object | Exactly one AuthID holds WRITE/DELETE, ceremony-only, on rotated SCP03 admin session | Concentrates all mutation rights in one auditable credential | AN12413 §3.7 | One object writable (admin AuthID); all others read/use-only |
| S-J | Persistent/lifecycle | half_E + PIN object persistent (NVM), not transient | Persistent objects survive reset, cannot be exported | AN13483; SE050 datasheet | Confirm half_E + PIN persistent |
| S-K | Inherit CC (all variants); FIPS is SE050F-only | SCP03 rotated; minimal policies; factory-reset NXP-reserved (unavailable to us) | **CC EAL6+ to OS level — all variants** ✓. ⚠️ **FIPS 140-2 SL3/SL4 is SE050F-ONLY** — an SE050E-class part is NOT FIPS (don't claim it unless we BOM SE050F). ⚠️ **"0x7FFF0207 forces SCP03" is SE050F-ONLY** — an SE050E-class part defaults `SCP_NOT_REQUIRED`; our half_E/PIN confidentiality rests on **per-object `REQUIRE_SM`** (`apdu.rs:568`), NOT forced platform SCP (decide: also `SetPlatformSCPRequest` for defense-in-depth?) | SE050 datasheet; AN12436 §2.1 | `GetVersion`/OEF assert the variant (work-todo); confirm basis = REQUIRE_SM not forced-SCP |

---

## Consolidated Provisioning Ceremony (stage → verify → burn-last, dependency-ordered)

The chips are coupled: SE roots derive from DHUK/BHK, which become per-die/final only at the MCU `RDP0→1` transition (SAES uses a *constant* for DHUK in Open). **SE secret injection is gated on the MCU lifecycle step.** All locks are one-way.

**PHASE 0 — Sacrificial validation.** Run the *complete* ceremony (incl. final burns) on ≥3 sacrificial units. Confirm FSBL boots, SPHINCS+ verify passes, PIN lockstep locks at 10, seed reconstructs from both halves, JTAG dead, no object at LcsO=creation. Only then run production.

**PHASE 1 — Stage (reversible).** 1.1 Acceptance: `DBGMCU_IDCODE` (`DEV_ID=0x482`, STM32U585 rev. U), virgin flash (0xFF), genuine OPTIGA V3 (UID + chain to "Infineon OPTIGA ECC Root CA 2"), SE050 variant via `se05x_GetInfo`. 1.2 Program FSBL + A/B firmware; stage TZEN/SECWM/HDP/WRP/BOOT_LOCK values uncommitted. 1.3 Stage OTP counter (hold lock bits), prepare OEM1/OEM2 DA keys. ⚠️ All reversible (RDP0; mass-erase recovers).

**PHASE 2 — MCU lifecycle transition (FIRST irreversible dependency).** 2.1 **🔥 IRREVERSIBLE-1:** `RDP0→1` / set the config that makes DHUK per-die and BHK provisionable. (RDP1→0 regression still possible here, so still recoverable at cost of full re-stage.) 2.2 FSBL provisions BHK into TAMP backup regs (write-once); confirm KEYSEL + set `TAMP_SECCFGR.BHKLOCK` (BHK then SAES-only, never SW-readable; verify via a SAES-CMAC check-value, not a read-back).

**PHASE 3 — SE injection (gated on Phase 2; reversible until ratchet/rotate).** 3.1 OPTIGA: derive PBS from DHUK, write chip-unique 64-byte to `0xE140` (still `LcsO<op`), write half_O, init `0xE120`, prepare F1D0. 3.2 SE050: open ISD with default SCP03; *stage* new BHK-derived keys, half_E, UserID/PIN object + policies.

**PHASE 4 — FULL VERIFICATION GATE (no burns; go/no-go).** 4.1 MCU: read back all set Matrix-1 rows; FSBL option-byte self-check + HDP1_ACCDIS engage. 4.2 OPTIGA: read back all Matrix-2 rows; shielded works w/ unique PBS, fails w/ default; **nothing ratcheted yet** (recoverable). 4.3 SE050: new SCP03 authenticates, defaults fail; `P1=0x33`; half_E bitmask; UserID delete admin-bound; factory-reset credential state; attested read (S-G) as proof. 4.4 Functional: XOR-reconstruct seed in TrustZone SRAM, derive SPHINCS+ key, sign+verify test vector; drive 10-attempt lockstep, confirm strictest-of-three. **Any failure → unit still recoverable; fix and re-verify; do not proceed.**

**PHASE 5 — Irreversible burns, LAST, dependency-ordered (SE-first, MCU-RDP2-last so no failure bricks).** 5.1 **🔥 IRREVERSIBLE-2 (SE050):** PUT KEY rotate SCP03 (defaults gone); finalize half_E/PIN policies. 5.2 **🔥 IRREVERSIBLE-3 (OPTIGA):** ratchet `LcsO=operational` on E140, F1D0, E120, all used/empty cert+anchor slots (E0E1/2/3, E0E8/9/EF), all spare F1Dx/F1Ex. 5.3 **🔥 IRREVERSIBLE-4 (MCU OTP):** set OTP lock bits. 5.4 **🔥 IRREVERSIBLE-5 (MCU WRP):** commit `WRP1A + WRP2A UNLOCK=0` over FSBL pages 0..3 in BOTH banks (removable only while RDP≠2 → must precede RDP2; see SWAP_BANK ship-blocker). 5.5 **🔥 IRREVERSIBLE-6 (MCU DA/OEM):** finalize OEM1/OEM2 keys + regression policy (resettable in RDP0 only). 5.6 **🔥 IRREVERSIBLE-7 (MCU RDP2 — FINAL BURN):** `RDP=0xCC`; JTAG dies, option bytes lock (EXCEPT SWAP_BANK — must be neutralized by WRP-both-banks + identical-FSBL-both-banks, see ship-blocker), WRP unremovable.

**PHASE 6 — Post-burn confirmation (every unit).** Confirm `RDP=0xCC`, JTAG dead, device boots/signs/enforces PIN, default SE050 SCP03 + default OPTIGA PBS both fail. Shippable-state attestation.

---

## Known Misconfiguration Pitfalls (per chip, from the audit literature → preventing setting)

**STM32U585**
- **MCU-1 RDP2→RDP1 fault-injection downgrade** (wallet.fail 35C3; Kraken Security Labs on STM32F2/F4 — "downgrading RDP2 to RDP1 can reliably be performed at boot with voltage glitching"). → Prevent: M-8 RDP2 + M-15 FI countermeasures + M-6 FSBL option-byte self-check; residual accepted because seed is split (Finding 2).
- **MCU-2 RDP not actually at Level 2 / left at Level 1** (Kraken: RDP1 allows SRAM read-out over SWD). → M-8 `RDP=0xCC`; verified last.
- **MCU-3 WRP left unlocked / FSBL rewritable** (left-open lock bit). → M-7 `WRP1A UNLOCK=0`; erase-attempt test.
- **MCU-4 Default OEM2/DA password left in place** (un-rotated default key). → M-9 provision secret OEM2; default-password challenge must fail.
- **MCU-5 BOOT_LOCK off / alternate boot entry** → M-3 `BOOT_LOCK=1`.
- **MCU-6 HDP not engaged at runtime** (HDP1_ACCDIS unset) → M-6 self-test.
- **MCU-7 Seed/keys in flash recoverable** (Kraken extracted encrypted seed from STM32 flash). → Architectural: SPHINCS+ key in TrustZone SRAM only; seed XOR-split.
- **MCU-8 SWAP_BANK cross-bank boot redirect** (DS Table 4 note 6: SWAP_BANK stays writable at RDP2; BOOT_LOCK pins a *logical* address that SWAP_BANK remaps to the other physical bank; our bank-2 boot pages are NS-writable today). → WRP1A **and WRP2A** over FSBL pages 0..3 in **both** banks + identical FSBL staged in both banks + HDP2/SECWM2 mirror; `SWAP_BANK=0` necessary-not-sufficient. **SHIP-BLOCKER** — full treatment in production-todo.md "STM32U585 — datasheet cross-reference".

**OPTIGA Trust M V3**
- **S-1 F1D0 left un-ratcheted at `Change=LcsO<op`** — desoldered-chip attacker overwrites the AuthRef secret. → O-2 ratchet `LcsO=operational` + `Change=Conf(0xE140)&&Auto(0xF1D0)`.
- **S-2 Public-sample trust anchor usable / empty anchor slots open** — anyone signs a SetObjectProtected manifest. → O-3/O-4/O-5/O-10 neutralize 0xE0E0 sample cert; fill-and-lock or ratchet-close E0E1/2/3, E0E8/9/EF; restrict Protected Update to PQ1 anchor.
- **S-3 Monotonic counter not enabled in production** — no silicon usage/attempt cap. → O-7 `0xE120` linked to F1D0, ratcheted.
- **S-4 (added) Default/non-unique Platform Binding Secret left in 0xE140** — bus traffic decryptable; also any object left at LcsO=creation is rewritable by a physical attacker ("could change Read from NEV to ALW"). → O-1 unique PBS + O-6/O-12 ratchet every used/spare object to operational.
- **S-4b (added) Shielded connection not enforced on sensitive objects** — I²C probe reads plaintext. → O-9 `Read/Execute=Conf(0xE140)`.

**SE050**
- **S-5 SCP03 not at full security level** — bus data exposed. → S-B `P1=0x33`.
- **S-6 UserID admin-delete allows delete→recreate substitution** — bypasses lockout. → S-D bind delete to admin AuthID.
- **S-7 UserID max_attempts / status-code mishandling** — lockout not enforced or status misread as success. → S-E set =10, map to MCU strictest-of-three.
- **S-8 (added) Published default Platform SCP03 keys not rotated** (AN12436; OP-TEE source) — anyone authenticates to half_E. → S-A rotate via PUT KEY.
- **S-9 (added) Over-permissive object policy / writable-deletable secrets** — half_E rewritable/exportable. → S-C/S-I deny all but one admin object.
- **S-10 (added) Factory-reset credential default/unset** — wipe+reprovision/clone path. → S-F PQ1-secret or unprovisioned.
- **S-11 (added) Unused applet features left enabled** — surface bloat. → S-H AppletConfig minimization.

---

## Recommendations

**Stage 1 — Before any silicon (now):** Lock the exact option-byte/OID/policy *values* into a machine-checked provisioning script keyed to UM3387 §3.2.3 (MCU), the OPTIGA SRM metadata model (OPTIGA), and AN12436/AN12413 (SE050). Build the read-back verifier (Phase 4/6) first — it is the safety net.

**Stage 2 — Sacrificial validation (Phase 0):** Burn ≥3 sacrificial units fully to RDP2; confirm end-to-end (boot, sign, PIN lockstep, seed reconstruct, JTAG dead). **Benchmark that changes the plan:** if any sacrificial unit bricks or any default key/PBS still authenticates after burn, halt and fix the script before production.

**Stage 3 — Production with gate (Phases 1–6):** Run stage→verify→burn-last per unit. **Threshold:** zero objects at LcsO=creation, zero default keys authenticating, RDP=0xCC, JTAG dead — all four must be true on the Phase-6 read-back or the unit is quarantined, not shipped.

**Stage 4 — Ongoing:** Track Infineon/NXP/ST security advisories; re-run the verifier if any chip's certified config assumptions change. Subscribe to BSI/PSA maintenance updates for BSI-DSZ-CC-0961 and PSA cert 0632793519409-10300.

**Secondary — post-supervision self-protection (minimum bar so the partner cannot extract roots, clone, or weaken a locked unit):** (1) The DHUK/BHK roots are per-die and never leave the MCU — the partner's tool never holds a usable root; PBS/SCP03 keys are *derived on-die*, not injected from a master. (2) The provisioning-admin SCP03 AuthID and OPTIGA Protected-Update anchor are held in PQ1's HSM, not on the partner's tool; the partner can run the ceremony but cannot mint new units that PQ1's trust path will accept. (3) After RDP2 + LcsO=operational + SCP03 rotation, the unit is self-enforcing: no debug, no creation-state objects, no default keys — a correctly-locked unit cannot be weakened even with the tool. (4) For anti-overbuild, gate the ceremony on per-unit authorization tokens from PQ1's HSM (license metering) and log each unit's UID + post-burn attestation. Tool-tamper defense is secondary because the locked unit's security does not depend on the tool's integrity after Phase 6.

---

## Sources / Citations
- **ST:** AN5156 (Introduction to STM32 microcontrollers security) — RDP/WRP/HDP/PCROP, secure-boot FSM, "WRP can be unset when RDP level ≠ 2." RM0456 (STM32U575/585 reference manual) — §3 security, §3.6 HDP, §3.10 RDP, SAES, OTP, TAMP. UM3387 (STM32U5x-WBA5x SESIP Level 3 security guidance) — §3.1 acceptance, §3.2.3 lockdown values, §4.2 RDP2/HDP/FI countermeasures. AN6008 (Debug Authentication for STM32). AN4992 (Secure Firmware Install / OEM password notes). STM32U5 Security Overview (SECOVW); STM32H5 DA training (DHUK/Open-state note); ES0499 errata (SAES KEYSEL); ST Community (BHK/RHUK/DHUK provisioning); Sensitive-key-protection wiki.
- **Infineon:** OPTIGA Trust M Solution Reference Manual (access conditions, LcsO model, Shielded Connection, Protected Update, monotonic counters); OPTIGA Trust M Datasheet v3.70 (CC EAL6+ high, **BSI-DSZ-CC-0961 / IFX_CCI_00000Bh**, PSA L3, Security Monitor); OPTIGA Trust M Configurations Guide (V1/V3/Express/MTR object defaults); Infineon V3 object dump (trust_m3_json.txt); KBA235350 (Shielded Connection), KBA235409 (Monotonic Counters); Protected Update / Metadata developer blogs; linux-optiga-trust-m tooling (LcsO one-way warning, trustm_metadata/monotonic_counter).
- **NXP:** AN12436 (SE050 configurations — default Platform SCP03 keys MUST be updated; SE050F FIPS, reserved key 0x7FFF0207). AN12413 (SE05x APDU spec — policies §3.7, SCP03, UserID). AN12543 (factory reset / RESERVED_ID_FACTORY_RESET). AN13483 (SE050E user guidelines — persistent/transient, policies). AN13254 (secure attestation — SIGN=0/DECRYPT=0). SE050 datasheet (CC EAL6+ to OS level). NXP Community (UserID delete-recreate; POLICY_OBJ_ALLOW_DELETE). GlobalPlatform SCP03 spec (P1 Table 7-3). foundries.io / u-boot (default-key rotation, BHK-derived SCP03).
- **CC / certification:** commoncriteriaportal.org & bsi.bund.de (BSI-DSZ-CC reports; OPTIGA underlying controller); products.psacertified.org (OPTIGA Trust M v3 PSA L3 cert 0632793519409-10300, HW V3.00.2440, 27/07/2024, SGS Brightsight).
- **Audits / research:** wallet.fail (35C3, media.ccc.de) — glitching to bypass IC security. Kraken Security Labs (Trezor/KeepKey RDP2→RDP1 voltage-glitch seed extraction). Ledger Donjon (secure elements vs FI; STM32U5 glitch-hardening; Mk4 DS28C36B laser FI). Coinkite Mk4 (multi-vendor three-chip seed split). Trezor Knowledge Base (no-SE rationale → adoption of OPTIGA Trust M V3 "no NDAs"). Tangem (ATECC508A LFI). Foundries.io (SE050 SCP03 in OP-TEE).

---

## Caveats
- **Two brief assumptions corrected** (top box): 0xF1D0 ships `Change=LcsO<op`/`Read=ALW`/untyped (not `Change=ALW`); only 0xE0E0 carries an Infineon *sample* cert (anchor slots E0E1/2/3/E0E8/9/EF ship empty). Both corrections make the configuration job more explicit; the fixes are unchanged.
- **Exact default OPTIGA metadata TLVs** come from Infineon's published V3 object dump + Configuration Guide, the most precise primary source short of the SRM PDF tables; cross-checked and consistent. Confirm against your specific chip with `trustm_metadata` during Phase 1.
- **CC augmentation components** (AVA_VAN.5/ALC_FLR) for BSI-DSZ-CC-0961 should be confirmed against the latest BSI maintenance report; the OPTIGA datasheet states EAL6+ (high).
- **Exact `P1` bit value `0x33`** follows the GlobalPlatform SCP03 P1 bitmap (AUTHENTICATED+C_MAC+C_DECRYPTION+R_MAC+R_ENCRYPTION); verify your middleware encodes the full level (some stacks default to C-MAC only) and that the SE050 negotiated level matches via I²C capture.
- **STM32U5 RDP2 immutability** is option-byte/state-machine enforced, not mask-ROM; the residual FI-downgrade risk is real but, per Ledger Donjon, no public U5 fault-injection attack exists at the time of writing, and PQ1's split-secret architecture removes the payoff. Treat any future published U5 FI attack as a trigger to re-evaluate.
- **Counter limits:** OPTIGA monotonic counters are capped at 600,000 updates each and ~2 million total updates across all objects — size the PIN/usage thresholds accordingly so the lockstep counter cannot exhaust device endurance.
- **Status-code mapping (S-E/S-7)** is the subtlest correctness risk: the MCU must reconcile SE050 UserID status + OPTIGA E120 + page-124 to the *strictest* and never interpret an SE error code as success; validate the full mapping table against AN12413 on sacrificial units.
