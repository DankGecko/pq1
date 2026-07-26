---
surface: multi
run_date: 2026-07-14
reviewer: "Codex primary + three blinded independent reviewer passes (runtime model identities not asserted)"
scope: "Full PQSigner_OS sweep: STM32U585/TrustZone, secure and nonsecure firmware, NSC, trusted UI, secure elements, firmware update/FSBL, clear signing/ERC-7730, contracts, USB, build/release and supply-chain gates"
status: fixes-landed-production-blocked
---

# Adversarial-review findings — full project sweep — 2026-07-14

## Summary

**Verdict: NOT READY FOR PRODUCTION.** The reviewed snapshot is
`a248c3a1ba063e07a93435fa3662a21c46218605` (`master`). The existing rollback
and ERC-7730 provenance fences correctly prevent a sanctioned production
artifact, but they also mask multiple independent hardware-boundary and
factory-ceremony defects that must be fixed before either fence is lifted.

This pass records **18 findings: 14 open and 4 deferred release blockers**.
There is no demonstrated remote critical compromise of a currently shippable
artifact because no production artifact can currently be built. There are,
however, three high-severity and one medium-severity software-reachable
TrustZone control-plane gaps under the project's hostile-Non-Secure model, one
high-severity and one medium-severity single-fault gap, and two high-severity
latent factory defects.

The sweep walked `docs/STATUS.md` and the live work ledger, all Rust workspace
members, the CMSE/TrustZone boundary, STM32 option-byte and peripheral
attribution code, both secure-element stacks, FSBL/update paths, USB framing,
the smart-wallet contracts, the ERC-7730 compiler/renderer/catalogue, release
automation, and dependency/secret surfaces. STM32 claims were checked against
RM0456 Rev. 7 and `/home/nicola/repos/STM32CubeU5`; OPTIGA claims were checked
against Infineon's Solution Reference Manual v3.70; catalogue drift was checked
against `/home/nicola/repos/clear-signing-erc7730-registry` at the vendored
upstream revision.

### Severity and reachability conventions

- **Hostile NS** means attacker-controlled execution in the non-secure image,
  consistent with the repository's TrustZone invariant. It is not a claim that
  a USB packet alone currently grants arbitrary code execution.
- **Physical/FI conditional** means the source defect is confirmed under the
  project's single-instruction-skip model, but no physical glitch was executed
  in this pass.
- **Latent factory** means the affected path is presently behind a production
  quarantine. It becomes reachable if an operator bypasses that quarantine.
- **Deferred release blocker** is not counted as an exploitable current-image
  vulnerability; the fail-closed fence is functioning.

## UPDATE 2026-07-14 — fix pass (branch `fix/sweep-2026-07-14-findings`)

Worked through all 14 open findings (F15–F18 remain deferred release blockers).
Report status → `fixes-landed-production-blocked`.

- **✅ FIXED (10):** F1 (SPI1 secure — partial, GPIO/RCC-clock residuals),
  F5 (deref-site re-validation; FI-sweep deferred), F6 (unconditional fail-closed
  readback; MPCBB-lock deferred), F7 (SCP03 axis-parity gate — keep-BHK, red by
  design), F8 (OPTIGA `TA_POOL` corrected + manifest; S-2 burn deferred),
  F10 (FI-proven UserOp gas-triple display + 6 tests), F11 (USB router
  owner-lease + 3 tests), F12 (SE050 SCP03 `Zeroizing` core; PBS refactor
  deferred), F13 (semgrep `no-unsafe` rule reconciled 17→0 + guard),
  F14 (`build-hw` feature set). Host tests green; all firmware changes
  compile-validated on `thumbv8m.main-none-eabi` (dual-se + ceremony builds).
- **⏸ DEFERRED with exact diffs (4):** F2 (IWDG secure + alias switch),
  F3 (`RCC_SECCFGR` mask), F4 (`TAMP_SECCFGR.TAMPSEC` + DBP), F9 (`SRAM_RST=0`).
  Owner decision 2026-07-14 ("land the soft two, defer the rest"): these are
  load-bearing TrustZone/clock/tamper/option-byte changes that lock at boot and
  can only be validated on silicon — the exact register diffs are recorded in
  each Resolution + `docs/work-todo.md` so nothing evaporates, but no
  silicon-unvalidated change entered the compiled path.
- **⏸ DEFERRED release blockers (4):** F15–F18 unchanged (this pass touched no
  F15–F18 firmware path).

Per-finding silicon receipts, the deferred Tier-2 diffs, the F5 rainbow sweep,
the F1 GPIO/clock residuals, the F7 phase-2B BHK provisioning, the F8
sacrificial-part matrix, and the F10 `make e2e` budget check are tracked in
`docs/work-todo.md`.

## Findings

### F1 — The shipping trusted-display SPI peripheral remains Non-Secure

- **Status:** ✅ FIXED (partial)
- **Mode / severity:** TZ / trusted UI · HIGH
- **Location:** `secure/src/sau.rs:313-351`; `secure/Cargo.toml:465-473`; `Makefile:2168,2207`; `secure/src/hw/spi_hw.rs:54-55,123-144`; `secure/src/hw/lcd_nv3007.rs:187-192,239-295`
- **What:** the canonical shipping profile enables `ui-lcd`, which uses SPI1
  from secure code, while `configure_gtzc` writes zero to
  `GTZC1_TZSC_SECCFGR2`; SPI1 is therefore deliberately left Non-Secure.
  RM0456 says securable-peripheral reset attribution is NS, and STM32CubeU5
  maps SPI1 to `GTZC_TZSC1_SECCFGR2` bit 1. A hostile NS image can reconfigure,
  disable, or drive the peripheral used for the trusted confirmation display.
  This definitively breaks exclusive secure ownership; deterministic stale-frame
  or spoof behavior still needs a silicon receipt.
- **PoC (falsifiable):** build the canonical feature set, read back
  `GTZC1_TZSC_SECCFGR2`, and issue an NS write to SPI1 CR1/TXDR. The current
  source fixes the expected security bit at zero while the secure LCD path uses
  the same peripheral. A hardware negative test must prove the NS write is
  blocked after the fix.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** mark SPI1 secure, include it in TZIC1 masks, perform
  unconditional readback, and lock the configuration. Add an on-device NS
  CPU/DMA denial test. The former SPI2/TROPIC01 follow-up was retired when that
  backend was removed on 2026-07-14.
- **Resolution:** ✅ SPI1 marked SECURE via `GTZC1_TZSC_SECCFGR2` bit 1
  (`secure/src/sau.rs`, feature-gated on `spi1-arduino`); rides the existing
  TZIC-arm + `lock_security_config` plumbing (no other change needed). Bit
  verified against CMSIS `GTZC_CFGR2_SPI1_Pos`; compile-validated on stm32u585.
  **PARTIAL — two residuals deferred to work-todo:** the panel GPIOE pins
  (PE7/12/13/14/15) stay NS (NS can drive the lines directly, bypassing SPI1)
  and the SPI1 RCC clock-enable is RCC-governed (F3). On-silicon
  `make gtzc-enforcement-hw` receipt still owed. (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F2 — Non-Secure code can keep refreshing the secure watchdog

- **Status:** ⏸ DEFERRED
- **Mode / severity:** TZ / reset recovery · MED
- **Location:** `secure/src/sau.rs:260-264,342-350`; `secure/src/hw/iwdg.rs:49-57,72-75,149-192,211-293`
- **What:** IWDG is omitted from the secure peripheral allowlist and the driver
  intentionally uses its NS alias. The driver calls NS accessibility harmless,
  but its policy enforcement works by *withholding* refresh after a stalled or
  wedged handler. Hostile NS code can write the reload key itself and defeat
  that decision, preventing the expected reset and reset-time secret cleanup.
  STM32CubeU5 maps IWDG to `GTZC1_TZSC_SECCFGR1` bit 7.
- **PoC (falsifiable):** on a test build, force the secure
  `systick_watch_and_kick` path past its stop-kicking threshold while an NS loop
  writes the documented reload value to the IWDG key register. The current
  attribution permits that write; the fixed build must reset and record a TZIC
  violation instead.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** attribute IWDG to Secure, add it to the TZIC mask, use the
  secure alias, read back unconditionally, and add a hostile-NS refresh-negative
  test.
- **Resolution:** ⏸ DEFERRED with the exact register diff recorded (owner
  decision 2026-07-14 "land-soft-two"). Fix = mark IWDG SECURE via
  `SECCFGR1` bit 7 AND switch `hw/iwdg.rs` from the NS alias `0x4000_3000` to
  the SECURE alias `0x5000_3000` — **the two MUST land atomically** or the newly
  secured TZSC blocks every secure `kick()` → ~2 s reset-loop brick. Brick-risky
  + silicon-validation-only. Blocker: bench silicon; tracked in work-todo.

### F3 — RCC/PWR clock and voltage security is never established

- **Status:** ⏸ DEFERRED
- **Mode / severity:** TZ / FI / clock integrity · HIGH
- **Location:** `secure/src/hw/rcc.rs:9-17,38-49,84-116,119-171`; `secure/src/sau.rs:313-351,433-436`
- **What:** no production code writes `RCC_SECCFGR`, `RCC_PRIVCFGR`, or the
  relevant PWR security controls. RM0456 gives `RCC_SECCFGR` a zero reset value,
  making HSI/HSI48, PLL1, SYSCLK selection, and prescalers non-secure. Because
  `SYSCLKSEC` remains zero, the PWR voltage-scaling/booster fields are also
  non-secure. Hostile NS can therefore alter system timing and voltage after
  secure boot. DoS and timeout distortion are direct; cryptographic corruption
  or a software-induced fault is conditional on silicon behavior.
- **PoC (falsifiable):** the repo-wide security-register search returns no
  writer, while `rcc.rs` itself uses the RCC NS alias. On sacrificial hardware,
  attempt NS changes to PLL/SYSCLK/prescalers/HSI48 and VOS after secure init,
  and observe whether secure signing or watchdog timing changes. The fixed
  image must RAZ/WI those accesses and raise the configured illegal-access
  signal.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** set the minimum RCC security mask covering HSI, HSI48,
  PLL1, SYSCLK, prescalers, LSI, and required kernel clocks; secure/privilege the
  corresponding PWR domains; configure GTZC2/TZIC2 where applicable; then
  unconditionally verify and lock the configuration. Keep intentionally NS USB
  clocks narrowly separated.
- **Resolution:** ⏸ DEFERRED with the exact register diff recorded. Fix =
  write `RCC_SECCFGR` mask `0xCE9` (HSISEC|LSISEC|SYSCLKSEC|PRESCSEC|PLL1SEC|
  ICLKSEC|HSI48SEC) via the **SECURE** alias `0x5602_0C10` (NOT the NS alias —
  that write is silently WI), after clock config and before
  `lock_security_config`. Clock-tree-brick-risky + silicon-only; also needs the
  RM0456 SYSCLKSEC↔PWR-VOS coupling confirmed. Blocker: bench silicon; work-todo.

### F4 — Tamper controls remain NS-writable and backup-domain writes remain open

- **Status:** ⏸ DEFERRED
- **Mode / severity:** TZ / tamper response · HIGH
- **Location:** `secure/src/hw/tamp.rs:224-264,267-325`; `secure/src/sau.rs:339-341,433-436`; `secure/src/hw/bhk.rs:328-329`
- **What:** tamper initialization sets `PWR_DBPR.DBP`, programs CR1/CR3/IER,
  but never sets `TAMP_SECCFGR.TAMPSEC` and never closes DBP. The production
  feature set enables `tamp,tamp-wipe`, yet GTZC2 is explicitly left at its NS
  reset state. RM0456 §64 states that all TAMP registers are S+NS read/write
  after backup-domain reset until TAMPSEC is set. BHKLOCK alone does not secure
  the rest of the TAMP control plane. Hostile NS can disable monitoring or
  clear/reconfigure state before the secure poll/IRQ path acts.
- **PoC (falsifiable):** read `TAMP_SECCFGR` after boot and attempt NS writes to
  TAMP CR1/CR3/SCR. Current source predicts `TAMPSEC=0` and DBP still open. The
  fixed build must preserve the configured enables, reject NS access, and
  report the violation.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** program and verify TAMPSEC plus counter/backup-register
  zones, secure the associated RCC/PWR controls, clear DBP after setup, enable
  the relevant TZIC2 path, and lock GTZC2 after all RTC/TAMP setup is complete.
- **Resolution:** ⏸ DEFERRED with the exact register diff recorded. Fix =
  set `TAMP_SECCFGR.TAMPSEC` (bit 31) via read-modify-**OR** (preserving
  BHKLOCK) at the tail of `init_tamp_registers`, and clear `PWR_DBPR.DBP` only
  **after** the BHK `BKP0R..7R` writes in `main.rs` (a mis-ordered DBP clear
  zeroes the BHK → broken SE pairing); optional GTZC2/TZIC2 detection DiD.
  Backup-domain-brick-risky + silicon-only. Blocker: bench silicon; work-todo.

### F5 — NSC pointer authorization still ends in one skippable caller branch

- **Status:** ✅ FIXED (functional; FI-sweep pending)
- **Mode / severity:** TZ / physical FI · HIGH
- **Location:** `secure/src/nsc/cmd_sign_userop.rs:131-151,1988-2004`; `secure/src/nsc/cmd_sign_userop_batch.rs:165-182`; `secure/src/nsc/cmd_sign_offchain.rs:98-119`; `secure/src/nsc/cmd_get_init_code.rs:89-99`; `secure/src/nsc/ns_ptr.rs:74-118`
- **What:** the shared sentinel primitive is branchless internally, but the
  major handlers perform only one sentinel call per pointer followed by one
  reject branch. A precise skip of that caller branch admits an invalid pointer
  to subsequent raw secure-mode volatile reads/writes. The stronger `NsPtr`
  helper already performs two independent validations separated by a random
  wait, but these handlers do not use it. Source comments incorrectly claim the
  single sentinel comparison itself closes the branch-skip case.
- **PoC (falsifiable):** current optimized Thumb disassembly preserves the
  call/compare/single conditional-reject shape. Extend the production FI target
  to skip the *outer* reject branch with an invalid secure-SRAM input or output
  address; success is any dereference or write past the gate. The fixed target
  must report zero bypasses for each handler and dereference site.
- **Disposition:** CONFIRMED_REAL (physical-FI conditional)
- **Proposed fix:** move to a capability/typestate pointer whose constructor
  performs two independent full validations and whose dereference repeats the
  security classification, or compose a second independent gate immediately
  at every raw dereference. Test the actual production handler disassembly, not
  a stronger mirror harness.
- **Resolution:** ✅ Bounded fix landed. Added a second, spatially-distant
  deref-site re-validation of the full `MAX_SIGN_RESPONSE_LEN` write extent
  immediately before the output write in `cmd_sign_userop.rs` (§15), mirroring
  the proven `cmd_sign_offchain.rs` §14 6492 template — so a single skip of the
  top gate's reject branch no longer admits an OOB write; corrected the
  over-claiming "fails closed" comment (per the project README's own
  "one-skip-of-the-return-branch" residual). Functional correctness
  compile-validated + covered by `make e2e`. **Deferred → work-todo:** the full
  `NsPtr` typestate adoption across all ~10 handlers + the rainbow
  instruction-skip FI-bypass sweep on the real ELF. The FI-property closure is
  NOT claimed. (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F6 — Production removes TrustZone readback checks and leaves MPCBB unlocked

- **Status:** ✅ FIXED (readback; MPCBB-lock deferred)
- **Mode / severity:** TZ / physical FI · MED
- **Location:** `secure/src/sau.rs:298-310,354-366,414-478`
- **What:** GTZC attribution and SAU/TZSC lock readbacks use
  `debug_assert_eq!`, so they disappear from release firmware. A skipped or
  faulted configuration/lock write can reach NS boot without detection. In
  addition, MPCBB1/2 are programmed with `CR=0` and neither block CFGLOCKR nor
  `CR.GLOCK` is set. Direct NS writes to MPCBB are not shown, so the MPCBB part
  is defense against FI or a secure-MMIO primitive rather than a standalone NS
  exploit.
- **PoC (falsifiable):** compile release and show the readback failure paths are
  absent; fault one `tzsc_seccfgr*` or lock-register write and continue to the
  NS branch. A fixed image must fail closed after one fault, and readbacks must
  remain in release disassembly. Separately verify MPCBB CFGLOCKR/GLOCK bits.
- **Disposition:** CONFIRMED_REAL (physical-FI conditional)
- **Proposed fix:** make redundant readback and fail-closed handling
  unconditional, add FI-separated duplicate checks, and set/verify all
  applicable MPCBB configuration locks before NS boot.
- **Resolution:** ✅ Promoted the TZSC-config and SAU/AIRCR/TZSC-lock
  readbacks from `debug_assert_eq!` (a no-op under the shipping `--release`
  profile — so the checks vanished from every shipping build) to an
  unconditional fail-closed `verify_or_halt` (`secure/src/sau.rs`); the
  source-string pure-test was updated + a regression guard added. Compile-
  validated on stm32u585. **Deferred → work-todo:** the MPCBB `CFGLOCKR`/`GLOCK`
  lock (Part B) + an on-silicon confirmation that the fail-closed halt does not
  false-trip a correct config. (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F7 — SE050 rotation and the shipping image derive different SCP03 keys

- **Status:** ✅ FIXED (code-now; ceremony deferred)
- **Mode / severity:** factory / secure element · HIGH
- **Location:** `Makefile:1229-1253,2159-2168,2195-2207`; `secure/src/hw/secret_keys.rs:208-250,318-356`; `secure/src/se050/scp03.rs:56-85,161-203`
- **What:** the irreversible rotation target enables `bhk`, so it installs
  BHK-derived keyset 0x0B. Both canonical release feature sets deliberately
  omit `bhk`; `derive_into_bhk` then falls back to DHUK. The final image will
  derive keys different from those installed by the ceremony and fail SCP03
  closed. This is a persistent availability brick/loss of `half_E`, not a
  demonstrated confidentiality bypass.
- **PoC (falsifiable):** resolve Cargo features and compute the three derived
  keys under the rotation and shipping profiles for one fixed device-root test
  fixture; all three pairs differ. A sacrificial successful PUT KEY followed by
  the exact final image must currently fail authentication.
- **Disposition:** CONFIRMED_REAL (latent factory path)
- **Proposed fix:** define one immutable, machine-readable key-derivation
  profile consumed by rotation and runtime; make feature/root parity a build
  assertion; require the exact final image to boot and authenticate before the
  ceremony is accepted.
- **Resolution:** ✅ (code-now) Added the `se050-scp03-axis-parity` build gate
  (`tools/check_se050_scp03_axis_parity.py` + Makefile target, single-source
  `SE050_ROTATE_FEATURES` var) that fails whenever the rotation-ceremony and
  ship SCP03 derivation axes diverge. **Owner decision 2026-07-14: KEEP the
  Tier-2 BHK split** — the gate is RED by design (ceremony=BHK, ship=DHUK) until
  the **phase-2B BHK provisioning** (bumped to the top of `docs/work-todo.md`)
  lands and flips the ship image to BHK. The irreversible PUT KEY ceremony +
  on-silicon acceptance stay deferred-by-design.

### F8 — OPTIGA trust-anchor lockdown targets device-certificate and nonexistent slots

- **Status:** ✅ FIXED (code-now; S-2 burn deferred)
- **Mode / severity:** factory / secure element · HIGH
- **Location:** `secure/src/optiga/mod.rs:1796-1876`; `docs/production-todo.md:201-264,343-372`
- **What:** `TA_POOL` is hard-coded as `E0E3..E0E8`. Infineon's Solution
  Reference Manual v3.70 Table 68 identifies E0E1-E0E3 as device-identity
  certificate slots and E0E8, E0E9, and E0EF as the three trust anchors. The
  current loop can overwrite/lock E0E3, then abort at nonexistent E0E4 because
  metadata failure is propagated, never reaching E0E9/E0EF. This is a
  destructive/incomplete ceremony, not a silent success. The direct protected-
  update bypass remains conditional because current target metadata does not
  expose the required `Int(anchor)`/reset shape.
- **PoC (falsifiable):** compare `TA_POOL` with SRM Table 68; a sacrificial
  device OID inventory must show the mismatch. Run only on disposable hardware:
  the present loop should fail before completing and leave the actual anchor
  set incompletely handled.
- **Disposition:** CONFIRMED_REAL (latent destructive factory path)
- **Proposed fix:** generate the OID policy from an authoritative checked-in
  manifest; handle `{E0E8,E0E9,E0EF}` as trust anchors, protect device identity
  slots separately, account for promotable spare data objects, and require
  readback plus negative protected-update receipts on sacrificial silicon.
- **Resolution:** ✅ (code-now) Corrected the destructive OPTIGA trust-anchor
  policy: `TA_POOL` was `0xE0E3..=0xE0E8` (junk-overwrites device-cert E0E3, then
  aborts at the absent E0E4, leaving the real anchors unlocked — destructive AND
  a false-closed S-2). Now the authoritative `apdu::ta_pool` manifest splits
  type-0x11 anchors `{E0E8,E0E9,E0EF}` (junk+NEV+lock) from type-0x12 device
  certs `{E0E1,E0E2,E0E3}` (ratchet-lock only, cert preserved), with a
  compile-time exact-policy pin + corrected `reset.rs`/`apdu.rs` docstrings.
  Compile-validated under the double factory gate. **S-2 stays open**: the
  irreversible on-silicon burn + sacrificial-part validation matrix remain
  deferred-by-design → work-todo. (2026-07-14, branch `fix/sweep-2026-07-14-findings`)
- **⚠️ Resolution amended 2026-07-26 — the code it describes did not survive the
  merge.** This entry's analysis of the defect stands unchanged and was the
  source used to correct four provisioning docs (see the CORRECTION 2026-07-26
  block in `docs/provisioning/first-boot-provisioning.md`). But the *fix* it
  describes was superseded at merge by the concurrent first-boot work, whose
  fail-closed placeholder won: **there is no `apdu::ta_pool` manifest and no
  compile-time exact-policy pin.** What exists today is
  `OptigaTrustM::lockdown_ta_pool` (`secure/src/optiga/mod.rs:1971-2003`), which
  holds the candidate inventory `{0xE0E8, 0xE0E9, 0xE0EF}` in a `const`, emits
  **no APDU**, and returns `Err(Status(0xEC))` — and which
  `OPTIGA_TA_POOL_LOCKDOWN_BLOCKED` (`secure/src/nsc/mod.rs:301-311`) prevents
  from existing in any compilable image at all. The device-cert split
  (`{E0E1,E0E2,E0E3}` ratchet-lock-only) is documented in the driver docstring
  and `docs/provisioning/provisioning-reference.md` O-4, not implemented. Net
  effect on the security posture is unchanged — S-2 is open either way — but do
  not cite this Resolution as evidence that a ceremony implementation exists.

### F9 — Reset hardening erases SRAM2 while secure secrets and stack live in SRAM1

- **Status:** ⏸ DEFERRED
- **Mode / severity:** reset / physical remanence · MED
- **Location:** `secure/memory-stm32u585.x:8-9,30-35`; `Makefile:262-277`; `secure/src/reset_cause.rs:43-76,145-148`; `secure/src/main.rs:963-976`; `secure/src/nsc/mod.rs:1183-1201`
- **What:** the secure linker places all secure data and stack in SRAM1. The
  provisioning target programs only `SRAM2_RST=0`; it does not program
  `SRAM_RST=0`, whose ST production value is 1 and which RM0456 defines as the
  reset erase for SRAM1/3/4/5/6. BOR is classified `Cold` and skips the software
  wipe, while `zeroize_sensitive_state` clears named globals rather than the
  complete old stack. A retaining reset can therefore leave prior secure stack
  and data bytes until overwritten.
- **PoC (falsifiable):** inspect live FLASH_OPTR after the documented hardening
  target and verify bit 15 remains set; place a canary in secure SRAM1, trigger
  each supported reset class, and inspect it through a controlled secure test
  path before normal RAM reuse.
- **Disposition:** CONFIRMED_REAL (physical readout conditional)
- **Proposed fix:** provision and verify `SRAM_RST=0`; add an earliest-possible
  full secure-RAM scrub where architecture permits; do not treat every BOR flag
  as proof of power-loss decay. Reconcile this with any future SRAM2 secret
  relocation/ECC plan.
- **Resolution:** ⏸ DEFERRED with the exact option-byte diff recorded. Fix =
  add `SRAM_RST=0` to the `stm32-harden-opts` target (Makefile) so silicon
  erases SRAM1/3/4 — where the secure stack + secrets live — on every reset (the
  current provisioning only sets `SRAM2_RST=0`, covering the wrong bank); +
  optional `reset_cause.rs` BOR-scrub companion. Option-byte-brick-vector +
  silicon-only. Blocker: sacrificial board; work-todo.

### F10 — Generic Safe/CoW UserOperation display is non-injective over signed gas fields

- **Status:** ✅ FIXED
- **Mode / severity:** clear signing / WYSIWYS · MED
- **Location:** `secure/src/nsc/cmd_sign_userop.rs:787-818`; `aa/src/userop.rs:637-706`; `tx-core/src/eip1559.rs:383-410`; `secure/src/tx/display/dispatch.rs:103-125`; `secure/src/tx/display/value_page.rs:299-324`; `pqsigner-erc7730/src/display/render/mod.rs:758-817,885-966`
- **What:** the sign digest commits to call, verification, and pre-verification
  gas as three ordered U256 values. The generic Safe/CoW envelope displays only
  their saturated aggregate `tx.gas_limit`, whereas only the ERC-7730 renderer
  consumes and shows `userop_fields` exactly. Distinct signed UserOperations can
  therefore produce identical confirmation pages.
- **PoC (falsifiable):** hold every other field constant and compare gas tuples
  `(100000, 200000, 21000)` and `(200000, 100000, 21000)`. Both produce the same
  aggregate gas pages, while `compute_sphincs_digest_v06` differs because the
  ordered words differ. Add this as a full dispatch differential test.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** make every UserOperation confirmation path render the exact
  three gas values and full nonce (or refuse); reuse the lossless ERC-7730
  envelope renderer instead of the legacy aggregate helper. Assert display
  injectivity for signed fee/gas operands across all dispatch branches.
- **Resolution:** ✅ Added an FI-proven UserOp gas-triple display lane
  (`secure/src/tx/display/userop_gas_lane.rs`) rendering the three signed gas
  words (Call/Verify/PreVer + Total) on one page, wired + independently proved
  at **every** UserOp confirm path — the single handler (`cmd_sign_userop.rs`)
  and all three batch render sites (`cmd_sign_userop_batch.rs`) — with the page
  reserved in both multiSend budgets (F10's page-budget regression guard). 6
  host tests incl. the `permuted_gas_triple_yields_distinct_pages` WYSIWYS-
  injectivity property (all pass). **Pending:** `make e2e` confirmation that no
  legitimate page-heavy multiSend overflows `MAX_PAGES` (fail-closed if it
  does). (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F11 — USB channel IDs are not bound to router or pending-response state

- **Status:** ✅ FIXED
- **Mode / severity:** USB / companion isolation · LOW
- **Location:** `nonsecure/src/usb/transport.rs:42-45,82-90,160-174`; `nonsecure/src/main.rs:210-219`; `nonsecure/src/usb/commands.rs:120-143,174-215,742-780,1015-1042`
- **What:** the HID transport retains a channel ID only for response framing;
  dispatch receives APDU bytes without that identity. Chaining state and the
  global pending GET_RESPONSE cursor have no owner, and any channel can drain
  them. Two clients on one physical device can interfere with or consume each
  other's response continuation. Because the first response chunk remains with
  the initiating channel and signatures are public, the demonstrated impact is
  cross-client confusion, partial disclosure, and DoS—not full signature or
  secret theft.
- **PoC (falsifiable):** start a chunked response on channel A, then issue
  GET_RESPONSE on channel B; current routing returns A's next chunk framed for
  B. Interleave a chained APDU across channel IDs and observe global state
  interference.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** pass channel identity through dispatch, bind chain and
  pending-response state to an owner, reject cross-channel continuation, and
  add two-channel tests.
- **Resolution:** ✅ Added a single-session router owner-lease: `ROUTER_OWNER`
  in `nonsecure/src/usb/commands.rs` + the pure, host-tested `router_lease_allows`
  in `shared/src/apdu_framing.rs`; threaded the HID channel id through
  `try_receive` → `dispatch`, and reject any foreign-channel continuation/drain
  WITHOUT disturbing the owner's chain/pending state (so a foreign channel can
  neither siphon nor DoS it). Lease released on drain/chain completion + the
  30 s timeout scrub. 3 host tests pass. (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F12 — Secure-element root material outlives the operation that needs it

- **Status:** ✅ FIXED (core; PBS refactor deferred)
- **Mode / severity:** secret lifecycle / physical readout · MED
- **Location:** `secure/src/optiga/shield.rs:74-95,113-144,541-548`; `secure/src/optiga/mod.rs:2859-2872`; `secure/src/se050/scp03.rs:56-85,174-203,210-327`
- **What:** OPTIGA session zeroization intentionally retains the 64-byte PBS in
  the static driver throughout the locked state, even though it is re-derivable
  from the device root. SE050 `load_platform_keys` returns ENC/MAC/DEK arrays by
  value; `establish` keeps ENC/MAC as ordinary stack locals and discards DEK
  without guaranteed zeroization on success or error. Session keys are cleaned,
  but these longer-lived roots can remain in secure SRAM/old stack frames.
- **PoC (falsifiable):** source-level lifetime tracing shows PBS survives
  `zeroize_sensitive_state` and SCP03 root locals have no `Zeroizing`/explicit
  wipe. A compiler-backed disassembly audit should confirm whether stores are
  removed or stack slots remain; this pass did not obtain that assembly receipt.
- **Disposition:** CONFIRMED_REAL at source-lifecycle level; physical extraction
  impact is conditional
- **Proposed fix:** derive PBS only immediately before handshake, wrap all root
  arrays in `Zeroizing`, wipe on every return path, and extend the assembly-level
  zeroization gate to these functions and the exact shipping LTO profile.
- **Resolution:** ✅ (core) The SE050 SCP03 static keys
  (`se050_scp03_{enc,mac,dek}_key`) and `load_platform_keys` now return
  `Zeroizing<[u8;16]>` (derived in place — no un-wiped `Copy` stack temp), and
  the PUT KEY APDU buffer in `rotate_scp03_keys` is `Zeroizing`-wrapped — so the
  per-device keys + the DEK `establish` binds-but-never-uses auto-wipe on every
  return path. Derivation labels unchanged (no frozen-tag impact). Compile-
  validated on the derived + rotate paths. **Deferred (owner decision):** the
  OPTIGA PBS just-before-handshake refactor reverses the accepted MEDIUM-1
  residual and carries an OPTIGA-unreachable availability risk — left as-is. (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F13 — The blocking invariant/CI gate is red on the reviewed tree

- **Status:** ✅ FIXED
- **Mode / severity:** build assurance / CI · MED
- **Location:** `.semgrep/pqsigner-invariants.yml`; `.github/workflows/ci.yml:55-76`; `pqsigner-erc7730/src/display/render/mod.rs:97-286`; `shared/src/ns_ptr_validate.rs:186-220,434-473`
- **What:** `make invariant-gates` fails with 17 ERROR-level findings under
  `semgrep.no-unsafe-in-pure-logic-crates`: six volatile canary operations in
  the ERC-7730 renderer and eleven NS-pointer primitive/test operations in
  `shared`. The same Semgrep ERROR rules are a blocking CI job. Either the
  documented safe-Rust invariant has regressed or the rule/package taxonomy is
  stale; in both cases the release signal is unusable until reconciled.
- **PoC (falsifiable):** `make invariant-gates` exits 2 on current `master` with
  exactly 17 findings. Cargo-deny advisories, bans, and sources pass before the
  Semgrep failure.
- **Disposition:** CONFIRMED_REAL (assurance-control failure; not a proven
  memory-safety exploit)
- **Proposed fix:** move hardware/FI volatile operations behind a narrowly
  reviewed safe abstraction outside pure crates, or explicitly revise the
  invariant and Semgrep scope with tests. Do not suppress individual findings
  without documenting the ownership/lifetime proof.
- **Resolution:** ✅ Reconciled the stale `no-unsafe-in-pure-logic-crates`
  ERROR rule: narrow `exclude:` for the two DELIBERATELY host-relocated,
  structurally-required-unsafe files (`shared/src/ns_ptr_validate.rs` — the
  Kani+Miri-verified NS-pointer primitives; `pqsigner-erc7730/.../render/mod.rs`
  — the FI stack-canary), each documented with its proof pointers, + a
  `make invariant-gates` allowlist guard (`.semgrep/check_unsafe_exclude_allowlist.py`)
  pinning the exclude list to exactly those two, + a CLAUDE.md taxonomy update.
  Gate goes 17 → 0 findings; a negative control confirms it still fires on new
  unsafe elsewhere. (Rejected the `black_box` "make it safe" path — a silent
  FI-category-4 weakening.) (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F14 — The advertised `build-hw` target cannot build its own hardware profile

- **Status:** ✅ FIXED
- **Mode / severity:** build assurance · LOW
- **Location:** `Makefile:304-310`; `secure/src/nsc/mod.rs:113-133,468-476`
- **What:** `make build-hw` selects a release STM32 profile with `mock-se`,
  `debug-log`, and `ui-semihosting` but omits the test escape and required
  consumption masking. The security fences correctly reject it with two compile
  errors. As a result, the named developer/hardware build target provides no
  current compilation receipt and can silently go unused while source drifts.
- **PoC (falsifiable):** `make build-hw` exits 2 on the reviewed snapshot after
  the secure crate reports the forbidden release diagnostics and missing
  `consumption-mask`.
- **Disposition:** CONFIRMED_REAL (assurance target defect; safety fences work)
- **Proposed fix:** define a coherent explicit non-shipping hardware-test
  profile (`e2e-test` or `dev-testkey` plus required hardening), or retire/rename
  the target. Add it to a gate only after it is intentionally green.
- **Resolution:** ✅ `make build-hw` now builds
  `mock-se,debug-log,ui-semihosting,e2e-test,stm32u585` — the `e2e-test` escape
  defuses both `nsc/mod.rs` ship-blocker fences (and dodges the probe-rs
  SYS_READC hang), keeping the image CI-denylisted / non-shippable by
  construction. `make build-hw` exits 0. The security fences were NOT weakened.
  (2026-07-14, branch `fix/sweep-2026-07-14-findings`)

### F15 — A/B binaries are not linked or booted for their physical slot addresses

- **Status:** ⏸ DEFERRED
- **Mode / severity:** firmware update / secure boot · HIGH release blocker
- **Location:** `secure/memory-stm32u585.x:16-35`; `secure/src/hw/flash.rs:814-879`; `fsbl/src/branch.rs:28-62`; `secure/src/main.rs:415-418,3724-3729`
- **What:** the secure runtime links at `0x0C000000`, but updater slots begin at
  `0x0C00E000` and `0x0C082000`; the FSBL branches directly to vectors at those
  physical slot bases without relocation. The non-secure runtime is linked for
  slot A and secure startup always boots NS at `0x08100000`, even when FSBL
  selected secure slot B. The manifest does jointly sign and FSBL does jointly
  verify the secure and non-secure hashes, so cryptographic pairing is not the
  defect; physical placement and the selected runtime boot bases are. The
  current binaries cannot form two independently bootable S+NS slot pairs.
- **PoC (falsifiable):** inspect linked vector/reset addresses and absolute
  relocations in one existing secure/NS ELF, copy it to each declared slot, and
  compare with the FSBL raw-vector branch and hard-coded NS base. At least slot B
  and the declared secure slot bases disagree without a per-slot link or reviewed
  relocation layer.
- **Disposition:** CONFIRMED_REAL, but unreachable from a sanctioned production
  build because rollback/update is quarantined
- **Proposed fix:** independently link each physical S/NS slot pair, or
  implement and verify a relocation design; make each selected secure runtime
  boot the matching NS base; retain the existing joint manifest binding; test
  both directions and torn-update recovery on hardware.
- **Resolution:** deferred behind the firmware-rollback redesign; this must be a
  named acceptance criterion before the quarantine is removed.

### F16 — The production rollback/factory backend is not implemented

- **Status:** ⏸ DEFERRED
- **Mode / severity:** firmware rollback · HIGH NO-GO
- **Location:** `secure/src/nsc/mod.rs:267-300`; `secure/build.rs:16-39`; `fsbl/build.rs:26-49`; `Makefile:2018-2019,2256-2263,2330`
- **What:** the live backend remains the rejected unary OTP design; Draft 0.9/1.1
  documents replacement interfaces but does not implement a production physical
  backend. Production, factory, and normal STM32 builds fail closed. This is a
  release blocker rather than a current exploit because the fence is effective.
- **PoC (falsifiable):** `make prod-check-ship` passes feature-policy resolution
  and then exits 2 at the explicit rollback-backend refusal. A custom
  `mode-production` Cargo build is also rejected in build-script and Rust code.
- **Disposition:** CONFIRMED_REAL release blocker; fail-safe fence functioning
- **Proposed fix:** implement the reviewed journal/typed-floor contract and
  obtain flash/RAM layout, power-loss, endurance, ECC, OTP, two-slot boot, and
  sacrificial-silicon receipts before removing any fence.
- **Resolution:** deferred to the rollback implementation program tracked in
  `docs/work-todo.md` and the A/B architecture document.

### F17 — Production option-byte state is externally assumed, not enforced by the trust root

- **Status:** ⏸ DEFERRED
- **Mode / severity:** silicon lockdown · HIGH release blocker
- **Location:** `secure/src/main.rs:897-940`; `fsbl/src/main.rs:82-138`; `Makefile:262-277`; `docs/production-todo.md:495-540,621-675`
- **What:** production code warns about RDP2/SECBOOTADD0 but does not establish
  or fail closed on the complete RDP/WRP/BOOT_LOCK/HDP/SECWM/BOR/SRAM option-byte
  contract. FSBL does not verify it before trusting a slot. The external factory
  ceremony remains load-bearing, and the rollback quarantine currently prevents
  a production run.
- **PoC (falsifiable):** boot a production-profile diagnostic image with one
  required option byte deliberately wrong; the current default behavior warns
  and continues unless a narrow opt-in halt feature is used. FSBL has no
  complete readback path.
- **Disposition:** CONFIRMED_REAL release blocker
- **Proposed fix:** define one machine-readable expected option-byte policy,
  program it only in an authenticated irreversible ceremony, and have the
  immutable FSBL redundantly read back and fail closed before rendering a
  trusted measurement or branching.
- **Resolution:** deferred pending factory/silicon authority and sacrificial
  validation.

### F18 — ERC-7730 production provenance is unavailable

- **Status:** ⏸ DEFERRED
- **Mode / severity:** clear signing / provenance · HIGH release blocker
- **Location:** `secure/src/db_roots.rs:126-140`; `Makefile:2209-2219`; `secure/data/erc7730-registry/README.md`
- **What:** the generated catalogue is explicitly `dev-unattested`; no trusted
  ERC-8176 attestation set currently authorizes the 420-leaf shipping root. The
  production gate correctly refuses it. The local vendored registry matches the
  recorded upstream revision and codegen is in sync, but source synchronization
  is not cryptographic production provenance.
- **PoC (falsifiable):** `make prod-erc7730-provenance-check` exits 2 after the
  descriptor sync check because `dev-unattested != erc8176-verified`. The live
  coverage query on 2026-07-14 found no attestation matching this descriptor
  set.
- **Disposition:** CONFIRMED_REAL release blocker; fail-safe fence functioning
- **Proposed fix:** implement the reviewed ERC-8176 verification/provenance
  pipeline, pin an authenticated trust policy and coverage receipt, regenerate
  the root, and keep the current fail-closed gate.
- **Resolution:** deferred until an authoritative attestation source and
  verifier are available.

## Suspicions (unverified — no PoC)

1. **Host-supplied EntryPoint address.** `cmd_sign_userop.rs:230-231` accepts
   the address signed into the digest instead of requiring the canonical v0.6
   singleton in `aa/src/userop.rs:616-622`. The deployed wallet hashes its own
   immutable EntryPoint, so substitution appears to yield only an unusable
   signature and one consumed local count. A malicious companion can already
   withhold a valid signature, so no stronger security impact was demonstrated.
2. **OPTIGA arbitrary data-object promotion.** The actual anchor OIDs are known,
   but whether a spare F1Dx object can be retyped and honored as a protected-
   update anchor needs sacrificial-silicon testing. Do not claim the current
   metadata exposes an unconditional bypass.
3. **Trusted-display spoof details.** NS register reachability is confirmed.
   The exact sequence that leaves a controlled stale frame while the secure UI
   continues rather than hangs is hardware-specific and was not demonstrated.
4. **Compiler survival of root-key wipes.** F12 identifies missing source-level
   cleanup. The mandatory compiler/assembly workflow could not complete its
   preflight in this embedded workspace, so this pass makes no claim about exact
   optimized stack residue.

## Reconfirmed accepted/by-design residuals

- `CMD_GET_INIT_CODE` remains an accepted, unlock-gated few-time bootstrap
  signature oracle documented in `docs/VULN-getinitcode-bootstrap-fewtime-oracle.md`.
  No practical key-recovery path was demonstrated in this sweep.
- Explicit off-chain RAW32 is a loud semantic downgrade tier. It remains safe
  only if production policy explicitly accepts blind hash signing.
- Wire-v2 slot rotation can omit data a seedless companion needs; companions
  must not retry a partially understood response because a retry can consume
  another bounded bootstrap signature.
- RDP/SECBOOT diagnostics are intentionally non-halting today to avoid factory
  rehearsal bricks. That tradeoff is acceptable only while production remains
  fenced; it is recorded as F17 before release.

## Reviewed claims that did not survive reproduction

- There is **no demonstrated unconditional current OPTIGA protected-update seed
  bypass**: current target metadata lacks the required integrity-anchor/reset
  form.
- The bad OPTIGA OID loop does **not** silently report success; it is expected to
  abort on an invalid slot after potentially destructive earlier writes.
- Missing BHK does **not** produce a successful zero-key SCP03 rotation; the
  relevant failure mode is the BHK-vs-DHUK profile mismatch in F7.
- No feasible CMSE reentrancy path was found under the current interrupt
  attribution and single-core polling design.
- The attempted composition “byte-wise NSC write directly reprograms MPCBB” is
  invalid: MPCBB registers require word accesses. F5 and F6 remain independent.
- No dependency CVE was reported by the locked `cargo deny` advisory gate.
  Duplicate versions and the large cargo-vet exemption set are assurance debt,
  not proof of a vulnerability.
- The vendored ERC-7730 corpus is intentionally a curated subset rather than a
  byte-for-byte copy of every upstream JSON file. Its recorded upstream revision
  and generated artifacts were in sync.

## Validation ledger

| Check | Result on/reconciled to reviewed snapshot | Security meaning |
|---|---:|---|
| `make test-unit` | PASS | Host workspace, secure suite, and ERC-7730 round-trip tests passed after the final merge snapshot. |
| `make check-codegen` | PASS | ERC-7730 and protocol-generated artifacts are in sync. |
| `make verify-pins` | PASS | Cargo checksums/git pins, Foundry revisions, Rust toolchain, and Actions SHAs are pinned. |
| `make verify-gate-enforcement` | PASS (21 gates) | Enrolled gates have documented trigger coverage; this meta-gate does not make a red child gate green. |
| `make invariant-gates` | **FAIL (17 Semgrep ERROR findings)** | F13; cargo-deny advisories/bans/sources passed first. |
| `make build-hw` | **FAIL (2 intended safety fences)** | F14; the target's feature profile is internally inconsistent. |
| `make prod-check-ship` | expected FAIL | Feature policy passes, then rollback F16 blocks shipping. |
| `make prod-erc7730-provenance-check` | expected FAIL | Descriptor sync passes, then provenance F18 blocks shipping. |
| `make miri` | PASS | Secure/shared NS-pointer primitive Miri coverage passed; this does not model instruction skips. |
| `make e2e` | PASS | All QEMU scenarios/assertions passed. |
| `make test-solidity` | PASS (115 passed, 0 failed, 1 skipped) | Smart-wallet contract suite passed. |
| `make fuzz-all FUZZ_TIME=5` | PASS (12 targets, 0 artifacts) | Short smoke campaigns only, not exhaustive fuzzing. |
| `make fsbl` | PASS, nonshipping | Legacy FSBL built at 28,316/32,768 bytes; build warns that it has no release authority. |
| `cargo vet --locked` | PASS with 50 fully audited, 2 partially audited, 169 exempted | Vet policy is internally satisfied; exemptions remain a large assurance residual. |
| `make erc8176-coverage` | 0 matching attestations | Live query on 2026-07-14; supports F18, but external state can change. |

Additional checks found no private-key PEM markers in tracked source. The
compiler-backed zeroization workflow's mandatory clean root-build preflight did
not fit the embedded target/feature topology, so no fresh optimizer-level
zeroization receipt is claimed. Trailmark was unavailable in the primary
environment and was not installed during the audit; structural prioritization
was therefore reproduced manually from entry points, call sites, and build
profiles rather than represented as a Trailmark result.

## Honest residual (the run is INVALID without this)

1. **What I tried to break and couldn't.** The production rollback and
   ERC-7730 provenance fences fail closed; the locked dependency advisory,
   pinning, codegen, unit, QEMU, Miri, fuzz-smoke, and Solidity suites held.
   Pointer range arithmetic, UserOperation digest binding, double signature
   verification before release, ERC-7730 proof/IR parsing, and exact ERC-7730
   gas/nonce rendering resisted the tested source and differential hypotheses.
   The strongest failed exploit attempts were the unconditional OPTIGA update
   bypass, a zero-key SCP03 rotation, CMSE reentrancy, and a direct byte-write to
   MPCBB control registers.
2. **What I did not do.** No irreversible option-byte burn, OPTIGA lifecycle
   transition, SE050 PUT KEY, destructive firmware update, physical memory
   extraction, logic-analyzer capture, real display-spoof experiment, voltage/
   clock glitch, or full multi-hour FI campaign was run. Kani's full nightly
   census and the two previously bounded ERC-7730 proofs were not rerun. No
   fresh LTO disassembly-level zeroization proof was produced. The five-second
   fuzz budget is only a startup/artifact smoke test. External ERC-8176 coverage
   is a dated observation, not a permanent fact.
3. **Snapshot reconciliation.** The sweep began before the Draft-1.1 rollback
   documentation/test branch was merged. The workspace advanced to clean
   `master` at `a248c3a1` during review. That merge changed documentation, CI,
   and rollback model tests—not the firmware paths cited above. All retained
   line references were reconciled to `a248c3a1`, and the key host/codegen/gate
   checks were rerun on that final snapshot.
4. **Reviewer provenance.** Three independent adversarial passes were asked to
   treat claims as anonymous and reproduce evidence before accepting it. The
   orchestration runtime does not expose enforceable model selection or a
   trustworthy model-identity attestation, so this report deliberately makes no
   claim that any pass was executed by a particular named model. Findings are
   accepted or rejected on reproducible repository/vendor evidence only.
