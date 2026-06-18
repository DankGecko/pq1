# PQ1 / PQSigner OS — EVT Red-Teaming Plan

**Status:** draft for the first EVT (engineering validation test) hardware build
**Target:** PQ1 hardware wallet — STM32U585 (Cortex-M33, TrustZone) + OPTIGA Trust M V3 + SE050, SPHINCS+C10-only, ERC-4337 v0.6
**Author:** generated from a codebase deep-dive (2026-06-12)
**Scope:** what to attack, how, with which instrument, and the pass/fail bar — once the EVT board is provisioned and bumped to RDP-2.

> This plan is the bench-attack companion to the existing paper audits in `docs/security/audits/`,
> `docs/security/security-review-2026-05.md`, and `docs/security/threat-model.md`. Those reason about the
> design; this document is about putting probes on copper and glitches on rails.

---

## 0. How to read this document

Each subsystem below is written as:

- **Property** — the security claim we are trying to falsify.
- **Test** — the concrete red-team action.
- **Instrument** — what gear actually measures it (this matters — see §3).
- **Pass / Fail** — the observable bar.
- **Status / caveats** — what's known-fixed, known-open, or untested on silicon.

A recurring theme: **a logic analyzer proves channel confidentiality, not secret quality.**
Anything encrypted-on-the-wire or internal-to-the-die (entropy, keys, PIN compare) is
invisible to passive bus capture *by design*; testing it needs a separate instrumented
build or a glitch/SCA rig. §3 makes this split explicit so tests are pointed at the right tool.

---

## 1. Device-under-test prerequisites

The EVT unit should be in the **shipping configuration** for most tests, because the point
is to attack what customers receive:

- `mode-production` (no `debug-log`, `e2e-test`, `mock-se`, `otp-hardcoded-master-key`, `ui-capture`).
- `dual-se` + `stm32u585` + `optiga-hw-counter` + `consumption-mask` + `tamp` + `tamp-wipe` + `tzic-wipe`.
- Both SEs provisioned with **device-unique** SCP03 / Shielded-Connection secrets (NOT the
  published NXP/Infineon factory defaults — see §5.1).
- OTP device-master burned; rollback floor initialised.
- **RDP-2 set** (SWD/JTAG permanently disabled, irreversible — do this last).

**Provision a second, sacrificial unit at RDP-0/1** for the tests that RDP-2 locks you out of:
raw-entropy statistical capture (§4.1), SWD-based counter manipulation (§6.3), and any
instrumented build that dumps per-source TRNG bytes. RDP-2 protects the device by locking out
exactly the introspection some of these tests need — so split the fleet by test goal.

**Expect to destroy parts.** Several high-value tests (desolder-OPTIGA, decap, OTP brownout)
are one-shot. Budget ≥3 sacrificial units beyond the RDP-2 "production-config" unit.

---

## 2. Threat model recap (what the attacker is assumed to have)

From `docs/security/threat-model.md`. The companion app and the entire Non-Secure (NS) world are
**fully attacker-controlled** — that is the *primary* surface and needs no physical access.
Physical attackers add: bus probing, glitch injection (voltage/clock/EM), decap, and chip
desoldering. The single-fault assumption is the design baseline; this campaign deliberately
also probes **two-fault** combinations, since most gates are now single-fault-hardened (§9).

Highest-value targets, in order:
1. The BIP-39 seed (reconstructed in S-SRAM) — breaks everything downstream.
2. Either entropy half (`half_O` on OPTIGA, `half_E` on SE050) **plus** a PIN brute-force path.
3. DHUK / OTP-master / SE channel keys — unlock the SE secrets.
4. A WYSIWYS gap — sign something the user didn't see (no key extraction required).

---

## 3. Instruments and what each can actually prove

| Instrument | Proves | Cannot prove |
|---|---|---|
| **Logic analyzer / scope on I²C1, I²C2, LCD SPI, USB** | Channel confidentiality (ciphertext + MAC on the wire), protocol sequencing, "no plaintext secret on any bus", timing of phases | RNG quality (entropy is encrypted or internal), key values, anything inside the die |
| **Instrumented RDP-0 build + entropy dump → NIST/AIS-31 suites** | TRNG statistical health, per-source independence | Nothing about the production-config device's runtime behaviour |
| **Voltage/clock/EM glitch rig (ChipWhisperer / NewAE Scaffold / EMFI probe)** | Fault-injection resistance (gate skips, sentinel bypass, counter rollback) | Confidentiality; needs the `sca-trigger` GPIO or a power-signature trigger to sync |
| **Power/EM CPA-DPA rig (current probe + scope + capture tooling)** | Side-channel leakage of WOTS/FORS secrets during signing | Logic-level behaviour; this is analog, not a digital LA |
| **Bench SE rig (desoldered chip on a breadboard with pull-ups + 3V3)** | Whether a removed SE defends itself standalone (OPTIGA S-1/S-2/S-3) | In-system behaviour |
| **USB host fuzzer (pyusb / WebHID companion)** | NS/gateway parsing robustness, TOCTOU, idle-timeout policy | Anything requiring physical access |

**Rule of thumb:** if the value you want to observe is supposed to be secret, the LA will
show you ciphertext or nothing — that's a *pass for confidentiality*, not a measurement of
the secret. Point a different instrument at the secret's quality.

---

## 4. Crypto core: RNG, seed, key derivation, FI

### 4.1 Seed-entropy RNG quality — **the headline RNG question**

**Property.** The "New Wallet" seed is full-entropy: `STM32 TRNG ⊕ OPTIGA GetRandom ⊕ SE050
GetRandom`, XOR-folded, fail-closed on any source error, all-zero rejected.
Path: `secure/src/rng_strong.rs` → `secure/src/rng.rs` → `secure/src/hw/rng.rs` +
SE fold in `secure/src/dual_se.rs::random()`. Consumed by the wizard at
`secure/src/main.rs` (`WizardChoice::NewWallet`).

**The LA cannot test this.** The STM32 TRNG never leaves the die; the OPTIGA/SE050 GetRandom
responses cross I²C **encrypted** under Shielded Connection / SCP03. On the production unit you
capture ciphertext, which looks random whether the underlying TRNG is healthy or stuck.

**Test (requires instrumented RDP-0/1 build).**
1. Build a diagnostic image that dumps, over UART/USB, the raw per-source streams **before**
   the fold: STM32-only, OPTIGA-only, SE050-only, and the folded output. (Seed from
   `tools/dev_fixture_keygen/` and the on-silicon `secure/src/se050_stress/tests/trng.rs`
   χ²/block-degeneracy probe, which already does this for SE050.)
2. Capture ≥10 MB per source. Run **NIST SP 800-22, Dieharder, `ent`**, and the **SP 800-90B /
   AIS-31** estimators. **Test each source independently** — the XOR masks a single biased
   source, so per-source testing is what catches it.
3. Confirm the STM32 silicon health monitors fire: perturb the RNG clock and confirm
   `SEIS/CEIS` latch and `hw::rng::fill` returns `Err` (fail-closed), per the recovery logic
   in `secure/src/hw/rng.rs`.

**Test (production unit, fail-closed behaviour).**
- Glitch one SE's I²C during a sign's `opt_rand`/seed draw and confirm the call **aborts loudly**
  (`rng_strong::fill` → `Err` → wizard shows "RNG failed, retry"), never silently degrading to
  fewer sources. `dual_se.rs::random()` requires *both* SEs.
- Induce a stuck-at-0 and confirm the all-zero acceptance gate in `rng_strong.rs` rejects.

**Pass.** Each source passes the statistical batteries standalone; any source fault aborts the
operation; all-zero is refused.

**Caveats / known gaps.**
- **Width/packing class (the Trail-of-Bits "short-sleeve RSA" bug) is NOT present** — the one
  risky transition (32-bit `RNG_DR` → byte buffer in `hw/rng.rs`) uses `to_le_bytes()` and
  copies all four bytes; the SE fold is byte-indexed. Re-verify after any refactor of that loop.
- **The all-zero gate does NOT detect a *structured* failure** (e.g. 3-of-4 bytes zero). RNG
  correctness here rests on the packing code being right, not on a runtime gate. This is the
  exact failure mode of the ToB bug — keep it in regression tests.
- **OPTIGA `get_random` silently truncates a short chip response** (`optiga/apdu.rs`
  `payload.len().min(out.len())`, caller discards the length) — a glitched/short OPTIGA reply
  leaves the tail of its contribution zero and still returns `Ok`, quietly dropping that byte
  range from 3 sources to 2 (STM32 ⊕ SE050). Output stays unpredictable (STM32 covers every
  byte) but it violates the documented strict "both-or-fail" semantics; the SE050 driver
  already guards this exact case. **Red-team action:** glitch OPTIGA to a short response, confirm
  whether bytes silently drop a source. *(Fix candidate: mirror the SE050 short-response check.)*

### 4.2 Dual-SE XOR seed split (Invariant #1)

**Property.** `half_O` on OPTIGA, `half_E` on SE050; neither chip alone reveals any bit.
Reconstruction `full = half_O ⊕ half_E` in S-SRAM with an FI cross-check (derive master, compare
to stored master with two constant-time compares). `secure/src/dual_se.rs` (provision + unlock).

**Tests.**
- **Single-chip extraction (destructive).** Decap/extract one chip's stored half; confirm it is
  uniformly random and yields zero information about the seed without the other half.
- **Reconstruction glitch.** Glitch the XOR or the master cross-check at unlock; confirm the
  sentinel-gated compare fails closed (no unlock on mismatch).
- **Bus check.** LA on both I²C buses during unlock: confirm neither half ever crosses to the
  *other* chip's bus, and neither chip ever receives the full entropy (Invariant #1).

**Pass.** One half is independent of the seed; mismatch → lockout; halves never co-mingle on a bus.

**Caveat.** The "single-chip break is harmless" claim only holds once the OPTIGA ship-blockers
(§5.4) are closed. Until then, a desoldered OPTIGA + shared-PIN brute-force cascades to defeat
SE050 and recover the full seed — see `project_se_removal_invariant` and `docs/security/threat-model.md`.

### 4.3 Key derivation (KDF tags, BIP-39 → C10)

**Property.** Deterministic, domain-separated derivation in `domain/src/lib.rs` (re-export shim
`secure/src/crypto.rs`). Bootstrap master is immutable per wallet; slot keys are chain-bound
(same `slot_index` on different `chain_id` → different keys). CREATE2 salt = `sha256(masterPkSeed‖masterPkRoot)`.

**Tests (mostly functional, on instrumented build).**
- Derive slot keys for `(chain=1,slot=0)` vs `(chain=2,slot=0)`; confirm they differ.
- Confirm Account 0 reproduces the legacy byte-for-byte derivation (KDF tags `"sphincs-c6-v1"` etc.).
- Confirm master secret never persists in plaintext flash/SRAM after lock (dump and search).

**Caveat (carry-over audit item H-1).** The entropy-blob AES-GCM nonce is *derived* from the
master secret, not random. Not a break (master differs per unlock), but verify the nonce changes
across unlocks; flagged for the next storage-format bump.

### 4.4 Signature FI hardening — verify-before-release (Invariant: never skip)

**Property.** Every Type-1/Type-2 sig is double-computed, byte-compared, then **verified before
release**, gated by FI sentinels, with a control-flow-integrity (CFI) counter over the critical
steps and a fresh `opt_rand` + shuffle seed per signature. `secure/src/fi.rs`,
`secure/src/crypto.rs` (`c10_sign_verified*`).

**Tests (glitch rig, use the `sca-trigger` GPIO to sync — note it is fenced out of production,
so run these on a `dev-testkey`/bench image, then re-confirm the gate exists in the prod binary).**
- Skip the double-compute / `ct_eq`; expect sentinel-gated reject.
- Skip the `verify(...)` call; expect the sentinel check to catch the missing verify.
- Fault the verify boolean to "true"; `black_box` + sentinel encoding should defeat a single
  register skip.
- Skip any single CFI step (rate-limit, opt_rand fill, shuffle, sign_a, sign_b, ct_eq,
  verify-gate); expect the final CFI sum mismatch to abort.
- **Two-fault:** skip both `ct_eq` and `verify`; this is the realistic attack and the design
  explicitly requires two coordinated faults.

**Pass.** No single fault releases an unverified signature; two-fault combinations do not either
within the timing window you can achieve.

**Side-channel (separate CPA/DPA rig).** Power/EM-probe a full SPHINCS+C10 sign (~1–3 s) and
attempt to recover WOTS/FORS secrets. Confirm `consumption-mask` (TIM2 PWM on PA5) is active and
that shuffle decorrelates traces. Note: the STM32 HASH peripheral is a timing accelerator, **not**
a DPA barrier — masking is the only SCA mitigation today.

---

## 5. Secure elements & channel security

### 5.1 SE050 SCP03 confidentiality — **closes the pending S-5 silicon item**

**Property.** SCP03 negotiated at `P1=0x33` (C-MAC + C-DEC + R-MAC + R-ENC); the response phase
is ciphertext + 8-byte R-MAC, so `half_E` is never plaintext on I²C2. `secure/src/se050/scp03.rs`,
`secure/src/se050/apdu.rs`. **This is the explicit "still pending" verification in CLAUDE.md.**

**Test (logic analyzer — this is the LA's sweet spot).**
- Capture I²C2 across a full unlock cycle (`read_authed(ENTROPY_OBJ)`).
- Confirm the **command** phase: header plaintext, body encrypted + C-MAC.
- Confirm the **response** phase: 8-byte MCV/R-MAC + ciphertext body + SW — **no `half_E`
  plaintext anywhere**. Decrypt offline with the session S-ENC key to prove the entropy is only
  recoverable with the session key.

**Pass.** Response is ciphertext + R-MAC; sweeping the whole capture finds no half_E / PIN / key
bytes. **This directly retires S-5.**

### 5.2 OPTIGA Shielded Connection confidentiality

**Property.** TLS-PRF + AES-128-CCM-8 over IFX I²C; PBS in flash page 126; application payloads
(half_O at F1D1, PIN-related OIDs) encrypted on I²C1. `secure/src/optiga/{shield,apdu,ifx_i2c}.rs`.

**Test (LA on I²C1).** Capture `establish()` + first encrypted GetDataObject. Confirm handshake
(MasterHello/SlaveHello) is the only plaintext; all post-handshake OID reads/writes are CCM
ciphertext. Sweep for `half_O`, PBS, AuthRef, PIN bytes — none should appear.

**Caveat / open.** The Shielded-Connection handshake (`MasterFinished`/`SlaveFinished`) has been
flaky on the bench (see `docs/secure-elements/optiga-bringup-status.md`); a full encrypted round-trip on real
silicon may still need to be confirmed. If the handshake doesn't complete, the LA test for §5.2
cannot run — fix the handshake first.

### 5.3 Three-way PIN-gating lockstep (Invariant #2)

**Property.** PIN compared in SE silicon only (never MCU). Three counters move in lockstep:
SE050 UserID (max 10), OPTIGA E120 LUC bound to F1D0, MCU page-124 (FI-hardened pre-commit in
`gated_unlock`). Boot reconciles to strictest; 10 wrong on any → admin wipe + page-124 erase.
`secure/src/nsc/mod.rs` (`gated_unlock`, `reconcile_pin_attempts`), `secure/src/hw/flash.rs`.

**Tests.**
- **10-wrong-PIN brick (functional, on a sacrificial provisioned unit).** Drive 10 wrong PINs;
  confirm all three counters advance together and the wallet bricks + admin-wipes both SEs.
  (`make pin-gate-wipe-e2e` is the QEMU analogue; do it on silicon here.)
- **Counter desync → tamper.** Externally reset MCU page-124 (SWD, RDP-0 unit) while the SE
  counters are non-zero; reboot; confirm the boot reconcile detects the mismatch and wipes.
- **Glitch `gated_unlock` pre-commit.** Glitch to skip the page-124 bump or flip the verdict;
  confirm the FI sentinels + double-read counter + FihBool `pin_verified` fail closed (single
  fault insufficient).
- **No software compare.** LA confirms the PIN bytes go *to* the SE and only a verdict returns —
  the MCU never compares the PIN.

**Pass.** Counters stay in lockstep; desync wipes; no single fault unlocks; PIN never compared in MCU.

**Caveat (audit MEDIUM, verify on silicon).** The boot reconcile path reads an OPTIGA counter via
`read_counter_raw` (`secure/src/optiga/mod.rs`); the pin-unlock-lockstep audit flagged that under
some build configs it reads the **soft** counter (F1E1), not the **hardware** E120 LUC, which would
make the three-way reconcile a no-op and risk false-positive wipes. **Explicitly confirm on the EVT
which counter is read with `optiga-hw-counter` on**, and that a real desync triggers the wipe.

### 5.4 OPTIGA shipping-state lockdown — **S-1 / S-2 / S-3 ship-blockers**

These are the **biggest open hardware-security items** and the highest-confidence physical attack
chain. All three must close before any device ships; the EVT is where you *prove the attack* (on a
pre-fix unit) and later *prove the fix* (on a locked unit). See `docs/production-todo.md` and the
ship-blocker section of `docs/work-todo.md`.

- **S-1 — F1D0 `Change = ALW`.** A desoldered OPTIGA lets a bench attacker overwrite F1D0 with a
  chosen HMAC key, self-auth, reset E120, and brute-force PINs unbounded. (`secure/src/optiga/apdu.rs`.)
- **S-2 — Trust anchor at `0xE0E3` is Infineon's PUBLIC sample cert.** The matching private key is
  public; anyone can sign a `SetObjectProtected` manifest that bypasses every `Change` AC — *including
  any S-1 fix*. **S-1 alone is insufficient; S-2 must close simultaneously.** (`secure/src/optiga/reset.rs`.)
- **S-3 — `optiga-hw-counter` must be mandatory.** Without the E120 hardware counter, a
  PBS-leaking/desoldered attacker gets unbounded HMAC attempts.

**Test (desolder a sacrificial OPTIGA onto a bench I²C rig).**
1. `GetMetadata(0xF1D0)` → confirm `Change` AC (pre-fix: `ALW`; post-fix: `Auto(F1D0)` + LcsO=Op).
2. Attempt to overwrite F1D0 with a chosen key with no auth → must **fail** on a fixed unit.
3. Sign a `SetObjectProtected` manifest with the Infineon sample key against `0xE0E3` → must
   **fail** on a fixed unit (TA replaced with a PQ1-HSM cert or removed; spare OIDs locked).
4. Confirm `optiga-hw-counter` is compiled in (the `compile_error!` fence in `nsc/mod.rs` is
   present — see §10) and that the E120 LUC, not the F1E1 soft counter, bounds attempts.

**Pass.** On the shipping-config unit: F1D0 is not overwritable, the sample-key manifest is
rejected, and PIN attempts are hardware-counter-bound. **Until then this is the #1 EVT finding to
reproduce and then re-test after the fix.**

**Verify the fences actually cover S-1.** `nsc/mod.rs` carries many `compile_error!` ship-blocker
fences (hw-counter, derived-scp03, tamp-wipe, consumption-mask, debug features). The lockstep audit
noted that **S-1's `optiga-lock-operational` may not be compile-fenced** — i.e. a production build
could theoretically ship with `Change=ALW`. Confirm at build time: try a `mode-production dual-se`
build *without* the lockdown feature and check whether it compiles. If it does, that's a gap to close.

### 5.5 SE050 UserID provisioning (S-6 / S-7)

**Property.** Admin cannot delete-and-substitute the user UserID (S-6 fixed: user UserID's
admin-delete policy is `None`); `max_attempts=0` is rejected for the user PIN (S-7a). Data objects
keep the admin-delete (DoS-wipe) path. `secure/src/se050/mod.rs`, `docs/secure-elements/se050-userid-pin-auth.md`.

**Tests.**
- From an admin session, attempt `delete_object(USERID_OBJ)` → must fail (`SW≠Ok`; expect `0x6986`).
- Attempt to create a user UserID with `max_attempts=0` → must fail `InvalidParam`.
- **S-7d silicon item (still open):** drive a UserID to `auth_attempts == max_attempts`, send
  VERIFY, **capture the actual SW from the chip** with the LA, and confirm the firmware's
  `AuthMethodBlocked` mapping matches empirically (the code assumes `0x6986`).

**Pass.** Substitution attack structurally closed; empirical lockout SW matches the firmware mapping.

### 5.6 Factory SCP03 / pairing secrets are device-unique

**Property.** Production must derive SE channel keys from the device's hardware-unique secret
(`se050-derived-scp03`, SAES-CMAC(DHUK)/HKDF in `secure/src/hw/secret_keys.rs`), **not** the
published NXP AN12436 / Infineon sample keys.

**Test.** Read the provisioned device's SCP03 keys are not the published constants (confirm
`se050-scp03-allow-factory-fallback` is fenced out; the establish must succeed with derived keys
and never fall back). On two different units, confirm the channel keys differ.

**Pass.** Channel keys are per-device and non-public.

---

## 6. Platform isolation, boot, tamper, OTP

### 6.1 TrustZone / GTZC peripheral isolation (Invariant #4)

**Property.** AES/HASH/RNG/PKA/SAES + I²C1/I²C2 are SECURE; USB OTG is NS. NS access to a secure
peripheral RAZ-faults and bumps `hw::tzic::VIOLATION_COUNT`. `secure/src/sau.rs`. **Silicon-validated
2026-05-20** (`make gtzc-enforcement-hw` PASSED 7/7; USB still enumerates as `1209:7051`).

**Tests.**
- **Re-run `gtzc-enforcement-hw` on the EVT** — confirm all 7 secure peripherals RAZ-fault on NS
  access and the violation IRQ fires (1 per probe). This is a regression gate, not new work.
- **Glitch the SAU/GTZC config write at boot** and confirm enforcement still holds (or boot aborts).
- Confirm USB still enumerates with the GTZC config live.

**Pass.** 7/7 RAZ-faults; USB enumerates.

**Open follow-up.** **TAMP lives in GTZC2** and its SECCFGR wiring is a documented follow-up
(`sau.rs`). Confirm the TAMP path's isolation separately (§6.3).

### 6.2 Measured boot / FSBL fingerprint

**Property.** FSBL (WRP1A-locked, immutable) and the secure world independently render the **same**
8-word BIP-39 fingerprint for the active slot; divergence ⇒ the slot is lying ⇒ tamper.
`secure/src/measured_boot.rs`, `fsbl/`, `docs/security/measured-boot.md`.

**Tests.**
- Corrupt the secure image in flash (glitch a write, or a malformed `CMD_FW_CHUNK`); reboot;
  confirm the rendered fingerprint changes (tamper detectable by comparison).
- LCD-SPI capture during the fingerprint render: confirm the 8 words shown on the OLED match the
  SPI bus exactly (no hidden/extra content), and constant-time word lookup (`word_bytes_at`).

**Pass.** Divergence is visible; display bus matches the screen.

**Known gaps (from `docs/security/audits/boot-fsbl-*.md`).**
- **The shipping build is currently MONOLITHIC** — the FSBL is built but not actually flashed/booted;
  A/B slotting reads as live in code but is aspirational. Confirm the EVT's real boot path.
- **Divergence detection is HUMAN-ONLY** — there is no automated on-device comparator between the
  FSBL row and the secure-world row. A user who doesn't compare gets no protection. Note this as a
  residual; an automated comparator is open work.
- MEDIUM-1 (fingerprint base now derived from `__vector_table`, not hardcoded `FLASH_BASE`) is fixed
  (commit `fa9345d6`) — regression-check it survived.

### 6.3 Tamper response (TAMP + TZIC intrusion wipe)

**Property.** On a confirmed tamper, production dual-SE images escalate to
`tzic::trigger_intrusion_wipe` (zeroize SRAM, arm page-125 wipe flag, reset → boot-time wipe
finishes SE factory_reset + page-124 erase). Forced ON via the `nsc/mod.rs` fence
(`tamp` + `tamp-wipe` + `tzic-wipe`). `secure/src/hw/tamp.rs`, `secure/src/hw/tzic.rs`.

**Tests (glitch / physical).**
- **ITAMP9 (crypto-peripheral fault) canary.** Glitch SAES/AES/PKA/TRNG during a crypto op; confirm
  the tamper flag sets and — on the production image — the wipe fires (a single glitch costs the
  attacker the whole secret state). On a bench (`tamp-wipe` off) it's log-only — confirm that too,
  so you understand the dev-vs-prod difference.
- **ITAMP1 (brownout/voltage).** Inject a VDD/backup-domain transient; confirm ITAMP1 fires.
- **ITAMP6 (SWD at RDP>0).** On an RDP-1 unit, attempt SWD; confirm ITAMP6 fires. On RDP-2, confirm
  the programmer is hardware-refused.
- **TZIC NS→S illegal access** → confirm it routes to the same wipe escalation.

**Pass.** Tamper events fire their flags; production image escalates to an irreversible wipe;
attacker does not get unbounded glitch attempts.

**Caveat.** Tune false-positive sensitivity: a too-trigger-happy ITAMP9 under a noisy bench supply
could brick units during legitimate validation. Characterise the threshold on the EVT.

### 6.4 OTP rollback floor / anti-brick (one-way)

**Property.** One-way OTP tally; floor only increases; firmware downgrade rejected. Floor =
`fw_version - 1` (anti-brick, commit `2d5733a1`). Device-master burned once, readback-verified.
`secure/src/hw/otp.rs`.

**Tests.**
- Install vN (floor → N-1); replay an older signed manifest → must reject at `FW_BEGIN`.
- Reinstall vN (floor stays N-1) then v(N+1) (floor → N) — confirm each boots (no brick).
- **Brownout during OTP write** (sacrificial): glitch power mid-QW-write; confirm readback-mismatch
  detection and the idempotent re-burn path on next boot (or the designed brick state — confirm which).

**Pass.** No downgrade; no off-by-one brick; partial writes detected.

### 6.5 SAES / DHUK key derivation (Tier-1 KDF)

**Property.** DHUK never appears in CPU-visible memory; subkeys via SAES-CMAC(DHUK). Self-test:
SW-key round-trip + DHUK≠SW domain separation + DHUK round-trip. `secure/src/hw/saes.rs`,
`saes_cmac.rs`, `secret_keys.rs`, `huk.rs`.

**Tests.**
- `make saes-self-test-hw`: confirm PASS + a stable DHUK fingerprint across reboots.
- Glitch the `SR.KEYVALID` gate / CCF completion during a DHUK op; confirm bus-error/timeout and
  (if enabled) ITAMP9.
- Confirm page-126 (PBS) and the BHK page read as ciphertext off a desoldered MCU (DHUK-sealed).

**Pass.** Self-test passes; DHUK never materialises in readable memory; glitch faults are caught.

**Caveat.** Confirm whether production `secret_keys` call sites are actually routed through
SAES-CMAC(DHUK) yet, or still on the legacy OTP-master+HKDF path (the SAES path landed behind a
feature gate; the flip is tracked work). Test whichever is live in the EVT image.

### 6.6 RDP-2 / debug lockdown + feature gating

**Property.** RDP-2 disables SWD/JTAG (irreversible). The `compile_error!` fences in `nsc/mod.rs`
forbid `debug-log`/`e2e-test`/`mock-se`/`otp-hardcoded-master-key`/`ui-capture`/`ui-semihosting`/
`uart-console`/`sca-trigger`/etc. on production. `docs/security/HARDENING.md`.

**Tests.**
- On the RDP-2 unit, attempt SWD/JTAG attach → hardware-refused.
- **Build-time:** attempt a `--release stm32u585` build with each forbidden feature → must
  `compile_error!`. (This is a CI gate; re-confirm on the exact EVT image's feature set.)
- Confirm the shipped binary contains no semihosting/UART debug strings (grep the ELF).

**Pass.** Debug ports dead; forbidden features don't compile into production; no debug strings ship.

### 6.7 Consumption mask / SCA jitter

**Property.** TIM2 CH1 PWM on PA5, xorshift-randomised duty, seeded from `rng_strong`; mandatory in
production (fence). `secure/src/hw/consumption_mask.rs`.

**Tests.** Scope PA5 — confirm the duty varies and is uniformly distributed (no PRNG bias). Run the
CPA/DPA campaign of §4.4 with the mask on vs off and quantify the decorrelation. Glitch the seed
draw at init and confirm the mask doesn't get stuck.

**Pass.** Mask is active, unbiased, and measurably raises the CPA trace count.

---

## 7. Clear-signing / WYSIWYS (no key extraction needed)

Core property: every signable artifact is decoded and rendered in S-world before confirm; the
companion can never substitute a hash or hide intent for a known shape. Many gaps here were
recently fixed — the EVT job is to **regression-test the fixes with real malicious payloads over USB**
and confirm true intent renders or it falls *loudly* to blind-sign.

### 7.1 Native-value invariant (CRITICAL class — fixed)

A `call{value}` must always render a "! NATIVE ETH" page. Fixed via dispatcher-level
`enforce_native_value_page` in `secure/src/tx/display/mod.rs` (commit-era fix
`project_erc20_unknown_hidden_value`). **Test:** drive non-zero `tx.value` through *every* renderer
(value transfer, erc20 known/unknown, blind, Safe, ERC-7730, typed-call, batch) and confirm the
value page appears each time. **Pass:** no path hides native value.

### 7.2 Safe SafeTx clear-sign

- **Refund block (HIGH — fixed):** non-zero `gasToken`/`gasPrice`/`refundReceiver` must render a
  loud 2-page refund block (`project_safe_refund_wysiwys_gap`). Craft a token-refund SafeTx; confirm.
- **multiSend (`0x8d80ff0a`) has no on-device decoder** — must fall to **loud blind-sign**, never a
  silent benign render. Craft a multiSend batch; confirm the blind banner + calldata hash + `to`.
- **Safe-wrapped CoW pre-sign:** confirm the order binds to `orderUid.owner == the Safe` and renders
  Safe context + full order intent. `secure/src/tx/eip712/safe/cow_binding.rs`.

### 7.3 CowSwap ZK proof binding — **check the byte-pack forgery status**

The Groth16 path attests the displayed order matches the signed payload. **Two CRITICAL forgeries
were found here:** the amount-overflow forgery (`project_cowswap_zk_amount_overflow`, fixed
2026-06-10) and the **byte-pack non-binding** forgery (`PackBytes31` lacking `Num2Bits(8)` →
display-vs-signed divergence). The amount-overflow fix is in; **confirm the byte-pack fix landed on
the EVT image** — `secure/src/zk/`, circuits, and the VK/`VK_DB_ROOT` must all be the
range-checked versions. **Test:** attempt to build a proof where displayed order ≠ canonical order
with out-of-range witness bytes; witness generation must fail the `Num2Bits` constraint, and the
firmware cross-check in `cowswap/verify.rs` must reject a mismatched canonical/readable pair.
**Pass:** no benign-display/malicious-sign proof verifies. *(If the VK on the EVT predates the fix,
this is a CRITICAL finding — the memory `project_cowswap_zk_bytepack_nonbinding` is the reference.)*

### 7.4 ERC-7730 / typed-call

- Walker slot-confusion and tuple-member completeness were fixed (`project_erc7730_walker_slot_confusion`,
  `project_erc7730_tuple_member_completeness_gap`; root regen `…→d510982a`). Confirm the descriptor
  root on the EVT matches the fixed build. Craft a descriptor that signs a tuple member without
  showing it → dbgen completeness lint should make this un-buildable; on-device walker bounds should
  reject hazardous paths and fall to blind-sign.
- Typed-call ABI parser caps (`MAX_ARGS`, nesting, arena): exceed each → must fall to blind-sign.

### 7.5 Off-chain (EIP-1271 / ERC-6492) domain separation

The raw32 UserOp-forgery (CRITICAL) is fixed by on-device `replay_safe_hash` nesting for kind=0/2
(`project_offchain_raw32_userop_forgery`). **Test:** request RAW32 over `sphincsDigest(drainOp)` and
confirm the firmware nests it (so the signed value is structurally disjoint from any on-chain
`sphincsDigest`) and shows a loud blind page. Also retest the `account_deployed` FI-OOB fix
(`project_offchain_account_deployed_fi_oob`): glitch the deployed/counterfactual size selector and
confirm no OOB write across the NS/secure SRAM boundary.

### 7.6 Paymaster authorization — **open MEDIUM to confirm on silicon**

Only the **SHA-256 of `paymasterAndData`** crosses the wire (`cmd_sign_userop.rs` offset 244..276);
the firmware never decodes or renders the paymaster address/selector. A malicious companion that
relies on a pre-existing paymaster allowance could, in principle, substitute `paymasterAndData` to
redirect gas/allowance, bounded by the displayed worst-case-fee cap and any existing allowance.
**Test:** with a real ERC-20 paymaster and a pre-existing allowance, confirm whether the device ever
shows a paymaster page (it doesn't today) and whether a substituted paymaster within the fee cap can
divert funds on-chain. **This is the one clear-sign item still worth a fresh on-device + on-chain
investigation.**

### 7.7 LCD/OLED trusted-display bus

LA on the LCD SPI during high-value signs: confirm every rendered character appears on the bus and
**no secret** (PIN, mnemonic word, key) ever crosses the display bus. Confirm seed-wizard decoy
mnemonics and PIN entry don't leak via timing or render order.

---

## 8. NS gateway, USB, firmware update, counters

### 8.1 NSC gateway / NS pointer validation (Invariant #4)

**Property.** `NsPtr<T>` typestate forces validation before deref; checks are null/bounds/overflow/
range/mailbox-exclusion, plus the ARMv8-M `TT` instruction for live SAU classification; double-
validated with `wait_random` between and sentinel-gated (HIGH-1 hardening). NS buffers copied to
S-stack before parse. `secure/src/nsc/{ns_ptr,ptr_validate,mod}.rs`.

**Tests (USB fuzzer + glitch rig).**
- Fuzz every `cmd_*` handler with null, just-below-base, arithmetic-wraparound, secure-straddling,
  and mailbox-overlapping pointers → all must reject with `InvalidPointer`, none deref.
- TOCTOU: flip the SAU classification mid-validation (RDP-0 unit) → second TT must catch it.
- Glitch a single validation sentinel → second sentinel + register scrub should hold (two faults
  required).

**Pass.** All malformed pointers reject; no single-fault deref of a secure/NS-straddling pointer.

### 8.2 USB protocol robustness

**Property.** APDU-v2 over HID (`CLA=0xF0`), command/response chaining up to 8192 B; OTG forced
device-mode, SOF interrupt masked (USB timing side-channel). `nonsecure/src/usb/`,
`docs/companion/usb-protocol-v2.md`.

**Tests.** Oversized (>8192) APDUs, malformed chaining (stale partial reassembly), response-drain
races → graceful reject, no overflow/DoS. Glitch the OTG `FDMOD`/SOF-mask config writes → confirm
the device doesn't fall into host mode or re-open the SOF side-channel.

### 8.3 Firmware update replay / rollback

**Property.** 75-byte signed preimage `"PQFW_V1"‖version‖secure_hash‖nonsecure_hash`, SPHINCS+C10
vendor sig, FI-sentinel-wrapped verify, OTP rollback floor, PIN required on every FW command
(STATUS/ABORT now gated too, LOW-1 fix). `secure/src/fw_update/`, `fw-manifest/`, `fwsign/`, `fsbl/`.

**Tests.** Replay an old signed manifest (reject at BEGIN); downgrade (reject); single-fault glitch
the verify (sentinel double-eval requires two faults); abort mid-stream + idle-wipe and confirm the
boot-state TRIED/COMMITTING flags pick a safe slot; corrupt a staged chunk and confirm COMMIT's
re-hash rejects it.

**Pass.** No replay/downgrade/single-fault-bypass installs unsigned or old firmware.

### 8.4 Off-chain counters / combined cap (Invariants #7, #9)

**Property.** Page-123 log-structured per-slot counter; `MAX_OFFCHAIN_GAP=100`; combined cap with
on-chain uses; monotonic, unresettable. `secure/src/offchain_state.rs`.

**Tests.** Exhaust the gap (101st unbacked sig rejects); exceed the combined cap; **glitch a
counter flash write + power-cycle** and confirm the page-123 self-heal no longer bulk-erases live
counters (HIGH-1 fix `6041f07a` gates the erase on `has_live_entries`) — i.e. a fault can't roll all
slot budgets back to zero. Confirm a network-retry of the same off-chain request yields a *different*
monotonic count (replay-evident).

**Pass.** Caps enforced; no fault rolls counters back; counts are monotonic.

### 8.5 Inactivity timeout / signing window

**Property.** 120 s S-only TIM timeout; NS pings do **not** reset it; `HandlerGuard` prevents the
idle-wipe ISR from zeroizing SRAM while a long sign holds stack copies. `secure/src/timeout.rs`.

**Tests.** Loop `GET_REMAINING` from NS during the window → timeout must still fire at 120 s. Glitch
the `HandlerGuard` depth check during a multi-second keygen → confirm the ISR doesn't wipe mid-sign
(would corrupt the derivation). Confirm continuous *signing* legitimately extends the window (by
design).

---

## 9. Fault-injection primitives — coverage map

The codebase is single-fault-hardened across critical gates; the realistic threat is **two
coordinated faults**. Prioritise these combinations on the glitch rig:

| Target | Single-fault defense | Two-fault test |
|---|---|---|
| `gated_unlock` verdict | F-15 double-read counter + FihBool `pin_verified` + sentinel | Skip bump *and* force verdict sentinel |
| NS pointer validation | F-8 double-validate + `wait_random` + sentinel + register scrub | Skip 2nd validate *and* stale OK_SENTINEL |
| Signature verify-before-release | double-compute + verify-gate sentinel + CFI counter | Skip `ct_eq` *and* `verify` |
| FW signature verify | `check_true_into_sentinel` double-eval | Skip verify *and* force sentinel |
| Counter monotonicity | F-12 forward+reverse scan readback | Corrupt write *and* glitch readback |
| Rate limiter (F-17) | SysTick min-delay | Zero the timer *and* skip the wait |

`secure/src/fi.rs` is the primitive library (sentinels, `wait_random`, CFI counter,
`zeroize_barrier`). Use the `sca-trigger` GPIO on a bench image to sync captures, then re-confirm the
gate exists in the production binary (the trigger itself is fenced out of production).

---

## 10. Ship-blocker verification checklist (build + bench)

Confirm on the actual EVT image / unit:

- [ ] **S-1** OPTIGA F1D0 `Change ≠ ALW` (Auto(F1D0) + LcsO=Op); desolder-overwrite fails. **And** a
      `compile_error!` fence requires the lockdown feature in production (verify it isn't missing).
- [ ] **S-2** `0xE0E3` TA is a PQ1-HSM cert or removed; Infineon-sample-key manifest rejected; spare
      OIDs locked.
- [ ] **S-3** `optiga-hw-counter` compiled in (fence present); E120 LUC (not F1E1) bounds attempts.
- [ ] **S-5** SE050 SCP03 response is ciphertext + R-MAC on I²C2 (LA-confirmed) — **retire the
      pending item**.
- [ ] **S-6** Admin cannot delete-substitute the user UserID (`SW=0x6986`).
- [ ] **S-7d** Empirical lockout SW matches the `AuthMethodBlocked` mapping (LA-captured).
- [ ] **Channel keys** are device-unique (not published NXP/Infineon defaults); fallback fenced out.
- [ ] **GTZC** 7/7 RAZ-fault (`gtzc-enforcement-hw`); USB enumerates; TAMP/GTZC2 isolation confirmed.
- [ ] **Tamper** `tamp`+`tamp-wipe`+`tzic-wipe` active; ITAMP9 escalates to wipe.
- [ ] **Consumption-mask** active and unbiased; measurably raises CPA trace count.
- [ ] **Debug** RDP-2 set; forbidden features `compile_error!`; no debug strings in the ELF.
- [ ] **Boot** confirm monolithic-vs-A/B reality; note the human-only fingerprint comparison gap.
- [ ] **CowSwap ZK** the byte-pack range-check fix (`Num2Bits`) and matching VK/`VK_DB_ROOT` are on
      the EVT image.

---

## 11. Suggested campaign phasing

**Phase 0 — bring-up & non-destructive (days 1–3).**
Run the existing on-silicon self-tests (`gtzc-enforcement-hw`, `saes-self-test-hw`, the SE050 TRNG
stress probe, `pin-gate-*-e2e`). LA-capture the SCP03 and Shielded-Connection channels (§5.1, §5.2 →
retire S-5). USB-fuzz the gateway (§8.1–8.2). Craft the WYSIWYS malicious payloads (§7) over WebHID.

**Phase 1 — entropy & functional crypto (days 3–6).**
Instrumented RDP-0 build: raw-entropy capture → NIST/AIS-31 per source (§4.1). KDF/slot-binding and
counter-cap functional tests (§4.3, §8.4). Firmware replay/downgrade (§8.3).

**Phase 2 — destructive physical (days 6–10).**
Desolder-OPTIGA S-1/S-2/S-3 chain (§5.4) — the headline. Decap for single-half extraction (§4.2).
OTP brownout (§6.4). These consume sacrificial units.

**Phase 3 — glitch & SCA (days 10–15, needs the rig).**
Two-fault campaign per §9 (gated_unlock, pointer validation, sign verify, FW verify). CPA/DPA on
signing with mask on/off (§4.4, §6.7). Tamper-canary glitches (§6.3).

**Phase 4 — synthesis.**
File each confirmed finding against the ship-blocker checklist (§10); re-test every fix on a freshly
locked unit before sign-off.

---

## 12. References

- Invariants & threat model: `docs/security/threat-model.md`, `README.md`
- Audits: `docs/security/audits/{crypto-core,fault-injection,pin-unlock-lockstep,counter-replay-state,boot-fsbl,gateway-parsing,wysiwys-clearsign,sig-domain-separation}-*.md`
- Security review + ship blockers: `docs/security/security-review-2026-05.md`, `docs/production-todo.md`, `docs/work-todo.md`
- SE bring-up: `docs/secure-elements/optiga-bringup-status.md`, `docs/secure-elements/optiga-brick-postmortem.md`, `docs/secure-elements/se050-userid-pin-auth.md`, `docs/secure-elements/se050-stress-harness.md`
- Hardening / boot: `docs/security/HARDENING.md`, `docs/security/measured-boot.md`, `docs/firmware/reproducible-builds.md`
- Known-vuln write-ups: `docs/VULN-*.md`, `docs/PROOF-*.md`
- Stress / fixtures: `secure/src/se050_stress/`, `tools/dev_fixture_keygen/`

> **Line-number note.** File paths in this plan are reliable; specific line numbers drift with the
> tree — confirm against the current source when you sit down at the bench.
