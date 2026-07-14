# PQ1 factory mass-production provisioning — tooling model

Status: **design** (2026-06-17). Supersedes nothing; extends the single-device
ceremony in [`factory-provisioning.md`](factory-provisioning.md) +
[`secure/src/factory_provisioning.rs`](../secure/src/factory_provisioning.rs)
toward a mass-production line that ships a device whose **dual-SE seed
invariant actually holds** ([[project_se_removal_invariant]]).

Decisions locked 2026-06-17:
1. OPTIGA shipping-state lockdown (S-1/S-2/S-3) is **folded into the ceremony**
   as new validated steps, ordered before the irreversible RDP2 bump.
2. S-2 trust anchor closed with a **PQ1 factory-HSM cert** (offline root;
   line carries the public cert only).
3. **No per-unit traceability** — the OTP sentinel is the only gate.

> **UPDATE 2026-07-14 (work-todo #36).** Decision 1's ordering survives but the
> **RDP2 bump leaves the line entirely**: devices ship at RDP-0 (batch-uniform,
> user-verifiable over SWD before first power) and the FSBL self-locks to
> RDP-2 on the first field boot, then self-provisions pairing keys
> (TRNG-salted rotation off factory-installed transport keysets). Fixture
> step 5 (`bump-rdp2-after-factory`) and the "sentinel → RDP2" gate below are
> superseded — the sentinel now gates *shipping*, not an RDP2 burn. The SE
> lockdown steps (5–8) stay at the line unchanged.

---

## 1. Why the current model isn't shippable for mass production

The existing 7-step ceremony provisions the MCU and **permanently locks it**
(`bump-rdp2-after-factory` → RDP=Level 2), but **none of its steps close the
OPTIGA ship-blockers**:

- **S-1** F1D0 `Change=ALW` — a desoldered OPTIGA can be re-keyed and PIN-brute-forced.
- **S-2** trust anchor at `0xE0E3` is the Infineon **public sample cert**
  (`tools/optiga_reset/out/trust_anchor_cert.bin`); its private key is public,
  so anyone can sign a `SetObjectProtected` manifest and bypass every Change AC.
- **S-3** soft counter instead of the E120 hardware counter.

Because RDP2 makes the MCU side unfixable in the field, a unit shipped today is
**permanently locked with the SE seed-protection invariant violated**. The
lockdown must happen at the line, before RDP2.

The primitives already exist (`provision_trust_anchor`, `optiga-lock-operational`
→ `build_metadata_auth_ref_luc` + `Change=Auto(F1D0)`, `optiga-hw-counter` E120
binding, `SetObjectProtected` CMD 0x83). The gap is purely orchestration: they
are not wired as ceremony steps, and the baked-in TA cert is still the sample.

---

## 2. Trust model — the line holds no secrets

Every per-device secret is **derived on-device** from silicon roots
(`SAES-CMAC(DHUK,·)` Tier-1, BHK Tier-2, OTP-master, UID-sealed HUK). The OTP
master is TRNG-burned idempotently on first boot (`otp::ensure_device_master`).
Nothing is injected per unit, so:

- **Every device flashes the identical firmware image.** No per-unit data file,
  no key-injection station, no HSM connectivity at the line.
- The **only** external key material in the whole model is the S-2 trust-anchor
  keypair, and only its **public cert** reaches the device (compiled into
  firmware, like any pinned root). The private key lives in an **offline HSM**
  and is used only for the one-time fleet root ceremony and for signing future
  refurbishment manifests.

This is the property that makes the line cheap to scale: provisioning is
embarrassingly parallel because units are interchangeable.

---

## 3. The extended ceremony (10 steps)

Add four SE-lockdown steps and re-order so the **SE point-of-no-return
(LcsO=Op) precedes wipe/validate**, and the MCU point-of-no-return (RDP2,
host-side) comes last. Each new step does a **read-back validation** before
returning `Ok`; reaching `WriteOtpSentinel` therefore proves all prior steps
verified (the existing `halt_with_failure` model gives the gate for free).

| # | `FactoryStep` | Action | New? | Err range |
|---|---|---|---|---|
| 1 | HardwareSelfTest | SAES Tier-1 + BHK Tier-2 | — | E01xx |
| 2 | OtpMasterKey | burn/verify OTP master | — | E02xx |
| 3 | PrePopulatedStateCheck | refuse non-fresh chip (E0301/E0702 reentry guard) | — | E03xx |
| 4 | DualSeProvisionInfrastructure | SCP03 rotate, PBS/E140, SE050 OIDs, dual-SE pair | — | E04xx |
| 5 | **OptigaS1AuthRef** | F1D0 `Change=Auto(F1D0)` (`build_metadata_auth_ref_luc`); read-back confirms AC | ✅ | E05xx |
| 6 | **OptigaS2TrustAnchor** | write PQ1-HSM TA cert → `0xE0E3`; lock/junk pool `0xE0E4..0xE0E8`; read-back cert hash | ✅ | E06xx |
| 7 | **OptigaS3HwCounter** | provision E120 LUC, bind F1D0 `Execute=LUC(E120)`, delete/freeze F1E1 soft counter | ✅ | E07xx |
| 8 | **OptigaLcsOpRatchet** | LcsO=Op on every touched OID — **SE no-take-backs line** | ✅ | E08xx |
| 9 | WipeUserState + PostWipeValidation | `factory_reset_admin`; confirm user state gone, admin reachable | — | E09xx |
| 10 | WriteOtpSentinel | clear `BIT_PRODUCTION`; sentinel now ship-eligible (post-#36: no RDP2 bump — unit ships at RDP-0) | — | E10xx |

Then host-side: read sentinel → box + ship at RDP-0. (Post-#36 the **MCU
no-take-backs line** moved to the device's first field boot — the FSBL
self-locks RDP-2; `bump-rdp2-after-factory` is retired.)

**Open validation item (must verify on silicon before this ships):** step 9
wipes user state *after* the LcsO=Op ratchet (step 8). Confirm `factory_reset_admin`
+ the F1Dx data-object clears still succeed under locked metadata — the F1Dx
data AC is `Conf(E140)` (independent of LcsO), so this *should* hold, but it is
load-bearing and must be proven on a real OPTIGA, not assumed. If it fails,
swap steps 8↔9 (wipe under Creation, then ratchet).

`FactoryStep::total()` becomes 10; the host-test that pins step/error/display
invariants (`cargo test -p sphincs-tz-secure factory_provisioning`) must be
extended in lockstep (the existing `total()==7` assert is the tripwire).

---

## 4. S-2 — the offline HSM root ceremony

Done **once per firmware lineage**, off the production floor:

1. **Root ceremony (offline HSM):** generate the PQ1 trust-anchor P-256 keypair
   inside the HSM. Private key never exported. Export the matching cert.
2. **Bake the public cert into firmware:** replace
   `tools/optiga_reset/out/trust_anchor_cert.bin` with the PQ1 cert and
   regenerate any pinned hash, exactly as a pinned root is handled today
   (cf. `ERC7730_DESCRIPTORS_ROOT`). A `compile_error!` fence rejects a
   production-irreversible build whose TA cert still hashes to the Infineon
   sample.
3. **At the line (step 6):** `provision_trust_anchor` writes the *public* cert
   to `0xE0E3` while the OPTIGA is still LcsO=Creation (authorized by the
   sample TA — fine, because the device is physically inside the trusted
   factory). The pool OIDs `0xE0E4..0xE0E8` are filled-junk/`Change=NEV`.
   Step 8 ratchets LcsO=Op, after which **only a PQ1-HSM-signed manifest is
   honored**. The field/desoldered attacker (the S-2 threat) has no usable
   manifest.

The HSM is therefore **not on the production line** — it is an offline asset
for (a) the one-time fleet root, (b) signing `SetObjectProtected` refurb
manifests for returned units.

---

## 5. Line orchestration

Because units are interchangeable (§2), the line is a fan-out of the existing
single-device flow, sentinel-driven so no operator watches each OLED:

```
for each station (probe-rs --probe <serial>):
  1. probe-rs download   <identical-image.elf>
  2. STM32_Programmer_CLI --optionbytes TZEN=1 ...
  3. probe-rs reset
  4. poll OTP sentinel @0x0BFA_00A0  (60s timeout)
       PRODUCTION_OK / BOTH_OK  -> step 5
       STARTED_FAILED           -> divert bin (read OLED step+code for vendor)
       DID_NOT_START / timeout  -> retry once, else divert bin
  5. box + ship at RDP-0       (post-#36: RDP=0xCC is self-programmed by the
                                FSBL on first field boot, never by the fixture)
```

- **Parallelism:** one fixture controller fans out N probe-rs invocations keyed
  by probe serial; same image to every station. No DB, no per-unit file.
- **OLED is the fallback channel**, not the gate — the host reads the sentinel
  over SWD. (Post-RDP2 the OLED becomes the only window, per the existing doc.)
- **Rehearsal build** must be extended to **dry-run steps 5–8 without committing
  LcsO=Op** (the ratchet is destructive on the OPTIGA). Today rehearsal already
  skips the destructive `provision()`/`factory_reset_admin`; extend the same
  skip to the new SE-lockdown commit so panel/layout iteration on dev OPTIGAs
  doesn't brick them.

---

## 6. Build-profile guards (extend the existing matrix)

The irreversible production profile must now also imply the SE lockdown and a
real TA cert:

| Feature combination | Result |
|---|---|
| `factory-provisioning` + `dev-testkey` | builds (dev/safe; SE lockdown SKIPPED) |
| `factory-provisioning,...-rehearsal` | builds (rehearsal; lockdown dry-run, no LcsO commit) |
| `factory-provisioning` w/o `optiga-lock-operational` | **compile_error** — production needs the ratchet |
| `factory-provisioning` w/o `optiga-hw-counter` | **compile_error** — S-3 mandatory (already specified) |
| TA cert == Infineon sample hash | **compile_error** — S-2 not closed |
| all above + `factory-production-irreversible-im-sure` | builds (real production) |

The opt-in remains a foot-gun guard, not a security gate.

---

## 7. Traceability — explicitly none (accepted)

Decided: no provisioning log, no attestation record, no label printing. The OTP
sentinel is the sole pass/fail gate. **RMA implication (accepted):** a returned
unit cannot be looked up against a factory record; the only refurb path is
vendor wipe-firmware → re-run ceremony (which requires an HSM-signed
`SetObjectProtected` manifest to re-open the LcsO=Op'd OIDs — see §4/refurb).
There is no cryptographic tie between a fielded unit and its factory run. If
this is later revisited, the natural minimal addition is a per-unit log row
keyed on the STM32 UID (`0x0BFA_0700`) + OPTIGA/SE050 UIDs read pre-RDP2.

---

## 8. Work breakdown (what to actually build)

1. `factory_provisioning.rs`: add steps 5–8 (`OptigaS1AuthRef`,
   `OptigaS2TrustAnchor`, `OptigaS3HwCounter`, `OptigaLcsOpRatchet`) with
   read-back validation + error codes; bump `FactoryStep::total()` to 10; update
   the host tests.
2. Resolve the **step-8-vs-step-9 ordering** question on real silicon (§3).
3. S-2 HSM root ceremony + cert-swap + `compile_error!` sample-cert fence (§4).
4. Extend rehearsal to dry-run the SE lockdown without the LcsO commit (§5).
5. Extend the build-profile guard matrix (§6).
6. Fixture controller for N-station fan-out (§5) — thin wrapper over the
   existing `make flash-hw-factory-provisioning` / `bump-rdp2-after-factory`.
7. Update `factory-provisioning.md` operator manual: 10 steps, new error codes,
   and the "FACTORY OK ⇒ SEs are LcsO=Op locked" guarantee.
