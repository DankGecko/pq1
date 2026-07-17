# First-boot self-provisioning (on-device) — work-todo #36

Status: **candidate implemented (`rdp2-self-lock`); not production-approved;
silicon and protocol-closure gates pending** (2026-07-15).

> **CANDIDATE RUNBOOK, NOT AN IRREVERSIBLE CEREMONY.** This document describes
> the current code and its intended factory/device boundary. It does not
> authorize RDP, OTP, SE-key, or OPTIGA lifecycle changes. The authenticated
> per-unit transport handoff/receipt, authenticate-before-rotate rule,
> old/new/KVN recovery proof, exact E140 order, and silicon receipts remain
> OPEN. Follow `docs/planning-and-review-workflow.md` §11 for any future
> owner-authorized hardware attempt.

Devices ship at **RDP-0** with a batch-uniform image (user-verifiable over SWD
before first power). The **first field boot** verifies the ship state,
self-locks the MCU to **RDP Level 2**, and rotates the secure-element pairing
secrets off the factory-installed **transport** keysets to their final
device-unique values — all **before the first PIN entry and before the seed
wizard**. This document is the operator/field-diagnosis reference for that
flow; the design decision record is `docs/work-todo.md` §36.

Owner amendment (2026-07-14): #36's text places the RDP-2 self-lock in the
FSBL, but it is implemented in the **secure app early-boot** (`secure/src/
first_boot/`) because the FSBL is at ~99 % of its 32 KB WRP1A budget. The FSBL
only branches into signature-verified slots, so "verify slots before lock"
holds structurally; the transit-reflash residual is identical either way. The
lock code can migrate into the FSBL later when the Draft-0.9 flash-map
reshuffle happens anyway.

---

<a id="authoritative-factory--first-boot-responsibility-split"></a>
## Candidate factory ⇄ first-boot responsibility split

This boundary is the current candidate realization of the #36 split. It is
mirrored verbatim in `docs/provisioning/factory-provisioning.md` and
`docs/factory-mass-production-model.md`; if you change one, change all three.

### Done at the FACTORY (RDP-0, on the production line, under read-back QA — no secret exists on the MCU yet)

- Flash the reproducible batch-uniform image (FSBL + secure + NS app into the
  A/B slots).
- Set the shipped option-byte profile: **TZEN=1, SECWM1/2, SECBOOTADD0, WRP1A
  on FSBL pages 0–3, BOR_LEV, BOOT_LOCK/nBOOT, OEM-key finalization —
  everything EXCEPT RDP.** RDP stays **0**. There is no RDP-2 burn anywhere at
  the factory.
- Burn the per-device **OTP master** (`otp::ensure_device_master`, TRNG). This
  must be a factory step: the initial two-QW burn is not crash-retry-safe, and
  it is the RDP-invariant root of every transport keyset.
- Provision **SE-internal structure + irreversible locks on transport
  keysets** (transport keys = HKDF over the OTP master, public-by-assumption):
  - **SE050:** create the admin UserID + user-object OID structure/policies;
    rotate the SCP03 keyset from the AN12436 defaults to the **transport**
    keyset (GP `PUT KEY` under `PLATFORM_DEK`); transport lock if applicable.
  - **OPTIGA:** write the **transport PBS** to E140 (metadata keeps the
    `Conf(E140)` arm so the PBS stays shield-rotatable); F1D0
    `Change=Auto(F1D0)` (S-1); PQ1-HSM trust-anchor cert at 0xE0E3 + neutralize
    the TA-pool 0xE0E4..0xE0E8 (S-2); provision the E120 LUC + bind F1D0
    `Execute=LUC`, freeze the F1E1 soft counter (S-3); **LcsO=Op ratchet** on
    the locked OIDs — the SE point-of-no-return.
  - The #22 attestation/binding manifest burn (when it lands).
- Read-back QA over SWD (connect-under-reset) against the reproducible build —
  encouraged, deliberately **not** load-bearing.
- Ship at **RDP-0** with SWD + NRST pads accessible. The only SE pairing
  material in existence is the public transport values.

### Done AT THE USER'S HOME on the first field boot (this flow; before PIN entry, before wallet creation)

- **Phase A (pre-lock):** verify the option-byte ship profile + OEM-locks-clear
  + blank per-device pages 123–127 → show "FIRST BOOT / DO NOT POWER OFF" →
  **program RDP=0xCC → reset.** This is the MCU point-of-no-return, moved off
  the factory line onto the user's device.

  > **UPDATE 2026-07-17 (owner design decision) — Phase A must be
  > CONFIRM-GATED.** The RDP=0xCC burn must not run automatically on first
  > power. Before it, the trusted UI shows "Confirm to lock device — after
  > that verification over SWD not possible anymore." and waits for a
  > deliberate on-device button sequence; until confirmed the device stays at
  > RDP-0, fully re-verifiable, touches no SE/USB/journal state, and every
  > boot re-enters the same prompt. This means accidental or transit
  > power-ups no longer destroy verifiability (today merely powering the
  > board self-locks it), and an attacker who confirms the lock in transit
  > only produces a unit that arrives locked → fails the unboxing
  > verification → returned (no seed exists yet). Not yet implemented —
  > current code runs Phase A unconditionally right after `ui::init()`.
  > User-side procedure this serves:
  > [`../security/user-device-verification.md`](../security/user-device-verification.md).
- **Phase B (post-lock, per-die DHUK now live), journaled + resumable:**
  - **BHK first-write** (TRNG → DHUK-ECB page 126; anti-pre-plant
    erase-and-reprovision).
  - **SE050 SCP03** rotation transport → **final (BHK-rooted)** via GP
    `PUT KEY` (key blocks wrapped under the transport DEK), two-phase confirm.
  - **SE050 admin credential** re-key transport → **final (BHK-rooted)**,
    delete + recreate.
  - **OPTIGA PBS** rotation transport → **final (DHUK + fresh TRNG salt)** via
    shielded `SetData(E140)`, two-phase confirm; salt persisted for device life
    in the page-127 journal.
- Then normal boot → **seed wizard** (PIN + mnemonic) → wallet creation.

### Explicitly NOT done on-device (stays factory-side)

The SE-internal irreversible locks (LcsO=Op ratchet, S-1/S-2/S-3 metadata,
trust-anchor cert), SE object/policy creation, the OTP-master burn, and the
whole option-byte profile except RDP. First boot only self-locks RDP-2 and
*rotates* the pairing secrets it inherits.

---

## Bounded power-loss recovery

The candidate resumes ordinary resets between completed flash quad-word
programs. Each step is idempotent; completion is recorded **commit-LAST** in
the append-only page-127 journal. A reset after one or two complete salt-data
QWs leaves them orphaned and the next attempt appends a new three-QW salt
record. Before starting that record, firmware reserves room for it plus the
two completion markers and otherwise fails closed without another write.

This is a finite recovery budget, not an unlimited guarantee. Repeatedly timed
interruptions or a flash defect can exhaust the 512-QW page and require RMA.
The host matrix models cuts between completed QW programs; partial-program,
retention, and the RDP `OPTSTRT` window remain silicon-validation gates. On a
resume boot the flow re-scans the journal, skips every completed step, and
continues at the first incomplete one. Per-SE rotation is **two-phase**: the
new keyset is confirmed live before the old one is considered dead (resume
probes the FINAL keyset first, then the TRANSPORT keyset).

The user must know: **do not disconnect power during first-boot setup.** The
screen says so. A resume shows "RECOVERING / DO NOT POWER OFF", not an error.

## Field failure UX

An unrecoverable state fails **closed** with a numbered code on the LCD:

```
 FIRST BOOT FAIL
 EXXXX HALT
```

Photograph the `EXXXX` code and send it to the vendor. Codes are STABLE across
firmware versions. Phase-A faults (`0x080x`) halt the unit **unlocked** (still
at RDP-0 → returnable/reflashable); Phase-B faults (`0x081x`+) occur after the
RDP-2 lock (→ RMA).

| Code | Meaning | Class |
|---|---|---|
| `E0801` | Option-byte / OTP / journal-page ship-profile mismatch | halt unlocked (reflash/return) |
| `E0802` | RDP=0xCC program / OPTSTRT failed | halt unlocked |
| `E0811` | OTP master not burned (factory step missing) | RMA |
| `E0812` | SAES Tier-1 (DHUK) self-test failed | RMA |
| `E0821` | BHK provision / load-lock failed | RMA |
| `E0822` | Page-126 refused programming (silicon program-hostility) | RMA |
| `E0831` | SE050 SCP03 establish failed under FINAL and TRANSPORT | RMA |
| `E0832` | SE050 `PUT KEY` (transport → final) failed | retry / RMA |
| `E0833` | Re-establish under the FINAL SCP03 keyset did not confirm | RMA |
| `E0841` | SE050 admin credential re-key failed | RMA |
| `E0851` | TRNG salt could not be persisted before use | halt |
| `E0852` | OPTIGA `SetData(E140)` of the final PBS failed | retry / RMA |
| `E0853` | Re-shield under the FINAL PBS did not confirm | RMA |
| `E0861` | Journal step-marker write failed | RMA |
| `E08F0` | SEs not in the expected factory transport state (pre-rotated?) | RMA |

(Source of truth: `secure/src/first_boot/state.rs` `FirstBootError`. The code
space `0x08xx–0x0Fxx` is disjoint from the factory ceremony's
`FactoryErrorCode` `0x01xx–0x07xx`.)

## Where it lives in code

| Piece | File |
|---|---|
| Phase A/B entry points + `FirstBootHw` impl | `secure/src/first_boot/mod.rs` |
| Page-127 journal codec (pure, host-tested) | `secure/src/first_boot/journal.rs` |
| Resumable state machine (pure, host-tested) | `secure/src/first_boot/state.rs` |
| Ship option-byte profile + comparators (pure) | `shared/src/lockdown.rs` |
| RDP-2 write path + OB readers + journal I/O | `secure/src/hw/flash.rs` |
| Transport keysets + salted PBS + `current_pbs` | `secure/src/hw/secret_keys.rs` |
| SE050 rotation methods | `secure/src/se050/mod.rs`, `scp03.rs` |
| OPTIGA PBS rotation | `secure/src/optiga/mod.rs` |
| Boot wiring (Phase A/B, BHK gate, SL7) | `secure/src/main.rs` |
| Feature + ship fences | `secure/Cargo.toml`, `secure/src/nsc/mod.rs` |
| Non-production anti-footgun check | `make build-rdp2-self-lock` (must reject the feature outside `mode-production`) |

## Silicon-validation runbook (MUST complete before any production run)

Nothing here can be done in the dev environment; RDP-2 mistakes are
unrecoverable, so validate on sacrificial parts first (same culture as the
S-1/S-2/S-3 burn ceremony). See also `docs/production-todo.md`.

1. **Power-cut matrix** (#36 (a)–(e)): induced cuts at every step boundary,
   incl. the unavoidable OPTSTRT window. The pure state machine's host
   power-cut matrix test (`first_boot::state::tests`) proves the *logic*
   converges; silicon must prove the *durability*.
2. **Page-126 program-hostility** re-check on shipping silicon (the current
   bench chip returns erase-OK / program-PROGERR) — gates the BHK first-write.
3. **RM0456 pins:** direct RDP 0→2 transition with TZEN=1 (erase behaviour +
   the exact OPTR-modify path); OEM1LOCK/OEM2LOCK register (FLASH_NSSR vs
   FLASH_OPTSR) + bit positions; `OPTWERR` bit for the OB-commit error check;
   BOR_LEV / WRP1AR / SECWM offsets for the Phase-A verifier; DHUK RDP-0 vs ≥1.
4. **SE050:** the transport→final `PUT KEY` flow; re-establish after a failed
   FINAL-probe auth; `SW=0x6986` admin-lockout behaviour during the resume
   verify probes (the admin UserID is unlimited-attempts, so it should not lock).
5. **OPTIGA:** the SetData wedge (2–3 ops) timing bracketing the salt+PBS
   rotation; E140 rewrite under the transport shield whether or not the factory
   ratcheted LcsO=Op.
