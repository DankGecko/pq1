# Firmware-update + secure-boot adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code-review pass over PQSigner's firmware-update and secure/measured-boot surface — the signed-image path (`secure/src/fw_update/`, `fw-manifest/`, `fwsign/`), the immutable FSBL (`fsbl/`), and the measured-boot fingerprint (`secure/src/measured_boot.rs`). The property everything here defends is **Claim 8 + boot integrity**:

> **A firmware COMMIT succeeds only for a payload whose 75-byte preimage `"PQFW_V1"‖fw_version_be‖secure_hash‖nonsecure_hash` verifies under the FSBL-pinned vendor SPHINCS+C10 key, and a downgrade is rejected by a monotonic anti-rollback floor.** The signature is verified *before any destructive write*; the preimage is intentionally minimal (reconstructable from version + the two ELFs by any auditor — never expand it); and the FSBL (WRP1A-locked) is the immutable trust root that verifies + measures each slot before branching.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) §6.2 (measured boot / FSBL fingerprint) and §8.3 (firmware-update replay / rollback) enumerate the *silicon bench bars*. **This playbook is the code-review counterpart** — walking the source of the verify chain, the staging state machine, the rollback floor, and the boot path against Claim 8, hunting an FI-skippable verify, a rollback bypass, a fail-open manifest parse, or a staging/brick edge. Same discipline as the [FV playbook](../../verification/fv-adversarial-review-playbook.md) (the fw-manifest decoder already has Kani coverage); cross-link red-teaming.md, do not re-run its bench steps. The **delivery of a malicious image over USB by a hostile companion** is the [USB/companion playbook](./usb-companion-adversarial-review.md)'s threat; the *verify/rollback/boot defense* is here.

> **Honesty note.** The `Status` column separates **defended** (with the FI-sweep / Kani / test that proves it), **found-this-surface** (FW10 — the Claim-8 OPTIGA-counter cross-check advertised but not implemented), and **hardware-enforced-not-code** (WRP1A). Most rows are defended; FW10 is a claim-vs-code drift promoted to work-todo.

---

## Part A — The FW-update / secure-boot failure catalog (FW1–FW10)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| FW1 | **FI-skip of the sig verify → unsigned image installed** | a fault skips `verify_signature` and the erase/flash proceeds | **DEFENDED.** `verify_manifest` is called at BEGIN *before* the slot erase (`fw_update/mod.rs:418-512`, erase at `cmd_fw_begin.rs:345-349` — the C-1 verify-before-destructive-write fix); `verify_signature` runs through `fi::check_true_into_sentinel` with `scrub_sentinel_register` between digest/rollback verdicts (`mod.rs:471-510`); COMMIT re-verifies from fresh flash read (`verify.rs:41-115`, aggregate sentinel + `black_box`) | Rainbow `fault_sweep_fw_verify.py` (BAD_SIG/BAD_DIGEST fixtures, success = zero Err→Ok flips) | ✅ FI sweep |
| FW2 | **Rollback-floor bypass / counter reset** | a downgrade to a vulnerable version is accepted, or the floor is reset | **DEFENDED.** `verify_rollback` requires `fw_version > rollback_floor` strict (`fw-manifest/src/lib.rs:474-480`, Kani `:1012-1023`); OTP tally floor with `max(a,b)` admission vote (`otp.rs:251-267`) + fail-closed double-read bump (`:273-379`); floor derived from the *signed* version, never the unsigned `boot_counter_snap` (`cmd_fw_commit.rs:138-143`); OTP bump is the LAST irreversible write (anti-brick ordering) | Rainbow `fault_sweep_flashctr.py` (counter-rollback-on-read) + the OTP Kani boundary | ✅ FI sweep + Kani |
| FW3 | **Manifest parse fail-open** | a malformed/oversized manifest is accepted | **DEFENDED (with a fuzz-only residual).** Total/panic-free parse (`read_array` checked slice `lib.rs:627-632`, proptest `:826`, Kani `:1000`); oversized-length reject at `cmd_fw_begin.rs:286-293`. **Residual**: `verify_structural`'s reserved-region hygiene scan is fuzz-covered but **not Kani-covered by design** (`lib.rs:1064-1073`) | fw-manifest Kani harnesses + `fw-manifest/tests/negative_{parser,verifier_chain}.rs` | ✅ Kani + fuzz (structural = fuzz only) |
| FW4 | **Boot-fingerprint spoof** | the FSBL trust-root fingerprint and the S-world advisory fingerprint diverge undetected | **DEFENDED (human-in-loop).** Both derive from `sphincs_tz_bip39::firmware_fingerprint_lines` (FSBL `fsbl/src/render.rs:30-44`, S-world `measured_boot.rs:151-186` over a *linker-derived* base so it measures the running slot); divergence = strong tamper signal. **Caveat**: the cross-check is a human reading two rows — the advisory row is self-attested, no automated compare | Manual boot inspection; `docs/security/measured-boot.md` | ⚠ human-in-loop (no auto cross-check) |
| FW5 | **Staging state-machine confusion** | COMMIT without the full CHUNK set, chunk reorder/retransmit, or a partial-write brick | **DEFENDED.** Strict monotonic append `check_chunk` rejects gaps/retransmits (`mod.rs:516-553`); QW-alignment + last-chunk pad (`staging.rs:50-72`); COMMIT requires `received==expected` + full-image hash match (`verify.rs:42-47`); STATUS reports `STAGED` only when both halves complete (`cmd_fw_status.rs:48-55`) | `nsc_fw_update_pure_tests.rs` (non-monotonic chunk tests `:496-518`) | ✅ host tests |
| FW6 | **Preimage expansion / weakening** | a signed field added/removed so the preimage no longer binds the images | **DEFENDED.** Frozen at 75 B with compile-time assert (`fw-manifest/src/lib.rs:156`) + a Kani layout proof (`:1033-1062`); `fwsign verify-release` reconstructs it from `(version, ELFs)` | `fw-manifest/tests/wire_format_stability.rs` + Kani layout | ✅ compile assert + Kani |
| FW7 | **Runtime write to WRP1A FSBL pages** | runtime firmware modifies the immutable bootloader (pages 0–3) | **HARDWARE-ENFORCED (not code).** WRP1A option-byte lock silently `WRPERR`s any runtime write; no runtime write path exists. **Verify the option-byte provisioning in factory tooling, not firmware** | Footprint CI gate `fsbl-tests/tests/footprint.rs` (≤32 KB); factory option-byte provisioning audit | ⚠ hardware / factory (not a code check) |
| FW8 | **Try-once / A-B slot rollback + torn-commit brick** | a bad slot bricks the device, or a try-once revert erases the live slot | **DEFENDED.** `pick_slot` = highest version + try-once-revert + `COMMITTING`-torn reject (`fsbl/src/main.rs:180-228`); COMMIT writes `TRY_ONCE_TRIED` + boot-state before OTP (`cmd_fw_commit.rs:165-214`); erase target uses secure VTOR (`running_slot()`), not boot-state, so a revert-divergence can't erase the live slot (`mod.rs:376-412`) | `docs/VULN-fwcommit-otp-before-commit-brick.md` regression; `fwup-transport-hw` e2e (stops before OTP) | ✅ regression + HW e2e |
| FW9 | **PIN not enforced on a FW command** | a FW command runs without a fresh PIN unlock | **DEFENDED.** All five (BEGIN/CHUNK/COMMIT/STATUS/ABORT) gate on `peek_state(pin_verified).check_sentinel() != OK_SENTINEL` (`cmd_fw_begin.rs:220`, `cmd_fw_chunk.rs:39`, `cmd_fw_commit.rs:35`, `cmd_fw_status.rs:26`, `cmd_fw_abort.rs:27`) | Source-text tests `nsc_fw_update_pure_tests.rs:663-720` | ✅ source-text tests |
| FW10 | **Claim-8 OPTIGA counter cross-check advertised but ABSENT** | the threat model claims a defense the code doesn't implement | **⚠ FOUND-THIS-SURFACE (claim-vs-code → work-todo).** `threat-model.md:167` (Claim 8) says a downgrade is rejected by "OPTIGA monotonic counter (E1E0, Conf(0xE140))" cross-checked at COMMIT — but `cmd_fw_commit.rs` has **no OPTIGA counter read/cross-check** (E1E0/F1E1 are used only for PIN/duress). Anti-rollback rests **entirely on STM32 OTP** (FW2, which is sound) — so either the doc overstates a second layer or the OPTIGA layer is missing. **Not a live vuln** (OTP holds); a doc-vs-code drift to reconcile | Grep `cmd_fw_commit.rs` for an OPTIGA counter read (none); reconcile threat-model.md Claim 8 | ❌ adversary (doc-vs-code) → work-todo |

**Read this catalog as the answer to "can a fault or a malicious image get an unsigned/downgraded firmware to run?"** For FW1–FW3, FW5, FW6, FW8, FW9 the answer is *no* by construction, each row naming the sweep/Kani/test. FW4 rests on a human reading the fingerprint (no automated cross-check — a disclosed limit). FW7 is hardware-enforced (verify the factory option-byte burn, not the firmware). **FW10 is the one claim-vs-code drift** — anti-rollback is OTP-only; the advertised OPTIGA layer is absent — promoted to work-todo to reconcile.

---

## Part B — The existing defenses (Layer 1)

1. **The verify chain, FI-sentinel-wrapped.** `verify_manifest` (`fw_update/mod.rs:418-512`) — structural → CRC → digest → **signature** → vendor-fingerprint (CT) → rollback, each verdict via `check_true_into_sentinel` with `scrub_sentinel_register` between; verify-before-erase (C-1). COMMIT re-verifies from fresh flash (`verify.rs`).
2. **Anti-rollback in OTP.** `hw/otp.rs` unary tally floor, `max`-vote admission, fail-closed bump, OTP-last ordering (`cmd_fw_commit.rs`). `MAX_FW_VERSION=1024`.
3. **The manifest decoder (FV-covered).** `fw-manifest/src/lib.rs` — total parse (proptest `:826`, Kani `:1000-1074`, extracted Lean spec `Extracted/FwManifestSpec.lean`); the 75-B preimage frozen with a compile-assert + Kani layout proof.
4. **The immutable FSBL + measured boot.** `fsbl/` (WRP1A, ≤32 KB footprint gate) verifies each A/B slot (`fsbl/src/verify.rs`, sentinel-gated) + branches (`branch.rs`); `measured_boot.rs` renders the 8-word fingerprint over the running slot.
5. **FI sweeps.** `tools/sca/fault_sweep_fw_verify.py` (skip + stuck-at over the verify) + `fault_sweep_flashctr.py` (counter rollback). Host tests `fw_update_boot_pure_tests.rs` + `nsc_fw_update_pure_tests.rs` (PIN gate + non-monotonic chunk). `fwsign/tests/` roundtrip + wire-format stability.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's firmware-update + secure-boot path.
Your job is to BREAK Claim 8 (a COMMIT installs only a vendor-signed, non-downgraded image;
verify happens before any destructive write) and boot integrity, NOT to confirm them.
Default to "a fault skips the verify / a downgrade slips through / the manifest parse fails
open until I prove otherwise." A passing FI unit test is a consistency signal — the attack
surface is the SWEEP result and the staging/rollback edges.

TARGET (read first, in this order):
  - docs/security/adversarial-review/firmware-update-secure-boot-adversarial-review.md §A — FW1–FW10.
  - secure/src/fw_update/{mod,staging,verify,vendor_pubkey}.rs — the on-device verify chain + staging.
  - fw-manifest/src/lib.rs — the 75-byte preimage + total-parse verify chain (+ its Kani).
  - secure/src/hw/otp.rs — the anti-rollback floor.
  - fsbl/src/{main,verify,branch,manifest,otp}.rs + secure/src/measured_boot.rs — the boot root.
  - secure/src/nsc/cmd_fw_*.rs — the five gated handlers.
SCOPE THIS RUN: {{e.g. "the verify chain's single-fault surface" | "the rollback floor + OTP
  ordering" | "the staging state machine + torn-commit brick" | "the Claim-8 OPTIGA-counter
  drift (FW10)" | "the manifest parse fail-open surface"}}.

ATTACK PROTOCOL — walk EVERY FW1–FW10 mode against each stage in scope:
  FW1 FI-skip verify · FW2 rollback bypass · FW3 manifest fail-open · FW4 fingerprint spoof ·
  FW5 staging confusion · FW6 preimage expansion · FW7 WRP1A runtime write · FW8 try-once/AB
  brick · FW9 PIN not enforced · FW10 Claim-8 OPTIGA-counter drift.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a rainbow fault_sweep BYPASS (an unsigned/downgraded image reaches flash / OTP);
  - a manifest input the parser accepts that it should reject (fuzz/Kani counterexample);
  - a chunk sequence that COMMITs without the full image, or bricks the live slot;
  - a diff between what threat-model Claim 8 advertises and what cmd_fw_commit.rs implements.
  No PoC ⇒ list under "suspicions, unverified".

RULES:
  - Verify against the CURRENT tree; a green FI UNIT test is not a green SWEEP — state which.
  - Never propose EXPANDING the 75-byte preimage (it is intentionally auditor-reconstructable).
  - WRP1A is a hardware/option-byte property — a "no runtime write path" finding must point at
    factory provisioning, not firmware.
  - For each finding: FW-mode, file:line, PoC, disposition, severity, proposed fix (flag if it
    would expand the preimage, weaken a sentinel, or change the anti-brick OTP-last ordering).

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per stage.
  2. "What I did NOT look at" — sweeps not run, stages not walked, FW-modes not exhausted.
  3. "PROVENANCE — did this pass RUN fault_sweep_fw_verify / cargo kani / the HW e2e, or read
     source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** ≥3 reviewers per scope, cross-vote, two model backends.

---

## Part D — Cadence + honest boundary

- **Per-PR touching `fw_update/`, `fw-manifest/`, `fsbl/`, `otp.rs`, or `measured_boot.rs`:** the Layer-1 host tests + Kani on the manifest + `fault_sweep_fw_verify.py` if the verify chain changed.
- **Per-milestone:** full rainbow sweep (verify + flashctr) + the `fwup-transport-hw` HW e2e + a boot-fingerprint manual check.
- **Pre-ship:** the WRP1A option-byte burn + the bench red-team (red-teaming.md §6.2/§8.3) — the once-only silicon work.
- **The one-line gut check:** *if I skip the verify instruction / feed a downgraded version / send a torn chunk set — does an unsigned or old image ever run?* If you haven't **run the sweep**, you don't know.

**The boundary, stated on purpose.** This playbook can tell you that no *swept* verify step is single-fault-skippable and the rollback floor is sound as of the last executing pass. It **cannot** tell you the WRP1A burn happened (factory), that the human will notice a diverged fingerprint (FW4), or that the OTP is the *only* anti-rollback layer the threat model should claim (FW10 — reconcile the doc). Those are the factory's, the human's, and the doc-owner's job.
