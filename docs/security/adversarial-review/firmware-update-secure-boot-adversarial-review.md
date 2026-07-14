# Firmware-update + secure-boot adversarial-review playbook

> **Status correction (2026-07-14).** FW2/FW8 and the 75-byte/V1 and
> 80-byte/V4 material below are legacy attack inventory, not current
> implementation authority. Independent review confirmed that the bitwise OTP
> tally is invalid on STM32U585 and A/B rollback is nonfunctional because the
> floor is advanced before probation. Production is compile-blocked. Draft 1.1
> in
> [`a-b-firmware-rollback-architecture.md`](../a-b-firmware-rollback-architecture.md)
> is the current preserved research/review candidate; it proposes V6/121-byte
> manifest bytes but remains unapproved for implementation and retains every
> named backend, resource, factory, and silicon gate.

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code-review pass over PQSigner's firmware-update and secure/measured-boot surface. Its v0x02 and Draft-0.9 assumptions are retained as historical attack inventory; Draft 1.1 is the current candidate to attack, not approved implementation authority.

> **Candidate target claim (not implemented or approved):** Draft 1.1 proposes
> manifest v6 over the exact 121-byte `PQFW_V6 || schema || physical_slot ||
> release_version || security_epoch || secure_image_length ||
> nonsecure_image_length || secure_image_hash || nonsecure_image_hash ||
> vendor_key_fingerprint` preimage. The immutable FSBL would verify the
> slot-bound artifact, typed marker state, and typed epoch floor before
> branching; runtime would never advance that floor. V1/75-byte and V4/80-byte
> paths are historical attack inventory and cannot satisfy this candidate.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) §6.2 (measured boot / FSBL fingerprint) and §8.3 (firmware-update replay / rollback) enumerate the *silicon bench bars*. **This playbook is the code-review counterpart** — walking the source of the verify chain, the staging state machine, the rollback floor, and the boot path against Claim 8, hunting an FI-skippable verify, a rollback bypass, a fail-open manifest parse, or a staging/brick edge. Same discipline as the [FV playbook](../../verification/fv-adversarial-review-playbook.md) (the fw-manifest decoder already has Kani coverage); cross-link red-teaming.md, do not re-run its bench steps. The **delivery of a malicious image over USB by a hostile companion** is the [USB/companion playbook](./usb-companion-adversarial-review.md)'s threat; the *verify/rollback/boot defense* is here.

> **Honesty note.** The `Status` column now separates locally defended pieces
> from the production-blocking FW2/FW8 architecture defects, claim-vs-code
> drift, and hardware-only controls. A green sub-check does not close the
> rollback backend.

---

## Part A — The FW-update / secure-boot failure catalog (FW1–FW10)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| FW1 | **FI-skip of the sig verify → unsigned image installed** | a fault skips `verify_signature` and the erase/flash proceeds | **DEFENDED.** `verify_manifest` is called at BEGIN *before* the slot erase (`fw_update/mod.rs:418-512`, erase at `cmd_fw_begin.rs:345-349` — the C-1 verify-before-destructive-write fix); `verify_signature` runs through `fi::check_true_into_sentinel` with `scrub_sentinel_register` between digest/rollback verdicts (`mod.rs:471-510`); COMMIT re-verifies from fresh flash read (`verify.rs:41-115`, aggregate sentinel + `black_box`) | Rainbow `fault_sweep_fw_verify.py` (BAD_SIG/BAD_DIGEST fixtures, success = zero Err→Ok flips) | ✅ FI sweep |
| FW2 | **Rollback-floor bypass / counter reset** | a downgrade to a vulnerable version is accepted, or the floor is reset | **NOT PRODUCTION-DEFENDED.** Strict version comparison exists, but the underlying unary OTP tally attempts unsupported reprogramming of ECC-protected QWs. Draft 1.1 proposes a typed epoch-floor interface; approval, physical codec/ECC/interruption, resource, and silicon gates remain OPEN. | Production compile fence + historical host models; current candidate review pending | ⛔ ship blocker |
| FW3 | **Manifest parse fail-open** | a malformed/oversized manifest is accepted | **DEFENDED (with a fuzz-only residual).** Total/panic-free parse (`read_array` checked slice `lib.rs:627-632`, proptest `:826`, Kani `:1000`); oversized-length reject at `cmd_fw_begin.rs:286-293`. **Residual**: `verify_structural`'s reserved-region hygiene scan is fuzz-covered but **not Kani-covered by design** (`lib.rs:1064-1073`) | fw-manifest Kani harnesses + `fw-manifest/tests/negative_{parser,verifier_chain}.rs` | ✅ Kani + fuzz (structural = fuzz only) |
| FW4 | **Boot-fingerprint spoof** | the FSBL trust-root fingerprint and the S-world advisory fingerprint diverge undetected | **DEFENDED (human-in-loop).** Both derive from `sphincs_tz_bip39::firmware_fingerprint_lines` (FSBL `fsbl/src/render.rs:30-44`, S-world `measured_boot.rs:151-186` over a *linker-derived* base so it measures the running slot); divergence = strong tamper signal. **Caveat**: the cross-check is a human reading two rows — the advisory row is self-attested, no automated compare | Manual boot inspection; `docs/security/measured-boot.md` | ⚠ human-in-loop (no auto cross-check) |
| FW5 | **Staging state-machine confusion** | COMMIT without the full CHUNK set, chunk reorder/retransmit, or a partial-write brick | **DEFENDED.** Strict monotonic append `check_chunk` rejects gaps/retransmits (`mod.rs:516-553`); QW-alignment + last-chunk pad (`staging.rs:50-72`); COMMIT requires `received==expected` + full-image hash match (`verify.rs:42-47`); STATUS reports `STAGED` only when both halves complete (`cmd_fw_status.rs:48-55`) | `nsc_fw_update_pure_tests.rs` (non-monotonic chunk tests `:496-518`) | ✅ host tests |
| FW6 | **Manifest-v6 candidate binding drift** | a proposed field/offset/domain byte changes, the physical slot or `(R,E)` is omitted, or a legacy artifact is accepted | **RESEARCH CANDIDATE; IMPLEMENTATION OPEN.** Draft 1.1 proposes the exact V6/121-byte preimage and fixtures. Existing V1/75-byte proofs and historical V4/80-byte models provide no V6 implementation assurance. | After candidate approval: shared V6 fixtures + parser/model/extraction gates before implementation approval | ⛔ implementation gate |
| FW7 | **Runtime write to the final WRP-protected FSBL range** | runtime firmware modifies the immutable bootloader | **LEGACY HARDWARE MECHANISM, CANDIDATE OPEN.** WRP rejects writes to a correctly programmed range, but Draft 1.1's proposed pages-0..4 geometry, both-bank protection, exact option bytes, and factory receipt are not approved. The current 32-KiB footprint test is only a legacy bench-link regression. | After candidate approval: physical LOAD-span + RAM/stack gates, both-bank option-byte receipt, and owner-authorized silicon validation | ⛔ architecture / hardware / factory gate |
| FW8 | **Try-once / A-B slot rollback + torn-commit brick** | a bad slot bricks the device, or a try-once revert erases the live slot | **CONFIRMED OPEN.** COMMIT advances the OTP floor before the candidate proves health, excluding the old slot; the single-candidate selector then cannot revert. Draft 1.1 proposes a replacement state machine but withholds implementation and physical-backend authority. | Candidate state/power-cut review; physical FLASH, RAM/stack, factory, and silicon receipts pending | ⛔ ship blocker |
| FW9 | **PIN not enforced on a FW command** | a FW command runs without a fresh PIN unlock | **DEFENDED.** All five (BEGIN/CHUNK/COMMIT/STATUS/ABORT) gate on `peek_state(pin_verified).check_sentinel() != OK_SENTINEL` (`cmd_fw_begin.rs:220`, `cmd_fw_chunk.rs:39`, `cmd_fw_commit.rs:35`, `cmd_fw_status.rs:26`, `cmd_fw_abort.rs:27`) | Source-text tests `nsc_fw_update_pure_tests.rs:663-720` | ✅ source-text tests |
| FW10 | **Claim-8 OPTIGA counter cross-check advertised but ABSENT** | the threat model claims a defense the code doesn't implement | **⚠ CONFIRMED CLAIM DRIFT.** `threat-model.md` advertises an OPTIGA cross-check that `cmd_fw_commit.rs` does not perform. The legacy STM32 OTP path is also not production-sound (FW2), so this cannot be dismissed as harmless defense-in-depth drift. Draft 1.1 keeps SE/hybrid counters out of the initial pre-PIN FSBL interface; reconcile the claim with the candidate before approval. | Grep `cmd_fw_commit.rs`; candidate-vs-threat-model conflict preflight | ⛔ documentation + architecture gate |

**Read this catalog narrowly.** Signature, parser, staging, PIN, and measured-
boot sub-properties retain their listed evidence, but anti-rollback and A/B
availability are not production-defended until FW2/FW8 are replaced and the
Draft-1.1 candidate's approval/physical/resource/factory gates close. FW7 remains factory/hardware evidence;
FW10 is an additional claim-vs-code correction.

---

## Part B — The existing defenses (Layer 1)

1. **The verify chain, FI-sentinel-wrapped.** `verify_manifest` (`fw_update/mod.rs:418-512`) — structural → CRC → digest → **signature** → vendor-fingerprint (CT) → rollback, each verdict via `check_true_into_sentinel` with `scrub_sentinel_register` between; verify-before-erase (C-1). COMMIT re-verifies from fresh flash (`verify.rs`).
2. **Anti-rollback candidate (not yet approved or implemented).** Draft 1.1 separates ordinary
   `release_version` from rare `security_epoch` revocation and freezes a typed
   floor API as a research proposal. The legacy unary `MAX_FW_VERSION=1024`
   implementation is invalid and production-fenced; approval plus physical
   OTP/ECC/journal/resource gates remain open.
3. **Legacy manifest evidence.** `fw-manifest/src/lib.rs` has total-parse tests/Kani and a 75-byte layout proof, and the historical Draft-0.9 model covers V4/80 bytes. Neither provides V6 assurance. After candidate approval, V6 needs shared fixtures and updated parser/formal extraction before it can count toward implementation.
4. **The immutable FSBL + measured boot.** The current 32-KiB legacy FSBL verifies and renders the shared 8-word fingerprint. Draft 1.1 keeps a 40-KiB candidate envelope; its physical FLASH LOAD-span and independent RAM/worst-case-stack gates remain NO-GO.
5. **FI sweeps.** `tools/sca/fault_sweep_fw_verify.py` (skip + stuck-at over the verify) + `fault_sweep_flashctr.py` (counter rollback). Host tests `fw_update_boot_pure_tests.rs` + `nsc_fw_update_pure_tests.rs` (PIN gate + non-monotonic chunk). `fwsign/tests/` roundtrip + wire-format stability.

---

## Part C — THE MASTER PROMPT

> Current-candidate prompt: preserve V1/V4 only as historical attack inventory,
> and attack Draft 1.1 as an unapproved research candidate. This is not a
> production or implementation approval template.

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
  - docs/security/a-b-firmware-rollback-architecture.md — Draft-1.1 V6/state/interface candidate; verify its exact digest and pending status.
  - fw-manifest/src/lib.rs — legacy 75-byte parser/proofs; identify every V6 delta still missing.
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
  - Treat Draft 1.1's exact V6/121-byte preimage as the candidate under review, never as implementation authority. Any candidate-byte change requires a new schema/domain where applicable, a new digest, fresh dual review, and owner approval. V4/80 and V1/75 are historical only.
  - WRP1A is a hardware/option-byte property — a "no runtime write path" finding must point at
    factory provisioning, not firmware.
  - For each finding: FW-mode, file:line, PoC, disposition, severity, proposed fix (flag if it
    changes candidate V6 bytes/state interfaces, weakens a sentinel, or gives runtime floor ownership).

OUTPUT — file findings so they can be catalogued + worked through (see
docs/security/adversarial-review/findings/README.md):
  Write a dated report to docs/security/adversarial-review/findings/<surface>-<YYYY-MM-DD>.md
  from findings/TEMPLATE.md — everything below (findings + the honest residual) goes IN it.
  Report frontmatter `status: open`; EACH finding gets its own `Status:` line (start 🔲 OPEN)
  + a falsifiable PoC. Add one row to the Catalogue table in findings/README.md. As findings
  are worked through, whoever handles each flips its `Status:` (✅ FIXED / ☑️ ACCEPTED /
  🚫 INVALID / ⏸ DEFERRED) + a Resolution (commit+date or why), and sets the report
  `status: resolved` once none remain OPEN. work-todo.md stays the action list; findings/ is
  the review record — cross-link them.

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

**The boundary, stated on purpose.** This playbook can tell you that no *swept*
legacy verify step was single-fault-skippable. It cannot claim the legacy
rollback floor is sound: that backend is production-fenced. Draft 1.1 proposes
software interfaces only and remains unapproved; physical journal/ECC/OTP
semantics, resource fit, factory authority, and silicon evidence remain open.
