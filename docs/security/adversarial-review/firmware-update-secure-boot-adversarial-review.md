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
| FW1 | **FI-skip of the sig verify → unsigned image installed** | a fault skips `verify_signature` and the erase/flash proceeds | **DEFENDED.** `verify_manifest` is called at BEGIN *before* the slot erase (`fw_update/mod.rs:447-533`, erase at `cmd_fw_begin.rs:190-194` — the C-1 verify-before-destructive-write fix); `verify_signature` runs through `fi::check_true_into_sentinel` with `scrub_sentinel_register` between digest/rollback verdicts (`mod.rs:471-510`); COMMIT re-verifies from fresh flash read (`verify.rs:41-115`, aggregate sentinel + `black_box`). **Boundary named (2026-07-17 sweep):** the *pre-OTP authorization gate* (`cmd_fw_commit.rs:229-237`) is NOT part of this defense — see FW11 | Rainbow `fault_sweep_fw_verify.py` (BAD_SIG/BAD_DIGEST fixtures, success = zero Err→Ok flips) | ✅ FI sweep |
| FW2 | **Rollback-floor bypass / counter reset** | a downgrade to a vulnerable version is accepted, or the floor is reset | **NOT PRODUCTION-DEFENDED.** Strict version comparison exists, but the underlying unary OTP tally attempts unsupported reprogramming of ECC-protected QWs. Draft 1.1 proposes a typed epoch-floor interface; approval, physical codec/ECC/interruption, resource, and silicon gates remain OPEN. | Production compile fence + historical host models; current candidate review pending | ⛔ ship blocker |
| FW3 | **Manifest parse fail-open** | a malformed/oversized manifest is accepted | **DEFENDED (with a fuzz-only residual).** Total/panic-free parse (`read_array` checked slice `lib.rs:638+`, proptest `:826`, Kani `:1016`); oversized-length reject at `cmd_fw_begin.rs:133-135` — note this check is the **sole** bound on the unsigned length fields (the `cmd_fw_begin.rs:123-125` comment claiming the lengths are signed-over is false: `SIGNED_PREIMAGE_LEN == 75` covers tag+version+hashes only; sweep 2026-07-17). **Residual**: `verify_structural`'s reserved-region hygiene scan is fuzz-covered but **not Kani-covered by design** (`lib.rs:1064-1073`) | fw-manifest Kani harnesses + `fw-manifest/tests/negative_{parser,verifier_chain}.rs` | ✅ Kani + fuzz (structural = fuzz only) |
| FW4 | **Boot-fingerprint spoof** | the legacy FSBL fingerprint and the S-world advisory fingerprint diverge undetected | **BENCH PARITY DEFENDED; PRODUCTION TRUST ROOT OPEN.** Both derive from `sphincs_tz_bip39::firmware_fingerprint_lines` (FSBL `fsbl/src/render.rs:30-44`, S-world `measured_boot.rs:151-186` over a *linker-derived* base so it measures the running slot), so divergence is a useful bench tamper signal. **Caveat**: the cross-check is a human reading two rows and the advisory row is self-attested; the current FSBL does not become a production trust root until geometry, WRP/RDP, resource, factory, and silicon gates close | Manual bench inspection now; immutable-FSBL receipts before production | ⛔ trust-root gate; ⚠ bench human check |
| FW5 | **Staging state-machine confusion** | COMMIT without the full CHUNK set, chunk reorder/retransmit, or a partial-write brick | **DEFENDED.** Strict monotonic append `check_chunk` rejects gaps/retransmits (`mod.rs:537-574`); QW-alignment + last-chunk pad (`staging.rs:50-72`); COMMIT requires `received==expected` + full-image hash match (`verify.rs:42-47`); STATUS reports `STAGED` only when both halves complete (`cmd_fw_status.rs:55-64`). **Drift note (2026-07-17):** the `SESSION_COUNTER` contract documented at `fw_update/mod.rs:379-382` is not wired — BEGIN discards the tag (`cmd_fw_begin.rs:225`) and STATUS has no session field; add it to the wire format or delete the counter + comment | `nsc_fw_update_pure_tests.rs` (non-monotonic chunk tests `:496-518`) | ✅ host tests |
| FW6 | **Manifest-v6 candidate binding drift** | a proposed field/offset/domain byte changes, the physical slot or `(R,E)` is omitted, or a legacy artifact is accepted | **RESEARCH CANDIDATE; IMPLEMENTATION OPEN.** Draft 1.1 proposes the exact V6/121-byte preimage and fixtures. Existing V1/75-byte proofs and historical V4/80-byte models provide no V6 implementation assurance. | After candidate approval: shared V6 fixtures + parser/model/extraction gates before implementation approval | ⛔ implementation gate |
| FW7 | **Runtime write to the final WRP-protected FSBL range** | runtime firmware modifies the immutable bootloader | **LEGACY HARDWARE MECHANISM, CANDIDATE OPEN.** WRP rejects writes to a correctly programmed range, but Draft 1.1's proposed pages-0..4 geometry, both-bank protection, exact option bytes, and factory receipt are not approved. The current 32-KiB footprint test is only a legacy bench-link regression. | After candidate approval: physical LOAD-span + RAM/stack gates, both-bank option-byte receipt, and owner-authorized silicon validation | ⛔ architecture / hardware / factory gate |
| FW8 | **Try-once / A-B slot rollback + torn-commit brick** | a bad slot bricks the device, or a try-once revert erases the live slot | **CONFIRMED OPEN.** COMMIT advances the OTP floor before the candidate proves health, excluding the old slot; the single-candidate selector then cannot revert. Draft 1.1 proposes a replacement state machine but withholds implementation and physical-backend authority. **Sub-arm named by the 2026-07-17 sweep:** the legacy try-once arm coerces an *unreadable* boot-state (both CRC copies torn) to "go ahead and try" the unproven winner (`fsbl/src/main.rs:224-234`) — class-(ii) inconclusive→risky-verdict; Draft 1.1's typed-marker decode must inherit "torn/ambiguous ⇒ known-good slot, never ATTEMPTED" | Candidate state/power-cut review; physical FLASH, RAM/stack, factory, and silicon receipts pending | ⛔ ship blocker |
| FW9 | **PIN not enforced on a FW command** | a FW command runs without a fresh PIN unlock | **DEFENDED.** All five (BEGIN/CHUNK/COMMIT/STATUS/ABORT) gate on `peek_state(pin_verified).check_sentinel() != OK_SENTINEL` (`cmd_fw_begin.rs:44`, `cmd_fw_chunk.rs:39`, `cmd_fw_commit.rs:42`, `cmd_fw_status.rs:35`, `cmd_fw_abort.rs:36`) | Source-text tests `nsc_fw_update_pure_tests.rs:663-720` | ✅ source-text tests |
| FW11 | **Pre-irreversible-write authorization gate without FI discipline** | the last check before an irreversible write (OTP floor, lifecycle burn) is a plain `&&`/`if` chain while every sibling verdict is sentinel-wrapped | **CANDIDATE (2026-07-17 sweep, pre-adjudication).** `cmd_fw_commit.rs:229-237`: `manifest_ok`/`pointer_ok` are plain booleans feeding `if !(…) { return }` before `otp::bump_to(new_rollback_floor)` — two coordinated faults (tear the manifest write + skip the reject) brick the device (new slot boot-invalid, old slot floor-excluded). Everything around it — BEGIN's `verify_manifest`, COMMIT's `verify_images` aggregate, `bump_to`'s own readback — is `check_true_into_sentinel`-hardened. Fix: route the gate through `check_true_into_sentinel` with `scrub_sentinel_register`, matching `verify_images`' aggregate-gate pattern | Fault-skip on the reject arm; check the shipped ELF for the branch shape | ❌ found-this-surface (candidate) |
| FW10 | **An OPTIGA firmware-version counter is advertised accidentally** | documentation claims a counter/cross-check that the implementation and approved architecture do not have | **DEFENDED AS DOCUMENTED.** `threat-model.md` explicitly states that there is no OPTIGA firmware-version counter. The legacy STM32 OTP path remains non-production-sound (FW2), while Draft 1.1 keeps SE/hybrid counters out of the initial pre-PIN FSBL interface. Treat any future OPTIGA firmware-counter claim as drift unless a separately reviewed architecture adds one. | Claim inventory across threat model, updater, FSBL, and candidate architecture | ✅ documentation preflight |

**Read this catalog narrowly.** Signature, parser, staging, PIN, and measured-
boot sub-properties retain their listed evidence, but anti-rollback and A/B
availability are not production-defended until FW2/FW8 are replaced and the
Draft-1.1 candidate's approval/physical/resource/factory gates close. FW7 remains factory/hardware evidence;
FW10 guards against reintroducing a counter claim that the current owner text
explicitly rejects.

---

## Part B — The existing defenses (Layer 1)

1. **The verify chain, FI-sentinel-wrapped.** `verify_manifest` (`fw_update/mod.rs:418-512`) — structural → CRC → digest → **signature** → vendor-fingerprint (CT) → rollback, each verdict via `check_true_into_sentinel` with `scrub_sentinel_register` between; verify-before-erase (C-1). COMMIT re-verifies from fresh flash (`verify.rs`).
2. **Anti-rollback candidate (not yet approved or implemented).** Draft 1.1 separates ordinary
   `release_version` from rare `security_epoch` revocation and freezes a typed
   floor API as a research proposal. The legacy unary `MAX_FW_VERSION=1024`
   implementation is invalid and production-fenced; approval plus physical
   OTP/ECC/journal/resource gates remain open.
3. **Legacy manifest evidence.** `fw-manifest/src/lib.rs` has total-parse tests/Kani and a 75-byte layout proof, and the historical Draft-0.9 model covers V4/80 bytes. Neither provides V6 assurance. After candidate approval, V6 needs shared fixtures and updated parser/formal extraction before it can count toward implementation.
4. **The target immutable FSBL + measured boot.** The current 32-KiB legacy FSBL verifies and renders the shared 8-word fingerprint but is not a production trust root. Draft 1.1 keeps a 40-KiB candidate envelope; its geometry/WRP ceremony, physical FLASH LOAD-span, and independent RAM/worst-case-stack gates remain NO-GO.
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
  ordering" | "the staging state machine + torn-commit brick" | "accidental OPTIGA
  firmware-counter claims (FW10)" | "the manifest parse fail-open surface"}}.

ATTACK PROTOCOL — walk EVERY FW1–FW10 mode against each stage in scope:
  FW1 FI-skip verify · FW2 rollback bypass · FW3 manifest fail-open · FW4 fingerprint spoof ·
  FW5 staging confusion · FW6 preimage expansion · FW7 WRP1A runtime write · FW8 try-once/AB
  brick · FW9 PIN not enforced · FW10 accidental OPTIGA firmware-counter claim.

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
  - For each candidate: FW-mode, file:line, PoC, provisional severity, stable
    candidate ID, and proposed fix (flag if it
    changes candidate V6 bytes/state interfaces, weakens a sentinel, or gives runtime floor ownership).
    Do not assign a finding disposition.

OUTPUT — return an external candidate packet to the coordinator. Do not modify
the repository, write a canonical findings report, or update catalogue/status
fields. Include every candidate and the honest residual. The coordinator freezes
the raw packet and gives the complete union to the exact Partner-A/Partner-B
pair; only their symmetric cross-adjudication may assign dispositions. An
authorized maintainer records the adjudicated result afterward.

FILING — the coordinator files every kept adversarial-review candidate as a
GitHub issue on EthereumPhone/PQ1 (labels `finding`, `priority:*`, `surface:*`;
`ship-blocker` when the candidate gates production). The issue is the
actionable record; any report under findings/ remains the frozen evidence.
Phase-D merge-review outcomes are never filed as issues. Do not file issues
yourself unless the coordinator's brief says so.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per stage.
  2. "What I did NOT look at" — sweeps not run, stages not walked, FW-modes not exhausted.
  3. "PROVENANCE — did this pass RUN fault_sweep_fw_verify / cargo kani / the HW e2e, or read
     source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** Use ≥3 independent discovery reviewers per scope
across two model backends. Quorum only corroborates/prioritizes discovery; it
does not set a disposition, and sub-quorum variants remain in the packet. Give
every candidate and origin variant to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only their symmetric cross-adjudication may disposition it, with disagreement
preserved.

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
