# Firmware-update + secure-boot adversarial-review playbook

> **Status correction (2026-07-11).** FW2/FW8 and the 75-byte-preimage claims
> below describe the legacy v0x02 implementation and are not current security
> conclusions. Independent review confirmed that the bitwise OTP tally is
> invalid on STM32U585 and A/B rollback is nonfunctional because the floor is
> advanced before probation. Production is compile-blocked. The reviewed
> replacement interfaces and remaining OPEN gates are in
> [`a-b-firmware-rollback-architecture.md`](../a-b-firmware-rollback-architecture.md).

**Purpose.** A legacy reusable recipe + copy-paste **master prompt** for an adversarial code-review pass over PQSigner's firmware-update and secure/measured-boot surface. Its v0x02 assumptions are retained as historical attack inventory; Draft 0.9 is now authoritative for the replacement contract.

> **Target claim (not yet implemented):** manifest v4 signs the exact frozen
> 80-byte `PQFW_V4 || physical_slot || release_version || security_epoch ||
> secure_hash || nonsecure_hash` preimage. The immutable FSBL verifies the
> slot-bound artifact, typed marker state, and typed epoch floor before
> branching. Runtime never advances that floor. The legacy V1/75-byte path is
> useful attack inventory only and cannot satisfy this claim.

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
| FW2 | **Rollback-floor bypass / counter reset** | a downgrade to a vulnerable version is accepted, or the floor is reset | **NOT PRODUCTION-DEFENDED.** Strict version comparison exists, but the underlying unary OTP tally attempts unsupported reprogramming of ECC-protected QWs. Draft 0.9 replaces it with a typed epoch-floor interface; physical codec/ECC/interruption gates remain OPEN. | Production compile fence + Draft-0.9 host models (pending) | ⛔ ship blocker |
| FW3 | **Manifest parse fail-open** | a malformed/oversized manifest is accepted | **DEFENDED (with a fuzz-only residual).** Total/panic-free parse (`read_array` checked slice `lib.rs:627-632`, proptest `:826`, Kani `:1000`); oversized-length reject at `cmd_fw_begin.rs:286-293`. **Residual**: `verify_structural`'s reserved-region hygiene scan is fuzz-covered but **not Kani-covered by design** (`lib.rs:1064-1073`) | fw-manifest Kani harnesses + `fw-manifest/tests/negative_{parser,verifier_chain}.rs` | ✅ Kani + fuzz (structural = fuzz only) |
| FW4 | **Boot-fingerprint spoof** | the FSBL trust-root fingerprint and the S-world advisory fingerprint diverge undetected | **DEFENDED (human-in-loop).** Both derive from `sphincs_tz_bip39::firmware_fingerprint_lines` (FSBL `fsbl/src/render.rs:30-44`, S-world `measured_boot.rs:151-186` over a *linker-derived* base so it measures the running slot); divergence = strong tamper signal. **Caveat**: the cross-check is a human reading two rows — the advisory row is self-attested, no automated compare | Manual boot inspection; `docs/security/measured-boot.md` | ⚠ human-in-loop (no auto cross-check) |
| FW5 | **Staging state-machine confusion** | COMMIT without the full CHUNK set, chunk reorder/retransmit, or a partial-write brick | **DEFENDED.** Strict monotonic append `check_chunk` rejects gaps/retransmits (`mod.rs:516-553`); QW-alignment + last-chunk pad (`staging.rs:50-72`); COMMIT requires `received==expected` + full-image hash match (`verify.rs:42-47`); STATUS reports `STAGED` only when both halves complete (`cmd_fw_status.rs:48-55`) | `nsc_fw_update_pure_tests.rs` (non-monotonic chunk tests `:496-518`) | ✅ host tests |
| FW6 | **Manifest-v4 binding drift** | a frozen field/offset/domain byte changes, the physical slot or `(R,E)` is omitted, or a legacy artifact is accepted | **TARGET INTERFACE FROZEN; IMPLEMENTATION OPEN.** Draft 0.9 fixes the exact 80-byte preimage and golden vectors. Existing 75-byte compile/Kani proofs cover the legacy format only and provide no V4 assurance. | New shared V4 golden vectors + parser/model/extraction gates required before implementation approval | ⛔ implementation gate |
| FW7 | **Runtime write to WRP1A FSBL pages** | runtime firmware modifies the immutable bootloader (pages 0–3) | **HARDWARE-ENFORCED (not code).** WRP1A option-byte lock silently `WRPERR`s any runtime write; no runtime write path exists. **Verify the option-byte provisioning in factory tooling, not firmware** | Footprint CI gate `fsbl-tests/tests/footprint.rs` (≤32 KB); factory option-byte provisioning audit | ⚠ hardware / factory (not a code check) |
| FW8 | **Try-once / A-B slot rollback + torn-commit brick** | a bad slot bricks the device, or a try-once revert erases the live slot | **CONFIRMED OPEN.** COMMIT advances the OTP floor before the candidate proves health, excluding the old slot; the single-candidate selector then cannot revert. Draft 0.9 freezes the replacement state machine but withholds implementation and physical-backend authority. | Draft-0.9 state/power-cut model; combined build and silicon receipts pending | ⛔ ship blocker |
| FW9 | **PIN not enforced on a FW command** | a FW command runs without a fresh PIN unlock | **DEFENDED.** All five (BEGIN/CHUNK/COMMIT/STATUS/ABORT) gate on `peek_state(pin_verified).check_sentinel() != OK_SENTINEL` (`cmd_fw_begin.rs:220`, `cmd_fw_chunk.rs:39`, `cmd_fw_commit.rs:35`, `cmd_fw_status.rs:26`, `cmd_fw_abort.rs:27`) | Source-text tests `nsc_fw_update_pure_tests.rs:663-720` | ✅ source-text tests |
| FW10 | **Claim-8 OPTIGA counter cross-check advertised but ABSENT** | the threat model claims a defense the code doesn't implement | **⚠ CONFIRMED CLAIM DRIFT.** `threat-model.md` advertises an OPTIGA cross-check that `cmd_fw_commit.rs` does not perform. The legacy STM32 OTP path is also not production-sound (FW2), so this cannot be dismissed as harmless defense-in-depth drift. Draft 0.9 deliberately keeps SE/hybrid counters out of the initial pre-PIN FSBL interface; reconcile the claim with that architecture. | Grep `cmd_fw_commit.rs`; reconcile threat model against Draft 0.9 | ⛔ documentation + architecture gate |

**Read this catalog narrowly.** Signature, parser, staging, PIN, and measured-
boot sub-properties retain their listed evidence, but anti-rollback and A/B
availability are not production-defended until FW2/FW8 are replaced and the
Draft-0.9 physical/resource gates close. FW7 remains factory/hardware evidence;
FW10 is an additional claim-vs-code correction.

---

## Part B — The existing defenses (Layer 1)

1. **The verify chain, FI-sentinel-wrapped.** `verify_manifest` (`fw_update/mod.rs:418-512`) — structural → CRC → digest → **signature** → vendor-fingerprint (CT) → rollback, each verdict via `check_true_into_sentinel` with `scrub_sentinel_register` between; verify-before-erase (C-1). COMMIT re-verifies from fresh flash (`verify.rs`).
2. **Anti-rollback target (not yet implemented).** Draft 0.9 separates ordinary
   `release_version` from rare `security_epoch` revocation and freezes a typed
   floor API. The legacy unary `MAX_FW_VERSION=1024` implementation is invalid
   and production-fenced; physical OTP/ECC/journal gates remain open.
3. **Legacy manifest evidence.** `fw-manifest/src/lib.rs` has total-parse tests/Kani and a 75-byte layout proof, but those results are V1-only. V4 needs new shared golden vectors and updated formal extraction before they count toward the target.
4. **The immutable FSBL + measured boot.** The current 32-KiB legacy FSBL verifies and renders the shared 8-word fingerprint. Draft 0.9's target envelope is 40 KiB and its final combined FLASH+RAM fit remains a NO-GO gate.
5. **FI sweeps.** `tools/sca/fault_sweep_fw_verify.py` (skip + stuck-at over the verify) + `fault_sweep_flashctr.py` (counter rollback). Host tests `fw_update_boot_pure_tests.rs` + `nsc_fw_update_pure_tests.rs` (PIN gate + non-monotonic chunk). `fwsign/tests/` roundtrip + wire-format stability.

---

## Part C — THE MASTER PROMPT

> Legacy v0x02 prompt: update its Claim-8/preimage/OTP assumptions from the
> Draft-0.9 frozen spec before reuse. It is not a production approval template.

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
  - docs/security/a-b-firmware-rollback-architecture.md — frozen V4 bytes/state/interface contract.
  - fw-manifest/src/lib.rs — legacy 75-byte parser/proofs; identify every V4 delta still missing.
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
  - Preserve the exact frozen Draft-0.9 80-byte V4 preimage. Any byte change requires a new schema/domain, digest freeze, and two-reviewer approval; never treat the legacy 75-byte format as authoritative.
  - WRP1A is a hardware/option-byte property — a "no runtime write path" finding must point at
    factory provisioning, not firmware.
  - For each finding: FW-mode, file:line, PoC, disposition, severity, proposed fix (flag if it
    changes frozen V4 bytes/state interfaces, weakens a sentinel, or gives runtime floor ownership).

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
rollback floor is sound: that backend is production-fenced. Draft 0.9 freezes
software interfaces only; physical journal/ECC/OTP semantics, resource fit,
factory authority, and silicon evidence remain open.
