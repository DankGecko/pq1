---
surface: multi (playbook family build-out + code-review fixes)
run_date: 2026-07-02..04
reviewer: opus-4.8 (interactive, advisor-reviewed) + Explore/Workflow surface-mapping agents
scope: authored the 10-playbook adversarial-review family + the FV playbook validation, then worked through the findings surfaced across trusted-UI, trustzone-gateway, on-chain, fw-update, and silicon-lockdown
status: in-review
---

# Adversarial-review findings — playbook-family engagement — 2026-07-02..04

## Summary

11 findings surfaced while building + running the adversarial-review playbook family. **None was live fund-theft.** Current tally: **7 fixed, 1 reviewed but not owner-ratified, 3 deferred (tracked, blocked on hardware / a design decision / an undefined OTP scheme).** This report is the *review record* — the actionable detail + validation evidence lives in `docs/work-todo.md` (#12b–#12g), cross-linked per finding. Provenance: fixes were compiled + host-tested (secure suite 2090/0, shared lockdown tests, forge SOL6/H-3); the surface reviews were source-read + advisor-cross-checked (not a rainbow/silicon executing pass — those are the bench sweeps).

This report also **seeds the catalogue convention** — see `findings/README.md` + `findings/TEMPLATE.md`. Future passes file one report here per run, each finding carrying its own `Status:` so a glance shows what is handled.

## Findings

### F1 — Confirm result is not FI-hardened (trusted-UI UI1)
- **Status:** ✅ FIXED
- **Mode / severity:** UI1 · MED
- **Location:** `secure/src/ui/confirm.rs` + the 9 sign-path `confirm()` call sites
- **What:** the confirm accept was a plain `match ConfirmResult` — a single instruction-skip on a reject arm could fall through into signing; the one un-hardened link in an otherwise FI-hardened sign chain.
- **Resolution:** `confirm()` now delegates to `confirm_checked() -> (ConfirmResult, sentinel)` which **borns the sentinel at the accept branch from `seen_last`** (advisor: not post-hoc from the enum, so a value-fault is also caught); all 9 sites gate on `verdict == OK_SENTINEL`, fail closed. Source-text pins updated. work-todo #12c.

### F2 — `ui-noop` has no `mode-production` fence (trusted-UI UI2)
- **Status:** ✅ FIXED
- **Mode / severity:** UI2 · MED
- **Location:** `secure/src/nsc/mod.rs` (the leaky-feature denylist)
- **What:** a hand-composed `mode-production,ui-noop` build compiled; if the noop hang were "fixed" it would auto-confirm every sign with zero physical consent.
- **Resolution:** added a `mode-production ⊥ ui-noop` `compile_error!` (verified fires; no target combines them). work-todo #12c.

### F3 — `nsc_register_heartbeat` uses a divergent, weaker NS-ptr validator (trustzone TZ4)
- **Status:** ✅ FIXED
- **Mode / severity:** TZ4 · LOW
- **Location:** `secure/src/nsc/mod.rs:1376` → `hw::iwdg::register_ns_heartbeat`
- **What:** the veneer range-checked the NS address inline (no mailbox-disjoint / `TT` / FI-doubling), bypassing the central hardened validator.
- **Resolution:** now routes through the FI-doubled `NsPtr::validate_read(4)` typestate; iwdg inline check kept as defense-in-depth. work-todo #12b.

### F4 — Claim-8 OPTIGA anti-rollback counter cross-check advertised but absent (fw-update FW10)
- **Status:** ✅ FIXED (doc reconciled)
- **Mode / severity:** FW10 · LOW/doc
- **Location:** `docs/security/threat-model.md` Claim 8 vs `secure/src/nsc/cmd_fw_commit.rs`
- **What:** the threat model claimed an OPTIGA E1E0 counter cross-check at COMMIT that the code doesn't implement — anti-rollback is STM32-OTP-only (sound).
- **Resolution:** added a dated CORRECTION note under Claim 8 ("anti-rollback is STM32-OTP-only"). The implement-the-2nd-layer option is left as a defense-in-depth choice. work-todo #12c.

### F5 — Cross-slot `removeOwnerAtIndex` not bound to the signing slot (on-chain SOL6)
- **Status:** 🔬 REVIEWED (current behavior pinned; owner decision remains open)
- **Mode / severity:** SOL6 · LOW (availability, not theft)
- **Location:** `contracts/smart-wallet/src/PQSmartWallet.sol:469-474`
- **What:** the H-3 parity check is deliberately skipped for the remove selector, so any slot key ≥1 can remove any other non-bootstrap slot (bootstrap is unremovable + can re-add).
- **Resolution:** descriptive `threat-model.md §8` note (framed as an open owner-management design decision, **not ratified**) + `test_sol6_crossSlotRemoveIsAcceptedByDesign` forge test PINNING current behavior so a future `i==j` binding is a deliberate flip. This is not risk acceptance; whether to tighten remains the owner's design call. work-todo #12c.

### F6 — RDP-verify-in-boot missing (silicon-lockdown SL7)
- **Status:** ✅ FIXED
- **Mode / severity:** SL7 · LOW (belt-and-braces; RDP2 disables SWD in silicon)
- **Location:** `secure/src/main.rs` boot audit + `shared::lockdown`
- **What:** `HARDENING §4.2` prescribes a boot-time RDP check; none existed.
- **Resolution:** a `mode-production` boot check warns if `FLASH_OPTR.RDP != Level 2` (hard-refuse behind opt-in `rdp-enforce-halt`; a halt would brick factory rehearsal). Pure decode + host test in `sphincs_tz_shared::lockdown` (`rdp_decode_only_cc_is_level2`). commit 69315a2f. work-todo #12e.

### F7 — Secure boot address not verified (silicon-lockdown SL2)
- **Status:** ✅ FIXED
- **Mode / severity:** SL2 · LOW
- **Location:** `secure/src/main.rs` boot audit + `shared::lockdown::secboot_selects`
- **What:** nothing checked that `SECBOOTADD0R` selects the FSBL base — a redirected secure boot would be silent.
- **Resolution:** the boot audit warns if `SECBOOTADD0R` doesn't select the FSBL base (`0x0C00_0000`); pure check + host test (`secboot_selects_fsbl_base_and_tolerates_control_bits`, masks the `[24:0]` address field). commit 562759c7. work-todo #12e.

### F8 — Lockdown enforcement not policed by the meta-gate (silicon-lockdown SL3-meta)
- **Status:** ✅ FIXED
- **Mode / severity:** SL3 · LOW
- **Location:** `scripts/gate_enforcement.json`
- **What:** the `nsc/mod.rs` fence wall + `prod-check-ship` (the lockdown enforcement) were not enrolled in `verify-gate-enforcement`, so a silent unwiring wouldn't be caught.
- **Resolution:** enrolled a `prod-check-ship` entry (`per_pr_blocking`); `check_gate_enforcement.py` validates it (18/18 gates + self-test). commit 69315a2f. work-todo #12d.

### F9 — S-3 soft-counter production fence (silicon-lockdown SL7 / claim-vs-code)
- **Status:** ⏸ DEFERRED
- **Mode / severity:** SL7 · LOW
- **Location:** `secure/src/optiga/apdu.rs` `build_metadata_counter` + its callers
- **What:** the historical remediation proposed making `build_metadata_counter` a `compile_error!` under `mode-production`, but F1E1 is deeply integrated (read 5+ sites, written by `factory_reset_body`, LcsO-ratcheted) — not a one-line fence.
- **Resolution (blocker):** production already requires E120 as lockout authority. F1E1 is only the provisioning/reset sentinel; retain it under a reviewed final lifecycle or replace all consumers under a separately reviewed design. Either route needs on-silicon validation. Deferred — do not ram in a partial gate. work-todo #12e.

### F10 — BOOT_LOCK bit + HDP1 boot-verify (silicon-lockdown SL2)
- **Status:** ⏸ DEFERRED
- **Mode / severity:** SL2 · LOW
- **Location:** `SECBOOTADD0R` BOOT_LOCK bit / `SECWM1R2` HDP1EN
- **What:** the boot *address* is checked (F7), but the `BOOT_LOCK` bit (forces boot to that address) and `HDP1` are not asserted.
- **Resolution (blocker):** the exact BOOT_LOCK bit position / HDP1 polarity are inconsistent across our docs (production-todo `0x0C00_007C` vs ob-configurator `0x0018_0000`); a firmware pass/fail on an unconfirmed security bit is worse than none. Needs a bench register read + RM0456 §7.11 confirm, then add the warn (symmetric with F6/F7). work-todo #12e.

### F11 — Vendor-pubkey OTP hash lock not tracked (silicon-lockdown / threat-model §9.8)
- **Status:** ⏸ DEFERRED
- **Mode / severity:** — · LOW
- **Location:** `fsbl/src/vendor_pubkey.rs` + `hw/otp.rs`
- **What:** the FSBL-pinned vendor pubkey is not hash-locked in one-way OTP; §9.8 / Phase 7 track the intent but it was absent from `docs/work-todo.md`.
- **Resolution (blocker):** the OTP hash region + burn scheme aren't defined yet, so a firmware verify has nothing to compare against (a `(b)` factory-ceremony dependency). Now tracked as work-todo #12g.

## Suspicions (unverified — no PoC)

None outstanding from this engagement — the surface reviews recorded their "what I did NOT look at" as the per-playbook honest residual (Part D boundaries), and the FV surface map notes the 5 FV surfaces not yet adversarially reviewed.

## Honest residual

1. **Survived:** no live fund-theft; the clear-signing WYSIWYS bindings, the SE tunnel/PIN-lockstep invariants, the FI-hardened sign chain (post-F1), and the on-chain `theft_free`-covered classes all held under source review + the fixes' tests.
2. **Not looked at (next rounds):** an *executing* rainbow/TVLA pass on the FI/SCA surface; the 5 never-adversarially-reviewed FV surfaces (Miri / protocol models / CT-SCA / Aeneas §33 / differential-fuzz per `FV_SURFACE_MAP.md`); the S-3/BOOT_LOCK/OTP items above once their hardware/scheme blockers clear.
3. **Provenance:** fixes are compiled + host-tested (secure 2090/0, shared lockdown, forge SOL6/H-3); the surface catalogs are source-read + advisor-cross-checked, NOT bench-executing — every "defended" row names the test/sweep that would prove it on an executing pass.
