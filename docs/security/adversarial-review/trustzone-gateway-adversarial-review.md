# TrustZone / NSC-gateway adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for running an adversarial code-review pass over PQSigner's TrustZone boundary — the NSC gateway (the CMSE veneers + QEMU mailbox), NS-pointer validation, and the SAU/GTZC platform config. The property everything here defends is **invariant #4**:

> **All secrets live only in the secure world; NS never sees a PIN, entropy, signing key, or derived secret.** The gateway returns opaque non-secret data. Every NS pointer is validated before deref, and every NS buffer is copied to the S-stack before parse (TOCTOU). A fully-adversarial non-secure world drives every gateway call.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) §6.1 (TrustZone/GTZC peripheral isolation) and §8.1 (NSC gateway/NS-pointer validation) enumerate the *silicon bench pass-fail bars* (`make gtzc-enforcement-hw` → 7/7 RAZ-fault). **This playbook is the code-review counterpart**: it walks the *source* of each veneer and validator against invariant #4, hunting an entry point that derefs before validating, trusts an NS-supplied length outside a proven kernel, uses a divergent weaker validator, or leaks a secret across the boundary. Same discipline as the [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md); do not re-run red-teaming.md's bench checks here.

> **Honesty note.** The `Status` column distinguishes **defended** (with evidence — most rows), **found-this-surface** (the `nsc_register_heartbeat` divergent validator, TZ4), and **reasoned-latent**. A structural strength worth stating up front: nearly every gate here is **FI-doubled through Hamming-distant sentinels** (`fi::check_true_into_sentinel`) rather than a bare `if !ok`, so single-fault bypass of a pointer/length/unlock gate is designed to fail closed. The realistic residual attacks are multi-fault, or logic/arithmetic errors in the non-proven inlined parse paths — not the proven window/typestate core.

---

## Part A — The TrustZone-boundary failure catalog (TZ1–TZ9)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| TZ1 | **Unvalidated NS-pointer deref** | a handler derefs an NS pointer before `NsPtr<T>` validation | **DEFENDED (by typestate).** `NsPtr<T>` (raw, unvalidated) → `validate_read(len)`/`validate_write(len)` → `ReadPtr`/`WritePtr`, the only types with accessors (`nsc/ns_ptr.rs:48,82,107`). Forgetting to validate is a **type error**, not a discipline lapse | Grep for raw `read_volatile` on an NS address outside `ns_ptr.rs`/`ns_ptr_validate.rs`; host typestate tests `ns_ptr.rs:251-575` | ✅ typestate (compile) + host tests |
| TZ2 | **TOCTOU double-read** | NS presents different bytes to the validator vs the consumer | **DEFENDED.** Per-byte `read_volatile` copy into an S-stack snapshot before parse (`shared/src/ns_ptr_validate.rs:148`); canonical flow `cmd_sign_userop.rs:121-174` (validate → wipe shared buf → `snap[i]=read_volatile(...)`). Per-byte volatile ordering is load-bearing (compiler may not coalesce/elide) | Miri tree-borrows over the volatile copy primitives (`cargo +nightly miri test -p sphincs-tz-shared`, `ns_ptr_validate.rs:363-465`) | ✅ Miri |
| TZ3 | **Length/offset arithmetic outside a proven kernel** | an NS-influenced length slices the snapshot, or `ptr+len` overflows, in a path not covered by a Kani proof | **DEFENDED (core) / ⚠ audit inlined paths.** Window check + `validate_data_len` are Kani-proven with non-vacuity controls (`ns_ptr_validate.rs:232-355`, `aa/userop.rs:777/789`); `checked_add`, `len>u32::MAX` reject. **Residual**: any handler doing its own offset-table arithmetic *outside* these kernels (the Kani scope note `userop.rs:727` excludes fixed-offset reads) | Kani (`cargo kani -p sphincs-tz-shared`); audit each handler's independent length handling (`cmd_sign_userop_batch`, `cmd_sign_offchain`, `cmd_get_init_code`, `cmd_offchain_sync`, `prodtest`) | ✅ Kani (core) / ❌ adversary (inlined) |
| TZ4 | **Divergent / weaker validator** | an entry point does its own inline range check instead of routing through the central FI-doubled validator | **✅ FIXED 2026-07-02 (was FOUND-THIS-SURFACE, LOW).** `nsc_register_heartbeat` now routes the NS address through the FI-doubled `NsPtr::validate_read(4)` typestate (mailbox-disjoint + `TT` + double-sentinel); iwdg's inline check stays as defense-in-depth. **Historically** `nsc_register_heartbeat(addr)` (`nsc/mod.rs:1376` → `hw::iwdg::register_ns_heartbeat`, `iwdg.rs:176`) used an inline `addr&0x3 \|\| addr<NS_SRAM_BASE \|\| addr+4>NS_SRAM_END` check — **no shared-mailbox-disjoint check, no `TT` check, not FI-doubled**, unlike `validate_ns_read_ptr`. Impact bounded (4-byte secure→NS read of a counter in NS SRAM; no secret egress) but it is the one entry point bypassing the hardened validator → **promoted to work-todo** | Audit every `nsc_*` veneer: does it route through `validate_ns_{read,write}_ptr`? Flag any with a private check | ❌ adversary (grep + review) |
| TZ5 | **Secret egress via the gateway** | a handler writes secret-bearing bytes to an NS `WritePtr` | **DEFENDED (by design).** Handlers return opaque non-secret data (address, initCode, signatures, status words); `gated_unlock` returns the master secret only internally to `SecureState`, never across a veneer. Most sensitive to audit: the `prodtest` handlers (SAES/BHK self-test writing to `out_ptr`) — gated behind a non-production `compile_error!` (`prodtest.rs:48`) | Audit every `WritePtr::write_from_slice` callsite for secret-derived bytes; confirm the prodtest fence | ⚠ partial (fence + review) |
| TZ6 | **GTZC / SAU misconfig** | a secure peripheral left NS-accessible, or a validation window that drifts outside the SAU NS region | **DEFENDED.** `GTZC1_TZSC_SECCFGR{1,3}` = default-secure allowlist (I2C1/2, AES/HASH/RNG/PKA/SAES secure; OTG stays NS) after the CRIT-4 `0x0`-everything fix (`sau.rs:352-354`); **compile-time subset assert** proves proto `NS_*` windows sit inside the SAU NS regions (`sau.rs:58-67`); source-text pins on register addresses + SECCFGR bits (`main_sau_pure_tests.rs`). **Residual**: `TZSC_SECCFGR4` (AHB3) + GTZC2 (TAMP) at NS reset default — flagged open in CLAUDE.md; the `debug_assert_eq!` readback is compiled out of release | Source-text invariants (`main_sau_pure_tests.rs`); silicon `make gtzc-enforcement-hw`; verify the subset-assert arithmetic against the real linker `memory.x` (the `NS_*_END-1` inclusive/exclusive juggling `sau.rs:60-65`) | ✅ compile assert + source pins / silicon bench |
| TZ7 | **Single-fault gate bypass** | a fault skips a pointer/length/unlock gate | **DEFENDED.** `validate_read`/`validate_write` run the predicate **twice** through `fi::check_true_into_sentinel` with `wait_random()` between, each sentinel checked independently (`ns_ptr.rs:83-93`) — two coordinated faults required. `gated_unlock` gates are all sentinel-wrapped | Rainbow FI sweep `tools/sca/fault_sweep_ns_ptr.py`; confirm no bare `if !ok` on a boundary gate | ✅ FI sweep (smoke) |
| TZ8 | **Non-reentrancy / shared-buffer leakage** | `HANDLER_DEPTH` breached, or the shared sign snapshot buffer not wiped before fill, leaking a prior request | **DEFENDED.** `HandlerGuard`/`HANDLER_DEPTH` (`AtomicU32`, `mod.rs:727-764`) enforces the single-threaded invariant every `unsafe` SAFETY comment relies on; wipe-before-fill on the shared `SIGN_SNAP_BUF` (`cmd_sign_userop.rs:164-169`). **Residual**: a handler that fills the buffer but returns early before wiping is a leak vector (the BSS/stack-clobber history `mod.rs:681-703` shows this region is stack-pressure-sensitive) | Audit each sign handler's early-return paths for a fill-without-wipe; confirm the guard covers every veneer | ⚠ partial (review) |
| TZ9 | **Config left un-frozen (post-boot mutability) — the TZ-lock row** | SAU regions / GTZC1 TZSC attributes / AIRCR security-config stay writable after boot, so a fault flip or a stray secure-world write can re-classify secure SRAM as NS, mark SAES NS, or re-point the secure vector table — a layer *below* the signing-path FI (TZ6 asks "is the config right?"; TZ9 asks "can it still be *changed*?") | **✅ FIXED 2026-07-02 (tz-2, Trezor-port `tz_init.c`).** `sau::lock_security_config` at the end of `init()` (`stm32u585`) sets SYSCFG `CSLCKR` LOCKSAU\|LOCKSVTAIRCR + GTZC1 `TZSC_CR.LCK` + AIRCR PRIS/BFHFNMINS (SYSRESETREQS gated behind `mode-production` so bench keeps its NS warm-reset), freezing the SAU regions + TZSC per-peripheral attributes + AIRCR sec-config *after* they are programmed. Reset-scoped (re-applied every boot). AIRCR `BFHFNMINS=0` also reinforces the rr-1 HardFault handler (fault taken S-side). GTZC2 (TAMP) deliberately NOT locked — unconfigured on this branch. This is the **runtime sibling** of the irreversible burns in the [silicon-lockdown](./silicon-lockdown-adversarial-review.md) playbook. **Residual**: silicon-only — `thumbv8m` compile + host source-invariant test (`main_sau_pure_tests.rs::positive_tz2_locks_security_config_after_enabling_sau`, register bytes cross-checked vs CMSIS); needs on-silicon boot + `make gtzc-enforcement-hw` run *after* the lock lands | Source-invariant test (fence STRING + register bytes, not line); silicon boot + `make gtzc-enforcement-hw` post-lock | ✅ compile + source pin / silicon bench |

**Read this catalog as the answer to "can a malicious NS world cross the boundary or extract a secret?"** For TZ1/TZ2/TZ6/TZ7/TZ9 the answer is *no* by construction, each row naming the mechanism. **TZ4 is the one found-this-surface residual** (a LOW divergent validator, now in work-todo). TZ3/TZ5/TZ8 are defended in the core but have **inlined-path / early-return residuals that are the adversary's job** — the proven window/typestate kernel is sound, so push on the parse paths the Kani harnesses explicitly exclude.

---

## Part B — The existing defenses (Layer 1)

1. **Typestate + Kani + Miri triad.** `NsPtr<T>` typestate makes unvalidated deref a compile error (TZ1); the pure-arithmetic window check is Kani-proven with non-vacuity controls — `ns_write_sound`, `ns_read_sound`, `ns_write_sound_symbolic_regions`, plus `*_control` reject-witnesses (`shared/src/ns_ptr_validate.rs:232-355`) (TZ3); Miri tree-borrows vet the volatile copy primitives (TZ2).
2. **Compile-time boundary asserts.** SAU NS-window ⊆ SAU-region subset assert (`sau.rs:58`); per-handler `const _: () = assert!(SNAP_LEN <= SIGN_SNAP_BUF_LEN)` (`cmd_sign_userop.rs:161`, `cmd_sign_userop_batch.rs:189`, `cmd_sign_offchain.rs:130`); trailer-budget asserts (`batch_trailers.rs:82,133`); the release-build feature ship-blocker `compile_error!` (`mod.rs:114`).
3. **FI-doubled gates.** Every boundary gate is `fi::check_true_into_sentinel` with Hamming-distant sentinels (`secure/src/fi.rs:115`) — not a bare branch (TZ7). See the [SCA/FI playbook](./sca-fi-adversarial-review.md) for the FI primitive review.
4. **Source-text platform-config pins.** `main_sau_pure_tests.rs` pins register addresses, SAU region calls, SECCFGR3 bit positions, the OTG-stays-NS contract (with a negative assert that `SECCFGR3_OTG_BIT` must *not* exist as secure), I2C bits, and `TZSC_BASE==0x5003_2400` with a regression guard against the TZIC address (TZ6).
5. **Silicon bench (red-teaming.md territory, cross-linked not duplicated).** `make gtzc-enforcement-hw` (7/7 secure peripherals RAZ-fault on NS access, USB still enumerates); `nonsecure/src/{gtzc_test,tzic_wipe_test}.rs`. Real `TT`/SAU semantics validated on silicon — the host `TT` stub is a deliberate `true` no-op (`ptr_validate.rs:124-140`), so on host the guarantee reduces to the constant-window check + the compile-time subset assert.

**Cross-linked surface (owned elsewhere).** The **firmware-update gateway**
(`cmd_fw_{begin,chunk,commit,status,abort}`) is a TrustZone entry surface. Its
legacy V1/OTP backend is production-fenced; review the unapproved Draft 1.1
research candidate and the corrected
[`red-teaming.md`](../red-teaming.md) §8.3 / [`threat-model.md`](../threat-model.md)
Claim 8. Here, only confirm the veneers use the central validator and a
`HandlerGuard`.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's TrustZone boundary. Your job is
to BREAK invariant #4 (no secret ever reaches the non-secure world; every NS pointer
validated before deref; every NS buffer copied to S-stack before parse), NOT to confirm
it. Default to "this veneer trusts NS input until I prove it validates." A green typestate
build and a passing Kani proof are CONSISTENCY signals for the CORE — the attack surface
is the inlined parse paths the proofs EXCLUDE, and any entry point with its own validator.

TARGET (read first, in this order):
  - docs/security/adversarial-review/trustzone-gateway-adversarial-review.md §A — the
    TZ1–TZ8 catalog.
  - secure/src/nsc/{mod,ptr_validate,ns_ptr}.rs — dispatcher, veneers, gated_unlock,
    NsPtr typestate, the central validators.
  - secure/src/nsc/cmd_*.rs — every handler; focus on independent length/offset handling.
  - shared/src/ns_ptr_validate.rs — the Kani-proven window kernel (+ its scope EXCLUSIONS).
  - secure/src/sau.rs + secure/src/main_sau_pure_tests.rs — SAU/GTZC config + source pins.
SCOPE THIS RUN: {{e.g. "every cmd_* handler's length handling" | "the SAU/GTZC config vs
  the linker script" | "secret-egress audit of every WritePtr callsite" | "the veneers"}}.

ATTACK PROTOCOL — walk EVERY TZ1–TZ8 mode against each entry point in scope:
  TZ1 unvalidated deref · TZ2 TOCTOU double-read · TZ3 length/offset outside a proven
  kernel · TZ4 divergent/weaker validator · TZ5 secret egress via the gateway ·
  TZ6 GTZC/SAU misconfig · TZ7 single-fault gate bypass · TZ8 non-reentrancy/buffer leak ·
  TZ9 config left un-frozen (post-boot mutability — the tz-2 lock).

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a handler path that slices the snapshot with an NS-influenced length NOT routed
    through validate_data_len / the Kani window kernel;
  - a veneer that derefs / range-checks an NS pointer with its own logic instead of
    validate_ns_{read,write}_ptr (cite the divergent check);
  - a WritePtr callsite that writes secret-derived bytes;
  - a SECCFGR/SAU-region value that leaves a secure peripheral NS-accessible, or a subset
    assert whose arithmetic disagrees with the linker memory.x;
  - an early-return path that fills the shared sign buffer without wiping it.
  No PoC ⇒ list under "suspicions, unverified".

RULES:
  - Verify against the CURRENT tree; the host TT check is a NO-OP stub — do not treat a
    passing host test as evidence the hardware reclassification holds (that is silicon).
  - The Kani window/decode_flags/validate_data_len proofs cover the CORE; their scope
    notes EXCLUDE fixed-offset inlined reads — that exclusion is your hunting ground.
  - For each finding: TZ-mode, file:line, PoC, disposition, severity, proposed fix
    (flag if it would regress a Kani proof, break the typestate, or weaken a sentinel).

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
  1. "What I tried to break and COULDN'T" — per entry point.
  2. "What I did NOT look at" — handlers/veneers not walked, TZ-modes not exhausted,
     whether you checked host-only or reasoned about silicon TT/SAU.
  3. "PROVENANCE — did this pass RUN Kani/Miri/gtzc-enforcement-hw, or read source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** ≥3 reviewers per scope, cross-vote, two model backends; the `contracts/verification/adversarial-review/` kit drives the fan-out.

---

## Part D — Cadence + honest boundary

- **Per-PR touching `nsc/` or `sau.rs`:** the Layer-1 gates (typestate build + Kani + Miri + source-text pins) and a scoped Part-C pass on the changed veneer/handler. A new veneer that takes an NS pointer ships routing through `validate_ns_*` or it does not ship.
- **Per platform-config change:** re-run `main_sau_pure_tests.rs` + (on silicon) `make gtzc-enforcement-hw`; re-check the subset-assert arithmetic against `memory.x`.
- **The one-line gut check:** *for each veneer, if NS hands it a pointer into secure memory or a length that overflows the snapshot — does it fail closed before any deref?* If you don't **know** (typestate proof or Kani kernel), it is not safe — it is green.

**The boundary, stated on purpose.** This playbook can tell you that no *covered* veneer derefs before validating and that the arithmetic core is Kani-sound as of the last executing pass. It **cannot** tell you the inlined offset-parse paths the Kani harnesses exclude are sound (TZ3), that the hardware `TT`/SAU reclassification holds (the host stub is a no-op — that is silicon, red-teaming.md §6.1), or that a divergent validator like `nsc_register_heartbeat` (TZ4) has no reachable higher-impact variant. Those are the adversary's + the bench's job.
