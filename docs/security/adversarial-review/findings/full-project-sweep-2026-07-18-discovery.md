---
report_kind: supplemental-discovery-pre-cross-adjudication
surface: multi
run_date: 2026-07-18
target_identity: "repo HEAD 89c600630d5d257479e88bc3647707c59f9409c0 (master, sweep date 2026-07-18; tree clean except untracked files)"
cross_adjudication_sha256: "none — this report has not been cross-adjudicated; no cross-adjudication matrix exists for it"
scope: "full-project discovery sweep: 15 parallel adversarial lanes over the 15 playbook surfaces plus the FV gate layer; source/config review evidence only, individual checkers executed only where stated"
status: open
---

# Full-project adversarial sweep — discovery report — 2026-07-18

> **SUPPLEMENTAL DISCOVERY EVIDENCE — PRE-CROSS, NON-CANONICAL.** This file is
> the output of a **single-coordinator discovery sweep** (15 parallel
> adversarial lanes). It has **NOT** been cross-adjudicated. Every finding below
> is `🔲 OPEN`; this report contains **no CONFIRMED / REFUTED / NARROWED /
> UNRESOLVED dispositions**. It grants **no merge, shipment, hardware, or
> adjudication authority**. Canonical recording follows the current
> three-reviewer regime in
> [`docs/planning-and-review-workflow.md`](../../../planning-and-review-workflow.md)
> §7/§7b: one simultaneous three-reviewer wave plus coordinator triage, with
> **no** Partner-A / Partner-B cross-adjudication step; triaged items are
> recorded as GitHub issues. Until that runs, nothing in this file is a
> canonical finding.

## Sweep metadata

- **Target:** repository HEAD `89c600630d5d257479e88bc3647707c59f9409c0`
  (branch `master`, sweep date 2026-07-18, tree clean except untracked files).
- **Method:** 15 parallel adversarial lanes (USB, TZGW, CS, SCAFI, FWSB, SE,
  LIFE, ENT, RUN, OFFCHAIN, CHAIN, TUI, PRODCFG, LOCK, FV). Each lane derived
  threats first-principles from source + the CLAUDE.md invariants **before**
  using its playbook (`docs/security/adversarial-review/`) as a coverage floor.
- **Known-issue exclusion:** a known-issue exclusion digest was built
  beforehand from `docs/work-todo.md` + `docs/STATUS.md` §A–§D + the findings
  catalogue (**367 tracked items excluded**); lanes also self-filtered, and each
  lane's "already tracked, not re-reported" list was spot-verified against the
  digest.
- **Evidence level:** source/config review only; no fuzz campaigns, no
  hardware; individual checkers were executed only where stated (per-finding
  and in the per-surface verdicts below).
- **Dedupe outcome:** 55 raw candidates received → 1 cross-lane exact
  duplicate pair merged (`TZGW-3` ≡ `RUN-2`, kept as one entry crediting both
  lanes) → **54 kept candidates** (29 KEEP + 25 KEEP-NOTE with `overlap-check:`
  refs for coordinator judgment; 0 DROP-TRACKED — no candidate was found to be
  materially the same issue as a digest entry; every borderline case was kept
  as KEEP-NOTE per the prefer-KEEP-NOTE rule). Severity and PoC/suspicion
  labels are the lanes' own, preserved verbatim.

## Coordinator verification

The following three lane claims were independently **re-verified by the
coordinator directly on HEAD `89c60063`** — not merely lane-claimed. (The same
commands were re-executed once more while assembling this report, with
identical results.)

- **FV-1 (→ F49):** `python3 contracts/verification/scripts/check_extraction_freshness.py`
  re-executed → **exit 1**: `extract-aa-userop` drifted (sha256 — rust file
  `aa/src/userop.rs` CHANGED; the committed extraction is no longer
  known-fresh). Totals: **13 fresh, 1 waived-stale** (`extract-tx-merkle`,
  tracked as work-todo FV15-F1), **1 drifted**.
- **FV-2 (→ F50):** `python3 scripts/check_gate_enforcement.py` re-executed →
  **exit 1**: two **G1META-1 COMPLETENESS** failures — `verify-hw-assumptions`
  and `verify-mmio-addresses` are invoked in `ci.yml` but are not manifest
  gates (nor in `_completeness_waived`).
- **RUN-1 (→ F30):** grep across `secure/src`, `nonsecure/src`, `fsbl/src`,
  `hal/src` confirms **zero `set_priority` calls** (only test comments mention
  priorities) — corroborates the no-exception-priority-programming claim.

## Findings

54 kept candidates, numbered F1–F54 per the findings TEMPLATE convention,
grouped by surface/lane. Each entry keeps its original lane ID, the lane's own
severity and PoC/suspicion label, the lane verdict with its `overlap-check:`
reference where one exists, and the full evidence block transcribed from the
sweep candidate record. **Every finding is `🔲 OPEN`** — open does not mean
confirmed; it means unadjudicated.

## Findings — USB companion (lane USB) — F1–F4

### F1 — [USB-1] Cross-channel seq=0 aborts an in-progress reassembly — silent starvation, bypasses both F11 lease and §31a channel isolation
- **Severity:** low (persistent DoS)
- **Evidence label:** PoC
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** findings:sweep-2026-07-14 F11 (FIXED at router level); work-todo:31a/31d (channel-isolation regression DONE). Same channel-isolation family, but the framing-layer assembler seq-0 path is arguably outside the landed fix; coordinator to judge whether F11's FIX was scoped to router state only.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `shared/src/apdu_framing.rs:336-357`: the `seq == 0` path never checks `channel`. While `rx_pos > 0`, ANY channel's first-frame scrubs the partially reassembled APDU of the channel that owns the stream (`buf[..stale]` zeroed, `reset()`, `Dropped`). The F11 fix (`commands.rs:203-219` `ROUTER_OWNER`) protects only router-level chain/pending state; the §31a channel-isolation regression tests (`apdu_framing.rs:804-847`) pin only the `seq != 0` mismatch path. The assembler is single-stream, so the seq-0 "desync abort" (a deliberate defense) doubles as a cross-channel kill primitive.
- PoC: client A on `0x0101` (the reference client's hardcoded id, `tools/webhid_test.html:324`) sends seq=0 declaring a ~15 KB SIGN_USEROP (≈250 HID frames). Client B on `0x0202` injects one seq=0 frame at any point → A's whole transfer is destroyed; `FrameOutcome::Dropped` produces **no response at all** (`transport.rs:112-115` returns `None`), so A hangs until its own timeout. B's frame is also eaten (it is dropped, not started as a new stream), so B retries at a cost of one frame vs A's 250 — asymmetric, repeatable starvation. A never reaches the on-device confirm.
- The in-code rationale (`apdu_framing.rs:341-349`) claims "the host can recover by retrying its seq=0 once the abort response (Dropped) arrives" — no abort response exists; that comment is wrong. Absent from the exclusion digest (F11 is marked FIXED at router level; UC7/X17-UC1 is the chain-lease wedge, a different mechanism).
- On-device defense that should stop it: the channel lease — but it is not enforced at the transport layer. No defense today.

### F2 — [USB-2] Slow-drain keepalive pins the single-session router lease indefinitely — 30 s timeout is activity-reset, not a total bound
- **Severity:** low (persistent DoS)
- **Evidence label:** PoC
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:X17-UC1 (chain-state wedge, OPEN). Same symptom (permanent router-lease wedge) but a different code path and a different missing bound (drain side has an idle timeout; it is activity-reset). Fixing X17-UC1 does not close this path.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `nonsecure/src/usb/commands.rs:783`: every GET_RESPONSE resets `PENDING_ELAPSED_FRAMES = 0`; `check_response_timeout` (`:825-846`) only fires after 30 s of *silence*. A host that drains all but ≥1 chunk and then issues one GET_RESPONSE every <30 s holds `PENDING_PTR` forever → `ROUTER_OWNER = Some(channel)` forever (`:213-217`) → every other channel gets `SW_CONDITIONS_NOT_SATISFIED` forever, across replugs (channel IDs are host-chosen).
- This is the response-drain sibling of X17-UC1 (chain-state wedge). The digest entry covers only the chain side: "Chained-APDU state has no idle timeout → permanent router-lease wedge". Fixing UC7 by adding a chain idle timeout does NOT close this path — the drain path already has an idle timeout; what it lacks is a total-exchange deadline. PENDING also survives `CMD_LOCK`/idle-wipe (NS RAM is not scrubbed on lock), so a stale drain from a previous session keeps leaking old (public) signature bytes to its owner after re-unlock — availability/confidentiality impact is nil, but the lease wedge persists across sessions.
- PoC: complete any chunked SIGN_USEROP on channel A, drain to the last chunk, then `GET_RESPONSE` once per 29 s with the final chunk never taken. Defense that should stop it: the F11 lease + 30 s scrubber — present but activity-resettable; no defense against keepalive. Not in the digest.

### F3 — [USB-3] REQUEST_UNLOCK is not idempotent — every host call pops a trusted-UI PIN dialog (UI hijack / prompt-fatigue, attempt-burn social vector)
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP — not the same root cause as work-todo:X17-UI3 (idle-timer reset on dialog entry); this is the missing already-unlocked short-circuit in the dispatcher/handler; it compounds X17-UI3 but stands alone (prompt spam and attempt-burn work even without the idle-reset issue).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/nsc/cmd_request_unlock.rs:18-47`: `run()` goes straight to `enter_pin()` with no `pin_verified` short-circuit; the dispatcher (`secure/src/nsc/mod.rs:1384`) adds no gate either. A hostile companion can spam INS 0x10 (or call it once per minute) and keep the trusted display occupied with unsolicited PIN prompts: (a) blocks/queues the confirm dialogs of real sign requests behind a PIN prompt — a confused user may type the PIN into an attacker-chosen moment (each wrong entry burns one of 10 attempts toward wipe); (b) compounds X17-UI3 (`pin_entry` resets the idle timer on dialog entry, `secure/src/ui/pin_entry.rs:83`) to keep the 120 s signing window open indefinitely without any button press.
- The short-circuit gap itself (return `Ok` immediately when already unlocked) is not in the digest; only the idle-reset half is (X17-UI3). Defense that should stop it: none — there is no rate limit or already-unlocked early return. PoC is a reasoning trace: unlocked device + `INS_V2_UNLOCK` APDU → PIN dialog appears (no state check on the path).

### F4 — [USB-4] Doc/comment drift on the USB attack surface (three spots)
- **Severity:** low (informational)
- **Evidence label:** PoC by inspection
- **Lane verdict:** KEEP — none of the three items appears in the digest (X17-UC2's constant `provisioned` byte is a different constant on a different command).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `nonsecure/src/usb/commands.rs:273-276` claims FW_CHUNK carries "up to 1024 bytes of data — well under the 253-byte APDU data limit". `FW_MAX_CHUNK = 1024` (`proto/src/lib.rs:729`) but APDU `Lc` is u8, so wire chunks cap at 247 B data; harmless (secure `check_chunk` still bounds), just wrong guidance for companion implementers.
- `secure/src/hw/usb_hw.rs:129` says it clears security bits for "PB5, PB6 (CC1), PB7 (CC2)"; the code clears `PA15` and `PB15` (`:130-131`). Comment/code mismatch on exactly the pins a reviewer must audit for NS-exposure.
- `nonsecure/src/usb/commands.rs:160` hardcodes `FW_VERSION = [3,0,0]` — GET_DEVICE_INFO cannot report real firmware identity; companions keying protocol decisions (e.g., batch wire v2) on it get a constant. None of these are in the digest.

## Findings — TrustZone gateway (lane TZGW) — F5–F8

### F5 — [TZGW-1] ICACHE and RAMCFG are NS-attributed — the SECCFGR3 "crypto allowlist, OTG-only exception" claim is false
- **Severity:** medium
- **Evidence label:** PoC (attribution) / suspicion, unverified (RAMCFG-erase semantics)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:trezor-port tz-3 (RCC/PWR/SYSCFG SECCFGR programming, OPEN); findings:sweep-2026-07-14 F3 (RCC/PWR never established, DEFERRED). Same "GTZC peripheral attribution incomplete" family, but ICACHE/DCACHE1/RAMCFG in SECCFGR3 are not named by any digest row; the falsified "crypto allowlist" audit claim is new.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/sau.rs:415-424` pins `SECCFR3_IMAGE` to bits 11–15 only (AES/HASH/RNG/PKA/SAES), and `sau.rs:284-293` documents "OTG (bit 10) stays NS" with every other peripheral dismissed as "irrelevant to the threat model" (`sau.rs:377-379`). The playbook's TZ6 row repeats this as "default-secure allowlist".
- Bit map of `GTZC1_TZSC_SECCFGR3` on U585 (per ST HAL `stm32u5xx_hal_gtzc.h` periph-list order, anchored by the six consecutive confirmed positions OTG=10/AES=11/HASH=12/RNG=13/PKA=14/SAES=15 that PQSigner itself pins): **ICACHE_REG = bit 6, DCACHE1_REG = bit 7, RAMCFG = bit 22** — all left at the NS reset default.
- Consequences, all reachable from NS today (both ICACHE @ `0x4003_0400` and RAMCFG @ `0x4602_2000` sit inside SAU region 3 `0x4000_0000–0x4FFF_FFFF`, `sau.rs:597`):
  - NS can disable/invalidate the ICACHE at will (timing manipulation of every secure operation) and read the ICACHE hit/miss monitor counters — a coarse secure-execution trace oracle. The secure flash driver itself uses the ICACHE (`hw_platform_under_test` pins `ICACHE_BASE = 0x5003_0400` + invalidations), proving secure fetches flow through it.
  - NS can write RAMCFG (SRAM ECC config; and per RM0456 the `RAMCFG_SRAMxER` erase registers). If the erase bits are immediate-effect (my recollection; **not verified against RM0456 or silicon**), NS gets a one-write secure-SRAM1 wipe → secure-world crash — a far stronger DoS than graceful USB-wedging and a direct falsification of the "7/7 secure peripherals RAZ-fault on NS access" isolation claim (the enforcement test never covers ICACHE/RAMCFG).
- No confidentiality break (no secret readout), so invariant #4's letter survives; the peripheral-isolation breadth claim does not. Absent from the exclusion digest (tz-3 covers RCC/PWR/SYSCFG; nothing names ICACHE/RAMCFG).

### F6 — [TZGW-2] MPCBB super-block config never locked and never read-back verified — the tz-2 freeze stops one layer short
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:trezor-port tz-3 (tz-2 SAU/GTZC/AIRCR locks DONE 2026-07-03). The digest's refuted-hypotheses row ("byte-wise NSC write→MPCBB reprogram invalid") is a different, NS-side hypothesis; this is the missing secure-side CFGLOCKR1 freeze + readback. Coordinator to judge whether "tz-2 DONE" was intended to include the MPCBB lock layer.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/sau.rs:340-351` writes `GTZC.mpcbb{1,2}_cr` and the SECCFGR banks; `lock_security_config` (`sau.rs:521-558`) then freezes SAU (`LOCKSAU`), AIRCR (`LOCKSVTAIRCR`) and TZSC (`TZSC_CR.LCK`) — but **never writes `MPCBBz_CFGLOCKR1`**, the per-super-block lock the hardware provides (confirmed present via ST HAL `HAL_GTZC_MPCBB_LockConfig`/`CFGLOCKR1`). The unconditional `verify_or_halt` readback (`sau.rs:445-450`) covers only TZSC SECCFGR1–3, not the MPCBB banks.
- tz-2's stated purpose is to stop "a fault flip or a stray secure-world write [from] re-classify[ing] secure SRAM as NS" — but the SRAM re-classification surface itself (MPCBB) remains writable post-boot.
- Mitigants that cap severity: MPCBB SECCFGR is secure-only writable (ST HAL doc: "Secure and non-secure attributes can only be set from the secure state when TZEN=1"), and even a flipped MPCBB1 doesn't open SRAM1 to NS because the SAU default-secure attribution of `0x2000_0000` is locked and load-bearing. ST's own template also ships unlocked. Digest's "tz-2 SAU/GTZC/AIRCR locks DONE" doesn't name the MPCBB lock; treat as DiD gap.

### F7 — [TZGW-3 / RUN-2] Production veneers run without `HandlerGuard`; preemption by idle-wipe+PendSV aliases the `SE`/`DISPLAY`/`STATE` singletons
- **Severity:** medium
- **Evidence label:** PoC (schedule); concrete corruption suspicion, unverified
- **Lane verdict:** KEEP — **MERGED CROSS-LANE DUPLICATE** (reported independently by lanes TZGW and RUN; one entry, both lanes credited). work-todo:X17-TZ2 is prodtest-scoped and fence-bounded; findings:lcr-2026-07-14 F2 (FW_STATUS/ABORT guard) is FIXED and FW-specific. No digest row covers the unguarded *production* handlers.
- **Status:** 🔲 OPEN

Evidence (TZGW lane):

- `nsc/mod.rs:1478` (`nsc_get_remaining_attempts`), `:1531` (`nsc_is_unlocked`), `:1541` (`nsc_lock`), `:1596` (`nsc_tzic_status`) call handlers with no `HandlerGuard::enter()` (grep over `secure/src/nsc` shows all long handlers hold it; these four don't). Only `cmd_get_remaining` (`cmd_get_remaining.rs:20-37`) does real work — an SE-driver `remaining_attempts()` I²C call plus a `with_state` write.
- The SysTick idle-wipe (`main.rs:3849-3858`) gates on `!handler_is_busy()`, so an idle expiry mid-`get_remaining` runs `zeroize_sensitive_state()` (incl. `SE.zeroize_caches()`) underneath the in-flight SE transaction, then PendSV (`main.rs:3927-3999`) runs the full re-unlock (`gated_unlock` + more SE I²C) while the suspended handler resumes into a zeroed session. Effects seen are fail-safe (torn session → transport error, one garbage response); no secret leak produced, and the PIN-attempt pre-commit happens after session re-init, so no attempt burn. The concrete issue is the overstated "guard covers every veneer" invariant and the Rust-aliasing race on `static mut SE`. X17-TZ2 tracks only the *prodtest* missing guards, not these four.

Evidence (RUN lane):

- `HandlerGuard::enter()` is called inside the guarded handlers only (nsc/mod.rs:950); `cmd_get_remaining.rs:20-37` (takes `&mut *addr_of_mut!(crate::SE)` at :23 + page-124 flash read), `cmd_lock.rs:11-15` (`zeroize` + `ui::show_status` on `static mut DISPLAY`), `cmd_is_unlocked.rs:10-16` (`&STATE`) take **no guard**.
- Schedule: NS tight-loops `nsc_get_remaining_attempts` (nsc/mod.rs:1478, no PIN required). At the single SysTick where `idle_for()` crosses 120 s, `is_idle() && is_unlocked() && !handler_is_busy()` (main.rs:3849) is true mid-veneer → SysTick zeroizes state, sets PENDSVSET; on SysTick exit PendSV tail-chains and preempts the suspended veneer for minutes. PendSV's `gated_unlock` (main.rs:3966-3967) drives the *same* `static mut SE` (page-124 flash bump, SCP03/shielded session re-establishment) and `enter_pin` drives the same `static mut DISPLAY`/`INPUT` (ui/mod.rs:152-177) and `with_state` (state.rs:356-361) — two simultaneously-live `&mut` to each: hard UB, and a direct violation of the "single-threaded non-reentrant dispatcher" invariant that every category-5 SAFETY comment cites.
- Demonstrated outcomes today are benign-ish (the preempted handlers are idempotent; GET_REMAINING recomputes over post-re-unlock values; LOCK's zeroize-after-re-unlock still ends locked), so concrete corruption is **suspicion, unverified** — but the broken invariant is load-bearing for every `static mut` in the gateway, and any future non-idempotent field added to these handlers inherits the hole. NS can align the idle-crossing deterministically, so reachability is not probabilistic.

### F8 — [TZGW-4] `sau.rs` asserts SECCFGR4 exists and is "left untouched"; U585 has no SECCFGR4 — and TZIC IER4=0 makes AHB3 NS probes silent
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP — no digest row names SECCFGR4 or TZIC IER4 masking (tz-3 covers RCC/PWR/SYSCFG; the playbook TZ6 residual inherits the same factual error, which is part of the finding).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `sau.rs:470-472`: "SECCFGR4 is left untouched (AHB3 peripherals stay at their NS reset default...)". The U585 `GTZC_TZSC_TypeDef` (CMSIS `stm32u585xx.h`) has only `SECCFGR1..3` at 0x10–0x18; offset 0x1C is reserved. The playbook's TZ6 residual ("TZSC_SECCFGR4 (AHB3) ... at NS reset default") inherits the same factual error. AHB3 peripherals on this die are hardwired or self-governed (TZIC is "accessible only with secure privileged transactions" per ST HAL; FLASH via its own watermark; GPDMA via its own SECCFGR). The comment is benign but the audit model is wrong.
- `sau.rs:473` calls `tzic::configure(seccfgr1, seccfgr2, seccfgr3, 0)` — IER4 mask 0, so NS probes of FLASH/GPDMA1/GTZC registers are blocked but raise no violation event (no forensic signal). Instrumentation gap only.

## Findings — Clear signing (lane CS) — F9–F12

### F9 — [CS-1] `personal_sign` message rendering is non-injective: `?`-substitution for non-printables + trailing-whitespace invisibility + no byte length
- **Severity:** medium
- **Evidence label:** PoC (reasoning trace, verifiable)
- **Lane verdict:** KEEP — no digest row covers the personal-sign sanitization path (offchain-raw32-downgrade is the RAW32 blind tier; cs-2026-07-10 F4's FIXED display-formatting row is a different path).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

The signature commits to the exact payload bytes (`personal_sign_replay_safe_hash(chain_id, wallet_addr, payload)`, `secure/src/nsc/cmd_sign_offchain.rs:844`), and the wire layer enforces only a length cap (`cmd_sign_offchain.rs:202-206` — no content gate, despite `docs/companion/usb-protocol-v2.md:258` documenting "UTF-8 message"). The renderer maps every non-printable byte to `?` (`secure/src/tx/display/eip1271.rs:493-503` `sanitise_byte`, used at `:404-406`) and space-pads rows with no length field anywhere (`write_msg_footer`, `:580-601`, shows only "Msg N/M"). Concrete collisions over the signed bytes: payload `"a\x01b"` and `"a?b"` paint pixel-identical pages; `"abc"` (3 B) and `"abc "` (4 B) both paint one "Msg 1/1" page with identical rows (trailing space is indistinguishable from row padding). So page renders X while the signature commits to Y, the lane's cardinal failure. The mandatory ERC-8213 fingerprint page (`calldata_digest(payload)`, `cmd_sign_offchain.rs:923-933`) binds the bytes but only as a hash the user must cross-check off-device against a dapp that shows text, not a hash — the human-readable pages are what the user actually confirms. The project's own stricter sibling demonstrates the expected fix: `render_dynamic_bytes` rejects non-printable and >32-byte strings outright (`pqsigner-erc7730/src/display/render/formatters.rs:1629-1631`), and renders an exact byte-length row. Not in the exclusion digest (no personal-sign/sanitization/glyph items; RAW32 downgrade item is a different surface).
- Lane caveat on exploit dependence: requires a verifying party that parses the personal-sign message with a normalization the display hides (control-byte stripping, C-string termination, whitespace collapsing) — plausible for dapp backends but unproven against any concrete verifier; severity could reasonably be graded medium-low.

### F10 — [CS-2] ERC-20 token amounts and legacy fee prices still round at ≤6 fraction digits — no exactness gate, unlike the native/ERC-7730 paths
- **Severity:** low
- **Evidence label:** PoC (concrete values)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:X17-CS1 (native-value exactness, source-CLOSED — scoped to native value); findings:cs-2026-07-10 F4 (display formatting non-injective, FIXED); STATUS:PQ1-V5/V6 exact-value remediation (native + ERC-7730 arms). The token-amount/legacy-fee rounding paths are not named in any row, but the coordinator may consider "documented deliberate rounding" an accepted dust-bounded tradeoff.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`write_token_amount_two_rows` (`pqsigner-erc7730/src/display/primitives.rs:980-1003`) formats with `frac = min(decimals, 6)` and `format_decimal` rounds half-up (`tx-core/src/eip1559.rs:207-234`); the ERC-20 known renderer paints it with no `amount_is_exact_at_fraction_digits` gate (`secure/src/tx/display/erc20_known.rs:99-106`), footer `"> next"` on `AmountFit::Full`. PoC: WETH `transfer(addr, 1_000_000_400_000_000_000)` and `1_000_000_490_000_000_000` both paint `"1.000000 WETH"`; `1_000_000_500_000_000_000` paints `"1.000001 WETH"` (display overstates). Distinct signed amounts share a page; the sign-more-than-shown direction hides ≤5e-7 token units per display (dust — ~$0.50 on a $1M transfer). Same family, same lack of gate: CoW legs/fee (`write_cow_leg_amount`, `primitives.rs:1018-1043`) and the legacy fee pages (`write_gwei`/`write_tip_row`/`write_native_fee_budget_row`, `primitives.rs:723-835`) used by value_transfer/erc20/typed_call/blind renderers — fee prices are signed fields and are only ever shown rounded on non-ERC-7730 paths (the exact handler gas-lane page covers gas *limits*, not prices). The exactness-or-refuse standard was applied to native value (`build_native_value_page`, `secure/src/tx/display/value_page.rs:283-302`, X17-CS1) and all ERC-7730 amount arms (`require_scaled_amount_exact`, `formatters.rs:85-91`) but not here; playbook CS4's "DEFENDED" claim is carefully scoped to those same two sets, so this is a genuine coverage gap rather than a falsified catalog row. Rounding is documented as deliberate ("Round to nearest instead", `eip1559.rs:196-202`), so this may be an accepted dust-bounded tradeoff — flagging since it is not in the exclusion digest and is asymmetric with the current standard.

### F11 — [CS-3] `ownerIndex` (= `slot_index + 1`) is signed but never displayed on ordinary UserOp signs
- **Severity:** low
- **Evidence label:** PoC (code citation)
- **Lane verdict:** KEEP — work-todo:wire-v2-slot-rotation concerns the Type-1 *response* omitting `newSlotPk` — a different issue; no digest row covers signed-but-undisplayed `ownerIndex` on Type-2 signs.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`t2_owner_index = (slot_index as u64) + 1` (`secure/src/nsc/cmd_sign_userop.rs:1828`) is ABI-encoded into the signed `executeWithOffchainCount(ownerIndex, …)` calldata (`aa/src/userop.rs:172-174`) and into the SignatureWrapper (`cmd_sign_userop.rs:2399`). `slot_index` is companion-supplied per invariant #8. On a normal Type-2 sign the page set is renderer pages + signer/target/native-value/gas-lane/nonce-lane/paymaster/fingerprint pages; the slot appears only on the slot-rotation page (`secure/src/tx/display/slot_rotation.rs`, REGISTER_SLOT only) — grep confirms no other slot display in `tx/display/`. Two UserOps identical except `slot_index` paint byte-identical confirmation sets. Impact is budget hygiene, not direct theft: a hostile companion concentrates signatures on one few-time slot (65536-use on-chain cap; SPHINCS+ few-time margin degrades per key) or burns an unregistered slot (UserOp fails), with no on-screen signal. Note the asymmetry: the off-chain EIP-1271 pages do show `Slot: N` (`eip1271.rs:528-540`). Not in the exclusion digest.

### F12 — [CS-4] ERC-20 header/name silently truncated with no `~` marker
- **Severity:** low
- **Evidence label:** PoC (code citation)
- **Lane verdict:** KEEP — findings:cs-2026-07-10 F12 (verified-name truncation, FIXED) is a different data path (verified-name records vs ERC-20 bundle header); the sibling renderers' marker/refusal convention makes this an inconsistency, not the tracked collision.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`write_erc20_header` truncates the token symbol to the remaining row with no truncation marker (`pqsigner-erc7730/src/display/primitives.rs:963-967`: `"Approve LONGSYMBOL…"` → `"Approve LONGSYMB"` for a >8-char symbol); `write_token_name` truncates the name at 16 cols silently (`:970-974`). Symbols/names up to 64 bytes pass the bundle verifier (`tx/src/erc20/bundle.rs:122-131`). Cosmetic in isolation — the full contract-address page follows (`erc20_known.rs:111-116`) — but inconsistent with the sibling renderers that either refuse ticker truncation or mark it (`write_unlimited_rows`, `write_label_row` with `~`). Not in the exclusion digest (F12 concerns verified-name records, a different path).

## Findings — SCA / fault injection (lane SCAFI) — F13–F18

### F13 — [SCAFI-1] OPTIGA Shielded-Connection CCM tag check is a single-skip plain-bool gate with a hand-rolled compare — the exact fault class the SCP03 twin was F-28/F-29-hardened against
- **Severity:** medium
- **Evidence label:** PoC (source-verified)
- **Lane verdict:** KEEP — work-todo:F-28/F-29 rows are SCP03-scoped and FIXED; OP17-* covers replay/wipe/verdict-confusion, not the shield tag gate. Same fault class, different component, live today.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/optiga/shield.rs:704-762`: `aes128_ccm_decrypt` writes the plaintext into the caller's `out` buffer, then verifies the tag via a hand-rolled `diff |= received_tag[i] ^ expected_tag[i]` loop returning a plain `bool`. Both release points gate on a bare `if !ok { return Err }` (`shield.rs:354` steady-state unwrap, `shield.rs:522` handshake SlaveFinished). One instruction-skip on either branch returns `Ok(plaintext_len)` with **unauthenticated** plaintext released to the APDU consumer — precisely the `[skip]` class `tools/sca` found on the SCP03 R-MAC, which was then hardened with `ct_eq_8` + recompute-inside-double-evaluated-closure + `check_true_into_sentinel` + branchless infective release mask (`secure/src/se050/scp03.rs:669-678, 734-759`). The same tunnel-level invariant (#3, every secret incl. `half_O` crosses this decrypt) got the full treatment on SE050 and nothing on OPTIGA. Bonus contradiction: `scp03.rs:523-529` documents *why* hand-rolled XOR-OR was rejected ("rustc + future LLVM can introduce vectorised early-exit"), while `optiga_under_test/pure_tests.rs:852-868` pins that same pattern in place as "constant-time". The entropy-blob path has a downstream AES-GCM + `dual_se` ct_eq guard, so the cleanest wins are non-entropy consumers (status/verdict-bearing responses). Absent from the digest.

### F14 — [SCAFI-2] Scroll-to-end WYSIWYS gate (`seen_last`) is a bare stack bool feeding the confirm sentinel — one stuck-at bit authorises signing without reaching the final page
- **Severity:** medium-low
- **Evidence label:** PoC (source-verified)
- **Lane verdict:** KEEP — findings:engagement-2026-07 F1 (UI1) hardened the confirm *result* and is FIXED; this is the unhardened *input* gate — a different variable and code site.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/ui/confirm.rs:80` (`let mut seen_last = false;`), set at `:97-99`, consumed at `:131-143`: `if seen_last { return (ConfirmResult::Confirmed, check_true_into_sentinel(|| seen_last)) }`. The sentinel is *born from the faulted variable itself* — a single bit-flip/stuck-at-1 on the stack bool makes all three reads (the `if` + both closure evaluations) read `true`, yielding `(Confirmed, OK_SENTINEL)`; every downstream gate (`cmd_sign_userop.rs:1782`, receipt `record_confirmed`) then passes. The comment at `:70-79` states the gate exists so a user can't "authorise a signature without ever seeing the security-critical pages… defeating every per-page WYSIWYS mitigation". Every other security bool in the tree got `FihBool` complement storage; this one didn't. Still requires a physical long-press + glitch, so not a remote forge. Adjacent-but-distinct to digest rows `engagement-2026-07 F1` and `work-todo:erc7730-hw-ui`; no row covers the FI leg of `seen_last`.

### F15 — [SCAFI-3] Unpublished WOTS/FORS secret intermediates never zeroized in sphincs-c10 (outside the 2026-07 zeroize-audit scope)
- **Severity:** low
- **Evidence label:** suspicion, unverified
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** STATUS:§C zeroize (zeroize-audit CLEAN, done). The lane's claim is that the audit deliberately scoped out un-named intermediates; coordinator to confirm the "done" row was not intended to close this class (or that the class is accepted given one-way chains + required S-SRAM read primitive).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`sphincs-c10/src/wots.rs:92-94,128-130` (`sk_i` per-chain secret dropped per iteration), `fors.rs:150-153,209-211` (`secret`/`s`), `merkle.rs:29,85` (512 `keygen_pk` calls per subtree build). Per sign ≈ 44k WOTS + 26k FORS 16-byte PRF secrets derived from `sk_seed` and dropped unwiped; keygen does the same for the bootstrap key. Per-iteration slot reuse means the *coherent* residue is fragmentary (last-derived chain secrets at various frame depths), but the 2026-07 audit (`docs/security/zeroize-audit-2026-07.md`) scoped itself to named buffers + `keygen`/`from_parts` and fixed exactly this class elsewhere (severity "medium / defense-in-depth", fault-dump/physical-extraction model). Exploit needs an S-SRAM read primitive; hash chains being one-way bounds the gain to extra chain preimages of the used leaves. Not in the digest (STATUS:§C-zeroize predates the audit; the audit's own framing admits the "un-named intermediates" class).

### F16 — [SCAFI-4] Durable counter commits `last_userop_count_set` / `offchain_count_promote_to` / `offchain_count_register_slot` lack the value-level read-back + sentinel the `_bump` twins carry
- **Severity:** low
- **Evidence label:** PoC (source-verified)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:X17-OC1 (commit elision under FI — different mechanism: skipped call vs missing readback inside the write); work-todo:FVX-2 (torn-QW integrity — adjacent page-123 family). Flagged same-family by the lane itself.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/hw/flash.rs:2146-2181, 2102-2130, 2031-2038` end in bare `write_entry(&qw)`; compare `offchain_count_bump:2073-2083` and `userop_sigs_bump:2233-2241` (post-write re-read + `check_true_into_sentinel`). `write_quadword_verified` verifies the QW landed *as given* — a value-fault corrupting `entry_qw`'s output (wrong slot key or count) before the write survives it. Impact is availability-direction only (wrong-high floor → stricter cap; wrong-low → on-chain monotonic revert; mis-registered slot → offchain refusal) because the few-time security counter (`userop_sigs`) *is* readback-verified. Mechanism distinct from X17-OC1 and FVX-2; flagged as same-family.

### F17 — [SCAFI-5] `gated_unlock` success path swallows `pin_attempts_reset()` failure — correct-PIN drift toward lockout/wipe
- **Severity:** low
- **Evidence label:** PoC (source-verified)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:SE17-6 (page-124 charged on post-verify InternalError); work-todo:OP17-4 (no PRL self-heal on unlock path → wedge burns page-124 to self-wipe). This exact arm (reset-failure *after a successful* verify, silent accumulation across N correct-PIN unlocks) is not named in either row.
- **Cross-reference:** SE-3 (F25) — same "reset-failure after a verified PIN aborts/penalizes the unlock" family on the OPTIGA E120 side; kept as separate findings (different chip, different counter, different failure semantics).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/nsc/mod.rs:1190-1192`: `let _ = crate::hw::flash::pin_attempts_reset();` on the success arm. A flash fault (or a skipped `bl`) leaves page-124 charged after a *correct* PIN; every subsequent unlock pre-charges again (`:1097` bump is unconditional and sentinel-enforced), so N successful unlocks accumulate N markers → spurious 10-attempt lockout → `trigger_lockout_wipe`. Fail-closed (availability) direction, but a silent self-brick path with no diagnostic. Adjacent to digest rows SE17-2/SE17-6; this exact arm is not listed.

### F18 — [SCAFI-6] `read_entropy_blob` ×3 gated by `is_true_fi()` plain bool, not the `check_sentinel` pattern FihBool's own docs prescribe for security gates
- **Severity:** low
- **Evidence label:** PoC (source-verified)
- **Lane verdict:** KEEP — no digest row covers `is_true_fi` gate idiom misuse; impact is essentially nil (fail-closed), reported as convention inconsistency.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/se050/mod.rs:2974`, `secure/src/optiga/mod.rs:3024`, `secure/src/dual_se.rs:469`: `if !self.blob_cached.is_true_fi() || buf.len() < … { return Err }`. `fih.rs:29-34` explicitly says caller branch-skip is *not* defended by `is_true_fi` and gates should use `check_sentinel`. Outcome of a skip is fail-closed (zeroed cache → AES-GCM decrypt fails → `CryptoError`), so impact is essentially nil — reported as a convention inconsistency, not a break. Not in the digest.

## Findings — Firmware update / secure boot (lane FWSB) — F19–F22

### F19 — [FWSB-1] CMD_FW_BEGIN erases 8 KB of the running monolithic image's own .text — the "cannot brick the live image" guard is inert on every bootable build
- **Severity:** medium
- **Evidence label:** PoC (built ELF + exact code path)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** findings:sweep-2026-07-14 F15 (A/B binaries not linked for physical slot addresses, DEFERRED release blocker). The lane's position: F15 covers FSBL→slot branching and the NS base, not the updater's erase set overlapping the monolithic link region; the falsified in-tree safety comments are new. Coordinator to judge whether F15's deferral already subsumes this concrete brick mechanism (both agree production is compile-fenced — hence medium, not high).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

Every current hardware image is monolithic at `0x0C000000` (F15 established A/B slot-linking doesn't exist). `secure/memory-stm32u585.x:28` gives FLASH `ORIGIN=0x0C000000, LENGTH=984K` — one contiguous region over pages 0–122 with **no holes** for manifest A (page 4), manifest B (page 5), or boot-state (page 6). Chain:
1. `running_slot()` (`secure/src/fw_update/mod.rs:424-441`) compares VTOR against `SLOT_A/B_SECURE_ADDR` (`0x0C00E000`/`0x0C082000`). On a monolithic boot VTOR = `0x0C000000` → matches neither → falls back to `read_active_slot()` → boot-state read at `0x0C00C000` (which is *inside the running .text*) → no `BSTE` magic → `Unavailable` → `Slot::A` → `inactive = Slot::B`.
2. `cmd_fw_begin.rs:190-194` then calls `erase_slot(Slot::B)`, whose final step (`secure/src/hw/flash.rs:1289`) erases `manifest_page_num(B) = 5` (`0x0C00A000-0x0C00C000`).
3. The lane built the exact FW-update image (`cargo build --locked --release -p sphincs-tz-secure --features mock-se,ui-noop,stm32u585,usb,fwup-transport-e2e` with the Makefile HW link flags): `.text` spans `0x0C000800-0x0C03DE4C` — page 5 is live code. `nm` shows two live symbols inside it: `nsc::factory_calldata::build` @ `0x0C00B24C` and `nsc::cmd_sign_userop_batch::run` @ `0x0C00B484`. Any batch-sign or initCode call after a completed BEGIN fetches `0xFF` → HardFault → reset; the damage persists across resets until SWD reflash. COMMIT's `boot_state::write` would additionally erase page 6 — also .text.

Why `make fwup-transport-hw` passes today: all FW-path functions (erase @ page 3, chunk/verify @ pages 0/7/13) happen to sit outside page 5 — pure LTO layout luck, nothing enforces it. The safety comments are falsified in-tree: `cmd_fw_begin.rs:188-189` ("erasing it cannot brick the live image") and `fw_update/mod.rs:418-419` ("VTOR cannot diverge, so the inverted slot is always genuinely inactive"). Reaching it needs PIN + two physical confirms + a manifest signed with the public in-tree dev key (bench images), and production is compile-fenced — hence medium, not high. Absent from the digest: F15 covers FSBL→slot branching and the NS base, not the updater's erase set overlapping the monolithic link region; FW8/X17-FW2 are the try-once/OTP family.

### F20 — [FWSB-2] COMMIT never resets the idle timer despite cmd_fw_chunk.rs documenting that it does
- **Severity:** low
- **Evidence label:** PoC (grep + file:line)
- **Lane verdict:** KEEP — X17-UC1 is the APDU-router lease, X17-UI3 is pin_entry; no digest row covers the FW-flow idle-timer contract.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`cmd_fw_chunk.rs:15-18`: "CHUNK does NOT reset the idle timer — BEGIN already did, and COMMIT will again." `grep reset_activity secure/src/nsc` shows it in `cmd_fw_begin.rs:223` only — not in `cmd_fw_commit.rs` at all. The 120 s window therefore spans the whole BEGIN→CHUNK*→COMMIT flow: a companion stall (or a slow ~1 MB HID transfer) mid-stream triggers the idle-wipe, drops `FW_UPDATE`, and kills the session (fail-safe, but contrary to the documented contract and a real liveness edge the companion can't code against). Absent from the digest.

### F21 — [FWSB-3] FSBL footprint CI gate silently passes when the ARM toolchain is absent
- **Severity:** low
- **Evidence label:** PoC (file:line)
- **Lane verdict:** KEEP — same test file as PRODCFG-1 but a distinct defect (test-internal skip-returns-success vs never-enrolled-in-CI); cross-referenced, both kept. Not in the digest.
- **Cross-reference:** PRODCFG-1 (F42) — same `fsbl-tests/tests/footprint.rs` file; this finding is the test-internal silent-skip defect, F42 is the never-enrolled-in-CI defect.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`fsbl-tests/tests/footprint.rs:48-54`: if `arm-none-eabi-size` isn't on PATH the test prints "skipping" and returns success *before ever building the FSBL* — a silent false-green for the 32 KB FSBL-size gate on any CI image lacking the bare-metal toolchain. Not in the digest.

### F22 — [FWSB-4] QEMU gateway never dispatches CMD_FW_* — the FW path has no dynamic host e2e at all
- **Severity:** low
- **Evidence label:** PoC (file:line)
- **Lane verdict:** KEEP — evidence-coverage gap; no digest row covers the QEMU FW dispatch absence.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/nsc/mod.rs:1381-1435` (QEMU `dispatch()`) routes 11 commands + prodtest but no FW command — they fall to `_ => InternalError`. All FW evidence below transport level is `include_str!` source-text greps (`nsc_fw_update_pure_tests.rs`, `fw_update_boot_pure_tests.rs`); the only dynamic end-to-end is on-hardware `make fwup-transport-hw`. Not a code vuln; it means layout/logic regressions in the FW path (cf. FWSB-1) can only be caught on silicon. Not in the digest.

## Findings — Secure element (lane SE) — F23–F25

### F23 — [SE-1] Post-lockout-wipe device is a permanent, unrecoverable brick — "restore from seed" is undeliverable
- **Severity:** high
- **Evidence label:** PoC (deterministic source trace)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** STATUS:S-6 (the no-admin-delete USERID policy, DONE — this is its availability consequence); work-todo:SE17-4 (duress objects survive wipe — different objects). The LIFE lane independently encountered the same mechanism and judged it "deliberate… the docs own this as the designed brick" (in-tree comment `se050/mod.rs:2307-2310`: "chip is single-use post-lockout — the OID range must be bumped") — but no digest row tracks the USERID-orphan → no-reprovision → panic-loop chain or the contradicting UI/CLAUDE.md promises. Coordinator to decide whether this is an accepted designed brick or a new HIGH.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

The advertised recovery flow deterministically panic-loops on real hardware. Chain: 10 wrong PINs → `trigger_lockout_wipe` (`secure/src/nsc/cmd_request_unlock.rs:155-176`) → `Se050::admin_factory_reset` deletes data objects but **cannot delete `USERID_OBJ`** — post-S-6 its policy has no admin-delete entry; the best-effort delete fails with SW=0x6986 and survival is explicitly accepted (`secure/src/se050/mod.rs:2230-2247`, `:2307-2310`). Next boot: `optiga.is_provisioned()=false` (F1E1 sentinel) ⇒ dual AND = false ⇒ wizard (`main.rs:3550`). The user enters a mnemonic → `dual_se.provision` → `optiga.provision` **succeeds (rewrites half_O/master)** → `se050.store_objects` hits `if userid_exists && admin_pin.is_some() { return Err(Status(0x6986)) }` (`se050/mod.rs:1873-1881`; admin_pin is `Some` on every `stm32u585` build, `:2786-2832`) → `provision_from_mnemonic` panics (`secure/src/crypto.rs:336-337`) → panic handler zeroizes and parks in WFI (`main.rs:4045-4060`) with "Provisioning ..." frozen on screen. Every power cycle repeats it. Rescue via firmware update is impossible (FW_BEGIN..COMMIT require PIN unlock, which no longer exists), and RDP-2 kills SWD. The same brick fires after **any** mid-first-boot provisioning failure (I2C glitch after USERID creation), after duress=wipe-mode entry, and after the boot-time `attempts_exhausted/wipe_armed` wipe (`main.rs:1517-1531`). Contradicts the UI contract ("WALLET WIPED — restore from seed", `cmd_request_unlock.rs:174`; "→ first-boot wizard", `main.rs:1528-1531`) and CLAUDE.md's "validated end-to-end" lockout claim (validation stops at the wipe). Lane note: QEMU cannot reproduce (admin-pin path is `stm32u585`-only); the only open empirical question is whether some un-discovered recovery path exists (none found: no runtime OID-range bump, no user-level `user_factory_reset`, fw-update PIN-gated, RDP-2 blocks SWD). The `pure_tests.rs` source-pins confirm the fail-loud guard exists and is intentional (Bug #28).

### F24 — [SE-2] Wizard-misfire on a used device destroys the live wallet before failing: destructive provision ordering + panic-on-any-error
- **Severity:** high
- **Evidence label:** PoC (source trace)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:SE17-8 (fail-open `check_provisioned` entry point, CANDIDATE) and OP17-6 (cold-boot misroute) — the *entry* into the wizard on a provisioned device is tracked; the destructive OPTIGA-first ordering + panic amplification is not.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`DualSecureElement::provision` runs `optiga.provision` **first** (`secure/src/dual_se.rs:181-184`), which rewrites F1D1/F1D2 (Change satisfied via `Conf(E140)`, `optiga/mod.rs:2666-2672`) — destroying the live half_O — and only then calls `se050.provision`, which can fail loud (orphan, transport glitch, `check_exists` error coerced to "not-exists" at `se050/mod.rs:1856-1867` then write-on-existing → chip refusal). Any error → `factory_reset_admin` + `panic!` (`crypto.rs:336-337`), so a *recoverable* error (a single I2C wedge during the wizard, a `check_provisioned` misread routing a provisioned device into the wizard) is escalated into: old half_O already overwritten, wipe re-run, device parked in WFI. The user's only remaining path is mnemonic-restore on *another* device. The fail-open `check_provisioned` entry point is already tracked (SE17-8); the destructive ordering (OPTIGA rewrite before the SE050 leg that can fail) + panic amplification is not in the digest. Fix direction: validate/recover the SE050 leg *before* any destructive OPTIGA write, and make provisioning errors recoverable instead of `panic!`.

### F25 — [SE-3] E120 ratchets on every F1D0 execute (incl. successful verifies); `reset_hw_pin_counter` is the only return path and its failure aborts the unlock post-verify
- **Severity:** medium
- **Evidence label:** suspicion, unverified
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:#25-gap2/gap5 (E120 exhaustion lockout on silicon, OPEN — same counter family); work-todo:OP17-4 (PRL-wedge → page-124 self-wipe variant); OP17-7 (E120 carry-over at re-provision). The specific claim (ratchet-on-success + reset-failure aborts a verified unlock + precharge on the InternalError path) is not named in any row.
- **Cross-reference:** SCAFI-5 (F17) — same "reset-failure after a verified PIN aborts/penalizes the unlock" family on the flash page-124 side; kept as separate findings (different chip, different counter, different failure semantics).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`authenticate_and_read` resets E120 only after the four reads succeed (`secure/src/optiga/mod.rs:2511-2517`), and a reset failure returns `Err` *after* the PIN verified OK. If the LUC increments on successful verifies (Trezor parity; the code's own silicon note only covers *failed*-verify increments, `:2305-2311`), then every successful unlock whose best-effort reset fails silently advances E120 toward its 32-lifetime limit — and each reset-failure also charges page-124 via the precharge (InternalError path). A recurring E120-write wedge converts healthy correct-PIN unlocks into lockout→wipe. Needs silicon: (a) does E120 ratchet on success? (b) can E120 writes wedge while other NVM writes succeed? Not in the digest.

## Findings — Lifecycle / persistent state (lane LIFE) — F26

### F26 — [LIFE-1] Wipe-on-duress policy silently downgrades to decoy — swallowed arm failure at provisioning + fail-open mode read at unlock
- **Severity:** medium
- **Evidence label:** PoC (source-verified, two cut points)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:OP17-8 (wipe atomicity incl. "swallowed arm" — the lane verified that arm is `arm_wipe_flag` in the factory-reset paths at `optiga/mod.rs:2616`, `se050/mod.rs:3085`, a different function and consequence); work-todo:SE17-4 (duress objects survive wipe — a completeness issue, not a silent mode downgrade); work-todo:#32-duress (LANDED + silicon-validated). Neither cut point (wizard arm-failure fallback; fail-open FI shape of the mode read) is named in a digest row, but OP17-8's wording is close enough to warrant coordinator review.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

The user explicitly answers "Wipe on duress?" = yes; the device can silently end up in decoy mode anyway, and the failure is invisible to the user (production has no log path):
- Cut point A (arm-time): `secure/src/main.rs:3601-3605` — `if hw::flash::arm_duress_wipe_mode().is_err() { secure_log!("... defaulting to decoy") }`. `secure_log!` compiles out in production (`debug-log` is bench-only). No UI warning, no retry, no abort; provisioning proceeds with page-125 QW2 left `0xFF` = decoy. Flash program faults on this exact bench silicon are documented in-tree (`secure/src/hw/flash.rs:739-745`: erase-OK/program-PROGERR "write-hostile" pages — the reason the PIN counter was moved off page 126), so the arm failure is not hypothetical. The flash.rs:671-675 docstring itself calls this state a "silent downgrade of the user's chosen protection" but only the *ordering* was fixed (pinned by `main_sau_pure_tests.rs:1338`), not the *error* path. There is also no post-arm readback/confirmation screen (`ui/seed_wizard.rs:211-213` returns the bare yes/no).
- Cut point B (read-time, FI): even when armed, `secure/src/nsc/mod.rs:1144-1158` shapes the branch as `if wipe_mode { wipe } else { duress_pad; Ok(m) }`. A single glitch on the `is_duress_wipe_mode()` read (`flash.rs:691-695`, a plain `== 0x00` byte read, no sentinel/double-read) or a skipped compare falls into the decoy branch — the inverted FAIL-OUT shape the project's own F-15 idiom prohibits (`cmd_request_unlock.rs:100-118`: bypass-target must be the explicit conditional, secure default the fall-through; here the bypass-target *is* the fall-through).

Breaks the duress-wipe security claim (§32 P5) exactly when invoked under coercion: user enters the duress PIN expecting destruction, the decoy opens, the real wallet survives behind the real PIN.

## Findings — Entropy / key lifecycle (lane ENT) — F27–F29

### F27 — [ENT-1] rng_strong multi-chunk fold reuses the previous chunk's SE block
- **Severity:** low
- **Evidence label:** PoC (code trace, latent)
- **Lane verdict:** KEEP — playbook EK5 names this drift but playbooks are not digest sources; no rng-* digest row covers the multi-chunk stale-block fold. Latent (every current caller requests ≤ 32 B).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/rng_strong.rs:82-104` never clears `block` between outer chunks, while the SE contribution (`DualSecureElement::random`, `secure/src/dual_se.rs:553-581`) XORs into the caller's buffer instead of overwriting it. For a 48-byte request: chunk 1 leaves `block = O1⊕E1`; chunk 2 folds fresh `O2⊕E2` into that stale block, so `buf[32..48] = STM32[32..48] ⊕ O1[..16] ⊕ E1[..16] ⊕ O2 ⊕ E2`. A repeat-stream fault on both SE TRNGs (`O2=O1[..16]`, `E2=E1[..16]`) silently cancels the SE contribution for the tail — 3-source degrades to platform-only with no alarm (the all-zero gate spans the whole buffer and passes on the STM32 bytes). Verified live in source; **latent** — every current caller requests ≤ 32 B (OptRand 16, shuffle/entropy/salt/OTP-master 32, mask seed 4), so no live key compromise. Fix: clear `block` per chunk or make `DualSecureElement::random` overwrite.

### F28 — [ENT-2] shuffle.rs doc comment inverts the implemented F-16 defense
- **Severity:** low
- **Evidence label:** PoC (comment vs code)
- **Lane verdict:** KEEP — comment-only hazard; no digest row.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`sphincs-c10/src/shuffle.rs:29-32` states the seed is "fed to BOTH double-compute signs unchanged (re-drawing per sign would break the F-13 byte-equality FI gate)". The actual implementation (`secure/src/crypto.rs:178-191`) draws **independent** `shuffle_seed_a`/`shuffle_seed_b` per pass and documents why a shared seed is strictly worse for both SCA (aligned traces) and FI (same-position HASH fault slipping ct_eq). A maintainer "simplifying" per the stale comment would reintroduce the shared-seed weakness the code deliberately closed. Comment-only today; not in the exclusion digest.

### F29 — [ENT-3] hw::huk::derive_device_key — DHUK-flavored public API actually rooted in OTP-master, zero callers
- **Severity:** low
- **Evidence label:** suspicion, unverified (foot-gun class)
- **Lane verdict:** KEEP — work-todo:#7-three-tier tracks the real DHUK/BHK/OTP axes and legacy-helper removal; #20-confirms tracks DHUK-at-RDP0 behavior. Neither covers this dead-but-loaded public API.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`secure/src/hw/huk.rs:93` derives `SHA256("pqsigner-device-key-v1" ‖ len ‖ tag ‖ UID ‖ otp_master)`. Its own doc admits it is *not* the silicon DHUK and is regenerable by any secure-world reader. Grep shows no production callers (only doc references in `secret_keys.rs` / `pq-seal`). Not a live break; the risk is a future caller treating it as a hardware-rooted key and sealing something that RDP-2+secure-world-RCE is supposed to protect. Not in the digest.

## Findings — Secure runtime / resources (lane RUN) — F30–F33

> Lane note: **[RUN-2] was merged into F7 ([TZGW-3 / RUN-2])** — the same
> unguarded production veneers and root cause were reported independently by
> the TZGW and RUN lanes and are kept as a single entry crediting both.

### F30 — [RUN-1] No exception-priority programming exists anywhere — the idle-wipe→PendSV re-unlock starves SysTick (guaranteed IWDG false-bite in production) and blocks tamper escalation
- **Severity:** high
- **Evidence label:** PoC
- **Coordinator re-verification:** ✅ re-verified on HEAD `89c60063` — repo-wide grep across `secure/src`, `nonsecure/src`, `fsbl/src`, `hal/src` confirms **zero** `set_priority` calls (only test comments mention priorities); corroborates the no-exception-priority-programming claim. See "Coordinator verification" above.
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:#17-power (IWDG setup, NOT STARTED — broad umbrella); findings:sweep-2026-07-14 F2 (IWDG NS-alias, DEFERRED). No digest row addresses exception priorities (SHPR/NVIC IPR), the re-unlock starvation, or tamper-IRQ preemption blocking; coordinator to judge whether the #17-power umbrella was meant to cover priority programming.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/main.rs:3853` ("PendSV has the lowest priority so it won't block SysTick"), `main.rs:3916-3918` ("Runs at the lowest exception priority … The blocking PIN entry UI is safe here") are false. Repo-wide grep for `SHPR`, `0xE000_ED18..ED23`, NVIC `IPR` (`0xE000_E4xx`), `set_priority`, `pre_init`: zero hits. `setup_systick` (main.rs:714-727) writes only SYST_CSR/RVR/CVR; `sau.rs:524-538` touches only AIRCR PRIS/BFHFNMINS/SYSRESETREQS. Reset value of SHPR3 is 0 → **PendSV, SysTick, TAMP-IRQ(2), GTZC-IRQ(8) all run at priority 0**, and equal-priority exceptions cannot preempt each other.
- Chain: 120 s idle → SysTick zeroizes and pends PendSV (main.rs:3849-3858) → PendSV runs the blocking PIN re-unlock loop (main.rs:3947-3999) for a user-paced duration (minutes). During the entire dialog: `timeout::tick()` never runs (idle timer frozen — the dialog's own `IdleWipe` exit is dead, pin_entry.rs:88 depends on it), and `iwdg::systick_watch_and_kick` never runs.
- Production profile (`Makefile:2244` PROD_SHIP_FEATURES) ships `iwdg` (+`tamp`,`tamp-wipe`,`tzic-wipe`, no `tamp-irq`; `ui-lcd` implies `gpio-buttons` so the dialog stays interactive via busy-poll, buttons.rs:188). IWDG last kicked at the wipe tick fires RLR=250@/256 ≈ 2 s (1–3 s LSI tolerance, iwdg.rs:105-114) → **every production idle-wipe resets the chip ~2 s into the re-unlock dialog, before an 8-digit PIN can be entered on a 2-button UI**. The designed "seamless re-unlock" (main.rs:3854-3856) never works; RT6's "watchdog false-bite … a reset loop can strand funds" applies (fail-safe direction: secrets were already wiped; user re-unlocks at the boot prompt).
- Same root cause starves the tamper layer: polled TAMP (`tamp::poll` from SysTick) stops, and the armed GTZC IRQ-8 (`tzic-wipe` production escalation, `tzic::on_violation` → `trigger_intrusion_wipe`, priority 0) cannot preempt PendSV — the "latency-critical" intrusion response is unboundedly delayed behind a user-paced dialog while SE shares are still intact on-chip.
- Corollary: the HIGH-8 re-entry guard (main.rs:3920-3924, `PENDSV_IN_FLIGHT`) defends against "SysTick re-pends PendSV while PendSV runs" — impossible at equal priority; the guard is dead code for today's build and the real interleaving (starvation) is unhandled. The pure test `main_sau_pure_tests.rs:1176` pins the comment's assumption text, not silicon behavior.
- Absent from the exclusion digest. Playbook RT3 hypothesized exactly this ("no SHPR/SCB priority programming was identified — require a receipt"); confirmed against source. Lane severity note: availability/mechanism-break with a tamper-response delay, not key exposure — the idle wipe itself works, post-reset boot re-locks cleanly; the tamper-starvation sub-impact assumes an attacker who can trigger GTZC/TAMP events during the re-unlock dialog, and SRAM secrets are already wiped in that window, so the delayed piece is the SE-share destruction, not SRAM secrecy.

### F31 — [RUN-3] IWDG coverage gaps: no watchdog at all before post-unlock `init()`, unbounded kick-forever boot grace, re-callable heartbeat registration
- **Severity:** medium
- **Evidence label:** PoC
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:#17-power (IWDG setup NOT STARTED umbrella); findings:sweep-2026-07-14 F2 (NS-alias kick, DEFERRED); findings:engagement-2026-07 F3 (heartbeat validator FIXED — a different heartbeat issue). The three enumerated gaps (boot-phase coverage, unbounded grace, re-registration latch) are not named in any digest row.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `iwdg::init()` runs at main.rs:3772 — *after* the user-paced seed wizard, provisioning, and PIN unlock (SysTick runs from main.rs:1225). A wedge during first-boot SE provisioning (cf. digest SE17-11: no I2C stuck-bus recovery, minutes-scale transceive) hangs forever with no watchdog backstop; the wizard's only documented recovery is restart-from-PIN-entry on dialog results, not a hang.
- `systick_watch_and_kick` treats `NS_HEARTBEAT_ADDR == 0` as unconditional `kick(); return;` (iwdg.rs:225-230). If NS never registers — torn/missing NS image (bank-2 flash is independently written), NS fault before `register_heartbeat`, or registration REJECTED (nonsecure/main.rs:182-186 logs and *continues*) — the secure world feeds the IWDG forever: the watchdog is silently dead for the rest of the session, including for genuine secure hangs. This is a designed grace path with an unbounded tail and no time bound.
- `nsc_register_heartbeat` (nsc/mod.rs:1556-1574) is re-callable at any time — no once-only latch — so NS can re-point the heartbeat window post-boot (validated, so impact is limited to feed-semantics, but it contradicts the "called once at boot" contract).
- Playbook RT6 lists these as "coverage gaps"; the digest's nearest row is the broad `#17-power` umbrella and the excluded NS-alias F2 — the boot-phase gap, the kick-forever grace, and re-registration are not enumerated there.

### F32 — [RUN-4] SysTick `kick()` can interleave the `iwdg::init()` KR sequence and silently drop PR/RLR programming
- **Severity:** low
- **Evidence label:** suspicion, unverified (KR-access semantics need RM0456 confirmation)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:#17-power (same umbrella question as RUN-3). This specific race falsifies an in-code SAFETY argument; not named in any digest row.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `iwdg::init()` (iwdg.rs:175-184) runs with SysTick already live (main.rs:1225 → 3772). Its SAFETY note (iwdg.rs:84-87) claims "SysTick never re-enters itself, so there is no aliasing between the two writers" — but the SysTick boot-grace path (addr==0) writes `KR=0xAAAA` and can land between `KEY_ACCESS (0x5555)` and the `PR`/`RLR` writes. Per windowed-IWDG KR semantics, a non-0x5555 write revokes PR/RLR write access → `PR=6`/`RLR=250` silently ignored → watchdog runs at reset defaults (~0.5 s @/4, RLR=0xFFF) while the design and all liveness math assume ~2 s. Fail-safe direction (shorter timeout), and the interleave window is cycles-wide per boot — but it falsifies the safety argument and, if the KR semantic holds on U585, means the fleet runs a different watchdog timeout than reviewed. Flagged by playbook RT9 as a "CURRENT IWDG ORDER TARGET"; not in the digest. The unbounded `while SR & 0b111` spin (iwdg.rs:181) is a second, fail-safe (reset-loop) boot hang if LSI never propagates.

### F33 — [RUN-5] Unexpected-IRQ `DefaultHandler` arm and the absent NMI handler park the CPU in WFE forever with secrets resident — no zeroize
- **Severity:** low
- **Evidence label:** PoC (code path), reachability conditional
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:FVX-3 (torn-QW ECC read: silent-skip vs NMI crash-loop — touches the missing NMI path from a different angle); work-todo:#21-tamp-css_pvd (ECCD NMI enabling, NOT STARTED — adjacent). The DefaultHandler-arm-without-zeroize half has no digest row.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `DefaultHandler` unmatched arm (main.rs:3899-3907): log + `loop { wfe() }` — no `zeroize_sensitive_state()`, unlike HardFault (4031-4040) and panic (4044-4060). Any unexpected/unmasked NVIC line (bug, glitch, future contributor forgetting the documented dispatch-arm contract at 3882-3885) parks the secure world with `master_secret`/`SLOT_CACHE` live; production IWDG resets ~2 s later into the abnormal-reset zeroize, but non-`iwdg` builds park indefinitely. Same for NMI: no `fn NMI` exists anywhere, so an NMI lands in cortex-m-rt's default infinite loop with no wipe (today no NMI source is armed; digest `#21-tamp-css_pvd` tracks enabling CSS/ECCD-NMI — this is the missing handler that work would need, adjacent but not identical).

## Findings — Off-chain signing (lane OFFCHAIN) — F34–F37

### F34 — [OFFCHAIN-1] MAX_OFFCHAIN_GAP is companion-resettable at zero on-chain cost — "≤100 unbacked sigs" claim is false
- **Severity:** medium-low
- **Evidence label:** PoC (reasoning trace, verified against source)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:P1.5-residual (few-time margin has no on-chain cap + torn page-123 reset — OPEN quantification; same budget-quantification family, different mechanism: sign-time `last_userop` commit without publication proof); work-todo:X17-OC1 (FI commit-elision — different). The lane's real-world caveat: extraction needs ~1 physical confirm per sig, so the bite is the falsified invariant/quantification, not a practical drain.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `cmd_sign_userop.rs:2417` durably sets `last_userop_count := new_offchain_count` at **sign time**, with no proof the UserOp is ever submitted/executed; identical commit in the batch path (`cmd_sign_userop_batch.rs:2445`). The gap gate is `gap = local − last_userop ≥ 100 ⇒ refuse` (`aa/src/offchain_gate.rs:141-143`, invoked at `cmd_sign_offchain.rs:340`).
- Cycle: 100 off-chain sigs (gap hits 100) → one user-confirmed `CMD_SIGN_USEROP` → companion **discards the sig** (or submits with a reverting nonce) → `last_userop` catches up, gap = 0. Repeat ≈648×: ~64,800 EIP-1271 sigs, on-chain `offchainSigCount` stays 0, one intact device, no FI, no state loss. Device combined cap (`userop_sigs + local ≤ 65,536`) still binds the total, so this is not margin erosion on one device — but the falsified claims are specific: CLAUDE.md invariant #9 "Refuses to sign past `MAX_OFFCHAIN_GAP = 100` unbacked sigs"; playbook header "bounds unbacked sigs at MAX_OFFCHAIN_GAP=100"; playbook OC4 "DEFENDED"; `cmd_sign_offchain.rs:30-33` "so the next UserOp **definitely publishes** the count". The gate test `userop_advances_last_userop_and_closes_gap` (`offchain_gate.rs:467`) pins the "signed == published" semantic.
- Playbook OC9 half-anticipates "withheld publishing UserOps" but only to claim `userop_sigs` bounds them; it never retracts the 100-bound. The TLA pilot `docs/verification/fv-pilot-combined-budget-lifetime-2026-07-17.md:87` quantifies erosion as "resets × MAX_OFFCHAIN_GAP", missing this no-reset desync source (non-publication leaves `offchainSigCount`=0 while 65,535 valid sigs exist; combined with one restore this is strictly worse than the modeled residual). Not in the exclusion digest (P1.5 covers torn-reset + no-on-chain-cap; X17-OC1 covers FI commit-elision; neither states the gap is companion-resettable). Whether `last_userop` should advance only via a (still lie-able) SYNC is an owner design decision.

### F35 — [OFFCHAIN-2] Post-restore re-registration needs no Type-1 rotation — any UserOp sign or a SYNC-0 confirm registers the slot
- **Severity:** low
- **Evidence label:** PoC (file:line trace)
- **Lane verdict:** KEEP — no digest row covers registration-semantics-via-value-write; distinct from P1.5-residual (budget reset) and from the tracked SYNC consent-gate work.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- Registration = journal-entry existence (`offchain_state.rs:240-245` F13; flash `is_registered_*` `flash.rs:1996-2023`), and **every value-write creates an entry**: `last_userop_count_set(k,0)` on an unknown slot skips both early-outs (`flash.rs:2166-2177`) and writes a `USEROP,0` entry; `userop_sigs_bump` writes unconditionally (`flash.rs:2216-2232`). `cmd_sign_userop.rs:2417/2437` runs both after *any* successful Type-2 sign — `offchain_count_register_slot` is the only call gated on `register_slot` (`:2404`). `cmd_offchain_sync.rs:153-204` confirms then registers a brand-new slot even at target 0.
- Falsifies: invariant #9 / playbook OC6 / `cmd_sign_offchain.rs:39-42` "forces a Type-1 rotation via CMD_SIGN_USEROP first" — a normal Type-2 sign (or one innocuous SYNC confirm) satisfies the gate with **no bootstrap sig spent**. This also breaks the TLA pilot's mitigation (`fv-pilot-combined-budget-lifetime-2026-07-17.md:79-82`): "each reset unregisters the slot, so invariant #9 forces a Type-1 re-registration, which spends the bootstrap few-time budget — bounding the number of resets" — resets are not bounded by `MAX_BOOTSTRAP_USES`. Aggravating consent gap: the SYNC-0 confirm (`tx/display/offchain_sync.rs:43-74`) shows "Current: 0 / Target: 0" and never discloses that it durably registers the slot and burns one of the 128 device-lifetime distinct-slot slots (`MAX_DISTINCT_SLOTS`, `offchain_state.rs:64`). Real theft impact is nil (sigs for never-on-chain-registered slots fail `isValidSignature`); it is a claimed-enforcement that does not exist. Not in the digest.

### F36 — [OFFCHAIN-3] ERC-6492 counterfactual path is a second bootstrap-key few-time release channel with no bootstrap-side tally
- **Severity:** low
- **Evidence label:** PoC (file:line trace)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** findings:sweep-2026-07-14 accepted (CMD_GET_INIT_CODE unlock-gated few-time bootstrap oracle — ACCEPTED). The lane itself grades this strictly weaker than the accepted case (same fixed digest, confirm-gated); kept only because the "no bootstrap-side tally on the 6492 channel (65,535 same-message sigs without a single deployment)" quantification is not in the digest. Coordinator may reasonably drop it into the accepted row.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- Every `account_deployed=0` call signs the fixed `addSlot0Digest(chain)` with the **bootstrap** key inside `factory_calldata::build` (`cmd_sign_offchain.rs:1362-1375` → `factory_calldata.rs:77-108`) and emits it in the blob; the only budget consumed is the **slot-0** combined counter (§13 bump). Bootstrap few-time usage is on-chain-capped only when deployments actually execute (`bootstrapUses < MAX_BOOTSTRAP_USES`); up to 65,535 same-message bootstrap sigs per (account, chain) can be released without a single deployment. Same fixed digest as the accepted `CMD_GET_INIT_CODE` oracle, and this path is confirm-gated, so it is strictly weaker than the accepted case — recorded for completeness as an uncounted channel, not a re-report.

### F37 — [OFFCHAIN-4] page-123 slot keys are seed-independent — cross-seed registration/counter inheritance
- **Severity:** low
- **Evidence label:** PoC (file:line trace)
- **Lane verdict:** KEEP — seed-independence is deliberate (brick defense must survive seed restore) but the cross-seed inheritance consequence is documented nowhere and absent from the digest.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `slot_key_compute` (`offchain_state.rs:23-33`) = `SHA256(account‖chain‖slot)[..8]`, no seed/wallet binding (deliberate: the brick defense must survive seed restore). A device re-provisioned with a **different** seed inherits all registrations and counters: the post-restore gate (OFFCHAIN-2's remaining purpose) is silently satisfied for the new seed, and the new seed's per-slot budgets are pre-burned (DoS direction only — monotonic over-counting is few-time-safe). Documented nowhere the lane could find; the VULN docs note seed-independence only as a brick-survival property. Not in the digest.

## Findings — On-chain contracts (lane CHAIN) — F38

### F38 — [CHAIN-1] contracts/verity Lean model silently drops H-3 parity, the transient credit, and the H-2 self-call block relative to the deployed wallet
- **Severity:** low
- **Evidence label:** PoC (file:line divergence, verified)
- **Lane verdict:** KEEP — fv-coord F1–F11 cover freshness/axioms/labels, not verity model content; the onchain-contracts digest rows (SOL6/SOL9/hevm/kontrol) do not name this divergence. Direction is model-more-permissive-than-contract, so soundness of what verity proves is preserved — the issue is unflagged model-content drift in `TRUST_ASSUMPTIONS.md`'s "dispatch correctness" row.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `contracts/verity/PQSigner/PQSmartWallet.lean:169-187` (slot branch of `validateUserOp`) checks only `isSlotAllowedSelector` + combined cap; the H-3 conjunct `selector != removeOwnerAtIndex ⇒ calldataOwnerIndex == ownerIndex` present in the real contract at `contracts/smart-wallet/src/PQSmartWallet.sol:469-474` is absent. `executeWithOffchainCount` at `PQSmartWallet.lean:225-236` likewise omits `_consumeValidatedCredit` (`PQSmartWallet.sol:247`) and `SelfCallForbidden` (`:248`).
- The canonical Lean tree does model it (`contracts/verification/lean/SphincsCVerify/Wallet/ValidateUserOp.lean:302`), and the binding equivalence gates (Halmos `LeanValidateUserOpModel.sol:229`, Kontrol credit-one-shot, forge `PQMultiOpBundle.t.sol`) all target the canonical tree + real bytecode, so the theorems are true of the verity model and the real dispatch gates are intact — the divergence direction (model more permissive than contract) preserves soundness of what verity proves but means `TRUST_ASSUMPTIONS.md`'s "dispatch correctness" row (#10/#11) speaks for a weaker machine than deployed, with the dropped conjuncts not flagged as modeling choices in that doc (only in source comments).
- Absent from the exclusion digest.

## Findings — Trusted UI (lane TUI) — F39–F41

### F39 — [TUI-1] Both-buttons chord confirm has no hold-duration floor and fires on button rollover — a ~30 ms simultaneous tap is a full confirm
- **Severity:** medium
- **Evidence label:** PoC (code path + reasoning trace)
- **Lane verdict:** KEEP — no digest row covers the chord/rollover confirm path (engagement F1 is the confirm-result FI fix; pq1-arch F4 is the forced-blind prompt-abuse budget). The chord is intentional and test-pinned, so this may be accepted-as-designed — the missing hold floor and rollover-fires-confirm aspect is what is new.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/hw/buttons.rs:188-258`: after a 30 ms debounce, if LEFT and RIGHT are both down at any instant inside the 80 ms `COMBO_WINDOW_MS`, `wait_combo_release()` returns `Some((Button::Right, Press::Long))` as soon as both are released — with **no minimum hold time** (contrast: a single-button confirm needs `LONG_PRESS_MS = 500`, `track_hold` at `buttons.rs:289-293`). `confirm.rs:131-143` treats `(Right, Long)` + sticky `seen_last` as the sign-authorizing accept.
- The playbook's stated property ("the user's **long-press** on the confirm dialog — after paging to the last page — is the only thing that releases a signature", trusted-ui-adversarial-review.md:5) is false for the chord: a momentary both-contact authorizes. Rollover makes it worse: pressing LEFT then RIGHT within ~110 ms (fast page navigation) synthesizes `(Right, Long)`, and since `seen_last` is sticky, doing this on any page after one full pass **confirms** — the user's intent was navigation, and a held-LEFT (cancel intent) with RIGHT touched inside the window also inverts to confirm.
- Sharper still: single taps shorter than ~110 ms are *dropped* by the combo-window logic (`buttons.rs:220-239`, "released during the combo window, ignore"), so the chord is literally the lowest-effort gesture the driver recognizes, and it is the one that authorizes. The chord is intentional and test-pinned (`hw_io_under_test/pure_tests.rs:438-442`), so this may be accepted-as-designed — but the missing hold floor / rollover-fires-confirm aspect is absent from the exclusion digest.

### F40 — [TUI-2] Button timing calibration is one unvoted MMIO read — a single boot-time fault collapses long-press 500 ms → ~12 ms and debounce 30 ms → <1 ms
- **Severity:** low
- **Evidence label:** suspicion, unverified (solid reasoning trace; needs a bench fault)
- **Lane verdict:** KEEP — no digest row covers button-timing calibration.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/hw/buttons.rs:117-124` (`detect_sysclk_mhz`: single `REG.rcc_cfgr1.read()`), `buttons.rs:97-107,148-152` (`LOOPS_PER_MS = mhz*200`, written once at `init` inside `ui::init`, main.rs:1204). If the SWS read is glitched to `0b00` (MSI) while the chip actually runs 160 MHz, every `delay_ms` runs 40× fast: `LONG_PRESS_MS` ≈ 12 ms real, `DEBOUNCE_MS` ≈ 0.75 ms real — mechanical bounce becomes "presses", a tap on the last page becomes a confirming long-press. No voted read, no runtime cross-check against the (later-started) SysTick, unlike the FI-hardening everywhere else at boot. Absent from the digest. The rcc HSI16 fallback itself is handled correctly (SWS=0b01 → 16 MHz → correct scale), so this is specifically the single-fault-on-the-read case.

### F41 — [TUI-3] `ui-capture` SHA-256-fingerprints secret-bearing frames — the `[UI-FP]` log is a seed-recovery oracle
- **Severity:** low
- **Evidence label:** PoC (reasoning trace)
- **Lane verdict:** KEEP — the digest treats ui-capture only as a never-ship/dev-fenced flag (MED-2 class); no row records the secret-frame-hashing preimage property.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/ui/semihosting.rs:107-117` routes `flush_with_secret_rows` through `flush()`, whose `ui-capture` arm (`semihosting.rs:92-100`) hashes the exact 64-byte cell grid; `capture.rs:46-64` emits it over the secure log. During the seed wizard each frame contains exactly 3 BIP-39 words in fixed columns → per-frame preimage space is 2048³ ≈ 2³³ (trivially brute-forced; the checksum word further constrains). Anyone with the log of a wizard run recovers all 24 words. `ui-capture` implies `debug-log` and is denylisted from `stm32u585` release (`nsc/mod.rs:93-133`), and e2e flows use fixed mnemonics — so the exposure is a dev who restores a *real* seed in a `make play`/capture build. The digest lists ui-capture as a never-ship flag but has no entry for the secret-frame-hashing property.

## Findings — Production configuration / prodtest (lane PRODCFG) — F42–F46

### F42 — [PRODCFG-1] FSBL/measurement trust-chain test suites are green-when-run but enrolled in NO CI job
- **Severity:** medium
- **Evidence label:** PoC
- **Lane verdict:** KEEP — sweep F13/F14 and the engagement-F8 meta-gate rows concern other gates; the gate_enforcement completeness pass structurally cannot see non-`make`-aggregated suites.
- **Cross-reference:** FWSB-3 (F21) — the footprint test's internal skip-on-missing-toolchain is a second, distinct defect in the same file.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`fsbl-tests/tests/footprint.rs` (32 KiB legacy-region regression gate), `fsbl-tests/tests/source_invariants.rs` (render-before-branch trust chain, `verify_images` digest type, NV3007 constants, `measured_boot` self-attest pins), the entire `fwmeasure/tests/` suite (`byte_identity.rs` = the FSBL↔host measurement-words parity evidence, CLI negatives, output stability), and `tools/test_factory_prodtest_runner.py` are invoked by zero workflows and zero Makefile aggregates. `ci.yml:171-185` deliberately excludes fsbl-tests from host-tests saying the footprint test "belongs in a firmware-target job" — but the only firmware-target job (`nightly.yml:155-181`) runs `cargo check` on secure+nonsecure and never the tests. `gate_enforcement.json`'s completeness pass only tracks `make verify-*`/`kani`/`miri` targets, so the G1 meta-lint cannot see this escape. Lane ran all three Rust suites: fwmeasure 5/5, source_invariants 8/8, footprint 1/1 pass — classic "green-when-run, never run". A regression in the FSBL size bound, the render-before-branch property, or the fingerprint parity would silently go green on every PR. Absent from the exclusion digest; concrete instance of playbook PC11 (rated generic PARTIAL).

### F43 — [PRODCFG-2] Stale `target/veneers.o`: cargo fresh-skip pairs the NS image with a *different* secure build's CMSE implib
- **Severity:** medium
- **Evidence label:** PoC (reproduced)
- **Lane verdict:** KEEP — work-todo:eng-git-ops covers untracked/junk files, not build-artifact staleness; the Makefile:970-975 comment is an incident note (with a fix applied only to `se050-reset`), not a tracked work item.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

All hw targets emit the CMSE import library to one shared path (`Makefile:18` `VENEERS = $(CURDIR)/target/veneers.o`, `--out-implib` at `:79`, NS consumes it at `:80`). The implib is a linker side-file cargo does not track. The lane built secure with features A (`stm32u585,mock-se,ui-noop`: veneers `nsc_fw_abort @0x0c081ed0`), then B (`+debug-log`: `@0x0c084710`, sha `fff231a9…`), then A again: cargo reported "Finished in 0.04s" (fresh, no relink) and `veneers.o` still contained **B's** addresses and hash. The Make targets then `rm -f` only the NS ELF (e.g. `Makefile:1377`) and link NS against the stale implib — an A/B alternation (`make e2e-hw` ↔ `make flash-hw-dual-se-*` ↔ `make build-hw-prodtest`, the normal bench loop) silently flashes a mismatched S/NS pair. The final secure ELF itself is *not* stale (cargo re-points it verified), so nothing else detects this. `Makefile:970-975` documents this exact mechanism plus a 2026-06-29 bench brick ("SecureFault INVEP at the first gateway call") but the fix (per-target veneers path) was applied only to `se050-reset`; every other target still shares the one path. Impact is mostly a loud brick plus invalid bench evidence collected against no coherent build; it is not in the exclusion digest (PC4 rates the mismatch class PARTIAL without this mechanism). Open sub-question: whether a B-address could land on a *valid but wrong* SG stub in A (silent wrong-function entry instead of a fault) — unresolved, needs layout-collision analysis or silicon.

### F44 — [PRODCFG-3] Reproducibility evidence covers only the dev QEMU cfg; FSBL is never byte-diffed; `gate_enforcement.json` overclaims the policed surface
- **Severity:** low-medium
- **Evidence label:** PoC
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** STATUS:§C repro (verify-repro byte-diff DONE, nightly-gated). The lane concedes the FEATURES/dev-cfg half is already catalogued as a "CONCRETE EVIDENCE TENSION" in playbook BR4; the unrecorded delta is the FSBL omission + the polices-paths overclaim.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`verify-repro` builds with `FEATURES ?= mock-se,debug-log,ui-semihosting` (+ forced `erc7730-dev-unattested`; `Makefile:95,112`) and `nightly.yml:78-79` invokes it bare, so the byte-diff proves determinism of the *dev QEMU* image only. `_repro_one` (`Makefile:2156-2166`) builds secure+nonsecure — the FSBL (the intended immutable trust root whose bytes anchor the 8-word fingerprint) is never rebuilt or diffed anywhere. `scripts/gate_enforcement.json` declares verify-repro `polices_paths: ["secure/src/**","nonsecure/src/**"]`, but the exercised cfg compiles out the entire `stm32u585`-gated half of `secure/src` (SE drivers, hw/*, veneers, LCD, first_boot) — a coverage overclaim the meta-lint itself certifies. The FEATURES half is catalog-covered (BR4); the FSBL omission and the polices-paths overclaim are the unrecorded delta. Not in the exclusion digest. Lane note: production half is moot while the rollback quarantine blocks every ship build — but when a ship cfg exists, no repro gate will cover it (or the FSBL) without new wiring.

### F45 — [PRODCFG-4] No CI job ever links the thumbv8m secure+nonsecure pair
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP — distinct from PRODCFG-2 (artifact-cache staleness vs source-level ABI drift invisible to CI); no digest row covers pair-linking coverage.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

Veneer symbol drift (rename/remove an `nsc_*` export, or NS referencing a veneer the secure cfg gates out, e.g. `cmd_tzic_status` under `e2e-test` only) fails only at NS link time against `--cmse-implib` output. `ci.yml` builds host tests + a QEMU pair (no implib); `nightly.yml:173-181` runs `cargo check` — its own comment admits "cargo check (not a full build)". Nothing links the pair except bench builds. Not in the exclusion digest.

### F46 — [PRODCFG-5] `flake.nix` vendors a git pin (`tropic01`) that no longer exists in `Cargo.lock`
- **Severity:** low
- **Evidence label:** suspicion, unverified
- **Lane verdict:** KEEP — no digest row (eng-git-ops is untracked-file hygiene, a different class).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`flake.nix:56-65` comments "the one git pin (tropic01)" and carries `outputHashes."tropic01-0.1.0"`, but `Cargo.lock` contains zero git sources and `deny.toml` forbids git deps since the TROPIC01 removal (2026-07-14). If `importCargoLock` rejects unknown outputHashes the canonical `nix build .#measure` path breaks; if it ignores them, it's cosmetic staleness on the user-facing reproducibility path. Not evaluated (would need network fetch).

## Findings — Silicon lockdown (lane LOCK) — F47–F48

### F47 — [LOCK-1] rdp-enforce-halt × rdp2-self-lock: unfenced contradiction makes the mandatory self-lock unreachable
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP — the digest's ACCEPTED non-halting row (sweep F17) is the opposite direction (warn-and-continue); `rdp-enforce-halt` appears nowhere in the digest.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `secure/src/nsc/mod.rs:550-570` forces `mode-production` ⇔ `rdp2-self-lock` (first field boot is *supposed* to run at RDP-0 and self-lock). `secure/src/main.rs:919-949`: in every `mode-production` build, the boot-time RDP check runs *before* Phase A (`main.rs:1215`); on a fresh unit `journal_all_done()` is false, the warning is a `secure_log!` no-op, and then `#[cfg(feature = "rdp-enforce-halt")] loop { wfe(); }` (`main.rs:945-948`) parks the CPU — before `ui::init()` (`main.rs:1204`), so a black screen, and `first_boot::run_pre_lock_and_maybe_lock()` is never reached. The device can never self-lock: every unit built with `mode-production,rdp2-self-lock,rdp-enforce-halt` is dead on first field power-on.
- PoC is pure cfg reasoning, verifiable in tree: grep shows `rdp-enforce-halt` appears only in `secure/Cargo.toml:143` (definition), `main.rs:917/945` (halt), and the prodtest fence (`nsc/mod.rs:303`) — no `compile_error!` rejects the combination, it is absent from the hardware-release denylist (`nsc/mod.rs:113`), and `prod-check-ship` always fails by design so no later gate catches it either. The comment at `main.rs:908-918` still advertises it as an opt-in without noting the contradiction with the now-mandatory self-lock.
- Breaks the lane property "no lockdown step silently skippable in a build the fence wall accepts." Absent from the exclusion digest.

### F48 — [LOCK-2] Ship-profile WRP1A check accepts over-wide spans → passes the last pre-lock gate into a permanent RDP-2 brick
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** work-todo:X17-SL2 (with SL8 bench-guess gate constants fail-direction / SL9 partial OPTR mask). Same gate-constant fail-direction family, but a checked comparator accepting a bricking superset is not the named mechanism in SL8 (guessed constants failing vacuous) or SL9 (unread bits); F17's option-byte deferral is about external assumption, not this device-side comparator.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

- `shared/src/lockdown.rs:168-173`: `wrp1a_covers_fsbl` requires only `UNLOCK==0 && strt==0 && end >= 3` — the host test at `lockdown.rs:310` explicitly asserts `(7 << 16) | 0` passes. So WRP1A = {STRT 0, END ≥ 123} passes `verify_ship_profile` (called at `secure/src/first_boot/mod.rs:136-148`), the device burns RDP=0xCC, and Phase B's first `write_journal_qw` (page 127) / `erase_secure_page(126)` then fails with WRPERR (`ERR_MASK=0xFA` includes WRPERR, `hw/flash.rs:117`) → `halt_first_boot(JournalWriteFailed/BhkPageHostile)` *after* the irreversible lock: a non-returnable brick. END ≥ 64 also kills every future FW update (`erase_slot`, `hw/flash.rs:1272-1292`), and END ≥ 124 kills the PIN-attempt counter.
- The comparator enforces *exact* equality for SECWM1/SECWM2 (`lockdown.rs:151-159`) but superset coverage for WRP1A; the fail-open direction is precisely the one that converts a factory ceremony error into an irreversible post-lock brick instead of a halt-unlocked E0801. The ship-profile check is the only device-side gate before the burn, and no tooling in the repo programs WRP1A at all, so the exact value is entirely ceremony-dependent.
- Absent from the digest: X17-SL2/SL8 covers guessed *bit-layout constants* failing vacuous; SL9 covers *unread OPTR bits*; neither covers a checked register's comparator accepting a bricking superset. Inherits the standing caveat that every BENCH-CONFIRM register layout remains unverified against RM0456/silicon (SL8/F10); the WRPERR chain assumes the documented WRP semantics.

## Findings — Formal verification / gates (lane FV) — F49–F54

### F49 — [FV-1] verify-extraction-freshness is RED on master HEAD — aa-userop extraction is stale, the live F1 defect
- **Severity:** high
- **Evidence label:** PoC (executed)
- **Coordinator re-verification:** ✅ re-verified on HEAD `89c60063` — `python3 contracts/verification/scripts/check_extraction_freshness.py` → exit 1, `extract-aa-userop` drifted (sha256); 13 fresh, 1 waived-stale (tx-merkle, tracked FV15-F1), 1 drifted. See "Coordinator verification" above.
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** findings:fv-coord-2026-07-15 F1 (freshness tripwire IMPLEMENTED; tracked residual is tx-merkle WAIVED-STALE only). The aa-userop drift is a new instance (commit 94bb2e9a, 2026-07-18 — same day the digest was built); coordinator may already have context on an in-flight re-extraction.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`python3 contracts/verification/scripts/check_extraction_freshness.py` on HEAD (870cb113) exits 1: `extract-aa-userop: rust file aa/src/userop.rs CHANGED (sha256 drift)`. Commit 94bb2e9a (2026-07-18) rewrote `aa/src/userop.rs` (+366 lines, incl. the new V6 batch-commitment functions `batch_member_commitment`/`batch_tuple_commitment_from_members` at `aa/src/userop.rs:240-265`) without re-running `extract-aa-userop` or re-pinning; `extraction_registry.json` was last pinned in 90867499 (2026-07-16). So every §33 extracted `Extracted.Equiv.compute_user_op_hash_*` theorem now proves a pre-V6 artifact, and the new batch-commitment code — a security remediation — has no extracted counterpart. The gate is `per_pr_blocking` (lean-extracted.yml:136-137, paths cover `aa/src/**`), so this either merged over a red required check or bypassed PR gating. Digest check: F1's tracked residual is tx-merkle WAIVED-STALE only; this aa-userop drift is new.

### F50 — [FV-2] verify-gate-enforcement is RED on master HEAD — two new soundness gates escape the G1 manifest
- **Severity:** medium
- **Evidence label:** PoC (executed)
- **Coordinator re-verification:** ✅ re-verified on HEAD `89c60063` — `python3 scripts/check_gate_enforcement.py` → exit 1, two G1META-1 COMPLETENESS failures (`verify-hw-assumptions`, `verify-mmio-addresses` invoked in ci.yml but not manifest gates). See "Coordinator verification" above.
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** findings:fv-coord-2026-07-15 F8 + work-todo:FV15-F8-registry (mandatory-ID registry IMPLEMENTED) + findings:sweep-2026-07-14 F13 (red-gate instance FIXED). These are new, post-2026-07-17 escape instances the landed machinery does not cover.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`python3 scripts/check_gate_enforcement.py` exits 1 with two G1META-1 COMPLETENESS failures: `verify-hw-assumptions` (ci.yml:83, added by f5f1b928) and `verify-mmio-addresses` (ci.yml:89, added by f538439f) are invoked per-PR in ci.yml but are not gates in `scripts/gate_enforcement.json`. The lint's own completeness check (check_gate_enforcement.py:240-253) caught them, yet the tree landed with the blocking `gate-enforcement` job (ci.yml:324-336, no continue-on-error) failing. Same merge-time-enforcement question as FV-1: two independent "blocking" FV gates are red on HEAD. Additionally invisible to the manifest's completeness scan (it only audits workflow-invoked targets): verify-tla, verify-verus, verify-crux-ns-ptr, verify-forsc-margin, verify-easycrypt-pins/docker are all local-only and undeclared. Digest check: F13's red-gate instance is marked FIXED; these are new, post-2026-07-17 instances.

### F51 — [FV-3] verify-mmio-addresses is a permanent green no-op in CI
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP — the gate is new (post-dates the registry work) and absent from the digest. Cross-reference FV-2 (its manifest escape) — FV-3 is the separate vacuity defect inside the same gate.
- **Cross-reference:** FV-2 (F50) — this finding is the vacuity defect inside the same gate whose manifest escape F50 records.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`scripts/check_mmio_addresses.py:273-277`: when `~/repos/STM32CubeU5/.../stm32u585xx.h` is absent the gate prints SKIP and `return 0`. The header is never present on CI runners, so the ci.yml:88-89 step named "MMIO base addresses vs ST CMSIS header" is green while asserting nothing, forever. The ci.yml comment honestly admits "it is a no-op in CI today", but combined with FV-2 (not in the manifest) no meta-layer tracks that this per-PR step is vacuous, and the header it would diff against on a dev box is an unpinned local checkout. Contrast with the sibling pattern done right: verify-tla fails loudly (exit 1) when its jar is absent (contracts/verification/Makefile:150-156).

### F52 — [FV-4] Kontrol/KEVM leg has no proof-identity baseline — the F7 fix was never extended to it
- **Severity:** low-medium
- **Evidence label:** PoC (source) + suspicion on tool semantics
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** findings:fv-coord-2026-07-15 F7 (prover exit-status/verdict-count pinning IMPLEMENTED — scoped to ProVerif/Tamarin protocol models); STATUS:§C kontrol (30/30 DONE — the claim this finding shows is stale against the tree). Same defect class, never-extended leg.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`contracts/verification/kontrol/run_kontrol.sh:95-100` runs `kontrol prove --match-test 'Kontrol.*\.prove_'` then prints `kontrol list` without asserting which or how many proofs passed. F7 (2026-07-16) fixed exactly this class for ProVerif/Tamarin with per-query identity dicts in check_protocol_models.py; the kontrol leg got nothing. The drift already happened silently: STATUS says "Kontrol/KEVM … (30/30)" but the tree now contains 38 `prove_` functions across the 5 harnesses (grep: 4+10+6+9+9) — no gate noticed. A renamed/dropped proof or a `--match-test` no-match shrinks coverage invisibly. Whether `kontrol prove` itself exits nonzero on a failed proof: unverified (no tool here) — suspicion; the identity-baseline absence is verified from source.

### F53 — [FV-5] The G1 lint's own negative control is never run
- **Severity:** low
- **Evidence label:** PoC
- **Lane verdict:** KEEP — no digest row covers self-test wiring of the meta-gate itself.
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

Every sibling gate's make target runs its `--self-test` first (contracts/verification/Makefile:107-108, 121-122, 182-183; root Makefile:3988-3989, 4006-4007), but `verify-gate-enforcement` (Makefile:4203-4204) and ci.yml:333-336 invoke only `python3 scripts/check_gate_enforcement.py` — the `--self-test` negative control exists (lane ran it: exit 0, works) but is wired nowhere. A silent regression of the meta-gate itself (regex/invokes_target rot) would be detected by nothing — the exact G1 class, one level up, self-exempted.

### F54 — [FV-6] Extraction-freshness pins under-cover the generated file set
- **Severity:** low
- **Evidence label:** PoC (source)
- **Lane verdict:** KEEP-NOTE
- **Overlap-check:** findings:fv-coord-2026-07-15 F1 (the tripwire whose coverage this finding shows is incomplete; same-day machinery, coordinator may treat as a follow-up of the F1 implementation).
- **Status:** 🔲 OPEN

Evidence (transcribed from the sweep candidate record):

`contracts/verification/scripts/check_extraction_freshness.py:70-81` pins only each entry's entry-point rust file + `Funs.lean`. The generated `Types.lean` and hand-augmented `FunsExternal.lean` siblings (e.g. `contracts/verification/extracted/Extracted/UserOp/`) are unpinned, as are same-crate sibling modules the extraction inlines. A partial regen committing only some regenerated files, or a change to a sibling module, stays green. Mitigant: cross-crate deps are extracted `--opaque` (keccak is a disclosed axiom at UserOp/FunsExternal.lean:14), so the blast radius is mostly same-crate — but same-crate is exactly where FV-1's drift came from.

## Per-surface verdicts

One subsection per covered surface — the 15 playbooks in
`docs/security/adversarial-review/` plus the FV gate layer. Each gives the
kept-findings count, whether any break was reproduced, and whether the lane
executed checkers or was source-only. These are lane-level discovery verdicts,
not adjudicated outcomes.

### clear-signing (lane CS)
4 kept (3 KEEP: CS-1, CS-3, CS-4; 1 KEEP-NOTE: CS-2 vs X17-CS1/F4), 0 dropped → F9–F12. Major WYSIWYS falsification attempts failed; findings are rendering-exactness/coverage gaps. No break reproduced. Executed `cargo check -p pqsigner-erc7730` (clean).

### trustzone-gateway (lane TZGW)
4 kept (2 KEEP: TZGW-3 [merged with RUN-2], TZGW-4; 2 KEEP-NOTE: TZGW-1 vs tz-3 family, TZGW-2 vs tz-2 DONE row), 0 dropped → F5–F8. Strongest hypothesis (NS rewriting GTZC via SECCFGR4) falsified against CMSIS/HAL. No break reproduced. Executed `cargo test -p sphincs-tz-shared` (47 pass).

### secure-element (lane SE)
3 kept (0 KEEP, 3 KEEP-NOTE: SE-1 vs S-6/SE17-4, SE-2 vs SE17-8, SE-3 vs #25-gap2/OP17-4), 0 dropped → F23–F25. Session/shield defenses held; findings are lifecycle/availability class. No break reproduced. Source-only.

### sca-fi (lane SCAFI)
6 kept (3 KEEP: SCAFI-1, SCAFI-2, SCAFI-6; 3 KEEP-NOTE: SCAFI-3 vs §C-zeroize, SCAFI-4 vs X17-OC1/FVX-2, SCAFI-5 vs SE17-6/OP17-4), 0 dropped → F13–F18. No single-fault forgery constructed beyond tracked items. Source-only pass (weakest for FI, per the lane).

### firmware-update-secure-boot (lane FWSB)
4 kept (3 KEEP: FWSB-2, FWSB-3, FWSB-4; 1 KEEP-NOTE: FWSB-1 vs sweep F15), 0 dropped → F19–F22. Lane's heavy hitters (FW2/FW8/FW11/F15/F16/F17) confirmed real but already tracked. No new break reproduced. Executed `cargo test -p fw-manifest` + full release build for the FWSB-1 layout PoC.

### usb-companion (lane USB)
4 kept (2 KEEP: USB-3, USB-4; 2 KEEP-NOTE: USB-1 vs F11/§31a, USB-2 vs X17-UC1), 0 dropped → F1–F4. No gateway-crossing break reproduced; all findings DoS/UX class, consistent with the "NS holds no secrets" bar. Executed `cargo test -p sphincs-tz-shared --tests` (134/134).

### offchain-signing (lane OFFCHAIN)
4 kept (2 KEEP: OFFCHAIN-2, OFFCHAIN-4; 2 KEEP-NOTE: OFFCHAIN-1 vs P1.5-residual, OFFCHAIN-3 vs accepted GET_INIT_CODE oracle), 0 dropped → F34–F37. Forgery-oracle paths structurally closed. No break reproduced. Executed `cargo test -p pqsigner-aa` (green).

### onchain-contracts (lane CHAIN)
1 kept (KEEP: CHAIN-1, model-fidelity nit), 0 dropped → F38. Nothing exploitable survived; known residuals (SOL2/SOL6/SOL9) stand as tracked. No break reproduced. Executed full forge suite (118 pass, 2 RPC-gated skips) + `cast` recomputations.

### trusted-ui (lane TUI)
3 kept (3 KEEP: TUI-1, TUI-2, TUI-3), 0 dropped → F39–F41. Confirm-gating structure held; findings are ergonomics/calibration/dev-flag class. No break reproduced. Source-only.

### silicon-lockdown (lane LOCK)
2 kept (1 KEEP: LOCK-1; 1 KEEP-NOTE: LOCK-2 vs X17-SL2/SL8/SL9), 0 dropped → F47–F48. No unenforced secret-exposure path found; findings are availability/fence-hygiene class. No break reproduced. Executed gate-enforcement script + two cargo test filters (47 + 22 pass).

### lifecycle-persistent-state (lane LIFE)
1 kept (KEEP-NOTE: LIFE-1 vs OP17-8/SE17-4), 0 dropped → F26. Lane explicitly judged and did not report several tracked/deliberate items (incl. the post-S-6 USERID orphan that SE-1 reports — LIFE treats it as docs-owned, SE as a live contradiction; carried as SE-1 KEEP-NOTE for coordinator adjudication). No break reproduced. Source-only.

### entropy-key-lifecycle (lane ENT)
3 kept (3 KEEP: ENT-1, ENT-2, ENT-3), 0 dropped → F27–F29. Entropy inventory clean; domain separation verified by executed tests. No break reproduced. Executed `cargo test -p pqsigner-domain` (73/73).

### secure-runtime-resource (lane RUN)
5 kept (1 KEEP: RUN-2 via merged TZGW-3/RUN-2 entry; 4 KEEP-NOTE: RUN-1/RUN-3/RUN-4 vs #17-power umbrella, RUN-5 vs FVX-3/#21), 0 dropped → F7 (merged), F30–F33. Priority-mechanism facts (SHPR absence, equal-priority non-preemption) grep-verified. No break reproduced beyond the coordinator-verified priority-programming absence. Source-only.

### production-configuration-prodtest (lane PRODCFG)
5 kept (4 KEEP: PRODCFG-1, PRODCFG-2, PRODCFG-4, PRODCFG-5; 1 KEEP-NOTE: PRODCFG-3 vs §C-repro), 0 dropped → F42–F46. Fence wall held. No break reproduced. Executed two repro builds + three test suites (fwmeasure 5/5, source_invariants 8/8, footprint 1/1).

### build-release-provenance (combined lane PRODCFG+BR)
**Assessed, but at reduced depth.** The sweep covered this surface through the PRODCFG lane, which was assigned both the production-configuration-prodtest and the build-release-provenance playbooks in one combined first-principles pass (repro-gate scope, CI/build integrity, paired-artifact pairing, signing/provenance naming, fence wall). Its kept findings F42–F46 straddle both playbooks — e.g. F44 concedes its FEATURES/dev-cfg half is already catalogued as a "CONCRETE EVIDENCE TENSION" in playbook BR4, and F42 (stale `veneers.o` pairing) is a build-integrity break squarely on the BR surface. What the combined pass did **not** reach: `supply-chain/` exemption contents, HSM/quorum signing-key custody, and xtask release packaging/distribution (named in the lane's own not-inspected list). Recorded as a depth gap, not a coverage absence; a dedicated BR pass remains worthwhile.

### fv (gate layer, lane FV)
6 kept (2 KEEP: FV-3, FV-5; 4 KEEP-NOTE: FV-1 vs fv-coord-F1 residual, FV-2 vs F8/F13, FV-4 vs F7, FV-6 vs F1), 0 dropped → F49–F54. Core gate machinery sound; headline result is two blocking gates red on HEAD (both coordinator-re-verified). Executed the pure-Python checkers + self-tests + kani census.

## Honest residual

Mandatory, per playbook convention. Aggregated across all 15 lanes from the
sweep's condensed residuals; nothing here is adjudicated.

### What survived contact (nothing worse than the 54 kept candidates)
- No wrong-but-valid signature, no gateway-crossing pointer/length violation, no host-driven parser panic, no single-fault forgery path beyond already-tracked items, no unenforced key-exposure path in the lockdown stack, nothing exploitable in the Solidity contracts beyond tracked residuals (SOL2/SOL6/SOL9).
- Defenses independently re-verified and held: NS-pointer window kernel + validate-before-deref on all production veneers; EntryPoint pinning device-side (digest row "canonical-singleton pin not enforced device-side" is stale against this tree — noted by USB and OFFCHAIN lanes); Safe/CoW/ERC-7730 binding chains; multiSend known-call gate (downgrade hypothesis refuted); double-compute→ct_eq→verify sign chain with sentinel gates; SCP03 level 0x33 + FI-hardened R-MAC; first-boot journal + two-phase rotation resume; page-124 precharge + readback; confirm_checked call-site coverage; fence wall (~20 compile_error!s) and production/factory quarantines; wallet entropy genuinely 3-source with exact-fill; KDF domain separation (executed tests); wrapper/digest field binding on-chain (forge suite executed); FSBL/fwsign/fwmeasure chain at source level.

### What was NOT looked at (aggregate — union of lane blind spots)
- **Third-party code trusted, not audited**: `usb-device 0.3` / `synopsys-usb-otg 0.4` internals (USB); Solady `LibClone`/`ERC1271` incl. TypedDataSign assembly parser (CHAIN); cortex-m-rt default handlers (RUN); `cargo vet` exemption contents (PRODCFG).
- **Large bodies partially read**: `cmd_sign_userop.rs` display sections ~700–1800 and batch middle; `safe_display.rs` (~25% read); `exec_decode.rs`; `deployment.rs`; `cowswap/verify.rs`; batch summary pages; ~95% of the 11.7k-line `dbgen/src/erc7730.rs` (visibility-gate tuple/path helpers deserve a dedicated pass); `render/array.rs` beyond caps.
- **SE/transport internals**: T=1'/IFX I²C layers, APDU builders beyond scp03/shield, `first_boot/{state,journal}.rs` crypto (LIFE verified journal logic; SE/ENT did not walk it), `factory_provisioning.rs`, `reset.rs`/`reset_pin.rs`, `i2c2_probe.rs`, duress-wipe-mode flash handling, `rekey_admin_transport_to_final`, F1E1/counter builders.
- **FW/boot**: `fsbl/src/nv3007.rs` (733-line LCD driver); draft09/draft11 `fsbl-tests` models; Draft-1.1 document internals; `hw/boot_state.rs` (legacy, fenced); QEMU USB/APDU stack; FSBL beyond main/branch/linker/verify.
- **FV heavy legs (not executed anywhere)**: `lake build`, `cargo kani`, kontrol, halmos, proverif, tamarin, easycrypt, verus, crux-mir, TLC; the 42 GB FormatDecimalSpec carve-out; EasyCrypt `.ec` sources; LeanLoop external tooling; verity/SphincscVerify proof bodies.
- **Config/CI periphery**: `supply-chain/` exemptions, `.semgrep/` rules, `tools/ob-configurator`, fuzz crate + ClusterFuzzLite configs, `scripts/check_kani_mutations.py`, xtask/release packaging, `production-todo.md` ceremony text.
- **Misc surfaces**: `tx/` semantic WYSIWYS content beyond panic-scan (CS owns it; USB only scanned); `pqsigner-erc7730` renderer internals beyond binding seams; `domain/` derivation (no display surface); `proto/`↔on-chain verifier equivalence; `cmd_get_init_code`/`cmd_get_wallet_address` (accepted surface); page-123 backend internals (heavily tracked); `fw_update` staging internals; NS USB stack beyond heartbeat; `hal/` beyond trait surface; `hw/saes*` key-register hygiene (GTZC-trusted); `secret_text.rs` CT-blit internals; button electrical/EM injection; `usb_hw.rs` soft-disconnect-in-IRQ (documented diverging); FSBL fingerprint display; `duress-pin` provisioning internals; prodtest handlers (tracked X17-TZ2); QEMU mailbox path (dev-only).
- **Surface covered only at reduced depth**: build-release-provenance — combined PRODCFG+BR lane rather than a dedicated pass; supply-chain exemptions, HSM/quorum custody, and release packaging/distribution unreached (see its per-surface verdict above).

### Which lanes executed checkers vs source-only
- **Executed real checkers/builds/tests (10 lanes)**: USB (`cargo test -p sphincs-tz-shared --tests`, 134 pass); TZGW (`cargo test -p sphincs-tz-shared`, 47 pass); CS (`cargo check -p pqsigner-erc7730`); FWSB (`cargo test -p fw-manifest` + full release build for layout PoC); ENT (`cargo test -p pqsigner-domain`, 73/73); OFFCHAIN (`cargo test -p pqsigner-aa`); CHAIN (full forge suite 118 pass + `cast` recomputations); PRODCFG (2 repro builds + fwmeasure 5/5 + fsbl-tests 8/8 + footprint 1/1); LOCK (`check_gate_enforcement.py` + shared 47 pass + secure first_boot 22 pass); FV (all pure-Python checkers live + self-tests + kani census + independent harness recount 162/25).
- **Source-only (5 lanes)**: SCAFI, SE, LIFE, RUN, TUI (grep/read-level only; their FI/physical claims carry the weakest evidence tier by their own declaration).

### Properties needing silicon/bench/RM0456 evidence (aggregated)
- TZGW-1: RAMCFG erase-register semantics (immediate vs reset-scoped) and ICACHE monitor granularity (RM0456/silicon).
- SE-3: E120 ratchet-on-successful-verify + E120-write wedge behavior (bench).
- SE-1/SE-2: confirming runs need host-sim or bench — QEMU cannot reach the `stm32u585`-only admin-pin path.
- LIFE-1: page-125 program-hostility reachability; OPTSTRT power-cut window; ECC-fault-on-torn-read across pages 123–127; OPTIGA SetData wedge timing; SE050 session-pending during wipe resume.
- RUN-1: SHPR3/IPR readout on the production ELF + scope/reset-cause capture of an idle-wipe→re-unlock cycle (the ~2 s IWDG bite); RUN-4: KR access-revocation semantics (RM0456).
- TUI-1: chord ergonomics (bench); TUI-2: boot-time fault practicality (bench fault).
- FWSB-1: whether the post-BEGIN crash actually fires on-device (layout-dependent); OTP ECC torn-write; WRP/option-byte ceremony; FSBL boot time on the real 245 KB .text.
- USB-1/USB-2: starvation timing (frame cadence, DWC2 FIFO backpressure) needs a two-channel host PoC on real hardware.
- LOCK (both findings inherit it): every BENCH-CONFIRM register layout unverified vs RM0456/silicon (tracked SL8/F10).
- SCAFI (tracked-class residuals): HW-HASH DPA on `sk_seed` PRF absorption, `wait_random` loop-count leakage, TRNG health under glitch, SRAM1 remanence of abandoned sign frames.
- ENT: physical entropy quality/source independence — needs the instrumented RDP-0 statistical campaign (already scheduled); CubeU5 RNG state-machine equivalence check not run.
- CHAIN: the 2 skipped RPC-gated deployed-bytecode/codehash tests need a networked run before any release claim cites them.
- FV: `kontrol prove` exit-status semantics (FV-4 tail) needs one tool run; nothing else in-lane needs silicon beyond tracked FVX-1..3.
- Tracked ship-gates unchanged: erc7730-hw-ui/hw-fi, erc7730-stack-bound, ~40 h FI fault-sweep, on-silicon SCA (dudect/lascar/ChipWhisperer), Phase-2B/2C BHK, OPTIGA S-1/S-2 sacrificial program, RDP-2 red-team.

*An executing pass may report that it reproduced no break within its recorded scope, configuration, and evidence level; it cannot establish that every covered or uncovered path is sound, that silicon matches source assumptions, or that a source-only pass executed the claimed behavior.*

## Action cross-link

All actionable items from this sweep are banked in `docs/work-todo.md` under
the dated **"Full-project adversarial sweep 2026-07-18 (discovery)"** entry;
this report is the evidence record, not the tracking surface. Nothing in this
report is canonical until it has passed coordinator triage under the current
three-reviewer regime in `docs/planning-and-review-workflow.md` §7/§7b (there
is no Partner-A / Partner-B cross-adjudication step) — until then every item
above remains `🔲 OPEN` discovery evidence with no merge,
shipment, hardware, or adjudication authority.
