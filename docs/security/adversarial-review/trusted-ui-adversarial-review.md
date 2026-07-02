# Trusted-UI / confirm-path adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code-review pass over PQSigner's trusted-path UI — the confirm dialog, PIN entry, seed wizard, the display backends, the physical buttons, and the inactivity timer (`secure/src/ui/*`, `secure/src/timeout.rs`, `secure/src/hw/buttons.rs`, and the three sign handlers). The property everything here defends:

> **A physical confirm gates every sign, NS can neither spoof nor suppress it, and the inactivity timer is S-world-only.** The user's long-press on the secure-world confirm dialog — after paging to the last page (scroll-to-end gate) — is the only thing that releases a signature; the buttons are secure-owned GPIO NS cannot drive; and the 120 s idle timer is reset *only* by physical interaction (NS pings never reset it) before it zeroizes.

**How this differs from the bench red-team + the sibling playbooks.** [`docs/security/red-teaming.md`](../red-teaming.md) covers the bench view of the trusted path (Claim 9). **This playbook is the code-review counterpart** — walking the confirm call sites, the timer reset surface, and the backend selection against the trusted-path property. It cross-links rather than duplicates: *what is rendered* on the confirm page is the [clear-signing playbook](./clear-signing-adversarial-review.md); the PIN *compare* (in SE silicon) is the [secure-element playbook](./secure-element-adversarial-review.md); the constant-time secret-glyph blit is [sca-fi](./sca-fi-adversarial-review.md). This playbook owns the **confirm-gates-the-sign binding, the NS-can't-reach-it property, and the timer**.

> **Honesty note.** This surface has **two genuine found-this-surface residuals** promoted to work-todo: **UI1** — the confirm *result* is not FI-hardened (unlike the rest of the sign chain), and **UI2** — `ui-noop` has no `mode-production` fence. The rest is defended-by-construction (all sign paths reach confirm; buttons secure-owned; timer single-mutator). Do not soften UI1/UI2 — they are real gaps.

---

## Part A — The trusted-UI failure catalog (UI1–UI8)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| UI1 | **Confirm result not FI-hardened** | a single instruction-skip on the `Cancelled`/`IdleWipe` arm falls through into signing | **✅ FIXED 2026-07-02 (was FOUND-THIS-SURFACE).** `confirm()` now delegates to `confirm_checked() -> (ConfirmResult, sentinel)` which borns the sign-gate sentinel at the accept branch; all 9 sites gate on `verdict == OK_SENTINEL` and fail closed. Historically the 9 sign-path call sites accepted on a plain `match`/`matches!` of `ConfirmResult` with no voted read / redundant check / `fi` barrier (`cmd_sign_userop.rs:1121,1187`, `cmd_sign_userop_batch.rs:630,873,928`, `cmd_sign_offchain.rs:630,772`, `cmd_offchain_sync.rs:145`, `fw_update/mod.rs:119` — the last via `matches!(confirm(&pages), ConfirmResult::Confirmed)`). Contrast the timer (`ticks_ptr` + `read_volatile_voted`) and the PIN counter double-reads. There is **no `fault_sweep_confirm`** — the accept decision has no FI sweep | Add a `fault_sweep_confirm.py`; harden the accept to a sentinel verdict (`check_true_into_sentinel`) | ❌ → work-todo |
| UI2 | **`ui-noop` has no `mode-production` fence** | a headless build silently ships with no physical confirm | **✅ FIXED 2026-07-02 (was FOUND-THIS-SURFACE).** Added a dedicated `mode-production ⊥ ui-noop` `compile_error!` guard (verified fires). Historically the denylist (`nsc/mod.rs:114-133`) fenced `ui-semihosting`/`ui-mirror`/`ui-capture` but **not `ui-noop`**. Under the current scroll-gate `confirm()`, `noop::wait_button` returns `(Right, Short)` → an infinite loop (never confirms, never idles) — *masked today* only because every `ui-noop` Makefile target also carries `e2e-test` (which short-circuits confirm). **The hazard**: a hand-composed `mode-production,ui-noop,usb` set compiles, and if anyone "fixes the hang" by returning `(Right, Long)`, every sign auto-confirms with zero physical consent | Add a `mode-production ⊥ ui-noop` fence, or make `ui-noop` refuse to sign | ❌ → work-todo |
| UI3 | **`e2e-test` confirm short-circuit ships** | the dev auto-confirm leaks into a shippable build | **DEFENDED.** `#[cfg(feature="e2e-test")] confirm()` returns `Confirmed` with no input (`confirm.rs:41-47`), fenced by MED-2 (`nsc/mod.rs:281-287`, `mode-production ⊥ e2e-test`) + the hardware-release denylist. **Verify CI actually runs `prod-check`/`mode-production` on the shipped artifact** (the fence only fires at compile time) | `make prod-check`; the MED-2 fence tests | ✅ fence (verify CI runs it) |
| UI4 | **NS spoofs a button press** | NS drives the confirm GPIO to fake consent | **DEFENDED.** Buttons LEFT=PC1 / RIGHT=PA8 via **secure MMIO aliases** (`buttons.rs:41,47,81,82`); with TZEN=1 all GPIO default secure, and USB bring-up un-secures only PA11/12/15 + PB5/15 (`usb_hw.rs:130-131`) — it **does not touch PA8/PC1**. NS can't read or drive them | A targeted assertion that PA8/PC1 `SECCFGR` bits stay set; `make gtzc-enforcement-hw` (peripheral side) | ⚠ (per-pin assertion worth adding) |
| UI5 | **Timer reset from an NS ping** | an NS command resets the inactivity timer, defeating the idle wipe | **DEFENDED.** `LAST_ACTIVITY` has exactly **one** mutator `reset_activity()` (asserted `secure_fi_pin_rng_pure_tests.rs:1555-1559`), reachable only from physical-interaction paths (confirm/pin/seed after a real `wait_button`; `cmd_request_unlock` *after* `gated_unlock` Ok; post-successful-sign). NS-only commands never touch it | Timer single-mutator test (`:1471-1559`) | ✅ source-text test |
| UI6 | **A sign path skips confirm** | a handler signs without a confirm, or confirms after signing | **DEFENDED.** All three handlers + both offchain kinds reach `confirm()` *before* entropy reconstruction / signing; `already_confirmed` (offchain) is a mutually-exclusive guard, not a skip; batch confirms per-tx + a final summary. Scroll-to-end gate (`seen_last`, `confirm.rs:62,79-81,104-107`) stops long-pressing past the spliced drain-bearing pages | Confirm-gating source-assertion tests (`nsc_batch_offchain_pure_tests.rs:778-796`, `fw_update_boot_pure_tests.rs:445`) | ✅ source-text tests |
| UI7 | **Confirm binds to the wrong page then confirms** | the page shown ≠ the bytes signed | **CROSS-LINK clear-signing.** `confirm()` is content-agnostic — it faithfully displays whatever `pick_sign_pages`/`render_*_pages` produced and gates on scroll-to-end; whether those pages match the signed digest is the [clear-signing](./clear-signing-adversarial-review.md) surface (CS1). This layer guarantees only: non-ASCII → `'?'` (`ui/mod.rs:108-111`, anti-homoglyph) + fail-closed if a mandatory page can't splice | clear-signing render-faithfulness tests | ✅ via clear-signing |
| UI8 | **PIN scramble predictable / seed to a non-trusted backend** | the digit-scramble is guessable, or the mnemonic reaches a dev backend | **DEFENDED (bounded).** PIN start-digits seeded per-position from `rng_strong` XOR-fold (`pin_entry.rs:71-80`); degrades to start-0 on RNG failure (documented, does not refuse); not a full grid-scramble (2-button HW). Backend is **compile-time** fixed (`ui/mod.rs:15-28`): `ui-lcd` = constant-time secret blit; dev backends (`ui-semihosting` prints, `ui-noop` drops) are denylisted from shipping. **Residual (accepted)**: the RNG-failure fallback + the camera-on-screen class | `pin_entry` tests; the backend fence (`build.rs:25-36`) | ✅ (bounded, disclosed) |

**Read this catalog as the answer to "does a physical confirm really gate every sign, and can NS get around it?"** UI3–UI8 are defended (all paths reach confirm, buttons secure-owned, timer single-mutator, backend compile-time fixed). **UI1 and UI2 are the real found-this-surface gaps**: the confirm *result* is the one link in an otherwise heavily-FI-hardened sign chain that is *not* fault-hardened, and `ui-noop` lacks the production fence its dev-backend siblings have. Both are promoted to work-todo.

---

## Part B — The existing defenses (Layer 1)

1. **The confirm contract + scroll-to-end gate.** `confirm.rs` — `confirm(pages) -> {Confirmed, Cancelled, IdleWipe}`; long-right confirms *only* after paging to the last page (`seen_last`, the WYSIWYS mitigation stopping a page-0 long-press skipping spliced drain pages); resets the timer *after* a real button event, never on entry (the HIGH-13 fix). Same gate mirrored in the seed wizard.
2. **The single-mutator timer.** `timeout.rs` — S-owned SysTick tick, `TIMEOUT_TICKS`=120 s, one mutator `reset_activity()` reachable only from physical interaction; `ticks_ptr()` exists for `read_volatile_voted` FI-aware reads. Background idle wipe won't fire while a handler is busy (holds stack secrets); the busy handler observes `is_idle()` at its own `wait_button` checks.
3. **Secure-owned buttons.** `buttons.rs` — PA8/PC1 via secure MMIO aliases, debounce + long-press, both-buttons chord → `(Right, Long)`; per-pin `SECCFGR` keeps them secure through USB bring-up.
4. **Compile-time backend + fences.** `ui/mod.rs` exactly-one-backend (`build.rs:25-36`); `ui-lcd` shipping; dev backends denylisted (`nsc/mod.rs:114-133` — **note the `ui-noop` omission, UI2**); `draw_line` non-ASCII → `'?'`; `ui-capture` per-frame SHA-256 for golden fixtures.
5. **Tests.** HIGH-13 regression (`ui_under_test/pure_tests.rs:510-563`), timer single-mutator (`secure_fi_pin_rng_pure_tests.rs:1471-1559`), confirm-gating source-assertions, `ui-capture` golden render. **Gap**: no `fault_sweep_confirm` (UI1).

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's trusted-UI / confirm path. Your job is
to find a way to SIGN WITHOUT A GENUINE PHYSICAL CONFIRM — via a fault, a build config, an NS
path, or a skipped/after-the-fact confirm — and to defeat the S-only inactivity timer. Default
to "confirm can be bypassed until I prove it gates every sign and NS can't reach it." Note two
KNOWN gaps up front (verify + deepen, don't just restate): the confirm RESULT is not
FI-hardened (UI1), and ui-noop has no mode-production fence (UI2).

TARGET (read first, in this order):
  - docs/security/adversarial-review/trusted-ui-adversarial-review.md §A — UI1–UI8.
  - secure/src/ui/{confirm,pin_entry,seed_wizard,mod,noop,lcd}.rs.
  - secure/src/timeout.rs + secure/src/hw/buttons.rs.
  - The 8 confirm call sites (cmd_sign_userop.rs, cmd_sign_userop_batch.rs, cmd_sign_offchain.rs,
    cmd_offchain_sync.rs, fw_update/mod.rs) + the nsc/mod.rs feature denylist.
SCOPE THIS RUN: {{e.g. "FI-hardness of the confirm result (UI1)" | "the ui-noop fence gap
  (UI2)" | "every sign path reaches confirm before signing (UI6)" | "the timer reset surface
  (UI5)" | "button GPIO ownership (UI4)"}}.

ATTACK PROTOCOL — walk EVERY UI1–UI8 mode:
  UI1 confirm result not FI-hardened · UI2 ui-noop no production fence · UI3 e2e-test
  short-circuit ships · UI4 NS spoofs a button · UI5 timer reset from NS · UI6 sign skips
  confirm · UI7 confirm binds wrong page (cross-link clear-signing) · UI8 PIN scramble / seed
  backend.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a fault (skip/stuck-at) on a Cancelled/IdleWipe arm that falls through to signing (UI1);
  - a feature set that compiles with no physical confirm and reaches a sign (UI2/UI3);
  - a sign handler path that reaches c10_sign without a preceding confirm() (UI6);
  - an NS-reachable path to reset_activity() or to drive PA8/PC1 (UI4/UI5).
  No PoC ⇒ list under "suspicions, unverified".

RULES:
  - Verify against the CURRENT tree; a green host test is not a green fault sweep — the confirm
    result has NO sweep (UI1), so a "confirm gates the sign" claim is source-level only until
    a fault_sweep_confirm exists.
  - WHAT is rendered is clear-signing's surface (UI7) — do not re-audit render faithfulness here.
  - For each finding: UI-mode, file:line, PoC, disposition, severity, proposed fix (flag if it
    would weaken the scroll-to-end gate or the single-mutator timer).

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per mode.
  2. "What I did NOT look at" — call sites not walked, feature combos not tried.
  3. "PROVENANCE — did this pass RUN a fault sweep / the HW confirm e2e, or read source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** ≥3 reviewers per scope, cross-vote, two model backends.

---

## Part D — Cadence + honest boundary

- **Per-PR touching `ui/`, `timeout.rs`, `buttons.rs`, or a confirm call site:** the HIGH-13 + timer + confirm-gating source-tests, and a scoped Part-C pass. A new sign path ships with a confirm-before-sign assertion.
- **Priority follow-ups (from this playbook):** land a `fault_sweep_confirm.py` + harden the confirm accept to a sentinel verdict (UI1); add the `mode-production ⊥ ui-noop` fence (UI2). Both are in work-todo.
- **The one-line gut check:** *if I skip the reject arm / compile a headless build / send an NS ping — can a signature be released without a genuine long-press on the last page?* For UI1 the fault answer is currently "not swept"; for UI2 the build answer is "compiles but hangs (and would auto-confirm if the hang were 'fixed')."

**The boundary, stated on purpose.** This playbook can tell you that every sign path reaches confirm and NS can't reach the buttons or the timer, as of the last executing pass. It **cannot** tell you the confirm result survives a fault (UI1 — no sweep exists), that no future headless build ships without a physical confirm (UI2 — no fence exists), or that the page shown matches the signed bytes (UI7 — clear-signing). The first two are promoted to work-todo; the third is the clear-signing playbook's job.
