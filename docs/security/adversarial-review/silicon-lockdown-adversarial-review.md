# Silicon-lockdown hardening-depth adversarial-review playbook

> **CURRENT NO-GO (2026-07-11).** The legacy factory receipt reprograms one
> write-once STM32U585 OTP quad-word, so it is not a `READY FOR RDP2` witness.
> Factory builds/flashes, production packaging, and RDP2 authority are blocked.
> Treat older catalog text below as attack input, not authorization.
>
> **SURFACE SHIFT (2026-07-17 sweep note).** The `rdp2-self-lock` first-boot
> self-lock landed 2026-07-14 (`secure/src/first_boot/`, four fences at
> `nsc/mod.rs:550-611`) and now owns the deepest layer — Phase A (pre-lock
> ship-profile + blank-page checks) → RDP2 burn → Phase B (journaled OTP-master/
> salt/SE rotation). This playbook predates it: SL1's "RDP0 leaves shared-DHUK
> behavior" and SL5's "OPEN" describe the pre-self-lock stack. Review the
> self-lock implementation with the same lenses; the 2026-07-17 sweep already
> filed candidates SL5/SL7/SL8/SL9 below against it.

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code/config-review pass over PQSigner's **silicon-lockdown** surface — the irreversible, hardware-enforced production hardening layers that must all be in place before a device ships: STM32U585 option bytes (RDP / WRP / HDP / BOOT_LOCK / TZEN / SECWM / OTP), the OPTIGA LcsO=Operational ratchet, SE050 lockdown, and secure-boot immutability (WRP1A FSBL). The property this playbook defends is not a single invariant but **hardening depth**:

> **No single lockdown layer, missing or left in a reversible/default state, may collapse the security stack; every layer that *can* be enforced at build time *is*; the irreversible burns happen in the right order (reversible-first, irreversible-last, validate-then-ratchet); and nothing silently ships unhardened.** The defense is a stack — RDP2 + WRP1A + HDP + OTP + debug-lock + OPTIGA-LcsO + SE050-lockdown — and its strength is the depth of the stack, not any one fuse.

**The honest spine — the (a)/(b)/(c) taxonomy.** Every lockdown layer falls into exactly one enforcement class, and **this playbook reviews only class (c):**

- **(a) compile-time-enforced** — a `compile_error!` fence in `nsc/mod.rs` and/or the `make prod-check-ship` allow/deny-list blocks an unhardened build. *These are done; the review confirms the fence exists and can't be bypassed.*
- **(b) bench/factory ceremony (currently NO-GO)** — irreversible burns
  remain unperformed and unauthorized. They are tracked, but an absent or
  broken receipt is a ship blocker, not evidence to suppress a finding.
- **(c) documented-but-not-enforced** — a lockdown step with **neither** a compile fence **nor** a bench-ceremony owner forcing it: it can silently ship un-done. **These are the review's real targets.**

**How this differs from the docs it consolidates.** [`production-todo.md` (archived)](../../archive/production-todo-retired-2026-07-19.md) is the *burn ceremony* (exact TLV bytes, ordering, the sacrificial-part checklist); [`STATUS.md`](../../STATUS.md) §A is the *current per-blocker state*; [`red-teaming.md`](../red-teaming.md) §5.4/§5.5/§5.6/§6.6 is the *silicon bench pass/fail*; and the per-subsystem runtime code lives in [secure-element](./secure-element-adversarial-review.md) (SE8 lockdown fences), [firmware-update + secure-boot](./firmware-update-secure-boot-adversarial-review.md) (FW7 WRP1A), and [sca-fi](./sca-fi-adversarial-review.md) (DHUK/BHK). **This playbook is the cross-cutting *depth / ordering / enforcement* lens** that no single one of those owns — it asks, across all of them, "is the lockdown stack deep, enforced, correctly ordered, and un-bypassable?" Cross-link, do not re-explain the runtime specifics.

> **Current enforcement note.** The older mode-production-only escape and
> meta-gate observations are superseded: all STM32 bench builds require the
> explicit production-forbidden legacy flag, production/factory builds are
> blocked, and the quarantine is enrolled in `verify-gate-enforcement` with an
> executed negative matrix. The irreversible layers themselves remain open.

---

## Part A — The silicon-lockdown depth catalog (SL1–SL7)

Each row asks a **distinct question**. SL1/SL2/SL3 can all fire on the same example (e.g. "RDP1 not burned → DHUK is a shared ST constant → identical pairing keys across every unit"), but they teach different lenses: SL1 = *is the state actually burned or default-read-as-locked?*, SL2 = *if this layer is absent, what do the survivors fail to cover?*, SL3 = *is there a build-time gate forcing it?*

| # | Depth failure mode | The question | Status / class | Detection | Auto? |
|---|---|---|---|---|---|
| SL1 | **Reversible state mistaken for locked (verification gap)** | is each layer *actually burned* on this unit — and validated on a sacrificial part — or just intended? | **SHIP BLOCKER.** RDP0 leaves shared-DHUK behavior; OPTIGA and SE closures remain open. The legacy OTP sentinel is broken and grants no authority. | A new reviewed receipt/ceremony plus later owner-authorized silicon evidence; every legacy sentinel value must report `NOT RDP2 AUTHORITY` | 🚫 blocked |
| SL2 | **Single-layer collapse (defense-in-depth coverage)** | if layer X is absent, what do the *surviving* layers fail to cover? | **(b) — deferred burns; the review is the coverage map.** RDP2 absent → SWD **readback** of secure flash *despite* WRP1A (WRP only write-protects; RDP is readout — `docs/archive/production-todo-retired-2026-07-19.md:519-523`); RDP1 absent → shared DHUK (SL1); OPTIGA F1D0 `Change=ALW` absent-ratchet → PIN gate degrades to **2-of-3** on a desoldered chip (S-1, tracked); BOOT_LOCK unset → SWAP_BANK cross-bank boot redirect (`docs/archive/production-todo-retired-2026-07-19.md:651-664`) | Build the per-layer "absent → exposed" table; each `(b)` burn's absence is a *coverage* fact, not a finding — the depth is the point | ❌ adversary (coverage map) |
| SL3 | **Unfenced silent-unhardened ship (enforcement gap)** | is there a build-time/CI gate that *forces* X out of a shipping image? | The canonical feature set is still resolved and checked, then `prod-check-ship` fails non-ignorably on the open rollback backend. Secure, FSBL, factory, release, and signer paths have independent quarantine gates. | Executed negative-compilation/process tests in CI; any production success is failure | ✅ quarantine |
| SL4 | **Fence escape hatch (fence keyed too narrowly)** | can a *legitimate, shippable* build config bypass a lockdown fence? | No STM32U585 build is silently shippable: production/factory are rejected, and every bench build requires `legacy-fw-rollback-unsafe`, which production policy forbids. | Negative compilation across secure + FSBL feature shapes | ✅ quarantine |
| SL5 | **Wrong ordering (irreversible-before-validation, or wrong sequence → silent-wrong-key/brick)** | is every irreversible step ordered *after* its validation and *after* its dependencies? | **OPEN — candidate instance found in the new self-lock (2026-07-17, pre-adjudication).** Phase A (`first_boot/mod.rs:124-176`) verifies option bytes + blank pages 123-127 but never the per-device OTP master; `otp_master_burned()` runs in Phase B (`first_boot/state.rs:157-162`), **after** the irreversible RDP-2 lock — a unit whose only defect is a skipped *reversible* factory step bricks permanently at `halt_first_boot(E0811)` with SWD dead, while the docs claim OTP is part of the pre-lock, halt-unlocked mismatch class (`state.rs:54-55`, `first-boot-provisioning.md:131`). Sub-mode to hunt generally: *a dependency validated only after the irreversible step it feeds*. Fix: add `otp::master_key_state() == Complete` (read-only, already fail-closed) to Phase A. Legacy: the old sentinel was not an ordering guard because entry and completion attempted to program the same QW | Replacement receipt and ceremony must be spec-reviewed before any burn; checklist alone is not authority | 🚫 blocked / ❌ candidate |
| SL6 | **Regression / DECONFIGURE un-lock** | can a path *undo* a lockdown, and does a foot-gun guard get mistaken for a security gate? | **(a/c).** RDP2→RDP0 regression mass-erases main flash + wipes BHK/backup-regs, but **DHUK and OTP survive** (`docs/archive/production-todo-retired-2026-07-19.md:524-528`, `otp.rs:398-399` "no recovery, not even RDP regression"); BHK-rooted SCP03 breaks post-regression (Phase-2C gate). The irreversible-burn foot-gun guards (`factory_provisioning.rs:88`, `prodtest.rs:33`, requiring `factory-production-irreversible-im-sure`) are a **foot-gun guard, NOT a security gate** — "anyone who can add it can remove it" (`:70-72`) | Confirm no *runtime* path lowers a lockdown; the OTP one-way property is the backstop; the foot-gun guards prevent accidents, not attackers | ✅ OTP one-way / ⚠ guards |
| SL7 | **Claimed-but-missing enforcement (claim-vs-code)** | does a doc/claim assert a gate that does not exist? | **Current authority is explicit.** (i) Production requires `optiga-hw-counter`; E120 is lockout authority. F1E1 is only a provisioning/reset sentinel, so deleting `build_metadata_counter()` without replacing its consumers would be incorrect; its final lifecycle remains factory/silicon-gated, tracked as a GitHub issue on `EthereumPhone/PQ1` (`source:production-todo`). (ii) **RDP-verify-in-boot** (`HARDENING.md §4.2`) — **IMPLEMENTED 2026-07-02** and now journal-aware under `rdp2-self-lock` with a hard halt post-`ALL_DONE` (`main.rs:929-938`), superseding the WARN-and-continue posture. (iii) **Candidate (2026-07-17, pre-adjudication):** `production-security.md:514` and `threat-model.md:606` state the BHK lives in "HDP-protected flash" as a *current* property — the ship profile sets `HDP1EN=HDP2EN=0` and nothing in `secure/src` engages HDP (no SECWM1R2/SECHDPCR write; `verify_ship_profile` has no HDP field). The BHK sits in ordinary secure flash (DHUK-wrapped, so exposure is the wrapped blob). Fix: mark HDP as a deferred layer in both docs; when it lands, add it to `verify_ship_profile`. Sub-mode to hunt: *docs asserting a hardware protection the ship profile explicitly disables* — grep the threat model for other "X-protected" claims vs the OB profile | Grep for the production E120 requirement, F1E1 sentinel wording, RDP check, and "HDP-protected" claims vs `HDP1EN` | ✅ fence / ⚠ factory lifecycle / ❌ candidate |
| SL8 | **BENCH-CONFIRM-but-load-bearing register guesses** | a hard gate in the ship-profile verify rests on an unconfirmed register/bit-layout guess whose wrong-guess direction is *vacuous-pass* | **CANDIDATE (2026-07-17, pre-adjudication; LOW).** `shared/src/lockdown.rs:98-104` (`OEM1LOCK/OEM2LOCK` bit positions) and `:161-173` (WRP1AR layout) are runbook pins; the host tests verify the *comparator* on synthetic values, never the shipped register read. If a guessed field reads as constant 0, `oem_locks_absent`/`wrp1a_covers_fsbl` **pass vacuously** — a transit attacker pre-plants an OEM2 password or strips WRP1A and sails through the one gate that exists to catch exactly that (the false-halt direction bricks every genuine first boot instead — also invisible to host tests). Fix: the #36 bench pin must record, per BENCH-CONFIRM field, the failure direction, and prioritize fields whose wrong-guess direction is vacuous-pass | Bench readback of the real registers vs the pinned constants | ❌ found-this-surface (candidate) |
| SL9 | **Pre-irreversible profile check is a spot-check, not an exact masked compare** | unverified OPTR bits (SWAP_BANK, nSWBOOT0, nBOOT0, NRST_MODE) are preserved verbatim into the permanent RDP-2 state | **CANDIDATE (2026-07-17, pre-adjudication; LOW-MEDIUM).** `lockdown.rs:139-147` checks only TZEN + RDP byte; `verify_ship_profile` adds SECWM/SECBOOTADD0/WRP1A/OEM but never compares the remaining OPTR bits; the burn preserves every non-RDP bit (`hw/flash.rs:520`). The "verifies the published ship option-byte profile" claim (`first_boot/mod.rs:133-135`) overstates a two-field check. (The pure-transit SWAP_BANK scenario itself fires before Phase A and is owned by the tracked BOOT_LOCK item — this row is the claim-vs-code + frozen-unverified-state class.) Fix: exact masked compare of full OPTR (expected value + don't-care mask) | n/a (code-shape) | ❌ found-this-surface (candidate) |

**Current answer:** the intended depth is not yet a shipping property. The
software quarantine prevents accidental claims while the replacement rollback
and factory authority remain open.

---

## Part B — The enforcement backbone (what already forces the lockdown)

1. **The `compile_error!` fence wall** (`secure/src/nsc/mod.rs`, ~20 fences). The feature-flag half of every lockdown: the dev-feature denylist, the Tier-1 SE-key requirement, S-3 `optiga-hw-counter`, the unconditional retired `optiga-reset-oids` fence, the independent `OPTIGA_S2_PRODUCTION_BLOCKED` gate for every production OPTIGA image, the S-1 `optiga-lock-operational` candidate requirement, consumption-mask, tamp/tamp-wipe/tzic-wipe, HIGH-1 `se050-derived-scp03`, `optiga-no-shield`-forbidden, the mode-production ⊥ {e2e-test, dev-testkey, ui-noop, mlkem, erc7730-dev-unattested, fw-rollback-e2e, fwup-transport-e2e} guards, and the UI/SE backend exactly-one checks. Line numbers are deliberately omitted because this wall changes frequently; grep the dedicated diagnostic strings and execute the negative compilation tests.
2. **`make prod-check-ship` (blocking CI)** — the production-quarantine job
   first resolves and validates `PROD_SHIP_FEATURES`, then requires the exact
   non-ignorable rollback refusal. CI also executes the negative build matrix.
3. **The legacy OTP factory sentinel is quarantined.** It is not an ordering
   guard and never signals RDP2 readiness. Its host decoder returns nonzero for
   every value; a replacement receipt remains open.
4. **The irreversible-burn foot-gun guards** (`factory_provisioning.rs:88`, `prodtest.rs:48`, requiring `factory-production-irreversible-im-sure`) — prevent *accidental* burns; explicitly not a security gate (SL6).
5. **The bench/factory ceremony (the `(b)` owner)** — [`production-todo.md` (archived)](../../archive/production-todo-retired-2026-07-19.md): register-exact TLV bytes (`:151-162`), the WRP-before-RDP2 ordering (`:563-566`), the sacrificial-part rehearsal checklist (`:600-641`), the RM0456 register map (`:697-716`). Silicon evidence: `make optiga-hw-counter-e2e` (PASSED 2026-04-22), `saes-self-test-hw-rdp1` (per-die DHUK), the SE050 stress verifiers.

**The one new (low) item — CLOSED 2026-07-02:** the fence wall + `prod-check-ship` were not registered in `scripts/gate_enforcement.json`, so the `verify-gate-enforcement` meta-gate did not police them. A `prod-check-ship` entry is now enrolled (`per_pr_blocking`, `polices_paths` = `nsc/mod.rs` + `Cargo.toml` + `Makefile`); the checker validates it. The S-3 review was refined: production already requires E120 lockout, while F1E1 is the provisioning/reset sentinel. Its final lifecycle or replacement is deferred to the hardware-validated owner path (work-todo #12e), not a partial one-line fence.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's SILICON-LOCKDOWN hardening DEPTH.
Find where the irreversible stack is shallow, unenforced, misordered, bypassable, or
falsely claimed complete. Known burns need not be duplicate-filed, but their absence is
still a ship blocker. Cross-link existing owners and always report false authority or a
quarantine bypass.

TARGET (read first, in this order):
  - docs/security/adversarial-review/silicon-lockdown-adversarial-review.md §A — SL1–SL7 +
    the (a)/(b)/(c) taxonomy.
  - secure/src/nsc/mod.rs — the compile_error! fence wall (the (a) enforcement).
  - Makefile PROD_SHIP_FEATURES / prod-check-ship + .github/workflows/ci.yml:106-126 (is it
    a BLOCKING step?).
  - secure/src/hw/{otp,secret_keys,bhk,saes}.rs — OTP sentinel, DHUK/BHK RDP-gating.
  - secure/src/optiga/apdu.rs (build_metadata_*), secure/src/se050/scp03.rs — the metadata
    the ratchet/ceremony installs.
  - docs/archive/production-todo-retired-2026-07-19.md (the (b) ceremony + ordering) + docs/STATUS.md §A (per-blocker
    state) — the tracking you cross-link to.
SCOPE THIS RUN: {{e.g. "the defense-in-depth coverage map (SL2)" | "every fence's cfg for
  an escape hatch (SL4)" | "the burn ORDERING dependencies (SL5)" | "claimed-but-missing
  gates (SL7)" | "is prod-check-ship blocking + meta-enforced (SL3)"}}.

ATTACK PROTOCOL — walk EVERY SL1–SL7 mode; for each, either produce a PoC OR cite the
tracking (docs/STATUS.md §A or an `EthereumPhone/PQ1` issue) that already owns it:
  SL1 reversible-mistaken-for-locked (verification) · SL2 single-layer-collapse (coverage) ·
  SL3 unfenced-silent-ship (enforcement) · SL4 fence-escape-hatch · SL5 wrong-ordering ·
  SL6 regression/un-lock · SL7 claimed-but-missing-gate.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a shipping feature-combo that compiles WITHOUT a lockdown feature and hits NO fence AND
    NO prod-check failure (a genuine (c) silent-unhardened ship);
  - a cfg predicate that lets a legitimate build bypass a lockdown fence (SL4);
  - an ordering dependency where the irreversible step can run before its validation/dep;
  - a claimed gate (grep) that does not exist in the source (SL7);
  - a defense-in-depth coverage row: "layer X absent → secret Y exposed via Z".
  No PoC ⇒ list under "suspicions, unverified". If docs/STATUS.md or an `EthereumPhone/PQ1` issue already tracks it,
  say so and cross-link — do NOT re-file it as new.

RULES:
  - Verify against the CURRENT tree; distinguish software-enforced quarantine,
    tracked-but-absent silicon state, and genuinely closed evidence.
  - Known S-1/S-2/S-3 items need not be duplicate-filed, but remain ship blockers;
    report every false closure/authority statement and new code/CI bypass.
  - Defer per-subsystem runtime specifics to the sibling playbooks (secure-element SE8,
    fw-update FW7, sca-fi DHUK/BHK) — cross-link, don't re-explain.
  - For each candidate: SL-mode, (a)/(b)/(c) class, file:line or doc:line,
    PoC, provisional severity, stable candidate ID, and proposed fix — flagging if a "fix" would make an irreversible burn fire in a
    dev/test build (a brick risk).
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
  1. "What I tried to break and COULDN'T" — the layers whose enforcement/ordering held.
  2. "What I did NOT look at" — layers not walked, the on-silicon burn state (bench-only).
  3. "PROVENANCE — did this pass READ the fence source + run prod-check-ship / cargo tree,
     or reason from docs only?" A depth review that didn't resolve whether prod-check-ship
     is a BLOCKING CI check cannot judge SL3.
  Never imply "the rest is fine." Absence of a finding on a (c) layer is not evidence it is
  burned on silicon — that is the factory ceremony's job.
```

**Running it as a swarm.** Use ≥3 independent discovery reviewers per scope
across two model backends. Quorum only corroborates/prioritizes discovery; it
does not set a disposition, and sub-quorum variants remain in the packet. Give
every candidate and origin variant to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only their symmetric cross-adjudication may disposition it, with disagreement
preserved. Split SL2's coverage map one-layer-per-reviewer (each owns "if
RDP2/RDP1/WRP1A/LcsO/BOOT_LOCK is absent, what's exposed?").

---

## Part D — Cadence + honest boundary

- **Per-PR touching a fence (`nsc/mod.rs`), `PROD_SHIP_FEATURES`, `otp.rs`, or a `build_metadata_*` builder:** re-run `make prod-check-ship` + confirm the fence still fires (a scoped Part-C pass on the changed fence). A new lockdown feature ships with a fence + a `prod-check` require/deny entry, or it is a `(c)` silent-ship gap.
- **Future pre-design-lock only:** define a replacement receipt/ceremony, obtain
  independent approval and named-board authorization, then execute its exact
  silicon plan. The legacy procedure is not that plan.
- **The one-line gut check:** *for each lockdown layer — is it (a) fenced so it can't ship un-done, (b) a tracked one-time burn, or (c) silently shippable? And if the deepest one (RDP2) were absent, what secret becomes readable?* If a layer is `(c)` and load-bearing, or you can't answer the RDP2-absent question, the stack is shallower than it looks.
- **Drift-proofing — cite fences by STRING, not line.** `nsc/mod.rs` (the fence wall) churns; a citation like `nsc/mod.rs:389` rots within weeks, and a review that greps a stale line finds nothing and mis-reports a live fence as missing (this bit `STATUS.md §A`, which cited the S-1/S-3 fences at long-dead lines). Anchor every fence reference on its unique compile-error string — `optiga-lock-operational` (S-1), `optiga-hw-counter` (S-3), `se050-derived-scp03` (HIGH-1) — so `grep` locates it regardless of line drift.

> **Scope note — runtime TZ-config lock is a SIBLING layer, not covered here.** This playbook is the *irreversible* (fuse/OTP/LcsO) lockdown lens. The **runtime, reset-scoped** TrustZone-config lock — `sau::lock_security_config` (SYSCFG `CSLCKR` LOCKSAU|LOCKSVTAIRCR + GTZC1 `TZSC_CR.LCK` + AIRCR PRIS/BFHFNMINS, tz-2, landed 2026-07-02) — freezes SAU/GTZC/AIRCR *per boot* so a later fault/stray write can't rewrite the S/NS partition. It is a distinct depth layer that composes with these burns but is **not** one of them; it belongs to the [trustzone-gateway](./trustzone-gateway-adversarial-review.md) playbook (see its TZ-lock row). Don't (a)/(b)/(c)-classify it here — it's neither an irreversible burn nor a compile fence; it's a boot-time register lock.

**The boundary, stated on purpose.** This playbook can verify the current
code/CI quarantine. It cannot establish per-unit irreversible state: no valid
factory receipt or approved ceremony exists in this revision, and the legacy
OTP sentinel is never evidence. That authority requires a future reviewed
ceremony plus separately authorized on-silicon receipts.
