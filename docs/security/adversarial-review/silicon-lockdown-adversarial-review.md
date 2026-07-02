# Silicon-lockdown hardening-depth adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code/config-review pass over PQSigner's **silicon-lockdown** surface — the irreversible, hardware-enforced production hardening layers that must all be in place before a device ships: STM32U585 option bytes (RDP / WRP / HDP / BOOT_LOCK / TZEN / SECWM / OTP), the OPTIGA LcsO=Operational ratchet, SE050 lockdown, and secure-boot immutability (WRP1A FSBL). The property this playbook defends is not a single invariant but **hardening depth**:

> **No single lockdown layer, missing or left in a reversible/default state, may collapse the security stack; every layer that *can* be enforced at build time *is*; the irreversible burns happen in the right order (reversible-first, irreversible-last, validate-then-ratchet); and nothing silently ships unhardened.** The defense is a stack — RDP2 + WRP1A + HDP + OTP + debug-lock + OPTIGA-LcsO + SE050-lockdown — and its strength is the depth of the stack, not any one fuse.

**The honest spine — the (a)/(b)/(c) taxonomy.** Every lockdown layer falls into exactly one enforcement class, and **this playbook reviews only class (c):**

- **(a) compile-time-enforced** — a `compile_error!` fence in `nsc/mod.rs` and/or the `make prod-check-ship` allow/deny-list blocks an unhardened build. *These are done; the review confirms the fence exists and can't be bypassed.*
- **(b) bench/factory ceremony (deferred-by-design, NOT a finding)** — an irreversible on-silicon burn (RDP2, WRP1A, HDP, OTP-master, the OPTIGA LcsO ratchet + sacrificial-part validation, the SE050 PUT-KEY ceremony, BOOT_LOCK, the vendor-pubkey OTP hash). Real chips cost money and the burns are one-way, so the reversible FV/design hardening is done first and the ceremony runs **once at design-lock**. These are tracked in [`docs/production-todo.md`](../../production-todo.md) + [`docs/STATUS.md`](../../STATUS.md) §A. **Cite them as tracked; never report them as gaps** (see [`memory: OPTIGA ship-blockers deferred deliberately`]).
- **(c) documented-but-not-enforced** — a lockdown step with **neither** a compile fence **nor** a bench-ceremony owner forcing it: it can silently ship un-done. **These are the review's real targets.**

**How this differs from the docs it consolidates.** [`production-todo.md`](../../production-todo.md) is the *burn ceremony* (exact TLV bytes, ordering, the sacrificial-part checklist); [`STATUS.md`](../../STATUS.md) §A is the *current per-blocker state*; [`red-teaming.md`](../red-teaming.md) §5.4/§5.5/§5.6/§6.6 is the *silicon bench pass/fail*; and the per-subsystem runtime code lives in [secure-element](./secure-element-adversarial-review.md) (SE8 lockdown fences), [firmware-update + secure-boot](./firmware-update-secure-boot-adversarial-review.md) (FW7 WRP1A), and [sca-fi](./sca-fi-adversarial-review.md) (DHUK/BHK). **This playbook is the cross-cutting *depth / ordering / enforcement* lens** that no single one of those owns — it asks, across all of them, "is the lockdown stack deep, enforced, correctly ordered, and un-bypassable?" Cross-link, do not re-explain the runtime specifics.

> **Honesty note — this playbook surfaced zero new *untracked* security gaps.** This surface is heavily pre-documented (production-todo has the register-exact TLV bytes; STATUS has a row per blocker). The class-(c) enforcement residuals below — RDP-verify-in-boot, BOOT_LOCK unset, the S-3 soft-counter absence, the vendor-pubkey OTP hash, the S-1 `mode-production`-only fence escape hatch — are **already tracked** in STATUS §A / production-todo / threat-model §9. The one genuinely-new (low) consistency observation is that the lockdown enforcement (`prod-check-ship` + the `nsc/mod.rs` fence wall) is **not enrolled in the `verify-gate-enforcement` meta-gate** the way the FV gates are — promoted to work-todo. The value of this doc is the consolidated depth lens + the master prompt, not a finding count.

---

## Part A — The silicon-lockdown depth catalog (SL1–SL7)

Each row asks a **distinct question**. SL1/SL2/SL3 can all fire on the same example (e.g. "RDP1 not burned → DHUK is a shared ST constant → identical pairing keys across every unit"), but they teach different lenses: SL1 = *is the state actually burned or default-read-as-locked?*, SL2 = *if this layer is absent, what do the survivors fail to cover?*, SL3 = *is there a build-time gate forcing it?*

| # | Depth failure mode | The question | Status / class | Detection | Auto? |
|---|---|---|---|---|---|
| SL1 | **Reversible state mistaken for locked (verification gap)** | is each layer *actually burned* on this unit — and validated on a sacrificial part — or just intended? | **(b/c) — the review target is verification, not the burn.** RDP0 reads as "no readout protection" and DHUK is then a **shared ST constant** (`hw/secret_keys.rs:42-45`) — all units derive identical SCP03/PBS/admin secrets, with **no runtime signal** (there is no firmware `FLASH_OPTR.RDP` read); OPTIGA F1D0 ships `LcsO<op` (rewriteable) until the ratchet; BHK-rooted SCP03 must be re-validated post-any-RDP-regression | The OTP **factory sentinel** (`hw/otp.rs:157-187`, "READY FOR RDP2" gate) records that the master burn + rehearsal happened; `make saes-self-test-hw-rdp1` fingerprints the per-die DHUK; on-silicon: re-run `pin-gate-hw-counter-e2e` against a *ratcheted* sacrificial part (bench, red-teaming §5.4) | ⚠ OTP sentinel + bench |
| SL2 | **Single-layer collapse (defense-in-depth coverage)** | if layer X is absent, what do the *surviving* layers fail to cover? | **(b) — deferred burns; the review is the coverage map.** RDP2 absent → SWD **readback** of secure flash *despite* WRP1A (WRP only write-protects; RDP is readout — `production-todo.md:644-645`); RDP1 absent → shared DHUK (SL1); OPTIGA F1D0 `Change=ALW` absent-ratchet → PIN gate degrades to **2-of-3** on a desoldered chip (S-1, tracked); BOOT_LOCK unset → SWAP_BANK cross-bank boot redirect (`production-todo.md:599`) | Build the per-layer "absent → exposed" table; each `(b)` burn's absence is a *coverage* fact, not a finding — the depth is the point | ❌ adversary (coverage map) |
| SL3 | **Unfenced silent-unhardened ship (enforcement gap)** | is there a build-time/CI gate that *forces* X out of a shipping image? | **(a) mostly closed / (c) residuals.** The `nsc/mod.rs` fence wall (~20 `compile_error!`) + `make prod-check-ship` (blocking CI, `ci.yml:106-126`) force the *feature-flag* half (S-1 metadata, S-2, S-3-presence, HIGH-1, Tier-1 keys, consumption-mask, tamp/tzic-wipe). **(c) residuals with NO gate**: BOOT_LOCK=1 (not set today), the vendor-pubkey OTP hash lock (threat-model §9.8), RDP-verify-in-boot (SL7) — all silently shippable, all **already tracked** | Audit each lockdown layer: compile-fence OR `prod-check` OR `(b)` bench-owner? A layer with none is a `(c)` gap. **Meta**: the fence wall itself is not in `verify-gate-enforcement` → work-todo | ✅ prod-check-ship (feature half) |
| SL4 | **Fence escape hatch (fence keyed too narrowly)** | can a *legitimate, shippable* build config bypass a lockdown fence? | **(c) — documented convention.** The **S-1** fence (`nsc/mod.rs:389`) is keyed to `mode-production` **ALONE** — a release `stm32u585` image built *without* `mode-production` compiles S-1-open (the LcsO ratchet must not fire on dev/test release builds, so the narrow keying is deliberate, but the escape hatch is real; documented `:369-379`, `STATUS.md:78`) | Audit each fence's `#[cfg(...)]` predicate for an unintended-but-shippable bypass; confirm `PROD_SHIP_FEATURES` (Makefile) is the canonical string CI actually pins | ⚠ tracked (STATUS §A) |
| SL5 | **Wrong ordering (irreversible-before-validation, or wrong sequence → silent-wrong-key/brick)** | is every irreversible step ordered *after* its validation and *after* its dependencies? | **(b/c) — checklist-enforced.** WRP1A `UNLOCK=0` MUST precede RDP2 (WRP is removable only while RDP≠2 — `production-todo.md:518-521`); BHK/SCP03 provisioning MUST happen *after* stepping to the final RDP level or the page-126 DHUK-wrap is silently wrong → **dead SE050** (`:811-819`); E120 MUST be created before F1D0's LUC metadata references it (`apdu.rs:1016-1019`); OTP master burn MUST precede the RDP2 sentinel (`otp.rs:157`) | The `production-todo.md` pre-commit checklist (`:555-588`) + the OTP factory sentinel ordering guard; a mis-order is a **brick**, so this is bench-rehearsal, not a runtime check | ⚠ checklist + OTP sentinel |
| SL6 | **Regression / DECONFIGURE un-lock** | can a path *undo* a lockdown, and does a foot-gun guard get mistaken for a security gate? | **(a/c).** RDP2→RDP0 regression mass-erases main flash + wipes BHK/backup-regs, but **DHUK and OTP survive** (`production-todo.md:485-487`, `otp.rs:388` "no recovery, not even RDP regression"); BHK-rooted SCP03 breaks post-regression (Phase-2C gate). The irreversible-burn foot-gun guards (`factory_provisioning.rs:88`, `prodtest.rs:48`, requiring `factory-production-irreversible-im-sure`) are a **foot-gun guard, NOT a security gate** — "anyone who can add it can remove it" (`:70-72`) | Confirm no *runtime* path lowers a lockdown; the OTP one-way property is the backstop; the foot-gun guards prevent accidents, not attackers | ✅ OTP one-way / ⚠ guards |
| SL7 | **Claimed-but-missing enforcement (claim-vs-code)** | does a doc/claim assert a gate that does not exist? | **(c) — two, both low, both tracked.** (i) The **S-3** `build_metadata_counter()` production gate **does not exist**: `apdu.rs:971` is un-gated and installs the *weak* F1D5 soft-counter; only `optiga-hw-counter` *presence* is fenced, not the soft-path *absence* (`STATUS.md:80,98` — code-doable residual). (ii) **RDP-verify-in-boot** (`HARDENING.md §4.2`) — **IMPLEMENTED 2026-07-02** (`hw::flash::rdp_level` + a `mode-production` boot check in `main.rs`): WARN-and-continue if RDP != Level 2 (hard-refuse behind the opt-in `rdp-enforce-halt` feature; a hard halt would brick a device during factory rehearsal). LOW/belt-and-braces (RDP2 disables SWD in silicon), so warn-not-halt is correct | Grep for the claimed gate; both are already in STATUS/HARDENING — cite, don't re-file | ❌ adversary (grep, tracked) |

**Read this catalog as the answer to "is the lockdown stack deep enough that no single miss sinks it?"** The depth is real: the `(a)` fence wall + blocking `prod-check-ship` force every enforceable layer, the `(b)` burns are a tracked one-time ceremony, and the `(c)` residuals are all documented and mostly belt-and-braces. **The sharpest lens is SL2** (the "absent → exposed" coverage map — RDP2 is load-bearing for readback secrecy, RDP1 for per-die DHUK, LcsO for the third PIN factor) and **SL4** (the S-1 fence's deliberate `mode-production`-only keying). No new *untracked* security gap survived; the enforcement-meta observation (SL3 "meta") is the one low item promoted.

---

## Part B — The enforcement backbone (what already forces the lockdown)

1. **The `compile_error!` fence wall** (`secure/src/nsc/mod.rs`, ~20 fences). The feature-flag half of every lockdown: the dev-feature denylist (`:114`), the Tier-1 SE-key REQUIRE (`:190`), S-3 `optiga-hw-counter` (`:331`), S-2 `optiga-reset-oids`-forbidden (`:354`), S-1 `optiga-lock-operational` (`:389`), consumption-mask (`:419`), tamp/tamp-wipe/tzic-wipe (`:457`), HIGH-1 `se050-derived-scp03` (`:496`), `optiga-no-shield`-forbidden (`:526`), the mode-production ⊥ {e2e-test, dev-testkey, ui-noop, mlkem, erc7730-dev-unattested, fw-rollback-e2e, fwup-transport-e2e} guards, and the UI/SE backend exactly-one checks.
2. **`make prod-check-ship` (blocking CI)** — `ci.yml:106-126`, the "Production feature-set gate (MED-2)" job (a normal `run:` step, no `continue-on-error`). Resolves `PROD_SHIP_FEATURES` and hard-fails if any never-ship feature is active OR any required hardening feature is missing (transitively, via `cargo tree`). Belt-and-braces with the compile fences.
3. **The OTP factory sentinel** (`hw/otp.rs:157-187`) — the *ordering* guard: records master-burn/rehearsal/production-complete so the host fixture only signals "READY FOR RDP2" after the reversible provisioning actually ran. Backs SL1/SL5.
4. **The irreversible-burn foot-gun guards** (`factory_provisioning.rs:88`, `prodtest.rs:48`, requiring `factory-production-irreversible-im-sure`) — prevent *accidental* burns; explicitly not a security gate (SL6).
5. **The bench/factory ceremony (the `(b)` owner)** — [`production-todo.md`](../../production-todo.md): register-exact TLV bytes (`:119-131`), the WRP-before-RDP2 ordering (`:518-521`), the sacrificial-part rehearsal checklist (`:555-588`), the RM0456 register map (`:639-658`). Silicon evidence: `make optiga-hw-counter-e2e` (PASSED 2026-04-22), `saes-self-test-hw-rdp1` (per-die DHUK), the SE050 stress verifiers.

**The one new (low) item — CLOSED 2026-07-02:** the fence wall + `prod-check-ship` were not registered in `scripts/gate_enforcement.json`, so the `verify-gate-enforcement` meta-gate did not police them. A `prod-check-ship` entry is now enrolled (`per_pr_blocking`, `polices_paths` = `nsc/mod.rs` + `Cargo.toml` + `Makefile`); the checker validates it (18/18 green, self-test passes). The S-3 soft-counter fence turned out NOT to be a quick fence (F1E1 is deeply integrated — read at 5+ sites, written by `factory_reset_body`, LcsO-ratcheted) → refined + deferred to a hardware-validated pass (work-todo #12e).

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's SILICON-LOCKDOWN hardening DEPTH.
Your job is to find where the irreversible lockdown stack is SHALLOW, UN-ENFORCED,
MIS-ORDERED, or BYPASSABLE — NOT to re-list the deferred factory burns. Default to "a
lockdown layer is un-done or reversible until I prove it is burned/enforced." Use the
(a)/(b)/(c) taxonomy as your spine and REVIEW ONLY CLASS (c): (a) is compile-fenced and
done, (b) is a deferred-by-design one-time factory ceremony (tracked in production-todo /
STATUS — NEVER report a (b) burn as a finding), (c) is documented-but-not-enforced — the
only real target. Do NOT manufacture findings; this surface is heavily pre-documented, so
"already tracked in STATUS §A / production-todo, cross-linked" is the honest common output.

TARGET (read first, in this order):
  - docs/security/adversarial-review/silicon-lockdown-adversarial-review.md §A — SL1–SL7 +
    the (a)/(b)/(c) taxonomy.
  - secure/src/nsc/mod.rs — the compile_error! fence wall (the (a) enforcement).
  - Makefile PROD_SHIP_FEATURES / prod-check-ship + .github/workflows/ci.yml:106-126 (is it
    a BLOCKING step?).
  - secure/src/hw/{otp,secret_keys,bhk,saes}.rs — OTP sentinel, DHUK/BHK RDP-gating.
  - secure/src/optiga/apdu.rs (build_metadata_*), secure/src/se050/scp03.rs — the metadata
    the ratchet/ceremony installs.
  - docs/production-todo.md (the (b) ceremony + ordering) + docs/STATUS.md §A (per-blocker
    state) — the tracking you cross-link to.
SCOPE THIS RUN: {{e.g. "the defense-in-depth coverage map (SL2)" | "every fence's cfg for
  an escape hatch (SL4)" | "the burn ORDERING dependencies (SL5)" | "claimed-but-missing
  gates (SL7)" | "is prod-check-ship blocking + meta-enforced (SL3)"}}.

ATTACK PROTOCOL — walk EVERY SL1–SL7 mode; for each, either produce a PoC OR cite the
tracking (STATUS/production-todo) that already owns it:
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
  No PoC ⇒ list under "suspicions, unverified". If STATUS/production-todo already tracks it,
  say so and cross-link — do NOT re-file it as new.

RULES:
  - Verify against the CURRENT tree; distinguish (a) enforced / (b) deferred-by-design /
    (c) unenforced. A (b) burn is NOT a finding — it is tracked ceremony work.
  - S-1/S-2/S-3 and every irreversible burn are DEFERRED-BY-DESIGN. Report only NEW
    code/CI-doable enforcement gaps, never the known blockers.
  - Defer per-subsystem runtime specifics to the sibling playbooks (secure-element SE8,
    fw-update FW7, sca-fi DHUK/BHK) — cross-link, don't re-explain.
  - For each finding: SL-mode, (a)/(b)/(c) class, file:line or doc:line, PoC, disposition,
    severity, proposed fix — flagging if a "fix" would make an irreversible burn fire in a
    dev/test build (a brick risk).

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — the layers whose enforcement/ordering held.
  2. "What I did NOT look at" — layers not walked, the on-silicon burn state (bench-only).
  3. "PROVENANCE — did this pass READ the fence source + run prod-check-ship / cargo tree,
     or reason from docs only?" A depth review that didn't resolve whether prod-check-ship
     is a BLOCKING CI check cannot judge SL3.
  Never imply "the rest is fine." Absence of a finding on a (c) layer is not evidence it is
  burned on silicon — that is the factory ceremony's job.
```

**Running it as a swarm.** ≥3 reviewers per scope, cross-vote, two model backends. Split SL2's coverage map one-layer-per-reviewer (each owns "if RDP2/RDP1/WRP1A/LcsO/BOOT_LOCK is absent, what's exposed?").

---

## Part D — Cadence + honest boundary

- **Per-PR touching a fence (`nsc/mod.rs`), `PROD_SHIP_FEATURES`, `otp.rs`, or a `build_metadata_*` builder:** re-run `make prod-check-ship` + confirm the fence still fires (a scoped Part-C pass on the changed fence). A new lockdown feature ships with a fence + a `prod-check` require/deny entry, or it is a `(c)` silent-ship gap.
- **Pre-design-lock (once):** the full `(b)` factory ceremony per `production-todo.md` — the sacrificial-part rehearsal, then the irreversible RDP2 / WRP1A / LcsO / OTP / PUT-KEY burns in order, then the bench red-team (red-teaming.md §5.4/§6.6) against a *ratcheted* part.
- **The one-line gut check:** *for each lockdown layer — is it (a) fenced so it can't ship un-done, (b) a tracked one-time burn, or (c) silently shippable? And if the deepest one (RDP2) were absent, what secret becomes readable?* If a layer is `(c)` and load-bearing, or you can't answer the RDP2-absent question, the stack is shallower than it looks.

**The boundary, stated on purpose.** This playbook can tell you whether the lockdown is *enforceable-and-enforced* at the code/CI level (the fence wall + blocking `prod-check-ship`), whether the ordering dependencies are documented, and which layers are `(c)` silently-shippable — all against the source, as of the last executing pass. It **cannot** tell you the irreversible burns actually happened on a given unit (that is the factory ceremony + the OTP sentinel + on-silicon bench verification — `production-todo.md` / `red-teaming.md`), that a `(b)` layer is present on the die in front of you, or that a sacrificial-part rehearsal validated the ratchet. Those are the ceremony's and the bench's job — and they are the point at which "reviewed" becomes "shipped."
