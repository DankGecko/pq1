# Silicon-lockdown hardening-depth adversarial-review playbook

> **CURRENT NO-GO (2026-07-11).** The legacy factory receipt reprograms one
> write-once STM32U585 OTP quad-word, so it is not a `READY FOR RDP2` witness.
> Factory builds/flashes, production packaging, and RDP2 authority are blocked.
> Treat older catalog text below as attack input, not authorization.

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code/config-review pass over PQSigner's **silicon-lockdown** surface — the irreversible, hardware-enforced production hardening layers that must all be in place before a device ships: STM32U585 option bytes (RDP / WRP / HDP / BOOT_LOCK / TZEN / SECWM / OTP), the OPTIGA LcsO=Operational ratchet, SE050 lockdown, and secure-boot immutability (WRP1A FSBL). The property this playbook defends is not a single invariant but **hardening depth**:

> **No single lockdown layer, missing or left in a reversible/default state, may collapse the security stack; every layer that *can* be enforced at build time *is*; the irreversible burns happen in the right order (reversible-first, irreversible-last, validate-then-ratchet); and nothing silently ships unhardened.** The defense is a stack — RDP2 + WRP1A + HDP + OTP + debug-lock + OPTIGA-LcsO + SE050-lockdown — and its strength is the depth of the stack, not any one fuse.

**The honest spine — the (a)/(b)/(c) taxonomy.** Every lockdown layer falls into exactly one enforcement class, and **this playbook reviews only class (c):**

- **(a) compile-time-enforced** — a `compile_error!` fence in `nsc/mod.rs` and/or the `make prod-check-ship` allow/deny-list blocks an unhardened build. *These are done; the review confirms the fence exists and can't be bypassed.*
- **(b) bench/factory ceremony (currently NO-GO)** — irreversible burns
  remain unperformed and unauthorized. They are tracked, but an absent or
  broken receipt is a ship blocker, not evidence to suppress a finding.
- **(c) documented-but-not-enforced** — a lockdown step with **neither** a compile fence **nor** a bench-ceremony owner forcing it: it can silently ship un-done. **These are the review's real targets.**

**How this differs from the docs it consolidates.** [`production-todo.md`](../../production-todo.md) is the *burn ceremony* (exact TLV bytes, ordering, the sacrificial-part checklist); [`STATUS.md`](../../STATUS.md) §A is the *current per-blocker state*; [`red-teaming.md`](../red-teaming.md) §5.4/§5.5/§5.6/§6.6 is the *silicon bench pass/fail*; and the per-subsystem runtime code lives in [secure-element](./secure-element-adversarial-review.md) (SE8 lockdown fences), [firmware-update + secure-boot](./firmware-update-secure-boot-adversarial-review.md) (FW7 WRP1A), and [sca-fi](./sca-fi-adversarial-review.md) (DHUK/BHK). **This playbook is the cross-cutting *depth / ordering / enforcement* lens** that no single one of those owns — it asks, across all of them, "is the lockdown stack deep, enforced, correctly ordered, and un-bypassable?" Cross-link, do not re-explain the runtime specifics.

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
| SL2 | **Single-layer collapse (defense-in-depth coverage)** | if layer X is absent, what do the *surviving* layers fail to cover? | **(b) — deferred burns; the review is the coverage map.** RDP2 absent → SWD **readback** of secure flash *despite* WRP1A (WRP only write-protects; RDP is readout — `production-todo.md:644-645`); RDP1 absent → shared DHUK (SL1); OPTIGA F1D0 `Change=ALW` absent-ratchet → PIN gate degrades to **2-of-3** on a desoldered chip (S-1, tracked); BOOT_LOCK unset → SWAP_BANK cross-bank boot redirect (`production-todo.md:599`) | Build the per-layer "absent → exposed" table; each `(b)` burn's absence is a *coverage* fact, not a finding — the depth is the point | ❌ adversary (coverage map) |
| SL3 | **Unfenced silent-unhardened ship (enforcement gap)** | is there a build-time/CI gate that *forces* X out of a shipping image? | The canonical feature set is still resolved and checked, then `prod-check-ship` fails non-ignorably on the open rollback backend. Secure, FSBL, factory, release, and signer paths have independent quarantine gates. | Executed negative-compilation/process tests in CI; any production success is failure | ✅ quarantine |
| SL4 | **Fence escape hatch (fence keyed too narrowly)** | can a *legitimate, shippable* build config bypass a lockdown fence? | No STM32U585 build is silently shippable: production/factory are rejected, and every bench build requires `legacy-fw-rollback-unsafe`, which production policy forbids. | Negative compilation across secure + FSBL feature shapes | ✅ quarantine |
| SL5 | **Wrong ordering (irreversible-before-validation, or wrong sequence → silent-wrong-key/brick)** | is every irreversible step ordered *after* its validation and *after* its dependencies? | **OPEN.** The old sentinel was not an ordering guard because entry and completion attempted to program the same QW. | Replacement receipt and ceremony must be spec-reviewed before any burn; checklist alone is not authority | 🚫 blocked |
| SL6 | **Regression / DECONFIGURE un-lock** | can a path *undo* a lockdown, and does a foot-gun guard get mistaken for a security gate? | **(a/c).** RDP2→RDP0 regression mass-erases main flash + wipes BHK/backup-regs, but **DHUK and OTP survive** (`production-todo.md:485-487`, `otp.rs:388` "no recovery, not even RDP regression"); BHK-rooted SCP03 breaks post-regression (Phase-2C gate). The irreversible-burn foot-gun guards (`factory_provisioning.rs:88`, `prodtest.rs:48`, requiring `factory-production-irreversible-im-sure`) are a **foot-gun guard, NOT a security gate** — "anyone who can add it can remove it" (`:70-72`) | Confirm no *runtime* path lowers a lockdown; the OTP one-way property is the backstop; the foot-gun guards prevent accidents, not attackers | ✅ OTP one-way / ⚠ guards |
| SL7 | **Claimed-but-missing enforcement (claim-vs-code)** | does a doc/claim assert a gate that does not exist? | **Current authority is explicit.** (i) Production requires `optiga-hw-counter`; E120 is lockout authority. F1E1 is only a provisioning/reset sentinel, so deleting `build_metadata_counter()` without replacing its consumers would be incorrect; its final lifecycle remains factory/silicon-gated in `docs/production-todo.md`. (ii) **RDP-verify-in-boot** (`HARDENING.md §4.2`) — **IMPLEMENTED 2026-07-02** (`hw::flash::rdp_level` + a `mode-production` boot check in `main.rs`): WARN-and-continue if RDP != Level 2 (hard-refuse behind the opt-in `rdp-enforce-halt` feature; a hard halt would brick a device during factory rehearsal). LOW/belt-and-braces (RDP2 disables SWD in silicon), so warn-not-halt is correct | Grep for the production E120 requirement, F1E1 sentinel wording, and RDP check | ✅ fence / ⚠ factory lifecycle |

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
5. **The bench/factory ceremony (the `(b)` owner)** — [`production-todo.md`](../../production-todo.md): register-exact TLV bytes (`:119-131`), the WRP-before-RDP2 ordering (`:518-521`), the sacrificial-part rehearsal checklist (`:555-588`), the RM0456 register map (`:639-658`). Silicon evidence: `make optiga-hw-counter-e2e` (PASSED 2026-04-22), `saes-self-test-hw-rdp1` (per-die DHUK), the SE050 stress verifiers.

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
