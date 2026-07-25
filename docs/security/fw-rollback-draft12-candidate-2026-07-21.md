# Rollback & Lock Architecture — Draft 1.2 candidate (2026-07-21)

**Status:** DELTA CANDIDATE over Draft 1.1 for owner/colleague comparison.
No production implementation, option-byte, OTP, or hardware authority.
No approval by inheritance: this draft requires its own exact-digest dual
review + owner approval before anything it selects is implemented.

**Base:** Draft 1.1 review candidate, `docs/security/a-b-firmware-rollback-architecture.md`
(commit `93da75679a06b0bd289d49bdb511a7d3cd1acac7`, SHA-256
`743bc156417ff84b5ac201996b07c97db1e53526e2f9a2f59e44a6681ce3d7ad`).
Except where a section below explicitly amends a named Draft 1.1 row,
**Draft 1.1 is inherited unchanged** — geometry (§5), manifest/journal (§6),
boot state machine (§7), milestones 1–2 health boundary (§8–9), floor
establishment (§10), power-cut matrix (§11), OTP constraints (§12),
sacrificial-silicon plan (§13), milestones (§14), evidence matrix (§15),
invariants (§16), non-goals (§17).

**Provenance honesty.** Draft 1.1's bounded-deletion receipt
(`fw-rollback-draft11-deletion-gate-2026-07.md`) says: "Do not start a
Draft 1.2 prose cycle from this receipt." This draft is NOT a prose cycle
from that receipt. It is opened at explicit owner direction (2026-07-21)
because two new inputs did not exist when Draft 1.1 froze:

1. **New named owner requirement** — the firmware-fingerprint generator must
   be immutable (§1 below).
2. **A concrete unsettled decision** — the colleague-proposed lock flow
   (ship RDP-0, first-boot heal-then-lock) conflicts with Draft 1.1's
   factory-burns-everything assumption (§2). That is a genuine "concrete
   unsafe trace / unimplementable requirement" class reopen trigger: the two
   flows disagree about when immutability begins.

---

## 1. New settled owner requirement: immutable fingerprint generator

> **Invariant (owner, 2026-07-21):** the 8-word firmware-fingerprint
> *generator* is frozen once and can never be changed by any update.
> Updates change only its *output* (a new image → new words → verified
> against the published release).

**What this means mechanically.** The generator is the composition: image
measurement/hash → digest→8-BIP-39-word mapping → NV3007 render. All of it
is already resident in the 40,960-B FSBL region (base-27 word table landed
at 6,144 B inside it; `fsbl/src/render.rs`, `fsbl/src/main.rs:130` render
before branch; the slot-side copy is advisory parity only). Draft 1.1's
WRP set (`WRP1A/WRP2A: PSTRT=0, PEND=4, UNLOCK=0`) already covers exactly
that region. So the invariant reduces to a question Draft 1.1 left to the
factory receipt: **when do the option bytes become unchangeable?** Only
RDP Level 2 freezes option bytes permanently on STM32U585; at RDP ≤ 1
they remain rewritable (by a probe at RDP-0, or by on-device code with an
option-byte path). The invariant is therefore physically true iff the
device reaches `WRP(FSBL) + SECWM + TZEN + BOOT_LOCK + RDP2` and false
before. §2 is the whole decision.

**Corollaries.**

- C1. The secure world / slots must never grow an option-byte write path.
  `ob-configurator` stays a bench-only tool; add a compile fence and an
  audit row. (New; no Draft 1.1 conflict.)
- C2. Post-freeze, the FSBL-rendered 8 words are the only factory-frozen
  ground truth the user ever sees. The companion and docs must never claim
  parity they cannot prove — and at RDP-0 they can prove nothing (§2.2).
- C3. The rollback floor still cannot live in option bytes (they freeze).
  Draft 1.1's OTP-first-backend analysis is untouched by this draft.
- C4. WRP/RDP2 gives *persistence* immutability, not execution integrity.
  Glitch-to-skip-verify at boot remains the FI bench campaign's surface
  (#376, BENCH-4/#398), unaffected by this draft.

## 2. THE decision: when does the device freeze?

Draft 1.1 assumed (§5 factory receipt, lines 1651–1662): factory burns
WRP+SECWM+HDP+BOOT_LOCK+SWAP_BANK, "WRP is burned before RDP2", and no
self-lock mechanism exists. The colleague proposal (2026-07-21) is: ship
RDP-0 (user can externally verify), and the device checks its own option
bytes at first boot, self-heals wrong ones, then takes itself to RDP-2.

### 2.1 Options

**Option A — factory full freeze.** Last irreversible factory step sets
WRP+SECWM+TZEN+BOOT_LOCK, then RDP-2, with read-back after each
OBL_LAUNCH. Device verifies read-back fail-closed every boot (tz-1);
mismatch = halt/RMA. Immutability begins on the loading dock.

**Option B — ship RDP-0 + first-boot heal-then-lock (colleague).** Factory
flashes everything, prodtests, provisions, sets WRP+SECWM+TZEN+BOOT_LOCK
(binds software, not probes), keeps RDP-0 so a user *with a probe* can
dump flash against published builds. First boot: FSBL checks the OB set,
heals drift, requires physical confirmation, then sets RDP-2 **last**;
only after that do keys/seed/provisioning happen.

### 2.2 What Option B must admit honestly (the circularity)

At RDP-0 the code doing check/heal/render is the same flash an attacker
can rewrite. A malicious FSBL will "verify" itself, "heal" nothing, print
even the *published* 8 words (they are public; the FSBL renders them), and
lock RDP-2 on the attacker's terms. Therefore:

- **RDP-0 self-verification is worth zero against interdiction.** The only
  honest RDP-0 verification is *external* (probe + published hash). The
  on-device check catches **factory escapes** (mis-flashed bytes — a yield
  feature: heal instead of scrap), **not attacks**. Companion/docs copy
  must say exactly this and never sell the ceremony as genuineness proof.
- The heal path is an **option-byte write primitive in the field** — the
  thing C1 forbids in steady state. It must be **one-shot and provably
  unreachable after the lock** (separate one-time provisioning image
  preferred; if resident: RDP-state hard gate + compile fence + bench
  receipt), **idempotent and crash-consistent** across power cuts
  (factory-provisioning power-cut class, issue #445), RDP-2 strictly last.
- **Nothing trust-bearing runs before the lock**: no key derivation, no
  seed ceremony, no SE provisioning. Otherwise devices linger at RDP-0 as
  *usable wallets* — the worst end-state (debug open, WRP clearable; and
  note: pre-RDP-2, even signed-malicious firmware could clear WRP and
  rewrite the FSBL, so the window also bounds vendor-key-compromise blast
  radius — see `docs/security/vendor-signing-key-compromise.md` (#486)).
- After the lock, the companion's only genuine-device signal is
  **attestation** (#249) — Option B makes it more load-bearing, not less.

### 2.3 Comparison for the owner/colleague discussion

| axis | A — factory freeze | B — ship RDP-0, heal-then-lock |
|---|---|---|
| Immutability begins | at the factory | at first-boot ceremony |
| Supply-chain window | none (attestation covers clones) | factory→ceremony; only *external* probe verification helps |
| Factory escapes | scrap | self-heal (yield win) |
| Field OB-write primitive | none | exists pre-lock; must be one-shot (OPEN-LOCK-1) |
| User verifiability | attestation only | external probe window + attestation |
| Device that never locks | n/a | must never become a usable wallet (mandatory-before-keys) |
| End-state | identical: WRP+SECWM+TZEN+BOOT_LOCK+RDP-2 | identical |

### 2.4 Coordinator recommendation

**Adopt B with §2.2's conditions, A's byte set.** The end-state is
identical; B buys user verifiability and factory yield at the price of a
bounded, well-understood window — *provided* mandatory-before-keys and
one-shot-heal are treated as invariants, and the honesty copy is written
before any companion ships the ceremony. If either condition is judged
unimplementable, fall back to A. **This remains the owner's decision,
tomorrow, with the colleague — this draft decides neither.**

> **2026-07-22 — this question was answered upstream.** See the
> Reconciliation section at the end of this document: invariant #10 +
> `docs/provisioning/first-boot-requirements.md` adopt a hardened Option B
> that drops the heal entirely (verify-or-fail, never fix), which is
> strictly stronger than both chat proposals.

## 3. Exact amendments to Draft 1.1 (line-anchored)

1. **§5 factory receipt (lines 1651–1662)** — under B: split the burn.
   Factory sets the full Draft 1.1 byte set *except RDP*: WRP1A/2A
   (PSTRT=0, PEND=4, UNLOCK=0) + symmetric SECWM1/2 + HDP1/2 + TZEN +
   BOOT_LOCK + SECBOOTADD0 + SWAP_BANK=0, read-back after OBL_LAUNCH. The
   first-boot ceremony heals drift against compiled-in expected values,
   physically confirms, then sets RDP-2 and re-verifies. Under A:
   unchanged.
2. **tz-1 (issue #366 row)** — promoted from candidate to required:
   FSBL reads back OPTR/WRP/SECWM/TZEN/BOOT_LOCK/RDP **before every slot
   branch**, FI-hardened (double-check + sentinel). Pre-lock mismatch →
   heal path (once); post-lock mismatch → halt, no entropy release, RMA.
3. **boot-1 note (issue #366 row)** — recorded, unchanged: the current
   runtime bump at `cmd_fw_commit.rs:268` is **nonconforming** under Draft
   1.1's FSBL-establishment rule ("runtime firmware MUST NOT advance the
   OTP floor", line 192); implementation planning must not lose this.
4. **Fingerprint render order** — settled as today: FSBL verifies →
   renders → branches. New: the render step is part of the frozen
   invariant surface (§1), so any change to `firmware_fingerprint_lines`,
   the base-27 table, or the render path is a **freeze-review event**
   after the first frozen ship, not a routine patch.
5. **Invariant register (§16)** — add: "The fingerprint generator and the
   FSBL verification path are factory/ceremony-frozen; updates change only
   their outputs." And the C1 no-field-OB-write-path invariant.

## 4. OPEN register deltas

All Draft 1.1 `OPEN-*` items carry unchanged (PIN-HW-1, JRN-HW-1,
JRN-DUR-1, ECC-1, FLASH-HW-1, RAM-1, OTP-1..3, REL-1, C10-1). New:

- **OPEN-LOCK-1 — one-shot heal path.** Prove the heal/lock code is
  unreachable after RDP-2 (separate image or hard gate + fence), idempotent
  and crash-consistent across power cuts at every step (incl. mid-OBL),
  with RDP-2 strictly last. Closes only with bench evidence; same evidence
  class as #445/#454.
- **OPEN-LOCK-2 — ceremony UX + honesty copy.** Companion + docs text:
  ceremony = factory-escape corrector + lock trigger, *not* genuineness
  proof; RDP-0 genuineness requires external probe verification (publish
  the how-to); post-lock genuineness = attestation (#249). Includes the
  physical-confirmation step and "this is one-way" wording.

**Ordering constraint:** BENCH-4 (issue #398, RDP-2 offensive downgrade
campaign) and A3/A4 (issues #388/#387 — largely moot under RDP-2, record
that) must conclude **before** the Option-B/A freeze review, because they
are the evidence that RDP-2 actually kills the downgrade paths.

## 5. Owner decisions carried (NOT decided here)

- **A vs B** — the §2 decision, for tomorrow's owner/colleague session.
- **RecoverySameEpoch** and **FloorBoundAccepted** — the two availability
  choices the deletion-gate receipt explicitly left to the owner; still
  open, unchanged by this draft.
- **OPEN-REL-1, OPEN-C10-1** — unchanged, still open.

## 6. Review gate state (honest)

Draft 1.1's approval rule (dual exact-digest review: Claude Opus 5
(`opus`) `xhigh` + GPT-5.6 SOL `ultra`, then owner approval) applies to this
draft. Current state: **coordinator draft only (Kimi); no external
reviews obtained** — Codex MCP unavailable in-session (two timeouts),
Claude not invocable from this environment. The §18-style review questions
for both reviewers, when run:

1. Does §2.2's circularity analysis miss any on-device RDP-0 signal that
   *would* bind an interdiction attacker?
2. Is the B factory byte-set (everything except RDP at factory) sufficient
   against software (non-probe) attackers pre-lock?
3. Does the heal-then-lock ceremony introduce any transition not covered
   by Draft 1.1 §11's power-cut matrix?
4. Does anything in §3 silently contradict a Draft 1.1 frozen row?

## 7. What this draft does NOT touch

Draft 1.1's flash geometry, OTP-first-backend candidacy and its NO-GO
gates, Route-1 journal, floor codec options A/B, ECC/FLASH/RAM open
items, §13 sacrificial-silicon plan, milestones, the rejected register
(single-QW floor, per-bit counters, grace/delayed commits, PIN-gated
counter backends, …), and the approval record. Draft 1.1 remains the
base; this is a delta. Nothing here authorizes code, option-byte, OTP, or
hardware changes.

---

## Reconciliation — 2026-07-22 (Markus's first-boot push)

After this draft was written, Markus Haas pushed 9 commits to
`origin/master` that answer §2. Reviewed here against the draft.

**What landed.**

- **CLAUDE.md invariant #10 — "verify-once-physically trust chain"
  (commit `8a93aaa5`, citing owner decision 2026-07-21):** RDP-0 ship →
  user verifies over SWD before first power → WRP'd FSBL fingerprint →
  RDP-2 self-lock freezes option bytes → the measuring code is physically
  immutable → boot-time 8-word fingerprint proves installed firmware
  forever. Binds: no runtime writes to the FSBL range, WRP-set strictly
  before RDP-2, FSBL owns the display in its fingerprint window,
  monolithic images bench-only. *This is §1's invariant, formalized.*
- **`docs/provisioning/first-boot-requirements.md`** (commits `51388ce0`,
  `afaa4c36`, amended by `38f6bedb`): normative RFC-2119 device-side spec
  for the `rdp2-self-lock` flow, plus the exact factory input state F1–F8.
- **Implementation `38f6bedb`**: closes #443 (ship-blocker); wires
  R2.1–R2.4 in `secure/src/first_boot/` with FI-sentinel gating
  (`rdp_burn_authorized` requires both the confirm verdict AND the
  sentinel word), per-`ObField` distinct error codes, rotation hardening,
  tests. `#443` is CLOSED.

**The design they adopted — "hardened B, minus the heal".** Factory
stages the full ship profile *except RDP* (F2: TZEN, SECWM1/2,
SECBOOTADD0, WRP1A over FSBL, BOR, OEM locks — WRP reversible at RDP-0,
so staging costs nothing), plus factory OTP-master (F3) and SE-internal
irreversibles incl. OPTIGA LcsO ratchet (F5) — all on the line, all
before any secret exists. First boot (Phase A): verify the staged
profile (R2.1, **hard-fail on wrong WRP — never "fix" it**: "a unit that
reaches the field unstaged is not a genuine ship unit"), blank-check
pages 123–127 (R2.2), confirm OTP-master present (R2.3), trusted-UI
confirm gate (R2.4, implemented: both-buttons chord, owner decision
2026-07-17), then — and only then — RDP=0xCC + OBL_LAUNCH (R2.5). Every
Phase-A fault halts **unlocked** (R2.6: returnable, reflashable). Phase B
(post-lock): journaled, commit-LAST, resumable rotation of BHK / SE050
SCP03 / SE050 admin / OPTIGA PBS off the transport keysets (R3.x), then
ALL_DONE; seed wizard only after that (R1.1).

**Against this draft's §2 conditions:**

| §2.2/§2.4 condition | Their answer |
|---|---|
| mandatory-before-keys | R1.1 — before seed wizard, PIN, USB, any wallet secret |
| physical confirm + one-way wording | R2.4 — explicit "after that verification over SWD not possible anymore", both-buttons chord |
| crash-consistency / idempotence | R1.3, §4 — journal, commit-LAST, resume scan, fail-closed on full journal |
| honesty about RDP-0 | invariant #10 — the *user's SWD verification* is the load-bearing check (F7 factory QA explicitly not load-bearing); no on-device RDP-0 self-verification is claimed |
| field OB-write primitive | **eliminated** — the device never writes WRP at all (R2.1 verify-don't-set); the only on-device OB write is RDP itself, behind the confirm gate |
| heal on wrong bytes | **rejected, deliberately** — hard fail unlocked instead (R2.1/R2.6); factory-escape units become RMA, not field repairs |

Dropping the heal is strictly stronger than what either chat proposal
contained: it removes OPEN-LOCK-1's worst case (a resident field
OB-write path) and converts factory escapes into a visible RMA class
rather than silent field mutations. This draft's §2.4 recommendation is
satisfied on every condition.

**Remaining deltas for tomorrow's discussion** (small, real):

1. **Every-boot FSBL-side OB verify (this draft's §3.2, tz-1) vs their
   R1.3** — their Phase A runs in the *secure world* pre-lock and is a
   no-op after completion; the FSBL itself does not re-verify OPTR/WRP/
   SECWM before branch. Post-RDP-2 the bytes are frozen, so the marginal
   value is an FI tripwire only. Decide: keep tz-1 in the FSBL as cheap
   defense-in-depth, or accept RDP-2 as sufficient and close #366's tz-1
   as superseded-by-RDP-2.
2. **Their spec does not touch Draft 1.1's floor** — OTP/journal/ECC/RAM
   OPEN-* items all still stand, as does §3.3's note that the current
   `cmd_fw_commit.rs:268` runtime bump is nonconforming under Draft 1.1.
   The rollback-floor settlement is still owed separately.
3. **Their own OPEN gates** (recorded in `first-boot-provisioning.md`):
   handoff/receipt, authenticate-before-rotate, recovery-adequacy,
   E140-ordering, silicon receipts, `OEM_LOCK_MASK_PINNED` fail-closed
   pin, `HW-CONFIRM-PUTKEY-KCV-RESP`, DEK-liveness bench. This draft's
   BENCH-4-before-freeze ordering constraint is compatible and stands.
4. **OPEN-LOCK-2 shrinks** to companion-side copy: the on-device prompt
   exists; the companion text and the "post-lock genuineness =
   attestation (#249)" story are still owed. F6 (attestation manifest
   burn) is "when it lands".
5. **Confirm the attribution** — invariant #10 cites "owner decision
   2026-07-21". CLAUDE.md is the project contract: confirm that entry is
   the owner ratifying Markus's formalization (it matches this
   conversation, so this is a check-the-box item, not a re-litigation).
