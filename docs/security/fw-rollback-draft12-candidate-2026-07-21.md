# Rollback & Lock Architecture — Draft 1.2 candidate (2026-07-21)

**Status:** DELTA CANDIDATE over Draft 1.1 for owner/colleague comparison.
No production implementation, option-byte, OTP, or hardware authority.
No approval by inheritance: this draft requires its own exact-digest dual
review + owner approval before anything it selects is implemented.

**Base:** Draft 1.1 review candidate, `docs/security/a-b-firmware-rollback-architecture.md`,
file SHA-256 `57b7e359ca1f8f0367e83ba355f61de35a8b6f25c6050435870227e4a5488293`
(post-errata-3, 2026-07-26: the owner-decision errata striking
`RecoverySameEpoch`/`FloorBoundAccepted` and all degraded boot authority,
the §11 burn-window rows + R5-2 phase-profile precision, and the
`FirstBootLockWriter` owner entry — see its ERRATA section. Lineage back
to the original pin commit `93da7567` / `743bc156…3d7ad` = +
reviewer-lineup `589fb771` + the errata passes, each hop verified by
diff). Except where a section below explicitly amends
a named Draft 1.1 row, **Draft 1.1 is inherited unchanged** — geometry (§5),
manifest/journal (§6),
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
  audit row. (New; no Draft 1.1 conflict.) **Clarified 2026-07-26** (review
  finding C2): the heal branch analyzed in §2 is DEAD — rejected by the
  adopted design (see Reconciliation). C1 is absolute: the only on-device
  option-byte write ever permitted is the confirm-gated RDP path of the
  lock ceremony itself.
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
- **Nothing trust-bearing runs before the lock**: no wallet secrets (no
  seed, no wallet-key derivation) and no final SE pairing credentials.
  Otherwise devices linger at RDP-0 as
  *usable wallets* — the worst end-state (debug open, WRP clearable; and
  note: pre-RDP-2, even signed-malicious firmware could clear WRP and
  rewrite the FSBL, so the window also bounds vendor-key-compromise blast
  radius — see `docs/security/vendor-signing-key-compromise.md` (#486)).
  Factory-staged transport structure (F3–F5: OTP master, SE object
  structure, transport keysets) is public-by-assumption, contains no
  wallet secret, and is explicitly OUT of scope of this invariant (review
  finding C3).
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
   first-boot ceremony **verifies** the staged profile and **hard-fails
   on any mismatch — verify-never-heal** (a unit that reaches the field
   unstaged is not a genuine ship unit; factory escapes become RMA, not
   field repairs), physically confirms, then sets RDP-2 and re-verifies.
   Under A: unchanged. *(Heal semantics removed 2026-07-26 per the
   Reconciliation and review finding R4-1; the only on-device option-byte
   write anywhere is the confirm-gated RDP path — §1 C1, §3 row 8.)*
2. **tz-1 (issue #366 row)** — promoted from candidate to required:
   FSBL reads back OPTR/WRP/SECWM/TZEN/BOOT_LOCK/RDP **before every slot
   branch**, FI-hardened (double-check + sentinel, halt only on
   persistent mismatch). The comparison is against the **phase-appropriate**
   expected profile: pre-ceremony = the staged ship profile with
   RDP≠0xCC; post-ceremony = the staged profile with RDP=0xCC. Any other
   persistent value in either phase (partial, torn, or alien) → hard fail
   unlocked pre-ceremony, halt + no entropy release post-ceremony — never
   heal, never re-attempt. *(Phase-awareness added 2026-07-26 per finding
   R5-2: a mid-burn cut that boots showing exactly the pre-ceremony
   staged profile is NOT a mismatch — that is "burn did not take", and
   the ceremony simply re-enters per Draft 1.1 §11's burn-window row.)*
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
6. **§7.4 factory-genesis exception (lines 2813–2827)** — added 2026-07-26
   (review findings A38/B4, both confirmed): §7.4's receipt binds
   "dual-bank WRP/SECWM/HDP/BOOT_LOCK/SWAP_BANK state" and requires that
   "final lifecycle locks independently prevent the underlying writes
   after the factory lifecycle closes". Under the adopted lock flow the
   factory lifecycle does NOT close the locks: the receipt binds the
   *staged* profile (F2, everything except RDP), and the final lock closes
   at the first-boot ceremony. Amended accordingly in the 2026-07-26
   errata; without this amendment the composite text holds the same RDP-0
   unit simultaneously factory-closed and not finally locked.
7. **§11 power-cut matrix** — added 2026-07-26 (review finding B3,
   confirmed); **executed in Draft 1.1's text 2026-07-26** (round-2
   remediation): three burn-window rows now exist in §11 — cut during the
   RDP program (torn-latch wedge = RMA; bootable = idempotent re-entry);
   cut after a clean program before `OBL_LAUNCH` (the next power-on
   completes the launch — POR ≡ option-byte reload; classify by
   read-back, never remembered intent; never reissue the RDP write once
   read-back shows `0xCC`); launch issued but no reset (park; classify at
   next power-on). R2.6's "halts unlocked" carries exactly one exception:
   a cut inside the burn window completes the lock by reset — the
   intended terminal state, not a fault violation. The first-boot
   ceremony spec mirrors these rows on its next edit (owner: Markus).
8. **§6.3 writer ownership — `FirstBootLockWriter`** — added 2026-07-26
   (round-2 finding A38-new): Draft 1.1's frozen exhaustive mutation map
   contained no first-boot RDP writer, making the required lock
   unimplementable without a boundary bypass. The new owner entry grants
   exactly one operation — the confirm-gated `RDP=0xCC` program +
   `OBL_LAUNCH`, reachable only after the R2.1–R2.4 verify+confirm chain,
   pre-Phase-B, production-compile-fenced, classification by read-back
   only, failure = park — cross-referenced from FROZEN-FLASH-MUT-1.

## 4. OPEN register deltas

All Draft 1.1 `OPEN-*` items carry unchanged (PIN-HW-1, JRN-HW-1,
JRN-DUR-1, ECC-1, FLASH-HW-1, RAM-1, OTP-1..3, REL-1, C10-1). New:

- **OPEN-LOCK-1 — lock-path one-shotness + crash-consistency.** *(Re-scoped
  2026-07-26: the heal branch is dead — verify-never-heal — so there is no
  heal path to contain.)* What remains: prove the confirm-gated RDP burn
  (`FirstBootLockWriter`, Draft 1.1 §6.3) is unreachable after the lock,
  and that the Phase-B journal/rotation steps are idempotent and
  crash-consistent across power cuts at every step (incl. mid-OBL),
  classification always by read-back. Closes only with bench evidence;
  same evidence class as #445/#454.
- **OPEN-LOCK-2 — ceremony UX + honesty copy.** Companion + docs text:
  ceremony = staged-profile verifier + lock trigger, *not* genuineness
  proof and *not* a field repair — a wrong staged profile hard-fails to
  RMA (verify-never-heal); RDP-0 genuineness requires external probe
  verification (publish the how-to — connect-under-reset, never energize
  first; canonical comparison ranges/normalization per review findings
  C4/C5); post-lock genuineness = attestation (#249). Includes the
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
3. Does the lock ceremony (verify-never-heal, confirm-gated RDP burn)
   introduce any transition not covered by Draft 1.1 §11's power-cut
   matrix — including mid-burn interruption classification?
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
  (commit `825b26ec`, citing owner decision 2026-07-21):** RDP-0 ship →
  user verifies over SWD before first power → WRP'd FSBL fingerprint →
  RDP-2 self-lock freezes option bytes → the measuring code is physically
  immutable → boot-time 8-word fingerprint proves installed firmware
  forever. Binds: no runtime writes to the FSBL range, WRP-set strictly
  before RDP-2, FSBL owns the display in its fingerprint window,
  monolithic images bench-only. *This is §1's invariant, formalized.*
- **`docs/provisioning/first-boot-requirements.md`** (commits `d872395b`,
  `650af535`, amended by `44941ccf`): normative RFC-2119 device-side spec
  for the `rdp2-self-lock` flow, plus the exact factory input state F1–F8.
- **Implementation `44941ccf`**: closes #443 (ship-blocker); wires
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

---

## UPDATE 2026-07-23 — the five deltas, resolved (colleague-agent pass, verified)

Markus's agent resolved all five deltas (output reviewed and
fact-checked here: the replacement SHAs below resolve and match subjects;
`cmd_fw_commit.rs:307` is the post-rewrite `otp::bump_to` anchor; the
2026-07-22 history rewrite invalidated the four pre-rewrite SHAs, now
repaired in this section — `8a93aaa5→825b26ec`, `51388ce0→d872395b`,
`afaa4c36→650af535`, `38f6bedb→44941ccf`).

1. **tz-1 — KEEP, decided now** (supersedes this draft's "defer to
   freeze review"). FSBL-resident fail-only tripwire: read
   OPTR/WRP/SECWM, compare against compiled-in constants, halt-no-entropy
   on mismatch, **never write** (~200 B of the 38,912 B budget). The
   asymmetry settles it: including costs 200 B; excluding is
   irreversible once the FSBL freezes — and the FSBL is the only code
   that survives updates, so the check must live there. #366's tz-1 row
   is re-scoped to "post-lock FI tripwire, FSBL-resident,
   verify-never-heal". *Coordinator refinement:* halt only on
   **persistent** mismatch (double-read with a gap, house FI idiom) — a
   transient read fault must not brick a good device.
2. **Floor — separate track, as this draft recommended.** Owner declines
   `RecoverySameEpoch` and `FloorBoundAccepted` (availability, not
   safety; RMA is cheaper than two state-machine subtrees pre-scale);
   freeze the 1.1+1.2 digest and run the dual exact-digest review (the
   blocker since 2026-07-14 — note the review lineup changed on master:
   `589fb771` replaces Claude Opus 4.8 with Claude Opus 5); §13
   sacrificial-silicon only after the review lands. The nonconforming
   runtime bump stays in place with its note (now `cmd_fw_commit.rs:307`).
3. **OPEN gates — one tracker.** Every gate in
   `first-boot-provisioning.md` gets a GitHub issue (doc-resident lists
   are the retired pattern); the two bench items fold into #398–#402;
   BENCH-4-before-freeze stands.
4. **Companion copy — just write it** (ceremony one-way wording, RDP-0
   SWD-verification how-to, "post-lock genuineness = attestation #249
   when it lands"). Half a day; no design question left.
5. **Attribution — RATIFIED** (owner-side confirmation via the recorded
   2026-07-21 conversation). Durable fix adopted as habit: owner-decision
   citations point at a written record (spec or decision issue), never a
   chat log.

---

## REVIEW RECEIPT + ERRATA 2026-07-26 — first gate run and its remediation

**Gate run 1 (2026-07-26).** GPT-5.6 SOL (`ultra`) reviewed Draft 1.1
(`4237ae1d…e180`) + this draft (`f256e909…85d3`): **NO-GO**. Coordinator
reproduction confirmed its two load-bearing claims (§7.4 inheritance
contradiction; missing RDP-burn cut transitions) and showed its
"no unique composite artifact" finding was exactly the `589fb771`
reviewer-lineup drift (benign). Its remaining GAPs restate Draft 1.1's
own OPEN register — no new architectural attack.

**Owner decision (2026-07-26, ratified):** `RecoverySameEpoch` and
`FloorBoundAccepted` DECLINED (availability, not safety; service/RMA
accepted). Executed as a bounded errata inside Draft 1.1 itself (its
`ERRATA 2026-07-26` section): both features and all degraded
boot/admission authority struck from the normative text; `Aborted` =
robust exact-`F` or service; terminal-quorum loss = service;
`SurvivingTerminalSet` survives only as repair-target classification;
floor-bound binding only as evidentiary record; `PeerRepair` +
`DegradedArtifactRepair` kept. Post-errata Draft 1.1 file SHA-256:
`077e4357b6e709e9e6ac2e621066ef608d627cb9d44afe1e9182a93ab5c617d2`.
**Line anchors cited in this draft's §3 refer to pre-errata Draft 1.1
numbering; the digest above is the re-freeze base.**

**This draft's own remediation (same date, answering the review):**
base re-pinned to `4237ae1d…e180` with lineage (finding C1); C1 clarified
absolute — heal branch dead, only the confirm-gated RDP write exists
(C2); pre-lock invariant rescoped to wallet secrets + final pairing
credentials, factory transport structure explicitly out (C3); §3
amendments extended to §7.4 factory-genesis rows (A38/B4) and the §11
burn-window cut transitions (B3); the SWD-verify how-to requirements
(connect-under-reset, canonical comparison ranges) fold into OPEN-LOCK-2
(C4/C5). OPEN-LOCK-2's companion copy and the first-boot spec's own
burn-window rows are owed by their owners.

**Next gate run:** both legs (GPT-5.6 SOL `ultra` + Claude Opus 5
`xhigh`, per the on-master review policy `589fb771`) over the post-errata
digests, then implementation planning (Draft 1.1 §14 Foundation A).

**Gate run 2 (2026-07-26, GPT-5.6 SOL `ultra`).** All ten run-1 findings
confirmed REMEDIATED; 26 of 40 §18 questions RESOLVED (the 13 GAPs are
Draft 1.1's own OPEN register — expected). NO-GO on exactly two
blockers: B3 carried (the burn-window transitions were admitted-owed
here but absent as normative text) and **A38-new** (the RDP burn had no
typed owner in Draft 1.1's frozen mutation map — an implementation must
bypass the boundary or cannot lock). Both remediated same-day: the three
§11 burn-window rows + R2.6 carve-out, and the `FirstBootLockWriter`
owner entry (see §3 rows 7–8). The first-boot spec's own mirror of the
burn-window rows remains owed by its owner.

**Gate run 3 (2026-07-26, GPT-5.6 SOL `ultra`).** Both run-2 blockers
confirmed REMEDIATED; §18 at 28 RESOLVED / 12 GAP (all OPEN register).
NO-GO on one administrative finding, **D1**: this file's Base and receipt
still named the superseded digests (`4237ae1d…`, `077e4357…`) rather
than the reviewed pair. Remediated here: the Base block now pins Draft
1.1 at `ee982785fa65f9534ed95638aaeb2b672f231a26250d8a65edcdbde8554c9c16`,
and the composite freeze identity is recorded in
`docs/security/fw-rollback-freeze-receipt-2026-07-26.md` (a file cannot
embed its own digest; the receipt names the final pair).

**Next gate run 4:** both legs (GPT-5.6 SOL `ultra` + Claude Opus 5
`xhigh`, per the on-master review policy `589fb771`) over the final
freeze pair in the receipt above, then implementation planning (Draft
1.1 §14 Foundation A).

**Gate run 4 (2026-07-26, GPT-5.6 SOL `ultra`).** D1 REMEDIATED; §18 at
28 RESOLVED / 12 GAP (OPEN register). Sole finding **R4-1**: this file's
own §3 rows 1–2 and OPEN-LOCK-1 still carried heal semantics
("heals drift", "one-shot heal path") contradicting the adopted
verify-never-heal — a leftover from the A-vs-B analysis era. Remediated
here: rows 1–2 now hard-fail on mismatch (never heal), and OPEN-LOCK-1 is
re-scoped to burn-path one-shotness + Phase-B crash-consistency.

**Gate run 5 (2026-07-26, GPT-5.6 SOL `ultra`).** R4-1 named edits
REMEDIATED; two new findings. **R5-1**: OPEN-LOCK-2's "factory-escape
corrector" wording and §6 Q3's "heal-then-lock" phrasing still implied
field repair — reworded here (verifier + lock trigger; wrong profile =
RMA). **R5-2**: Draft 1.1 §11's burn-window row ("re-enter on RDP≠0xCC")
contradicted tz-1's hard-fail — resolved by phase-appropriate profiles on
both sides: re-attempt only on read-back of *exactly* the pre-ceremony
staged profile; any other persistent value = halt/RMA, no re-attempt, no
heal (Draft 1.1 §11 row + carve-out now say so verbatim; tz-1 row 2
above carries the same rule). Note: this run's report honestly could not
attest its serving-model identity beyond "GPT-5 family"; runs 1–4
attested GPT-5.6 SOL.
