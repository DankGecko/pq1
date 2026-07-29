# PQSigner OS A/B Rollback Architecture Specification
Status: **DRAFT 1.1 REVIEW CANDIDATE — DRAFT-1.0 OPUS RED-LINES INCORPORATED; PHYSICAL JOURNAL DURABILITY, OTP CODEC, ECC, AND SILICON GATES OPEN; NO PRODUCTION IMPLEMENTATION OR HARDWARE AUTHORITY — ERRATA 2026-07-26 APPLIED (RecoverySameEpoch + FloorBoundAccepted struck)**<br>
Draft: 1.1 review candidate<br>
Date: 2026-07-14<br>
Target silicon: STM32U585AI, including the B-U585I-IOT02A development kit<br>
Historical research reference: annotated tag `rollback-architecture-v0.9`;
the earlier `/tmp/pqsigner-fw-rollback` worktree was ephemeral and is not
claimed present<br>
Implementation baseline: committed HEAD `8f335f8d1901976d2bb8fdab63b73512b5ce865f`
<br>Rejected Draft-1.0 review candidate: commit
`cc526ac8`, SHA-256
`59bb14f875ab0082382e2ef1130902c87c68b9b4bbb4b5c85e59d76368291efb`

This is a design artifact for digest-bound red-line review. Draft 0.9 remains
recoverable byte-for-byte from annotated tag `rollback-architecture-v0.9` and
is not overwritten as historical evidence. Draft 1.0 is preserved at the
commit and digest above: GPT-5.6 SOL at `ultra` approved it, but Claude Opus
4.8 1M at `ultracode` returned a normative NO-GO. Draft 1.1 receives no approval by
inheritance: both independent reviewers must approve this exact candidate
digest, with their reports bound in a separate immutable approval receipt,
before implementation begins. The document does not authorize firmware
flashing, OTP programming, option-byte changes, factory ceremonies, release
signatures, or production shipment.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are used as requirements language. They add conventional emphasis but are not
the only normative text: unless a paragraph is explicitly marked historical,
descriptive, example-only, or non-normative, declarative requirements in every
`FROZEN-*`/`OPEN-*` decision, transition table, acceptance gate, test/formal
obligation, and security invariant are binding even when written in lowercase
for readability.

---

## ERRATA 2026-07-26 (owner decision)

Owner decision, 2026-07-26, ratified: the two availability features
`RecoverySameEpoch` and `FloorBoundAccepted` are DECLINED. The 2026-07-14
bounded-deletion receipt
(`docs/security/fw-rollback-draft11-deletion-gate-2026-07.md`) showed both are
availability benefits, not safety requirements; the owner chose service/RMA
instead. A GPT-5.6 SOL review (2026-07-26, NO-GO) found that declining them in
a side note leaves stale mandatory constructors in the text; this errata
removes them from the normative text itself and answers that review's findings
A14/A16/A18/A28/A35.

Struck features and replacement semantics:

- `RecoverySameEpoch` is struck. It was "the sole permitted epoch decrease"
  and the only new-release path from the `Aborted` state. `Aborted` now has NO
  new-release path: the device boots only the previously accepted robust
  exact-`F` artifact via the existing exact-`F` selector
  (`boot_accepted_from_aborted`), or halts to service/RMA. Epoch never
  decreases, no exceptions. `RecoverySameEpoch` is removed from every
  enumeration of permitted paths/classes.
- `FloorBoundAccepted` is struck. It was the degraded-acceptance path when
  terminal CONFIRMED replicas are lost. Loss of terminal-set quorum now means
  service/RMA, with no degraded acceptance. The `FullTerminalSet` (two clean
  replicas) rule stays; the `SurvivingTerminalSet=1` -> `DegradedAcceptedBoot`
  and floor-bound recovery paths are removed.
- `PeerRepair` is NOT declined; every `PeerRepair` reference remains intact.

Blanket note: every remaining mention of `RecoverySameEpoch`/
`FloorBoundAccepted` outside §18/§19 is struck by this errata; §18 (review
questions) and §19 (approval record) are historical and are not edited.
Likewise, floor-bound evidence/authority and `DegradedAcceptedBoot`
boot/admission authority are struck wherever they appear outside §18/§19;
`SurvivingTerminalSet` survives only as a repair-target classification, and
floor-bound accepted-manifest binding only as an evidentiary record.

Amendment (round-2 review): burn-window §11 rows + `FirstBootLockWriter`
owner added; answers findings B3 and A38-new.

Amendment (Opus-5-leg review, 2026-07-26): §5 reassigns bank-1 page 127 from
the retired Tropic01-key reservation to the first-boot provisioning journal +
TRNG salt record; §6.3 adds the typed `FirstBootJournalWriter` (page-127
commit-LAST appends + journal-gated page-126 erase-and-reprogram);
FROZEN-FLASH-MUT-1's enumeration gains both operations; §12.6 item 4's
required-component list names the every-boot option-byte read-back tripwire
(issue #366 row tz-1). Answers the Opus-5 leg's BLOCKER-1 (the mandatory
Phase-B journal had no page owner in §5 and no writer owner in §6.3 while
`docs/provisioning/first-boot-requirements.md` R3.x and
`secure/src/first_boot/journal.rs` already own page 127) and its
§12.6/row-2 observation.

---

## 1. Purpose

This specification repairs the failed A/B rollback property identified as
finding #5: the old design advanced the irreversible rollback floor before a
candidate firmware had booted successfully, thereby making the known-good slot
ineligible before the advertised try-once recovery decision could run.

The desired end state has two separately tracked claims:

1. **Mechanism closure.** A candidate receives at most one probation handoff;
   a state-machine reset or failure after exact `ATTEMPTED` and before
   acceptance returns to the previous confirmed slot while that slot remains
   independently valid, while a pre-handoff exact arm may safely retry;
   mutable runtime firmware never advances the rollback floor; and only
   immutable FSBL code idempotently establishes the accepted security-epoch
   floor after exact acceptance.
2. **Defined probation-boundary closure.** The acceptance boundary exercises
   the exact surfaces named in Section 9: secure initialization, a local
   derivation/sign/verify self-test, the candidate NS image, USB transport, the
   dedicated NS-to-secure health gateway, and an external companion round-trip.

Mechanism closure does not imply probation-boundary closure. Neither claim
means that every post-confirmation crash is recoverable. In particular, the
first ordinary unlocked wallet lifecycle and ordinary signing dispatch occur
only after FSBL establishes the accepted epoch floor under this four-state
manifest design. Establishment is an abstract reviewed durable-stage plus
replicated OTP commitment for an epoch bump and an idempotent no-write check
for a same-epoch release. A pre-`COMPLETE` stage whose finite plan becomes
mathematically impossible may enter the typed `Aborted` floor class defined in
Section 3; this does not lower the floor or permit the failed candidate to
boot. It can reject a candidate that passed health when the irreversible
backend's finite establishment plan cannot complete. Project status and
documentation MUST report the mechanism, exact probation coverage, finite
epoch capacity, and this residual
separately.

An exact `Aborted` floor does not permanently freeze ordinary firmware repair.
It may restore an independently signed A/B peer through the complete
probation protocol. That path leaves the floor and dead-plan quarantine
unchanged and performs zero rollback-stage or OTP writes. `Aborted` admits no
new-release path: the device boots only the previously accepted robust
exact-`F` artifact or halts to service. `Aborted` is terminal
only for another autonomous epoch-floor advance; regaining that ability
requires service or a separately reviewed future architecture.

### 1.1 Version and floor semantics

The signed manifest carries two independent 32-bit values in
`1..=0xFFFF_FFFE`; zero and `0xFFFF_FFFF` are reserved invalid/fail-closed
sentinels:

- `R = release_version`: unique and strictly increasing within the Section-6.4
  immutable `(PQFW_V6, embedded vendor-key fingerprint)` product namespace for
  one logical vendor release-set. In
  normal, ledger-consistent states it orders epoch-admissible releases. The
  anomalous two-`CONFIRMED` recovery order is instead the explicit
  `(E, R, slot-A-first)` order in Section 7.2.
- `E = security_epoch`: a nondecreasing rollback-equivalence class; the epoch
  never decreases, with no exceptions. Every
  vendor-signed release in the current epoch remains epoch-floor-admissible
  until a later epoch is committed; signature, hashes, journal, and bounds must
  still pass independently.

The durable OTP value is:

- `F = rejected_through_epoch`: every manifest with `E <= F` is rejected; and
- `T = E - 1`: the only floor target derivable from an accepted manifest.

Because valid `E` is `1..=0xFFFF_FFFE`, every valid `T` and durable `F` is in
`0..=0xFFFF_FFFD`. A record decoding to `0xFFFF_FFFE` or `0xFFFF_FFFF` is never
a terminal floor shortcut; it is invalid/fail-closed.

Admission is exactly `E > F`. `F` is not a minimum-allowed epoch; the strict
comparison and the `E - 1` representation are an exclusive-floor convention.
For `E >= 1`, committing `F = E - 1` admits epoch `E` while rejecting every
older epoch. A higher `R` can never override `E <= F`.

A same-epoch release has `E_new == E_running`, so a steady device already has
`T == F` and performs no rollback-record or durable-stage mutation. Ordinary
same-epoch releases therefore consume no OTP epoch cells; they are not
literally unbounded because `R`, the physical vendor-key C10 budget,
publication policy, final-epoch policy, and device storage remain finite. An
epoch bump has
`E_new > E_running`, so `T > F` and requires one logical `commit_target(T)`,
regardless of the numeric jump. The approved physical codec defines how many
OTP quad-words, replicas, claims, and recovery-reserve cells implement that
one logical commitment. A single-QW committed floor is explicitly not
production-eligible. This specification therefore provides epoch-granular
irreversible rollback protection, not per-release irreversible rollback
protection.

The protected release ledger maintains
`epoch_high_water = max(E of every reserved release record)`, including
abandoned ceremonies. Ordinary and epoch-bumping releases
MUST use `E_new >= epoch_high_water`. No release class permits an
entry-by-entry epoch decrease; `epoch_high_water` never lowers.

"Same epoch" is always device-relative. A release that repeats the preceding
ledger entry's `E` can still require a commitment on a lagging device whose
local `F < E - 1`. Neither server metadata nor release classification may
promise a global no-write path; the device derives it only from signed `E` and
its independently validated local `F`.

Floor admissibility is not a user-facing version picker. After filtering every
artifact through `E > F`, the selector accepts only `RobustAccepted` authority
and applies the frozen tuple order. This permits an older robust
fallback to repair a higher-`R` degraded artifact instead of stranding the only
writer-capable peer. If no robust authority remains, FSBL halts to
service with no updater, probation, floor, fallback,
or repair capability. This design provides no
user demotion, reinstall-to-downgrade, boot chord, or lower-`R` selection while
a newer valid release remains preferred.

---

## 2. Resolved architectural decisions

The following decisions are settled for this design:

- The persistent boot state machine is health-boundary-agnostic. FSBL sees
  only exact composite manifest/TAMP states; it does not interpret how runtime
  health was established.
- The only manifest lifecycle states are `UNINSTALLED`, `PENDING`,
  `ATTEMPTED`, and `CONFIRMED`; Draft 1.1 freezes their composite software
  encoding while
  `OPEN-JRN-HW-1` gates the physical TAMP backend.
- A candidate remains `ATTEMPTED` throughout all health evaluation.
- Within the validated retained/sanitized backup-domain envelope selected by
  `OPEN-JRN-HW-1`, any reset, crash, watchdog, cancellation, timeout, invalid
  health response, or power event after exact durable `ATTEMPTED` and before
  `CONFIRMED` excludes the candidate and selects the old confirmed slot only
  when a fresh `Steady` or exact constrained `Aborted` authority and that slot's
  independent validity permit it. A reset before `ATTEMPTED` becomes durable
  may safely retry arming because the candidate has not run. Outside that
  envelope immutable cold boot first applies the selected ES0499 policy;
  missing or ambiguous token state never grants retry, and no deterministic
  at-most-once claim is made for an unsanitized marginal backup-power state.
- `CONFIRMED` is final acceptance of the release. It is not an early "booted
  once" marker. It authorizes retirement of older epochs only when `E`
  increases. Accepted authority requires two independently programmed terminal
  replicas; loss of terminal-set quorum removes that artifact's boot authority.
  After terminal-
  set validation, lifetime confirmation authority
  no longer depends on re-reading `QW_PENDING`; the validated terminal set is
  the authoritative recovery source defined below.
- For field updates, `CONFIRMED` MUST be written only after the full Milestone-2
  health boundary and an explicit trusted-display finalization gesture. The
  sole exception is the offline pre-lifecycle factory genesis in Section 7.4.
- Runtime firmware MUST NOT advance the OTP rollback floor.
- FSBL establishes only `T = E - 1`, and only after independently re-verifying
  a `CONFIRMED` slot. It performs no OTP program command when `T == F`.
- The candidate first backend is STM32U585AI OTP, and authoritative rollback
  records remain in OTP rather than erasable main flash. OTP is not production-
  eligible until `OPEN-OTP-1..3` closes, including the ECCC, redundancy, and
  complete-power-loss rules. External OPTIGA/SE050 counters and hybrid
  checkpointing remain a separate architecture; they are not silently pulled
  into finding #5's minimum repair.
- The current OPTIGA E120-LUC and SE050 UserID counters are PIN-gated, whereas
  FSBL verifies rollback before PIN entry and intentionally contains neither
  the PIN/SE policy nor the Shielded-Connection/SCP03 transport stacks. They
  are therefore not drop-in replacements for this pre-PIN immutable check, and
  importing those drivers into the 40 KiB FSBL would require its own security
  and footprint architecture. A future design may introduce a distinct
  pre-PIN-readable SE monotonic object, move/checkpoint the trust decision, or
  combine OTP and SE state, but it must re-specify measured boot, failure
  recovery, authentication, and immutable size rather than treating the
  existing PIN counters as an equivalent backend.
- Persistent grace, delayed floor commitment after `CONFIRMED`, user demotion,
  boot chords, and `REJECTED` states are outside this core design.
- A typed floor result `Aborted(DeadStageProof)` is not a manifest state,
  `REJECTED` state, user cancellation, or demotion feature. It is the
  deterministic result of an authenticated pre-`COMPLETE` stage whose frozen
  finite plan cannot complete and for which no completion-authority write may
  have launched. It preserves the unchanged prior floor and permanently
  quarantines the entire failed plan.
- `Aborted` carries no renewable or reserved follow-on epoch allowance. A two-page
  erasable launch journal makes every possible OTP launch identifiable, but it
  cannot make consumed WORM cells reusable. A mathematically dead finite plan
  therefore remains a typed terminal condition so the exact-`F` fallback and
  no-floor-write repair remain available instead of halting or forgetting the
  quarantine. No `T > F` field entry is constructible from `Aborted`.
- `PeerRepair` is a protected release/update class,
  not a new manifest lifecycle state or unsigned manifest flag. It uses a
  fresh installation identity and the complete
  `PENDING -> ATTEMPTED -> health -> CONFIRMED` lifecycle. A peer is never
  directly confirmed and never borrows its source's confirmation authority.
- Repository-wide formatting, expanded reset assembly, broad FI hardening,
  further fingerprint format/table changes beyond the landed base-27 packing,
  and unrelated factory lifecycle changes are outside the minimum series.
- A production-capable FSBL build MUST retain at least 2 KiB free in its fixed
  40 KiB region after the clean core implementation.
- FSBL transient SRAM/stack geometry is not silently expanded. `OPEN-RAM-1`
  must freeze the current 16 KiB envelope or a reviewed replacement, with
  static/worst-case stack accounting, margin, guard, and runtime handoff.
- A production device MUST have both independently verified slot-bound A and B
  artifacts of one logical release-set in `RobustAccepted` state before any
  field-update probation. This dual-slot genesis protects the completed `F=0`
  factory state against loss of one terminal replica; a one-slot or
  `PENDING`-only device is not a supported first-boot path. It is not a
  continuous two-witness guarantee: once a field update erases/replaces one
  peer and before the candidate gains independent terminal confirmation, the
  retained slot may be the sole accepted boot authority. Loss of that sole
  authority halts; PENDING/ATTEMPTED is never promoted.
- Every ordinarily selected robust `CONFIRMED(R,E)` slot, including factory genesis
  and a lone confirmed slot, MUST idempotently establish `F == E - 1` before
  handoff. A degraded accepted artifact never establishes a floor. Post-abort
  exact-`F` fallback leaves the floor unchanged;
  the failed candidate is never handed off.
- `R` is strictly increasing across logical release-sets within its namespace.
  `E` is nondecreasing as `R` increases; the independent
  `epoch_high_water` never decreases. Slot-A and slot-B artifacts for one release
  share the same `(R,E)` and logical source/policy identity. Any slot-specific
  linked bytes and hashes are explicitly paired by the release-set record.
- Every security-relevant release that must make any prior same-epoch signed
  artifact inadmissible MUST advance `E`. This is a production-signing policy
  gate, not a documentation convention.

---

## 3. Frozen software interfaces and explicitly open decisions

### FROZEN-JRN-IFACE-3 / OPEN-JRN-HW-1: PENDING/ATTEMPTED representation

Draft 0.2's manifest-resident `ATTEMPTED` quad-word is rejected. RM0456 says
that reset or power interruption during a main-flash single write leaves the
contents unguaranteed and mandates a page erase before rewriting that location.
An interrupted marker may therefore appear erased but not be safely
reprogrammable. Exact all-`0xFF` readback does not authorize retry.

Draft 1.1 re-freezes the exact composite software representation in Section 6:
`PENDING` plus two replicated `CONFIRMED` terminal markers live in three manifest quad-words and the arm
token lives in TAMP backup registers `BKP8..31`; BHK exclusively owns
`BKP0..7`. This freezes bytes, decoding, binding, and transition ordering so
independent host models cannot invent incompatible formats. It does **not**
make the TAMP backend production-eligible. `OPEN-JRN-HW-1` remains until exact
silicon demonstrates BHK coexistence, secure/privileged NS denial, reset and
tamper behavior, supported-board VBAT retention, and the final production
initialization/readback sequence. Failure of that gate reopens the physical
backend and requires a new reviewed digest. The Route-1 pages in Section 5 are
reserved only for OTP-launch intent and do not replace the TAMP probation
token or create a second lifecycle parser.

The ES0499 errata titled **"Incorrect backup domain reset with VBAT and VDD
supplied by the same power source"** and **"Incorrect backup domain reset with
VBAT and VDD supplied by different power sources"** are load-bearing to this
gate. Section numbers have moved between ES0499 revisions, and the currently
available project evidence does not justify pinning an unarchived revision
number. The production receipt MUST therefore archive the exact official
ES0499 PDF used for release, record its revision and SHA-256, map every
load-bearing erratum title to its section in that archived copy, record the
exact STM32 device/revision ID, and confirm applicability. A section number or
revision mentioned in an earlier review is not evidence by itself. In the
documented
VDD/VBAT power-cycling window the backup-domain reset may be missed and TAMP/
BKP contents may be unpredictable. Therefore Draft 1.1 makes no deterministic
at-most-once claim across complete or marginal backup-domain power loss. The
production cold-boot path must implement and validate the applicable ST
workaround for the final board topology. With separately supplied VBAT,
`PWR_BDCR1.MONEN` must have been continuously active before the questionable
power event; setting it afterward does not retroactively authenticate retained
state. FSBL verifies retained MONEN before token decode, sets it for future
boots, and configures `PWR_SECCFGR.VBSEC=1`,
`PWR_PRIVCFGR.SPRIV=1`, and exact secure/privileged readback before NS.

`OPEN-JRN-HW-1` must select exactly one reviewed cold-boot policy for the final
topology: (a) protected retained `MONEN`, but only when continuous pre-event
validity is proved; (b) structurally authenticated token-first handling plus
reactive forced-`BDRST` sanitation; or (c) a separately re-frozen conditional
policy when supported Shutdown must be distinguished from backup-domain
power-on. Policy (b) MUST NOT erase the token before its one full immutable
decode: doing so makes `ARM_READY` unreachable and destroys the selected
mechanism. FSBL first snapshots tamper/reset evidence and reads all
`BKP8..31` twice. Only an exact, stable, fully complement/seal/binding-valid
token may influence classification. Invalid, unstable, or unavailable content
grants no authority and then triggers the documented `DBP` +
`RCC_BDCR.BDRST` assertion/readback/deassertion/reinitialization sequence
before any later rebind. A valid `ARM_READY` is changed to exact `ATTEMPTED`
before handoff; a valid `ATTEMPTED` excludes the candidate. Production
eligibility requires silicon evidence that the selected power envelope
preserves this liveness and that no marginal/reset transition can transform a
previous `ATTEMPTED` into valid bound `ARM_READY`.

Policy (c) is ineligible until a new reviewed digest freezes every immutable
reset-cause input (including the exact `BORRSTF` register/bit/read/clear
semantics if the archived workaround uses it), the complete balanced
canary/integrity/CRC representation and update ordering, its disjoint BKP
ownership, and its fail-closed truth table. There is no generic or implicit
`integrity-test` branch. If that representation consumes or aliases any of
`BKP8..31`, `FROZEN-JRN-IFACE-3` and all token fixtures must be re-frozen.
Before any forced BDRST, immutable boot captures tamper flags
and applies the selected tamper-wipe policy so sanitation cannot erase evidence
and bypass escalation. The implementation also accounts for the ES0499
errata titled **"SRAM2, PKA SRAM, and ICACHE are erased when BDRST bit is
set"** and **"IWDG is stopped when BDRST is set"**. Their section numbers
likewise come from the archived production receipt, not from this draft.
BDRST assertion/deassertion is tightly sequenced and no secret or watchdog
assumption survives it.

That tamper action remains `OPEN-JRN-HW-1`: FSBL intentionally has no PIN or
secure-element administrative stack, so this sentence does not authorize
pulling those drivers into immutable boot. The reviewed resolution must be an
implementable immutable halt/quarantine, a separately authenticated evidence
handoff, or a retained-MONEN path that does not need destructive sanitation;
it may not silently claim that FSBL itself performed the existing admin wipe.

Resetting the domain invalidates the token and BHK; BHK is regenerated from
its separately protected wrapped record before later use. Until the workaround,
exact reset classification, and board power envelope pass on silicon, token
corruption or apparent retention can only reject a probationary candidate and
cannot grant retry authority. A fallback may boot only when the independently
decoded floor class is `Steady` or exact constrained `Aborted`; terminal
confirmation ignores the token, and `Recovering`/`Unknown` still forbid
handoff.

The exact 24-word token leaves no spare backup register for ES0499's optional
backup-domain CRC. If the final board cannot use the protected `MONEN` route or
a reviewed unconditional/conditional forced-`BDRST` policy and therefore
requires that CRC, the BKP allocation is not viable and MUST be re-frozen under
a new digest; a token seal may be repurposed only after equivalent structure is
reproved. The token's SHA-256 binding detects token corruption but is not the
configuration CRC described by the erratum.

The production tamper-source/erase policy also remains part of
`OPEN-JRN-HW-1`. The current research TAMP path enables a broad internal-
tamper mask with erase-on-event behavior; existing project analysis warns that
debug-related and legitimate-crypto-related sources such as ITAMP6/ITAMP9 can
erase the loaded BHK and arm token. Token loss is rollback-fail-safe but may be
an availability failure. No production journal selection may inherit that mask
or `CR3` policy without a source-by-source BHK/token coexistence receipt.

The at-most-once claim is software- and trust-scoped: once FSBL writes exact
`ATTEMPTED`, an ordinary crash, watchdog, or reset inside the validated
retained backup-domain envelope cannot turn it back into `ARM_READY`, so the candidate
receives no second handoff. Complete/marginal backup-power events are excluded
until the ES0499 sanitation gate closes. The running
vendor-signed secure candidate is nevertheless privileged enough to rewrite
TAMP deliberately; the design relies on there being no such production path
and does not claim a hardware write-once token. Every new field reinstall or
recreation of `ARM_READY` is again gated by the production PIN/unlock path.
FSBL may retry an already exact `ARM_READY` only because no candidate handoff
has yet occurred; that retry neither recreates the token nor opens a new health
session. TAMP is preferred over another
retryable flash arm marker specifically because RM0456 Section 7.3.12 requires
page erase after an interrupted main-flash write even when the location later
appears erased. The selected TAMP interface and any later TAMP-versus-erasable-
journal reconsideration MUST record this tradeoff explicitly.

The retry advantage is bounded by backup-domain retention. `ARM_READY`
survives only while VBAT keeps the backup domain powered and no tamper or
authorized backup-domain reset clears it. The current hardware plan's
0.47--1 F supercapacitor has an estimated, not guaranteed, retention window of
roughly 12--24 hours; the B-U585I-IOT02A development kit does not provide that
production retention by default unless an appropriate battery/supercapacitor
is fitted. VBAT removal, supercapacitor drain, tamper erase, or backup-domain
reset before the transition therefore turns the candidate into a safe false
negative: the missing/malformed token rejects the candidate and requires a
fresh PIN-gated reinstall/re-arm. The eligible confirmed fallback boots only
from `Steady` or exact constrained `Aborted`; any other floor class retains its
own no-handoff rule.
No security or at-most-once claim may depend on token retention. `OPEN-JRN-HW-1`
must record the measured supported-board retention envelope and compare this
bounded retry/UX benefit with an erasable journal's persistence and larger
power-cut/compaction TCB.

Probation arming also requires a clean credential-attempt budget without
adding PIN or secure-element drivers to FSBL. A confirmed runtime mints private
linear `CleanPinBudget` only after a successful production OPTIGA+SE050 unlock,
fresh OPTIGA E120 reset/readback at zero, two agreeing page-124 reset/readbacks
at zero, successful SE050 UserID authentication with its documented automatic
counter reset, and no later credential attempt. SE050's production UserID
counter is not numerically readable; this design does not claim a three-way
numeric reserve. Any reset/readback failure zeroizes the reconstructed master,
withholds `pin_verified`, and creates no update or arm authority.

The activation writer consumes `CleanPinBudget` exactly once and encodes the
fixed `CLEAN10` state into the Section-6 token binding for that installation,
candidate, fallback, manifest, and boot/session. Full clean (ten attempts
remaining), rather than merely an estimated reserve, is the only accepted
arming state. A future relaxed bound requires a new reviewed digest; the host
model still proves that fewer than three remaining attempts would be
insufficient for candidate plus bounded fallback recovery.

Probation handoff mints one non-`Copy`, non-`Clone` `ProbationPinPermit`.
Before showing the real PIN prompt, the candidate must consume an attempt-
neutral `PreparedProbationPin` obtained from the exact production derivation
KAT, shield/SCP03 setup, and an SE050 create/close-session check that does not
invoke `VerifySession`. Only `gated_unlock_prepared` may consume both values.
Success, wrong PIN, cancel, transport failure, or internal error terminates
that probation handoff; no second prompt or credential retry exists.
`ATTEMPTED` remains the durable one-handoff counter, so no second persistent
retry counter is added.

Failed probation debt is never refunded. From a clean baseline and one permit,
the only expected readable `(MCU,E120)` pairs are `(0,0)`, `(1,0)`, and
`(1,1)`; any other pair blocks re-arm for that installation. MCU-leading debt
remains conservative and recoverable by an ordinary correct fallback unlock
below the existing maximum; it is not by itself a new wallet-wipe condition.
Existing readable-SE-leading/split and actual lockout policies remain. A fresh
reinstall/re-arm requires another successful confirmed-fallback unlock and new
`CleanPinBudget`. `OPEN-PIN-HW-1` remains until the attempt-neutral SE050
session and exact cut traces are validated on silicon; no OTP write is involved.

### OPEN-PIN-HW-1: attempt-neutral preparation and one-attempt cut evidence

The software contract above is frozen, but its hardware premise remains open.
Before production probation is eligible, a named nonproduction STM32U585AI +
OPTIGA + SE050 assembly MUST demonstrate that `PreparedProbationPin` performs
the production KAT, tunnel/session setup, and SE050 create/close-session path
without invoking `VerifySession`, consuming a PIN attempt, changing page 124,
or changing OPTIGA E120. Bus/APDU instrumentation and before/after receipts
must prove the absence rather than infer it from a success status.

The same fixture then cuts or resets every boundary before, during, and after
the one real `gated_unlock_prepared` attempt, including MCU page-124 precommit,
OPTIGA authentication/counter handling, SE050 UserID verification/session
close, clean-counter reset/readback, master reconstruction, and receipt
construction. After each cut, boot reconciliation must select the strictest
durable debt, never issue a second probation permit, never refund an actual
wrong attempt, never publish unlock/master state, and permit re-arm only after
the ordinary confirmed-fallback unlock and complete reinstall path. The
readable `(MCU,E120)` outcomes are limited to `(0,0)`, `(1,0)`, and `(1,1)`;
every other readable pair follows the existing tamper/lockout policy.

The receipt MUST also validate the real SE050 successful-authentication reset
semantics and wrong-PIN/terminal-lockout status used by the three-way policy.
Host mocks, QEMU, or a vendor API description cannot close this gate. These
tests do not authorize OTP, option-byte, or production-credential operations;
any intentionally destructive UserID-lockout case requires a separately named
throwaway secure element/device and owner authorization.

The epoch split makes confirmation-writer ownership an explicit red line.
Draft 1.1 retains the smaller runtime writer: after revalidating its own bound
`ATTEMPTED` identity and completing Section 9, the candidate consumes one
private `RuntimeFinalizationReceipt`. The candidate-bound writer derives its
destination only from immutable trusted execution-slot identity plus frozen
manifest geometry, double-checks that address and its complement, programs
`QW_CONFIRMED_0`, obtains its selected durable receipt, then programs
`QW_CONFIRMED_1` and obtains a separately attributed durable receipt. No
manifest field, TAMP body, NS buffer, or companion value selects either
destination. It resets immediately without wallet/NS authority. For a
same-epoch release there is no OTP witness. This relies on the stated trust in
vendor-signed secure runtime and MUST NOT be described as FSBL having directly
observed the health transcript.

Moving the confirmation write into FSBL remains an alternative for reviewers,
not a silently accepted expansion. A safe version would require at least a
bound `HEALTH_PASSED` token, invalidation-before-token-rebind, and a durable
pre-write `SEALING` claim so an interrupted apparently-erased confirmation
quad-word is never reprogrammed. Those extra composite states and flash paths
must justify their immutable size and power-cut complexity before replacing
the smaller writer model.

Whichever TAMP design is selected, rebinding the global token for a new slot
installation MUST first write and read back an exact non-forward-decoding
invalid state before changing the binding body, then activate `ARM_READY` last.
Otherwise a stale activation could transiently pair with a new body. The
write-prefix model must include reinstalling byte-identical signed artifacts;
if freshness beyond the signed identity is required, the token must bind a
fresh per-install nonce generated only after exact invalidation.

### OPEN-JRN-DUR-1: interrupted manifest-marker durability

The frozen marker and per-install identity values do not by themselves prove
physical durability.
RM0456 Sections 7.3.11--7.3.12 say a reset or power interruption during a
main-flash QW write leaves contents not guaranteed and requires page erase
before rewriting. A later read that is byte-exact and currently `ECCC`-clear
is not a documented retention/margin read. This is most consequential for
terminal acceptance: accepting a marginal exact-looking replica, advancing the
epoch floor, and later losing all independent authority can make both slots
ineligible.

Accordingly, every `exact` marker in Sections 6--11 means a typed
**durably-clean exact** observation produced by the ultimately approved rule,
never raw byte comparison. `OPEN-JRN-DUR-1` must define how a boot after a
possible marker launch distinguishes a completed durable write from an
interrupted exact-looking outcome. Draft 1.1 freezes the software authority
rule: `FullTerminalSet` needs two independently launched and attributed clean
replicas; `SurvivingTerminalSet` needs one and is repair-target evidence only,
never boot or floor authority.
EOP observed only before reset is not durable evidence.

A single lost terminal or install-identity QW therefore does not brick the
device while an independently robust peer remains, but it removes that
artifact's own boot authority. The surviving clean evidence
may reconstruct the exact installation identity as repair-target
authority under Section 6.2. It never creates floor-establishment, updater,
probation, fallback, boot, or repair-writer authority. Only a robust peer
preserves a bootable path; if no robust accepted authority
remains, FSBL halts to service.

A committed floor group for an epoch bump MUST bind the full accepted manifest
identity: physical slot, `R`, `E`, `T`, freshly recomputed signed-manifest
digest, both signed image hashes, exact `install_id`, group identity, and
codec/domain. That binding is evidentiary only; it grants no admission
authority when the artifact's terminal set later becomes unavailable. It cannot
authorize a different artifact, lower `F`, revive a retired epoch, replace
initial confirmation, or bypass image/vector/handoff revalidation. The
physical representation and recovery copies remain
`OPEN-JRN-DUR-1`/`OPEN-OTP-1..3`.

The marker decoder uses **terminal-set precedence**. It snapshots operation
status and fresh-probes `QW_CONFIRMED_0` and `QW_CONFIRMED_1` before PENDING.
Two clean exact replicas form `FullTerminalSet`. One forms
`SurvivingTerminalSet` only under the writer-order and no-conflict rules in
Section 6.2. The probation branch is permitted only when both replicas are
`BlankVirgin`; any exact, may-have-launched, corrected, conflicting, or
impossible-order terminal state never falls through to PENDING. Normalized CRC/signature
verification synthesizes canonical all-`0xFF` bytes for the full 80-byte
journal window, and the signature preimage contains no journal QW.

After the lifecycle branch is chosen, the decoder constructs
`FullInstallGeneration` or the narrowly allowed
`SurvivingInstallGeneration` before issuing an `ArtifactEvidenceKey`. It never
reads historical PENDING/TAMP after accepted terminal authority. Operation
status attributable only to an old PENDING write does not demote an
independently robust terminal set; ambiguous attribution fails closed.

Initial floor establishment, ordinary probation fallback, factory genesis, and
every repair/update writer require `RobustAccepted`. Factory genesis
requires both terminal replicas in both slots. While the floor decoder remains
`Recovering` and before `Steady(T)`, loss of robust candidate authority does
not expose the prior floor. `CheckedRecoveryIntent` instead yields
`RecoveryBlocked(MissingRobustTerminalAuthority)` and halts without writer,
fallback, or handoff authority. Draft 1.1 selects no stage-bound confirmation
authority. Failure to meet this availability boundary leaves field epoch bumps
ship-blocked.

Any later change to this authority order, binding set, manifest QW ownership,
or normalized window reopens this interface and `FROZEN-MAN-4` under a new
digest.

At immutable entry, before any flash mutation or status clear, the sole flash-
evidence owner snapshots the common `FLASH_OPSR` once and exhaustively decodes
`SYSF_OP`, `BK_OP`, and `ADDR_OP`. It preserves that typed snapshot until both
manifest-journal and OTP floor/stage classification or recovery have
incorporated it. For a probation handoff it additionally preserves a compact
typed `BootFlashEvidenceSummary` in the secure-only context through finalization;
initial consumers do not discard the evidence needed by that later pass.
Ambiguous fields, an invalid address, or inconsistent status fail closed
and cannot produce `BlankVirgin`. An interrupted
operation attributed to a manifest page/QW makes that exact location
`UnknownMayHaveLaunched` regardless of current bytes; it cannot confirm,
authorize floor establishment, or be reprogrammed. The mandated page-erase/new-
generation corrective action is permitted only when the slot is independently
safe to treat as inactive and the confirmed fallback remains valid. Otherwise
FSBL globally inhibits further flash mutation and halts.
Status is not cleared or overwritten
before this decision.

One immutable flash-evidence owner controls all common `FLASH_OPSR` and
`FLASH_ECCR` state. After the single early OPSR snapshot, it classifies the
floor/stage region with one exact-index fresh-read transaction at a time,
consumes or clears only the attributed ECC result, and only then probes
candidate manifests. Within each candidate it probes CONFIRMED before PENDING.
No helper may clear common status, trigger an unrelated flash read, or reuse an
ECC observation between indices. NMI recovery returns only a typed result to
this owner. This ordering is part of `OPEN-ECC-1` and the combined FSBL
footprint, not optional diagnostic code.

Because the applicable ES0499 workaround may stop IWDG while `BDRST` is
asserted, immutable boot MUST deassert/read back `BDRST`, reinitialize and read
back the watchdog from a clean bounded state, and only then enter any long
hash/signature/recovery path or handoff. No pre-BDRST watchdog assumption or
deadline is carried forward.

`FLASH_OPSR` covers system-reset interruption only. Complete power loss removes
that evidence, so the separate durable-witness rule remains mandatory and may
not be replaced by an OPSR-only implementation.

Until this closes, host models must include `UnknownMayHaveLaunched` separately
from `BlankVirgin`, `DurablyCleanExact`, and `Malformed`; raw exact bytes can
never authorize `CONFIRMED` or floor establishment after an ambiguous launch.
`OPEN-ECC-1` covers manifest activation markers as well as OTP reads. If
closure needs another manifest QW or a wider CRC-normalized window, the
manifest schema/layout must be re-frozen under a new reviewed digest. Failure
to construct a fit, power-cut-safe rule is a journal-backend ship blocker.

### FROZEN-MAN-4: exact manifest-v6 schema and domain bytes

Section 6.1 freezes the manifest-v6 schema byte, exact offsets, 7-byte
`PQFW_V6` signing domain, domain-separated vendor-key fingerprint, 121-byte
signed preimage, normalized CRC, golden
vectors, and flag-day legacy rejection. No manifest, FSBL, signer, inspector,
factory, updater, extraction, or formal implementation may substitute a
temporary literal, default epoch, translated legacy offset, or dual parser.
Changing any frozen byte requires a new schema/domain and a newly reviewed
architecture digest.

### OPEN-ECC-1: candidate/marker reads and OTP correction attribution

Double-bit flash ECC raises NMI on STM32U585AI. Ordinary `Result`-returning
parsing cannot guarantee that FSBL evaluates the good slot after encountering
a torn candidate line. Section 7's minimal NMI recovery primitive is core
scope, but its exception-return and cache behavior must be validated on exact
silicon before the fallback claim is production-valid.

The same primitive covers all five device-written manifest journal QWs: the
install-identity value/complement pair, PENDING, and the two independent
CONFIRMED terminal replicas. An ECCC/ECCD result is never an exact identity or marker, and an
ECCC-clear exact-looking result after a possible interrupted program remains
subject to `OPEN-JRN-DUR-1`; fresh-array attribution is necessary but not a
retention proof.

OTP floor reads add a separate single-error requirement. RM0456 reports a
corrected one-bit read through `FLASH_ECCR.ECCC`, and warns that a buffered
reread may not raise the flag again after it is cleared. The production OTP
decoder therefore needs a silicon-validated per-QW primitive that clears stale
ECC state, forces a new array read through documented cache/data-buffer
maintenance, attributes `ECCC`/`ECCD` to the exact QW, and consumes the flags
before any other flash read. Corrected bytes are never accepted as clean floor
authority. If a fresh array read and flag attribution cannot be demonstrated,
the OTP backend remains NO-GO.

The one immutable `FlashEvidenceOwner` implements this frozen state machine
from SRAM:

```rust
enum ProbePhase {
    Idle,
    Armed { epoch: u32, index: u16, address: u32 },
    LoadIssued { epoch: u32, index: u16, address: u32 },
    EccdCaught { epoch: u32, index: u16, eccr: u32 },
    Completed,
}

fn fresh_qw_read(
    owner: &mut FlashEvidenceOwner,
    index: PhysicalQw,
) -> FreshQwRead;
```

For each read it consumes the saved operation evidence, snapshots and clears
stale `ECCC/ECCD` with verified clear, executes the selected cache/current-
buffer eviction, arms the exact address/index/probe epoch, performs exactly one
array transaction, and snapshots `FLASH_ECCR` immediately before any other
flash data or instruction fetch. It validates the address, bank/system-info
fields, and flags, clears only attributed status, performs the required cache
maintenance, verifies clear, and then returns the Section-3 typed result. A
wrong address, stale flag, nested probe, simultaneous NMI source, or failed
maintenance is `AmbiguousOrFault`.

The permanent SRAM NMI handler distinguishes one matching FLASH ECCD from all
other NMI causes, records only into volatile owner state, discards the loaded
bytes, and uses the silicon-validated exception-return contract. Unexpected or
nested NMI resets or halts directly from SRAM. `ECCC` suppressing later address
reporting, ECCD NMI suppression while ECCC remains set, current-buffer-served
rereads, and special erased-line behavior are explicit negative tests. Neither
ICACHE invalidation alone nor repeated volatile loads is a freshness proof.

### FROZEN-FLASH-MUT-1 / OPEN-FLASH-HW-1: complete SRAM mutation closure

Every operation that can make bank 1 or the FLASH/OTP controller busy uses one
private SRAM execution capsule: inactive secure-image page erase/program,
manifest erase/program, Route-1 journal erase/program/compaction, install-ID,
PENDING, both CONFIRMED replicas, OTP programming, the confirm-gated
first-boot RDP option-byte program with `OBL_LAUNCH` (Section 6.3
`FirstBootLockWriter`), and the first-boot page-127 journal append plus the
journal-gated page-126 erase-and-reprogram (Section 6.3
`FirstBootJournalWriter`). Masking interrupts while
executing ordinary bank-1 `.text` is nonconforming.

```rust
struct PreparedRamClosure<'boot> { /* private, linear */ }
struct CheckedFlashMutation<'boot> { /* exact operation/range/data */ }

enum FlashMutationOutcome {
    Completed(FlashMutationReceipt),
    ProvenNoLaunch,
    UnknownMayHaveLaunched(FlashFault),
}

fn execute_same_bank(
    closure: PreparedRamClosure<'_>,
    op: CheckedFlashMutation<'_>,
    watchdog: BoundedWatchdogLease,
) -> FlashMutationOutcome;
```

There is no public raw-address mutator. `CheckedFlashMutation` is created only
by the separate logical writer allowlists in Section 6.3. The capsule contains
all code, literal pools, rodata, mutable state, target bytes, stack, exception
frame, cache/relock logic, and direct reset path. Post-link reachability and
relocation analysis rejects every reference outside approved SRAM/MMIO; the
complete copied capsule and permanent vector are integrity-checked before
entry. No logging, formatting, panic, allocator, flash-resident failure path,
or unbounded call is reachable.

Before mutable runtime sets `SYSCFG_CSLCKR.LOCKSVTAIRCR`, it installs and
integrity-checks the permanent secure SRAM vector and points secure VTOR at it.
NMI and HardFault entries and their complete direct-reset callees remain SRAM-
resident for the lifetime of the image. The capsule masks Secure and
Nonsecure maskable exceptions, clears/quiesces pending NS work, and closes all
relevant bus masters; flash-resident configurable handlers cannot run while a
bank is busy. Where an approved MPU policy permits, vector/code is RO+X and
stack/data is RW+XN. A later temporary VTOR switch is forbidden after the
lock.

The capsule pre-kicks IWDG once under a bounded operation-time proof and never
feeds it from an unbounded `BSY` wait. Timeout resets and classifies
`UnknownMayHaveLaunched`. After completion it captures status, clears
operation bits, relocks, performs cache maintenance plus `DSB; ISB`, and
returns to flash only after busy is proven clear. `OPEN-RAM-1` charges the
permanent vector, closure code/data, staged operation list, stack, and worst-
case nested NMI frame. Host post-link closure proofs are required before any
physical implementation is eligible; exact U585 execution, exception return,
IWDG timing, and cache behavior remain `OPEN-FLASH-HW-1` silicon gates.

### OPEN-RAM-1: immutable FSBL RAM/stack envelope

The current FSBL linker reserves the first 16 KiB of secure SRAM1 for all
initialized/static data and MSP stack. This is a current linker contract, not
an immutable silicon partition: the runtime reuses SRAM1 after handoff. The
research history already contains a documented approximately 24.7 KiB silent
stack overflow when two manifest copies were live across C10 verification, and
the current FSBL has no `MSPLIM` guard. Passing the FLASH link therefore does
not prove boot safety.

Before any journal/codec combination can be selected, the architecture MUST
freeze either the existing 16 KiB envelope or a separately reviewed larger
transient FSBL SRAM1 window, the authoritative static-RAM end, a nonzero
worst-case stack margin, and the guard/fault policy. The static end is the
maximum end address of every RAM-mapped allocatable section—including `.data`,
`.bss`, `.uninit`, custom `NOLOAD`, linker/runtime statics, and alignment
gaps—or an equivalent linker-defined symbol/assertion; a `.data + .bss` sum is
not sufficient. Silent RAM enlargement is not a size fix: it requires linker,
TrustZone/MPCBB, runtime-reuse, handoff, named-secret zeroization, and
coexistence review. It does not authorize the deferred full-SRAM scrub
assembly.

For every production-equivalent combined candidate and final build, evidence
MUST account for that complete static occupied span and the worst-case LTO call
chain through C10 verification, SHA/image verification,
measured-boot rendering, journal/floor decoding and recovery, and an ECC-NMI
exception frame at the worst legal nesting point, including the retained
probation handoff context and runtime finalization-verifier/NMI path. Compiler stack-usage/call-
graph evidence must cover indirect calls and hand-written assembly; on-target
stack-pattern high-water tests over normal, malformed-slot, recovery, and NMI
paths corroborate but do not replace the bound. A Cortex-M33 `MSPLIM` guard (or
an independently reviewed equivalent fail-closed bound) SHOULD be configured
before mutable slot/OTP data is parsed, with explicit fault/reset behavior and
safe handoff to the runtime's own approved limit. The exact margin and guard
are open; a candidate with unbounded/unknown stack use is ineligible.

With `static_end` and downward-growing MSP stack start `stack_start`, the gate
MUST use checked arithmetic and establish:

```text
available_bytes = checked_sub(stack_start, static_end)
required_base  = checked_add(worst_case_stack_bytes,
                             frozen_margin_bytes)
required_bytes = checked_add(required_base, reserved_guard_bytes)
available_bytes >= required_bytes
```

Failure of either checked operation—including `static_end > stack_start`—makes
the candidate ineligible. No unsigned intermediate may wrap.

A configured guard violation MUST fail closed. If hardware guarding is
omitted under the reviewed SHOULD decision, the receipt must state that
omission explicitly. `reserved_guard_bytes` is the exact space reserved by the
selected guard policy; an omission may set it to zero only through that
explicit review. The static bound and nonzero frozen margin remain mandatory
in either case and may not be replaced by high-water sampling.

### FROZEN-OTP-API-3: typed floor and establishment semantics

Draft 1.1 freezes the software semantics at the FSBL admission and
establishment boundary, but not Rust layout or the still-open physical OTP
codec. The full decoder scans every reserved rollback QW and both Route-1
journal pages and yields exactly one mutually exclusive class:

```rust
enum FloorView {
    Steady(SteadyProof),
    Recovering(RecoveryProof),
    Aborted(DeadStageProof),
    Unknown(FloorFault),
}
```

`SteadyProof` binds the admission-authoritative `F`, a committed group identity
or canonical `BASE0`, allocation generation/cursor, cumulative ownership and
quarantine digest, accepted-manifest binding where one exists, and a digest of
the complete physical snapshot. `RecoveryProof` binds at least `prior_f`, the
prior group identity/digest or `BASE0`, allocation generation/cursor, exact
target and active group, candidate/manifest binding, ordered non-aliasing
physical-cell role map, consumed/quarantined set, finite remaining plan, and
the exact Route-1 durable launch-journal generation. It deliberately has no
method exposing `prior_f` as an admission floor.

`DeadStageProof` is a typed terminal proof, not a writable state or
cancellation command. It binds the unchanged authoritative prior `F`, exact
failed candidate and A/B release-set identity, failed `E/T`,
`aborted_release_high_water`, predecessor/group digest or `BASE0`, allocation
generation/cursor, the entire permanently quarantined failed-plan role set,
cumulative ownership digest, authoritative predecessor accepted-manifest
binding when one exists, Route-1 journal high-water, immutable-entry
boot-evidence epoch, and a digest of the complete floor/stage/journal physical
snapshot. It also carries durable proof that no `COMPLETE` body, activation,
or equivalent completion-authority write may have launched. It carries no
renewable capacity or method that can authorize `T > F` or another field epoch
plan. A mathematically dead finite plan remains `Aborted` so the exact-`F`
fallback and zero-floor-write repair stay available; OTP WORM cells are never
pretended reusable. `Unknown` carries diagnostics only and never a usable
floor.

`SteadyProof`, `RecoveryProof`, and `DeadStageProof` are boot-scoped linear
capabilities: they are neither `Copy` nor `Clone`, are not serializable, and
cannot survive or be reconstructed from a cached prior-boot value. Every typed
entry consumes its proof by value and first requires a fresh full decode
against the preserved immutable-entry `FLASH_OPSR` snapshot with newly forced,
newly attributed per-QW reads. A mutation-capable entry never returns the
consumed old proof. Only a later full decode can issue a new class, and it can
reissue `Aborted` only when the same terminal dead plan and quarantine remain
fully proved.

No decoder receives a bare `[u8; 16]`. The hardware boundary is typed:

```rust
enum FreshQwRead {
    Clean(CleanQw),
    Corrected { bytes: [u8; 16], index: u16 },
    Uncorrectable { index: u16 },
    AmbiguousOrFault,
}
```

`CleanQw` is constructible only by the exact-index fresh-array primitive. Its
typestate binds physical QW index, absolute address, bytes, probe epoch, and
attributed status snapshot; it cannot be reinterpreted at another index. A
`BlankVirgin` proof requires `CleanQw(all-FF)` plus proof that no operation
status, Route-1 reservation/claim, floor stage, ownership record, or writer
launch for that exact index may be missing. `Corrected` has zero quorum weight
and is never virgin. `Uncorrectable` and ambiguous observations confer no
authority. The exact SRAM probe/NMI/cache mechanics remain `OPEN-ECC-1` and
silicon-gated.

Every reserved rollback QW is accounted for by the authenticated chain as
canonical virgin, one distinct committed role, one distinct active role,
permanently consumed/quarantined, or an invalid/unknown orphan. A nonblank,
corrected, uncorrectable, or may-have-launched QW outside that map forces
`Unknown`. One physical QW cannot count twice or alias a committed, active,
journal-reserved, or quarantined role. The decoder never relies on a mutable
head oracle.

Classification from fresh `Steady(F)` is exact:

```text
T < F  -> inconsistent/fail
T == F -> SameEpoch
T > F  -> EpochBump
```

For `T == F`, the caller bypasses every mutable rollback-backend entry.
Counters and trace proofs require zero OTP unlocks/programs, zero Route-1
reservation/claim/stage/activation writes, and zero rollback-journal
compactions even when capacity is exhausted. For `T > F`, read-only preflight
binds the exact snapshot, robustly confirmed candidate, codec, target,
complete finite cell-role plan, replacement margin, Route-1 journal capacity,
completion-witness cost, accepted-manifest binding, and selected key health.
It reserves only this one frozen plan. If the plan becomes
mathematically dead, the result may become `Aborted` and no later autonomous
epoch bump is constructible from it. A preflight receipt is comparison data,
not durable authority; the private immutable writer reparses and reverifies
all raw inputs before mutation.

The frozen entries are:

```text
arm_probation_from_steady(CheckedSteadyProbationIntent)
start_from_steady(CheckedSteadyIntent)
resume_from_recovery(CheckedRecoveryIntent)
boot_accepted_from_aborted(CheckedAbortedAcceptedIntent)
arm_peer_repair(CheckedPeerRepairIntent)
arm_degraded_artifact_repair(CheckedDegradedRepairIntent)
```

Each `Checked*` wrapper is a private, boot-scoped, non-`Copy`,
non-`Clone`, nonserializable linear owner of exactly one decoder proof and all
artifact evidence required for that action. Constructors consume every input,
join all floor evidence to one boot/snapshot, and separately require byte-equal
`ArtifactEvidenceKey` only between each physical artifact and its own
lifecycle evidence. Distinct artifacts retain distinct keys.

`CheckedSteadyProbationIntent` owns `SteadyProof`, an independently verified
`RobustAccepted` exact-`F` fallback, and the qualified
PENDING/`ARM_READY` candidate. It requires the candidate to be strictly
`R`-newer and normally `E`-nondecreasing. Its private variant is
`SameEpoch { T == F }` with no rollback capacity receipt, or
`EpochBump { T > F, receipt }` with the fresh read-only finite-plan receipt.
`CheckedSteadyIntent` owns one `SteadyProof` and a
`RobustAccepted` confirmed artifact; only its epoch-bump variant can enter the
rollback writer.

`CheckedRecoveryIntent` owns fresh `RecoveryProof` and a freshly verified
proof-bound `RobustAccepted` candidate. It requires matching candidate,
target, floor/stage/journal snapshot, boot epoch, and artifact key.
Missing robust
terminal authority returns nonwritable
`RecoveryBlocked(MissingRobustTerminalAuthority)`, consumes every input, and
exposes no prior floor, fallback, handoff, or writer authority.

`arm_probation_from_steady` is the sole ordinary entry that may perform
`ARM_READY -> ATTEMPTED` and hand off a candidate. It makes no rollback-state
mutation. After changing TAMP it freshly decodes `Steady(F)` and reverifies the
robust exact-`F` fallback and exact composite `ATTEMPTED` candidate immediately
before handoff. Any error consumes all capabilities. Exact `ARM_READY` may be
retried only after a new top-level decode proves that no candidate ran; exact
`ATTEMPTED` never retries.

`start_from_steady` returns a no-write same-epoch result only for `T == F` or
begins exactly one preflighted `T > F` plan. `resume_from_recovery` resumes only
the bound active plan; it cannot call fresh begin, reinterpret `prior_f`, enter
the same-epoch branch, or return handoff authority. Each recovery action must
establish a planned clean role, terminally consume one, establish exact
`COMPLETE`, or make a fresh decoder reach `Aborted` or `Unknown`. A finite plan
may not remain `Recovering` after it is mathematically non-completable.

Only the decoder constructs `DeadStageProof`, and only when one authenticated
pre-`COMPLETE` stage is current; the prior floor still has clean authoritative
quorum (or first-bump `BASE0` is exact); `T > F` and `T == E - 1`; the complete
finite plan is accounted for and cannot reach its clean threshold; every
uncertain role is terminally owned; no valid target group or `COMPLETE(T)`
exists; and a durable completion-launch fence proves no completion-authority
write may have launched. Missing or all-`FF` completion bytes alone are not
proof. Classification priority is: authoritative `COMPLETE` plus clean group
to `Steady(T)`; bound completion recovery to `Recovering`; any ambiguous or
conflicting completion authority to `Unknown`; only then proven-no-completion-
launch plus a mathematically dead plan to `Aborted`.

An `Aborted` view excludes the failed candidate and its A/B twin and permits
only no-floor-write paths. `boot_accepted_from_aborted` requires and consumes
fresh `DeadStageProof` plus the best independently reverified
`RobustAccepted` artifact with exact `T == F`, performs no persistent
mutation, then repeats the complete decode and artifact verification
immediately before handoff. This may be the original fallback or a later
fully probated peer-repair artifact; `Aborted` persists. It
may emit only stable comparison data in a non-authorizing
`AbortedUpdateContext`; no floor proof or writer capability crosses handoff.

`Aborted` has no new-release path. The device boots only the previously
accepted robust exact-`F` artifact through `boot_accepted_from_aborted`, or
halts to service. No on-device or off-device classification can admit a new
release from `Aborted`, and no path from `Aborted` performs rollback-journal,
floor-stage, compaction, or OTP writes.

`PeerRepair` restores A/B redundancy without pretending an unexecuted twin is
healthy. It requires a `RobustAccepted` source, the opposite-slot artifact from
the protected archived A/B release set with identical `(R,E)`, vendor policy,
and logical source identity, an independently valid slot-bound signature and
images, exact `T == F`, and a fresh install identity. It performs a complete
inactive erase/restage and the full probation and health protocol before that
peer gains its own two terminal replicas. It never directly confirms a copied
peer and performs zero rollback-backend writes. This narrow typed exception is
the only equal-`R` PENDING path.

`DegradedArtifactRepair` is similarly narrow. When a robust source outranks a
higher-`R` degraded terminal artifact for writer authority, it may completely
erase/restage that exact target slot from its protected archived package and
rerun full probation and health. Under `Aborted`, exact `T=F` is mandatory and
the backend remains untouched. Under `Steady`, a repaired `T>F` target becomes
eligible for only the ordinary one-plan establishment after it is robust; the
repair itself grants no floor authority.
The degraded artifact counts in release and epoch high-water calculations.
There is no in-place replica patch. If only degraded accepted authority remains,
FSBL halts to service and exposes no updater,
probation, floor, fallback, or repair capability.

The durable establishment flow is:

```text
fresh: observe -> preflight -> Route-1 reserve/activate exact launch intent
       -> program/classify one exact OTP role
       -> record clean or consume -> COMPLETE(full clean group)
recovery: observe -> resume bound roles -> COMPLETE | Aborted | Unknown
maintenance: after COMPLETE, retain old authority until a disjoint copy is exact
```

Before each OTP launch the Route-1 backend must produce an exact-index,
exact-role `OtpLaunchAuthority` proving that a possibly launched QW can never
later be classified virgin or retried after reset or complete power loss. An
outstanding or ambiguous claim is permanently consumed even if the QW reads
all `0xFF`. Only EOP plus a fresh attributed clean readback records a clean
role; it is not a lifetime-retention proof. Initial commitment requires the
selected full clean threshold and exact durable `COMPLETE`. Post-`COMPLETE`
maintenance remains `Steady(T)` while one authoritative copy exists;
ambiguity becomes `Unknown`, never a lower floor.

`FROZEN-ROUTE1-1` below fixes the two physical pages, page-region ownership,
domain separators, copy-on-write activation rule, current-boot launch-
authority rule, and the finite plan of three initial replicas plus one
replacement.
`OPEN-OTP-1..3` and `OPEN-ECC-1` still govern the inner codec payload
serialization, OTP role codewords, group/completion and accepted-binding
encodings, MAC/plain choice, key storage, fresh-read mechanics, and
demonstrated usable capacity. Fake/scripted backends may implement the frozen
interface; no physical epoch-bump writer is production-eligible until every
named open and silicon gate closes.

### OPEN-OTP-1: OTP physical record format

Choose between MAC-authenticated records and a simpler plain-record format only
after the sacrificial-silicon master-closure test in Section 13. Both options
MUST use:

- a one-shot completeness/antichain encoding—such as target plus complement,
  domain, role, and structural check, or a formally equivalent code—such that
  no strict erased-to-target 1→0 programming prefix can decode as any valid
  floor record for `T` or `V != T`;
- every valid role codeword MUST clear at least one data bit from erased `1`
  to `0`; an all-`0xFF` role payload is invalid, the writer MUST reject it,
  and erased bytes can never constitute a committed role;
- independently programmed physical replicas under a reviewed group/threshold
  protocol; a single-QW committed floor is not production-eligible; and
- a combined floor/stage decoder that tolerates the promised number of rejected
  replicas without ever returning a lower floor, returns bound `Recovering`
  only for one fully validated completable in-progress stage, returns
  `Aborted` only for the exact terminal proof in `FROZEN-OTP-API-3`, and
  otherwise returns `Unknown`/halts.

The codec MUST distinguish the initial completion threshold from the allowed
post-commit degraded threshold. A new target is not committed in an already
degraded state: its durable stage reaches `COMPLETE` only after the full
required clean replica set is EOP-verified. Only after that completion may the
decoder tolerate the reviewed number of later replica failures. Loss,
rollback, or ambiguity of the completion evidence halts rather than lowering
`F`.

"Highest committed group" means the newest group whose approved full initial
clean threshold and durable `COMPLETE` evidence were established. It excludes
every reserved, claimed, writing, replacement, or otherwise in-progress
frontier group. A valid durable completable stage is `Recovering`; a valid
pre-`COMPLETE` stage whose immutable finite plan is provably exhausted is
`Aborted`; neither is promoted to a committed floor. Missing, invalid,
rolled-back, conflicting, or ambiguous stage/completion evidence that prevents
proving one class is `Unknown` and halts.

The codec and durable-stage design MUST maintain a global, non-aliasing
physical-cell ownership partition. At every decode, each reserved rollback QW
is exactly one of: canonical virgin; one distinct role in one committed group;
one distinct role in the single active group; one role in a permanently
quarantined dead-stage plan; durably consumed/quarantined; or an
invalid/unknown condition that halts. The decoder MUST scan every reserved QW;
any nonblank or non-clean QW not owned by the authenticated chain is an orphan
and yields `Unknown`. One QW index may not appear twice in a quorum, in two
groups, as both source and replacement, or as both consumed/quarantined and
writable. Quorum cardinality counts distinct physical QWs, not record entries.
No capacity outside the single authenticated plan is reserved.

Every stage and `COMPLETE` record MUST bind a fixed codec/domain, the exact
prior committed-group identity and digest (or canonical `BASE0`), `prior_f`, a
monotonic allocation generation/cursor, target and active-group identity,
candidate/manifest identity, accepted-manifest binding,
abort-chain/release-watermark where present, and the full ordered map from physical QW indices
to replica/claim/replacement roles. Replaying a stage against a later prior
floor, generation, cursor, candidate, group, or ownership map is `Unknown`.
Completion, replacement, journal compaction, and recovery MUST preserve
permanent consumed/quarantined ownership, including a launched-all-`0xFF` cell
and every failed-plan role owned by an aborted plan. Neither recovery nor
repair may make an old stage current or a used index virgin. Route 1 uses the
pairwise-disjoint bank-1 pages 64 and 122; manifests, images, fallback state,
runtime journals, keys, and all other persistent owners remain outside those
erase units.
After exact authoritative `COMPLETE`, optional close/compaction is maintenance,
not a new epoch-advance recovery. It MUST preserve at least one old
authoritative completion copy and `Steady(T)` until a disjoint replacement is
fully durable. It never returns the epoch-advance `Recovering` class; loss or
ambiguity of all authoritative completion evidence is `Unknown`.
The Route-1 owner may not borrow a manifest, image, fallback, counter, key,
reserved, or FSBL page. Any geometry change is a separately reviewed flag day.

A MAC may additionally authenticate virgin-cell writes against an unclosed
master, but it does not replace deterministic torn-write structure, replica
health, or the ECCC rules. `FROZEN-ROUTE1-1` fixes three initial replica roles,
one distinct replacement, three clean replicas for initial `COMPLETE`, and a
two-clean-replica threshold only after commitment. `OPEN-OTP-1` still selects
the role codewords, inner snapshot/group/completion/accepted-binding
serialization, MAC/plain construction, and resulting physical capacity.

### OPEN-OTP-2: rollback-key storage, if MAC records are retained

The research prototype's single page-126 rollback-key record is rejected as a
default. Page 126 already has an independent wrapped-BHK lifecycle in the
current product design and MUST NOT silently acquire a second owner. A final
MAC design must identify non-conflicting storage and specify redundancy, ECC
failure behavior, WRP/HDP/SECWM factory receipts, recovery policy, and the
exact impact of a lost key.

Under a MAC-record design, a fully blank, ECC-clean rollback-record region plus
the synchronized active factory `BASE0` Route-1 pair decodes to the logical
base `Steady(0)` without reading or possessing the MAC key, provided the
approved durable-intent mechanism also proves that no reservation, stage, or
writer launch may be missing or active. Erased-looking Route-1 pages never
substitute for that pair.
A blank, lost, or corrupt MAC key therefore MUST NOT by itself brick an
otherwise valid `F = 0` genesis/same-floor boot; it prevents a future
authenticated commitment. If any rollback cell is nonblank, ambiguous, or
already contains a record, an unavailable key fails closed rather than
treating the region as blank. Devices with a nonzero durable floor still
depend on the approved redundant-key design.

This keyless `F = 0` behavior is runtime recovery semantics, not an acceptable
factory-provisioning state. If the MAC codec is selected, the production ship
receipt MUST prove that the approved redundant rollback-key material is
present, integrity/KAT-valid, and readable under final protections even while
the rollback-record region is fully blank. A factory image with missing,
blank, single-copy, corrupt, or unreadable required key material is NO-GO.

### OPEN-OTP-3: interrupted-cell authority and durable intent

The OTP backend must specify how every attempted physical QW is classified
across system reset and complete power loss. RM0456 does not permit visible
erased data alone to prove that an interrupted QW remains programmable;
`FLASH_OPSR` may identify a system-reset interruption but disappears across
complete power loss.

Every boot scans each candidate record through the `OPEN-ECC-1` fresh-read
primitive. A QW whose read raises matching `ECCC` contributes zero clean-
replica/quorum weight, is never considered virgin, and is never itself used as
the floor witness. It is not simply skipped if doing so would expose an older
floor: the decoder may return the same target only from the approved remaining
clean-replica threshold. If that QW belongs to the highest committed group and
the threshold is lost, the result is `Unknown`, never an older floor. If it
belongs only to one valid in-progress frontier, it receives zero weight and the
decoder recomputes the complete authenticated finite plan. It returns bound
`Recovering` only while a legal planned action sequence can still establish the
full clean threshold and exact `COMPLETE`; exact mathematical exhaustion plus
all `DeadStageProof` predicates returns the state-appropriate `Aborted` variant;
every other recovery, ownership, stage, or completion ambiguity is `Unknown`.
`ECCD`, malformed, structurally incomplete, and
retention-unstable frontier records follow the same no-downgrade rule. `ECCC`
clear is necessary for a clean replica but is not proof of retention margin.

An exact-looking authorized `T` in a QW whose program may have been
interrupted is not a settled acceptance path and contributes zero authority or
quorum weight. Clean pre-cut replicas remain usable only when the durable stage
proves their completion. Separately selected-route-authorized replacement QWs may be written
after recovery, but the logical target is established only after the resulting
full clean initial-threshold group receives a fresh durable `COMPLETE` stage
under an approved ordered protocol in which:

- the complete required clean-replica set was established before lower-epoch
  retirement;
- no possibly interrupted or corrected QW contributes to the accepting quorum;
- later rejection of the promised number of replicas still yields `T` from
  independent clean witnesses; and
- an incomplete group returns bound `Recovering` only while one unambiguous
  durable stage proves a legal completion path; exact terminal exhaustion with
  no possible completion-authority launch returns `Aborted`, and every other
  threshold/stage/completion ambiguity returns `Unknown` rather than a lower or
  attacker-chosen floor.

A launched-but-visibly-all-`0xFF` QW after complete power loss is currently
indistinguishable from virgin state. This specification claims no write-free quarantine
construction and does not assume finite board sampling can prove that physical
class absent. `OPEN-OTP-3` may close only through one of these reviewed routes:

1. a crash-consistent durable pre-claim/cursor, committed before each OTP
   launch on the `T > F` path, which reserves the exact QW across complete
   power loss and is itself safe across torn writes, replay, runtime tampering,
   and a second power loss;
2. authoritative STM32 retention/programming guarantees, corroborated on exact
   silicon, that rule out the marginal all-`0xFF` class or supply an equally
   reliable discriminator—finite sacrificial-board sampling alone cannot
   prove lifetime absence; or
3. treating field epoch-bump programming as a ship blocker.

#### FROZEN-ROUTE1-1: two-page copy-on-write launch journal

Route 1 owns exactly bank-1 page 64 at `0x0C08_0000` and bank-1 page 122 at
`0x0C0F_4000`. Each 8-KiB page is one complete 512-QW snapshot. In synchronized
steady state the two active copies represent the same canonical logical
snapshot. A direct predecessor pair is a temporary copy-on-write recovery
state, not a second logical log; neither page is a delta log and neither may
borrow another erase unit.

| QWs, inclusive | Frozen owner |
|---|---|
| 0–7 | snapshot header |
| 8–19 | prior accepted-artifact binding |
| 20–31 | candidate-artifact binding |
| 32–35 | committed-group state |
| 36–43 | active finite stage |
| 44–75 | complete 32-entry OTP-QW ownership map |
| 76–79 | snapshot summary |
| 80–505 | reserved; MUST remain erased `0xFF` |
| 506–507 | 32-byte page digest |
| 508–509 | bitwise complement of that digest |
| 510 | footer, programmed after the body |
| 511 | activation, programmed last |

The exact ASCII domain bytes are `PQJ1SNP\0` for a snapshot, `PQJ1LOG\0` for
the authenticated logical chain, `PQJ1HASH` for the page digest,
`PQJ1FTR\0` for the footer, and `PQJ1ACT\0` for activation. The canonical
predecessor of the first snapshot is `SHA-256("PQJ1BASE")`. The page digest is
`SHA-256("PQJ1HASH" || bytes(QW[0..=505]))`; QWs 508–509 carry its full
bitwise complement. Footer and activation encodings bind that digest, the
nonwrapping snapshot generation, target, exact next OTP index, and role under
their respective domains. Their inner field serialization, and that of QWs
0–79, remains `OPEN-OTP-1`; an implementation may not change the frozen QW
ownership ranges or domain bytes.

A page is active only when every required body, digest, complement, footer,
and activation read is durably clean under `OPEN-ECC-1`, all reserved QWs are
erased, and every binding verifies. Canonical `BASE0` is a synchronized pair
of active generation-zero snapshots provisioned under the Section-7.4 factory
boot hold. Field decode never treats erased-looking Route-1 pages as `BASE0`.

On recovery, two different active pages are usable only when the newer is
exactly one nonwrapping generation after the older and its authenticated
predecessor is the older snapshot digest. The newer valid snapshot governs. A
single active page also governs when the other is erased, torn, corrected, or
otherwise inactive. This is ordinary activation-last copy-on-write: positive
state in a durably-clean active snapshot is authoritative, while an inactive
or torn newer write leaves the older active preclaim authoritative. The full
OTP scan and ownership map still reject a stale snapshot that omits a nonblank,
corrected, or claimed cell. Any generation rollback, non-predecessor pair,
ownership loss/alias, conflict, or absence of one valid active state is
`Unknown`. Recovery observations never construct OTP launch authority.

Before **every** physical OTP-QW program, FSBL MUST, during the same boot:

1. derive one next-generation preclaim snapshot binding the target, QW index,
   role, codeword, finite plan, complete ownership map, and predecessor;
2. erase and freshly verify page 64 while page 122 retains the prior active
   snapshot, then program page 64 body-first, digest/complement, footer, and
   activation-last, observe EOP, and freshly decode it;
3. only after page 64 is active, erase and freshly verify page 122, program the
   identical logical snapshot in the same order, observe EOP, and freshly
   decode it;
4. freshly decode and compare both complete pages again, in that boot, as the
   same active generation and logical preclaim; and
5. only then mint one boot-local `OtpLaunchAuthority` for that exact
   `(generation, target, QW index, role, codeword)`.

The two current-boot erase/program/verification receipt chains are constructor
inputs. Persisted bytes alone never reconstruct `OtpLaunchAuthority`. It is
private, non-`Copy`, non-`Clone`, nonserializable, and consumed by exactly one
program attempt.

Every normal post-launch clean/consumed outcome, `COMPLETE`, accepted-binding
update, close, and compaction snapshot uses the same sequential copy-on-write
order. An active newer snapshot is the commit point; an inactive/torn write
leaves the older active snapshot authoritative.

A cut while rewriting page 64 leaves page 122's prior snapshot authoritative;
a cut after page 64 activates leaves that newer preclaim authoritative while
page 122 is old or incomplete. Because OTP launch authority is unavailable
until both new copies are freshly verified in one boot, the first case proves
no new launch, while the second conservatively persists the new claim. A reset
after both copies activate—before, during, or after the OTP transaction—loses
the volatile authority and classifies the claimed QW as may-have-launched and
nonvirgin even if it freshly reads all `0xFF`. Recovery from one active page or
a valid direct-predecessor pair MUST retain the governing active page and
rewrite the missing, inactive, or older page first to the exact same generation
and logical snapshot. It may not erase the governing page or derive a different
OTP preclaim until the pair is synchronized. This recovery order is deliberately
the reverse of the normal page-64-then-page-122 order when page 64 is the newer
governing copy. Convergence grants no OTP launch authority. Only afterward may
a different unclaimed role start a new generation and repeat the full current-
boot receipt chain. Thus a second power loss cannot erase a claim or authorize
retry of its QW.

The finite target plan has three distinct initial replica roles and one
distinct replacement role. Initial `COMPLETE(T)` requires three distinct
freshly clean replicas. The replacement may substitute for at most one failed
initial role before `COMPLETE`; no fifth replica role or later field plan may
be allocated. After `COMPLETE`, the committed group may degrade to two clean
members. If the full initial threshold is no longer reachable, the decoder
returns `Aborted` only with the complete `DeadStageProof`; otherwise it returns
`Unknown`.

After the one-time offline factory `BASE0` provisioning, no Route-1 erase,
program, activation, close, or compaction is permitted for any field path with
`T == F`. TAMP alone does not survive backup-domain loss, and an OTP-resident
claim would recurse into the same interruption uncertainty.

#### FROZEN-OTP-PROGRAM-1: one-operation nonsecure transaction

STM32U585 OTP programming requires a nonsecure bus transaction. The private
FSBL writer therefore consumes one `OtpLaunchAuthority` to open one bounded
transaction for its internally bound absolute OTP address and 128-bit
codeword. No caller supplies an arbitrary address, index, or value, and no
runtime or NSC command exposes the operation.

Before entry, all independent masters and interrupts capable of interfering
with the transaction MUST be quiesced or locked under the selected master-
closure configuration. The window may execute only the reviewed single-QW
program sequence; it closes and restores the reviewed attribution state before
ordinary nonsecure firmware executes. On return, FSBL captures program status,
closes the window, and applies the fresh attributed read/EOP classification.
Reset, fault, non-return, or ambiguous status consumes the authority and leaves
the QW may-have-launched; that index is never retried.

The exact trampoline/register mechanism and master-lock receipts remain
silicon-gated by Sections 13.1–13.4. Until those tests pass on explicitly
authorized sacrificial parts, real OTP programming remains a nonproduction
backend; only fake/scripted implementations may satisfy this interface.
Nothing in this freeze authorizes an OTP write or exposes the OTP alias to the
normal nonsecure runtime.

Route 2 remains only a contingent alternative if an authoritative STM32
guarantee supplies an equivalent discriminator. Finite board sampling,
ECCC-clear readback, or exact-looking bytes cannot close it. Route 3 remains a
ship blocker, not a same-epoch-only shipping profile. Factory genesis with
`E > 1` is subject to the same selected-route and `OPEN-OTP-1..3` closure
before it can program a nonzero floor.

Under every route, a possibly launched QW is never programmed again, a partial
state cannot decode as a valid record, and a degraded frontier can neither
create an unauthorized high floor nor make a committed floor disappear. The
durable stage, completion evidence, full ownership scan, and dead-stage
quarantine remain required; no later field epoch plan or renewable capacity is
available after `Aborted`.

On each boot the decoder returns exactly one result from
`FROZEN-OTP-API-3`: `Steady`, fully validated completable `Recovering`,
fully validated terminal `Aborted`, or `Unknown`. Recovery must reach fresh
`Steady(T)` before ordinary candidate admission. `Aborted` permits the robust
exact-`F` fallback plus the zero-floor-write repair paths
and never enters ordinary epoch-bump admission. No slot boots from
`Recovering` or `Unknown`.

Every codec candidate freezes a finite attempt plan per replica role, maximum
consumed/interrupted attempts, stage/completion records, cumulative quarantine,
and exact terminal predicate. Begin is permitted only when the complete cost
fits. Recovery allocates nothing outside that plan. If no-completion-launch and
dead-stage ownership cannot survive a second power loss, the backend is
production-ineligible. Missing or apparently erased completion bytes are not
proof. After `Aborted`, no new `T > F` capacity is allocated; service or a
separately reviewed future architecture is required to restore epoch-advance
ability.

### FROZEN-HLT-1: dedicated local signing self-test key

The local health suite uses an install-specific health-only C10 key and exact
domains:

```text
HEALTH_KEY_DOMAIN = b"pqsigner/fw-health-key/v1"
HEALTH_SK_DOMAIN  = b"pqsigner/fw-health-sk/v1"
HEALTH_PK_DOMAIN  = b"pqsigner/fw-health-pk/v1"
HEALTH_MSG_DOMAIN = b"PQFW_HEALTH_MSG_V1"

health_seed = HMAC-SHA512(
    key = bip39_seed,
    data = HEALTH_KEY_DOMAIN || physical_slot_u8 || R_be_u32 || E_be_u32 ||
           install_id[16] || signed_manifest_digest[32])

health_sk_seed = SHA256(HEALTH_SK_DOMAIN || health_seed[0..32])
health_pk_seed = SHA256(HEALTH_PK_DOMAIN || health_seed[32..64]) & N_MASK

health_message = SHA256(
    HEALTH_MSG_DOMAIN || physical_slot_u8 || R_be_u32 || E_be_u32 ||
    T_be_u32 || install_id[16] || signed_manifest_digest[32] ||
    boot_session_nonce[32])
```

The exact production C10 parameters are used. One installation permits exactly
one FI-hardened health signing operation, meaning the existing mandatory two
primitive sign computations over this one message plus comparison and
verify-before-release; it is not a wallet or firmware-vendor launch budget.
The signature never leaves secure SRAM and is zeroized with `health_seed`,
both derived seeds, key material, and message after verification or any error.
No health key, signature, or intermediate is returned to NS or the companion.

The key/message domains, inclusion order, slot/install binding, and per-boot
nonce structurally separate this transcript from firmware manifests, wallet
bootstrap/slot keys, and off-chain signing. Tests substitute every field and
cross-verify each health signature against firmware-vendor, wallet-bootstrap,
wallet-slot, and differently bound health public keys; every cross-domain case
must fail. Reinstalling after a false negative creates a fresh `install_id` and
therefore a distinct key.

### FROZEN-HLT-2: human challenge presentation and retry bound

The device samples four independent uniform BIP-39 word indices from secure
TRNG and renders their canonical five-character prefixes using the shared
measured-boot word substrate. This supplies 44 raw challenge bits. One session
permits at most three syntactically valid, constant-time comparisons against
the same challenge, giving online-guess probability at most `3 / 2^44`
(less than `2^-42`). Malformed frames do not consume a comparison but count
against the total command budget.

A wrong entry displays the remaining try count and leaves the same challenge,
session, host nonce, and absolute deadline bound. USB reconnect/rebind may
resume only that same session. It cannot generate a new challenge, accept a new
host nonce, or extend time. Three wrong entries, user cancel, or session loss
terminates probation and requires PIN-gated reinstall/re-arm. No challenge or
derivable value is returned to NS/host before the human types it.

### FROZEN-TIME-1: probation deadlines and command budgets

The normal trusted PIN screen retains its existing secure 120-second inactivity
timeout; no firmware-probation health deadline starts before successful PIN
unlock. At that success tick the local-health deadline is fixed at 60 seconds.
On creation of `LocalHealthPassed`, a separate transport/finalization deadline
is fixed at 300 seconds. The final trusted-display long-confirmation must
complete inside that same 300-second deadline.

Per session, at most eight `HEALTH_BEGIN` frames, eight
`HEALTH_COMPLETE` frames, three syntactically valid challenge comparisons, and
32 total probation gateway frames are processed. Exact duplicate begin or
post-success complete responses count against those budgets. Malformed input,
NS traffic, heartbeat changes, USB disconnect/reconnect, and retries never
reset or extend either absolute secure monotonic deadline. Expiry or budget
exhaustion produces a distinct trusted-display reason and the common clean
revert/reset path; it never hangs or confirms. These values are frozen software
policy. Hardware timing evidence may require a longer value under a new
reviewed digest, never an implicit build-time override.

### OPEN-REL-1: production release-policy authority

The monotonic `(R,E)` and advisory-to-epoch decisions require an authoritative
production signing ledger. The current optional per-user/XDG signing log is not
an authority boundary. Before any production signing implementation is
approved, the project must select the protected ledger, signing-service/HSM
gate, atomic A/B release-set ceremony, trusted checkpoint/publication model,
and exact human approval required to classify a release as same-epoch-safe.
Tooling can enforce recorded decisions; it cannot prove that an advisory list
is complete or that a code change is not security-relevant.

The publication identity bound by the finalized record MUST be an externally
assigned, immutable, namespace-unique canonical identifier (or other
independently rooted value) and MUST NOT be the hash of that same finalized
record. It may be assigned before finalization but may not be reused after an
aborted reservation. The ledger schema and package hash graph must remain
acyclic; neither a bundle nor any field needed to hash the finalized record
may recursively depend on the finalized-record hash.

### OPEN-C10-1: immutable vendor-key launch budget

The exact maximum number of C10 signing operations permitted under one
physical firmware-vendor key is not selected by this draft. The cap is global
across every manifest domain, product namespace, abandoned/partial ceremony,
test artifact, and slot-specific artifact that uses that same key; it is not a
per-device or per-release-ledger allowance. The C10 security review must freeze
the numeric cap before production key provisioning and before implementation
of the signing authority. Milestone 0 records the number and its counting and
archival rules; no implementation may silently inherit `65,536` from an
unrelated wallet-key budget.

---

## 4. Threat model and trust boundaries

### 4.1 Trusted components

- Byte-identical complete FSBL copies, including the embedded vendor key,
  protected on physical banks 1 and 2 by WRP1A/WRP2A pages 0–4 plus the
  reviewed BOOT_LOCK/SWAP_BANK/SECWM/HDP factory configuration.
- Vendor C10 firmware-signing public key embedded in the FSBL.
- STM32U585 TrustZone hardware and correctly burned production option bytes.
- Secure-world trusted display and physical buttons.
- Hardware PIN policy in the OPTIGA, SE050, and MCU attempt-state convergence.
- Correct C10 verification and hash implementations within their reviewed
  assumptions.
- The vendor-signed secure-world runtime, specifically its inactive-slot
  updater, probation-health/finalization verifier, TAMP writer, and ordered
  two-replica `CandidateFinalizationWriter`, is trusted not to act deliberately maliciously or
  intentionally subvert the protocol. It is not assumed bug-free or FI-immune:
  the failure model, typed evidence, duplicate checks, and reset paths are
  intended to contain crashes, accidental bugs, malformed untrusted inputs,
  and faults within their stated models. Arbitrary secure-runtime code
  execution or a maliciously signed secure image can rewrite secure state,
  forge the runtime-owned confirmation replicas, or corrupt the fallback and is
  outside this architecture's guarantee.

### 4.2 Untrusted components

- Nonsecure firmware, including a compromised NS image.
- USB framing and companion-facing NS transport.
- Desktop/mobile companion software.
- Host operating system and USB port.
- All data delivered through NSC until copied and validated in secure world.

### 4.3 Failure model

The mechanism must safely handle:

- a validly signed but buggy firmware release whose failure manifests before
  completion of the defined probation boundary; post-boundary residuals are
  scoped in Section 9.7;
- crashes before, during, and after secure initialization;
- malformed manifests and journal words;
- power loss at every flash or OTP transition;
- torn flash and OTP programming;
- exact-looking but retention-uncertain inactive-slot image or manifest-body
  lines after an interrupted pre-PENDING write; no field or factory attempt
  resumes them, and every retry fully erases/restages the affected slot ranges;
- retention/aging degradation of previously accepted manifest-marker or OTP
  cells, including later `ECCC`, `ECCD`, or unreadable observations. A degraded
  terminal set leaves the artifact as a repair-target classification only; it
  grants no boot, admission, or floor authority;
  a degraded floor group is usable only at its approved
  redundant clean threshold. Otherwise loss of all terminal
  authority makes only that slot ineligible (an independently eligible slot
  may still boot), while
  loss of authoritative floor state yields `Unknown` and halt. Neither case
  returns an older floor or newly infers confirmation;
- a missing, unresponsive, or incompatible companion;
- a malicious NS or companion attempting to confirm without the human-bound
  trusted-display challenge;
- bounded single-event fault assumptions only where a later reviewed FI stage
  states the exact model.

The minimum core does not claim resistance to invasive silicon attacks, an
attacker holding the vendor signing key, or deliberately malicious/arbitrarily
compromised vendor-signed secure runtime. This explicit exclusion does not
weaken the required fail-closed handling of a validly signed but accidentally
buggy release throughout the defined probation boundary.

An older correctly vendor-signed artifact in the current `security_epoch` is
also not an attacker forgery. If it is restored after a newer same-epoch slot
is erased, corrupted, or otherwise absent, the immutable floor permits it.
That is the deliberate cost of amortizing scarce OTP writes. Every release
process, product claim, and recovery test must treat one epoch as a rollback-
equivalence class.

---

## 5. Fixed flash geometry and immutable resource budget

STM32U585AI flash uses 128 physical 8-KiB pages per 1-MiB bank. The following
registry assigns every one of the 256 pages exactly one owner, including when
the owning feature is disabled:

| Physical bank | Pages | Address range (end exclusive) | Owner / capacity |
|---|---:|---|---|
| bank 1 | 0–4 | `0x0C00_0000..0x0C00_A000` | complete FSBL, 40,960 B |
| bank 1 | 5 | `0x0C00_A000..0x0C00_C000` | manifest A, 8,192 B |
| bank 1 | 6 | `0x0C00_C000..0x0C00_E000` | manifest B, 8,192 B |
| bank 1 | 7–63 | `0x0C00_E000..0x0C08_0000` | secure slot A, `0x72000` B |
| bank 1 | 64 | `0x0C08_0000..0x0C08_2000` | Route-1 rollback launch-journal page A |
| bank 1 | 65–121 | `0x0C08_2000..0x0C0F_4000` | secure slot B, `0x72000` B |
| bank 1 | 122 | `0x0C0F_4000..0x0C0F_6000` | Route-1 rollback launch-journal page B |
| bank 1 | 123 | `0x0C0F_6000..0x0C0F_8000` | off-chain/UserOp journal |
| bank 1 | 124 | `0x0C0F_8000..0x0C0F_A000` | MCU PIN-attempt state |
| bank 1 | 125 | `0x0C0F_A000..0x0C0F_C000` | admin-wipe/duress state; old admin-PIN owner retired |
| bank 1 | 126 | `0x0C0F_C000..0x0C0F_E000` | wrapped SE050 BHK only |
| bank 1 | 127 | `0x0C0F_E000..0x0C10_0000` | first-boot provisioning journal + TRNG salt record (Section 6.3 `FirstBootJournalWriter`) |
| bank 2 | 0–4 | `0x0810_0000..0x0810_A000` | byte-identical complete FSBL mirror, 40,960 B |
| bank 2 | 5–65 | `0x0810_A000..0x0818_4000` | nonsecure slot A, `0x7A000` B |
| bank 2 | 66–126 | `0x0818_4000..0x081F_E000` | nonsecure slot B, `0x7A000` B |
| bank 2 | 127 | `0x081F_E000..0x0820_0000` | reserved/retired-page owner; must remain erased |

The shared geometry crate, both linker families, updater, FSBL, signer,
inspector, extraction tool, QEMU model, and host tests MUST consume this one
registry. Compile-time and host checks enumerate all 256 pages, reject every
gap/overlap/second owner, and reject legacy manifest/boot-state constants.
There is no current boot-state role: the physical page formerly assigned that
role is bank-1 page 6 and its sole current owner is manifest B. Reserved and
retired roles remain explicit page owners rather than ownerless gaps.

An update may erase/program only the inactive manifest page and the inactive
secure/nonsecure slot ranges. It MUST preserve both complete FSBL copies,
both Route-1 rollback launch-journal pages, bank-1 pages 123–127, and bank-2
page 127. Bank-2 pages 0–4 are never part of an NS slot or updater allowlist,
even before protection is burned. Bank-1 pages 64 and 122 are a symmetric,
pairwise-disjoint, FSBL-owned erasable journal pair; they are never image
capacity, updater scratch, manifest space, or runtime-owned persistent state.
Bank-1 page 127 is the first-boot ceremony's commit-LAST append-only
provisioning journal (one 512-QW page, fail-closed on exhaustion) including
its TRNG salt record; the Tropic01-key reservation formerly assigned here was
retired with that backend's removal on 2026-07-14. Bank-2 page 127 remains
nonsecure/reserved under the frozen SECWM design;
neither may be borrowed for rollback intent.

Every newly authenticated field-update BEGIN creates a fresh staging attempt
by erasing and verifying the complete inactive manifest page and **every page**
of that inactive slot's full secure and nonsecure capacity ranges above before
accepting any image chunk. It does so even when all bytes look erased or a
prior attempt appears complete. The attempt identity is volatile and is lost
on reset; therefore any reset, watchdog event, or complete power loss before
exact durable PENDING forces the next authorized BEGIN to repeat the complete
inactive-range erase and fully restage both images and the manifest. No
pre-PENDING image/body byte is resumable across reset. This conservative rule
is the durable generation discriminator for image/body programming and avoids
treating exact-looking interrupted lines as retention-clean. An erase that is
itself interrupted is corrected only by the next full page erase/verification,
never by accepting its readback as an installed byte.

The FSBL linker region MUST remain exactly 40,960 bytes. It MUST NOT be expanded
over Manifest A.

Both physical-bank FSBL copies MUST be byte-identical over all 40,960 bytes,
including vector table, code/rodata, initialized data LMA, padding, SG veneers,
and the embedded vendor public key. The production protection target is:

```text
WRP1A: PSTRT=0, PEND=4, UNLOCK=0
WRP2A: PSTRT=0, PEND=4, UNLOCK=0
```

The factory receipt also freezes and reads back `TZEN`, `BOOT_LOCK`,
`SWAP_BANK=0`, `SECBOOTADD0`, and the selected symmetric SECWM1/2 and HDP1/2
coverage. WRP is burned before RDP2. On explicitly authorized sacrificial
parts, cold-reset receipt testing must prove both ranges remain locked and
negative program/erase attempts on each physical copy produce the expected
protected-write failure. These are OPEN factory/silicon gates; current tooling
does not satisfy them, and this document authorizes no burn.

The current implementation baseline still contains the legacy 32-KiB FSBL,
old manifest/boot-state pages, 64-page NS capacities, non-slot-specific linker
origins, and legacy updater ranges. Migration to this registry is one atomic
software change: no intermediate build may mix old and new constants, and no
option-byte transition is attempted by the nonshipping implementation phase.
Every old geometry constant is a negative-test input. The authoritative FSBL
size metric is the physical initialized `PT_LOAD` span from the immutable
origin, never Berkeley `text + data`.

For the clean core:

- final on-flash FSBL use MUST be at most 38,912 bytes;
- the measurement MUST use release flags and a real-size vendor public key;
- the authoritative metric is initialized FLASH load span from the FSBL origin
  through the last loaded byte (for example,
  `max_i(p_paddr_i + p_filesz_i) - ORIGIN` over FLASH-mapped `PT_LOAD`
  segments, `max_j(section_LMA_j + section_file_size_j) - ORIGIN`, or a
  linker-defined `__flash_image_end`), not a sum that omits alignment gaps or
  separately loaded sections;
- `.vector_table`, `.text`, `.rodata`, embedded vendor key, `.data`, and any SG
  stubs, loadable padding/alignment, and data LMA MUST all be counted;
- an overflow is a hard design failure, not a test waiver;
- prefix-4 fingerprint compression MAY be considered later only as an
  independently reviewed optimization, never as an implicit pressure valve.

FLASH fit is necessary but not sufficient. The current FSBL also has a 16 KiB
transient secure-SRAM linker envelope shared by static data and MSP stack.
`OPEN-RAM-1` must freeze the final transient geometry, authoritative static
end/span, worst-case stack margin, and guard policy. Every combined candidate and final
build must pass both the physical FLASH LOAD-span gate and the RAM/stack gate;
neither resource may be traded for removal of a load-bearing check.

The frozen research worktree is not a size-valid implementation: its release
FLASH load span was reproduced at exactly 42,212 bytes, overflowing the 40,960-byte
region by 1,252 bytes. The dominant measured contributors include the 10,240-
byte five-character BIP-39 prefix table, SHA-256, C10 verification, rollback
logic, and an estimated 3--5 KiB aggregation of FI/complement/sentinel code.
That aggregation is not wholly removable headroom: trust-root signature,
digest, rollback, and handoff checks retain their reviewed sentinel/double-
evaluation layer, while only the broader per-callsite/remanence expansion is
deferred. This evidence motivates the staged exclusions; it does not prove
that removing them makes the clean core fit. Only a fresh production-profile
link at or below 38,912 bytes satisfies this specification. A four-character
BIP-39 table may save 2,048 bytes but remains a separately reviewed UI/
measurement-format change.

The independently reviewed base-27 packed five-character table is now an
isolated commit on the software branch. It replaces the 10,240-byte table with
6,144 bytes and measures 28,316 bytes of initialized FSBL sections, a
28,320-byte physical LOAD span, and a 4,024-byte net physical saving after
decoder growth. The 32-byte vendor-key section is included. Exhaustive
all-2,048-entry round-trip, uniqueness, bounds, constant-time-scan equivalence,
golden-grid, clean-build reproducibility, and FSBL/secure-world display-parity
tests passed. This is a reviewed dependency, but it is not the completed
rollback core. The final combined production-profile FSBL must still satisfy
the 38,912-byte limit with real vendor-key material.

The arithmetic `42,212 - 4,024 = 38,188` is illustrative cross-worktree,
mixed-metric arithmetic only. It is not a measured combined ELF, a projected
final size, or 724 bytes of usable headroom below the 38,912-byte target. The
research image retains rejected journal/single-QW machinery and over-broad FI
while the packed baseline lacks the final manifest-v6, fresh-ECCC,
replica-group, completion/replacement, and possible durable-intent machinery;
LTO makes those deltas non-additive. No security or layout decision may rely
on that subtraction.

As an early-warning checkpoint for the live resource NO-GO, once each
materially distinct journal/codec/durable-intent family has concrete interfaces
but before destructive Section-13 work or detailed production-shared
implementation, the project MUST produce a nonshipping combined FSBL warning
build for that family. It uses one frozen source/toolchain/linker/profile,
links every then-available real component together, and represents each still-
unimplemented immutable component with an explicitly documented conservative
size/RAM reservation derived from an isolated measurement or padded link
reservation. The report applies the Section-5 FLASH and `OPEN-RAM-1` metrics,
lists every placeholder and uncertainty, and gives a range rather than
presenting an estimate as a final ELF.

This checkpoint is an actual combined link/resource experiment, not the
cross-worktree subtraction above. A result already exceeding 38,912 bytes or
the candidate RAM/stack envelope triggers an immediate simplify/defer/layout-
review decision before more expensive work. A passing warning build neither
selects a backend nor satisfies Section 12.6: every final viable combination
still needs its complete production-equivalent combined build and all security
and silicon evidence.

Draft 0.9 records that warning experiment as **AMBER**, not green. Against one
frozen nonshipping source/toolchain/profile, the padded proxy was reduced from
a 40,268-byte physical LOAD span to 38,860 bytes: 52 bytes below the warning
line and 2,100 bytes below the immutable 40 KiB ceiling. The useful isolated
changes and security dispositions are recorded in
`docs/security/fw-rollback-fsbl-resource-map-2026-07.md`. Its corrected known
deepest interruptible stack path is 7,896 bytes after renderer de-inlining,
with provisional remaining RAM of 2,084 bytes in the low reservation scenario
and 1,060 bytes in the high scenario. The 2 KiB FLASH and 512-byte BSS pads are
still placeholders; 52 bytes is within LTO/toolchain noise. Therefore this
result de-risks but does not pass the final FLASH/RAM gate, select an OTP
codec, or create authority to delete further checks. The expanded full-SRAM/
GPR scrub omission was measurement-only and must be restored or replaced by an
independently reviewed remanence defense before production.

The AMBER proxy implements Draft-0.8-era research logic plus explicit
reservations; it is not an implementation of the current Draft-1.1 manifest-
v6, five-QW lifecycle, paired terminal replicas, robust/degraded evidence,
fresh-ECC, replicated-floor, single terminal `Aborted`, no-floor repair, and
durable-stage semantics. Draft 1.1 provisionally
freezes its abstract interfaces only for the limited nonshipping implementation
authorized by Milestone 0; that freeze is permission to build and measure, not
evidence of resource fit or backend selection. Production selection and final
interface eligibility for any candidate journal/codec/durable-intent
combination are contingent on its complete Section-12.6 combined build proving
FLASH and `OPEN-RAM-1` fit. If fit requires any load-bearing semantic,
interface, margin, or layout change, work on that candidate MUST stop and the
changed specification MUST receive a new digest, both exact reviews, and owner
approval before continuation. The
physical linker ceiling is 40,960 bytes: exceeding it is an unconditional
layout failure. The 38,912-byte line is the reviewed warning/final-core target
that reserves 2 KiB of immutable FLASH headroom; exceeding that line, even
while still linking below 40,960 bytes, does not satisfy this draft without an
explicit owner/reviewer re-freeze of the margin policy. The same build must
pass `OPEN-RAM-1`. Neither the 38,860-byte proxy nor any placeholder range may
stand in for that build or authorize backend selection, a production-shared
physical writer, production eligibility, or silicon work. Limited nonshipping
implementation authority comes only from Milestone 0.

---

## 6. Signed manifest and journal representation

### 6.1 Signed preimage

Draft 1.1 re-freezes a flag-day 8,192-byte manifest-v6 page. All integer fields
are big-endian:

| Offset | Size | Field | Frozen rule |
|---:|---:|---|---|
| 0 | 4 | magic | exact ASCII `PQSF` |
| 4 | 1 | schema | exact `0x06` |
| 5 | 1 | physical slot | `0x00=A`, `0x01=B`; must match containing page |
| 6 | 2 | header reserved | exact zero |
| 8 | 4 | `release_version` | `1..=0xFFFF_FFFE` |
| 12 | 4 | `security_epoch` | `1..=0xFFFF_FFFE` |
| 16 | 4 | secure image length | at least 8; within frozen slot capacity |
| 20 | 4 | nonsecure image length | at least 8; within frozen slot capacity |
| 24 | 32 | secure image SHA-256 | exact signed image binding |
| 56 | 32 | nonsecure image SHA-256 | exact signed image binding |
| 88 | 32 | vendor-key fingerprint | signed `SHA-256("PQFW_VK_V6" \|\| pk_seed[16] \|\| pk_root[16])` of the immutable embedded verifying key; must equal a fresh recomputation from those key bytes |
| 120 | 32 | build ID | unsigned, non-authoritative correlation metadata |
| 152 | 32 | manifest digest | exact freshly recomputed digest below |
| 184 | 4008 | C10 signature | signature over the 32-byte manifest digest |
| 4192 | 16 | `QW_PENDING` | QW index 262; CRC-normalized |
| 4208 | 16 | `QW_CONFIRMED_0` | QW index 263; first terminal replica; CRC-normalized |
| 4224 | 16 | `QW_INSTALL_ID` | QW index 264; device-generated per-install 128-bit identity; CRC-normalized |
| 4240 | 16 | `QW_INSTALL_ID_INV` | QW index 265; exact bitwise complement; CRC-normalized |
| 4256 | 16 | `QW_CONFIRMED_1` | QW index 266; second terminal replica; CRC-normalized |
| 4272 | 3916 | trailing reserved | exact `0xFF` through offset 8187 |
| 8188 | 4 | normalized CRC-32 | IEEE/zlib CRC, stored big-endian |

Implementations MUST compile-time pin every offset, `SIGNATURE_LEN == 4008`,
all five journal offsets modulo 16, `184 + 4008 == 4192`, and
`OFF_CRC32 == MANIFEST_SIZE - 4`.

The signing domain and preimage are exactly:

```text
MANIFEST_VERSION    = 0x06
DOMAIN_TAG          = b"PQFW_V6"       // exact 7 bytes
VENDOR_FPR_DOMAIN   = b"PQFW_VK_V6"    // exact 10 bytes
SIGNED_PREIMAGE_LEN = 121

DOMAIN_TAG[7] || schema_u8 || physical_slot_u8 || release_version_be_u32 ||
security_epoch_be_u32 || secure_image_length_be_u32 ||
nonsecure_image_length_be_u32 || secure_image_hash[32] ||
nonsecure_image_hash[32] || vendor_key_fingerprint[32]
```

`manifest_digest = SHA256(preimage)`. FSBL MUST verify C10 over a freshly
recomputed digest. The stored digest is a redundant comparison value, never an
independent signing authority. Slot A and slot B artifacts for one logical
release-set carry identical `(R,E)` and policy identity but are independently
signed for their physical slot and their slot-specific image hashes.

FSBL verifies only with the immutable embedded firmware-vendor C10 public key.
The signed fingerprint is an equality check against that key's freshly
recomputed fingerprint; it is never a key selector, key locator, rollover
instruction, or authority to load key bytes from the manifest. Firmware-vendor
C10 private/public key material and derivation domains are distinct from every
wallet bootstrap, wallet slot, and health-only C10 key. No wallet seed or key
can authorize a firmware manifest.

The frozen digest fixture is:

```text
slot = 01
R = 01020304
E = 05060708
secure_hash = 000102...1f
nonsecure_hash = 202122...3f
secure_len = 00001000
nonsecure_len = 00002000
vendor_key_fingerprint = 404142...5f
digest = fb0f51ff0ad21bf02a15041dbaa2728e
         a10b6a7601753b15cb083ad212d61662
```

The normalized CRC is computed over bytes `0..8188` after replacing exactly
bytes `4192..4272` with 80 bytes of `0xFF`. It uses reflected IEEE polynomial
`0xEDB88320`, initial `0xFFFFFFFF`, final XOR `0xFFFFFFFF`, and is stored BE.
No raw-CRC call site is permitted. For the shared full-page fixture—golden
fields above, lengths `0x1000/0x2000`, FPR bytes `40..5f`, build-ID bytes
`60..7f`, signature byte `i mod 256` for zero-based `i=0..4007`, all five
journal QWs exact erased `0xFF × 16`, and all trailing reserved bytes `0xFF`—the
normalized CRC is `0x5F7DEB92` and finalized page SHA-256 is
`632e90f280c80ce6843aa5a5e679658295f3738b8ee27a058fb8baff3a44e25f`.

The valid lifecycle rows use
`install_id=808182838485868788898a8b8c8d8e8f` and
`install_id_inv=7f7e7d7c7b7a79787776757473727170`. The same fixture with only the normalized
journal window changed pins CRC normalization behavior explicitly:

| Journal bytes | Normalized CRC | Full-page SHA-256 |
|---|---|---|
| all five QWs erased (unstamped package only) | `5F7DEB92` | `632e90f280c80ce6843aa5a5e679658295f3738b8ee27a058fb8baff3a44e25f` |
| exact install pair + exact PENDING; both CONFIRMED replicas erased | `5F7DEB92` | `02aa62037bf01285f3a09cbbd1292f1995a1b3d21141a8af8dee528710d822be` |
| exact install pair + exact PENDING + `CONFIRMED_0`; replica 1 erased | `5F7DEB92` | `b10c7bdf879e5cce6abb8a20558e339d8023c2b04b1a11dc0032871b9d5e83d6` |
| exact install pair + exact PENDING + `CONFIRMED_1`; replica 0 erased (negative writer-order fixture) | `5F7DEB92` | `84738dd794722e9025341214410faeb2dfbe0f4e2794f80c13cc80e2fdbe4845` |
| exact install pair + exact PENDING + both CONFIRMED replicas | `5F7DEB92` | `e7f9b80d21d0a24cf3a84ec76a2b62cd19c6f22464515039c7ea77fa198a8db6` |

These values were independently reproduced with separate Python/zlib and
Node.js bitwise CRC implementations. A production test must derive them
through the shared Rust manifest code and cross-check at least one independent
implementation; merely copying this table is not evidence.

The `i mod 256` signature pages above are serialization, normalization, and
journal fixtures; they are not a valid C10 signature KAT and MUST NOT be
reported as one. Foundation A MUST add a separately labeled, checked-in,
key-matched positive manifest-v6 fixture using a dedicated nonproduction C10
key, its exact public-key fingerprint, signed images, manifest digest, 4,008-
byte signature, and expected successful shared-verifier result. Its receipt
binds the fixture-file hashes. Negative fixtures cover wrong key, one-bit
signature corruption, domain/schema/slot substitution, tuple changes, length/
image-hash changes, and legacy-format retry. The patterned fixtures remain
unchanged.

The all-erased row is the canonical **unstamped release-package
serialization**. It is not a device `BlankVirgin` proof: package bytes carry no
operation history, ECC attribution, or physical-page generation. Every
incoming release bundle MUST contain raw `0xFF x 16` in all five journal QWs
and is rejected if any contains PENDING, CONFIRMED, an install identity, or any
other value even though normalized CRC would otherwise ignore it. The inactive physical manifest may
hold an old CONFIRMED or malformed generation. An authorized update first
erases the whole inactive page, establishes a new physical generation, then
programs body/CRC and eventually PENDING; it never treats package all-`0xFF`
as permission to reuse a possibly launched physical QW.

Under the frozen 40-KiB FSBL layout, secure length is at most `0x72000` and
nonsecure length at most `0x7A000`. Vector words and every reset-handler target
must lie inside the corresponding signed-hash range `[base, base + len)`, not
merely somewhere in slot capacity. Both lengths and the vendor-key fingerprint
are direct signed preimage fields and are independently range/equality checked;
they are not trusted merely because the stored header contains them.
`build_id` remains unsigned and is never displayed or consumed as trusted
provenance; only the protected external release ledger may authenticate or
cross-check it. The release namespace is keyed by the actual embedded vendor
key identity, never by an unverified header string.

Journal bytes are device-mutated and are the only CRC-normalized range. Every
manifest **installation/stamping body writer**, including field secure runtime
during inactive-slot installation and the offline factory stamper, MUST erase
the complete destination manifest page and process body QWs
`0..261` plus CRC QW `511` with the same algorithm. It programs a processed QW
exactly once only when that QW's canonical package value is not all-`0xFF`; a
canonical all-`0xFF` immutable-body QW remains physically erased under proof of
the fresh whole-page generation and is recorded as an intentional skip. It
issues no immutable-body program command to journal QWs `262..266` or all-
`0xFF` reserved QWs `267..510`. An intentionally skipped immutable-body QW is
ordinary signed/CRC-covered data, not a `BlankVirgin` journal proof and not
permission for any later in-generation write. Every installation writer
generates and durably programs the install-identity pair before arming or
PENDING; the field writer then programs `QW_PENDING` only after body/CRC/
install-identity verification and exact TAMP arming. The factory follows
Section 7.4's offline identity-then-PENDING-then-CONFIRMED order. An erased-
looking read without the new-generation operation history is never permission
to program an all-`0xFF` QW.

This is a true flag day: FSBL accepts only schema `0x06` and domain `PQFW_V6`,
never assigns a default epoch, never translates legacy offsets, and never
retries a v1/v2/v3/v4/v5 signature under v6. Bench devices are reflashed and factory
genesis is provisioned directly in v6. The exact bytes and shared fixtures
MUST be common to firmware, fwsign, inspector, factory/updater, extraction,
formal models, and host tests.

### 6.2 Logical states and frozen composite software encoding

The manifest codewords are exact 16-byte values:

```text
QW_PENDING =
12 34 56 78 9A BC DE F0 ED CB A9 87 65 43 21 0F

QW_CONFIRMED_0 =
AA 55 99 66 F0 0F C3 3C 55 AA 66 99 0F F0 3C C3

QW_CONFIRMED_1 =
5A A5 96 69 3C C3 F0 0F A5 5A 69 96 C3 3C 0F F0
```

Each has 64 programmed zero bits and a second half equal to the bitwise
complement of the first. Every pairwise Hamming distance is at least 64 and each is
distance 64 from erased. Only an exact full-QW read attributed as ECC-clean
**and durably clean** by `OPEN-JRN-DUR-1` is valid. Torn, `ECCC`, `ECCD`, an
exact-looking may-have-launched result, or any other ambiguous observation is
not a valid marker.

Each fresh manifest-page generation also carries a device-generated 128-bit
`install_id` in `QW_INSTALL_ID` and its exact 128-bit complement in
`QW_INSTALL_ID_INV`. Secure installation/factory tooling obtains `install_id`
from the approved secure RNG only after the whole-page erase; it never accepts
the value from a package, NS, companion, or unsigned header. It rejects and
resamples all-zero or all-one values so both QWs require a real program
operation. A `FullInstallGeneration` requires two durably-clean exact reads,
exact complementarity, and neither forbidden value. A
`SurvivingInstallGeneration` may reconstruct the same identity from exactly
one independently durable, clean, nontrivial half only after PENDING or
terminal evidence proves that the activation writer reached the later
lifecycle step; the missing half contributes no authority and any conflicting
exact value rejects the generation. A lone identity half before activation is
incomplete, not an installed artifact. The pair is programmed once, before
TAMP binding/PENDING, and never retried in place. A torn, corrected, ambiguous,
repeated, or may-have-launched half has zero independent weight. Unless the
surviving-generation rule above applies, the generation is invalid and
requires a later authorized complete inactive-range erase/restage in the
field (and the same affected-slot full-range restart under offline factory recovery).
Its 128-bit collision bound and
durability are part of `OPEN-JRN-DUR-1`; no production authority is claimed
before that gate closes.

The one global arm token occupies exactly TAMP `BKP8..31`; `BKP0..7` remain
the exclusive 32-byte BHK allocation:

| Register(s) | Frozen value/meaning |
|---|---|
| `BKP8/9` | magic `0x4152_4D33` (`ARM3`) and `0xBEAD_B2CC` |
| `BKP10/11` | physical slot code and complement |
| `BKP12/13` | `R` and `!R` |
| `BKP14/15` | `E` and `!E` |
| `BKP16/17` | `T` and `!T` |
| `BKP18..25` | binding hash as eight big-endian u32 words |
| `BKP26/27` | seal `0x1357_9BDF` and `0xECA8_6420` |
| `BKP28/29` | seal `0x2468_ACE0` and `0xDB97_531F` |
| `BKP30/31` | state and state complement |

This table is the single authoritative backup-register allocation for the
rollback design. It supersedes roadmap-only proposals that placed a VBAT
canary, dirty-shutdown flag, diagnostic counter, or resume state in `BKP8..31`.
Those features must use another reviewed resource or be deferred; they may not
alias the token. A build-time allocation registry/test MUST reject every
second owner of `BKP0..31`. If ES0499 mitigation requires an in-bank CRC or
canary, this 24-word token layout must be redesigned and re-reviewed rather
than silently sharing a word.

Slot codes are `A=0x3C3C_A5A5`/`0xC3C3_5A5A` and
`B=0x9696_6969`/`0x6969_9696`. State pairs are:

```text
INVALID   = (0xA5A5_A5A5, 0x5A5A_5A5A)
ARM_READY = (0x3C3C_3C3C, 0xC3C3_C3C3)
ATTEMPTED = (0x9696_9696, 0x6969_6969)
```

Each valid state pair is Hamming distance 32 from either other pair. Reset
`(0,0)` and every one-word transition intermediate are invalid.

The binding is exactly:

```text
ARM_TOKEN_DOMAIN    = b"PQFW_A3"       // exact 7 bytes
PIN_BUDGET_STATE    = b"CLEAN10"       // exact 7 bytes
ARM_TOKEN_PREIMAGE  = 139 bytes

domain[7] || physical_slot_u8 || R_be_u32 || E_be_u32 || T_be_u32 ||
install_id[16] || signed_manifest_digest[32] || secure_hash[32] ||
nonsecure_hash[32] || PIN_BUDGET_STATE[7]
```

For the Section-6.1 golden fixture, exact install identity above, and
`T=0x05060707`, the binding digest is
`b8efdef828957f09689c6af0b74b73028a0a00214db4f2a00ac1792136c9ba2f`,
stored as numeric words `B8EFDEF8 28957F09 689C6AF0 B74B7302 8A0A0021
4DB4F2A0 0AC17921 36C9BA2F`.
The decoder independently requires exact complements/magic/seals/slot code,
`R,E` in `1..=0xFFFF_FFFE`, checked `T == E - 1`,
`T <= 0xFFFF_FFFD`, the physical slot match, and a recomputed binding to a
fully verified manifest plus state-appropriate `InstallGenerationEvidence`.
The initial writer must program both halves; after PENDING or terminal
activation, one missing half may contribute only through the qualified
`SurvivingInstallGeneration` rule and must not be proven `BlankVirgin`, because
the later lifecycle write proves both ID writes should have launched. Both
missing halves, conflicting halves, or a lone half before activation are
invalid. The decoder never trusts a companion-supplied digest or generation
value.

In this table, `BlankVirgin` means an exact-index, ECC-clean all-`0xFF` read
plus proof from immutable-entry operation status and the approved journal state
that no program may have launched for that QW. `DurablyCleanExact` means the
exact codeword plus the still-open durability proof required by
`OPEN-JRN-DUR-1`. An ECCC-corrected all-`0xFF` value is neither blank nor
virgin.

Every artifact has one stable physical-generation identity, while proofs from
one verification transaction share a private boot-scoped join key:

```text
ArtifactIdentity =
    physical_slot || manifest_page_start || pending_qw_address ||
    confirmed_0_qw_address || confirmed_1_qw_address || install_id || R || E || T ||
    signed_manifest_digest || secure_image_hash ||
    nonsecure_image_hash

ArtifactEvidenceKey =
    ArtifactIdentity || boot_evidence_epoch || verifier_pass_id ||
    attributed_ecc_receipt_set_digest
```

Only the immutable decoder/verifier may construct this key. `install_id` is the
value reconstructed by valid `FullInstallGeneration` or qualified
`SurvivingInstallGeneration`, not a companion nonce or unsigned header field.
`verifier_pass_id` is a private, nonserializable token allocated
once for one bounded immutable verification transaction and unique within its
`boot_evidence_epoch`; it is not parsed from flash or supplied by mutable code.
Each exact-index manifest, journal, install-identity, image, vector, and
handoff read still owns its distinct attributed `FreshQwRead` receipt. After
every read required by the artifact/lifecycle proof finishes, the verifier
seals the complete canonical address-ordered receipt set together with the
single immutable-entry `FLASH_OPSR` snapshot into
`attributed_ecc_receipt_set_digest` and issues all artifact/lifecycle proofs
for that transaction together. Sharing this aggregate key never reuses one
QW's ECCC/ECCD observation at another index or leaves image/vector evidence
outside the joined pass.
Any later read, mutation, or verification attempt requires a new pass ID and
new aggregate receipt set; proofs from the two passes cannot join. Such a
recheck compares the stable `ArtifactIdentity` fields and then constructs a
new current-pass key—it never claims equality with the old ephemeral key.
`VerifiedArtifact`, PENDING/ATTEMPTED evidence, and `TerminalSet`
for one artifact in one pass each carry the
exact same key. A wrapper containing a candidate and fallback carries two
distinct artifact keys, one per physical artifact. Proof
constructors are private, boot-scoped, neither `Copy` nor `Clone`, and cannot
be serialized. No cross-slot, cross-address, cross-image, cross-snapshot, or
old/new-generation join is defined, even when `(R,E,T)` happens to match.

Accepted authority is typed:

```rust
enum AcceptedArtifact {
    RobustAccepted(RobustConfirmedEvidence),
}

enum RobustConfirmedEvidence {
    RobustTerminalSet(FullTerminalSet),
}
```

`FullTerminalSet` requires two independently attributed durably-clean exact
terminal replicas. `SurvivingTerminalSet` requires exactly one such replica;
the other has zero authority and MUST NOT be a conflicting exact codeword. A
`CONFIRMED_1` replica with `CONFIRMED_0` proven `BlankVirgin` is an impossible
writer-order state and rejects the artifact; a later unavailable or rejected
replica is different from proven-never-launched virgin state. Each terminal
proof comes only from terminal-first fresh probes and carries the exact
`ArtifactEvidenceKey`.

The decoder accepts exactly:

| Logical state | terminal probes / authority | PENDING and TAMP | Floor relation |
|---|---|---|---|
| `UNINSTALLED` | both `BlankVirgin` | PENDING `BlankVirgin`; token ignored | n/a |
| `PENDING(R,E)` | both `BlankVirgin` | PENDING exact; token exact `ARM_READY` | `E > F` |
| `ATTEMPTED(R,E)` | both `BlankVirgin` | PENDING exact; token exact `ATTEMPTED` | `E > F` |
| robust `CONFIRMED(R,E)` | exact `FullTerminalSet` | not read; non-authoritative | `F <= T` |
| degraded `CONFIRMED(R,E)` | exact `SurvivingTerminalSet` | not read; non-authoritative | `F == T`; repair target only, never boot/floor |
| degraded epoch candidate | exact `SurvivingTerminalSet` | not read; non-authoritative | `F < T`; repair target only, never boot/floor |

Every artifact-bearing row requires state-appropriate nontrivial
`InstallGenerationEvidence` for the same reconstructed identity used by its
`ArtifactEvidenceKey`; a fully erased raw package/page is not an eligible
`UNINSTALLED` artifact. Before activation only `FullInstallGeneration` is
valid. After PENDING or terminal evidence, a qualified single survivor is
permitted only under the rules above; a missing half proven virgin is an
impossible writer-order state. The `UNINSTALLED` row describes a verified
newly installed body/full identity before activation.

The terminal-first decoder fresh-probes both terminal QWs before considering
PENDING/TAMP. For probation it reads PENDING/TAMP only after both terminal QWs
are proven `BlankVirgin`. A torn, corrected, may-have-launched, conflicting,
or impossible-order terminal observation never falls through to PENDING. A
surviving terminal replica is accepted only as degraded repair-target
evidence; it never constructs boot or floor authority and never exposes an
older floor.

Every other combination—including a missing/malformed/binding-mismatched token
on the probation branch, out-of-order marker, out-of-range `R/E`, or
`F > T`—is `MALFORMED` and ineligible.
Before terminal authority, token loss is a safe false negative. After terminal
authority, the token and historical PENDING marker confer no authority. Raw
exact bytes never construct these types; TAMP retention is not a security
assumption.

The only legal transition chain within one slot-installation generation is:

```text
UNINSTALLED --runtime COMMIT--> PENDING
PENDING     --immutable FSBL--> ATTEMPTED
ATTEMPTED   --full HEALTH_PASS + user finalization--> CONFIRMED_0
CONFIRMED_0 --independent durable receipt-----------> CONFIRMED_1
CONFIRMED   --immutable FSBL--> establish F := security_epoch - 1
                                     (no OTP write when already equal)
```

Manifest journal words are never erased or rewritten in place. `MALFORMED` has
no marker-only outgoing transition. A slot starts a new installation generation
only when it is inactive and a later independently authorized update erases
its complete manifest page. The TAMP token is rewritable backup-domain state;
its exact one-way logical transition is enforced by FSBL software, not by an
immutable per-register hardware lock. This design therefore trusts
vendor-signed secure privileged runtime not to deliberately rewrite the token,
consistent with the existing trust placed in that runtime not to forge
`CONFIRMED` or corrupt the fallback. That limitation MUST remain explicit.

The production protection target is exact
`TAMP_SECCFGR.BKPRWSEC=32`, `BKPWSEC=32`, `TAMPSEC=1` and
`TAMP_PRIVCFGR.BKPRWPRIV=1`, `BKPWPRIV=1`, `TAMPPRIV=1`. With TrustZone
enabled, all 32 backup registers are then zone-1 secure read/write and
privileged; `BHKLOCK` additionally makes only `BKP0..7` software-inaccessible,
so `BKP8..31` remain usable by secure privileged journal code. These literal
settings, plus `PWR_SECCFGR.VBSEC=1` and `PWR_PRIVCFGR.SPRIV=1` when the
retained-MONEN route is selected, are the software target, not a silicon
receipt. The archived production errata receipt MUST also include the ES0499
item titled **"PWR_BDCR1 is not write-protected by DBP"**; clearing `DBP`
does not protect retained `MONEN`, so `VBSEC`, privilege restriction, and
readback are load-bearing. `OPEN-JRN-HW-1` must
prove final write/read denial, ES0499 cold-boot sanitation, and BHK coexistence
before production. Complement pairs and the 256-bit binding make ordinary
corruption fail closed, but they do not substitute for that erratum workaround
or justify trusting unpredictable backup-domain retention.

### 6.3 Writer ownership and ordering

Logical authorization is split into disjoint compile-time mutation maps. The
shared SRAM capsule in `FROZEN-FLASH-MUT-1` is only a physical executor; it
cannot invent an address and accepts exactly one linear checked operation from
one of these owners:

- `UpdaterWriter` owns only the inactive manifest/body, inactive secure and
  nonsecure image ranges, fresh install-identity pair, bound `ARM_READY`, and
  one PENDING QW. It cannot address the running slot, rollback journals, OTP,
  terminal replicas, or pages 123--127.
- `FsblProbationWriter` owns only bound `ARM_READY -> ATTEMPTED` TAMP words.
- `CandidateFinalizationWriter` owns only the two terminal QWs derived from
  trusted running-slot identity and frozen geometry. It consumes one
  `RuntimeFinalizationReceipt`, writes replica 0 then replica 1, and resets.
- `FsblRollbackWriter` owns only Route-1 pages 64/122 and the exact checked OTP
  QW/record named by a fresh recovery or establishment capability. It cannot
  address manifests, images, TAMP, or runtime-state pages.
- Existing `RuntimeStateWriter` families retain their separately typed page-
  123/124/125/126 allowlists and cannot construct any rollback mutation.
- `FactoryGenesisWriter` is an offline, build-gated exception limited to the
  exact Section-7.4 ceremony; it is absent from field images.
- `FirstBootLockWriter` owns exactly one operation: the confirm-gated
  `RDP = 0xCC` option-byte program plus `OBL_LAUNCH` of the first-boot lock
  ceremony (`docs/provisioning/first-boot-requirements.md` R2.1--R2.6). It
  performs no flash/OTP/journal write and programs no option byte other than
  RDP, runs only pre-Phase-B, and is fenced to production builds at compile
  time against debug-log, e2e-test, and mock-SE profiles. It is reachable only
  after the R2.1--R2.4 verify + physical-confirm chain; classification after
  any interruption is by option-byte read-back only, never by remembered
  intent; failure parks the device. With this entry the lock ceremony needs no
  bypass of the frozen mutation boundary; every other option-byte writer
  remains bench/factory-host-only tooling, never device firmware.
- `FirstBootJournalWriter` owns exactly two operations of the first-boot
  ceremony (`docs/provisioning/first-boot-requirements.md` R3.x/R4.x):
  (a) commit-LAST append-only quad-word programs into the bank-1 page-127
  provisioning journal, and (b) the journal-gated erase-and-reprogram of the
  page-126 wrapped-BHK page (anti-pre-plant). It cannot construct any
  rollback, manifest, image, TAMP, OTP, or other runtime-state mutation. It
  runs only during the first-boot ceremony before `ALL_DONE`; classification
  after any interruption is by journal re-scan and read-back only, never by
  remembered intent; a full journal fails closed to RMA with no further
  write; and it is fenced to production builds at compile time against
  debug-log, e2e-test, and mock-SE profiles. Operation (b) is a full-page
  erase sequenced against a record on a different page — a two-page protocol
  the `RuntimeStateWriter` page-126 allowlist does not express — so this
  writer is its sole typed owner.

Each map is generated from the one geometry registry and checked twice with
address/complement and range/owner equality immediately before entering SRAM.
No raw address, manifest field, TAMP body, NS buffer, companion input, or
generic flash helper can select a destination. Compile-fail and post-link tests
prove that no owner can construct another owner's operation. No NS command or
other code path may perform these writes.

All BHK and arm-token accesses MUST use one reviewed secure/privileged backup-
domain transaction owner. It may set `PWR_DBPR.DBP` only for the bounded write
sequence, MUST fail closed if set/readback does not succeed, then MUST clear
and verify DBP cleared before handoff or NS execution.
Current research helpers that set DBP and leave it set are nonconforming and
cannot be reused unchanged. Every `TAMP_SECCFGR` read-modify-write preserves
`BHKLOCK`, counter-security fields, and all unrelated reserved/configuration
bits. If ES0499 sanitation forces `BDRST`, FSBL treats the token as lost and
uses that loss only on the probation branch after both confirmation replicas
are proven `BlankVirgin`: the PENDING/ATTEMPTED candidate becomes ineligible and an
independently verified confirmed fallback may boot only when the floor decoder
is `Steady` or supplies the exact constrained `Aborted` authority. A valid
terminal set ignores the token, while `Recovering` and `Unknown` still forbid
fallback. The reset also erases `BKP0..7` and `BHKLOCK`, so the later mutable
secure boot reloads BHK from its separately protected wrapped record before any
BHK-derived operation. On an ordinary retained-VBAT reset, boot validates the
exact retained BHK/`BHKLOCK` state rather than assuming it was cleared or
attempting to overwrite locked `BKP0..7`.

Field COMMIT ordering is:

An ordinary update reaches this ordering only through its authenticated staging
session. `PeerRepair` and
`DegradedArtifactRepair` each use their separately typed staging-only receipt
from Section 3. After complete inactive-range restage, a private validator
consumes the completed session, freshly reconstructs the required floor/source/
package/slot/high-water evidence, and creates exactly one activation receipt.
Every activation path also consumes a fresh `CleanPinBudget`. No staging or
activation receipt authorizes CONFIRMED, floor/Route-1/OTP mutation, handoff, or
another slot.

1. install and verify inactive images and immutable manifest body/CRC without
   issuing a program command to a journal or erased-reserved QW, with every
   write inside the Section-5 inactive-slot allowlist;
2. consume `CleanPinBudget` and bind exact `CLEAN10`, installation, candidate,
   robust fallback/source, manifest digest, and boot/session into this
   activation;
3. write `BKP30` then `BKP31` to exact `INVALID` and construct a private
   writer-local `InvalidatedToken` after two stable reads; `BKP8..29` remains
   opaque until rebuilt;
4. generate fresh nontrivial `install_id`, program `QW_INSTALL_ID` then
   `QW_INSTALL_ID_INV` once, and obtain independently attributed durable-clean
   validation of both; any interruption requires later full restage;
5. write `BKP8..25` with the complete new binding body;
6. write body seals `BKP26..29` last within the body;
7. read and validate the body twice, including fresh `PQFW_A3`/`CLEAN10`
   binding recomputation;
8. write `BKP30` then `BKP31` to exact `ARM_READY`;
9. read and validate the complete token twice;
10. program `QW_PENDING` last and perform its immediate diagnostic ECC-clean
    readback; and
11. consume/zeroize all update authority and reset without releasing wallet or
    NS authority.
A reset/rebooted update never resumes COMMIT. The volatile staging attempt is
discarded and the next authorized BEGIN performs Section 5's complete inactive-
range erase/restage before generating a new install identity. Within one
uninterrupted attempt, a pre-ID failure proven to have launched no ID program
may abort without activating the slot; once either install-ID program may have
launched, any error likewise terminates the attempt and only full erase/restage
may retry. A stale exact `ARM_READY` with `QW_PENDING` `BlankVirgin` never
authorizes resume. Thus a byte-identical erase/reinstall receives a new identity
and cannot join old lifecycle or accepted-manifest evidence.

FSBL arming ordering is:

1. construct and consume exactly one of `CheckedSteadyProbationIntent`,
   `CheckedPeerRepairIntent`, or
   `CheckedDegradedRepairIntent`, requiring exact PENDING plus bound
   `ARM_READY`, `CLEAN10`, and the independently verified `RobustAccepted`
   exact-`F` fallback/source. Ordinary same-epoch and every repair path carry
   no rollback capacity receipt; only an ordinary epoch bump from `Steady`
   carries the fresh read-only one-plan preflight;
2. write `BKP30`, then `BKP31`, to exact `ATTEMPTED`;
3. exact-readback the complete token twice;
4. freshly decode the complete floor/stage state and reverify manifest, images,
   slot, exact-`F` fallback authority, the applicable read-only receipt/vector,
   and handoff binding; and
5. hand off only while the composite state is exact `ATTEMPTED` and the fresh
   floor class is the same bound `Steady(F)` or exact `Aborted` authority
   required by the consumed entry, with `T == F` on every repair/recovery path.

If the TAMP transition is interrupted, exact `ARM_READY` may retry because the
candidate has not run, but only after top-level redispatch constructs a new
state-appropriate checked arming intent from fresh evidence. Exact
`ATTEMPTED`, token loss, or any malformed token makes the probationary
candidate ineligible. An independently valid confirmed fallback is selected
only through a newly constructed ordinary `Steady(F)` exact-target no-write
intent or `CheckedAbortedAcceptedIntent`; no arming entry returns that
authority directly. `Recovering` dispatches only to checked recovery,
`Unknown` halts, and exact terminal confirmation ignores TAMP entirely.
Backup-domain reset or tamper erasure therefore cannot grant a second candidate
boot.

For every non-all-`0xFF` immutable body/CRC QW, install-identity QW, or
PENDING/CONFIRMED-replica activation QW that the frozen algorithm actually schedules
for programming, every manifest-flash writer MUST:

1. verify the destination quad-word is exactly erased;
2. program one complete quad-word using the documented STM32U585 sequence;
3. use bounded `BSY|WDW` waits;
4. avoid control/status writes after a stuck-busy timeout;
5. relock the relevant FLASH controller before returning or handing off;
6. invalidate relevant cache state;
7. exact-readback the complete codeword;
8. fail closed on ECC or disagreement.

Immediate EOP/readback is a local diagnostic only. It does not itself create
a valid install identity or logical `PENDING`/`CONFIRMED` authority across
reset. The next immutable boot decode must obtain `DurablyCleanExact` through
the eventual `OPEN-JRN-DUR-1` rule before using any of those five journal QWs.
If that rule requires any
persistent post-marker write, completion witness, or altered ordering, this
transition sequence and any affected manifest offsets/CRC normalization MUST
be re-frozen before implementation.

Exact erased readback is not sufficient if an install-identity or marker
program may already have launched. Once any of `QW_INSTALL_ID`,
`QW_INSTALL_ID_INV`, `QW_PENDING`, `QW_CONFIRMED_0`, or
`QW_CONFIRMED_1` programming is launched
or its launch status becomes ambiguous, no path may program that quad-word
again in the same slot-installation generation, even if it later reads all
`0xFF`.
`ATTEMPTED` prevents a candidate from retrying a torn confirmation. A later
authorized reinstall may reuse the physical location only after erasing and
restaging the complete inactive manifest page as a new generation.

Before NS runs, FSBL and secure boot MUST configure the token registers as
secure read/write, privileged where supported, preserve the disjoint BHK
allocation, and verify the configuration. BHK loading MUST preserve those
settings. The receipt MUST NOT call this an immutable TAMP lock: secure
privileged firmware remains able to reconfigure/write the registers.

Manifest pages and their flash-control path MUST likewise be secure and
privileged against NS CPU and NS bus-master programming, with production
readback/lock receipts. NS-side command filtering alone is insufficient.

### 6.4 Release-set and signing-policy authority

The on-device product namespace is exactly the pair `(domain = PQFW_V6,
embedded vendor-key fingerprint)`. That pair is exclusively assigned to
PQSigner OS STM32U585 firmware; no other product/family may sign under both the
same domain bytes and the same physical key. A different domain under a shared
key is counted by the global C10 budget but is cryptographically rejected by
this device's fixed preimage. Reusing the same pair for another product is a
key-ceremony/build-gate violation and requires a new manifest schema/domain or
dedicated key before signing. The external ledger keys its numbering namespace
by this exact pair; no unsigned product string creates a sub-namespace.
The embedded fingerprint is an equality check against the one compiled-in
vendor public key, never a key identifier, lookup selector, or alternate-key
dispatch input.

Production signing MUST use one canonical, protected,
append-only policy ledger with two atomic stages:

1. a pre-sign reservation containing at least `(R,E)`, the preceding tuple,
   source/build-request hashes, release classification, advisory identifiers,
   explicit same-epoch-safety or epoch-bump approval, and a hash link to the
   preceding trusted record; and
2. a finalized release-set record binding both slot-specific signed manifests,
   exact image/package hashes, manifest schema/domain, the pre-sign reservation
   record hash, and publication identity. The finalized record is created only
   after both complete bundles exist; no bundle embeds the hash of this final
   record, avoiding a package/record hash cycle.

The production signer MUST fail closed if that record is absent, malformed,
stale, or inconsistent. It MUST enforce:

- `R` is strictly increasing over reservations within the namespace, not
  merely published releases; an abandoned signed/reserved number is never
  reused;
- `E` is nondecreasing as `R` increases; the separate
  `epoch_high_water` never decreases;
- an epoch bump is normally exactly `E_previous + 1`; a numeric skip needs
  explicit migration approval but still performs only one logical
  `commit_target(T)`; its physical cost is the selected codec's declared cost,
  not one quad-word per skipped epoch;
- reserving terminal `R = 0xFFFF_FFFE` requires an explicit product end-of-
  releases ceremony; reserving terminal `E = 0xFFFF_FFFE` requires an explicit
  irreversible anti-rollback-EOL ceremony because no later epoch can revoke a
  bad same-epoch artifact. Ordinary numeric-skip approval cannot authorize
  either terminal value;
- slot A and slot B are the sole same-`R` exception and form one atomic release-
  set with identical policy identity and `(R,E)`;
- exact republication uses only archived, byte-identical signed artifacts
  through a no-private-key replay path. If the archive is lost, any fresh
  signing invocation—whether deterministic like current software `fwsign` or
  hedged by a future HSM—requires a newly reserved `R`; and
- no production `--force`, operator-supplied floor target, or missing-ledger
  fallback exists.

An advisory fixed by a release and marked as requiring anti-rollback MUST
force an epoch bump. A same-epoch production request MUST affirm that every
earlier signed artifact in that epoch remains acceptable **if automatic
failure fallback becomes necessary**. This does not authorize demotion,
reinstallation, or lower-`R` selection except where the frozen evidence-
quality/tuple order independently prefers that artifact—for example, robust
authority over a newer degraded artifact.
Unresolved security impact defaults to review/block, not ordinary release.
The offline signer or HSM enforces the recorded decision before private-key
use; repository CI alone is insufficient if the signing key can bypass it.

OTP amortization does not make vendor-key usage unbounded. One complete A/B
release-set normally requires two distinct slot-bound C10 signatures. The key
custody system MUST maintain the reviewed per-physical-vendor-key signature-
release budget across every product/domain namespace that shares that key;
partial A-only or B-only ceremonies are durably counted even though nothing is
published. Archived republication consumes zero new signature operations. A
dedicated vendor key per immutable manifest domain is preferred; otherwise the
global key-use tally, not a per-product ledger, is authoritative. The numeric
launch cap remains a required C10 security-review input and MUST be fixed before
production key provisioning or signing.

New release bundles MUST carry canonical metadata containing `(R,E,T)`, slot,
schema/domain, source/build identity, advisory identifiers, the pre-sign
reservation-record hash, and image/manifest digests. Verification tools MUST
cross-check every duplicate field against signed bytes and the supplied policy
ledger. Device admission does not parse or trust this external policy metadata;
its authority is the vendor-signed `(R,E)` and image binding. Inspection
without a trusted ledger must label policy as unverified. Publication of the
complete A/B release-set is atomic, and duplicate critical archive entries are
rejected. A crash or failure after only one slot is signed publishes neither
slot and leaves `R` permanently reserved/burned.

---

## 7. Boundary-agnostic boot state machine

### 7.1 Candidate admission

Before parsing either slot for ordinary admission, FSBL obtains one typed
floor/stage result from the approved decoder:

- `Steady(F)`: either (a) the highest committed group has the required clean
  quorum or (b) the canonical logical base is proven as `F = 0` by a fully
  blank, ECC-clean record bank, the synchronized active factory `BASE0`
  Route-1 pair, and durable-intent state proving that no stage, reservation,
  claim, or writer launch may be missing or active. Erased-looking Route-1
  pages do not prove the base. No unresolved durable stage may change the
  interpretation. Only this state enters ordinary candidate admission and the
  Section-7.2 selector.
- `Recovering { prior_f, prior_group, allocation_generation, target,
  stage_binding, ordered_cell_roles, consumed_set }`: either the exact highest
  committed group or the canonical `BASE0` identity proves `prior_f`, while a
  separately validated durable stage proves an in-progress
  `target > prior_f`. The stage binds the codec/domain, exact prior-group
  identity/digest and floor, allocation generation/cursor, target and active
  group, candidate/manifest identity, complete ordered cell-role assignment,
  and attempted/consumed/quarantined sets required by the selected codec. FSBL
  MUST bypass ordinary admission, fallback selection, and handoff. The remaining
  plan is nonempty and mathematically completable. FSBL consumes the fresh
  `RecoveryProof`, proof-bound artifact, and exact `RobustAccepted` authority
  into `CheckedRecoveryIntent`; only that checked value reaches Section 10's
  recovery writer. A failed join yields
   `RecoveryBlocked(MissingRobustTerminalAuthority)` with no relabeling of the floor-
  only `Recovering` result and no writer/fallback/handoff. No slot is
  admitted until recovery completes and a fresh full scan returns
  `Steady(target)`.
- `Aborted(DeadStageProof)`: the prior floor remains authoritative, but one
  exact pre-`COMPLETE` stage has exhausted its immutable finite plan under the
  no-completion-launch proof in `FROZEN-OTP-API-3`. FSBL bypasses ordinary
  epoch-bump admission and invokes Section 7.2's exact-`F` selector. The failed
  candidate and its A/B twin are excluded. The proof may authorize the best
  robust exact-`F` accepted artifact, `PeerRepair`, or a
  same-floor degraded-artifact repair; it can never construct `T > F`.
- `Unknown`: the decoder cannot prove either a steady highest committed floor
  or one unambiguous recoverable/aborted stage. FSBL halts before either slot is
  admitted.

These are logical proof classes at the decoder/admission boundary, not four
new persistent journal states and not a mandate for a particular Rust enum or
additional flash record. An implementation may represent them more compactly
provided the behavioral distinctions remain explicit and testable.

An incomplete frontier is never the highest committed group. A valid
completable stage yields `Recovering`, while a valid mathematically dead stage
with proven no completion launch yields `Aborted`; neither is a misleading
plain `Steady(prior_f)`. Invalid, missing, rolled-back, multiply active,
target-inconsistent, orphaned, or completion-ambiguous evidence; loss of the
clean threshold for the highest committed group; or ambiguity about cell
ownership yields `Unknown`. The decoder never defaults to zero, maximum, or a
next-lower historical target.

The canonical base rule requires the synchronized active factory `BASE0`
Route-1 pair, a fully blank ECC-clean OTP bank, and proof that no establishment
writer may have launched. All-`0xFF` readback alone never reconstructs
`Steady(0)`, and erased-looking Route-1 pages never reconstruct `BASE0`. A
first epoch-bump stage may bind `prior_group = BASE0` only when that same
canonical proof was established before stage activation. A later exact
`Aborted` first-bump proof may expose unchanged `F=0` only through that
authenticated predecessor and a complete ownership/quarantine account of
every nonblank or uncertain QW; it does not reconstruct BASE0 from current
erased-looking bytes.

For physical slot `s` and rollback floor `F`,
`VerifiedArtifact(s, F, ArtifactEvidenceKey)` means all of the following
immutable-artifact checks independently pass under one current join key:

- manifest structure and normalized CRC;
- physical slot binding;
- signed digest binding;
- vendor-key fingerprint and C10 signature;
- exact full or narrowly surviving nontrivial install generation bound into the current
  `ArtifactEvidenceKey`;
- in-range `release_version` and `security_epoch` under Section 1.1;
- strict epoch rollback rule `security_epoch > rejected_through_epoch`;
- secure and nonsecure image lengths and hashes;
- vector-table and handoff bounds.

Lifecycle evidence is a separate typed result from the terminal-first Section-
6.2 decoder. A slot is `Verified(s, F, state)` only when
`VerifiedArtifact(s, F, key)` and the evidence appropriate to exactly that
state both hold **and carry a byte-for-byte equal `key`**:

- `PENDING`: both CONFIRMED replicas are proven `BlankVirgin`, PENDING is exact, and the bound
  TAMP token is exact `ARM_READY`;
- `ATTEMPTED`: both CONFIRMED replicas are proven `BlankVirgin`, PENDING is exact, and the
  bound TAMP token is exact `ATTEMPTED`;
- `CONFIRMED`: typed authority is `RobustAccepted` from both terminal replicas.
  A lone surviving replica is
  repair-target evidence, not boot or floor authority.

`UNINSTALLED` is not an eligible state. PENDING and ATTEMPTED never need or
receive confirmation evidence. This separation is normative even if an implementation
stores the artifact and lifecycle proofs in one compact handle. A proof from
the other slot, another image with the same tuple, a prior page generation, or
another boot/ECC snapshot cannot satisfy the join.

Invalid slots do not enter selection. Failure in one slot MUST NOT invalidate
an independently valid other slot.

Before any inactive-slot mutation, runtime constructs exactly one typed update
class. All classes require trusted running-slot identity, a
`RobustAccepted` source with exact `T_source == F`, the other physical slot as
destination, five erased package journal QWs, correct signed physical-slot tag,
a fresh `CleanPinBudget`, complete inactive-range erase/restage, fresh install
identity, and trusted-display approval of signed `(R,E)` and the derived
classification. If only degraded authority remains, no update class is
constructible.

Common admission scans both slots before erase and counts every independently
verified robust and degraded-repair-target artifact in the live
release/epoch high-water. The package and source are rebound after restage and
again before activation. The classes are:

1. **Ordinary update from `Steady(F)`.** Require `R_new` strictly above every
   live artifact `R`, `E_new` at least every live artifact `E`, `E_new > F`,
   and checked `T=E_new-1`. `T==F` bypasses every rollback backend call.
   `T>F` requires a fresh read-only receipt for exactly one complete finite
   establishment plan, including clean replicas, completion/accepted binding,
   interrupted-write replacements, quarantine retention, and Route-1 journal
   cost. Capacity shortfall rejects before erase.
2. **`PeerRepair` from `Steady(F)` or `Aborted(F)`.** Require the protected
   archived opposite-slot artifact of the robust source's exact logical A/B
   release set, identical `(R,E)` and policy/source identity, independent
   slot-bound signature/images, and `T=F`. This is the sole equal-`R` PENDING
   exception. It performs zero rollback-backend operations and cannot directly
   copy confirmation.
3. **`DegradedArtifactRepair`.** Require a robust source and the exact archived
   package matching the degraded target slot/artifact; count the degraded
   artifact in all high-water calculations and perform no in-place marker
   repair. Under `Aborted` it requires `T=F` and zero backend operations. Under
   `Steady` a repaired `T>F` artifact may enter only the ordinary one-plan
   establishment path after earning `RobustAccepted`; the repair itself has no
   floor authority.

Each class creates a private staging-only receipt bound to source, target,
package, floor class, high-water, and boot/session. After complete erase,
restage, and verification, a fresh class-specific validator consumes that
receipt plus the completed staging session and produces one activation receipt
for install ID, TAMP, and PENDING only. Reset destroys the chain. No receipt
authorizes CONFIRMED, floor state, Route-1 state, OTP, handoff, or another slot.

Every repair/recovery candidate traverses PENDING, one ATTEMPTED handoff,
Milestone 1, Milestone 2, trusted finalization, and both terminal-replica writes
before it is robust. Failure leaves the source accepted and the prior floor
class unchanged. An exact `ARM_READY` may retry only under the no-handoff
proof; `ATTEMPTED` never retries. A successful repair resets and later boots
through the ordinary `Steady` selector or
`boot_accepted_from_aborted` with no floor write.

The device does not authenticate or parse the external advisory ledger.
Release classification, `epoch_high_water`, and security-advisory completeness
are signer/HSM gates before vendor-key use. Device authority is the signed
tuple/images plus the exact current floor/dead/live high-water evidence.

After prerequisites pass, Section 5's full inactive manifest, secure-capacity,
and nonsecure-capacity erase starts a fresh volatile generation. Body/CRC/images
are programmed and reverified without touching either Route-1 page or another
persistent owner; class-specific activation then writes install identity,
TAMP, and PENDING last. A reset before durable PENDING discards the whole
attempt and the next authorized BEGIN repeats full erase/restage. Package
all-`FF` bytes and exact-looking interrupted image lines are never resume
authority.
### 7.2 Selection rules

Selection first filters every artifact through signature/image/slot checks,
`E > F`, lifecycle evidence, and the current floor class. Only
`RobustAccepted` artifacts are bootable; the total order among them
is `(E, R, slot-A-first)`. A degraded artifact is repair-target evidence and
is never bootable.

For `Steady(F)` the ordinary decisions are:

| Eligible set | Required decision |
|---|---|
| no accepted artifact and no qualified PENDING | halt |
| one or more robust accepted artifacts, no qualified PENDING | choose the robust total-order winner; idempotently establish its `T`, then boot only after fresh `Steady(T)` |
| robust exact-`F` fallback plus ordinary PENDING with `Rp>Rc` and `Ep>=Ec` | first establish/redecode the robust fallback's exact floor; then consume `arm_probation_from_steady` once |
| robust source plus exact `PeerRepair` equal-`R` PENDING | consume `arm_peer_repair`; no rollback write |
| robust source plus exact degraded-target repair PENDING | consume `arm_degraded_artifact_repair`; no repair-time rollback write |
| robust source plus any nonqualifying PENDING or any ATTEMPTED | ignore candidate and boot robust winner |
| no robust artifact remains | halt to service; expose no updater/probation/floor/fallback/repair authority |
| PENDING with no robust fallback/source | halt |

When two robust artifacts exist, higher `E`, then higher `R`, then slot A wins.
A preferred robust artifact with `T>F` enters Section 10. If the backend proves
that no reservation, claim, stage, completion, compaction, or OTP operation may
have launched and remains fresh `Steady(F)`, an independently robust exact-`F`
fallback may boot. After any possible establishment launch, no fallback or
handoff occurs until a fresh decode returns `Steady(T)` or exact `Aborted`;
`Recovering` resumes only its bound plan and `Unknown` halts. Post-`COMPLETE`
maintenance remains `Steady(T)` while an authoritative copy survives, otherwise
`Unknown`; it is never epoch-advance `Recovering`.

For `Aborted(DeadStageProof)`, FSBL excludes the failed release and its A/B twin
and rejects every `T>F` artifact or request before mutation/capability
construction. It accepts only:

- the best robust exact-`F` accepted artifact through
  `boot_accepted_from_aborted`, including a later fully probated
  peer-repair artifact;
- a qualified equal-`R` `PeerRepair` PENDING through `arm_peer_repair`;
- a qualified exact-`F` degraded-target repair PENDING through
  `arm_degraded_artifact_repair`.

With no robust exact-`F` artifact remaining, `Aborted` admits no new-release
path and FSBL halts to service.

An ATTEMPTED repair/recovery candidate is never handed off again; FSBL boots
the robust exact-`F` source when one exists. After a repair earns both terminal
replicas and resets, the persistent `Aborted` proof remains, but the new robust
exact-`F` artifact can boot through `boot_accepted_from_aborted`. Repair failure
or cancellation similarly leaves `Aborted` and the robust source unchanged.
Neither success nor failure renews epoch-advance capacity.

`UNINSTALLED`, `ATTEMPTED`, and unauthenticated `MALFORMED` are never selected.
A surviving terminal replica is degraded evidence, not generic malformed; it
never outranks robust authority. A nonqualifying PENDING cannot suppress an
accepted source. Immutable selection does not depend on mutable runtime having
behaved correctly and no user/API input can alter the evidence-quality or tuple
order.

For every selected PENDING entry, FSBL consumes the exact class-specific
checked intent, changes and twice reads back bound `ATTEMPTED`, freshly decodes
the same floor class, reparses both artifact identities and `CLEAN10`, reruns
fallback/source/vector/handoff checks, and then hands off once. Any failure
consumes all capabilities and redispatches from a complete fresh decode.
`ARM_READY` may retry only under proven no handoff; `ATTEMPTED`, lost token, or
malformed token permanently excludes that installation generation.
`Recovering` dispatches only to checked recovery and `Unknown` halts.
### 7.3 Probation authority

While the running slot is `ATTEMPTED`:

- no wallet signing signature may leave secure world;
- no wallet address, init code, registration signature, off-chain signature,
  user operation signature, or batch signature may be released;
- firmware-update BEGIN/COMMIT operations are rejected;
- ordinary unlock state is never published to NS;
- only the narrow probation-health/status surface is available after NS boot;
- all reconstructed wallet secrets are zeroized before NS probation begins.

The candidate remains `ATTEMPTED` until Section 9 completes.

### 7.4 Factory-genesis exception

Factory genesis is not a field update and does not pretend to have passed the
field health protocol. Its inputs are the paired canonical raw-blank A/B
release packages, not device-decoded `UNINSTALLED` proofs. Before final lifecycle locks, a narrowly
scoped offline factory writer MUST create both slot-bound artifacts of one
logical A/B release-set in `CONFIRMED` state. For each slot independently, and
without allowing a normal field handoff between them, it follows this order.
An external factory boot-hold/lifecycle interlock, independent of either slot's
mutable firmware, MUST remain asserted from before the first slot write until
both slots are durably confirmed, completely read back, and the final cold-boot
verification is ready. The factory receipt binds the interlock mechanism, its
asserted interval, release evidence, and deassertion authorization:

Before the first slot write, the offline factory writer erases and verifies
both dedicated Route-1 pages, programs and independently validates the two
active generation-zero `BASE0` snapshots defined by `FROZEN-ROUTE1-1`, and
proves their byte-equal logical state. This is the sole blank-to-`BASE0`
initialization. It occurs only under the external boot hold, performs no OTP
program, and grants no floor-advance authority. Any cut before both base
snapshots are active forces complete erase and restart of both Route-1 pages;
normal FSBL boot is never permitted to decode that intermediate.

1. erase and verify the complete manifest page plus every page in that slot's
   full secure and nonsecure capacity ranges (or use a documented mass-erase
   procedure proven equivalent under the Section-5 ownership map), then
   install body/CRC and both images and independently reverify signed bytes,
   hashes, ranges, and vector targets;
2. generate a fresh nontrivial 128-bit `install_id`, program its exact value/
   complement QWs once, and obtain selected durable-clean validation of both;
3. program `QW_PENDING` once and obtain selected durable-clean validation;
4. freshly reverify the complete artifact and install identity, then program
   `QW_CONFIRMED_0` once and obtain its separately attributed selected durable-
   clean validation; only after that receipt exists, program
   `QW_CONFIRMED_1` once and obtain its separately attributed selected durable-
   clean validation;
5. never create `ARM_READY`/`ATTEMPTED` or claim field-health evidence; and
6. after both A and B have completed those transitions, cold reset through the
   actual FSBL and prove canonical active `BASE0`, terminal-first
   `FullTerminalSet` decode and
   `RobustAccepted` authority for both, deterministic equal-`(R,E)` slot-A tie-
   breaking, exact floor behavior, measured-boot binding, and handoff.

Any reset/power loss during an affected slot's factory attempt—including image,
manifest body, install-identity, PENDING, `CONFIRMED_0`, or `CONFIRMED_1`
programming—forces the
same complete manifest + full secure/nonsecure capacity erase/restage before
that slot is retried while lifecycle state permits it. Exact-looking post-cut
bytes and a previously complete ID/marker pair are never resumed. A cut leaving only one confirmed
slot is incomplete factory state, not shippable genesis; before lifecycle locks
the factory either completes the independently verified peer or erases/restarts
the incomplete release-set under its offline recovery procedure. The same
marker/install-identity QW is never retried in place, even if it reads all
`0xFF`. This sequence
is mandatory in addition to all of the following:

1. `release_version` and `security_epoch` are in range under Section 1.1, and
   the factory logical rejected-through floor is verified as exactly
   `security_epoch - 1`; if the
   target is zero, erased OTP may represent that logical base without consuming
   a rollback record only when the synchronized Route-1 `BASE0` pair and the
   canonical `Steady(0)` proof in Section 7.1 both validate;
2. both byte-identical complete FSBL copies and the vendor key are reverified,
   and both independently slot-bound signed manifests, secure/NS image bytes,
   physical addresses, hashes, and measured-boot fingerprints are reverified
   after stamping;
3. slot A and slot B share the exact ledger-approved `(R,E)` and logical
   release-set identity but retain their distinct physical-slot tags,
   signatures, linked bytes, and image hashes; both decode
   `RobustAccepted(FullTerminalSet)`;
4. complete bank readback matches the expected final factory image and the
   exhaustive Section-5 ownership map;
5. a trusted, tamper-evident factory receipt anchored to the selected policy-
   ledger checkpoint binds all inputs, both install identities, all six
   PENDING/`CONFIRMED_0`/`CONFIRMED_1` marker-transition receipts,
   both generation-zero Route-1 `BASE0` page receipts,
   the external boot-hold/lifecycle-interlock mechanism and its continuously
   asserted interval through dual-slot readback,
   dual-bank WRP/SECWM/HDP/BOOT_LOCK/SWAP_BANK state, and option/security state;
6. if the selected codec uses MACs, that receipt proves the approved redundant
   rollback-key material is present, integrity/KAT-valid, and readable under
   final protections even when the rollback-record bank is fully blank; and
7. the stamper exists only as offline host/factory tooling, never as device
   firmware or an NSC command; a compile-time/build-profile ship fence rejects
   any production device build that includes factory-stamping authority; and
   final lifecycle locks independently prevent the underlying writes after
   the factory lifecycle closes.

The offline-tool separation, production build fence, and final lifecycle-lock
receipt are all required. A source-level convention or hidden command is not
evidence of non-field-reachability.

The factory packager MUST select a ledger-approved, factory-eligible release;
it need not hardcode `(R,E) = (1,1)`. A genesis with `E > 1` establishes its
target under the selected OTP codec and reduces field capacity by that codec's
exact full clean group, durable-stage, and recovery cost. No single-QW factory
floor is production-eligible. Such an `E > 1` genesis is not production-
eligible until the same selected-route `OPEN-OTP-1..3`, `OPEN-ECC-1`, durable-
stage, interrupted-launch, and complete final-build gates required for a field
epoch bump are closed; an offline factory label does not waive them.

The keyless blank-bank `F = 0` decoder rule is an availability recovery path
if valid key material later becomes unavailable. It MUST NOT be used to pass
factory provisioning or deliberately ship a MAC-mode device without the
required redundant key receipt.

Every later FSBL handoff of a selected `RobustAccepted` confirmed slot still
idempotently establishes `F == security_epoch - 1`; it does not rely
indefinitely on the factory receipt.

Seed restoration, wallet/admin reset, secure-element replacement, ordinary
main-flash mass erase, and factory rework MUST NOT lower or reinterpret `F`.
After production lifecycle closure, a full main-flash erase is terminal for
this four-state design: with no confirmed fallback, a merely `PENDING` recovery
image cannot boot and the unit is quarantined. Only authorized pre-lifecycle
factory rework may create a replacement `CONFIRMED` image using the same
PENDING-then-CONFIRMED order while preserving and satisfying `E > F`; that
inequality is necessary but not sufficient authority for recovery.
Pre-production boards carrying incompatible legacy OTP encodings
are never silently migrated by the new FSBL; they must be proven
blank/compatible or quarantined as development-only inventory.

### 7.5 Minimal recoverable flash-ECC reads

All reads of mutable/candidate-controlled flash that can precede evaluation of
the good slot—including activation markers, manifest fields, image hashes,
vector data, and final handoff rechecks—MUST use one minimal recoverable probe
primitive.

Within an active probe, the FLASH ECCD NMI handler MUST:

1. distinguish FLASH ECCD from every other NMI source;
2. clear the documented ECC flags and perform the required cache maintenance;
3. record probe failure in FSBL-owned state;
4. return only under a silicon-validated exception-return contract; and
5. cause the caller to discard every value loaded during that probe and reject
   only the affected candidate.

An ECCD outside a probe, a non-ECCD NMI, nested/inconsistent probe state, or
failed cache maintenance halts fail-closed. Host mirror tests are insufficient:
a deliberately torn inactive-manifest line on B-U585I-IOT02A must demonstrate
that FSBL rejects it and boots an independently valid confirmed fallback. Until
that receipt exists, `OPEN-ECC-1` and the production fallback claim remain
open.

---

## 8. Milestone 1: local secure-world health

Milestone 1 establishes mechanism-local evidence. It is a staged development
milestone, not the production acceptance boundary.

The secure candidate MUST complete:

1. running-slot identification and physical-slot cross-check;
2. independent manifest structural, digest, vendor-signature, rollback, and
   exact-journal verification;
3. re-hash and comparison of both installed secure and NS images;
4. an attempt-neutral `PreparedProbationPin` preflight followed by trusted PIN
   entry through exactly one call to `gated_unlock_prepared`, consuming the
   single `ProbationPinPermit`; every success, wrong-PIN, cancellation,
   transport failure, or internal error terminates that permit;
5. successful OPTIGA + SE050 unlock and wallet-master reconstruction;
6. after that success, the complete clean-counter reset/readback checks from
   Section 3, including E120 zero, two agreeing page-124 zero reads, and the
   documented SE050 successful-authentication reset semantics. These checks
   construct only a probation-local `ProbationCredentialReceipt`, never a new
   `CleanPinBudget` or update/arming capability; no weaker or estimated PIN
   reserve is health evidence;
7. a reviewed local derivation and C10 sign/verify self-test satisfying
   `FROZEN-HLT-1`;
8. zeroization of self-test keys, signatures, reconstructed master, PIN, and
   secure caches;
9. proof that the gateway remains logically locked.

Successful completion constructs a private, non-`Copy`, non-`Clone`
`LocalHealthPassed` value. It owns the FSBL-created stable probation handoff
binding plus a fixed-size canonical `LocalHealthEventRecord` containing the
exact executed step IDs, candidate binding, self-test result, zeroization
completion events, the consumed `ProbationPinPermit` identity, the exact
`ProbationCredentialReceipt`, and exactly one classification-bound dry-run
disposition: `NotApplicableSameEpoch`, `IncludedAndPassed`, or
`WaivedByReviewedBuildPolicy`. The waiver value is a compile-time disposition
for the exact artifact already bound by `ArtifactIdentity`; it is not an
on-device authentication of an external policy-ledger receipt. The record also
contains the
locked-gateway recheck, local deadline, local completion tick with checked
`completion_tick <= local_deadline`, the newly frozen absolute transport/
finalization deadline that starts no later than this completion, and terminal
local phase. Its private
constructor is reachable only after the applicable dry-run/waiver/not-
applicable branch and every named zeroization check below has completed; the
same-epoch classification is freshly rechecked during finalization. The full
nonsecret event record—not merely a previously computed
digest—is retained in secure SRAM so the later finalization constructor can
independently recompute the domain-separated complete health transcript.
`LocalHealthPassed` has no public constructor and cannot be synthesized from a
boolean, status word, or companion input. The transcript digest is evidence
that the reviewed cleanup/control path completed, not a claim that a hash
proves analogue remanence absence; compiler-fenced zeroization and the separate
remanence review remain mandatory.

A PIN typo, PIN cancellation, user walk-away, timeout, missing companion, or
health cancellation is a safe probation false negative: CONFIRMED is not
written. The next FSBL boot rejects the ATTEMPTED candidate and selects the
eligible fallback when the floor remains `Steady` or exact constrained
`Aborted`; any independently arising `Recovering`/`Unknown` condition retains
its no-handoff rule. The normal
three-way PIN attempt was real and MUST NOT be refunded, bypassed, or assigned
a weaker lockout policy merely because it occurred during probation. Re-arm
still requires a fresh authorized update/PIN flow and consumes the health-key
budget.

The self-test tuple and message MUST be firmware-selected, not
companion-selected. Its domain MUST bind the health-protocol version, physical
slot, signed `release_version`, signed `security_epoch`, and manifest/image
digest. It MUST traverse production seed reconstruction and the same reviewed
KDF/C10 implementation paths, but through the dedicated domain-separated
health-only derivation selected by `FROZEN-HLT-1`. It MUST NOT derive or use a
wallet bootstrap key, wallet slot key, wallet address key, firmware-vendor key,
or any key material capable of authorizing a wallet or manifest. Health-key
C10 key generation, signing, and verification are real executions, not a
stubbed KAT. The signature, digest, key, randomizer, and all derivation
intermediates remain in secure SRAM and MUST NOT be returned to NS or counted
as externally released wallet/vendor signing usage.

As defense in depth before an epoch-bump confirmation, secure runtime SHOULD,
after the named self-test secrets are zeroized and before NS
probation boots, drive the production parsers and renderers over
firmware-embedded canonical artifacts covering at least one UserOp, one
Safe/EIP-712 transaction, and one ERC-7730 descriptor. Inputs, pinned roots,
expected status, and expected rendered-page digest/shape are firmware-selected
and immutable for the release; neither NS nor the companion supplies them.
The output is consumed by an internal bounded test sink and MUST NOT release a
wallet address, signature, signing digest, or other authority, and the dry-run
must not reconstruct a key beyond the separately required self-test. Any
executed dry-run failure blocks `CONFIRMED`. Omitting it requires an explicit
reviewed release/spec waiver; it is not silently compiled out for size or
convenience. For a build that includes the dry-run, the production build
receipt must demonstrate that the parsers and renderers execute at runtime; an
optimizer-folded/precomputed success constant is not health evidence. For a
waived build, the protected policy ledger and finalized release receipt MUST
bind the waiver and exact build identity, and product evidence MUST disclose
that the extra renderer check was not part of probation; absence cannot be
reported as a pass.

This dry-run catches gross production-parser/renderer regressions only. It
does not exercise user-selected calldata, a real unlocked `SecureState`, the
publish/unlock transition, live signing dispatch, firmware-update dispatch, or
real authority release, and therefore does not expand the Section-9.7
availability claim.

The reconstructed master and every self-test secret MUST be zeroized before NS
boot. This requirement is explicit zeroization of named values; it does not
authorize the deferred broad reset assembly.

Milestone-1 failure MUST reset or otherwise cause the next FSBL boot without
writing `CONFIRMED`.

For production builds, Milestone 1 MUST NOT by itself authorize the
`ATTEMPTED -> CONFIRMED` write. No on-device local-confirm shortcut is compiled
even for development profiles; host/QEMU state-machine fixtures may inject an
abstract health verdict without adding a firmware command or shipping branch.

Milestone 1 demonstrates logical/state-machine behavior, not production
mechanism closure. Target mechanism closure remains open until the physical
journal, ECC recovery, and OTP backend pass their respective gates.

---

## 9. Milestone 2: defined NS/USB/gateway health boundary

### 9.1 Restricted probation mode

After Milestone 1, secure runtime:

1. retains only a nonsecret probation context plus secure-only challenge state;
2. initializes the normal USB hardware path;
3. boots the signed NS image;
4. exposes only probation health/status commands through NSC;
5. keeps `IS_UNLOCKED` false and rejects every signing, address, init-code,
   counter mutation, and firmware-update command.

The dispatch restriction MUST be centralized so adding a future command cannot
accidentally make it probation-eligible by omission. The allowlist contains at
most secure watchdog/heartbeat registration, probation status,
`HEALTH_BEGIN`, and `HEALTH_COMPLETE`. The normal unlocked `SecureState` MUST
never receive the reconstructed master during probation, and `pin_verified`
MUST remain false. NS-side filtering is defense in depth only.

### 9.2 Probation context binding

The FSBL-created secure-only `ProbationHandoffBinding` binds only stable
handoff facts:

- one exact entry kind: `OrdinaryFromSteady`,
  `PeerRepair`, or `DegradedArtifactRepair`;
- the candidate's complete stable `ArtifactIdentity` (including physical slot,
  install ID, signed manifest digest, image hashes, `R`, `E`, and `T`);
- the distinct `RobustAccepted` source/fallback's complete stable
  `ArtifactIdentity`, checked target `T_source == F_snapshot`, and exact
  confirmation-authority identity (`FullTerminalSet`); degraded evidence can never fill this field;
- the arming floor-authority identity: for `OrdinaryFromSteady`, exact
  `Steady(F)` group/`BASE0`, allocation generation/cursor, ownership digest,
  and physical snapshot digest; for any repair from `Aborted`, the exact
  predecessor, dead-plan/quarantine digest, effective dead-plus-live release
  high-water, allocation generation/cursor, and physical snapshot digest;
- for `PeerRepair`, the archived paired-release identity, opposite-slot rule,
  equal `(R,E,T)`, independent slot-bound signature/images, and exact source-
  twin relationship;
- for `DegradedArtifactRepair`, the archived degraded artifact identity,
  robust source identity, full-erase/restage requirement, and whether the
  containing floor class is `Steady` or `Aborted`; the latter requires
  `T == F` and zero backend writes;
- the preserved immutable-entry `BootFlashEvidenceSummary` and
  `boot_evidence_epoch`;
- signed `release_version`;
- signed `security_epoch` and derived `T = E - 1`;
- independently validated `F_snapshot` and the derived same-epoch/epoch-bump
  classification;
- only for an ordinary `Steady` epoch bump, the preflighted single finite-plan
  replica/stage/replacement/recovery-margin result and its exact receipt
  digest; both repair kinds bind an explicit zero-rollback-backend-write
  receipt and no capacity, reservation, stage, claim, or OTP authority;
- secure image digest;
- nonsecure image digest;
- exact composite `ATTEMPTED` state.

It contains no session ID, host nonce, challenge, mutable phase, response
attempt, deadline verdict, health-success boolean, or UI-approval boolean.
Those values do not exist at FSBL handoff and cannot be retroactively treated
as FSBL evidence.

FSBL constructs this `ProbationHandoffBinding` immediately before the final
ATTEMPTED handoff, after the fresh floor decode and both artifact
reverifications. It stores stable comparison data only—never a `SteadyProof`,
`DeadStageProof`, `ArtifactEvidenceKey`, or other reusable capability. The
layout, complement/integrity checks, fixed secure-SRAM reservation, and
zeroization are part of the combined FLASH/RAM/stack gate. The retained runtime
writer trust means vendor-signed secure runtime could deliberately corrupt its
own context just as it could deliberately forge CONFIRMED; the design makes no
stronger claim. Private constructors, duplicate validation, and FI sentinels
are required to contain accidental bugs and faults within that stated trust
boundary.

Runtime authority advances only through this private linear typestate chain:

```text
ProbationHandoffBinding
    -> LocalHealthPassed
    -> ActiveHealthSession
    -> TransportPassed
TransportPassed + LongConfirmApproved
    -> HealthAndUiApproved
    -> RuntimeFinalizationReceipt
    -> CONFIRMED_0 writer receipt
    -> CONFIRMED_1 writer receipt
    -> reset
```

`LocalHealthPassed` is the Section-8 value and canonical event record.
`ActiveHealthSession` owns it while binding the generated session ID, host
nonce, challenge state, the inherited historical local-completion/deadline
proof, the already-running immutable absolute transport/finalization deadline,
and the fixed three-attempt response budget. Each syntactically valid
completion atomically consumes one budget unit before comparison; malformed
frames do not consume a unit but remain bounded by the independent total-frame
and deadline budgets. The successful `HEALTH_COMPLETE`
transition consumes that active phase and constructs a private
`TransportPassed` value containing the still-owned local-health proof, the
canonical session/response record, two independently domain-separated leaves
computed and compared before erasure—one duplicate-classification request
digest and one complete-health-transcript transport-event digest—proof of the
exact attempt number, all preceding failed comparisons, and successful
consumption within the fixed three-attempt bound, plus
fresh unexpired-deadline observations. The transcript leaf binds the canonical
request length/encoding, host nonce, session ID, successful challenge-match
event, attempt-consumed event, and absolute deadline identity without retaining
the plaintext challenge. The plaintext challenge is erased after both leaves
are established; the typed transport value, not either bare digest or a phase
flag, carries authority. The duplicate-classification digest is used only for
duplicate response handling and is never substituted for the separately
domain-separated transcript leaf.

After every required finalization page has been rendered from the bound data,
the FI-hardened long-confirmation routine may construct one private
`LongConfirmApproved` value. It binds the exact canonical page-sequence digest,
physical approval event/counter, the historical checked
`local_completion_tick <= local_deadline`, a freshly unexpired active
transport/finalization deadline, locked-gateway recheck, and proof that no
cancellation or terminal error won the phase transition. A private constructor
consumes `TransportPassed` and
`LongConfirmApproved`, independently recomputes the complete domain-separated
health transcript from the retained `LocalHealthEventRecord`, canonical
transport record/digest, page-sequence digest, deadline observations, and
approval event, and yields `HealthAndUiApproved`. It atomically enters the
non-command-accepting `FINALIZING` phase. No boolean, enum discriminant,
companion message, duplicate completion, or display-return status can
construct any of these proof values.

Immediately before the marker write, the reviewed secure-runtime
`finalization_verifier` consumes `HealthAndUiApproved`—which owns the original
stable handoff binding—and performs all fresh Section-9.5 artifact, lifecycle,
floor, fallback-authority, classification, capacity, deadline, phase, and ECC
checks. Only then may it create a private, non-`Copy`, non-`Clone`
`RuntimeFinalizationReceipt`. This runtime-scoped receipt is not an immutable
`ArtifactEvidenceKey`. The runtime verifier instead creates one private
runtime-local join key per artifact:

```text
RuntimeArtifactEvidenceKey =
    ArtifactIdentity || runtime_pass_id || boot_evidence_epoch ||
    BootFlashEvidenceSummary || current_floor_snapshot_digest ||
    canonical_attributed_runtime_receipt_set_digest
```

`runtime_pass_id` is fresh and nonserializable for one bounded finalization
verification transaction. Candidate artifact plus exact ATTEMPTED evidence
must carry one byte-equal runtime key; fallback artifact plus its exact
terminal confirmation evidence must carry a separate byte-equal
runtime key. Candidate and fallback keys cannot be interchanged, joined across
passes, or equated merely because they share `(R,E,T)` or a floor snapshot.
The keys are private, non-`Copy`, non-`Clone`, runtime-only values; they are
never accepted by an immutable `ArtifactEvidenceKey` API, never cross reset,
and are consumed into the final receipt.

`RuntimeFinalizationReceipt` binds the two newly verified
`ArtifactIdentity` values and their exact runtime keys, the fresh current
floor-authority identity, entry kind,
current runtime pass ID, complete recomputed health-transcript digest,
long-confirmation/page-sequence identity, absolute deadline and final observed
tick, terminal `FINALIZING` phase identity, and the canonical digest of every
newly attributed read receipt. The first confirmation writer accepts only that
receipt, rechecks the secure monotonic deadline and terminal phase immediately
before programming, consumes it exactly once, writes only
`QW_CONFIRMED_0`, and after a separately attributed selected durable readback
yields one private `Confirmation0Written` receipt. The second writer accepts
only that linear receipt, writes only `QW_CONFIRMED_1`, and obtains its own
separately attributed selected durable readback. It never writes replica 1 if
replica 0 did not produce the first receipt. Neither interval permits an
intervening unowned flash **data-array probe**, unrelated flash program/erase,
or floor-state mutation, and neither QW is retried in place after an ambiguous
launch.
Ordinary reviewed instruction fetches between verifier and handoff are not
misdescribed as data probes: the recoverable NMI owner remains active, and any
unexpected ECC status fails before programming. The final receipt check,
deadline/phase check, status check/clear, both confirmation program sequences, and
immediate diagnostic readback execute from a reviewed SRAM-resident bounded
stub so same-bank flash busy time introduces no instruction/data fetch. Its
code copy/integrity check, RAM reservation, and stack are included in the
combined resource gate.

The SRAM-resident interval is closed over execution, not merely over the
writer function's text. Before entering it, secure runtime masks every maskable
interrupt and exception that is not required for the flash operation. Any
unmaskable or otherwise unavoidable NMI/HardFault path uses an integrity-
checked SRAM vector table and SRAM-resident handler. The complete call graph,
literals, read-only data, mutable state, stack, exception frame, readback/cache
maintenance, timeout, relock, and fail-closed exit path MUST reside outside the
busy flash bank and be included in `OPEN-RAM-1`. An unexpected exception,
vector-integrity failure, or attempted fetch/data dependency on the busy bank
terminates the receipt and fails closed; it never reprograms the QW, returns to
ordinary runtime, or reports confirmation success.

All runtime proof values and canonical event records are stored only in secure
SRAM and are destroyed on reset, timeout, cancellation, terminal error, or
final confirmation. An error after consuming one proof never reconstructs its
predecessor and always takes the Section-9.4 reset path.

The runtime verifier uses the same reviewed validation logic and exact-index
fresh-array primitive as FSBL, but under the explicitly trusted runtime writer
model. Before it starts, every earlier page-124 or other permitted flash
operation in that boot must have completed without outstanding/ambiguous
status; otherwise finalization resets. During probation, the secure NMI vector
MUST retain or delegate to the reviewed recoverable ECC owner so an image,
vector, manifest, journal, or floor read that raises ECCD returns a typed failed
receipt instead of faulting past the check. This runtime copy/delegation, its
exception frame, context, and worst-case nested stack are charged by
`OPEN-RAM-1` and remain production-gated by `OPEN-ECC-1` silicon evidence.

### 9.3 Fixed two-command health exchange

The full boundary uses one active session and two fixed-size, canonically
encoded commands. Exact instruction numbers and transport framing remain an
implementation parameter, but the semantic transcript is fixed.

#### `HEALTH_BEGIN`

The companion sends:

```text
protocol_version : fixed
host_nonce       : 32 bytes
```

The host nonce correlates the transport transcript. Security MUST NOT depend
on its randomness because the companion is untrusted.

Only in the post-local-health probation phase, secure runtime:

1. generates an independent 128-bit `session_id` from secure TRNG;
2. generates an independent uniformly sampled display challenge satisfying
   `FROZEN-HLT-2`;
3. binds `{host_nonce, session_id, challenge, slot, release_version,
   security_epoch, target, F_snapshot, update_class,
   bump_capacity_preflight_result, image hashes, deadline,
   valid_attempts_remaining = 3, total_frame_budget}`
   in secure SRAM;
4. displays the challenge on the trusted device with an instruction to enter
   it into the companion; and
5. returns through S -> NS -> physical USB:

```text
protocol_version : fixed
physical_slot    : fixed width
release_version  : u32 BE
security_epoch   : u32 BE
session_id       : 16 bytes
host_nonce_echo  : 32 bytes
```

The response MUST NOT contain the challenge or any value from which the
challenge can be derived. Session creation and trusted-display presentation
must succeed before the response is released.

An exact duplicate `HEALTH_BEGIN` with the same host nonce MAY return the same
session response, but MUST NOT generate a new challenge, reset attempt state,
or extend the deadline. A different host nonce while a session is active
returns `BUSY`. Begin retransmissions are bounded by both the absolute secure
deadline and a finite per-session command/rate budget; an untrusted host cannot
turn duplicate handling into an unbounded secure-world loop.

#### `HEALTH_COMPLETE`

After the user manually copies the trusted-display challenge into the
companion, it sends:

```text
protocol_version : fixed
host_nonce       : 32 bytes
session_id       : 16 bytes
challenge        : exact canonical encoding
```

Secure runtime MUST:

1. require exact length and canonical encoding;
2. match the active host nonce and 128-bit session identifier;
3. atomically decrement the fixed valid-attempt counter before comparing the
   challenge, rejecting if it was already zero;
4. compare without an early-exit timing oracle;
5. retain the same challenge, session, deadline, and remaining-attempt state
   after a wrong comparison while at least one valid attempt remains; never
   generate or display a replacement challenge in that session;
6. reject reuse after success and terminate probation when the third valid
   comparison fails; and
7. on success, independently double-compute and compare both domain-separated
   secure-only leaves defined in Section 9.2—the duplicate-classification
   request digest and the complete-health-transcript transport-event digest—
   then erase the stored plaintext challenge, consume `ActiveHealthSession`,
   and construct `TransportPassed`.

A wrong syntactically valid challenge consumes exactly one of the three valid
comparisons. The first two wrong comparisons return a fixed retry status and
preserve the same session/challenge/deadline; the third causes clean probation
failure. Malformed frames need not consume a valid comparison, but the total
gateway-frame budget still bounds them, and neither they nor any other NS
traffic may extend the absolute secure deadline. There is no abort-and-create-
new-session path; session loss or exhausted comparisons safely requires
reinstalling and rearming the candidate.

While `TransportPassed` remains live, secure runtime may recompute and
constant-time compare only the duplicate-classification request digest for an
exact duplicate completion. An exact duplicate MAY return a fixed
`ALREADY_COMPLETE` status and MUST NOT reset state, consume another attempt,
extend the deadline, or construct a second proof. A different completion is
rejected without revoking the already-established transport result. Neither
retained digest is ever returned, and the duplicate digest is not used as the
later complete-health-transcript leaf. Duplicate completion responses are also
bounded by the same absolute deadline and a finite per-session command/rate
budget.
Loss of the completion response or USB
disconnect after `TRANSPORT_PASSED` does not cancel health; only trusted-UI
cancel/timeout, an internal identity failure, or reset prevents confirmation.

This exchange exercises host-to-device USB, NS parsing, NSC dispatch, secure
handling, secure-to-NS return, NS-to-host USB, and a second inbound request.
It does not cryptographically prove an independent or honest external host:
without a secure-owned USB stack or an independent host secret, colluding NS
and companion remain one untrusted domain. Its security value is the
display-only unpredictable challenge plus explicit physical finalization,
which requires human participation before confirmation.

### 9.4 Deadline and failure policy

The normal production PIN-entry timeout remains 120 seconds. No probation-
health deadline begins before a successful PIN, so time spent entering a
correct PIN does not consume the post-authentication health window. At that
success, one absolute secure monotonic 60-second local-health deadline begins,
and its successful completion tick is frozen into `LocalHealthPassed`. At
Milestone-1 completion, one absolute 300-second transport/finalization deadline
begins. The two waits are individually bounded; later finalization proves the
historical local completion was timely but requires only the still-active
transport/finalization deadline to remain unexpired. The session also enforces
the frozen command budgets: at most eight `HEALTH_BEGIN` frames, eight
`HEALTH_COMPLETE` frames, three syntactically valid challenge comparisons, and
32 total probation gateway frames. These values and starts are exactly
`FROZEN-TIME-1`; a build cannot tune them independently. NS traffic, heartbeat
changes, retransmissions, malformed commands, USB reconnects, and gateway
activity MUST NOT reset or extend either deadline or any command budget.
The existing secure timer and/or IWDG MUST guarantee reset if NS fails to start
or service the restricted probation loop; this requirement does not by itself
authorize a new broad watchdog/reset subsystem.

On deadline expiry, challenge-attempt exhaustion, user rejection, display or
TRNG failure, pre-`TRANSPORT_PASSED` USB loss, command-budget exhaustion,
gateway failure, or
impossible volatile phase:

1. clear session/challenge and any remaining sensitive buffers;
2. leave the journal exactly `ATTEMPTED`;
3. show a concise update-check failure/revert page when possible;
4. reset; and
5. never hang or expose wallet authority.

### 9.5 Final trusted-display acceptance

After a valid round-trip, the device displays at least:

- that this is firmware-update finalization;
- candidate `release_version`, `security_epoch`, and trusted fingerprint;
- confirmation that local signing and external communication checks passed;
- an instruction to approve only if the user personally entered the displayed
  challenge into the companion during this probation session;
- a secure-world-derived classification and matching warning:
  - same epoch: the release becomes preferred, consumes no OTP floor record,
    and older releases remain only automatic failure fallbacks if the newer
    preferred release later becomes absent or independently invalid; there is
    no user downgrade or lower-version reinstall control; or
  - epoch bump: the next FSBL boot attempts immutable establishment; only after
    fresh `Steady(T)` is reached are all releases through epoch `T`, including
    the previous lower-epoch fallback, irreversibly rejected. A proven-no-
    launch failure or exact `Aborted` leaves the old floor/fallback unchanged,
    while `Recovering`/`Unknown` permits no handoff;
- clear cancel and timeout behavior.

The user must review all pages and perform an FI-hardened long confirmation.
Only the private long-confirmation routine may construct
`LongConfirmApproved`, and only while `TransportPassed` is live, all required
pages were rendered in canonical order, the historical local completion tick
is within its local deadline, the active transport/finalization deadline
remains unexpired, the gateway remains locked, and neither cancellation nor a
terminal error has won the atomic phase transition. Consuming those two linear values
constructs `HealthAndUiApproved` and enters the non-command-accepting
`FINALIZING` phase as specified in Section 9.2.

Immediately before the write, `finalization_verifier` MUST consume that exact
`HealthAndUiApproved` and re-read and validate the running physical slot,
signed `(R,E)`, current floor class and binding, derived classification, image
identity, exact composite `ATTEMPTED` state, and current unexpired deadline.
Any difference from the probation-bound snapshot fails closed rather than
changing classification. It MUST freshly reverify the probation-bound
candidate and `RobustAccepted` source/fallback stable `ArtifactIdentity` values
under separate current-pass evidence joins. The source's checked target must
equal the current authoritative `F`, and its current `FullTerminalSet`
confirmation authority must pass. It then rederives exactly the
entry kind bound at handoff:

1. `OrdinaryFromSteady` requires a fresh complete decoder result of the same
   bound `Steady(F)`. If `T > F`, the verifier repeats the selected backend's
   complete **single finite-plan** capacity/recovery-margin preflight. If
   `T == F`, it proves that no Route-1 reservation/stage/claim/compaction or OTP
   operation is requested.
2. `PeerRepair` requires the same floor class (`Steady` or `Aborted`), exact
   archived opposite-slot A/B twin, equal `(R,E,T)`, independent slot-bound
   signature/images, fresh install identity, and `T == F`.
3. `DegradedArtifactRepair` requires the same archived degraded target,
   `RobustAccepted` source, full erase/restage identity, and floor class. Under
   `Aborted`, `T == F` is mandatory. Under `Steady`, a target with `T > F`
   earns only robust terminal evidence here; any later floor establishment is
   the ordinary one-plan `start_from_steady` path after reset.

Both repair kinds prove zero rollback-journal and OTP writes during
finalization. None may change entry kind, borrow ordinary epoch-bump authority,
allocate capacity, or construct `T > F` from `Aborted`. Loss or mismatch of the
applicable floor class, source artifact, archived package evidence, terminal
authority, high-water, or zero-write classification before either candidate
confirmation write resets without confirmation.

Only after all of those checks succeed may `finalization_verifier` construct
one current-pass `RuntimeFinalizationReceipt` binding the complete health/UI
proof and separate candidate/fallback joins. Only the SRAM-resident writer may
consume that receipt, re-sample the deadline and `FINALIZING` phase, write
`QW_CONFIRMED_0`, obtain its separate selected durable receipt, consume that
receipt to write `QW_CONFIRMED_1`, and obtain its separate selected durable
receipt. A failure or ambiguous launch at either step is never retried in the
same installation generation. After reset, zero, one, or two surviving
terminal replicas are classified only by the Section-6 decoder; volatile
success flags confer no authority.

Immediately afterward, secure runtime:

1. performs the immediate diagnostic ECC-clean exact readback of both
   confirmation replicas, without treating either as cross-reset durability
   authority;
2. permanently keeps the gateway in its restricted/locked state and prevents
   return to NS or the ordinary wallet lifecycle;
3. zeroizes probation and sensitive state; and
4. enters a non-returning reset path without publishing an unlocked state. If
   the reset request unexpectedly returns or fails, execution remains in a
   terminal locked watchdog/halt loop until watchdog, external reset, or power
   cycle transfers control back to FSBL. It never returns to the caller.

Cancellation, deadline expiry, transport exhaustion, third wrong challenge,
identity mismatch, or any internal error before the first writer MUST reset
without writing either confirmation replica. An error after a writer launch
still takes the same terminal reset path; the decoder alone adjudicates the
result on the next boot.

### 9.6 False-negative behavior

A good candidate paired with a broken companion, flaky USB port, or absent host
may fail Milestone 2. That is an accepted safe false negative.

On failure:

- the device must not hang or confirm;
- the next FSBL boot rejects the candidate and selects the old confirmed slot
  when `Steady` or exact constrained `Aborted` authorizes it; an independent
  `Recovering`/`Unknown` floor condition still forbids handoff;
- the old firmware should clearly report that the update probation failed and
  may be retried;
- retrying requires reinstalling/rearming the candidate through the ordinary
  authenticated update flow.

### 9.7 Exact coverage claim and accepted residual

Milestone 2 proves one candidate boot traversed the defined local suite, NS
reset/main loop, ordinary USB hardware initialization and enumeration, the
dedicated fixed-size health route in both directions, secure gateway dispatch,
trusted display, and trusted physical confirmation.

It does not prove ordinary UserOp/off-chain parsing, large APDU chaining,
transaction clear-sign rendering, normal unlocked `SecureState`, release of a
real signature, bundler/RPC behavior, USB reconnection after confirmation, or
long-term stability. The first ordinary wallet lifecycle occurs only after the
next FSBL boot has established `F == E - 1`, so a bug unique to that path can
still brick the device under this no-grace/four-state design.

The Section-8 canned decode/render dry-run, when present, narrows gross parser/
renderer risk but does not change that boundary. An immediate persistent
reselection of a confirmed higher-`R` buggy release can brick either a same-
epoch or epoch-bumping update. The distinct cost of an epoch bump is that
durable floor establishment additionally retires the lower-epoch deep fallback;
same-epoch confirmation leaves older same-epoch releases floor-admissible but
not selectable while a newer `RobustAccepted` release remains preferred. They
are reached automatically when every newer same-epoch artifact is absent,
invalid, excluded by exact dead-stage proof, or in a lower evidence-quality
tier. A renderer-only fault may still leave the PIN-gated firmware-
update path usable for a forward repair; a fault in the normal unlock/publish
or update-dispatch path may not. None of these cases is claimed closed here.

Project documentation MUST say "rollback covers failures through the defined
local and USB/gateway probation checks," not "all crashing releases recover."
Closing the post-confirm ordinary-path residual requires an additional durable
pre-handoff milestone or a demotion/grace design and is explicitly deferred
for separate downgrade-policy review.

---

## 10. Confirmation and epoch-floor establishment

Section 10 has exactly the six disjoint typed entries frozen in Section 3:
`arm_probation_from_steady`, `start_from_steady`,
`resume_from_recovery`, `boot_accepted_from_aborted`,
`arm_peer_repair`, and
`arm_degraded_artifact_repair`. There is one unparameterized
`Aborted(DeadStageProof)`: it carries no follow-on epoch allowance, cannot construct
`T > F`, and persists across every exact-`F` boot or repair. Recovery is bound
to one already-active target and bypasses the ordinary selector, classifier,
preflight, and fallback path. FSBL MUST:

1. independently re-read the rollback floor and durable stage through the
   fresh-array, per-QW ECC-aware decoder required by
   `OPEN-ECC-1`/`OPEN-OTP-3`; dispatch `Steady(F)` only to
   `arm_probation_from_steady`, `start_from_steady`, or an eligible peer/degraded
   repair arm according to the independently
   decoded slot lifecycle and evidence quality. For exact bound `Recovering`, first
   construct `CheckedRecoveryIntent` by joining the fresh proof to the exact
   bound candidate's independently verified artifact and `RobustAccepted`
   terminal authority; dispatch only that checked intent to
   `resume_from_recovery`. A failed join yields
   `RecoveryBlocked(MissingRobustTerminalAuthority)` and halts without
   changing the floor-only `Recovering` classification. Dispatch exact
   `Aborted` only to `boot_accepted_from_aborted`,
   `arm_peer_repair`, or `arm_degraded_artifact_repair`; reject every
   `T > F` request before erase, activation, capability construction, or
   rollback-backend access. Halt on `Unknown`, type/entry mismatch, or
   inconsistent binding;
2. re-validate manifest structure, normalized CRC, slot binding, vendor
   signature, and strict rollback rule against `F` or exact `prior_f`. The
   probation entry requires exact state-appropriate `PENDING` evidence and must
   prove both confirmation replicas `BlankVirgin`; every floor-establishment/
   recovery entry and exact-`F` accepted boot requires typed robust terminal
   evidence. Initial establishment requires `FullTerminalSet`. Recovery obtains
   that same authority only through the
   `CheckedRecoveryIntent` constructor. Within each
   physical artifact, its artifact proof and state-appropriate lifecycle or
   confirmation proof must carry the same `ArtifactEvidenceKey`; candidate and
   fallback keys remain distinct while sharing the entry's boot/floor snapshot;
3. re-hash secure and nonsecure images;
4. independently re-read signed `R` and `E`, require both values to be in
   `1..=0xFFFF_FFFE`, derive `T = E - 1` using checked arithmetic, and require
   `T <= 0xFFFF_FFFD`; no reserved sentinel can reach the writer even if an
   earlier validation is faulted;
5. on `arm_probation_from_steady`, consume a fresh full-snapshot
   `SteadyProof`; require an independently verified `RobustAccepted` fallback with
   target exactly `F`, a qualified strictly `R`-newer/nondecreasing-`E`
   PENDING candidate and exact `ARM_READY`; classify checked `T` against `F`.
   Same-epoch arming bypasses all capacity preflight. Epoch-bump arming runs
   the snapshot-bound **read-only** single finite-plan
   preflight and carries its receipt in `CheckedSteadyProbationIntent`; this
   receipt grants no persistent authority. Perform only the TAMP transition to
   exact `ATTEMPTED`, then freshly decode the complete floor/stage state and
   reverify both artifacts, fallback authority, and (for an epoch bump) the
   still-current read-only preflight receipt immediately before handoff. It
   MUST NOT invoke `begin`, recovery, compaction, or any OTP/stage writer;
6. on `start_from_steady`, require `T >= F`; `T < F` fails closed. When
   `T == F`, issue no OTP unlock/program command or persistent stage write.
   When `T > F`, repeat the snapshot-bound read-only preflight and invoke
   `begin(intent)` exactly once through the private FSBL stage/OTP writer;
7. on `resume_from_recovery`, consume only `CheckedRecoveryIntent`, require the
   freshly derived `T` equals its proof target and `T > prior_f`, independently
   revalidate every candidate/terminal/stage/group/role binding, and resume that
   exact active protocol. It MUST NOT call `begin`, ordinary preflight/
   classification, or any fallback path. A raw `RecoveryProof` or
   `RecoveryBlocked` value cannot call the writer;
8. on `boot_accepted_from_aborted`, consume fresh `DeadStageProof` plus the
   best independently verified `RobustAccepted` artifact with `T == F`, prove
   exclusion of the failed release and A/B twin, perform no persistent write,
   and repeat the complete decode and artifact verification immediately before
   handoff. This artifact may be the original fallback or a later fully
   probated repair; the same `Aborted` proof remains authoritative;
9. on `arm_peer_repair`, consume fresh `Steady(F)` or `Aborted(F)`, the
    `RobustAccepted` source, and the independently restaged opposite-slot
    archived A/B twin. Require exact equal `(R,E,T)`, `T == F`, independent
    slot-bound signature/images, fresh install identity, exact `ARM_READY`, and
    evidence that no direct-confirm shortcut occurred. Then perform only the
    TAMP transition, fresh decode/reverification, and probation handoff;
10. on `arm_degraded_artifact_repair`, consume fresh `Steady(F)` or
    `Aborted(F)`, a `RobustAccepted` source, the exact archived package for the
    previously degraded target, full erase/restage evidence, fresh install
    identity, and exact `ARM_READY`. Under `Aborted`, require `T == F` and no
    rollback-backend authority. Under `Steady`, a repaired `T > F` candidate
    may earn robust terminal evidence through probation, but floor establishment
    remains a later ordinary `start_from_steady` action after reset;
11. for each physical replica independently, invalidate the documented flash
    cache/data-buffer state, clear stale ECC flags, force one attributed array
    read, and snapshot/consume ECC status before the next flash access;
12. after any floor writer, recovery, or role consumption, perform a fresh full
    decode and recompute the complete
    authenticated finite plan. Exact `Steady(T)` permits candidate revalidation;
    exact `Aborted` is returned only when every `DeadStageProof` predicate,
    including no possible completion-authority launch, holds and redispatches to
    the constrained top-level path; `Recovering` is returned only while at least
    one legal completion sequence remains; every other threshold, role,
    ownership, or completion ambiguity is `Unknown` and halts. No floor writer
    returns handoff authority directly; and
13. perform handoff only for (a) an ordinary exact `ATTEMPTED` candidate after
    consuming the probation entry and fresh `Steady(F)` plus exact-`F`
    source revalidation, (b) a repair candidate in exact `ATTEMPTED` after the
    applicable fresh floor/source/class recheck, (c) a robust exact-`F`
    accepted artifact through `boot_accepted_from_aborted`, or (d) a confirmed
    candidate after fresh `Steady(T)`, and only after the applicable final
    recheck. A repair that has earned both terminal replicas may boot after
    reset through the corresponding no-write accepted-artifact path; it never
    starts a second floor plan from `Aborted`.

The following arithmetic list applies only to a fresh
`start_from_steady(CheckedSteadyIntent)` entry with current rejected-through floor `F`
and target `T = E - 1`:

- `F == T` succeeds idempotently and consumes no new cell;
- `F < T` invokes exactly one logical
  `start_from_steady(...)->begin(intent)` under the selected OTP backend; the
  approved codec may require multiple physical quad-word
  programs, replicas, or stage records for that one commitment;
- `F > T` fails closed;
- after the replicated commitment, a fresh scan MUST establish exactly
  `Steady(T)`; and
- no mutable slot code may run until that postcondition and the still-confirmed
  image binding both succeed.

A `RecoveryProof` never re-enters this arithmetic list or calls `begin`, even
though its bound `prior_f < target` satisfies the same numeric inequality. It
must first be consumed into a fresh `CheckedRecoveryIntent`, and only that
checked value follows the `resume_from_recovery` branch above in one boot.
Across reset, the decoder and all artifact/terminal evidence are reconstructed
afresh.

`commit_target(T)` is the umbrella name for one logical transition from the
previously decoded floor to exactly `T`; it does not prescribe a one-QW
encoding and is not one callable entry. A fresh transition uses
`start_from_steady`/`begin` once; a rebooted transition uses only
`resume_from_recovery`. The
floor is the `Steady` value produced by the approved fail-closed decoder over
the complete OTP record bank plus its approved durable stage. While a valid
completable target is in progress, the interface returns `Recovering`; a
mathematically dead pre-`COMPLETE` plan returns exact `Aborted`; neither exposes
`prior_f` to ordinary admission. A torn or unreadable physical record
never contributes a lower or higher value merely through best-effort parsing.
Physical-cell reuse and durable intent follow `OPEN-OTP-3`.

An exact raw QW value is never by itself a successful commitment. Success
requires the complete approved structural code and clean-replica group. A
matching `ECCC` read rejects that replica even when hardware-corrected bytes
equal `T`. For the highest committed group, the remaining independent clean
witnesses either satisfy the approved degraded threshold for that same target
or the result is `Unknown`; no older record is returned. For an active target
group, a valid stage is `Recovering` only while its frozen plan can still
complete; exact finite-plan exhaustion with proven no completion launch becomes
`Aborted`, while any stage/threshold/completion ambiguity is `Unknown`.
`ECCC`-clean exact bytes are necessary but not sufficient after a possible
interruption; a possibly interrupted QW has zero quorum weight even when its
returned bytes equal `T`. Durably logged clean pre-cut replicas may be retained,
and selected-route-authorized clean replacements may be added after recovery;
neither path establishes `T` until a fresh `COMPLETE` records the full clean
initial threshold. Until `OPEN-OTP-1..3` defines and validates that ordered
protocol and the all-`0xFF` intent rules, the epoch-bump success path is not
production-authorized.

Failure before a target commit is distinct from ambiguity after one may have
launched. FSBL may boot a lower preferred-order slot only if all of the
following hold:

1. the combined decoder entry and fresh re-read both remain exactly
   `Steady(F)`;
2. the backend proves no durable reservation, claim, pre-`COMPLETE` stage-body/
   stage-activation, or compaction write and no OTP program operation for this
   target may have
   launched;
3. the other slot is independently valid and exactly `CONFIRMED` under that
   floor; and
4. the fallback's checked target equals the existing floor
   (`E_fallback - 1 == F`), so its handoff needs no OTP program command.

This proven-no-establishment-launch fallback is deterministic on every later
boot while the physical artifacts remain unchanged. The higher confirmed
candidate remains unselected while present and valid until capacity/key/backend
availability is repaired. Its physical presence may change only through an
authorized factory/service action or the ordinary authenticated updater under
Section 7.1's strict live-confirmed high-water rule, which permits replacement
only by a release with `R_new` above every valid confirmed artifact and
nondecreasing `E_new`. Such replacement is still not bootable unless its own
admission/floor requirements pass; it is not demotion authority. If no exact-
`F` fallback exists, FSBL halts.
If any pre-`COMPLETE` establishment-state or OTP write for the target may have
launched, FSBL cannot use the ordinary proven-no-launch fallback. It proceeds
only through bound recovery, which gives uncertain QWs zero weight and never
retries them. A still-completable plan remains `Recovering`; a mathematically
dead plan may become `Aborted` only under the exact no-completion-launch and
whole-plan-quarantine proof. Only that proof permits the exact-`F` fallback.
If completion may have launched, the stage/ownership chain is ambiguous, or
the highest committed floor cannot be proved, the result is `Unknown` and
halts. An older release never masks ambiguous anti-rollback state.
Post-`COMPLETE` close/compaction follows the separate maintenance rule in
`OPEN-OTP-1`: retained authoritative evidence yields `Steady(T)` and permits
normal handoff; loss/ambiguity yields `Unknown`; it never enters this fallback
or epoch-advance `Recovering` path.

A same-epoch confirmation does not floor-retire the previous slot. It remains
admissible and loses only when the frozen evidence-quality/tuple order prefers
the newer artifact; a lower-`R` `RobustAccepted` artifact still outranks a
higher-`R` degraded artifact. No command, reinstall, or user choice may
reverse that preference. A successful epoch bump retires every slot
with `E <= F'`; the prior lower-epoch slot becomes ineligible only after exact
durable establishment of the new target.

The canonically proven factory `BASE0` pair plus blank-OTP logical floor is
exactly `Steady(0)`; security epoch zero is never admissible.
`release_version` is independent and also starts at one or
above. Jumping either number does not create multiple logical floor
transitions: only a transition from `T == F` to `T > F` invokes
`commit_target(T)`. Its physical QW cost is whatever the approved codec
declares, independent of the number of skipped epoch values.

---

## 11. Power-cut and transition matrix

| Cut/failure point | Durable state | Required next boot | Old slot status |
|---|---|---|---|
| Factory cut during either generation-zero Route-1 `BASE0` page | incomplete offline genesis; lifecycle not locked; external boot-hold remains asserted | permit no normal boot; completely erase and restart both Route-1 base pages under the factory interlock | no field slot is eligible |
| Factory cut before both slots reach CONFIRMED, including during either slot's image/body/marker writes | incomplete offline genesis; lifecycle not locked; external boot-hold remains asserted | permit no normal boot or field lifecycle; retain the external interlock until both slots are durably confirmed and read back, or fully restart the affected release-set/slot under factory recovery after complete manifest + full secure/nonsecure capacity erase/restage | one confirmed artifact is factory recovery evidence, not supported product genesis |
| Completed dual-slot factory genesis, then one confirmation replica in either slot degrades | both slots retain at least `SurvivingTerminalSet`; an independently robust peer remains unless it also degraded | prefer any `RobustAccepted` peer; use a surviving set only as repair-target evidence, never boot or floor authority | bootable while robust evidence remains |
| Image/manifest staging before token/PENDING activation, including exact-looking post-cut bytes | incomplete/non-PENDING volatile attempt | candidate ignored; no resume. Next authenticated BEGIN erases/verifies the complete inactive manifest and full secure/nonsecure capacity ranges and fully restages | eligible |
| Field COMMIT cuts after exact TAMP invalidation and before any install-ID program may have launched | inactive generation has no valid install identity and token is exact INVALID or later lost | ignore candidate; a rebooted update starts a new full-range erase/restage attempt and new RNG value | eligible fallback preserved when independently valid |
| Install-ID value/complement write torn, corrected, repeated, complete-before-reset, or may have launched | no valid resumable `ArtifactEvidenceKey`; never `UNINSTALLED`/PENDING | reject generation; no same-QW or exact-pair resume; later authorized reinstall starts with complete inactive-range erase/restage and fresh RNG value | eligible fallback preserved when independently valid |
| Byte-identical artifact is erased/reinstalled with a fresh install ID | new physical generation and key | old terminal/TAMP proof cannot join; candidate must follow ordinary activation/probation unless it has new exact authority | prior accepted artifact identity does not bless new generation |
| System reset reports interrupted inactive-slot manifest/image operation in `FLASH_OPSR` | exact address/QW is `UnknownMayHaveLaunched` regardless of bytes | immutable entry snapshots/attributes status before any later mutation; no confirm/floor advance/rewrite; only a later authenticated complete inactive-range erase/restage when independently inactive may replace it, otherwise inhibit flash and halt/recover | eligible fallback preserved when independently valid |
| TAMP token body/ARM_READY torn, PENDING absent | no valid candidate activation | stale/malformed token ignored | eligible |
| Exact ARM_READY token, PENDING absent | no valid candidate activation | stale token ignored | eligible |
| PENDING activation torn or apparently erased after launch | malformed/non-PENDING | candidate rejected; no same-QW retry, later reinstall requires complete inactive-range erase/restage | eligible |
| PENDING activation interrupted, then reads exact/ECCC-clear without approved durability proof | `UnknownMayHaveLaunched`, not PENDING | candidate rejected; follow only the approved durability/reinstall rule | eligible |
| Exact PENDING + exact bound ARM_READY | PENDING | FSBL may arm once | eligible |
| Valid CONFIRMED + equal/crossed/otherwise non-qualifying PENDING | confirmed fallback plus ignored candidate | establish confirmed target and boot fallback | selected; pending cannot brick it |
| Two accepted CONFIRMED artifacts with robust/degraded, crossed, or equal tuples | normal post-update state or recovery anomaly | select among `RobustAccepted` artifacts by higher `E`, `R`, and fixed slot A, subject to Section 10 | selected only after required target establishment |
| Cut before Ready→Attempted TAMP transition | PENDING | retry arming; candidate has not run | eligible |
| Cut before Ready→Attempted transition, then ARM_READY is lost by VBAT drain, tamper, or backup-domain reset | malformed PENDING composite | reject candidate and boot eligible confirmed fallback; fresh retry requires PIN-gated reinstall/re-arm | eligible; retry benefit was lost, not security |
| VDD/VBAT marginal power cycle covered by ES0499 before the cold-boot workaround is proven | TAMP/BKP content is unpredictable, not an authoritative retained token | do not decode for retry authority; apply the selected reviewed Section-3 protected-`MONEN`, unconditional forced-`BDRST`, or separately re-frozen conditional forced-`BDRST` policy; only a probationary slot with CONFIRMED `BlankVirgin` is rejected for token loss, and fallback still requires `Steady` or exact constrained `Aborted`; terminal CONFIRMED ignores token and `Recovering`/`Unknown` forbid handoff | eligible only under the applicable floor class; TAMP backend remains production NO-GO until silicon receipt |
| Ready→Attempted interrupted, token still exact ARM_READY | PENDING | retry transition; candidate has not run | eligible |
| Ready→Attempted interrupted, token exact ATTEMPTED | ATTEMPTED | candidate excluded; fallback | eligible |
| Ready→Attempted interrupted, token lost/malformed | malformed | candidate rejected | eligible |
| Exact ATTEMPTED durable, before handoff | ATTEMPTED | candidate rejected | eligible |
| ATTEMPTED durable, before local health | ATTEMPTED | candidate rejected | eligible |
| During PIN/SE/self-test | ATTEMPTED | candidate rejected | eligible |
| During NS/USB/gateway probation | ATTEMPTED | candidate rejected | eligible |
| Companion absent/unresponsive | ATTEMPTED | bounded failure then reset/fallback | eligible |
| First or second wrong canonical challenge | ATTEMPTED plus same live volatile session and reduced attempt budget | retain the same challenge/deadline and return the fixed retry status | eligible if probation later fails |
| Third wrong/replayed challenge or attempt-budget exhaustion | ATTEMPTED | reset/fallback | eligible |
| Final UI cancelled or timed out | ATTEMPTED | reset/fallback | eligible |
| Inactive peer is staged/PENDING/ATTEMPTED and the sole retained source loses all robust confirmation authority | no robust source remains | reject candidate and halt; never promote probation state | safety preserved; availability lost |
| `QW_CONFIRMED_0` write torn or apparently erased after launch | no robust terminal set | never retry the QW; reject or classify only a permitted surviving degraded set after fresh terminal-first decode | eligible source preserved |
| Replica 0 is durably clean, then replica 1 write is torn, corrected, or ambiguous | exactly one possible surviving terminal replica | never retry either QW; classify as repair target only, never boot | robust source outranks it |
| Both confirmation replicas are durable, then TAMP token is lost | exact `FullTerminalSet` | ignore token; classify from signed `E`, current `F`, and accepted authority | same-epoch old slot remains eligible; lower epoch remains eligible until floor completion |
| At least one permitted terminal replica is exact, historical PENDING is torn/ECCC/ECCD | terminal-first accepted/degraded evidence; PENDING not read | normalize the complete CRC journal window as specified; do not demote terminal state merely because PENDING is unreadable | selection follows evidence quality then tuple |
| Same-epoch CONFIRMED, `T == F` | steady without floor write | issue zero OTP/stage commands; select by evidence quality, then `E`, `R`, slot A | older release is floor-admissible and may outrank a newer degraded artifact, but not a newer `RobustAccepted` artifact |
| Epoch-bump CONFIRMED, `T > F`, before commitment | `Steady(F)` plus CONFIRMED candidate | FSBL starts only the approved durable-stage and replicated floor commitment | eligible until any launch; no handoff before `Steady(T)` |
| Cut during durable-stage body/activation, with proof that no stage write launched | `Steady(F)`; no active establishment state | proven-no-establishment-launch rule may select only an independently verified confirmed fallback with target `F` | fallback remains eligible |
| Exact-`F` fallback is running while a higher valid CONFIRMED peer remains unselected after proven-no-establishment-launch/capacity failure | both artifacts remain independently confirmed; peer is not demoted | updater includes both in live-confirmed maxima and refuses to erase the peer for any package with `R_new <= R_confirmed_high` or `E_new < E_confirmed_high`; only a strictly later nonregressing release may replace it | archived tuple cannot erase the preferred accepted artifact |
| Durable-stage body/activation may have launched, before first OTP command | exact valid stage => `Recovering`; torn/replayed/ambiguous stage => `Unknown` | bypass selector and fallback; resume the exact bound stage or halt | no handoff even though no OTP pulse is proven |
| Durable recovery stage active at boot | `Recovering { prior_f: F, target: T, ... }` with a nonempty completable plan | bypass admission and fallback; construct `CheckedRecoveryIntent` from the fresh proof, bound candidate, and `RobustAccepted` terminal authority, then resume Section 10 only on success | neither slot handed off until fresh `Steady(T)` |
| Candidate loses robust terminal authority while epoch establishment is `Recovering`, before `Steady(T)` accepted binding exists | floor-only decode remains exact `Recovering` | `CheckedRecoveryIntent` yields nonwritable `RecoveryBlocked(MissingRobustTerminalAuthority)` and halts; never relabel floor, fall back, or hand off | lower fallback is not exposed while unresolved |
| The one frozen replica plan becomes mathematically impossible before any `COMPLETE` authority may have launched | exact `Aborted`; every failed-plan role, including unused planned roles, remains permanently owned/quarantined | exclude failed release/twin; boot the best independently verified robust target-`F` artifact or admit only an exact no-floor-write repair class | prior floor unchanged; robust exact-`F` source may boot |
| Missing/all-FF, torn, exact-looking, or conflicting `COMPLETE` for which launch cannot be disproved | `Recovering` only if exact completion recovery exists; otherwise `Unknown` | never classify `Aborted`, never expose prior floor, never retry the same completion role | no handoff |
| Stable reboot after exact `Aborted` | same authenticated dead-stage proof, floor, release high-water, ownership, and quarantine | deterministically rederive the same class; never create capacity, another plan, or `T > F` authority | robust exact-`F` accepted boot remains available |
| Power cut, crash, health failure, cancel, or reset while floor class is `Aborted` | unchanged `Aborted`; no rollback-backend mutation | boot only the previously accepted robust exact-`F` artifact through `boot_accepted_from_aborted`; if no robust exact-`F` artifact remains, halt to service/RMA | preserved and still exact-`F` |
| Peer or degraded-artifact repair is cut at any pre-terminal step | original `Steady` or `Aborted` class remains authoritative | reject attempted repair, boot robust source, and require full reinstall/re-arm | preserved |
| Any `T > F` request is presented while floor class is `Aborted` | unchanged `Aborted`; no capability or mutation | reject before erase, activation, Route-1, or OTP access | preserved |
| Epoch-bump OTP replica write interrupted by system reset | clean-looking, corrected, malformed, exact-looking, or ambiguous replica outcome with the attempted role consumed at zero quorum weight | consume `FLASH_OPSR`, fresh-read, never reprogram the QW, and recompute the complete authenticated finite plan: `Recovering` only if a legal completion sequence remains; exact `Aborted` only if every dead-stage/no-completion-launch predicate holds; otherwise `Unknown`/halt | lower epoch retires only if a later clean full group and exact `COMPLETE` establish it; otherwise not handed off |
| Epoch-bump OTP replica may have launched, then complete power loss; QW reads all `0xFF` | indistinguishable from virgin without durable pre-claim or authoritative discriminator | do not claim reuse or quarantine from readback alone; follow an approved pre-claim/discriminator, otherwise halt and keep field epoch bumps NO-GO | physically present; not handed off |
| Possibly interrupted QW later reads bit-exact `T`, `ECCC` clear | uncertain replica; exact bytes are not durability evidence | give that QW zero quorum weight; retain only durably logged clean pre-cut replicas, add selected-route-authorized clean replacements, recompute the finite plan, and require a fresh `COMPLETE` for the full initial threshold | lower epoch retires only after that new complete group establishes `T` |
| Any highest-committed-group read raises matching `ECCC` | corrected replica; not clean authority | reject that replica after fresh-array attribution; accept the same floor only from the remaining clean threshold, otherwise return `Unknown` and halt—never fall back to a lower floor | not selected through a lowered floor |
| Full clean target replicas exist, but `COMPLETE` body/activation is torn or may have launched | exact valid pre-complete stage => `Recovering`; ambiguous/replayed completion => `Unknown` | never accept a degraded initial group or retry an ambiguous same record; use only the approved bound replacement/completion recovery or halt | lower epoch remains unselected; no handoff |
| Exact `COMPLETE` durable, then optional stage close/compaction is cut | old authoritative completion copy and group remain `Steady(T)` until a disjoint replacement is durable; loss/alias/ambiguity of all authoritative copies => `Unknown` | never overload epoch-advance `Recovering`; continue from `Steady(T)` or halt, never return prior `F` | handoff only from `Steady(T)` |
| Epoch-bump replicated commitment durable and complete | fresh decoder returns `Steady(T)` from clean target group and resolved authoritative completion evidence | restart ordinary admission, then select the confirmed candidate | lower epoch intentionally retired |
| Previously accepted epoch-bump CONFIRMED marker later degrades | `Steady(F)` retains the floor-bound accepted-manifest binding as an evidentiary record only | the degraded artifact has no boot authority; independently reverify signature/images of any surviving robust artifact and boot only that, otherwise halt; never lower `F` | old lower epoch remains intentionally retired |
| Floor capacity exhausted before ordinary same-epoch update | fresh `Steady(F)` and checked `T == F` | ordinary `SameEpoch` update remains permitted; zero OTP/stage writes and no plan allocation | remains eligible |
| Floor capacity/key/backend unavailable for epoch bump, proven before any reservation/stage/claim/compaction or OTP launch | exact `Steady(F)`; higher candidate remains CONFIRMED | boot an independently verified confirmed fallback only when its target is exactly `F`; otherwise halt | fallback selected without establishment write; higher candidate remains unselected |
| MAC root/key unreadable with fully blank, ECC-clean record bank, synchronized active factory `BASE0` Route-1 pair, and durable-intent proof that no writer state/launch is missing | canonical `Steady(0)`, future commitment unavailable | boot an otherwise-valid `E=1` confirmed slot; for a higher-epoch candidate use the proven-no-establishment-launch fallback rule or halt | runtime recovery only; factory ship gate still requires valid key receipt |
| OTP record root/key unreadable with any nonblank or ambiguous record bank | floor fail-closed | fail closed | not used to bypass floor |
| First-boot lock ceremony: cut DURING the `RDP = 0xCC` option-byte program | possibly torn option-byte latches; the next power-on runs the option-byte loader from whatever latched | if the device boots and Phase-A read-back shows exactly the pre-ceremony staged ship profile with `RDP != 0xCC` (the burn did not take), the ceremony re-enters (re-verify, re-confirm, re-attempt; idempotent under R1.3); any other persistent value—partial, torn, alien, or `RDP = 0xCC` paired with any wrong staged word—halts to RMA with no re-attempt and no heal, since a re-attempt cannot repair a locked-but-wrong profile, and tz-1's phase-appropriate profile check enforces the same classification at every later boot; if the device does not boot, the torn wedge is RMA: an accepted factory-class residual, mitigated by stable powered-line execution and the `DO NOT POWER OFF` UI | classification by read-back of actual OB state, never by remembered intent |
| First-boot lock ceremony: cut AFTER a clean `RDP = 0xCC` program and BEFORE `OBL_LAUNCH` | the next power-on reset itself reloads option bytes (POR ≡ option-byte reload); the device comes up LOCKED | Phase A reads `RDP = 0xCC`, classifies the burn as complete, and proceeds to Phase B; after any cut in the burn window the next power-on completes the launch; the flow MUST classify by read-back, never by remembered intent, and MUST NOT reissue the RDP write once read-back shows `RDP = 0xCC` | lock completes at next power-on |
| First-boot lock ceremony: `OBL_LAUNCH` issued but no reset occurs | launch pending; actual OB state decides at the next power-on | park (never continue executing below RDP-2); on the following power-on classify by read-back as above | lock completes at next power-on |

The first-boot lock rows above define the exact burn-window semantics of the
R2.1--R2.6 ceremony: option-byte programming takes effect only when the
option-byte loader runs, at `OBL_LAUNCH` or at any power-on reset, so a power
cut between a clean RDP program and `OBL_LAUNCH` completes the lock at the
next power-on. The `every Phase-A fault halts unlocked` rule (R2.6) has
exactly one exception: a cut inside the burn window completes the lock by
reset; that is the intended terminal state, not a fault violation. The
burn-window classification above is identical to tz-1's phase-appropriate
expected-profile rule (Draft 1.2 §3 row 2), so the two documents issue one
order, not two.

All ordinary state-machine pre-confirmation failures preserve the previous
confirmed slot; independent loss of all robust authority for that slot is
the phase-scoped halt case stated in `OPEN-JRN-DUR-1`.
No state transition treats a torn word as a weaker valid state. The OTP rows
are architecture gates, not an implemented retry or acceptance promise.
Visible all-`0xFF` data alone MUST NOT authorize reusing a QW whose program may
have launched. Exact authorized bytes and `ECCC` clear are still insufficient
without the approved clean replicated group and retention policy. A corrected
or ambiguous frontier never makes the decoder return a lower floor. Loss of
clean quorum for the highest committed group produces `Unknown`; an incomplete
frontier with intact prior committed quorum and one exact completable stage is
`Recovering`; a fully authenticated dead pre-completion plan is `Aborted`; an
invalid, orphaned, completion-ambiguous, or otherwise uncertain stage is
`Unknown`.

---

## 12. OTP constraints and open record decision

### 12.1 Authoritative STM32U585AI properties

The programming/ECC statements below are pinned to local RM0456 Rev. 7
Sections 7.3.2, 7.3.7, 7.3.9, and 7.3.11--7.3.12; Cube HAL behavior is
corroboration, not the authority.

- User OTP is 512 bytes: 32 independent 128-bit ECC quad-words.
- Each program operation writes one 137-bit codeword: 128 data bits plus nine
  hardware ECC bits computed over the complete quad-word.
- A one-bit error is silently corrected in returned data and sets
  `FLASH_ECCR.ECCC`; a two-bit error sets `ECCD` and raises NMI. While an ECC
  flag remains set, later error address reporting is suppressed, and a reread
  served from the current flash data buffer may not raise the flag again after
  software clears it. Per-QW attribution therefore requires clear-before-read
  and a silicon-validated fresh-array/cache-buffer sequence.
- Erased is all ones; programming clears selected bits one-to-zero.
- A quad-word is a one-program unit.
- Reprogramming any already-partially-programmed quad-word raises `PROGERR` and
  is ignored.
- The main-flash all-zero reprogramming exception does not apply to a partially
  programmed OTP quad-word. OTP has no erased -> value -> zero odometer state;
  there is exactly one supported programming transition per quad-word.
- An interrupted program may permanently lose the quad-word. After system
  reset, `FLASH_OPSR` reports an interrupted operation and MUST be consumed
  before further programming. After complete power loss, contents are not
  guaranteed; even visible all-ones data is not authoritative evidence that
  the cell may be reused.
- OTP has a nonsecure information-block alias and a secure read alias.
- OTP programming requires a nonsecure transaction.
- RDP2 is not an OTP write lock; documented user execution retains OTP access.
- A write after applicable OTP write protection raises `WRPERR`; the final
  production protection/programmability lifecycle must remain compatible with
  the deliberate FSBL-owned field floor writer.
- GTZC MPCWM, MPCBB, and main-FLASH SECWM do not cover the OTP information
  block.
- STM32U585AI OTG_FS is not a DMA bus master.

Therefore:

- an unauthorized writer cannot modify a valid existing floor record downward;
- it may consume virgin cells;
- without record authentication it may forge a high record and brick admission;
- hardware SECDED does not make an arbitrary partial program a valid logical
  record, prove retention margin, or replace the structural/replica codec;
- there is no direct target-side "make OTP secure" watermark.
- authoritative rollback records MUST remain in OTP. An erasable main-flash
  mirror may be a cache or journal only and may never replace the OTP root.

### 12.2 Master closure

The relevant STM32U585AI masters are:

- Cortex-M33 NS CPU: excluded from the OTP alias by SAU;
- GPDMA1: arbitrary-address AHB master with reset-default nonsecure channels;
- DMA2D: internal-flash-capable AHB master;
- SDMMC1/2 IDMA: internal-flash-capable independent masters;
- LPDMA1: cannot reach flash/OTP and is not part of OTP closure;
- OTG_FS: not a U585 bus master;
- debug/DAP: controlled by final RDP lifecycle.

Whether each independent master can reach the OTP information-block aliases,
and whether the proposed secure/privileged/locked configuration blocks it, is
a silicon question. The test in Section 13 must validate the complete master
set. Until then, project documentation may say "master closure designed" but
not "OTP is GTZC protected," "GPDMA reaches OTP," or "master closure proven"
as an established production fact.

### 12.3 Current capacity envelope

No production 32-QW ownership map is frozen yet. The following numbers are a
provisional capacity-planning upper-bound assumption pending `OPEN-OTP-1`,
`OPEN-OTP-2`, and the final Section-13.4 receipt; they are not an allocation,
writer allowlist, or authority to overwrite any legacy/secret/factory QW. The
selected backend MUST publish all 32 absolute indices, current contents,
owner/purpose, blank/locked status, and rollback role or explicit exclusion,
then replace these estimates. Under the provisional assumption that 27 QWs can
be made exclusively available to rollback records without conflicting with any
other owner:

- provisionally, 27 OTP quad-words are assumed available to rollback records;
- at least one recovery cell is preserved;
- at most 26 clean physical QW programs remain after preserving that reserve;
  because a single-QW committed floor is rejected, the number of logical epoch
  bumps is strictly lower and is determined only by the final group/claim/
  recovery cost;
- canonical `E = 1, F = 0` factory genesis consumes no floor record and, under
  that provisional map, leaves 26 physical QWs, not 26 promised epoch bumps; a higher-epoch genesis consumes
  the selected codec's complete factory group cost;
- torn/poisoned virgin cells reduce remaining capacity;
- an ambiguously attempted all-ones cell counts as unavailable only when the
  approved durable pre-claim/discriminator identifies it; without such a
  mechanism the backend cannot claim safe remaining capacity and stays NO-GO;
- jumping `security_epoch` performs one logical `commit_target(T)`, not one
  commitment per skipped number; its physical cost is codec-defined, while
  changing only `release_version` consumes none;
- every approved replicated format reduces epoch-advance capacity and must
  state its exact clean, degraded, interrupted-write, dead-stage-quarantine,
  replacement-margin, and terminal capacities.
- capacity is computed from the global unique-ownership partition: duplicate
  indices never increase quorum or capacity, and committed, active,
  replacement, consumed/quarantined, and virgin roles are pairwise disjoint;
  compaction may not recycle a quarantined index.

The provisional 26-clean-program number is only a physical-program upper bound, not a
promise of 26 field bumps on any device. Same-epoch releases are not counted
against it. Every durable claim/cursor, incomplete group, rejected ECCC
replica, interrupted-write reserve, and multi-QW commitment reduces the final
logical count and must be included before approval.

For scale only, the frozen Route-1 finite plan uses three target replicas and
one distinct replacement. It requires all three clean plus a durable `COMPLETE` stage before initial
commitment, and permits a two-of-three clean quorum only for later degradation.
It would allow at most `floor(26 / 3) = 8` provisional clean epoch commitments before any
additional accepted-manifest binding, claim, staging, completion, replacement,
or dead-stage-retention cost. A cut between a
replica's EOP and `COMPLETE` treats that replica as uncertain and replaces it;
it does not commit a degraded group. A two-replica scheme has no one-replica-
loss availability margin unless additional durable completion state changes
its decoder semantics. The cardinality and thresholds are frozen; the example
does not approve physical codewords, serialization, capacity, or a production
codec. It shows why the owner must review security and usable epoch capacity
together.

For the frozen minimum plan of three initially clean roles plus one distinct
replacement role, `N` selected rollback QWs provide at most
`floor((N - 1) / 3)` clean commitments because a new plan may begin only while
its replacement margin exists, and `floor(N / 4)` commitments in a scenario
where every successful bump consumes its replacement. At provisional `N=27`,
those are eight and six respectively, before any extra codec-specific OTP
cost. These are risk-planning bounds, not an approved capacity receipt. Before selection the
owner MUST freeze a lifetime revocation budget and require each candidate
report to separate nominal clean commitments, recoverable interrupted
commitments, replacement consumption, worst-case dead-stage loss, and the
terminal `Aborted` state in which exact-floor releases/repairs may continue but
no later security epoch can be committed. Shipping without an accepted final-
epoch/EOL policy is prohibited.

"No OTP record" does not mean unlimited signing: every logical release still
consumes its slot-bound vendor C10 authorization under Section 6.4's global
per-key budget and the finite `R` namespace.

No per-bit unary, ternary, or full-zero extension is valid because a programmed
OTP quad-word cannot be programmed a second time.

The capacity preflight formula is physical, not merely logical. There is one
epoch-bump entry from `Steady`; every exact-floor path is zero-write:

```text
ordinary_new_physical_qws = 0
    when floor_class == Steady(F) and T == F

ordinary_new_physical_qws = codec.target_commit_qws(T)
                          + codec.recovery_margin_qws(T)
                          + codec.accepted_binding_qws(T)
                          + codec.abort_quarantine_reserve_qws(T)
    when floor_class == Steady(F) and T > F

ordinary_new_stage_records = 0
    when floor_class == Steady(F) and T == F

ordinary_new_stage_records = codec.stage_commit_records(T)
                           + codec.stage_recovery_margin(T)
                           + codec.completion_launch_fence_records(T)
                           + codec.abort_chain_retention(T)
    when floor_class == Steady(F) and T > F

repair_new_physical_qws = 0
repair_new_stage_records = 0
    when floor_class in {Steady(F), Aborted(F)} and T == F
    and entry in {PeerRepair, DegradedArtifactRepair}
```

`target_commit_qws` includes every OTP replica normally required for one
successful logical `commit_target(T)`; `recovery_margin_qws` reserves OTP cells
the interruption model can consume or replace. The other QW terms charge the
accepted-artifact authority and capacity that may be stranded by a dead stage.
The stage terms cover selected-route launch-authority/discriminator state
(route-1 preclaim only when applicable), completion, no-launch, abort-chain
authority, and compaction for the one finite plan. No later field epoch plan or
renewed capacity exists after `Aborted`. Route 1 uses the two dedicated pages 64 and
122 and may not borrow another erase unit.
Every term is codec-specific, and preflight must prove both OTP and stage
capacity/health rather than assuming any cost equals one.

Project UI and tooling must report remaining epoch-advance capacity, not
"firmware updates remaining." Device-specific poisoned or quarantined cells
mean a release server cannot promise the exact remaining count for a device it
has not interrogated through a separately authenticated status design.

### 12.4 Option A: MAC-authenticated structurally complete replicas

Potential benefit:

- if a future NS-capable master can program a virgin cell, it cannot forge an
  accepted high floor without guessing the per-device tag;
- physical guesses are limited by the finite virgin-cell count.

Costs and risks:

- protected key provisioning and factory sequencing;
- key-loss/ECC availability failure;
- structural encoding and multi-replica group cost still required;
- FSBL code and flash budget;
- WRP/HDP/SECWM receipt dependency;
- key redundancy requirements;
- capacity exhaustion remains possible.

### 12.5 Option B: plain structurally complete replicated records

Potential benefit:

- smaller immutable TCB;
- no secret key or key-loss brick;
- simpler factory flow.

Costs and risks:

- any future unclosed master may forge a high floor in a virgin cell;
- complement/antichain structure and physical replicas reduce update capacity;
- the entire security argument depends on complete, durable master closure.

### 12.6 Decision rule

Security and immutable footprint are one joint selection gate. No journal,
floor codec, or durable-intent route may be selected on logical safety first
and measured only afterward. Before an option can be final:

1. the Section-13 silicon test completes on a named sacrificial board;
2. both exact independent reviews—Claude Opus 5 (`opus`) at `xhigh`
   effort and
   GPT-5.6 SOL at `ultra` effort—adjudicate the security evidence;
3. every still-viable `(journal, floor codec, durable-intent route)`
   combination receives its own isolated, nonshipping, production-equivalent
   combined FSBL build from one frozen source state, toolchain, linker script,
   release/LTO flags, feature set, 40 KiB FLASH geometry, the exact
   `OPEN-RAM-1` transient-RAM geometry, and real 32-byte vendor key;
4. that combined build includes the manifest-v6 parser and legacy rejection,
   confirmed-preserving selector, selected journal, minimal ECCD-NMI recovery,
   fresh-array per-QW ECCC attribution, complete floor/group/stage decoder,
   completion/replacement and selected durable-intent path (including
   pre-claim machinery only when that route requires it), floor writer,
   dead-stage/no-floor repair logic, orphan scan,
   handoff, measured-boot decoder/table actually proposed, the selected
   master-closure/stale-DMA-abort logic, ES0499 TAMP/BDRST sanitation and IWDG
   restart, the FSBL-resident every-boot option-byte read-back tripwire
   (OPTR/WRP/SECWM/TZEN/BOOT_LOCK/RDP against compiled-in phase-appropriate
   constants, fail-only, never writes — issue #366 row tz-1), and every
   load-bearing trust-root FI check;
5. its report gives the initialized physical FLASH LOAD span from the FSBL
   origin, including vectors, SG stubs, vendor key, `.data` LMA, alignment and
   loadable padding, plus a section/symbol breakdown and device capacity under
   clean and interrupted operation; it separately reports the authoritative
   RAM-mapped allocatable static end/span (including `.uninit`, custom `NOLOAD`,
   gaps, and alignment), the worst-case normal/recovery/ECC-NMI stack bound,
   the selected stack-limit/
   guard policy (including an explicit reviewed omission if applicable), and
   remaining RAM margin;
6. the combined FLASH span is at most 38,912 bytes and the approved RAM/stack
   envelope and margin pass without deleting or weakening a security
   requirement; a candidate above either limit or lacking either combined
   measurement is ineligible;
7. factory and field failure behavior are documented; and
8. the exact clean/interrupted/dead-stage/terminal epoch budget satisfies the
   owner-frozen lifetime revocation policy without consuming reserved recovery
   capacity; and
9. the owner explicitly selects the security/capacity/footprint tradeoff.

For this decision, a "still-viable" combination is one that can authorize a
physical field epoch-bump success path under the frozen layout. Route 1 is
geometrically eligible because Section 5 assigns its pairwise-disjoint pages
64 and 122, but it remains production-ineligible until the two-page protocol,
durability rules, resource fit, and silicon assumptions all close. Route 2 is
a contingent alternative only if it supplies an authoritative discriminator.
Route 3 exposes no epoch-bump writer and is a ship blocker rather than a
production combination. Every viable build includes the full durable stage,
finite-plan/dead-stage quarantine, replacement, completion, accepted binding,
and recovery machinery. Foundation A models every frozen abstract outcome
against fake/scripted backends without selecting a production route.

Section 12.6 is the production-backend finalization gate, not a prerequisite
for Milestone 0's limited nonshipping implementation permission. Milestone 0
exists to produce the concrete combined artifact and measurements this gate
requires. A measurement-driven semantic, interface, margin, or layout change
invalidates that permission for the changed surface and requires a new frozen
digest, both independent architecture reviews, and owner approval before work
continues.

The cross-worktree `38,188` arithmetic in Section 5 cannot satisfy this gate
and says nothing about RAM/stack safety.
An isolated size experiment also confers no implementation approval: the final
Foundation-A production-shared build must reproduce the same metric and limit.
If no security-approved candidate fits, the architecture is NO-GO and must be
simplified or receive a separately reviewed layout redesign; the project must
not recover space by weakening the signature, digest, rollback, ECC, or handoff
checks that protect the immutable trust root.

---

## 13. Sacrificial-silicon master-closure test plan

This test irreversibly consumes OTP cells. It MUST NOT run until the owner names
a specific sacrificial B-U585I-IOT02A by board serial and MCU ID/revision and
explicitly authorizes the exact OTP quad-words. The board MUST be permanently
marked non-production, contain no wallet seed or production SE credentials,
and have a recorded pre-test OTP map. Authorization to consume test cells does
not authorize RDP2 or option-byte changes.

The test image and fixture MUST be explicitly destructive-test-gated and
impossible to include in a production build. Canary values MUST be chosen so
they can never decode as valid rollback records; the test MUST never write a
valid high floor. Do not attach an active debugger during an RDP1 OTP-write
trial when debug/RDP interaction could suppress programming and create a false
pass. Evidence must come from standalone test firmware and the fixture.

### 13.1 Per-master matrix

For each of GPDMA1, DMA2D, SDMMC1 IDMA, and SDMMC2 IDMA:

1. prove the transfer fixture with a positive control against ordinary NS
   SRAM;
2. before lockdown, test OTP-alias read and a canary write to a dedicated
   virgin QW, or capture authoritative controller/bus rejection;
3. configure the production-equivalent closure before NS handoff: abort/reset
   stale work, set the master or every GPDMA channel Secure + Privileged, lock
   the attributes/TZSC configuration, and exact-readback them;
4. prove NS cannot configure or start the master after lockdown;
5. where pre-lockdown read reachability existed, require the post-lockdown
   OTP-to-NS destination remain unchanged;
6. where pre-lockdown write reachability existed, require the post-lockdown
   write target remain exactly erased and capture the expected illegal-access
   or controller evidence, then program that same dedicated canary QW through
   the authorized fixture and verify it succeeds—proving the denied attempt did
   not silently launch and lose an apparently erased cell; and
7. repeat closure and adversarial attempts after warm and cold resets, proving
   closure is re-established before NS runs.

The NS CPU direct read of `0x0BFA_0000` must also be denied by CPU attribution.
LPDMA is outside the OTP path on U585AI. OTG_FS is not tested as an attacker
master because this part has no OTG DMA master; normal USB `1209:7051`
enumeration remains a mandatory coexistence regression test.

### 13.2 Evidence receipt

Capture at least:

- board serial, MCU ID/revision, operator and timestamp;
- test-firmware digest and build features;
- exact option/security registers and lock-bit readback;
- master/channel and source/destination addresses;
- raw OTP snapshot before and after each destructive case;
- observed TZIC, bus, DMA, and FLASH status; and
- warm/cold reset and USB-coexistence results.

Stop immediately on any unexpected OTP change and quarantine the board. One
named part may inform the architecture decision. Before production, the full
master-closure matrix in Section 13.1 and OTP primitive/interruption receipt in
Section 13.4 MUST each pass on at least two parts of every MCU silicon revision
that will ship.

### 13.3 Stop and decision condition

Shipping is NO-GO if any candidate master remains NS-controllable and
OTP-write-capable after production locking, or remains untested. A MAC does not
cure virgin-cell exhaustion. Plain records become eligible only after complete
read/write closure is demonstrated and independently reviewed. MAC records
remain merely an eligible defense-in-depth option and still require an
accepted redundant-key/factory/failure design and measured FSBL cost.
Neither option is production-eligible without the antichain proof, fresh-read
ECCC primitive, full-initial/degraded replica protocol, and an approved
complete-power-loss durable-intent route from `OPEN-OTP-1..3`.
If MAC records are selected, shipping is also NO-GO unless the factory receipt
proves all required redundant rollback-key copies are present,
integrity/KAT-valid, and readable under final protections. The blank-bank
keyless `F = 0` recovery rule does not satisfy this provisioning gate.

This master-closure test does not by itself resolve `OPEN-OTP-3`. Production
also requires the fresh-read ECCC primitive, antichain record proof, ordered
replica/completion protocol, and a complete-power-loss intent/discriminator
route. Finite reset/power-cut receipts can reject a candidate design but cannot
alone prove lifetime absence of a marginal exact or all-`0xFF` outcome.

### 13.4 OTP primitive and capacity characterization

On the same or another explicitly named sacrificial U585AI, and only under a
separate exact-QW authorization, the receipt MUST confirm the assumptions that
make bit-packing invalid and interrupted-cell handling load-bearing:

1. program one canary quad-word once, then attempt both an additional bit-clear
   and a full-zero reprogram; both must produce the documented OTP `PROGERR`,
   leave the accepted data unchanged, and never be used as valid floor records;
2. interrupt a dedicated OTP program at controlled cut points and characterize
   raw bytes, `ECCC`/`ECCD`/NMI behavior, `FLASH_OPSR` behavior after system
   reset, and behavior after complete power loss—the result is not assumed to
   be one deterministic ECC pattern merely because the reference manual says
   contents are not guaranteed;
3. validate a production-identical per-QW read sequence that clears stale ECC
   flags, forces a new array access despite cache/current-buffer effects,
   attributes the recorded address before any intervening flash read, and
   classifies corrected all-`0xFF` as degraded rather than virgin;
4. feed every observed interrupted outcome—including all-`0xFF`, structurally
   partial, ECCC-corrected exact `T`, and ECCC-clean exact `T`—through the
   production decoder; every possibly interrupted QW has zero quorum weight;
   loss of the highest committed group's clean quorum yields `Unknown`; an
   incomplete frontier with intact prior committed quorum and one exact bound
   completable stage yields `Recovering`; exact finite-plan exhaustion with
   no-completion-launch evidence yields `Aborted`; an invalid/ambiguous/
   replayed stage or uncertain completion yields `Unknown`; and no case returns
   an older or unauthorized higher floor;
5. exhaustively or machine-check the selected record code under the 1→0
   erased-to-programmed partial order: no strict prefix toward any role/target
   may decode as any valid record;
6. cut every replica write and every durable reservation/stage/`COMPLETE`/
   compaction transition, then cut again during recovery; prove no uncertain QW
   is retried, no group is initially committed below its full clean threshold,
   later tolerated degradation preserves the same target, and journal loss or
   rollback halts rather than lowering the floor; mutate prior-group digest,
   generation/cursor, group/candidate binding, and every cell-role index to
   prove stale stages, duplicate/overlapping quorum cells, replacement aliases,
   orphan cells, incomplete dead-plan quarantine, false plan exhaustion,
   uncertain-COMPLETE-to-Aborted transitions, and consumed/quarantined reuse
   are rejected; cut every ordinary one-plan launch class (reservation, claim,
   stage body, stage activation, completion authority, accepted binding,
   compaction, and OTP program), every zero-floor-write repair lifecycle, and
   each recovery path a second time; cached or serialized
   old `DeadStageProof` values must fail after every such mutation. For Route 1,
   cut both page erases, every body/digest/footer/activation write, the
   one-new/one-old interval, the interval after both activations but before OTP
   launch, the OTP transaction, and outcome recording, then cut again during
   journal recovery. No reboot may reconstruct `OtpLaunchAuthority`, lose a
   prior claim, or make a claimed all-`0xFF` QW virgin;
7. prove an ordinary fresh `Steady(F) -> SameEpoch { T == F }` entry executes
   none of the OTP or durable-stage writer/compaction paths, including on
   exhausted or degraded devices;
8. treat cut testing as falsification/characterization, not proof that a
   retention-marginal or launched-all-`0xFF` class is absent for product life;
   any design relying on absence needs an authoritative STM32 guarantee and a
   quantitative production reliability argument in addition to board receipts;
9. review the then-current STM32U575/U585 device errata, including ES0499, for
   OTP, flash programming, ECC, reset, cache, and debug/RDP interactions;
   archive the exact official PDFs with revision and SHA-256 and map every
   load-bearing erratum title used by this design to the section number in
   that archived revision rather than inheriting moving section numbers; and
10. publish the final 32-quad-word production map and recalculate nominal,
   recoverable, replacement-consumption, dead-stage-loss, and terminal epoch-advance
   capacity after every reservation and recovery margin; and
11. validate the bounded nonsecure transaction so it accepts only the
   authority-bound OTP address and codeword, remains unreachable from ordinary
   NS/runtime/NSC code, preserves the selected master closure, and consumes the
   authority on every reset, fault, non-return, or ambiguous-status path.

Nothing in this section authorizes an OTP write. A test plan, build, or fixture
must not infer authorization from the existence of this specification.

---

## 14. Staged implementation milestones

### Milestone 0: specification approval

No production-shared rollback implementation code starts until:

- a candidate-final document is frozen under one full SHA-256 digest;
- Claude Opus 5 (`opus`) at `xhigh` effort,
  and GPT-5.6 SOL with `ultra` reasoning effort, independently inspect that
  same frozen digest and approve it or issue explicit red lines;
- the owner resolves every required red line, then the resulting changed text
  is re-frozen and rechecked by both reviewers (or separately approved by both
  as the final digest); no materially changed draft inherits an earlier
  approval;
- the owner explicitly approves the final digest in the separate immutable
  approval receipt; Section 19 remains historical/pending text and is not
  edited after review to create a digest cycle;
- `FROZEN-MAN-4` has exact approved schema/domain/offset/CRC bytes;
- `FROZEN-JRN-IFACE-3` and `FROZEN-OTP-API-3` have exact typed authority,
  terminal-first, dead-stage, and no-floor repair semantics,
  while
  `OPEN-JRN-HW-1` and `OPEN-JRN-DUR-1` must close before the TAMP/marker
  backend is production-eligible;
- the exhaustive Section-5 geometry and updater mutation allowlist are frozen;
- `OPEN-RAM-1` and Section 5 define the provisional nonshipping resource
  envelope and the final no-waiver gate;
- the document names every remaining open decision honestly.

After this digest is approved, the abstract interface/resource freeze is
provisional and implementation authority is limited to isolated
no_std pure cores, host models, fake/scripted backends, QEMU, slot-specific
linkers/tooling, production compile fences, and nonshipping size experiments.
Those implementations MUST embody the frozen abstract interfaces but MUST NOT
select or simulate away an unresolved physical success condition. They confer
no physical-backend, production, release, or hardware authority. It is
permission to build and measure the artifact needed for Section 12.6, not a
promise that the provisional interfaces or envelope fit. Any resource-driven
change to semantics, authority, layout, margin, or a frozen interface stops
that work and requires a new digest, both named reviewers, and owner approval.
Any hardware
write still requires the separate named-board/QW authorization in Section 13.

After the minimum abstract skeleton and conservative reservations exist, but
before a destructive Section-13 fixture runs, a physical backend is selected,
or a candidate family receives substantial implementation investment, Section
5's early combined FLASH+RAM
warning build MUST be recorded. A red warning triggers design simplification/
deferral review; a green warning is not Milestone-0 closure and grants no code
or hardware authority.

### Foundation A: nonshipping rollback core and physical-backend closure

Scope:

- clean slot-bound manifest-v6 format signing canonical `(R,E)` under a new
  domain, with legacy formats rejected;
- implement the reviewed pure `FROZEN-JRN-IFACE-3` decoder and
  `FROZEN-OTP-API-3` state machine against fake/scripted storage first;
- composite terminal-first journal decoder,
  five-QW lifecycle, full/surviving install and terminal evidence,
  robust-only boot selector, dead-stage quarantine, and exact no-floor
  repair entries;
- PENDING/ATTEMPTED transition intents and writers only against abstract or
  explicitly nonshipping fake/QEMU backends until `OPEN-JRN-HW-1` and
  `OPEN-JRN-DUR-1` close;
- minimal recoverable ECC-NMI reads and per-QW fresh-array ECCC attribution
  under `OPEN-ECC-1`;
- implement only the reviewed `OPEN-RAM-1` linker/stack-bound/guard policy and
  preserve the runtime's approved handoff limit; no silent SRAM enlargement;
- runtime floor writer removal;
- compile-time and build-script quarantine rejecting `mode-production`, a real
  vendor key, release packaging, or direct-Cargo production routing together
  with any legacy/unresolved rollback backend; Makefile refusals are defense in
  depth, not the sole fence;
- FSBL-only idempotent abstract epoch-floor interface whose ordinary
  `start_from_steady` `SameEpoch { T == F }` path issues no OTP program command
  or durable stage write and whose `T > F` path performs one logical target
  commitment for `T > F` using the approved codec's explicitly measured
  reservation, replica, completion, replacement, and recovery cost;
- resolve `OPEN-ECC-1` and `OPEN-OTP-1..3` through isolated models,
  measurements, and authorized evidence; freeze the exact selected read
  primitive, record/group code, durable-stage state machine, capacity, and
  interruption behavior in a reviewed spec digest; only then implement a real
  physical writer in production-shared code. Until then, production and
  real-vendor-key builds compile-fail on every epoch-bump success path;
- implement the Milestone-0-approved `OPEN-REL-1` canonical A/B release-set,
  signing-ledger, advisory/epoch, inspector, and package gates before any
  production signature;
- production-equivalent master closure plus the explicitly authorized
  Section-13 test when the owner names a sacrificial board;
- retain the reviewed sentinel/double-evaluation checks on vendor signature,
  signed digest/image binding, rollback admission/establishment, and final
  handoff; only broader per-callsite FI and remanence expansion is deferred;
- no repository-wide formatting;
- no expanded reset assembly, persistent demotion, unreviewed fingerprint-
  table optimization, or broad FI layer in the rollback series.

No field health path writes `CONFIRMED` in Foundation A. Production remains
blocked until every open physical-storage/ECC decision and the later full
health milestone pass.

In Foundation A, "model the frozen semantics, then resolve and implement the
physical backend" is strict ordering. Pure code cannot choose an unresolved
record codec, durability discriminator, or hardware behavior. Foundation A's
physical half cannot close on host/QEMU evidence; the selected backend needs
every required Section-13 receipt and both exact adversarial implementation
reviews defined below.

Every binding implementation-review gate in this section uses the same exact
independent pair as Section 19: Claude Opus 5 (`opus`) at `xhigh`
effort and GPT-5.6 SOL with `ultra` effort. Both receive the
same frozen implementation-diff digest and neither receives the other's report
before issuing its own digest-bound verdict. The initial pair may approve only
the nonshipping abstract software core while physical gates remain open; a
later selected physical backend and any materially changed diff require fresh
reports from the same pair. No nonshipping verdict approves hardware use or
production shipment.

Stop unless:

- the initialized physical FSBL FLASH LOAD span, measured as Section 5 defines
  it and including real vendor key, vectors, SG stubs, data LMA, alignment, and
  padding, is at most 38,912 bytes;
- the complete RAM-mapped allocatable static span plus the worst-case normal/
  recovery/ECC-NMI stack bound, reserved guard, and frozen margin fits the
  approved FSBL SRAM window, and the selected guard decision and fault/handoff
  behavior pass on target;
- both A and B secure/NS images link;
- all executed selector/journal/floor tests pass production-shared logic;
- QEMU power-cut/fallback scenarios pass;
- exact silicon ECC recovery and OTP receipts pass when authorized;
- both exact adversarial reviewers above approve the same frozen
  implementation-diff digest at the authority level then available.

Before the first non-destructive rollback-validation run on hardware, the
Foundation-A host behavioral suite and QEMU power-cut suite MUST be green, the
real-key production-profile FSBL MUST link at no more than 38,912 bytes, and
the static/worst-case stack report MUST pass the approved `OPEN-RAM-1` gate,
and both A/B secure and NS images MUST link at their exact addresses. Hardware is
not used to discover an already-red host state or conceal a footprint failure.
This ordering does not authorize, or change the separate owner authorization
required for, any destructive Section-13 OTP test.

### Milestone 1: local health integration

Implement Section 8 on top of the accepted physical foundation. The result is
volatile local-health evidence only; no device build contains a local-only
confirmation shortcut. Re-run the ARM budget, zeroization, PIN/SE, fallback,
and adversarial gates.

### Milestone 2: defined probation-boundary closure

Scope:

- restricted probation lifecycle;
- USB and NS boot while wallet authority remains unavailable;
- human-bound challenge;
- two-way gateway round-trip;
- bounded retries/deadline;
- trusted-display finalization;
- clean fallback UX.

Stop unless:

- a good update with an unresponsive companion reverts cleanly;
- wrong, replayed, duplicate, timeout, cancellation, and malformed cases are
  executed;
- signing/address/update commands are centrally rejected in probation;
- real USB hardware round-trip passes on STM32U585AI;
- every reset/power cut inside the validated retained-token envelope after exact
  `ATTEMPTED` and before exact `CONFIRMED` selects the old slot when its own
  confirmation authority remains independently valid; outside that envelope,
  the frozen ES0499 cold-boot sanitation policy destroys retry authority before
  token decode and then applies the same floor-class/fallback rules;
  the sole-authority degradation case halts as specified by
  `OPEN-JRN-DUR-1`; pre-`ATTEMPTED` cuts follow Sections 6/11's exact retry-or-
  ignore rules because no candidate handoff occurred; post-confirmation floor
  cuts follow Sections 10–11 and may reach `Steady`, continue `Recovering`,
  enter exact `Aborted` with its constrained exact-`F` accepted/service and
  no-floor repair paths, or halt on `Unknown`; they never
  boot through unresolved floor state;
- product documentation exactly names the proven coverage boundary;
- both exact adversarial reviewers above approve the same frozen Milestone-2
  implementation-diff digest.

Only after Foundation A and Milestones 1 and 2 may a production build write
`CONFIRMED` and establish `F == E - 1` under this specification. Same-epoch
establishment writes neither OTP nor durable stage state; an epoch bump
performs the reviewed reservation and replicated commitment protocol.

### Later separately reviewed stages

- targeted FI hardening beyond the load-bearing trust-root checks retained in
  Foundation A, with one demonstrated fault path per added countermeasure;
- expanded reset-remanence assembly with on-silicon proof;
- persistent grace/demotion as an explicit downgrade/recovery product feature;
- prefix-4 or any further BIP-39 fingerprint-format optimization beyond the
  landed base-27 packing, with exact FSBL/secure-world output parity,
  all-entry vectors, and measured net size;
- broader DMA closure not required by the settled STM32U585AI master model.
- OPTIGA/SE050 rollback counters or hybrid OTP checkpoints; these require a
  separate immutable-boot architecture and are not a fallback shortcut for
  Foundation A.

No later stage may consume the 2 KiB core headroom without a new budget plan.

---

## 15. Acceptance and evidence matrix

### 15.1 Host-executed behavior

Tests MUST execute production-shared logic rather than merely search source
text. Required coverage includes:

- all exact and malformed composite manifest/TAMP state tuples;
- exact pinning of all three 16-byte marker codewords, every single-bit mutation,
  erased/zero/ECCC/ECCD classifications, all three state pairs, both slot
  pairs, every complement/seal/reset intermediate, the 139-byte `PQFW_A3` plus
  `CLEAN10` preimage, and its frozen binding digest;
- every prefix of token invalidation/rebinding/activation, including reinstall
  of byte-identical signed artifacts, fails backward rather than decoding as a
  forward state;
- interrupted TAMP Ready→Attempted outcomes: exact ready retries, while exact
  attempted, lost, binding-mismatched, or malformed tokens fall back;
- token loss/VBAT drain/tamper/backup-reset before Ready→Attempted rejects the
  candidate and requires a new PIN-gated reinstall rather than falsely taking
  the exact-ready retry path;
- ES0499 marginal VDD/VBAT traces never let unpredictable backup state enter
  the token decoder: the selected reviewed Section-3 protected-`MONEN`,
  unconditional forced-`BDRST`, or separately re-frozen conditional
  forced-`BDRST` policy sanitizes first. Conditional policy tests freeze and
  exercise every reset input and complete canary/integrity/CRC representation;
  no generic `integrity-test` branch exists. Forced BDRST makes only a
  candidate with both confirmation replicas `BlankVirgin` ineligible;
  `Steady` or exact
  constrained `Aborted` may then select the fallback, exact terminal
  set authority ignores the token, and `Recovering`/`Unknown` still prohibit
  handoff. Later mutable boot reloads BHK before BHK-derived use;
- NS/unprivileged writes cannot change `PWR_BDCR1.MONEN`, TAMP zone/privilege
  settings, or `BKP8..31`; DBP is cleared and read back before every handoff,
  while every TAMP configuration RMW preserves `BHKLOCK` and counter fields;
- exhaustive four-class floor/stage decoding: `Steady(F)` reaches ordinary
  admission; exact completable stage yields bound `Recovering`; exact dead
  pre-`COMPLETE` plan with no-launch proof yields `Aborted`; invalid, orphaned,
  multiply active, rolled-back, target-inconsistent, or completion-ambiguous
  evidence yields `Unknown`;
- a fully blank ECC-clean OTP bank plus the synchronized active factory
  Route-1 `BASE0` pair, with proof that no durable-intent state or writer launch
  is missing, returns canonical `Steady(0)`; the first active target may bind
  that exact `BASE0` as `prior_group`, while blank OTP readback or erased-
  looking Route-1 pages never reconstruct the base;
- every `Recovering` transition monotonically consumes its finite plan and
  reaches fresh `Steady(T)`, exact `Aborted`, or `Unknown`; only `Aborted`
  admits the independently verified exact-`F` fallback, and no possible-
  completion-launch trace can construct it;
- one-plan death yields the single stable `Aborted` class only with complete
  permanent failed-plan ownership/quarantine and no possible completion launch;
  reboot, reinstall, higher `R`, compaction, or fresh preflight cannot construct
  `T > F` authority from it, while exact-`F` accepted boot and the two
  named no-floor repair classes remain available;
- mutation tests reject every stale prior-group digest, allocation generation/
  cursor, active-group/candidate identity, and cell-role-map replay; duplicate
  QW indices, cross-group overlap, source/replacement alias, consumed-or-
  quarantined reuse, an orphan nonblank/corrected QW, incomplete whole-plan
  quarantine, false exhaustion, and one QW counted twice toward quorum all
  yield `Unknown`; compaction preserves the global ownership/quarantine partition;
  after authoritative `COMPLETE`, every safe compaction prefix preserves
  `Steady(T)` from an old copy and never reuses epoch-advance `Recovering`, while
  loss/ambiguity of all authoritative copies is `Unknown`;
- exhaustive two-slot selector combinations and confirmed recovery ordering;
- pending-only and multiple-pending rejection when no confirmed fallback
  exists;
- equal-`R` and both crossed `R/E` PENDING tuples are ignored when a valid
  confirmed fallback exists, including the same release's other-slot artifact;
- selection chooses among `RobustAccepted` artifacts by higher `E`,
  higher `R`, then physical slot A for exact `(R,E)` equality;
- manifest-v6 golden vectors shared by signer, inspector, firmware, FSBL, and
  formal extraction; mutation of slot, `R`, `E`, either signed length, either
  image hash, vendor-key fingerprint, schema, or domain breaks the signed
  binding, and every legacy schema is rejected;
- vendor-key tests prove the fingerprint is only compared with the immutable
  embedded firmware-vendor key, never selects another key, and no wallet or
  health C10 key can authorize a manifest. They pin
  `SHA-256("PQFW_VK_V6" || pk_seed[16] || pk_root[16])` and reject the legacy
  unprefixed formula, wrong domain, swapped halves, and every non-vendor key;
- the checked-in key-matched positive manifest-v6 C10 fixture executes through
  the real verifier and is accepted only under its dedicated nonproduction
  vendor key, while wrong-key, signature-bit, domain/schema/slot/tuple/length/
  image-hash mutations and every legacy retry fail. The patterned `i mod 256`
  serialization fixture is exercised only for layout/CRC/journal tests and is
  never counted as a signature KAT;
- product-namespace tests pin the device namespace to the exact
  `(PQFW_V6, embedded vendor-key fingerprint)` pair, reject every other domain
  or key on device, and make signing-ledger/build gates reject assigning that
  same pair to another product while still charging all domains sharing the
  physical key to its one global C10 budget;
- state-appropriate verification tests prove a valid PENDING/ATTEMPTED slot
  needs its exact journal/TAMP evidence but no confirmation evidence, while a
  CONFIRMED slot needs typed terminal authority and cannot
  borrow PENDING/ATTEMPTED evidence;
- ordinary probation tests prove the only PENDING handoff from `Steady(F)`
  consumes `CheckedSteadyProbationIntent`, first has an independently verified
  confirmed fallback with target exactly `F`, performs no floor/stage/OTP
  mutation, bypasses capacity preflight exactly when `T == F`, and carries a
  fresh snapshot-bound read-only complete one-plan preflight
  receipt exactly when `T > F`. It requires a new complete `Steady(F)` decode,
  both artifact reverifications, and a still-current bump receipt after exact
  ATTEMPTED. The consumed proof cannot be reused to boot the fallback after an
  arming failure;
- `ArtifactEvidenceKey` swap tests reject lifecycle evidence from slot A paired
  with artifact B, equal `(R,E,T)` with different image bytes, a prior page
  generation, a prior boot/snapshot, or another marker address; private proof
  types cannot be copied, cloned, serialized, or replayed after mutation. A
  fresh recheck preserves the expected `ArtifactIdentity` but necessarily
  issues a different pass key/receipt set; candidate and fallback evidence
  cannot be joined to each other merely because they share a floor snapshot;
- `RuntimeArtifactEvidenceKey` tests independently reject candidate/fallback
  swaps, cross-pass receipt sets, stale runtime IDs, changed floor snapshots,
  changed `BootFlashEvidenceSummary`/epoch, immutable-key substitution, and any
  attempt to use a runtime key at an FSBL proof API. Candidate and fallback
  runtime artifact/lifecycle joins must each be internally byte-equal and must
  remain distinct through receipt consumption;
- install-identity tests reject companion/package-supplied, all-zero, all-one,
  non-complement, corrected, conflicting, repeated, and may-have-launched
  evidence. Before activation, only a complete exact pair is valid. After
  PENDING or terminal evidence, tests accept the narrowly qualified
  `SurvivingInstallGeneration` from one clean nontrivial half, reject both-half
  loss, and reject the impossible ordering in which the missing half is proven
  `BlankVirgin`; the writer still never retries either ID QW in place. Field
  COMMIT tests prove
  exact TAMP INVALID is written and twice read back before RNG generation or
  either install-ID program launch. `InvalidatedToken` tests inject arbitrary,
  stale, zeroed, and complement-invalid `BKP8..29` bodies and prove this first
  observation validates only stable exact `INVALID` in `BKP30/31`; the body is
  opaque until rewritten, and neither `InvalidatedToken` nor the ordinary
  decoder can construct ARM_READY, ATTEMPTED, candidate, probation, or handoff
  authority. A byte-identical full-range erase/reinstall receives a
  fresh ID and cannot borrow the old floor accepted-manifest binding or a
  prior-generation TAMP/lifecycle proof;
- pre-PENDING staging power-cut tests interrupt erase/program at every manifest-
  body, CRC, secure-image, and nonsecure-image page/QW, including outcomes that
  later read exact with ECCC clear. No rebooted attempt resumes any such byte;
  the next authenticated BEGIN erases/verifies every page in the inactive
  manifest and full secure/nonsecure capacity ranges, fully restages, and
  leaves every page outside the inactive allowlist untouched;
- all five full-page manifest-v6 fixtures retain `CRC=0x5F7DEB92` while
  producing the frozen distinct page SHA-256 values: blank journal
  `632e90f280c80ce6843aa5a5e679658295f3738b8ee27a058fb8baff3a44e25f`,
  ID+PENDING `02aa62037bf01285f3a09cbbd1292f1995a1b3d21141a8af8dee528710d822be`,
  plus replica 0 `b10c7bdf879e5cce6abb8a20558e339d8023c2b04b1a11dc0032871b9d5e83d6`,
  the replica-1-only negative writer-order fixture
  `84738dd794722e9025341214410faeb2dfbe0f4e2794f80c13cc80e2fdbe4845`,
  and both replicas
  `e7f9b80d21d0a24cf3a84ec76a2b62cd19c6f22464515039c7ea77fa198a8db6`.
  Tests pin offsets
  `4192/4208/4224/4240/4256`, QWs `262..266`, the normalized 80-byte
  `4192..4272` window, and the trailing-reserved boundary;
- exhaustive `E > F` admission and checked `T = E - 1`, including both
  reserved sentinels, base `E == 1, F == 0`, numeric jumps, and integer
  ceilings;
- the private floor writer independently rejects every `R` or `E` outside
  `1..=0xFFFF_FFFE` and every derived `T > 0xFFFF_FFFD`, even when its caller
  supplies a faulted/prevalidated object;
- runtime cannot call a floor writer;
- the ordered `CandidateFinalizationWriter` rejects a wrong running slot, non-`ATTEMPTED`
  or binding-mismatched token, changed `(R,E,F)`/classification, loss or
  mismatch of the probation-bound exact-`F` fallback's artifact or current
  terminal confirmation authority, failed bump-capacity recheck,
  absent/forged/incomplete local-health, transport, transcript, deadline, or
  long-confirmation typestate, user cancel, and any nonblank/ambiguous
  destination. No direct status/boolean path can construct
  `HealthAndUiApproved` or `RuntimeFinalizationReceipt`; ordinary probation
  also requires fresh matching `Steady(F)`, while every repair requires its
  fresh matching floor/source/high-water/package evidence and exact zero-write
  disposition. Tests exercise the linear chain receipt -> replica-0 receipt ->
  replica-1 receipt, cuts at both launches, and the prohibition on in-place
  retry. No sole-authority loss is converted into promotion;
- probation-handoff/finalization tests mutate every stable candidate,
  source, confirmation-authority, floor/abort-chain, high-water, archived-
  package, preflight, boot-evidence, zero-write disposition, and entry-kind
  field and require refusal.
  They also mutate/omit/reorder every `LocalHealthEventRecord` step and dry-run
  disposition, local completion/deadline relation, session/attempt phase,
  duplicate and transcript digest leaf, active deadline, page sequence,
  long-confirmation event, cancellation race, and terminal phase. Tests prove
  every predecessor value is linear and consumed, exact duplicates cannot
  construct a second proof, local deadline expiry after timely local completion
  does not invalidate a still-live finalization window, and finalization-window
  expiry before the writer's fresh re-sample always refuses. They prove no
  linear FSBL proof/pass key crosses handoff, the runtime receipt contains the
  complete recomputed health/UI transcript plus distinct same-pass candidate/
  fallback joins, prior flash operations are quiescent, ECCD is caught by the
  probation NMI owner, and no intervening unowned flash data-array probe,
  flash program/erase, floor-state mutation, or second receipt use reaches the
  two-replica writer. The reviewed SRAM-resident
  writer stub is copied and integrity-checked before receipt construction.
  Tests prove maskable interrupts are disabled, the SRAM VTOR/vector table and
  unavoidable NMI/HardFault handlers are integrity-checked, and the complete
  writer call graph, literals, data, stack, exception frame, timeout/readback/
  cache/relock path resides outside the busy bank. Injected unexpected
  exceptions, vector corruption, and attempted busy-bank dependencies consume
  authority and fail closed without reprogramming, ordinary-runtime return, or
  success. Ordinary reviewed instruction fetches before entry to that stub
  remain governed by Section 9.2's ECC-owner and status-failure rules;
- a torn or apparently-erased PENDING, `CONFIRMED_0`, or `CONFIRMED_1` marker is never programmed
  again; a later field retry requires the complete inactive-range erase/restage
  rule, and offline factory recovery likewise repeats the complete affected-
  slot manifest + full secure/nonsecure capacity erase/restage;
- incoming packages with any stamped marker/install-identity journal QW are rejected even though
  CRC normalization ignores the window; replacement of a previously confirmed
  inactive slot succeeds only after complete inactive-range erase/restage and
  new-generation proof;
- canonical all-`0xFF` immutable-body QWs are deliberately left erased after
  the whole-page new-generation erase, are still covered by signature/CRC, and
  are never confused with journal `BlankVirgin` authority or programmed later
  within that generation; every non-all-`0xFF` body/CRC QW is programmed once;
- an interrupted marker that later returns exact bytes with `ECCC` clear is
  classified `UnknownMayHaveLaunched` unless the selected durability witness
  proves it clean; it never confirms or advances the floor from bytes alone;
- immutable reset-entry tests snapshot the single common `FLASH_OPSR` once
  before any later flash mutation and exhaust `CODE_OP`/`SYSF_OP`/`BK_OP`/
  `ADDR_OP` attribution for both bank-selector values,
  and prove an interrupted manifest QW cannot be rewritten or masked by an
  exact-looking read; complete-power-loss tests separately omit OPSR evidence;
- after an epoch floor binds an accepted manifest, loss/degradation of one
  confirmation witness removes that artifact's boot authority; the
  accepted-manifest binding is an evidentiary record only and can never
  authorize a different same-floor artifact or lower `F`;
- completed dual-robust factory/same-epoch states lose either one terminal
  replica and classify that artifact through `SurvivingTerminalSet` as
  repair-target evidence only; any robust peer
  outranks degraded evidence. Degraded-only state exposes no boot, updater, or
  wallet authority. `Recovering` candidate loss of robust authority
  before `Steady(T)` leaves the floor view `Recovering` but makes the checked
  join yield `RecoveryBlocked(MissingRobustTerminalAuthority)`/halt with no
  write, fallback, or handoff;
- checked-recovery tests prove only a fresh `RecoveryProof` joined to the exact
  proof-bound artifact and `RobustAccepted` terminal authority constructs
  `CheckedRecoveryIntent`; missing/degraded/wrong-artifact/wrong-epoch
  authority produces `RecoveryBlocked`, and raw or cross-snapshot proofs cannot call
  the writer. After every zero-weight or terminal role consumption, tests
  recompute the full finite plan: a nonempty legal completion plan alone yields
  `Recovering`, all dead-stage predicates including no completion launch yield
  the state-appropriate `Aborted`, and every other case is `Unknown`; an empty
  or mathematically non-completable `RecoveryProof` is impossible;
- terminal-first tests probe both confirmation replicas before PENDING/TAMP;
  a valid full/surviving terminal set ignores torn, corrected, or ECCD PENDING,
  while an uncertain terminal observation never falls through to PENDING.
  `CONFIRMED_1` with replica 0 proven `BlankVirgin` is rejected as impossible;
- after a valid `FullTerminalSet` or permitted `SurvivingTerminalSet`, every
  TAMP value—including lost, malformed, stale, or rebound—is ignored under the
  retained writer model;
- a post-confirm reset primitive that unexpectedly returns cannot re-enter NS,
  normal dispatch, or wallet authority and reaches only the terminal locked
  watchdog/halt path;
- ordinary `Steady(F) -> SameEpoch { T == F }` confirmation never enters the OTP writer, OTP unlock, durable
  reservation/stage writer, or stage-compaction path across repeated boots,
  including when no virgin record cell remains;
- entry instrumentation proves same-epoch `CheckedSteadyIntent` performs zero
  preflight and zero `begin`, fresh epoch-bump entry invokes `begin` at most
  once, and `resume_from_recovery` invokes neither ordinary preflight nor
  `begin` across any number of resets;
- `Aborted` boot tests prove `boot_accepted_from_aborted` emits only
  non-authorizing stable comparison data after a final fresh `Aborted` decode,
  and that `Aborted` admits no new-release path: every attempted new-release
  admission from `Aborted` rejects before mutation;
- `PeerRepair` tests require the protected archived opposite-slot A/B twin,
  equal `(R,E,T)`, exact `T=F`, independent slot-bound signature/images, full
  erase/restage, fresh identity, and complete probation. No source marker or
  health result is copied, and this is the only equal-`R` PENDING exception;
- `DegradedArtifactRepair` tests forbid in-place marker repair, require a
  robust source and exact archived target package, and rerun complete
  probation. Under `Aborted`, exact `T=F` and zero backend writes are mandatory;
  under `Steady`, a repaired `T>F` artifact can enter only a later ordinary
  one-plan `start_from_steady` action after it becomes robust. Every attempted
  `T>F` constructor from `Aborted` fails before mutation;
- an epoch bump invokes exactly one logical `commit_target(T)` and the
  codec-declared number of physical QW programs; numeric epoch skips do not
  multiply either cost, and old epochs become inadmissible only after the
  logical target is durable;
- same-epoch tests cover preferred-slot absence, corruption, independent
  invalidity, and an older `RobustAccepted` artifact beside a newer
  degraded repair-target artifact; selection follows the frozen tuple order
  among robust artifacts. No
  user input, reinstall, boot chord, or lower-`R` request alters that order;
- updater high-water tests boot an exact-`F` fallback beside a still-valid
  higher CONFIRMED peer after a proven-no-establishment-launch capacity
  failure. Packages newer only than the running fallback, equal to the peer,
  lower in `E`, or crossed between the separate live maxima are rejected
  before erase; a package with `R_new` above every valid confirmed artifact and
  nondecreasing `E_new` is eligible. A non-CONFIRMED failed generation may
  still retry its same signed release with a fresh install identity;
- commitment idempotency and conditional replica/stage/recovery-margin
  preflight;
- deterministic capacity/key/backend failure while the decoder remains
  `Steady(F)` and before any reservation/stage/claim/compaction or OTP write may
  have launched boots only an independently verified confirmed fallback with
  `T_fallback == F`; absence of that fallback halts, and any possibly launched/
  ambiguous establishment write never takes that ordinary fallback path;
  after an initial-plan launch, only fresh exact `Aborted` can authorize the
  same target-`F` accepted path, and no `Aborted` proof can authorize another
  epoch-advance plan. Completion
  ambiguity remains `Unknown`/halt;
- the per-QW ECC reader clears stale flags, forces a fresh array access despite
  flash-buffer/cache reuse, attributes the matching QW, and classifies
  every ECCC-corrected result—including returned exact `T` or all-`0xFF`—as
  degraded/consumed rather than clean or virgin;
- a corrected or unreadable highest-floor replica contributes zero quorum
  weight: remaining clean replicas either establish the same `T`, or the floor
  is `Unknown`; the decoder never returns an older `F`;
- every strict 1→0 partial-program prefix of every record role/target fails the
  antichain decoder rather than becoming `T` or any `V != T`; every valid role
  clears at least one bit, an all-`0xFF` role payload is rejected by both
  encoder and writer, and erased bytes never decode as a role;
- initial commitment requires the full clean replica threshold and durable
  completion state; only later degradation may use the separately approved
  lower threshold;
- a possibly interrupted exact-`T` QW has zero quorum weight; target authority
  comes only from durably logged clean pre-cut replicas plus selected-route-
  authorized clean replacements under a fresh full-threshold `COMPLETE`;
- a may-have-launched all-`0xFF` QW is never treated as reusable from readback
  alone; tests cover the approved durable pre-claim/discriminator or assert the
  epoch-bump ship blocker;
- Route-1 tests accept only two synchronized active generation-zero factory
  snapshots as canonical `BASE0`; they cut both factory writes under the boot
  hold, cut the first field preclaim from the active base, and reject every
  erased-looking reconstruction;
- every Route-1 preclaim, outcome, `COMPLETE`, accepted-binding, close, and
  compaction copy-on-write transition is cut at both pages and cut again during
  recovery. A valid newer direct predecessor governs while an inactive/torn
  newer write leaves the older active snapshot authoritative; recovery retains
  the governing page and rewrites the missing/older page first. Persisted pages
  never mint `OtpLaunchAuthority`, and no second cut forgets or retries a
  claimed QW;
- every claim/cursor/stage/`COMPLETE`/compaction transition is cut again during
  recovery and cannot authorize same-QW retry, degraded initial commit, or a
  lower floor;
- under a MAC codec, a fully blank record region plus the synchronized active
  factory Route-1 `BASE0` pair and a missing key decodes read-only canonical
  `Steady(0)` only when durable-intent state proves no writer state/launch is
  missing or active; erased-looking Route-1 pages, any nonblank, stage-active,
  or ambiguous region plus missing key fail closed and no commitment is
  permitted;
- under a MAC codec, factory/ship validation rejects missing, blank, corrupt,
  single-copy when redundancy is required, KAT-invalid, or unreadable rollback
  key material even though the runtime blank-bank decoder still yields `F = 0`;
- `HEALTH_BEGIN` correlation/idempotency and busy behavior;
- `HEALTH_COMPLETE` parsing, atomic bounded-comparison consumption, replay binding,
  deadline transitions, command allowlist, exact post-success duplicate-tag
  acceptance, and different post-success transcript rejection;
- for builds including the SHOULD-level dry-run, the firmware-selected UserOp,
  Safe/EIP-712, and ERC-7730 vectors traverse production parsers/renderers at
  runtime into the bounded internal sink and match their frozen page digest/
  shape; injected parser, root, expected-output, or sink failure blocks epoch-
  bump confirmation without releasing authority; waived builds instead prove
  off-device that the reviewed policy ledger and finalized release receipt
  bind the exact artifact/build, while the on-device transcript records only
  `WaivedByReviewedBuildPolicy`; evidence discloses the absent coverage without
  synthesizing a pass;
- the dedicated `FROZEN-HLT-1` health-key budget proof covers the configured worst-case
  lifetime number of PIN-gated re-arms and never borrows the vendor-key cap;
- zeroization and no-output behavior on probation failures.
- the shared flash-layout registry accounts for all 256 pages exactly once;
  updater mutation is confined to the inactive manifest/secure/NS ranges; both
  40,960-byte FSBL copies including vendor key are byte-identical; dual WRP
  fields and factory ordering are pinned in host receipt tests.

Release-process tests MUST additionally reject a missing/stale/broken policy
ledger, history modification relative to the trusted checkpoint, duplicate or
concurrent `R` reservations, namespace/domain/vendor-key mismatch, stale valid
checkpoint replay, tuple reuse with different bytes, epoch decrease, terminal
counter use without its EOL ceremony, unapproved epoch skip, a security
advisory without a bump, an unjustified bump, same-epoch classification that
lacks explicit acknowledgement, A/B mismatch, one-slot-only partial
finalization/publication, duplicate critical archive entries, and unsigned or
inconsistent metadata. Positive tests cover the canonical
`R1/E1 -> R2/E1 -> R3/E2 -> R4/E2` sequence, atomic A/B finalization, and
archived byte-identical republication with zero private-key operations. A/B
signing consumes exactly two authorized slot-bound C10 signatures; a partial
ceremony is durably reflected in the global per-key tally, and signing refuses
at the reviewed cap.

The release-ledger suite MUST also reject a publication identity derived from
the finalized record being constructed, every other cyclic package/record hash
graph, and any device build/profile exposing factory-stamping authority.
Positive factory tests use only offline host tooling, require the production
ship fence plus lifecycle-lock receipt, and never expose a device command.

Source-invariant tests MAY supplement but never substitute for behavioral
tests.

### 15.2 ARM build and footprint

- FSBL release link with real-size vendor key.
- For each materially distinct viable family, the early nonshipping combined
  warning build records its actual linked components, conservative placeholders,
  uncertainty range, physical FLASH span, static RAM end/span, worst-stack
  estimate, and stop/escalation result; it is never reported as final fit.
- Every still-viable journal/codec/durable-intent combination has an isolated
  production-equivalent combined build before selection; unmeasured and
  over-limit combinations are rejected.
- The selected Route-1 production-equivalent FSBL candidate reproduces an initialized physical FLASH LOAD
  span at most 38,912 bytes under the frozen production toolchain, linker,
  release/LTO flags, and feature set, counting vectors, SG stubs, vendor key,
  `.data` LMA, alignment, and loadable padding.
- The same combined build reports the exact approved FSBL SRAM window,
  authoritative end/span of every RAM-mapped allocatable section (including
  `.uninit`, custom `NOLOAD`, gaps, and alignment), compiler/binary worst-case
  normal and recovery call chains, hand-written/indirect-call allowances,
  ECC-NMI exception nesting, selected stack-limit/guard policy, reserved guard,
  and remaining frozen margin.
- On-target stack-pattern high-water tests cover valid A/B boot, both-invalid
  failure, C10 verify, measured display, active recovery, malformed records,
  and injected recoverable ECC NMI; they corroborate the static bound and do
  not replace it. A configured guard violation fails closed; an explicitly
  reviewed guard omission is recorded and relies on the mandatory static bound
  and margin. Handoff installs/preserves the runtime's separately approved
  stack-limit policy.
- Slot A and B secure images link under production features.
- Slot A and B NS images link at their exact addresses.
- Both full 40,960-byte physical-bank FSBL images, including the vendor key,
  are byte-identical; no legacy 32-KiB/old-manifest/boot-state/64-page-NS
  constant survives any geometry consumer.
- Factory, signer, updater, inspector, and FSBL generate byte-identical signed
  preimages for the same physical-slot artifact; slot-A and slot-B preimages
  are intentionally distinct.
- The measured report separates code/rodata and records any independently
  landed BIP-39 bit-packing saving rather than assuming its gross table delta.
- The report maps each load-bearing trust-root FI check retained in the build
  and proves no size optimization removed or weakened signature, digest,
  rollback, ECC, or final-handoff validation.
- The measured FSBL includes the actual master-closure/stale-DMA abort path,
  ES0499 sanitation, IWDG restart/readback, orphan scan,
  one-plan `Aborted`, and exact-`F` repair logic; none may be a zero-byte placeholder
  in the final gate.
- No untracked source file is omitted from the owner diff.

### 15.3 QEMU/integration

- candidate crash before local health -> old slot;
- local health failure -> old slot;
- local pass but NS boot failure -> old slot after reset;
- absent/unresponsive companion -> bounded timeout and old slot;
- three invalid canonical challenge comparisons -> old slot; the first two
  retain the same challenge/session/deadline and fixed remaining budget;
- attempts to skip, forge, replay, duplicate, or reorder any
  `ProbationHandoffBinding -> LocalHealthPassed -> ActiveHealthSession ->
  TransportPassed`, `TransportPassed + LongConfirmApproved ->
  HealthAndUiApproved`, or `HealthAndUiApproved ->
  RuntimeFinalizationReceipt -> replica-0 receipt -> replica-1 receipt`
  transition never obtains robust confirmation out of order; timely local
  completion remains valid across its expired historical window, while expiry
  of the active transport/finalization deadline before the SRAM writer's fresh
  sample always reverts;
- valid defined health + same-epoch confirmation -> no floor record and new
  higher-`R` slot;
- canonical blank ECC-clean OTP bank plus the synchronized active factory
  Route-1 `BASE0` pair -> `Steady(0)` and normal `E=1` genesis boot; erased-
  looking Route-1 pages or a blank-looking OTP bank after possible
  establishment launch never recreate it;
- valid defined health + epoch bump -> one logical target commitment with the
  codec-declared physical record cost, then rejection of the old epoch;
- lagging device `R1/E1/F0` installing `R3/E2` after skipping `R2/E2` -> device
  classifies from signed `E` and local `F` as an epoch bump, despite `R3` being
  same-epoch relative to the immediately preceding ledger release;
- proven-no-launch fallback boot with a still-valid higher CONFIRMED peer ->
  updater refuses every incoming tuple not strictly above the maximum live
  confirmed `R` and nondecreasing from the maximum live confirmed `E`, before
  erasing that peer;
- same-epoch preferred-slot absence/corruption/independent invalidity -> older
  same-epoch confirmed fallback; older `RobustAccepted` plus newer
  degraded repair-target artifact -> older robust slot; demotion/reinstall requests never
  override the frozen tuple order;
- `CONFIRMED(A,R5,E2) + PENDING(B,R5,E2)` and crossed pending tuples -> ignore
  pending and boot the confirmed slot rather than halt;
- crossed two-confirmed tuples -> boot higher `E`; equal `(R,E)` -> fixed slot
  A;
- captured same-epoch UI says older same-epoch releases remain admissible only
  if otherwise valid/present; captured epoch-bump UI shows exact `T` and lower-
  epoch fallback retirement;
- power loss after each journal and OTP transition, including marker writes
  that later appear erased;
- ambiguous OTP interruption never retries the same cell without approved
  durable evidence;
- ECCC on the sole/highest witness returns `Unknown`, not an older floor;
  approved remaining clean quorum returns the same `T`;
- cuts at every replica, stage body/activation, `COMPLETE`, and close/compaction
  transition never commit below the full initial clean threshold; a possibly
  interrupted exact-`T` or all-`0xFF` replica has zero authority; exact bound
  completable stages return `Recovering`, exact dead/no-completion-launch plans
  return `Aborted`, ambiguous stages return `Unknown`, and only authoritative
  completion evidence can yield `Steady(T)`;
- ordinary fresh `Steady(F) -> SameEpoch { T == F }` QEMU traces invoke neither
  OTP nor persistent-stage writes;
- proven-no-establishment-launch epoch-bump preflight failure—decoder remains
  `Steady(F)` and neither stage/reservation/claim/compaction nor OTP write may
  have launched—with a confirmed `T_fallback == F` slot boots that fallback on
  repeated boots; any pre-`COMPLETE` establishment-state or OTP write that may
  have launched never takes that fallback and resumes only through the approved
  zero-weight/replacement/full-threshold/fresh-`COMPLETE` recovery protocol,
  reaches exact `Aborted` and only then boots a robust target-`F` artifact, or
  halts. QEMU separately cuts every `PeerRepair` and
  `DegradedArtifactRepair` staging, activation, ATTEMPTED, health, and both-
  terminal-replica transition; each failed trace preserves the source and
  floor class, every successful `Aborted` repair retains `Aborted` and records
  zero rollback-backend operations, and every attempted `T>F` entry from
  `Aborted` rejects before mutation. Post-`COMPLETE` compaction separately preserves
  `Steady(T)` and handoff from an old authoritative copy or returns `Unknown`;
- probation dispatch rejects every wallet authority command;
- crash/reset from exact `ATTEMPTED` falls back without re-arming; every later
  field reinstall or new `ARM_READY` creation again requires the production
  PIN/unlock gate, while an exact pre-handoff `ARM_READY` retry is separately
  tested as the no-handoff case;
- old runtime reports a failed probation clearly;
- after floor establishment, loss of the accepted artifact's terminal-set
  quorum leaves no boot authority and halts to service; mutation to another
  same-floor manifest or image halts without lowering the floor.

### 15.4 Real STM32U585AI evidence

- complete A/B update on the B-U585I-IOT02A;
- owner-authorized factory receipt for byte-identical bank-1/bank-2 FSBL
  copies and exact WRP1A/WRP2A pages 0–4, SECWM/HDP, BOOT_LOCK,
  `SWAP_BANK=0`, and `SECBOOTADD0`, including cold-reset readback and negative
  program/erase attempts on authorized sacrificial parts;
- factory Route-1 genesis cuts cover both active generation-zero `BASE0` page
  writes under the external boot hold; every cut forces complete two-page
  factory restart, and normal FSBL boot never decodes an intermediate or
  erased-looking page pair as `BASE0`;
- factory genesis cuts cover every secure-image, nonsecure-image, manifest-
  body/CRC, install-ID, PENDING, `CONFIRMED_0`, and `CONFIRMED_1` write for both slot-bound A/B
  packages independently; any restart performs complete manifest + full
  secure/nonsecure capacity erase/restage, PENDING is durable before replica 0,
  replica 0 is durable before replica 1, no marker QW is retried in place, six
  marker receipts are recorded, and a non-robust slot intermediate is never
  accepted as shippable genesis;
- the external factory boot-hold/lifecycle interlock is asserted before the
  first slot write and remains continuously asserted through both slots'
  durable confirmation and complete readback; loss, premature deassertion, or
  unverifiable interlock state never permits boot of a one-slot intermediate
  and invalidates the factory receipt;
- completed dual-slot genesis loses either one terminal replica: the
  independently verified robust peer outranks the degraded artifact, and
  degraded-only state halts to service with no degraded acceptance. Loss of
  every applicable terminal-set authority halts;
- USB enumeration and defined health round-trip;
- physical cancel and timeout;
- controlled reset/power interruption at each safe test point;
- deliberately torn inactive-manifest ECCD is rejected while the independently
  valid fallback boots;
- TAMP-token loss, tamper erase, backup-domain reset, NS denial, and BHK
  coexistence;
- ES0499 VDD/VBAT-window characterization and the selected reviewed Section-3
  cold-boot policy, including `VBSEC` protection for a retained-`MONEN` design
  or the exact unconditional/conditional forced-`BDRST` sequence; a conditional
  policy additionally characterizes every frozen reset input and its complete
  canary/integrity/CRC representation. Evidence also covers DBP
  clear/readback before NS and BHK
  regeneration after forced backup-domain reset; the receipt also covers
  tamper-flag capture/escalation before sanitation, SRAM2/PKA-SRAM/ICACHE erase,
  IWDG stop/restart timing, `SPRIV`, and exact MCU revision applicability;
- measured backup-domain retention on the production VBAT/supercapacitor
  design records the supported retry window and demonstrates clean fallback
  after deliberate drain; the unmodified development kit is not cited as
  evidence of the production retention envelope;
- `OPEN-PIN-HW-1` receipts prove attempt-neutral preparation without
  `VerifySession` or counter mutation and cut every one-attempt MCU/OPTIGA/
  SE050 boundary; reboot reconciliation retains strictest debt, issues no
  second permit, and validates the real SE050 success-reset and wrong-PIN/
  lockout statuses on explicitly authorized nonproduction hardware;
- production `tamp-wipe` profiles explicitly account for the existing shared
  intrusion-wipe escalation: a confirmed tamper may factory-reset the secure
  elements, which is orthogonal to the A/B selector and does not make the
  candidate confirmed or retire the old slot; destructive wipe evidence uses
  a separately authorized non-production device/fixture;
- no unlocked/signing state during probation;
- measured boot fingerprint consistency;
- FSBL stack high-water and the selected `MSPLIM`/equivalent guard policy
  (including the explicit rationale if hardware guarding is omitted) under
  normal, recovery, malformed-slot, and recoverable ECC-NMI paths, including a
  clean transition to the runtime's approved stack-limit policy;
- OTP snapshots around an authorized same-epoch update prove no record change;
- OTP snapshots around an authorized epoch bump prove exactly the reviewed
  record transition, subject to the approved reservation/replica/recovery
  design;
- production-identical fresh-array reads demonstrate reliable per-QW
  `ECCC`/`ECCD` attribution despite flash-buffer/cache effects; corrected
  exact/all-`0xFF` outcomes never count as clean/virgin;
- replica-loss tests preserve the same target at the approved degraded
  threshold and return `Unknown` rather than an older floor below it;
- independent sacrificial-board master closure and OTP
  primitive/interruption characterization under Section 13; production
  evidence covers at least two parts of every MCU silicon revision shipped;
- no regression of trusted UI, PIN lockout, SE tunnels, or USB coexistence.

### 15.5 Formal evidence

Formal models must state exactly what they prove. A private-channel ordering
model does not prove the implementation, namespace/global release-process
monotonicity, capacity, or
power-cut behavior. Domain-separation and extracted signed-preimage
differentials may be retained when connected to production bytes. Any state
model must separate release preference (`R`) from epoch admission (`E > F`) and
must model same-epoch no-write separately from epoch-bump commitment. The OTP model
must prove the selected code is an antichain under 1→0 partial programming,
distinguish initial completion from later degraded quorum, give every uncertain
or corrected QW zero weight, and make loss of top-floor quorum produce
`Unknown` rather than an older floor. It must also model `Steady`, bound
`Recovering`, exact `Aborted(DeadStageProof)`, and `Unknown` as mutually
exclusive and complete boundary classes: a frontier is never committed,
`Recovering` never invokes the selector, and `Aborted` requires mathematical
death of the one finite plan, complete permanent quarantine, and proof that no
completion authority may have launched. `Aborted` preserves unchanged `F` but
cannot construct `T>F` or any rollback-backend writer authority. The model
separately proves `PeerRepair` and
`DegradedArtifactRepair`: each requires its exact source/package/high-water
bindings, full probation and both terminal replicas, and zero rollback-backend
writes when entered from `Aborted`. No repair copies confirmation authority or
repairs a marker in place. Ordinary confirmed-candidate handoff requires
`Steady(T)`.
It must bind each stage to the exact prior-group identity and allocation generation and
prove a global unique physical-QW ownership partition: no duplicate quorum
index, cross-group/source-replacement alias, consumed-cell reuse, or stale
stage/compaction replay or orphan physical cell is accepted. It must prove the
authoritative committed group binds at most one exact accepted manifest and
cannot authorize another slot, install identity, `(R,E,T)`, digest, or image after terminal-set
degradation. Every artifact/lifecycle proof join for one artifact and one pass
in immutable/FSBL code must use one equal `ArtifactEvidenceKey`; a wrapper may
instead carry distinct candidate/fallback keys tied to the same boot/floor
snapshot. Runtime finalization joins must use the separate equal
`RuntimeArtifactEvidenceKey` for each artifact/current runtime pass and consume
both keys into the receipt. Neither key type is accepted by the other domain.
Rechecks compare stable `ArtifactIdentity` and issue a fresh domain-appropriate
pass key. Cross-slot/artifact/generation/snapshot/pass or immutable/runtime-key
joins are unconstructible. Floor proofs are linear,
boot-scoped capabilities. Ordinary
probation consumes its `SteadyProof` through the sole checked arming entry and
must freshly decode `Steady(F)` plus reverify the exact-`F` fallback before
ATTEMPTED handoff. Same-epoch arming has no capacity receipt; epoch-bump arming
must produce and revalidate the snapshot-bound read-only receipt for exactly
one complete finite plan without invoking a persistent writer. No parallel
selector path may mutate TAMP or reuse the consumed proof. The model preserves
cumulative quarantine across `Aborted` and rejects cached proof/context values
after every floor/journal mutation. It distinguishes the consumed immutable
`DeadStageProof` from stable non-authorizing comparison context and the
class-specific runtime staging/activation receipts. Only a completed staging
session plus fresh class validation may write install identity, TAMP, and
PENDING once; no such receipt authorizes terminal confirmation, floor/stage/
OTP mutation, probation, or handoff, and reset destroys the chain. The model
also recomputes the complete
finite plan after every terminal role: `Recovering` requires a remaining legal
completion sequence, `Aborted` requires all dead-stage/no-completion-launch
predicates, and every other case is `Unknown`. `RecoveryBlocked` models a
failed artifact/robust-terminal-authority join outside `FloorView`; it is not a fifth
persistent decoder class. Ordinary updater replacement
must derive separate maxima across every independently valid CONFIRMED live
artifact and require `R_new` strictly above the live maximum with nondecreasing
`E_new`; a fallback cannot erase a still-valid higher confirmed peer for an
archived intermediate tuple.
The Route-1 model cuts every sequential page erase, body/footer/activation
write, synchronized-pair check, OTP transaction, and recovery convergence. It
proves that one authoritative snapshot survives an incomplete rewrite, that a
direct-predecessor pair selects the newer active snapshot, that persisted
state cannot reconstruct `OtpLaunchAuthority`, and that a second cut cannot
forget or retry a may-have-launched QW.
Post-`COMPLETE` maintenance must preserve `Steady(T)` from an authoritative old
copy until its disjoint replacement is durable; it is never modeled as an
epoch-advance `Recovering` transition.

---

## 16. Security invariants

An implementation conforming to this specification maintains:

1. Runtime firmware never advances, lowers, resets, or reinterprets `F`.
2. FSBL establishes only checked `T = E - 1` for a release with exact typed
   `RobustAccepted` confirmation authority. Initial establishment requires
   `FullTerminalSet`. It
   never establishes for `PENDING`, `ATTEMPTED`, malformed, or merely
   Milestone-1-ready firmware.
3. Ordinary admission occurs only from `Steady(F)` and requires `E > F`.
   `Recovering` bypasses the selector; exact `Aborted` permits only robust
   exact-`F` accepted boot and the two typed
   no-backend repair paths. It cannot construct `T > F`; `Unknown` halts. `R`
   cannot override a rejected epoch.
4. In normal ledger-consistent states, `R` determines preference among epoch-
   admissible releases. Only `RobustAccepted` artifacts are bootable;
   among them FSBL chooses higher `E`, then `R`, then slot A.
5. After `OPEN-JRN-HW-1` closes, a candidate receives at most one probation
   boot before its terminal-replica sequence. No at-most-once claim is made for an
   unsanitized ES0499 marginal backup-power state.
6. Every reset inside the validated reset/retention envelope after exact
   `ATTEMPTED` and before confirmation makes that candidate ineligible; exact
   `ARM_READY` may retry only before any handoff. A detected or ambiguous cold
   backup-domain power event is sanitized before token decode and loses retry
   authority. It selects the fallback/reinstall path only under `Steady` or
   exact constrained `Aborted`; other floor classes retain their no-handoff
   semantics.
7. The previous robust confirmed source remains eligible through probation and
   the confirmation writes only while its own full-terminal
   confirmation authority remains valid. This is not a continuous redundant-
   witness guarantee; loss of robust source authority halts probation rather
   than promoting the candidate, and no degraded service
   boot remains. After same-epoch finalization it remains floor-eligible;
   it is not user-selectable while a newer valid release is preferred;
   after durable higher-epoch establishment every slot with `E <= F` is
   ineligible.
8. An ordinary fresh `Steady(F) -> SameEpoch { T == F }` establishment consumes
   no rollback record and issues no OTP program command or persistent
   reservation/stage write. Capacity exhaustion cannot turn that no-op into
   failure while the existing floor remains readable and valid.
   Authorized exact-`F` repairs under `Aborted` obey the same zero Route-1,
   stage, compaction, OTP-window, and OTP-program rule.
9. Each epoch-bumping confirmation performs exactly one logical
   `commit_target(T)`. The number of valid physical records, replicas, claims,
   and loss/replacement/degradation cells is exactly the cost admitted by the approved
   codec and interruption model; no one-record assumption is implicit. Initial
   commitment requires the full clean threshold and durable completion state;
   only a previously completed group may use its approved degraded threshold.
   No strict 1→0 partial-program prefix decodes as any valid floor record, and
   every valid role clears at least one bit so erased all-`0xFF` is never a role. One
   physical QW has one global role/owner and counts at most once; stage replay,
   group/replacement overlap, orphan cells, and consumed/quarantined reuse are
   invalid. A finite plan terminates in `Steady`, exact `Aborted`, or `Unknown`.
   One begin charges exactly one finite plan, including replacement margin and
   permanent quarantine. Plan death preserves all owned roles and creates no
   renewed capacity or `T>F` constructor. Class-specific runtime staging and
   activation receipts may write only the exact inactive install identity,
   TAMP token, and PENDING once; they authorize no confirmation, floor
   mutation, probation, or handoff, and FSBL rederives a new immutable proof
   before probation.
   Post-`COMPLETE` maintenance preserves authoritative `Steady(T)` until a
   disjoint replacement is durable or returns `Unknown`; it is not an
   epoch-advance `Recovering` state.
10. Under Draft 1.1's retained writer model, field-update confirmation replicas
    are written in order only by the running secure candidate after bound `ATTEMPTED` and
    consumption of the private linear `ProbationHandoffBinding ->
    LocalHealthPassed -> ActiveHealthSession -> TransportPassed`,
    `TransportPassed + LongConfirmApproved -> HealthAndUiApproved`, and
    `HealthAndUiApproved -> RuntimeFinalizationReceipt` chain. The final receipt
    binds the independently recomputed complete health transcript, canonical
    page sequence, long physical approval, active deadline, and fresh artifact/
    floor evidence. The SRAM writer re-samples deadline/phase, writes
    `QW_CONFIRMED_0`, consumes its separate receipt to write
    `QW_CONFIRMED_1`, and never retries either QW. This is runtime-issued
    terminal evidence, not proof that FSBL observed the health transcript. The sole
    non-field writer is the offline factory exception in Section 7.4. After a
    terminal-write sequence, runtime cannot return to NS or ordinary wallet execution before
    a reset through FSBL.
11. Manifest mutations are one-shot exact codewords; before exact
    terminal authority, both confirmation replicas must be proven
    `BlankVirgin`, and the frozen rewritable TAMP transition accepts only
    exact bound states, starts every rebind from exact invalidation, and every
    other state fails toward the fallback. Terminal-first decode independently
    probes `_0` and `_1` and never reads PENDING/TAMP after a valid terminal
    set. After confirmation the token
    and historical PENDING are ignored. No TAMP state is interpreted
    before the selected ES0499 cold-boot sanitation and protection readback.
12. No wallet authority or signature is released during probation.
13. The defined production confirmation requires typed timely local health,
    at most three valid comparisons against one fixed challenge/deadline, and
    explicit trusted-display acceptance;
    no bare digest, phase enum, boolean, duplicate response, or companion value
    can construct the next proof. NS traffic cannot extend probation or brute-
    force the human challenge.
14. A missing or broken companion causes a safe false negative, never a
    confirmation.
15. The FSBL always fits within its immutable physical region with required
    headroom. Security and footprint are selected jointly from isolated
    production-equivalent combined builds; the independently measured BIP-39
    saving and cross-worktree arithmetic do not replace the final physical
    LOAD-span measurement. The selected transient SRAM geometry also contains
    the complete RAM-mapped allocatable static span plus the statically bounded
    worst-case normal/recovery/ECC-NMI stack, reserved guard, and frozen margin;
    any configured guard fails closed, while omission requires explicit review.
    Both complete physical-bank copies including vendor key are byte-identical,
    every flash page has one owner, and the production receipt protects pages
    0–4 under both WRP1A and WRP2A plus the frozen boot/security configuration.
16. OTP claims distinguish target-side protection from master-by-master
    closure and remain open until silicon evidence exists.
17. A corrected, unreadable, or possibly interrupted OTP QW contributes zero
    clean quorum weight and is never reused merely because returned bytes read
    erased or exact. `ECCC`-clean exact bytes alone are not durability proof.
    Remaining independent clean replicas may establish only the same target
    under the approved completed-group threshold. A valid in-progress durable
    completable stage returns bound `Recovering`; a mathematically dead plan
    returns `Aborted` only with no-completion-launch proof and full quarantine;
loss of authoritative state returns `Unknown`. None lowers `F`. A launched-all-`0xFF`
    ambiguity requires an approved pre-claim/discriminator or keeps field
    epoch bumps blocked. No programmed OTP QW is treated as a bitwise multi-
    update counter. Under Route 1, `OtpLaunchAuthority` exists only after both
    sequential copy-on-write pages have been rewritten and freshly verified as
    one matching preclaim in the same boot. Persisted or mixed-generation pages
    never mint it; recovery retains the governing active snapshot and rewrites
    the missing, inactive, or older page first. After offline factory `BASE0`
    provisioning, no Route-1 write occurs for a field `T == F` path.
18. The availability claim is phase-scoped by `OPEN-JRN-DUR-1`: it does not
    promise survival when every robust accepted authority
    is lost during staging/probation, and
    it ends at the defined probation boundary rather than
    promise recovery from a bug unique to the first ordinary post-establishment
    wallet lifecycle. The anti-rollback claim is epoch-granular, not release-
    granular.
19. The private irreversible-floor path independently revalidates the complete
    `R,E` range and checked `T` range before any write; upstream validation or
    a typed caller object is never its sole sentinel defense.
20. Canonical `Steady(0)` requires a fully blank ECC-clean OTP bank, the
    synchronized active factory Route-1 `BASE0` pair, and proof that no
    establishment writer state may be missing; all-`0xFF` bytes or erased-
    looking Route-1 pages never recreate the base. Fallback from a higher confirmed
    candidate requires `Steady(F)`, no unresolved maintenance compaction, and
    proof that neither pre-`COMPLETE` durable establishment state nor OTP
    programming for the target may have launched, in addition to an
    independently verified confirmed fallback with target `F`. The sole
    post-launch fallback exception is a fresh decoder-issued
    `Aborted(DeadStageProof)`, which carries that unchanged floor and excludes
    the failed candidate/twin.
21. A committed epoch group's accepted-manifest binding, whether exposed by
    `Steady` or carried as the authoritative predecessor of exact `Aborted`, binds at most one
    exact slot/install-id/tuple/digest/image set as an evidentiary record only. It cannot
    initialize a commitment, grant boot or admission authority after terminal-set
    degradation, authorize another same-floor artifact, or revive
    an epoch at or below `F`.
22. The updater mutates only the inactive manifest/secure/NS ranges in the
    exhaustive map. Under the external boot hold, factory genesis first
    provisions both active generation-zero Route-1 `BASE0` snapshots, then
    installs both independently slot-bound A/B
    artifacts and, for each, writes and validates PENDING before writing
    `QW_CONFIRMED_0` and then `QW_CONFIRMED_1`; an external boot-hold/lifecycle interlock remains asserted
    from before the first slot write through dual-slot durable confirmation and
    readback. A one-confirmed-slot intermediate cannot boot or ship, and no
    uncertain marker QW is retried in place.
23. `Aborted` is terminal for epoch advancement but not for exact-`F`
    availability. `PeerRepair` and
    `DegradedArtifactRepair` may restore a robust accepted artifact only
    through complete restage, one-shot probation, full health, and both
    terminal replicas, with zero rollback-backend writes. No such path can
    construct `T>F`, lower `F`, directly copy confirmation, or revive
    quarantined capacity.

---

## 17. Non-goals

This specification does not add:

- EntryPoint migration;
- wallet-key rotation;
- persistent user demotion or rollback grace;
- a secure-world USB stack;
- proof that an untrusted companion is honest;
- automatic recovery without a reset when a candidate hangs before watchdog
  initialization;
- irreversible per-release rollback prevention among releases intentionally
  sharing one `security_epoch`;
- more epoch-bumping floor commits than the final OTP codec and device-specific
  reservation/replica/recovery state physically supports;
- OPTIGA/SE050 rollback counters in the first implementation;
- broad FI or remanence defenses without separate evidence;
- any page allocation beyond the exhaustive Section-5 map, or reuse of either
  dedicated Route-1 page by another owner.

---

## 18. Review questions for both independent adjudicators

Each reviewer must answer:

1. Does the four-state composite representation admit any sequence that
   retires a lower-epoch fallback before exact defined health?
2. Is the frozen-but-hardware-gated secure TAMP token safer and smaller than a
   separately erasable flash journal, given that secure privileged runtime can
   rewrite it?
3. Do resets and power cuts inside the validated retained-token envelope, plus
   every tamper, BHK-load, and token-transition ordering case, preserve at-most-
   once probation, while out-of-envelope or ambiguous cold-boot cases sanitize
   token state under the frozen ES0499 policy before decode?
4. Can NS or the companion self-confirm without learning the display-only
   challenge through the human path?
5. Are `HEALTH_BEGIN` idempotency and the fixed maximum of three valid
   `HEALTH_COMPLETE` comparisons against one unchanged challenge/deadline both
   guess-resistant and tolerant of realistic USB loss?
6. Does any probation command release wallet authority, reset the active
   deadline, or construct confirmation authority without consuming the exact
   linear local-health, bounded-attempt transport, transcript, page-sequence, and
   long-approval proofs? Does the writer freshly reject a deadline that expires
   after receipt construction but before programming?
7. Is the defined health boundary and its FSBL-stable/runtime-mutable evidence
   split implementable without changing FSBL state semantics?
8. Is the post-establishment ordinary-wallet residual stated honestly and
   narrowly?
9. Are false-negative outcomes clean and user-comprehensible?
10. Is the OTP record-format decision correctly left open, and is the master
    list complete for STM32U585AI?
11. Does the OTP abstraction actually permit safe cross-power-loss intent and
   replica recovery, or must the core state machine expose more durable state?
12. Is the minimal ECC-NMI recovery contract implementable and testable without
    reintroducing the deferred broad hardening?
13. Does the offline factory exception require both independently slot-bound
    A/B artifacts to pass PENDING, `CONFIRMED_0`, then `CONFIRMED_1` before shipment, reject every
    one-slot intermediate, and keep universal confirmed `F = E - 1`
    establishment sufficient and non-bypassable?
14. Before any durable establishment-state or OTP write may launch, does the
    selector ignore every non-qualifying pending tuple and deterministically
    order confirmed slots by higher `E`, then `R`, then fixed slot A? If
    preferred-floor establishment cannot start while the decoder remains
    `Steady(F)`, does it boot only a separately verified confirmed fallback
    with target exactly `F`? After a pre-`COMPLETE` stage/claim or OTP write may
    have launched, does it forbid ordinary fallback/handoff, recover through
    fresh full-threshold `COMPLETE`, or enter `Aborted` only after finite-plan
    death plus proof no completion authority launched? Does `Aborted` permit
    only robust exact-`F` accepted boot, degraded exact-`F` service boot, and
    the three typed zero-backend repair paths, while making every `T>F`
    constructor impossible? Do class-specific staging and activation receipts
    authorize only complete inactive restage plus install identity/TAMP/PENDING,
    with FSBL freshly rederiving the immutable class before probation? Does
    post-`COMPLETE` compaction instead preserve
    `Steady(T)`/handoff from an authoritative old copy or return `Unknown`,
    never `Recovering`?
15. Does the joint security/footprint gate measure every viable combined
    journal/codec/durable-intent TCB by physical production-equivalent LOAD
    span and worst-case RAM/stack, reject anything above the approved FLASH or
    SRAM envelope, and forbid buying space by weakening a trust-root check?
    Does the earlier combined warning build surface likely NO-GO paths without
    relying on cross-worktree subtraction or being mistaken for final fit?
16. What requirement should be removed or simplified because its own
    complexity creates greater risk than the path it closes?
17. Are `R`, `E`, `F = rejected_through_epoch`, and `T = E - 1` used without
    any minimum-allowed/off-by-one ambiguity in every state and tool?
18. Does an ordinary fresh `Steady(F) -> SameEpoch { T == F }` release provably
    issue zero OTP program commands, durable reservation/stage writes, or stage
    compaction, including with exhausted capacity and across repeated boots,
    and do all authorized exact-`F` repairs under `Aborted` obey the same zero-
    backend invariant?
19. Is the explicit same-epoch rollback-equivalence class an acceptable product
    policy, and can the production signer make advisory-to-epoch decisions
    sufficiently hard to bypass, given that it provides no user demotion and
    permits lower-`R` selection only when no higher-`R` `RobustAccepted`
    artifact exists, including the explicit robust-over-degraded repair order?
20. Is Draft 1.1's ordered runtime-written confirmation-replica chain acceptable under
    the trust model, or does its same-epoch evidence justify the larger
    `HEALTH_PASSED`/`SEALING`/FSBL-writer design despite the extra power-cut and
    immutable-budget surface?
21. Does manifest-v6 perform a clean flag-day cutover with no legacy default or
    ambiguous A/B release-set pairing?
22. Does any claimed BIP-39 bit-packing or prefix saving preserve identical
    FSBL/secure-world fingerprints and count only measured net ELF savings?
23. Under a MAC codec, does a fully blank record region plus the synchronized
    active factory Route-1 `BASE0` pair decode canonical `Steady(0)` without a
    key only when durable-intent state proves no writer state/launch is missing
    or active, while erased-looking Route-1 pages and every nonblank/stage-
    active/ambiguous key-loss case fail closed, and does factory/ship validation
    nevertheless require valid redundant key material under final protections?
24. Does the final OTP interruption design give corrected or possibly
    interrupted replicas zero weight, force fresh-array ECCC attribution,
    prevent loss of top-floor quorum from returning an older `F`, and handle
    apparently erased, exact-looking, poisoned, and second-power-loss outcomes
    without retry, unauthorized advance, downgrade, or hidden capacity?
25. Is the TAMP at-most-once claim scoped honestly to crash/reset behavior,
    PIN-gated reinstallation, and trusted vendor-signed secure runtime rather
    than described as a hardware write-once property?
26. Is `OPEN-C10-1` closed with a concrete global per-physical-vendor-key
    launch cap and accounting rules before signing-authority implementation or
    production key provisioning, without borrowing a wallet-key cap by
    analogy?
27. Does the chosen OTP codec have a machine-checked 1→0 antichain record code,
    a full clean initial-completion threshold distinct from its later degraded
    threshold, and selected-route launch authority that makes every
    may-have-launched all-`0xFF` cell non-reusable—route-1 crash-consistent
    preclaim or an authoritative route-2 guarantee/discriminator? If not, are
    field epoch bumps explicitly blocked rather than justified by finite
    sampling?
28. Are `Steady(F)`, bound `Recovering`, exact `Aborted`, and `Unknown` mutually
    exclusive and complete across every prefix? Is `Aborted` reachable only
    after mathematical finite-plan exhaustion and a durable proof that no
    completion authority may have launched, with whole-plan quarantine,
    candidate/twin exclusion, and no lowering of `F`? Can no constructor from
    `Aborted` authorize `T>F`, while `RecoverySameEpoch`, `PeerRepair`, and
    `DegradedArtifactRepair` each preserve `Aborted`, perform zero backend
    writes, traverse full probation, and obtain both terminal replicas? Does
    canonical base state yield `Steady(0)` only from the synchronized active
    factory Route-1 `BASE0` pair, a blank ECC-clean OTP bank, and proof that no
    writer state is missing?
29. Does the irreversible writer independently reject the complete reserved
    `R,E,T` range even if upstream validation or a typed proof object is
    faulted?
30. Is the epoch-bump canned decode/render dry-run useful and implementable as
    authority-free SHOULD-level defense in depth, and is its inability to test
    real unlock/publish/sign/update dispatch stated without over-claim?
31. Is TAMP's exact-ready retry benefit evaluated against the measured finite
    VBAT/supercapacitor retention window, with token loss on the
    both-confirmation-replicas-`BlankVirgin` probation branch producing a safe
    PIN-gated reinstall rather than a second handoff, while valid terminal-set
    authority ignores the token and floor `Recovering`/`Unknown` still forbids
    fallback?
32. Is OTP-first justified narrowly by the present pre-PIN FSBL architecture
    and current PIN-gated SE counters, while leaving a differently specified
    pre-PIN SE/hybrid architecture as a legitimate future option?
33. Does every stage bind the exact prior committed-group identity (or
    `BASE0`), allocation generation/cursor, candidate/active group, and complete
    physical cell-role map, with global unique QW ownership and no stale-stage,
    duplicate-quorum, cross-group, replacement, quarantine, or compaction
    alias or orphan QW? Are dedicated Route-1 pages 64 and 122 uniquely owned,
    pairwise disjoint, and excluded from every image/updater allowlist?
34. Is `OPEN-RAM-1` closed with an exact transient SRAM geometry, authoritative
    static end/span covering every allocatable/`NOLOAD` section and alignment,
    worst-case LTO stack bound including ECC-NMI exception nesting, nonzero
    margin, on-target high-water corroboration, and a reviewed `MSPLIM`/
    equivalent guard decision plus safe runtime handoff?
35. Does `OPEN-JRN-DUR-1` prevent post-cut exact-looking/ECCC-clear authority,
    probe both confirmation replicas before and independently of PENDING, and
    recover robust authority after terminal-set degradation only from the exact
    install-id-bound accepted-manifest binding in the authoritative committed
    floor group without admitting another artifact or lowering `F`? Is the
    evidence order `RobustAccepted` before `DegradedAcceptedBoot`, with
    degraded-only state restricted to service? Does loss of robust authority
    for a Recovering candidate before `Steady(T)` leave
    the floor view `Recovering` and yield nonwritable
    `RecoveryBlocked(MissingRobustTerminalAuthority)` rather than promoting probation
    state or exposing an older floor?
36. Does `OPEN-JRN-HW-1` apply the correct ES0499 route for the final VBAT
    topology before token decode, protect retained `MONEN` through `VBSEC` and
    privilege controls, scope/clear DBP through one owner, preserve/reload BHK,
    avoid unsafe tamper-source erasure, and prevent every roadmap feature or
    backup-domain CRC from aliasing `BKP8..31`? Does the BDRST route account
    for tamper evidence, SRAM2/PKA-SRAM/ICACHE erase, IWDG timing, and exact
    silicon-revision applicability? Is the exact official ES0499 revision
    archived with SHA-256 and a title-to-section map, rather than relying on
    section numbers copied from a different revision?
37. Does immutable entry snapshot/attribute the single common `FLASH_OPSR`
    once before every later flash mutation, exhaust both `BK_OP` values, and
    keep its system-reset evidence distinct from
    complete-power-loss durability, with no exact-looking interrupted marker
    admitted or reprogrammed?
38. Does the production factory receipt protect byte-identical complete FSBL
    copies including the vendor key on both physical banks with exact
    WRP1A/WRP2A pages 0–4, SECWM/HDP, BOOT_LOCK, `SWAP_BANK=0`, and
    `SECBOOTADD0`, and is every irreversible action separately authorized?
39. Does the shared layout assign all 256 pages exactly once, pin secure A to
    `0x0C00_E000..0x0C08_0000` and secure B to
    `0x0C08_2000..0x0C0F_4000` with exact `0x72000` capacities, uniquely own
    Route-1 pages 64/122, keep both FSBLs and pages 123–127 outside updater
    mutation, reject every legacy geometry, and require both factory A/B
    artifacts to follow PENDING, `CONFIRMED_0`, then `CONFIRMED_1`
    ordering under a continuously asserted external boot-hold through dual-slot
    durable readback, with no same-QW retry, normal boot, or one-slot shippable
    intermediate?
40. Does each physical codec charge accepted-manifest authority, one finite
    plan, replacement margin, recovery, permanent dead-stage quarantine, and
    terminal/EOL capacity; and is the owner-frozen lifetime epoch policy
    realistic rather than derived from the provisional naive 26-QW upper bound?

---

## 19. Approval record

Reviewer A's Draft-0.5 re-adjudication initially returned architecture approval
before its independent OTP prosecutor completed, then transparently superseded
that preliminary verdict with `APPROVE WITH RED-LINES`. The final red-lines
were RL-2a through RL-2d: corrected reads, exact-target retention, structural
record validity, and launched-all-`0xFF` intent.

Frozen Draft 0.6 addressed that family and deliberately sharpened two points.
An ECCC-corrected highest witness is not merely treated as absent—it has zero
weight, and insufficient remaining clean quorum yields `Unknown` rather than a
lower floor. Also, invariant 8 forbids persistent writes only for `T == F`; a
crash-consistent pre-OTP claim on the `T > F` path is a possible, still-open
closure route. Its exact spec and prompt SHA-256 digests were
`b82f4a55917fdc6b2bf76f44f49765fd19b67a866f520ae2a18e252de7e0590d`
and `39f85fccee04a896c27c126873ff0a0ba4bbdfd17feeea67c0ac5bebcc460805`.

Reviewer A approved that Draft-0.6 architecture for open-decision closure,
while correctly withholding implementation approval. Independent Reviewer B
then returned `APPROVE WITH RED-LINES` for the same frozen digest: R1 made
security and physical FSBL footprint a joint selection gate; R2 added the
honestly scoped epoch-bump decode/render dry-run; R3 hardened the irreversible
writer's full range check; R4 cross-linked in-progress recovery and admission;
and R5 added pre-transition token loss plus bounded backup-domain retention.
R6--R12 were observations/editorial hardening. Reviewer B's report was
historically written to the ephemeral path
`/tmp/pqsigner-ab-rollback-reviewer-B-adjudication.md`, with recorded SHA-256
`7067a883117bfb948a839f4541c21aa4cf2dd1d41f6f972d632435a345961bc8`.
That file is not present on this host and is chronology only, not evidence for
Draft 1.1 approval.

Frozen Draft 0.7 incorporated R1--R12 and deliberately sharpened R4 beyond a
prose cross-link through the typed pre-admission states `Steady`, `Recovering`,
and `Unknown`. Its spec and reapproval-prompt SHA-256 digests were
`c6fd64f7dcd49b7cb66a9918a66e65e6452a763856b265c68647ce65cb4b5fd2`
and `6a591c66fd87d164ee95ccd4aacd32094fa68380c09a5f351aeee79d2823e251`.

Reviewer A returned `APPROVE ARCHITECTURE FOR OPEN-DECISION CLOSURE` for that
digest after two independent prosecutor passes found no new state-machine
hole. A noted R1 nuance was that Draft 0.7's complete per-combination gate is
stronger than, but occurs later than, Reviewer B's requested cheap early
combined estimate; Reviewer A recommended restoring a non-authoritative early
warning build to reduce NO-GO discovery latency.

Reviewer B returned `APPROVE WITH RED-LINES` for Draft 0.7: RL-A required the
RAM inequality to use checked, underflow-safe arithmetic; RL-B required Section
7.2 to exclude post-`COMPLETE` compaction from epoch-advance
`Recovering|Unknown`/no-handoff wording. The report was historically written
to the ephemeral path `/tmp/pqsigner-ab-rollback-reviewer-B-0.7-reapproval.md`,
with recorded SHA-256
`5310cea9187b2e228db3a4525c4f641114885c9dba98ad9c9603110e161249fd`.
It is not present on this host and is not relied on for Draft 1.1 approval.

Draft 0.8 applies RL-A and RL-B, defines the guard-reservation term when the
SHOULD-level hardware guard is omitted, and restores an actual combined
FLASH+RAM early-warning experiment without allowing it to satisfy the final
Section-12.6 gate. Reviewer-B observation O2 was already enforced by the
explicit post-`COMPLETE` maintenance rule; O3 is resolved by the guard-term
definition; O1 remains redundant because the `Steady(F)` branch itself already
excludes every unresolved stage. Both reviewers subsequently approved the same
frozen Draft-0.8 digest
`66b0bd6587b14d0f6d048aafff27d66532a7710070912ef2d7de02ef3f10d4b1`
for open-decision closure while explicitly withholding implementation
approval. Reviewer B's durable report SHA-256 is
`73cb4c0ab079777272203aa9837d2e244c1645a4fd5343557d611196f461375d`.

Draft 0.9 froze candidate software interfaces under SHA-256
`f38b90307f15b87a65e9dc9d69583a74775fe4f77385e8b3a84978c34a947336`
and annotated tag `rollback-architecture-v0.9`. Two independent exact Opus
4.8, 1M-context, maximum-effort reviews examined that byte-identical digest.
Reviewer A returned `NO-GO`; its schema-valid report SHA-256 is
`b846afe6d077de5a732de72c732f765c92d50eb08c47a14b6947db00c4f8cdb6`
and receipt SHA-256 is
`86b740022c35fdd8a7e5098de1fd35947a8a0f3316c84813f76e72dfa35f38e9`.
Reviewer B returned `APPROVE WITH NORMATIVE RED-LINES`; its report SHA-256 is
`b1c7b28eb3c145077112224a4ad5fd8d49bbf9c169875c50b9f87a7aa848e135`
and receipt SHA-256 is
`298706589a861cc584415b4e3694f22907a54dd0a2a93c90fff5fba902c15cff`.
Neither approved implementation or shipment.

Draft-0.9's blocking red-lines were: terminal-marker degradation could brick
after floor retirement; a finite recovery plan could exhaust permanently;
confirmed decoding depended forever on historical PENDING; incoming package
blank bytes were conflated with physical virgin state; the full flash/dual-WRP
map and factory PENDING-before-CONFIRMED order were incomplete; and same-epoch
admissibility wording implied more demotion authority than the selector
provides. Resource fit, orphan scanning, realistic epoch EOL, signed manifest
fields, and the atomic legacy-geometry migration were also required.

Draft 1.0 is preserved at commit `cc526ac8` with SHA-256
`59bb14f875ab0082382e2ef1130902c87c68b9b4bbb4b5c85e59d76368291efb`.
GPT-5.6 SOL at `ultra` approved its architecture, while Claude Opus 4.8 1M at
`ultracode` returned a normative `NO-GO`. Draft 1.0 therefore never authorized
implementation or shipment.

Draft 1.1 incorporates those red-lines through `FROZEN-MAN-4`,
`FROZEN-JRN-IFACE-3`, `FROZEN-OTP-API-3`, `FROZEN-ROUTE1-1`,
`FROZEN-OTP-PROGRAM-1`, `FROZEN-HLT-1`, `FROZEN-HLT-2`, and
`FROZEN-TIME-1`. It inherits no approval. Once editing and internal consistency
checks finish, two fresh independent reviewers must inspect the same exact
digest: Claude Opus 5 (`opus`) at `xhigh`, and GPT-5.6 SOL at
`ultra`. Each is told only that the other model/effort is independently
reviewing the same digest; findings and verdict are withheld until both report.
Their digest-bound reports live in a separate approval receipt so recording
them cannot change the reviewed spec bytes.

| Reviewer | Reviewed artifact | Verdict | Status |
|---|---|---|---|
| Independent reviewer A | Draft 0.9 `f38b9030...a947336` | NO-GO; no implementation/shipment approval | historical only |
| Independent reviewer B | Draft 0.9 `f38b9030...a947336` | APPROVE WITH NORMATIVE RED-LINES; no implementation/shipment approval | historical only |
| GPT-5.6 SOL, `ultra` effort | Draft 1.0 `59bb14f8...68291efb` | architecture approved; no shipment approval | superseded by Opus NO-GO and Draft 1.1 |
| Claude Opus 4.8, 1M context, `ultracode` effort | Draft 1.0 `59bb14f8...68291efb` | normative NO-GO | red-lines incorporated into Draft 1.1 candidate |
| Claude Opus 5, `opus`, `xhigh` effort | Draft 1.1 exact final digest | pending | no inherited approval |
| GPT-5.6 SOL, `ultra` effort | Draft 1.1 exact final digest | pending | no inherited approval |
| Owner | Draft 1.1 exact final digest and external approval receipt | pending | pending |

Draft 0.2 received a non-Opus internal adversarial `NO-GO`; its main-flash
interruption, factory, ECC, USB-completion, and claim-scope red-lines were
incorporated in Draft 0.3. Draft 0.4 added the owner-reviewed OTP decision and
the `(release_version, security_epoch)` split. Its reviewed artifacts were
historically written to `/tmp/pqsigner-ab-rollback-architecture-spec-v0.4.md`
and `/tmp/pqsigner-ab-rollback-spec-opus-prompt-v0.4.txt`, with recorded SHA-256
`75a2eb52861e0c5bbe57b9413e4ca33fed4e9c9037de459522cb720a9cb3b528`
and `8e0c5ae1b0be3947f5275475124c0e150e778aa8f9e7141c60216892a7f91544`.
Those ephemeral files are no longer present and are not used as Draft 1.1
approval evidence.

An earlier bounded Claude Code Opus 4.8
architecture consultation agreed that OTP is the smaller initial immutable
root and that one OTP quad-word cannot be reused bitwise; it did not review
this full specification and is not an approval. Its mistaken suggestion that
`F = E - 1` leaves a one-epoch window was rejected against the strict `E > F`
arithmetic and existing comparator. Other earlier stalled sessions likewise
remain unrecorded as approvals.
