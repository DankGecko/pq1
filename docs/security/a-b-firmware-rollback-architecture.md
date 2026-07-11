# PQSigner OS A/B Rollback Architecture Specification

Status: **DRAFT 0.9 — SOFTWARE INTERFACES FROZEN; PHYSICAL JOURNAL/OTP/ECC AND SILICON GATES OPEN; NO PRODUCTION IMPLEMENTATION OR HARDWARE AUTHORITY**  
Draft: 0.9  
Date: 2026-07-11  
Target silicon: STM32U585AI, including the B-U585I-IOT02A development kit  
Reference implementation worktree: `/tmp/pqsigner-fw-rollback` on
`codex/fw-rollback-research-freeze`  
Reference baseline: committed HEAD `8d231c24`  

This is a design artifact for red-line review. Review copies may live outside
the PQSigner repository; after approval, only a byte-identical copy carrying
the frozen digest may be committed as the project record. The document does
not authorize production-shared code, firmware flashing, OTP programming,
option-byte changes, or releases.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are used as requirements language.

---

## 1. Purpose

This specification repairs the failed A/B rollback property identified as
finding #5: the old design advanced the irreversible rollback floor before a
candidate firmware had booted successfully, thereby making the known-good slot
ineligible before the advertised try-once recovery decision could run.

The desired end state has two separately tracked claims:

1. **Mechanism closure.** A candidate receives at most one probation handoff;
   a reset or failure after exact `ATTEMPTED` and before acceptance returns to
   the previous confirmed slot, while a pre-handoff exact arm may safely retry;
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
design. Establishment is a reviewed durable-stage plus replicated OTP
commitment for an epoch bump and an idempotent no-write check for a same-epoch
release. Project status and documentation MUST report the mechanism, the exact
probation coverage, and this residual separately.

### 1.1 Version and floor semantics

The signed manifest carries two independent 32-bit values in
`1..=0xFFFF_FFFE`; zero and `0xFFFF_FFFF` are reserved invalid/fail-closed
sentinels:

- `R = release_version`: unique and strictly increasing within the Section-6.4
  product/domain/vendor-key namespace for one logical vendor release-set. In
  normal, ledger-consistent states it orders epoch-admissible releases. The
  anomalous two-`CONFIRMED` recovery order is instead the explicit
  `(E, R, slot-A-first)` order in Section 7.2.
- `E = security_epoch`: a nondecreasing rollback-equivalence class. Every
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
`T == F` and performs no rollback-record program operation. An epoch bump has
`E_new > E_running`, so `T > F` and requires one logical `commit_target(T)`,
regardless of the numeric jump. The approved physical codec defines how many
OTP quad-words, replicas, claims, and recovery-reserve cells implement that
one logical commitment. A single-QW committed floor is explicitly not
production-eligible. This specification therefore provides epoch-granular
irreversible rollback protection, not per-release irreversible rollback
protection.

"Same epoch" is always device-relative. A release that repeats the preceding
ledger entry's `E` can still require a commitment on a lagging device whose
local `F < E - 1`. Neither server metadata nor release classification may
promise a global no-write path; the device derives it only from signed `E` and
its independently validated local `F`.

---

## 2. Resolved architectural decisions

The following decisions are settled for this design:

- The persistent boot state machine is health-boundary-agnostic. FSBL sees
  only exact composite manifest/TAMP states; it does not interpret how runtime
  health was established.
- The only valid logical states are `UNINSTALLED`, `PENDING`, `ATTEMPTED`, and
  `CONFIRMED`; Draft 0.9 freezes their composite software encoding while
  `OPEN-JRN-HW-1` gates the physical TAMP backend.
- A candidate remains `ATTEMPTED` throughout all health evaluation.
- Any reset, crash, watchdog, power loss, cancellation, timeout, or invalid
  health response after exact durable `ATTEMPTED` and before `CONFIRMED` causes
  the old confirmed slot to be chosen on the next FSBL boot, when that slot
  remains otherwise valid. A reset before `ATTEMPTED` becomes durable may
  safely retry arming because the candidate has not run.
- `CONFIRMED` is final acceptance of the release. It is not an early "booted
  once" marker. It authorizes retirement of older epochs only when `E`
  increases; a same-epoch fallback remains floor-admissible.
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
- Repository-wide formatting, expanded reset assembly, broad FI hardening,
  further fingerprint format/table changes beyond the landed base-27 packing,
  and unrelated factory lifecycle changes are outside the minimum series.
- A production-capable FSBL build MUST retain at least 2 KiB free in its fixed
  40 KiB region after the clean core implementation.
- FSBL transient SRAM/stack geometry is not silently expanded. `OPEN-RAM-1`
  must freeze the current 16 KiB envelope or a reviewed replacement, with
  static/worst-case stack accounting, margin, guard, and runtime handoff.
- A production device MUST have an independently verified `CONFIRMED` genesis
  slot before any field-update probation. A `PENDING`-only device is not a
  supported first-boot path.
- Every selected `CONFIRMED(R,E)` slot, including factory genesis and a lone
  confirmed slot, MUST idempotently establish `F == E - 1` before handoff.
- `R` is strictly increasing across logical release-sets within its namespace,
  and `E` is nondecreasing as `R` increases. Slot-A and slot-B artifacts for one release
  share the same `(R,E)` and logical source/policy identity. Any slot-specific
  linked bytes and hashes are explicitly paired by the release-set record.
- Every security-relevant release that must make any prior same-epoch signed
  artifact inadmissible MUST advance `E`. This is a production-signing policy
  gate, not a documentation convention.

---

## 3. Frozen software interfaces and explicitly open decisions

### FROZEN-JRN-IFACE-1 / OPEN-JRN-HW-1: PENDING/ATTEMPTED representation

Draft 0.2's manifest-resident `ATTEMPTED` quad-word is rejected. RM0456 says
that reset or power interruption during a main-flash single write leaves the
contents unguaranteed and mandates a page erase before rewriting that location.
An interrupted marker may therefore appear erased but not be safely
reprogrammable. Exact all-`0xFF` readback does not authorize retry.

Draft 0.9 freezes the exact composite software representation in Section 6:
`PENDING`/`CONFIRMED` activation lives in two manifest quad-words and the arm
token lives in TAMP backup registers `BKP8..31`; BHK exclusively owns
`BKP0..7`. This freezes bytes, decoding, binding, and transition ordering so
independent host models cannot invent incompatible formats. It does **not**
make the TAMP backend production-eligible. `OPEN-JRN-HW-1` remains until exact
silicon demonstrates BHK coexistence, secure/privileged NS denial, reset and
tamper behavior, supported-board VBAT retention, and the final production
initialization/readback sequence. Failure of that gate reopens the physical
backend and requires a new reviewed digest; an erasable flash journal remains
the fallback architecture, not an alternate parser compiled beside TAMP.

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
BKP contents may be unpredictable. Therefore Draft 0.9 makes no deterministic
at-most-once claim across complete or marginal backup-domain power loss. The
production cold-boot path must implement and validate the applicable ST
workaround for the final board topology. With separately supplied VBAT,
`PWR_BDCR1.MONEN` must have been continuously active before the questionable
power event; setting it afterward does not retroactively authenticate retained
state. FSBL verifies retained MONEN before token decode, sets it for future
boots, and configures `PWR_SECCFGR.VBSEC=1`,
`PWR_PRIVCFGR.SPRIV=1`, and exact secure/privileged readback before NS.

If VBAT topology is shared/unknown, retained MONEN was not already valid, or
state validity cannot be established, immutable boot treats the token as
unavailable and performs the documented `DBP` + `RCC_BDCR.BDRST` readback/
deassert/reinitialize sequence before token decode; no `ARM_READY` retry
survives. If Shutdown mode is supported and must be distinguished from backup-
domain power-on, the balanced canary/CRC discriminator becomes part of the
reviewed physical design. Before BDRST, immutable boot captures tamper flags
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
corruption or apparent retention is a safe-fallback input only and cannot grant
retry authority.

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
negative: the missing/malformed token rejects the candidate, boots the
eligible confirmed fallback, and requires a fresh PIN-gated reinstall/re-arm.
No security or at-most-once claim may depend on token retention. `OPEN-JRN-HW-1`
must record the measured supported-board retention envelope and compare this
bounded retry/UX benefit with an erasable journal's persistence and larger
power-cut/compaction TCB.

The epoch split makes confirmation-writer ownership an explicit red line.
Draft 0.9 retains the smaller Draft-0.3 design: the running secure candidate,
after revalidating its own bound `ATTEMPTED` identity and completing Section 9,
writes exact `QW_CONFIRMED`; FSBL treats that codeword as the durable health
acceptance seal. For a same-epoch release there is no additional OTP witness.
This relies on the stated trust in vendor-signed secure runtime and on one
running-slot-bound confirmation writer. It MUST NOT be described as FSBL having
directly observed the health transcript.

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

The frozen marker values do not by themselves prove physical durability.
RM0456 Sections 7.3.11--7.3.12 say a reset or power interruption during a
main-flash QW write leaves contents not guaranteed and requires page erase
before rewriting. A later read that is byte-exact and currently `ECCC`-clear
is not a documented retention/margin read. This is most consequential for
`QW_CONFIRMED`: accepting a marginal exact-looking seal, advancing the epoch
floor, and later losing that seal can make both slots ineligible.

Accordingly, every `exact` marker in Sections 6--11 means a typed
**durably-clean exact** observation produced by the ultimately approved
journal rule, never a raw `[u8;16]` comparison. `OPEN-JRN-DUR-1` must define
how a boot after a possible marker launch distinguishes a completed durable
write from an interrupted exact-looking outcome and how later marker loss
preserves an epoch-bump boot path. Candidate routes include a separately
durable completion witness/state, binding the accepted manifest into the
replicated floor authority, or a reviewed redundant marker protocol; none is
selected here. An EOP observed only before reset is not durable evidence
available to the next boot.

These routes do not all preserve the frozen admission interface. In
particular, a design that authorizes a floor-bound manifest from replicated
floor state after its `QW_CONFIRMED` marker becomes unavailable adds a new
authenticated admission source. Selecting that route MUST re-open and
re-freeze `FROZEN-JRN-IFACE-1`, the Section-6.2 marker decoder, and the
Sections-7.1/7.2 verification and selection rules under a new reviewed digest;
it may not be hidden behind the present `Malformed => ineligible` rule. A
redundant-marker route that changes manifest bytes, QW ownership, or the
CRC-normalized window instead re-opens `FROZEN-MAN-1` as stated below. The
present freeze therefore covers only the current marker-authorized admission
contract, not every candidate resolution of `OPEN-JRN-DUR-1`.

At the earliest immutable reset entry, before any later flash program or erase,
FSBL MUST snapshot the single common `FLASH_OPSR` once and validate `CODE_OP`,
`SYSF_OP`, `BK_OP`, and `ADDR_OP`. It preserves that typed snapshot until both
manifest-journal and OTP floor/stage classification or recovery have consumed
it. Ambiguous fields, an invalid address, or inconsistent status fail closed
and cannot produce `BlankVirgin`. An interrupted
operation attributed to a manifest page/QW makes that exact location
`UnknownMayHaveLaunched` regardless of current bytes; it cannot confirm,
authorize floor establishment, or be reprogrammed. The mandated page-erase/new-
generation corrective action is permitted only when the slot is independently
safe to treat as inactive and the confirmed fallback remains valid. Otherwise
FSBL globally inhibits further flash mutation and halts or follows the later
approved floor-bound journal recovery. Status is not cleared or overwritten
before this decision.

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

### FROZEN-MAN-1: exact manifest-v4 schema and domain bytes

Section 6.1 freezes the manifest-v4 schema byte, exact offsets, 7-byte
`PQFW_V4` signing domain, 80-byte signed preimage, normalized CRC, golden
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

The same primitive covers both manifest activation QWs. An ECCC/ECCD result is
never an exact marker, and an ECCC-clear exact-looking result after a possible
interrupted program remains subject to `OPEN-JRN-DUR-1`; fresh-array
attribution is necessary but not a retention proof.

OTP floor reads add a separate single-error requirement. RM0456 reports a
corrected one-bit read through `FLASH_ECCR.ECCC`, and warns that a buffered
reread may not raise the flag again after it is cleared. The production OTP
decoder therefore needs a silicon-validated per-QW primitive that clears stale
ECC state, forces a new array read through documented cache/data-buffer
maintenance, attributes `ECCC`/`ECCD` to the exact QW, and consumes the flags
before any other flash read. Corrected bytes are never accepted as clean floor
authority. If a fresh array read and flag attribution cannot be demonstrated,
the OTP backend remains NO-GO.

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
exception frame at the worst legal nesting point. Compiler stack-usage/call-
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

The following OTP questions remain open and MUST NOT be silently resolved in
code:

### FROZEN-OTP-API-1: typed floor and establishment semantics

Draft 0.9 freezes the software semantics at the FSBL admission/establishment
boundary, but not Rust layout, physical serialization, or backend selection.
The decoder yields exactly one logical class:

```rust
enum FloorView {
    Steady(SteadyProof),
    Recovering(RecoveryProof),
    Unknown(FloorFault),
}
```

`SteadyProof` binds the admission-authoritative `F`, a committed group identity
or canonical `BASE0`, allocation generation/cursor, and a digest of the state
snapshot. `RecoveryProof` binds at least `prior_f`, the prior group identity
and digest or `BASE0`, allocation generation/cursor, exact target and active
group, candidate/manifest binding, ordered non-aliasing physical-cell role map,
consumed/quarantined set, and opaque durable-stage binding. It deliberately
has no method that exposes `prior_f` as an admission floor. `Unknown` carries
diagnostics only and never a usable fallback floor. Compact references or
numeric handles MAY implement these proof objects; this semantic list does not
require copying a large owning struct onto the FSBL stack.

No floor decoder receives a bare `[u8; 16]`. The hardware boundary is typed:

```rust
enum FreshQwRead {
    Clean(CleanQw),
    Corrected { bytes: [u8; 16], index: u16 },
    Uncorrectable { index: u16 },
    AmbiguousOrFault,
}
```

`CleanQw` is constructible only by the exact-index fresh-array primitive. Its
typestate binds the physical QW index, absolute address, returned bytes, and
the attributed status snapshot; it cannot be reinterpreted at another index.
A `BlankVirgin` proof is derived only from `CleanQw(all-FF)` plus proof that no
operation-status, durable-stage, claim, or writer launch for that exact index
may be missing. Clean-looking bytes alone never construct it.
`Corrected` has zero quorum weight and is never virgin even if its returned
bytes are exact; `Uncorrectable` and ambiguous observations likewise confer no
authority. Cache/data-buffer invalidation, flag clearing, exact address/ECCC/
ECCD attribution, exception recovery, and flag consumption remain
`OPEN-ECC-1` and require silicon evidence.

The runtime/public side is read-only: from `Steady` it may `decode`, classify a
checked target, and request a read-only preflight receipt. It exposes no OTP unlock,
program, stage mutation, claim, or compaction symbol. Classification is exact:

```text
T < F  -> inconsistent/fail
T == F -> SameEpoch
T > F  -> EpochBump
```

For `T == F`, the top-level caller bypasses preflight and every mutable backend
entry. Read-only fresh scans are permitted, but counters must prove zero OTP
unlocks/programs, zero durable reservations/claims/stage writes, and zero stage
compactions on every same-epoch path, including exhausted-bank paths.

For `T > F`, preflight is read-only and binds its result to the exact `Steady`
snapshot, candidate binding, codec identity, target, required target QWs,
replacement/recovery margin, durable-stage capacity, and any selected key
health. A preflight receipt is never durable authority. The private immutable
writer independently reparses and re-verifies raw manifest ranges, exact
`CONFIRMED`, images, target, floor state, and receipt bindings before mutation;
an upstream typed value is not its sole FI/range gate.

The establishment launch boundary has two disjoint frozen entries:

```text
enum CheckedSteadyIntent {
    SameEpoch { proof: SteadyProof, intent: SameEpochIntent },
    EpochBump {
        proof: SteadyProof,
        receipt: PreflightReceipt,
        intent: EpochBumpIntent,
    },
}

start_from_steady(CheckedSteadyIntent)
resume_from_recovery(RecoveryProof)
```

`start_from_steady` independently authorizes the exact confirmed manifest/
images and checked `T`. The `SameEpoch` variant exists only for `T == F`; it
contains no receipt, performs no preflight or mutation, and requires a fresh
`Steady(T)`. The `EpochBump` variant exists only for `T > F`; it revalidates a
receipt bound to that exact steady snapshot and may invoke `begin(intent)`
exactly once. A dummy/default receipt is not constructible. Before `begin`, a
preflight failure is proven-no-launch and may use only Section 10's narrowly
defined no-write fallback. Once `begin` is invoked, no return value can grant
fallback or handoff; every outcome requires a new full decode.

`resume_from_recovery` accepts only the exact decoder-issued `RecoveryProof`.
It never calls `begin`, performs ordinary preflight, reclassifies `prior_f`,
takes a same-epoch branch, or grants fallback authority. It independently
revalidates the proof's candidate, target, prior-group digest, generation,
role map, and durable-stage binding, then resumes only the already-active
protocol or halts. A recovery-specific capacity check may allocate only
preclaimed replacements permitted by that proof; failure remains
`Recovering`/halt or `Unknown`, never `Steady(prior_f)` admission.

Both entries finish only through a new full decode: `Steady(T)` permits final
candidate revalidation then handoff, an exact bound `Recovering` can only enter
`resume_from_recovery` or halt, and `Unknown` halts.

The writer never returns handoff authority directly. Only a subsequent fresh
full scan yielding `Steady(T)` can do so.

The durable-stage interface is semantic and opaque:

```text
fresh start: observe -> read_only_preflight -> begin(intent) ->
preclaim(exact cell, exact role) -> classify program result ->
record_clean(cell) -> allocate_preclaimed_replacement as needed ->
complete(full-clean group) -> optional post-COMPLETE maintenance

recovery: observe -> resume(existing bound intent/claim/role map) ->
record/replace/complete only as authorized by RecoveryProof
```

The stage binds the complete intent and role map before any OTP command. Each
exact cell is durably preclaimed before launch. After any reboot an outstanding
claim is permanently consumed even if the QW reads all `0xFF`; it is never
retried. Only EOP plus a fresh clean attributed read may be recorded clean. A
cut before that record leaves the cell uncertain/consumed. Initial commitment
requires the selected full clean threshold and exact durable `COMPLETE` before
`Steady(T)`. Post-`COMPLETE` maintenance keeps an old authoritative copy until
a disjoint replacement is durable, otherwise decoding is `Unknown`.

The physical stage pages/encoding/copies/compaction, record codec, QW map,
replica and degraded thresholds, MAC/plain choice, key storage, fresh-ECC
mechanics, and usable capacity remain `OPEN-OTP-1..3`/`OPEN-ECC-1`. This frozen
API must not be cited as evidence that any physical epoch-bump path is
production-eligible.

### OPEN-OTP-1: OTP physical record format

Choose between MAC-authenticated records and a simpler plain-record format only
after the sacrificial-silicon master-closure test in Section 13. Both options
MUST use:

- a one-shot completeness/antichain encoding—such as target plus complement,
  domain, role, and structural check, or a formally equivalent code—such that
  no strict erased-to-target 1→0 programming prefix can decode as any valid
  floor record for `T` or `V != T`;
- independently programmed physical replicas under a reviewed group/threshold
  protocol; a single-QW committed floor is not production-eligible; and
- a combined floor/stage decoder that tolerates the promised number of rejected
  replicas without ever returning a lower floor, returns bound `Recovering`
  only for one fully validated in-progress stage, and otherwise returns
  `Unknown`/halts.

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
frontier group. A valid durable in-progress stage is represented as
`Recovering`, not silently promoted to a committed floor and not collapsed to
the terminal `Unknown` result merely because the frontier is incomplete; the
typed pre-admission behavior is defined in Section 7.1. Missing, invalid,
rolled-back, or ambiguous stage evidence that prevents proving the highest
committed group is `Unknown` and halts.

The codec and durable-stage design MUST maintain a global, non-aliasing
physical-cell ownership partition. At every decode, each reserved rollback QW
is exactly one of: canonical virgin; one distinct role in one committed group;
one distinct role in the single active group; durably consumed/quarantined; or
an invalid/unknown condition that halts. One QW index may not appear twice in a
quorum, in two groups, as both source and replacement, or as both
consumed/quarantined and writable. Quorum cardinality counts distinct physical
QWs, not record entries.

Every stage and `COMPLETE` record MUST bind a fixed codec/domain, the exact
prior committed-group identity and digest (or canonical `BASE0`), `prior_f`, a
monotonic allocation generation/cursor, target and active-group identity,
candidate/manifest identity, and the full ordered map from physical QW indices
to replica/claim/replacement roles. Replaying a stage against a later prior
floor, generation, cursor, candidate, group, or ownership map is `Unknown`.
Completion, replacement, journal compaction, and recovery MUST preserve
permanent consumed/quarantined ownership, including a launched-all-`0xFF` cell;
they may not make an old stage current or a used index virgin. If route 1 uses
erasable main flash, its replicated journal copies, manifests, fallback state,
and all other persistent owners MUST have a frozen pairwise-disjoint
page/erase-unit map before the route can be approved.
After exact authoritative `COMPLETE`, optional close/compaction is maintenance,
not a new epoch-advance recovery. It MUST preserve at least one old
authoritative completion copy and `Steady(T)` until a disjoint replacement is
fully durable. It never returns the epoch-advance `Recovering` class; loss or
ambiguity of all authoritative completion evidence is `Unknown`.
If the frozen layout has no such independently erasable space, route 1 is
ineligible for the minimum repair; it may not borrow a manifest, fallback,
counter, key, or FSBL page, and any new reservation is a separately reviewed
whole-layout redesign.

A MAC may additionally authenticate virgin-cell writes against an unclosed
master, but it does not replace deterministic torn-write structure, replica
health, or the ECCC rules. The exact replica count, group identity, completion
rule, degradation threshold, and physical capacity remain open.

### OPEN-OTP-2: rollback-key storage, if MAC records are retained

The research prototype's single page-126 rollback-key record is rejected as a
default. Page 126 already has an independent wrapped-BHK lifecycle in the
current product design and MUST NOT silently acquire a second owner. A final
MAC design must identify non-conflicting storage and specify redundancy, ECC
failure behavior, WRP/HDP/SECWM factory receipts, recovery policy, and the
exact impact of a lost key.

Under a MAC-record design, a fully blank, ECC-clean rollback-record region for
which the approved durable-intent mechanism proves that no reservation/stage or
writer launch may be missing or active decodes to the logical base `Steady(0)`
without reading or possessing the MAC key.
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
belongs only to one valid in-progress frontier, it receives zero weight and
the combined decoder returns the bound `Recovering` context; invalid recovery
evidence is `Unknown`. `ECCD`, malformed, structurally incomplete, and
retention-unstable frontier records follow the same no-downgrade rule. `ECCC`
clear is necessary for a clean replica but is not proof of retention margin.

An exact-looking authorized `T` in a QW whose program may have been
interrupted is not a settled acceptance path and contributes zero authority or
quorum weight. Clean pre-cut replicas remain usable only when the durable stage
proves their completion. Separately preclaimed replacement QWs may be written
after recovery, but the logical target is established only after the resulting
full clean initial-threshold group receives a fresh durable `COMPLETE` stage
under an approved ordered protocol in which:

- the complete required clean-replica set was established before lower-epoch
  retirement;
- no possibly interrupted or corrected QW contributes to the accepting quorum;
- later rejection of the promised number of replicas still yields `T` from
  independent clean witnesses; and
- an incomplete group returns bound `Recovering` only while one unambiguous
  durable stage proves how to continue; every threshold/stage failure returns
  `Unknown` rather than a lower or attacker-chosen floor.

A launched-but-visibly-all-`0xFF` QW after complete power loss is currently
indistinguishable from virgin state. Draft 0.9 claims no write-free quarantine
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

Route 1 does not violate same-epoch zero-write: no claim, cursor, OTP unlock, or
program operation is permitted when `T == F`. It does add persistent state and
TCB and therefore needs its own state/power-cut review; no construction is
approved by this draft. A replicated, FSBL-owned erasable-main-flash journal is
one feasibility candidate because an interrupted main-flash write can be
recovered through page erase while another valid copy remains. Its compaction,
rollback/tamper resistance, runtime access boundary, and missing-state behavior
must be proved; TAMP alone does not survive complete backup-domain loss, and an
OTP claim simply recurses into the same uncertainty. Under every route, a QW
known to be possibly launched is never programmed again, a partial state cannot
decode as any valid record, and a degraded frontier can neither create an
unauthorized high floor nor make a previously committed floor disappear.

The last rule is a recovery-protocol terminal rule, not an instruction to
misclassify every ordinary incomplete frontier as an admission-time
`Unknown`. On each boot, the floor/stage decoder must return exactly one of the
typed results in Section 7.1: `Steady(F)`, a fully validated `Recovering`
context that resumes Section 10 without slot admission, or `Unknown`. Recovery
must reach a fresh `Steady(T)` before either slot can enter ordinary admission.

### OPEN-HLT-1: local signing self-test key

The local health suite must exercise real derivation and C10 signing code, but
the final design must decide whether to use:

- a real slot key under a fixed synthetic `(account, chain, slot)` tuple, with
  the signature retained entirely inside secure SRAM; or
- a dedicated health-only derived key that avoids any ambiguity in the wallet
  key usage budget.

The choice must be reviewed by the C10/signature-budget reviewers. No health
signature may be returned to NS or the companion unless a later specification
explicitly accounts for its key-usage and domain-separation consequences.
That review MUST use the worst-case lifetime self-test frequency, including
every PIN-gated reinstall/re-arm after safe probation false negatives, rather
than assuming one self-test per published release. This wallet-health-key
budget is distinct from the firmware-vendor-key cap in `OPEN-C10-1`; the two
must never share a counter by analogy. A dedicated health-only derived key is
preferred unless the reviewed bound demonstrates that use of a real slot key
preserves the slot key's global security budget across restoration and every
re-arm path.

### OPEN-HLT-2: human challenge presentation

The challenge must carry at least 40 bits of unpredictability under a
one-syntactically-valid-guess probation policy. The exact presentation—such as
four independently sampled BIP-39 words or another unambiguous trusted-display
encoding—requires a separate UX review. A lower-entropy decimal code is not
accepted by this draft merely because a later physical confirmation also
exists; lowering this bound requires an explicit security/UX red-line.

### OPEN-TIME-1: probation deadline

The secure deadline and transport retry count remain parameters to be chosen
from hardware measurements. The deadline MUST be finite and MUST NOT be
extendable by NS traffic.

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

- Immutable, WRP1A-protected FSBL after the factory ceremony.
- Vendor C10 firmware-signing public key embedded in the FSBL.
- STM32U585 TrustZone hardware and correctly burned production option bytes.
- Secure-world trusted display and physical buttons.
- Hardware PIN policy in the OPTIGA, SE050, and MCU attempt-state convergence.
- Correct C10 verification and hash implementations within their reviewed
  assumptions.

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
- a missing, unresponsive, or incompatible companion;
- a malicious NS or companion attempting to confirm without the human-bound
  trusted-display challenge;
- bounded single-event fault assumptions only where a later reviewed FI stage
  states the exact model.

The minimum core does not claim resistance to invasive silicon attacks or an
attacker holding the vendor signing key.

An older correctly vendor-signed artifact in the current `security_epoch` is
also not an attacker forgery. If it is restored after a newer same-epoch slot
is erased, corrupted, or otherwise absent, the immutable floor permits it.
That is the deliberate cost of amortizing scarce OTP writes. Every release
process, product claim, and recovery test must treat one epoch as a rollback-
equivalence class.

---

## 5. Fixed flash geometry and immutable resource budget

The STM32U585AI layout is fixed as follows unless a separate whole-layout
redesign is approved:

- FSBL: bank-1 pages 0–4, `0x0C00_0000..0x0C00_9FFF`, exactly 40 KiB.
- Manifest A: bank-1 page 5 at `0x0C00_A000`; Manifest B: page 6 at
  `0x0C00_C000`.
- Slot-A secure image: `0x0C00_E000`, bank-1 pages 7–64, capacity `0x74000`.
- Slot-B secure image: `0x0C08_2000`, bank-1 pages 65–122, capacity `0x74000`.
- Slot-A nonsecure image: `0x0810_A000`, bank-2 pages 5–65, capacity `0x7A000`.
- Slot-B nonsecure image: `0x0818_4000`, bank-2 pages 66–126, capacity
  `0x7A000`; bank-2 pages 0–4 hold the physical FSBL mirror and page 127 is
  reserved.

The FSBL linker region MUST remain exactly 40,960 bytes. It MUST NOT be expanded
over Manifest A.

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
while the packed baseline lacks the final manifest-v4, fresh-ECCC,
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
reservations; it is not an implementation of the frozen Draft-0.9 manifest,
typed journal, fresh-ECC, replicated-floor, recovery, and durable-stage
semantics. Software-interface freeze is therefore contingent on an actual
combined build of the selected Draft-0.9 semantics proving resource fit. The
physical linker ceiling is 40,960 bytes: exceeding it is an unconditional
layout failure. The 38,912-byte line is the reviewed warning/final-core target
that reserves 2 KiB of immutable FLASH headroom; exceeding that line, even
while still linking below 40,960 bytes, does not satisfy this draft without an
explicit owner/reviewer re-freeze of the margin policy. The same build must
pass `OPEN-RAM-1`. Neither the 38,860-byte proxy nor any placeholder range may
stand in for that build or authorize implementation, backend selection, or
silicon work.

---

## 6. Signed manifest and journal representation

### 6.1 Signed preimage

Draft 0.9 freezes a flag-day 8,192-byte manifest-v4 page. All integer fields
are big-endian:

| Offset | Size | Field | Frozen rule |
|---:|---:|---|---|
| 0 | 4 | magic | exact ASCII `PQSF` |
| 4 | 1 | schema | exact `0x04` |
| 5 | 1 | physical slot | `0x00=A`, `0x01=B`; must match containing page |
| 6 | 2 | header reserved | exact zero |
| 8 | 4 | `release_version` | `1..=0xFFFF_FFFE` |
| 12 | 4 | `security_epoch` | `1..=0xFFFF_FFFE` |
| 16 | 4 | secure image length | at least 8; within frozen slot capacity |
| 20 | 4 | nonsecure image length | at least 8; within frozen slot capacity |
| 24 | 32 | secure image SHA-256 | exact signed image binding |
| 56 | 32 | nonsecure image SHA-256 | exact signed image binding |
| 88 | 32 | vendor-key fingerprint | `SHA256(pk_seed || pk_root)` |
| 120 | 32 | build ID | unsigned, non-authoritative correlation metadata |
| 152 | 32 | manifest digest | exact freshly recomputed digest below |
| 184 | 4008 | C10 signature | signature over the 32-byte manifest digest |
| 4192 | 16 | `QW_PENDING` | QW index 262; CRC-normalized |
| 4208 | 16 | `QW_CONFIRMED` | QW index 263; CRC-normalized |
| 4224 | 3964 | trailing reserved | exact `0xFF` through offset 8187 |
| 8188 | 4 | normalized CRC-32 | IEEE/zlib CRC, stored big-endian |

Implementations MUST compile-time pin every offset, `SIGNATURE_LEN == 4008`,
both journal offsets modulo 16, `184 + 4008 == 4192`, and
`OFF_CRC32 == MANIFEST_SIZE - 4`.

The signing domain and preimage are exactly:

```text
MANIFEST_VERSION    = 0x04
DOMAIN_TAG          = b"PQFW_V4"       // exact 7 bytes
SIGNED_PREIMAGE_LEN = 80

DOMAIN_TAG[7] || physical_slot_u8 || release_version_be_u32 ||
security_epoch_be_u32 || secure_image_hash[32] ||
nonsecure_image_hash[32]
```

`manifest_digest = SHA256(preimage)`. FSBL MUST verify C10 over a freshly
recomputed digest. The stored digest is a redundant comparison value, never an
independent signing authority. Slot A and slot B artifacts for one logical
release-set carry identical `(R,E)` and policy identity but are independently
signed for their physical slot and their slot-specific image hashes.

The frozen digest fixture is:

```text
slot = 01
R = 01020304
E = 05060708
secure_hash = 000102...1f
nonsecure_hash = 202122...3f
digest = b26491e86c8b97fe7e6bc3b67be73d1a
         6963ee4290c9fcaef5f2dad01f86461f
```

The normalized CRC is computed over bytes `0..8188` after replacing exactly
bytes `4192..4224` with 32 bytes of `0xFF`. It uses reflected IEEE polynomial
`0xEDB88320`, initial `0xFFFFFFFF`, final XOR `0xFFFFFFFF`, and is stored BE.
No raw-CRC call site is permitted. For the shared full-page fixture—golden
fields above, lengths `0x1000/0x2000`, FPR bytes `40..5f`, build-ID bytes
`60..7f`, signature byte `i mod 256` for zero-based `i=0..4007`, both journal
QWs exact erased `0xFF × 16`, and all trailing reserved bytes `0xFF`—the
normalized CRC is `0x993615CD` and finalized page SHA-256 is
`8e80b317a7a57a80136644339c6a10e340abf6c584fd73d58afedf3318875710`.

The same fixture with only the normalized journal window changed pins CRC
normalization behavior explicitly:

| Journal bytes | Normalized CRC | Full-page SHA-256 |
|---|---|---|
| both QWs erased | `993615CD` | `8e80b317a7a57a80136644339c6a10e340abf6c584fd73d58afedf3318875710` |
| exact PENDING, CONFIRMED erased | `993615CD` | `0b2b7e22e23fa9c17a7a769a210354f711202273719e541695ff1c1c5fbd7847` |
| exact PENDING + exact CONFIRMED | `993615CD` | `da4eec46baed2812be2af731bf76e319e1ca23137f4a117d7ba3ecedec0918f3` |

These values were independently reproduced with separate Python/zlib and
Node.js/table-driven CRC implementations. A production test must derive them
through the shared Rust manifest code and cross-check at least one independent
implementation; merely copying this table is not evidence.

Under the frozen 40-KiB FSBL layout, secure length is at most `0x74000` and
nonsecure length at most `0x7A000`. Vector words and every reset-handler target
must lie inside the corresponding signed-hash range `[base, base + len)`, not
merely somewhere in slot capacity. Lengths are not separate preimage fields:
the signed hash is over exactly `len` bytes, so changing a length while
retaining the signed hash requires a SHA-256 second preimage. `build_id` is
never displayed or consumed as trusted provenance; only the protected external
release ledger may authenticate/cross-check it.

Journal bytes are device-mutated and are the only CRC-normalized range. The
field-update secure-runtime writer MUST erase the inactive manifest page and
program body QWs
`0..261` plus CRC QW `511`, and issue no program command to journal QWs
`262/263` or all-`0xFF` reserved QWs `264..510`. `QW_PENDING` is programmed
only after body/CRC verification and exact TAMP arming. An erased-looking input
value is not permission to program an all-`0xFF` QW.

This is a true flag day: FSBL accepts only schema `0x04` and domain `PQFW_V4`,
never assigns a default epoch, never translates legacy offsets, and never
retries a v1/v2/v3 signature under v4. Bench devices are reflashed and factory
genesis is provisioned directly in v4. The exact bytes and shared fixtures
MUST be common to firmware, fwsign, inspector, factory/updater, extraction,
formal models, and host tests.

### 6.2 Logical states and frozen composite software encoding

The manifest codewords are exact 16-byte values:

```text
QW_PENDING =
12 34 56 78 9A BC DE F0 ED CB A9 87 65 43 21 0F

QW_CONFIRMED =
AA 55 99 66 F0 0F C3 3C 55 AA 66 99 0F F0 3C C3
```

Each has 64 programmed zero bits and a second half equal to the bitwise
complement of the first. Their pairwise Hamming distance is 68 and each is
distance 64 from erased. Only an exact full-QW read attributed as ECC-clean
**and durably clean** by `OPEN-JRN-DUR-1` is valid. Torn, `ECCC`, `ECCD`, an
exact-looking may-have-launched result, or any other ambiguous observation is
not a valid marker.

The one global arm token occupies exactly TAMP `BKP8..31`; `BKP0..7` remain
the exclusive 32-byte BHK allocation:

| Register(s) | Frozen value/meaning |
|---|---|
| `BKP8/9` | magic `0x4152_4D31` (`ARM1`) and `0xBEAD_B2CE` |
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
ARM_TOKEN_DOMAIN    = b"PQFW_A1"       // exact 7 bytes
ARM_TOKEN_PREIMAGE  = 116 bytes

domain[7] || physical_slot_u8 || R_be_u32 || E_be_u32 || T_be_u32 ||
signed_manifest_digest[32] || secure_hash[32] || nonsecure_hash[32]
```

For the Section-6.1 golden fixture with `T=0x05060707`, the binding digest is
`167270423f35f16bcdecad4e9e19817ac87b06bb8838483be8b97636476c7b7a`,
stored as numeric words `16727042 3F35F16B CDECAD4E 9E19817A C87B06BB
8838483B E8B97636 476C7B7A`.
The decoder independently requires exact complements/magic/seals/slot code,
`R,E` in `1..=0xFFFF_FFFE`, checked `T == E - 1`,
`T <= 0xFFFF_FFFD`, the physical slot match, and a recomputed binding to a
fully verified manifest. It never trusts a companion-supplied digest.

In this table, `BlankVirgin` means an exact-index, ECC-clean all-`0xFF` read
plus proof from immutable-entry operation status and the approved journal state
that no program may have launched for that QW. `DurablyCleanExact` means the
exact codeword plus the still-open durability proof required by
`OPEN-JRN-DUR-1`. An ECCC-corrected all-`0xFF` value is neither blank nor
virgin.

The decoder accepts exactly:

| Logical state | PENDING QW | CONFIRMED QW | Bound TAMP token | Floor relation |
|---|---|---|---|---|
| `UNINSTALLED` | `BlankVirgin` | `BlankVirgin` | ignored | n/a |
| `PENDING(R,E)` | `DurablyCleanExact(PENDING)` | `BlankVirgin` | exact `ARM_READY` | `E > F` |
| `ATTEMPTED(R,E)` | `DurablyCleanExact(PENDING)` | `BlankVirgin` | exact `ATTEMPTED` | `E > F` |
| `CONFIRMED(R,E)` epoch-bump pre-floor | `DurablyCleanExact(PENDING)` | `DurablyCleanExact(CONFIRMED)` | ignored | `F < E - 1` |
| `CONFIRMED(R,E)` steady/same-epoch/factory | `DurablyCleanExact(PENDING)` | `DurablyCleanExact(CONFIRMED)` | ignored | `F == E - 1` |

Every other combination—including a torn flash word, missing, malformed, or
binding-mismatched token while `QW_CONFIRMED` is `BlankVirgin`, an out-of-order
`DurablyCleanExact` marker, an out-of-range `R` or `E`, or `F > E - 1`—is
`MALFORMED` and MUST make
that slot ineligible.
Before `DurablyCleanExact(QW_CONFIRMED)`, token loss is always a safe false
negative. After the approved durability decoder returns that state, the token
is ignored: under the retained writer model the durably validated confirmation
codeword is the acceptance seal. Raw exact bytes never reach this branch.
TAMP retention is never a security assumption.

The only legal transition chain within one slot-installation generation is:

```text
UNINSTALLED --runtime COMMIT--> PENDING
PENDING     --immutable FSBL--> ATTEMPTED
ATTEMPTED   --full HEALTH_PASS + user finalization--> CONFIRMED
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

- Field-update runtime owns creation of the bound `ARM_READY` token and the
  one-time manifest `UNINSTALLED -> PENDING` write.
- FSBL alone changes exact bound `ARM_READY -> ATTEMPTED`.
- Secure runtime health owns the one-time manifest
  `ATTEMPTED -> CONFIRMED` write after Section 9.
- FSBL alone owns floor establishment and any required durable reservation/
  stage plus replicated OTP commitment.
- Factory packaging has the narrow offline genesis exception in Section 7.4.
- No NS command or other code path may perform these writes.

All BHK and arm-token accesses MUST use one reviewed secure/privileged backup-
domain transaction owner. It may set `PWR_DBPR.DBP` only for the bounded write
sequence, MUST fail closed if set/readback does not succeed, then MUST clear
and verify DBP cleared before handoff or NS execution.
Current research helpers that set DBP and leave it set are nonconforming and
cannot be reused unchanged. Every `TAMP_SECCFGR` read-modify-write preserves
`BHKLOCK`, counter-security fields, and all unrelated reserved/configuration
bits. If ES0499 sanitation forces `BDRST`, FSBL treats the token as lost and
selects only the confirmed fallback; the reset also erases `BKP0..7` and
`BHKLOCK`, so the later mutable secure boot reloads BHK from its separately
protected wrapped record before any BHK-derived operation.
On an ordinary retained-VBAT system reset, BHK and `BHKLOCK` may both remain;
boot code validates that exact protected state rather than assuming it was
cleared or attempting to overwrite locked `BKP0..7`.

Field COMMIT ordering is:

1. install and verify inactive images and the immutable manifest body/CRC,
   without issuing a program command to either journal QW or erased reserved
   QWs;
2. write `BKP30`, then `BKP31`, to exact `INVALID`, and read/validate the
   complete token twice before changing any binding word;
3. write `BKP8..25` with the complete new binding body;
4. write body seals `BKP26..29` last within the body;
5. read and validate the complete body twice, including a fresh recomputation
   of the `PQFW_A1` binding;
6. write `BKP30`, then `BKP31`, to exact `ARM_READY`;
7. read and validate the complete token twice;
8. program and perform an immediate diagnostic ECC-clean readback of manifest
   `QW_PENDING` last; and
9. zeroize update state and reset without releasing wallet authority.

A restarted COMMIT always invalidates and rebinds. It never resumes merely
because a stale exact `ARM_READY` exists while `QW_PENDING` is `BlankVirgin`. This
ordering covers byte-identical reinstallations without a per-install nonce.

FSBL arming ordering is:

1. require exact `PENDING` plus exact bound `ARM_READY`;
2. write `BKP30`, then `BKP31`, to exact `ATTEMPTED`;
3. exact-readback the complete token twice;
4. freshly reverify manifest, images, slot, floor, vector and handoff binding;
5. hand off only while the composite state is exact `ATTEMPTED`.

If the TAMP transition is interrupted, exact `ARM_READY` may retry because the
candidate has not run; exact `ATTEMPTED`, token loss, or any malformed token
selects the fallback. Backup-domain reset or tamper erasure therefore cannot
grant a second boot.

Every manifest-flash writer MUST:

1. verify the destination quad-word is exactly erased;
2. program one complete quad-word using the documented STM32U585 sequence;
3. use bounded `BSY|WDW` waits;
4. avoid control/status writes after a stuck-busy timeout;
5. relock the relevant FLASH controller before returning or handing off;
6. invalidate relevant cache state;
7. exact-readback the complete codeword;
8. fail closed on ECC or disagreement.

Immediate EOP/readback is a local diagnostic only. It does not itself create
logical `PENDING` or `CONFIRMED` authority across reset. The next immutable
boot decode must obtain `DurablyCleanExact` through the eventual
`OPEN-JRN-DUR-1` rule before using either marker. If that rule requires any
persistent post-marker write, completion witness, or altered ordering, this
transition sequence and any affected manifest offsets/CRC normalization MUST
be re-frozen before implementation.

Exact erased readback is not sufficient if a marker program may already have
launched. Once `QW_PENDING` or `QW_CONFIRMED` programming is launched or its
launch status becomes ambiguous, no path may program that quad-word again in
the same slot-installation generation, even if it later reads all `0xFF`.
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

The numbering namespace is scoped by the manifest domain/product and vendor-
key fingerprint. Production signing MUST use one canonical, protected,
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
- `E` is nondecreasing as `R` increases;
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
earlier signed artifact in that epoch remains an acceptable rollback target.
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
  blank, ECC-clean record bank plus durable-intent state proving that no stage,
  reservation, claim, or writer launch may be missing or active. No unresolved
  durable stage may change the interpretation. Only this state enters ordinary
  candidate admission and the Section-7.2 selector.
- `Recovering { prior_f, prior_group, allocation_generation, target,
  stage_binding, ordered_cell_roles, consumed_set }`: either the exact highest
  committed group or the canonical `BASE0` identity proves `prior_f`, while a
  separately validated durable stage proves an in-progress
  `target > prior_f`. The stage binds the codec/domain, exact prior-group
  identity/digest and floor, allocation generation/cursor, target and active
  group, candidate/manifest identity, complete ordered cell-role assignment,
  and attempted/consumed/quarantined sets required by the selected codec. FSBL
  MUST bypass ordinary admission, fallback selection, and handoff; it resumes
  only Section 10's approved recovery protocol. The bound `CONFIRMED`
  candidate and signed `T` are independently reverified there. No slot is
  admitted until recovery completes and a fresh full scan returns
  `Steady(target)`.
- `Unknown`: the decoder cannot prove either a steady highest committed floor
  or one unambiguous recoverable stage. FSBL halts before either slot is
  admitted.

These are logical proof classes at the decoder/admission boundary, not three
new persistent journal states and not a mandate for a particular Rust enum or
additional flash record. An implementation may represent them more compactly
provided the behavioral distinctions remain explicit and testable.

An incomplete frontier is never itself the "highest committed group." A valid
durable stage therefore yields `Recovering`, not a misleading plain
`Steady(prior_f)` that could admit a fallback after a possible program launch,
and not terminal `Unknown` merely because recovery is unfinished. Invalid,
missing, rolled-back, multiply active, or target-inconsistent stage evidence;
loss of the clean threshold for the highest committed group; and any ambiguity
about which recovery owns a cell yield `Unknown`. The decoder never defaults
to zero, maximum, or the next-lower historical target. The exact representation
and proof obligations remain part of `OPEN-OTP-1..3`.

The canonical blank-base rule is available only before any establishment
writer may have launched. All-`0xFF` readback alone never reconstructs
`Steady(0)` after a possible stage, claim, or OTP launch. A first epoch-bump
stage may bind `prior_group = BASE0` only when that same canonical proof was
established before stage activation.

For physical slot `s` and rollback floor `F`, `Verified(s, F)` means all of the
following independently pass:

- manifest structure and normalized CRC;
- physical slot binding;
- signed digest binding;
- vendor-key fingerprint and C10 signature;
- in-range `release_version` and `security_epoch` under Section 1.1;
- strict epoch rollback rule `security_epoch > rejected_through_epoch`;
- secure and nonsecure image lengths and hashes;
- exact composite state decoding;
- vector-table and handoff bounds.

Invalid slots do not enter selection. Failure in one slot MUST NOT invalidate
an independently valid other slot.

Before erasing or staging the inactive slot, field-update runtime MUST prove:

1. the running slot is uniquely identified from trusted execution state;
2. the running slot is `CONFIRMED` and fully verified;
3. the target is the other, inactive slot;
4. the release bundle journal is exactly `UNINSTALLED`;
5. the signed physical-slot tag names that inactive slot;
6. `R_new > R_running`, `E_new >= E_running`, and `E_new > F`;
7. checked derivation establishes `T = E_new - 1` and classifies the release as
   same-epoch (`T == F`) or epoch-bumping (`T > F`);
8. only for `T > F`, the selected floor backend reports enough capacity for
   the codec-declared physical cost of `commit_target(T)` and its required
   interrupted-write recovery margin;
9. the user authorizes both signed values and the derived same-epoch/epoch-
    bump classification on the trusted display.

The device does not authenticate or parse the external advisory ledger. That
policy gate acts before vendor-key use and at release publication; on-device
authority is the signed manifest tuple and image binding.

Capacity exhaustion MUST NOT prevent installing a same-epoch release when the
floor still decodes exactly and reliably. It MUST prevent an epoch-bumping
installation before the inactive slot is erased if the required OTP replica,
durable-stage, replacement, and recovery margins are unavailable.

The inactive manifest activation quad-word MUST be programmed last. Before
that activation write is exact and durable, the partially installed slot MUST
fail admission.

### 7.2 Selection rules

FSBL applies this fail-closed selector after independently computing
`Verified(s, F)` for both slots:

| Eligible set | Required decision |
|---|---|
| no `CONFIRMED`, no `PENDING` | halt |
| exactly one `CONFIRMED(Rc,Ec)`, no `PENDING` | idempotently establish `Ec - 1`, then boot it |
| one `CONFIRMED(Rc,Ec)` plus one `PENDING(Rp,Ep)`, `Rp > Rc` and `Ep >= Ec` | arm and try pending once |
| one `CONFIRMED(Rc,Ec)` plus any other valid `PENDING` tuple | ignore the pending release; establish `Ec - 1`, then boot confirmed |
| one `CONFIRMED(Rc,Ec)` plus one `ATTEMPTED` | establish `Ec - 1`, then boot confirmed |
| two `CONFIRMED` with different `E` | attempt to establish and boot the higher-`E` slot; apply Section 10's proven-no-establishment-launch fallback rule if establishment cannot safely start |
| two `CONFIRMED` with equal `E` and different `R` | establish and boot the higher-`R` slot |
| two `CONFIRMED` with equal `(R,E)` | establish the common target and boot physical slot A as the fixed tie-breaker |
| `PENDING` with no confirmed fallback | halt |
| multiple pending candidates | halt |

Every table entry that says "establish ... then boot" is shorthand for the
full Section-10 contract: it may hand off only after a fresh decoder pass
returns `Steady(E - 1)`. "Proven no establishment launch" means the decoder
remains `Steady(F)` and the backend proves that no durable reservation, stage,
claim, activation, or compaction write and no OTP program operation may have
launched. Only then is the alternative handoff Section 10's independently
verified confirmed fallback whose target already equals reliable `F`. If any
pre-`COMPLETE` reservation, stage, claim, or activation write or OTP program
for the target may have launched, FSBL enters/resumes `Recovering` or halts on
`Unknown`; neither fallback nor handoff is available. Post-`COMPLETE` close/
compaction is not an epoch-advance launch: it follows `OPEN-OTP-1`, preserving
`Steady(T)` and permitting normal handoff while an authoritative old copy
survives, or returning `Unknown` if all authoritative completion evidence is
lost or ambiguous. Failure to reach an authorized `Steady` state halts.

`UNINSTALLED`, `ATTEMPTED`, and `MALFORMED` slots are never selected at FSBL
entry. `R` orders only manifests that already pass `E > F`; it is not a second
rollback floor. A non-qualifying `PENDING` never suppresses an independently
valid confirmed fallback. For two confirmed slots, the recovery ordering is
security epoch first, then release preference, then a fixed physical tie-
breaker: `(E, R, slot-A-first)`. This total order does not bless a crossed or
duplicate tuple in the release ledger; it prevents mutable or buggy runtime
state from turning an otherwise bootable confirmed release into a brick.
Immutable selection MUST NOT depend on mutable runtime having behaved
correctly.

The selector's preference does not authorize booting a release whose target
floor was not established. If a preferred confirmed slot needs `T > F` but
the decoder remains `Steady(F)` and the backend proves no establishment-state
or OTP write may have launched, Section 10 may instead boot an independently
verified confirmed fallback whose own target already equals `F`. Once any
pre-`COMPLETE` reservation/stage/claim/activation or OTP program for the target
may have launched, no fallback or handoff selection occurs. On reset the typed
decoder returns the exact bound `Recovering` state or `Unknown`, and FSBL
follows Section 10's approved durable-stage recovery or halts. Only after the
full clean group establishes `T` and a fresh scan returns `Steady(T)` may the
higher candidate enter admission and be handed off. Post-`COMPLETE`
maintenance is instead typed solely by the preserved authoritative completion
evidence: `Steady(T)` permits normal selection/handoff; `Unknown` halts; it is
never `Recovering`. Inability to establish `T` halts. RL-1's confirmed-
preserving selector is not a promise to boot through unresolved OTP state.

For a selected `PENDING` candidate, FSBL follows Section 6.3's frozen
TAMP transition: it requires exact bound `ARM_READY`, changes and twice
readbacks exact bound `ATTEMPTED`, reparses the composite state, freshly reruns
manifest/image/slot/rollback/vector/handoff validation, and only then enters
the candidate.

If arming fails and a verified confirmed fallback exists, FSBL idempotently
establishes that fallback's `E - 1` and then boots it. Without a fallback,
FSBL halts. A cut before `ATTEMPTED` is durable
may leave exact `PENDING`, in which case retry is safe because the candidate
has not run. Once `ATTEMPTED` is durable, every reset before exact
`CONFIRMED` excludes the candidate permanently for that installation
generation.

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
field health protocol. Before final lifecycle locks, a narrowly scoped offline
factory packager MAY stamp a vendor-signed `UNINSTALLED` slot-A release into
canonical `CONFIRMED` form only when all of the following hold:

1. `release_version` and `security_epoch` are in range under Section 1.1, and
   the factory logical rejected-through floor is verified as exactly
   `security_epoch - 1`; if the
   target is zero, erased OTP may represent that logical base without consuming
   a rollback record only under the canonical `Steady(0)` proof in Section 7.1;
2. the vendor key, FSBL bytes, signed manifest, secure and NS image bytes,
   physical addresses, hashes, and measured-boot fingerprint are independently
   reverified after stamping;
3. slot B is canonically invalid/erased, not `PENDING`;
4. complete bank readback matches the expected package;
5. a trusted, tamper-evident factory receipt anchored to the selected policy-
   ledger checkpoint binds all inputs and option/security state;
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
floor is production-eligible.

The keyless blank-bank `F = 0` decoder rule is an availability recovery path
if valid key material later becomes unavailable. It MUST NOT be used to pass
factory provisioning or deliberately ship a MAC-mode device without the
required redundant key receipt.

Every later FSBL handoff of any selected confirmed slot still idempotently
establishes `F == security_epoch - 1`; it does not rely indefinitely on
the factory receipt.

Seed restoration, wallet/admin reset, secure-element replacement, ordinary
main-flash mass erase, and factory rework MUST NOT lower or reinterpret `F`.
After production lifecycle closure, a full main-flash erase is terminal for
this four-state design: with no confirmed fallback, a merely `PENDING` recovery
image cannot boot and the unit is quarantined. Only authorized pre-lifecycle
factory rework may stamp a replacement `CONFIRMED` image while preserving and
satisfying `E > F`; that inequality is necessary but not sufficient authority
for recovery. Pre-production boards carrying incompatible legacy OTP encodings
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
4. trusted PIN entry through the production three-way gated unlock path;
5. successful OPTIGA + SE050 unlock and wallet-master reconstruction;
6. a reviewed local derivation and C10 sign/verify self-test satisfying
   `OPEN-HLT-1`;
7. zeroization of self-test keys, signatures, reconstructed master, PIN, and
   secure caches;
8. proof that the gateway remains logically locked.

The self-test tuple and message MUST be firmware-selected, not
companion-selected. Its domain MUST bind the health-protocol version, physical
slot, signed `release_version`, signed `security_epoch`, and manifest/image
digest. It MUST traverse the
production seed reconstruction, chosen slot derivation, C10 key generation,
signing, and verification path. The signature, digest, key, randomizer, and all
derivation intermediates remain in secure SRAM and MUST NOT be returned to NS
or counted as externally released signing usage.

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

The secure-only probation context binds:

- physical slot;
- signed `release_version`;
- signed `security_epoch` and derived `T = E - 1`;
- independently validated `F_snapshot` and the derived same-epoch/epoch-bump
  classification;
- for an epoch bump, the preflighted replica/stage/replacement/recovery-margin
  result;
- secure image digest;
- nonsecure image digest;
- exact composite `ATTEMPTED` state;
- the fresh 128-bit secure `session_id` once created;
- the companion-provided host nonce;
- a secure monotonic deadline;
- response-attempt state;
- after success, a secure-only digest of the exact canonical completion
  transcript, retained solely for duplicate-response classification;
- finalization state.

It is stored only in secure SRAM and is destroyed on reset, timeout, cancel, or
final confirmation. Transport completion erases the plaintext challenge but
retains only the transcript digest until finalization.

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
   `OPEN-HLT-2`;
3. binds `{host_nonce, session_id, challenge, slot, release_version,
   security_epoch, target, F_snapshot, update_class,
   bump_capacity_preflight_result, image hashes, deadline, attempt_consumed}`
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
returns `BUSY`. Begin retransmissions are bounded.

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
3. atomically consume the sole syntactically valid response opportunity before
   comparing the challenge;
4. compare without an early-exit timing oracle;
5. reject reuse in every pre-success phase; and
6. on success, compute and retain a domain-separated secure-only digest of the
   exact canonical `HEALTH_COMPLETE` request, erase the stored plaintext
   challenge, and enter a volatile `TRANSPORT_PASSED` phase.

A wrong syntactically valid challenge consumes the session and causes clean
probation failure. Malformed frames need not consume the challenge opportunity,
but neither they nor any other NS traffic may extend the absolute secure
deadline. There is no abort-and-create-new-session path; session loss safely
requires reinstalling and rearming the candidate.

After `TRANSPORT_PASSED`, secure runtime recomputes and constant-time compares
the canonical request digest. An exact duplicate completion MAY return a fixed
`ALREADY_COMPLETE` status and MUST NOT reset state, consume another attempt, or
extend the deadline. A different completion is rejected without revoking the
already-established transport result. The retained digest is never returned.
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

The secure monotonic deadline starts no later than completion of Milestone 1.
PIN/local-health waits and full transport/finalization waits are individually
bounded. NS traffic, heartbeat changes, retransmissions, malformed commands,
USB reconnects, and gateway activity MUST NOT reset or extend either deadline.
The existing secure timer and/or IWDG MUST guarantee reset if NS fails to start
or service the restricted probation loop; this requirement does not by itself
authorize a new broad watchdog/reset subsystem.

On deadline expiry, wrong challenge, user rejection, display or TRNG failure,
pre-`TRANSPORT_PASSED` USB loss, retry exhaustion, gateway failure, or
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
    and older releases in that epoch remain admissible fallbacks; or
  - epoch bump: the next FSBL boot irreversibly rejects every release through
    epoch `T`, including the previous lower-epoch fallback;
- clear cancel and timeout behavior.

The user must review all pages and perform an FI-hardened long confirmation.
Immediately before the write, secure runtime MUST re-read and validate the
running physical slot, signed `(R,E)`, current `F`, derived classification,
image identity, and exact composite `ATTEMPTED` state. Any difference from the
probation-bound snapshot fails closed rather than changing classification.
For an epoch bump it MUST also repeat the selected backend's capacity and
recovery-margin preflight before making `CONFIRMED` durable; an unexpected
shortfall resets toward the fallback. Same-epoch finalization must not require
or invoke an OTP-commit or durable-stage-capacity path.

Only this affirmative branch may write the exact `CONFIRMED` codeword.

Immediately afterward, secure runtime:

1. performs the immediate diagnostic ECC-clean exact readback of
   `CONFIRMED`, without treating it as cross-reset durability authority;
2. permanently keeps the gateway in its restricted/locked state and prevents
   return to NS or the ordinary wallet lifecycle;
3. zeroizes probation and sensitive state; and
4. enters a non-returning reset path without publishing an unlocked state. If
   the reset request unexpectedly returns or fails, execution remains in a
   terminal locked watchdog/halt loop until watchdog, external reset, or power
   cycle transfers control back to FSBL. It never returns to the caller.

Cancellation, deadline expiry, transport exhaustion, wrong challenge, identity
mismatch, or any internal error MUST reset without writing `CONFIRMED`.

### 9.6 False-negative behavior

A good candidate paired with a broken companion, flaky USB port, or absent host
may fail Milestone 2. That is an accepted safe false negative.

On failure:

- the device must not hang or confirm;
- the next FSBL boot selects the old confirmed slot;
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
same-epoch confirmation leaves older same-epoch releases floor-admissible if
they remain otherwise valid and can be reached by a future separately reviewed
recovery design. A renderer-only fault may still leave the PIN-gated firmware-
update path usable for a forward repair; a fault in the normal unlock/publish
or update-dispatch path may not. None of these cases is claimed closed here.

Project documentation MUST say "rollback covers failures through the defined
local and USB/gateway probation checks," not "all crashing releases recover."
Closing the post-confirm ordinary-path residual requires an additional durable
pre-handoff milestone or a demotion/grace design and is explicitly deferred
for separate downgrade-policy review.

---

## 10. Confirmation and epoch-floor establishment

Section 10 has two disjoint entries: `start_from_steady` for a preferred exact-
`CONFIRMED` slot selected from `Steady(F)`, or `resume_from_recovery` for a
decoder-supplied context after an earlier `begin`. Recovery is bound to one
target/candidate and bypasses the ordinary selector, same-epoch classifier,
ordinary preflight, and every fallback path. In both cases FSBL MUST:

1. independently re-read the rollback floor and durable stage through the
   fresh-array, per-QW ECC-aware decoder required by
   `OPEN-ECC-1`/`OPEN-OTP-3`; dispatch `Steady(F)` only to
   `start_from_steady` and exact bound
   `Recovering { prior_f, target, ... }` only to `resume_from_recovery`; halt
   on `Unknown`, type/entry mismatch, or inconsistent recovery binding;
2. re-validate manifest structure, normalized CRC, slot binding, vendor
   signature, strict rollback rule against `F` or the exact recovery
   `prior_f`, and `DurablyCleanExact(CONFIRMED)` state;
3. re-hash secure and nonsecure images;
4. independently re-read signed `R` and `E`, require both values to be in
   `1..=0xFFFF_FFFE`, derive `T = E - 1` using checked arithmetic, and require
   `T <= 0xFFFF_FFFD`; no reserved sentinel can reach the writer even if an
   earlier validation is faulted;
5. on `start_from_steady`, require `T >= F`; `T < F` fails closed. When
   `T == F`, issue no OTP unlock/program command or persistent stage write.
   When `T > F`, repeat the snapshot-bound read-only preflight and invoke
   `begin(intent)` exactly once through the private FSBL stage/OTP writer;
6. on `resume_from_recovery`, require the freshly derived `T` equals the proof
   target and `T > prior_f`, independently revalidate every stage/group/role
   binding, and resume that exact active protocol. It MUST NOT call `begin`,
   ordinary preflight/classification, or any fallback path;
7. for each physical replica independently, invalidate the documented flash
   cache/data-buffer state, clear stale ECC flags, force one attributed array
   read, and snapshot/consume ECC status before the next flash access;
8. verify a fresh full scan returns exactly `Steady(T)`, with no unresolved
   durable stage or higher ambiguous group;
9. re-check the still-confirmed `(R,E)`, manifest, and image binding; and
10. only then perform final handoff.

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

A `RecoveryProof` never re-enters this list or calls `begin`, even though its
bound `prior_f < target` satisfies the same numeric inequality. It follows only
the `resume_from_recovery` branch above across every reset.

`commit_target(T)` is the umbrella name for one logical transition from the
previously decoded floor to exactly `T`; it does not prescribe a one-QW
encoding and is not one callable entry. A fresh transition uses
`start_from_steady`/`begin` once; a rebooted transition uses only
`resume_from_recovery`. The
floor is the `Steady` value produced by the approved fail-closed decoder over
the complete OTP record bank plus its approved durable stage. While a valid
target is in progress, the same interface returns `Recovering` rather than
exposing `prior_f` to ordinary admission. A torn or unreadable physical record
never contributes a lower or higher value merely through best-effort parsing.
Physical-cell reuse and durable intent follow `OPEN-OTP-3`.

An exact raw QW value is never by itself a successful commitment. Success
requires the complete approved structural code and clean-replica group. A
matching `ECCC` read rejects that replica even when hardware-corrected bytes
equal `T`. For the highest committed group, the remaining independent clean
witnesses either satisfy the approved degraded threshold for that same target
or the result is `Unknown`; no older record is returned. For an active target
group, a valid stage remains `Recovering` and may use only separately
preclaimed replacements, while a stage/threshold ambiguity is `Unknown`.
`ECCC`-clean exact bytes are necessary but not sufficient after a possible
interruption; a possibly interrupted QW has zero quorum weight even when its
returned bytes equal `T`. Durably logged clean pre-cut replicas may be retained,
and separately preclaimed clean replacements may be added after recovery;
neither path establishes `T` until a fresh `COMPLETE` records the full clean
initial threshold. Until `OPEN-OTP-1..3` defines and validates that ordered
protocol and the all-`0xFF` intent rules, the epoch-bump success path is not
production-authorized.

Failure before a target commit is distinct from ambiguity after one may have
launched. FSBL may boot a lower preferred-order slot only if all of the
following hold:

1. the combined decoder entry and fresh re-read both remain exactly
   `Steady(F)`;
2. the backend proves no durable reservation, stage, claim, activation, or
   compaction write and no OTP program operation for this target may have
   launched;
3. the other slot is independently valid and exactly `CONFIRMED` under that
   floor; and
4. the fallback's checked target equals the existing floor
   (`E_fallback - 1 == F`), so its handoff needs no OTP program command.

This proven-no-establishment-launch fallback is deterministic on every later
boot; the higher confirmed candidate remains unselected until
capacity/key/backend availability is repaired or authorized factory/service
action changes the physical state. If no such fallback exists, FSBL halts.
If any pre-`COMPLETE` establishment-state or OTP write for the target may have
launched, FSBL never takes the fallback path. It may proceed only through the
approved durable-stage recovery protocol, which gives the uncertain QW zero
weight, never retries it, and establishes `T` from a newly completed clean
group before handoff. If the
reservation/stage remains valid but the required group cannot yet be completed,
the decoder remains `Recovering` and FSBL halts without booting either slot. If
it cannot prove the reservation/stage or the highest committed floor, the
result is `Unknown` and FSBL likewise halts. It never uses an older release to
mask ambiguous anti-rollback state.
Post-`COMPLETE` close/compaction follows the separate maintenance rule in
`OPEN-OTP-1`: retained authoritative evidence yields `Steady(T)` and permits
normal handoff; loss/ambiguity yields `Unknown`; it never enters this fallback
or epoch-advance `Recovering` path.

A same-epoch confirmation does not floor-retire the previous slot. It remains
admissible and loses only by the unique higher-`R` selector while that newer
release remains valid and present. A successful epoch bump retires every slot
with `E <= F'`; the prior lower-epoch slot becomes ineligible only after exact
durable establishment of the new target.

The canonically proven erased/factory logical base floor is exactly
`Steady(0)`; security epoch zero is never admissible. `release_version` is
independent and also starts at one or
above. Jumping either number does not create multiple logical floor
transitions: only a transition from `T == F` to `T > F` invokes
`commit_target(T)`. Its physical QW cost is whatever the approved codec
declares, independent of the number of skipped epoch values.

---

## 11. Power-cut and transition matrix

| Cut/failure point | Durable state | Required next boot | Old slot status |
|---|---|---|---|
| Image/manifest staging before token/PENDING activation | incomplete/non-PENDING | candidate ignored | eligible |
| System reset reports interrupted manifest operation in `FLASH_OPSR` | exact address/QW is `UnknownMayHaveLaunched` regardless of bytes | immutable entry snapshots/attributes status before any later mutation; no confirm/floor advance/rewrite; safe full-page new-generation erase only when independently inactive, otherwise inhibit flash and halt/recover | eligible fallback preserved when independently valid |
| TAMP token body/ARM_READY torn, PENDING absent | no valid candidate activation | stale/malformed token ignored | eligible |
| Exact ARM_READY token, PENDING absent | no valid candidate activation | stale token ignored | eligible |
| PENDING activation torn or apparently erased after launch | malformed/non-PENDING | candidate rejected; no same-QW retry, later reinstall requires full manifest-page erase | eligible |
| PENDING activation interrupted, then reads exact/ECCC-clear without approved durability proof | `UnknownMayHaveLaunched`, not PENDING | candidate rejected; follow only the approved durability/reinstall rule | eligible |
| Exact PENDING + exact bound ARM_READY | PENDING | FSBL may arm once | eligible |
| Valid CONFIRMED + equal/crossed/otherwise non-qualifying PENDING | confirmed fallback plus ignored candidate | establish confirmed target and boot fallback | selected; pending cannot brick it |
| Two valid CONFIRMED with cleanly ordered, crossed, or equal tuples | normal post-update state or recovery anomaly | select higher `E`, then `R`, then fixed slot A, subject to Section 10 | selected only after required target establishment |
| Cut before Ready→Attempted TAMP transition | PENDING | retry arming; candidate has not run | eligible |
| Cut before Ready→Attempted transition, then ARM_READY is lost by VBAT drain, tamper, or backup-domain reset | malformed PENDING composite | reject candidate and boot eligible confirmed fallback; fresh retry requires PIN-gated reinstall/re-arm | eligible; retry benefit was lost, not security |
| VDD/VBAT marginal power cycle covered by ES0499 before the cold-boot workaround is proven | TAMP/BKP content is unpredictable, not an authoritative retained token | do not decode for retry authority; apply the approved `MONEN` or earliest immutable `BORRSTF` + integrity-test + forced-`BDRST` sanitation, then treat the cleared token as fallback/reinstall | eligible; TAMP backend remains production NO-GO until silicon receipt |
| Ready→Attempted interrupted, token still exact ARM_READY | PENDING | retry transition; candidate has not run | eligible |
| Ready→Attempted interrupted, token exact ATTEMPTED | ATTEMPTED | candidate excluded; fallback | eligible |
| Ready→Attempted interrupted, token lost/malformed | malformed | candidate rejected | eligible |
| Exact ATTEMPTED durable, before handoff | ATTEMPTED | candidate rejected | eligible |
| ATTEMPTED durable, before local health | ATTEMPTED | candidate rejected | eligible |
| During PIN/SE/self-test | ATTEMPTED | candidate rejected | eligible |
| During NS/USB/gateway probation | ATTEMPTED | candidate rejected | eligible |
| Companion absent/unresponsive | ATTEMPTED | bounded failure then reset/fallback | eligible |
| Wrong/replayed challenge | ATTEMPTED | reset/fallback | eligible |
| Final UI cancelled or timed out | ATTEMPTED | reset/fallback | eligible |
| CONFIRMED write torn or apparently erased after launch | malformed | candidate rejected; no same-QW retry, later reinstall requires full manifest-page erase | eligible |
| CONFIRMED write interrupted, then reads exact/ECCC-clear without approved durability proof | `UnknownMayHaveLaunched`, never accepted confirmation | do not establish floor; reject candidate and use only the independently valid fallback | eligible |
| CONFIRMED durable, then TAMP token lost | exact acceptance seal | token ignored; classify from signed `E` and current `F` | same-epoch old slot remains eligible; lower epoch remains eligible until replicated commitment |
| Same-epoch CONFIRMED, `T == F` | steady without floor write | issue zero OTP program commands; boot unique higher `R` | remains floor-eligible |
| Epoch-bump CONFIRMED, `T > F`, before commitment | `Steady(F)` plus CONFIRMED candidate | FSBL starts only the approved durable-stage and replicated floor commitment | eligible until any launch; no handoff before `Steady(T)` |
| Cut during durable-stage body/activation, with proof that no stage write launched | `Steady(F)`; no active establishment state | proven-no-establishment-launch rule may select only an independently verified confirmed fallback with target `F` | fallback remains eligible |
| Durable-stage body/activation may have launched, before first OTP command | exact valid stage => `Recovering`; torn/replayed/ambiguous stage => `Unknown` | bypass selector and fallback; resume the exact bound stage or halt | no handoff even though no OTP pulse is proven |
| Durable recovery stage active at boot | `Recovering { prior_f: F, target: T, ... }` | bypass admission and fallback; reverify the bound CONFIRMED candidate and resume Section 10 | neither slot handed off until fresh `Steady(T)`; otherwise halt |
| Epoch-bump OTP replica write interrupted by system reset | `Recovering` plus a clean-looking, corrected, malformed, exact-looking, or ambiguous replica outcome | consume `FLASH_OPSR`; fresh-read and mark the attempted QW consumed with zero quorum weight regardless of returned bytes; continue only through the approved durable-stage and replica-group protocol, otherwise halt; never reprogram it | lower epoch retires only if other proven-clean replicas complete the approved group; otherwise not handed off |
| Epoch-bump OTP replica may have launched, then complete power loss; QW reads all `0xFF` | indistinguishable from virgin without durable pre-claim or authoritative discriminator | do not claim reuse or quarantine from readback alone; follow an approved pre-claim/discriminator, otherwise halt and keep field epoch bumps NO-GO | physically present; not handed off |
| Possibly interrupted QW later reads bit-exact `T`, `ECCC` clear | uncertain replica; exact bytes are not durability evidence | give that QW zero quorum weight; retain only durably logged clean pre-cut replicas, add separately preclaimed clean replacements, and require a fresh `COMPLETE` for the full initial threshold | lower epoch retires only after that new complete group establishes `T` |
| Any highest-committed-group read raises matching `ECCC` | corrected replica; not clean authority | reject that replica after fresh-array attribution; accept the same floor only from the remaining clean threshold, otherwise return `Unknown` and halt—never fall back to a lower floor | not selected through a lowered floor |
| Full clean target replicas exist, but `COMPLETE` body/activation is torn or may have launched | exact valid pre-complete stage => `Recovering`; ambiguous/replayed completion => `Unknown` | never accept a degraded initial group or retry an ambiguous same record; use only the approved bound replacement/completion recovery or halt | lower epoch remains unselected; no handoff |
| Exact `COMPLETE` durable, then optional stage close/compaction is cut | old authoritative completion copy and group remain `Steady(T)` until a disjoint replacement is durable; loss/alias/ambiguity of all authoritative copies => `Unknown` | never overload epoch-advance `Recovering`; continue from `Steady(T)` or halt, never return prior `F` | handoff only from `Steady(T)` |
| Epoch-bump replicated commitment durable and complete | fresh decoder returns `Steady(T)` from clean target group and resolved authoritative completion evidence | restart ordinary admission, then select the confirmed candidate | lower epoch intentionally retired |
| Previously accepted epoch-bump CONFIRMED marker later degrades | physical-journal durability/recovery route required by `OPEN-JRN-DUR-1` | preserve an authenticated boot path for the floor-bound accepted manifest or halt; never lower `F` | old lower epoch remains intentionally retired; a design that only bricks is production-ineligible |
| Floor capacity exhausted before same-epoch update | reliable existing floor | same-epoch update remains permitted; zero OTP writes | remains eligible |
| Floor capacity/key/backend unavailable for epoch bump, proven before any reservation/stage/claim/compaction or OTP launch | exact `Steady(F)`; higher candidate remains CONFIRMED | boot an independently verified confirmed fallback only when its target is exactly `F`; otherwise halt | fallback selected without establishment write; higher candidate remains unselected |
| MAC root/key unreadable with fully blank, ECC-clean record bank and durable-intent proof that no writer state/launch is missing | canonical `Steady(0)`, future commitment unavailable | boot an otherwise-valid `E=1` confirmed slot; for a higher-epoch candidate use the proven-no-establishment-launch fallback rule or halt | runtime recovery only; factory ship gate still requires valid key receipt |
| OTP record root/key unreadable with any nonblank or ambiguous record bank | floor fail-closed | fail closed | not used to bypass floor |

All ordinary pre-confirmation failures preserve the previous confirmed slot.
No state transition treats a torn word as a weaker valid state. The OTP rows
are architecture gates, not an implemented retry or acceptance promise.
Visible all-`0xFF` data alone MUST NOT authorize reusing a QW whose program may
have launched. Exact authorized bytes and `ECCC` clear are still insufficient
without the approved clean replicated group and retention policy. A corrected
or ambiguous frontier never makes the decoder return a lower floor. Loss of
clean quorum for the highest committed group produces `Unknown`; an incomplete
frontier with intact prior committed quorum and one exact bound stage remains
`Recovering`; an invalid or ambiguous stage is `Unknown`.

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

Under the currently proposed physical reservation map:

- 27 OTP quad-words are available to rollback records;
- at least one recovery cell is preserved;
- at most 26 clean physical QW programs remain after preserving that reserve;
  because a single-QW committed floor is rejected, the number of logical epoch
  bumps is strictly lower and is determined only by the final group/claim/
  recovery cost;
- canonical `E = 1, F = 0` factory genesis consumes no floor record and leaves
  26 physical QWs, not 26 promised epoch bumps; a higher-epoch genesis consumes
  the selected codec's complete factory group cost;
- torn/poisoned virgin cells reduce remaining capacity;
- an ambiguously attempted all-ones cell counts as unavailable only when the
  approved durable pre-claim/discriminator identifies it; without such a
  mechanism the backend cannot claim safe remaining capacity and stays NO-GO;
- jumping `security_epoch` performs one logical `commit_target(T)`, not one
  commitment per skipped number; its physical cost is codec-defined, while
  changing only `release_version` consumes none;
- every approved replicated format reduces epoch-advance capacity and must
  state its exact clean, degraded, and interrupted-write capacities.
- capacity is computed from the global unique-ownership partition: duplicate
  indices never increase quorum or capacity, and committed, active,
  replacement, consumed/quarantined, and virgin roles are pairwise disjoint;
  compaction may not recycle a quarantined index.

The 26-clean-program number is only a physical-program upper bound, not a
promise of 26 field bumps on any device. Same-epoch releases are not counted
against it. Every durable claim/cursor, incomplete group, rejected ECCC
replica, interrupted-write reserve, and multi-QW commitment reduces the final
logical count and must be included before approval.

For scale only, an unselected feasibility candidate uses three target replicas,
requires all three clean plus a durable `COMPLETE` stage before initial
commitment, and permits a two-of-three clean quorum only for later degradation.
It would allow at most `floor(26 / 3) = 8` clean epoch commitments before any
additional claim, staging, replacement, or recovery cost. A cut between a
replica's EOP and `COMPLETE` treats that replica as uncertain and replaces it;
it does not commit a degraded group. A two-replica scheme has no one-replica-
loss availability margin unless additional durable completion state changes
its decoder semantics. These examples are not codec approval; they show why
the owner must review security and usable epoch capacity together.

"No OTP record" does not mean unlimited signing: every logical release still
consumes its slot-bound vendor C10 authorization under Section 6.4's global
per-key budget and the finite `R` namespace.

No per-bit unary, ternary, or full-zero extension is valid because a programmed
OTP quad-word cannot be programmed a second time.

The capacity preflight formula is physical, not merely logical:

```text
required_physical_qws = 0
    when T == F

required_physical_qws = codec.target_commit_qws(T)
                      + codec.recovery_margin_qws(T)
    when T > F

required_stage_records = 0
    when T == F

required_stage_records = codec.stage_commit_records(T)
                       + codec.stage_recovery_margin(T)
    when T > F
```

`target_commit_qws` includes every OTP replica normally required for one
successful logical `commit_target(T)`; `recovery_margin_qws` reserves OTP cells
the interruption model can consume or replace. The stage terms separately
cover a pre-OTP reservation/completion journal if route 1 is selected. Every
term is codec-specific, and preflight must prove both OTP and journal capacity
and health rather than assuming either cost equals one.

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
2. both Opus reviews adjudicate the security evidence;
3. every still-viable `(journal, floor codec, durable-intent route)`
   combination receives its own isolated, nonshipping, production-equivalent
   combined FSBL build from one frozen source state, toolchain, linker script,
   release/LTO flags, feature set, 40 KiB FLASH geometry, the exact
   `OPEN-RAM-1` transient-RAM geometry, and real 32-byte vendor key;
4. that combined build includes the manifest-v4 parser and legacy rejection,
   confirmed-preserving selector, selected journal, minimal ECCD-NMI recovery,
   fresh-array per-QW ECCC attribution, complete floor/group/stage decoder,
   completion/replacement and selected durable-intent path (including
   pre-claim machinery only when that route requires it), floor writer,
   handoff, measured-boot decoder/table actually proposed, and every load-
   bearing trust-root FI check;
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
8. the owner explicitly selects the security/capacity/footprint tradeoff.

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
   active stage yields `Recovering`; an invalid/ambiguous/replayed stage yields
   `Unknown`; and no case returns an older or unauthorized higher floor;
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
   and consumed/quarantined reuse are rejected;
7. prove `T == F` executes none of the OTP or durable-stage writer/compaction
   paths, including on exhausted or degraded devices;
8. treat cut testing as falsification/characterization, not proof that a
   retention-marginal or launched-all-`0xFF` class is absent for product life;
   any design relying on absence needs an authoritative STM32 guarantee and a
   quantitative production reliability argument in addition to board receipts;
9. review the then-current STM32U575/U585 device errata, including ES0499, for
   OTP, flash programming, ECC, reset, cache, and debug/RDP interactions;
   archive the exact official PDFs with revision and SHA-256 and map every
   load-bearing erratum title used by this design to the section number in
   that archived revision rather than inheriting moving section numbers; and
10. publish the final 32-quad-word production map and recalculate usable epoch-
   advance capacity after every reservation and recovery margin.

Nothing in this section authorizes an OTP write. A test plan, build, or fixture
must not infer authorization from the existence of this specification.

---

## 14. Staged implementation milestones

### Milestone 0: specification approval

No production-shared rollback implementation code starts until:

- a candidate-final document is frozen under one full SHA-256 digest;
- two independent Claude Code Opus reviewers inspect that same frozen digest
  and approve it or issue explicit red lines;
- the owner resolves every required red line, then the resulting changed text
  is re-frozen and rechecked by both reviewers (or separately approved by both
  as the final digest); no materially changed draft inherits an earlier
  approval;
- the owner explicitly approves the final digest and signs the Section-19
  record;
- `FROZEN-MAN-1` has exact approved schema/domain/offset/CRC bytes;
- `FROZEN-JRN-IFACE-1` has exact composite bytes and trust tradeoff, while
  `OPEN-JRN-HW-1` and `OPEN-JRN-DUR-1` must close before the TAMP/marker
  backend is production-eligible;
- `OPEN-RAM-1` freezes the transient FSBL SRAM geometry, authoritative static
  end/span,
  worst-case stack margin, and guard/handoff policy;
- `OPEN-REL-1` selects the protected authority, A/B ceremony, and checkpoint
  model;
- `OPEN-C10-1` is replaced by the reviewed numeric global per-physical-key cap
  and exact counting/republication rules; and
- Section 12.6's joint security/footprint gate has measured every still-viable
  combination and the selected journal/codec/durable-intent combination has a
  production-equivalent combined physical FLASH LOAD span no greater than
  38,912 bytes and passes the approved RAM/stack envelope; and
- the document names every remaining open decision honestly.

Isolated nonshipping host models, size experiments, and explicitly destructive-
test-gated silicon fixtures may be used to close an open decision. They MUST
live outside production dispatch/build profiles, cannot create a de facto wire
format or state-machine default, and confer no implementation approval. Any
hardware write still requires the separate named-board/QW authorization in
Section 13.

Before a destructive Section-13 fixture runs or a candidate family receives
substantial implementation investment, Section 5's early combined FLASH+RAM
warning build MUST be recorded. A red warning triggers design simplification/
deferral review; a green warning is not Milestone-0 closure and grants no code
or hardware authority.

### Foundation A: OTP-backed physical boot mechanism

Scope:

- clean slot-bound manifest-v4 format signing canonical `(R,E)` under a new
  domain, with legacy formats rejected;
- implement only the reviewed `FROZEN-JRN-IFACE-1` encoding after
  `OPEN-JRN-HW-1` and `OPEN-JRN-DUR-1` close; isolated host models may precede
  that evidence;
- composite journal decoder and pure confirmed-preserving selector;
- PENDING/ATTEMPTED transition writers;
- minimal recoverable ECC-NMI reads and per-QW fresh-array ECCC attribution
  under `OPEN-ECC-1`;
- implement only the reviewed `OPEN-RAM-1` linker/stack-bound/guard policy and
  preserve the runtime's approved handoff limit; no silent SRAM enlargement;
- runtime floor writer removal;
- FSBL-only idempotent epoch-floor interface that issues no OTP program command
  or durable stage write for `T == F` and performs one logical target
  commitment for `T > F` using the approved codec's explicitly measured
  reservation, replica, completion, replacement, and recovery cost;
- resolve `OPEN-ECC-1` and `OPEN-OTP-1..3` through isolated models,
  measurements, and authorized evidence; freeze the exact selected read
  primitive, record/group code, durable-stage state machine, capacity, and
  interruption behavior in a reviewed spec digest; only then implement those
  semantics in production-shared code;
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

In Foundation A, "resolve, then implement" is a strict ordering: code does not
choose an unresolved load-bearing behavior. Foundation A cannot close on a
host model or footprint result alone; the selected backend needs every
required Section-13 silicon receipt and both adversarial implementation reviews.

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
- both adversarial reviewers approve the implementation diff.

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
- every power cut after exact `ATTEMPTED` and before exact `CONFIRMED` selects
  the old slot; pre-`ATTEMPTED` cuts follow Sections 6/11's exact retry-or-
  ignore rules because no candidate handoff occurred; post-confirmation floor
  cuts follow Sections 10–11 and may recover the replicated group or halt, but
  never boot through `Unknown` floor state;
- product documentation exactly names the proven coverage boundary;
- both adversarial reviewers approve.

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
- exact pinning of both 16-byte marker codewords, every single-bit mutation,
  erased/zero/ECCC/ECCD classifications, all three state pairs, both slot
  pairs, every complement/seal/reset intermediate, the 116-byte `PQFW_A1`
  preimage, and its frozen binding digest;
- every prefix of token invalidation/rebinding/activation, including reinstall
  of byte-identical signed artifacts, fails backward rather than decoding as a
  forward state;
- interrupted TAMP Ready→Attempted outcomes: exact ready retries, while exact
  attempted, lost, binding-mismatched, or malformed tokens fall back;
- token loss/VBAT drain/tamper/backup-reset before Ready→Attempted rejects the
  candidate and requires a new PIN-gated reinstall rather than falsely taking
  the exact-ready retry path;
- ES0499 marginal VDD/VBAT traces never let unpredictable backup state enter
  the token decoder: the selected protected-`MONEN` or earliest immutable
  `BORRSTF`/integrity/`BDRST` path sanitizes first, and forced BDRST yields a
  fallback plus later BHK reload rather than retry;
- NS/unprivileged writes cannot change `PWR_BDCR1.MONEN`, TAMP zone/privilege
  settings, or `BKP8..31`; DBP is cleared and read back before every handoff,
  while every TAMP configuration RMW preserves `BHKLOCK` and counter fields;
- exhaustive typed floor/stage decoding: only `Steady(F)` reaches admission;
  one exact valid in-progress stage yields bound `Recovering` and bypasses
  selection/handoff; invalid, missing, multiply active, rolled-back, or
  target-inconsistent stage evidence yields `Unknown`; an incomplete frontier
  is never treated as the highest committed group;
- a fully blank ECC-clean bank with proof that no durable-intent state or
  writer launch is missing returns canonical `Steady(0)`; the first active
  target may bind exact `BASE0` as `prior_group`, while blank readback after any
  possible stage/claim/OTP launch never reconstructs the base;
- every `Recovering` transition either reaches a fresh `Steady(T)` under the
  approved full-threshold protocol or halts, and no possible-launch recovery
  path admits the prior-floor fallback;
- mutation tests reject every stale prior-group digest, allocation generation/
  cursor, active-group/candidate identity, and cell-role-map replay; duplicate
  QW indices, cross-group overlap, source/replacement alias, consumed-or-
  quarantined reuse, and one QW counted twice toward quorum all yield
  `Unknown`; compaction preserves the global ownership/quarantine partition;
  after authoritative `COMPLETE`, every safe compaction prefix preserves
  `Steady(T)` from an old copy and never reuses epoch-advance `Recovering`, while
  loss/ambiguity of all authoritative copies is `Unknown`;
- exhaustive two-slot selector combinations and confirmed recovery ordering;
- pending-only and multiple-pending rejection when no confirmed fallback
  exists;
- equal-`R` and both crossed `R/E` PENDING tuples are ignored when a valid
  confirmed fallback exists, including the same release's other-slot artifact;
- two-confirmed selection chooses higher `E`, then higher `R`, then physical
  slot A for exact `(R,E)` equality;
- manifest-v4 golden vectors shared by signer, inspector, firmware, FSBL, and
  any formal extraction; mutation of slot, `R`, `E`, either image hash, schema,
  or domain must break the signed binding, and every legacy schema is rejected;
- all three full-page manifest fixtures—erased journal, exact PENDING, and
  exact PENDING+CONFIRMED—retain `CRC=0x993615CD` while producing their frozen
  distinct page SHA-256 values, proving the journal window is normalized rather
  than accidentally omitted or raw-hashed;
- exhaustive `E > F` admission and checked `T = E - 1`, including both
  reserved sentinels, base `E == 1, F == 0`, numeric jumps, and integer
  ceilings;
- the private floor writer independently rejects every `R` or `E` outside
  `1..=0xFFFF_FFFE` and every derived `T > 0xFFFF_FFFD`, even when its caller
  supplies a faulted/prevalidated object;
- runtime cannot call a floor writer;
- the field confirmation writer rejects a wrong running slot, non-`ATTEMPTED`
  or binding-mismatched token, changed `(R,E,F)`/classification, failed bump-
  capacity recheck, incomplete or expired health, user cancel, and any
  nonblank/ambiguous destination;
- a torn or apparently-erased PENDING/CONFIRMED marker is never programmed
  again before a full later inactive-manifest-page erase;
- an interrupted marker that later returns exact bytes with `ECCC` clear is
  classified `UnknownMayHaveLaunched` unless the selected durability witness
  proves it clean; it never confirms or advances the floor from bytes alone;
- immutable reset-entry tests snapshot the single common `FLASH_OPSR` once
  before any later flash mutation and exhaust `CODE_OP`/`SYSF_OP`/`BK_OP`/
  `ADDR_OP` attribution for both bank-selector values,
  and prove an interrupted manifest QW cannot be rewritten or masked by an
  exact-looking read; complete-power-loss tests separately omit OPSR evidence;
- after an epoch floor binds an accepted manifest, loss/degradation of one
  confirmation witness exercises the selected redundant/floor-bound recovery
  rather than silently lowering `F` or accepting a brick-only design;
- after `DurablyCleanExact(QW_CONFIRMED)`, every TAMP value—including lost,
  malformed, stale, or rebound—is ignored under the retained writer model;
- a post-confirm reset primitive that unexpectedly returns cannot re-enter NS,
  normal dispatch, or wallet authority and reaches only the terminal locked
  watchdog/halt path;
- same-epoch confirmation never enters the OTP writer, OTP unlock, durable
  reservation/stage writer, or stage-compaction path across repeated boots,
  including when no virgin record cell remains;
- entry instrumentation proves same-epoch `CheckedSteadyIntent` performs zero
  preflight and zero `begin`, fresh epoch-bump entry invokes `begin` at most
  once, and `resume_from_recovery` invokes neither ordinary preflight nor
  `begin` across any number of resets;
- an epoch bump invokes exactly one logical `commit_target(T)` and the
  codec-declared number of physical QW programs; numeric epoch skips do not
  multiply either cost, and old epochs become inadmissible only after the
  logical target is durable;
- same-epoch preferred-slot corruption may boot an older eligible same-epoch
  release, and this is asserted as the documented residual;
- commitment idempotency and conditional replica/stage/recovery-margin
  preflight;
- deterministic capacity/key/backend failure while the decoder remains
  `Steady(F)` and before any reservation/stage/claim/compaction or OTP write may
  have launched boots only an independently verified confirmed fallback with
  `T_fallback == F`; absence of that fallback halts, and any possibly launched/
  ambiguous establishment write never takes the fallback path;
- the per-QW ECC reader clears stale flags, forces a fresh array access despite
  flash-buffer/cache reuse, attributes the matching QW, and classifies
  every ECCC-corrected result—including returned exact `T` or all-`0xFF`—as
  degraded/consumed rather than clean or virgin;
- a corrected or unreadable highest-floor replica contributes zero quorum
  weight: remaining clean replicas either establish the same `T`, or the floor
  is `Unknown`; the decoder never returns an older `F`;
- every strict 1→0 partial-program prefix of every record role/target fails the
  antichain decoder rather than becoming `T` or any `V != T`;
- initial commitment requires the full clean replica threshold and durable
  completion state; only later degradation may use the separately approved
  lower threshold;
- a possibly interrupted exact-`T` QW has zero quorum weight; target authority
  comes only from durably logged clean pre-cut replicas plus separately
  preclaimed clean replacements under a fresh full-threshold `COMPLETE`;
- a may-have-launched all-`0xFF` QW is never treated as reusable from readback
  alone; tests cover the approved durable pre-claim/discriminator or assert the
  epoch-bump ship blocker;
- every claim/cursor/stage/`COMPLETE`/compaction transition is cut again during
  recovery and cannot authorize same-QW retry, degraded initial commit, or a
  lower floor;
- under a MAC codec, fully blank record region plus missing key decodes
  read-only canonical `Steady(0)` only when durable-intent state proves no
  writer state/launch is missing or active; any nonblank, stage-active, or
  ambiguous region plus missing key fails closed and no commitment is
  permitted;
- under a MAC codec, factory/ship validation rejects missing, blank, corrupt,
  single-copy when redundancy is required, KAT-invalid, or unreadable rollback
  key material even though the runtime blank-bank decoder still yields `F = 0`;
- `HEALTH_BEGIN` correlation/idempotency and busy behavior;
- `HEALTH_COMPLETE` parsing, atomic one-attempt consumption, replay binding,
  deadline transitions, command allowlist, exact post-success duplicate-tag
  acceptance, and different post-success transcript rejection;
- for builds including the SHOULD-level dry-run, the firmware-selected UserOp,
  Safe/EIP-712, and ERC-7730 vectors traverse production parsers/renderers at
  runtime into the bounded internal sink and match their frozen page digest/
  shape; injected parser, root, expected-output, or sink failure blocks epoch-
  bump confirmation without releasing authority; waived builds instead prove
  the protected-ledger/finalized-receipt waiver binding and disclose the absent
  coverage without synthesizing a pass;
- the selected `OPEN-HLT-1` key-budget proof covers the configured worst-case
  lifetime number of PIN-gated re-arms and never borrows the vendor-key cap;
- zeroization and no-output behavior on probation failures.

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
- The selected Foundation-A FSBL reproduces an initialized physical FLASH LOAD
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
- Factory, signer, updater, inspector, and FSBL generate byte-identical signed
  preimages for the same physical-slot artifact; slot-A and slot-B preimages
  are intentionally distinct.
- The measured report separates code/rodata and records any independently
  landed BIP-39 bit-packing saving rather than assuming its gross table delta.
- The report maps each load-bearing trust-root FI check retained in the build
  and proves no size optimization removed or weakened signature, digest,
  rollback, ECC, or final-handoff validation.
- No untracked source file is omitted from the owner diff.

### 15.3 QEMU/integration

- candidate crash before local health -> old slot;
- local health failure -> old slot;
- local pass but NS boot failure -> old slot after reset;
- absent/unresponsive companion -> bounded timeout and old slot;
- invalid challenge -> old slot;
- valid defined health + same-epoch confirmation -> no floor record and new
  higher-`R` slot;
- canonical blank ECC-clean bank with no possible missing writer state ->
  `Steady(0)` and normal `E=1` genesis boot; first bump binds `BASE0`, while a
  blank-looking bank after possible establishment launch never recreates it;
- valid defined health + epoch bump -> one logical target commitment with the
  codec-declared physical record cost, then rejection of the old epoch;
- lagging device `R1/E1/F0` installing `R3/E2` after skipping `R2/E2` -> device
  classifies from signed `E` and local `F` as an epoch bump, despite `R3` being
  same-epoch relative to the immediately preceding ledger release;
- same-epoch preferred-slot corruption -> older same-epoch confirmed fallback;
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
  stages return `Recovering`, ambiguous stages return `Unknown`, and only
  authoritative completion evidence can yield `Steady(T)`;
- same-epoch QEMU traces invoke neither OTP nor persistent-stage writes;
- proven-no-establishment-launch epoch-bump preflight failure—decoder remains
  `Steady(F)` and neither stage/reservation/claim/compaction nor OTP write may
  have launched—with a confirmed `T_fallback == F` slot boots that fallback on
  repeated boots; any pre-`COMPLETE` establishment-state or OTP write that may
  have launched never takes that fallback and resumes only through the approved
  zero-weight/replacement/full-threshold/fresh-`COMPLETE` recovery protocol,
  otherwise it halts; post-`COMPLETE` compaction separately preserves
  `Steady(T)` and handoff from an old authoritative copy or returns `Unknown`;
- probation dispatch rejects every wallet authority command;
- crash/reset from exact `ATTEMPTED` falls back without re-arming; every later
  field reinstall or new `ARM_READY` creation again requires the production
  PIN/unlock gate, while an exact pre-handoff `ARM_READY` retry is separately
  tested as the no-handoff case;
- old runtime reports a failed probation clearly.

### 15.4 Real STM32U585AI evidence

- complete A/B update on the B-U585I-IOT02A;
- USB enumeration and defined health round-trip;
- physical cancel and timeout;
- controlled reset/power interruption at each safe test point;
- deliberately torn inactive-manifest ECCD is rejected while the independently
  valid fallback boots;
- TAMP-token loss, tamper erase, backup-domain reset, NS denial, and BHK
  coexistence;
- ES0499 VDD/VBAT-window characterization and the selected cold-boot
  workaround, including `VBSEC` protection for a `MONEN` design or exact
  `BORRSTF`/integrity/`BDRST` behavior, DBP clear/readback before NS, and BHK
  regeneration after forced backup-domain reset; the receipt also covers
  tamper-flag capture/escalation before sanitation, SRAM2/PKA-SRAM/ICACHE erase,
  IWDG stop/restart timing, `SPRIV`, and exact MCU revision applicability;
- measured backup-domain retention on the production VBAT/supercapacitor
  design records the supported retry window and demonstrates clean fallback
  after deliberate drain; the unmodified development kit is not cited as
  evidence of the production retention envelope;
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
`Recovering`, and `Unknown` as mutually exclusive admission-boundary classes:
an in-progress frontier is never committed, `Recovering` never invokes the slot
selector, and every accepting recovery reaches `Steady(T)` first. It must bind
each stage to the exact prior-group identity and allocation generation and
prove a global unique physical-QW ownership partition: no duplicate quorum
index, cross-group/source-replacement alias, consumed-cell reuse, or stale
stage/compaction replay is accepted.
Post-`COMPLETE` maintenance must preserve `Steady(T)` from an authoritative old
copy until its disjoint replacement is durable; it is never modeled as an
epoch-advance `Recovering` transition.

---

## 16. Security invariants

An implementation conforming to this specification maintains:

1. Runtime firmware never advances, lowers, resets, or reinterprets `F`.
2. FSBL establishes only the checked target `T = E - 1` of an exactly
   `CONFIRMED` release; it never does so for `PENDING`, `ATTEMPTED`, malformed,
   or merely Milestone-1-ready firmware.
3. Ordinary admission occurs only from `Steady(F)` and requires `E > F`.
   `Recovering` bypasses the selector and admits no slot until a fresh
   `Steady(T)`; `Unknown` halts. `R` cannot override a rejected epoch.
4. In normal ledger-consistent states, `R` determines preference among epoch-
   admissible releases. In anomalous two-confirmed recovery, FSBL chooses
   higher `E` before `R`, so a crossed higher-`R`/lower-`E` tuple can never
   displace the higher security epoch.
5. After `OPEN-JRN-HW-1` closes, a candidate receives at most one probation
   boot before exact `CONFIRMED`. No at-most-once claim is made for an
   unsanitized ES0499 marginal backup-power state.
6. Every reset inside the validated reset/retention envelope after exact
   `ATTEMPTED` and before confirmation makes that candidate ineligible; exact
   `ARM_READY` may retry only before any handoff. A detected or ambiguous cold
   backup-domain power event is sanitized before token decode and loses retry
   authority, selecting the fallback/reinstall path.
7. The previous confirmed slot remains eligible through probation and the
   confirmation write. After same-epoch finalization it remains floor-eligible;
   after durable higher-epoch establishment every slot with `E <= F` is
   ineligible.
8. Same-epoch establishment consumes no rollback record and issues no OTP
   program command or persistent reservation/stage write. Capacity exhaustion
   cannot turn that no-op into failure while the existing floor remains
   readable and valid.
9. Each epoch-bumping confirmation performs exactly one logical
   `commit_target(T)`. The number of valid physical records, replicas, claims,
   and loss/replacement/degradation cells is exactly the cost admitted by the approved
   codec and interruption model; no one-record assumption is implicit. Initial
   commitment requires the full clean threshold and durable completion state;
   only a previously completed group may use its approved degraded threshold.
   No strict 1→0 partial-program prefix decodes as any valid floor record. One
   physical QW has one global role/owner and counts at most once; stage replay,
   group/replacement overlap, and consumed/quarantined reuse are invalid.
   Post-`COMPLETE` maintenance preserves authoritative `Steady(T)` until a
   disjoint replacement is durable or returns `Unknown`; it is not an
   epoch-advance `Recovering` state.
10. Under Draft 0.9's retained writer model, exact field-update `CONFIRMED` is
    written only by the running secure candidate after bound `ATTEMPTED`, full
    defined health, and trusted-display approval. It is a runtime-issued
    durable seal, not proof that FSBL observed the health transcript. The sole
    non-field writer is the offline factory exception in Section 7.4. After a
    field seal, runtime cannot return to NS or ordinary wallet execution before
    a reset through FSBL.
11. Manifest mutations are one-shot exact codewords; before exact
    `QW_CONFIRMED`, the frozen rewritable TAMP transition accepts only
    exact bound states, starts every rebind from exact invalidation, and every
    other state fails toward the fallback. After confirmation the token is
    ignored under the retained writer model. No TAMP state is interpreted
    before the selected ES0499 cold-boot sanitation and protection readback.
12. No wallet authority or signature is released during probation.
13. The defined production confirmation requires local health, external
    round-trip, and explicit trusted-display acceptance. NS traffic cannot
    extend probation or brute-force the human challenge.
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
16. OTP claims distinguish target-side protection from master-by-master
    closure and remain open until silicon evidence exists.
17. A corrected, unreadable, or possibly interrupted OTP QW contributes zero
    clean quorum weight and is never reused merely because returned bytes read
    erased or exact. `ECCC`-clean exact bytes alone are not durability proof.
    Remaining independent clean replicas may establish only the same target
    under the approved completed-group threshold. A valid in-progress durable
    stage returns bound `Recovering`, while loss of authoritative committed or
    recovery state returns `Unknown`; neither result exposes an older `F` to
    admission. A launched-all-`0xFF`
    ambiguity requires an approved pre-claim/discriminator or keeps field
    epoch bumps blocked. No programmed OTP QW is treated as a bitwise multi-
    update counter.
18. The availability claim ends at the defined probation boundary and does not
    promise recovery from a bug unique to the first ordinary post-establishment
    wallet lifecycle. The anti-rollback claim is epoch-granular, not release-
    granular.
19. The private irreversible-floor path independently revalidates the complete
    `R,E` range and checked `T` range before any write; upstream validation or
    a typed caller object is never its sole sentinel defense.
20. Canonical `Steady(0)` requires a fully blank ECC-clean bank plus proof that
    no establishment writer state may be missing; all-`0xFF` bytes alone never
    recreate the base after a possible launch. Fallback from a higher confirmed
    candidate requires `Steady(F)`, no unresolved maintenance compaction, and
    proof that neither pre-`COMPLETE` durable establishment state nor OTP
    programming for the target may have launched, in addition to an
    independently verified confirmed fallback with target `F`.

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
- a new flash layout beyond the reviewed 40 KiB FSBL geometry.

---

## 18. Review questions for both Opus adjudicators

Each reviewer must answer:

1. Does the four-state composite representation admit any sequence that
   retires a lower-epoch fallback before exact defined health?
2. Is the frozen-but-hardware-gated secure TAMP token safer and smaller than a
   separately erasable flash journal, given that secure privileged runtime can
   rewrite it?
3. Do every reset, power, tamper, BHK-load, and token-transition ordering case
   preserve at-most-once probation?
4. Can NS or the companion self-confirm without learning the display-only
   challenge through the human path?
5. Are `HEALTH_BEGIN` idempotency and one-shot `HEALTH_COMPLETE` rules both
   guess-resistant and tolerant of realistic USB loss?
6. Does any probation command release wallet authority or reset the deadline?
7. Is the defined health boundary implementable without changing FSBL state
   semantics?
8. Is the post-establishment ordinary-wallet residual stated honestly and
   narrowly?
9. Are false-negative outcomes clean and user-comprehensible?
10. Is the OTP record-format decision correctly left open, and is the master
    list complete for STM32U585AI?
11. Does the OTP abstraction actually permit safe cross-power-loss intent and
   replica recovery, or must the core state machine expose more durable state?
12. Is the minimal ECC-NMI recovery contract implementable and testable without
    reintroducing the deferred broad hardening?
13. Are the factory-genesis exception and universal confirmed `F = E - 1`
    establishment sufficient and non-bypassable?
14. Before any durable establishment-state or OTP write may launch, does the
    selector ignore every non-qualifying pending tuple and deterministically
    order confirmed slots by higher `E`, then `R`, then fixed slot A? If
    preferred-floor establishment cannot start while the decoder remains
    `Steady(F)`, does it boot only a separately verified confirmed fallback
    with target exactly `F`? After a pre-`COMPLETE` stage/claim or OTP write may
    have launched, does it forbid fallback/handoff, recover only through the
    approved replacement and fresh full-threshold `COMPLETE`, then hand off the
    higher candidate—or halt if `T` cannot be established—without opening a
    rollback path? Does post-`COMPLETE` compaction instead preserve
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
18. Does a same-epoch release provably issue zero OTP program commands,
    durable reservation/stage writes, or stage compaction, including with
    exhausted capacity and across repeated boots?
19. Is the explicit same-epoch rollback-equivalence class an acceptable product
    policy, and can the production signer make advisory-to-epoch decisions
    sufficiently hard to bypass?
20. Is Draft 0.9's smaller runtime-written `CONFIRMED` seal acceptable under
    the trust model, or does its same-epoch evidence justify the larger
    `HEALTH_PASSED`/`SEALING`/FSBL-writer design despite the extra power-cut and
    immutable-budget surface?
21. Does manifest-v4 perform a clean flag-day cutover with no legacy default or
    ambiguous A/B release-set pairing?
22. Does any claimed BIP-39 bit-packing or prefix saving preserve identical
    FSBL/secure-world fingerprints and count only measured net ELF savings?
23. Under a MAC codec, does a fully blank record region decode canonical
    `Steady(0)` without a key only when durable-intent state proves no writer
    state/launch is missing or active, while every nonblank/stage-active/
    ambiguous key-loss case fails closed, and does factory/ship validation
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
    threshold, and a crash-consistent pre-OTP stage that makes every
    may-have-launched all-`0xFF` cell identifiable? If not, are field epoch
    bumps explicitly blocked rather than justified by finite sampling?
28. Are `Steady(F)`, bound `Recovering`, and `Unknown` mutually exclusive and
    complete across every stage/power-cut prefix, with an in-progress frontier
    excluded from the highest committed group and no selector/handoff during
    recovery? Does canonical blank state yield `Steady(0)` only with proof that
    no establishment writer state is missing?
29. Does the irreversible writer independently reject the complete reserved
    `R,E,T` range even if upstream validation or a typed proof object is
    faulted?
30. Is the epoch-bump canned decode/render dry-run useful and implementable as
    authority-free SHOULD-level defense in depth, and is its inability to test
    real unlock/publish/sign/update dispatch stated without over-claim?
31. Is TAMP's exact-ready retry benefit evaluated against the measured finite
    VBAT/supercapacitor retention window, with token loss always producing a
    safe PIN-gated reinstall rather than a second handoff?
32. Is OTP-first justified narrowly by the present pre-PIN FSBL architecture
    and current PIN-gated SE counters, while leaving a differently specified
    pre-PIN SE/hybrid architecture as a legitimate future option?
33. Does every stage bind the exact prior committed-group identity (or
    `BASE0`), allocation generation/cursor, candidate/active group, and complete
    physical cell-role map, with global unique QW ownership and no stale-stage,
    duplicate-quorum, cross-group, replacement, quarantine, or compaction
    alias? Is any route-1 main-flash journal on disjoint erase units?
34. Is `OPEN-RAM-1` closed with an exact transient SRAM geometry, authoritative
    static end/span covering every allocatable/`NOLOAD` section and alignment,
    worst-case LTO stack bound including ECC-NMI exception nesting, nonzero
    margin, on-target high-water corroboration, and a reviewed `MSPLIM`/
    equivalent guard decision plus safe runtime handoff?
35. Does `OPEN-JRN-DUR-1` prevent a post-cut exact-looking/ECCC-clear marker
    from becoming confirmation authority without durable evidence, and does
    the selected rule preserve an authenticated boot path if a confirmation
    witness degrades after the epoch floor has retired the fallback?
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
R6--R12 were observations/editorial hardening. Reviewer B's durable report is
`/tmp/pqsigner-ab-rollback-reviewer-B-adjudication.md`, SHA-256
`7067a883117bfb948a839f4541c21aa4cf2dd1d41f6f972d632435a345961bc8`.

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
`Recovering|Unknown`/no-handoff wording. The durable report is
`/tmp/pqsigner-ab-rollback-reviewer-B-0.7-reapproval.md`, SHA-256
`5310cea9187b2e228db3a4525c4f641114885c9dba98ad9c9603110e161249fd`.

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

Draft 0.9 freezes the manifest bytes, composite journal/token bytes, and typed
OTP software contract; records the AMBER warning build; and adds the ES0499
backup-domain red lines found during independent TAMP prosecution. It does not
close `OPEN-JRN-HW-1`, `OPEN-JRN-DUR-1`, `OPEN-ECC-1`, or `OPEN-OTP-1..3`, authorize production-
shared implementation, or authorize any hardware write. Both reviewers must
inspect the same frozen Draft-0.9 digest. The owner must resolve any red lines
and approve the resulting re-frozen digest before its frozen interfaces become
the project authority.

| Reviewer | Model/session | Verdict | Required changes |
|---|---|---|---|
| Independent reviewer A | Claude Code Opus 4.8, 1M context, max effort; Draft-0.8 spec SHA `66b0bd65...10d4b1`, prompt SHA `c6092539...25af9920` | APPROVE ARCHITECTURE FOR OPEN-DECISION CLOSURE; no implementation approval | Draft 0.9 interface-freeze reapproval pending |
| Independent reviewer B | Claude Code Opus 4.8, 1M context, max effort; Draft-0.8 spec SHA `66b0bd65...10d4b1`; report SHA `73cb4c0a...461375d` | APPROVE ARCHITECTURE FOR OPEN-DECISION CLOSURE; no implementation approval | Draft 0.9 interface-freeze reapproval pending |
| Owner | pending | pending | pending |

Draft 0.2 received a non-Opus internal adversarial `NO-GO`; its main-flash
interruption, factory, ECC, USB-completion, and claim-scope red-lines were
incorporated in Draft 0.3. Draft 0.4 added the owner-reviewed OTP decision and
the `(release_version, security_epoch)` split. Its exact reviewed artifacts are
preserved at `/tmp/pqsigner-ab-rollback-architecture-spec-v0.4.md` and
`/tmp/pqsigner-ab-rollback-spec-opus-prompt-v0.4.txt` with SHA-256
`75a2eb52861e0c5bbe57b9413e4ca33fed4e9c9037de459522cb720a9cb3b528`
and `8e0c5ae1b0be3947f5275475124c0e150e778aa8f9e7141c60216892a7f91544`.

An earlier bounded Claude Code Opus 4.8
architecture consultation agreed that OTP is the smaller initial immutable
root and that one OTP quad-word cannot be reused bitwise; it did not review
this full specification and is not an approval. Its mistaken suggestion that
`F = E - 1` leaves a one-epoch window was rejected against the strict `E > F`
arithmetic and existing comparator. Other earlier stalled sessions likewise
remain unrecorded as approvals.
