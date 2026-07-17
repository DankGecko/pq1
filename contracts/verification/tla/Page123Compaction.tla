-------------------------- MODULE Page123Compaction --------------------------
(***************************************************************************)
(* Bounded TLA+/TLC model of the STM32U585 page-123 log-structured         *)
(* off-chain signing-counter store crash-atomicity.                        *)
(*                                                                          *)
(* FV surface: durable-counter-crash-recovery (roadmap P1.1 invariant #5). *)
(* Models secure/src/hw/flash.rs {write_entry, compact_page,               *)
(* scan_page_into_table, offchain_count_read, is_registered_*}.            *)
(*                                                                          *)
(* WHAT THIS IS AND IS NOT (read first — FV-review F9 anti-over-claim):     *)
(*   * This verifies a MODEL of the compaction ALGORITHM under the STATED   *)
(*     assumptions below. It is NOT the Rust, NOT the silicon. TLC is       *)
(*     BOUNDED model checking over the small constants in the .cfg, not a   *)
(*     universal proof. A green run means "no crash trace in this bounded   *)
(*     model reaches the bad state", not "the firmware is crash-safe".      *)
(*                                                                          *)
(* THE CLAIM UNDER TEST (flash.rs compact_page F3 comment): replaying       *)
(* USEROP_SIGS FIRST per slot makes UNREACHABLE the dangerous               *)
(* torn-compaction state "slot REGISTERED but its few-time-key sig tally    *)
(* (SIGS) rolled back below its true durable high-water mark". SIGS has no  *)
(* on-chain backstop, so a rollback silently re-opens the C10 few-time-key  *)
(* signing budget (invariant #7 combined cap) => forgery-margin erosion.    *)
(*                                                                          *)
(* The page is a single flash page of quad-word (QW) entries               *)
(* (slot_key, type, count), type in {SIGS, UO, CNT}. Readback PROJECTS the  *)
(* MAX count per (slot,type) (scan_page_into_table). "Registered" == at     *)
(* least one decoded entry exists for the slot (is_registered_forward).     *)
(* When full, compact_page snapshots the projection, ERASES the page, then  *)
(* REPLAYS (single page, no two-phase staging) => a power loss during       *)
(* replay can tear it.                                                      *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Slots,        \* set of abstract slot keys, e.g. {"a","b"} (assume collision-free: an abstraction)
    MaxCount,     \* counts range 0..MaxCount (real: 7 big-endian bytes; here small for TLC)
    PageCap,      \* max live QWs on the page (real OFFCHAIN_CAPACITY = 512)
    ReplayOrder,  \* "SigsFirst" (shipped) | "SigsLast" (NEGATIVE CONTROL — must break the invariant)
    TornModel,    \* "Skip" (torn QW reads back undecodable & is skipped — the code's HW premise)
                  \*   | "MayValid" (torn QW may read back as an arbitrary VALID entry — no CRC/marker)
    EnablePartialErase \* FALSE = ATOMIC erase (AX-ERASE-ATOMIC — the 5 base cfgs are all FALSE). TRUE =
                       \* model the erase NON-atomically: a torn erase leaves a PREFIX of the append-only
                       \* log, so a LOWER SIGS QW survives while a higher is wiped → registered-slot
                       \* rollback. Complements the Verus pilot (which ASSUMES AX-ERASE-ATOMIC): this is
                       \* the TLC counterexample that proves erase-atomicity is load-bearing (flash.rs:1669).

ASSUME ReplayOrder \in {"SigsFirst", "SigsLast"}
ASSUME TornModel   \in {"Skip", "MayValid"}
ASSUME EnablePartialErase \in BOOLEAN
ASSUME PageCap \in Nat /\ PageCap >= 3

Types == {"SIGS", "UO", "CNT"}     \* USEROP_SIGS, USEROP, COUNT

Ent(s, t, c) == [kind |-> "e", s |-> s, t |-> t, c |-> c]
TornQW       == [kind |-> "torn"]  \* a power-interrupted QW program; under "Skip" it decodes to nothing

VARIABLES
    page,   \* Seq of QW (Ent/TornQW). Blank tail is implicit (positions > Len(page)).
    mode,   \* "run" | "compact"
    rq,     \* Seq of Ent to replay (built at StartCompact from the pre-erase projection)
    ri,     \* number of rq entries already written this compaction
    hwm,    \* [Slots -> Nat] ghost: max SIGS count ever DURABLY committed (true high-water)
    chwm,   \* [Slots -> Nat] ghost: max CNT  count ever durably committed (for the weaker property)
    cpUnsafe, \* ghost: TRUE once a COMPACTION STEP lowered a slot's SIGS below its PRE-compaction value
    preSigs  \* ghost: [Slots -> Nat] snapshot of Proj(SIGS) taken at StartCompact (pre-erase)

vars == <<page, mode, rq, ri, hwm, chwm, cpUnsafe, preSigs>>

--------------------------------------------------------------------------------
(* Readback projection over the durable page. TornQW markers are skipped   *)
(* (undecodable), exactly like parse_entry's Some((0,_,_)) branch.         *)

RealEntries(pg) == { i \in 1..Len(pg) : pg[i].kind = "e" }

Proj(pg, s, t) ==
    LET cs == { pg[i].c : i \in { j \in RealEntries(pg) : pg[j].s = s /\ pg[j].t = t } }
    IN IF cs = {} THEN 0 ELSE CHOOSE m \in cs : \A x \in cs : x <= m

Registered(pg, s) == \E i \in RealEntries(pg) : pg[i].s = s

\* Did a COMPACTION step lower a slot's SIGS BELOW the value it had entering this
\* compaction (preSigs snapshot)? This isolates the replay-ORDERING property: a
\* SIGS-present slot must never come back registered-with-lower-SIGS. A slot that
\* entered compaction already SIGS-less (preSigs=0) can't be 'rolled back' by
\* compaction (that is the separate re-registration / invariant-#9 gap, tracked by
\* INV_SIGS_NO_ROLLBACK against the global hwm).
HasCompactionRollback(pg) ==
    \E s \in Slots : Registered(pg, s) /\ Proj(pg, s, "SIGS") < preSigs[s]

--------------------------------------------------------------------------------
(* Compaction: build the per-slot replay queue in the configured order.    *)

TypeOrder == IF ReplayOrder = "SigsFirst"
             THEN << "SIGS", "UO", "CNT" >>
             ELSE << "UO", "CNT", "SIGS" >>   \* the pre-F3 wrong order (negative control)

\* Deterministic slot iteration order (cross-slot order is irrelevant to the
\* per-slot invariant; a permutation of Slots).
SlotOrder == CHOOSE seq \in [1..Cardinality(Slots) -> Slots] :
                \A i, j \in 1..Cardinality(Slots) : i # j => seq[i] # seq[j]

\* Replay entries for one slot: only present types, in TypeOrder, at their max.
RECURSIVE SlotReplay(_, _)
SlotReplay(s, k) ==
    IF k > Len(TypeOrder) THEN << >>
    ELSE LET t == TypeOrder[k]
             rest == SlotReplay(s, k + 1)
         IN IF \E i \in RealEntries(page) : page[i].s = s /\ page[i].t = t
            THEN << Ent(s, t, Proj(page, s, t)) >> \o rest
            ELSE rest

RECURSIVE BuildRQ(_)
BuildRQ(k) ==
    IF k > Len(SlotOrder) THEN << >>
    ELSE SlotReplay(SlotOrder[k], 1) \o BuildRQ(k + 1)

--------------------------------------------------------------------------------
Init ==
    /\ page = << >>
    /\ mode = "run"
    /\ rq   = << >>
    /\ ri   = 0
    /\ hwm  = [s \in Slots |-> 0]
    /\ chwm = [s \in Slots |-> 0]
    /\ cpUnsafe = FALSE
    /\ preSigs = [s \in Slots |-> 0]

\* Append one SIGS bump for slot s (a user-confirmed Type-2 few-time-key sig).
\* Atomic: write_quadword_verified verifies, so a torn single append is retried
\* (either lands or not) — the crash-atomicity surface is compaction replay.
AppendSigs(s) ==
    /\ mode = "run"
    /\ Len(page) < PageCap
    /\ LET c == Proj(page, s, "SIGS") + 1 IN
         /\ c <= MaxCount
         /\ page' = Append(page, Ent(s, "SIGS", c))
         /\ hwm'  = [hwm EXCEPT ![s] = IF c > hwm[s] THEN c ELSE hwm[s]]  \* monotonic max
    /\ UNCHANGED << mode, rq, ri, chwm, cpUnsafe, preSigs >>

AppendCnt(s) ==
    /\ mode = "run"
    /\ Len(page) < PageCap
    /\ Registered(page, s)   \* invariant #9: cmd_sign_offchain refuses an UNREGISTERED slot
    /\ LET c == Proj(page, s, "CNT") + 1 IN
         /\ c <= MaxCount
         /\ page' = Append(page, Ent(s, "CNT", c))
         /\ chwm' = [chwm EXCEPT ![s] = c]
    /\ UNCHANGED << mode, rq, ri, hwm, cpUnsafe, preSigs >>

AppendUo(s) ==
    /\ mode = "run"
    /\ Len(page) < PageCap
    /\ Registered(page, s)   \* invariant #9: a UO snapshot write follows a registered Type-2 slot
    /\ LET c == Proj(page, s, "UO") + 1 IN
         /\ c <= MaxCount
         /\ page' = Append(page, Ent(s, "UO", c))
    /\ UNCHANGED << mode, rq, ri, hwm, chwm, cpUnsafe, preSigs >>

\* Page full -> compact: snapshot projection, ERASE, then replay. Only fire when
\* compaction would actually FREE space (duplicates exist), else it is a no-op
\* loop; a full page of all-distinct entries simply stops accepting new appends
\* (availability, not safety) -> a benign deadlock (deadlock check disabled).
StartCompact ==
    /\ ~EnablePartialErase                    \* ATOMIC erase path (the 5 base cfgs)
    /\ mode = "run"
    /\ Len(page) = PageCap
    /\ LET newrq == BuildRQ(1) IN
         /\ Len(newrq) < PageCap              \* progress guard: frees >= 1 QW
         /\ rq'   = newrq
         /\ page' = << >>                      \* erase_offchain_page (one indivisible step)
         /\ mode' = "compact"
         /\ ri'   = 0
         /\ preSigs' = [s \in Slots |-> Proj(page, s, "SIGS")]  \* snapshot BEFORE erase
    /\ UNCHANGED << hwm, chwm, cpUnsafe >>

\* ── NON-ATOMIC erase (EnablePartialErase = TRUE) ────────────────────────────
\* The genuine Verus>TLA delta: the Verus pilot proves the positive theorem ASSUMING
\* AX-ERASE-ATOMIC; here TLC drops that assumption. StartCompactNA snapshots preSigs and
\* enters "erasing" WITHOUT wiping the page yet (the 1.5 ms erase is in flight); then EITHER
\* EraseComplete finishes it cleanly (page -> <<>>, proceed to replay) OR CrashPartialErase
\* tears it — a brownout mid-erase leaves a PREFIX of the append-only log (the erase cleared
\* the high-address QWs but not the low). Because SIGS bumps append in increasing order, a
\* surviving prefix holds a LOWER SIGS than preSigs while the higher is gone → the slot is
\* registered with rolled-back SIGS. The forward/reverse double-scan does NOT catch it (both
\* MAX over the survivors and agree). This is unreachable in the atomic-erase model.
StartCompactNA ==
    /\ EnablePartialErase
    /\ mode = "run"
    /\ Len(page) = PageCap
    /\ LET newrq == BuildRQ(1) IN
         /\ Len(newrq) < PageCap
         /\ rq'   = newrq
         /\ mode' = "erasing"                  \* erase in flight; page NOT yet wiped
         /\ ri'   = 0
         /\ preSigs' = [s \in Slots |-> Proj(page, s, "SIGS")]  \* snapshot BEFORE erase
    /\ UNCHANGED << page, hwm, chwm, cpUnsafe >>

EraseComplete ==
    /\ mode = "erasing"
    /\ page' = << >>                           \* erase finished with power intact
    /\ mode' = "compact"                        \* proceed to the (SIGS-first) replay
    /\ UNCHANGED << rq, ri, hwm, chwm, cpUnsafe, preSigs >>

\* Torn erase: a crash mid-erase leaves an arbitrary PREFIX of the pre-erase log readable
\* (the suffix QWs were cleared to Blank first), then reboots to steady state.
CrashPartialErase ==
    /\ mode = "erasing"
    /\ \E cut \in 0..Len(page) :
         /\ page' = SubSeq(page, 1, cut)
         /\ cpUnsafe' = (cpUnsafe \/ HasCompactionRollback(SubSeq(page, 1, cut)))
    /\ mode' = "run"
    /\ rq'   = << >>
    /\ ri'   = 0
    /\ UNCHANGED << hwm, chwm, preSigs >>

\* Replay the next queued entry cleanly (its QW programmed fully).
ReplayClean ==
    /\ mode = "compact"
    /\ ri < Len(rq)
    /\ page' = Append(page, rq[ri + 1])
    /\ ri'   = ri + 1
    /\ cpUnsafe' = (cpUnsafe \/ HasCompactionRollback(Append(page, rq[ri + 1])))
    /\ UNCHANGED << mode, rq, hwm, chwm, preSigs >>

\* Power loss BETWEEN two QW programs: the written prefix is durable; reboot to
\* "run" with whatever is on the page. No torn frontier QW.
CrashBetween ==
    /\ mode = "compact"
    /\ mode' = "run"
    /\ rq' = << >>
    /\ ri' = 0
    /\ UNCHANGED << page, hwm, chwm, cpUnsafe, preSigs >>

\* Power loss DURING the next QW program: a torn frontier QW is left durably,
\* then reboot to "run". Under "Skip" it reads back undecodable (skipped);
\* under "MayValid" the torn bytes happen to decode as an arbitrary VALID entry
\* (no CRC / commit marker in the format) — the worse, unverified HW premise.
CrashTornSkip ==
    /\ mode = "compact"
    /\ ri < Len(rq)
    /\ TornModel = "Skip"
    /\ page' = Append(page, TornQW)
    /\ mode' = "run"
    /\ rq' = << >>
    /\ ri' = 0
    /\ cpUnsafe' = (cpUnsafe \/ HasCompactionRollback(Append(page, TornQW)))
    /\ UNCHANGED << hwm, chwm, preSigs >>

CrashTornValid ==
    /\ mode = "compact"
    /\ ri < Len(rq)
    /\ TornModel = "MayValid"
    /\ \E s \in Slots, t \in Types, c \in 0..MaxCount :
         /\ page' = Append(page, Ent(s, t, c))    \* torn bytes decode as *some* valid entry
         /\ cpUnsafe' = (cpUnsafe \/ HasCompactionRollback(Append(page, Ent(s, t, c))))
    /\ mode' = "run"
    /\ rq' = << >>
    /\ ri' = 0
    /\ UNCHANGED << hwm, chwm, preSigs >>

\* All queued entries replayed: compaction committed.
FinishCompact ==
    /\ mode = "compact"
    /\ ri = Len(rq)
    /\ mode' = "run"
    /\ rq' = << >>
    /\ ri' = 0
    /\ UNCHANGED << page, hwm, chwm, cpUnsafe, preSigs >>

Next ==
    \/ \E s \in Slots : AppendSigs(s) \/ AppendCnt(s) \/ AppendUo(s)
    \/ StartCompact
    \/ StartCompactNA        \* non-atomic-erase path (EnablePartialErase)
    \/ EraseComplete
    \/ CrashPartialErase
    \/ ReplayClean
    \/ CrashBetween
    \/ CrashTornSkip
    \/ CrashTornValid
    \/ FinishCompact

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------------
(* PROPERTIES                                                              *)

\* THE headline crash-atomicity invariant. Every durable state (a crash can *)
\* leave ANY reachable state on the page) must satisfy: a REGISTERED slot's  *)
\* recovered SIGS is never below its true durable high-water mark.          *)
INV_SIGS_NO_ROLLBACK ==
    \A s \in Slots : Registered(page, s) => Proj(page, s, "SIGS") >= hwm[s]

\* What the F3 replay ORDERING actually guarantees, scoped to the compaction's
\* OWN output (GPT-5.6's "scope to the immediate compaction result"): no
\* compaction STEP (clean replay or torn frontier QW) ever itself produces a
\* state where a slot is registered with SIGS below its high-water. This
\* ISOLATES the ordering property from the separate re-registration-after-total-
\* loss gap (INV_SIGS_NO_ROLLBACK). Expected: HOLDS under SigsFirst, VIOLATED
\* under SigsLast (the negative control), for either TornModel.
INV_SIGS_COMPACTION_LOCAL == cpUnsafe = FALSE

\* The WEAKER property that the design KNOWINGLY accepts as failing (F3 comment:
\* a torn COUNT roll-back is possible but bounded by on-chain backstops). TLC is
\* EXPECTED to produce a counterexample here even under the shipped (SigsFirst)
\* order — which proves the model can EXPRESS a rollback (non-vacuity of the SIGS
\* result), and machine-confirms the documented SIGS-vs-COUNT asymmetry.
INV_CNT_NO_ROLLBACK ==
    \A s \in Slots : Registered(page, s) => Proj(page, s, "CNT") >= chwm[s]

\* Sanity: counts stay in range (guards the model, not a security property).
TypeOK ==
    /\ mode \in {"run", "compact", "erasing"}
    /\ ri \in 0..Len(rq)
    /\ cpUnsafe \in BOOLEAN
    /\ preSigs \in [Slots -> Nat]
    /\ \A i \in 1..Len(page) : page[i].kind \in {"e", "torn"}
================================================================================
