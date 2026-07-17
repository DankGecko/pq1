-------------------------- MODULE PinReconcileDirectional --------------------------
(***************************************************************************)
(* Faithful bounded model of the DEPLOYED directional boot-time PIN-rollback *)
(* reconcile — the P1.6 follow-up that replaces the OVERSTATING idealized     *)
(* SYMMETRIC three-counter model (contracts/verification/tamarin/             *)
(* pin_lockstep.spthy, finding PM-1) with the actual ordered-counter          *)
(* predicate the firmware runs.                                               *)
(*                                                                            *)
(* DEPLOYED CODE (secure/src/nsc/mod.rs `reconcile_pin_attempts`, shipping    *)
(* dual-SE + optiga-hw-counter config):                                       *)
(*   mcu      = pin_attempts_read()          (MCU page-124 count)             *)
(*   se_count = optiga E120 count            (SE050 read = None, policy 6986) *)
(*   se_split = false                        (dead: needs BOTH legs readable) *)
(*   if se leg unavailable (None): return    (skip — NO wipe)                 *)
(*   tamper   = (se_count > mcu) || se_split  =  (se_count > mcu)             *)
(*   wipe iff tamper.                                                         *)
(*                                                                            *)
(* Pre-commit invariant the directional `>` relies on: gated_unlock precharges *)
(* page-124 BEFORE the SE verify, so in every BENIGN state mcu LEADS or equals *)
(* the SE counter (mcu == se after both advance, mcu == se+1 across a power-cut *)
(* in the sub-ms window). We DERIVE that here (honest attempt = two-phase bump *)
(* mcu-then-se) rather than assert it, so `se > mcu` is provably unreachable   *)
(* under honest-only play — that is what makes the directional `>` sound.      *)
(*                                                                            *)
(* WHAT THIS IS/IS NOT (F9): a bounded MODEL of the reconcile predicate over   *)
(* small counters, TLC-checked, not the Rust and not the silicon. Silicon      *)
(* counter/reset/ECC behaviour stays a hardware-receipt assumption; three-way  *)
(* boot reconciliation is explicitly NOT modelled or claimed (SE050 is not a   *)
(* reconcile input in the shipping policy).                                    *)
(*                                                                            *)
(* THE FINDING = a TWO-SIDED CROSSING (see PROPERTIES). The deployed           *)
(* DIRECTIONAL predicate and the idealized SYMMETRIC one (`se_count != mcu`)   *)
(* trade off against each other:                                              *)
(*   * directional NEVER false-wipes the benign mcu==se+1 power-cut state, but *)
(*     does NOT catch an SE-silicon-counter reset (the residual);             *)
(*   * symmetric catches that reset, but FALSE-WIPES every power-cut.         *)
(* So the deployed directionality is a DELIBERATE availability-vs-detection    *)
(* trade, not an oversight. The `SymmetricReconcile` constant is the negative  *)
(* control that surfaces both sides.                                          *)
(*                                                                            *)
(* SEVERITY (carried forward from the tamarin README, DiD framing): the        *)
(* SE-reset residual requires the attacker to have ALREADY reset the OPTIGA    *)
(* E120 SILICON counter — i.e. defeated the PRIMARY per-SE lockout before      *)
(* reconcile is even relevant. The residual is "reconcile adds no DiD against  *)
(* an SE-silicon reset", NOT "reconcile grants attempts": the primary controls *)
(* (per-SE silicon lockout + the FI-hardened page-124 pre-commit in            *)
(* gated_unlock) still bound the attacker to <= MAX_ATTEMPTS. No fund-drain.   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Cap,                 \* small bound on each counter (real MAX_ATTEMPTS = 10)
          SymmetricReconcile,  \* FALSE = deployed directional (se>mcu); TRUE = idealized symmetric (se#mcu) NEGATIVE CONTROL
          EnableAttack         \* FALSE = honest-only play; TRUE = attacker may reset counters / glitch the leg

ASSUME Cap \in Nat /\ Cap >= 2
ASSUME SymmetricReconcile \in BOOLEAN
ASSUME EnableAttack \in BOOLEAN

VARIABLES
    mcu,        \* MCU page-124 failed-attempt count
    se,         \* SE counter reconcile reads (optiga E120 in shipping = se_count)
    pendingSe,  \* an honest attempt precharged page-124 but the SE silicon has not yet bumped
                \* (the power-cut window). Enforces the benign invariant mcu \in {se, se+1}.
    legUp,      \* is the SE (optiga) attempt-counter leg readable at boot?
    booted,     \* terminal: reconcile has run (one boot per trace)
    wiped,      \* reconcile wiped
    mcuReset,   \* GHOST: an out-of-band page-124 rollback occurred (MCU counter forced down)
    seReset     \* GHOST: an out-of-band SE-silicon counter reset occurred (primary control defeated)

vars == <<mcu, se, pendingSe, legUp, booted, wiped, mcuReset, seReset>>

Init ==
    /\ mcu = 0 /\ se = 0 /\ pendingSe = FALSE
    /\ legUp = TRUE
    /\ booted = FALSE /\ wiped = FALSE
    /\ mcuReset = FALSE /\ seReset = FALSE

------------------------------------------------------------------------------
(* HONEST wrong-PIN attempt = two phases (gated_unlock precharges page-124,
   THEN the SE silicon bumps on the failed verify). Modelling the two phases
   separately makes the benign invariant mcu \in {se, se+1} a THEOREM of honest
   dynamics and `se > mcu` provably unreachable without an attack. *)

\* Phase 1: precharge page-124. mcu leads by one until the SE catches up.
AttemptPrecharge ==
    /\ ~booted /\ ~pendingSe
    /\ mcu < Cap
    /\ mcu' = mcu + 1
    /\ pendingSe' = TRUE
    /\ UNCHANGED <<se, legUp, booted, wiped, mcuReset, seReset>>

\* Phase 2: the SE silicon bumps, re-syncing mcu == se. A power-cut BETWEEN the
\* two phases is modelled by simply booting while pendingSe = TRUE (mcu == se+1).
AttemptSeBump ==
    /\ ~booted /\ pendingSe
    /\ se < Cap
    /\ se' = se + 1
    /\ pendingSe' = FALSE
    /\ UNCHANGED <<mcu, legUp, booted, wiped, mcuReset, seReset>>

------------------------------------------------------------------------------
(* ATTACKER actions (out-of-band; only with EnableAttack). *)

\* Page-124 rollback (e.g. a TZ-bypass flash erase of the MCU attempt page).
\* The SE silicon retains its count => se can now exceed mcu. This is exactly
\* what the directional reconcile is FOR.
ResetMcu ==
    /\ EnableAttack /\ ~booted
    /\ mcu' = 0
    /\ pendingSe' = FALSE
    /\ mcuReset' = TRUE
    /\ UNCHANGED <<se, legUp, booted, wiped, seReset>>

\* SE-silicon attempt-counter reset (the attacker has DEFEATED the primary OPTIGA
\* E120 lockout). se drops to 0 => mcu now leads. The directional reconcile does
\* NOT treat mcu-lead as tamper, so this is undetected — the residual.
ResetSe ==
    /\ EnableAttack /\ ~booted
    /\ se' = 0
    /\ seReset' = TRUE
    /\ UNCHANGED <<mcu, pendingSe, legUp, booted, wiped, mcuReset>>

\* Force the OPTIGA read to fail (I2C glitch) => se_used = None => reconcile SKIPS.
\* Residual #2: disabling the leg disables the whole cross-check.
DisableLeg ==
    /\ EnableAttack /\ ~booted
    /\ legUp' = FALSE
    /\ UNCHANGED <<mcu, se, pendingSe, booted, wiped, mcuReset, seReset>>

------------------------------------------------------------------------------
(* BOOT (terminal): run reconcile exactly as the firmware does. *)

Tampered ==
    IF SymmetricReconcile
    THEN se # mcu       \* idealized symmetric variant (the overstating model)
    ELSE se > mcu       \* DEPLOYED directional predicate (shipping: se_split dead)

Boot ==
    /\ ~booted
    /\ booted' = TRUE
    /\ IF legUp
         THEN wiped' = Tampered           \* leg readable: wipe iff tamper
         ELSE wiped' = FALSE              \* se_used = None: skip, no wipe
    /\ UNCHANGED <<mcu, se, pendingSe, legUp, mcuReset, seReset>>

Next ==
    \/ AttemptPrecharge
    \/ AttemptSeBump
    \/ ResetMcu
    \/ ResetSe
    \/ DisableLeg
    \/ Boot

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(* PROPERTIES.

   The finding is the CROSSING of the two negative-control-parameterised
   invariants below (run under the matching .cfg):

   | invariant           | attack | directional (deployed) | symmetric (variant) |
   |---------------------|--------|------------------------|---------------------|
   | INV_NO_FALSE_WIPE   |  OFF   | HOLD                   | VIOLATED            |
   | INV_CATCHES_RESET   |  ON    | VIOLATED (residual)    | HOLD                |

   Directional buys availability (no false-wipe on power-cut) at the cost of not
   catching an SE-silicon reset; symmetric buys reset-detection at the cost of
   false-wiping every power-cut. That is the availability-vs-detection trade that
   explains the deployed design. *)

TypeOK ==
    /\ mcu \in 0..Cap /\ se \in 0..Cap
    /\ pendingSe \in BOOLEAN /\ legUp \in BOOLEAN
    /\ booted \in BOOLEAN /\ wiped \in BOOLEAN
    /\ mcuReset \in BOOLEAN /\ seReset \in BOOLEAN

\* Benign-dynamics theorem (holds in ALL configs): honest play keeps mcu >= se.
\* Under EnableAttack this can be broken (that is the point) — checked only in the
\* honest-only cfg, where it certifies the directional `>` never fires benignly.
INV_BENIGN_MCU_LEADS == (~mcuReset /\ ~seReset) => mcu >= se

\* NO FALSE WIPE (check honest-only, EnableAttack=FALSE): reconcile must not wipe a
\* device that was never attacked. Directional HOLDS (mcu>=se => se>mcu false);
\* symmetric VIOLATED (mcu==se+1 power-cut => se#mcu => false-wipe).
INV_NO_FALSE_WIPE == booted => ~wiped

\* CATCHES RESET (check with EnableAttack=TRUE): a MEANINGFUL SE-silicon reset —
\* one that creates a real MCU-lead gap (se < mcu) with the leg READABLE (so the
\* reconcile predicate actually runs) — must never survive a boot unwiped.
\* Directional VIOLATED (0 > mcu is false => no wipe => the residual); symmetric
\* HOLDS (se < mcu => se # mcu => wipe). The `legUp` guard ISOLATES the
\* predicate-choice crossing from the orthogonal leg-availability residual #2
\* (which defeats BOTH predicates and is captured by INV_NO_LEG_BYPASS); the
\* `se < mcu` guard excludes the vacuous reset of an already-zero counter,
\* undetectable by ANY reconcile.
INV_CATCHES_RESET == booted => ~(seReset /\ se < mcu /\ legUp /\ ~wiped)

\* DEPLOYED POSITIVE GUARANTEE (holds in BOTH configs — the property reconcile
\* EXISTS for): whenever the leg is readable and the SE count exceeds MCU (an MCU
\* page-124 rollback), reconcile wipes.
INV_ROLLBACK_DETECTED == (booted /\ legUp /\ se > mcu) => wiped

\* RESIDUAL #2 (expect VIOLATED with EnableAttack=TRUE, either config): if the
\* attacker glitches the OPTIGA leg down, an MCU rollback that WOULD be caught
\* (se > mcu) goes undetected because reconcile skips on se_used = None.
INV_NO_LEG_BYPASS == booted => ~(~legUp /\ se > mcu /\ ~wiped)

\* ANTI-VACUITY (expect VIOLATED = a surviving honest boot is reachable, so the
\* model is not trivially always-wipe). Run in the honest-only cfg.
INV_ALIVE_NONVACUOUS == ~(booted /\ ~wiped)
================================================================================
