----------------------------- MODULE CombinedBudget -----------------------------
(***************************************************************************)
(* Bounded TLA+/TLC composition of the per-slot few-time-key budget across  *)
(* a torn-compaction counter RESET — the P1.5 follow-up that closes Finding  *)
(* 2 of the page-123 crash-atomicity pilot                                   *)
(* (fv-pilot-page123-crash-atomicity-2026-07-16.md).                         *)
(*                                                                          *)
(* Composes the two seams the review left un-joined:                        *)
(*   * the LOCAL, RESETTABLE counter policy — aa/src/offchain_gate.rs        *)
(*     (Kani-proven monotonic/gap/combined-cap, but its own doc scopes OUT   *)
(*     the torn-compaction rollback below the seam), and                     *)
(*   * the ON-CHAIN, MONOTONIC combined cap — PQMultiOwnable.sol             *)
(*     `_bumpSlotUses` (revert if slotUses+1 > cap) + `_setOffchainSigCount` *)
(*     (revert if newCount < prev, revert if slotUses+newCount > cap).       *)
(*                                                                          *)
(* WHAT THIS IS/IS NOT (F9): a bounded MODEL of the composition, not the     *)
(* Rust and not the Solidity; TLC over small constants, not a universal      *)
(* proof. It answers Finding 2's exact question: does the on-chain cap bound *)
(* the few-time-key budget across torn resets?                              *)
(*                                                                          *)
(* Distinctions the model makes explicit:                                   *)
(*   * a Type-2 UserOp sig LANDS on-chain (bumps slotUses, reconciles        *)
(*     offchainSigCount) only if the on-chain gates pass; a revert = no land.*)
(*   * an off-chain (EIP-1271) sig is VIEW-ONLY: it uses the slot key (erodes*)
(*     the C10 few-time margin) but NEVER touches the on-chain counters.     *)
(*   * a torn compaction RESETS the local counters (offchain/last_userop/    *)
(*     userop_sigs -> 0, unregistered); the on-chain counters are untouched. *)
(*   * invariant #9: an unregistered slot refuses off-chain until a Type-1   *)
(*     re-registration.                                                      *)
(***************************************************************************)
EXTENDS Naturals, TLC

CONSTANTS MaxSlotUses,  \* the on-chain per-slot cap (real MAX_SLOT_USES = 65536)
          MaxGap,       \* MAX_OFFCHAIN_GAP unbacked off-chain sigs (real 100)
          EnableReset   \* TRUE = torn compaction can reset local counters;
                        \* FALSE = the NEGATIVE CONTROL (no reset ⇒ margin must be bounded,
                        \*         proving the reset is the CAUSE of the residual).

ASSUME MaxSlotUses \in Nat /\ MaxSlotUses >= 2
ASSUME MaxGap \in Nat /\ MaxGap >= 1
ASSUME EnableReset \in BOOLEAN

VARIABLES
    lOff,   \* local offchain_count (resettable)
    lLast,  \* local last_userop_count (resettable; the firmware's on-chain-offchain estimate)
    lSigs,  \* local userop_sigs tally (resettable)
    reg,    \* local: slot registered (a journal entry exists)
    cSlot,  \* on-chain slotUses[i]      (monotonic, unresettable)
    cOff,   \* on-chain offchainSigCount[i] (monotonic, unresettable)
    margin  \* GHOST: total slot-key C10 sigs ever RELEASED (few-time-margin usage)

vars == <<lOff, lLast, lSigs, reg, cSlot, cOff, margin>>

Max(a, b) == IF a > b THEN a ELSE b

Init ==
    /\ lOff = 0 /\ lLast = 0 /\ lSigs = 0 /\ reg = FALSE
    /\ cSlot = 0 /\ cOff = 0
    /\ margin = 0

\* Type-1 re-registration (bootstrap-signed): installs the slot key on-chain,
\* re-marks it registered. Consumes a slot-key SIG (margin) but does not bump the
\* slotUses/offchainSigCount counters (Type-1 bumps bootstrapUses on-chain, modelled
\* out of scope). Only meaningful when currently unregistered (post-reset recovery).
Type1Register ==
    /\ reg = FALSE
    /\ reg' = TRUE
    \* Type-1 is signed by the BOOTSTRAP key (ownerIndex 0), a SEPARATE few-time
    \* budget — it does NOT erode the SLOT key's margin. (Re-registrations are
    \* instead bounded by MAX_BOOTSTRAP_USES, out of this model's scope.)
    /\ UNCHANGED <<lOff, lLast, lSigs, cSlot, cOff, margin>>

\* CMD_OFFCHAIN_SYNC: the companion restores the local last_userop floor from the
\* true on-chain offchainSigCount (the documented post-reset repair). Clamped to
\* the ceiling (MaxSlotUses-1); monotone-raise only.
OffchainSync ==
    /\ reg = TRUE
    /\ \E t \in 0..cOff :                      \* honest companion supplies <= the true on-chain count
         /\ lLast' = Max(lLast, t)
    /\ UNCHANGED <<lOff, lSigs, reg, cSlot, cOff, margin>>

\* Off-chain (EIP-1271) sign: VIEW-ONLY. Gated LOCALLY (invariant #9 registration,
\* the gap gate, and the local combined cap over the LOCAL counters). Erodes the
\* few-time margin; never touches the on-chain counters. `eff` folds the repair.
SignOffchain ==
    /\ reg = TRUE
    /\ LET eff == Max(lOff, lLast) IN
         /\ eff - lLast < MaxGap                     \* gap gate
         /\ lSigs + (eff + 1) <= MaxSlotUses         \* LOCAL combined cap (resettable inputs!)
         /\ lOff' = eff + 1
         /\ margin' = margin + 1
    /\ UNCHANGED <<lLast, lSigs, reg, cSlot, cOff>>

\* Type-2 UserOp sign: the firmware RELEASES it (margin++) if the LOCAL cap passes;
\* then it either LANDS on-chain (both on-chain gates pass) or REVERTS (no on-chain
\* effect). newCount published = eff = max(lOff,lLast).
SignUserop ==
    /\ reg = TRUE
    /\ LET eff == Max(lOff, lLast) IN
         /\ lSigs + eff < MaxSlotUses                \* LOCAL cap: firmware releases the sig
         /\ margin' = margin + 1                      \* the C10 sig is released (uses the key)
         /\ \/ /\ cSlot + 1 <= MaxSlotUses            \* _bumpSlotUses ok
               /\ eff >= cOff                          \* _setOffchainSigCount monotonic (revert if <)
               /\ (cSlot + 1) + eff <= MaxSlotUses     \* combined cap
               \* LANDS: on-chain counters advance, local reconciles.
               /\ cSlot' = cSlot + 1
               /\ cOff' = eff
               /\ lSigs' = lSigs + 1
               /\ lLast' = eff
               /\ lOff' = eff
            \/ /\ ~ ( cSlot + 1 <= MaxSlotUses /\ eff >= cOff /\ (cSlot + 1) + eff <= MaxSlotUses )
               \* REVERTS on-chain: no on-chain effect. The firmware still bumped its
               \* local userop_sigs before release (verify-before-release), but the
               \* on-chain reconcile did not happen.
               /\ lSigs' = lSigs + 1
               /\ UNCHANGED <<cSlot, cOff, lLast, lOff>>
    /\ UNCHANGED reg

\* Torn compaction (below the offchain_gate seam): the LOCAL counters are lost and
\* the slot becomes unregistered. The ON-CHAIN counters are untouched (the backstop).
TornReset ==
    /\ EnableReset
    /\ lOff' = 0 /\ lLast' = 0 /\ lSigs' = 0 /\ reg' = FALSE
    /\ UNCHANGED <<cSlot, cOff, margin>>

Next ==
    \/ Type1Register
    \/ OffchainSync
    \/ SignOffchain
    \/ SignUserop
    \/ TornReset

Spec == Init /\ [][Next]_vars

--------------------------------------------------------------------------------
(* PROPERTIES *)

\* THE BACKSTOP (expected HOLD): the on-chain combined cap is preserved by every
\* action, including torn resets — so the sigs that LAND / validate on-chain (the
\* fund-moving ones) are bounded by MaxSlotUses regardless of any local reset.
INV_ONCHAIN_CAP == cSlot + cOff <= MaxSlotUses

\* On-chain monotonicity (the _bumpSlotUses / _setOffchainSigCount reverts): the
\* authoritative counters never decrease. (Checked as a state invariant against a
\* ghost of their max — here simply that they are within cap and only grow, which
\* the actions guarantee by construction; INV_ONCHAIN_CAP is the load-bearing one.)

\* THE RESIDUAL (expected VIOLATED, and that is the finding): the TRUE few-time-key
\* margin usage is NOT bounded by MaxSlotUses across torn resets. A torn reset
\* zeroes the LOCAL cap inputs, so more view-only off-chain (and Type-2) sigs are
\* released against the same slot key than the on-chain cap ever sees. This is the
\* precise, quantified statement of Finding 2's residual: the on-chain cap bounds
\* LANDED sigs, not RELEASED slot-key sigs.
INV_MARGIN_BOUNDED == margin <= MaxSlotUses

TypeOK ==
    /\ lOff \in Nat /\ lLast \in Nat /\ lSigs \in Nat
    /\ cSlot \in Nat /\ cOff \in Nat /\ margin \in Nat
    /\ reg \in BOOLEAN

\* margin (the ghost) grows without bound across resets — cap it so TLC's state
\* space is finite. The on-chain + local counters are already bounded by MaxSlotUses.
StateBound == margin <= 3 * MaxSlotUses
================================================================================
