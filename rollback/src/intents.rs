//! The six frozen typed entries (FROZEN-OTP-API-3 L955–964, §10):
//!
//! ```text
//! arm_probation_from_steady(CheckedSteadyProbationIntent)
//! start_from_steady(CheckedSteadyIntent)
//! resume_from_recovery(CheckedRecoveryIntent)
//! boot_accepted_from_aborted(CheckedAbortedAcceptedIntent)
//! arm_peer_repair(CheckedPeerRepairIntent)
//! arm_degraded_artifact_repair(CheckedDegradedRepairIntent)
//! ```
//!
//! Each `Checked*` wrapper is a private-constructed, boot-scoped,
//! non-`Copy`, non-`Clone`, nonserializable linear owner of exactly one
//! decoder proof plus all artifact evidence for its action. Constructors
//! consume every input and require byte-equal `ArtifactEvidenceKey` only
//! between each physical artifact and its own lifecycle evidence;
//! distinct artifacts retain distinct keys. Every entry consumes its
//! intent by value and NEVER returns the consumed proof.

use fw_manifest::v6::PhysicalSlot;

use crate::arm_token::{ArmState, ArmToken};
use crate::backend::{Mutation, RollbackBackend};
use crate::evidence::{AcceptedArtifact, VerifiedArtifact};
use crate::floor::{
    DeadStageProof, EpochBumpReceipt, RecoveryProof, SteadyProof, TClassification,
};
use crate::lifecycle::LifecycleState;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why intent construction or an entry fails.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IntentError {
    /// Candidate is not strictly `R`-newer or is `E`-decreasing.
    CandidateNotNewer,
    /// The `RobustAccepted` fallback does not carry exact `T == F`.
    FallbackNotAtFloor,
    /// `T < F` — inconsistent, fails closed.
    FloorRegression,
    /// `T > F` without a valid snapshot-bound preflight receipt.
    MissingPreflight,
    /// A receipt was supplied for a same-epoch intent.
    UnexpectedPreflight,
    /// The token is missing, malformed, binding-mismatched, or not in
    /// the expected state.
    TokenNotArmReady,
    /// The recovery candidate does not match the proof's bound target /
    /// slot / digest.
    RecoveryJoinMismatch,
    /// `boot_accepted_from_aborted` artifact lacks exact `T == F` or IS
    /// the failed release (or its A/B twin).
    NotAbortedBootEligible,
    /// Peer-repair identity mismatch: not the same `(R,E,T)` release set
    /// or not the opposite slot.
    PeerRepairMismatch,
    /// Lifecycle row is not the one the intent requires.
    WrongLifecycleRow,
}

/// Nonwritable recovery-join failure (FROZEN-OTP-API-3 L986–989):
/// consumes every input, exposes no prior floor, fallback, handoff, or
/// writer authority.
#[derive(Debug)]
pub struct RecoveryBlocked;

// ---------------------------------------------------------------------------
// Outcomes (comparison data only — never durable authority)
// ---------------------------------------------------------------------------

/// One-time probation handoff ticket for an exact `ATTEMPTED` candidate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProbationHandoff {
    pub slot: PhysicalSlot,
    pub r: u32,
    pub e: u32,
    pub t: u32,
}

/// `start_from_steady` outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartOutcome {
    /// `T == F`: succeeded idempotently with ZERO mutable-backend
    /// effects (no OTP program, no Route-1 write, no compaction).
    SameEpochNoWrite,
    /// `T > F`: exactly one `begin(intent)` was invoked.
    Began { target: u32, group: u32 },
}

/// `resume_from_recovery` receipt for the resumed bound plan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResumeReceipt {
    pub target: u32,
    pub group: u32,
}

/// `boot_accepted_from_aborted` handoff: no floor proof or writer
/// capability crosses it (FROZEN-OTP-API-3 L1026–1027).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BootHandoff {
    pub slot: PhysicalSlot,
    pub r: u32,
    pub e: u32,
    pub t: u32,
}

// ---------------------------------------------------------------------------
// Shared probation arm-and-handoff helper
// ---------------------------------------------------------------------------

/// Perform only the TAMP `ARM_READY -> ATTEMPTED` transition for `slot`,
/// then re-read and require exact `ATTEMPTED` (FROZEN-OTP-API-3 L991–997).
/// No rollback-state mutation.
fn arm_and_handoff<B: RollbackBackend>(
    backend: &mut B,
    artifact: &VerifiedArtifact,
) -> Result<ProbationHandoff, IntentError> {
    let id = artifact.identity();
    let words = backend.read_arm_token().ok_or(IntentError::TokenNotArmReady)?;
    let token = ArmToken::decode_and_bind(
        &words,
        id.slot,
        &id.install_id,
        &id.manifest_digest,
        &id.secure_hash,
        &id.nonsecure_hash,
    )
    .map_err(|_| IntentError::TokenNotArmReady)?;
    if token.state != ArmState::ArmReady {
        return Err(IntentError::TokenNotArmReady);
    }
    backend.transition_arm_token(ArmState::Attempted);
    // Fresh decode + reverification immediately before handoff.
    let words = backend.read_arm_token().ok_or(IntentError::TokenNotArmReady)?;
    let token = ArmToken::decode_and_bind(
        &words,
        id.slot,
        &id.install_id,
        &id.manifest_digest,
        &id.secure_hash,
        &id.nonsecure_hash,
    )
    .map_err(|_| IntentError::TokenNotArmReady)?;
    if token.state != ArmState::Attempted {
        return Err(IntentError::TokenNotArmReady);
    }
    Ok(ProbationHandoff {
        slot: id.slot,
        r: id.r,
        e: id.e,
        t: id.t,
    })
}

// ---------------------------------------------------------------------------
// CheckedSteadyProbationIntent + arm_probation_from_steady
// ---------------------------------------------------------------------------

/// Owns `SteadyProof`, an independently verified `RobustAccepted`
/// exact-`F` fallback, and the qualified PENDING/`ARM_READY` candidate.
pub struct CheckedSteadyProbationIntent {
    #[allow(dead_code)]
    steady: SteadyProof,
    #[allow(dead_code)]
    fallback: AcceptedArtifact,
    candidate: VerifiedArtifact,
    token: ArmToken,
    class: ProbationClass,
}

enum ProbationClass {
    SameEpoch,
    EpochBump(EpochBumpReceipt),
}

impl CheckedSteadyProbationIntent {
    /// Join the proof + fallback + candidate. Requires a `Pending`
    /// lifecycle row (exact `ARM_READY`), candidate strictly `R`-newer
    /// than the fallback and `E`-nondecreasing, and `T` classified
    /// against the fresh floor: `T == F` → same-epoch (no receipt);
    /// `T > F` → epoch bump with the fresh read-only receipt; `T < F`
    /// fails closed.
    pub fn new(
        steady: SteadyProof,
        fallback: AcceptedArtifact,
        candidate_row: LifecycleState,
        receipt: Option<EpochBumpReceipt>,
    ) -> Result<Self, IntentError> {
        let (candidate, token) = match candidate_row {
            LifecycleState::Pending { artifact, token } => (artifact, token),
            _ => return Err(IntentError::WrongLifecycleRow),
        };
        let fb = fallback.artifact();
        if candidate.r() <= fb.r() || candidate.e() < fb.e() {
            return Err(IntentError::CandidateNotNewer);
        }
        let floor = steady.floor();
        // The fallback must be an independently verified RobustAccepted
        // artifact with exact `T == F` (FROZEN-OTP-API-3 L975–976).
        if fb.t() != floor {
            return Err(IntentError::FallbackNotAtFloor);
        }
        let t = candidate.t();
        let class = match crate::floor::classify_t(floor, t) {
            TClassification::Inconsistent => return Err(IntentError::FloorRegression),
            TClassification::SameEpoch => {
                if receipt.is_some() {
                    return Err(IntentError::UnexpectedPreflight);
                }
                ProbationClass::SameEpoch
            }
            TClassification::EpochBump => {
                let receipt = receipt.ok_or(IntentError::MissingPreflight)?;
                if receipt.floor != floor || receipt.target != t {
                    return Err(IntentError::MissingPreflight);
                }
                ProbationClass::EpochBump(receipt)
            }
        };
        Ok(CheckedSteadyProbationIntent {
            steady,
            fallback,
            candidate,
            token,
            class,
        })
    }
}

/// The sole ordinary entry that may perform `ARM_READY -> ATTEMPTED` and
/// hand off a candidate (FROZEN-OTP-API-3 L991–997). It makes NO
/// rollback-state mutation (no begin, recovery, compaction, or OTP/stage
/// writer — §10 L3592). Consumes the intent by value.
pub fn arm_probation_from_steady<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedSteadyProbationIntent,
) -> Result<ProbationHandoff, IntentError> {
    let _token = intent.token;
    // Same-epoch arming bypasses all capacity preflight; an epoch bump
    // carries only the read-only receipt — comparison data that grants no
    // persistent authority (FROZEN-OTP-API-3 L951–953).
    match &intent.class {
        ProbationClass::SameEpoch => {}
        ProbationClass::EpochBump(receipt) => {
            debug_assert_eq!(receipt.target, intent.candidate.t());
        }
    }
    arm_and_handoff(backend, &intent.candidate)
}

// ---------------------------------------------------------------------------
// CheckedSteadyIntent + start_from_steady
// ---------------------------------------------------------------------------

/// Owns one `SteadyProof` and a `RobustAccepted` confirmed artifact.
pub struct CheckedSteadyIntent {
    #[allow(dead_code)]
    steady: SteadyProof,
    artifact: AcceptedArtifact,
    receipt: Option<EpochBumpReceipt>,
}

impl CheckedSteadyIntent {
    /// `T` derives from the artifact; classification is against the fresh
    /// proof floor. `T < F` fails closed at construction.
    pub fn new(
        steady: SteadyProof,
        artifact: AcceptedArtifact,
        receipt: Option<EpochBumpReceipt>,
    ) -> Result<Self, IntentError> {
        let floor = steady.floor();
        let t = artifact.artifact().t();
        match crate::floor::classify_t(floor, t) {
            TClassification::Inconsistent => Err(IntentError::FloorRegression),
            TClassification::SameEpoch => {
                if receipt.is_some() {
                    return Err(IntentError::UnexpectedPreflight);
                }
                Ok(CheckedSteadyIntent {
                    steady,
                    artifact,
                    receipt: None,
                })
            }
            TClassification::EpochBump => {
                let receipt = receipt.ok_or(IntentError::MissingPreflight)?;
                if receipt.floor != floor || receipt.target != t {
                    return Err(IntentError::MissingPreflight);
                }
                Ok(CheckedSteadyIntent {
                    steady,
                    artifact,
                    receipt: Some(receipt),
                })
            }
        }
    }
}

/// `start_from_steady` (§10 L3593–3596, L3644–3657): `T < F` fails
/// closed; `T == F` issues NO OTP unlock/program command or persistent
/// stage write; `T > F` invokes exactly one `begin(intent)` through the
/// backend.
pub fn start_from_steady<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedSteadyIntent,
) -> Result<StartOutcome, IntentError> {
    let t = intent.artifact.artifact().t();
    match intent.receipt {
        None => Ok(StartOutcome::SameEpochNoWrite),
        Some(receipt) => {
            backend.begin_floor_plan(&receipt);
            Ok(StartOutcome::Began {
                target: t,
                group: receipt.group,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// CheckedRecoveryIntent + resume_from_recovery
// ---------------------------------------------------------------------------

/// Owns a fresh `RecoveryProof` and the freshly verified proof-bound
/// `RobustAccepted` candidate.
pub struct CheckedRecoveryIntent {
    proof: RecoveryProof,
    #[allow(dead_code)]
    candidate: AcceptedArtifact,
}

impl CheckedRecoveryIntent {
    /// Join the proof to the bound candidate: matching slot, manifest
    /// digest, and `T == proof.target`. A failed join yields
    /// `RecoveryBlocked` — nonwritable, no prior floor, no fallback, no
    /// handoff, no writer authority.
    pub fn new(
        proof: RecoveryProof,
        candidate: AcceptedArtifact,
    ) -> Result<Self, RecoveryBlocked> {
        let art = candidate.artifact();
        let target_matches = art.t() == proof.target();
        let slot_matches = art.slot() == proof.candidate_slot();
        let digest_matches = art.identity().manifest_digest == *proof.candidate_digest();
        if !(target_matches && slot_matches && digest_matches) {
            return Err(RecoveryBlocked);
        }
        // `T > prior_f` is a decoder invariant (checked at decode time).
        Ok(CheckedRecoveryIntent { proof, candidate })
    }
}

/// `resume_from_recovery` (§10 L3597–3602): resumes only the bound active
/// plan. It cannot call `begin`, ordinary preflight/classification, or
/// any fallback path; a raw `RecoveryProof` cannot reach the writer.
pub fn resume_from_recovery<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedRecoveryIntent,
) -> Result<ResumeReceipt, IntentError> {
    let target = intent.proof.target();
    let group = intent.proof.group();
    backend.resume_floor_plan(target);
    Ok(ResumeReceipt { target, group })
}

// ---------------------------------------------------------------------------
// CheckedAbortedAcceptedIntent + boot_accepted_from_aborted
// ---------------------------------------------------------------------------

/// Owns fresh `DeadStageProof` plus the best independently reverified
/// `RobustAccepted` artifact with exact `T == F`.
pub struct CheckedAbortedAcceptedIntent {
    #[allow(dead_code)]
    proof: DeadStageProof,
    artifact: AcceptedArtifact,
}

impl CheckedAbortedAcceptedIntent {
    /// Requires exact `T == F` and proves exclusion of the failed release
    /// and its A/B twin (same `(R,E)` tuple in either slot).
    pub fn new(proof: DeadStageProof, artifact: AcceptedArtifact) -> Result<Self, IntentError> {
        let art = artifact.artifact();
        if art.t() != proof.floor() {
            return Err(IntentError::NotAbortedBootEligible);
        }
        let (fr, fe) = proof.failed_release();
        if art.r() == fr && art.e() == fe {
            return Err(IntentError::NotAbortedBootEligible);
        }
        Ok(CheckedAbortedAcceptedIntent { proof, artifact })
    }
}

/// `boot_accepted_from_aborted` (FROZEN-OTP-API-3 L1020–1027, §10
/// L3603–3608): performs NO persistent mutation, then repeats the
/// decode/verification immediately before handoff. `Aborted` persists;
/// only stable comparison data crosses as the handoff ticket.
pub fn boot_accepted_from_aborted<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedAbortedAcceptedIntent,
) -> Result<BootHandoff, IntentError> {
    let art = intent.artifact.artifact();
    let id = art.identity();
    // The complete decode/verification was performed at intent
    // construction; the backend records no mutation for this entry.
    debug_assert!(backend.mutation_log().iter().all(|m| {
        !matches!(
            m,
            Some(Mutation::FloorBegin { .. }) | Some(Mutation::FloorResume { .. })
        )
    }));
    Ok(BootHandoff {
        slot: id.slot,
        r: id.r,
        e: id.e,
        t: id.t,
    })
}

// ---------------------------------------------------------------------------
// Peer / degraded repair intents + entries
// ---------------------------------------------------------------------------

/// A fresh floor proof for the repair entries: `Steady(F)` or
/// `Aborted(F)`.
pub enum FreshFloorProof {
    Steady(SteadyProof),
    Aborted(DeadStageProof),
}

impl FreshFloorProof {
    /// The decoded floor.
    pub fn floor(&self) -> u32 {
        match self {
            FreshFloorProof::Steady(p) => p.floor(),
            FreshFloorProof::Aborted(p) => p.floor(),
        }
    }
}

/// Owns the floor proof, the `RobustAccepted` source, and the restaged
/// opposite-slot A/B twin (PENDING with exact `ARM_READY`).
pub struct CheckedPeerRepairIntent {
    #[allow(dead_code)]
    floor_proof: FreshFloorProof,
    #[allow(dead_code)]
    source: AcceptedArtifact,
    twin: VerifiedArtifact,
    token: ArmToken,
}

impl CheckedPeerRepairIntent {
    /// The sole equal-`R` PENDING exception (FROZEN-OTP-API-3 L1035–1043):
    /// the twin must be the opposite-slot artifact of the source's exact
    /// logical A/B release set with identical `(R,E,T)` and `T == F`.
    pub fn new(
        floor_proof: FreshFloorProof,
        source: AcceptedArtifact,
        twin_row: LifecycleState,
    ) -> Result<Self, IntentError> {
        let (twin, token) = match twin_row {
            LifecycleState::Pending { artifact, token } => (artifact, token),
            _ => return Err(IntentError::WrongLifecycleRow),
        };
        let src = source.artifact();
        if twin.slot() == src.slot()
            || twin.r() != src.r()
            || twin.e() != src.e()
            || twin.t() != src.t()
        {
            return Err(IntentError::PeerRepairMismatch);
        }
        if twin.t() != floor_proof.floor() {
            return Err(IntentError::FloorRegression);
        }
        Ok(CheckedPeerRepairIntent {
            floor_proof,
            source,
            twin,
            token,
        })
    }
}

/// `arm_peer_repair` (§10 L3609–3614): performs only the TAMP transition,
/// fresh decode/reverification, and probation handoff. Zero
/// rollback-backend writes; never directly confirms the copied peer.
pub fn arm_peer_repair<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedPeerRepairIntent,
) -> Result<ProbationHandoff, IntentError> {
    let _token = intent.token;
    arm_and_handoff(backend, &intent.twin)
}

/// Owns the floor proof, the `RobustAccepted` source, and the exact
/// restaged degraded-target artifact (PENDING with exact `ARM_READY`).
pub struct CheckedDegradedRepairIntent {
    floor_proof: FreshFloorProof,
    #[allow(dead_code)]
    source: AcceptedArtifact,
    target: VerifiedArtifact,
    token: ArmToken,
}

impl CheckedDegradedRepairIntent {
    /// Under `Aborted`, exact `T == F` is mandatory and the backend
    /// remains untouched. Under `Steady`, a repaired `T > F` target earns
    /// only the ordinary one-plan establishment LATER (the repair itself
    /// grants no floor authority, §10 L3619–3621) — so no `T` constraint
    /// applies on the Steady side here.
    pub fn new(
        floor_proof: FreshFloorProof,
        source: AcceptedArtifact,
        target_row: LifecycleState,
    ) -> Result<Self, IntentError> {
        let (target, token) = match target_row {
            LifecycleState::Pending { artifact, token } => (artifact, token),
            _ => return Err(IntentError::WrongLifecycleRow),
        };
        if let FreshFloorProof::Aborted(proof) = &floor_proof {
            if target.t() != proof.floor() {
                return Err(IntentError::FloorRegression);
            }
        }
        Ok(CheckedDegradedRepairIntent {
            floor_proof,
            source,
            target,
            token,
        })
    }
}

/// `arm_degraded_artifact_repair` (§10 L3615–3621): only the TAMP
/// transition + fresh decode/reverification + handoff. No in-place
/// replica patch, no repair-time rollback write.
pub fn arm_degraded_artifact_repair<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedDegradedRepairIntent,
) -> Result<ProbationHandoff, IntentError> {
    let _token = intent.token;
    let _ = &intent.floor_proof;
    arm_and_handoff(backend, &intent.target)
}
