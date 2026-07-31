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
use crate::backend::{ArmTransitionPermit, FloorBeginPermit, FloorResumePermit, RollbackBackend};
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
    /// The repair target does not bind to the supplied degraded-history
    /// evidence (wrong slot/tuple, stale install identity, or the source
    /// shares the target's slot) — a fresh no-history target is not a
    /// degraded-artifact repair.
    MissingDegradedHistory,
    /// The frozen recheck-immediately-before-handoff found the
    /// floor/stage state CHANGED since intent construction (fresh
    /// re-decode disagrees on class, floor, or snapshot digest). The
    /// intent is consumed and no authority is granted.
    FloorDrift,
    /// The frozen artifact recheck-immediately-before-handoff found the
    /// artifact/lifecycle evidence CHANGED since intent construction
    /// (manifest re-verification, identity, terminal QWs, or install
    /// generation disagree). The intent is consumed and no authority is
    /// granted.
    ArtifactDrift,
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

/// What the frozen recheck-immediately-before-handoff expects of the
/// floor/stage state when the entry runs (FROZEN-OTP-API-3 L898–900,
/// L991–997, §10 L3589–3591, L3603–3608).
struct RecheckContext {
    /// Required decoder class.
    class: RecheckClass,
    /// The floor the intent was constructed against.
    floor: u32,
    /// Digest of the complete physical snapshot the intent's proof
    /// decoded from.
    snapshot_digest: [u8; 32],
    /// When set, the fresh decode's floor must ALSO equal this value
    /// (the exact-`F` fallback's target re-verified at entry, R3-7).
    fallback_t: Option<u32>,
}

/// The floor class a recheck must reproduce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RecheckClass {
    /// Exact `Steady(F)` (same floor, same snapshot digest).
    Steady,
    /// Exact `Aborted(F)` — the same terminal dead plan and quarantine
    /// remain fully proved.
    Aborted,
    /// Either `Steady(F)` or `Aborted(F)` (repair entries).
    SteadyOrAborted,
    /// Exact `Recovering` with the bound active plan (same target,
    /// group, and snapshot digest).
    Recovering { target: u32, group: u32 },
}

/// Run the frozen recheck: a FRESH complete floor/stage decode against
/// current backend state must return the expected class with the same
/// bound values and a byte-equal snapshot digest. Any drift consumes the
/// intent and grants no authority.
fn run_recheck<B: RollbackBackend>(backend: &mut B, ctx: &RecheckContext) -> Result<(), IntentError> {
    use crate::floor::FloorView;
    match (ctx.class, backend.redecode_floor()) {
        (RecheckClass::Steady, FloorView::Steady(p))
        | (RecheckClass::SteadyOrAborted, FloorView::Steady(p))
            if p.floor() == ctx.floor && p.snapshot_digest() == &ctx.snapshot_digest =>
        {
            Ok(())
        }
        (RecheckClass::Aborted, FloorView::Aborted(p))
        | (RecheckClass::SteadyOrAborted, FloorView::Aborted(p))
            if p.floor() == ctx.floor && p.snapshot_digest() == &ctx.snapshot_digest =>
        {
            Ok(())
        }
        (
            RecheckClass::Recovering { target, group },
            FloorView::Recovering(p),
        ) if p.target() == target
            && p.group() == group
            && p.snapshot_digest() == &ctx.snapshot_digest =>
        {
            Ok(())
        }
        _ => Err(IntentError::FloorDrift),
    }
    .and_then(|()| {
        // R3-7: re-verify the exact-`F` fallback binding against the
        // FRESH floor (post-recheck), not just the construction-time one.
        if let Some(fallback_t) = ctx.fallback_t {
            if fallback_t != ctx.floor {
                return Err(IntentError::FloorDrift);
            }
        }
        Ok(())
    })
}

/// What the frozen artifact recheck expects of the presented artifact.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ArtifactExpectation {
    /// A PENDING probation candidate: both terminals proven
    /// `BlankVirgin`, exact PENDING, and a valid install generation for
    /// the artifact's sealed key.
    PendingCandidate,
    /// A robust CONFIRMED artifact (probation fallback / aborted boot):
    /// exact `FullTerminalSet` for the artifact's sealed key.
    Robust,
}

/// The artifact half of the frozen recheck-immediately-before-handoff
/// (R6-1; FROZEN-OTP-API-3 L897–900, §10 item 5): re-probe and re-verify
/// the manifest, re-derive the identity, and re-check the state-
/// appropriate lifecycle evidence against the intent's sealed key. Any
/// drift consumes the intent and grants no authority.
fn reverify_artifact<B: RollbackBackend>(
    backend: &mut B,
    artifact: &VerifiedArtifact,
    expect: ArtifactExpectation,
) -> Result<(), IntentError> {
    let id = artifact.identity();
    let recheck = backend
        .reverify_artifact(id)
        .ok_or(IntentError::ArtifactDrift)?;
    if recheck.identity != *id {
        return Err(IntentError::ArtifactDrift);
    }
    match expect {
        ArtifactExpectation::PendingCandidate => {
            for (read, _, launch) in [&recheck.terminal_c0, &recheck.terminal_c1] {
                if crate::qw_read::BlankVirgin::prove(read, *launch).is_none() {
                    return Err(IntentError::ArtifactDrift);
                }
            }
            let (read, durability, _) = &recheck.pending;
            if !crate::journal::exact_marker(read, &fw_manifest::v6::QW_PENDING, *durability) {
                return Err(IntentError::ArtifactDrift);
            }
            // R7-4: the admission rule admits a qualified
            // SurvivingInstallGeneration on this row, so the recheck
            // must supply the same later-lifecycle evidence — a
            // Full-only reconstruction would self-DoS every legally
            // armed survivor-generation candidate.
            let gen = crate::lifecycle::decode_install_generation(
                artifact,
                crate::lifecycle::AttributedRead {
                    read: &recheck.install_id.0,
                    durability: recheck.install_id.1,
                    launch: recheck.install_id.2,
                },
                crate::lifecycle::AttributedRead {
                    read: &recheck.install_id_inv.0,
                    durability: recheck.install_id_inv.1,
                    launch: recheck.install_id_inv.2,
                },
                Some(fw_manifest::v6::LaterLifecycleEvidence::Pending),
            );
            if gen.is_none() {
                return Err(IntentError::ArtifactDrift);
            }
            Ok(())
        }
        ArtifactExpectation::Robust => {
            let key_digest = artifact.key().digest();
            match crate::journal::decode_terminal_set(
                &recheck.terminal_c0.0,
                recheck.terminal_c0.1,
                recheck.terminal_c0.2,
                &recheck.terminal_c1.0,
                recheck.terminal_c1.1,
                recheck.terminal_c1.2,
                artifact.key(),
            ) {
                crate::journal::TerminalSetOutcome::Full(set)
                    if set.evidence_key() == &key_digest => {}
                _ => return Err(IntentError::ArtifactDrift),
            }
            // R8-3: a robust row also requires state-appropriate
            // InstallGenerationEvidence (§6.2 L2174–2178). Re-run the
            // generation decode with terminal evidence (full or
            // qualified surviving), bound to the artifact's key.
            let gen = crate::lifecycle::decode_install_generation(
                artifact,
                crate::lifecycle::AttributedRead {
                    read: &recheck.install_id.0,
                    durability: recheck.install_id.1,
                    launch: recheck.install_id.2,
                },
                crate::lifecycle::AttributedRead {
                    read: &recheck.install_id_inv.0,
                    durability: recheck.install_id_inv.1,
                    launch: recheck.install_id_inv.2,
                },
                Some(fw_manifest::v6::LaterLifecycleEvidence::Terminal),
            );
            if gen.is_none() {
                return Err(IntentError::ArtifactDrift);
            }
            Ok(())
        }
    }
}

/// Perform only the TAMP `ARM_READY -> ATTEMPTED` transition, then run
/// the frozen recheck (fresh complete floor/stage decode with
/// class/floor/snapshot-digest equality), re-verify the candidate
/// artifact/lifecycle evidence against fresh reads, and re-read/re-bind
/// the token to exact `ATTEMPTED` immediately before handoff
/// (FROZEN-OTP-API-3 L991–997, L898–900, R6-1). Any drift or token
/// anomaly consumes the intent and grants no authority. No
/// rollback-state mutation.
fn arm_and_handoff<B: RollbackBackend>(
    backend: &mut B,
    artifact: &VerifiedArtifact,
    recheck: &RecheckContext,
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
    // The re-bind must match the artifact's exact (R, E, T), not merely
    // be self-consistent (the binding hash commits to the token's own
    // structural tuple).
    if (token.binding().r, token.binding().e, token.binding().t) != (id.r, id.e, id.t) {
        return Err(IntentError::TokenNotArmReady);
    }
    if token.state() != ArmState::ArmReady {
        return Err(IntentError::TokenNotArmReady);
    }
    // Mint the one-time transition permit inside the entry after the
    // pre-mutation validation (R5-2); the frozen transition-then-recheck
    // order follows (§10 item 5).
    backend.transition_arm_token(ArmTransitionPermit::mint(ArmState::Attempted));
    // Frozen recheck: fresh complete floor/stage decode must agree with
    // the intent's proof snapshot (no drift since construction).
    run_recheck(backend, recheck)?;
    // Frozen artifact recheck (R6-1): the candidate's manifest and
    // lifecycle evidence must still verify against fresh reads.
    reverify_artifact(backend, artifact, ArtifactExpectation::PendingCandidate)?;
    // Fresh token decode + binding immediately before handoff.
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
    if (token.binding().r, token.binding().e, token.binding().t) != (id.r, id.e, id.t) {
        return Err(IntentError::TokenNotArmReady);
    }
    if token.state() != ArmState::Attempted {
        return Err(IntentError::TokenNotArmReady);
    }
    Ok(ProbationHandoff {
        slot: id.slot,
        r: id.r,
        e: id.e,
        t: id.t,
    })
}

/// Re-validate a preflight receipt against the proof it must be bound
/// to (R3-5): floor, target, snapshot digest, allocation sequence
/// (group), and capacity (margin). The receipt is comparison data; this
/// is the only validation path.
fn receipt_matches(steady: &SteadyProof, receipt: &EpochBumpReceipt, t: u32) -> bool {
    let expected_group = match steady.group() {
        crate::floor::GroupIdentity::Base0 => Some(1),
        crate::floor::GroupIdentity::Group(g) => g.checked_add(1),
    };
    receipt.floor() == steady.floor()
        && receipt.target() == t
        && receipt.snapshot_digest() == steady.snapshot_digest()
        && Some(receipt.group()) == expected_group
        // The margin is proof-bound: it must equal THIS proof's decoded
        // virgin-cell count, and it must fund the COMPLETE frozen plan
        // (PLAN_CELLS = three initial witnesses plus one replacement;
        // R8-1).
        && receipt.margin() == steady.virgin_cells()
        && receipt.margin() >= crate::floor::PLAN_CELLS
}

// ---------------------------------------------------------------------------
// CheckedSteadyProbationIntent + arm_probation_from_steady
// ---------------------------------------------------------------------------

/// Owns `SteadyProof`, an independently verified `RobustAccepted`
/// exact-`F` fallback, and the qualified PENDING/`ARM_READY` candidate.
pub struct CheckedSteadyProbationIntent {
    steady: SteadyProof,
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
            LifecycleState::Pending(row) => row.into_parts(),
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
                // The receipt must be current for THIS proof: floor,
                // target, digest, allocation sequence, and capacity.
                if !receipt_matches(&steady, &receipt, t) {
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
/// writer — §10 L3592). After the TAMP transition it runs the frozen
/// recheck: a fresh complete floor/stage decode must reproduce exact
/// `Steady(F)` with the intent proof's snapshot digest, and the token is
/// re-read/re-bound to exact `ATTEMPTED` immediately before handoff.
/// Any drift or error consumes the intent by value.
pub fn arm_probation_from_steady<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedSteadyProbationIntent,
) -> Result<ProbationHandoff, IntentError> {
    let _token = intent.token;
    // Same-epoch arming bypasses all capacity preflight; an epoch bump
    // carries only the read-only receipt — comparison data that grants no
    // persistent authority (FROZEN-OTP-API-3 L951–953). The receipt is
    // re-verified at entry (R3-7: no debug-only assertions here).
    match &intent.class {
        ProbationClass::SameEpoch => {}
        ProbationClass::EpochBump(receipt) => {
            if receipt.target() != intent.candidate.t() {
                return Err(IntentError::MissingPreflight);
            }
        }
    }
    let recheck = RecheckContext {
        class: RecheckClass::Steady,
        floor: intent.steady.floor(),
        snapshot_digest: *intent.steady.snapshot_digest(),
        fallback_t: Some(intent.fallback.artifact().t()),
    };
    let handoff = arm_and_handoff(backend, &intent.candidate, &recheck)?;
    // R6-1: the robust exact-`F` fallback must ALSO still verify
    // immediately before handoff (§10 item 5: "reverify both artifacts").
    reverify_artifact(backend, intent.fallback.artifact(), ArtifactExpectation::Robust)?;
    Ok(handoff)
}

// ---------------------------------------------------------------------------
// CheckedSteadyIntent + start_from_steady
// ---------------------------------------------------------------------------

/// Owns one `SteadyProof` and a `RobustAccepted` confirmed artifact.
pub struct CheckedSteadyIntent {
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
                if !receipt_matches(&steady, &receipt, t) {
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
/// stage write; `T > F` first runs the frozen recheck (fresh complete
/// decode must reproduce exact `Steady(F)` with the intent proof's
/// snapshot digest) and only then invokes exactly one `begin(intent)`
/// through the backend.
pub fn start_from_steady<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedSteadyIntent,
) -> Result<StartOutcome, IntentError> {
    let t = intent.artifact.artifact().t();
    match intent.receipt {
        None => Ok(StartOutcome::SameEpochNoWrite),
        Some(receipt) => {
            // FROZEN-OTP-API-3 L897–900: fresh re-verification of the
            // robust artifact (R7-1) and a fresh full decode immediately
            // before the mutation.
            reverify_artifact(backend, intent.artifact.artifact(), ArtifactExpectation::Robust)?;
            let recheck = RecheckContext {
                class: RecheckClass::Steady,
                floor: intent.steady.floor(),
                snapshot_digest: *intent.steady.snapshot_digest(),
                fallback_t: None,
            };
            run_recheck(backend, &recheck)?;
            backend.begin_floor_plan(
                FloorBeginPermit::mint(t, receipt.group()),
                &receipt,
            );
            Ok(StartOutcome::Began {
                target: t,
                group: receipt.group(),
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
/// plan, after the frozen recheck reproduces exact `Recovering` with the
/// same target, group, and snapshot digest. It cannot call `begin`,
/// ordinary preflight/classification, or any fallback path; a raw
/// `RecoveryProof` cannot reach the writer.
pub fn resume_from_recovery<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedRecoveryIntent,
) -> Result<ResumeReceipt, IntentError> {
    let target = intent.proof.target();
    let group = intent.proof.group();
    // FROZEN-OTP-API-3 L897–900: fresh re-verification of the bound
    // robust candidate (R7-1) and a fresh full decode immediately
    // before the mutation, reproducing the bound plan.
    reverify_artifact(backend, intent.candidate.artifact(), ArtifactExpectation::Robust)?;
    let recheck = RecheckContext {
        class: RecheckClass::Recovering { target, group },
        floor: target,
        snapshot_digest: *intent.proof.snapshot_digest(),
        fallback_t: None,
    };
    run_recheck(backend, &recheck)?;
    backend.resume_floor_plan(FloorResumePermit::mint(target));
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
/// L3603–3608): performs NO persistent mutation, then immediately before
/// handoff repeats the complete floor/stage decode — it must reproduce
/// exact `Aborted(F)` with the proof's snapshot digest (any drift
/// consumes the intent and grants no authority) — and re-verifies the
/// artifact's exact `T == F` and failed-release exclusion.
/// `Aborted` persists; only stable comparison data crosses as the
/// handoff ticket.
pub fn boot_accepted_from_aborted<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedAbortedAcceptedIntent,
) -> Result<BootHandoff, IntentError> {
    let art = intent.artifact.artifact();
    let id = *art.identity();
    // Re-verify the artifact predicates immediately before handoff.
    let (fr, fe) = intent.proof.failed_release();
    if id.t != intent.proof.floor() || (id.r == fr && id.e == fe) {
        return Err(IntentError::NotAbortedBootEligible);
    }
    // Frozen recheck: the complete fresh decode must reproduce the same
    // terminal dead plan (same floor, same snapshot digest).
    let recheck = RecheckContext {
        class: RecheckClass::Aborted,
        floor: intent.proof.floor(),
        snapshot_digest: *intent.proof.snapshot_digest(),
        fallback_t: None,
    };
    run_recheck(backend, &recheck)?;
    // R6-1: re-verify the artifact's manifest and robust terminal
    // evidence against fresh reads immediately before handoff.
    reverify_artifact(backend, art, ArtifactExpectation::Robust)?;
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

    /// Digest of the complete physical snapshot the proof decodes from.
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        match self {
            FreshFloorProof::Steady(p) => p.snapshot_digest(),
            FreshFloorProof::Aborted(p) => p.snapshot_digest(),
        }
    }
}

/// Writer-minted linear receipt for the twin slot's complete
/// erase/restage (§10 item 9: "the independently restaged opposite-slot
/// archived A/B twin... fresh install identity"). Mirrors
/// [`DegradedHistoryEvidence`]: the receipt cross-checks the supplied
/// prior twin identity (slot + manifest digest) against the erase/
/// restage receipt and requires the NEW install id to differ from the
/// prior twin generation's — proving the twin is a FRESH restage, not
/// merely a different stale copy. HOST-MODEL constructor stands in for
/// the physical writer (same posture as [`EraseRestageReceipt`]).
#[derive(PartialEq, Eq, Debug)]
pub struct TwinRestageReceipt {
    prior_identity: crate::evidence::ArtifactIdentity,
    new_install_id: [u8; 16],
}

impl TwinRestageReceipt {
    /// HOST-MODEL constructor (the writer is out of scope). `None` when
    /// the erase/restage receipt does not bind the prior identity's
    /// slot and manifest digest, or when the new install id equals the
    /// prior generation's (no fresh identity, no restage).
    pub fn new(
        prior_identity: crate::evidence::ArtifactIdentity,
        restage: EraseRestageReceipt,
        new_install_id: [u8; 16],
    ) -> Option<TwinRestageReceipt> {
        if restage.slot() != prior_identity.slot
            || restage.prior_manifest_digest() != &prior_identity.manifest_digest
            || prior_identity.install_id == new_install_id
        {
            return None;
        }
        Some(TwinRestageReceipt {
            prior_identity,
            new_install_id,
        })
    }

    /// The prior twin generation's slot.
    pub fn slot(&self) -> PhysicalSlot {
        self.prior_identity.slot
    }

    /// The prior twin generation's identity.
    pub fn prior_identity(&self) -> &crate::evidence::ArtifactIdentity {
        &self.prior_identity
    }

    /// The fresh install id of the restaged twin.
    pub fn new_install_id(&self) -> [u8; 16] {
        self.new_install_id
    }
}

/// Owns the floor proof, the `RobustAccepted` source, the restaged
/// opposite-slot A/B twin (PENDING with exact `ARM_READY`), and the
/// twin's erase/restage receipt.
pub struct CheckedPeerRepairIntent {
    floor_proof: FreshFloorProof,
    #[allow(dead_code)]
    source: AcceptedArtifact,
    twin: VerifiedArtifact,
    token: ArmToken,
}

impl CheckedPeerRepairIntent {
    /// The sole equal-`R` PENDING exception (FROZEN-OTP-API-3 L1035–1043):
    /// the twin must be the opposite-slot artifact of the source's exact
    /// logical A/B release set with identical `(R,E,T)` and `T == F`,
    /// and must carry a FRESH install identity proven by the twin's
    /// erase/restage receipt (R6-2: the receipt binds the twin slot and
    /// its NEW install id, which its constructor already required to
    /// differ from the PRIOR twin generation's id — not merely from the
    /// source's).
    pub fn new(
        floor_proof: FreshFloorProof,
        source: AcceptedArtifact,
        twin_row: LifecycleState,
        receipt: TwinRestageReceipt,
    ) -> Result<Self, IntentError> {
        let (twin, token) = match twin_row {
            LifecycleState::Pending(row) => row.into_parts(),
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
        if twin.install_id() == src.install_id()
            || receipt.slot() != twin.slot()
            || receipt.new_install_id() != twin.install_id()
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
/// the frozen recheck (fresh decode must reproduce the intent's floor
/// class/floor/digest), token re-read/re-bind, and probation handoff.
/// Zero rollback-backend writes; never directly confirms the copied peer.
pub fn arm_peer_repair<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedPeerRepairIntent,
) -> Result<ProbationHandoff, IntentError> {
    let _token = intent.token;
    let recheck = RecheckContext {
        class: RecheckClass::SteadyOrAborted,
        floor: intent.floor_proof.floor(),
        snapshot_digest: *intent.floor_proof.snapshot_digest(),
        fallback_t: None,
    };
    arm_and_handoff(backend, &intent.twin, &recheck)
}

/// Receipt for a complete inactive-range erase/restage of one physical
/// slot (§10 item 10: "full erase/restage evidence"). The physical
/// writer is out of scope; this HOST-MODEL constructor stands in for
/// the writer's receipt.
#[derive(PartialEq, Eq, Debug)]
pub struct EraseRestageReceipt {
    slot: PhysicalSlot,
    prior_manifest_digest: [u8; 32],
}

impl EraseRestageReceipt {
    /// HOST-MODEL constructor (the writer is out of scope).
    pub fn new(slot: PhysicalSlot, prior_manifest_digest: [u8; 32]) -> Self {
        EraseRestageReceipt {
            slot,
            prior_manifest_digest,
        }
    }

    pub fn slot(&self) -> PhysicalSlot {
        self.slot
    }

    pub fn prior_manifest_digest(&self) -> &[u8; 32] {
        &self.prior_manifest_digest
    }
}

/// The typed degraded-history evidence §10 item 10 requires: proof that
/// the repair target previously existed as a DEGRADED artifact — its
/// prior [`ArtifactIdentity`] AND a surviving terminal set bound to it
/// (R8-4: evidence of actual degradation, not a caller claim) — plus a
/// full erase/restage receipt binding that same slot and manifest
/// digest. Consumed linearly by [`CheckedDegradedRepairIntent::new`].
#[derive(Debug)]
pub struct DegradedHistoryEvidence {
    prior_identity: crate::evidence::ArtifactIdentity,
    #[allow(dead_code)]
    restage: EraseRestageReceipt,
    #[allow(dead_code)]
    degradation: crate::journal::SurvivingTerminalSet,
}

impl DegradedHistoryEvidence {
    /// Join the prior degraded identity, its erase/restage receipt, and
    /// the surviving terminal proof. `None` when the receipt binds a
    /// different slot or digest, or when the surviving set's sealed key
    /// digest does not match `prior_key_digest` (a set minted for some
    /// other identity — or a full, non-degraded set, which cannot even
    /// be presented in this position).
    pub fn new(
        prior_identity: crate::evidence::ArtifactIdentity,
        restage: EraseRestageReceipt,
        degradation: crate::journal::SurvivingTerminalSet,
        prior_key_digest: &[u8; 32],
    ) -> Option<DegradedHistoryEvidence> {
        if restage.slot() != prior_identity.slot
            || restage.prior_manifest_digest() != &prior_identity.manifest_digest
        {
            return None;
        }
        if degradation.evidence_key() != prior_key_digest {
            return None;
        }
        Some(DegradedHistoryEvidence {
            prior_identity,
            restage,
            degradation,
        })
    }
}

/// Owns the floor proof, the `RobustAccepted` source, and the exact
/// restaged degraded-target artifact (PENDING with exact `ARM_READY`)
/// — admitted only with the full degraded-history evidence set.
pub struct CheckedDegradedRepairIntent {
    floor_proof: FreshFloorProof,
    source: AcceptedArtifact,
    target: VerifiedArtifact,
    token: ArmToken,
}

impl CheckedDegradedRepairIntent {
    /// §10 item 10 (L3615–3621): requires the `RobustAccepted` source,
    /// the exact archived package for the PREVIOUSLY DEGRADED target
    /// (same slot, same `(R,E)` as `history`'s prior identity), a full
    /// erase/restage receipt, and a FRESH install identity (the new
    /// row's install id must differ from the degraded generation's).
    /// Under `Aborted`, exact `T == F` is mandatory and the backend
    /// remains untouched. Under `Steady`, the item only PERMITS a
    /// repaired `T > F` candidate to later earn robust terminal
    /// evidence through probation (floor establishment remains a later
    /// ordinary `start_from_steady` action) — it does NOT require
    /// strict `T > F`, and the ordinary same-floor `DegradedConfirmed`
    /// repair (the `F == T` row) is legal, so the Steady arm rejects
    /// only `target.t() < floor`.
    pub fn new(
        floor_proof: FreshFloorProof,
        source: AcceptedArtifact,
        target_row: LifecycleState,
        history: DegradedHistoryEvidence,
    ) -> Result<Self, IntentError> {
        let (target, token) = match target_row {
            LifecycleState::Pending(row) => row.into_parts(),
            _ => return Err(IntentError::WrongLifecycleRow),
        };
        // Degraded-history binding: the repair target must be the
        // restaged PRIOR DEGRADED artifact, not a fresh no-history one.
        let prior = &history.prior_identity;
        if target.slot() != prior.slot
            || target.r() != prior.r
            || target.e() != prior.e
            || target.slot() == source.artifact().slot()
        {
            return Err(IntentError::MissingDegradedHistory);
        }
        if target.install_id() == prior.install_id {
            // The install identity must be FRESH (never the degraded
            // generation's id).
            return Err(IntentError::MissingDegradedHistory);
        }
        match &floor_proof {
            FreshFloorProof::Aborted(proof) => {
                if target.t() != proof.floor() {
                    return Err(IntentError::FloorRegression);
                }
            }
            FreshFloorProof::Steady(proof) => {
                if target.t() < proof.floor() {
                    return Err(IntentError::FloorRegression);
                }
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
/// transition + the frozen recheck + token re-read/re-bind + handoff. No
/// in-place replica patch, no repair-time rollback write.
pub fn arm_degraded_artifact_repair<B: RollbackBackend>(
    backend: &mut B,
    intent: CheckedDegradedRepairIntent,
) -> Result<ProbationHandoff, IntentError> {
    let _token = intent.token;
    // R8-4(b): the load-bearing robust source is reverified at entry,
    // same discipline as R7-1.
    reverify_artifact(backend, intent.source.artifact(), ArtifactExpectation::Robust)?;
    let recheck = RecheckContext {
        class: RecheckClass::SteadyOrAborted,
        floor: intent.floor_proof.floor(),
        snapshot_digest: *intent.floor_proof.snapshot_digest(),
        fallback_t: None,
    };
    arm_and_handoff(backend, &intent.target, &recheck)
}
