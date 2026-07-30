//! End-to-end tests of the six frozen entries (§10): T==F zero-write,
//! T>F begin-once, resume, Aborted no-write boot, probation arm, peer /
//! degraded repair — plus every rejected construction.

mod common;

use common::*;
use fw_manifest::v6::PhysicalSlot;
use pqsigner_rollback::arm_token::{ArmState, ArmToken};
use pqsigner_rollback::backend::{Mutation, ProbeScript, RollbackBackend};
use pqsigner_rollback::floor::{
    self, CompletionLaunchEvidence, DeadStageProof, EpochBumpReceipt, FloorView, RecoveryProof,
    StageBinding, SteadyProof,
};
use pqsigner_rollback::intents::*;
use pqsigner_rollback::lifecycle::{decode_lifecycle, LifecycleState};

const FENCE: CompletionLaunchEvidence = CompletionLaunchEvidence::ProvenNoCompletionLaunch;

/// A committed-group SteadyProof at `t`.
fn steady_proof_at(t: u32) -> SteadyProof {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(floor::encode_floor_record(t, 1));
    }
    bank.clean(floor::encode_complete_record(1));
    bank.route1(false);
    match bank.decode(FENCE, None) {
        FloorView::Steady(p) => p,
        _ => panic!("steady"),
    }
}

/// A DeadStageProof with prior floor `t` and a dead stage at `t+1`.
fn dead_proof(t: u32, binding: StageBinding) -> DeadStageProof {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(floor::encode_floor_record(t, 1));
    }
    bank.clean(floor::encode_complete_record(1));
    bank.clean(floor::encode_stage_record(2));
    bank.clean(floor::encode_floor_record(t + 1, 2));
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.route1(false);
    match bank.decode(FENCE, Some(binding)) {
        FloorView::Aborted(p) => p,
        _ => panic!("aborted"),
    }
}

/// A RecoveryProof with prior floor `t` and a completable stage at `t+1`.
fn recovery_proof(t: u32, binding: StageBinding) -> RecoveryProof {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(floor::encode_floor_record(t, 1));
    }
    bank.clean(floor::encode_complete_record(1));
    bank.clean(floor::encode_stage_record(2));
    for _ in 0..3 {
        bank.clean(floor::encode_floor_record(t + 1, 2));
    }
    bank.virgin();
    bank.route1(false);
    match bank.decode(FENCE, Some(binding)) {
        FloorView::Recovering(p) => p,
        _ => panic!("recovering"),
    }
}

fn binding_for(slot: PhysicalSlot, r: u32, e: u32) -> StageBinding {
    StageBinding {
        slot,
        r,
        e,
        manifest_digest: manifest(slot, r, e).stored_digest,
    }
}

/// A Pending lifecycle row for a candidate with the arm token planted in
/// `backend` in the given state.
fn pending_row(
    pass: &pqsigner_rollback::evidence::VerificationPass,
    backend: &mut TestBackend,
    slot: PhysicalSlot,
    r: u32,
    e: u32,
    state: ArmState,
) -> LifecycleState {
    let m = manifest(slot, r, e);
    let art = pass
        .verify_artifact(&m, INSTALL_ID)
        .expect("test manifest is in range");
    let binding = binding_of(&art);
    backend.set_arm_token(Some(ArmToken::encode(state, &binding)));
    let tok = ArmToken::decode_and_bind(
        &ArmToken::encode(state, &binding),
        binding.slot,
        &binding.install_id,
        &binding.manifest_digest,
        &binding.secure_hash,
        &binding.nonsecure_hash,
    )
    .unwrap();
    let c0 = probe_clean(backend, 20, ERASED);
    let c1 = probe_clean(backend, 21, ERASED);
    let pd = probe_clean(backend, 22, fw_manifest::v6::QW_PENDING);
    let gen = Some(full_generation(backend, 23, 24));
    let row = decode_lifecycle(art, gen, atr_nl(&c0), atr_nl(&c1), atr(&pd), Some(tok), m.security_epoch - 1);
    row
}

// ---------------------------------------------------------------------------
// start_from_steady
// ---------------------------------------------------------------------------

#[test]
fn start_same_epoch_has_zero_mutable_backend_effects() {
    let p = pass();
    let mut b = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let artifact = accepted_artifact(&p, &mut b, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let intent = CheckedSteadyIntent::new(steady, artifact, None).expect("intent");
    let mut backend = TestBackend::new(7);
    let out = start_from_steady(&mut backend, intent).expect("start");
    assert_eq!(out, StartOutcome::SameEpochNoWrite);
    assert!(backend.is_pristine(), "T==F: ZERO mutations of any kind");
    assert_eq!(backend.floor_mutation_count(), 0);
    assert!(backend.mutation_log().is_empty());
}

#[test]
fn start_epoch_bump_invokes_begin_exactly_once() {
    let p = pass();
    let mut b = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let artifact = accepted_artifact(&p, &mut b, PhysicalSlot::A, GOLDEN_R, GOLDEN_E + 1);
    let receipt: EpochBumpReceipt = floor::preflight(&steady, GOLDEN_T + 1, 4).unwrap();
    let intent = CheckedSteadyIntent::new(steady, artifact, Some(receipt)).expect("intent");
    let mut backend = TestBackend::new(7);
    backend.set_floor_script(steady_floor_script(GOLDEN_T));
    let out = start_from_steady(&mut backend, intent).expect("start");
    assert_eq!(
        out,
        StartOutcome::Began {
            target: GOLDEN_T + 1,
            group: 2
        }
    );
    assert_eq!(backend.floor_mutation_count(), 1, "exactly one begin");
    assert!(matches!(
        backend.mutation_log()[0],
        Some(Mutation::FloorBegin { target, .. }) if target == GOLDEN_T + 1
    ));
}

#[test]
fn start_t_less_than_f_fails_closed() {
    let p = pass();
    let mut b = TestBackend::new(7);
    // Artifact T == GOLDEN_T but the floor is GOLDEN_T + 1.
    let steady = steady_proof_at(GOLDEN_T + 1);
    let artifact = accepted_artifact(&p, &mut b, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    assert!(matches!(
        CheckedSteadyIntent::new(steady, artifact, None),
        Err(IntentError::FloorRegression)
    ));
}

// ---------------------------------------------------------------------------
// arm_probation_from_steady
// ---------------------------------------------------------------------------

#[test]
fn probation_arm_attempted_once_never_retries() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let fallback = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E);

    let mut backend = TestBackend::new(7);
    let row = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    let intent =
        CheckedSteadyProbationIntent::new(steady, fallback, row, None).expect("intent");
    // The recheck requires the backend to re-decode the same floor state.
    backend.set_floor_script(steady_floor_script(GOLDEN_T));
    let handoff = arm_probation_from_steady(&mut backend, intent).expect("handoff");
    assert_eq!(
        (handoff.slot, handoff.r, handoff.e, handoff.t),
        (PhysicalSlot::A, GOLDEN_R, GOLDEN_E, GOLDEN_T)
    );
    // Only the TAMP transition was recorded — NO rollback-state mutation.
    assert_eq!(backend.floor_mutation_count(), 0);
    assert_eq!(backend.mutation_count(), 1);
    assert!(matches!(
        backend.mutation_log()[0],
        Some(Mutation::ArmTokenTransition(ArmState::Attempted))
    ));
    // The backend token is now exact ATTEMPTED.
    let words = backend.read_arm_token().unwrap();
    let art = artifact(&p, PhysicalSlot::A);
    let binding = binding_of(&art);
    let tok = ArmToken::decode_and_bind(
        &words,
        binding.slot,
        &binding.install_id,
        &binding.manifest_digest,
        &binding.secure_hash,
        &binding.nonsecure_hash,
    )
    .unwrap();
    assert_eq!(tok.state, ArmState::Attempted);

    // ATTEMPTED never retries, at TWO levels:
    // (a) the lifecycle row now decodes as `Attempted` (token is
    //     ATTEMPTED), which is not the `Pending` row the intent requires.
    let steady2 = steady_proof_at(GOLDEN_T);
    let fallback2 = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E);
    let row2 = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::Attempted);
    assert!(matches!(
        CheckedSteadyProbationIntent::new(steady2, fallback2, row2, None),
        Err(IntentError::WrongLifecycleRow)
    ));

    // (b) even with a valid ARM_READY-era intent, if the backend token
    //     is ATTEMPTED by entry time the entry refuses (at-most-once).
    let steady3 = steady_proof_at(GOLDEN_T);
    let fallback3 = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E);
    let row3 = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    let intent3 = CheckedSteadyProbationIntent::new(steady3, fallback3, row3, None).unwrap();
    // Flip the backend token to ATTEMPTED (as the first handoff left it).
    let binding3 = binding_of(&artifact(&p, PhysicalSlot::A));
    backend.set_arm_token(Some(ArmToken::encode(ArmState::Attempted, &binding3)));
    assert_eq!(
        arm_probation_from_steady(&mut backend, intent3).unwrap_err(),
        IntentError::TokenNotArmReady
    );
}

#[test]
fn probation_requires_strictly_newer_candidate() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    // Fallback with the SAME R as the candidate.
    let fallback = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R, GOLDEN_E);
    let mut backend = TestBackend::new(7);
    let row = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    assert!(matches!(
        CheckedSteadyProbationIntent::new(steady, fallback, row, None),
        Err(IntentError::CandidateNotNewer)
    ));
}

#[test]
fn probation_requires_exact_f_fallback() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    // Fallback T = GOLDEN_T - 1, not at the floor.
    let fallback = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E - 1);
    let mut backend = TestBackend::new(7);
    let row = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    assert!(matches!(
        CheckedSteadyProbationIntent::new(steady, fallback, row, None),
        Err(IntentError::FallbackNotAtFloor)
    ));
}

#[test]
fn probation_epoch_bump_receipt_rules() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let floor_val = GOLDEN_T - 1;
    let fallback = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E - 1);

    // T > F without a receipt → MissingPreflight.
    let steady = steady_proof_at(floor_val);
    let mut backend = TestBackend::new(7);
    let steady_for_receipt = steady_proof_at(floor_val);
    assert!(matches!(
        CheckedSteadyProbationIntent::new(steady_for_receipt, accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E - 1), pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady), None),
        Err(IntentError::MissingPreflight)
    ));

    // T > F with a mismatched receipt → MissingPreflight.
    let receipt = floor::preflight(&steady, GOLDEN_T + 5, 4).unwrap();
    assert!(matches!(
        CheckedSteadyProbationIntent::new(
            steady_proof_at(floor_val),
            accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E - 1),
            pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady),
            Some(receipt)
        ),
        Err(IntentError::MissingPreflight)
    ));

    // T > F with the correct receipt → intent builds and arms.
    let good = floor::preflight(&steady, GOLDEN_T, 4).unwrap();
    let intent = CheckedSteadyProbationIntent::new(
        steady,
        fallback,
        pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady),
        Some(good),
    )
    .expect("intent");
    backend.set_floor_script(steady_floor_script(floor_val));
    assert!(arm_probation_from_steady(&mut backend, intent).is_ok());

    // Same-epoch with a receipt → UnexpectedPreflight.
    let steady_se = steady_proof_at(GOLDEN_T);
    let fb_se = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E);
    let stray = floor::preflight(&steady_proof_at(GOLDEN_T - 1), GOLDEN_T, 4).unwrap();
    assert!(matches!(
        CheckedSteadyProbationIntent::new(
            steady_se,
            fb_se,
            pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady),
            Some(stray)
        ),
        Err(IntentError::UnexpectedPreflight)
    ));
}

// ---------------------------------------------------------------------------
// resume_from_recovery
// ---------------------------------------------------------------------------

#[test]
fn resume_from_recovery_resumes_bound_plan_only() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let binding = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof = recovery_proof(GOLDEN_T - 1, binding);
    let candidate = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let intent = CheckedRecoveryIntent::new(proof, candidate).expect("join");
    let mut backend = TestBackend::new(7);
    backend.set_floor_script(recovering_floor_script(GOLDEN_T - 1, binding));
    let receipt = resume_from_recovery(&mut backend, intent).expect("resume");
    assert_eq!(receipt.target, GOLDEN_T);
    assert_eq!(receipt.group, 2);
    assert!(matches!(
        backend.mutation_log()[0],
        Some(Mutation::FloorResume { target }) if target == GOLDEN_T
    ));
    // No `begin` on the recovery path.
    assert!(!backend
        .mutation_log()
        .iter()
        .any(|m| matches!(m, Some(Mutation::FloorBegin { .. }))));
}

#[test]
fn recovery_join_mismatch_is_blocked() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let binding = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof = recovery_proof(GOLDEN_T - 1, binding);
    // Candidate with a different manifest (different digest + T).
    let wrong = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R + 1, GOLDEN_E + 1);
    assert!(CheckedRecoveryIntent::new(proof, wrong).is_err());
}

// ---------------------------------------------------------------------------
// boot_accepted_from_aborted
// ---------------------------------------------------------------------------

#[test]
fn aborted_boots_only_exact_f_artifact_with_zero_writes() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let failed = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof = dead_proof(GOLDEN_T - 1, failed);
    // Boot artifact: T == F, different (R,E) from the failed release.
    let boot = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E - 1);
    let intent = CheckedAbortedAcceptedIntent::new(proof, boot).expect("intent");
    let mut backend = TestBackend::new(7);
    backend.set_floor_script(dead_floor_script(GOLDEN_T - 1, binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E)));
    let handoff = boot_accepted_from_aborted(&mut backend, intent).expect("handoff");
    assert_eq!(handoff.t, GOLDEN_T - 1);
    assert!(backend.is_pristine(), "boot_accepted_from_aborted writes nothing");
    assert_eq!(backend.floor_mutation_count(), 0);
}

#[test]
fn aborted_rejects_non_exact_f_artifact_and_new_release() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let failed = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof = dead_proof(GOLDEN_T - 1, failed);
    // A "new release" artifact with T > F cannot be admitted.
    let new_release = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E);
    assert!(matches!(
        CheckedAbortedAcceptedIntent::new(proof, new_release),
        Err(IntentError::NotAbortedBootEligible)
    ));
}

// ---------------------------------------------------------------------------
// arm_peer_repair / arm_degraded_artifact_repair
// ---------------------------------------------------------------------------

#[test]
fn peer_repair_equal_release_set_arms_and_writes_no_backend() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let mut backend = TestBackend::new(7);
    // Twin: opposite slot, SAME (R, E).
    let twin_row = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    let intent = CheckedPeerRepairIntent::new(FreshFloorProof::Steady(steady), source, twin_row)
        .expect("intent");
    backend.set_floor_script(steady_floor_script(GOLDEN_T));
    let handoff = arm_peer_repair(&mut backend, intent).expect("handoff");
    assert_eq!(handoff.slot, PhysicalSlot::B);
    assert_eq!(backend.floor_mutation_count(), 0, "repair: zero rollback-backend writes");
}

#[test]
fn peer_repair_rejects_non_twin() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    // Different R → not the same release set.
    let steady = steady_proof_at(GOLDEN_T);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let mut backend = TestBackend::new(7);
    let row = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E, ArmState::ArmReady);
    assert!(matches!(
        CheckedPeerRepairIntent::new(FreshFloorProof::Steady(steady), source, row),
        Err(IntentError::PeerRepairMismatch)
    ));
    // Same slot → not the opposite-slot twin.
    let steady = steady_proof_at(GOLDEN_T);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let row = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    assert!(matches!(
        CheckedPeerRepairIntent::new(FreshFloorProof::Steady(steady), source, row),
        Err(IntentError::PeerRepairMismatch)
    ));
}

#[test]
fn degraded_repair_under_aborted_requires_exact_f() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let failed = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof = dead_proof(GOLDEN_T - 1, failed);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E - 1);
    let mut backend = TestBackend::new(7);
    // Target with T == F → arms.
    let row_ok = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E - 1, ArmState::ArmReady);
    let intent = CheckedDegradedRepairIntent::new(FreshFloorProof::Aborted(proof), source, row_ok)
        .expect("intent");
    backend.set_floor_script(dead_floor_script(GOLDEN_T - 1, binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E)));
    assert!(arm_degraded_artifact_repair(&mut backend, intent).is_ok());
    assert_eq!(backend.floor_mutation_count(), 0);

    // Target with T != F → rejected.
    let failed2 = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof2 = dead_proof(GOLDEN_T - 1, failed2);
    let source2 = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E - 1);
    let row_bad = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E, ArmState::ArmReady);
    assert!(matches!(
        CheckedDegradedRepairIntent::new(FreshFloorProof::Aborted(proof2), source2, row_bad),
        Err(IntentError::FloorRegression)
    ));
}

// ---------------------------------------------------------------------------
// Frozen recheck-immediately-before-handoff (drift rejection)
// ---------------------------------------------------------------------------

#[test]
fn probation_floor_drift_rejects_handoff() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let fallback = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E);

    let mut backend = TestBackend::new(7);
    let row = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    let intent =
        CheckedSteadyProbationIntent::new(steady, fallback, row, None).expect("intent");
    // The backend's floor state MATCHES the intent's proof at this point…
    backend.set_floor_script(steady_floor_script(GOLDEN_T));
    // …then mutates before the entry runs (different floor content →
    // different class AND digest).
    backend.set_floor_script(steady_floor_script(GOLDEN_T - 1));
    assert_eq!(
        arm_probation_from_steady(&mut backend, intent).unwrap_err(),
        IntentError::FloorDrift
    );
}

#[test]
fn aborted_boot_rejects_floor_drift() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let failed = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof = dead_proof(GOLDEN_T - 1, failed);
    let boot = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E - 1);
    let intent = CheckedAbortedAcceptedIntent::new(proof, boot).expect("intent");

    let mut backend = TestBackend::new(7);
    // Backend state no longer shows the same terminal dead plan (class
    // changed Aborted → Steady, digest differs).
    backend.set_floor_script(steady_floor_script(GOLDEN_T - 1));
    assert_eq!(
        boot_accepted_from_aborted(&mut backend, intent).unwrap_err(),
        IntentError::FloorDrift
    );
}

#[test]
fn peer_repair_floor_drift_rejects_handoff() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let mut backend = TestBackend::new(7);
    let twin_row = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    let intent = CheckedPeerRepairIntent::new(FreshFloorProof::Steady(steady), source, twin_row)
        .expect("intent");
    // Drift: the floor moved since intent construction.
    backend.set_floor_script(dead_floor_script(
        GOLDEN_T - 1,
        binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E),
    ));
    assert_eq!(
        arm_peer_repair(&mut backend, intent).unwrap_err(),
        IntentError::FloorDrift
    );
}

// ---------------------------------------------------------------------------
// R2-3: recheck before the mutating entries (start/resume)
// ---------------------------------------------------------------------------

#[test]
fn start_epoch_bump_floor_drift_rejects_begin() {
    let p = pass();
    let mut b = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let artifact = accepted_artifact(&p, &mut b, PhysicalSlot::A, GOLDEN_R, GOLDEN_E + 1);
    let receipt = floor::preflight(&steady, GOLDEN_T + 1, 4).unwrap();
    let intent = CheckedSteadyIntent::new(steady, artifact, Some(receipt)).expect("intent");
    let mut backend = TestBackend::new(7);
    // Drift: the backend's floor moved since intent construction.
    backend.set_floor_script(steady_floor_script(GOLDEN_T + 1));
    assert_eq!(
        start_from_steady(&mut backend, intent).unwrap_err(),
        IntentError::FloorDrift
    );
    assert_eq!(backend.floor_mutation_count(), 0, "no begin on drift");
}

#[test]
fn resume_floor_drift_rejects_resume() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let binding = binding_for(PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let proof = recovery_proof(GOLDEN_T - 1, binding);
    let candidate = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let intent = CheckedRecoveryIntent::new(proof, candidate).expect("join");
    let mut backend = TestBackend::new(7);
    // Drift: the bound plan is gone (backend shows plain Steady).
    backend.set_floor_script(steady_floor_script(GOLDEN_T - 1));
    assert_eq!(
        resume_from_recovery(&mut backend, intent).unwrap_err(),
        IntentError::FloorDrift
    );
    assert_eq!(backend.floor_mutation_count(), 0, "no resume on drift");
}

// ---------------------------------------------------------------------------
// R2-4: degraded repair floor relations
// ---------------------------------------------------------------------------

#[test]
fn degraded_repair_steady_requires_target_strictly_above_floor() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    // Review PoC: Steady(F=9), target T=3 → FloorRegression.
    let steady9 = steady_proof_at(9);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, 10);
    let mut backend = TestBackend::new(7);
    let row = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R + 1, 4, ArmState::ArmReady);
    assert!(matches!(
        CheckedDegradedRepairIntent::new(FreshFloorProof::Steady(steady9), source, row),
        Err(IntentError::FloorRegression)
    ));

    // Steady with T == F → rejected (not strictly above).
    let steady = steady_proof_at(GOLDEN_T);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let row = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E, ArmState::ArmReady);
    assert!(matches!(
        CheckedDegradedRepairIntent::new(FreshFloorProof::Steady(steady), source, row),
        Err(IntentError::FloorRegression)
    ));

    // Steady with T > F → accepted and arms (with recheck active).
    let steady = steady_proof_at(GOLDEN_T);
    let source = accepted_artifact(&p, &mut setup, PhysicalSlot::A, GOLDEN_R, GOLDEN_E);
    let row = pending_row(&p, &mut backend, PhysicalSlot::B, GOLDEN_R + 1, GOLDEN_E + 1, ArmState::ArmReady);
    let intent = CheckedDegradedRepairIntent::new(FreshFloorProof::Steady(steady), source, row)
        .expect("T>F accepted");
    backend.set_floor_script(steady_floor_script(GOLDEN_T));
    assert!(arm_degraded_artifact_repair(&mut backend, intent).is_ok());
    assert_eq!(backend.floor_mutation_count(), 0);
}

// ---------------------------------------------------------------------------
// R2-6: the handoff re-bind matches (R, E, T)
// ---------------------------------------------------------------------------

#[test]
fn handoff_rejects_token_with_mismatched_target() {
    let p = pass();
    let mut setup = TestBackend::new(7);
    let steady = steady_proof_at(GOLDEN_T);
    let fallback = accepted_artifact(&p, &mut setup, PhysicalSlot::B, GOLDEN_R - 1, GOLDEN_E);

    let mut backend = TestBackend::new(7);
    let row = pending_row(&p, &mut backend, PhysicalSlot::A, GOLDEN_R, GOLDEN_E, ArmState::ArmReady);
    let intent =
        CheckedSteadyProbationIntent::new(steady, fallback, row, None).expect("intent");
    // Replace the backend token with a structurally valid token whose
    // tuple carries DIFFERENT (E, T) — internally consistent (T == E-1),
    // binding hash self-consistent, but NOT the artifact's tuple. Only
    // the (R,E,T) re-bind can catch it.
    let art = artifact(&p, PhysicalSlot::A);
    let mut binding = binding_of(&art);
    binding.e += 1;
    binding.t = binding.e - 1;
    backend.set_arm_token(Some(ArmToken::encode(ArmState::ArmReady, &binding)));
    backend.set_floor_script(steady_floor_script(GOLDEN_T));
    assert_eq!(
        arm_probation_from_steady(&mut backend, intent).unwrap_err(),
        IntentError::TokenNotArmReady
    );
}
