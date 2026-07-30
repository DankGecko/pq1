//! Acceptance-table tests: the six rows (§6.2 L2165–2172) plus a
//! MALFORMED sweep. Every combination outside the table is MALFORMED.

mod common;

use common::*;
use fw_manifest::v6::{LaterLifecycleEvidence, PhysicalSlot, QW_CONFIRMED_0, QW_CONFIRMED_1, QW_PENDING};
use pqsigner_rollback::arm_token::{ArmState, ArmToken};
use pqsigner_rollback::backend::{ProbeScript, ScriptedBackend};
use pqsigner_rollback::journal::{
    surviving_install_generation, InstallGenerationEvidence, InstallHalfEvidence,
};
use pqsigner_rollback::lifecycle::{decode_lifecycle, AttributedRead, LifecycleState, MalformedReason};

const F: u32 = GOLDEN_T; // floor == golden T for the passing rows

fn atr(read: &pqsigner_rollback::qw_read::FreshQwRead) -> AttributedRead<'_> {
    AttributedRead {
        read,
        durability: CLEAN,
        launch: MAY_LAUNCH,
    }
}

fn atr_no_launch(read: &pqsigner_rollback::qw_read::FreshQwRead) -> AttributedRead<'_> {
    AttributedRead {
        read,
        durability: CLEAN,
        launch: NO_LAUNCH,
    }
}

struct Fixture {
    b: ScriptedBackend,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            b: TestBackend::new(7),
        }
    }

    fn token(&self, art: &pqsigner_rollback::evidence::VerifiedArtifact, state: ArmState) -> ArmToken {
        let binding = binding_of(art);
        let words = ArmToken::encode(state, &binding);
        ArmToken::decode_and_bind(
            &words,
            binding.slot,
            &INSTALL_ID,
            &binding.manifest_digest,
            &binding.secure_hash,
            &binding.nonsecure_hash,
        )
        .expect("token binds")
    }
}

#[test]
fn row_uninstalled() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, ERASED);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr_no_launch(&c1), atr_no_launch(&pd), None, F)
    {
        LifecycleState::Uninstalled { artifact } => {
            assert_eq!(artifact.r(), GOLDEN_R);
        }
        _ => panic!("expected Uninstalled"),
    }
}

#[test]
fn row_uninstalled_requires_full_generation() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, ERASED);
    // A surviving (one-half) generation before activation is incomplete.
    let surviving = surviving_install_generation(
        InstallHalfEvidence::Exact(INSTALL_ID),
        InstallHalfEvidence::Indeterminate,
        LaterLifecycleEvidence::Pending,
    )
    .unwrap();
    let gen = Some(InstallGenerationEvidence::Surviving(surviving));
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr_no_launch(&c1), atr_no_launch(&pd), None, F)
    {
        LifecycleState::Malformed(MalformedReason::BadInstallGeneration) => {}
        _ => panic!("expected Malformed(BadInstallGeneration)"),
    }
}

#[test]
fn row_pending() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let tok = fx.token(&art, ArmState::ArmReady);
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, QW_PENDING);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr_no_launch(&c1), atr(&pd), Some(tok), F) {
        LifecycleState::Pending { artifact, token } => {
            assert_eq!(artifact.e(), GOLDEN_E);
            assert_eq!(token.state, ArmState::ArmReady);
        }
        _ => panic!("expected Pending"),
    }
}

#[test]
fn row_attempted() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let tok = fx.token(&art, ArmState::Attempted);
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, QW_PENDING);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr_no_launch(&c1), atr(&pd), Some(tok), F) {
        LifecycleState::Attempted { token, .. } => assert_eq!(token.state, ArmState::Attempted),
        _ => panic!("expected Attempted"),
    }
}

#[test]
fn row_confirmed_robust() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let c0 = probe_clean(&mut fx.b, 0, QW_CONFIRMED_0);
    let c1 = probe_clean(&mut fx.b, 1, QW_CONFIRMED_1);
    let pd = probe_clean(&mut fx.b, 2, ERASED);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    // F <= T admitted (F == T here); PENDING/token not consulted.
    match decode_lifecycle(art, gen, atr(&c0), atr(&c1), atr_no_launch(&pd), None, F) {
        LifecycleState::ConfirmedRobust(a) => assert_eq!(a.artifact().t(), GOLDEN_T),
        _ => panic!("expected ConfirmedRobust"),
    }
}

#[test]
fn row_confirmed_robust_rejects_f_greater_than_t() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let c0 = probe_clean(&mut fx.b, 0, QW_CONFIRMED_0);
    let c1 = probe_clean(&mut fx.b, 1, QW_CONFIRMED_1);
    let pd = probe_clean(&mut fx.b, 2, ERASED);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr(&c0), atr(&c1), atr_no_launch(&pd), None, F + 1) {
        LifecycleState::Malformed(MalformedReason::FloorRelationViolation) => {}
        _ => panic!("expected Malformed(FloorRelationViolation) for F > T"),
    }
}

#[test]
fn row_degraded_confirmed_repair_target_only() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    // One exact replica (C0), the other indeterminate; F == T.
    let c0 = probe_clean(&mut fx.b, 0, QW_CONFIRMED_0);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, ERASED);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr(&c0), atr(&c1), atr_no_launch(&pd), None, F) {
        LifecycleState::DegradedConfirmed(_) => {}
        _ => panic!("expected DegradedConfirmed"),
    }
}

#[test]
fn row_degraded_epoch_candidate_repair_target_only() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let c0 = probe_clean(&mut fx.b, 0, QW_CONFIRMED_0);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, ERASED);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    // F < T → degraded epoch candidate (repair target only).
    match decode_lifecycle(art, gen, atr(&c0), atr(&c1), atr_no_launch(&pd), None, F - 1) {
        LifecycleState::DegradedEpochCandidate(_) => {}
        _ => panic!("expected DegradedEpochCandidate"),
    }
}

// ---------------------------------------------------------------------------
// MALFORMED sweep
// ---------------------------------------------------------------------------

#[test]
fn malformed_impossible_writer_order_terminal() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    // CONFIRMED_1 exact with CONFIRMED_0 proven BlankVirgin.
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, QW_CONFIRMED_1);
    let pd = probe_clean(&mut fx.b, 2, QW_PENDING);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    let tok = {
        let a = artifact(&pass(), PhysicalSlot::A);
        fx.token(&a, ArmState::ArmReady)
    };
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr(&c1), atr(&pd), Some(tok), F) {
        LifecycleState::Malformed(MalformedReason::TerminalRejected(_)) => {}
        other => panic!("expected Malformed(TerminalRejected), got {}", row_name(&other)),
    }
}

#[test]
fn malformed_torn_terminal_never_falls_through_to_pending() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let tok = fx.token(&art, ArmState::ArmReady);
    let c0 = probe(&mut fx.b, 0, ProbeScript::AmbiguousOrFault);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, QW_PENDING);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr(&c0), atr_no_launch(&c1), atr(&pd), Some(tok), F) {
        LifecycleState::Malformed(_) => {}
        _ => panic!("a torn terminal must never fall through to PENDING"),
    }
}

#[test]
fn malformed_missing_token_on_probation_branch() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, QW_PENDING);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr_no_launch(&c1), atr(&pd), None, F) {
        LifecycleState::Malformed(MalformedReason::MissingOrMalformedToken) => {}
        _ => panic!("expected Malformed(MissingOrMalformedToken)"),
    }
}

#[test]
fn malformed_binding_mismatched_token() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    // Token for a DIFFERENT install id.
    let bad_token = {
        let mut binding = binding_of(&art);
        binding.install_id = [0x11; 16];
        let words = ArmToken::encode(ArmState::ArmReady, &binding);
        // Decoding against the artifact fails, so the caller models a
        // binding-mismatched token as None… but a structurally valid
        // token for another artifact must ALSO be rejected here. Build a
        // token that decodes against the OTHER binding and present it.
        ArmToken::decode_and_bind(
            &words,
            binding.slot,
            &binding.install_id,
            &binding.manifest_digest,
            &binding.secure_hash,
            &binding.nonsecure_hash,
        )
        .unwrap()
    };
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, QW_PENDING);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr_no_launch(&c1), atr(&pd), Some(bad_token), F)
    {
        LifecycleState::Malformed(MalformedReason::TokenBindingMismatch) => {}
        other => panic!("expected Malformed(TokenBindingMismatch), got {}", row_name(&other)),
    }
}

#[test]
fn malformed_conflicting_install_halves() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, ERASED);
    // No valid generation (conflicting halves → None).
    match decode_lifecycle(art, None, atr_no_launch(&c0), atr_no_launch(&c1), atr_no_launch(&pd), None, F)
    {
        LifecycleState::Malformed(MalformedReason::BadInstallGeneration) => {}
        _ => panic!("expected Malformed(BadInstallGeneration)"),
    }
}

#[test]
fn malformed_floor_relation_on_probation() {
    let mut fx = Fixture::new();
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let tok = fx.token(&art, ArmState::ArmReady);
    let c0 = probe_clean(&mut fx.b, 0, ERASED);
    let c1 = probe_clean(&mut fx.b, 1, ERASED);
    let pd = probe_clean(&mut fx.b, 2, QW_PENDING);
    let gen = Some(full_generation(&mut fx.b, 3, 4));
    // E <= F on the probation branch.
    match decode_lifecycle(art, gen, atr_no_launch(&c0), atr_no_launch(&c1), atr(&pd), Some(tok), GOLDEN_E)
    {
        LifecycleState::Malformed(MalformedReason::FloorRelationViolation) => {}
        other => panic!("expected Malformed(FloorRelationViolation), got {}", row_name(&other)),
    }
}

#[test]
fn out_of_range_version_is_caught_at_manifest_layer() {
    // v6 already refuses R/E outside 1..=0xFFFF_FFFE (FA-1.2); the
    // lifecycle decoder never sees such an artifact.
    assert!(fw_manifest::v6::build_release_package(&fw_manifest::v6::ReleasePackageFields {
        slot: PhysicalSlot::A,
        release_version: 0,
        security_epoch: GOLDEN_E,
        secure_len: 0x1000,
        nonsecure_len: 0x2000,
        secure_hash: &seq(0x00),
        nonsecure_hash: &seq(0x20),
        vendor_fpr: &seq(0x40),
        build_id: &seq(0x60),
        signature: &[0xAA; fw_manifest::SIGNATURE_LEN],
    })
    .is_err());
}

fn row_name(s: &LifecycleState) -> &'static str {
    match s {
        LifecycleState::Uninstalled { .. } => "Uninstalled",
        LifecycleState::Pending { .. } => "Pending",
        LifecycleState::Attempted { .. } => "Attempted",
        LifecycleState::ConfirmedRobust(_) => "ConfirmedRobust",
        LifecycleState::DegradedConfirmed(_) => "DegradedConfirmed",
        LifecycleState::DegradedEpochCandidate(_) => "DegradedEpochCandidate",
        LifecycleState::Malformed(_) => "Malformed",
    }
}
