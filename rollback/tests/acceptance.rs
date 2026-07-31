//! Acceptance-table tests: the six rows (§6.2 L2165–2172) plus a
//! MALFORMED sweep. Every combination outside the table is MALFORMED.

mod common;

use common::*;
use fw_manifest::v6::{LaterLifecycleEvidence, PhysicalSlot, QW_CONFIRMED_0, QW_CONFIRMED_1, QW_PENDING};
use pqsigner_rollback::arm_token::{ArmState, ArmToken};
use pqsigner_rollback::backend::ProbeScript;

use pqsigner_rollback::lifecycle::{decode_lifecycle, LifecycleState, MalformedReason};

const F: u32 = GOLDEN_T; // floor == golden T for the passing rows

/// Plant + acquire the arm token THROUGH the TerminalFirst capability
/// (R14-3 + R15-1: TAMP evidence is read only after both terminal QWs,
/// and reaches the decoder only as sealed TokenEvidence).
fn token_for(
    b: &mut TestBackend,
    tf: &pqsigner_rollback::lifecycle::TerminalFirst,
    art: &pqsigner_rollback::evidence::VerifiedArtifact,
    state: ArmState,
) -> pqsigner_rollback::lifecycle::TokenEvidence {
    let binding = binding_of(art);
    b.set_arm_token(Some(ArmToken::encode(state, &binding)));
    tf.read_arm_token(b).expect("token planted")
}

#[test]
fn row_uninstalled() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED));
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, None, F)
    {
        LifecycleState::Uninstalled(row) => {
            assert_eq!(row.artifact().r(), GOLDEN_R);
        }
        _ => panic!("expected Uninstalled"),
    }
}

#[test]
fn row_uninstalled_requires_full_generation() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED));
    // A surviving (one-half) generation before activation is incomplete:
    // construct one via the canonical orchestrator (exact id half,
    // indeterminate inv half, later-lifecycle evidence).
    let idq = probe_at(&mut b, 4, art.identity().install_id_qw_address(), ProbeScript::Clean(INSTALL_ID));
    let invq = probe_at(&mut b, 5, art.identity().install_id_inv_qw_address(), ProbeScript::Clean(ERASED));
    let gen = pqsigner_rollback::lifecycle::decode_install_generation(
        &art,
        pqsigner_rollback::lifecycle::AttributedRead {
            read: &idq,
            durability: CLEAN,
            launch: MAY_LAUNCH,
        },
        pqsigner_rollback::lifecycle::AttributedRead {
            read: &invq,
            durability: pqsigner_rollback::qw_read::Durability::Ambiguous,
            launch: MAY_LAUNCH,
        },
        Some(LaterLifecycleEvidence::Pending),
        None,
    );
    match decode_lifecycle(art, gen, &tf, &pd, None, F)
    {
        LifecycleState::Malformed(MalformedReason::BadInstallGeneration) => {}
        _ => panic!("expected Malformed(BadInstallGeneration)"),
    }
}

#[test]
fn row_pending() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(QW_PENDING));
    let tok = token_for(&mut b, &tf, &art, ArmState::ArmReady);
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, Some(tok), F) {
        LifecycleState::Pending(row) => {
            assert_eq!(row.artifact().e(), GOLDEN_E);
            assert_eq!(row.token().state(), ArmState::ArmReady);
        }
        _ => panic!("expected Pending"),
    }
}

#[test]
fn row_attempted() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(QW_PENDING));
    let tok = token_for(&mut b, &tf, &art, ArmState::Attempted);
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, Some(tok), F) {
        LifecycleState::Attempted(row) => assert_eq!(row.token().state(), ArmState::Attempted),
        _ => panic!("expected Attempted"),
    }
}

#[test]
fn row_confirmed_robust() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(QW_CONFIRMED_0), ProbeScript::Clean(QW_CONFIRMED_1), ProbeScript::Clean(ERASED));
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    // F <= T admitted (F == T here); PENDING/token not consulted.
    match decode_lifecycle(art, gen, &tf, &pd, None, F) {
        LifecycleState::ConfirmedRobust(a) => assert_eq!(a.artifact().t(), GOLDEN_T),
        _ => panic!("expected ConfirmedRobust"),
    }
}

#[test]
fn row_confirmed_robust_rejects_f_greater_than_t() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(QW_CONFIRMED_0), ProbeScript::Clean(QW_CONFIRMED_1), ProbeScript::Clean(ERASED));
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, None, F + 1) {
        LifecycleState::Malformed(MalformedReason::FloorRelationViolation) => {}
        _ => panic!("expected Malformed(FloorRelationViolation) for F > T"),
    }
}

#[test]
fn row_degraded_confirmed_repair_target_only() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    // One exact replica (C0), the other indeterminate; F == T.
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(QW_CONFIRMED_0), ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED));
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, None, F) {
        LifecycleState::DegradedConfirmed(_) => {}
        _ => panic!("expected DegradedConfirmed"),
    }
}

#[test]
fn row_degraded_epoch_candidate_repair_target_only() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(QW_CONFIRMED_0), ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED));
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    // F < T → degraded epoch candidate (repair target only).
    match decode_lifecycle(art, gen, &tf, &pd, None, F - 1) {
        LifecycleState::DegradedEpochCandidate(_) => {}
        _ => panic!("expected DegradedEpochCandidate"),
    }
}

// ---------------------------------------------------------------------------
// MALFORMED sweep
// ---------------------------------------------------------------------------

#[test]
fn malformed_impossible_writer_order_terminal() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    // CONFIRMED_1 exact with CONFIRMED_0 proven BlankVirgin.
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(QW_CONFIRMED_1), ProbeScript::Clean(QW_PENDING));
    let tok = token_for(&mut b, &tf, &art, ArmState::ArmReady);
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, Some(tok), F) {
        LifecycleState::Malformed(MalformedReason::TerminalRejected(_)) => {}
        other => panic!("expected Malformed(TerminalRejected), got {}", row_name(&other)),
    }
}

#[test]
fn malformed_torn_terminal_never_falls_through_to_pending() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::AmbiguousOrFault, ProbeScript::Clean(ERASED), ProbeScript::Clean(QW_PENDING));
    let tok = token_for(&mut b, &tf, &art, ArmState::ArmReady);
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, Some(tok), F) {
        LifecycleState::Malformed(_) => {}
        _ => panic!("a torn terminal must never fall through to PENDING"),
    }
}

#[test]
fn malformed_missing_token_on_probation_branch() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(QW_PENDING));
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, None, F) {
        LifecycleState::Malformed(MalformedReason::MissingOrMalformedToken) => {}
        _ => panic!("expected Malformed(MissingOrMalformedToken)"),
    }
}

#[test]
fn malformed_binding_mismatched_token() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    // Token for a DIFFERENT install id (via the test-scaffold mint —
    // the honest path mints only through the capability).
    let bad_token = {
        let mut binding = binding_of(&art);
        binding.install_id = [0x11; 16];
        pqsigner_rollback::lifecycle::TokenEvidence::for_test(ArmToken::encode(
            ArmState::ArmReady,
            &binding,
        ))
    };
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(QW_PENDING));
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, Some(bad_token), F)
    {
        // R15-1: the sealed evidence is decoded against THIS artifact
        // inside decode_lifecycle — a mismatched install id now fails at
        // the binding stage, before the tuple comparison.
        LifecycleState::Malformed(MalformedReason::MissingOrMalformedToken) => {}
        other => panic!("expected Malformed(MissingOrMalformedToken), got {}", row_name(&other)),
    }
}

#[test]
fn malformed_conflicting_install_halves() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED));
    // No valid generation (conflicting halves → None).
    match decode_lifecycle(art, None, &tf, &pd, None, F)
    {
        LifecycleState::Malformed(MalformedReason::BadInstallGeneration) => {}
        _ => panic!("expected Malformed(BadInstallGeneration)"),
    }
}

#[test]
fn malformed_floor_relation_on_probation() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, pd) = probe_journal(&mut b, &art, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(QW_PENDING));
    let tok = token_for(&mut b, &tf, &art, ArmState::ArmReady);
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    // E <= F on the probation branch.
    match decode_lifecycle(art, gen, &tf, &pd, Some(tok), GOLDEN_E)
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

// ---------------------------------------------------------------------------
// R3-2: cross-artifact journal QWs and cross-epoch reads
// ---------------------------------------------------------------------------

#[test]
fn cross_slot_terminal_qws_are_rejected() {
    // A's terminal codewords presented for B: the reads sit at A's
    // canonical addresses, not B's — rejected before any authority.
    let mut b = TestBackend::new(7);
    let p = pass();
    let art_b = artifact(&p, PhysicalSlot::B);
    let art_a = artifact(&p, PhysicalSlot::A);
    let id_a = art_a.identity();
    let c0 = probe_at(&mut b, 10, id_a.confirmed_0_qw_address, ProbeScript::Clean(QW_CONFIRMED_0));
    let c1 = probe_at(&mut b, 11, id_a.confirmed_1_qw_address, ProbeScript::Clean(QW_CONFIRMED_1));
    let pd = probe_at(&mut b, 12, id_a.pending_qw_address, ProbeScript::Clean(ERASED));
    let gen = Some(full_generation(&mut b, &art_b, 3, 4));
    // Inject the mis-addressed reads through the test-scaffold
    // constructor (the honest TerminalFirst::probe path can never
    // produce them — that's the point of R10-2).
    let tf = pqsigner_rollback::lifecycle::TerminalFirst::from_reads(
        (c0, CLEAN, MAY_LAUNCH),
        (c1, CLEAN, MAY_LAUNCH),
    );
    let pd = pqsigner_rollback::lifecycle::PendingEvidence::for_test(pd, CLEAN, NO_LAUNCH);
    match decode_lifecycle(art_b, gen, &tf, &pd, None, F) {
        LifecycleState::Malformed(MalformedReason::NonCanonicalJournalQw) => {}
        other => panic!("expected Malformed(NonCanonicalJournalQw), got {}", row_name(&other)),
    }
}

#[test]
fn cross_epoch_terminal_reads_are_rejected() {
    // Terminal reads from two different probe epochs (two passes) can
    // never join one lifecycle proof.
    let mut b7 = TestBackend::new(7);
    let mut b8 = TestBackend::new(8);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let id = art.identity();
    let c0 = probe_at(&mut b7, 10, id.confirmed_0_qw_address, ProbeScript::Clean(QW_CONFIRMED_0));
    let c1 = probe_at(&mut b8, 11, id.confirmed_1_qw_address, ProbeScript::Clean(QW_CONFIRMED_1));
    let pd = probe_at(&mut b8, 12, id.pending_qw_address, ProbeScript::Clean(ERASED));
    let gen = Some(full_generation(&mut b7, &art, 3, 4));
    let tf = pqsigner_rollback::lifecycle::TerminalFirst::from_reads(
        (c0, CLEAN, MAY_LAUNCH),
        (c1, CLEAN, MAY_LAUNCH),
    );
    let pd = pqsigner_rollback::lifecycle::PendingEvidence::for_test(pd, CLEAN, NO_LAUNCH);
    match decode_lifecycle(art, gen, &tf, &pd, None, F) {
        LifecycleState::Malformed(MalformedReason::NonCanonicalJournalQw) => {}
        other => panic!("expected Malformed(NonCanonicalJournalQw), got {}", row_name(&other)),
    }
}

fn row_name(s: &LifecycleState) -> &'static str {
    match s {
        LifecycleState::Uninstalled(_) => "Uninstalled",
        LifecycleState::Pending { .. } => "Pending",
        LifecycleState::Attempted { .. } => "Attempted",
        LifecycleState::ConfirmedRobust(_) => "ConfirmedRobust",
        LifecycleState::DegradedConfirmed(_) => "DegradedConfirmed",
        LifecycleState::DegradedEpochCandidate(_) => "DegradedEpochCandidate",
        LifecycleState::Malformed(_) => "Malformed",
    }
}

#[test]
fn generation_minted_for_a_rejected_for_b() {
    // R5-4: generation evidence minted for artifact A (same install_id)
    // must not join artifact B — the proof binds A's sealed key.
    let mut b = TestBackend::new(7);
    let p = pass();
    let art_a = artifact(&p, PhysicalSlot::A);
    let art_b = artifact(&p, PhysicalSlot::B);
    // Mint the generation for A through the canonical orchestrator.
    let id = probe_at(&mut b, 4, art_a.identity().install_id_qw_address(), ProbeScript::Clean(INSTALL_ID));
    let inv = probe_at(&mut b, 5, art_a.identity().install_id_inv_qw_address(), ProbeScript::Clean(INSTALL_ID_INV));
    let gen_for_a = pqsigner_rollback::lifecycle::decode_install_generation(&art_a, atr(&id), atr(&inv), None, None);
    assert!(gen_for_a.is_some(), "generation mints for A");
    // Present it for B (identical install_id, different sealed key).
    let (tf, pd) = probe_journal(&mut b, &art_b, ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED), ProbeScript::Clean(ERASED));
    match decode_lifecycle(art_b, gen_for_a, &tf, &pd, None, F) {
        LifecycleState::Malformed(MalformedReason::BadInstallGeneration) => {}
        other => panic!(
            "A's generation evidence must never join B, got {}",
            row_name(&other)
        ),
    }
}

#[test]
fn terminal_row_ignores_pending_evidence_entirely() {
    // R13-1a: on a terminal row the PENDING read is "not read;
    // non-authoritative" (§6.2 L2170–2172) — even garbage, mis-addressed,
    // or cross-epoch PENDING bytes cannot demote a robust CONFIRMED
    // artifact.
    let mut b = TestBackend::new(7);
    let mut b8 = TestBackend::new(8);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let (tf, _pd) = probe_journal(
        &mut b,
        &art,
        ProbeScript::Clean(QW_CONFIRMED_0),
        ProbeScript::Clean(QW_CONFIRMED_1),
        ProbeScript::Clean([0x42; 16]), // garbage PENDING
    );
    // …and an even more hostile PENDING: wrong address AND wrong epoch.
    let pd = probe_at(&mut b8, 9, 0x0BAD_0000, ProbeScript::Clean([0x00; 16]));
    let pd = pqsigner_rollback::lifecycle::PendingEvidence::for_test(pd, CLEAN, MAY_LAUNCH);
    let gen = Some(full_generation(&mut b, &art, 3, 4));
    match decode_lifecycle(art, gen, &tf, &pd, None, F) {
        LifecycleState::ConfirmedRobust(a) => assert_eq!(a.artifact().t(), GOLDEN_T),
        other => panic!("expected ConfirmedRobust, got {}", row_name(&other)),
    }
}
