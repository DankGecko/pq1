//! FloorView decoder tests: the four classes, classification priority,
//! QW accountancy, canonical map, T-vs-F classification, and preflight.

mod common;

use common::*;
use fw_manifest::v6::PhysicalSlot;
use pqsigner_rollback::backend::ProbeScript;
use pqsigner_rollback::floor::*;

const FENCE_OK: CompletionLaunchEvidence = CompletionLaunchEvidence::ProvenNoCompletionLaunch;

fn steady_bank(t: u32, g: u32) -> Bank {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(t, g));
    }
    bank.clean(encode_complete_record(g));
    bank.route1(false);
    bank
}

#[test]
fn steady_from_committed_group() {
    let mut bank = steady_bank(0x0506_0707, 1);
    bank.route1(false);
    match bank.decode(FENCE_OK, None) {
        FloorView::Steady(p) => {
            assert_eq!(p.floor(), 0x0506_0707);
            assert_eq!(p.group(), GroupIdentity::Group(1));
        }
        _ => panic!("expected Steady"),
    }
}

#[test]
fn steady_degraded_group_down_to_one_witness() {
    let mut bank = Bank::new();
    bank.clean(encode_floor_record(7, 1));
    bank.clean(encode_complete_record(1));
    bank.route1(false);
    match bank.decode(FENCE_OK, None) {
        FloorView::Steady(p) => assert_eq!(p.floor(), 7),
        _ => panic!("degraded threshold 1 must still be Steady"),
    }
}

#[test]
fn complete_with_zero_witnesses_is_unknown_never_lower() {
    let mut bank = Bank::new();
    bank.clean(encode_complete_record(1));
    for _ in 0..3 {
        bank.clean(encode_floor_record(3, 2));
    }
    bank.clean(encode_complete_record(2));
    bank.route1(false);
    match bank.decode(FENCE_OK, None) {
        FloorView::Unknown(FloorFault::MissingQuorum { group: 1 }) => {}
        other => panic!("expected MissingQuorum, got {}", view_name(&other)),
    }
}

#[test]
fn canonical_base0_requires_route1_pair_and_blank_bank() {
    let mut bank = Bank::new();
    for _ in 0..4 {
        bank.virgin();
    }
    bank.route1(true);
    match bank.decode(FENCE_OK, None) {
        FloorView::Steady(p) => {
            assert_eq!(p.floor(), 0);
            assert_eq!(p.group(), GroupIdentity::Base0);
        }
        other => panic!("expected Steady(0, Base0), got {}", view_name(&other)),
    }

    // Erased-looking Route-1 pages never prove the base.
    let mut bank = Bank::new();
    for _ in 0..4 {
        bank.virgin();
    }
    bank.route1(false);
    match bank.decode(FENCE_OK, None) {
        FloorView::Unknown(FloorFault::MissingBaseProof) => {}
        other => panic!("expected MissingBaseProof, got {}", view_name(&other)),
    }
}

#[test]
fn orphan_cell_forces_unknown() {
    let mut bank = steady_bank(5, 1);
    bank.clean([0x42; 16]); // clean nonblank, decodes to nothing
    match bank.decode(FENCE_OK, None) {
        FloorView::Unknown(FloorFault::OrphanQw { .. }) => {}
        other => panic!("expected OrphanQw, got {}", view_name(&other)),
    }
}

#[test]
fn uncertain_cell_outside_stage_forces_unknown() {
    let mut bank = steady_bank(5, 1);
    bank.add(ProbeScript::Corrected(ERASED));
    match bank.decode(FENCE_OK, None) {
        FloorView::Unknown(FloorFault::UncertainQw { .. }) => {}
        other => panic!("expected UncertainQw, got {}", view_name(&other)),
    }
}

#[test]
fn completable_stage_is_recovering() {
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::Corrected(encode_floor_record(6, 2)));
    bank.virgin();
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7))) {
        FloorView::Recovering(p) => {
            assert_eq!(p.target(), 6);
            assert_eq!(p.group(), 2);
            assert_eq!(p.clean_records(), 2);
        }
        other => panic!("expected Recovering, got {}", view_name(&other)),
    }
}

#[test]
fn dead_stage_with_no_completion_launch_is_aborted() {
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7))) {
        FloorView::Aborted(p) => {
            assert_eq!(p.floor(), 5);
            assert_eq!(p.failed_target(), 6);
            assert_eq!(p.failed_group(), 2);
        }
        other => panic!("expected Aborted, got {}", view_name(&other)),
    }
}

#[test]
fn dead_stage_with_possible_completion_is_unknown() {
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.route1(false);
    match bank.decode(
        CompletionLaunchEvidence::MayHaveLaunched,
        Some(binding(PhysicalSlot::A, 7)),
    ) {
        FloorView::Unknown(FloorFault::CompletionMayHaveLaunched) => {}
        other => panic!("expected CompletionMayHaveLaunched, got {}", view_name(&other)),
    }
}

#[test]
fn conflicting_completion_authority_is_unknown() {
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(1));
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 6))) {
        FloorView::Unknown(FloorFault::ConflictingCompletion) => {}
        other => panic!("expected ConflictingCompletion, got {}", view_name(&other)),
    }
}

#[test]
fn two_active_stages_are_unknown() {
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_stage_record(3));
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7))) {
        FloorView::Unknown(FloorFault::AmbiguousStage) => {}
        other => panic!("expected AmbiguousStage, got {}", view_name(&other)),
    }
}

#[test]
fn stage_target_not_above_floor_is_unknown() {
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(5, 2));
    bank.clean(encode_floor_record(5, 2));
    bank.virgin();
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 6))) {
        FloorView::Unknown(FloorFault::AmbiguousStage) => {}
        other => panic!("expected AmbiguousStage, got {}", view_name(&other)),
    }
}

#[test]
fn classification_priority_unresolved_stage_outranks_plain_steady() {
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    for _ in 0..3 {
        bank.clean(encode_floor_record(6, 2));
    }
    bank.virgin();
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7))) {
        FloorView::Recovering(_) => {}
        other => panic!("expected Recovering, got {}", view_name(&other)),
    }
}

#[test]
fn first_bump_stage_requires_base0_proof() {
    // Missing Route-1 BASE0 markers → Unknown.
    let mut bank = Bank::new();
    bank.clean(encode_stage_record(1));
    for _ in 0..3 {
        bank.clean(encode_floor_record(1, 1));
    }
    bank.virgin();
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 2))) {
        FloorView::Unknown(FloorFault::MissingBaseProof) => {}
        other => panic!("expected MissingBaseProof, got {}", view_name(&other)),
    }

    // With the canonical pair → Recovering toward target 1.
    let mut bank = Bank::new();
    bank.clean(encode_stage_record(1));
    for _ in 0..3 {
        bank.clean(encode_floor_record(1, 1));
    }
    bank.virgin();
    bank.route1(true);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 2))) {
        FloorView::Recovering(p) => assert_eq!(p.target(), 1),
        other => panic!("expected Recovering, got {}", view_name(&other)),
    }
}

#[test]
fn t_classification_and_preflight() {
    assert_eq!(classify_t(5, 4), TClassification::Inconsistent);
    assert_eq!(classify_t(5, 5), TClassification::SameEpoch);
    assert_eq!(classify_t(5, 6), TClassification::EpochBump);

    let mut bank = steady_bank(5, 1);
    let FloorView::Steady(proof) = bank.decode(FENCE_OK, None) else {
        panic!("steady")
    };
    let receipt = preflight(&proof, 6, 4).expect("receipt");
    assert_eq!((receipt.floor(), receipt.target(), receipt.group()), (5, 6, 2));
    assert_eq!(receipt.margin(), 4);
    assert!(preflight(&proof, 5, 4).is_none());
    assert!(preflight(&proof, 4, 4).is_none());
    assert!(preflight(&proof, 6, INITIAL_THRESHOLD - 1).is_none());
}

// ---------------------------------------------------------------------------
// Accountancy overflow — fail CLOSED, never silently truncate
// ---------------------------------------------------------------------------

#[test]
fn floor_record_overflow_never_admits_a_lower_floor() {
    // The reproduced PoC: nine COMPLETE records where the 9th carries
    // group 9 with t=7 while earlier groups top out at t=5. The old
    // truncating accountancy returned Steady(5) — a two-epoch rollback.
    // It must now fail CLOSED, and it must NOT return Steady(5).
    let mut bank = Bank::new();
    for g in 1..=8u32 {
        bank.clean(encode_floor_record(5, g));
        bank.clean(encode_floor_record(5, g));
        bank.clean(encode_complete_record(g));
    }
    bank.clean(encode_floor_record(7, 9));
    bank.clean(encode_floor_record(7, 9));
    bank.clean(encode_complete_record(9)); // the 9th COMPLETE
    bank.route1(false);
    let view = bank.decode(FENCE_OK, None);
    if let FloorView::Steady(p) = &view {
        panic!("BLOCKER PoC admitted a truncated floor: Steady({})", p.floor());
    }
    match view {
        FloorView::Unknown(FloorFault::RecordOverflow {
            kind: RecordKind::Complete,
            index,
        }) => {
            assert_eq!(index as usize, 26, "the 9th COMPLETE is the overflow");
        }
        other => panic!("expected RecordOverflow(Complete), got {}", view_name(&other)),
    }
}

#[test]
fn stage_record_overflow_fails_closed() {
    let mut bank = Bank::new();
    for g in 1..=9u32 {
        bank.clean(encode_stage_record(g));
    }
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 2))) {
        FloorView::Unknown(FloorFault::RecordOverflow {
            kind: RecordKind::Stage,
            ..
        }) => {}
        other => panic!("expected RecordOverflow(Stage), got {}", view_name(&other)),
    }
}

#[test]
fn full_bank_of_floor_records_does_not_overflow() {
    // Boundary: exactly RESERVED_ROLLBACK_QWS floor records with no
    // COMPLETE/STAGE — no truncation, no overflow, honest AmbiguousStage
    // (floor records without group structure).
    let mut bank = Bank::new();
    for _ in 0..RESERVED_ROLLBACK_QWS {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.route1(false);
    match bank.decode(FENCE_OK, None) {
        FloorView::Unknown(FloorFault::AmbiguousStage) => {}
        other => panic!("expected AmbiguousStage, got {}", view_name(&other)),
    }
}

// ---------------------------------------------------------------------------
// Exact-cardinality full scan (R3-1)
// ---------------------------------------------------------------------------

#[test]
fn empty_map_with_exact_route1_is_not_steady_zero() {
    // R3-1: cells=[] + exact Route-1 markers previously yielded
    // Steady(0). With the exact-cardinality rule it is IncompleteMap.
    let mut bank = Bank::new();
    bank.route1(true);
    let mut snap = bank.snapshot(FENCE_OK, None);
    for slot in snap.cells.iter_mut() {
        *slot = None;
    }
    let view = decode_floor(&snap);
    if let FloorView::Steady(_) = &view {
        panic!("an empty cell map must never yield Steady(0)");
    }
    match view {
        FloorView::Unknown(FloorFault::IncompleteMap { expected, got }) => {
            assert_eq!((expected, got), (RESERVED_ROLLBACK_QWS, 0));
        }
        other => panic!("expected IncompleteMap, got {}", view_name(&other)),
    }
}

#[test]
fn prefix_snapshot_omitting_newer_complete_is_incomplete() {
    // R3-1: a prefix snapshot omitting the newer records (would lower
    // the floor) is rejected as incomplete.
    let mut bank = steady_bank(5, 1);
    let mut snap = bank.snapshot(FENCE_OK, None);
    // Keep only a prefix of the cells.
    for slot in snap.cells.iter_mut().skip(2) {
        *slot = None;
    }
    match decode_floor(&snap) {
        FloorView::Unknown(FloorFault::IncompleteMap { expected, got }) => {
            assert_eq!((expected, got), (RESERVED_ROLLBACK_QWS, 2));
        }
        other => panic!("expected IncompleteMap, got {}", view_name(&other)),
    }
}

// ---------------------------------------------------------------------------
// Canonical physical map (R2-2: no aliasing, no misaddressing, one pass)
// ---------------------------------------------------------------------------

#[test]
fn duplicate_clean_index_is_unknown() {
    // One physical QW presented at two positions must never fill two
    // roles.
    let mut bank = steady_bank(5, 1);
    let mut snap = bank.snapshot(FENCE_OK, None);
    let dup = probe_clean(&mut bank.b, 0, encode_floor_record(5, 1));
    snap.cells[1] = Some(FloorCell {
        read: dup,
        durability: CLEAN,
        launch: MAY_LAUNCH,
    });
    match decode_floor(&snap) {
        FloorView::Unknown(FloorFault::NonCanonicalMap(MapFault::DuplicateIndex { index: 0 })) => {}
        other => panic!("expected DuplicateIndex, got {}", view_name(&other)),
    }
}

#[test]
fn index_address_mismatch_is_unknown() {
    // A CleanQw bound to a non-canonical address for its index must
    // never be reinterpreted at that index.
    let mut bank = steady_bank(5, 1);
    let mut snap = bank.snapshot(FENCE_OK, None);
    let wrong_addr = canonical_cell_addr(0) + 16;
    let read = probe_at(&mut bank.b, 0, wrong_addr, ProbeScript::Clean(encode_floor_record(5, 1)));
    snap.cells[0] = Some(FloorCell {
        read,
        durability: CLEAN,
        launch: MAY_LAUNCH,
    });
    match decode_floor(&snap) {
        FloorView::Unknown(FloorFault::NonCanonicalMap(MapFault::AddressMismatch {
            index: 0,
        })) => {}
        other => panic!("expected AddressMismatch, got {}", view_name(&other)),
    }
}

#[test]
fn probe_epoch_inconsistency_is_unknown() {
    // Cells probed under two different epochs (two passes) can never
    // join one decode.
    let mut bank = steady_bank(5, 1);
    let mut snap = bank.snapshot(FENCE_OK, None);
    let mut other = TestBackend::new(8);
    let read = probe_clean(&mut other, 0, encode_floor_record(5, 1));
    snap.cells[0] = Some(FloorCell {
        read,
        durability: CLEAN,
        launch: MAY_LAUNCH,
    });
    match decode_floor(&snap) {
        FloorView::Unknown(FloorFault::NonCanonicalMap(MapFault::InconsistentProbeEpoch)) => {}
        other => panic!("expected InconsistentProbeEpoch, got {}", view_name(&other)),
    }
}

#[test]
fn route1_pair_must_be_two_distinct_qws() {
    // Both Route-1 reads pointing at the SAME physical QW: never BASE0.
    let mut bank = Bank::new();
    for _ in 0..4 {
        bank.virgin();
    }
    bank.route1(true);
    let mut snap = bank.snapshot(FENCE_OK, None);
    let dup = probe_at(
        &mut bank.b,
        60,
        canonical_route1_addr(0),
        ProbeScript::Clean(ROUTE1_BASE0_CODEWORD),
    );
    snap.route1[1] = FloorCell {
        read: dup,
        durability: CLEAN,
        launch: NO_LAUNCH,
    };
    let view = decode_floor(&snap);
    if let FloorView::Steady(_) = &view {
        panic!("a non-disjoint Route-1 pair must never yield Steady(0)");
    }
    assert!(matches!(view, FloorView::Unknown(_)), "expected Unknown");
}

// ---------------------------------------------------------------------------
// Route-1 accountancy (R3-6)
// ---------------------------------------------------------------------------

#[test]
fn garbage_route1_with_committed_group_is_unknown() {
    // R3-6: a Clean+DurableClean garbage Route-1 page (non-BASE0,
    // nonblank) is outside the authenticated map → Unknown, never
    // Steady(5).
    let mut bank = steady_bank(5, 1);
    let mut snap = bank.snapshot(FENCE_OK, None);
    let garbage = probe_at(
        &mut bank.b,
        61,
        canonical_route1_addr(1),
        ProbeScript::Clean([0x42; 16]),
    );
    snap.route1[1] = FloorCell {
        read: garbage,
        durability: CLEAN,
        launch: MAY_LAUNCH,
    };
    let view = decode_floor(&snap);
    if let FloorView::Steady(_) = &view {
        panic!("garbage Route-1 must never yield Steady");
    }
    match view {
        FloorView::Unknown(FloorFault::OrphanQw { .. }) => {}
        other => panic!("expected OrphanQw, got {}", view_name(&other)),
    }
}

// ---------------------------------------------------------------------------
// Orphan roles (R2-5)
// ---------------------------------------------------------------------------

#[test]
fn orphan_role_in_committed_steady_arm_is_unknown() {
    // R2-5 PoC: floor(g1,t5)+complete(g1) plus floor(g2,t9) with g2's
    // stage/complete cells proven virgin → Unknown, never Steady(5).
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_floor_record(9, 2)); // orphan: no stage, no complete
    bank.virgin();
    bank.route1(false);
    let view = bank.decode(FENCE_OK, None);
    if let FloorView::Steady(p) = &view {
        panic!("orphan role admitted as Steady({})", p.floor());
    }
    match view {
        FloorView::Unknown(FloorFault::AmbiguousStage) => {}
        other => panic!("expected AmbiguousStage, got {}", view_name(&other)),
    }
}

// ---------------------------------------------------------------------------
// Preflight allocation overflow (R3-8)
// ---------------------------------------------------------------------------

#[test]
fn preflight_group_overflow_fail_closed() {
    let mut bank = steady_bank(5, u32::MAX);
    let FloorView::Steady(proof) = bank.decode(FENCE_OK, None) else {
        panic!("steady")
    };
    // g == u32::MAX: the allocation sequence cannot advance — fail
    // closed, no panic, no wrap.
    assert!(preflight(&proof, 6, 4).is_none());
}

fn view_name(v: &FloorView) -> &'static str {
    match v {
        FloorView::Steady(_) => "Steady",
        FloorView::Recovering(_) => "Recovering",
        FloorView::Aborted(_) => "Aborted",
        FloorView::Unknown(_) => "Unknown",
    }
}
