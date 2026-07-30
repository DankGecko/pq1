//! FloorView decoder tests: the four classes, classification priority,
//! QW accountancy, canonical map, T-vs-F classification, and preflight.

mod common;

use common::*;
use fw_manifest::v6::PhysicalSlot;
use pqsigner_rollback::backend::ProbeScript;
use pqsigner_rollback::floor::*;

const FENCE_OK: CompletionLaunchEvidence = CompletionLaunchEvidence::ProvenNoCompletionLaunch;

/// Role plans matching the scripted banks below (indices are the
/// bank-cell positions).
const COMPLETABLE_ROLES: [(u16, PlanRole); 4] = [
    (5, PlanRole::Witness),
    (6, PlanRole::Witness),
    (7, PlanRole::Consumed),
    (8, PlanRole::Reserved),
];
const DEAD_ROLES: [(u16, PlanRole); 4] = [
    (5, PlanRole::Witness),
    (6, PlanRole::Consumed),
    (7, PlanRole::Consumed),
    (8, PlanRole::Consumed),
];
const RECOVERING_ROLES: [(u16, PlanRole); 4] = [
    (5, PlanRole::Witness),
    (6, PlanRole::Witness),
    (7, PlanRole::Witness),
    (8, PlanRole::Reserved),
];
const FIRST_BUMP_ROLES: [(u16, PlanRole); 4] = [
    (1, PlanRole::Witness),
    (2, PlanRole::Witness),
    (3, PlanRole::Witness),
    (4, PlanRole::Reserved),
];

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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, COMPLETABLE_ROLES))) {
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, DEAD_ROLES))) {
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
        Some(binding(PhysicalSlot::A, 7, DEAD_ROLES)),
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 6, RECOVERING_ROLES))) {
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, RECOVERING_ROLES))) {
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 6, RECOVERING_ROLES))) {
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, RECOVERING_ROLES))) {
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 2, FIRST_BUMP_ROLES))) {
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 2, FIRST_BUMP_ROLES))) {
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
    let receipt = preflight(&proof, 6).expect("receipt");
    assert_eq!((receipt.floor(), receipt.target(), receipt.group()), (5, 6, 2));
    // Proof-bound margin: 28 canonical virgins remain after the
    // committed group's four role cells.
    assert_eq!(receipt.margin(), 28);
    assert_eq!(proof.virgin_cells(), 28);
    assert!(preflight(&proof, 5).is_none());
    assert!(preflight(&proof, 4).is_none());
}

#[test]
fn preflight_margin_is_proof_bound_not_caller_asserted() {
    // A receipt preflighted from a bank with 27 virgins (five role
    // cells) must not validate against a proof with 28 — the margin is
    // bound to the decoding, not to any caller-supplied number.
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_floor_record(5, 1));
    let FloorView::Steady(proof_27) = bank.decode(FENCE_OK, None) else {
        panic!("steady")
    };
    assert_eq!(proof_27.virgin_cells(), 27);
    let receipt = preflight(&proof_27, 6).expect("receipt");
    assert_eq!(receipt.margin(), 27);
    let mut bank = steady_bank(5, 1);
    let FloorView::Steady(proof_28) = bank.decode(FENCE_OK, None) else {
        panic!("steady")
    };
    assert_eq!(proof_28.virgin_cells(), 28);
    assert_ne!(
        receipt.snapshot_digest(),
        proof_28.snapshot_digest(),
        "different virgin counts change the snapshot"
    );
    assert!(!receipt_matches_for_test(&proof_28, &receipt));

    // Capacity is proof-bound: a full bank of role cells (zero virgins)
    // yields no receipt at all.
    let mut full = Bank::new();
    for _ in 0..(RESERVED_ROLLBACK_QWS - 1) {
        full.clean(encode_floor_record(5, 1));
    }
    full.clean(encode_complete_record(1));
    full.route1(false);
    let FloorView::Steady(full_proof) = full.decode(FENCE_OK, None) else {
        panic!("steady")
    };
    assert_eq!(full_proof.virgin_cells(), 0);
    assert!(preflight(&full_proof, 6).is_none());
}

/// Mirror of the crate-private revalidation rule (floor/target/digest/
/// group/proof-bound margin) for direct margin testing.
fn receipt_matches_for_test(
    steady: &pqsigner_rollback::floor::SteadyProof,
    receipt: &pqsigner_rollback::floor::EpochBumpReceipt,
) -> bool {
    let expected_group = match steady.group() {
        GroupIdentity::Base0 => Some(1),
        GroupIdentity::Group(g) => g.checked_add(1),
    };
    receipt.floor() == steady.floor()
        && receipt.target() == steady.floor() + 1
        && receipt.snapshot_digest() == steady.snapshot_digest()
        && Some(receipt.group()) == expected_group
        && receipt.margin() == steady.virgin_cells()
        && receipt.margin() >= INITIAL_THRESHOLD
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
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 2, FIRST_BUMP_ROLES))) {
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
    for slot in snap.cells_mut().iter_mut() {
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
    for slot in snap.cells_mut().iter_mut().skip(2) {
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
    snap.cells_mut()[1] = Some(FloorCell {
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
    snap.cells_mut()[0] = Some(FloorCell {
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
    snap.cells_mut()[0] = Some(FloorCell {
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
    snap.route1_mut()[1] = FloorCell {
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
    snap.route1_mut()[1] = FloorCell {
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
    assert!(preflight(&proof, 6).is_none());
}

fn view_name(v: &FloorView) -> &'static str {
    match v {
        FloorView::Steady(_) => "Steady",
        FloorView::Recovering(_) => "Recovering",
        FloorView::Aborted(_) => "Aborted",
        FloorView::Unknown(_) => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Role-map accountancy (R5-3): no implicit absorption
// ---------------------------------------------------------------------------

#[test]
fn uncertain_qw_outside_role_map_is_unknown() {
    // The corrected plan cell is NOT in the binding's role map → the
    // decode must NOT silently absorb it into the plan.
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::Corrected(encode_floor_record(6, 2)));
    bank.virgin();
    bank.route1(false);
    // Role map names only the two witnesses + two reserved virgins;
    // the corrected cell (index 7) is unmapped.
    let roles = [
        (5, PlanRole::Witness),
        (6, PlanRole::Witness),
        (8, PlanRole::Reserved),
        (9, PlanRole::Reserved),
    ];
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, roles))) {
        FloorView::Unknown(FloorFault::UnmappedRole { index: 7 }) => {}
        other => panic!("expected UnmappedRole, got {}", view_name(&other)),
    }
}

#[test]
fn torn_newer_group_cell_is_not_absorbed_into_old_plan() {
    // A torn COMPLETE of a NEWER group (index 7, uncertain) presented
    // alongside an older stage's plan must not be absorbed as an
    // old-plan cell: UnmappedRole → Unknown.
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::Corrected(encode_complete_record(9))); // torn newer-group COMPLETE
    bank.virgin();
    bank.route1(false);
    let roles = [
        (5, PlanRole::Witness),
        (6, PlanRole::Witness),
        (8, PlanRole::Reserved),
        (9, PlanRole::Reserved),
    ];
    let view = bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, roles)));
    match view {
        FloorView::Unknown(FloorFault::UnmappedRole { index: 7 }) => {}
        other => panic!(
            "a torn newer-group cell must never be absorbed into an older plan, got {}",
            view_name(&other)
        ),
    }
}

#[test]
fn uncertain_qw_inside_role_map_still_recovers() {
    // Same bank, but the role map names the corrected cell as Consumed:
    // the plan is completable → Recovering.
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::Corrected(encode_floor_record(6, 2)));
    bank.virgin();
    bank.route1(false);
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, COMPLETABLE_ROLES))) {
        FloorView::Recovering(p) => {
            assert_eq!(p.target(), 6);
            assert_eq!(p.clean_records(), 2);
        }
        other => panic!("expected Recovering, got {}", view_name(&other)),
    }
}

#[test]
fn plan_cell_not_matching_physical_reality_is_unknown() {
    // The role map claims a Reserved cell at index 8, but the bank has
    // a clean floor record there for the stage: plan/physical mismatch.
    let mut bank = steady_bank(5, 1);
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.clean(encode_floor_record(6, 2));
    bank.clean(encode_floor_record(6, 2)); // index 7
    bank.clean(encode_floor_record(6, 2)); // index 8
    bank.route1(false);
    let roles = [
        (5, PlanRole::Witness),
        (6, PlanRole::Witness),
        (7, PlanRole::Witness),
        (8, PlanRole::Reserved),
    ];
    match bank.decode(FENCE_OK, Some(binding(PhysicalSlot::A, 7, roles))) {
        FloorView::Unknown(FloorFault::UnmappedRole { index: 8 }) => {}
        other => panic!("expected UnmappedRole, got {}", view_name(&other)),
    }
}
