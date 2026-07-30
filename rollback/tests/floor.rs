//! FloorView decoder tests: the four classes, classification priority,
//! QW accountancy, T-vs-F classification, and read-only preflight.

mod common;

use common::*;
use fw_manifest::v6::PhysicalSlot;
use pqsigner_rollback::backend::{ProbeScript, ScriptedBackend};
use pqsigner_rollback::floor::*;
use pqsigner_rollback::qw_read::FreshQwRead;

struct Bank {
    b: ScriptedBackend,
    reads: Vec<FreshQwRead>,
    r1: Vec<FreshQwRead>,
}

impl Bank {
    fn new() -> Self {
        Bank {
            b: TestBackend::new(7),
            reads: Vec::new(),
            r1: Vec::new(),
        }
    }

    fn add(&mut self, outcome: ProbeScript) {
        let idx = self.reads.len() as u16;
        self.reads.push(probe(&mut self.b, idx, outcome));
    }

    fn clean(&mut self, bytes: [u8; 16]) {
        self.add(ProbeScript::Clean(bytes));
    }

    fn virgin(&mut self) {
        self.clean(ERASED);
    }

    /// Route both Route-1 markers: exact BASE0 codeword or plain erased.
    fn route1(&mut self, exact: bool) {
        let codeword = if exact {
            ROUTE1_BASE0_CODEWORD
        } else {
            ERASED
        };
        self.r1.push(probe_clean(&mut self.b, 60, codeword));
        self.r1.push(probe_clean(&mut self.b, 61, codeword));
    }

    /// Attribute reads per cell: clean erased reads are scripted as
    /// untouched (NO_LAUNCH → claimable virgin), everything else as
    /// may-have-launched.
    fn cells_auto(&self) -> Vec<FloorCell<'_>> {
        self.reads
            .iter()
            .map(|read| {
                let launch = match read {
                    FreshQwRead::Clean(qw) if qw.is_erased() => NO_LAUNCH,
                    _ => MAY_LAUNCH,
                };
                FloorCell {
                    read,
                    durability: CLEAN,
                    launch,
                }
            })
            .collect()
    }

    fn route1_cells(&self) -> [FloorCell<'_>; 2] {
        [
            FloorCell {
                read: &self.r1[0],
                durability: CLEAN,
                launch: NO_LAUNCH,
            },
            FloorCell {
                read: &self.r1[1],
                durability: CLEAN,
                launch: NO_LAUNCH,
            },
        ]
    }
}

fn binding(slot: PhysicalSlot, e: u32) -> StageBinding {
    StageBinding {
        slot,
        r: GOLDEN_R,
        e,
        manifest_digest: seq(0x99),
    }
}

const FENCE_OK: CompletionLaunchEvidence = CompletionLaunchEvidence::ProvenNoCompletionLaunch;

#[test]
fn steady_from_committed_group() {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(0x0506_0707, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.virgin();
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
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
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
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
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::MissingQuorum { group: 1 }) => {}
        other => panic!("expected MissingQuorum, got {}", view_name(&other)),
    }
}

#[test]
fn canonical_base0_requires_route1_pair_and_blank_bank() {
    // Full BASE0 proof.
    let mut bank = Bank::new();
    for _ in 0..4 {
        bank.virgin();
    }
    bank.route1(true);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
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
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::MissingBaseProof) => {}
        other => panic!("expected MissingBaseProof, got {}", view_name(&other)),
    }
}

#[test]
fn orphan_cell_forces_unknown() {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.clean([0x42; 16]); // clean nonblank, decodes to nothing
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::OrphanQw { .. }) => {}
        other => panic!("expected OrphanQw, got {}", view_name(&other)),
    }
}

#[test]
fn uncertain_cell_outside_stage_forces_unknown() {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.add(ProbeScript::Corrected(ERASED));
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::UncertainQw { .. }) => {}
        other => panic!("expected UncertainQw, got {}", view_name(&other)),
    }
}

#[test]
fn completable_stage_is_recovering() {
    let mut bank = Bank::new();
    // Committed floor F=5.
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    // Active stage g=2, target 6: 2 clean records + 1 corrected + virgins.
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::Corrected(encode_floor_record(6, 2)));
    bank.virgin();
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 7)),
    };
    match decode_floor(&s) {
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
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    // Stage g=2 target 6: 1 clean + 3 uncertain, no virgin cells left.
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 7)),
    };
    match decode_floor(&s) {
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
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(6, 2));
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.add(ProbeScript::AmbiguousOrFault);
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: CompletionLaunchEvidence::MayHaveLaunched,
        stage_binding: Some(binding(PhysicalSlot::A, 7)),
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::CompletionMayHaveLaunched) => {}
        other => panic!("expected CompletionMayHaveLaunched, got {}", view_name(&other)),
    }
}

#[test]
fn conflicting_completion_authority_is_unknown() {
    let mut bank = Bank::new();
    // Group 1 is committed AND has a stage record → conflict.
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.clean(encode_stage_record(1));
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 6)),
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::ConflictingCompletion) => {}
        other => panic!("expected ConflictingCompletion, got {}", view_name(&other)),
    }
}

#[test]
fn two_active_stages_are_unknown() {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.clean(encode_stage_record(2));
    bank.clean(encode_stage_record(3));
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 7)),
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::AmbiguousStage) => {}
        other => panic!("expected AmbiguousStage, got {}", view_name(&other)),
    }
}

#[test]
fn stage_target_not_above_floor_is_unknown() {
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.clean(encode_stage_record(2));
    bank.clean(encode_floor_record(5, 2)); // t == F, not >
    bank.clean(encode_floor_record(5, 2));
    bank.virgin();
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 6)),
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::AmbiguousStage) => {}
        other => panic!("expected AmbiguousStage, got {}", view_name(&other)),
    }
}

#[test]
fn classification_priority_unresolved_stage_outranks_plain_steady() {
    // Committed group 1 + completable stage 2 → Recovering (an unresolved
    // durable stage changes the interpretation; §7.1 L2530).
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.clean(encode_stage_record(2));
    for _ in 0..3 {
        bank.clean(encode_floor_record(6, 2));
    }
    bank.virgin();
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 7)),
    };
    match decode_floor(&s) {
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
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 2)),
    };
    match decode_floor(&s) {
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
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 2)),
    };
    match decode_floor(&s) {
        FloorView::Recovering(p) => assert_eq!(p.target(), 1),
        other => panic!("expected Recovering, got {}", view_name(&other)),
    }
}

#[test]
fn t_classification_and_preflight() {
    assert_eq!(classify_t(5, 4), TClassification::Inconsistent);
    assert_eq!(classify_t(5, 5), TClassification::SameEpoch);
    assert_eq!(classify_t(5, 6), TClassification::EpochBump);

    // Build a real SteadyProof for the preflight.
    let mut bank = Bank::new();
    for _ in 0..3 {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.clean(encode_complete_record(1));
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    let FloorView::Steady(proof) = decode_floor(&s) else {
        panic!("steady")
    };
    // T > F with margin → receipt (comparison data only).
    let receipt = preflight(&proof, 6, 4).expect("receipt");
    assert_eq!((receipt.floor, receipt.target, receipt.group), (5, 6, 2));
    assert_eq!(receipt.margin, 4);
    // T == F / T < F / insufficient margin → no receipt.
    assert!(preflight(&proof, 5, 4).is_none());
    assert!(preflight(&proof, 4, 4).is_none());
    assert!(preflight(&proof, 6, INITIAL_THRESHOLD - 1).is_none());
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
// Accountancy overflow — fail CLOSED, never silently truncate
// ---------------------------------------------------------------------------

#[test]
fn floor_bank_larger_than_max_fails_closed() {
    let mut bank = Bank::new();
    for _ in 0..(MAX_ROLLBACK_CELLS + 1) {
        bank.virgin();
    }
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::RecordOverflow {
            kind: RecordKind::Cell,
            ..
        }) => {}
        other => panic!("expected RecordOverflow(Cell), got {}", view_name(&other)),
    }
}

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
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    let view = decode_floor(&s);
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
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: Some(binding(PhysicalSlot::A, 2)),
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::RecordOverflow {
            kind: RecordKind::Stage,
            ..
        }) => {}
        other => panic!("expected RecordOverflow(Stage), got {}", view_name(&other)),
    }
}

#[test]
fn full_bank_of_floor_records_does_not_overflow() {
    // Boundary: exactly MAX_ROLLBACK_CELLS floor records with no
    // COMPLETE/STAGE — no truncation, no overflow, honest AmbiguousStage
    // (floor records without group structure).
    let mut bank = Bank::new();
    for _ in 0..MAX_ROLLBACK_CELLS {
        bank.clean(encode_floor_record(5, 1));
    }
    bank.route1(false);
    let cells = bank.cells_auto();
    let s = FloorSnapshot {
        cells: &cells,
        route1: bank.route1_cells(),
        completion_fence: FENCE_OK,
        stage_binding: None,
    };
    match decode_floor(&s) {
        FloorView::Unknown(FloorFault::AmbiguousStage) => {}
        other => panic!("expected AmbiguousStage, got {}", view_name(&other)),
    }
}
