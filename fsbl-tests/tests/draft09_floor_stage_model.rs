//! Nonshipping host model for Draft 0.9's frozen typed floor boundary.
//!
//! This deliberately does not implement an OTP codec, durable-stage storage,
//! ECC attribution, or an FSBL writer.  It exercises only the backend-neutral
//! `Steady / Recovering / Unknown` admission classes and the launch partition
//! frozen in Sections 7 and 10.  No production crate depends on this model.

#![forbid(unsafe_code)]

const MAX_RELEASE_OR_EPOCH: u32 = 0xffff_fffe;
const MAX_TARGET: u32 = 0xffff_fffd;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReleaseVersion(u32);

impl ReleaseVersion {
    fn checked(value: u32) -> Option<Self> {
        (1..=MAX_RELEASE_OR_EPOCH)
            .contains(&value)
            .then_some(Self(value))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SecurityEpoch(u32);

impl SecurityEpoch {
    fn checked(value: u32) -> Option<Self> {
        (1..=MAX_RELEASE_OR_EPOCH)
            .contains(&value)
            .then_some(Self(value))
    }

    fn target(self) -> Target {
        let value = self.0.checked_sub(1).expect("validated epoch is nonzero");
        assert!(value <= MAX_TARGET);
        Target(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Floor(u32);

impl Floor {
    fn checked(value: u32) -> Option<Self> {
        (value <= MAX_TARGET).then_some(Self(value))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CandidateBinding {
    release: ReleaseVersion,
    epoch: SecurityEpoch,
    manifest_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SteadyProof {
    floor: Floor,
    allocation_generation: u32,
    state_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecoveryProof {
    prior: SteadyProof,
    target: Target,
    allocation_generation: u32,
    candidate: CandidateBinding,
}

impl RecoveryProof {
    fn is_self_consistent(self) -> bool {
        self.target.0 > self.prior.floor.0
            && self.candidate.epoch.target() == self.target
            && self.allocation_generation > self.prior.allocation_generation
    }
}

/// Abstract proof that an independently verified CONFIRMED fallback binds the
/// current floor.  This model does not construct it from untrusted slot bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConfirmedFallbackProof {
    candidate: CandidateBinding,
    target: Target,
}

impl ConfirmedFallbackProof {
    fn binds(self, floor: Floor) -> bool {
        self.target == Target(floor.0) && self.candidate.epoch.target() == self.target
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FloorView {
    Steady(SteadyProof),
    Recovering(RecoveryProof),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetClass {
    Inconsistent,
    SameEpoch,
    EpochBump,
}

fn classify_target(floor: Floor, target: Target) -> TargetClass {
    use core::cmp::Ordering::{Equal, Greater, Less};
    match target.0.cmp(&floor.0) {
        Less => TargetClass::Inconsistent,
        Equal => TargetClass::SameEpoch,
        Greater => TargetClass::EpochBump,
    }
}

fn epoch_is_admissible(epoch: SecurityEpoch, floor: Floor) -> bool {
    epoch.0 > floor.0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EstablishResult {
    Handoff,
    ProvenNoLaunchFallback,
    Recovering,
    Halt,
}

/// Instrumented abstract backend.  Its scripted state changes stand in for a
/// candidate durable-stage design; counters make the frozen launch partition
/// observable without selecting that design.
#[derive(Clone, Copy, Debug)]
struct FakeBackend {
    view: FloorView,
    after_begin: FloorView,
    after_resume: FloorView,
    fresh_scan_override: Option<FloorView>,
    begin_generation: u32,
    preflight_succeeds: bool,
    preflight_calls: u32,
    begin_calls: u32,
    resume_calls: u32,
    fresh_scan_calls: u32,
    persistent_write_calls: u32,
}

impl FakeBackend {
    fn new(view: FloorView) -> Self {
        Self {
            view,
            after_begin: view,
            after_resume: view,
            fresh_scan_override: None,
            begin_generation: 7,
            preflight_succeeds: true,
            preflight_calls: 0,
            begin_calls: 0,
            resume_calls: 0,
            fresh_scan_calls: 0,
            persistent_write_calls: 0,
        }
    }

    fn preflight(&mut self) -> bool {
        self.preflight_calls += 1;
        self.preflight_succeeds
    }

    fn begin(&mut self) {
        self.begin_calls += 1;
        self.persistent_write_calls += 1;
        self.view = self.after_begin;
    }

    fn resume(&mut self) {
        self.resume_calls += 1;
        self.persistent_write_calls += 1;
        self.view = self.after_resume;
    }

    fn fresh_full_decode(&mut self) -> FloorView {
        self.fresh_scan_calls += 1;
        if let Some(view) = self.fresh_scan_override.take() {
            self.view = view;
        }
        self.view
    }
}

fn finish_from_fresh_view(
    view: FloorView,
    target: Target,
    expected_recovery: Option<RecoveryProof>,
) -> EstablishResult {
    match view {
        FloorView::Steady(proof) if proof.floor.0 == target.0 => EstablishResult::Handoff,
        FloorView::Recovering(proof)
            if proof.is_self_consistent() && Some(proof) == expected_recovery =>
        {
            EstablishResult::Recovering
        }
        FloorView::Steady(_) | FloorView::Recovering(_) | FloorView::Unknown => {
            EstablishResult::Halt
        }
    }
}

/// Model `start_from_steady(CheckedSteadyIntent)`.
fn start_from_steady(
    backend: &mut FakeBackend,
    candidate: CandidateBinding,
    fallback: Option<ConfirmedFallbackProof>,
) -> EstablishResult {
    let FloorView::Steady(steady) = backend.view else {
        return EstablishResult::Halt;
    };
    let floor = steady.floor;
    let target = candidate.epoch.target();

    match classify_target(floor, target) {
        TargetClass::Inconsistent => EstablishResult::Halt,
        TargetClass::SameEpoch => {
            // No preflight, durable stage, claim, compaction, OTP unlock, or
            // program operation exists on this branch.  Handoff still
            // requires a new full typed decode; the entry snapshot is not
            // reused as authority.
            let fresh = backend.fresh_full_decode();
            finish_from_fresh_view(fresh, target, None)
        }
        TargetClass::EpochBump => {
            if !backend.preflight() {
                // This is the sole proven-no-launch fallback window.  The
                // independently verified fallback must already bind F, and
                // a new full decode must reproduce the exact entry proof.
                // The entry snapshot alone is never reused as authority.
                let fresh = backend.fresh_full_decode();
                return if fresh == FloorView::Steady(steady)
                    && backend.begin_calls == 0
                    && backend.persistent_write_calls == 0
                    && fallback.is_some_and(|proof| proof.binds(floor))
                {
                    EstablishResult::ProvenNoLaunchFallback
                } else {
                    EstablishResult::Halt
                };
            }

            backend.begin();
            // `begin` never returns handoff authority directly.  Only a new
            // typed scan can return Steady(target).
            let expected_recovery = RecoveryProof {
                prior: steady,
                target,
                allocation_generation: backend.begin_generation,
                candidate,
            };
            let fresh = backend.fresh_full_decode();
            finish_from_fresh_view(fresh, target, Some(expected_recovery))
        }
    }
}

/// Model `resume_from_recovery(RecoveryProof)`.
fn resume_from_recovery(backend: &mut FakeBackend, supplied: RecoveryProof) -> EstablishResult {
    let FloorView::Recovering(current) = backend.view else {
        return EstablishResult::Halt;
    };
    if current != supplied || !current.is_self_consistent() {
        return EstablishResult::Halt;
    }
    backend.resume();
    let fresh = backend.fresh_full_decode();
    finish_from_fresh_view(fresh, supplied.target, Some(supplied))
}

fn binding(epoch: u32) -> CandidateBinding {
    CandidateBinding {
        release: ReleaseVersion::checked(epoch + 10).unwrap(),
        epoch: SecurityEpoch::checked(epoch).unwrap(),
        manifest_digest: [epoch as u8; 32],
    }
}

fn steady(floor: u32) -> SteadyProof {
    SteadyProof {
        floor: Floor::checked(floor).unwrap(),
        allocation_generation: floor + 1,
        state_digest: [floor as u8; 32],
    }
}

fn recovery(prior: u32, target: u32) -> RecoveryProof {
    RecoveryProof {
        prior: steady(prior),
        target: Target(target),
        allocation_generation: 7,
        candidate: binding(target + 1),
    }
}

fn fallback(epoch: u32) -> ConfirmedFallbackProof {
    ConfirmedFallbackProof {
        candidate: binding(epoch),
        target: SecurityEpoch::checked(epoch).unwrap().target(),
    }
}

#[test]
fn ranges_and_exclusive_floor_arithmetic_are_exact() {
    assert!(ReleaseVersion::checked(0).is_none());
    assert!(SecurityEpoch::checked(0).is_none());
    assert_eq!(SecurityEpoch::checked(1).unwrap().target(), Target(0));
    assert_eq!(
        SecurityEpoch::checked(MAX_RELEASE_OR_EPOCH)
            .unwrap()
            .target(),
        Target(MAX_TARGET)
    );
    assert!(SecurityEpoch::checked(u32::MAX).is_none());
    assert!(Floor::checked(MAX_TARGET).is_some());
    assert!(Floor::checked(MAX_TARGET + 1).is_none());

    for epoch in [1, 2, 3, 0x0102_0304, MAX_RELEASE_OR_EPOCH] {
        let epoch = SecurityEpoch::checked(epoch).unwrap();
        let target = epoch.target();
        assert!(epoch_is_admissible(epoch, Floor(target.0)));
        assert_eq!(epoch.0, target.0 + 1);
    }
}

#[test]
fn target_classification_covers_below_equal_and_above() {
    let floor = Floor(9);
    assert_eq!(classify_target(floor, Target(8)), TargetClass::Inconsistent);
    assert_eq!(classify_target(floor, Target(9)), TargetClass::SameEpoch);
    assert_eq!(classify_target(floor, Target(10)), TargetClass::EpochBump);
}

#[test]
fn same_epoch_performs_zero_preflight_begin_resume_or_persistent_write() {
    for exhausted_capacity in [false, true] {
        let mut backend = FakeBackend::new(FloorView::Steady(steady(4)));
        backend.preflight_succeeds = !exhausted_capacity;
        let result = start_from_steady(&mut backend, binding(5), None);
        assert_eq!(result, EstablishResult::Handoff);
        assert_eq!(backend.preflight_calls, 0);
        assert_eq!(backend.begin_calls, 0);
        assert_eq!(backend.resume_calls, 0);
        assert_eq!(backend.fresh_scan_calls, 1);
        assert_eq!(backend.persistent_write_calls, 0);
    }
}

#[test]
fn same_epoch_handoff_requires_a_new_full_steady_target_decode() {
    for fresh in [
        FloorView::Steady(steady(3)),
        FloorView::Recovering(recovery(4, 5)),
        FloorView::Unknown,
    ] {
        let mut backend = FakeBackend::new(FloorView::Steady(steady(4)));
        backend.fresh_scan_override = Some(fresh);
        assert_eq!(
            start_from_steady(&mut backend, binding(5), None),
            EstablishResult::Halt
        );
        assert_eq!(backend.fresh_scan_calls, 1);
        assert_eq!(backend.preflight_calls, 0);
        assert_eq!(backend.begin_calls, 0);
        assert_eq!(backend.persistent_write_calls, 0);
    }
}

#[test]
fn inconsistent_target_halts_without_touching_backend() {
    let mut backend = FakeBackend::new(FloorView::Steady(steady(9)));
    let result = start_from_steady(&mut backend, binding(9), None);
    assert_eq!(result, EstablishResult::Halt);
    assert_eq!(backend.preflight_calls, 0);
    assert_eq!(backend.begin_calls, 0);
    assert_eq!(backend.fresh_scan_calls, 0);
    assert_eq!(backend.persistent_write_calls, 0);
}

#[test]
fn preflight_failure_allows_only_exact_floor_fallback_before_launch() {
    for fallback_proof in [
        None,
        Some(fallback(3)),
        Some(fallback(4)),
        Some(fallback(5)),
    ] {
        let mut backend = FakeBackend::new(FloorView::Steady(steady(3)));
        backend.preflight_succeeds = false;
        let result = start_from_steady(&mut backend, binding(5), fallback_proof);
        let expected = if fallback_proof == Some(fallback(4)) {
            EstablishResult::ProvenNoLaunchFallback
        } else {
            EstablishResult::Halt
        };
        assert_eq!(result, expected);
        assert_eq!(backend.preflight_calls, 1);
        assert_eq!(backend.begin_calls, 0);
        assert_eq!(backend.fresh_scan_calls, 1);
        assert_eq!(backend.persistent_write_calls, 0);
    }
}

#[test]
fn preflight_failure_rejects_any_changed_or_unusable_fresh_floor_view() {
    let mut same_floor_different_generation = steady(3);
    same_floor_different_generation.allocation_generation += 1;
    let mut same_floor_different_digest = steady(3);
    same_floor_different_digest.state_digest[0] ^= 1;

    for fresh in [
        FloorView::Steady(steady(2)),
        FloorView::Steady(steady(4)),
        FloorView::Steady(same_floor_different_generation),
        FloorView::Steady(same_floor_different_digest),
        FloorView::Recovering(recovery(3, 4)),
        FloorView::Unknown,
    ] {
        let mut backend = FakeBackend::new(FloorView::Steady(steady(3)));
        backend.preflight_succeeds = false;
        backend.fresh_scan_override = Some(fresh);
        assert_eq!(
            start_from_steady(&mut backend, binding(5), Some(fallback(4))),
            EstablishResult::Halt
        );
        assert_eq!(backend.preflight_calls, 1);
        assert_eq!(backend.fresh_scan_calls, 1);
        assert_eq!(backend.begin_calls, 0);
        assert_eq!(backend.resume_calls, 0);
        assert_eq!(backend.persistent_write_calls, 0);
    }
}

#[test]
fn epoch_bump_invokes_begin_once_and_requires_fresh_steady_target() {
    let target = Target(4);
    for (after, expected) in [
        (FloorView::Steady(steady(4)), EstablishResult::Handoff),
        (FloorView::Steady(steady(3)), EstablishResult::Halt),
        (
            FloorView::Recovering(recovery(3, 4)),
            EstablishResult::Recovering,
        ),
        (FloorView::Unknown, EstablishResult::Halt),
    ] {
        let mut backend = FakeBackend::new(FloorView::Steady(steady(3)));
        backend.after_begin = after;
        assert_eq!(
            start_from_steady(&mut backend, binding(5), Some(fallback(4))),
            expected
        );
        assert_eq!(backend.preflight_calls, 1);
        assert_eq!(backend.begin_calls, 1);
        assert_eq!(backend.fresh_scan_calls, 1);
        assert_eq!(backend.persistent_write_calls, 1);
        assert_eq!(target, binding(5).epoch.target());
    }
}

#[test]
fn epoch_bump_rejects_a_same_target_recovery_proof_with_any_rebound_field() {
    let expected = recovery(3, 4);
    let mut wrong_candidate = expected;
    wrong_candidate.candidate.manifest_digest[0] ^= 1;
    let mut wrong_prior = expected;
    wrong_prior.prior.state_digest[0] ^= 1;
    let mut wrong_generation = expected;
    wrong_generation.allocation_generation += 1;

    for observed in [wrong_candidate, wrong_prior, wrong_generation] {
        let mut backend = FakeBackend::new(FloorView::Steady(steady(3)));
        backend.after_begin = FloorView::Recovering(observed);
        assert_eq!(
            start_from_steady(&mut backend, binding(5), Some(fallback(4))),
            EstablishResult::Halt
        );
        assert_eq!(backend.begin_calls, 1);
        assert_eq!(backend.fresh_scan_calls, 1);
    }
}

#[test]
fn recovery_entry_never_reclassifies_or_calls_preflight_or_begin() {
    let proof = recovery(3, 4);
    for (after, expected) in [
        (FloorView::Steady(steady(4)), EstablishResult::Handoff),
        (FloorView::Recovering(proof), EstablishResult::Recovering),
        (FloorView::Steady(steady(3)), EstablishResult::Halt),
        (FloorView::Unknown, EstablishResult::Halt),
    ] {
        let mut backend = FakeBackend::new(FloorView::Recovering(proof));
        backend.after_resume = after;
        assert_eq!(resume_from_recovery(&mut backend, proof), expected);
        assert_eq!(backend.preflight_calls, 0);
        assert_eq!(backend.begin_calls, 0);
        assert_eq!(backend.resume_calls, 1);
        assert_eq!(backend.fresh_scan_calls, 1);
        assert_eq!(backend.persistent_write_calls, 1);
    }
}

#[test]
fn recovery_rejects_stale_or_rebound_proof_without_mutation() {
    let current = recovery(3, 4);
    let mut stale = current;
    stale.allocation_generation += 1;
    let mut rebound = current;
    rebound.candidate.manifest_digest[0] ^= 1;

    for wrong in [stale, rebound, recovery(2, 4), recovery(3, 5)] {
        let mut backend = FakeBackend::new(FloorView::Recovering(current));
        assert_eq!(
            resume_from_recovery(&mut backend, wrong),
            EstablishResult::Halt
        );
        assert_eq!(backend.preflight_calls, 0);
        assert_eq!(backend.begin_calls, 0);
        assert_eq!(backend.resume_calls, 0);
        assert_eq!(backend.fresh_scan_calls, 0);
        assert_eq!(backend.persistent_write_calls, 0);
    }
}

#[test]
fn recovery_rejects_self_consistent_equality_but_invalid_semantics() {
    let mut non_increasing = recovery(3, 4);
    non_increasing.target = Target(3);
    non_increasing.candidate = binding(4);

    let mut target_candidate_mismatch = recovery(3, 4);
    target_candidate_mismatch.candidate = binding(6);

    let mut non_monotonic_generation = recovery(3, 4);
    non_monotonic_generation.allocation_generation =
        non_monotonic_generation.prior.allocation_generation;

    for invalid in [
        non_increasing,
        target_candidate_mismatch,
        non_monotonic_generation,
    ] {
        let mut backend = FakeBackend::new(FloorView::Recovering(invalid));
        assert_eq!(
            resume_from_recovery(&mut backend, invalid),
            EstablishResult::Halt
        );
        assert_eq!(backend.resume_calls, 0);
        assert_eq!(backend.fresh_scan_calls, 0);
        assert_eq!(backend.persistent_write_calls, 0);
    }
}

#[test]
fn unknown_or_recovering_never_enters_start_from_steady() {
    for view in [FloorView::Unknown, FloorView::Recovering(recovery(3, 4))] {
        let mut backend = FakeBackend::new(view);
        assert_eq!(
            start_from_steady(&mut backend, binding(5), Some(fallback(4))),
            EstablishResult::Halt
        );
        assert_eq!(backend.preflight_calls, 0);
        assert_eq!(backend.begin_calls, 0);
        assert_eq!(backend.fresh_scan_calls, 0);
        assert_eq!(backend.persistent_write_calls, 0);
    }
}
