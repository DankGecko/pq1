//! Bounded host-only deletion experiments for rollback Draft 1.1.
//!
//! This is disposable architecture research, not a conformance or production
//! implementation. It contains no manifest bytes, flash addresses, ECC
//! emulation, TAMP register layout, OTP codec, or hardware writer. Physical
//! observations and cryptographic verification enter only as opaque typed
//! facts; the still-open silicon/backend gates remain open.

#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

const FLOOR: u8 = 4;
const CURRENT_GROUP: u8 = 9;
const CURRENT_SNAPSHOT: u8 = 2;
const CODEC_ID: u8 = 3;
const DOMAIN_ID: u8 = 7;
const CURRENT_BOOT: u64 = 41;
const STATE_CAP: usize = 128;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Artifact {
    slot: u8,
    install: u8,
    release: u8,
    epoch: u8,
    manifest: u8,
    secure_image: u8,
    nonsecure_image: u8,
}

impl Artifact {
    fn target(self) -> Option<u8> {
        self.epoch.checked_sub(1)
    }

    fn exact_target(self, floor: u8) -> bool {
        self.target() == Some(floor)
    }
}

const SOURCE: Artifact = Artifact {
    slot: 0,
    install: 1,
    release: 10,
    epoch: FLOOR + 1,
    manifest: 11,
    secure_image: 12,
    nonsecure_image: 13,
};

const RECOVERY: Artifact = Artifact {
    slot: 1,
    install: 8,
    release: 12,
    epoch: FLOOR + 1,
    manifest: 21,
    secure_image: 22,
    nonsecure_image: 23,
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum BootDecision {
    Source,
    Candidate,
    RetryProbation,
    ReinstallRequired,
    ServiceRequired,
    Halt,
}

// -------------------------------------------------------------------------
// Experiment 1: RecoverySameEpoch versus Aborted -> service/RMA.

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum RecoveryPolicy {
    ServiceOnly,
    FieldRecovery,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum RepairPhase {
    Aborted,
    Staged,
    Armed,
    Attempted,
    Confirmed0,
    Confirmed2,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum RepairVolatile {
    None,
    StageReceipt,
    ArmReceipt,
    AttemptReceipt,
    Running,
    HealthPassed,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct RepairNode {
    phase: RepairPhase,
    volatile: RepairVolatile,
    floor: u8,
    release_high_water: u8,
    epoch_high_water: u8,
    source: Artifact,
    candidate: Artifact,
    failed_install: u8,
    handoffs: u8,
    route1_writes: u8,
    otp_writes: u8,
}

impl RepairNode {
    fn initial() -> Self {
        Self {
            phase: RepairPhase::Aborted,
            volatile: RepairVolatile::None,
            floor: FLOOR,
            release_high_water: 11,
            epoch_high_water: FLOOR + 2,
            source: SOURCE,
            candidate: RECOVERY,
            failed_install: 7,
            handoffs: 0,
            route1_writes: 0,
            otp_writes: 0,
        }
    }

    fn is_well_formed(self) -> bool {
        self.floor == FLOOR
            && self.source.exact_target(self.floor)
            && self.candidate.exact_target(self.floor)
            && self.candidate.release > self.release_high_water
            && self.candidate.epoch < self.epoch_high_water
            && self.candidate.install != self.failed_install
            && self.handoffs <= 1
            && self.route1_writes == 0
            && self.otp_writes == 0
            && (!matches!(
                self.phase,
                RepairPhase::Confirmed0 | RepairPhase::Confirmed2
            ) || self.handoffs == 1)
    }

    fn reboot(self) -> BootDecision {
        if !self.is_well_formed() {
            return BootDecision::Halt;
        }
        if self.phase == RepairPhase::Confirmed2 {
            BootDecision::Candidate
        } else {
            BootDecision::Source
        }
    }

    fn cut(mut self) -> Self {
        self.volatile = RepairVolatile::None;
        self
    }
}

fn repair_successors(node: RepairNode, policy: RecoveryPolicy) -> Vec<RepairNode> {
    let mut out = Vec::new();

    if node.volatile != RepairVolatile::None {
        out.push(node.cut());
    }

    match (policy, node.phase, node.volatile) {
        (RecoveryPolicy::FieldRecovery, RepairPhase::Aborted, RepairVolatile::None) => {
            let mut staged = node;
            staged.phase = RepairPhase::Staged;
            staged.volatile = RepairVolatile::StageReceipt;
            out.push(staged);

            let mut torn = node;
            torn.phase = RepairPhase::Ambiguous;
            out.push(torn);
        }
        (RecoveryPolicy::FieldRecovery, RepairPhase::Staged, RepairVolatile::StageReceipt) => {
            let mut armed = node;
            armed.phase = RepairPhase::Armed;
            armed.volatile = RepairVolatile::ArmReceipt;
            out.push(armed);

            let mut torn = node;
            torn.phase = RepairPhase::Ambiguous;
            out.push(torn);
        }
        (RecoveryPolicy::FieldRecovery, RepairPhase::Armed, RepairVolatile::ArmReceipt) => {
            let mut attempted = node;
            attempted.phase = RepairPhase::Attempted;
            attempted.volatile = RepairVolatile::AttemptReceipt;
            out.push(attempted);

            let mut torn = node;
            torn.phase = RepairPhase::Ambiguous;
            out.push(torn);
        }
        (RecoveryPolicy::FieldRecovery, RepairPhase::Attempted, RepairVolatile::AttemptReceipt) => {
            let mut running = node;
            running.volatile = RepairVolatile::Running;
            running.handoffs = running.handoffs.saturating_add(1);
            out.push(running);
        }
        (RecoveryPolicy::FieldRecovery, RepairPhase::Attempted, RepairVolatile::Running) => {
            let mut healthy = node;
            healthy.volatile = RepairVolatile::HealthPassed;
            out.push(healthy);
        }
        (RecoveryPolicy::FieldRecovery, RepairPhase::Attempted, RepairVolatile::HealthPassed) => {
            let mut confirmed0 = node;
            confirmed0.phase = RepairPhase::Confirmed0;
            out.push(confirmed0);

            let mut torn = node;
            torn.phase = RepairPhase::Ambiguous;
            torn.volatile = RepairVolatile::None;
            out.push(torn);
        }
        (RecoveryPolicy::FieldRecovery, RepairPhase::Confirmed0, RepairVolatile::HealthPassed) => {
            let mut confirmed2 = node;
            confirmed2.phase = RepairPhase::Confirmed2;
            confirmed2.volatile = RepairVolatile::None;
            out.push(confirmed2);

            let mut torn = node;
            torn.phase = RepairPhase::Ambiguous;
            torn.volatile = RepairVolatile::None;
            out.push(torn);
        }
        (RecoveryPolicy::ServiceOnly, _, _) | (RecoveryPolicy::FieldRecovery, _, _) => {}
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExplorationSummary {
    states: usize,
    candidate_reachable: bool,
}

fn explore_repair(policy: RecoveryPolicy) -> Result<ExplorationSummary, &'static str> {
    let initial = RepairNode::initial();
    let mut seen = HashSet::from([initial]);
    let mut queue = VecDeque::from([initial]);
    let mut candidate_reachable = false;

    while let Some(node) = queue.pop_front() {
        if !node.is_well_formed() {
            return Err("reachable malformed repair state");
        }
        candidate_reachable |= node.reboot() == BootDecision::Candidate;

        for successor in repair_successors(node, policy) {
            if seen.insert(successor) {
                if seen.len() > STATE_CAP {
                    return Err("NO VERDICT: repair state cap exceeded");
                }
                queue.push_back(successor);
            }
        }
    }

    Ok(ExplorationSummary {
        states: seen.len(),
        candidate_reachable,
    })
}

#[test]
fn aborted_service_only_is_safe_and_field_recovery_is_availability_only() {
    let service = explore_repair(RecoveryPolicy::ServiceOnly).expect("bounded exploration");
    let field = explore_repair(RecoveryPolicy::FieldRecovery).expect("bounded exploration");

    assert_eq!(service.states, 1);
    assert!(!service.candidate_reachable);
    assert!(field.states > service.states);
    assert!(field.candidate_reachable);
}

// -------------------------------------------------------------------------
// Experiment 2: FloorBoundAccepted versus terminal-only service.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommittedGroup {
    generation: u8,
    snapshot: u8,
    codec: u8,
    domain: u8,
    floor: u8,
    complete: bool,
    accepted: Artifact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FloorAuthority {
    Steady(CommittedGroup),
    Aborted { predecessor: CommittedGroup },
    Recovering,
    Unknown,
    Base0,
}

#[derive(Debug, PartialEq, Eq)]
struct FloorBoundProof {
    artifact: Artifact,
    group: CommittedGroup,
    boot: u64,
    _private: (),
}

fn authoritative_group(authority: FloorAuthority) -> Option<CommittedGroup> {
    match authority {
        FloorAuthority::Steady(group) | FloorAuthority::Aborted { predecessor: group } => {
            Some(group)
        }
        FloorAuthority::Recovering | FloorAuthority::Unknown | FloorAuthority::Base0 => None,
    }
}

fn derive_floor_bound(
    authority: FloorAuthority,
    observed: Artifact,
    boot: u64,
) -> Option<FloorBoundProof> {
    let group = authoritative_group(authority)?;

    (group.generation == CURRENT_GROUP
        && group.snapshot == CURRENT_SNAPSHOT
        && group.codec == CODEC_ID
        && group.domain == DOMAIN_ID
        && group.floor == FLOOR
        && group.complete
        && group.accepted == observed
        && observed.exact_target(FLOOR))
    .then_some(FloorBoundProof {
        artifact: observed,
        group,
        boot,
        _private: (),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalEvidence {
    Full,
    One,
    None,
    Ambiguous,
}

fn terminal_decision(
    terminal: TerminalEvidence,
    artifact: Artifact,
    proof: Option<FloorBoundProof>,
    current_authority: FloorAuthority,
    current_boot: u64,
    robust_peer: Option<Artifact>,
) -> BootDecision {
    if !artifact.exact_target(FLOOR) {
        return BootDecision::Halt;
    }

    let floor_bound = proof.is_some_and(|candidate| {
        candidate.artifact == artifact
            && candidate.boot == current_boot
            && authoritative_group(current_authority) == Some(candidate.group)
    });
    let candidate_robust = terminal == TerminalEvidence::Full
        || matches!(terminal, TerminalEvidence::One | TerminalEvidence::None) && floor_bound;

    if candidate_robust {
        return match robust_peer {
            Some(peer) if !candidate_precedes_peer(artifact, peer) => BootDecision::Source,
            Some(_) | None => BootDecision::Candidate,
        };
    }

    robust_peer.map_or(BootDecision::ServiceRequired, |_| BootDecision::Source)
}

fn candidate_precedes_peer(candidate: Artifact, peer: Artifact) -> bool {
    candidate.epoch > peer.epoch
        || (candidate.epoch == peer.epoch && candidate.release > peer.release)
        || (candidate.epoch == peer.epoch
            && candidate.release == peer.release
            && candidate.slot < peer.slot)
}

fn exact_group() -> CommittedGroup {
    CommittedGroup {
        generation: CURRENT_GROUP,
        snapshot: CURRENT_SNAPSHOT,
        codec: CODEC_ID,
        domain: DOMAIN_ID,
        floor: FLOOR,
        complete: true,
        accepted: RECOVERY,
    }
}

#[test]
fn floor_bound_is_authoritative_only_and_adds_degraded_availability() {
    for terminal in [TerminalEvidence::One, TerminalEvidence::None] {
        let steady = FloorAuthority::Steady(exact_group());
        assert_eq!(
            terminal_decision(
                terminal,
                RECOVERY,
                derive_floor_bound(steady, RECOVERY, CURRENT_BOOT),
                steady,
                CURRENT_BOOT,
                None,
            ),
            BootDecision::Candidate
        );
        assert_eq!(
            terminal_decision(terminal, RECOVERY, None, steady, CURRENT_BOOT, None),
            BootDecision::ServiceRequired
        );

        let aborted = FloorAuthority::Aborted {
            predecessor: exact_group(),
        };
        assert_eq!(
            terminal_decision(
                terminal,
                RECOVERY,
                derive_floor_bound(aborted, RECOVERY, CURRENT_BOOT),
                aborted,
                CURRENT_BOOT,
                None,
            ),
            BootDecision::Candidate
        );

        // Floor binding reconstructs robust accepted authority. The newer
        // candidate then competes with the peer under (E, R, slot-A).
        assert_eq!(
            terminal_decision(
                terminal,
                RECOVERY,
                derive_floor_bound(steady, RECOVERY, CURRENT_BOOT),
                steady,
                CURRENT_BOOT,
                Some(SOURCE),
            ),
            BootDecision::Candidate
        );
        assert_eq!(
            terminal_decision(terminal, RECOVERY, None, steady, CURRENT_BOOT, Some(SOURCE),),
            BootDecision::Source
        );
    }

    let steady = FloorAuthority::Steady(exact_group());
    assert_eq!(
        terminal_decision(
            TerminalEvidence::Ambiguous,
            RECOVERY,
            derive_floor_bound(steady, RECOVERY, CURRENT_BOOT),
            steady,
            CURRENT_BOOT,
            None,
        ),
        BootDecision::ServiceRequired
    );
}

#[test]
fn floor_bound_proof_is_current_boot_and_current_authority_scoped() {
    let steady = FloorAuthority::Steady(exact_group());
    let stale_boot = derive_floor_bound(steady, RECOVERY, CURRENT_BOOT)
        .expect("exact committed accepted binding");
    assert_eq!(
        terminal_decision(
            TerminalEvidence::None,
            RECOVERY,
            Some(stale_boot),
            steady,
            CURRENT_BOOT + 1,
            None,
        ),
        BootDecision::ServiceRequired
    );

    let stale_group = derive_floor_bound(steady, RECOVERY, CURRENT_BOOT)
        .expect("exact committed accepted binding");
    let mut changed = exact_group();
    changed.snapshot ^= 1;
    assert_eq!(
        terminal_decision(
            TerminalEvidence::None,
            RECOVERY,
            Some(stale_group),
            FloorAuthority::Steady(changed),
            CURRENT_BOOT,
            None,
        ),
        BootDecision::ServiceRequired
    );
}

#[test]
fn floor_bound_cannot_be_derived_from_wrong_or_preauthoritative_state() {
    for authority in [
        FloorAuthority::Recovering,
        FloorAuthority::Unknown,
        FloorAuthority::Base0,
    ] {
        assert!(derive_floor_bound(authority, RECOVERY, CURRENT_BOOT).is_none());
    }

    for field in 0..7 {
        let mut group = exact_group();
        match field {
            0 => group.generation ^= 1,
            1 => group.snapshot ^= 1,
            2 => group.codec ^= 1,
            3 => group.domain ^= 1,
            4 => group.floor ^= 1,
            5 => group.complete = false,
            6 => group.accepted.install ^= 1,
            _ => unreachable!(),
        }
        assert!(
            derive_floor_bound(FloorAuthority::Steady(group), RECOVERY, CURRENT_BOOT).is_none()
        );
    }

    for field in 0..7 {
        let mut artifact = RECOVERY;
        match field {
            0 => artifact.slot ^= 1,
            1 => artifact.install ^= 1,
            2 => artifact.release ^= 1,
            3 => artifact.epoch ^= 1,
            4 => artifact.manifest ^= 1,
            5 => artifact.secure_image ^= 1,
            6 => artifact.nonsecure_image ^= 1,
            _ => unreachable!(),
        }
        assert!(derive_floor_bound(
            FloorAuthority::Steady(exact_group()),
            artifact,
            CURRENT_BOOT,
        )
        .is_none());
        assert!(derive_floor_bound(
            FloorAuthority::Aborted {
                predecessor: exact_group(),
            },
            artifact,
            CURRENT_BOOT,
        )
        .is_none());
    }
}

// -------------------------------------------------------------------------
// Experiment 3: can a manifest-only ATTEMPTED word replace retained TAMP?

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllFfHistory {
    VirginFirstBoot,
    TornAttemptBeforeHandoff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllFfPolicy {
    Retry,
    ExcludeOrReinstall,
}

fn all_ff_policy_is_safe(policy: AllFfPolicy, history: AllFfHistory) -> bool {
    !matches!(
        (policy, history),
        (AllFfPolicy::Retry, AllFfHistory::TornAttemptBeforeHandoff)
    )
}

fn all_ff_policy_allows_first_probation(policy: AllFfPolicy, history: AllFfHistory) -> bool {
    policy == AllFfPolicy::Retry && history == AllFfHistory::VirginFirstBoot
}

#[test]
fn manifest_only_attempt_word_has_no_safe_and_live_all_ff_policy() {
    // Both hidden histories have the same post-power-loss observation:
    // an all-FF manifest ATTEMPTED QW with no independent durable witness.
    for policy in [AllFfPolicy::Retry, AllFfPolicy::ExcludeOrReinstall] {
        let safe = [
            AllFfHistory::VirginFirstBoot,
            AllFfHistory::TornAttemptBeforeHandoff,
        ]
        .into_iter()
        .all(|history| all_ff_policy_is_safe(policy, history));
        let live = all_ff_policy_allows_first_probation(policy, AllFfHistory::VirginFirstBoot);
        assert!(!(safe && live));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenState {
    Ready,
    Attempted,
    Malformed,
}

#[derive(Debug, PartialEq, Eq)]
struct AttemptReceipt {
    install: u8,
    boot: u64,
    _private: (),
}

#[derive(Debug, PartialEq, Eq)]
struct RunningCandidate {
    install: u8,
    _private: (),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteOutcome {
    ProvenNoLaunch,
    DurableExact,
    MayHaveLaunched,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetainedAttemptModel {
    install: u8,
    boot: u64,
    token: TokenState,
    handoffs: u8,
}

impl RetainedAttemptModel {
    fn new(install: u8) -> Self {
        Self {
            install,
            boot: 1,
            token: TokenState::Ready,
            handoffs: 0,
        }
    }

    fn write_attempt(&mut self, outcome: WriteOutcome) -> Option<AttemptReceipt> {
        if self.token != TokenState::Ready {
            return None;
        }
        match outcome {
            WriteOutcome::ProvenNoLaunch => None,
            WriteOutcome::DurableExact => {
                self.token = TokenState::Attempted;
                Some(AttemptReceipt {
                    install: self.install,
                    boot: self.boot,
                    _private: (),
                })
            }
            WriteOutcome::MayHaveLaunched => {
                self.token = TokenState::Malformed;
                None
            }
        }
    }

    fn handoff(&mut self, receipt: AttemptReceipt) -> Option<RunningCandidate> {
        if receipt.install != self.install
            || receipt.boot != self.boot
            || self.token != TokenState::Attempted
            || self.handoffs != 0
        {
            return None;
        }
        self.handoffs = 1;
        Some(RunningCandidate {
            install: self.install,
            _private: (),
        })
    }

    fn reset(&mut self) {
        self.boot = self.boot.checked_add(1).expect("bounded host boot epoch");
    }

    fn reboot_decision(self) -> BootDecision {
        match self.token {
            TokenState::Ready => BootDecision::RetryProbation,
            TokenState::Attempted => BootDecision::Source,
            TokenState::Malformed => BootDecision::ReinstallRequired,
        }
    }
}

#[test]
fn retained_attempt_state_mints_one_current_boot_handoff_receipt() {
    let mut no_launch = RetainedAttemptModel::new(RECOVERY.install);
    assert!(no_launch
        .write_attempt(WriteOutcome::ProvenNoLaunch)
        .is_none());
    no_launch.reset();
    assert_eq!(no_launch.reboot_decision(), BootDecision::RetryProbation);

    let mut torn = RetainedAttemptModel::new(RECOVERY.install);
    assert!(torn.write_attempt(WriteOutcome::MayHaveLaunched).is_none());
    torn.reset();
    assert_eq!(torn.reboot_decision(), BootDecision::ReinstallRequired);

    let mut cut_before_handoff = RetainedAttemptModel::new(RECOVERY.install);
    let stale = cut_before_handoff
        .write_attempt(WriteOutcome::DurableExact)
        .expect("current-boot exact receipt");
    cut_before_handoff.reset();
    assert!(cut_before_handoff.handoff(stale).is_none());
    assert_eq!(cut_before_handoff.reboot_decision(), BootDecision::Source);

    let mut successful = RetainedAttemptModel::new(RECOVERY.install);
    let receipt = successful
        .write_attempt(WriteOutcome::DurableExact)
        .expect("current-boot exact receipt");
    let running = successful.handoff(receipt).expect("one handoff");
    assert_eq!(running.install, RECOVERY.install);
    successful.reset();
    assert_eq!(successful.handoffs, 1);
    assert_eq!(successful.reboot_decision(), BootDecision::Source);
}

// -------------------------------------------------------------------------
// Experiment 4 policy gate. This is bookkeeping, not resource evidence.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FormatEvidence {
    signed_tool_interop: bool,
    executed_cut_property: bool,
    physical_backend_closed: bool,
    combined_flash_fit: bool,
    combined_ram_stack_fit: bool,
}

fn exact_bytes_may_freeze(evidence: FormatEvidence) -> bool {
    evidence.signed_tool_interop
        && evidence.executed_cut_property
        && evidence.physical_backend_closed
        && evidence.combined_flash_fit
        && evidence.combined_ram_stack_fit
}

#[test]
fn byte_freeze_policy_refuses_every_incomplete_evidence_set() {
    let complete = FormatEvidence {
        signed_tool_interop: true,
        executed_cut_property: true,
        physical_backend_closed: true,
        combined_flash_fit: true,
        combined_ram_stack_fit: true,
    };
    assert!(exact_bytes_may_freeze(complete));

    for missing in 0..5 {
        let mut evidence = complete;
        match missing {
            0 => evidence.signed_tool_interop = false,
            1 => evidence.executed_cut_property = false,
            2 => evidence.physical_backend_closed = false,
            3 => evidence.combined_flash_fit = false,
            4 => evidence.combined_ram_stack_fit = false,
            _ => unreachable!(),
        }
        assert!(!exact_bytes_may_freeze(evidence));
    }
}
