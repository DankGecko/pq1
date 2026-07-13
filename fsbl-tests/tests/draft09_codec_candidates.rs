//! Nonshipping host candidates for Draft 0.9's still-open OTP codec/stage work.
//!
//! This file intentionally lives outside every production crate.  It explores
//! properties that a later `OPEN-OTP-1..3` design must retain, but it does not
//! choose a physical record, threshold, journal, key, QW map, or backend.
//! Passing these tests closes none of `OPEN-OTP-1..3` or `OPEN-ECC-1`: the
//! stage, receipt, digest, cursor, thresholds, and codeword below remain
//! abstract host candidates pending a separately reviewed physical design.

#![forbid(unsafe_code)]

const CELL_COUNT: usize = 26;
const FULL_INITIAL_THRESHOLD: usize = 3;
const DEGRADED_THRESHOLD: usize = 2;
const PLANNED_ATTEMPTS_PER_ROLE: usize = 2;
const CODEC_DOMAIN: u32 = 0x4652_4200; // "FRB" plus the role byte.
const CODEC_ID: [u8; 8] = *b"D09PLN01";
const BASE0_DIGEST: [u8; 16] = *b"D09-BASE0-DIGEST";
const VALID_CODEWORD_ONES: u32 = 64;
const MAX_TARGET: u32 = 0xffff_fffd;

// ---------------------------------------------------------------------------
// Candidate A: one plain structural 16-byte codeword.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlainRecord {
    target: u32,
    role: u8,
}

fn encode_plain(record: PlainRecord) -> [u8; 16] {
    let tagged_role = CODEC_DOMAIN | u32::from(record.role);
    let mut out = [0_u8; 16];
    out[..4].copy_from_slice(&record.target.to_be_bytes());
    out[4..8].copy_from_slice(&(!record.target).to_be_bytes());
    out[8..12].copy_from_slice(&tagged_role.to_be_bytes());
    out[12..].copy_from_slice(&(!tagged_role).to_be_bytes());
    out
}

fn decode_plain(bytes: [u8; 16]) -> Option<PlainRecord> {
    // This explicit constant-weight gate is load-bearing.  Every valid pair
    // `x || !x` contains exactly 32 one bits; two pairs contain exactly 64.
    // Any strict erased-to-codeword 1->0 prefix has more than 64 one bits.
    if codeword_ones(bytes) != VALID_CODEWORD_ONES {
        return None;
    }

    let target = u32::from_be_bytes(bytes[..4].try_into().ok()?);
    let target_complement = u32::from_be_bytes(bytes[4..8].try_into().ok()?);
    let tagged_role = u32::from_be_bytes(bytes[8..12].try_into().ok()?);
    let tagged_role_complement = u32::from_be_bytes(bytes[12..].try_into().ok()?);
    let role = (tagged_role & 0xff) as u8;

    if target_complement != !target
        || target > MAX_TARGET
        || tagged_role_complement != !tagged_role
        || tagged_role & 0xffff_ff00 != CODEC_DOMAIN
        || usize::from(role) >= FULL_INITIAL_THRESHOLD
    {
        return None;
    }

    Some(PlainRecord { target, role })
}

fn codeword_ones(bytes: [u8; 16]) -> u32 {
    bytes.into_iter().map(u8::count_ones).sum()
}

/// `observed` is an erased-to-`intended` programming prefix when it has not
/// cleared any bit that the final codeword needs to remain one.
fn is_programming_prefix(observed: [u8; 16], intended: [u8; 16]) -> bool {
    observed != intended
        && observed
            .into_iter()
            .zip(intended)
            .all(|(partial, final_byte)| partial & final_byte == final_byte)
}

#[test]
fn plain_candidate_round_trips_and_has_constant_weight() {
    for target in [0, 1, 0x5555_aaaa, 0x8000_0000, MAX_TARGET] {
        for role in 0..FULL_INITIAL_THRESHOLD as u8 {
            let record = PlainRecord { target, role };
            let encoded = encode_plain(record);
            assert_eq!(codeword_ones(encoded), VALID_CODEWORD_ONES);
            assert_eq!(decode_plain(encoded), Some(record));
        }
    }
}

#[test]
fn strict_programming_prefix_weight_lemma_is_exhaustive_per_byte() {
    // Exhaust all byte pairs.  Additivity of popcount lifts this lemma to all
    // sixteen bytes: if at least one byte is a strict prefix and no byte
    // clears a required one, the whole codeword has strictly greater weight.
    for final_byte in u8::MIN..=u8::MAX {
        for partial in u8::MIN..=u8::MAX {
            if partial != final_byte && partial & final_byte == final_byte {
                assert!(partial.count_ones() > final_byte.count_ones());
            }
        }
    }
}

#[test]
fn every_strict_one_to_zero_prefix_is_rejected_by_construction() {
    // The exhaustive byte lemma plus the explicit constant-weight decoder
    // gate covers every subset/order of intended 1->0 transitions, not merely
    // one assumed flash programming order.  Restore every individual cleared
    // bit as an executable sanity check across representative full records.
    for target in [0, 1, 0x5555_aaaa, 0xdead_beef, MAX_TARGET] {
        for role in 0..FULL_INITIAL_THRESHOLD as u8 {
            let intended = encode_plain(PlainRecord { target, role });
            for bit in 0..128 {
                let byte = bit / 8;
                let mask = 1_u8 << (bit % 8);
                if intended[byte] & mask == 0 {
                    let mut partial = intended;
                    partial[byte] |= mask;
                    assert!(is_programming_prefix(partial, intended));
                    assert!(codeword_ones(partial) > VALID_CODEWORD_ONES);
                    assert_eq!(decode_plain(partial), None);
                }
            }
        }
    }
}

#[test]
fn plain_candidate_valid_codewords_are_an_antichain() {
    // For any two accepted codewords, both weights are exactly 64.  Two
    // distinct equal-weight bitsets cannot be strict subsets of one another.
    let records = [
        PlainRecord { target: 0, role: 0 },
        PlainRecord { target: 0, role: 1 },
        PlainRecord { target: 1, role: 0 },
        PlainRecord {
            target: 0x5555_aaaa,
            role: 2,
        },
        PlainRecord {
            target: MAX_TARGET,
            role: 2,
        },
    ];
    for left in records {
        for right in records {
            let left = encode_plain(left);
            let right = encode_plain(right);
            assert_eq!(codeword_ones(left), codeword_ones(right));
            assert!(!is_programming_prefix(left, right));
        }
    }
}

#[test]
fn plain_decoder_rejects_reserved_targets() {
    assert_eq!(
        decode_plain(encode_plain(PlainRecord {
            target: MAX_TARGET,
            role: 0,
        })),
        Some(PlainRecord {
            target: MAX_TARGET,
            role: 0,
        })
    );
    for target in [MAX_TARGET + 1, u32::MAX] {
        for role in 0..FULL_INITIAL_THRESHOLD as u8 {
            assert_eq!(
                decode_plain(encode_plain(PlainRecord { target, role })),
                None
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Backend-neutral replicated-group and durable-stage model.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Cell(u8);

impl Cell {
    fn checked(index: u8) -> Option<Self> {
        (usize::from(index) < CELL_COUNT).then_some(Self(index))
    }

    fn index(self) -> usize {
        usize::from(self.0)
    }

    fn is_valid(self) -> bool {
        self.index() < CELL_COUNT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GroupId {
    generation: u32,
    target: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplicaHealth {
    FreshClean,
    NeedsFreshValidation,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Replica {
    cell: Cell,
    role: u8,
    health: ReplicaHealth,
    durable_clean_binding: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedGroup {
    codec_id: [u8; 8],
    id: GroupId,
    prior: Option<GroupId>,
    prior_f: u32,
    prior_digest: [u8; 16],
    prior_cursor: u8,
    state_digest: [u8; 16],
    allocation_cursor: u8,
    candidate_binding: [u8; 16],
    ordered_plan: Vec<ClaimBinding>,
    consumed_attempts: Vec<Cell>,
    replicas: Vec<Replica>,
    clean_at_complete: usize,
    initial_threshold: usize,
    degraded_threshold: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommittedHead {
    id: GroupId,
    state_digest: [u8; 16],
    allocation_cursor: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveClaimState {
    Preclaimed,
    MayHaveLaunched,
    Clean,
    NeedsFreshValidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LiveClaim {
    cell: Cell,
    role: u8,
    state: LiveClaimState,
    durable_clean_binding: Option<[u8; 16]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClaimBinding {
    cell: Cell,
    role: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveStage {
    codec_id: [u8; 8],
    id: GroupId,
    prior: Option<GroupId>,
    prior_digest: [u8; 16],
    prior_cursor: u8,
    allocation_cursor: u8,
    prior_f: u32,
    candidate_binding: [u8; 16],
    ordered_map: Vec<ClaimBinding>,
    live: Vec<LiveClaim>,
    consumed_attempts: Vec<Cell>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StageToken {
    codec_id: [u8; 8],
    id: GroupId,
    prior: Option<GroupId>,
    prior_digest: [u8; 16],
    prior_cursor: u8,
    allocation_cursor: u8,
    prior_f: u32,
    candidate_binding: [u8; 16],
    ordered_map: Vec<ClaimBinding>,
    live: Vec<LiveClaim>,
    consumed_attempts: Vec<Cell>,
}

impl ActiveStage {
    fn token(&self) -> StageToken {
        StageToken {
            codec_id: self.codec_id,
            id: self.id,
            prior: self.prior,
            prior_digest: self.prior_digest,
            prior_cursor: self.prior_cursor,
            allocation_cursor: self.allocation_cursor,
            prior_f: self.prior_f,
            candidate_binding: self.candidate_binding,
            ordered_map: self.ordered_map.clone(),
            live: self.live.clone(),
            consumed_attempts: self.consumed_attempts.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreshEccStatus {
    Clean,
    Corrected,
    Uncorrectable,
}

// EOP is a launch-time diagnostic only.  It is consumed while recording the
// clean transition into the abstract authenticated stage; it is neither
// durable nor re-observable after reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreshCleanReceipt {
    cell: Cell,
    generation: u32,
    observed: [u8; 16],
    eop: bool,
    ecc: FreshEccStatus,
    fresh_array_read: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreshRevalidationReceipt {
    cell: Cell,
    generation: u32,
    boot_epoch: u64,
    observed: [u8; 16],
    prior_durable_clean_binding: [u8; 16],
    ecc: FreshEccStatus,
    fresh_array_read: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreshBase0Receipt {
    boot_epoch: u64,
    all_reserved_cells_ff: bool,
    fresh_array_reads: bool,
    ecc: FreshEccStatus,
    no_missing_durable_intent: bool,
}

impl FreshCleanReceipt {
    fn clean(cell: Cell, generation: u32, observed: [u8; 16]) -> Self {
        Self {
            cell,
            generation,
            observed,
            eop: true,
            ecc: FreshEccStatus::Clean,
            fresh_array_read: true,
        }
    }
}

fn classify_revalidation(
    receipt: FreshRevalidationReceipt,
    boot_epoch: u64,
    generation: u32,
    expected: PlainRecord,
    durable_clean_binding: [u8; 16],
) -> Result<RevalidationOutcome, ModelError> {
    if receipt.boot_epoch != boot_epoch
        || receipt.generation != generation
        || !receipt.fresh_array_read
        || receipt.prior_durable_clean_binding != durable_clean_binding
    {
        return Err(ModelError::InvalidReceipt);
    }
    if receipt.ecc == FreshEccStatus::Clean && decode_plain(receipt.observed) == Some(expected) {
        Ok(RevalidationOutcome::FreshClean)
    } else {
        // Corrected, uncorrectable, or structurally unexpected current bytes
        // receive zero weight.  The abstract model does not claim the silicon
        // fresh-read/ECC primitive needed to make this classification real.
        Ok(RevalidationOutcome::Rejected)
    }
}

fn durable_clean_binding(receipt: FreshCleanReceipt) -> [u8; 16] {
    let generation = receipt.generation.to_be_bytes();
    let cell = [receipt.cell.0];
    binding_digest([
        b"D09-STAGED-CLEAN".as_slice(),
        generation.as_slice(),
        cell.as_slice(),
        receipt.observed.as_slice(),
    ])
}

fn expected_durable_clean_binding(cell: Cell, generation: u32, target: u32, role: u8) -> [u8; 16] {
    durable_clean_binding(FreshCleanReceipt::clean(
        cell,
        generation,
        encode_plain(PlainRecord { target, role }),
    ))
}

// Identity-only host digest.  This is deliberately not a candidate MAC or
// production hash; it merely makes binding omissions observable in this model.
fn binding_digest<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 16] {
    let mut left = 0xcbf2_9ce4_8422_2325_u64;
    let mut right = 0x9e37_79b9_7f4a_7c15_u64;
    for byte in parts.into_iter().flatten().copied() {
        left ^= u64::from(byte);
        left = left.wrapping_mul(0x0000_0100_0000_01b3);
        right ^= left.rotate_left(17) ^ u64::from(byte);
        right = right.wrapping_mul(0xd6e8_feb8_6659_fd93);
    }
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&left.to_be_bytes());
    out[8..].copy_from_slice(&right.to_be_bytes());
    out
}

struct StageDigestFields<'a> {
    codec_id: &'a [u8; 8],
    id: GroupId,
    prior: Option<GroupId>,
    prior_f: u32,
    prior_digest: &'a [u8; 16],
    prior_cursor: u8,
    allocation_cursor: u8,
    candidate_binding: &'a [u8; 16],
}

fn stage_digest(fields: StageDigestFields<'_>, ordered_plan: &[ClaimBinding]) -> [u8; 16] {
    let generation = fields.id.generation.to_be_bytes();
    let target = fields.id.target.to_be_bytes();
    let mut prior_identity = [0_u8; 9];
    if let Some(prior) = fields.prior {
        prior_identity[0] = 1;
        prior_identity[1..5].copy_from_slice(&prior.generation.to_be_bytes());
        prior_identity[5..9].copy_from_slice(&prior.target.to_be_bytes());
    }
    let prior_floor = fields.prior_f.to_be_bytes();
    let cursor_bytes = [fields.prior_cursor, fields.allocation_cursor];
    let mut plan_bytes = Vec::with_capacity(ordered_plan.len() * 2);
    for binding in ordered_plan {
        plan_bytes.extend_from_slice(&[binding.cell.0, binding.role]);
    }
    binding_digest([
        fields.codec_id.as_slice(),
        generation.as_slice(),
        target.as_slice(),
        prior_identity.as_slice(),
        prior_floor.as_slice(),
        fields.prior_digest.as_slice(),
        cursor_bytes.as_slice(),
        fields.candidate_binding.as_slice(),
        plan_bytes.as_slice(),
    ])
}

fn completed_group_digest(
    stage_binding: [u8; 16],
    replicas: &[Replica],
    consumed_attempts: &[Cell],
) -> [u8; 16] {
    // Replica identity is the clean set accepted at COMPLETE, including the
    // authenticated stage's durable clean-transition binding that authorizes
    // later-boot revalidation.  Launch-time EOP itself is not durable;
    // current-boot health is also transient and deliberately excluded.
    let mut replica_bytes = Vec::with_capacity(replicas.len() * 18);
    for replica in replicas {
        replica_bytes.extend_from_slice(&[replica.cell.0, replica.role]);
        replica_bytes.extend_from_slice(&replica.durable_clean_binding);
    }
    let consumed_bytes: Vec<u8> = consumed_attempts.iter().map(|cell| cell.0).collect();
    binding_digest([
        stage_binding.as_slice(),
        replica_bytes.as_slice(),
        consumed_bytes.as_slice(),
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FloorFault {
    AmbiguousDurableState,
    MissingDurableStage,
    FreshValidationRequired,
    OwnershipAlias,
    InvalidCommittedGroup,
    MissingOrReplayedCommittedHead,
    InvalidRecoveryStage,
    LostHighestQuorum,
    UnprovenBase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FloorView {
    Steady {
        floor: u32,
        group: Option<GroupId>,
    },
    Recovering {
        prior_f: u32,
        target: u32,
        group: GroupId,
        token: StageToken,
    },
    Unknown(FloorFault),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelError {
    NotSteady,
    StageAlreadyActive,
    NoActiveStage,
    NotRecovering,
    WrongStageToken,
    InvalidTarget,
    InvalidPlan,
    InvalidRole,
    CellUnavailable,
    RoleAlreadyLive,
    NotPreclaimed,
    NotLaunched,
    InvalidReceipt,
    NotAwaitingFreshValidation,
    InitialThresholdNotMet,
    OwnershipInvalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RevalidationOutcome {
    FreshClean,
    Rejected,
}

#[derive(Clone, Debug)]
struct FloorModel {
    groups: Vec<CommittedGroup>,
    committed_head: Option<CommittedHead>,
    stage: Option<ActiveStage>,
    consumed: Vec<Cell>,
    base0_proven: bool,
    base0_fresh_this_boot: bool,
    writer_may_have_begun: bool,
    ambiguous_durable_state: bool,
    next_generation: u32,
    boot_epoch: u64,
}

impl FloorModel {
    fn blank() -> Self {
        Self {
            groups: Vec::new(),
            committed_head: None,
            stage: None,
            consumed: Vec::new(),
            base0_proven: true,
            base0_fresh_this_boot: true,
            writer_may_have_begun: false,
            ambiguous_durable_state: false,
            next_generation: 1,
            boot_epoch: 0,
        }
    }

    fn highest_group(&self) -> Option<&CommittedGroup> {
        self.groups.iter().max_by_key(|group| group.id.generation)
    }

    fn decode(&self) -> FloorView {
        if self.ambiguous_durable_state {
            return FloorView::Unknown(FloorFault::AmbiguousDurableState);
        }
        if self.writer_may_have_begun && self.stage.is_none() {
            return FloorView::Unknown(FloorFault::MissingDurableStage);
        }
        if !self.ownership_is_globally_unique() {
            return FloorView::Unknown(FloorFault::OwnershipAlias);
        }
        if self.groups_are_well_formed().is_err() {
            return FloorView::Unknown(FloorFault::InvalidCommittedGroup);
        }

        let highest = self.highest_group();
        match (self.committed_head, highest) {
            (None, None) => {}
            (Some(head), Some(group))
                if head.id == group.id
                    && head.state_digest == group.state_digest
                    && head.allocation_cursor == group.allocation_cursor => {}
            (None, Some(_)) | (Some(_), None) | (Some(_), Some(_)) => {
                return FloorView::Unknown(FloorFault::MissingOrReplayedCommittedHead);
            }
        }
        // Every committed candidate record participates in the authenticated
        // chain scan.  Do not declare the highest group authoritative while
        // any older group still carries a receipt from a previous boot.
        if self
            .groups
            .iter()
            .flat_map(|group| &group.replicas)
            .any(|replica| replica.health == ReplicaHealth::NeedsFreshValidation)
        {
            return FloorView::Unknown(FloorFault::FreshValidationRequired);
        }
        if let Some(group) = highest {
            let clean = group
                .replicas
                .iter()
                .filter(|replica| replica.health == ReplicaHealth::FreshClean)
                .count();
            if clean < group.degraded_threshold {
                return FloorView::Unknown(FloorFault::LostHighestQuorum);
            }
        }

        if let Some(stage) = &self.stage {
            if !self.stage_is_well_formed(stage, highest) {
                return FloorView::Unknown(FloorFault::InvalidRecoveryStage);
            }
            if stage
                .live
                .iter()
                .any(|claim| claim.state == LiveClaimState::NeedsFreshValidation)
            {
                return FloorView::Unknown(FloorFault::FreshValidationRequired);
            }
            return FloorView::Recovering {
                prior_f: stage.prior_f,
                target: stage.id.target,
                group: stage.id,
                token: stage.token(),
            };
        }

        match highest {
            Some(group) => FloorView::Steady {
                floor: group.id.target,
                group: Some(group.id),
            },
            None if self.base0_proven && self.base0_fresh_this_boot && self.consumed.is_empty() => {
                FloorView::Steady {
                    floor: 0,
                    group: None,
                }
            }
            None if self.base0_proven && !self.base0_fresh_this_boot => {
                FloorView::Unknown(FloorFault::FreshValidationRequired)
            }
            None => FloorView::Unknown(FloorFault::UnprovenBase),
        }
    }

    fn begin(
        &mut self,
        target: u32,
        candidate_binding: [u8; 16],
        ordered_plan: Vec<ClaimBinding>,
    ) -> Result<StageToken, ModelError> {
        if self.stage.is_some() {
            return Err(ModelError::StageAlreadyActive);
        }
        let FloorView::Steady { floor, group } = self.decode() else {
            return Err(ModelError::NotSteady);
        };
        if target <= floor || target > MAX_TARGET {
            return Err(ModelError::InvalidTarget);
        }

        let (prior_digest, prior_cursor) = match group {
            Some(group_id) => {
                let prior = self
                    .groups
                    .iter()
                    .find(|candidate| candidate.id == group_id)
                    .expect("Steady group came from this model");
                (prior.state_digest, prior.allocation_cursor)
            }
            None => (BASE0_DIGEST, 0),
        };
        let allocation_cursor = self
            .validate_new_plan(&ordered_plan, prior_cursor)
            .ok_or(ModelError::InvalidPlan)?;

        let id = GroupId {
            generation: self.next_generation,
            target,
        };
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("host generation overflow");
        let stage = ActiveStage {
            codec_id: CODEC_ID,
            id,
            prior: group,
            prior_digest,
            prior_cursor,
            allocation_cursor,
            prior_f: floor,
            candidate_binding,
            ordered_map: ordered_plan,
            live: Vec::new(),
            consumed_attempts: Vec::new(),
        };
        let token = stage.token();
        // This is independent durable-intent state in the host model.  A
        // missing/torn stage after this boundary cannot reconstruct BASE0 or
        // expose the previous committed floor as ordinary admission state.
        self.writer_may_have_begun = true;
        self.stage = Some(stage);
        Ok(token)
    }

    fn validate_new_plan(&self, plan: &[ClaimBinding], prior_cursor: u8) -> Option<u8> {
        if plan.len() != FULL_INITIAL_THRESHOLD * PLANNED_ATTEMPTS_PER_ROLE {
            return None;
        }
        let mut seen_cells = [false; CELL_COUNT];
        let mut role_counts = [0_usize; FULL_INITIAL_THRESHOLD];
        let mut highest = usize::from(prior_cursor);
        for binding in plan {
            let index = binding.cell.index();
            let role = usize::from(binding.role);
            if !binding.cell.is_valid()
                || index < usize::from(prior_cursor)
                || role >= FULL_INITIAL_THRESHOLD
                || seen_cells[index]
                || self.cell_is_owned(binding.cell)
            {
                return None;
            }
            seen_cells[index] = true;
            role_counts[role] += 1;
            highest = highest.max(index.checked_add(1)?);
        }
        if !role_counts
            .into_iter()
            .all(|count| count == PLANNED_ATTEMPTS_PER_ROLE)
            || highest > CELL_COUNT
        {
            return None;
        }
        u8::try_from(highest).ok()
    }

    fn current_token(&self) -> Result<StageToken, ModelError> {
        self.stage
            .as_ref()
            .map(ActiveStage::token)
            .ok_or(ModelError::NoActiveStage)
    }

    fn resume(&self, token: &StageToken) -> Result<(), ModelError> {
        if self.stage.is_none() {
            return Err(ModelError::NoActiveStage);
        }
        let FloorView::Recovering { token: current, .. } = self.decode() else {
            return Err(ModelError::NotRecovering);
        };
        (current == *token)
            .then_some(())
            .ok_or(ModelError::WrongStageToken)
    }

    fn preclaim(
        &mut self,
        token: &StageToken,
        cell: Cell,
        role: u8,
    ) -> Result<StageToken, ModelError> {
        self.resume(token)?;
        if usize::from(role) >= FULL_INITIAL_THRESHOLD {
            return Err(ModelError::InvalidRole);
        }
        if !cell.is_valid() || self.cell_is_owned(cell) {
            // A cell in the frozen current plan is reserved by that plan and
            // remains eligible for its exact role until used.  Other owners
            // are unavailable.
            let in_current_plan = self
                .stage
                .as_ref()
                .is_some_and(|stage| stage.ordered_map.contains(&ClaimBinding { cell, role }));
            if !in_current_plan {
                return Err(ModelError::CellUnavailable);
            }
        }
        let stage = self.stage.as_mut().expect("resume proved an active stage");
        let Some(plan_index) = stage
            .ordered_map
            .iter()
            .position(|binding| *binding == ClaimBinding { cell, role })
        else {
            return Err(ModelError::InvalidPlan);
        };
        if self.consumed.contains(&cell) || stage.live.iter().any(|claim| claim.cell == cell) {
            return Err(ModelError::CellUnavailable);
        }
        if stage.live.iter().any(|claim| claim.role == role) {
            return Err(ModelError::RoleAlreadyLive);
        }
        if stage.ordered_map[..plan_index]
            .iter()
            .filter(|binding| binding.role == role)
            .any(|binding| !stage.consumed_attempts.contains(&binding.cell))
        {
            return Err(ModelError::InvalidPlan);
        }
        stage.live.push(LiveClaim {
            cell,
            role,
            state: LiveClaimState::Preclaimed,
            durable_clean_binding: None,
        });
        Ok(stage.token())
    }

    fn launch(&mut self, token: &StageToken, cell: Cell) -> Result<StageToken, ModelError> {
        self.resume(token)?;
        let stage = self.stage.as_mut().expect("resume proved an active stage");
        let claim = stage
            .live
            .iter_mut()
            .find(|claim| claim.cell == cell)
            .ok_or(ModelError::NotPreclaimed)?;
        if claim.state != LiveClaimState::Preclaimed {
            return Err(ModelError::NotPreclaimed);
        }
        claim.state = LiveClaimState::MayHaveLaunched;
        Ok(stage.token())
    }

    fn record_clean(
        &mut self,
        token: &StageToken,
        receipt: FreshCleanReceipt,
    ) -> Result<StageToken, ModelError> {
        self.resume(token)?;
        let stage = self.stage.as_ref().expect("resume proved an active stage");
        if receipt.generation != stage.id.generation
            || !receipt.eop
            || !receipt.fresh_array_read
            || receipt.ecc != FreshEccStatus::Clean
        {
            return Err(ModelError::InvalidReceipt);
        }
        let claim = stage
            .live
            .iter()
            .find(|claim| claim.cell == receipt.cell)
            .ok_or(ModelError::InvalidReceipt)?;
        if claim.state != LiveClaimState::MayHaveLaunched {
            return Err(ModelError::NotLaunched);
        }
        let expected = PlainRecord {
            target: stage.id.target,
            role: claim.role,
        };
        if decode_plain(receipt.observed) != Some(expected) {
            return Err(ModelError::InvalidReceipt);
        }

        let stage = self.stage.as_mut().expect("resume proved an active stage");
        let claim = stage
            .live
            .iter_mut()
            .find(|claim| claim.cell == receipt.cell)
            .expect("claim was checked before mutable borrow");
        claim.state = LiveClaimState::Clean;
        claim.durable_clean_binding = Some(durable_clean_binding(receipt));
        Ok(stage.token())
    }

    /// Model a reset or complete power cut.  An unrecorded preclaim is
    /// conservative: whether or not launch actually occurred, the exact QW is
    /// durably consumed and cannot become virgin again.
    fn power_cut(&mut self) {
        self.boot_epoch = self
            .boot_epoch
            .checked_add(1)
            .expect("host boot epoch overflow");
        self.base0_fresh_this_boot = false;
        for replica in self.groups.iter_mut().flat_map(|group| &mut group.replicas) {
            if replica.health == ReplicaHealth::FreshClean {
                replica.health = ReplicaHealth::NeedsFreshValidation;
            }
        }
        let Some(stage) = self.stage.as_mut() else {
            return;
        };
        let mut retained = Vec::with_capacity(stage.live.len());
        for claim in stage.live.drain(..) {
            match claim.state {
                LiveClaimState::Clean => retained.push(LiveClaim {
                    state: LiveClaimState::NeedsFreshValidation,
                    ..claim
                }),
                LiveClaimState::NeedsFreshValidation => retained.push(claim),
                LiveClaimState::Preclaimed | LiveClaimState::MayHaveLaunched => {
                    if !self.consumed.contains(&claim.cell) {
                        self.consumed.push(claim.cell);
                    }
                    stage.consumed_attempts.push(claim.cell);
                }
            }
        }
        stage.live = retained;
    }

    fn revalidate_base0(&mut self, receipt: FreshBase0Receipt) -> Result<(), ModelError> {
        if !self.groups.is_empty()
            || self.stage.is_some()
            || !self.consumed.is_empty()
            || self.writer_may_have_begun
            || self.ambiguous_durable_state
            || receipt.boot_epoch != self.boot_epoch
            || !receipt.all_reserved_cells_ff
            || !receipt.fresh_array_reads
            || receipt.ecc != FreshEccStatus::Clean
            || !receipt.no_missing_durable_intent
        {
            return Err(ModelError::InvalidReceipt);
        }
        self.base0_fresh_this_boot = true;
        Ok(())
    }

    fn bind_stage_for_revalidation(&self, token: &StageToken) -> Result<(), ModelError> {
        let stage = self.stage.as_ref().ok_or(ModelError::NoActiveStage)?;
        if self.ambiguous_durable_state
            || !self.writer_may_have_begun
            || !self.ownership_is_globally_unique()
            || self.groups_are_well_formed().is_err()
            || !self.stage_is_well_formed(stage, self.highest_group())
        {
            return Err(ModelError::NotRecovering);
        }
        (stage.token() == *token)
            .then_some(())
            .ok_or(ModelError::WrongStageToken)
    }

    /// Revalidate a pre-cut clean active replica in the current boot.  A
    /// corrected/uncorrectable/malformed observation consumes the exact cell
    /// with zero weight; only an exact fresh clean decode restores `Clean`.
    fn revalidate_active_clean(
        &mut self,
        token: &StageToken,
        receipt: FreshRevalidationReceipt,
    ) -> Result<(RevalidationOutcome, StageToken), ModelError> {
        self.bind_stage_for_revalidation(token)?;
        let stage = self.stage.as_ref().expect("binding proved an active stage");
        let Some(index) = stage.live.iter().position(|claim| {
            claim.cell == receipt.cell && claim.state == LiveClaimState::NeedsFreshValidation
        }) else {
            return Err(ModelError::NotAwaitingFreshValidation);
        };
        let expected = PlainRecord {
            target: stage.id.target,
            role: stage.live[index].role,
        };
        let durable_clean_binding = stage.live[index]
            .durable_clean_binding
            .ok_or(ModelError::InvalidReceipt)?;
        let outcome = classify_revalidation(
            receipt,
            self.boot_epoch,
            stage.id.generation,
            expected,
            durable_clean_binding,
        )?;

        let stage = self.stage.as_mut().expect("binding proved an active stage");
        match outcome {
            RevalidationOutcome::FreshClean => {
                stage.live[index].state = LiveClaimState::Clean;
            }
            RevalidationOutcome::Rejected => {
                let cell = stage.live.remove(index).cell;
                if !self.consumed.contains(&cell) {
                    self.consumed.push(cell);
                }
                if !stage.consumed_attempts.contains(&cell) {
                    stage.consumed_attempts.push(cell);
                }
            }
        }
        Ok((outcome, stage.token()))
    }

    /// Revalidate one authoritative committed replica for the current boot.
    /// Rejected observations retain their committed identity but have zero
    /// quorum weight; the decoder never falls through to an older floor.
    fn revalidate_committed(
        &mut self,
        group_id: GroupId,
        receipt: FreshRevalidationReceipt,
    ) -> Result<RevalidationOutcome, ModelError> {
        let group = self
            .groups
            .iter()
            .find(|group| group.id == group_id)
            .ok_or(ModelError::InvalidReceipt)?;
        let replica = group
            .replicas
            .iter()
            .find(|replica| replica.cell == receipt.cell)
            .ok_or(ModelError::InvalidReceipt)?;
        if replica.health != ReplicaHealth::NeedsFreshValidation {
            return Err(ModelError::NotAwaitingFreshValidation);
        }
        let expected = PlainRecord {
            target: group.id.target,
            role: replica.role,
        };
        let outcome = classify_revalidation(
            receipt,
            self.boot_epoch,
            group.id.generation,
            expected,
            replica.durable_clean_binding,
        )?;
        let replica = self
            .groups
            .iter_mut()
            .find(|group| group.id == group_id)
            .and_then(|group| {
                group
                    .replicas
                    .iter_mut()
                    .find(|replica| replica.cell == receipt.cell)
            })
            .expect("replica was checked before mutable borrow");
        replica.health = match outcome {
            RevalidationOutcome::FreshClean => ReplicaHealth::FreshClean,
            RevalidationOutcome::Rejected => ReplicaHealth::Rejected,
        };
        Ok(outcome)
    }

    fn mark_complete_torn(&mut self) -> Result<(), ModelError> {
        self.stage.as_ref().ok_or(ModelError::NoActiveStage)?;
        self.ambiguous_durable_state = true;
        Ok(())
    }

    fn complete(&mut self, token: &StageToken) -> Result<GroupId, ModelError> {
        self.resume(token)?;
        if !self.ownership_is_globally_unique() {
            return Err(ModelError::OwnershipInvalid);
        }
        let stage = self.stage.as_ref().expect("resume proved an active stage");
        let mut roles = [false; FULL_INITIAL_THRESHOLD];
        for claim in &stage.live {
            if claim.state == LiveClaimState::Clean {
                roles[usize::from(claim.role)] = true;
            }
        }
        let clean_count = roles.into_iter().filter(|present| *present).count();
        if clean_count != FULL_INITIAL_THRESHOLD
            || stage.live.len() != FULL_INITIAL_THRESHOLD
            || stage
                .live
                .iter()
                .any(|claim| claim.state != LiveClaimState::Clean)
        {
            return Err(ModelError::InitialThresholdNotMet);
        }

        let stage = self.stage.take().expect("active stage checked above");
        let stage_binding = stage_digest(
            StageDigestFields {
                codec_id: &stage.codec_id,
                id: stage.id,
                prior: stage.prior,
                prior_f: stage.prior_f,
                prior_digest: &stage.prior_digest,
                prior_cursor: stage.prior_cursor,
                allocation_cursor: stage.allocation_cursor,
                candidate_binding: &stage.candidate_binding,
            },
            &stage.ordered_map,
        );
        let replicas: Vec<Replica> = stage
            .live
            .iter()
            .map(|claim| Replica {
                cell: claim.cell,
                role: claim.role,
                health: ReplicaHealth::FreshClean,
                durable_clean_binding: claim
                    .durable_clean_binding
                    .expect("a clean claim carries durable launch evidence"),
            })
            .collect();
        let state_digest =
            completed_group_digest(stage_binding, &replicas, &stage.consumed_attempts);
        let group = CommittedGroup {
            codec_id: stage.codec_id,
            id: stage.id,
            prior: stage.prior,
            prior_f: stage.prior_f,
            prior_digest: stage.prior_digest,
            prior_cursor: stage.prior_cursor,
            state_digest,
            allocation_cursor: stage.allocation_cursor,
            candidate_binding: stage.candidate_binding,
            ordered_plan: stage.ordered_map,
            consumed_attempts: stage.consumed_attempts,
            replicas,
            clean_at_complete: clean_count,
            initial_threshold: FULL_INITIAL_THRESHOLD,
            degraded_threshold: DEGRADED_THRESHOLD,
        };
        let id = group.id;
        let head = CommittedHead {
            id,
            state_digest: group.state_digest,
            allocation_cursor: group.allocation_cursor,
        };
        self.groups.push(group);
        self.committed_head = Some(head);
        // Once any group has committed, a later total loss or blank-looking
        // record bank can never reconstruct canonical BASE0.
        self.base0_proven = false;
        self.writer_may_have_begun = false;
        Ok(id)
    }

    fn reject_replica(&mut self, group: GroupId, cell: Cell) {
        let replica = self
            .groups
            .iter_mut()
            .find(|candidate| candidate.id == group)
            .and_then(|candidate| {
                candidate
                    .replicas
                    .iter_mut()
                    .find(|replica| replica.cell == cell)
            })
            .expect("test requested an existing replica");
        replica.health = ReplicaHealth::Rejected;
    }

    fn cell_is_owned(&self, cell: Cell) -> bool {
        self.consumed.contains(&cell)
            || self
                .groups
                .iter()
                .flat_map(|group| &group.ordered_plan)
                .any(|binding| binding.cell == cell)
            || self
                .stage
                .as_ref()
                .into_iter()
                .flat_map(|stage| &stage.ordered_map)
                .any(|binding| binding.cell == cell)
    }

    fn ownership_is_globally_unique(&self) -> bool {
        let mut owner = [false; CELL_COUNT];
        let mut consumed_reference = [false; CELL_COUNT];
        let mut claim = |cell: Cell| {
            let Some(slot) = owner.get_mut(cell.index()) else {
                return false;
            };
            if *slot {
                false
            } else {
                *slot = true;
                true
            }
        };

        for cell in &self.consumed {
            if !claim(*cell) {
                return false;
            }
        }
        for group in &self.groups {
            for binding in &group.ordered_plan {
                if !binding.cell.is_valid() {
                    return false;
                }
                if group.consumed_attempts.contains(&binding.cell) {
                    if consumed_reference[binding.cell.index()] {
                        return false;
                    }
                    consumed_reference[binding.cell.index()] = true;
                    continue;
                }
                if !claim(binding.cell) {
                    return false;
                }
            }
        }
        if let Some(stage) = &self.stage {
            let mut live_cells = [false; CELL_COUNT];
            for live in &stage.live {
                if !live.cell.is_valid()
                    || self.consumed.contains(&live.cell)
                    || live_cells[live.cell.index()]
                {
                    return false;
                }
                live_cells[live.cell.index()] = true;
            }
            for binding in &stage.ordered_map {
                if !binding.cell.is_valid() {
                    return false;
                }
                if self.consumed.contains(&binding.cell) {
                    if !stage.consumed_attempts.contains(&binding.cell)
                        || consumed_reference[binding.cell.index()]
                    {
                        return false;
                    }
                    consumed_reference[binding.cell.index()] = true;
                    continue;
                }
                if !claim(binding.cell) {
                    return false;
                }
            }
        }
        self.consumed
            .iter()
            .all(|cell| consumed_reference[cell.index()])
    }

    fn groups_are_well_formed(&self) -> Result<(), ()> {
        let mut ordered: Vec<&CommittedGroup> = self.groups.iter().collect();
        ordered.sort_by_key(|group| group.id.generation);
        for (index, group) in ordered.iter().enumerate() {
            if group.codec_id != CODEC_ID
                || group.id.generation == 0
                || group.id.target == 0
                || group.id.target > MAX_TARGET
                || group.initial_threshold != FULL_INITIAL_THRESHOLD
                || group.degraded_threshold != DEGRADED_THRESHOLD
                || group.clean_at_complete != group.initial_threshold
                || group.replicas.len() != group.initial_threshold
            {
                return Err(());
            }
            let (expected_prior, expected_prior_f, expected_digest, expected_cursor) = if index == 0
            {
                (None, 0, BASE0_DIGEST, 0)
            } else {
                let prior = ordered[index - 1];
                (
                    Some(prior.id),
                    prior.id.target,
                    prior.state_digest,
                    prior.allocation_cursor,
                )
            };
            if group.prior != expected_prior
                || group.prior_f != expected_prior_f
                || group.prior_digest != expected_digest
                || group.prior_cursor != expected_cursor
            {
                return Err(());
            }

            let mut plan_cells = [false; CELL_COUNT];
            let mut planned_role_counts = [0_usize; FULL_INITIAL_THRESHOLD];
            let mut expected_allocation_cursor = usize::from(expected_cursor);
            for binding in &group.ordered_plan {
                let role = usize::from(binding.role);
                let cell = binding.cell.index();
                if !binding.cell.is_valid()
                    || cell < usize::from(expected_cursor)
                    || role >= FULL_INITIAL_THRESHOLD
                    || plan_cells[cell]
                {
                    return Err(());
                }
                plan_cells[cell] = true;
                planned_role_counts[role] += 1;
                expected_allocation_cursor = expected_allocation_cursor.max(cell + 1);
            }
            let mut consumed_cells = [false; CELL_COUNT];
            for consumed in &group.consumed_attempts {
                if !consumed.is_valid()
                    || consumed_cells[consumed.index()]
                    || !self.consumed.contains(consumed)
                    || !group
                        .ordered_plan
                        .iter()
                        .any(|binding| binding.cell == *consumed)
                {
                    return Err(());
                }
                consumed_cells[consumed.index()] = true;
            }
            if group.ordered_plan.iter().any(|binding| {
                self.consumed.contains(&binding.cell)
                    != group.consumed_attempts.contains(&binding.cell)
            }) {
                return Err(());
            }

            let stage_binding = stage_digest(
                StageDigestFields {
                    codec_id: &group.codec_id,
                    id: group.id,
                    prior: group.prior,
                    prior_f: group.prior_f,
                    prior_digest: &group.prior_digest,
                    prior_cursor: group.prior_cursor,
                    allocation_cursor: group.allocation_cursor,
                    candidate_binding: &group.candidate_binding,
                },
                &group.ordered_plan,
            );
            if !planned_role_counts
                .into_iter()
                .all(|count| count == PLANNED_ATTEMPTS_PER_ROLE)
                || usize::from(group.allocation_cursor) != expected_allocation_cursor
                || group.state_digest
                    != completed_group_digest(
                        stage_binding,
                        &group.replicas,
                        &group.consumed_attempts,
                    )
            {
                return Err(());
            }

            let mut roles = [false; FULL_INITIAL_THRESHOLD];
            for replica in &group.replicas {
                let role = usize::from(replica.role);
                if !replica.cell.is_valid() || role >= FULL_INITIAL_THRESHOLD || roles[role] {
                    return Err(());
                }
                if replica.durable_clean_binding
                    != expected_durable_clean_binding(
                        replica.cell,
                        group.id.generation,
                        group.id.target,
                        replica.role,
                    )
                {
                    return Err(());
                }
                if !group.ordered_plan.contains(&ClaimBinding {
                    cell: replica.cell,
                    role: replica.role,
                }) || group.consumed_attempts.contains(&replica.cell)
                {
                    return Err(());
                }
                roles[role] = true;
            }
            if !roles.into_iter().all(|present| present) {
                return Err(());
            }
            if index != 0 {
                let prior = ordered[index - 1];
                if group.id.generation <= prior.id.generation || group.id.target <= prior.id.target
                {
                    return Err(());
                }
            }
        }
        Ok(())
    }

    fn stage_is_well_formed(&self, stage: &ActiveStage, highest: Option<&CommittedGroup>) -> bool {
        let prior_matches = match highest {
            Some(group) => {
                stage.prior == Some(group.id)
                    && stage.prior_f == group.id.target
                    && stage.prior_digest == group.state_digest
                    && stage.prior_cursor == group.allocation_cursor
            }
            None => {
                stage.prior.is_none()
                    && stage.prior_f == 0
                    && stage.prior_digest == BASE0_DIGEST
                    && stage.prior_cursor == 0
                    && self.base0_proven
            }
        };
        if stage.codec_id != CODEC_ID
            || !self.writer_may_have_begun
            || !prior_matches
            || stage.id.target <= stage.prior_f
            || stage.id.target > MAX_TARGET
        {
            return false;
        }
        if highest.is_some_and(|group| stage.id.generation <= group.id.generation) {
            return false;
        }

        let mut history_cells = [false; CELL_COUNT];
        let mut planned_role_counts = [0_usize; FULL_INITIAL_THRESHOLD];
        let mut expected_cursor = usize::from(stage.prior_cursor);
        for binding in &stage.ordered_map {
            let role = usize::from(binding.role);
            let cell = binding.cell.index();
            if !binding.cell.is_valid()
                || cell < usize::from(stage.prior_cursor)
                || role >= FULL_INITIAL_THRESHOLD
                || history_cells[cell]
            {
                return false;
            }
            history_cells[cell] = true;
            planned_role_counts[role] += 1;
            expected_cursor = expected_cursor.max(cell + 1);
        }
        if !planned_role_counts
            .into_iter()
            .all(|count| count == PLANNED_ATTEMPTS_PER_ROLE)
            || usize::from(stage.allocation_cursor) != expected_cursor
            || stage.ordered_map.iter().any(|binding| {
                self.consumed.contains(&binding.cell)
                    != stage.consumed_attempts.contains(&binding.cell)
            })
        {
            return false;
        }
        let mut live_roles = [false; FULL_INITIAL_THRESHOLD];
        for live in &stage.live {
            let role = usize::from(live.role);
            let binding_state_is_valid = match (live.state, live.durable_clean_binding) {
                (LiveClaimState::Preclaimed | LiveClaimState::MayHaveLaunched, None) => true,
                (LiveClaimState::Clean | LiveClaimState::NeedsFreshValidation, Some(binding)) => {
                    binding
                        == expected_durable_clean_binding(
                            live.cell,
                            stage.id.generation,
                            stage.id.target,
                            live.role,
                        )
                }
                _ => false,
            };
            if !live.cell.is_valid()
                || role >= FULL_INITIAL_THRESHOLD
                || live_roles[role]
                || !binding_state_is_valid
                || !stage.ordered_map.contains(&ClaimBinding {
                    cell: live.cell,
                    role: live.role,
                })
            {
                return false;
            }
            live_roles[role] = true;
        }
        let mut consumed_seen = [false; CELL_COUNT];
        for consumed in &stage.consumed_attempts {
            if !consumed.is_valid()
                || consumed_seen[consumed.index()]
                || !self.consumed.contains(consumed)
                || stage.live.iter().any(|live| live.cell == *consumed)
                || !stage
                    .ordered_map
                    .iter()
                    .any(|binding| binding.cell == *consumed)
            {
                return false;
            }
            consumed_seen[consumed.index()] = true;
        }
        true
    }
}

fn planned_group(first_cell: u8) -> Vec<ClaimBinding> {
    // Two pre-bound attempts per replica role.  The second entry for a role is
    // replacement capacity and cannot be preclaimed until the first is
    // durably consumed.  This 3+3 shape is illustrative, not selected.
    vec![
        ClaimBinding {
            cell: Cell(first_cell),
            role: 0,
        },
        ClaimBinding {
            cell: Cell(first_cell + 3),
            role: 0,
        },
        ClaimBinding {
            cell: Cell(first_cell + 1),
            role: 1,
        },
        ClaimBinding {
            cell: Cell(first_cell + 4),
            role: 1,
        },
        ClaimBinding {
            cell: Cell(first_cell + 2),
            role: 2,
        },
        ClaimBinding {
            cell: Cell(first_cell + 5),
            role: 2,
        },
    ]
}

fn clean_one_role(model: &mut FloorModel, mut token: StageToken, cell: u8, role: u8) -> StageToken {
    let cell = Cell::checked(cell).unwrap();
    token = model.preclaim(&token, cell, role).unwrap();
    token = model.launch(&token, cell).unwrap();
    let receipt = FreshCleanReceipt::clean(
        cell,
        token.id.generation,
        encode_plain(PlainRecord {
            target: token.id.target,
            role,
        }),
    );
    model.record_clean(&token, receipt).unwrap()
}

fn revalidation_receipt(
    boot_epoch: u64,
    generation: u32,
    target: u32,
    cell: Cell,
    role: u8,
    ecc: FreshEccStatus,
) -> FreshRevalidationReceipt {
    let observed = encode_plain(PlainRecord { target, role });
    FreshRevalidationReceipt {
        cell,
        generation,
        boot_epoch,
        observed,
        prior_durable_clean_binding: expected_durable_clean_binding(cell, generation, target, role),
        ecc,
        fresh_array_read: true,
    }
}

fn commit_group(model: &mut FloorModel, target: u32, first_cell: u8) -> GroupId {
    let mut token = model
        .begin(target, [target as u8; 16], planned_group(first_cell))
        .unwrap();
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        token = clean_one_role(model, token, first_cell + role, role);
    }
    model.complete(&token).unwrap()
}

fn commit_group_with_role0_replacement(
    model: &mut FloorModel,
    target: u32,
    first_cell: u8,
) -> GroupId {
    let mut token = model
        .begin(target, [target as u8; 16], planned_group(first_cell))
        .unwrap();
    token = model.preclaim(&token, Cell(first_cell), 0).unwrap();
    model.launch(&token, Cell(first_cell)).unwrap();
    model.power_cut();
    token = model.current_token().unwrap();
    token = clean_one_role(model, token, first_cell + 3, 0);
    token = clean_one_role(model, token, first_cell + 1, 1);
    token = clean_one_role(model, token, first_cell + 2, 2);
    model.complete(&token).unwrap()
}

fn rebind_highest_group_for_tamper_test(model: &mut FloorModel) {
    let index = model.groups.len() - 1;
    let (id, state_digest, allocation_cursor) = {
        let group = &mut model.groups[index];
        let stage_binding = stage_digest(
            StageDigestFields {
                codec_id: &group.codec_id,
                id: group.id,
                prior: group.prior,
                prior_f: group.prior_f,
                prior_digest: &group.prior_digest,
                prior_cursor: group.prior_cursor,
                allocation_cursor: group.allocation_cursor,
                candidate_binding: &group.candidate_binding,
            },
            &group.ordered_plan,
        );
        group.state_digest =
            completed_group_digest(stage_binding, &group.replicas, &group.consumed_attempts);
        (group.id, group.state_digest, group.allocation_cursor)
    };
    model.committed_head = Some(CommittedHead {
        id,
        state_digest,
        allocation_cursor,
    });
}

#[test]
fn typed_decoder_distinguishes_initial_and_degraded_thresholds() {
    let mut model = FloorModel::blank();
    let first = commit_group(&mut model, 4, 0);
    assert_eq!(
        model.decode(),
        FloorView::Steady {
            floor: 4,
            group: Some(first)
        }
    );

    let mut token = model.begin(5, [5; 16], planned_group(6)).unwrap();
    token = clean_one_role(&mut model, token, 6, 0);
    token = clean_one_role(&mut model, token, 7, 1);
    assert_eq!(
        model.complete(&token),
        Err(ModelError::InitialThresholdNotMet)
    );
    assert!(matches!(
        model.decode(),
        FloorView::Recovering { target: 5, .. }
    ));

    token = clean_one_role(&mut model, token, 8, 2);
    let second = model.complete(&token).unwrap();
    model.reject_replica(second, Cell(6));
    assert!(matches!(model.decode(), FloorView::Steady { floor: 5, .. }));

    model.reject_replica(second, Cell(7));
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::LostHighestQuorum)
    );
    assert_ne!(
        model.decode(),
        FloorView::Steady {
            floor: 4,
            group: Some(first)
        }
    );
}

#[test]
fn decoder_classes_are_mutually_exclusive_and_frontier_is_never_committed() {
    let mut model = FloorModel::blank();
    assert!(matches!(model.decode(), FloorView::Steady { floor: 0, .. }));
    let token = model.begin(1, [1; 16], planned_group(0)).unwrap();
    assert!(matches!(
        model.decode(),
        FloorView::Recovering { target: 1, .. }
    ));
    assert_ne!(
        model.decode(),
        FloorView::Steady {
            floor: 1,
            group: None
        }
    );
    model.mark_complete_torn().unwrap();
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::AmbiguousDurableState)
    );
    assert_eq!(model.resume(&token), Err(ModelError::NotRecovering));
}

#[test]
fn lost_or_torn_stage_after_begin_never_reconstructs_base_or_prior_floor() {
    let mut base = FloorModel::blank();
    base.begin(1, [1; 16], planned_group(0)).unwrap();
    assert!(base.writer_may_have_begun);
    base.stage = None; // model torn/lost durable-stage activation/body
    assert_eq!(
        base.decode(),
        FloorView::Unknown(FloorFault::MissingDurableStage)
    );
    assert_ne!(
        base.decode(),
        FloorView::Steady {
            floor: 0,
            group: None,
        }
    );

    let mut prior = FloorModel::blank();
    let committed = commit_group(&mut prior, 1, 0);
    prior.begin(2, [2; 16], planned_group(6)).unwrap();
    prior.stage = None;
    assert_eq!(
        prior.decode(),
        FloorView::Unknown(FloorFault::MissingDurableStage)
    );
    assert_ne!(
        prior.decode(),
        FloorView::Steady {
            floor: 1,
            group: Some(committed),
        }
    );
}

#[test]
fn total_committed_group_loss_never_reconstructs_base0() {
    let mut model = FloorModel::blank();
    commit_group(&mut model, 1, 0);
    assert!(!model.base0_proven);
    model.groups.clear(); // model total loss/blank-looking committed evidence
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::MissingOrReplayedCommittedHead)
    );
    assert_ne!(
        model.decode(),
        FloorView::Steady {
            floor: 0,
            group: None,
        }
    );
}

#[test]
fn loss_of_newest_group_never_exposes_an_older_committed_floor() {
    let mut model = FloorModel::blank();
    let older = commit_group(&mut model, 1, 0);
    commit_group(&mut model, 2, 6);
    model.groups.pop(); // model total loss of only the newest group evidence
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::MissingOrReplayedCommittedHead)
    );
    assert_ne!(
        model.decode(),
        FloorView::Steady {
            floor: 1,
            group: Some(older),
        }
    );
}

#[test]
fn begin_freezes_the_complete_plan_and_token_binding_before_launch() {
    let mut model = FloorModel::blank();
    assert_eq!(
        model.begin(
            1,
            [1; 16],
            vec![ClaimBinding {
                cell: Cell(0),
                role: 0,
            }],
        ),
        Err(ModelError::InvalidPlan)
    );
    assert_eq!(
        model.begin(
            1,
            [1; 16],
            vec![
                ClaimBinding {
                    cell: Cell(0),
                    role: 0,
                },
                ClaimBinding {
                    cell: Cell(0),
                    role: 1,
                },
                ClaimBinding {
                    cell: Cell(2),
                    role: 2,
                },
            ],
        ),
        Err(ModelError::InvalidPlan)
    );

    let plan = planned_group(0);
    let token = model.begin(1, [0xa5; 16], plan.clone()).unwrap();
    assert_eq!(token.codec_id, CODEC_ID);
    assert_eq!(
        token.id,
        GroupId {
            generation: 1,
            target: 1
        }
    );
    assert_eq!(token.prior, None);
    assert_eq!(token.prior_digest, BASE0_DIGEST);
    assert_eq!(token.prior_cursor, 0);
    assert_eq!(token.allocation_cursor, 6);
    assert_eq!(token.candidate_binding, [0xa5; 16]);
    assert_eq!(token.ordered_map, plan);

    // The replacement is already bound but cannot be selected until its
    // preceding role attempt is durably consumed.
    assert_eq!(
        model.preclaim(&token, Cell(3), 0),
        Err(ModelError::InvalidPlan)
    );
    let claimed = model.preclaim(&token, Cell(0), 0).unwrap();
    let launched = model.launch(&claimed, Cell(0)).unwrap();
    assert_eq!(launched.ordered_map, token.ordered_map);

    for mut stale in [
        {
            let mut value = launched.clone();
            value.codec_id[0] ^= 1;
            value
        },
        {
            let mut value = launched.clone();
            value.id.generation += 1;
            value
        },
        {
            let mut value = launched.clone();
            value.id.target += 1;
            value
        },
        {
            let mut value = launched.clone();
            value.prior_digest[0] ^= 1;
            value
        },
        {
            let mut value = launched.clone();
            value.prior_cursor += 1;
            value
        },
        {
            let mut value = launched.clone();
            value.allocation_cursor += 1;
            value
        },
        {
            let mut value = launched.clone();
            value.candidate_binding[0] ^= 1;
            value
        },
    ] {
        assert_eq!(model.resume(&stale), Err(ModelError::WrongStageToken));
        stale.ordered_map.reverse();
        assert_eq!(model.resume(&stale), Err(ModelError::WrongStageToken));
    }
}

#[test]
fn floor_model_rejects_reserved_targets() {
    for target in [MAX_TARGET + 1, u32::MAX] {
        let mut model = FloorModel::blank();
        assert_eq!(
            model.begin(target, [0; 16], planned_group(0)),
            Err(ModelError::InvalidTarget)
        );
    }

    let mut corrupted = FloorModel::blank();
    let group = commit_group(&mut corrupted, 1, 0);
    corrupted
        .groups
        .iter_mut()
        .find(|candidate| candidate.id == group)
        .unwrap()
        .id
        .target = MAX_TARGET + 1;
    assert_eq!(
        corrupted.decode(),
        FloorView::Unknown(FloorFault::InvalidCommittedGroup)
    );
}

#[test]
fn raw_decoder_rejects_zero_generation_or_zero_target_even_with_fresh_bindings() {
    for (generation, target) in [(0, 1), (1, 0)] {
        let mut model = FloorModel::blank();
        commit_group(&mut model, 1, 0);
        model.groups[0].id = GroupId { generation, target };
        rebind_highest_group_for_tamper_test(&mut model);
        assert_eq!(
            model.decode(),
            FloorView::Unknown(FloorFault::InvalidCommittedGroup)
        );
    }
}

#[test]
fn completion_binding_covers_exact_prior_identity_and_floor() {
    let mut wrong_floor = FloorModel::blank();
    commit_group(&mut wrong_floor, 1, 0);
    commit_group(&mut wrong_floor, 2, 6);
    let original = wrong_floor.groups[1].state_digest;
    wrong_floor.groups[1].prior_f = 0;
    rebind_highest_group_for_tamper_test(&mut wrong_floor);
    assert_ne!(wrong_floor.groups[1].state_digest, original);
    assert_eq!(
        wrong_floor.decode(),
        FloorView::Unknown(FloorFault::InvalidCommittedGroup)
    );

    let mut wrong_identity = FloorModel::blank();
    commit_group(&mut wrong_identity, 1, 0);
    commit_group(&mut wrong_identity, 2, 6);
    let original = wrong_identity.groups[1].state_digest;
    wrong_identity.groups[1].prior = None;
    wrong_identity.groups[1].prior_f = 0;
    wrong_identity.groups[1].prior_digest = BASE0_DIGEST;
    wrong_identity.groups[1].prior_cursor = 0;
    rebind_highest_group_for_tamper_test(&mut wrong_identity);
    assert_ne!(wrong_identity.groups[1].state_digest, original);
    assert_eq!(
        wrong_identity.decode(),
        FloorView::Unknown(FloorFault::InvalidCommittedGroup)
    );
}

#[test]
fn global_qw_ownership_rejects_every_alias_family() {
    let mut committed_alias = FloorModel::blank();
    let group = commit_group(&mut committed_alias, 1, 0);
    committed_alias
        .groups
        .iter_mut()
        .find(|candidate| candidate.id == group)
        .unwrap()
        .ordered_plan[1]
        .cell = Cell(0);
    assert_eq!(
        committed_alias.decode(),
        FloorView::Unknown(FloorFault::OwnershipAlias)
    );

    let mut cross_group_alias = FloorModel::blank();
    commit_group(&mut cross_group_alias, 1, 0);
    let mut token = cross_group_alias
        .begin(2, [2; 16], planned_group(6))
        .unwrap();
    // Bypass the writer API to model a corrupt/stale role map.
    let stage = cross_group_alias.stage.as_mut().unwrap();
    stage.ordered_map.push(ClaimBinding {
        cell: Cell(0),
        role: 0,
    });
    stage.live.push(LiveClaim {
        cell: Cell(0),
        role: 0,
        state: LiveClaimState::Preclaimed,
        durable_clean_binding: None,
    });
    token.ordered_map.push(ClaimBinding {
        cell: Cell(0),
        role: 0,
    });
    assert_eq!(
        cross_group_alias.decode(),
        FloorView::Unknown(FloorFault::OwnershipAlias)
    );

    let mut consumed_alias = FloorModel::blank();
    let token = consumed_alias.begin(1, [1; 16], planned_group(0)).unwrap();
    consumed_alias.preclaim(&token, Cell(0), 0).unwrap();
    consumed_alias.power_cut();
    assert!(consumed_alias.consumed.contains(&Cell(0)));
    let stage = consumed_alias.stage.as_mut().unwrap();
    stage.live.push(LiveClaim {
        cell: Cell(0),
        role: 0,
        state: LiveClaimState::Preclaimed,
        durable_clean_binding: None,
    });
    assert_eq!(
        consumed_alias.decode(),
        FloorView::Unknown(FloorFault::OwnershipAlias)
    );
}

#[test]
fn one_consumed_cell_cannot_be_referenced_by_two_group_or_stage_maps() {
    let mut cross_group = FloorModel::blank();
    commit_group_with_role0_replacement(&mut cross_group, 1, 0);
    commit_group(&mut cross_group, 2, 6);
    assert_eq!(cross_group.consumed, vec![Cell(0)]);
    cross_group.groups[1].ordered_plan[0].cell = Cell(0);
    cross_group.groups[1].consumed_attempts.push(Cell(0));
    assert!(!cross_group.ownership_is_globally_unique());
    assert_eq!(
        cross_group.decode(),
        FloorView::Unknown(FloorFault::OwnershipAlias)
    );

    let mut committed_stage = FloorModel::blank();
    commit_group_with_role0_replacement(&mut committed_stage, 1, 0);
    committed_stage.begin(2, [2; 16], planned_group(6)).unwrap();
    let stage = committed_stage.stage.as_mut().unwrap();
    stage.ordered_map[0].cell = Cell(0);
    stage.consumed_attempts.push(Cell(0));
    assert!(!committed_stage.ownership_is_globally_unique());
    assert_eq!(
        committed_stage.decode(),
        FloorView::Unknown(FloorFault::OwnershipAlias)
    );
}

#[test]
fn cuts_consume_claims_and_second_cuts_never_make_a_qw_reusable() {
    let mut model = FloorModel::blank();
    let mut token = model.begin(1, [0xa5; 16], planned_group(0)).unwrap();

    token = model.preclaim(&token, Cell(0), 0).unwrap();
    model.launch(&token, Cell(0)).unwrap();
    model.power_cut();
    assert!(model.consumed.contains(&Cell(0)));
    assert!(matches!(
        model.decode(),
        FloorView::Recovering { target: 1, .. }
    ));

    token = model.current_token().unwrap();
    assert_eq!(
        model.preclaim(&token, Cell(0), 0),
        Err(ModelError::CellUnavailable)
    );
    model.preclaim(&token, Cell(3), 0).unwrap();
    // Even a cut before the modeled launch consumes the durable preclaim.
    model.power_cut();
    assert!(model.consumed.contains(&Cell(3)));
    model.power_cut();
    assert_eq!(
        model
            .consumed
            .iter()
            .filter(|cell| **cell == Cell(0))
            .count(),
        1
    );
    assert_eq!(
        model
            .consumed
            .iter()
            .filter(|cell| **cell == Cell(3))
            .count(),
        1
    );

    token = model.current_token().unwrap();
    assert_eq!(
        model.preclaim(&token, Cell(3), 0),
        Err(ModelError::CellUnavailable)
    );
    assert_eq!(
        model.preclaim(&token, Cell(1), 0),
        Err(ModelError::CellUnavailable)
    );
    assert_eq!(
        model.launch(&token, Cell(1)),
        Err(ModelError::NotPreclaimed)
    );
}

#[test]
fn cut_replacement_complete_returns_fresh_steady_without_aliasing() {
    let mut model = FloorModel::blank();
    let mut token = model.begin(1, [0x5a; 16], planned_group(0)).unwrap();

    token = model.preclaim(&token, Cell(0), 0).unwrap();
    model.launch(&token, Cell(0)).unwrap();
    model.power_cut();
    assert!(model.consumed.contains(&Cell(0)));
    token = model.current_token().unwrap();

    token = clean_one_role(&mut model, token, 3, 0);
    token = clean_one_role(&mut model, token, 1, 1);
    token = clean_one_role(&mut model, token, 2, 2);
    let committed = model.complete(&token).unwrap();
    assert!(model.ownership_is_globally_unique());
    assert_eq!(
        model.decode(),
        FloorView::Steady {
            floor: 1,
            group: Some(committed),
        }
    );
    let group = model
        .groups
        .iter()
        .find(|candidate| candidate.id == committed)
        .unwrap();
    assert_eq!(group.consumed_attempts, vec![Cell(0)]);
    assert_eq!(
        group
            .replicas
            .iter()
            .map(|replica| (replica.cell, replica.role))
            .collect::<Vec<_>>(),
        vec![(Cell(3), 0), (Cell(1), 1), (Cell(2), 2)]
    );

    // Both final clean membership and consumed outcome are part of the
    // authoritative group identity.  Removing either without recomputing the
    // completion state is rejected rather than exposing BASE0.
    let mut clean_set_tamper = FloorModel::blank();
    commit_group(&mut clean_set_tamper, 1, 0);
    // Cell 3 is an otherwise valid, clean-looking planned role-0 replacement,
    // so only binding the exact selected full-clean set distinguishes it from
    // the role-0 cell that was actually accepted at COMPLETE.
    clean_set_tamper.groups[0].replicas[0].cell = Cell(3);
    assert_eq!(
        clean_set_tamper.decode(),
        FloorView::Unknown(FloorFault::InvalidCommittedGroup)
    );

    let mut consumed_tamper = model.clone();
    consumed_tamper.consumed.clear();
    consumed_tamper.groups[0].consumed_attempts.clear();
    assert_eq!(
        consumed_tamper.decode(),
        FloorView::Unknown(FloorFault::InvalidCommittedGroup)
    );
}

#[test]
fn durable_clean_binding_tamper_fails_even_after_outer_identity_is_rebound() {
    let mut model = FloorModel::blank();
    commit_group(&mut model, 1, 0);
    let original_state_digest = model.groups[0].state_digest;
    model.groups[0].replicas[0].durable_clean_binding[0] ^= 1;

    // Recompute the abstract outer group digest and committed-head witness so
    // this test exercises the independent derivation of staged clean
    // authority, rather than passing merely because an outer checksum is old.
    rebind_highest_group_for_tamper_test(&mut model);
    assert_ne!(model.groups[0].state_digest, original_state_digest);
    assert_eq!(
        model.committed_head.unwrap().state_digest,
        model.groups[0].state_digest
    );
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::InvalidCommittedGroup)
    );
}

#[test]
fn active_durable_clean_binding_tamper_blocks_recovery_and_complete() {
    let mut model = FloorModel::blank();
    let mut token = model.begin(1, [0x61; 16], planned_group(0)).unwrap();
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        token = clean_one_role(&mut model, token, role, role);
    }

    model.stage.as_mut().unwrap().live[0]
        .durable_clean_binding
        .as_mut()
        .unwrap()[0] ^= 1;
    let rebound_token = model.current_token().unwrap();
    assert_ne!(rebound_token, token);
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::InvalidRecoveryStage)
    );
    assert_eq!(
        model.complete(&rebound_token),
        Err(ModelError::NotRecovering)
    );
}

#[test]
fn pre_cut_active_clean_replicas_cannot_complete_without_fresh_revalidation() {
    let mut model = FloorModel::blank();
    let mut token = model.begin(1, [0x33; 16], planned_group(0)).unwrap();
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        token = clean_one_role(&mut model, token, role, role);
    }
    model.power_cut();
    let current = model.current_token().unwrap();
    assert!(model
        .stage
        .as_ref()
        .unwrap()
        .live
        .iter()
        .all(|claim| { claim.state == LiveClaimState::NeedsFreshValidation }));
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    assert_eq!(model.complete(&current), Err(ModelError::NotRecovering));
}

#[test]
fn exact_active_revalidation_restores_weight_and_second_cut_invalidates_it_again() {
    let mut model = FloorModel::blank();
    let mut token = model.begin(1, [0x34; 16], planned_group(0)).unwrap();
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        token = clean_one_role(&mut model, token, role, role);
    }
    model.power_cut();
    token = model.current_token().unwrap();

    let mut wrong_binding = revalidation_receipt(
        model.boot_epoch,
        token.id.generation,
        token.id.target,
        Cell(0),
        0,
        FreshEccStatus::Clean,
    );
    wrong_binding.prior_durable_clean_binding[0] ^= 1;
    assert_eq!(
        model.revalidate_active_clean(&token, wrong_binding),
        Err(ModelError::InvalidReceipt)
    );
    assert_eq!(model.current_token().unwrap(), token);

    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            token.id.generation,
            token.id.target,
            Cell(role),
            role,
            FreshEccStatus::Clean,
        );
        let (outcome, next) = model.revalidate_active_clean(&token, receipt).unwrap();
        assert_eq!(outcome, RevalidationOutcome::FreshClean);
        token = next;
    }
    assert!(matches!(
        model.decode(),
        FloorView::Recovering { target: 1, .. }
    ));

    let stale_receipt = revalidation_receipt(
        model.boot_epoch,
        token.id.generation,
        token.id.target,
        Cell(0),
        0,
        FreshEccStatus::Clean,
    );
    model.power_cut();
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    token = model.current_token().unwrap();
    assert_eq!(
        model.revalidate_active_clean(&token, stale_receipt),
        Err(ModelError::InvalidReceipt)
    );
    assert_eq!(model.current_token().unwrap(), token);
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            token.id.generation,
            token.id.target,
            Cell(role),
            role,
            FreshEccStatus::Clean,
        );
        token = model.revalidate_active_clean(&token, receipt).unwrap().1;
    }
    let committed = model.complete(&token).unwrap();
    assert_eq!(
        model.decode(),
        FloorView::Steady {
            floor: 1,
            group: Some(committed),
        }
    );
}

#[test]
fn corrected_active_revalidation_consumes_and_uses_only_preplanned_replacements() {
    let mut model = FloorModel::blank();
    let mut token = model.begin(1, [0x35; 16], planned_group(0)).unwrap();
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        token = clean_one_role(&mut model, token, role, role);
    }
    model.power_cut();
    token = model.current_token().unwrap();

    for (cell, role, ecc) in [
        (Cell(0), 0, FreshEccStatus::Corrected),
        (Cell(1), 1, FreshEccStatus::Uncorrectable),
        (Cell(2), 2, FreshEccStatus::Clean),
    ] {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            token.id.generation,
            token.id.target,
            cell,
            role,
            ecc,
        );
        let (outcome, next) = model.revalidate_active_clean(&token, receipt).unwrap();
        assert_eq!(
            outcome,
            if ecc == FreshEccStatus::Clean {
                RevalidationOutcome::FreshClean
            } else {
                RevalidationOutcome::Rejected
            }
        );
        token = next;
    }
    assert!(model.consumed.contains(&Cell(0)));
    assert!(model.consumed.contains(&Cell(1)));
    assert!(matches!(
        model.decode(),
        FloorView::Recovering { target: 1, .. }
    ));

    token = clean_one_role(&mut model, token, 3, 0);
    token = clean_one_role(&mut model, token, 4, 1);
    let committed = model.complete(&token).unwrap();
    assert!(matches!(
        model.decode(),
        FloorView::Steady {
            floor: 1,
            group: Some(group)
        } if group == committed
    ));

    let mut exhausted = FloorModel::blank();
    let mut token = exhausted.begin(1, [0x36; 16], planned_group(0)).unwrap();
    clean_one_role(&mut exhausted, token, 0, 0);
    exhausted.power_cut();
    token = exhausted.current_token().unwrap();
    let rejected = revalidation_receipt(
        exhausted.boot_epoch,
        token.id.generation,
        token.id.target,
        Cell(0),
        0,
        FreshEccStatus::Corrected,
    );
    token = exhausted
        .revalidate_active_clean(&token, rejected)
        .unwrap()
        .1;
    clean_one_role(&mut exhausted, token, 3, 0);
    exhausted.power_cut();
    token = exhausted.current_token().unwrap();
    let rejected = revalidation_receipt(
        exhausted.boot_epoch,
        token.id.generation,
        token.id.target,
        Cell(3),
        0,
        FreshEccStatus::Uncorrectable,
    );
    exhausted.revalidate_active_clean(&token, rejected).unwrap();
    assert!(matches!(
        exhausted.decode(),
        FloorView::Recovering { target: 1, .. }
    ));
}

#[test]
fn committed_floor_requires_current_boot_fresh_reads_before_steady() {
    let mut model = FloorModel::blank();
    let committed = commit_group(&mut model, 1, 0);
    model.power_cut();
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );

    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            committed.generation,
            committed.target,
            Cell(role),
            role,
            FreshEccStatus::Clean,
        );
        assert_eq!(
            model.revalidate_committed(committed, receipt),
            Ok(RevalidationOutcome::FreshClean)
        );
        if role + 1 < FULL_INITIAL_THRESHOLD as u8 {
            assert_eq!(
                model.decode(),
                FloorView::Unknown(FloorFault::FreshValidationRequired)
            );
        }
    }
    assert_eq!(
        model.decode(),
        FloorView::Steady {
            floor: 1,
            group: Some(committed),
        }
    );

    let stale_receipt = revalidation_receipt(
        model.boot_epoch,
        committed.generation,
        committed.target,
        Cell(0),
        0,
        FreshEccStatus::Clean,
    );
    model.power_cut();
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    assert_eq!(
        model.revalidate_committed(committed, stale_receipt),
        Err(ModelError::InvalidReceipt)
    );
}

#[test]
fn corrected_committed_reads_have_zero_weight_and_never_expose_older_floor() {
    let mut model = FloorModel::blank();
    let older = commit_group(&mut model, 1, 0);
    let newest = commit_group(&mut model, 2, 6);
    model.power_cut();

    for (cell, role, ecc) in [
        (Cell(6), 0, FreshEccStatus::Clean),
        (Cell(7), 1, FreshEccStatus::Corrected),
        (Cell(8), 2, FreshEccStatus::Uncorrectable),
    ] {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            newest.generation,
            newest.target,
            cell,
            role,
            ecc,
        );
        let expected = if ecc == FreshEccStatus::Clean {
            RevalidationOutcome::FreshClean
        } else {
            RevalidationOutcome::Rejected
        };
        assert_eq!(model.revalidate_committed(newest, receipt), Ok(expected));
    }
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            older.generation,
            older.target,
            Cell(role),
            role,
            FreshEccStatus::Clean,
        );
        assert_eq!(
            model.revalidate_committed(older, receipt),
            Ok(RevalidationOutcome::FreshClean)
        );
    }
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::LostHighestQuorum)
    );
    assert_ne!(
        model.decode(),
        FloorView::Steady {
            floor: 1,
            group: Some(older),
        }
    );
}

#[test]
fn base0_requires_a_fresh_blank_virgin_scan_after_every_cut() {
    let mut model = FloorModel::blank();
    model.power_cut();
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    assert_eq!(
        model.revalidate_base0(FreshBase0Receipt {
            boot_epoch: model.boot_epoch,
            all_reserved_cells_ff: true,
            fresh_array_reads: true,
            ecc: FreshEccStatus::Corrected,
            no_missing_durable_intent: true,
        }),
        Err(ModelError::InvalidReceipt)
    );
    model
        .revalidate_base0(FreshBase0Receipt {
            boot_epoch: model.boot_epoch,
            all_reserved_cells_ff: true,
            fresh_array_reads: true,
            ecc: FreshEccStatus::Clean,
            no_missing_durable_intent: true,
        })
        .unwrap();
    assert_eq!(
        model.decode(),
        FloorView::Steady {
            floor: 0,
            group: None,
        }
    );
    let stale_receipt = FreshBase0Receipt {
        boot_epoch: model.boot_epoch,
        all_reserved_cells_ff: true,
        fresh_array_reads: true,
        ecc: FreshEccStatus::Clean,
        no_missing_durable_intent: true,
    };
    model.power_cut();
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    assert_eq!(
        model.revalidate_base0(stale_receipt),
        Err(ModelError::InvalidReceipt)
    );
    model
        .revalidate_base0(FreshBase0Receipt {
            boot_epoch: model.boot_epoch,
            all_reserved_cells_ff: true,
            fresh_array_reads: true,
            ecc: FreshEccStatus::Clean,
            no_missing_durable_intent: true,
        })
        .unwrap();
    assert_eq!(
        model.decode(),
        FloorView::Steady {
            floor: 0,
            group: None,
        }
    );
}

#[test]
fn clean_authority_requires_eop_and_an_explicit_fresh_clean_receipt() {
    let mut model = FloorModel::blank();
    let mut token = model.begin(1, [0x11; 16], planned_group(0)).unwrap();
    token = model.preclaim(&token, Cell(0), 0).unwrap();
    let exact = encode_plain(PlainRecord { target: 1, role: 0 });
    let clean = FreshCleanReceipt::clean(Cell(0), token.id.generation, exact);
    assert_eq!(
        model.record_clean(&token, clean),
        Err(ModelError::NotLaunched)
    );

    token = model.launch(&token, Cell(0)).unwrap();
    let mut partial = exact;
    let (byte, bit) = (0..128)
        .map(|bit| (bit / 8, bit % 8))
        .find(|(byte, bit)| exact[*byte] & (1_u8 << *bit) == 0)
        .unwrap();
    partial[byte] |= 1_u8 << bit;
    assert!(is_programming_prefix(partial, exact));

    let invalid = [
        FreshCleanReceipt {
            generation: token.id.generation + 1,
            ..clean
        },
        FreshCleanReceipt {
            fresh_array_read: false,
            ..clean
        },
        FreshCleanReceipt {
            eop: false,
            ..clean
        },
        FreshCleanReceipt {
            ecc: FreshEccStatus::Corrected,
            ..clean
        },
        FreshCleanReceipt {
            ecc: FreshEccStatus::Uncorrectable,
            ..clean
        },
        FreshCleanReceipt {
            observed: encode_plain(PlainRecord { target: 2, role: 0 }),
            ..clean
        },
        FreshCleanReceipt {
            observed: encode_plain(PlainRecord { target: 1, role: 1 }),
            ..clean
        },
        FreshCleanReceipt {
            observed: partial,
            ..clean
        },
    ];

    for receipt in invalid {
        assert_eq!(
            model.record_clean(&token, receipt),
            Err(ModelError::InvalidReceipt)
        );
        assert_eq!(model.current_token().unwrap(), token);
    }
    assert!(model.record_clean(&token, clean).is_ok());
}

#[test]
fn stale_stage_replay_and_replacement_without_preclaim_are_rejected() {
    let mut model = FloorModel::blank();
    let initial = model.begin(1, [0x22; 16], planned_group(0)).unwrap();
    let after_claim = model.preclaim(&initial, Cell(0), 0).unwrap();
    assert_eq!(model.resume(&initial), Err(ModelError::WrongStageToken));
    let after_launch = model.launch(&after_claim, Cell(0)).unwrap();
    model.power_cut();
    assert_eq!(
        model.resume(&after_launch),
        Err(ModelError::WrongStageToken)
    );

    let current = model.current_token().unwrap();
    assert_eq!(
        model.launch(&current, Cell(3)),
        Err(ModelError::NotPreclaimed)
    );
    let replacement = model.preclaim(&current, Cell(3), 0).unwrap();
    assert!(model.launch(&replacement, Cell(3)).is_ok());
}

#[test]
fn cuts_replays_and_quorum_loss_never_lower_the_floor() {
    let mut model = FloorModel::blank();
    let prior = commit_group(&mut model, 7, 0);
    let mut token = model.begin(8, [8; 16], planned_group(6)).unwrap();
    token = clean_one_role(&mut model, token, 6, 0);
    token = model.preclaim(&token, Cell(7), 1).unwrap();
    token = model.launch(&token, Cell(7)).unwrap();
    model.power_cut();

    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    assert_ne!(
        model.decode(),
        FloorView::Steady {
            floor: 7,
            group: Some(prior)
        }
    );
    assert_eq!(model.resume(&token), Err(ModelError::NotRecovering));

    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            prior.generation,
            prior.target,
            Cell(role),
            role,
            FreshEccStatus::Clean,
        );
        assert_eq!(
            model.revalidate_committed(prior, receipt),
            Ok(RevalidationOutcome::FreshClean)
        );
    }
    let mut current = model.current_token().unwrap();
    let receipt = revalidation_receipt(
        model.boot_epoch,
        current.id.generation,
        current.id.target,
        Cell(6),
        0,
        FreshEccStatus::Clean,
    );
    model.revalidate_active_clean(&current, receipt).unwrap();
    assert!(matches!(
        model.decode(),
        FloorView::Recovering {
            prior_f: 7,
            target: 8,
            ..
        }
    ));
    assert_eq!(model.resume(&token), Err(ModelError::WrongStageToken));

    // A second cut invalidates both sources of current-boot authority again;
    // after explicit fresh revalidation it returns to the same recovery class
    // without making any consumed QW reusable.
    let consumed_before = model.consumed.clone();
    model.power_cut();
    assert_eq!(
        model.decode(),
        FloorView::Unknown(FloorFault::FreshValidationRequired)
    );
    for role in 0..FULL_INITIAL_THRESHOLD as u8 {
        let receipt = revalidation_receipt(
            model.boot_epoch,
            prior.generation,
            prior.target,
            Cell(role),
            role,
            FreshEccStatus::Clean,
        );
        model.revalidate_committed(prior, receipt).unwrap();
    }
    current = model.current_token().unwrap();
    let receipt = revalidation_receipt(
        model.boot_epoch,
        current.id.generation,
        current.id.target,
        Cell(6),
        0,
        FreshEccStatus::Clean,
    );
    model.revalidate_active_clean(&current, receipt).unwrap();
    assert!(matches!(
        model.decode(),
        FloorView::Recovering {
            prior_f: 7,
            target: 8,
            ..
        }
    ));
    assert_eq!(model.consumed, consumed_before);
    assert!(model.consumed.contains(&Cell(7)));
}

// ---------------------------------------------------------------------------
// Non-authoritative capacity arithmetic.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct CapacityFamily {
    label: &'static str,
    fixed_qws: usize,
    qws_per_epoch: usize,
}

impl CapacityFamily {
    fn illustrative_epochs(self, cells: usize) -> usize {
        cells.saturating_sub(self.fixed_qws) / self.qws_per_epoch
    }
}

#[test]
fn twenty_six_cell_capacity_examples_are_explicitly_non_authoritative() {
    // These numbers are comparison arithmetic only.  They omit torn-write
    // losses and do not approve a codec, durable-stage route, replica count,
    // degraded threshold, key layout, recovery margin, or physical QW map.
    let families = [
        CapacityFamily {
            label: "rejected single-QW comparison only",
            fixed_qws: 0,
            qws_per_epoch: 1,
        },
        CapacityFamily {
            label: "two-QW comparison (not production-eligible by itself)",
            fixed_qws: 0,
            qws_per_epoch: 2,
        },
        CapacityFamily {
            label: "three clean replicas, replacement plan excluded",
            fixed_qws: 0,
            qws_per_epoch: 3,
        },
        CapacityFamily {
            label: "three replicas with two fixed recovery-margin QWs",
            fixed_qws: 2,
            qws_per_epoch: 3,
        },
        CapacityFamily {
            label: "four QWs per epoch",
            fixed_qws: 0,
            qws_per_epoch: 4,
        },
        CapacityFamily {
            label: "this host candidate: three roles times two bound attempts",
            fixed_qws: 0,
            qws_per_epoch: FULL_INITIAL_THRESHOLD * PLANNED_ATTEMPTS_PER_ROLE,
        },
    ];

    let examples: Vec<(&str, usize)> = families
        .into_iter()
        .map(|family| (family.label, family.illustrative_epochs(CELL_COUNT)))
        .collect();
    assert_eq!(
        examples,
        vec![
            ("rejected single-QW comparison only", 26),
            ("two-QW comparison (not production-eligible by itself)", 13),
            ("three clean replicas, replacement plan excluded", 8),
            ("three replicas with two fixed recovery-margin QWs", 8),
            ("four QWs per epoch", 6),
            (
                "this host candidate: three roles times two bound attempts",
                4
            ),
        ]
    );
}
