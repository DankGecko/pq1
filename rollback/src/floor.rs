//! The `FloorView` 4-class decoder (FROZEN-OTP-API-3, §7.1, §10).
//!
//! The production OTP physical record codec is OPEN-OTP-1..3 — NOT frozen.
//! This module therefore defines a MODEL-ONLY record encoding (below) that
//! exercises exactly the frozen interface semantics: role accountancy,
//! committed-group / active-stage distinction, initial vs degraded
//! thresholds, classification priority, and the four proof classes. When
//! OPEN-OTP-1..3 lands, the inner codec swaps out; the frozen semantics
//! here must not change.
//!
//! MODEL-ONLY record encoding (16 bytes, all integers big-endian):
//!   * floor record:    `T(4) || !T(4) || g(4) || !g(4)`
//!   * COMPLETE record: `g(4) || !g(4) || "COMPLETE"`
//!   * stage record:    `g(4) || !g(4) || "STAGEACT"`
//!   * Route-1 BASE0 marker: [`ROUTE1_BASE0_CODEWORD`]
//! A durable COMPLETE attests that the full initial clean threshold was
//! EOP-verified at establishment; the decoder then tolerates later replica
//! failures down to the degraded threshold (§10 L3679–3695).

use sha2::{Digest, Sha256};

use crate::qw_read::{BlankVirgin, Durability, FreshQwRead, LaunchAttribution};

/// Initial clean threshold: replicas required at establishment.
pub const INITIAL_THRESHOLD: u32 = 3;
/// Degraded threshold: clean witnesses a committed group must retain.
pub const DEGRADED_THRESHOLD: u32 = 1;
/// Finite plan size: three initial replicas plus one replacement.
pub const PLAN_CELLS: u32 = 4;

/// Reserved rollback QW bank size: the decoder scans EXACTLY this many
/// cells (a full scan is mandatory; a prefix or overflow map fails
/// closed).
pub const RESERVED_ROLLBACK_QWS: usize = 32;
/// Maximum reserved rollback QWs the decoder scans (alias of
/// [`RESERVED_ROLLBACK_QWS`]; a larger snapshot fails CLOSED, never
/// silently truncates).
pub const MAX_ROLLBACK_CELLS: usize = RESERVED_ROLLBACK_QWS;
/// Maximum tracked floor records (one per cell).
pub const MAX_FLOOR_RECORDS: usize = 32;
/// Maximum tracked COMPLETE records.
pub const MAX_COMPLETE_RECORDS: usize = 8;
/// Maximum tracked stage records.
pub const MAX_STAGE_RECORDS: usize = 8;

// ---------------------------------------------------------------------------
// Canonical physical map (MODEL choice — the production OTP assignment
// belongs to OPEN-OTP-1..3 and the geometry registry's OTP extension).
// Reserved rollback QW `index` sits at `OTP_ROLLBACK_BANK_BASE + index*16`;
// the Route-1 markers are the FIRST quad-words of the registry's Route-1
// journal pages (bank-1 pages 64 and 122).
// ---------------------------------------------------------------------------

/// MODEL base address of the reserved rollback QW bank.
pub const OTP_ROLLBACK_BANK_BASE: u32 = 0x0BFA_0000;

/// The canonical absolute address of reserved rollback QW `index`.
pub const fn canonical_cell_addr(index: u16) -> u32 {
    OTP_ROLLBACK_BANK_BASE + index as u32 * 16
}

/// The canonical absolute address of Route-1 marker `which` (0 or 1).
pub const fn canonical_route1_addr(which: usize) -> u32 {
    pqsigner_geometry::page_addr(
        pqsigner_geometry::Bank::One,
        pqsigner_geometry::ROUTE1_JOURNAL_PAGES[which],
    )
}

/// Why a snapshot's canonical physical map is invalid (FROZEN-OTP-API-3
/// L931: one physical QW can never count twice or alias a role).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapFault {
    /// Two `Clean` reads in one snapshot carry the same physical index.
    DuplicateIndex { index: u16 },
    /// A `CleanQw`'s bound address does not equal the canonical
    /// registry-derived address for its index.
    AddressMismatch { index: u16 },
    /// Not all `Clean` reads in the snapshot share one probe epoch (one
    /// common immutable-entry pass).
    InconsistentProbeEpoch,
    /// The two Route-1 reads are not distinct physical QWs.
    NonDisjointRoute1,
}

/// Which accountancy array overflowed (see
/// [`FloorFault::RecordOverflow`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// The bank snapshot itself exceeded [`MAX_ROLLBACK_CELLS`].
    Cell,
    /// More than [`MAX_FLOOR_RECORDS`] floor records.
    Floor,
    /// More than [`MAX_COMPLETE_RECORDS`] COMPLETE records.
    Complete,
    /// More than [`MAX_STAGE_RECORDS`] stage records.
    Stage,
}

/// MODEL-ONLY Route-1 BASE0 marker codeword (the synchronized active
/// factory `BASE0` Route-1 pair). Erased-looking Route-1 pages never
/// prove the base (§7.1 L2574–2576).
pub const ROUTE1_BASE0_CODEWORD: [u8; 16] = *b"PQFW_R1_BASE0!!!";

/// Durable completion-launch fence evidence (FROZEN-OTP-API-3 L1012–1013:
/// "Missing or all-`FF` completion bytes alone are not proof").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompletionLaunchEvidence {
    /// The durable fence proves no COMPLETE body, activation, or
    /// equivalent completion-authority write may have launched.
    ProvenNoCompletionLaunch,
    /// Completion may have launched: `Aborted` is not constructible.
    MayHaveLaunched,
}

/// One reserved rollback QW's attributed read (owned).
pub struct FloorCell {
    pub read: FreshQwRead,
    pub durability: Durability,
    pub launch: LaunchAttribution,
}

/// One cell of the durable stage's ordered physical-cell role plan
/// (MODEL choice pending OPEN-OTP-1..3: the real plan serialization is
/// the open OTP codec's; the plan content and its digest are bound
/// here). Mirrors the spec's "complete ordered cell-role assignment"
/// (§7.1 L2539) and "ordered non-aliasing physical-cell role map"
/// (FROZEN-OTP-API-3 L876).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlanRole {
    /// A clean floor record planned as a replica witness (already
    /// programmed and EOP-verified).
    Witness,
    /// A consumed/quarantined plan cell (torn, corrected, ambiguous,
    /// may-have-launched).
    Consumed,
    /// A reserved, claimable, canonically-virgin plan cell.
    Reserved,
}

/// Plan size in cells (== [`PLAN_CELLS`]).
pub const STAGE_PLAN_CELLS: usize = PLAN_CELLS as usize;

/// The durable stage's bound candidate/manifest identity (§7.1
/// L2536–2538) PLUS its ordered per-index role plan: exactly
/// [`STAGE_PLAN_CELLS`] cells, each assigned one [`PlanRole`]. Required
/// whenever a stage record exists. Private fields: constructible only
/// through the validating constructor. NOTE (model): the 16-byte model
/// stage-record QW references the plan; the plan content is carried
/// here as the durable-stage model input, and it is folded into the
/// snapshot digest. OPEN-OTP-1..3 owns the production serialization.
#[derive(PartialEq, Eq, Debug)]
pub struct StageBinding {
    slot: fw_manifest::v6::PhysicalSlot,
    r: u32,
    e: u32,
    manifest_digest: [u8; 32],
    roles: [(u16, PlanRole); STAGE_PLAN_CELLS],
}

impl StageBinding {
    /// The only constructor. `R`/`E` must be in `1..=0xFFFF_FFFE`; the
    /// role plan must be strictly ordered by index with every index
    /// inside the reserved bank (ordered and non-aliasing).
    pub fn new(
        slot: fw_manifest::v6::PhysicalSlot,
        r: u32,
        e: u32,
        manifest_digest: [u8; 32],
        roles: [(u16, PlanRole); STAGE_PLAN_CELLS],
    ) -> Option<StageBinding> {
        let valid = |v: u32| (fw_manifest::v6::VERSION_MIN..=fw_manifest::v6::VERSION_MAX).contains(&v);
        if !valid(r) || !valid(e) {
            return None;
        }
        for w in roles.windows(2) {
            if w[0].0 >= w[1].0 {
                return None;
            }
        }
        if roles.iter().any(|&(i, _)| i as usize >= RESERVED_ROLLBACK_QWS) {
            return None;
        }
        Some(StageBinding {
            slot,
            r,
            e,
            manifest_digest,
            roles,
        })
    }

    pub fn slot(&self) -> fw_manifest::v6::PhysicalSlot {
        self.slot
    }

    pub fn r(&self) -> u32 {
        self.r
    }

    pub fn e(&self) -> u32 {
        self.e
    }

    pub fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    /// The ordered per-index role plan.
    pub fn roles(&self) -> &[(u16, PlanRole); STAGE_PLAN_CELLS] {
        &self.roles
    }

    /// The role assigned to `index`, if any.
    pub fn role_of(&self, index: u16) -> Option<PlanRole> {
        self.roles
            .iter()
            .find(|&&(i, _)| i == index)
            .map(|&(_, role)| role)
    }
}

/// The complete decoder input: exactly [`RESERVED_ROLLBACK_QWS`] cells
/// (one per canonical reserved index), both Route-1 journal-page
/// markers, the completion-launch fence for the (at most one) active
/// stage, and the stage's bound candidate identity.
///
/// FROZEN-OTP-API-3 requires a FULL scan of every reserved rollback QW
/// and both Route-1 pages. [`decode_floor`] enforces exact cardinality
/// and exact per-index enumeration (see [`FloorFault::IncompleteMap`]);
/// [`FloorSnapshot::probe`] is the canonical constructor and enumerates
/// every canonical index exactly once through the fresh-array probe.
pub struct FloorSnapshot {
    /// One cell per canonical reserved index; every slot must be filled.
    cells: [Option<FloorCell>; RESERVED_ROLLBACK_QWS],
    /// The two Route-1 markers (distinct physical QWs).
    route1: [FloorCell; 2],
    completion_fence: CompletionLaunchEvidence,
    /// Required iff a stage record is present.
    stage_binding: Option<StageBinding>,
}

impl FloorSnapshot {
    /// The bank cells (one per canonical reserved index).
    pub fn cells(&self) -> &[Option<FloorCell>; RESERVED_ROLLBACK_QWS] {
        &self.cells
    }

    /// The two Route-1 markers.
    pub fn route1(&self) -> &[FloorCell; 2] {
        &self.route1
    }

    /// The completion-launch fence input.
    pub fn completion_fence(&self) -> CompletionLaunchEvidence {
        self.completion_fence
    }

    /// The stage's bound candidate identity and role plan.
    pub fn stage_binding(&self) -> Option<&StageBinding> {
        self.stage_binding.as_ref()
    }

    /// TEST-SCAFFOLD mutators (feature-gated): adversarial map-injection
    /// tests mutate a probed snapshot through these. Not part of the
    /// library surface.
    #[cfg(feature = "test-backend")]
    pub fn cells_mut(&mut self) -> &mut [Option<FloorCell>; RESERVED_ROLLBACK_QWS] {
        &mut self.cells
    }

    /// See [`FloorSnapshot::cells_mut`].
    #[cfg(feature = "test-backend")]
    pub fn route1_mut(&mut self) -> &mut [FloorCell; 2] {
        &mut self.route1
    }
}

impl FloorSnapshot {
    /// The canonical constructor: probe EVERY canonical reserved index
    /// `0..RESERVED_ROLLBACK_QWS` and both Route-1 markers exactly once,
    /// attaching the caller's explicit per-index attributions. A
    /// caller-assembled incomplete or prefix snapshot is impossible on
    /// this path (and rejected by [`decode_floor`] on any other path).
    pub fn probe<P: crate::qw_read::FreshArrayProbe>(
        backend: &mut P,
        completion_fence: CompletionLaunchEvidence,
        stage_binding: Option<StageBinding>,
        cell_attributions: &[(Durability, LaunchAttribution); RESERVED_ROLLBACK_QWS],
        route1_attributions: [(Durability, LaunchAttribution); 2],
    ) -> FloorSnapshot {
        let mut cells: [Option<FloorCell>; RESERVED_ROLLBACK_QWS] = [const { None }; RESERVED_ROLLBACK_QWS];
        for (i, slot) in cells.iter_mut().enumerate() {
            let (durability, launch) = cell_attributions[i];
            *slot = Some(FloorCell {
                read: backend.fresh_probe(i as u16, canonical_cell_addr(i as u16)),
                durability,
                launch,
            });
        }
        let route1 = [0usize, 1].map(|j| {
            let (durability, launch) = route1_attributions[j];
            FloorCell {
                read: backend.fresh_probe(60 + j as u16, canonical_route1_addr(j)),
                durability,
                launch,
            }
        });
        FloorSnapshot {
            cells,
            route1,
            completion_fence,
            stage_binding,
        }
    }
}

/// The committed group's identity, or the canonical logical base.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GroupIdentity {
    /// Canonical `BASE0` (F = 0), proven by the full canonical rule.
    Base0,
    /// Committed group index.
    Group(u32),
}

/// Boot-scoped linear proof of the admission-authoritative floor `F`
/// (FROZEN-OTP-API-3 L869–874). Neither `Copy` nor `Clone`, never
/// serializable, consumed by value.
pub struct SteadyProof {
    floor: u32,
    group: GroupIdentity,
    virgin_cells: u32,
    snapshot_digest: [u8; 32],
}

impl SteadyProof {
    /// The admission-authoritative rejected-through floor.
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// The committed group identity or canonical `BASE0`.
    pub fn group(&self) -> GroupIdentity {
        self.group
    }

    /// Canonically-virgin cells counted by THIS decode (proof-bound
    /// capacity input for [`preflight`] — never caller-asserted).
    pub fn virgin_cells(&self) -> u32 {
        self.virgin_cells
    }

    /// Digest of the complete physical snapshot this proof decodes from.
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
}

/// Boot-scoped linear proof of one bound, completable in-progress stage
/// (FROZEN-OTP-API-3 L875–878). It DELIBERATELY has no method exposing
/// `prior_f` as an admission floor.
pub struct RecoveryProof {
    /// Bound at decode time and joined internally, but DELIBERATELY
    /// never exposed: no method may return `prior_f` as an admission
    /// floor (FROZEN-OTP-API-3 L877–878).
    #[allow(dead_code)]
    prior_f: u32,
    /// The prior group identity/digest or `BASE0`, bound at decode time
    /// (FROZEN-OTP-API-3 L876). Not separately exposed.
    #[allow(dead_code)]
    prior_group: GroupIdentity,
    target: u32,
    group: u32,
    candidate_slot: fw_manifest::v6::PhysicalSlot,
    candidate_digest: [u8; 32],
    clean_records: u32,
    snapshot_digest: [u8; 32],
}

impl RecoveryProof {
    /// The bound active target (`> prior_f`). This is the ONLY numeric
    /// accessor; `prior_f` is never exposed as an admission floor.
    pub fn target(&self) -> u32 {
        self.target
    }

    /// The active stage's group index.
    pub fn group(&self) -> u32 {
        self.group
    }

    /// The bound candidate's physical slot.
    pub fn candidate_slot(&self) -> fw_manifest::v6::PhysicalSlot {
        self.candidate_slot
    }

    /// The bound candidate's manifest digest.
    pub fn candidate_digest(&self) -> &[u8; 32] {
        &self.candidate_digest
    }

    /// Clean active records currently witnessed.
    pub fn clean_records(&self) -> u32 {
        self.clean_records
    }

    /// Digest of the complete physical snapshot.
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
}

/// Boot-scoped linear TERMINAL proof of a mathematically dead pre-COMPLETE
/// plan (FROZEN-OTP-API-3 L880–893). Not a writable state, not a
/// cancellation command, and carries no renewable capacity or method that
/// can authorize `T > F`.
pub struct DeadStageProof {
    floor: u32,
    failed_target: u32,
    failed_group: u32,
    failed_slot: fw_manifest::v6::PhysicalSlot,
    failed_digest: [u8; 32],
    failed_r: u32,
    failed_e: u32,
    aborted_release_high_water: u32,
    snapshot_digest: [u8; 32],
}

impl DeadStageProof {
    /// The unchanged authoritative prior floor.
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// The failed stage's target (the dead plan).
    pub fn failed_target(&self) -> u32 {
        self.failed_target
    }

    /// The failed release's `(R, E)` identity (both slots of its A/B twin
    /// are excluded by checking this tuple, see `intents.rs`).
    pub fn failed_release(&self) -> (u32, u32) {
        (self.failed_r, self.failed_e)
    }

    /// The failed candidate's physical slot.
    pub fn failed_slot(&self) -> fw_manifest::v6::PhysicalSlot {
        self.failed_slot
    }

    /// The failed stage's group index.
    pub fn failed_group(&self) -> u32 {
        self.failed_group
    }

    /// The failed candidate's manifest digest.
    pub fn failed_digest(&self) -> &[u8; 32] {
        &self.failed_digest
    }

    /// `aborted_release_high_water` (FROZEN-OTP-API-3 L882).
    pub fn aborted_release_high_water(&self) -> u32 {
        self.aborted_release_high_water
    }

    /// Digest of the complete floor/stage/journal physical snapshot.
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
}

/// Diagnostics-only fault payload for `Unknown`. Never carries a usable
/// floor (FROZEN-OTP-API-3 L893).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FloorFault {
    /// A clean nonblank QW outside the authenticated accountancy map.
    OrphanQw { index: u16 },
    /// A corrected/uncorrectable/may-have-launched QW outside the map.
    UncertainQw { index: u16 },
    /// Two incompatible role assignments for one group.
    AliasedGroup { group: u32 },
    /// A committed group lost every clean witness (never return a lower
    /// floor — halt instead).
    MissingQuorum { group: u32 },
    /// Conflicting or ambiguous completion authority.
    ConflictingCompletion,
    /// More than one active stage, or a target-inconsistent stage.
    AmbiguousStage,
    /// The canonical BASE0 proof is incomplete (blank bank alone never
    /// reconstructs `Steady(0)`).
    MissingBaseProof,
    /// A dead plan whose completion may have launched.
    CompletionMayHaveLaunched,
    /// An accountancy array overflowed. Fail CLOSED: overflowing records
    /// are never silently dropped (a truncated view could admit a lower
    /// committed floor than the bank actually proves).
    RecordOverflow { kind: RecordKind, index: u16 },
    /// The snapshot's canonical physical map is invalid (duplicate
    /// index, index/address mismatch, probe-epoch inconsistency, or a
    /// non-disjoint Route-1 pair).
    NonCanonicalMap(MapFault),
    /// The snapshot is not a full scan: fewer than
    /// [`RESERVED_ROLLBACK_QWS`] cells were presented (a prefix snapshot
    /// omitting newer records would otherwise lower the floor).
    IncompleteMap { expected: usize, got: usize },
    /// A QW's actual role is not the one the stage's authenticated
    /// role map assigns (or it has no assignment): an uncertain QW is
    /// never silently absorbed into a plan, and a plan cell that does
    /// not match physical reality rejects the decode.
    UnmappedRole { index: u16 },
    /// The committed allocation history is not a valid monotone
    /// sequence: duplicate group, or targets not non-decreasing in
    /// group order. The allocation cursor is only ever the max
    /// VALIDATED group — never reissued.
    NonMonotoneAllocation,
}

/// The four mutually exclusive decoder classes (FROZEN-OTP-API-3
/// L860–867).
pub enum FloorView {
    Steady(SteadyProof),
    Recovering(RecoveryProof),
    Aborted(DeadStageProof),
    Unknown(FloorFault),
}

// ---------------------------------------------------------------------------
// MODEL-ONLY record codec
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Record {
    Floor { t: u32, g: u32 },
    Complete { g: u32 },
    Stage { g: u32 },
}

fn decode_record(bytes: &[u8; 16]) -> Option<Record> {
    let a = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    let a_inv = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if a_inv != !a {
        return None;
    }
    let tail: &[u8] = &bytes[8..16];
    if tail == b"COMPLETE" {
        return Some(Record::Complete { g: a });
    }
    if tail == b"STAGEACT" {
        return Some(Record::Stage { g: a });
    }
    let b = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let b_inv = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
    if b_inv != !b {
        return None;
    }
    Some(Record::Floor { t: a, g: b })
}

/// Test/model helper: encode a floor record (MODEL-ONLY codec).
pub fn encode_floor_record(t: u32, g: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&t.to_be_bytes());
    out[4..8].copy_from_slice(&(!t).to_be_bytes());
    out[8..12].copy_from_slice(&g.to_be_bytes());
    out[12..16].copy_from_slice(&(!g).to_be_bytes());
    out
}

/// Test/model helper: encode a COMPLETE record (MODEL-ONLY codec).
pub fn encode_complete_record(g: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&g.to_be_bytes());
    out[4..8].copy_from_slice(&(!g).to_be_bytes());
    out[8..16].copy_from_slice(b"COMPLETE");
    out
}

/// Test/model helper: encode a stage record (MODEL-ONLY codec).
pub fn encode_stage_record(g: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&g.to_be_bytes());
    out[4..8].copy_from_slice(&(!g).to_be_bytes());
    out[8..16].copy_from_slice(b"STAGEACT");
    out
}

// ---------------------------------------------------------------------------
// Cell classification + accountancy
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CellClass {
    /// Canonically virgin (clean all-`0xFF` + proven no launch).
    Virgin,
    /// Exact durably-clean record.
    Role(Record),
    /// Clean nonblank bytes that decode to nothing — outside the map.
    Orphan,
    /// Corrected / uncorrectable / ambiguous / may-have-launched /
    /// durability-ambiguous. Tolerable only inside an active or dead
    /// stage's plan.
    Uncertain,
}

fn classify_cell(cell: &FloorCell) -> CellClass {
    if BlankVirgin::prove(&cell.read, cell.launch).is_some() {
        return CellClass::Virgin;
    }
    match &cell.read {
        FreshQwRead::Clean(qw) => {
            if !cell.durability.is_clean() {
                return CellClass::Uncertain;
            }
            // Erased bytes WITHOUT the no-launch proof are a consumed/
            // uncertain cell (a possibly interrupted program), tolerable
            // only inside an active or dead stage's plan — never a
            // committed role and never an orphan.
            if qw.is_erased() {
                return CellClass::Uncertain;
            }
            match decode_record(qw.bytes()) {
                Some(rec) => CellClass::Role(rec),
                None => CellClass::Orphan,
            }
        }
        _ => CellClass::Uncertain,
    }
}

/// Route-1 marker classification (R3-6): a Route-1 QW is in the
/// authenticated map only as canonical virgin or the exact BASE0
/// codeword. Anything else — garbage-but-clean, corrected,
/// uncorrectable, may-have-launched — forces `Unknown` (FROZEN-OTP-API-3
/// L926–932).
enum Route1Class {
    Virgin,
    Base0Marker,
    Orphan,
    Uncertain,
}

fn classify_route1(cell: &FloorCell) -> Route1Class {
    if BlankVirgin::prove(&cell.read, cell.launch).is_some() {
        return Route1Class::Virgin;
    }
    if let FreshQwRead::Clean(qw) = &cell.read {
        if !cell.durability.is_clean() {
            return Route1Class::Uncertain;
        }
        if qw.bytes() == &ROUTE1_BASE0_CODEWORD {
            return Route1Class::Base0Marker;
        }
        if qw.is_erased() {
            return Route1Class::Uncertain;
        }
        return Route1Class::Orphan;
    }
    Route1Class::Uncertain
}

fn snapshot_digest(snapshot: &FloorSnapshot) -> [u8; 32] {
    let mut h = Sha256::new();
    for cell in snapshot.cells().iter().flatten().chain(snapshot.route1().iter()) {
        match &cell.read {
            FreshQwRead::Clean(qw) => {
                h.update([0x01]);
                h.update(qw.bytes());
            }
            FreshQwRead::Corrected { bytes, index } => {
                h.update([0x02]);
                h.update(index.to_be_bytes());
                h.update(bytes);
            }
            FreshQwRead::Uncorrectable { index } => {
                h.update([0x03]);
                h.update(index.to_be_bytes());
            }
            FreshQwRead::AmbiguousOrFault => {
                h.update([0x04]);
            }
        }
    }
    // The digest binds the COMPLETE floor/stage state: the completion
    // fence discriminant and the stage's bound candidate identity
    // (R3-4), not merely the raw cell bytes.
    h.update([match snapshot.completion_fence() {
        CompletionLaunchEvidence::ProvenNoCompletionLaunch => 0xA0,
        CompletionLaunchEvidence::MayHaveLaunched => 0xA1,
    }]);
    match snapshot.stage_binding() {
        Some(b) => {
            h.update([0xB1, b.slot().to_u8()]);
            h.update(b.r().to_be_bytes());
            h.update(b.e().to_be_bytes());
            h.update(b.manifest_digest());
            // The stage's ordered role plan is part of the bound state.
            for &(index, role) in b.roles() {
                h.update(index.to_be_bytes());
                h.update([match role {
                    PlanRole::Witness => 0xC1,
                    PlanRole::Consumed => 0xC2,
                    PlanRole::Reserved => 0xC3,
                }]);
            }
        }
        None => h.update([0xB0]),
    }
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// The decoder
// ---------------------------------------------------------------------------

/// Validate the snapshot's canonical physical map BEFORE accountancy:
/// every presented read must sit at its canonical position (index ==
/// position, canonical address for its index), indices must be unique
/// across cells and the Route-1 pair, all `Clean` reads must share one
/// probe epoch, and the Route-1 pair must be two distinct physical QWs
/// at their canonical pages.
fn validate_physical_map(snapshot: &FloorSnapshot) -> Result<(), FloorFault> {
    let mut seen: [u16; RESERVED_ROLLBACK_QWS + 2] = [0; RESERVED_ROLLBACK_QWS + 2];
    let mut n_seen = 0usize;
    let mut epoch: Option<u32> = None;

    fn check(
        seen: &mut [u16],
        n_seen: &mut usize,
        epoch: &mut Option<u32>,
        qw: &crate::qw_read::CleanQw,
        canonical_addr: u32,
    ) -> Result<(), FloorFault> {
        if seen[..*n_seen].contains(&qw.index()) {
            return Err(FloorFault::NonCanonicalMap(MapFault::DuplicateIndex {
                index: qw.index(),
            }));
        }
        seen[*n_seen] = qw.index();
        *n_seen += 1;
        if qw.addr() != canonical_addr {
            return Err(FloorFault::NonCanonicalMap(MapFault::AddressMismatch {
                index: qw.index(),
            }));
        }
        match epoch {
            None => *epoch = Some(qw.probe_epoch()),
            Some(e) if *e != qw.probe_epoch() => {
                return Err(FloorFault::NonCanonicalMap(MapFault::InconsistentProbeEpoch));
            }
            _ => {}
        }
        Ok(())
    }

    for (i, cell) in snapshot.cells().iter().enumerate() {
        let Some(cell) = cell else { continue };
        match &cell.read {
            FreshQwRead::Clean(qw) => {
                // A QW presented twice anywhere in the map is a
                // duplicate; a QW at the wrong position is an
                // index/address inconsistency.
                if seen[..n_seen].contains(&qw.index()) {
                    return Err(FloorFault::NonCanonicalMap(MapFault::DuplicateIndex {
                        index: qw.index(),
                    }));
                }
                if qw.index() != i as u16 {
                    return Err(FloorFault::NonCanonicalMap(MapFault::AddressMismatch {
                        index: qw.index(),
                    }));
                }
                check(&mut seen, &mut n_seen, &mut epoch, qw, canonical_cell_addr(i as u16))?;
            }
            FreshQwRead::Corrected { index, .. } | FreshQwRead::Uncorrectable { index } => {
                if *index != i as u16 {
                    return Err(FloorFault::NonCanonicalMap(MapFault::AddressMismatch {
                        index: *index,
                    }));
                }
            }
            FreshQwRead::AmbiguousOrFault => {}
        }
    }
    for (j, cell) in snapshot.route1().iter().enumerate() {
        if let FreshQwRead::Clean(qw) = &cell.read {
            check(&mut seen, &mut n_seen, &mut epoch, qw, canonical_route1_addr(j))?;
        }
    }
    // Route-1 non-disjointness: both Clean reads must be distinct QWs at
    // their own canonical pages (a duplicate index already fired above;
    // identical (index, addr) pairs are caught the same way).
    if let (FreshQwRead::Clean(a), FreshQwRead::Clean(b)) =
        (&snapshot.route1()[0].read, &snapshot.route1()[1].read)
    {
        if a.index() == b.index() || a.addr() == b.addr() {
            return Err(FloorFault::NonCanonicalMap(MapFault::NonDisjointRoute1));
        }
    }
    Ok(())
}

/// Scan every reserved rollback QW and both Route-1 markers and yield
/// exactly one mutually exclusive class (FROZEN-OTP-API-3 L856–867).
///
/// Classification priority (L1014–1017): authoritative COMPLETE plus a
/// clean group → `Steady(T)`; bound completion recovery → `Recovering`;
/// ambiguous/conflicting completion authority → `Unknown`; only then
/// proven-no-completion-launch plus a mathematically dead plan →
/// `Aborted`. Accountancy (L926–932): any nonblank/corrected/
/// uncorrectable/may-have-launched QW outside the authenticated map
/// forces `Unknown`; no aliasing; no mutable head oracle.
pub fn decode_floor(snapshot: &FloorSnapshot) -> FloorView {
    // FULL scan mandatory (FROZEN-OTP-API-3): every one of the
    // RESERVED_ROLLBACK_QWS cells must be present — a prefix or
    // caller-trimmed map fails closed, never a lower floor.
    let present = snapshot.cells().iter().flatten().count();
    if present != RESERVED_ROLLBACK_QWS {
        return FloorView::Unknown(FloorFault::IncompleteMap {
            expected: RESERVED_ROLLBACK_QWS,
            got: present,
        });
    }
    // Canonical physical map next: no aliasing, no misaddressed reads,
    // one common probe pass (FROZEN-OTP-API-3 L926–932).
    if let Err(fault) = validate_physical_map(snapshot) {
        return FloorView::Unknown(fault);
    }
    // Route-1 accountancy (R3-6): only virgin or exact BASE0 codeword is
    // inside the authenticated map; anything else forces Unknown.
    let mut base_proof_ok = true;
    for (j, cell) in snapshot.route1().iter().enumerate() {
        match classify_route1(cell) {
            Route1Class::Virgin => base_proof_ok = false,
            Route1Class::Base0Marker => {}
            Route1Class::Orphan => {
                let index = match &cell.read {
                    FreshQwRead::Clean(qw) => qw.index(),
                    _ => 60 + j as u16,
                };
                return FloorView::Unknown(FloorFault::OrphanQw { index });
            }
            Route1Class::Uncertain => {
                return FloorView::Unknown(FloorFault::UncertainQw {
                    index: 60 + j as u16,
                });
            }
        }
    }
    let digest = snapshot_digest(snapshot);

    // ---- accountancy pass -------------------------------------------------
    let mut floor_records: [(u16, u32, u32); MAX_FLOOR_RECORDS] =
        [(0, 0, 0); MAX_FLOOR_RECORDS];
    let mut n_floor = 0usize;
    let mut completes: [u32; MAX_COMPLETE_RECORDS] = [0; MAX_COMPLETE_RECORDS];
    let mut n_complete = 0usize;
    let mut stages: [u32; MAX_STAGE_RECORDS] = [0; MAX_STAGE_RECORDS];
    let mut n_stage = 0usize;
    let mut n_virgin = 0u32;
    let mut n_uncertain = 0u32;
    let mut virgin_indices: [u16; RESERVED_ROLLBACK_QWS] = [0; RESERVED_ROLLBACK_QWS];
    let mut n_virgin_idx = 0usize;
    let mut uncertain_indices: [u16; RESERVED_ROLLBACK_QWS] = [0; RESERVED_ROLLBACK_QWS];
    let mut n_uncertain_idx = 0usize;
    let mut uncertain_index: Option<u16> = None;

    for (i, cell) in snapshot.cells().iter().enumerate() {
        let Some(cell) = cell else { continue };
        match classify_cell(cell) {
            CellClass::Virgin => {
                n_virgin += 1;
                virgin_indices[n_virgin_idx] = i as u16;
                n_virgin_idx += 1;
            }
            CellClass::Uncertain => {
                n_uncertain += 1;
                uncertain_index.get_or_insert(i as u16);
                uncertain_indices[n_uncertain_idx] = i as u16;
                n_uncertain_idx += 1;
            }
            CellClass::Orphan => {
                let index = match &cell.read {
                    FreshQwRead::Clean(qw) => qw.index(),
                    _ => i as u16,
                };
                return FloorView::Unknown(FloorFault::OrphanQw { index });
            }
            CellClass::Role(Record::Floor { t, g }) => {
                if n_floor == MAX_FLOOR_RECORDS {
                    return FloorView::Unknown(FloorFault::RecordOverflow {
                        kind: RecordKind::Floor,
                        index: i as u16,
                    });
                }
                floor_records[n_floor] = (i as u16, g, t);
                n_floor += 1;
            }
            CellClass::Role(Record::Complete { g }) => {
                if n_complete == MAX_COMPLETE_RECORDS {
                    return FloorView::Unknown(FloorFault::RecordOverflow {
                        kind: RecordKind::Complete,
                        index: i as u16,
                    });
                }
                completes[n_complete] = g;
                n_complete += 1;
            }
            CellClass::Role(Record::Stage { g }) => {
                if n_stage == MAX_STAGE_RECORDS {
                    return FloorView::Unknown(FloorFault::RecordOverflow {
                        kind: RecordKind::Stage,
                        index: i as u16,
                    });
                }
                stages[n_stage] = g;
                n_stage += 1;
            }
        }
    }

    // ---- committed groups -------------------------------------------------
    // A group is committed when its durable COMPLETE exists; it must
    // retain at least DEGRADED_THRESHOLD clean witnesses, and all its
    // floor records must agree on one target (no aliasing). The
    // committed history must be a valid monotone allocation sequence
    // (R6-3): no duplicate groups, targets non-decreasing in group
    // order; the allocation cursor is the max VALIDATED group.
    let mut committed_list: [(u32, u32); MAX_COMPLETE_RECORDS] = [(0, 0); MAX_COMPLETE_RECORDS];
    let mut n_committed = 0usize;
    for &g in &completes[..n_complete] {
        let mut t_val: Option<u32> = None;
        let mut witnesses = 0u32;
        for &(_, rg, rt) in &floor_records[..n_floor] {
            if rg == g {
                match t_val {
                    None => t_val = Some(rt),
                    Some(t0) if t0 != rt => {
                        return FloorView::Unknown(FloorFault::AliasedGroup { group: g });
                    }
                    _ => {}
                }
                witnesses += 1;
            }
        }
        if witnesses < DEGRADED_THRESHOLD {
            return FloorView::Unknown(FloorFault::MissingQuorum { group: g });
        }
        let t = t_val.unwrap_or(0);
        if t == 0 || t > crate::arm_token::T_MAX {
            return FloorView::Unknown(FloorFault::ConflictingCompletion);
        }
        committed_list[n_committed] = (g, t);
        n_committed += 1;
    }
    // Sequence validation: unique groups; targets non-decreasing in
    // group order. A non-monotone or duplicate history is Unknown,
    // never a silent max-pick.
    for w in committed_list[..n_committed].windows(2) {
        let ((g0, _), (g1, _)) = (w[0], w[1]);
        if g0 == g1 {
            return FloorView::Unknown(FloorFault::NonMonotoneAllocation);
        }
    }
    committed_list[..n_committed].sort_unstable_by_key(|&(g, _)| g);
    for w in committed_list[..n_committed].windows(2) {
        let ((_, t0), (_, t1)) = (w[0], w[1]);
        if t1 < t0 {
            return FloorView::Unknown(FloorFault::NonMonotoneAllocation);
        }
    }
    let committed: Option<(u32, u32)> = committed_list[..n_committed].last().copied();

    // A stage record for a group that is already committed is conflicting
    // completion authority.
    for &g in &stages[..n_stage] {
        if completes[..n_complete].contains(&g) {
            return FloorView::Unknown(FloorFault::ConflictingCompletion);
        }
    }

    // Floor records belonging to NO group context are orphan roles: any
    // record whose group has neither COMPLETE nor STAGE evidence forces
    // Unknown — in the committed-Steady arm just as in the active-stage
    // arm (§7.1 L2568–2569: orphaned evidence yields Unknown).
    for &(_, rg, _) in &floor_records[..n_floor] {
        if !completes[..n_complete].contains(&rg) && !stages[..n_stage].contains(&rg) {
            return FloorView::Unknown(FloorFault::AmbiguousStage);
        }
    }

    // ---- active stage ------------------------------------------------------
    let active: Option<u32> = match n_stage {
        0 => None,
        1 => Some(stages[0]),
        _ => return FloorView::Unknown(FloorFault::AmbiguousStage),
    };

    // Uncertain cells outside any stage plan force Unknown.
    if n_uncertain > 0 && active.is_none() {
        return FloorView::Unknown(FloorFault::UncertainQw {
            index: uncertain_index.unwrap_or(0),
        });
    }


    match active {
        None => {
            match committed {
                Some((g, t)) => FloorView::Steady(SteadyProof {
                    floor: t,
                    group: GroupIdentity::Group(g),
                    virgin_cells: n_virgin,
                    snapshot_digest: digest,
                }),
                None => {
                    // Canonical base: fully virgin bank, exact BASE0 pair,
                    // proven no launch anywhere (classify_cell already
                    // forced any may-have-launched cell to Uncertain, which
                    // returns above).
                    if n_floor == 0 && base_proof_ok && n_virgin as usize == RESERVED_ROLLBACK_QWS {
                        FloorView::Steady(SteadyProof {
                            floor: 0,
                            group: GroupIdentity::Base0,
                            virgin_cells: n_virgin,
                            snapshot_digest: digest,
                        })
                    } else if n_floor == 0 && n_virgin as usize == RESERVED_ROLLBACK_QWS {
                        FloorView::Unknown(FloorFault::MissingBaseProof)
                    } else {
                        // Floor records with no group structure at all.
                        FloorView::Unknown(FloorFault::AmbiguousStage)
                    }
                }
            }
        }
        Some(g) => {
            // The stage must carry its bound candidate identity.
            let binding = match snapshot.stage_binding() {
                Some(b) => b,
                None => return FloorView::Unknown(FloorFault::AmbiguousStage),
            };
            // Gather the stage's floor records; they must agree on one
            // target t > F (or > 0 with a BASE0 predecessor).
            let (prior_f, prior_group) = match committed {
                Some((cg, ct)) => (ct, GroupIdentity::Group(cg)),
                None => {
                    if !base_proof_ok {
                        // A first-bump stage may bind BASE0 only through
                        // the canonical proof (§7.1 L2577–2579).
                        return FloorView::Unknown(FloorFault::MissingBaseProof);
                    }
                    (0, GroupIdentity::Base0)
                }
            };
            let mut t_val: Option<u32> = None;
            let mut clean_records = 0u32;
            let mut stage_record_indices: [u16; MAX_FLOOR_RECORDS] = [0; MAX_FLOOR_RECORDS];
            let mut n_stage_records = 0usize;
            for &(idx, rg, rt) in &floor_records[..n_floor] {
                if rg == g {
                    match t_val {
                        None => t_val = Some(rt),
                        Some(t0) if t0 != rt => {
                            return FloorView::Unknown(FloorFault::AliasedGroup { group: g });
                        }
                        _ => {}
                    }
                    clean_records += 1;
                    stage_record_indices[n_stage_records] = idx;
                    n_stage_records += 1;
                }
            }
            // Floor records belonging to NO group context were already
            // rejected by the hoisted orphan-role check above.
            let t = match t_val {
                Some(t) => t,
                None => 0,
            };
            // FROZEN-OTP-API-3 L1009: `T > F` and checked `T == E - 1`.
            if t == 0 || t <= prior_f || t > crate::arm_token::T_MAX || binding.e().checked_sub(1) != Some(t) {
                return FloorView::Unknown(FloorFault::AmbiguousStage);
            }
            // Role-map accountancy (R5-3): the stage's authenticated
            // ordered role map is the ONLY map a QW may join — nothing
            // is absorbed implicitly. Every stage floor record must be a
            // planned Witness; every uncertain QW must be a planned
            // Consumed cell; every plan entry must match physical
            // reality.
            for &idx in &stage_record_indices[..n_stage_records] {
                if binding.role_of(idx) != Some(PlanRole::Witness) {
                    return FloorView::Unknown(FloorFault::UnmappedRole { index: idx });
                }
            }
            for &idx in &uncertain_indices[..n_uncertain_idx] {
                if binding.role_of(idx) != Some(PlanRole::Consumed) {
                    return FloorView::Unknown(FloorFault::UnmappedRole { index: idx });
                }
            }
            let mut n_reserved = 0u32;
            for &(idx, role) in binding.roles() {
                let mapped = match role {
                    PlanRole::Witness => stage_record_indices[..n_stage_records].contains(&idx),
                    PlanRole::Consumed => uncertain_indices[..n_uncertain_idx].contains(&idx),
                    PlanRole::Reserved => {
                        if virgin_indices[..n_virgin_idx].contains(&idx) {
                            n_reserved += 1;
                            true
                        } else {
                            false
                        }
                    }
                };
                if !mapped {
                    return FloorView::Unknown(FloorFault::UnmappedRole { index: idx });
                }
            }
            // Finite plan: achievable clean witnesses = clean records +
            // reserved virgin claims (and only those).
            let achievable = clean_records + n_reserved;
            if achievable >= INITIAL_THRESHOLD {
                FloorView::Recovering(RecoveryProof {
                    prior_f,
                    prior_group,
                    target: t,
                    group: g,
                    candidate_slot: binding.slot(),
                    candidate_digest: *binding.manifest_digest(),
                    clean_records,
                    snapshot_digest: digest,
                })
            } else {
                // Mathematically dead plan. Classification priority puts
                // Aborted LAST: only after no completion authority and no
                // ambiguity remains.
                match snapshot.completion_fence() {
                    CompletionLaunchEvidence::ProvenNoCompletionLaunch => {
                        FloorView::Aborted(DeadStageProof {
                            floor: prior_f,
                            failed_target: t,
                            failed_group: g,
                            failed_slot: binding.slot(),
                            failed_digest: *binding.manifest_digest(),
                            failed_r: binding.r(),
                            failed_e: binding.e(),
                            aborted_release_high_water: binding.r(),
                            snapshot_digest: digest,
                        })
                    }
                    CompletionLaunchEvidence::MayHaveLaunched => {
                        FloorView::Unknown(FloorFault::CompletionMayHaveLaunched)
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// T-vs-F classification + read-only preflight
// ---------------------------------------------------------------------------

/// The exact `T` vs `F` classification from fresh `Steady(F)`
/// (FROZEN-OTP-API-3 L934–940).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TClassification {
    /// `T < F` — inconsistent, fails closed.
    Inconsistent,
    /// `T == F` — same epoch: ZERO mutable-backend effects (no OTP
    /// program, no Route-1 write, no journal compaction).
    SameEpoch,
    /// `T > F` — epoch bump: read-only preflight receipt (comparison
    /// data, not durable authority).
    EpochBump,
}

/// Classify `T` against `F`.
pub fn classify_t(floor: u32, t: u32) -> TClassification {
    if t < floor {
        TClassification::Inconsistent
    } else if t == floor {
        TClassification::SameEpoch
    } else {
        TClassification::EpochBump
    }
}

/// The read-only `T > F` preflight receipt (FROZEN-OTP-API-3 L944–953).
/// Comparison data, NOT durable authority: the private immutable writer
/// reparses and reverifies all raw inputs before mutation. Carries no
/// method that performs or authorizes a write. Private fields: only
/// [`preflight`] can construct one (never struct-literal-forgeable, not
/// `Copy`-replayable).
#[derive(PartialEq, Eq, Debug)]
pub struct EpochBumpReceipt {
    floor: u32,
    target: u32,
    /// Next allocation group (model: committed group index + 1, or 1
    /// after BASE0).
    group: u32,
    /// Replacement margin: virgin cells available to the plan.
    margin: u32,
    snapshot_digest: [u8; 32],
}

impl EpochBumpReceipt {
    pub fn floor(&self) -> u32 {
        self.floor
    }

    pub fn target(&self) -> u32 {
        self.target
    }

    pub fn group(&self) -> u32 {
        self.group
    }

    pub fn margin(&self) -> u32 {
        self.margin
    }

    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
}

/// Snapshot-bound read-only preflight. Returns `None` unless `T > F`,
/// the allocation sequence can advance (fail-closed at
/// `u32::MAX`), and the proof's own virgin-cell count still funds one
/// full initial threshold. The margin is PROOF-BOUND (counted by the
/// decode, never caller-asserted), and the receipt binds the proof's
/// snapshot digest (currency proof for the recheck).
pub fn preflight(steady: &SteadyProof, target: u32) -> Option<EpochBumpReceipt> {
    let floor = steady.floor();
    if target <= floor || target > crate::arm_token::T_MAX {
        return None;
    }
    if steady.virgin_cells() < INITIAL_THRESHOLD {
        return None;
    }
    let group = match steady.group() {
        GroupIdentity::Base0 => 1,
        GroupIdentity::Group(g) => g.checked_add(1)?,
    };
    Some(EpochBumpReceipt {
        floor,
        target,
        group,
        margin: steady.virgin_cells(),
        snapshot_digest: *steady.snapshot_digest(),
    })
}
