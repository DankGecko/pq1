//! The backend trait surface for the six frozen entries plus (behind the
//! `test-backend` feature) a fake/scripted storage backend for host
//! tests.
//!
//! The library builds WITHOUT the fake: only [`Mutation`] and the
//! [`RollbackBackend`] trait are always present. The fake is compiled
//! only with `--features test-backend` (enabled for this crate's own
//! integration tests via a self dev-dependency) and provides the
//! scripted [`FreshArrayProbe`] source plus a mutation log for
//! zero-write assertions and the FA-1.4 per-commitment measured-cost
//! accounting (`PlanCostAccount`/`BegunPlan`, test builds only).

use crate::arm_token::ArmState;
use crate::floor::{EpochBumpReceipt, FloorView};

/// One recorded backend mutation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mutation {
    /// TAMP token state transition (`ARM_READY -> ATTEMPTED`).
    ArmTokenTransition(ArmState),
    /// One `begin(intent)` for a preflighted `T > F` plan.
    FloorBegin { target: u32, group: u32 },
    /// One resume step of a bound active plan.
    FloorResume { target: u32 },
}

/// One-time permit for the TAMP `ARM_READY -> ATTEMPTED` transition.
/// Minted ONLY inside the six typed entries (crate-private constructor)
/// after the entry's pre-mutation validation. Linear: the backend call
/// consumes it.
pub struct ArmTransitionPermit {
    to: ArmState,
}

impl ArmTransitionPermit {
    pub(crate) fn mint(to: ArmState) -> Self {
        ArmTransitionPermit { to }
    }

    /// The transition the permit authorizes.
    pub fn to(&self) -> ArmState {
        self.to
    }
}

/// One-time permit for one `begin(intent)` floor-plan mutation.
/// Minted ONLY inside `start_from_steady` after the frozen recheck.
pub struct FloorBeginPermit {
    target: u32,
    group: u32,
}

impl FloorBeginPermit {
    pub(crate) fn mint(target: u32, group: u32) -> Self {
        FloorBeginPermit { target, group }
    }

    /// The plan target.
    pub fn target(&self) -> u32 {
        self.target
    }

    /// The plan's allocation group.
    pub fn group(&self) -> u32 {
        self.group
    }
}

/// One-time permit for one resume step of a bound active plan. Minted
/// ONLY inside `resume_from_recovery` after the frozen recheck.
pub struct FloorResumePermit {
    target: u32,
}

impl FloorResumePermit {
    pub(crate) fn mint(target: u32) -> Self {
        FloorResumePermit { target }
    }

    /// The resumed plan target.
    pub fn target(&self) -> u32 {
        self.target
    }
}

/// Fresh re-probed artifact evidence for the frozen
/// recheck-immediately-before-handoff (R6-1): the artifact's
/// re-derived identity plus fresh reads of all five journal QWs at the
/// identity's canonical addresses, each with explicit attributions.
pub struct ArtifactRecheck {
    /// The re-parsed manifest page (R18-3: the ENTRY re-runs the
    /// embedded-key verification against it — the backend returns RAW
    /// evidence, it does not attest validity).
    pub manifest: fw_manifest::v6::ManifestV6,
    /// `QW_CONFIRMED_0` fresh read + attributions.
    pub terminal_c0: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
    /// `QW_CONFIRMED_1` fresh read + attributions.
    pub terminal_c1: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
    /// `QW_PENDING` fresh read + attributions.
    pub pending: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
    /// `QW_INSTALL_ID` fresh read + attributions.
    pub install_id: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
    /// `QW_INSTALL_ID_INV` fresh read + attributions.
    pub install_id_inv: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
}

/// Terminal-only artifact recheck (R15-2): the terminal QWs and
/// install-identity halves, NO PENDING probe — the physical acquisition
/// for terminal-authoritative (Robust) artifacts never touches the
/// PENDING field at all.
pub struct TerminalRecheck {
    /// The re-parsed manifest page (R18-3: the ENTRY re-runs the
    /// embedded-key verification against it).
    pub manifest: fw_manifest::v6::ManifestV6,
    /// `QW_CONFIRMED_0` fresh read + attributions.
    pub terminal_c0: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
    /// `QW_CONFIRMED_1` fresh read + attributions.
    pub terminal_c1: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
    /// `QW_INSTALL_ID` fresh read + attributions.
    pub install_id: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
    /// `QW_INSTALL_ID_INV` fresh read + attributions.
    pub install_id_inv: (crate::qw_read::FreshQwRead, crate::qw_read::Durability, crate::qw_read::LaunchAttribution),
}

/// The mutation surface the six entries may touch. Deliberately narrow:
/// token transitions and floor-plan begin/resume ONLY — there is no
/// generic write method, so an entry physically cannot reach manifests,
/// images, Route-1 pages, or OTP outside these typed calls. Every
/// mutation consumes a one-time permit minted inside a typed entry
/// (R5-2): no downstream caller can mutate directly.
pub trait RollbackBackend {
    /// Current arm-token words, if any token is present.
    fn read_arm_token(&self) -> Option<[u32; crate::arm_token::TOKEN_WORDS]>;

    /// Perform the TAMP state transition (`ARM_READY -> ATTEMPTED`).
    fn transition_arm_token(&mut self, permit: ArmTransitionPermit);

    /// Invoke `begin(intent)` exactly once for a preflighted plan.
    fn begin_floor_plan(&mut self, permit: FloorBeginPermit, receipt: &EpochBumpReceipt);

    /// Resume one step of the bound active plan.
    fn resume_floor_plan(&mut self, permit: FloorResumePermit);

    /// The complete mutation log prefix (for zero-write assertions).
    fn mutation_log(&self) -> &[Option<Mutation>];

    /// Repeat the complete floor/stage decode against CURRENT backend
    /// state (FROZEN-OTP-API-3 L898–900, §10 L3625–3632: every typed
    /// entry requires a fresh full decode against newly forced, newly
    /// attributed per-QW reads immediately before mutation/handoff).
    /// This is the capability behind the frozen recheck-before-handoff.
    fn redecode_floor(&mut self) -> FloorView;

    /// Re-probe the artifact evidence for `identity` (manifest page,
    /// terminal QWs, install generation) against CURRENT backend state
    /// — the artifact half of the frozen pre-handoff recheck (R6-1).
    /// `None` when the backend cannot produce a coherent re-read.
    ///
    /// CONTRACT (R16-4 + R18-3): the backend returns RAW evidence — a
    /// structurally valid re-parse of the manifest page plus the fresh
    /// journal reads. The backend performs NO signature verification;
    /// the ENTRY re-runs the embedded-key C10 check against the
    /// returned page. A backend that swaps in a different manifest is
    /// caught structurally by the entry's identity comparison.
    fn reverify_artifact(
        &mut self,
        identity: &crate::evidence::ArtifactIdentity,
    ) -> Option<ArtifactRecheck>;

    /// Terminal-only variant for terminal-authoritative (Robust)
    /// artifacts (R15-2): never probes the PENDING QW. Same R16-4
    /// signature-verification contract as [`Self::reverify_artifact`].
    fn reverify_terminal(
        &mut self,
        identity: &crate::evidence::ArtifactIdentity,
    ) -> Option<TerminalRecheck>;
}

// ---------------------------------------------------------------------------
// Fake/scripted backend — test builds ONLY (`test-backend` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "test-backend")]
mod scripted {
    use super::{
        ArmTransitionPermit, ArtifactRecheck, FloorBeginPermit, FloorResumePermit, Mutation,
        RollbackBackend, TerminalRecheck,
    };
    use crate::floor::{
        self, CompletionLaunchEvidence, EpochBumpReceipt, FloorView, StageBinding,
    };
    use crate::qw_read::{Durability, FreshArrayProbe, LaunchAttribution, ProbeStatus, RawProbeResult};

    /// Scriptable probe script for the fake backend (Copy data only).
    /// The script sets the raw STATUS (and bytes where meaningful); the
    /// outcome class is derived canonically by
    /// [`FreshArrayProbe::fresh_probe`], never chosen here.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ProbeScript {
        /// ECC-clean read of these bytes (status: no ECC event).
        Clean([u8; 16]),
        /// Single-bit ECC correction (status: corrected).
        Corrected([u8; 16]),
        /// Double-bit ECC error (status: ECCD).
        Uncorrectable,
        /// Unattributable read (status: torn/fault/may-have-launched).
        AmbiguousOrFault,
    }

    /// One scripted journal-QW read: outcome plus explicit attributions.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct JournalQwScript {
        pub outcome: ProbeScript,
        pub durability: Durability,
        pub launch: LaunchAttribution,
    }

    /// A complete scripted artifact for `reverify_artifact` (R6-1): the
    /// signed manifest page, its key material, and the five journal QWs.
    pub struct ArtifactScript {
        pub page: [u8; 8192],
        pub pk_seed: [u8; 16],
        pub pk_root: [u8; 16],
        pub terminal_c0: JournalQwScript,
        pub terminal_c1: JournalQwScript,
        pub pending: JournalQwScript,
        pub install_id: JournalQwScript,
        pub install_id_inv: JournalQwScript,
    }

    /// One scripted floor-bank cell: probe outcome plus the explicit
    /// attributions the decoder requires.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct FloorCellScript {
        pub outcome: ProbeScript,
        pub durability: Durability,
        pub launch: LaunchAttribution,
    }

    /// A complete scripted floor/stage state for `redecode_floor`.
    pub struct FloorScript {
        pub cells: [Option<FloorCellScript>; 32],
        pub cells_len: usize,
        pub route1: [FloorCellScript; 2],
        pub completion_fence: CompletionLaunchEvidence,
        pub stage_binding: Option<StageBinding>,
    }

    impl FloorScript {
        /// An empty-bank script (all cells clean-erased, both Route-1
        /// markers clean-erased).
        pub fn empty() -> Self {
            let erased = FloorCellScript {
                outcome: ProbeScript::Clean([0xFF; 16]),
                durability: Durability::DurableClean,
                launch: LaunchAttribution::ProvenNoLaunch,
            };
            FloorScript {
                cells: [Some(erased); 32],
                cells_len: 0,
                route1: [erased, erased],
                completion_fence: CompletionLaunchEvidence::ProvenNoCompletionLaunch,
                stage_binding: None,
            }
        }

        /// Append one cell (fail-closed: returns false past capacity).
        pub fn push(&mut self, cell: FloorCellScript) -> bool {
            if self.cells_len >= self.cells.len() {
                return false;
            }
            self.cells[self.cells_len] = Some(cell);
            self.cells_len += 1;
            true
        }
    }

    /// The measured five-component cost of one logical target commitment
    /// (FA-1.4; Draft 1.1 §14 L4380–4384: "the approved codec's
    /// explicitly measured reservation, replica, completion, replacement,
    /// and recovery cost"). Every value derives from the MODEL codec's
    /// frozen constants (`floor.rs`); `OPEN-OTP-1..3` owns the production
    /// numbers. TEST-ONLY (the fake backend's account).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct PlanCostAccount {
        /// Durable stage-activation (`STAGEACT`) reservation cell, drawn
        /// from the same virgin bank as the plan (R10-4; the model
        /// codec's `+1` marker cell).
        pub reservation: u32,
        /// Initial replica witness cells required at establishment
        /// (`floor::INITIAL_THRESHOLD`).
        pub replica: u32,
        /// Durable `COMPLETE` marker cell attesting the full initial
        /// clean threshold was EOP-verified at establishment (R10-4's
        /// second marker cell; R11-2 requires it to remain available
        /// beyond the plan's own claims).
        pub completion: u32,
        /// Replacement margin cell inside the finite plan
        /// (`floor::PLAN_CELLS - floor::INITIAL_THRESHOLD` — "three
        /// initial replicas plus one replacement", floor.rs L28–29; the
        /// claimable `PlanRole::Reserved` cell).
        pub replacement: u32,
        /// Recovery draw: ZERO per commitment. The §12.3 L3930–3932
        /// recovery cell is a bank-level preserve outside the
        /// per-commitment account, and `resume_from_recovery`
        /// re-establishes the bound plan from its already-accounted
        /// cells — it never begins a new plan (FROZEN-OTP-API-3
        /// L1000–1002). The field exists so the account names every
        /// §14 component explicitly.
        pub recovery: u32,
    }

    impl PlanCostAccount {
        /// The MODEL codec's measured per-commitment cost. The total
        /// provably equals the frozen preflight gate `PLAN_CELLS + 2`
        /// (floor.rs L1554–1582, R10-4): three replica witnesses + one
        /// replacement + the STAGEACT and COMPLETE marker cells.
        pub const MODEL: PlanCostAccount = PlanCostAccount {
            reservation: 1,
            replica: crate::floor::INITIAL_THRESHOLD,
            completion: 1,
            replacement: crate::floor::PLAN_CELLS - crate::floor::INITIAL_THRESHOLD,
            recovery: 0,
        };

        /// Total virgin-bank cells one logical target commitment draws.
        pub fn total(&self) -> u32 {
            self.reservation + self.replica + self.completion + self.replacement + self.recovery
        }
    }

    /// One accounted logical target commitment: the target, its
    /// allocation group, the measured five-component cost, and the
    /// proof-bound virgin margin the receipt carried at begin (R10-4).
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct BegunPlan {
        /// The plan target (`T > F` at begin).
        pub target: u32,
        /// The allocation group the plan was admitted under.
        pub group: u32,
        /// The measured five-component cost of this commitment.
        pub cost: PlanCostAccount,
        /// The receipt's proof-bound virgin-cell margin at begin.
        pub margin: u32,
    }

    /// A fake/scripted storage backend for host tests. Fixed capacity:
    /// `CELLS` probe scripts, 64 mutation-log entries. TEST-ONLY.
    pub struct ScriptedBackend<const CELLS: usize = 64> {
        probe_epoch: u32,
        scripts: [Option<(u16, u32, ProbeScript)>; CELLS],
        token: Option<[u32; crate::arm_token::TOKEN_WORDS]>,
        log: [Option<Mutation>; 64],
        log_len: usize,
        floor_script: Option<FloorScript>,
        artifact_scripts: [Option<ArtifactScript>; 2],
        begun: [Option<BegunPlan>; 8],
        n_begun: usize,
    }

    impl<const CELLS: usize> Default for ScriptedBackend<CELLS> {
        fn default() -> Self {
            Self::new(1)
        }
    }

    impl<const CELLS: usize> ScriptedBackend<CELLS> {
        /// A backend with the given immutable-entry probe epoch.
        pub fn new(probe_epoch: u32) -> Self {
            ScriptedBackend {
                probe_epoch,
                scripts: [None; CELLS],
                token: None,
                log: [None; 64],
                log_len: 0,
                floor_script: None,
                artifact_scripts: [None, None],
                begun: [None; 8],
                n_begun: 0,
            }
        }

        /// Script one exact-index probe outcome. A second script for the
        /// same index replaces the first. Returns false past capacity
        /// (fail-closed; the caller must not assume the script landed).
        pub fn script(&mut self, index: u16, addr: u32, outcome: ProbeScript) -> bool {
            for slot in self.scripts.iter_mut() {
                match slot {
                    Some((i, a, o)) if *i == index => {
                        *a = addr;
                        *o = outcome;
                        return true;
                    }
                    None => {
                        *slot = Some((index, addr, outcome));
                        return true;
                    }
                    _ => {}
                }
            }
            false
        }

        /// Plant an arm token (or remove it with `None`).
        pub fn set_arm_token(&mut self, token: Option<[u32; crate::arm_token::TOKEN_WORDS]>) {
            self.token = token;
        }

        /// Clear every scripted probe outcome (used before loading a
        /// floor script for `redecode_floor`).
        pub fn clear_probe_scripts(&mut self) {
            self.scripts = [None; CELLS];
        }

        /// Set (or replace) the floor/stage script consumed by
        /// `redecode_floor`. Replacing it between intent construction and
        /// entry is how drift tests simulate backend mutation.
        pub fn set_floor_script(&mut self, script: FloorScript) {
            self.floor_script = Some(script);
        }

        /// Set (or replace) the artifact script for `slot`, consumed by
        /// `reverify_artifact`. Replacing it between intent construction
        /// and entry is how artifact-drift tests simulate physical
        /// mutation.
        pub fn set_artifact_script(&mut self, slot: fw_manifest::v6::PhysicalSlot, script: ArtifactScript) {
            let idx = match slot {
                fw_manifest::v6::PhysicalSlot::A => 0,
                fw_manifest::v6::PhysicalSlot::B => 1,
            };
            self.artifact_scripts[idx] = Some(script);
        }

        /// Number of recorded mutations.
        pub fn mutation_count(&self) -> usize {
            self.log_len
        }

        /// True iff the backend recorded ZERO mutations (the `T == F` /
        /// `Aborted` no-write assertion).
        pub fn is_pristine(&self) -> bool {
            self.log_len == 0
        }

        /// Count floor-plan mutations (`FloorBegin` + `FloorResume`).
        pub fn floor_mutation_count(&self) -> usize {
            self.log[..self.log_len]
                .iter()
                .flatten()
                .filter(|m| matches!(m, Mutation::FloorBegin { .. } | Mutation::FloorResume { .. }))
                .count()
        }

        /// Number of logical target commitments begun through this
        /// backend (FA-1.4: exactly one per target, ever).
        pub fn begun_plan_count(&self) -> usize {
            self.n_begun
        }

        /// The accounted commitment for `target`, if one began.
        pub fn begun_plan(&self, target: u32) -> Option<BegunPlan> {
            self.begun[..self.n_begun]
                .iter()
                .flatten()
                .find(|p| p.target == target)
                .copied()
        }

        fn record(&mut self, m: Mutation) {
            assert!(self.log_len < 64, "mutation log capacity exhausted");
            self.log[self.log_len] = Some(m);
            self.log_len += 1;
        }
    }

    impl<const CELLS: usize> FreshArrayProbe for ScriptedBackend<CELLS> {
        fn probe_epoch(&self) -> u32 {
            self.probe_epoch
        }

        fn fresh_raw_read(&mut self, index: u16, addr: u32) -> RawProbeResult {
            for slot in self.scripts.iter() {
                if let Some((i, _, outcome)) = slot {
                    if *i == index {
                        return match outcome {
                            ProbeScript::Clean(bytes) => RawProbeResult {
                                bytes: *bytes,
                                status: ProbeStatus::NoEccEvent,
                            },
                            ProbeScript::Corrected(bytes) => RawProbeResult {
                                bytes: *bytes,
                                status: ProbeStatus::EccCorrected,
                            },
                            ProbeScript::Uncorrectable => RawProbeResult {
                                bytes: [0xFF; 16],
                                status: ProbeStatus::EccDoubleError,
                            },
                            ProbeScript::AmbiguousOrFault => RawProbeResult {
                                bytes: [0xFF; 16],
                                status: ProbeStatus::Unattributable,
                            },
                        };
                    }
                }
            }
            // Unscripted indices fail closed.
            let _ = addr;
            RawProbeResult {
                bytes: [0xFF; 16],
                status: ProbeStatus::Unattributable,
            }
        }
    }

    impl<const CELLS: usize> RollbackBackend for ScriptedBackend<CELLS> {
        fn read_arm_token(&self) -> Option<[u32; crate::arm_token::TOKEN_WORDS]> {
            self.token
        }

        fn transition_arm_token(&mut self, permit: ArmTransitionPermit) {
            let to = permit.to();
            if let Some(mut words) = self.token {
                let (s, s_inv) = to.pair();
                words[crate::arm_token::WORD_STATE] = s;
                words[crate::arm_token::WORD_STATE + 1] = s_inv;
                self.token = Some(words);
            }
            self.record(Mutation::ArmTokenTransition(to));
        }

        fn begin_floor_plan(&mut self, permit: FloorBeginPermit, receipt: &EpochBumpReceipt) {
            // FA-1.4 (§14 L4380–4384): account the measured five-component
            // cost of this one logical target commitment. Two fail-loud
            // guards model physical truth so an entry-level regression
            // cannot pass silently:
            //   * one logical target commitment per target, ever — the
            //     real bank can host at most one plan for `T` (while it
            //     is in flight the decode is Recovering; once completed
            //     `T == F` classifies same-epoch), and the entry's frozen
            //     recheck is the primary gate;
            //   * the receipt's proof-bound margin must fund the measured
            //     plan (the entry's `receipt_matches` enforces the same
            //     `PLAN_CELLS + 2` gate, R10-4).
            let cost = PlanCostAccount::MODEL;
            assert!(
                !self.begun[..self.n_begun]
                    .iter()
                    .flatten()
                    .any(|p| p.target == permit.target()),
                "a second plan for the same target can never begin"
            );
            assert!(
                receipt.margin() >= cost.total(),
                "receipt margin cannot fund the measured commitment cost"
            );
            assert!(self.n_begun < self.begun.len(), "begun-plan log capacity exhausted");
            self.begun[self.n_begun] = Some(BegunPlan {
                target: permit.target(),
                group: permit.group(),
                cost,
                margin: receipt.margin(),
            });
            self.n_begun += 1;
            self.record(Mutation::FloorBegin {
                target: permit.target(),
                group: permit.group(),
            });
        }

        fn resume_floor_plan(&mut self, permit: FloorResumePermit) {
            self.record(Mutation::FloorResume {
                target: permit.target(),
            });
        }

        fn mutation_log(&self) -> &[Option<Mutation>] {
            &self.log[..self.log_len]
        }

        fn redecode_floor(&mut self) -> FloorView {
            // Extract the script into locals first (StageBinding is
            // linear; it is reconstructed through the range-checked
            // constructor), then mutate the probe table.
            let (cells, cells_len, route1, fence, binding) = {
                let Some(script) = self.floor_script.as_ref() else {
                    // No scripted floor state: fail CLOSED.
                    return FloorView::Unknown(floor::FloorFault::AmbiguousStage);
                };
                let mut cells: [Option<FloorCellScript>; 32] = [None; 32];
                cells[..script.cells_len].copy_from_slice(&script.cells[..script.cells_len]);
                let binding = script.stage_binding.as_ref().map(|b| {
                    floor::StageBinding::new(
                        b.slot(),
                        b.r(),
                        b.e(),
                        *b.manifest_digest(),
                        b.install_id(),
                        *b.roles(),
                    )
                    .expect("script binding was validated")
                });
                (
                    cells,
                    script.cells_len,
                    script.route1,
                    script.completion_fence,
                    binding,
                )
            };
            // Load the scripted outcomes for EVERY canonical index
            // (unscripted tail = canonical virgin), then run the REAL
            // decoder over a freshly probed full scan.
            self.clear_probe_scripts();
            for (i, cell) in cells[..cells_len].iter().enumerate() {
                if let Some(scripted) = cell {
                    let addr = floor::canonical_cell_addr(i as u16);
                    self.script(i as u16, addr, scripted.outcome);
                }
            }
            for i in cells_len..floor::RESERVED_ROLLBACK_QWS {
                let addr = floor::canonical_cell_addr(i as u16);
                self.script(i as u16, addr, ProbeScript::Clean([0xFF; 16]));
            }
            for (j, cell) in route1.iter().enumerate() {
                let addr = floor::canonical_route1_addr(j);
                self.script(60 + j as u16, addr, cell.outcome);
            }
            let mut attrs = [(
                Durability::DurableClean,
                LaunchAttribution::ProvenNoLaunch,
            ); floor::RESERVED_ROLLBACK_QWS];
            for (i, cell) in cells[..cells_len].iter().enumerate() {
                if let Some(c) = cell {
                    attrs[i] = (c.durability, c.launch);
                }
            }
            let snapshot = floor::FloorSnapshot::probe(
                self,
                fence,
                binding,
                &attrs,
                [
                    (route1[0].durability, route1[0].launch),
                    (route1[1].durability, route1[1].launch),
                ],
            );
            floor::decode_floor(&snapshot)
        }

        fn reverify_artifact(
            &mut self,
            identity: &crate::evidence::ArtifactIdentity,
        ) -> Option<ArtifactRecheck> {
            let idx = match identity.slot {
                fw_manifest::v6::PhysicalSlot::A => 0,
                fw_manifest::v6::PhysicalSlot::B => 1,
            };
            // Extract the script into locals first (everything is
            // Copy), then probe with &mut self.
            let (page, pk_seed, pk_root, t_c0, t_c1, pd, iid, iid_inv) = {
                let script = self.artifact_scripts[idx].as_ref()?;
                (
                    script.page,
                    script.pk_seed,
                    script.pk_root,
                    script.terminal_c0,
                    script.terminal_c1,
                    script.pending,
                    script.install_id,
                    script.install_id_inv,
                )
            };
            // R18-3: RAW evidence only — structurally parse the page
            // (the ENTRY owns the signature verification now; the
            // key-material fields in the script are unused here).
            let _ = (pk_seed, pk_root);
            let m = fw_manifest::v6::parse_and_validate(&page, identity.slot).ok()?;
            let ProbeScript::Clean(install_id) = iid.outcome else {
                return None;
            };
            // R10-6: when the complement half is also a clean read,
            // cross-check exact complementarity before deriving (a
            // torn/ambiguous half is legitimate survivor territory and
            // is left to the generation layer).
            if let ProbeScript::Clean(inv) = iid_inv.outcome {
                let mut complement = [0u8; 16];
                for (i, b) in complement.iter_mut().enumerate() {
                    *b = !install_id[i];
                }
                if inv != complement {
                    return None;
                }
            }
            let mk = |b: &mut Self, index: u16, addr: u32, s: &JournalQwScript| {
                assert!(b.script(index, addr, s.outcome));
                (b.fresh_probe(index, addr), s.durability, s.launch)
            };
            let terminal_c0 = mk(self, 40, identity.confirmed_0_qw_address, &t_c0);
            let terminal_c1 = mk(self, 41, identity.confirmed_1_qw_address, &t_c1);
            let pending = mk(self, 42, identity.pending_qw_address, &pd);
            let install = mk(self, 43, identity.install_id_qw_address(), &iid);
            let install_inv = mk(self, 44, identity.install_id_inv_qw_address(), &iid_inv);
            Some(ArtifactRecheck {
                manifest: m,
                terminal_c0,
                terminal_c1,
                pending,
                install_id: install,
                install_id_inv: install_inv,
            })
        }

        fn reverify_terminal(
            &mut self,
            identity: &crate::evidence::ArtifactIdentity,
        ) -> Option<TerminalRecheck> {
            // R15-2: never reads the PENDING QW. Duplicate the manifest
            // leg of reverify_artifact, minus the pending probe.
            let idx = match identity.slot {
                fw_manifest::v6::PhysicalSlot::A => 0,
                fw_manifest::v6::PhysicalSlot::B => 1,
            };
            let (page, pk_seed, pk_root, t_c0, t_c1, iid, iid_inv) = {
                let script = self.artifact_scripts[idx].as_ref()?;
                (
                    script.page,
                    script.pk_seed,
                    script.pk_root,
                    script.terminal_c0,
                    script.terminal_c1,
                    script.install_id,
                    script.install_id_inv,
                )
            };
            let m = fw_manifest::v6::parse_and_validate(&page, identity.slot).ok()?;
            let ProbeScript::Clean(install_id) = iid.outcome else {
                return None;
            };
            if let ProbeScript::Clean(inv) = iid_inv.outcome {
                let mut complement = [0u8; 16];
                for (i, b) in complement.iter_mut().enumerate() {
                    *b = !install_id[i];
                }
                if inv != complement {
                    return None;
                }
            }
            let _ = (pk_seed, pk_root);
            let mk = |b: &mut Self, index: u16, addr: u32, s: &JournalQwScript| {
                assert!(b.script(index, addr, s.outcome));
                (b.fresh_probe(index, addr), s.durability, s.launch)
            };
            let terminal_c0 = mk(self, 40, identity.confirmed_0_qw_address, &t_c0);
            let terminal_c1 = mk(self, 41, identity.confirmed_1_qw_address, &t_c1);
            let install = mk(self, 43, identity.install_id_qw_address(), &iid);
            let install_inv = mk(self, 44, identity.install_id_inv_qw_address(), &iid_inv);
            Some(TerminalRecheck {
                manifest: m,
                terminal_c0,
                terminal_c1,
                install_id: install,
                install_id_inv: install_inv,
            })
        }
    }
}

#[cfg(feature = "test-backend")]
pub use scripted::*;
