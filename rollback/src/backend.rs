//! The backend trait surface for the six frozen entries plus (behind the
//! `test-backend` feature) a fake/scripted storage backend for host
//! tests.
//!
//! The library builds WITHOUT the fake: only [`Mutation`] and the
//! [`RollbackBackend`] trait are always present. The fake is compiled
//! only with `--features test-backend` (enabled for this crate's own
//! integration tests via a self dev-dependency) and provides the
//! scripted [`FreshArrayProbe`] source plus a mutation log for
//! zero-write assertions.

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

/// The mutation surface the six entries may touch. Deliberately narrow:
/// token transitions and floor-plan begin/resume ONLY — there is no
/// generic write method, so an entry physically cannot reach manifests,
/// images, Route-1 pages, or OTP outside these typed calls.
pub trait RollbackBackend {
    /// Current arm-token words, if any token is present.
    fn read_arm_token(&self) -> Option<[u32; crate::arm_token::TOKEN_WORDS]>;

    /// Perform the TAMP state transition (`ARM_READY -> ATTEMPTED`).
    fn transition_arm_token(&mut self, to: ArmState);

    /// Invoke `begin(intent)` exactly once for a preflighted plan.
    fn begin_floor_plan(&mut self, receipt: &EpochBumpReceipt);

    /// Resume one step of the bound active plan.
    fn resume_floor_plan(&mut self, target: u32);

    /// The complete mutation log prefix (for zero-write assertions).
    fn mutation_log(&self) -> &[Option<Mutation>];

    /// Repeat the complete floor/stage decode against CURRENT backend
    /// state (FROZEN-OTP-API-3 L898–900, §10 L3625–3632: every typed
    /// entry requires a fresh full decode against newly forced, newly
    /// attributed per-QW reads immediately before mutation/handoff).
    /// This is the capability behind the frozen recheck-before-handoff.
    fn redecode_floor(&mut self) -> FloorView;
}

// ---------------------------------------------------------------------------
// Fake/scripted backend — test builds ONLY (`test-backend` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "test-backend")]
mod scripted {
    use super::{Mutation, RollbackBackend};
    use crate::arm_token::ArmState;
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

    /// A fake/scripted storage backend for host tests. Fixed capacity:
    /// `CELLS` probe scripts, 64 mutation-log entries. TEST-ONLY.
    pub struct ScriptedBackend<const CELLS: usize = 64> {
        probe_epoch: u32,
        scripts: [Option<(u16, u32, ProbeScript)>; CELLS],
        token: Option<[u32; crate::arm_token::TOKEN_WORDS]>,
        log: [Option<Mutation>; 64],
        log_len: usize,
        floor_script: Option<FloorScript>,
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

        fn transition_arm_token(&mut self, to: ArmState) {
            if let Some(mut words) = self.token {
                let (s, s_inv) = to.pair();
                words[crate::arm_token::WORD_STATE] = s;
                words[crate::arm_token::WORD_STATE + 1] = s_inv;
                self.token = Some(words);
            }
            self.record(Mutation::ArmTokenTransition(to));
        }

        fn begin_floor_plan(&mut self, receipt: &EpochBumpReceipt) {
            self.record(Mutation::FloorBegin {
                target: receipt.target(),
                group: receipt.group(),
            });
        }

        fn resume_floor_plan(&mut self, target: u32) {
            self.record(Mutation::FloorResume { target });
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
                    floor::StageBinding::new(b.slot(), b.r(), b.e(), *b.manifest_digest())
                        .expect("script binding was range-checked")
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
    }
}

#[cfg(feature = "test-backend")]
pub use scripted::*;
