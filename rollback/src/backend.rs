//! The backend trait surface for the six frozen entries plus a
//! no_std fake/scripted storage backend for host tests.
//!
//! The fake backend implements [`FreshArrayProbe`] (the only
//! [`crate::qw_read::CleanQw`] source outside the crate internals) and
//! [`RollbackBackend`] with a fixed-capacity mutation log, so tests can
//! assert exact write behavior — including ZERO mutable-backend effects
//! on the `T == F` and `Aborted` paths (hard design rule 7).

use crate::arm_token::ArmState;
use crate::floor::EpochBumpReceipt;
use crate::qw_read::{FreshArrayProbe, RawProbeOutcome};

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
}

/// Scriptable probe outcome for the fake backend (Copy data only; the
/// typed [`crate::qw_read::FreshQwRead`] wrapper is built by the
/// [`FreshArrayProbe`] provided method).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeScript {
    /// ECC-clean read of these bytes.
    Clean([u8; 16]),
    /// ECC-corrected read (zero quorum weight).
    Corrected([u8; 16]),
    /// ECC double-bit error.
    Uncorrectable,
    /// Torn / may-have-launched / faulted.
    AmbiguousOrFault,
}

/// A no_std fake/scripted storage backend for host tests. Fixed
/// capacity: `CELLS` probe scripts and 64 log entries.
pub struct ScriptedBackend<const CELLS: usize = 64> {
    probe_epoch: u32,
    scripts: [Option<(u16, u32, ProbeScript)>; CELLS],
    token: Option<[u32; crate::arm_token::TOKEN_WORDS]>,
    log: [Option<Mutation>; 64],
    log_len: usize,
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
        }
    }

    /// Script one exact-index probe outcome. A second script for the same
    /// index replaces the first.
    pub fn script(&mut self, index: u16, addr: u32, outcome: ProbeScript) {
        for slot in self.scripts.iter_mut() {
            match slot {
                Some((i, a, o)) if *i == index => {
                    *a = addr;
                    *o = outcome;
                    return;
                }
                None => {
                    *slot = Some((index, addr, outcome));
                    return;
                }
                _ => {}
            }
        }
        panic!("script capacity exhausted");
    }

    /// Plant an arm token (or remove it with `None`).
    pub fn set_arm_token(&mut self, token: Option<[u32; crate::arm_token::TOKEN_WORDS]>) {
        self.token = token;
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

    fn fresh_raw_read(&mut self, index: u16, addr: u32) -> RawProbeOutcome {
        for slot in self.scripts.iter() {
            if let Some((i, _, outcome)) = slot {
                if *i == index {
                    return match outcome {
                        ProbeScript::Clean(bytes) => RawProbeOutcome::Clean { bytes: *bytes },
                        ProbeScript::Corrected(bytes) => RawProbeOutcome::Corrected { bytes: *bytes },
                        ProbeScript::Uncorrectable => RawProbeOutcome::Uncorrectable,
                        ProbeScript::AmbiguousOrFault => RawProbeOutcome::AmbiguousOrFault,
                    };
                }
            }
        }
        // Unscripted indices fail closed.
        let _ = addr;
        RawProbeOutcome::AmbiguousOrFault
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
            target: receipt.target,
            group: receipt.group,
        });
    }

    fn resume_floor_plan(&mut self, target: u32) {
        self.record(Mutation::FloorResume { target });
    }

    fn mutation_log(&self) -> &[Option<Mutation>] {
        &self.log[..self.log_len]
    }
}
