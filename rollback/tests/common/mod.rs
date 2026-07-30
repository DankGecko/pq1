//! Shared helpers for the pqsigner-rollback host behavioral suite.
//! Test-side only.

#![allow(dead_code)]

use fw_manifest::v6::{self, ManifestV6, PhysicalSlot, ReleasePackageFields};
use fw_manifest::SIGNATURE_LEN;
use pqsigner_rollback::backend::{ProbeScript, ScriptedBackend};

/// Concrete backend type for tests (the const-generic default does not
/// infer at bare call sites).
pub type TestBackend = ScriptedBackend<64>;
use pqsigner_rollback::evidence::{ArtifactIdentity, VerificationPass, VerifiedArtifact};
use pqsigner_rollback::journal::{
    full_install_generation, install_half_evidence, InstallGenerationEvidence,
};
use pqsigner_rollback::qw_read::{Durability, FreshArrayProbe, FreshQwRead, LaunchAttribution};

/// The §6.1 golden install identity.
pub const INSTALL_ID: [u8; 16] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
];
/// Exact bitwise complement of [`INSTALL_ID`].
pub const INSTALL_ID_INV: [u8; 16] = [
    0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x70,
];

/// Golden tuple: R (matches §6.1).
pub const GOLDEN_R: u32 = 0x0102_0304;
/// Golden tuple: E (matches §6.1).
pub const GOLDEN_E: u32 = 0x0506_0708;
/// Golden tuple: T = E - 1 (matches the §6.2 golden arm-token fixture).
pub const GOLDEN_T: u32 = 0x0506_0707;

pub const CLEAN: Durability = Durability::DurableClean;
pub const NO_LAUNCH: LaunchAttribution = LaunchAttribution::ProvenNoLaunch;
pub const MAY_LAUNCH: LaunchAttribution = LaunchAttribution::MayHaveLaunched;

pub fn seq(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(i as u8);
    }
    out
}

/// A valid manifest-v6 for the golden tuple at `slot` (patterned
/// signature; signature verification is not under test here).
pub fn manifest(slot: PhysicalSlot, r: u32, e: u32) -> ManifestV6 {
    let fields = ReleasePackageFields {
        slot,
        release_version: r,
        security_epoch: e,
        secure_len: 0x1000,
        nonsecure_len: 0x2000,
        secure_hash: &seq(0x00),
        nonsecure_hash: &seq(0x20),
        vendor_fpr: &seq(0x40),
        build_id: &seq(0x60),
        signature: &[0xAA; SIGNATURE_LEN],
    };
    let page = v6::build_release_package(&fields).expect("fields valid");
    v6::parse_and_validate(&page, slot).expect("page parses")
}

/// One verification pass (host-model immutable allocator).
pub fn pass() -> VerificationPass {
    VerificationPass::begin(1, 1, [0x42; 32])
}

/// A verified golden artifact for `slot` under `pass`.
pub fn artifact(pass: &VerificationPass, slot: PhysicalSlot) -> VerifiedArtifact {
    pass.verify_artifact(&manifest(slot, GOLDEN_R, GOLDEN_E), INSTALL_ID)
        .expect("golden manifest is in range")
}

/// Script a clean read at the canonical bank address and probe it.
pub fn probe_clean(b: &mut ScriptedBackend, index: u16, bytes: [u8; 16]) -> FreshQwRead {
    let addr = pqsigner_rollback::floor::canonical_cell_addr(index);
    assert!(b.script(index, addr, ProbeScript::Clean(bytes)));
    b.fresh_probe(index, addr)
}

/// Script any outcome at the canonical bank address and probe it.
pub fn probe(b: &mut ScriptedBackend, index: u16, outcome: ProbeScript) -> FreshQwRead {
    let addr = pqsigner_rollback::floor::canonical_cell_addr(index);
    assert!(b.script(index, addr, outcome));
    b.fresh_probe(index, addr)
}

/// Script any outcome at an EXPLICIT address (for map-validation tests).
pub fn probe_at(b: &mut ScriptedBackend, index: u16, addr: u32, outcome: ProbeScript) -> FreshQwRead {
    assert!(b.script(index, addr, outcome));
    b.fresh_probe(index, addr)
}

/// Script a clean Route-1 marker read at its canonical page address.
/// `which` is 0 (bank-1 page 64) or 1 (bank-1 page 122); the marker QW
/// index is 60+which (disjoint from every bank-cell index in these tests).
pub fn probe_route1(b: &mut ScriptedBackend, which: u16, bytes: [u8; 16]) -> FreshQwRead {
    let addr = pqsigner_rollback::floor::canonical_route1_addr(which as usize);
    let index = 60 + which;
    assert!(b.script(index, addr, ProbeScript::Clean(bytes)));
    b.fresh_probe(index, addr)
}

pub const ERASED: [u8; 16] = [0xFF; 16];

/// Full install-generation evidence for [`INSTALL_ID`].
pub fn full_generation(
    b: &mut ScriptedBackend,
    id_idx: u16,
    inv_idx: u16,
) -> InstallGenerationEvidence {
    let id = probe_clean(b, id_idx, INSTALL_ID);
    let inv = probe_clean(b, inv_idx, INSTALL_ID_INV);
    let id_ev = install_half_evidence(&id, CLEAN, MAY_LAUNCH);
    let inv_ev = install_half_evidence(&inv, CLEAN, MAY_LAUNCH);
    InstallGenerationEvidence::Full(
        full_install_generation(id_ev, inv_ev).expect("full generation"),
    )
}

/// The artifact identity fields for binding an arm token to `artifact`.
pub fn binding_of(artifact: &VerifiedArtifact) -> pqsigner_rollback::arm_token::ArmBinding {
    let id: &ArtifactIdentity = artifact.identity();
    pqsigner_rollback::arm_token::ArmBinding {
        slot: id.slot,
        r: id.r,
        e: id.e,
        t: id.t,
        install_id: id.install_id,
        manifest_digest: id.manifest_digest,
        secure_hash: id.secure_hash,
        nonsecure_hash: id.nonsecure_hash,
    }
}

// ---------------------------------------------------------------------------
// FloorScript helpers for the frozen recheck (backend redecode)
// ---------------------------------------------------------------------------

use pqsigner_rollback::backend::{
    FloorScript, FloorCellScript, ProbeScript as PS,
};
use pqsigner_rollback::floor::{
    encode_complete_record, encode_floor_record, encode_stage_record,
};

fn cell(bytes: [u8; 16]) -> FloorCellScript {
    FloorCellScript {
        outcome: PS::Clean(bytes),
        durability: CLEAN,
        launch: MAY_LAUNCH,
    }
}

/// The floor script mirroring `steady_proof_at(t)`: three clean floor
/// records + COMPLETE for group 1, erased Route-1 markers.
pub fn steady_floor_script(t: u32) -> FloorScript {
    let mut s = FloorScript::empty();
    for _ in 0..3 {
        assert!(s.push(cell(encode_floor_record(t, 1))));
    }
    assert!(s.push(cell(encode_complete_record(1))));
    s
}

/// The floor script mirroring `dead_proof(t, binding)`: committed group 1
/// plus the dead stage (one clean record, three ambiguous cells).
pub fn dead_floor_script(t: u32, binding: StageBinding) -> FloorScript {
    let mut s = steady_floor_script(t);
    assert!(s.push(cell(encode_stage_record(2))));
    assert!(s.push(cell(encode_floor_record(t + 1, 2))));
    for _ in 0..3 {
        assert!(s.push(FloorCellScript {
            outcome: PS::AmbiguousOrFault,
            durability: CLEAN,
            launch: MAY_LAUNCH,
        }));
    }
    s.stage_binding = Some(binding);
    s
}

/// The floor script mirroring `recovery_proof(t, binding)`: committed
/// group 1 plus a completable stage (three clean records, one virgin
/// cell).
pub fn recovering_floor_script(t: u32, binding: StageBinding) -> FloorScript {
    let mut s = steady_floor_script(t);
    assert!(s.push(cell(encode_stage_record(2))));
    for _ in 0..3 {
        assert!(s.push(cell(encode_floor_record(t + 1, 2))));
    }
    assert!(s.push(FloorCellScript {
        outcome: PS::Clean(ERASED),
        durability: CLEAN,
        launch: NO_LAUNCH,
    }));
    s.stage_binding = Some(binding);
    s
}

// ---------------------------------------------------------------------------
// Floor-bank scaffold (model OTP bank through the scripted backend)
// ---------------------------------------------------------------------------

use pqsigner_rollback::floor::{
    decode_floor, CompletionLaunchEvidence, FloorCell, FloorSnapshot, FloorView, StageBinding,
    ROUTE1_BASE0_CODEWORD,
};
use pqsigner_rollback::lifecycle::{decode_lifecycle, AttributedRead, LifecycleState};

/// A scripted OTP/floor bank.
pub struct Bank {
    pub b: ScriptedBackend,
    reads: Vec<FreshQwRead>,
    r1: Vec<FreshQwRead>,
}

impl Bank {
    pub fn new() -> Self {
        Bank {
            b: TestBackend::new(7),
            reads: Vec::new(),
            r1: Vec::new(),
        }
    }

    pub fn add(&mut self, outcome: ProbeScript) {
        let idx = self.reads.len() as u16;
        self.reads.push(probe(&mut self.b, idx, outcome));
    }

    pub fn clean(&mut self, bytes: [u8; 16]) {
        self.add(ProbeScript::Clean(bytes));
    }

    pub fn virgin(&mut self) {
        self.clean(ERASED);
    }

    pub fn route1(&mut self, exact: bool) {
        let codeword = if exact {
            ROUTE1_BASE0_CODEWORD
        } else {
            ERASED
        };
        self.r1.push(probe_route1(&mut self.b, 0, codeword));
        self.r1.push(probe_route1(&mut self.b, 1, codeword));
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

    /// Decode the bank into a FloorView (per-cell attribution: clean
    /// erased reads are scripted untouched, everything else
    /// may-have-launched).
    pub fn decode(
        &self,
        fence: CompletionLaunchEvidence,
        binding: Option<StageBinding>,
    ) -> FloorView {
        let cells = self.cells_auto();
        let snap = FloorSnapshot {
            cells: &cells,
            route1: self.route1_cells(),
            completion_fence: fence,
            stage_binding: binding,
        };
        decode_floor(&snap)
    }
}

/// Attributed-read constructor (durably clean; may-have-launched).
pub fn atr(read: &FreshQwRead) -> AttributedRead<'_> {
    AttributedRead {
        read,
        durability: CLEAN,
        launch: MAY_LAUNCH,
    }
}

/// Attributed-read constructor (durably clean; proven no launch).
pub fn atr_nl(read: &FreshQwRead) -> AttributedRead<'_> {
    AttributedRead {
        read,
        durability: CLEAN,
        launch: NO_LAUNCH,
    }
}

/// Build a `ConfirmedRobust` artifact through the lifecycle decoder
/// (both terminal replicas exact; F == T).
pub fn accepted_artifact(
    pass: &VerificationPass,
    b: &mut ScriptedBackend,
    slot: PhysicalSlot,
    r: u32,
    e: u32,
) -> pqsigner_rollback::evidence::AcceptedArtifact {
    use fw_manifest::v6::{QW_CONFIRMED_0, QW_CONFIRMED_1};
    let m = manifest(slot, r, e);
    let art = pass
        .verify_artifact(&m, INSTALL_ID)
        .expect("test manifest is in range");
    let c0 = probe_clean(b, 10, QW_CONFIRMED_0);
    let c1 = probe_clean(b, 11, QW_CONFIRMED_1);
    let pd = probe_clean(b, 12, ERASED);
    let gen = Some(full_generation(b, 13, 14));
    let t = m.security_epoch - 1;
    match decode_lifecycle(art, gen, atr(&c0), atr(&c1), atr_nl(&pd), None, t) {
        LifecycleState::ConfirmedRobust(a) => a,
        _ => panic!("expected ConfirmedRobust"),
    }
}
