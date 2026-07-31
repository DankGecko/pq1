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
use pqsigner_rollback::journal::InstallGenerationEvidence;
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

// ---------------------------------------------------------------------------
// Test key material — TEST ONLY. A dedicated nonproduction C10 keypair
// used to sign test manifests so `verify_artifact`'s real verification
// (R5-1) has genuine signatures. Never a production/vendor/wallet key.
// ---------------------------------------------------------------------------

/// TEST-ONLY signing-key seed.
pub const TEST_SK_SEED: [u8; 32] = *b"RB-TEST-SK-SEED-NONPROD-00000001";
/// TEST-ONLY public seed.
pub const TEST_PK_SEED: [u8; 16] = *b"RB-TEST-PK-00001";

/// The test signing key (regenerated per call; deterministic).
pub fn test_signing_key() -> sphincs_c10::SigningKey {
    sphincs_c10::SigningKey::keygen(TEST_SK_SEED, TEST_PK_SEED)
}

/// The test key's verifying material `(pk_seed, pk_root)`.
pub fn test_key_material() -> ([u8; 16], [u8; 16]) {
    let vk = test_signing_key().verifying_key();
    (vk.pk_seed, vk.pk_root)
}

/// A valid signed manifest-v6 PAGE at `slot` with tuple `(r, e)`: built
/// through the canonical builder, then genuinely signed with the test
/// key and the vendor-fpr field set to the test key's fingerprint.
pub fn signed_page(slot: PhysicalSlot, r: u32, e: u32) -> [u8; 8192] {
    let (pk_seed, pk_root) = test_key_material();
    let fpr = v6::vendor_fingerprint(&pk_seed, &pk_root);
    let fields = ReleasePackageFields {
        slot,
        release_version: r,
        security_epoch: e,
        secure_len: 0x1000,
        nonsecure_len: 0x2000,
        secure_hash: &seq(0x00),
        nonsecure_hash: &seq(0x20),
        vendor_fpr: &fpr,
        build_id: &seq(0x60),
        signature: &[0xFF; SIGNATURE_LEN],
    };
    let mut page = v6::build_release_package(&fields).expect("fields valid");
    let digest = v6::parse_and_validate(&page, slot)
        .expect("page parses")
        .manifest_digest();
    let sig = test_signing_key().sign(&digest, None);
    page[v6::OFF_SIGNATURE..v6::OFF_SIGNATURE + SIGNATURE_LEN].copy_from_slice(&sig);
    v6::rewrite_normalized_crc(&mut page);
    page
}

/// A valid SIGNED manifest-v6 at `slot` with tuple `(r, e)` (parses
/// [`signed_page`]).
pub fn manifest(slot: PhysicalSlot, r: u32, e: u32) -> ManifestV6 {
    v6::parse_and_validate(&signed_page(slot, r, e), slot).expect("signed page parses")
}

/// One verification pass (host-model immutable allocator).
pub fn pass() -> VerificationPass {
    VerificationPass::begin(1, 1, [0x42; 32])
}

/// A verified golden artifact for `slot` under `pass`.
pub fn artifact(pass: &VerificationPass, slot: PhysicalSlot) -> VerifiedArtifact {
    let (pk_seed, pk_root) = test_key_material();
    pass.verify_artifact(&manifest(slot, GOLDEN_R, GOLDEN_E), INSTALL_ID, &pk_seed, &pk_root)
        .expect("golden manifest verifies")
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

/// Full install-generation evidence for [`INSTALL_ID`], constructed via
/// the canonical orchestrator at the artifact's identity addresses
/// (R4-1).
pub fn full_generation(
    b: &mut TestBackend,
    art: &VerifiedArtifact,
    id_idx: u16,
    inv_idx: u16,
) -> InstallGenerationEvidence {
    let identity = art.identity();
    let mut inv_bytes = [0u8; 16];
    for (i, b) in inv_bytes.iter_mut().enumerate() {
        *b = !art.install_id()[i];
    }
    let id = probe_at(
        b,
        id_idx,
        identity.install_id_qw_address(),
        ProbeScript::Clean(art.install_id()),
    );
    let inv = probe_at(
        b,
        inv_idx,
        identity.install_id_inv_qw_address(),
        ProbeScript::Clean(inv_bytes),
    );
    pqsigner_rollback::lifecycle::decode_install_generation(art, atr(&id), atr(&inv), None, None)
        .expect("full generation")
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
    decode_floor, CompletionLaunchEvidence, FloorSnapshot, FloorView, PlanRole, StageBinding,
    ROUTE1_BASE0_CODEWORD,
};
use pqsigner_rollback::lifecycle::{decode_lifecycle, AttributedRead, LifecycleState};

/// A scripted OTP/floor bank: scripts are accumulated, then every
/// canonical index is probed through `FloorSnapshot::probe` (the
/// decoder's canonical constructor). Cells past the scripted prefix are
/// canonical virgins.
pub struct Bank {
    pub b: TestBackend,
    scripts: Vec<ProbeScript>,
    r1_exact: bool,
}

impl Bank {
    pub fn new() -> Self {
        Bank {
            b: TestBackend::new(7),
            scripts: Vec::new(),
            r1_exact: false,
        }
    }

    pub fn add(&mut self, outcome: ProbeScript) {
        assert!(
            self.scripts.len() < pqsigner_rollback::floor::RESERVED_ROLLBACK_QWS,
            "bank capacity"
        );
        self.scripts.push(outcome);
    }

    pub fn clean(&mut self, bytes: [u8; 16]) {
        self.add(ProbeScript::Clean(bytes));
    }

    pub fn virgin(&mut self) {
        self.clean(ERASED);
    }

    pub fn route1(&mut self, exact: bool) {
        self.r1_exact = exact;
    }

    /// Load the scripts and probe a full exact-cardinality snapshot.
    /// Attribution: clean erased reads are scripted untouched
    /// (NO_LAUNCH → claimable virgin), everything else
    /// may-have-launched; the virgin tail is proven-untouched.
    pub fn snapshot(
        &mut self,
        fence: CompletionLaunchEvidence,
        binding: Option<StageBinding>,
    ) -> FloorSnapshot {
        use pqsigner_rollback::floor::{
            canonical_cell_addr, canonical_route1_addr, RESERVED_ROLLBACK_QWS,
        };
        self.b.clear_probe_scripts();
        for (i, s) in self.scripts.iter().enumerate() {
            assert!(self.b.script(i as u16, canonical_cell_addr(i as u16), *s));
        }
        for i in self.scripts.len()..RESERVED_ROLLBACK_QWS {
            assert!(self.b.script(i as u16, canonical_cell_addr(i as u16), ProbeScript::Clean(ERASED)));
        }
        let codeword = if self.r1_exact {
            ROUTE1_BASE0_CODEWORD
        } else {
            ERASED
        };
        assert!(self.b.script(60, canonical_route1_addr(0), ProbeScript::Clean(codeword)));
        assert!(self.b.script(61, canonical_route1_addr(1), ProbeScript::Clean(codeword)));
        let mut attrs = [(CLEAN, NO_LAUNCH); RESERVED_ROLLBACK_QWS];
        for (i, s) in self.scripts.iter().enumerate() {
            if !matches!(s, ProbeScript::Clean(bytes) if *bytes == ERASED) {
                attrs[i] = (CLEAN, MAY_LAUNCH);
            }
        }
        FloorSnapshot::probe(&mut self.b, fence, binding, &attrs, [(CLEAN, NO_LAUNCH); 2])
    }

    /// Decode the bank into a FloorView.
    pub fn decode(
        &mut self,
        fence: CompletionLaunchEvidence,
        binding: Option<StageBinding>,
    ) -> FloorView {
        let snap = self.snapshot(fence, binding);
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
    let (pk_seed, pk_root) = test_key_material();
    let art = pass
        .verify_artifact(&m, INSTALL_ID, &pk_seed, &pk_root)
        .expect("test manifest verifies");
    let (tf, pd) = probe_journal(
        b,
        &art,
        ProbeScript::Clean(QW_CONFIRMED_0),
        ProbeScript::Clean(QW_CONFIRMED_1),
        ProbeScript::Clean(ERASED),
    );
    let gen = Some(full_generation(b, &art, 13, 14));
    let t = m.security_epoch - 1;
    match decode_lifecycle(art, gen, &tf, &pd, None, t) {
        LifecycleState::ConfirmedRobust(a) => a,
        _ => panic!("expected ConfirmedRobust"),
    }
}

/// A second install identity (the degraded generation's id; the repair
/// target's INSTALL_ID must differ from it).
pub const OLD_INSTALL_ID: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
/// The peer-repair twin's FRESH install identity (must differ from the
/// source's INSTALL_ID, R5-5).
pub const TWIN_INSTALL_ID: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];

/// A stage binding with the golden R (model default digest) and an
/// explicit ordered role plan (R5-3).
pub fn binding(slot: PhysicalSlot, e: u32, roles: [(u16, PlanRole); 4]) -> StageBinding {
    StageBinding::new(slot, GOLDEN_R, e, seq(0x99), roles).expect("binding range")
}

/// Probe the lifecycle journal evidence at the artifact's canonical
/// identity addresses (R3-2), terminal-first (R10-2): both terminal QWs
/// are fresh-probed through the `TerminalFirst` capability BEFORE the
/// PENDING read is made. Terminal attributions are auto-assigned
/// (erased → proven-no-launch, everything else → may-have-launched);
/// the PENDING read's attribution is applied at the decode call site.
pub fn probe_journal(
    b: &mut TestBackend,
    art: &VerifiedArtifact,
    c0: ProbeScript,
    c1: ProbeScript,
    pd: ProbeScript,
) -> (
    pqsigner_rollback::lifecycle::TerminalFirst,
    pqsigner_rollback::lifecycle::PendingEvidence,
) {
    use pqsigner_rollback::lifecycle::TerminalFirst;
    let id = art.identity();
    // Terminal-first acquisition: script and probe BOTH terminals before
    // PENDING is touched.
    assert!(b.script(30, id.confirmed_0_qw_address, c0));
    assert!(b.script(31, id.confirmed_1_qw_address, c1));
    let attr = |s: &ProbeScript| -> (pqsigner_rollback::qw_read::Durability, LaunchAttribution) {
        match s {
            ProbeScript::Clean(bytes) if *bytes == ERASED => (CLEAN, NO_LAUNCH),
            _ => (CLEAN, MAY_LAUNCH),
        }
    };
    let tf = TerminalFirst::probe(b, id, 30, attr(&c0), 31, attr(&c1));
    // R11-3 + R13-1b: the PENDING evidence is minted THROUGH the
    // capability — it cannot precede the terminal probes and cannot be
    // fabricated by a direct probe.
    assert!(b.script(32, id.pending_qw_address, pd));
    let pd_ev = tf.probe_pending(b, 32, id.pending_qw_address, attr(&pd));
    (tf, pd_ev)
}

/// Full degraded-history evidence for a prior degraded artifact at
/// `slot` with tuple `(r, e)` (the repair target's new generation uses
/// [`INSTALL_ID`], which differs from [`OLD_INSTALL_ID`]). The
/// surviving-terminal degradation proof is decoded through the real
/// lifecycle decoder (R8-4).
pub fn degraded_history(
    slot: PhysicalSlot,
    r: u32,
    e: u32,
) -> pqsigner_rollback::intents::DegradedHistoryEvidence {
    use pqsigner_rollback::intents::{DegradedHistoryEvidence, EraseRestageReceipt};
    let p = pass();
    let (pk_seed, pk_root) = test_key_material();
    let m = manifest(slot, r, e);
    let prior_art = p
        .verify_artifact(&m, OLD_INSTALL_ID, &pk_seed, &pk_root)
        .expect("prior artifact verifies");
    let prior = *prior_art.identity();
    // Decode the degradation proof: one exact terminal replica, the
    // other indeterminate, at the canonical journal addresses.
    let mut b = TestBackend::new(7);
    let (tf, pd) = probe_journal(
        &mut b,
        &prior_art,
        ProbeScript::Clean(fw_manifest::v6::QW_CONFIRMED_0),
        ProbeScript::Clean(ERASED),
        ProbeScript::Clean(ERASED),
    );
    let gen = Some(full_generation(&mut b, &prior_art, 3, 4));
    let row = match decode_lifecycle(prior_art, gen, &tf, &pd, None, e - 1) {
        LifecycleState::DegradedConfirmed(row) => row,
        _ => panic!("expected DegradedConfirmed for the prior artifact"),
    };
    let restage = EraseRestageReceipt::new(slot, prior.manifest_digest);
    DegradedHistoryEvidence::new(row, restage).expect("history joins")
}

// ---------------------------------------------------------------------------
// Artifact scripts for the frozen artifact recheck (R6-1)
// ---------------------------------------------------------------------------

use pqsigner_rollback::backend::{ArtifactScript, JournalQwScript};
use pqsigner_rollback::qw_read::{Durability as D, LaunchAttribution as L};

fn jq(outcome: ProbeScript, durability: D, launch: L) -> JournalQwScript {
    JournalQwScript {
        outcome,
        durability,
        launch,
    }
}

/// The artifact script for a PENDING candidate: both terminals
/// proven-virgin, exact PENDING, full install pair.
pub fn pending_script(slot: PhysicalSlot, r: u32, e: u32, install_id: [u8; 16]) -> ArtifactScript {
    let (pk_seed, pk_root) = test_key_material();
    let mut inv = [0u8; 16];
    for (i, b) in inv.iter_mut().enumerate() {
        *b = !install_id[i];
    }
    ArtifactScript {
        page: signed_page(slot, r, e),
        pk_seed,
        pk_root,
        terminal_c0: jq(ProbeScript::Clean(ERASED), D::DurableClean, L::ProvenNoLaunch),
        terminal_c1: jq(ProbeScript::Clean(ERASED), D::DurableClean, L::ProvenNoLaunch),
        pending: jq(
            ProbeScript::Clean(fw_manifest::v6::QW_PENDING),
            D::DurableClean,
            L::MayHaveLaunched,
        ),
        install_id: jq(ProbeScript::Clean(install_id), D::DurableClean, L::MayHaveLaunched),
        install_id_inv: jq(ProbeScript::Clean(inv), D::DurableClean, L::MayHaveLaunched),
    }
}

/// The artifact script for a robust CONFIRMED artifact (fallback /
/// aborted boot): both terminal replicas exact.
pub fn robust_script(slot: PhysicalSlot, r: u32, e: u32, install_id: [u8; 16]) -> ArtifactScript {
    let (pk_seed, pk_root) = test_key_material();
    let mut inv = [0u8; 16];
    for (i, b) in inv.iter_mut().enumerate() {
        *b = !install_id[i];
    }
    ArtifactScript {
        page: signed_page(slot, r, e),
        pk_seed,
        pk_root,
        terminal_c0: jq(
            ProbeScript::Clean(fw_manifest::v6::QW_CONFIRMED_0),
            D::DurableClean,
            L::MayHaveLaunched,
        ),
        terminal_c1: jq(
            ProbeScript::Clean(fw_manifest::v6::QW_CONFIRMED_1),
            D::DurableClean,
            L::MayHaveLaunched,
        ),
        pending: jq(ProbeScript::Clean(ERASED), D::DurableClean, L::ProvenNoLaunch),
        install_id: jq(ProbeScript::Clean(install_id), D::DurableClean, L::MayHaveLaunched),
        install_id_inv: jq(ProbeScript::Clean(inv), D::DurableClean, L::MayHaveLaunched),
    }
}
