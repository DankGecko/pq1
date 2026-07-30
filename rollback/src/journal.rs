//! Manifest-journal codec for the rollback core (§6.2 + owner-adopted
//! review amendments). The codewords themselves (`QW_PENDING`,
//! `QW_CONFIRMED_0/1`) are REUSED from `fw_manifest::v6` — never
//! duplicated. Journal evidence enters only as [`FreshQwRead`] plus
//! explicit [`Durability`]/[`LaunchAttribution`] parameters.
//!
//! Linear proof types (`FullInstallGeneration`, `SurvivingInstallGeneration`,
//! `FullTerminalSet`, `SurvivingTerminalSet`) are boot-scoped: neither
//! `Copy` nor `Clone`, never serializable, consumed by value.

use fw_manifest::v6::{LaterLifecycleEvidence, QW_CONFIRMED_0, QW_CONFIRMED_1, QW_PENDING};

use crate::evidence::ArtifactEvidenceKey;
use crate::qw_read::{BlankVirgin, Durability, FreshQwRead, LaunchAttribution};

// ---------------------------------------------------------------------------
// Marker observation helpers
// ---------------------------------------------------------------------------

/// A codeword marker is valid only on a `Clean` fresh read whose bytes
/// equal the codeword exactly AND whose durability attribution is
/// `DurableClean`. Corrected/uncorrectable/torn/may-have-launched
/// observations are never markers (§6.2 L2000–2003).
pub fn exact_marker(read: &FreshQwRead, codeword: &[u8; 16], durability: Durability) -> bool {
    durability.is_clean()
        && matches!(read, FreshQwRead::Clean(qw) if qw.bytes() == codeword)
}

/// How one journal QW observed as evidence classifies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MarkerObservation {
    /// Exact durably-clean codeword.
    Exact,
    /// Proven BlankVirgin (clean all-`0xFF` + no-launch proof).
    ProvenVirgin,
    /// Clean read of some other value, durably attributed — an exact
    /// conflicting value.
    Conflicting,
    /// Anything else: corrected, uncorrectable, torn, ambiguous,
    /// durability-ambiguous, or may-have-launched.
    Indeterminate,
}

/// Classify one journal-QW observation against an expected codeword.
/// A durably-clean exact read of a NON-erased value that is not the
/// codeword is a conflicting exact value; erased bytes without the
/// no-launch proof are merely indeterminate, never conflicting.
pub fn observe_marker(
    read: &FreshQwRead,
    codeword: &[u8; 16],
    durability: Durability,
    launch: LaunchAttribution,
) -> MarkerObservation {
    if exact_marker(read, codeword, durability) {
        return MarkerObservation::Exact;
    }
    if BlankVirgin::prove(read, launch).is_some() {
        return MarkerObservation::ProvenVirgin;
    }
    if durability.is_clean() {
        if let FreshQwRead::Clean(qw) = read {
            if !qw.is_erased() {
                return MarkerObservation::Conflicting;
            }
        }
    }
    MarkerObservation::Indeterminate
}

// ---------------------------------------------------------------------------
// Install-identity generation (§6.2 L2005–2026; Q16 owner decision
// 2026-07-26 implemented as frozen)
// ---------------------------------------------------------------------------

/// `FullInstallGeneration` — two durably-clean exact reads, exact
/// complementarity, neither forbidden value. Boot-scoped linear proof.
pub struct FullInstallGeneration {
    install_id: [u8; 16],
}

impl FullInstallGeneration {
    /// The reconstructed 128-bit install identity.
    pub fn install_id(&self) -> [u8; 16] {
        self.install_id
    }
}

/// `SurvivingInstallGeneration` — the identity reconstructed from exactly
/// one independently durable, clean, nontrivial half, permitted only
/// because the caller supplied later-lifecycle evidence. Boot-scoped
/// linear proof.
pub struct SurvivingInstallGeneration {
    install_id: [u8; 16],
}

impl SurvivingInstallGeneration {
    /// The reconstructed 128-bit install identity (the surviving half
    /// contributes it; the missing half contributed NO authority).
    pub fn install_id(&self) -> [u8; 16] {
        self.install_id
    }
}

/// The install-generation evidence a lifecycle decode may use.
pub enum InstallGenerationEvidence {
    Full(FullInstallGeneration),
    Surviving(SurvivingInstallGeneration),
}

impl InstallGenerationEvidence {
    /// The reconstructed install identity, whichever leg proved it.
    pub fn install_id(&self) -> [u8; 16] {
        match self {
            InstallGenerationEvidence::Full(g) => g.install_id(),
            InstallGenerationEvidence::Surviving(g) => g.install_id(),
        }
    }
}

/// One half of the install-identity pair as observed evidence.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstallHalfEvidence {
    /// Exact durably-clean read of this half's bytes.
    Exact([u8; 16]),
    /// Proven BlankVirgin: clean all-`0xFF` read PLUS proof no program
    /// for this index may have launched.
    ProvenBlankVirgin,
    /// Anything else: torn, corrected, uncorrectable, ambiguous,
    /// durability-ambiguous, or may-have-launched.
    Indeterminate,
}

/// Build the evidence view of one install-identity half from its fresh
/// read and explicit attributions.
pub(crate) fn install_half_evidence(
    read: &FreshQwRead,
    durability: Durability,
    launch: LaunchAttribution,
) -> InstallHalfEvidence {
    if BlankVirgin::prove(read, launch).is_some() {
        return InstallHalfEvidence::ProvenBlankVirgin;
    }
    if durability.is_clean() {
        if let FreshQwRead::Clean(qw) = read {
            return InstallHalfEvidence::Exact(*qw.bytes());
        }
    }
    InstallHalfEvidence::Indeterminate
}

fn is_all(byte: u8, raw: &[u8; 16]) -> bool {
    raw.iter().all(|&b| b == byte)
}

/// All-zero and all-one install identities are forbidden (§6.2
/// L2008–2010): the writer rejects and resamples them so both QWs require
/// a real program operation. All-one is also the erased pattern.
fn is_forbidden_install_id(raw: &[u8; 16]) -> bool {
    is_all(0x00, raw) || is_all(0xFF, raw)
}

fn complement(raw: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = !raw[i];
    }
    out
}

/// `FullInstallGeneration` (§6.2 L2011): two durably-clean exact reads,
/// exact complementarity, neither forbidden value. Both halves must be
/// `Exact`; anything less is `None` — use [`surviving_install_generation`]
/// for the one-half rule. Crate-private (R4-1): the public path is
/// `lifecycle::decode_install_generation`, which enforces canonical
/// install-QW addresses and one common probe epoch.
pub(crate) fn full_install_generation(
    id: InstallHalfEvidence,
    inv: InstallHalfEvidence,
) -> Option<FullInstallGeneration> {
    match (id, inv) {
        (InstallHalfEvidence::Exact(a), InstallHalfEvidence::Exact(b)) => {
            if is_forbidden_install_id(&a) || complement(&a) != b {
                None
            } else {
                Some(FullInstallGeneration { install_id: a })
            }
        }
        _ => None,
    }
}

/// `SurvivingInstallGeneration` (Q16 owner decision 2026-07-26,
/// IMPLEMENT-AS-FROZEN; §6.2 L2012–2017 and L2085–2089):
///
/// * `evidence` is a REQUIRED parameter — a lone identity half before
///   activation is incomplete, never an installed artifact, and no call
///   site can reconstruct silently.
/// * Exactly one independently durable, clean, NONTRIVIAL half
///   reconstructs; the missing half contributes no authority.
/// * A survivor whose other half is proven `BlankVirgin` is an impossible
///   writer-order state (the later lifecycle write proves both ID writes
///   should have launched) and REJECTS.
/// * Any conflicting exact value rejects. When both halves are exact this
///   degenerates to the full-generation rule (complementarity +
///   nontriviality); callers with two exact halves should prefer
///   [`full_install_generation`].
pub(crate) fn surviving_install_generation(
    id: InstallHalfEvidence,
    inv: InstallHalfEvidence,
    evidence: LaterLifecycleEvidence,
) -> Option<SurvivingInstallGeneration> {
    // Both evidence kinds carry the same weight here; the parameter
    // exists so no call site can reconstruct without it.
    let _ = evidence;
    let wrap = |install_id| Some(SurvivingInstallGeneration { install_id });
    match (id, inv) {
        // Impossible writer-order: a proven-virgin half after later
        // lifecycle evidence rejects outright.
        (InstallHalfEvidence::ProvenBlankVirgin, _)
        | (_, InstallHalfEvidence::ProvenBlankVirgin) => None,
        (InstallHalfEvidence::Exact(a), InstallHalfEvidence::Exact(b)) => {
            if is_forbidden_install_id(&a) || complement(&a) != b {
                None
            } else {
                wrap(a)
            }
        }
        (InstallHalfEvidence::Exact(a), InstallHalfEvidence::Indeterminate) => {
            if is_forbidden_install_id(&a) {
                None
            } else {
                wrap(a)
            }
        }
        (InstallHalfEvidence::Indeterminate, InstallHalfEvidence::Exact(b)) => {
            let reconstructed = complement(&b);
            if is_forbidden_install_id(&reconstructed) {
                None
            } else {
                wrap(reconstructed)
            }
        }
        (InstallHalfEvidence::Indeterminate, InstallHalfEvidence::Indeterminate) => None,
    }
}

// ---------------------------------------------------------------------------
// Terminal sets (§6.2 L2142–2161) — terminal-first probing
// ---------------------------------------------------------------------------

/// `FullTerminalSet` — two independently attributed durably-clean exact
/// terminal replicas. The only robust terminal authority. Boot-scoped
/// linear proof; carries the artifact's `ArtifactEvidenceKey` digest.
pub struct FullTerminalSet {
    evidence_key: [u8; 32],
}

impl FullTerminalSet {
    /// The `ArtifactEvidenceKey` digest this proof binds.
    pub fn evidence_key(&self) -> &[u8; 32] {
        &self.evidence_key
    }
}

/// Which physical terminal replica survived.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TerminalReplica {
    /// `QW_CONFIRMED_0` (written first).
    Replica0,
    /// `QW_CONFIRMED_1` (written second).
    Replica1,
}

/// `SurvivingTerminalSet` — exactly one durably-clean exact terminal
/// replica; the other has zero authority. Repair-target evidence ONLY:
/// never boot authority, never floor authority, never an older floor
/// (hard design rule 4; §6.2 L2171–2172).
pub struct SurvivingTerminalSet {
    evidence_key: [u8; 32],
    replica: TerminalReplica,
}

impl SurvivingTerminalSet {
    /// The `ArtifactEvidenceKey` digest this proof binds.
    pub fn evidence_key(&self) -> &[u8; 32] {
        &self.evidence_key
    }

    /// Which replica survived.
    pub fn replica(&self) -> TerminalReplica {
        self.replica
    }
}

/// Why a terminal-set decode rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TerminalRejection {
    /// A durably-attributed clean read of a value that is not the
    /// position's codeword — conflicting terminal evidence.
    ConflictingExactValue,
    /// `CONFIRMED_1` exact while `CONFIRMED_0` is proven `BlankVirgin`:
    /// the writer programs replica 0 before replica 1 (§6.3
    /// `CandidateFinalizationWriter`), so this is an impossible
    /// writer-order state (§6.2 L2157–2158).
    ImpossibleWriterOrder,
    /// Neither replica exact (the caller proceeds to the PENDING branch
    /// only when BOTH are proven `BlankVirgin`).
    NoTerminalAuthority,
}

/// The result of terminal-first probing of both terminal QWs.
pub enum TerminalSetOutcome {
    Full(FullTerminalSet),
    Surviving(SurvivingTerminalSet),
    Rejected(TerminalRejection),
}

/// Decode the two terminal replicas from fresh reads and explicit
/// attributions. Both terminal QWs MUST be fresh-probed before any
/// PENDING/TAMP evidence is considered (hard design rule 4; §6.2
/// L2183–2186) — this function is the only terminal-set constructor.
///
/// The evidence key is DERIVED from the artifact's sealed
/// [`ArtifactEvidenceKey`] for the current verification pass — never
/// accepted as a raw parameter (R3-2). Crate-private (R4-1): the only
/// caller is `lifecycle::decode_lifecycle`, which enforces canonical
/// terminal addresses and one common probe epoch before delegating.
pub(crate) fn decode_terminal_set(
    c0: &FreshQwRead,
    c0_durability: Durability,
    c0_launch: LaunchAttribution,
    c1: &FreshQwRead,
    c1_durability: Durability,
    c1_launch: LaunchAttribution,
    key: &ArtifactEvidenceKey,
) -> TerminalSetOutcome {
    let evidence_key = key.digest();
    let o0 = observe_marker(c0, &QW_CONFIRMED_0, c0_durability, c0_launch);
    let o1 = observe_marker(c1, &QW_CONFIRMED_1, c1_durability, c1_launch);
    match (o0, o1) {
        (MarkerObservation::Exact, MarkerObservation::Exact) => {
            TerminalSetOutcome::Full(FullTerminalSet { evidence_key })
        }
        (MarkerObservation::Conflicting, _) | (_, MarkerObservation::Conflicting) => {
            TerminalSetOutcome::Rejected(TerminalRejection::ConflictingExactValue)
        }
        (MarkerObservation::ProvenVirgin, MarkerObservation::Exact) => {
            TerminalSetOutcome::Rejected(TerminalRejection::ImpossibleWriterOrder)
        }
        (MarkerObservation::Exact, _) => TerminalSetOutcome::Surviving(SurvivingTerminalSet {
            evidence_key,
            replica: TerminalReplica::Replica0,
        }),
        (_, MarkerObservation::Exact) => TerminalSetOutcome::Surviving(SurvivingTerminalSet {
            evidence_key,
            replica: TerminalReplica::Replica1,
        }),
        _ => TerminalSetOutcome::Rejected(TerminalRejection::NoTerminalAuthority),
    }
}

/// Re-export of the PENDING codeword for lifecycle decoders (owned by
/// `fw_manifest::v6`).
pub const PENDING_CODEWORD: [u8; 16] = QW_PENDING;

// ---------------------------------------------------------------------------
// Crate-internal constructor tests (R4-1: the raw codec constructors are
// pub(crate); these exercise them directly. The public orchestrator
// paths are covered by the integration suite.)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::VerificationPass;
    use crate::qw_read::CleanQw;
    use fw_manifest::v6::{self, PhysicalSlot, ReleasePackageFields};

    const ID: [u8; 16] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f,
    ];
    const ID_INV: [u8; 16] = [
        0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x78, 0x77, 0x76, 0x75, 0x74, 0x73, 0x72, 0x71,
        0x70,
    ];
    const ERASED: [u8; 16] = [0xFF; 16];
    const CLEAN: Durability = Durability::DurableClean;
    const MAY_LAUNCH: LaunchAttribution = LaunchAttribution::MayHaveLaunched;
    const NO_LAUNCH: LaunchAttribution = LaunchAttribution::ProvenNoLaunch;

    fn read(index: u16, bytes: [u8; 16]) -> FreshQwRead {
        FreshQwRead::Clean(CleanQw::new(index, 0x1000 + 0x20 * index as u32, bytes, 7))
    }

    fn test_key() -> crate::evidence::ArtifactEvidenceKey {
        let seq = |start: u8| -> [u8; 32] {
            let mut o = [0u8; 32];
            for (i, b) in o.iter_mut().enumerate() {
                *b = start.wrapping_add(i as u8);
            }
            o
        };
        let fields = ReleasePackageFields {
            slot: PhysicalSlot::A,
            release_version: 0x0102_0304,
            security_epoch: 0x0506_0708,
            secure_len: 0x1000,
            nonsecure_len: 0x2000,
            secure_hash: &seq(0x00),
            nonsecure_hash: &seq(0x20),
            vendor_fpr: &seq(0x40),
            build_id: &seq(0x60),
            signature: &[0xAA; fw_manifest::SIGNATURE_LEN],
        };
        let page = v6::build_release_package(&fields).unwrap();
        let m = v6::parse_and_validate(&page, PhysicalSlot::A).unwrap();
        let pass = VerificationPass::begin(1, 1, [0x42; 32]);
        *pass.verify_artifact(&m, ID).unwrap().key()
    }

    #[test]
    fn install_generation_full_and_forbidden() {
        let full = full_install_generation(
            InstallHalfEvidence::Exact(ID),
            InstallHalfEvidence::Exact(ID_INV),
        );
        assert_eq!(full.map(|g| g.install_id()), Some(ID));

        // Forbidden values: all-zero / all-one (erased).
        assert!(full_install_generation(
            InstallHalfEvidence::Exact([0x00; 16]),
            InstallHalfEvidence::Exact([0xFF; 16]),
        )
        .is_none());
        assert!(full_install_generation(
            InstallHalfEvidence::Exact([0xFF; 16]),
            InstallHalfEvidence::Exact([0x00; 16]),
        )
        .is_none());

        // Conflicting exact halves reject.
        let mut bad = ID_INV;
        bad[0] ^= 1;
        assert!(full_install_generation(
            InstallHalfEvidence::Exact(ID),
            InstallHalfEvidence::Exact(bad),
        )
        .is_none());

        // A missing half is never a FULL generation.
        assert!(full_install_generation(
            InstallHalfEvidence::Exact(ID),
            InstallHalfEvidence::Indeterminate,
        )
        .is_none());
    }

    #[test]
    fn surviving_install_generation_requires_evidence_and_rejects_impossible() {
        let ev = LaterLifecycleEvidence::Pending;

        // Exactly one durable clean nontrivial half + evidence → reconstruct.
        let s = surviving_install_generation(
            InstallHalfEvidence::Exact(ID),
            InstallHalfEvidence::Indeterminate,
            ev,
        );
        assert_eq!(s.map(|g| g.install_id()), Some(ID));
        let s = surviving_install_generation(
            InstallHalfEvidence::Indeterminate,
            InstallHalfEvidence::Exact(ID_INV),
            ev,
        );
        assert_eq!(s.map(|g| g.install_id()), Some(ID));

        // IMPOSSIBLE WRITER-ORDER: a survivor half proven BlankVirgin
        // after later lifecycle evidence rejects (hard design rule 3).
        assert!(surviving_install_generation(
            InstallHalfEvidence::Exact(ID),
            InstallHalfEvidence::ProvenBlankVirgin,
            ev,
        )
        .is_none());
        assert!(surviving_install_generation(
            InstallHalfEvidence::ProvenBlankVirgin,
            InstallHalfEvidence::Exact(ID_INV),
            ev,
        )
        .is_none());

        // Conflicting exact halves reject even with evidence.
        let mut bad = ID_INV;
        bad[3] ^= 0x40;
        assert!(surviving_install_generation(
            InstallHalfEvidence::Exact(ID),
            InstallHalfEvidence::Exact(bad),
            ev,
        )
        .is_none());

        // No exact half → nothing to reconstruct.
        assert!(surviving_install_generation(
            InstallHalfEvidence::Indeterminate,
            InstallHalfEvidence::Indeterminate,
            ev,
        )
        .is_none());

        // Nontrivial-half rule: all-zero/all-one surviving halves reject.
        assert!(surviving_install_generation(
            InstallHalfEvidence::Exact([0x00; 16]),
            InstallHalfEvidence::Indeterminate,
            ev,
        )
        .is_none());
    }

    #[test]
    fn terminal_set_full_surviving_and_rejections() {
        let key = test_key();
        let c0 = read(0, QW_CONFIRMED_0);
        let c1 = read(1, QW_CONFIRMED_1);

        // Full: both exact.
        match decode_terminal_set(&c0, CLEAN, MAY_LAUNCH, &c1, CLEAN, MAY_LAUNCH, &key) {
            TerminalSetOutcome::Full(set) => assert_eq!(set.evidence_key(), &key.digest()),
            _ => panic!("expected Full"),
        }

        // Surviving: C0 exact, C1 indeterminate (may-have-launched erased).
        let c1_erased = read(1, ERASED);
        match decode_terminal_set(&c0, CLEAN, MAY_LAUNCH, &c1_erased, CLEAN, MAY_LAUNCH, &key) {
            TerminalSetOutcome::Surviving(set) => {
                assert_eq!(set.replica(), TerminalReplica::Replica0)
            }
            _ => panic!("expected Surviving(Replica0)"),
        }

        // IMPOSSIBLE WRITER-ORDER: C1 exact with C0 proven BlankVirgin.
        let c0_erased = read(0, ERASED);
        match decode_terminal_set(&c0_erased, CLEAN, NO_LAUNCH, &c1, CLEAN, MAY_LAUNCH, &key) {
            TerminalSetOutcome::Rejected(TerminalRejection::ImpossibleWriterOrder) => {}
            other => panic!("expected ImpossibleWriterOrder, got {}", name_of(&other)),
        }

        // Conflicting exact value: clean durably-clean read of garbage.
        let c0_garbage = read(0, [0x42; 16]);
        match decode_terminal_set(&c0_garbage, CLEAN, MAY_LAUNCH, &c1, CLEAN, MAY_LAUNCH, &key) {
            TerminalSetOutcome::Rejected(TerminalRejection::ConflictingExactValue) => {}
            other => panic!("expected ConflictingExactValue, got {}", name_of(&other)),
        }

        // Corrected codeword bytes have ZERO weight (not an exact marker).
        let c0_corrected = FreshQwRead::Corrected {
            bytes: QW_CONFIRMED_0,
            index: 0,
        };
        match decode_terminal_set(&c0_corrected, CLEAN, NO_LAUNCH, &c1, CLEAN, MAY_LAUNCH, &key) {
            TerminalSetOutcome::Surviving(set) => {
                assert_eq!(set.replica(), TerminalReplica::Replica1)
            }
            other => panic!("expected Surviving(Replica1), got {}", name_of(&other)),
        }

        // Neither exact → NoTerminalAuthority.
        let e0 = read(2, ERASED);
        let e1 = read(3, ERASED);
        match decode_terminal_set(&e0, CLEAN, NO_LAUNCH, &e1, CLEAN, NO_LAUNCH, &key) {
            TerminalSetOutcome::Rejected(TerminalRejection::NoTerminalAuthority) => {}
            other => panic!("expected NoTerminalAuthority, got {}", name_of(&other)),
        }

        // Durability-ambiguous exact-looking read is NOT exact.
        let c0_amb = read(0, QW_CONFIRMED_0);
        match decode_terminal_set(&c0_amb, Durability::Ambiguous, MAY_LAUNCH, &c1, CLEAN, MAY_LAUNCH, &key)
        {
            TerminalSetOutcome::Surviving(set) => {
                assert_eq!(set.replica(), TerminalReplica::Replica1)
            }
            other => panic!("expected Surviving(Replica1), got {}", name_of(&other)),
        }
    }

    fn name_of(o: &TerminalSetOutcome) -> &'static str {
        match o {
            TerminalSetOutcome::Full(_) => "Full",
            TerminalSetOutcome::Surviving(_) => "Surviving",
            TerminalSetOutcome::Rejected(TerminalRejection::ConflictingExactValue) => "Conflicting",
            TerminalSetOutcome::Rejected(TerminalRejection::ImpossibleWriterOrder) => {
                "ImpossibleWriterOrder"
            }
            TerminalSetOutcome::Rejected(TerminalRejection::NoTerminalAuthority) => "NoTerminal",
        }
    }
}
