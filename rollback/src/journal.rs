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
pub fn install_half_evidence(
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
/// for the one-half rule.
pub fn full_install_generation(
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
pub fn surviving_install_generation(
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
/// `evidence_key` is the digest of the artifact's `ArtifactEvidenceKey`
/// for the current verification pass (see `evidence.rs`).
pub fn decode_terminal_set(
    c0: &FreshQwRead,
    c0_durability: Durability,
    c0_launch: LaunchAttribution,
    c1: &FreshQwRead,
    c1_durability: Durability,
    c1_launch: LaunchAttribution,
    evidence_key: [u8; 32],
) -> TerminalSetOutcome {
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
