//! Slot-lifecycle decoder: the six-row acceptance table (§6.2
//! L2165–2172) and the legal transition chain (§6.2 L2199–2208).
//!
//! Terminal-first probing (hard design rule 4): both terminal QWs are
//! fresh-probed before PENDING/TAMP evidence is considered; a torn,
//! corrected, may-have-launched, conflicting, or impossible-order
//! terminal observation NEVER falls through to PENDING. Every combination
//! outside the six rows is `Malformed` — a missing/malformed/
//! binding-mismatched token on the probation branch, out-of-order
//! markers, out-of-range `R/E`, `F > T`, impossible writer-order, or
//! conflicting halves.

use fw_manifest::v6::QW_PENDING;

use crate::arm_token::{ArmState, ArmToken};
use crate::evidence::{AcceptedArtifact, VerifiedArtifact};
use crate::journal::{
    decode_terminal_set, full_install_generation, install_half_evidence, observe_marker,
    surviving_install_generation, InstallGenerationEvidence, MarkerObservation,
    SurvivingTerminalSet, TerminalRejection, TerminalSetOutcome,
};
use crate::qw_read::{Durability, FreshQwRead, LaunchAttribution};

/// One attributed journal-QW observation: the fresh read plus its
/// explicit durability and launch attributions.
pub struct AttributedRead<'a> {
    pub read: &'a FreshQwRead,
    pub durability: Durability,
    pub launch: LaunchAttribution,
}

/// Sealed arm-token evidence (R15-1): the 24 TAMP words minted ONLY
/// through [`TerminalFirst::read_arm_token`] — `pub(crate)`
/// constructor, so `decode_lifecycle`'s probation branch can never be
/// handed a caller-synthesized bound token. The backend-writer-side raw
/// `ArmToken::encode`/`decode_and_bind` stays public; the
/// decode-lifecycle surface requires this sealed evidence.
pub struct TokenEvidence {
    words: [u32; crate::arm_token::TOKEN_WORDS],
}

impl TokenEvidence {
    pub(crate) fn from_words(words: [u32; crate::arm_token::TOKEN_WORDS]) -> TokenEvidence {
        TokenEvidence { words }
    }

    /// Decode + bind the sealed words against the artifact's fields.
    pub fn decode_and_bind(
        &self,
        expected_slot: fw_manifest::v6::PhysicalSlot,
        install_id: &[u8; 16],
        manifest_digest: &[u8; 32],
        secure_hash: &[u8; 32],
        nonsecure_hash: &[u8; 32],
    ) -> Result<crate::arm_token::ArmToken, crate::arm_token::TokenError> {
        crate::arm_token::ArmToken::decode_and_bind(
            &self.words,
            expected_slot,
            install_id,
            manifest_digest,
            secure_hash,
            nonsecure_hash,
        )
    }

    /// TEST-SCAFFOLD mint (feature-gated): adversarial tests inject
    /// crafted token words through this. The honest path remains
    /// `TerminalFirst::read_arm_token` only.
    #[cfg(feature = "test-backend")]
    pub fn for_test(words: [u32; crate::arm_token::TOKEN_WORDS]) -> TokenEvidence {
        TokenEvidence { words }
    }
}

/// One sealed probation session (R18-1): the terminal reads, PENDING
/// evidence, and arm-token evidence for ONE artifact identity, owned
/// together. The three evidence pieces can only exist as one session's
/// product — a caller cannot mix artifact A's capability with artifact
/// B's PENDING or token, and cannot reuse a second session's evidence.
pub struct ProbationSession {
    identity: crate::evidence::ArtifactIdentity,
    terminals: TerminalFirst,
    pending: PendingEvidence,
    token: Option<TokenEvidence>,
}

impl ProbationSession {
    /// The identity the session is bound to.
    pub fn identity(&self) -> &crate::evidence::ArtifactIdentity {
        &self.identity
    }

    /// The terminal-first reads (shared with terminal rows).
    pub fn terminals(&self) -> &TerminalFirst {
        &self.terminals
    }

    /// The sealed PENDING evidence.
    pub fn pending(&self) -> &PendingEvidence {
        &self.pending
    }

    /// The sealed arm-token evidence, when present.
    pub fn token(&self) -> Option<&TokenEvidence> {
        self.token.as_ref()
    }
}

/// The evidence input to `decode_lifecycle` (R18-1): either bare
/// terminal-first reads (terminal rows — PENDING/TAMP never probed,
/// per R16-3) or one sealed probation session.
pub enum JournalEvidence<'a> {
    /// Terminal-first reads only (terminal rows).
    TerminalsOnly(&'a TerminalFirst),
    /// One sealed probation session (terminals + pending + token).
    Probation(&'a ProbationSession),
}

/// Sealed probation evidence (R13-1b): a PENDING read minted ONLY by
/// [`TerminalFirst::probe_pending`]. `pub(crate)` constructor — no
/// other public path exists, so probation evidence can only exist as
/// the capability's product.
pub struct PendingEvidence {
    read: FreshQwRead,
    durability: Durability,
    launch: LaunchAttribution,
}

impl PendingEvidence {
    /// The sealed read as an attributed observation.
    pub fn as_attributed_read(&self) -> AttributedRead<'_> {
        AttributedRead {
            read: &self.read,
            durability: self.durability,
            launch: self.launch,
        }
    }

    /// TEST-SCAFFOLD mint (feature-gated): adversarial tests inject
    /// non-canonical or cross-epoch PENDING reads through this. The
    /// honest path remains `TerminalFirst::probe_pending` only.
    #[cfg(feature = "test-backend")]
    pub fn for_test(
        read: FreshQwRead,
        durability: Durability,
        launch: LaunchAttribution,
    ) -> PendingEvidence {
        PendingEvidence {
            read,
            durability,
            launch,
        }
    }
}

/// The terminal-first probing capability (R10-2): PROOF that both
/// terminal QWs were fresh-probed BEFORE any PENDING/TAMP evidence was
/// obtained (§6.2 L2183–2189). Only constructible through
/// [`TerminalFirst::probe`] (canonical addresses, one acquisition
/// order); the capability carries the terminal reads it made. PENDING/
/// TAMP evidence is only meaningful downstream of this value.
pub struct TerminalFirst {
    identity: crate::evidence::ArtifactIdentity,
    c0: (FreshQwRead, Durability, LaunchAttribution),
    c1: (FreshQwRead, Durability, LaunchAttribution),
}

impl TerminalFirst {
    /// The only construction path: fresh-probe BOTH terminal QWs first,
    /// at the artifact's canonical addresses, with the caller's explicit
    /// attributions. Callers obtain PENDING/TAMP evidence only AFTER
    /// this returns.
    pub fn probe<P: crate::qw_read::FreshArrayProbe>(
        backend: &mut P,
        identity: &crate::evidence::ArtifactIdentity,
        c0_index: u16,
        c0_attribution: (Durability, LaunchAttribution),
        c1_index: u16,
        c1_attribution: (Durability, LaunchAttribution),
    ) -> TerminalFirst {
        let c0 = backend.fresh_probe(c0_index, identity.confirmed_0_qw_address);
        let c1 = backend.fresh_probe(c1_index, identity.confirmed_1_qw_address);
        TerminalFirst {
            identity: *identity,
            c0: (c0, c0_attribution.0, c0_attribution.1),
            c1: (c1, c1_attribution.0, c1_attribution.1),
        }
    }

    /// The artifact identity this capability is bound to (R18-1).
    pub fn identity(&self) -> &crate::evidence::ArtifactIdentity {
        &self.identity
    }

    /// The terminal reads this capability made.
    pub fn terminals(&self) -> (AttributedRead<'_>, AttributedRead<'_>) {
        (
            AttributedRead {
                read: &self.c0.0,
                durability: self.c0.1,
                launch: self.c0.2,
            },
            AttributedRead {
                read: &self.c1.0,
                durability: self.c1.1,
                launch: self.c1.2,
            },
        )
    }

    /// Acquire PENDING evidence — ONLY through this capability
    /// (R11-3 + R13-1b): the probation branch's reads are minted by the
    /// capability itself and sealed into [`PendingEvidence`], so
    /// terminal-first acquisition is enforced by construction and the
    /// evidence cannot be fabricated by a direct probe. (Token evidence
    /// is separately bound via `ArmToken::decode_and_bind`.)
    pub fn probe_pending<P: crate::qw_read::FreshArrayProbe>(
        &self,
        backend: &mut P,
        index: u16,
        attribution: (Durability, LaunchAttribution),
    ) -> PendingEvidence {
        // R18-1: the PENDING read is always THIS capability's canonical
        // address — no caller-chosen address exists.
        PendingEvidence {
            read: backend.fresh_probe(index, self.identity.pending_qw_address),
            durability: attribution.0,
            launch: attribution.1,
        }
    }

    /// Acquire the arm-token evidence for the probation branch —
    /// through this capability only (R14-3): TAMP words are read only
    /// AFTER both terminal QWs, mirroring the frozen
    /// terminal-before-PENDING/TAMP order. The caller still runs
    /// `ArmToken::decode_and_bind` on the returned words.
    pub fn read_arm_token<B: crate::backend::RollbackBackend>(
        &self,
        backend: &mut B,
    ) -> Option<TokenEvidence> {
        backend.read_arm_token().map(TokenEvidence::from_words)
    }

    /// Consume this capability into ONE sealed probation session bound
    /// to the SAME artifact identity it was probed for (R18-1). The
    /// PENDING evidence must be this capability's own product (its
    /// canonical address) — anything else is not a session.
    pub fn into_probation_session(
        self,
        pending: PendingEvidence,
        token: Option<TokenEvidence>,
    ) -> Option<ProbationSession> {
        if let crate::qw_read::FreshQwRead::Clean(qw) = &pending.read {
            if qw.addr() != self.identity.pending_qw_address {
                return None;
            }
        }
        Some(ProbationSession {
            identity: self.identity,
            terminals: self,
            pending,
            token,
        })
    }

    /// TEST-SCAFFOLD constructor (feature-gated): adversarial tests
    /// inject mis-addressed or cross-epoch terminal reads through this.
    #[cfg(feature = "test-backend")]
    pub fn from_reads(
        identity: &crate::evidence::ArtifactIdentity,
        c0: (FreshQwRead, Durability, LaunchAttribution),
        c1: (FreshQwRead, Durability, LaunchAttribution),
    ) -> TerminalFirst {
        TerminalFirst {
            identity: *identity,
            c0,
            c1,
        }
    }
}

/// Why a combination is `MALFORMED` (§6.2 L2191–2193).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MalformedReason {
    /// Torn/corrected/may-have-launched/conflicting/impossible-order
    /// terminal observation — never falls through to PENDING.
    TerminalRejected(TerminalRejection),
    /// Terminal evidence exists but PENDING/TAMP was consulted anyway,
    /// or out-of-order markers (e.g. exact terminal plus exact PENDING).
    OutOfOrderMarkers,
    /// Missing, malformed, or binding-mismatched token on the probation
    /// branch.
    MissingOrMalformedToken,
    /// Token state does not match the lifecycle branch (e.g. PENDING
    /// exact with an ATTEMPTED token on the PENDING row).
    TokenStateMismatch,
    /// `R`/`E` out of range (already enforced by v6 parse, re-enforced
    /// here for the decoded relation rows).
    OutOfRangeVersion,
    /// `F > T` on any terminal row, or `E <= F` on a probation row.
    FloorRelationViolation,
    /// Install-generation evidence missing, conflicting, or not
    /// state-appropriate (Full required before activation).
    BadInstallGeneration,
    /// Token binding does not match the artifact identity.
    TokenBindingMismatch,
    /// The probation session is bound to a DIFFERENT artifact identity
    /// than the one being decoded (R18-1).
    SessionIdentityMismatch,
    /// The artifact proof and its lifecycle/terminal proof do not carry
    /// the same sealed `ArtifactEvidenceKey` (R17-3: not a token issue —
    /// no token is consulted on terminal rows).
    EvidenceKeyMismatch,
    /// A presented journal read is not the artifact's canonical QW for
    /// its role (wrong address), or the presented reads do not share
    /// one probe epoch (R3-2: A's QWs can never construct B's evidence).
    NonCanonicalJournalQw,
}

/// The artifact + bound token payload of a PENDING/ATTEMPTED row.
/// Crate-private constructor (R6-4): `decode_lifecycle` is the sole
/// producer — no caller can synthesize a probation row and bypass the
/// decode gates (terminal-first probing, both-terminals-BlankVirgin,
/// exact PENDING, canonical-QW/one-epoch binding, generation join).
pub struct PendingRow {
    artifact: VerifiedArtifact,
    token: ArmToken,
}

impl PendingRow {
    pub(crate) fn new(artifact: VerifiedArtifact, token: ArmToken) -> PendingRow {
        PendingRow { artifact, token }
    }

    /// The row's verified artifact.
    pub fn artifact(&self) -> &VerifiedArtifact {
        &self.artifact
    }

    /// The row's bound arm token.
    pub fn token(&self) -> &ArmToken {
        &self.token
    }

    /// Consume the row into its parts (intents are linear consumers).
    pub fn into_parts(self) -> (VerifiedArtifact, ArmToken) {
        (self.artifact, self.token)
    }
}

/// A sealed artifact-only row payload (R8-6): crate-private
/// constructor, `decode_lifecycle` is the sole producer.
pub struct ArtifactRow {
    artifact: VerifiedArtifact,
}

impl ArtifactRow {
    pub(crate) fn new(artifact: VerifiedArtifact) -> ArtifactRow {
        ArtifactRow { artifact }
    }

    /// The row's verified artifact.
    pub fn artifact(&self) -> &VerifiedArtifact {
        &self.artifact
    }

    /// Consume the row into the artifact.
    pub fn into_artifact(self) -> VerifiedArtifact {
        self.artifact
    }
}

/// A sealed surviving-terminal-set row payload (R8-6, extended in
/// R9-1): crate-private constructor — the floor-relation label
/// (`F == T` vs `F < T`) cannot be forged or relabeled outside
/// `decode_lifecycle`, and the row carries the artifact's sealed
/// `ArtifactEvidenceKey` so downstream evidence sets can bind it
/// WITHOUT any caller-supplied digest.
#[derive(Debug)]
pub struct DegradedRow {
    set: SurvivingTerminalSet,
    key: crate::evidence::ArtifactEvidenceKey,
}

impl DegradedRow {
    pub(crate) fn new(set: SurvivingTerminalSet, key: crate::evidence::ArtifactEvidenceKey) -> DegradedRow {
        DegradedRow { set, key }
    }

    /// The surviving terminal set (repair-target evidence only).
    pub fn set(&self) -> &SurvivingTerminalSet {
        &self.set
    }

    /// The artifact's sealed evidence key.
    pub fn key(&self) -> &crate::evidence::ArtifactEvidenceKey {
        &self.key
    }

    /// Consume the row into its parts (linear proof consumption for the
    /// degraded-history evidence set).
    pub fn into_parts(self) -> (SurvivingTerminalSet, crate::evidence::ArtifactEvidenceKey) {
        (self.set, self.key)
    }
}

/// The six accepted lifecycle rows plus `Malformed` (§6.2 L2165–2172).
pub enum LifecycleState {
    /// Verified newly installed body/full identity before activation:
    /// both terminals `BlankVirgin`, PENDING `BlankVirgin`, token
    /// ignored. Requires `FullInstallGeneration`. Grants no authority.
    Uninstalled(ArtifactRow),
    /// Both terminals `BlankVirgin`; PENDING exact; token exact
    /// `ARM_READY`; `E > F`.
    Pending(PendingRow),
    /// Both terminals `BlankVirgin`; PENDING exact; token exact
    /// `ATTEMPTED`; `E > F`.
    Attempted(PendingRow),
    /// `FullTerminalSet` — robust `CONFIRMED`. `F <= T`. Bootable.
    ConfirmedRobust(AcceptedArtifact),
    /// `SurvivingTerminalSet`, `F == T` — degraded `CONFIRMED`.
    /// Repair-target evidence ONLY: never boot/floor authority.
    DegradedConfirmed(DegradedRow),
    /// `SurvivingTerminalSet`, `F < T` — degraded epoch candidate.
    /// Repair-target evidence ONLY: never boot/floor authority.
    DegradedEpochCandidate(DegradedRow),
    /// Every other combination (§6.2 L2191–2193). Ineligible; has no
    /// marker-only outgoing transition.
    Malformed(MalformedReason),
}

/// The canonical install-generation orchestrator (R4-1): the public
/// path for constructing install-generation evidence. The presented
/// install-identity reads must sit at the identity's canonical install
/// QW addresses and share one common probe epoch; the raw codec
/// constructors stay crate-private. With `later_evidence == None` only
/// a `FullInstallGeneration` can result (before-activation rule); with
/// `Some(..)` the qualified-survivor rule applies.
pub fn decode_install_generation(
    artifact: &VerifiedArtifact,
    id: AttributedRead<'_>,
    inv: AttributedRead<'_>,
    later_evidence: Option<fw_manifest::v6::LaterLifecycleEvidence>,
    expected_epoch: Option<u32>,
) -> Option<InstallGenerationEvidence> {
    let identity = artifact.identity();
    for (read, expected_addr) in [
        (id.read, identity.install_id_qw_address()),
        (inv.read, identity.install_id_inv_qw_address()),
    ] {
        if let crate::qw_read::FreshQwRead::Clean(qw) = read {
            if qw.addr() != expected_addr {
                return None;
            }
        }
    }
    // The halves must share one probe epoch with each other AND with
    // the required pass epoch when one is supplied (R13-4: no
    // cross-epoch generation joins).
    let mut epoch: Option<u32> = None;
    for read in [id.read, inv.read] {
        if let crate::qw_read::FreshQwRead::Clean(qw) = read {
            if let Some(required) = expected_epoch {
                if qw.probe_epoch() != required {
                    return None;
                }
            }
            match epoch {
                None => epoch = Some(qw.probe_epoch()),
                Some(e) if e != qw.probe_epoch() => return None,
                _ => {}
            }
        }
    }
    let epoch = epoch?;
    let id_ev = install_half_evidence(id.read, id.durability, id.launch);
    let inv_ev = install_half_evidence(inv.read, inv.durability, inv.launch);
    // Bind the minted proof to THIS artifact's sealed key (R5-4).
    let key_digest = artifact.key().digest();
    match later_evidence {
        None => full_install_generation(id_ev, inv_ev, key_digest, epoch)
            .map(InstallGenerationEvidence::Full),
        Some(ev) => surviving_install_generation(id_ev, inv_ev, ev, key_digest, epoch)
            .map(InstallGenerationEvidence::Surviving),
    }
}

/// Decode one slot's lifecycle row. Consumes the terminal-set outcome and
/// the verified artifact by value where they become part of the row.
///
/// * `floor` is the current independently decoded rollback floor `F`.
/// * `token` is `Some` only when a structurally valid, binding-matched
///   arm token for THIS artifact was supplied (missing/malformed/
///   binding-mismatched token on the probation branch → `Malformed`).
/// * `generation` is the install-generation evidence for the artifact's
///   reconstructed identity.
#[allow(clippy::too_many_arguments)]
pub fn decode_lifecycle(
    artifact: VerifiedArtifact,
    generation: Option<InstallGenerationEvidence>,
    evidence: JournalEvidence<'_>,
    floor: u32,
) -> LifecycleState {
    let (terminal_c0, terminal_c1) = match &evidence {
        JournalEvidence::TerminalsOnly(terminals) => terminals.terminals(),
        JournalEvidence::Probation(session) => session.terminals().terminals(),
    };
    // Terminal-first classification (R13-1a): the TERMINAL reads must
    // be canonical for THIS artifact on every row (R3-2); the PENDING
    // read is consulted ONLY on the probation branch below — on
    // terminal rows it is "not read; non-authoritative" (§6.2
    // L2170–2172) and never validated.
    let trio_epoch = match canonical_terminal_reads(artifact.identity(), terminal_c0.read, terminal_c1.read) {
        Some(epoch) => epoch,
        None => return LifecycleState::Malformed(MalformedReason::NonCanonicalJournalQw),
    };
    let terminal = decode_terminal_set(
        terminal_c0.read,
        terminal_c0.durability,
        terminal_c0.launch,
        terminal_c1.read,
        terminal_c1.durability,
        terminal_c1.launch,
        artifact.key(),
    );
    let t = artifact.t();

    // Terminal-first: exact terminal evidence decides the row before any
    // PENDING/TAMP consideration.
    match terminal {
        TerminalSetOutcome::Full(set) => {
            // Robust CONFIRMED requires F <= T.
            if floor > t {
                return LifecycleState::Malformed(MalformedReason::FloorRelationViolation);
            }
            if !generation_matches(&generation, &artifact, true, trio_epoch) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            return match AcceptedArtifact::new(
                artifact,
                crate::evidence::RobustConfirmedEvidence::RobustTerminalSet(set),
            ) {
                Some(accepted) => LifecycleState::ConfirmedRobust(accepted),
                None => LifecycleState::Malformed(MalformedReason::EvidenceKeyMismatch),
            };
        }
        TerminalSetOutcome::Surviving(set) => {
            // Degraded rows: repair-target evidence only. F == T →
            // degraded CONFIRMED; F < T → degraded epoch candidate;
            // F > T → malformed.
            if !generation_matches(&generation, &artifact, true, trio_epoch) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            return if floor == t {
                LifecycleState::DegradedConfirmed(DegradedRow::new(set, *artifact.key()))
            } else if floor < t {
                LifecycleState::DegradedEpochCandidate(DegradedRow::new(set, *artifact.key()))
            } else {
                LifecycleState::Malformed(MalformedReason::FloorRelationViolation)
            };
        }
        TerminalSetOutcome::Rejected(TerminalRejection::NoTerminalAuthority) => {
            // Only now may PENDING/TAMP be considered — and only when
            // BOTH terminals are proven BlankVirgin.
        }
        TerminalSetOutcome::Rejected(reason) => {
            return LifecycleState::Malformed(MalformedReason::TerminalRejected(reason));
        }
    }

    let c0 = observe_marker(
        terminal_c0.read,
        &fw_manifest::v6::QW_CONFIRMED_0,
        terminal_c0.durability,
        terminal_c0.launch,
    );
    let c1 = observe_marker(
        terminal_c1.read,
        &fw_manifest::v6::QW_CONFIRMED_1,
        terminal_c1.durability,
        terminal_c1.launch,
    );
    if !matches!(
        (c0, c1),
        (MarkerObservation::ProvenVirgin, MarkerObservation::ProvenVirgin)
    ) {
        // A terminal QW that is neither exact nor proven virgin is torn /
        // corrected / may-have-launched: never falls through to PENDING.
        return LifecycleState::Malformed(MalformedReason::OutOfOrderMarkers);
    }

    // PENDING branch (R13-1a + R18-1): only here is probation evidence
    // consulted — and it must come from ONE sealed session bound to
    // THIS artifact (R18-1: the session's identity must match, or the
    // evidence is not this artifact's at all). The session's PENDING
    // evidence must satisfy the full trio canonical check.
    let session = match &evidence {
        JournalEvidence::Probation(session) if session.identity() == artifact.identity() => session,
        JournalEvidence::Probation(_) => {
            return LifecycleState::Malformed(MalformedReason::SessionIdentityMismatch);
        }
        JournalEvidence::TerminalsOnly(_) => {
            return LifecycleState::Malformed(MalformedReason::OutOfOrderMarkers);
        }
    };
    let pending = session.pending().as_attributed_read();
    if canonical_journal_reads(
        artifact.identity(),
        terminal_c0.read,
        terminal_c1.read,
        pending.read,
    )
    .is_none()
    {
        return LifecycleState::Malformed(MalformedReason::NonCanonicalJournalQw);
    }
    let p = observe_marker(
        pending.read,
        &QW_PENDING,
        pending.durability,
        pending.launch,
    );
    let e = artifact.e();
    match p {
        MarkerObservation::ProvenVirgin => {
            // UNINSTALLED: token ignored; before activation only a full
            // generation is valid.
            if !generation_matches(&generation, &artifact, false, trio_epoch) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            LifecycleState::Uninstalled(ArtifactRow::new(artifact))
        }
        MarkerObservation::Exact => {
            // Probation rows require E > F and an exact, state-matching
            // bound token.
            if e <= floor {
                return LifecycleState::Malformed(MalformedReason::FloorRelationViolation);
            }
            if !generation_matches(&generation, &artifact, true, trio_epoch) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            // R15-1: the token evidence comes from the SAME sealed
            // session; it is decoded and bound HERE, against this
            // artifact.
            let id = artifact.identity();
            let token = match session.token() {
                Some(evidence) => match evidence.decode_and_bind(
                    id.slot,
                    &id.install_id,
                    &id.manifest_digest,
                    &id.secure_hash,
                    &id.nonsecure_hash,
                ) {
                    Ok(token) => token,
                    Err(_) => {
                        return LifecycleState::Malformed(
                            MalformedReason::MissingOrMalformedToken,
                        )
                    }
                },
                None => {
                    return LifecycleState::Malformed(MalformedReason::MissingOrMalformedToken)
                }
            };
            if !token_matches(&token, &artifact) {
                return LifecycleState::Malformed(MalformedReason::TokenBindingMismatch);
            }
            match token.state() {
                ArmState::ArmReady => LifecycleState::Pending(PendingRow::new(artifact, token)),
                ArmState::Attempted => LifecycleState::Attempted(PendingRow::new(artifact, token)),
            }
        }
        _ => LifecycleState::Malformed(MalformedReason::OutOfOrderMarkers),
    }
}

/// Install-generation evidence must exist, reconstruct the SAME identity
/// the artifact key carries, and be state-appropriate: before activation
/// (`after_activation == false`) only `FullInstallGeneration` is valid;
/// after PENDING or terminal evidence a qualified survivor is permitted.
fn generation_matches(
    generation: &Option<InstallGenerationEvidence>,
    artifact: &VerifiedArtifact,
    after_activation: bool,
    expected_epoch: u32,
) -> bool {
    // The generation must reconstruct the SAME identity, bind the SAME
    // sealed key, AND carry the SAME probe epoch as the lifecycle reads
    // (R5-4 + R13-4: no old-pass, cross-artifact, or cross-epoch joins).
    let key_digest = artifact.key().digest();
    match generation {
        Some(InstallGenerationEvidence::Full(g)) => {
            g.install_id() == artifact.install_id()
                && g.evidence_key() == &key_digest
                && g.epoch() == expected_epoch
        }
        Some(InstallGenerationEvidence::Surviving(g)) => {
            after_activation
                && g.install_id() == artifact.install_id()
                && g.evidence_key() == &key_digest
                && g.epoch() == expected_epoch
        }
        None => false,
    }
}

/// R3-2 canonical journal-QW check: every presented Clean journal read
/// must sit at the artifact identity's canonical address for its role
/// (terminal 0, terminal 1, PENDING), and all presented reads must
/// share one probe epoch (one common pass). Non-Clean reads fail closed
/// elsewhere and are not address-checkable here.
/// R13-1a: canonical check for the TERMINAL reads only (applied on
/// every row): this artifact's canonical terminal addresses, one
/// common probe epoch.
pub(crate) fn canonical_terminal_reads(
    id: &crate::evidence::ArtifactIdentity,
    c0: &crate::qw_read::FreshQwRead,
    c1: &crate::qw_read::FreshQwRead,
) -> Option<u32> {
    let mut epoch: Option<u32> = None;
    for (read, expected_addr) in [
        (c0, id.confirmed_0_qw_address),
        (c1, id.confirmed_1_qw_address),
    ] {
        if let crate::qw_read::FreshQwRead::Clean(qw) = read {
            if qw.addr() != expected_addr {
                return None;
            }
            match epoch {
                None => epoch = Some(qw.probe_epoch()),
                Some(e) if e != qw.probe_epoch() => return None,
                _ => {}
            }
        }
    }
    epoch
}

/// R13-2-era canonical journal check (probation branch): every presented
/// Clean journal read must sit at the artifact identity's canonical
/// address for its role (terminal 0, terminal 1, PENDING), and all
/// presented reads must share one common probe epoch. On success the
/// shared epoch is returned (R13-4: the generation must carry the same
/// epoch).
pub(crate) fn canonical_journal_reads(
    id: &crate::evidence::ArtifactIdentity,
    c0: &crate::qw_read::FreshQwRead,
    c1: &crate::qw_read::FreshQwRead,
    pending: &crate::qw_read::FreshQwRead,
) -> Option<u32> {
    let mut epoch: Option<u32> = None;
    for (read, expected_addr) in [
        (c0, id.confirmed_0_qw_address),
        (c1, id.confirmed_1_qw_address),
        (pending, id.pending_qw_address),
    ] {
        if let crate::qw_read::FreshQwRead::Clean(qw) = read {
            if qw.addr() != expected_addr {
                return None;
            }
            match epoch {
                None => epoch = Some(qw.probe_epoch()),
                Some(e) if e != qw.probe_epoch() => return None,
                _ => {}
            }
        }
    }
    epoch
}

/// The bound token must carry exactly the artifact's tuple and identity.
fn token_matches(token: &ArmToken, artifact: &VerifiedArtifact) -> bool {
    let id = artifact.identity();
    token.binding().slot == id.slot
        && token.binding().r == id.r
        && token.binding().e == id.e
        && token.binding().t == id.t
        && token.binding().install_id == id.install_id
        && token.binding().manifest_digest == id.manifest_digest
        && token.binding().secure_hash == id.secure_hash
        && token.binding().nonsecure_hash == id.nonsecure_hash
}

// ---------------------------------------------------------------------------
// The legal transition chain (§6.2 L2199–2208)
// ---------------------------------------------------------------------------

/// Chain states for the one legal transition sequence within one
/// slot-installation generation. `Malformed` appears in NO legal
/// transition: it has no marker-only outgoing transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainState {
    Uninstalled,
    Pending,
    Attempted,
    /// `CONFIRMED_0` written (first terminal replica).
    ConfirmedReplica0,
    /// Both terminal replicas written (`CONFIRMED`).
    Confirmed,
    /// Floor established at `T` (`F := security_epoch - 1`; no OTP write
    /// when already equal).
    FloorEstablished,
    Malformed,
}

/// The only legal transition chain (§6.2 L2199–2208):
///
/// ```text
/// UNINSTALLED --runtime COMMIT--> PENDING
/// PENDING     --immutable FSBL--> ATTEMPTED
/// ATTEMPTED   --full HEALTH_PASS + user finalization--> CONFIRMED_0
/// CONFIRMED_0 --independent durable receipt-----------> CONFIRMED_1
/// CONFIRMED   --immutable FSBL--> establish F := security_epoch - 1
/// ```
pub fn is_legal_transition(from: ChainState, to: ChainState) -> bool {
    matches!(
        (from, to),
        (ChainState::Uninstalled, ChainState::Pending)
            | (ChainState::Pending, ChainState::Attempted)
            | (ChainState::Attempted, ChainState::ConfirmedReplica0)
            | (ChainState::ConfirmedReplica0, ChainState::Confirmed)
            | (ChainState::Confirmed, ChainState::FloorEstablished)
    )
}
