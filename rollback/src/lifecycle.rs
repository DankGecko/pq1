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
    decode_terminal_set, observe_marker, InstallGenerationEvidence, MarkerObservation,
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
}

/// The six accepted lifecycle rows plus `Malformed` (§6.2 L2165–2172).
pub enum LifecycleState {
    /// Verified newly installed body/full identity before activation:
    /// both terminals `BlankVirgin`, PENDING `BlankVirgin`, token
    /// ignored. Requires `FullInstallGeneration`.
    Uninstalled { artifact: VerifiedArtifact },
    /// Both terminals `BlankVirgin`; PENDING exact; token exact
    /// `ARM_READY`; `E > F`.
    Pending {
        artifact: VerifiedArtifact,
        token: ArmToken,
    },
    /// Both terminals `BlankVirgin`; PENDING exact; token exact
    /// `ATTEMPTED`; `E > F`.
    Attempted {
        artifact: VerifiedArtifact,
        token: ArmToken,
    },
    /// `FullTerminalSet` — robust `CONFIRMED`. `F <= T`. Bootable.
    ConfirmedRobust(AcceptedArtifact),
    /// `SurvivingTerminalSet`, `F == T` — degraded `CONFIRMED`.
    /// Repair-target evidence ONLY: never boot/floor authority.
    DegradedConfirmed(SurvivingTerminalSet),
    /// `SurvivingTerminalSet`, `F < T` — degraded epoch candidate.
    /// Repair-target evidence ONLY: never boot/floor authority.
    DegradedEpochCandidate(SurvivingTerminalSet),
    /// Every other combination (§6.2 L2191–2193). Ineligible; has no
    /// marker-only outgoing transition.
    Malformed(MalformedReason),
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
    terminal_c0: AttributedRead<'_>,
    terminal_c1: AttributedRead<'_>,
    pending: AttributedRead<'_>,
    token: Option<ArmToken>,
    floor: u32,
) -> LifecycleState {
    let key_digest = artifact.key().digest();
    let terminal = decode_terminal_set(
        terminal_c0.read,
        terminal_c0.durability,
        terminal_c0.launch,
        terminal_c1.read,
        terminal_c1.durability,
        terminal_c1.launch,
        key_digest,
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
            if !generation_matches(&generation, &artifact, true) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            return match AcceptedArtifact::new(
                artifact,
                crate::evidence::RobustConfirmedEvidence::RobustTerminalSet(set),
            ) {
                Some(accepted) => LifecycleState::ConfirmedRobust(accepted),
                None => LifecycleState::Malformed(MalformedReason::TokenBindingMismatch),
            };
        }
        TerminalSetOutcome::Surviving(set) => {
            // Degraded rows: repair-target evidence only. F == T →
            // degraded CONFIRMED; F < T → degraded epoch candidate;
            // F > T → malformed.
            if !generation_matches(&generation, &artifact, true) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            return if floor == t {
                LifecycleState::DegradedConfirmed(set)
            } else if floor < t {
                LifecycleState::DegradedEpochCandidate(set)
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

    // PENDING branch.
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
            if !generation_matches(&generation, &artifact, false) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            LifecycleState::Uninstalled { artifact }
        }
        MarkerObservation::Exact => {
            // Probation rows require E > F and an exact, state-matching
            // bound token.
            if e <= floor {
                return LifecycleState::Malformed(MalformedReason::FloorRelationViolation);
            }
            if !generation_matches(&generation, &artifact, true) {
                return LifecycleState::Malformed(MalformedReason::BadInstallGeneration);
            }
            let token = match token {
                Some(token) => token,
                None => {
                    return LifecycleState::Malformed(MalformedReason::MissingOrMalformedToken)
                }
            };
            if !token_matches(&token, &artifact) {
                return LifecycleState::Malformed(MalformedReason::TokenBindingMismatch);
            }
            match token.state {
                ArmState::ArmReady => LifecycleState::Pending { artifact, token },
                ArmState::Attempted => LifecycleState::Attempted { artifact, token },
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
) -> bool {
    match generation {
        Some(InstallGenerationEvidence::Full(g)) => g.install_id() == artifact.install_id(),
        Some(InstallGenerationEvidence::Surviving(g)) => {
            after_activation && g.install_id() == artifact.install_id()
        }
        None => false,
    }
}

/// The bound token must carry exactly the artifact's tuple and identity.
fn token_matches(token: &ArmToken, artifact: &VerifiedArtifact) -> bool {
    let id = artifact.identity();
    token.binding.slot == id.slot
        && token.binding.r == id.r
        && token.binding.e == id.e
        && token.binding.t == id.t
        && token.binding.install_id == id.install_id
        && token.binding.manifest_digest == id.manifest_digest
        && token.binding.secure_hash == id.secure_hash
        && token.binding.nonsecure_hash == id.nonsecure_hash
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
