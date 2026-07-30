//! Legal transition chain (§6.2 L2199–2208): the only legal sequence,
//! every illegal transition rejected, MALFORMED has no marker-only
//! outgoing transition.

use pqsigner_rollback::lifecycle::{is_legal_transition, ChainState};

const ALL: [ChainState; 7] = [
    ChainState::Uninstalled,
    ChainState::Pending,
    ChainState::Attempted,
    ChainState::ConfirmedReplica0,
    ChainState::Confirmed,
    ChainState::FloorEstablished,
    ChainState::Malformed,
];

const LEGAL: [(ChainState, ChainState); 5] = [
    (ChainState::Uninstalled, ChainState::Pending),
    (ChainState::Pending, ChainState::Attempted),
    (ChainState::Attempted, ChainState::ConfirmedReplica0),
    (ChainState::ConfirmedReplica0, ChainState::Confirmed),
    (ChainState::Confirmed, ChainState::FloorEstablished),
];

#[test]
fn the_legal_chain_end_to_end() {
    let mut state = ChainState::Uninstalled;
    for (from, to) in LEGAL {
        assert_eq!(state, from);
        assert!(is_legal_transition(state, to));
        state = to;
    }
    assert_eq!(state, ChainState::FloorEstablished);
}

#[test]
fn every_illegal_transition_is_rejected() {
    for from in ALL {
        for to in ALL {
            let expect = LEGAL.contains(&(from, to));
            assert_eq!(
                is_legal_transition(from, to),
                expect,
                "transition {from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn malformed_has_no_marker_only_outgoing_transition() {
    for to in ALL {
        assert!(
            !is_legal_transition(ChainState::Malformed, to),
            "MALFORMED must have no outgoing transition to {to:?}"
        );
        assert!(
            !is_legal_transition(to, ChainState::Malformed),
            "no marker-only transition may CONSTRUCT Malformed from {to:?} (it is a decode outcome)"
        );
    }
}

#[test]
fn no_skips_no_retries_no_reverse() {
    // Skips.
    assert!(!is_legal_transition(
        ChainState::Uninstalled,
        ChainState::Attempted
    ));
    assert!(!is_legal_transition(
        ChainState::Pending,
        ChainState::Confirmed
    ));
    assert!(!is_legal_transition(
        ChainState::Attempted,
        ChainState::FloorEstablished
    ));
    // ATTEMPTED never retries back to PENDING/ARM_READY semantics.
    assert!(!is_legal_transition(
        ChainState::Attempted,
        ChainState::Pending
    ));
    // No reverse transitions at all.
    assert!(!is_legal_transition(
        ChainState::Confirmed,
        ChainState::Attempted
    ));
    assert!(!is_legal_transition(
        ChainState::FloorEstablished,
        ChainState::Confirmed
    ));
}
