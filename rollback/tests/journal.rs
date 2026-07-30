//! Journal-codec tests: codeword Hamming properties, install-generation
//! semantics (incl. the required-evidence parameter and the impossible
//! writer-order rule), terminal-set decoding.

mod common;

use common::*;
use fw_manifest::v6::{LaterLifecycleEvidence, PhysicalSlot, QW_CONFIRMED_0, QW_CONFIRMED_1, QW_PENDING};
use pqsigner_rollback::backend::ProbeScript;
use pqsigner_rollback::journal::*;
use pqsigner_rollback::qw_read::{Durability, FreshQwRead, LaunchAttribution};

fn hamming(a: &[u8; 16], b: &[u8; 16]) -> u32 {
    let mut d = 0;
    for i in 0..16 {
        d += (a[i] ^ b[i]).count_ones();
    }
    d
}

#[test]
fn codeword_hamming_properties() {
    const ERASED: [u8; 16] = [0xFF; 16];
    for cw in [QW_PENDING, QW_CONFIRMED_0, QW_CONFIRMED_1] {
        assert_eq!(hamming(&cw, &ERASED), 64, "distance 64 from erased");
        for i in 0..8 {
            assert_eq!(cw[8 + i], !cw[i], "second half is complement");
        }
    }
    assert!(hamming(&QW_PENDING, &QW_CONFIRMED_0) >= 64);
    assert!(hamming(&QW_PENDING, &QW_CONFIRMED_1) >= 64);
    assert!(hamming(&QW_CONFIRMED_0, &QW_CONFIRMED_1) >= 64);
}

#[test]
fn install_generation_full_and_forbidden() {
    let full = full_install_generation(
        InstallHalfEvidence::Exact(INSTALL_ID),
        InstallHalfEvidence::Exact(INSTALL_ID_INV),
    );
    assert_eq!(full.map(|g| g.install_id()), Some(INSTALL_ID));

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
    let mut bad = INSTALL_ID_INV;
    bad[0] ^= 1;
    assert!(full_install_generation(
        InstallHalfEvidence::Exact(INSTALL_ID),
        InstallHalfEvidence::Exact(bad),
    )
    .is_none());

    // A missing half is never a FULL generation.
    assert!(full_install_generation(
        InstallHalfEvidence::Exact(INSTALL_ID),
        InstallHalfEvidence::Indeterminate,
    )
    .is_none());
}

#[test]
fn surviving_install_generation_requires_evidence_and_rejects_impossible() {
    let ev = LaterLifecycleEvidence::Pending;

    // Exactly one durable clean nontrivial half + evidence → reconstruct.
    let s = surviving_install_generation(
        InstallHalfEvidence::Exact(INSTALL_ID),
        InstallHalfEvidence::Indeterminate,
        ev,
    );
    assert_eq!(s.map(|g| g.install_id()), Some(INSTALL_ID));
    let s = surviving_install_generation(
        InstallHalfEvidence::Indeterminate,
        InstallHalfEvidence::Exact(INSTALL_ID_INV),
        ev,
    );
    assert_eq!(s.map(|g| g.install_id()), Some(INSTALL_ID));

    // IMPOSSIBLE WRITER-ORDER: a survivor half proven BlankVirgin after
    // later lifecycle evidence rejects (hard design rule 3).
    assert!(surviving_install_generation(
        InstallHalfEvidence::Exact(INSTALL_ID),
        InstallHalfEvidence::ProvenBlankVirgin,
        ev,
    )
    .is_none());
    assert!(surviving_install_generation(
        InstallHalfEvidence::ProvenBlankVirgin,
        InstallHalfEvidence::Exact(INSTALL_ID_INV),
        ev,
    )
    .is_none());

    // Conflicting exact halves reject even with evidence.
    let mut bad = INSTALL_ID_INV;
    bad[3] ^= 0x40;
    assert!(surviving_install_generation(
        InstallHalfEvidence::Exact(INSTALL_ID),
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

    // NOTE (API shape): the `evidence` parameter is REQUIRED — a lone
    // half before activation cannot even be expressed as a call. This is
    // the type-level encoding of "a lone half before activation is
    // incomplete".
}

#[test]
fn blank_virgin_requires_clean_erased_and_no_launch() {
    let mut b = TestBackend::new(7);
    let erased = probe_clean(&mut b, 0, ERASED);
    // Clean all-FF + proven no launch → BlankVirgin.
    assert!(pqsigner_rollback::qw_read::BlankVirgin::prove(&erased, NO_LAUNCH).is_some());
    // Clean all-FF but a program may have launched → NOT virgin.
    assert!(pqsigner_rollback::qw_read::BlankVirgin::prove(&erased, MAY_LAUNCH).is_none());
    // Corrected all-FF is neither blank nor virgin even with no launch.
    let corrected = probe(&mut b, 1, ProbeScript::Corrected(ERASED));
    assert!(pqsigner_rollback::qw_read::BlankVirgin::prove(&corrected, NO_LAUNCH).is_none());
}

#[test]
fn terminal_set_full_surviving_and_rejections() {
    let mut b = TestBackend::new(7);
    let p = pass();
    let art = artifact(&p, PhysicalSlot::A);
    let key = art.key();

    // Full: both exact.
    let c0 = probe_clean(&mut b, 0, QW_CONFIRMED_0);
    let c1 = probe_clean(&mut b, 1, QW_CONFIRMED_1);
    match decode_terminal_set(&c0, CLEAN, MAY_LAUNCH, &c1, CLEAN, MAY_LAUNCH, key) {
        TerminalSetOutcome::Full(set) => assert_eq!(set.evidence_key(), &key.digest()),
        _ => panic!("expected Full"),
    }

    // Surviving: C0 exact, C1 indeterminate (may-have-launched erased).
    let c1_erased = probe_clean(&mut b, 1, ERASED);
    match decode_terminal_set(&c0, CLEAN, MAY_LAUNCH, &c1_erased, CLEAN, MAY_LAUNCH, key) {
        TerminalSetOutcome::Surviving(set) => {
            assert_eq!(set.replica(), TerminalReplica::Replica0)
        }
        _ => panic!("expected Surviving(Replica0)"),
    }

    // IMPOSSIBLE WRITER-ORDER: C1 exact with C0 proven BlankVirgin.
    let c0_erased = probe_clean(&mut b, 0, ERASED);
    match decode_terminal_set(&c0_erased, CLEAN, NO_LAUNCH, &c1, CLEAN, MAY_LAUNCH, key) {
        TerminalSetOutcome::Rejected(TerminalRejection::ImpossibleWriterOrder) => {}
        other => panic!("expected ImpossibleWriterOrder, got {}", name_of(&other)),
    }

    // Conflicting exact value: clean durably-clean read of garbage.
    let c0_garbage = probe_clean(&mut b, 0, [0x42; 16]);
    match decode_terminal_set(&c0_garbage, CLEAN, MAY_LAUNCH, &c1, CLEAN, MAY_LAUNCH, key) {
        TerminalSetOutcome::Rejected(TerminalRejection::ConflictingExactValue) => {}
        other => panic!("expected ConflictingExactValue, got {}", name_of(&other)),
    }

    // Corrected codeword bytes have ZERO weight (not an exact marker).
    let c0_corrected = probe(&mut b, 0, ProbeScript::Corrected(QW_CONFIRMED_0));
    match decode_terminal_set(&c0_corrected, CLEAN, NO_LAUNCH, &c1, CLEAN, MAY_LAUNCH, key) {
        TerminalSetOutcome::Surviving(set) => {
            assert_eq!(set.replica(), TerminalReplica::Replica1)
        }
        other => panic!("expected Surviving(Replica1), got {}", name_of(&other)),
    }

    // Neither exact → NoTerminalAuthority.
    let e0 = probe_clean(&mut b, 2, ERASED);
    let e1 = probe_clean(&mut b, 3, ERASED);
    match decode_terminal_set(&e0, CLEAN, NO_LAUNCH, &e1, CLEAN, NO_LAUNCH, key) {
        TerminalSetOutcome::Rejected(TerminalRejection::NoTerminalAuthority) => {}
        other => panic!("expected NoTerminalAuthority, got {}", name_of(&other)),
    }

    // Durability-ambiguous exact-looking read is NOT exact.
    let c0_amb = probe_clean(&mut b, 0, QW_CONFIRMED_0);
    match decode_terminal_set(&c0_amb, Durability::Ambiguous, MAY_LAUNCH, &c1, CLEAN, MAY_LAUNCH, key)
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

#[test]
fn pending_marker_observation() {
    let mut b = TestBackend::new(7);
    let p = probe_clean(&mut b, 0, QW_PENDING);
    assert!(exact_marker(&p, &PENDING_CODEWORD, CLEAN));
    assert!(!exact_marker(&p, &PENDING_CODEWORD, Durability::Ambiguous));
    let _ = LaunchAttribution::MayHaveLaunched;
    let _ = FreshQwRead::AmbiguousOrFault;
}

#[test]
fn probe_classification_is_canonical_not_scriptable() {
    // R2-1: the script sets the raw STATUS; the provided `fresh_probe`
    // derives the outcome class. A backend can never upgrade a corrected
    // or faulted read to Clean, and the CleanQw always binds the
    // REQUESTED index/address, never one the backend chose.
    let mut b = TestBackend::new(7);

    // Corrected bytes that happen to equal a codeword classify as
    // Corrected (zero quorum weight), never Clean.
    let read = probe(&mut b, 0, ProbeScript::Corrected(QW_CONFIRMED_0));
    match &read {
        FreshQwRead::Corrected { index, .. } => assert_eq!(*index, 0),
        FreshQwRead::Clean(_) => panic!("a corrected read must never classify as Clean"),
        _ => panic!("expected Corrected"),
    }

    // An ECCD script classifies as Uncorrectable regardless of bytes.
    let read = probe(&mut b, 1, ProbeScript::Uncorrectable);
    assert!(matches!(read, FreshQwRead::Uncorrectable { index: 1 }));

    // An unattributable script classifies as AmbiguousOrFault.
    let read = probe(&mut b, 2, ProbeScript::AmbiguousOrFault);
    assert!(matches!(read, FreshQwRead::AmbiguousOrFault));

    // A Clean script binds exactly the requested index/address/epoch.
    let addr = pqsigner_rollback::floor::canonical_cell_addr(5);
    let read = probe_clean(&mut b, 5, INSTALL_ID);
    match &read {
        FreshQwRead::Clean(qw) => {
            assert_eq!(qw.index(), 5);
            assert_eq!(qw.addr(), addr);
            assert_eq!(qw.probe_epoch(), 7);
            assert_eq!(qw.bytes(), &INSTALL_ID);
        }
        _ => panic!("expected Clean"),
    }
}
