//! Journal-codec tests: codeword Hamming properties and the probe
//! boundary. The raw codec constructor suites (install-generation,
//! terminal sets) moved to crate-internal unit tests in
//! `rollback/src/journal.rs` when the constructors went `pub(crate)`
//! (R4-1); the canonical orchestrator paths are covered in
//! `acceptance.rs`.

mod common;

use common::*;
use fw_manifest::v6::{QW_CONFIRMED_0, QW_CONFIRMED_1, QW_PENDING};
use pqsigner_rollback::backend::ProbeScript;
use pqsigner_rollback::journal::{exact_marker, PENDING_CODEWORD};
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
