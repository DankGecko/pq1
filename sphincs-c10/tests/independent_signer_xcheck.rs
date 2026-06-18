//! Cross-implementation differential (A3.1 independent-source KAT leg, work-todo #7).
//!
//! The INDEPENDENT clean-room Python C10 signer
//! (`contracts/verification/scripts/independent_c10_signer.py`) — written from the
//! deployed `SPHINCsC10Asm.sol` verifier + the documented PRF preimages, NOT
//! transliterated from this Rust crate — must produce signatures that THIS crate's
//! `verify` accepts, on FRESH (non-KAT) messages.
//!
//! This is the genuine independence guard: the Python self-test already reproduces
//! the 4 Rust-generated KAT vectors byte-for-byte (independent SIGN == Rust SIGN),
//! but that round-trips through the Python verifier. Here the EXISTING Rust verifier
//! checks fresh Python-signer output, so a hypothetical bug shared by the Python
//! sign+verify pair (but absent from the Rust verifier and the deployed Yul) is
//! caught. Honest scope: implementation diversity over the SHARED C10 spec, not a
//! second spec.
//!
//! Requires `python3` on PATH (as do the other `contracts/verification` make targets).
//! Run: `cargo test -p sphincs-c10 --test independent_signer_xcheck --release`.

use sphincs_c10::params::{N, SIGNATURE_LEN};
use sphincs_c10::verify;
use std::process::Command;

fn hexdec(s: &str) -> Vec<u8> {
    hex::decode(s.trim().trim_start_matches("0x")).expect("valid hex")
}

#[test]
fn independent_python_signer_output_accepted_by_rust_verifier() {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/verification/scripts/independent_c10_signer.py"
    );
    // Fresh, non-KAT 32-byte messages (distinct from gen_test_vectors.rs):
    //   b"PQSigner C10 xcheck vector ONE!!" and b"...TWO!!".
    let messages = [
        "0x50515369676e6572204331302078636865636b20766563746f72204f4e452121",
        "0x50515369676e6572204331302078636865636b20766563746f722054574f2121",
    ];

    for msg_hex in messages {
        let out = Command::new("python3")
            .args([script, "--emit-fields", msg_hex])
            .output()
            .expect("run independent python signer (python3 must be installed)");
        assert!(
            out.status.success(),
            "independent python signer failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = String::from_utf8(out.stdout).expect("utf8 output");
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "expected `pkSeed pkRoot msg sig`, got: {line}");

        let pk_seed = hexdec(fields[0]);
        let pk_root = hexdec(fields[1]);
        let msg = hexdec(fields[2]);
        let sig = hexdec(fields[3]);
        assert_eq!(pk_seed.len(), N);
        assert_eq!(pk_root.len(), N);
        assert_eq!(msg.len(), 32);
        assert_eq!(sig.len(), SIGNATURE_LEN);

        let pk_seed: [u8; N] = pk_seed.try_into().unwrap();
        let pk_root: [u8; N] = pk_root.try_into().unwrap();
        let msg: [u8; 32] = msg.try_into().unwrap();
        let sig: [u8; SIGNATURE_LEN] = sig.try_into().unwrap();

        assert!(
            verify(&pk_seed, &pk_root, &msg, &sig),
            "Rust verifier REJECTED the independent Python signer's output for {msg_hex} \
             — the two independent C10 implementations diverge"
        );
    }
}
