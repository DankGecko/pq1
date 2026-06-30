//! libFuzzer harness for `pqsigner_tx::multisend::decode_multisend` + the
//! `MsRecordIter` per-record walk — the STRICT Safe `multiSend` decoder.
//!
//! This is the shape the Safe web UI emits for any multi-step transaction
//! (selector `0x8d80ff0a`): a DELEGATECALL into `MultiSendCallOnly` whose
//! packed records the firmware clear-signs one-by-one. A decode bug here is
//! the highest-stakes parse on the trusted-display path — a DELEGATECALL is
//! never blind-signed, so every record must decode exactly or the whole tx
//! refuses. The strict outer-frame + per-record framing is adversarial input
//! straight from the (untrusted) companion.
//!
//! Property: must terminate without panic/overflow/OOB and return a `Result`
//! for any input; the inner `MsRecordIter` must likewise yield `Result`s
//! without panicking. Complements the in-crate Kani proofs
//! (`tx/src/multisend.rs` `#[cfg(kani)] mod verification`) by exercising the
//! unbounded/large-input coverage-guided surface.

#![no_main]
use libfuzzer_sys::fuzz_target;
use pqsigner_tx::multisend::{decode_multisend, MsRecordIter};

fuzz_target!(|data: &[u8]| {
    if let Ok(packed) = decode_multisend(data) {
        // Walk every record exactly as the per-record clear-sign ladder does.
        for rec in MsRecordIter::new(packed) {
            let _ = rec;
        }
    }
});
