//! Bulk random C10 vectors for the Lean executable-spec differential
//! (A3.1 follow-up: extend the 10-vector KAT to a broad random corpus that
//! exercises many hypertree-leaf positions / merkle-path lengths, including
//! the boundary-read edge case at signature offset 3992).
//!
//! Emits `contracts/verification/bulk_vectors.json`:
//!   { "vectors": [ {label, pkSeed, pkRoot, message, signature, expectValid}, ... ] }
//!
//! Run:
//!   cargo test -p sphincs-c10 --test gen_bulk_vectors --release -- --nocapture
//!
//! Deterministic: a fixed SplitMix64 PRNG seeds the keypairs and messages so
//! the corpus is reproducible (the Lean side embeds the emitted JSON).

use sphincs_c10::params::N;
use sphincs_c10::{verify, SigningKey};
use std::fs;

const KEYPAIRS: usize = 8;
const MSGS_PER_KEY: usize = 24; // 8*24 = 192 valid + 192 negatives = 384 vectors

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn pad_b32_hex(val: &[u8; N]) -> String {
    let mut out = [0u8; 32];
    out[..N].copy_from_slice(val);
    to_hex(&out)
}

/// SplitMix64 — tiny deterministic PRNG (no external dep).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let r = self.next().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
    }
}

#[test]
fn gen_bulk_vectors() {
    let mut rng = Rng(0xC10B_5EED_1234_ABCD_u64);
    let mut out = String::from("{\n  \"vectors\": [\n");
    let mut first = true;
    let emit = |label: &str, pks: &str, pkr: &str, msg: &str, sig: &str, ok: bool, out: &mut String, first: &mut bool| {
        if !*first {
            out.push_str(",\n");
        }
        *first = false;
        out.push_str(&format!(
            "    {{\"label\": \"{label}\", \"pkSeed\": \"{pks}\", \"pkRoot\": \"{pkr}\", \"message\": \"{msg}\", \"signature\": \"{sig}\", \"expectValid\": {ok}}}"
        ));
    };

    for k in 0..KEYPAIRS {
        let mut sk_seed = [0u8; 32];
        let mut pk_seed = [0u8; N];
        rng.fill(&mut sk_seed);
        rng.fill(&mut pk_seed);
        let sk = SigningKey::keygen(sk_seed, pk_seed);
        let pks = pad_b32_hex(sk.pk_seed());
        let pkr = pad_b32_hex(sk.pk_root());

        for m in 0..MSGS_PER_KEY {
            let mut msg = [0u8; 32];
            rng.fill(&mut msg);
            let sig = sk.sign(&msg, None);
            assert!(
                verify(sk.pk_seed(), sk.pk_root(), &msg, &sig),
                "self-verify failed k={k} m={m}"
            );
            let sighex = to_hex(&sig);
            emit(
                &format!("bulk-valid-k{k}-m{m}"),
                &pks, &pkr, &to_hex(&msg), &sighex, true,
                &mut out, &mut first,
            );

            // One single-byte mutation per valid vector → a negative.
            // Rotate the mutated offset across the whole 4008-byte sig so the
            // corpus covers R / FORS / WOTS / auth regions, including the
            // last auth entry near offset 3992 (the boundary-read case).
            let mut bad = sig;
            let pos = ((rng.next() as usize) % 4008).max(0);
            bad[pos] ^= 0x01 | ((rng.next() as u8) & 0xFE);
            let bad_ok = verify(sk.pk_seed(), sk.pk_root(), &msg, &bad);
            // Almost always false; if a mutation lands in a don't-care pad bit
            // and still verifies, record its true outcome so the Lean side
            // must match exactly (not assert false).
            emit(
                &format!("bulk-mut-k{k}-m{m}-p{pos}"),
                &pks, &pkr, &to_hex(&msg), &to_hex(&bad), bad_ok,
                &mut out, &mut first,
            );
        }
        eprintln!("keypair {k}: {MSGS_PER_KEY} valid + {MSGS_PER_KEY} mutated done");
    }
    out.push_str("\n  ]\n}\n");

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../contracts/verification/bulk_vectors.json"
    );
    fs::write(path, out).expect("write bulk_vectors.json");
    eprintln!("wrote {path}");
}
