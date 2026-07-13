//! One-off corpus seeder for the `erc7730_render_dispatch` fuzz target.
//!
//! `erc7730_render_dispatch` drives the FULL ERC-7730 render (parse →
//! `find_format_by_selector` → per-`FormatOp` field render → `Pages` emission).
//! Its highest-value code — the field formatters — is only reached once a
//! descriptor actually PARSES, and a random byte string parses into a rich IR
//! essentially never. So this test compiles the real vendored ERC-7730 registry
//! into its IR leaves and writes each as a corpus seed, giving libFuzzer valid
//! descriptors to mutate from (the `#[ignore]` keeps it out of the normal
//! `cargo test` pass — it writes files and is slow).
//!
//! Run it before fuzzing:
//! ```text
//!   cargo test --test gen_render_seeds -- --ignored --nocapture
//!   cargo +nightly fuzz run erc7730_render_dispatch
//! ```
//! (`make fuzz-seed-erc7730-render` wraps the first line.)
//!
//! The fuzz input is `[u16 ir_len BE][ir_bytes][payload]`; the render loop
//! dispatches each format with its OWN contract selector / EIP-712 type hash.
//! The separate payload is deliberately nonempty so libFuzzer can mutate
//! calldata/envelope bytes while leaving the valid descriptor intact. The
//! harness derives both arbitrary-length and canonical static/string/array
//! frames from this entropy so exact-framing preflight does not make the corpus
//! vacuous.

use std::path::PathBuf;

#[test]
#[ignore = "corpus seeder — writes files, run explicitly before fuzzing"]
fn gen_render_dispatch_seeds() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ws = manifest.parent().expect("fuzz/ lives under workspace root");
    let reg = ws.join("secure/data/erc7730-registry");
    let policy = ws.join("secure/data/erc7730/policy.toml");

    let (res, _skips) =
        dbgen::erc7730::build_db_tolerant(&reg.join("registry"), &policy, Some(&reg))
            .expect("compile the ERC-7730 registry");

    let corpus = std::env::var_os("PQSIGNER_ERC7730_RENDER_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("corpus/erc7730_render_dispatch"));
    std::fs::create_dir_all(&corpus).expect("create corpus dir");
    // Catalogue shrinkage is expected when a new fail-closed compiler gate
    // rejects unsafe formats. Remove only our deterministic generated seeds so
    // stale leaves do not survive indefinitely and distort the next campaign;
    // preserve every hand-authored/non-matching corpus entry. The optional
    // output override lets tests exercise this cleanup in a disposable path.
    for entry in std::fs::read_dir(&corpus).expect("read corpus dir") {
        let entry = entry.expect("read corpus entry");
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("seed_leaf_"))
        {
            std::fs::remove_file(entry.path()).expect("remove stale generated seed");
        }
    }

    let mut written = 0usize;
    for entry in &res.entries {
        let ir_len: u16 = entry
            .ir_bytes
            .len()
            .try_into()
            .expect("IR length fits the fuzz framing");
        let mut buf = Vec::with_capacity(2 + entry.ir_bytes.len() + 64 * 32);
        buf.extend_from_slice(&ir_len.to_be_bytes());
        buf.extend_from_slice(&entry.ir_bytes);
        // 64 words with a leaf-specific nonuniform pattern. The harness uses
        // these as independent entropy for contract calldata, EIP-712
        // encoded_data, canonical dynamic tails, and framing lengths.
        for i in 0..64 * 32 {
            buf.push(
                (i as u8)
                    .wrapping_mul(131)
                    .wrapping_add(entry.leaf_index as u8),
            );
        }
        let path = corpus.join(format!("seed_leaf_{:04}", entry.leaf_index));
        std::fs::write(&path, &buf).expect("write seed");
        written += 1;
    }
    eprintln!(
        "wrote {written} render-dispatch seeds ({} leaves) to {}",
        res.entries.len(),
        corpus.display()
    );
    assert!(written > 0, "registry produced no IR leaves to seed from");
}
