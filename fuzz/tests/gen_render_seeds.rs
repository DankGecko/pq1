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
//! The fuzz input is `[4 sel_a][4 sel_b][ir_bytes]`; the render loop dispatches
//! each format with its OWN 4-byte selector, so the 8 prefix bytes are
//! don't-cares here — the value is the valid `ir_bytes` tail.

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

    let corpus = manifest.join("corpus/erc7730_render_dispatch");
    std::fs::create_dir_all(&corpus).expect("create corpus dir");

    let mut written = 0usize;
    for entry in &res.entries {
        let mut buf = vec![0u8; 8]; // sel_a || sel_b (don't-cares)
        buf.extend_from_slice(&entry.ir_bytes);
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
