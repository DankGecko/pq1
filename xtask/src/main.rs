//! `pqsigner-xtask` — host-side codegen and tooling.
//!
//! See `Cargo.toml` for the design rationale. Subcommands (run `xtask help`):
//!   * `gen-solidity-constants` — render the Solidity `PqsignerProto` library
//!     from the public constants in `pqsigner-proto`.
//!   * `gen-erc7730-descriptors` — compile + Merkle-anchor the ERC-7730 catalog.
//!   * `scan-registry` / `build-registry` — read-only upstream-registry coverage
//!     probes (how much PQ1 can clear-sign; what the full corpus builds to).
//!   * `vendor-registry` — vendor the complete security-relevant registry JSON
//!     corpus and verify both render leaves and refused-call coverage.
//! The `gen-*` commands take `--check` (rebuild-in-memory + drift-diff) for CI.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use pqsigner_proto as proto;
use sha2::{Digest, Sha256};

const SOLIDITY_OUT_PATH: &str = "contracts/smart-wallet/src/generated/PqsignerProto.sol";
const ERC7730_VENDOR_MARKER: &str = ".pqsigner-erc7730-vendor";
const ERC7730_VENDOR_MARKER_BYTES: &[u8] =
    b"PQSigner ERC-7730 tool-managed registry/ and ercs/ directories.\n";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let subcmd = args.first().map(String::as_str).unwrap_or("");

    match subcmd {
        "gen-solidity-constants" => cmd_gen_solidity_constants(&args[1..]),
        "gen-erc7730-descriptors" => cmd_gen_erc7730_descriptors(&args[1..]),
        "scan-registry" => cmd_scan_registry(&args[1..]),
        "build-registry" => cmd_build_registry(&args[1..]),
        "vendor-registry" => cmd_vendor_registry(&args[1..]),
        "" | "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("error: unknown subcommand `{other}`");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "pqsigner-xtask — host-side workspace tooling

Subcommands:
  gen-solidity-constants [--check]
      Render `{SOLIDITY_OUT_PATH}` from `pqsigner-proto`.
      With --check: print the rendered output to stdout instead of
      writing the file (used by CI to diff against the checked-in copy).

  gen-erc7730-descriptors [--check]
                          [--input-dir PATH] [--policy PATH]
                          [--out-binary PATH] [--out-review PATH]
                          [--e2e-input-dir PATH] [--e2e-out-binary PATH]
      Compile the production ERC-7730 catalogue from
      `secure/data/erc7730-registry/registry` plus
      `secure/data/erc7730-registry/ercs`, and the E2E catalogue from
      `secure/data/erc7730-e2e`, against `secure/data/erc7730/policy.toml`.
      Build their Merkle trees and emit:
        tools/companion-stub/erc7730_db.bin
        tools/companion-stub/erc7730_db_e2e.bin
        secure/data/erc7730.review.txt
        secure/data/erc7730-known-calls.bloom
        secure/data/erc7730-known-calls-e2e.bloom
      With --check: rebuild in-memory and compare against the checked-in
      artifacts; exit non-zero on drift. `secure/src/db_roots.rs` is
      validation-only here and is regenerated with `cargo run -p dbgen`.

  scan-registry [--registry-root PATH] [--input PATH] [--policy PATH]
                [--report PATH]
      Read-only coverage probe: tolerantly compile every descriptor under
      the upstream registry through the on-device pipeline and tally how
      many PQ1 can clear-sign today vs. skipped-and-why. Writes nothing
      into the firmware corpus.

  build-registry [--registry-root PATH] [--input PATH] [--policy PATH]
                 [--report PATH]
      Build the full upstream registry via `build_db_tolerant` (the corpus
      switch) and report leaf count, root, and skips. Read-only: does NOT
      overwrite the firmware-pinned root.

  vendor-registry [--registry-root PATH] [--out PATH] [--policy PATH]
      Scan every `registry/**/*.json` and `ercs/**/*.json` file. Vendor the
      production corpus into `secure/data/erc7730-registry/` while excluding
      upstream test fixtures after validating and receipting them. Then VERIFY
      byte-identical compiled catalogue/review output plus the exact known-call
      tuple-set receipt and Bloom filter. Merkle-root equality alone does not
      prove that unsupported calls remained covered by the fail-closed omission
      filter.

  help
      Print this message.
"
    );
}

fn cmd_gen_solidity_constants(args: &[String]) -> ExitCode {
    let check_mode = args.iter().any(|a| a == "--check");
    let rendered = render_solidity_library();

    if check_mode {
        // CI uses this output for `diff /tmp/expected.sol <checked-in>`.
        print!("{rendered}");
        return ExitCode::SUCCESS;
    }

    let out_path = workspace_root().join(SOLIDITY_OUT_PATH);

    if let Some(parent) = out_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("error: cannot create {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
    }

    if let Err(e) = fs::write(&out_path, &rendered) {
        eprintln!("error: cannot write {}: {e}", out_path.display());
        return ExitCode::FAILURE;
    }

    eprintln!("wrote {}", out_path.display());
    ExitCode::SUCCESS
}

/// Workspace root, derived from `CARGO_MANIFEST_DIR` (which points at
/// `<workspace>/xtask` when invoked via `cargo run -p pqsigner-xtask`).
/// Falls back to the current directory if the env var is missing — that
/// keeps the binary usable when run outside Cargo (manual invocation,
/// debugger, packaged tooling).
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    manifest_dir
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Render the Solidity library text from `pqsigner-proto`'s public
/// constants. Pure function — same input ⇒ same output, byte-for-byte.
fn render_solidity_library() -> String {
    let mut s = String::with_capacity(2 * 1024);

    s.push_str("// SPDX-License-Identifier: MIT\n");
    s.push_str("// AUTO-GENERATED — DO NOT EDIT.\n");
    s.push_str("// Source of truth: `pqsigner-proto` crate (Rust).\n");
    s.push_str("// Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`.\n");
    s.push_str("//\n");
    s.push_str("// Reference: /home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md\n");
    s.push_str("// Phase 4 of the modularity refactor.\n");
    s.push_str("pragma solidity ^0.8.28;\n");
    s.push('\n');
    s.push_str("/// @notice Cross-language protocol constants shared by the firmware\n");
    s.push_str("///         (Rust, `pqsigner-proto` crate) and the on-chain wallet.\n");
    s.push_str("///         The firmware is the source of truth — every constant in\n");
    s.push_str("///         this library is generated from a `pub const` in the Rust\n");
    s.push_str("///         crate. CI diffs the generated file against\n");
    s.push_str("///         `pqsigner-xtask gen-solidity-constants --check` so any\n");
    s.push_str("///         drift is caught at PR review.\n");
    s.push_str("library PqsignerProto {\n");

    section_header(&mut s, "Signature sizes");
    sol_uint256(&mut s, "C10_SIG_LEN", proto::C10_SIG_LEN as u128);
    let padded_inner = padded_to_32(proto::C10_SIG_LEN as u128);
    sol_uint256_with_doc(
        &mut s,
        "SIG_WRAPPER_LEN",
        // abi.encode(uint256, bytes) head + tail:
        // 32 (ownerIndex) + 32 (offset) + 32 (length) + 32-padded inner sig.
        32 + 32 + 32 + padded_inner,
        "abi.encode(uint256 ownerIndex, bytes innerSig) layout: \
         32 (ownerIndex) + 32 (offset) + 32 (length) + ((C10_SIG_LEN + 31) / 32) * 32",
    );

    section_header(&mut s, "Per-chain usage caps");
    sol_uint256(
        &mut s,
        "MAX_BOOTSTRAP_USES",
        u128::from(proto::MAX_BOOTSTRAP_USES),
    );
    sol_uint256(&mut s, "MAX_SLOT_USES", u128::from(proto::MAX_SLOT_USES));
    sol_uint256(
        &mut s,
        "MAX_OFFCHAIN_GAP",
        u128::from(proto::MAX_OFFCHAIN_GAP),
    );

    section_header(&mut s, "Wallet storage layout");
    sol_uint256(&mut s, "OWNER_BYTES_LEN", proto::OWNER_BYTES_LEN as u128);

    section_header(&mut s, "Selectors");
    sol_bytes4(&mut s, "EXECUTE_SELECTOR", &proto::EXECUTE_SELECTOR);
    sol_bytes4(
        &mut s,
        "EXECUTE_BATCH_SELECTOR",
        &proto::EXECUTE_BATCH_SELECTOR,
    );

    section_header(&mut s, "Domain tags");
    sol_bytes(
        &mut s,
        "FACTORY_ADD_SLOT_DOMAIN",
        proto::FACTORY_ADD_SLOT_DOMAIN,
    );

    s.push_str("}\n");
    s
}

/// Round `v` up to the next multiple of 32 (Solidity ABI word size).
fn padded_to_32(v: u128) -> u128 {
    v.div_ceil(32) * 32
}

fn section_header(s: &mut String, name: &str) {
    s.push('\n');
    let _ = writeln!(s, "    // ─────────────────────────────────────────────");
    let _ = writeln!(s, "    // {name}");
    let _ = writeln!(s, "    // ─────────────────────────────────────────────");
}

fn sol_uint256(s: &mut String, name: &str, value: u128) {
    let _ = writeln!(s, "    uint256 internal constant {name} = {value};");
}

fn sol_uint256_with_doc(s: &mut String, name: &str, value: u128, doc: &str) {
    let _ = writeln!(s, "    /// @dev {doc}");
    let _ = writeln!(s, "    uint256 internal constant {name} = {value};");
}

fn sol_bytes4(s: &mut String, name: &str, bytes: &[u8; 4]) {
    let _ = writeln!(
        s,
        "    bytes4 internal constant {name} = 0x{:02x}{:02x}{:02x}{:02x};",
        bytes[0], bytes[1], bytes[2], bytes[3],
    );
}

/// Render a `bytes` constant. If every byte is printable ASCII (and
/// safe to embed in a Solidity string literal), use a `"..."` literal —
/// otherwise fall back to `hex"..."`. The hex path is defensive: today
/// this codepath only sees domain tags that are printable ASCII by
/// construction.
fn sol_bytes(s: &mut String, name: &str, bytes: &[u8]) {
    if is_solidity_string_safe(bytes) {
        let s_lit = std::str::from_utf8(bytes).expect("ASCII validated above");
        let _ = writeln!(s, "    bytes internal constant {name} = \"{s_lit}\";");
    } else {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(hex, "{b:02x}");
        }
        let _ = writeln!(s, "    bytes internal constant {name} = hex\"{hex}\";");
    }
}

/// Printable ASCII (0x20–0x7E), excluding `"` and `\` which would need
/// escaping inside a Solidity double-quoted string literal.
fn is_solidity_string_safe(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| (0x20..=0x7E).contains(b) && *b != b'"' && *b != b'\\')
}

// ─────────────────────────────────────────────────────────────────────
// gen-erc7730-descriptors
// ─────────────────────────────────────────────────────────────────────

// PROD catalog now sources from the vendored upstream registry (the corpus
// switch); the policy still lives with the hand-authored render-test fixtures.
const ERC7730_DEFAULT_INPUT: &str = "secure/data/erc7730-registry/registry";
const ERC7730_DEFAULT_POLICY: &str = "secure/data/erc7730/policy.toml";
const ERC7730_DEFAULT_E2E_INPUT: &str = "secure/data/erc7730-e2e";
const ERC7730_DEFAULT_OUT: &str = "tools/companion-stub/erc7730_db.bin";
const ERC7730_DEFAULT_E2E_OUT: &str = "tools/companion-stub/erc7730_db_e2e.bin";
const ERC7730_DEFAULT_REVIEW: &str = "secure/data/erc7730.review.txt";
const ERC7730_DEFAULT_KNOWN_CALLS: &str = "secure/data/erc7730-known-calls.bloom";
const ERC7730_DEFAULT_KNOWN_CALLS_E2E: &str = "secure/data/erc7730-known-calls-e2e.bloom";

#[derive(Default)]
struct Erc7730Args {
    check: bool,
    input_dir: Option<PathBuf>,
    policy: Option<PathBuf>,
    out_binary: Option<PathBuf>,
    out_review: Option<PathBuf>,
    e2e_input_dir: Option<PathBuf>,
    e2e_out_binary: Option<PathBuf>,
}

fn parse_erc7730_args(args: &[String]) -> Result<Erc7730Args, String> {
    let mut out = Erc7730Args::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => out.check = true,
            "--input-dir" => {
                i += 1;
                out.input_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--input-dir requires a value")?,
                ));
            }
            "--policy" => {
                i += 1;
                out.policy = Some(PathBuf::from(
                    args.get(i).ok_or("--policy requires a value")?,
                ));
            }
            "--out-binary" => {
                i += 1;
                out.out_binary = Some(PathBuf::from(
                    args.get(i).ok_or("--out-binary requires a value")?,
                ));
            }
            "--out-review" => {
                i += 1;
                out.out_review = Some(PathBuf::from(
                    args.get(i).ok_or("--out-review requires a value")?,
                ));
            }
            "--e2e-input-dir" => {
                i += 1;
                out.e2e_input_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--e2e-input-dir requires a value")?,
                ));
            }
            "--e2e-out-binary" => {
                i += 1;
                out.e2e_out_binary = Some(PathBuf::from(
                    args.get(i).ok_or("--e2e-out-binary requires a value")?,
                ));
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
        i += 1;
    }
    Ok(out)
}

fn cmd_gen_erc7730_descriptors(args: &[String]) -> ExitCode {
    let parsed = match parse_erc7730_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let workspace_root = manifest_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let input_dir = parsed
        .input_dir
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_INPUT));
    let policy = parsed
        .policy
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_POLICY));
    let out_binary = parsed
        .out_binary
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_OUT));
    let out_review = parsed
        .out_review
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_REVIEW));
    let e2e_input_dir = parsed
        .e2e_input_dir
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_E2E_INPUT));
    let e2e_out_binary = parsed
        .e2e_out_binary
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_E2E_OUT));
    let known_calls_out = workspace_root.join(ERC7730_DEFAULT_KNOWN_CALLS);
    let known_calls_e2e_out = workspace_root.join(ERC7730_DEFAULT_KNOWN_CALLS_E2E);

    // Build both prod + e2e catalogs. PROD is the tolerant registry build
    // (the corpus switch) — `input_dir` is `<registry>/registry`, so its parent
    // is the registry root used to resolve `includes`. E2E stays strict.
    let registry_root = input_dir.parent().map(|p| p.to_path_buf());
    let prod =
        match dbgen::erc7730::build_db_tolerant(&input_dir, &policy, registry_root.as_deref()) {
            Ok((r, _skips)) => r,
            Err(e) => {
                eprintln!("error: prod build failed: {e}");
                return ExitCode::FAILURE;
            }
        };
    if let Err(e) = dbgen::erc7730::round_trip_check(&prod) {
        eprintln!("error: prod round-trip failed: {e}");
        return ExitCode::FAILURE;
    }
    let e2e = match dbgen::erc7730::build_db(&e2e_input_dir, &policy) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: e2e build failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = dbgen::erc7730::round_trip_check(&e2e) {
        eprintln!("error: e2e round-trip failed: {e}");
        return ExitCode::FAILURE;
    }

    if parsed.check {
        // CI mode: diff against checked-in artifacts.
        let mut drift = false;
        if let Err(e) = diff_bytes("erc7730_db.bin", &out_binary, &prod.blob) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes("erc7730_db_e2e.bin", &e2e_out_binary, &e2e.blob) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_text("erc7730.review.txt", &out_review, &prod.review_text) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes(
            "erc7730-known-calls.bloom",
            &known_calls_out,
            &prod.known_calls_bloom,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if let Err(e) = diff_bytes(
            "erc7730-known-calls-e2e.bloom",
            &known_calls_e2e_out,
            &e2e.known_calls_bloom,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        // db_roots.rs is owned by `cargo run -p dbgen` (it bakes 5
        // other roots besides ours); only assert that the ERC-7730
        // root line in it matches.
        let roots_path = workspace_root.join("secure/src/db_roots.rs");
        if let Err(e) = diff_root_in_db_roots(
            &roots_path,
            &prod.root,
            prod.leaf_count,
            &e2e.root,
            e2e.leaf_count,
            prod.provenance,
            e2e.provenance,
        ) {
            eprintln!("DRIFT: {e}");
            drift = true;
        }
        if drift {
            eprintln!(
                "\nERC-7730 catalog has drifted from the checked-in artifacts.\n\
                 Run `cargo run -p dbgen` (which writes ALL DBs in one pass) and\n\
                 commit the resulting changes."
            );
            return ExitCode::FAILURE;
        }
        eprintln!("erc7730: in sync");
        return ExitCode::SUCCESS;
    }

    // Write artifacts.
    if let Some(parent) = out_binary.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("error: cannot create {}: {e}", parent.display());
            return ExitCode::FAILURE;
        }
    }
    if let Err(e) = fs::write(&out_binary, &prod.blob) {
        eprintln!("error: write {}: {e}", out_binary.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&e2e_out_binary, &e2e.blob) {
        eprintln!("error: write {}: {e}", e2e_out_binary.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&out_review, &prod.review_text) {
        eprintln!("error: write {}: {e}", out_review.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&known_calls_out, prod.known_calls_bloom) {
        eprintln!("error: write {}: {e}", known_calls_out.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(&known_calls_e2e_out, e2e.known_calls_bloom) {
        eprintln!("error: write {}: {e}", known_calls_e2e_out.display());
        return ExitCode::FAILURE;
    }
    eprintln!(
        "wrote {} ({} bytes, {} leaves, root = {})",
        out_binary.display(),
        prod.blob.len(),
        prod.leaf_count,
        hex::encode(prod.root),
    );
    eprintln!(
        "wrote {} ({} bytes, {} leaves, e2e root = {})",
        e2e_out_binary.display(),
        e2e.blob.len(),
        e2e.leaf_count,
        hex::encode(e2e.root),
    );
    eprintln!(
        "wrote {} ({} known calls)",
        known_calls_out.display(),
        prod.known_call_count,
    );
    eprintln!(
        "wrote {} ({} known calls)",
        known_calls_e2e_out.display(),
        e2e.known_call_count,
    );
    eprintln!("wrote {}", out_review.display());
    eprintln!(
        "note: secure/src/db_roots.rs is owned by `cargo run -p dbgen` — \
         run that to refresh the ERC7730_DESCRIPTORS_ROOT constant."
    );
    ExitCode::SUCCESS
}

fn diff_bytes(label: &str, path: &PathBuf, fresh: &[u8]) -> Result<(), String> {
    let existing =
        fs::read(path).map_err(|e| format!("read {label} at {}: {e}", path.display()))?;
    if existing == fresh {
        return Ok(());
    }
    Err(format!(
        "{label} at {} differs from fresh build ({} vs {} bytes)",
        path.display(),
        existing.len(),
        fresh.len()
    ))
}

fn diff_text(label: &str, path: &PathBuf, fresh: &str) -> Result<(), String> {
    let existing =
        fs::read_to_string(path).map_err(|e| format!("read {label} at {}: {e}", path.display()))?;
    if existing == fresh {
        return Ok(());
    }
    Err(format!(
        "{label} at {} differs from fresh build",
        path.display()
    ))
}

fn diff_root_in_db_roots(
    path: &PathBuf,
    prod_root: &[u8; 32],
    prod_count: usize,
    e2e_root: &[u8; 32],
    e2e_count: usize,
    prod_provenance: dbgen::erc7730::CatalogueProvenance,
    e2e_provenance: dbgen::erc7730::CatalogueProvenance,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read db_roots.rs at {}: {e}", path.display()))?;
    if erc7730_security_tail_matches(
        &text,
        prod_root,
        prod_count,
        e2e_root,
        e2e_count,
        prod_provenance,
        e2e_provenance,
    ) {
        return Ok(());
    }
    let sentinel_count = text
        .matches(dbgen::ERC7730_SECURITY_TAIL_SENTINEL)
        .count();
    Err(format!(
        "ERC-7730 generated security tail in {} does not exactly match the fresh byte-for-byte suffix through EOF (sentinels={sentinel_count}, expected prod root {}, e2e root {}, prod provenance {}, e2e provenance {})",
        path.display(),
        hex::encode(prod_root),
        hex::encode(e2e_root),
        prod_provenance.as_str(),
        e2e_provenance.as_str(),
    ))
}

fn erc7730_security_tail_matches(
    text: &str,
    prod: &[u8; 32],
    prod_count: usize,
    e2e: &[u8; 32],
    e2e_count: usize,
    prod_provenance: dbgen::erc7730::CatalogueProvenance,
    e2e_provenance: dbgen::erc7730::CatalogueProvenance,
) -> bool {
    let expected = dbgen::render_erc7730_security_tail(
        prod,
        prod_count,
        prod_provenance,
        e2e,
        e2e_count,
        e2e_provenance,
    );
    text.matches(dbgen::ERC7730_SECURITY_TAIL_SENTINEL)
        .count()
        == 1
        && text.ends_with(&expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_to_32_rounds_up_to_word_boundary() {
        assert_eq!(padded_to_32(0), 0);
        assert_eq!(padded_to_32(1), 32);
        assert_eq!(padded_to_32(31), 32);
        assert_eq!(padded_to_32(32), 32);
        assert_eq!(padded_to_32(33), 64);
        assert_eq!(padded_to_32(4008), 4032);
    }

    #[test]
    fn solidity_string_safe_accepts_printable_ascii() {
        assert!(is_solidity_string_safe(b"hello-world_1"));
        assert!(is_solidity_string_safe(b"PQSigner-FactoryAddSlot-v1"));
        assert!(is_solidity_string_safe(b""));
    }

    #[test]
    fn solidity_string_safe_rejects_unsafe_bytes() {
        assert!(!is_solidity_string_safe(b"contains\"quote"));
        assert!(!is_solidity_string_safe(b"contains\\backslash"));
        assert!(!is_solidity_string_safe(&[0x1f])); // below 0x20
        assert!(!is_solidity_string_safe(&[0x7f])); // above 0x7E
        assert!(!is_solidity_string_safe(&[0xff])); // non-ASCII
    }

    #[test]
    fn sol_bytes_emits_string_literal_for_ascii() {
        let mut s = String::new();
        sol_bytes(&mut s, "TAG", b"abc");
        assert_eq!(s, "    bytes internal constant TAG = \"abc\";\n");
    }

    #[test]
    fn sol_bytes_emits_hex_literal_for_non_ascii() {
        let mut s = String::new();
        sol_bytes(&mut s, "TAG", &[0x00, 0xff, 0x10]);
        assert_eq!(s, "    bytes internal constant TAG = hex\"00ff10\";\n");
    }

    #[test]
    fn sol_bytes4_emits_lowercase_hex() {
        let mut s = String::new();
        sol_bytes4(&mut s, "SEL", &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(s, "    bytes4 internal constant SEL = 0xdeadbeef;\n");
    }

    #[test]
    fn sol_uint256_emits_decimal() {
        let mut s = String::new();
        sol_uint256(&mut s, "N", 65_536);
        assert_eq!(s, "    uint256 internal constant N = 65536;\n");
    }

    #[test]
    fn erc7730_codegen_requires_the_complete_exact_security_suffix() {
        use dbgen::erc7730::CatalogueProvenance::DevUnattested;

        let prod = [0x11u8; 32];
        let e2e = [0x22u8; 32];
        let prod_count = 17;
        let e2e_count = 3;
        let tail = dbgen::render_erc7730_security_tail(
            &prod,
            prod_count,
            DevUnattested,
            &e2e,
            e2e_count,
            DevUnattested,
        );
        assert_eq!(
            tail.matches("extern crate core as __pqsigner_erc7730_core;")
                .count(),
            1
        );
        assert_eq!(
            tail.matches("self::__pqsigner_erc7730_core::include_bytes!")
                .count(),
            2
        );
        assert_eq!(
            tail.matches("self::__pqsigner_erc7730_core::compile_error!")
                .count(),
            3
        );
        assert!(
            !tail.lines().any(|line| line.starts_with("include_bytes!"))
                && !tail.lines().any(|line| line.starts_with("compile_error!")),
            "generated security macros must resolve through the collision-sensitive core alias"
        );
        let correct = format!("pub static SELECTOR_DB_ROOT: [u8; 32] = [0; 32];\n\n{tail}");
        assert!(erc7730_security_tail_matches(
            &correct,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            DevUnattested,
        ));

        let swapped_roots = dbgen::render_erc7730_security_tail(
            &e2e,
            e2e_count,
            DevUnattested,
            &prod,
            prod_count,
            DevUnattested,
        );
        assert!(!erc7730_security_tail_matches(
            &swapped_roots,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            DevUnattested,
        ));

        let swapped_filters = tail
            .replace("erc7730-known-calls-e2e.bloom", "TEMP_FILTER")
            .replace("erc7730-known-calls.bloom", "erc7730-known-calls-e2e.bloom")
            .replace("TEMP_FILTER", "erc7730-known-calls.bloom");
        assert!(!erc7730_security_tail_matches(
            &swapped_filters,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            DevUnattested,
        ));

        let deleted_fence = tail.replacen(
            "compile_error!(\"mode-production cannot embed the dev-unattested ERC-7730 catalogue.",
            "compile_error!(\"disabled: mode-production cannot embed the dev-unattested ERC-7730 catalogue.",
            1,
        );
        assert!(!erc7730_security_tail_matches(
            &deleted_fence,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            DevUnattested,
        ));

        // This is the concrete false-green that defeated the old lexical
        // marker scan: the expected root bytes remained in Rust code but the
        // effective cfg disabled them. Exact-tail comparison rejects any
        // attribute inserted between the inert anchor and a protected item.
        let cfg_disabled_root = tail.replacen(
            "#[cfg(not(feature = \"e2e-test\"))]\npub static ERC7730_DESCRIPTORS_ROOT",
            "#[cfg(any())]\n#[cfg(not(feature = \"e2e-test\"))]\npub static ERC7730_DESCRIPTORS_ROOT",
            1,
        );
        assert!(!erc7730_security_tail_matches(
            &cfg_disabled_root,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            DevUnattested,
            DevUnattested,
        ));

        let block_commented = format!("/*\n{tail}\n*/");
        let raw_string = format!("const _: &str = r###\"{tail}\"###;");
        let enclosed = format!("#[cfg(any())]\nmod disabled {{\n{tail}}}\n");
        for forged in [&block_commented, &raw_string, &enclosed] {
            assert!(!erc7730_security_tail_matches(
                forged,
                &prod,
                prod_count,
                &e2e,
                e2e_count,
                DevUnattested,
                DevUnattested,
            ));
        }
    }

    #[test]
    fn erc7730_generated_core_alias_defeats_extern_prelude_shadowing() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        // `::core::compile_error!` is NOT intrinsically unshadowable: a prefix
        // can rebind `core` to this crate and re-export a no-op macro. The
        // generated suffix instead imports the real crate under a unique local
        // name. A hostile prefix cannot predeclare that name without a
        // duplicate-item error, and cannot redirect this path.
        let source = r#"
extern crate self as core;
macro_rules! compile_error { ($message:literal) => {} }
pub(crate) use compile_error;

mod generated_suffix {
    pub const ERC7730_GENERATED_SECURITY_TAIL_ANCHOR: () = ();
    extern crate core as __pqsigner_erc7730_core;
    self::__pqsigner_erc7730_core::compile_error!("real generated fence fired");
}
"#;
        let temp = tempfile::tempdir().expect("create rustc output directory");
        let metadata = temp.path().join("core-alias-test.rmeta");
        let mut child = Command::new("rustc")
            .args(["--edition=2021", "--crate-type=lib", "--emit=metadata", "-"])
            .arg("-o")
            .arg(&metadata)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rustc for generated-core-alias regression");
        child
            .stdin
            .take()
            .expect("rustc stdin")
            .write_all(source.as_bytes())
            .expect("write rustc source");
        let output = child.wait_with_output().expect("wait for rustc");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "hostile prefix suppressed fence");
        assert!(
            stderr.contains("real generated fence fired"),
            "failure did not come from the real core macro: {stderr}"
        );
    }

    #[test]
    fn erc7730_codegen_verified_provenance_is_also_exact() {
        use dbgen::erc7730::CatalogueProvenance::Erc8176Verified;

        let prod = [0x33u8; 32];
        let e2e = [0x44u8; 32];
        let prod_count = 23;
        let e2e_count = 5;
        let correct = dbgen::render_erc7730_security_tail(
            &prod,
            prod_count,
            Erc8176Verified,
            &e2e,
            e2e_count,
            Erc8176Verified,
        );
        assert!(erc7730_security_tail_matches(
            &correct,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            Erc8176Verified,
            Erc8176Verified,
        ));
        let altered = correct.replacen(
            "feature = \"erc7730-dev-unattested\"",
            "not(feature = \"erc7730-dev-unattested\")",
            1,
        );
        assert!(!erc7730_security_tail_matches(
            &altered,
            &prod,
            prod_count,
            &e2e,
            e2e_count,
            Erc8176Verified,
            Erc8176Verified,
        ));
    }

    #[test]
    fn vendor_install_second_move_failure_restores_both_prior_directories() {
        let temp = tempfile::tempdir().expect("create vendor rollback test directory");
        let root = temp.path();
        let out = root.join("installed");
        let staging = root.join("staging");
        fs::create_dir_all(out.join("registry")).unwrap();
        fs::create_dir_all(out.join("ercs")).unwrap();
        fs::create_dir_all(staging.join("registry")).unwrap();
        fs::write(out.join("registry/old.json"), b"old registry").unwrap();
        fs::write(out.join("ercs/old.json"), b"old ercs").unwrap();
        fs::write(staging.join("registry/new.json"), b"new registry").unwrap();
        // Intentionally omit staging/ercs so the second new-directory rename
        // fails after the first succeeded.

        let error = install_vendored_subdirs(&staging, &out).unwrap_err();
        assert!(
            error.contains("checked rollback restored the prior corpus"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(out.join("registry/old.json")).unwrap(), b"old registry");
        assert_eq!(fs::read(out.join("ercs/old.json")).unwrap(), b"old ercs");
        assert!(!out.join("registry/new.json").exists());
        assert_eq!(
            fs::read(staging.join("registry/new.json")).unwrap(),
            b"new registry"
        );
        assert!(
            fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .contains(".vendor-backup-")),
            "successful rollback must not leave a backup"
        );
    }

    #[test]
    fn excluded_fixture_domain_only_eip712_binding_is_rejected() {
        let temp = tempfile::tempdir().expect("create excluded-fixture test directory");
        let root = temp.path();
        let fixture = root.join("domain.tests.json");
        fs::write(
            &fixture,
            br#"{
  "context": {
    "eip712": {
      "deployments": [],
      "domain": {
        "chainId": 1,
        "verifyingContract": "0x0000000000000000000000000000000000000001"
      }
    }
  }
}"#,
        )
        .unwrap();

        let error = validate_excluded_vendor_fixture(&fixture).unwrap_err();
        assert!(
            error.contains("fully-specified EIP-712 domain binding"),
            "unexpected error: {error}"
        );
    }

    /// Guard against accidental drift in the rendered output. The rendered
    /// library is checked into `contracts/smart-wallet/src/generated/`
    /// and CI diffs it on every PR; this test catches drift before CI does.
    #[test]
    fn rendered_library_matches_checked_in_solidity() {
        let rendered = render_solidity_library();

        // Structural invariants we never want to lose.
        assert!(rendered.starts_with("// SPDX-License-Identifier: MIT\n"));
        assert!(rendered.contains("library PqsignerProto {"));
        assert!(rendered.ends_with("}\n"));

        // Every public constant from `pqsigner-proto` must surface.
        for name in [
            "C10_SIG_LEN",
            "SIG_WRAPPER_LEN",
            "MAX_BOOTSTRAP_USES",
            "MAX_SLOT_USES",
            "MAX_OFFCHAIN_GAP",
            "OWNER_BYTES_LEN",
            "EXECUTE_SELECTOR",
            "EXECUTE_BATCH_SELECTOR",
            "FACTORY_ADD_SLOT_DOMAIN",
        ] {
            assert!(rendered.contains(name), "missing constant {name}");
        }

        // The wrapper-size arithmetic must match the spec.
        let expected_wrapper = 32 + 32 + 32 + padded_to_32(proto::C10_SIG_LEN as u128);
        assert!(rendered.contains(&format!(
            "uint256 internal constant SIG_WRAPPER_LEN = {expected_wrapper};"
        )));
    }

    // ─────────────────────────────────────────────────────────────────
    //                       POSITIVE — extended
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn positive_padded_to_32_handles_protocol_relevant_values() {
        // C10_SIG_LEN = 4008 → 4032 (used in SIG_WRAPPER_LEN).
        assert_eq!(padded_to_32(4008), 4032);
        // The EIP-6492 blob is 8608 bytes — already 32-aligned, must
        // round to itself, not the next word.
        assert_eq!(padded_to_32(8608), 8608);
        // Exact multiples must be unchanged.
        assert_eq!(padded_to_32(64), 64);
        assert_eq!(padded_to_32(96), 96);
        // One byte past a multiple must jump exactly one word up.
        assert_eq!(padded_to_32(65), 96);
        assert_eq!(padded_to_32(97), 128);
    }

    #[test]
    fn positive_render_library_is_deterministic() {
        // Pure-function contract: same input ⇒ same output, every time.
        // CI relies on this for the `--check` diff to be stable across
        // re-invocations.
        let a = render_solidity_library();
        let b = render_solidity_library();
        let c = render_solidity_library();
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn positive_render_library_emits_pragma_and_header() {
        let s = render_solidity_library();
        assert!(s.contains("pragma solidity ^0.8.28;"));
        assert!(s.contains("AUTO-GENERATED — DO NOT EDIT."));
        assert!(s.contains("Source of truth: `pqsigner-proto` crate (Rust)."));
    }

    #[test]
    fn positive_section_header_format_is_exact() {
        let mut s = String::new();
        section_header(&mut s, "Hello");
        let expected = "\n    // \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\n    // Hello\n    // \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\n";
        assert_eq!(s, expected);
    }

    #[test]
    fn positive_sol_uint256_with_doc_emits_doc_then_const() {
        let mut s = String::new();
        sol_uint256_with_doc(&mut s, "N", 42, "the answer");
        assert_eq!(
            s,
            "    /// @dev the answer\n    uint256 internal constant N = 42;\n"
        );
    }

    #[test]
    fn positive_sol_uint256_emits_zero_and_large_values() {
        let mut s = String::new();
        sol_uint256(&mut s, "Z", 0);
        assert_eq!(s, "    uint256 internal constant Z = 0;\n");

        let mut s = String::new();
        sol_uint256(&mut s, "BIG", u128::MAX);
        assert_eq!(
            s,
            format!("    uint256 internal constant BIG = {};\n", u128::MAX),
        );
    }

    #[test]
    fn positive_sol_bytes4_zero_and_max() {
        let mut s = String::new();
        sol_bytes4(&mut s, "ZERO", &[0, 0, 0, 0]);
        assert_eq!(s, "    bytes4 internal constant ZERO = 0x00000000;\n");

        let mut s = String::new();
        sol_bytes4(&mut s, "MAX", &[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(s, "    bytes4 internal constant MAX = 0xffffffff;\n");
    }

    #[test]
    fn positive_sol_bytes_empty_emits_string_literal() {
        let mut s = String::new();
        sol_bytes(&mut s, "EMPTY", b"");
        assert_eq!(s, "    bytes internal constant EMPTY = \"\";\n");
    }

    #[test]
    fn positive_sol_bytes_uses_string_literal_for_real_domain_tag() {
        let mut s = String::new();
        sol_bytes(&mut s, "T", b"pqwallet-factory-add-slot");
        assert_eq!(
            s,
            "    bytes internal constant T = \"pqwallet-factory-add-slot\";\n"
        );
    }

    #[test]
    fn positive_is_solidity_string_safe_accepts_full_printable_range() {
        // 0x20 (space) through 0x7E (~), excluding " and \.
        for b in 0x20u8..=0x7Eu8 {
            if b == b'"' || b == b'\\' {
                continue;
            }
            assert!(
                is_solidity_string_safe(&[b]),
                "printable byte 0x{b:02x} must be accepted",
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────
    //                       NEGATIVE — adversarial
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn negative_is_solidity_string_safe_rejects_every_control_byte() {
        // Every byte 0x00–0x1F is a control char that would either
        // break a Solidity string literal (e.g. CR/LF/tab inside "...")
        // or render as invisible/garbage in the on-chain source. The
        // generator must always force hex"..." encoding for these.
        for b in 0u8..0x20 {
            assert!(
                !is_solidity_string_safe(&[b]),
                "control byte 0x{b:02x} must be rejected — would corrupt the rendered Solidity",
            );
        }
        // DEL (0x7F) and everything above must also be rejected.
        assert!(!is_solidity_string_safe(&[0x7F]));
    }

    #[test]
    fn negative_is_solidity_string_safe_rejects_quote_and_backslash_within_text() {
        // Single unsafe byte inside otherwise-safe text MUST trip the
        // check; otherwise the rendered Solidity would have an
        // unescaped quote or backslash and fail to compile (or worse,
        // alter the constant's value).
        assert!(!is_solidity_string_safe(b"safe\"quote"));
        assert!(!is_solidity_string_safe(b"safe\\back"));
        assert!(!is_solidity_string_safe(b"\""));
        assert!(!is_solidity_string_safe(b"\\"));
        // Quote/backslash at every position is rejected.
        assert!(!is_solidity_string_safe(b"\"hello"));
        assert!(!is_solidity_string_safe(b"hello\""));
        assert!(!is_solidity_string_safe(b"\\hello"));
        assert!(!is_solidity_string_safe(b"hello\\"));
    }

    #[test]
    fn negative_is_solidity_string_safe_rejects_every_non_ascii_byte() {
        for b in 0x80u8..=0xFFu8 {
            assert!(
                !is_solidity_string_safe(&[b]),
                "non-ASCII byte 0x{b:02x} must be rejected",
            );
        }
    }

    #[test]
    fn negative_sol_bytes_picks_hex_when_input_contains_any_unsafe_byte() {
        // A single 0xff inside otherwise-ASCII payload must force the
        // hex encoding path. A regression would emit an unescaped
        // 0xff inside a string literal, breaking Solidity parsing.
        let mut s = String::new();
        sol_bytes(&mut s, "T", b"hello\xffworld");
        assert!(
            s.starts_with("    bytes internal constant T = hex\""),
            "any unsafe byte must force hex encoding, got: {s}",
        );
        assert!(s.contains("68656c6c6fff776f726c64"));
    }

    /// CLAUDE.md invariant #7: per-chain caps are monotonic and
    /// unresettable. The same numeric values are baked into the
    /// `PQMultiOwnable` storage checks and the rendered Solidity
    /// library; if they drift in `pqsigner-proto`, every consumer
    /// (firmware + on-chain wallet) breaks silently. This test fires
    /// the moment anyone moves them.
    #[test]
    fn negative_proto_caps_match_frozen_on_chain_values() {
        assert_eq!(
            proto::MAX_BOOTSTRAP_USES,
            65_536,
            "MAX_BOOTSTRAP_USES drift — see CLAUDE.md invariant #7",
        );
        assert_eq!(
            proto::MAX_SLOT_USES,
            65_536,
            "MAX_SLOT_USES drift — see CLAUDE.md invariant #7",
        );
        assert_eq!(
            proto::MAX_OFFCHAIN_GAP,
            100,
            "MAX_OFFCHAIN_GAP drift — see CLAUDE.md invariant #9",
        );
    }

    /// `C10_SIG_LEN` is baked into the Yul verifier
    /// (`SPHINCsC10Asm.sol`) AND into every signature wrapper layout
    /// (`SIG_WRAPPER_LEN = 4128`). Drift breaks every signature path.
    #[test]
    fn negative_c10_sig_len_is_frozen_at_4008() {
        assert_eq!(proto::C10_SIG_LEN, 4008);
    }

    /// `OWNER_BYTES_LEN = 64` is the size the on-chain wallet allocates
    /// for each owner entry (`ownerAtIndex`); drifting it would either
    /// truncate slot keys (silent forgery surface) or break ABI decode.
    #[test]
    fn negative_owner_bytes_len_is_frozen_at_64() {
        assert_eq!(proto::OWNER_BYTES_LEN, 64);
    }

    /// `EXECUTE_SELECTOR = keccak256("execute(address,uint256,bytes)")[..4]`
    /// — drift means the firmware emits a calldata prefix the wallet
    /// won't dispatch to, bricking the wallet at the next user tx.
    #[test]
    fn negative_execute_selectors_are_byte_exact() {
        assert_eq!(proto::EXECUTE_SELECTOR, [0x14, 0x44, 0x3c, 0x57]);
        assert_eq!(proto::EXECUTE_BATCH_SELECTOR, [0x7a, 0x38, 0x99, 0x33]);
    }

    /// CLAUDE.md "No casual KDF tag changes." `FACTORY_ADD_SLOT_DOMAIN`
    /// is the domain-separator tag the bootstrap key signs over in
    /// `PQSmartWalletFactory.createAccount`; renaming it invalidates
    /// every already-issued bootstrap signature.
    #[test]
    fn negative_factory_add_slot_domain_tag_is_byte_exact() {
        assert_eq!(proto::FACTORY_ADD_SLOT_DOMAIN, b"pqwallet-factory-add-slot");
        // Length is part of the on-chain hash preimage — pin it.
        assert_eq!(proto::FACTORY_ADD_SLOT_DOMAIN.len(), 25);
    }

    /// `SIG_WRAPPER_LEN` is `abi.encode(uint256 ownerIndex, bytes sig)`
    /// head + tail: 32 (ownerIndex) + 32 (offset) + 32 (length) +
    /// 32-aligned inner sig. For C10 (4008 B → 4032 padded) this is
    /// exactly 4128. Any drift breaks on-chain ABI decoding.
    #[test]
    fn negative_sig_wrapper_len_is_4128_in_rendered_library() {
        let expected = 32u128 + 32 + 32 + padded_to_32(proto::C10_SIG_LEN as u128);
        assert_eq!(expected, 4128, "wrapper arithmetic drifted");
        let rendered = render_solidity_library();
        assert!(
            rendered.contains("uint256 internal constant SIG_WRAPPER_LEN = 4128;"),
            "SIG_WRAPPER_LEN must render as exactly 4128",
        );
    }

    /// The single highest-value test in this suite: render the library
    /// in-process and compare byte-for-byte against the checked-in
    /// Solidity file. Mirrors what
    /// `pqsigner-xtask gen-solidity-constants --check` does in CI —
    /// any code change that alters the generator's output without
    /// regenerating the on-chain library fires here, BEFORE CI.
    #[test]
    fn negative_rendered_output_matches_checked_in_solidity_byte_for_byte() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let checked_in = manifest_dir
            .parent()
            .expect("xtask sits one dir below workspace root")
            .join(SOLIDITY_OUT_PATH);
        let checked_in_text = fs::read_to_string(&checked_in)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", checked_in.display()));
        let rendered = render_solidity_library();
        assert_eq!(
            rendered, checked_in_text,
            "rendered Solidity drifted from checked-in file — \
             regenerate with `cargo run -p pqsigner-xtask -- gen-solidity-constants`",
        );
    }

    /// Defensive: the rendered library must always include the
    /// auto-generated warning AND a pointer to the regenerator command.
    /// Without these, an auditor could hand-edit the Solidity file and
    /// have it survive a regen (until the next CI run catches the diff).
    #[test]
    fn negative_rendered_output_keeps_do_not_edit_warning() {
        let rendered = render_solidity_library();
        assert!(rendered.contains("AUTO-GENERATED — DO NOT EDIT."));
        assert!(rendered
            .contains("Regenerate: `cargo run -p pqsigner-xtask -- gen-solidity-constants`."));
    }

    /// The factory domain tag is printable ASCII; the generator MUST
    /// emit it as a string literal, never as `hex"..."`. A regression
    /// to hex would still be semantically correct on-chain but would
    /// (a) silently flip the rendered diff and (b) hide the tag's
    /// human-readable form from auditors reading the contract.
    #[test]
    fn negative_factory_add_slot_domain_renders_as_string_literal() {
        let rendered = render_solidity_library();
        assert!(rendered.contains(
            "bytes internal constant FACTORY_ADD_SLOT_DOMAIN = \"pqwallet-factory-add-slot\";"
        ));
        assert!(
            !rendered.contains("FACTORY_ADD_SLOT_DOMAIN = hex"),
            "domain tag must NOT fall through to hex encoding for printable ASCII",
        );
    }

    /// `workspace_root()` derives from `CARGO_MANIFEST_DIR`. In a
    /// `cargo test` invocation that env is always set, and the result
    /// must point at the directory above the xtask manifest — i.e.
    /// the workspace root that contains both `xtask/` and
    /// `contracts/`.
    #[test]
    fn positive_workspace_root_is_parent_of_manifest_dir() {
        let root = workspace_root();
        // The workspace root must contain the contracts/ directory and
        // the xtask/ directory; if `workspace_root()` resolves to "."
        // or stays inside xtask/, we've regressed.
        assert!(
            root.join("contracts/smart-wallet/src/generated/PqsignerProto.sol")
                .is_file(),
            "workspace_root() must resolve to the actual workspace root, got {}",
            root.display(),
        );
        assert!(
            root.join("xtask/Cargo.toml").is_file(),
            "workspace_root() must contain xtask/, got {}",
            root.display(),
        );
    }

    /// CLAUDE.md "No classical signer anywhere." The xtask renderer is
    /// the bridge between Rust constants and the on-chain library; if
    /// anyone ever adds a non-C10 sig-length / wrapper / selector
    /// constant to `pqsigner-proto`, this test won't catch it directly
    /// — but it does pin the rendered library to expose ONLY the
    /// approved constant names. New entries are a conscious change.
    #[test]
    fn negative_rendered_library_exposes_only_approved_constants() {
        let rendered = render_solidity_library();
        let approved = [
            "C10_SIG_LEN",
            "SIG_WRAPPER_LEN",
            "MAX_BOOTSTRAP_USES",
            "MAX_SLOT_USES",
            "MAX_OFFCHAIN_GAP",
            "OWNER_BYTES_LEN",
            "EXECUTE_SELECTOR",
            "EXECUTE_BATCH_SELECTOR",
            "FACTORY_ADD_SLOT_DOMAIN",
        ];
        // Every `internal constant` in the rendered output must be one
        // of the approved names. We walk the lines and parse the name.
        for line in rendered.lines() {
            // Match lines like "    uint256 internal constant FOO = …;"
            // or "    bytes4  internal constant FOO = …;" etc.
            let trimmed = line.trim_start();
            let Some(rest) = trimmed
                .strip_prefix("uint256 internal constant ")
                .or_else(|| trimmed.strip_prefix("bytes4 internal constant "))
                .or_else(|| trimmed.strip_prefix("bytes internal constant "))
            else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            assert!(
                approved.contains(&name.as_str()),
                "rendered library exposes unapproved constant `{name}` — \
                 adding constants requires a conscious update to this allowlist",
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// scan-registry — render-coverage scan over the upstream ERC-7730 registry
// ─────────────────────────────────────────────────────────────────────

/// Per-category skip examples retained for the report (the printed summary
/// shows the first few; the `--report` file gets all of them).
const EXAMPLES_PER_CATEGORY: usize = 500;

/// `(count, [(registry-relative path, raw skip reason)])` for one skip category.
type SkipBucket = (usize, Vec<(String, String)>);

/// `scan-registry --registry-root <dir> [--input <dir>] [--policy <path>]
/// [--report <path>]`
///
/// Tolerantly compiles every descriptor under `--input` (default
/// `<registry-root>/registry`) through the SAME `dbgen::erc7730` pipeline
/// the firmware-pinned catalog uses, and tallies how many the on-device
/// renderer can clear-sign today vs. how many are skipped and why. Read-
/// only — writes nothing into the firmware corpus; it answers "how much of
/// the real registry can PQ1 clear-sign, and what is the rest blocked on".
fn cmd_scan_registry(args: &[String]) -> ExitCode {
    let mut registry_root: Option<PathBuf> = None;
    let mut input: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--registry-root" => {
                i += 1;
                registry_root = args.get(i).map(PathBuf::from);
            }
            "--input" => {
                i += 1;
                input = args.get(i).map(PathBuf::from);
            }
            "--policy" => {
                i += 1;
                policy_path = args.get(i).map(PathBuf::from);
            }
            "--report" => {
                i += 1;
                report_path = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("scan-registry: unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let registry_root = match registry_root {
        Some(r) => r,
        None => {
            eprintln!("scan-registry: --registry-root <dir> is required");
            return ExitCode::FAILURE;
        }
    };
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    let input = input.unwrap_or_else(|| registry_root.join("registry"));
    let policy_path =
        policy_path.unwrap_or_else(|| workspace_root.join("secure/data/erc7730/policy.toml"));

    let policy = match dbgen::erc7730::load_policy(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("scan-registry: load policy {}: {e}", policy_path.display());
            return ExitCode::FAILURE;
        }
    };

    let mut files: Vec<PathBuf> = Vec::new();
    collect_json_recursive(&input, &mut files);
    files.sort();
    if files.is_empty() {
        eprintln!(
            "scan-registry: no .json descriptors under {}",
            input.display()
        );
        return ExitCode::FAILURE;
    }

    let mut ok_files = 0usize;
    let mut ok_leaves = 0usize;
    let mut covered_projects: std::collections::BTreeSet<String> = Default::default();
    // category -> (count, example (relpath, raw reason) list)
    let mut skips: std::collections::BTreeMap<&'static str, SkipBucket> = Default::default();

    for f in &files {
        let rel = f
            .strip_prefix(&registry_root)
            .unwrap_or(f)
            .to_string_lossy()
            .to_string();
        match dbgen::erc7730::try_compile_one(f, &policy, Some(&registry_root)) {
            Ok(entries) => {
                ok_files += 1;
                ok_leaves += entries.len();
                covered_projects.insert(project_of(&rel));
            }
            Err(reason) => {
                let cat = skip_category(&reason);
                let e = skips.entry(cat).or_default();
                e.0 += 1;
                if e.1.len() < EXAMPLES_PER_CATEGORY {
                    e.1.push((rel, reason));
                }
            }
        }
    }

    let total = files.len();
    let skipped: usize = skips.values().map(|(c, _)| c).sum();
    let mut by_count: Vec<(&&'static str, &SkipBucket)> = skips.iter().collect();
    by_count.sort_by_key(|(_, bucket)| std::cmp::Reverse(bucket.0));

    let mut out = String::new();
    let _ = writeln!(out, "# ERC-7730 registry render-coverage scan\n");
    let _ = writeln!(out, "input:    {}", input.display());
    let _ = writeln!(
        out,
        "policy:   {} (allow_unattested_dev_descriptors = {})",
        policy_path.display(),
        policy.allow_unattested_dev_descriptors
    );
    let _ = writeln!(out, "\n## Summary");
    let _ = writeln!(out, "descriptors scanned:        {total}");
    let pct = (ok_files * 100).checked_div(total).unwrap_or(0);
    let _ = writeln!(out, "COMPILE (renderable today):  {ok_files}  ({pct}%) -> {ok_leaves} catalog leaves, across {} projects", covered_projects.len());
    let _ = writeln!(out, "skipped:                     {skipped}");
    let _ = writeln!(out, "\n## Skipped, by reason (what the rest is blocked on)");
    for (cat, (count, examples)) in &by_count {
        let _ = writeln!(out, "\n### {count}  {cat}");
        for (path, reason) in examples.iter() {
            let short: String = reason.chars().take(140).collect();
            let _ = writeln!(out, "    - {path}\n        {short}");
        }
    }
    let _ = writeln!(out, "\n## Covered projects ({})", covered_projects.len());
    let cps: Vec<&String> = covered_projects.iter().collect();
    let _ = writeln!(
        out,
        "    {}",
        cps.iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    print!("{out}");
    if let Some(rp) = report_path {
        if let Err(e) = fs::write(&rp, &out) {
            eprintln!("scan-registry: write report {}: {e}", rp.display());
            return ExitCode::FAILURE;
        }
        println!("\nscan-registry: wrote {}", rp.display());
    }
    ExitCode::SUCCESS
}

/// `build-registry --registry-root <dir> [--input <dir>] [--policy <path>]
/// [--report <path>]`
///
/// Tolerantly builds the ERC-7730 catalog (Merkle root + leaves) from the
/// upstream registry via `dbgen::erc7730::build_db_tolerant` — the corpus
/// switch. Reports the leaf count, root, and skips (descriptors / dup leaves
/// the on-device renderer can't take). Read-only for now: it does NOT yet
/// overwrite the firmware-pinned root (the vendoring + prod-root restructure
/// is the follow-up step); use it to see exactly what the registry corpus
/// builds to.
fn cmd_build_registry(args: &[String]) -> ExitCode {
    let mut registry_root: Option<PathBuf> = None;
    let mut input: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--registry-root" => {
                i += 1;
                registry_root = args.get(i).map(PathBuf::from);
            }
            "--input" => {
                i += 1;
                input = args.get(i).map(PathBuf::from);
            }
            "--policy" => {
                i += 1;
                policy_path = args.get(i).map(PathBuf::from);
            }
            "--report" => {
                i += 1;
                report_path = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("build-registry: unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    let Some(registry_root) = registry_root else {
        eprintln!("build-registry: --registry-root <dir> is required");
        return ExitCode::FAILURE;
    };
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    let input = input.unwrap_or_else(|| registry_root.join("registry"));
    let policy_path =
        policy_path.unwrap_or_else(|| workspace_root.join("secure/data/erc7730/policy.toml"));

    let (result, skips) =
        match dbgen::erc7730::build_db_tolerant(&input, &policy_path, Some(&registry_root)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("build-registry: {e}");
                return ExitCode::FAILURE;
            }
        };

    println!("# ERC-7730 tolerant registry build");
    println!("input:   {}", input.display());
    println!("leaves:  {}", result.leaf_count);
    println!("root:    {}", hex_lower(&result.root));
    println!("skipped: {} descriptor(s)/leaf(s)", skips.len());

    if let Some(rp) = report_path {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# tolerant registry build — {} leaves, {} skipped\n",
            result.leaf_count,
            skips.len()
        );
        let _ = writeln!(out, "root: {}\n", hex_lower(&result.root));
        // Sorted leaf keys (chain:contract:typehash) for cross-build diffing.
        let mut keys: Vec<String> = result
            .entries
            .iter()
            .map(|e| {
                format!(
                    "{}:{}:{}",
                    e.chain_id,
                    hex_lower(&e.contract),
                    hex_lower(&e.primary_type_hash)
                )
            })
            .collect();
        keys.sort();
        let _ = writeln!(out, "## leaf keys ({})", keys.len());
        for k in &keys {
            let _ = writeln!(out, "LEAF {k}");
        }
        let _ = writeln!(out, "\n## skips");
        for s in &skips {
            let rel = s.source.strip_prefix(&registry_root).unwrap_or(&s.source);
            let short: String = s.reason.chars().take(160).collect();
            let _ = writeln!(out, "- {}\n    {}", rel.display(), short);
        }
        if let Err(e) = fs::write(&rp, &out) {
            eprintln!("build-registry: write report {}: {e}", rp.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", rp.display());
    }
    ExitCode::SUCCESS
}

/// `vendor-registry --registry-root <dir> [--out <dir>] [--policy <path>]`
///
/// Vendors the complete security-relevant JSON corpus of the upstream registry
/// into the repo (default `secure/data/erc7730-registry/`) so both accepted
/// render leaves and intentionally-refused call declarations remain
/// reproducible.  A dead-only project contributes no Merkle leaf but still has
/// to remain in the known-call omission filter; therefore root equality alone
/// is explicitly insufficient as a faithfulness proof.
fn cmd_vendor_registry(args: &[String]) -> ExitCode {
    let mut registry_root: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--registry-root" => {
                i += 1;
                registry_root = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--policy" => {
                i += 1;
                policy_path = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("vendor-registry: unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }
    let Some(registry_root) = registry_root else {
        eprintln!("vendor-registry: --registry-root <dir> is required");
        return ExitCode::FAILURE;
    };
    let workspace_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default();
    let out = out.unwrap_or_else(|| workspace_root.join("secure/data/erc7730-registry"));
    let policy_path =
        policy_path.unwrap_or_else(|| workspace_root.join("secure/data/erc7730/policy.toml"));
    match vendor_registry(&registry_root, &out, &policy_path) {
        Ok(receipt) => {
            println!(
                "vendored {} files ({} leaf-bearing sources + {} refused/support JSON files)",
                receipt.copied, receipt.descriptor_count, receipt.support_count
            );
            println!("out:   {}", out.display());
            println!(
                "root:  {} (exact catalogue + known-call coverage reproduced ✓)",
                hex_lower(&receipt.root)
            );
            println!("leaves: {}", receipt.leaf_count);
            println!("known calls: {}", receipt.known_call_count);
            println!(
                "known-call tuple-set SHA-256: {}",
                hex_lower(&receipt.known_call_set_hash)
            );
            println!("source-corpus SHA-256: {}", hex_lower(&receipt.corpus_hash));
            println!(
                "excluded fixture JSON: {} files, SHA-256 {}",
                receipt.excluded_fixture_count,
                hex_lower(&receipt.excluded_fixture_hash)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("vendor-registry: {error}");
            ExitCode::FAILURE
        }
    }
}

struct VendorReceipt {
    copied: usize,
    descriptor_count: usize,
    support_count: usize,
    root: [u8; 32],
    leaf_count: usize,
    known_call_count: usize,
    known_call_set_hash: [u8; 32],
    corpus_hash: [u8; 32],
    excluded_fixture_count: usize,
    excluded_fixture_hash: [u8; 32],
}

fn vendor_registry(
    registry_root: &std::path::Path,
    out: &std::path::Path,
    policy_path: &std::path::Path,
) -> Result<VendorReceipt, String> {
    let registry_root = fs::canonicalize(registry_root)
        .map_err(|e| format!("canonicalize source {}: {e}", registry_root.display()))?;
    if out.file_name().is_none() {
        return Err(format!(
            "unsafe --out {} (must be a distinct named directory)",
            out.display()
        ));
    }
    if out
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(format!("--out may not be a symlink: {}", out.display()));
    }
    let out_parent = out
        .parent()
        .ok_or_else(|| format!("--out has no parent: {}", out.display()))?;
    fs::create_dir_all(out_parent)
        .map_err(|e| format!("create output parent {}: {e}", out_parent.display()))?;
    let canonical_parent = fs::canonicalize(out_parent)
        .map_err(|e| format!("canonicalize output parent {}: {e}", out_parent.display()))?;
    let canonical_out = canonical_parent.join(out.file_name().expect("checked named output"));
    if canonical_out.starts_with(&registry_root) || registry_root.starts_with(&canonical_out) {
        return Err(format!(
            "source/output overlap is forbidden: source={} out={}",
            registry_root.display(),
            canonical_out.display()
        ));
    }

    if canonical_out.exists() {
        let mut entries = fs::read_dir(&canonical_out)
            .map_err(|e| format!("read output {}: {e}", canonical_out.display()))?;
        let nonempty = entries
            .next()
            .transpose()
            .map_err(|e| format!("read output entry {}: {e}", canonical_out.display()))?
            .is_some();
        if nonempty && !canonical_out.join(ERC7730_VENDOR_MARKER).is_file() {
            return Err(format!(
                "refusing to replace unmarked nonempty output {}",
                canonical_out.display()
            ));
        }
    }

    let input = registry_root.join("registry");
    let ercs_input = registry_root.join("ercs");
    validate_vendor_source_directory(&input, "registry")?;
    validate_vendor_source_directory(&ercs_input, "ercs")?;
    let (result, _skips) =
        dbgen::erc7730::build_db_tolerant(&input, policy_path, Some(&registry_root))
            .map_err(|e| format!("registry build: {e}"))?;
    let descriptor_count = result
        .entries
        .iter()
        .map(|entry| &entry.source)
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    let mut source_files = std::collections::BTreeSet::<PathBuf>::new();
    let mut excluded_fixtures = std::collections::BTreeSet::<PathBuf>::new();
    for dir in [input, ercs_input] {
        collect_vendor_jsons(&dir, &mut source_files, &mut excluded_fixtures, false)?;
    }
    let source_corpus = vendor_corpus_receipt(&registry_root, &source_files)?;
    let excluded_fixture_corpus =
        vendor_excluded_fixture_receipt(&registry_root, &excluded_fixtures)?;
    let support_count = source_files.len().saturating_sub(descriptor_count);

    let out_name = canonical_out
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output directory name must be UTF-8".to_string())?;
    let staging =
        canonical_parent.join(format!(".{out_name}.vendor-staging-{}", std::process::id()));
    if staging.exists() {
        return Err(format!(
            "staging path already exists: {}",
            staging.display()
        ));
    }
    fs::create_dir(&staging)
        .map_err(|e| format!("create staging directory {}: {e}", staging.display()))?;

    for src in &source_files {
        let rel = src
            .strip_prefix(&registry_root)
            .map_err(|_| format!("source escaped registry root: {}", src.display()))?;
        let dst = staging.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::copy(src, &dst).map_err(|e| format!("copy {}: {e}", src.display()))?;
    }

    let mut staged_files = std::collections::BTreeSet::<PathBuf>::new();
    let mut staged_excluded_fixtures = std::collections::BTreeSet::<PathBuf>::new();
    for dir in [staging.join("registry"), staging.join("ercs")] {
        collect_vendor_jsons(
            &dir,
            &mut staged_files,
            &mut staged_excluded_fixtures,
            false,
        )?;
    }
    if !staged_excluded_fixtures.is_empty() {
        return Err("internal error: excluded fixture JSON was copied into staging".to_string());
    }
    let staged_corpus = vendor_corpus_receipt(&staging, &staged_files)?;
    if staged_corpus != source_corpus {
        return Err(format!(
            "FAITHFULNESS CHECK FAILED — source corpus count/hash={}/{} staged={}/{}",
            source_corpus.0,
            hex_lower(&source_corpus.1),
            staged_corpus.0,
            hex_lower(&staged_corpus.1)
        ));
    }

    let (vendored, _) =
        dbgen::erc7730::build_db_tolerant(&staging.join("registry"), policy_path, Some(&staging))
            .map_err(|e| format!("rebuild from staged tree: {e}"))?;
    let faithful = vendored.root == result.root
        && vendored.blob == result.blob
        && vendored.leaf_count == result.leaf_count
        && vendored.provenance == result.provenance
        && vendored.known_call_count == result.known_call_count
        && vendored.known_call_set_hash == result.known_call_set_hash
        && vendored.known_calls_bloom == result.known_calls_bloom
        && vendored.review_text == result.review_text;
    if !faithful {
        return Err(format!(
            "FAITHFULNESS CHECK FAILED\n\
             source:   root={} leaves={} provenance={} known_calls={} tuple_hash={}\n\
             staged:   root={} leaves={} provenance={} known_calls={} tuple_hash={}\n\
             exact checks: blob={} bloom={} review={}",
            hex_lower(&result.root),
            result.leaf_count,
            result.provenance.as_str(),
            result.known_call_count,
            hex_lower(&result.known_call_set_hash),
            hex_lower(&vendored.root),
            vendored.leaf_count,
            vendored.provenance.as_str(),
            vendored.known_call_count,
            hex_lower(&vendored.known_call_set_hash),
            vendored.blob == result.blob,
            vendored.known_calls_bloom == result.known_calls_bloom,
            vendored.review_text == result.review_text,
        ));
    }

    install_vendored_subdirs(&staging, &canonical_out)?;
    Ok(VendorReceipt {
        copied: source_files.len(),
        descriptor_count,
        support_count,
        root: result.root,
        leaf_count: result.leaf_count,
        known_call_count: result.known_call_count,
        known_call_set_hash: result.known_call_set_hash,
        corpus_hash: source_corpus.1,
        excluded_fixture_count: excluded_fixture_corpus.0,
        excluded_fixture_hash: excluded_fixture_corpus.1,
    })
}

fn validate_vendor_source_directory(path: &std::path::Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("inspect {label} source directory {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} source directory may not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!(
            "{label} source path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

/// Collect every `*.json` under `dir`, including upstream test-fixture paths.
/// Fixture naming may exclude a file from trusted rendering, but it is not a
/// safe omission-filter boundary: moving a declaration under `tests/` or adding
/// `.tests.` to its name must not restore a blind-sign path. Any traversal error
/// or symlink is fatal.
fn collect_vendor_jsons(
    dir: &std::path::Path,
    out: &mut std::collections::BTreeSet<PathBuf>,
    excluded: &mut std::collections::BTreeSet<PathBuf>,
    under_tests_dir: bool,
) -> Result<(), String> {
    validate_vendor_source_directory(dir, "recursive corpus")?;
    let rd = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("read entry under {}: {e}", dir.display()))?;
        let p = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("file type {}: {e}", p.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "symlink is not allowed in vendored corpus: {}",
                p.display()
            ));
        }
        if file_type.is_dir() {
            let child_is_tests = p.file_name().is_some_and(|name| name == "tests");
            collect_vendor_jsons(&p, out, excluded, under_tests_dir || child_is_tests)?;
        } else if file_type.is_file() {
            let name = p
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    "vendored corpus contains a non-UTF-8 regular-file name".to_string()
                })?;
            if name.to_ascii_lowercase().ends_with(".json") && !name.ends_with(".json") {
                return Err(format!(
                    "non-canonical JSON filename `{name}` in vendored corpus — use lowercase `.json`"
                ));
            }
            if name.ends_with(".json") {
                if under_tests_dir || name.contains(".tests.") {
                    validate_excluded_vendor_fixture(&p)?;
                    excluded.insert(p);
                } else {
                    out.insert(p);
                }
            }
        } else {
            return Err(format!(
                "unsupported filesystem entry in vendored corpus: {}",
                p.display()
            ));
        }
    }
    Ok(())
}

/// Excluded upstream fixtures are not copied or trusted for rendering, but the
/// exclusion cannot become a known-call escape hatch. Parse every fixture and
/// refuse a nested include or any live binding: contract/EIP-712 deployment
/// arrays and the EIP-712 domain-only `{chainId, verifyingContract}` form. The
/// inventory is separately receipted for the root-rotation review.
fn validate_excluded_vendor_fixture(path: &std::path::Path) -> Result<(), String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("read excluded fixture {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse excluded fixture {}: {e}", path.display()))?;
    if json.get("includes").is_some() {
        return Err(format!(
            "excluded fixture {} contains `includes`; it must be curated into the security corpus",
            path.display()
        ));
    }
    for pointer in [
        "/context/contract/deployments",
        "/context/eip712/deployments",
    ] {
        if let Some(value) = json.pointer(pointer) {
            let deployments = value.as_array().ok_or_else(|| {
                format!(
                    "excluded fixture {} has non-array `{pointer}`",
                    path.display()
                )
            })?;
            if !deployments.is_empty() {
                return Err(format!(
                    "excluded fixture {} declares deployments at `{pointer}`; fixture naming cannot exclude a live binding",
                    path.display()
                ));
            }
        }
    }
    if let Some(domain) = json.pointer("/context/eip712/domain") {
        let domain = domain.as_object().ok_or_else(|| {
            format!(
                "excluded fixture {} has non-object `/context/eip712/domain`",
                path.display()
            )
        })?;
        let has_chain = domain.get("chainId").is_some_and(|value| !value.is_null());
        let has_contract = domain
            .get("verifyingContract")
            .is_some_and(|value| !value.is_null());
        if has_chain && has_contract {
            return Err(format!(
                "excluded fixture {} declares a fully-specified EIP-712 domain binding; fixture naming cannot exclude a live binding",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Aggregate byte-level receipt for the complete copied corpus. Paths are
/// registry-root-relative and sorted; each file contributes its own SHA-256 so
/// semantically-unused templates remain part of the faithfulness proof.
fn vendor_corpus_receipt(
    root: &std::path::Path,
    files: &std::collections::BTreeSet<PathBuf>,
) -> Result<(usize, [u8; 32]), String> {
    vendor_corpus_receipt_with_domain(root, files, b"pqsigner/erc7730-vendor-corpus-v1")
}

fn vendor_corpus_receipt_with_domain(
    root: &std::path::Path,
    files: &std::collections::BTreeSet<PathBuf>,
    domain: &[u8],
) -> Result<(usize, [u8; 32]), String> {
    let count = u64::try_from(files.len())
        .map_err(|_| "vendor corpus file count does not fit u64".to_string())?;
    let mut aggregate = Sha256::new();
    aggregate.update(domain);
    aggregate.update(count.to_be_bytes());
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("corpus source escaped root: {}", path.display()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 corpus path: {}", path.display()))?;
        let path_len = u32::try_from(relative.len())
            .map_err(|_| format!("corpus path is too long: {relative}"))?;
        let bytes =
            fs::read(path).map_err(|e| format!("read corpus file {}: {e}", path.display()))?;
        let file_len = u64::try_from(bytes.len())
            .map_err(|_| format!("corpus file is too large: {}", path.display()))?;
        let file_hash = Sha256::digest(&bytes);
        aggregate.update(path_len.to_be_bytes());
        aggregate.update(relative.as_bytes());
        aggregate.update(file_len.to_be_bytes());
        aggregate.update(file_hash);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&aggregate.finalize());
    Ok((files.len(), out))
}

fn vendor_excluded_fixture_receipt(
    root: &std::path::Path,
    files: &std::collections::BTreeSet<PathBuf>,
) -> Result<(usize, [u8; 32]), String> {
    vendor_corpus_receipt_with_domain(
        root,
        files,
        b"pqsigner/erc7730-excluded-fixture-corpus-v1",
    )
}

/// Install only the two tool-managed subdirectories after every source/staged
/// receipt has passed. This is a checked two-directory transaction, not a
/// filesystem-atomic pair swap: existing directories are moved to a retained
/// sibling backup first, and every rollback operation is checked. Any uncertain
/// rollback reports the backup path and never claims that the prior corpus was
/// restored.
fn install_vendored_subdirs(
    staging: &std::path::Path,
    out: &std::path::Path,
) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("create output {}: {e}", out.display()))?;
    let marker = out.join(ERC7730_VENDOR_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => validate_vendor_marker(&marker)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::write(&marker, ERC7730_VENDOR_MARKER_BYTES)
                .map_err(|e| format!("write vendor marker {}: {e}", marker.display()))?;
        }
        Err(error) => {
            return Err(format!(
                "inspect vendor marker {}: {error}",
                marker.display()
            ));
        }
    }

    let parent = out
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", out.display()))?;
    let name = out
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "output directory name must be UTF-8".to_string())?;
    let backup = parent.join(format!(".{name}.vendor-backup-{}", std::process::id()));
    if backup.exists() {
        return Err(format!("backup path already exists: {}", backup.display()));
    }
    fs::create_dir(&backup)
        .map_err(|e| format!("create backup directory {}: {e}", backup.display()))?;

    let subdirs = ["registry", "ercs"];
    let mut old_moved = [false; 2];
    for (index, subdir) in subdirs.iter().enumerate() {
        let old = out.join(subdir);
        if old.exists() {
            if let Err(error) = fs::rename(&old, backup.join(subdir)) {
                let rollback = rollback_vendored_install(
                    staging,
                    out,
                    &backup,
                    &subdirs,
                    &old_moved,
                    &[false; 2],
                );
                return Err(install_failure_message(
                    &format!("move existing {} into backup: {error}", old.display()),
                    &backup,
                    rollback,
                ));
            }
            old_moved[index] = true;
        }
    }

    let mut new_moved = [false; 2];
    for (index, subdir) in subdirs.iter().enumerate() {
        let staged = staging.join(subdir);
        let destination = out.join(subdir);
        if let Err(error) = fs::rename(&staged, &destination) {
            let rollback = rollback_vendored_install(
                staging,
                out,
                &backup,
                &subdirs,
                &old_moved,
                &new_moved,
            );
            return Err(install_failure_message(
                &format!("install staged directory {}: {error}", staged.display()),
                &backup,
                rollback,
            ));
        }
        new_moved[index] = true;
    }

    fs::remove_dir(staging)
        .map_err(|e| format!("installed corpus but could not remove empty staging dir: {e}"))?;
    fs::remove_dir_all(&backup).map_err(|e| {
        format!(
            "installed corpus but could not remove tool-owned backup {}: {e}",
            backup.display()
        )
    })?;
    Ok(())
}

fn validate_vendor_marker(marker: &std::path::Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(marker)
        .map_err(|e| format!("inspect vendor marker {}: {e}", marker.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "vendor marker must be a regular non-symlink file: {}",
            marker.display()
        ));
    }
    let bytes =
        fs::read(marker).map_err(|e| format!("read vendor marker {}: {e}", marker.display()))?;
    if bytes != ERC7730_VENDOR_MARKER_BYTES {
        return Err(format!(
            "vendor marker content mismatch at {}; refusing to replace tool-managed directories",
            marker.display()
        ));
    }
    Ok(())
}

fn rollback_vendored_install(
    staging: &std::path::Path,
    out: &std::path::Path,
    backup: &std::path::Path,
    subdirs: &[&str; 2],
    old_moved: &[bool; 2],
    new_moved: &[bool; 2],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // First remove every newly-installed directory from the destination so an
    // old directory can be restored without a destination collision.
    for index in (0..subdirs.len()).rev() {
        if new_moved[index] {
            let installed = out.join(subdirs[index]);
            let staged = staging.join(subdirs[index]);
            if let Err(error) = fs::rename(&installed, &staged) {
                errors.push(format!(
                    "move newly installed {} back to staging {}: {error}",
                    installed.display(),
                    staged.display()
                ));
            }
        }
    }

    for index in (0..subdirs.len()).rev() {
        if old_moved[index] {
            let saved = backup.join(subdirs[index]);
            let destination = out.join(subdirs[index]);
            if let Err(error) = fs::rename(&saved, &destination) {
                errors.push(format!(
                    "restore prior {} from {}: {error}",
                    destination.display(),
                    saved.display()
                ));
            }
        }
    }

    if errors.is_empty() {
        if let Err(error) = fs::remove_dir(backup) {
            errors.push(format!(
                "remove empty rollback backup {}: {error}",
                backup.display()
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn install_failure_message(
    cause: &str,
    backup: &std::path::Path,
    rollback: Result<(), Vec<String>>,
) -> String {
    match rollback {
        Ok(()) => format!("{cause}; checked rollback restored the prior corpus"),
        Err(errors) => format!(
            "{cause}; ROLLBACK INCOMPLETE — do not use the destination. Retained backup at {}. Rollback errors: {}",
            backup.display(),
            errors.join(" | ")
        ),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn collect_json_recursive(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            // Skip the registry's `tests/` fixture dirs.
            if p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            collect_json_recursive(&p, out);
        } else if is_descriptor_file(&p) {
            out.push(p);
        }
    }
}

/// True only for standalone ERC-7730 descriptors. The registry mixes, in
/// the same dirs: `calldata-*.json` / `eip712-*.json` (the descriptors),
/// `common-*.json` (include-only templates with no `context`, pulled in via
/// `includes`), and `*.tests.json` (test fixtures). Only the first kind is a
/// compilable descriptor; counting the rest would mis-report coverage.
fn is_descriptor_file(p: &std::path::Path) -> bool {
    let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(".json")
        && !name.contains(".tests.")
        && (name.starts_with("calldata-") || name.starts_with("eip712-"))
}

/// The project segment of a registry-relative path (`registry/aave/...` ->
/// `aave`, `ercs/...` -> `ercs`), for the covered-projects roll-up.
fn project_of(rel: &str) -> String {
    let parts: Vec<&str> = rel.split('/').collect();
    match parts.as_slice() {
        [first, second, ..] if *first == "registry" => second.to_string(),
        [first, ..] => first.to_string(),
        _ => rel.to_string(),
    }
}

/// Bucket a dbgen compile error into a coarse "what's blocking it" category.
/// Ordered most-specific-first; the raw reason is still shown per example.
fn skip_category(msg: &str) -> &'static str {
    let m = msg;
    if m.contains("array index") || m.contains("array slice") || m.contains("ArrayIdx") {
        "array-path (needs dynamic-array walker)"
    } else if m.contains("dynamic tuple") || m.contains("is dynamic") || m.contains("calldata tail")
    {
        "dynamic-ABI-type (needs dynamic-array walker)"
    } else if m.contains("spanning") && m.contains("words") {
        "multi-word static field (>32B)"
    } else if m.contains("includes") {
        "includes-unresolved"
    } else if m.contains("nested calldata") || m.contains("encrypted") {
        "unsupported formatter (nested-calldata / encrypted)"
    } else if m.contains("nft") {
        "unsupported formatter (nft)"
    } else if m.contains("enum") {
        "enum issue"
    } else if m.contains("completeness")
        || m.contains("not covered")
        || m.contains("must cover")
        || m.contains("uncovered")
    {
        "completeness lint (un-displayed field)"
    } else if m.contains("MAX_IR_LEN")
        || m.contains("exceeds")
        || m.contains("too large")
        || m.contains("too long")
    {
        "IR too large (>4KiB)"
    } else if m.contains("policy") || m.contains("attest") {
        "attestation policy"
    } else if m.starts_with("schema")
        || m.starts_with("parse")
        || m.contains("schema:")
        || m.contains("missing field")
        || m.contains("unknown field")
    {
        "schema / parse"
    } else if m.contains("selector")
        || m.contains("signature")
        || m.contains("encodeType")
        || m.contains("primary")
    {
        "selector / type-signature"
    } else {
        "other"
    }
}
