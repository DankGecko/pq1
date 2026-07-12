//! `pqsigner-xtask` — host-side codegen and tooling.
//!
//! See `Cargo.toml` for the design rationale. Subcommands (run `xtask help`):
//!   * `gen-solidity-constants` — render the Solidity `PqsignerProto` library
//!     from the public constants in `pqsigner-proto`.
//!   * `gen-erc7730-descriptors` — compile + Merkle-anchor the ERC-7730 catalog.
//!   * `scan-registry` / `build-registry` — read-only upstream-registry coverage
//!     probes (how much PQ1 can clear-sign; what the full corpus builds to).
//!   * `vendor-registry` — vendor the leaf-contributing registry into the repo
//!     and verify it rebuilds the identical Merkle root.
//! The `gen-*` commands take `--check` (rebuild-in-memory + drift-diff) for CI.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use pqsigner_proto as proto;

const SOLIDITY_OUT_PATH: &str = "contracts/smart-wallet/src/generated/PqsignerProto.sol";

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
                          [--out-root PATH]
      Compile the ERC-7730 descriptor catalog from
      `secure/data/erc7730/*.json` against `policy.toml`, build the
      Merkle tree, and emit:
        tools/companion-stub/erc7730_db.bin
        tools/companion-stub/erc7730_db_e2e.bin
        secure/data/erc7730.review.txt
        secure/src/db_roots.rs   (ERC7730_DESCRIPTORS_ROOT)
      With --check: rebuild in-memory and compare against the checked-in
      artifacts; exit non-zero on drift. CI uses this gate, mirroring
      the gen-solidity-constants pattern.

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
      Vendor every leaf-contributing descriptor + include template into the
      repo (default `secure/data/erc7730-registry/`), preserving the tree so
      `includes` resolve, then VERIFY the vendored tree rebuilds the identical
      Merkle root (reproducible-build faithfulness proof).

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
            &e2e.root,
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

/// `str::contains` would accept a generated security fence copied into a Rust
/// comment or raw string, even though rustc would not enforce it. Scan just
/// enough Rust lexical structure to require the marker's first token to occur
/// in active code. (The marker itself is exact, so an inserted comment inside
/// it already fails the byte comparison.)
fn contains_active_rust_marker(text: &str, marker: &str) -> bool {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        LineComment,
        BlockComment(usize),
        String,
        Char,
        RawString(usize),
    }

    fn raw_prefix(bytes: &[u8], i: usize) -> Option<(usize, usize)> {
        let mut p = i;
        if bytes.get(p) == Some(&b'b') {
            p += 1;
        }
        if bytes.get(p) != Some(&b'r') {
            return None;
        }
        p += 1;
        let mut hashes = 0usize;
        while bytes.get(p) == Some(&b'#') {
            hashes += 1;
            p += 1;
        }
        (bytes.get(p) == Some(&b'"')).then_some((p + 1, hashes))
    }

    fn looks_like_char(bytes: &[u8], i: usize) -> bool {
        let end = (i + 12).min(bytes.len());
        bytes
            .get(i + 1..end)
            .is_some_and(|tail| tail.iter().position(|&b| b == b'\'').is_some())
    }

    let bytes = text.as_bytes();
    let needle = marker.as_bytes();
    let mut state = State::Code;
    let mut i = 0usize;
    while i < bytes.len() {
        match state {
            State::Code => {
                if bytes[i..].starts_with(needle) {
                    return true;
                }
                if bytes.get(i..i + 2) == Some(b"//") {
                    state = State::LineComment;
                    i += 2;
                } else if bytes.get(i..i + 2) == Some(b"/*") {
                    state = State::BlockComment(1);
                    i += 2;
                } else if let Some((next, hashes)) = raw_prefix(bytes, i) {
                    state = State::RawString(hashes);
                    i = next;
                } else if bytes[i] == b'"' {
                    state = State::String;
                    i += 1;
                } else if bytes[i] == b'\'' && looks_like_char(bytes, i) {
                    state = State::Char;
                    i += 1;
                } else {
                    i += 1;
                }
            }
            State::LineComment => {
                if bytes[i] == b'\n' {
                    state = State::Code;
                }
                i += 1;
            }
            State::BlockComment(depth) => {
                if bytes.get(i..i + 2) == Some(b"/*") {
                    state = State::BlockComment(depth + 1);
                    i += 2;
                } else if bytes.get(i..i + 2) == Some(b"*/") {
                    state = if depth == 1 {
                        State::Code
                    } else {
                        State::BlockComment(depth - 1)
                    };
                    i += 2;
                } else {
                    i += 1;
                }
            }
            State::String | State::Char => {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else {
                    let terminator = if matches!(state, State::String) {
                        b'"'
                    } else {
                        b'\''
                    };
                    if bytes[i] == terminator {
                        state = State::Code;
                    }
                    i += 1;
                }
            }
            State::RawString(hashes) => {
                if bytes[i] == b'"'
                    && bytes
                        .get(i + 1..i + 1 + hashes)
                        .is_some_and(|tail| tail.iter().all(|&b| b == b'#'))
                {
                    state = State::Code;
                    i += 1 + hashes;
                } else {
                    i += 1;
                }
            }
        }
    }
    false
}

const ERC7730_PROD_FILTER_MARKER: &str = "#[cfg(not(feature = \"e2e-test\"))]\n\
pub static ERC7730_KNOWN_CALLS_BLOOM: &[u8; pqsigner_erc7730::known_calls::BLOOM_BYTES] =\n\
include_bytes!(\"../data/erc7730-known-calls.bloom\");";
const ERC7730_E2E_FILTER_MARKER: &str = "#[cfg(feature = \"e2e-test\")]\n\
pub static ERC7730_KNOWN_CALLS_BLOOM: &[u8; pqsigner_erc7730::known_calls::BLOOM_BYTES] =\n\
include_bytes!(\"../data/erc7730-known-calls-e2e.bloom\");";

fn diff_root_in_db_roots(
    path: &PathBuf,
    prod_root: &[u8; 32],
    e2e_root: &[u8; 32],
    prod_provenance: dbgen::erc7730::CatalogueProvenance,
    e2e_provenance: dbgen::erc7730::CatalogueProvenance,
) -> Result<(), String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read db_roots.rs at {}: {e}", path.display()))?;
    let (prod_present, e2e_present, prod_filter_present, e2e_filter_present) =
        erc7730_root_filter_cfg_matches(&text, prod_root, e2e_root);
    let (
        prod_provenance_present,
        e2e_provenance_present,
        prod_provenance_fences_present,
        e2e_provenance_fences_present,
    ) = erc7730_provenance_cfg_matches(&text, prod_provenance, e2e_provenance);
    if prod_present
        && e2e_present
        && prod_filter_present
        && e2e_filter_present
        && prod_provenance_present
        && e2e_provenance_present
        && prod_provenance_fences_present
        && e2e_provenance_fences_present
    {
        return Ok(());
    }
    let prod_hex = hex::encode(prod_root);
    let e2e_hex = hex::encode(e2e_root);
    Err(format!(
        "ERC-7730 root/filter/provenance in {} doesn't match fresh build (prod root {prod_hex} under prod cfg={prod_present}, e2e root {e2e_hex} under e2e cfg={e2e_present}, prod filter path/cfg={prod_filter_present}, e2e filter path/cfg={e2e_filter_present}, prod provenance {} present={prod_provenance_present} fences={prod_provenance_fences_present}, e2e provenance {} present={e2e_provenance_present} fences={e2e_provenance_fences_present})",
        path.display(),
        prod_provenance.as_str(),
        e2e_provenance.as_str(),
    ))
}

fn erc7730_provenance_cfg_matches(
    text: &str,
    prod: dbgen::erc7730::CatalogueProvenance,
    e2e: dbgen::erc7730::CatalogueProvenance,
) -> (bool, bool, bool, bool) {
    let prod_marker = erc7730_provenance_marker(prod, false);
    let e2e_marker = erc7730_provenance_marker(e2e, true);
    let prod_fences = erc7730_provenance_fence_markers(prod, false);
    let e2e_fences = erc7730_provenance_fence_markers(e2e, true);
    (
        contains_active_rust_marker(text, &prod_marker),
        contains_active_rust_marker(text, &e2e_marker),
        prod_fences
            .iter()
            .all(|marker| contains_active_rust_marker(text, marker)),
        e2e_fences
            .iter()
            .all(|marker| contains_active_rust_marker(text, marker)),
    )
}

fn erc7730_provenance_marker(provenance: dbgen::erc7730::CatalogueProvenance, e2e: bool) -> String {
    let selected = if e2e {
        "feature = \"e2e-test\""
    } else {
        "not(feature = \"e2e-test\")"
    };
    format!(
        "#[cfg({selected})]\npub const ERC7730_CATALOGUE_PROVENANCE: &str = {:?};",
        provenance.as_str()
    )
}

/// Exact cfg-associated compile fences emitted by dbgen for the selected
/// catalogue provenance. These are part of the generated security policy, not
/// commentary: losing one must drift-fail just like losing the root itself.
fn erc7730_provenance_fence_markers(
    provenance: dbgen::erc7730::CatalogueProvenance,
    e2e: bool,
) -> Vec<String> {
    use dbgen::erc7730::CatalogueProvenance;

    match (provenance, e2e) {
        (CatalogueProvenance::DevUnattested, false) => vec![
            "#[cfg(all(not(feature = \"e2e-test\"), feature = \"mode-production\"))]\n\
compile_error!(\"mode-production cannot embed the dev-unattested ERC-7730 catalogue. Implement and run real ERC-8176 EAS verification, regenerate db_roots.rs, and only then build production firmware.\");"
                .to_string(),
            "#[cfg(all(not(feature = \"e2e-test\"), not(feature = \"mode-production\"), not(feature = \"erc7730-dev-unattested\"), not(test)))]\n\
compile_error!(\"the pinned ERC-7730 catalogue is dev-unattested; enable erc7730-dev-unattested so the trusted display shows the provenance warning, or regenerate from a genuinely ERC-8176-verified corpus\");"
                .to_string(),
        ],
        (CatalogueProvenance::DevUnattested, true) => vec![
            "#[cfg(all(feature = \"e2e-test\", not(feature = \"erc7730-dev-unattested\"), not(test)))]\n\
compile_error!(\"the e2e ERC-7730 fixture catalogue is dev-unattested; e2e builds must enable erc7730-dev-unattested so the display warning matches its provenance\");"
                .to_string(),
        ],
        (CatalogueProvenance::Erc8176Verified, e2e) => {
            let selected = if e2e {
                "feature = \"e2e-test\""
            } else {
                "not(feature = \"e2e-test\")"
            };
            vec![format!(
                "#[cfg(all({selected}, feature = \"erc7730-dev-unattested\"))]\n\
compile_error!(\"erc7730-dev-unattested is enabled but the selected catalogue is ERC-8176-verified; disable the feature so the trusted display does not show false provenance\");"
            )]
        }
    }
}

fn erc7730_root_filter_cfg_matches(
    text: &str,
    prod_root: &[u8; 32],
    e2e_root: &[u8; 32],
) -> (bool, bool, bool, bool) {
    let prod_root_marker = cfg_root_marker(
        "not(feature = \"e2e-test\")",
        "ERC7730_DESCRIPTORS_ROOT",
        prod_root,
    );
    let e2e_root_marker = cfg_root_marker(
        "feature = \"e2e-test\"",
        "ERC7730_DESCRIPTORS_ROOT",
        e2e_root,
    );
    let prod_present = contains_active_rust_marker(text, &prod_root_marker);
    let e2e_present = contains_active_rust_marker(text, &e2e_root_marker);
    let prod_filter_present = contains_active_rust_marker(text, ERC7730_PROD_FILTER_MARKER);
    let e2e_filter_present = contains_active_rust_marker(text, ERC7730_E2E_FILTER_MARKER);
    (
        prod_present,
        e2e_present,
        prod_filter_present,
        e2e_filter_present,
    )
}

fn cfg_root_marker(cfg: &str, name: &str, root: &[u8; 32]) -> String {
    use std::fmt::Write;

    let mut out = format!("#[cfg({cfg})]\npub static {name}: [u8; 32] = [");
    for (i, byte) in root.iter().enumerate() {
        if i % 8 == 0 {
            out.push_str("\n    ");
        } else {
            out.push(' ');
        }
        write!(out, "0x{byte:02x},").unwrap();
    }
    out.push_str("\n];");
    out
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
    fn erc7730_codegen_check_binds_roots_and_filters_to_their_cfgs() {
        let prod = [0x11u8; 32];
        let e2e = [0x22u8; 32];
        let prod_root = cfg_root_marker(
            "not(feature = \"e2e-test\")",
            "ERC7730_DESCRIPTORS_ROOT",
            &prod,
        );
        let e2e_root = cfg_root_marker("feature = \"e2e-test\"", "ERC7730_DESCRIPTORS_ROOT", &e2e);
        let correct = format!(
            "{prod_root}\n{e2e_root}\n{ERC7730_PROD_FILTER_MARKER}\n{ERC7730_E2E_FILTER_MARKER}"
        );
        assert_eq!(
            erc7730_root_filter_cfg_matches(&correct, &prod, &e2e),
            (true, true, true, true)
        );

        let swapped_roots = format!(
            "{}\n{}\n{ERC7730_PROD_FILTER_MARKER}\n{ERC7730_E2E_FILTER_MARKER}",
            cfg_root_marker(
                "not(feature = \"e2e-test\")",
                "ERC7730_DESCRIPTORS_ROOT",
                &e2e,
            ),
            cfg_root_marker("feature = \"e2e-test\"", "ERC7730_DESCRIPTORS_ROOT", &prod,),
        );
        assert_eq!(
            erc7730_root_filter_cfg_matches(&swapped_roots, &prod, &e2e),
            (false, false, true, true),
            "swapping prod/e2e roots must be detected"
        );

        let swapped_filters = correct
            .replace("erc7730-known-calls-e2e.bloom", "TEMP_FILTER")
            .replace("erc7730-known-calls.bloom", "erc7730-known-calls-e2e.bloom")
            .replace("TEMP_FILTER", "erc7730-known-calls.bloom");
        assert_eq!(
            erc7730_root_filter_cfg_matches(&swapped_filters, &prod, &e2e),
            (true, true, false, false),
            "swapping prod/e2e omission filters must be detected"
        );
    }

    fn provenance_fixture(
        prod: dbgen::erc7730::CatalogueProvenance,
        e2e: dbgen::erc7730::CatalogueProvenance,
    ) -> String {
        let mut blocks = vec![
            erc7730_provenance_marker(prod, false),
            erc7730_provenance_marker(e2e, true),
        ];
        blocks.extend(erc7730_provenance_fence_markers(prod, false));
        blocks.extend(erc7730_provenance_fence_markers(e2e, true));
        blocks.join("\n\n")
    }

    #[test]
    fn erc7730_codegen_check_requires_dev_provenance_fences() {
        use dbgen::erc7730::CatalogueProvenance::DevUnattested;

        let correct = provenance_fixture(DevUnattested, DevUnattested);
        assert_eq!(
            erc7730_provenance_cfg_matches(&correct, DevUnattested, DevUnattested),
            (true, true, true, true)
        );

        let prod_fence = erc7730_provenance_fence_markers(DevUnattested, false)
            .into_iter()
            .next()
            .unwrap();
        let deleted = correct.replacen(&prod_fence, "", 1);
        assert_eq!(
            erc7730_provenance_cfg_matches(&deleted, DevUnattested, DevUnattested),
            (true, true, false, true),
            "deleting the production dev-root fence must drift-fail"
        );

        let e2e_fence = erc7730_provenance_fence_markers(DevUnattested, true)
            .into_iter()
            .next()
            .unwrap();
        let wrong_cfg = e2e_fence.replace(
            "all(feature = \"e2e-test\"",
            "all(not(feature = \"e2e-test\")",
        );
        let mutated = correct.replacen(&e2e_fence, &wrong_cfg, 1);
        assert_eq!(
            erc7730_provenance_cfg_matches(&mutated, DevUnattested, DevUnattested),
            (true, true, true, false),
            "moving the e2e fence under the production cfg must drift-fail"
        );

        let block_commented = format!("/*\n{correct}\n*/");
        assert_eq!(
            erc7730_provenance_cfg_matches(&block_commented, DevUnattested, DevUnattested,),
            (false, false, false, false),
            "security markers preserved only inside a block comment are inactive"
        );

        let raw_string = format!("const _: &str = r###\"{correct}\"###;");
        assert_eq!(
            erc7730_provenance_cfg_matches(&raw_string, DevUnattested, DevUnattested),
            (false, false, false, false),
            "security markers copied into a raw string are inactive"
        );
    }

    #[test]
    fn erc7730_codegen_check_requires_verified_provenance_fences() {
        use dbgen::erc7730::CatalogueProvenance::Erc8176Verified;

        let correct = provenance_fixture(Erc8176Verified, Erc8176Verified);
        assert_eq!(
            erc7730_provenance_cfg_matches(&correct, Erc8176Verified, Erc8176Verified,),
            (true, true, true, true)
        );

        let prod_fence = erc7730_provenance_fence_markers(Erc8176Verified, false)
            .into_iter()
            .next()
            .unwrap();
        let altered = prod_fence.replace(
            "feature = \"erc7730-dev-unattested\"",
            "not(feature = \"erc7730-dev-unattested\")",
        );
        let mutated = correct.replacen(&prod_fence, &altered, 1);
        assert_eq!(
            erc7730_provenance_cfg_matches(&mutated, Erc8176Verified, Erc8176Verified,),
            (true, true, false, true),
            "mutating the verified-root warning-feature fence must drift-fail"
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
/// Vendors the COMPILABLE SUBSET of the upstream registry into the repo (default
/// `secure/data/erc7730-registry/`) so the firmware-pinned root can be rebuilt
/// from in-repo sources (reproducible builds / CI). Copies every descriptor that
/// contributes ≥ 1 leaf (via `build_db_tolerant`) PLUS every include template
/// (`ercs/*.json`, `common-*.json`), preserving the registry-relative tree so
/// `includes` still resolve, then VERIFIES the vendored tree rebuilds the
/// identical Merkle root (the faithfulness proof).
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
    let input = registry_root.join("registry");

    // 1. Tolerant build over the registry → the survivor descriptor sources.
    let (result, _skips) =
        match dbgen::erc7730::build_db_tolerant(&input, &policy_path, Some(&registry_root)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vendor-registry: registry build: {e}");
                return ExitCode::FAILURE;
            }
        };
    let orig_root = result.root;
    let descriptor_count = result
        .entries
        .iter()
        .map(|e| &e.source)
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    // 2. Vendor every `*.json` in each survivor descriptor's PROJECT DIR (so its
    //    sibling include templates — `common-*.json`, `<proj>-common-*.json`,
    //    etc., whatever they're named — come along) plus all `ercs/*.json`.
    //    Include resolution is sibling- or `../../ercs/`-relative, so this is
    //    the complete closure; the faithfulness check below proves it.
    let mut dirs: std::collections::BTreeSet<PathBuf> = result
        .entries
        .iter()
        .filter_map(|e| e.source.parent().map(PathBuf::from))
        .collect();
    dirs.insert(registry_root.join("ercs"));
    let mut files: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    for dir in &dirs {
        collect_dir_jsons(dir, &mut files);
    }
    let support_count = files.len().saturating_sub(descriptor_count);

    // 3. Clean the tool-managed subdirs, then copy preserving registry-relative paths.
    for sub in ["registry", "ercs"] {
        let _ = fs::remove_dir_all(out.join(sub));
    }
    let mut copied = 0usize;
    for src in &files {
        let Ok(rel) = src.strip_prefix(&registry_root) else {
            continue;
        };
        let dst = out.join(rel);
        if let Some(parent) = dst.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("vendor-registry: mkdir {}: {e}", parent.display());
                return ExitCode::FAILURE;
            }
        }
        if let Err(e) = fs::copy(src, &dst) {
            eprintln!("vendor-registry: copy {}: {e}", src.display());
            return ExitCode::FAILURE;
        }
        copied += 1;
    }

    // 4. Reproducibility proof: the vendored tree must rebuild the IDENTICAL root.
    let (vresult, _) =
        match dbgen::erc7730::build_db_tolerant(&out.join("registry"), &policy_path, Some(&out)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("vendor-registry: rebuild from vendored tree: {e}");
                return ExitCode::FAILURE;
            }
        };
    if vresult.root != orig_root {
        eprintln!(
            "vendor-registry: FAITHFULNESS CHECK FAILED — vendored root {} != registry root {} \
             (an include template is missing from the vendored subset)",
            hex_lower(&vresult.root),
            hex_lower(&orig_root)
        );
        return ExitCode::FAILURE;
    }

    println!("vendored {copied} files ({descriptor_count} leaf-bearing descriptors + {support_count} sibling/template files)");
    println!("out:   {}", out.display());
    println!(
        "root:  {} (reproduced from the vendored tree ✓)",
        hex_lower(&orig_root)
    );
    println!("leaves: {}", vresult.leaf_count);
    ExitCode::SUCCESS
}

/// Collect every `*.json` under `dir` (recursively, skipping `tests/` fixture
/// dirs and `*.tests.json`) — both descriptors and their sibling include
/// templates. Used to vendor a whole project dir so any `includes` resolves.
fn collect_dir_jsons(dir: &std::path::Path, out: &mut std::collections::BTreeSet<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            collect_dir_jsons(&p, out);
        } else if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".json") && !name.contains(".tests.") {
                out.insert(p);
            }
        }
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
