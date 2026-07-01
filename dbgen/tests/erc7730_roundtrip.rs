//! Integration test for the ERC-7730 descriptor pipeline.
//!
//! Runs end-to-end against the checked-in seed corpus:
//!   1. Compile every `secure/data/erc7730/*.json` descriptor.
//!   2. Build the Merkle tree.
//!   3. For each leaf:
//!        - Reconstruct the synthetic trailer the companion would
//!          ship (`[u16 ir_len][ir][u32 leaf_index][u32 proof_depth][proof]`).
//!        - Hand the trailer to `pqsigner_erc7730::bundle::verify_erc7730_bundle`,
//!          which is the same byte-for-byte verifier the secure firmware
//!          uses on-device.
//!        - Cross-check the IR's `(chain_id, contract)` /
//!          `(domain_separator)` binding via
//!          `pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712}`.
//!
//! Also exercises the host-side compiler against a synthetic in-memory
//! corpus (one contract + one EIP-712 descriptor) so this test does
//! not depend on the real `secure/data/erc7730/` corpus for its smoke
//! coverage — the seed corpus is exercised separately via the embedded
//! `build_db_seed_corpus` unit test inside `dbgen::erc7730`.
//!
//! See `docs/archive/handoff-erc7730-phase2.md` §"Verification recipe" — this
//! test is what that recipe's step 2 (`cargo test -p dbgen --test
//! erc7730_roundtrip`) refers to.

use std::path::PathBuf;

use dbgen::erc7730::{
    build_db, build_db_tolerant, load_policy, round_trip_check, try_compile_one,
    Erc7730BuildResult,
};
use pqsigner_erc7730::abi::container_field;
use pqsigner_erc7730::binding::{cross_check_contract, cross_check_eip712};
use pqsigner_erc7730::bundle::{verify_erc7730_bundle, MAX_ERC7730_BUNDLE_LEN};
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir, PathOp, CTX_CONTRACT, CTX_EIP712};
use pqsigner_erc7730::walker::path_bytes;
use pqsigner_tx_core::hash::keccak256;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build_seed() -> Erc7730BuildResult {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    build_db(&dir, &policy).expect("build seed corpus")
}

/// The PROD catalog — the vendored upstream registry, built tolerantly (the
/// corpus switch). This is what `tools/companion-stub/erc7730_db.bin` and the
/// firmware-pinned `ERC7730_DESCRIPTORS_ROOT` are built from, so a companion
/// trailer cut from that blob must verify against THIS root.
fn build_registry() -> Erc7730BuildResult {
    let root = workspace_root();
    let reg = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let (res, _skips) =
        build_db_tolerant(&reg.join("registry"), &policy, Some(&reg)).expect("build registry corpus");
    res
}

/// ANTI-RECURRENCE GUARD. The vendored upstream registry
/// (`secure/data/erc7730-registry/`) is the SOURCE OF TRUTH and the pinned
/// prod corpus. A hand-authored render-test fixture in `secure/data/erc7730/`
/// must NOT duplicate a registry descriptor by `(chainId, contract)` — that is
/// exactly the redundancy the corpus switch removed (we had hand-authored
/// Aave/Lido/Tether/WETH that the registry already shipped). Render tests must
/// either exercise the REAL registry descriptor (via `build_registry()`), or
/// use a SYNTHETIC, non-registry address. Fails loudly if anyone reintroduces a
/// protocol fixture the registry already covers.
#[test]
fn fixtures_do_not_duplicate_the_registry() {
    use std::collections::BTreeSet;
    let fixtures = build_seed();
    let registry = build_registry();
    let reg: BTreeSet<(u64, [u8; 20])> =
        registry.entries.iter().map(|e| (e.chain_id, e.contract)).collect();
    let mut dups: Vec<String> = fixtures
        .entries
        .iter()
        .filter(|e| reg.contains(&(e.chain_id, e.contract)))
        .map(|e| {
            format!(
                "  {} — chain {} contract 0x{}",
                e.source.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                e.chain_id,
                hex::encode(e.contract),
            )
        })
        .collect();
    dups.sort();
    dups.dedup();
    assert!(
        dups.is_empty(),
        "hand-authored render fixture(s) in secure/data/erc7730/ duplicate the authoritative \
         vendored registry by (chainId, contract):\n{}\n\
         The registry (secure/data/erc7730-registry/) is the source of truth + the pinned prod \
         corpus. Repoint the render test at the REAL registry descriptor (`build_registry()`), or \
         use a SYNTHETIC non-registry address. Never hand-author a descriptor for a protocol the \
         registry already covers.",
        dups.join("\n"),
    );
}

fn extract_proof(blob: &[u8], leaf_index: usize, proof_depth: usize) -> Vec<[u8; 32]> {
    // Catalog header layout — see `dbgen::erc7730` module doc.
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let base = proofs_off + leaf_index * proof_depth * 32;
    (0..proof_depth)
        .map(|j| {
            let off = base + j * 32;
            let mut h = [0u8; 32];
            h.copy_from_slice(&blob[off..off + 32]);
            h
        })
        .collect()
}

fn proof_depth(blob: &[u8]) -> usize {
    u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize
}

fn synth_bundle(ir: &[u8], leaf_index: u32, proof: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + ir.len() + 4 + 4 + proof.len() * 32);
    buf.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    buf.extend_from_slice(ir);
    buf.extend_from_slice(&leaf_index.to_be_bytes());
    buf.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    for h in proof {
        buf.extend_from_slice(h);
    }
    buf
}

#[test]
fn seed_corpus_compiles_and_round_trips() {
    // The hand-authored `secure/data/erc7730/` is now a synthetic-only
    // render-test corpus (1 leaf), so the Merkle round-trip runs against the
    // PROD corpus — the vendored registry — which is what `db_roots.rs` pins
    // and where the ≥6-leaf sanity floor still means something.
    let res = build_registry();
    assert!(
        res.leaf_count >= 6,
        "registry corpus shrunk below sanity threshold: {} leaves",
        res.leaf_count
    );
    round_trip_check(&res).expect("round-trip");
}

#[test]
fn seed_corpus_bundles_verify_against_on_device_parser() {
    let res = build_seed();
    let pd = proof_depth(&res.blob);

    for (i, entry) in res.entries.iter().enumerate() {
        let proof = extract_proof(&res.blob, i, pd);
        let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);

        assert!(
            bundle.len() <= MAX_ERC7730_BUNDLE_LEN,
            "{}: bundle {} > MAX ({})",
            entry.source.display(),
            bundle.len(),
            MAX_ERC7730_BUNDLE_LEN
        );

        let verified = verify_erc7730_bundle(&bundle, &res.root).unwrap_or_else(|e| {
            panic!(
                "verify_erc7730_bundle failed on leaf {} ({}): {e:?}",
                i,
                entry.source.display()
            )
        });

        assert_eq!(verified.ir.chain_id, entry.chain_id);
        assert_eq!(verified.ir.contract, entry.contract);
        assert_eq!(verified.ir.descriptor_hash, entry.descriptor_hash);

        // Round-trip the context cross-check as the on-device caller
        // would: synthesize a tx envelope / EIP-712 domain that
        // matches this entry, then call the corresponding binding.
        if entry.context_kind == CTX_CONTRACT {
            assert!(matches!(verified.ir.context_kind, ContextKind::Contract));
            cross_check_contract(&verified.ir, entry.chain_id, &entry.contract).unwrap_or_else(
                |e| {
                    panic!(
                        "cross_check_contract failed for leaf {} ({}): {e:?}",
                        i,
                        entry.source.display()
                    )
                },
            );
        } else if entry.context_kind == CTX_EIP712 {
            assert!(matches!(verified.ir.context_kind, ContextKind::Eip712));
            cross_check_eip712(
                &verified.ir,
                entry.chain_id,
                &verified.ir.domain_separator,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "cross_check_eip712 failed for leaf {} ({}): {e:?}",
                    i,
                    entry.source.display()
                )
            });
        } else {
            panic!(
                "unknown context_kind 0x{:02x} on leaf {}",
                entry.context_kind, i
            );
        }
    }
}

#[test]
fn binding_mismatch_is_rejected() {
    // Any chain_id flip in the cross-check MUST surface as a
    // BindingError::ChainIdMismatch — same protection the on-device
    // dispatcher relies on.
    let res = build_seed();
    let entry = res
        .entries
        .iter()
        .find(|e| e.context_kind == CTX_CONTRACT)
        .expect("seed corpus has at least one contract-context leaf");
    let pd = proof_depth(&res.blob);
    let proof = extract_proof(&res.blob, entry.leaf_index, pd);
    let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
    let v = verify_erc7730_bundle(&bundle, &res.root).expect("bundle verifies");

    let wrong_chain = entry.chain_id.wrapping_add(1);
    let err = cross_check_contract(&v.ir, wrong_chain, &entry.contract).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::binding::BindingError::ChainIdMismatch),
        "expected ChainIdMismatch, got {err:?}"
    );

    let mut wrong_contract = entry.contract;
    wrong_contract[0] ^= 0x01;
    let err = cross_check_contract(&v.ir, entry.chain_id, &wrong_contract).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::binding::BindingError::ContractMismatch),
        "expected ContractMismatch, got {err:?}"
    );
}

#[test]
fn tampered_proof_is_rejected() {
    // Flip one byte of the proof and verify the bundle now fails. This
    // is the canonical "did we actually bind?" check.
    let res = build_seed();
    let entry = &res.entries[0];
    let pd = proof_depth(&res.blob);
    let mut proof = extract_proof(&res.blob, entry.leaf_index, pd);
    if !proof.is_empty() {
        proof[0][0] ^= 0xff;
        let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
        let err = verify_erc7730_bundle(&bundle, &res.root).unwrap_err();
        assert!(
            matches!(err, pqsigner_erc7730::bundle::BundleError::Merkle),
            "expected Merkle, got {err:?}"
        );
    }
}

/// Lock the container-field index constants in `pqsigner_erc7730::abi`
/// to the host emitter's keccak-prefix convention. The on-device
/// walker indexes `@.value` / `@.to` / etc. by exactly these `u16`
/// values; any drift breaks every existing `erc7730_db.bin`.
/// The Python companion stub at `tools/companion-stub/erc7730_trailer.py`
/// must produce a byte-for-byte trailer that the on-device parser
/// accepts. Phase 3 e2e relies on this — if the stub drifts from the
/// catalog blob layout, every QEMU smoke test fails opaquely.
#[test]
fn companion_stub_trailer_verifies_against_on_device() {
    let root_dir = workspace_root();
    let db_path = root_dir.join("tools/companion-stub/erc7730_db.bin");
    let stub_path = root_dir.join("tools/companion-stub/erc7730_trailer.py");
    if !db_path.exists() || !stub_path.exists() {
        eprintln!("(skipped) companion stub or db missing");
        return;
    }
    // USDT mainnet — a Contract-context descriptor in the seed corpus.
    let usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    let out = std::process::Command::new("python3")
        .arg(&stub_path)
        .arg("--db")
        .arg(&db_path)
        .arg("--chain")
        .arg("1")
        .arg("--contract")
        .arg(usdt)
        .output()
        .expect("run companion stub");
    if !out.status.success() {
        panic!(
            "companion stub failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    let trailer = out.stdout;
    assert!(!trailer.is_empty(), "stub produced empty trailer");
    // The companion blob IS the registry (prod) catalog, so the trailer must
    // verify against the registry root (== the pinned `ERC7730_DESCRIPTORS_ROOT`),
    // NOT the hand-authored render-test fixtures' root.
    let result = build_registry();
    let v = verify_erc7730_bundle(&trailer, &result.root)
        .expect("trailer verifies against pinned root");
    assert_eq!(v.ir.chain_id, 1, "chain_id from IR");
    let want_addr =
        hex::decode("dAC17F958D2ee523a2206206994597C13D831ec7").unwrap();
    assert_eq!(&v.ir.contract, &want_addr[..], "contract from IR");
    assert!(
        matches!(v.ir.context_kind, ContextKind::Contract),
        "Contract context"
    );
}

#[test]
fn container_field_constants_match_keccak_prefix() {
    fn prefix(name: &str) -> u16 {
        let h = keccak256(name.as_bytes());
        u16::from_be_bytes([h[0], h[1]])
    }
    assert_eq!(container_field::VALUE, prefix("value"));
    assert_eq!(container_field::TO, prefix("to"));
    assert_eq!(container_field::FROM, prefix("from"));
    assert_eq!(container_field::CHAIN_ID, prefix("chainId"));
    assert_eq!(container_field::NONCE, prefix("nonce"));
}

/// Every path program the host emitter writes into the seed corpus
/// must parse cleanly via the on-device walker's path-extraction
/// helper (length prefix valid, opcodes recognised, args sized
/// correctly). Catches "host emits a byte the walker rejects" drift
/// without needing a populated ABI tree.
#[test]
fn seed_corpus_path_programs_parse() {
    let result = build_seed();
    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("ir parses");
        for fmt in ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            for field in fmt.fields() {
                let field = field.expect("field entry parses");
                if field.path_off == 0 {
                    continue;
                }
                let prog = path_bytes(&ir, field.path_off).unwrap_or_else(|e| {
                    panic!(
                        "path_bytes failed for {:?} field {:?}: {:?}",
                        ir.contract, field.label, e
                    )
                });
                assert!(
                    !prog.is_empty(),
                    "empty program at non-zero offset (chain {} contract {:?} field {:?})",
                    ir.chain_id,
                    ir.contract,
                    field.label,
                );
                // First opcode must be a root.
                let root = PathOp::try_from(prog[0]).unwrap_or_else(|_| {
                    panic!(
                        "unknown root opcode 0x{:02X} at field {:?}",
                        prog[0], field.label
                    )
                });
                assert!(
                    matches!(
                        root,
                        PathOp::RootStructured
                            | PathOp::RootContainer
                            | PathOp::RootMetadata
                    ),
                    "first opcode must be a root, got {:?}",
                    root,
                );
                // Every subsequent opcode + arg must fit; walk the
                // stream to verify alignment.
                let mut p = 1;
                while p < prog.len() {
                    let op = PathOp::try_from(prog[p]).unwrap_or_else(|_| {
                        panic!(
                            "unknown opcode 0x{:02X} mid-program (chain {} field {:?})",
                            prog[p], ir.chain_id, field.label
                        )
                    });
                    p += 1;
                    p += match op {
                        PathOp::RootStructured
                        | PathOp::RootContainer
                        | PathOp::RootMetadata => panic!(
                            "Root opcode {:?} mid-descent in field {:?}",
                            op, field.label,
                        ),
                        PathOp::FieldIdx => 2,
                        PathOp::ArrayIdx => 4,
                        PathOp::ArraySlice => 8,
                        PathOp::ArrayLast | PathOp::ArrayAll | PathOp::FollowOffset => 0,
                    };
                    assert!(
                        p <= prog.len(),
                        "opcode {:?} overruns program in field {:?}",
                        op,
                        field.label
                    );
                }
            }
        }
    }
}

/// Host-side wire-format check for the param TLV blob at every
/// `FieldEntry.param_off`. Confirms the host emitter (`dbgen::erc7730::
/// compile_params` + `push_tlv`) produces blobs that satisfy the
/// on-device parser's invariants:
///
///   - `pool[param_off]` is the blob length byte (or `param_off == 0`).
///   - The inner stream is `[tag][len][payload]*` with cursor staying
///     within `blob_len` bytes.
///   - Every tag is in the known 0x30..=0x40 space.
///   - Fixed-width tags carry the documented payload size.
///
/// This complements the per-renderer unit tests in
/// `sphincs-tz-secure::tx::erc7730_render::params` by validating the
/// production emitter's output across every seed-corpus IR.
#[test]
fn seed_corpus_param_tlv_blobs_are_well_formed() {
    let result = build_seed();
    for entry in &result.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("ir parses");
        for fmt in ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            for field in fmt.fields() {
                let field = field.expect("field entry parses");
                if field.param_off == 0 {
                    continue;
                }
                let off = field.param_off as usize;
                let blob_len = *ir.pool.get(off).unwrap_or_else(|| {
                    panic!(
                        "param_off {} out of range for {:?} field {:?}",
                        off, ir.contract, field.label
                    )
                }) as usize;
                let body = ir.pool.get(off + 1..off + 1 + blob_len).unwrap_or_else(|| {
                    panic!(
                        "param blob_len {} overruns pool for {:?} field {:?}",
                        blob_len, ir.contract, field.label
                    )
                });
                let mut cursor = 0usize;
                while cursor < body.len() {
                    assert!(
                        cursor + 2 <= body.len(),
                        "truncated TLV header in {:?} field {:?}",
                        ir.contract,
                        field.label
                    );
                    let tag = body[cursor];
                    let len = body[cursor + 1] as usize;
                    cursor += 2;
                    assert!(
                        cursor + len <= body.len(),
                        "TLV tag 0x{:02X} overruns blob in {:?} field {:?}",
                        tag,
                        ir.contract,
                        field.label
                    );
                    // Tag must be in the documented space (0x30..=0x40;
                    // 0x40 = PARAM_CONST_VALUE for path-less constant fields).
                    assert!(
                        (0x30u8..=0x40).contains(&tag),
                        "unknown TLV tag 0x{:02X} in {:?} field {:?}",
                        tag,
                        ir.contract,
                        field.label
                    );
                    // Per-tag width invariants.
                    match tag {
                        0x31 => assert_eq!(
                            len, 20,
                            "PARAM_TOKEN must be 20 B in {:?}",
                            field.label
                        ),
                        0x32 => assert_eq!(
                            len, 32,
                            "PARAM_THRESHOLD must be 32 B in {:?}",
                            field.label
                        ),
                        0x34 | 0x35 | 0x36 | 0x38 | 0x3A => assert_eq!(
                            len, 1,
                            "fixed-1-byte tag 0x{:02X} in {:?}",
                            tag, field.label
                        ),
                        0x37 => assert_eq!(
                            len, 2,
                            "PARAM_ENUM_REF must be 2 B in {:?}",
                            field.label
                        ),
                        0x3C => assert_eq!(
                            len, 4,
                            "PARAM_NESTED_SELECTOR must be 4 B in {:?}",
                            field.label
                        ),
                        0x3D => assert_eq!(
                            len, 20,
                            "PARAM_NESTED_CALLEE must be 20 B in {:?}",
                            field.label
                        ),
                        0x3F => assert!(
                            (1..=255).contains(&len),
                            "PARAM_VISIBILITY must be ≥1 B in {:?}",
                            field.label
                        ),
                        _ => {} // variable-width tags: 0x30, 0x33, 0x39, 0x3B, 0x3E
                    }
                    cursor += len;
                }
                assert_eq!(
                    cursor,
                    body.len(),
                    "param blob has trailing bytes in {:?} field {:?}",
                    ir.contract,
                    field.label
                );
            }
        }
    }
}

#[test]
fn wrong_root_is_rejected() {
    let res = build_seed();
    let entry = &res.entries[0];
    let pd = proof_depth(&res.blob);
    let proof = extract_proof(&res.blob, entry.leaf_index, pd);
    let bundle = synth_bundle(&entry.ir_bytes, entry.leaf_index as u32, &proof);
    let bad_root = [0xAAu8; 32];
    let err = verify_erc7730_bundle(&bundle, &bad_root).unwrap_err();
    assert!(
        matches!(err, pqsigner_erc7730::bundle::BundleError::Merkle),
        "expected Merkle, got {err:?}"
    );
}

/// CURATION GUARD (re-vendor durability). The single-hop Uniswap V3 swaps
/// (`exactInputSingle` / `exactOutputSingle`) clear-sign ONLY because the vendored
/// descriptor hides the redundant `sqrtPriceLimitX96` price bound
/// (`visible:"never"`) to satisfy the H-3 tuple-member-completeness lint — a
/// curation that `xtask vendor-registry` would DROP when it re-copies from
/// upstream (which omits it). A STRICT compile of the vendored descriptor
/// succeeds only if EVERY format compiles: the curated single-hop pair AND the
/// Tier B slice/array tokenPaths (`exactInput`/`exactOutput` `params.path.[0:20]`/
/// `[-20:]`, V2 `swap*ForTokens` `path.[0]`/`[-1]`). So this fails LOUD if either
/// the curation is dropped on re-vendor or a Tier B slice regression lands —
/// exactly the two silent-regression paths the single-hop render tests don't cover.
#[test]
fn vendored_uniswap_v3_router_curation_and_slices_all_compile() {
    let root = workspace_root();
    let reg = root.join("secure/data/erc7730-registry");
    let desc = reg.join("registry/uniswap/calldata-UniswapV3Router02.json");
    let policy =
        load_policy(&root.join("secure/data/erc7730/policy.toml")).expect("load policy");
    let emitted = try_compile_one(&desc, &policy, Some(&reg)).expect(
        "vendored Uniswap V3 Router must compile strictly — if this fails, the \
         sqrtPriceLimitX96 curation was dropped (re-vendor) or a Tier B slice regressed",
    );
    assert_eq!(emitted.len(), 1, "one Uniswap leaf (mainnet chain 1)");
    let ir = Erc7730Ir::parse(&emitted[0].ir_bytes).expect("Uniswap IR parses");
    let n = ir.format_iter().filter(|f| f.is_ok()).count();
    assert_eq!(
        n, 6,
        "all 6 Uniswap formats must compile (exactInputSingle, exactOutputSingle, \
         exactInput, exactOutput, swapExactTokensForTokens, swapTokensForExactTokens)"
    );
}

// ── Nested-EIP-712 v0x03 anchor emission (Phase 5 v1) ──────────────────────

fn hex_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// A length-prefixed pool entry (`[u8 len][bytes]`) at `off`; `off == 0` → empty.
fn pool_entry<'a>(ir: &Erc7730Ir<'a>, off: u16) -> &'a [u8] {
    if off == 0 {
        return &[];
    }
    let o = off as usize;
    let len = ir.pool[o] as usize;
    &ir.pool[o + 1..o + 1 + len]
}

/// First TLV payload with `tag` in a param blob (`[tag][len][payload]`*).
fn find_tlv(blob: &[u8], tag: u8) -> Option<&[u8]> {
    let mut c = 0usize;
    while c + 2 <= blob.len() {
        let t = blob[c];
        let l = blob[c + 1] as usize;
        let pl = &blob[c + 2..c + 2 + l];
        if t == tag {
            return Some(pl);
        }
        c += 2 + l;
    }
    None
}

struct SubField {
    format_op: u8,
    path_off: u16,
    param_off: u16,
}

/// Read one `{format_op, label_len, label, path_off, param_off}` sub-field
/// record from `payload` at `p`; returns the record + the next cursor.
fn read_subfield(payload: &[u8], p: usize) -> (SubField, usize) {
    let format_op = payload[p];
    let label_len = payload[p + 1] as usize;
    let q = p + 2 + label_len;
    let path_off = u16::from_be_bytes([payload[q], payload[q + 1]]);
    let param_off = u16::from_be_bytes([payload[q + 2], payload[q + 3]]);
    (
        SubField {
            format_op,
            path_off,
            param_off,
        },
        q + 4,
    )
}

/// The nested-struct anchor payload of `fmt` (the `PARAM_NESTED_STRUCT` = 0x41
/// TLV), or `None` if the format has no v0x03 anchor.
fn nested_anchor_payload(ir: &Erc7730Ir<'_>, type_hash: &[u8]) -> Option<Vec<u8>> {
    let fmt = ir
        .format_iter()
        .map(|f| f.expect("format parses"))
        .find(|f| f.type_hash[..] == type_hash[..])?;
    let payload = fmt
        .fields()
        .map(|f| f.expect("field parses"))
        .find_map(|fe| find_tlv(pool_entry(ir, fe.param_off), 0x41).map(<[u8]>::to_vec));
    payload.map(|pl| {
        // Also cross-check the E1 pin as a side effect of every lookup.
        assert_eq!(fmt.nested_descent_count, 1, "one nested descent point");
        pl
    })
}

fn keccak_hex(s: &str) -> String {
    let h = keccak256(s.as_bytes());
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Byte-level proof of the nested-EIP-712 v0x03 anchor emission (Phase 5 v1),
/// against the REAL shipped DB (the tolerant registry build — the one the pinned
/// Merkle root is cut from, so this is exactly what the device parses).
///
///  * `PermitSingle` → anchor: version 0x03, word_pos 0 (details is the FIRST
///    *member* — proves member order, not field order), foundry-pinned
///    `typeHash(PermitDetails)`, member_count 4, flags 0, addr_word_bmp 0x01
///    (only local word 0 = token is an address), two LOCAL sub-fields:
///      amount → tokenAmount, render FieldIdx(1), tokenPath FieldIdx(0)=token;
///      expiration → date(timestamp), render FieldIdx(2).
///    `nonce` (local word 3) + top-level `sigDeadline` stay hidden — the hash
///    still covers them (member_count pins the blob length; E5 + rule 3).
///  * `PermitTransferFrom` → the minimal binding (`TokenPermissions`, 2 members),
///    unlocked by the hand-curated `nonce` `visible:"never"` completeness field
///    (upstream omits it; guarded by
///    `vendored_permit2_transfer_from_curation_compiles`).
///  * `PermitBatch` (`PermitDetails[]`, array-of-struct) → DROPPED by the
///    pre-existing visibility gate (v1 scope boundary), so its format is ABSENT.
#[test]
fn permit2_nested_anchor_emission_is_byte_exact() {
    let registry = build_registry();
    let permit2 = hex_bytes("000000000022d473030f116ddee9f6b43ac78ba3");
    let leaf = registry
        .entries
        .iter()
        .find(|e| e.contract[..] == permit2[..])
        .expect("Permit2 leaf present in the shipped registry DB");
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");

    // ── PermitSingle ──
    let single = hex_bytes("f3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0");
    let payload = nested_anchor_payload(&ir, &single).expect("PermitSingle anchor present");
    assert_eq!(payload[0], 0x03, "structured v0x03 block (not the bare 0x01 belt)");
    assert_eq!(
        u16::from_be_bytes([payload[1], payload[2]]),
        0,
        "word_pos 0 — details is member 0 (member order, not field order)"
    );
    assert_eq!(
        &payload[3..35],
        &hex_bytes("65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678")[..],
        "pinned typeHash(PermitDetails) matches foundry"
    );
    assert_eq!(
        u16::from_be_bytes([payload[35], payload[36]]),
        4,
        "member_count 4 (PermitDetails' OWN word count — pins the blob length)"
    );
    assert_eq!(payload[37], 0, "flags: non-array");
    assert_eq!(payload[38], 0x01, "addr_word_bmp: only local word 0 (token) is address");
    assert_eq!(payload[39], 2, "two visible sub-fields (amount + expiration)");
    let (sf0, next) = read_subfield(&payload, 40);
    assert_eq!(sf0.format_op, 0x03, "sub-field 0 is tokenAmount");
    assert_eq!(
        pool_entry(&ir, sf0.path_off),
        [0x10, 0x20, 0x00, 0x01],
        "amount render path = RootStructured+FieldIdx(1) (local word 1)"
    );
    assert_eq!(
        find_tlv(pool_entry(&ir, sf0.param_off), 0x30).expect("tokenPath TLV"),
        [0x10, 0x20, 0x00, 0x00],
        "tokenPath = RootStructured+FieldIdx(0) (local word 0 = token)"
    );
    let (sf1, _) = read_subfield(&payload, next);
    assert_eq!(sf1.format_op, 0x05, "sub-field 1 is date");
    assert_eq!(
        pool_entry(&ir, sf1.path_off),
        [0x10, 0x20, 0x00, 0x02],
        "expiration render path = RootStructured+FieldIdx(2) (local word 2)"
    );
    assert_eq!(
        find_tlv(pool_entry(&ir, sf1.param_off), 0x36).expect("date-encoding TLV"),
        [0x00],
        "date encoding = timestamp"
    );

    // ── PermitTransferFrom (minimal binding — TokenPermissions, 2 members) ──
    // Unlocked by the hand-curated `nonce` `visible:"never"` field. word_pos 0
    // (permitted is member 0), pinned typeHash(TokenPermissions), member_count 2,
    // addr_word_bmp 0x01 (token), one sub-field (amount, tokenPath word 0).
    let ptf = hex_bytes("939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106");
    let payload = nested_anchor_payload(&ir, &ptf).expect("PermitTransferFrom anchor present");
    assert_eq!(payload[0], 0x03);
    assert_eq!(u16::from_be_bytes([payload[1], payload[2]]), 0, "permitted is member 0");
    assert_eq!(
        &payload[3..35],
        &hex_bytes("618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1")[..],
        "pinned typeHash(TokenPermissions)"
    );
    assert_eq!(u16::from_be_bytes([payload[35], payload[36]]), 2, "TokenPermissions has 2 members");
    assert_eq!(payload[37], 0, "non-array");
    assert_eq!(payload[38], 0x01, "token is address");
    assert_eq!(payload[39], 1, "one visible sub-field (amount)");
    let (ptf_sf0, _) = read_subfield(&payload, 40);
    assert_eq!(ptf_sf0.format_op, 0x03, "tokenAmount");
    assert_eq!(pool_entry(&ir, ptf_sf0.path_off), [0x10, 0x20, 0x00, 0x01], "amount = local word 1");
    assert_eq!(
        find_tlv(pool_entry(&ir, ptf_sf0.param_off), 0x30).expect("tokenPath TLV"),
        [0x10, 0x20, 0x00, 0x00],
        "tokenPath = local word 0 (token)"
    );

    // ── PermitBatch (array-of-struct) — v1 scope boundary: DROPPED, absent. ──
    let batch = hex_bytes(&keccak_hex(
        "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)\
         PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
    ));
    assert!(
        ir.format_iter()
            .map(|f| f.expect("format parses"))
            .all(|f| f.type_hash[..] != batch[..]),
        "PermitBatch (array-of-struct) must be absent in v1 (dropped by the visibility gate)"
    );
}

/// RE-VENDOR GUARD (Tier A curation discipline — mirrors
/// `vendored_uniswap_v3_router_curation_and_slices_all_compile`). Upstream's
/// Permit2 `PermitTransferFrom` OMITS its `nonce` member, so the EIP-712
/// completeness lint DROPS the whole format. We hand-curate a `nonce`
/// `visible:"never"` field into the vendored descriptor
/// (`secure/data/erc7730-registry/registry/uniswap/eip712-uniswap-permit2.json`)
/// to unlock it. `xtask vendor-registry` re-copying from upstream would SILENTLY
/// drop that curation; this fails LOUD if `PermitTransferFrom`
/// (typeHash `0x939c21a4…`) is no longer clear-signable in the shipped DB.
#[test]
fn vendored_permit2_transfer_from_curation_compiles() {
    let registry = build_registry();
    let permit2 = hex_bytes("000000000022d473030f116ddee9f6b43ac78ba3");
    let leaf = registry
        .entries
        .iter()
        .find(|e| e.contract[..] == permit2[..])
        .expect("Permit2 leaf present");
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let ptf = hex_bytes("939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106");
    assert!(
        ir.format_iter()
            .map(|f| f.expect("format parses"))
            .any(|f| f.type_hash[..] == ptf[..]),
        "PermitTransferFrom dropped — the `nonce` visible:never curation was lost \
         (re-vendored from upstream?). Re-apply it to \
         secure/data/erc7730-registry/registry/uniswap/eip712-uniswap-permit2.json"
    );
}
