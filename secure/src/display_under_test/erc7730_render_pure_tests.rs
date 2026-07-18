//! End-to-end render tests for the ERC-7730 / ERC-8213 display renderers.
//!
//! Each test builds a realistic transaction (chain + to + calldata),
//! verifies the firmware-pinned bundle via `verify_erc7730_bundle`, then
//! runs the on-device renderer at `super::erc7730::render_erc7730_pages`
//! and asserts the resulting 4-row × 16-col display pages line-by-line
//! against the strings a user would actually see on the device.
//!
//! Why this exists: existing tests cover the host pipeline (`dbgen`),
//! the bundle verifier, the path walker, the parameter parser, and the
//! per-formatter row primitives. Until now there was no test that
//! plumbed a full `(tx, calldata, descriptor) -> Pages -> rendered
//! strings` round-trip end-to-end. A regression that breaks the user-
//! visible row text (truncation, intent label, decimal alignment, ticker
//! lookup) would not have been caught by any unit test.
//!
//! Inputs are NOT hand-rolled IR fixtures. Shipping cases come from the real
//! registry through `dbgen`; nested renderer-only cases use process-private
//! copies compiled by the same dbgen after changing every explicit
//! `visible:"never"` to `visible:"always"`. The real unsafe sources are
//! separately asserted absent. UniswapX cannot be made into an equivalent safe
//! positive fixture (dynamic bytes expose only a hash, and showing all fields
//! exceeds the page budget), so those historical vectors are exclusion tests.

use std::path::PathBuf;

use pqsigner_erc7730::bundle::{verify_erc7730_bundle, VerifiedDescriptor};
use pqsigner_erc7730::display::primitives::write_addr_full;
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir};
use pqsigner_tx_core::hash::keccak256;

use crate::erc20::bundle::Erc20Metadata;
use crate::names::{NameMeta, NameResolver};
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

use super::dispatch::{pick_sign_pages, DispatchPageProofs};
use super::erc7730::{
    render_erc7730_pages, render_erc7730_pages_with_signer,
    render_erc7730_pages_with_signer_checked, INTENT_PUBLICATION_INTERPOLATED,
    INTENT_PUBLICATION_STATIC,
};
use super::erc8213::{
    append_fingerprint_page, fingerprint_final_set_proof, fingerprint_page_proof,
    Kind as Erc8213Kind, FINGERPRINT_CFI_EXPECTED,
};
use super::Pages;

// ───────────────────────────────────────────────────────────────────────
// One-shot seed-corpus build, cached across every test in this module.
// ───────────────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Compile the checked-in seed corpus into a Merkle catalog. Doing this
/// per-test is cheap (the seed dir is now a tiny synthetic-only render-test
/// corpus) and keeps each test self-contained — no `static` / `OnceLock`
/// plumbing required.
fn build_seed() -> dbgen::erc7730::Erc7730BuildResult {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    dbgen::erc7730::build_db(&dir, &policy).expect("compile seed corpus")
}

/// The PROD catalog — the vendored upstream registry, built tolerantly
/// (the corpus switch). This is what `tools/companion-stub/erc7730_db.bin`
/// and the firmware-pinned `ERC7730_DESCRIPTORS_ROOT` are built from, so a
/// render test that exercises a REAL protocol descriptor (Aave/Tether/WETH/
/// wstETH/…) must drive it from THIS root, not a hand-authored duplicate.
///
/// The registry build is several hundred ms and many tests use it, so memoize
/// it in a `OnceLock` — built once per test binary, not per test.
/// Returns a `&'static`, so callers pass it straight to `find_leaf(res, …)`
/// (NOT `&res`) and read `res.blob` / `res.root` directly.
fn build_registry() -> &'static dbgen::erc7730::Erc7730BuildResult {
    static REGISTRY: std::sync::OnceLock<dbgen::erc7730::Erc7730BuildResult> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let root = workspace_root();
        let reg = root.join("secure/data/erc7730-registry");
        let policy = root.join("secure/data/erc7730/policy.toml");
        let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
            .expect("build ERC-20 capability set");
        let (res, _skips) = dbgen::erc7730::build_db_tolerant_with_erc20_capabilities(
            &reg.join("registry"),
            &policy,
            Some(&reg),
            &erc20.capabilities,
        )
        .expect("build registry corpus");
        res
    })
}

/// Real descriptors whose nested renderer shapes are valuable test vectors but
/// which the shipping catalogue now correctly excludes because they contain
/// hidden non-address material. For renderer tests only, compile copies in a
/// process-private temporary registry after promoting both explicit
/// `visible:"never"` fields and the few legacy fields whose omitted visibility
/// defaults to hidden. This preserves the original ABI/type tree and runs
/// through the real dbgen compiler, while making the emitted fixture satisfy
/// the same strict hidden-material policy as production.
const SAFE_VISIBLE_NESTED_FIXTURES: &[(&str, &str)] = &[
    (
        "eip712-uniswap-permit2.json",
        "registry/uniswap/eip712-uniswap-permit2.json",
    ),
    (
        "eip712-SessionManager-FT.json",
        "registry/flyingtulip/eip712-SessionManager-FT.json",
    ),
];

fn build_safe_visible_nested_fixtures(
) -> &'static std::collections::BTreeMap<String, Vec<dbgen::erc7730::Emitted>> {
    static FIXTURES: std::sync::OnceLock<
        std::collections::BTreeMap<String, Vec<dbgen::erc7730::Emitted>>,
    > = std::sync::OnceLock::new();
    FIXTURES.get_or_init(|| {
        let source_root = workspace_root().join("secure/data/erc7730-registry");
        let temp_root = std::env::temp_dir().join(format!(
            "pqsigner-erc7730-safe-visible-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(temp_root.join("registry/uniswap"))
            .expect("create synthetic Uniswap fixture dir");
        std::fs::create_dir_all(temp_root.join("registry/flyingtulip"))
            .expect("create synthetic SessionManager fixture dir");

        // Every Uniswap fixture includes this context-only template.
        std::fs::copy(
            source_root.join("registry/uniswap/uniswap-common-eip712.json"),
            temp_root.join("registry/uniswap/uniswap-common-eip712.json"),
        )
        .expect("copy synthetic fixture include");

        let policy = dbgen::erc7730::Policy::default();
        let mut emitted_by_source = std::collections::BTreeMap::new();
        for &(source_name, relative) in SAFE_VISIBLE_NESTED_FIXTURES {
            let source = source_root.join(relative);
            let destination = temp_root.join(relative);
            let text = std::fs::read_to_string(&source).expect("read nested fixture source");
            assert!(
                text.contains("\"visible\": \"never\""),
                "fixture {source_name} must exercise the hidden-material gate"
            );
            let safe_text = text
                .replace("\"visible\": \"never\"", "\"visible\": \"always\"")
                // PermitBatch predates the explicit-visibility requirement on
                // its amount/tokenPath and expiration fields. Promote those
                // two omitted values in this process-private positive only.
                .replace(
                    "\"tokenPath\": \"details.[].token\"\n            }\n          }",
                    "\"tokenPath\": \"details.[].token\"\n            },\n            \"visible\": \"always\"\n          }",
                )
                // PermitSingle and PermitBatch both omitted visibility on the
                // nested expiration field; make both explicit test positives.
                .replace(
                    "\"encoding\": \"timestamp\"\n            }\n          }",
                    "\"encoding\": \"timestamp\"\n            },\n            \"visible\": \"always\"\n          }",
                );
            assert!(!safe_text.contains("\"visible\": \"never\""));
            std::fs::write(&destination, safe_text).expect("write safe nested fixture");
            let emitted = dbgen::erc7730::try_compile_one(&destination, &policy, Some(&temp_root))
                .unwrap_or_else(|e| panic!("safe visible fixture {source_name} must compile: {e}"));
            emitted_by_source.insert(source_name.to_string(), emitted);
        }
        let _ = std::fs::remove_dir_all(&temp_root);
        emitted_by_source
    })
}

fn safe_visible_nested_leaf(source_name: &str, chain_id: u64) -> &'static dbgen::erc7730::Emitted {
    build_safe_visible_nested_fixtures()
        .get(source_name)
        .and_then(|entries| entries.iter().find(|entry| entry.chain_id == chain_id))
        .unwrap_or_else(|| panic!("no safe visible nested fixture for {source_name} on {chain_id}"))
}

/// Build a compiler-authenticated C1 `string` descriptor, then coherently
/// change both its authenticated dynamic-kind and schema-v4 terminal-kind TLVs
/// to `bytes`. Production dbgen refuses to emit arbitrary dynamic `bytes`; this
/// process-private fixture proves the device parser independently refuses the
/// now-forbidden `raw` + `DynamicBytes` pair.
fn opaque_bytes_runtime_fixture() -> &'static Vec<u8> {
    static FIXTURE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let temp_root = std::env::temp_dir().join(format!(
            "pqsigner-erc7730-opaque-bytes-runtime-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).expect("create opaque-bytes fixture dir");
        let source = temp_root.join("opaque-bytes-runtime.json");
        std::fs::write(
            &source,
            r#"{
              "context": { "contract": { "deployments": [
                { "chainId": 1, "address": "0xbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc" }
              ] } },
              "metadata": { "owner": "Test", "contractName": "Runtime Belt" },
              "display": { "formats": {
                "probe(string data)": {
                  "intent": "Probe",
                  "fields": [
                    { "path": "data", "label": "Data", "format": "raw", "visible": "always" }
                  ]
                }
              } }
            }"#,
        )
        .expect("write opaque-bytes fixture");
        let mut emitted = dbgen::erc7730::try_compile_one(
            &source,
            &dbgen::erc7730::Policy::default(),
            Some(&temp_root),
        )
        .expect("safe string source compiles");
        let mut ir_bytes = emitted
            .pop()
            .expect("one deployment emits one leaf")
            .ir_bytes;
        let tag = pqsigner_erc7730::render::params::PARAM_DYNAMIC_KIND;
        let string_kind = pqsigner_erc7730::render::params::DYNAMIC_KIND_STRING;
        let bytes_kind = pqsigner_erc7730::render::params::DYNAMIC_KIND_BYTES;
        let pattern = [tag, 1, string_kind];
        let hits: Vec<usize> = (pqsigner_erc7730::ir::HEADER_LEN..ir_bytes.len().saturating_sub(2))
            .filter(|&i| ir_bytes[i..i + 3] == pattern)
            .collect();
        assert_eq!(hits.len(), 1, "fixture must have one dynamic-kind TLV");
        ir_bytes[hits[0] + 2] = bytes_kind;
        let terminal_tag = pqsigner_erc7730::render::params::PARAM_TERMINAL_KIND;
        let string_terminal = pqsigner_erc7730::render::policy::TerminalKind::DynamicString as u8;
        let bytes_terminal = pqsigner_erc7730::render::policy::TerminalKind::DynamicBytes as u8;
        let terminal_pattern = [terminal_tag, 1, string_terminal];
        let terminal_hits: Vec<usize> = (pqsigner_erc7730::ir::HEADER_LEN
            ..ir_bytes.len().saturating_sub(2))
            .filter(|&i| ir_bytes[i..i + 3] == terminal_pattern)
            .collect();
        assert_eq!(
            terminal_hits.len(),
            1,
            "fixture must have one terminal-kind TLV"
        );
        ir_bytes[terminal_hits[0] + 2] = bytes_terminal;
        let _ = std::fs::remove_dir_all(&temp_root);
        ir_bytes
    })
}

fn assert_opaque_bytes_runtime_rejected(data: &[u8]) {
    // Keep a realistically framed payload so these tests still cover both
    // printable and binary attacker inputs. Schema v4 refuses the descriptor
    // before payload-dependent rendering, which is stronger than the former
    // formatter-only belt and cannot create a lossy preview.
    let _calldata = calldata_sole_bytes(b"probe(string)", data);
    assert!(
        matches!(
            Erc7730Ir::parse(opaque_bytes_runtime_fixture()),
            Err(pqsigner_erc7730::ir::IrError::BadField)
        ),
        "raw DynamicBytes must fail authenticated-IR admission"
    );
}

fn assert_registry_source_excluded(source_name: &str) {
    assert!(
        !build_registry().entries.iter().any(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
        }),
        "unsafe or incomplete descriptor {source_name} must remain absent from the catalogue"
    );
}

#[test]
fn eip712_hash_only_values_have_no_verified_runtime_leaf() {
    let registry = build_registry();
    for source_name in ["eip712-withdraw.json", "eip712-SpotOrderCancel.json"] {
        assert!(
            !registry.entries.iter().any(|entry| {
                entry.source.file_name().and_then(|n| n.to_str()) == Some(source_name)
            }),
            "{source_name} contains visible EIP-712 dynamic strings whose encodeData words are \
             hashes, not values; catalogue absence is required so no verified descriptor can \
             reach the secure renderer"
        );
    }
}

#[test]
fn explicit_hidden_material_descriptors_have_no_verified_runtime_leaf() {
    for source_name in [
        "eip712-permit-ethereum-link.json",
        "eip712-uniswap-permit2.json",
        "eip712-UniswapX-ExclusiveDutchOrder.json",
        "eip712-UniswapX-DutchOrder.json",
        "eip712-UniswapX-LimitOrder.json",
        "eip712-uniswap-V2DutchOrder.json",
        "eip712-SessionManager-FT.json",
    ] {
        assert_registry_source_excluded(source_name);
    }
}

/// Locate a leaf by `(source filename, chain_id)` so a multi-chain
/// descriptor (USDT on mainnet vs Polygon) is unambiguous.
fn find_leaf<'a>(
    res: &'a dbgen::erc7730::Erc7730BuildResult,
    source_name: &str,
    chain_id: u64,
) -> &'a dbgen::erc7730::Emitted {
    res.entries
        .iter()
        .find(|e| {
            e.chain_id == chain_id
                && e.source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map_or(false, |n| n == source_name)
        })
        .unwrap_or_else(|| {
            panic!(
                "no leaf for {source_name} on chain {chain_id}; entries: {:?}",
                res.entries
                    .iter()
                    .map(|e| (e.source.display().to_string(), e.chain_id))
                    .collect::<Vec<_>>()
            )
        })
}

/// Reconstruct the bundle the companion would ship for the on-wire
/// verifier. Mirrors `dbgen/tests/erc7730_roundtrip.rs::synth_bundle`
/// (kept inline here so this module doesn't depend on the dbgen test
/// helpers).
fn synth_bundle(blob: &[u8], ir_bytes: &[u8], leaf_index: usize) -> Vec<u8> {
    let proof_depth = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let proof_base = proofs_off + leaf_index * proof_depth * 32;

    let mut buf = Vec::with_capacity(2 + ir_bytes.len() + 4 + 4 + proof_depth * 32);
    buf.extend_from_slice(&(ir_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(ir_bytes);
    buf.extend_from_slice(&(leaf_index as u32).to_be_bytes());
    buf.extend_from_slice(&(proof_depth as u32).to_be_bytes());
    for j in 0..proof_depth {
        let off = proof_base + j * 32;
        buf.extend_from_slice(&blob[off..off + 32]);
    }
    buf
}

// ───────────────────────────────────────────────────────────────────────
// Tx + calldata builders.
// ───────────────────────────────────────────────────────────────────────

fn u256_from_u64(n: u64) -> U256 {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&n.to_be_bytes());
    U256(out)
}

/// "Approve max" — the value that triggers the unlimited-amount branch
/// in tokenAmount rendering against the descriptor's threshold param.
fn u256_max() -> U256 {
    U256([0xFFu8; 32])
}

/// Plain receiver-tx envelope. ERC-7730 path expects `tx.to ==
/// descriptor.contract`; the caller fills `to` with the real contract
/// address per-test.
fn envelope(chain_id: u64, contract: [u8; 20]) -> Eip1559Tx {
    let mut tx = Eip1559Tx::default();
    tx.chain_id = chain_id;
    tx.nonce = 7;
    tx.to = Some(contract);
    tx.value = U256::default();
    tx.gas_limit = 100_000;
    tx.max_fee_per_gas = u256_from_u64(30_000_000_000);
    tx.max_priority_fee_per_gas = u256_from_u64(1_500_000_000);
    tx
}

/// ERC-20 `transfer(address,uint256)` calldata.
fn calldata_transfer(to: [u8; 20], amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    let mut to_padded = [0u8; 32];
    to_padded[12..].copy_from_slice(&to);
    data.extend_from_slice(&to_padded);
    data.extend_from_slice(&amount.0);
    data
}

/// ERC-20 `approve(address,uint256)` calldata.
fn calldata_approve(spender: [u8; 20], amount: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
    let mut sp_padded = [0u8; 32];
    sp_padded[12..].copy_from_slice(&spender);
    data.extend_from_slice(&sp_padded);
    data.extend_from_slice(&amount.0);
    data
}

/// `WETH9.deposit()` — zero-argument call. The amount the user is
/// wrapping is `@.value` (envelope's `value`), which the descriptor
/// pulls from the container path.
fn calldata_deposit() -> Vec<u8> {
    vec![0xd0, 0xe3, 0x0d, 0xb0]
}

/// Aave V3 `borrow(address asset, uint256 amount, uint256 interestRateMode,
/// uint16 referralCode, address onBehalfOf)` — all-static 5-word head.
/// Used to exercise the `enum` formatter on `interestRateMode`.
fn calldata_borrow(
    asset: [u8; 20],
    amount: U256,
    interest_rate_mode: U256,
    referral_code: u16,
    on_behalf_of: [u8; 20],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 5 * 32);
    let sel = keccak256(b"borrow(address,uint256,uint256,uint16,address)");
    data.extend_from_slice(&sel[..4]);
    let mut asset_w = [0u8; 32];
    asset_w[12..].copy_from_slice(&asset);
    data.extend_from_slice(&asset_w);
    data.extend_from_slice(&amount.0);
    data.extend_from_slice(&interest_rate_mode.0);
    let mut ref_w = [0u8; 32];
    ref_w[30..].copy_from_slice(&referral_code.to_be_bytes());
    data.extend_from_slice(&ref_w);
    let mut obo_w = [0u8; 32];
    obo_w[12..].copy_from_slice(&on_behalf_of);
    data.extend_from_slice(&obo_w);
    data
}

/// Aave V3 `repay(address asset,uint256 amount,uint256 interestRateMode,
/// address onBehalfOf)` — a safe all-visible format that retains real emitted
/// enum-table coverage after `borrow` was excluded for hiding `referralCode`.
fn calldata_repay(
    asset: [u8; 20],
    amount: U256,
    interest_rate_mode: U256,
    on_behalf_of: [u8; 20],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 4 * 32);
    let sel = keccak256(b"repay(address,uint256,uint256,address)");
    data.extend_from_slice(&sel[..4]);
    let mut asset_w = [0u8; 32];
    asset_w[12..].copy_from_slice(&asset);
    data.extend_from_slice(&asset_w);
    data.extend_from_slice(&amount.0);
    data.extend_from_slice(&interest_rate_mode.0);
    let mut obo_w = [0u8; 32];
    obo_w[12..].copy_from_slice(&on_behalf_of);
    data.extend_from_slice(&obo_w);
    data
}

/// Re-confirm the function selector we synthesised actually keccaks to
/// what the descriptor expects. Catches a "we mis-built the calldata"
/// bug before the renderer ever sees it. Mirrors the firmware's own
/// selector dispatch.
fn assert_selector_matches(ir: &Erc7730Ir<'_>, calldata: &[u8], text_sig: &str) {
    let sel = keccak256(text_sig.as_bytes());
    assert_eq!(
        &sel[..4],
        &calldata[..4],
        "test bug: calldata selector != keccak256({text_sig:?})[..4]"
    );
    let key: [u8; 4] = calldata[..4].try_into().unwrap();
    ir.find_format_by_selector(&key)
        .expect("ir format table well-formed")
        .unwrap_or_else(|| panic!("no format for {text_sig:?} in descriptor"));
}

// ───────────────────────────────────────────────────────────────────────
// Row assertion helpers — string-trim then compare.
// ───────────────────────────────────────────────────────────────────────

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    let end = row.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    String::from_utf8(row[..end].to_vec()).expect("rendered rows must be printable ASCII")
}

fn page_strs(pages: &Pages, page: usize) -> [String; 4] {
    let p = &pages.buf[page];
    [
        row_str(&p[0]),
        row_str(&p[1]),
        row_str(&p[2]),
        row_str(&p[3]),
    ]
}

/// Index of the semantic intent page in either catalogue-provenance mode.
///
/// Dev-unattested firmware prepends a mandatory warning page. Keep the same
/// semantic assertions useful in both builds, while also proving that the
/// warning has the exact trusted-display text whenever the feature is active.
fn intent_page_index(pages: &Pages) -> usize {
    let index = pqsigner_erc7730::display::render::intent::INTENT_BANNER_PAGES - 1;
    #[cfg(feature = "erc7730-dev-unattested")]
    {
        assert_eq!(
            page_strs(pages, 0),
            [
                "** DEV BUILD **".to_string(),
                "Unattested".to_string(),
                "descriptor".to_string(),
                "> next".to_string(),
            ]
        );
    }
    index
}

fn dump_pages(pages: &Pages) -> String {
    let mut out = String::new();
    for (i, page) in pages.as_slice().iter().enumerate() {
        out.push_str(&format!("--- page {i} ---\n"));
        for row in page.iter() {
            out.push_str(&format!("| {} |\n", row_str(row)));
        }
    }
    out
}

fn assert_all_pages_printable(pages: &Pages) {
    for (p, page) in pages.as_slice().iter().enumerate() {
        for (r, row) in page.iter().enumerate() {
            for (c, &b) in row.iter().enumerate() {
                assert!(
                    (0x20..=0x7E).contains(&b),
                    "page {p} row {r} col {c} byte {:#x} not printable\n{}",
                    b,
                    dump_pages(pages),
                );
            }
        }
    }
}

/// Find the first page whose row 0 trims to exactly `label`. Used to
/// locate a field page when the field-order is descriptor-driven and a
/// test doesn't want to over-pin on page indices.
fn find_page_by_label(pages: &Pages, label: &str) -> usize {
    for (i, page) in pages.as_slice().iter().enumerate() {
        if row_str(&page[0]) == label {
            return i;
        }
    }
    panic!(
        "no page with row 0 == {label:?}; full dump:\n{}",
        dump_pages(pages)
    );
}

fn assert_full_contract_identity_page(pages: &Pages, contract: &[u8; 20]) {
    let page = find_page_by_label(pages, "Token contract");
    let mut expected = [[b' '; DISPLAY_COLS]; 4];
    expected[0][..14].copy_from_slice(b"Token contract");
    let [_, r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, contract);
    assert_eq!(
        pages.buf[page], expected,
        "trusted pages must carry the exact bound token contract"
    );
}

fn assert_full_unverified_token_identity_page(pages: &Pages, contract: &[u8; 20]) {
    let page = find_page_by_label(pages, "Token (UNVERIFI~");
    let mut expected = [[b' '; DISPLAY_COLS]; 3];
    let [r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, contract);
    assert_eq!(
        pages.buf[page][1..4],
        expected,
        "unbound token pages must carry the exact signed token contract"
    );
}

fn find_full_nft_collection_page(pages: &Pages, collection: &[u8; 20]) -> usize {
    let mut expected = [[b' '; DISPLAY_COLS]; 3];
    let [r1, r2, r3] = &mut expected;
    write_addr_full(r1, r2, r3, collection);
    pages
        .as_slice()
        .iter()
        .position(|page| page[1..4] == expected)
        .unwrap_or_else(|| {
            panic!(
                "no page carries full NFT collection {}; dump:\n{}",
                hex::encode(collection),
                dump_pages(pages)
            )
        })
}

// ───────────────────────────────────────────────────────────────────────
// Per-corpus tests. One per representative descriptor + format.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_seed_corpus_compiles() {
    // `secure/data/erc7730/` is now a synthetic-only render-test corpus: the
    // protocol fixtures that used to live here were duplicates of the vendored
    // registry (the PROD corpus, exercised via `build_registry()` in the
    // repointed render tests). Only the synthetic non-registry fixtures remain,
    // so the floor is ≥1.
    let res = build_seed();
    assert!(
        res.leaf_count >= 1,
        "seed corpus has shrunk below the sanity floor ({} leaves)",
        res.leaf_count
    );
}

#[test]
#[ignore = "diagnostic — run with `--ignored` to dump the seed-corpus IR layout"]
fn diagnostic_dump_seed_corpus_path_offsets() {
    let res = build_seed();
    for entry in &res.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("seed IR parses");
        eprintln!(
            "== {} chain={} ctx={:?}",
            entry.source.display(),
            entry.chain_id,
            ir.context_kind
        );
        for fmt in ir.format_iter() {
            let fmt = fmt.expect("format header");
            let sel = fmt.selector;
            eprintln!(
                "  fmt sel=0x{:02x}{:02x}{:02x}{:02x} intent={:?}",
                sel[0],
                sel[1],
                sel[2],
                sel[3],
                core::str::from_utf8(fmt.intent).unwrap_or("?")
            );
            for field in fmt.fields() {
                let field = field.expect("field");
                eprintln!(
                    "    field op={:#04x} label={:?} path_off={} param_off={}",
                    field.format_op,
                    core::str::from_utf8(field.label).unwrap_or("?"),
                    field.path_off,
                    field.param_off
                );
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// `path_off == 0` collision fix landed in `dbgen::erc7730::Pool::new`:
// the pool now reserves byte 0 with a 1-byte filler so the first
// interned path program lands at offset 1. The on-device walker and
// renderer's `path_off == 0` / `param_off == 0` "no path" sentinels
// stay intact, and the descriptors that previously fell through to
// blind-sign (weth.deposit, tether-usdt.transfer/approve, and the
// accepted Aave/Circle formats) now render their full clear-sign page
// sequence. Incomplete Aave formats remain known-call refusals.
//
// The three tests below assert the user-visible display text end-to-end.

#[test]
fn positive_registry_celo_from_uses_explicit_device_signer() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-celo_accounts.json", 42220);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let calldata = keccak256(b"createAccount()")[..4].to_vec();
    assert_selector_matches(&verified.ir, &calldata, "createAccount()");
    let tx = envelope(42220, entry.contract);
    let resolver = NameResolver::new();

    assert!(matches!(
        render_erc7730_pages(&tx, &calldata, &verified, None, &resolver),
        Err(crate::tx::erc7730_render::RenderErr::Reject(
            "7730 from unbound"
        ))
    ));

    let sender = [0x12u8; 20];
    let pages =
        render_erc7730_pages_with_signer(&tx, &calldata, &verified, None, &resolver, &sender)
            .expect("Celo @.from renders from the device signer");
    let field_page = intent_page_index(&pages) + 1;
    assert_eq!(page_strs(&pages, field_page)[0], "Account Owner");
    assert_eq!(&pages.buf[field_page][1], b"0x12121212121212");
    assert_eq!(&pages.buf[field_page][2], b"1212121212121212");
    assert_eq!(&pages.buf[field_page][3][..10], b"1212121212");
}

#[test]
fn positive_usdt_transfer_mainnet_renders_send_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert!(matches!(verified.ir.context_kind, ContextKind::Contract));

    let amount = u256_from_u64(100_000_000); // 100.00 USDT (6 decimals)
    let recipient = [0x33u8; 20];
    let calldata = calldata_transfer(recipient, amount);
    assert_selector_matches(&verified.ir, &calldata, "transfer(address,uint256)");

    let tx = envelope(1, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let checked = render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata,
        &verified,
        Some(&usdt_meta),
        &resolver,
        &[0u8; 20],
    )
    .expect("checked static render");
    let pages = checked.pages;
    assert_eq!(
        checked.transcript_receipt.state_code(),
        INTENT_PUBLICATION_STATIC
    );
    assert_eq!(checked.transcript_receipt.page_count() as usize, pages.len);
    assert!(checked.transcript_receipt.range_matches(&pages, 0));

    assert_all_pages_printable(&pages);

    // Page 0: intent banner.
    let [r0, r1, r2, r3] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Send");
    assert_eq!(r1, "Tether Limited");
    assert_eq!(r2, "Tether USD");
    assert_eq!(r3, "> next");

    // Amount page — labelled "Amount", value should render as
    // "100" / "USDT" across two rows.
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    assert!(
        amount_rows[1].contains("100"),
        "amount row 1 should carry the integer part: rows={amount_rows:?}",
    );
    assert!(
        amount_rows[1].contains("USDT") || amount_rows[2].contains("USDT"),
        "USDT ticker missing from amount: rows={amount_rows:?}",
    );

    // To page — labelled "To".
    let to_page = find_page_by_label(&pages, "To");
    let to_rows = page_strs(&pages, to_page);
    let recipient_hex_head = "3333";
    assert!(
        to_rows.iter().any(|r| r.contains(recipient_hex_head)),
        "recipient hex prefix missing: rows={to_rows:?}",
    );
}

#[test]
fn flyingtulip_dynamic_token_path_keeps_static_intent_and_exact_token_identity() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PositionsManager.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify FlyingTulip leaf");
    let resolver = NameResolver::new();
    let tx = envelope(1, entry.contract);
    let amount = u256_from_u64(1_000_000); // 1 USDT at six decimals.
    let assets = [
        [
            0x1c, 0xdd, 0x2e, 0xab, 0x61, 0x11, 0x26, 0x97, 0x62, 0x6f, 0x7b, 0x4b, 0xb0, 0xe2,
            0x3d, 0xa4, 0xfe, 0xbf, 0x7b, 0x7c,
        ],
        [
            0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45,
            0x97, 0xc1, 0x3d, 0x83, 0x1e, 0xc7,
        ],
    ];

    let calldata_for = |asset: [u8; 20], amount: U256| {
        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&keccak256(b"deposit(address,uint256)")[..4]);
        let mut asset_word = [0u8; 32];
        asset_word[12..].copy_from_slice(&asset);
        calldata.extend_from_slice(&asset_word);
        calldata.extend_from_slice(&amount.0);
        calldata
    };
    let render = |asset: [u8; 20], amount: U256| {
        let calldata = calldata_for(asset, amount);
        let meta = Erc20Metadata {
            chain_id: 1,
            contract: asset,
            decimals: 6,
            name: b"USDT",
            symbol: b"USDT",
        };
        render_erc7730_pages(&tx, &calldata, &verified, Some(&meta), &resolver)
            .expect("FlyingTulip deposit renders")
    };

    let pages_a = render(assets[0], amount);
    let pages_b = render(assets[1], amount);
    assert_eq!(
        page_strs(&pages_a, intent_page_index(&pages_a))[0],
        "Deposit collater",
        "a calldata-derived tokenPath must not authorize value-bearing intent interpolation"
    );
    assert_eq!(
        page_strs(&pages_b, intent_page_index(&pages_b))[0],
        "Deposit collater"
    );
    let amount_page = find_page_by_label(&pages_a, "Amount");
    let amount_rows = page_strs(&pages_a, amount_page);
    assert!(
        amount_rows[1].contains("1")
            && (amount_rows[1].contains("USDT") || amount_rows[2].contains("USDT")),
        "interpolation must not replace the ordinary amount page: {amount_rows:?}"
    );
    assert_ne!(
        pages_a.as_slice(),
        pages_b.as_slice(),
        "same ticker/decimals must not collapse distinct signed assets"
    );
    assert_full_contract_identity_page(&pages_a, &assets[0]);
    assert_full_contract_identity_page(&pages_b, &assets[1]);

    let two_pages = render(assets[0], u256_from_u64(2_000_000));
    assert_eq!(
        page_strs(&two_pages, intent_page_index(&two_pages))[0],
        "Deposit collater",
        "changing the signed amount must not turn a static intent into interpolation"
    );
    assert_ne!(
        page_strs(&pages_a, find_page_by_label(&pages_a, "Amount")),
        page_strs(&two_pages, find_page_by_label(&two_pages, "Amount")),
        "the retained amount page must change with the same signed word"
    );

    let calldata = calldata_for(assets[0], amount);
    let no_meta = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("static intent remains safe with an exact unverified raw amount");
    assert_eq!(
        page_strs(&no_meta, intent_page_index(&no_meta))[0],
        "Deposit collater"
    );
    assert!(
        dump_pages(&no_meta).contains("! raw, dec=?"),
        "missing token metadata must not imply a decimal scale"
    );
    assert_full_unverified_token_identity_page(&no_meta, &assets[0]);
    for meta in [
        Erc20Metadata {
            chain_id: 2,
            contract: assets[0],
            decimals: 6,
            name: b"USDT",
            symbol: b"USDT",
        },
        Erc20Metadata {
            chain_id: 1,
            contract: [0x55; 20],
            decimals: 6,
            name: b"USDT",
            symbol: b"USDT",
        },
    ] {
        let mismatched = render_erc7730_pages(&tx, &calldata, &verified, Some(&meta), &resolver)
            .expect("mismatched metadata remains safely unbound");
        assert_eq!(
            page_strs(&mismatched, intent_page_index(&mismatched))[0],
            "Deposit collater",
            "wrong-chain or wrong-contract metadata must not mint a title witness"
        );
        assert!(dump_pages(&mismatched).contains("! raw, dec=?"));
        assert_full_unverified_token_identity_page(&mismatched, &assets[0]);
    }
}

#[test]
fn positive_usdt_approve_unlimited_renders_approve_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // U256::MAX is the canonical "approve unlimited" sentinel; the
    // descriptor sets `threshold` to 0x8000...0000 (top bit) — any
    // value above renders as "unlimited" via tokenAmount.
    let calldata = calldata_approve([0x44u8; 20], u256_max());
    assert_selector_matches(&verified.ir, &calldata, "approve(address,uint256)");

    let tx = envelope(1, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdt_meta), &resolver)
        .expect("render");

    assert_all_pages_printable(&pages);

    let [intent_r0, _, _, _] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(intent_r0, "Approve");

    // Spender page must be present (labelled "Spender" per the
    // descriptor).
    let _spender_page = find_page_by_label(&pages, "Spender");

    // Amount page — for U256::MAX with the descriptor's threshold set,
    // `render_token_amount` short-circuits the digit formatter and
    // writes "unlimited <ticker>" on row 1. No `!AMOUNT OVERFLOW`
    // banner, no truncated decimal soup — just the human-readable
    // sentinel.
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    let amount_blob = amount_rows.join("\n");
    assert!(
        amount_blob.to_lowercase().contains("unlimited"),
        "approve(MAX) should render 'unlimited', got:\n{amount_blob}",
    );
    assert!(
        amount_blob.contains("USDT"),
        "unlimited row should carry the ticker, got:\n{amount_blob}",
    );
    assert!(
        !amount_blob.contains("AMOUNT OVERFLOW"),
        "threshold check must short-circuit before the overflow fallback, got:\n{amount_blob}",
    );
}

#[test]
fn usdt_exact_zero_approve_derives_revoke_from_authenticated_signed_facts() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(1, entry.contract);
    let meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let spender = [0x44u8; 20];
    let resolver = NameResolver::new();
    let zero_calldata = calldata_approve(spender, U256::zero());
    let pages = render_erc7730_pages(&tx, &zero_calldata, &verified, Some(&meta), &resolver)
        .expect("render zero approval");

    assert_eq!(
        page_strs(&pages, intent_page_index(&pages))[0],
        "Revoke approval"
    );
    let spender_page = find_page_by_label(&pages, "Spender");
    let spender_blob = page_strs(&pages, spender_page).join("");
    assert!(spender_blob.to_ascii_lowercase().contains("44444444"));
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_blob = page_strs(&pages, amount_page).join(" ");
    assert!(
        amount_blob.contains("0 USDT"),
        "zero amount and authenticated ticker must remain visible: {amount_blob:?}"
    );
    assert_full_contract_identity_page(&pages, &entry.contract);
    assert!(pages
        .as_slice()
        .iter()
        .any(|page| row_str(&page[0]) == "Network:" && row_str(&page[1]) == "Chain: 1"));

    // Exact means all 32 signed amount bytes must be zero. Flipping any one
    // byte leaves every other authenticated fact unchanged and must restore
    // the descriptor's ordinary approval intent.
    for byte in 0..32 {
        let mut nonzero = [0u8; 32];
        nonzero[byte] = 1;
        let calldata = calldata_approve(spender, U256(nonzero));
        let changed = render_erc7730_pages(&tx, &calldata, &verified, Some(&meta), &resolver)
            .expect("render nonzero approval");
        assert_eq!(
            page_strs(&changed, intent_page_index(&changed))[0],
            "Approve",
            "nonzero amount byte {byte} must not be called a revocation"
        );
    }
}

#[test]
fn usdt_zero_approve_without_matching_erc20_capability_keeps_approve_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let calldata = calldata_approve([0x44; 20], U256::zero());

    let no_meta = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("descriptor-only zero approval renders");
    assert_eq!(
        page_strs(&no_meta, intent_page_index(&no_meta))[0],
        "Approve"
    );

    let wrong_contract = Erc20Metadata {
        chain_id: 1,
        contract: [0x55; 20],
        decimals: 6,
        name: b"Not USDT",
        symbol: b"NOPE",
    };
    let mismatched =
        render_erc7730_pages(&tx, &calldata, &verified, Some(&wrong_contract), &resolver)
            .expect("mismatched metadata remains unbound");
    assert_eq!(
        page_strs(&mismatched, intent_page_index(&mismatched))[0],
        "Approve"
    );

    let wrong_chain = Erc20Metadata {
        chain_id: 10,
        contract: entry.contract,
        decimals: 6,
        name: b"Wrong-chain USDT",
        symbol: b"USDT",
    };
    let chain_mismatched =
        render_erc7730_pages(&tx, &calldata, &verified, Some(&wrong_chain), &resolver)
            .expect("wrong-chain metadata remains unbound");
    assert_eq!(
        page_strs(&chain_mismatched, intent_page_index(&chain_mismatched))[0],
        "Approve"
    );
}

#[test]
fn lido_erc721_zero_token_id_never_becomes_revoke_approval() {
    // ERC-721 deliberately shares approve(address,uint256). A verified
    // descriptor and canonical two-word calldata are therefore insufficient
    // to claim ERC-20 revocation semantics without a matching ERC-20 metadata
    // capability.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WithdrawalQueueERC721.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify Lido NFT leaf");
    let tx = envelope(1, entry.contract);
    let calldata = calldata_approve([0x44; 20], U256::zero());
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &NameResolver::new())
        .expect("render ERC-721 approve token id zero");

    let nft_intent = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(nft_intent[0], "Approve unstETH");
    assert_eq!(nft_intent[1], "NFT");
    assert!(dump_pages(&pages).contains("Request ID"));
    assert!(!dump_pages(&pages).contains("Revoke approval"));
}

#[test]
fn positive_unlimited_uses_descriptor_message_param() {
    // review 3.6: the descriptor's `message` param overrides the default
    // "unlimited" wording (spec: "message above threshold, defaults to
    // Unlimited"). Synthetic approve with message="Max"; rendered unbound so
    // the amount page reads "Max" / "(unverified)".
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-approve-message.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_approve([0x44u8; 20], u256_max());
    assert_selector_matches(&verified.ir, &calldata, "approve(address,uint256)");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let amount_page = find_page_by_label(&pages, "Amount");
    let blob = page_strs(&pages, amount_page).join("\n");
    assert!(
        blob.contains("Max"),
        "descriptor message 'Max' must render:\n{blob}"
    );
    assert!(
        !blob.to_lowercase().contains("unlimited"),
        "the message param must OVERRIDE the default 'unlimited':\n{blob}"
    );
}

#[test]
fn positive_usdt_approve_unlimited_unbound_renders_unlimited_not_overflow() {
    // review 4.5: an unlimited approval of an UNKNOWN (unbound) token used to
    // render "!AMOUNT OVERFLOW" — the raw 2^256-1 overflows the amount
    // formatter, an alarming banner with no meaning for the single most
    // dangerous action, exactly when trust is LOWEST. It must now render
    // "unlimited" + "(unverified)". Same REAL USDT approve descriptor
    // (threshold set), but NO metadata supplied → the token cannot bind.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_approve([0x44u8; 20], u256_max());
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_blob = page_strs(&pages, amount_page).join("\n");
    assert!(
        amount_blob.to_lowercase().contains("unlimited"),
        "unbound approve(MAX) must render 'unlimited', got:\n{amount_blob}"
    );
    assert!(
        !amount_blob.contains("OVERFLOW"),
        "must NOT render the alarming overflow banner for an unlimited approve:\n{amount_blob}"
    );
    assert!(
        amount_blob.contains("(unverified)"),
        "unbound must mark the missing token identity:\n{amount_blob}"
    );
}

#[test]
fn positive_erc7730_golden_grid_hash() {
    // te-2: full-grid golden over a canonical ERC-7730 render (the REAL USDT
    // approve descriptor). ERC-7730 is the highest-churn WYSIWYS surface (it
    // now also carries Aave clear-signing) and the per-field asserts elsewhere
    // check only the amount/label cells; this binds the WHOLE rendered grid so
    // an intent-banner / divider / row-shift regression trips even if the
    // checked substrings survive. Re-bless GOLDEN only for an INTENTIONAL
    // layout change. (Firmware `ui/golden.rs` cannot cover this screen — its
    // input needs the host-only dbgen registry, built here.)
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();

    let calldata = calldata_approve([0x44u8; 20], u256_max());
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    let h = super::golden_grid_hash(&pages);

    // Non-vacuity: a different spender address MUST move the digest (the
    // spender renders on-page), proving the hash binds rendered content.
    let calldata2 = calldata_approve([0x77u8; 20], u256_max());
    let h2 = super::golden_grid_hash(
        &render_erc7730_pages(&tx, &calldata2, &verified, None, &resolver).expect("render"),
    );
    assert_ne!(
        h, h2,
        "golden hash must bind rendered content (spender change did not move it)"
    );

    // Re-blessed after inspecting the full grid: the intentional envelope
    // hardening adds a lossless EIP-1559 nonce page (`Nonce: 7`) between the
    // exact fee budget and confirmation. All descriptor intent/field pages are
    // otherwise unchanged.
    #[cfg(not(feature = "erc7730-dev-unattested"))]
    const GOLDEN: [u8; 32] = [
        0x4b, 0xa2, 0x70, 0x68, 0xd8, 0x81, 0xed, 0xb6, 0xe9, 0x51, 0x08, 0x02, 0x30, 0x02, 0xf1,
        0xc8, 0xad, 0xae, 0xfb, 0x8c, 0x36, 0x30, 0x63, 0xde, 0x00, 0xab, 0xa6, 0x07, 0x55, 0xa4,
        0x4c, 0x61,
    ];
    // Same reviewed grid with the mandatory dev-unattested warning prepended.
    #[cfg(feature = "erc7730-dev-unattested")]
    const GOLDEN: [u8; 32] = [
        0xc1, 0x3d, 0x17, 0x94, 0x49, 0x46, 0x08, 0xf9, 0x2e, 0xf7, 0x55, 0xca, 0x09, 0x79, 0xf2,
        0xcd, 0x08, 0x4f, 0x77, 0x21, 0x3f, 0x0d, 0x75, 0xd8, 0x6a, 0xad, 0x3b, 0xe7, 0x64, 0x4c,
        0xbe, 0x7b,
    ];
    assert_eq!(
        h, GOLDEN,
        "ERC-7730 render golden changed — re-bless if intentional. got={h:?}"
    );
}

#[test]
fn positive_aave_withdraw_eth_renders_native_currency() {
    // Item-1 `nativeCurrencyAddress`: Aave `WrappedTokenGatewayV3.withdrawETH`'s
    // `amount` is a `tokenAmount` whose `token` AND `nativeCurrencyAddress` are
    // both the native-ETH sentinel `0x0`. The renderer must resolve it to chain
    // NATIVE currency — 18 decimals + `native_ticker` ("ETH" on mainnet) —
    // WITHOUT an ERC-20 lookup (we pass `erc20 = None`) and WITHOUT emitting the
    // "Token (UNVERIFIED)" identity page for the sentinel address.
    //
    // Non-vacuity: if `is_native` silently flipped false the amount would fall
    // through to the unbound branch — raw integer "1500000000000000000",
    // footer "! raw, dec=?", plus a "Token (UNVERIFIED)" page for `0x0`. Every
    // assertion below (positive "1.5"/"ETH", negative UNVERIFIED/"! raw, dec=?")
    // therefore discriminates the feature working from not.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WrappedTokenGatewayV3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // withdrawETH(address pool, uint256 amount, address to) — 1.5 ETH, chosen
    // to exercise 18-decimal FRACTIONAL formatting (not a round integer).
    let pool = [0x55u8; 20];
    let to = [0x33u8; 20];
    let amount = u256_from_u64(1_500_000_000_000_000_000); // 1.5e18 wei
    let mut calldata = Vec::with_capacity(4 + 3 * 32);
    let sel = keccak256(b"withdrawETH(address,uint256,address)");
    calldata.extend_from_slice(&sel[..4]);
    let mut pool_w = [0u8; 32];
    pool_w[12..].copy_from_slice(&pool);
    calldata.extend_from_slice(&pool_w);
    calldata.extend_from_slice(&amount.0);
    let mut to_w = [0u8; 32];
    to_w[12..].copy_from_slice(&to);
    calldata.extend_from_slice(&to_w);
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "withdrawETH(address,uint256,address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    // erc20 = None: native rendering must NOT depend on any companion metadata.
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Intent banner.
    assert_eq!(
        page_strs(&pages, intent_page_index(&pages))[0],
        "Withdraw",
        "intent banner:\n{dump}"
    );

    // (a) Native amount: 18-dec fractional "1.5" + chain native ticker "ETH".
    assert!(
        dump.contains("1.5"),
        "native amount should render 1.5:\n{dump}"
    );
    assert!(
        dump.contains("ETH"),
        "native amount must carry ticker ETH:\n{dump}"
    );

    // (b) NO unbound-token artefacts — the sentinel is native, not an unverified
    // ERC-20. These strings appear ONLY when `is_native` is false.
    assert!(
        !dump.contains("Token (UNVERIFI~"),
        "native render must NOT emit a token-identity page for the 0x0 sentinel:\n{dump}",
    );
    assert!(
        !dump.contains("! raw, dec=?"),
        "native render must NOT fall through to the raw-integer unbound path:\n{dump}",
    );

    // Pool page: the curation unlock (was `visible:"never"` → now `raw`/always).
    assert!(
        dump.to_lowercase().contains("5555"),
        "curated pool address must render as raw hex:\n{dump}",
    );
}

#[test]
fn positive_1inch_native_currency_list_renders_both_members_and_rejects_a_miss() {
    // Real upstream list witness: the 1inch V4 definition authenticates
    // [0xEeee…, 0x0] for BOTH tokenAmount fields. `clipperSwap` is all-static,
    // complete, and binds its beneficiary to the device-derived signer.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-AggregationRouterV4-eth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify 1inch leaf");
    let signer = [0x12u8; 20];
    let resolver = NameResolver::new();
    let tx = envelope(1, entry.contract);

    let calldata = |src_token: [u8; 20]| {
        let mut out = Vec::with_capacity(4 + 4 * 32);
        let selector = keccak256(b"clipperSwap(address,address,uint256,uint256)");
        out.extend_from_slice(&selector[..4]);
        for address in [src_token, [0u8; 20]] {
            let mut word = [0u8; 32];
            word[12..].copy_from_slice(&address);
            out.extend_from_slice(&word);
        }
        out.extend_from_slice(&u256_from_u64(1_500_000_000_000_000_000).0);
        out.extend_from_slice(&u256_from_u64(2_250_000_000_000_000_000).0);
        out
    };

    let eth_sentinel = [0xEEu8; 20];
    let native_calldata = calldata(eth_sentinel);
    assert_selector_matches(
        &verified.ir,
        &native_calldata,
        "clipperSwap(address,address,uint256,uint256)",
    );
    let pages = render_erc7730_pages_with_signer(
        &tx,
        &native_calldata,
        &verified,
        None,
        &resolver,
        &signer,
    )
    .expect("both list members render as native ETH");
    let dump = dump_pages(&pages);
    assert_eq!(page_strs(&pages, intent_page_index(&pages))[0], "Swap");
    let send = page_strs(&pages, find_page_by_label(&pages, "Amount to Send")).join("\n");
    let receive = page_strs(&pages, find_page_by_label(&pages, "Minimum to Rece~")).join("\n");
    assert!(send.contains("1.5") && send.contains("ETH"), "{dump}");
    assert!(
        receive.contains("2.25") && receive.contains("ETH"),
        "{dump}"
    );
    assert!(
        !dump.contains("Token (UNVERIFI~") && !dump.contains("! raw, dec=?"),
        "both authenticated sentinels must stay on the native path:\n{dump}"
    );
    let beneficiary = page_strs(&pages, find_page_by_label(&pages, "Beneficiary"));
    assert_eq!(beneficiary[1], "0x12121212121212");

    // Flip one byte of the first sentinel. It is no longer a member, while the
    // zero-address receive token still is. With no ERC-20 metadata, the send
    // amount must become raw and expose the full unverified token identity.
    let mut miss = eth_sentinel;
    miss[19] ^= 1;
    let miss_pages =
        render_erc7730_pages_with_signer(&tx, &calldata(miss), &verified, None, &resolver, &signer)
            .expect("one-byte list miss remains safely renderable as unverified raw");
    let miss_dump = dump_pages(&miss_pages);
    assert!(miss_dump.contains("! raw, dec=?"), "{miss_dump}");
    assert!(miss_dump.contains("Token (UNVERIFI~"), "{miss_dump}");
    let miss_receive = page_strs(
        &miss_pages,
        find_page_by_label(&miss_pages, "Minimum to Rece~"),
    )
    .join("\n");
    assert!(
        miss_receive.contains("2.25") && miss_receive.contains("ETH"),
        "the second list member must remain native after a first-member miss:\n{miss_dump}"
    );
}

/// Multi-chain chain-pinning: USDT's registry descriptor carries Mainnet (1)
/// AND Polygon (137) deployments under the SAME JSON. Picking the chain-137
/// leaf (contract 0xc2132D…8e8F, the bridged Polygon USDT) proves the
/// renderer + bundle verifier bind to the right `(chain_id, contract)` leaf —
/// a Mainnet tx must never render against the Polygon leaf and vice-versa.
/// Replaces the deleted vacuous `circle-usdc` chain-pinning test, which fed
/// an EIP-712 descriptor calldata it could never render (its
/// `find_format_by_selector` guard early-returned, asserting nothing).
#[test]
fn positive_usdt_transfer_polygon_chain_pinning() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 137);
    // The chain-137 leaf is the bridged Polygon USDT, a different address
    // from Mainnet's 0xdAC17… — proves we picked the right deployment.
    let polygon_usdt = hex::decode("c2132D05D31c914a87C6611C10748AEb04B58e8F").unwrap();
    assert_eq!(
        &entry.contract[..],
        &polygon_usdt[..],
        "chain-137 leaf must bind the Polygon USDT contract"
    );

    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert_eq!(verified.ir.chain_id, 137, "verified leaf is chain 137");
    assert_eq!(
        &verified.ir.contract,
        &polygon_usdt[..],
        "verified leaf contract"
    );

    let calldata = calldata_transfer([0x33u8; 20], u256_from_u64(100_000_000));
    assert_selector_matches(&verified.ir, &calldata, "transfer(address,uint256)");

    let tx = envelope(137, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 137,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdt_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);

    // The Polygon leaf renders the same "Send" intent as Mainnet.
    let [r0, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Send");
}

#[test]
fn positive_weth_deposit_pulls_value_from_envelope() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // deposit() is the zero-arg selector — the "Amount" field is
    // sourced from `@.value` (container), not the calldata.
    let calldata = calldata_deposit();
    assert_selector_matches(&verified.ir, &calldata, "deposit()");

    let mut tx = envelope(1, entry.contract);
    tx.value = u256_from_u64(500_000_000_000_000_000); // 0.5 ETH

    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    assert_all_pages_printable(&pages);

    let [intent_r0, owner_r, contract_r, _] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(intent_r0, "Wrap");
    assert_eq!(owner_r, "WETH");
    assert_eq!(contract_r, "WETH");

    // Amount page — 0.5 ETH at 18 decimals. review 4.3: the amount now prefers
    // a SINGLE row ("0.5 ETH") instead of the old split ("0" / ".5 ETH").
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    assert_eq!(
        amount_rows[1], "0.5 ETH",
        "amount must render on a single row (4.3), got:\n{amount_rows:?}",
    );
}

#[test]
fn positive_native_amount_uses_chain_ticker_not_eth_on_polygon() {
    // review 3.5: the `amount` format defaults to the chain's NATIVE ticker,
    // not always "ETH". A Polygon (137) descriptor must render "POL". (The WETH
    // deposit test above covers the chain-1 → ETH case by render.)
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-native-amount.json", 137);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"pay(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(500_000_000_000_000_000).0); // 0.5
    assert_selector_matches(&verified.ir, &calldata, "pay(uint256)");
    let tx = envelope(137, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let amount_page = find_page_by_label(&pages, "Amount");
    let rows = page_strs(&pages, amount_page).join(" ");
    assert!(
        rows.contains("POL"),
        "Polygon native amount must render POL:\n{rows}"
    );
    assert!(
        !rows.contains("ETH"),
        "must NOT render ETH on Polygon:\n{rows}"
    );
}

// NOTE: The corresponding EIP-712 path (`render_erc7730_eip712_pages`)
// would be the right way to exercise USDC's TransferWithAuthorization
// descriptor — but the firmware-side EIP-712 entry point requires the
// 32-byte primaryTypeHash + ABI-encoded data buffer that the
// `cmd_sign_offchain` handler computes from the dapp's typed payload,
// and that scaffolding is wired through the on-device sign command
// rather than the renderer's public API. A future test pass that
// reaches into `cmd_sign_offchain` would close that gap; for now we
// limit coverage to the contract-context path above.
//
// (Multi-chain chain-pinning is now exercised by
// `positive_usdt_transfer_polygon_chain_pinning` above, against the real
// registry USDT descriptor's chain-137 leaf. The former
// `positive_usdc_transfer_polygon_uses_correct_chain_pinning` was vacuous:
// it fed `transfer` calldata to an EIP-712 `circle-usdc` descriptor whose
// `find_format_by_selector` guard always early-returned, asserting nothing.)

#[test]
fn negative_unknown_selector_returns_no_format() {
    // The renderer must NOT try to fall through to a "best-guess"
    // format. The raw renderer reports `NoFormat`; because this descriptor
    // has already verified and bound, the dispatcher must refuse rather than
    // downgrade the same request to a weaker blind-sign interpretation.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 0xdeadbeef — selector not in the registry WETH descriptor (deposit only).
    let calldata = vec![0xde, 0xad, 0xbe, 0xef];
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::NoFormat) => {}
        Err(other) => panic!("expected RenderErr::NoFormat for unknown selector, got {other:?}"),
        Ok(_) => panic!("unknown selector must not render"),
    }
}

#[test]
fn negative_verified_descriptor_no_format_refuses_dispatch() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let calldata = vec![0xde, 0xad, 0xbe, 0xef];
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let mut dispatch_proofs = super::dispatch::DispatchPageProofs::new();
    dispatch_proofs.fail_initialize();

    let outcome = pick_sign_pages(
        &tx,
        &calldata,
        &[0u8; 20],
        None,
        None,
        None,
        Some(&verified),
        None,
        None,
        &resolver,
        &mut dispatch_proofs,
    );
    assert!(
        outcome.is_err(),
        "a bound verified descriptor that cannot render must not fall through"
    );
}

#[test]
fn negative_short_calldata_rejects() {
    // Less than 4 bytes — can't even extract a selector. The renderer
    // must reject cleanly so a verified-descriptor caller can fail closed.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata: Vec<u8> = vec![0xab, 0xcd]; // 2 bytes
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::NoFormat) => {}
        Err(other) => panic!("expected NoFormat, got {other:?}"),
        Ok(_) => panic!("short calldata must not render"),
    }
}

#[test]
fn positive_intent_truncation_is_safe() {
    // The intent banner now wraps the intent across two rows (up to 32 chars,
    // a visible `~` marker beyond that) instead of the old 10-char "Sign: "
    // prefix form, so an intent of ANY length renders safely (no silent clip).
    // Verify the seed corpus' intents stay within the host-pipeline ASCII cap
    // (≤ 254 B) and that every rendered row stays within DISPLAY_COLS = 16.
    let res = build_seed();
    for entry in &res.entries {
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified =
            verify_erc7730_bundle(&bundle, &res.root).expect("seed corpus entries verify");
        if !matches!(verified.ir.context_kind, ContextKind::Contract) {
            continue;
        }
        for fmt in verified.ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            assert!(
                fmt.intent.len() <= 254,
                "intent exceeds the host-pipeline ASCII cap: {:?}",
                core::str::from_utf8(fmt.intent).unwrap_or("<bin>")
            );
            // The banner caps every row at DISPLAY_COLS and marks truncation
            // with `~`; the row-length invariant is asserted at the page level
            // via `assert_all_pages_printable` (and the wrap/marker behaviour by
            // `positive_long_intent_wraps_and_marks_truncation`).
        }
    }
}

#[test]
fn positive_long_intent_wraps_and_marks_truncation() {
    // review 4.1: the intent banner drops the old "Sign: " prefix and wraps the
    // intent across rows 0-1 (32 chars). A >32-char intent gets a visible `~`
    // marker in the last cell — never a silent clip.
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-long-intent.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"f(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1).0);
    assert_selector_matches(&verified.ir, &calldata, "f(uint256)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    // "Withdraw Collateral from the Morpho Market" (42 chars) → rows 0-1.
    let [r0, r1, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(
        r0, "Withdraw Collate",
        "row 0 = first 16 chars, no `Sign:` prefix"
    );
    assert!(
        r1.starts_with("ral from the"),
        "row 1 = intent continuation, got {r1:?}"
    );
    assert!(
        r1.ends_with('~'),
        "row 1 must mark truncation with `~`, got {r1:?}"
    );
}

#[test]
fn positive_medium_intent_wraps_two_rows_no_marker() {
    // review 4.1: a 17..32-char intent uses both rows with NO marker.
    // "Request stETH withdrawal" (24 chars) → "Request stETH wi" / "thdrawal".
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = rw_calldata(&[u256_from_u64(1_000_000_000_000_000_000)], [0x55u8; 20]);
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");

    let [r0, r1, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Request stETH wi");
    assert_eq!(r1, "thdrawal");
    assert!(!r1.contains('~'), "24 chars fits two rows → no marker");
}

#[test]
fn positive_erc8213_fingerprint_renders_full_hash() {
    // The ERC-8213 fingerprint page is independent of the descriptor —
    // it just renders the 32-byte hash. Smoke-test it produces exactly
    // 2 pages and the rendered hex matches the input bytewise.
    let mut pages = Pages::empty_with_len(0);

    let hash: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    append_fingerprint_for_test(&mut pages, Erc8213Kind::CalldataDigest(hash))
        .expect("fingerprint fits");

    assert_eq!(pages.len, 2, "fingerprint renders exactly 2 pages");
    assert_all_pages_printable(&pages);

    // Banner: row 0 "8213 Fingerprint", row 1 "CalldataDigest".
    assert_eq!(row_str(&pages.buf[0][0]), "8213 Fingerprint");
    assert_eq!(row_str(&pages.buf[0][1]), "CalldataDigest");
    assert_eq!(row_str(&pages.buf[0][3]), "> verify off-dev");

    // Hash page: 8 bytes per row × 4 rows = full 32 B.
    let hash_page = &pages.buf[1];
    let rendered: String = hash_page
        .iter()
        .map(|r| row_str(r))
        .collect::<Vec<_>>()
        .join("");
    let expected_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        rendered, expected_hex,
        "fingerprint rows must spell out the full 32-byte hash bytewise"
    );
}

fn append_fingerprint_for_test(pages: &mut Pages, kind: Erc8213Kind) -> Result<(), ()> {
    let mut cfi = crate::fi::CfiCounter::new();
    append_fingerprint_page(pages, kind, &mut cfi)?;
    if cfi.check_into_sentinel(FINGERPRINT_CFI_EXPECTED) != crate::fi::OK_SENTINEL {
        return Err(());
    }
    Ok(())
}

fn eip712_transcript_verdict(
    proof: &super::erc7730_secure_shim::Eip712TranscriptProof,
    pages: &Pages,
) -> u32 {
    let mut verdict = crate::fi::FAIL_SENTINEL;
    proof.final_set_proof(pages, &mut verdict);
    verdict
}

#[test]
fn positive_erc8213_labels_cover_every_kind() {
    // Pin the label text on every Kind variant. Surfaces a regression
    // where someone renames the label in `erc8213.rs::Kind::label`
    // without updating the doc + tests in lockstep.
    for (kind, expected_label) in [
        (Erc8213Kind::CalldataDigest([0u8; 32]), "CalldataDigest"),
        (Erc8213Kind::Eip712Final([0u8; 32]), "EIP-712 Final"),
        (Erc8213Kind::Raw32([0u8; 32]), "Raw32 Hash"),
        (Erc8213Kind::SafeTxHash([0u8; 32]), "SafeTxHash"),
    ] {
        let mut pages = Pages::empty_with_len(0);
        append_fingerprint_for_test(&mut pages, kind).expect("fits");
        assert_eq!(
            row_str(&pages.buf[0][1]),
            expected_label,
            "label row for {:?}",
            std::any::type_name_of_val(&kind)
        );
    }
}

#[test]
fn erc8213_append_is_atomic_and_requires_both_complete_pages() {
    use pqsigner_erc7730::display::erc8213_contract::FINGERPRINT_PAGES;
    use pqsigner_erc7730::display::MAX_PAGES;

    let mut one_page_short = Pages::empty_with_len(MAX_PAGES - 1);
    one_page_short.buf[MAX_PAGES - 2][0] = *b"existing page   ";
    let before_len = one_page_short.len;
    let before_page = one_page_short.buf[MAX_PAGES - 2];
    assert!(
        append_fingerprint_for_test(&mut one_page_short, Erc8213Kind::CalldataDigest([0xA5; 32]),)
            .is_err(),
        "one free page must not permit a banner without the complete hash"
    );
    assert_eq!(one_page_short.len, before_len);
    assert_eq!(one_page_short.buf[MAX_PAGES - 2], before_page);

    let mut exact_fit = Pages::empty_with_len(MAX_PAGES - FINGERPRINT_PAGES);
    append_fingerprint_for_test(&mut exact_fit, Erc8213Kind::CalldataDigest([0x5A; 32]))
        .expect("exact two-page capacity must fit");
    assert_eq!(exact_fit.len, MAX_PAGES);
    assert_eq!(
        row_str(&exact_fit.buf[MAX_PAGES - 2][0]),
        "8213 Fingerprint"
    );
    assert_eq!(
        row_str(&exact_fit.buf[MAX_PAGES - 1][0]),
        "5a5a5a5a5a5a5a5a"
    );
}

#[test]
fn erc8213_authoritative_append_mints_cfi_and_binds_exact_pair() {
    let kind = Erc8213Kind::Eip712Final([0xa5; 32]);
    let mut pages = Pages::empty_with_len(3);
    for (index, page) in pages.buf[..pages.len].iter_mut().enumerate() {
        *page = [[b'A' + index as u8; DISPLAY_COLS]; 4];
    }
    let prefix = pages.buf;
    let prior_len = pages.len;
    let mut cfi = crate::fi::CfiCounter::new();

    append_fingerprint_page(&mut pages, kind, &mut cfi).expect("pair fits");
    assert_eq!(&pages.buf[..prior_len], &prefix[..prior_len]);
    assert_eq!(
        cfi.check_into_sentinel(FINGERPRINT_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        fingerprint_page_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );
    assert_eq!(
        fingerprint_final_set_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );

    let skipped = crate::fi::CfiCounter::new();
    assert_ne!(
        skipped.check_into_sentinel(FINGERPRINT_CFI_EXPECTED),
        crate::fi::OK_SENTINEL,
        "skipping the whole append must leave caller-owned CFI short"
    );

    pages.buf[prior_len + 1][3][15] ^= 1;
    assert_ne!(
        fingerprint_page_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );
    assert_ne!(
        fingerprint_final_set_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL
    );
}

#[test]
fn erc8213_proofs_reject_wrong_index_kind_hash_and_short_capacity() {
    use pqsigner_erc7730::display::MAX_PAGES;

    let kind = Erc8213Kind::Raw32([0x3c; 32]);
    let mut pages = Pages::empty_with_len(2);
    let prior_len = pages.len;
    let mut cfi = crate::fi::CfiCounter::new();
    append_fingerprint_page(&mut pages, kind, &mut cfi).unwrap();

    for wrong in [
        Erc8213Kind::Raw32([0x3d; 32]),
        Erc8213Kind::CalldataDigest([0x3c; 32]),
        Erc8213Kind::Eip712Final([0x3c; 32]),
        Erc8213Kind::SafeTxHash([0x3c; 32]),
    ] {
        assert_ne!(
            fingerprint_page_proof(&pages, prior_len, wrong),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            fingerprint_final_set_proof(&pages, prior_len, wrong),
            crate::fi::OK_SENTINEL
        );
    }
    assert_ne!(
        fingerprint_final_set_proof(&pages, prior_len - 1, kind),
        crate::fi::OK_SENTINEL
    );

    pages.push_blank().unwrap();
    assert_ne!(
        fingerprint_page_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL,
        "the transition proof must reject later growth"
    );
    assert_eq!(
        fingerprint_final_set_proof(&pages, prior_len, kind),
        crate::fi::OK_SENTINEL,
        "the final-set proof must tolerate later append-only pages"
    );

    let mut short = Pages::empty_with_len(MAX_PAGES - 1);
    let before = short.buf;
    let mut short_cfi = crate::fi::CfiCounter::new();
    assert!(append_fingerprint_page(&mut short, kind, &mut short_cfi).is_err());
    assert_eq!(short.len, MAX_PAGES - 1);
    assert_eq!(
        short.buf, before,
        "failed atomic append must preserve all pages"
    );
    assert_ne!(
        short_cfi.check_into_sentinel(FINGERPRINT_CFI_EXPECTED),
        crate::fi::OK_SENTINEL
    );
}

// ───────────────────────────────────────────────────────────────────────
// Enum formatter (FormatOp 0x08) — Aave V3. The real `borrow` format is now
// excluded because it explicitly hides `referralCode`; the all-visible `repay`
// format carries the same emitted enum table and preserves the end-to-end host
// `encode_enum_table` → device `lookup_enum_label` → `render_enum` coverage.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_aave_repay_renders_enum_label_and_borrow_is_excluded() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let excluded_borrow =
        calldata_borrow([0u8; 20], u256_from_u64(0), u256_from_u64(2), 0, [0u8; 20]);
    let borrow_selector: [u8; 4] = excluded_borrow[..4].try_into().unwrap();
    assert!(
        verified
            .ir
            .find_format_by_selector(&borrow_selector)
            .expect("format table")
            .is_none(),
        "Aave borrow hides referralCode and must not survive strict compilation"
    );

    // interestRateMode = 2 → "variable" in the descriptor's enum.
    let calldata = calldata_repay(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(2),
        [0x44u8; 20],
    );
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "repay(address,uint256,uint256,address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let [r0, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Repay loan");

    // The enum page must show the RESOLVED label "variable", not the bare
    // index "2" (audit M-7). The registry's field label is "Interest Rate
    // mode" (18 chars); row 0 is truncated to DISPLAY_COLS (16), so the page
    // header reads "Interest rate m~".
    let enum_page = find_page_by_label(&pages, "Interest rate m~");
    let rows = page_strs(&pages, enum_page);
    assert!(
        rows[1].contains("variable"),
        "enum index 2 must resolve to label 'variable': rows={rows:?}",
    );
    assert!(
        !rows.iter().any(|r| r.trim() == "2"),
        "must not render the bare enum index: rows={rows:?}",
    );
}

#[test]
fn positive_aave_repay_unknown_enum_value_renders_raw_index_loudly() {
    // review 3.3: interestRateMode = 7 is outside the declared set {0,1,2}. The
    // OLD behaviour declined the WHOLE tx to blind-sign; the spec says render
    // the raw value. Now the enum field renders the exact index (7) with a loud
    // `! enum: unknown` marker — WYSIWYS-honest (the real signed value is shown,
    // not a substituted gloss) and strictly better than blind-signing.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let calldata = calldata_repay(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(7),
        [0x44u8; 20],
    );
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("unknown enum value must now RENDER (loud raw index), not decline");
    assert_all_pages_printable(&pages);

    // Locate the enum field page by its (truncated) label and assert BOTH the
    // raw index and the loud unknown marker appear ON THAT PAGE (not elsewhere
    // — the envelope nonce is also 7).
    let enum_page = find_page_by_label(&pages, "Interest rate m~");
    let rows = page_strs(&pages, enum_page).join(" ");
    assert!(rows.contains('7'), "raw enum index 7 must render:\n{rows}");
    assert!(
        rows.contains("enum: unknown"),
        "loud unknown-enum marker must render:\n{rows}"
    );
}

#[test]
fn nftname_small_id_keeps_raw_id_and_full_target_collection_identity() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftNft.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify pFT NFT leaf");
    let tx = envelope(1, entry.contract);
    let calldata = calldata_approve([0x44; 20], u256_from_u64(7));
    assert_selector_matches(&verified.ir, &calldata, "approve(address,uint256)");
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &NameResolver::new())
        .expect("render pFT NFT approve");

    let id = page_strs(&pages, find_page_by_label(&pages, "Position"));
    assert_eq!(id[1], "7");
    assert_eq!(id[3], "! raw nft id");
    let collection_page = find_full_nft_collection_page(&pages, &entry.contract);
    assert_eq!(
        page_strs(&pages, collection_page)[0],
        "+ pFT NFT",
        "descriptor contractName is eligible only because @.to equals the bound collection"
    );
}

#[test]
fn nftname_full_width_id_shows_every_byte_plus_full_collection_identity() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftNft.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify pFT NFT leaf");
    let tx = envelope(1, entry.contract);
    let token_id = U256([0xAB; 32]);
    let calldata = calldata_approve([0x44; 20], token_id);
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &NameResolver::new())
        .expect("render full-width pFT token id");

    let id_pages: Vec<_> = pages
        .as_slice()
        .iter()
        .enumerate()
        .filter_map(|(index, page)| (row_str(&page[0]) == "Position").then_some(index))
        .collect();
    assert_eq!(id_pages.len(), 2, "full uint256 id requires two pages");
    let first = page_strs(&pages, id_pages[0]);
    let second = page_strs(&pages, id_pages[1]);
    for row in [&first[1], &first[2], &second[1], &second[2]] {
        assert_eq!(row, "abababababababab");
    }
    assert_eq!(first[3], "1/2 > next");
    assert_eq!(second[3], "2/2 > next");
    let _ = find_full_nft_collection_page(&pages, &entry.contract);
}

#[test]
fn nftname_external_collection_name_requires_exact_chain_metadata() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-PftMarketplace.json", 146);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify marketplace leaf");
    let tx = envelope(146, entry.contract);
    let mut calldata = keccak256(b"removeListing(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(9).0);
    assert_selector_matches(&verified.ir, &calldata, "removeListing(uint256)");
    let collection: [u8; 20] = hex::decode("1d8051c90076FaA5b683A3551Ee4369d00f99D67")
        .unwrap()
        .try_into()
        .unwrap();

    let mut exact = NameResolver::new();
    exact.push(NameMeta {
        chain_id: 146,
        address: collection,
        name: b"pFT Positions",
    });
    let exact_pages = render_erc7730_pages(&tx, &calldata, &verified, None, &exact)
        .expect("exact collection name renders");
    let exact_page = find_full_nft_collection_page(&exact_pages, &collection);
    assert_eq!(page_strs(&exact_pages, exact_page)[0], "+ pFT Positions");

    let mut wildcard = NameResolver::new();
    wildcard.push(NameMeta {
        chain_id: 0,
        address: collection,
        name: b"Wildcard Name",
    });
    let wildcard_pages = render_erc7730_pages(&tx, &calldata, &verified, None, &wildcard)
        .expect("wildcard metadata cannot change collection label");
    let wildcard_page = find_full_nft_collection_page(&wildcard_pages, &collection);
    assert_eq!(
        page_strs(&wildcard_pages, wildcard_page)[0],
        "NFT collection"
    );
}

/// Pack-expansion sanity: the registry Lido `wstETH.wrap(uint256)`
/// descriptor renders the exact derived intent + retained field label. A render test
/// (not just round-trip) catches descriptor-authoring slips — wrong
/// path, selector, or label — that re-parse + Merkle-verify can't.
#[test]
fn positive_wsteth_wrap_renders_intent_and_amount_label() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-wstETH.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let mut calldata = keccak256(b"wrap(uint256)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1_500_000_000_000_000_000).0); // 1.5e18
    assert_selector_matches(&verified.ir, &calldata, "wrap(uint256)");

    let tx = envelope(1, entry.contract);
    // The registry wrap field is `tokenAmount` with `token` = stETH
    // (0xae7ab9…), so supply stETH ERC-20 metadata (18 decimals) for the
    // amount to render — mirrors how the USDT tests pass `Some(erc20)`.
    let steth: [u8; 20] = hex::decode("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
        .unwrap()
        .try_into()
        .unwrap();
    let steth_meta = Erc20Metadata {
        chain_id: 1,
        contract: steth,
        decimals: 18,
        name: b"Liquid staked Ether 2.0",
        symbol: b"stETH",
    };
    let resolver = NameResolver::new();
    let checked = render_erc7730_pages_with_signer_checked(
        &tx,
        &calldata,
        &verified,
        Some(&steth_meta),
        &resolver,
        &[0u8; 20],
    )
    .expect("checked render");
    let pages = checked.pages;
    let transcript = checked.transcript_receipt;
    assert_all_pages_printable(&pages);

    let mut colliding_calldata = keccak256(b"wrap(uint256)")[..4].to_vec();
    colliding_calldata.extend_from_slice(&u256_from_u64(1_500_000_000_000_000_001).0);
    assert!(
        render_erc7730_pages_with_signer_checked(
            &tx,
            &colliding_calldata,
            &verified,
            Some(&steth_meta),
            &resolver,
            &[0u8; 20],
        )
        .is_err(),
        "1.5 stETH and 1.5 stETH + 1 wei collide under six-decimal paint; the enrolled checked render must hard-refuse the latter"
    );

    assert_eq!(transcript.state_code(), INTENT_PUBLICATION_INTERPOLATED);
    assert_eq!(transcript.page_count() as usize, pages.len);
    assert!(transcript.range_matches(&pages, 0));
    let intent_index = intent_page_index(&pages);
    #[cfg(feature = "erc7730-dev-unattested")]
    {
        let mut warning_corruption = Pages::with_len(pages.len);
        warning_corruption.buf = pages.buf;
        warning_corruption.buf[0][0][0] ^= 1;
        assert!(
            !transcript.range_matches(&warning_corruption, 0),
            "the dev-unattested warning page is part of the transcript"
        );
    }

    let mut skipped_repaint = Pages::with_len(pages.len);
    skipped_repaint.buf = pages.buf;
    skipped_repaint.buf[intent_index] = [[b' '; DISPLAY_COLS]; 4];
    skipped_repaint.buf[intent_index][0].copy_from_slice(b"! INTENT INVALID");
    assert!(
        !transcript.range_matches(&skipped_repaint, 0),
        "the invalid initial paint must never satisfy the transcript receipt"
    );

    let mut static_substitution = Pages::with_len(pages.len);
    static_substitution.buf = pages.buf;
    static_substitution.buf[intent_index][0] = [b' '; DISPLAY_COLS];
    static_substitution.buf[intent_index][0][..10].copy_from_slice(b"Wrap stETH");
    assert!(
        !transcript.range_matches(&static_substitution, 0),
        "restoring the authenticated static title is not transcript authority"
    );

    for row in 0..4 {
        for col in 0..DISPLAY_COLS {
            let mut corrupted = Pages::with_len(pages.len);
            corrupted.buf = pages.buf;
            corrupted.buf[intent_index][row][col] ^= 1;
            assert!(
                !transcript.range_matches(&corrupted, 0),
                "every one of the 64 visible title bytes must be exact ({row},{col})"
            );
        }
    }

    let [r0, ..] = page_strs(&pages, intent_page_index(&pages));
    assert_eq!(r0, "Wrap 1.5 stETH");
    // The amount field must render under its authored label (proves
    // `#._stETHAmount` resolved to the right static-head slot).
    let amt_page = find_page_by_label(&pages, "stETH amount");
    let amount_rows = page_strs(&pages, amt_page);
    assert!(
        amount_rows[1].contains("1.5")
            && (amount_rows[1].contains("stETH") || amount_rows[2].contains("stETH")),
        "derived intent must not replace the ordinary amount page: {amount_rows:?}"
    );

    // Mount the same fixture through the production dispatcher seam. This
    // keeps the independently classified requirement and the renderer-issued
    // publication receipt alive through later handler-owned suffixes and the
    // final confirmation-boundary proof.
    let dispatch_once = |dispatch_tx: &Eip1559Tx| {
        let mut proofs = DispatchPageProofs::new();
        proofs.fail_initialize();
        let pages = pick_sign_pages(
            dispatch_tx,
            &calldata,
            &[0u8; 20],
            None,
            None,
            None,
            Some(&verified),
            Some(&steth_meta),
            None,
            &resolver,
            &mut proofs,
        )
        .expect("real wstETH fixture dispatches with its publication receipt");
        (pages, proofs)
    };
    let fingerprint_kind =
        Erc8213Kind::CalldataDigest(pqsigner_tx_core::erc8213::calldata_digest(&calldata));
    let append_later_suffixes = |pages: &mut Pages| {
        let prior_len = pages.len;
        append_fingerprint_for_test(pages, fingerprint_kind)
            .expect("later handler fingerprint suffix fits");
        assert_eq!(pages.len, prior_len + 2);
        assert_eq!(
            fingerprint_final_set_proof(pages, prior_len, fingerprint_kind),
            crate::fi::OK_SENTINEL,
            "the later suffix remains independently bound at final confirmation"
        );
    };
    let final_verdict = |proofs: &DispatchPageProofs, pages: &Pages| {
        let mut verdict = crate::fi::FAIL_SENTINEL;
        proofs.final_set_proof(pages, &tx, false, &mut verdict);
        verdict
    };

    let (mut dispatched_pages, dispatch_proofs) = dispatch_once(&tx);
    assert_eq!(
        page_strs(&dispatched_pages, intent_page_index(&dispatched_pages))[0],
        "Wrap 1.5 stETH"
    );
    append_later_suffixes(&mut dispatched_pages);
    assert_eq!(
        final_verdict(&dispatch_proofs, &dispatched_pages),
        crate::fi::OK_SENTINEL,
        "the real receipt must survive later append-only pages"
    );

    let mut omitted_init = DispatchPageProofs::new();
    assert!(
        pick_sign_pages(
            &tx,
            &calldata,
            &[0u8; 20],
            None,
            None,
            None,
            Some(&verified),
            Some(&steth_meta),
            None,
            &resolver,
            &mut omitted_init,
        )
        .is_err(),
        "omitting fail_initialize must refuse even when classification, render, and receipt otherwise agree"
    );

    let (mut corrupted_pages, corrupted_proofs) = dispatch_once(&tx);
    let corrupted_intent_index = intent_page_index(&corrupted_pages);
    append_later_suffixes(&mut corrupted_pages);
    corrupted_pages.buf[corrupted_intent_index][3][15] ^= 1;
    assert_eq!(
        final_verdict(&corrupted_proofs, &corrupted_pages),
        crate::fi::FAIL_SENTINEL,
        "one changed visible byte must invalidate the real receipt at the final boundary"
    );

    let (mut ordinary_corruption, ordinary_proofs) = dispatch_once(&tx);
    let amount_index = find_page_by_label(&ordinary_corruption, "stETH amount");
    append_later_suffixes(&mut ordinary_corruption);
    ordinary_corruption.buf[amount_index][1][0] ^= 1;
    assert_eq!(
        final_verdict(&ordinary_proofs, &ordinary_corruption),
        crate::fi::FAIL_SENTINEL,
        "an ordinary signed-field page is part of the full transcript"
    );

    let (inner_pages, mut batch_proofs) = dispatch_once(&tx);
    let mut batch_pages = Pages::with_len(inner_pages.len + 1);
    batch_pages.buf[0][0][..12].copy_from_slice(b"Batch member");
    for index in 0..inner_pages.len {
        batch_pages.buf[index + 1] = inner_pages.buf[index];
    }
    append_later_suffixes(&mut batch_pages);
    assert_eq!(
        final_verdict(&batch_proofs, &batch_pages),
        crate::fi::FAIL_SENTINEL,
        "adding a batch prefix without shifting the real receipt index must refuse"
    );
    batch_proofs
        .shift_indices(1)
        .expect("one-page batch prefix index shift");
    assert_eq!(
        final_verdict(&batch_proofs, &batch_pages),
        crate::fi::OK_SENTINEL,
        "the exact one-page batch-prefix shift must preserve the real receipt"
    );

    // Exact outer native value: the dispatcher-owned page is additive to the
    // ERC-7730 transcript, and both proofs must survive the one-page batch
    // prefix shift. Exactly 1 ETH is the positive member of the formatter's
    // real collision pair; 1 ETH + 1 wei and a literal 1 wei cannot be
    // represented by the fixed six-decimal native sink and therefore refuse.
    let mut exact_outer = envelope(1, entry.contract);
    exact_outer.value = u256_from_u64(1_000_000_000_000_000_000); // 1 ETH
    let (exact_inner, mut exact_outer_proofs) = dispatch_once(&exact_outer);
    let mut exact_batch = Pages::with_len(exact_inner.len + 1);
    exact_batch.buf[0][0][..12].copy_from_slice(b"Batch member");
    for index in 0..exact_inner.len {
        exact_batch.buf[index + 1] = exact_inner.buf[index];
    }
    exact_outer_proofs.shift_indices(1).unwrap();
    let mut exact_verdict = crate::fi::FAIL_SENTINEL;
    exact_outer_proofs.final_set_proof(&exact_batch, &exact_outer, false, &mut exact_verdict);
    assert_eq!(exact_verdict, crate::fi::OK_SENTINEL);

    let mut one_wei_outer = envelope(1, entry.contract);
    one_wei_outer.value = u256_from_u64(1);
    let mut one_wei_proofs = DispatchPageProofs::new();
    one_wei_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &one_wei_outer,
            &calldata,
            &[0u8; 20],
            None,
            None,
            None,
            Some(&verified),
            Some(&steth_meta),
            None,
            &resolver,
            &mut one_wei_proofs,
        )
        .is_err(),
        "one wei must refuse rather than alias to an exact-zero native page"
    );

    let mut one_eth_plus_one_wei_outer = envelope(1, entry.contract);
    one_eth_plus_one_wei_outer.value = u256_from_u64(1_000_000_000_000_000_001);
    let mut one_eth_plus_one_wei_proofs = DispatchPageProofs::new();
    one_eth_plus_one_wei_proofs.fail_initialize();
    assert!(
        pick_sign_pages(
            &one_eth_plus_one_wei_outer,
            &calldata,
            &[0u8; 20],
            None,
            None,
            None,
            Some(&verified),
            Some(&steth_meta),
            None,
            &resolver,
            &mut one_eth_plus_one_wei_proofs,
        )
        .is_err(),
        "1 ETH + 1 wei must refuse rather than alias to the exact 1 ETH page"
    );
}

/// Constant-annotation field (path-less `{value, label}`): the registry
/// yield.xyz USDe-vault `deposit(uint256,address)` descriptor carries
/// `{ "label": "Share ticker", "format": "raw", "value":
/// "$.metadata.constants.vaultTicker" }`, which the host resolves to the
/// literal "stk-USDe" and the device renders verbatim under its label — no
/// calldata binding. This is the construct the ERC-4626/7540 vault templates
/// use (the registry coverage lever that took render-coverage 40% -> 76%).
#[test]
fn positive_wsteth_wrap_renders_constant_annotation_field() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-yieldxyz-usde-vault.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // deposit(uint256 _underlying, address receiver).
    let mut calldata = keccak256(b"deposit(uint256,address)")[..4].to_vec();
    calldata.extend_from_slice(&u256_from_u64(1_000_000).0); // _underlying
    let mut recv = [0u8; 32];
    recv[12..].copy_from_slice(&[0x55u8; 20]); // receiver
    calldata.extend_from_slice(&recv);
    assert_selector_matches(&verified.ir, &calldata, "deposit(uint256,address)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let page = find_page_by_label(&pages, "Share ticker");
    let rows = page_strs(&pages, page);
    assert!(
        rows.iter().any(|r| r.contains("stk-USDe")),
        "constant-annotation field must render the resolved string: rows={rows:?}",
    );
}

// ───────────────────────────────────────────────────────────────────────
// Dynamic-array walker (sole-dynamic-array `<arg>.[]` render-all).
// Security-critical: it follows the dynamic calldata tail, the slot-
// confusion attack surface. All of the resolution safety lives in
// `formatters::resolve_array`; these tests drive it directly with crafted
// HOSTILE bodies (the descriptor is the trusted/pinned input, the calldata
// body is attacker-controlled) and diff it against the Kani-proven `walk`.
// ───────────────────────────────────────────────────────────────────────

/// Canonical `requestWithdrawals(uint256[],address)` calldata BODY (no
/// selector): `offset(0x40) | owner | length | amounts…`.
fn rw_body(amounts: &[U256], owner: [u8; 20]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&u256_from_u64(64).0); // offset to _amounts
    let mut ow = [0u8; 32];
    ow[12..].copy_from_slice(&owner);
    b.extend_from_slice(&ow); // _owner
    b.extend_from_slice(&u256_from_u64(amounts.len() as u64).0); // length
    for a in amounts {
        b.extend_from_slice(&a.0);
    }
    b
}

fn rw_calldata(amounts: &[U256], owner: [u8; 20]) -> Vec<u8> {
    let mut d = keccak256(b"requestWithdrawals(uint256[],address)")[..4].to_vec();
    d.extend_from_slice(&rw_body(amounts, owner));
    d
}

/// The Lido `_amounts.[]` array field + the format's `static_head_words`,
/// from the trusted/pinned descriptor.
fn lido_array_field<'a>(ir: &'a Erc7730Ir<'a>) -> (crate::tx::erc7730::FieldEntry<'a>, u16) {
    let sel = keccak256(b"requestWithdrawals(uint256[],address)");
    let s4: [u8; 4] = sel[..4].try_into().unwrap();
    let format = ir.find_format_by_selector(&s4).unwrap().unwrap();
    let field = format
        .fields()
        .filter_map(Result::ok)
        .find(|f| f.label == b"Amount")
        .expect("the `_amounts.[]` array field");
    (field, format.static_head_words)
}

#[test]
fn positive_lido_request_withdrawals_renders_every_element() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 1.0 / 2.5 / 0.3 stETH (18 decimals).
    let amounts = [
        u256_from_u64(1_000_000_000_000_000_000),
        u256_from_u64(2_500_000_000_000_000_000),
        u256_from_u64(300_000_000_000_000_000),
    ];
    let owner = [0x55u8; 20];
    let calldata = rw_calldata(&amounts, owner);
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "requestWithdrawals(uint256[],address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    // Header makes the count explicit. `write_amount_two_rows` splits an
    // amount across an integer row + a fraction row, so 2.5 → "2" / ".5".
    assert!(dump.contains("3 items"), "count header missing:\n{dump}");
    assert!(
        dump.contains(".5"),
        "amount 2.5 (fraction) missing:\n{dump}"
    );
    assert!(
        dump.contains(".3"),
        "amount 0.3 (fraction) missing:\n{dump}"
    );
    // ARRAY-TAIL-HIDING CLOSED, asserted concretely: one header page + EXACTLY
    // one page per element (3) all labelled "Amount" — never fewer.
    let amount_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]) == "Amount")
        .count();
    assert_eq!(
        amount_pages, 4,
        "expected 1 header + 3 element pages (every element shown):\n{dump}"
    );
    // owner page present.
    let _ = find_page_by_label(&pages, "Owner");
}

/// review finding 1.2 — a `raw`-formatted ARRAY ELEMENT must show EVERY signed
/// byte. The old array Raw arm passed two 16-byte slices to `write_hex_word`
/// (caps at 8 bytes/row), silently dropping bytes 8..16 and 24..32 — so a value
/// living there rendered as all-zeros (WYSIWYS magnitude-hiding, the array
/// sibling of the fixed scalar `render_raw` bug). This feeds an element word
/// with a nonzero byte in BOTH dropped ranges (byte 8 = 0xAA, byte 31 = 0x7B)
/// and asserts both appear on the rendered pages — they would BOTH be invisible
/// under the old form.
#[test]
fn positive_raw_array_element_shows_all_bytes_not_zeros() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-raw-array.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // One bytes32 element: byte[8]=0xAA (in the dropped 8..16 range) and
    // byte[31]=0x7B (in the dropped 24..32 range); everything else zero.
    let mut elem = [0u8; 32];
    elem[8] = 0xAA;
    elem[31] = 0x7B;
    let calldata = {
        let mut d = Vec::with_capacity(4 + 3 * 32);
        d.extend_from_slice(&keccak256(b"record(bytes32[])")[..4]);
        d.extend_from_slice(&u256_from_u64(0x20).0); // offset to the array
        d.extend_from_slice(&u256_from_u64(1).0); // length = 1
        d.extend_from_slice(&elem); // element 0
        d
    };
    assert_selector_matches(&verified.ir, &calldata, "record(bytes32[])");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Both previously-dropped bytes must now render.
    assert!(
        dump.contains("aa"),
        "byte 8 (0xAA, range 8..16) must render — the old form dropped it:\n{dump}"
    );
    assert!(
        dump.contains("7b"),
        "byte 31 (0x7B, low word, range 24..32) must render — the old form \
         dropped it, hiding any BE value < 2^64 as all-zeros:\n{dump}"
    );
}

/// review finding 1.1 — field-level `$ref` into `$.display.definitions` must
/// resolve, verified BY RENDER (not just "it compiled to a leaf", the exact
/// failure mode that shipped the degraded 1inch/paraswap routers). The
/// referenced `tokenAmount` FORMAT (from the definition) and the field-local
/// `tokenPath` param (the reference's own params) must BOTH reach the IR, so
/// the field renders a bound token amount rather than the blank-label 64-hex
/// raw dump the pre-fix silent `$ref`-drop produced. Also pins the `label`
/// merge in both directions: field 1 inherits the definition's "Amount to
/// Send" (it carries no label); field 2 overrides it with "Min Received".
#[test]
fn positive_synthetic_ref_field_renders_bound_token_amount() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-ref-token-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // srcToken == the bound USDC metadata below; the send field's
    // `tokenPath:"srcToken"` must resolve to it so "Amount to Send" binds.
    let usdc: [u8; 20] = hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        .unwrap()
        .try_into()
        .unwrap();
    let dst = [0x77u8; 20];
    let calldata = {
        let mut d = Vec::with_capacity(4 + 4 * 32);
        d.extend_from_slice(&keccak256(b"swap(address,address,uint256,uint256)")[..4]);
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&usdc);
        d.extend_from_slice(&w); // srcToken
        let mut w2 = [0u8; 32];
        w2[12..].copy_from_slice(&dst);
        d.extend_from_slice(&w2); // dstToken
        d.extend_from_slice(&u256_from_u64(1_500_000).0); // sendAmount = 1.5 USDC (6 dp)
        d.extend_from_slice(&u256_from_u64(900_000).0); // minReceive
        d
    };
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "swap(address,address,uint256,uint256)",
    );

    let tx = envelope(1, entry.contract);
    let usdc_meta = Erc20Metadata {
        chain_id: 1,
        contract: usdc,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&usdc_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages);

    // Field 1: definition's label inherited (the field carries none).
    let send_page = find_page_by_label(&pages, "Amount to Send");
    // `$ref` resolved to `tokenAmount` (format from def) AND kept the field's
    // `tokenPath:"srcToken"` (params merge) → a bound USDC amount, not a raw
    // 64-hex dump. Both survivals are proven by the ticker + scaled value.
    let send_rows = page_strs(&pages, send_page).join(" ");
    assert!(
        send_rows.contains("USDC"),
        "send amount must bind the USDC ticker (proves format-from-def + tokenPath-from-field both survived $ref):\n{dump}"
    );
    assert!(
        send_rows.contains(".5"),
        "send amount 1.5 (fraction row) missing — field degraded to raw?:\n{dump}"
    );

    // Field 2: field-local label OVERRIDES the definition's "Amount to Receive".
    let _ = find_page_by_label(&pages, "Min Received");
    assert!(
        !dump.contains("Amount to Receive"),
        "field-local `label` must override the definition's label:\n{dump}"
    );
}

/// The REAL registry Lido `requestWithdrawals` leaf — a `tokenAmount` `uint256[]`
/// array (the synthetic fixture uses `format:amount`; EVERY registry `uint256[]`
/// uses `tokenAmount`, so this is the shape the synthetic cannot exercise, and
/// the render-faithfulness spot-check on a real registry descriptor).
/// BOUND branch: with Merkle-verified stETH metadata the shared token is
/// resolved ONCE and every element renders as a scaled `stETH` amount.
#[test]
fn positive_registry_lido_tokenamount_array_bound_renders_steth() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WithdrawalQueueERC721.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 1.0 / 2.5 / 0.3 stETH (18 decimals).
    let amounts = [
        u256_from_u64(1_000_000_000_000_000_000),
        u256_from_u64(2_500_000_000_000_000_000),
        u256_from_u64(300_000_000_000_000_000),
    ];
    let calldata = rw_calldata(&amounts, [0x55u8; 20]);
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "requestWithdrawals(uint256[],address)",
    );

    // Registry `token` is the stETH constant (0xae7ab9…); supply its metadata.
    let steth: [u8; 20] = hex::decode("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84")
        .unwrap()
        .try_into()
        .unwrap();
    let steth_meta = Erc20Metadata {
        chain_id: 1,
        contract: steth,
        decimals: 18,
        name: b"Liquid staked Ether 2.0",
        symbol: b"stETH",
    };
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, Some(&steth_meta), &resolver)
        .expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    assert!(dump.contains("3 items"), "count header missing:\n{dump}");
    assert!(dump.contains(".5"), "amount 2.5 fraction missing:\n{dump}");
    // WYSIWYS: EXACTLY the 3 element pages (label "Amount") show the bound
    // symbol — proves the shared token was Merkle-bound and applied per element
    // (not declined-to-blind), and array-tail-hiding stays closed (all shown).
    let steth_element_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]) == "Amount" && (1..=2).any(|r| row_str(&p[r]).contains("stETH")))
        .count();
    assert_eq!(
        steth_element_pages, 3,
        "every element must render as stETH:\n{dump}"
    );
    // Bound → no UNVERIFIED token page.
    let unverified = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]).contains("UNVERIF"))
        .count();
    assert_eq!(
        unverified, 0,
        "bound token must not show UNVERIFIED:\n{dump}"
    );
    let _ = find_page_by_label(&pages, "Beneficiary");
}

/// Same registry leaf, UNBOUND branch (audit M-4 + M-1): with NO Merkle-verified
/// metadata each element renders as a loud RAW integer (never a scaled decimal
/// with an assumed scale) and the token identity is named EXACTLY ONCE — not
/// per element.
#[test]
fn positive_registry_lido_tokenamount_array_unbound_raw_and_one_token_page() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-WithdrawalQueueERC721.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    let amounts = [
        u256_from_u64(1_000_000_000_000_000_000),
        u256_from_u64(2_500_000_000_000_000_000),
    ];
    let calldata = rw_calldata(&amounts, [0x55u8; 20]);
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    // No stETH metadata supplied → unbound.
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    // M-4: every element footer is the loud raw/unknown-scale marker.
    let raw_footers = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[3]).contains("raw, dec=?"))
        .count();
    assert_eq!(
        raw_footers, 2,
        "both unbound elements must render loud raw:\n{dump}"
    );
    // M-1: the token is named EXACTLY ONCE (a per-element page would be noise
    // and could push the array past the page budget).
    let token_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]).contains("UNVERIF"))
        .count();
    assert_eq!(
        token_pages, 1,
        "unbound token must be named exactly once:\n{dump}"
    );
}

/// COMPLETENESS + FAITHFULNESS over the WHOLE prod registry: enumerates every
/// compiled sole-dynamic-array (`<arg>.[]`) field across all 776 leaves and
/// checks two things the roundtrip/Kani tests can't (they never render):
///
/// 1. **Coverage guard** — every compiled array's element `format_op` has a
///    `render_array_element` arm (`Raw`/`Amount`/`TokenAmount`/`AddressName`).
///    If a `unit`/`calldata`/nested array ever slips the dbgen gate into the
///    corpus, a verified known call would hard-refuse on a real user tx; this
///    fails loudly during generation/testing instead. (This is the durable
///    regression guard.)
/// 2. **End-to-end render** — the sole-dynamic arrays whose siblings my generic
///    calldata satisfies actually RENDER every element (array-tail-hiding
///    closed). `visible:never` arrays (e.g. `setAllowedTargets`, Raw+hidden)
///    and multi-field functions my stub calldata can't fully satisfy simply
///    don't reach the ≥4-page bar — that's fine, they're covered by (1) and
///    must not crash.
#[test]
fn all_compiled_registry_array_leaves_render() {
    // render_array_element arms: Raw=0x01, Amount=0x02, TokenAmount=0x03,
    // AddressName=0x07, Unit=0x09 (see pqsigner_erc7730::ir::FormatOp).
    const HANDLED: &[u8] = &[0x01, 0x02, 0x03, 0x07, 0x09];
    let res = build_registry();
    let mut all_arrays: Vec<(String, u8)> = Vec::new();
    let mut rendered: Vec<(String, u8)> = Vec::new();

    for entry in res.entries.iter() {
        let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let Ok(verified) = verify_erc7730_bundle(&bundle, &res.root) else {
            continue;
        };
        let mut arrays: Vec<([u8; 4], usize, Vec<u8>, u8)> = Vec::new();
        for format in verified.ir.format_iter() {
            let Ok(format) = format else { continue };
            for field in format.fields() {
                let Ok(field) = field else { continue };
                let is_arr = super::erc7730::formatters::path_ends_with_array_all(
                    &verified.ir,
                    field.path_off,
                )
                .unwrap_or(false);
                if is_arr {
                    arrays.push((
                        format.selector,
                        format.static_head_words as usize,
                        field.label.to_vec(),
                        field.format_op,
                    ));
                }
            }
        }

        for (selector, shw, label, fmt_op) in arrays {
            let key = format!(
                "{}  sel={}  elem_fmt={}",
                entry
                    .source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?"),
                hex::encode(selector),
                fmt_op,
            );
            all_arrays.push((key.clone(), fmt_op));

            // Canonical SOLE-dynamic-array calldata: selector + head (all words
            // = head_end, so the array's offset slot reads `offset == head_end`
            // whichever slot it is, and every other head field renders that
            // value as a scalar) + tail `[count=3][1][2][3]`.
            let head_end = shw * 32;
            let mut cd = selector.to_vec();
            for _ in 0..shw {
                cd.extend_from_slice(&u256_from_u64(head_end as u64).0);
            }
            cd.extend_from_slice(&u256_from_u64(3).0); // count
            for i in 1..=3u64 {
                cd.extend_from_slice(&u256_from_u64(i).0);
            }

            let tx = envelope(entry.chain_id, entry.contract);
            let resolver = NameResolver::new();
            let want_bytes = &label[..label.len().min(DISPLAY_COLS)];
            let want = String::from_utf8_lossy(want_bytes);
            let want = want.trim_end();
            // A render must never CRASH on a corpus leaf; a decline (Err) or a
            // hidden/unsatisfied field (0 label pages) is acceptable here.
            if let Ok(pages) = render_erc7730_pages(&tx, &cd, &verified, None, &resolver) {
                let label_pages = pages
                    .as_slice()
                    .iter()
                    .filter(|p| row_str(&p[0]) == want)
                    .count();
                if label_pages >= 4 {
                    // header + 3 element pages: every element shown.
                    rendered.push((key, fmt_op));
                }
            }
        }
    }

    // (1) Coverage guard — the durable regression check.
    let unhandled: Vec<&(String, u8)> = all_arrays
        .iter()
        .filter(|(_, f)| !HANDLED.contains(f))
        .collect();
    assert!(
        unhandled.is_empty(),
        "compiled ArrayAll field(s) whose element format has NO render_array_element arm \
         (would hard-refuse if visible — add the arm or tighten the dbgen \
         gate):\n{unhandled:#?}",
    );

    // (2) End-to-end non-vacuity — real sole-dynamic arrays render every element.
    eprintln!(
        "compiled registry array fields: {} total, {} rendered end-to-end",
        all_arrays.len(),
        rendered.len()
    );
    for (k, _f) in &rendered {
        eprintln!("  RENDER  {k}");
    }
    assert!(
        rendered.len() >= 6,
        "expected several sole-dynamic array leaves to render every element, found {}",
        rendered.len()
    );
}

// ───────────────────────────────────────────────────────────────────────
// C1 — dynamic `bytes`/`string` leaf (FollowOffset). The value lives in the
// calldata tail; the device follows the ABI offset at the arg's head slot and
// reads the length-prefixed blob — the SAME position the contract decodes.
// ───────────────────────────────────────────────────────────────────────

/// `f(bytes arg)` calldata: selector + `[offset=32][len][data padded to 32]`.
fn calldata_sole_bytes(sig: &[u8], data: &[u8]) -> Vec<u8> {
    let mut cd = keccak256(sig)[..4].to_vec();
    cd.extend_from_slice(&u256_from_u64(32).0); // offset to the bytes arg
    cd.extend_from_slice(&u256_from_u64(data.len() as u64).0); // length
    if !data.is_empty() {
        let mut padded = data.to_vec();
        while padded.len() % 32 != 0 {
            padded.push(0);
        }
        cd.extend_from_slice(&padded);
    }
    cd
}

/// Production does not advertise `addStorageRoot(bytes)`, and the independent
/// runtime belt rejects the same opaque type even when its attacker-controlled
/// bytes happen to be printable. Payload printability is not authenticated type
/// information and must never turn arbitrary bytes into a trusted string.
#[test]
fn c1_dynamic_bytes_declines_even_when_printable() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-celo_accounts.json", 42220);
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("Celo Accounts IR parses");
    let selector: [u8; 4] = keccak256(b"addStorageRoot(bytes)")[..4].try_into().unwrap();
    assert!(
        ir.find_format_by_selector(&selector)
            .expect("format table is well formed")
            .is_none(),
        "opaque dynamic bytes format must not be advertised in production"
    );

    for url in [&b"a"[..], b"https://ex.io/s", b"ipfs://Qm12345"] {
        assert_opaque_bytes_runtime_rejected(url);
    }
}

/// Non-printable/oversized bytes also decline. A length and short preview are
/// not injective: equal-length blobs sharing the prefix would show identical
/// clear-sign pages while signing different calldata.
#[test]
fn c1_opaque_bytes_decline_without_lossy_preview() {
    let payload = [0xFFu8; 40]; // binary, 40 bytes → opaque
    assert_opaque_bytes_runtime_rejected(&payload);
}

/// Morpho Blue `borrow` — the nested static-tuple GROUP (`marketParams`)
/// unlocked by field-group flattening. Drives the REAL shipping registry leaf
/// (`calldata-MorphoBlue.json`, mainnet). WYSIWYS differential value-equality:
/// every member of the 5-word `marketParams` tuple AND every post-tuple
/// argument renders from its EXACT ABI head-word slot — `assets` at head word
/// 5, `receiver` at head word 8 (the non-leading-static-tuple slots the
/// slot-confusion fix guards). If the flatten mis-computed any member's slot,
/// the rendered value would differ from the encoded word and this fails.
#[test]
fn morpho_borrow_nested_tuple_group_renders_exact_values() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-MorphoBlue.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // Distinct, recognizable words at each of the 9 head slots.
    let addr_word = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let loan = [0x11u8; 20];
    let collat = [0x22u8; 20];
    let oracle = [0x33u8; 20];
    let irm = [0x44u8; 20];
    let on_behalf = [0x66u8; 20];
    let receiver = [0x77u8; 20];

    let types_sig =
        "borrow((address,address,address,address,uint256),uint256,uint256,address,address)";
    let mut cd = keccak256(types_sig.as_bytes())[..4].to_vec();
    cd.extend_from_slice(&addr_word(loan)); // slot 0: loanToken
    cd.extend_from_slice(&addr_word(collat)); // slot 1: collateralToken
    cd.extend_from_slice(&addr_word(oracle)); // slot 2: oracle
    cd.extend_from_slice(&addr_word(irm)); // slot 3: irm
    cd.extend_from_slice(&u256_from_u64(0xBEEF).0); // slot 4: lltv
    cd.extend_from_slice(&u256_from_u64(0xA55E5).0); // slot 5: assets (AFTER tuple)
    cd.extend_from_slice(&u256_from_u64(0).0); // slot 6: shares
    cd.extend_from_slice(&addr_word(on_behalf)); // slot 7: onBehalf
    cd.extend_from_slice(&addr_word(receiver)); // slot 8: receiver
                                                // Confirms the selector matches AND `borrow` actually compiled into the IR.
    assert_selector_matches(&verified.ir, &cd, types_sig);

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &cd, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();

    // Tuple members read from their exact slots (addresses not in ERC20_DB/ENS
    // render as the raw calldata address — still faithful to the signed word).
    assert!(
        dump.contains("1111"),
        "loanToken (tuple slot 0) not read:\n{dump}"
    );
    assert!(
        dump.contains("2222"),
        "collateralToken (tuple slot 1) not read:\n{dump}"
    );
    assert!(
        dump.contains("3333"),
        "oracle (tuple slot 2) not read:\n{dump}"
    );
    assert!(
        dump.contains("4444"),
        "irm (tuple slot 3) not read:\n{dump}"
    );
    assert!(
        dump.contains("beef"),
        "lltv (tuple slot 4) not read:\n{dump}"
    );
    // Post-tuple args at their WIDTH-AWARE head slots (not logical ordinals).
    assert!(
        dump.contains("a55e5"),
        "assets (head slot 5, AFTER the 5-word tuple) not read:\n{dump}"
    );
    assert!(
        dump.contains("6666"),
        "onBehalf (head slot 7) not read:\n{dump}"
    );
    assert!(
        dump.contains("7777"),
        "receiver (head slot 8) not read:\n{dump}"
    );
    // Labels the descriptor declares are present.
    let _ = find_page_by_label(&pages, "Loan Token");
    let _ = find_page_by_label(&pages, "Assets");
    let _ = find_page_by_label(&pages, "Receiver");
}

#[test]
fn array_resolve_matches_walk_differential() {
    // When the Kani-proven `walk` accepts the body, our resolver must agree
    // EXACTLY on (element-start, count). (Not the converse — we are stricter.)
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let (field, shw) = lido_array_field(&verified.ir);

    let parsed =
        pqsigner_tx::typed_call::parser::parse_text_sig(b"requestWithdrawals(uint256[],address)")
            .unwrap();

    for amounts in [
        vec![],
        vec![u256_from_u64(7)],
        vec![u256_from_u64(7), u256_from_u64(8), u256_from_u64(9)],
    ] {
        let body = rw_body(&amounts, [0x11u8; 20]);
        let walked = pqsigner_tx::typed_call::abi::walk(&parsed, &body).expect("walk accepts");
        let amounts_arg = walked.args[0]; // body_off = the length word
        let (elems_start, count) =
            super::erc7730::formatters::resolve_array(&field, &verified.ir, &body, shw)
                .expect("resolver accepts the same canonical body");
        assert_eq!(
            count, amounts_arg.count as usize,
            "count disagrees with walk"
        );
        assert_eq!(
            elems_start,
            amounts_arg.body_off + 32,
            "element-start disagrees with walk (walk body_off is the length word)"
        );
        // element words must be byte-identical to what walk points at.
        for i in 0..count {
            let mine = &body[elems_start + i * 32..elems_start + i * 32 + 32];
            assert_eq!(mine, &amounts[i].0, "element {i} word mismatch");
        }
    }
}

/// Minimal IR blob carrying just `pool` (CTX_CONTRACT, empty formats) so a
/// test can drive `path_ends_with_array_all` over hand-built path programs.
fn ir_bytes_with_pool(pool: &[u8]) -> Vec<u8> {
    let hl = pqsigner_erc7730::ir::HEADER_LEN;
    let pool_len = pool.len() as u16;
    let mut buf = vec![0u8; hl];
    buf[0] = pqsigner_erc7730::ir::SCHEMA_VER;
    buf[1] = 0x01; // CTX_CONTRACT
    buf[2..10].copy_from_slice(&1u64.to_be_bytes());
    buf[126..128].copy_from_slice(&(hl as u16).to_be_bytes()); // metadata_off
    buf[128..130].copy_from_slice(&((hl as u16) + pool_len).to_be_bytes()); // formats_off
    buf[130..132].copy_from_slice(&pool_len.to_be_bytes()); // pool_len
    buf[132..134].copy_from_slice(&1u16.to_be_bytes()); // formats_len (count byte)
    buf.extend_from_slice(pool);
    buf.push(0u8); // format count = 0
    buf
}

#[test]
fn array_routing_is_structural_not_last_byte() {
    // A SCALAR path [Root][FieldIdx(arg=0x0024)] ends in the byte 0x24, which
    // == PathOp::ArrayAll — but it is NOT an array path. The structural router
    // must return false (→ scalar dispatch / clear-sign), NOT misroute it to
    // render_array (which would needlessly blind-sign a clear-signable field).
    let mut pool = vec![0xFFu8]; // offset-0 filler
    let scalar_off = pool.len() as u16;
    pool.push(4);
    pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x24]); // Root, FieldIdx(0x0024)
    let array_off = pool.len() as u16;
    pool.push(5);
    pool.extend_from_slice(&[0x10, 0x20, 0x00, 0x00, 0x24]); // Root, FieldIdx(0), ArrayAll
    let bytes = ir_bytes_with_pool(&pool);
    let ir = pqsigner_erc7730::ir::Erc7730Ir::parse(&bytes).unwrap();

    assert!(
        !super::erc7730::formatters::path_ends_with_array_all(&ir, scalar_off).unwrap(),
        "scalar FieldIdx whose arg low byte is 0x24 must NOT route to render_array"
    );
    assert!(
        super::erc7730::formatters::path_ends_with_array_all(&ir, array_off).unwrap(),
        "a real Root+FieldIdx+ArrayAll path routes to render_array"
    );
    // PathOp::ArrayAll is the wire constant the router + dbgen agree on.
    assert_eq!(pqsigner_erc7730::ir::PathOp::ArrayAll as u8, 0x24);
}

#[test]
fn adversarial_array_resolve_declines_hostile_bodies() {
    let res = build_seed();
    let entry = find_leaf(&res, "synthetic-uint256-array-amount.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    let (field, shw) = lido_array_field(&verified.ir);
    let ir = &verified.ir;
    let resolve = |body: &[u8]| super::erc7730::formatters::resolve_array(&field, ir, body, shw);

    // Baseline: a canonical 2-element body resolves to (elems_start=96, count=2).
    let canon = rw_body(&[u256_from_u64(1), u256_from_u64(2)], [0x11u8; 20]);
    assert_eq!(resolve(&canon).unwrap(), (96, 2));

    // (1) offset word top-28-bytes nonzero (huge offset) → decline.
    let mut b = canon.clone();
    b[0] = 0x01;
    assert!(resolve(&b).is_err(), "huge offset must decline");

    // (2) offset != head-end (gap after the head) → decline.
    let mut b = canon.clone();
    b[31] = 96; // offset 0x60 instead of 0x40
    assert!(resolve(&b).is_err(), "non-head-end offset must decline");

    // (3) offset points INTO the head (alias the owner word) → decline.
    let mut b = canon.clone();
    b[31] = 32;
    assert!(resolve(&b).is_err(), "offset-into-head must decline");

    // (4a) length word top-28-bytes nonzero → decline.
    let mut b = canon.clone();
    b[64] = 0x01; // first byte of the length word (at offset 64)
    assert!(resolve(&b).is_err(), "huge length (top bytes) must decline");

    // (4b) length > MAX_DYNAMIC_LEN → decline.
    let mut b = rw_body(&[u256_from_u64(1)], [0x11u8; 20]);
    // overwrite the length word (offset 64) with MAX_DYNAMIC_LEN + 1.
    let big = (1u32 << 20) + 1;
    b[64 + 28..64 + 32].copy_from_slice(&big.to_be_bytes());
    assert!(resolve(&b).is_err(), "length over the cap must decline");

    // (5a) length OVER-claims (says 3, body holds 2) → decline (not whole tail).
    let mut b = canon.clone();
    b[64 + 31] = 3;
    assert!(resolve(&b).is_err(), "length over-claim must decline");

    // (5b) length UNDER-claims (says 1, body holds 2) → decline (not whole tail).
    let mut b = canon.clone();
    b[64 + 31] = 1;
    assert!(resolve(&b).is_err(), "length under-claim must decline");

    // (6) body truncated mid-element (drop the last 16 bytes of a 2-elem body).
    let b = &canon[..canon.len() - 16];
    assert!(resolve(b).is_err(), "truncated-mid-element must decline");

    // (7) body length not a multiple of 32 (drop 1 byte) → decline.
    let b = &canon[..canon.len() - 1];
    assert!(resolve(b).is_err(), "non-32-aligned body must decline");

    // (8) count == 0 → VALID (renders an empty page, no panic); resolver Ok(_, 0).
    let empty = rw_body(&[], [0x11u8; 20]);
    assert_eq!(
        resolve(&empty).unwrap().1,
        0,
        "empty array is valid, count 0"
    );

    // (9) count large-but-in-bounds (9 > MAX_ARRAY_RENDER=8) → decline, not 9 pages.
    let nine: Vec<U256> = (0..9).map(|i| u256_from_u64(i)).collect();
    let b = rw_body(&nine, [0x11u8; 20]);
    assert!(resolve(&b).is_err(), "over-cap element count must decline");

    // (10) head absent entirely (body shorter than the static head) → decline.
    let b = &canon[..16];
    assert!(resolve(b).is_err(), "short-head must decline");

    // none of the above panicked — the decline-or-safe property holds over all
    // crafted bodies (no UB, no slice-OOB), the core adversarial guarantee.
}

// ───────────────────────────────────────────────────────────────────────
// WYSIWYS belt — VULN-erc7730-visible-never-noparam-clearsign.
//
// A contract-context format that DECLARES a field but renders NONE (the
// field is `visible:"never"`) must be refused on-device so the dispatcher
// falls through to the honest blind-sign ladder instead of a parameter-less
// clear-sign. The build-time visibility gate refuses to COMPILE an
// all-`never` format, so this drives the belt directly: compile a valid
// one-field format with the field `visible:"optional"` (passes the gate and
// emits a visibility TLV), flip that TLV to `never` in the IR bytes, and
// render the patched descriptor — the exact bad-DB shape the belt exists to
// catch even though the gate makes it unshippable.
// ───────────────────────────────────────────────────────────────────────
#[test]
fn belt_rejects_all_hidden_contract_format() {
    use pqsigner_erc7730::ir::HEADER_LEN;

    // 1. Compile a valid one-field descriptor (field visible → passes gate).
    let dir = std::env::temp_dir().join(format!("pq_erc7730_belt_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let contract = [0xABu8; 20];
    let addr_hex: String = contract.iter().map(|b| format!("{b:02x}")).collect();
    let desc = format!(
        r#"{{
          "context": {{ "contract": {{ "deployments": [
            {{ "chainId": 1, "address": "0x{addr_hex}" }}
          ] }} }},
          "metadata": {{ "owner": "Belt", "contractName": "Belt" }},
          "display": {{ "formats": {{
            "poke(uint256 amount)": {{
              "intent": "Poke",
              "fields": [
                {{ "path": "amount", "label": "Amount", "format": "raw", "visible": "optional" }}
              ]
            }}
          }} }}
        }}"#
    );
    std::fs::write(dir.join("belt.json"), desc).expect("write desc");
    let policy = workspace_root().join("secure/data/erc7730/policy.toml");
    let res = dbgen::erc7730::build_db(&dir, &policy).expect("compile one-field descriptor");
    let _ = std::fs::remove_dir_all(&dir);
    let mut ir_bytes = res.entries[0].ir_bytes.clone();

    // 2. Flip the field's visibility TLV `optional (0x02)` → `never (0x01)`.
    //    Search past the fixed header only (its sha256 descriptor_hash could
    //    coincidentally hold the 3-byte pattern). push_tlv layout is
    //    `[kind=0x3F][len=0x01][value]`.
    let pat = [0x3Fu8, 0x01, 0x02];
    let hits: Vec<usize> = (HEADER_LEN..ir_bytes.len().saturating_sub(2))
        .filter(|&i| ir_bytes[i..i + 3] == pat)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "exactly one visibility TLV to flip, found {hits:?}"
    );
    ir_bytes[hits[0] + 2] = 0x01; // VIS_NEVER

    // 3. Render the patched IR directly (bypass Merkle verify — we test only
    //    the belt, and VerifiedDescriptor.ir is a public field).
    let ir = Erc7730Ir::parse(&ir_bytes).expect("patched IR still parses");
    assert!(matches!(ir.context_kind, ContextKind::Contract));
    let verified = VerifiedDescriptor { ir };

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&keccak256(b"poke(uint256)")[..4]);
    calldata.extend_from_slice(&u256_from_u64(42).0);
    let tx = envelope(1, contract);
    let resolver = NameResolver::new();

    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::Reject(msg)) => {
            assert!(
                msg.contains("no visible fields"),
                "belt reject message: {msg}"
            );
        }
        Err(other) => panic!("expected belt Reject, got a different RenderErr: {other:?}"),
        Ok(_) => panic!(
            "all-hidden contract format must be belt-rejected, but it rendered clear-sign pages"
        ),
    }
}

#[test]
fn eip712_v2_two_pass_transcript_binds_static_warning_and_fields() {
    let res = build_registry();
    let entry = find_leaf(res, "eip712-tally-ethereum-pool-token.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify EIP-712 leaf");
    assert!(matches!(verified.ir.context_kind, ContextKind::Eip712));
    let format = verified
        .ir
        .format_iter()
        .next()
        .expect("one format")
        .expect("valid format");

    let mut encoded_data = vec![0u8; format.static_head_words as usize * 32];
    encoded_data[12..32].copy_from_slice(&[0x11; 20]);
    encoded_data[32..64].copy_from_slice(&u256_from_u64(7).0);
    encoded_data[64..96].copy_from_slice(&u256_from_u64(1_800_000_000).0);

    let resolver = NameResolver::new();
    let (mut pages, proof) = super::erc7730_secure_shim::render_erc7730_eip712_pages_checked(
        1,
        &entry.contract,
        &format.type_hash,
        &encoded_data,
        &verified,
        None,
        &resolver,
    )
    .expect("checked V2 EIP-712 render");
    assert_all_pages_printable(&pages);
    assert!(dump_pages(&pages).contains("POOL token"));
    let field_page = find_page_by_label(&pages, "Delegatee");

    append_fingerprint_for_test(&mut pages, Erc8213Kind::Eip712Final([0x77; 32]))
        .expect("handler fingerprint suffix fits");
    assert_eq!(
        eip712_transcript_verdict(&proof, &pages),
        crate::fi::OK_SENTINEL,
        "handler-owned fingerprint suffix must preserve the renderer range"
    );

    let mut static_corruption = Pages::with_len(pages.len);
    static_corruption.buf = pages.buf;
    let intent_index = intent_page_index(&static_corruption);
    static_corruption.buf[intent_index][0][0] ^= 1;
    assert_eq!(
        eip712_transcript_verdict(&proof, &static_corruption),
        crate::fi::FAIL_SENTINEL,
        "authenticated static intent bytes are transcript-bound"
    );

    let mut field_corruption = Pages::with_len(pages.len);
    field_corruption.buf = pages.buf;
    field_corruption.buf[field_page][1][0] ^= 1;
    assert_eq!(
        eip712_transcript_verdict(&proof, &field_corruption),
        crate::fi::FAIL_SENTINEL,
        "every displayed EIP-712 field is transcript-bound"
    );

    #[cfg(feature = "erc7730-dev-unattested")]
    {
        let mut warning_corruption = Pages::with_len(pages.len);
        warning_corruption.buf = pages.buf;
        warning_corruption.buf[0][0][0] ^= 1;
        assert_eq!(
            eip712_transcript_verdict(&proof, &warning_corruption),
            crate::fi::FAIL_SENTINEL,
            "the dev-unattested warning is part of the EIP-712 transcript"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// VULN-erc7730-eip712-nested-struct-address-hide — on-device belt.
//
// A pinned EIP-712 descriptor whose primary type has a nested struct member
// (a single opaque `hashStruct` word this renderer cannot expand) MUST be
// declined to blind-sign, not partially clear-signed or mis-resolved. Driven
// by a safe-visible, dbgen-emitted copy of the real Uniswap Permit2 descriptor
// (its `PermitSingle` / `PermitTransferFrom` nest a `PermitDetails` /
// `TokenPermissions` struct). Production absence is asserted separately.
// ───────────────────────────────────────────────────────────────────────
#[test]
fn v2_kind_declines_nested_permit2() {
    // Post-Phase-5: a nested-struct format signed via the OLD kind
    // (`render_erc7730_eip712_pages`, no `nested_blob`) MUST still decline — the
    // descent finds no DFS record to bind the `PermitDetails` hashStruct word,
    // so the whole render Rejects. A companion must use the V3 entry. This keeps
    // the "old kind never clear-signs a nested format" guarantee.
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    assert!(matches!(ir.context_kind, ContextKind::Eip712));

    let fmt = ir
        .format_iter()
        .next()
        .expect("≥1 Permit2 format")
        .expect("valid format header");
    let pth = fmt.type_hash;
    let encoded_data = std::vec![0u8; fmt.static_head_words as usize * 32];

    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    match super::erc7730::render_erc7730_eip712_pages(
        1,
        &[0u8; 20],
        &pth,
        &encoded_data,
        &verified,
        None,
        &resolver,
    ) {
        Err(crate::tx::erc7730_render::RenderErr::Reject(_)) => {}
        Err(other) => panic!("expected a nested Reject, got {other:?}"),
        Ok(_) => {
            panic!("nested Permit2 format must NOT clear-sign via the V2 (no-nested-blob) path")
        }
    }
}

// ───────────────────────────────────────────────────────────────────────
// THE DECISIVE nested-EIP-712 test (design §3 rule 6): a safe-visible copy of
// the real Permit2 PermitSingle type drives the V3 render path. Every explicit
// descriptor field is visible in this fixture. The binding test proves that
// flipping ANY nested word or the committed top-level `details` word declines.
// (a) alone would pass even if the keccak binding were never checked; (b) is
// what proves shown ⟺ signed.
// ───────────────────────────────────────────────────────────────────────

// typeHash(PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)) — foundry.
const PERMIT_DETAILS_TYPEHASH: [u8; 32] = [
    0x65, 0x62, 0x6c, 0xad, 0x6c, 0xb9, 0x64, 0x93, 0xbf, 0x6f, 0x5e, 0xbe, 0xa2, 0x87, 0x56, 0xc9,
    0x66, 0xf0, 0x23, 0xab, 0x9e, 0x8a, 0x83, 0xa7, 0x10, 0x18, 0x49, 0xd5, 0x57, 0x3b, 0x36, 0x78,
];

/// Build a valid PermitSingle (top `encoded_data`, `nested_blob`) for a concrete
/// order. `nested_ed` = token | amount | expiration | nonce (4 words); the top
/// `details` word is the REAL `hashStruct(PermitDetails)` = the device's binding
/// target. Returns `(top_ed[96], nested_blob[2+128])`.
fn permit_single_vectors(
    token: [u8; 20],
    amount: u64,
    expiration: u64,
    nonce: u64,
    spender: [u8; 20],
    sig_deadline: u64,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut nested_ed = std::vec![0u8; 128];
    nested_ed[12..32].copy_from_slice(&token);
    nested_ed[32 + 24..64].copy_from_slice(&amount.to_be_bytes());
    nested_ed[64 + 24..96].copy_from_slice(&expiration.to_be_bytes());
    nested_ed[96 + 24..128].copy_from_slice(&nonce.to_be_bytes());

    // The committed word IS the real hashStruct — the same primitive the device
    // recomputes and binds against (not circular: the device uses the IR-pinned
    // type_hash + the blob's nested_ed; a flip in either breaks the equality).
    let details_hs = super::erc7730::nested::hash_struct(&PERMIT_DETAILS_TYPEHASH, &nested_ed);

    let mut top_ed = std::vec![0u8; 96];
    top_ed[0..32].copy_from_slice(&details_hs);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&sig_deadline.to_be_bytes());

    let mut nested_blob = std::vec![0u8; 2];
    nested_blob[0..2].copy_from_slice(&(nested_ed.len() as u16).to_be_bytes());
    nested_blob.extend_from_slice(&nested_ed);

    (top_ed, nested_blob)
}

#[test]
fn v3_permit_single_renders_nested_members() {
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    // PermitSingle primary-type hash in the safe-visible Permit2 fixture.
    let pth: [u8; 32] = [
        0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79,
        0x97, 0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10,
        0xf3, 0xd0,
    ];
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ]; // USDC
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ]; // Universal Router
    let (top_ed, nested_blob) = permit_single_vectors(
        token,
        1_000_000_000,
        1_735_689_600,
        0,
        spender,
        1_735_689_600,
    );

    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let (mut pages, proof) = super::erc7730_secure_shim::render_erc7730_eip712_pages_v3_checked(
        1,
        &[0u8; 20],
        &pth,
        &top_ed,
        &nested_blob,
        &verified,
        None,
        &resolver,
    )
    .expect("valid PermitSingle clear-signs via checked V3");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // spender (top-level, shown).
    assert!(dump.contains("3fc9"), "spender must be shown:\n{dump}");
    // nested amount = 1_000_000_000 → without token metadata it renders raw
    // (`! raw, dec=?`); the digits must appear.
    assert!(
        dump.contains("1000000000"),
        "nested amount must render:\n{dump}"
    );
    // nested expiration is a timestamp date → a 2025 date renders.
    assert!(
        dump.contains("2025"),
        "nested expiration date must render:\n{dump}"
    );

    let spender_page = find_page_by_label(&pages, "Spender");
    append_fingerprint_for_test(&mut pages, Erc8213Kind::Eip712Final([0x88; 32]))
        .expect("V3 handler fingerprint suffix fits");
    assert_eq!(
        eip712_transcript_verdict(&proof, &pages),
        crate::fi::OK_SENTINEL,
        "checked V3 transcript survives only the handler suffix"
    );
    pages.buf[spender_page][1][0] ^= 1;
    assert_eq!(
        eip712_transcript_verdict(&proof, &pages),
        crate::fi::FAIL_SENTINEL,
        "nested V3 field corruption must fail the final transcript proof"
    );
}

#[test]
fn v3_permit_single_binding_is_non_vacuous() {
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);
    let pth: [u8; 32] = [
        0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79,
        0x97, 0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10,
        0xf3, 0xd0,
    ];
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];
    let (top_ed, nested_blob) = permit_single_vectors(
        token,
        1_000_000_000,
        1_735_689_600,
        0,
        spender,
        1_735_689_600,
    );

    let render = |ed: &[u8], blob: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, blob, &verified, None, &resolver,
        )
    };

    // Baseline: renders.
    assert!(
        render(&top_ed, &nested_blob).is_ok(),
        "baseline must render"
    );

    // (b1) Flip EVERY byte of EVERY nested word. Each flip breaks
    // keccak(type_hash‖nested_ed) == committed → DECLINE.
    for word in 0..4usize {
        for byte in 0..32usize {
            let mut blob = nested_blob.clone();
            blob[2 + word * 32 + byte] ^= 0x01; // flip one bit inside nested_ed
            assert!(
                render(&top_ed, &blob).is_err(),
                "flipping nested word {word} byte {byte} must decline (binding is live)"
            );
        }
    }

    // (b2) Flip the committed top-level `details` hashStruct word → the device's
    // recomputed hashStruct no longer matches → DECLINE.
    for byte in 0..32usize {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &nested_blob).is_err(),
            "flipping committed details word byte {byte} must decline"
        );
    }
}

// PermitSingle primary-type hash (foundry) — shared by the reconciliation tests.
const PERMIT_SINGLE_TYPEHASH: [u8; 32] = [
    0xf3, 0x84, 0x1c, 0xd1, 0xff, 0x00, 0x85, 0x02, 0x6a, 0x63, 0x27, 0xb6, 0x20, 0xb6, 0x79, 0x97,
    0xce, 0x40, 0xf2, 0x82, 0xc8, 0x8a, 0x8e, 0x90, 0x5a, 0x7a, 0x56, 0x26, 0xe3, 0x10, 0xf3, 0xd0,
];

fn permit_single_valid_vectors() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];
    permit_single_vectors(
        token,
        1_000_000_000,
        1_735_689_600,
        0,
        spender,
        1_735_689_600,
    )
}

/// Walk an EIP-712 IR's formats section and return the byte offset of the
/// `nested_descent_count` byte of the format whose `type_hash == target`.
/// Mirrors `ir::FormatIter` (fixed prefix 9 B: selector(4) field_count(1)
/// intent_len(1) static_head_words(2) nested_descent_count(1); then intent;
/// then type_hash(32) for EIP-712; then `field_count` FieldEntry records).
fn eip712_format_ndc_offset(ir_bytes: &[u8], target: &[u8; 32]) -> Option<usize> {
    let formats_off = u16::from_be_bytes([ir_bytes[128], ir_bytes[129]]) as usize;
    let count = *ir_bytes.get(formats_off)? as usize;
    let mut p = formats_off + 1;
    for _ in 0..count {
        let entry_start = p;
        let field_count = *ir_bytes.get(p + 4)? as usize;
        let intent_len = *ir_bytes.get(p + 5)? as usize;
        p += 9 + intent_len; // fixed prefix + intent
        let th = ir_bytes.get(p..p + 32)?;
        let matched = th == target;
        p += 32; // EIP-712 type_hash
        for _ in 0..field_count {
            let label_len = *ir_bytes.get(p + 1)? as usize;
            p += 2 + label_len + 4; // format_op + label_len + label + path_off + param_off
        }
        if matched {
            return Some(entry_start + 8);
        }
    }
    None
}

/// THE reconciliation tripwire test (advisor blocker #1 — the E1 pinned-count
/// control). Schema v4 deep-validates the nested program before rendering, so a
/// format header whose authenticated `nested_descent_count` disagrees with the
/// recursively parsed anchors is rejected at IR admission. This is earlier and
/// stronger than the retained after-render consumption belt: malformed pinned
/// IR cannot become a `VerifiedDescriptor` at all.
#[test]
fn v3_reconciliation_rejects_wrong_pinned_descent_count() {
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);

    // Locate PermitSingle's format header nested_descent_count byte. The permit2
    // leaf now carries three formats (PermitSingle, PermitTransferFrom,
    // PermitBatch), so we WALK the formats section to find PermitSingle's entry
    // (by its type_hash) rather than assuming it is first. Within a format entry
    // the fixed prefix is selector(4)+field_count(1)+intent_len(1)+
    // static_head_words(2) = 8, so nested_descent_count sits at entry_start + 8.
    let ndc_off = eip712_format_ndc_offset(&leaf.ir_bytes, &PERMIT_SINGLE_TYPEHASH)
        .expect("PermitSingle format present in the permit2 leaf");

    let parse_patched = |ndc: u8| {
        let mut ir_bytes = leaf.ir_bytes.clone();
        assert_eq!(
            ir_bytes[ndc_off], 1,
            "PermitSingle pins exactly one descent point"
        );
        ir_bytes[ndc_off] = ndc;
        Erc7730Ir::parse(&ir_bytes).err()
    };

    // Claim TWO descent points but encode one anchor → reject at admission.
    assert!(
        matches!(
            parse_patched(2),
            Some(pqsigner_erc7730::ir::IrError::BadFormat)
        ),
        "one encoded anchor != pinned nested_descent_count(2) must decline"
    );
    // Claim ZERO while retaining one anchor → reject at admission.
    assert!(
        matches!(
            parse_patched(0),
            Some(pqsigner_erc7730::ir::IrError::BadFormat)
        ),
        "one encoded anchor != pinned nested_descent_count(0) must decline"
    );
}

/// The other half of E4-3 (total consumption): a valid nested_blob plus one
/// trailing byte → after the DFS binds the single record, cursor != blob.len()
/// → decline. (nested_blob is display-only/unsigned, so padding is hygiene not a
/// live exploit — but the cursor check must fire.)
#[test]
fn v3_reconciliation_rejects_trailing_nested_blob() {
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);
    let (top_ed, mut nested_blob) = permit_single_valid_vectors();
    nested_blob.push(0xEE); // one unconsumed trailing byte

    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    assert!(
        super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_SINGLE_TYPEHASH,
            &top_ed,
            &nested_blob,
            &verified,
            None,
            &resolver,
        )
        .is_err(),
        "cursor != nested_blob.len() (trailing byte) must decline"
    );
}

// typeHash(TokenPermissions(address token,uint256 amount)) — foundry.
const TOKEN_PERMISSIONS_TYPEHASH: [u8; 32] = [
    0x61, 0x83, 0x58, 0xac, 0x3d, 0xb8, 0xdc, 0x27, 0x4f, 0x0c, 0xd8, 0x82, 0x9d, 0xa7, 0xe2, 0x34,
    0xbd, 0x48, 0xcd, 0x73, 0xc4, 0xa7, 0x40, 0xae, 0xde, 0x1a, 0xde, 0xc9, 0x84, 0x6d, 0x06, 0xa1,
];
// typeHash(PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)...) — foundry.
const PERMIT_TRANSFER_FROM_TYPEHASH: [u8; 32] = [
    0x93, 0x9c, 0x21, 0xa4, 0x8a, 0x8d, 0xbe, 0x3a, 0x9a, 0x24, 0x04, 0xa1, 0xd4, 0x66, 0x91, 0xe4,
    0xd3, 0x9f, 0x65, 0x83, 0xd6, 0xec, 0x6b, 0x35, 0x71, 0x46, 0x04, 0xc9, 0x86, 0xd8, 0x01, 0x06,
];

/// The MINIMAL nested binding: Permit2 `PermitTransferFrom` (`TokenPermissions`,
/// 2 members) — unlocked by the `nonce` curation. Proves the v0x03 machinery
/// handles a smaller struct than PermitSingle end-to-end: the nested amount +
/// token render, top-level spender + deadline + nonce show, AND flipping the
/// committed `permitted` word declines (binding is live for the 2-member shape).
#[test]
fn v3_permit_transfer_from_renders_and_flip_declines() {
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);
    let token = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ]; // USDC
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];

    // nested_ed (TokenPermissions) = token | amount (2 words).
    let mut nested_ed = std::vec![0u8; 64];
    nested_ed[12..32].copy_from_slice(&token);
    nested_ed[32 + 24..64].copy_from_slice(&500_000_000u64.to_be_bytes()); // 500 USDC
    let permitted_hs = super::erc7730::nested::hash_struct(&TOKEN_PERMISSIONS_TYPEHASH, &nested_ed);

    // top_ed (PermitTransferFrom) = permitted | spender | nonce | deadline (4 words).
    let mut top_ed = std::vec![0u8; 128];
    top_ed[0..32].copy_from_slice(&permitted_hs);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&42u64.to_be_bytes()); // nonce (VISIBLE fixture)
    top_ed[96 + 24..128].copy_from_slice(&1_735_689_600u64.to_be_bytes()); // deadline (SHOWN)

    let mut nested_blob = std::vec![0u8; 2];
    nested_blob[0..2].copy_from_slice(&(nested_ed.len() as u16).to_be_bytes());
    nested_blob.extend_from_slice(&nested_ed);

    let render = |ed: &[u8], blob: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_TRANSFER_FROM_TYPEHASH,
            ed,
            blob,
            &verified,
            None,
            &resolver,
        )
    };

    let pages = render(&top_ed, &nested_blob).expect("valid PermitTransferFrom clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("3fc9"), "spender must be shown:\n{dump}");
    assert!(
        dump.contains("500000000"),
        "nested amount must render:\n{dump}"
    );
    assert!(dump.contains("2025"), "deadline date must render:\n{dump}");
    assert!(!dump.contains("hidden"), "sanity");

    // Flip the committed `permitted` hashStruct word → decline (binding live).
    for byte in [0usize, 15, 31] {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &nested_blob).is_err(),
            "flipping committed permitted word byte {byte} must decline"
        );
    }
    // Flip a nested word → decline.
    let mut blob = nested_blob.clone();
    blob[2 + 40] ^= 0x01; // inside the amount word
    assert!(
        render(&top_ed, &blob).is_err(),
        "flipping nested amount must decline"
    );
}

// PermitBatch primary-type hash (foundry).
const PERMIT_BATCH_TYPEHASH: [u8; 32] = [
    0xaf, 0x1b, 0x0d, 0x30, 0xd2, 0xca, 0xb0, 0x38, 0x0e, 0x68, 0xf0, 0x68, 0x90, 0x07, 0xe3, 0x25,
    0x49, 0x93, 0xc5, 0x96, 0xf2, 0xfd, 0xd0, 0xaa, 0xa7, 0xf4, 0xd0, 0x4f, 0x79, 0x44, 0x08, 0x63,
];

/// A REAL 2-element Permit2 `PermitBatch` (v2 array-of-struct). el0 = USDC/1e9/
/// 2025-01-01/nonce0, el1 = WETH/5e18/2026-01-01/nonce1. The committed `details`
/// word is the foundry-pinned array binding `keccak(hashStruct(el0)‖hashStruct(el1))
/// = 0x57b01054…` (recomputed here via the SAME device primitive — not circular:
/// the device recomputes from the IR-pinned type_hash + the blob; a flip in
/// either breaks the equality). Returns `(top_ed[96], nested_blob)`.
fn permit_batch_vectors() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let usdc = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let weth = [
        0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27, 0xeA, 0xD9,
        0x08, 0x3C, 0x75, 0x6C, 0xc2,
    ];
    let spender = [
        0x3fu8, 0xC9, 0x1A, 0x3a, 0xfd, 0x70, 0x39, 0x5C, 0xd4, 0x96, 0xC6, 0x47, 0xd5, 0xa6, 0xcC,
        0x9D, 0x4B, 0x2b, 0x7F, 0xAD,
    ];

    let mut el0 = std::vec![0u8; 128];
    el0[12..32].copy_from_slice(&usdc);
    el0[32 + 24..64].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    el0[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());
    let mut el1 = std::vec![0u8; 128];
    el1[12..32].copy_from_slice(&weth);
    el1[32 + 24..64].copy_from_slice(&5_000_000_000_000_000_000u64.to_be_bytes());
    el1[64 + 24..96].copy_from_slice(&1_767_225_600u64.to_be_bytes());
    el1[96 + 24..128].copy_from_slice(&1u64.to_be_bytes());

    let details_word =
        super::erc7730::nested::hash_struct_array(&PERMIT_DETAILS_TYPEHASH, &[&el0[..], &el1[..]]);
    let mut top_ed = std::vec![0u8; 96];
    top_ed[0..32].copy_from_slice(&details_word);
    top_ed[32 + 12..64].copy_from_slice(&spender);
    top_ed[64 + 24..96].copy_from_slice(&1_735_689_600u64.to_be_bytes());

    // nested_blob = [u16 elem_count=2] [u16 128][el0] [u16 128][el1].
    let mut blob = std::vec![0u8, 2]; // elem_count = 2
    blob.extend_from_slice(&128u16.to_be_bytes());
    blob.extend_from_slice(&el0);
    blob.extend_from_slice(&128u16.to_be_bytes());
    blob.extend_from_slice(&el1);
    (top_ed, blob)
}

#[test]
fn v3_permit_batch_array_renders_both_elements() {
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);
    let (top_ed, blob) = permit_batch_vectors();
    let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
    let verified = VerifiedDescriptor { ir };
    let resolver = NameResolver::new();
    let pages = super::erc7730::render_erc7730_eip712_pages_v3(
        1,
        &[0u8; 20],
        &PERMIT_BATCH_TYPEHASH,
        &top_ed,
        &blob,
        &verified,
        None,
        &resolver,
    )
    .expect("valid 2-element PermitBatch clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    // Both element amounts render (raw, no token metadata → `! raw, dec=?`; a
    // 19-digit value splits across two display rows, so match the leading run).
    assert!(
        dump.contains("1000000000"),
        "element 0 (USDC 1e9) amount:\n{dump}"
    );
    assert!(
        dump.contains("5000000000000000"),
        "element 1 (WETH 5e18) amount:\n{dump}"
    );
    // Distinct token addresses (unverified pages) prove per-element resolution.
    assert!(
        dump.contains("a0b86991c6218b"),
        "element 0 token (USDC):\n{dump}"
    );
    assert!(dump.contains("c02aaa39"), "element 1 token (WETH):\n{dump}");
    // The "Item 1 of 2" / "Item 2 of 2" dividers.
    assert!(dump.contains("item 1 of 2"), "element 0 divider:\n{dump}");
    assert!(dump.contains("item 2 of 2"), "element 1 divider:\n{dump}");
    // Both element expiration dates.
    assert!(dump.contains("2025"), "element 0 expiration:\n{dump}");
    assert!(dump.contains("2026"), "element 1 expiration:\n{dump}");
}

#[test]
fn v3_permit_batch_array_binding_is_non_vacuous() {
    let leaf = safe_visible_nested_leaf("eip712-uniswap-permit2.json", 1);
    let (top_ed, blob) = permit_batch_vectors();

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("permit2 IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1,
            &[0u8; 20],
            &PERMIT_BATCH_TYPEHASH,
            ed,
            b,
            &verified,
            None,
            &resolver,
        )
    };
    assert!(render(&top_ed, &blob).is_ok(), "baseline renders");

    // (a) Flip ONE bit inside EACH element word (both elements, every word) →
    // the concat hashStruct no longer matches `committed` → DECLINE.
    // `blob` layout: elem_count(2) then [len(2) el0(128)] [len(2) el1(128)];
    // element bytes start at offset 4 (el0) and 4+128+2=134 (el1).
    for (base, label) in [(4usize, "el0"), (134usize, "el1")] {
        for word in 0..4usize {
            let mut b = blob.clone();
            b[base + word * 32] ^= 0x01;
            assert!(
                render(&top_ed, &b).is_err(),
                "flipping {label} word {word} must decline (array binding is live)"
            );
        }
    }
    // (b) Flip the committed `details` array word → DECLINE.
    for byte in [0usize, 31] {
        let mut ed = top_ed.clone();
        ed[byte] ^= 0x01;
        assert!(
            render(&ed, &blob).is_err(),
            "flipping committed array word byte {byte} declines"
        );
    }
    // (c) Lie about elem_count (claim 1) — the concat over 1 element != committed
    // (which bound 2) → DECLINE (element-count is implicitly bound by the hash).
    let mut b = blob.clone();
    b[0] = 0;
    b[1] = 1;
    assert!(
        render(&top_ed, &b).is_err(),
        "lying elem_count=1 must decline"
    );
    // (d) elem_count = 0 → explicit decline (the empty-batch attack).
    let mut b0 = blob.clone();
    b0[0] = 0;
    b0[1] = 0;
    assert!(
        render(&top_ed, &b0).is_err(),
        "elem_count=0 must decline (empty batch)"
    );
}

/// The canonical EIP-2612 template hides `owner` and `nonce`. The strict
/// compiler no longer carries global semantic allowlists: a hidden signed
/// scalar cannot enter the authenticated catalogue, even when a convention
/// suggests it will equal the signer. Assert exclusion instead of exercising
/// an unreachable trusted-render path.
#[test]
fn erc2612_permit_with_hidden_owner_is_excluded() {
    assert_registry_source_excluded("eip712-permit-ethereum-link.json");
}

// ───────────────────────────────────────────────────────────────────────
// Tier B: canonical dynamic tokenPath framing — Uniswap swaps.
//
// Endpoint tokenPaths identify amount metadata; they do not display a complete
// signed packed route or address array. The upstream Router02 descriptor is now
// excluded because it showed only those endpoints. A process-private safe
// fixture adds `path.[]`, preserving the runtime extraction/framing backstop
// while requiring all route addresses to reach the display.
// ───────────────────────────────────────────────────────────────────────
const UNI_V3: [u8; 20] = [
    0x68, 0xb3, 0x46, 0x58, 0x33, 0xfb, 0x72, 0xa7, 0x0e, 0xcd, 0xf4, 0x85, 0xe0, 0xe4, 0xc7, 0xbd,
    0x86, 0x65, 0xfc, 0x45,
];
const TOKEN_IN: [u8; 20] = [0x11; 20];
const TOKEN_MID: [u8; 20] = [0xAB; 20];
const TOKEN_OUT: [u8; 20] = [0x22; 20];

fn safe_uniswap_route_fixture() -> &'static dbgen::erc7730::Emitted {
    static FIXTURE: std::sync::OnceLock<dbgen::erc7730::Emitted> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let temp_root = std::env::temp_dir().join(format!(
            "pqsigner-erc7730-safe-uniswap-route-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&temp_root);
        std::fs::create_dir_all(&temp_root).expect("create safe route fixture dir");
        let source = temp_root.join("safe-uniswap-route.json");
        std::fs::write(
            &source,
            r#"{
              "context": { "contract": { "deployments": [
                { "chainId": 1, "address": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45" }
              ] } },
              "metadata": { "owner": "Test", "contractName": "Safe Route" },
              "display": { "formats": {
                "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to)": {
                  "intent": "Swap",
                  "fields": [
                    { "path": "amountIn", "label": "Amount to Send", "format": "tokenAmount",
                      "params": { "tokenPath": "path.[0]" }, "visible": "always" },
                    { "path": "amountOutMin", "label": "Minimum Receive", "format": "tokenAmount",
                      "params": { "tokenPath": "path.[-1]" }, "visible": "always" },
                    { "path": "path.[]", "label": "Route", "format": "addressName", "visible": "always" },
                    { "path": "to", "label": "Beneficiary", "format": "addressName", "visible": "always" }
                  ]
                }
              } }
            }"#,
        )
        .expect("write safe route fixture");
        let emitted = dbgen::erc7730::try_compile_one(
            &source,
            &dbgen::erc7730::Policy::default(),
            Some(&temp_root),
        )
        .expect("whole-route fixture must compile")
        .into_iter()
        .find(|entry| entry.chain_id == 1)
        .expect("safe route fixture emits mainnet leaf");
        let _ = std::fs::remove_dir_all(&temp_root);
        emitted
    })
}

fn meta(contract: [u8; 20], decimals: u8, symbol: &'static [u8]) -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: 1,
        contract,
        decimals,
        name: symbol,
        symbol,
    }
}

/// `swap*ForTokens(uint256 a0, uint256 a1, address[] path, address to)`
/// (same layout for `swapExactTokensForTokens` / `swapTokensForExactTokens`).
fn calldata_v2_swap(
    selector: [u8; 4],
    a0: U256,
    a1: U256,
    path: &[[u8; 20]],
    to: [u8; 20],
) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&selector);
    d.extend_from_slice(&a0.0);
    d.extend_from_slice(&a1.0);
    d.extend_from_slice(&u256_from_u64(128).0); // offset to path array (4-word head)
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(&to);
    d.extend_from_slice(&t);
    d.extend_from_slice(&u256_from_u64(path.len() as u64).0); // element count
    for a in path {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a);
        d.extend_from_slice(&w);
    }
    d
}

fn render_safe_uni_result(
    calldata: &[u8],
    token: Option<&Erc20Metadata<'_>>,
) -> Result<Pages, crate::tx::erc7730_render::RenderErr> {
    let entry = safe_uniswap_route_fixture();
    let verified = VerifiedDescriptor {
        ir: Erc7730Ir::parse(&entry.ir_bytes).expect("safe route IR parses"),
    };
    let tx = envelope(1, UNI_V3);
    let resolver = NameResolver::new();
    render_erc7730_pages(&tx, calldata, &verified, token, &resolver)
}

fn render_safe_uni(calldata: &[u8], token: Option<&Erc20Metadata<'_>>) -> Pages {
    render_safe_uni_result(calldata, token).expect("render safe route")
}

#[test]
fn uniswap_exact_input_c2_input_slice_is_excluded() {
    assert_registry_source_excluded("calldata-UniswapV3Router02.json");
}

#[test]
fn uniswap_exact_input_c2_output_slice_is_excluded() {
    assert_registry_source_excluded("calldata-UniswapV3Router02.json");
}

#[test]
fn uniswap_v2_swap_binds_first_and_last_array_element() {
    // 3-hop path so `[-1]` genuinely selects the LAST element, not index 1.
    // Unlike upstream, the synthetic descriptor also renders `path.[]`.
    let path = [TOKEN_IN, TOKEN_MID, TOKEN_OUT];
    let cd_in = calldata_v2_swap(
        [0x47, 0x2b, 0x43, 0xf3],
        u256_from_u64(1_500_000),
        u256_from_u64(1),
        &path,
        [0x33; 20],
    );
    let fixture_ir = Erc7730Ir::parse(&safe_uniswap_route_fixture().ir_bytes).unwrap();
    let selector: [u8; 4] = cd_in[..4].try_into().unwrap();
    let fmt = fixture_ir
        .find_format_by_selector(&selector)
        .unwrap()
        .unwrap();
    for field in fmt.fields() {
        let field = field.unwrap();
        let params = pqsigner_erc7730::render::params::parse(&fixture_ir, field.param_off).unwrap();
        let Some(token_path) = params.token_path else {
            continue;
        };
        let resolved =
            pqsigner_erc7730::render::resolve::resolve_token_address(&token_path[1..], &cd_in[4..])
                .unwrap();
        if field.label == b"Amount to Send" {
            assert_eq!(resolved, TOKEN_IN);
        } else if field.label == b"Minimum Receive" {
            assert_eq!(resolved, TOKEN_OUT);
        }
    }
    let ma = meta(TOKEN_IN, 6, b"TKA");
    let pages = render_safe_uni(&cd_in, Some(&ma));
    let p = find_page_by_label(&pages, "Amount to Send");
    let rows = page_strs(&pages, p);
    assert!(
        rows.iter().any(|r| r.contains("TKA")),
        "path.[0] must bind the first element → TKA: {rows:?}"
    );

    let route_pages = pages
        .as_slice()
        .iter()
        .filter(|page| row_str(&page[0]) == "Route")
        .count();
    assert_eq!(
        route_pages, 4,
        "whole-route display must include one count page plus all three elements"
    );
    assert_registry_source_excluded("calldata-UniswapV3Router02.json");
}

#[test]
fn uniswap_exact_input_c2_decoy_path_cannot_reach_renderer() {
    assert_registry_source_excluded("calldata-UniswapV3Router02.json");
}

/// Parse a 64-char hex string into a `[u8; 32]` for the remaining synthetic
/// nested fixture vectors.
fn hx32(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    o
}

/// v3 fixture-wide safety: recursive descent remains a GENERAL renderer
/// capability even though the real descriptors that hid signed members are no
/// longer authenticated. Exercise every format in the safe-visible dbgen-emitted
/// fixture set with hostile nested blobs and require panic/OOB freedom.
#[test]
fn v3_all_nested_eip712_leaves_are_panic_safe_and_fail_closed() {
    let resolver = NameResolver::new();
    let mut nested_leaf_formats = 0usize;
    for entry in build_safe_visible_nested_fixtures()
        .values()
        .flat_map(|entries| entries.iter())
    {
        let Ok(ir) = Erc7730Ir::parse(&entry.ir_bytes) else {
            continue;
        };
        if !matches!(ir.context_kind, ContextKind::Eip712) {
            continue;
        }
        let chain = ir.chain_id;
        let contract = ir.contract;
        for format in ir.format_iter() {
            let Ok(fmt) = format else { continue };
            if fmt.nested_descent_count == 0 {
                continue; // no nested anchor in this format
            }
            nested_leaf_formats += 1;
            let pth = fmt.type_hash;
            let ed = std::vec![0u8; fmt.static_head_words as usize * 32];
            for blob in [
                std::vec::Vec::new(),
                std::vec![0u8; 64],
                std::vec![0xFFu8; 300],
            ] {
                let verified = VerifiedDescriptor {
                    ir: Erc7730Ir::parse(&entry.ir_bytes).unwrap(),
                };
                // A wrong blob must decline (Err), never render a mis-bound
                // page and never panic. Asserting only "returns Result" would
                // make this fail-closed regression vacuous if a hostile blob
                // ever started producing pages.
                assert!(
                    super::erc7730::render_erc7730_eip712_pages_v3(
                        chain, &contract, &pth, &ed, &blob, &verified, None, &resolver,
                    )
                    .is_err(),
                    "hostile nested blob unexpectedly rendered: source={} selector=0x{} blob_len={}",
                    entry.source.display(),
                    hex::encode(fmt.selector),
                    blob.len(),
                );
            }
        }
    }
    // Permit2 (Single/Batch/TransferFrom) and SessionManager provide four
    // distinct safe nested formats (single struct + arrays-of-struct).
    assert!(
        nested_leaf_formats >= 4,
        "expected many nested EIP-712 leaf-formats across the corpus, got {nested_leaf_formats}"
    );
}

/// Nested `tokenAmount` FULL vocabulary (threshold + message) in a top-level
/// array-of-struct: flyingtulip SessionManager `Session(...AssetLimit[] limits...)`.
/// Each `AssetLimit(token, limit)` renders `limit` as a tokenAmount whose
/// `threshold = max-uint` maps to the message "Unlimited" — the same "approve
/// unlimited" display the top-level path has, now reachable inside a nested
/// element. Proves the dbgen nested-subfield vocabulary extension end-to-end
/// (element 0 = a normal limit renders the number; element 1 = max-uint renders
/// "Unlimited").
#[test]
fn v3_session_manager_nested_tokenamount_threshold_renders_unlimited() {
    use super::erc7730::nested::{hash_struct, hash_struct_array};
    let leaf = safe_visible_nested_leaf("eip712-SessionManager-FT.json", 1);
    let pth = hx32("10e2e916a5d944a9c9fa82748951934e444783850c4cb366694967607dbd2fc5");
    let asset_limit_th = hx32("269888c0029efe9424c548a264e5ee66803094ad203b068ca44e278b02db9d6f");
    let wa = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let wu = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let usdc = [
        0xA0u8, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9D, 0x4a, 0x2e, 0x9E, 0xb0,
        0xcE, 0x36, 0x06, 0xeB, 0x48,
    ];
    let weth = [
        0xC0u8, 0x2a, 0xaA, 0x39, 0xb2, 0x23, 0xFE, 0x8D, 0x0A, 0x0e, 0x5C, 0x4F, 0x27, 0xeA, 0xD9,
        0x08, 0x3C, 0x75, 0x6C, 0xc2,
    ];

    // AssetLimit: token, limit (2 words). el0 normal, el1 = max-uint → "Unlimited".
    let mut el0 = std::vec![0u8; 64];
    el0[0..32].copy_from_slice(&wa(usdc));
    el0[32..64].copy_from_slice(&wu(1_000_001)); // a finite limit
    let mut el1 = std::vec![0u8; 64];
    el1[0..32].copy_from_slice(&wa(weth));
    el1[32..64].copy_from_slice(&[0xFFu8; 32]); // max-uint => >= threshold => "Unlimited"
    let limits_word = hash_struct_array(&asset_limit_th, &[&el0[..], &el1[..]]);
    let _ = hash_struct; // (single-struct primitive unused here; array path only)

    // Session top_ed (8 words): owner, delegate, validAfter, validUntil, maxCalls,
    // maxFeeBps, limits, salt.
    let mut top_ed = std::vec![0u8; 256];
    top_ed[0..32].copy_from_slice(&wa([0x71; 20])); // owner
    top_ed[32..64].copy_from_slice(&wa([0x72; 20])); // delegate
    top_ed[64..96].copy_from_slice(&wu(1_735_689_600)); // validAfter (2025)
    top_ed[96..128].copy_from_slice(&wu(1_767_225_600)); // validUntil (2026)
    top_ed[128..160].copy_from_slice(&wu(50)); // maxCalls
    top_ed[160..192].copy_from_slice(&wu(30)); // maxFeeBps
    top_ed[192..224].copy_from_slice(&limits_word); // limits (array)
    top_ed[224..256].copy_from_slice(&[0xAB; 32]); // salt (VISIBLE fixture)

    // nested_blob: the single `limits` array descent — [elem_count=2][el0][el1].
    let mut blob = std::vec::Vec::new();
    blob.extend_from_slice(&2u16.to_be_bytes());
    blob.extend_from_slice(&64u16.to_be_bytes());
    blob.extend_from_slice(&el0);
    blob.extend_from_slice(&64u16.to_be_bytes());
    blob.extend_from_slice(&el1);

    let render = |ed: &[u8], b: &[u8]| {
        let ir = Erc7730Ir::parse(&leaf.ir_bytes).expect("SessionManager IR parses");
        let verified = VerifiedDescriptor { ir };
        let resolver = NameResolver::new();
        super::erc7730::render_erc7730_eip712_pages_v3(
            1, &[0u8; 20], &pth, ed, b, &verified, None, &resolver,
        )
    };
    let pages = render(&top_ed, &blob).expect("valid SessionManager clear-signs");
    assert_all_pages_printable(&pages);
    let dump = dump_pages(&pages).to_lowercase();
    assert!(dump.contains("7171717171"), "owner shown:\n{dump}");
    assert!(dump.contains("7272727272"), "delegate shown:\n{dump}");
    assert!(
        dump.contains("2025") && dump.contains("2026"),
        "validAfter/Until dates:\n{dump}"
    );
    assert!(
        dump.contains("1000001"),
        "element 0 finite limit renders the number:\n{dump}"
    );
    assert!(
        dump.contains("unlimited"),
        "element 1 (max-uint) renders the threshold message 'Unlimited':\n{dump}"
    );
    assert!(
        dump.contains("item 1 of 2") && dump.contains("item 2 of 2"),
        "per-element dividers:\n{dump}"
    );
    assert!(
        dump.contains("abababab"),
        "formerly-hidden salt must be visible in the safe fixture:\n{dump}"
    );
    // Flip a nested word (element 1's limit) → array binding breaks → decline.
    let mut b = blob.clone();
    b[2 + 2 + 64 + 2 + 40] ^= 0x01; // inside el1's limit word
    assert!(render(&top_ed, &b).is_err(), "flip el1 limit declines");
}
