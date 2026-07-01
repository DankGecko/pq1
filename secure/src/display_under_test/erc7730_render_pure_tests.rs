//! End-to-end render tests for the ERC-7730 / ERC-8213 OLED renderers.
//!
//! Each test builds a realistic transaction (chain + to + calldata),
//! verifies the firmware-pinned bundle via `verify_erc7730_bundle`, then
//! runs the on-device renderer at `super::erc7730::render_erc7730_pages`
//! and asserts the resulting 4-row × 16-col OLED pages line-by-line
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
//! Inputs are NOT hand-rolled IR fixtures — they come straight from the
//! seed-corpus JSON via `dbgen::erc7730::build_db`, the same pipeline
//! that produces the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`. So
//! these tests would also catch a host-side compiler regression that
//! ships subtly broken IR into the catalog without anyone noticing,
//! since "broken IR" surfaces as a wrong rendered string.

use std::path::PathBuf;

use pqsigner_erc7730::bundle::{verify_erc7730_bundle, VerifiedDescriptor};
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir};
use pqsigner_tx_core::hash::keccak256;

use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::ui::DISPLAY_COLS;

use super::erc7730::render_erc7730_pages;
use super::erc8213::{append_fingerprint_page, Kind as Erc8213Kind};
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
/// The 776-leaf registry build is several hundred ms, and ~16 tests use it,
/// so memoize it in a `OnceLock` — built once per test binary, not per test.
/// Returns a `&'static`, so callers pass it straight to `find_leaf(res, …)`
/// (NOT `&res`) and read `res.blob` / `res.root` directly.
fn build_registry() -> &'static dbgen::erc7730::Erc7730BuildResult {
    static REGISTRY: std::sync::OnceLock<dbgen::erc7730::Erc7730BuildResult> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let root = workspace_root();
        let reg = root.join("secure/data/erc7730-registry");
        let policy = root.join("secure/data/erc7730/policy.toml");
        let (res, _skips) = dbgen::erc7730::build_db_tolerant(
            &reg.join("registry"),
            &policy,
            Some(&reg),
        )
        .expect("build registry corpus");
        res
    })
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
    let proof_depth =
        u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let proofs_off =
        u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let proof_base = proofs_off + leaf_index * proof_depth * 32;

    let mut buf =
        Vec::with_capacity(2 + ir_bytes.len() + 4 + 4 + proof_depth * 32);
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
    String::from_utf8(row[..end].to_vec())
        .expect("rendered rows must be printable ASCII")
}

fn page_strs(pages: &Pages, page: usize) -> [String; 4] {
    let p = &pages.buf[page];
    [row_str(&p[0]), row_str(&p[1]), row_str(&p[2]), row_str(&p[3])]
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
        let ir =
            Erc7730Ir::parse(&entry.ir_bytes).expect("seed IR parses");
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
// blind-sign (weth.deposit, tether-usdt.transfer/approve, every
// aave-v3-pool.* and circle-usdc-*) now render their full clear-sign
// page sequence.
//
// The three tests below assert the user-visible OLED text end-to-end.

#[test]
fn positive_usdt_transfer_mainnet_renders_send_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert!(matches!(
        verified.ir.context_kind,
        ContextKind::Contract
    ));

    let amount = u256_from_u64(100_000_000); // 100.00 USDT (6 decimals)
    let recipient = [0x33u8; 20];
    let calldata = calldata_transfer(recipient, amount);
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "transfer(address,uint256)",
    );

    let tx = envelope(1, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(
        &tx,
        &calldata,
        &verified,
        Some(&usdt_meta),
        &resolver,
    )
    .expect("render");

    assert_all_pages_printable(&pages);

    // Page 0: intent banner.
    let [r0, r1, r2, r3] = page_strs(&pages, 0);
    assert_eq!(r0, "Sign: Send");
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
fn positive_usdt_approve_unlimited_renders_approve_intent() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-usdt.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // U256::MAX is the canonical "approve unlimited" sentinel; the
    // descriptor sets `threshold` to 0x8000...0000 (top bit) — any
    // value above renders as "unlimited" via tokenAmount.
    let calldata = calldata_approve([0x44u8; 20], u256_max());
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "approve(address,uint256)",
    );

    let tx = envelope(1, entry.contract);
    let usdt_meta = Erc20Metadata {
        chain_id: 1,
        contract: entry.contract,
        decimals: 6,
        name: b"Tether USD",
        symbol: b"USDT",
    };
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(
        &tx,
        &calldata,
        &verified,
        Some(&usdt_meta),
        &resolver,
    )
    .expect("render");

    assert_all_pages_printable(&pages);

    let [intent_r0, _, _, _] = page_strs(&pages, 0);
    assert_eq!(intent_r0, "Sign: Approve");

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
    let polygon_usdt =
        hex::decode("c2132D05D31c914a87C6611C10748AEb04B58e8F").unwrap();
    assert_eq!(
        &entry.contract[..],
        &polygon_usdt[..],
        "chain-137 leaf must bind the Polygon USDT contract"
    );

    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");
    assert_eq!(verified.ir.chain_id, 137, "verified leaf is chain 137");
    assert_eq!(&verified.ir.contract, &polygon_usdt[..], "verified leaf contract");

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
    let [r0, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Sign: Send");
}

#[test]
fn positive_weth_deposit_pulls_value_from_envelope() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // deposit() is the zero-arg selector — the "Amount" field is
    // sourced from `@.value` (container), not the calldata.
    let calldata = calldata_deposit();
    assert_selector_matches(&verified.ir, &calldata, "deposit()");

    let mut tx = envelope(1, entry.contract);
    tx.value = u256_from_u64(500_000_000_000_000_000); // 0.5 ETH

    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver)
        .expect("render");

    assert_all_pages_printable(&pages);

    let [intent_r0, owner_r, contract_r, _] = page_strs(&pages, 0);
    assert_eq!(intent_r0, "Sign: Wrap");
    assert_eq!(owner_r, "WETH");
    assert_eq!(contract_r, "WETH");

    // Amount page — 0.5 ETH at 18 decimals. `write_amount_two_rows`
    // splits the integer / decimal across two rows on small values, so
    // the rendered page reads `"Amount" / "0" / ".5 ETH" / "> next"`.
    // Both halves must be visible somewhere on the page, and the ETH
    // unit must appear.
    let amount_page = find_page_by_label(&pages, "Amount");
    let amount_rows = page_strs(&pages, amount_page);
    let amount_blob = amount_rows.join("\n");
    let single_row = amount_blob.contains("0.5") || amount_blob.contains("0,5");
    let split_rows = amount_rows.iter().any(|r| r.trim_end() == "0")
        && amount_rows.iter().any(|r| r.contains(".5") || r.contains(",5"));
    assert!(
        single_row || split_rows,
        "weth.deposit amount should print '0.5 ETH' (single- or split-row), got:\n{amount_blob}",
    );
    assert!(
        amount_blob.contains("ETH"),
        "amount unit missing: {amount_blob}",
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
    // format — an unknown selector means "blind sign should handle
    // this", which the dispatcher achieves by getting `RenderErr::
    // NoFormat` back from us and proceeding down the ladder.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // 0xdeadbeef — selector not in the registry WETH descriptor (deposit only).
    let calldata = vec![0xde, 0xad, 0xbe, 0xef];
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::NoFormat) => {}
        Err(other) => panic!(
            "expected RenderErr::NoFormat for unknown selector, got {other:?}"
        ),
        Ok(_) => panic!("unknown selector must not render"),
    }
}

#[test]
fn negative_short_calldata_rejects() {
    // Less than 4 bytes — can't even extract a selector. The renderer
    // must reject cleanly so the caller falls through to blind-sign.
    let res = build_registry();
    let entry = find_leaf(res, "calldata-weth.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified =
        verify_erc7730_bundle(&bundle, &res.root).expect("verify");

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
    // ERC-7730 intent labels live in 10 chars after "Sign: " — verify
    // that the seed corpus' actual intents fit, AND that the rendered
    // row never exceeds DISPLAY_COLS = 16.
    let res = build_seed();
    for entry in &res.entries {
        let bundle =
            synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
        let verified = verify_erc7730_bundle(&bundle, &res.root)
            .expect("seed corpus entries verify");
        if !matches!(verified.ir.context_kind, ContextKind::Contract) {
            continue;
        }
        for fmt in verified.ir.format_iter() {
            let fmt = fmt.expect("format header parses");
            assert!(
                fmt.intent.len() <= 32,
                "intent oversized in source: {:?}",
                core::str::from_utf8(fmt.intent).unwrap_or("<bin>")
            );
            // The renderer pads to exactly DISPLAY_COLS so length-16
            // post-truncation is the invariant we assert at the page
            // level via `assert_all_pages_printable`.
        }
    }
}

#[test]
fn positive_erc8213_fingerprint_renders_full_hash() {
    // The ERC-8213 fingerprint page is independent of the descriptor —
    // it just renders the 32-byte hash. Smoke-test it produces exactly
    // 2 pages and the rendered hex matches the input bytewise.
    let mut pages = Pages::empty_with_len(0);

    let hash: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    append_fingerprint_page(&mut pages, Erc8213Kind::CalldataDigest(hash))
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
    let expected_hex: String =
        hash.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        rendered, expected_hex,
        "fingerprint rows must spell out the full 32-byte hash bytewise"
    );
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
        append_fingerprint_page(&mut pages, kind).expect("fits");
        assert_eq!(
            row_str(&pages.buf[0][1]),
            expected_label,
            "label row for {:?}",
            std::any::type_name_of_val(&kind)
        );
    }
}

// ───────────────────────────────────────────────────────────────────────
// Enum formatter (FormatOp 0x08) — Aave V3 `borrow`. This is the FIRST and
// only descriptor that emits an enum table, so these two tests are the
// sole end-to-end coverage of the host `encode_enum_table` → on-device
// `enums::lookup_enum_label` → `render_enum` round trip. The dbgen
// round-trip / Kani suites NEVER render a page, so without these a broken
// `render_enum` would ship green.
// ───────────────────────────────────────────────────────────────────────

#[test]
fn positive_aave_borrow_renders_enum_label() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // interestRateMode = 2 → "variable" in the descriptor's enum.
    let calldata = calldata_borrow(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(2),
        0,
        [0x44u8; 20],
    );
    assert_selector_matches(
        &verified.ir,
        &calldata,
        "borrow(address,uint256,uint256,uint16,address)",
    );

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let [r0, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Sign: Borrow");

    // The enum page must show the RESOLVED label "variable", not the bare
    // index "2" (audit M-7). The registry's field label is "Interest Rate
    // mode" (18 chars); row 0 is truncated to DISPLAY_COLS (16), so the page
    // header reads "Interest Rate mo".
    let enum_page = find_page_by_label(&pages, "Interest Rate mo");
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
fn negative_aave_borrow_unknown_enum_value_declines_to_blind() {
    let res = build_registry();
    let entry = find_leaf(res, "calldata-lpv3.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = verify_erc7730_bundle(&bundle, &res.root).expect("verify");

    // interestRateMode = 7 is outside the declared set {0,1,2}; the whole
    // descriptor render must reject so the ladder falls to loud blind-sign
    // rather than rendering an unrecognised value under the verified banner.
    let calldata = calldata_borrow(
        [0x11u8; 20],
        u256_from_u64(500),
        u256_from_u64(7),
        0,
        [0x44u8; 20],
    );
    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    match render_erc7730_pages(&tx, &calldata, &verified, None, &resolver) {
        Err(crate::tx::erc7730_render::RenderErr::Reject(_)) => {}
        Err(other) => panic!("expected a Reject decline-to-blind, got {other:?}"),
        Ok(_) => panic!("unknown enum value must decline-to-blind, but render succeeded"),
    }
}

/// Pack-expansion sanity: the registry Lido `wstETH.wrap(uint256)`
/// descriptor renders the right intent + field label. A render test
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
    let pages =
        render_erc7730_pages(&tx, &calldata, &verified, Some(&steth_meta), &resolver)
            .expect("render");
    assert_all_pages_printable(&pages);

    let [r0, ..] = page_strs(&pages, 0);
    assert_eq!(r0, "Sign: Wrap stETH");
    // The amount field must render under its authored label (proves
    // `#._stETHAmount` resolved to the right static-head slot).
    let _amt_page = find_page_by_label(&pages, "stETH amount");
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
fn lido_array_field<'a>(
    ir: &'a Erc7730Ir<'a>,
) -> (crate::tx::erc7730::FieldEntry<'a>, u16) {
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
    assert_selector_matches(&verified.ir, &calldata, "requestWithdrawals(uint256[],address)");

    let tx = envelope(1, entry.contract);
    let resolver = NameResolver::new();
    let pages = render_erc7730_pages(&tx, &calldata, &verified, None, &resolver).expect("render");
    assert_all_pages_printable(&pages);

    let dump = dump_pages(&pages);
    // Header makes the count explicit. `write_amount_two_rows` splits an
    // amount across an integer row + a fraction row, so 2.5 → "2" / ".5".
    assert!(dump.contains("3 items"), "count header missing:\n{dump}");
    assert!(dump.contains(".5"), "amount 2.5 (fraction) missing:\n{dump}");
    assert!(dump.contains(".3"), "amount 0.3 (fraction) missing:\n{dump}");
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
    assert_selector_matches(&verified.ir, &calldata, "requestWithdrawals(uint256[],address)");

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
    assert_eq!(steth_element_pages, 3, "every element must render as stETH:\n{dump}");
    // Bound → no UNVERIFIED token page.
    let unverified = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]).contains("UNVERIFIE"))
        .count();
    assert_eq!(unverified, 0, "bound token must not show UNVERIFIED:\n{dump}");
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
    assert_eq!(raw_footers, 2, "both unbound elements must render loud raw:\n{dump}");
    // M-1: the token is named EXACTLY ONCE (a per-element page would be noise
    // and could push the array past the page budget).
    let token_pages = pages
        .as_slice()
        .iter()
        .filter(|p| row_str(&p[0]).contains("UNVERIFIE"))
        .count();
    assert_eq!(token_pages, 1, "unbound token must be named exactly once:\n{dump}");
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
        assert_eq!(count, amounts_arg.count as usize, "count disagrees with walk");
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
    let resolve =
        |body: &[u8]| super::erc7730::formatters::resolve_array(&field, ir, body, shw);

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
    assert_eq!(resolve(&empty).unwrap().1, 0, "empty array is valid, count 0");

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
