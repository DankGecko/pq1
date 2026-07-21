//! Production-catalogue evidence for issue #347's bounded multi-tail ABI.
//!
//! The marker inventory is exhaustive: every generated format carrying the
//! authenticated topology TLV must be one of the five reviewed source formats
//! below. The same test Merkle-verifies two real production leaves and drives
//! their blob/blob and blob/static-array/static-array calls through the device
//! renderer, including later-tail mutations and malformed framing.

use std::collections::BTreeSet;
use std::path::PathBuf;

use dbgen::erc7730::{build_db_tolerant_with_erc20_capabilities, Emitted, Erc7730BuildResult};
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::bundle::verify_erc7730_bundle;
use pqsigner_erc7730::display::render::render_erc7730_pages;
use pqsigner_erc7730::display::Pages;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_erc7730::render::calldata_topology::{TAIL_KIND_BLOB, TAIL_KIND_STATIC_WORD_ARRAY};
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_erc7730::render::RenderErr;
use pqsigner_tx::names::NameResolver;
use pqsigner_tx_core::eip1559::Eip1559Tx;
use pqsigner_tx_core::hash::keccak256;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MarkerRow {
    source: String,
    selector: [u8; 4],
    chain_id: u64,
    contract: [u8; 20],
    static_head_words: u16,
    topology: Vec<(u16, u8)>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen sits below the workspace root")
        .to_path_buf()
}

fn build_production() -> Erc7730BuildResult {
    let root = workspace_root();
    let registry = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build exact production ERC20 capability corpus");
    build_db_tolerant_with_erc20_capabilities(
        &registry.join("registry"),
        &policy,
        Some(&registry),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 catalogue")
    .0
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("selector width")
}

fn address(hex_address: &str) -> [u8; 20] {
    hex::decode(hex_address)
        .expect("valid address hex")
        .try_into()
        .expect("address width")
}

fn expected_rows() -> Vec<MarkerRow> {
    let sei = address("0000000000000000000000000000000000001005");
    let kiln_mainnet = address("8659eeff31cfcff580d37af8e7af250f8998aa83");
    let kiln_hoodi = address("1a76bc69922744807e86375f8b8ab8a7cf18eb7a");
    let agent = address("d5667acb0ac8108b45f6cdd4774559264098f8de");
    let asset = address("fc9ca736d384d482af5d23cc7616765c66244d29");

    let edit_validator = selector("editValidator(string,string,uint256)");
    let redelegate = selector("redelegate(string,string,uint256)");
    let create_operator =
        selector("createOperator(address,string,uint256,uint256,address[],uint256[])");
    let register_agent = selector(
        "registerAgent(address,address,uint8,string,string,string,string,uint256,uint256)",
    );
    let register_asset = selector("registerAsset(address,uint8,uint8,string,string,string)");

    let two_blobs = vec![(0, TAIL_KIND_BLOB), (1, TAIL_KIND_BLOB)];
    let kiln_topology = vec![
        (1, TAIL_KIND_BLOB),
        (4, TAIL_KIND_STATIC_WORD_ARRAY),
        (5, TAIL_KIND_STATIC_WORD_ARRAY),
    ];
    let agent_topology = vec![
        (3, TAIL_KIND_BLOB),
        (4, TAIL_KIND_BLOB),
        (5, TAIL_KIND_BLOB),
        (6, TAIL_KIND_BLOB),
    ];
    let asset_topology = vec![
        (3, TAIL_KIND_BLOB),
        (4, TAIL_KIND_BLOB),
        (5, TAIL_KIND_BLOB),
    ];

    vec![
        MarkerRow {
            source: "calldata-sei-staking.json".into(),
            selector: edit_validator,
            chain_id: 1_329,
            contract: sei,
            static_head_words: 3,
            topology: two_blobs.clone(),
        },
        MarkerRow {
            source: "calldata-sei-staking.json".into(),
            selector: redelegate,
            chain_id: 1_329,
            contract: sei,
            static_head_words: 3,
            topology: two_blobs,
        },
        MarkerRow {
            source: "calldata-kiln-fee-splitter-factory.json".into(),
            selector: create_operator,
            chain_id: 1,
            contract: kiln_mainnet,
            static_head_words: 6,
            topology: kiln_topology.clone(),
        },
        MarkerRow {
            source: "calldata-kiln-fee-splitter-factory.json".into(),
            selector: create_operator,
            chain_id: 560_048,
            contract: kiln_hoodi,
            static_head_words: 6,
            topology: kiln_topology,
        },
        MarkerRow {
            source: "calldata-AgentIdentityRegistry-base.json".into(),
            selector: register_agent,
            chain_id: 8_453,
            contract: agent,
            static_head_words: 9,
            topology: agent_topology,
        },
        MarkerRow {
            source: "calldata-AssetIdentityRegistry-base.json".into(),
            selector: register_asset,
            chain_id: 8_453,
            contract: asset,
            static_head_words: 6,
            topology: asset_topology,
        },
    ]
}

fn actual_rows(catalogue: &Erc7730BuildResult) -> Vec<MarkerRow> {
    let mut rows = Vec::new();
    for entry in &catalogue.entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated production IR parses");
        for format in ir.format_iter() {
            let format = format.expect("generated production format parses");
            let mut marker = None;
            for (ordinal, field) in format.fields().enumerate() {
                let field = field.expect("generated production field parses");
                let params = parse_params(&ir, field.param_off).expect("generated params parse");
                if let Some(topology) = params.dynamic_tail_topology {
                    assert_eq!(
                        ordinal,
                        0,
                        "topology marker moved off field zero in {} selector 0x{}",
                        entry.source.display(),
                        hex::encode(format.selector),
                    );
                    assert!(
                        marker.is_none(),
                        "format acquired duplicate topology markers"
                    );
                    marker = Some(
                        topology
                            .records()
                            .iter()
                            .map(|record| (record.slot, record.kind.as_byte()))
                            .collect(),
                    );
                }
            }
            if let Some(topology) = marker {
                rows.push(MarkerRow {
                    source: entry
                        .source
                        .file_name()
                        .and_then(|name| name.to_str())
                        .expect("UTF-8 descriptor filename")
                        .to_owned(),
                    selector: format.selector,
                    chain_id: entry.chain_id,
                    contract: entry.contract,
                    static_head_words: format.static_head_words,
                    topology,
                });
            }
        }
    }
    rows.sort();
    rows
}

fn word(value: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&(value as u64).to_be_bytes());
    out
}

fn address_word(value: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&value);
    out
}

fn blob(value: &[u8]) -> Vec<u8> {
    let padded = value.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(32 + padded);
    out.extend_from_slice(&word(value.len()));
    out.extend_from_slice(value);
    out.resize(32 + padded, 0);
    out
}

fn word_array(values: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + values.len() * 32);
    out.extend_from_slice(&word(values.len()));
    for value in values {
        out.extend_from_slice(value);
    }
    out
}

fn encode_call(signature: &str, mut head: Vec<[u8; 32]>, tails: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut cursor = head.len() * 32;
    for (slot, tail) in tails {
        head[*slot] = word(cursor);
        cursor += tail.len();
    }
    let mut calldata = Vec::with_capacity(4 + cursor);
    calldata.extend_from_slice(&selector(signature));
    for value in head {
        calldata.extend_from_slice(&value);
    }
    for (_, tail) in tails {
        calldata.extend_from_slice(tail);
    }
    calldata
}

fn sei_edit_validator(moniker: &[u8], commission: &[u8]) -> Vec<u8> {
    encode_call(
        "editValidator(string,string,uint256)",
        vec![[0u8; 32], [0u8; 32], word(1_000_000)],
        &[(0, blob(moniker)), (1, blob(commission))],
    )
}

fn kiln_create_operator(percent: usize) -> Vec<u8> {
    let signature = "createOperator(address,string,uint256,uint256,address[],uint256[])";
    let owner = address("1111111111111111111111111111111111111111");
    let recipient = address("2222222222222222222222222222222222222222");
    encode_call(
        signature,
        vec![
            address_word(owner),
            [0u8; 32],
            word(500),
            word(1_000),
            [0u8; 32],
            [0u8; 32],
        ],
        &[
            (1, blob(b"PQ1 Operator")),
            (4, word_array(&[address_word(recipient)])),
            (5, word_array(&[word(percent)])),
        ],
    )
}

fn proof_bundle(blob: &[u8], entry: &Emitted) -> Vec<u8> {
    let depth = u32::from_le_bytes(blob[24..28].try_into().expect("proof depth")) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().expect("proof offset")) as usize;
    let proof_base = proofs_off + entry.leaf_index * depth * 32;
    let mut bundle = Vec::with_capacity(2 + entry.ir_bytes.len() + 8 + depth * 32);
    bundle.extend_from_slice(&(entry.ir_bytes.len() as u16).to_be_bytes());
    bundle.extend_from_slice(&entry.ir_bytes);
    bundle.extend_from_slice(&(entry.leaf_index as u32).to_be_bytes());
    bundle.extend_from_slice(&(depth as u32).to_be_bytes());
    bundle.extend_from_slice(&blob[proof_base..proof_base + depth * 32]);
    bundle
}

fn render_call(
    catalogue: &Erc7730BuildResult,
    source: &str,
    chain_id: u64,
    calldata: &[u8],
) -> Result<Pages, RenderErr> {
    let selector: [u8; 4] = calldata[..4].try_into().expect("calldata selector");
    let entry = catalogue
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == chain_id
                && entry.source.file_name().and_then(|name| name.to_str()) == Some(source)
                && Erc7730Ir::parse(&entry.ir_bytes)
                    .expect("candidate IR parses")
                    .find_format_by_selector(&selector)
                    .expect("candidate formats parse")
                    .is_some()
        })
        .unwrap_or_else(|| {
            panic!(
                "missing production format {source} 0x{}",
                hex::encode(selector)
            )
        });
    let bundle = proof_bundle(&catalogue.blob, entry);
    let verified = verify_erc7730_bundle(&bundle, &catalogue.root)
        .expect("production descriptor Merkle-verifies");
    cross_check_contract(&verified.ir, chain_id, &entry.contract)
        .expect("production descriptor binds target");
    let tx = Eip1559Tx {
        chain_id,
        gas_limit: 500_000,
        to: Some(entry.contract),
        data_len: calldata.len(),
        ..Eip1559Tx::default()
    };
    render_erc7730_pages(&tx, calldata, &verified, None, &NameResolver::new())
}

fn read_offset(calldata: &[u8], slot: usize) -> usize {
    let start = 4 + slot * 32;
    let word = &calldata[start..start + 32];
    assert!(word[..24].iter().all(|byte| *byte == 0));
    u64::from_be_bytes(word[24..].try_into().expect("offset width")) as usize
}

#[test]
fn production_bounded_multi_tail_inventory_and_renderer_are_exact() {
    let catalogue = build_production();

    let mut expected = expected_rows();
    expected.sort();
    let actual = actual_rows(&catalogue);
    assert_eq!(actual, expected, "bounded multi-tail catalogue drifted");
    assert_eq!(actual.len(), 6, "expected six deployment-format rows");
    let unique_formats: BTreeSet<_> = actual
        .iter()
        .map(|row| (row.source.as_str(), row.selector))
        .collect();
    assert_eq!(unique_formats.len(), 5, "expected five unique formats");

    let sei = sei_edit_validator(b"pq1-validator", b"0.150000");
    let sei_pages = render_call(&catalogue, "calldata-sei-staking.json", 1_329, &sei)
        .expect("real Sei blob/blob format renders");
    let changed_sei = sei_edit_validator(b"pq1-validator", b"0.160000");
    let changed_sei_pages =
        render_call(&catalogue, "calldata-sei-staking.json", 1_329, &changed_sei)
            .expect("changed later Sei string remains canonical");
    assert_ne!(
        sei_pages.as_slice(),
        changed_sei_pages.as_slice(),
        "changing a later signed string must change the trusted pages"
    );

    let mut dirty_padding = sei.clone();
    let second_tail = read_offset(&dirty_padding, 1);
    let second_len_start = 4 + second_tail;
    let second_len = u64::from_be_bytes(
        dirty_padding[second_len_start + 24..second_len_start + 32]
            .try_into()
            .expect("string length width"),
    ) as usize;
    let first_padding_byte = second_len_start + 32 + second_len;
    assert_eq!(dirty_padding[first_padding_byte], 0);
    dirty_padding[first_padding_byte] = 1;
    assert!(matches!(
        render_call(
            &catalogue,
            "calldata-sei-staking.json",
            1_329,
            &dirty_padding,
        ),
        Err(RenderErr::Reject(_))
    ));

    let kiln = kiln_create_operator(10_000);
    let kiln_pages = render_call(
        &catalogue,
        "calldata-kiln-fee-splitter-factory.json",
        1,
        &kiln,
    )
    .expect("real Kiln blob/address[]/uint[] format renders");
    let changed_kiln = kiln_create_operator(9_999);
    let changed_kiln_pages = render_call(
        &catalogue,
        "calldata-kiln-fee-splitter-factory.json",
        1,
        &changed_kiln,
    )
    .expect("changed later Kiln uint[] remains canonical");
    assert_ne!(
        kiln_pages.as_slice(),
        changed_kiln_pages.as_slice(),
        "changing the final signed array must change the trusted pages"
    );

    let mut bad_later_offset = kiln.clone();
    let final_offset = read_offset(&bad_later_offset, 5);
    bad_later_offset[4 + 5 * 32..4 + 6 * 32].copy_from_slice(&word(final_offset + 32));
    assert!(matches!(
        render_call(
            &catalogue,
            "calldata-kiln-fee-splitter-factory.json",
            1,
            &bad_later_offset,
        ),
        Err(RenderErr::Reject(_))
    ));

    let mut suffix = kiln;
    suffix.extend_from_slice(&[0u8; 32]);
    assert!(matches!(
        render_call(
            &catalogue,
            "calldata-kiln-fee-splitter-factory.json",
            1,
            &suffix,
        ),
        Err(RenderErr::Reject(_))
    ));
}
