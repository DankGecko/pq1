//! Offline deployment and semantic evidence for the Aave V3 Ethereum Pool.
//!
//! This evidence is deliberately narrow: it binds the chain-1 Pool proxy at
//! one historical block to revision 11 source and to the ten formats that PQ1
//! currently admits. It does not authorize future proxy upgrades or make any
//! claim about the other fourteen unique Pool deployments in the descriptor.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::abi::container_field;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, PathOp, Visibility};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::enums::lookup_enum_label;
use pqsigner_erc7730::render::params::{parse as parse_params, ADDR_TYPE_EOA, ADDR_TYPE_TOKEN};
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const DESCRIPTOR_RELATIVE: &str = "registry/aave/calldata-lpv3.json";
const POOL_PROXY: &str = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2";
const ADDRESSES_PROVIDER: &str = "0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e";
const POOL_IMPLEMENTATION: &str = "0x728a138A4823392C2EFA55e028d434F526fE03CF";
const BORROW_LOGIC: &str = "0x52Da0ce88202D1542543598D1e1e27F0d344726A";
const SUPPLY_LOGIC: &str = "0x584C7d8c4cb05304FE5Ac7fbc97f20A10Fb07564";
const BLOCK_NUMBER: u64 = 25_574_144;
const BLOCK_NUMBER_HEX: &str = "0x1863b00";
const BLOCK_HASH: &str = "0xc764a3327787002b64c36ae2776c0f25a9c9e7fa8e94dc1748c04550adba4bfd";
const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const LOCAL_AND_ENS: u8 = 0x01 | 0x02;

const REFUSED: [&str; 3] = [
    "multicall(bytes[])",
    "repayWithPermit(address,uint256,uint256,address,uint256,uint8,bytes32,bytes32)",
    "supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/aave-v3-ethereum-pool")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("field {key} is a string"))
}

fn decode_hex_text(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid hex evidence")
}

fn address(text: &str) -> [u8; 20] {
    decode_hex_text(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn abi_word_address(value: &Value) -> [u8; 20] {
    let word = decode_hex_text(value.as_str().expect("ABI word is hex"));
    assert_eq!(word.len(), 32, "ABI address result is one word");
    assert_eq!(&word[..12], &[0u8; 12], "ABI address padding changed");
    word[12..].try_into().expect("address word width")
}

fn hex_u64(value: &Value) -> u64 {
    let text = value.as_str().expect("hex quantity is a string");
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).expect("hex quantity")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex_text(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Clone, Copy)]
struct SolidityFunction<'a> {
    header: &'a str,
    body: &'a str,
}

fn solidity_function<'a>(source: &'a str, name: &str) -> SolidityFunction<'a> {
    let needle = format!("function {name}(");
    let mut matches = source.match_indices(&needle);
    let (start, _) = matches
        .next()
        .unwrap_or_else(|| panic!("official Pool source lost {name}"));
    assert!(
        matches.next().is_none(),
        "official Pool source contains multiple {name} definitions"
    );

    let definition = &source[start..];
    let opening = definition
        .find('{')
        .unwrap_or_else(|| panic!("official Pool function {name} has no body"));
    assert!(
        !definition[..opening].contains(';'),
        "official Pool function {name} is only a declaration"
    );

    let mut depth = 0usize;
    for (offset, byte) in definition[opening..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("unbalanced function body");
                if depth == 0 {
                    let closing = opening + offset + 1;
                    return SolidityFunction {
                        header: &definition[..opening],
                        body: &definition[opening..closing],
                    };
                }
            }
            _ => {}
        }
    }
    panic!("official Pool function {name} has an unclosed body")
}

fn assert_fragments_in_order(source: &str, fragments: &[&str], context: &str) {
    let normalized = normalized_whitespace(source);
    let mut cursor = 0usize;
    for fragment in fragments {
        let offset = normalized[cursor..]
            .find(fragment)
            .unwrap_or_else(|| panic!("{context} lost semantic fragment: {fragment}"));
        cursor += offset + fragment.len();
    }
}

fn function_selector(signature: &str) -> String {
    format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
}

fn collect_receipts(value: &Value, receipts: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            if let Some(path) = object.get("path").and_then(Value::as_str) {
                let hash = object
                    .get("file_sha256")
                    .or_else(|| object.get("sha256"))
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("evidence receipt {path} has no file SHA-256"));
                assert!(
                    receipts.insert(path.to_owned(), hash.to_owned()).is_none(),
                    "duplicate evidence receipt for {path}"
                );
            }
            for child in object.values() {
                collect_receipts(child, receipts);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_receipts(child, receipts);
            }
        }
        _ => {}
    }
}

fn collect_files(root: &Path, directory: &Path, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read evidence directory {}: {error}", directory.display()))
    {
        let path = entry.expect("evidence directory entry").path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else {
            files.insert(
                path.strip_prefix(root)
                    .expect("evidence file under root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn result_map(batch: &Value, source: &str, results: &mut BTreeMap<u64, Value>) {
    for response in batch.as_array().expect("RPC response batch") {
        assert_eq!(response["jsonrpc"].as_str(), Some("2.0"));
        assert!(response.get("error").is_none(), "RPC error in {source}");
        let id = response["id"].as_u64().expect("numeric RPC response id");
        let result = response
            .get("result")
            .unwrap_or_else(|| panic!("RPC result absent in {source} for id {id}"));
        assert!(
            results.insert(id, result.clone()).is_none(),
            "duplicate RPC result id {id} in {source}"
        );
    }
}

fn source_from_report<'a>(report: &'a Value, suffix: &str) -> &'a str {
    let mut matches = Vec::new();
    if report["file_path"]
        .as_str()
        .is_some_and(|path| path.ends_with(suffix))
    {
        matches.push(
            report["source_code"]
                .as_str()
                .expect("primary Blockscout source"),
        );
    }
    for source in report["additional_sources"]
        .as_array()
        .expect("Blockscout additional sources")
    {
        if source["file_path"]
            .as_str()
            .is_some_and(|path| path.ends_with(suffix))
        {
            matches.push(required_str(source, "source_code"));
        }
    }
    assert_eq!(
        matches.len(),
        1,
        "Blockscout report must contain exactly one {suffix}"
    );
    matches[0]
}

#[derive(Clone, Copy)]
enum ExpectedPath {
    Structured(u16),
    Sender,
}

#[derive(Clone, Copy)]
struct FieldExpectation {
    label: &'static str,
    op: FormatOp,
    path: ExpectedPath,
    terminal: TerminalKind,
    integer_width: Option<u8>,
    token_path: Option<u16>,
    threshold: bool,
    message: Option<&'static str>,
    addr_types: Option<u8>,
    addr_sources: Option<u8>,
    has_enum: bool,
}

impl FieldExpectation {
    const fn amount(
        label: &'static str,
        arg: u16,
        threshold: bool,
        message: Option<&'static str>,
    ) -> Self {
        Self {
            label,
            op: FormatOp::TokenAmount,
            path: ExpectedPath::Structured(arg),
            terminal: TerminalKind::Unsigned,
            integer_width: Some(32),
            token_path: Some(0),
            threshold,
            message,
            addr_types: None,
            addr_sources: None,
            has_enum: false,
        }
    }

    const fn unsigned(label: &'static str, arg: u16, width: u8) -> Self {
        Self {
            label,
            op: FormatOp::Raw,
            path: ExpectedPath::Structured(arg),
            terminal: TerminalKind::Unsigned,
            integer_width: Some(width),
            token_path: None,
            threshold: false,
            message: None,
            addr_types: None,
            addr_sources: None,
            has_enum: false,
        }
    }

    const fn boolean(label: &'static str, arg: u16) -> Self {
        Self {
            label,
            op: FormatOp::Raw,
            path: ExpectedPath::Structured(arg),
            terminal: TerminalKind::Bool,
            integer_width: None,
            token_path: None,
            threshold: false,
            message: None,
            addr_types: None,
            addr_sources: None,
            has_enum: false,
        }
    }

    const fn enum_field(label: &'static str, arg: u16) -> Self {
        Self {
            label,
            op: FormatOp::Enum,
            path: ExpectedPath::Structured(arg),
            terminal: TerminalKind::Unsigned,
            integer_width: Some(32),
            token_path: None,
            threshold: false,
            message: None,
            addr_types: None,
            addr_sources: None,
            has_enum: true,
        }
    }

    const fn address(
        label: &'static str,
        path: ExpectedPath,
        types: u8,
        sources: Option<u8>,
    ) -> Self {
        Self {
            label,
            op: FormatOp::AddressName,
            path,
            terminal: TerminalKind::Address,
            integer_width: None,
            token_path: None,
            threshold: false,
            message: None,
            addr_types: Some(types),
            addr_sources: sources,
            has_enum: false,
        }
    }
}

struct RouteExpectation {
    signature: &'static str,
    abi_inputs: &'static [(&'static str, &'static str)],
    intent: &'static str,
    head_words: u16,
    fields: Vec<FieldExpectation>,
}

fn route_expectations() -> Vec<RouteExpectation> {
    let eoa = |label, arg| {
        FieldExpectation::address(
            label,
            ExpectedPath::Structured(arg),
            ADDR_TYPE_EOA,
            Some(LOCAL_AND_ENS),
        )
    };
    let sender = |label, sources| {
        FieldExpectation::address(label, ExpectedPath::Sender, ADDR_TYPE_EOA, sources)
    };
    vec![
        RouteExpectation {
            signature: "approvePositionManager(address,bool)",
            abi_inputs: &[("positionManager", "address"), ("approve", "bool")],
            intent: "Approve Manager",
            head_words: 2,
            fields: vec![
                FieldExpectation::address(
                    "Position manager",
                    ExpectedPath::Structured(0),
                    ADDR_TYPE_EOA,
                    None,
                ),
                FieldExpectation::boolean("Approve", 1),
            ],
        },
        RouteExpectation {
            signature: "borrow(address,uint256,uint256,uint16,address)",
            abi_inputs: &[
                ("asset", "address"),
                ("amount", "uint256"),
                ("interestRateMode", "uint256"),
                ("referralCode", "uint16"),
                ("onBehalfOf", "address"),
            ],
            intent: "Borrow",
            head_words: 5,
            fields: vec![
                FieldExpectation::amount("Amount to borrow", 1, false, None),
                FieldExpectation::enum_field("Interest Rate mode", 2),
                eoa("Debtor", 4),
                FieldExpectation::unsigned("Referral Code", 3, 2),
            ],
        },
        RouteExpectation {
            signature: "deposit(address,uint256,address,uint16)",
            abi_inputs: &[
                ("asset", "address"),
                ("amount", "uint256"),
                ("onBehalfOf", "address"),
                ("referralCode", "uint16"),
            ],
            intent: "Supply",
            head_words: 4,
            fields: vec![
                FieldExpectation::amount("Amount to supply", 1, false, None),
                eoa("Collateral recipient", 2),
                FieldExpectation::unsigned("Referral Code", 3, 2),
            ],
        },
        RouteExpectation {
            signature: "renouncePositionManagerRole(address)",
            abi_inputs: &[("user", "address")],
            intent: "Revoke Manager Role",
            head_words: 1,
            fields: vec![
                sender("Position manager", None),
                FieldExpectation::address("User", ExpectedPath::Structured(0), ADDR_TYPE_EOA, None),
            ],
        },
        RouteExpectation {
            signature: "repay(address,uint256,uint256,address)",
            abi_inputs: &[
                ("asset", "address"),
                ("amount", "uint256"),
                ("interestRateMode", "uint256"),
                ("onBehalfOf", "address"),
            ],
            intent: "Repay loan",
            head_words: 4,
            fields: vec![
                FieldExpectation::amount("Amount to repay", 1, true, Some("All")),
                FieldExpectation::enum_field("Interest rate mode", 2),
                eoa("For debt holder", 3),
            ],
        },
        RouteExpectation {
            signature: "repayWithATokens(address,uint256,uint256)",
            abi_inputs: &[
                ("asset", "address"),
                ("amount", "uint256"),
                ("interestRateMode", "uint256"),
            ],
            intent: "Repay with aTokens",
            head_words: 3,
            fields: vec![
                FieldExpectation::amount("Amount to repay", 1, true, Some("All")),
                FieldExpectation::enum_field("Interest rate mode", 2),
                sender("For debt holder", Some(LOCAL_AND_ENS)),
            ],
        },
        RouteExpectation {
            signature: "setUserUseReserveAsCollateral(address,bool)",
            abi_inputs: &[("asset", "address"), ("useAsCollateral", "bool")],
            intent: "Manage collateral",
            head_words: 2,
            fields: vec![
                FieldExpectation::address(
                    "For asset",
                    ExpectedPath::Structured(0),
                    ADDR_TYPE_TOKEN,
                    Some(LOCAL_AND_ENS),
                ),
                FieldExpectation::boolean("Use as collateral", 1),
            ],
        },
        RouteExpectation {
            signature: "setUserUseReserveAsCollateralOnBehalfOf(address,bool,address)",
            abi_inputs: &[
                ("asset", "address"),
                ("useAsCollateral", "bool"),
                ("onBehalfOf", "address"),
            ],
            intent: "Manage collateral",
            head_words: 3,
            fields: vec![
                FieldExpectation::address(
                    "For asset",
                    ExpectedPath::Structured(0),
                    ADDR_TYPE_TOKEN,
                    Some(LOCAL_AND_ENS),
                ),
                FieldExpectation::boolean("Use as collateral", 1),
                eoa("Debtor", 2),
            ],
        },
        RouteExpectation {
            signature: "supply(address,uint256,address,uint16)",
            abi_inputs: &[
                ("asset", "address"),
                ("amount", "uint256"),
                ("onBehalfOf", "address"),
                ("referralCode", "uint16"),
            ],
            intent: "Supply",
            head_words: 4,
            fields: vec![
                FieldExpectation::amount("Amount to supply", 1, false, None),
                eoa("Collateral recipient", 2),
                FieldExpectation::unsigned("Referral Code", 3, 2),
            ],
        },
        RouteExpectation {
            signature: "withdraw(address,uint256,address)",
            abi_inputs: &[
                ("asset", "address"),
                ("amount", "uint256"),
                ("to", "address"),
            ],
            intent: "Withdraw",
            head_words: 3,
            fields: vec![
                FieldExpectation::amount("Amount to withdraw", 1, true, Some("Max")),
                eoa("To recipient", 2),
            ],
        },
    ]
}

#[test]
fn aave_v3_ethereum_fixed_block_evidence_is_complete_and_cross_bound() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["fixed_block"]["number"].as_u64(),
        Some(BLOCK_NUMBER)
    );
    assert_eq!(
        manifest["fixed_block"]["number_hex"].as_str(),
        Some(BLOCK_NUMBER_HEX)
    );
    assert_eq!(manifest["fixed_block"]["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(manifest["contracts"]["pool_revision"].as_u64(), Some(11));
    assert_eq!(
        required_str(&manifest["contracts"], "eip1967_implementation_slot"),
        IMPLEMENTATION_SLOT
    );
    let boundary = required_str(&manifest, "boundary").to_ascii_lowercase();
    assert!(boundary.contains("historical fixed-block"));
    assert!(boundary.contains("other fourteen"));
    assert!(boundary.contains("future upgrades"));

    // Every archived byte except the self-describing manifest is hash-receipted,
    // and every manifest receipt names a file that is actually in the bundle.
    let mut receipts = BTreeMap::new();
    collect_receipts(&manifest, &mut receipts);
    let mut archived = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut archived);
    archived.remove("manifest.json");
    assert_eq!(
        receipts.keys().cloned().collect::<BTreeSet<_>>(),
        archived,
        "unreceipted or dangling Aave evidence artifact"
    );
    for (relative, expected_hash) in &receipts {
        let bytes = fs::read(evidence.join(relative))
            .unwrap_or_else(|error| panic!("read evidence {relative}: {error}"));
        assert_eq!(
            sha256_hex(&bytes),
            *expected_hash,
            "artifact drift: {relative}"
        );
    }

    let expected_request_batches: BTreeMap<&str, BTreeSet<u64>> = [
        ("admin", [12, 13].into_iter().collect()),
        ("identity", [1, 2, 3].into_iter().collect()),
        ("implementation", [7, 8, 9].into_iter().collect()),
        ("libraries", [10, 11].into_iter().collect()),
        ("proxy", [4, 5, 6].into_iter().collect()),
    ]
    .into_iter()
    .collect();
    let mut requests = BTreeMap::<u64, Value>::new();
    for receipt in manifest["rpc"]["requests"]
        .as_array()
        .expect("RPC request receipts")
    {
        let batch_name = required_str(receipt, "batch");
        let path = required_str(receipt, "path");
        let batch = read_json(&evidence.join(path));
        let mut ids = BTreeSet::new();
        for request in batch.as_array().expect("RPC request batch") {
            assert_eq!(request["jsonrpc"].as_str(), Some("2.0"));
            let id = request["id"].as_u64().expect("numeric RPC request id");
            ids.insert(id);
            assert!(
                requests.insert(id, request.clone()).is_none(),
                "duplicate request id {id}"
            );
        }
        assert_eq!(
            expected_request_batches.get(batch_name),
            Some(&ids),
            "request batch membership drifted: {batch_name}"
        );
    }
    assert_eq!(
        requests.keys().copied().collect::<BTreeSet<_>>(),
        (1u64..=13).collect(),
        "the raw request archive must contain exactly ids 1..=13"
    );

    let block_tag = json!({"blockHash": BLOCK_HASH, "requireCanonical": true});
    let expected_requests = [
        (1, "eth_chainId", json!([])),
        (2, "eth_getBlockByHash", json!([BLOCK_HASH, false])),
        (
            3,
            "eth_getStorageAt",
            json!([POOL_PROXY, IMPLEMENTATION_SLOT, block_tag.clone()]),
        ),
        (4, "eth_getCode", json!([POOL_PROXY, block_tag.clone()])),
        (
            5,
            "eth_call",
            json!([{"to": POOL_PROXY, "data": function_selector("ADDRESSES_PROVIDER()")}, block_tag.clone()]),
        ),
        (
            6,
            "eth_call",
            json!([{"to": POOL_PROXY, "data": function_selector("POOL_REVISION()")}, block_tag.clone()]),
        ),
        (
            7,
            "eth_getCode",
            json!([POOL_IMPLEMENTATION, block_tag.clone()]),
        ),
        (
            8,
            "eth_getCode",
            json!([ADDRESSES_PROVIDER, block_tag.clone()]),
        ),
        (
            9,
            "eth_call",
            json!([{"to": ADDRESSES_PROVIDER, "data": function_selector("getPool()")}, block_tag.clone()]),
        ),
        (10, "eth_getCode", json!([BORROW_LOGIC, block_tag.clone()])),
        (11, "eth_getCode", json!([SUPPLY_LOGIC, block_tag.clone()])),
        (
            12,
            "eth_call",
            json!([{"from": ADDRESSES_PROVIDER, "to": POOL_PROXY, "data": function_selector("implementation()")}, block_tag.clone()]),
        ),
        (
            13,
            "eth_call",
            json!([{"from": ADDRESSES_PROVIDER, "to": POOL_PROXY, "data": function_selector("admin()")}, block_tag.clone()]),
        ),
    ];
    for (id, method, params) in expected_requests {
        assert_eq!(
            requests[&id]["method"].as_str(),
            Some(method),
            "method for RPC id {id}"
        );
        assert_eq!(requests[&id]["params"], params, "params for RPC id {id}");
    }

    let expected_providers = [
        ("dRPC", "https://eth.drpc.org"),
        ("MEV Blocker", "https://rpc.mevblocker.io"),
        ("Tenderly", "https://mainnet.gateway.tenderly.co"),
    ];
    let providers = manifest["rpc"]["providers"]
        .as_array()
        .expect("three provider receipts");
    assert_eq!(providers.len(), expected_providers.len());
    assert_eq!(
        providers
            .iter()
            .map(|provider| (
                required_str(provider, "name"),
                required_str(provider, "url")
            ))
            .collect::<BTreeSet<_>>(),
        expected_providers.into_iter().collect()
    );
    let mut provider_results = Vec::<(&str, BTreeMap<u64, Value>)>::new();
    for provider in providers {
        let name = required_str(provider, "name");
        let response_receipts = provider["responses"]
            .as_array()
            .expect("provider response receipts");
        assert_eq!(response_receipts.len(), 5);
        let mut results = BTreeMap::new();
        for receipt in response_receipts {
            let path = required_str(receipt, "path");
            result_map(&read_json(&evidence.join(path)), path, &mut results);
        }
        assert_eq!(
            results.keys().copied().collect::<BTreeSet<_>>(),
            (1u64..=13).collect(),
            "{name} did not answer every request id exactly once"
        );
        provider_results.push((name, results));
    }
    let agreed = &provider_results[0].1;
    for (name, results) in &provider_results[1..] {
        assert_eq!(
            results, agreed,
            "three-provider result disagreement: {name}"
        );
    }

    assert_eq!(hex_u64(&agreed[&1]), 1);
    let block = &agreed[&2];
    assert_eq!(block["number"].as_str(), Some(BLOCK_NUMBER_HEX));
    assert_eq!(block["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(block["parentHash"], manifest["fixed_block"]["parent_hash"]);
    assert_eq!(block["stateRoot"], manifest["fixed_block"]["state_root"]);
    assert_eq!(
        hex_u64(&block["timestamp"]),
        manifest["fixed_block"]["timestamp"].as_u64().unwrap()
    );
    assert_eq!(abi_word_address(&agreed[&3]), address(POOL_IMPLEMENTATION));
    assert_eq!(abi_word_address(&agreed[&5]), address(ADDRESSES_PROVIDER));
    assert_eq!(hex_u64(&agreed[&6]), 11);
    assert_eq!(abi_word_address(&agreed[&9]), address(POOL_PROXY));
    assert_eq!(abi_word_address(&agreed[&12]), address(POOL_IMPLEMENTATION));
    assert_eq!(abi_word_address(&agreed[&13]), address(ADDRESSES_PROVIDER));

    let mut runtimes = BTreeMap::<String, Vec<u8>>::new();
    for runtime in manifest["runtimes"].as_array().expect("runtime receipts") {
        let key = required_str(runtime, "key");
        let path = required_str(runtime, "path");
        let code = read_hex(&evidence.join(path));
        assert_eq!(
            code.len() as u64,
            runtime["bytes"].as_u64().expect("runtime bytes")
        );
        assert_eq!(sha256_hex(&code), required_str(runtime, "decoded_sha256"));
        assert_eq!(keccak_hex(&code), required_str(runtime, "keccak256"));
        let rpc_id = runtime["rpc_id"].as_u64().expect("runtime RPC id");
        assert_eq!(
            decode_hex_text(agreed[&rpc_id].as_str().expect("RPC runtime hex")),
            code,
            "fixed-block runtime mismatch for {key}"
        );
        assert_eq!(
            address(required_str(runtime, "address")),
            match key {
                "pool_proxy" => address(POOL_PROXY),
                "pool_implementation" => address(POOL_IMPLEMENTATION),
                "borrow_logic" => address(BORROW_LOGIC),
                "supply_logic" => address(SUPPLY_LOGIC),
                _ => panic!("unexpected runtime key {key}"),
            }
        );
        runtimes.insert(key.to_owned(), code);
    }
    assert_eq!(runtimes.len(), 4);
    let provider_runtime = decode_hex_text(agreed[&8].as_str().expect("provider runtime hex"));
    assert_eq!(provider_runtime.len(), 9_846);
    assert_eq!(
        sha256_hex(&provider_runtime),
        "e5416052b67aa0475bffe5707510a1981ffcc131d9b49066d51f6e25eb6c5c9f"
    );
    assert_eq!(
        keccak_hex(&provider_runtime),
        "0x0f8c7f9c735ac0f3f35b1e78882a617380549def43faeca0d959d5aadd81dee4"
    );

    let mut reports = BTreeMap::<String, Value>::new();
    for receipt in manifest["blockscout"]
        .as_array()
        .expect("Blockscout receipts")
    {
        let key = required_str(receipt, "key");
        let report = read_json(&evidence.join(required_str(receipt, "path")));
        assert_eq!(report["name"], receipt["name"]);
        assert_eq!(report["compiler_version"], receipt["compiler"]);
        assert_eq!(report["evm_version"], receipt["evm_version"]);
        assert_eq!(report["is_changed_bytecode"].as_bool(), Some(false));
        match required_str(receipt, "verification") {
            "full" => {
                assert_eq!(report["is_fully_verified"].as_bool(), Some(true));
                assert_eq!(report["is_partially_verified"].as_bool(), Some(false));
            }
            "partial" => {
                assert_eq!(report["is_fully_verified"].as_bool(), Some(false));
                assert_eq!(report["is_partially_verified"].as_bool(), Some(true));
            }
            status => panic!("unexpected verification status {status}"),
        }
        assert_eq!(
            decode_hex_text(required_str(&report, "deployed_bytecode")),
            runtimes[key],
            "Blockscout runtime diverged from three fixed-block providers: {key}"
        );
        let url_address = required_str(receipt, "url")
            .rsplit('/')
            .next()
            .expect("Blockscout URL address");
        let runtime_address = manifest["runtimes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|runtime| runtime["key"].as_str() == Some(key))
            .expect("runtime receipt for Blockscout report");
        assert_eq!(
            address(url_address),
            address(required_str(runtime_address, "address"))
        );
        reports.insert(key.to_owned(), report);
    }

    let proxy_report = &reports["pool_proxy"];
    assert_eq!(proxy_report["proxy_type"].as_str(), Some("eip1967"));
    let implementations = proxy_report["implementations"]
        .as_array()
        .expect("proxy implementations");
    assert_eq!(implementations.len(), 1);
    assert_eq!(
        address(required_str(&implementations[0], "address_hash")),
        address(POOL_IMPLEMENTATION)
    );
    assert_eq!(implementations[0]["name"].as_str(), Some("PoolInstance"));

    let implementation_report = &reports["pool_implementation"];
    let libraries = implementation_report["external_libraries"]
        .as_array()
        .expect("implementation linked libraries");
    for (suffix, expected) in [("BorrowLogic", BORROW_LOGIC), ("SupplyLogic", SUPPLY_LOGIC)] {
        let matches: BTreeSet<_> = libraries
            .iter()
            .filter(|library| required_str(library, "name").ends_with(suffix))
            .map(|library| address(required_str(library, "address_hash")))
            .collect();
        assert_eq!(
            matches,
            [address(expected)].into_iter().collect(),
            "linked {suffix}"
        );
    }

    for (archive, suffix) in [
        ("source/PoolInstance.sol", "PoolInstance.sol"),
        ("source/Pool.sol", "/Pool.sol"),
        ("source/BorrowLogic.sol", "BorrowLogic.sol"),
        ("source/SupplyLogic.sol", "SupplyLogic.sol"),
    ] {
        let archived = fs::read(evidence.join(archive)).expect("read archived official source");
        assert_eq!(
            source_from_report(implementation_report, suffix).as_bytes(),
            archived,
            "official origin source and verified deployed build diverged: {archive}"
        );
    }
    assert_eq!(
        source_from_report(&reports["borrow_logic"], "BorrowLogic.sol").as_bytes(),
        fs::read(evidence.join("source/BorrowLogic.sol")).unwrap()
    );
    assert_eq!(
        source_from_report(&reports["supply_logic"], "SupplyLogic.sol").as_bytes(),
        fs::read(evidence.join("source/SupplyLogic.sol")).unwrap()
    );
    assert_eq!(
        required_str(&manifest["upstream"]["origin"], "commit"),
        "fd1fbd9150426ca8ace9cee45b4acf912ae84f5b"
    );
    assert_eq!(
        required_str(&manifest["upstream"]["origin"], "tree"),
        "e4986ad5868db92d6551b25a9191393cdecfdef4"
    );
    assert_eq!(
        required_str(&manifest["upstream"]["address_book"], "commit"),
        "7e444a1e73b538fd0b9e093e5156401d6fccca7d"
    );
    assert_eq!(
        required_str(&manifest["upstream"]["address_book"], "tree"),
        "b87cc868bac4c5ac2a0cb970ef3973e15350e9df"
    );

    let address_book = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/AaveV3Ethereum.sol"))
            .expect("address book source"),
    );
    for (symbol, declaration) in [
        (
            "POOL_ADDRESSES_PROVIDER",
            format!(
                "IPoolAddressesProvider internal constant POOL_ADDRESSES_PROVIDER = IPoolAddressesProvider({ADDRESSES_PROVIDER});"
            ),
        ),
        (
            "POOL",
            format!("IPool internal constant POOL = IPool({POOL_PROXY});"),
        ),
        (
            "POOL_IMPL",
            format!("address internal constant POOL_IMPL = {POOL_IMPLEMENTATION};"),
        ),
    ] {
        assert!(
            address_book.contains(&declaration),
            "official Aave address book lost exact {symbol} assignment"
        );
    }
    let pool_instance = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/PoolInstance.sol")).unwrap(),
    );
    assert!(pool_instance.contains("uint256 public constant POOL_REVISION = 11;"));
    assert!(pool_instance.contains("require(provider == ADDRESSES_PROVIDER"));
    let pool_source = fs::read_to_string(evidence.join("source/Pool.sol")).unwrap();
    let pool_functions = [
        "approvePositionManager",
        "borrow",
        "deposit",
        "renouncePositionManagerRole",
        "repay",
        "repayWithATokens",
        "setUserUseReserveAsCollateral",
        "setUserUseReserveAsCollateralOnBehalfOf",
        "supply",
        "withdraw",
    ]
    .into_iter()
    .map(|name| (name, solidity_function(&pool_source, name)))
    .collect::<BTreeMap<_, _>>();
    assert_fragments_in_order(
        pool_functions["approvePositionManager"].body,
        &[
            "_positionManager[_msgSender()][positionManager] = approve;",
            "user: _msgSender()",
            "positionManager: positionManager",
        ],
        "approvePositionManager",
    );
    assert_fragments_in_order(
        pool_functions["borrow"].body,
        &[
            "BorrowLogic.executeBorrow(",
            "_usersConfig[onBehalfOf]",
            "asset: asset",
            "user: _msgSender()",
            "onBehalfOf: onBehalfOf",
            "amount: amount",
            "interestRateMode: DataTypes.InterestRateMode(interestRateMode)",
            "referralCode: referralCode",
            "releaseUnderlying: true",
        ],
        "borrow",
    );
    for name in ["deposit", "supply"] {
        assert_fragments_in_order(
            pool_functions[name].body,
            &[
                "SupplyLogic.executeSupply(",
                "_usersConfig[onBehalfOf]",
                "user: _msgSender()",
                "asset: asset",
                "amount: amount",
                "onBehalfOf: onBehalfOf",
                "referralCode: referralCode",
            ],
            name,
        );
    }
    assert_fragments_in_order(
        pool_functions["renouncePositionManagerRole"].body,
        &[
            "_positionManager[user][_msgSender()] = false;",
            "user: user",
            "positionManager: _msgSender()",
        ],
        "renouncePositionManagerRole",
    );
    assert_fragments_in_order(
        pool_functions["repay"].body,
        &[
            "BorrowLogic.executeRepay(",
            "_usersConfig[onBehalfOf]",
            "asset: asset",
            "user: _msgSender()",
            "amount: amount",
            "interestRateMode: DataTypes.InterestRateMode(interestRateMode)",
            "onBehalfOf: onBehalfOf",
            "useATokens: false",
        ],
        "repay",
    );
    assert_fragments_in_order(
        pool_functions["repayWithATokens"].body,
        &[
            "BorrowLogic.executeRepay(",
            "_usersConfig[_msgSender()]",
            "asset: asset",
            "user: _msgSender()",
            "amount: amount",
            "interestRateMode: DataTypes.InterestRateMode(interestRateMode)",
            "onBehalfOf: _msgSender()",
            "useATokens: true",
        ],
        "repayWithATokens",
    );
    assert_fragments_in_order(
        pool_functions["setUserUseReserveAsCollateral"].body,
        &[
            "SupplyLogic.executeUseReserveAsCollateral(",
            "_usersConfig[_msgSender()]",
            "_msgSender()",
            "asset",
            "useAsCollateral",
        ],
        "setUserUseReserveAsCollateral",
    );
    assert!(pool_functions["setUserUseReserveAsCollateralOnBehalfOf"]
        .header
        .contains("onlyPositionManager(onBehalfOf)"));
    assert_fragments_in_order(
        pool_functions["setUserUseReserveAsCollateralOnBehalfOf"].body,
        &[
            "SupplyLogic.executeUseReserveAsCollateral(",
            "_usersConfig[onBehalfOf]",
            "onBehalfOf",
            "asset",
            "useAsCollateral",
        ],
        "setUserUseReserveAsCollateralOnBehalfOf",
    );
    assert_fragments_in_order(
        pool_functions["withdraw"].body,
        &[
            "SupplyLogic.executeWithdraw(",
            "_usersConfig[_msgSender()]",
            "user: _msgSender()",
            "asset: asset",
            "amount: amount",
            "to: to",
        ],
        "withdraw",
    );
    assert!(solidity_function(&pool_source, "getBorrowLogic")
        .body
        .contains("return address(BorrowLogic);"));
    assert!(solidity_function(&pool_source, "getSupplyLogic")
        .body
        .contains("return address(SupplyLogic);"));

    let route_abi = read_json(&evidence.join(required_str(&manifest["abi"], "path")));
    assert_eq!(route_abi.as_array().map(Vec::len), Some(10));
    let full_abi = implementation_report["abi"]
        .as_array()
        .expect("implementation ABI");
    let mut abi_entries = BTreeMap::new();
    for entry in route_abi.as_array().unwrap() {
        assert!(
            full_abi.contains(entry),
            "saved route ABI entry not derived from deployed ABI"
        );
        assert_eq!(entry["type"].as_str(), Some("function"));
        assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
        let signature = format!(
            "{}({})",
            required_str(entry, "name"),
            entry["inputs"]
                .as_array()
                .expect("ABI inputs")
                .iter()
                .map(|input| required_str(input, "type"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(
            abi_entries.insert(signature, entry).is_none(),
            "duplicate admitted ABI signature"
        );
    }
    let route_expectations = route_expectations();
    assert_eq!(
        abi_entries.keys().cloned().collect::<BTreeSet<_>>(),
        route_expectations
            .iter()
            .map(|route| route.signature.to_owned())
            .collect(),
        "the archived ABI must contain exactly the ten admitted selectors"
    );
    for route in &route_expectations {
        let entry = abi_entries
            .get(route.signature)
            .unwrap_or_else(|| panic!("archived ABI lost {}", route.signature));
        let inputs = entry["inputs"]
            .as_array()
            .expect("ABI inputs")
            .iter()
            .map(|input| (required_str(input, "name"), required_str(input, "type")))
            .collect::<Vec<_>>();
        assert_eq!(
            inputs.as_slice(),
            route.abi_inputs,
            "ordered ABI input names/types drifted: {}",
            route.signature
        );
    }
}

#[test]
fn aave_v3_generated_ir_exactly_matches_the_ten_evidenced_routes() {
    let root = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let descriptor_manifest = &manifest["descriptor"];
    let vendored_path = root.join(required_str(descriptor_manifest, "vendored_file"));
    let curated_path = root.join(required_str(descriptor_manifest, "curation_overlay"));
    let vendored = fs::read(&vendored_path).expect("read production Aave descriptor");
    let curated = fs::read(&curated_path).expect("read curated Aave descriptor");
    assert_eq!(
        vendored, curated,
        "curated and installed Aave descriptors diverged"
    );
    assert_eq!(
        sha256_hex(&vendored),
        required_str(descriptor_manifest, "vendored_file_sha256")
    );
    assert_eq!(
        sha256_hex(&curated),
        required_str(descriptor_manifest, "curation_overlay_sha256")
    );

    let curation_manifest = read_json(&root.join("secure/data/erc7730/curations/manifest.json"));
    let replacement = curation_manifest["replacements"]
        .as_array()
        .expect("curation replacements")
        .iter()
        .find(|replacement| replacement["path"].as_str() == Some(DESCRIPTOR_RELATIVE))
        .expect("Aave curation replacement is receipted");
    assert_eq!(
        required_str(replacement, "replacement_sha256"),
        sha256_hex(&curated)
    );

    let descriptor: Value = serde_json::from_slice(&vendored).expect("parse Aave descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("Aave deployments");
    assert_eq!(
        deployments.len(),
        16,
        "descriptor declaration count drifted"
    );
    let unique_deployments = deployments
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"].as_u64().expect("deployment chain"),
                address(deployment["address"].as_str().expect("deployment address")),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        unique_deployments.len(),
        15,
        "duplicate Linea entry must dedupe"
    );
    assert!(unique_deployments.contains(&(1, address(POOL_PROXY))));

    let manifest_admitted = descriptor_manifest["admitted_routes"]
        .as_array()
        .expect("admitted route receipts");
    assert_eq!(manifest_admitted.len(), 10);
    let route_expectations = route_expectations();
    assert_eq!(
        route_expectations
            .iter()
            .map(|route| route.fields.len())
            .sum::<usize>(),
        27
    );
    for route in &route_expectations {
        let receipt = manifest_admitted
            .iter()
            .find(|candidate| candidate["canonical_signature"].as_str() == Some(route.signature))
            .unwrap_or_else(|| panic!("manifest lost admitted route {}", route.signature));
        assert_eq!(
            required_str(receipt, "selector"),
            function_selector(route.signature)
        );
        assert_eq!(receipt["intent"].as_str(), Some(route.intent));
        assert_eq!(receipt["fields"].as_u64(), Some(route.fields.len() as u64));
    }
    let refused_receipts = descriptor_manifest["refused_routes"]
        .as_array()
        .expect("refused routes");
    assert_eq!(refused_receipts.len(), 3);
    for signature in REFUSED {
        let receipt = refused_receipts
            .iter()
            .find(|candidate| candidate["canonical_signature"].as_str() == Some(signature))
            .unwrap_or_else(|| panic!("manifest lost refused route {signature}"));
        assert_eq!(
            required_str(receipt, "selector"),
            function_selector(signature)
        );
    }

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| entry.source == vendored_path)
        .collect();
    assert_eq!(
        entries.len(),
        15,
        "Aave descriptor must emit one leaf per unique deployment"
    );

    let descriptor_hash: [u8; 32] =
        decode_hex_text(required_str(descriptor_manifest, "descriptor_hash"))
            .try_into()
            .expect("descriptor hash width");
    let erc8176_hash: [u8; 32] = decode_hex_text(required_str(descriptor_manifest, "erc8176_hash"))
        .try_into()
        .expect("ERC-8176 hash width");
    let admitted_selectors = route_expectations
        .iter()
        .map(|route| {
            keccak256(route.signature.as_bytes())[..4]
                .try_into()
                .expect("selector width")
        })
        .collect::<BTreeSet<[u8; 4]>>();

    for entry in &entries {
        assert_eq!(entry.descriptor_hash, descriptor_hash);
        assert_eq!(entry.erc8176_hash, erc8176_hash);
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated Aave IR parses");
        let schema_v5_ir_bytes = descriptor_manifest["ir_bytes"].as_u64().unwrap() as usize;
        assert_eq!(
            schema_v5_ir_bytes, 1_134,
            "archived schema-v5 IR receipt drifted"
        );
        assert_eq!(
            entry.ir_bytes.len(),
            schema_v5_ir_bytes + ir.format_count().expect("Aave format count") as usize,
            "schema v6 adds exactly one string-preimage count byte to each format header"
        );
        assert_eq!(
            cross_check_contract(&ir, entry.chain_id, &entry.contract),
            Ok(())
        );
        assert_eq!(ir.owner, b"Aave DAO");
        assert_eq!(ir.contract_name, b"PoolInstance");
        assert_eq!(ir.format_count(), Ok(10));
        let formats = ir
            .format_iter()
            .map(|format| format.expect("Aave format parses"))
            .collect::<Vec<_>>();
        assert_eq!(formats.len(), 10);
        assert_eq!(
            formats
                .iter()
                .map(|format| format.selector)
                .collect::<BTreeSet<_>>(),
            admitted_selectors
        );

        let mut total_fields = 0usize;
        let mut threshold_fields = 0usize;
        let mut token_path_fields = 0usize;
        for route in &route_expectations {
            let selector: [u8; 4] = keccak256(route.signature.as_bytes())[..4]
                .try_into()
                .unwrap();
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Aave format table parses")
                .unwrap_or_else(|| panic!("missing admitted route {}", route.signature));
            assert_eq!(format.intent, route.intent.as_bytes());
            assert_eq!(u16::from(format.static_head_words), route.head_words);
            assert_eq!(format.nested_descent_count, 0);
            let fields = format
                .fields()
                .map(|field| field.expect("Aave field parses"))
                .collect::<Vec<_>>();
            assert_eq!(
                fields.len(),
                route.fields.len(),
                "field count: {}",
                route.signature
            );
            total_fields += fields.len();

            for (ordinal, (field, expected)) in fields.iter().zip(&route.fields).enumerate() {
                assert_eq!(
                    field.label,
                    expected.label.as_bytes(),
                    "{} field {ordinal} label",
                    route.signature
                );
                assert_eq!(
                    FormatOp::try_from(field.format_op),
                    Ok(expected.op),
                    "{} field {ordinal} op",
                    route.signature
                );
                let expected_path = match expected.path {
                    ExpectedPath::Structured(index) => vec![
                        PathOp::RootStructured as u8,
                        PathOp::FieldIdx as u8,
                        (index >> 8) as u8,
                        index as u8,
                    ],
                    ExpectedPath::Sender => {
                        let mut path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
                        path.extend_from_slice(&container_field::FROM.to_be_bytes());
                        path
                    }
                };
                assert_eq!(
                    ir.path_bytes(field.path_off).expect("field path"),
                    expected_path,
                    "{} field {ordinal} path",
                    route.signature
                );
                let params = parse_params(&ir, field.param_off).expect("field params parse");
                assert_eq!(params.visibility, Visibility::Always);
                assert_eq!(params.terminal_kind, Some(expected.terminal));
                assert_eq!(params.integer_width_bytes, expected.integer_width);
                let expected_token_path = expected.token_path.map(|index| {
                    vec![
                        PathOp::RootStructured as u8,
                        PathOp::FieldIdx as u8,
                        (index >> 8) as u8,
                        index as u8,
                    ]
                });
                assert_eq!(
                    params.token_path,
                    expected_token_path.as_deref(),
                    "{} field {ordinal} token path",
                    route.signature
                );
                assert_eq!(
                    params.threshold.copied(),
                    expected.threshold.then_some([0xff; 32]),
                    "{} field {ordinal} MAX threshold",
                    route.signature
                );
                assert_eq!(
                    params.message,
                    expected.message.map(str::as_bytes),
                    "{} field {ordinal} threshold wording",
                    route.signature
                );
                assert_eq!(params.addr_types, expected.addr_types);
                assert_eq!(params.addr_sources, expected.addr_sources);
                assert_eq!(params.enum_ref.is_some(), expected.has_enum);
                assert!(params.token.is_none());
                assert!(params.native_currency_addresses.is_none());
                assert!(params.sender_addresses.is_none());
                assert!(params.word_guard.is_none());
                if let Some(enum_off) = params.enum_ref {
                    for (value, label) in [
                        (0u64, b"none".as_slice()),
                        (1, b"deprecated".as_slice()),
                        (2, b"variable".as_slice()),
                    ] {
                        let mut word = [0u8; 32];
                        word[24..].copy_from_slice(&value.to_be_bytes());
                        assert_eq!(lookup_enum_label(ir.pool, enum_off, &word), Ok(Some(label)));
                    }
                }
                threshold_fields += usize::from(params.threshold.is_some());
                token_path_fields += usize::from(params.token_path.is_some());
            }
            assert!(registry
                .known_calls
                .contains(&(entry.chain_id, entry.contract, selector)));
            assert!(known_call_may_contain(
                &registry.known_calls_bloom,
                entry.chain_id,
                &entry.contract,
                &selector
            ));
        }
        assert_eq!(total_fields, 27);
        assert_eq!(
            threshold_fields, 3,
            "only repay, repayWithATokens, and withdraw use MAX"
        );
        assert_eq!(
            token_path_fields, 6,
            "all six token amounts bind signed asset word zero"
        );

        for signature in REFUSED {
            let selector: [u8; 4] = keccak256(signature.as_bytes())[..4].try_into().unwrap();
            assert!(
                ir.find_format_by_selector(&selector)
                    .expect("format table parses")
                    .is_none(),
                "refused route became clear-signable: {signature}"
            );
            assert!(
                registry
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, selector)),
                "refused route lost exact guard: {signature}"
            );
            assert!(
                known_call_may_contain(
                    &registry.known_calls_bloom,
                    entry.chain_id,
                    &entry.contract,
                    &selector
                ),
                "refused route lost Bloom guard: {signature}"
            );
        }
    }

    let ethereum_entry = entries
        .iter()
        .find(|entry| entry.chain_id == 1 && entry.contract == address(POOL_PROXY))
        .expect("evidenced Ethereum Pool leaf");
    assert_eq!(ethereum_entry.descriptor_hash, descriptor_hash);

    let expected = &manifest["expected_catalogue"];
    // This archived receipt is part of the historical Aave evidence and must
    // remain immutable even as later, independently reviewed descriptors move
    // the production catalogue root.
    assert_eq!(expected["entries"].as_u64(), Some(453));
    assert_eq!(
        required_str(expected, "root"),
        "0x48aac419f76889375e21dd7813b0abefafa02485a5d1f52e510d854d97192e96"
    );
    assert_eq!(expected["known_calls"].as_u64(), Some(4_552));
    assert_eq!(
        required_str(expected, "known_call_set_sha256"),
        "0x0bb0187224e44ff489d779af1564fa0c1148f03e9b9f27a82d5d0eebd81f13c9"
    );
    assert_eq!(
        required_str(expected, "known_call_bloom_sha256"),
        "efa6ab9408d73888d979e243de78ed558f809ebd6d04a71545df7f118260bade"
    );

    assert_eq!(
        registry.entries.len(),
        467,
        "current production catalogue leaf count drifted"
    );
    assert_eq!(
        registry.leaf_count, 467,
        "current production catalogue Merkle leaf count drifted"
    );
    assert_eq!(
        registry.blob.len(),
        404_904,
        "current production catalogue blob size drifted"
    );
    assert_eq!(
        hex::encode(registry.root),
        "01fc3633f39a453684445b87fbfd1b8d3b1063fe9824984508a890f3c949db21"
    );
    assert_eq!(
        registry.known_call_count, 4_580,
        "current exact known-call count drifted"
    );
    assert_eq!(
        hex::encode(registry.known_call_set_hash),
        "b67b0f2548231a5d4c9b54625c52854c7bb4da0e2ce84bedff24630682ccb829"
    );
    assert_eq!(
        sha256_hex(&registry.known_calls_bloom),
        "9466b4e65c129292578b5722d2e100630e7caca05f23c75acc3a5855345c99b9"
    );
}
