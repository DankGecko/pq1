//! Offline deployment, source, and semantic evidence for Layerswap funding.
//!
//! The admitted call only forwards signed funds to a signed receiver. It does
//! not execute or promise the later off-chain swap/bridge outcome.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::abi::container_field;
use pqsigner_erc7730::binding::{cross_check_contract, BindingError};
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, PathOp, Visibility};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BLOCK_NUMBER: u64 = 25_582_700;
const BLOCK_HASH: &str = "0xdb61c00eb37a578f0eae2918a5a0ca4ef276ef3eacd7d0df1d4a7b1bedf38631";
const STATE_ROOT: &str = "0x4dfb03c4196b479af7cce62a79339002b002910a420ec52ea44e8b69656e966c";
const ACCEPTED: &str = "0xE226E4825CB215aBaFAd98fdd400583eAb6a594f";
const TRANSCRIPTION_TYPO: &str = "0xE2260D5eF5d71467f0C1AacC3B6e5Ab6f6B8594f";
const DESCRIPTOR_RELATIVE: &str = "registry/layerswap/calldata-LayerswapDepository.json";
const OFFICIAL_COMMIT: &str = "a7a4ccd89f0fb5046f8d0053283da6e36c6b638c";
const OFFICIAL_TREE: &str = "23e6d14d7a81950582f49dcf93a528abac9223d0";
const SOURCE_SHA256: &str = "cec2f97ae17b70c76eddf12238995ef1bb6c7c791c4c8bedacb71fecad451bcb";
const RUNTIME_SHA256: &str = "8ebd4663a71c87b52791e9b9951fa63201e8ecb0734b2e97d109404e0ef19089";
const UPSTREAM_DESCRIPTOR_BYTES: u64 = 9_526;
const UPSTREAM_DESCRIPTOR_SHA256: &str =
    "b9cc03aebb3c30fc8b189345fb3f1416601d3ee6bc6af8f4fac09fb0ab06f13d";

const NATIVE: (&str, [u8; 4]) = ("depositNative(bytes32,address)", [0x80, 0xa6, 0xde, 0x92]);
const ERC20: (&str, [u8; 4]) = (
    "depositERC20(bytes32,address,address,uint256)",
    [0xf4, 0x37, 0x1f, 0x63],
);
const ALL_ROUTES: [(&str, [u8; 4]); 10] = [
    NATIVE,
    ERC20,
    ("addToWhitelist(address)", [0xe4, 0x32, 0x52, 0xd7]),
    ("removeFromWhitelist(address)", [0x8a, 0xb1, 0xd6, 0x81]),
    (
        "updateWhitelistedAddress(address,address)",
        [0x86, 0xd1, 0x10, 0x66],
    ),
    ("pause()", [0x84, 0x56, 0xcb, 0x59]),
    ("unpause()", [0x3f, 0x4b, 0xa8, 0x3a]),
    ("transferOwnership(address)", [0xf2, 0xfd, 0xe3, 0x8b]),
    ("acceptOwnership()", [0x79, 0xba, 0x50, 0x97]),
    ("renounceOwnership()", [0x71, 0x50, 0x18, 0xa6]),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/layerswap-depository-funding")
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

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid archived hex")
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn hex_quantity(value: &Value) -> u64 {
    let text = value.as_str().expect("hex quantity string");
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).expect("hex quantity")
}

fn collect_files(root: &Path, directory: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let entry = entry.expect("evidence directory entry");
        let path = entry.path();
        let ty = entry.file_type().expect("evidence file type");
        assert!(!ty.is_symlink(), "evidence may not contain symlinks");
        if ty.is_dir() {
            collect_files(root, &path, out);
        } else {
            assert!(
                ty.is_file(),
                "unsupported evidence entry: {}",
                path.display()
            );
            let relative = path
                .strip_prefix(root)
                .expect("evidence path stays under root")
                .to_str()
                .expect("UTF-8 evidence path")
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn rpc_results(path: &Path) -> BTreeMap<String, Value> {
    let mut results = BTreeMap::new();
    for item in read_json(path).as_array().expect("RPC response array") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(
            item.get("error").is_none() || item["error"].is_null(),
            "RPC response contains an error: {}",
            path.display()
        );
        let id = required_str(item, "id").to_owned();
        let result = item
            .get("result")
            .unwrap_or_else(|| panic!("missing result {id}"))
            .clone();
        assert!(results.insert(id, result).is_none(), "duplicate RPC id");
    }
    results
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments_in_order(text: &str, fragments: &[&str], context: &str) {
    let text = normalized(text);
    let mut cursor = 0usize;
    for fragment in fragments {
        let offset = text[cursor..]
            .find(fragment)
            .unwrap_or_else(|| panic!("{context} lost semantic fragment: {fragment}"));
        cursor += offset + fragment.len();
    }
}

struct SolidityFunction<'a> {
    header: &'a str,
    body: &'a str,
}

fn solidity_function<'a>(source: &'a str, name: &str) -> SolidityFunction<'a> {
    let needle = format!("function {name}(");
    let starts = source.match_indices(&needle).collect::<Vec<_>>();
    assert_eq!(starts.len(), 1, "expected one function {name}");
    let definition = &source[starts[0].0..];
    let opening = definition.find('{').expect("implemented Solidity function");
    assert!(!definition[..opening].contains(';'));
    let mut depth = 0usize;
    for (offset, byte) in definition[opening..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("balanced Solidity braces");
                if depth == 0 {
                    return SolidityFunction {
                        header: &definition[..opening],
                        body: &definition[opening..opening + offset + 1],
                    };
                }
            }
            _ => {}
        }
    }
    panic!("unterminated Solidity function {name}")
}

fn abi_signature(function: &Value) -> String {
    let name = required_str(function, "name");
    let types = function["inputs"]
        .as_array()
        .expect("ABI inputs")
        .iter()
        .map(|input| required_str(input, "type"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({types})")
}

fn structured_path(index: u16) -> Vec<u8> {
    vec![
        PathOp::RootStructured as u8,
        PathOp::FieldIdx as u8,
        (index >> 8) as u8,
        index as u8,
    ]
}

#[test]
fn layerswap_evidence_receipts_cover_every_offline_artifact() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["fixed_block"]["number"].as_u64(),
        Some(BLOCK_NUMBER)
    );
    assert_eq!(manifest["fixed_block"]["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(
        manifest["fixed_block"]["state_root"].as_str(),
        Some(STATE_ROOT)
    );
    assert_eq!(
        required_str(&manifest["contracts"], "accepted_deployment"),
        ACCEPTED
    );
    assert_eq!(
        required_str(&manifest["contracts"], "transcription_typo"),
        TRANSCRIPTION_TYPO
    );

    for (route, (signature, selector)) in manifest["routes"]
        .as_array()
        .expect("route receipts")
        .iter()
        .zip([NATIVE, ERC20])
    {
        assert_eq!(required_str(route, "canonical_signature"), signature);
        assert_eq!(
            required_str(route, "selector"),
            format!("0x{}", hex::encode(selector))
        );
        assert_eq!(&keccak256(signature.as_bytes())[..4], &selector);
    }

    let boundary = required_str(&manifest, "boundary");
    for residual in [
        "does not sign or guarantee an off-chain swap",
        "destination asset",
        "output",
        "fulfillment",
        "success",
    ] {
        assert!(boundary.contains(residual), "lost boundary: {residual}");
    }
    assert!(required_str(&manifest["semantics"], "wording_decision")
        .contains("Swap wording overpromised an off-chain outcome"));

    let mut declared = BTreeSet::new();
    for artifact in manifest["artifacts"].as_array().expect("artifact receipts") {
        let relative = required_str(artifact, "path");
        assert!(declared.insert(relative.to_owned()), "duplicate receipt");
        let bytes = fs::read(evidence.join(relative)).expect("read receipted evidence");
        assert_eq!(
            sha256_hex(&bytes),
            required_str(artifact, "sha256"),
            "archived evidence drifted: {relative}"
        );
    }
    let mut actual = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut actual);
    assert_eq!(actual, declared, "every non-manifest artifact is receipted");
}

#[test]
fn three_fixed_block_providers_bind_the_deployment_and_reject_the_typo() {
    let evidence = evidence_root();
    let request = read_json(&evidence.join("rpc/request.json"));
    let requests = request.as_array().expect("RPC request array");
    assert_eq!(requests.len(), 4);
    for item in requests {
        if item["method"] == "eth_getCode" {
            let block = &item["params"][1];
            assert_eq!(block["blockHash"].as_str(), Some(BLOCK_HASH));
            assert_eq!(block["requireCanonical"].as_bool(), Some(true));
            assert_eq!(block.as_object().expect("EIP-1898 block").len(), 2);
        }
    }

    let providers = ["mevblocker", "tenderly", "flashbots"];
    let mut reference: Option<BTreeMap<String, Value>> = None;
    for provider in providers {
        let results = rpc_results(&evidence.join(format!("rpc/response-{provider}.json")));
        assert_eq!(results.len(), 4);
        assert_eq!(results["chain-id"], "0x1");
        assert_eq!(results["transcription-typo-runtime"], "0x");
        let block = &results["block"];
        assert_eq!(hex_quantity(&block["number"]), BLOCK_NUMBER);
        assert_eq!(block["hash"].as_str(), Some(BLOCK_HASH));
        assert_eq!(block["stateRoot"].as_str(), Some(STATE_ROOT));
        let runtime = decode_hex(results["accepted-runtime"].as_str().expect("runtime hex"));
        assert_eq!(runtime.len(), 3_876);
        assert_eq!(sha256_hex(&runtime), RUNTIME_SHA256);
        if let Some(expected) = &reference {
            assert_eq!(&results, expected, "provider disagreement at fixed block");
        } else {
            reference = Some(results);
        }
    }

    let runtime = read_hex(&evidence.join("runtime/LayerswapDepository.ethereum-mainnet.hex"));
    assert_eq!(runtime.len(), 3_876);
    assert_eq!(sha256_hex(&runtime), RUNTIME_SHA256);
}

#[test]
fn verified_source_official_source_and_exact_compiler_bind_the_runtime() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let record = read_json(&evidence.join("blockscout/LayerswapDepository.json"));
    let runtime = read_hex(&evidence.join("runtime/LayerswapDepository.ethereum-mainnet.hex"));

    assert_eq!(record["is_verified"].as_bool(), Some(true));
    assert_eq!(record["is_fully_verified"].as_bool(), Some(true));
    assert_eq!(record["is_changed_bytecode"].as_bool(), Some(false));
    assert_eq!(record["proxy_type"], Value::Null);
    assert_eq!(record["implementations"], json!([]));
    assert_eq!(record["compiler_version"], "v0.8.29+commit.ab55807c");
    assert_eq!(record["evm_version"], "prague");
    assert_eq!(record["optimization_enabled"].as_bool(), Some(true));
    assert_eq!(record["optimization_runs"].as_u64(), Some(200));
    assert_eq!(
        decode_hex(required_str(&record, "deployed_bytecode")),
        runtime
    );

    let official =
        fs::read(evidence.join("official/src/LayerswapDepository.sol")).expect("official source");
    let verified = fs::read(evidence.join("source/verified/src/LayerswapDepository.sol"))
        .expect("verified primary source");
    assert_eq!(official, verified, "official and verified source differ");
    assert_eq!(sha256_hex(&official), SOURCE_SHA256);
    assert_eq!(
        required_str(&manifest["official_source"], "primary_sha256"),
        SOURCE_SHA256
    );

    let commit = read_json(&evidence.join("official/github-git-commit.json"));
    assert_eq!(required_str(&commit, "sha"), OFFICIAL_COMMIT);
    assert_eq!(required_str(&commit["tree"], "sha"), OFFICIAL_TREE);

    let mut verified_sources = BTreeMap::new();
    verified_sources.insert(
        required_str(&record, "file_path").to_owned(),
        required_str(&record, "source_code").to_owned(),
    );
    for source in record["additional_sources"]
        .as_array()
        .expect("verified dependency sources")
    {
        assert!(
            verified_sources
                .insert(
                    required_str(source, "file_path").to_owned(),
                    required_str(source, "source_code").to_owned(),
                )
                .is_none(),
            "duplicate verified source"
        );
    }
    assert_eq!(verified_sources.len(), 20);
    for (path, source) in &verified_sources {
        assert!(!path.starts_with('/') && !path.split('/').any(|part| part == ".."));
        assert_eq!(
            fs::read(evidence.join("source/verified").join(path)).expect("extracted source"),
            source.as_bytes(),
            "verified source extraction drifted: {path}"
        );
    }

    let compiler = read_json(&evidence.join("compiler/LayerswapDepository.standard-output.json"));
    assert!(compiler["errors"].as_array().map_or(true, |errors| errors
        .iter()
        .all(|error| error["severity"] != "error")));
    let rebuilt = decode_hex(
        compiler["contracts"]["src/LayerswapDepository.sol"]["LayerswapDepository"]["evm"]
            ["deployedBytecode"]["object"]
            .as_str()
            .expect("compiled runtime"),
    );
    assert_eq!(
        rebuilt, runtime,
        "exact compiler no longer rebuilds runtime"
    );

    let abi = read_json(&evidence.join("abi/LayerswapDepository.deposit-routes.abi.json"));
    let signatures = abi
        .as_array()
        .expect("route ABI")
        .iter()
        .map(abi_signature)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        signatures,
        [NATIVE.0.to_owned(), ERC20.0.to_owned()]
            .into_iter()
            .collect()
    );

    let source = String::from_utf8(official).expect("Solidity source UTF-8");
    let native = solidity_function(&source, "depositNative");
    assert_fragments_in_order(
        native.header,
        &["external", "payable", "nonReentrant", "whenNotPaused"],
        "depositNative header",
    );
    assert_fragments_in_order(
        native.body,
        &[
            "if (!_whitelist.contains(receiver)) revert NotWhitelisted();",
            "if (msg.value == 0) revert ZeroAmount();",
            "emit Deposited(id, address(0), receiver, msg.value);",
            "(bool success,) = receiver.call{value: msg.value}(\"\");",
            "if (!success) revert TransferFailed();",
        ],
        "depositNative body",
    );

    let erc20 = solidity_function(&source, "depositERC20");
    assert_fragments_in_order(
        erc20.header,
        &["external", "nonReentrant", "whenNotPaused"],
        "depositERC20 header",
    );
    assert_fragments_in_order(
        erc20.body,
        &[
            "if (token == address(0)) revert ZeroAddress();",
            "if (!_whitelist.contains(receiver)) revert NotWhitelisted();",
            "if (amount == 0) revert ZeroAmount();",
            "uint256 balBefore = IERC20(token).balanceOf(receiver);",
            "IERC20(token).safeTransferFrom(msg.sender, receiver, amount);",
            "uint256 received = IERC20(token).balanceOf(receiver) - balBefore;",
            "emit Deposited(id, token, receiver, received);",
        ],
        "depositERC20 body",
    );
    assert!(!native.body.contains("swap("));
    assert!(!erc20.body.contains("swap("));

    let readme = fs::read_to_string(evidence.join("official/README.md")).expect("official README");
    assert_fragments_in_order(
        &readme,
        &[
            "forwards native and ERC20 tokens to whitelisted Layerswap receiver addresses",
            "backend picks up event",
            "fulfills the order on dst chain",
        ],
        "official outcome boundary",
    );
}

#[test]
fn curated_leaf_is_operand_complete_and_every_other_declared_tuple_stays_known() {
    let root = workspace_root();
    let vendored = root
        .join("secure/data/erc7730-registry")
        .join(DESCRIPTOR_RELATIVE);
    let overlay = root
        .join("secure/data/erc7730/curations/files")
        .join(DESCRIPTOR_RELATIVE);
    let vendored_bytes = fs::read(&vendored).expect("vendored Layerswap descriptor");
    let overlay_bytes = fs::read(&overlay).expect("Layerswap curation overlay");
    assert_eq!(vendored_bytes, overlay_bytes);

    let curation = read_json(&root.join("secure/data/erc7730/curations/manifest.json"));
    let replacement = curation["replacements"]
        .as_array()
        .expect("curation replacements")
        .iter()
        .find(|entry| entry["path"].as_str() == Some(DESCRIPTOR_RELATIVE))
        .expect("Layerswap replacement receipt");
    assert_eq!(
        replacement["upstream_bytes"].as_u64(),
        Some(UPSTREAM_DESCRIPTOR_BYTES)
    );
    assert_eq!(
        required_str(replacement, "upstream_sha256"),
        UPSTREAM_DESCRIPTOR_SHA256
    );
    assert_eq!(
        replacement["replacement_bytes"].as_u64(),
        Some(vendored_bytes.len() as u64)
    );
    assert_eq!(
        required_str(replacement, "replacement_sha256"),
        sha256_hex(&vendored_bytes)
    );

    let descriptor: Value = serde_json::from_slice(&vendored_bytes).expect("descriptor JSON");
    let admission = &descriptor["_pqsigner"]["deploymentFormats"];
    assert_eq!(admission.as_array().expect("deployment allowlist").len(), 1);
    assert_eq!(admission[0]["chainId"].as_u64(), Some(1));
    assert_eq!(admission[0]["address"].as_str(), Some(ACCEPTED));
    assert_eq!(
        admission[0]["formats"],
        json!([
            "depositNative(bytes32 id,address receiver)",
            "depositERC20(bytes32 id,address token,address receiver,uint256 amount)"
        ])
    );

    let formats = &descriptor["display"]["formats"];
    let native = &formats["depositNative(bytes32 id,address receiver)"];
    assert_eq!(native["intent"], "Forward ETH");
    assert_eq!(native["interpolatedIntent"], "Forward {@.value}");
    assert_eq!(
        native["fields"]
            .as_array()
            .expect("native fields")
            .iter()
            .map(|field| required_str(field, "label"))
            .collect::<Vec<_>>(),
        ["Reference ID", "Receiver", "ETH amount"]
    );
    let erc20 = &formats["depositERC20(bytes32 id,address token,address receiver,uint256 amount)"];
    assert_eq!(erc20["intent"], "Forward token");
    assert!(erc20.get("interpolatedIntent").is_none());
    assert_eq!(
        erc20["fields"]
            .as_array()
            .expect("ERC20 fields")
            .iter()
            .map(|field| required_str(field, "label"))
            .collect::<Vec<_>>(),
        [
            "Reference ID",
            "Token contract",
            "Receiver",
            "Requested amount"
        ]
    );
    for field in native["fields"]
        .as_array()
        .unwrap()
        .iter()
        .chain(erc20["fields"].as_array().unwrap())
    {
        assert_eq!(field["visible"], "always");
    }

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20_capabilities = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20_capabilities.capabilities,
    )
    .expect("build production registry");

    let entries = registry
        .entries
        .iter()
        .filter(|entry| entry.source == vendored)
        .collect::<Vec<_>>();
    assert_eq!(
        entries.len(),
        1,
        "only the evidenced Ethereum deployment emits a leaf"
    );
    let entry = entries[0];
    assert_eq!(entry.chain_id, 1);
    assert_eq!(entry.contract, address(ACCEPTED));
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("Layerswap IR parses");
    assert_eq!(cross_check_contract(&ir, 1, &address(ACCEPTED)), Ok(()));
    assert_eq!(ir.format_count(), Ok(2));
    assert_eq!(ir.owner, b"Layerswap");
    // The fixed IR header intentionally stores at most 15 printable bytes.
    assert_eq!(ir.contract_name, b"LayerswapDeposi");

    let native_ir = ir
        .find_format_by_selector(&NATIVE.1)
        .expect("format table parses")
        .expect("native route admitted");
    assert_eq!(native_ir.intent, b"Forward ETH");
    let native_fields = native_ir
        .fields()
        .map(|field| field.expect("native field parses"))
        .collect::<Vec<_>>();
    assert_eq!(native_fields.len(), 3);
    for (index, (field, (label, op, path))) in native_fields
        .iter()
        .zip([
            ("Reference ID", FormatOp::Raw, structured_path(0)),
            ("Receiver", FormatOp::AddressName, structured_path(1)),
            ("ETH amount", FormatOp::Amount, {
                let mut path = vec![PathOp::RootContainer as u8, PathOp::FieldIdx as u8];
                path.extend_from_slice(&container_field::VALUE.to_be_bytes());
                path
            }),
        ])
        .enumerate()
    {
        assert_eq!(field.label, label.as_bytes(), "native field {index} label");
        assert_eq!(FormatOp::try_from(field.format_op), Ok(op));
        assert_eq!(ir.path_bytes(field.path_off).unwrap(), path);
        assert_eq!(
            parse_params(&ir, field.param_off).unwrap().visibility,
            Visibility::Always
        );
    }
    // Container-value interpolation is outside the deliberately bounded
    // scalar-calldata subset. The signed ETH value remains an always-visible
    // field and the device authenticates the honest static intent.
    for field in &native_fields {
        assert!(parse_params(&ir, field.param_off)
            .unwrap()
            .interpolated_intent
            .is_none());
    }

    let erc20_ir = ir
        .find_format_by_selector(&ERC20.1)
        .expect("format table parses")
        .expect("ERC20 route admitted");
    assert_eq!(erc20_ir.intent, b"Forward token");
    let erc20_fields = erc20_ir
        .fields()
        .map(|field| field.expect("ERC20 field parses"))
        .collect::<Vec<_>>();
    assert_eq!(erc20_fields.len(), 4);
    for (index, (field, (label, op, path))) in erc20_fields
        .iter()
        .zip([
            ("Reference ID", FormatOp::Raw, structured_path(0)),
            ("Token contract", FormatOp::AddressName, structured_path(1)),
            ("Receiver", FormatOp::AddressName, structured_path(2)),
            (
                "Requested amount",
                FormatOp::TokenAmount,
                structured_path(3),
            ),
        ])
        .enumerate()
    {
        assert_eq!(field.label, label.as_bytes(), "ERC20 field {index} label");
        assert_eq!(FormatOp::try_from(field.format_op), Ok(op));
        assert_eq!(ir.path_bytes(field.path_off).unwrap(), path);
        let params = parse_params(&ir, field.param_off).unwrap();
        assert_eq!(params.visibility, Visibility::Always);
        assert!(params.interpolated_intent.is_none());
    }
    assert_eq!(
        parse_params(&ir, erc20_fields[3].param_off)
            .unwrap()
            .token_path,
        Some(structured_path(1).as_slice())
    );

    for (signature, selector) in ALL_ROUTES {
        assert_eq!(&keccak256(signature.as_bytes())[..4], &selector);
        let format = ir
            .find_format_by_selector(&selector)
            .expect("format table parses");
        assert_eq!(
            format.is_some(),
            selector == NATIVE.1 || selector == ERC20.1
        );
    }
    let mut wrong_contract = address(ACCEPTED);
    wrong_contract[19] ^= 1;
    assert_eq!(
        cross_check_contract(&ir, 1, &wrong_contract),
        Err(BindingError::ContractMismatch)
    );

    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 56);
    for deployment in deployments {
        let chain_id = deployment["chainId"].as_u64().expect("deployment chain");
        let contract = address(required_str(deployment, "address"));
        for (_, selector) in ALL_ROUTES {
            assert!(
                registry.known_calls.contains(&(chain_id, contract, selector)),
                "registry-declared Layerswap tuple must stay exact-known: chain={chain_id} contract=0x{} selector=0x{}",
                hex::encode(contract),
                hex::encode(selector)
            );
            assert!(known_call_may_contain(
                &registry.known_calls_bloom,
                chain_id,
                &contract,
                &selector
            ));
        }
    }
}
