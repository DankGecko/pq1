//! Offline provenance and admission checks for Celo LockedGold/LockedCelo.
//!
//! The upstream mainnet binding names the implementation instead of the
//! Registry-selected proxy, while Alfajores names a legacy deployment for
//! which this package has no live-state authority. The curated descriptor adds
//! the evidence-bound mainnet proxy and admits all six static routes only at
//! that identity. Authenticated deployment/format narrowing leaves the two
//! upstream targets in exact omission protection with no trusted leaf.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Map;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DESCRIPTOR_RELATIVE: &str = "registry/celo/calldata-locked_celo.json";
const MAINNET_PROXY: &str = "6cc083aed9e3ebe302a6336dbc7c921c9f03349e";
const STALE_DEPLOYMENTS: [(u64, &str); 2] = [
    (42_220, "55e1a0c8f376964bd339167476063bfed7f213d5"),
    (44_787, "6a4cc5693dc5bfa3799c699f3b941ba2cb00c341"),
];
const ALL_DEPLOYMENTS: [(u64, &str); 3] = [
    (42_220, "55e1a0c8f376964bd339167476063bfed7f213d5"),
    (42_220, MAINNET_PROXY),
    (44_787, "6a4cc5693dc5bfa3799c699f3b941ba2cb00c341"),
];
const ROUTES: [(&str, &str); 6] = [
    (
        "delegateGovernanceVotes(address,uint256)",
        "delegateFraction",
    ),
    ("lock()", "@.value"),
    ("relock(uint256,uint256)", "index"),
    (
        "revokeDelegatedGovernanceVotes(address,uint256)",
        "revokeFraction",
    ),
    ("unlock(uint256)", "value"),
    ("withdraw(uint256)", "index"),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/celo-lockedcelo-quarantine")
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
        .unwrap_or_else(|| panic!("manifest field {key} is a string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn decode_hex_text(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid hex evidence")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex_text(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn address(text: &str) -> [u8; 20] {
    decode_hex_text(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn abi_word_address(text: &str) -> [u8; 20] {
    let word = decode_hex_text(text);
    assert_eq!(word.len(), 32, "ABI address result is one word");
    assert_eq!(&word[..12], &[0u8; 12], "ABI address padding changed");
    word[12..].try_into().expect("address word width")
}

fn canonicalize_signature(authored: &str) -> String {
    let (name, tail) = authored.split_once('(').expect("authored signature opens");
    let params = tail.strip_suffix(')').expect("authored signature closes");
    let types = params
        .split(',')
        .filter(|param| !param.trim().is_empty())
        .map(|param| {
            param
                .split_ascii_whitespace()
                .next()
                .expect("parameter type")
        })
        .collect::<Vec<_>>();
    format!("{name}({})", types.join(","))
}

fn object_containing_path<'a>(value: &'a Value, path: &str) -> Option<&'a Map<String, Value>> {
    match value {
        Value::Object(object) => {
            if object
                .values()
                .any(|candidate| candidate.as_str() == Some(path))
            {
                return Some(object);
            }
            object
                .values()
                .find_map(|candidate| object_containing_path(candidate, path))
        }
        Value::Array(array) => array
            .iter()
            .find_map(|candidate| object_containing_path(candidate, path)),
        _ => None,
    }
}

fn assert_manifest_file_hash(evidence: &Path, manifest: &Value, relative: &str) -> Vec<u8> {
    let artifact = object_containing_path(manifest, relative)
        .unwrap_or_else(|| panic!("manifest does not receipt {relative}"));
    let expected = ["file_sha256", "archive_file_sha256", "sha256"]
        .iter()
        .find_map(|key| artifact.get(*key).and_then(Value::as_str))
        .unwrap_or_else(|| panic!("manifest artifact {relative} has no file SHA-256"));
    let bytes = fs::read(evidence.join(relative))
        .unwrap_or_else(|error| panic!("read evidence {relative}: {error}"));
    assert_eq!(
        sha256_hex(&bytes),
        expected,
        "archived evidence drifted: {relative}"
    );
    bytes
}

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn hex_u64(text: &str) -> u64 {
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).expect("hex quantity")
}

fn registry_calldata(key: &str) -> String {
    let mut encoded = Vec::with_capacity(4 + 96);
    encoded.extend_from_slice(&keccak256(b"getAddressForString(string)")[..4]);
    let mut word = [0u8; 32];
    word[31] = 32;
    encoded.extend_from_slice(&word);
    word[31] = u8::try_from(key.len()).expect("short Registry key");
    encoded.extend_from_slice(&word);
    encoded.extend_from_slice(key.as_bytes());
    let padded_key_len = key.len().div_ceil(32) * 32;
    encoded.resize(4 + 64 + padded_key_len, 0);
    format!("0x{}", hex::encode(encoded))
}

fn assert_eip1898_tag(tag: &Value, block_hash: &str) {
    assert_eq!(tag["blockHash"].as_str(), Some(block_hash));
    assert_eq!(tag["requireCanonical"].as_bool(), Some(true));
    assert_eq!(tag.as_object().expect("EIP-1898 object").len(), 2);
}

fn markdown_contract_address(document: &str, contract: &str) -> [u8; 20] {
    let row = document
        .lines()
        .find(|line| line.split('|').nth(1).map(str::trim) == Some(contract))
        .unwrap_or_else(|| panic!("missing current core-contract row {contract}"));
    let encoded = row
        .split('`')
        .nth(1)
        .unwrap_or_else(|| panic!("missing address in core-contract row {contract}"));
    address(encoded)
}

fn python_dict_address(document: &str, dictionary: &str, contract: &str) -> [u8; 20] {
    let start_marker = format!("{dictionary} = {{");
    let section = document
        .split_once(&start_marker)
        .unwrap_or_else(|| panic!("missing Python dictionary {dictionary}"))
        .1
        .split_once('}')
        .expect("closed Python address dictionary")
        .0;
    let key_marker = format!("\"{contract}\":");
    let row = section
        .lines()
        .find(|line| line.trim_start().starts_with(&key_marker))
        .unwrap_or_else(|| panic!("missing {contract} in {dictionary}"));
    let encoded = row
        .split('"')
        .nth(3)
        .unwrap_or_else(|| panic!("missing address for {contract} in {dictionary}"));
    address(encoded)
}

#[test]
fn canonical_proxy_emits_one_leaf_while_stale_bindings_stay_fail_closed() {
    let root = workspace_root();
    let curated_path = root
        .join("secure/data/erc7730/curations/files")
        .join(DESCRIPTOR_RELATIVE);
    let vendored_path = root
        .join("secure/data/erc7730-registry")
        .join(DESCRIPTOR_RELATIVE);
    let curated = fs::read(&curated_path).expect("read curated LockedCelo descriptor");
    let vendored = fs::read(&vendored_path).expect("read vendored LockedCelo descriptor");
    assert_eq!(
        curated, vendored,
        "curated and production LockedCelo descriptors diverged"
    );

    let curation_manifest = read_json(&root.join("secure/data/erc7730/curations/manifest.json"));
    let replacement = curation_manifest["replacements"]
        .as_array()
        .expect("curation replacement array")
        .iter()
        .find(|replacement| replacement["path"].as_str() == Some(DESCRIPTOR_RELATIVE))
        .expect("LockedCelo replacement is receipted");
    assert_eq!(
        sha256_hex(&curated),
        required_str(replacement, "replacement_sha256"),
        "curation manifest no longer authenticates LockedCelo"
    );
    assert_ne!(
        required_str(replacement, "upstream_sha256"),
        required_str(replacement, "replacement_sha256"),
        "quarantine must remain an explicit full-file replacement"
    );

    let descriptor: Value =
        serde_json::from_slice(&curated).expect("parse curated LockedCelo descriptor");
    let descriptor_deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("LockedCelo deployment array")
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"].as_u64().expect("chain id"),
                deployment["address"]
                    .as_str()
                    .expect("deployment address")
                    .trim_start_matches("0x")
                    .to_ascii_lowercase(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        descriptor_deployments,
        ALL_DEPLOYMENTS
            .iter()
            .map(|(chain_id, contract)| (*chain_id, (*contract).to_owned()))
            .collect()
    );

    let formats = descriptor["display"]["formats"]
        .as_object()
        .expect("LockedCelo formats");
    let formats_by_signature = formats
        .iter()
        .map(|(authored, format)| (canonicalize_signature(authored), format))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        formats_by_signature
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        ROUTES
            .iter()
            .map(|(signature, _)| (*signature).to_owned())
            .collect(),
        "the curated descriptor must cover exactly the six verified LockedGold calls"
    );
    let admissions = descriptor["_pqsigner"]["deploymentFormats"]
        .as_array()
        .expect("authenticated deployment/format admissions");
    assert_eq!(admissions.len(), 1, "one exact proxy authority boundary");
    assert_eq!(admissions[0]["chainId"].as_u64(), Some(42_220));
    assert_eq!(
        address(required_str(&admissions[0], "address")),
        address(MAINNET_PROXY)
    );
    let admitted_formats = admissions[0]["formats"]
        .as_array()
        .expect("admitted format array")
        .iter()
        .map(|format| canonicalize_signature(format.as_str().expect("format signature")))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        admitted_formats,
        ROUTES
            .iter()
            .map(|(signature, _)| (*signature).to_owned())
            .collect(),
        "the proxy admission must select all and only the six verified routes"
    );

    for (signature, required_visible_path) in ROUTES {
        let fields = formats_by_signature[signature]["fields"]
            .as_array()
            .expect("LockedCelo fields");
        assert!(
            fields
                .iter()
                .all(|field| field["visible"].as_str() == Some("always")),
            "{signature} may not hide any signed operand"
        );
        assert!(
            fields.iter().any(|field| {
                field["path"].as_str() == Some(required_visible_path)
                    && field["visible"].as_str() == Some("always")
            }),
            "{signature} lost the previously hidden signed path {required_visible_path}"
        );
    }

    let proxy_additions = curation_manifest["known_call_additions"]
        .as_array()
        .expect("known-call additions")
        .iter()
        .filter(|addition| {
            addition["chain_id"].as_u64() == Some(42_220)
                && address(required_str(addition, "contract")) == address(MAINNET_PROXY)
        })
        .map(|addition| required_str(addition, "selector").to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        proxy_additions,
        ROUTES
            .iter()
            .map(|(signature, _)| {
                format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
            })
            .collect(),
        "the curation manifest must authorize exactly the six new proxy tuples"
    );

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, skips) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");

    let locked_entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| entry.source == vendored_path)
        .collect();
    assert_eq!(
        locked_entries.len(),
        1,
        "authenticated narrowing must emit exactly one canonical proxy leaf"
    );
    let proxy_entry = locked_entries[0];
    assert_eq!(proxy_entry.chain_id, 42_220);
    assert_eq!(proxy_entry.contract, address(MAINNET_PROXY));
    assert_eq!(
        hex::encode(proxy_entry.descriptor_hash),
        "e570e3b60c310caa32abd6ceca95ac64a61e286659798748be71fd381e23816d",
        "reviewed JCS descriptor identity drifted"
    );
    let ir = Erc7730Ir::parse(&proxy_entry.ir_bytes).expect("canonical Celo IR parses");
    assert_eq!(ir.format_count(), Ok(6));
    for (signature, _) in ROUTES {
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        assert!(
            ir.find_format_by_selector(&selector)
                .expect("format table")
                .is_some(),
            "proxy IR lost {signature}"
        );
    }
    for (chain_id, contract_text) in STALE_DEPLOYMENTS {
        assert!(
            !locked_entries.iter().any(|entry| {
                entry.chain_id == chain_id && entry.contract == address(contract_text)
            }),
            "stale deployment unexpectedly emitted a trusted leaf"
        );
    }

    for (chain_id, contract_text) in ALL_DEPLOYMENTS {
        let contract = address(contract_text);
        for (signature, _) in ROUTES {
            let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width");
            assert!(
                registry
                    .known_calls
                    .contains(&(chain_id, contract, selector)),
                "missing exact known-call guard for chain {chain_id} {signature}"
            );
            assert!(
                known_call_may_contain(&registry.known_calls_bloom, chain_id, &contract, &selector,),
                "missing Bloom guard for chain {chain_id} {signature}"
            );
        }
    }

    let locked_skips: Vec<_> = skips
        .iter()
        .filter(|skip| skip.source == vendored_path)
        .collect();
    assert_eq!(
        locked_skips.len(),
        STALE_DEPLOYMENTS.len(),
        "each stale deployment needs one explicit narrowing receipt"
    );
    for (chain_id, contract_text) in STALE_DEPLOYMENTS {
        let needle = format!(
            "PARTIAL FORMAT DROP: deployment chain_id={chain_id} contract=0x{contract_text} excluded by the authenticated PQSigner deploymentFormats allowlist"
        );
        assert!(
            locked_skips.iter().any(|skip| skip.reason == needle),
            "missing exact stale-deployment receipt: {needle}"
        );
    }
}

#[test]
fn lockedcelo_evidence_binds_the_canonical_proxy_to_runtime_source_and_rpc() {
    let root = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["policy"]["outcome"].as_str(),
        Some("canonical_proxy_only_admission")
    );
    let admitted_deployment = &manifest["policy"]["admitted_deployment"];
    assert_eq!(admitted_deployment["chain_id"].as_u64(), Some(42_220));
    assert_eq!(
        address(required_str(admitted_deployment, "address")),
        address(MAINNET_PROXY)
    );
    assert_eq!(
        required_str(admitted_deployment, "descriptor_hash"),
        "0xe570e3b60c310caa32abd6ceca95ac64a61e286659798748be71fd381e23816d"
    );
    let stale_manifest_deployments = manifest["policy"]["stale_deployments"]
        .as_array()
        .expect("stale deployment array")
        .iter()
        .map(|deployment| {
            (
                deployment["chain_id"].as_u64().expect("stale chain id"),
                address(required_str(deployment, "address")),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        stale_manifest_deployments,
        STALE_DEPLOYMENTS
            .iter()
            .map(|(chain_id, contract)| (*chain_id, address(contract)))
            .collect()
    );

    let admitted_routes = manifest["policy"]["admitted_routes"]
        .as_array()
        .expect("admitted route array");
    assert_eq!(admitted_routes.len(), ROUTES.len());
    let manifest_routes = admitted_routes
        .iter()
        .map(|route| {
            let signature = required_str(route, "canonical_signature");
            let expected_selector =
                format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]));
            assert_eq!(required_str(route, "selector"), expected_selector);
            signature.to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        manifest_routes,
        ROUTES
            .iter()
            .map(|(signature, _)| (*signature).to_owned())
            .collect()
    );

    let descriptor = &manifest["descriptor"];
    let claimed_deployments = descriptor["claimed_deployments"]
        .as_array()
        .expect("claimed deployment array");
    assert_eq!(claimed_deployments.len(), 2);
    let claimed_mainnet = required_str(&claimed_deployments[0], "address");
    let mainnet = &manifest["celo_mainnet"];
    let actual_mainnet = required_str(mainnet, "resolved_proxy");
    assert_eq!(address(claimed_mainnet), address(STALE_DEPLOYMENTS[0].1));
    assert_eq!(address(actual_mainnet), address(MAINNET_PROXY));
    assert_ne!(address(claimed_mainnet), address(actual_mainnet));

    assert_eq!(mainnet["chain_id"].as_u64(), Some(42_220));
    assert_eq!(
        address(required_str(mainnet, "registry_address")),
        address("000000000000000000000000000000000000ce10")
    );
    assert_eq!(
        address(required_str(mainnet, "resolved_proxy")),
        address(actual_mainnet)
    );
    assert_eq!(
        address(required_str(mainnet, "resolved_implementation")),
        address(claimed_mainnet),
        "the upstream descriptor names the implementation, not the Registry-selected proxy"
    );
    assert_eq!(
        address(required_str(mainnet, "upstream_descriptor_target")),
        address(claimed_mainnet)
    );
    assert_eq!(
        address(required_str(mainnet, "curated_descriptor_target")),
        address(actual_mainnet)
    );
    assert_eq!(
        required_str(mainnet, "eip1967_implementation_slot"),
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    );

    let residual = &manifest["testnet_residual"];
    assert_eq!(residual["chain_id"].as_u64(), Some(44_787));
    assert_eq!(
        address(required_str(residual, "descriptor_address")),
        address(STALE_DEPLOYMENTS[1].1)
    );

    let rpc_bytes = assert_manifest_file_hash(&evidence, &manifest, "rpc/fixed-block-receipt.json");
    let rpc: Value = serde_json::from_slice(&rpc_bytes).expect("parse fixed-block RPC receipt");
    assert_eq!(rpc["chain_id"].as_u64(), Some(42_220));
    assert_eq!(rpc["block"], mainnet["fixed_block"]);

    let request_receipts = mainnet["rpc_receipt"]["request_batches"]
        .as_array()
        .expect("raw RPC request receipts");
    assert_eq!(request_receipts.len(), 3);
    assert_eq!(
        request_receipts
            .iter()
            .map(|receipt| required_str(receipt, "path"))
            .collect::<BTreeSet<_>>(),
        rpc["request_files"]
            .as_array()
            .expect("fixed-block request files")
            .iter()
            .map(|path| path.as_str().expect("fixed-block request path"))
            .collect()
    );
    let mut requests = BTreeMap::<String, Value>::new();
    for receipt in request_receipts {
        let path = required_str(receipt, "path");
        let bytes = assert_manifest_file_hash(&evidence, &manifest, path);
        let batch: Value = serde_json::from_slice(&bytes).expect("parse raw RPC request batch");
        for request in batch.as_array().expect("raw request batch array") {
            assert_eq!(request["jsonrpc"].as_str(), Some("2.0"));
            let id = request["id"]
                .as_str()
                .expect("string request id")
                .to_owned();
            assert!(
                requests.insert(id.clone(), request.clone()).is_none(),
                "duplicate raw request id {id}"
            );
        }
    }
    let expected_ids = [
        "chain-id",
        "block",
        "locked-gold",
        "locked-celo",
        "implementation-slot",
        "proxy-code",
        "implementation-code",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        requests.keys().cloned().collect::<BTreeSet<_>>(),
        expected_ids
    );

    let block_hash = required_str(&mainnet["fixed_block"], "hash");
    assert_eq!(requests["chain-id"]["method"].as_str(), Some("eth_chainId"));
    assert_eq!(
        requests["chain-id"]["params"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        requests["block"]["method"].as_str(),
        Some("eth_getBlockByHash")
    );
    assert_eq!(requests["block"]["params"][0].as_str(), Some(block_hash));
    assert_eq!(requests["block"]["params"][1].as_bool(), Some(false));
    for (id, key) in [("locked-gold", "LockedGold"), ("locked-celo", "LockedCelo")] {
        let request = &requests[id];
        assert_eq!(request["method"].as_str(), Some("eth_call"));
        assert_eq!(
            address(required_str(&request["params"][0], "to")),
            address(required_str(mainnet, "registry_address"))
        );
        assert_eq!(
            required_str(&request["params"][0], "data"),
            registry_calldata(key)
        );
        assert_eip1898_tag(&request["params"][1], block_hash);
    }
    assert_eq!(
        required_str(&rpc["queries"], "locked_gold_calldata"),
        registry_calldata("LockedGold")
    );
    assert_eq!(
        required_str(&rpc["queries"], "locked_celo_calldata"),
        registry_calldata("LockedCelo")
    );
    assert_eq!(
        requests["implementation-slot"]["method"].as_str(),
        Some("eth_getStorageAt")
    );
    assert_eq!(
        address(
            requests["implementation-slot"]["params"][0]
                .as_str()
                .expect("proxy storage target")
        ),
        address(actual_mainnet)
    );
    assert_eq!(
        requests["implementation-slot"]["params"][1].as_str(),
        Some(required_str(mainnet, "eip1967_implementation_slot"))
    );
    assert_eip1898_tag(&requests["implementation-slot"]["params"][2], block_hash);
    for (id, expected_address) in [
        ("proxy-code", actual_mainnet),
        ("implementation-code", claimed_mainnet),
    ] {
        assert_eq!(requests[id]["method"].as_str(), Some("eth_getCode"));
        assert_eq!(
            address(requests[id]["params"][0].as_str().expect("code target")),
            address(expected_address)
        );
        assert_eip1898_tag(&requests[id]["params"][1], block_hash);
    }

    let runtime_paths = [
        ("proxy", "runtime/LockedGoldProxy.celo-mainnet.hex"),
        (
            "implementation",
            "runtime/LockedGold.implementation.celo-mainnet.hex",
        ),
    ];
    let mut runtimes = BTreeMap::<String, Vec<u8>>::new();
    for (role, runtime_path) in runtime_paths {
        let file_bytes = assert_manifest_file_hash(&evidence, &manifest, runtime_path);
        let runtime = read_hex(&evidence.join(runtime_path));
        let spec = object_containing_path(&manifest, runtime_path).expect("runtime manifest entry");
        assert_eq!(
            runtime.len() as u64,
            spec["bytes"].as_u64().expect("runtime byte length")
        );
        assert_eq!(
            sha256_hex(&runtime),
            spec["decoded_sha256"]
                .as_str()
                .expect("decoded runtime SHA-256")
        );
        assert_eq!(
            keccak_hex(&runtime),
            spec["keccak256"].as_str().expect("runtime Keccak-256")
        );
        assert_eq!(
            sha256_hex(&runtime),
            rpc["runtime_identity"][role]["sha256"]
                .as_str()
                .expect("RPC runtime SHA-256")
        );
        assert_eq!(
            keccak_hex(&runtime),
            rpc["runtime_identity"][role]["keccak256"]
                .as_str()
                .expect("RPC runtime Keccak-256")
        );
        assert!(!file_bytes.is_empty());
        runtimes.insert(role.to_owned(), runtime);
    }

    let receipt_providers = rpc["providers"].as_array().expect("RPC provider receipts");
    let manifest_providers = mainnet["rpc_receipt"]["provider_responses"]
        .as_array()
        .expect("raw provider response receipts");
    assert_eq!(receipt_providers.len(), 3);
    assert_eq!(manifest_providers.len(), 3);
    assert_eq!(
        manifest_providers
            .iter()
            .map(|provider| (
                required_str(provider, "name"),
                required_str(provider, "url")
            ))
            .collect::<BTreeSet<_>>(),
        [
            ("Ankr", "https://rpc.ankr.com/celo"),
            ("Celo Forno", "https://forno.celo.org"),
            ("dRPC", "https://celo.drpc.org"),
        ]
        .into_iter()
        .collect()
    );
    for provider in manifest_providers {
        let name = required_str(provider, "name");
        let receipt_provider = receipt_providers
            .iter()
            .find(|candidate| candidate["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("fixed-block receipt lost provider {name}"));
        assert_eq!(provider["url"], receipt_provider["url"]);
        let response_receipts = provider["files"]
            .as_array()
            .expect("provider response files");
        let response_paths = response_receipts
            .iter()
            .map(|receipt| required_str(receipt, "path"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            response_paths,
            receipt_provider["raw_response_files"]
                .as_array()
                .expect("fixed-block raw response files")
                .iter()
                .map(|path| path.as_str().expect("raw response path"))
                .collect()
        );

        let mut responses = BTreeMap::<String, Value>::new();
        for response_receipt in response_receipts {
            let path = required_str(response_receipt, "path");
            let bytes = assert_manifest_file_hash(&evidence, &manifest, path);
            let batch: Value = serde_json::from_slice(&bytes).expect("parse raw RPC response");
            for response in batch.as_array().expect("raw response batch array") {
                assert_eq!(response["jsonrpc"].as_str(), Some("2.0"));
                assert!(response.get("error").is_none(), "RPC error in {path}");
                assert!(
                    response.get("result").is_some(),
                    "RPC result absent in {path}"
                );
                let id = response["id"]
                    .as_str()
                    .expect("string response id")
                    .to_owned();
                assert!(
                    responses.insert(id.clone(), response.clone()).is_none(),
                    "duplicate raw response id {id} from {name}"
                );
            }
        }
        assert_eq!(
            responses.keys().cloned().collect::<BTreeSet<_>>(),
            expected_ids
        );
        assert_eq!(
            hex_u64(responses["chain-id"]["result"].as_str().expect("chain id")),
            42_220
        );
        let block = &responses["block"]["result"];
        assert_eq!(block["number"], mainnet["fixed_block"]["number_hex"]);
        assert_eq!(block["hash"], mainnet["fixed_block"]["hash"]);
        assert_eq!(block["parentHash"], mainnet["fixed_block"]["parent_hash"]);
        assert_eq!(block["stateRoot"], mainnet["fixed_block"]["state_root"]);
        assert_eq!(
            hex_u64(block["timestamp"].as_str().expect("block timestamp")),
            mainnet["fixed_block"]["timestamp"]
                .as_u64()
                .expect("manifest block timestamp")
        );

        let locked_gold = abi_word_address(
            responses["locked-gold"]["result"]
                .as_str()
                .expect("LockedGold Registry result"),
        );
        let locked_celo = abi_word_address(
            responses["locked-celo"]["result"]
                .as_str()
                .expect("LockedCelo Registry result"),
        );
        let implementation = abi_word_address(
            responses["implementation-slot"]["result"]
                .as_str()
                .expect("implementation slot result"),
        );
        assert_eq!(locked_gold, address(actual_mainnet));
        assert_eq!(locked_celo, locked_gold);
        assert_eq!(implementation, address(claimed_mainnet));
        assert_ne!(implementation, locked_gold);
        assert_eq!(
            decode_hex_text(
                responses["proxy-code"]["result"]
                    .as_str()
                    .expect("proxy runtime response")
            ),
            runtimes["proxy"],
            "{name} proxy runtime diverged"
        );
        assert_eq!(
            decode_hex_text(
                responses["implementation-code"]["result"]
                    .as_str()
                    .expect("implementation runtime response")
            ),
            runtimes["implementation"],
            "{name} implementation runtime diverged"
        );
    }
    assert_eq!(
        abi_word_address(required_str(&rpc["queries"], "registry_return")),
        address(actual_mainnet)
    );
    assert_eq!(
        abi_word_address(required_str(&rpc["queries"], "implementation_slot_return")),
        address(claimed_mainnet)
    );

    for artifact in [
        "blockscout/LockedGoldProxy.json",
        "blockscout/LockedGold.implementation.json",
        "abi/LockedGold.abi.json",
        "source/LockedGold.sol",
        "source/LockedGoldProxy.sol",
        "source/Proxy.sol",
        "source/Registry.sol",
        "deployment/core-contracts.md",
        "deployment/contracts.py",
        "governance/release-9-proposal.json",
    ] {
        assert_manifest_file_hash(&evidence, &manifest, artifact);
    }

    let abi = read_json(&evidence.join("abi/LockedGold.abi.json"));
    let proxy_report = read_json(&evidence.join("blockscout/LockedGoldProxy.json"));
    let implementation_report =
        read_json(&evidence.join("blockscout/LockedGold.implementation.json"));
    assert_eq!(proxy_report["name"].as_str(), Some("LockedGoldProxy"));
    assert_eq!(proxy_report["is_fully_verified"].as_bool(), Some(true));
    assert_eq!(proxy_report["is_changed_bytecode"].as_bool(), Some(false));
    assert_eq!(proxy_report["proxy_type"].as_str(), Some("eip1967"));
    let reported_implementations = proxy_report["implementations"]
        .as_array()
        .expect("Blockscout proxy implementations");
    assert_eq!(reported_implementations.len(), 1);
    assert_eq!(
        address(required_str(&reported_implementations[0], "address_hash")),
        address(claimed_mainnet)
    );
    assert_eq!(
        reported_implementations[0]["name"].as_str(),
        Some("LockedGold")
    );
    assert_eq!(implementation_report["name"].as_str(), Some("LockedGold"));
    assert_eq!(
        implementation_report["is_fully_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(
        implementation_report["is_changed_bytecode"].as_bool(),
        Some(false)
    );
    for (role, report, expected_address) in [
        ("proxy", &proxy_report, actual_mainnet),
        ("implementation", &implementation_report, claimed_mainnet),
    ] {
        assert_eq!(
            decode_hex_text(required_str(report, "deployed_bytecode")),
            runtimes[role],
            "Blockscout {role} bytecode diverged from all fixed-block RPC responses"
        );
        let url = required_str(&manifest["blockscout"][role], "url");
        assert_eq!(
            address(url.rsplit('/').next().expect("Blockscout URL address")),
            address(expected_address),
            "Blockscout {role} response URL lost its target binding"
        );
    }
    assert_eq!(implementation_report["abi"], abi);

    let locked_gold_source =
        fs::read(evidence.join("source/LockedGold.sol")).expect("read archived LockedGold source");
    let locked_gold_proxy_source = fs::read(evidence.join("source/LockedGoldProxy.sol"))
        .expect("read archived LockedGoldProxy source");
    let proxy_source =
        fs::read(evidence.join("source/Proxy.sol")).expect("read archived Proxy source");
    assert_eq!(
        implementation_report["source_code"]
            .as_str()
            .expect("Blockscout implementation source")
            .as_bytes(),
        locked_gold_source
    );
    assert_eq!(
        proxy_report["source_code"]
            .as_str()
            .expect("Blockscout proxy primary source")
            .as_bytes(),
        locked_gold_proxy_source
    );
    let proxy_support_sources = proxy_report["additional_sources"]
        .as_array()
        .expect("Blockscout proxy support sources")
        .iter()
        .filter(|source| {
            source["file_path"]
                .as_str()
                .is_some_and(|path| path.ends_with("/contracts/common/Proxy.sol"))
        })
        .collect::<Vec<_>>();
    assert_eq!(proxy_support_sources.len(), 1);
    assert_eq!(
        proxy_support_sources[0]["source_code"]
            .as_str()
            .expect("Blockscout common Proxy source")
            .as_bytes(),
        proxy_source
    );

    let core_contracts = fs::read_to_string(evidence.join("deployment/core-contracts.md"))
        .expect("read current Celo core-contract documentation");
    assert!(core_contracts.contains("## Celo Mainnet"));
    assert!(core_contracts.contains("## Celo Sepolia Testnet"));
    assert!(
        !core_contracts.to_ascii_lowercase().contains("alfajores"),
        "the captured current authority unexpectedly reacquired Alfajores"
    );
    for contract in ["LockedCelo", "LockedGold"] {
        assert_eq!(
            markdown_contract_address(&core_contracts, contract),
            address(actual_mainnet)
        );
    }
    assert_eq!(
        markdown_contract_address(&core_contracts, "Registry"),
        address(required_str(mainnet, "registry_address"))
    );
    let documented = &manifest["deployment_identity"]["current_core_contracts"];
    assert_eq!(
        address(required_str(documented, "mainnet_locked_celo")),
        address(actual_mainnet)
    );
    assert_eq!(
        address(required_str(documented, "mainnet_locked_gold")),
        address(actual_mainnet)
    );
    assert_eq!(
        address(required_str(documented, "mainnet_registry")),
        address(required_str(mainnet, "registry_address"))
    );

    let mcp_contracts = fs::read_to_string(evidence.join("deployment/contracts.py"))
        .expect("read Celo MCP contract identities");
    assert_eq!(
        python_dict_address(&mcp_contracts, "MAINNET_ADDRESSES", "LockedGold"),
        address(actual_mainnet)
    );
    assert_eq!(
        python_dict_address(&mcp_contracts, "ALFAJORES_ADDRESSES", "LockedGold"),
        address(required_str(residual, "descriptor_address"))
    );
    let mcp = &manifest["deployment_identity"]["celo_mcp_config"];
    assert_eq!(
        address(required_str(mcp, "mainnet_locked_gold")),
        address(actual_mainnet)
    );
    assert_eq!(
        address(required_str(mcp, "alfajores_locked_gold")),
        address(required_str(residual, "descriptor_address"))
    );
    assert!(
        manifest["testnet_residual"].get("rpc_receipt").is_none()
            && manifest["testnet_residual"].get("runtime").is_none()
            && manifest["testnet_residual"]
                .get("verified_source")
                .is_none(),
        "identity-only Alfajores evidence must not masquerade as live-state authority"
    );

    let abi_signatures = abi
        .as_array()
        .expect("LockedGold ABI array")
        .iter()
        .filter(|entry| entry["type"].as_str() == Some("function"))
        .map(|entry| {
            format!(
                "{}({})",
                required_str(entry, "name"),
                entry["inputs"]
                    .as_array()
                    .expect("ABI inputs")
                    .iter()
                    .map(|input| required_str(input, "type"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect::<BTreeSet<_>>();
    for (signature, _) in ROUTES {
        assert!(
            abi_signatures.contains(signature),
            "verified LockedGold ABI lost {signature}"
        );
    }
    let route_mutability = abi
        .as_array()
        .expect("LockedGold ABI array")
        .iter()
        .filter(|entry| entry["type"].as_str() == Some("function"))
        .filter_map(|entry| {
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
            ROUTES
                .iter()
                .any(|(route, _)| *route == signature)
                .then(|| (signature, required_str(entry, "stateMutability").to_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(route_mutability.len(), ROUTES.len());
    assert_eq!(route_mutability["lock()"], "payable");
    for (signature, _) in ROUTES {
        if signature != "lock()" {
            assert_eq!(
                route_mutability[signature], "nonpayable",
                "only lock() may consume native CELO value"
            );
        }
    }

    let locked_gold = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/LockedGold.sol"))
            .expect("read LockedGold source"),
    );
    for function in [
        "delegateGovernanceVotes",
        "lock",
        "relock",
        "revokeDelegatedGovernanceVotes",
        "unlock",
        "withdraw",
    ] {
        assert!(
            locked_gold.contains(&format!("function {function}(")),
            "official source lost {function} semantics"
        );
    }
    for source_contract in [
        "_incrementNonvotingAccountBalance(msg.sender, msg.value)",
        "account.pendingWithdrawals.push(PendingWithdrawal(value, available))",
        "PendingWithdrawal storage pendingWithdrawal = account.pendingWithdrawals[index]",
        "msg.sender.sendValue(value)",
        "FixidityLib.Fraction memory percentageToDelegate = FixidityLib.wrap(delegateFraction)",
        "FixidityLib.Fraction memory percentageToRevoke = FixidityLib.wrap(revokeFraction)",
    ] {
        assert!(
            locked_gold.contains(&normalized_whitespace(source_contract)),
            "source-binding lost route semantics: {source_contract}"
        );
    }
    let fixidity_source = implementation_report["additional_sources"]
        .as_array()
        .expect("verified additional sources")
        .iter()
        .find(|source| {
            source["file_path"]
                .as_str()
                .is_some_and(|path| path.ends_with("FixidityLib.sol"))
        })
        .and_then(|source| source["source_code"].as_str())
        .expect("verified FixidityLib source");
    assert!(fixidity_source.contains("FIXED1_UINT = 1000000000000000000000000"));
    assert!(fixidity_source.contains("return 24;"));

    let hazards = manifest["semantic_hazards"]
        .as_array()
        .expect("semantic hazard array")
        .iter()
        .map(|hazard| {
            hazard
                .as_str()
                .expect("semantic hazard text")
                .to_ascii_lowercase()
        })
        .collect::<Vec<_>>();
    assert!(hazards
        .iter()
        .any(|hazard| { hazard.contains("implementation") && hazard.contains("proxy") }));
    assert!(hazards.iter().any(|hazard| {
        hazard.contains("44787") || hazard.contains("alfajores") || hazard.contains("testnet")
    }));

    let curated_path = root.join(required_str(descriptor, "curation_overlay"));
    let vendored_path = root.join(required_str(descriptor, "vendored_file"));
    let curated = fs::read(curated_path).expect("read evidence-bound curation");
    assert_eq!(
        sha256_hex(&curated),
        required_str(descriptor, "curation_overlay_sha256")
    );
    assert_eq!(
        curated,
        fs::read(vendored_path).expect("read evidence-bound production descriptor")
    );
    assert_eq!(
        sha256_hex(&curated),
        required_str(descriptor, "vendored_file_sha256")
    );
}
