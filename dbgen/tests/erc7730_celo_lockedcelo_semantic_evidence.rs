//! Offline provenance checks for the quarantined Celo LockedCelo descriptor.
//!
//! The two upstream deployment bindings are stale: mainnet names the
//! LockedGold implementation instead of the Registry-selected proxy, while
//! Alfajores names a legacy deployment for which this evidence package does
//! not establish current, audited LockedCelo semantics.  The curated
//! descriptor therefore keeps all six selectors in omission protection but
//! deliberately makes every format incomplete so no trusted-display leaf can
//! be emitted for either address.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Map;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DESCRIPTOR_RELATIVE: &str = "registry/celo/calldata-locked_celo.json";
const DEPLOYMENTS: [(u64, &str); 2] = [
    (42_220, "55e1a0c8f376964bd339167476063bfed7f213d5"),
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

#[test]
fn stale_lockedcelo_bindings_emit_no_leaf_but_keep_every_call_fail_closed() {
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
        DEPLOYMENTS
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
        "the quarantine must cover exactly the six upstream LockedCelo calls"
    );
    for (signature, hidden_path) in ROUTES {
        let fields = formats_by_signature[signature]["fields"]
            .as_array()
            .expect("LockedCelo fields");
        let hidden: Vec<_> = fields
            .iter()
            .filter(|field| field["visible"].as_str() == Some("never"))
            .collect();
        assert_eq!(
            hidden.len(),
            1,
            "{signature} must retain exactly one deliberate incompleteness guard"
        );
        assert_eq!(hidden[0]["path"].as_str(), Some(hidden_path));
    }

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
    assert!(
        locked_entries.is_empty(),
        "neither stale LockedCelo deployment may produce a trusted leaf"
    );
    for (chain_id, contract_text) in DEPLOYMENTS {
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
        1,
        "the all-format quarantine must produce one descriptor-level receipt"
    );
    let reason = &locked_skips[0].reason;
    assert!(reason.contains("no compilable formats in descriptor"));
    for (signature, hidden_path) in ROUTES {
        let authored = formats
            .keys()
            .find(|authored| canonicalize_signature(authored) == signature)
            .unwrap_or_else(|| panic!("missing authored signature for {signature}"));
        let marker = format!("format `{authored}`");
        let start = reason
            .find(&marker)
            .unwrap_or_else(|| panic!("descriptor receipt lost exact route {authored}"));
        let tail = &reason[start..];
        let end = tail[marker.len()..]
            .find("; format `")
            .map_or(tail.len(), |offset| marker.len() + offset);
        let route_receipt = &tail[..end];
        assert!(
            route_receipt.contains(hidden_path),
            "descriptor-level receipt lost the route-specific {authored} / {hidden_path} witness"
        );
    }
}

#[test]
fn lockedcelo_evidence_binds_the_stale_addresses_to_runtime_source_and_rpc() {
    let root = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["policy"]["outcome"].as_str(),
        Some("hard_refusal_quarantine")
    );

    let quarantined = manifest["policy"]["known_call_quarantine"]
        .as_array()
        .expect("known-call quarantine array");
    assert_eq!(quarantined.len(), ROUTES.len());
    let manifest_routes = quarantined
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
    assert_eq!(address(claimed_mainnet), address(DEPLOYMENTS[0].1));
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
        "the descriptor names the implementation, not the Registry-selected proxy"
    );
    assert_eq!(
        required_str(mainnet, "eip1967_implementation_slot"),
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    );

    let residual = &manifest["testnet_residual"];
    assert_eq!(residual["chain_id"].as_u64(), Some(44_787));
    assert_eq!(
        address(required_str(residual, "descriptor_address")),
        address(DEPLOYMENTS[1].1)
    );
    let residual_reason = required_str(residual, "unsettled").to_ascii_lowercase();
    assert!(
        residual_reason.contains("legacy") && residual_reason.contains("quarantined"),
        "the testnet refusal boundary must remain explicit"
    );

    let rpc_bytes = assert_manifest_file_hash(&evidence, &manifest, "rpc/fixed-block-receipt.json");
    let rpc: Value = serde_json::from_slice(&rpc_bytes).expect("parse fixed-block RPC receipt");
    assert_eq!(rpc["chain_id"].as_u64(), Some(42_220));
    assert_eq!(rpc["block"], mainnet["fixed_block"]);
    assert_eq!(
        abi_word_address(required_str(&rpc["queries"], "registry_return")),
        address(actual_mainnet)
    );
    assert_eq!(
        abi_word_address(required_str(&rpc["queries"], "implementation_slot_return")),
        address(claimed_mainnet)
    );
    let providers = rpc["providers"].as_array().expect("RPC provider receipts");
    assert_eq!(providers.len(), 3);
    for provider in providers {
        for agreement in [
            "block_header_agrees",
            "locked_gold_registry_call_agrees",
            "locked_celo_registry_call_agrees",
            "implementation_slot_agrees",
            "proxy_runtime_agrees",
            "implementation_runtime_agrees",
        ] {
            assert_eq!(provider[agreement].as_bool(), Some(true));
        }
    }

    for runtime_path in [
        "runtime/LockedGoldProxy.celo-mainnet.hex",
        "runtime/LockedGold.implementation.celo-mainnet.hex",
    ] {
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
        assert!(!file_bytes.is_empty());
    }

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
