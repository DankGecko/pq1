//! Offline provenance checks for externally audited ERC-7730 semantics.
//!
//! These tests deliberately do not contact RPC or explorer services. They
//! authenticate the fixed-block inputs archived under
//! tests/erc7730-semantic-evidence and bind them back to the production
//! descriptor deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/stakewise-claim-exited-assets")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("manifest field {key} is a string"))
}

#[test]
fn stakewise_fixed_block_runtimes_match_the_archived_receipt() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let signature = required_str(&manifest, "canonical_signature");
    assert_eq!(
        required_str(&manifest, "selector"),
        format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
    );

    let artifacts = manifest["runtime_artifacts"]
        .as_object()
        .expect("runtime_artifacts object");
    let mut decoded = BTreeMap::<String, Vec<u8>>::new();
    for (name, spec) in artifacts {
        let bytes = read_hex(&evidence.join(required_str(spec, "file")));
        assert_eq!(
            bytes.len() as u64,
            spec["bytes"].as_u64().expect("runtime byte count"),
            "{name} byte count drifted"
        );
        assert_eq!(
            keccak_hex(&bytes),
            required_str(spec, "keccak256"),
            "{name} code hash drifted"
        );
        decoded.insert(name.clone(), bytes);
    }

    let slot = decode_hex_text(required_str(&manifest, "eip1967_implementation_slot"));
    let proxy = decoded.get("proxy").expect("proxy runtime");
    assert!(
        proxy.windows(slot.len()).any(|window| window == slot),
        "archived proxy runtime must embed the EIP-1967 implementation slot"
    );

    let implementation = decode_hex_text(required_str(&manifest, "implementation_address"));
    assert_eq!(implementation.len(), 20);
    let deployments = manifest["deployments"]
        .as_array()
        .expect("deployments array");
    assert_eq!(deployments.len(), 3);
    for deployment in deployments {
        let word = decode_hex_text(required_str(deployment, "implementation_slot_value"));
        assert_eq!(word.len(), 32);
        assert_eq!(&word[..12], &[0u8; 12]);
        assert_eq!(&word[12..], implementation.as_slice());
        assert!(decoded.contains_key(required_str(deployment, "implementation_runtime")));
    }

    let blocks = manifest["blocks"].as_array().expect("blocks array");
    assert_eq!(blocks.len(), 2);
    for block in blocks {
        assert_eq!(
            block["rpc_endpoints"]
                .as_array()
                .expect("RPC endpoint array")
                .len(),
            2,
            "each fixed block must have two independent observations"
        );
        assert_eq!(decode_hex_text(required_str(block, "hash")).len(), 32);
        assert_eq!(decode_hex_text(required_str(block, "state_root")).len(), 32);
    }

    let mut mainnet = decoded
        .get("implementation_mainnet")
        .expect("mainnet implementation")
        .clone();
    let mut hoodi = decoded
        .get("implementation_hoodi")
        .expect("Hoodi implementation")
        .clone();
    assert_eq!(mainnet.len(), hoodi.len());

    let ranges = manifest["cross_chain_runtime"]["variant_ranges"]
        .as_array()
        .expect("variant range array");
    assert_eq!(ranges.len(), 22, "variant-range inventory changed");
    let mut prior_end = 0usize;
    let mut label_counts = BTreeMap::<String, usize>::new();
    for range in ranges {
        let offset = range["offset"].as_u64().expect("range offset") as usize;
        let length = range["length"].as_u64().expect("range length") as usize;
        let end = offset.checked_add(length).expect("range end");
        assert!(
            offset >= prior_end,
            "variant ranges overlap or are unsorted"
        );
        assert!(end <= mainnet.len(), "variant range exceeds runtime");

        let expected_mainnet = decode_hex_text(required_str(range, "mainnet_hex"));
        let expected_hoodi = decode_hex_text(required_str(range, "hoodi_hex"));
        assert_eq!(expected_mainnet.len(), length);
        assert_eq!(expected_hoodi.len(), length);
        assert_eq!(&mainnet[offset..end], expected_mainnet.as_slice());
        assert_eq!(&hoodi[offset..end], expected_hoodi.as_slice());

        mainnet[offset..end].fill(0);
        hoodi[offset..end].fill(0);
        prior_end = end;
        *label_counts
            .entry(required_str(range, "label").to_owned())
            .or_default() += 1;
    }
    assert_eq!(
        label_counts,
        BTreeMap::from([
            ("chainId".to_owned(), 1),
            ("depositDataRegistry".to_owned(), 2),
            ("keeper".to_owned(), 5),
            ("osTokenConfig".to_owned(), 3),
            ("osTokenVaultController".to_owned(), 7),
            ("osTokenVaultEscrow".to_owned(), 1),
            ("sharedMevEscrow".to_owned(), 2),
            ("vaultsRegistry".to_owned(), 1),
        ])
    );
    assert_eq!(
        mainnet, hoodi,
        "implementation instruction bytes differ outside declared chain/address immutables"
    );
}

#[test]
fn stakewise_claim_source_abi_and_descriptors_agree_on_caller_semantics() {
    let root = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    let verified_source = &manifest["verified_source"];
    assert_eq!(verified_source["upstream_release"].as_str(), Some("v4.0.1"));
    assert_eq!(
        verified_source["upstream_commit"].as_str(),
        Some("c511cd912cb881f60cf2a32d6c5d5f533e5d04b5")
    );
    assert_eq!(
        verified_source["upstream_tree"].as_str(),
        Some("6185defc0ea2c9d5e72f02bd3e1411e13684b7fc")
    );
    assert_eq!(
        verified_source["openzeppelin_submodule_commit"].as_str(),
        Some("60b305a8f3ff0c7688f02ac470417b6bbf1c4d27")
    );
    assert_eq!(
        verified_source["archived_files_match_verified_explorer_sources"].as_bool(),
        Some(true)
    );

    let mut archived_sources = BTreeMap::<String, String>::new();
    for source in verified_source["files"]
        .as_array()
        .expect("verified source file array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read archived source");
        assert_eq!(sha256_hex(&bytes), required_str(source, "sha256"));
        archived_sources.insert(
            archive_file.to_owned(),
            String::from_utf8(bytes).expect("Solidity source is UTF-8"),
        );
    }
    let eth_vault = &archived_sources["source/EthVault.sol"];
    assert!(eth_vault.contains("VaultEnterExit"));
    assert!(
        !eth_vault.contains("function claimExitedAssets"),
        "the concrete EthVault must inherit, not override, the audited claim semantics"
    );

    let module = &archived_sources["source/VaultEnterExit.sol"];
    let semantics = manifest["claim_semantics"]
        .as_object()
        .expect("claim semantics object");
    for key in [
        "request_lookup",
        "request_delete",
        "residual_request_key",
        "transfer_recipient",
        "event_recipient",
    ] {
        assert!(
            module.contains(required_str(&Value::Object(semantics.clone()), key)),
            "archived implementation lost the {key} msg.sender binding"
        );
    }

    let interface: String = archived_sources["source/IVaultEnterExit.sol"]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(interface.contains(
        "function claimExitedAssets(uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex) external;"
    ));

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse route ABI");
    let entries = abi.as_array().expect("ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(entry["outputs"].as_array().map(Vec::len), Some(0));
    let input_types: Vec<_> = entry["inputs"]
        .as_array()
        .expect("ABI inputs")
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect();
    assert_eq!(input_types, ["uint256", "uint256", "uint256"]);
    let signature = format!(
        "{}({})",
        entry["name"].as_str().expect("ABI function name"),
        input_types.join(",")
    );
    assert_eq!(signature, required_str(&manifest, "canonical_signature"));

    let mut expected_by_descriptor = BTreeMap::<String, BTreeSet<(u64, String)>>::new();
    for deployment in manifest["deployments"]
        .as_array()
        .expect("deployment array")
    {
        expected_by_descriptor
            .entry(required_str(deployment, "descriptor").to_owned())
            .or_default()
            .insert((
                deployment["chain_id"].as_u64().expect("deployment chain"),
                required_str(deployment, "address").to_ascii_lowercase(),
            ));
    }
    assert_eq!(expected_by_descriptor.len(), 2);

    for (descriptor_path, expected_deployments) in expected_by_descriptor {
        let descriptor_bytes =
            fs::read(root.join(&descriptor_path)).expect("read curated descriptor");
        let registry_suffix = descriptor_path
            .strip_prefix("secure/data/erc7730/curations/files/")
            .expect("curation descriptor prefix");
        assert_eq!(
            descriptor_bytes,
            fs::read(
                root.join("secure/data/erc7730-registry")
                    .join(registry_suffix)
            )
            .expect("read vendored descriptor"),
            "curation and production descriptor copies diverged"
        );
        let descriptor: Value = serde_json::from_slice(&descriptor_bytes).expect("descriptor JSON");
        let actual_deployments: BTreeSet<_> = descriptor["context"]["contract"]["deployments"]
            .as_array()
            .expect("descriptor deployments")
            .iter()
            .map(|deployment| {
                (
                    deployment["chainId"].as_u64().expect("descriptor chain"),
                    deployment["address"]
                        .as_str()
                        .expect("descriptor address")
                        .to_ascii_lowercase(),
                )
            })
            .collect();
        assert_eq!(actual_deployments, expected_deployments);

        let format = &descriptor["display"]["formats"]
            ["claimExitedAssets(uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex)"];
        let fields = format["fields"].as_array().expect("claim display fields");
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["label"].as_str(), Some("Claim receiver"));
        assert_eq!(fields[0]["path"].as_str(), Some("@.from"));
        assert_eq!(fields[0]["format"].as_str(), Some("addressName"));
        assert_eq!(fields[0]["visible"].as_str(), Some("always"));
        assert_eq!(fields[1]["path"].as_str(), Some("#.positionTicket"));
        assert_eq!(fields[2]["path"].as_str(), Some("#.timestamp"));
        assert_eq!(fields[3]["path"].as_str(), Some("#.exitQueueIndex"));
        assert!(fields.iter().all(|field| field["visible"] == "always"));
    }
}
