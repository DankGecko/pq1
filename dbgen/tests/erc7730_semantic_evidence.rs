//! Offline provenance checks for externally audited ERC-7730 semantics.
//!
//! These tests deliberately do not contact RPC or explorer services. They
//! authenticate the fixed-block inputs archived under
//! tests/erc7730-semantic-evidence and bind them back to the production
//! descriptor deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::{cross_check_contract, BindingError};
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, Visibility};
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn stakewise_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/stakewise-claim-exited-assets")
}

fn lido_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/lido-wsteth-permit")
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

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments_in_order(haystack: &str, fragments: &[&str]) {
    let mut remainder = haystack;
    for fragment in fragments {
        let offset = remainder
            .find(fragment)
            .unwrap_or_else(|| panic!("missing ordered source fragment: {fragment}"));
        remainder = &remainder[offset + fragment.len()..];
    }
}

fn decode_abi_string_result(text: &str) -> String {
    let bytes = decode_hex_text(text);
    assert!(bytes.len() >= 64, "ABI string result is truncated");
    assert_eq!(&bytes[..31], &[0u8; 31]);
    assert_eq!(bytes[31], 32, "ABI string data offset changed");
    assert_eq!(&bytes[32..63], &[0u8; 31]);
    let length = bytes[63] as usize;
    assert!(
        64 + length <= bytes.len(),
        "ABI string payload is truncated"
    );
    String::from_utf8(bytes[64..64 + length].to_vec()).expect("ABI string is UTF-8")
}

fn eip712_domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    contract: &[u8; 20],
) -> [u8; 32] {
    let mut encoded = [0u8; 160];
    encoded[..32].copy_from_slice(&keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ));
    encoded[32..64].copy_from_slice(&keccak256(name.as_bytes()));
    encoded[64..96].copy_from_slice(&keccak256(version.as_bytes()));
    encoded[120..128].copy_from_slice(&chain_id.to_be_bytes());
    encoded[140..160].copy_from_slice(contract);
    keccak256(&encoded)
}

#[test]
fn stakewise_fixed_block_runtimes_match_the_archived_receipt() {
    let evidence = stakewise_evidence_root();
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
    let evidence = stakewise_evidence_root();
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

#[test]
fn lido_wsteth_fixed_block_runtime_and_state_match_receipt() {
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let signature = required_str(&manifest, "canonical_signature");
    let selector = &keccak256(signature.as_bytes())[..4];
    assert_eq!(
        required_str(&manifest, "selector"),
        format!("0x{}", hex::encode(selector))
    );
    assert_eq!(selector, [0xd5, 0x05, 0xac, 0xcf]);

    let deployment = &manifest["deployment"];
    assert_eq!(deployment["chain_id"].as_u64(), Some(1));
    let contract_bytes = decode_hex_text(required_str(deployment, "address"));
    let contract: [u8; 20] = contract_bytes.try_into().expect("wstETH address width");
    assert_eq!(
        hex::encode(contract),
        "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"
    );
    assert_eq!(deployment["block_number"].as_u64(), Some(11_888_477));
    assert_eq!(deployment["deployer_nonce"].as_u64(), Some(4));
    assert_eq!(deployment["receipt_status"].as_u64(), Some(1));
    assert_eq!(
        required_str(deployment, "receipt_contract_address"),
        required_str(deployment, "address")
    );
    assert_eq!(deployment["creation_input_bytes"].as_u64(), Some(7_277));
    assert_eq!(
        decode_hex_text(required_str(deployment, "transaction_hash")).len(),
        32
    );
    assert_eq!(
        decode_hex_text(required_str(deployment, "creation_input_keccak256")).len(),
        32
    );
    assert_eq!(
        required_str(deployment, "constructor_argument_steth"),
        "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"
    );

    for receipt in [deployment, &manifest["evidence_block"]] {
        let endpoints: BTreeSet<_> = receipt["rpc_endpoints"]
            .as_array()
            .expect("RPC endpoint array")
            .iter()
            .map(|endpoint| endpoint.as_str().expect("RPC endpoint string"))
            .collect();
        assert_eq!(
            endpoints.len(),
            2,
            "each receipt needs two independent RPC observations"
        );
        let hash_key = if receipt.get("block_hash").is_some() {
            "block_hash"
        } else {
            "hash"
        };
        assert_eq!(decode_hex_text(required_str(receipt, hash_key)).len(), 32);
    }
    let fixed_block = &manifest["evidence_block"];
    assert_eq!(fixed_block["number"].as_u64(), Some(25_566_776));
    assert_eq!(decode_hex_text(required_str(fixed_block, "hash")).len(), 32);
    assert_eq!(
        decode_hex_text(required_str(fixed_block, "state_root")).len(),
        32
    );

    let runtime_spec = &manifest["runtime"];
    let runtime = read_hex(&evidence.join(required_str(runtime_spec, "file")));
    assert_eq!(
        runtime.len() as u64,
        runtime_spec["bytes"].as_u64().expect("runtime byte count")
    );
    assert_eq!(
        keccak_hex(&runtime),
        required_str(runtime_spec, "keccak256")
    );
    assert!(
        runtime
            .windows(selector.len())
            .any(|window| window == selector),
        "archived runtime lost the permit selector"
    );
    assert_eq!(
        runtime_spec["explorer_deployed_bytecode_matches_artifact"].as_bool(),
        Some(true)
    );
    assert_eq!(
        decode_hex_text(required_str(runtime_spec, "eip1967_implementation_slot")).len(),
        32
    );
    assert_eq!(
        decode_hex_text(required_str(
            runtime_spec,
            "eip1967_implementation_slot_value"
        )),
        [0u8; 32],
        "fixed-block wstETH unexpectedly became an ERC-1967 proxy"
    );

    let calls = &manifest["fixed_block_calls"];
    for (name, canonical_signature) in [
        ("name", "name()"),
        ("symbol", "symbol()"),
        ("decimals", "decimals()"),
        ("steth", "stETH()"),
        ("domain_separator", "DOMAIN_SEPARATOR()"),
    ] {
        assert_eq!(
            required_str(&calls[name], "selector"),
            format!(
                "0x{}",
                hex::encode(&keccak256(canonical_signature.as_bytes())[..4])
            ),
            "{name} selector drifted"
        );
    }
    let token_name = decode_abi_string_result(required_str(&calls["name"], "result"));
    let token_symbol = decode_abi_string_result(required_str(&calls["symbol"], "result"));
    assert_eq!(token_name, required_str(&calls["name"], "decoded"));
    assert_eq!(token_symbol, required_str(&calls["symbol"], "decoded"));
    assert_eq!(token_name, "Wrapped liquid staked Ether 2.0");
    assert_eq!(token_symbol, "wstETH");

    let decimals = decode_hex_text(required_str(&calls["decimals"], "result"));
    assert_eq!(decimals.len(), 32);
    assert_eq!(&decimals[..31], &[0u8; 31]);
    assert_eq!(
        decimals[31] as u64,
        calls["decimals"]["decoded"]
            .as_u64()
            .expect("decoded decimals")
    );
    assert_eq!(decimals[31], 18);

    let steth_word = decode_hex_text(required_str(&calls["steth"], "result"));
    assert_eq!(steth_word.len(), 32);
    assert_eq!(&steth_word[..12], &[0u8; 12]);
    assert_eq!(
        &steth_word[12..],
        decode_hex_text(required_str(&calls["steth"], "decoded")).as_slice()
    );
    assert_eq!(
        required_str(&calls["steth"], "decoded"),
        required_str(deployment, "constructor_argument_steth")
    );

    let domain = decode_hex_text(required_str(&calls["domain_separator"], "result"));
    assert_eq!(
        domain,
        eip712_domain_separator(&token_name, "1", 1, &contract),
        "fixed-block domain separator does not bind the archived name, version, chain, and contract"
    );
}

#[test]
fn lido_wsteth_source_abi_descriptor_and_metadata_agree_on_permit_semantics() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let source_spec = &manifest["verified_source"];

    assert_eq!(
        source_spec["compiler"].as_str(),
        Some("0.6.12+commit.27d51765")
    );
    assert_eq!(source_spec["evm_version"].as_str(), Some("istanbul"));
    assert_eq!(source_spec["optimizer_enabled"].as_bool(), Some(true));
    assert_eq!(source_spec["optimizer_runs"].as_u64(), Some(200));
    assert_eq!(
        source_spec["upstream_commit"].as_str(),
        Some("2b46615a11dee77d4d22066f942f6c6afab9b87a")
    );
    assert_eq!(
        source_spec["upstream_tree"].as_str(),
        Some("b4e0ba7c36530d279ff0c4f18b1ae6e68a272da7")
    );
    assert_eq!(source_spec["openzeppelin_version"].as_str(), Some("3.4.0"));
    assert_eq!(
        source_spec["openzeppelin_tag_commit"].as_str(),
        Some("fa64a1ced0b70ab89073d5d0b6e01b0778f7e7d6")
    );
    assert_eq!(
        source_spec["archived_upstream_lines_present_in_verified_flattened_source"].as_bool(),
        Some(true)
    );

    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let upstream_bytes = fs::read(evidence.join(required_str(source_spec, "upstream_file")))
        .expect("read archived Lido source");
    assert_eq!(
        sha256_hex(&upstream_bytes),
        required_str(source_spec, "upstream_file_sha256")
    );
    let openzeppelin_bytes =
        fs::read(evidence.join(required_str(source_spec, "openzeppelin_file")))
            .expect("read archived OpenZeppelin source");
    assert_eq!(
        sha256_hex(&openzeppelin_bytes),
        required_str(source_spec, "openzeppelin_file_sha256")
    );

    let flattened = String::from_utf8(flattened_bytes).expect("flattened source is UTF-8");
    let flattened_lines: BTreeSet<_> = flattened.lines().map(str::trim).collect();
    for (label, source_bytes) in [
        ("official Lido WstETH", upstream_bytes),
        ("OpenZeppelin ERC20Permit", openzeppelin_bytes),
    ] {
        let source = String::from_utf8(source_bytes).expect("archived source is UTF-8");
        for line in source.lines().map(str::trim).filter(|line| {
            !line.is_empty() && !line.starts_with("// SPDX") && !line.starts_with("import ")
        }) {
            assert!(
                flattened_lines.contains(line),
                "{label} line is absent from the verified flattened source: {line}"
            );
        }
    }

    let permit_signature =
        "function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual override {";
    let permit_start = flattened
        .find(permit_signature)
        .expect("deployed permit implementation");
    let permit_tail = &flattened[permit_start..];
    let permit_end = permit_tail
        .find("function nonces(address owner)")
        .expect("permit implementation end");
    let permit = normalized_whitespace(&permit_tail[..permit_end]);
    assert_fragments_in_order(
        &permit,
        &[
            r#"require(block.timestamp <= deadline, "ERC20Permit: expired deadline");"#,
            "_PERMIT_TYPEHASH, owner, spender, value, _nonces[owner].current(), deadline",
            "bytes32 hash = _hashTypedDataV4(structHash);",
            "address signer = ECDSA.recover(hash, v, r, s);",
            r#"require(signer == owner, "ERC20Permit: invalid signature");"#,
            "_nonces[owner].increment();",
            "_approve(owner, spender, value);",
        ],
    );
    let flattened_normalized = normalized_whitespace(&flattened);
    assert!(flattened_normalized
        .contains(r#"constructor(string memory name) internal EIP712(name, "1") { }"#));
    assert_fragments_in_order(
        &flattened_normalized,
        &[
            "contract WstETH is ERC20Permit",
            r#"constructor(IStETH _stETH) public ERC20Permit("Wrapped liquid staked Ether 2.0") ERC20("Wrapped liquid staked Ether 2.0", "wstETH")"#,
            "stETH = _stETH;",
        ],
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read permit ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse permit ABI");
    let entries = abi.as_array().expect("permit ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["name"].as_str(), Some("permit"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(entry["outputs"].as_array().map(Vec::len), Some(0));
    let inputs = entry["inputs"].as_array().expect("permit ABI inputs");
    let input_names: Vec<_> = inputs
        .iter()
        .map(|input| input["name"].as_str().expect("ABI input name"))
        .collect();
    let input_types: Vec<_> = inputs
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect();
    assert_eq!(
        input_names,
        ["owner", "spender", "value", "deadline", "v", "r", "s"]
    );
    assert_eq!(
        input_types,
        ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"]
    );
    let abi_signature = format!("permit({})", input_types.join(","));
    assert_eq!(
        abi_signature,
        required_str(&manifest, "canonical_signature")
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor"),
        "curated and installed Lido descriptors diverged"
    );
    let descriptor: Value = serde_json::from_slice(&curated_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor deployment address")
            .to_ascii_lowercase(),
        required_str(&manifest["deployment"], "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["wstETHaddress"]
            .as_str()
            .expect("wstETH token constant")
            .to_ascii_lowercase(),
        required_str(&manifest["deployment"], "address")
    );

    let formats = descriptor["display"]["formats"]
        .as_object()
        .expect("descriptor formats");
    let permits: Vec<_> = formats
        .iter()
        .filter(|(signature, _)| signature.starts_with("permit("))
        .collect();
    assert_eq!(permits.len(), 1);
    let fields = permits[0].1["fields"]
        .as_array()
        .expect("permit display fields");
    let expected_fields = [
        ("Owner", "#.owner", "addressName"),
        ("Spender", "#.spender", "addressName"),
        ("Amount", "#.value", "tokenAmount"),
        ("Deadline", "#.deadline", "date"),
        ("V", "#.v", "raw"),
        ("R", "#.r", "raw"),
        ("S", "#.s", "raw"),
    ];
    assert_eq!(fields.len(), expected_fields.len());
    for (field, (label, path, format)) in fields.iter().zip(expected_fields) {
        assert_eq!(field["label"].as_str(), Some(label));
        assert_eq!(field["path"].as_str(), Some(path));
        assert_eq!(field["format"].as_str(), Some(format));
        assert_eq!(field["visible"].as_str(), Some("always"));
    }
    let manifest_paths: Vec<_> = descriptor_spec["permit_operand_paths"]
        .as_array()
        .expect("manifest operand paths")
        .iter()
        .map(|path| path.as_str().expect("manifest operand path"))
        .collect();
    let descriptor_paths: Vec<_> = fields
        .iter()
        .map(|field| field["path"].as_str().expect("descriptor field path"))
        .collect();
    assert_eq!(descriptor_paths, manifest_paths);

    let records = dbgen::load_erc20_records(&root.join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let metadata: Vec<_> = records
        .iter()
        .filter(|record| {
            record.chain_id == 1
                && record
                    .address
                    .eq_ignore_ascii_case(required_str(&manifest["deployment"], "address"))
        })
        .collect();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].name, "Wrapped liquid staked Ether 2.0");
    assert_eq!(metadata[0].symbol, "wstETH");
    assert_eq!(metadata[0].decimals, 18);

    let registry_root = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &policy,
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    assert_eq!(
        (registry_entry.chain_id, registry_entry.contract),
        (1, {
            let mut address = [0u8; 20];
            address.copy_from_slice(&decode_hex_text(required_str(
                &manifest["deployment"],
                "address",
            )));
            address
        })
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated Lido IR");
    assert_eq!(
        cross_check_contract(&ir, 1, &registry_entry.contract),
        Ok(())
    );
    assert_eq!(
        cross_check_contract(&ir, 10, &registry_entry.contract),
        Err(BindingError::ChainIdMismatch)
    );
    let mut wrong_contract = registry_entry.contract;
    wrong_contract[19] ^= 1;
    assert_eq!(
        cross_check_contract(&ir, 1, &wrong_contract),
        Err(BindingError::ContractMismatch)
    );
    let permit_selector: [u8; 4] =
        keccak256(required_str(&manifest, "canonical_signature").as_bytes())[..4]
            .try_into()
            .expect("permit selector width");
    let format = ir
        .find_format_by_selector(&permit_selector)
        .expect("Lido format table parses")
        .expect("Lido permit remains admitted");
    assert_eq!(format.fields().count(), 7);

    assert!(manifest["residuals"]
        .as_array()
        .expect("residual array")
        .iter()
        .any(|residual| residual
            .as_str()
            .is_some_and(|text| text.contains("nonce") && text.contains("not signed calldata"))));
}

#[test]
fn lido_wsteth_wrap_source_abi_descriptor_and_metadata_agree_on_input_semantics() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let deployment = &manifest["deployment"];
    let source_spec = &manifest["verified_source"];
    let wrap_spec = &manifest["additional_routes"]["wrap"];
    let signature = required_str(wrap_spec, "canonical_signature");

    assert_eq!(signature, "wrap(uint256)");
    let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("wrap selector width");
    assert_eq!(selector, [0xea, 0x59, 0x8c, 0xb0]);
    assert_eq!(required_str(wrap_spec, "selector"), "0xea598cb0");

    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let upstream_bytes = fs::read(evidence.join(required_str(source_spec, "upstream_file")))
        .expect("read archived official Lido source");
    assert_eq!(
        sha256_hex(&upstream_bytes),
        required_str(source_spec, "upstream_file_sha256")
    );

    for (label, source_bytes) in [
        ("verified flattened", flattened_bytes),
        ("official Lido", upstream_bytes),
    ] {
        let source = String::from_utf8(source_bytes).expect("wrap source is UTF-8");
        let wrap_start = source
            .find("function wrap(uint256 _stETHAmount) external returns (uint256) {")
            .unwrap_or_else(|| panic!("{label} wrap implementation"));
        let wrap_tail = &source[wrap_start..];
        let wrap_end = wrap_tail
            .find("function unwrap(uint256 _wstETHAmount)")
            .unwrap_or_else(|| panic!("{label} wrap implementation end"));
        let wrap = normalized_whitespace(&wrap_tail[..wrap_end]);
        assert_fragments_in_order(
            &wrap,
            &[
                r#"require(_stETHAmount > 0, "wstETH: can't wrap zero stETH");"#,
                "uint256 wstETHAmount = stETH.getSharesByPooledEth(_stETHAmount);",
                "_mint(msg.sender, wstETHAmount);",
                "stETH.transferFrom(msg.sender, address(this), _stETHAmount);",
                "return wstETHAmount;",
            ],
        );
    }

    let abi_spec = &wrap_spec["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read wrap ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse wrap ABI");
    let entries = abi.as_array().expect("wrap ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["name"].as_str(), Some("wrap"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    let inputs = entry["inputs"].as_array().expect("wrap ABI inputs");
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["name"].as_str(), Some("_stETHAmount"));
    assert_eq!(inputs[0]["type"].as_str(), Some("uint256"));
    let outputs = entry["outputs"].as_array().expect("wrap ABI outputs");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["type"].as_str(), Some("uint256"));
    assert_eq!(
        format!(
            "{}({})",
            entry["name"].as_str().unwrap(),
            inputs[0]["type"].as_str().unwrap()
        ),
        signature
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor"),
        "curated and installed Lido descriptors diverged"
    );
    let descriptor: Value = serde_json::from_slice(&curated_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor address")
            .to_ascii_lowercase(),
        required_str(deployment, "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["stETHaddress"]
            .as_str()
            .expect("stETH constant")
            .to_ascii_lowercase(),
        required_str(deployment, "constructor_argument_steth")
    );

    let format = &descriptor["display"]["formats"]["wrap(uint256 _stETHAmount)"];
    assert_eq!(format["intent"].as_str(), Some("Wrap stETH"));
    let fields = format["fields"].as_array().expect("wrap display fields");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["label"].as_str(), Some("stETH amount"));
    assert_eq!(fields[0]["path"].as_str(), Some("#._stETHAmount"));
    assert_eq!(fields[0]["format"].as_str(), Some("tokenAmount"));
    assert_eq!(fields[0]["visible"].as_str(), Some("always"));
    assert_eq!(
        fields[0]["params"]["token"].as_str(),
        Some("$.metadata.constants.stETHaddress")
    );
    let displayed_paths: Vec<_> = wrap_spec["displayed_operand_paths"]
        .as_array()
        .expect("wrap displayed paths")
        .iter()
        .map(|path| path.as_str().expect("wrap displayed path"))
        .collect();
    assert_eq!(displayed_paths, ["#._stETHAmount"]);

    let records = dbgen::load_erc20_records(&root.join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let steth: Vec<_> = records
        .iter()
        .filter(|record| {
            record.chain_id == 1
                && record
                    .address
                    .eq_ignore_ascii_case(required_str(deployment, "constructor_argument_steth"))
        })
        .collect();
    assert_eq!(steth.len(), 1);
    assert_eq!(steth[0].name, "Liquid staked Ether 2.0");
    assert_eq!(steth[0].symbol, "stETH");
    assert_eq!(steth[0].decimals, 18);

    let registry_root = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &policy,
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    assert_eq!(registry_entry.chain_id, 1);
    assert_eq!(
        hex::encode(registry_entry.contract),
        required_str(deployment, "address").trim_start_matches("0x")
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated Lido IR");
    let format = ir
        .find_format_by_selector(&selector)
        .expect("Lido format table parses")
        .expect("Lido wrap remains admitted");
    let fields: Vec<_> = format
        .fields()
        .map(|field| field.expect("generated wrap field parses"))
        .collect();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].label, b"stETH amount");
    assert_eq!(
        FormatOp::try_from(fields[0].format_op),
        Ok(FormatOp::TokenAmount)
    );
    let params = parse_params(&ir, fields[0].param_off).expect("wrap field params parse");
    assert_eq!(params.visibility, Visibility::Always);
    assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
    assert_eq!(params.integer_width_bytes, Some(32));
    assert_eq!(
        params.token.map(hex::encode),
        Some(
            required_str(deployment, "constructor_argument_steth")
                .trim_start_matches("0x")
                .to_owned()
        )
    );

    let output_residual = required_str(wrap_spec, "output_residual");
    assert!(output_residual.contains("live stETH share state"));
    assert!(output_residual.contains("not signed calldata"));
}
