//! Offline evidence and renderer coverage for the bounded SafeL2 slice in #497.
//!
//! This test admits only three operand-complete inherited SafeL2 singleton
//! calls. Migrations, proxy instances, module routes, fallback authority,
//! blind signing, production, hardware, and shipment are deliberately outside
//! this evidence boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::{build_db_tolerant_with_erc20_capabilities, Erc7730BuildResult};
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::bundle::verify_erc7730_bundle;
use pqsigner_erc7730::display::render::render_erc7730_pages_with_signer_checked;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_tx::names::NameResolver;
use pqsigner_tx_core::eip1559::Eip1559Tx;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EVIDENCE_PATH: &str = "tests/erc7730-semantic-evidence/safe-l2";
const COMMON_DESCRIPTOR: &str = "secure/data/erc7730-registry/registry/safe/common-Safe.json";
const BLOCK_HASH: &str = "0x5ceb4e40574ba2b93faf07aaa23587804ac417d25aa6a57174c318438c22c64d";
const V130_CANONICAL: &str = "0x3E5c63644E683549055b9Be8653de26E0B4CD36E";
const V130_EIP155: &str = "0xfb1bffC9d739B8D520DaF37dF666da4C687191EA";
const V141: &str = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762";
const V150: &str = "0xEdd160fEBBD92E350D4D398fb636302fccd67C7e";

const ADMITTED_SOURCE_SIGNATURES: [&str; 3] = [
    "addOwnerWithThreshold(address owner, uint256 _threshold)",
    "changeThreshold(uint256 _threshold)",
    "approveHash(bytes32 hashToApprove)",
];
const ADMITTED_CANONICAL_SIGNATURES: [&str; 3] = [
    "addOwnerWithThreshold(address,uint256)",
    "changeThreshold(uint256)",
    "approveHash(bytes32)",
];
const REFUSED_SOURCE_SIGNATURES: [&str; 4] = [
    "setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)",
    "execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)",
    "removeOwner(address prevOwner, address owner, uint256 _threshold)",
    "swapOwner(address prevOwner, address oldOwner, address newOwner)",
];
const REFUSED_CANONICAL_SIGNATURES: [&str; 4] = [
    "setup(address[],uint256,address,bytes,address,address,uint256,address)",
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    "removeOwner(address,address,uint256)",
    "swapOwner(address,address,address)",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent")
        .to_path_buf()
}

fn evidence() -> PathBuf {
    root().join(EVIDENCE_PATH)
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
        .unwrap_or_else(|| panic!("{key} must be a string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid evidence hex")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read hex evidence {}: {error}", path.display())),
    )
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("selector")
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn collect_files(root: &Path, directory: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read evidence directory") {
        let entry = entry.expect("evidence entry");
        let kind = entry.file_type().expect("evidence file type");
        assert!(!kind.is_symlink(), "evidence must not contain symlinks");
        if kind.is_dir() {
            collect_files(root, &entry.path(), out);
        } else {
            out.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("file below evidence root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn assert_receipted_package(expected_artifacts: usize) -> Value {
    let evidence = evidence();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let artifacts = manifest["artifacts"].as_array().expect("artifact receipts");
    assert_eq!(artifacts.len(), expected_artifacts);
    let mut receipts = BTreeMap::new();
    for artifact in artifacts {
        let path = required_str(artifact, "path");
        assert!(
            receipts
                .insert(path.to_owned(), required_str(artifact, "sha256"))
                .is_none(),
            "duplicate receipt: {path}"
        );
        assert_eq!(
            sha256_hex(&fs::read(evidence.join(path)).expect("read receipted artifact")),
            required_str(artifact, "sha256"),
            "artifact receipt changed: {path}"
        );
    }
    let mut files = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut files);
    files.remove("manifest.json");
    assert_eq!(
        files,
        receipts.keys().cloned().collect(),
        "every non-manifest artifact must be receipted exactly once"
    );
    manifest
}

fn rpc_results(path: &Path) -> BTreeMap<u64, Value> {
    let mut out = BTreeMap::new();
    for item in read_json(path).as_array().expect("RPC batch") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(
            item.get("error").is_none(),
            "RPC evidence contains an error"
        );
        let id = item["id"].as_u64().expect("RPC id");
        assert!(out.insert(id, item["result"].clone()).is_none());
    }
    out
}

fn provider_results(provider: &str) -> BTreeMap<u64, Value> {
    let mut out = BTreeMap::new();
    for suffix in ["identity", "v1.3.0", "v1.4.1-v1.5.0"] {
        for (id, value) in
            rpc_results(&evidence().join(format!("rpc/raw/response-{provider}-{suffix}.json")))
        {
            assert!(out.insert(id, value).is_none(), "duplicate RPC id {id}");
        }
    }
    out
}

fn request_map() -> BTreeMap<u64, Value> {
    let mut out = BTreeMap::new();
    for suffix in ["identity", "v1.3.0", "v1.4.1-v1.5.0"] {
        for request in read_json(&evidence().join(format!("rpc/raw/request-{suffix}.json")))
            .as_array()
            .expect("request batch")
        {
            let id = request["id"].as_u64().expect("request id");
            assert!(out.insert(id, request.clone()).is_none());
        }
    }
    out
}

fn build_registry() -> Erc7730BuildResult {
    let root = root();
    let registry = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build ERC20 capabilities");
    build_db_tolerant_with_erc20_capabilities(
        &registry.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 catalogue")
    .0
}

fn synth_bundle(blob: &[u8], ir: &[u8], leaf_index: usize) -> Vec<u8> {
    let depth = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let proof_off = proofs_off + leaf_index * depth * 32;
    let mut bundle = Vec::new();
    bundle.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    bundle.extend_from_slice(ir);
    bundle.extend_from_slice(&(leaf_index as u32).to_be_bytes());
    bundle.extend_from_slice(&(depth as u32).to_be_bytes());
    bundle.extend_from_slice(&blob[proof_off..proof_off + depth * 32]);
    bundle
}

fn word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_address(value: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&value);
    word
}

fn calldata(signature: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut out = selector(signature).to_vec();
    for word in words {
        out.extend_from_slice(word);
    }
    out
}

fn abi_inputs(asset: &Value, name: &str) -> Vec<(String, String)> {
    let matches = asset["abi"]
        .as_array()
        .expect("deployment ABI")
        .iter()
        .filter(|item| {
            item["type"].as_str() == Some("function") && item["name"].as_str() == Some(name)
        })
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "one ABI function named {name}");
    matches[0]["inputs"]
        .as_array()
        .expect("ABI inputs")
        .iter()
        .map(|input| {
            (
                required_str(input, "name").to_string(),
                required_str(input, "type").to_string(),
            )
        })
        .collect()
}

fn deployment_addresses(asset: &Value, chain_id: u64) -> BTreeSet<[u8; 20]> {
    let network = &asset["networkAddresses"][chain_id.to_string()];
    let kinds = if let Some(kind) = network.as_str() {
        vec![kind]
    } else {
        network
            .as_array()
            .unwrap_or_else(|| panic!("chain {chain_id} missing from official deployment manifest"))
            .iter()
            .map(|kind| kind.as_str().expect("deployment kind"))
            .collect()
    };
    kinds
        .into_iter()
        .map(|kind| address(required_str(&asset["deployments"][kind], "address")))
        .collect()
}

fn descriptor(name: &str) -> Value {
    read_json(&root().join(format!("secure/data/erc7730-registry/registry/safe/{name}")))
}

fn descriptor_deployments(descriptor: &Value) -> BTreeSet<(u64, [u8; 20])> {
    descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments")
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"].as_u64().expect("chain id"),
                address(required_str(deployment, "address")),
            )
        })
        .collect()
}

fn assert_source_semantics(main: &str, l2: &str, owners: &str, version: &str) {
    assert!(
        main.contains(&format!("VERSION = \"{version}\""))
            || main.contains(&format!("VERSION = '{version}'")),
        "source version changed"
    );
    for fragment in [
        "approvedHashes[msg.sender][hashToApprove] = 1;",
        "emit ApproveHash(hashToApprove, msg.sender);",
    ] {
        assert!(main.contains(fragment), "{version} lost: {fragment}");
    }
    for fragment in [
        "owners[owner] = owners[SENTINEL_OWNERS];",
        "owners[SENTINEL_OWNERS] = owner;",
        "if (threshold != _threshold) changeThreshold(_threshold);",
        "threshold = _threshold;",
    ] {
        assert!(owners.contains(fragment), "{version} lost: {fragment}");
    }
    assert!(
        owners.contains("function addOwnerWithThreshold")
            && owners.contains("function changeThreshold")
            && owners.matches("authorized").count() >= 2,
        "{version} owner mutations must remain self-authorized"
    );
    assert!(
        l2.contains("contract GnosisSafeL2 is GnosisSafe")
            || l2.contains("contract SafeL2 is Safe"),
        "{version} SafeL2 inheritance changed"
    );
    for fragment in [
        "event SafeMultiSigTransaction(",
        "event SafeModuleTransaction(",
        "emit SafeMultiSigTransaction(",
        "emit SafeModuleTransaction(",
    ] {
        assert!(l2.contains(fragment), "{version} SafeL2 lost: {fragment}");
    }
    for inherited in [
        "function addOwnerWithThreshold",
        "function changeThreshold",
        "function approveHash",
    ] {
        assert!(
            !l2.contains(inherited),
            "{version} SafeL2 unexpectedly overrides {inherited}"
        );
    }
}

#[test]
fn safe_l2_offline_evidence_is_complete_and_consistent() {
    let manifest = assert_receipted_package(26);
    assert_eq!(
        required_str(&manifest, "issue"),
        "https://github.com/EthereumPhone/PQ1/issues/497"
    );
    let expected_sources = [
        (
            "v1.3.0",
            "186a21a74b327f17fc41217a927dea7064f74604",
            [
                "source/v1.3.0/GnosisSafeL2.sol",
                "source/v1.3.0/GnosisSafe.sol",
                "source/v1.3.0/OwnerManager.sol",
            ],
        ),
        (
            "v1.4.1",
            "bf943f80fec5ac647159d26161446ac5d716a294",
            [
                "source/v1.4.1/SafeL2.sol",
                "source/v1.4.1/Safe.sol",
                "source/v1.4.1/OwnerManager.sol",
            ],
        ),
        (
            "v1.5.0",
            "dc437e8fba8b4805d76bcbd1c668c9fd3d1e83be",
            [
                "source/v1.5.0/SafeL2.sol",
                "source/v1.5.0/Safe.sol",
                "source/v1.5.0/OwnerManager.sol",
            ],
        ),
    ];
    let source_pins = manifest["upstream_sources"]
        .as_array()
        .expect("source pins");
    assert_eq!(source_pins.len(), expected_sources.len());
    for (pin, (tag, commit, files)) in source_pins.iter().zip(expected_sources) {
        assert_eq!(
            required_str(pin, "repository"),
            "https://github.com/safe-fndn/safe-smart-account"
        );
        assert_eq!(required_str(pin, "tag"), tag);
        assert_eq!(required_str(pin, "commit"), commit);
        assert_eq!(
            pin["files"]
                .as_array()
                .expect("source files")
                .iter()
                .map(|file| file.as_str().expect("source file"))
                .collect::<Vec<_>>(),
            files
        );
    }
    assert_eq!(
        required_str(&manifest["safe_deployments"], "repository"),
        "https://github.com/safe-global/safe-deployments"
    );
    assert_eq!(
        required_str(&manifest["safe_deployments"], "commit"),
        "06021f40739266f21a9ec083cf19827ab48b5dc7"
    );
    assert_eq!(
        manifest["safe_deployments"]["assets"]
            .as_array()
            .expect("deployment assets")
            .iter()
            .map(|asset| asset.as_str().expect("deployment asset"))
            .collect::<Vec<_>>(),
        [
            "deployments/v1.3.0-gnosis_safe_l2.json",
            "deployments/v1.4.1-safe_l2.json",
            "deployments/v1.5.0-safe_l2.json",
        ]
    );
    let expected_descriptors = [
        (
            COMMON_DESCRIPTOR,
            "354793337c021f674f4f510fedfe3b922a63d8435983c8449d0ab6ee5e9d7d4b",
        ),
        (
            "secure/data/erc7730-registry/registry/safe/calldata-SafeL2-1.3.0.json",
            "27a910f57238a1771cf920e290551ffc93efbb667f8d918c5123816fd7b5adee",
        ),
        (
            "secure/data/erc7730-registry/registry/safe/calldata-SafeL2-1.4.1.json",
            "c247b99e93fdeac090e20220217b2aa0edbcf1e0bd800dba8979180025fcf9ca",
        ),
        (
            "secure/data/erc7730-registry/registry/safe/calldata-SafeL2-1.5.0.json",
            "7b35a9aaec838b7fb4283e109eef5504caf4396cb93e922d78632309ea0f956c",
        ),
    ];
    let descriptor_inputs = manifest["descriptor_inputs"]
        .as_array()
        .expect("descriptor inputs");
    assert_eq!(descriptor_inputs.len(), expected_descriptors.len());
    for (input, (path, expected_hash)) in descriptor_inputs.iter().zip(expected_descriptors) {
        assert_eq!(required_str(input, "path"), path);
        assert_eq!(required_str(input, "sha256"), expected_hash);
        assert_eq!(
            sha256_hex(&fs::read(root().join(path)).expect("read descriptor input")),
            expected_hash
        );
    }
    assert_eq!(manifest["fixed_block"]["number"].as_u64(), Some(25_624_960));
    assert_eq!(required_str(&manifest["fixed_block"], "hash"), BLOCK_HASH);

    let requests = request_map();
    assert_eq!(
        requests.keys().copied().collect::<Vec<_>>(),
        (1..=6).collect::<Vec<_>>()
    );
    assert_eq!(requests[&1]["method"].as_str(), Some("eth_chainId"));
    assert_eq!(requests[&2]["method"].as_str(), Some("eth_getBlockByHash"));
    assert_eq!(requests[&2]["params"][0].as_str(), Some(BLOCK_HASH));
    for (id, expected_address) in [(3, V130_CANONICAL), (4, V130_EIP155), (5, V141), (6, V150)] {
        assert_eq!(requests[&id]["method"].as_str(), Some("eth_getCode"));
        assert_eq!(requests[&id]["params"][0].as_str(), Some(expected_address));
        assert_eq!(
            requests[&id]["params"][1]["blockHash"].as_str(),
            Some(BLOCK_HASH)
        );
        assert_eq!(
            requests[&id]["params"][1]["requireCanonical"].as_bool(),
            Some(true)
        );
    }

    let drpc = provider_results("drpc");
    let mev = provider_results("mevblocker");
    assert_eq!(drpc[&1].as_str(), Some("0x1"));
    assert_eq!(mev[&1].as_str(), Some("0x1"));
    for field in ["number", "hash", "parentHash", "stateRoot", "timestamp"] {
        assert_eq!(
            drpc[&2][field], mev[&2][field],
            "provider block mismatch: {field}"
        );
    }
    assert_eq!(drpc[&2]["number"].as_str(), Some("0x1870180"));
    assert_eq!(drpc[&2]["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(
        drpc[&2]["parentHash"].as_str(),
        Some("0x8769fdf35dd709cc52d7ab7598fb04365cc540a8f63e2d4d00118a35a2616df8")
    );
    assert_eq!(
        drpc[&2]["stateRoot"].as_str(),
        Some("0x6e43c0236e18ae6ed7204d7ab91b21b6f5735f73ba531acad04594fdf93bc349")
    );
    assert_eq!(drpc[&2]["timestamp"].as_str(), Some("0x6a67754b"));
    for id in 3..=6 {
        assert_eq!(drpc[&id], mev[&id], "provider runtime mismatch at id {id}");
    }

    let runtime_130 = read_hex(&evidence().join("runtime/SafeL2-1.3.0.ethereum.hex"));
    let runtime_141 = read_hex(&evidence().join("runtime/SafeL2-1.4.1.ethereum.hex"));
    let runtime_150 = read_hex(&evidence().join("runtime/SafeL2-1.5.0.ethereum.hex"));
    assert_eq!(runtime_130, decode_hex(drpc[&3].as_str().unwrap()));
    assert_eq!(runtime_130, decode_hex(drpc[&4].as_str().unwrap()));
    assert_eq!(runtime_141, decode_hex(drpc[&5].as_str().unwrap()));
    assert_eq!(runtime_150, decode_hex(drpc[&6].as_str().unwrap()));

    let assets = [
        (
            "1.3.0",
            "deployments/v1.3.0-gnosis_safe_l2.json",
            V130_CANONICAL,
            "0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f",
            &runtime_130,
        ),
        (
            "1.4.1",
            "deployments/v1.4.1-safe_l2.json",
            V141,
            "0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff",
            &runtime_141,
        ),
        (
            "1.5.0",
            "deployments/v1.5.0-safe_l2.json",
            V150,
            "0x180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc",
            &runtime_150,
        ),
    ];
    for (version, path, expected_address, expected_hash, runtime) in assets {
        let asset = read_json(&evidence().join(path));
        assert_eq!(asset["version"].as_str(), Some(version));
        assert_eq!(asset["released"].as_bool(), Some(true));
        assert_eq!(
            asset["deployments"]["canonical"]["address"].as_str(),
            Some(expected_address)
        );
        assert_eq!(
            asset["deployments"]["canonical"]["codeHash"].as_str(),
            Some(expected_hash)
        );
        assert_eq!(keccak_hex(runtime), expected_hash);
        assert_eq!(
            abi_inputs(&asset, "addOwnerWithThreshold"),
            vec![
                ("owner".to_string(), "address".to_string()),
                ("_threshold".to_string(), "uint256".to_string()),
            ]
        );
        assert_eq!(
            abi_inputs(&asset, "changeThreshold"),
            vec![("_threshold".to_string(), "uint256".to_string())]
        );
        assert_eq!(
            abi_inputs(&asset, "approveHash"),
            vec![("hashToApprove".to_string(), "bytes32".to_string())]
        );
    }
    let v130_asset = read_json(&evidence().join("deployments/v1.3.0-gnosis_safe_l2.json"));
    assert_eq!(
        v130_asset["deployments"]["eip155"]["address"].as_str(),
        Some(V130_EIP155)
    );
    assert_eq!(
        v130_asset["deployments"]["eip155"]["codeHash"].as_str(),
        Some("0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f")
    );

    let source = |path: &str| {
        fs::read_to_string(evidence().join(path))
            .unwrap_or_else(|error| panic!("read source {path}: {error}"))
    };
    assert_source_semantics(
        &source("source/v1.3.0/GnosisSafe.sol"),
        &source("source/v1.3.0/GnosisSafeL2.sol"),
        &source("source/v1.3.0/OwnerManager.sol"),
        "1.3.0",
    );
    assert_source_semantics(
        &source("source/v1.4.1/Safe.sol"),
        &source("source/v1.4.1/SafeL2.sol"),
        &source("source/v1.4.1/OwnerManager.sol"),
        "1.4.1",
    );
    assert_source_semantics(
        &source("source/v1.5.0/Safe.sol"),
        &source("source/v1.5.0/SafeL2.sol"),
        &source("source/v1.5.0/OwnerManager.sol"),
        "1.5.0",
    );
}

#[test]
fn safe_l2_descriptors_pin_official_deployments_and_refusal_boundary() {
    let versions = [
        (
            "calldata-SafeL2-1.3.0.json",
            "deployments/v1.3.0-gnosis_safe_l2.json",
            14,
        ),
        (
            "calldata-SafeL2-1.4.1.json",
            "deployments/v1.4.1-safe_l2.json",
            7,
        ),
        (
            "calldata-SafeL2-1.5.0.json",
            "deployments/v1.5.0-safe_l2.json",
            2,
        ),
    ];
    for (descriptor_name, asset_path, expected_count) in versions {
        let descriptor = descriptor(descriptor_name);
        let asset = read_json(&evidence().join(asset_path));
        let deployments = descriptor_deployments(&descriptor);
        assert_eq!(deployments.len(), expected_count);
        for (chain_id, contract) in &deployments {
            assert!(
                deployment_addresses(&asset, *chain_id).contains(contract),
                "{descriptor_name} contains a deployment absent from the official manifest"
            );
        }

        let admissions = descriptor["_pqsigner"]["deploymentFormats"]
            .as_array()
            .expect("Safe deploymentFormats");
        assert_eq!(
            descriptor["_pqsigner"]["refusalOnlyFormats"]
                .as_array()
                .expect("Safe refusalOnlyFormats")
                .iter()
                .map(|format| format.as_str().expect("refusal-only format"))
                .collect::<BTreeSet<_>>(),
            REFUSED_SOURCE_SIGNATURES.into_iter().collect(),
            "{descriptor_name} must structurally fence every permanently refused Safe format"
        );
        assert_eq!(admissions.len(), expected_count);
        let admitted_deployments = admissions
            .iter()
            .map(|admission| {
                let formats = admission["formats"].as_array().expect("admitted formats");
                assert_eq!(
                    formats
                        .iter()
                        .map(|format| format.as_str().expect("format"))
                        .collect::<BTreeSet<_>>(),
                    ADMITTED_SOURCE_SIGNATURES.into_iter().collect()
                );
                (
                    admission["chainId"].as_u64().expect("chain id"),
                    address(required_str(admission, "address")),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(admitted_deployments, deployments);

        let curated = root().join(format!(
            "secure/data/erc7730/curations/files/registry/safe/{descriptor_name}"
        ));
        assert_eq!(
            fs::read(root().join(format!(
                "secure/data/erc7730-registry/registry/safe/{descriptor_name}"
            )))
            .unwrap(),
            fs::read(curated).expect("curated Safe replacement")
        );
    }

    let common = read_json(&root().join(COMMON_DESCRIPTOR));
    let formats = common["display"]["formats"]
        .as_object()
        .expect("Safe formats");
    assert_eq!(formats.len(), 7);
    let field = |signature: &str, path: &str| {
        formats[signature]["fields"]
            .as_array()
            .expect("format fields")
            .iter()
            .find(|field| field["path"].as_str() == Some(path))
    };
    assert!(field(ADMITTED_SOURCE_SIGNATURES[0], "owner").is_some());
    assert!(field(ADMITTED_SOURCE_SIGNATURES[0], "_threshold").is_some());
    assert!(field(ADMITTED_SOURCE_SIGNATURES[1], "_threshold").is_some());
    assert!(field(ADMITTED_SOURCE_SIGNATURES[2], "hashToApprove").is_some());

    let setup =
        "setup(address[] _owners, uint256 _threshold, address to, bytes data, address fallbackHandler, address paymentToken, uint256 payment, address paymentReceiver)";
    let exec =
        "execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)";
    let remove = "removeOwner(address prevOwner, address owner, uint256 _threshold)";
    let swap = "swapOwner(address prevOwner, address oldOwner, address newOwner)";
    assert!(
        field(setup, "to").is_none(),
        "setup target must not be silently admitted"
    );
    assert!(
        field(exec, "to").is_none(),
        "exec target must not be silently admitted"
    );
    assert_eq!(
        field(remove, "prevOwner").and_then(|field| field["visible"].as_str()),
        Some("never")
    );
    assert_eq!(
        field(swap, "prevOwner").and_then(|field| field["visible"].as_str()),
        Some("never")
    );
}

#[test]
fn safe_l2_catalogue_merkle_binds_three_formats_and_refuses_known_siblings() {
    let registry = build_registry();
    let admitted = ADMITTED_CANONICAL_SIGNATURES
        .into_iter()
        .map(selector)
        .collect::<BTreeSet<_>>();
    let refused = REFUSED_CANONICAL_SIGNATURES
        .into_iter()
        .map(selector)
        .collect::<BTreeSet<_>>();
    let resolver = NameResolver::new();
    let signer = [0x44; 20];

    let source_counts = [
        ("calldata-SafeL2-1.3.0.json", 14),
        ("calldata-SafeL2-1.4.1.json", 7),
        ("calldata-SafeL2-1.5.0.json", 2),
    ];
    for (source_name, expected_count) in source_counts {
        let entries = registry
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), expected_count);

        for entry in entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("Safe IR");
            assert_eq!(ir.format_count(), Ok(3));
            assert_eq!(
                ir.format_iter()
                    .map(|format| format.expect("format").selector)
                    .collect::<BTreeSet<_>>(),
                admitted
            );
            let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
            let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("Safe proof");
            assert_eq!(
                cross_check_contract(&verified.ir, entry.chain_id, &entry.contract),
                Ok(())
            );

            for selector in refused.iter().copied() {
                assert!(ir.find_format_by_selector(&selector).unwrap().is_none());
                assert!(
                    registry
                        .known_calls
                        .contains(&(entry.chain_id, entry.contract, selector)),
                    "excluded Safe call must remain exact-known"
                );
                assert!(known_call_may_contain(
                    &registry.known_calls_bloom,
                    entry.chain_id,
                    &entry.contract,
                    &selector
                ));
            }

            let cases = [
                (
                    ADMITTED_CANONICAL_SIGNATURES[0],
                    vec![word_address([0x11; 20]), word_u64(2)],
                    vec![word_address([0x12; 20]), word_u64(3)],
                ),
                (
                    ADMITTED_CANONICAL_SIGNATURES[1],
                    vec![word_u64(2)],
                    vec![word_u64(3)],
                ),
                (
                    ADMITTED_CANONICAL_SIGNATURES[2],
                    vec![[0x33; 32]],
                    vec![[0x34; 32]],
                ),
            ];
            let tx = Eip1559Tx {
                chain_id: entry.chain_id,
                to: Some(entry.contract),
                ..Eip1559Tx::default()
            };
            for (signature, words, mutations) in cases {
                let call = calldata(signature, &words);
                let rendered = render_erc7730_pages_with_signer_checked(
                    &tx, &call, &verified, None, &resolver, &signer,
                )
                .unwrap_or_else(|error| panic!("render {source_name} {signature}: {error:?}"));
                assert!(rendered
                    .transcript_receipt
                    .range_matches(&rendered.pages, 0));
                for index in 0..words.len() {
                    let mut mutated = call.clone();
                    mutated[4 + index * 32..4 + (index + 1) * 32]
                        .copy_from_slice(&mutations[index]);
                    let changed = render_erc7730_pages_with_signer_checked(
                        &tx, &mutated, &verified, None, &resolver, &signer,
                    )
                    .unwrap_or_else(|error| {
                        panic!("render {source_name} {signature} mutation {index}: {error:?}")
                    });
                    assert_ne!(rendered.pages.as_slice(), changed.pages.as_slice());
                    assert!(!rendered
                        .transcript_receipt
                        .exact_match(&changed.transcript_receipt));
                }
            }
        }
    }
}
