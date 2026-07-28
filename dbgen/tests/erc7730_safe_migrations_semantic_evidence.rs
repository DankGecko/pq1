//! Offline evidence and renderer coverage for the bounded Safe migration slice in #497.
//!
//! Only version-pinned singleton migrations and operand-complete L2 setup are
//! admitted. Fallback-handler migration, proxy state, wrapper/delegatecall
//! construction, blind signing, production, hardware, and shipment remain
//! outside this evidence boundary.

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

const EVIDENCE_PATH: &str = "tests/erc7730-semantic-evidence/safe-migrations";
const BLOCK_HASH: &str = "0x5ceb4e40574ba2b93faf07aaa23587804ac417d25aa6a57174c318438c22c64d";
const BLOCK_NUMBER: &str = "0x1870180";

const MIGRATION_V141: &str = "0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6";
const SETUP_V141: &str = "0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54";
const SAFE_V141: &str = "0x41675C099F32341bf84BFc5382aF534df5C7461a";
const SAFE_L2_V141: &str = "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762";
const FALLBACK_V141: &str = "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99";

const MIGRATION_V150: &str = "0x6439e7ABD8Bb915A5263094784C5CF561c4172AC";
const SETUP_V150: &str = "0x900C7589200010D6C6eCaaE5B06EBe653bc2D82a";
const SAFE_V150: &str = "0xFf51A5898e281Db6DfC7855790607438dF2ca44b";
const SAFE_L2_V150: &str = "0xEdd160fEBBD92E350D4D398fb636302fccd67C7e";
const FALLBACK_V150: &str = "0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4";

const MIGRATION_ADMITTED_SOURCE: [&str; 2] = ["migrateSingleton()", "migrateL2Singleton()"];
const MIGRATION_ADMITTED_CANONICAL: [&str; 2] = ["migrateSingleton()", "migrateL2Singleton()"];
const MIGRATION_REFUSED_SOURCE: [&str; 2] = [
    "migrateWithFallbackHandler()",
    "migrateL2WithFallbackHandler()",
];
const MIGRATION_REFUSED_CANONICAL: [&str; 2] = [
    "migrateWithFallbackHandler()",
    "migrateL2WithFallbackHandler()",
];
const SETUP_SOURCE: &str = "setupToL2(address l2Singleton)";
const SETUP_CANONICAL: &str = "setupToL2(address)";

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

fn rpc_address(value: &Value) -> [u8; 20] {
    let word = decode_hex(value.as_str().expect("RPC address result"));
    assert_eq!(word.len(), 32);
    word[12..].try_into().expect("ABI address word")
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

fn batch_names() -> [&'static str; 6] {
    [
        "identity",
        "runtime-v1.4.1",
        "runtime-v1.5.0",
        "getters-a",
        "getters-b",
        "getters-c",
    ]
}

fn provider_results(provider: &str) -> BTreeMap<u64, Value> {
    let mut out = BTreeMap::new();
    for suffix in batch_names() {
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
    for suffix in batch_names() {
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

fn pages_text(pages: &pqsigner_erc7730::display::Pages) -> String {
    pages
        .as_slice()
        .iter()
        .flat_map(|page| page.iter())
        .map(|row| String::from_utf8_lossy(row).trim().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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

fn assert_source_semantics(migration: &str, setup: &str, version: &str) {
    for fragment in [
        "require(address(this) != MIGRATION_SINGLETON",
        "MIGRATION_SINGLETON = address(this);",
        "SAFE_SINGLETON = safeSingleton;",
        "SAFE_L2_SINGLETON = safeL2Singleton;",
        "SAFE_FALLBACK_HANDLER = fallbackHandler;",
        "function migrateSingleton() public onlyDelegateCall",
        "singleton = SAFE_SINGLETON;",
        "function migrateL2Singleton() public onlyDelegateCall",
        "singleton = SAFE_L2_SINGLETON;",
        "function migrateWithFallbackHandler() external onlyDelegateCall",
        "setFallbackHandler(SAFE_FALLBACK_HANDLER);",
        "function migrateL2WithFallbackHandler() external onlyDelegateCall",
    ] {
        assert!(
            migration.contains(fragment),
            "{version} migration source lost: {fragment}"
        );
    }
    for fragment in [
        "modifier onlyDelegateCall()",
        "modifier onlyNonceZero()",
        "modifier onlyContract(address account)",
        "function setupToL2(address l2Singleton) external onlyDelegateCall onlyNonceZero onlyContract(l2Singleton)",
        "if (chainId() != 1)",
        "singleton = l2Singleton;",
    ] {
        assert!(
            setup.contains(fragment),
            "{version} setup source lost: {fragment}"
        );
    }
}

#[test]
fn safe_migration_offline_evidence_is_complete_and_consistent() {
    let manifest = assert_receipted_package(38);
    assert_eq!(
        required_str(&manifest, "issue"),
        "https://github.com/EthereumPhone/PQ1/issues/497"
    );
    assert_eq!(manifest["fixed_block"]["number"].as_u64(), Some(25_624_960));
    assert_eq!(required_str(&manifest["fixed_block"], "hash"), BLOCK_HASH);

    for descriptor_input in manifest["descriptor_inputs"]
        .as_array()
        .expect("descriptor inputs")
    {
        let path = root().join(required_str(descriptor_input, "path"));
        assert_eq!(
            sha256_hex(&fs::read(&path).expect("descriptor input")),
            required_str(descriptor_input, "sha256"),
            "descriptor input changed: {}",
            path.display()
        );
    }

    let requests = request_map();
    assert_eq!(
        requests.keys().copied().collect::<Vec<_>>(),
        (1..=14).collect::<Vec<_>>()
    );
    assert_eq!(requests[&1]["method"].as_str(), Some("eth_chainId"));
    assert_eq!(requests[&2]["method"].as_str(), Some("eth_getBlockByHash"));
    assert_eq!(requests[&2]["params"][0].as_str(), Some(BLOCK_HASH));
    for (id, expected_address) in [
        (3, MIGRATION_V141),
        (4, SETUP_V141),
        (5, MIGRATION_V150),
        (6, SETUP_V150),
    ] {
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
    let getter_specs = [
        (7, MIGRATION_V141, "0x72f7a956"),
        (8, MIGRATION_V141, "0xcaa12add"),
        (9, MIGRATION_V141, "0x9bf47d6e"),
        (10, MIGRATION_V141, "0x0d7101f7"),
        (11, MIGRATION_V150, "0x72f7a956"),
        (12, MIGRATION_V150, "0xcaa12add"),
        (13, MIGRATION_V150, "0x9bf47d6e"),
        (14, MIGRATION_V150, "0x0d7101f7"),
    ];
    for (id, expected_to, expected_data) in getter_specs {
        assert_eq!(requests[&id]["method"].as_str(), Some("eth_call"));
        assert_eq!(requests[&id]["params"][0]["to"].as_str(), Some(expected_to));
        assert_eq!(
            requests[&id]["params"][0]["data"].as_str(),
            Some(expected_data)
        );
        assert_eq!(requests[&id]["params"][1].as_str(), Some(BLOCK_NUMBER));
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
    assert_eq!(drpc[&2]["number"].as_str(), Some(BLOCK_NUMBER));
    assert_eq!(drpc[&2]["hash"].as_str(), Some(BLOCK_HASH));
    for id in 3..=14 {
        assert_eq!(drpc[&id], mev[&id], "provider result mismatch at id {id}");
    }

    let versions = [
        (
            "1.4.1",
            "v1.4.1-2",
            MIGRATION_V141,
            SETUP_V141,
            SAFE_V141,
            SAFE_L2_V141,
            FALLBACK_V141,
            7_u64,
            3_u64,
            4_u64,
            7_u64,
        ),
        (
            "1.5.0",
            "v1.5.0",
            MIGRATION_V150,
            SETUP_V150,
            SAFE_V150,
            SAFE_L2_V150,
            FALLBACK_V150,
            2_u64,
            5_u64,
            6_u64,
            11_u64,
        ),
    ];
    for (
        version,
        source_version,
        migration_address,
        setup_address,
        safe_address,
        safe_l2_address,
        fallback_address,
        _deployment_count,
        migration_code_id,
        setup_code_id,
        getter_base,
    ) in versions
    {
        let deployment = |name: &str| {
            read_json(
                &evidence()
                    .join("deployments")
                    .join(format!("v{version}"))
                    .join(format!("{name}.json")),
            )
        };
        let migration_asset = deployment("safe_migration");
        let setup_asset = deployment("safe_to_l2_setup");
        let safe_asset = deployment("safe");
        let safe_l2_asset = deployment("safe_l2");
        let fallback_asset = deployment("compatibility_fallback_handler");
        for asset in [
            &migration_asset,
            &setup_asset,
            &safe_asset,
            &safe_l2_asset,
            &fallback_asset,
        ] {
            assert_eq!(asset["version"].as_str(), Some(version));
            assert_eq!(asset["released"].as_bool(), Some(true));
        }
        assert_eq!(
            migration_asset["deployments"]["canonical"]["address"].as_str(),
            Some(migration_address)
        );
        assert_eq!(
            setup_asset["deployments"]["canonical"]["address"].as_str(),
            Some(setup_address)
        );
        assert_eq!(
            safe_asset["deployments"]["canonical"]["address"].as_str(),
            Some(safe_address)
        );
        assert_eq!(
            safe_l2_asset["deployments"]["canonical"]["address"].as_str(),
            Some(safe_l2_address)
        );
        assert_eq!(
            fallback_asset["deployments"]["canonical"]["address"].as_str(),
            Some(fallback_address)
        );

        for name in [
            "migrateSingleton",
            "migrateL2Singleton",
            "migrateWithFallbackHandler",
            "migrateL2WithFallbackHandler",
        ] {
            assert!(abi_inputs(&migration_asset, name).is_empty());
        }
        assert_eq!(
            abi_inputs(&setup_asset, "setupToL2"),
            vec![("l2Singleton".to_string(), "address".to_string())]
        );

        let migration_runtime = read_hex(
            &evidence()
                .join("runtime")
                .join(format!("SafeMigration-{version}.ethereum.hex")),
        );
        let setup_runtime = read_hex(
            &evidence()
                .join("runtime")
                .join(format!("SafeToL2Setup-{version}.ethereum.hex")),
        );
        assert_eq!(
            migration_runtime,
            decode_hex(drpc[&migration_code_id].as_str().unwrap())
        );
        assert_eq!(
            setup_runtime,
            decode_hex(drpc[&setup_code_id].as_str().unwrap())
        );
        assert_eq!(
            keccak_hex(&migration_runtime),
            required_str(&migration_asset["deployments"]["canonical"], "codeHash")
        );
        assert_eq!(
            keccak_hex(&setup_runtime),
            required_str(&setup_asset["deployments"]["canonical"], "codeHash")
        );

        assert_eq!(rpc_address(&drpc[&getter_base]), address(migration_address));
        assert_eq!(
            rpc_address(&drpc[&(getter_base + 1)]),
            address(safe_address)
        );
        assert_eq!(
            rpc_address(&drpc[&(getter_base + 2)]),
            address(safe_l2_address)
        );
        assert_eq!(
            rpc_address(&drpc[&(getter_base + 3)]),
            address(fallback_address)
        );

        let migration_source = fs::read_to_string(
            evidence()
                .join("source")
                .join(source_version)
                .join("SafeMigration.sol"),
        )
        .expect("migration source");
        let setup_source = fs::read_to_string(
            evidence()
                .join("source")
                .join(source_version)
                .join("SafeToL2Setup.sol"),
        )
        .expect("setup source");
        assert_source_semantics(&migration_source, &setup_source, version);
    }
}

#[test]
fn safe_migration_descriptors_pin_deployments_intents_and_refusal_boundary() {
    let versions = [
        (
            "1.4.1",
            "calldata-SafeMigration-1.4.1.json",
            "calldata-SafeToL2Setup-1.4.1.json",
            "deployments/v1.4.1/safe_migration.json",
            "deployments/v1.4.1/safe_to_l2_setup.json",
            7,
        ),
        (
            "1.5.0",
            "calldata-SafeMigration-1.5.0.json",
            "calldata-SafeToL2Setup-1.5.0.json",
            "deployments/v1.5.0/safe_migration.json",
            "deployments/v1.5.0/safe_to_l2_setup.json",
            2,
        ),
    ];
    for (
        version,
        migration_name,
        setup_name,
        migration_asset_path,
        setup_asset_path,
        expected_count,
    ) in versions
    {
        let migration = descriptor(migration_name);
        let setup = descriptor(setup_name);
        let migration_asset = read_json(&evidence().join(migration_asset_path));
        let setup_asset = read_json(&evidence().join(setup_asset_path));

        for (document, asset, name) in [
            (&migration, &migration_asset, migration_name),
            (&setup, &setup_asset, setup_name),
        ] {
            let deployments = descriptor_deployments(document);
            assert_eq!(deployments.len(), expected_count);
            for (chain_id, contract) in &deployments {
                assert!(
                    deployment_addresses(asset, *chain_id).contains(contract),
                    "{name} contains a deployment absent from the official manifest"
                );
            }
            let admissions = document["_pqsigner"]["deploymentFormats"]
                .as_array()
                .expect("deploymentFormats");
            assert_eq!(admissions.len(), expected_count);
            assert_eq!(
                admissions
                    .iter()
                    .map(|admission| (
                        admission["chainId"].as_u64().expect("chain id"),
                        address(required_str(admission, "address"))
                    ))
                    .collect::<BTreeSet<_>>(),
                deployments
            );
            let curated = root().join(format!(
                "secure/data/erc7730/curations/files/registry/safe/{name}"
            ));
            assert_eq!(
                fs::read(root().join(format!("secure/data/erc7730-registry/registry/safe/{name}")))
                    .unwrap(),
                fs::read(curated).expect("curated Safe migration replacement")
            );
        }

        assert_eq!(
            migration["_pqsigner"]["refusalOnlyFormats"]
                .as_array()
                .expect("migration refusal markers")
                .iter()
                .map(|format| format.as_str().expect("refusal format"))
                .collect::<BTreeSet<_>>(),
            MIGRATION_REFUSED_SOURCE.into_iter().collect()
        );
        for admission in migration["_pqsigner"]["deploymentFormats"]
            .as_array()
            .unwrap()
        {
            assert_eq!(
                admission["formats"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|format| format.as_str().unwrap())
                    .collect::<BTreeSet<_>>(),
                MIGRATION_ADMITTED_SOURCE.into_iter().collect()
            );
        }
        for admission in setup["_pqsigner"]["deploymentFormats"].as_array().unwrap() {
            assert_eq!(
                admission["formats"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|format| format.as_str().unwrap())
                    .collect::<Vec<_>>(),
                vec![SETUP_SOURCE]
            );
        }
        assert!(setup["_pqsigner"].get("refusalOnlyFormats").is_none());

        assert_eq!(
            migration["metadata"]["contractName"].as_str(),
            Some(format!("Safe Migration {version}").as_str())
        );
        assert_eq!(
            setup["metadata"]["contractName"].as_str(),
            Some(format!("Safe L2 Setup {version}").as_str())
        );
        let formats = migration["display"]["formats"]
            .as_object()
            .expect("migration formats");
        assert_eq!(
            formats[MIGRATION_ADMITTED_SOURCE[0]]["intent"].as_str(),
            Some(format!("Migrate Safe to {version}").as_str())
        );
        assert_eq!(
            formats[MIGRATION_ADMITTED_SOURCE[1]]["intent"].as_str(),
            Some(format!("Migrate Safe L2 to {version}").as_str())
        );
        for signature in MIGRATION_ADMITTED_SOURCE {
            let fields = formats[signature]["fields"].as_array().unwrap();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0]["path"].as_str(), Some("@.to"));
            assert_eq!(fields[0]["visible"].as_str(), Some("always"));
        }
        let setup_format = &setup["display"]["formats"][SETUP_SOURCE];
        assert_eq!(
            setup_format["intent"].as_str(),
            Some("Set L2 singleton off Ethereum")
        );
        assert_eq!(
            setup_format["fields"][0]["path"].as_str(),
            Some("l2Singleton")
        );
        assert_eq!(
            setup_format["fields"][0]["label"].as_str(),
            Some("L2 singleton")
        );
        assert_eq!(
            setup_format["fields"][0]["visible"].as_str(),
            Some("always")
        );
    }
}

#[test]
fn safe_migration_catalogue_binds_admitted_routes_and_keeps_fallback_exact_known() {
    let registry = build_registry();
    let resolver = NameResolver::new();
    let signer = [0x44; 20];
    let migration_admitted = MIGRATION_ADMITTED_CANONICAL
        .into_iter()
        .map(selector)
        .collect::<BTreeSet<_>>();
    let migration_refused = MIGRATION_REFUSED_CANONICAL
        .into_iter()
        .map(selector)
        .collect::<BTreeSet<_>>();

    let sources = [
        (
            "1.4.1",
            "calldata-SafeMigration-1.4.1.json",
            "calldata-SafeToL2Setup-1.4.1.json",
            7,
        ),
        (
            "1.5.0",
            "calldata-SafeMigration-1.5.0.json",
            "calldata-SafeToL2Setup-1.5.0.json",
            2,
        ),
    ];
    for (version, migration_source, setup_source, expected_count) in sources {
        let migration_entries = registry
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(migration_source)
            })
            .collect::<Vec<_>>();
        assert_eq!(migration_entries.len(), expected_count);
        for entry in migration_entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("migration IR");
            assert_eq!(ir.format_count(), Ok(2));
            assert_eq!(
                ir.format_iter()
                    .map(|format| format.expect("format").selector)
                    .collect::<BTreeSet<_>>(),
                migration_admitted
            );
            let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
            let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("proof");
            assert_eq!(
                cross_check_contract(&verified.ir, entry.chain_id, &entry.contract),
                Ok(())
            );

            for refused in migration_refused.iter().copied() {
                assert!(ir.find_format_by_selector(&refused).unwrap().is_none());
                assert!(registry
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, refused)));
                assert!(known_call_may_contain(
                    &registry.known_calls_bloom,
                    entry.chain_id,
                    &entry.contract,
                    &refused
                ));
            }

            let tx = Eip1559Tx {
                chain_id: entry.chain_id,
                to: Some(entry.contract),
                ..Eip1559Tx::default()
            };
            let direct = render_erc7730_pages_with_signer_checked(
                &tx,
                &calldata(MIGRATION_ADMITTED_CANONICAL[0], &[]),
                &verified,
                None,
                &resolver,
                &signer,
            )
            .expect("render Safe migration");
            let l2 = render_erc7730_pages_with_signer_checked(
                &tx,
                &calldata(MIGRATION_ADMITTED_CANONICAL[1], &[]),
                &verified,
                None,
                &resolver,
                &signer,
            )
            .expect("render Safe L2 migration");
            assert!(direct.transcript_receipt.range_matches(&direct.pages, 0));
            assert!(l2.transcript_receipt.range_matches(&l2.pages, 0));
            assert!(pages_text(&direct.pages).contains(&format!("Migrate Safe to {version}")));
            assert!(pages_text(&l2.pages).contains(&format!("Migrate Safe L2 to {version}")));
            assert_ne!(direct.pages.as_slice(), l2.pages.as_slice());
            assert!(!direct
                .transcript_receipt
                .exact_match(&l2.transcript_receipt));
        }

        let setup_entries = registry
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(setup_source)
            })
            .collect::<Vec<_>>();
        assert_eq!(setup_entries.len(), expected_count);
        for entry in setup_entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("setup IR");
            assert_eq!(ir.format_count(), Ok(1));
            assert!(ir
                .find_format_by_selector(&selector(SETUP_CANONICAL))
                .unwrap()
                .is_some());
            let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
            let verified = verify_erc7730_bundle(&bundle, &registry.root).expect("proof");
            assert_eq!(
                cross_check_contract(&verified.ir, entry.chain_id, &entry.contract),
                Ok(())
            );
            let tx = Eip1559Tx {
                chain_id: entry.chain_id,
                to: Some(entry.contract),
                ..Eip1559Tx::default()
            };
            let call = calldata(SETUP_CANONICAL, &[word_address([0x11; 20])]);
            let rendered = render_erc7730_pages_with_signer_checked(
                &tx, &call, &verified, None, &resolver, &signer,
            )
            .expect("render Safe L2 setup");
            assert!(rendered
                .transcript_receipt
                .range_matches(&rendered.pages, 0));
            let text = pages_text(&rendered.pages);
            assert!(text.contains("Set L2 singleton off Ethereum"));
            assert!(text.contains("L2 singleton"));

            let changed_call = calldata(SETUP_CANONICAL, &[word_address([0x12; 20])]);
            let changed = render_erc7730_pages_with_signer_checked(
                &tx,
                &changed_call,
                &verified,
                None,
                &resolver,
                &signer,
            )
            .expect("render mutated Safe L2 setup");
            assert_ne!(rendered.pages.as_slice(), changed.pages.as_slice());
            assert!(!rendered
                .transcript_receipt
                .exact_match(&changed.transcript_receipt));
        }
    }
}
