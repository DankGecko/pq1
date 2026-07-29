//! Offline evidence, semantic-display, compiled-IR, and exact-refusal checks for
//! the bounded P2P pod/message slice tracked by PQ1 issue #497.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EIGEN_FILE: &str = "calldata-EigenPodManager.json";
const MESSAGE_FILE: &str = "calldata-P2pMessageSender.json";
const EIP1967_IMPLEMENTATION_SLOT: &str =
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const EIGEN_DEPLOYMENTS: [(u64, &str); 2] = [
    (1, "0x91e677b07f7af907ec9a428aafa9fc14a0d3a338"),
    (560_048, "0xcd1442415fc5c29aa848a49d2e232720be07976c"),
];
const MESSAGE_DEPLOYMENTS: [(u64, &str); 3] = [
    (1, "0x4e1224f513048e18e7a1883985b45dc0fe1d917e"),
    (560_048, "0x917105cc314c12890d9c8224aee5af9574f871cf"),
    (560_048, "0x158f2bbef21cf9f92cf4a294999ba422948c8242"),
];
const EIGEN_REFUSED: [&str; 14] = [
    "addShares(address,address,uint256)",
    "increaseBurnOrRedistributableShares((address,uint32),uint256,address,uint256)",
    "initialize(address,uint256)",
    "pause(uint256)",
    "pauseAll()",
    "recordBeaconChainETHBalanceUpdate(address,uint256,int256)",
    "removeDepositShares(address,address,uint256)",
    "renounceOwnership()",
    "setPectraForkTimestamp(uint64)",
    "setProofTimestampSetter(address)",
    "stake(bytes,bytes,bytes32)",
    "transferOwnership(address)",
    "unpause(uint256)",
    "withdrawSharesAsTokens(address,address,address,uint256)",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/p2p-pod-message")
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

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("selector width")
}

fn address(text: &str) -> [u8; 20] {
    hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .expect("hex address")
        .try_into()
        .expect("address width")
}

fn runtime(name: &str) -> String {
    let path = if name.contains('/') {
        evidence_root().join(name)
    } else {
        evidence_root().join("runtime").join(name)
    };
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read runtime {name}: {error}"))
        .trim()
        .to_string()
}

fn runtime_bytes(name: &str) -> Vec<u8> {
    hex::decode(runtime(name).strip_prefix("0x").unwrap()).expect("runtime hex")
}

fn collect_files(root: &Path, directory: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let entry = entry.expect("evidence entry");
        let path = entry.path();
        let ty = entry.file_type().expect("evidence file type");
        assert!(!ty.is_symlink(), "evidence may not contain symlinks");
        if ty.is_dir() {
            collect_files(root, &path, out);
        } else {
            assert!(ty.is_file(), "unsupported evidence entry");
            let relative = path
                .strip_prefix(root)
                .expect("evidence path remains below root")
                .to_str()
                .expect("UTF-8 evidence path")
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn record<'a>(receipt: &'a Value, kind: &str, target: &str) -> &'a Value {
    receipt
        .as_array()
        .expect("RPC receipt array")
        .iter()
        .find(|entry| entry["kind"] == kind && entry["target"] == target)
        .unwrap_or_else(|| panic!("missing RPC record {kind} {target}"))
}

fn result<'a>(receipt: &'a Value, kind: &str, target: &str) -> &'a str {
    required_str(&record(receipt, kind, target)["response"], "result")
}

fn assert_rpc_agreement(left: &Value, right: &Value) {
    let project = |receipt: &Value| {
        receipt
            .as_array()
            .expect("RPC receipt array")
            .iter()
            .map(|entry| {
                assert!(entry["response"].get("error").is_none());
                (
                    required_str(entry, "kind").to_string(),
                    required_str(entry, "target").to_string(),
                    entry["request"]["method"].clone(),
                    entry["request"]["params"].clone(),
                    entry["response"]["result"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        project(left),
        project(right),
        "independent RPC results differ"
    );
}

fn assert_fixed_block(receipt: &Value, chain: &str, fixed: &Value) {
    let block = &record(receipt, "block_header", chain)["response"]["result"];
    assert_eq!(block["number"], fixed["number_hex"]);
    assert_eq!(block["hash"], fixed["hash"]);
    assert_eq!(block["stateRoot"], fixed["state_root"]);
    assert_eq!(
        block["timestamp"],
        format!("0x{:x}", fixed["timestamp"].as_u64().unwrap())
    );
}

fn word_address(address: &str) -> String {
    format!(
        "0x{:0>64}",
        address.strip_prefix("0x").unwrap_or(address).to_lowercase()
    )
}

fn strip_solidity_metadata(bytes: &[u8]) -> &[u8] {
    assert!(bytes.len() >= 2, "runtime includes metadata length");
    let metadata_len = usize::from(u16::from_be_bytes(
        bytes[bytes.len() - 2..].try_into().unwrap(),
    ));
    assert!(
        bytes.len() >= metadata_len + 2,
        "metadata length remains within runtime"
    );
    &bytes[..bytes.len() - metadata_len - 2]
}

fn abi_type(input: &Value) -> String {
    match required_str(input, "type") {
        "tuple" => format!(
            "({})",
            input["components"]
                .as_array()
                .expect("tuple components")
                .iter()
                .map(abi_type)
                .collect::<Vec<_>>()
                .join(",")
        ),
        other => other.to_string(),
    }
}

fn mutating_abi_signatures(abi: &Value) -> BTreeSet<String> {
    abi.as_array()
        .expect("ABI array")
        .iter()
        .filter(|entry| {
            entry["type"] == "function"
                && matches!(
                    required_str(entry, "stateMutability"),
                    "nonpayable" | "payable"
                )
        })
        .map(|entry| {
            let inputs = entry["inputs"]
                .as_array()
                .expect("function inputs")
                .iter()
                .map(abi_type)
                .collect::<Vec<_>>()
                .join(",");
            format!("{}({inputs})", required_str(entry, "name"))
        })
        .collect()
}

fn descriptor(name: &str) -> Value {
    read_json(
        &workspace_root()
            .join("secure/data/erc7730/curations/files/registry/p2p")
            .join(name),
    )
}

fn visible_paths(format: &Value) -> BTreeSet<String> {
    format["fields"]
        .as_array()
        .expect("format fields")
        .iter()
        .filter(|field| field["visible"] == "always")
        .filter_map(|field| field["path"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

fn build_registry() -> dbgen::erc7730::Erc7730BuildResult {
    let root = workspace_root();
    let registry_root = root.join("secure/data/erc7730-registry");
    let capabilities = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("production ERC20 capability corpus");
    build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &capabilities.capabilities,
    )
    .expect("build curated registry")
    .0
}

#[test]
fn p2p_evidence_inventory_rpc_and_runtime_bindings_are_exact() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["descriptor_families"]
            .as_array()
            .unwrap()
            .iter()
            .map(|family| family["admitted_leaf_count"].as_u64().unwrap())
            .sum::<u64>(),
        5
    );
    let boundary = required_str(&manifest, "boundary");
    for excluded in [
        "live pause",
        "off-chain message-processing",
        "transaction-success",
        "future-upgrade/deployment",
        "blind-signing",
    ] {
        assert!(boundary.contains(excluded), "missing boundary: {excluded}");
    }

    let mut actual = BTreeSet::new();
    collect_files(&root, &root, &mut actual);
    let artifacts = manifest["artifacts"].as_array().expect("artifact receipts");
    let expected = artifacts
        .iter()
        .map(|artifact| required_str(artifact, "path").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "evidence inventory must be exact");
    for artifact in artifacts {
        let path = root.join(required_str(artifact, "path"));
        let bytes = fs::read(&path).expect("read receipted artifact");
        assert_eq!(artifact["bytes"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(
            required_str(artifact, "sha256"),
            hex::encode(Sha256::digest(&bytes)),
            "hash receipt changed: {}",
            path.display()
        );
    }

    let eth_drpc = read_json(&root.join("rpc/ethereum-drpc.json"));
    let eth_mev = read_json(&root.join("rpc/ethereum-mevblocker.json"));
    let hoodi_drpc = read_json(&root.join("rpc/hoodi-drpc.json"));
    let hoodi_panda = read_json(&root.join("rpc/hoodi-ethpandaops.json"));
    assert_rpc_agreement(&eth_drpc, &eth_mev);
    assert_rpc_agreement(&hoodi_drpc, &hoodi_panda);
    assert_fixed_block(&eth_drpc, "ethereum", &manifest["fixed_blocks"][0]);
    assert_fixed_block(&eth_mev, "ethereum", &manifest["fixed_blocks"][0]);
    assert_fixed_block(&hoodi_drpc, "hoodi", &manifest["fixed_blocks"][1]);
    assert_fixed_block(&hoodi_panda, "hoodi", &manifest["fixed_blocks"][1]);

    let eigen = &manifest["eigen_pod_manager"];
    for (index, receipt) in [&eth_drpc, &hoodi_drpc].into_iter().enumerate() {
        let deployment = &eigen["deployments"][index];
        let proxy = required_str(deployment, "proxy");
        let implementation = required_str(deployment, "implementation");
        assert_eq!(
            result(receipt, "proxy_code", proxy),
            runtime(required_str(deployment, "proxy_runtime"))
        );
        assert_eq!(
            result(receipt, "implementation_slot", proxy),
            required_str(deployment, "implementation_slot_value")
        );
        assert_eq!(
            result(receipt, "implementation_code", implementation),
            runtime(required_str(deployment, "implementation_runtime"))
        );
        for (kind, key) in [
            ("eigen_pod_beacon_call", "eigen_pod_beacon"),
            ("delegation_manager_call", "delegation_manager"),
            ("pauser_registry_call", "pauser_registry"),
        ] {
            assert_eq!(
                result(receipt, kind, proxy),
                word_address(required_str(deployment, key))
            );
        }
        assert!(
            result(receipt, "proxy_code", proxy).contains(EIP1967_IMPLEMENTATION_SLOT),
            "proxy must contain the EIP-1967 implementation slot"
        );
    }

    let mut ethereum_impl = runtime_bytes("EigenPodManager.implementation.ethereum.hex");
    let hoodi_impl = runtime_bytes("EigenPodManager.implementation.hoodi.hex");
    assert_eq!(ethereum_impl.len(), hoodi_impl.len());
    let ranges = eigen["cross_chain_variant_ranges"]
        .as_array()
        .expect("variant ranges");
    assert_eq!(ranges.len(), 13);
    for range in ranges {
        let offset = usize::try_from(range["offset"].as_u64().unwrap()).unwrap();
        let length = usize::try_from(range["length"].as_u64().unwrap()).unwrap();
        assert_eq!(length, 20);
        let ethereum = hex::decode(required_str(range, "ethereum_hex")).unwrap();
        let hoodi = hex::decode(required_str(range, "hoodi_hex")).unwrap();
        assert_eq!(&ethereum_impl[offset..offset + length], ethereum);
        assert_eq!(&hoodi_impl[offset..offset + length], hoodi);
        ethereum_impl[offset..offset + length].copy_from_slice(&hoodi);
    }
    assert_eq!(
        ethereum_impl, hoodi_impl,
        "implementations differ outside pinned immutable addresses"
    );

    let message = &manifest["p2p_message_sender"];
    let message_runtime = runtime("P2pMessageSender.hoodi.hex");
    assert_eq!(
        result(&eth_drpc, "message_code", MESSAGE_DEPLOYMENTS[0].1),
        runtime("P2pMessageSender.ethereum.hex")
    );
    for (_, address) in &MESSAGE_DEPLOYMENTS[1..] {
        assert_eq!(
            result(&hoodi_drpc, "message_code", address),
            message_runtime
        );
    }
    for (index, deployment) in message["deployments"]
        .as_array()
        .unwrap()
        .iter()
        .skip(1)
        .enumerate()
    {
        let tx_hash = required_str(deployment, "creation_tx");
        let tx = &record(&hoodi_drpc, "message_creation_tx", tx_hash)["response"]["result"];
        let receipt =
            &record(&hoodi_drpc, "message_creation_receipt", tx_hash)["response"]["result"];
        let input = required_str(tx, "input");
        assert!(input.ends_with(message_runtime.trim_start_matches("0x")));
        assert_eq!(receipt["status"], "0x1");
        assert_eq!(
            required_str(receipt, "contractAddress"),
            required_str(deployment, "address")
        );

        let explorer = read_json(&root.join(format!(
            "blockscout/P2pMessageSender.creation.hoodi-{}.json",
            if index == 0 { "a" } else { "b" }
        )));
        let explorer = &explorer["result"][0];
        assert_eq!(required_str(explorer, "txHash"), tx_hash);
        assert_eq!(required_str(explorer, "creationBytecode"), input);
        assert_eq!(
            required_str(explorer, "contractAddress"),
            required_str(deployment, "address")
        );
    }
}

#[test]
fn p2p_verified_sources_abis_and_message_instructions_are_exact() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    let eigen = read_json(&root.join("blockscout/EigenPodManager.implementation.ethereum.json"));
    let message = read_json(&root.join("blockscout/P2pMessageSender.ethereum.json"));

    for (contract, name, compiler, evm, runs, runtime_name) in [
        (
            &eigen,
            "EigenPodManager",
            "0.8.30+commit.73712a01",
            "prague",
            200,
            "EigenPodManager.implementation.ethereum.hex",
        ),
        (
            &message,
            "P2pMessageSender",
            "0.8.10+commit.fc410830",
            "london",
            200_000,
            "P2pMessageSender.ethereum.hex",
        ),
    ] {
        assert_eq!(contract["name"], name);
        assert_eq!(contract["compiler_version"], compiler);
        assert_eq!(contract["evm_version"], evm);
        assert_eq!(contract["optimization_enabled"], true);
        assert_eq!(contract["optimization_runs"].as_u64(), Some(runs));
        assert_eq!(contract["is_verified"], true);
        assert_eq!(contract["is_fully_verified"], true);
        assert_eq!(contract["is_changed_bytecode"], false);
        assert_eq!(
            required_str(contract, "deployed_bytecode"),
            runtime(runtime_name)
        );
    }

    let eigen_source =
        fs::read_to_string(root.join("source/EigenPodManager.sol")).expect("Eigen source");
    assert_eq!(
        required_str(&eigen, "source_code").trim_end(),
        eigen_source.trim_end()
    );
    for fragment in [
        "require(!hasPod(msg.sender), EigenPodAlreadyExists());",
        "bytes32(uint256(uint160(msg.sender)))",
        "abi.encodePacked(beaconProxyBytecode, abi.encode(eigenPodBeacon, \"\"))",
        "pod.initialize(msg.sender);",
        "ownerToPod[msg.sender] = pod;",
        "emit PodDeployed(address(pod), msg.sender);",
    ] {
        assert!(
            eigen_source.contains(fragment),
            "Eigen source fragment changed: {fragment}"
        );
    }
    let eigen_abi = read_json(&root.join("abi/EigenPodManager.abi.json"));
    assert_eq!(eigen["abi"], eigen_abi);
    let expected_eigen = EIGEN_REFUSED
        .into_iter()
        .chain(["createPod()"])
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(mutating_abi_signatures(&eigen_abi), expected_eigen);

    let message_source = fs::read_to_string(root.join("source/P2pMessageSender.ethereum.sol"))
        .expect("message source");
    assert_eq!(
        required_str(&message, "source_code").trim_end(),
        message_source.trim_end()
    );
    assert!(message_source
        .contains("event Message(address indexed sender, string indexed hash, string text);"));
    assert!(message_source.contains("emit Message(msg.sender, text, text);"));
    let message_abi = read_json(&root.join("abi/P2pMessageSender.abi.json"));
    assert_eq!(message["abi"], message_abi);
    assert_eq!(
        mutating_abi_signatures(&message_abi),
        BTreeSet::from(["send(string)".to_string()])
    );
    assert_eq!(
        required_str(&manifest["p2p_message_sender"], "selector"),
        format!("0x{}", hex::encode(selector("send(string)")))
    );
    assert_eq!(
        required_str(&manifest["p2p_message_sender"], "event_topic"),
        format!(
            "0x{}",
            hex::encode(keccak256(b"Message(address,string,string)"))
        )
    );

    let reconstruction = &manifest["p2p_message_sender"]["hoodi_semantic_reconstruction"];
    assert_eq!(reconstruction["exact_source_provenance"], false);
    let compiled = read_json(&root.join(required_str(reconstruction, "standard_output")));
    let compiled_runtime = hex::decode(
        compiled["contracts"]["src/P2pMessageSender.sol"]["P2pMessageSender"]["evm"]
            ["deployedBytecode"]["object"]
            .as_str()
            .expect("compiled runtime"),
    )
    .expect("compiled runtime hex");
    let onchain_runtime = runtime_bytes("P2pMessageSender.hoodi.hex");
    assert_eq!(
        strip_solidity_metadata(&compiled_runtime),
        strip_solidity_metadata(&onchain_runtime),
        "Hoodi runtime instructions must match the semantic reconstruction"
    );
    assert_eq!(
        strip_solidity_metadata(&onchain_runtime).len(),
        usize::try_from(reconstruction["instruction_bytes"].as_u64().unwrap()).unwrap()
    );
}

#[test]
fn p2p_curations_compile_only_honest_routes_and_preserve_exact_refusals() {
    let root = workspace_root();
    for name in [EIGEN_FILE, MESSAGE_FILE] {
        let installed = root
            .join("secure/data/erc7730-registry/registry/p2p")
            .join(name);
        let curated = root
            .join("secure/data/erc7730/curations/files/registry/p2p")
            .join(name);
        assert_eq!(
            fs::read(installed).expect("installed P2P descriptor"),
            fs::read(curated).expect("curated P2P descriptor")
        );
    }

    let inventory =
        read_json(&root.join("tests/erc7730-semantic-evidence/accepted-family-inventory.json"));
    assert_eq!(
        inventory["evidence_sets"]["p2p-pod-message"]["classification"],
        "pinned-evidence"
    );
    for (source, count) in [
        ("p2p/calldata-EigenPodManager.json", 2),
        ("p2p/calldata-P2pMessageSender.json", 3),
    ] {
        let family = inventory["families"]
            .as_array()
            .unwrap()
            .iter()
            .find(|family| family["source"] == source)
            .expect("P2P inventory family");
        assert_eq!(family["accepted_leaf_count"].as_u64(), Some(count));
        assert_eq!(family["classification"], "pinned-evidence");
        assert_eq!(family["evidence"], "p2p-pod-message");
        assert!(family.get("successor_issue").is_none());
    }

    let eigen = descriptor(EIGEN_FILE);
    let eigen_formats = eigen["display"]["formats"]
        .as_object()
        .expect("Eigen formats");
    assert_eq!(eigen_formats.len(), 15);
    let create = &eigen_formats["createPod()"];
    assert_eq!(create["intent"], "Create EigenPod");
    assert_eq!(
        visible_paths(create),
        BTreeSet::from(["@.from".to_string()])
    );
    let refusal_formats = eigen["_pqsigner"]["refusalOnlyFormats"]
        .as_array()
        .expect("Eigen refusals");
    assert_eq!(refusal_formats.len(), EIGEN_REFUSED.len());
    for refusal in refusal_formats {
        let format = &eigen_formats[refusal.as_str().unwrap()];
        assert_eq!(format["intent"], "Refused EigenPodManager call");
        assert_eq!(format["fields"].as_array().unwrap().len(), 0);
    }

    let message = descriptor(MESSAGE_FILE);
    let send = &message["display"]["formats"]["send(string text)"];
    assert_eq!(send["intent"], "Publish p2p message");
    assert_eq!(
        visible_paths(send),
        BTreeSet::from(["#.text".to_string(), "@.from".to_string()])
    );
    let message_text = serde_json::to_string(send).unwrap();
    assert!(!message_text.contains("Withdrawal message"));
    assert!(!message_text.contains("Public keys"));

    let registry = build_registry();
    for (file, deployments, admitted) in [
        (
            EIGEN_FILE,
            EIGEN_DEPLOYMENTS.as_slice(),
            selector("createPod()"),
        ),
        (
            MESSAGE_FILE,
            MESSAGE_DEPLOYMENTS.as_slice(),
            selector("send(string)"),
        ),
    ] {
        let entries = registry
            .entries
            .iter()
            .filter(|entry| entry.source.file_name().and_then(|name| name.to_str()) == Some(file))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), deployments.len());
        for &(chain_id, contract) in deployments {
            let contract = address(contract);
            let entry = entries
                .iter()
                .find(|entry| entry.chain_id == chain_id && entry.contract == contract)
                .expect("deployment-specific P2P IR");
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("P2P IR");
            assert_eq!(cross_check_contract(&ir, chain_id, &contract), Ok(()));
            assert_eq!(
                ir.format_iter()
                    .map(|format| format.unwrap().selector)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([admitted])
            );
        }
    }

    for (chain_id, contract) in EIGEN_DEPLOYMENTS {
        let contract = address(contract);
        let entry = registry
            .entries
            .iter()
            .find(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(EIGEN_FILE)
                    && entry.chain_id == chain_id
                    && entry.contract == contract
            })
            .unwrap();
        let ir = Erc7730Ir::parse(&entry.ir_bytes).unwrap();
        for route in EIGEN_REFUSED {
            let refused = selector(route);
            assert!(ir.find_format_by_selector(&refused).unwrap().is_none());
            assert!(registry
                .known_calls
                .contains(&(chain_id, contract, refused)));
            assert!(known_call_may_contain(
                &registry.known_calls_bloom,
                chain_id,
                &contract,
                &refused
            ));
        }
    }
}
