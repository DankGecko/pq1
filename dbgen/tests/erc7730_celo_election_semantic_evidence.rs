//! Offline evidence checks for the bounded Celo Election `vote` admission.
//!
//! The catalogue/rendering behavior is exercised in `erc7730_roundtrip` and
//! the secure display tests. This file keeps the external authority package
//! honest: every archived byte is receipted, three fixed-block RPC providers
//! agree on the proxy/implementation identity, and the verified ABI/source
//! establish the meaning of all four signed operands.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const BLOCK_HASH: &str = "0x810df7ac9ef91261a1ed3ef97f2848ec71a4f943c64715908fdeabd985bf4a3c";
const PROXY: &str = "8d6677192144292870907e3fa8a5527fe55a7ff6";
const IMPLEMENTATION: &str = "74f9e5ee4071b9b35d127000a20f8e964009cb57";
const EIP1967_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/celo-election-vote")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid archived hex")
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn response<'a>(document: &'a Value, id: &str) -> &'a Value {
    document
        .as_array()
        .expect("RPC response batch")
        .iter()
        .find(|item| item["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing RPC response id {id}"))
}

fn request<'a>(document: &'a Value, id: &str) -> &'a Value {
    document
        .as_array()
        .expect("RPC request batch")
        .iter()
        .find(|item| item["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing RPC request id {id}"))
}

fn assert_eip1898(value: &Value) {
    assert_eq!(value["blockHash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(value["requireCanonical"].as_bool(), Some(true));
    assert_eq!(value.as_object().expect("EIP-1898 object").len(), 2);
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
                .expect("evidence path remains under root")
                .to_str()
                .expect("UTF-8 evidence path")
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

#[test]
fn election_evidence_receipts_and_fixed_block_identity_are_exact() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(manifest["fixed_block"]["number"].as_u64(), Some(72_649_728));
    assert_eq!(manifest["fixed_block"]["hash"].as_str(), Some(BLOCK_HASH));

    let mut declared = BTreeSet::new();
    for artifact in manifest["artifacts"].as_array().expect("artifact receipts") {
        let relative = artifact["path"].as_str().expect("artifact path");
        assert!(
            declared.insert(relative.to_owned()),
            "duplicate receipt {relative}"
        );
        let bytes = fs::read(evidence.join(relative))
            .unwrap_or_else(|error| panic!("read evidence {relative}: {error}"));
        assert_eq!(
            sha256_hex(&bytes),
            artifact["sha256"].as_str().expect("artifact SHA-256"),
            "archived evidence drifted: {relative}"
        );
    }
    let mut actual = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut actual);
    assert_eq!(
        actual, declared,
        "every non-manifest artifact must be receipted"
    );

    let identity_request = read_json(&evidence.join("rpc/raw/request-identity.json"));
    let proxy_request = read_json(&evidence.join("rpc/raw/request-proxy.json"));
    let implementation_request = read_json(&evidence.join("rpc/raw/request-implementation.json"));
    assert_eq!(
        request(&identity_request, "chain-id")["method"],
        "eth_chainId"
    );
    assert_eq!(
        request(&identity_request, "block")["params"][0].as_str(),
        Some(BLOCK_HASH)
    );
    let election_call = request(&identity_request, "election");
    assert_eq!(election_call["method"], "eth_call");
    assert_eq!(
        election_call["params"][0]["to"].as_str(),
        Some("0x000000000000000000000000000000000000ce10")
    );
    let registry_calldata = election_call["params"][0]["data"]
        .as_str()
        .expect("Registry calldata");
    assert!(registry_calldata.starts_with("0x853db323"));
    assert!(decode_hex(registry_calldata)
        .windows(b"Election".len())
        .any(|window| window == b"Election"));
    assert_eip1898(&election_call["params"][1]);

    let slot_request = request(&proxy_request, "implementation-slot");
    assert_eq!(slot_request["method"], "eth_getStorageAt");
    assert_eq!(
        slot_request["params"][0]
            .as_str()
            .expect("proxy address")
            .trim_start_matches("0x")
            .to_ascii_lowercase(),
        PROXY
    );
    assert_eq!(slot_request["params"][1].as_str(), Some(EIP1967_SLOT));
    assert_eip1898(&slot_request["params"][2]);
    assert_eip1898(&request(&proxy_request, "proxy-code")["params"][1]);
    assert_eip1898(&request(&implementation_request, "implementation-code")["params"][1]);

    let archived_proxy = decode_hex(
        &fs::read_to_string(evidence.join("runtime/ElectionProxy.celo-mainnet.hex"))
            .expect("read proxy runtime"),
    );
    let archived_implementation = decode_hex(
        &fs::read_to_string(evidence.join("runtime/Election.implementation.celo-mainnet.hex"))
            .expect("read implementation runtime"),
    );
    assert_eq!(archived_proxy.len(), 2_585);
    assert_eq!(archived_implementation.len(), 47_571);
    assert_eq!(
        sha256_hex(&archived_proxy),
        manifest["runtimes"]["proxy"]["decoded_sha256"]
    );
    assert_eq!(
        format!("0x{}", hex::encode(keccak256(&archived_proxy))),
        manifest["runtimes"]["proxy"]["keccak256"]
    );
    assert_eq!(
        sha256_hex(&archived_implementation),
        manifest["runtimes"]["implementation"]["decoded_sha256"]
    );
    assert_eq!(
        format!("0x{}", hex::encode(keccak256(&archived_implementation))),
        manifest["runtimes"]["implementation"]["keccak256"]
    );

    for provider in ["forno", "drpc", "ankr"] {
        let identity =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-identity.json")));
        let proxy = read_json(&evidence.join(format!("rpc/raw/response-{provider}-proxy.json")));
        let implementation =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-implementation.json")));
        assert_eq!(response(&identity, "chain-id")["result"], "0xa4ec");
        let block = &response(&identity, "block")["result"];
        assert_eq!(block["number"], "0x4548c00");
        assert_eq!(block["hash"], BLOCK_HASH);
        assert_eq!(
            block["stateRoot"],
            "0x16ef9a83ecb75fd3214684fe2a8c9a2ff91a60a483d1eff5886b9a55b10ae855"
        );
        let election = decode_hex(
            response(&identity, "election")["result"]
                .as_str()
                .expect("Election Registry result"),
        );
        assert_eq!(&election[..12], &[0u8; 12]);
        assert_eq!(hex::encode(&election[12..]), PROXY);
        let slot = decode_hex(
            response(&proxy, "implementation-slot")["result"]
                .as_str()
                .expect("implementation slot result"),
        );
        assert_eq!(&slot[..12], &[0u8; 12]);
        assert_eq!(hex::encode(&slot[12..]), IMPLEMENTATION);
        assert_eq!(
            decode_hex(response(&proxy, "proxy-code")["result"].as_str().unwrap()),
            archived_proxy,
            "proxy runtime disagreement at {provider}"
        );
        assert_eq!(
            decode_hex(
                response(&implementation, "implementation-code")["result"]
                    .as_str()
                    .unwrap(),
            ),
            archived_implementation,
            "implementation runtime disagreement at {provider}"
        );
    }
}

#[test]
fn election_verified_source_and_abi_bind_all_vote_operands() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let proxy = read_json(&evidence.join("blockscout/ElectionProxy.json"));
    let implementation = read_json(&evidence.join("blockscout/Election.implementation.json"));
    assert_eq!(proxy["is_verified"].as_bool(), Some(true));
    assert_eq!(proxy["is_fully_verified"].as_bool(), Some(false));
    assert_eq!(proxy["proxy_type"].as_str(), Some("eip1967"));
    assert_eq!(implementation["name"].as_str(), Some("Election"));
    assert_eq!(implementation["is_verified"].as_bool(), Some(true));
    assert_eq!(implementation["is_fully_verified"].as_bool(), Some(false));

    let proxy_runtime = decode_hex(
        &fs::read_to_string(evidence.join("runtime/ElectionProxy.celo-mainnet.hex")).unwrap(),
    );
    let implementation_runtime = decode_hex(
        &fs::read_to_string(evidence.join("runtime/Election.implementation.celo-mainnet.hex"))
            .unwrap(),
    );
    assert_eq!(
        decode_hex(proxy["deployed_bytecode"].as_str().unwrap()),
        proxy_runtime
    );
    assert_eq!(
        decode_hex(implementation["deployed_bytecode"].as_str().unwrap()),
        implementation_runtime
    );

    let election_source =
        fs::read_to_string(evidence.join("source/Election.sol")).expect("Election source");
    assert_eq!(
        implementation["source_code"].as_str(),
        Some(election_source.as_str()),
        "official pinned Election.sol must match the explorer primary source byte-for-byte"
    );
    assert_eq!(
        sha256_hex(election_source.as_bytes()),
        "f4f897289538a084161c179ddf61dbd06284f8aec521c794c8c0a0912241d191"
    );
    let source = normalized(&election_source);
    for claim in [
        "function vote( address group, uint256 value, address lesser, address greater ) external nonReentrant onlyWhenNotBlocked returns (bool)",
        "address account = getAccounts().voteSignerToAccount(msg.sender);",
        "incrementPendingVotes(group, account, value);",
        "incrementTotalVotes(account, group, value, lesser, greater);",
        "getLockedGold().decrementNonvotingAccountBalance(account, value);",
        "emit ValidatorGroupVoteCast(account, group, value);",
        "The amount of gold to use to vote.",
        "The group receiving fewer votes than `group`, or 0",
        "The group receiving more votes than `group`, or 0",
    ] {
        assert!(source.contains(claim), "Election semantic source claim drifted: {claim}");
    }
    let accounts = normalized(&fs::read_to_string(evidence.join("source/Accounts.sol")).unwrap());
    assert!(accounts
        .contains("function voteSignerToAccount(address signer) external view returns (address)"));
    let gold = normalized(&fs::read_to_string(evidence.join("source/GoldToken.sol")).unwrap());
    assert!(gold.contains("string constant SYMBOL = \"CELO\";"));
    assert!(gold.contains("uint8 constant DECIMALS = 18;"));
    assert!(
        gold.contains("function symbol() external view returns (string memory) { return SYMBOL; }")
    );
    assert!(gold.contains("function decimals() external view returns (uint8) { return DECIMALS; }"));

    let abi = read_json(&evidence.join("abi/Election.vote.abi.json"));
    let function = &abi.as_array().expect("vote ABI array")[0];
    assert_eq!(function["name"], "vote");
    assert_eq!(function["stateMutability"], "nonpayable");
    let inputs = function["inputs"].as_array().expect("vote ABI inputs");
    let actual = inputs
        .iter()
        .map(|input| {
            (
                input["name"].as_str().unwrap(),
                input["type"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            ("group", "address"),
            ("value", "uint256"),
            ("lesser", "address"),
            ("greater", "address"),
        ]
    );
    assert_eq!(
        format!(
            "0x{}",
            hex::encode(&keccak256(b"vote(address,uint256,address,address)")[..4])
        ),
        manifest["abi"]["selector"]
    );

    let core_contracts = fs::read_to_string(evidence.join("deployment/core-contracts.md")).unwrap();
    assert!(core_contracts.contains("0x8D6677192144292870907E3Fa8A5527fE55A7ff6"));
    let legacy = fs::read_to_string(evidence.join("deployment/contracts.py")).unwrap();
    assert!(legacy.contains("0x1c3eDf937CFc2F6F51784D20DEB1af1F9a8655fA"));
    let migration = fs::read_to_string(evidence.join("deployment/celo-sepolia.md")).unwrap();
    assert!(migration.contains("Alfajores"));
    assert!(manifest["boundary"]
        .as_str()
        .expect("honest boundary")
        .contains("does not monitor future upgrades"));
}
