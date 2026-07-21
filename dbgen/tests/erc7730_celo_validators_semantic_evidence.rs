//! Offline evidence checks for the bounded Celo Validators first-member admission.
//!
//! Catalogue and rendering behavior are exercised elsewhere. This test keeps
//! the external authority package honest: every archived byte is receipted,
//! three fixed-block RPC providers agree on deployment identity, and the
//! verified ABI/source establish the meaning and live-state limits of every
//! signed `addFirstMember` operand.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const BLOCK_HASH: &str = "0x810df7ac9ef91261a1ed3ef97f2848ec71a4f943c64715908fdeabd985bf4a3c";
const PROXY: &str = "aeb865bca93ddc8f47b8e29f40c5399ce34d0c58";
const IMPLEMENTATION: &str = "13b0b89f3242f815c1fc6c9cf56e1ab5aea4dc58";
const REGISTRY_PROXY: &str = "000000000000000000000000000000000000ce10";
const REGISTRY_IMPLEMENTATION: &str = "203fdf86a00999107df531fa00b4ba81d674cb66";
const ACCOUNTS_PROXY: &str = "7d21685c17607338b313a7174bab6620bad0aab7";
const ACCOUNTS_IMPLEMENTATION: &str = "907f5c53c0e31db06af45bc58f076563469c525a";
const ELECTION_PROXY: &str = "8d6677192144292870907e3fa8a5527fe55a7ff6";
const ELECTION_IMPLEMENTATION: &str = "74f9e5ee4071b9b35d127000a20f8e964009cb57";
const ADDRESS_LINKED_LIST: &str = "08a4b5bc1b5adef0a283c8f0185ded6169f0bd29";
const ADDRESS_SORTED_LINKED_LIST: &str = "0e3e96a0d64b59b46872432f47bed6a1825a1552";
const EIP1967_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const SELECTOR: [u8; 4] = [0x31, 0x73, 0xb8, 0xdb];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/celo-validators-first-member")
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

fn read_runtime(evidence: &Path, name: &str) -> Vec<u8> {
    decode_hex(
        &fs::read_to_string(evidence.join(format!("runtime/{name}.celo-mainnet.hex")))
            .unwrap_or_else(|error| panic!("read runtime {name}: {error}")),
    )
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn solidity_function<'a>(source: &'a str, name: &str) -> &'a str {
    let needle = format!("function {name}(");
    let mut matches = source.match_indices(&needle);
    let (start, _) = matches
        .next()
        .unwrap_or_else(|| panic!("missing Solidity function {name}"));
    assert!(
        matches.next().is_none(),
        "multiple Solidity functions named {name}"
    );
    let definition = &source[start..];
    let opening = definition
        .find('{')
        .unwrap_or_else(|| panic!("Solidity function {name} has no body"));
    assert!(
        !definition[..opening].contains(';'),
        "Solidity function {name} is only a declaration"
    );
    let mut depth = 0usize;
    for (offset, byte) in definition[opening..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("balanced Solidity braces");
                if depth == 0 {
                    return &definition[..opening + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("Solidity function {name} has no closing brace")
}

fn solidity_natspec<'a>(source: &'a str, name: &str) -> &'a str {
    let function_start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("missing Solidity function {name}"));
    let comment_start = source[..function_start]
        .rfind("/**")
        .unwrap_or_else(|| panic!("missing Natspec for {name}"));
    let comment_end = source[comment_start..function_start]
        .rfind("*/")
        .map(|offset| comment_start + offset + 2)
        .expect("closed Natspec");
    &source[comment_start..comment_end]
}

fn abi_function<'a>(abi: &'a Value, name: &str) -> &'a Value {
    let matches = abi
        .as_array()
        .expect("ABI array")
        .iter()
        .filter(|item| item["type"].as_str() == Some("function") && item["name"] == name)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "ABI must contain exactly one {name}");
    matches[0]
}

fn response<'a>(document: &'a Value, id: &str) -> &'a Value {
    let item = document
        .as_array()
        .expect("RPC response batch")
        .iter()
        .find(|item| item["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing RPC response id {id}"));
    assert!(
        item.get("error").is_none() || item["error"].is_null(),
        "archived RPC response {id} contains an error"
    );
    item
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

fn rpc_address(document: &Value, id: &str) -> String {
    let bytes = decode_hex(
        response(document, id)["result"]
            .as_str()
            .unwrap_or_else(|| panic!("RPC response {id} is not hex")),
    );
    assert_eq!(bytes.len(), 32, "RPC address result {id} is not one word");
    assert_eq!(
        &bytes[..12],
        &[0u8; 12],
        "RPC address {id} is not canonical"
    );
    hex::encode(&bytes[12..])
}

fn assert_runtime_record(record: &Value, runtime: &[u8]) {
    assert_eq!(
        decode_hex(
            record["deployed_bytecode"]
                .as_str()
                .expect("Blockscout deployed bytecode"),
        ),
        runtime
    );
    assert_eq!(record["is_changed_bytecode"].as_bool(), Some(false));
}

fn additional_source<'a>(record: &'a Value, path: &str) -> &'a str {
    let matches = record["additional_sources"]
        .as_array()
        .expect("Blockscout additional sources")
        .iter()
        .filter(|source| source["file_path"].as_str() == Some(path))
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "expected one Blockscout source {path}");
    matches[0]["source_code"]
        .as_str()
        .expect("Blockscout source code")
}

fn assert_code_request(document: &Value, id: &str, address: &str) {
    let item = request(document, id);
    assert_eq!(item["method"], "eth_getCode");
    assert_eq!(
        item["params"][0]
            .as_str()
            .expect("code address")
            .trim_start_matches("0x")
            .to_ascii_lowercase(),
        address
    );
    assert_eip1898(&item["params"][1]);
}

fn assert_slot_request(document: &Value, id: &str, address: &str) {
    let item = request(document, id);
    assert_eq!(item["method"], "eth_getStorageAt");
    assert_eq!(
        item["params"][0]
            .as_str()
            .expect("proxy address")
            .trim_start_matches("0x")
            .to_ascii_lowercase(),
        address
    );
    assert_eq!(item["params"][1].as_str(), Some(EIP1967_SLOT));
    assert_eip1898(&item["params"][2]);
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
fn validators_evidence_receipts_and_fixed_block_identity_are_exact() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(manifest["fixed_block"]["chain_id"].as_u64(), Some(42_220));
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
    let dependency_state_a = read_json(&evidence.join("rpc/raw/request-dependency-state-a.json"));
    let dependency_state_b = read_json(&evidence.join("rpc/raw/request-dependency-state-b.json"));
    let registry_code_request = read_json(&evidence.join("rpc/raw/request-registry-code.json"));
    let accounts_code_request = read_json(&evidence.join("rpc/raw/request-accounts-code.json"));
    let election_code_request = read_json(&evidence.join("rpc/raw/request-election-code.json"));
    let library_code_request = read_json(&evidence.join("rpc/raw/request-library-code.json"));
    assert_eq!(
        request(&identity_request, "chain-id")["method"],
        "eth_chainId"
    );
    assert_eq!(
        request(&identity_request, "block")["params"][0].as_str(),
        Some(BLOCK_HASH)
    );
    let validators_call = request(&identity_request, "validators");
    assert_eq!(validators_call["method"], "eth_call");
    assert_eq!(
        validators_call["params"][0]["to"].as_str(),
        Some("0x000000000000000000000000000000000000ce10")
    );
    let registry_calldata = validators_call["params"][0]["data"]
        .as_str()
        .expect("Registry calldata");
    assert!(registry_calldata.starts_with("0x853db323"));
    let registry_calldata = decode_hex(registry_calldata);
    assert!(registry_calldata
        .windows(b"Validators".len())
        .any(|window| window == b"Validators"));
    assert_eip1898(&validators_call["params"][1]);

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
    let implementation_code = request(&implementation_request, "implementation-code");
    assert_eq!(
        implementation_code["params"][0]
            .as_str()
            .expect("implementation address")
            .trim_start_matches("0x")
            .to_ascii_lowercase(),
        IMPLEMENTATION
    );
    assert_eip1898(&implementation_code["params"][1]);

    let validators_registry = request(&dependency_state_a, "validators-registry");
    assert_eq!(validators_registry["method"], "eth_call");
    assert_eq!(
        validators_registry["params"][0]["to"]
            .as_str()
            .expect("Validators proxy")
            .trim_start_matches("0x")
            .to_ascii_lowercase(),
        PROXY
    );
    assert_eq!(validators_registry["params"][0]["data"], "0x7b103999");
    assert_eip1898(&validators_registry["params"][1]);
    assert_slot_request(
        &dependency_state_a,
        "registry-implementation-slot",
        REGISTRY_PROXY,
    );
    let accounts_lookup = request(&dependency_state_a, "accounts");
    let election_lookup = request(&dependency_state_b, "election");
    for (lookup, name) in [(accounts_lookup, "Accounts"), (election_lookup, "Election")] {
        assert_eq!(lookup["method"], "eth_call");
        assert_eq!(
            lookup["params"][0]["to"]
                .as_str()
                .expect("Registry proxy")
                .trim_start_matches("0x")
                .to_ascii_lowercase(),
            REGISTRY_PROXY
        );
        let calldata = decode_hex(
            lookup["params"][0]["data"]
                .as_str()
                .expect("Registry lookup calldata"),
        );
        assert_eq!(&calldata[..4], &[0x85, 0x3d, 0xb3, 0x23]);
        assert!(
            calldata
                .windows(name.len())
                .any(|window| window == name.as_bytes()),
            "Registry lookup lost {name}"
        );
        assert_eip1898(&lookup["params"][1]);
    }
    assert_slot_request(
        &dependency_state_b,
        "accounts-implementation-slot",
        ACCOUNTS_PROXY,
    );
    assert_slot_request(
        &dependency_state_b,
        "election-implementation-slot",
        ELECTION_PROXY,
    );
    for (document, id, address) in [
        (
            &registry_code_request,
            "registry-proxy-code",
            REGISTRY_PROXY,
        ),
        (
            &registry_code_request,
            "registry-implementation-code",
            REGISTRY_IMPLEMENTATION,
        ),
        (
            &accounts_code_request,
            "accounts-proxy-code",
            ACCOUNTS_PROXY,
        ),
        (
            &accounts_code_request,
            "accounts-implementation-code",
            ACCOUNTS_IMPLEMENTATION,
        ),
        (
            &election_code_request,
            "election-proxy-code",
            ELECTION_PROXY,
        ),
        (
            &election_code_request,
            "election-implementation-code",
            ELECTION_IMPLEMENTATION,
        ),
        (
            &library_code_request,
            "address-linked-list-code",
            ADDRESS_LINKED_LIST,
        ),
        (
            &library_code_request,
            "address-sorted-linked-list-code",
            ADDRESS_SORTED_LINKED_LIST,
        ),
    ] {
        assert_code_request(document, id, address);
    }

    let archived_proxy = decode_hex(
        &fs::read_to_string(evidence.join("runtime/ValidatorsProxy.celo-mainnet.hex"))
            .expect("read proxy runtime"),
    );
    let archived_implementation = decode_hex(
        &fs::read_to_string(evidence.join("runtime/Validators.implementation.celo-mainnet.hex"))
            .expect("read implementation runtime"),
    );
    let registry_proxy_runtime = read_runtime(&evidence, "RegistryProxy");
    let registry_implementation_runtime = read_runtime(&evidence, "Registry.implementation");
    let accounts_proxy_runtime = read_runtime(&evidence, "AccountsProxy");
    let accounts_implementation_runtime = read_runtime(&evidence, "Accounts.implementation");
    let election_proxy_runtime = read_runtime(&evidence, "ElectionProxy");
    let election_implementation_runtime = read_runtime(&evidence, "Election.implementation");
    let address_linked_list_runtime = read_runtime(&evidence, "AddressLinkedList");
    let address_sorted_linked_list_runtime = read_runtime(&evidence, "AddressSortedLinkedList");
    assert_eq!(archived_proxy.len(), 2_585);
    assert_eq!(archived_implementation.len(), 33_037);
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
    assert_eq!(
        archived_implementation
            .windows(SELECTOR.len())
            .filter(|window| *window == SELECTOR)
            .count(),
        2,
        "captured implementation lost the addFirstMember selector"
    );
    for (key, runtime, expected_len, expected_sha256) in [
        (
            "registry_proxy",
            registry_proxy_runtime.as_slice(),
            2_585,
            "f266810b196e706592258066094b4652c54391cb948ffb9b4287ba61417aa2fc",
        ),
        (
            "registry_implementation",
            registry_implementation_runtime.as_slice(),
            4_195,
            "651f3a842f4ba674e377e8a933ef588e467c6fa48fea20027639951975bd68e2",
        ),
        (
            "accounts_proxy",
            accounts_proxy_runtime.as_slice(),
            2_585,
            "8ea6a07a465e641ec6f32c2b7c9c8ef0747fa479bfd26ebd187a18d2ab3856d7",
        ),
        (
            "accounts_implementation",
            accounts_implementation_runtime.as_slice(),
            35_259,
            "47ac441dc1897e5be647b92732f096041ff7f4dffa6864cc64977c89d5a794b1",
        ),
        (
            "election_proxy",
            election_proxy_runtime.as_slice(),
            2_585,
            "a61442fd4c5488d47304b69f1095df7d43f84452c6ec167240aedad24b15b07e",
        ),
        (
            "election_implementation",
            election_implementation_runtime.as_slice(),
            47_571,
            "d66474681b8923edb1b0b9e6ecc70d83e65b275af05cd2b410d7ec10c2c73694",
        ),
        (
            "address_linked_list",
            address_linked_list_runtime.as_slice(),
            4_491,
            "a1e45118579de1f1481c0e9d8b50e949f61edea07352372d843dd3ac2f79c7aa",
        ),
        (
            "address_sorted_linked_list",
            address_sorted_linked_list_runtime.as_slice(),
            7_118,
            "23fcda9b5b8b3a2f78ea364215b01a0372c521944fa0ea41bfa1cba2c0d6aa43",
        ),
    ] {
        assert_eq!(runtime.len(), expected_len, "runtime length drifted: {key}");
        assert_eq!(
            sha256_hex(runtime),
            expected_sha256,
            "runtime drifted: {key}"
        );
        assert_eq!(
            manifest["runtimes"][key]["bytes"].as_u64(),
            Some(expected_len as u64)
        );
        assert_eq!(
            manifest["runtimes"][key]["decoded_sha256"].as_str(),
            Some(expected_sha256)
        );
    }

    for provider in ["forno", "drpc", "ankr"] {
        let identity =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-identity.json")));
        let proxy = read_json(&evidence.join(format!("rpc/raw/response-{provider}-proxy.json")));
        let implementation =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-implementation.json")));
        let dependency_state_a = read_json(&evidence.join(format!(
            "rpc/raw/response-{provider}-dependency-state-a.json"
        )));
        let dependency_state_b = read_json(&evidence.join(format!(
            "rpc/raw/response-{provider}-dependency-state-b.json"
        )));
        let registry_code =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-registry-code.json")));
        let accounts_code =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-accounts-code.json")));
        let election_code =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-election-code.json")));
        let library_code =
            read_json(&evidence.join(format!("rpc/raw/response-{provider}-library-code.json")));
        assert_eq!(response(&identity, "chain-id")["result"], "0xa4ec");
        let block = &response(&identity, "block")["result"];
        assert_eq!(block["number"], "0x4548c00");
        assert_eq!(block["hash"], BLOCK_HASH);
        assert_eq!(
            block["stateRoot"],
            "0x16ef9a83ecb75fd3214684fe2a8c9a2ff91a60a483d1eff5886b9a55b10ae855"
        );
        let validators = decode_hex(
            response(&identity, "validators")["result"]
                .as_str()
                .expect("Validators Registry result"),
        );
        assert_eq!(validators.len(), 32);
        assert_eq!(&validators[..12], &[0u8; 12]);
        assert_eq!(hex::encode(&validators[12..]), PROXY);
        let slot = decode_hex(
            response(&proxy, "implementation-slot")["result"]
                .as_str()
                .expect("implementation slot result"),
        );
        assert_eq!(slot.len(), 32);
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
        assert_eq!(
            rpc_address(&dependency_state_a, "validators-registry"),
            REGISTRY_PROXY,
            "Validators Registry pointer disagreement at {provider}"
        );
        assert_eq!(
            rpc_address(&dependency_state_a, "registry-implementation-slot"),
            REGISTRY_IMPLEMENTATION,
            "Registry implementation disagreement at {provider}"
        );
        assert_eq!(
            rpc_address(&dependency_state_a, "accounts"),
            ACCOUNTS_PROXY,
            "Accounts Registry entry disagreement at {provider}"
        );
        assert_eq!(
            rpc_address(&dependency_state_b, "election"),
            ELECTION_PROXY,
            "Election Registry entry disagreement at {provider}"
        );
        assert_eq!(
            rpc_address(&dependency_state_b, "accounts-implementation-slot"),
            ACCOUNTS_IMPLEMENTATION,
            "Accounts implementation disagreement at {provider}"
        );
        assert_eq!(
            rpc_address(&dependency_state_b, "election-implementation-slot"),
            ELECTION_IMPLEMENTATION,
            "Election implementation disagreement at {provider}"
        );
        for (document, id, expected) in [
            (
                &registry_code,
                "registry-proxy-code",
                registry_proxy_runtime.as_slice(),
            ),
            (
                &registry_code,
                "registry-implementation-code",
                registry_implementation_runtime.as_slice(),
            ),
            (
                &accounts_code,
                "accounts-proxy-code",
                accounts_proxy_runtime.as_slice(),
            ),
            (
                &accounts_code,
                "accounts-implementation-code",
                accounts_implementation_runtime.as_slice(),
            ),
            (
                &election_code,
                "election-proxy-code",
                election_proxy_runtime.as_slice(),
            ),
            (
                &election_code,
                "election-implementation-code",
                election_implementation_runtime.as_slice(),
            ),
            (
                &library_code,
                "address-linked-list-code",
                address_linked_list_runtime.as_slice(),
            ),
            (
                &library_code,
                "address-sorted-linked-list-code",
                address_sorted_linked_list_runtime.as_slice(),
            ),
        ] {
            assert_eq!(
                decode_hex(
                    response(document, id)["result"]
                        .as_str()
                        .unwrap_or_else(|| panic!("missing code response {id}")),
                ),
                expected,
                "dependency runtime disagreement for {id} at {provider}"
            );
        }
    }
}

#[test]
fn validators_verified_source_and_abi_bind_first_member_operands_and_residuals() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let proxy = read_json(&evidence.join("blockscout/ValidatorsProxy.json"));
    let implementation = read_json(&evidence.join("blockscout/Validators.implementation.json"));
    let registry_proxy_record = read_json(&evidence.join("blockscout/RegistryProxy.json"));
    let registry_implementation_record =
        read_json(&evidence.join("blockscout/Registry.implementation.json"));
    let accounts_proxy_record = read_json(&evidence.join("blockscout/AccountsProxy.json"));
    let accounts_implementation_record =
        read_json(&evidence.join("blockscout/Accounts.implementation.json"));
    let election_proxy_record = read_json(&evidence.join("blockscout/ElectionProxy.json"));
    let election_implementation_record =
        read_json(&evidence.join("blockscout/Election.implementation.json"));
    let address_linked_list_record = read_json(&evidence.join("blockscout/AddressLinkedList.json"));
    let address_sorted_linked_list_record =
        read_json(&evidence.join("blockscout/AddressSortedLinkedList.json"));
    assert_eq!(proxy["name"].as_str(), Some("ValidatorsProxy"));
    assert_eq!(proxy["is_verified"].as_bool(), Some(true));
    assert_eq!(proxy["is_fully_verified"].as_bool(), Some(true));
    assert_eq!(proxy["is_partially_verified"].as_bool(), Some(false));
    assert_eq!(proxy["proxy_type"].as_str(), Some("eip1967"));
    assert_eq!(implementation["name"].as_str(), Some("Validators"));
    assert_eq!(implementation["is_verified"].as_bool(), Some(true));
    assert_eq!(implementation["is_fully_verified"].as_bool(), Some(false));
    assert_eq!(
        implementation["is_partially_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(
        implementation["compiler_version"].as_str(),
        Some("v0.8.19+commit.7dd6d404")
    );
    assert_eq!(implementation["optimization_enabled"].as_bool(), Some(true));
    assert_eq!(implementation["optimization_runs"].as_u64(), Some(200));
    assert_eq!(implementation["evm_version"].as_str(), Some("paris"));
    assert_eq!(
        implementation["external_libraries"],
        serde_json::json!([{
            "name": "contracts-0.8/common/linkedlists/AddressLinkedList.sol:AddressLinkedList",
            "address_hash": "0x08a4B5bc1b5aDef0a283C8f0185dEd6169F0Bd29"
        }])
    );

    for record in [
        &registry_proxy_record,
        &registry_implementation_record,
        &accounts_proxy_record,
        &accounts_implementation_record,
        &election_proxy_record,
        &election_implementation_record,
        &address_sorted_linked_list_record,
    ] {
        assert_eq!(record["is_verified"].as_bool(), Some(true));
    }
    assert_eq!(registry_proxy_record["proxy_type"], "eip1967");
    assert_eq!(
        registry_proxy_record["is_partially_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(
        registry_implementation_record["compiler_version"].as_str(),
        Some("v0.5.17+commit.d19bba13")
    );
    assert_eq!(
        registry_implementation_record["optimization_enabled"].as_bool(),
        Some(true)
    );
    assert_eq!(
        registry_implementation_record["optimization_runs"].as_u64(),
        Some(200)
    );
    assert_eq!(
        registry_implementation_record["evm_version"].as_str(),
        Some("istanbul")
    );
    assert_eq!(accounts_proxy_record["proxy_type"], "eip1967");
    assert_eq!(
        accounts_proxy_record["is_fully_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(accounts_implementation_record["name"], "Accounts");
    assert_eq!(
        accounts_implementation_record["is_fully_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(
        accounts_implementation_record["compiler_version"].as_str(),
        Some("0.5.13+commit.5b0b510c")
    );
    assert_eq!(
        accounts_implementation_record["optimization_enabled"].as_bool(),
        Some(false)
    );
    assert_eq!(
        accounts_implementation_record["evm_version"].as_str(),
        Some("istanbul")
    );
    assert_eq!(election_proxy_record["proxy_type"], "eip1967");
    assert_eq!(
        election_proxy_record["is_partially_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(election_implementation_record["name"], "Election");
    assert_eq!(
        election_implementation_record["is_partially_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(
        election_implementation_record["compiler_version"].as_str(),
        Some("v0.5.14+commit.01f1aaa4")
    );
    assert_eq!(
        election_implementation_record["optimization_enabled"].as_bool(),
        Some(false)
    );
    assert_eq!(
        election_implementation_record["evm_version"].as_str(),
        Some("istanbul")
    );
    assert_eq!(
        election_implementation_record["external_libraries"],
        serde_json::json!([{
            "name": "contracts/common/linkedlists/AddressSortedLinkedList.sol:AddressSortedLinkedList",
            "address_hash": "0x0E3E96a0D64B59b46872432f47BeD6A1825A1552"
        }])
    );
    assert_eq!(
        address_sorted_linked_list_record["name"],
        "AddressSortedLinkedList"
    );
    assert_eq!(
        address_sorted_linked_list_record["is_fully_verified"].as_bool(),
        Some(true)
    );
    assert_eq!(
        address_sorted_linked_list_record["compiler_version"].as_str(),
        Some("0.5.13+commit.5b0b510c")
    );
    assert_eq!(
        address_sorted_linked_list_record["optimization_enabled"].as_bool(),
        Some(false)
    );
    assert_eq!(
        address_sorted_linked_list_record["evm_version"].as_str(),
        Some("istanbul")
    );
    assert!(address_linked_list_record.get("is_verified").is_none());
    assert!(address_linked_list_record.get("compiler_version").is_none());

    let proxy_runtime = decode_hex(
        &fs::read_to_string(evidence.join("runtime/ValidatorsProxy.celo-mainnet.hex")).unwrap(),
    );
    let implementation_runtime = decode_hex(
        &fs::read_to_string(evidence.join("runtime/Validators.implementation.celo-mainnet.hex"))
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
    let registry_proxy_runtime = read_runtime(&evidence, "RegistryProxy");
    let registry_implementation_runtime = read_runtime(&evidence, "Registry.implementation");
    let accounts_proxy_runtime = read_runtime(&evidence, "AccountsProxy");
    let accounts_implementation_runtime = read_runtime(&evidence, "Accounts.implementation");
    let election_proxy_runtime = read_runtime(&evidence, "ElectionProxy");
    let election_implementation_runtime = read_runtime(&evidence, "Election.implementation");
    let address_linked_list_runtime = read_runtime(&evidence, "AddressLinkedList");
    let address_sorted_linked_list_runtime = read_runtime(&evidence, "AddressSortedLinkedList");
    for (record, runtime) in [
        (&registry_proxy_record, registry_proxy_runtime.as_slice()),
        (
            &registry_implementation_record,
            registry_implementation_runtime.as_slice(),
        ),
        (&accounts_proxy_record, accounts_proxy_runtime.as_slice()),
        (
            &accounts_implementation_record,
            accounts_implementation_runtime.as_slice(),
        ),
        (&election_proxy_record, election_proxy_runtime.as_slice()),
        (
            &election_implementation_record,
            election_implementation_runtime.as_slice(),
        ),
        (
            &address_sorted_linked_list_record,
            address_sorted_linked_list_runtime.as_slice(),
        ),
    ] {
        assert_runtime_record(record, runtime);
    }
    assert_eq!(
        decode_hex(
            address_linked_list_record["deployed_bytecode"]
                .as_str()
                .expect("unverified linked-library runtime"),
        ),
        address_linked_list_runtime,
    );

    let validators_source =
        fs::read_to_string(evidence.join("source/Validators.sol")).expect("Validators source");
    assert_eq!(
        implementation["source_code"].as_str(),
        Some(validators_source.as_str()),
        "official pinned Validators.sol must match the explorer primary source byte-for-byte"
    );
    assert_eq!(
        sha256_hex(validators_source.as_bytes()),
        "71f446ee0e435710b6661202d4e26e53e9688d161e2339ce1648ff502f5ca664"
    );

    let registry_source = fs::read_to_string(evidence.join("source/deployed/Registry.sol"))
        .expect("deployed Registry source");
    assert_eq!(
        additional_source(
            &registry_implementation_record,
            "contracts/common/Registry.sol"
        ),
        registry_source,
        "independent official Registry source must match Blockscout"
    );
    assert_eq!(
        sha256_hex(registry_source.as_bytes()),
        "523b6c9ea1e3fc3e0fb17604a6821b0b25e7e47727f707826d3ee563e96db483"
    );
    let registry_lookup = normalized(solidity_function(&registry_source, "getAddressForString"));
    assert!(registry_lookup.contains(
        "bytes32 identifierHash = keccak256(abi.encodePacked(identifier)); return registry[identifierHash];"
    ));
    let registry_update = normalized(solidity_function(&registry_source, "setAddressFor"));
    assert!(registry_update.contains(
        "function setAddressFor(string calldata identifier, address addr) external onlyOwner"
    ));
    assert!(registry_update.contains("registry[identifierHash] = addr;"));
    let using_registry = fs::read_to_string(evidence.join("source/UsingRegistry.sol"))
        .expect("UsingRegistry source");
    assert!(using_registry.contains("IRegistry public registry;"));
    let set_registry = normalized(solidity_function(&using_registry, "setRegistry"));
    assert!(set_registry.contains("function setRegistry(address registryAddress) public onlyOwner"));
    assert!(set_registry.contains("registry = IRegistry(registryAddress);"));
    for (name, claim) in [
        (
            "getAccounts",
            "return IAccounts(registry.getAddressForOrDie(ACCOUNTS_REGISTRY_ID));",
        ),
        (
            "getElection",
            "return IElection(registry.getAddressForOrDie(ELECTION_REGISTRY_ID));",
        ),
        (
            "getLockedGold",
            "return ILockedGold(registry.getAddressForOrDie(LOCKED_GOLD_REGISTRY_ID));",
        ),
    ] {
        assert!(
            normalized(solidity_function(&using_registry, name)).contains(claim),
            "Registry accessor drifted: {name}"
        );
    }

    let accounts_source = fs::read_to_string(evidence.join("source/deployed/Accounts.sol"))
        .expect("deployed Accounts source");
    assert_eq!(
        accounts_implementation_record["source_code"].as_str(),
        Some(accounts_source.as_str()),
        "independent official Accounts source must match the fully verified record"
    );
    assert_eq!(
        sha256_hex(accounts_source.as_bytes()),
        "b6d6e7c8170ffec83a38f997eee639b83aef5f71ca1eda6ed9b2a17bdc232829"
    );
    let signer_entry = normalized(solidity_function(
        &accounts_source,
        "validatorSignerToAccount",
    ));
    assert!(signer_entry.contains("return signerToAccountWithRole(signer, ValidatorSigner);"));
    let signer_resolution = normalized(solidity_function(
        &accounts_source,
        "signerToAccountWithRole",
    ));
    for claim in [
        "address account = authorizedBy[signer];",
        "require(isSigner(account, signer, role), \"not active authorized signer for role\");",
        "return account;",
        "require(isAccount(signer), \"Must first register address with Account.createAccount\");",
        "return signer;",
    ] {
        assert!(
            signer_resolution.contains(claim),
            "validator-signer resolution drifted: {claim}"
        );
    }

    let natspec = normalized(solidity_natspec(&validators_source, "addFirstMember"));
    for claim in [
        "Adds the first member to a group's list of members and marks the group eligible for election.",
        "@param validator The validator to add to the group",
        "@param lesser The address of the group that has received fewer votes than this group.",
        "@param greater The address of the group that has received more votes than this group.",
        "Fails if `validator` has not set their affiliation to this account.",
        "Fails if the group has > 0 members.",
    ] {
        assert!(natspec.contains(claim), "addFirstMember Natspec drifted: {claim}");
    }
    let add_first = normalized(solidity_function(&validators_source, "addFirstMember"));
    for claim in [
        "address validator, address lesser, address greater",
        ") external nonReentrant returns (bool)",
        "address account = getAccounts().validatorSignerToAccount(msg.sender);",
        "require(groups[account].members.numElements == 0, \"Validator group not empty\");",
        "return _addMember(account, validator, lesser, greater);",
    ] {
        assert!(
            add_first.contains(claim),
            "addFirstMember semantics drifted: {claim}"
        );
    }

    let add_member = normalized(solidity_function(&validators_source, "_addMember"));
    for claim in [
        "require(isValidatorGroup(group) && isValidator(validator), \"Not validator and group\");",
        "require(_group.members.numElements < maxGroupSize, \"group would exceed maximum size\");",
        "require(validators[validator].affiliation == group, \"Not affiliated to group\");",
        "require(!_group.members.contains(validator), \"Already in group\");",
        "uint256 numMembers = _group.members.numElements.add(1);",
        "_group.members.push(validator);",
        "require(meetsAccountLockedGoldRequirements(group), \"Group requirements not met\");",
        "require(meetsAccountLockedGoldRequirements(validator), \"Validator requirements not met\");",
        "if (numMembers == 1) { getElection().markGroupEligible(group, lesser, greater); }",
        "emit ValidatorGroupMemberAdded(group, validator);",
        "return true;",
    ] {
        assert!(add_member.contains(claim), "_addMember semantics drifted: {claim}");
    }
    assert!(
        normalized(solidity_function(&validators_source, "isValidatorGroup"))
            .contains("return groups[account].exists;")
    );
    assert!(
        normalized(solidity_function(&validators_source, "isValidator"))
            .contains("return validators[account].publicKeys.ecdsa.length > 0;")
    );
    let locked_requirement = normalized(solidity_function(
        &validators_source,
        "meetsAccountLockedGoldRequirements",
    ));
    assert!(locked_requirement
        .contains("uint256 balance = getLockedGold().getAccountTotalLockedGold(account);"));
    assert!(locked_requirement
        .contains("return balance.add(10) >= getAccountLockedGoldRequirement(account);"));

    let address_list = fs::read_to_string(evidence.join("source/deployed/AddressLinkedList.sol"))
        .expect("deployed AddressLinkedList source");
    assert_eq!(
        sha256_hex(address_list.as_bytes()),
        "c05472ed25b9d9a9f03bb21f38cb24d92bb37d70182a3e5661afda0ff0d4d74d"
    );
    assert!(normalized(solidity_function(&address_list, "push"))
        .contains("list.insert(toBytes(key), bytes32(0), list.tail);"));
    assert!(normalized(solidity_function(&address_list, "contains"))
        .contains("return list.elements[toBytes(key)].exists;"));
    let linked_list = fs::read_to_string(evidence.join("source/deployed/LinkedList.sol"))
        .expect("deployed LinkedList source");
    assert_eq!(
        sha256_hex(linked_list.as_bytes()),
        "b625eda18bf7e55996483598dd338747c4527830ccfa5260dd944ec7fee8e4f2"
    );
    let list_insert = normalized(solidity_function(&linked_list, "insert"));
    for claim in [
        "require(key != bytes32(0), \"Key must be defined\");",
        "require(!contains(list, key), \"Can't insert an existing element\");",
        "element.exists = true;",
        "list.numElements = list.numElements.add(1);",
    ] {
        assert!(
            list_insert.contains(claim),
            "member-list semantics drifted: {claim}"
        );
    }

    let election_source = fs::read_to_string(evidence.join("source/deployed/Election.sol"))
        .expect("deployed Election source");
    assert_eq!(
        election_implementation_record["source_code"].as_str(),
        Some(election_source.as_str()),
        "independent official Election source must match Blockscout"
    );
    assert_eq!(
        sha256_hex(election_source.as_bytes()),
        "f4f897289538a084161c179ddf61dbd06284f8aec521c794c8c0a0912241d191"
    );
    let mark_eligible = normalized(solidity_function(&election_source, "markGroupEligible"));
    for claim in [
        ") external onlyRegisteredContract(VALIDATORS_REGISTRY_ID)",
        "uint256 value = getTotalVotesForGroup(group);",
        "votes.total.eligible.insert(group, value, lesser, greater);",
        "emit ValidatorGroupMarkedEligible(group);",
    ] {
        assert!(
            mark_eligible.contains(claim),
            "eligibility effect drifted: {claim}"
        );
    }

    let address_sorted =
        fs::read_to_string(evidence.join("source/deployed/AddressSortedLinkedList.sol"))
            .expect("deployed AddressSortedLinkedList source");
    let sorted = fs::read_to_string(evidence.join("source/deployed/SortedLinkedList.sol"))
        .expect("deployed SortedLinkedList source");
    assert_eq!(
        address_sorted_linked_list_record["source_code"].as_str(),
        Some(address_sorted.as_str()),
        "independent official AddressSortedLinkedList source must match Blockscout"
    );
    assert_eq!(
        additional_source(
            &address_sorted_linked_list_record,
            "project:/contracts/common/linkedlists/SortedLinkedList.sol",
        ),
        sorted,
        "independent official SortedLinkedList source must match Blockscout"
    );
    assert!(normalized(solidity_function(&address_sorted, "insert"))
        .contains("list.insert(toBytes(key), value, toBytes(lesserKey), toBytes(greaterKey));"));
    let sorted_insert = normalized(solidity_function(&sorted, "insert"));
    assert!(sorted_insert.contains(
        "(lesserKey != bytes32(0) || greaterKey != bytes32(0)) || list.list.numElements == 0"
    ));
    assert!(sorted_insert.contains("list.list.insert(key, lesserKey, greaterKey);"));

    let safe_math = fs::read_to_string(evidence.join("source/deployed/SafeMath.sol"))
        .expect("deployed SafeMath source");
    assert_eq!(
        sha256_hex(safe_math.as_bytes()),
        "ccbc65eddc0fe23db1360af754dfc534f2ab28ab1d2e79c1ca0cc9420a96dc58"
    );
    let compiler_input =
        read_json(&evidence.join("compiler/AddressLinkedList.standard-input.json"));
    assert_eq!(compiler_input["language"], "Solidity");
    assert_eq!(
        compiler_input["sources"]["project:/contracts/common/linkedlists/AddressLinkedList.sol"]
            ["content"]
            .as_str(),
        Some(address_list.as_str())
    );
    assert_eq!(
        compiler_input["sources"]["project:/contracts/common/linkedlists/LinkedList.sol"]
            ["content"]
            .as_str(),
        Some(linked_list.as_str())
    );
    assert_eq!(
        compiler_input["sources"]["openzeppelin-solidity/contracts/math/SafeMath.sol"]["content"]
            .as_str(),
        Some(safe_math.as_str())
    );
    assert_eq!(compiler_input["settings"]["optimizer"]["enabled"], false);
    assert_eq!(compiler_input["settings"]["optimizer"]["runs"], 200);
    assert_eq!(compiler_input["settings"]["evmVersion"], "istanbul");
    assert_eq!(
        compiler_input["settings"]["metadata"]["useLiteralContent"],
        true
    );
    assert_eq!(
        fs::read_to_string(evidence.join("compiler/solc-0.5.13.version.txt"))
            .expect("solc version receipt"),
        "0.5.13+commit.5b0b510c.Emscripten.clang\n"
    );
    let compiler_output =
        read_json(&evidence.join("compiler/AddressLinkedList.standard-output.json"));
    assert!(
        compiler_output
            .get("errors")
            .and_then(Value::as_array)
            .map_or(true, Vec::is_empty),
        "AddressLinkedList compiler witness contains diagnostics"
    );
    let mut compiled_linked_list = decode_hex(
        compiler_output["contracts"]["project:/contracts/common/linkedlists/AddressLinkedList.sol"]
            ["AddressLinkedList"]["evm"]["deployedBytecode"]["object"]
            .as_str()
            .expect("compiled AddressLinkedList runtime"),
    );
    assert_eq!(compiled_linked_list.len(), 4_491);
    assert_eq!(
        compiled_linked_list[0], 0x73,
        "Solidity library guard prefix"
    );
    assert_eq!(&compiled_linked_list[1..21], &[0u8; 20]);
    compiled_linked_list[1..21].copy_from_slice(&decode_hex(ADDRESS_LINKED_LIST));
    assert_eq!(
        compiled_linked_list, address_linked_list_runtime,
        "official historical sources and pinned solc input must reproduce the full deployed linked-library runtime"
    );
    assert_eq!(
        manifest["compiler_witness"]["full_runtime_match"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["dependency_sources"]["accounts"]["commit"],
        "fad3410bdaf159749ace623887caaac7adf753ca"
    );
    assert_eq!(
        manifest["dependency_sources"]["address_linked_list"]["commit"],
        "a607b2f504e4aaf998ef1f88fcc893bfb7e7b007"
    );
    assert_eq!(
        manifest["dependency_sources"]["address_linked_list"]["openzeppelin_commit"],
        "58a3368215581509d05bd3ec4d53cd381c9bb40e"
    );

    let route_abi = read_json(&evidence.join("abi/Validators.add-first-member.abi.json"));
    assert_eq!(route_abi.as_array().expect("curated route ABI").len(), 1);
    let archived = abi_function(&route_abi, "addFirstMember");
    let explorer = abi_function(&implementation["abi"], "addFirstMember");
    assert_eq!(
        archived, explorer,
        "curated addFirstMember ABI must be derived from Blockscout"
    );
    assert_eq!(archived["type"], "function");
    assert_eq!(archived["stateMutability"], "nonpayable");
    let inputs = archived["inputs"].as_array().expect("route ABI inputs");
    let actual_inputs = inputs
        .iter()
        .map(|input| {
            (
                input["name"].as_str().expect("ABI input name"),
                input["type"].as_str().expect("ABI input type"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual_inputs,
        [
            ("validator", "address"),
            ("lesser", "address"),
            ("greater", "address")
        ]
    );
    let outputs = archived["outputs"].as_array().expect("route ABI outputs");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["name"], "");
    assert_eq!(outputs[0]["type"], "bool");
    let signature = "addFirstMember(address,address,address)";
    assert_eq!(&keccak256(signature.as_bytes())[..4], SELECTOR);
    assert_eq!(manifest["abi"]["canonical_signature"], signature);
    assert_eq!(manifest["abi"]["selector"], "0x3173b8db");
    assert_eq!(manifest["abi"]["route_count"].as_u64(), Some(1));

    let boundary = manifest["boundary"].as_str().expect("honest boundary");
    for claim in [
        "exactly addFirstMember",
        "Celo mainnet",
        "Registry pointer",
        "proxy implementations",
        "does not monitor future upgrades",
        "legacy Alfajores",
        "any other Validators route",
        "blind signing",
    ] {
        assert!(
            boundary.contains(claim),
            "authority boundary drifted: {claim}"
        );
    }
    assert_eq!(
        manifest["semantics"]["caller"],
        "msg.sender resolves through Accounts.validatorSignerToAccount; the live effective group can differ from the immediate caller"
    );
    assert!(manifest["semantics"]["effect"]
        .as_str()
        .expect("eligibility effect")
        .contains("Election.markGroupEligible"));
    assert!(manifest["semantics"]["fixed_dependency_binding"]
        .as_str()
        .expect("fixed dependency binding")
        .contains("converge across three providers"));
    assert!(manifest["semantics"]["success_residual"]
        .as_str()
        .expect("live-state residual")
        .contains("execution success remain live-state preconditions"));
}
