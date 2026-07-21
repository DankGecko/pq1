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

    let archived_proxy = decode_hex(
        &fs::read_to_string(evidence.join("runtime/ValidatorsProxy.celo-mainnet.hex"))
            .expect("read proxy runtime"),
    );
    let archived_implementation = decode_hex(
        &fs::read_to_string(evidence.join("runtime/Validators.implementation.celo-mainnet.hex"))
            .expect("read implementation runtime"),
    );
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
    }
}

#[test]
fn validators_verified_source_and_abi_bind_first_member_operands_and_residuals() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let proxy = read_json(&evidence.join("blockscout/ValidatorsProxy.json"));
    let implementation = read_json(&evidence.join("blockscout/Validators.implementation.json"));
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

    let registry_source =
        fs::read_to_string(evidence.join("source/Registry.sol")).expect("Registry source");
    let registry_lookup = normalized(solidity_function(&registry_source, "getAddressForString"));
    assert!(registry_lookup.contains(
        "bytes32 identifierHash = keccak256(abi.encodePacked(identifier)); return registry[identifierHash];"
    ));
    let using_registry = fs::read_to_string(evidence.join("source/UsingRegistry.sol"))
        .expect("UsingRegistry source");
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

    let accounts_source =
        fs::read_to_string(evidence.join("source/Accounts.sol")).expect("Accounts source");
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

    let address_list = fs::read_to_string(evidence.join("source/AddressLinkedList.sol"))
        .expect("AddressLinkedList source");
    assert!(normalized(solidity_function(&address_list, "push"))
        .contains("list.insert(toBytes(key), bytes32(0), list.tail);"));
    assert!(normalized(solidity_function(&address_list, "contains"))
        .contains("return list.elements[toBytes(key)].exists;"));
    let linked_list =
        fs::read_to_string(evidence.join("source/LinkedList.sol")).expect("LinkedList source");
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

    let election_source =
        fs::read_to_string(evidence.join("source/Election.sol")).expect("Election source");
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
    assert!(manifest["semantics"]["success_residual"]
        .as_str()
        .expect("live-state residual")
        .contains("execution success remain live-state preconditions"));
}
