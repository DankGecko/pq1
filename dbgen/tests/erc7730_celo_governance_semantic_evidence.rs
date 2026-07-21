//! Offline evidence checks for bounded Celo Governance voting-route admissions.
//!
//! Catalogue and rendering behavior are exercised elsewhere. This test keeps
//! the external authority package honest: every archived byte is receipted,
//! three fixed-block RPC providers agree on deployment identity, and the
//! verified ABI/source establish the meaning and live-state limits of every
//! signed operand admitted by this slice.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const BLOCK_HASH: &str = "0x810df7ac9ef91261a1ed3ef97f2848ec71a4f943c64715908fdeabd985bf4a3c";
const PROXY: &str = "d533ca259b330c7a88f74e000a3faea2d63b7972";
const IMPLEMENTATION: &str = "40cac0be7e25b14e39f782d5b7e5c3076aa6c57a";
const EIP1967_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/celo-governance-voting")
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

fn assert_route_abi(
    function: &Value,
    name: &str,
    expected_inputs: &[(&str, &str)],
    expected_selector: &str,
) {
    assert_eq!(function["type"], "function");
    assert_eq!(function["name"], name);
    assert_eq!(function["stateMutability"], "nonpayable");
    assert_eq!(function["payable"].as_bool(), Some(false));
    assert_eq!(function["constant"].as_bool(), Some(false));
    let inputs = function["inputs"].as_array().expect("function ABI inputs");
    let actual_inputs = inputs
        .iter()
        .map(|input| {
            (
                input["name"].as_str().expect("ABI input name"),
                input["type"].as_str().expect("ABI input type"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual_inputs, expected_inputs);
    let outputs = function["outputs"]
        .as_array()
        .expect("function ABI outputs");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["name"], "");
    assert_eq!(outputs[0]["type"], "bool");
    let signature = format!(
        "{name}({})",
        inputs
            .iter()
            .map(|input| input["type"].as_str().unwrap())
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4])),
        expected_selector,
        "selector derived from Blockscout ABI drifted for {signature}"
    );
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
fn governance_evidence_receipts_and_fixed_block_identity_are_exact() {
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
    let governance_call = request(&identity_request, "governance");
    assert_eq!(governance_call["method"], "eth_call");
    assert_eq!(
        governance_call["params"][0]["to"].as_str(),
        Some("0x000000000000000000000000000000000000ce10")
    );
    let registry_calldata = governance_call["params"][0]["data"]
        .as_str()
        .expect("Registry calldata");
    assert!(registry_calldata.starts_with("0x853db323"));
    let registry_calldata = decode_hex(registry_calldata);
    assert!(registry_calldata
        .windows(b"Governance".len())
        .any(|window| window == b"Governance"));
    assert_eip1898(&governance_call["params"][1]);

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
        &fs::read_to_string(evidence.join("runtime/GovernanceProxy.celo-mainnet.hex"))
            .expect("read proxy runtime"),
    );
    let archived_implementation = decode_hex(
        &fs::read_to_string(evidence.join("runtime/Governance.implementation.celo-mainnet.hex"))
            .expect("read implementation runtime"),
    );
    assert_eq!(archived_proxy.len(), 2_585);
    assert_eq!(archived_implementation.len(), 57_635);
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
        let governance = decode_hex(
            response(&identity, "governance")["result"]
                .as_str()
                .expect("Governance Registry result"),
        );
        assert_eq!(governance.len(), 32);
        assert_eq!(&governance[..12], &[0u8; 12]);
        assert_eq!(hex::encode(&governance[12..]), PROXY);
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
fn governance_verified_source_and_abi_bind_voting_operands_and_residuals() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let proxy = read_json(&evidence.join("blockscout/GovernanceProxy.json"));
    let implementation = read_json(&evidence.join("blockscout/Governance.implementation.json"));
    assert_eq!(proxy["name"].as_str(), Some("GovernanceProxy"));
    assert_eq!(proxy["is_verified"].as_bool(), Some(true));
    assert_eq!(proxy["is_fully_verified"].as_bool(), Some(true));
    assert_eq!(proxy["proxy_type"].as_str(), Some("eip1967"));
    assert_eq!(implementation["name"].as_str(), Some("Governance"));
    assert_eq!(implementation["is_verified"].as_bool(), Some(true));
    assert_eq!(implementation["is_fully_verified"].as_bool(), Some(false));
    assert_eq!(
        implementation["is_partially_verified"].as_bool(),
        Some(true)
    );

    let proxy_runtime = decode_hex(
        &fs::read_to_string(evidence.join("runtime/GovernanceProxy.celo-mainnet.hex")).unwrap(),
    );
    let implementation_runtime = decode_hex(
        &fs::read_to_string(evidence.join("runtime/Governance.implementation.celo-mainnet.hex"))
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

    let governance_source =
        fs::read_to_string(evidence.join("source/Governance.sol")).expect("Governance source");
    assert_eq!(
        implementation["source_code"].as_str(),
        Some(governance_source.as_str()),
        "official pinned Governance.sol must match the explorer primary source byte-for-byte"
    );
    assert_eq!(
        sha256_hex(governance_source.as_bytes()),
        "5a5c44ab0c0fcbab6f9b492612e460c78dbd9c9d3d9e73ed751df806a6581e53"
    );

    let registry_source =
        fs::read_to_string(evidence.join("source/Registry.sol")).expect("Registry source");
    let registry_lookup = normalized(solidity_function(&registry_source, "getAddressForString"));
    assert!(registry_lookup.contains(
        "bytes32 identifierHash = keccak256(abi.encodePacked(identifier)); return registry[identifierHash];"
    ));
    let using_registry = fs::read_to_string(evidence.join("source/UsingRegistry.sol"))
        .expect("UsingRegistry source");
    assert!(
        normalized(solidity_function(&using_registry, "getAccounts"))
            .contains("return IAccounts(registry.getAddressForOrDie(ACCOUNTS_REGISTRY_ID));")
    );
    assert!(
        normalized(solidity_function(&using_registry, "getLockedGold"))
            .contains("return ILockedGold(registry.getAddressForOrDie(LOCKED_GOLD_REGISTRY_ID));")
    );

    let accounts_source =
        fs::read_to_string(evidence.join("source/Accounts.sol")).expect("Accounts source");
    let signer_entry = normalized(solidity_function(&accounts_source, "voteSignerToAccount"));
    assert!(signer_entry.contains("return signerToAccountWithRole(signer, VoteSigner);"));
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
            "vote-signer resolution drifted: {claim}"
        );
    }

    let locked_gold =
        fs::read_to_string(evidence.join("source/LockedGold.sol")).expect("LockedGold source");
    let total_locked = normalized(solidity_function(&locked_gold, "getAccountTotalLockedGold"));
    assert!(total_locked.contains("uint256 total = balances[account].nonvoting;"));
    assert!(
        total_locked.contains("return total.add(getElection().getTotalVotesByAccount(account));")
    );
    let governance_power = normalized(solidity_function(
        &locked_gold,
        "getAccountTotalGovernanceVotingPower",
    ));
    for claim in [
        "uint256 totalLockedGold = getAccountTotalLockedGold(account);",
        "uint256 availableForVoting = FixidityLib .newFixed(totalLockedGold) .multiply(availableUndelegatedPercents) .fromFixed();",
        "return availableForVoting.add(totalDelegatedCelo[account]);",
    ] {
        assert!(
            governance_power.contains(claim),
            "governance voting-power semantics drifted: {claim}"
        );
    }

    let proposals_source =
        fs::read_to_string(evidence.join("source/Proposals.sol")).expect("Proposals source");
    let proposals = normalized(&proposals_source);
    assert!(
        proposals.contains("enum VoteValue { None, Abstain, No, Yes }"),
        "canonical Proposals.VoteValue ordering drifted"
    );
    let update_vote = normalized(solidity_function(&proposals_source, "updateVote"));
    for claim in [
        "proposal.votes.yes = proposal.votes.yes.sub(previousYesVotes);",
        "proposal.votes.no = proposal.votes.no.sub(previousNoVotes);",
        "proposal.votes.abstain = proposal.votes.abstain.sub(previousAbstainVotes);",
        "proposal.votes.yes = proposal.votes.yes.add(yesVotes);",
        "proposal.votes.no = proposal.votes.no.add(noVotes);",
        "proposal.votes.abstain = proposal.votes.abstain.add(abstainVotes);",
    ] {
        assert!(
            update_vote.contains(claim),
            "vote-total semantics drifted: {claim}"
        );
    }

    let upvote = normalized(solidity_function(&governance_source, "upvote"));
    for claim in [
        "address account = getAccounts().voteSignerToAccount(msg.sender);",
        "uint256 weight = getLockedGold().getAccountTotalLockedGold(account);",
        "require(weight > 0, \"cannot upvote without locking gold\");",
        "require(queue.contains(proposalId), \"cannot upvote a proposal not in the queue\");",
        "uint256 upvotes = queue.getValue(proposalId).add(weight);",
        "queue.update(proposalId, upvotes, lesser, greater);",
        "voter.upvote = UpvoteRecord(proposalId, weight);",
    ] {
        assert!(upvote.contains(claim), "upvote semantics drifted: {claim}");
    }
    let revoke = normalized(solidity_function(&governance_source, "revokeUpvote"));
    for claim in [
        "address account = getAccounts().voteSignerToAccount(msg.sender);",
        "uint256 proposalId = voter.upvote.proposalId;",
        "queue.getValue(proposalId).sub(voter.upvote.weight)",
        "lesser, greater",
        "emit ProposalUpvoteRevoked(proposalId, account, voter.upvote.weight);",
        "voter.upvote = UpvoteRecord(0, 0);",
    ] {
        assert!(
            revoke.contains(claim),
            "revokeUpvote live-state semantics drifted: {claim}"
        );
    }

    let vote = normalized(solidity_function(&governance_source, "vote"));
    for claim in [
        "Proposals.VoteValue value",
        "require(stage == Proposals.Stage.Referendum, \"Incorrect proposal state\");",
        "require(value != Proposals.VoteValue.None, \"Vote value unset\");",
        "address account = getAccounts().voteSignerToAccount(msg.sender);",
        "uint256 weight = getLockedGold().getAccountTotalGovernanceVotingPower(account);",
        "value == Proposals.VoteValue.Yes ? weight : 0",
        "value == Proposals.VoteValue.No ? weight : 0",
        "value == Proposals.VoteValue.Abstain ? weight : 0",
    ] {
        assert!(
            vote.contains(claim),
            "whole-vote semantics drifted: {claim}"
        );
    }
    let partial = normalized(solidity_function(&governance_source, "votePartially"));
    for claim in [
        "uint256 yesVotes, uint256 noVotes, uint256 abstainVotes",
        "require(stage == Proposals.Stage.Referendum, \"Incorrect proposal state\");",
        "address account = getAccounts().voteSignerToAccount(msg.sender);",
        "uint256 totalVotingPower = getLockedGold().getAccountTotalGovernanceVotingPower(account);",
        "totalVotingPower >= yesVotes.add(noVotes).add(abstainVotes)",
        "_vote(proposal, proposalId, index, account, yesVotes, noVotes, abstainVotes);",
    ] {
        assert!(
            partial.contains(claim),
            "partial-vote semantics drifted: {claim}"
        );
    }
    let vote_update = normalized(solidity_function(&governance_source, "_vote"));
    for claim in [
        "VoteRecord storage previousVoteRecord = voter.referendumVotes[index];",
        "proposal.updateVote(0, 0, 0, yesVotes, noVotes, abstainVotes);",
        "voter.referendumVotes[index] = VoteRecord( Proposals.VoteValue.None, proposalId, 0, yesVotes, noVotes, abstainVotes );",
        "emit ProposalVotedV2(proposalId, account, yesVotes, noVotes, abstainVotes);",
    ] {
        assert!(vote_update.contains(claim), "vote-record semantics drifted: {claim}");
    }

    let dequeue_check = normalized(solidity_function(&governance_source, "_isDequeuedProposal"));
    assert!(dequeue_check.contains(
        "require(index < dequeued.length, \"Provided index greater than dequeue length.\");"
    ));
    assert!(dequeue_check.contains("return proposal.exists() && dequeued[index] == proposalId;"));
    let require_dequeued = normalized(solidity_function(
        &governance_source,
        "requireDequeuedAndDeleteExpired",
    ));
    assert!(require_dequeued.contains(
        "require(_isDequeuedProposal(proposal, proposalId, index), \"Proposal not dequeued\");"
    ));

    let governance_normalized = normalized(&governance_source);
    for claim in [
        "@param lesser The ID of the proposal that will be just behind `proposalId` in the queue.",
        "@param greater The ID of the proposal that will be just ahead `proposalId` in the queue.",
        "@dev Provide 0 for `lesser`/`greater` when the proposal will be at the tail/head of the queue.",
        "@param index The index of the proposal ID in `dequeued`.",
    ] {
        assert!(
            governance_normalized.contains(claim),
            "proposal/hint/index Natspec drifted: {claim}"
        );
    }
    let integer_list = normalized(
        &fs::read_to_string(evidence.join("source/IntegerSortedLinkedList.sol"))
            .expect("IntegerSortedLinkedList source"),
    );
    assert!(integer_list
        .contains("list.update(bytes32(key), value, bytes32(lesserKey), bytes32(greaterKey));"));
    let sorted_list = normalized(
        &fs::read_to_string(evidence.join("source/SortedLinkedList.sol"))
            .expect("SortedLinkedList source"),
    );
    for claim in [
        "lesserKey == bytes32(0) && isValueBetween(list, value, lesserKey, list.list.tail)",
        "greaterKey == bytes32(0) && isValueBetween(list, value, list.list.head, greaterKey)",
        "bool isLesser = lesserKey == bytes32(0) || list.values[lesserKey] <= value;",
        "bool isGreater = greaterKey == bytes32(0) || list.values[greaterKey] >= value;",
    ] {
        assert!(
            sorted_list.contains(claim),
            "sorted-list hint semantics drifted: {claim}"
        );
    }

    let routes_abi = read_json(&evidence.join("abi/Governance.voting-routes.abi.json"));
    let blockscout_abi = &implementation["abi"];
    let routes = [
        (
            "upvote",
            &[
                ("proposalId", "uint256"),
                ("lesser", "uint256"),
                ("greater", "uint256"),
            ][..],
            "0x57333978",
        ),
        (
            "revokeUpvote",
            &[("lesser", "uint256"), ("greater", "uint256")][..],
            "0xaf108a0e",
        ),
        (
            "vote",
            &[
                ("proposalId", "uint256"),
                ("index", "uint256"),
                ("value", "uint8"),
            ][..],
            "0xbbb2eab9",
        ),
        (
            "votePartially",
            &[
                ("proposalId", "uint256"),
                ("index", "uint256"),
                ("yesVotes", "uint256"),
                ("noVotes", "uint256"),
                ("abstainVotes", "uint256"),
            ][..],
            "0x2edfd12e",
        ),
    ];
    assert_eq!(
        routes_abi.as_array().expect("curated routes ABI").len(),
        routes.len()
    );
    for (name, inputs, selector) in routes {
        let archived = abi_function(&routes_abi, name);
        let explorer = abi_function(blockscout_abi, name);
        assert_eq!(
            archived, explorer,
            "curated {name} ABI must be byte-semantically derived from Blockscout"
        );
        assert_route_abi(archived, name, inputs, selector);
    }
    assert_eq!(
        abi_function(&routes_abi, "vote")["inputs"][2]["internalType"],
        "enum Proposals.VoteValue"
    );

    let excluded = manifest["abi"]["excluded_routes"]
        .as_array()
        .expect("excluded route list")
        .iter()
        .map(|value| value.as_str().expect("excluded route name"))
        .collect::<Vec<_>>();
    assert_eq!(excluded, ["execute", "propose", "executeHotfix"]);
    for name in excluded {
        assert!(
            routes_abi
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["name"] != name),
            "excluded route leaked into deterministic ABI projection: {name}"
        );
        let _ = solidity_function(&governance_source, name);
    }
    let boundary = manifest["boundary"].as_str().expect("honest boundary");
    for claim in [
        "exactly four voting routes",
        "does not monitor future upgrades",
        "execute",
        "propose",
        "executeHotfix",
        "blind signing",
    ] {
        assert!(
            boundary.contains(claim),
            "authority boundary drifted: {claim}"
        );
    }
    assert_eq!(
        manifest["semantics"]["caller"],
        "msg.sender resolves through Accounts.voteSignerToAccount; the live effective account can differ from the immediate caller"
    );
    assert!(manifest["semantics"]["success_residual"]
        .as_str()
        .expect("live-state residual")
        .contains("execution success remain live-state preconditions"));
}
