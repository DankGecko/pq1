//! Offline evidence and compiled-IR checks for the bounded Corestake, Sei, and
//! Avvatar calldata slice tracked by PQ1 issue #497.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EIP1967_IMPL_SLOT_ZERO: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";
const EARN_IMPLEMENTATION_WORD: &str =
    "0x00000000000000000000000062c5e03a5bfa0d6af08b81165a9eb87d1c8b8a0b";

const CORE_AGENT_ROUTES: &[&str] = &[
    "delegateCoin(address candidate)",
    "undelegateCoin(address candidate, uint256 amount)",
    "transferCoin(address sourceCandidate, address targetCandidate, uint256 amount)",
];
const CORE_EARN_ROUTES: &[&str] = &[
    "mint(address _validator)",
    "redeem(uint256 stCore)",
    "withdraw()",
];
const CORE_STAKE_HUB_ROUTES: &[&str] = &["claimReward()"];
const SEI_DISTRIBUTION_ROUTES: &[&str] = &[
    "setWithdrawAddress(address withdrawAddr)",
    "withdrawDelegationRewards(string validator)",
    "withdrawMultipleDelegationRewards(string[] validators)",
    "withdrawValidatorCommission()",
];
const SEI_DISTRIBUTION_REFUSALS: &[&str] =
    &["withdrawMultipleDelegationRewards(string[] validators)"];
const SEI_STAKING_ROUTES: &[&str] = &[
    "createValidator(string pubKeyHex, string moniker, string commissionRate, string commissionMaxRate, string commissionMaxChangeRate, uint256 minSelfDelegation)",
    "delegate(string valAddress)",
    "editValidator(string moniker, string commissionRate, uint256 minSelfDelegation)",
    "redelegate(string srcAddress, string dstAddress, uint256 amount)",
    "undelegate(string valAddress, uint256 amount)",
];
const SEI_STAKING_REFUSALS: &[&str] = &[
    "createValidator(string pubKeyHex, string moniker, string commissionRate, string commissionMaxRate, string commissionMaxChangeRate, uint256 minSelfDelegation)",
];
const ALIA_AGENT_ROUTES: &[&str] = &[
    "recordDecision(address _agent, string _action, address _assetInvolved, uint256 _value, bool _success, bytes32 _txHash)",
    "recordIncident(address _agent, string _description)",
    "registerAgent(address _agentWallet, address _ownerWallet, uint8 _agentType, string _name, string _version, string _manufacturer, string _serialNumber, uint256 _minColScore, uint256 _maxLTV)",
    "updateAgentStatus(address _agent, uint8 _newStatus, string _reason)",
    "updateFirmware(address _agent, string _newVersion)",
];
const ALIA_ASSET_ROUTES: &[&str] = &[
    "addCrossChainRecord(address _tokenAddress, uint256 _chainId, address _crossChainToken)",
    "registerAsset(address _tokenAddress, uint8 _assetClass, uint8 _backingType, string _legalIdentifier, string _jurisdiction, string _custodian)",
    "revokeAsset(address _tokenAddress, string _reason)",
    "updateCustodian(address _tokenAddress, string _newCustodian)",
];
const ALIA_SCORE_ROUTES: &[&str] = &[
    "refreshScore(address asset)",
    "refreshScoreBatch(address[] assets)",
];

struct Family {
    source: &'static str,
    chain_id: u64,
    contract: &'static str,
    routes: &'static [&'static str],
    refusals: &'static [&'static str],
}

fn families() -> [Family; 8] {
    [
        Family {
            source: "corestake/calldata-coreagent.json",
            chain_id: 1116,
            contract: "0x0000000000000000000000000000000000001011",
            routes: CORE_AGENT_ROUTES,
            refusals: &[],
        },
        Family {
            source: "corestake/calldata-corestake.json",
            chain_id: 1116,
            contract: "0xf5fA1728bABc3f8D2a617397faC2696c958C3409",
            routes: CORE_EARN_ROUTES,
            refusals: &[],
        },
        Family {
            source: "corestake/calldata-stakehub.json",
            chain_id: 1116,
            contract: "0x0000000000000000000000000000000000001010",
            routes: CORE_STAKE_HUB_ROUTES,
            refusals: &[],
        },
        Family {
            source: "sei/calldata-sei-distribution.json",
            chain_id: 1329,
            contract: "0x0000000000000000000000000000000000001007",
            routes: SEI_DISTRIBUTION_ROUTES,
            refusals: SEI_DISTRIBUTION_REFUSALS,
        },
        Family {
            source: "sei/calldata-sei-staking.json",
            chain_id: 1329,
            contract: "0x0000000000000000000000000000000000001005",
            routes: SEI_STAKING_ROUTES,
            refusals: SEI_STAKING_REFUSALS,
        },
        Family {
            source: "avvatar-labs-alia/calldata-AgentIdentityRegistry-base.json",
            chain_id: 8453,
            contract: "0xD5667AcB0Ac8108B45f6CDD4774559264098f8de",
            routes: ALIA_AGENT_ROUTES,
            refusals: &[],
        },
        Family {
            source: "avvatar-labs-alia/calldata-AssetIdentityRegistry-base.json",
            chain_id: 8453,
            contract: "0xfC9cA736d384D482af5d23CC7616765C66244D29",
            routes: ALIA_ASSET_ROUTES,
            refusals: &[],
        },
        Family {
            source: "avvatar-labs-alia/calldata-ScoreEngineV2-base.json",
            chain_id: 8453,
            contract: "0x295CCcDE8Fb06148d4FB6Bfc06B6c332E42aCb43",
            routes: ALIA_SCORE_ROUTES,
            refusals: &[],
        },
    ]
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/corestake-sei-avvatar")
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

fn address(text: &str) -> [u8; 20] {
    hex::decode(text.strip_prefix("0x").unwrap_or(text))
        .expect("hex address")
        .try_into()
        .expect("address width")
}

fn selector(signature: &str) -> [u8; 4] {
    let (name, arguments) = signature
        .strip_suffix(')')
        .and_then(|signature| signature.split_once('('))
        .expect("function signature");
    let canonical = if arguments.is_empty() {
        format!("{name}()")
    } else {
        let types = arguments
            .split(',')
            .map(|argument| argument.split_whitespace().next().expect("argument type"))
            .collect::<Vec<_>>()
            .join(",");
        format!("{name}({types})")
    };
    keccak256(canonical.as_bytes())[..4]
        .try_into()
        .expect("selector width")
}

fn hex_bytes(path: &Path) -> Vec<u8> {
    let text = fs::read_to_string(path).expect("read hex evidence");
    hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim())).expect("hex evidence")
}

fn collect_files(root: &Path, directory: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read evidence directory") {
        let entry = entry.expect("evidence entry");
        let path = entry.path();
        let ty = entry.file_type().expect("evidence file type");
        assert!(!ty.is_symlink(), "evidence may not contain symlinks");
        if ty.is_dir() {
            collect_files(root, &path, out);
        } else {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative));
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
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["kind"].clone(),
                    entry["target"].clone(),
                    entry["request"]["method"].clone(),
                    entry["request"]["params"].clone(),
                    entry["response"]["result"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(project(left), project(right));
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
fn evidence_receipts_sources_and_runtime_bindings_are_exact() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"], 1);
    assert!(required_str(&manifest, "boundary").contains("No live-state"));
    assert_eq!(
        manifest["descriptor_families"]
            .as_array()
            .unwrap()
            .iter()
            .map(|family| family["admitted_leaf_count"].as_u64().unwrap())
            .sum::<u64>(),
        25
    );

    let mut actual = BTreeSet::new();
    collect_files(&root, &root, &mut actual);
    let artifacts = manifest["artifacts"].as_array().unwrap();
    let expected = artifacts
        .iter()
        .map(|artifact| required_str(artifact, "path").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    for artifact in artifacts {
        let bytes = fs::read(root.join(required_str(artifact, "path"))).unwrap();
        assert_eq!(artifact["bytes"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(
            required_str(artifact, "sha256"),
            hex::encode(Sha256::digest(&bytes))
        );
    }

    let core_primary = read_json(&root.join("rpc/core-primary.json"));
    let core_secondary = read_json(&root.join("rpc/core-secondary.json"));
    let base_primary = read_json(&root.join("rpc/base-primary.json"));
    let base_secondary = read_json(&root.join("rpc/base-secondary.json"));
    assert_rpc_agreement(&core_primary, &core_secondary);
    assert_rpc_agreement(&base_primary, &base_secondary);
    assert_eq!(
        record(&core_primary, "block_header", "core")["response"]["result"]["hash"],
        manifest["fixed_blocks"]["core"]["hash"]
    );
    assert_eq!(
        record(&base_primary, "block_header", "base")["response"]["result"]["hash"],
        manifest["fixed_blocks"]["base"]["hash"]
    );

    assert_eq!(
        hex_bytes(&root.join("runtime/CoreAgent.onchain.hex")),
        hex_bytes(&root.join("source/core/core-chain/CoreAgentContract.hex"))
    );
    assert_eq!(
        hex_bytes(&root.join("runtime/StakeHub.onchain.hex")),
        hex_bytes(&root.join("source/core/core-chain/StakeHubContract.hex"))
    );
    assert_eq!(
        hex_bytes(&root.join("runtime/EarnImplementation.onchain.hex")),
        hex_bytes(&root.join("compiler/Earn.linked-runtime.hex"))
    );
    assert_eq!(
        result(
            &core_primary,
            "implementation_slot",
            "0xf5fA1728bABc3f8D2a617397faC2696c958C3409"
        ),
        EARN_IMPLEMENTATION_WORD
    );
    let upgrade = fs::read_to_string(root.join("source/core/core-chain/upgrade.go")).unwrap();
    assert!(upgrade.contains("7f973185d67cea94518ff6a176d9ffa8e6eaad80"));

    let sei_primary = read_json(&root.join("rpc/sei-primary.json"));
    let sei_secondary = read_json(&root.join("rpc/sei-secondary.json"));
    let sei_header = &record(&sei_primary, "block_header", "sei")["response"]["result"];
    assert_eq!(sei_header["hash"], manifest["fixed_blocks"]["sei"]["hash"]);
    assert_eq!(
        sei_secondary["response"][1]["result"]["hash"],
        sei_header["hash"]
    );
    for target in [
        "0x0000000000000000000000000000000000001007",
        "0x0000000000000000000000000000000000001005",
    ] {
        assert_eq!(result(&sei_primary, "runtime", target), "0x");
        assert_eq!(
            result(&sei_primary, "implementation_slot", target),
            EIP1967_IMPL_SLOT_ZERO
        );
    }
    assert_eq!(
        read_json(&root.join("rpc/sei-node-v6.5.0.json"))["application_version"]["git_commit"],
        "fbc0d9342ca28887958013170e4020d93cacdbfa"
    );
    assert_eq!(
        read_json(&root.join("rpc/sei-node-v6.5.2.json"))["application_version"]["git_commit"],
        "ab134842ce1bd97af73021bcff5850ad6c29e534"
    );
    assert_eq!(
        read_json(&root.join("rpc/sei-v6.5-upgrade.json"))["height"],
        "208377745"
    );
    for relative in [
        "precompiles/distribution/abi.json",
        "precompiles/distribution/distribution.go",
        "precompiles/staking/abi.json",
        "precompiles/staking/staking.go",
    ] {
        assert_eq!(
            fs::read(root.join("source/sei/v6.5.0").join(relative)).unwrap(),
            fs::read(root.join("source/sei/v6.5.2").join(relative)).unwrap()
        );
    }

    for name in [
        "AgentIdentityRegistry",
        "AssetIdentityRegistry",
        "ScoreEngineV2",
    ] {
        let explorer = read_json(&root.join("blockscout").join(format!("{name}.json")));
        assert_eq!(explorer["is_verified"], true);
        assert_eq!(explorer["proxy_type"], Value::Null);
        assert_eq!(
            hex::decode(
                required_str(&explorer, "deployed_bytecode")
                    .strip_prefix("0x")
                    .unwrap()
            )
            .unwrap(),
            hex_bytes(&root.join("runtime").join(format!("{name}.onchain.hex")))
        );
    }
}

#[test]
fn curated_routes_are_visible_and_compile_to_exact_ir_sets() {
    let root = workspace_root();
    for family in families() {
        let installed = root
            .join("secure/data/erc7730-registry/registry")
            .join(family.source);
        let curated = root
            .join("secure/data/erc7730/curations/files/registry")
            .join(family.source);
        assert_eq!(fs::read(&installed).unwrap(), fs::read(&curated).unwrap());

        let descriptor = read_json(&installed);
        let formats = descriptor["display"]["formats"].as_object().unwrap();
        assert_eq!(formats.len(), family.routes.len());
        assert_eq!(
            descriptor["_pqsigner"]["deploymentFormats"][0]["formats"]
                .as_array()
                .unwrap()
                .iter()
                .map(|route| route.as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            family
                .routes
                .iter()
                .copied()
                .filter(|route| !family.refusals.contains(route))
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            descriptor["_pqsigner"]
                .get("refusalOnlyFormats")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|route| route.as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            family.refusals.iter().copied().collect::<BTreeSet<_>>()
        );
        for route in family.routes {
            for field in formats[*route]["fields"].as_array().unwrap() {
                if field.get("path").is_some() {
                    assert_eq!(
                        field["visible"], "always",
                        "signed operand is not always visible: {} {route}",
                        family.source
                    );
                }
            }
        }
    }

    let asset = read_json(
        &root.join(
            "secure/data/erc7730-registry/registry/avvatar-labs-alia/calldata-AssetIdentityRegistry-base.json",
        ),
    );
    assert_eq!(
        asset["display"]["formats"]
            ["addCrossChainRecord(address _tokenAddress, uint256 _chainId, address _crossChainToken)"]
            ["fields"][2]["format"],
        "raw"
    );
    assert_eq!(
        asset["display"]["formats"]
            ["registerAsset(address _tokenAddress, uint8 _assetClass, uint8 _backingType, string _legalIdentifier, string _jurisdiction, string _custodian)"]
            ["fields"][1]["format"],
        "enum"
    );

    let registry = build_registry();
    for family in families() {
        let entries = registry
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str())
                    == Path::new(family.source)
                        .file_name()
                        .and_then(|name| name.to_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            entries.len(),
            1,
            "unexpected entry count: {}",
            family.source
        );
        let entry = entries[0];
        assert_eq!(entry.chain_id, family.chain_id);
        assert_eq!(entry.contract, address(family.contract));
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("curated IR");
        assert_eq!(
            cross_check_contract(&ir, family.chain_id, &address(family.contract)),
            Ok(())
        );
        assert_eq!(
            ir.format_iter()
                .map(|format| format.unwrap().selector)
                .collect::<BTreeSet<_>>(),
            family
                .routes
                .iter()
                .filter(|route| !family.refusals.contains(route))
                .map(|route| selector(route))
                .collect::<BTreeSet<_>>()
        );
    }
}
