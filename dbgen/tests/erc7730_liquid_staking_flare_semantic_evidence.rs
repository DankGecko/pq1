//! Offline evidence, semantic-display, compiled-IR, and exact-refusal checks
//! for the bounded liquid-staking and Flare calldata slice in PQ1 issue #497.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const FILES: [(&str, &str); 7] = [
    ("benqi", "calldata-sAVAX.json"),
    ("ethena", "calldata-ethena.json"),
    ("swell", "calldata-swell.json"),
    ("flare", "calldata-DistributionToDelegators-Flare.json"),
    ("flare", "calldata-PollingFoundation-Flare.json"),
    ("flare", "calldata-PollingFoundation-Songbird.json"),
    ("flare", "calldata-ValidatorRewardManager-Flare.json"),
];

const ZERO_WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const EXECUTABLE_PROPOSE_NAMED: &str = "propose(address[] _targets, uint256[] _values, bytes[] _calldatas, string _description, (bool accept, uint256 votingStartTs, uint256 votingPeriodSeconds, uint256 vpBlockPeriodSeconds, uint256 thresholdConditionBIPS, uint256 majorityConditionBIPS, uint256 executionDelaySeconds, uint256 executionPeriodSeconds) _settings)";
const EXECUTABLE_PROPOSE: &str =
    "propose(address[],uint256[],bytes[],string,(bool,uint256,uint256,uint256,uint256,uint256,uint256,uint256))";
const AUTO_CLAIM_NAMED: &str = "autoClaim(address[] _rewardOwners, uint256 _month)";
const AUTO_CLAIM: &str = "autoClaim(address[],uint256)";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/liquid-staking-flare-calldata")
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

fn rpc_results(chain: &str) -> BTreeMap<String, Value> {
    let root = evidence_root().join("rpc");
    let request = read_json(&root.join(format!("request-{chain}.json")));
    let response = read_json(&root.join(format!("response-{chain}.json")));
    let request_ids = request
        .as_array()
        .expect("RPC request array")
        .iter()
        .map(|entry| required_str(entry, "id").to_string())
        .collect::<BTreeSet<_>>();
    let response_rows = response.as_array().expect("RPC response array");
    let response_ids = response_rows
        .iter()
        .map(|entry| {
            assert!(
                entry.get("error").is_none(),
                "RPC evidence contains an error"
            );
            required_str(entry, "id").to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(request_ids.len(), request.as_array().unwrap().len());
    assert_eq!(response_ids.len(), response_rows.len());
    assert_eq!(request_ids, response_ids, "RPC request/response ID drift");
    response_rows
        .iter()
        .map(|entry| {
            (
                required_str(entry, "id").to_string(),
                entry["result"].clone(),
            )
        })
        .collect()
}

fn result<'a>(results: &'a BTreeMap<String, Value>, id: &str) -> &'a str {
    results
        .get(id)
        .unwrap_or_else(|| panic!("missing RPC result {id}"))
        .as_str()
        .unwrap_or_else(|| panic!("RPC result {id} is not a string"))
}

fn runtime(name: &str) -> String {
    fs::read_to_string(evidence_root().join("runtime").join(name))
        .unwrap_or_else(|error| panic!("read runtime {name}: {error}"))
        .trim()
        .to_string()
}

fn abi_string(encoded: &str) -> String {
    let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded)).expect("ABI hex");
    assert!(bytes.len() >= 64, "ABI string head and length");
    let offset = usize::try_from(u64::from_be_bytes(bytes[24..32].try_into().unwrap())).unwrap();
    let length = usize::try_from(u64::from_be_bytes(
        bytes[offset + 24..offset + 32].try_into().unwrap(),
    ))
    .unwrap();
    String::from_utf8(bytes[offset + 32..offset + 32 + length].to_vec()).expect("UTF-8 ABI string")
}

fn word_u64(encoded: &str) -> u64 {
    let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded)).expect("ABI hex");
    assert_eq!(bytes.len(), 32);
    assert!(bytes[..24].iter().all(|byte| *byte == 0));
    u64::from_be_bytes(bytes[24..].try_into().unwrap())
}

fn word_address(encoded: &str) -> [u8; 20] {
    let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded)).expect("ABI hex");
    assert_eq!(bytes.len(), 32);
    assert!(bytes[..12].iter().all(|byte| *byte == 0));
    bytes[12..].try_into().unwrap()
}

fn descriptor(directory: &str, name: &str) -> Value {
    read_json(
        &workspace_root()
            .join("secure/data/erc7730/curations/files/registry")
            .join(directory)
            .join(name),
    )
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

fn format_values(descriptor: &Value) -> String {
    fn collect(value: &Value, out: &mut Vec<String>) {
        if let Some(text) = value["value"].as_str() {
            out.push(text.to_string());
        }
        if let Some(fields) = value["fields"].as_array() {
            for field in fields {
                collect(field, out);
            }
        }
    }
    let mut values = Vec::new();
    for format in descriptor["display"]["formats"]
        .as_object()
        .expect("display formats")
        .values()
    {
        collect(format, &mut values);
    }
    values.join(" ")
}

#[test]
fn liquid_staking_flare_evidence_is_complete_and_runtime_bound() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let mut actual = BTreeSet::new();
    collect_files(&root, &root, &mut actual);
    let artifacts = manifest["artifacts"].as_array().expect("artifact receipts");
    let expected = artifacts
        .iter()
        .map(|artifact| required_str(artifact, "path").to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "evidence inventory must be exact");
    assert_eq!(
        expected.len(),
        artifacts.len(),
        "duplicate artifact receipt"
    );
    for artifact in artifacts {
        let path = root.join(required_str(artifact, "path"));
        let bytes = fs::read(&path).expect("read receipted evidence");
        assert_eq!(
            artifact["bytes"].as_u64(),
            Some(bytes.len() as u64),
            "byte receipt changed: {}",
            path.display()
        );
        assert_eq!(
            required_str(artifact, "sha256"),
            hex::encode(Sha256::digest(&bytes)),
            "hash receipt changed: {}",
            path.display()
        );
    }

    let receipt = read_json(&root.join("fixed-block-receipt.json"));
    assert_eq!(receipt["schema_version"].as_u64(), Some(1));
    assert!(
        required_str(&receipt, "boundary").contains("No live-state"),
        "authority boundary must remain explicit"
    );
    let expected_blocks = [
        (
            "avalanche",
            43_114,
            "0x57342cb",
            "0x6d59ebd9bcf8821a03679b239129830a17becfd146b82e2aca16004c8493e108",
            "0x756aaf987f3745541cbf111143830f5a08ac483edb3bfcdcddda4fac6b01f00d",
            "0x6a68ad5c",
        ),
        (
            "ethereum",
            1,
            "0x1871b6c",
            "0x20b7d8e8c074fbf86cb88b84aa139c61411637f28e23ed47a469f5298f1b1244",
            "0xe353e35cf219642500ceefb7c5a372800f9b6f72816494475d2d2a4a883c5180",
            "0x6a68ad57",
        ),
        (
            "flare",
            14,
            "0x3f0a439",
            "0x7fba1cba6be5584c736b80dba543b6f996c9fa2828a6837f50933067a0cc3f98",
            "0x43b51b97545a93c68d8133aeb2af96a7ef27df548dc7c6d66a318ee25e049444",
            "0x6a68ad5d",
        ),
        (
            "songbird",
            19,
            "0x7aef31c",
            "0xbbc02055b364abbdad23aea63f356f3e444bae51867b752c1d7317effe15e83e",
            "0x69c1562484d91c68d00a1972fdeaf27063d568819dd218ad01bff282501603cd",
            "0x6a68ad5f",
        ),
    ];
    let mut all_results = BTreeMap::new();
    for (chain, chain_id, number, hash, state_root, timestamp) in expected_blocks {
        let results = rpc_results(chain);
        let block = &results["block"];
        assert_eq!(block["number"], number);
        assert_eq!(block["hash"], hash);
        assert_eq!(block["stateRoot"], state_root);
        assert_eq!(block["timestamp"], timestamp);
        assert_eq!(
            receipt["blocks"][chain]["chain_id"].as_u64(),
            Some(chain_id)
        );
        assert_eq!(receipt["blocks"][chain]["number_hex"], number);
        assert_eq!(receipt["blocks"][chain]["hash"], hash);
        assert_eq!(receipt["blocks"][chain]["state_root"], state_root);
        all_results.insert(chain, results);
    }

    let runtime_bindings = [
        ("avalanche", "savax-proxy-code", "benqi-savax-proxy.hex"),
        (
            "avalanche",
            "savax-implementation-code",
            "benqi-savax-implementation.hex",
        ),
        ("ethereum", "susde-code", "ethena-susde.hex"),
        ("ethereum", "swell-proxy-code", "swell-rsweth-proxy.hex"),
        (
            "ethereum",
            "swell-implementation-code",
            "swell-rsweth-implementation.hex",
        ),
        ("flare", "distribution-code", "flare-distribution.hex"),
        ("flare", "polling-code", "flare-polling.hex"),
        ("songbird", "polling-code", "songbird-polling.hex"),
        ("flare", "validator-code", "flare-validator-reward.hex"),
    ];
    for (chain, id, file) in runtime_bindings {
        assert_eq!(result(&all_results[chain], id), runtime(file));
    }

    let avalanche = &all_results["avalanche"];
    assert_eq!(
        word_address(result(avalanche, "savax-implementation-slot")),
        address("0xb791c7a42fd0d10f90deaa906a8735f79719fa53")
    );
    assert_eq!(result(avalanche, "savax-admin-slot"), ZERO_WORD);
    assert_eq!(result(avalanche, "savax-beacon-slot"), ZERO_WORD);
    assert_eq!(abi_string(result(avalanche, "savax-name")), "Staked AVAX");
    assert_eq!(abi_string(result(avalanche, "savax-symbol")), "sAVAX");
    assert_eq!(word_u64(result(avalanche, "savax-decimals")), 18);
    assert_eq!(
        word_u64(result(avalanche, "savax-cooldown-period")),
        1_296_000
    );
    assert_eq!(word_u64(result(avalanche, "savax-redeem-period")), 172_800);

    let ethereum = &all_results["ethereum"];
    for id in [
        "susde-implementation-slot",
        "susde-admin-slot",
        "susde-beacon-slot",
        "swell-admin-slot",
        "swell-beacon-slot",
        "swell-core-paused",
    ] {
        assert_eq!(result(ethereum, id), ZERO_WORD, "{id}");
    }
    assert_eq!(
        word_address(result(ethereum, "swell-implementation-slot")),
        address("0x4796d939b22027c2876d5ce9fde52da9ec4e2362")
    );
    assert_eq!(abi_string(result(ethereum, "susde-name")), "Staked USDe");
    assert_eq!(abi_string(result(ethereum, "susde-symbol")), "sUSDe");
    assert_eq!(word_u64(result(ethereum, "susde-decimals")), 18);
    assert_eq!(
        word_address(result(ethereum, "susde-asset")),
        address("0x4c9edd5852cd905f086c759e8383e09bff1e68b3")
    );
    assert_eq!(
        word_address(result(ethereum, "susde-silo")),
        address("0x7fc7c91d556b400afa565013e3f32055a0713425")
    );
    assert_eq!(
        word_u64(result(ethereum, "susde-cooldown-duration")),
        86_400
    );
    assert_eq!(abi_string(result(ethereum, "usde-name")), "USDe");
    assert_eq!(abi_string(result(ethereum, "usde-symbol")), "USDe");
    assert_eq!(word_u64(result(ethereum, "usde-decimals")), 18);
    assert_eq!(abi_string(result(ethereum, "swell-name")), "rswETH");
    assert_eq!(abi_string(result(ethereum, "swell-symbol")), "rswETH");
    assert_eq!(word_u64(result(ethereum, "swell-decimals")), 18);
    for (id, expected) in [
        (
            "swell-access-manager",
            "0x796592b2092f7e150c48643da19dd2f28be3333f",
        ),
        (
            "swell-deposit-manager",
            "0x5e6342d8090665be14eeb8154c8a87b7249a4889",
        ),
        (
            "swell-treasury",
            "0xf17b581496bc2669ce0931facaa1ade35029e85d",
        ),
        (
            "swell-operator-registry",
            "0xaae0b305b3f1edde7b11b680d4fa9252f7a1c524",
        ),
    ] {
        assert_eq!(
            word_address(result(ethereum, id)),
            address(expected),
            "{id}"
        );
    }

    let flare = &all_results["flare"];
    for id in [
        "distribution-implementation-slot",
        "distribution-admin-slot",
        "distribution-beacon-slot",
        "polling-implementation-slot",
        "polling-admin-slot",
        "polling-beacon-slot",
        "validator-implementation-slot",
        "validator-admin-slot",
        "validator-beacon-slot",
    ] {
        assert_eq!(result(flare, id), ZERO_WORD, "{id}");
    }
    assert_eq!(
        word_address(result(flare, "distribution-wnat")),
        address("0x1d80c49bbbcd1c0911346656b529df9e5c2f783d")
    );
    assert_eq!(
        word_address(result(flare, "distribution-claim-setup-manager")),
        address("0xd56c0ea37b848939b59e6f5cda119b3fa473b5eb")
    );
    assert_eq!(
        word_address(result(flare, "validator-wnat")),
        address("0x1d80c49bbbcd1c0911346656b529df9e5c2f783d")
    );
    assert_eq!(word_u64(result(flare, "validator-active")), 1);
    let songbird = &all_results["songbird"];
    for id in [
        "polling-implementation-slot",
        "polling-admin-slot",
        "polling-beacon-slot",
    ] {
        assert_eq!(result(songbird, id), ZERO_WORD, "{id}");
    }
}

#[test]
fn verified_source_and_curations_preserve_the_semantic_boundary() {
    let root = evidence_root();
    let routescan_proxy = read_json(&root.join("explorer/benqi-savax-proxy.json"));
    let routescan_impl = read_json(&root.join("explorer/benqi-savax-implementation.json"));
    assert_eq!(routescan_proxy["status"], "1");
    assert_eq!(
        routescan_proxy["result"][0]["ContractName"],
        "TransparentUpgradeableProxy"
    );
    assert_eq!(routescan_proxy["result"][0]["Proxy"], "1");
    assert_eq!(
        routescan_proxy["result"][0]["Implementation"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase(),
        "0xb791c7a42fd0d10f90deaa906a8735f79719fa53"
    );
    assert_eq!(routescan_impl["result"][0]["ContractName"], "StakedAvax");
    assert_eq!(
        routescan_impl["result"][0]["CompilerVersion"],
        "v0.6.12+commit.27d51765"
    );
    let savax_source = required_str(&routescan_impl["result"][0], "SourceCode");
    for fragment in [
        "function submit() public payable",
        "uint deposit = msg.value;",
        "uint shareAmount = getSharesByPooledAvax(deposit);",
        "function requestUnlock(uint shareAmount)",
        "_transfer(msg.sender, address(this), shareAmount);",
        "function redeem(uint unlockIndex)",
        "function redeemOverdueShares(uint unlockIndex)",
    ] {
        assert!(
            savax_source.contains(fragment),
            "sAVAX source lost {fragment}"
        );
    }

    let blockscout_cases = [
        (
            "ethena-susde.json",
            "StakedUSDeV2",
            "0.8.19+commit.7dd6d404",
            "ethena-susde.hex",
        ),
        (
            "swell-rsweth-proxy.json",
            "TransparentUpgradeableProxy",
            "0.8.9+commit.e5eed63a",
            "swell-rsweth-proxy.hex",
        ),
        (
            "swell-rsweth-implementation.json",
            "RswETH",
            "0.8.16+commit.07a7930e",
            "swell-rsweth-implementation.hex",
        ),
        (
            "flare-distribution.json",
            "DistributionToDelegators",
            "v0.7.6+commit.7338295f",
            "flare-distribution.hex",
        ),
        (
            "flare-polling.json",
            "PollingFoundation",
            "v0.8.20+commit.a1b79de6",
            "flare-polling.hex",
        ),
        (
            "songbird-polling.json",
            "PollingFoundation",
            "v0.8.20+commit.a1b79de6",
            "songbird-polling.hex",
        ),
        (
            "flare-validator-reward.json",
            "ValidatorRewardManager",
            "v0.7.6+commit.7338295f",
            "flare-validator-reward.hex",
        ),
    ];
    for (file, name, compiler, runtime_file) in blockscout_cases {
        let contract = read_json(&root.join("explorer").join(file));
        assert_eq!(contract["name"], name);
        assert_eq!(contract["compiler_version"], compiler);
        assert_eq!(contract["is_verified"], true);
        assert_eq!(contract["is_changed_bytecode"], false);
        assert_eq!(
            required_str(&contract, "deployed_bytecode"),
            runtime(runtime_file),
            "{file} runtime drift"
        );
    }

    let source_cases: [(&str, &[&str]); 6] = [
        (
            "ethena-susde.json",
            &[
                "function unstake(address receiver) external",
                "UserCooldown storage userCooldown = cooldowns[msg.sender];",
                "silo.withdraw(receiver, assets);",
                "function cooldownAssets(uint256 assets)",
                "function cooldownShares(uint256 shares)",
            ],
        ),
        (
            "swell-rsweth-implementation.json",
            &[
                "function withdrawERC20(",
                "_token.balanceOf(address(this))",
                "function depositWithReferral(address referral)",
                "function depositViaDepositManager(",
                "msg.sender != address(AccessControlManager.DepositManager())",
                "function reprice(",
            ],
        ),
        (
            "flare-distribution.json",
            &[
                "function confirmOptOutOfAirdrop(address[] calldata _optOutAddresses)",
                "function claim(",
                "function autoClaim(address[] calldata _rewardOwners, uint256 _month)",
                "getAutoClaimAddressesAndExecutorFee(msg.sender, _rewardOwners)",
                "executorFeeValue.mul(_rewardOwners.length)",
            ],
        ),
        (
            "flare-polling.json",
            &[
                "new address[](0), new uint256[](0), new bytes[](0)",
                "bytes[] memory _calldatas",
                "_propose(_targets, _values, _calldatas, _description, _settings)",
            ],
        ),
        (
            "songbird-polling.json",
            &[
                "new address[](0), new uint256[](0), new bytes[](0)",
                "bytes[] memory _calldatas",
            ],
        ),
        (
            "flare-validator-reward.json",
            &[
                "contract ValidatorRewardManager is GenericRewardManager",
                "GenericRewardManager(",
                "return \"ValidatorRewardManager\";",
            ],
        ),
    ];
    for (file, fragments) in source_cases {
        let contract = read_json(&root.join("explorer").join(file));
        let source = required_str(&contract, "source_code");
        for fragment in fragments {
            assert!(source.contains(fragment), "{file} source lost {fragment}");
        }
    }

    for (directory, name) in FILES {
        let installed = workspace_root()
            .join("secure/data/erc7730-registry/registry")
            .join(directory)
            .join(name);
        let curated = workspace_root()
            .join("secure/data/erc7730/curations/files/registry")
            .join(directory)
            .join(name);
        assert_eq!(
            fs::read(&installed).expect("installed descriptor"),
            fs::read(&curated).expect("curated descriptor"),
            "installed descriptor diverged from curation: {directory}/{name}"
        );
        let descriptor = descriptor(directory, name);
        let note = required_str(&descriptor, "_curation_note");
        for boundary in ["historical authority", "future", "blind-signing authority"] {
            assert!(note.contains(boundary), "{name} lost boundary {boundary}");
        }
        assert_eq!(
            descriptor["_pqsigner"]["deploymentFormats"]
                .as_array()
                .expect("deployment allowlist")
                .len(),
            1
        );
    }

    let savax = descriptor("benqi", "calldata-sAVAX.json");
    let ethena = descriptor("ethena", "calldata-ethena.json");
    let swell = descriptor("swell", "calldata-swell.json");
    for (descriptor, count, warnings) in [
        (
            &savax,
            6,
            &[
                "Live pool rate; no signed minimum",
                "Amount uses request-time exchange-rate state",
                "Amount comes from the indexed request state",
            ][..],
        ),
        (
            &ethena,
            3,
            &[
                "Calculated at the live vault rate",
                "Full amount from caller cooldown state",
            ][..],
        ),
        (
            &swell,
            15,
            &[
                "Read-only; allowance is not changed",
                "Configured DepositManager only",
                "Live rate; no signed minimum",
                "Configured operators and treasury",
                "Authenticated platform-admin signer",
            ][..],
        ),
    ] {
        assert_eq!(
            descriptor["_pqsigner"]["deploymentFormats"][0]["formats"]
                .as_array()
                .unwrap()
                .len(),
            count
        );
        let values = format_values(descriptor);
        for warning in warnings {
            assert!(values.contains(warning), "missing warning: {warning}");
        }
    }

    let distribution = descriptor("flare", "calldata-DistributionToDelegators-Flare.json");
    assert_eq!(
        distribution["_pqsigner"]["refusalOnlyFormats"],
        serde_json::json!([AUTO_CLAIM_NAMED])
    );
    assert_eq!(
        distribution["_pqsigner"]["deploymentFormats"][0]["formats"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        distribution["metadata"]["enums"]["payout"],
        serde_json::json!({
            "0": "Native FLR",
            "1": "Wrapped FLR"
        })
    );
    assert!(format_values(&distribution).contains("Calculated from distribution state"));

    for name in [
        "calldata-PollingFoundation-Flare.json",
        "calldata-PollingFoundation-Songbird.json",
    ] {
        let polling = descriptor("flare", name);
        assert_eq!(
            polling["_pqsigner"]["refusalOnlyFormats"],
            serde_json::json!([EXECUTABLE_PROPOSE_NAMED])
        );
        assert_eq!(
            polling["_pqsigner"]["deploymentFormats"][0]["formats"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            polling["metadata"]["enums"]["vote"],
            serde_json::json!({"0": "Against", "1": "For"})
        );
        assert!(format_values(&polling).contains("None; source supplies empty call arrays"));
    }

    let validator = descriptor("flare", "calldata-ValidatorRewardManager-Flare.json");
    assert_eq!(
        validator["_pqsigner"]["deploymentFormats"][0]["formats"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let validator_values = format_values(&validator);
    assert!(validator_values.contains("Replace full list; empty clears all"));
    assert!(validator_values.contains("Replace full list; owner remains allowed"));
}

#[test]
fn liquid_staking_flare_compilation_admits_only_allowlisted_routes_and_refusals() {
    let registry = build_registry();
    let cases: [(&str, u64, &str, &[&str]); 7] = [
        (
            "calldata-sAVAX.json",
            43_114,
            "0x2b2c81e08f1af8835a78bb2a90ae924ace0ea4be",
            &[
                "submit()",
                "requestUnlock(uint256)",
                "redeem()",
                "redeem(uint256)",
                "redeemOverdueShares()",
                "redeemOverdueShares(uint256)",
            ],
        ),
        (
            "calldata-ethena.json",
            1,
            "0x9d39a5de30e57443bff2a8307a4256c8797a3497",
            &[
                "cooldownAssets(uint256)",
                "cooldownShares(uint256)",
                "unstake(address)",
            ],
        ),
        (
            "calldata-swell.json",
            1,
            "0xfae103dc9cf190ed75350761e95403b7b8afa6c0",
            &[
                "addToWhitelist(address)",
                "allowance(address,address)",
                "approve(address,uint256)",
                "batchAddToWhitelist(address[])",
                "batchRemoveFromWhitelist(address[])",
                "burn(uint256)",
                "decreaseAllowance(address,uint256)",
                "depositViaDepositManager(uint256,address,uint256)",
                "depositWithReferral(address)",
                "increaseAllowance(address,uint256)",
                "removeFromWhitelist(address)",
                "reprice(uint256,uint256,uint256)",
                "transfer(address,uint256)",
                "transferFrom(address,address,uint256)",
                "withdrawERC20(address)",
            ],
        ),
        (
            "calldata-DistributionToDelegators-Flare.json",
            14,
            "0x9c7a4c83842b29bb4a082b0e689cb9474bd938d0",
            &[
                "claim(address,address,uint256,bool)",
                "confirmOptOutOfAirdrop(address[])",
            ],
        ),
        (
            "calldata-PollingFoundation-Flare.json",
            14,
            "0xc8294a2335c6c45de827121090ce4ba9977907d2",
            &[
                "castVote(uint256,uint8)",
                "propose(string,(bool,uint256,uint256,uint256,uint256,uint256))",
            ],
        ),
        (
            "calldata-PollingFoundation-Songbird.json",
            19,
            "0x79df47237292dbd1477502cff3f61cd535b0face",
            &[
                "castVote(uint256,uint8)",
                "propose(string,(bool,uint256,uint256,uint256,uint256,uint256))",
            ],
        ),
        (
            "calldata-ValidatorRewardManager-Flare.json",
            14,
            "0xc0cf3aaf93bd978c5bc662564aa73e331f2ec0b5",
            &[
                "claim(address,address,uint256,bool)",
                "setAllowedClaimRecipients(address[])",
                "setClaimExecutors(address[])",
            ],
        ),
    ];
    for (file, chain_id, contract_text, routes) in cases {
        let entries = registry
            .entries
            .iter()
            .filter(|entry| entry.source.file_name().and_then(|name| name.to_str()) == Some(file))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "accepted leaf count changed: {file}");
        let entry = entries[0];
        let contract = address(contract_text);
        assert_eq!(entry.chain_id, chain_id);
        assert_eq!(entry.contract, contract);
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse curated IR");
        assert_eq!(cross_check_contract(&ir, chain_id, &contract), Ok(()));
        let expected = routes
            .iter()
            .map(|route| selector(route))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            ir.format_iter()
                .map(|format| format.expect("valid format").selector)
                .collect::<BTreeSet<_>>(),
            expected,
            "unexpected admitted selector set: {file}"
        );
        for route_selector in expected {
            assert!(registry
                .known_calls
                .contains(&(chain_id, contract, route_selector)));
            assert!(known_call_may_contain(
                &registry.known_calls_bloom,
                chain_id,
                &contract,
                &route_selector
            ));
        }
    }

    for (chain_id, contract_text, refused) in [
        (14, "0x9c7a4c83842b29bb4a082b0e689cb9474bd938d0", AUTO_CLAIM),
        (
            14,
            "0xc8294a2335c6c45de827121090ce4ba9977907d2",
            EXECUTABLE_PROPOSE,
        ),
        (
            19,
            "0x79df47237292dbd1477502cff3f61cd535b0face",
            EXECUTABLE_PROPOSE,
        ),
    ] {
        let contract = address(contract_text);
        let refused_selector = selector(refused);
        let entry = registry
            .entries
            .iter()
            .find(|entry| entry.chain_id == chain_id && entry.contract == contract)
            .expect("refusal deployment remains accepted for safe siblings");
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse refusal deployment IR");
        assert!(ir
            .find_format_by_selector(&refused_selector)
            .expect("format lookup")
            .is_none());
        assert!(registry
            .known_calls
            .contains(&(chain_id, contract, refused_selector)));
        assert!(known_call_may_contain(
            &registry.known_calls_bloom,
            chain_id,
            &contract,
            &refused_selector
        ));
    }

    let inventory = read_json(
        &workspace_root().join("tests/erc7730-semantic-evidence/accepted-family-inventory.json"),
    );
    let families = inventory["families"]
        .as_array()
        .expect("accepted-family records");
    for category in [
        "pinned-evidence",
        "shared-standard-implementation",
        "lower-priority-residual",
    ] {
        let source_count = families
            .iter()
            .filter(|family| family["classification"] == category)
            .count() as u64;
        let leaf_count = families
            .iter()
            .filter(|family| family["classification"] == category)
            .map(|family| family["accepted_leaf_count"].as_u64().unwrap())
            .sum::<u64>();
        assert_eq!(
            inventory["catalogue_snapshot"]["category_source_counts"][category].as_u64(),
            Some(source_count),
            "{category} source accounting"
        );
        assert_eq!(
            inventory["catalogue_snapshot"]["category_leaf_counts"][category].as_u64(),
            Some(leaf_count),
            "{category} leaf accounting"
        );
    }
    assert_eq!(
        inventory["evidence_sets"]["liquid-staking-flare-calldata"]["paths"],
        serde_json::json!([
            "tests/erc7730-semantic-evidence/liquid-staking-flare-calldata/manifest.json"
        ])
    );
    let sources = FILES
        .iter()
        .map(|(directory, file)| format!("{directory}/{file}"))
        .collect::<BTreeSet<_>>();
    let promoted = families
        .iter()
        .filter(|family| sources.contains(required_str(family, "source")))
        .collect::<Vec<_>>();
    assert_eq!(promoted.len(), 7);
    for family in promoted {
        assert_eq!(family["classification"], "pinned-evidence");
        assert_eq!(family["evidence"], "liquid-staking-flare-calldata");
        assert!(family.get("successor_issue").is_none());
    }
}
