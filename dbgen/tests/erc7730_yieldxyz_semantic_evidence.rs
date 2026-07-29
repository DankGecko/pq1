//! Offline evidence, semantic-display, compiled-IR, and exact-refusal checks for
//! the bounded Yield.xyz slice tracked by PQ1 issue #497.

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

const POL_FILE: &str = "calldata-yieldxyz-pol-validator.json";
const USDE_FILE: &str = "calldata-yieldxyz-usde-vault.json";

const POL_IMPLEMENTATION: &str = "0xbe63b977abbaa99fc0243e208340c530dd4ee9e8";
const USDE_PROXY: &str = "0x2d152fb171353e70e45322d32bc748f8a61d9971";
const USDE_IMPLEMENTATION: &str = "0xa7249e2902b956e7127df56bf45d58cff610d832";
const USDE: &str = "0x4c9edd5852cd905f086c759e8383e09bff1e68b3";
const SUSDE: &str = "0x9d39a5de30e57443bff2a8307a4256c8797a3497";

const POL_ROUTES: [&str; 4] = [
    "buyVoucherPOL(uint256,uint256)",
    "sellVoucher_newPOL(uint256,uint256)",
    "unstakeClaimTokens_newPOL(uint256)",
    "withdrawRewardsPOL()",
];
const USDE_DEPOSIT: &str = "deposit(uint256,address)";
const USDE_REFUSED: [&str; 3] = [
    "mint(uint256,address)",
    "redeem(uint256,address,address)",
    "withdraw(uint256,address,address)",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/yieldxyz")
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

fn assert_fixed_block(receipt: &Value) {
    let block = &record(receipt, "block_header", "ethereum")["response"]["result"];
    assert_eq!(block["number"], "0x1871800");
    assert_eq!(
        block["hash"],
        "0x6ef230ed8c6d2bd0eaf04e8e59953d2dfa035151e666101de3d7195aefec9af7"
    );
    assert_eq!(
        block["stateRoot"],
        "0x56201c1863e551e47e584fbe807a6200b8937e7d62a373a37e1342c0f113e27d"
    );
    assert_eq!(block["timestamp"], "0x6a68843b");
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
    assert!(bytes.len() >= offset + 32, "ABI string length word");
    let length = usize::try_from(u64::from_be_bytes(
        bytes[offset + 24..offset + 32].try_into().unwrap(),
    ))
    .unwrap();
    String::from_utf8(bytes[offset + 32..offset + 32 + length].to_vec()).expect("UTF-8 ABI string")
}

fn word_u64(encoded: &str, index: usize) -> u64 {
    let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded)).expect("ABI hex");
    let start = index * 32;
    assert!(bytes[start..start + 24].iter().all(|byte| *byte == 0));
    u64::from_be_bytes(bytes[start + 24..start + 32].try_into().unwrap())
}

fn word_address(encoded: &str, index: usize) -> [u8; 20] {
    let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(encoded)).expect("ABI hex");
    let start = index * 32;
    assert!(bytes[start..start + 12].iter().all(|byte| *byte == 0));
    bytes[start + 12..start + 32].try_into().unwrap()
}

fn abi_signatures(contract: &Value) -> BTreeSet<String> {
    contract["abi"]
        .as_array()
        .expect("verified ABI")
        .iter()
        .filter(|entry| entry["type"] == "function")
        .map(|entry| {
            let inputs = entry["inputs"]
                .as_array()
                .expect("function inputs")
                .iter()
                .map(|input| required_str(input, "type"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{}({inputs})", required_str(entry, "name"))
        })
        .collect()
}

fn descriptor(name: &str) -> Value {
    read_json(
        &workspace_root()
            .join("secure/data/erc7730/curations/files/registry/yieldxyz")
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
fn yieldxyz_evidence_inventory_and_fixed_block_bindings_are_exact() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(manifest["fixed_block"]["number"].as_u64(), Some(25_630_720));
    assert!(required_str(&manifest, "boundary").contains("No live-state"));
    assert_eq!(
        manifest["descriptor_families"]
            .as_array()
            .unwrap()
            .iter()
            .map(|family| family["admitted_leaf_count"].as_u64().unwrap())
            .sum::<u64>(),
        18
    );

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

    let pol_drpc = read_json(&root.join("rpc/pol-drpc.json"));
    let pol_mev = read_json(&root.join("rpc/pol-mevblocker.json"));
    let usde_drpc = read_json(&root.join("rpc/usde-drpc.json"));
    let usde_mev = read_json(&root.join("rpc/usde-mevblocker.json"));
    assert_rpc_agreement(&pol_drpc, &pol_mev);
    assert_rpc_agreement(&usde_drpc, &usde_mev);
    for receipt in [&pol_drpc, &pol_mev, &usde_drpc, &usde_mev] {
        assert_fixed_block(receipt);
    }

    let pol_family = &manifest["descriptor_families"][0];
    let proxies = pol_family["deployments"].as_array().expect("POL proxies");
    assert_eq!(proxies.len(), 17);
    let proxy_runtime = runtime("ValidatorShareProxy.hex");
    let implementation_word = format!("0x{:0>64}", &POL_IMPLEMENTATION[2..]);
    for proxy in proxies {
        let proxy = proxy.as_str().unwrap();
        assert_eq!(result(&pol_drpc, "proxy_code", proxy), proxy_runtime);
        assert_eq!(
            result(&pol_drpc, "implementation_call", proxy),
            implementation_word
        );
    }
    assert_eq!(
        result(&pol_drpc, "implementation_code", POL_IMPLEMENTATION),
        runtime("ValidatorShare.hex")
    );

    assert_eq!(
        result(&usde_drpc, "implementation_slot", USDE_PROXY),
        format!("0x{:0>64}", &USDE_IMPLEMENTATION[2..])
    );
    assert_eq!(
        result(&usde_drpc, "proxy_code", USDE_PROXY),
        runtime("AllocatorVaultProxy.hex")
    );
    assert_eq!(
        result(&usde_drpc, "implementation_code", USDE_IMPLEMENTATION),
        runtime("AllocatorVaultV3.hex")
    );
    assert_eq!(
        word_address(result(&usde_drpc, "underlying_call", USDE_PROXY), 0),
        address(USDE)
    );
    assert_eq!(
        word_address(result(&usde_drpc, "asset_call", USDE_PROXY), 0),
        address(SUSDE)
    );
    assert_eq!(
        word_address(result(&usde_drpc, "strategy_call", USDE_PROXY), 0),
        address(SUSDE)
    );
    assert_eq!(
        abi_string(result(&usde_drpc, "name_call", USDE_PROXY)),
        "StakeKit Ethena USDe Vault"
    );
    assert_eq!(
        abi_string(result(&usde_drpc, "symbol_call", USDE_PROXY)),
        "stk-USDe"
    );
    assert_eq!(
        word_u64(result(&usde_drpc, "decimals_call", USDE_PROXY), 0),
        18
    );

    let config = result(&usde_drpc, "config_call", USDE_PROXY);
    assert_eq!(word_u64(config, 0), 0, "deposit fee");
    assert_eq!(word_u64(config, 1), 1_000_000_000, "performance fee");
    assert_eq!(word_u64(config, 2), 0, "management fee");
    assert_eq!(
        word_address(config, 3),
        address("0xeb8cecc3af94a8308b5b90e78b31a976e162f97f")
    );
    assert_eq!(word_u64(config, 4), 1, "cooldown enabled");

    for (token, runtime_name, name, symbol) in [
        (USDE, "USDe.hex", "USDe", "USDe"),
        (SUSDE, "sUSDe.hex", "Staked USDe", "sUSDe"),
    ] {
        assert_eq!(
            result(&usde_drpc, "token_code", token),
            runtime(runtime_name)
        );
        assert_eq!(abi_string(result(&usde_drpc, "token_name", token)), name);
        assert_eq!(
            abi_string(result(&usde_drpc, "token_symbol", token)),
            symbol
        );
        assert_eq!(word_u64(result(&usde_drpc, "token_decimals", token), 0), 18);
    }
    assert_eq!(
        word_address(result(&usde_drpc, "strategy_asset_call", SUSDE), 0),
        address(USDE)
    );
}

#[test]
fn yieldxyz_verified_source_abi_and_runtime_bind_the_semantic_boundary() {
    let root = evidence_root();
    let pol_proxy = read_json(&root.join("blockscout/ValidatorShareProxy.json"));
    let pol = read_json(&root.join("blockscout/ValidatorShare.json"));
    let usde_proxy = read_json(&root.join("blockscout/AllocatorVaultProxy.json"));
    let usde = read_json(&root.join("blockscout/AllocatorVaultV3.json"));

    for (contract, name, compiler, runs, runtime_name) in [
        (
            &pol_proxy,
            "ValidatorShareProxy",
            "0.5.17+commit.d19bba13",
            200,
            "ValidatorShareProxy.hex",
        ),
        (
            &pol,
            "ValidatorShare",
            "0.5.17+commit.d19bba13",
            200,
            "ValidatorShare.hex",
        ),
        (
            &usde_proxy,
            "TransparentUpgradeableProxy",
            "v0.8.25+commit.b61c2a91",
            10_000,
            "AllocatorVaultProxy.hex",
        ),
        (
            &usde,
            "AllocatorVaultV3",
            "v0.8.25+commit.b61c2a91",
            10_000,
            "AllocatorVaultV3.hex",
        ),
    ] {
        assert_eq!(contract["name"], name);
        assert_eq!(contract["compiler_version"], compiler);
        assert_eq!(contract["optimization_enabled"], true);
        assert_eq!(contract["optimization_runs"].as_u64(), Some(runs));
        assert_eq!(contract["is_verified"], true);
        assert_eq!(contract["is_changed_bytecode"], false);
        assert_eq!(
            required_str(contract, "deployed_bytecode"),
            runtime(runtime_name)
        );
    }
    assert_eq!(pol["is_fully_verified"], true);
    assert_eq!(pol["is_verified_via_sourcify"], true);
    assert_eq!(pol["is_verified_via_eth_bytecode_db"], true);
    assert_eq!(usde["is_partially_verified"], true);
    assert_eq!(usde["is_verified_via_sourcify"], false);
    assert_eq!(usde["is_verified_via_eth_bytecode_db"], true);
    assert_eq!(
        pol_proxy["implementations"][0]["address_hash"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        POL_IMPLEMENTATION
    );
    assert_eq!(usde_proxy["proxy_type"], "eip1967");
    assert_eq!(
        usde_proxy["implementations"][0]["address_hash"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        USDE_IMPLEMENTATION
    );

    let pol_abi = abi_signatures(&pol);
    for route in POL_ROUTES {
        assert!(pol_abi.contains(route), "verified POL ABI lacks {route}");
    }
    let usde_abi = abi_signatures(&usde);
    for route in [USDE_DEPOSIT].into_iter().chain(USDE_REFUSED).chain([
        "underlying()",
        "asset()",
        "strategy()",
        "config()",
    ]) {
        assert!(usde_abi.contains(route), "verified vault ABI lacks {route}");
    }

    let pol_source = required_str(&pol, "source_code");
    for fragment in [
        "return _buyVoucher(_amount, _minSharesToMint, true);",
        "_withdrawAndTransferReward(msg.sender, pol);",
        "uint256 shares = _amount.mul(precision).div(rate);",
        "require(shares >= _minSharesToMint, \"Too much slippage\");",
        "_amount = rate.mul(shares).div(precision);",
        "_sellVoucher_new(claimAmount, maximumSharesToBurn, true);",
        "require(shares <= maximumSharesToBurn, \"too much slippage\");",
        "DelegatorUnbond memory unbond = unbonds_new[msg.sender][unbondNonce];",
        "uint256 _amount = withdrawExchangeRate().mul(shares).div(_getRatePrecision());",
        "_payout(_amount, msg.sender, \"Insufficent rewards\", pol);",
        "_withdrawAndTransferReward(msg.sender, true);",
    ] {
        assert!(
            pol_source.contains(fragment),
            "POL source fragment changed: {fragment}"
        );
    }

    let usde_source = required_str(&usde, "source_code");
    for fragment in [
        "IERC20(underlying).safeTransferFrom(msg.sender, address(this), _underlying);",
        "uint256 userShares = (newShares * (MAX_BPS - config.depositFee)) / MAX_BPS;",
        "uint256 _underlying = previewMint(shares);",
        "uint256 assets = strategy.previewWithdraw(_underlying);",
        "uint256 assets = _convertToAssets(shares, false);",
        "if (config.hasCooldown)",
        "IERC20(address(strategy)).safeTransfer(receiver, assets);",
    ] {
        assert!(
            usde_source.contains(fragment),
            "vault source fragment changed: {fragment}"
        );
    }
}

#[test]
fn yieldxyz_curations_compile_only_the_honest_routes_and_preserve_refusals() {
    let root = workspace_root();
    for name in [POL_FILE, USDE_FILE] {
        let installed = root
            .join("secure/data/erc7730-registry/registry/yieldxyz")
            .join(name);
        let curated = root
            .join("secure/data/erc7730/curations/files/registry/yieldxyz")
            .join(name);
        let bytes = fs::read(&installed).expect("installed Yield.xyz descriptor");
        assert_eq!(
            bytes,
            fs::read(&curated).expect("curated Yield.xyz descriptor")
        );

        let manifest = read_json(&root.join("secure/data/erc7730/curations/manifest.json"));
        let receipt = manifest["replacements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["path"] == format!("registry/yieldxyz/{name}"))
            .expect("Yield.xyz curation receipt");
        assert_eq!(
            receipt["replacement_bytes"].as_u64(),
            Some(bytes.len() as u64)
        );
        assert_eq!(
            required_str(receipt, "replacement_sha256"),
            hex::encode(Sha256::digest(&bytes))
        );
    }

    let pol = descriptor(POL_FILE);
    let pol_formats = pol["display"]["formats"].as_object().expect("POL formats");
    assert_eq!(pol_formats.len(), 4);
    assert_eq!(
        visible_paths(&pol_formats["buyVoucherPOL(uint256 _amount, uint256 _minSharesToMint)"]),
        BTreeSet::from(["#._amount".to_string(), "#._minSharesToMint".to_string()])
    );
    assert_eq!(
        visible_paths(
            &pol_formats["sellVoucher_newPOL(uint256 claimAmount, uint256 maximumSharesToBurn)"]
        ),
        BTreeSet::from([
            "#.claimAmount".to_string(),
            "#.maximumSharesToBurn".to_string()
        ])
    );
    assert_eq!(
        visible_paths(&pol_formats["unstakeClaimTokens_newPOL(uint256 unbondNonce)"]),
        BTreeSet::from(["#.unbondNonce".to_string(), "@.from".to_string()])
    );
    assert_eq!(
        visible_paths(&pol_formats["withdrawRewardsPOL()"]),
        BTreeSet::from(["@.from".to_string()])
    );
    let pol_values = pol_formats
        .values()
        .flat_map(|format| format["fields"].as_array().unwrap())
        .filter_map(|field| field["value"].as_str())
        .collect::<Vec<_>>()
        .join(" ");
    for phrase in [
        "round down",
        "claims accrued",
        "live withdrawal",
        "accrued caller state",
    ] {
        assert!(
            pol_values.contains(phrase),
            "missing POL state warning: {phrase}"
        );
    }

    let usde = descriptor(USDE_FILE);
    assert_eq!(
        usde["_pqsigner"]["deploymentFormats"][0]["formats"],
        serde_json::json!(["deposit(uint256 _underlying, address receiver)"])
    );
    assert_eq!(
        usde["_pqsigner"]["refusalOnlyFormats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "mint(uint256 shares, address receiver)",
            "redeem(uint256 shares, address receiver, address owner)",
            "withdraw(uint256 _underlying, address receiver, address owner)",
        ])
    );
    let deposit = &usde["display"]["formats"]["deposit(uint256 _underlying, address receiver)"];
    assert_eq!(deposit["intent"], "Deposit USDe");
    assert_eq!(
        visible_paths(deposit),
        BTreeSet::from(["_underlying".to_string(), "receiver".to_string()])
    );
    let deposit_values = deposit["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|field| field["value"].as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(deposit_values.contains("live rates and fees"));
    assert!(deposit_values.contains("None signed"));

    let registry = build_registry();
    let pol_entries = registry
        .entries
        .iter()
        .filter(|entry| entry.source.file_name().and_then(|name| name.to_str()) == Some(POL_FILE))
        .collect::<Vec<_>>();
    assert_eq!(pol_entries.len(), 17);
    let expected_pol_selectors = POL_ROUTES
        .into_iter()
        .map(selector)
        .collect::<BTreeSet<_>>();
    for entry in pol_entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("POL IR");
        assert_eq!(
            cross_check_contract(&ir, entry.chain_id, &entry.contract),
            Ok(())
        );
        assert_eq!(
            ir.format_iter()
                .map(|format| format.unwrap().selector)
                .collect::<BTreeSet<_>>(),
            expected_pol_selectors
        );
    }

    let usde_entries = registry
        .entries
        .iter()
        .filter(|entry| entry.source.file_name().and_then(|name| name.to_str()) == Some(USDE_FILE))
        .collect::<Vec<_>>();
    assert_eq!(usde_entries.len(), 1);
    let entry = usde_entries[0];
    assert_eq!(entry.chain_id, 1);
    assert_eq!(entry.contract, address(USDE_PROXY));
    let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("USDe IR");
    assert_eq!(cross_check_contract(&ir, 1, &address(USDE_PROXY)), Ok(()));
    assert_eq!(
        ir.format_iter()
            .map(|format| format.unwrap().selector)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([selector(USDE_DEPOSIT)])
    );
    for route in USDE_REFUSED {
        let refused = selector(route);
        assert!(ir.find_format_by_selector(&refused).unwrap().is_none());
        assert!(registry
            .known_calls
            .contains(&(1, address(USDE_PROXY), refused)));
        assert!(known_call_may_contain(
            &registry.known_calls_bloom,
            1,
            &address(USDE_PROXY),
            &refused
        ));
    }
}
