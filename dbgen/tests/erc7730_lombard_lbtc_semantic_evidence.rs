//! Offline evidence checks for the bounded Ethereum Lombard LBTC routes.
//!
//! Rendering and Merkle dispatch are covered by the catalogue tests. This
//! suite pins the external authority package: exact archived bytes, fixed-
//! block multi-provider identity, reproducible deployed runtimes, official-
//! source binding, exact ABI, and the burn/request semantics behind the six
//! flat-static calls accepted by PQ1.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const BLOCK_NUMBER: u64 = 25_582_800;
const BLOCK_HASH: &str = "0x6af3d522c4fdc09750a5677af4a4c2c1cf6baae78663ee577f02b2646716f469";
const STATE_ROOT: &str = "0x62d6ab3264e16b736903423ccfb4804114554c3808264a8df211a7bfcbcf0505";
const EIP1967_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const LBTC_PROXY: &str = "8236a87084f8b84306f72007f36f2618a5634494";
const LBTC_IMPLEMENTATION: &str = "072072317469ebb6c340a47e41561c9c3b782bd9";
const ROUTER_PROXY: &str = "9ece5fb1ab62d9075c4ec814b321e24d8ea021ac";
const ROUTER_IMPLEMENTATION: &str = "b823359367978a28eae71e90f79d95b62348bd80";
const NATIVE_TOKEN_AT_BLOCK: &str = "b0f70c0bd6fd87dbeb7c10dc692a2a6106817072";
const OFFICIAL_COMMIT: &str = "bfd32248badaa2fb35a453f17f3c181badfb3dd6";
const OFFICIAL_TREE: &str = "5278bc4c8f292e58dac2ba21fe016df1e810fc18";
const BATCHES: [&str; 6] = [
    "identity",
    "lbtc-state",
    "lbtc-metadata",
    "lbtc-configuration",
    "router-state",
    "router-configuration",
];
const PROVIDERS: [&str; 3] = ["drpc", "tenderly", "mevblocker"];
const ROUTES: [&str; 6] = [
    "approve(address,uint256)",
    "burn(uint256)",
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "redeem(uint256)",
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/lombard-lbtc")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid archived hex")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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

fn result_map(path: &Path) -> BTreeMap<String, Value> {
    let document = read_json(path);
    let mut results = BTreeMap::new();
    for item in document.as_array().expect("RPC response batch") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(item.get("error").is_none() || item["error"].is_null());
        let id = item["id"].as_str().expect("string RPC id").to_owned();
        let result = item.get("result").expect("RPC result").clone();
        assert!(
            results.insert(id.clone(), result).is_none(),
            "duplicate id {id}"
        );
    }
    results
}

fn request<'a>(document: &'a Value, id: &str) -> &'a Value {
    document
        .as_array()
        .expect("RPC request batch")
        .iter()
        .find(|item| item["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing request id {id}"))
}

fn assert_eip1898(value: &Value) {
    assert_eq!(value["blockHash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(value["requireCanonical"].as_bool(), Some(true));
    assert_eq!(value.as_object().expect("EIP-1898 object").len(), 2);
}

fn address_word(value: &Value) -> String {
    let word = decode_hex(value.as_str().expect("ABI address word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..12], &[0u8; 12], "address word has dirty padding");
    hex::encode(&word[12..])
}

fn uint_word(value: &Value) -> u128 {
    let word = decode_hex(value.as_str().expect("ABI uint word"));
    assert_eq!(word.len(), 32);
    assert_eq!(
        &word[..16],
        &[0u8; 16],
        "test decoder only admits u128 values"
    );
    u128::from_be_bytes(word[16..].try_into().expect("u128 suffix"))
}

fn abi_string(value: &Value) -> String {
    let encoded = decode_hex(value.as_str().expect("ABI string result"));
    assert!(encoded.len() >= 64 && encoded.len() % 32 == 0);
    assert_eq!(&encoded[..31], &[0u8; 31]);
    assert_eq!(encoded[31], 32);
    assert_eq!(&encoded[32..63], &[0u8; 31]);
    let length = usize::from(encoded[63]);
    assert!(64 + length <= encoded.len());
    String::from_utf8(encoded[64..64 + length].to_vec()).expect("UTF-8 metadata")
}

fn abi_signature(function: &Value) -> String {
    let name = function["name"].as_str().expect("ABI function name");
    let types = function["inputs"]
        .as_array()
        .expect("ABI inputs")
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({types})")
}

#[test]
fn evidence_manifest_receipts_every_archived_byte() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(2));
    assert_eq!(
        manifest["fixed_block"]["number"].as_u64(),
        Some(BLOCK_NUMBER)
    );
    assert_eq!(manifest["fixed_block"]["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(
        manifest["fixed_block"]["state_root"].as_str(),
        Some(STATE_ROOT)
    );
    assert_eq!(
        manifest["official_source"]["commit"].as_str(),
        Some(OFFICIAL_COMMIT)
    );
    assert_eq!(
        manifest["official_source"]["tree"].as_str(),
        Some(OFFICIAL_TREE)
    );

    let mut actual = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut actual);
    let mut receipted = BTreeSet::new();
    for artifact in manifest["artifacts"].as_array().expect("artifact receipts") {
        let relative = artifact["path"].as_str().expect("artifact path");
        assert!(!relative.starts_with('/') && !relative.split('/').any(|part| part == ".."));
        assert!(
            receipted.insert(relative.to_owned()),
            "duplicate receipt {relative}"
        );
        let bytes = fs::read(evidence.join(relative)).expect("receipted artifact exists");
        assert_eq!(
            artifact["sha256"].as_str(),
            Some(sha256_hex(&bytes).as_str())
        );
    }
    assert_eq!(
        receipted, actual,
        "manifest must receipt the exact artifact set"
    );
}

#[test]
fn fixed_block_providers_agree_on_proxy_runtime_and_live_configuration() {
    let evidence = evidence_root();
    let rpc = evidence.join("rpc/raw");

    for batch in BATCHES {
        let request_doc = read_json(&rpc.join(format!("request-{batch}.json")));
        for item in request_doc.as_array().expect("request batch") {
            match item["method"].as_str().expect("RPC method") {
                "eth_getCode" | "eth_getStorageAt" | "eth_call" => {
                    let params = item["params"].as_array().expect("RPC params");
                    assert_eip1898(params.last().expect("historical block selector"));
                }
                "eth_getBlockByHash" => {
                    assert_eq!(item["params"][0].as_str(), Some(BLOCK_HASH));
                    assert_eq!(item["params"][1].as_bool(), Some(false));
                }
                "eth_chainId" => {}
                other => panic!("unexpected RPC method {other}"),
            }
        }

        let baseline = result_map(&rpc.join(format!("response-drpc-{batch}.json")));
        for provider in &PROVIDERS[1..] {
            let candidate = result_map(&rpc.join(format!("response-{provider}-{batch}.json")));
            assert_eq!(candidate, baseline, "provider disagreement in {batch}");
        }
    }

    let identity = result_map(&rpc.join("response-drpc-identity.json"));
    assert_eq!(identity["chain-id"].as_str(), Some("0x1"));
    let block = &identity["block"];
    assert_eq!(block["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(block["number"].as_str(), Some("0x1865cd0"));
    assert_eq!(block["stateRoot"].as_str(), Some(STATE_ROOT));

    let lbtc_state = result_map(&rpc.join("response-drpc-lbtc-state.json"));
    assert_eq!(
        address_word(&lbtc_state["lbtc-implementation-slot"]),
        LBTC_IMPLEMENTATION
    );
    let lbtc_proxy_runtime = decode_hex(lbtc_state["lbtc-proxy-code"].as_str().unwrap());
    let lbtc_impl_runtime = decode_hex(lbtc_state["lbtc-implementation-code"].as_str().unwrap());
    assert!(!lbtc_proxy_runtime.is_empty() && !lbtc_impl_runtime.is_empty());
    assert_eq!(
        lbtc_proxy_runtime,
        decode_hex(&read_text(
            &evidence.join("runtime/StakedLBTCProxy.ethereum-mainnet.hex")
        ))
    );
    assert_eq!(
        lbtc_impl_runtime,
        decode_hex(&read_text(
            &evidence.join("runtime/StakedLBTC.implementation.ethereum-mainnet.hex")
        ))
    );

    let router_state = result_map(&rpc.join("response-drpc-router-state.json"));
    assert_eq!(
        address_word(&router_state["router-implementation-slot"]),
        ROUTER_IMPLEMENTATION
    );
    assert_eq!(
        decode_hex(router_state["router-proxy-code"].as_str().unwrap()),
        decode_hex(&read_text(
            &evidence.join("runtime/AssetRouterProxy.ethereum-mainnet.hex")
        ))
    );
    assert_eq!(
        decode_hex(router_state["router-implementation-code"].as_str().unwrap()),
        decode_hex(&read_text(
            &evidence.join("runtime/AssetRouter.implementation.ethereum-mainnet.hex")
        ))
    );

    let metadata = result_map(&rpc.join("response-drpc-lbtc-metadata.json"));
    assert_eq!(abi_string(&metadata["lbtc-name"]), "Lombard Staked Bitcoin");
    assert_eq!(abi_string(&metadata["lbtc-symbol"]), "LBTC");
    assert_eq!(uint_word(&metadata["lbtc-decimals"]), 8);

    let lbtc_config = result_map(&rpc.join("response-drpc-lbtc-configuration.json"));
    assert_eq!(
        address_word(&lbtc_config["lbtc-asset-router"]),
        ROUTER_PROXY
    );
    assert_eq!(uint_word(&lbtc_config["lbtc-redeem-fee"]), 10_000);
    assert_eq!(uint_word(&lbtc_config["lbtc-redeems-enabled"]), 1);

    let router_config = result_map(&rpc.join("response-drpc-router-configuration.json"));
    assert_eq!(
        address_word(&router_config["router-native-token"]),
        NATIVE_TOKEN_AT_BLOCK
    );
    let token_config = decode_hex(router_config["router-lbtc-token-config"].as_str().unwrap());
    assert_eq!(token_config.len(), 96);
    assert_eq!(
        uint_word(&Value::String(format!(
            "0x{}",
            hex::encode(&token_config[..32])
        ))),
        10_000
    );
    assert_eq!(
        uint_word(&Value::String(format!(
            "0x{}",
            hex::encode(&token_config[64..])
        ))),
        1
    );
}

#[test]
fn official_and_verified_sources_rebuild_both_deployed_implementations() {
    let evidence = evidence_root();
    let receipt = read_json(&evidence.join("official/github-git-commit.json"));
    assert_eq!(receipt["sha"].as_str(), Some(OFFICIAL_COMMIT));
    assert_eq!(receipt["tree"]["sha"].as_str(), Some(OFFICIAL_TREE));

    let records = [
        (
            "StakedLBTC",
            "contracts/LBTC/StakedLBTC.sol",
            LBTC_IMPLEMENTATION,
        ),
        (
            "AssetRouter",
            "contracts/LBTC/AssetRouter.sol",
            ROUTER_IMPLEMENTATION,
        ),
    ];
    for (name, source_path, implementation) in records {
        let record = read_json(&evidence.join(format!("blockscout/{name}.implementation.json")));
        assert_eq!(record["name"].as_str(), Some(name));
        assert_eq!(record["file_path"].as_str(), Some(source_path));
        assert_eq!(record["is_verified"].as_bool(), Some(true));
        assert_eq!(
            record["compiler_version"].as_str(),
            Some("v0.8.24+commit.e11b9ed9")
        );
        assert_eq!(record["optimization_enabled"].as_bool(), Some(true));
        assert_eq!(record["optimization_runs"].as_u64(), Some(200));
        assert_eq!(record["evm_version"].as_str(), Some("paris"));

        let output = read_json(&evidence.join(format!("compiler/{name}.standard-output.json")));
        assert!(output["errors"]
            .as_array()
            .map(|errors| errors
                .iter()
                .all(|error| error["severity"].as_str() != Some("error")))
            .unwrap_or(true));
        let compiled = decode_hex(
            output["contracts"][source_path][name]["evm"]["deployedBytecode"]["object"]
                .as_str()
                .expect("compiled deployed runtime"),
        );
        let deployed = decode_hex(&read_text(&evidence.join(format!(
            "runtime/{name}.implementation.ethereum-mainnet.hex"
        ))));
        assert_eq!(
            compiled, deployed,
            "{name} source/settings must rebuild runtime"
        );

        let proxy = read_json(&evidence.join(format!("blockscout/{name}Proxy.json")));
        assert_eq!(proxy["is_verified"].as_bool(), Some(true));
        assert_eq!(proxy["proxy_type"].as_str(), Some("eip1967"));
        assert_eq!(
            proxy["implementations"][0]["address_hash"]
                .as_str()
                .expect("explorer implementation")
                .trim_start_matches("0x")
                .to_ascii_lowercase(),
            implementation
        );
    }

    let exact_sources = [
        ("staked", "contracts/LBTC/StakedLBTC.sol"),
        ("staked", "contracts/LBTC/BaseLBTC.sol"),
        ("router", "contracts/LBTC/AssetRouter.sol"),
        ("staked", "contracts/LBTC/interfaces/IAssetRouter.sol"),
        ("staked", "contracts/LBTC/interfaces/IBaseLBTC.sol"),
        ("staked", "contracts/LBTC/interfaces/IStakedLBTC.sol"),
        ("router", "contracts/LBTC/libraries/Assets.sol"),
        ("router", "contracts/gmp/libs/GMPUtils.sol"),
        ("staked", "contracts/libs/Actions.sol"),
        ("router", "contracts/libs/LChainId.sol"),
    ];
    for (closure, path) in exact_sources {
        assert_eq!(
            fs::read(evidence.join("official").join(path)).expect("official source"),
            fs::read(evidence.join("source/verified").join(closure).join(path))
                .expect("verified source"),
            "official and verified bytes differ for {path}"
        );
    }
}

#[test]
fn exact_abi_and_sources_support_only_the_claimed_signed_meaning() {
    let evidence = evidence_root();
    let abi = read_json(&evidence.join("abi/StakedLBTC.accepted-routes.abi.json"));
    let actual: BTreeSet<String> = abi
        .as_array()
        .expect("ABI projection")
        .iter()
        .map(abi_signature)
        .collect();
    let expected: BTreeSet<String> = ROUTES.iter().map(|route| (*route).to_owned()).collect();
    assert_eq!(actual, expected);
    for route in ROUTES {
        let selector = &keccak256(route.as_bytes())[..4];
        assert_ne!(
            selector, &[0u8; 4],
            "selector derivation remains nontrivial"
        );
    }

    let staked = normalized(&read_text(
        &evidence.join("source/verified/staked/contracts/LBTC/StakedLBTC.sol"),
    ));
    assert!(staked.contains(
        "function burn(uint256 amount) external whenMintBurnAllowed { _burn(_msgSender(), amount); }"
    ));
    assert!(staked
        .contains("function redeem(uint256 amount) external nonReentrant whenMintBurnAllowed"));
    assert!(staked.contains("$.assetRouter.redeem(_msgSender(), address(this), amount);"));

    let router = normalized(&read_text(
        &evidence.join("source/verified/router/contracts/LBTC/AssetRouter.sol"),
    ));
    assert!(router.contains(
        "function redeem( address fromAddress, address fromToken, uint256 amount ) external nonReentrant"
    ));
    assert!(router.contains("uint256 redeemFee = $.tokenConfigs[fromToken].redeemFee;"));
    assert!(router.contains("amount -= redeemFee; fee = redeemFee;"));
    assert!(router.contains(
        "$.mailbox.send( $.ledgerChainId, gmpRecipient, Assets.LEDGER_CALLER, rawPayload );"
    ));
    assert!(router.contains("tokenContract.burn(fromAddress, amount + fee);"));

    let erc20 = normalized(&read_text(&evidence.join(
        "source/verified/staked/@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol",
    )));
    assert!(erc20.contains(
        "function approve(address spender, uint256 value) public virtual returns (bool)"
    ));
    assert!(erc20.contains("_approve(owner, spender, value);"));
    assert!(erc20
        .contains("function transfer(address to, uint256 value) public virtual returns (bool)"));
    assert!(erc20.contains("_transfer(owner, to, value);"));
    assert!(erc20.contains("function transferFrom(address from, address to, uint256 value) public virtual returns (bool)"));
    assert!(erc20.contains("_spendAllowance(from, spender, value); _transfer(from, to, value);"));

    let permit = normalized(&read_text(&evidence.join(
        "source/verified/staked/@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol",
    )));
    assert!(permit.contains(
        "address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s"
    ));
    assert!(permit.contains("ECDSA.recover(hash, v, r, s)"));
    assert!(permit.contains("_approve(owner, spender, value);"));

    let descriptor = read_json(
        &workspace_root()
            .join("secure/data/erc7730-registry/registry/lombard/calldata-lbtc-mainnet.json"),
    );
    let formats = &descriptor["display"]["formats"];
    assert_eq!(
        formats["permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)"]["intent"].as_str(),
        Some("Submit permit")
    );
    assert_eq!(
        formats["redeem(uint256 amount)"]["intent"].as_str(),
        Some("Request redemption")
    );
    assert_eq!(
        formats["redeem(uint256 amount)"]["fields"][0]["label"].as_str(),
        Some("LBTC to Burn")
    );
    assert!(formats.get("mint(bytes rawPayload, bytes proof)").is_some());
    assert!(formats
        .get("redeemForBtc(bytes scriptPubkey, uint256 amount)")
        .is_some());

    let request_state = read_json(&evidence.join("rpc/raw/request-lbtc-state.json"));
    assert_eq!(
        request(&request_state, "lbtc-implementation-slot")["params"][1].as_str(),
        Some(EIP1967_SLOT)
    );
    assert_eq!(
        request(&request_state, "lbtc-proxy-code")["params"][0]
            .as_str()
            .expect("proxy address")
            .trim_start_matches("0x"),
        LBTC_PROXY
    );
}
