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

use dbgen::erc7730::{build_db_tolerant_with_erc20_capabilities, Emitted, Erc7730BuildResult};
use pqsigner_erc7730::binding::{cross_check_eip712, BindingError};
use pqsigner_erc7730::bundle::verify_erc7730_bundle;
use pqsigner_erc7730::display::render::render_erc7730_eip712_pages_v3;
use pqsigner_erc7730::ir::ContextKind;
use pqsigner_erc7730::render::RenderErr;
use pqsigner_tx::names::NameResolver;
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
const EIP712_DESCRIPTOR: &str = "registry/lombard/eip712-network-fee-authorization-mainnet.json";
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const DOMAIN_NAME: &str = "Lombard Staked Bitcoin";
const DOMAIN_VERSION: &str = "1";
const FEE_APPROVAL_TYPE: &str = "feeApproval(uint256 chainId,uint256 fee,uint256 expiry)";
const FEE_APPROVAL_TYPEHASH: &str =
    "40ac9f6aa27075e64c1ed1ea2e831b20b8c25efdeb6b79fd0cf683c9a9c50725";
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

fn upstream_fixture_root() -> PathBuf {
    workspace_root().join("tests/erc7730-upstream-fixtures/registry-v2/lombard/testsv2")
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

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn production_registry() -> Erc7730BuildResult {
    let root = workspace_root();
    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry")
    .0
}

fn synth_bundle(registry: &Erc7730BuildResult, entry: &Emitted) -> Vec<u8> {
    let depth = u32::from_le_bytes(registry.blob[24..28].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(registry.blob[28..32].try_into().unwrap()) as usize;
    let proof_base = proofs_off + entry.leaf_index * depth * 32;
    let mut bundle = Vec::with_capacity(2 + entry.ir_bytes.len() + 8 + depth * 32);
    bundle.extend_from_slice(&(entry.ir_bytes.len() as u16).to_be_bytes());
    bundle.extend_from_slice(&entry.ir_bytes);
    bundle.extend_from_slice(&(entry.leaf_index as u32).to_be_bytes());
    bundle.extend_from_slice(&(depth as u32).to_be_bytes());
    bundle.extend_from_slice(&registry.blob[proof_base..proof_base + depth * 32]);
    bundle
}

fn eip712_domain_separator_with_name(name: &str, chain_id: u64, contract: &[u8; 20]) -> [u8; 32] {
    let mut encoded = [0u8; 160];
    encoded[..32].copy_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    encoded[32..64].copy_from_slice(&keccak256(name.as_bytes()));
    encoded[64..96].copy_from_slice(&keccak256(DOMAIN_VERSION.as_bytes()));
    encoded[120..128].copy_from_slice(&chain_id.to_be_bytes());
    encoded[140..160].copy_from_slice(contract);
    keccak256(&encoded)
}

fn eip712_domain_separator(chain_id: u64, contract: &[u8; 20]) -> [u8; 32] {
    eip712_domain_separator_with_name(DOMAIN_NAME, chain_id, contract)
}

fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn pages_text(pages: &pqsigner_erc7730::display::Pages) -> String {
    pages
        .as_slice()
        .iter()
        .flat_map(|page| page.iter())
        .map(|row| String::from_utf8_lossy(row).trim().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn raw_word_transcript(label: &str, word: &[u8; 32]) -> String {
    let encoded = hex::encode(word);
    format!(
        "{label}\n{}\n{}\n1/2 > next\n{label}\n{}\n{}\n2/2 > next",
        &encoded[0..16],
        &encoded[16..32],
        &encoded[32..48],
        &encoded[48..64]
    )
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
    assert_eq!(
        manifest["eip712"]["deployment"]["chain_id"].as_u64(),
        Some(1)
    );
    assert_eq!(
        manifest["eip712"]["deployment"]["verifying_contract"].as_str(),
        Some("0x8236a87084f8b84306f72007f36f2618a5634494")
    );
    assert_eq!(
        manifest["eip712"]["domain"]["canonical_type"].as_str(),
        Some(DOMAIN_TYPE)
    );
    assert_eq!(
        manifest["eip712"]["domain"]["name"].as_str(),
        Some(DOMAIN_NAME)
    );
    assert_eq!(
        manifest["eip712"]["domain"]["version"].as_str(),
        Some(DOMAIN_VERSION)
    );
    assert_eq!(
        manifest["eip712"]["primary_type"]["canonical_type"].as_str(),
        Some(FEE_APPROVAL_TYPE)
    );
    assert_eq!(
        manifest["eip712"]["primary_type"]["typehash"].as_str(),
        Some(format!("0x{FEE_APPROVAL_TYPEHASH}").as_str())
    );
    assert_eq!(
        hex::encode(keccak256(FEE_APPROVAL_TYPE.as_bytes())),
        FEE_APPROVAL_TYPEHASH
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
    assert!(router.contains(
        "uint256 fee = Math.min( $.tokenConfigs[token].maximumMintCommission, feeAction.fee );"
    ));
    assert!(router.contains(
        "bytes32 digest = tokenContract.getFeeDigest( feeAction.fee, feeAction.expiry );"
    ));
    assert!(router.contains("Assert.feeApproval(digest, recipient, userSignature);"));

    let base_lbtc = normalized(&read_text(
        &evidence.join("source/verified/staked/contracts/LBTC/BaseLBTC.sol"),
    ));
    assert!(base_lbtc.contains("Actions.FEE_APPROVAL_EIP712_ACTION, block.chainid, fee, expiry"));
    assert!(base_lbtc.contains("_hashTypedDataV4("));

    let actions = normalized(&read_text(
        &evidence.join("source/verified/staked/contracts/libs/Actions.sol"),
    ));
    assert!(actions.contains(
        "bytes32 internal constant FEE_APPROVAL_EIP712_ACTION = 0x40ac9f6aa27075e64c1ed1ea2e831b20b8c25efdeb6b79fd0cf683c9a9c50725;"
    ));

    assert!(staked.contains("__ERC20Permit_init(\"Lombard Staked Bitcoin\");"));
    let eip712 = normalized(&read_text(&evidence.join(
        "source/verified/staked/@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol",
    )));
    assert!(eip712.contains(
        "keccak256(abi.encode(TYPE_HASH, _EIP712NameHash(), _EIP712VersionHash(), block.chainid, address(this)))"
    ));
    let erc20_permit = normalized(&read_text(&evidence.join(
        "source/verified/staked/@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol",
    )));
    assert!(erc20_permit.contains("__EIP712_init_unchained(name, \"1\");"));

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

    let fee_descriptor = read_json(
        &workspace_root()
            .join("secure/data/erc7730-registry")
            .join(EIP712_DESCRIPTOR),
    );
    assert_eq!(
        fee_descriptor["_pqsigner"]["deploymentFormats"][0]["formats"],
        serde_json::json!([FEE_APPROVAL_TYPE])
    );
    let fee_field = &fee_descriptor["display"]["formats"][FEE_APPROVAL_TYPE]["fields"][1];
    assert_eq!(
        fee_descriptor["display"]["formats"][FEE_APPROVAL_TYPE]["intent"],
        "Max LBTC fee"
    );
    assert_eq!(fee_field["label"], "Base units (hex)");
    assert_eq!(fee_field["format"], "raw");
    assert!(fee_field.get("params").is_none());
    assert_eq!(fee_field["visible"], "always");

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

#[test]
fn upstream_v2_fee_fixtures_preserve_mainnet_exactness_and_sepolia_refusal() {
    let fixtures = [
        (
            "eip712-network-fee-authorization-mainnet.tests.json",
            "43f8267b1804af15dd114772fe0a2d294324188c8281c3199ef8a40623220f03",
            "eip712-network-fee-authorization-mainnet.json",
            1u64,
            "8236a87084f8b84306f72007f36f2618a5634494",
            300_000_000_000_000u128,
            1_779_321_600u64,
            true,
        ),
        (
            "eip712-network-fee-authorization-sepolia.tests.json",
            "1ffa565c0d694bbe09fdbacafa115131f2946d8bfce06b0d6707e0d6532c2dfc",
            "eip712-network-fee-authorization-sepolia.json",
            11_155_111u64,
            "731efa688f3679688cf60a3993b8658138953ed6",
            2_000_000_000_000_000u128,
            1_782_345_600u64,
            false,
        ),
    ];
    let expected_domain_members = serde_json::json!([
        { "name": "name", "type": "string" },
        { "name": "version", "type": "string" },
        { "name": "chainId", "type": "uint256" },
        { "name": "verifyingContract", "type": "address" }
    ]);
    let expected_fee_members = serde_json::json!([
        { "name": "chainId", "type": "uint256" },
        { "name": "fee", "type": "uint256" },
        { "name": "expiry", "type": "uint256" }
    ]);
    let registry = production_registry();
    let registry_root = workspace_root().join("secure/data/erc7730-registry/registry/lombard");
    let typehash = keccak256(FEE_APPROVAL_TYPE.as_bytes());
    let resolver = NameResolver::new();

    for (
        fixture_name,
        fixture_sha256,
        source_name,
        chain_id,
        contract_hex,
        expected_fee,
        expected_expiry,
        admitted,
    ) in fixtures
    {
        let fixture_path = upstream_fixture_root().join(fixture_name);
        let fixture_bytes = fs::read(&fixture_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", fixture_path.display()));
        assert_eq!(
            sha256_hex(&fixture_bytes),
            fixture_sha256,
            "{fixture_name} must remain the exact pulled registry-v2 artifact"
        );
        let fixture: Value = serde_json::from_slice(&fixture_bytes)
            .unwrap_or_else(|error| panic!("parse {}: {error}", fixture_path.display()));
        assert_eq!(
            fixture["$schema"].as_str(),
            Some("../../../specs/erc7730-tests-v2.schema.json")
        );
        let expected_descriptor = format!("../{source_name}");
        assert_eq!(
            fixture["descriptor"].as_str(),
            Some(expected_descriptor.as_str())
        );
        let tests = fixture["tests"].as_array().expect("fixture tests");
        assert_eq!(tests.len(), 1, "fixture has one signed case");
        let test = &tests[0];
        assert_eq!(
            test["description"].as_str(),
            Some("Lombard Network Fee Authorization")
        );
        let data = &test["data"];
        assert_eq!(data["primaryType"].as_str(), Some("feeApproval"));
        assert_eq!(data["types"]["EIP712Domain"], expected_domain_members);
        assert_eq!(data["types"]["feeApproval"], expected_fee_members);
        assert_eq!(
            data["types"].as_object().expect("fixture type map").len(),
            2,
            "no unexamined signed types"
        );
        let domain = &data["domain"];
        assert_eq!(domain["name"].as_str(), Some(DOMAIN_NAME));
        assert_eq!(domain["version"].as_str(), Some(DOMAIN_VERSION));
        assert_eq!(domain["chainId"].as_u64(), Some(chain_id));
        assert_eq!(
            domain["verifyingContract"]
                .as_str()
                .expect("fixture verifying contract")
                .trim_start_matches("0x")
                .to_ascii_lowercase(),
            contract_hex
        );
        assert_eq!(
            domain.as_object().expect("fixture domain").len(),
            4,
            "domain shape is exact"
        );
        let message = &data["message"];
        assert_eq!(
            message
                .as_object()
                .expect("fixture feeApproval message")
                .len(),
            3,
            "every signed feeApproval member is inspected"
        );
        assert_eq!(message["chainId"].as_u64(), Some(chain_id));
        let fixture_fee = message["fee"]
            .as_str()
            .map(|value| value.parse::<u128>().expect("decimal fixture fee"))
            .or_else(|| message["fee"].as_u64().map(u128::from))
            .expect("fixture fee is a uint");
        assert_eq!(fixture_fee, expected_fee);
        assert_eq!(message["expiry"].as_u64(), Some(expected_expiry));

        let contract = address(
            domain["verifyingContract"]
                .as_str()
                .expect("fixture verifying contract"),
        );
        let source = registry_root.join(source_name);
        if admitted {
            assert_eq!(
                source,
                workspace_root()
                    .join("secure/data/erc7730-registry")
                    .join(EIP712_DESCRIPTOR),
                "mainnet fixture must bind the exact curated source"
            );
            let entry = registry
                .entries
                .iter()
                .find(|entry| {
                    entry.chain_id == chain_id
                        && entry.contract == contract
                        && entry.source == source
                })
                .expect("mainnet fixture maps to one production catalogue leaf");
            let bundle = synth_bundle(&registry, entry);
            let verified = verify_erc7730_bundle(&bundle, &registry.root)
                .expect("mainnet fixture Merkle proof verifies");
            assert_eq!(verified.ir.context_kind, ContextKind::Eip712);
            assert_eq!(verified.ir.chain_id, chain_id);
            assert_eq!(verified.ir.contract, contract);
            assert_eq!(verified.ir.format_count(), Ok(1));
            let domain_separator = eip712_domain_separator(chain_id, &contract);
            assert_eq!(verified.ir.domain_separator, domain_separator);
            assert_eq!(
                cross_check_eip712(&verified.ir, chain_id, &domain_separator),
                Ok(())
            );

            let chain_word = word_u128(u128::from(chain_id));
            let fee_word = word_u128(fixture_fee);
            let expiry_word = word_u128(u128::from(expected_expiry));
            let encoded = [chain_word, fee_word, expiry_word].concat();
            let pages = render_erc7730_eip712_pages_v3(
                chain_id,
                &contract,
                &typehash,
                &encoded,
                &[],
                &verified,
                None,
                &resolver,
            )
            .expect("mainnet fixture renders through the production catalogue");
            let text = pages_text(&pages);
            assert!(text.contains("Max LBTC fee"));
            assert!(
                text.contains(&raw_word_transcript("Chain ID", &chain_word)),
                "complete signed chain word is missing:\n{text}"
            );
            assert!(
                text.contains(&raw_word_transcript("Base units (hex)", &fee_word)),
                "complete exact raw base-unit fee is missing:\n{text}"
            );
            assert!(
                text.contains("Expiry\n2026-05-21\n00:00:00 UTC"),
                "exact expiry is missing:\n{text}"
            );
            assert!(
                !text.contains("0.0003 ETH"),
                "unauthenticated upstream denomination must not replace raw LBTC base units"
            );
        } else {
            let descriptor = read_json(&source);
            assert_eq!(
                descriptor["_pqsigner"]["deploymentFormats"],
                serde_json::json!([])
            );
            assert_eq!(
                descriptor["_pqsigner"]["refusalOnlyFormats"],
                serde_json::json!([FEE_APPROVAL_TYPE])
            );
            assert!(
                !registry.entries.iter().any(|entry| entry.source == source),
                "Sepolia refusal-only descriptor must emit no production leaf"
            );
            assert!(
                !registry.entries.iter().any(|entry| {
                    if entry.chain_id != chain_id || entry.contract != contract {
                        return false;
                    }
                    let ir = pqsigner_erc7730::ir::Erc7730Ir::parse(&entry.ir_bytes)
                        .expect("production IR parses");
                    ir.context_kind == ContextKind::Eip712
                        && ir
                            .format_iter()
                            .any(|format| format.is_ok_and(|format| format.type_hash == typehash))
                }),
                "Sepolia feeApproval tuple must remain unregistered and therefore unrenderable"
            );
        }
    }
}

#[test]
fn mainnet_fee_approval_is_exactly_bound_and_renders_production_raw_base_units() {
    let registry = production_registry();
    let registry_root = workspace_root().join("secure/data/erc7730-registry");
    let contract = address(LBTC_PROXY);
    let entry = registry
        .entries
        .iter()
        .find(|entry| {
            entry.chain_id == 1
                && entry.contract == contract
                && entry.source == registry_root.join(EIP712_DESCRIPTOR)
        })
        .expect("admitted mainnet Lombard feeApproval leaf");

    let bundle = synth_bundle(&registry, entry);
    let verified = verify_erc7730_bundle(&bundle, &registry.root)
        .expect("mainnet Lombard feeApproval Merkle proof verifies");
    assert_eq!(verified.ir.context_kind, ContextKind::Eip712);
    assert_eq!(verified.ir.chain_id, 1);
    assert_eq!(verified.ir.contract, contract);
    assert_eq!(verified.ir.format_count(), Ok(1));

    let domain_separator = eip712_domain_separator(1, &contract);
    assert_eq!(verified.ir.domain_separator, domain_separator);
    assert_eq!(
        cross_check_eip712(&verified.ir, 1, &domain_separator),
        Ok(())
    );
    assert_eq!(
        cross_check_eip712(&verified.ir, 2, &domain_separator),
        Err(BindingError::ChainIdMismatch)
    );
    assert_eq!(
        cross_check_eip712(
            &verified.ir,
            1,
            &eip712_domain_separator_with_name("Not Lombard Staked Bitcoin", 1, &contract)
        ),
        Err(BindingError::DomainSeparatorMismatch)
    );
    let mut wrong_contract = contract;
    wrong_contract[19] ^= 1;
    assert_eq!(
        cross_check_eip712(
            &verified.ir,
            1,
            &eip712_domain_separator(1, &wrong_contract)
        ),
        Err(BindingError::DomainSeparatorMismatch)
    );

    let typehash = keccak256(FEE_APPROVAL_TYPE.as_bytes());
    assert_eq!(hex::encode(typehash), FEE_APPROVAL_TYPEHASH);
    let resolver = NameResolver::new();
    let exact_fee = word_u128(123_456_700);
    let exact = [word_u128(1), exact_fee, word_u128(1_800_000_000)].concat();
    let pages = render_erc7730_eip712_pages_v3(
        1,
        &contract,
        &typehash,
        &exact,
        &[],
        &verified,
        None,
        &resolver,
    )
    .expect("production metadata-less LBTC fee renders as raw base units");
    let text = pages_text(&pages);
    assert!(
        text.contains("Max LBTC fee"),
        "maximum-fee intent missing:\n{text}"
    );
    assert!(
        text.contains("Base units (hex)"),
        "base-unit radix label missing:\n{text}"
    );
    let exact_hex = hex::encode(exact_fee);
    let exact_raw_pages = format!(
        "Base units (hex)\n{}\n{}\n1/2 > next\nBase units (hex)\n{}\n{}\n2/2 > next",
        &exact_hex[0..16],
        &exact_hex[16..32],
        &exact_hex[32..48],
        &exact_hex[48..64]
    );
    assert!(
        text.contains(&exact_raw_pages),
        "complete signed fee word missing:\n{text}"
    );

    let wrong_signed_chain = [word_u128(2), exact_fee, word_u128(1_800_000_000)].concat();
    let wrong_signed_chain_result = render_erc7730_eip712_pages_v3(
        1,
        &contract,
        &typehash,
        &wrong_signed_chain,
        &[],
        &verified,
        None,
        &resolver,
    );
    assert!(
        matches!(
            wrong_signed_chain_result,
            Err(RenderErr::Reject("7730 word guard failed"))
        ),
        "Lombard constructs feeApproval with block.chainid, so the signed chainId word must equal the authenticated deployment chain"
    );

    let adjacent_fee = word_u128(123_456_701);
    let adjacent = [word_u128(1), adjacent_fee, word_u128(1_800_000_000)].concat();
    let adjacent_pages = render_erc7730_eip712_pages_v3(
        1,
        &contract,
        &typehash,
        &adjacent,
        &[],
        &verified,
        None,
        &resolver,
    )
    .expect("adjacent raw base-unit fee renders without rounding");
    let adjacent_text = pages_text(&adjacent_pages);
    let adjacent_hex = hex::encode(adjacent_fee);
    let adjacent_raw_pages = format!(
        "Base units (hex)\n{}\n{}\n1/2 > next\nBase units (hex)\n{}\n{}\n2/2 > next",
        &adjacent_hex[0..16],
        &adjacent_hex[16..32],
        &adjacent_hex[32..48],
        &adjacent_hex[48..64]
    );
    assert!(
        adjacent_text.contains(&adjacent_raw_pages),
        "adjacent complete signed fee word missing:\n{adjacent_text}"
    );
    assert_ne!(
        text, adjacent_text,
        "distinct signed base-unit values must remain visibly distinct"
    );

    let wrong_typehash = keccak256(b"feeApproval(uint256 chainId,uint256 fee,uint64 expiry)");
    assert!(matches!(
        render_erc7730_eip712_pages_v3(
            1,
            &contract,
            &wrong_typehash,
            &exact,
            &[],
            &verified,
            None,
            &resolver,
        ),
        Err(RenderErr::NoFormat)
    ));
}
