//! Offline deployment, source, token, and signed-meaning evidence for the
//! accepted Ondo GMTokenLimitOrder, OUSGInstantManager, and USDYInstantManager
//! descriptor leaves.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const ETH_HASH: &str = "0xd4f3efc66ddcf9d4804e2bee00128fdfc02a54c95a74fd4ba5c79e96729d9944";
const BSC_HASH: &str = "0x298e6b16ec7c93069a4d7048ab44e41f2fae718b7014c1574a606fa7c58816cd";
const EIP1967_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const ETH_BATCHES: [&str; 10] = [
    "identity",
    "managers-runtime",
    "token-proxies-runtime",
    "token-implementations-runtime",
    "token-implementation-slots",
    "ousg-manager-bindings",
    "usdy-manager-bindings",
    "ousg-token-metadata",
    "usdy-token-metadata",
    "rusdy-token-metadata",
];

const GM_ROUTES: [&str; 5] = [
    "cancelOrder(uint256)",
    "createBuyOrderExactIn(address,address,uint256,uint256,uint256)",
    "createBuyOrderExactOut(address,address,uint256,uint256,uint256)",
    "createSellOrderExactIn(address,address,uint256,uint256,uint256)",
    "createSellOrderExactOut(address,address,uint256,uint256,uint256)",
];
const OUSG_ROUTES: [&str; 2] = [
    "redeem(uint256,address,uint256)",
    "subscribe(address,uint256,uint256)",
];
const USDY_ROUTES: [&str; 4] = [
    "redeem(uint256,address,uint256)",
    "redeemRebasingUSDY(uint256,address,uint256)",
    "subscribe(address,uint256,uint256)",
    "subscribeRebasingUSDY(address,uint256,uint256)",
];
const GM_DESCRIPTOR_ROUTES: [&str; 5] = [
    "cancelOrder(uint256 orderId)",
    "createBuyOrderExactIn(address gmToken, address quoteToken, uint256 quoteAmount, uint256 limitPrice, uint256 expiry)",
    "createBuyOrderExactOut(address gmToken, address quoteToken, uint256 gmAmount, uint256 limitPrice, uint256 expiry)",
    "createSellOrderExactIn(address gmToken, address quoteToken, uint256 gmAmount, uint256 limitPrice, uint256 expiry)",
    "createSellOrderExactOut(address gmToken, address quoteToken, uint256 quoteAmount, uint256 limitPrice, uint256 expiry)",
];
const OUSG_DESCRIPTOR_ROUTES: [&str; 2] = [
    "redeem(uint256 rwaAmount, address receivingToken, uint256 minimumTokenReceived)",
    "subscribe(address depositToken, uint256 depositAmount, uint256 minimumRwaReceived)",
];
const USDY_DESCRIPTOR_ROUTES: [&str; 4] = [
    "redeem(uint256 rwaAmount, address receivingToken, uint256 minimumTokenReceived)",
    "redeemRebasingUSDY(uint256 rusdyAmount, address receivingToken, uint256 minimumTokenReceived)",
    "subscribe(address depositToken, uint256 depositAmount, uint256 minimumRwaReceived)",
    "subscribeRebasingUSDY(address depositToken, uint256 depositAmount, uint256 minimumRusdyReceived)",
];

#[derive(Clone, Copy)]
struct Manager {
    chain_id: u64,
    address: &'static str,
    verifier: &'static str,
    runtime: &'static str,
}

const MANAGERS: [Manager; 4] = [
    Manager {
        chain_id: 1,
        address: "0xf0bc39fc911f6437c84d16188dd8294f7110f451",
        verifier: "gm-token-limit-order.ethereum.json",
        runtime: "GMTokenLimitOrder.ethereum.hex",
    },
    Manager {
        chain_id: 56,
        address: "0x96b525b1a93f31e65f4aaf18c53842ed28525d48",
        verifier: "gm-token-limit-order.bsc.json",
        runtime: "GMTokenLimitOrder.bsc.hex",
    },
    Manager {
        chain_id: 1,
        address: "0x93358db73b6cd4b98d89c8f5f230e81a95c2643a",
        verifier: "ousg-instant-manager.ethereum.json",
        runtime: "OUSGInstantManager.ethereum.hex",
    },
    Manager {
        chain_id: 1,
        address: "0xa42613c243b67bf6194ac327795b926b4b491f15",
        verifier: "usdy-instant-manager.ethereum.json",
        runtime: "USDYInstantManager.ethereum.hex",
    },
];

#[derive(Clone, Copy)]
struct Token {
    slug: &'static str,
    address: &'static str,
    implementation: &'static str,
    name: &'static str,
    symbol: &'static str,
    decimals: u128,
}

const TOKENS: [Token; 3] = [
    Token {
        slug: "ousg",
        address: "0x1b19c19393e2d034d8ff31ff34c81252fcbbee92",
        implementation: "0x1ceb44b6e515abf009e0ccb6ddafd723886cf3ff",
        name: "Ondo Short-Term U.S. Government Bond Fund",
        symbol: "OUSG",
        decimals: 18,
    },
    Token {
        slug: "usdy",
        address: "0x96f6ef951840721adbf46ac996b59e0235cb985c",
        implementation: "0xea0f7eebdc2ae40edfe33bf03d332f8a7f617528",
        name: "Ondo U.S. Dollar Yield",
        symbol: "USDY",
        decimals: 18,
    },
    Token {
        slug: "rusdy",
        address: "0xaf37c1167910ebc994e266949387d2c7c326b879",
        implementation: "0x58910371d0b52dcf9d2e0a1af4e0078c58436908",
        name: "Ondo U.S. Dollar Yield (Rebasing)",
        symbol: "rUSDY",
        decimals: 18,
    },
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/ondo-managers")
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
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
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
        let kind = entry.file_type().expect("evidence file type");
        assert!(!kind.is_symlink(), "evidence may not contain symlinks");
        if kind.is_dir() {
            collect_files(root, &path, out);
        } else {
            assert!(kind.is_file(), "unsupported evidence entry");
            let relative = path
                .strip_prefix(root)
                .expect("path remains under evidence root")
                .to_string_lossy()
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn result_map(path: &Path) -> BTreeMap<String, Value> {
    let response = read_json(path);
    let mut results = BTreeMap::new();
    for item in response.as_array().expect("RPC response array") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(item.get("error").is_none() || item["error"].is_null());
        let id = item["id"].as_str().expect("string RPC id").to_owned();
        assert!(
            results.insert(id.clone(), item["result"].clone()).is_none(),
            "duplicate RPC id {id}"
        );
    }
    results
}

fn address_word(value: &Value) -> String {
    let word = decode_hex(value.as_str().expect("ABI address word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..12], &[0u8; 12], "dirty ABI address padding");
    format!("0x{}", hex::encode(&word[12..]))
}

fn uint_word(value: &Value) -> u128 {
    let word = decode_hex(value.as_str().expect("ABI uint word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..16], &[0u8; 16], "test value exceeds u128");
    u128::from_be_bytes(word[16..].try_into().expect("u128 suffix"))
}

fn abi_string(value: &Value) -> String {
    let encoded = decode_hex(value.as_str().expect("ABI string result"));
    assert!(encoded.len() >= 64 && encoded.len() % 32 == 0);
    let offset = uint_word(&Value::String(format!("0x{}", hex::encode(&encoded[..32])))) as usize;
    assert!(offset + 32 <= encoded.len());
    let length = uint_word(&Value::String(format!(
        "0x{}",
        hex::encode(&encoded[offset..offset + 32])
    ))) as usize;
    assert!(offset + 32 + length <= encoded.len());
    String::from_utf8(encoded[offset + 32..offset + 32 + length].to_vec())
        .expect("UTF-8 token metadata")
}

fn abi_signature(function: &Value) -> String {
    let name = function["name"].as_str().expect("ABI function name");
    let inputs = function["inputs"]
        .as_array()
        .expect("ABI function inputs")
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({inputs})")
}

fn source<'a>(record: &'a Value, path: &str) -> &'a str {
    record["sources"][path]["content"]
        .as_str()
        .unwrap_or_else(|| panic!("verified source {path}"))
}

fn format_keys(descriptor: &Value) -> BTreeSet<String> {
    descriptor["display"]["formats"]
        .as_object()
        .expect("descriptor formats")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn receipts_cover_every_byte_and_descriptor_inputs() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["fixed_blocks"]["ethereum"]["hash"].as_str(),
        Some(ETH_HASH)
    );
    assert_eq!(
        manifest["fixed_blocks"]["bsc"]["hash"].as_str(),
        Some(BSC_HASH)
    );
    assert_eq!(manifest["deployments"].as_array().unwrap().len(), 4);
    assert_eq!(
        manifest["deployments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|deployment| deployment["accepted_routes"].as_u64().unwrap())
            .sum::<u64>(),
        16
    );

    let mut actual = BTreeSet::new();
    collect_files(&root, &root, &mut actual);
    let mut receipted = BTreeSet::new();
    for artifact in manifest["artifacts"].as_array().expect("artifact receipts") {
        let relative = artifact["path"].as_str().expect("artifact path");
        assert!(!relative.starts_with('/') && !relative.split('/').any(|part| part == ".."));
        assert!(receipted.insert(relative.to_owned()), "duplicate receipt");
        let bytes = fs::read(root.join(relative)).expect("receipted artifact exists");
        assert_eq!(
            artifact["sha256"].as_str(),
            Some(sha256_hex(&bytes).as_str())
        );
    }
    assert_eq!(receipted, actual, "manifest must receipt the exact package");

    for descriptor in manifest["descriptor_inputs"]
        .as_array()
        .expect("descriptor inputs")
    {
        let path = workspace_root().join(descriptor["path"].as_str().unwrap());
        assert_eq!(
            descriptor["sha256_at_evidence_freeze"].as_str(),
            Some(sha256_hex(&fs::read(path).unwrap()).as_str())
        );
    }
}

#[test]
fn fixed_block_runtime_proxy_and_metadata_bindings_hold() {
    let root = evidence_root();
    let rpc = root.join("rpc/raw");

    for batch in ETH_BATCHES {
        let request = read_json(&rpc.join(format!("request-ethereum-{batch}.json")));
        for item in request.as_array().expect("request batch") {
            match item["method"].as_str().unwrap() {
                "eth_chainId" => assert_eq!(item["params"].as_array().unwrap().len(), 0),
                "eth_getBlockByHash" => {
                    assert_eq!(item["params"][0].as_str(), Some(ETH_HASH));
                    assert_eq!(item["params"][1].as_bool(), Some(false));
                }
                "eth_getCode" | "eth_getStorageAt" | "eth_call" => {
                    let bound = item["params"].as_array().unwrap().last().unwrap();
                    assert_eq!(bound["blockHash"].as_str(), Some(ETH_HASH));
                    assert_eq!(bound["requireCanonical"].as_bool(), Some(true));
                    assert_eq!(bound.as_object().unwrap().len(), 2);
                    if item["method"].as_str() == Some("eth_getStorageAt") {
                        assert_eq!(item["params"][1].as_str(), Some(EIP1967_SLOT));
                    }
                }
                method => panic!("unexpected Ethereum RPC method {method}"),
            }
        }
        let drpc = result_map(&rpc.join(format!("response-ethereum-drpc-{batch}.json")));
        let tenderly = result_map(&rpc.join(format!("response-ethereum-tenderly-{batch}.json")));
        assert_eq!(drpc, tenderly, "provider disagreement in {batch}");
    }

    let eth_identity = result_map(&rpc.join("response-ethereum-drpc-identity.json"));
    assert_eq!(eth_identity["chain-id"].as_str(), Some("0x1"));
    assert_eq!(eth_identity["block"]["hash"].as_str(), Some(ETH_HASH));
    assert_eq!(eth_identity["block"]["number"].as_str(), Some("0x1870100"));
    assert_eq!(
        eth_identity["block"]["stateRoot"].as_str(),
        Some("0xc0d11f7af5afc3ccf3cc3ba0485adf191b4f617ff89c4a3b3a3a552ca7ed89ae")
    );

    let bsc_request = read_json(&rpc.join("request-bsc-identity-runtime.json"));
    let bound = &bsc_request.as_array().unwrap()[2]["params"][1];
    assert_eq!(bound["blockHash"].as_str(), Some(BSC_HASH));
    assert_eq!(bound["requireCanonical"].as_bool(), Some(true));
    let nodereal = result_map(&rpc.join("response-bsc-nodereal-identity-runtime.json"));
    let meowrpc = result_map(&rpc.join("response-bsc-meowrpc-identity-runtime.json"));
    assert_eq!(nodereal["chain-id"], meowrpc["chain-id"]);
    assert_eq!(nodereal["gm-code"], meowrpc["gm-code"]);
    for field in ["hash", "number", "parentHash", "stateRoot", "timestamp"] {
        assert_eq!(nodereal["block"][field], meowrpc["block"][field]);
    }
    assert_eq!(nodereal["chain-id"].as_str(), Some("0x38"));
    assert_eq!(nodereal["block"]["hash"].as_str(), Some(BSC_HASH));

    let sourcify = root.join("verifier/sourcify");
    for manager in MANAGERS {
        let record = read_json(&sourcify.join(manager.verifier));
        assert_eq!(
            record["chainId"].as_str().unwrap().parse::<u64>().unwrap(),
            manager.chain_id
        );
        assert_eq!(
            record["address"].as_str().unwrap().to_ascii_lowercase(),
            manager.address
        );
        assert_eq!(record["match"].as_str(), Some("match"));
        assert_eq!(record["creationMatch"].as_str(), Some("match"));
        assert_eq!(record["runtimeMatch"].as_str(), Some("match"));
        assert_eq!(record["proxyResolution"]["isProxy"].as_bool(), Some(false));
        assert_eq!(
            record["proxyResolution"]["implementations"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            decode_hex(
                record["runtimeBytecode"]["onchainBytecode"]
                    .as_str()
                    .unwrap()
            ),
            decode_hex(&read_text(&root.join("runtime").join(manager.runtime)))
        );
    }

    let eth_manager_results = result_map(&rpc.join("response-ethereum-drpc-managers-runtime.json"));
    assert_eq!(
        decode_hex(eth_manager_results["gm-code"].as_str().unwrap()),
        decode_hex(&read_text(
            &root.join("runtime/GMTokenLimitOrder.ethereum.hex")
        ))
    );
    assert_eq!(
        decode_hex(eth_manager_results["ousg-manager-code"].as_str().unwrap()),
        decode_hex(&read_text(
            &root.join("runtime/OUSGInstantManager.ethereum.hex")
        ))
    );
    assert_eq!(
        decode_hex(eth_manager_results["usdy-manager-code"].as_str().unwrap()),
        decode_hex(&read_text(
            &root.join("runtime/USDYInstantManager.ethereum.hex")
        ))
    );
    assert_eq!(
        decode_hex(nodereal["gm-code"].as_str().unwrap()),
        decode_hex(&read_text(&root.join("runtime/GMTokenLimitOrder.bsc.hex")))
    );

    let slots = result_map(&rpc.join("response-ethereum-drpc-token-implementation-slots.json"));
    let proxy_codes = result_map(&rpc.join("response-ethereum-drpc-token-proxies-runtime.json"));
    let implementation_codes =
        result_map(&rpc.join("response-ethereum-drpc-token-implementations-runtime.json"));
    for token in TOKENS {
        assert_eq!(
            address_word(&slots[&format!("{}-token-implementation-slot", token.slug)])
                .to_ascii_lowercase(),
            token.implementation
        );
        let proxy = read_json(&sourcify.join(format!("{}-token-proxy.ethereum.json", token.slug)));
        let implementation =
            read_json(&sourcify.join(format!("{}-token-implementation.ethereum.json", token.slug)));
        assert_eq!(proxy["match"].as_str(), Some("exact_match"));
        assert_eq!(proxy["proxyResolution"]["isProxy"].as_bool(), Some(true));
        assert_eq!(
            proxy["proxyResolution"]["proxyType"].as_str(),
            Some("EIP1967Proxy")
        );
        assert_eq!(
            proxy["proxyResolution"]["implementations"][0]["address"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase(),
            token.implementation
        );
        assert_eq!(
            implementation["proxyResolution"]["isProxy"].as_bool(),
            Some(false)
        );
        assert_eq!(implementation["runtimeMatch"].as_str(), Some("exact_match"));
        assert_eq!(
            decode_hex(
                proxy_codes[&format!("{}-token-code", token.slug)]
                    .as_str()
                    .unwrap()
            ),
            decode_hex(
                proxy["runtimeBytecode"]["onchainBytecode"]
                    .as_str()
                    .unwrap()
            )
        );
        assert_eq!(
            decode_hex(
                implementation_codes[&format!("{}-token-implementation-code", token.slug)]
                    .as_str()
                    .unwrap()
            ),
            decode_hex(
                implementation["runtimeBytecode"]["onchainBytecode"]
                    .as_str()
                    .unwrap()
            )
        );

        let metadata = result_map(&rpc.join(format!(
            "response-ethereum-drpc-{}-token-metadata.json",
            token.slug
        )));
        assert_eq!(
            abi_string(&metadata[&format!("{}-token-name", token.slug)]),
            token.name
        );
        assert_eq!(
            abi_string(&metadata[&format!("{}-token-symbol", token.slug)]),
            token.symbol
        );
        assert_eq!(
            uint_word(&metadata[&format!("{}-token-decimals", token.slug)]),
            token.decimals
        );
    }

    let ousg = result_map(&rpc.join("response-ethereum-drpc-ousg-manager-bindings.json"));
    assert_eq!(
        address_word(&ousg["ousg-manager-rwa-token"]),
        TOKENS[0].address
    );
    let usdy = result_map(&rpc.join("response-ethereum-drpc-usdy-manager-bindings.json"));
    assert_eq!(
        address_word(&usdy["usdy-manager-rwa-token"]),
        TOKENS[1].address
    );
    assert_eq!(address_word(&usdy["usdy-manager-rusdy"]), TOKENS[2].address);

    let erc20 = read_json(&workspace_root().join("secure/data/erc20.json"));
    for token in &TOKENS[..2] {
        let record = erc20
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| {
                entry["chain_id"].as_u64() == Some(1)
                    && entry["address"]
                        .as_str()
                        .is_some_and(|address| address.eq_ignore_ascii_case(token.address))
            })
            .expect("OUSG/USDY production metadata entry");
        assert_eq!(record["name"].as_str(), Some(token.name));
        assert_eq!(record["symbol"].as_str(), Some(token.symbol));
        assert_eq!(record["decimals"].as_u64(), Some(token.decimals as u64));
    }
}

#[test]
fn verified_abis_sources_and_descriptors_bind_the_signed_meaning() {
    let root = evidence_root();
    let sourcify = root.join("verifier/sourcify");

    let projected = [
        ("GMTokenLimitOrder.accepted-routes.abi.json", &GM_ROUTES[..]),
        (
            "OUSGInstantManager.accepted-routes.abi.json",
            &OUSG_ROUTES[..],
        ),
        (
            "USDYInstantManager.accepted-routes.abi.json",
            &USDY_ROUTES[..],
        ),
    ];
    for (path, expected) in projected {
        let actual: BTreeSet<String> = read_json(&root.join("abi").join(path))
            .as_array()
            .unwrap()
            .iter()
            .map(abi_signature)
            .collect();
        assert_eq!(
            actual,
            expected.iter().map(|route| (*route).to_owned()).collect()
        );
    }

    let manifest = read_json(&root.join("manifest.json"));
    for routes in manifest["routes"].as_object().unwrap().values() {
        for route in routes.as_array().unwrap() {
            let signature = route["signature"].as_str().unwrap();
            let expected = format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]));
            assert_eq!(route["selector"].as_str(), Some(expected.as_str()));
        }
    }

    let gm_eth = read_json(&sourcify.join("gm-token-limit-order.ethereum.json"));
    let gm_bsc = read_json(&sourcify.join("gm-token-limit-order.bsc.json"));
    assert_eq!(gm_eth["sources"], gm_bsc["sources"]);
    assert_eq!(gm_eth["abi"], gm_bsc["abi"]);
    let gm = normalized(source(
        &gm_eth,
        "contracts/limit-order/GMTokenLimitOrder.sol",
    ));
    let order_lib = normalized(source(&gm_eth, "contracts/limit-order/LimitOrderLib.sol"));
    for fragment in [
        "side: IGMTokenManager.QuoteSide.BUY, exactType: IGMTokenLimitOrder.ExactType.EXACT_QUOTE",
        "side: IGMTokenManager.QuoteSide.BUY, exactType: IGMTokenLimitOrder.ExactType.EXACT_GM",
        "side: IGMTokenManager.QuoteSide.SELL, exactType: IGMTokenLimitOrder.ExactType.EXACT_GM",
        "side: IGMTokenManager.QuoteSide.SELL, exactType: IGMTokenLimitOrder.ExactType.EXACT_QUOTE",
        "function cancelOrder(uint256 orderId) external",
    ] {
        assert!(
            gm.contains(fragment),
            "missing GM source fragment {fragment}"
        );
    }
    for fragment in [
        "user: msg.sender, gmToken: params.gmToken, quoteToken: params.quoteToken",
        "exactAmount: params.exactAmount, limitPrice: params.limitPrice, expiry: params.expiry",
        "if (order.user != msg.sender) revert IGMTokenLimitOrder.NotOrderMaker();",
        "if (quote.price > order.limitPrice)",
        "if (quote.price < order.limitPrice)",
        "if (block.timestamp > order.expiry)",
    ] {
        assert!(
            order_lib.contains(fragment),
            "missing order-library fragment {fragment}"
        );
    }

    let ousg_record = read_json(&sourcify.join("ousg-instant-manager.ethereum.json"));
    let usdy_record = read_json(&sourcify.join("usdy-instant-manager.ethereum.json"));
    let base_ousg = normalized(source(
        &ousg_record,
        "contracts/xManager/rwaManagers/BaseRWAManager.sol",
    ));
    let base_usdy = normalized(source(
        &usdy_record,
        "contracts/xManager/rwaManagers/BaseRWAManager.sol",
    ));
    assert_eq!(base_ousg, base_usdy);
    for fragment in [
        "safeTransferFrom( _msgSender(), address(this), depositAmount )",
        "if (rwaAmountOut < minimumRwaReceived) revert RwaReceiveAmountTooSmall();",
        "if (receiveTokenAmount < minimumTokenReceived) revert ReceiveAmountTooSmall();",
        "IERC20(receivingToken).safeTransfer(_msgSender(), receiveTokenAmount);",
    ] {
        assert!(
            base_ousg.contains(fragment),
            "missing shared RWA-manager fragment {fragment}"
        );
    }
    let ousg = normalized(source(
        &ousg_record,
        "contracts/xManager/rwaManagers/OUSG_InstantManager.sol",
    ));
    assert!(ousg.contains("IRWALike(rwaToken).mint(_msgSender(), rwaAmountOut);"));
    assert!(ousg.contains("IRWALike(rwaToken).burn(rwaAmount);"));
    let usdy = normalized(source(
        &usdy_record,
        "contracts/xManager/rwaManagers/USDY_InstantManager.sol",
    ));
    assert!(usdy.contains("rusdy.wrap(usdyAmountOut);"));
    assert!(usdy.contains("if (rusdyAmountOut < minimumRusdyReceived)"));
    assert!(usdy.contains("rusdy.unwrap(rusdyAmount);"));
    assert!(usdy.contains("IRWALike(rwaToken).burn(usdyAmountIn);"));

    let registry = workspace_root().join("secure/data/erc7730-registry/registry/ondo-finance");
    let gm_descriptor = read_json(&registry.join("calldata-GMTokenLimitOrder.json"));
    let ousg_descriptor = read_json(&registry.join("calldata-OUSGInstantManager.json"));
    let usdy_descriptor = read_json(&registry.join("calldata-USDYInstantManager.json"));
    assert_eq!(
        format_keys(&gm_descriptor),
        GM_DESCRIPTOR_ROUTES
            .iter()
            .map(|route| (*route).to_owned())
            .collect::<BTreeSet<_>>(),
    );
    assert_eq!(
        format_keys(&ousg_descriptor),
        OUSG_DESCRIPTOR_ROUTES
            .iter()
            .map(|route| (*route).to_owned())
            .collect()
    );
    assert_eq!(
        format_keys(&usdy_descriptor),
        USDY_DESCRIPTOR_ROUTES
            .iter()
            .map(|route| (*route).to_owned())
            .collect()
    );
    assert_eq!(
        ousg_descriptor["metadata"]["constants"]["OUSGaddress"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase(),
        TOKENS[0].address
    );
    assert_eq!(
        usdy_descriptor["metadata"]["constants"]["USDYaddress"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase(),
        TOKENS[1].address
    );
    assert_eq!(
        usdy_descriptor["metadata"]["constants"]["rUSDYaddress"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase(),
        TOKENS[2].address
    );
    assert_eq!(
        gm_descriptor["context"]["contract"]["deployments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        ousg_descriptor["context"]["contract"]["deployments"][0]["address"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase(),
        MANAGERS[2].address
    );
    assert_eq!(
        usdy_descriptor["context"]["contract"]["deployments"][0]["address"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase(),
        MANAGERS[3].address
    );

    assert_eq!(
        gm_descriptor["display"]["formats"]
            ["createBuyOrderExactIn(address gmToken, address quoteToken, uint256 quoteAmount, uint256 limitPrice, uint256 expiry)"]
            ["fields"][1]["label"]
            .as_str(),
        Some("Spend Amount")
    );
    assert_eq!(
        gm_descriptor["display"]["formats"]
            ["createSellOrderExactIn(address gmToken, address quoteToken, uint256 gmAmount, uint256 limitPrice, uint256 expiry)"]
            ["fields"][2]["label"]
            .as_str(),
        Some("Min Price")
    );
    assert_eq!(
        ousg_descriptor["display"]["formats"]
            ["redeem(uint256 rwaAmount, address receivingToken, uint256 minimumTokenReceived)"]
            ["fields"][1]["label"]
            .as_str(),
        Some("Min Receive Amount")
    );
    assert_eq!(
        usdy_descriptor["display"]["formats"]
            ["subscribeRebasingUSDY(address depositToken, uint256 depositAmount, uint256 minimumRusdyReceived)"]
            ["fields"][1]["label"]
            .as_str(),
        Some("Min rUSDY Received")
    );
}
