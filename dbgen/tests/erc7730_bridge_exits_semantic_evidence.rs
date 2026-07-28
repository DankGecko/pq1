//! Offline source, deployment, compiled-IR, and refusal checks for four
//! bounded bridge/exit descriptor families.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::{cross_check_contract, BindingError};
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, Visibility};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const EIP1967_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const IGRA_BLOCK: &str = "0x0171afba2a066c674b4fff9e25bbbddc34ef159d430de93a5d95478913149d25";
const SEPOLIA_BLOCK: &str = "0xab08b06d380d5fc12e60c1a21407014dcc5251aa8b37690432ba836d00c2bd88";
const ETHEREUM_BLOCK: &str = "0x6ef230ed8c6d2bd0eaf04e8e59953d2dfa035151e666101de3d7195aefec9af7";

const IGRA_PROXY: &str = "0x4bb88c213d3ed9dc4bae694f1bc1bf745903b2d0";
const IGRA_IMPLEMENTATION: &str = "0x00d39E05A20b2C4f6D0D6CfC3C5718066B861334";
const LOMBARD_PROXY: &str = "0x731eFa688F3679688cf60A3993b8658138953ED6";
const LOMBARD_IMPLEMENTATION: &str = "0xfcC108e3E588cb85018aB736091d134f26151670";
const STARKGATE_PROXY: &str = "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4";
const STARKGATE_IMPLEMENTATION: &str = "0x6ad74D4B79A06A492C288eF66Ef868Dd981fdC85";
const NTT_PROXY: &str = "0x66a28B080918184851774a89aB94850a41f6a1e5";
const NTT_IMPLEMENTATION: &str = "0xd048a8D52da402611A0C5eb6f7388ffC41cd1417";
const BORG_TOKEN: &str = "0x64d0f55Cd8C7133a9D7102b13987235F486F2224";

const IGRA_SOURCE: &str = "registry/igra/calldata-KasExitBridge.json";
const LOMBARD_SOURCE: &str = "registry/lombard/calldata-lbtc-sepolia.json";
const STARKGATE_SOURCE: &str = "registry/starkgate/calldata-StarkGate-STRK.json";
const NTT_SOURCE: &str = "registry/swissborg/calldata-NttManager.json";

const IGRA_ROUTE: &str = "requestExit(string,uint64)";
const STARKGATE_ROUTE: &str = "deposit(address,uint256,uint256)";
const NTT_SIMPLE: &str = "transfer(uint256,uint16,bytes32)";
const NTT_EXTENDED: &str = "transfer(uint256,uint16,bytes32,bytes32,bool,bytes)";
const LOMBARD_ACCEPTED: [&str; 6] = [
    "approve(address,uint256)",
    "burn(uint256)",
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "redeem(uint256)",
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
];
const LOMBARD_REFUSED: [&str; 2] = ["mint(bytes,bytes)", "redeemForBtc(bytes,uint256)"];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/bridge-exits")
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
        .unwrap_or_else(|| panic!("field {key} is a string"))
}

fn decode_hex(text: &str) -> Vec<u8> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).expect("valid hex")
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("four-byte selector")
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
            assert!(ty.is_file(), "unsupported evidence entry");
            let relative = path
                .strip_prefix(root)
                .expect("evidence path under root")
                .to_str()
                .expect("UTF-8 evidence path")
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn rpc_results(path: &Path) -> BTreeMap<String, Value> {
    let mut results = BTreeMap::new();
    for item in read_json(path).as_array().expect("RPC response array") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(
            item.get("error").is_none() || item["error"].is_null(),
            "RPC error in {}",
            path.display()
        );
        let id = required_str(item, "id").to_owned();
        assert!(
            results.insert(id.clone(), item["result"].clone()).is_none(),
            "duplicate RPC id {id}"
        );
    }
    results
}

fn address_word(value: &Value) -> [u8; 20] {
    let word = decode_hex(value.as_str().expect("ABI address word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..12], &[0u8; 12]);
    word[12..].try_into().expect("address word suffix")
}

fn uint_word(value: &Value) -> u64 {
    let word = decode_hex(value.as_str().expect("ABI uint word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..24], &[0u8; 24]);
    u64::from_be_bytes(word[24..].try_into().expect("uint64 suffix"))
}

fn abi_string(value: &Value) -> String {
    let encoded = decode_hex(value.as_str().expect("ABI string"));
    assert!(encoded.len() >= 64);
    assert_eq!(&encoded[..31], &[0u8; 31]);
    assert_eq!(encoded[31], 32);
    let length = uint_word(&Value::String(format!(
        "0x{}",
        hex::encode(&encoded[32..64])
    ))) as usize;
    String::from_utf8(encoded[64..64 + length].to_vec()).expect("UTF-8 ABI string")
}

fn verified_sources(record: &Value) -> BTreeMap<String, String> {
    let mut sources = BTreeMap::new();
    let primary = required_str(record, "file_path").to_owned();
    assert!(sources
        .insert(primary, required_str(record, "source_code").to_owned())
        .is_none());
    for source in record["additional_sources"]
        .as_array()
        .expect("additional sources")
    {
        let path = required_str(source, "file_path").to_owned();
        assert!(!path.starts_with('/') && !path.split('/').any(|part| part == ".."));
        assert!(
            sources
                .insert(path.clone(), required_str(source, "source_code").to_owned())
                .is_none(),
            "duplicate source {path}"
        );
    }
    sources
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments(text: &str, fragments: &[&str], context: &str) {
    let text = normalized(text);
    for fragment in fragments {
        assert!(
            text.contains(fragment),
            "{context} lost semantic fragment: {fragment}"
        );
    }
}

fn abi_signatures(path: &Path) -> BTreeSet<String> {
    read_json(path)
        .as_array()
        .expect("route ABI array")
        .iter()
        .map(|function| {
            let types = function["inputs"]
                .as_array()
                .expect("ABI inputs")
                .iter()
                .map(|input| required_str(input, "type"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{}({types})", required_str(function, "name"))
        })
        .collect()
}

fn request_block_for(path: &Path) -> &'static str {
    let name = path
        .file_name()
        .expect("request file name")
        .to_str()
        .expect("UTF-8 request file name");
    if name.contains("igra") {
        IGRA_BLOCK
    } else if name.contains("sepolia") {
        SEPOLIA_BLOCK
    } else {
        ETHEREUM_BLOCK
    }
}

fn assert_verified_record(record: &Value, name: &str) {
    assert_eq!(record["is_verified"].as_bool(), Some(true), "{name}");
    assert_eq!(
        record["is_changed_bytecode"].as_bool(),
        Some(false),
        "{name}"
    );
    assert!(
        !required_str(record, "deployed_bytecode").is_empty(),
        "{name} deployed bytecode"
    );
    assert!(
        !verified_sources(record).is_empty(),
        "{name} source closure"
    );
}

#[test]
fn evidence_manifest_receipts_every_archived_byte_and_binds_requests() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(2));
    assert_eq!(
        manifest["contracts"]["eip1967_implementation_slot"],
        EIP1967_SLOT
    );
    assert_eq!(
        manifest["fixed_blocks"]["igra"]["hash"].as_str(),
        Some(IGRA_BLOCK)
    );
    assert_eq!(
        manifest["fixed_blocks"]["sepolia"]["hash"].as_str(),
        Some(SEPOLIA_BLOCK)
    );
    assert_eq!(
        manifest["fixed_blocks"]["ethereum"]["hash"].as_str(),
        Some(ETHEREUM_BLOCK)
    );

    let mut receipted = BTreeSet::new();
    for artifact in manifest["artifacts"].as_array().expect("artifact receipts") {
        let relative = required_str(artifact, "path");
        assert!(!relative.starts_with('/') && !relative.split('/').any(|part| part == ".."));
        assert!(
            receipted.insert(relative.to_owned()),
            "duplicate receipt {relative}"
        );
        let bytes = fs::read(evidence.join(relative)).expect("receipted artifact exists");
        assert_eq!(
            required_str(artifact, "sha256"),
            sha256_hex(&bytes),
            "evidence drifted: {relative}"
        );
    }
    let mut actual = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut actual);
    assert_eq!(receipted, actual);

    for entry in fs::read_dir(evidence.join("rpc/raw")).expect("RPC directory") {
        let path = entry.expect("RPC entry").path();
        let name = path.file_name().unwrap().to_str().unwrap();
        if !name.starts_with("request-") {
            continue;
        }
        let expected_block = request_block_for(&path);
        for request in read_json(&path).as_array().expect("request batch") {
            match required_str(request, "method") {
                "eth_getCode" | "eth_getStorageAt" | "eth_call" => {
                    let params = request["params"].as_array().expect("RPC params");
                    let block = params.last().expect("historical block selector");
                    assert_eq!(block["blockHash"].as_str(), Some(expected_block));
                    assert_eq!(block["requireCanonical"].as_bool(), Some(true));
                    assert_eq!(block.as_object().expect("EIP-1898 object").len(), 2);
                }
                "eth_getBlockByHash" => {
                    assert_eq!(request["params"][0].as_str(), Some(expected_block));
                    assert_eq!(request["params"][1].as_bool(), Some(false));
                }
                "eth_chainId" => {}
                method => panic!("unexpected RPC method {method}"),
            }
        }
    }

    for group in manifest["routes"]
        .as_object()
        .expect("route groups")
        .values()
    {
        for route in group.as_array().expect("route list") {
            let signature = required_str(route, "canonical_signature");
            assert_eq!(
                required_str(route, "selector"),
                format!("0x{}", hex::encode(selector(signature)))
            );
        }
    }
}

#[test]
fn fixed_block_providers_bind_proxy_implementation_runtime_and_metadata() {
    let rpc = evidence_root().join("rpc/raw");

    let igra = rpc_results(&rpc.join("response-igra-official-state.json"));
    assert_eq!(igra["chain"], "0x97b1");
    assert_eq!(igra["block"]["hash"].as_str(), Some(IGRA_BLOCK));
    assert_eq!(
        address_word(&igra["implementation"]),
        address(IGRA_IMPLEMENTATION)
    );

    for batch in ["identity", "state", "metadata", "router"] {
        let drpc = rpc_results(&rpc.join(format!("response-sepolia-drpc-{batch}.json")));
        let tenderly = rpc_results(&rpc.join(format!("response-sepolia-tenderly-{batch}.json")));
        assert_eq!(drpc, tenderly, "Sepolia provider disagreement in {batch}");
    }
    let sepolia_identity = rpc_results(&rpc.join("response-sepolia-drpc-identity.json"));
    let sepolia_state = rpc_results(&rpc.join("response-sepolia-drpc-state.json"));
    let sepolia_metadata = rpc_results(&rpc.join("response-sepolia-drpc-metadata.json"));
    assert_eq!(sepolia_identity["chain"], "0xaa36a7");
    assert_eq!(
        sepolia_identity["block"]["hash"].as_str(),
        Some(SEPOLIA_BLOCK)
    );
    assert_eq!(
        address_word(&sepolia_state["implementation"]),
        address(LOMBARD_IMPLEMENTATION)
    );
    assert_eq!(
        abi_string(&sepolia_metadata["name"]),
        "Lombard Staked Bitcoin"
    );
    assert_eq!(abi_string(&sepolia_metadata["symbol"]), "LBTC");
    assert_eq!(uint_word(&sepolia_metadata["decimals"]), 8);

    for batch in [
        "identity",
        "starkgate",
        "ntt-state",
        "ntt-config",
        "borg-state",
        "borg-metadata",
    ] {
        let drpc = rpc_results(&rpc.join(format!("response-ethereum-drpc-{batch}.json")));
        let mev = rpc_results(&rpc.join(format!("response-ethereum-mevblocker-{batch}.json")));
        assert_eq!(drpc, mev, "Ethereum provider disagreement in {batch}");
    }
    let ethereum_identity = rpc_results(&rpc.join("response-ethereum-drpc-identity.json"));
    assert_eq!(ethereum_identity["chain"], "0x1");
    assert_eq!(
        ethereum_identity["block"]["hash"].as_str(),
        Some(ETHEREUM_BLOCK)
    );
    let starkgate = rpc_results(&rpc.join("response-ethereum-drpc-starkgate.json"));
    assert_eq!(
        address_word(&starkgate["implementation"]),
        address(STARKGATE_IMPLEMENTATION)
    );
    let ntt_state = rpc_results(&rpc.join("response-ethereum-drpc-ntt-state.json"));
    assert_eq!(
        address_word(&ntt_state["implementation"]),
        address(NTT_IMPLEMENTATION)
    );
    let ntt_config = rpc_results(&rpc.join("response-ethereum-drpc-ntt-config.json"));
    assert_eq!(address_word(&ntt_config["token"]), address(BORG_TOKEN));
    assert_eq!(uint_word(&ntt_config["mode"]), 0, "locking mode");
    assert_eq!(uint_word(&ntt_config["chain-id"]), 2, "Wormhole Ethereum");
    let borg_state = rpc_results(&rpc.join("response-ethereum-drpc-borg-state.json"));
    assert_eq!(uint_word(&borg_state["manager-token-decimals"]), 18);
    let borg_metadata = rpc_results(&rpc.join("response-ethereum-drpc-borg-metadata.json"));
    assert_eq!(abi_string(&borg_metadata["name"]), "SwissBorg Token");
    assert_eq!(abi_string(&borg_metadata["symbol"]), "BORG");
    assert_eq!(uint_word(&borg_metadata["decimals"]), 18);

    let records = [
        (
            "blockscout/IgraKasExitBridge.proxy.json",
            &igra["proxy-code"],
        ),
        (
            "blockscout/IgraKasExitBridge.implementation.json",
            &igra["implementation-code"],
        ),
        (
            "blockscout/LombardLBTC.proxy.sepolia.json",
            &sepolia_state["proxy-code"],
        ),
        (
            "blockscout/LombardLBTC.implementation.sepolia.json",
            &sepolia_state["implementation-code"],
        ),
        (
            "blockscout/StarkGate.proxy.ethereum.json",
            &starkgate["proxy-code"],
        ),
        (
            "blockscout/StarkGate.implementation.ethereum.json",
            &starkgate["implementation-code"],
        ),
        (
            "blockscout/SwissborgNtt.proxy.ethereum.json",
            &ntt_state["proxy-code"],
        ),
        (
            "blockscout/SwissborgNtt.implementation.ethereum.json",
            &ntt_state["implementation-code"],
        ),
        (
            "blockscout/SwissborgBorgToken.ethereum.json",
            &borg_state["token-code"],
        ),
    ];
    for (relative, runtime) in records {
        let record = read_json(&evidence_root().join(relative));
        assert_verified_record(&record, relative);
        assert_eq!(
            decode_hex(required_str(&record, "deployed_bytecode")),
            decode_hex(runtime.as_str().expect("fixed-block runtime")),
            "verified runtime mismatch: {relative}"
        );
    }
}

#[test]
fn verified_source_and_exact_abis_support_only_the_claimed_meaning() {
    let evidence = evidence_root();

    let igra = read_json(&evidence.join("blockscout/IgraKasExitBridge.implementation.json"));
    assert_eq!(igra["name"], "KasExitBridge");
    assert_eq!(igra["compiler_version"], "v0.8.30+commit.73712a01");
    let igra_source = required_str(&igra, "source_code");
    assert_fragments(
        igra_source,
        &[
            "uint256 internal constant SOMPI_SCALE = 1e10;",
            "uint64 feeAmountSompi = _quoteFee(l.feePolicyAddress, msg.sender, unlockAmountSompi);",
            "uint256 expectedMsgValueWei = (uint256(unlockAmountSompi) + uint256(feeAmountSompi)) * SOMPI_SCALE;",
            "if (msg.value != expectedMsgValueWei)",
            "uint256 burnAmountWei = uint256(unlockAmountSompi) * SOMPI_SCALE;",
            "new KasExitBridgeBurnProxy{value: burnAmountWei}();",
            "messageId = MAILBOX.dispatch(KASPA_DOMAIN, _effectiveKaspaBridgeEndpoint(l), body);",
        ],
        "Igra requestExit",
    );

    let lombard = read_json(&evidence.join("blockscout/LombardLBTC.implementation.sepolia.json"));
    assert_eq!(lombard["name"], "StakedLBTC");
    assert_eq!(lombard["compiler_version"], "v0.8.24+commit.e11b9ed9");
    assert_fragments(
        required_str(&lombard, "source_code"),
        &[
            "function mint( bytes calldata rawPayload, bytes calldata proof ) external nonReentrant returns (address recipient)",
            "return $.assetRouter.mint(rawPayload, proof);",
            "function redeemForBtc( bytes calldata scriptPubkey, uint256 amount ) external",
            "$.assetRouter.redeemForBtc( address(_msgSender()), address(this), scriptPubkey, amount );",
            "function burn(uint256 amount) external",
            "_burn(_msgSender(), amount);",
            "function redeem(uint256 amount) external nonReentrant",
            "$.assetRouter.redeem(_msgSender(), address(this), amount);",
        ],
        "Lombard StakedLBTC",
    );

    let starkgate = read_json(&evidence.join("blockscout/StarkGate.implementation.ethereum.json"));
    assert_eq!(starkgate["name"], "StarknetERC20Bridge");
    let stark_sources = verified_sources(&starkgate);
    let bridge = &stark_sources["src/solidity/StarknetTokenBridge.sol"];
    assert_fragments(
        bridge,
        &[
            "modifier onlyServicingToken(address token)",
            "require(isServicingToken(token), \"TOKEN_NOT_SERVICED\");",
            "function acceptDeposit(address token, uint256 amount) internal virtual returns (uint256)",
            "Fees.checkFee(msg.value);",
            "Transfers.transferIn(token, msg.sender, amount);",
            "function deposit( address token, uint256 amount, uint256 l2Recipient ) external payable onlyServicingToken(token)",
            "uint256 fee = acceptDeposit(token, amount);",
            "uint256 nonce = sendDepositMessage(",
            "messagingContract().sendMessageToL2{value: fee}(",
        ],
        "StarkGate deposit",
    );
    assert_fragments(
        &stark_sources["starkware/solidity/libraries/Transfers.sol"],
        &[
            "IERC20 erc20Token = IERC20(token);",
            "uint256 balanceBefore = erc20Token.balanceOf(address(this));",
            "erc20Token.transferFrom.selector",
            "require(balanceAfter == expectedAfter, \"INCORRECT_AMOUNT_TRANSFERRED\");",
        ],
        "StarkGate exact transfer",
    );

    let ntt = read_json(&evidence.join("blockscout/SwissborgNtt.implementation.ethereum.json"));
    assert_eq!(ntt["name"], "NttManager");
    let ntt_sources = verified_sources(&ntt);
    let manager = &ntt_sources["src/NttManager/NttManager.sol"];
    assert_fragments(
        manager,
        &[
            "_transferEntryPoint(amount, recipientChain, recipient, recipient, false, new bytes(1));",
            "amount, recipientChain, recipient, refundAddress, shouldQueue, transceiverInstructions",
            "IERC20(token).safeTransferFrom(msg.sender, address(this), amount);",
            "if (!shouldQueue && isAmountRateLimited)",
            "if (shouldQueue && isAmountRateLimited)",
            "_refundToSender(msg.value);",
        ],
        "SwissBorg transfer entry points",
    );
    assert_fragments(
        &ntt_sources["src/NttManager/ManagerBase.sol"],
        &[
            "if (msg.value < totalPriceQuote)",
            "uint256 excessValue = msg.value - totalPriceQuote;",
            "_refundToSender(excessValue);",
            "ITransceiver(transceiverAddr).sendMessage{value: priceQuotes[i]}(",
        ],
        "SwissBorg relaying-value rule",
    );
    let borg = read_json(&evidence.join("blockscout/SwissborgBorgToken.ethereum.json"));
    let borg_source = required_str(&borg, "source_code");
    assert!(borg_source.contains("contract SwissBorgToken is"));
    assert!(borg_source.contains("ERC20,"));
    assert!(
        !borg_source.contains("function transfer(") && !borg_source.contains("function _transfer("),
        "BORG adds no custom transfer-fee behavior"
    );

    assert_eq!(
        abi_signatures(&evidence.join("abi/IgraKasExitBridge.routes.json")),
        [IGRA_ROUTE.to_owned()].into_iter().collect()
    );
    assert_eq!(
        abi_signatures(&evidence.join("abi/LombardLBTC.routes.sepolia.json")),
        LOMBARD_ACCEPTED
            .into_iter()
            .chain(LOMBARD_REFUSED)
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(
        abi_signatures(&evidence.join("abi/StarkGate.routes.ethereum.json")),
        [STARKGATE_ROUTE.to_owned()].into_iter().collect()
    );
    assert_eq!(
        abi_signatures(&evidence.join("abi/SwissborgNtt.routes.ethereum.json")),
        [NTT_SIMPLE.to_owned(), NTT_EXTENDED.to_owned()]
            .into_iter()
            .collect()
    );
}

#[test]
fn curated_descriptors_are_hash_bound_and_semantically_explicit() {
    let root = workspace_root();
    let curation = read_json(&root.join("secure/data/erc7730/curations/manifest.json"));
    let expectations = [
        (
            IGRA_SOURCE,
            1_110,
            "9c6fbece743979770b283aaf0f973132d3e81fbca971e45bf122fa7398f29197",
        ),
        (
            LOMBARD_SOURCE,
            4_612,
            "f79cc8eb93054c1233f5cd044a2d4b2f5ba82a4162d4890dc182a1bbfea22fc7",
        ),
        (
            STARKGATE_SOURCE,
            1_004,
            "5f62cef09fa63eafeb5ed357707958dec92c60f7673e056a532f0597207b961b",
        ),
        (
            NTT_SOURCE,
            2_846,
            "67624662a436152aee08819a3cdfe8362e6c51f5d7f70a5fc206ca890322f96e",
        ),
    ];

    for (relative, upstream_bytes, upstream_sha256) in expectations {
        let vendored = root.join("secure/data/erc7730-registry").join(relative);
        let overlay = root
            .join("secure/data/erc7730/curations/files")
            .join(relative);
        let bytes = fs::read(&vendored).expect("curated descriptor");
        assert_eq!(bytes, fs::read(&overlay).expect("curation overlay"));
        let replacement = curation["replacements"]
            .as_array()
            .expect("curation replacements")
            .iter()
            .find(|entry| entry["path"].as_str() == Some(relative))
            .unwrap_or_else(|| panic!("missing replacement {relative}"));
        assert_eq!(replacement["upstream_bytes"].as_u64(), Some(upstream_bytes));
        assert_eq!(
            replacement["upstream_sha256"].as_str(),
            Some(upstream_sha256)
        );
        assert_eq!(
            replacement["replacement_bytes"].as_u64(),
            Some(bytes.len() as u64)
        );
        assert_eq!(
            replacement["replacement_sha256"].as_str(),
            Some(sha256_hex(&bytes).as_str())
        );
    }

    let igra = read_json(&root.join("secure/data/erc7730-registry").join(IGRA_SOURCE));
    assert_eq!(
        igra["_pqsigner"]["deploymentFormats"][0]["formats"],
        json!(["requestExit(string kasPayoutAddress, uint64 unlockAmountSompi)"])
    );
    let igra_format = &igra["display"]["formats"]
        ["requestExit(string kasPayoutAddress, uint64 unlockAmountSompi)"];
    assert_eq!(igra_format["intent"], "Request Kaspa exit");
    assert_eq!(igra_format["fields"][2]["label"], "Total iKAS sent");
    assert_eq!(igra_format["fields"][3]["label"], "Value rule");

    let lombard = read_json(
        &root
            .join("secure/data/erc7730-registry")
            .join(LOMBARD_SOURCE),
    );
    assert_eq!(
        lombard["_pqsigner"]["deploymentFormats"][0]["formats"]
            .as_array()
            .expect("Lombard allowlist")
            .len(),
        6
    );
    assert_eq!(
        lombard["_pqsigner"]["refusalOnlyFormats"],
        json!([
            "mint(bytes rawPayload, bytes proof)",
            "redeemForBtc(bytes scriptPubkey, uint256 amount)"
        ])
    );
    assert_eq!(
        lombard["display"]["formats"]["redeem(uint256 amount)"]["intent"],
        "Request redemption"
    );
    assert_eq!(
        lombard["display"]["formats"]["redeem(uint256 amount)"]["fields"][0]["label"],
        "LBTC to Burn"
    );

    let starkgate = read_json(
        &root
            .join("secure/data/erc7730-registry")
            .join(STARKGATE_SOURCE),
    );
    assert_eq!(starkgate["context"]["$id"], "StarkGate ERC-20 Bridge");
    let starkgate_fields = &starkgate["display"]["formats"]
        ["deposit(address token, uint256 amount, uint256 l2Recipient)"]["fields"];
    assert_eq!(starkgate_fields[0]["label"], "L1 token contract");
    assert_eq!(starkgate_fields[2]["label"], "Starknet recipient felt");
    assert_eq!(starkgate_fields[3]["label"], "L1 message fee");
    assert!(starkgate_fields
        .as_array()
        .unwrap()
        .iter()
        .all(|field| field["visible"] == "always"));

    let ntt = read_json(&root.join("secure/data/erc7730-registry").join(NTT_SOURCE));
    assert_eq!(
        ntt["_pqsigner"]["deploymentFormats"][0]["formats"]
            .as_array()
            .expect("NTT allowlist")
            .len(),
        1
    );
    assert_eq!(
        ntt["_pqsigner"]["refusalOnlyFormats"],
        json!([
            "transfer(uint256 amount, uint16 recipientChain, bytes32 recipient, bytes32 refundAddress, bool shouldQueue, bytes transceiverInstructions)"
        ])
    );
    for format in ntt["display"]["formats"]
        .as_object()
        .expect("NTT formats")
        .values()
    {
        assert_eq!(format["intent"], "Request BORG bridge");
        assert!(format["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| field["visible"] == "always"));
        assert!(format["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["label"] == "Max relaying value"));
    }
}

#[test]
fn compiled_ir_admits_exact_routes_and_unsafe_calls_stay_exact_known_refusals() {
    let root = workspace_root();
    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20_capabilities = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("production ERC20 capability corpus");
    let (registry, skips) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20_capabilities.capabilities,
    )
    .expect("build curated registry");

    let cases = [
        (
            IGRA_SOURCE,
            38_833,
            IGRA_PROXY,
            vec![IGRA_ROUTE],
            vec![("Request Kaspa exit", 4usize)],
        ),
        (
            LOMBARD_SOURCE,
            11_155_111,
            LOMBARD_PROXY,
            LOMBARD_ACCEPTED.to_vec(),
            vec![
                ("Approve", 2),
                ("Burn", 1),
                ("Submit permit", 7),
                ("Request redemption", 1),
                ("Send", 2),
                ("Transfer", 3),
            ],
        ),
        (
            STARKGATE_SOURCE,
            1,
            STARKGATE_PROXY,
            vec![STARKGATE_ROUTE],
            vec![("Request Starknet deposit", 4)],
        ),
        (
            NTT_SOURCE,
            1,
            NTT_PROXY,
            vec![NTT_SIMPLE],
            vec![("Request BORG bridge", 5)],
        ),
    ];

    for (relative, chain_id, contract_text, routes, formats) in cases {
        let source_path = registry_root.join(relative);
        let entries = registry
            .entries
            .iter()
            .filter(|entry| entry.source == source_path)
            .collect::<Vec<_>>();
        assert_eq!(
            entries.len(),
            1,
            "one evidenced leaf for {relative}; skips: {:?}",
            skips
                .iter()
                .filter(|skip| skip.source == source_path)
                .map(|skip| skip.reason.as_str())
                .collect::<Vec<_>>()
        );
        let entry = entries[0];
        let contract = address(contract_text);
        assert_eq!(entry.chain_id, chain_id);
        assert_eq!(entry.contract, contract);
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("compiled IR parses");
        assert_eq!(cross_check_contract(&ir, chain_id, &contract), Ok(()));
        assert_eq!(ir.format_count(), Ok(routes.len() as u8));

        for ((route, (intent, field_count)), index) in
            routes.iter().zip(formats.iter()).zip(0usize..)
        {
            let selector = selector(route);
            let format = ir
                .find_format_by_selector(&selector)
                .expect("format table parses")
                .unwrap_or_else(|| panic!("missing admitted route {route}"));
            assert_eq!(format.intent, intent.as_bytes(), "format {index} intent");
            let fields = format
                .fields()
                .map(|field| field.expect("compiled field parses"))
                .collect::<Vec<_>>();
            assert_eq!(fields.len(), *field_count, "route {route} field count");
            assert!(fields.iter().all(|field| {
                parse_params(&ir, field.param_off)
                    .expect("field params")
                    .visibility
                    == Visibility::Always
            }));
            assert!(
                registry
                    .known_calls
                    .contains(&(chain_id, contract, selector)),
                "admitted route remains exact known"
            );
        }

        let mut wrong_contract = contract;
        wrong_contract[19] ^= 1;
        assert_eq!(
            cross_check_contract(&ir, chain_id, &wrong_contract),
            Err(BindingError::ContractMismatch)
        );
    }

    let lombard_entry = registry
        .entries
        .iter()
        .find(|entry| entry.source == registry_root.join(LOMBARD_SOURCE))
        .expect("Lombard leaf");
    let lombard_ir = Erc7730Ir::parse(&lombard_entry.ir_bytes).expect("Lombard IR");
    for signature in LOMBARD_REFUSED {
        let selector = selector(signature);
        assert!(
            lombard_ir
                .find_format_by_selector(&selector)
                .expect("format table")
                .is_none(),
            "refused dynamic route emitted a format"
        );
        assert!(
            registry
                .known_calls
                .contains(&(11_155_111, address(LOMBARD_PROXY), selector)),
            "refused dynamic route lost exact-known refusal"
        );
        assert!(known_call_may_contain(
            &registry.known_calls_bloom,
            11_155_111,
            &address(LOMBARD_PROXY),
            &selector
        ));
    }

    let ntt_entry = registry
        .entries
        .iter()
        .find(|entry| entry.source == registry_root.join(NTT_SOURCE))
        .expect("SwissBorg NTT leaf");
    let ntt_ir = Erc7730Ir::parse(&ntt_entry.ir_bytes).expect("SwissBorg NTT IR");
    let extended_selector = selector(NTT_EXTENDED);
    assert!(
        ntt_ir
            .find_format_by_selector(&extended_selector)
            .expect("format table")
            .is_none(),
        "opaque-instructions overload emitted a trusted format"
    );
    assert!(
        registry
            .known_calls
            .contains(&(1, address(NTT_PROXY), extended_selector)),
        "opaque-instructions overload lost exact-known refusal"
    );
    assert!(known_call_may_contain(
        &registry.known_calls_bloom,
        1,
        &address(NTT_PROXY),
        &extended_selector
    ));

    let starkgate_entry = registry
        .entries
        .iter()
        .find(|entry| entry.source == registry_root.join(STARKGATE_SOURCE))
        .expect("StarkGate leaf");
    let starkgate_ir = Erc7730Ir::parse(&starkgate_entry.ir_bytes).expect("StarkGate IR");
    let deposit = starkgate_ir
        .find_format_by_selector(&selector(STARKGATE_ROUTE))
        .expect("format table")
        .expect("deposit format");
    let deposit_ops = deposit
        .fields()
        .map(|field| FormatOp::try_from(field.unwrap().format_op).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        deposit_ops,
        [
            FormatOp::AddressName,
            FormatOp::TokenAmount,
            FormatOp::Raw,
            FormatOp::Amount
        ]
    );
}

#[test]
fn inventory_promotes_only_the_four_evidenced_sources() {
    let inventory = read_json(
        &workspace_root().join("tests/erc7730-semantic-evidence/accepted-family-inventory.json"),
    );
    let families = inventory["families"]
        .as_array()
        .expect("accepted-family records");
    let mut source_counts = BTreeMap::<&str, u64>::new();
    let mut leaf_counts = BTreeMap::<&str, u64>::new();
    for family in families {
        let classification = family["classification"]
            .as_str()
            .expect("family classification");
        *source_counts.entry(classification).or_default() += 1;
        *leaf_counts.entry(classification).or_default() += family["accepted_leaf_count"]
            .as_u64()
            .expect("accepted leaf count");
    }
    assert_eq!(
        inventory["catalogue_snapshot"]["category_source_counts"],
        serde_json::to_value(source_counts).expect("source counts")
    );
    assert_eq!(
        inventory["catalogue_snapshot"]["category_leaf_counts"],
        serde_json::to_value(leaf_counts).expect("leaf counts")
    );
    assert_eq!(
        inventory["evidence_sets"]["bridge-exits"]["paths"],
        json!(["tests/erc7730-semantic-evidence/bridge-exits/manifest.json"])
    );
    for source in [
        "igra/calldata-KasExitBridge.json",
        "lombard/calldata-lbtc-sepolia.json",
        "starkgate/calldata-StarkGate-STRK.json",
        "swissborg/calldata-NttManager.json",
    ] {
        let family = families
            .iter()
            .find(|family| family["source"].as_str() == Some(source))
            .unwrap_or_else(|| panic!("missing family {source}"));
        assert_eq!(family["classification"], "pinned-evidence");
        assert_eq!(family["evidence"], "bridge-exits");
        assert!(family.get("successor_issue").is_none());
        assert_eq!(family["accepted_leaf_count"].as_u64(), Some(1));
    }
}
