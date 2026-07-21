//! Offline evidence checks for the bounded Midas mTBILL DepositVault route.
//!
//! Catalogue and rendering behavior are exercised elsewhere. This test keeps
//! the external authority package honest: every archived byte is receipted,
//! three fixed-block providers agree, the verified compiler closure rebuilds
//! the deployed runtime, and the exact source/ABI establish the meaning of all
//! four signed operands in the admitted overload.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BLOCK_NUMBER: u64 = 25_579_745;
const BLOCK_HASH: &str = "0x747c9dfcb1988c490d72011332edaebdea48acba3a29df44a82be5ecdeceb7fb";
const STATE_ROOT: &str = "0xf57084a6e4c99a3efd5b27392676b554b73b08333fda9a3f1a6012063077a7de";
const EIP1967_SLOT: &str = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const VAULT_PROXY: &str = "99361435420711723af805f08187c9e6bf796683";
const VAULT_IMPLEMENTATION: &str = "c8af8477f3caa89f60fe9d1f48eee5433c55982b";
const MTBILL_PROXY: &str = "dd629e5241cbc5919847783e6c96b2de4754e438";
const MTBILL_IMPLEMENTATION: &str = "d4998cc1ba435298c521f250b81856b1f25c8455";
const OFFICIAL_COMMIT: &str = "237c56a85e51560a977d9473ce3f939d877f2a4f";
const OFFICIAL_TREE: &str = "1cff2a6fe8ad0f97e312a28624e9b32166f0d942";
const ROUTE: &str = "depositInstant(address,uint256,uint256,bytes32)";
const SELECTOR: [u8; 4] = [0xc0, 0x2d, 0xd2, 0x7a];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/midas-mtbill-deposit-vault")
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
        &fs::read_to_string(evidence.join(format!("runtime/{name}.ethereum-mainnet.hex")))
            .unwrap_or_else(|error| panic!("read runtime {name}: {error}")),
    )
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments_in_order(source: &str, fragments: &[&str], context: &str) {
    let normalized = normalized(source);
    let mut cursor = 0usize;
    for fragment in fragments {
        let offset = normalized[cursor..]
            .find(fragment)
            .unwrap_or_else(|| panic!("{context} lost semantic fragment: {fragment}"));
        cursor += offset + fragment.len();
    }
}

#[derive(Clone, Copy)]
struct SolidityFunction<'a> {
    header: &'a str,
    body: &'a str,
}

fn solidity_functions<'a>(source: &'a str, name: &str) -> Vec<SolidityFunction<'a>> {
    let needle = format!("function {name}(");
    let mut functions = Vec::new();
    for (start, _) in source.match_indices(&needle) {
        let definition = &source[start..];
        let Some(opening) = definition.find('{') else {
            continue;
        };
        if definition[..opening].contains(';') {
            continue;
        }
        let mut depth = 0usize;
        for (offset, byte) in definition[opening..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.checked_sub(1).expect("balanced Solidity braces");
                    if depth == 0 {
                        functions.push(SolidityFunction {
                            header: &definition[..opening],
                            body: &definition[opening..opening + offset + 1],
                        });
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    functions
}

fn solidity_function<'a>(source: &'a str, name: &str) -> SolidityFunction<'a> {
    let functions = solidity_functions(source, name);
    assert_eq!(functions.len(), 1, "expected one implemented {name}");
    functions[0]
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

fn result_map(path: &Path) -> BTreeMap<String, Value> {
    let document = read_json(path);
    let mut results = BTreeMap::new();
    for item in document.as_array().expect("RPC response batch") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(
            item.get("error").is_none() || item["error"].is_null(),
            "RPC error in {}",
            path.display()
        );
        let id = item["id"].as_str().expect("string RPC id").to_owned();
        let result = item
            .get("result")
            .unwrap_or_else(|| panic!("missing result {id} in {}", path.display()))
            .clone();
        assert!(
            results.insert(id.clone(), result).is_none(),
            "duplicate id {id}"
        );
    }
    results
}

fn address_word(value: &Value) -> String {
    let word = decode_hex(value.as_str().expect("ABI address word"));
    assert_eq!(word.len(), 32, "address return is one word");
    assert_eq!(&word[..12], &[0u8; 12], "address return is canonical");
    hex::encode(&word[12..])
}

fn abi_string(value: &Value) -> String {
    let encoded = decode_hex(value.as_str().expect("ABI string result"));
    assert!(encoded.len() >= 64 && encoded.len() % 32 == 0);
    assert_eq!(&encoded[..31], &[0u8; 31]);
    assert_eq!(encoded[31], 32, "ABI string data starts at word one");
    assert_eq!(&encoded[32..63], &[0u8; 31]);
    let length = usize::from(encoded[63]);
    assert!(64 + length <= encoded.len(), "ABI string length is bounded");
    String::from_utf8(encoded[64..64 + length].to_vec()).expect("UTF-8 token metadata")
}

fn hex_quantity(value: &Value) -> u64 {
    let text = value.as_str().expect("hex quantity string");
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).expect("hex quantity")
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

fn source_map(record: &Value) -> BTreeMap<String, String> {
    let mut sources = BTreeMap::new();
    let primary_path = record["file_path"].as_str().expect("primary source path");
    let primary = record["source_code"].as_str().expect("primary source");
    assert!(sources
        .insert(primary_path.to_owned(), primary.to_owned())
        .is_none());
    for source in record["additional_sources"]
        .as_array()
        .expect("additional verified sources")
    {
        let path = source["file_path"].as_str().expect("source path");
        let content = source["source_code"].as_str().expect("source content");
        assert!(
            !path.starts_with('/') && !path.split('/').any(|part| part == ".."),
            "verified source path must remain relative"
        );
        assert!(
            sources
                .insert(path.to_owned(), content.to_owned())
                .is_none(),
            "duplicate verified source {path}"
        );
    }
    sources
}

fn assert_blockscout_runtime(record: &Value, runtime: &[u8]) {
    assert_eq!(record["is_verified"].as_bool(), Some(true));
    assert_eq!(record["is_changed_bytecode"].as_bool(), Some(false));
    assert_eq!(
        decode_hex(
            record["deployed_bytecode"]
                .as_str()
                .expect("Blockscout deployed bytecode")
        ),
        runtime
    );
}

#[test]
fn midas_evidence_receipts_cover_every_offline_artifact() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(manifest["fixed_block"]["chain_id"].as_u64(), Some(1));
    assert_eq!(
        manifest["fixed_block"]["number"].as_u64(),
        Some(BLOCK_NUMBER)
    );
    assert_eq!(manifest["fixed_block"]["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(
        manifest["route"]["canonical_signature"].as_str(),
        Some(ROUTE)
    );
    assert_eq!(manifest["route"]["selector"].as_str(), Some("0xc02dd27a"));

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
}

#[test]
fn three_providers_bind_the_same_vault_mtoken_and_metadata_at_one_block() {
    let evidence = evidence_root();
    let rpc = evidence.join("rpc/raw");
    let identity_request = read_json(&rpc.join("request-identity.json"));
    assert_eq!(
        request(&identity_request, "chain-id")["method"],
        "eth_chainId"
    );
    assert_eq!(
        request(&identity_request, "block")["params"],
        json!([BLOCK_HASH, false])
    );

    let requests = [
        read_json(&rpc.join("request-vault.json")),
        read_json(&rpc.join("request-vault-implementation.json")),
        read_json(&rpc.join("request-mtbill-state.json")),
        read_json(&rpc.join("request-mtbill-metadata.json")),
    ];
    for document in &requests {
        for item in document.as_array().expect("RPC request array") {
            match item["method"].as_str().expect("RPC method") {
                "eth_getCode" => assert_eip1898(&item["params"][1]),
                "eth_getStorageAt" => {
                    assert_eq!(item["params"][1].as_str(), Some(EIP1967_SLOT));
                    assert_eip1898(&item["params"][2]);
                }
                "eth_call" => assert_eip1898(&item["params"][1]),
                method => panic!("unexpected historical method {method}"),
            }
        }
    }

    let vault_request = &requests[0];
    assert_eq!(
        request(vault_request, "vault-implementation-slot")["params"][0]
            .as_str()
            .map(str::to_ascii_lowercase),
        Some(format!("0x{VAULT_PROXY}"))
    );
    assert_eq!(
        request(vault_request, "vault-mtoken")["params"][0]["data"],
        "0xc3b6f939"
    );
    assert_eq!(
        request(&requests[1], "vault-implementation-code")["params"][0]
            .as_str()
            .map(str::to_ascii_lowercase),
        Some(format!("0x{VAULT_IMPLEMENTATION}"))
    );
    assert_eq!(
        request(&requests[2], "mtbill-implementation-code")["params"][0]
            .as_str()
            .map(str::to_ascii_lowercase),
        Some(format!("0x{MTBILL_IMPLEMENTATION}"))
    );
    for (id, selector) in [
        ("mtbill-name", "0x06fdde03"),
        ("mtbill-symbol", "0x95d89b41"),
        ("mtbill-decimals", "0x313ce567"),
    ] {
        let call = request(&requests[3], id);
        assert_eq!(
            call["params"][0]["to"]
                .as_str()
                .map(str::to_ascii_lowercase),
            Some(format!("0x{MTBILL_PROXY}"))
        );
        assert_eq!(call["params"][0]["data"].as_str(), Some(selector));
    }

    let batches = [
        "identity",
        "vault",
        "vault-implementation",
        "mtbill-state",
        "mtbill-metadata",
    ];
    let providers = ["drpc", "tenderly", "mevblocker"];
    let mut provider_results = Vec::new();
    for provider in providers {
        let mut combined = BTreeMap::new();
        for batch in batches {
            for (id, result) in result_map(&rpc.join(format!("response-{provider}-{batch}.json"))) {
                assert!(
                    combined.insert(id.clone(), result).is_none(),
                    "duplicate RPC id {id} across {provider} batches"
                );
            }
        }
        provider_results.push((provider, combined));
    }

    let state_ids = [
        "chain-id",
        "vault-implementation-slot",
        "vault-proxy-code",
        "vault-mtoken",
        "vault-implementation-code",
        "mtbill-implementation-slot",
        "mtbill-proxy-code",
        "mtbill-implementation-code",
        "mtbill-name",
        "mtbill-symbol",
        "mtbill-decimals",
    ];
    for id in state_ids {
        let expected = provider_results[0]
            .1
            .get(id)
            .unwrap_or_else(|| panic!("dRPC result {id}"));
        for (provider, results) in &provider_results[1..] {
            assert_eq!(
                results.get(id),
                Some(expected),
                "fixed-block result {id} disagrees at {provider}"
            );
        }
    }

    for (provider, results) in &provider_results {
        assert_eq!(hex_quantity(&results["chain-id"]), 1);
        let block = &results["block"];
        assert_eq!(block["hash"].as_str(), Some(BLOCK_HASH));
        assert_eq!(hex_quantity(&block["number"]), BLOCK_NUMBER);
        assert_eq!(block["stateRoot"].as_str(), Some(STATE_ROOT));
        assert_eq!(hex_quantity(&block["timestamp"]), 1_784_620_631);
        assert!(
            block["transactions"].as_array().is_some(),
            "{provider} must answer the exact block request"
        );
    }

    let results = &provider_results[0].1;
    assert_eq!(
        address_word(&results["vault-implementation-slot"]),
        VAULT_IMPLEMENTATION
    );
    assert_eq!(address_word(&results["vault-mtoken"]), MTBILL_PROXY);
    assert_eq!(
        address_word(&results["mtbill-implementation-slot"]),
        MTBILL_IMPLEMENTATION
    );
    assert_eq!(
        abi_string(&results["mtbill-name"]),
        "Midas US Treasury Bill Token"
    );
    assert_eq!(abi_string(&results["mtbill-symbol"]), "mTBILL");
    assert_eq!(hex_quantity(&results["mtbill-decimals"]), 18);

    for (id, runtime_name) in [
        ("vault-proxy-code", "DepositVaultProxy"),
        ("vault-implementation-code", "DepositVault.implementation"),
        ("mtbill-proxy-code", "MTBillProxy"),
        ("mtbill-implementation-code", "MTBill.implementation"),
    ] {
        assert_eq!(
            decode_hex(results[id].as_str().expect("RPC runtime")),
            read_runtime(&evidence, runtime_name),
            "runtime artifact {runtime_name} drifted from raw RPC"
        );
    }
}

#[test]
fn verified_source_closure_rebuilds_the_exact_deployed_runtime() {
    let evidence = evidence_root();
    let vault_proxy = read_json(&evidence.join("blockscout/DepositVaultProxy.json"));
    let vault_implementation =
        read_json(&evidence.join("blockscout/DepositVault.implementation.json"));
    let mtbill_proxy = read_json(&evidence.join("blockscout/MTBillProxy.json"));
    let mtbill_implementation = read_json(&evidence.join("blockscout/MTBill.implementation.json"));

    let vault_proxy_runtime = read_runtime(&evidence, "DepositVaultProxy");
    let vault_implementation_runtime = read_runtime(&evidence, "DepositVault.implementation");
    let mtbill_proxy_runtime = read_runtime(&evidence, "MTBillProxy");
    let mtbill_implementation_runtime = read_runtime(&evidence, "MTBill.implementation");
    assert_blockscout_runtime(&vault_proxy, &vault_proxy_runtime);
    assert_blockscout_runtime(&vault_implementation, &vault_implementation_runtime);
    assert_blockscout_runtime(&mtbill_proxy, &mtbill_proxy_runtime);
    assert_blockscout_runtime(&mtbill_implementation, &mtbill_implementation_runtime);

    assert_eq!(vault_proxy["proxy_type"].as_str(), Some("eip1967"));
    assert_eq!(
        vault_proxy["implementations"][0]["address_hash"]
            .as_str()
            .map(str::to_ascii_lowercase),
        Some(format!("0x{VAULT_IMPLEMENTATION}"))
    );
    assert_eq!(mtbill_proxy["proxy_type"].as_str(), Some("eip1967"));
    assert_eq!(
        mtbill_proxy["implementations"][0]["address_hash"]
            .as_str()
            .map(str::to_ascii_lowercase),
        Some(format!("0x{MTBILL_IMPLEMENTATION}"))
    );
    assert_eq!(vault_implementation["name"].as_str(), Some("DepositVault"));
    assert_eq!(
        vault_implementation["compiler_version"].as_str(),
        Some("v0.8.9+commit.e5eed63a")
    );
    assert_eq!(
        vault_implementation["optimization_enabled"].as_bool(),
        Some(true)
    );
    assert_eq!(
        vault_implementation["optimization_runs"].as_u64(),
        Some(200)
    );
    assert_eq!(
        vault_implementation["compiler_settings"]["libraries"],
        json!({})
    );
    assert_eq!(
        vault_implementation["compiler_settings"]["metadata"]["useLiteralContent"].as_bool(),
        Some(true)
    );

    assert_eq!(vault_proxy_runtime.len(), 2_227);
    assert_eq!(vault_implementation_runtime.len(), 17_677);
    assert_eq!(mtbill_proxy_runtime.len(), 2_227);
    assert_eq!(mtbill_implementation_runtime.len(), 6_271);
    assert!(
        vault_implementation_runtime
            .windows(SELECTOR.len())
            .any(|window| window == SELECTOR),
        "deployed runtime lost the admitted selector"
    );

    let verified_sources = source_map(&vault_implementation);
    assert_eq!(verified_sources.len(), 36, "verified closure size drifted");
    let verified_root = evidence.join("source/verified");
    let mut extracted = BTreeSet::new();
    collect_files(&verified_root, &verified_root, &mut extracted);
    assert_eq!(
        extracted,
        verified_sources.keys().cloned().collect(),
        "materialized verified-source closure is incomplete"
    );
    for (path, expected) in &verified_sources {
        assert_eq!(
            fs::read(verified_root.join(path)).expect("materialized verified source"),
            expected.as_bytes(),
            "verified source drifted: {path}"
        );
    }

    let settings = read_json(&evidence.join("compiler/DepositVault.settings.json"));
    assert_eq!(settings, vault_implementation["compiler_settings"]);
    let input = read_json(&evidence.join("compiler/DepositVault.standard-input.json"));
    assert_eq!(input["language"].as_str(), Some("Solidity"));
    let input_sources = input["sources"].as_object().expect("compiler source map");
    assert_eq!(input_sources.len(), verified_sources.len());
    for (path, source) in &verified_sources {
        assert_eq!(
            input_sources[path]["content"].as_str(),
            Some(source.as_str())
        );
    }
    let mut expected_settings = settings.clone();
    expected_settings["outputSelection"] = json!({
        "contracts/DepositVault.sol": {
            "DepositVault": ["evm.deployedBytecode.object", "metadata"]
        }
    });
    assert_eq!(input["settings"], expected_settings);

    assert_eq!(
        fs::read_to_string(evidence.join("compiler/solc-0.8.9.version.txt")).expect("solc version"),
        "0.8.9+commit.e5eed63a.Emscripten.clang\n"
    );
    let output = read_json(&evidence.join("compiler/DepositVault.standard-output.json"));
    for diagnostic in output["errors"].as_array().into_iter().flatten() {
        assert_ne!(diagnostic["severity"].as_str(), Some("error"));
    }
    let compiled = decode_hex(
        output["contracts"]["contracts/DepositVault.sol"]["DepositVault"]["evm"]
            ["deployedBytecode"]["object"]
            .as_str()
            .expect("compiled DepositVault runtime"),
    );
    assert_eq!(compiled, vault_implementation_runtime);

    let commit = read_json(&evidence.join("official/github-git-commit.json"));
    assert_eq!(commit["sha"].as_str(), Some(OFFICIAL_COMMIT));
    assert_eq!(commit["tree"]["sha"].as_str(), Some(OFFICIAL_TREE));
    let addresses = fs::read_to_string(evidence.join("official/config/constants/addresses.ts"))
        .expect("official Midas address map");
    assert!(addresses.contains("token: '0xDD629E5241CbC5919847783e6C96B2De4754e438'"));
    assert!(addresses.contains("depositVault: '0x99361435420711723aF805F08187c9E6bF796683'"));
    let config = fs::read_to_string(evidence.join("official/scripts/deploy/configs/mTBILL.ts"))
        .expect("official mTBILL deployment config");
    assert!(config.contains("[chainIds.main]:"));
    assert!(config.contains("instantDailyLimit: parseUnits('1000')"));
    assert!(config.contains("instantFee: parseUnits('0.1', 2)"));
    assert!(config.contains("enableSanctionsList: true"));

    for path in [
        "contracts/DepositVault.sol",
        "contracts/abstract/ManageableVault.sol",
        "contracts/interfaces/IDepositVault.sol",
        "contracts/interfaces/IMToken.sol",
        "contracts/libraries/DecimalsCorrectionLibrary.sol",
    ] {
        assert_eq!(
            fs::read(evidence.join("official").join(path)).expect("official pinned source"),
            verified_sources[path].as_bytes(),
            "official commit and deployed verified source disagree: {path}"
        );
    }
}

#[test]
fn exact_abi_and_deployed_source_bind_all_four_signed_operands() {
    let evidence = evidence_root();
    let abi = read_json(&evidence.join("abi/DepositVault.deposit-instant.abi.json"));
    let functions = abi.as_array().expect("ABI projection array");
    assert_eq!(
        functions.len(),
        1,
        "ABI projection must authorize one overload"
    );
    let function = &functions[0];
    assert_eq!(function["type"].as_str(), Some("function"));
    assert_eq!(function["name"].as_str(), Some("depositInstant"));
    assert_eq!(function["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(function["outputs"], json!([]));
    let inputs = function["inputs"].as_array().expect("ABI inputs");
    assert_eq!(inputs.len(), 4);
    for (input, (name, ty)) in inputs.iter().zip([
        ("tokenIn", "address"),
        ("amountToken", "uint256"),
        ("minReceiveAmount", "uint256"),
        ("referrerId", "bytes32"),
    ]) {
        assert_eq!(input["name"].as_str(), Some(name));
        assert_eq!(input["type"].as_str(), Some(ty));
    }
    assert_eq!(&keccak256(ROUTE.as_bytes())[..4], &SELECTOR);

    let deposit = fs::read_to_string(evidence.join("source/verified/contracts/DepositVault.sol"))
        .expect("verified DepositVault source");
    let overloads = solidity_functions(&deposit, "depositInstant");
    assert_eq!(overloads.len(), 2, "deployed source overload set drifted");
    let standard = overloads
        .iter()
        .find(|function| {
            let header = normalized(function.header);
            header.contains("bytes32 referrerId") && !header.contains("address recipient")
        })
        .expect("standard four-argument depositInstant");
    assert!(normalized(standard.header).contains("whenFnNotPaused(_DEPOSIT_INSTANT_SELECTOR)"));
    assert_fragments_in_order(
        standard.body,
        &[
            "_validateUserAccess(msg.sender);",
            "_depositInstant( tokenIn, amountToken, minReceiveAmount, msg.sender )",
            "emit DepositInstant( msg.sender, tokenIn, result.tokenAmountInUsd, amountToken, result.feeTokenAmount, result.mintAmount, referrerId )",
        ],
        "four-argument depositInstant",
    );

    assert!(
        deposit.contains("bytes4(keccak256(\"depositInstant(address,uint256,uint256,bytes32)\"))")
    );
    let instant = solidity_function(&deposit, "_depositInstant");
    assert!(normalized(instant.header).contains("uint256 amountToken"));
    assert!(normalized(instant.header).contains("uint256 minReceiveAmount"));
    assert!(normalized(instant.header).contains("address recipient"));
    assert_fragments_in_order(
        instant.body,
        &[
            "result = _calcAndValidateDeposit(user, tokenIn, amountToken, true);",
            "result.mintAmount >= minReceiveAmount",
            "_instantTransferTokensToTokensReceiver( tokenIn, result.amountTokenWithoutFee, result.tokenDecimals )",
            "mToken.mint(recipient, result.mintAmount);",
        ],
        "instant deposit implementation",
    );

    let calculation = solidity_function(&deposit, "_calcAndValidateDeposit");
    assert_fragments_in_order(
        calculation.body,
        &[
            "require(amountToken > 0, \"DV: invalid amount\");",
            "result.tokenDecimals = _tokenDecimals(tokenIn);",
            "_requireTokenExists(tokenIn);",
            "_convertTokenToUsd( tokenIn, amountToken )",
            "_requireAndUpdateAllowance(tokenIn, amountToken);",
            "result.amountTokenWithoutFee = amountToken - result.feeTokenAmount;",
            "result.mintAmount = mTokenAmount;",
        ],
        "deposit calculation",
    );

    let manageable =
        fs::read_to_string(evidence.join("source/verified/contracts/abstract/ManageableVault.sol"))
            .expect("verified ManageableVault source");
    let transfer = solidity_function(&manageable, "_tokenTransferFromUser");
    assert_fragments_in_order(
        transfer.body,
        &[
            "transferAmount = amount.convertFromBase18(tokenDecimals);",
            "amount == transferAmount.convertToBase18(tokenDecimals)",
            "IERC20(token).safeTransferFrom(msg.sender, to, transferAmount);",
        ],
        "base-18 exact payment transfer",
    );

    let decimal_library = fs::read_to_string(
        evidence.join("source/verified/contracts/libraries/DecimalsCorrectionLibrary.sol"),
    )
    .expect("verified decimal-correction source");
    let from_base = solidity_function(&decimal_library, "convertFromBase18");
    assert!(
        normalized(from_base.body).contains("return convert(originalAmount, 18, decidedDecimals);")
    );
}
