//! Offline evidence checks for the bounded Midas mTBILL RedemptionVault routes.
//!
//! Catalogue and rendering behavior are exercised elsewhere. This test keeps
//! the external authority package honest: every archived byte is receipted,
//! three fixed-block providers agree, the verified compiler closure rebuilds
//! the deployed runtime, and the exact source/ABI establish the signed
//! operands, implicit/explicit beneficiary, authenticated payer, exact
//! token-out minimum, pay-now request semantics, and explicit fiat refusal.

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
const VAULT_PROXY: &str = "f6e51d24f4793ac5e71e0502213a9bbe3a6d4517";
const VAULT_IMPLEMENTATION: &str = "2f1372244cedcaf8ee1759d2f02435628f14975f";
const MTBILL_PROXY: &str = "dd629e5241cbc5919847783e6c96b2de4754e438";
const MTBILL_IMPLEMENTATION: &str = "d4998cc1ba435298c521f250b81856b1f25c8455";
const OFFICIAL_COMMIT: &str = "237c56a85e51560a977d9473ce3f939d877f2a4f";
const OFFICIAL_TREE: &str = "1cff2a6fe8ad0f97e312a28624e9b32166f0d942";
const ROUTES: [(&str, [u8; 4]); 4] = [
    (
        "redeemInstant(address,uint256,uint256)",
        [0x8b, 0x53, 0xf7, 0x5e],
    ),
    (
        "redeemInstant(address,uint256,uint256,address)",
        [0x85, 0xab, 0x2c, 0x13],
    ),
    ("redeemRequest(address,uint256)", [0xbf, 0xc2, 0xd4, 0x6a]),
    (
        "redeemRequest(address,uint256,address)",
        [0x15, 0x57, 0x1a, 0x04],
    ),
];
const FIAT_ROUTE: (&str, [u8; 4]) = ("redeemFiatRequest(uint256)", [0xd5, 0xf7, 0x3f, 0x5c]);

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/midas-mtbill-redemption-vault")
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

fn abi_signature(function: &Value) -> String {
    let name = function["name"].as_str().expect("ABI function name");
    let types = function["inputs"]
        .as_array()
        .expect("ABI function inputs")
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({types})")
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
    assert_eq!(manifest["schema_version"].as_u64(), Some(2));
    assert_eq!(manifest["fixed_block"]["chain_id"].as_u64(), Some(1));
    assert_eq!(
        manifest["fixed_block"]["number"].as_u64(),
        Some(BLOCK_NUMBER)
    );
    assert_eq!(manifest["fixed_block"]["hash"].as_str(), Some(BLOCK_HASH));
    assert_eq!(
        manifest["abi_artifact"].as_str(),
        Some("abi/RedemptionVault.redeem-routes.abi.json")
    );
    let routes = manifest["routes"].as_array().expect("manifest routes");
    assert_eq!(routes.len(), ROUTES.len());
    for (route, (signature, selector)) in routes.iter().zip(ROUTES) {
        assert_eq!(route["canonical_signature"].as_str(), Some(signature));
        assert_eq!(
            route["selector"].as_str(),
            Some(format!("0x{}", hex::encode(selector)).as_str())
        );
        assert_eq!(route["state_mutability"].as_str(), Some("nonpayable"));
        assert_eq!(route["payer"].as_str(), Some("msg.sender"));
    }
    let excluded = manifest["excluded_routes"]
        .as_array()
        .expect("manifest excluded routes");
    assert_eq!(excluded.len(), 1);
    assert_eq!(
        excluded[0]["canonical_signature"].as_str(),
        Some(FIAT_ROUTE.0)
    );
    assert_eq!(
        excluded[0]["selector"].as_str(),
        Some(format!("0x{}", hex::encode(FIAT_ROUTE.1)).as_str())
    );
    for boundary in ["currency", "bank destination", "no on-chain fiat transfer"] {
        assert!(
            manifest["semantics"]["fiat_refusal"]
                .as_str()
                .expect("fiat refusal semantics")
                .contains(boundary),
            "fiat refusal lost boundary {boundary:?}"
        );
    }
    assert_eq!(
        manifest["semantics"]["trusted_request_intent"].as_str(),
        Some("mTBILL leaves now; no output minimum")
    );
    for boundary in [
        "immediately",
        "later supplied mToken rate",
        "no output minimum",
    ] {
        assert!(
            manifest["semantics"]["request_lifecycle"]
                .as_str()
                .expect("request lifecycle semantics")
                .contains(boundary),
            "request authority lost boundary {boundary:?}"
        );
    }

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
        ("vault-proxy-code", "RedemptionVaultProxy"),
        (
            "vault-implementation-code",
            "RedemptionVault.implementation",
        ),
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
    let vault_proxy = read_json(&evidence.join("blockscout/RedemptionVaultProxy.json"));
    let vault_implementation =
        read_json(&evidence.join("blockscout/RedemptionVault.implementation.json"));
    let mtbill_proxy = read_json(&evidence.join("blockscout/MTBillProxy.json"));
    let mtbill_implementation = read_json(&evidence.join("blockscout/MTBill.implementation.json"));

    let vault_proxy_runtime = read_runtime(&evidence, "RedemptionVaultProxy");
    let vault_implementation_runtime = read_runtime(&evidence, "RedemptionVault.implementation");
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
    assert_eq!(
        vault_implementation["name"].as_str(),
        Some("RedemptionVault")
    );
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
    assert_eq!(vault_implementation_runtime.len(), 17_811);
    assert_eq!(mtbill_proxy_runtime.len(), 2_227);
    assert_eq!(mtbill_implementation_runtime.len(), 6_271);
    for (signature, selector) in ROUTES {
        assert!(
            vault_implementation_runtime
                .windows(selector.len())
                .any(|window| window == selector),
            "deployed runtime lost admitted selector for {signature}"
        );
    }
    assert!(
        vault_implementation_runtime
            .windows(FIAT_ROUTE.1.len())
            .any(|window| window == FIAT_ROUTE.1),
        "deployed runtime lost exact-known refused fiat selector"
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

    let settings = read_json(&evidence.join("compiler/RedemptionVault.settings.json"));
    assert_eq!(settings, vault_implementation["compiler_settings"]);
    let input = read_json(&evidence.join("compiler/RedemptionVault.standard-input.json"));
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
        "contracts/RedemptionVault.sol": {
            "RedemptionVault": ["evm.deployedBytecode.object", "metadata"]
        }
    });
    assert_eq!(input["settings"], expected_settings);

    assert_eq!(
        fs::read_to_string(evidence.join("compiler/solc-0.8.9.version.txt")).expect("solc version"),
        "0.8.9+commit.e5eed63a.Emscripten.clang\n"
    );
    let output = read_json(&evidence.join("compiler/RedemptionVault.standard-output.json"));
    for diagnostic in output["errors"].as_array().into_iter().flatten() {
        assert_ne!(diagnostic["severity"].as_str(), Some("error"));
    }
    let compiled = decode_hex(
        output["contracts"]["contracts/RedemptionVault.sol"]["RedemptionVault"]["evm"]
            ["deployedBytecode"]["object"]
            .as_str()
            .expect("compiled RedemptionVault runtime"),
    );
    assert_eq!(compiled, vault_implementation_runtime);

    let commit = read_json(&evidence.join("official/github-git-commit.json"));
    assert_eq!(commit["sha"].as_str(), Some(OFFICIAL_COMMIT));
    assert_eq!(commit["tree"]["sha"].as_str(), Some(OFFICIAL_TREE));
    let addresses = fs::read_to_string(evidence.join("official/config/constants/addresses.ts"))
        .expect("official Midas address map");
    assert!(addresses.contains("token: '0xDD629E5241CbC5919847783e6C96B2De4754e438'"));
    assert!(addresses.contains("redemptionVault: '0xF6e51d24F4793Ac5e71e0502213a9BBE3A6d4517'"));
    let config = fs::read_to_string(evidence.join("official/scripts/deploy/configs/mTBILL.ts"))
        .expect("official mTBILL deployment config");
    assert!(config.contains("[chainIds.main]:"));
    assert!(config.contains("instantDailyLimit: parseUnits('1000')"));
    assert!(config.contains("instantFee: parseUnits('0.07', 2)"));
    assert!(config.contains("enableSanctionsList: true"));

    for path in [
        "contracts/RedemptionVault.sol",
        "contracts/abstract/ManageableVault.sol",
        "contracts/interfaces/IRedemptionVault.sol",
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
fn exact_abi_and_deployed_source_bind_four_token_routes_and_refuse_fiat() {
    let evidence = evidence_root();
    let abi = read_json(&evidence.join("abi/RedemptionVault.redeem-routes.abi.json"));
    let functions = abi.as_array().expect("ABI projection array");
    assert_eq!(
        functions.len(),
        ROUTES.len() + 1,
        "ABI projection must retain four admitted token routes plus fiat refusal control"
    );
    let functions_by_signature: BTreeMap<_, _> = functions
        .iter()
        .map(|function| (abi_signature(function), function))
        .collect();
    assert_eq!(functions_by_signature.len(), ROUTES.len() + 1);

    for (signature, selector) in ROUTES {
        let function = functions_by_signature
            .get(signature)
            .unwrap_or_else(|| panic!("missing ABI route {signature}"));
        assert_eq!(function["type"].as_str(), Some("function"));
        assert_eq!(function["stateMutability"].as_str(), Some("nonpayable"));
        if signature.starts_with("redeemRequest") {
            assert_eq!(
                function["outputs"],
                json!([{"internalType": "uint256", "name": "", "type": "uint256"}])
            );
        } else {
            assert_eq!(function["outputs"], json!([]));
        }
        assert_eq!(&keccak256(signature.as_bytes())[..4], &selector);
    }

    let fiat = functions_by_signature
        .get(FIAT_ROUTE.0)
        .expect("fiat ABI refusal control");
    assert_eq!(fiat["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(
        fiat["outputs"],
        json!([{"internalType": "uint256", "name": "", "type": "uint256"}])
    );
    assert_eq!(&keccak256(FIAT_ROUTE.0.as_bytes())[..4], &FIAT_ROUTE.1);

    let expected_names = [
        (
            ROUTES[0].0,
            &["tokenOut", "amountMTokenIn", "minReceiveAmount"][..],
        ),
        (
            ROUTES[1].0,
            &[
                "tokenOut",
                "amountMTokenIn",
                "minReceiveAmount",
                "recipient",
            ][..],
        ),
        (ROUTES[2].0, &["tokenOut", "amountMTokenIn"][..]),
        (
            ROUTES[3].0,
            &["tokenOut", "amountMTokenIn", "recipient"][..],
        ),
        (FIAT_ROUTE.0, &["amountMTokenIn"][..]),
    ];
    for (signature, names) in expected_names {
        let actual = functions_by_signature[signature]["inputs"]
            .as_array()
            .expect("ABI inputs")
            .iter()
            .map(|input| input["name"].as_str().expect("ABI input name"))
            .collect::<Vec<_>>();
        assert_eq!(actual, names, "ABI operand order drifted for {signature}");
    }

    let redemption =
        fs::read_to_string(evidence.join("source/verified/contracts/RedemptionVault.sol"))
            .expect("verified RedemptionVault source");
    for (signature, _) in ROUTES {
        assert!(
            redemption.contains(&format!("keccak256(\"{signature}\")")),
            "deployed source lost selector declaration for {signature}"
        );
    }

    let instant_overloads = solidity_functions(&redemption, "redeemInstant");
    assert_eq!(instant_overloads.len(), 2, "instant overload set drifted");
    let standard_instant = instant_overloads
        .iter()
        .find(|function| !normalized(function.header).contains("address recipient"))
        .expect("standard redeemInstant");
    assert!(
        normalized(standard_instant.header).contains("whenFnNotPaused(_REDEEM_INSTANT_SELECTOR)")
    );
    assert_fragments_in_order(
        standard_instant.body,
        &[
            "_validateUserAccess(msg.sender);",
            "_redeemInstant( tokenOut, amountMTokenIn, minReceiveAmount, msg.sender )",
            "emit RedeemInstant( msg.sender, tokenOut, amountMTokenIn, calcResult.feeAmount, amountTokenOutWithoutFee )",
        ],
        "implicit-beneficiary redeemInstant",
    );
    let custom_instant = instant_overloads
        .iter()
        .find(|function| normalized(function.header).contains("address recipient"))
        .expect("custom-recipient redeemInstant");
    assert!(normalized(custom_instant.header)
        .contains("whenFnNotPaused(_REDEEM_INSTANT_WITH_CUSTOM_RECIPIENT_SELECTOR)"));
    assert_fragments_in_order(
        custom_instant.body,
        &[
            "_validateUserAccess(msg.sender);",
            "if (recipient != msg.sender)",
            "_validateUserAccess(recipient);",
            "_redeemInstant( tokenOut, amountMTokenIn, minReceiveAmount, recipient )",
            "emit RedeemInstantWithCustomRecipient( msg.sender, tokenOut, recipient, amountMTokenIn, calcResult.feeAmount, amountTokenOutWithoutFee )",
        ],
        "signed-beneficiary redeemInstant",
    );

    let instant = solidity_function(&redemption, "_redeemInstant");
    assert_fragments_in_order(
        instant.body,
        &[
            "calcResult = _calcAndValidateRedeem( user, tokenOut, amountMTokenIn, true, false )",
            "_requireAndUpdateLimit(amountMTokenIn);",
            "amountTokenOutWithoutFee = _truncate( (calcResult.amountMTokenWithoutFee * mTokenRate) / tokenOutRate, tokenDecimals )",
            "amountTokenOutWithoutFee >= minReceiveAmount",
            "mToken.burn(user, calcResult.amountMTokenWithoutFee);",
            "_tokenTransferFromUser( address(mToken), feeReceiver, calcResult.feeAmount, 18 )",
            "_tokenTransferToUser( tokenOutCopy, recipient, amountTokenOutWithoutFee, tokenDecimals )",
        ],
        "instant normalized-minimum and exact-payer implementation",
    );

    let request_overloads = solidity_functions(&redemption, "redeemRequest");
    assert_eq!(request_overloads.len(), 2, "request overload set drifted");
    let standard_request = request_overloads
        .iter()
        .find(|function| !normalized(function.header).contains("address recipient"))
        .expect("standard redeemRequest");
    assert!(
        normalized(standard_request.header).contains("whenFnNotPaused(_REDEEM_REQUEST_SELECTOR)")
    );
    assert_fragments_in_order(
        standard_request.body,
        &[
            "_validateUserAccess(msg.sender);",
            "_redeemRequest(tokenOut, amountMTokenIn, false, msg.sender)",
            "emit RedeemRequest( requestId, msg.sender, tokenOut, amountMTokenIn, calcResult.feeAmount )",
        ],
        "implicit-beneficiary redeemRequest",
    );
    let custom_request = request_overloads
        .iter()
        .find(|function| normalized(function.header).contains("address recipient"))
        .expect("custom-recipient redeemRequest");
    assert!(normalized(custom_request.header)
        .contains("whenFnNotPaused(_REDEEM_REQUEST_WITH_CUSTOM_RECIPIENT_SELECTOR)"));
    assert_fragments_in_order(
        custom_request.body,
        &[
            "_validateUserAccess(msg.sender);",
            "if (recipient != msg.sender)",
            "_validateUserAccess(recipient);",
            "_redeemRequest(tokenOut, amountMTokenIn, false, recipient)",
            "emit RedeemRequestWithCustomRecipient( requestId, msg.sender, tokenOut, recipient, amountMTokenIn, calcResult.feeAmount )",
        ],
        "signed-beneficiary redeemRequest",
    );

    let request = solidity_function(&redemption, "_redeemRequest");
    assert_fragments_in_order(
        request.body,
        &[
            "calcResult = _calcAndValidateRedeem( user, tokenOut, amountMTokenIn, false, isFiat )",
            "_tokenTransferFromUser( address(mToken), address(this), calcResult.amountMTokenWithoutFee, 18",
            "_tokenTransferFromUser( address(mToken), feeReceiver, calcResult.feeAmount, 18 )",
            "redeemRequests[requestId] = Request({ sender: recipient, tokenOut: tokenOutCopy, status: RequestStatus.Pending, amountMToken: calcResult.amountMTokenWithoutFee, mTokenRate: mTokenRate, tokenOutRate: tokenOutRate })",
        ],
        "pay-now pending redemption request",
    );

    let approve = solidity_function(&redemption, "_approveRequest");
    assert_fragments_in_order(
        approve.body,
        &[
            "bool isFiat = request.tokenOut == MANUAL_FULLFILMENT_TOKEN;",
            "uint256 amountTokenOutWithoutFee = _truncate( (request.amountMToken * newMTokenRate) / request.tokenOutRate, tokenDecimals )",
            "if (!isFiat)",
            "_tokenTransferFromTo( request.tokenOut, requestRedeemer, request.sender, amountTokenOutWithoutFee, tokenDecimals )",
            "mToken.burn(address(this), request.amountMToken);",
            "request.status = RequestStatus.Processed;",
        ],
        "later administrator-rate request completion",
    );
    let reject = solidity_function(&redemption, "rejectRequest");
    assert_fragments_in_order(
        reject.body,
        &[
            "Request memory request = redeemRequests[requestId];",
            "redeemRequests[requestId].status = RequestStatus.Canceled;",
        ],
        "request rejection without automatic refund",
    );

    let fiat = solidity_function(&redemption, "redeemFiatRequest");
    assert_fragments_in_order(
        fiat.body,
        &[
            "_validateUserAccess(msg.sender);",
            "_redeemRequest( MANUAL_FULLFILMENT_TOKEN, amountMTokenIn, true, msg.sender )",
            "emit RedeemRequest( requestId, msg.sender, MANUAL_FULLFILMENT_TOKEN, amountMTokenIn, calcResult.feeAmount )",
        ],
        "manual-fiat route with no signed payout terms",
    );

    let calculation = solidity_function(&redemption, "_calcAndValidateRedeem");
    assert_fragments_in_order(
        calculation.body,
        &[
            "require(amountMTokenIn > 0, \"RV: invalid amount\");",
            "result.feeAmount = _getFeeAmount( user, tokenOut, amountMTokenIn, isInstant, isFiat ? fiatAdditionalFee : 0 )",
            "if (isFiat)",
            "tokenOut == MANUAL_FULLFILMENT_TOKEN",
            "result.feeAmount += fiatFlatFee;",
            "_requireTokenExists(tokenOut);",
            "result.amountMTokenWithoutFee = amountMTokenIn - result.feeAmount;",
        ],
        "redemption fee and fiat-sentinel calculation",
    );

    let manageable =
        fs::read_to_string(evidence.join("source/verified/contracts/abstract/ManageableVault.sol"))
            .expect("verified ManageableVault source");
    assert!(normalized(&manageable)
        .contains("address public constant MANUAL_FULLFILMENT_TOKEN = address(0x0);"));
    let transfer = solidity_function(&manageable, "_tokenTransferFromUser");
    assert_fragments_in_order(
        transfer.body,
        &[
            "transferAmount = amount.convertFromBase18(tokenDecimals);",
            "amount == transferAmount.convertToBase18(tokenDecimals)",
            "IERC20(token).safeTransferFrom(msg.sender, to, transferAmount);",
        ],
        "base-18 exact authenticated-payer transfer",
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
