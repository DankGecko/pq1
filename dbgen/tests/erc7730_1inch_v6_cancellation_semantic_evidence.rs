//! Offline deployment and semantic evidence for the bounded 1inch V6
//! cancellation-control curation.
//!
//! Descriptor/IR/Merkle/render behavior is exercised by the catalogue and
//! secure-world suites. These tests keep the external authority package
//! honest: every byte is receipted, two fixed-block RPC observations agree per
//! admitted deployment, verifier records bind the exact runtime and direct
//! classification, and deployed source preserves the conditional cancellation
//! and epoch-transition semantics shown to the signer.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const NORMAL_ADDRESS: &str = "0x111111125421ca6dc452d289314280a0f8842a65";
const ZKSYNC_ADDRESS: &str = "0x6fd4383cb451173d5f9304f041c7bcbf27d561ff";
const PRERELEASE_COMMIT: &str = "1a32e059f78ddcf1fe6294baed6cafb73a04b685";
const PRERELEASE_TREE: &str = "b4e359b24ab246b72272be703f64b674de0a21d5";
const FINAL_COMMIT: &str = "c8be9c67247880bd6ec88cf7ad2e040a16a483f2";
const FINAL_TREE: &str = "f020f3e3a32b6150fcc8167fded29a0e67035342";
const AUDIT_CATALOGUE_COMMIT: &str = "1deaa3bca4d3f0637bd0bfac4430e620956dba22";
const ZKSYNC_RUNTIME_SHA256: &str =
    "a5d93f86e1de8f2cdbf788f9d0b68afc71d9e5c48cb12149d68ca250f6dfcb99";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Deployment {
    chain_id: u64,
    slug: &'static str,
    address: &'static str,
    family: &'static str,
    fixed_block: u64,
}

const DEPLOYMENTS: [Deployment; 10] = [
    Deployment {
        chain_id: 1,
        slug: "ethereum",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 25_581_128,
    },
    Deployment {
        chain_id: 10,
        slug: "optimism",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 154_519_885,
    },
    Deployment {
        chain_id: 56,
        slug: "bsc",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 111_287_866,
    },
    Deployment {
        chain_id: 100,
        slug: "gnosis",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 47_316_637,
    },
    Deployment {
        chain_id: 137,
        slug: "polygon",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 90_622_689,
    },
    Deployment {
        chain_id: 324,
        slug: "zksync",
        address: ZKSYNC_ADDRESS,
        family: "zksync-v6",
        fixed_block: 71_249_090,
    },
    Deployment {
        chain_id: 8_453,
        slug: "base",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 48_924_600,
    },
    Deployment {
        chain_id: 42_161,
        slug: "arbitrum",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 486_191_758,
    },
    Deployment {
        chain_id: 59_144,
        slug: "linea",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 31_467_177,
    },
    Deployment {
        chain_id: 1_313_161_554,
        slug: "aurora",
        address: NORMAL_ADDRESS,
        family: "ordinary-v6",
        fixed_block: 207_912_504,
    },
];

const ROUTES: [(&str, &str, bool); 5] = [
    ("cancelOrder(uint256,bytes32)", "0xb68fb020", true),
    ("cancelOrders(uint256[],bytes32[])", "0x89e7c650", false),
    ("increaseEpoch(uint96)", "0xc3cf8043", true),
    (
        "bitsInvalidateForOrder(uint256,uint256)",
        "0x05b1ea03",
        false,
    ),
    ("advanceEpoch(uint96,uint256)", "0x0d2c7c16", false),
];

const SOURCE_PATHS: [&str; 6] = [
    "contracts/OrderMixin.sol",
    "contracts/helpers/SeriesEpochManager.sol",
    "contracts/libraries/MakerTraitsLib.sol",
    "contracts/libraries/BitInvalidatorLib.sol",
    "contracts/libraries/RemainingInvalidatorLib.sol",
    "contracts/interfaces/IOrderMixin.sol",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/1inch-v6-cancellation")
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid evidence hex")
}

fn read_runtime(evidence: &Path, slug: &str) -> Vec<u8> {
    decode_hex(
        &fs::read_to_string(evidence.join(format!("runtime/AggregationRouterV6.{slug}.hex")))
            .unwrap_or_else(|error| panic!("read runtime for {slug}: {error}")),
    )
}

fn selector(signature: &str) -> String {
    format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
}

fn hex_quantity(value: &Value) -> u64 {
    let text = value.as_str().expect("hex quantity is a string");
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).expect("valid hex quantity")
}

fn collect_files(root: &Path, directory: &Path, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read evidence directory {}: {error}", directory.display()))
    {
        let entry = entry.expect("evidence directory entry");
        let path = entry.path();
        let kind = entry.file_type().expect("evidence file type");
        assert!(!kind.is_symlink(), "evidence may not contain symlinks");
        if kind.is_dir() {
            collect_files(root, &path, files);
        } else {
            assert!(
                kind.is_file(),
                "unsupported evidence entry {}",
                path.display()
            );
            let relative = path
                .strip_prefix(root)
                .expect("evidence path stays under root")
                .to_string_lossy()
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(files.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn response_results(path: &Path) -> BTreeMap<String, Value> {
    let response = read_json(path);
    let mut results = BTreeMap::new();
    for item in response.as_array().expect("RPC response batch") {
        assert_eq!(item["jsonrpc"].as_str(), Some("2.0"));
        assert!(
            item.get("error").is_none() || item["error"].is_null(),
            "RPC error in {}",
            path.display()
        );
        let id = item["id"].as_str().expect("string RPC id").to_owned();
        let result = item
            .get("result")
            .unwrap_or_else(|| panic!("missing RPC result {id} in {}", path.display()))
            .clone();
        assert!(
            results.insert(id.clone(), result).is_none(),
            "duplicate RPC id {id}"
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
        .unwrap_or_else(|| panic!("missing RPC request id {id}"))
}

fn abi_signature(function: &Value) -> String {
    let name = required_str(function, "name");
    let types = function["inputs"]
        .as_array()
        .expect("ABI function inputs")
        .iter()
        .map(|input| required_str(input, "type"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({types})")
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments_in_order(source: &str, fragments: &[&str], context: &str) {
    let source = normalized(source);
    let mut cursor = 0usize;
    for fragment in fragments {
        let offset = source[cursor..]
            .find(fragment)
            .unwrap_or_else(|| panic!("{context} lost semantic fragment: {fragment}"));
        cursor += offset + fragment.len();
    }
}

#[derive(Clone, Copy)]
struct SolidityFunction<'a> {
    full: &'a str,
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
                        let closing = opening + offset + 1;
                        functions.push(SolidityFunction {
                            full: &definition[..closing],
                            header: &definition[..opening],
                            body: &definition[opening..closing],
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

fn sourcify_source(record: &Value) -> String {
    record["sources"]
        .as_object()
        .expect("Sourcify source map")
        .values()
        .map(|source| required_str(source, "content"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn zksync_standard_input(record: &Value) -> Value {
    let raw = record["result"][0]["SourceCode"]
        .as_str()
        .expect("zkSync verified compiler input");
    let unwrapped = if raw.starts_with("{{") && raw.ends_with("}}") {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    serde_json::from_str(unwrapped).expect("valid zkSync standard JSON compiler input")
}

fn standard_input_source(input: &Value) -> String {
    input["sources"]
        .as_object()
        .expect("compiler input source map")
        .values()
        .map(|source| required_str(source, "content"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn evidence_receipts_inventory_and_all_five_selectors_are_exact() {
    let workspace = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["issue"].as_str(),
        Some("https://github.com/EthereumPhone/PQ1/issues/491")
    );
    for denied in [
        "live-state",
        "future-code",
        "selector-only",
        "blind signing",
    ] {
        assert!(
            required_str(&manifest, "boundary").contains(denied),
            "authority boundary lost {denied:?}"
        );
    }

    let mut actual_routes = BTreeSet::new();
    for (admitted, routes) in [
        (true, &manifest["routes"]["admitted"]),
        (false, &manifest["routes"]["refused"]),
    ] {
        for route in routes.as_array().expect("route array") {
            let signature = required_str(route, "canonical_signature");
            let declared = required_str(route, "selector");
            assert_eq!(
                selector(signature),
                declared,
                "selector drift for {signature}"
            );
            assert!(
                actual_routes.insert((signature.to_owned(), declared.to_owned(), admitted)),
                "duplicate route {signature}"
            );
        }
    }
    let expected_routes: BTreeSet<_> = ROUTES
        .iter()
        .map(|(signature, selector, admitted)| {
            ((*signature).to_owned(), (*selector).to_owned(), *admitted)
        })
        .collect();
    assert_eq!(actual_routes, expected_routes);

    let actual_deployments: BTreeSet<_> = manifest["admitted_deployments"]
        .as_array()
        .expect("admitted deployments")
        .iter()
        .map(|deployment| Deployment {
            chain_id: deployment["chain_id"].as_u64().expect("chain id"),
            slug: Box::leak(required_str(deployment, "slug").to_owned().into_boxed_str()),
            address: Box::leak(
                required_str(deployment, "address")
                    .to_ascii_lowercase()
                    .into_boxed_str(),
            ),
            family: Box::leak(
                required_str(deployment, "family")
                    .to_owned()
                    .into_boxed_str(),
            ),
            fixed_block: deployment["fixed_block"].as_u64().expect("fixed block"),
        })
        .collect();
    assert_eq!(actual_deployments, DEPLOYMENTS.into_iter().collect());

    let exclusions = manifest["excluded_deployments"]
        .as_array()
        .expect("excluded deployments");
    assert_eq!(exclusions.len(), 4);
    let excluded_chains: BTreeSet<_> = exclusions
        .iter()
        .map(|excluded| excluded["chain_id"].as_u64().expect("excluded chain id"))
        .collect();
    assert_eq!(excluded_chains, BTreeSet::from([146, 250, 8_217, 43_114]));
    for excluded in exclusions {
        let chain_id = excluded["chain_id"].as_u64().expect("excluded chain id");
        assert_eq!(
            required_str(excluded, "address").to_ascii_lowercase(),
            NORMAL_ADDRESS
        );
        assert_eq!(
            excluded["status"].as_str(),
            Some("exact-known-hard-refusal")
        );
        assert_eq!(excluded["sourcify_http_status"].as_u64(), Some(404));
        let lookup = read_json(&evidence.join(required_str(excluded, "sourcify_record")));
        assert_eq!(
            lookup["chainId"].as_str(),
            Some(chain_id.to_string().as_str())
        );
        assert_eq!(
            lookup["address"].as_str().map(str::to_ascii_lowercase),
            Some(NORMAL_ADDRESS.to_owned())
        );
        for field in ["match", "creationMatch", "runtimeMatch"] {
            assert!(lookup[field].is_null(), "excluded chain gained {field}");
        }
        assert_eq!(
            fs::read_to_string(evidence.join(format!(
                "verifier/sourcify/excluded-{chain_id}.http-status.txt"
            )))
            .expect("excluded Sourcify HTTP status"),
            "404\n"
        );
    }

    for input in manifest["descriptor_inputs"]
        .as_array()
        .expect("descriptor input receipts")
    {
        let path = required_str(input, "path");
        let bytes = fs::read(workspace.join(path))
            .unwrap_or_else(|error| panic!("read descriptor input {path}: {error}"));
        let hash = required_str(input, "sha256_at_evidence_freeze");
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            sha256_hex(&bytes),
            hash,
            "source-to-descriptor receipt drifted: {path}"
        );
    }
    for relative in [
        "secure/data/erc7730-registry/registry/1inch/calldata-AggregationRouterV6.json",
        "secure/data/erc7730-registry/registry/1inch/calldata-AggregationRouterV6-zksync.json",
    ] {
        let descriptor = read_json(&workspace.join(relative));
        let expected_refusal_only = if relative.ends_with("AggregationRouterV6-zksync.json") {
            serde_json::json!([
                "advanceEpoch(uint96 series, uint256 amount)",
                "bitsInvalidateForOrder(uint256 makerTraits, uint256 additionalMask)"
            ])
        } else {
            serde_json::json!([
                "advanceEpoch(uint96 series, uint256 amount)",
                "bitsInvalidateForOrder(uint256 makerTraits, uint256 additionalMask)",
                "clipperSwap(address clipperExchange, uint256 srcToken, address dstToken, uint256 inputAmount, uint256 outputAmount, uint256 goodUntil, bytes32 r, bytes32 vs)",
                "clipperSwapTo(address clipperExchange, address recipient, uint256 srcToken, address dstToken, uint256 inputAmount, uint256 outputAmount, uint256 goodUntil, bytes32 r, bytes32 vs)"
            ])
        };
        assert_eq!(
            descriptor["_pqsigner"]["refusalOnlyFormats"],
            expected_refusal_only
        );
        let refusal_only = descriptor["_pqsigner"]["refusalOnlyFormats"]
            .as_array()
            .expect("structural refusal-only format list");
        let refusal_only = refusal_only
            .iter()
            .map(|value| value.as_str().expect("refusal-only signature"))
            .collect::<BTreeSet<_>>();
        for admission in descriptor["_pqsigner"]["deploymentFormats"]
            .as_array()
            .expect("deployment format admissions")
        {
            for format in admission["formats"].as_array().expect("admitted formats") {
                assert!(
                    !refusal_only.contains(format.as_str().expect("admitted signature")),
                    "refusal-only and admitted format overlap in {relative}"
                );
            }
        }
    }
    if let Some(overlay) = manifest["curation_overlay"].as_object() {
        let relative = overlay["path"].as_str().expect("curation overlay path");
        let bytes = fs::read(workspace.join(relative)).expect("curation overlay bytes");
        assert_eq!(
            sha256_hex(&bytes),
            required_str(&Value::Object(overlay.clone()), "sha256")
        );
    }

    // The Etherscan-compatible source payload has no address field. Preserve
    // the Phase-B join by pinning both exact address-scoped official-explorer
    // requests in the receipted collector instead of treating source.json as
    // self-identifying.
    let collector = fs::read_to_string(evidence.join("collect.sh")).expect("evidence collector");
    for url in [
        format!("https://block-explorer-api.mainnet.zksync.io/address/{ZKSYNC_ADDRESS}"),
        format!("https://block-explorer-api.mainnet.zksync.io/api?module=contract&action=getsourcecode&address={ZKSYNC_ADDRESS}"),
    ] {
        assert!(
            collector.contains(&url),
            "collector lost address-scoped zkSync join: {url}"
        );
    }

    let mut declared = BTreeSet::new();
    for artifact in manifest["artifacts"].as_array().expect("artifact receipts") {
        let relative = required_str(artifact, "path");
        assert!(
            declared.insert(relative.to_owned()),
            "duplicate receipt {relative}"
        );
        let bytes = fs::read(evidence.join(relative))
            .unwrap_or_else(|error| panic!("read evidence {relative}: {error}"));
        assert_eq!(
            sha256_hex(&bytes),
            required_str(artifact, "sha256"),
            "archived evidence drifted: {relative}"
        );
    }
    let mut actual = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut actual);
    assert_eq!(actual, declared, "every non-manifest artifact is receipted");
}

#[test]
fn two_fixed_block_providers_and_verifiers_bind_every_exact_runtime() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let fixed = read_json(&evidence.join("rpc/fixed-block-receipt.json"));
    assert_eq!(fixed["schema_version"].as_u64(), Some(1));
    let observations = fixed["observations"]
        .as_array()
        .expect("fixed-block observations");
    assert_eq!(observations.len(), DEPLOYMENTS.len());

    let manifest_by_chain: BTreeMap<_, _> = manifest["admitted_deployments"]
        .as_array()
        .expect("admitted deployments")
        .iter()
        .map(|deployment| {
            (
                deployment["chain_id"].as_u64().expect("chain id"),
                deployment,
            )
        })
        .collect();
    assert_eq!(manifest_by_chain.len(), DEPLOYMENTS.len());

    let mut seen = BTreeSet::new();
    for observation in observations {
        let chain_id = observation["chain_id"].as_u64().expect("receipt chain id");
        assert!(seen.insert(chain_id), "duplicate chain receipt {chain_id}");
        let expected = DEPLOYMENTS
            .iter()
            .find(|deployment| deployment.chain_id == chain_id)
            .unwrap_or_else(|| panic!("unexpected admitted chain {chain_id}"));
        let deployment = manifest_by_chain[&chain_id];
        assert_eq!(required_str(observation, "slug"), expected.slug);
        assert_eq!(required_str(deployment, "slug"), expected.slug);
        assert_eq!(required_str(deployment, "family"), expected.family);
        assert_eq!(
            required_str(observation, "address").to_ascii_lowercase(),
            expected.address
        );
        assert_eq!(
            observation["block"]["number"].as_u64(),
            Some(expected.fixed_block)
        );
        assert_eq!(
            deployment["fixed_block"].as_u64(),
            Some(expected.fixed_block)
        );

        let request_document = read_json(&evidence.join(required_str(observation, "request_path")));
        assert_eq!(
            request_document
                .as_array()
                .expect("RPC request batch")
                .len(),
            2
        );
        let header_id = format!("{}-header", expected.slug);
        let code_id = format!("{}-code", expected.slug);
        let header_request = request(&request_document, &header_id);
        let code_request = request(&request_document, &code_id);
        assert_eq!(
            header_request["method"].as_str(),
            Some("eth_getBlockByNumber")
        );
        assert_eq!(
            header_request["params"][0].as_str(),
            observation["block"]["number_hex"].as_str()
        );
        assert_eq!(header_request["params"][1].as_bool(), Some(false));
        assert_eq!(code_request["method"].as_str(), Some("eth_getCode"));
        assert_eq!(
            code_request["params"][0]
                .as_str()
                .map(str::to_ascii_lowercase),
            Some(expected.address.to_owned())
        );
        let block_selector = code_request["params"][1]
            .as_object()
            .expect("EIP-1898 block selector");
        assert_eq!(block_selector.len(), 2);
        assert_eq!(
            block_selector["blockHash"].as_str(),
            observation["block"]["hash"].as_str()
        );
        assert_eq!(block_selector["requireCanonical"].as_bool(), Some(true));

        let providers = observation["providers"]
            .as_array()
            .expect("two RPC providers");
        assert_eq!(providers.len(), 2);
        assert_ne!(providers[0]["name"], providers[1]["name"]);
        assert_ne!(providers[0]["url"], providers[1]["url"]);
        assert_ne!(providers[0]["response_path"], providers[1]["response_path"]);
        let provider_results: Vec<_> = providers
            .iter()
            .map(|provider| {
                response_results(&evidence.join(required_str(provider, "response_path")))
            })
            .collect();
        let first_header = &provider_results[0][&header_id];
        let first_code = &provider_results[0][&code_id];
        for results in &provider_results {
            let header = &results[&header_id];
            assert_eq!(header["hash"], first_header["hash"]);
            assert_eq!(header["parentHash"], first_header["parentHash"]);
            assert_eq!(header["stateRoot"], first_header["stateRoot"]);
            assert_eq!(header["timestamp"], first_header["timestamp"]);
            assert_eq!(hex_quantity(&header["number"]), expected.fixed_block);
            assert_eq!(&results[&code_id], first_code);
        }
        assert_eq!(
            first_header["hash"].as_str(),
            observation["block"]["hash"].as_str()
        );
        assert_eq!(
            first_header["parentHash"].as_str(),
            observation["block"]["parent_hash"].as_str()
        );
        assert_eq!(
            first_header["stateRoot"].as_str(),
            observation["block"]["state_root"].as_str()
        );
        assert_eq!(
            first_header["timestamp"].as_str(),
            observation["block"]["timestamp_hex"].as_str()
        );

        let runtime = read_runtime(&evidence, expected.slug);
        assert_eq!(
            decode_hex(first_code.as_str().expect("RPC runtime hex")),
            runtime
        );
        assert_eq!(
            observation["runtime"]["bytes"].as_u64(),
            Some(runtime.len() as u64)
        );
        let runtime_path = evidence.join(required_str(&observation["runtime"], "path"));
        assert_eq!(
            sha256_hex(&fs::read(runtime_path).expect("runtime artifact bytes")),
            required_str(&observation["runtime"], "file_sha256")
        );
        assert_eq!(
            sha256_hex(&runtime),
            required_str(&observation["runtime"], "decoded_sha256")
        );
        for (signature, expected_selector, _) in ROUTES {
            let bytes: [u8; 4] = decode_hex(expected_selector)
                .try_into()
                .expect("four-byte selector");
            assert!(
                runtime.windows(4).any(|window| window == bytes),
                "{expected:?} runtime lost selector {signature}"
            );
        }

        match chain_id {
            1 | 10 | 56 | 100 | 137 | 8_453 | 42_161 | 59_144 => {
                let record = read_json(&evidence.join(required_str(deployment, "verifier")));
                assert_eq!(
                    record["chainId"].as_str(),
                    Some(chain_id.to_string().as_str())
                );
                assert_eq!(
                    record["address"].as_str().map(str::to_ascii_lowercase),
                    Some(expected.address.to_owned())
                );
                assert_eq!(record["match"].as_str(), Some("exact_match"));
                assert_eq!(record["creationMatch"].as_str(), Some("exact_match"));
                assert_eq!(record["runtimeMatch"].as_str(), Some("exact_match"));
                assert_eq!(record["proxyResolution"]["isProxy"].as_bool(), Some(false));
                assert!(record["proxyResolution"]["proxyType"].is_null());
                assert_eq!(
                    record["proxyResolution"]["implementations"]
                        .as_array()
                        .map(Vec::len),
                    Some(0)
                );
                assert_eq!(
                    record["compilation"]["compilerVersion"].as_str(),
                    Some("0.8.23+commit.f704f362")
                );
                assert_eq!(
                    decode_hex(required_str(&record["runtimeBytecode"], "onchainBytecode")),
                    runtime,
                    "Sourcify and fixed-block runtime disagree on chain {chain_id}"
                );
                assert!(record["deployment"]["transactionHash"].as_str().is_some());
                assert!(record["deployment"]["blockNumber"].as_str().is_some());
            }
            1_313_161_554 => {
                let record = read_json(&evidence.join(required_str(deployment, "verifier")));
                assert_eq!(record["name"].as_str(), Some("AggregationRouterV6"));
                assert_eq!(record["is_verified"].as_bool(), Some(true));
                assert_eq!(record["is_fully_verified"].as_bool(), Some(true));
                assert_eq!(record["is_changed_bytecode"].as_bool(), Some(false));
                assert!(record["proxy_type"].is_null());
                assert_eq!(record["implementations"].as_array().map(Vec::len), Some(0));
                assert_eq!(
                    record["compiler_version"].as_str(),
                    Some("v0.8.23+commit.f704f362")
                );
                assert_eq!(
                    decode_hex(required_str(&record, "deployed_bytecode")),
                    runtime,
                    "Aurora Blockscout and fixed-block runtime disagree"
                );
            }
            324 => {
                let address_record = read_json(&evidence.join("verifier/zksync/address.json"));
                assert_eq!(
                    address_record["address"]
                        .as_str()
                        .map(str::to_ascii_lowercase),
                    Some(ZKSYNC_ADDRESS.to_owned())
                );
                let explorer_runtime = decode_hex(required_str(&address_record, "bytecode"));
                assert_eq!(explorer_runtime.len(), 227_808);
                assert_eq!(sha256_hex(&explorer_runtime), ZKSYNC_RUNTIME_SHA256);
                assert_eq!(explorer_runtime, runtime);

                let source_record = read_json(&evidence.join(required_str(deployment, "verifier")));
                assert_eq!(source_record["status"].as_str(), Some("1"));
                assert_eq!(source_record["message"].as_str(), Some("OK"));
                assert_eq!(source_record["result"].as_array().map(Vec::len), Some(1));
                let source = &source_record["result"][0];
                assert_eq!(source["Proxy"].as_str(), Some("0"));
                assert_eq!(source["Implementation"].as_str(), Some(""));
                assert_eq!(source["CompilerVersion"].as_str(), Some("0.8.23"));
                assert_eq!(source["ZkSolcVersion"].as_str(), Some("v1.3.22"));
                assert_eq!(
                    source["ContractName"].as_str(),
                    Some("contracts/networks/AggregationRouterV6.zksync.sol:AggregationRouterV6")
                );
            }
            _ => unreachable!("deployment set is exact"),
        }
    }
    assert_eq!(
        seen,
        DEPLOYMENTS
            .iter()
            .map(|deployment| deployment.chain_id)
            .collect()
    );
}

#[test]
fn exact_abi_and_verified_sources_share_the_official_v4_semantics() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    let prerelease_commit = read_json(&evidence.join("official/github/prerelease-19.commit.json"));
    let final_commit = read_json(&evidence.join("official/github/v4.0.0.commit.json"));
    assert_eq!(prerelease_commit["sha"].as_str(), Some(PRERELEASE_COMMIT));
    assert_eq!(
        prerelease_commit["tree"]["sha"].as_str(),
        Some(PRERELEASE_TREE)
    );
    assert_eq!(final_commit["sha"].as_str(), Some(FINAL_COMMIT));
    assert_eq!(final_commit["tree"]["sha"].as_str(), Some(FINAL_TREE));
    for (path, commit) in [
        ("official/github/prerelease-19.ref.json", PRERELEASE_COMMIT),
        ("official/github/v4.0.0.ref.json", FINAL_COMMIT),
    ] {
        let reference = read_json(&evidence.join(path));
        assert_eq!(reference["object"]["type"].as_str(), Some("commit"));
        assert_eq!(reference["object"]["sha"].as_str(), Some(commit));
    }
    let audit_commit = read_json(&evidence.join("official/audits/github-git-commit.json"));
    assert_eq!(audit_commit["sha"].as_str(), Some(AUDIT_CATALOGUE_COMMIT));
    let audit_directory = read_json(
        &evidence.join("official/audits/AggregationRouterV6-LimitOrderV4.directory.json"),
    );
    let audit_names: BTreeSet<_> = audit_directory
        .as_array()
        .expect("official audit directory")
        .iter()
        .map(|item| required_str(item, "name"))
        .collect();
    assert!(audit_names.contains("1inch Limit Order Protocol v4_OpenZeppelin.pdf"));
    assert!(audit_names.contains("1inch Aggregation Router V6_OpenZeppelin.pdf"));
    assert!(
        required_str(&manifest["official_source"], "audit_catalogue_boundary")
            .contains("not a claim")
    );

    for path in SOURCE_PATHS {
        assert_eq!(
            fs::read(evidence.join("official/prerelease-19").join(path))
                .expect("prerelease official source"),
            fs::read(evidence.join("official/v4.0.0").join(path)).expect("final official source"),
            "load-bearing source changed between official tags: {path}"
        );
    }

    let abi = read_json(&evidence.join("abi/AggregationRouterV6.cancellation.abi.json"));
    let normal_functions: BTreeMap<_, _> = abi
        .as_array()
        .expect("normal ABI projection")
        .iter()
        .map(|function| (abi_signature(function), function))
        .collect();
    let zk_record = read_json(&evidence.join("verifier/zksync/source.json"));
    let zk_abi_text = zk_record["result"][0]["ABI"]
        .as_str()
        .expect("zkSync exact ABI");
    let zk_abi: Value = serde_json::from_str(zk_abi_text).expect("valid zkSync ABI JSON");
    let zk_functions: BTreeMap<_, _> = zk_abi
        .as_array()
        .expect("zkSync ABI")
        .iter()
        .filter(|function| {
            function["type"].as_str() == Some("function")
                && matches!(
                    function["name"].as_str(),
                    Some(
                        "advanceEpoch"
                            | "bitsInvalidateForOrder"
                            | "cancelOrder"
                            | "cancelOrders"
                            | "increaseEpoch"
                    )
                )
        })
        .map(|function| (abi_signature(function), function))
        .collect();
    let abi_signatures = BTreeSet::from([
        "advanceEpoch(uint96,uint256)".to_owned(),
        "bitsInvalidateForOrder(uint256,uint256)".to_owned(),
        "cancelOrder(uint256,bytes32)".to_owned(),
        "cancelOrders(uint256[],bytes32[])".to_owned(),
        "increaseEpoch(uint96)".to_owned(),
    ]);
    assert_eq!(
        normal_functions.keys().cloned().collect::<BTreeSet<_>>(),
        abi_signatures
    );
    assert_eq!(
        zk_functions.keys().cloned().collect::<BTreeSet<_>>(),
        abi_signatures
    );
    for signature in &abi_signatures {
        let normal = normal_functions[signature];
        let zk = zk_functions[signature];
        assert_eq!(normal["type"].as_str(), Some("function"));
        assert_eq!(normal["stateMutability"].as_str(), Some("nonpayable"));
        assert_eq!(normal["outputs"].as_array().map(Vec::len), Some(0));
        assert_eq!(normal["inputs"], zk["inputs"]);
        assert_eq!(normal["outputs"], zk["outputs"]);
        assert_eq!(normal["stateMutability"], zk["stateMutability"]);
        let expected_names: &[&str] = match signature.as_str() {
            "advanceEpoch(uint96,uint256)" => &["series", "amount"],
            "bitsInvalidateForOrder(uint256,uint256)" => &["makerTraits", "additionalMask"],
            "cancelOrder(uint256,bytes32)" => &["makerTraits", "orderHash"],
            "cancelOrders(uint256[],bytes32[])" => &["makerTraits", "orderHashes"],
            "increaseEpoch(uint96)" => &["series"],
            _ => unreachable!("ABI signature set is exact"),
        };
        let actual_names = normal["inputs"]
            .as_array()
            .expect("ABI inputs")
            .iter()
            .map(|input| required_str(input, "name"))
            .collect::<Vec<_>>();
        assert_eq!(actual_names, expected_names, "ABI operand order drifted");
        let expected = ROUTES
            .iter()
            .find(|(candidate, _, _)| candidate == signature)
            .expect("ABI route is in exact selector inventory");
        assert_eq!(selector(signature), expected.1);
    }

    let order_mixin =
        fs::read_to_string(evidence.join("official/prerelease-19/contracts/OrderMixin.sol"))
            .expect("official OrderMixin");
    let series = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/helpers/SeriesEpochManager.sol"),
    )
    .expect("official SeriesEpochManager");
    let maker_traits = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/libraries/MakerTraitsLib.sol"),
    )
    .expect("official MakerTraitsLib");
    let bit_invalidator = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/libraries/BitInvalidatorLib.sol"),
    )
    .expect("official BitInvalidatorLib");
    let remaining = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/libraries/RemainingInvalidatorLib.sol"),
    )
    .expect("official RemainingInvalidatorLib");

    let relevant = [
        (&order_mixin, "cancelOrder"),
        (&series, "increaseEpoch"),
        (&series, "advanceEpoch"),
        (&series, "epochEquals"),
        (&maker_traits, "allowPartialFills"),
        (&maker_traits, "allowMultipleFills"),
        (&maker_traits, "useBitInvalidator"),
        (&maker_traits, "nonceOrEpoch"),
        (&maker_traits, "series"),
        (&maker_traits, "needCheckEpochManager"),
        (&bit_invalidator, "massInvalidate"),
        (&remaining, "fullyFilled"),
    ];

    let mut verified_variants = Vec::new();
    for chain_id in [1, 10, 56, 100, 137, 8_453, 42_161, 59_144] {
        let record = read_json(&evidence.join(format!("verifier/sourcify/{chain_id}.json")));
        verified_variants.push((
            format!("Sourcify chain {chain_id}"),
            sourcify_source(&record),
        ));
    }
    let aurora = read_json(&evidence.join("verifier/aurora/AggregationRouterV6.json"));
    verified_variants.push((
        "Aurora Blockscout".to_owned(),
        required_str(&aurora, "source_code").to_owned(),
    ));
    let zk_input = zksync_standard_input(&zk_record);
    verified_variants.push((
        "zkSync official explorer".to_owned(),
        standard_input_source(&zk_input),
    ));
    assert_eq!(verified_variants.len(), DEPLOYMENTS.len());

    for (variant, deployed_source) in &verified_variants {
        for (official_source, function_name) in relevant {
            let function = solidity_function(official_source, function_name);
            assert!(
                deployed_source.contains(function.full),
                "{variant} source changed official {function_name} body byte-for-byte"
            );
        }
    }
}

#[test]
fn official_source_proves_conditional_hash_cancellation_and_epoch_activation_hazard() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let order_mixin =
        fs::read_to_string(evidence.join("official/prerelease-19/contracts/OrderMixin.sol"))
            .expect("official OrderMixin");
    let series = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/helpers/SeriesEpochManager.sol"),
    )
    .expect("official SeriesEpochManager");
    let maker_traits = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/libraries/MakerTraitsLib.sol"),
    )
    .expect("official MakerTraitsLib");
    let bit_invalidator = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/libraries/BitInvalidatorLib.sol"),
    )
    .expect("official BitInvalidatorLib");
    let remaining = fs::read_to_string(
        evidence.join("official/prerelease-19/contracts/libraries/RemainingInvalidatorLib.sol"),
    )
    .expect("official RemainingInvalidatorLib");

    let cancel = solidity_function(&order_mixin, "cancelOrder");
    assert!(normalized(cancel.header).contains("public"));
    assert_fragments_in_order(
        cancel.body,
        &[
            "if (makerTraits.useBitInvalidator())",
            "_bitInvalidator[msg.sender].massInvalidate(makerTraits.nonceOrEpoch(), 0)",
            "emit BitInvalidatorUpdated(msg.sender, makerTraits.nonceOrEpoch() >> 8, invalidator)",
            "else",
            "_remainingInvalidator[msg.sender][orderHash] = RemainingInvalidatorLib.fullyFilled()",
            "emit OrderCancelled(orderHash)",
        ],
        "conditional cancelOrder semantics",
    );
    assert_fragments_in_order(
        solidity_function(&maker_traits, "useBitInvalidator").body,
        &["return !allowPartialFills(makerTraits) || !allowMultipleFills(makerTraits)"],
        "maker-traits invalidator choice",
    );
    assert_fragments_in_order(
        solidity_function(&bit_invalidator, "massInvalidate").body,
        &[
            "uint256 invalidatorSlot = nonce >> 8",
            "uint256 invalidatorBits = (1 << (nonce & 0xff)) | additionalMask",
            "result = self._raw[invalidatorSlot] | invalidatorBits",
            "self._raw[invalidatorSlot] = result",
        ],
        "nonce-bit invalidation",
    );
    assert_fragments_in_order(
        solidity_function(&remaining, "fullyFilled").body,
        &["return RemainingInvalidator.wrap(type(uint256).max)"],
        "hash invalidation",
    );

    let increase = solidity_function(&series, "increaseEpoch");
    assert!(normalized(increase.header).contains("external"));
    assert_fragments_in_order(
        increase.body,
        &["advanceEpoch(series, 1)"],
        "single-step epoch advance",
    );
    assert_fragments_in_order(
        solidity_function(&series, "advanceEpoch").body,
        &[
            "if (amount == 0 || amount > 255) revert AdvanceEpochFailed()",
            "uint256 key = uint160(msg.sender) | (uint256(series) << 160)",
            "uint256 newEpoch = _epochs[key] + amount",
            "_epochs[key] = newEpoch",
            "emit EpochIncreased(msg.sender, series, newEpoch)",
        ],
        "maker-scoped epoch transition",
    );
    assert_fragments_in_order(
        solidity_function(&series, "epochEquals").body,
        &["return _epochs[uint160(maker) | (uint256(series) << 160)] == makerEpoch"],
        "epoch equality",
    );
    assert_fragments_in_order(
        solidity_function(&order_mixin, "_fill").body,
        &[
            "if (order.makerTraits.needCheckEpochManager())",
            "if (order.makerTraits.useBitInvalidator()) revert EpochManagerAndBitInvalidatorsAreIncompatible()",
            "if (!epochEquals(order.maker.get(), order.makerTraits.series(), order.makerTraits.nonceOrEpoch())) revert WrongSeriesNonce()",
        ],
        "fill-time epoch activation check",
    );

    let admitted = manifest["routes"]["admitted"]
        .as_array()
        .expect("admitted route semantics");
    let cancel_effect = admitted
        .iter()
        .find(|route| route["canonical_signature"] == "cancelOrder(uint256,bytes32)")
        .expect("cancelOrder semantic receipt");
    assert_eq!(
        cancel_effect["authenticated_actor"].as_str(),
        Some("msg.sender")
    );
    for phrase in ["nonce-bit", "orderHash", "ignored", "same-nonce"] {
        assert!(required_str(cancel_effect, "effect").contains(phrase));
    }
    let epoch_effect = admitted
        .iter()
        .find(|route| route["canonical_signature"] == "increaseEpoch(uint96)")
        .expect("increaseEpoch semantic receipt");
    assert_eq!(
        epoch_effect["authenticated_actor"].as_str(),
        Some("msg.sender")
    );
    for phrase in ["exactly one", "invalidate", "activate", "next-epoch"] {
        assert!(required_str(epoch_effect, "effect").contains(phrase));
    }
}
