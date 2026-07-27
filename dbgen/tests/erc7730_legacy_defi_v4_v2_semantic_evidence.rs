//! Offline deployment and semantic evidence for the bounded legacy-DeFi slice.
//!
//! This binds one 1inch V4 deployment and three Aave V2 Pool proxies at fixed
//! historical blocks to the exact static routes admitted by PQ1. It grants no
//! authority for future upgrades, omitted dynamic/permit routes, or blind
//! signing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, Visibility};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ONEINCH_DESCRIPTOR: &str = "registry/1inch/calldata-AggregationRouterV4-eth.json";
const AAVE_DESCRIPTOR: &str = "registry/aave/calldata-lpv2.json";
const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const ONEINCH_NAMED_ROUTES: [&str; 2] = [
    "clipperSwap(address srcToken, address dstToken, uint256 amount, uint256 minReturn)",
    "clipperSwapTo(address recipient, address srcToken, address dstToken, uint256 amount, uint256 minReturn)",
];
const ONEINCH_CANONICAL_ROUTES: [&str; 2] = [
    "clipperSwap(address,address,uint256,uint256)",
    "clipperSwapTo(address,address,address,uint256,uint256)",
];
const ONEINCH_PERMIT: &str =
    "clipperSwapToWithPermit(address,address,address,uint256,uint256,bytes)";
const ONEINCH_AGGREGATION: &str =
    "swap(address,(address,address,address,address,uint256,uint256,uint256,bytes),bytes)";

const AAVE_NAMED_ROUTES: [&str; 6] = [
    "repay(address asset, uint256 amount, uint256 rateMode, address onBehalfOf)",
    "setUserUseReserveAsCollateral(address asset, bool useAsCollateral)",
    "withdraw(address asset, uint256 amount, address to)",
    "swapBorrowRateMode(address asset, uint256 rateMode)",
    "borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf)",
    "deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)",
];
const AAVE_CANONICAL_ROUTES: [&str; 6] = [
    "borrow(address,uint256,uint256,uint16,address)",
    "deposit(address,uint256,address,uint16)",
    "repay(address,uint256,uint256,address)",
    "setUserUseReserveAsCollateral(address,bool)",
    "swapBorrowRateMode(address,uint256)",
    "withdraw(address,uint256,address)",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/legacy-defi-v4-v2")
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
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid archived hex")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn abi_word_address(value: &Value) -> [u8; 20] {
    let word = decode_hex(value.as_str().expect("ABI address word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..12], &[0u8; 12], "address word has nonzero padding");
    word[12..].try_into().expect("address width")
}

fn abi_word_u64(value: &Value) -> u64 {
    let word = decode_hex(value.as_str().expect("ABI integer word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..24], &[0u8; 24], "integer exceeds u64");
    u64::from_be_bytes(word[24..].try_into().expect("u64 word"))
}

fn hex_u64(value: &Value) -> u64 {
    let text = value.as_str().expect("hex quantity");
    u64::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).expect("valid quantity")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("selector width")
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
                .expect("path stays below evidence root")
                .to_str()
                .expect("UTF-8 evidence path")
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn rpc_results(path: &Path) -> BTreeMap<u64, Value> {
    let mut results = BTreeMap::new();
    for item in read_json(path).as_array().expect("RPC response array") {
        assert!(
            item.get("error").is_none(),
            "RPC error in {}",
            path.display()
        );
        let id = item["id"].as_u64().expect("numeric RPC id");
        assert!(
            results.insert(id, item["result"].clone()).is_none(),
            "duplicate RPC id"
        );
    }
    results
}

fn response(root: &Path, directory: &str, provider: &str, batch: &str) -> BTreeMap<u64, Value> {
    rpc_results(
        &root
            .join("rpc/raw")
            .join(directory)
            .join(format!("response-{provider}-{batch}.json")),
    )
}

fn normalized_source(value: &Value) -> String {
    value["sources"]
        .as_object()
        .expect("verified sources")
        .values()
        .map(|source| required_str(source, "content"))
        .collect::<Vec<_>>()
        .join("\n")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn routescan_source(value: &Value) -> String {
    let wrapped = required_str(&value["result"][0], "SourceCode");
    assert!(
        wrapped.starts_with("{{") && wrapped.ends_with("}}"),
        "Routescan standard-json wrapper changed"
    );
    let standard: Value =
        serde_json::from_str(&wrapped[1..wrapped.len() - 1]).expect("Routescan standard JSON");
    normalized_source(&standard)
}

fn abi_signatures(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("ABI array")
        .iter()
        .map(|entry| {
            let types = entry["inputs"]
                .as_array()
                .expect("ABI inputs")
                .iter()
                .map(|input| required_str(input, "type"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{}({types})", required_str(entry, "name"))
        })
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
fn legacy_defi_evidence_is_complete_and_cross_provider_bound() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        required_str(&manifest, "issue"),
        "https://github.com/EthereumPhone/PQ1/issues/497"
    );
    assert_eq!(
        required_str(&manifest, "eip1967_implementation_slot"),
        IMPLEMENTATION_SLOT
    );

    let receipts = manifest["artifacts"].as_array().expect("artifact receipts");
    let receipted = receipts
        .iter()
        .map(|receipt| required_str(receipt, "path").to_string())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut actual);
    assert_eq!(receipted, actual, "evidence inventory changed");
    for receipt in receipts {
        let path = evidence.join(required_str(receipt, "path"));
        assert_eq!(
            sha256_hex(&fs::read(&path).expect("read receipted artifact")),
            required_str(receipt, "sha256"),
            "evidence hash changed: {}",
            path.display()
        );
    }

    let oneinch = &manifest["oneinch"];
    let oneinch_a = response(&evidence, "oneinch-ethereum", "drpc", "identity");
    let oneinch_b = response(&evidence, "oneinch-ethereum", "mevblocker", "identity");
    assert_eq!(oneinch_a, oneinch_b, "1inch identity providers disagree");
    assert_eq!(hex_u64(&oneinch_a[&1]), 1);
    let block = &oneinch_a[&2];
    assert_eq!(
        required_str(block, "number"),
        required_str(oneinch, "block_number_hex")
    );
    for key in ["hash", "parentHash", "stateRoot", "timestamp"] {
        let manifest_key = match key {
            "parentHash" => "parent_hash",
            "stateRoot" => "state_root",
            "timestamp" => "timestamp_hex",
            _ => "block_hash",
        };
        assert_eq!(
            required_str(block, key),
            required_str(oneinch, manifest_key)
        );
    }
    assert_eq!(
        decode_hex(oneinch_a[&3].as_str().expect("implementation slot")),
        vec![0u8; 32],
        "AggregationRouterV4 unexpectedly occupies the EIP-1967 slot"
    );
    let oneinch_runtime_a = response(&evidence, "oneinch-ethereum", "drpc", "runtime");
    let oneinch_runtime_b = response(&evidence, "oneinch-ethereum", "mevblocker", "runtime");
    assert_eq!(oneinch_runtime_a, oneinch_runtime_b);
    let oneinch_runtime = read_hex(&evidence.join(required_str(oneinch, "runtime")));
    assert_eq!(
        decode_hex(oneinch_runtime_a[&4].as_str().unwrap()),
        oneinch_runtime
    );

    let oneinch_verified = read_json(&evidence.join(required_str(oneinch, "verification")));
    assert_eq!(
        required_str(&oneinch_verified, "address"),
        required_str(oneinch, "address")
    );
    assert_eq!(required_str(&oneinch_verified, "chainId"), "1");
    assert_eq!(oneinch_verified["proxyResolution"]["isProxy"], false);
    assert_eq!(
        decode_hex(required_str(
            &oneinch_verified["runtimeBytecode"],
            "onchainBytecode"
        )),
        oneinch_runtime
    );
    assert_eq!(
        oneinch_verified["compilation"]["name"],
        "AggregationRouterV4"
    );
    let oneinch_source = normalized_source(&oneinch_verified);
    for fragment in [
        "contract ClipperRouter is EthReceiver, Permitable",
        "IERC20 private constant _ETH = IERC20(address(0));",
        "return clipperSwapTo(msg.sender, srcToken, dstToken, amount, minReturn);",
        "if (srcToken == _WETH)",
        "else if (srcToken == _ETH)",
        "else if (dstToken == _WETH)",
        "else if (dstToken == _ETH)",
        "_permit(address(srcToken), permit);",
    ] {
        assert!(
            oneinch_source.contains(fragment),
            "verified 1inch source lost `{fragment}`"
        );
    }
    assert_eq!(
        abi_signatures(&read_json(
            &evidence.join("abi/AggregationRouterV4.clipper.abi.json")
        )),
        BTreeSet::from([
            ONEINCH_CANONICAL_ROUTES[0].to_string(),
            ONEINCH_CANONICAL_ROUTES[1].to_string(),
            ONEINCH_PERMIT.to_string(),
        ])
    );

    let address_book = ["Ethereum", "Polygon", "Avalanche"]
        .iter()
        .map(|network| {
            fs::read_to_string(evidence.join(format!("source/AaveV2{network}.sol")))
                .expect("Aave address-book source")
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    let mut reference_abi: Option<Value> = None;
    for deployment in manifest["aave"]["deployments"]
        .as_array()
        .expect("Aave deployments")
    {
        let slug = required_str(deployment, "slug");
        let providers = deployment["providers"].as_array().expect("RPC providers");
        let first = required_str(&providers[0], "name");
        let second = required_str(&providers[1], "name");
        let directory = format!("aave-{slug}");
        let identity_a = response(&evidence, &directory, first, "identity");
        let identity_b = response(&evidence, &directory, second, "identity");
        assert_eq!(identity_a[&1], identity_b[&1], "{slug} chain IDs disagree");
        assert_eq!(
            identity_a[&3], identity_b[&3],
            "{slug} implementation slots disagree"
        );
        for field in ["number", "hash", "parentHash", "stateRoot", "timestamp"] {
            assert_eq!(
                identity_a[&2][field], identity_b[&2][field],
                "{slug} canonical block field {field} disagrees"
            );
        }
        assert_eq!(
            hex_u64(&identity_a[&1]),
            deployment["chain_id"].as_u64().unwrap()
        );
        let block = &identity_a[&2];
        assert_eq!(
            required_str(block, "number"),
            required_str(deployment, "block_number_hex")
        );
        assert_eq!(
            required_str(block, "hash"),
            required_str(deployment, "block_hash")
        );
        assert_eq!(
            required_str(block, "parentHash"),
            required_str(deployment, "parent_hash")
        );
        assert_eq!(
            required_str(block, "stateRoot"),
            required_str(deployment, "state_root")
        );
        assert_eq!(
            required_str(block, "timestamp"),
            required_str(deployment, "timestamp_hex")
        );
        assert_eq!(
            abi_word_address(&identity_a[&3]),
            address(required_str(deployment, "implementation"))
        );

        let links_a = response(&evidence, &directory, first, "links");
        let links_b = response(&evidence, &directory, second, "links");
        assert_eq!(links_a, links_b, "{slug} link providers disagree");
        assert_eq!(
            abi_word_address(&links_a[&6]),
            address(required_str(deployment, "addresses_provider"))
        );
        assert_eq!(
            abi_word_u64(&links_a[&7]),
            deployment["revision"].as_u64().unwrap()
        );
        assert_eq!(
            abi_word_address(&links_a[&8]),
            address(required_str(deployment, "proxy"))
        );

        let runtime_a = response(&evidence, &directory, first, "runtime");
        let runtime_b = response(&evidence, &directory, second, "runtime");
        assert_eq!(runtime_a, runtime_b, "{slug} runtime providers disagree");
        let proxy_runtime = read_hex(&evidence.join(format!("runtime/AaveV2PoolProxy.{slug}.hex")));
        let implementation_runtime =
            read_hex(&evidence.join(format!("runtime/AaveV2PoolImplementation.{slug}.hex")));
        assert_eq!(decode_hex(runtime_a[&4].as_str().unwrap()), proxy_runtime);
        assert_eq!(
            decode_hex(runtime_a[&5].as_str().unwrap()),
            implementation_runtime
        );

        let proxy = read_json(&evidence.join(required_str(deployment, "proxy_verification")));
        assert_eq!(
            required_str(&proxy, "address"),
            required_str(deployment, "proxy")
        );
        assert_eq!(proxy["proxyResolution"]["isProxy"], true);
        assert_eq!(proxy["proxyResolution"]["proxyType"], "EIP1967Proxy");
        assert_eq!(
            required_str(&proxy["proxyResolution"]["implementations"][0], "address"),
            required_str(deployment, "implementation")
        );
        assert_eq!(
            decode_hex(required_str(&proxy["runtimeBytecode"], "onchainBytecode")),
            proxy_runtime
        );

        let (verified_source, route_abi) = if slug == "avalanche" {
            let verification =
                read_json(&evidence.join(required_str(deployment, "implementation_verification")));
            assert_eq!(verification["status"], "1");
            assert_eq!(verification["message"], "OK");
            assert_eq!(verification["result"][0]["ContractName"], "LendingPool");
            assert_eq!(verification["result"][0]["Proxy"], "0");
            (
                routescan_source(&verification),
                read_json(&evidence.join("abi/AaveV2.routes.avalanche.abi.json")),
            )
        } else {
            let verification =
                read_json(&evidence.join(required_str(deployment, "implementation_verification")));
            assert_eq!(
                required_str(&verification, "address"),
                required_str(deployment, "implementation")
            );
            assert_eq!(verification["compilation"]["name"], "LendingPool");
            assert_eq!(
                decode_hex(required_str(
                    &verification["runtimeBytecode"],
                    "onchainBytecode"
                )),
                implementation_runtime
            );
            (
                normalized_source(&verification),
                read_json(&evidence.join(format!("abi/AaveV2.routes.{slug}.abi.json"))),
            )
        };
        for fragment in [
            "function deposit(",
            "emit Deposit(asset, msg.sender, onBehalfOf, amount, referralCode);",
            "function borrow(",
            "function repay(",
            "function withdraw(",
            "function setUserUseReserveAsCollateral(",
            "function swapBorrowRateMode(address asset, uint256 rateMode)",
            "if (interestRateMode == DataTypes.InterestRateMode.STABLE)",
            "IStableDebtToken(reserve.stableDebtTokenAddress).burn(msg.sender, stableDebt);",
            "IVariableDebtToken(reserve.variableDebtTokenAddress).mint(",
            "IVariableDebtToken(reserve.variableDebtTokenAddress).burn(",
            "IStableDebtToken(reserve.stableDebtTokenAddress).mint(",
        ] {
            assert!(
                verified_source.contains(fragment),
                "{slug} verified source lost `{fragment}`"
            );
        }
        assert_eq!(
            abi_signatures(&route_abi),
            AAVE_CANONICAL_ROUTES
                .iter()
                .map(|route| route.to_string())
                .collect(),
            "{slug} route ABI changed"
        );
        if let Some(reference) = &reference_abi {
            assert_eq!(&route_abi, reference, "{slug} ABI semantics diverged");
        } else {
            reference_abi = Some(route_abi);
        }

        for expected in [
            required_str(deployment, "proxy"),
            required_str(deployment, "implementation"),
            required_str(deployment, "addresses_provider"),
        ] {
            assert!(
                address_book.contains(&expected.to_ascii_lowercase()),
                "official address book lost {slug} address {expected}"
            );
        }
    }
}

#[test]
fn legacy_defi_curations_admit_only_evidenced_routes_and_keep_siblings_known() {
    let root = workspace_root();
    for relative in [ONEINCH_DESCRIPTOR, AAVE_DESCRIPTOR] {
        let installed = fs::read(root.join("secure/data/erc7730-registry").join(relative))
            .expect("installed descriptor");
        let curated = fs::read(
            root.join("secure/data/erc7730/curations/files")
                .join(relative),
        )
        .expect("curated descriptor");
        assert_eq!(
            installed, curated,
            "installed curation diverged: {relative}"
        );
        let manifest = read_json(&root.join("secure/data/erc7730/curations/manifest.json"));
        let replacement = manifest["replacements"]
            .as_array()
            .expect("curation replacements")
            .iter()
            .find(|entry| entry["path"].as_str() == Some(relative))
            .unwrap_or_else(|| panic!("missing replacement receipt: {relative}"));
        assert_eq!(
            required_str(replacement, "replacement_sha256"),
            sha256_hex(&curated)
        );
        assert_eq!(
            replacement["replacement_bytes"].as_u64(),
            Some(curated.len() as u64)
        );
    }

    let oneinch_descriptor = read_json(
        &root
            .join("secure/data/erc7730-registry")
            .join(ONEINCH_DESCRIPTOR),
    );
    assert_eq!(
        oneinch_descriptor["_pqsigner"]["deploymentFormats"][0]["formats"],
        json!(ONEINCH_NAMED_ROUTES)
    );
    let oneinch_note = required_str(&oneinch_descriptor, "_curation_note");
    assert!(oneinch_note.contains("not the shared 0xEeee sentinel"));
    assert!(oneinch_note.contains("exact known-call refusal"));
    let permit = &oneinch_descriptor["display"]["formats"]
        ["clipperSwapToWithPermit(address recipient, address srcToken, address dstToken, uint256 amount, uint256 minReturn, bytes permit)"];
    assert_eq!(permit["intent"], "Unsupported Clipper permit swap");
    assert!(
        permit["fields"]
            .as_array()
            .expect("permit fields")
            .iter()
            .all(|field| field["visible"] == "always"),
        "the refusal-only format must not normalize hidden authority"
    );
    for signature in ONEINCH_NAMED_ROUTES {
        let fields = oneinch_descriptor["display"]["formats"][signature]["fields"]
            .as_array()
            .expect("Clipper fields");
        for field in fields
            .iter()
            .filter(|field| matches!(field["path"].as_str(), Some("amount" | "minReturn")))
        {
            assert_eq!(
                field["params"]["nativeCurrencyAddress"],
                json!(["$.metadata.constants.addressAsNull"])
            );
        }
    }

    let aave_descriptor = read_json(
        &root
            .join("secure/data/erc7730-registry")
            .join(AAVE_DESCRIPTOR),
    );
    let allowlists = aave_descriptor["_pqsigner"]["deploymentFormats"]
        .as_array()
        .expect("Aave deployment allowlists");
    assert_eq!(allowlists.len(), 3);
    assert_eq!(
        allowlists
            .iter()
            .map(|entry| entry["chainId"].as_u64().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 137, 43_114])
    );
    for allowlist in allowlists {
        assert_eq!(allowlist["formats"], json!(AAVE_NAMED_ROUTES));
    }
    let formats = &aave_descriptor["display"]["formats"];
    assert_eq!(
        formats["swapBorrowRateMode(address asset, uint256 rateMode)"]["intent"],
        "Swap borrow rate mode"
    );
    for signature in [
        "borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf)",
        "deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)",
    ] {
        let referral = formats[signature]["fields"]
            .as_array()
            .expect("Aave fields")
            .iter()
            .find(|field| field["path"] == "referralCode")
            .expect("visible referral code");
        assert_eq!(referral["format"], "raw");
        assert_eq!(referral["visible"], "always");
    }

    let catalogue = build_registry();
    let oneinch_entries = catalogue
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-AggregationRouterV4-eth.json")
        })
        .collect::<Vec<_>>();
    assert_eq!(oneinch_entries.len(), 1);
    let oneinch_entry = oneinch_entries[0];
    let oneinch_contract = address("0x1111111254fb6c44bAC0beD2854e76F90643097d");
    assert_eq!(oneinch_entry.chain_id, 1);
    assert_eq!(oneinch_entry.contract, oneinch_contract);
    let oneinch_ir = Erc7730Ir::parse(&oneinch_entry.ir_bytes).expect("1inch IR");
    assert_eq!(
        cross_check_contract(&oneinch_ir, 1, &oneinch_contract),
        Ok(())
    );
    let admitted = oneinch_ir
        .format_iter()
        .map(|format| format.expect("1inch format").selector)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        admitted,
        ONEINCH_CANONICAL_ROUTES
            .iter()
            .map(|route| selector(route))
            .collect()
    );
    for route in ONEINCH_CANONICAL_ROUTES {
        let format = oneinch_ir
            .find_format_by_selector(&selector(route))
            .expect("format table")
            .expect("admitted Clipper route");
        let token_amounts = format
            .fields()
            .map(|field| field.expect("Clipper field"))
            .filter(|field| FormatOp::try_from(field.format_op) == Ok(FormatOp::TokenAmount))
            .collect::<Vec<_>>();
        assert_eq!(token_amounts.len(), 2);
        for field in token_amounts {
            let params = parse_params(&oneinch_ir, field.param_off).expect("token params");
            assert_eq!(params.native_currency_addresses, Some(&[0u8; 20][..]));
            assert_eq!(params.visibility, Visibility::Always);
        }
    }
    for refused in [ONEINCH_PERMIT, ONEINCH_AGGREGATION] {
        let refused_selector = selector(refused);
        assert!(
            oneinch_ir
                .find_format_by_selector(&refused_selector)
                .expect("format table")
                .is_none(),
            "{refused} must not render"
        );
        assert!(
            catalogue
                .known_calls
                .contains(&(1, oneinch_contract, refused_selector)),
            "{refused} left exact known-call inventory"
        );
        assert!(known_call_may_contain(
            &catalogue.known_calls_bloom,
            1,
            &oneinch_contract,
            &refused_selector
        ));
    }

    let aave_entries = catalogue
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-lpv2.json")
        })
        .collect::<Vec<_>>();
    assert_eq!(aave_entries.len(), 3);
    assert_eq!(
        aave_entries
            .iter()
            .map(|entry| entry.chain_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 137, 43_114])
    );
    for entry in aave_entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("Aave V2 IR");
        assert_eq!(
            cross_check_contract(&ir, entry.chain_id, &entry.contract),
            Ok(())
        );
        assert_eq!(
            ir.format_iter()
                .map(|format| format.expect("Aave format").selector)
                .collect::<BTreeSet<_>>(),
            AAVE_CANONICAL_ROUTES
                .iter()
                .map(|route| selector(route))
                .collect()
        );
        let swap = ir
            .find_format_by_selector(&selector("swapBorrowRateMode(address,uint256)"))
            .expect("format table")
            .expect("rate-mode swap");
        assert_eq!(swap.intent, b"Swap borrow rate mode");
        for signature in AAVE_CANONICAL_ROUTES {
            let route_selector = selector(signature);
            assert!(
                catalogue
                    .known_calls
                    .contains(&(entry.chain_id, entry.contract, route_selector)),
                "Aave admitted route left exact known-call inventory: {signature}"
            );
        }
    }
}
