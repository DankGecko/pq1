//! Offline evidence and fail-closed compilation checks for the bounded
//! Flying Tulip EpochRewardsVault/MintAndRedeem slice tracked by PQ1 #497.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EPOCH_DEV: &str = "calldata-EpochRewardsVault-dev.json";
const EPOCH_PROD: &str = "calldata-EpochRewardsVault.json";
const MINT_DEV: &str = "calldata-MintAndRedeem-dev.json";
const MINT_PROD: &str = "calldata-MintAndRedeem.json";

const DEPOSIT: &str = "deposit(uint256,address)";
const WITHDRAW: &str = "withdraw(uint256,address,address)";
const CLAIM: &str = "claim(address)";
const MINT: &str = "mint(address,uint256,uint256,uint256)";
const REDEEM: &str = "redeem(address,uint256,uint256,uint256)";

const EPOCH_NAMED: [&str; 3] = [
    "deposit(uint256 assets, address receiver)",
    "withdraw(uint256 assets, address receiver, address owner)",
    "claim(address to)",
];
const MINT_NAMED: [&str; 2] = [
    "mint(address collateralToken, uint256 collateralAmount, uint256 txDeadline, uint256 minFtUSDOut)",
    "redeem(address collateralToken, uint256 ftUSDAmount, uint256 txDeadline, uint256 minCollateralOut)",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/flyingtulip-vault-mint")
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

fn address_word(text: &str) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&address(text));
    word
}

fn read_hex(path: &Path) -> Vec<u8> {
    let text =
        fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim()))
        .unwrap_or_else(|error| panic!("decode {}: {error}", path.display()))
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

fn descriptor(name: &str) -> Value {
    read_json(
        &workspace_root()
            .join("secure/data/erc7730/curations/files/registry/flyingtulip")
            .join(name),
    )
}

fn abi_signature(function: &Value) -> String {
    let name = required_str(function, "name");
    let types = function["inputs"]
        .as_array()
        .expect("ABI inputs")
        .iter()
        .map(|input| required_str(input, "type"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{name}({types})")
}

fn function_signatures(abi: &Value) -> BTreeMap<String, &Value> {
    abi.as_array()
        .expect("ABI array")
        .iter()
        .filter(|entry| entry["type"] == "function")
        .map(|entry| (abi_signature(entry), entry))
        .collect()
}

fn immutable_spans<'a>(compiler: &'a Value, id: &str) -> &'a Vec<Value> {
    compiler["deployed_bytecode"]["immutable_references"][id]
        .as_array()
        .unwrap_or_else(|| panic!("immutable reference {id}"))
}

fn mask_immutables(bytes: &mut [u8], compiler: &Value) {
    for spans in compiler["deployed_bytecode"]["immutable_references"]
        .as_object()
        .expect("immutable references")
        .values()
    {
        for span in spans.as_array().expect("immutable spans") {
            let start = span["start"].as_u64().expect("immutable start") as usize;
            let length = span["length"].as_u64().expect("immutable length") as usize;
            let end = start.checked_add(length).expect("immutable span end");
            assert!(end <= bytes.len(), "immutable span exceeds runtime");
            bytes[start..end].fill(0);
        }
    }
}

fn assert_immutable_address(runtime: &[u8], compiler: &Value, name: &str, expected: &str) {
    let id = compiler["immutable_bindings"][name]
        .as_str()
        .unwrap_or_else(|| panic!("immutable binding {name}"));
    let word = address_word(expected);
    let spans = immutable_spans(compiler, id);
    assert!(!spans.is_empty(), "{name} has no compiler spans");
    for span in spans {
        let start = span["start"].as_u64().expect("immutable start") as usize;
        let length = span["length"].as_u64().expect("immutable length") as usize;
        assert_eq!(length, 32, "{name} immutable width");
        assert_eq!(&runtime[start..start + length], &word, "{name} span drift");
    }
}

fn expected_routes(name: &str) -> BTreeSet<String> {
    match name {
        EPOCH_DEV | EPOCH_PROD => EPOCH_NAMED
            .iter()
            .map(|route| (*route).to_string())
            .collect(),
        MINT_DEV | MINT_PROD => MINT_NAMED
            .iter()
            .map(|route| (*route).to_string())
            .collect(),
        _ => panic!("unexpected descriptor {name}"),
    }
}

fn field_by_label<'a>(
    fields: &'a [pqsigner_erc7730::ir::FieldEntry<'a>],
    label: &[u8],
) -> &'a pqsigner_erc7730::ir::FieldEntry<'a> {
    fields
        .iter()
        .find(|field| field.label == label)
        .unwrap_or_else(|| panic!("missing field label {:?}", String::from_utf8_lossy(label)))
}

#[test]
fn flyingtulip_vault_mint_evidence_is_complete_and_runtime_bound() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert!(
        required_str(&manifest, "boundary").contains("No live reward"),
        "evidence boundary must remain explicit"
    );
    assert_eq!(
        manifest["descriptor_families"]
            .as_array()
            .expect("descriptor families")
            .iter()
            .map(|family| family["admitted_leaf_count"].as_u64().unwrap())
            .sum::<u64>(),
        10
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

    let official = fs::read_to_string(root.join("official/solver-integration.md"))
        .expect("official solver integration note");
    for fact in [
        "0xF7D85EC4E7710f71992752eac2111312e73E9C9C",
        "0xAa48EcBC843cF7E9A29155D112b8Cb27902bD23C",
        "0xeb48218a4c35C814C7678cBcae88C6Ee037F7625",
        "Use `0` for no deadline.",
        "fixed 1:1 share-to-asset ratio",
        "Flying Tulip USD        | ftUSD  | 6",
    ] {
        assert!(official.contains(fact), "official fact drifted: {fact}");
    }

    for source_name in ["EpochRewardsVault.prod.sol", "EpochRewardsVault.dev.sol"] {
        let source =
            fs::read_to_string(root.join("source").join(source_name)).expect("Epoch source");
        for fact in [
            "/// @notice Claim settled FT rewards.",
            "uint256 paidGross = claimable <= bal ? claimable : bal;",
            "FT.safeTransfer(to, paidToUser);",
            "function deposit(",
            "function withdraw(",
        ] {
            assert!(source.contains(fact), "{source_name} lost {fact}");
        }
    }
    for source_name in ["MintAndRedeem.prod.sol", "MintAndRedeem.dev.sol"] {
        let source =
            fs::read_to_string(root.join("source").join(source_name)).expect("Mint source");
        for fact in [
            "function mint(",
            "function redeem(",
            "if (txDeadline == 0) return;",
            "if (block.timestamp > txDeadline) revert TransactionExpired();",
            "if (ftUSDAmount < minFtUSDOut) revert SlippageExceeded",
            "if (collateralAmount < minCollateralOut)",
        ] {
            assert!(source.contains(fact), "{source_name} lost {fact}");
        }
    }

    let expected_epoch =
        BTreeSet::from([DEPOSIT.to_string(), WITHDRAW.to_string(), CLAIM.to_string()]);
    let expected_mint = BTreeSet::from([MINT.to_string(), REDEEM.to_string()]);
    for (file, expected_routes) in [
        ("abi/epoch-prod.abi.json", &expected_epoch),
        ("abi/epoch-dev.abi.json", &expected_epoch),
        ("abi/mint-prod.abi.json", &expected_mint),
        ("abi/mint-dev.abi.json", &expected_mint),
    ] {
        let abi = read_json(&root.join(file));
        let functions = function_signatures(&abi);
        for route in expected_routes {
            let function = functions
                .get(route)
                .unwrap_or_else(|| panic!("{file} missing {route}"));
            assert_eq!(function["stateMutability"], "nonpayable");
        }
    }

    let compiler_names = ["epoch-prod", "epoch-dev", "mint-prod", "mint-dev"];
    let compilers = compiler_names
        .into_iter()
        .map(|name| {
            let value = read_json(&root.join(format!("compiler/{name}.json")));
            assert_eq!(value["schema_version"].as_u64(), Some(1));
            assert_eq!(value["match"], "match");
            assert_eq!(value["runtime_match"], "match");
            assert_eq!(value["creation_match"], "match");
            assert_eq!(
                value["compilation"]["compilerVersion"],
                "0.8.30+commit.73712a01"
            );
            assert_eq!(value["compilation"]["compilerSettings"]["viaIR"], true);
            assert_eq!(
                value["compilation"]["compilerSettings"]["evmVersion"],
                "cancun"
            );
            assert_eq!(
                value["compilation"]["compilerSettings"]["optimizer"]["runs"].as_u64(),
                Some(200)
            );
            (name.to_string(), value)
        })
        .collect::<BTreeMap<_, _>>();

    let receipt = read_json(&root.join("rpc/fixed-block-receipt.json"));
    assert_eq!(receipt["schema_version"].as_u64(), Some(1));
    assert_eq!(
        required_str(&receipt, "eip1967_implementation_slot"),
        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    );
    let blocks = receipt["blocks"].as_array().expect("fixed blocks");
    assert_eq!(blocks.len(), 4);
    assert_eq!(
        blocks
            .iter()
            .map(|block| block["chain_id"].as_u64().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([1, 56, 146, 43_114])
    );
    for block in blocks {
        for key in ["hash", "state_root"] {
            let value = required_str(block, key);
            assert_eq!(value.len(), 66, "{key} width");
            assert!(value.starts_with("0x"), "{key} prefix");
        }
        assert!(
            required_str(block, "rpc_endpoint").starts_with("https://"),
            "RPC evidence endpoint"
        );
    }

    let deployments = receipt["deployments"]
        .as_array()
        .expect("deployment receipts");
    assert_eq!(deployments.len(), 10);
    let mut identities = BTreeSet::new();
    for deployment in deployments {
        let chain_id = deployment["chain_id"].as_u64().expect("chain ID");
        let proxy = required_str(deployment, "proxy");
        assert!(
            identities.insert((chain_id, proxy.to_string())),
            "duplicate deployment receipt"
        );
        let implementation = required_str(deployment, "implementation");
        assert_eq!(
            required_str(deployment, "implementation_slot_word"),
            format!(
                "0x{}{}",
                "0".repeat(24),
                implementation.trim_start_matches("0x")
            )
        );

        let proxy_runtime = read_hex(&root.join(required_str(deployment, "proxy_runtime")));
        assert!(!proxy_runtime.is_empty(), "proxy runtime must be pinned");
        let runtime = read_hex(&root.join(required_str(deployment, "implementation_runtime")));
        let compiler = &compilers[required_str(deployment, "verified_build")];
        let mut compiled = hex::decode(required_str(&compiler["deployed_bytecode"], "object"))
            .expect("compiled runtime template");
        assert_eq!(
            runtime.len(),
            compiled.len(),
            "runtime/template width changed for {chain_id} {proxy}"
        );
        let mut normalized_runtime = runtime.clone();
        mask_immutables(&mut normalized_runtime, compiler);
        mask_immutables(&mut compiled, compiler);
        assert_eq!(
            normalized_runtime, compiled,
            "runtime diverged outside compiler-declared immutables for {chain_id} {proxy}"
        );

        let config = &deployment["config"];
        if required_str(deployment, "variant").starts_with("epoch-") {
            assert_immutable_address(&runtime, compiler, "ASSET", required_str(config, "asset"));
            assert_immutable_address(&runtime, compiler, "FT", required_str(config, "ft_reward"));
            assert_immutable_address(
                &runtime,
                compiler,
                "yieldWrapper",
                required_str(config, "yield_wrapper"),
            );
            assert_eq!(config["asset_metadata"]["name"], "Flying Tulip USD");
            assert_eq!(config["asset_metadata"]["symbol"], "ftUSD");
            assert_eq!(config["asset_metadata"]["decimals"].as_u64(), Some(6));
            assert_eq!(config["reward_metadata"]["name"], "Flying Tulip");
            assert_eq!(config["reward_metadata"]["symbol"], "FT");
            assert_eq!(config["reward_metadata"]["decimals"].as_u64(), Some(18));
        } else {
            assert_immutable_address(&runtime, compiler, "ftUSD", required_str(config, "ftusd"));
            assert_eq!(config["ftusd_metadata"]["name"], "Flying Tulip USD");
            assert_eq!(config["ftusd_metadata"]["symbol"], "ftUSD");
            assert_eq!(config["ftusd_metadata"]["decimals"].as_u64(), Some(6));
        }
    }

    let production_ftusd = "0xf7d85ec4e7710f71992752eac2111312e73e9c9c";
    for deployment in deployments
        .iter()
        .filter(|deployment| required_str(deployment, "variant").ends_with("-prod"))
    {
        let config = &deployment["config"];
        let bound = config["asset"]
            .as_str()
            .or_else(|| config["ftusd"].as_str())
            .expect("production ftUSD binding");
        assert_eq!(bound, production_ftusd);
    }

    let inventory = read_json(
        &workspace_root().join("tests/erc7730-semantic-evidence/accepted-family-inventory.json"),
    );
    assert_eq!(
        inventory["catalogue_snapshot"]["category_source_counts"]["pinned-evidence"].as_u64(),
        Some(52)
    );
    assert_eq!(
        inventory["catalogue_snapshot"]["category_leaf_counts"]["pinned-evidence"].as_u64(),
        Some(176)
    );
    let promoted = inventory["families"]
        .as_array()
        .expect("accepted-family records")
        .iter()
        .filter(|family| {
            matches!(
                required_str(family, "source"),
                "flyingtulip/calldata-EpochRewardsVault-dev.json"
                    | "flyingtulip/calldata-EpochRewardsVault.json"
                    | "flyingtulip/calldata-MintAndRedeem-dev.json"
                    | "flyingtulip/calldata-MintAndRedeem.json"
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(promoted.len(), 4);
    assert_eq!(
        promoted
            .iter()
            .map(|family| family["accepted_leaf_count"].as_u64().unwrap())
            .sum::<u64>(),
        10
    );
    for family in promoted {
        assert_eq!(family["classification"], "pinned-evidence");
        assert_eq!(family["evidence"], "flyingtulip-vault-mint");
        assert!(family.get("successor_issue").is_none());
    }
}

#[test]
fn flyingtulip_vault_mint_curations_compile_only_the_evidenced_routes() {
    let root = workspace_root();
    let files = [EPOCH_DEV, EPOCH_PROD, MINT_DEV, MINT_PROD];
    let receipt = read_json(&evidence_root().join("rpc/fixed-block-receipt.json"));
    let receipt_deployments = receipt["deployments"]
        .as_array()
        .expect("deployment receipts");

    for name in files {
        let curated = root
            .join("secure/data/erc7730/curations/files/registry/flyingtulip")
            .join(name);
        let installed = root
            .join("secure/data/erc7730-registry/registry/flyingtulip")
            .join(name);
        assert_eq!(
            fs::read(&curated).expect("curated descriptor"),
            fs::read(&installed).expect("installed descriptor"),
            "installed descriptor diverged from curation: {name}"
        );

        let descriptor = descriptor(name);
        let note = required_str(&descriptor, "_curation_note");
        for boundary in ["fixed-block", "future proxy", "blind signing"] {
            assert!(
                note.contains(boundary),
                "{name} curation note lost {boundary}"
            );
        }
        let formats = descriptor["display"]["formats"]
            .as_object()
            .expect("display formats");
        let expected = expected_routes(name);
        assert_eq!(
            formats.keys().cloned().collect::<BTreeSet<_>>(),
            expected,
            "descriptor format set changed: {name}"
        );

        let context = descriptor["context"]["contract"]["deployments"]
            .as_array()
            .expect("context deployments");
        let allowlists = descriptor["_pqsigner"]["deploymentFormats"]
            .as_array()
            .expect("deployment format allowlists");
        assert_eq!(context.len(), allowlists.len());
        let context_set = context
            .iter()
            .map(|deployment| {
                (
                    deployment["chainId"].as_u64().unwrap(),
                    required_str(deployment, "address").to_ascii_lowercase(),
                )
            })
            .collect::<BTreeSet<_>>();
        let allowlist_set = allowlists
            .iter()
            .map(|deployment| {
                assert_eq!(
                    deployment["formats"]
                        .as_array()
                        .expect("allowed formats")
                        .iter()
                        .map(|format| format.as_str().unwrap().to_string())
                        .collect::<BTreeSet<_>>(),
                    expected
                );
                (
                    deployment["chainId"].as_u64().unwrap(),
                    required_str(deployment, "address").to_ascii_lowercase(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(context_set, allowlist_set);

        let source_path = format!("flyingtulip/{name}");
        let evidence_set = receipt_deployments
            .iter()
            .filter(|deployment| deployment["descriptor"] == source_path)
            .map(|deployment| {
                (
                    deployment["chain_id"].as_u64().unwrap(),
                    required_str(deployment, "proxy").to_string(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(context_set, evidence_set, "evidence deployment set: {name}");
    }

    for name in [EPOCH_DEV, EPOCH_PROD] {
        let descriptor = descriptor(name);
        let formats = &descriptor["display"]["formats"];
        let claim = &formats[EPOCH_NAMED[2]];
        assert_eq!(claim["intent"], "Claim FT rewards");
        assert_eq!(claim["interpolatedIntent"], "Claim FT to {to}");
        assert!(claim["fields"].as_array().unwrap().iter().any(|field| {
            field["label"] == "FT amount"
                && field["value"] == "Computed on-chain"
                && field["format"] == "raw"
                && field["visible"] == "always"
        }));
        if name == EPOCH_DEV {
            for route in &EPOCH_NAMED[..2] {
                assert_eq!(formats[*route]["fields"][0]["label"], "ftUSD base units");
                assert_eq!(formats[*route]["fields"][0]["format"], "raw");
            }
        } else {
            for route in &EPOCH_NAMED[..2] {
                assert_eq!(formats[*route]["fields"][0]["format"], "tokenAmount");
                assert_eq!(
                    formats[*route]["fields"][0]["params"]["token"],
                    "0xF7D85EC4E7710f71992752eac2111312e73E9C9C"
                );
            }
        }
    }

    for name in [MINT_DEV, MINT_PROD] {
        let descriptor = descriptor(name);
        let formats = &descriptor["display"]["formats"];
        for route in MINT_NAMED {
            assert!(formats[route]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| {
                    field["label"] == "Deadline rule"
                        && field["value"] == "0 means no expiry"
                        && field["format"] == "raw"
                        && field["visible"] == "always"
                }));
        }
        if name == MINT_DEV {
            assert_eq!(
                formats[MINT_NAMED[0]]["fields"][1]["label"],
                "Min ftUSD base units"
            );
            assert_eq!(formats[MINT_NAMED[0]]["fields"][1]["format"], "raw");
            assert_eq!(
                formats[MINT_NAMED[1]]["fields"][0]["label"],
                "ftUSD base units"
            );
            assert_eq!(formats[MINT_NAMED[1]]["fields"][0]["format"], "raw");
        }
    }

    let registry = build_registry();
    let expectations = [
        (
            EPOCH_DEV,
            3usize,
            BTreeSet::from([selector(DEPOSIT), selector(WITHDRAW), selector(CLAIM)]),
        ),
        (
            EPOCH_PROD,
            2usize,
            BTreeSet::from([selector(DEPOSIT), selector(WITHDRAW), selector(CLAIM)]),
        ),
        (
            MINT_DEV,
            3usize,
            BTreeSet::from([selector(MINT), selector(REDEEM)]),
        ),
        (
            MINT_PROD,
            2usize,
            BTreeSet::from([selector(MINT), selector(REDEEM)]),
        ),
    ];
    for (name, count, expected_selectors) in expectations {
        let entries = registry
            .entries
            .iter()
            .filter(|entry| entry.source.file_name().and_then(|file| file.to_str()) == Some(name))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), count, "accepted leaf count changed: {name}");
        for entry in entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse Flying Tulip IR");
            assert_eq!(
                cross_check_contract(&ir, entry.chain_id, &entry.contract),
                Ok(())
            );
            assert_eq!(
                ir.format_iter()
                    .map(|format| format.expect("valid format").selector)
                    .collect::<BTreeSet<_>>(),
                expected_selectors,
                "unexpected admitted selector set: {name}"
            );

            for route_selector in &expected_selectors {
                assert!(
                    registry.known_calls.contains(&(
                        entry.chain_id,
                        entry.contract,
                        *route_selector
                    )),
                    "accepted route left exact known-call set"
                );
                assert!(
                    known_call_may_contain(
                        &registry.known_calls_bloom,
                        entry.chain_id,
                        &entry.contract,
                        route_selector
                    ),
                    "accepted route left fail-closed known-call Bloom"
                );
            }

            if name.starts_with("calldata-EpochRewardsVault") {
                let claim = ir
                    .find_format_by_selector(&selector(CLAIM))
                    .expect("claim format table")
                    .expect("claim format");
                assert_eq!(claim.intent, b"Claim FT rewards");
                let fields = claim
                    .fields()
                    .map(|field| field.expect("claim field"))
                    .collect::<Vec<_>>();
                assert_eq!(fields.len(), 2);
                let amount = field_by_label(&fields, b"FT amount");
                assert_eq!(amount.path_off, 0);
                assert_eq!(FormatOp::try_from(amount.format_op), Ok(FormatOp::Raw));
                let params = parse_params(&ir, amount.param_off).expect("FT amount params");
                assert_eq!(params.terminal_kind, Some(TerminalKind::ConstantText));
                assert_eq!(params.const_value, Some(b"Computed on-chain".as_slice()));
            } else {
                for route_selector in [selector(MINT), selector(REDEEM)] {
                    let format = ir
                        .find_format_by_selector(&route_selector)
                        .expect("mint format table")
                        .expect("mint format");
                    let fields = format
                        .fields()
                        .map(|field| field.expect("mint field"))
                        .collect::<Vec<_>>();
                    assert_eq!(fields.len(), 4);
                    let warning = field_by_label(&fields, b"Deadline rule");
                    assert_eq!(warning.path_off, 0);
                    assert_eq!(FormatOp::try_from(warning.format_op), Ok(FormatOp::Raw));
                    let params =
                        parse_params(&ir, warning.param_off).expect("deadline warning params");
                    assert_eq!(params.terminal_kind, Some(TerminalKind::ConstantText));
                    assert_eq!(params.const_value, Some(b"0 means no expiry".as_slice()));
                }
            }
        }
    }
}
