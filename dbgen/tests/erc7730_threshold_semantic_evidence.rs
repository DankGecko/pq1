//! Offline evidence and fail-closed compilation checks for the bounded
//! Threshold Network calldata slice tracked by PQ1 issue #497.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::Erc7730Ir;
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::enums::lookup_enum_label;
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const GATEWAY_FILE: &str = "calldata-L2WormholeGateway.json";
const REBATE_FILE: &str = "calldata-RebateStaking.json";
const VAULT_FILE: &str = "calldata-TBTCVault.json";

const SEND_TBTC: &str = "sendTbtc(uint256,uint16,bytes32,uint256,uint32)";
const RECEIVE_TBTC: &str = "receiveTbtc(bytes)";
const SEND_TBTC_PAYLOAD: &str =
    "sendTbtcWithPayloadToNativeChain(uint256,uint16,bytes32,uint32,bytes)";
const REBATE_ROUTES: [&str; 5] = [
    "finalizeUnstaking(address)",
    "setDelegatee(address)",
    "setRebateTreasuryFeeMode(uint8)",
    "stake(uint96)",
    "startUnstaking(uint96)",
];
const VAULT_ROUTES: [&str; 2] = [
    "finalizeOptimisticMint(bytes32,uint32)",
    "requestOptimisticMint(bytes32,uint32)",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/threshold")
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

fn pinned_wormhole_chains() -> BTreeMap<u64, String> {
    let source = fs::read_to_string(evidence_root().join("source/wormhole-chains.ts"))
        .expect("read pinned Wormhole chain-ID source");
    let table = source
        .split_once("const chainIdAndChainEntries = [")
        .expect("Wormhole chain table start")
        .1
        .split_once("] as const")
        .expect("Wormhole chain table end")
        .0;
    let mut chains = BTreeMap::new();
    for line in table.lines().map(str::trim) {
        let Some(entry) = line.strip_prefix('[') else {
            continue;
        };
        let (chain_id, label) = entry
            .split_once(',')
            .expect("Wormhole chain entry separates ID and label");
        let chain_id = chain_id
            .trim()
            .parse::<u64>()
            .expect("Wormhole chain ID is an integer");
        let label = label
            .split('"')
            .nth(1)
            .expect("Wormhole chain label is quoted");
        assert!(
            chains.insert(chain_id, label.to_string()).is_none(),
            "duplicate Wormhole chain ID {chain_id}"
        );
    }
    assert_eq!(chains.len(), 64, "pinned Wormhole chain inventory changed");
    chains
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
            .join("secure/data/erc7730/curations/files/registry/threshold")
            .join(name),
    )
}

fn visible_paths(format: &Value) -> BTreeSet<String> {
    format["fields"]
        .as_array()
        .expect("format fields")
        .iter()
        .filter_map(|field| field["path"].as_str())
        .map(ToOwned::to_owned)
        .collect()
}

fn assert_two_provider_receipt(value: &Value) {
    let endpoints = value["rpc_endpoints"].as_array().expect("RPC endpoints");
    assert_eq!(endpoints.len(), 2, "two independent RPC endpoints");
    assert_ne!(endpoints[0], endpoints[1]);
    let corroborated = value["evidence_block"]["independently_corroborated_by"]
        .as_array()
        .expect("block corroboration");
    assert_eq!(corroborated, endpoints);
    for key in ["hash", "state_root"] {
        let text = required_str(&value["evidence_block"], key);
        assert_eq!(text.len(), 66, "{key} width");
        assert!(text.starts_with("0x"), "{key} prefix");
    }
}

#[test]
fn threshold_evidence_is_complete_and_cross_provider_bound() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert!(
        required_str(&manifest, "boundary").contains("No live state"),
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

    assert_eq!(
        fs::read_to_string(root.join("source/threshold-commit.txt"))
            .expect("threshold commit")
            .trim(),
        required_str(&manifest["upstream"]["threshold"], "commit")
    );
    assert_eq!(
        fs::read_to_string(root.join("source/wormhole-sdk-ts-commit.txt"))
            .expect("Wormhole SDK commit")
            .trim(),
        required_str(&manifest["upstream"]["wormhole_sdk_ts"], "commit")
    );

    let receipt = read_json(&root.join("rpc/fixed-block-receipt.json"));
    let gateways = receipt["l2_wormhole_gateways"]
        .as_array()
        .expect("gateway receipts");
    assert_eq!(gateways.len(), 7);
    for gateway in gateways {
        assert_two_provider_receipt(gateway);
        assert_eq!(gateway["tbtc_metadata"]["symbol"], "tBTC");
        assert_eq!(gateway["tbtc_metadata"]["decimals"].as_u64(), Some(18));
        assert_eq!(
            required_str(gateway, "implementation"),
            format!(
                "0x{}",
                &required_str(gateway, "eip1967_implementation_slot")[26..]
            )
        );
    }

    let rebate = &receipt["rebate_staking"];
    assert_two_provider_receipt(rebate);
    assert_eq!(rebate["token_metadata"]["name"], "Threshold Network Token");
    assert_eq!(rebate["token_metadata"]["symbol"], "T");
    assert_eq!(rebate["token_metadata"]["decimals"].as_u64(), Some(18));
    assert_eq!(
        fs::read(root.join("runtime/rebate-implementation.hex")).unwrap(),
        fs::read(root.join("runtime/rebate-official-implementation.hex")).unwrap(),
        "proxy implementation must match the official hotfix runtime"
    );

    let zero_slot = Value::String(format!("0x{}", "00".repeat(32)));
    let vaults = receipt["tbtc_vaults"].as_array().expect("vault receipts");
    assert_eq!(vaults.len(), 2);
    for vault in vaults {
        assert_two_provider_receipt(vault);
        for key in ["implementation", "admin", "beacon"] {
            assert_eq!(
                vault["standard_proxy_slots"][key], zero_slot,
                "vault unexpectedly became a standard proxy"
            );
        }
    }
}

#[test]
fn threshold_curations_admit_only_operand_complete_routes_and_preserve_refusals() {
    let root = workspace_root();
    for name in [GATEWAY_FILE, REBATE_FILE, VAULT_FILE] {
        assert_eq!(
            fs::read(
                root.join("secure/data/erc7730/curations/files/registry/threshold")
                    .join(name)
            )
            .unwrap(),
            fs::read(
                root.join("secure/data/erc7730-registry/registry/threshold")
                    .join(name)
            )
            .unwrap(),
            "installed descriptor diverged from curation: {name}"
        );
    }

    let gateway = descriptor(GATEWAY_FILE);
    let gateway_deployments = gateway["_pqsigner"]["deploymentFormats"]
        .as_array()
        .expect("gateway deployment allowlists");
    assert_eq!(gateway_deployments.len(), 7);
    let named_send = gateway["display"]["formats"]
        .as_object()
        .unwrap()
        .keys()
        .find(|signature| signature.starts_with("sendTbtc(uint256 amount,"))
        .expect("named sendTbtc signature")
        .to_string();
    for deployment in gateway_deployments {
        assert_eq!(
            deployment["formats"],
            Value::Array(vec![Value::String(named_send.clone())])
        );
    }
    assert_eq!(
        gateway["_pqsigner"]["refusalOnlyFormats"],
        serde_json::json!([
            "receiveTbtc(bytes encodedVm)",
            "sendTbtcWithPayloadToNativeChain(uint256 amount, uint16 recipientNativeChain, bytes32 recipient, uint32 nonce, bytes payload)"
        ])
    );
    assert_eq!(
        visible_paths(&gateway["display"]["formats"][&named_send]),
        BTreeSet::from([
            "@.value".to_string(),
            "amount".to_string(),
            "arbiterFee".to_string(),
            "nonce".to_string(),
            "recipient".to_string(),
            "recipientChain".to_string(),
        ])
    );
    let wormhole_chains = pinned_wormhole_chains();
    let descriptor_chains = gateway["metadata"]["enums"]["wormholeChain"]
        .as_object()
        .expect("Wormhole enum table");
    assert_eq!(
        descriptor_chains.len(),
        wormhole_chains.len(),
        "descriptor must name every chain in the pinned Wormhole SDK table"
    );
    for (chain_id, label) in &wormhole_chains {
        assert_eq!(
            descriptor_chains
                .get(&chain_id.to_string())
                .and_then(Value::as_str),
            Some(label.as_str()),
            "Wormhole destination {chain_id} has a stale or missing label"
        );
    }

    let rebate = descriptor(REBATE_FILE);
    assert_eq!(
        rebate["metadata"]["enums"]["rebateTreasuryFeeMode"]["0"],
        "Deposits and redemptions"
    );
    assert_eq!(
        rebate["display"]["formats"]["finalizeUnstaking(address receiver)"]["fields"][1]["value"],
        "Amount comes from pending unstake state"
    );

    let vault = descriptor(VAULT_FILE);
    for signature in [
        "requestOptimisticMint(bytes32 fundingTxHash, uint32 fundingOutputIndex)",
        "finalizeOptimisticMint(bytes32 fundingTxHash, uint32 fundingOutputIndex)",
    ] {
        assert_eq!(
            visible_paths(&vault["display"]["formats"][signature]),
            BTreeSet::from([
                "fundingOutputIndex".to_string(),
                "fundingTxHash".to_string()
            ])
        );
        assert!(vault["display"]["formats"][signature]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["value"]
                .as_str()
                .is_some_and(|text| text.contains("amount") || text.contains("Amount"))));
    }

    let registry = build_registry();
    let gateway_entry = registry
        .entries
        .iter()
        .find(|entry| entry.source.file_name().and_then(|file| file.to_str()) == Some(GATEWAY_FILE))
        .expect("compiled gateway entry");
    let gateway_ir = Erc7730Ir::parse(&gateway_entry.ir_bytes).expect("parse gateway IR");
    let send_format = gateway_ir
        .format_iter()
        .map(|format| format.expect("valid gateway format"))
        .find(|format| format.selector == selector(SEND_TBTC))
        .expect("compiled sendTbtc format");
    let enum_offsets = send_format
        .fields()
        .map(|field| field.expect("valid sendTbtc field"))
        .filter_map(|field| {
            parse_params(&gateway_ir, field.param_off)
                .expect("sendTbtc field params")
                .enum_ref
        })
        .collect::<Vec<_>>();
    assert_eq!(
        enum_offsets.len(),
        1,
        "sendTbtc must compile exactly one destination enum"
    );
    assert_eq!(
        gateway_ir
            .pool
            .get(enum_offsets[0] as usize)
            .copied(),
        Some(64),
        "compiled Wormhole enum entry-count byte must bind all 64 pinned chains"
    );
    for (chain_id, label) in &wormhole_chains {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&chain_id.to_be_bytes());
        assert_eq!(
            lookup_enum_label(gateway_ir.pool, enum_offsets[0], &word),
            Ok(Some(label.as_bytes())),
            "compiled Wormhole label mismatch for destination {chain_id}"
        );
    }
    let mut unassigned_word = [0u8; 32];
    unassigned_word[24..].copy_from_slice(&3u64.to_be_bytes());
    assert_eq!(
        lookup_enum_label(gateway_ir.pool, enum_offsets[0], &unassigned_word),
        Ok(None),
        "an ID absent from the pinned Wormhole table must not acquire a label"
    );

    let expectations = [
        (GATEWAY_FILE, 7usize, vec![SEND_TBTC]),
        (REBATE_FILE, 1usize, REBATE_ROUTES.to_vec()),
        (VAULT_FILE, 2usize, VAULT_ROUTES.to_vec()),
    ];
    for (name, count, routes) in expectations {
        let entries = registry
            .entries
            .iter()
            .filter(|entry| entry.source.file_name().and_then(|file| file.to_str()) == Some(name))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), count, "accepted leaf count changed: {name}");
        let expected_selectors = routes
            .iter()
            .map(|route| selector(route))
            .collect::<BTreeSet<_>>();
        for entry in entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse Threshold IR");
            assert_eq!(
                cross_check_contract(&ir, entry.chain_id, &entry.contract),
                Ok(())
            );
            assert_eq!(
                ir.format_iter()
                    .map(|format| format.expect("valid Threshold format").selector)
                    .collect::<BTreeSet<_>>(),
                expected_selectors,
                "unexpected admitted selector set: {name}"
            );
        }
    }

    for deployment in gateway_deployments {
        let chain_id = deployment["chainId"].as_u64().expect("gateway chain");
        let contract = address(required_str(deployment, "address"));
        for refused in [RECEIVE_TBTC, SEND_TBTC_PAYLOAD] {
            let refused_selector = selector(refused);
            assert!(
                registry
                    .known_calls
                    .contains(&(chain_id, contract, refused_selector)),
                "refused route left exact known-call inventory: {chain_id} {refused}"
            );
            assert!(
                known_call_may_contain(
                    &registry.known_calls_bloom,
                    chain_id,
                    &contract,
                    &refused_selector
                ),
                "refused route left fail-closed Bloom: {chain_id} {refused}"
            );
        }
    }
}
