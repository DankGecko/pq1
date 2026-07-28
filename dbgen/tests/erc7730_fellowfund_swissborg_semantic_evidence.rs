//! Offline deployment/source evidence and exact-refusal checks for the
//! FellowFund and SwissBorg CHSB-to-BORG migrator residual descriptors.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const FELLOW_SOURCE: &str = "registry/fellow-fund/calldata-fellow-fund.json";
const SWISSBORG_SOURCE: &str = "registry/swissborg/calldata-ChsbToBorgMigrator.json";
const FELLOW: &str = "25d598cbb74fa73290e74697616de2740d280745";
const MIGRATOR: &str = "aa854688caab725fe17b7d21b46fda5af365985a";
const IMPLEMENTATION: &str = "fb976ea3ae9bfe4bc36fb7078e0b32e579463e96";
const CHSB: &str = "ba9d4199fab4f26efe3551d490e3821486f135ba";
const BORG: &str = "64d0f55cd8c7133a9d7102b13987235f486f2224";
const SONIC_FT: &str = "5dd1a7a369e8273371d2dbf9d83356057088082c";
const IMPLEMENTATION_WORD: &str =
    "0x000000000000000000000000fb976ea3ae9bfe4bc36fb7078e0b32e579463e96";
const CHSB_WORD: &str = "0x000000000000000000000000ba9d4199fab4f26efe3551d490e3821486f135ba";
const BORG_WORD: &str = "0x00000000000000000000000064d0f55cd8c7133a9d7102b13987235f486f2224";
const TRUE_WORD: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
const FELLOW_FORMATS: [&str; 3] = [
    "createFellowship(string,uint256,uint256,uint256,uint256)",
    "applyToFellowship(uint256,string)",
    "setApplicantImpact(uint256,uint256,bool,bytes)",
];
const SWISSBORG_FORMATS: [&str; 1] = ["migrate(uint256)"];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/fellowfund-swissborg")
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
    hex::decode(text.trim().strip_prefix("0x").unwrap_or(text.trim())).expect("valid hex")
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn rpc_result<'a>(records: &'a Value, kind: &str, target: &str) -> &'a Value {
    records
        .as_array()
        .expect("RPC record array")
        .iter()
        .find(|record| {
            record["kind"].as_str() == Some(kind) && record["target"].as_str() == Some(target)
        })
        .unwrap_or_else(|| panic!("missing RPC record {kind} {target}"))
        .get("response")
        .and_then(|response| response.get("result"))
        .expect("RPC result")
}

fn canonical_signatures(descriptor: &Value) -> BTreeSet<String> {
    descriptor["display"]["formats"]
        .as_object()
        .expect("display formats")
        .keys()
        .map(|authored| {
            let (name, tail) = authored.split_once('(').expect("signature opens");
            let params = tail.strip_suffix(')').expect("signature closes");
            let types = params
                .split(',')
                .filter(|param| !param.trim().is_empty())
                .map(|param| {
                    param
                        .split_ascii_whitespace()
                        .next()
                        .expect("parameter type")
                })
                .collect::<Vec<_>>();
            format!("{name}({})", types.join(","))
        })
        .collect()
}

#[test]
fn fixed_evidence_proves_both_families_must_remain_exact_refusals() {
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["fixed_block"]["chain_id"].as_u64(), Some(1));
    assert_eq!(manifest["fixed_block"]["number"].as_u64(), Some(25_630_720));
    for artifact in manifest["artifacts"].as_array().expect("artifact receipts") {
        let relative = required_str(artifact, "path");
        let bytes = fs::read(evidence.join(relative)).expect("read evidence artifact");
        assert_eq!(
            artifact["bytes"].as_u64(),
            Some(bytes.len() as u64),
            "artifact byte count drifted: {relative}"
        );
        assert_eq!(
            required_str(artifact, "sha256"),
            sha256_hex(&bytes),
            "artifact hash drifted: {relative}"
        );
    }

    let drpc = read_json(&evidence.join("rpc/drpc.json"));
    let mev = read_json(&evidence.join("rpc/mevblocker.json"));
    for provider in [&drpc, &mev] {
        let block = rpc_result(provider, "block_header", "ethereum");
        assert_eq!(block["number"].as_str(), Some("0x1871800"));
        assert_eq!(
            rpc_result(provider, "code", &format!("0x{FELLOW}")).as_str(),
            Some("0x"),
            "the sole FellowFund destination unexpectedly has bytecode"
        );
        assert_eq!(
            rpc_result(provider, "implementation_slot", &format!("0x{MIGRATOR}")).as_str(),
            Some(IMPLEMENTATION_WORD)
        );
        assert_eq!(
            rpc_result(provider, "chsb_call", &format!("0x{MIGRATOR}")).as_str(),
            Some(CHSB_WORD)
        );
        assert_eq!(
            rpc_result(provider, "borg_call", &format!("0x{MIGRATOR}")).as_str(),
            Some(BORG_WORD)
        );
        assert_eq!(
            rpc_result(provider, "paused_call", &format!("0x{MIGRATOR}")).as_str(),
            Some(TRUE_WORD)
        );
    }
    for (kind, target) in [
        ("code", FELLOW),
        ("code", MIGRATOR),
        ("code", IMPLEMENTATION),
        ("code", CHSB),
        ("code", BORG),
        ("implementation_slot", MIGRATOR),
        ("chsb_call", MIGRATOR),
        ("borg_call", MIGRATOR),
        ("paused_call", MIGRATOR),
    ] {
        assert_eq!(
            rpc_result(&drpc, kind, &format!("0x{target}")),
            rpc_result(&mev, kind, &format!("0x{target}")),
            "providers disagree for {kind} {target}"
        );
    }

    let proxy = read_json(&evidence.join("blockscout/ChsbToBorgMigratorProxy.json"));
    assert_eq!(proxy["is_verified"].as_bool(), Some(true));
    assert_eq!(proxy["proxy_type"].as_str(), Some("eip1967"));
    assert!(proxy["implementations"]
        .as_array()
        .expect("proxy implementations")
        .iter()
        .any(|implementation| {
            implementation["address_hash"]
                .as_str()
                .map(|value| value.eq_ignore_ascii_case(&format!("0x{IMPLEMENTATION}")))
                == Some(true)
        }));

    let implementation = read_json(&evidence.join("blockscout/ChsbToBorgMigratorV2.json"));
    assert_eq!(implementation["is_fully_verified"].as_bool(), Some(true));
    assert_eq!(
        implementation["name"].as_str(),
        Some("ChsbToBorgMigratorV2")
    );
    let source = required_str(&implementation, "source_code");
    assert!(source.contains("version 2, which closes the migrator"));
    assert!(source.contains("function migrate(uint256 _amount) external whenNotPaused"));
    assert!(source.contains("revert(\"MIGRATION_CLOSED\");"));
    assert_eq!(
        rpc_result(&drpc, "code", &format!("0x{IMPLEMENTATION}"))
            .as_str()
            .expect("implementation runtime"),
        required_str(&implementation, "deployed_bytecode"),
        "verified implementation runtime differs from fixed-block RPC"
    );
    assert_eq!(
        fs::read_to_string(evidence.join("blockscout/FellowFund.http-status.txt"))
            .expect("FellowFund HTTP status")
            .trim(),
        "404"
    );
}

#[test]
fn curated_descriptors_emit_no_clear_leaf_but_preserve_every_exact_known_call() {
    let root = workspace_root();
    let registry_root = root.join("secure/data/erc7730-registry");
    for relative in [FELLOW_SOURCE, SWISSBORG_SOURCE] {
        assert_eq!(
            fs::read(registry_root.join(relative)).expect("read production descriptor"),
            fs::read(
                root.join("secure/data/erc7730/curations/files")
                    .join(relative)
            )
            .expect("read curated descriptor"),
            "production and curated descriptor diverged: {relative}"
        );
    }

    let fellow = read_json(&registry_root.join(FELLOW_SOURCE));
    let swissborg = read_json(&registry_root.join(SWISSBORG_SOURCE));
    assert_eq!(
        canonical_signatures(&fellow),
        FELLOW_FORMATS.into_iter().map(str::to_owned).collect()
    );
    assert_eq!(
        canonical_signatures(&swissborg),
        SWISSBORG_FORMATS.into_iter().map(str::to_owned).collect()
    );
    for descriptor in [&fellow, &swissborg] {
        assert!(
            descriptor["_pqsigner"].get("deploymentFormats").is_none(),
            "refused family may not retain clear-signing admission"
        );
        assert_eq!(
            descriptor["_pqsigner"]["refusalOnlyFormats"]
                .as_array()
                .expect("refusal-only formats")
                .len(),
            descriptor["display"]["formats"]
                .as_object()
                .expect("display formats")
                .len()
        );
    }

    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let refused_sources = [
        registry_root.join(FELLOW_SOURCE),
        registry_root.join(SWISSBORG_SOURCE),
    ];
    assert!(
        registry
            .entries
            .iter()
            .all(|entry| !refused_sources.contains(&entry.source)),
        "refusal-only descriptor emitted a clear-signing leaf"
    );
    for (target, signatures) in [
        (FELLOW, FELLOW_FORMATS.as_slice()),
        (MIGRATOR, SWISSBORG_FORMATS.as_slice()),
    ] {
        for signature in signatures {
            let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
                .try_into()
                .expect("selector width");
            assert!(
                registry
                    .known_calls
                    .contains(&(1, address(target), selector)),
                "refused exact tuple disappeared from the known-call set: {signature}"
            );
        }
    }

    let inventory =
        read_json(&root.join("tests/erc7730-semantic-evidence/accepted-family-inventory.json"));
    let accepted_sources = inventory["families"]
        .as_array()
        .expect("accepted families")
        .iter()
        .map(|family| required_str(family, "source"))
        .collect::<BTreeSet<_>>();
    assert!(!accepted_sources.contains("fellow-fund/calldata-fellow-fund.json"));
    assert!(!accepted_sources.contains("swissborg/calldata-ChsbToBorgMigrator.json"));

    let token_db = read_json(&root.join("secure/data/erc20.json"));
    let sonic_ft = token_db
        .as_array()
        .expect("ERC20 metadata array")
        .iter()
        .find(|token| {
            token["chain_id"].as_u64() == Some(146)
                && token["address"]
                    .as_str()
                    .map(|value| value.eq_ignore_ascii_case(&format!("0x{SONIC_FT}")))
                    == Some(true)
        })
        .expect("Sonic FT metadata");
    assert_eq!(sonic_ft["name"].as_str(), Some("Flying Tulip"));
    assert_eq!(sonic_ft["symbol"].as_str(), Some("FT"));
    assert_eq!(sonic_ft["decimals"].as_u64(), Some(18));
}
