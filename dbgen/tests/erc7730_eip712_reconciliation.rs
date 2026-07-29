use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use serde_json::Value;
use sha2::{Digest, Sha256};

const EVIDENCE_MANIFEST: &str =
    "tests/erc7730-semantic-evidence/eip712-reconciliation/manifest.json";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen is one directory below the workspace")
        .to_path_buf()
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
        .unwrap_or_else(|| panic!("missing string `{key}`"))
}

fn normalized_address(value: &str) -> String {
    let stripped = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .expect("address prefix");
    assert_eq!(stripped.len(), 40, "address width");
    assert!(
        stripped.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "address hex"
    );
    format!("0x{}", stripped.to_ascii_lowercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn source_path(entry_source: &Path, source_root: &Path) -> String {
    entry_source
        .strip_prefix(source_root)
        .unwrap_or_else(|_| {
            panic!(
                "accepted source {} escaped {}",
                entry_source.display(),
                source_root.display()
            )
        })
        .to_string_lossy()
        .replace('\\', "/")
}

fn string_set(values: &Value, label: &str) -> BTreeSet<String> {
    values
        .as_array()
        .unwrap_or_else(|| panic!("{label} must be an array"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{label} member must be a string"))
                .to_string()
        })
        .collect()
}

fn declared_deployments(descriptor: &Value) -> BTreeSet<(u64, String)> {
    descriptor["context"]["eip712"]["deployments"]
        .as_array()
        .expect("EIP-712 deployments")
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"].as_u64().expect("deployment chainId"),
                normalized_address(deployment["address"].as_str().expect("deployment address")),
            )
        })
        .collect()
}

fn admitted_deployments(descriptor: &Value) -> BTreeSet<(u64, String)> {
    descriptor["_pqsigner"]["deploymentFormats"]
        .as_array()
        .expect("authenticated deploymentFormats")
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"].as_u64().expect("admission chainId"),
                normalized_address(deployment["address"].as_str().expect("admission address")),
            )
        })
        .collect()
}

#[test]
fn exact_eip712_queue_is_evidenced_or_structurally_quarantined() {
    let root = workspace_root();
    let evidence = read_json(&root.join(EVIDENCE_MANIFEST));
    assert_eq!(evidence["schema_version"].as_u64(), Some(1));
    assert_eq!(
        evidence["authority_contract"].as_str(),
        Some(
            "Promote only exact source/runtime/domain/type/deployment semantics with executable binding, render, and refusal evidence. Otherwise emit no clear-signing leaf; the typed-data handler's mandatory descriptor proof then fails closed. EIP-712 quarantine never grants forced-blind authority."
        )
    );

    let promoted = evidence["promoted"].as_array().expect("promoted queue");
    let quarantined = evidence["quarantined"]
        .as_array()
        .expect("quarantined queue");
    let reason_codes = evidence["reason_codes"]
        .as_object()
        .expect("reason-code contract");

    let promoted_sources: BTreeSet<_> = promoted
        .iter()
        .map(|record| required_str(record, "source").to_string())
        .collect();
    let quarantined_sources: BTreeSet<_> = quarantined
        .iter()
        .map(|record| required_str(record, "source").to_string())
        .collect();
    assert_eq!(promoted_sources.len(), promoted.len());
    assert_eq!(quarantined_sources.len(), quarantined.len());
    assert!(
        promoted_sources.is_disjoint(&quarantined_sources),
        "a source cannot be both promoted and quarantined"
    );

    let promoted_leaves: u64 = promoted
        .iter()
        .map(|record| {
            record["prior_accepted_leaf_count"]
                .as_u64()
                .expect("promoted prior leaf count")
        })
        .sum();
    let quarantined_leaves: u64 = quarantined
        .iter()
        .map(|record| {
            record["prior_accepted_leaf_count"]
                .as_u64()
                .expect("quarantined prior leaf count")
        })
        .sum();
    assert_eq!(promoted_sources.len(), 3);
    assert_eq!(promoted_leaves, 8);
    assert_eq!(quarantined_sources.len(), 24);
    assert_eq!(quarantined_leaves, 31);
    assert_eq!(promoted_sources.len() + quarantined_sources.len(), 27);
    assert_eq!(promoted_leaves + quarantined_leaves, 39);
    assert_eq!(
        evidence["totals"]["promoted_source_count"].as_u64(),
        Some(promoted_sources.len() as u64)
    );
    assert_eq!(
        evidence["totals"]["promoted_leaf_count"].as_u64(),
        Some(promoted_leaves)
    );
    assert_eq!(
        evidence["totals"]["quarantined_source_count"].as_u64(),
        Some(quarantined_sources.len() as u64)
    );
    assert_eq!(
        evidence["totals"]["quarantined_leaf_count"].as_u64(),
        Some(quarantined_leaves)
    );

    let registry_root = root.join("secure/data/erc7730-registry");
    let source_root = registry_root.join("registry");
    let curation_root = root.join("secure/data/erc7730/curations/files/registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC-20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &source_root,
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build reconciled ERC-7730 registry");

    assert_eq!(
        registry.known_call_count as u64,
        evidence["baseline"]["known_call_count"]
            .as_u64()
            .expect("baseline known-call count"),
        "EIP-712 reconciliation must not change the contract-call authority set"
    );
    assert_eq!(
        sha256_hex(
            &fs::read(root.join("secure/data/erc7730-forced-eligible.set"))
                .expect("read forced-eligible set")
        ),
        evidence["baseline"]["forced_eligible_set_sha256"]
            .as_str()
            .expect("baseline forced-set hash"),
        "EIP-712 quarantine must not create forced-blind eligibility"
    );
    assert_eq!(
        sha256_hex(
            &fs::read(root.join("secure/data/erc7730-known-calls.bloom"))
                .expect("read known-call Bloom")
        ),
        evidence["baseline"]["known_call_bloom_sha256"]
            .as_str()
            .expect("baseline Bloom hash"),
        "EIP-712 reconciliation must not change the known-call Bloom"
    );

    let mut accepted_counts = BTreeMap::<String, usize>::new();
    for entry in &registry.entries {
        *accepted_counts
            .entry(source_path(&entry.source, &source_root))
            .or_default() += 1;
    }

    for record in promoted {
        let source = required_str(record, "source");
        let descriptor = read_json(&curation_root.join(source));
        let note = descriptor["_curation_note"]
            .as_str()
            .expect("promoted curation note");
        assert!(note.contains("#498"), "missing #498 note in {source}");
        assert_eq!(
            admitted_deployments(&descriptor),
            declared_deployments(&descriptor),
            "promoted deployments are not exact for {source}"
        );

        let expected_formats: BTreeSet<_> = descriptor["display"]["formats"]
            .as_object()
            .expect("display formats")
            .keys()
            .cloned()
            .collect();
        for admission in descriptor["_pqsigner"]["deploymentFormats"]
            .as_array()
            .expect("promoted admissions")
        {
            assert_eq!(
                string_set(&admission["formats"], "admitted formats"),
                expected_formats,
                "promoted type set is incomplete for {source}"
            );
        }
        assert!(
            descriptor["_pqsigner"]
                .get("refusalOnlyFormats")
                .is_none_or(Value::is_null),
            "promoted source unexpectedly carries refusal-only types: {source}"
        );
        assert_eq!(
            accepted_counts.get(source).copied(),
            Some(
                record["prior_accepted_leaf_count"]
                    .as_u64()
                    .expect("promoted leaf count") as usize
            ),
            "promoted leaf count drift for {source}"
        );
    }

    for record in quarantined {
        let source = required_str(record, "source");
        let reason_code = required_str(record, "reason_code");
        assert!(
            reason_codes
                .get(reason_code)
                .and_then(Value::as_str)
                .is_some_and(|reason| !reason.trim().is_empty()),
            "unknown or empty reason code {reason_code} for {source}"
        );

        let mut curated = read_json(&curation_root.join(source));
        assert_eq!(
            read_json(&source_root.join(source)),
            curated,
            "checked-in vendored descriptor is not the manifest-curated replacement for {source}"
        );
        let note = curated["_curation_note"]
            .as_str()
            .expect("quarantine curation note");
        assert!(note.contains("#498"), "missing #498 note in {source}");
        assert!(
            note.contains(reason_code),
            "curation note does not name {reason_code} for {source}"
        );
        assert_eq!(
            curated["_pqsigner"]["deploymentFormats"],
            serde_json::json!([]),
            "quarantine must admit no deployment for {source}"
        );
        let declared_formats: BTreeSet<_> = curated["display"]["formats"]
            .as_object()
            .expect("display formats")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            string_set(
                &curated["_pqsigner"]["refusalOnlyFormats"],
                "refusal-only formats"
            ),
            declared_formats,
            "quarantine marker must cover every type in {source}"
        );
        curated
            .as_object_mut()
            .expect("descriptor object")
            .remove("_curation_note");
        curated
            .as_object_mut()
            .expect("descriptor object")
            .remove("_pqsigner");
        assert!(
            curated["context"]["eip712"].is_object() && curated["display"]["formats"].is_object(),
            "quarantine must retain the source EIP-712 context and display formats for {source}"
        );
        assert!(
            !accepted_counts.contains_key(source),
            "quarantined source still emitted a clear-signing leaf: {source}"
        );
    }

    let accepted_inventory =
        read_json(&root.join("tests/erc7730-semantic-evidence/accepted-family-inventory.json"));
    let accepted_families: BTreeMap<_, _> = accepted_inventory["families"]
        .as_array()
        .expect("accepted families")
        .iter()
        .map(|family| (required_str(family, "source"), family))
        .collect();
    for record in promoted {
        let source = required_str(record, "source");
        let family = accepted_families
            .get(source)
            .unwrap_or_else(|| panic!("promoted source missing from accepted inventory: {source}"));
        assert_eq!(family["classification"].as_str(), Some("pinned-evidence"));
        assert_eq!(
            family["evidence"].as_str(),
            Some(required_str(record, "evidence"))
        );
    }
    for source in &quarantined_sources {
        assert!(
            !accepted_families.contains_key(source.as_str()),
            "quarantined source remains in accepted inventory: {source}"
        );
    }
    assert!(
        accepted_inventory["families"]
            .as_array()
            .expect("accepted families")
            .iter()
            .all(|family| {
                family["successor_issue"].as_str() != Some("remaining-eip712-families")
            }),
        "the completed #498 queue still has accepted residuals"
    );
    assert!(
        accepted_inventory["successor_issues"]
            .get("remaining-eip712-families")
            .is_none(),
        "completed #498 successor record must be removed"
    );
}
