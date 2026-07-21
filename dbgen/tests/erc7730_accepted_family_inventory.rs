use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use serde::Deserialize;
use serde_json::Value;

const INVENTORY_PATH: &str = "tests/erc7730-semantic-evidence/accepted-family-inventory.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum Classification {
    PinnedEvidence,
    SharedStandardImplementation,
    LowerPriorityResidual,
}

impl Classification {
    fn key(self) -> &'static str {
        match self {
            Self::PinnedEvidence => "pinned-evidence",
            Self::SharedStandardImplementation => "shared-standard-implementation",
            Self::LowerPriorityResidual => "lower-priority-residual",
        }
    }
}

#[derive(Debug, Deserialize)]
struct Inventory {
    schema_version: u64,
    scope: String,
    claim_limit: String,
    catalogue_snapshot: CatalogueSnapshot,
    classification_contract: BTreeMap<String, String>,
    evidence_sets: BTreeMap<String, EvidenceSet>,
    successor_issues: BTreeMap<String, SuccessorIssue>,
    families: Vec<Family>,
}

#[derive(Debug, Deserialize)]
struct CatalogueSnapshot {
    upstream_commit: String,
    upstream_tree: String,
    curated_corpus_sha256: String,
    merkle_root: String,
    accepted_leaf_count: usize,
    accepted_source_descriptor_count: usize,
    compiled_blob_bytes: usize,
    known_call_count: usize,
    category_source_counts: BTreeMap<String, usize>,
    category_leaf_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Deserialize)]
struct EvidenceSet {
    classification: Classification,
    reason: String,
    scope: String,
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SuccessorIssue {
    title: String,
    body: String,
}

#[derive(Debug, Deserialize)]
struct Family {
    source: String,
    accepted_leaf_count: usize,
    classification: Classification,
    evidence: Option<String>,
    successor_issue: Option<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn nonempty(value: &str, context: &str) {
    assert!(!value.trim().is_empty(), "{context} must not be empty");
}

fn checked_relative_path<'a>(value: &'a str, context: &str) -> &'a Path {
    let path = Path::new(value);
    assert!(!path.as_os_str().is_empty(), "{context} must not be empty");
    assert!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "{context} must be a normalized repository-relative path: {value}"
    );
    path
}

fn accepted_source_path(source: &Path, source_root: &Path) -> String {
    source
        .strip_prefix(source_root)
        .expect("accepted source stays beneath the production registry root")
        .components()
        .map(|component| match component {
            Component::Normal(value) => {
                value.to_str().expect("accepted source path is valid UTF-8")
            }
            _ => panic!("accepted source path is normalized"),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_exact_shared_erc4626_source(root: &Path, source: &str) -> bool {
    let source_path = root
        .join("secure/data/erc7730-registry/registry")
        .join(source);
    let document: Value = serde_json::from_slice(&fs::read(&source_path).unwrap_or_else(|error| {
        panic!(
            "read accepted descriptor {}: {error}",
            source_path.display()
        )
    }))
    .unwrap_or_else(|error| {
        panic!(
            "parse accepted descriptor {}: {error}",
            source_path.display()
        )
    });

    // A shared classification is valid only for a thin instance descriptor;
    // any local display override needs its own semantic classification.
    if document.get("display").is_some() {
        return false;
    }
    match document.get("includes").and_then(Value::as_str) {
        Some("../../ercs/calldata-erc4626-vaults.json") => true,
        Some("common-KilnVaults.json") => {
            let common_path = source_path
                .parent()
                .expect("accepted descriptor has a parent")
                .join("common-KilnVaults.json");
            let common: Value =
                serde_json::from_slice(&fs::read(&common_path).unwrap_or_else(|error| {
                    panic!(
                        "read shared Kiln template {}: {error}",
                        common_path.display()
                    )
                }))
                .unwrap_or_else(|error| {
                    panic!(
                        "parse shared Kiln template {}: {error}",
                        common_path.display()
                    )
                });
            common.get("display").is_none()
                && common.get("includes").and_then(Value::as_str)
                    == Some("../../ercs/calldata-erc4626-vaults.json")
        }
        _ => false,
    }
}

#[test]
fn accepted_source_families_are_accounted_exactly_once() {
    let root = workspace_root();
    let inventory_path = root.join(INVENTORY_PATH);
    let inventory: Inventory = serde_json::from_slice(
        &fs::read(&inventory_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", inventory_path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", inventory_path.display()));

    assert_eq!(inventory.schema_version, 1);
    nonempty(&inventory.scope, "inventory scope");
    nonempty(&inventory.claim_limit, "inventory claim_limit");

    let registry_root = root.join("secure/data/erc7730-registry");
    let source_root = registry_root.join("registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &source_root,
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");

    let snapshot = &inventory.catalogue_snapshot;
    assert_eq!(hex::encode(registry.root), snapshot.merkle_root);
    assert_eq!(registry.leaf_count, snapshot.accepted_leaf_count);
    assert_eq!(registry.entries.len(), snapshot.accepted_leaf_count);
    assert_eq!(registry.blob.len(), snapshot.compiled_blob_bytes);
    assert_eq!(registry.known_call_count, snapshot.known_call_count);

    let curation_manifest: Value = serde_json::from_slice(
        &fs::read(root.join("secure/data/erc7730/curations/manifest.json"))
            .expect("read curation manifest"),
    )
    .expect("parse curation manifest");
    assert_eq!(
        curation_manifest["upstream"]["commit"].as_str(),
        Some(snapshot.upstream_commit.as_str())
    );
    assert_eq!(
        curation_manifest["upstream"]["tree"].as_str(),
        Some(snapshot.upstream_tree.as_str())
    );
    assert_eq!(
        curation_manifest["curated_corpus"]["sha256"].as_str(),
        Some(snapshot.curated_corpus_sha256.as_str())
    );

    let mut accepted = BTreeMap::<String, usize>::new();
    for entry in &registry.entries {
        *accepted
            .entry(accepted_source_path(&entry.source, &source_root))
            .or_default() += 1;
    }
    assert_eq!(accepted.len(), snapshot.accepted_source_descriptor_count);

    let expected_classes: BTreeSet<_> = [
        "pinned-evidence".to_string(),
        "shared-standard-implementation".to_string(),
        "lower-priority-residual".to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        inventory
            .classification_contract
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected_classes
    );
    for (classification, contract) in &inventory.classification_contract {
        nonempty(
            contract,
            &format!("classification contract {classification}"),
        );
    }

    let mut evidence_uses = BTreeMap::<String, usize>::new();
    let mut issue_uses = BTreeMap::<String, usize>::new();
    let mut classified = BTreeMap::<String, usize>::new();
    let mut source_counts = BTreeMap::<String, usize>::new();
    let mut leaf_counts = BTreeMap::<String, usize>::new();
    let mut previous_source: Option<&str> = None;

    for family in &inventory.families {
        checked_relative_path(&family.source, "family source");
        if let Some(previous) = previous_source {
            assert!(
                previous < family.source.as_str(),
                "family records must be unique and sorted: {previous} then {}",
                family.source
            );
        }
        previous_source = Some(&family.source);
        assert!(family.accepted_leaf_count > 0);
        assert_eq!(
            accepted.get(&family.source),
            Some(&family.accepted_leaf_count),
            "missing, stale, or miscounted accepted family {}",
            family.source
        );
        assert!(
            classified
                .insert(family.source.clone(), family.accepted_leaf_count)
                .is_none(),
            "duplicate family record {}",
            family.source
        );

        let structurally_shared = is_exact_shared_erc4626_source(&root, &family.source);
        assert_eq!(
            family.classification == Classification::SharedStandardImplementation,
            structurally_shared,
            "shared-standard classification drift for {}",
            family.source
        );

        *source_counts
            .entry(family.classification.key().to_string())
            .or_default() += 1;
        *leaf_counts
            .entry(family.classification.key().to_string())
            .or_default() += family.accepted_leaf_count;

        match family.classification {
            Classification::PinnedEvidence | Classification::SharedStandardImplementation => {
                assert!(family.successor_issue.is_none());
                let evidence_id = family
                    .evidence
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} requires an evidence reference", family.source));
                let evidence = inventory.evidence_sets.get(evidence_id).unwrap_or_else(|| {
                    panic!("{} names unknown evidence {evidence_id}", family.source)
                });
                assert_eq!(evidence.classification, family.classification);
                *evidence_uses.entry(evidence_id.to_string()).or_default() += 1;
            }
            Classification::LowerPriorityResidual => {
                assert!(family.evidence.is_none());
                let issue_id = family
                    .successor_issue
                    .as_deref()
                    .unwrap_or_else(|| panic!("{} requires a successor issue", family.source));
                assert!(
                    inventory.successor_issues.contains_key(issue_id),
                    "{} names unknown successor issue {issue_id}",
                    family.source
                );
                *issue_uses.entry(issue_id.to_string()).or_default() += 1;
            }
        }
    }

    assert_eq!(classified, accepted, "inventory source set is not exact");
    assert_eq!(source_counts, snapshot.category_source_counts);
    assert_eq!(leaf_counts, snapshot.category_leaf_counts);
    assert_eq!(
        source_counts.values().sum::<usize>(),
        snapshot.accepted_source_descriptor_count
    );
    assert_eq!(
        leaf_counts.values().sum::<usize>(),
        snapshot.accepted_leaf_count
    );

    for (id, evidence) in &inventory.evidence_sets {
        assert!(evidence_uses.contains_key(id), "unused evidence set {id}");
        nonempty(&evidence.reason, &format!("evidence reason {id}"));
        nonempty(&evidence.scope, &format!("evidence scope {id}"));
        assert!(!evidence.paths.is_empty(), "evidence {id} has no paths");
        for value in &evidence.paths {
            let path = checked_relative_path(value, &format!("evidence path {id}"));
            let metadata = fs::symlink_metadata(root.join(path))
                .unwrap_or_else(|error| panic!("evidence path {} does not exist: {error}", value));
            assert!(metadata.is_file(), "evidence path is not a file: {value}");
            assert!(
                !metadata.file_type().is_symlink(),
                "evidence path must not be a symlink: {value}"
            );
        }
    }

    for (id, issue) in &inventory.successor_issues {
        assert!(issue_uses.contains_key(id), "unused successor issue {id}");
        nonempty(&issue.title, &format!("successor title {id}"));
        nonempty(&issue.body, &format!("successor body {id}"));
    }
}
