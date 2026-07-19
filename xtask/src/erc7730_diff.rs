//! Read-only, deterministic A/B review of two official ERC-7730 registry
//! revisions.
//!
//! This module deliberately reports catalogue facts; it does not vendor,
//! apply curations, regenerate artifacts, install roots, or grant signing or
//! release authority. In particular, an unregistered contract-call tuple is
//! not labelled "blind": runtime dispatch and Bloom false positives may still
//! refuse it, and forced-blind signing is a separate product phase.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use pqsigner_erc7730::ir::{Erc7730Ir, CTX_CONTRACT, CTX_EIP712};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::erc7730_curation::{
    self, CorpusReceipt, RegistryCheckoutIdentity, ReplacementIdentity, VerifiedOverlay,
};
use super::{
    build_capability_bound_registry, collect_vendor_jsons, load_production_erc20_capability_input,
    vendor_corpus_receipt, vendor_excluded_fixture_receipt, CapabilityBoundRegistryBuild,
    Erc20CapabilityInput, Erc20CapabilityReceipt, ERC7730_DEFAULT_CURATION_MANIFEST,
    ERC7730_DEFAULT_POLICY,
};

const REPORT_SCHEMA: &str = "pqsigner-erc7730-registry-diff-v1";
const AUTHORITY_MODE: &str = "review-only-dev-unattested";

pub(crate) fn cmd_diff_registry(args: &[String], workspace_root: &Path) -> ExitCode {
    if matches!(args, [arg] if matches!(arg.as_str(), "--help" | "-h")) {
        print_usage();
        return ExitCode::SUCCESS;
    }
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("diff-registry: {error}");
            return ExitCode::FAILURE;
        }
    };
    match run_diff(parsed, workspace_root) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("diff-registry: serialize deterministic report: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("diff-registry: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "pqsigner-xtask diff-registry \\\n  --base-root PATH --candidate-root PATH \\\n  [--policy PATH] [--curation-manifest PATH]\n\n\
Read-only deterministic JSON comparison of two clean official ERC-7730\n\
registry checkouts. The base must match the manifest-pinned revision."
    );
}

#[derive(Debug)]
struct DiffArgs {
    base_root: PathBuf,
    candidate_root: PathBuf,
    policy: Option<PathBuf>,
    curation_manifest: Option<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<DiffArgs, String> {
    let mut base_root = None;
    let mut candidate_root = None;
    let mut policy = None;
    let mut curation_manifest = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let slot = match flag {
            "--base-root" => &mut base_root,
            "--candidate-root" => &mut candidate_root,
            "--policy" => &mut policy,
            "--curation-manifest" => &mut curation_manifest,
            other => return Err(format!("unknown flag `{other}`")),
        };
        if slot.is_some() {
            return Err(format!("duplicate flag `{flag}`"));
        }
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        if value.is_empty() || value.starts_with("--") {
            return Err(format!("{flag} requires a path value"));
        }
        *slot = Some(PathBuf::from(value));
        index += 1;
    }

    Ok(DiffArgs {
        base_root: base_root.ok_or("--base-root PATH is required")?,
        candidate_root: candidate_root.ok_or("--candidate-root PATH is required")?,
        policy,
        curation_manifest,
    })
}

fn run_diff(args: DiffArgs, workspace_root: &Path) -> Result<DiffReport, String> {
    let manifest_path = args
        .curation_manifest
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_CURATION_MANIFEST));
    let policy_path = args
        .policy
        .unwrap_or_else(|| workspace_root.join(ERC7730_DEFAULT_POLICY));
    let overlay = VerifiedOverlay::load_and_verify_local_inputs(workspace_root, &manifest_path)
        .map_err(|error| format!("curation overlay: {error}"))?;
    overlay
        .verify_selected_policy(workspace_root, &policy_path)
        .map_err(|error| format!("curation overlay: {error}"))?;
    overlay
        .verify_upstream_checkout(&args.base_root)
        .map_err(|error| format!("base checkout: {error}"))?;

    let erc20 = load_production_erc20_capability_input(workspace_root)?;
    let base = capture_snapshot(&args.base_root, &policy_path, &erc20)
        .map_err(|error| format!("base snapshot: {error}"))?;
    overlay
        .verify_source_receipts(base.corpus, base.excluded_fixtures)
        .map_err(|error| format!("base checkout: {error}"))?;
    let candidate = capture_snapshot(&args.candidate_root, &policy_path, &erc20)
        .map_err(|error| format!("candidate snapshot: {error}"))?;

    let leaf_changes = diff_leaves(&base, &candidate)?;
    let contract_calls = diff_contract_calls(&base, &candidate)?;
    let skip_categories = diff_skip_categories(&base.build.skips, &candidate.build.skips)?;
    let curation_collisions =
        curation_collisions(&overlay.replacement_identities()?, &candidate.files);

    Ok(DiffReport {
        schema: REPORT_SCHEMA,
        authority: AuthorityReport {
            mode: AUTHORITY_MODE,
            scope: "raw upstream revisions under the current manifest-bound compiler, policy, and production ERC-20 capability input; curations are not applied",
            unregistered_call_semantics: "absent from this registry's exact known-call set; this report does not claim the runtime will permit blind signing",
            curation_manifest_sha256: hex::encode(overlay.manifest_sha256()),
            policy_sha256: hex::encode(overlay.policy_sha256()?),
            production_erc20: Erc20ReceiptReport::from(erc20.receipt),
        },
        base: SnapshotReport::from_snapshot(&base),
        candidate: SnapshotReport::from_snapshot(&candidate),
        files: CorpusFileDiffs {
            security_corpus: diff_files(&base.files, &candidate.files),
            excluded_fixtures: diff_files(&base.excluded_files, &candidate.excluded_files),
        },
        leaves: leaf_changes,
        contract_calls,
        skip_categories,
        curation_collisions,
    })
}

struct Snapshot {
    root: PathBuf,
    identity: RegistryCheckoutIdentity,
    corpus: CorpusReceipt,
    excluded_fixtures: CorpusReceipt,
    files: BTreeMap<String, FileVersion>,
    excluded_files: BTreeMap<String, FileVersion>,
    build: CapabilityBoundRegistryBuild,
}

fn capture_snapshot(
    root: &Path,
    policy: &Path,
    erc20: &Erc20CapabilityInput,
) -> Result<Snapshot, String> {
    let root = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize registry root {}: {error}", root.display()))?;
    let identity = erc7730_curation::verify_official_clean_checkout(&root)?;
    let before = collect_inputs(&root)?;
    let build =
        build_capability_bound_registry(&root.join("registry"), policy, Some(&root), erc20)?;
    let after_identity = erc7730_curation::verify_official_clean_checkout(&root)?;
    let after = collect_inputs(&root)?;
    if identity != after_identity
        || before.corpus != after.corpus
        || before.excluded_fixtures != after.excluded_fixtures
        || before.files != after.files
        || before.excluded_files != after.excluded_files
    {
        return Err(
            "registry security inputs changed while the snapshot was being built; retry from a stable checkout"
                .to_string(),
        );
    }
    if build.catalogue.known_calls.len() != build.catalogue.known_call_count {
        return Err("internal: exact known-call inventory/count mismatch".to_string());
    }

    Ok(Snapshot {
        root,
        identity,
        corpus: before.corpus,
        excluded_fixtures: before.excluded_fixtures,
        files: before.files,
        excluded_files: before.excluded_files,
        build,
    })
}

struct CollectedInputs {
    corpus: CorpusReceipt,
    excluded_fixtures: CorpusReceipt,
    files: BTreeMap<String, FileVersion>,
    excluded_files: BTreeMap<String, FileVersion>,
}

fn collect_inputs(root: &Path) -> Result<CollectedInputs, String> {
    let mut files = BTreeSet::new();
    let mut excluded = BTreeSet::new();
    for directory in [root.join("registry"), root.join("ercs")] {
        collect_vendor_jsons(&directory, &mut files, &mut excluded, false)?;
    }
    let corpus = vendor_corpus_receipt(root, &files)?;
    let excluded_fixtures = vendor_excluded_fixture_receipt(root, &excluded)?;
    Ok(CollectedInputs {
        corpus,
        excluded_fixtures,
        files: file_versions(root, &files)?,
        excluded_files: file_versions(root, &excluded)?,
    })
}

fn file_versions(
    root: &Path,
    paths: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<String, FileVersion>, String> {
    let mut out = BTreeMap::new();
    for path in paths {
        let relative = registry_relative_path(root, path)?;
        let bytes = fs::read(path)
            .map_err(|error| format!("read registry input {}: {error}", path.display()))?;
        let byte_count = u64::try_from(bytes.len())
            .map_err(|_| format!("registry input is too large: {relative}"))?;
        let version = FileVersion {
            path: relative.clone(),
            bytes: byte_count,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        if out.insert(relative.clone(), version).is_some() {
            return Err(format!("duplicate registry-relative path: {relative}"));
        }
    }
    Ok(out)
}

fn registry_relative_path(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| format!("registry input escaped checkout root: {}", path.display()))?;
    let value = relative
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 registry-relative path: {}", relative.display()))?;
    if std::path::MAIN_SEPARATOR == '/' {
        Ok(value.to_string())
    } else {
        Ok(value.replace(std::path::MAIN_SEPARATOR, "/"))
    }
}

#[derive(Serialize)]
struct DiffReport {
    schema: &'static str,
    authority: AuthorityReport,
    base: SnapshotReport,
    candidate: SnapshotReport,
    files: CorpusFileDiffs,
    leaves: LeafChanges,
    contract_calls: ContractCallChanges,
    skip_categories: Vec<SkipCategoryDelta>,
    curation_collisions: Vec<CurationCollision>,
}

#[derive(Serialize)]
struct AuthorityReport {
    mode: &'static str,
    scope: &'static str,
    unregistered_call_semantics: &'static str,
    curation_manifest_sha256: String,
    policy_sha256: String,
    production_erc20: Erc20ReceiptReport,
}

#[derive(Serialize)]
struct Erc20ReceiptReport {
    input_sha256: String,
    database_root: String,
    entries: usize,
    capabilities: usize,
}

impl From<Erc20CapabilityReceipt> for Erc20ReceiptReport {
    fn from(value: Erc20CapabilityReceipt) -> Self {
        Self {
            input_sha256: hex::encode(value.input_sha256),
            database_root: hex::encode(value.db_root),
            entries: value.entry_count,
            capabilities: value.capability_count,
        }
    }
}

#[derive(Serialize)]
struct SnapshotReport {
    repository: String,
    commit: String,
    tree: String,
    schema_sha256: String,
    security_corpus: CorpusReceiptReport,
    excluded_fixtures: CorpusReceiptReport,
    catalogue: CatalogueReceiptReport,
}

impl SnapshotReport {
    fn from_snapshot(snapshot: &Snapshot) -> Self {
        let result = &snapshot.build.catalogue;
        Self {
            repository: snapshot.identity.repository.clone(),
            commit: snapshot.identity.commit.clone(),
            tree: snapshot.identity.tree.clone(),
            schema_sha256: hex::encode(snapshot.identity.schema_sha256),
            security_corpus: snapshot.corpus.into(),
            excluded_fixtures: snapshot.excluded_fixtures.into(),
            catalogue: CatalogueReceiptReport {
                root: hex::encode(result.root),
                blob_sha256: hex::encode(Sha256::digest(&result.blob)),
                blob_bytes: result.blob.len(),
                leaves: result.leaf_count,
                provenance: result.provenance.as_str(),
                known_calls: result.known_call_count,
                known_call_set_sha256: hex::encode(result.known_call_set_hash),
                known_calls_bloom_sha256: hex::encode(Sha256::digest(result.known_calls_bloom)),
                skipped: snapshot.build.skips.len(),
            },
        }
    }
}

#[derive(Serialize)]
struct CorpusReceiptReport {
    files: usize,
    bytes: u64,
    sha256: String,
}

impl From<CorpusReceipt> for CorpusReceiptReport {
    fn from(value: CorpusReceipt) -> Self {
        Self {
            files: value.file_count,
            bytes: value.byte_count,
            sha256: hex::encode(value.sha256),
        }
    }
}

#[derive(Serialize)]
struct CatalogueReceiptReport {
    root: String,
    blob_sha256: String,
    blob_bytes: usize,
    leaves: usize,
    provenance: &'static str,
    known_calls: usize,
    known_call_set_sha256: String,
    known_calls_bloom_sha256: String,
    skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FileVersion {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct CorpusFileDiffs {
    security_corpus: FileChanges,
    excluded_fixtures: FileChanges,
}

#[derive(Serialize)]
struct FileChanges {
    added: Vec<FileVersion>,
    removed: Vec<FileVersion>,
    changed: Vec<FileChange>,
}

#[derive(Serialize)]
struct FileChange {
    path: String,
    before: FileVersionReceipt,
    after: FileVersionReceipt,
}

#[derive(Serialize)]
struct FileVersionReceipt {
    bytes: u64,
    sha256: String,
}

fn diff_files(
    base: &BTreeMap<String, FileVersion>,
    candidate: &BTreeMap<String, FileVersion>,
) -> FileChanges {
    let added = candidate
        .iter()
        .filter(|(path, _)| !base.contains_key(*path))
        .map(|(_, version)| version.clone())
        .collect();
    let removed = base
        .iter()
        .filter(|(path, _)| !candidate.contains_key(*path))
        .map(|(_, version)| version.clone())
        .collect();
    let changed = base
        .iter()
        .filter_map(|(path, before)| {
            let after = candidate.get(path)?;
            (before != after).then(|| FileChange {
                path: path.clone(),
                before: FileVersionReceipt {
                    bytes: before.bytes,
                    sha256: before.sha256.clone(),
                },
                after: FileVersionReceipt {
                    bytes: after.bytes,
                    sha256: after.sha256.clone(),
                },
            })
        })
        .collect();
    FileChanges {
        added,
        removed,
        changed,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LeafKey {
    context_kind: u8,
    chain_id: u64,
    contract: [u8; 20],
    primary_type_hash: [u8; 32],
}

#[derive(Clone)]
struct LeafRecord {
    key: LeafKey,
    source: String,
    descriptor_id: String,
    descriptor_sha256: [u8; 32],
    erc8176_sha256: [u8; 32],
    ir_sha256: [u8; 32],
    ir_bytes: usize,
    ir: Vec<u8>,
}

#[derive(Serialize)]
struct LeafChanges {
    gained: Vec<LeafReport>,
    lost: Vec<LeafReport>,
    ir_changed: Vec<LeafIrChange>,
}

#[derive(Serialize)]
struct LeafIrChange {
    key: LeafKeyReport,
    before: LeafContentReport,
    after: LeafContentReport,
}

#[derive(Serialize)]
struct LeafReport {
    key: LeafKeyReport,
    #[serde(flatten)]
    content: LeafContentReport,
}

#[derive(Serialize)]
struct LeafKeyReport {
    context: &'static str,
    chain_id: u64,
    contract: String,
    primary_type_hash: String,
}

#[derive(Serialize)]
struct LeafContentReport {
    source: String,
    descriptor_id: String,
    descriptor_sha256: String,
    erc8176_sha256: String,
    ir_bytes: usize,
    ir_sha256: String,
}

impl LeafRecord {
    fn key_report(&self) -> LeafKeyReport {
        LeafKeyReport {
            context: context_name(self.key.context_kind),
            chain_id: self.key.chain_id,
            contract: prefixed_hex(&self.key.contract),
            primary_type_hash: prefixed_hex(&self.key.primary_type_hash),
        }
    }

    fn content_report(&self) -> LeafContentReport {
        LeafContentReport {
            source: self.source.clone(),
            descriptor_id: self.descriptor_id.clone(),
            descriptor_sha256: hex::encode(self.descriptor_sha256),
            erc8176_sha256: hex::encode(self.erc8176_sha256),
            ir_bytes: self.ir_bytes,
            ir_sha256: hex::encode(self.ir_sha256),
        }
    }

    fn report(&self) -> LeafReport {
        LeafReport {
            key: self.key_report(),
            content: self.content_report(),
        }
    }
}

fn context_name(context_kind: u8) -> &'static str {
    match context_kind {
        CTX_CONTRACT => "contract",
        CTX_EIP712 => "eip712",
        _ => "unknown",
    }
}

fn leaf_map(snapshot: &Snapshot) -> Result<BTreeMap<LeafKey, LeafRecord>, String> {
    let mut out = BTreeMap::new();
    for entry in &snapshot.build.catalogue.entries {
        if !matches!(entry.context_kind, CTX_CONTRACT | CTX_EIP712) {
            return Err(format!(
                "unknown emitted ERC-7730 context kind: {}",
                entry.context_kind
            ));
        }
        let key = LeafKey {
            context_kind: entry.context_kind,
            chain_id: entry.chain_id,
            contract: entry.contract,
            primary_type_hash: entry.primary_type_hash,
        };
        let record = LeafRecord {
            key,
            source: registry_relative_path(&snapshot.root, &entry.source)?,
            descriptor_id: entry.descriptor_id.clone(),
            descriptor_sha256: entry.descriptor_hash,
            erc8176_sha256: entry.erc8176_hash,
            ir_sha256: Sha256::digest(&entry.ir_bytes).into(),
            ir_bytes: entry.ir_bytes.len(),
            ir: entry.ir_bytes.clone(),
        };
        if out.insert(key, record).is_some() {
            return Err("internal: duplicate emitted leaf key in diff input".to_string());
        }
    }
    Ok(out)
}

fn diff_leaves(base: &Snapshot, candidate: &Snapshot) -> Result<LeafChanges, String> {
    let base = leaf_map(base)?;
    let candidate = leaf_map(candidate)?;
    Ok(diff_leaf_maps(&base, &candidate))
}

fn diff_leaf_maps(
    base: &BTreeMap<LeafKey, LeafRecord>,
    candidate: &BTreeMap<LeafKey, LeafRecord>,
) -> LeafChanges {
    let gained = candidate
        .iter()
        .filter(|(key, _)| !base.contains_key(*key))
        .map(|(_, record)| record.report())
        .collect();
    let lost = base
        .iter()
        .filter(|(key, _)| !candidate.contains_key(*key))
        .map(|(_, record)| record.report())
        .collect();
    let ir_changed = base
        .iter()
        .filter_map(|(key, before)| {
            let after = candidate.get(key)?;
            (before.ir != after.ir).then(|| LeafIrChange {
                key: before.key_report(),
                before: before.content_report(),
                after: after.content_report(),
            })
        })
        .collect();
    LeafChanges {
        gained,
        lost,
        ir_changed,
    }
}

type CallKey = (u64, [u8; 20], [u8; 4]);

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallState {
    Unregistered,
    RefusedKnown,
    Clear,
}

#[derive(Serialize)]
struct ContractCallChanges {
    unregistered_to_clear: Vec<CallKeyReport>,
    unregistered_to_refused_known: Vec<CallKeyReport>,
    clear_to_unregistered: Vec<CallKeyReport>,
    clear_to_refused_known: Vec<CallKeyReport>,
    refused_known_to_unregistered: Vec<CallKeyReport>,
    refused_known_to_clear: Vec<CallKeyReport>,
}

impl ContractCallChanges {
    fn empty() -> Self {
        Self {
            unregistered_to_clear: Vec::new(),
            unregistered_to_refused_known: Vec::new(),
            clear_to_unregistered: Vec::new(),
            clear_to_refused_known: Vec::new(),
            refused_known_to_unregistered: Vec::new(),
            refused_known_to_clear: Vec::new(),
        }
    }
}

#[derive(Serialize)]
struct CallKeyReport {
    chain_id: u64,
    contract: String,
    selector: String,
}

fn diff_contract_calls(
    base: &Snapshot,
    candidate: &Snapshot,
) -> Result<ContractCallChanges, String> {
    let base_known = base
        .build
        .catalogue
        .known_calls
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let candidate_known = candidate
        .build
        .catalogue
        .known_calls
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let base_clear = clear_calls(&base.build.catalogue.entries)?;
    let candidate_clear = clear_calls(&candidate.build.catalogue.entries)?;
    diff_call_sets(&base_known, &base_clear, &candidate_known, &candidate_clear)
}

fn clear_calls(entries: &[dbgen::erc7730::Emitted]) -> Result<BTreeSet<CallKey>, String> {
    let mut calls = BTreeSet::new();
    for entry in entries {
        if entry.context_kind != CTX_CONTRACT {
            continue;
        }
        let ir = Erc7730Ir::parse(&entry.ir_bytes).map_err(|error| {
            format!(
                "parse compiled contract IR for call-state diff ({}): {error:?}",
                entry.source.display()
            )
        })?;
        for format in ir.format_iter() {
            let format = format.map_err(|error| {
                format!(
                    "parse compiled contract format for call-state diff ({}): {error:?}",
                    entry.source.display()
                )
            })?;
            calls.insert((entry.chain_id, entry.contract, format.selector));
        }
    }
    Ok(calls)
}

fn diff_call_sets(
    base_known: &BTreeSet<CallKey>,
    base_clear: &BTreeSet<CallKey>,
    candidate_known: &BTreeSet<CallKey>,
    candidate_clear: &BTreeSet<CallKey>,
) -> Result<ContractCallChanges, String> {
    if !base_clear.is_subset(base_known) || !candidate_clear.is_subset(candidate_known) {
        return Err("internal: clear-call set is not a subset of exact known calls".to_string());
    }
    let keys = base_known
        .union(candidate_known)
        .copied()
        .chain(base_clear.union(candidate_clear).copied())
        .collect::<BTreeSet<_>>();
    let mut out = ContractCallChanges::empty();
    for key in keys {
        let before = call_state(&key, base_known, base_clear);
        let after = call_state(&key, candidate_known, candidate_clear);
        if before == after {
            continue;
        }
        let report = CallKeyReport {
            chain_id: key.0,
            contract: prefixed_hex(&key.1),
            selector: prefixed_hex(&key.2),
        };
        match (before, after) {
            (CallState::Unregistered, CallState::Clear) => out.unregistered_to_clear.push(report),
            (CallState::Unregistered, CallState::RefusedKnown) => {
                out.unregistered_to_refused_known.push(report)
            }
            (CallState::Clear, CallState::Unregistered) => out.clear_to_unregistered.push(report),
            (CallState::Clear, CallState::RefusedKnown) => out.clear_to_refused_known.push(report),
            (CallState::RefusedKnown, CallState::Unregistered) => {
                out.refused_known_to_unregistered.push(report)
            }
            (CallState::RefusedKnown, CallState::Clear) => out.refused_known_to_clear.push(report),
            _ => unreachable!("identity call-state transitions were filtered"),
        }
    }
    Ok(out)
}

fn call_state(key: &CallKey, known: &BTreeSet<CallKey>, clear: &BTreeSet<CallKey>) -> CallState {
    if clear.contains(key) {
        CallState::Clear
    } else if known.contains(key) {
        CallState::RefusedKnown
    } else {
        CallState::Unregistered
    }
}

#[derive(Serialize)]
struct SkipCategoryDelta {
    category: String,
    base: usize,
    candidate: usize,
    delta: i64,
}

fn diff_skip_categories(
    base: &[dbgen::erc7730::SkipReport],
    candidate: &[dbgen::erc7730::SkipReport],
) -> Result<Vec<SkipCategoryDelta>, String> {
    let base = skip_counts(base);
    let candidate = skip_counts(candidate);
    let categories = base
        .keys()
        .chain(candidate.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    categories
        .into_iter()
        .map(|category| {
            let before = *base.get(&category).unwrap_or(&0);
            let after = *candidate.get(&category).unwrap_or(&0);
            let before_i64 = i64::try_from(before)
                .map_err(|_| format!("skip count does not fit i64: {before}"))?;
            let after_i64 = i64::try_from(after)
                .map_err(|_| format!("skip count does not fit i64: {after}"))?;
            Ok(SkipCategoryDelta {
                category,
                base: before,
                candidate: after,
                delta: after_i64 - before_i64,
            })
        })
        .collect()
}

fn skip_counts(skips: &[dbgen::erc7730::SkipReport]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for skip in skips {
        *counts
            .entry(dbgen::erc7730::review_skip_category(&skip.reason).to_string())
            .or_insert(0) += 1;
    }
    counts
}

#[derive(Serialize)]
struct CurationCollision {
    path: String,
    kind: &'static str,
    expected_upstream_sha256: String,
    candidate_sha256: Option<String>,
    replacement_sha256: String,
}

fn curation_collisions(
    replacements: &[ReplacementIdentity],
    candidate_files: &BTreeMap<String, FileVersion>,
) -> Vec<CurationCollision> {
    replacements
        .iter()
        .filter_map(|replacement| {
            let candidate = candidate_files.get(&replacement.path);
            let candidate_hash = candidate.and_then(|file| decode_sha256(&file.sha256));
            if candidate_hash == Some(replacement.upstream_sha256) {
                return None;
            }
            let kind = match candidate_hash {
                None => "removed",
                Some(hash) if hash == replacement.replacement_sha256 => "upstreamed_replacement",
                Some(_) => "upstream_modified",
            };
            Some(CurationCollision {
                path: replacement.path.clone(),
                kind,
                expected_upstream_sha256: hex::encode(replacement.upstream_sha256),
                candidate_sha256: candidate.map(|file| file.sha256.clone()),
                replacement_sha256: hex::encode(replacement.replacement_sha256),
            })
        })
        .collect()
}

fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    let decoded = hex::decode(value).ok()?;
    decoded.try_into().ok()
}

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn args_require_each_root_and_reject_duplicates_or_unknowns() {
        assert!(parse_args(&strings(&["--base-root", "a", "--candidate-root", "b"])).is_ok());
        for args in [
            strings(&["--base-root", "a"]),
            strings(&["--candidate-root", "b"]),
            strings(&[
                "--base-root",
                "a",
                "--base-root",
                "b",
                "--candidate-root",
                "c",
            ]),
            strings(&["--base-root", "a", "--candidate-root", "b", "--write"]),
        ] {
            assert!(parse_args(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn file_diff_is_sorted_and_distinguishes_add_remove_change() {
        let file = |path: &str, hash: &str| FileVersion {
            path: path.to_string(),
            bytes: 1,
            sha256: hash.to_string(),
        };
        let base = [
            ("b.json".to_string(), file("b.json", "bb")),
            ("c.json".to_string(), file("c.json", "cc")),
        ]
        .into_iter()
        .collect();
        let candidate = [
            ("a.json".to_string(), file("a.json", "aa")),
            ("c.json".to_string(), file("c.json", "dd")),
        ]
        .into_iter()
        .collect();
        let diff = diff_files(&base, &candidate);
        assert_eq!(diff.added[0].path, "a.json");
        assert_eq!(diff.removed[0].path, "b.json");
        assert_eq!(diff.changed[0].path, "c.json");
    }

    fn call(index: u8) -> CallKey {
        (u64::from(index), [index; 20], [index; 4])
    }

    #[test]
    fn exact_call_diff_covers_all_six_non_identity_transitions() {
        let base_known = [call(1), call(2), call(3), call(4)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let base_clear = [call(1), call(2)].into_iter().collect::<BTreeSet<_>>();
        let candidate_known = [call(2), call(3), call(5), call(6)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let candidate_clear = [call(3), call(5)].into_iter().collect::<BTreeSet<_>>();
        let diff =
            diff_call_sets(&base_known, &base_clear, &candidate_known, &candidate_clear).unwrap();
        assert_eq!(diff.clear_to_refused_known.len(), 1); // 2
        assert_eq!(diff.refused_known_to_clear.len(), 1); // 3
        assert_eq!(diff.refused_known_to_unregistered.len(), 1); // 4
        assert_eq!(diff.unregistered_to_clear.len(), 1); // 5
        assert_eq!(diff.unregistered_to_refused_known.len(), 1); // 6

        let mut candidate_known = candidate_known;
        candidate_known.insert(call(1));
        candidate_known.remove(&call(2));
        let candidate_clear = [call(3), call(5)].into_iter().collect();
        let diff =
            diff_call_sets(&base_known, &base_clear, &candidate_known, &candidate_clear).unwrap();
        assert_eq!(diff.clear_to_unregistered.len(), 1); // 2
    }

    fn leaf(key: LeafKey, ir: &[u8]) -> LeafRecord {
        LeafRecord {
            key,
            source: "registry/test/calldata-test.json".to_string(),
            descriptor_id: "test".to_string(),
            descriptor_sha256: [1; 32],
            erc8176_sha256: [2; 32],
            ir_sha256: Sha256::digest(ir).into(),
            ir_bytes: ir.len(),
            ir: ir.to_vec(),
        }
    }

    #[test]
    fn leaf_diff_distinguishes_gained_lost_and_same_key_ir_change() {
        let key = |index| LeafKey {
            context_kind: CTX_CONTRACT,
            chain_id: index,
            contract: [index as u8; 20],
            primary_type_hash: [0; 32],
        };
        let base = [
            (key(1), leaf(key(1), b"old")),
            (key(2), leaf(key(2), b"lost")),
        ]
        .into_iter()
        .collect();
        let candidate = [
            (key(1), leaf(key(1), b"new")),
            (key(3), leaf(key(3), b"gained")),
        ]
        .into_iter()
        .collect();
        let diff = diff_leaf_maps(&base, &candidate);
        assert_eq!(diff.gained.len(), 1);
        assert_eq!(diff.lost.len(), 1);
        assert_eq!(diff.ir_changed.len(), 1);
    }

    #[test]
    fn curation_collision_classification_is_stable() {
        let replacements = [
            ReplacementIdentity {
                path: "registry/a.json".to_string(),
                upstream_sha256: [1; 32],
                replacement_sha256: [2; 32],
            },
            ReplacementIdentity {
                path: "registry/b.json".to_string(),
                upstream_sha256: [3; 32],
                replacement_sha256: [4; 32],
            },
            ReplacementIdentity {
                path: "registry/c.json".to_string(),
                upstream_sha256: [5; 32],
                replacement_sha256: [6; 32],
            },
        ];
        let candidate = [
            (
                "registry/a.json".to_string(),
                FileVersion {
                    path: "registry/a.json".to_string(),
                    bytes: 1,
                    sha256: hex::encode([2; 32]),
                },
            ),
            (
                "registry/b.json".to_string(),
                FileVersion {
                    path: "registry/b.json".to_string(),
                    bytes: 1,
                    sha256: hex::encode([9; 32]),
                },
            ),
        ]
        .into_iter()
        .collect();
        let collisions = curation_collisions(&replacements, &candidate);
        assert_eq!(collisions.len(), 3);
        assert_eq!(collisions[0].kind, "upstreamed_replacement");
        assert_eq!(collisions[1].kind, "upstream_modified");
        assert_eq!(collisions[2].kind, "removed");
    }
}
