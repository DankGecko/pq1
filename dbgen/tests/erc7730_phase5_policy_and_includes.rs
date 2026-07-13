//! Phase 5 items 1 + 2 — production policy gate + `includes` resolution.
//!
//! Item 1 (production policy gate): exercises `build_db_with_policy_override`.
//!   - Default (force_production = false): existing seed corpus builds clean.
//!   - Override (force_production = true): fails closed because real ERC-8176
//!     EAS verification is not implemented; embedded attester names never count.
//!
//! Item 2 (`includes` resolution): exercises the local-filesystem resolver
//! `dbgen::erc7730::compile_descriptor`'s new `registry_root` parameter.
//!   - Positive: relative include, registry-relative include, deep-merge.
//!   - Negative: include without `--registry-root`, escape attempt
//!     (`../../etc/passwd`), recursion depth cap.

use std::fs;
use std::path::PathBuf;

use dbgen::erc7730::{
    build_db, build_db_tolerant, build_db_with_policy_override, CatalogueProvenance,
};

fn expect_err<T>(res: Result<T, String>, msg: &str) -> String {
    match res {
        Ok(_) => panic!("{msg}"),
        Err(e) => e,
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

// ─────────────────────────────────────────────────────────────────────
// Item 1: production policy gate
// ─────────────────────────────────────────────────────────────────────

#[test]
fn dev_policy_accepts_unattested_seed_corpus() {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    let result = build_db_with_policy_override(&dir, &policy, false, None)
        .expect("dev policy must accept the seed corpus");
    assert_eq!(result.provenance, CatalogueProvenance::DevUnattested);
    assert!(
        result
            .review_text
            .contains("# Provenance: dev-unattested\n"),
        "review artifact must carry machine-readable dev provenance"
    );
}

#[test]
fn production_policy_rejects_unattested_seed_corpus() {
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    let err = expect_err(
        build_db_with_policy_override(&dir, &policy, true, None),
        "production policy MUST reject while real ERC-8176 verification is unavailable",
    );
    assert!(
        err.contains("attestation") && err.contains("not implemented"),
        "unexpected production-rejection message: {err}"
    );
}

#[test]
fn build_db_default_matches_dev_override() {
    // Sanity: `build_db` (no override) and `build_db_with_policy_override(..,
    // false)` produce byte-identical output. Guards against accidental
    // semantic drift between the two entry points.
    let root = workspace_root();
    let dir = root.join("secure/data/erc7730");
    let policy = dir.join("policy.toml");
    let a = build_db(&dir, &policy).expect("default build");
    let b =
        build_db_with_policy_override(&dir, &policy, false, None).expect("override(false) build");
    assert_eq!(a.blob, b.blob, "blob diverged");
    assert_eq!(a.root, b.root, "root diverged");
}

#[test]
fn production_policy_never_accepts_legacy_embedded_attesters() {
    let dir = make_tempdir("legacy_attesters_not_production");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    let mut descriptor: serde_json::Value =
        serde_json::from_str(&transfer_descriptor("To", "Amount")).unwrap();
    descriptor["attestations"] = serde_json::json!([
        { "attester": "eip155:1:0x0000000000000000000000000000000000000001" },
        { "attester": "eip155:1:0x0000000000000000000000000000000000000002" }
    ]);
    fs::write(
        dir.join("descriptor.json"),
        serde_json::to_vec_pretty(&descriptor).unwrap(),
    )
    .unwrap();

    let err = expect_err(
        build_db_with_policy_override(&dir, &dir.join("policy.toml"), true, None),
        "legacy embedded attesters must never manufacture production provenance",
    );
    assert!(err.contains("not implemented"), "unexpected error: {err}");
    assert!(
        err.contains("obsolete descriptor-embedded `attestations`"),
        "rejection must name the obsolete evidence model: {err}"
    );
}

fn assert_descriptor_key_rejected(name: &str, key_path: &[&str]) {
    let dir = make_tempdir(name);
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    let mut descriptor: serde_json::Value =
        serde_json::from_str(&transfer_descriptor("To", "Amount")).unwrap();
    let mut cursor = &mut descriptor;
    for key in &key_path[..key_path.len() - 1] {
        cursor = cursor
            .get_mut(*key)
            .unwrap_or_else(|| panic!("missing fixture object at `{key}`"));
    }
    let rejected_key = key_path[key_path.len() - 1];
    cursor
        .as_object_mut()
        .expect("fixture key parent must be an object")
        .insert(
            rejected_key.to_string(),
            serde_json::json!({ "enabled": true }),
        );
    fs::write(
        dir.join("descriptor.json"),
        serde_json::to_vec_pretty(&descriptor).unwrap(),
    )
    .unwrap();

    let err = expect_err(
        build_db(&dir, &dir.join("policy.toml")),
        "unmodelled descriptor/context key must fail closed",
    );
    assert!(
        (err.contains("unknown field") || err.contains("unsupported"))
            && err.contains(rejected_key),
        "unexpected fail-closed error for `{rejected_key}`: {err}"
    );
}

#[test]
fn unknown_top_level_descriptor_key_is_rejected() {
    assert_descriptor_key_rejected("unknown_descriptor_key", &["futureTrustSemantics"]);
}

#[test]
fn unsupported_contract_proxy_context_is_rejected() {
    assert_descriptor_key_rejected(
        "unsupported_proxy_context",
        &["context", "contract", "proxy"],
    );
}

#[test]
fn unsupported_contract_state_refs_context_is_rejected() {
    assert_descriptor_key_rejected(
        "unsupported_state_refs_context",
        &["context", "contract", "stateRefs"],
    );
}

#[test]
fn unsupported_eip712_schemas_context_is_rejected() {
    let dir = make_tempdir("unsupported_eip712_schemas");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("descriptor.json"),
        r#"{
  "context": {
    "eip712": {
      "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }],
      "domain": { "name": "Schema Test", "version": "1" },
      "schemas": [{ "primaryType": "Order", "types": {} }]
    }
  },
  "metadata": { "owner": "Schema Test", "contractName": "SchemaTest" },
  "display": {
    "formats": {
      "Order(uint256 amount)": {
        "intent": "Order",
        "fields": [{ "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }]
      }
    }
  }
}"#,
    )
    .unwrap();

    let err = expect_err(
        build_db(&dir, &dir.join("policy.toml")),
        "unsupported EIP-712 schemas must fail closed",
    );
    assert!(
        err.contains("context.eip712.schemas") && err.contains("unsupported"),
        "unexpected schemas rejection: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// review 2.2: duplicate-leaf precedence (byte-identical dedup vs conflict)
// ─────────────────────────────────────────────────────────────────────

const POLICY_DEV_2: &str =
    "allow_unattested_dev_descriptors = true\nmin_attesters = 0\ntrusted_attesters = []\n";

/// A minimal compilable calldata descriptor for `transfer(address,uint256)` at
/// chain 1 / contract 0x…01, parameterised by the two field labels (so two
/// instances with different labels compile to DIFFERENT IR for the SAME leaf
/// key).
fn transfer_descriptor(to_label: &str, amt_label: &str) -> String {
    format!(
        r#"{{
  "context": {{ "contract": {{ "deployments": [{{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }}] }} }},
  "metadata": {{ "owner": "Dup Test", "contractName": "DupTest" }},
  "display": {{ "formats": {{ "transfer(address to, uint256 amount)": {{
      "intent": "Send",
      "fields": [
        {{ "path": "to", "format": "addressName", "label": "{to_label}", "visible": "always" }},
        {{ "path": "amount", "format": "raw", "label": "{amt_label}", "visible": "always" }}
      ] }} }} }}
}}"#
    )
}

#[test]
fn dup_leaf_byte_identical_is_deduped_not_error() {
    // Same (chain, contract) in two differently-named files with IDENTICAL
    // content → identical IR → benign dedup: build succeeds, one leaf, and the
    // drop is recorded as a byte-identical skip (review 2.2).
    let dir = make_tempdir("dup_identical");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let d = transfer_descriptor("To", "Amount");
    fs::write(dir.join("calldata-a.json"), &d).unwrap();
    fs::write(dir.join("calldata-b.json"), &d).unwrap();

    let (res, skips) = build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir))
        .expect("byte-identical dup must dedupe cleanly, not error");
    assert_eq!(res.leaf_count, 1, "identical dup must collapse to one leaf");
    assert!(
        skips.iter().any(|s| s.reason.contains("byte-identical")),
        "the dropped identical dup must be recorded as byte-identical: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn dup_leaf_non_identical_is_conflict_error() {
    // Same (chain, contract) but DIFFERENT IR (different field labels) → the
    // device would trust whichever sorts first by filename (a silent trust-swap
    // on re-vendor). Must hard-error, not pick a filename-order winner.
    let dir = make_tempdir("dup_conflict");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-a.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-b.json"),
        transfer_descriptor("Recipient", "Value"),
    )
    .unwrap();

    let err = match build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)) {
        Ok(_) => panic!("non-identical dup MUST hard-error (review 2.2)"),
        Err(e) => e,
    };
    assert!(
        err.contains("CONFLICT") && err.contains("non-identical duplicate"),
        "unexpected error for non-identical dup: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// review 1.3: unmodeled top-level field/format keys gate the format
// ─────────────────────────────────────────────────────────────────────

/// A clean, always-compilable transfer descriptor at contract 0x…02 (distinct
/// from the 0x…01 fixtures) so the tolerant build has ≥1 leaf — otherwise
/// build_db_tolerant errors with "no IR entries emitted" and drops `skips`.
const VALID_SIBLING_02: &str = r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000002" }] } },
  "metadata": { "owner": "Sib", "contractName": "Sib" },
  "display": { "formats": { "transfer(address to, uint256 amount)": {
      "intent": "Send",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ] } } }
}"#;

fn transfer_with_extra_field_key(extra_key: &str, extra_val: &str) -> String {
    format!(
        r#"{{
  "context": {{ "contract": {{ "deployments": [{{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }}] }} }},
  "metadata": {{ "owner": "T", "contractName": "T" }},
  "display": {{ "formats": {{ "transfer(address to, uint256 amount)": {{
      "intent": "Send",
      "fields": [
        {{ "path": "to", "format": "addressName", "label": "To", "visible": "always" }},
        {{ "path": "amount", "format": "raw", "label": "Amt", "visible": "always", "{extra_key}": {extra_val} }}
      ] }} }} }}
}}"#
    )
}

#[test]
fn unmodeled_field_key_is_skipped_with_reason() {
    // A field carrying a key dbgen doesn't model (a typo or foreign key) must
    // NOT silently compile — the format skips-loud, naming the offending key
    // (finding 1.3; the $ref-silent-drop failure class).
    let dir = make_tempdir("unmodeled_key");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-gated.json"),
        transfer_with_extra_field_key("bogusKey", "1"),
    )
    .unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("tolerant build");
    assert_eq!(res.leaf_count, 1, "only the clean sibling leaf survives");
    assert!(
        skips.iter().any(|s| s.reason.contains("unmodeled descriptor key")
            && s.reason.contains("bogusKey")),
        "skip must name the unmodeled key: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn semantic_key_encryption_is_gated_not_ignored() {
    // `encryption` is a VALID v2 key, but dbgen doesn't implement it; rendering
    // as if absent would mis-represent the field, so it must gate (skip-loud),
    // not silently ignore (finding 1.3).
    let dir = make_tempdir("encryption_gated");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(
        dir.join("calldata-gated.json"),
        transfer_with_extra_field_key("encryption", r#"{"a":1}"#),
    )
    .unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("tolerant build");
    assert_eq!(res.leaf_count, 1, "only the clean sibling leaf survives");
    assert!(
        skips
            .iter()
            .any(|s| s.reason.contains("unmodeled descriptor key")
                && s.reason.contains("encryption")),
        "encryption must gate the format: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn unmodeled_key_in_definition_body_is_gated() {
    // finding 1.3 (definitions-body bypass, verify pass 2026-07-02): an
    // unmodeled key on a $.display.definitions BODY must gate through the $ref
    // channel, exactly like one on the reference object or an inline field —
    // otherwise resolve_display_refs silently discards it on merge (the 1.1
    // silent-drop class, through the very mechanism 1.1 introduced).
    let dir = make_tempdir("def_body_key");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    let d = r#"{
      "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }] } },
      "metadata": { "owner": "T", "contractName": "T" },
      "display": {
        "definitions": { "amt": { "format": "raw", "label": "Amt", "bogusDefKey": 1 } },
        "formats": { "transfer(address to, uint256 amount)": {
          "intent": "Send",
          "fields": [
            { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
            { "path": "amount", "$ref": "$.display.definitions.amt", "visible": "always" }
          ] } } }
    }"#;
    fs::write(dir.join("calldata-gated.json"), d).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("tolerant build");
    assert_eq!(
        res.leaf_count, 1,
        "only the clean sibling survives; the def-body key must gate"
    );
    assert!(
        skips
            .iter()
            .any(|s| s.reason.contains("unmodeled key") && s.reason.contains("bogusDefKey")),
        "skip must name the definition-body key: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );
}

#[test]
fn misnamed_descriptor_is_flagged_unscanned() {
    // review 2.3 (filename-convention tripwire): a *.json that carries a
    // descriptor shape (context+display) but doesn't match calldata-*/eip712-*
    // would be SILENTLY dropped by the scanner on an upstream rename. It must
    // instead be flagged UNSCANNED in the (drift-gated) skip report.
    let dir = make_tempdir("misnamed");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    // Mis-named (wrong prefix) — looks like a descriptor, must be flagged.
    fs::write(
        dir.join("swapRouter.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert_eq!(
        res.leaf_count, 1,
        "only the correctly-named descriptor is scanned"
    );
    assert!(
        skips.iter().any(|s| s.reason.contains("UNSCANNED")
            && s.source.file_name().and_then(|n| n.to_str()) == Some("swapRouter.json")),
        "mis-named descriptor must be flagged UNSCANNED: {:?}",
        skips.iter().map(|s| &s.reason).collect::<Vec<_>>()
    );

    // Coverage may follow the filename convention, but omission protection
    // must not. The misnamed file still declares mainnet contract 0x...01 and
    // transfer(address,uint256), so stripping its clear-sign proof must refuse
    // instead of restoring the blind-sign rung.
    let mut contract = [0u8; 20];
    contract[19] = 1;
    let digest = pqsigner_tx_core::hash::keccak256(b"transfer(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn deployed_common_descriptor_is_flagged_and_covered_by_omission_filter() {
    // `common-*` is only a naming convention for include templates. It cannot
    // exempt a file that independently carries context+display: upstream may
    // add deployments to a former template, and silently skipping that file
    // would otherwise restore blind-signing for its declared calls.
    let dir = make_tempdir("deployed_common");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("common-deployed.json"),
        transfer_descriptor("To", "Amount").replace(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000003",
        ),
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert_eq!(
        res.leaf_count, 1,
        "the common-* descriptor is tripwired, not renderer-compiled"
    );
    assert!(
        skips.iter().any(|skip| {
            skip.reason.contains("UNSCANNED")
                && skip.source.file_name().and_then(|name| name.to_str())
                    == Some("common-deployed.json")
        }),
        "deployed common-* descriptor must be visible in the skip receipt: {:?}",
        skips.iter().map(|skip| &skip.reason).collect::<Vec<_>>()
    );

    let mut contract = [0u8; 20];
    contract[19] = 3;
    let digest = pqsigner_tx_core::hash::keccak256(b"transfer(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn unscanned_child_with_deployments_and_included_formats_is_known() {
    let dir = make_tempdir("unscanned_child_include");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("common-format.json"),
        r#"{
  "metadata": { "owner": "Template", "contractName": "Template" },
  "display": { "formats": {
    "splitCall(address to,uint256 amount)": {
      "intent": "Split",
      "fields": [
        { "path": "to", "format": "addressName", "label": "To", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    }
  } }
}"#,
    )
    .unwrap();
    fs::write(
        dir.join("common-child.json"),
        r#"{
  "\u0063ontext": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000004" }
  ] } },
  "includes": "common-format.json"
}"#,
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert!(skips.iter().any(|skip| {
        skip.reason.contains("UNSCANNED")
            && skip.source.file_name().and_then(|name| name.to_str()) == Some("common-child.json")
    }));
    let mut contract = [0u8; 20];
    contract[19] = 4;
    let digest = pqsigner_tx_core::hash::keccak256(b"splitCall(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn duplicate_parameter_names_are_unrenderable_but_selector_remains_known() {
    let dir = make_tempdir("duplicate_names_known");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("calldata-duplicate.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000005" }
  ] } },
  "metadata": { "owner": "Rejected", "contractName": "Rejected" },
  "display": { "formats": {
    "f(address to,uint256 to)": { "intent": "Rejected", "fields": [] }
  } }
}"#,
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert!(skips
        .iter()
        .any(|skip| skip.reason.contains("duplicate top-level argument name")));
    let mut contract = [0u8; 20];
    contract[19] = 5;
    let digest = pqsigner_tx_core::hash::keccak256(b"f(address,uint256)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn test_fixture_paths_are_not_omission_filter_escape_hatches() {
    let dir = make_tempdir("test_fixture_paths_known");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::create_dir_all(dir.join("tests")).unwrap();

    let descriptor = |last_byte: u8, signature: &str| {
        format!(
            r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "0x00000000000000000000000000000000000000{last_byte:02x}" }}
  ] }} }},
  "metadata": {{ "owner": "Fixture", "contractName": "Fixture" }},
  "display": {{ "formats": {{
    "{signature}": {{ "intent": "Fixture", "fields": [] }}
  }} }}
}}"#
        )
    };
    fs::write(
        dir.join("calldata-hidden.tests.backdoor.json"),
        descriptor(0x61, "suffixFixture(uint256 value)"),
    )
    .unwrap();
    fs::write(
        dir.join("tests/calldata-hidden.json"),
        descriptor(0x62, "directoryFixture(address target)"),
    )
    .unwrap();

    let (res, skips) =
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
    assert!(
        skips
            .iter()
            .filter(|skip| skip.reason.contains("UNSCANNED"))
            .count()
            >= 2,
        "both fixture-named descriptors need visible omission-scan receipts"
    );

    for (last_byte, signature) in [
        (0x61, "suffixFixture(uint256)"),
        (0x62, "directoryFixture(address)"),
    ] {
        let mut contract = [0u8; 20];
        contract[19] = last_byte;
        let digest = pqsigner_tx_core::hash::keccak256(signature.as_bytes());
        let selector = [digest[0], digest[1], digest[2], digest[3]];
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &res.known_calls_bloom,
            1,
            &contract,
            &selector,
        ));
    }
}

#[test]
fn malformed_contract_selector_grammar_fails_the_catalogue_closed() {
    for (case, signature, expected) in [
        (
            "invalid_function_name",
            "transfer.foo(address to,uint256 amount)",
            "expected `(`",
        ),
        (
            "digit_function_name",
            "1transfer(uint256 amount)",
            "invalid function name",
        ),
        (
            "invalid_uint_width",
            "badWidth(uint7 value)",
            "unsupported ABI type `uint7`",
        ),
        (
            "invalid_bytes_width",
            "badBytes(bytes33 value)",
            "unsupported ABI type `bytes33`",
        ),
        (
            "custom_type",
            "custom(Foo value)",
            "unsupported ABI type `Foo`",
        ),
    ] {
        let dir = make_tempdir(case);
        fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
        fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
        fs::write(
            dir.join("calldata-hostile.json"),
            format!(
                r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "0x0000000000000000000000000000000000000063" }}
  ] }} }},
  "metadata": {{ "owner": "Hostile", "contractName": "Hostile" }},
  "display": {{ "formats": {{
    "{signature}": {{ "intent": "Hostile", "fields": [] }}
  }} }}
}}"#
            ),
        )
        .unwrap();
        let error = expect_err(
            build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
            "noncanonical selector grammar must abort omission preflight",
        );
        assert!(error.contains(expected), "{case}: {error}");
    }
}

#[test]
fn sibling_ercs_json_is_always_omission_scanned() {
    let root = make_tempdir("sibling_ercs_known");
    let registry = root.join("registry");
    let ercs = root.join("ercs");
    fs::create_dir_all(&registry).unwrap();
    fs::create_dir_all(&ercs).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(registry.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        ercs.join("common-live-binding.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000064" }
  ] } },
  "display": { "formats": {
    "ercsOnly(bytes32 value)": { "intent": "Support template", "fields": [] }
  } }
}"#,
    )
    .unwrap();

    let (res, _) = build_db_tolerant(&registry, &root.join("policy.toml"), Some(&root))
        .expect("sibling ercs scan");
    let mut contract = [0u8; 20];
    contract[19] = 0x64;
    let digest = pqsigner_tx_core::hash::keccak256(b"ercsOnly(bytes32)");
    let selector = [digest[0], digest[1], digest[2], digest[3]];
    assert!(pqsigner_erc7730::known_calls::may_contain(
        &res.known_calls_bloom,
        1,
        &contract,
        &selector,
    ));
}

#[test]
fn uppercase_json_extension_is_rejected_not_silently_omitted() {
    let dir = make_tempdir("uppercase_json");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("calldata-hidden.JSON"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "uppercase JSON extension must fail closed",
    );
    assert!(err.contains("non-canonical JSON filename"), "{err}");
}

// ─────────────────────────────────────────────────────────────────────
// Item 2: `includes` resolution
// ─────────────────────────────────────────────────────────────────────
//
// Strategy: create a per-test tempdir with (a) a tiny "registry" mirror
// holding template fragments, (b) a descriptor that references the
// template via `"includes"`, (c) a policy.toml. Run the compiler and
// assert the merge happened (or was correctly refused).
//
// We use std::env::temp_dir() + a per-test subdir; no extra crate dep.

fn make_tempdir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("dbgen_phase5_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create tempdir");
    p
}

const POLICY_DEV: &str =
    "allow_unattested_dev_descriptors = true\nmin_attesters = 0\ntrusted_attesters = []\n";

const TEMPLATE_PERMIT: &str = r#"{
  "metadata": { "owner": "Permit Template" },
  "display": { "formats": { "templated()": { "intent": "Templated intent from include" } } }
}"#;

const DESCRIPTOR_WITH_RELATIVE_INCLUDE: &str = r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }] } },
  "includes": "./template_permit.json",
  "display": { "formats": { "transfer(address,uint256)": { "intent": "Local override wins" } } }
}"#;

const DESCRIPTOR_WITH_REGISTRY_INCLUDE: &str = r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000002" }] } },
  "includes": "templates/permit.json"
}"#;

#[test]
fn include_relative_path_resolves_against_descriptor_dir() {
    let dir = make_tempdir("rel_include");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(dir.join("template_permit.json"), TEMPLATE_PERMIT).unwrap();
    fs::write(
        dir.join("descriptor.json"),
        DESCRIPTOR_WITH_RELATIVE_INCLUDE,
    )
    .unwrap();

    // registry_root is required for *any* include, even relative ones —
    // the sandbox check canonicalises and verifies the resolved path is
    // inside the registry_root. So we pass the tempdir as both.
    let res = build_db_with_policy_override(&dir, &dir.join("policy.toml"), false, Some(&dir));
    // We don't assert on the full IR (the test fixture is minimal and
    // may not pass full schema validation) — but the error, if any,
    // must NOT be the "includes requires --registry-root" rejection.
    if let Err(e) = res {
        assert!(
            !e.contains("requires `--registry-root`"),
            "include resolution didn't fire: {e}"
        );
    }
}

#[test]
fn nested_include_is_relative_to_the_immediate_including_file() {
    let root = make_tempdir("nested_include_relative_base");
    let registry = root.join("registry");
    let project = registry.join("project");
    let sub = project.join("sub");
    fs::create_dir_all(&sub).unwrap();
    fs::write(root.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(registry.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        project.join("calldata-leaf.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000071" }
  ] } },
  "metadata": { "owner": "Nested", "contractName": "Nested" },
  "includes": "sub/base.json"
}"#,
    )
    .unwrap();
    fs::write(sub.join("base.json"), r#"{ "includes": "common.json" }"#).unwrap();
    fs::write(
        sub.join("common.json"),
        r#"{ "display": { "formats": {
  "correctNested()": { "intent": "Correct nested include", "fields": [] }
} } }"#,
    )
    .unwrap();
    fs::write(
        project.join("common.json"),
        r#"{ "display": { "formats": {
  "wrongParent()": { "intent": "Wrong parent include", "fields": [] }
} } }"#,
    )
    .unwrap();

    let (res, _) = build_db_tolerant(&registry, &root.join("policy.toml"), Some(&root))
        .expect("nested include build");
    let entry = res
        .entries
        .iter()
        .find(|entry| entry.contract[19] == 0x71)
        .expect("nested include deployment emitted");
    let ir = pqsigner_erc7730::ir::Erc7730Ir::parse(&entry.ir_bytes).expect("parse emitted IR");
    let selectors: Vec<[u8; 4]> = ir
        .format_iter()
        .map(|format| format.expect("format").selector)
        .collect();
    let correct = pqsigner_tx_core::hash::keccak256(b"correctNested()");
    assert_eq!(
        selectors,
        vec![[correct[0], correct[1], correct[2], correct[3]]]
    );
}

#[test]
fn include_without_registry_root_is_rejected() {
    let dir = make_tempdir("no_root");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("descriptor.json"),
        DESCRIPTOR_WITH_REGISTRY_INCLUDE,
    )
    .unwrap();

    let err = expect_err(
        build_db_with_policy_override(
            &dir,
            &dir.join("policy.toml"),
            false,
            None, // no registry root → must fail
        ),
        "includes without registry_root MUST fail",
    );
    assert!(
        err.contains("`--registry-root`") || err.contains("registry-root"),
        "unexpected error: {err}"
    );
}

#[test]
fn broken_include_fails_the_catalogue_closed() {
    // Even when the child has enough raw information to recover this one call,
    // a broken include may contain additional deployments or formats. Tolerant
    // renderer compilation is not permission to publish a possibly incomplete
    // known-call filter, so the whole catalogue must fail closed.
    let dir = make_tempdir("broken_include_known_call");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("calldata-valid.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();

    let broken = r#"{
      "context": { "contract": { "deployments": [
        { "chainId": 1, "address": "0x0000000000000000000000000000000000000002" }
      ] } },
      "includes": "missing-template.json",
      "metadata": { "owner": "Broken Include", "contractName": "Broken" },
      "display": { "formats": {
        "swap(address target,uint256 amount)": {
          "intent": "Swap",
          "fields": [
            { "path": "target", "label": "Target", "format": "addressName" },
            { "path": "amount", "label": "Amount", "format": "raw" }
          ]
        }
      } }
    }"#;
    fs::write(dir.join("calldata-broken.json"), broken).unwrap();

    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "a broken include must fail the entire catalogue closed",
    );
    assert!(
        err.contains("calldata-broken.json")
            && err.contains("known-call omission scan failed closed")
            && err.contains("missing-template.json"),
        "unexpected fail-closed diagnostic: {err}"
    );
    assert!(
        !err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must not contain the checkout/temp root: {err}"
    );
}

#[test]
fn non_string_include_fails_split_declaration_closed() {
    let dir = make_tempdir("non_string_include_known_call");
    fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
    fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
    fs::write(
        dir.join("calldata-non-string-include.json"),
        r#"{
  "context": { "contract": { "deployments": [
    { "chainId": 1, "address": "0x0000000000000000000000000000000000000065" }
  ] } },
  "includes": ["common-format.json"]
}"#,
    )
    .unwrap();
    fs::write(
        dir.join("common-format.json"),
        r#"{
  "display": { "formats": {
    "splitCall(address target,uint256 amount)": {
      "intent": "Split",
      "fields": [
        { "path": "target", "format": "addressName", "label": "Target", "visible": "always" },
        { "path": "amount", "format": "raw", "label": "Amount", "visible": "always" }
      ]
    }
  } }
}"#,
    )
    .unwrap();

    let error = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "a present non-string include must fail the catalogue closed",
    );
    assert!(
        error.contains("calldata-non-string-include.json")
            && error.contains("known-call omission scan failed closed")
            && error.contains("`includes` must be a string"),
        "unexpected fail-closed diagnostic: {error}"
    );
}

#[test]
fn selector_parser_differentials_are_not_emitted_but_remain_known() {
    for (case, signature, canonical, last_byte) in [
        (
            "alias_selector_disagreement",
            "aliasCall(uint value)",
            "aliasCall(uint256)",
            0x66,
        ),
        (
            "array_selector_disagreement",
            "arrayCall(uint256 [2] value)",
            "arrayCall(uint256[2])",
            0x67,
        ),
    ] {
        let dir = make_tempdir(case);
        fs::write(dir.join("policy.toml"), POLICY_DEV_2).unwrap();
        fs::write(dir.join("calldata-valid.json"), VALID_SIBLING_02).unwrap();
        fs::write(
            dir.join("calldata-differential.json"),
            format!(
                r#"{{
  "context": {{ "contract": {{ "deployments": [
    {{ "chainId": 1, "address": "0x00000000000000000000000000000000000000{last_byte:02x}" }}
  ] }} }},
  "metadata": {{ "owner": "Differential", "contractName": "Differential" }},
  "display": {{ "formats": {{
    "{signature}": {{
      "intent": "Differential",
      "fields": [
        {{ "path": "value", "format": "raw", "label": "Value", "visible": "always" }}
      ]
    }}
  }} }}
}}"#
            ),
        )
        .unwrap();

        let (result, skips) =
            build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)).expect("build");
        assert!(
            skips
                .iter()
                .any(|skip| skip.reason.contains("selector parser disagreement")),
            "the parser disagreement must be visible in the review receipt"
        );
        let mut contract = [0u8; 20];
        contract[19] = last_byte;
        assert!(
            !result
                .entries
                .iter()
                .any(|entry| entry.chain_id == 1 && entry.contract == contract),
            "a parser disagreement must not emit an authenticated leaf"
        );
        let digest = pqsigner_tx_core::hash::keccak256(canonical.as_bytes());
        let selector = [digest[0], digest[1], digest[2], digest[3]];
        assert!(pqsigner_erc7730::known_calls::may_contain(
            &result.known_calls_bloom,
            1,
            &contract,
            &selector,
        ));
    }
}

#[test]
fn malformed_raw_descriptor_fails_tolerant_catalogue_closed() {
    // The renderer build is tolerant only after the independent known-call
    // scan succeeds. A malformed selected descriptor may still have intended
    // deployments/formats that cannot be recovered, so it cannot become a
    // renderer skip while silently disappearing from the Bloom filter.
    let dir = make_tempdir("malformed_raw_known_call");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("calldata-valid.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("calldata-malformed.json"),
        r#"{ "context": { "contract": { "deployments": [] } }, "display": "#,
    )
    .unwrap();

    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "malformed raw descriptor must fail the entire catalogue closed",
    );
    assert!(
        err.contains("calldata-malformed.json")
            && err.contains("known-call omission scan failed closed")
            && err.contains("parse:"),
        "unexpected fail-closed diagnostic: {err}"
    );
    assert!(
        !err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must not contain the checkout/temp root: {err}"
    );
}

#[test]
fn child_deployments_with_all_formats_in_broken_include_fail_closed() {
    // This is the false-negative shape a selected-file-only scan cannot recover: the
    // child declares deployments, while every callable format is supplied by
    // an include. If that include is malformed, the child contributes zero raw
    // tuples. Silently tolerating resolution failure would publish a Bloom
    // filter that forgets the known call entirely. Every unselected JSON is
    // now parsed independently, so the malformed template itself is the first
    // deterministic fail-closed source in sorted order.
    let dir = make_tempdir("child_deployments_include_formats");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        dir.join("calldata-valid.json"),
        transfer_descriptor("To", "Amount"),
    )
    .unwrap();
    fs::write(
        dir.join("common-all-formats.json"),
        r#"{
          "display": { "formats": {
            "swap(address target,uint256 amount)": { "intent": "Swap" }
          } }
        } trailing-invalid-json"#,
    )
    .unwrap();
    fs::write(
        dir.join("calldata-child.json"),
        r#"{
          "context": { "contract": { "deployments": [
            { "chainId": 1, "address": "0x0000000000000000000000000000000000000004" }
          ] } },
          "includes": "common-all-formats.json",
          "metadata": { "owner": "Child", "contractName": "Child" }
        }"#,
    )
    .unwrap();

    let err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "unrecoverable include declarations must fail closed",
    );
    assert!(
        err.contains("common-all-formats.json")
            && err.contains("known-call omission scan failed closed")
            && err.contains("parse:"),
        "unexpected fail-closed diagnostic: {err}"
    );
    assert!(
        !err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must not contain the checkout/temp root: {err}"
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_regular_file_name_fails_collectors_closed() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = make_tempdir("non_utf8_name");
    fs::write(dir.join("policy.toml"), POLICY_DEV).unwrap();
    let bad_name = OsString::from_vec(b"calldata-\xff.json".to_vec());
    fs::write(dir.join(bad_name), transfer_descriptor("To", "Amount")).unwrap();

    let tolerant_err = expect_err(
        build_db_tolerant(&dir, &dir.join("policy.toml"), Some(&dir)),
        "tolerant collector must reject a non-UTF-8 regular-file name",
    );
    assert!(
        tolerant_err.contains("non-UTF-8 regular-file name"),
        "unexpected tolerant diagnostic: {tolerant_err}"
    );
    assert!(
        !tolerant_err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must be checkout-path-independent: {tolerant_err}"
    );

    let strict_err = expect_err(
        build_db(&dir, &dir.join("policy.toml")),
        "strict collector must reject a non-UTF-8 regular-file name",
    );
    assert!(
        strict_err.contains("non-UTF-8 regular-file name"),
        "unexpected strict diagnostic: {strict_err}"
    );
    assert!(
        !strict_err.contains(dir.to_string_lossy().as_ref()),
        "diagnostic must be checkout-path-independent: {strict_err}"
    );
}

#[test]
fn include_escape_outside_registry_root_is_rejected() {
    // Build the descriptor in a tempdir, point registry_root at a
    // *sibling* directory, and have the include attempt to escape via
    // `../`. The canonicalisation-then-prefix check must refuse.
    let parent = make_tempdir("escape");
    let registry = parent.join("registry");
    let descriptors = parent.join("descriptors");
    fs::create_dir_all(&registry).unwrap();
    fs::create_dir_all(&descriptors).unwrap();
    fs::write(parent.join("OUTSIDE.json"), TEMPLATE_PERMIT).unwrap();
    fs::write(descriptors.join("policy.toml"), POLICY_DEV).unwrap();
    fs::write(
        descriptors.join("descriptor.json"),
        r#"{
  "context": { "contract": { "deployments": [{ "chainId": 1, "address": "0x0000000000000000000000000000000000000003" }] } },
  "includes": "../OUTSIDE.json"
}"#,
    )
    .unwrap();

    let err = expect_err(
        build_db_with_policy_override(
            &descriptors,
            &descriptors.join("policy.toml"),
            false,
            Some(&registry),
        ),
        "../-escape MUST be refused",
    );
    assert!(
        err.contains("outside registry-root") || err.contains("canonicalize"),
        "expected sandbox rejection, got: {err}"
    );
    assert!(
        !err.contains(parent.to_string_lossy().as_ref()),
        "sandbox rejection must not leak the host checkout/temp path: {err}"
    );
}
