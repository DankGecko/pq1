//! Construction evidence for the exact ERC-7730 forced-eligible partition.

#[cfg(feature = "nested-calldata-test-fixture")]
use dbgen::erc7730::build_e2e_db_with_policy_override_and_erc20_capabilities;
use dbgen::erc7730::{
    build_db_tolerant_with_erc20_capabilities, catalogue_status_v1, encode_forced_eligible_set,
    prove_forced_eligible_partition, recover_clear_contract_calls_from_p730,
};
use pqsigner_erc7730::forced_eligible::{
    ForcedEligibleSet, FORCED_ELIGIBLE_GROUP_LEN, FORCED_ELIGIBLE_HEADER_LEN,
    FORCED_ELIGIBLE_SELECTOR_LEN,
};
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn production_and_e2e_partitions_are_exact_and_fail_closed() {
    let root = workspace_root();
    let registry = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC-20 capabilities");
    let (mut production, _) = build_db_tolerant_with_erc20_capabilities(
        &registry.join("registry"),
        &policy,
        Some(&registry),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 catalogue");

    prove_forced_eligible_partition(&production).expect("prove production C/F partition");
    assert_eq!(production.known_call_count, 4_587);
    assert_eq!(production.clear_contract_call_count, 1_331);
    assert_eq!(production.forced_eligible_count, 3_256);
    assert_eq!(production.forced_eligible_group_count, 556);
    assert_eq!(production.forced_eligible_set.len(), 33_056);

    let clear = recover_clear_contract_calls_from_p730(&production.blob)
        .expect("recover C from final production P730");
    assert_eq!(clear.calls.len(), production.clear_contract_call_count);
    let clear_bytes = encode_forced_eligible_set(&clear.calls).expect("encode C shape probe");
    let clear_view = ForcedEligibleSet::from_bytes(&clear_bytes).expect("parse C shape probe");
    assert_eq!(clear_view.group_count(), 345);
    assert_eq!(clear_bytes.len(), 17_760);

    let known_bytes =
        encode_forced_eligible_set(&production.known_calls).expect("encode K shape probe");
    let known_view = ForcedEligibleSet::from_bytes(&known_bytes).expect("parse K shape probe");
    assert_eq!(known_view.group_count(), 777);
    assert_eq!(known_bytes.len(), 46_336);

    let forced_view = ForcedEligibleSet::from_bytes(&production.forced_eligible_set)
        .expect("parse production P73K");
    assert_eq!(
        production.forced_eligible_set.len(),
        FORCED_ELIGIBLE_HEADER_LEN
            + forced_view.group_count() as usize * FORCED_ELIGIBLE_GROUP_LEN
            + forced_view.tuple_count() as usize * FORCED_ELIGIBLE_SELECTOR_LEN
    );

    // Any P730 mutation invalidates C recovery before it can authorize a
    // partition. Mutate a proof byte so the authenticated IR itself remains
    // syntactically valid and the stored-proof consistency check is exercised.
    let proof_byte = production.blob.len() - 1;
    production.blob[proof_byte] ^= 1;
    assert!(prove_forced_eligible_partition(&production).is_err());
    production.blob[proof_byte] ^= 1;

    // A malformed P73K is rejected by the shared strict parser.
    let reserved_byte = FORCED_ELIGIBLE_HEADER_LEN + FORCED_ELIGIBLE_GROUP_LEN - 1;
    production.forced_eligible_set[reserved_byte] ^= 1;
    assert!(prove_forced_eligible_partition(&production).is_err());
    production.forced_eligible_set[reserved_byte] ^= 1;

    // A canonical, internally valid P73K still fails if it overlaps C. Keep
    // the retained counts consistent so this exercises the set-partition gate,
    // not a superficial metadata mismatch.
    let original_forced = production.forced_eligible_set.clone();
    let original_forced_groups = production.forced_eligible_group_count;
    let original_forced_count = production.forced_eligible_count;
    let mut overlapping: Vec<_> = ForcedEligibleSet::from_bytes(&production.forced_eligible_set)
        .expect("restored production P73K")
        .iter()
        .collect();
    overlapping.push(clear.calls[0]);
    overlapping.sort_unstable();
    production.forced_eligible_set =
        encode_forced_eligible_set(&overlapping).expect("encode overlapping P73K probe");
    let overlap_view = ForcedEligibleSet::from_bytes(&production.forced_eligible_set)
        .expect("overlap probe remains canonical P73K");
    production.forced_eligible_group_count = overlap_view.group_count() as usize;
    production.forced_eligible_count = overlap_view.tuple_count() as usize;
    assert!(prove_forced_eligible_partition(&production).is_err());
    production.forced_eligible_set = original_forced;
    production.forced_eligible_group_count = original_forced_groups;
    production.forced_eligible_count = original_forced_count;

    // P73S generation is itself gated on the union/Bloom proof.
    let bloom = production.known_calls_bloom;
    production.known_calls_bloom.fill(0);
    assert!(catalogue_status_v1(&production, [0; 32]).is_err());
    production.known_calls_bloom = bloom;
    prove_forced_eligible_partition(&production).expect("restored production partition");

    #[cfg(feature = "nested-calldata-test-fixture")]
    {
        let erc20_e2e = dbgen::erc20::build_db(&root.join("secure/data/erc20-e2e.json"))
            .expect("build e2e ERC-20 capabilities");
        let e2e = build_e2e_db_with_policy_override_and_erc20_capabilities(
            &root.join("secure/data/erc7730-e2e"),
            &policy,
            false,
            None,
            &erc20_e2e.capabilities,
        )
        .expect("build e2e ERC-7730 catalogue");
        prove_forced_eligible_partition(&e2e).expect("prove e2e C/F partition");
        assert_eq!(e2e.known_call_count, 27);
        assert_eq!(e2e.clear_contract_call_count, 27);
        assert_eq!(e2e.forced_eligible_count, 0);
        assert_eq!(e2e.forced_eligible_group_count, 0);
        assert_eq!(e2e.forced_eligible_set.len(), 16);
        assert_eq!(
            e2e.clear_contract_call_count + e2e.forced_eligible_count,
            e2e.known_call_count
        );
        let e2e_view = ForcedEligibleSet::from_bytes(&e2e.forced_eligible_set)
            .expect("parse e2e P73K, including canonical empty F if applicable");
        assert_eq!(e2e_view.tuple_count() as usize, e2e.forced_eligible_count);
    }
}
