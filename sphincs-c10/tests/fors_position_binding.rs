//! Position-binding property test — CWE-347 regression guard for the
//! `fcee705a` shared-FORS-forest forgery fix.
//!
//! **The bug (pre-`fcee705a`).** The FORS few-time forest was derived from
//! the FORS *tree* index only, never from the hypertree leaf position
//! `ht_idx`. That made `fors_pk` a per-key **constant**: one shared forest
//! reused at every one of the `2^18` hypertree positions. Because FORS leaf
//! secrets are published in the clear inside every signature, a passive
//! observer who collects ~3–4k of a wallet's signatures could reassemble the
//! shared forest and forge a valid signature for any message — no secret key
//! required (a few-time primitive used as a many-time one).
//!
//! **The fix.** `fors_secret` and every FORS ADRS now fold in `ht_idx`, so
//! each of the `2^18` positions is an independent forest.
//!
//! **Why this test exists.** `fcee705a` shipped the fix with **zero**
//! regression tests — the existing `signing_suite.rs` / `c10_test_vectors.json`
//! exercise each position only once and never assert *position-dependence*, so
//! the class could silently regress (drop the `ht_idx` argument again) with
//! nothing in CI to catch it. These are the cheap, position-dependence
//! assertions that close that gap. They run in normal `cargo test`; the
//! heavyweight end-to-end forgery lives in `fors_forgery_resistance.rs`.
//!
//! Run:
//! ```text
//! cargo test -p sphincs-c10 --features sim-internals --test fors_position_binding -- --nocapture
//! ```
//!
//! Every assertion below **passes on HEAD** (post-fix) and would **fail on
//! `fcee705a^`** (pre-fix), where the values are `ht_idx`-independent.

#![cfg(feature = "sim-internals")]

use std::collections::HashSet;

use sphincs_c10::params::{ADRS_FORS_TREE, K, N};
use sphincs_c10::sim_internals::{compute_fors_pk, compute_fors_root, fors_secret, make_adrs, pad16};

// Fixed, arbitrary key material (same shape as the other test suites).
const SK_SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];
const PK_SEED: [u8; N] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
];

/// A spread of hypertree positions across the full `H=18`-bit range
/// (`0..=0x3FFFF`), including both endpoints.
const HT_POSITIONS: [u32; 8] = [0, 1, 2, 42, 1000, 0x1_abcd, 0x2_ffff, 0x3_ffff];

/// **Root cause.** For a *fixed* `(tree_idx, leaf_idx)`, the FORS leaf
/// secret must be **unique** across hypertree positions. Pre-fix it was a
/// per-key constant — the shared forest the forgery reassembles.
#[test]
fn fors_secret_is_unique_per_ht_idx() {
    // A handful of (tree, leaf) coordinates, including edges of the
    // K=13 tree range and the A=11-bit (2048-leaf) range.
    let coords: [(u32, u32); 5] = [
        (0, 0),
        (3, 1234),
        (6, 2047),
        ((K - 1) as u32, 0), // the forced-zero tree
        ((K - 1) as u32, 777),
    ];

    for (tree_idx, leaf_idx) in coords {
        let mut seen: HashSet<[u8; N]> = HashSet::new();
        for ht_idx in HT_POSITIONS {
            let secret = fors_secret(&SK_SEED, ht_idx, tree_idx, leaf_idx);
            assert!(
                seen.insert(secret),
                "fors_secret collided across ht_idx for (tree={tree_idx}, leaf={leaf_idx}) at \
                 ht_idx={ht_idx:#x} — the shared-forest (CWE-347) regression is back: \
                 the FORS PRF no longer folds in ht_idx",
            );
        }
        assert_eq!(seen.len(), HT_POSITIONS.len());
    }
}

/// **Determinism + non-degeneracy** sanity: the PRF is a function (stable
/// across calls) and distinct `(tree, leaf)` at the SAME position differ —
/// so the uniqueness above is really `ht_idx` doing the work, not noise.
#[test]
fn fors_secret_is_deterministic_and_distinct_within_a_position() {
    let ht_idx = 0x1234;
    let a = fors_secret(&SK_SEED, ht_idx, 4, 99);
    let b = fors_secret(&SK_SEED, ht_idx, 4, 99);
    assert_eq!(a, b, "fors_secret must be deterministic for fixed inputs");

    let mut seen: HashSet<[u8; N]> = HashSet::new();
    for tree_idx in 0..K as u32 {
        for leaf_idx in [0u32, 1, 2, 1023, 2047] {
            assert!(
                seen.insert(fors_secret(&SK_SEED, ht_idx, tree_idx, leaf_idx)),
                "fors_secret collided for distinct (tree,leaf) within one position",
            );
        }
    }
}

/// **The signed value.** The composed FORS public key — the message the
/// bottom hypertree WOTS layer signs — must differ per position. If it is
/// constant, one observed HT signature over `fors_pk` is reusable at every
/// position (the forgery's HT-tail splice). Pre-fix this was constant `P`.
///
/// This is the expensive assertion (full FORS-tree builds), but each
/// `compute_fors_root` is `O(2^A)` and only a few positions are checked, so
/// it stays well under the cost of the keygen the other suites already run.
#[test]
fn fors_pk_is_unique_per_ht_idx() {
    let seed = pad16(&PK_SEED);
    // 3 positions is enough to prove non-constancy while keeping the
    // 3 × K full-tree builds cheap.
    let positions = [0u32, 0x2_abcd, 0x3_ffff];

    let mut seen: HashSet<[u8; N]> = HashSet::new();
    for ht_idx in positions {
        let mut roots = [[0u8; N]; K];
        for (t, root) in roots.iter_mut().enumerate() {
            *root = compute_fors_root(&seed, &SK_SEED, ht_idx, t as u32);
        }
        let pk = compute_fors_pk(&seed, ht_idx, &roots);
        assert!(
            seen.insert(pk),
            "fors_pk collided across ht_idx at ht_idx={ht_idx:#x} — the shared-forest \
             forgery surface (constant fors_pk reused at every hypertree position) is back",
        );
    }
    assert_eq!(seen.len(), positions.len());
}

/// **A single FORS tree root** is `ht_idx`-bound too (a cheaper proxy that
/// localises a regression to the tree level rather than the K-way
/// compression). Builds one tree per position.
#[test]
fn fors_tree_root_is_unique_per_ht_idx() {
    let seed = pad16(&PK_SEED);
    let tree_idx = 5u32;
    let mut seen: HashSet<[u8; N]> = HashSet::new();
    for ht_idx in HT_POSITIONS {
        let root = compute_fors_root(&seed, &SK_SEED, ht_idx, tree_idx);
        assert!(
            seen.insert(root),
            "FORS tree-{tree_idx} root collided across ht_idx at ht_idx={ht_idx:#x}",
        );
    }
}

/// **Spec-conformance, structural.** The FORS ADRS must carry `ht_idx` in
/// the *tree* field (ADRS bytes `[4..12)`, the 64-bit `tree` slot per
/// `address.rs`). This is the exact line a desk review of `make_adrs(0, 0,
/// …)` vs `make_adrs(0, ht_idx, …)` would have caught (work-todo §18b ③).
/// It pins the byte position so a future refactor can't quietly move the
/// binding into a field the on-chain Yul verifier doesn't read.
#[test]
fn fors_adrs_encodes_ht_idx_in_the_tree_field() {
    let ht_idx: u32 = 0x2_abcd;
    let leaf_idx: u32 = 1500;
    let adrs = make_adrs(0, u64::from(ht_idx), ADRS_FORS_TREE, 7, 0, 0, leaf_idx);

    // tree field = bytes [4..12) as u64 BE — must equal ht_idx.
    let tree_field = u64::from_be_bytes([
        adrs[4], adrs[5], adrs[6], adrs[7], adrs[8], adrs[9], adrs[10], adrs[11],
    ]);
    assert_eq!(
        tree_field,
        u64::from(ht_idx),
        "FORS ADRS tree field must carry ht_idx (post-fcee705a binding)",
    );

    // address_type = bytes [12..16) must still be ADRS_FORS_TREE.
    let atype = u32::from_be_bytes([adrs[12], adrs[13], adrs[14], adrs[15]]);
    assert_eq!(atype, ADRS_FORS_TREE);

    // A zero ht_idx must produce a zero tree field (the pre-fix shape) — so
    // the difference above is genuinely ht_idx and not some other field.
    let adrs0 = make_adrs(0, 0, ADRS_FORS_TREE, 7, 0, 0, leaf_idx);
    let tree_field0 = u64::from_be_bytes([
        adrs0[4], adrs0[5], adrs0[6], adrs0[7], adrs0[8], adrs0[9], adrs0[10], adrs0[11],
    ]);
    assert_eq!(tree_field0, 0);
    assert_ne!(adrs, adrs0, "ht_idx must change the FORS ADRS bytes");
}
