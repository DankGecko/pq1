//! FORS shared-forest **forgery simulator** — the regression test that
//! `fcee705a` never shipped (work-todo §18b ①). Guards CWE-347.
//!
//! ## The attack this reproduces
//!
//! Pre-`fcee705a`, the FORS few-time forest was derived from the FORS *tree*
//! index only — never from the hypertree leaf position `ht_idx`. So:
//!
//!  * every FORS **tree root** (hence the composed `fors_pk`) was a per-key
//!    **constant**, identical at all `2^18` hypertree positions; and
//!  * FORS leaf secrets are published *in the clear* inside every signature.
//!
//! A passive observer who harvests enough of a wallet's public signatures can
//! therefore **reassemble the shared forest** and mint a valid signature for
//! an attacker-chosen message — with no secret key — by mixing and matching
//! material across the harvested signatures:
//!
//!  * the FORS leaf secret + auth path for each tree's selected leaf is pulled
//!    from *whichever* harvested signature happened to open that leaf (the
//!    forest is global, so any one works); and
//!  * the hypertree tail (the WOTS+C signature over the constant `fors_pk`,
//!    plus its Merkle auth path) is copied verbatim from *whichever* harvested
//!    signature sits at the forged digest's `ht_idx` (it signs the same
//!    constant `fors_pk`, so it is reusable).
//!
//! The attacker only grinds the 16-byte randomizer `R` (a freely chosen field
//! of the signature) until the resulting digest selects leaves and an `ht_idx`
//! that the harvest already covers. Everything the harness uses is **public**
//! signature bytes interpreted via `sim_internals::{h_msg, extract_*}` (the
//! exact capability of an on-chain observer) — the victim's `sk_seed` is used
//! only to *produce* the harvested signatures, never to forge.
//!
//! ## Acceptance (the pre/post-fix flip)
//!
//!  * **HEAD (post-fix):** `ht_idx` is folded into the FORS PRF and every FORS
//!    ADRS, so each position is an independent forest. The reassembled
//!    signature **fails** `verify` — this file asserts that.
//!  * **`fcee705a^` (pre-fix):** the same harness mints a signature that
//!    `verify` **accepts** in well under a second (confirmed out-of-band; see
//!    `docs/verification/sphincs-c10-spec-conformance-checklist.md`). The archived sweep
//!    `tools/sca/out/c10_sign_sweep.PREFIX-VULNERABLE.jsonl.bak` is the
//!    historical record that the FI sweep was *blind* to this class.
//!
//! ## SCOPE — read before trusting a green run
//!
//! This audits **cryptographic forgery resistance** (few-time-key reuse), the
//! exact class the `tools/sca` FI sweep is structurally blind to. It is NOT a
//! constant-time / fault-injection check. A passing run means "the shared-
//! forest reassembly forgery is defeated", nothing more.
//!
//! Run the fast CI guards (default — parse/assemble roundtrip, cross-position
//! splice rejection, and the 65,536-use-cap forgery-work margin ≥ 2^128):
//! ```text
//! cargo test -p sphincs-c10 --features sim-internals --test fors_forgery_resistance -- --nocapture
//! ```
//! Run the full end-to-end forgery (≈2 min; harvest-dominated):
//! ```text
//! cargo test -p sphincs-c10 --features sim-internals --test fors_forgery_resistance \
//!     -- --ignored --nocapture
//! # tune: FORS_FORGERY_HARVEST=4000 FORS_FORGERY_GRIND=800000000 cargo test …
//! ```

#![cfg(feature = "sim-internals")]

use std::collections::{HashMap, HashSet};

use sphincs_c10::params::{A, H, K, N, SIGNATURE_LEN, SIG_FORS_TOTAL};
use sphincs_c10::sim_internals::{extract_fors_indices, extract_ht_index, h_msg, pad16};
use sphincs_c10::SigningKey;

// ---- signature layout (mirrors params.rs; pinned here so a layout change
//      that breaks the harness is loud) -------------------------------------
const SECRETS_OFF: usize = N; // after R
const AUTH_OFF: usize = N + K * N; // after R + K secrets
const AUTH_PER_TREE: usize = A * N; // 11 * 16 = 176
const HT_TAIL_OFF: usize = SIG_FORS_TOTAL; // 2336
const HT_TAIL_LEN: usize = SIGNATURE_LEN - SIG_FORS_TOTAL; // 1672

const _: () = assert!(AUTH_OFF == 16 + 13 * 16);
const _: () = assert!(HT_TAIL_OFF == 2336);
const _: () = assert!(HT_TAIL_LEN == 1672);

const SK_SEED: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];
const PK_SEED: [u8; N] = [
    0xca, 0xfe, 0xba, 0xbe, 0x13, 0x37, 0x42, 0x24, 0xaa, 0x55, 0xcc, 0x33, 0x0f, 0xf0, 0x77, 0x88,
];

/// The message the attacker wants signed without ever holding the key.
fn evil_message() -> [u8; 32] {
    // "drain everything to the attacker" — a 32-byte hash stand-in.
    let mut m = [0u8; 32];
    let tag = b"DRAIN-ALL-FUNDS-TO-ATTACKER";
    m[..tag.len()].copy_from_slice(tag);
    m
}

/// Recompute the H_msg digest from PUBLIC inputs only (what an on-chain
/// observer can do): `digest = H_msg(pk_seed, pk_root, R, msg)`.
fn digest_of(pk_seed: &[u8; N], pk_root: &[u8; N], r: &[u8; N], msg: &[u8; 32]) -> [u8; 32] {
    h_msg(&pad16(pk_seed), &pad16(pk_root), &pad16(r), msg)
}

/// A harvested signature decomposed into the pieces the forgery reuses.
struct Parsed {
    r: [u8; N],
    ht_idx: u32,
    fors_indices: [u32; K],
    secrets: [[u8; N]; K],
    auths: [[u8; AUTH_PER_TREE]; K - 1],
    ht_tail: [u8; HT_TAIL_LEN],
}

/// Parse a signature using only the public layout + a public digest.
fn parse(sig: &[u8; SIGNATURE_LEN], pk_seed: &[u8; N], pk_root: &[u8; N], msg: &[u8; 32]) -> Parsed {
    let mut r = [0u8; N];
    r.copy_from_slice(&sig[..N]);
    let digest = digest_of(pk_seed, pk_root, &r, msg);
    let fors_indices = extract_fors_indices(&digest);
    let ht_idx = extract_ht_index(&digest);

    let mut secrets = [[0u8; N]; K];
    for (t, s) in secrets.iter_mut().enumerate() {
        s.copy_from_slice(&sig[SECRETS_OFF + t * N..SECRETS_OFF + (t + 1) * N]);
    }
    let mut auths = [[0u8; AUTH_PER_TREE]; K - 1];
    for (t, a) in auths.iter_mut().enumerate() {
        a.copy_from_slice(&sig[AUTH_OFF + t * AUTH_PER_TREE..AUTH_OFF + (t + 1) * AUTH_PER_TREE]);
    }
    let mut ht_tail = [0u8; HT_TAIL_LEN];
    ht_tail.copy_from_slice(&sig[HT_TAIL_OFF..]);

    Parsed {
        r,
        ht_idx,
        fors_indices,
        secrets,
        auths,
        ht_tail,
    }
}

/// Assemble a 4008-byte signature from chosen pieces (no secret key).
#[allow(clippy::too_many_arguments)]
fn assemble(
    r: &[u8; N],
    secrets: &[[u8; N]; K],
    auths: &[[u8; AUTH_PER_TREE]; K - 1],
    ht_tail: &[u8; HT_TAIL_LEN],
) -> [u8; SIGNATURE_LEN] {
    let mut out = [0u8; SIGNATURE_LEN];
    out[..N].copy_from_slice(r);
    for (t, s) in secrets.iter().enumerate() {
        out[SECRETS_OFF + t * N..SECRETS_OFF + (t + 1) * N].copy_from_slice(s);
    }
    for (t, a) in auths.iter().enumerate() {
        out[AUTH_OFF + t * AUTH_PER_TREE..AUTH_OFF + (t + 1) * AUTH_PER_TREE].copy_from_slice(a);
    }
    out[HT_TAIL_OFF..].copy_from_slice(ht_tail);
    out
}

fn counter_msg(i: u64) -> [u8; 32] {
    let mut m = [0u8; 32];
    m[..8].copy_from_slice(b"harvest-");
    m[24..32].copy_from_slice(&i.to_be_bytes());
    m
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Fast CI guard #1 — the parse/assemble layer is byte-exact.
//
// Decompose a genuine signature into the forgery's working pieces and put it
// back together; the result must be byte-identical and still verify. Without
// this, a layout-offset bug could make the heavy forgery "fail" for the wrong
// reason and mask a real regression.
// ---------------------------------------------------------------------------
#[test]
fn reassembly_roundtrip_is_byte_exact() {
    let key = SigningKey::keygen(SK_SEED, PK_SEED);
    let vk = key.verifying_key();
    let msg = counter_msg(7);
    let sig = key.sign(&msg, None);
    assert!(vk.verify(&msg, &sig), "baseline signature must verify");

    let p = parse(&sig, &vk.pk_seed, &vk.pk_root, &msg);
    let rebuilt = assemble(&p.r, &p.secrets, &p.auths, &p.ht_tail);
    assert_eq!(rebuilt, sig, "decompose→assemble must reproduce the signature byte-for-byte");
    assert!(vk.verify(&msg, &rebuilt), "reassembled signature must verify");
}

// ---------------------------------------------------------------------------
// Fast CI guard #2 — the *cross-position splice* is rejected (post-fix).
//
// A minimal, genuine end-to-end forgery attempt: take one signature A and
// splice in tree-t material harvested from a DIFFERENT signature B that opened
// the SAME leaf of tree t at a DIFFERENT ht_idx. Pre-fix the two are
// byte-identical (shared forest) so the splice is a no-op and the result
// verifies — i.e. cross-position material is interchangeable, the whole bug.
// Post-fix the spliced bytes differ (position-bound) and the splice breaks
// verification. This runs in seconds and flips between pre/post-fix.
// ---------------------------------------------------------------------------
#[test]
fn cross_position_tree_splice_is_rejected() {
    let key = SigningKey::keygen(SK_SEED, PK_SEED);
    let vk = key.verifying_key();

    // Harvest a small batch and index (tree, leaf) -> list of (parsed-sig idx).
    let harvest_n = 96usize;
    let mut parsed: Vec<(Parsed, [u8; SIGNATURE_LEN], [u8; 32])> = Vec::with_capacity(harvest_n);
    for i in 0..harvest_n as u64 {
        let msg = counter_msg(i);
        let sig = key.sign(&msg, None);
        let p = parse(&sig, &vk.pk_seed, &vk.pk_root, &msg);
        parsed.push((p, sig, msg));
    }

    // Find tree t and sigs A, B that selected the same leaf of tree t at
    // different ht_idx (a within-tree leaf collision — birthday-cheap over
    // 2048 leaves with ~96 draws).
    let mut found: Option<(usize, usize, usize)> = None; // (t, a, b)
    'search: for t in 0..(K - 1) {
        let mut by_leaf: HashMap<u32, usize> = HashMap::new();
        for (idx, (p, _, _)) in parsed.iter().enumerate() {
            let leaf = p.fors_indices[t];
            if let Some(&prev) = by_leaf.get(&leaf) {
                if parsed[prev].0.ht_idx != p.ht_idx {
                    found = Some((t, prev, idx));
                    break 'search;
                }
            } else {
                by_leaf.insert(leaf, idx);
            }
        }
    }

    let (t, a, b) = found.expect(
        "no within-tree leaf collision across distinct ht_idx in 96 sigs — \
         very unlikely; rerun or raise harvest_n",
    );

    // Splice B's tree-t (secret, auth) into a copy of A and re-verify A's msg.
    let (pa, _sig_a, msg_a) = &parsed[a];
    let pb = &parsed[b].0;
    assert_eq!(pa.fors_indices[t], pb.fors_indices[t], "same selected leaf");
    assert_ne!(pa.ht_idx, pb.ht_idx, "different hypertree position");

    let mut secrets = pa.secrets;
    let mut auths = pa.auths;
    secrets[t] = pb.secrets[t];
    auths[t] = pb.auths[t];
    let forged = assemble(&pa.r, &secrets, &auths, &pa.ht_tail);

    let forged_ok = vk.verify(msg_a, &forged);
    println!(
        "[splice] tree={t} leaf={} ht_a={:#x} ht_b={:#x} forged_verifies={forged_ok}",
        pa.fors_indices[t], pa.ht_idx, pb.ht_idx,
    );
    assert!(
        !forged_ok,
        "cross-position tree splice VERIFIED — FORS leaf material is interchangeable across \
         hypertree positions: the shared-forest forgery (CWE-347) has regressed. \
         (Pre-fcee705a this assertion fails because the spliced bytes are identical.)",
    );
}

// ---------------------------------------------------------------------------
// Heavy end-to-end forgery (≈2 min, harvest-dominated) — the full
// reassembly attack, run on demand. Asserts the forgery is DEFEATED on HEAD
// while proving the harness actually built a real forged signature (the
// grind landed on a fully-covered digest), so a green result is never
// vacuous.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "heavy: harvests thousands of signatures (~2 min); run with --ignored"]
fn shared_forest_reassembly_forgery_is_defeated() {
    let harvest_n = env_usize("FORS_FORGERY_HARVEST", 3000);
    let grind_budget = env_usize("FORS_FORGERY_GRIND", 400_000_000) as u64;

    let key = SigningKey::keygen(SK_SEED, PK_SEED);
    let vk = key.verifying_key();
    let evil = evil_message();

    // ---- Harvest phase: collect the public material an observer would see.
    // ht_idx -> HT tail (signs the [pre-fix constant] fors_pk at that position)
    let mut ht_part: HashMap<u32, [u8; HT_TAIL_LEN]> = HashMap::new();
    // per-tree leaf_idx -> (secret, auth) for the first K-1 trees
    let mut tree_leaf: Vec<HashMap<u32, ([u8; N], [u8; AUTH_PER_TREE])>> =
        (0..K - 1).map(|_| HashMap::new()).collect();
    // the forced-zero (last) tree's emitted "secret" is its root (pre-fix
    // constant); record one.
    let mut last_root = [0u8; N];

    let t_start = std::time::Instant::now();
    for i in 0..harvest_n as u64 {
        let msg = counter_msg(i);
        let sig = key.sign(&msg, None);
        let p = parse(&sig, &vk.pk_seed, &vk.pk_root, &msg);
        ht_part.entry(p.ht_idx).or_insert(p.ht_tail);
        for t in 0..(K - 1) {
            tree_leaf[t].entry(p.fors_indices[t]).or_insert((p.secrets[t], p.auths[t]));
        }
        last_root = p.secrets[K - 1];
    }
    let harvest_dt = t_start.elapsed();

    // Coverage diagnostics.
    let min_tree_cov = (0..K - 1).map(|t| tree_leaf[t].len()).min().unwrap();
    let max_tree_cov = (0..K - 1).map(|t| tree_leaf[t].len()).max().unwrap();
    println!(
        "[harvest] {harvest_n} sigs in {harvest_dt:?} | distinct ht positions={} | \
         per-tree leaf coverage min={min_tree_cov} max={max_tree_cov} (of 2048)",
        ht_part.len(),
    );

    // ---- Forge phase: grind R (a freely chosen 16-byte field) until the
    // digest selects an ht_idx + leaves the harvest fully covers.
    let mut forged: Option<([u8; N], [u32; K], u32)> = None;
    let mut grinds = 0u64;
    let t_forge = std::time::Instant::now();
    'grind: for nonce in 0..grind_budget {
        grinds += 1;
        let mut r = [0u8; N];
        r[8..16].copy_from_slice(&nonce.to_be_bytes());
        let digest = digest_of(&vk.pk_seed, &vk.pk_root, &r, &evil);
        let idx = extract_fors_indices(&digest);
        // forced-zero constraint that verify() also enforces
        if idx[K - 1] != 0 {
            continue;
        }
        let ht = extract_ht_index(&digest);
        if !ht_part.contains_key(&ht) {
            continue;
        }
        for t in 0..(K - 1) {
            if !tree_leaf[t].contains_key(&idx[t]) {
                continue 'grind;
            }
        }
        forged = Some((r, idx, ht));
        break;
    }
    let forge_dt = t_forge.elapsed();

    let (r, idx, ht) = forged.unwrap_or_else(|| {
        panic!(
            "grind budget {grind_budget} exhausted without a fully-covered digest \
             (min tree coverage {min_tree_cov}/2048, {} ht positions). The harness is not \
             exercising a real forgery — raise FORS_FORGERY_HARVEST (more coverage) or \
             FORS_FORGERY_GRIND (more attempts).",
            ht_part.len(),
        )
    });
    println!(
        "[forge ] covered digest found after {grinds} grinds in {forge_dt:?} \
         (ht_idx={ht:#x}, forced-zero ok)",
    );

    // Assemble the forged signature entirely from harvested material.
    let mut secrets = [[0u8; N]; K];
    let mut auths = [[0u8; AUTH_PER_TREE]; K - 1];
    for t in 0..(K - 1) {
        let (s, a) = tree_leaf[t][&idx[t]];
        secrets[t] = s;
        auths[t] = a;
    }
    secrets[K - 1] = last_root;
    let ht_tail = ht_part[&ht];
    let forged_sig = assemble(&r, &secrets, &auths, &ht_tail);

    let forged_ok = vk.verify(&evil, &forged_sig);
    println!("[verify] reassembled-forgery verifies = {forged_ok}  (expected: false on HEAD)");

    assert!(
        !forged_ok,
        "SHARED-FOREST FORGERY SUCCEEDED on HEAD — a reassembled signature for an \
         attacker-chosen message verified with no secret key. The fcee705a fix (fold ht_idx \
         into the FORS PRF + ADRS) has regressed (CWE-347). On fcee705a^ this assertion is \
         expected to fail, i.e. the forgery verifies.",
    );
}

// ---------------------------------------------------------------------------
// Security margin at the on-chain cap — validates the fcee705a claim that
// "at the on-chain cap (65,536 uses) forgery work is ~2^131 (> 128-bit
// target)". A slot/bootstrap key signs at most MAX_SLOT_USES = 65,536 times
// on a chain before it must rotate, so 65,536 is the MOST signatures an
// attacker can ever harvest from one key — the protocol's worst case.
//
// This reconstructs the EXACT post-fix per-grind forgery probability for a
// full-cap harvest WITHOUT signing: the harvest's coverage distribution is a
// function of the public digests alone (each real signature sits at the
// `ht_idx` its digest selects and reveals one leaf per FORS tree; the
// forced-zero constraint on the last index doesn't bias the other K-1 indices,
// which are independent bits of a hash). Coverage grows monotonically with
// harvest size, so the cap is the FLOOR on forgery work — asserting ≥ 128 bits
// here bounds it everywhere below the cap too.
// ---------------------------------------------------------------------------

/// On-chain `MAX_SLOT_USES == MAX_BOOTSTRAP_USES` (per CLAUDE.md / the wallet
/// contract): a key rotates at this many signatures, so it is the maximum
/// single-key harvest an attacker can collect.
const ONCHAIN_USE_CAP: usize = 65_536;

#[test]
fn forgery_work_at_onchain_cap_exceeds_128_bits() {
    let key = SigningKey::keygen(SK_SEED, PK_SEED);
    let vk = key.verifying_key();
    let evil = evil_message();

    // cov[ht_idx][t] = distinct leaves of FORS tree t revealed by the harvested
    // signatures that landed at that hypertree position (the first K-1 = 12
    // "normal" trees; the last tree is forced-zero, its root known everywhere).
    let mut cov: HashMap<u32, Vec<HashSet<u32>>> = HashMap::new();
    for i in 0..ONCHAIN_USE_CAP as u64 {
        let mut r = [0u8; N];
        r[8..16].copy_from_slice(&i.to_be_bytes());
        let digest = digest_of(&vk.pk_seed, &vk.pk_root, &r, &evil);
        let ht = extract_ht_index(&digest);
        let idx = extract_fors_indices(&digest);
        let entry = cov.entry(ht).or_insert_with(|| vec![HashSet::new(); K - 1]);
        for (t, set) in entry.iter_mut().enumerate() {
            set.insert(idx[t]);
        }
    }

    // Post-fix per-grind forgery probability (forge an attacker-chosen message
    // by grinding the signature's R field only — everything else is the honest
    // verifier's digest-driven selection):
    //
    //   p = (1/2^A)                           [forced-zero on the last index]
    //     * Σ_P (1/2^H)                        [the forged digest lands ht_idx = P]
    //           * Π_{t<K-1} |cov[P][t]| / 2^A  [each selected leaf is one we hold]
    //
    // Only positions the harvest actually covers contribute (an uncovered tree
    // makes the product 0). `sum_term` collects the Π over all covered
    // positions; the 1/2^H and 1/2^A factors are applied once.
    let leaf_scale = 1.0_f64 / (1u64 << A) as f64; // 1/2^A
    let mut sum_term = 0.0_f64;
    let mut best_min_cov = 0usize; // best position's bottleneck-tree coverage
    for sets in cov.values() {
        let mut prod = 1.0_f64;
        let mut min_c = usize::MAX;
        for s in sets {
            prod *= s.len() as f64 * leaf_scale;
            min_c = min_c.min(s.len());
        }
        sum_term += prod;
        best_min_cov = best_min_cov.max(min_c);
    }
    let ht_prob = 1.0_f64 / (1u64 << H) as f64;
    let fz_prob = 1.0_f64 / (1u64 << A) as f64;
    let p_grind = fz_prob * ht_prob * sum_term;
    let work_bits = -p_grind.log2();

    println!(
        "[cap ] harvest={ONCHAIN_USE_CAP} sigs (MAX_SLOT_USES) | distinct positions covered={} \
         (~{:.0}% of 2^18) | best position's bottleneck-tree coverage={best_min_cov}/2048 | \
         post-fix forgery work = 2^{work_bits:.1} grinds (commit claims ~2^131)",
        cov.len(),
        100.0 * cov.len() as f64 / (1u64 << H) as f64,
    );

    assert!(
        work_bits >= 128.0,
        "post-fix forgery work at the 65,536-use cap is only 2^{work_bits:.1} (< the 2^128 \
         target) — fcee705a's position binding does not deliver the claimed margin. Each FORS \
         position is supposed to be an independent forest, so a max-harvest attacker still \
         cannot assemble a forgery; if this fails, the per-position coverage is too dense \
         (binding regressed).",
    );
}
