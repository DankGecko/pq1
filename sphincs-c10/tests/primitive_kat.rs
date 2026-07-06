//! Per-primitive component KAT for the C10 tweakable-hash boundary
//! (ETHFALCON-port R1 — `docs/verification/external-kat-provenance-and-ethfalcon-port-2026-07.md` §5).
//!
//! Golden intermediate-value vectors for each C10 hash primitive
//! (`th`, `th_pair`, `th_multi`, `h_msg`, `chain_hash`, `wots_digest`,
//! `wots_secret`, `fors_secret`): declared inputs → 16/32-byte output. The
//! committed artifact `contracts/smart-wallet/test/c10_primitive_kat_vectors.json`
//! is consumed by THREE independent implementations:
//!   * this test          — recomputes each output from the JSON's inputs and
//!                           asserts it matches (a Rust regression pin: any change
//!                           to a `sphincs-c10` primitive desyncs from the golden);
//!   * the clean-room Python signer (`contracts/verification/scripts/
//!     independent_c10_signer.py --check-primitives`) — the independence guard;
//!   * the on-chain Yul verifier's layout (`contracts/smart-wallet/test/
//!     C10PrimitiveKat.t.sol`) — reconstructs each verify-side primitive's SHA-256
//!     preimage the way `SPHINCsC10Asm.sol` does and asserts via precompile 0x02.
//!
//! HONEST SCOPE (per the R1 assessment): these are **self-generated + internally
//! N-way cross-checked**, NOT externally conformant. No official SPHINCS+/SLH-DSA
//! KAT can anchor them — C10 shares only raw SHA-256 with any standard (that layer
//! IS anchored, to NIST CAVP). Value is **localization**: when a whole-signature
//! KAT (`c10_test_vectors.json`) fails, these pin WHICH primitive/offset diverged
//! (the class of the A3.1 `chain_hash` `chain_index`-vs-`chain_pos` bug), instead of
//! leaving a 4008-byte haystack — not new coverage over the whole-sig differential.
//!
//! Run (assert):  `cargo test -p sphincs-c10 --features sim-internals --test primitive_kat --release`
//! Regenerate:    `C10_KAT_REGEN=1 cargo test -p sphincs-c10 --features sim-internals \
//!                    --test primitive_kat --release -- --nocapture regenerate`
//! After a regen, re-run the Python + Solidity legs to confirm all three still agree.

#![cfg(feature = "sim-internals")]

use serde::{Deserialize, Serialize};
use sphincs_c10::params::N;
use sphincs_c10::sim_internals::{
    chain_hash, fors_secret, h_msg, make_adrs, pad16, th, th_multi, th_pair, wots_digest,
    wots_secret,
};

const VECTORS_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/smart-wallet/test/c10_primitive_kat_vectors.json");

// ── JSON schema (one array per primitive) ───────────────────────────────────
// All byte fields are `0x`-prefixed hex; 32-byte words are the exact SHA-256
// preimage words (seed/val are N-masked = 16 value bytes + 16 zero; adrs is the
// full packed 32-byte address). `out` is 16 bytes (truncated primitives) or 32
// bytes (`h_msg` / `wots_digest`, which the scheme consumes whole).

#[derive(Serialize, Deserialize)]
struct ThV { label: String, seed: String, adrs: String, val: String, out: String }
#[derive(Serialize, Deserialize)]
struct PairV { label: String, seed: String, adrs: String, left: String, right: String, out: String }
#[derive(Serialize, Deserialize)]
struct MultiV { label: String, seed: String, adrs: String, vals: Vec<String>, out: String }
#[derive(Serialize, Deserialize)]
struct HMsgV { label: String, seed: String, root: String, r: String, msg: String, out: String }
#[derive(Serialize, Deserialize)]
struct ChainV { label: String, seed: String, adrs_base: String, val: String, start: u32, steps: u32, out: String }
#[derive(Serialize, Deserialize)]
struct WDigestV { label: String, seed: String, wots_adrs: String, msg: String, count: u32, out: String }
#[derive(Serialize, Deserialize)]
struct WSecretV { label: String, sk_seed: String, layer: u32, tree: u64, kp: u32, chain_idx: u32, out: String }
#[derive(Serialize, Deserialize)]
struct FSecretV { label: String, sk_seed: String, ht_idx: u32, tree_idx: u32, leaf_idx: u32, out: String }

/// Per-primitive vector counts — a top-level object so the Solidity leg can loop
/// with `vm.parseJsonUint(json, ".counts.<prim>")` + per-index scalar getters
/// (this Foundry build does not support the `[*]` array-wildcard cheatcodes).
#[derive(Serialize, Deserialize)]
struct Counts {
    th: usize,
    th_pair: usize,
    th_multi: usize,
    h_msg: usize,
    chain_hash: usize,
    wots_digest: usize,
    wots_secret: usize,
    fors_secret: usize,
}

#[derive(Serialize, Deserialize)]
struct Kat {
    #[serde(rename = "_comment")]
    comment: String,
    counts: Counts,
    th: Vec<ThV>,
    th_pair: Vec<PairV>,
    th_multi: Vec<MultiV>,
    h_msg: Vec<HMsgV>,
    chain_hash: Vec<ChainV>,
    wots_digest: Vec<WDigestV>,
    wots_secret: Vec<WSecretV>,
    fors_secret: Vec<FSecretV>,
}

// ADRS type constants (mirror `address.rs`): WOTS=0, WOTS_PK=1, TREE=2,
// FORS_TREE=3, FORS_ROOTS=4.
const T_WOTS: u32 = 0;
const T_WOTS_PK: u32 = 1;
const T_TREE: u32 = 2;
const T_FORS_TREE: u32 = 3;
const T_FORS_ROOTS: u32 = 4;

// ── hex helpers ─────────────────────────────────────────────────────────────
fn hx(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}
fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim().trim_start_matches("0x")).expect("valid hex")
}
fn u32b(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte word")
}
fn u16b(s: &str) -> [u8; N] {
    unhex(s).try_into().expect("16-byte value")
}
/// 16 identical bytes, N-mask-padded to a 32-byte word.
fn rep16(b: u8) -> [u8; 32] {
    pad16(&[b; N])
}
/// bytes `[lo, lo+1, ...]` (16 of them), N-mask-padded to 32 bytes.
fn seq16(lo: u8) -> [u8; 32] {
    let mut v = [0u8; N];
    for (i, x) in v.iter_mut().enumerate() {
        *x = lo.wrapping_add(i as u8);
    }
    pad16(&v)
}
/// A raw 32-byte message (NOT N-masked): bytes `[lo, lo+1, ...]`.
fn msg32(lo: u8) -> [u8; 32] {
    let mut v = [0u8; 32];
    for (i, x) in v.iter_mut().enumerate() {
        *x = lo.wrapping_add(i as u8);
    }
    v
}

// ── build the golden set (deterministic inputs → computed outputs) ───────────
fn build() -> Kat {
    // th
    let th_in: [(&str, [u8; 32], [u8; 32], [u8; 32]); 4] = [
        ("th/all-zero", [0u8; 32], [0u8; 32], [0u8; 32]),
        ("th/fors-leaf", rep16(0xAA), make_adrs(0, 7, T_FORS_TREE, 5, 0, 0, 42), rep16(0x11)),
        ("th/tree-node", rep16(0xFF), make_adrs(1, 0, T_TREE, 0, 0, 5, 3), rep16(0xFF)),
        ("th/mixed", seq16(0x00), make_adrs(0, 0x0102_0304_05, T_FORS_ROOTS, 9, 0, 0, 0), seq16(0xF0)),
    ];
    let th: Vec<ThV> = th_in
        .iter()
        .map(|(l, s, a, v)| ThV {
            label: (*l).into(),
            seed: hx(s),
            adrs: hx(a),
            val: hx(v),
            out: hx(&th(s, a, v)),
        })
        .collect();

    // th_pair
    let pair_in: [(&str, [u8; 32], [u8; 32], [u8; 32], [u8; 32]); 3] = [
        ("th_pair/all-zero", [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]),
        ("th_pair/tree", rep16(0xAA), make_adrs(1, 0, T_TREE, 0, 0, 1, 0), rep16(0x11), rep16(0x22)),
        ("th_pair/fors-ordered", rep16(0xBB), make_adrs(0, 7, T_FORS_TREE, 5, 0, 1, 3), rep16(0xFF), rep16(0x00)),
    ];
    let th_pair: Vec<PairV> = pair_in
        .iter()
        .map(|(l, s, a, lft, r)| PairV {
            label: (*l).into(),
            seed: hx(s),
            adrs: hx(a),
            left: hx(lft),
            right: hx(r),
            out: hx(&th_pair(s, a, lft, r)),
        })
        .collect();

    // th_multi (1, K=13, L=43 values)
    let mk_vals = |lo: u8, n: usize| -> Vec<[u8; N]> {
        (0..n).map(|i| [lo.wrapping_add(i as u8); N]).collect()
    };
    let multi_in: [(&str, [u8; 32], u32, Vec<[u8; N]>); 3] = [
        ("th_multi/single", rep16(0xAA), 0, mk_vals(0x11, 1)),
        ("th_multi/fors-roots-13", make_adrs_seed(0xCC), 0, mk_vals(0x20, 13)),
        ("th_multi/wots-pk-43", rep16(0xDD), 0, mk_vals(0x40, 43)),
    ];
    // adrs for the three: FORS_ROOTS / WOTS_PK shapes.
    let multi_adrs = [
        make_adrs(0, 0, T_FORS_ROOTS, 0, 0, 0, 0),
        make_adrs(0, 7, T_FORS_ROOTS, 0, 0, 0, 0),
        make_adrs(1, 0, T_WOTS_PK, 9, 0, 0, 0),
    ];
    let th_multi: Vec<MultiV> = multi_in
        .iter()
        .zip(multi_adrs.iter())
        .map(|((l, s, _z, vals), a)| MultiV {
            label: (*l).into(),
            seed: hx(s),
            adrs: hx(a),
            vals: vals.iter().map(|v| hx(v)).collect(),
            out: hx(&th_multi(s, a, vals)),
        })
        .collect();

    // h_msg (seed/root/r N-masked; msg is a raw 32-byte digest) → 32-byte out
    let hmsg_in: [(&str, [u8; 32], [u8; 32], [u8; 32], [u8; 32]); 3] = [
        ("h_msg/all-zero", [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]),
        ("h_msg/mixed", rep16(0xAA), rep16(0xBB), rep16(0xCC), msg32(0x01)),
        ("h_msg/seq", seq16(0x10), seq16(0x30), rep16(0x5A), msg32(0x80)),
    ];
    let h_msg: Vec<HMsgV> = hmsg_in
        .iter()
        .map(|(l, s, root, r, m)| HMsgV {
            label: (*l).into(),
            seed: hx(s),
            root: hx(root),
            r: hx(r),
            msg: hx(m),
            out: hx(&h_msg(s, root, r, m)),
        })
        .collect();

    // chain_hash (steps=0 is the identity; walks `th` `steps` times)
    let wots_base = make_adrs(0, 0, T_WOTS, 5, 3, 0, 0);
    let chain_in: [(&str, [u8; 32], [u8; 32], [u8; N], u32, u32); 4] = [
        ("chain/identity-steps0", rep16(0xAA), wots_base, [0x11; N], 0, 0),
        ("chain/full-steps7", rep16(0xAA), wots_base, [0x11; N], 0, 7),
        ("chain/mid", rep16(0xAA), wots_base, [0x22; N], 3, 4),
        ("chain/zero-val", rep16(0xAA), wots_base, [0x00; N], 0, 7),
    ];
    let chain_hash: Vec<ChainV> = chain_in
        .iter()
        .map(|(l, s, a, v, start, steps)| ChainV {
            label: (*l).into(),
            seed: hx(s),
            adrs_base: hx(a),
            val: hx(v),
            start: *start,
            steps: *steps,
            out: hx(&chain_hash(s, a, v, *start, *steps)),
        })
        .collect();

    // wots_digest (seed/wots_adrs; msg raw 32; count grind) → 32-byte out
    let wd_adrs = make_adrs(1, 0, T_WOTS, 9, 0, 0, 0);
    let wd_in: [(&str, u32); 3] = [("wots_digest/count0", 0), ("wots_digest/count205", 205), ("wots_digest/count-big", 9_999_999)];
    let wd_seed = rep16(0xAA);
    let wd_msg = msg32(0x01);
    let wots_digest: Vec<WDigestV> = wd_in
        .iter()
        .map(|(l, count)| WDigestV {
            label: (*l).into(),
            seed: hx(&wd_seed),
            wots_adrs: hx(&wd_adrs),
            msg: hx(&wd_msg),
            count: *count,
            out: hx(&wots_digest(&wd_seed, &wd_adrs, &wd_msg, *count)),
        })
        .collect();

    // wots_secret (PRF, sk_seed FIRST + ASCII "wots") → 16-byte out
    let ws_in: [(&str, [u8; 32], u32, u64, u32, u32); 3] = [
        ("wots_secret/zero", [0u8; 32], 0, 0, 0, 0),
        ("wots_secret/ab", [0xAB; 32], 1, 5, 9, 42),
        ("wots_secret/seq", sk_seq(), 0, 0x0102_0304_05, 3, 7),
    ];
    let wots_secret: Vec<WSecretV> = ws_in
        .iter()
        .map(|(l, sk, layer, tree, kp, ci)| WSecretV {
            label: (*l).into(),
            sk_seed: hx(sk),
            layer: *layer,
            tree: *tree,
            kp: *kp,
            chain_idx: *ci,
            out: hx(&wots_secret(sk, *layer, *tree, *kp, *ci)),
        })
        .collect();

    // fors_secret (PRF, sk_seed FIRST + ASCII "fors" + ht_idx forest binding)
    let fs_in: [(&str, [u8; 32], u32, u32, u32); 3] = [
        ("fors_secret/zero", [0u8; 32], 0, 0, 0),
        ("fors_secret/ab", [0xAB; 32], 7, 12, 2047),
        ("fors_secret/seq", sk_seq(), 131_071, 5, 1000),
    ];
    let fors_secret: Vec<FSecretV> = fs_in
        .iter()
        .map(|(l, sk, ht, tr, lf)| FSecretV {
            label: (*l).into(),
            sk_seed: hx(sk),
            ht_idx: *ht,
            tree_idx: *tr,
            leaf_idx: *lf,
            out: hx(&fors_secret(sk, *ht, *tr, *lf)),
        })
        .collect();

    let counts = Counts {
        th: th.len(),
        th_pair: th_pair.len(),
        th_multi: th_multi.len(),
        h_msg: h_msg.len(),
        chain_hash: chain_hash.len(),
        wots_digest: wots_digest.len(),
        wots_secret: wots_secret.len(),
        fors_secret: fors_secret.len(),
    };

    Kat {
        counts,
        comment: "C10 per-primitive tweakable-hash golden KAT (n=16, sig=4008). \
                  SELF-GENERATED + N-way cross-checked (Rust primitive_kat.rs \u{2194} \
                  independent_c10_signer.py --check-primitives \u{2194} Yul C10PrimitiveKat.t.sol) \
                  \u{2014} NOT externally conformant: C10 shares only raw SHA-256 with any \
                  standard (that layer is anchored to NIST CAVP). Regenerate with \
                  C10_KAT_REGEN=1. See docs/verification/external-kat-provenance-and-ethfalcon-port-2026-07.md."
            .into(),
        th,
        th_pair,
        th_multi,
        h_msg,
        chain_hash,
        wots_digest,
        wots_secret,
        fors_secret,
    }
}

fn make_adrs_seed(b: u8) -> [u8; 32] {
    rep16(b)
}
fn sk_seq() -> [u8; 32] {
    let mut v = [0u8; 32];
    for (i, x) in v.iter_mut().enumerate() {
        *x = i as u8;
    }
    v
}

// ── regenerate (env-gated) ──────────────────────────────────────────────────
#[test]
fn regenerate() {
    if std::env::var("C10_KAT_REGEN").as_deref() != Ok("1") {
        eprintln!("primitive_kat: set C10_KAT_REGEN=1 to (re)write {VECTORS_PATH}; skipping");
        return;
    }
    let kat = build();
    let json = serde_json::to_string_pretty(&kat).expect("serialize");
    std::fs::write(VECTORS_PATH, json + "\n").expect("write vectors");
    eprintln!(
        "wrote {} th / {} th_pair / {} th_multi / {} h_msg / {} chain / {} wots_digest / {} wots_secret / {} fors_secret vectors to {}",
        kat.th.len(),
        kat.th_pair.len(),
        kat.th_multi.len(),
        kat.h_msg.len(),
        kat.chain_hash.len(),
        kat.wots_digest.len(),
        kat.wots_secret.len(),
        kat.fors_secret.len(),
        VECTORS_PATH,
    );
}

// ── assert: recompute every committed vector from ITS inputs, byte-compare ───
#[test]
fn recompute_matches_committed_golden() {
    // During a regen run the sibling `regenerate` test is rewriting VECTORS_PATH
    // concurrently — skip the assert then; it runs on the next normal invocation.
    if std::env::var("C10_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("primitive_kat: skipping assert during a C10_KAT_REGEN run");
        return;
    }
    let raw = std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| {
        panic!("read {VECTORS_PATH}: {e} — run the `regenerate` test with C10_KAT_REGEN=1 first")
    });
    let k: Kat = serde_json::from_str(&raw).expect("parse committed golden");

    assert!(!k.th.is_empty() && !k.th_pair.is_empty() && !k.th_multi.is_empty(), "empty th* lists");
    assert!(
        !k.h_msg.is_empty() && !k.chain_hash.is_empty() && !k.wots_digest.is_empty(),
        "empty h_msg/chain/wots_digest"
    );
    assert!(!k.wots_secret.is_empty() && !k.fors_secret.is_empty(), "empty PRF lists");

    let mut outs16: Vec<[u8; N]> = Vec::new();
    let mut outs32: Vec<[u8; 32]> = Vec::new();

    for v in &k.th {
        let got = th(&u32b(&v.seed), &u32b(&v.adrs), &u32b(&v.val));
        assert_eq!(hx(&got), v.out, "th mismatch [{}]", v.label);
        nonzero16(&got, &v.label);
        outs16.push(got);
    }
    for v in &k.th_pair {
        let got = th_pair(&u32b(&v.seed), &u32b(&v.adrs), &u32b(&v.left), &u32b(&v.right));
        assert_eq!(hx(&got), v.out, "th_pair mismatch [{}]", v.label);
        nonzero16(&got, &v.label);
    }
    for v in &k.th_multi {
        let vals: Vec<[u8; N]> = v.vals.iter().map(|s| u16b(s)).collect();
        let got = th_multi(&u32b(&v.seed), &u32b(&v.adrs), &vals);
        assert_eq!(hx(&got), v.out, "th_multi mismatch [{}]", v.label);
        nonzero16(&got, &v.label);
    }
    for v in &k.h_msg {
        let got = h_msg(&u32b(&v.seed), &u32b(&v.root), &u32b(&v.r), &u32b(&v.msg));
        assert_eq!(hx(&got), v.out, "h_msg mismatch [{}]", v.label);
        assert_eq!(unhex(&v.out).len(), 32, "h_msg out must be 32 bytes [{}]", v.label);
        outs32.push(got);
    }
    for v in &k.chain_hash {
        let val = u16b(&v.val);
        let got = chain_hash(&u32b(&v.seed), &u32b(&v.adrs_base), &val, v.start, v.steps);
        assert_eq!(hx(&got), v.out, "chain_hash mismatch [{}]", v.label);
        if v.steps == 0 {
            // Structural identity: zero steps must return the input unchanged.
            assert_eq!(got, val, "chain_hash steps=0 must be identity [{}]", v.label);
        }
    }
    for v in &k.wots_digest {
        let got = wots_digest(&u32b(&v.seed), &u32b(&v.wots_adrs), &u32b(&v.msg), v.count);
        assert_eq!(hx(&got), v.out, "wots_digest mismatch [{}]", v.label);
        assert_eq!(unhex(&v.out).len(), 32, "wots_digest out must be 32 bytes [{}]", v.label);
        outs32.push(got);
    }
    for v in &k.wots_secret {
        let sk: [u8; 32] = u32b(&v.sk_seed);
        let got = wots_secret(&sk, v.layer, v.tree, v.kp, v.chain_idx);
        assert_eq!(hx(&got), v.out, "wots_secret mismatch [{}]", v.label);
        nonzero16(&got, &v.label);
    }
    for v in &k.fors_secret {
        let sk: [u8; 32] = u32b(&v.sk_seed);
        let got = fors_secret(&sk, v.ht_idx, v.tree_idx, v.leaf_idx);
        assert_eq!(hx(&got), v.out, "fors_secret mismatch [{}]", v.label);
        nonzero16(&got, &v.label);
    }

    // Non-vacuity: distinct inputs must give distinct digests (no accidental
    // collapse to a constant preimage).
    assert!(distinct(&outs16), "th outputs collapsed to a constant");
    assert!(distinct(&outs32), "h_msg/wots_digest outputs collapsed to a constant");
}

fn nonzero16(b: &[u8; N], label: &str) {
    assert!(b.iter().any(|&x| x != 0), "all-zero digest for [{label}] — vacuous");
}
fn distinct<const M: usize>(v: &[[u8; M]]) -> bool {
    for i in 0..v.len() {
        for j in (i + 1)..v.len() {
            if v[i] == v[j] {
                return false;
            }
        }
    }
    true
}
