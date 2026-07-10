//! FORS+C model ⇔ implementation bridge — empirically ground the EasyCrypt
//! `FORS_C10.ec` abstract index map against the SHIPPED C10 Rust code.
//!
//! Closes a named systemic residual of the EasyCrypt port: *"nothing checks
//! that the EasyCrypt scheme model equals the Rust implementation on the
//! signing side."* The EC model (`FORS_C10.ec`) abstracts the FORS message-
//! hash index map as an opaque `g : out_t -> (int*int*int) list` constrained
//! by structural axioms + a `+C` predicate. This bridge builds the SAME map
//! from the shipped extractor and asserts each axiom holds, and — the
//! genuinely discriminating part — pins the EXACT bit offsets the `+C`
//! predicate and the hypertree index read from, cross-checked three ways
//! (shipped `extract_*`, a local verbatim copy of `read_bits_le`, and the
//! literal shifts in `SPHINCsC10Asm.sol`).
//!
//! Add-only: this file adds tests + a doc. No production Rust/Solidity is
//! touched. Companion doc: `docs/verification/fors-model-impl-bridge-2026-07.md`.
//!
//! ==========================================================================
//! EC-MODEL ⇔ RUST correspondence (each axiom → the line it is grounded at)
//! ==========================================================================
//!
//! Let `digest = h_msg(pk_seed, pk_root, R, m)` (256-bit). The EC model's
//! `g y` (FORS_C10.ec:163) is realised in Rust by `g_model(digest)` below as
//! the K tuples `(instance, tree, leaf)` with:
//!     instance = extract_ht_index(digest)          (all K trees share it)
//!     tree     = i                                  (loop position 0..K)
//!     leaf     = extract_fors_indices(digest)[i]    (read_bits_le@ i*A, A)
//!
//!   EC axiom (FORS_C10.ec)            Rust ground (this file / shipped code)
//!   -------------------------------  ----------------------------------------
//!   size_g  (:166) size (g y) = k    extract_fors_indices -> [u32; K]  (TYPE)
//!                                     → structural_axioms_* asserts len == 13
//!   rng_g   (:174) 0 <= leaf < t     read_bits_le masks to A bits      (CONSTR)
//!                  t = 2^a = 2048     → asserts each leaf < 2048
//!   eqiks_g (:168) all same instance instance = htIdx for all K        (CONSTR)
//!                                     → asserts all g[i].0 equal
//!   neqisvs_g(:171)/uniq_g(:192)     tree = i, positions 0..K distinct (CONSTR)
//!                  distinct trees     → asserts g[i].1 pairwise-distinct
//!   predC_fors (:197)                read_bits_le(digest, 132, 11) == 0 (PINNED,
//!     (nth (g y) (k-1)).`3 = 0         = grind_r exit cond, fors.rs:126)  EMPIRICAL)
//!                                     → predC_grounded_on_real_grind_outputs
//!   (htIdx layout, not an axiom but   read_bits_le(digest, 143, 18)     (PINNED,
//!    the on-chain FORS-forest binding: = extract_ht_index, Solidity      EMPIRICAL)
//!    Solidity shr(143) — :81)          shr(143),0x3FFFF
//!
//! HONEST SCOPE (see the doc). size_g / rng_g / eqiks_g / neqisvs_g / uniq_g
//! hold BY CONSTRUCTION (Rust type + bit-mask + loop-index): this harness
//! could NOT catch a violation of them short of a source change, and it does
//! not claim to. The genuinely EMPIRICAL, discriminating content is the
//! OFFSET PINNING (predC @ bit 132, htIdx @ bit 143) plus the local-vs-shipped
//! `read_bits_le` cross-check and the Solidity triangulation — exactly what a
//! one-bit mis-statement of the `+C` correspondence would break, as the
//! negative control proves. This grounds the INDEX/PREDICATE LAYER only; the
//! random-oracle idealisation of `H(sk||…)` and the distributional axioms
//! (`dmkey_ll`, `good_pos`) are NOT closed here.
//!
//! Run (the sim-internals feature exposes the shipped extractors — same
//! convention as fors_position_binding.rs / primitive_kat.rs):
//! ```text
//! cargo test -p sphincs-c10 --features sim-internals --test fors_model_bridge -- --nocapture
//! ```
//! Negative-control failing run (flip the pinned +C offset via env):
//! ```text
//! C10_BRIDGE_PREDC_OFFSET=131 cargo test -p sphincs-c10 --features sim-internals \
//!     --test fors_model_bridge predC_grounded_on_real_grind_outputs -- --nocapture
//! ```

#![cfg(feature = "sim-internals")]

use std::sync::OnceLock;

use sphincs_c10::params::{A, H, K, N};
use sphincs_c10::sim_internals::{extract_fors_indices, extract_ht_index, h_msg, pad16};
use sphincs_c10::{verify, SigningKey};

// ---------------------------------------------------------------------------
// Concrete literals from the EC model — pinned as LITERALS, then asserted to
// equal params. The EC model FIXES k=13, a=11, h=18; if we derived these from
// params::{K,A,H} the test would silently track params and could not catch a
// params-vs-model drift — which is precisely a divergence this bridge exists
// to catch. So: literal on the left, params::* asserted equal at runtime.
// ---------------------------------------------------------------------------

/// (k-1)*a = 12*11 = 132 — the bit offset of the LAST FORS tree's leaf index,
/// forced to zero by R-grinding (fors.rs:107,126) and by BOTH verifiers
/// (hypertree.rs / SPHINCsC10Asm.sol:86 `shr(132,…),0x7FF`).
const PREDC_BIT_OFFSET: usize = 132;
/// k*a = 13*11 = 143 — the bit offset of the 18-bit hypertree index
/// (SPHINCsC10Asm.sol:81 `and(shr(143,digest),0x3FFFF)`).
const HTIDX_BIT_OFFSET: usize = 143;
/// a = 11 — width of each FORS leaf index.
const LEAF_WIDTH: usize = 11;
/// h = 18 — width of the hypertree index.
const HTIDX_WIDTH: usize = 18;
/// k = 13 — number of FORS trees / tuples in `g y`.
const FORS_TREES: usize = 13;
/// t = 2^a = 2048 — the leaf-index bound (`rng_g`).
const LEAF_BOUND: u32 = 2048;

// ---------------------------------------------------------------------------
// VERBATIM copy of fors.rs::read_bits_le (lines 19-34). Kept local so the
// negative control can read a PERTURBED offset the shipped API never exposes.
// Faithfulness of this copy is not assumed — it is asserted, on every digest,
// against the shipped `extract_fors_indices` / `extract_ht_index` (see the
// cross-checks below). If this copy ever drifts from the shipped function the
// cross-check fails loudly.
// ---------------------------------------------------------------------------
fn local_read_bits_le(digest: &[u8; 32], bit_offset: usize, num_bits: usize) -> u64 {
    assert!(num_bits > 0 && num_bits <= 57);
    let byte_start = 31 - (bit_offset / 8);
    let bit_in_byte = bit_offset % 8;
    let bytes_needed = (num_bits + bit_in_byte + 7) / 8;

    let mut val: u64 = 0;
    for b in 0..bytes_needed {
        let idx = byte_start.wrapping_sub(b);
        if idx < 32 {
            val |= u64::from(digest[idx]) << (b * 8);
        }
    }
    let mask = (1u64 << num_bits) - 1;
    (val >> bit_in_byte) & mask
}

/// The EC model's `g : out_t -> (int*int*int) list`, realised in Rust from the
/// SHIPPED extractors. `instance = htIdx` (all K FORS trees are bound to the
/// same hypertree leaf position — matches `eqiks_g` and the Solidity
/// `shl(160, htIdx)` fold into every FORS leaf ADRS), `tree = i` (loop
/// position, distinct by construction — the model's `uniq_g`), `leaf` = the
/// shipped extracted index.
fn g_model(digest: &[u8; 32]) -> [(u32, u32, u32); K] {
    let leaves = extract_fors_indices(digest);
    let instance = extract_ht_index(digest);
    let mut g = [(0u32, 0u32, 0u32); K];
    for i in 0..K {
        g[i] = (instance, i as u32, leaves[i]);
    }
    g
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64) — reproducible, no external dependency, so
// the coordinator re-running the negative control gets identical digests.
// ---------------------------------------------------------------------------
struct SplitMix64(u64);
impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}
fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// A real grind_r output: the digest reconstructed from an EMITTED signature's
/// R (`sig[0..N]`) via the shipped `h_msg`, byte-for-byte the object grind_r's
/// forced-zero exit condition tested (fors.rs:124-126).
struct Sample {
    digest: [u8; 32],
    msg: [u8; 32],
}

/// Fixture: real grind_r digests. `predC` is a property of grind_r's exit
/// condition and is KEY-INDEPENDENT, so we spend keygens sparingly (2 keys)
/// and vary message + fresh opt_rand heavily (advisor's guidance). Each sample
/// is self-checking: `verify(...)` must accept the emitted signature, which
/// independently pins that `sig[0..N]` is R and that our `h_msg` input order
/// matches the signer's — if either were wrong, bit 132 would not be zero and
/// the predC test would fail loudly rather than pass silently.
fn grind_samples() -> &'static Vec<Sample> {
    static SAMPLES: OnceLock<Vec<Sample>> = OnceLock::new();
    SAMPLES.get_or_init(|| {
        let mut prng = SplitMix64(0x5164_9E27_C10B_51D6);
        let key_seeds: [[u8; 32]; 2] = [
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
                0xd0, 0xe0, 0xf0, 0x01,
            ],
            [
                0xa5, 0x5a, 0x3c, 0xc3, 0x0f, 0xf0, 0x69, 0x96, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
                0xde, 0xf0, 0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0xde, 0xad, 0xbe, 0xef,
                0xca, 0xfe, 0xba, 0xbe,
            ],
        ];
        let mut out: Vec<Sample> = Vec::new();
        for ks in key_seeds {
            let mut pk_seed = [0u8; N];
            prng.fill(&mut pk_seed);
            let sk = SigningKey::keygen(ks, pk_seed);
            for _ in 0..24 {
                let mut msg = [0u8; 32];
                prng.fill(&mut msg);
                let mut opt_rand = [0u8; N];
                prng.fill(&mut opt_rand);

                let sig = sk.sign(&msg, Some(&opt_rand));
                // Self-check: independently pins R placement + h_msg input order.
                assert!(
                    verify(sk.pk_seed(), sk.pk_root(), &msg, &sig),
                    "emitted signature must verify — otherwise the R-from-sig[0..N] \
                     reconstruction or the h_msg input order is wrong and every \
                     downstream predC ground is meaningless"
                );
                let mut r = [0u8; N];
                r.copy_from_slice(&sig[0..N]);
                // Reproduce grind_r's final digest exactly (fors.rs:105,123,124).
                let digest = h_msg(
                    &pad16(sk.pk_seed()),
                    &pad16(sk.pk_root()),
                    &pad16(&r),
                    &msg,
                );
                out.push(Sample { digest, msg });
            }
        }
        out
    })
}

// ===========================================================================
// TEST 1 — structural axioms (size_g, rng_g, eqiks_g, neqisvs_g/uniq_g) +
// local-vs-shipped read_bits_le faithfulness, over many random digests.
//
// These axioms hold BY CONSTRUCTION; this test pins them against LITERALS
// (not params) so a params-vs-EC-model drift is caught, and proves the local
// read_bits_le copy is faithful to the shipped extractor (the lever the
// negative control depends on).
// ===========================================================================
#[test]
fn structural_axioms_and_read_bits_faithfulness() {
    // params-vs-EC-model pin: the EC model FIXES these; assert code agrees.
    assert_eq!(K, FORS_TREES, "K must equal the EC model's k=13");
    assert_eq!(A, LEAF_WIDTH, "A must equal the EC model's a=11");
    assert_eq!(H, HTIDX_WIDTH, "H must equal the EC model's h=18");
    assert_eq!(1u32 << A, LEAF_BOUND, "t = 2^a must be 2048");
    assert_eq!((K - 1) * A, PREDC_BIT_OFFSET, "(k-1)*a must be 132");
    assert_eq!(K * A, HTIDX_BIT_OFFSET, "k*a must be 143");

    let mut prng = SplitMix64(0xC10F_0125_D0DE_1BEE);
    let mut checked = 0u64;
    for _ in 0..10_000 {
        let mut digest = [0u8; 32];
        prng.fill(&mut digest);
        let g = g_model(&digest);

        // size_g: exactly k = 13 tuples.
        assert_eq!(g.len(), FORS_TREES);

        // eqiks_g: all tuples name the SAME FORS instance (= htIdx).
        let inst0 = g[0].0;
        assert!(g.iter().all(|t| t.0 == inst0), "eqiks_g: instances differ");

        // neqisvs_g + uniq_g: the k trees are pairwise-distinct (position i).
        for i in 0..K {
            for j in (i + 1)..K {
                assert_ne!(g[i].1, g[j].1, "uniq_g: tree {i} and {j} collide");
            }
        }

        // rng_g: every leaf index in [0, t) = [0, 2048).
        for t in &g {
            assert!(t.2 < LEAF_BOUND, "rng_g: leaf {} >= 2048", t.2);
        }

        // Faithfulness: the local read_bits_le copy composes exactly to the
        // shipped extract_fors_indices, per position. This is what makes the
        // negative control's PERTURBED offset a real perturbation of the
        // shipped semantics.
        let leaves = extract_fors_indices(&digest);
        for i in 0..K {
            assert_eq!(
                local_read_bits_le(&digest, i * LEAF_WIDTH, LEAF_WIDTH) as u32,
                leaves[i],
                "local read_bits_le@{} != shipped extract[{i}]",
                i * LEAF_WIDTH
            );
        }
        // htIdx faithfulness: local read_bits_le@143 == shipped extract_ht_index
        // (== Solidity `shr(143,digest),0x3FFFF`).
        assert_eq!(
            local_read_bits_le(&digest, HTIDX_BIT_OFFSET, HTIDX_WIDTH) as u32,
            extract_ht_index(&digest),
            "local read_bits_le@143 != shipped extract_ht_index"
        );
        checked += 1;
    }
    eprintln!(
        "structural axioms (size_g/rng_g/eqiks_g/uniq_g) + read_bits_le \
         faithfulness: {checked} random digests, all pass"
    );
}

// ===========================================================================
// TEST 2 — predC_fors grounded on REAL grind_r outputs.
//
// For every emitted signature's reconstructed digest, the pinned +C predicate
// `read_bits_le(digest, 132, 11) == 0` must hold. Offset + target are env-
// overridable ONLY to produce the negative-control failing run
// (C10_BRIDGE_PREDC_OFFSET / C10_BRIDGE_PREDC_TARGET); defaults are the
// pinned-correct (132, 0).
// ===========================================================================
#[test]
#[allow(non_snake_case)] // deliberate: mirrors the EC op name `predC_fors`
fn predC_grounded_on_real_grind_outputs() {
    assert_eq!(K, FORS_TREES);
    assert_eq!(A, LEAF_WIDTH);

    let offset = env_usize("C10_BRIDGE_PREDC_OFFSET", PREDC_BIT_OFFSET);
    let target = env_u64("C10_BRIDGE_PREDC_TARGET", 0);
    let overridden = offset != PREDC_BIT_OFFSET || target != 0;

    let samples = grind_samples();
    assert!(!samples.is_empty(), "no grind samples generated");

    for (n, s) in samples.iter().enumerate() {
        // predC via the SHIPPED extractor: last FORS tree's leaf index.
        let last_via_extract = extract_fors_indices(&s.digest)[K - 1];
        // predC via the LOCAL faithful read_bits_le at the (possibly perturbed) offset.
        let last_via_local = local_read_bits_le(&s.digest, offset, LEAF_WIDTH);

        if !overridden {
            // At the pinned offset the two MUST agree: this is the tautology
            // that grind_r's exit condition == extract[K-1] == read_bits_le@132.
            assert_eq!(
                last_via_local as u32, last_via_extract,
                "sample {n}: local read_bits_le@132 must equal shipped extract[K-1]"
            );
            // htIdx layout cross-check (Solidity shr(143), width H).
            assert_eq!(
                local_read_bits_le(&s.digest, HTIDX_BIT_OFFSET, HTIDX_WIDTH) as u32,
                extract_ht_index(&s.digest),
                "sample {n}: htIdx bit-143 layout must match shipped extract_ht_index"
            );
        }

        // The grounding assertion: predC holds on this real grind_r output.
        assert_eq!(
            last_via_local, target,
            "sample {n}: predC_fors at bit {offset} width {LEAF_WIDTH} must equal \
             {target} on a real grind_r output (msg[..4]={:02x?}) — at the pinned \
             (132,0) this is grind_r's forced-zero exit condition; a non-default \
             offset/target is the negative-control failing run",
            &s.msg[..4]
        );
    }
    eprintln!(
        "predC grounded: {} real grind_r digests, all read_bits_le(digest,{offset},{LEAF_WIDTH}) == {target}{}",
        samples.len(),
        if overridden { "  [ENV-OVERRIDDEN — expected to FAIL if offset/target wrong]" } else { "" }
    );
}

// ===========================================================================
// TEST 3 — NEGATIVE CONTROL (always green): the harness discriminates the
// EXACT +C offset.
//
// If the +C offset were mis-stated by even one bit, this bridge would catch
// it. We prove that at the PERTURBED offset 131 (one below the pinned 132),
// read_bits_le is NOT universally zero over the SAME real grind_r digests,
// while at the pinned 132 it is zero on every one. So the offset-132 grounding
// in TEST 2 is non-trivial: it pins the exact bit, not merely "some low bit".
// Also perturbs the TARGET (==1 must not universally hold).
// ===========================================================================
#[test]
fn negative_control_perturbed_offset_is_not_universal() {
    let samples = grind_samples();
    let perturbed = PREDC_BIT_OFFSET - 1; // 131 — one bit below the forced-zero window

    let nonzero_at_correct = samples
        .iter()
        .filter(|s| local_read_bits_le(&s.digest, PREDC_BIT_OFFSET, LEAF_WIDTH) != 0)
        .count();
    let nonzero_at_perturbed = samples
        .iter()
        .filter(|s| local_read_bits_le(&s.digest, perturbed, LEAF_WIDTH) != 0)
        .count();

    // The pinned offset is zero on EVERY real grind_r output (the property).
    assert_eq!(
        nonzero_at_correct, 0,
        "sanity: pinned +C offset {PREDC_BIT_OFFSET} must be zero on every grind_r output"
    );

    // The perturbed offset is NOT — proving the harness distinguishes the exact
    // bit. If this were also universally zero the grounding would be false
    // comfort (the harness could not tell 132 from 131).
    assert!(
        nonzero_at_perturbed > 0,
        "NEGATIVE CONTROL FAILED: perturbed offset {perturbed} was ALSO universally \
         zero over {} samples — the harness cannot distinguish the correct +C offset \
         from a neighbouring one, so its grounding is not discriminating",
        samples.len()
    );

    // Perturb the TARGET: predC with target==1 must NOT universally hold.
    let all_one = samples
        .iter()
        .all(|s| local_read_bits_le(&s.digest, PREDC_BIT_OFFSET, LEAF_WIDTH) == 1);
    assert!(
        !all_one,
        "target perturbation: read_bits_le@132 == 1 must not universally hold"
    );

    eprintln!(
        "negative control: pinned offset {} nonzero on {}/{} samples; \
         perturbed offset {} nonzero on {}/{} samples (harness discriminates the exact bit)",
        PREDC_BIT_OFFSET,
        nonzero_at_correct,
        samples.len(),
        perturbed,
        nonzero_at_perturbed,
        samples.len()
    );
}
