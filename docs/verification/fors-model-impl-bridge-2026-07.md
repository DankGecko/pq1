# FORS+C model ⇔ implementation bridge (2026-07)

**What this closes.** A named systemic residual of the EasyCrypt port:
*"nothing checks that the EasyCrypt scheme model equals the Rust
implementation on the signing side."* The EC model
(`contracts/verification/easycrypt/drafts/FORS_C10.ec`, vendored from
`c10-eufcma-port/drafts/FORS_C10.ec`) abstracts the FORS message-hash index
map as an opaque `g : out_t -> (int*int*int) list` plus a `+C` predicate
`predC_fors`. Until now the *contents* of that abstraction — the digest bit
layout, the forced-zero offset, the tree/leaf split — were asserted only in
the paper text of the `.ec` file's comments, never checked against the shipped
`sphincs-c10` crate. This bridge builds the SAME map in Rust from the shipped
extractor and asserts each axiom, and — the discriminating part — pins the
EXACT bit offsets the predicate and the hypertree index read from, triangulated
against the shipped Rust, a local verbatim `read_bits_le`, and the on-chain
Yul verifier.

**Add-only.** The work is `sphincs-c10/tests/fors_model_bridge.rs` (a test
module) + this doc. No production Rust or Solidity was changed.

**Scope, stated up front.** This grounds the **index / predicate LAYER** — the
digest-bit map and the `+C` forced-zero offset — against the shipped code. It
does **NOT** verify the cryptographic idealisation the EC game rests on (the
random-oracle model of the keyed hash, the distributional axioms). See
"What remains idealized" below. Grounding the layout is real and valuable; it
is not a proof of the security reduction.

---

## The two sides

| | EC model (`FORS_C10.ec`) | C10 Rust (`sphincs-c10`) |
|---|---|---|
| Index map | `g : out_t -> (int*int*int) list` (:163) | `extract_fors_indices(digest) -> [u32; K]` (`fors.rs:42`) |
| Digest | `out_t` (opaque) | `digest = h_msg(pk_seed, pk_root, R, m)` — 256-bit (`fors.rs:124`) |
| `+C` predicate | `predC_fors y = (nth witness (g y) (k-1)).\`3 = 0` (:197) | `read_bits_le(digest, (K-1)*A, A) == 0`, i.e. `read_bits_le(digest, 132, 11) == 0` (`fors.rs:107,126`, `grind_r` exit) |
| Params | `k=13`, `a=11`, `t=2^a=2048` (fixed) | `K=13`, `A=11`, `H=18`, `FORS_LEAVES=2^A` (`params.rs`) |

The Rust `g_model(digest)` in the test realises the EC `g y` as the K tuples
`(instance, tree, leaf)` with `instance = extract_ht_index(digest)` (all K FORS
trees share the one hypertree leaf position), `tree = i` (loop position `0..K`),
`leaf = extract_fors_indices(digest)[i]`.

---

## Correspondence pinned (the whole point)

| EC axiom (`FORS_C10.ec` line) | Rust ground | Kind | Test |
|---|---|---|---|
| `size_g` (:166) `size (g y) = k` | `extract_fors_indices` returns `[u32; K]` | **by construction** (type) | `structural_axioms_and_read_bits_faithfulness` — asserts `len == 13` (literal) |
| `rng_g` (:174) `0 <= leaf < t`, `t=2048` | `read_bits_le(_, i*A, A)` masks to `A` bits | **by construction** (bit-mask) | same — asserts each `leaf < 2048` (literal) |
| `eqiks_g` (:168) all tuples same instance | `instance = htIdx` for all K | **by construction** | same — asserts all `g[i].0` equal |
| `neqisvs_g` (:171) / `uniq_g` (:192) distinct trees | `tree = i`, positions `0..K` distinct | **by construction** | same — asserts `g[i].1` pairwise-distinct |
| `predC_fors` (:197) `(nth (g y)(k-1)).\`3 = 0` | `read_bits_le(digest, **132**, 11) == 0` | **PINNED / EMPIRICAL** | `predC_grounded_on_real_grind_outputs` — over real `grind_r` outputs |
| (htIdx layout — the FORS-forest ⇔ position binding, not an axiom) | `read_bits_le(digest, **143**, 18) == extract_ht_index` | **PINNED / EMPIRICAL** | both structural + predC tests, cross-checked against Solidity |

The **exact** offsets are the load-bearing content: `(k-1)*a = 12*11 = 132`
width 11 for `predC_fors`; `k*a = 13*11 = 143` width 18 for the hypertree
index. A bridge that checked a weaker or shifted correspondence would be false
comfort — the negative control (below) proves this harness is not that.

The test pins `132`, `143`, `2048`, `13`, `11`, `18` as **literals** and then
asserts `K/A/H` equal them — so a params-vs-EC-model drift (the EC model's
`k,a,h` are fixed) is caught, rather than silently tracked.

---

## What is now EMPIRICALLY GROUNDED

1. **The `+C` predicate over the shipped digest layout.** Over 48 real
   `grind_r` outputs (2 keys × 24 messages, fresh `opt_rand` each), the digest
   reconstructed from the emitted signature's `R = sig[0..N]` via the shipped
   `h_msg` satisfies `read_bits_le(digest, 132, 11) == 0` on every sample. Each
   sample is self-checking: `verify(pk_seed, pk_root, msg, sig)` must accept the
   signature, which independently pins that `sig[0..N]` is `R` and that the
   `h_msg` input order matches the signer — if either were wrong, bit 132 would
   not be zero and the test would fail loudly rather than pass silently.

2. **The local-vs-shipped `read_bits_le` faithfulness.** A verbatim copy of
   `fors.rs::read_bits_le` (needed so the negative control can read an offset
   the shipped API never exposes) is asserted, on every digest, to compose
   exactly to the shipped `extract_fors_indices` per position and to the shipped
   `extract_ht_index` at offset 143. So the perturbed-offset read in the
   negative control is a real perturbation of the shipped semantics, not of a
   private reimplementation.

3. **On-chain agreement (`SPHINCsC10Asm.sol`).** The same two offsets appear in
   the deployed Yul verifier, confirming the model, the firmware, and the
   contract agree on the layout:
   - `SPHINCsC10Asm.sol:86` — `if and(shr(132, dVal), 0x7FF) { revert(0, 0) }`
     — the forced-zero window is bits 132..142 (11 bits), == `predC_fors`.
   - `SPHINCsC10Asm.sol:81` — `let htIdx := and(shr(143, digest), 0x3FFFF)` —
     the 18-bit hypertree index at bit 143, == `extract_ht_index` == the
     bridge's `read_bits_le(digest, 143, 18)`.
   - `SPHINCsC10Asm.sol:91,97` — `treeIdx := and(shr(mul(i, 11), dVal), 0x7FF)`
     and `or(shl(96, i), treeIdx)` — the per-tree leaf at `i*11`, with the ADRS
     *tree field* = the loop position `i`, == the model's `tree = i` and hence
     `uniq_g` (position `i` = tree `i` ⇒ K distinct trees).

**Honest note on "by construction".** `size_g`, `rng_g`, `eqiks_g`,
`neqisvs_g`, and `uniq_g` hold by Rust type / bit-mask / loop-index and this
harness could **not** catch a violation of them short of a source change — it
asserts them, and pins them to literals against a params drift, but their
empirical discriminating power is nil. The genuinely discriminating,
empirical content of this bridge is the **offset pinning** (predC @ 132,
htIdx @ 143) plus the local-vs-shipped cross-check and the Solidity
triangulation. That is exactly what a one-bit mis-statement of the `+C`
correspondence would break.

### Negative control (mandatory — the harness discriminates the exact bit)

`negative_control_perturbed_offset_is_not_universal` (always green) proves the
grounding is non-trivial: over the same 48 real `grind_r` digests, the pinned
offset 132 is zero on **0/48** (i.e. all satisfy predC), while the perturbed
offset 131 (one bit below the forced-zero window) is nonzero on **19/48**. So
the harness distinguishes 132 from a neighbouring bit — a mis-stated offset
would be caught, not silently accepted. A target perturbation (`==1` must not
universally hold) is checked too.

Separately, the grounding assertion in `predC_grounded_on_real_grind_outputs`
is offset/target-overridable via env vars **solely** to exhibit the failing
run: flipping the pinned offset 132 → 131 makes it fail on sample 1
(`left: 1, right: 0`). See the pasted run in the landing report / below.

---

## What REMAINS IDEALIZED (NOT closed by this bridge)

This bridge grounds the digest **layout and predicate**. It does not touch the
cryptographic idealisation the EC EUF-CMA argument rests on. Explicitly open:

1. **Random-oracle idealisation of the keyed hash.** The EC oracle
   (`O_ITSRC10_Default.query`, :253) draws the message key `mk` from
   `dcond dmkey (good m)` — a uniform draw conditioned on `predC`. The shipped
   `R` is *not* uniform: it is `trunc(sha256(sk_seed ‖ "R_grind" ‖ opt_rand ‖ m
   ‖ nonce))` grinding to the forced-zero exit (`fors.rs:98-131`). Modelling
   that keyed derivation as a fresh draw from a distribution is a
   **random-oracle idealisation** — the same idealisation MM45 makes for its own
   `mco` key. This bridge does not (and cannot, empirically) verify the RO
   assumption; it only checks that the *index map applied to the digest* matches.

2. **The distributional axioms `dmkey_ll` (:149) and `good_pos` (:208).**
   `good_pos` is the paper's `p_nu` ("it is always possible to find a good
   counter"), load-bearing for oracle losslessness (`query_ll`). This is a
   quantitative axiom over the hash's output distribution — not something a
   layout test can ground. The fact that `grind_r` never panics in 10M
   iterations across every test run is *consistent operational evidence* that
   good `R`'s are findable, but it does **not** ground the distributional axiom
   (it is not a measurement of `mu dmkey (good m)`, and the RO model is what
   licenses treating the grind as such a draw).

3. **Per-signing-call fresh, non-memoized `opt_rand`.** The EC oracle does NOT
   memoize: a fresh conditioned key per query (:231-260), because production
   draws a fresh `opt_rand` on **every** signing call
   (`secure/src/crypto.rs:130-142`: `rng_strong::fill(&mut opt_rand_buf)`, then
   `Some(&opt_rand_buf)`), so signing the same message twice yields a different
   `R`, digest, and revealed FORS leaves (regression
   `positive_opt_rand_changes_sig_bytes`). This bridge exercises fresh
   `opt_rand` per sample (so the digests are genuinely distinct grind outputs),
   which is *consistent with* the non-memoized model, but the modelling choice
   (fresh `dcond` draw per query, no `mmap`) is a design decision about the
   game, not a code property this test verifies.

4. **The tight security bound itself is OPEN in the EC file.** `FORS_C10.ec`
   proves the model + game + 7 structural lemmas with no `admit`, but the tight
   `Pr[ITSRC10]` bound (the DarkSide direct argument) is deliberately not
   discharged; the black-box route to MM45's ITSR is the ~102-bit dead end
   documented in the file header. Nothing here changes that.

**Bottom line.** The digest index map and the `+C` forced-zero offset in
`FORS_C10.ec` now match the shipped `sphincs-c10` extractor and the deployed
`SPHINCsC10Asm.sol` verifier, checked empirically and triangulated three ways,
with a negative control that catches a one-bit mis-statement. The cryptographic
idealisation (RO model of `H(sk‖…)`, the `p_nu`/`dmkey` distributional axioms,
the open tight bound) is unchanged and unverified.

---

## Run

```text
# passing suite (sim-internals exposes the shipped extractors)
cargo test -p sphincs-c10 --features sim-internals --test fors_model_bridge -- --nocapture

# negative-control FAILING run: flip the pinned +C offset 132 -> 131
C10_BRIDGE_PREDC_OFFSET=131 cargo test -p sphincs-c10 --features sim-internals \
    --test fors_model_bridge predC_grounded_on_real_grind_outputs -- --nocapture
```

The `--features sim-internals` flag is required (same convention as
`fors_position_binding.rs` / `primitive_kat.rs`): it re-exports the shipped
`extract_fors_indices` / `extract_ht_index` / `h_msg` / `pad16` so the bridge
checks the SHIPPED code, not a reimplementation. Without the feature the file
compiles to zero tests. `--release` is recommended (the fixture does two full
`SigningKey::keygen`s + 48 signs); the whole suite runs in ~2 s in release.
