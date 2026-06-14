/- §33 axiom-collapse: the pure hash layer.

   Every former content axiom (`th_pair_pure`, `th_multi_pure`,
   `chain_hash_pure`, `wots_digest_pure`, `leaf_hash_pure`, `node_hash_pure`)
   is now a DEF over ONE function, `sha256_pure`, exposing its exact
   domain-separated preimage layout. The layouts for the five sphincs-c10
   primitives are PROVEN against the real extracted Rust in
   `Extracted/HashSpecs.lean`; the two tx trust-bundle constructors
   (`leaf_hash_pure` = sha256(0x00 ‖ canonical), `node_hash_pure` =
   sha256(0x01 ‖ l ‖ r)) mirror the 6-line Rust bodies in
   `tx/src/erc20/merkle.rs:72-92` by manual review — their variable-length
   `canonical` is not stack-bufferable in no_std, so they stay un-extracted
   (same deferral class as `personal_sign_prefixed_hash`).

   `sha256_pure` itself is pinned to the vendored FIPS 180-4 transcription
   (`Extracted/Sha256Vendored.lean`, drift-guarded against
   `lean/SphincsCVerify/Spec/Sha256Impl.lean`, which passes the full
   229-vector NIST CAVP suite via `make verify-cavp`).

   Every def here is `@[irreducible]`: the rank proofs treat hash results
   opaquely (and `congr`-style tactics whnf-diverge on unfolded hash bodies —
   see the rank-5 grind notes). -/
import Aeneas
import Extracted.Sha256Pure
open Aeneas Aeneas.Std Result

/-- Truncate a 32-byte digest to its top 16 bytes (`hash::truncate`). -/
def truncate16 (d : Std.Array Std.U8 32#usize) :
    Std.Array Std.U8 16#usize :=
  ⟨d.val.take 16, by
    have := d.property
    simp_all [List.length_take]⟩

/-- Right-zero-pad a 16-byte value to 32 bytes (`hash::pad16`). -/
def pad16Pure (v : Std.Array Std.U8 16#usize) :
    Std.Array Std.U8 32#usize :=
  ⟨v.val ++ List.replicate 16 0#u8, by
    have := v.property
    simp_all⟩

/-- The 4 big-endian bytes of `n` (low 32 bits), `u32::to_be_bytes`. -/
def u32beBytes (n : Nat) : List Std.U8 :=
  [⟨BitVec.ofNat 8 (n >>> 24)⟩, ⟨BitVec.ofNat 8 (n >>> 16)⟩,
   ⟨BitVec.ofNat 8 (n >>> 8)⟩, ⟨BitVec.ofNat 8 n⟩]

/-- `adrs` with bytes [24..28) replaced by the BE encoding of `pos` —
    the per-step chain-position tweak inside `hash::chain_hash`. -/
def chainAdrs (adrs : Std.Array Std.U8 32#usize) (pos : Nat) :
    Std.Array Std.U8 32#usize :=
  ⟨adrs.val.take 24 ++ u32beBytes pos ++ adrs.val.drop 28, by
    have := adrs.property
    simp_all [u32beBytes]⟩

/-- `th(seed, adrs, val) = sha256(seed ‖ adrs ‖ val)[0..16]` (96-B preimage). -/
def th_pure
    (seed adrs val : Std.Array Std.U8 32#usize) : Std.Array Std.U8 16#usize :=
  truncate16 (sha256_pure (seed.val ++ adrs.val ++ val.val))

/-- `th_pair(seed, adrs, l, r) = sha256(seed ‖ adrs ‖ l ‖ r)[0..16]`
    (128-B preimage). -/
def th_pair_pure
    (seed adrs l r : Std.Array Std.U8 32#usize) : Std.Array Std.U8 16#usize :=
  truncate16 (sha256_pure (seed.val ++ adrs.val ++ l.val ++ r.val))

/-- `th_multi(seed, adrs, vals) = sha256(seed ‖ adrs ‖ pad16(v₀) ‖ …)[0..16]`
    (64 + 32·|vals| bytes; meaningful for |vals| ≤ 43 = TH_MULTI_MAX). -/
def th_multi_pure
    (seed adrs : Std.Array Std.U8 32#usize)
    (vals : Slice (Std.Array Std.U8 16#usize)) : Std.Array Std.U8 16#usize :=
  truncate16 (sha256_pure
    (seed.val ++ adrs.val ++ (vals.val.map (fun v => (pad16Pure v).val)).flatten))

/-- `wots_digest(seed, adrs, msg, count) = sha256(seed ‖ adrs ‖ msg ‖
    count_uint256)` — full 32-byte digest; `count` sits in bytes [124..128)
    of the 128-B preimage, the rest of its word zero. -/
def wots_digest_pure
    (seed adrs padded : Std.Array Std.U8 32#usize) (count : Std.U32) :
    Std.Array Std.U8 32#usize :=
  sha256_pure (seed.val ++ adrs.val ++ padded.val ++
    (List.replicate 28 0#u8 ++ u32beBytes count.val))

/-- `chain_hash(seed, adrs, x, start, steps)` — fold `th` for `steps`
    iterations, tweaking the ADRS chain position to `start + i` per step;
    the 32-byte running value is the 16-byte chain value right-zero-padded.
    Total for all inputs; equals the Rust for `start + steps ≤ u32::MAX`
    (the extracted code panics past that — see `chain_hash_spec`). -/
def chain_hash_pure
    (seed adrs : Std.Array Std.U8 32#usize) (x : Std.Array Std.U8 16#usize)
    (start steps : Std.U32) : Std.Array Std.U8 16#usize :=
  truncate16 ((List.range steps.val).foldl
    (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs (start.val + i)) cur))
    (pad16Pure x))

/-- Trust-bundle leaf: `sha256(0x00 ‖ canonical)` (`erc20::merkle::leaf_hash`,
    manual-review fidelity — see module docstring). -/
def leaf_hash_pure (canonical : Slice Std.U8) :
    Std.Array Std.U8 32#usize :=
  sha256_pure (0#u8 :: canonical.val)

/-- Trust-bundle node: `sha256(0x01 ‖ l ‖ r)` (`erc20::merkle::node_hash`,
    manual-review fidelity — see module docstring). -/
def node_hash_pure
    (l r : Std.Array Std.U8 32#usize) : Std.Array Std.U8 32#usize :=
  sha256_pure (1#u8 :: (l.val ++ r.val))

/-! ### Controlled-unfolding equations (stated before irreducibility) -/

theorem truncate16_val (d : Std.Array Std.U8 32#usize) :
    (truncate16 d).val = d.val.take 16 := rfl

theorem pad16Pure_val (v : Std.Array Std.U8 16#usize) :
    (pad16Pure v).val = v.val ++ List.replicate 16 0#u8 := rfl

theorem chainAdrs_val (adrs : Std.Array Std.U8 32#usize) (pos : Nat) :
    (chainAdrs adrs pos).val = adrs.val.take 24 ++ u32beBytes pos ++ adrs.val.drop 28 := rfl

theorem th_pure_def (seed adrs val : Std.Array Std.U8 32#usize) :
    th_pure seed adrs val = truncate16 (sha256_pure (seed.val ++ adrs.val ++ val.val)) := rfl

theorem th_pair_pure_def (seed adrs l r : Std.Array Std.U8 32#usize) :
    th_pair_pure seed adrs l r
      = truncate16 (sha256_pure (seed.val ++ adrs.val ++ l.val ++ r.val)) := rfl

theorem th_multi_pure_def (seed adrs : Std.Array Std.U8 32#usize)
    (vals : Slice (Std.Array Std.U8 16#usize)) :
    th_multi_pure seed adrs vals
      = truncate16 (sha256_pure
          (seed.val ++ adrs.val ++ (vals.val.map (fun v => (pad16Pure v).val)).flatten)) := rfl

theorem wots_digest_pure_def (seed adrs padded : Std.Array Std.U8 32#usize) (count : Std.U32) :
    wots_digest_pure seed adrs padded count
      = sha256_pure (seed.val ++ adrs.val ++ padded.val ++
          (List.replicate 28 0#u8 ++ u32beBytes count.val)) := rfl

theorem chain_hash_pure_def (seed adrs : Std.Array Std.U8 32#usize)
    (x : Std.Array Std.U8 16#usize) (start steps : Std.U32) :
    chain_hash_pure seed adrs x start steps
      = truncate16 ((List.range steps.val).foldl
          (fun cur i => pad16Pure (th_pure seed (chainAdrs adrs (start.val + i)) cur))
          (pad16Pure x)) := rfl

theorem leaf_hash_pure_def (canonical : Slice Std.U8) :
    leaf_hash_pure canonical = sha256_pure (0#u8 :: canonical.val) := rfl

theorem node_hash_pure_def (l r : Std.Array Std.U8 32#usize) :
    node_hash_pure l r = sha256_pure (1#u8 :: (l.val ++ r.val)) := rfl

attribute [irreducible] truncate16 pad16Pure chainAdrs th_pure th_pair_pure
  th_multi_pure wots_digest_pure chain_hash_pure leaf_hash_pure node_hash_pure
