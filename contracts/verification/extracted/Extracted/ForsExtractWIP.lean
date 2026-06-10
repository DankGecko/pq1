/- §33 P3 — FORS index FUNCTIONAL specs (the remaining residue).

   NOT a code file — a roadmap. PANIC-FREEDOM of the entire FORS index
   path is DONE and proven (see `ForsLoop.lean`, all in the sorry-free
   default target): next_usize_spec, read_bits_le(_loop)_terminates,
   extract_ht_index_terminates, extract_fors_indices(_loop)_terminates.

   What REMAINS (the "genuinely mathy" part the research flagged):
   FUNCTIONAL correctness — that extract_ht_index computes the right
   value, not merely that it doesn't panic:

     extract_ht_index digest = (digest_le_u256 >>> 143) &&& 0x3FFFF

   (= the Yul `and(shr(143, digest), 0x3FFFF)` and the firmware-side
   close of the CWE-347 FORS-position binding).

   The hard core is a LOOP ACCUMULATOR INVARIANT for read_bits_le_loop:
   after processing range [start, k), the accumulator `val` equals the
   bits [start_bit .. k*8) of the digest, little-endian. Concretely,
   strengthen the `loop.spec_decr_nat` post (currently `_ => True`) to
       post := fun v => v.val = <partial LE bit-read of digest>
   and the invariant to relate `val` to the bytes consumed so far. This
   is NOT the SetSliceLemmas byte-layout method (that's for fixed-offset
   serialization); it's a bit-level accumulator induction. Once
   read_bits_le's functional spec is proven, extract_ht_index /
   extract_fors_indices compose, then vendor `Spec/Fors.lean`'s htIdx
   extraction + a `firmware_extract_ht_index_matches_vendored` bridge
   (the SpecBridge pattern) closes CWE-347 at the firmware level.

   FOUNDATIONAL LEMMA NEEDED (the load-bearing fact, attempted
   2026-06-10): the accumulator step `val ||| (x <<< 8b) = val + x*2^8b`
   when `val < 2^8b` and `x < 256` (the new byte's bits are disjoint
   from the occupied low bits, so OR = ADD). This is a known-true Nat
   fact (disjoint-or-equals-add) but its mathlib name was not quickly
   located by hand; provable via `Nat.eq_of_testBit_eq` + the
   testBit-of-or / testBit-of-shiftLeft lemmas + carry-free
   testBit-of-add, or by finding the existing
   `land_eq_zero → lor = add` lemma. With it, the strengthened loop
   invariant is `val.val = <partial byte window> ∧ val.val < 256^start`
   (the < bound feeds the next step's disjointness).

   This is prime AI-prover-loop fodder: a well-scoped invariant-discovery
   problem on a frozen, fully-panic-free function, blocked only on a
   named-lemma lookup the AI loop resolves trivially. -/
