/- §33 P3 — FORS index FUNCTIONAL specs (the remaining residue).

   NOT a code file — a roadmap. PANIC-FREEDOM of the entire FORS index
   path is DONE and proven (see `ForsLoop.lean`, all in the sorry-free
   default target): next_usize_spec, read_bits_le(_loop)_terminates,
   extract_ht_index_terminates, extract_fors_indices(_loop)_terminates.

   **DONE 2026-06-12: `read_bits_le_spec` (Extracted/ForsExtract.lean)
   PROVEN — kernel-clean, in the default target.** read_bits_le computes
   EXACTLY (digestWord >>> bit_offset) %% 2^num_bits, via the loop-accumulator
   invariant (lor_eq_add_disjoint OR->ADD) + window arithmetic. The remaining
   FORS work (below) now composes on top of it.

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
   serialization); it's a bit-level accumulator induction. **rank 2 DONE 2026-06-12: extract_ht_index_spec + extract_fors_indices_spec
   PROVEN** (ForsExtract.lean, kernel-clean). Once
   read_bits_le's functional spec is proven, extract_ht_index /
   extract_fors_indices compose, then vendor `Spec/Fors.lean`'s htIdx
   extraction + a `firmware_extract_ht_index_matches_vendored` bridge
   (the SpecBridge pattern) closes CWE-347 at the firmware level.

   FOUNDATIONAL LEMMA: **PROVEN 2026-06-11** — `lor_eq_add_disjoint`
   in `Extracted/Bits.lean` (closed via the LeanLoop pipeline:
   core's `Nat.testBit_two_pow_mul_add` append lemma + testBit
   extensionality; kernel-clean). The strengthened loop invariant is
   now unblocked: `val.val = <partial byte window> ∧ val.val < 256^start`
   (the < bound feeds the next step's disjointness via Bits). -/
