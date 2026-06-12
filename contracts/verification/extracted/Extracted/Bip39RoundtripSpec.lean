/- §33 rank 9 — bip39 11-bit pack/unpack round-trip: FUNCTIONAL spec
   (statement only). The bug-prone part of BIP-39 mnemonic ↔ entropy is the
   MSB-first 11-bit packing arithmetic (top = 24 - shift - 11): an off-by-one
   there silently corrupts entropy on every recovery. roundtrip_11 writes an
   11-bit value into a fresh 33-byte buffer and reads it back; the spec is
   that this is the identity for in-range values at any in-bounds offset —
   i.e. write_11_bits and read_11_bits are exact inverses, the lemma the full
   24-word from_entropy/to_entropy bijection composes from.

   Proof plan: unfold roundtrip_11; write_11_bits is a sequence of `buf[k] |=`
   (setSlice!-on-single-bytes / Array.update with OR); read_11_bits loads the
   same ≤3 bytes big-endian and masks the window. The combined 24-bit value
   after write has `value << (24-shift-11)` in the touched bytes (disjoint OR
   into a zero buffer = ADD, lor_shiftLeft_add); read shifts back by the same
   `top` and masks 0x7FF, recovering value (value < 2^11). A window-arithmetic
   proof in the rank-1 family (digestWord_byte-style byte assembly + mask). -/
import Extracted.Bip39.Funs
import Extracted.WotsDigits   -- lor_shiftLeft_add

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open sphincs_tz_bip39

/-- **Functional spec**: the 11-bit pack/unpack is the identity for in-range
    values at any offset whose 3-byte window fits the 33-byte buffer. -/
theorem roundtrip_11_id (value : Std.U16) (bit : Std.Usize)
    (hv : value.val < 2 ^ 11) (hb : bit.val ≤ 253) :
    full.roundtrip_11 value bit ⦃ r => r = value ⦄ := by
  sorry

end Extracted.Equiv
