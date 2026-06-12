/- §33 rank 8 — rlp::decode_item: FUNCTIONAL spec (statement only).

   The canonical-RLP boundary: every length threshold and leading-zero rule is
   where historical RLP bugs live, and `used` (bytes consumed) drives the list
   walk — a wrong `used` desyncs every subsequent field.

   The reference `decodeRef` below is an INDEPENDENT transcription of the RLP
   grammar (5-way first-byte split + the 6 canonical-form checks), returning
   `(isList, used)` on accept and `none` on reject. It was #eval-validated
   byte-for-byte against the real tx-core/tests/rlp_decoder.rs vectors (8
   positive + 7 negative — single byte / empty / short & long string & list /
   the 0x81,0x00 & 0x81,0x7f NonCanonical / 0x83,0x11,0x22 & 0xb9,0x10
   Truncated / long-form-≤55) BEFORE being stated, so the spec itself is
   ground-truth-checked, not just plausible.

   Proof plan: unfold decode_item; case on `first` (Slice.first → some; the
   ≤0x7f / ≤0xb7 / ≤0xbf / ≤0xf7 / else ladder via scalar_tac); each branch
   mirrors a decodeRef arm. decode_length_be is the rank-7 BE accumulator
   (checked_shl/checked_add never overflow for len_of_len ≤ 8 — reuse
   bytes_to_u64's beValue argument). The Item payload slice = input[header..
   total] is a Slice.index identity. NOTE: the extraction axiomatized
   core::{checked_shl, Option.ok_or, Try.branch, Slice.first}; the proof phase
   should DEF these (the into_iter pattern) or whitelist them — they are total
   stdlib helpers, not content axioms. -/
import Extracted.Decode.Funs

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_tx_core

/-- Independent canonical-RLP reference: `(isList, used)` on accept, `none` on
    reject. #eval-validated against the rlp_decoder.rs vectors (see header). -/
def decodeRef (input : List Nat) : Option (Bool × Nat) :=
  match input with
  | [] => none
  | first :: _ =>
    if first ≤ 0x7f then some (false, 1)
    else if first ≤ 0xb7 then
      let len := first - 0x80
      let total := 1 + len
      if input.length < total then none
      else if len = 1 ∧ (input.getD 1 0) ≤ 0x7f then none
      else some (false, total)
    else if first ≤ 0xbf then
      let lol := first - 0xb7
      if lol = 0 ∨ lol > 8 then none
      else if input.length < 1 + lol then none
      else match (input.drop 1).take lol with
        | [] => none
        | b0 :: tl =>
          if b0 = 0 then none
          else let len := (b0 :: tl).foldl (fun a b => a * 256 + b) 0
               if len ≤ 55 then none
               else let total := 1 + lol + len
                    if input.length < total then none else some (false, total)
    else if first ≤ 0xf7 then
      let len := first - 0xc0
      let total := 1 + len
      if input.length < total then none else some (true, total)
    else
      let lol := first - 0xf7
      if lol = 0 ∨ lol > 8 then none
      else if input.length < 1 + lol then none
      else match (input.drop 1).take lol with
        | [] => none
        | b0 :: tl =>
          if b0 = 0 then none
          else let len := (b0 :: tl).foldl (fun a b => a * 256 + b) 0
               if len ≤ 55 then none
               else let total := 1 + lol + len
                    if input.length < total then none else some (true, total)

/-- True iff the decoded item is a list — matched against `decodeRef`'s flag. -/
def itemIsList : rlp.Item → Bool
  | .Bytes _ => false
  | .List _ => true

/-- **Functional spec**: `decode_item` accepts exactly the canonical inputs
    `decodeRef` accepts, returns the matching `used`, and the item kind agrees.
    (The payload-slice identity `input[header..used]` is a follow-on refinement
    once the accept/used/kind core is closed.) -/
theorem decode_item_spec (input : Slice Std.U8) :
    rlp.decode_item input
      ⦃ r =>
        match decodeRef (input.val.map (·.val)) with
        | none => ∃ e, r = core.result.Result.Err e
        | some (isList, used) =>
            ∃ item u, r = core.result.Result.Ok (item, u) ∧
              u.val = used ∧ itemIsList item = isList ⦄ := by
  sorry

end Extracted.Equiv
