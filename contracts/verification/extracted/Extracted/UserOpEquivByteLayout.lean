/- §33 P2 WIP — full byte-layout equivalence for `compute_user_op_hash`.

   NOT imported into the default target (`Extracted.lean`) and NOT in
   AxiomCheck: it carries a `sorry` on the list-arithmetic tail, and
   the §33 discipline keeps the shipped target sorry-free.

   STATUS: `step*` performs the ENTIRE symbolic execution and the goal
   reduces to a single equation — the 320-byte buffer built by the ten
   `setSlice!` writes equals the abi.encode preimage `specInner`, and
   likewise the 96-byte outer buffer equals `specOuter`. What remains
   is pure list arithmetic: pushing `setSlice!` (= take ++ s' ++ drop)
   through a `List.replicate` initial buffer at ten disjoint
   word-aligned positions and recognizing the concatenation. Unfolding
   `List.setSlice!` definitionally over the 320-element replicate times
   out; the right move (for the §33 P1 AI-prover loop, or a focused
   manual session) is a `setSlice!`-into-`replicate`-at-disjoint-spans
   lemma proven once and reused, OR `List.ext_getElem!` elementwise
   with `getElem!_setSlice!_{prefix,middle,suffix}`.

   keccak256 stays the single uninterpreted axiom throughout. -/
import Extracted.UserOp.Funs
import Extracted.UserOpEquiv

set_option linter.unusedSimpArgs false

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

open pqsigner_aa

/-- One right-aligned 32-byte ABI word. -/
def padWord (row : List U8) : List U8 :=
  List.replicate (32 - row.length) 0#u8 ++ row

/-- `hashStruct(userOp)` preimage — 10 right-aligned words, EntryPoint
    v0.6 `UserOp.hash()` field order. -/
def specInner (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) : List U8 :=
  padWord p.sender.val ++ p.nonce.val ++ p.init_code_hash.val ++ cdh.val ++
  p.call_gas_limit.val ++ p.verification_gas_limit.val ++
  p.pre_verification_gas.val ++ p.max_fee_per_gas.val ++
  p.max_priority_fee_per_gas.val ++ p.paymaster_and_data_hash.val

/-- `abi.encode(inner, entryPoint, chainId)` — 3 words. -/
def specOuter (inner : Array U8 32#usize) (p : userop.AaUserOpParams) : List U8 :=
  inner.val ++ padWord p.entry_point.val ++
  padWord ((p.chain_id.bv.toBEBytes).map (@UScalar.mk .U8))

theorem specInner_length (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) :
    (specInner p cdh).length = 320 := by
  simp [specInner, padWord]

theorem specOuter_length (inner : Array U8 32#usize) (p : userop.AaUserOpParams) :
    (specOuter inner p).length = 96 := by
  simp [specOuter, padWord]

def innerSlice (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) : Slice U8 :=
  ⟨specInner p cdh, by rw [specInner_length]; scalar_tac⟩

def outerSlice (inner : Array U8 32#usize) (p : userop.AaUserOpParams) : Slice U8 :=
  ⟨specOuter inner p, by rw [specOuter_length]; scalar_tac⟩

/-- GOAL (firmware↔chain binding, firmware side): the firmware's
    userOpHash is exactly the EntryPoint v0.6 double-keccak over the
    abi.encode preimage. `step*` closes everything but the buffer↔spec
    list equality — see file header. -/
theorem compute_user_op_hash_spec
    (p : userop.AaUserOpParams) (cdh : Array U8 32#usize) :
    userop.compute_user_op_hash p cdh
      ⦃ h => h = keccak256_pure (outerSlice (keccak256_pure (innerSlice p cdh)) p) ⦄ := by
  sorry

end Extracted.Equiv
