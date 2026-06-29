/- Grind postcondition lemmas for the reference signer (verify_signs increment 1).

   `grindR` and `findCount` are TOTAL (bounded by `limit`, `termination_by`),
   so `… = some result` carries usable information: the loop returns `some`
   ONLY through a gated branch. These lemmas extract those gates — the facts the
   `consistent`-assembly consumes:

   * `grindR_post` — the forced-zero (last FORS index 0) + the digest agreement
     (`digest = hMsg … (pad16 r) message`, so the verifier recomputes the same
     digest the signer ground).
   * `findCount_post` — the WOTS+C target-sum + the `wotsDigest` shape (the
     `hdig`/`hsum` of `wots_pk_roundtrip`).

   Each is a one-line appeal to a `fun_induction` over the bounded loop. -/
import SphincsCVerify.Spec.Signer

namespace SphincsCVerify.Spec.Signer

open SphincsCVerify SphincsCVerify.Spec SphincsCVerify.Util ByteVec

/-- `grindR.loop`: any `some (r, d)` result satisfies the forced-zero gate and
    fixes `d` to be the message-bound digest at the found nonce. -/
theorem grindR_loop_post (skSeed message : ByteVec 32) (limit : Nat)
    (seedB32 rootB32 : ByteVec 32) (lastShift : Nat) (nonce : Nat) (r : ByteVec 16) (d : ByteVec 32)
    (h : grindR.loop skSeed message limit seedB32 rootB32 lastShift nonce = some (r, d)) :
    readBitsLe d lastShift A = 0 ∧ d = hMsg seedB32 rootB32 (pad16 r) message := by
  fun_induction grindR.loop skSeed message limit seedB32 rootB32 lastShift nonce with
  | case1 x hx => simp [hx] at h
  | case2 x _hx _nb _rf _rr _rb _dg hz =>
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨hr, hd⟩ := h; subst hr; subst hd; exact ⟨hz, rfl⟩
  | case3 x _hx _nb _rf _rr _rb _dg _hnz ih => exact ih h

/-- `grindR` succeeds ⇒ the last FORS index is forced to zero, and the returned
    digest equals the verifier-recomputed `hMsg (pad16 pkSeed) (pad16 pkRoot)
    (pad16 r) message`. -/
theorem grindR_post (skSeed : ByteVec 32) (pkSeed pkRoot : ByteVec 16) (message : ByteVec 32)
    (limit : Nat) (r : ByteVec 16) (d : ByteVec 32)
    (h : grindR skSeed pkSeed pkRoot message limit = some (r, d)) :
    readBitsLe d ((K - 1) * A) A = 0
      ∧ d = hMsg (pad16 pkSeed) (pad16 pkRoot) (pad16 r) message := by
  unfold grindR at h
  exact grindR_loop_post skSeed message limit (pad16 pkSeed) (pad16 pkRoot) ((K - 1) * A) 0 r d h

/-- `findCount.loop`: any `some (cnt, d)` result satisfies the WOTS+C target-sum
    and fixes `d` to be the `wotsDigest` at the found count. -/
theorem findCount_loop_post (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 32) (limit : Nat) (count : Nat) (cnt : UInt32) (d : ByteVec 32)
    (h : findCount.loop seed layer tree kp msgHash limit count = some (cnt, d)) :
    digitSum (extractDigits d) = TargetSum
      ∧ d = wotsDigest seed (Adrs.wots layer tree kp) msgHash cnt := by
  fun_induction findCount.loop seed layer tree kp msgHash limit count with
  | case1 x hx => simp [hx] at h
  | case2 x _hx _wa _c32 _d _dg hz =>
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨hc, hd⟩ := h; subst hc; subst hd; exact ⟨hz, rfl⟩
  | case3 x _hx _wa _c32 _d _dg _hnz ih => exact ih h

/-- `findCount` succeeds ⇒ the recovered digit-sum equals `TargetSum`, and the
    returned digest is the `wotsDigest` at the found count. -/
theorem findCount_post (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 32) (limit : Nat) (cnt : UInt32) (d : ByteVec 32)
    (h : findCount seed layer tree kp msgHash limit = some (cnt, d)) :
    digitSum (extractDigits d) = TargetSum
      ∧ d = wotsDigest seed (Adrs.wots layer tree kp) msgHash cnt := by
  unfold findCount at h
  exact findCount_loop_post seed layer tree kp msgHash limit 0 cnt d h

/-- The `t`-th extracted FORS index (for `t < K`) is the `A`-bit window at
    `t*A` — connects the grind's forced-zero / index bounds to `extractForsIndices`
    (the form `fors_pk_roundtrip`'s `hzero`/`hbound` use). -/
theorem extractForsIndices_getD (digest : ByteVec 32) (t : Nat) (ht : t < K) :
    (extractForsIndices digest).getD t 0 = readBitsLe digest (t * A) A := by
  unfold extractForsIndices
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn]
  simp [ht]

end SphincsCVerify.Spec.Signer
