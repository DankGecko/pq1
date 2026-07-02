/- §33 rank (FV-#2 sequel) — `domain::slot_entropy` byte-layout.

   `slot_entropy` is THE chain-binding step of the slot-key derivation
   (invariant #8): it must hash exactly `master_entropy ‖ "slot_entropy" ‖
   chain_id_be ‖ slot_index_be`, so a slot key is unique per (chain_id,
   slot_index) and an attacker who learns a slot key on chain A cannot replay
   it on chain B. The FV-#2 refactor funneled this through the single-shot
   `sha256_bytes`, making it Aeneas-extractable; this rank proves the extracted
   code hashes exactly that canonical preimage in the documented order.

   Proof shape mirrors `AdrsEquiv.make_adrs_spec` (the same `Array.index_mut` +
   `copy_from_slice` buffer-building): `unfold; step*` then reduce the buffer
   ops to a byte concatenation. The function ends in the opaque single-shot
   hash, so the spec characterises the PREIMAGE (it holds for any pure hash).

   Kernel-clean modulo the disclosed `sha256_pure_bytes` hash axiom (the
   FV-#2 `sha256_bytes` boundary) — same status as the project's `sha256_pure`. -/
import Extracted.SlotKdf.Funs
import Extracted.AdrsEquiv

set_option linter.unusedSimpArgs false
set_option linter.unusedTactic false

open Aeneas Aeneas.Std Result

namespace Extracted.Equiv

/-- ASCII bytes of the `"slot_entropy"` domain label. -/
def slotEntropyLabel : List Nat :=
  [115, 108, 111, 116, 95, 101, 110, 116, 114, 111, 112, 121]

/-- Canonical 56-byte preimage `slot_entropy` SHA-256's:
    `master[32] ‖ "slot_entropy"[12] ‖ chain_id_be[8] ‖ slot_index_be[4]`. -/
def slotEntropyPreimage (master : List Nat) (chain slot : Nat) : List Nat :=
  master ++ slotEntropyLabel ++ u64be chain ++ u32be slot

/-- The four nested `setSlice!`s the extracted buffer-building performs collapse
    to the segment concatenation, given the segment lengths (32 ‖ 12 ‖ 8 ‖ 4 = 56)
    and any 56-byte base: the four segments cover `[0,56)` contiguously, so the
    base content is fully overwritten and irrelevant. Base-generic so the caller
    needn't reduce the `Array.repeat`-derived base's literal coercions. -/
theorem setSlice56_layout
    (base m lbl c s : List Nat) (hbase : base.length = 56)
    (hm : m.length = 32) (hl : lbl.length = 12) (hc : c.length = 8) (hs : s.length = 4) :
    ((((base.setSlice! 0 m).setSlice! 32 lbl).setSlice! 44 c).setSlice! 52 s)
      = m ++ lbl ++ c ++ s := by
  simp only [List.setSlice!, hm, hl, hc, hs, hbase,
             List.length_append, List.take_append, List.drop_append,
             List.append_assoc]
  simp +arith [List.take_of_length_le, List.drop_eq_nil_of_le, hm, hl, hc, hs, hbase,
               List.length_append, List.take_append, List.drop_append, List.drop_drop]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 1000000 in
/-- **`slot_entropy` hashes exactly the canonical chain-bound preimage**
    (invariant #8 byte-layout). For all inputs, the extracted `slot_entropy`
    returns `sha256(master ‖ "slot_entropy" ‖ chain_be ‖ slot_be)` — the
    chain_id and slot_index are bound into the hash preimage in the documented
    order, so slot keys are per-(chain,slot) unique. -/
theorem slot_entropy_hashes_canonical_preimage
    (master : Std.Array U8 32#usize) (chain : U64) (slot : U32) :
    pqsigner_domain.slot_entropy master chain slot ⦃ r =>
      ∃ pre : Slice U8,
        pre.val.map (·.val)
          = slotEntropyPreimage (master.val.map (·.val)) chain.val slot.val
        ∧ r = sha256_pure_bytes pre ⦄ := by
  -- The input array's byte-length, needed to resolve the take/drop the
  -- setSlice! expansion produces (master fills bytes [0..32)).
  have l_master : master.val.length = 32 := by have := master.property; simp_all
  unfold pqsigner_domain.slot_entropy
  simp only [sha256_bytes, Array.Insts.ZeroizeZeroize.zeroize]
  step*
  refine ⟨_, ?_, rfl⟩
  -- `s12 = to_slice buf4`, so strip the `to_slice` (Array.val_to_slice) IN THE
  -- SAME pass that applies the setSlice-writer post hyps, else the wrapper
  -- blocks them (make_adrs returns the array directly and needs no strip).
  -- `Array.make` unfolds the literal "slot_entropy" label; `Array.length_to_slice`
  -- + `l_master` give the lengths the take/drop need.
  -- Strip to_slice + distribute the outer `map` into each `setSlice!` (keeping
  -- setSlice! intact) + reduce each segment (label via Array.make, chain/slot
  -- via toBEBytes*). Leaves the 4 nested setSlice!s over a 56-zero base.
  simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
             Array.repeat_val, List.map_replicate, Array.make, map_val_mk,
             toBEBytes64_map_toNat, toBEBytes32_map_toNat]
  -- Collapse the nested setSlice!s to the segment concatenation (helper):
  -- base, m, lbl, c, s inferred; lengths discharged by simp.
  rw [setSlice56_layout _ _ _ _ _
        (by simp) (by rw [List.length_map]; exact l_master) (by simp)
        (by simp [u64be]) (by simp [u32be])]
  simp [slotEntropyPreimage, slotEntropyLabel]

/-! ## `derive_c10_slot_seeds` byte-layout (the slot signing-key SEED derivation) -/

/-- ASCII bytes of `"slot_c10_sk_seed"`. -/
def slotSkSeedLabel : List Nat :=
  [115, 108, 111, 116, 95, 99, 49, 48, 95, 115, 107, 95, 115, 101, 101, 100]

/-- ASCII bytes of `"slot_c10_pk_seed"`. -/
def slotPkSeedLabel : List Nat :=
  [115, 108, 111, 116, 95, 99, 49, 48, 95, 112, 107, 95, 115, 101, 101, 100]

/-- Two contiguous `setSlice!`s (16 ‖ 32 = 48) over any 48-byte base collapse to
    the concatenation (the base is fully overwritten). -/
theorem setSlice48_layout
    (base a b : List Nat) (hbase : base.length = 48)
    (ha : a.length = 16) (hb : b.length = 32) :
    ((base.setSlice! 0 a).setSlice! 16 b) = a ++ b := by
  simp only [List.setSlice!, ha, hb, hbase,
             List.length_append, List.take_append, List.drop_append, List.append_assoc]
  simp +arith [List.take_of_length_le, List.drop_eq_nil_of_le, ha, hb, hbase,
               List.length_append, List.take_append, List.drop_append, List.drop_drop]

/-- A single head `setSlice! 0` of a 16-byte source over a 32-byte base writes
    the source then keeps the base tail (the N-mask: `pk_digest[..16] ‖ base[16..]`). -/
theorem setSlice_head16_of_32
    (base src : List Nat) (hbase : base.length = 32) (hsrc : src.length = 16) :
    base.setSlice! 0 src = src ++ base.drop 16 := by
  simp [List.setSlice!, hbase, hsrc, List.take_of_length_le]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 1000000 in
/-- **`derive_c10_slot_seeds` byte-layout.** For all `slot_entropy`, the
    extracted derivation returns
      `sk_seed = sha256("slot_c10_sk_seed" ‖ slot_entropy)` and
      `pk_seed = sha256("slot_c10_pk_seed" ‖ slot_entropy)[..16] ‖ 0¹⁶`
    (the N-masked layout the on-chain commitment hashes over). Proves the slot
    signing-key seeds are derived from exactly those domain-separated preimages. -/
theorem derive_c10_slot_seeds_byte_layout (se : Std.Array U8 32#usize) :
    pqsigner_domain.derive_c10_slot_seeds se ⦃ r =>
      ∃ pre_sk pre_pk : Slice U8,
        pre_sk.val.map (·.val) = slotSkSeedLabel ++ se.val.map (·.val)
        ∧ pre_pk.val.map (·.val) = slotPkSeedLabel ++ se.val.map (·.val)
        ∧ r.1 = sha256_pure_bytes pre_sk
        ∧ (r.2).val.map (·.val)
            = ((sha256_pure_bytes pre_pk).val.map (·.val)).take 16 ++ List.replicate 16 0 ⦄ := by
  have l_se : (se.val).length = 32 := by have := se.property; simp_all
  unfold pqsigner_domain.derive_c10_slot_seeds
  simp only [sha256_bytes, Array.Insts.ZeroizeZeroize.zeroize]
  step*
  refine ⟨s6, s13, ?_, ?_, rfl, ?_⟩
  · -- sk preimage layout
    simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
               Array.repeat_val, Array.make, map_val_mk]
    rw [setSlice48_layout _ _ _ (by simp) (by simp) (by rw [List.length_map]; exact l_se)]
    simp [slotSkSeedLabel]
  · -- pk preimage layout
    simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
               Array.repeat_val, Array.make, map_val_mk]
    rw [setSlice48_layout _ _ _ (by simp) (by simp) (by rw [List.length_map]; exact l_se)]
    simp [slotPkSeedLabel]
  · -- pk_seed = mask(pk_digest)
    simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
               Array.repeat_val, List.map_replicate, Array.make, map_val_mk]
    rw [setSlice_head16_of_32 _ _ (by simp) (by simp)]
    simp [List.map_append, List.map_take, List.map_drop, List.drop_replicate]

/-! ## `slot_master_entropy_from_bip39` byte-layout (the account-binding step) -/

/-- ASCII bytes of `"pqwallet-slot-master"`. -/
def slotMasterLabel : List Nat :=
  [112, 113, 119, 97, 108, 108, 101, 116, 45, 115, 108, 111, 116, 45, 109, 97, 115, 116, 101, 114]

/-- ASCII bytes of `"pqwallet-slot-master-acct"`. -/
def slotMasterAcctLabel : List Nat :=
  [112, 113, 119, 97, 108, 108, 101, 116, 45, 115, 108, 111, 116, 45, 109, 97, 115, 116, 101, 114,
   45, 97, 99, 99, 116]

/-- Three contiguous `setSlice!`s (25 ‖ 64 ‖ 4 = 93) over any 93-byte base. -/
theorem setSlice93_layout
    (base a b c : List Nat) (hbase : base.length = 93)
    (ha : a.length = 25) (hb : b.length = 64) (hc : c.length = 4) :
    ((((base.setSlice! 0 a).setSlice! 25 b).setSlice! 89 c)) = a ++ b ++ c := by
  simp only [List.setSlice!, ha, hb, hc, hbase,
             List.length_append, List.take_append, List.drop_append, List.append_assoc]
  simp +arith [List.take_of_length_le, List.drop_eq_nil_of_le, ha, hb, hc, hbase,
               List.length_append, List.take_append, List.drop_append, List.drop_drop]

/-- The account-0 path: two `setSlice!`s (20 ‖ 64) over an 85-byte base, then
    `.set 84 0` for the trailing `kdf` index byte. The two segments cover
    `[0,84)`, leaving one byte at 84 which `.set 84 0` forces to 0 — so the
    result is `a ‖ b ‖ [0]` for any 85-byte base. -/
theorem setSlice85_set_layout
    (base a b : List Nat) (i v : Nat) (hbase : base.length = 85)
    (ha : a.length = 20) (hb : b.length = 64) (hi : i = 84) (hv : v = 0) :
    (((base.setSlice! 0 a).setSlice! 20 b).set i v) = a ++ b ++ [0] := by
  subst hi hv
  have h2 : (base.setSlice! 0 a).setSlice! 20 b = a ++ b ++ base.drop 84 := by
    simp only [List.setSlice!, ha, hb, hbase,
               List.length_append, List.take_append, List.drop_append, List.append_assoc]
    simp +arith [List.take_of_length_le, List.drop_eq_nil_of_le, ha, hb, hbase,
                 List.length_append, List.take_append, List.drop_append, List.drop_drop]
  obtain ⟨x, hx⟩ := List.length_eq_one_iff.mp (show (base.drop 84).length = 1 by simp [hbase])
  rw [h2, hx]
  simp [ha, hb, List.set_append]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 1000000 in
/-- **`slot_master_entropy_from_bip39` byte-layout.** For all inputs, the
    extracted derivation returns `sha256` of the account-bound preimage:
    account 0 → `"pqwallet-slot-master" ‖ bip39_seed ‖ 0x00`;
    account ≠ 0 → `"pqwallet-slot-master-acct" ‖ bip39_seed ‖ account_index_be`.
    The account index is bound into the preimage (the account-0 path keeps the
    historical `kdf` trailing `0x00`), so distinct accounts have distinct slot
    master entropy. -/
theorem slot_master_byte_layout (bip39 : Std.Array U8 64#usize) (acct : U32) :
    pqsigner_domain.slot_master_entropy_from_bip39 bip39 acct ⦃ r =>
      ∃ pre : Slice U8,
        pre.val.map (·.val) = (if acct = 0#u32
          then slotMasterLabel ++ bip39.val.map (·.val) ++ [0]
          else slotMasterAcctLabel ++ bip39.val.map (·.val) ++ u32be acct.val)
        ∧ r = sha256_pure_bytes pre ⦄ := by
  have l_bip : (bip39.val).length = 64 := by have := bip39.property; simp_all
  unfold pqsigner_domain.slot_master_entropy_from_bip39
  simp only [sha256_bytes, Array.Insts.ZeroizeZeroize.zeroize]
  by_cases hacct : acct = 0#u32
  · rw [if_pos hacct]
    step*
    refine ⟨_, ?_, rfl⟩
    rw [if_pos hacct]
    simp only [*, Array.set_val_eq, Array.val_to_slice, Array.length_to_slice,
               List.map_setSlice!, List.map_set, Array.repeat_val, List.map_replicate,
               Array.make, map_val_mk]
    rw [setSlice85_set_layout _ _ _ _ _ (by simp) (by simp)
          (by rw [List.length_map]; exact l_bip) (by decide) (by decide)]
    simp [slotMasterLabel]
  · rw [if_neg hacct]
    step*
    refine ⟨_, ?_, rfl⟩
    rw [if_neg hacct]
    simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
               Array.repeat_val, Array.make, map_val_mk, toBEBytes32_map_toNat]
    rw [setSlice93_layout _ _ _ _ (by simp) (by simp) (by rw [List.length_map]; exact l_bip)
          (by simp [u32be])]
    simp [slotMasterAcctLabel]

/-! ## `derive_c10_master_from_bip39_seed` byte-layout (the BOOTSTRAP key derivation)

This is the CREATE2-critical bootstrap: `masterPkSeed`/`masterSkSeed` (hence the
wallet's CREATE2 salt + address) are derived here. -/

/-- ASCII bytes of `"sphincs-c6-v1"` (the historical HMAC domain tag; C10 now). -/
def bootDomain : List Nat := [115, 112, 104, 105, 110, 99, 115, 45, 99, 54, 45, 118, 49]
/-- ASCII bytes of `"sphincs-c6-v1-acct"`. -/
def bootDomainAcct : List Nat :=
  [115, 112, 104, 105, 110, 99, 115, 45, 99, 54, 45, 118, 49, 45, 97, 99, 99, 116]
/-- ASCII bytes of `"pk_seed"`. -/
def bootPkLabel : List Nat := [112, 107, 95, 115, 101, 101, 100]
/-- ASCII bytes of `"sk_seed"`. -/
def bootSkLabel : List Nat := [115, 107, 95, 115, 101, 101, 100]

/-- Two contiguous `setSlice!`s (7 ‖ 32 = 39) over any 39-byte base (the
    `"{pk,sk}_seed" ‖ master[..32]` preimage). -/
theorem setSlice39_layout
    (base a b : List Nat) (hbase : base.length = 39)
    (ha : a.length = 7) (hb : b.length = 32) :
    ((base.setSlice! 0 a).setSlice! 7 b) = a ++ b := by
  simp only [List.setSlice!, ha, hb, hbase,
             List.length_append, List.take_append, List.drop_append, List.append_assoc]
  simp +arith [List.take_of_length_le, List.drop_eq_nil_of_le, ha, hb, hbase,
               List.length_append, List.take_append, List.drop_append, List.drop_drop]

/-- Two contiguous `setSlice!`s (64 ‖ 4 = 68) over any 68-byte base (the account≠0
    HMAC message `bip39_seed ‖ account_index_be`). -/
theorem setSlice68_layout
    (base a b : List Nat) (hbase : base.length = 68)
    (ha : a.length = 64) (hb : b.length = 4) :
    ((base.setSlice! 0 a).setSlice! 64 b) = a ++ b := by
  simp only [List.setSlice!, ha, hb, hbase,
             List.length_append, List.take_append, List.drop_append, List.append_assoc]
  simp +arith [List.take_of_length_le, List.drop_eq_nil_of_le, ha, hb, hbase,
               List.length_append, List.take_append, List.drop_append, List.drop_drop]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 1000000 in
/-- **`derive_c10_master_from_bip39_seed` FULL byte-layout** (CREATE2 red-line,
    incl. the account-binding HMAC inputs). For all inputs, the extracted
    bootstrap derivation computes `master_lo = HMAC-SHA512(key, msg)[..32]` where
    `key` is `"sphincs-c6-v1"` (acct 0) / `"sphincs-c6-v1-acct"` (acct≠0) and
    `msg` is `bip39_seed` (acct 0) / `bip39_seed ‖ account_index_be` (acct≠0) —
    so the account index is bound into the master — and returns the
    domain-separated seeds `sk_seed = sha256("sk_seed" ‖ master_lo)` (masterSkSeed)
    and `pk_seed = sha256("pk_seed" ‖ master_lo)[..16] ‖ 0¹⁶` (masterPkSeed — the
    N-masked value the CREATE2 salt hashes over). The HMAC primitive itself stays
    opaque, so this proves the account-bound PREIMAGE structure (distinct-account
    ⇒ distinct-master needs HMAC collision-resistance, out of scope). -/
theorem derive_c10_master_byte_layout (bip39 : Std.Array U8 64#usize) (acct : U32) :
    pqsigner_domain.derive_c10_master_from_bip39_seed bip39 acct ⦃ r =>
      ∃ (key msg master_lo pre_pk pre_sk : Slice U8),
        master_lo.val = ((hmac_sha512_pure_bytes key msg).val).take 32
        ∧ key.val.map (·.val) = (if acct = 0#u32 then bootDomain else bootDomainAcct)
        ∧ msg.val.map (·.val) = (if acct = 0#u32 then bip39.val.map (·.val)
                                  else bip39.val.map (·.val) ++ u32be acct.val)
        ∧ pre_pk.val.map (·.val) = bootPkLabel ++ master_lo.val.map (·.val)
        ∧ pre_sk.val.map (·.val) = bootSkLabel ++ master_lo.val.map (·.val)
        ∧ (r.1).val.map (·.val)
            = ((sha256_pure_bytes pre_pk).val.map (·.val)).take 16 ++ List.replicate 16 0
        ∧ r.2 = sha256_pure_bytes pre_sk ⦄ := by
  have l_bip : (bip39.val).length = 64 := by have := bip39.property; simp_all
  unfold pqsigner_domain.derive_c10_master_from_bip39_seed
  simp only [sha256_bytes, hmac_sha512_bytes, Array.Insts.ZeroizeZeroize.zeroize]
  by_cases hacct : acct = 0#u32
  · simp only [if_pos hacct]
    step*
    -- key = "sphincs-c6-v1" label slice (proof-irrelevant vs the inlined _proof),
    -- msg = bip39.to_slice; master_lo/pre_pk/pre_sk are step* binders.
    refine ⟨Array.to_slice (Array.make 13#usize
              [115#u8, 112#u8, 104#u8, 105#u8, 110#u8, 99#u8, 115#u8, 45#u8, 99#u8,
               54#u8, 45#u8, 118#u8, 49#u8] (by decide)),
            Array.to_slice bip39, master_lo, s5, s14, ?_, ?_, ?_, ?_, ?_, ?_, rfl⟩
    · -- C_hmac: master_lo = HMAC(key,msg)[..32]
      rw [master_lo_post1]; simp [List.slice, Array.val_to_slice, x_post]
    · -- C_key: key.val.map = "sphincs-c6-v1"
      simp [Array.val_to_slice, Array.make, map_val_mk, bootDomain]
    · -- C_msg: msg.val.map = bip39 (acct 0)
      simp [Array.val_to_slice]
    · clear master_lo_post1
      simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
                 Array.repeat_val, Array.make, map_val_mk]
      rw [setSlice39_layout _ _ _ (by simp) (by simp)
            (by rw [List.length_map]; exact master_lo_post2)]
      simp [bootPkLabel]
    · clear master_lo_post1
      simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
                 Array.repeat_val, Array.make, map_val_mk]
      rw [setSlice39_layout _ _ _ (by simp) (by simp)
            (by rw [List.length_map]; exact master_lo_post2)]
      simp [bootSkLabel]
    · clear master_lo_post1
      simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
                 Array.repeat_val, List.map_replicate, Array.make, map_val_mk]
      rw [setSlice_head16_of_32 _ _ (by simp) (by simp)]
      simp [List.map_append, List.map_take, List.map_drop, List.drop_replicate]
  · simp only [if_neg hacct]
    step*
    -- key = "sphincs-c6-v1-acct" label slice; msg = x (the bip39‖acct_be buffer slice).
    refine ⟨Array.to_slice (Array.make 18#usize
              [115#u8, 112#u8, 104#u8, 105#u8, 110#u8, 99#u8, 115#u8, 45#u8, 99#u8,
               54#u8, 45#u8, 118#u8, 49#u8, 45#u8, 97#u8, 99#u8, 99#u8, 116#u8] (by decide)),
            x, master_lo, s5, s14, ?_, ?_, ?_, ?_, ?_, ?_, rfl⟩
    · -- C_hmac: master_lo = HMAC(key,msg)[..32]
      rw [master_lo_post1]; simp [List.slice, Array.val_to_slice]
    · -- C_key: key.val.map = "sphincs-c6-v1-acct"
      simp [Array.val_to_slice, Array.make, map_val_mk, bootDomainAcct]
    · -- C_msg: x.val.map = bip39 ++ account_index_be  (the 68-byte buffer)
      simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
                 Array.repeat_val, List.map_replicate, Array.make, map_val_mk,
                 toBEBytes32_map_toNat]
      rw [setSlice68_layout _ _ _ (by simp) (by rw [List.length_map]; exact l_bip)
            (by simp [u32be])]
      simp
    · clear master_lo_post1
      simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
                 Array.repeat_val, Array.make, map_val_mk]
      rw [setSlice39_layout _ _ _ (by simp) (by simp)
            (by rw [List.length_map]; exact master_lo_post2)]
      simp [bootPkLabel]
    · clear master_lo_post1
      simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
                 Array.repeat_val, Array.make, map_val_mk]
      rw [setSlice39_layout _ _ _ (by simp) (by simp)
            (by rw [List.length_map]; exact master_lo_post2)]
      simp [bootSkLabel]
    · clear master_lo_post1
      simp only [*, Array.val_to_slice, Array.length_to_slice, List.map_setSlice!,
                 Array.repeat_val, List.map_replicate, Array.make, map_val_mk]
      rw [setSlice_head16_of_32 _ _ (by simp) (by simp)]
      simp [List.map_append, List.map_take, List.map_drop, List.drop_replicate]

/-! ## §1 deepening — derivation injectivity (domain separation) + the
    key-collision ⇒ hash-collision reduction.

    The byte-layout ranks prove each key seed is `hash(preimage)` with the
    `(account, chain, slot)` inputs in fixed positions. Here we prove the
    PREIMAGE map is INJECTIVE in those inputs (pure, no crypto), so any two
    distinct inputs yield distinct preimages — the derivation never internally
    aliases. Composed with a byte-layout rank, this yields: distinct inputs ⇒
    the keys differ UNLESS the hash collided (the honest reduction; we do NOT
    assume the hash is injective, which is false). -/

/-- Big-endian 4-byte decomposition is injective on `< 2^32`. -/
theorem u32be_inj {x y : Nat} (hx : x < 2 ^ 32) (hy : y < 2 ^ 32)
    (h : u32be x = u32be y) : x = y := by
  simp only [u32be, List.cons.injEq] at h
  omega

/-- Big-endian 8-byte decomposition is injective on `< 2^64`. -/
theorem u64be_inj {x y : Nat} (hx : x < 2 ^ 64) (hy : y < 2 ^ 64)
    (h : u64be x = u64be y) : x = y := by
  simp only [u64be, List.cons.injEq] at h
  omega

/-- **Cross-chain isolation (preimage injectivity in `chain_id`).** For a fixed
    master + slot, distinct chain ids give distinct `slot_entropy` preimages.
    (Pure list fact: the chain bytes occupy a fixed window of the preimage.) -/
theorem slotEntropyPreimage_chain_inj {m : List Nat} {c1 c2 s : Nat}
    (hc1 : c1 < 2 ^ 64) (hc2 : c2 < 2 ^ 64)
    (h : slotEntropyPreimage m c1 s = slotEntropyPreimage m c2 s) : c1 = c2 := by
  apply u64be_inj hc1 hc2
  unfold slotEntropyPreimage at h
  -- cancel the common `u32be s` suffix, then the `m ++ label` prefix
  exact List.append_right_injective _ (List.append_left_injective _ h)

/-- Contrapositive: distinct chain ids ⇒ distinct `slot_entropy` preimages. -/
theorem slotEntropyPreimage_chain_ne {m : List Nat} {c1 c2 s : Nat}
    (hc1 : c1 < 2 ^ 64) (hc2 : c2 < 2 ^ 64) (hne : c1 ≠ c2) :
    slotEntropyPreimage m c1 s ≠ slotEntropyPreimage m c2 s :=
  fun h => hne (slotEntropyPreimage_chain_inj hc1 hc2 h)

/-- **Per-slot isolation (preimage injectivity in `slot_index`).** For a fixed
    master + chain, distinct slot indices give distinct `slot_entropy` preimages
    (the slot bytes are the trailing window). -/
theorem slotEntropyPreimage_slot_inj {m : List Nat} {c s1 s2 : Nat}
    (hs1 : s1 < 2 ^ 32) (hs2 : s2 < 2 ^ 32)
    (h : slotEntropyPreimage m c s1 = slotEntropyPreimage m c s2) : s1 = s2 := by
  apply u32be_inj hs1 hs2
  unfold slotEntropyPreimage at h
  exact List.append_right_injective _ h

/-- Contrapositive: distinct slot indices ⇒ distinct `slot_entropy` preimages. -/
theorem slotEntropyPreimage_slot_ne {m : List Nat} {c s1 s2 : Nat}
    (hs1 : s1 < 2 ^ 32) (hs2 : s2 < 2 ^ 32) (hne : s1 ≠ s2) :
    slotEntropyPreimage m c s1 ≠ slotEntropyPreimage m c s2 :=
  fun h => hne (slotEntropyPreimage_slot_inj hs1 hs2 h)

/-- **Cross-chain key reuse ⇒ a genuine SHA-256 collision.** If two slices `p1`,
    `p2` are the canonical `slot_entropy` preimages for the same master+slot but
    DISTINCT chains, and their hashes coincide (i.e. the slot keys collide
    cross-chain), then `(p1, p2)` is a SHA-256 collision: distinct inputs, equal
    digest. So cross-chain slot-key reuse is impossible UNLESS SHA-256 collides —
    the honest reduction (we never assume the hash is injective). Compose with
    `slot_entropy_hashes_canonical_preimage` to supply `hp1`/`hp2`. -/
theorem slot_entropy_crosschain_reduction {m : List Nat} {c1 c2 s : Nat}
    {p1 p2 : Slice U8}
    (hc1 : c1 < 2 ^ 64) (hc2 : c2 < 2 ^ 64) (hne : c1 ≠ c2)
    (hp1 : p1.val.map (·.val) = slotEntropyPreimage m c1 s)
    (hp2 : p2.val.map (·.val) = slotEntropyPreimage m c2 s)
    (hcol : sha256_pure_bytes p1 = sha256_pure_bytes p2) :
    p1.val ≠ p2.val ∧ sha256_pure_bytes p1 = sha256_pure_bytes p2 := by
  refine ⟨fun heq => ?_, hcol⟩
  apply slotEntropyPreimage_chain_ne hc1 hc2 hne
  rw [← hp1, ← hp2, heq]

end Extracted.Equiv
