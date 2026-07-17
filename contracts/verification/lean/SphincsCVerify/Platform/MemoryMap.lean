/-
TrustZone memory-map region disjointness (P1.9, invariant #4 static leg).

## What this proves — and what it deliberately does NOT

The NS-pointer validator (`shared/src/ns_ptr_validate.rs`, Kani-proven) establishes
only `accept ⟹ range ⊆ NS-window`. The security-relevant conclusion is one step
further: `accept ⟹ range ∉ SECURE memory`. That step rests on
`SAU-NS ∩ secure = ∅`, which today lives only as PROSE + two Rust `const _`
subset-asserts in `secure/src/sau.rs` (both NS-side; neither introduces a secure
region literal). This module MECHANIZES that missing disjointness and the
composition, over the exact region literals of the shipping `stm32u585` target.

### PROVEN here (kernel-clean, mathlib-free, `decide`/`omega` over `Nat` intervals)

* `sauNs{Flash,Sram}_disjoint_secure{Flash,Ram}` — the SAU NS regions are disjoint
  from BOTH secure regions (the currently-unmechanized fact).
* `ns{Flash,Sram}Window_subset_sauNs*` — the proto NS-pointer windows sit inside the
  SAU NS regions (mirrors the `sau.rs` `const _` asserts, now a theorem).
* `mailbox_subset_nsSram` + `mailbox_disjoint_secure*`.
* `linkerNs{Flash,Ram}_eq_protoNs*` — the linker `.x` NS regions EQUAL the proto NS
  windows (the drift the `check_linker_memory_map.py` source-binding gate guards,
  stated in Lean so the two agree by construction).
* `accepted_range_disjoint_secure` — the COMPOSITION: any range the validator would
  accept (⊆ an NS window) is disjoint from every secure region. This is the
  `accept ⟹ ∉ secure` step, mechanized nowhere else end-to-end.

### NOT proven / stays cited-TCB (stated, not discovered)

1. **Silicon enforcement.** That SAU/IDAU/GTZC actually enforce these attributes on
   the die is NOT in-proof — there is no public ARMv8-M M-profile model and GTZC is
   ST-proprietary; it is validated only by `make gtzc-enforcement-hw`. `decide` over
   `u32` literals witnesses the interval-algebra SHAPE, NOT that these literals equal
   the silicon's real config registers.
2. **No veneer⊆secure theorem.** "Every NSC veneer ⊆ secure" is FALSE on QEMU (the
   NSC region is deliberately at `0x103FF000`, NS-MPC territory) and on `stm32u585`
   the veneer bounds are `__veneer_base`/`__veneer_limit` LINK-TIME symbols absent
   from the `.x` (resolvable only from an emitted `.map`). So this module models only
   the STATIC region literals; the veneer-containment half is build/silicon-time and
   deliberately out of frame.
3. **Bank-1 S-alias ≡ NS-alias physical aliasing** is a hardware assumption.
4. **Target scope.** These are the `stm32u585` (shipping) literals; the QEMU layout
   (`secure/memory.x`) is a different map and is out of frame for the secure-region
   disjointness (its NSC placement makes veneer⊆secure false, see (2)).
-/

namespace SphincsCVerify.Platform.MemoryMap

/-- A memory region `[base, endExcl)` (exclusive upper bound). -/
structure Region where
  base : Nat
  endExcl : Nat
deriving DecidableEq

/-- Well-formed: nonempty and within the 32-bit address space. -/
@[reducible] def Region.wf (r : Region) : Prop := r.base < r.endExcl ∧ r.endExcl ≤ 2 ^ 32

/-- Two regions do not overlap. -/
@[reducible] def Disjoint (a b : Region) : Prop := a.endExcl ≤ b.base ∨ b.endExcl ≤ a.base

/-- `a` is contained in `b`. -/
@[reducible] def Subset (a b : Region) : Prop := b.base ≤ a.base ∧ a.endExcl ≤ b.endExcl

/-! ## Region literals — the shipping `stm32u585` target.

Sources (kept in sync by `contracts/verification/scripts/check_linker_memory_map.py`):
proto NS windows + mailbox = `proto/src/lib.rs`; SAU NS = `secure/src/sau.rs`
(INCLUSIVE end there, normalized to exclusive `+1` here); secure regions =
`secure/memory-stm32u585.x` (ORIGIN + LENGTH); linker NS = `nonsecure/memory-stm32u585.x`. -/

/-- proto `NS_FLASH` window (exclusive end) — `proto/src/lib.rs`. -/
def nsFlashWindow : Region := ⟨0x08100000, 0x08200000⟩
/-- proto `NS_SRAM` window. -/
def nsSramWindow : Region := ⟨0x20030000, 0x20040000⟩
/-- proto `SHARED_MAILBOX` window. -/
def mailbox : Region := ⟨0x2003FF00, 0x2003FF18⟩

/-- `SAU_NS_FLASH` — `sau.rs` `0x0810_0000..=0x081F_FFFF` (inclusive) → exclusive end. -/
def sauNsFlash : Region := ⟨0x08100000, 0x08200000⟩
/-- `SAU_NS_SRAM` — `sau.rs` `0x2003_0000..=0x2003_FFFF` (inclusive) → exclusive end. -/
def sauNsSram : Region := ⟨0x20030000, 0x20040000⟩

/-- Secure FLASH — `secure/memory-stm32u585.x` ORIGIN `0x0C000000`, LENGTH 984K. -/
def secureFlash : Region := ⟨0x0C000000, 0x0C0F6000⟩
/-- Secure RAM — `secure/memory-stm32u585.x` ORIGIN `0x30000000`, LENGTH 192K. -/
def secureRam : Region := ⟨0x30000000, 0x30030000⟩

/-- Linker NS FLASH — `nonsecure/memory-stm32u585.x` ORIGIN `0x08100000`, LENGTH 1024K. -/
def linkerNsFlash : Region := ⟨0x08100000, 0x08200000⟩
/-- Linker NS RAM — `nonsecure/memory-stm32u585.x` ORIGIN `0x20030000`, LENGTH 64K. -/
def linkerNsRam : Region := ⟨0x20030000, 0x20040000⟩

/-! ## Well-formedness -/

theorem regions_wf :
    Region.wf nsFlashWindow ∧ Region.wf nsSramWindow ∧ Region.wf mailbox
    ∧ Region.wf sauNsFlash ∧ Region.wf sauNsSram
    ∧ Region.wf secureFlash ∧ Region.wf secureRam := by decide

/-! ## The load-bearing disjointness: SAU-NS ∩ secure = ∅ (unmechanized until now) -/

theorem sauNsFlash_disjoint_secureFlash : Disjoint sauNsFlash secureFlash := by decide
theorem sauNsFlash_disjoint_secureRam : Disjoint sauNsFlash secureRam := by decide
theorem sauNsSram_disjoint_secureFlash : Disjoint sauNsSram secureFlash := by decide
theorem sauNsSram_disjoint_secureRam : Disjoint sauNsSram secureRam := by decide

theorem nsFlashWindow_disjoint_secureFlash : Disjoint nsFlashWindow secureFlash := by decide
theorem nsFlashWindow_disjoint_secureRam : Disjoint nsFlashWindow secureRam := by decide
theorem nsSramWindow_disjoint_secureFlash : Disjoint nsSramWindow secureFlash := by decide
theorem nsSramWindow_disjoint_secureRam : Disjoint nsSramWindow secureRam := by decide

/-! ## Subset: proto windows ⊆ SAU-NS (mirrors the `sau.rs` const-asserts) -/

theorem nsFlashWindow_subset_sauNsFlash : Subset nsFlashWindow sauNsFlash := by decide
theorem nsSramWindow_subset_sauNsSram : Subset nsSramWindow sauNsSram := by decide

/-! ## Mailbox is inside NS-SRAM and disjoint from secure -/

theorem mailbox_subset_nsSram : Subset mailbox nsSramWindow := by decide
theorem mailbox_disjoint_secureFlash : Disjoint mailbox secureFlash := by decide
theorem mailbox_disjoint_secureRam : Disjoint mailbox secureRam := by decide

/-! ## Linker `.x` NS == proto NS windows (the drift the source-binding gate guards) -/

theorem linkerNsFlash_eq_protoNsFlash : linkerNsFlash = nsFlashWindow := by decide
theorem linkerNsRam_eq_protoNsSram : linkerNsRam = nsSramWindow := by decide

/-! ## Composition: `accept ⟹ ∉ secure` -/

/-- `Subset`-transports `Disjoint`: if `a ⊆ b` and `b` is disjoint from `c`, so is `a`. -/
theorem subset_disjoint (a b c : Region) (hs : Subset a b) (hd : Disjoint b c) :
    Disjoint a c := by
  unfold Subset Disjoint at *
  omega

/-- **`accept ⟹ ∉ secure` (P1.9 composition).** The NS-pointer validator accepts a
    range only if it is contained in an NS window (the Kani-proven
    `accept ⟹ ⊆ NS-window`). Any such range is disjoint from BOTH secure regions —
    the step the validator's own crate cannot state (it holds no secure-region
    literal). Modeled over a range `r` with the window-subset accept condition. -/
theorem accepted_range_disjoint_secure (r : Region)
    (hacc : Subset r nsFlashWindow ∨ Subset r nsSramWindow) :
    Disjoint r secureFlash ∧ Disjoint r secureRam := by
  cases hacc with
  | inl h =>
    exact ⟨subset_disjoint r nsFlashWindow secureFlash h nsFlashWindow_disjoint_secureFlash,
           subset_disjoint r nsFlashWindow secureRam h nsFlashWindow_disjoint_secureRam⟩
  | inr h =>
    exact ⟨subset_disjoint r nsSramWindow secureFlash h nsSramWindow_disjoint_secureFlash,
           subset_disjoint r nsSramWindow secureRam h nsSramWindow_disjoint_secureRam⟩

end SphincsCVerify.Platform.MemoryMap
