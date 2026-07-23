-- External functions for the `domain::{,de}serialize_pin_state` extraction
-- (§33 rank). Hand-filled from the Aeneas-generated FunsExternal_Template.lean:
-- the template AXIOMATIZED every external; following the project convention
-- (Extracted/Rlp/FunsExternal.lean, Extracted/Decode/FunsExternal.lean) we give
-- each a DEF so the rank's proof closures carry NO content axioms. The iterator
-- adapters (`Chunks`, generic `Enumerate::next`) mirror Aeneas Std's
-- `core.slice.iter.{Iter,ChunksExact}` + `Enumerate` shapes (see
-- .lake/packages/aeneas/.../Std/SliceIter.lean + Std/Core/Iter.lean).
import Aeneas
import Extracted.PinState.Types
-- Reuse the slice `into_iter` DEF already provided for the RLP rank (the
-- `@[rust_fun "…into_iter"]` name is global, so it must be defined exactly once).
import Extracted.Rlp.FunsExternal
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000

/- You can set the `maxRecDepth` value with the `-max-recdepth` CLI option -/
set_option maxRecDepth 2048
open pqsigner_domain

/-- `core::num::{usize}::is_multiple_of`. Faithful to Rust 1.87's semantics:
    `m == 0 ⇒ (self == 0)`, else `self % m == 0`. -/
@[rust_fun "core::num::{usize}::is_multiple_of"]
def core.num.Usize.is_multiple_of (a b : Std.Usize) : Result Bool :=
  ok (decide (if b.val = 0 then a.val = 0 else a.val % b.val = 0))

-- `&[T]::into_iter()` is provided by `Extracted.Rlp.FunsExternal` (imported
-- above); reused here (used by the serialize direction only).

/-- `[T]::chunks(n)` — build a `Chunks` from the slice + chunk size. -/
@[rust_fun "core::slice::{[@T]}::chunks"]
def core.slice.Slice.chunks
    {T : Type} (s : Slice T) (n : Std.Usize) : Result (core.slice.iter.Chunks T) :=
  ok ⟨ s, n ⟩

/-- `Chunks::next` — peel `chunkSize` elements off the front (the last chunk may
    be short). Mirrors `IteratorChunksExact.next`'s pop shape. -/
@[rust_fun
  "core::slice::iter::{core::iter::traits::iterator::Iterator<core::slice::iter::Chunks<'a, @T>, &'a [@T]>}::next"]
def core.slice.iter.Chunks.Insts.CoreIterTraitsIteratorIteratorSharedASlice.next
    {T : Type} (self : core.slice.iter.Chunks T) :
    Result ((Option (Slice T)) × (core.slice.iter.Chunks T)) :=
  if self.remaining.length = 0 then
    ok (none, self)
  else
    let chunk : Slice T :=
      ⟨ self.remaining.val.take self.chunkSize.val,
        by have := self.remaining.property; simp only [List.length_take]; omega ⟩
    ok (some chunk, ⟨ self.remaining.drop self.chunkSize, self.chunkSize ⟩)

/-- The generic `Iterator::enumerate` adapter requested by the fresh Aeneas
    external template. It preserves the supplied iterator and starts at zero. -/
@[rust_fun "core::iter::traits::iterator::Iterator::enumerate"]
def core.iter.traits.iterator.Iterator.enumerate.default
    {Self : Type} {Clause0_Item : Type}
    (_inst : core.iter.traits.iterator.Iterator Self Clause0_Item)
    (self : Self) :
    Result (core.iter.adapters.enumerate.Enumerate Self) :=
  ok { iter := self, count := 0#usize }

/-- `Chunks::enumerate` — wrap in `Enumerate` at count 0. -/
@[rust_fun
  "core::slice::iter::{core::iter::traits::iterator::Iterator<core::slice::iter::Chunks<'a, @T>, &'a [@T]>}::enumerate"]
def core.slice.iter.Chunks.Insts.CoreIterTraitsIteratorIteratorSharedASlice.enumerate
    {T : Type} (self : core.slice.iter.Chunks T) :
    Result (core.iter.adapters.enumerate.Enumerate (core.slice.iter.Chunks T)) :=
  ok { iter := self, count := 0#usize }

/-- `Chunks::step_by` — needed only to complete the `Iterator` trait record
    (deserialize never calls it). Mirrors `IteratorChunksExact.step_by`. -/
def core.slice.iter.Chunks.Insts.CoreIterTraitsIteratorIteratorSharedASlice.step_by
    {T : Type} (self : core.slice.iter.Chunks T) (steps : Std.Usize) :
    Result (core.iter.adapters.step_by.StepBy (core.slice.iter.Chunks T)) :=
  if steps.val = 0 then .fail .panic else ok ⟨ self, steps ⟩

/-- `Chunks::take` — needed only to complete the `Iterator` trait record.
    Mirrors `IteratorChunksExact.take`. -/
def core.slice.iter.Chunks.Insts.CoreIterTraitsIteratorIteratorSharedASlice.take
    {T : Type} (self : core.slice.iter.Chunks T) (n : Std.Usize) :
    Result (core.iter.adapters.take.Take (core.slice.iter.Chunks T)) :=
  ok ⟨ self, n ⟩

/-- Generic `Enumerate::next` over any inner `Iterator` — Aeneas Std models the
    `Enumerate` struct (`{iter, count}`) but not this `next`, so it is given here
    (faithful: delegate to the inner iterator, pairing each item with the running
    count and incrementing). -/
@[rust_fun
  "core::iter::adapters::enumerate::{core::iter::traits::iterator::Iterator<core::iter::adapters::enumerate::Enumerate<@I>, (usize, @Clause0_Item)>}::next"]
def core.iter.adapters.enumerate.Enumerate.Insts.CoreIterTraitsIteratorIteratorPairUsizeClause0_Item.next
    {I : Type} {Clause0_Item : Type}
    (inst : core.iter.traits.iterator.Iterator I Clause0_Item)
    (self : core.iter.adapters.enumerate.Enumerate I) :
    Result ((Option (Std.Usize × Clause0_Item)) ×
      (core.iter.adapters.enumerate.Enumerate I)) := do
  let (o, inner) ← inst.next self.iter
  match o with
  | none => ok (none, { self with iter := inner })
  | some x =>
    let c ← self.count + 1#usize
    ok (some (self.count, x), { iter := inner, count := c })

/-- `pqsigner_proto::MAX_ATTEMPTS` = 10. -/
@[rust_const "pqsigner_proto::MAX_ATTEMPTS"]
def pqsigner_proto.MAX_ATTEMPTS : Result Std.U8 := ok 10#u8
