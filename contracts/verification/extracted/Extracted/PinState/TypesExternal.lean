-- External types for the `domain::{,de}serialize_pin_state` extraction (§33 rank).
-- Hand-filled from the Aeneas-generated TypesExternal_Template.lean: the template
-- left `core::slice::iter::Chunks` as an opaque `axiom ... : Type`; we give it a
-- DEF (content-axiom-free, matching the project's no-content-axiom convention —
-- see Extracted/Rlp/FunsExternal.lean) so the rank carries no type axiom.
import Aeneas
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000

/- You can set the `maxRecDepth` value with the `-max-recdepth` CLI option -/
set_option maxRecDepth 2048

/-- Model of Rust's `core::slice::iter::Chunks` (`[T]::chunks(n)`): the
    not-yet-consumed slice plus the chunk size. `next` peels `chunkSize`
    elements off the front; the LAST chunk may be short, which this faithfully
    captures (`deserialize_pin_state` only reaches the iterator after an
    `is_multiple_of PER_SLOT_CT_LEN` guard, so in that call every chunk is
    exact, but the model does not assume it). Mirrors the shape of Aeneas Std's
    `core.slice.iter.Iter` / `ChunksExact`. -/
@[rust_type "core::slice::iter::Chunks"]
structure core.slice.iter.Chunks (T : Type) where
  remaining : Slice T
  chunkSize : Std.Usize
