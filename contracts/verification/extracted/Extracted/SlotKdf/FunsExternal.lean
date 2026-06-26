-- External functions for the `domain` slot-KDF extraction (FV-#2 sequel).
-- `sha256_bytes` (the FV-#2 single-shot SHA-256 boundary the derivation was
-- refactored to funnel through) is opaqued at extraction time
-- (`--opaque pqsigner_domain::sha256_bytes`), so it appears here as the
-- DISCLOSED hash content-axiom — exactly like the project's existing
-- `sha256_pure` / `keccak256_pure` hash boundaries. The slot-KDF byte-layout
-- theorem (`SlotKdfSpec.lean`) is about the PREIMAGE fed to this function, so it
-- holds for any opaque `sha256_bytes` and does not depend on a SHA-256 model.
import Aeneas
import Extracted.SlotKdf.Types
open Aeneas Aeneas.Std Result ControlFlow Error
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000

/- You can set the `maxRecDepth` value with the `-max-recdepth` CLI option -/
set_option maxRecDepth 2048
open pqsigner_domain

/-- The disclosed pure SHA-256 hash (a total `Slice → [u8;32]` function) — the
    single content axiom this rank rests on, like the project's `sha256_pure` /
    `keccak256_pure`. The slot-KDF byte-layout theorem is about the PREIMAGE fed
    to it, so it holds for ANY pure hash and never inspects this axiom's value. -/
axiom sha256_pure_bytes : Slice Std.U8 → Array Std.U8 32#usize

/-- [pqsigner_domain::sha256_bytes]: the FV-#2 single-shot SHA-256 boundary the
    derivation funnels through (opaque at extraction —
    `--opaque pqsigner_domain::sha256_bytes`). Modeled as the TOTAL wrapper
    `ok ∘ sha256_pure_bytes` (a SHA-256 of a byte slice never fails), so a WP
    spec over `slot_entropy` — which ends in this call — can assert success. -/
noncomputable def sha256_bytes (s : Slice Std.U8) : Result (Array Std.U8 32#usize) :=
  ok (sha256_pure_bytes s)
