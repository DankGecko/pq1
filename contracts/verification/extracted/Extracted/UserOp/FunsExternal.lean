-- [pqsigner_aa]: external function declarations.
-- Filled from FunsExternal_Template.lean (work-todo §33 P2).
import Aeneas
import Extracted.UserOp.Types
open Aeneas Aeneas.Std Result ControlFlow Error

/-- THE keccak-256 axiom — the single uninterpreted hash boundary of
    the §33 firmware track, mirroring `AXIOM_STATUS.json` A1 (which
    axiomatizes the EVM SHA-256 precompile the same way): a TOTAL,
    deterministic function on byte slices whose algebraic content we
    never rely on. Discharge artifact: the Rust `keccak256` KATs in
    `tx-core` + the EVM-side keccak conformance the wallet model
    already cites. -/
axiom keccak256_pure : Slice Std.U8 → Array Std.U8 32#usize

/-- [pqsigner_tx_core::hash::keccak256]:
    Source: 'tx-core/src/hash.rs', lines 10:0-10:42
    Name pattern: [pqsigner_tx_core::hash::keccak256]
    Visibility: public

    Total `def` wrapping the pure axiom (the Rust function cannot
    fail or diverge), so total-correctness `⦃ ⦄` triples can step
    through hash calls without interpreting the hash. -/
@[rust_fun "pqsigner_tx_core::hash::keccak256"]
noncomputable def pqsigner_tx_core.hash.keccak256
    (s : Slice Std.U8) : Result (Array Std.U8 32#usize) :=
  ok (keccak256_pure s)

/-- Step spec: `keccak256` always succeeds and returns
    `keccak256_pure` of its argument. -/
@[step]
theorem pqsigner_tx_core.hash.keccak256.step_spec (s : Slice Std.U8) :
    pqsigner_tx_core.hash.keccak256 s ⦃ r => r = keccak256_pure s ⦄ := by
  simp [pqsigner_tx_core.hash.keccak256, WP.spec_ok]
