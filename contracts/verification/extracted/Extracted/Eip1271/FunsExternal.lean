-- [pqsigner_aa] external declarations for the eip1271 extraction.
-- REUSES the single `keccak256_pure` axiom (the §33 hash boundary) defined in
-- Extracted.UserOp.FunsExternal — do NOT re-declare it, so the whole track has
-- exactly ONE uninterpreted keccak axiom.
import Extracted.UserOp.FunsExternal
import Extracted.Eip1271.Types
