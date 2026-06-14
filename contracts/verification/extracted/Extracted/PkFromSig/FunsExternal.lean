-- [sphincs_c10] external declarations for the pk_from_sig extraction.
--
-- §33 axiom-collapse: nothing left to declare here. The three former
-- tweakable-hash boundaries (`hash.wots_digest`, `hash.chain_hash`,
-- `hash.th_multi` — previously handwritten total wrappers over the
-- `wots_digest_pure` / `chain_hash_pure` / `th_multi_pure` AXIOMS) are now
-- the REAL extracted bodies in `Extracted/Hash/Funs.lean`; the `*_pure`
-- names are DEFs over the vendored FIPS 180-4 `sha256_pure`
-- (`Extracted/HashPure.lean`); the proven step lemmas live in
-- `Extracted/HashSpecs.lean`.
import Aeneas
import Extracted.PkFromSig.Types
import Extracted.Hash.Funs
open Aeneas Aeneas.Std Result
