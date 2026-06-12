-- [sphincs_c10] external declarations for the merkle extraction.
--
-- §33 axiom-collapse: nothing left to declare here. `hash.th_pair` (rank 6's
-- tweakable-hash boundary, formerly a handwritten total wrapper over the
-- `th_pair_pure` AXIOM) is now the REAL extracted body in
-- `Extracted/Hash/Funs.lean`, `th_pair_pure` is a DEF over the vendored
-- FIPS 180-4 `sha256_pure` (`Extracted/HashPure.lean`), and the proven
-- `th_pair_spec` step lemma lives in `Extracted/HashSpecs.lean`.
import Aeneas
import Extracted.Merkle.Types
import Extracted.Hash.Funs
open Aeneas Aeneas.Std Result
