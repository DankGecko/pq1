(* ==========================================================================
   SPHINCS_C_Skeleton.ec
   --------------------------------------------------------------------------
   SCOUTING VERDICT + the +C-INVARIANT composition-arithmetic glue for the
   capstone's `hfx` hypothesis (drafts/SPHINCS_C.ec:178, "[FX+C skeleton]").

   This file is the honest answer to the task's DECISIVE QUESTION:
     "Is MM45's `EUFCMA_SPHINCS_PLUS_FX` PARAMETRIC over the leaf games
      (=> discharge hfx by CLONE/INSTANTIATION), or does it INLINE concrete
      reductions (=> genuine re-derivation needed)?"

   =========================================================================
   VERDICT: (c) GENUINE RE-DERIVATION NEEDED.  FX is NOT parametric over the
            leaf games; hfx CANNOT be discharged by cloning/instantiation.
   =========================================================================

   EVIDENCE (all line refs into FV-SPHINCSPLUS-EC/proofs/SPHINCS_PLUS.ec):

   E1. FX is a section-`local` lemma.
       `local lemma EUFCMA_SPHINCS_PLUS_FX &m` (line 4287) lives inside
       `section Proof_SPHINCS_PLUS_EUFCMA` (1631) .. `end section` (4609),
       over the section-`declare`d concrete adversary `A` (line 1633).  A
       `local` lemma is not even referenceable outside its section -- there
       is no name to `clone`, `import`, or instantiate.  This alone rules out
       the (a)/(b) "instantiate the abstract theorem" shape.

   E2. FX's RHS terms are CONCRETE reductions applied to the concrete `A`,
       over the CONCRETE leaf games -- not abstract-clone leaf hypotheses:
         Pr[EUF_CMA_MFORSTWESNPRF(R_MFORSTWESNPRFEUFCMA_EUFCMA(A),
                                  O_CMA_MFORSTWESNPRF).main() @ &m : res]   (4296)
         Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(
                 R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A),
                 FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]         (4298)
       These are consumed as *proven concrete inequalities*, not as abstract
       hypotheses of a parametric theorem.  Contrast the WOTS+C / FORS+C legs,
       which ARE clone-instantiations of abstract theories (MFORSC, STCR_C):
       there the port is a `clone ... with WOTS -> WOTS+C`.  FX offers no such
       abstract handle.

   E3. FX's proof is a fixed chain of SIX section-`local` game-hops, each a
       `byequiv`/`Pr[...]`-manipulation over the CONCRETE `SPHINCS_PLUS`
       scheme module and its intermediate games (2110/2133/2159/2186):
         (1) Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF            (2243, byequiv)
         (2) EqAdv_..._PRFPRF_NPRFPRF_SKGPRF                    (2668)
         (3) EqAdv_..._NPRFPRF_NPRFNPRF_MKGPRF                  (3055)
         (4a) Eqv_..._NPRFNPRF_V                                (2572, byequiv)
         (4b) Pr[mu_split ... valid_MFORSTWESNPRF]              (in-proof, 4327)
         (5) LeqPr_..._NPRFNPRF_VT_MFORSTWESNPRF                (3129, byequiv)
         (6) LeqPr_..._NPRFNPRF_VF_FLSLXMSSMTTWESNPRF           (3468, byequiv)
       Every one of (1)-(6) walks the concrete scheme's internals.

   E4. THE +C INJECTION POINT is `mco`.  The valid/invalid split flag is
       `valid_MFORSTWESNPRF <- pkFORS' = pkFORS` (2230), and the index+digest
       that drives the whole FORS-vs-XMSSMT dichotomy is read off
             (cm, idx) <- mco mk' m'                             (2221)
       -- the COUNTER-FREE message-compression.  The same counter-free
       `mco mk m` is hardcoded in EVERY intermediate game and reduction
       (1008, 1042, 1092, 1244, 1388, 1494, 1620, 2221).  In +C (paper
       2022/778) message compression is `mco mk m cf` (counter-dependent):
       porting FX means REDEFINING all four intermediate games + both
       reductions with the counter and RE-PROVING all six byequivs.  This is
       exactly the counter-free-vs-counter-dependent mismatch already found on
       the FORS-tree leg (FORS_ES reads indices off a counter-free digest,
       FORS+C's is counter-dependent).  Redefinition is NOT instantiation.

   CONCLUSION.  Discharging hfx = building a `SPHINCS_PLUS_C` scheme module
   and re-deriving the six concrete game-hops over it.  That is the multi-month
   scheme-module remainder the capstone (SPHINCS_C.ec:22-25) deliberately
   scopes OUT.  There is no clone/instantiation shortcut and no small "bridge
   lemma" that closes it: the entire +C-specific difficulty is concentrated in
   the six byequivs at the `mco` injection point.

   =========================================================================
   WHAT THIS FILE NEVERTHELESS CONTRIBUTES (honest, bounded).
   =========================================================================
   The COMPOSITION ARITHMETIC that MM45's FX proof uses to assemble the six
   hops into the top-level bound is +C-INVARIANT: it is the two-`ler_norm_add`
   triangle chain + the mu_split, over abstract probabilities, touching no
   scheme internals.  `FX_skeleton_C` below machine-checks that arithmetic
   generically.  Its value is DIAGNOSTIC, not a discharge:

     * It PROVES that the glue binding the six hops into hfx's RHS shape is
       trivial real-arithmetic and carries ZERO +C-specific content -- i.e.
       the entire +C difficulty lives in the six byequiv premises, none in the
       composition.
     * It gives a machine-checked 1:1 MAP from hfx to the six concrete MM45
       game-hop lemmas that a real +C port must re-prove (the residual),
       each named in a bridge premise below.

   WHAT THIS FILE DOES **NOT** DO (do not overstate):
     * It does NOT discharge hfx, and does NOT "reduce hfx to bridge admits"
       in the instantiation sense -- (b) is unreachable per E1-E4.  It
       replaces one abstract hypothesis (hfx) with six abstract hypotheses
       (the byequiv bridges) PLUS a proven triangle inequality.  The six
       bridges remain genuine, out-of-scope, scheme-level obligations.
     * It does NOT pin `p_sphincs_c` to a real forgery probability.  Every
       real below (`p0`,`pp`,`np`,`nn`,`nnv_t`,`nnv_f`) is a FREE abstract
       real; pinning `p0 = Pr[EUF_CMA(SPHINCS_PLUS_C, ...)]` requires the
       out-of-scope `SPHINCS_PLUS_C` scheme module.  This inherits -- does not
       add to -- the capstone's stated anchoring situation (SPHINCS_C.ec:26,
       "its only anchor is the labelled FX-port hypothesis hfx").

   NO easycrypt `axiom`, NO `sorry`, NO `admit` in this file.
   ========================================================================== *)

require import AllCore StdOrder.
import RealOrder.

(* --------------------------------------------------------------------------
   FX_skeleton_C : the +C-INVARIANT composition arithmetic of MM45's
   `EUFCMA_SPHINCS_PLUS_FX`, over abstract probabilities.

   Reals (all FREE -- this pins nothing):
     p0     -- would be Pr[EUF_CMA(SPHINCS_PLUS_C, A, ...)]  (out of scope)
     pp     -- Pr[..._PRFPRF]      (+C-ported)
     np     -- Pr[..._NPRFPRF]     (+C-ported)
     nn     -- Pr[..._NPRFNPRF]    (+C-ported)
     nnv_t  -- Pr[..._NPRFNPRF_V : res /\  valid_MFORSCTWESNPRF]  (+C-ported)
     nnv_f  -- Pr[..._NPRFNPRF_V : res /\ !valid_MFORSCTWESNPRF]  (+C-ported)
     skg    -- SKG-PRF advantage        (= |pp - np|,  +C-INVARIANT hop)
     mkg    -- MKG-PRF advantage        (= |np - nn|,  +C-INVARIANT hop)
     mforsc -- Pr[FORS+C multi game]    (the capstone's EUF_CMA_MFORSC term)
     pxmt   -- Pr[XMSS-MT+C EUF-NAGCMA]  (the capstone's p_xmssmt_c term)

   Each premise is EXACTLY one MM45 game-hop lemma "ported to +C" -- the
   residual a real port must discharge over a SPHINCS_PLUS_C scheme module.
   NB: `br_v` bundles TWO MM45 steps: the byequiv Eqv_..._NPRFNPRF_V (2572)
   AND the mu_split on valid_MFORSTWESNPRF (4327).
   -------------------------------------------------------------------------- *)
lemma FX_skeleton_C
  (p0 pp np nn nnv_t nnv_f skg mkg mforsc pxmt : real) :
     (* br_orig  [(1) Eqv_..._Orig_FSPRFPRF, byequiv, ported +C] *)
     p0 = pp =>
     (* br_skg   [(2) EqAdv_..._PRFPRF_NPRFPRF_SKGPRF, ported +C] *)
     `|pp - np| = skg =>
     (* br_mkg   [(3) EqAdv_..._NPRFPRF_NPRFNPRF_MKGPRF, ported +C] *)
     `|np - nn| = mkg =>
     (* br_v     [(4a) Eqv_..._NPRFNPRF_V byequiv + (4b) mu_split, ported +C] *)
     nn = nnv_t + nnv_f =>
     (* br_fors  [(5) LeqPr_..._VT_MFORSTWESNPRF, byequiv, ported +C] *)
     nnv_t <= mforsc =>
     (* br_xmssmt [(6) LeqPr_..._VF_FLSLXMSSMTTWESNPRF, byequiv, ported +C] *)
     nnv_f <= pxmt =>
     (* ---- the FX bound (hfx's RHS shape), assembled by +C-invariant glue ---- *)
     p0 <= skg + mkg + mforsc + pxmt.
proof.
  move=> br_orig br_skg br_mkg br_v br_fors br_xmssmt.
  (* pp <= |pp-np| + np  (triangle);  np <= |np-nn| + nn  (triangle);
     nn = nnv_t + nnv_f <= mforsc + pxmt.  Pure real arithmetic, no scheme. *)
  smt(ler_norm normr_ge0 normrN).
qed.

(* --------------------------------------------------------------------------
   NON-DEGENERACY of the glue (what it IS, honestly).

   This does NOT pin p0 (that needs SPHINCS_PLUS_C, out of scope).  It only
   witnesses that the arithmetic is NOT vacuously satisfied by forcing a term
   to 0: a fully non-degenerate assignment -- every one of skg, mkg, mforsc,
   pxmt STRICTLY POSITIVE, p0 > 0, RHS a real bound < 1 with genuine slack --
   satisfies all six bridge premises and yields the FX bound.

     pp=0.5 np=0.4 nn=0.5  =>  skg=|0.1|=0.1, mkg=|-0.1|=0.1
     nn=0.5 = nnv_t(0.3)+nnv_f(0.2),  mforsc=0.3, pxmt=0.2,  p0=0.5
     bound: 0.5 <= 0.1+0.1+0.3+0.2 = 0.7   (all terms > 0; none forced to 0)
   -------------------------------------------------------------------------- *)
lemma FX_skeleton_C_nondegenerate :
  (5%r/10%r) <= (1%r/10%r) + (1%r/10%r) + (3%r/10%r) + (2%r/10%r).
proof.
  apply (FX_skeleton_C
           (5%r/10%r)   (* p0    *)
           (5%r/10%r)   (* pp    *)
           (4%r/10%r)   (* np    *)
           (5%r/10%r)   (* nn    *)
           (3%r/10%r)   (* nnv_t *)
           (2%r/10%r)   (* nnv_f *)
           (1%r/10%r)   (* skg   *)
           (1%r/10%r)   (* mkg   *)
           (3%r/10%r)   (* mforsc*)
           (2%r/10%r)); (* pxmt  *)
    smt().
qed.
