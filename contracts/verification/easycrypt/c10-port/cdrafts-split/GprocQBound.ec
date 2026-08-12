(* ===========================================================================
   THE Q BOUND -- the composition of the three branch proofs.

   gproc_Q_decomposition (GprocFORSC10.ec:1514) splits

     Q = Pr[EUF_CMA_Gproc_I(A) : res /\ !covered]

   into exactly three summands, by the OpenPRE and TRH-TCR event splits:

     Q = Pr[V : (res /\ !cov) /\ vOpenPRE]                    <- T1
       + Pr[V : ((res /\ !cov) /\ !vOpenPRE) /\  vTRHTCR]     <- T2
       + Pr[V : ((res /\ !cov) /\ !vOpenPRE) /\ !vTRHTCR]     <- T3

   and GprocT1Opre / GprocT2Trh / GprocT3Trco bound them one apiece, each by a
   reduction to a named hardness game.  This file does the only thing left:
   adds them up.  It is one `smt()` over four facts, and that is the point --
   all of the content is in the three branch files; what was missing until now
   was a single statement saying Q is bounded at all.

   WHAT THIS BUYS, STATED PRECISELY.  It does NOT reduce the assumption count:
   the three right-hand terms are hardness advantages (one SM-DT-OpenPRE, two
   SM-DT-TCR-C), and they are assumptions exactly as the free reals they replace
   were.  What changes is that they are NAMED and INSTANTIATED -- the bound is
   now against concrete games with concrete reductions rather than three
   unconstrained reals.  The cone census confirms the shape of that claim: the
   promotion of the three branch files adds 16 census keys, all `module:` and
   `operand:` (meaning-carriers), and ZERO `admit` or `axiom` rows.

   THE RESTRICTION SET is the UNION of the three branches': A must be disjoint
   from all three reductions and from every challenger they instantiate.  Each
   branch lemma asks for a subset of it, so each applies.

   [STALE HEADING — SUPERSEDED 2026-08-11 by GprocQWired.ec, which DOES wire this
   bound: EUFCMA_SPHINCS_PLUS_C10_QWIRED (:67) carries the nine extra module
   separations described below, and the deployed pair
   ..._AT_DEPLOYED_PARAMS_QWIRED (:299) / ..._PINNED_ENCODER_QWIRED (:387) is the
   canonical one to quote.  The GROUNDED-derived deployed lemmas were NOT
   repaired -- they are superseded for quotation, per the repo's parallel-supersede
   precedent.  Caught by GPT-5.6 adversarial review.  The analysis below of WHAT
   blocked the discharge remains accurate and is why the restriction set had to
   be widened rather than the capstone edited in place.]
   NOT YET WIRED INTO THE CAPSTONE, and the reason is recorded rather than left
   to be rediscovered.  SphincsC10CapstoneWired.ec:566 carries exactly this
   bound as its H-TREE-MULTI premise, at A := R_fors_p(F), with the three free
   reals mtree_openpre/mtree_trh/mtree_trco -- which ARE lemma binders
   (:523), so they are instantiable.  What blocks the discharge is the
   restriction set: EUFCMA_SPHINCS_PLUS_C10's forger F is declared disjoint
   from O_CMA_Gproc_I and EUF_CMA_Gproc_I, but NOT from EUF_CMA_Gproc_V, the
   three reductions R_OPRE_Gproc/R_TRH_Gproc/R_TRCO_Gproc, or the four FTWES
   challengers (F_OpenPRE.O_SMDTOpenPRE_Default, TRHC_TCR/TRHC and
   TRCOC_TCR/TRCOC O_SMDTTCR_Default/O_THFC_Default) -- 9 separations missing,
   so `gproc_Q_bound (R_fors_p(F))` does not typecheck there.  Adding them is
   the same move the capstone already made once (its "WIRED (Step 4)" block),
   and by that precedent it is standard reduction well-formedness; but it is
   formally a NARROWING of a headline theorem's hypothesis, so it is left as a
   deliberate decision rather than taken here.
   =========================================================================== *)
require import AllCore List Distr StdBigop StdOrder IntDiv.
require import SPHINCS_PLUS XmssmtCC_All RtopCSoundness FxChain GprocFORSC10 GprocVI.
require import GprocT1Opre GprocT2Trh GprocT3Trco.

lemma gproc_Q_bound
  (A <: Adv_EUFCMA_Gproc{ -O_CMA_Gproc_I, -EUF_CMA_Gproc_I, -EUF_CMA_Gproc_V,
        -R_OPRE_Gproc, -FTWES.F_OpenPRE.O_SMDTOpenPRE_Default,
        -R_TRH_Gproc, -FTWES.TRHC_TCR.O_SMDTTCR_Default, -FTWES.TRHC.O_THFC_Default,
        -R_TRCO_Gproc, -FTWES.TRCOC_TCR.O_SMDTTCR_Default,
        -FTWES.TRCOC.O_THFC_Default }) &m :
    Pr[EUF_CMA_Gproc_I(A).main() @ &m : res /\ ! EUF_CMA_Gproc_I.covered]
  <= Pr[FTWES.F_OpenPRE.SM_DT_OpenPRE(R_OPRE_Gproc(A),
           FTWES.F_OpenPRE.O_SMDTOpenPRE_Default).main() @ &m : res]
   + Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRH_Gproc(A),
           FTWES.TRHC_TCR.O_SMDTTCR_Default, FTWES.TRHC.O_THFC_Default).main() @ &m : res]
   + Pr[FTWES.TRCOC_TCR.SM_DT_TCR_C(R_TRCO_Gproc(A),
           FTWES.TRCOC_TCR.O_SMDTTCR_Default, FTWES.TRCOC.O_THFC_Default).main() @ &m : res].
proof.
have hd := gproc_Q_decomposition A &m.
have h1 := t1_opre_bound A &m.
have h2 := t2_trh_bound A &m.
have h3 := t3_trco_bound A &m.
smt().
qed.
