(* ==========================================================================
   SPHINCS_C.ec  --  THE CAPSTONE: top-level SPHINCS+C EUF-CMA composition.

   Mirrors MM45's high-level security theorem `EUFCMA_SPHINCS_PLUS_FX`
   (FV-SPHINCSPLUS-EC/proofs/SPHINCS_PLUS.ec:4287) with the TWO +C
   substitutions of paper 2022/778 Thm 5.2:

       MM45 term                          +C substitution (this file)
       ---------------------------------  -----------------------------------
       Pr[EUF_CMA_MFORSTWESNPRF ...]  -->  the FORS+C multi bound  (EUFCMA_MFORSC,
                                             drafts/FORS_C_Multi.ec)
       WOTS-TW multi  (inside the         -->  the WOTS+C multi bound
         XMSS-MT EUF-NAGCMA term)             (D1_MEUFNACMA_WOTSC_MM45_embthfc,
                                             drafts/WOTS_C_EmbDischarge.ec)

   The PRF hops (SKG/MKG) and the whole hypertree / Merkle-tree layer are
   +C-INVARIANT and carried UNCHANGED, exactly as in the paper.

   ---------------------------------------------------------------------------
   WHAT IS PROVEN vs WHAT IS CARRIED (read this before trusting the bound).

   This is an HONEST CONDITIONAL COMPOSITION.  There is no `SPHINCS_PLUS_C`
   *scheme module* in the repo (building it + re-running MM45's whole section
   proof over +C is the multi-month remainder of the port and is deliberately
   OUT OF SCOPE for this capstone).  So the SPHINCS+C forgery probability is
   represented by an ABSTRACT real `p_sphincs_c`, and its only anchor is the
   labelled FX-port hypothesis `hfx` below.  This is the correct shape, NOT a
   weakness: what is +C-SPECIFIC (the two leaf games) is discharged CONCRETELY
   against the two proven leg theorems; what is +C-INVARIANT (the PRF hops, the
   FX game-hop skeleton, the XMSS-MT -> WOTS-multi internal reduction, the
   Merkle-tree THF cluster) is CARRIED as explicit, labelled hypotheses.

   PROVEN CONCRETELY (the two +C-specific terms, pinned to real leg games):
     * FORS+C multi term  -> Pr[M.ITSRC ...] + mtree_{openpre,trh,trco}
         via  M.EUFCMA_MFORSC  (drafts/FORS_C_Multi.ec:452; 1 labelled
         tree admit H-TREE-MULTI + abstract mtree_* reals INSIDE that leg).
     * WOTS+C multi term  -> Pr[STCRC_WC.S_TCR_C ...] + Pr[M_EUF_GCMA_WOTSTWESNPRF ...]
         via  D1_MEUFNACMA_WOTSC_MM45_embthfc  (drafts/WOTS_C_EmbDischarge.ec:173;
         0 admit, conditional on the flagged leg hypotheses below).

   CARRIED (labelled hypotheses of THIS theorem -- NOT easycrypt `axiom`s):
     [FX+C skeleton]  hfx      -- MM45 `EUFCMA_SPHINCS_PLUS_FX` (SPHINCS_PLUS.ec:4287)
                                  ported to the +C scheme: EUF-CMA(SPHINCS+C)
                                  <= |SKG-PRF adv| + |MKG-PRF adv|
                                     + Pr[FORS+C multi] + Pr[XMSS-MT+C EUF-NAGCMA].
                                  +C-invariant except the two leaf games it names.
     [XMSS-MT+C bridge] hbridge -- MM45 `EUFNAGCMA_FLSLXMSSMTTWESNPRF`
                                  (FL_SL_XMSS_MT_ES.ec) with WOTS -> WOTS+C: the
                                  XMSS-MT EUF-NAGCMA advantage decomposes into the
                                  WOTS+C multi game (M_EUF_NACMA_WOTSC_L) + the
                                  +C-invariant tree THF cluster (PKCO/TRH/FC-UD/
                                  FC-TCR/FC-PRE), lumped here as `xmssmt_trees`.
     Leg-side conditions threaded through to the two legs:
       c <= p_tgts                (WOTS+C target-count side-condition)
       encode-compat              (WOTS+C `encode_msgWOTS_C = encode_msgWOTS o ThC`)
       [FLAG-2 emb_disj_wgpidxs is NO LONGER a premise -- DISCHARGED 2026-07-09
        by re-basing the WOTS+C stack onto the CONCRETE `FSSLXMTWES.WTWES`
        instance and DEFINING `emb_tw`; `emb_disj_wgpidxs_holds`
        (WOTS_C_Bridge.ec) now proves it from `emb_disj_concrete`
        (WOTS_C_Real.ec). The WOTS+C leg is UNCONDITIONAL apart from the
        parameter side-condition `c <= p_tgts` and the definitional
        encode-compat identity.]
       good_counter_exists        (FORS+C: a Prop-satisfying counter always exists
                                   -- App-C `r=lambda`; a COMPLETENESS premise,
                                   never a security term)
     Plus the leg-INTERNAL admits/abstract reals that the leg theorems already
     carry: FORS's H-TREE-MULTI admit + mtree_{openpre,trh,trco} abstract reals.

   INHERITED-AXIOM CLOSURE (EasyCrypt has no `Print Assumptions`, so this
   `grep '^ *axiom'` over the required port files IS the closure certificate --
   a clean compile log does NOT show transitively-inherited axioms).  The two
   legs drag in, from the port's own files:
     * STCR_C.dpp_ll : is_lossless dpp           -- STANDARD modelling axiom
         (sampling the S-TCR(+C) public parameters is lossless); benign, the
         accepted shape.  Enters via the WOTS+C S-TCR term (WOTS_C_Real clones
         STCR_C).
     * ge0_ptgts, ge0_pstcr, ge1_d, ge0_{tree,mtree}_{openpre,trh,trco}
                                                 -- trivial non-negativity /
         size side-conditions on parameters and the abstract tree reals.
   NOT in the closure (checked, worth stating because they are the App-D gap):
     * grindCP  ("+C grinding always finds a good counter" = App-D gap #1 for
         WOTS+C) is ABSENT **AS AN AXIOM**.  It lived in WOTS_C_Encoding.ec,
         which was DELETED 2026-07-09 (broken, orphaned).  D1's grinding is
         modelled operationally via STCRC_WC.G.grind, not axiomatised.

         !! UPDATE 2026-07-29 -- THIS ENTRY NO LONGER MEANS THE GAP IS CLOSED. !!
         The P-relativized fork (base-c10-fork/) RETIRED both MM45 encoding
         axioms by GATING the WOTS-TW game on `P m /\ P m'`.  That gate made
         grind-success LOAD-BEARING: the queried message on the reduction side
         is `ThC ps ad m (grindC ps ad m)`, so the queried-side `P m` holds
         exactly when the grind succeeded.  The content of grindCP is therefore
         BACK -- not as an axiom, but as an explicit PREMISE

           N2 : forall ps ad m, exists cc, predC (ThC ps ad m cc)

         carried by interactive_D1 / interactive_D1_MA and by every consumer
         above them (7 lemmas in XmssmtCC_All.ec, up to
         EUFNAGCMA_FLSLXMSSMTTWCESNPRF_Unfolded).  A premise is more honest than
         an axiom -- it is visible in every statement that depends on it and
         cannot be inherited silently -- but "ABSENT" read alone would now be
         MISLEADING.  The correct accounting of the fork is:
             2 encoding axioms RETIRED, 1 grind-success premise ADDED.
         NOT a strict reduction in assumptions.  It is a trade of an
         unjustifiable structural assumption about the ENCODING for a named,
         realistic assumption about the GRIND (the deployed C10 firmware does
         grind to target_sum=205 and succeeds in practice).
         N2 is NOT discharged by P_inhabited / targetSumReachable -- those are
         the weak `exists d, predC d` shape; see base-c10-fork/WOTS_TW_ES.ec.
     * grindP  (Grind.ec) is ABSENT as a live axiom -- Grind.ec discharges the
         FORS-side grinding-termination gap operationally (0 live axioms there);
         FORS_C's `gc = G.grind` inherits that operational model.
   Beyond the port files, the MM45 base theories (WOTS_TW_ES / FORS_ES /
   FL_SL_XMSS_MT_ES / the KHF/THF model) carry the STANDARD SPHINCS+ security-
   model axioms -- the accepted foundation of the MM45 proof, inherited but not
   re-litigated here.

   FAITHFULNESS / SHARED-ADVERSARY NOTE (important).  In MM45 every RHS term is
   `R_x(A)` for ONE shared EUF-CMA adversary `A`.  Here `A_fors` and `A_wots`
   are FREE module parameters; the composition is therefore stated for the two
   reduction IMAGES of a single (out-of-scope) SPHINCS+C adversary `A` under
   MM45's FORS-multi and XMSS-MT reductions.  Constructing `A_fors`/`A_wots`
   from a common `A` is precisely part of the carried `hfx`/`hbridge` content
   (the MM45 reductions ported to +C).  We do NOT claim to have proven that the
   two leg adversaries arise from one `A`; that is inside the labelled skeleton.

   NON-VACUITY (checked, not inherited):
     * The two +C-specific RHS terms are pinned to REAL leg games proven
       winnable / non-identically-0 in the leg files: Pr[M.ITSRC ...] is
       ITSR(+C) hardness (FORS_C_Multi.ec:346-400 non-vacuity block, conjunct
       (ii) satisfiable), and Pr[STCRC_WC.S_TCR_C ...] is S-TCR(+C) (the WOTS+C
       leg's concrete winning witness `emb_disj_wgpidxs_lists`, WOTS_C_Bridge.ec:200).
     * The composition arithmetic closes as a pure `<=` transitivity chain with
       NO term forced to 0: the intended non-degenerate assignment
       (p_sphincs_c > 0, every Pr and tree real >= its game value) satisfies all
       hypotheses.  LHS `p_sphincs_c` is a free, upper-bounded real -- winnable.
     * Sound direction throughout: LHS <= sum of RHS terms; no flip.

   NO easycrypt `axiom`, NO `sorry`, NO `admit` in THIS file; the two leg
   theorems are imported READ-ONLY and used unchanged.
   ========================================================================== *)

require import AllCore List Distr.

(* --- WOTS+C leg: mirror WOTS_C_EmbDischarge.ec's own require/import chain so
       the game names (M_EUF_NACMA_WOTSC_L, STCRC_WC, M_EUF_GCMA_WOTSTWESNPRF,
       R_multi_STCRC, R_bridge_WOTSTW, O_MEUFGCMA_WOTSTWESNPRF, FC, the ThC /
       encode_msgWOTS_C / emb_disj_wgpidxs predicates, c, p_tgts) resolve. --- *)
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Reduction WOTS_C_Multi WOTS_C_Bridge WOTS_C_EmbDischarge.
import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Reduction.
import WOTS_C_Multi.
import WOTS_C_Bridge.
import WOTS_C_EmbDischarge.

(* --- FORS+C leg: `MFORSC` is an ABSTRACT theory (cannot be imported), so we
       CLONE it to a concrete handle `M` and keep it FULLY QUALIFIED under `M.`
       / `M.F.` -- this both makes its members reachable AND avoids dumping
       FORS's type namespace (mkey/msg/cntr/pseed/adrs) into scope where it
       would clash with the WOTS chain's `cntr`/`pseed`/`adrs`.  Cloning with no
       `with` keeps every abstract op abstract and carries `EUFCMA_MFORSC`'s
       proof (incl. its own labelled tree admit) verbatim into `M`. --- *)
require FORS_C10_Multi.
clone FORS_C10_Multi.MFORSC10 as M.


(* ==========================================================================
   THE CAPSTONE THEOREM.

   Faithful to MM45 `EUFCMA_SPHINCS_PLUS_FX` term-for-term:
     skg_adv  +  mkg_adv                                  (PRF hops, +C-invariant)
     +  [ FORS+C multi expansion ]                        (+C substitution #1)
     +  [ WOTS+C multi expansion  +  XMSS-MT tree cluster](+C substitution #2)
   The RHS is written in FX term-order so it diffs cleanly against SPHINCS_PLUS.ec.
   ========================================================================== *)
lemma EUFCMA_SPHINCS_PLUS_C
  (* WOTS+C leg adversary -- restriction set copied VERBATIM from
     D1_MEUFNACMA_WOTSC_MM45_embthfc (WOTS_C_EmbDischarge.ec:173). *)
  (A_wots <: Adv_MnaCMA_WOTSC{-R_multi_STCRC, -R_multi_WOTSTW, -R_bridge_WOTSTW,
                              -G0_MULTI, -STCRC_WC.O_STCRC_Default,
                              -STCRC_WC.Col.O_THFC_Default,
                              -O_MEUFGCMA_WOTSTWESNPRF, -FC.O_THFC_Default})
  (* FORS+C leg adversary -- restriction set copied VERBATIM from
     M.EUFCMA_MFORSC (FORS_C_Multi.ec:452). *)
  (A_fors <: M.Adv_EUFCMA_MFORSC10{-M.R_ITSRC10_MFORSC10, -M.O_CMA_MFORSC10,
                                        -M.O_CMA_MFORSC10_I, -M.F.O_ITSRC10_Default,
                                        -M.EUF_CMA_MFORSC10_I})
  (* Abstract reals: the SPHINCS+C forgery prob, the XMSS-MT+C EUF-NAGCMA prob,
     the two PRF advantages, the +C-invariant XMSS-MT tree THF cluster, and the
     three +C-invariant FORS tree terms (forall-bound, NOT abstract ops -- see
     FORS_C_Multi.ec; as ops the tree bound was FALSE under `mtree_* <- 0%r`). *)
  (p_sphincs_c p_xmssmt_c skg_adv mkg_adv xmssmt_trees : real)
  (mtree_openpre mtree_trh mtree_trco : real)
  &m :
    (* ---- carried leg-side conditions (threaded to the two legs) ---- *)
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (* NO good_counter_exists premise: C10 grinds the randomiser R (no counter),
       so the good-key existence obligation is the FORS_C10.ec axiom `good_pos`
       (= p_nu), inherited by FORS_C10_Multi and LOAD-BEARING there via `query_ll`
       -- it lives in the axiom ledger, not as a per-theorem premise. *)

    (* ---- [FORS+C tree cluster] labelled hypothesis (H-TREE-MULTI): the three
            +C-INVARIANT FORS_ES tree hops (leaf-hash OpenPRE + tree-hash TCR +
            root-compression TCR) over d*k*t targets.  Discharge = port that tree
            layer and instantiate the three reals with its advantages. ---- *)
    (   Pr[M.EUF_CMA_MFORSC10_I(A_fors).main() @ &m
             : res /\ !M.EUF_CMA_MFORSC10_I.covered]
     <= mtree_openpre + mtree_trh + mtree_trco) =>

    (* ---- [FX+C skeleton] labelled hypothesis: MM45 EUFCMA_SPHINCS_PLUS_FX
            (SPHINCS_PLUS.ec:4287) ported to the +C scheme.  +C-invariant except
            the two leaf games it names. ---- *)
    p_sphincs_c
      <= skg_adv
       + mkg_adv
       + Pr[M.EUF_CMA_MFORSC10(A_fors, M.O_CMA_MFORSC10).main() @ &m : res]
       + p_xmssmt_c =>

    (* ---- [XMSS-MT+C bridge] labelled hypothesis: MM45
            EUFNAGCMA_FLSLXMSSMTTWESNPRF (FL_SL_XMSS_MT_ES.ec) with WOTS ->
            WOTS+C.  The XMSS-MT EUF-NAGCMA advantage decomposes into the WOTS+C
            multi game + the +C-invariant tree THF cluster. ---- *)
    p_xmssmt_c
      <= Pr[M_EUF_NACMA_WOTSC_L(A_wots, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
       + xmssmt_trees =>

    (* ---- CONCLUSION (FX term-order, two +C substitutions applied) ---- *)
    p_sphincs_c
      <= skg_adv
       + mkg_adv
       (* +C substitution #1: FORS+C multi expansion (EUFCMA_MFORSC10) *)
       + ( Pr[M.F.ITSRC10(M.R_ITSRC10_MFORSC10(A_fors),
                             M.F.O_ITSRC10_Default).main() @ &m : res]
           + mtree_openpre + mtree_trh + mtree_trco )
       (* +C substitution #2: WOTS+C multi expansion (D1) + XMSS-MT tree cluster *)
       + ( Pr[STCRC_WC.S_TCR_C(R_multi_STCRC(A_wots),
                               STCRC_WC.O_STCRC_Default,
                               STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
           + Pr[M_EUF_GCMA_WOTSTWESNPRF(R_bridge_WOTSTW(A_wots),
                                        O_MEUFGCMA_WOTSTWESNPRF,
                                        FC.O_THFC_Default).main() @ &m : res]
           + xmssmt_trees ).
proof.
  move=> hc encb htree hfx hbridge.
  (* FORS+C leg (READ-ONLY): discharges the FORS+C multi term, CONDITIONAL on the
     explicit tree premise `htree` (was a false-as-stated admit before 2026-07-09). *)
  have hF := M.EUFCMA_MFORSC10 A_fors mtree_openpre mtree_trh mtree_trco &m htree.
  (* WOTS+C leg (READ-ONLY): discharges the WOTS+C multi term. *)
  have hW := D1_MEUFNACMA_WOTSC_MM45_embthfc A_wots &m hc encb.
  (* Pure sound-direction linear-arith transitivity over the four bounds.
     Chain:  p_sphincs_c <= skg+mkg+FORS+p_x        (hfx)
             FORS        <= ITSR + mtree_*           (hF)
             p_x         <= WOTS + xmssmt_trees       (hbridge)
             WOTS        <= STCR + M_EUF_GCMA         (hW)
     => the stated conclusion.  No term forced to 0; no flip.
     (hfx, hbridge, hgc-derived hF, hc/encb/hd-derived hW are all local
      hypotheses, auto-included by smt.) *)
  smt().
qed.
