(* ==========================================================================
   XMSSMT_C_Bridge.ec  --  SCOUTING VERDICT + FAITHFUL DISCHARGE ATTEMPT of the
   capstone's `hbridge` hypothesis (SPHINCS_C.ec:184-190).

   TASK.  The capstone `EUFCMA_SPHINCS_PLUS_C` (drafts/SPHINCS_C.ec) is
   conditional on the labelled hypothesis

     [XMSS-MT+C bridge] hbridge :
        p_xmssmt_c
          <= Pr[M_EUF_NACMA_WOTSC_L(A_wots, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
           + xmssmt_trees                                       (SPHINCS_C.ec:188)

   i.e. MM45's `EUFNAGCMA_FLSLXMSSMTTWESNPRF` (FL_SL_XMSS_MT_ES.ec:6306 / its
   `..._MEUFGCMAWOTSTWES` intermediate at :4075) with WOTS -> WOTS+C, routing the
   XMSS-MT+C bound through the WOTS+C multi game.  This file discharges hbridge
   for real -- OR, as it turns out, characterises the gap precisely.

   ==========================================================================
   VERDICT (from reading MM45's reduction + the two WOTS+C multi games).

   (1) PARAMETRICITY:  MM45's XMSS-MT reduction is *INLINE*, not parametric over
       the WOTS leaf game.  `R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA` (FL_SL_XMSS_MT_ES.ec
       :1888) hardcodes WOTS-TW scheme internals -- it walks the chains, calls
       `WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS` (:2091), `pkco`/`trh` (:1981,:2002),
       `cons_ap_trh`/`val_ap_trh` -- directly, not through an abstract leaf-game
       interface.  CONSEQUENCE: porting to WOTS+C is a RE-DERIVATION of the whole
       ~700-line intermediate lemma (+ the ~2200 further lines expanding WOTS
       multi into FC_UD/FC_TCR/FC_PRE), not a clean instantiation.  This is the
       "multi-month remainder" the capstone header already calls out.

   (2) LEAF-GAME INTERFACE:  MM45's reduction consumes the *ADAPTIVE* multi game
       `M_EUF_GCMA_WOTSTWESNPRF` (WOTS_TW_ES.ec:2323).  Its adversary interface is
         choose() : unit { O.query, OC.query }                 (WOTS_TW_ES.ec:2316)
       -- `O.query(wad, m)` RETURNS `(pkWOTS, sigWOTS)` *immediately* (:2304), and
       the reduction uses exactly this adaptivity: it queries a lower hypertree
       layer, derives the leaves (`pkco` of the returned pkWOTS), Merkle-hashes
       them to a subtree root, and then queries the *upper* layer's WOTS instance
       ON THAT ROOT (FL_SL_XMSS_MT_ES.ec:1972-2018, the interleaved layer loop:
       `root <- nth witness rootsntp ...; (pkWOTS, sigWOTS) <@ O.query(.., root)`,
       where `rootsntp` is built from the previous layer's O.query responses).
       So the upper-layer signing MESSAGES are FUNCTIONS OF the game's own random
       NPRF public keys, revealed only through prior queries.  This matches the
       paper's `Exp^{d-EU-naCMA}` (2022/778 App-D), whose phase-1 gives the
       adversary an INTERACTIVE sign oracle `A1^{WOTS+C.sign(Seed,.,S)}` and hands
       over `Seed` only in phase 2.

   (3) THE GAP (load-bearing).  The capstone routes hbridge through
       `M_EUF_NACMA_WOTSC_L` (WOTS_C_Multi.ec:59), which is STRICTLY BATCH-COMMIT:
         choose() : qC list { OC.query }                       (WOTS_C_Multi.ec:54)
       hands the adversary ONLY the collection oracle, forces it to commit EVERY
       `(wad, m)` up front, and reveals all keypairs+signatures only later in
       `forge(ps, ks)` (:55, :93).  A batch adversary therefore CANNOT compute the
       upper-layer messages it must commit -- those are `trh(pkco(pkWOTS_lower))`
       and the `pkWOTS_lower` are the game's keys, unavailable at choose() time.
       The circular dependency is STRUCTURAL, not an artefact of MM45's code:
       MM45's reduction cannot be typed as an `Adv_MnaCMA_WOTSC` at all.
       => hbridge, as written (batch game), is NOT dischargeable by porting MM45.

   (4) FAITHFUL TARGET.  The correct +C mirror of MM45's leaf game already exists
       in the repo: `M_EUF_GCMA_WOTSC_NPRF` (WOTS_C_Scheme.ec:182), the INTERACTIVE
       WOTS+C multi game -- oracle `query(wad,m) : pkWOTS * (sigWOTS * cntr)`
       returns pk+sig immediately (:133), adversary `choose() : unit {O.query,
       OC.query}` (:141).  The faithful hbridge routes through THIS game (Part B
       below).  The inline WOTS+C re-derivation of MM45's :4075 lemma is the
       residual `H-XMSSMT-C-INLINE`.

   (4b) WHY hbridge STAYS A PREMISE (cannot be reduced to a *true* labelled admit
       in-repo).  MM45's :4075 lemma bounds `Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(A,
       ..).main() @ &m : res]` -- a REAL game over a REAL scheme module.  The +C
       analogue would bound `Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C(A,..)]`, but NO
       such +C XMSS-MT scheme/game module exists in the repo (building it is the
       out-of-scope multi-month remainder).  So the XMSS-MT+C forgery advantage is
       unavoidably the ABSTRACT real `p_xmssmt_c`, un-bound to any game term.  An
       admit-backed lemma `p_xmssmt_c <= Pr[..WOTS+C game..] + trees` with a FREE
       `p_xmssmt_c` would be UNIVERSALLY FALSE (take `p_xmssmt_c` large); admitting
       it -- even labelled -- would be unsound.  Hence, exactly as the capstone
       does with `hbridge`, the faithful bound is carried as a FLAGGED HYPOTHESIS
       (`=>`), and the composition around it is what we prove (Part B, real qed,
       0 admit).  The honest discharge boundary is therefore: (i) construct the
       +C XMSS-MT scheme+game module, (ii) inline-port MM45 :4075 over it through
       the interactive game (`H-XMSSMT-C-INLINE`).  Both are named residuals; the
       gap-characterisation, not a fake admit, is the sound deliverable.

   (5) DIRECTION / SOUNDNESS (the trap the task flags).  The ONLY sound relation
       between the two WOTS+C games is
              Pr[batch M_EUF_NACMA_WOTSC_L] <= Pr[interactive M_EUF_GCMA_WOTSC_NPRF]
       (a batch adversary embeds into the interactive game by making all its
       committed queries at once and ignoring the intermediate responses -- see
       `R_batch2int` below).  The REVERSE (`interactive <= batch`) does NOT hold:
       interactive is the STRONGER adversary interface.  So one CANNOT re-connect
       a faithful (interactive-routed) hbridge back to the repo's PROVEN D.1
       (`D1_MEUFNACMA_WOTSC_MM45_embthfc`, WOTS_C_EmbDischarge.ec:173), because
       that D.1 is proven over the BATCH game `M_EUF_NACMA_WOTSC_L` -- deliberately,
       to make its S-TCR(+C) reduction clean (WOTS_C_Multi.ec:24-34).  Faithful
       hbridge needs interactive; the repo's D.1 is batch; THEY DO NOT COMPOSE ON
       THE SHARED naCMA GAME NAME.  Stating a bound in the reverse direction to
       force them together would be the false-direction error.

   (6) RESIDUAL (why the gap is not "just effort").  A *batch-compatible*
       XMSS-MT+C reduction does exist -- via a guessing/hybrid argument (embed
       the challenge keys at ONE guessed layer, generate the rest honestly so the
       committed upper messages are known), but that loses a hypertree factor and
       is a DIFFERENT, non-tight theorem -- NOT the paper's multi-instance
       d-EU-naCMA bound.  The clean fix is to RE-PROVE D.1 over the interactive
       `M_EUF_GCMA_WOTSC_NPRF` (which is what the paper's Thm D.1 actually is, with
       its interactive phase-1 oracle), then route hbridge through it.  Both pieces
       are labelled residuals below; neither is dischargeable in-file.

   NON-VACUITY (checked): every term below is pinned to a REAL game module
   (`M_EUF_GCMA_WOTSC_NPRF`, `M_EUF_NACMA_WOTSC_L`) that both typecheck and are
   winnable in their leg files; the composition arithmetic closes as a pure `<=`
   transitivity with NO term forced to 0 and NO direction flip; each introduced
   hypothesis (`H-XMSSMT-C-INLINE`, `H-D1-INTERACTIVE`) is individually
   satisfiable by the intended non-degenerate assignment.

   NO easycrypt `axiom`, NO `sorry`, and NO `admit` in this file (see (4b): an
   admit here would be an admit of a universally-false statement, which we refuse
   to write).  The two named residuals `H-XMSSMT-C-INLINE` and `H-D1-INTERACTIVE`
   are carried as FLAGGED HYPOTHESES of the proven composition (Part B), each
   individually satisfiable, routed through the SOUND (interactive) game.
   ========================================================================== *)

require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Scheme WOTS_C_Reduction WOTS_C_Multi.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Scheme.
import WOTS_C_Multi.


(* ==========================================================================
   PART A -- the faithful hbridge SHAPE (as a carried premise, per (4b)).

   MM45's :4075 lemma, under WOTS -> WOTS+C, has the shape

     p_xmssmt_c
       <= Pr[M_EUF_GCMA_WOTSC_NPRF(A_wots, O_MEUFGCMA_WOTSC_Default,
                                   FC.O_THFC_Default).main() @ &m : res]
        + pkco_tcr_C + trh_tcr_C

   where `p_xmssmt_c` is the abstract XMSS-MT+C EUF-NAGCMA advantage (no +C
   scheme module -> abstract, see (4b)), `A_wots` is the interactive WOTS+C
   adversary the ported inline reduction would emit, and `pkco_tcr_C + trh_tcr_C`
   are the two +C-invariant SM-DT-TCR-C tree terms (pkco leaf-compression + trh
   Merkle-node hashing) of MM45's :4075 lemma.  Discharging it to a PROVEN lemma
   requires the two residuals in (4b) -- so, exactly as SPHINCS_C.ec carries
   `hbridge`, it is a FLAGGED HYPOTHESIS here.  The value added over the capstone:
   this shape routes through the INTERACTIVE `M_EUF_GCMA_WOTSC_NPRF`
   (WOTS_C_Scheme.ec:182), which per the header (2)-(5) is the SOUND target --
   the capstone's `M_EUF_NACMA_WOTSC_L` (batch) target is structurally unreachable
   by MM45's adaptive reduction.  Part B proves the composition around this shape.
   ========================================================================== *)


(* ==========================================================================
   PART B -- The composition that a FAITHFUL capstone would run (real qed).

   Chains the faithful (interactive-routed) hbridge PREMISE with the paper's
   Thm D.1 *stated over the interactive game* (`H-D1-INTERACTIVE`), reaching the
   capstone's intended XMSS-MT+C expansion `<= p_stcr + p_gcma + trees`.  This is
   the analog of SPHINCS_C.ec's own `smt()` transitivity, but through the CORRECT
   game.  No `admit`: both residuals are honest `=>` premises.

   H-D1-INTERACTIVE is a FLAGGED, SATISFIABLE hypothesis and a genuine RESIDUAL:
   it is NOT the repo's proven D.1.  The proven `D1_MEUFNACMA_WOTSC_MM45_embthfc`
   (WOTS_C_EmbDischarge.ec:173) bounds the BATCH game `M_EUF_NACMA_WOTSC_L`, which
   -- per the header's direction analysis -- does NOT upper-bound the interactive
   game's advantage.  So this composition is honestly conditional on re-proving
   D.1 over `M_EUF_GCMA_WOTSC_NPRF`.
   ========================================================================== *)
lemma xmssmt_c_expansion_interactive
  (A_wots <: Adv_MEUFGCMA_WOTSC{-O_MEUFGCMA_WOTSC_Default, -FC.O_THFC_Default})
  (p_xmssmt_c pkco_tcr_C trh_tcr_C p_stcr p_gcma : real) &m :
    (* faithful interactive-routed hbridge (Part A applied) *)
    p_xmssmt_c
      <= Pr[M_EUF_GCMA_WOTSC_NPRF(A_wots, O_MEUFGCMA_WOTSC_Default,
                                  FC.O_THFC_Default).main() @ &m : res]
       + pkco_tcr_C + trh_tcr_C =>
    (* [H-D1-INTERACTIVE] paper Thm D.1 over the INTERACTIVE game (RESIDUAL -- NOT
       the repo's batch D1_MEUFNACMA_WOTSC_MM45_embthfc). *)
    Pr[M_EUF_GCMA_WOTSC_NPRF(A_wots, O_MEUFGCMA_WOTSC_Default,
                             FC.O_THFC_Default).main() @ &m : res]
      <= p_stcr + p_gcma =>
    (* conclusion: the capstone's intended XMSS-MT+C expansion, through the
       interactive game.  Sound `<=` transitivity, no term forced to 0. *)
    p_xmssmt_c <= p_stcr + p_gcma + pkco_tcr_C + trh_tcr_C.
proof.
  move=> hxmt hd1.
  smt().
qed.
