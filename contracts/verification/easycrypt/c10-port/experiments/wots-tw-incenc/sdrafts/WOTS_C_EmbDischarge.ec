(* ==========================================================================
   WOTS_C_EmbDischarge.ec  --  Discharging the WOTS+C bridge's two embedding
                               hypotheses (FLAG-1 / FLAG-2 of WOTS_C_Bridge.ec).

   GOAL.  WOTS_C_Bridge.ec proves the WOTS+C multi-instance d-EU-naCMA bound
     `D1_MEUFNACMA_WOTSC_MM45` as a CONDITIONAL theorem on two flagged
     embedding hypotheses over the message-compression embedding
     (`emb_tw : adrs -> adrs`, `emb_in : msgWOTS * cntr -> dgst`):

       FLAG-1  emb_thfc_ThC :
         forall ps tw x, thfc (size (emb_in x)) ps (emb_tw tw) (emb_in x)
                         = ThC ps tw x.`1 x.`2
         "Th+C is the SPHINCS+ tweakable hash `thfc` at the embedded message-
          compression address on the embedded input."

       FLAG-2  emb_disj_wgpidxs :
         forall a b, valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)
         "No valid WOTS chain-signing address shares a wgpidx global part with
          any message-compression image."  (SPHINCS+ address-TYPE separation.)

   This file reports which of the two is dischargeable NOW, discharges it, and
   PRECISELY CHARACTERISES the residual — SPECIALISING `D1_MEUFNACMA_WOTSC_MM45`
   at the concrete `ThC = thfc o emb` so that its `emb_thfc_ThC` premise is
   discharged, leaving a ONE-hypothesis conditional (`emb_disj_wgpidxs` only)
   plus the modelling encoding-compatibility premise that was already there.

   HONEST HEADLINE (read this first).  The FLAG-1 discharge is a DEFINITIONAL
   trivialisation: by DEFINING `ThC := thfc o emb`, `emb_thfc_ThC` becomes true
   BY CONSTRUCTION, for an ARBITRARY `emb_tw`.  This is legitimate (it is the
   task's "unconditional bound for the concrete instantiation", and it is the
   faithful SPHINCS+ realisation of Th+C — Thm 5.2), but it is a SPECIALISATION
   of the prior 2-hypothesis lemma at one concrete `ThC`, NOT a strengthening of
   it.  Crucially, ALL genuine embedding content MIGRATES into the still-open
   FLAG-2: emb_thfc now says NOTHING about WHICH address `emb_tw` hits; the
   substantive constraint ("emb_tw lands in a type-separated address so the
   wgpidx global parts are disjoint") lives ENTIRELY in `emb_disj_wgpidxs`,
   which stays an unproven-but-satisfiable hypothesis.  We eliminated the cheap
   predicate; the substantive one remains open (see FLAG-2 gap below).

   --------------------------------------------------------------------------
   RESULT SUMMARY (honest).

   * FLAG-1 (emb_thfc_ThC): DISCHARGED — `emb_thfc_ThC_holds` below, ZERO admit.
     The discharge is DEFINITIONAL and non-degenerate.  `ThC` was an INDEPENDENT
     abstract op in the earlier draft of WOTS_C_Real.ec; it is now DEFINED there
     (2026-07-08) exactly as SPHINCS+ realises Th+C:
        ThC ps tw m c = thfc (size (emb_in (m,c))) ps (emb_tw tw) (emb_in (m,c)).
     `emb_thfc_ThC` then holds by unfolding the definition (surjective pairing).
     This is the paper's own modelling fact (Thm 5.2: Th+C is a member of the
     SPHINCS+ tweakable-hash family), NOT a vacuity trap — see NON-VACUITY.

   * FLAG-2 (emb_disj_wgpidxs): NOT reachable at this abstraction layer.
     PRECISE GAP (structural, mirrors the FORS tree-leg situation):

       - The bridge / the whole WOTS_C stack `import WOTS_TW_ES` — the ABSTRACT
         WOTS-TW theory.  There, `get_wgpidxs ad = drop 2 (val ad)` is concrete,
         but `valid_wadrs ad = valid_wadrsidxs (val ad)` routes through the
         ABSTRACT predicate `valid_widxvalsgp` (WOTS_TW_ES.ec:311).  So at this
         layer a `valid_wadrs a` hypothesis exposes NO address type field:
         nothing distinguishes `get_wgpidxs a` from `get_wgpidxs (emb_tw b)`.

       - The mechanism that MAKES emb_disj true lives ONLY in the CONCRETE
         instantiation SPHINCS_PLUS.ec: there the address is 6 indices, index 3
         is the TYPE field, `valid_idxvalsch` REQUIRES `nth _ 3 = chtype` for a
         WOTS chain address, the five types are distinct (`axiom dist_adrstypes`
         : uniq [chtype; pkcotype; trhxtype; trhftype; trcotype]), and
         `get_wgpidxs = drop 2` INCLUDES index 3.  There, choosing `emb_tw` to
         set the type field to a non-`chtype` type discharges emb_disj cleanly.

       - BUT SPHINCS_PLUS.ec is a SELF-CONTAINED universe: it does NOT
         require/import/clone the standalone WOTS_TW_ES the WOTS_C stack sits on.
         Its concrete `valid_idxvals` / `chtype` / `dist_adrstypes` are simply
         NOT in scope for the bridge's abstract `valid_wadrs`.  Discharging
         emb_disj therefore requires RE-BASING the entire WOTS_C stack
         (Real/Scheme/Reduction/Multi/Bridge) onto a WOTS_TW_ES clone with the
         concrete SPHINCS+ address validity — a multi-file restructure that
         crosses WOTS_C_Multi.ec (out of scope / must stay untouched).

     WHAT emb_disj NEEDS, exactly: the concrete SPHINCS+ address-type scheme
     (`valid_widxvalsgp`/`valid_idxvals` instantiated so `valid_wadrs a` forces
     `nth (val a) 3 = chtype`, `dist_adrstypes`, and an `emb_tw` that sets the
     type field to a non-chain type) visible at the layer where the bridge's
     `valid_wadrs`/`get_wgpidxs` are defined.  It is a genuine, satisfiable
     scheme fact (the concrete witness exists in SPHINCS_PLUS.ec) — labelled
     here as the remaining hypothesis, NOT an easycrypt axiom.

   --------------------------------------------------------------------------
   NON-VACUITY (FLAG-1 discharge is not a vacuity trap).

   * `emb_thfc_ThC` is a MODELLING/IMPLEMENTATION fact ("Th+C is realised as the
     tweakable hash at the message-compression address"), NOT a security claim.
     Making it hold by DEFINING `ThC := thfc o emb` is the faithful encoding of
     how SPHINCS+ computes Th+C — the paper's Thm 5.2 statement itself.

   * The definition does NOT trivialise the bound.  `thfc`, `emb_tw`, `emb_in`,
     `predC` all remain ABSTRACT.  Hence:
       - the RHS S-TCR(+C) term `InSec^{S-TCR(+C)}(Th+C)` is the genuine
         SM-DT-TCR-C advantage over the abstract tweakable hash at the abstract
         message-compression addresses — non-zero, not degenerate;
       - the LHS WOTS+C game and the MM45 term are unchanged;
       - `emb_disj_wgpidxs` is STILL required (real address-separation content),
         so the corollary below is a proper ONE-hypothesis conditional, not a
         theorem proved by collapsing its premises.

   * `emb_tw` is NOT constant / degenerate: it stays an arbitrary abstract map;
     the discharge holds for EVERY such map, precisely because emb_thfc is an
     implementation identity, not a constraint on emb_tw.  (The constraint on
     `emb_tw` — that it lands in a wgpidx-disjoint address type — is exactly the
     content of the still-open FLAG-2, kept honest as a hypothesis.)

   * LINCHPIN — `emb_disj_wgpidxs` is STILL SATISFIABLE under the now-concrete
     `ThC = thfc o emb`, so the one-hypothesis corollary is NOT vacuously true
     via an impossible premise.  `emb_disj_wgpidxs` constrains ONLY `emb_tw`'s
     codomain (`get_wgpidxs (emb_tw b)` vs `get_wgpidxs a` for `valid_wadrs a`);
     `emb_tw` stays an arbitrary abstract map UNCONSTRAINED by the `ThC`
     definition (which fixes ThC's VALUE, never emb_tw's type field).  The
     concrete SPHINCS+ address scheme (SPHINCS_PLUS.ec: index-3 type field,
     `dist_adrstypes`, `valid_idxvalsch` forcing `chtype` on chain addresses) is
     an explicit WITNESS that an `emb_tw` satisfying FLAG-2 exists.  Hence:
     FLAG-1 trivial (definitional) + FLAG-2 a satisfiable-but-unproven REAL
     constraint = a genuine conditional, not a vacuity.  (Had BOTH been
     trivialised, that would be vacuity; only FLAG-1 was.)

   --------------------------------------------------------------------------
   PROVENANCE OF THE EDIT.
   * WOTS_C_Real.ec: `emb_tw`/`emb_in` declared upstream; `ThC` changed from an
     abstract op to the definition above.  Conservative: no proof in the stack
     unfolds `ThC` (grep: zero `/ThC` rewrites in Multi/Reduction/Scheme/STCR_C),
     so Real + Multi + Bridge all recompile 0-admit unchanged.
   * WOTS_C_Bridge.ec: the two now-upstream `op` declarations removed; predicate
     bodies + both bridge lemmas (`D1_bridge_WOTSTW`,`D1_MEUFNACMA_WOTSC_MM45`)
     UNCHANGED and still 0-admit (verified).
   ========================================================================== *)

require import AllCore List Distr.
require import SPHINCS_PLUS.
require WOTS_C_Real WOTS_C_Reduction WOTS_C_Multi WOTS_C_Bridge.

import FSSLXMTWES.WTWES.
import HA.Adrs.
import WOTS_C_Real.
import WOTS_C_Reduction.
import WOTS_C_Multi.
import WOTS_C_Bridge.

(* ==========================================================================
   FLAG-1 DISCHARGE.  `emb_thfc_ThC` holds by the definition of `ThC` in
   WOTS_C_Real.ec (`ThC ps tw m c = thfc (size (emb_in (m,c))) ps (emb_tw tw)
   (emb_in (m,c))`).  Zero admit; unfold + surjective pairing on the (msg,cntr)
   argument.
   ========================================================================== *)
lemma emb_thfc_ThC_holds : emb_thfc_ThC.
proof.
rewrite /emb_thfc_ThC => ps tw [m c].
by rewrite /ThC /=.
qed.

(* ==========================================================================
   COMPOSITION COROLLARY (FLAG-1 discharged).

   `D1_MEUFNACMA_WOTSC_MM45` with its `emb_thfc_ThC` premise DISCHARGED.  The
   bound now stands on:
     (1) `c <= p_tgts`                    (parameter side-condition, as before),
     (2) the WOTS+C encoding-compatibility modelling premise
         `encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)`
         (already a hypothesis of D1; unchanged), and
     (3) `emb_disj_wgpidxs`               (FLAG-2, the residual scheme fact —
                                           see this file's header for the exact
                                           gap and what discharges it).
   The `emb_thfc_ThC` hypothesis is GONE — this is D1 SPECIALISED at the
   concrete `ThC = thfc o emb` (not a strengthening of the abstract-ThC lemma),
   the honest form of the WOTS+C leg reachable at the abstract-address layer.
   ========================================================================== *)
lemma D1_MEUFNACMA_WOTSC_MM45_embthfc
  (A <: Adv_MnaCMA_WOTSC{-R_multi_STCRC, -R_multi_WOTSTW, -R_bridge_WOTSTW,
                         -G0_MULTI, -STCRC_WC.O_STCRC_Default,
                         -STCRC_WC.Col.O_THFC_Default,
                         -O_MEUFGCMA_WOTSTWESNPRF, -FC.O_THFC_Default}) &m :
    c <= p_tgts =>
    (forall (p : pseed) (a : adrs) (x : msgWOTS) (cc : cntr),
       encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)) =>
    (* FLAG-2 (`emb_disj_wgpidxs`) is NO LONGER a premise: it is discharged by the
       proved `emb_disj_wgpidxs_holds` (WOTS_C_Bridge.ec), which rests on
       `emb_disj_concrete` over the concrete instance (WOTS_C_Real.ec). *)
    Pr[M_EUF_NACMA_WOTSC_L(A, STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
  <=   Pr[STCRC_WC.S_TCR_C(R_multi_STCRC(A),
                           STCRC_WC.O_STCRC_Default,
                           STCRC_WC.Col.O_THFC_Default).main() @ &m : res]
     + Pr[M_EUF_GCMA_WOTSTWESNPRF(R_bridge_WOTSTW(A),
                                  O_MEUFGCMA_WOTSTWESNPRF,
                                  FC.O_THFC_Default).main() @ &m : res].
proof.
move=> hc encb.
exact: (D1_MEUFNACMA_WOTSC_MM45 A &m hc encb emb_thfc_ThC_holds emb_disj_wgpidxs_holds).
qed.
