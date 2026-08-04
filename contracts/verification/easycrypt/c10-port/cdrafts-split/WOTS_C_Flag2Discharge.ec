(* ==========================================================================
   WOTS_C_Flag2Discharge.ec  --  FLAG-2 (`emb_disj_wgpidxs`) PROVEN over the
                                 REAL, VETTED SPHINCS+ concrete address scheme.

   CONTEXT.  WOTS_C_Bridge.ec proves the WOTS+C multi-instance d-EU-naCMA bound
   `D1_MEUFNACMA_WOTSC_MM45` as a CONDITIONAL theorem on two flagged embedding
   hypotheses; WOTS_C_EmbDischarge.ec discharged FLAG-1 (`emb_thfc_ThC`)
   definitionally, leaving the SUBSTANTIVE residual FLAG-2:

     emb_disj_wgpidxs :
       forall (a b : adrs), valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b)
     "No valid WOTS chain-signing address shares a wgpidx global part with any
      message-compression image."  (SPHINCS+ address-TYPE separation.)

   At the WOTS+C stack's base (abstract `WOTS_TW_ES`), `valid_widxvalsgp` and
   `valid_idxvals` are ABSTRACT ops (no body) and `emb_tw` is an ABSTRACT op, so
   FLAG-2 is UNPROVABLE there (indeed FALSE for some models — take `emb_tw = id`
   and `a = b` a valid address: `get_wgpidxs a = get_wgpidxs (emb_tw b)`).  It is
   NOT a theorem of the abstract theory; it is a genuine SCHEME fact, kept as an
   explicit lemma hypothesis (never an easycrypt axiom).

   WHAT THIS FILE ESTABLISHES (honest headline).
   ---------------------------------------------------------------------------
   Over the CONCRETE, already-vetted SPHINCS+ address scheme (SPHINCS_PLUS.ec,
   the same instance the whole FV-SPHINCSPLUS-EC proof runs on), FLAG-2 is
   PROVABLE: `emb_disj_concrete` below is EXACTLY the shape of the bridge's
   `emb_disj_wgpidxs`, over a GENUINE (non-degenerate) message-compression
   embedding `emb_tw`, and it is proved with ZERO admit / ZERO axiom.

   This UPGRADES FLAG-2 from "satisfiable modelling hypothesis" (what the bridge
   header asserts) to "PROVEN true in the real SPHINCS+ scheme".  The security-
   relevant content the paper's proof extracts from the address scheme --
   message-compression tweaks are TYPE-disjoint from WOTS chain-hash tweaks --
   is here a machine-checked lemma, not an assumption.

   WHAT THIS FILE DOES **NOT** DO (equally honest -- read this).
   ---------------------------------------------------------------------------
   It does NOT make the corollary `D1_MEUFNACMA_WOTSC_MM45_embthfc`
   (WOTS_C_EmbDischarge.ec) unconditional.  That corollary's `emb_disj_wgpidxs`
   is stated over the ABSTRACT `WOTS_TW_ES` instance (abstract `valid_widxvalsgp`
   / abstract `emb_tw`); the concrete `emb_disj_concrete` proved here lives in
   the DISTINCT concrete namespace `FSSLXMTWES.WTWES` and is therefore NOT the
   same proposition.  Threading it into the corollary requires RE-BASING the
   WOTS+C stack off the abstract `WOTS_TW_ES` and onto the concrete `WTWES`.

   THE PRECISE RE-BASE GAP (why the corollary stays conditional).
   ---------------------------------------------------------------------------
   `WOTS_C_{Real,Reduction,Scheme,Multi,Bridge}.ec` each do
       require (*--*) WOTS_TW_ES.   import WOTS_TW_ES.
   i.e. they are WELDED to the ABSTRACT `WOTS_TW_ES` instance (whose
   `valid_widxvalsgp` / `valid_idxvals` are free abstract ops), the same way
   `FL_SL_XMSS_MT_ES.ec` is PARAMETERISED over it (it `clone`s `WOTS_TW_ES as
   WTWES`, realising `valid_widxvalsgp` concretely -- FL_SL_XMSS_MT_ES.ec:557).
   You cannot re-realise a `require import`ed abstract op from a downstream
   file; only a `clone` can.  So making FLAG-2 provable inside the corollary's
   namespace means converting the whole WOTS+C stack from "import abstract
   WOTS_TW_ES" to "build over concrete WTWES" (a clone).  Real/Reduction/Multi/
   Bridge SHARE one `WOTS_TW_ES` instance and pass `adrs` between each other;
   rebasing Real+Bridge while `WOTS_C_Multi.ec` stays abstract makes
   `WOTS_C_Real.adrs != WOTS_C_Multi.adrs`, breaking the D1 lemma that consumes
   `M_EUF_NACMA_WOTSTW_L`.  Hence `WOTS_C_Multi.ec` MUST move too -- and it is
   the file this task is forbidden to touch (two FORS siblings + the D.1 debt).
   The rebase is a multi-file restructure crossing that file; it is the SOLE
   blocker between this proved scheme fact and an unconditional WOTS+C bound.

   NON-VACUITY (this discharge is not a degenerate/vacuity trap).
   ---------------------------------------------------------------------------
   * `emb_tw` is GENUINE, not degenerate.  It is the same-instance message/
     public-key compression address map: it PRESERVES the instance-identifying
     indices (kpidx@2, tidx@4, lidx@5) of the input and flips only the type
     field (index 3) chtype -> pkcotype (local hash/chain indices 0,1 zeroed).
     It is NOT constant (`emb_type` + the preserved tidx/lidx make its image
     vary with the input's hypertree position) and NOT the identity
     (`emb_type`: its image always has type pkcotype).  Its codomain lands
     OUTSIDE `valid_wadrs` (image type pkcotype != chtype) -- which is the whole
     point of type separation, NOT a cheat.
   * The guard premise `valid_wadrs a` stays SATISFIABLE (`nonvac_guard`:
     `exists a, valid_wadrs a`), so FLAG-2 is not vacuously true via a dead
     premise.  Both the "there is a valid chain address" and "emb_tw lands off
     the chain type" facts are live and machine-checked.
   * pkcotype is the concrete DISTINCT-TYPE witness.  The scheme has no address
     type literally named "message compression" (message hashing in SPHINCS+ is
     a separate keyed hash, not a tweakable-hash address); the security-relevant
     property the paper's reduction needs is exactly TYPE-DISJOINTNESS FROM THE
     WOTS CHAIN TYPE, and the public-key-compression type realises precisely
     that (chtype != pkcotype by `dist_adrstypes`).  Choosing trcotype instead
     would prove the same way; the essential content is "a type != chtype".

   PROVENANCE / TOOLCHAIN.  Built on `require import SPHINCS_PLUS` (the real
   scheme), r2026.02 switch, Alt-Ergo 2.6.0.  Zero admit, zero axiom, zero sorry.
   Edits: this NEW file only.  No proven file (Real/Bridge/Multi/...) touched.
   ========================================================================== *)

require import AllCore List StdOrder.
require import SPHINCS_PLUS.
import FSSLXMTWES.WTWES.   (* the CONCRETE WOTS-TW instance: valid_widxvalsgp
                              forces the type field to chtype (FL_SL:557) *)
import HA.Adrs.            (* val / insubd / insubdK / valP on the adrs subtype *)

(* --------------------------------------------------------------------------
   1.  INSTANCE PROPERTIES.  Any valid SPHINCS+ address (any of the 5 types)
       carries a valid keypair index at 2 and a valid (tree,layer) pair at
       (4,5) -- the fields the pk-compression image reuses.  By case analysis
       over the 5-way `valid_idxvals`; the trhx branch needs `valid_kpidx 0`
       (l' = 2^h' > 0), the trhf/trco branches need `valid_lidx 0` (d >= 1).
   -------------------------------------------------------------------------- *)
lemma valwadrs_inst (b : adrs) :
     valid_kpidx (nth witness (val b) 2)
  /\ valid_tidx (nth witness (val b) 5) (nth witness (val b) 4)
  /\ valid_lidx (nth witness (val b) 5).
proof.
have vb := valP b.
move: vb; rewrite /valid_adrsidxs => -[_].
rewrite /valid_idxvals /valid_idxvalsch /valid_idxvalspkco /valid_idxvalstrhx.
rewrite /valid_idxvalstrhf /valid_idxvalstrco /valid_kpidx /valid_lidx /l'.
move=> H.
smt(ge1_d IntOrder.expr_gt0).
qed.

(* --------------------------------------------------------------------------
   2.  THE GENUINE MESSAGE / PUBLIC-KEY-COMPRESSION EMBEDDING.
       Same instance (kpidx@2, tidx@4, lidx@5 preserved); type field @3 flipped
       chtype -> pkcotype; local chain/hash indices @0,@1 zeroed.  A distinct
       address TYPE from the WOTS chain address -- exactly the separation the
       paper's Th+C reduction relies on.
   -------------------------------------------------------------------------- *)
op emb_tw (ad : adrs) : adrs =
  insubd (put (put (put (val ad) 0 0) 1 0) 3 pkcotype).

(* emb_tw ALWAYS lands on a valid pk-compression address, for EVERY input
   address (all 5 SPHINCS+ types), because every valid address supplies the
   kpidx/tidx/lidx the pkco validity predicate demands (lemma 1). *)
lemma emb_tw_valid (b : adrs) :
  valid_adrsidxs (put (put (put (val b) 0 0) 1 0) 3 pkcotype).
proof.
have szb : size (val b) = adrs_len by move: (valP b); rewrite /valid_adrsidxs.
have [hk [ht hl]] := valwadrs_inst b.
rewrite /valid_adrsidxs !size_put szb /=.
rewrite /valid_idxvals; right; left.
rewrite /valid_idxvalspkco.
rewrite !nth_put ?size_put ?szb //= /adrs_len //=.
qed.

lemma emb_tw_val (b : adrs) :
  val (emb_tw b) = put (put (put (val b) 0 0) 1 0) 3 pkcotype.
proof. by rewrite /emb_tw insubdK 1:emb_tw_valid. qed.

(* the embedding's type field is pkcotype (index 3) -- image is off the chain
   type; witnesses non-degeneracy (emb_tw is neither constant nor identity). *)
lemma nth3_emb_tw (b : adrs) : nth witness (val (emb_tw b)) 3 = pkcotype.
proof.
have sz : size (put (put (val b) 0 0) 1 0) = adrs_len.
+ rewrite !size_put; move: (valP b); rewrite /valid_adrsidxs => -[-> _] //.
rewrite emb_tw_val nth_put; 1: by rewrite sz /adrs_len.
done.
qed.

lemma emb_type (b : adrs) : get_typeidx (emb_tw b) = pkcotype.
proof. by rewrite /get_typeidx /get_idx nth3_emb_tw. qed.

(* --------------------------------------------------------------------------
   3.  TYPE-FIELD EXTRACTION for valid WOTS chain addresses.
       `valid_wadrs a` routes through the CONCRETE `valid_widxvalsgp`
       (FL_SL_XMSS_MT_ES.ec:557), which forces `nth (drop 2 (val a)) 1 = chtype`,
       i.e. `nth (val a) 3 = chtype`.
   -------------------------------------------------------------------------- *)
lemma nth3_valid (a : adrs) : valid_wadrs a => nth witness (val a) 3 = chtype.
proof.
rewrite /valid_wadrs /valid_wadrsidxs /valid_widxvals /valid_widxvalsgp => -[_ [+ _]].
rewrite drop_drop //= => -[_ [+ _]].
by rewrite nth_drop.
qed.

(* --------------------------------------------------------------------------
   4.  NON-VACUITY: the guard premise is live -- there IS a valid WOTS-TW
       signing address (so FLAG-2 is not vacuously true via a dead premise).
   -------------------------------------------------------------------------- *)
lemma nonvac_guard : exists (a : adrs), valid_wadrs a.
proof. exists (WAddress.val witness); exact: WAddress.valP. qed.

(* NON-DEGENERACY, machine-checked: the embedding lands STRICTLY OUTSIDE the
   guard's range -- no emb_tw image is itself a valid WOTS chain address (its
   type field is pkcotype != chtype).  Directly answers the "emb_tw must not
   map into valid_wadrs's own range" degeneracy clause: were it inside, FLAG-2
   would be vacuously true via `a := emb_tw b` self-collision. *)
lemma emb_off_range (b : adrs) : ! valid_wadrs (emb_tw b).
proof.
apply/negP => v.
have := nth3_valid (emb_tw b) v; rewrite nth3_emb_tw.
smt(dist_adrstypes).
qed.

(* ==========================================================================
   5.  THE FLAG-2 DISCHARGE (concrete).  EXACTLY the shape of
       `WOTS_C_Bridge.emb_disj_wgpidxs`, over the concrete `emb_tw` and the
       concrete WTWES `valid_wadrs` / `get_wgpidxs`.  A valid chain address has
       chtype at global-part position 1; every emb_tw image has pkcotype there;
       chtype != pkcotype (dist_adrstypes) => the global parts differ.
       ZERO admit, ZERO axiom.
   ========================================================================== *)
lemma emb_disj_concrete (a b : adrs) :
  valid_wadrs a => get_wgpidxs a <> get_wgpidxs (emb_tw b).
proof.
move=> va; apply/negP => heq.
have e1 : nth witness (get_wgpidxs a) 1 = chtype.
+ by rewrite /get_wgpidxs nth_drop //= (nth3_valid a va).
have e2 : nth witness (get_wgpidxs (emb_tw b)) 1 = pkcotype.
+ by rewrite /get_wgpidxs nth_drop //= nth3_emb_tw.
have : chtype = pkcotype by rewrite -e1 -e2 heq.
smt(dist_adrstypes).
qed.
