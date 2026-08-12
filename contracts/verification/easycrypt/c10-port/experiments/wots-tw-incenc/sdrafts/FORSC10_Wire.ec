(* ==========================================================================
   FORSC10_Wire.ec  --  THE VIRTUAL -> WIRE FORS+C BRIDGE, MECHANIZED.

   WHY THIS FILE EXISTS.
   Everything downstream of FORS in this port (FxChain.ec:242, GprocFORSC10.ec:307,
   RtopCSoundness.ec:272/432, SphincsC10CapstoneWired.ec) verifies a FORS+C
   signature by calling  FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW  (FORS_ES.ec:1629).
   That procedure is the paper-2022/778 SECURITY-ANALYSIS object: the VIRTUAL
   k-full-tree FORS+C.  Its signature type is  sigFORSTW = k pairs
   (dgstblock * apFORSTW)  (FORS_ES.ec:183-191, apFORSTW a size-`a` list), and it
   rebuilds ALL k roots by  val_ap_trh  with NO last-tree special case
   (FORS_ES.ec:1640-1657).

   The DEPLOYED crate ships the paper CONSTRUCTION, which is a different object:
     * /home/nicola/repos/PQSigner_OS/sphincs-c10/src/params.rs:63-73 --
         SIG_FORS_SECRETS = K * N   but   SIG_FORS_AUTH = (K-1) * A * N
         ("The last tree is forced-zero and emits only its secret (the root),
           so it has no authentication path.")
     * signer  hypertree.rs:223-228 --
         last_root  = fors::compute_fors_root(seed, sk_seed, ht_idx, K-1);
         fors_secrets[K-1] = last_root;                       (* goes on the WIRE *)
         fors_roots[K-1]   = th(seed, adrs(h=0,i=0,tree=K-1), pad16(last_root));
     * verifier hypertree.rs:412-414 --
         fors_roots[K-1]   = th(seed, adrs(h=0,i=0,tree=K-1), pad16(fors_secrets[K-1]));
     * verifier hypertree.rs:373-376 -- the +C forced-zero constraint IS enforced:
         if fors_indices[K - 1] != 0 { return false }

   So the deployed K-th "root" is ONE application of the LEAF hash `f` to the wire
   value -- it is NOT the climbed Merkle root the model computes.  A deployed
   forgery therefore carries no last-tree authentication path, and its K-th root is
   a different function of a differently shaped input.  This file makes that
   relation EXACT and machine-checked instead of prose.

   WHAT IS PROVEN HERE (all 0-admit, no new axiom):
     (1) `pkfromsig_cf` -- a CLOSED FORM for the model's reconstruction procedure.
         This is the anchor: everything below is about `virt_pkFORS`, and (1) says
         `virt_pkFORS` IS what FL_FORS_ES.pkFORS_from_sigFORSTW computes, with
         probability 1.  Without it the ops below would be my ops, not the model's.
     (2) The WIRE object (`wire_root`, `wire_pkFORS`, `wire_verify`), transcribed
         from the crate lines cited above.
     (3) `wire_virt_prefix` -- on trees 0 .. k-2 the two reconstructions are
         POINTWISE IDENTICAL, for ANY filler auth path.  (The bridge is not
         blocked there.)
     (4) `wire_virt_last` -- THE GAP, exactly: under the +C forced-zero side
         condition, the model's k-th root is the a-level CLIMB of the wire's
         k-th root:
             virt_root .. (k-1) = val_ap_trh ps ad aplast 0 (wire_root .. (k-1)) (k-1)
         i.e. the wire's k-th root is precisely the model's k-th LEAF.
     (5) `bridge_pkFORS_sufficient` / `bridge_verify_sufficient` -- the CONDITIONAL
         bridge: IF that climb is the identity on that leaf, THEN wire and model
         reconstruct the SAME pkFORS and wire-acceptance transfers to
         model-acceptance.  This is the mechanized form of paper 2022/778 §4.1.1
         ("One can (virtually) imagine that all k trees exist ...", txt:543-546).
     (6) `psi_wire_root` / `psi_wire_pkFORS` -- the UNCONDITIONAL model -> wire
         direction: from any model signature one can compute a wire signature, and
         then the wire root vector is the model root vector with `f` post-composed
         on the LAST component only.  This is the precise algebraic statement of
         the delta and needs no hypothesis.
     (7) `splice_*` (SECTION 7) -- the FORGERY-TRANSFER core of a reduction that
         DOES go the useful way (wire -> model).  A model signature reveals ALL k
         roots (each tree carries secret + auth path), so a reduction that makes ONE
         setup query can compute the wire public key; and `splice_root_last_portable`
         proves the saved last-tree opening is MESSAGE-INDEPENDENT across any two
         +C-forced-zero messages, so it can be spliced into a wire forgery to yield
         a MODEL forgery.  `splice_pkFORS_transfer` is that step, machine-checked.
     (8) `prefix_locator` (SECTION 8) -- at the concrete `FTWES.g`, every
         non-coverage forgery has an UNCOVERED tree among 0 .. k-2.  So the ITSR
         hardness never has to be charged to the last tree -- the one tree where
         wire and model differ.

   WHAT IS **NOT** PROVEN, AND WHY (the honest residual -- read before citing):
     * The hypothesis of (5) is NOT a theorem of the closure.  `thfc`
       (SPHINCS_PLUS.ec:434) is declared with ZERO axioms, and `f = thfc (8*n)`,
       `trh = thfc (8*n*2)` (FORS_ES.ec:455/591) inherit that; no lemma anywhere in
       the closure gives `val_ap_trh` a fixed point.  So the naive SAME-KEY embedding
       of a wire signature into a model signature is NOT DERIVABLE.  (It is also not
       refutable from the closure alone -- `thfc := const` satisfies every axiom and
       makes it hold.  The correct claim is NON-DERIVABILITY, not falsity.)
     * NO PROBABILITY TRANSFER IS PROVEN HERE.  Precisely (this sentence was
       corrected 2026-07-25 after external adversarial review found the earlier
       wording over-claimed): `psi_wire_pkFORS` proves that the canonical
       componentwise model->wire transform changes the last input of `trco` from
       R_{k-1} to f(R_{k-1}).  Consequently this file establishes neither a
       same-public-key signature embedding nor an elementwise transformation
       computable from the COMPRESSED model pkFORS alone.  It does NOT rule out
       black-box reductions that use signing-oracle openings, selective embedding or
       guessing, or a `trco`-collision branch -- indeed SECTION 7 mechanizes the
       forgery-transfer core of exactly such a reduction.  WHERE THE OBSTRUCTION
       ACTUALLY IS (both external reviewers converged on this; it is NOT the pk
       mismatch):
         (i)  SINGLE-INSTANCE: no obstruction.  The reduction burns one signing
              query, reconstructs every R_i by `virt_root`, presents
              pkFORS_W, and simulates exactly via `psi` -- exactly because the
              conditioned oracle forces widx (k-1) = 0 on EVERY query, so the
              dropped last pair is always a leaf-0 opening available for splicing
              (`splice_root_last_portable`).  Cost: one burned-message freshness
              term (the wire adversary's view is independent of that message).
         (ii) MULTI-INSTANCE (Gproc, GprocFORSC10.ec:186/301) -- THE FIRST REAL
              OBSTRUCTION.  The public key is the whole POOL of COMPRESSED pkFORS
              values and routing is by `edivz (Index.val idx) l'` with `idx` from
              `mco mk m`, `mk` sampled INSIDE the oracle.  The reduction can compute
              neither the wire entry of an instance no query has routed to, nor
              steer routing -- so it cannot even PRESENT the wire public key without
              a coupon-collector query blow-up or an instance-guessing factor.
        (iii) COMPOSED SCHEME -- THE SECOND, HARDER OBSTRUCTION.  The hypertree
              WOTS-signs the pkFORS VALUE, so a model signature authenticates
              trco(..,R_{k-1}) and cannot be repointed to trco(..,f R_{k-1}).  No
              setup-query trick reaches this layer.
         (iv) EXTRACTION IS NOT PURE EUF <= EUF.  The forgery branch yields
              model-forgery OR a `trco` collision (`trco_case`) OR a collision on
              the last climb (`f`/`trh`), so a wire bound inherits hash terms.
     * THE ITSR LEG.  Honest scope: what is proven (predC_widx / g_widx /
       prefix_locator) is that the message->index map and the +C forced-zero
       predicate are the SAME op on both sides, so the ITSRC10 GAME SCHEMA and its
       coverage predicate are reusable unchanged in a wire-specific re-derivation,
       and the last tree never carries the coverage hardness.  It is NOT proven that
       the concrete wire and model ITSRC10 probability TERMS are equal: the wire
       reduction adversary and its key/signing simulation still have to be rebuilt.
       (Earlier wording said "the ITSR obligation is UNCHANGED" -- corrected.)
     * The last-tree hash leg is NOT claimed to be "strictly easier" (an earlier
       version did claim that; withdrawn).  The wire verifier has no
       adversary-supplied last auth path, so a wire-specific proof has no last-path
       `trh`-TCR subcase -- but that is an absence of a subcase, not a proved
       assumption-level or quantitative ordering.
     * ADDRESS / BYTE CORRESPONDENCE IS ASSUMED, NOT PROVED (as everywhere else in
       this port): the crate packs (layer, tree=ht_idx, type, keypair=K-1, h, i)
       (address.rs) and pads each 16-byte value to 32, while the model flattens
       (tree i, leaf idx) into `set_thtbidx ad 0 (i*t+idx)` over abstract `dgst`.
       The arities line up (`th`/`th_pair`/`th_multi` <-> `f`/`trh`/`trco` at
       8n / 8n*2 / 8n*k); byte-identity is NOT mechanized.  Likewise the crate's
       LSB-up `read_bits_le` index extraction (fors.rs:19-47) is matched to the
       model's `bs2int (rev (chunk a ..))` only by the port's standing bit-order
       abstraction.

     * ** FINDING (2026-07-25) -- THE WRAP TWEAK IS NOT DOMAIN-SEPARATED. **
       Flagged INDEPENDENTLY by both external reviewers and then verified by me
       directly against the crate.  The wrap address at hypertree.rs:226-227 (signer)
       and :412 (verifier) is
           make_adrs(0, ht_idx, ADRS_FORS_TREE, K-1, 0, 0, 0)
       and the leaf address inside compute_fors_root at j = 0, tree_idx = K-1
       (fors.rs:151) is
           make_adrs(0, ht_idx, ADRS_FORS_TREE, tree_idx, 0, 0, j)
       -- with tree_idx = K-1 and j = 0 these are the SAME 32 bytes.  So the crate
       evaluates `th` at ONE (seed, ADRS) on TWO different inputs: the leaf-0 SECRET
       of the last FORS tree, and that tree's ROOT.  The mechanized half of this is
       `wire_last_is_virt_leaf`: the wire's k-th root is `f` at the model's k-th
       LEAF address.  CLASSIFICATION (both reviewers, and I concur): a PROOF red
       flag, not a demonstrated attack -- there is no known way to exploit it, but
       the multi-target tweakable-hash reductions (SM-DT-TCR / OpenPRE) index their
       targets BY TWEAK, so a wire-shape re-derivation has two distinct targets at
       one tweak and cannot reuse the address-uniqueness discipline unmodified.
       This is the same class of side condition this port already fights with
       elsewhere (the emb_tw disjointness/uniqueness premises).  A cleaner design
       would wrap at the last tree's ROOT address (h = a) instead of its leaf-0
       address.
     * DISTRIBUTIONAL RESIDUAL, named explicitly: the crate's wire value for the
       last tree is  compute_fors_root(...)  -- a `th_pair` output -- whereas the
       model's NPRF keygen samples every cube element uniformly from `ddgstblock`.
       Note it IS exactly the model's R_{k-1} (the virtual last tree's Merkle root),
       which is what makes SECTION 7's transform faithful; but the verification
       equation, not keygen, is what is proven here.  Closing keygen needs a
       derivation/PRF hop or an explicit idealization disclosure.

   PLACEMENT.  This is a LEAF file: it `require`s the chain and NOTHING requires it.
   No mid-chain `.eco` can go stale because of it (hazard T2 does not apply), so
   `bash ec-certify.sh drafts/FORSC10_Wire.ec` is a sound gate for it.
   ========================================================================== *)

require import AllCore List Distr StdBigop StdOrder IntDiv.
require import BinaryTrees MerkleTrees.
require import BitEncoding.
import BS2Int BitChunking.
require import SPHINCS_PLUS.
import IntOrder.

(* ==========================================================================
   SECTION 1 -- THE MODEL (VIRTUAL) RECONSTRUCTION, IN CLOSED FORM.

   Transcription of FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW (FORS_ES.ec:1629-1663),
   then PROVEN equal to it (pkfromsig_cf).
   ========================================================================== *)

(* The leaf index of tree i, read off the FORS message digest.
   Mirrors  bsidx <- take a (drop (a * size roots) (val m)); idx <- bs2int (rev bsidx)
   (FORS_ES.ec:1638-1639). *)
op widx (m : FTWES.msgFORSTW) (i : int) : int =
  bs2int (rev (take a (drop (a * i) (FTWES.BLKAL.val m)))).

(* The model's per-tree root (FORS_ES.ec:1641-1655): hash the secret at the LEAF
   address, then climb the a-level authentication path. *)
op virt_root (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
             (sig : FTWES.sigFORSTW) (i : int) : dgstblock =
  FTWES.val_ap_trh ps ad (nth witness (FTWES.DBAPKL.val sig) i).`2 (widx m i)
    (f ps (set_thtbidx ad 0 (i * t + widx m i))
         (DigestBlock.val (nth witness (FTWES.DBAPKL.val sig) i).`1))
    i.

(* The model's FORS public key (FORS_ES.ec:1658-1661). *)
op virt_pkFORS (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
               (sig : FTWES.sigFORSTW) : FTWES.pkFORS =
  trco ps (set_kpidx (set_typeidx ad trcotype) (FTWES.get_kpidx ad))
       (flatten (map DigestBlock.val (mkseq (virt_root ps ad m sig) k))).

(* THE ANCHOR.  The model's reconstruction PROCEDURE computes exactly virt_pkFORS,
   with probability 1.  Every claim below about `virt_pkFORS` is therefore a claim
   about the object FxChain/GprocFORSC10/RtopCSoundness actually verify against. *)
lemma pkfromsig_cf (sigv : FTWES.sigFORSTW) (mv : FTWES.msgFORSTW)
                   (psv : pseed) (adv : adrs) :
  phoare[ FTWES.FL_FORS_ES.pkFORS_from_sigFORSTW :
          arg = (sigv, mv, psv, adv)
          ==> res = virt_pkFORS psv adv mv sigv ] = 1%r.
proof.
proc.
wp.
while (sig = sigv /\ m = mv /\ ps = psv /\ ad = adv /\
       0 <= size roots <= k /\
       roots = mkseq (virt_root psv adv mv sigv) (size roots))
      (k - size roots).
+ move => z; wp; skip => /> &hr hge hle heq hlt.
  rewrite !size_rcons.
  do !split; 1,2,4: smt().
  rewrite (mkseqS (virt_root psv adv mv sigv) (size roots{hr})) 1:hge.
  by rewrite -heq; congr.
wp; skip => />.
split; 1: by split; [smt(ge1_k) | rewrite mkseq0].
move => roots0; split; 1: smt().
move => hnlt hge hle heq.
have hsz : size roots0 = k by smt().
by rewrite /virt_pkFORS heq hsz.
qed.


(* ==========================================================================
   SECTION 2 -- THE WIRE OBJECT (the DEPLOYED shape).

   A wire FORS+C signature is  (secs, aps)  with  size secs = k  and
   size aps = k - 1  -- exactly params.rs:63-73 (K secrets, (K-1) auth paths).
   Kept as plain lists with explicit size side conditions rather than a Subtype,
   so that every lemma below shows its size hypotheses instead of hiding them.

   ADDRESS-ENCODING NOTE (a modelling correspondence inherited from the port, NOT
   introduced here).  The crate addresses a FORS leaf as
     make_adrs(.., ADRS_FORS_TREE, tree_idx, 0 /*h*/, leaf /*i*/)
   while the model flattens (tree i, leaf idx) into one height-0 breadth index,
     set_thtbidx ad 0 (i * t + idx)     (FORS_ES.ec:380, :1653).
   The crate's last-tree leaf address is (tree = K-1, h = 0, i = 0), which is the
   model's  set_thtbidx ad 0 ((k-1) * t + 0).  That correspondence is the port's
   standing address abstraction and is assumed here as it is everywhere else in
   the chain.
   ========================================================================== *)

(* The wire per-tree root.  Trees 0..k-2: identical to the model.  Tree k-1:
   ONE application of the leaf hash `f` at the forced leaf 0 of tree k-1 --
   the transcription of hypertree.rs:412-414 (and of the signer's
   hypertree.rs:227-228, which writes the same value). *)
op wire_root (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
             (secs : dgstblock list) (aps : FTWES.apFORSTW list) (i : int) : dgstblock =
  if i < k - 1
  then FTWES.val_ap_trh ps ad (nth witness aps i) (widx m i)
         (f ps (set_thtbidx ad 0 (i * t + widx m i))
              (DigestBlock.val (nth witness secs i)))
         i
  else f ps (set_thtbidx ad 0 ((k - 1) * t + 0))
            (DigestBlock.val (nth witness secs (k - 1))).

(* The wire FORS public key -- same trco compression over the k roots
   (crate: fors::compute_fors_pk = th_multi over roots[0..K), fors.rs:262-266). *)
op wire_pkFORS (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
               (secs : dgstblock list) (aps : FTWES.apFORSTW list) : FTWES.pkFORS =
  trco ps (set_kpidx (set_typeidx ad trcotype) (FTWES.get_kpidx ad))
       (flatten (map DigestBlock.val (mkseq (wire_root ps ad m secs aps) k))).

(* The wire verify.  The `widx m (k-1) = 0` conjunct is hypertree.rs:373-376
   (`if fors_indices[K-1] != 0 { return false }`) -- the +C forced-zero check IS
   enforced on the deployed verification path; it is not assumed here for free. *)
op wire_wf (secs : dgstblock list) (aps : FTWES.apFORSTW list) : bool =
  size secs = k /\ size aps = k - 1.

op wire_verify (pk : FTWES.pkFORS * pseed * adrs) (m : FTWES.msgFORSTW)
               (secs : dgstblock list) (aps : FTWES.apFORSTW list) : bool =
  wire_wf secs aps /\ widx m (k - 1) = 0
  /\ wire_pkFORS pk.`2 pk.`3 m secs aps = pk.`1.

(* The model verify, at the closed form (FORS_ES.ec:1665-1677). *)
op virt_verify (pk : FTWES.pkFORS * pseed * adrs) (m : FTWES.msgFORSTW)
               (sig : FTWES.sigFORSTW) : bool =
  virt_pkFORS pk.`2 pk.`3 m sig = pk.`1.


(* ==========================================================================
   SECTION 3 -- THE EMBEDDING, AND THE EXACT STRUCTURAL THEOREMS.

   `emb_wire secs aps aplast` is the CANONICAL COMPONENT-PRESERVING shape of a
   wire->model map: keep the k secrets, keep the k-1 auth paths, and supply SOME
   last-tree auth path `aplast` (which the wire format does not carry).  It is not
   the only conceivable map -- SECTION 7 uses a different one (`splice`), which is
   the one a reduction actually wants.
   ========================================================================== *)

op emb_wire (secs : dgstblock list) (aps : FTWES.apFORSTW list)
            (aplast : FTWES.apFORSTW) : FTWES.sigFORSTW =
  FTWES.DBAPKL.insubd
    (mkseq (fun (i : int) =>
              (nth witness secs i,
               if i < k - 1 then nth witness aps i else aplast)) k).

lemma emb_wire_val (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                   (aplast : FTWES.apFORSTW) :
  FTWES.DBAPKL.val (emb_wire secs aps aplast)
  = mkseq (fun (i : int) =>
             (nth witness secs i,
              if i < k - 1 then nth witness aps i else aplast)) k.
proof.
rewrite /emb_wire FTWES.DBAPKL.insubdK //.
by rewrite /P size_mkseq; smt(ge1_k).
qed.

(* (3)  PREFIX AGREEMENT.  On trees 0 .. k-2 the wire and the model reconstruct
   the SAME root, for ANY filler auth path.  The bridge is NOT blocked here. *)
lemma wire_virt_prefix (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                       (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                       (aplast : FTWES.apFORSTW) (i : int) :
  0 <= i < k - 1 =>
  virt_root ps ad m (emb_wire secs aps aplast) i = wire_root ps ad m secs aps i.
proof.
move => [hge hlt].
rewrite /virt_root /wire_root emb_wire_val nth_mkseq /=; 1: smt(ge1_k).
by rewrite hlt.
qed.

(* (4)  THE GAP, EXACTLY.  Under the +C forced-zero side condition the model's
   k-th root is the a-level CLIMB of the wire's k-th root; equivalently the wire's
   k-th root is precisely the model's k-th LEAF.  This single equation is the whole
   virtual-vs-wire delta. *)
lemma wire_virt_last (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                     (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                     (aplast : FTWES.apFORSTW) :
  widx m (k - 1) = 0 =>
  virt_root ps ad m (emb_wire secs aps aplast) (k - 1)
  = FTWES.val_ap_trh ps ad aplast 0 (wire_root ps ad m secs aps (k - 1)) (k - 1).
proof.
move => hz.
rewrite /virt_root /wire_root emb_wire_val nth_mkseq /=; 1: smt(ge1_k).
by rewrite hz /=.
qed.

(* The same fact stated as "the wire's last root IS the model's last leaf". *)
lemma wire_last_is_virt_leaf (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                             (secs : dgstblock list) (aps : FTWES.apFORSTW list) :
  widx m (k - 1) = 0 =>
  wire_root ps ad m secs aps (k - 1)
  = f ps (set_thtbidx ad 0 ((k - 1) * t + widx m (k - 1)))
         (DigestBlock.val (nth witness secs (k - 1))).
proof. by move => hz; rewrite /wire_root hz. qed.


(* ==========================================================================
   SECTION 4 -- THE CONDITIONAL BRIDGE.

   `clim_id` is the hypothesis the bridge needs and the closure does NOT supply:
   that the supplied last-tree authentication path climbs the wire's k-th root to
   itself.  It is the mechanized content of paper 2022/778 §4.1.1's
   "One can (virtually) imagine that all k trees exist, where in the last tree we
   always open the same leaf" (paper-nist-pqc2022.txt:543-546).

   IT IS NOT DERIVABLE.  `thfc` (SPHINCS_PLUS.ec:434) is declared with no axioms and
   `f`/`trh` are its instances; nothing in the closure gives `val_ap_trh` a fixed
   point.  It is likewise NOT refutable from the closure (thfc := const validates
   it).  See the header residual.
   ========================================================================== *)

op clim_id (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
           (secs : dgstblock list) (aps : FTWES.apFORSTW list)
           (aplast : FTWES.apFORSTW) : bool =
  FTWES.val_ap_trh ps ad aplast 0 (wire_root ps ad m secs aps (k - 1)) (k - 1)
  = wire_root ps ad m secs aps (k - 1).

lemma bridge_roots_sufficient (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                              (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                              (aplast : FTWES.apFORSTW) (i : int) :
  widx m (k - 1) = 0 =>
  clim_id ps ad m secs aps aplast =>
  0 <= i < k =>
  virt_root ps ad m (emb_wire secs aps aplast) i = wire_root ps ad m secs aps i.
proof.
move => hz hcl [hge hlt].
case (i < k - 1) => hi; 1: by apply wire_virt_prefix.
have -> : i = k - 1 by smt().
by rewrite (wire_virt_last _ _ _ _ _ _ hz); apply hcl.
qed.

(* (5)  THE CONDITIONAL BRIDGE at the public key. *)
lemma bridge_pkFORS_sufficient (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                               (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                               (aplast : FTWES.apFORSTW) :
  widx m (k - 1) = 0 =>
  clim_id ps ad m secs aps aplast =>
  virt_pkFORS ps ad m (emb_wire secs aps aplast) = wire_pkFORS ps ad m secs aps.
proof.
move => hz hcl.
rewrite /virt_pkFORS /wire_pkFORS; do 3! congr.
apply eq_in_mkseq => i hi.
by apply (bridge_roots_sufficient _ _ _ _ _ _ _ hz hcl hi).
qed.

(* (5')  ... and the acceptance transfer that the bound would need: a WIRE
   forgery that verifies becomes a MODEL forgery that verifies, against the SAME
   public key -- CONDITIONAL on clim_id. *)
lemma bridge_verify_sufficient (pk : FTWES.pkFORS * pseed * adrs)
                               (m : FTWES.msgFORSTW)
                               (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                               (aplast : FTWES.apFORSTW) :
  clim_id pk.`2 pk.`3 m secs aps aplast =>
  wire_verify pk m secs aps =>
  virt_verify pk m (emb_wire secs aps aplast).
proof.
move => hcl [hwf [hz hpk]].
by rewrite /virt_verify (bridge_pkFORS_sufficient _ _ _ _ _ _ hz hcl).
qed.


(* ==========================================================================
   SECTION 5 -- THE MODEL -> WIRE DIRECTION (UNCONDITIONAL).

   Psi turns any model signature into a wire signature: drop the last auth path,
   and put the model's k-th ROOT into the k-th secret slot (this is exactly what
   the crate's signer does -- hypertree.rs:223-225 writes
   compute_fors_root(..) into fors_secrets[K-1]).

   The resulting theorem needs NO hypothesis and is the precise algebraic
   statement of the delta:  the wire root vector is the model root vector with `f`
   post-composed on the LAST component only.  Consequence, spelled out below in
   psi_wire_pkFORS: the two schemes' public keys are DIFFERENT functions of the
   same secret key, which is why no black-box reduction that only holds pkFORS_V
   can simulate the wire game.
   ========================================================================== *)

op psi_secs (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
            (sig : FTWES.sigFORSTW) : dgstblock list =
  mkseq (fun (i : int) =>
           if i < k - 1 then (nth witness (FTWES.DBAPKL.val sig) i).`1
                        else virt_root ps ad m sig (k - 1)) k.

op psi_aps (sig : FTWES.sigFORSTW) : FTWES.apFORSTW list =
  mkseq (fun (i : int) => (nth witness (FTWES.DBAPKL.val sig) i).`2) (k - 1).

lemma psi_wire_root (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                    (sig : FTWES.sigFORSTW) (i : int) :
  0 <= i < k =>
  wire_root ps ad m (psi_secs ps ad m sig) (psi_aps sig) i
  = if i < k - 1
    then virt_root ps ad m sig i
    else f ps (set_thtbidx ad 0 ((k - 1) * t + 0))
              (DigestBlock.val (virt_root ps ad m sig (k - 1))).
proof.
move => [hge hlt].
rewrite /wire_root /psi_secs /psi_aps.
case (i < k - 1) => hi.
+ rewrite !nth_mkseq /=; 1,2: smt().
  by rewrite hi /= /virt_root.
by rewrite nth_mkseq /=; smt(ge1_k).
qed.

(* THE SEPARATION, in one line: the wire public key is the model public key's
   root vector with `f` applied to the last root -- NOT the model public key.
   Reading:  pkFORS_W = trco (R_0 || .. || R_{k-2} || f R_{k-1})
             pkFORS_V = trco (R_0 || .. || R_{k-2} ||   R_{k-1}).
   These coincide only if `f` fixes R_{k-1} (or trco collides).  Nothing in the
   closure provides either. *)
lemma psi_wire_pkFORS (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                      (sig : FTWES.sigFORSTW) :
  wire_pkFORS ps ad m (psi_secs ps ad m sig) (psi_aps sig)
  = trco ps (set_kpidx (set_typeidx ad trcotype) (FTWES.get_kpidx ad))
         (flatten (map DigestBlock.val
            (mkseq (fun (i : int) =>
                      if i < k - 1
                      then virt_root ps ad m sig i
                      else f ps (set_thtbidx ad 0 ((k - 1) * t + 0))
                                (DigestBlock.val (virt_root ps ad m sig (k - 1)))) k))).
proof.
rewrite /wire_pkFORS; do 3! congr.
by apply eq_in_mkseq => i hi /=; apply psi_wire_root.
qed.


(* ==========================================================================
   SECTION 6 -- THE FORCED-ZERO LINK (the ITSR leg is UNCHANGED).

   `predC_fors` (FORS_C10.ec:197) is  (nth witness (g y) (k-1)).`3 = 0  and
   FTWES.g (FORS_ES.ec:421-424) is
     mkseq (fun i => (idx, i, bs2int (rev (nth witness (chunk a (val m)) i)))) k.
   The lemma below shows that predicate is LITERALLY the wire verifier's
   forced-zero check `widx m (k-1) = 0`  (= crate hypertree.rs:373-376 /
   fors.rs:126 / SPHINCsC10Asm.sol:86).

   WHY THIS MATTERS FOR THE RESIDUAL: the message->index map, the +C predicate and
   hence the ITSR target/covered structure are IDENTICAL between the wire scheme
   and the model scheme.  The wire/model delta is confined to the last-tree HASH
   leg.  So the re-derivation the residual calls for does not touch ITSRC10.
   ========================================================================== *)

lemma g_widx (m : FTWES.msgFORSTW) (ix : index) (i : int) :
  0 <= i < k =>
  (nth witness (FTWES.g (m, ix)) i).`3 = widx m i.
proof.
move => [hge hlt].
rewrite /FTWES.g /= nth_mkseq //= /widx; do 2! congr.
rewrite /chunk nth_mkseq //=.
by rewrite FTWES.BLKAL.valP mulzK; smt(ge1_a).
qed.

lemma predC_widx (m : FTWES.msgFORSTW) (ix : index) :
  (nth witness (FTWES.g (m, ix)) (k - 1)).`3 = 0 <=> widx m (k - 1) = 0.
proof. by rewrite (g_widx m ix (k - 1)); smt(ge1_k). qed.


(* ==========================================================================
   SECTION 7 -- THE FORGERY-TRANSFER CORE OF A **WIRE -> MODEL** REDUCTION.

   ADDED 2026-07-25 after external adversarial review (GPT-5.6) showed that the
   header's earlier "no black-box reduction exists" was WRONG, by exhibiting the
   reduction shape this section mechanizes.  The observation that unlocks it:
   a MODEL signature reveals ALL k roots (each tree carries secret + auth path, so
   `virt_root` is publicly computable from it).  A reduction can therefore

     1. make ONE setup query to its model signing oracle,
     2. compute every R_i by `virt_root`, hence compute
          pkFORS_W = trco(R_0 || .. || R_{k-2} || f R_{k-1})   (psi_wire_pkFORS),
     3. hand pkFORS_W to the wire adversary and answer its queries by `psi`
        (which is exactly what the crate's signer emits -- see the note in
        SECTION 5),
     4. on a wire forgery, either extract a `trco` collision (`trco_case`) or
        SPLICE the saved last-tree opening into the forged first k-1 components
        (`splice`) to obtain a MODEL forgery.

   Step 4's soundness rests on ONE fact, and it is the fact this section proves:
   the saved last-tree opening is MESSAGE-INDEPENDENT across +C messages
   (`splice_root_last_portable`) -- because the +C forced-zero constraint pins the
   last tree's opened leaf to 0 for EVERY valid message.  That is the mechanized
   content of the paper's "in the last tree we always open the same leaf".

   WHAT THIS SECTION DOES **NOT** DO: it is the transfer step only.  It is not a
   probability statement, it does not build the reduction module, and it does not
   address the three open obstructions listed in the header residual (setup-query
   freshness, multi-instance routing, and the full-SPHINCS hypertree binding).
   ========================================================================== *)

(* The reduction's map: the forged first k-1 (secret, auth path) pairs, plus a
   SAVED model last-tree opening. *)
op splice (secs : dgstblock list) (aps : FTWES.apFORSTW list)
          (lst : dgstblock * FTWES.apFORSTW) : FTWES.sigFORSTW =
  FTWES.DBAPKL.insubd
    (mkseq (fun (i : int) =>
              if i < k - 1 then (nth witness secs i, nth witness aps i) else lst) k).

lemma splice_val (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                 (lst : dgstblock * FTWES.apFORSTW) :
  FTWES.DBAPKL.val (splice secs aps lst)
  = mkseq (fun (i : int) =>
             if i < k - 1 then (nth witness secs i, nth witness aps i) else lst) k.
proof.
rewrite /splice FTWES.DBAPKL.insubdK //.
by rewrite /P size_mkseq; smt(ge1_k).
qed.

(* On trees 0..k-2 the spliced model signature reconstructs exactly the WIRE roots
   of the forgery -- nothing about the forgery's first k-1 trees is disturbed. *)
lemma splice_root_prefix (ps : pseed) (ad : adrs) (m : FTWES.msgFORSTW)
                         (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                         (lst : dgstblock * FTWES.apFORSTW) (i : int) :
  0 <= i < k - 1 =>
  virt_root ps ad m (splice secs aps lst) i = wire_root ps ad m secs aps i.
proof.
move => [hge hlt].
rewrite /virt_root /wire_root splice_val nth_mkseq /=; 1: smt(ge1_k).
by rewrite hlt.
qed.

(* THE PORTABILITY FACT.  The last-tree opening saved from a setup query on m0 is
   a valid opening for ANY other +C message m: both reconstructions coincide.
   This is why one setup query suffices, and it is the mechanized form of
   paper 2022/778 s4.1.1's "in the last tree we always open the same leaf". *)
lemma splice_root_last_portable (ps : pseed) (ad : adrs)
                                (m m0 : FTWES.msgFORSTW)
                                (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                                (sig0 : FTWES.sigFORSTW) :
  widx m  (k - 1) = 0 =>
  widx m0 (k - 1) = 0 =>
  virt_root ps ad m
    (splice secs aps (nth witness (FTWES.DBAPKL.val sig0) (k - 1))) (k - 1)
  = virt_root ps ad m0 sig0 (k - 1).
proof.
move => hz hz0.
rewrite /virt_root splice_val nth_mkseq /=; 1: smt(ge1_k).
by rewrite hz hz0 /=.
qed.

(* THE TRANSFER.  If the wire forgery's first k-1 roots agree with the honest
   ones (which is exactly what the non-collision branch of step 4 delivers), then
   the spliced model signature reconstructs the HONEST MODEL pkFORS -- i.e. it is
   a valid model forgery against the SAME model public key. *)
lemma splice_pkFORS_transfer (ps : pseed) (ad : adrs)
                             (m m0 : FTWES.msgFORSTW)
                             (secs : dgstblock list) (aps : FTWES.apFORSTW list)
                             (sig0 : FTWES.sigFORSTW) :
  widx m  (k - 1) = 0 =>
  widx m0 (k - 1) = 0 =>
  (forall (i : int), 0 <= i < k - 1 =>
     wire_root ps ad m secs aps i = virt_root ps ad m0 sig0 i) =>
  virt_pkFORS ps ad m
    (splice secs aps (nth witness (FTWES.DBAPKL.val sig0) (k - 1)))
  = virt_pkFORS ps ad m0 sig0.
proof.
move => hz hz0 hpre.
rewrite /virt_pkFORS; do 3! congr.
apply eq_in_mkseq => i hi.
case (i < k - 1) => hlt.
+ have h1 : 0 <= i < k - 1 by smt().
  by rewrite (splice_root_prefix ps ad m secs aps
                (nth witness (FTWES.DBAPKL.val sig0) (k - 1)) i h1) (hpre i h1).
have -> : i = k - 1 by smt().
by apply (splice_root_last_portable _ _ _ _ _ _ _ hz hz0).
qed.

(* The collision branch, made explicit.  (The proof is the trivial case split;
   the content is in naming the branch a reduction must discharge, so that it
   cannot be silently dropped.) *)
lemma trco_case (ps : pseed) (adr : adrs) (x y : dgst) :
  trco ps adr x = trco ps adr y =>
  x = y \/ (exists (u v : dgst), u <> v /\ trco ps adr u = trco ps adr v).
proof. by move => heq; case (x = y) => hxy; [left | right; exists x y]. qed.


(* ==========================================================================
   SECTION 8 -- THE PREFIX LOCATOR: the LAST tree never carries ITSR hardness.

   ADDED 2026-07-25 (route suggested by GPT-5.6 review).  Stated at the CONCRETE
   `FTWES.g` (FORS_ES.ec:421-424), which is what the C10 chain instantiates
   FORS_C10's abstract `g` with (GprocFORSC10.ec:140-146 realize clauses) -- the
   abstract axioms alone are too weak (they do not pin the tree label of the i-th
   tuple), so this is deliberately not stated abstractly.

   THE ARGUMENT.  Every +C-good digest's last tuple is (I, k-1, 0), and all k
   tuples of one digest share the instance coordinate I.  So if the forgery's LAST
   tuple is uncovered, no recorded target used instance I at all, and therefore the
   forgery's FIRST tuple is uncovered too.  Hence, for k >= 2, every non-coverage
   forgery has an uncovered tree among 0 .. k-2 -- the trees on which the wire and
   the model schemes are POINTWISE IDENTICAL (wire_virt_prefix).

   CONSEQUENCE for the residual: a wire-specific re-derivation never has to charge
   the coverage failure to the last tree, i.e. to the one tree where the two
   schemes differ.
   ========================================================================== *)

lemma ftw_size_g_loc (y : FTWES.msgFORSTW * index) : size (FTWES.g y) = k.
proof. by rewrite /FTWES.g /= size_mkseq; smt(ge1_k). qed.

(* The concrete g's i-th tuple: instance, tree LABEL i, and the digest's i-th
   leaf index.  (The abstract FORS_C10 axioms do not give the middle coordinate --
   which is exactly why this section is stated concretely.) *)
lemma g_nth (y : FTWES.msgFORSTW * index) (i : int) :
  0 <= i < k =>
  nth witness (FTWES.g y) i = (Index.val y.`2, i, widx y.`1 i).
proof.
move => hi.
have hc : nth witness (chunk a (FTWES.BLKAL.val y.`1)) i
        = take a (drop (a * i) (FTWES.BLKAL.val y.`1)).
+ rewrite /chunk nth_mkseq //=.
  by rewrite FTWES.BLKAL.valP mulzK; smt(ge1_a).
rewrite /FTWES.g /=.
rewrite nth_mkseq 1:hi /=.
by rewrite /widx hc.
qed.

(* If ANY recorded target shares the forgery's instance, the forgery's LAST tuple
   is covered -- because both digests' last tuples are (I, k-1, 0). *)
lemma last_tuple_covered (yf y : FTWES.msgFORSTW * index) :
  widx yf.`1 (k - 1) = 0 =>
  widx y.`1  (k - 1) = 0 =>
  Index.val y.`2 = Index.val yf.`2 =>
  nth witness (FTWES.g yf) (k - 1) \in FTWES.g y.
proof.
move => hzf hzq heqi.
have hk1 : 0 <= k - 1 < k by smt(ge1_k).
rewrite (g_nth yf (k - 1) hk1) hzf.
have -> : (Index.val yf.`2, k - 1, 0) = nth witness (FTWES.g y) (k - 1).
+ by rewrite (g_nth y (k - 1) hk1) hzq heqi.
by apply mem_nth; rewrite ftw_size_g_loc; smt(ge1_k).
qed.

(* Conversely, any tuple of the forgery that IS covered pins the covering target's
   instance to the forgery's instance (all tuples of one digest share it). *)
lemma covered_pins_instance (yf y : FTWES.msgFORSTW * index) (i : int) :
  0 <= i < k =>
  nth witness (FTWES.g yf) i \in FTWES.g y =>
  Index.val y.`2 = Index.val yf.`2.
proof.
move => hi.
rewrite (g_nth yf i hi) /FTWES.g /=.
by move => /mkseqP [j [hj heq]]; move: heq; smt().
qed.

(* THE PREFIX LOCATOR.  If SOME tuple of the (+C-good) forgery is uncovered by the
   (+C-good) recorded targets, then the tuple of one of the trees 0 .. k-2 is
   uncovered.  Requires 2 <= k (deployed C10 has k = 13). *)
lemma prefix_locator (yf : FTWES.msgFORSTW * index)
                     (ys : (FTWES.msgFORSTW * index) list) :
  2 <= k =>
  widx yf.`1 (k - 1) = 0 =>
  (forall (y : FTWES.msgFORSTW * index), y \in ys => widx y.`1 (k - 1) = 0) =>
  (exists (x : int * int * int),
     x \in FTWES.g yf /\ ! (x \in flatten (map FTWES.g ys))) =>
  (exists (i : int),
     0 <= i < k - 1 /\ ! (nth witness (FTWES.g yf) i \in flatten (map FTWES.g ys))).
proof.
move => hk hzf hzq [x [hxin hxout]].
case (nth witness (FTWES.g yf) 0 \in flatten (map FTWES.g ys)) => h0; last first.
+ by exists 0; smt(ge1_k).
(* tuple 0 covered => some recorded target shares the instance => the LAST tuple
   is covered too. *)
have hlast : nth witness (FTWES.g yf) (k - 1) \in flatten (map FTWES.g ys).
+ move: h0 => /flattenP [zs [hzs hin]].
  move: hzs => /mapP [y [hy hzeq]].
  apply/flattenP; exists (FTWES.g y); split; 1: by apply/mapP; exists y.
  apply (last_tuple_covered yf y hzf (hzq y hy)).
  apply (covered_pins_instance yf y 0); 1: smt(ge1_k).
  by move: hin; rewrite hzeq.
(* so the uncovered tuple x cannot be the last one; locate its index. *)
pose j := index x (FTWES.g yf).
have hnx : nth witness (FTWES.g yf) j = x by rewrite /j nth_index.
have hjr : 0 <= j < k.
+ rewrite /j; split; 1: exact index_ge0.
  by move => _; rewrite -(ftw_size_g_loc yf) index_mem hxin.
have hjne : j <> k - 1.
+ apply/negP => heq.
  by move: hxout; rewrite -hnx heq hlast.
exists j; split; 1: smt().
by rewrite hnx; exact hxout.
qed.
