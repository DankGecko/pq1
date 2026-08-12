(* ==========================================================================
   FORS_C_Tree.ec  --  The FORS+C tree-layer leg: a GAP CHARACTERIZATION of the
                       tie between FORS_C.ec's ABSTRACT tree-layer terms
                       (tree_openpre / tree_trh / tree_trco) and FORS_ES.ec's
                       CONCRETE tree-layer reduction advantages.

   ==========================================================================
   STATUS / SCOPE  (read this first -- honest framing).
   ==========================================================================
   This file is a CHARACTERIZATION ONLY.  It states NO formal tie lemma, by
   design, and it does not even `require FORS_ES` -- because, as the (G1-G4)
   analysis below establishes, there is NO sound, non-vacuous, typechecking tie
   lemma between a FORS+C forger and the EXISTING FORS_ES tree-reduction
   advantages that can be written tonight.  A faithful concrete tie is a
   multi-week +C-variant reduction PORT (scoped below), not a one-lemma
   instantiation.

   Contrast with the WOTS+C MM45 bridge (WOTS_C_Bridge.ec).  That leg connects
   two multi-instance games over the SAME concrete WOTS_TW_ES vocabulary and so
   could state a sound, typechecking, admit-terminated bridge lemma.  The
   FORS+C tree tie crosses FOUR coupled boundaries at once (below), and the
   decisive one -- (G1) -- is that the concrete FORS_ES tree reductions are
   HARD-WIRED to the counter-FREE message hash at three independent sites, so
   they are NOT black-box reusable for +C at all.

   WHY NO PLACEHOLDER LEMMA HERE.  An earlier draft of this file carried an
   "interface tie" lemma (`fors_c_tree_tie`) over three fresh abstract reals
   `treeC_openpre/treeC_trh/treeC_trco` with a `treeC_inv` hypothesis
   `FC.tree_openpre <= treeC_openpre /\ ...`.  It compiled admit-free, but it
   was INERT: those reals are undefined constants in the SAME logical status as
   FORS_C's own `tree_*`; the lemma proved only pure monotonicity
   (`A <= B => bound+A <= bound+B`) over two sets of undefined reals; it does
   not `require FORS_ES`, so it establishes NOTHING about the ES advantages; and
   `treeC_inv` is NOT +C-invariance (which would relate the +C tree layer to
   ES's concrete tree quantities -- it merely relates one undefined real to
   another).  Nor is it staging for later work: an `op` cannot be
   clone-substituted with a `Pr[...]` expression, so `treeC_openpre` can never
   be instantiated to the ES advantage -- the hooks are a dead end, not a
   scaffold.  Per the coordinator's standing constraint (no manufactured
   statement to look further-along), that lemma was REMOVED.  The honest
   deliverable is this characterization.

   ==========================================================================
   THE PRECISE STRUCTURAL GAP  (four coupled differences; (G1) is the crux).
   ==========================================================================
   Let  ES  = FV-SPHINCSPLUS-EC/proofs/FORS_ES.ec  (concrete multi-instance
   FORS-TW), and  FC = drafts/FORS_C.ec's `abstract theory FORSC` (the +C leg).
   The three concrete tree terms live in ES's four-term theorem
     `EUFCMA_MFORSTWESNPRF_OPRE`  (ES:3829, a `local lemma`):
        Pr[EUF_CMA_MFORSTWESNPRF(A,.)] <=
             Pr[MCO_ITSR.ITSR(R_ITSR_EUFCMA(A),.)]                         (msg-hash)
           + Pr[F_OpenPRE.SM_DT_OpenPRE(R_FSMDTOpenPRE_EUFCMA(A),.)]       (leaf f)
           + Pr[TRHC_TCR.SM_DT_TCR_C(R_TRHSMDTTCRC_EUFCMA(A),.,.)]         (tree trh)
           + Pr[TRCOC_TCR.SM_DT_TCR_C(R_TRCOSMDTTCRC_EUFCMA(A),.,.)].      (root trco)
   FC carries the last three as ABSTRACT non-negative reals `tree_openpre`,
   `tree_trh`, `tree_trco` (FORS_C.ec:486-488) and admits
     Pr[EUF_CMA_FORSC_I(A) : res /\ !covered] <= tree_openpre+tree_trh+tree_trco
   (FORS_C.ec:701-704, "H-TREE").  The tie question is: are those three reals
   the three ES advantages (for some sound composed adversary)?  ANSWER: not via
   the existing ES modules -- (G1) below.

   (G1)  COUNTER-FREE HARD-WIRING  (the crux; bigger than the WOTS gap).
         ES's message hash is  mco : mkey -> msg -> msgFORSTW * index  (ES:412)
         -- it takes NO counter.  FC's is  mco : mkey -> msg -> cntr -> out_t
         (FORS_C.ec:176) -- the counter is exactly the +C ingredient.  The whole
         ES multi-instance tree machinery reads the leaf indices AND the FORS
         INSTANCE index (which of the s*l trees) off the counter-free digest, at
         THREE independent sites, each of which a +C forgery breaks:
           * SIGNING oracle (ES:2135 `O_CMA_MFORSTWESNPRF_AV.sign`):
                 (cm, idx) <- mco mk m;   (* counter-free *)
             then signs the FORS-TW instance `edivz (val idx) l` over `cm`.  A
             +C signer must sign over  mco mk m (gc mk m)  -- a DIFFERENT digest
             selecting a DIFFERENT instance and DIFFERENT leaves.  So the ES
             signing oracle cannot PRODUCE +C signatures: a transformer wrapping
             a +C forger around ES's oracle would mis-simulate it (an UNSOUND
             reduction).
           * FORGERY extraction, TRH reduction (ES:2448 body):
                 (cm', idx') <- mco mk' m';  lidxs' <- g (cm', idx');
             evaluated at the forger's (mk', m') WITHOUT the forger's counter c'.
             A +C forgery's digest is  mco mk' m' c'  -- the reduction would read
             the WRONG index list, so its located tree collision need not exist.
           * FORGERY extraction, OpenPRE reduction (ES:2244 body): same
                 (cm', idx') <- mco mk' m';   (counter-free) at find().
         CONSEQUENCE: `R_FSMDTOpenPRE_EUFCMA`, `R_TRHSMDTTCRC_EUFCMA`,
         `R_TRCOSMDTTCRC_EUFCMA` are NOT black-box reusable for +C.  The paper's
         "the security analysis follows verbatim" (SPHINCS+C Sec 4.1.1) means
         the proof STRUCTURE ports (the tree layer is untouched by +C), NOT that
         these exact EasyCrypt modules can be applied to a +C forger.  A faithful
         tie needs +C-VARIANT reductions in which every `mco mk m` is replaced by
         `mco mk m (gc mk m)` (signing / oracle-recorded indices) and every
         `mco mk' m'` by `mco mk' m' c'` (forgery extraction with the carried
         free counter).  That is a genuine port of ES:2135-2815, not a lemma.

   (G2)  SINGLE-INSTANCE ABSTRACT vs MULTI-INSTANCE CONCRETE.
         FC's `EUF_CMA_FORSC` (FORS_C.ec:399) is ONE abstract FORS instance:
         `(pk, sk) = fkeygen ps ad`, abstract `pkFORS/skFORS/sigFORSTW`.  ES's
         `EUF_CMA_MFORSTWESNPRF` (ES:2007) is the whole SPHINCS+ FORS FOREST:
         `pkFORS list list` (s*l instances), the concrete `M_FORS_ES_NPRF`
         Merkle scheme, instance chosen by `edivz (val idx) l` off the digest.
         Tying FC to the ES terms needs a single->multi embedding (place the one
         abstract instance at a chosen forest address and index), analogous to
         the WOTS bridge's `emb_tw`, but compounded by (G1)'s counter rewrite.

   (G3)  ABSTRACT vs CONCRETE TREE TYPES.  FC's `pkFORS`, `skFORS`,
         `sigFORSTW`, `fkeygen`, `fverify` are ABSTRACT ops/types (FORS_C.ec:
         162-330).  ES's are concrete (`pkFORS = dgstblock`, `sigFORSTW =
         DBAPKL.sT`, the concrete `trh/trco/f` over the SPHINCS+ address scheme).
         Even naming the ES terms in an FC-side statement requires cloning FORSC
         onto ES's concrete tree types first -- but (G1) makes that clone WRONG
         for `mco`: ES's counter-free `mco` cannot instantiate FC's
         counter-dependent `mco` without collapsing the +C constraint
         `predC_fors` (killing the +C mechanism), since the counter would then be
         a no-op input.

   (G4)  `local` INACCESSIBILITY of the ES theorem.  `EUFCMA_MFORSTWESNPRF_OPRE`
         (ES:3829) is a `local lemma` inside `section Proof_EUFCMA_M_FORS_ES`
         (ES:2809-6591): it CANNOT be cited from another file.  The reduction
         MODULES (`R_FSMDTOpenPRE_EUFCMA` ES:2244, `R_TRHSMDTTCRC_EUFCMA`
         ES:2448, `R_TRCOSMDTTCRC_EUFCMA` ES:2643) and the CLONES (`F_OpenPRE`
         ES:470, `TRHC_TCR` ES:616, `TRCOC_TCR` ES:648) ARE top-level
         (defined before ES:2809), so their advantage EXPRESSIONS are namable --
         but the three-term BOUND that relates them to the top game is trapped
         in the section.  So even a +C-variant port would have to RE-DERIVE the
         three tree hops (they cannot be black-boxed through the local theorem),
         re-running the ES:3910-6590 pRHL over the +C-rewritten digest.

   ROOT CAUSE.  (G1) is the essential one and it is why this is bigger than the
   WOTS bridge.  The WOTS+C leg's +C ingredient (the constant-sum counter) lands
   OUTSIDE the reused security game: WOTS-TW verifies ANY encoded digest, so the
   WOTS-TW term was reusable verbatim and only the S-TCR(+C) term was new (one
   extra additive term, WOTS_C_Bridge.ec).  The FORS+C +C ingredient lands
   INSIDE the tree game's index selection: the counter changes which leaves AND
   which forest instance the digest points at, and the ES tree reductions read
   those off the counter-free `mco` at signing, oracle-recording, and forgery
   extraction.  So the FORS tree terms are NOT reusable verbatim; they must be
   re-derived over `mco (.) (gc .)`.  (Consistent with the paper folding the
   FORS+C contribution into the ITSR term rather than adding a labelled +C term
   -- FORS_C.ec header, cross-check (D)/(E).)

   ==========================================================================
   WHAT A FAITHFUL FULL TIE WOULD NEED  (scoping, for the record).
   ==========================================================================
     1. A +C-variant multi-instance FORS-TW development: clone/port ES's
        `M_FORS_ES_NPRF` signing oracle and the three reductions with the
        counter-composed digest `mco mk m (gc mk m)` at signing/recording and
        the free counter `mco mk' m' c'` at forgery extraction (ports of
        ES:2135, ES:2244 find, ES:2448 body).  ~ the ES:2041-2815 block, +C'd.
     2. A single->multi embedding `emb_fadrs : adrs -> adrs` + index placement
        putting FC's one abstract instance at a forest slot, with an
        address-type-separation hypothesis (WOTS-bridge FLAG-2 analogue) so the
        embedded instance's tweaks are disjoint from the family-oracle tweaks.
     3. Re-derivation of the three tree hops over the +C digest (ES:3910-6590
        pRHL, re-run) -- the `local` theorem (G4) forbids black-boxing them.
     4. The three abstract reals `tree_openpre/tree_trh/tree_trco` then BECOME
        the +C-variant advantages of the composed adversary; the tie is the
        +C-invariance of the tree layer (the digest changes, but f/trh/trco and
        the SM-DT-OpenPRE / SM-DT-TCR-C games over them do not).
   Estimated effort: multi-week, comparable to porting the FORS_ES tree half.
   This is the honest scope: the FORS+C tree leg is a structural instantiation
   PORT, not a bridge lemma.  The msg-hash (+C) leg -- the genuinely +C-specific
   contribution -- is already PROVEN as the zero-admit `ITSRC_hop` in FORS_C.ec;
   the tree leg is the +C-INVARIANT remainder, whose only obstacle to closure is
   this concrete multi-week port (there is no +C-specific mathematics left in it).
   ========================================================================== *)

require import AllCore.
require FORS_C.

(* Intentionally no formal declarations: see STATUS / SCOPE above.  A faithful
   tie is unreachable tonight (G1-G4); this unit is the characterization, and
   any lemma over fresh abstract reals would be inert (removed by review). *)
