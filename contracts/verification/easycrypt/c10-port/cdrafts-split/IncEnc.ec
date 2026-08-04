(* ==========================================================================
   IncEnc.ec  --  INCOMPARABLE ENCODINGS (the encoding layer only).

   TRACK B, MILESTONE 1.  This file mechanizes the ENCODING LAYER of the
   incomparable-encoding framework and instantiates it at DEPLOYED C10
   geometry.  It is a LEAF: no file in drafts/ and no file in the vendored
   base requires it (the ONLY requirers anywhere are the four scratch
   canaries listed in the RECEIPTS block, which exist to be rejected), and
   it requires nothing from the vendored MM45 base.  It does NOT re-base the
   WOTS layer -- that is a separate, larger piece.  See "WHAT THIS DOES NOT
   ESTABLISH" at the bottom of this header.

   --------------------------------------------------------------------------
   PRIMARY SOURCE (read directly, not via a summary)
   --------------------------------------------------------------------------
   Justin Drake, Dmitry Khovratovich, Mikhail Kudinov, Benedikt Wagner,
   "Hash-Based Multi-Signatures for Post-Quantum Ethereum",
   IACR Communications in Cryptology 2(1):13  ( = ePrint 2025/055 ).

   Local copies in this repo:
       paper-cic-2-1-13.txt   sha256 bd0e93cd9778df48f3c4f3315e98f33e6d1319b24a06e8ddaa63816fbe7a7725
         *** TRACKED IN GIT (force-added past the .gitignore "*.txt" rule) ***
       paper-cic-2-1-13.pdf   sha256 e6a18255293545dc351d1b0d73742115d956250b9d26312bc759d2af8b889671
         NOT tracked (978 KB; .gitignore "*.pdf", like every other paper-*.pdf
         in the repo root).  The sha256 + the fetch route below pin it.
   The .txt is `pdftotext -layout` of the .pdf; ALL line numbers cited below
   are lines of paper-cic-2-1-13.txt.  WHY THE .txt IS TRACKED AND THE .pdf IS
   NOT: `pdftotext` output is VERSION-DEPENDENT, so re-extracting on another
   machine can shift every :NNNN citation in this file.  Tracking the exact
   .txt makes ~25 line-number citations checkable from a fresh clone instead
   of "trust the sha256".

   FETCH ROUTE.  eprint.iacr.org is behind Cloudflare from this host and
   returns HTTP 403 for both /2025/055 and /2025/055.pdf.  The IACR CiC
   journal mirror works:
       curl -sL -A "Mozilla/5.0 (X11; Linux x86_64)" \
            -o paper-cic-2-1-13.pdf https://cic.iacr.org/p/2/1/13/pdf

   Cited locations:
       Definition  9 (Incomparable Encoding Scheme) ......... :839-:848
       Definition 10 (Error of IE) ......................... :851-:857
       Definition 11 (T-COLL-RES for IE) ................... :863-:891
       Remark      4 (related notions) ..................... :893-:903
       Construction 6 (IE for Target Sum Winternitz) ....... :1533-:1556
       Lemma       7 (Correctness and Error of TSW) ........ :1558-:1587
       Game.2 (the T-COLL-RES game hop) .................... :1134-:1156
       Game.3 then the Def-9 case split .................... :1173-:1199

   --------------------------------------------------------------------------
   WHY THIS FILE EXISTS (the obstruction it dissolves)
   --------------------------------------------------------------------------
   MM45's WOTS model carries

       axiom two_encodings (m m' : msgWOTS) :
            m <> m'
         => exists (i : int), 0 <= i < len
            /\ BaseW.val (encode_msgWOTS m).[i] < BaseW.val (encode_msgWOTS m').[i].

   pinned at FV-SPHINCSPLUS-EC/proofs/WOTS_TW_ES.ec:572, with exactly two
   consumers, WOTS_TW_ES.ec:582 (exenc_neq0) and WOTS_TW_ES.ec:1305
   (nhchwcoll_hchwpre).  It quantifies over distinct MESSAGES, which forces
   the encoding to be INJECTIVE -- and injectivity is unsatisfiable at C10
   geometry, where the largest antichain of {0..7}^43 is ~2^123.76 < 2^128.
   TWO CAVEATS ON THAT SENTENCE, both flagged because neither is mechanized
   in this file: (i) the "antichain" reading of `two_encodings` comes from
   applying it in BOTH argument orders -- only the INJECTIVITY half is
   mechanized below (`mm45_forces_injectivity`); (ii) the 2^123.76 Sperner
   number (and the 2^114.09 size of the T = 205 layer) are EXTERNAL
   ARITHMETIC, not EasyCrypt receipts.  They are motivation, not proof.

   Definition 9 quantifies the SAME antichain condition over distinct
   CODEWORDS IN THE CODE.  That is strictly weaker, it is what the security
   argument actually uses, and the incomparability property HOLDS for any
   (v, w, T) -- with the honest caveat that for degenerate parameters (say
   v <= 0, or T > v*(2^w - 1)) the code is EMPTY and the property holds
   VACUOUSLY.  Non-emptiness is a separate obligation and is discharged here
   only for the C10 instance.  The
   injectivity that MM45 gets for free is replaced by the COMPUTATIONAL
   assumption of Definition 11 (T-COLL-RES).

   The MM45-vs-Def-9 quantification gap is MECHANIZED here, locally and
   parametrically, as `mm45_forces_injectivity` + `c10_def9_vs_mm45`.  This
   file deliberately does NOT `require` the vendored tree: doing so would
   drag the whole MM45 base into a leaf and destroy the leaf property.

   --------------------------------------------------------------------------
   HONESTY LEDGER -- what is PROVEN here vs what is merely STATED
   --------------------------------------------------------------------------
   PROVEN (no admits, no axioms; `bash ec-certify.sh drafts/IncEnc.ec`):
     * Def 9 as a predicate, parametric in v, w and the code C.  NO
       admissibility restriction on v or w -- that is the whole point.
     * Construction 6's code C_T = { x : |x| = v, digits in {0..2^w-1},
       sum x = T }, parametric in v, w, T.
     * Lemma 7, INCOMPARABILITY HALF, for ARBITRARY v, w, T
       (`tsw_incomparable`), from the list lemma `dominated_eqsum_eq`
       (equal length + pointwise domination + equal sum => equal).
     * Construction 6's encoding function lands in the code
       (`IncEncTSW_into_code`).
     * The C10 instance v = 43, w = 3 bits (base 8), T = 205 satisfies Def 9
       (`c10_is_IE_code`), and is NON-VACUOUS: the code is non-empty and has at
       least two distinct members (`c10_code_two_distinct`), so the Def-9
       property has actual content there (`c10_incomparable_witnessed`,
       `c10_witnessed_explicit`).
     * The SUM constraint is load-bearing FOR INCOMPARABILITY: drop it and
       incomparability FAILS (`cube3_not_incomparable`).
     * The DIGIT BOUND is load-bearing FOR CODE MEMBERSHIP, and pins the base
       at 8: a length-43, sum-205 vector containing the digit 8 is REJECTED
       (`c10_baddigit_notin`) -- the machine-visible guard against the
       w = 3-bits vs w = 8 notation trap.  BE PRECISE HERE: the digit bound
       is NOT used by `tsw_incomparable`, whose proof consumes only equal
       length and equal sum.  Incomparability of a target-sum code does not
       depend on the alphabet bound at all.
     * The quantification gap: an MM45-shaped hypothesis forces injectivity
       (`mm45_forces_injectivity`), while at C10 geometry there is an
       encoding into the (incomparable) C10 code that is NOT injective and
       therefore refutes the MM45-shaped hypothesis (`c10_def9_vs_mm45`).
       SCOPE, IN THREE PARTS -- the first was previously understated:
        (i)  `c10_def9_vs_mm45`'s witness is the CONSTANT map on `bool`.  Over
             a two-element message type non-injectivity FORCES constancy, so
             its image is ONE codeword and the antichain is never exercised;
             the lemma would hold with ANY non-empty code, even a chain.  It
             proves only the bare logical non-implication.  Both round-2
             external reviewers flagged the original wording as overselling
             this, and they were right.
        (ii) `c10_def9_vs_mm45_nondeg` is the fix: three messages, image
             = {c10_wit1, c10_wit2}, still many-to-one, and its two image
             points are mutually incomparable in BOTH directions.  THAT one
             genuinely exercises the C10 geometry.  Cite it, not (i).
        (iii) Neither proves that EVERY 128-bit-message encoder into this code
             must be many-to-one -- that is the counting argument, which is
             external arithmetic (see the caveat above), not a theorem here.

   STATED, NOT PROVEN (this is the milestone's deliberate boundary):
     * Definition 11 (T-COLL-RES) is transcribed as a GAME (module
       `T_COLL_RES`).  It type-checks; nothing is claimed about its
       advantage.  It becomes a NAMED LEDGER ASSUMPTION for the later WOTS
       swap.  It is a game, not an axiom -- this file declares no axiom.
       NAME THE LEDGER ENTRY "Def 11 VARIANT M1" AND NOT "Def 11": see the
       modelling-choice block below.  The transcription is also missing every
       side condition of Def 11 (naturals, epoch domain [L], uniform
       parameter sampling, losslessness) and the adversary-memory
       restriction; all are itemised in M2 and M6 as CONSUMER OBLIGATIONS.
       The game's own NON-VACUITY -- that the win event is reachable for some
       adversary and some IncEnc -- is NOT established.

   NOT PROVEN AND NOT ATTEMPTED:
     * Lemma 7 is TWO claims in the paper: "is an incomparable encoding
       scheme AND has error delta = eps + (1 - eta_T / 2^(vw))".  ONLY THE
       INCOMPARABILITY HALF IS PROVEN HERE.  The error/delta half (Def 10)
       is where eps-uniformity of Th_msg and the grind budget enter, and it
       is exactly where the open C10 parameter-margin question lives
       (v*w = 129 vs the framework's 131.32 classical / 137.64 quantum, and
       the 2^23.25 grind budget -- deliberately NOT called "randomness", see
       (d) below).  This file says NOTHING about that.
     * Lemma 8 (T-COLL-RES of TSW reduces to SM-rTCR of Th_msg) is not
       ported.
     * No WOTS, XMSS, FORS or SPHINCS+C statement is touched.

   --------------------------------------------------------------------------
   ORDERING REQUIREMENT FOR THE LATER WOTS SWAP  (do not get this wrong)
   --------------------------------------------------------------------------
   NOTATION IN THIS COMMENT: EasyCrypt comments cannot contain the two-
   character sequence star-paren, so the paper's starred symbols m*, rho*,
   ep*, x*, sigma*_OTS are written mS, rhoS, epS, xS, sigmaS_OTS below.

   T-COLL-RES must be discharged in a GAME HOP **BEFORE** any "either the
   encodings differ or it is a collision" case split.  A port that builds
   only the case split is UNSOUND.  The paper's own ordering, verbatim:

     Game.2 (:1134-:1140) "is the same as Game.1 but we let the game output 0
       if we can extract a collision for the incomparable encoding scheme
       ... We let the game output 0 if we have
          (m, rho) <> (mS, rhoS) AND IncEnc(P,m,rho,epS) = IncEnc(P,mS,rhoS,epS)"
       bounded (:1153-:1156) by
         Adv^{Game.1}_SIG(A) - Adv^{Game.2}_SIG(A) <= Adv^{T-COLL-RES,K}_{IncEnc,qs}(B2).

     Game.3 (:1173-:1189) then removes the remaining "(m,rho) = (mS, rhoS) but
       sigma_OTS <> sigmaS_OTS" branch, charged to SM-TCR of Th.

     ONLY THEN (:1196-:1199) "Now that we have ruled out the second case, we
       can focus on the first case, i.e., the case in which x <> xS. ...
       Therefore, the definition of the incomparable encoding scheme
       (definition 9) ensures that there exists some i in [v] such that
       xS_i < x_i."

   So: Def 9 is applied to two codewords that are ALREADY KNOWN DISTINCT,
   and the "already known distinct" is manufactured by the T-COLL-RES hop.
   Note also that the paper instantiates the Def-11 query bound p with qs,
   the number of signing queries.

   --------------------------------------------------------------------------
   MODELLING CHOICES IN THE Def-11 TRANSCRIPTION (flagged, with direction)
   --------------------------------------------------------------------------
   (M1) The paper's step 2(c) inserts the log entry (m, BOT, ep, BOT) -- BOT
        in the RANDOMNESS slot -- while the win condition in step 4 quantifies
        over a pair (m, rho) with rho in R.  Literally read, a failure entry
        can never be matched by such a pair.  Here the log's randomness slot
        is `rand option` and the win predicate `tcoll_win` requires `Some r`,
        which is the LITERAL TYPED READING of step 4.
        DIRECTION, STATED CAREFULLY (an earlier draft of this comment got it
        backwards; corrected after two independent external reviews).  For
        every A, Adv_M1(A) <= Adv_paper(A) under the permissive reading of
        step 4 that lets rho be BOT.  So:
          - as an ASSUMPTION, "Adv_M1 is small" is WEAKER than the paper's,
            i.e. EASIER to satisfy.  That is fine in itself, but it means the
            ledger entry must be named "Def 11 VARIANT M1", not "Def 11".
          - the RISK IS ON THE REDUCTION SIDE, not the assumption side.  A
            consumer's game hop must exhibit a win IN THIS GAME; if the
            consumer's bad event could be matched by a FAILURE entry, the
            reduction does NOT close and no amount of "conservatism" helps.
        WHY IT IS NEVERTHELESS ENOUGH FOR THE PAPER'S OWN CONSUMER: in the
        B2 reduction the matched entry always comes from a SUCCESSFUL
        signature, and verification checks x* in C and x in C (:1196-:1197),
        so the bad event never involves a failure entry.  THAT INVARIANT IS
        NOT PROVEN HERE.  A consumer of this game MUST prove it.
        THE WEAKENING IS STRICT, NOT MERELY NON-STRICT -- and this is the
        cleanest argument for the "VARIANT M1" rename, so state it plainly.
        `IncEnc` here is an UNCONSTRAINED `op` (M7), so take one that returns
        None always.  An adversary that makes a single query (m0, ep0) and
        then outputs any (mS, rhoS, ep0) WINS the permissive game with
        probability 1 -- the failure entry (m0, BOT, ep0, BOT) matches, and
        (m0, BOT) <> (mS, rhoS) is automatic because rhoS is typed in R --
        while Adv_M1 = 0, since no `Some`-entry exists at all.  So
        Adv_M1 < Adv_permissive strictly for that A.  (Found independently by
        both round-2 reviewers.)  NOTE THE OTHER SIDE OF IT: against the
        LITERAL TYPED reading of step 4, where rho ranges over R and a BOT
        slot simply cannot be matched, M1 is EXACTLY EQUIVALENT to Def 11 --
        not weaker.  The whole risk analysis above is relative to the
        PERMISSIVE reading, which the paper may well not intend (its step 3
        types rhoS in R at :884, and Lemma 8 at :1622 wins only on a valid
        x <> BOT).  "VARIANT M1" is therefore prudent audit policy rather
        than a mathematically forced distinction.
        CONSEQUENCE OF M1: under this reading a target with x* = BOT is
        unwinnable, because no `Some`-entry carries BOT.  If a future
        consumer needs BOT-targets to be winnable, THIS is the line to
        revisit.
        *** BUT THAT CONSEQUENCE HOLDS ONLY FOR A RESTRICTED ADVERSARY. ***
        (Caught by GPT-5.6 in round 2; the unqualified claim was wrong.)  In
        EasyCrypt an UNRESTRICTED `A` may WRITE `TCollOracle.log` directly and
        simply plant an entry (m0, Some r0, ep, None), then return a distinct
        BOT target -- winning with x* = BOT.  The consequence is true only for
            A <: TCollAdvT{-TCollOracle}
        with an oracle-generated log, i.e. exactly under M6's restriction.
        M6 is therefore not merely hygiene: it is load-bearing for this claim.
        NEXT RECEIPT TO CONVERT (deliberately NOT built at this milestone --
        the task scoped Def 11 to "stated is enough", and building it would
        be the first piece of the consumer side, not of the encoding layer):
        that consequence is currently PROSE but is MECHANIZABLE.  For an
        `{-TCollOracle}`-restricted A, every `Some r` entry is written by step
        2(d), which runs only when `x <> None`, so the log carries the
        invariant
            forall e, e \in log => (e.`2 <> None <=> e.`4 <> None)
        from which `tcoll_win log ep None ms rs = false` follows.  That needs
        a while-loop invariant + an oracle-level `hoare`/`phoare` proof over
        `TCollOracle.encode`, PLUS the memory restriction to rule out the
        planted-entry attack just described.  Whoever does the WOTS swap
        should do this FIRST: it is the cheapest non-vacuity evidence the
        Def-11 game can carry, and until it exists the game's own non-vacuity
        is unestablished (see [NV]).
   (M2) EVERY side condition of Definition 11 is DEFERRED TO THE CONSUMER,
        because stating one here would require an axiom and move this file
        off 0-axiom.  Do not patch any of them in.  The deferred list, in
        full, so that a consumer can carry them as explicit hypotheses:
          - K and p are abstract `op int` with no positivity constraint,
            while the paper has K, p in N (:865, :1610-:1613).  K <= 0 makes
            the regeneration loop never run (every query logs a failure
            entry); p <= 0 makes the oracle reject every query.
          - The epoch is an unrestricted `int`; the paper's lifetime domain
            [L] (:871-:873, :884-:885) is NOT modelled.  This makes the
            adversary here STRICTLY STRONGER than the paper's, which is the
            safe direction for an assumption but will matter to any consumer
            that ports an L-dependent union bound.
          - `dparam` is an arbitrary distribution; the paper samples P
            uniformly from P (:868).  Neither `dparam` nor `drand` is assumed
            lossless, and adversary termination is not assumed.
          - `drand` IS NOT ASSUMED UNIFORM, and the paper's step 2(b)i samples
            rho uniformly from R (:877).  This one was MISSING from the list
            in an earlier revision even though the list claims to be "in
            full" -- added after round-2 external review.  It is NOT a
            direction-safe omission: with R = {r0, r1} and collisions
            reachable only at r1, a point mass at r0 gives advantage 0 while
            the uniform paper game has positive advantage, and a point mass
            at r1 distorts the other way.  So NO Def-11 comparison is
            available at all until a consumer pins the support/uniformity of
            `drand`.  THIS ALSO BITES AT C10 (see (d) in the header): the
            deployed WOTS+C encoder ENUMERATES a counter deterministically
            rather than sampling, so instantiating this game at C10 needs a
            separate coupling argument, not just a choice of `drand`.
          - Definition 11 presupposes an IE with a code C (:863-:865); the
            game here is stated over an ARBITRARY `IncEnc` with no `C`,
            `is_IE_code`, or codomain premise attached.  A consumer should
            instantiate `IncEnc` at `IncEncTSW v w T` and carry
            `IncEncTSW_into_code`.
          - The advantage (:887-:891) is not stated as a lemma; only the
            Boolean experiment is executable.  `tcoll_adv_restriction_shape`
            below pins the exact `Pr[...]` expression and the required
            adversary restriction, and nothing else.
   (M3) K lives in the ORACLE, not in IncEnc.  Construction 6's encoding is
        single-shot (hash, reject if not in C); the retry loop is the
        oracle's (and the real signer's).  Do not fold K into `IncEncTSW`.
   (M4) `tweakm : int -> tweak` is declared abstract.  The paper assumes it
        is injective; injectivity is NOT needed for anything proven here, so
        it is not assumed (assuming it would need an axiom).  A consumer that
        needs it must carry it as a hypothesis.
   (M5) The chunk decomposition is modelled directly: a codeword IS an
        `int list` of digits, not a bit string that is later split.  Def 9's
        "x in {0..2^w-1}^v" is the pair (size x = v, all digits in range),
        which is `code_wf` below.
   (M6) ADVERSARY MEMORY RESTRICTION IS A CONSUMER OBLIGATION.  In the
        paper A gets ONLY oracle access (:871-:873).  In EasyCrypt an
        abstract adversary may read and WRITE any global it is not forbidden
        from touching, so an unrestricted A could rewrite `TCollOracle.log`
        or `TCollOracle.pp` and make the experiment meaningless.  The
        restriction CANNOT be attached to the game functor's parameter --
        `module T_COLL_RES (A : TCollAdvT{-TCollOracle})` is a PARSE ERROR in
        this EasyCrypt (verified: scratch/incenc/probe6.ec, probe7.ec, both
        rejected at the `{`) -- and the vendored MM45 base does the same
        thing: its games take unrestricted functor parameters, VERIFIED as
        real (non-comment) module declarations at
            FL_SL_XMSS_MT_ES.ec:1832   module EUF_NAGCMA_FLSLXMSSMTTWESNPRF
            FORS_ES.ec:2007            module EUF_CMA_MFORSTWESNPRF
        and impose the memory restriction OUTSIDE the functor.  CORRECTION
        (round-2 external review): an earlier revision cited FORS_ES.ec:571 as
        the lemma-quantifier precedent.  THAT CITATION IS BAD -- :571 is
        INSIDE A COMMENT (a commented-out `EqPr_FPTCR_FTCR` block), so it is
        not compiled precedent for anything.  The base's ACTUAL discipline is
        a SECTION-LEVEL declaration:
            FORS_ES.ec:2809   section Proof_EUFCMA_M_FORS_ES.
            FORS_ES.ec:2811   declare module A <: Adv_EUFCMA_MFORSTWESNPRF {
            FORS_ES.ec:2813-2818   ... -O_CMA_MFORSTWESNPRF, -R_ITSR_EUFCMA, ...
        i.e. `declare module` inside a `section`, carrying the minus-list.
        This file has no section, so it uses the LEMMA-quantifier form, which
        is independently verified to compile (probe8.ec, rc=0).  Either way,
        EVERY consumer statement MUST quantify as
            (A <: TCollAdvT{-TCollOracle})
        `tcoll_adv_restriction_shape` below is a compiled receipt that this
        exact form type-checks.  A consumer that omits `{-TCollOracle}` has
        stated a VACUOUS assumption.
   (M7) `thmsg` is an unconstrained `op` returning an `int list`, whereas the
        paper's Th_msg is TYPED into the cube {0..2^w-1}^v (:1533-:1535).
        So `IncEncTSW` here can return BOT for a malformed length or an
        out-of-range digit, not only for a wrong sum -- strictly more BOTs
        than the paper.  Harmless for everything proven here; it matters for
        the unported error/delta analysis.  Note the corollary: for an
        adversarial `thmsg`, `IncEncTSW` may return None ALWAYS.  Nothing
        here proves the encoder ever reaches a codeword; only that the CODE
        is non-empty.

   --------------------------------------------------------------------------
   GATE / NON-VACUITY RECEIPTS   (see the RECEIPTS block at the end of file)
   --------------------------------------------------------------------------
   Verification of this file is `bash ec-certify.sh drafts/IncEnc.ec`
   (compile EXIT 0 + zero admit tactics + zero axiom declarations), plus the
   FIVE REJECTED canaries recorded at the end of this file, plus the in-file
   non-vacuity lemmas listed in the honesty ledger.  Because this is a LEAF
   (see the qualified leaf statement above and the [L] receipt at the end)
   the whole-chain vacuity_repair_gate is not needed; the leaf property is
   itself receipted at the end of the file.

   --------------------------------------------------------------------------
   WHAT THIS DOES NOT ESTABLISH
   --------------------------------------------------------------------------
   Nothing here re-bases anything.  No MM45 file is modified, no MM45
   theorem is reproved, and the C10 EUF-CMA chain is untouched and still
   rests on `two_encodings`.  What is established is that the ENCODING LAYER
   of the published framework is mechanizable, that its central lemma holds
   for arbitrary (v, w, T), and that DEPLOYED C10 geometry is admissible and
   non-vacuous in it -- i.e. the foundation the later WOTS swap would stand
   on exists and is 0-admit.

   READ "ADMISSIBLE" NARROWLY.  It means exactly: the fixed-sum C10 code is a
   non-empty, at-least-two-element antichain in the sense of Def 9, and
   Construction 6's wrapper has codomain closure into it.  It does NOT mean
   "C10 is secure in the DKKW framework".  The whole COMPUTATIONAL leg is
   absent: the T-COLL-RES advantage at C10, Lemma 8, the error delta and its
   K-grind, and the parameter-margin question (v*w = 129 vs 131.32 / 137.64;
   the 2^23.25 grind BUDGET -- not "randomness", see (d)).  Note also that
   43 / 3 / 205 are the
   DEPLOYED C10 values, NOT the paper's.  ALL FOUR PROVENANCE CLAIMS BELOW
   ARE COMMANDS WITH THEIR OBSERVED OUTPUT, not English assertions.  An
   earlier revision of this paragraph asserted two of them in prose and BOTH
   WERE WRONG AS WRITTEN -- see [P] in the RECEIPTS block for the correction
   history.  The failure mode is the one this project keeps hitting: a
   receipt nobody re-ran.

     (a) The deployed values, at source.  SIBLING REPO, PINNED:
         /home/nicola/repos/PQSigner_OS at commit
         d9f4dcd8dd58b44a26e07b7fef81c6b190f06d34 (params.rs unmodified there).
         Stated AS A COMMAND, because the first version of this receipt gave
         file:line assertions and TWO OF THE FOUR LINE NUMBERS WERE WRONG
         (:44/:47 for W/LOG_W; actual :43/:46).  Both round-2 reviewers caught
         it.  Re-runnable form:
           command grep -nE "pub const (W|LOG_W|L|TARGET_SUM):" \
             sphincs-c10/src/params.rs
             -> 43:pub const W: usize = 8;          (the BASE)
                46:pub const LOG_W: usize = 3;      (bits per digit = paper w)
                49:pub const L: usize = 43;         (= paper v)
                52:pub const TARGET_SUM: usize = 205;
         `LOG_W = 3` is the machine-checkable corroboration of the w-notation
         reading: the firmware's own "W" is the BASE and the paper's w is the
         BIT-WIDTH, and the firmware carries BOTH constants side by side, so
         the identification base 8 = 2^3 <-> paper w = 3 is read off source
         rather than inferred.  Corroborated again by the digit extractor,
         which shifts by LOG_W per digit (sphincs-c10/src/wots.rs:13,
         "digit i = (digest >> (i * LOG_W)) & W_MASK").  This is what
         `c10_w = 3` + `c10_base` pin.

     (b) The paper's TSW tables use w in {1,2,4,8} -- EXHAUSTIVELY, across
         BOTH tables, verified by enumeration rather than by eye:
           command grep -nE "TSW +w = [0-9]+" paper-cic-2-1-13.txt \
             | sed -E 's/.*(w = [0-9]+).*/\1/' | sort -u
             -> exactly four lines: w = 1, w = 2, w = 4, w = 8
         THE ENUMERATION IS THE RECEIPT; the coordinates below are navigation
         aids only (an earlier revision gave clipped ranges and an off-by-one
         row, corrected after round-2 review).  Table 2's caption is at :2118
         with TSW rows at :2136-:2160; Table 3's caption is at :2185 with TSW
         rows at :2203-:2227 -- each table has TWO lifetime blocks (L = 2^18
         and L = 2^20), and quoting only the first block clips half the rows.
         NB the TSW w = 8, delta = 1 row's "Hash AC = 4008.53" (:2142, NOT
         :2143 -- that is the delta = 1.1 row, 3613.22) is a COINCIDENCE with
         C10's 4008-BYTE signature: different quantity (Table 2's caption at
         :2124 says hashing is "given in words (1 word = 32 Bytes)"), and a
         different parameter set.  It is the notation trap in its most
         seductive form -- do not read it as corroboration that C10 is the
         paper's w = 8 row.  C10 is w = 3.  (Table 3 is Poseidon2 and its
         hash columns are permutation calls, not 32-byte words; the 4008.53
         cell is in Table 2.)

     (c) 205 is not a paper parameter.  The CORRECT receipt is a
         word-boundary search, and it is EMPTY:
           command grep -nE '(^|[^0-9])205([^0-9]|$)' paper-cic-2-1-13.txt
             -> no output
         A plain `command grep -c '205'` returns 1 and does NOT support the
         claim: the sole hit is the substring inside the DOI "10.62056" on
         line 1.  The earlier prose form of this sentence -- "the string 205
         does not occur in paper-cic-2-1-13.txt" -- was therefore LITERALLY
         FALSE, though its substance survives under (c).

     (d) THE 2^23.25 GRIND FIGURE -- TWICE-CORRECTED, READ THE WHOLE ENTRY.
         Revision 1 cited it to `params.rs`; nothing in that file matches, so
         the citation was unfollowable.  Revision 2 (this session, before
         external review) "fixed" it to the FORS R-grind -- WHICH IS THE WRONG
         LAYER, caught by GPT-5.6 in round 2.  C10 has TWO independent 10^7
         grind loops, and because log2(10^7) = 23.25 for both, a wrong-layer
         citation looks right:
           sphincs-c10/src/fors.rs:98,109,130   `grind_r`, R-grinding: finds a
             randomizer R forcing the LAST FORS INDEX TO ZERO.  Cap is the
             loop bound at :109 (`for nonce in 0..10_000_000u32`); :130 is only
             the panic text.  NOT the encoding layer.  IRRELEVANT HERE.
           sphincs-c10/src/wots.rs:62,74        WOTS+C count-grinding: finds a
             `count` whose base-w digit sum equals TARGET_SUM.  Cap at :62
             (`for count in 0..10_000_000u32`), panic at :74.
         *** wots.rs:62 IS the analogue of Construction 6's reject-and-resample
         loop, and its `count` is the syntactic analogue of the paper's rho.
         *** The module header says so in as many words (wots.rs:1-5: "grinds
         a `count` value until the base-w digit sum of the message digest
         equals exactly `TARGET_SUM`").  Compare Construction 6 (:1546-:1552)
         and Def 11 step 2(b) (:875-:879).

         AND "RANDOMNESS" IS THE WRONG WORD FOR IT.  The paper samples rho
         UNIFORMLY FROM R on every attempt (:877).  C10 does not sample at
         all: it enumerates count = 0, 1, 2, ... and returns the FIRST hit,
         from a public seed; the count is then TRANSMITTED in the signature
         and the verifier RE-CHECKS rather than re-searching.  The sister
         document works this through and concludes the count carries
         "approximately 0 bits of entropy, not 23.25 -- quoting 2^23.25 as its
         'randomness' already overstates it":
           docs/verification/easycrypt-euf-cma-port-feasibility-2026-07.md
             :3736         where the 2^23.25 figure is introduced
             :3838-:3847   Q3, why the counter is not the framework's R
             :3849-:3850   a standing "CORRECTED after external review" note
                           on this very mapping
         So this file had re-introduced, in a receipt, an error the sister
         document had ALREADY been corrected for.  That is the whole argument
         for stating provenance as commands.

         CONSEQUENCE, and it is not cosmetic: the deterministic-enumeration
         vs uniform-sampling gap is exactly why instantiating the Def-11 game
         (section 7) at deployed C10 needs a separate coupling argument and
         not merely a choice of `drand` -- see the `drand` bullet in M2.
         Neither the 2^23.25 figure nor 43 / 3 / 205 comes from the paper.
   ========================================================================== *)

require import AllCore List IntDiv StdOrder Distr.

(* ==========================================================================
   0.  LIST INFRASTRUCTURE  (all proven; nothing here is C10-specific)
   ========================================================================== *)

lemma sumz_nil : sumz [] = 0.
proof. by rewrite /sumz. qed.

lemma sumz_cons (a : int) (s : int list) : sumz (a :: s) = a + sumz s.
proof. by rewrite /sumz. qed.

lemma sumz_cat (s1 s2 : int list) : sumz (s1 ++ s2) = sumz s1 + sumz s2.
proof.
elim: s1 => [| a s1 ih]; first by rewrite cat0s sumz_nil.
by rewrite cat_cons !sumz_cons ih /#.
qed.

lemma sumz_nseq (n c : int) : 0 <= n => sumz (nseq n c) = n * c.
proof.
elim: n => [| n ge0_n ih]; first by rewrite nseq0 sumz_nil.
by rewrite nseqS // sumz_cons ih /#.
qed.

(* Pointwise domination is monotone for the sum. *)
lemma sumz_dominated_le (x y : int list) :
     size x = size y
  => (forall (i : int), 0 <= i < size x => nth 0 y i <= nth 0 x i)
  => sumz y <= sumz x.
proof.
elim: x y => [| a x ih] [| b y].
+ by move=> _ _; rewrite sumz_nil.
+ by smt(size_ge0).
+ by smt(size_ge0).
move=> eq_sz dom.
have le_ba : b <= a by have := dom 0 _; smt(size_ge0).
have le_sum : sumz y <= sumz x.
+ apply ih; first by smt().
  by move=> i rng_i; have := dom (i + 1) _; smt().
by rewrite !sumz_cons /#.
qed.

(* THE KERNEL OF LEMMA 7.  Equal length + pointwise domination + equal sum
   forces equality.  This is the formal content of the paper's one-line
   argument (:1571-:1580): "assume towards contradiction that every
   coordinate of x is larger or equal than the respective coordinate of x'.
   We know that at least one of these inequalities has to be strict as
   x <> x'.  Then T = sum x_i > sum x'_i = T, a contradiction." *)
lemma dominated_eqsum_eq (x y : int list) :
     size x = size y
  => (forall (i : int), 0 <= i < size x => nth 0 y i <= nth 0 x i)
  => sumz x = sumz y
  => x = y.
proof.
elim: x y => [| a x ih] [| b y].
+ by move=> _ _ _.
+ by smt(size_ge0).
+ by smt(size_ge0).
move=> eq_sz dom eq_sum.
have le_ba : b <= a by have := dom 0 _; smt(size_ge0).
have dom' : forall (i : int), 0 <= i < size x => nth 0 y i <= nth 0 x i.
+ by move=> i rng_i; have := dom (i + 1) _; smt().
have le_sum : sumz y <= sumz x by apply (sumz_dominated_le x y); smt().
have eq_ab : a = b by move: eq_sum; rewrite !sumz_cons; smt().
have eq_sxy : sumz x = sumz y by move: eq_sum; rewrite !sumz_cons; smt().
by rewrite eq_ab (ih y) // /#.
qed.

(* ==========================================================================
   1.  DEFINITION 9  --  INCOMPARABLE ENCODING SCHEME     (paper :839-:848)
   ==========================================================================
   "such that for every distinct codewords x = (x_1,...,x_v) in C and
    x' = (x'_1,...,x'_v) in C, we have
        (exists i in [v] : x_i < x'_i) AND (exists i' in [v] : x'_i' < x_i')."

   NOTE THE QUANTIFIER: over distinct CODEWORDS IN C.  Not over encodings of
   distinct messages.  Parametric in v and C; NO admissibility restriction
   on v or w.
   ========================================================================== *)

type codeword = int list.

op incomparable (v : int) (C : codeword -> bool) : bool =
  forall (x x' : codeword),
       C x
    => C x'
    => x <> x'
    => (exists (i  : int), 0 <= i  < v /\ nth 0 x  i  < nth 0 x' i )
    /\ (exists (i' : int), 0 <= i' < v /\ nth 0 x' i' < nth 0 x  i').

(* "code C included in {0,...,2^w - 1}^v", spelled out over int lists. *)
op code_wf (v w : int) (C : codeword -> bool) : bool =
  forall (x : codeword),
    C x => size x = v /\ all (fun (d : int) => 0 <= d < 2 ^ w) x.

(* A code is Def-9-admissible for (v, w) when it sits in the cube and its
   distinct members are pairwise incomparable.
   NAME IS DELIBERATELY `is_IE_code`, NOT `is_IE`: this is the CODE half of
   Definition 9 only.  Definition 9 is a SCHEME -- an efficiently computable
   function into C u {BOT} -- and this predicate says nothing about the
   function, its efficiency, its lifetime domain [L], or which codewords it
   actually reaches.  The codomain half is `enc_into_code` below; efficiency
   and reachability are not modelled at all. *)
op is_IE_code (v w : int) (C : codeword -> bool) : bool =
  code_wf v w C /\ incomparable v C.

(* The cube itself -- Def 9's ambient set, WITHOUT any further constraint.
   Used below to show the sum constraint is load-bearing. *)
op cube_code (v w : int) (x : codeword) : bool =
     size x = v
  /\ all (fun (d : int) => 0 <= d < 2 ^ w) x.

(* ==========================================================================
   2.  CONSTRUCTION 6  --  TARGET SUM WINTERNITZ CODE   (paper :1533-:1545)
   ==========================================================================
   "Let v, w, T in N be integers. ... Define the code
        C := { (x_1,...,x_v) in {0,...,2^w-1}^v  |  sum_{i=1}^{v} x_i = T }."
   Parametric in v, w, T.  The paper states no admissibility restriction and
   neither does this.
   ========================================================================== *)

op tsw_code (v w T : int) (x : codeword) : bool =
     size x = v
  /\ all (fun (d : int) => 0 <= d < 2 ^ w) x
  /\ sumz x = T.

lemma tsw_size (v w T : int) (x : codeword) : tsw_code v w T x => size x = v.
proof. by rewrite /tsw_code; smt(). qed.

lemma tsw_sum (v w T : int) (x : codeword) : tsw_code v w T x => sumz x = T.
proof. by rewrite /tsw_code; smt(). qed.

lemma tsw_code_wf (v w T : int) : code_wf v w (tsw_code v w T).
proof. by rewrite /code_wf /tsw_code; smt(). qed.

(* ==========================================================================
   3.  LEMMA 7  --  INCOMPARABILITY HALF, FOR ARBITRARY v, w, T
   ==========================================================================
   Paper :1558-:1580.  REMINDER (see the honesty ledger in the header): the
   paper's Lemma 7 also states the ERROR delta of the encoding; that half is
   NOT proven here and is not needed for this milestone.
   ========================================================================== *)

lemma tsw_incomparable (v w T : int) : incomparable v (tsw_code v w T).
proof.
rewrite /incomparable => x x' hx hx' nex.
have szx  := tsw_size v w T x  hx.
have szx' := tsw_size v w T x' hx'.
have sx   := tsw_sum  v w T x  hx.
have sx'  := tsw_sum  v w T x' hx'.
split.
+ case: (exists (i : int), 0 <= i < v /\ nth 0 x i < nth 0 x' i) => // hno.
  have contra : x = x'.
  + apply dominated_eqsum_eq; 1,3: smt().
    by move=> i rng_i; smt().
  by move: nex; rewrite contra.
+ case: (exists (i : int), 0 <= i < v /\ nth 0 x' i < nth 0 x i) => // hno.
  have contra : x' = x.
  + apply dominated_eqsum_eq; 1,3: smt().
    by move=> i rng_i; smt().
  by move: nex; rewrite contra.
qed.

lemma tsw_is_IE_code (v w T : int) : is_IE_code v w (tsw_code v w T).
proof. by rewrite /is_IE_code; split; [exact tsw_code_wf | exact tsw_incomparable]. qed.

(* ==========================================================================
   4.  CONSTRUCTION 6's ENCODING FUNCTION                (paper :1546-:1556)
   ==========================================================================
       IncEnc_TSW[Th_msg, T](P, m, rho, ep):
         1. x := Th_msg(P, tweakm(ep), (m, rho))
         2. If x not in C, return BOT.  Else return x.
   Single-shot: NO retry loop here (see modelling choice M3).
   ========================================================================== *)

type param, msg, rand, tweak.

op thmsg  : param -> tweak -> (msg * rand) -> codeword.
op tweakm : int -> tweak.

op IncEncTSW (v w T : int) (pp : param) (m : msg) (r : rand) (ep : int)
  : codeword option =
  if   tsw_code v w T (thmsg pp (tweakm ep) (m, r))
  then Some (thmsg pp (tweakm ep) (m, r))
  else None.

(* An encoding function is well-formed for a code C when every non-BOT output
   is a member of C.  (Def 9's codomain "C u {BOT}".) *)
op enc_into_code (C : codeword -> bool)
                 (enc : param -> msg -> rand -> int -> codeword option) : bool =
  forall (pp : param) (m : msg) (r : rand) (ep : int) (x : codeword),
    enc pp m r ep = Some x => C x.

lemma IncEncTSW_into_code (v w T : int) :
  enc_into_code (tsw_code v w T) (IncEncTSW v w T).
proof. by rewrite /enc_into_code /IncEncTSW => pp m r ep x; smt(). qed.

(* ==========================================================================
   5.  THE PAYOFF: INSTANTIATION AT DEPLOYED C10 GEOMETRY
   ==========================================================================
   C10: v = 43 chains, base 8 => w = 3 BITS PER CHUNK, target sum T = 205.

   NOTATION TRAP, PINNED IN CODE.  In this literature w is BITS PER CHUNK.
   C10's base-8 Winternitz is their w = 3.  Their "w = 8" means base 256.
   `c10_base` below fixes 2^w = 8, and `c10_baddigit_notin` proves that the
   digit 8 is REJECTED -- which would be legal at base 256.  Together those
   two make the reading machine-checked rather than a comment.
   ========================================================================== *)

op c10_v : int = 43.
op c10_w : int = 3.
op c10_T : int = 205.

lemma c10_base : 2 ^ c10_w = 8.
proof. by rewrite /c10_w; smt(). qed.

op c10_code : codeword -> bool = tsw_code c10_v c10_w c10_T.

(* DEPLOYED C10 PARAMETERS ARE ADMISSIBLE IN THE Def-9 FRAMEWORK.
   READ NARROWLY (this is the sentence most likely to be misquoted): it means
   the C10 CODE is a Def-9 antichain, and -- with the non-vacuity lemmas
   below -- a non-degenerate one.  It does NOT mean C10 is secure in that
   framework: the entire computational leg (T-COLL-RES advantage, Lemma 8,
   the error delta and its grind budget, the v*w = 129 margin) is absent.
   See "WHAT THIS DOES NOT ESTABLISH" in the header. *)
lemma c10_incomparable : incomparable c10_v c10_code.
proof. by apply tsw_incomparable. qed.

lemma c10_is_IE_code : is_IE_code c10_v c10_w c10_code.
proof. by apply tsw_is_IE_code. qed.

(* -------------------------------------------------------------------------
   5a.  NON-VACUITY.  A vacuous (empty, or singleton) code satisfies Def 9
        trivially and would make the instantiation meaningless.  Two explicit
        distinct members are exhibited.

        29 sevens (= 203) then 2, 0, then twelve 0s : 29 + 1 + 1 + 12 = 43
        digits, all in {0..7}, summing to 203 + 2 = 205.  The second witness
        swaps the two middle digits, so the two differ at index 29 AND at
        index 30 -- in opposite directions.
   ------------------------------------------------------------------------- *)

op c10_wit1 : codeword = nseq 29 7 ++ 2 :: 0 :: nseq 12 0.
op c10_wit2 : codeword = nseq 29 7 ++ 0 :: 2 :: nseq 12 0.

lemma c10_wit1_code : c10_code c10_wit1.
proof.
rewrite /c10_code /c10_wit1 /tsw_code /c10_v /c10_T c10_base.
split; first by rewrite size_cat size_nseq /= size_nseq.
split; first by rewrite all_cat all_nseq /= all_nseq /=.
by rewrite sumz_cat sumz_nseq // !sumz_cons sumz_nseq.
qed.

lemma c10_wit2_code : c10_code c10_wit2.
proof.
rewrite /c10_code /c10_wit2 /tsw_code /c10_v /c10_T c10_base.
split; first by rewrite size_cat size_nseq /= size_nseq.
split; first by rewrite all_cat all_nseq /= all_nseq /=.
by rewrite sumz_cat sumz_nseq // !sumz_cons sumz_nseq.
qed.

lemma c10_wit1_29 : nth 0 c10_wit1 29 = 2.
proof. by rewrite /c10_wit1 nth_cat size_nseq. qed.

lemma c10_wit2_29 : nth 0 c10_wit2 29 = 0.
proof. by rewrite /c10_wit2 nth_cat size_nseq. qed.

lemma c10_wit1_30 : nth 0 c10_wit1 30 = 0.
proof. by rewrite /c10_wit1 nth_cat size_nseq. qed.

lemma c10_wit2_30 : nth 0 c10_wit2 30 = 2.
proof. by rewrite /c10_wit2 nth_cat size_nseq. qed.

lemma c10_wit_neq : c10_wit1 <> c10_wit2.
proof. by apply (neq_from_nth 0 _ _ 29); rewrite c10_wit1_29 c10_wit2_29. qed.

lemma c10_code_nonempty : exists (x : codeword), c10_code x.
proof. by exists c10_wit1; exact c10_wit1_code. qed.

lemma c10_code_two_distinct :
  exists (x x' : codeword), c10_code x /\ c10_code x' /\ x <> x'.
proof.
exists c10_wit1 c10_wit2.
by rewrite c10_wit1_code c10_wit2_code c10_wit_neq.
qed.

(* The Def-9 property has ACTUAL CONTENT at C10: applied to two genuinely
   distinct members of the deployed code it yields two genuine indices. *)
lemma c10_incomparable_witnessed :
     (exists (i  : int), 0 <= i  < c10_v /\ nth 0 c10_wit1 i  < nth 0 c10_wit2 i )
  /\ (exists (i' : int), 0 <= i' < c10_v /\ nth 0 c10_wit2 i' < nth 0 c10_wit1 i').
proof.
have h := c10_incomparable.
move: h; rewrite /incomparable => h.
by apply (h c10_wit1 c10_wit2 c10_wit1_code c10_wit2_code c10_wit_neq).
qed.

(* ... and here they are, explicitly, independently of the general lemma. *)
lemma c10_witnessed_explicit :
     (0 <= 30 < c10_v /\ nth 0 c10_wit1 30 < nth 0 c10_wit2 30)
  /\ (0 <= 29 < c10_v /\ nth 0 c10_wit2 29 < nth 0 c10_wit1 29).
proof.
by rewrite /c10_v c10_wit1_30 c10_wit2_30 c10_wit1_29 c10_wit2_29.
qed.

(* -------------------------------------------------------------------------
   5b.  BOTH CONSTRAINTS ARE LOAD-BEARING (guards against a vacuous read of
        `tsw_incomparable`).
   ------------------------------------------------------------------------- *)

(* Drop the sum constraint and incomparability FAILS: [0;0] and [1;1] are
   distinct members of the cube, and [1;1] dominates [0;0] everywhere.
   So `tsw_incomparable` genuinely uses `sumz x = T`. *)
lemma cube3_not_incomparable : ! incomparable 2 (cube_code 2 3).
proof.
apply/negP; rewrite /incomparable => h.
have hc0 : cube_code 2 3 [0; 0] by rewrite /cube_code /=; smt().
have hc1 : cube_code 2 3 [1; 1] by rewrite /cube_code /=; smt().
have [_ [i' [rng_i' lt_i']]] := h [0; 0] [1; 1] hc0 hc1 _; first by smt().
have e0 : nth 0 [1; 1] 0 = 1 by done.
have e1 : nth 0 [1; 1] 1 = 1 by done.
have f0 : nth 0 [0; 0] 0 = 0 by done.
have f1 : nth 0 [0; 0] 1 = 0 by done.
smt().
qed.

(* The digit bound really is base 8 (w = 3 BITS), not base 256.  This vector
   has length 43 and sum 205 -- it passes both other constraints -- but
   contains the digit 8 and is REJECTED. *)
op c10_baddigit : codeword = (8 :: nseq 28 7) ++ (1 :: nseq 13 0).

lemma c10_baddigit_size : size c10_baddigit = c10_v.
proof. by rewrite /c10_baddigit /c10_v size_cat /= !size_nseq. qed.

lemma c10_baddigit_sum : sumz c10_baddigit = c10_T.
proof.
by rewrite /c10_baddigit /c10_T sumz_cat !sumz_cons !sumz_nseq.
qed.

lemma c10_baddigit_notin : ! c10_code c10_baddigit.
proof.
by rewrite /c10_code /tsw_code /c10_baddigit c10_base all_cat /=.
qed.

(* ==========================================================================
   6.  THE QUANTIFICATION GAP, MECHANIZED
   ==========================================================================
   MM45's shape (FV-SPHINCSPLUS-EC/proofs/WOTS_TW_ES.ec:572), transcribed
   LOCALLY and parametrically -- this file deliberately does not require the
   vendored tree.
   ========================================================================== *)

op mm45_two_encodings (v : int) (enc : 'm -> codeword) : bool =
  forall (m m' : 'm),
    m <> m' =>
      exists (i : int), 0 <= i < v /\ nth 0 (enc m) i < nth 0 (enc m') i.

(* Quantifying over distinct MESSAGES forces the encoding to be INJECTIVE.
   THIS is the artifact: it is what makes the deployed C10 geometry
   unsatisfiable (2^128 messages cannot inject into a 2^123.76 antichain). *)
lemma mm45_forces_injectivity (v : int) (enc : 'm -> codeword) :
  mm45_two_encodings v enc => forall (m m' : 'm), enc m = enc m' => m = m'.
proof.
rewrite /mm45_two_encodings => h m m' eq_enc.
case: (m = m') => // nem.
have [i [rng_i lt_i]] := h m m' nem.
by move: lt_i; rewrite eq_enc /#.
qed.

lemma mm45_excludes_noninjective (v : int) (enc : 'm -> codeword) :
  (exists (m m' : 'm), m <> m' /\ enc m = enc m') => ! mm45_two_encodings v enc.
proof.
move=> [m m' [nem eq_enc]]; apply/negP => h.
by have := mm45_forces_injectivity v enc h m m' eq_enc.
qed.

(* THE SEPARATION AT DEPLOYED C10 GEOMETRY.  The C10 code is Def-9-admissible
   AND there is a many-to-one encoding whose image lies inside it -- which
   therefore REFUTES the MM45-shaped hypothesis.  Def 9 accommodates what
   MM45's quantifier forbids.  (The code is non-degenerate: it has at least
   two distinct members, `c10_code_two_distinct`, so the Def-9 half of this
   statement is not vacuously true.)

   READ THE WITNESS HONESTLY -- BOTH EXTERNAL REVIEWERS FLAGGED THIS, AND
   THEY WERE RIGHT.  The encoder below is the CONSTANT map on `bool`, which
   is the WEAKEST possible witness: over a two-element message type,
   non-injectivity FORCES constancy, so its image is a SINGLE codeword and
   the antichain structure is never exercised at all.  This lemma would stay
   true with any non-empty code -- even a totally ordered one -- substituted
   for `c10_code` in the second conjunct.  It establishes the bare LOGICAL
   non-implication (the Def-9 code condition does not force MM45 injectivity)
   and nothing more.  `c10_def9_vs_mm45_nondeg` below is the witness that
   actually exercises the geometry; prefer citing THAT one. *)
lemma c10_def9_vs_mm45 :
     incomparable c10_v c10_code
  /\ (exists (enc : bool -> codeword),
           (forall (m : bool), c10_code (enc m))
        /\ (exists (m m' : bool), m <> m' /\ enc m = enc m')
        /\ ! mm45_two_encodings c10_v enc).
proof.
split; first exact c10_incomparable.
exists (fun (_ : bool) => c10_wit1); split; first by move=> m /=; exact c10_wit1_code.
split; first by exists true false.
by apply mm45_excludes_noninjective; exists true false.
qed.

(* THE NON-DEGENERATE SEPARATION.  Three messages, image = {c10_wit1,
   c10_wit2}: the encoder is genuinely many-to-one (1 and 2 collide) AND its
   image contains TWO DISTINCT codewords that are mutually incomparable in
   BOTH directions (`c10_incomparable_witnessed`, re-exposed here as the last
   conjunct).  So the refutation of the MM45-shaped hypothesis survives even
   when the encoder is required to reach more than one codeword -- which is
   what the constant witness above cannot show.  STILL NOT the counting
   argument: this says nothing about encoders on a 2^128-element message
   space, and `enc3` is of course not T-COLL-RES-secure. *)
op enc3 (m : int) : codeword = if m = 0 then c10_wit1 else c10_wit2.

lemma c10_def9_vs_mm45_nondeg :
     (forall (m : int), c10_code (enc3 m))
  /\ (exists (m m' : int), m <> m' /\ enc3 m = enc3 m')
  /\ (exists (m m' : int), enc3 m <> enc3 m')
  /\ ! mm45_two_encodings c10_v enc3
  /\ (exists (i i' : int),
           0 <= i  < c10_v /\ nth 0 (enc3 0) i  < nth 0 (enc3 1) i
        /\ 0 <= i' < c10_v /\ nth 0 (enc3 1) i' < nth 0 (enc3 0) i').
proof.
split.
+ by move=> m; rewrite /enc3; case: (m = 0) => _; [exact c10_wit1_code | exact c10_wit2_code].
split; first by exists 1 2; rewrite /enc3.
split; first by exists 0 1; rewrite /enc3 /= c10_wit_neq.
split; first by apply mm45_excludes_noninjective; exists 1 2; rewrite /enc3.
exists 30 29; rewrite /enc3 /= /c10_v.
by rewrite c10_wit1_30 c10_wit2_30 c10_wit1_29 c10_wit2_29.
qed.

(* ==========================================================================
   7.  DEFINITION 11  --  T-COLL-RES FOR IE            (paper :863-:891)
   ==========================================================================
   STATED, NOT PROVEN.  This is a GAME, not an axiom: this file declares no
   axiom, and nothing below is used by any proof above.  It becomes a NAMED
   LEDGER ASSUMPTION for the later WOTS swap, to be discharged in the game
   hop described in the header's ORDERING REQUIREMENT block (paper Game.2,
   :1134-:1152) -- BEFORE any Def-9 case split.

   Paper text, transcribed:
     1. Sample parameters P from P.
     2. Run A with input P and (classical) access to an oracle that takes as
        input m, ep and is defined as follows:
        (a) If there exists an entry (m', rho, ep, x) in L (with the same ep)
            or |L| >= p, then return BOT.
        (b) Set ctr := 0 and x := BOT.  While ctr < K and x = BOT:
              i. Sample rho from R.  ii. Set x := IncEnc(P, m, rho, ep).
              iii. Set ctr := ctr + 1.
        (c) If x = BOT, insert (m, BOT, ep, BOT) into L and return BOT.
        (d) Else (note: x in C), insert (m, rho, ep, x) into L and return
            (x, rho).
     3. Get from A a triple (mS, rhoS, epS).  Compute xS := IncEnc(P, mS, rhoS, epS).
     4. Output 1 iff there is a pair (m, rho) <> (mS, rhoS) with
        (m, rho, epS, xS) in L.

   Adv^{T-COLL-RES,K}_{IncEnc,p}(A) := Pr[ T_COLL_RES(A).main() @ &m : res ].

   See modelling choices M1 (BOT in the randomness slot), M2 (K, p abstract
   and unconstrained) and M3 (K is the ORACLE's budget) in the header.
   ========================================================================== *)

op dparam : param distr.   (* the distribution "P from P" of step 1 *)
op drand  : rand  distr.   (* the distribution "rho from R" of step 2(b)i  *)

(* The IE under attack, abstract.  The later swap instantiates this at
   `IncEncTSW v w T` (section 4). *)
op IncEnc : param -> msg -> rand -> int -> codeword option.

op Kbudget : int.   (* paper's K: regeneration budget, oracle-side (M3) *)
op pbound  : int.   (* paper's p: query budget; the paper's XMSS proof
                       instantiates it with qs, the # of signing queries *)

(* Log entries (m, rho, ep, x).  The randomness slot is an OPTION: see M1. *)
type tcoll_entry = msg * rand option * int * codeword option.

op entry_ep (e : tcoll_entry) : int = e.`3.

(* Step 4's win condition.  Requires `Some r` in the randomness slot, so a
   step-2(c) failure entry is never matched -- modelling choice M1.
   DO NOT CALL THIS "CONSERVATIVE" (an earlier revision did, and BOTH external
   reviewers flagged it in round 2 as contradicting the header's own M1
   adjudication).  It is EVENT-RESTRICTING: it makes the ADVERSARY's job
   harder, hence Adv_M1 <= Adv_permissive, hence -- read the direction
   carefully -- "Adv_M1 is small" is a WEAKER assumption than the paper's,
   i.e. EASIER to satisfy, NOT a safer one.  The risk therefore sits on the
   CONSUMER's reduction, which must exhibit a win in THIS smaller event.  See
   M1 in the header for the full adjudication and the strictness example. *)
op tcoll_win (log : tcoll_entry list) (eps : int) (xs : codeword option)
             (ms : msg) (rs : rand) : bool =
  exists (m : msg) (r : rand),
    ((m, Some r, eps, xs) \in log) /\ (m, r) <> (ms, rs).

module type TCollOracleT = {
  proc encode(m : msg, ep : int) : (codeword * rand) option
}.

module type TCollAdvT (O : TCollOracleT) = {
  proc guess(pp : param) : msg * rand * int
}.

module TCollOracle : TCollOracleT = {
  var pp  : param
  var log : tcoll_entry list

  proc init(pp0 : param) : unit = {
    pp  <- pp0;
    log <- [];
  }

  proc encode(m : msg, ep : int) : (codeword * rand) option = {
    var ctr : int;
    var r   : rand;
    var x   : codeword option;
    var out : (codeword * rand) option;

    out <- None;
    (* step 2(a): one query per epoch, and at most p entries *)
    if (! (has (fun (e : tcoll_entry) => entry_ep e = ep) log \/ pbound <= size log)) {
      (* step 2(b): regenerate at most K times *)
      ctr <- 0;
      x   <- None;
      r   <- witness;
      while (ctr < Kbudget /\ x = None) {
        r   <$ drand;
        x   <- IncEnc pp m r ep;
        ctr <- ctr + 1;
      }
      if (x = None) {
        (* step 2(c) *)
        log <- rcons log (m, None, ep, None);
        out <- None;
      } else {
        (* step 2(d) *)
        log <- rcons log (m, Some r, ep, x);
        out <- Some (oget x, r);
      }
    }
    return out;
  }
}.

module T_COLL_RES (A : TCollAdvT) = {
  proc main() : bool = {
    var pp  : param;
    var ms  : msg;
    var rs  : rand;
    var eps : int;
    var xs  : codeword option;

    pp <$ dparam;                                    (* step 1 *)
    TCollOracle.init(pp);
    (ms, rs, eps) <@ A(TCollOracle).guess(pp);       (* steps 2, 3 *)
    xs <- IncEnc pp ms rs eps;
    return tcoll_win TCollOracle.log eps xs ms rs;   (* step 4 *)
  }
}.

(* SHAPE RECEIPT (see modelling choice M6).  This lemma is a TAUTOLOGY and
   claims NOTHING about security.  Its only job is to be COMPILED, so that
   the exact form every consumer must use -- the advantage expression of
   paper :887-:891, quantified over an adversary that CANNOT touch the
   oracle's state -- is machine-checked to type-check rather than merely
   asserted in a comment.  A consumer statement that drops `{-TCollOracle}`
   would be a VACUOUS assumption, because an unrestricted EasyCrypt adversary
   may write `TCollOracle.log` and `TCollOracle.pp` directly.
   IT DOES CARRY ONE REAL FACT, and that is why it is worth compiling: it pins
   that `T_COLL_RES(A)` is INSTANTIABLE at a `{-TCollOracle}`-restricted `A`,
   i.e. the game body itself never needs `A` to read or write those globals.
   If a later edit made the game depend on the adversary touching the oracle's
   state, THIS LEMMA WOULD STOP COMPILING -- which is exactly the alarm
   wanted. *)
lemma tcoll_adv_restriction_shape (A <: TCollAdvT{-TCollOracle}) &m :
  Pr[T_COLL_RES(A).main() @ &m : res] = Pr[T_COLL_RES(A).main() @ &m : res].
proof. by []. qed.

(* ==========================================================================
   RECEIPTS
   ==========================================================================
   [G] GATE.  bash ec-certify.sh drafts/IncEnc.ec
         compile=OK  admit-tactics=0  axiom-decls=0
         CERTIFIED-0-ADMIT
       (Note on running the gate by hand: `bash scratch-ecc.sh F | tail` gives
        you TAIL's exit code, not EasyCrypt's.  Capture it as
        `out=$(bash scratch-ecc.sh F 2>&1); rc=$?` or the rc is meaningless.)

   [G2] GATE BLIND SPOT, CLOSED BY HAND.  ec-certify.sh redirects the
        compiler's own output to /dev/null, so EasyCrypt's admit WARNINGS are
        discarded and the textual grep is the ONLY admit/axiom detector -- and
        that grep matches `^\s*axiom\s+`, which would MISS `declare axiom`,
        `hypothesis`, or a `section`-scoped assumption.  Two commands close
        it, both run 2026-07-25 (second session):
          command grep -nE '^[[:space:]]*(axiom|declare|hypothesis|section)\b' \
            drafts/IncEnc.ec
            -> EXACTLY TWO hits, both INSIDE a comment: the quoted MM45
               `axiom two_encodings (m m' : msgWOTS) :` in this header, and
               the prose line "axiom, and nothing below is used by any proof
               above." in section 7.  Zero at tactic/declaration position.
               (Deliberately quoted BY CONTENT, not by line number: this
               file's own edits shift them -- they were :54/:706 before this
               receipt was added and :54/:762 after.  Match the text.)
          out=$(bash scratch-ecc.sh drafts/IncEnc.ec 2>&1); rc=$?
            -> rc=0 and the output contains NO line matching warn|admit|axiom
        So 0-axiom / 0-admit is a property of the file, not an artifact of one
        regex.  RE-RUN BOTH after any edit.

   [P] PROVENANCE-RECEIPT CORRECTION HISTORY (2026-07-25, second session).
       The header's "WHAT THIS DOES NOT ESTABLISH" paragraph originally
       carried two prose provenance claims.  An independent re-verification
       pass RAN them and BOTH FAILED to reproduce:
         (i)  "the string 205 does not occur in paper-cic-2-1-13.txt" --
              LITERALLY FALSE.  `command grep -c '205'` returns 1; the hit is
              the DOI substring "10.62056" on line 1.  The substance (205 is
              not a paper parameter) SURVIVES, but only under the
              word-boundary command now recorded at (c), which is empty.
         (ii) "the 2^23.25 grind figure ... comes from ... params.rs" --
              UNFOLLOWABLE.  Nothing in params.rs matches 23.25 or 10^7.  The
              real source is fors.rs:130, now recorded at (d).
       Both are DOCUMENTATION-ONLY: no lemma, proof, or receipt of the
       mechanized content depended on either, and the gate result is
       unchanged (re-certified after the fix).  They are logged here rather
       than silently patched because "a receipt nobody re-ran" is this
       project's recurring failure mode, and the fix is to state provenance
       AS COMMANDS WITH OUTPUT -- which (a)-(d) now do.
       Also re-verified in the same pass, and these DID reproduce exactly:
       the four canaries C1-C4 that existed at that point (all rc=1; C5 was
       added later in the same session, see [C5]), probes 6/7 (parse error at the
       `{`, line 68) and 8 (rc=0), both [L] leaf greps (empty), Def 9 at
       :839-:848, Def 11 at :863-:891, Construction 6 at :1533-:1556,
       Lemma 7 at :1558-:1587, Game.2 at :1134-:1156 with the bound
       instantiated at qs, Game.3 + the Def-9 case split at :1173-:1199, and
       MM45 `two_encodings` at WOTS_TW_ES.ec:572 with exactly two consumers
       at :582 and :1305.  The paper .txt sha256 also matches the header.

   [L] LEAF.  No file in drafts/ and no file in the vendored base requires
       this one, so a stale-.eco (trap T2) whole-chain re-gate is not needed.
       Receipt -- both of these are EMPTY:
           command grep -rn "require.*IncEnc" drafts/ FV-SPHINCSPLUS-EC/proofs/ \
             | command grep -v 'drafts/IncEnc.ec:'
           command grep -rln IncEnc drafts/ | command grep -v 'IncEnc\.ec'
       (A plain `command grep -rn IncEnc drafts/` is NOT a valid leaf receipt:
        it self-matches on this file's own name and prose -- and the first
        command above self-matches on THIS VERY LINE unless the file itself
        is excluded, which is why the exclusion is part of the receipt.)
       The ONLY requirers anywhere are the FIVE canaries C1-C5 in
       scratch/incenc/ below, which exist precisely to be rejected.
       CONSEQUENCE OF T2: if this file is edited, ALL FIVE canaries must be
       RE-RUN, because their .eco would otherwise be stale against the new
       IncEnc.eco.  (The count was four before the second session added C5
       alongside `c10_def9_vs_mm45_nondeg`; if you add another lemma with a
       negative control, update this number too -- a stale count here is the
       same class of defect as the stale line numbers logged in [P].)

   [C1] CANARY -- gate liveness.  scratch/incenc/canary1_false.ec
        `lemma canary_false : false. proof. by []. qed.`
        MUST BE REJECTED.  Observed rc=1:
          [critical] [scratch/incenc/canary1_false.ec: line 5 (7-13)]
                     [by]: cannot close goals

   [C2] CANARY -- the sum constraint is load-bearing.
        scratch/incenc/canary2_cube.ec asserts
          lemma canary_cube : incomparable 2 (cube_code 2 3).
        i.e. incomparability for the FULL CUBE with the sum constraint
        DROPPED, discharged by
          smt(tsw_incomparable dominated_eqsum_eq cube3_not_incomparable)
        -- SMT is handed the general Lemma-7 result, its kernel, AND the
        negation of the goal, so a success would have meant an inconsistency.
        MUST BE REJECTED (the negation is PROVEN in this file as
        `cube3_not_incomparable`).  Observed rc=1:
          [critical] [scratch/incenc/canary2_cube.ec: line 9 (7-71)]
                     cannot prove goal (strict)

   [C3] CANARY -- pins the base.  scratch/incenc/canary3_base9.ec asserts
          lemma canary_base9 : 2 ^ c10_w = 9.
        by the SAME script that proves `c10_base : 2 ^ c10_w = 8` in this
        file, so it also shows `c10_base` is not an artifact of a tactic that
        proves anything.  MUST BE REJECTED.  Observed rc=1:
          [critical] [scratch/incenc/canary3_base9.ec: line 6 (7-32)]
                     cannot prove goal (strict)

   [C4] CANARY -- the digit bound is load-bearing (base 8, not base 256).
        scratch/incenc/canary4_baddigit.ec asserts
          lemma canary_baddigit : c10_code c10_baddigit.
        for the length-43, sum-205 vector that contains the digit 8 (both of
        those facts are PROVEN here as c10_baddigit_size / c10_baddigit_sum
        and are handed to SMT).  MUST BE REJECTED.  Observed rc=1:
          [critical] [scratch/incenc/canary4_baddigit.ec: line 7 (7-61)]
                     cannot prove goal (strict)

   [M6] ADVERSARY-RESTRICTION EVIDENCE.  The claim in modelling choice M6
        that the restriction cannot be attached to the game functor's
        parameter is a RUN RESULT, not an assumption:
          scratch/incenc/probe6.ec  `(A : TCollAdvT{-TCollOracle})`  -> rc=1
            [critical] [scratch/incenc/probe6.ec: line 68 (32-33)] parse error
          scratch/incenc/probe7.ec  `(A : TCollAdvT {-TCollOracle})` -> rc=1
            [critical] [scratch/incenc/probe7.ec: line 68 (33-34)] parse error
          In BOTH probes line 68 is the game-functor header
            module T_COLL_RES (A : TCollAdvT{-TCollOracle}) = {
          (probe7 with a space before the brace), and the reported column is
          the `{`.  Both probes are `sed`-derived copies of probe5.ec, so if
          probe5.ec is ever edited these line numbers go stale -- the line
          CONTENT above, not the number, is the receipt.
        The lemma-level form DOES compile: scratch/incenc/probe8.ec, rc=0,
        and it is carried in this file as `tcoll_adv_restriction_shape`.
        The vendored base uses the same discipline -- unrestricted functor
        parameters (FL_SL_XMSS_MT_ES.ec:1832, FORS_ES.ec:2007) with the
        restriction on the lemma quantifier (FORS_ES.ec:571).

   [XR] EXTERNAL ADVERSARIAL REVIEW (2026-07-25).  Reviewed by GPT-5.6
        (codex, read-only) and Kimi K3, both given file:line and told to read
        the paper .txt.  Both independently confirmed Q1/Q2/Q3/Q5/Q7 clean
        (Def 9 and Construction 6 faithful; `tsw_incomparable` a genuine
        parametric proof; C10 witness arithmetic correct by hand; leaf,
        0-axiom, 0-admit).  Findings ADOPTED into this file: the M1 direction
        was stated backwards and is rewritten; "both constraints are
        load-bearing" was wrong for incomparability and is split; the leaf
        and canary counts were unqualified/wrong; `is_IE` was renamed
        `is_IE_code`; M2 was expanded to the full deferred-side-condition
        list; M6 (adversary memory restriction) and M7 (unconstrained thmsg)
        were added; three paper citations were off by one and are corrected
        (verified at source, not taken on trust).  THE ONE DISAGREEMENT: on
        M1, GPT-5.6 said the "conservatism" claim was backwards, Kimi said it
        was correct.  Adjudicated in M1 above: both are right about different
        things -- Adv_M1 <= Adv_paper makes the ASSUMPTION weaker (Kimi), and
        that is precisely why the risk sits on the REDUCTION side (GPT-5.6);
        the paper's own B2 is unaffected only because verification forces
        x* in C, an invariant NOT proven here.

   [C5] CANARY -- the NON-DEGENERATE separation really refutes MM45.
        scratch/incenc/canary5_enc3_mm45.ec asserts
          lemma canary_enc3_mm45 : mm45_two_encodings c10_v enc3.
        i.e. the NEGATION of the fourth conjunct of
        `c10_def9_vs_mm45_nondeg`, with that lemma AND
        `mm45_forces_injectivity` AND `mm45_excludes_noninjective` handed to
        SMT -- so a success would have meant an inconsistency.
        MUST BE REJECTED.  Observed rc=1:
          [critical] [scratch/incenc/canary5_enc3_mm45.ec: line 9 (7-87)]
                     cannot prove goal (strict)
        (Added in the second session together with the lemma it guards.  Same
        T2 consequence as C1-C4: re-run it after ANY edit to this file.)

   [XR2] EXTERNAL ADVERSARIAL REVIEW, ROUND 2 (2026-07-25, second session).
        Round 1 (see [XR]) reviewed an EARLIER revision and its findings were
        adopted; round 2 re-reviewed the FINAL text with both models, scoped
        to (1) the M1 adjudication -- the one place round 1 DISAGREED and the
        file adjudicated rather than resolved -- (2) the rewritten provenance
        receipts, (3) the Lemma-7 proof, (4) the scope of "admissible", and
        (5) non-vacuity / game fidelity.
        UNCHANGED BY ROUND 2: items (3) and (5).  Both models independently
        audited every tactic of `dominated_eqsum_eq` / `tsw_incomparable`,
        confirmed no `smt()` does unjustified work (the hardest, `eq_ab`, is
        exactly the paper's "T = sum > sum = T" step), confirmed `incomparable`
        faithfully transcribes Def 9's quantification over distinct CODEWORDS
        IN C at :845-:848, and confirmed the Def-11 game implements steps
        2(a)-2(d), 3, 4 with M1 as the ONLY deviation.
        M1 ADJUDICATION UPHELD: the direction Adv_M1 <= Adv_paper is correct
        and both conclusions follow.  Round 2 ADDED the strictness example
        (unconstrained `IncEnc` returning None always => Adv_M1 = 0 while the
        permissive game is 1), found independently by BOTH models, now folded
        into M1 as the strongest argument for the "VARIANT M1" rename.
        FINDINGS ADOPTED (all were real; verified at source before acting):
          - "CONSERVATIVE" survived on the `tcoll_win` comment, contradicting
            the header's own M1 adjudication.  BOTH models.  Fixed.
          - Receipt (a): W/LOG_W line numbers were :44/:47, actually :43/:46.
            BOTH models.  Fixed, and re-expressed AS A COMMAND.
          - Receipt (b): "4008.53 (:2143)" is :2142; both table ranges clipped
            the second lifetime block.  BOTH models.  Fixed.
          - Receipt (d): WRONG LAYER.  GPT-5.6 only.  The FORS R-grind
            (fors.rs) is not the encoding layer; the paper's rho/K analogue is
            the WOTS+C count grind (wots.rs:62).  Both caps are 10^7, which is
            why it looked right.  Rewritten; see (d).
          - M2's "in full" list omitted uniformity of `drand`.  GPT-5.6 only.
            Added, with the point-mass distortion argument.
          - The x* = BOT unwinnability claim is FALSE for an unrestricted
            adversary (it can plant a log entry).  GPT-5.6 only.  Qualified.
          - M6 cited FORS_ES.ec:571 as compiled precedent; that line is INSIDE
            A COMMENT.  GPT-5.6 only.  Replaced with the base's real
            discipline, the section-level `declare module` at
            FORS_ES.ec:2809-:2818.
          - `c10_def9_vs_mm45`'s constant witness is degenerate.  BOTH models.
            Kept (it is still a valid countermodel) but relabelled honestly,
            and `c10_def9_vs_mm45_nondeg` was ADDED as the witness that
            actually exercises the geometry.
        THE ONE DISAGREEMENT: receipt (d).  GPT-5.6 called it materially
        wrong; Kimi K3 called it CLEAN with a minor nuance.  ADJUDICATED IN
        GPT-5.6's FAVOUR, by reading the source rather than either review:
        wots.rs:1-5 and :62 are explicitly the target-sum reject-and-retry
        loop, which is Construction 6; fors.rs:98-130 forces the last FORS
        index to zero, which is a different mechanism entirely.  Kimi
        independently reached the same "not randomness" nuance (its H5) via
        the sister document, so the two agree on the entropy point and differ
        only on which subsystem to cite.
        ENVIRONMENTAL CAVEAT, recorded because it matters for how much the
        round-2 canary evidence is worth: GPT-5.6's sandbox blocked Why3's
        socket, so ITS canary C2-C4 runs returned rc=1 for an infrastructure
        reason, NOT a semantic rejection -- rc=1 alone is not a canary
        receipt.  Kimi's runs and this session's runs (in the ec-grind
        container, with the full diagnostics matching [C1]-[C4] verbatim) are
        the actual evidence.

   [NV] NON-VACUITY (in-file, proven): c10_code_nonempty,
        c10_code_two_distinct, c10_incomparable_witnessed,
        c10_witnessed_explicit, cube3_not_incomparable, c10_baddigit_notin,
        and (second session) c10_def9_vs_mm45_nondeg -- the last being the one
        that shows the MM45 separation is not carried by a degenerate
        constant encoder.
        The Def-11 game is NOT covered by these: it is stated, and its own
        non-vacuity (that some adversary/IncEnc makes the win event
        reachable) is deliberately NOT established at this milestone.  The
        cheapest first step toward it is the x* = BOT invariant written out
        under M1 ("NEXT RECEIPT TO CONVERT"), which needs M6's memory
        restriction to be sound.
   ========================================================================== *)
