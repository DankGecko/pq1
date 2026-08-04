(* - Require/Import - *)
(* -- Built-In (Standard Library) -- *)
require import AllCore List Distr DList DMap StdOrder StdBigop IntDiv RealExp FinType BitEncoding.
require (*--*) DigitalSignatures.
(*---*) import BS2Int BitChunking.
(*---*) import IntOrder Bigint BIA.

(* -- Local -- *)
require import BinaryTrees MerkleTrees.
require (*--*) KeyedHashFunctions TweakableHashFunctions HashAddresses.
require (*--*) WOTS_TW_ES.


(* - Parameters - *)
(* -- General -- *)
(*
  Length of (integer lists corresponding to) addresses used in tweakable hash functions
  (including unspecified global/context part)
*)
const adrs_len : { int | 6 <= adrs_len} as ge6_adrslen.

(*
  Length (in bytes) of messages as well as the length of elements of
  private keys, public keys, and signatures
*)
const n : { int | 1 <= n } as ge1_n.


(* -- WOTS-TW -- *)
(* Base 2 logarithm of the Winternitz parameter w *)
(* F1 EXPERIMENT: mirrors the relaxation in WOTS_TW_ES.ec *)
const log2_w : { int | 2 <= log2_w } as val_log2w.

(* Winternitz parameter (base/radix) *)
const w = 2 ^ log2_w.

(* Length of the message in base/radix w *)
(* len1 dropped: +C has no checksum split *)

(* Length of the checksum in base/radix w *)
(* len2 dropped: +C has no checksum *)

(* Number of elements (of length n) in private keys, public keys, and signatures *)
(* +C GEOMETRY CHANGE: WOTS+C has NO checksum, so `len` is an independent
   parameter (C10: 43), not `len1 + len2` (which would give 46).  MM45's
   checksum never enters the proof BODY -- the encoding is abstract and
   constrained only by `two_encodings`; len1/len2 existed solely to define
   `len` and to derive `ge2_len`.  Making `len` primitive with `2 <= len`
   supplies `ge2_len` (used 160x chain-wide) directly and dissolves the
   whole checksum chain -- INCLUDING the false `val_len1`. *)
const len : { int | 2 <= len } as ge2_len.


(* -- FL-SL-XMSS(-MT)-TW -- *)
(* Height of a single inner (XMSS) tree  *)
const h' : { int | 1 <= h' } as ge1_hp.

(* Number of WOTS-TW instances of a single inner (XMSS) tree (i.e., number of leaves) *)
const l' = 2 ^ h'.

(* Number of layers in the hypertree (i.e., height of tree of XMSS trees) *)
const d : { int | 1 <= d } as ge1_d.

(*
  Height of "flattened" hypertree (i.e., total height of concatenation of inner trees)
*)
const h : int = h' * d.

(*
  Number of leaves of "flattened" hypertree
  (i.e., total number of leaves of all inner trees on bottom layer)
*)
const l : int = 2 ^ h.


(* -- Address types -- *)
(* Address type for chaining (used in tweakable hash function calls of WOTS-TW chains) *)
const chtype : int.

(*
  Address type for public (WOTS-TW) key compression
  (used in tweakable hash function calls of WOTS-TW public key compression)
*)
const pkcotype : int.

(* Address type for tree hashing (used in tweakable hash function calls of inner hash trees) *)
const trhtype : int.


(* -- Properties of parameters -- *)
(* The different address types are distinct *)
axiom dist_adrstypes : chtype <> pkcotype /\ chtype <> trhtype /\ pkcotype <> trhtype.

(* l' is greater than or equal to 2 *)
lemma ge2_lp : 2 <= l'.
proof. by rewrite /l' ler_eexpr 2://; smt(ge1_hp). qed.

(* h is greater than or equal to 1 *)
lemma ge1_h : 1 <= h.
proof. by rewrite /h mulr_ege1 1:ge1_hp ge1_d. qed.

(* l is greater than or equal to 1 *)
lemma ge2_l : 2 <= l.
proof. rewrite /l ler_eexpr 2://; smt(ge1_h). qed.



(* - Types (1/3) - *)
(* -- General -- *)
(* Index *)
clone import Subtype as Index with
  type T <= int,
    op P i <= 0 <= i < l

  proof *.
  realize inhabited by exists 0; smt(ge2_l).

type index = Index.sT.

(* Secret seeds *)
type sseed.

(* Public seeds *)
type pseed.

(* Digests, i.e., outputs of (tweakable) hash functions. *)
type dgst = bool list.

(* Digests with length 1 (block of 8 * n bits) *)
clone import Subtype as DigestBlock with
  type T   <= dgst,
    op P x <= size x = 8 * n

  proof *.
  realize inhabited by exists (nseq (8 * n) witness); smt(size_nseq ge1_n).

type dgstblock = DigestBlock.sT.

(* Finiteness of dgstblock *)
clone import FinType as DigestBlockFT with
  type t <= dgstblock,

    op enum <= map DigestBlock.insubd (map (int2bs (8 * n)) (range 0 (2 ^ (8 * n))))

  proof *.
  realize enum_spec.
    move=> m; rewrite count_uniq_mem 1:map_inj_in_uniq => [x y | |].
    + rewrite 2!mapP => -[i [/mem_range rng_i ->]] -[j [/mem_range rng_j ->]] eqins.
      rewrite -(DigestBlock.insubdK (int2bs (8 * n) i)) 1:size_int2bs; 1: smt(ge1_n).
      rewrite -(DigestBlock.insubdK (int2bs (8 * n) j)) 1:size_int2bs; 1: smt(ge1_n).
      by rewrite eqins.
    + rewrite map_inj_in_uniq => [x y /mem_range rng_x /mem_range rng_y|].
      rewrite -{2}(int2bsK (8 * n) x) 3:-{2}(int2bsK (8 * n) y) //; 1,2: smt(ge1_n).
      by move=> ->.
    + by rewrite range_uniq.
    rewrite -b2i1; congr; rewrite eqT mapP.
    exists (DigestBlock.val m).
    rewrite DigestBlock.valKd mapP /=.
    exists (bs2int (DigestBlock.val m)).
    rewrite mem_range bs2int_ge0 /=.
    rewrite (: 8 * n = size (DigestBlock.val m)) 1:DigestBlock.valP 1://.
    by rewrite bs2intK bs2int_le2Xs.
  qed.



(* - Operators (1/3) - *)
(* -- Auxiliary -- *)
(* Number of nodes in a (XMSS) binary tree (of total height h') at a particular height h'' *)
op nr_nodes (h'' : int) = 2 ^ (h' - h'').

(*
  Number of trees in hypertree (with d layers) at a particular layer d'.
  Note that each "node" (i.e., inner tree) of the hypertree creates 2 ^ h' children, not 2.
  Furthermore, note that the number of layers is always one more than the height.
  This is because the number of layers increases with each level containing nodes,
  while height increases with each edge between layers.
  (So, in a sense, the final layer does contribute to the number of layers
  but does not contribute to the height)
*)
op nr_trees (d' : int) = 2 ^ (h' * (d - d' - 1)).

(*
  Number of nodes in "flattened" hypertree (with d layers and inner trees of height h') at
  a particular layer d' and (inner) height h''.
*)
op nr_nodes_ht (d' h'' : int) = nr_trees d' * nr_nodes h''.

(* Alternative expression for nr_nodes_ht using total height of hypertree (h) *)
lemma nrnodesht_h (d' h'' : int) :
     d' < d
  => h'' <= h'
  => nr_nodes_ht d' h'' = 2 ^ (h - d' * h' - h'').
proof.
move=> gtdp_d gehpp_hp.
rewrite /nr_nodes_ht /nr_trees /nr_nodes /h -exprD_nneg; 2: smt().
+ by rewrite mulr_ge0; smt(ge1_hp).
by congr; ring.
qed.

(*
  Number of nodes in "flattened" hypertree at a particular layer d'
  and (inner) height 0 is equal to the number of trees in layer d' - 1
*)
lemma nrnodesht_nrtrees (d' : int) :
     0 < d' < d
  => nr_nodes_ht d' 0 = nr_trees (d' - 1).
proof.
move => -[gt0_dp ltd_dp].
by rewrite /nr_trees nrnodesht_h //= /h; smt(ge1_hp).
qed.

(* The number of inner trees in the bottom d' layers is greater than or equal to 1. *)
lemma ge1_bigitrees (d' : int) :
     0 < d' <= d
  => 1 <= bigi predT nr_trees 0 d'.
proof.
move=> [gt0_dp led_dp]; rewrite (: d' = d' - 1 + 1) 1:// big_int_recr 1:/#.
rewrite -{1}add0r ler_add; last first.
+ by rewrite /nr_trees {1}(: 1 = 0 + 1) 1:// -ltzE expr_gt0.
rewrite sumz_ge0 filter_predT allP => x /mapP [x' [/mem_range [ge0_x _] ->]].
by rewrite /nr_trees expr_ge0.
qed.


(* -- Validity checks for (indices corresponding to) XMSS-MT-TW addresses -- *)
(* Layer index validity check (note: regards hypertree) *)
op valid_lidx (lidx : int) : bool =
  0 <= lidx < d.

(*
  Tree index validity check
  (Note: regards hypertree; i.e., is tidx a valid index for pointing to a tree in layer lidx)
*)
op valid_tidx (lidx tidx : int) : bool =
  0 <= tidx < nr_trees lidx.

(*
(* Type index validity check *)
op valid_typeidx (typeidx : int) : bool =
  typeidx = chtype \/ typeidx = pkcotype \/ typeidx = trhtype.
*)

(* Key pair index validity check (note: regards inner tree) *)
op valid_kpidx (kpidx : int) : bool =
  0 <= kpidx < l'.

(* Tree height index validity check (note: regards inner tree) *)
op valid_thidx (thidx : int) : bool =
  0 <= thidx <= h'.

(* Tree breadth index validity check (note: regards inner tree) *)
op valid_tbidx (thidx tbidx : int) : bool =
  0 <= tbidx < nr_nodes thidx.

(* Chain index validity check *)
op valid_chidx (chidx : int) : bool =
  0 <= chidx < len.

(* Hash index validity check *)
op valid_hidx (hidx : int) : bool =
  0 <= hidx < w - 1.

(* Chaining address indices validity check (local part) *)
op valid_xidxvalslpch (adidxs : int list) : bool =
     valid_hidx (nth witness adidxs 0)
  /\ valid_chidx (nth witness adidxs 1)
  /\ valid_kpidx (nth witness adidxs 2)
  /\ nth witness adidxs 3 = chtype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ valid_lidx (nth witness adidxs 5).

(* Public-key compression address indices validity check (local part) *)
op valid_xidxvalslppkco (adidxs : int list) : bool =
     nth witness adidxs 0 = 0
  /\ nth witness adidxs 1 = 0
  /\ valid_kpidx (nth witness adidxs 2)
  /\ nth witness adidxs 3 = pkcotype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ valid_lidx (nth witness adidxs 5).

(* Tree hashing address indices validity check (local part)*)
op valid_xidxvalslptrh (adidxs : int list) : bool =
     valid_tbidx (nth witness adidxs 1) (nth witness adidxs 0)
  /\ valid_thidx (nth witness adidxs 1)
  /\ nth witness adidxs 2 = 0
  /\ nth witness adidxs 3 = trhtype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ valid_lidx (nth witness adidxs 5).

(* Local address indices validity check *)
op valid_xidxvalslp (adidxs : int list) : bool =
  valid_xidxvalslpch adidxs \/ valid_xidxvalslppkco adidxs \/ valid_xidxvalslptrh adidxs.

(*
  Validity check for the values of the list of integers corresonding to addresses used in
  the encompassing structure.
  As the encompassing structure is abstract, many of the valid
  addresses may be unknown (as their validity is defined by this unknown structure).
  For this reason, the validity check is left abstract.
*)
op valid_idxvals : int list -> bool.

(*
  Overall validity check for the list of integers corresponding to addresses used in the
  encompassing structure. This checks for the correct length and valid values.
*)
op valid_adrsidxs (adidxs : int list) =
  size adidxs = adrs_len /\ valid_idxvals adidxs.

(*
  Validity check for the values of the global/context part of the list of integers
  corresponding to FL-SL-XMSS-MT-TW addresses used in the
  encompassing structure. This global/context part is the part that is to be defined
  by this unknown structure and, therefore, this validity check is left abstract.
*)
op valid_xidxvalsgp : int list -> bool.

(*
  Validity check for the values of the list of integers corresponding to
  FL-SL-XMSS-MT-TW addresses used in the encompassing structure.
  This includes the local part that we defined, and the abstract global/context part
  defined by the unknown structure.
*)
op valid_xidxvals (adidxs : int list) =
  valid_xidxvalsgp (drop 6 adidxs) /\ valid_xidxvalslp (take 6 adidxs).

(*
  Overall validity check for the list of integers corresponding to
  FL-SL-XMSS-MT-TW addresses used in the encompassing structure.
  This checks for the correct length and valid values.
*)
op valid_xadrsidxs (adidxs : int list) =
  size adidxs = adrs_len /\ valid_xidxvals adidxs.

(*
  The list of integers that correspond to FL-SL-XMSS-MT-TW addresses are a subset of
  the list of integers that correspond to valid addresses. (In other words,
  the FL-SL-XMSS-MT-TW addresses are a subset of the complete set of valid addresses
  used in the encompassing structure.)
*)
axiom valid_xidxvals_idxvals :
  valid_xidxvals <= valid_idxvals.

(*
  The FL-SL-XMSS-MT-TW addresses are a subset of the complete set of valid addresses
  used in the encompassing structure.
*)
lemma valid_xadrsidxs_adrsidxs :
  valid_xadrsidxs <= valid_adrsidxs.
proof.
rewrite /(<=) /valid_xadrsidxs /valid_adrsidxs => adidxs [-> /=].
by apply valid_xidxvals_idxvals.
qed.



(* - Distributions (1/2) - *)
(* Proper distribution over public seeds *)
op [lossless] dpseed : pseed distr.

(* Proper distribution over (single) digestblocks  *)
op [lossless] ddgstblock : dgstblock distr.



(* - Types (2/3) - *)
(*
  Addresses used in encompassing structure (complete set, including
  FL-SL-XMSS-MT-TW addresses)
*)
clone import HashAddresses as HA with
  type index <= int,
    op l <- adrs_len,
    op valid_idxvals <- valid_idxvals,
    op valid_adrsidxs <- valid_adrsidxs

    proof ge1_l.
    realize ge1_l by smt(ge6_adrslen).

import Adrs.

type adrs = HA.adrs.



(* - Operators (2/3) -- *)
(* -- Tweakable hash functions -- *)
(*
  Tweakable hash function collection that contains all tweakable hash functions
  used in FORS-TW, FL-SL-XMSS-MT-TW, and SPHINCS+
*)
op thfc : int -> pseed -> adrs -> dgst -> dgstblock.

(*
  Tweakable hash function used for the compression of public (WOTS-TW) keys to leaves
  of inner trees
*)
op pkco : pseed -> adrs -> dgst -> dgstblock = thfc (8 * n * len).

(* Import and instantiate tweakable hash function definitions for pkco *)
clone TweakableHashFunctions as PKCO with
  type pp_t <- pseed,
  type tw_t <- adrs,
  type in_t <- dgst,
  type out_t <- dgstblock,

  op f <- pkco,

  op dpp <- dpseed

  proof *.
  realize dpp_ll by exact: dpseed_ll.

clone PKCO.Collection as PKCOC with
  type diff_t <- int,

    op get_diff <- size,

    op fc <- thfc

  proof *.
  realize in_collection by exists (8 * n * len).

clone PKCOC.SMDTTCRC as PKCOC_TCR with
  op t_smdttcr <- bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d

  proof *.
  realize ge0_tsmdttcr.
  rewrite (: d = d - 1 + 1) // big_int_recr /= 2:ler_paddl; 1: smt(ge1_d).
  + rewrite sumr_ge0_seq => d' /mem_range [ge0_dp ltd_dp] _ /=.
    by rewrite nrnodesht_h 3:expr_ge0 //; 1,2: smt(ge1_h).
  by rewrite nrnodesht_h 3:expr_ge0; 1,2: smt(ge1_hp ge1_d).
  qed.

(* Tweakable hash function used for constructing inner (XMSS) trees. *)
op trh : pseed -> adrs -> dgst -> dgstblock = thfc (8 * n * 2).

(* Import and instantiate tweakable hash function definitions for trh *)
clone TweakableHashFunctions as TRH with
  type pp_t <- pseed,
  type tw_t <- adrs,
  type in_t <- dgst,
  type out_t <- dgstblock,

  op f <- trh,

  op dpp <- dpseed

  proof *.
  realize dpp_ll by exact: dpseed_ll.

clone import TRH.Collection as TRHC with
  type diff_t <- int,

    op get_diff <- size,

    op fc <- thfc

  proof *.
  realize in_collection by exists (8 * n * 2).

clone TRHC.SMDTTCRC as TRHC_TCR with
  op t_smdttcr <- bigi predT nr_trees 0 d * (2 ^ h' - 1)

  proof *.
  realize ge0_tsmdttcr.
    rewrite mulr_ge0 2:ler_subr_addr 2:-ltzE 2:expr_gt0 2://.
    by rewrite sumr_ge0 => ? _; rewrite expr_ge0.
  qed.


(* -- Validity/type checks for (indices corresponding to) XMSS-TW addresses -- *)
op valid_xidxchvals (adidxs : int list) : bool =
  valid_xidxvalsgp (drop 6 adidxs) /\ valid_xidxvalslpch (take 6 adidxs).

op valid_xidxpkcovals (adidxs : int list) : bool =
  valid_xidxvalsgp (drop 6 adidxs) /\ valid_xidxvalslppkco (take 6 adidxs).

op valid_xidxtrhvals (adidxs : int list) : bool =
  valid_xidxvalsgp (drop 6 adidxs) /\ valid_xidxvalslptrh (take 6 adidxs).

op valid_xadrschidxs (adidxs : int list) : bool =
  size adidxs = adrs_len /\ valid_xidxchvals adidxs.

op valid_xadrspkcoidxs (adidxs : int list) : bool =
  size adidxs = adrs_len /\ valid_xidxpkcovals adidxs.

op valid_xadrstrhidxs (adidxs : int list) : bool =
  size adidxs = adrs_len /\ valid_xidxtrhvals adidxs.

lemma valid_xadrsidxs_xadrschpkcotrhidxs (adidxs : int list) :
  valid_xadrsidxs adidxs
  <=>
  valid_xadrschidxs adidxs \/ valid_xadrspkcoidxs adidxs \/ valid_xadrstrhidxs adidxs.
proof. smt(). qed.

op valid_xadrsch (ad : adrs) : bool =
  valid_xadrschidxs (val ad).

op valid_xadrspkco (ad : adrs) : bool =
  valid_xadrspkcoidxs (val ad).

op valid_xadrstrh (ad : adrs) : bool =
  valid_xadrstrhidxs (val ad).

op valid_xadrs (ad : adrs) : bool =
  valid_xadrsidxs (val ad).

lemma valid_xadrs_xadrschpkcotrh (ad : adrs) :
  valid_xadrs ad
  <=>
  valid_xadrsch ad \/ valid_xadrspkco ad \/ valid_xadrstrh ad.
proof. smt(). qed.

(* Initialization ("zero") address *)
const adz : { adrs | valid_xadrs adz } as valx_adz.


(* -- Setters -- *)
op set_lidx (ad : adrs) (i : int) : adrs =
  set_idx ad 5 i.

op set_tidx (ad : adrs) (i : int) : adrs =
  set_idx ad 4 i.

op set_ltidx (ad : adrs) (i j : int) : adrs =
  insubd (put (put (val ad) 4 j) 5 i).

op set_typeidx (ad : adrs) (i : int) : adrs =
  insubd (put (put (put (put (val ad) 0 0) 1 0) 2 0) 3 i).

op set_kpidx (ad : adrs) (i : int) : adrs =
  set_idx ad 2 i.

op set_thtbidx (ad : adrs) (i j : int) : adrs =
  insubd (put (put (val ad) 0 j) 1 i).


(* -- Getters -- *)
op get_typeidx (ad : adrs) : int =
  get_idx ad 3.


(* - Clones and imports - *)
(* WOTS-TW-ES *)
clone import WOTS_TW_ES as WTWES with
    op adrs_len <- adrs_len,
    op n <- n,
    op log2_w <- log2_w,
    op w <- w,
    (* len1/len2 clone bindings dropped: +C has no checksum *)
    op len <- len,
    op c <- bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d,

  type sseed <- sseed,
  type pseed <- pseed,
  type dgst <- dgst,

    op valid_chidx <- valid_chidx,
    op valid_hidx <- valid_hidx,
    op valid_idxvals <- valid_idxvals,
    op valid_adrsidxs <- valid_adrsidxs,
    op valid_widxvalsgp adidxswgp <=    valid_kpidx (nth witness adidxswgp 0)
                                     /\ nth witness adidxswgp 1 = chtype
                                     /\ valid_tidx (nth witness adidxswgp 3) (nth witness adidxswgp 2)
                                     /\ valid_lidx (nth witness adidxswgp 3)
                                     /\ valid_xidxvalsgp (drop 4 adidxswgp),

    op thfc <- thfc,

    op dpseed <- dpseed,
    op ddgstblock <- ddgstblock,

  theory DigestBlock <- DigestBlock,
  theory DigestBlockFT <- DigestBlockFT,
  theory HA <- HA,

  type dgstblock <- dgstblock,
  type adrs <- adrs

  proof ge2_adrslen, ge1_n, val_log2w, ge2_len, ge1_c, dpseed_ll, ddgstblock_ll, valid_widxvals_idxvals.
  realize ge2_len by exact: ge2_len.
  realize ge2_adrslen by smt(ge6_adrslen).
  realize ge1_n by exact: ge1_n.
  realize val_log2w by exact: val_log2w.
  realize ge1_c.
    rewrite (: d = d - 1 + 1) // big_int_recr /= 2:ler_paddl; 1: smt(ge1_d).
    + rewrite sumr_ge0_seq => d' /mem_range [ge0_dp ltd_dp] _ /=.
      by rewrite nrnodesht_h 3:expr_ge0 //; 1,2: smt(ge1_h).
    rewrite nrnodesht_h; 1,2: smt(ge1_hp ge1_d).
    by rewrite -add0r -ltzE expr_gt0.
  qed.
  realize dpseed_ll by exact: dpseed_ll.
  realize ddgstblock_ll by exact: ddgstblock_ll.
  realize valid_widxvals_idxvals.
    rewrite /(<=) => adidxs valwadidxs; apply valid_xidxvals_idxvals.
    move: valwadidxs => @/valid_widxvals @/valid_widxvalsgp @/valid_widxvalslp.
    rewrite /valid_xidxvals /valid_xidxvalslp /valid_xidxvalslpch.
    by rewrite drop_drop //= ?nth_drop //= ?nth_take //= /#.
  qed.

import DBLL WAddress EmsgWOTS BaseW.



(* - Types (3/3) - *)
(* -- FL-SL-XMSS(-MT)-TW specific -- *)
(* Public keys *)
type pkFLXMSSMTTW = dgstblock * pseed * adrs.
type pkFLSLXMSSMTTW = pkFLXMSSMTTW.

(* Secret keys *)
type skFLSLXMSSMTTW = sseed * pseed * adrs.

(* Messages *)
type msgFLXMSSMTTW = dgstblock.   (* the hypertree signs NODES: layer k's message IS layer k-1's root *)
type msgFLSLXMSSMTTW = msgFLXMSSMTTW.

(* Lists of length h' of which the entries are digest of length 1 (block of 8 * n bits) *)
clone import Subtype as DBHPL with
  type T <= dgstblock list,
    op P ls <= size ls = h'

  proof *.
  realize inhabited by exists (nseq h' witness); rewrite size_nseq; smt(ge1_hp).

(* Authentication paths in inner (XMSS) tree *)
type apFLXMSSTW = DBHPL.sT.

(*
  Lists of length d of which the entries are sigWOTS/authentication path pairs
  (i.e., FL-SL-XMSS signatures)
*)
clone import Subtype as SAPDL with
  type T <= (sigWOTS * apFLXMSSTW) list,
    op P ls <= size ls = d

  proof *.
  realize inhabited by exists (nseq d witness); rewrite size_nseq; smt(ge1_d).

type sigFLSLXMSSMTTW = SAPDL.sT.



(* - Distributions (2/2) - *)
(* Proper distribution over messages considered for FL-SL-XMSS-MT *)
op [lossless] dmsgFLSLXMSSMTTW : msgFLSLXMSSMTTW distr.



(* - Operators (2/2) - *)
(* -- Merkle (hyper)ree -- *)
(* Update function for height and breadth indices (down the tree) *)
op updhbidx (hbidx : int * int) (b : bool) : int * int =
  (hbidx.`1 - 1, if b then 2 * hbidx.`2 + 1 else 2 * hbidx.`2).

(*
  Function ("wrapper") around trh with desired form for
  use in abstract merkle tree operators
*)
op trhi (ps : pseed) (ad : adrs) (hbidx : int * int) (x x' : dgstblock) : dgstblock =
  trh ps (set_thtbidx ad hbidx.`1 hbidx.`2) (val x ++ val x').

(*
  Computes the (hash) value corresponding to the root of a binary hash tree w.r.t.
  a certain public seed, address, height index, and breadth index.
*)
op val_bt_trh_gen (ps : pseed) (ad : adrs) (bt : dgstblock bintree) (hidx bidx : int) : dgstblock =
  val_bt (trhi ps ad) updhbidx bt (hidx, bidx).

(*
  Constructs an authentication path (without embedding it in the corresponding subtype)
  from a binary hash tree and a path represented by a boolean list w.r.t. a certain
  public seed, address, height index, and breadth index
*)
op cons_ap_trh_gen (ps : pseed) (ad : adrs) (bt : dgstblock bintree) (bs : bool list) (hidx bidx : int) : dgstblock list =
  cons_ap (trhi ps ad) updhbidx bt bs (hidx, bidx).

(*
  Computes the (hash) value corresponding to an authentication path, a leaf, and a
  path represented by a boolean list w.r.t a certain public seed, address, height index,
  and breadth index
*)
op val_ap_trh_gen (ps : pseed) (ad : adrs) (ap : dgstblock list) (bs : bool list) (leaf : dgstblock) (hidx : int) (bidx : int) : dgstblock =
  val_ap (trhi ps ad) updhbidx ap bs leaf (hidx, bidx).

(*
  Computes the (hash) value corresponding to the root of a binary hash tree using
  starting height index h' and breadth index 0, w.r.t.
  a certain public seed, address, height index, and breadth index.
*)
op val_bt_trh (ps : pseed) (ad : adrs) (bt : dgstblock bintree) : dgstblock =
  val_bt (trhi ps ad) updhbidx bt (h', 0).

(*
  Constructs authentication path (embedding it in the corresponding subtype)
  for the special case of binary hash trees of height h' and indices between
  0 (including) and 2 ^ h' (excluding) w.r.t. a certain public seed and address.
  Note that this operator does not explicitly fail when it is given arguments that do not
  conform to the above; instead, it returns witness.
*)
op cons_ap_trh (ps : pseed) (ad : adrs) (bt : dgstblock bintree) (idx : int) : apFLXMSSTW =
  DBHPL.insubd (cons_ap_trh_gen ps ad bt (rev (int2bs h' idx)) h' 0).

(*
  Computes value corresponding to an authentication path, leaf, and a path represented
  by the big-endian binary representation of an index between 0 (including)
  and 2 ^ h' (excluding) using starting height index h' and breadth index 0,
  w.r.t. a certain public seed and address. If the provided index is not actually
  in [0, 2 ^ h' - 1], the h' least significant bits of the big-endian binary
  representation of the index are used as path.
*)
op val_ap_trh (ps : pseed) (ad : adrs) (ap : apFLXMSSTW) (idx : int) (leaf : dgstblock) : dgstblock =
  val_ap_trh_gen ps ad (val ap) (rev (int2bs h' idx)) leaf h' 0.

(*
  Extracts a collision and related subtrees, partial authentication path, height index,
  and breadth index from a binary tree, an authentication path, and a leaf,
  w.r.t. a certain public seed, address, (initial) height index,
  and (initial) breadth index
*)
op extract_coll_bt_ap_trh (ps : pseed)
                          (ad : adrs)
                          (bt : dgstblock bintree)
                          (ap : dgstblock list)
                          (bs : bool list)
                          (leaf : dgstblock)
                          (hidx bidx : int) =
   extract_collision_bt_ap (trhi ps ad) updhbidx bt ap bs leaf (hidx, bidx).



(* - Auxiliary properties - *)
lemma take_take_drop_cat (s : 'a list) (i j : int):
  0 <= i => 0 <= j =>
  take (i + j) s = take i s ++ take j (drop i s).
proof.
elim: s i j => // x s ih /= i j /= ge0_i ge0_j.
case (i = 0) => [/#| neq0j].
rewrite (: ! i <= 0) 2:(: ! i + j <= 0) 1,2:/# /=.
by move: (ih (i - 1) j _ _); smt().
qed.

lemma take_rev_int2bs (i j n : int):
  0 <= j <= i =>
  take j (rev (int2bs i n)) = rev (int2bs j (n %/ 2 ^ (i - j))).
proof.
move=> rng_j.
rewrite (int2bs_cat (i - j) i n) 1:/# rev_cat take_cat size_rev size_int2bs.
rewrite (: ! j < max 0 (i - (i - j))) 1:/# /= (: max 0 (i - (i - j)) = j) 1:/# /=.
by rewrite take0 cats0 /#.
qed.

lemma rcons_take_rev_int2bs (i j n : int) (b : bool):
     0 <= j <= i
  => rcons (take j (rev (int2bs i n))) b
     =
     if b
     then rev (int2bs (j + 1) (2 * (n %/ 2 ^ (i - j)) + 1))
     else rev (int2bs (j + 1) (2 * (n %/ 2 ^ (i - j)))).
proof.
move=> rng_j.
rewrite take_rev_int2bs // -rev_cons {1}(: j = j + 1 - 1) //.
case b => _.
+ rewrite {1}(: n %/ 2 ^ (i - j) = (2 * (n %/ 2 ^ (i - j)) + 1) %/ 2).
  - rewrite divzDl 1:dvdz_mulr //.
    by move: (divz_eq0 1 2 _) => //; move/iffLR => /(_ _) // -> /=; rewrite mulKz.
  rewrite (: true = ! 2 %| (2 * (n %/ 2 ^ (i - j)) + 1)).
  - by rewrite dvdzE mulzC modzMDl.
  by rewrite -int2bs_cons 1:/#.
rewrite {1}(: n %/ 2 ^ (i - j) = 2 * (n %/ 2 ^ (i - j)) %/ 2) 1:mulKz //.
rewrite (: false = ! 2 %| (2 * (n %/ 2 ^ (i - j)))) 1: dvdz_mulr //.
by rewrite -int2bs_cons 1:/#.
qed.

lemma take1_head (x0 : 'a) (s : 'a list) :
     1 <= size s
  => take 1 s = [head x0 s].
proof. by elim: s => /#. qed.

lemma drop1_behead (s : 'a list) :
     drop 1 s = behead s.
proof. by elim: s => /#. qed.

lemma foldlupdhbidx (i : int) (bs : bool list) :
  foldl updhbidx (i, 0) (rev bs) = (i - size bs, bs2int bs).
proof.
elim: bs i => /= [| b bs ih i]; 1: by rewrite bs2int_nil.
by rewrite rev_cons foldl_rcons ih /updhbidx bs2int_cons /#.
qed.

lemma foldedivz (i j n : int) :
  0 <= n =>
  0 <= j =>
  fold (fun (xy : int * int) => edivz xy.`1 j) (i, 0) n
  =
  (i %/ j ^ n, if n = 0 then 0 else i %/ j ^ (n - 1) %% j).
proof.
move=> ge0_n; elim: n ge0_n i j => /=.
move=> i j; rewrite fold0 expr0 //.
move => n ge0_n ih i j ge0_j.
rewrite foldS 1:// /=.
rewrite ih 1:// (: n + 1 <> 0) 1:/# /=.
rewrite exprD_nneg // divz_mul 1:expr_ge0 // 1:expr1.
by case: (edivz (i %/ j ^ n) j).
qed.

lemma ltbignrt_i (i i' j j' u u' : int) :
     0 <= i < i'
  => 0 <= j < nr_trees i
  => 0 <= j'
  => 0 <= u < l'
  => 0 <= u'
  => bigi predT (fun (d' : int) => nr_trees d') 0 i * l' + j * l' + u
     <
     bigi predT (fun (d' : int) => nr_trees d') 0 i' * l' + j' * l' + u'.
proof.
move=> [ge0_i ltip_i] [ge0_j lenti_j] ge0_jp [ge0_u ltlp_u] ge0_up.
rewrite -(addr0 u) addrA -(addrA _ (j' * l') u') ltr_le_add 2:/#.
rewrite (big_cat_int i _ i') 1:// 1:/# -addrA mulrDl ltr_add2l.
rewrite big_ltn 1:// /= mulrDl.
suff /#: j * l' + u < nr_trees i * l' /\ 0 <= bigi predT nr_trees (i + 1) i'.
rewrite sumr_ge0 => [? | /=]; 1: by rewrite expr_ge0.
rewrite (: nr_trees i = nr_trees i - 1 + 1) 1:// mulrDl /=.
by rewrite ler_lt_add 1:/#.
qed.

lemma ltnn1_bignn (u v : int) :
     0 <= u < h'
  => 0 <= v < nr_nodes (u + 1)
  => bigi predT nr_nodes 1 (u + 1) + v < 2 ^ h' - 1.
proof.
move=> [ge0_u lthp_u] [ge0_v @/nr_nodes ltnnu1_v].
rewrite (: 2 ^ h' - 1 = bigi predT nr_nodes 1 (h' + 1)).
+ rewrite eq_sym /nr_nodes; have ge0_hp: 0 <= h' by smt(ge1_hp).
  rewrite (big_reindex _ _ (fun i => h' - i) (fun i => h' - i)).
  + by move=> i /mem_range rng_i /= /#.
  rewrite /(\o) /predT /= -/predT (eq_bigr _ _ (fun i => 2 ^ i)) => [i _ /= /# |].
  rewrite (eq_big_perm _ _ _ (range 0 h')).
  - rewrite uniq_perm_eq_size 2:range_uniq 2:size_map 2:?size_range 2://.
    * by rewrite map_inj_in_uniq 2:range_uniq => i j rng_i rng_j /= /#.
    by move=> i /mapP [j] [/mem_range rng_j /= ->]; rewrite mem_range; smt(ge1_hp).
  elim: h' ge0_hp=> [| i ge0_i ih]; 1: by rewrite expr0 big_geq.
  by rewrite big_int_recr 1:// exprD_nneg 1,2:// /= ih expr1 /#.
rewrite (big_cat_int (u + 1) _ (h' + 1)) 1,2:/# ltr_add2l.
rewrite big_ltn 1:/#; suff /# : 0 <= bigi predT nr_nodes (u + 2) (h' + 1).
by rewrite sumr_ge0 => ? _; rewrite expr_ge0.
qed.

lemma ltbignn_i (i i' j j' u u' v v' : int) :
     0 <= i < i'
  => 0 <= j < nr_trees i
  => 0 <= j'
  => 0 <= u < h'
  => 0 <= u'
  => 0 <= v < nr_nodes (u + 1)
  => 0 <= v'
  => bigi predT (fun (d' : int) => nr_trees d') 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1)
     + bigi predT nr_nodes 1 (u + 1) + v
     <
     bigi predT (fun (d' : int) => nr_trees d') 0 i' * (2 ^ h' - 1) + j' * (2 ^ h' - 1)
     + bigi predT nr_nodes 1 (u' + 1) + v'.
proof.
move=> [ge0_i ltip_i] [ge0_j lenti_j] ge0_jp [ge0_u ltlp_u] ge0_up [ge0_v ltnnu1_v] ge0_vp.
rewrite -(addr0 v) addrA -(addrA _ _ v') -(addrA _ (j' * (2 ^ h' - 1))) ltr_le_add; last first.
+ rewrite addr_ge0 1:mulr_ge0 1:// 1:subr_ge0; 1: smt(expr_gt0).
  by rewrite addr_ge0 2:// sumr_ge0 => ? _; rewrite expr_ge0.
rewrite (big_cat_int i _ i') 1:// 1:/# mulrDl -2!addrA ltr_add2l addrA.
rewrite (big_ltn i) 1:// /= mulrDl (: nr_trees i = nr_trees i - 1 + 1) 1:// mulrDl /=.
rewrite -(addr0 v) addrA ltr_le_add; last first.
+ by rewrite mulr_ge0 2:subr_ge0 1:sumr_ge0 => [? _ |]; smt(expr_gt0).
by rewrite -addrA ler_lt_add 2:ltnn1_bignn 2,3:// ler_pmul 1,4:// 1:subr_ge0; smt(expr_gt0).
qed.

lemma validxadrs_validwadrs_setallboch (i j u : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_tidx i j
  => valid_kpidx u
  => valid_wadrs (set_kpidx (set_typeidx (set_ltidx ad i j) chtype) u).
proof.
move=> @/valid_xadrs @/valid_xadrsidxs [eqal_szad @/valid_xidxvals [valgpad @/valid_xidxvalslp vallpad]].
have gtl6_szad : forall i, i < 6 => i < adrs_len by smt(ge6_adrslen).
have gtif_szad : forall i, i < 6 => i < if 6 < adrs_len then 6 else adrs_len by smt(ge6_adrslen).
move=> vali valj valu @/set_ltidx @/set_typeidx.
+ rewrite insubdK 1:/valid_adrsidxs 1:?size_put 1:eqal_szad /= 1:valid_xidxvals_idxvals.
  rewrite /valid_xidxvals ?drop_put_out 1,2:// valgpad /= /valid_xidxvalslp.
  move: vallpad => @/valid_xidxvalslpch @/valid_xidxvalslppkco @/valid_xidxvalslptrh.
  by rewrite ?take_put /= ?nth_put ?size_put ?size_take ?eqal_szad
              1,3,5,7,9,11,13,15,17,19,21,23:// 1..12:gtif_szad 1..24:// /= /#.
rewrite /set_kpidx /set_idx insubdK 1:/valid_adrsidxs 1:?size_put 1:eqal_szad /= 1:valid_xidxvals_idxvals.
+ rewrite /valid_xidxvals ?drop_put_out 1..6:// valgpad /= /valid_xidxvalslp.
  left.
  by rewrite ?take_put /= /valid_xidxvalslpch ?nth_put ?size_put ?size_take ?eqal_szad
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,
             57,59,61,63,65,67,69,71:// 1..36:gtif_szad 1..72:// /=; smt(val_w ge2_len ge2_lp).
rewrite /valid_wadrs insubdK 1:/valid_adrsidxs 1:?size_put 1:eqal_szad /= 1:valid_xidxvals_idxvals.
+ rewrite /valid_xidxvals ?drop_put_out 1..7:// valgpad /= /valid_xidxvalslp.
  left.
  by rewrite ?take_put /= /valid_xidxvalslpch ?nth_put ?size_put ?size_take ?eqal_szad
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,
             57,59,61,63,65,67,69,71,73,75,77,79,81,83:// 1..42:gtif_szad 1..85:// /=; smt(val_w ge2_len ge2_lp).
rewrite /valid_wadrsidxs ?size_put eqal_szad /= /valid_widxvals drop_drop 1,2://.
rewrite ?nth_drop 1..8:// /= ?nth_put ?size_put ?eqal_szad ?gtl6_szad 1..56:// /=.
rewrite ?drop_put_out 1..8:// valgpad /= ?take_put /= /valid_widxvalslp.
by rewrite ?nth_put ?size_put ?size_take ?eqal_szad 1,3,5,7://; smt(ge6_adrslen val_w ge2_len).
qed.

lemma validxadrs_validwadrs_setallch (i j u v : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_tidx i j
  => valid_kpidx u
  => valid_chidx v
  => valid_wadrs (set_chidx (set_kpidx (set_typeidx (set_ltidx ad i j) chtype) u) v).
proof.
move => vad vi vj vu vv.
move: (validxadrs_validwadrs_setallboch i j u ad vad vi vj vu) => vwadbo.
have vwp: valid_widxvals (put (val (set_kpidx (set_typeidx (set_ltidx ad i j) chtype) u)) 1 v).
+ rewrite /valid_widxvals drop_put_out 1:// /valid_widxvalslp.
  by rewrite take_put /= ?nth_put 1,2:size_take /=; smt(Adrs.valP ge6_adrslen).
rewrite /set_chidx /set_idx /valid_wadrs /valid_wadrsidxs; split; 1: smt(Adrs.valP).
rewrite insubdK 2:// /valid_adrsidxs; split; 1: by rewrite size_put; smt(Adrs.valP).
by apply valid_widxvals_idxvals.
qed.

lemma gettype_setalltrh (i j u v : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_tidx i j
  => valid_thidx u
  => valid_tbidx u v
  => get_typeidx (set_thtbidx (set_typeidx (set_ltidx ad i j) trhtype) u v) = trhtype.
proof.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> vad vi vj vu vv @/get_typeidx @/set_ltidx @/set_typeidx; rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite /set_thtbidx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
          1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,
          57,59,61,63,65,67,69,71:// 1..36:gtif_szad 1..72:// /=.
  by rewrite /valid_tbidx expr_gt0 1:// /=; smt(ge1_hp).
rewrite /get_idx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,
             57,59,61,63,65,67,69,71,73,75,77,79,81,83,85,87,89,91,93,95,97://
             1..48:gtif_szad 1..96:// /= vi vj vu vv /#.
by rewrite ?nth_put ?size_put 9:// /#.
qed.

lemma gettype_setkptypeltchpkco (i j t u : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_tidx i j
  => t = chtype \/ t = pkcotype
  => valid_kpidx u
  => get_typeidx (set_kpidx (set_typeidx (set_ltidx ad i j) t) u) = t.
proof.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> vad vi vj vt vu @/get_typeidx @/set_ltidx @/set_typeidx; rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
          1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad 1..72:// /=; smt(val_w ge2_len).
rewrite /get_idx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
by rewrite ?nth_put ?size_put 8:// /#.
qed.

lemma gettype_setallch (i j u v x : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_tidx i j
  => valid_kpidx u
  => valid_chidx v
  => valid_hidx x
  => get_typeidx (set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad i j) chtype) u) v) x) = chtype.
proof.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> vad vi vj vu vv vx @/get_typeidx @/set_ltidx @/set_typeidx; rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(val_w ge2_len).
rewrite /set_chidx /set_idx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
rewrite /set_hidx /set_idx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83,85,87,89,91,93,95://
             1..48:gtif_szad 1..96:// /=; smt(val_w ge2_len).
rewrite /get_idx insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..7:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83,85,87,89,91,93,95,97,99,101,103,105,107://
             1..54:gtif_szad 1..108:// /=; smt(val_w ge2_len).
by rewrite ?nth_put ?size_put 8:// /#.
qed.

lemma neqlidx_setkptypelt (i i' j j' t u u' : int) (ad : adrs)  :
     valid_xadrs ad
  => valid_lidx i
  => valid_lidx i'
  => valid_tidx i j
  => valid_tidx i' j'
  => t = chtype \/ t = pkcotype
  => valid_kpidx u
  => valid_kpidx u'
  => i <> i'
  => nth witness (val (set_kpidx (set_typeidx (set_ltidx ad i j) t) u)) 5
     <>
     nth witness (val (set_kpidx (set_typeidx (set_ltidx ad i' j') t) u')) 5.
proof.
move=> vad vi vip vj vjp vt vu vup neqip_i.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> @/set_ltidx @/set_typeidx.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vip vjp /= /#.
rewrite /set_kpidx /set_idx (Adrs.insubdK (put (put _ _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(val_w ge2_len).
rewrite eq_sym (Adrs.insubdK (put (put _ _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(val_w ge2_len).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
by rewrite ?nth_put ?size_put 15:// /#.
qed.

lemma neqtidx_setkptypelt (i i' j j' t u u' : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_lidx i'
  => valid_tidx i j
  => valid_tidx i' j'
  => t = chtype \/ t = pkcotype
  => valid_kpidx u
  => valid_kpidx u'
  => j <> j'
  => nth witness (val (set_kpidx (set_typeidx (set_ltidx ad i j) t) u)) 4
     <>
     nth witness (val (set_kpidx (set_typeidx (set_ltidx ad i' j') t) u')) 4.
proof.
move=> vad vi vip vj vjp vt vu vup neqip_i.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> @/set_ltidx @/set_typeidx.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vip vjp /= /#.
rewrite /set_kpidx /set_idx (Adrs.insubdK (put (put _ _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(val_w ge2_len).
rewrite eq_sym (Adrs.insubdK (put (put _ _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(val_w ge2_len).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
by rewrite ?nth_put ?size_put 15:// /#.
qed.

lemma neqkpidx_setkptypelt (i i' j j' t u u' : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_lidx i'
  => valid_tidx i j
  => valid_tidx i' j'
  => t = chtype \/ t = pkcotype
  => valid_kpidx u
  => valid_kpidx u'
  => u <> u'
  => nth witness (val (set_kpidx (set_typeidx (set_ltidx ad i j) t) u)) 2
     <>
     nth witness (val (set_kpidx (set_typeidx (set_ltidx ad i' j') t) u')) 2.
proof.
move=> vad vi vip vj vjp vt vu vup neqip_i.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> @/set_ltidx @/set_typeidx.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vip vjp /= /#.
rewrite /set_kpidx /set_idx (Adrs.insubdK (put (put _ _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(val_w ge2_len).
rewrite eq_sym (Adrs.insubdK (put (put _ _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(val_w ge2_len).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(val_w ge2_len).
by rewrite ?nth_put ?size_put 15:// /#.
qed.

lemma neqlidx_setthtypelt (i i' j j' u u' v v' : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_lidx i'
  => valid_tidx i j
  => valid_tidx i' j'
  => valid_thidx u
  => valid_thidx u'
  => valid_tbidx u v
  => valid_tbidx u' v'
  => i <> i'
  => nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i j) trhtype) u v)) 5
     <>
     nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i' j') trhtype) u' v')) 5.
proof.
move=> vad vi vip vj vjp vu vup vv vvp neqip_i.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> @/set_ltidx @/set_typeidx.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vip vjp /= /#.
rewrite /set_thtbidx /set_idx (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite eq_sym (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /= /#.
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(ge1_hp expr_gt0).
by rewrite ?nth_put ?size_put 15:// /#.
qed.

lemma neqtidx_setthtypelt (i i' j j' u u' v v' : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_lidx i'
  => valid_tidx i j
  => valid_tidx i' j'
  => valid_thidx u
  => valid_thidx u'
  => valid_tbidx u v
  => valid_tbidx u' v'
  => j <> j'
  => nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i j) trhtype) u v)) 4
     <>
     nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i' j') trhtype) u' v')) 4.
proof.
move=> vad vi vip vj vjp vu vup vv vvp neqjp_j.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> @/set_ltidx @/set_typeidx.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vip vjp /= /#.
rewrite /set_thtbidx /set_idx (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite eq_sym (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /= /#.
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(ge1_hp expr_gt0).
by rewrite ?nth_put ?size_put /#.
qed.

lemma neqthidx_setthtypelt (i i' j j' u u' v v' : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_lidx i'
  => valid_tidx i j
  => valid_tidx i' j'
  => valid_thidx u
  => valid_thidx u'
  => valid_tbidx u v
  => valid_tbidx u' v'
  => u <> u'
  => nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i j) trhtype) u v)) 1
     <>
     nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i' j') trhtype) u' v')) 1.
proof.
move=> vad vi vip vj vjp vu vup vv vvp nequp_u.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> @/set_ltidx @/set_typeidx.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vip vjp /= /#.
rewrite /set_thtbidx /set_idx (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite eq_sym (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /= /#.
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(ge1_hp expr_gt0).
by rewrite ?nth_put ?size_put /#.
qed.

lemma neqtbidx_setthtypelt (i i' j j' u u' v v' : int) (ad : adrs) :
     valid_xadrs ad
  => valid_lidx i
  => valid_lidx i'
  => valid_tidx i j
  => valid_tidx i' j'
  => valid_thidx u
  => valid_thidx u'
  => valid_tbidx u v
  => valid_tbidx u' v'
  => v <> v'
  => nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i j) trhtype) u v)) 0
     <>
     nth witness (val (set_thtbidx (set_typeidx (set_ltidx ad i' j') trhtype) u' v')) 0.
proof.
move=> vad vi vip vj vjp vu vup vv vvp neqvp_v.
have gtif_szad : forall i, i < 6 => i < if 6 < size (val ad) then 6 else size (val ad) by smt(Adrs.valP ge6_adrslen).
move=> @/set_ltidx @/set_typeidx.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vi vj /= /#.
rewrite (Adrs.insubdK (put (put (val ad) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  move: vad => @/valid_xadrs @/valid_xadrsidxs [eqszad].
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?nth_put ?size_put ?size_take 1,3,5,7,9,11,13,15,17,19,21,23://
             1..12:gtif_szad 1..24:// /= ?nth_take 1..12:// vip vjp /= /#.
rewrite /set_thtbidx /set_idx (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite eq_sym (Adrs.insubdK (put (put (put _ _ _) _ _) _ _)).
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..4:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,
             45,47,49,51,53,55,57,59,61,63,65,67,69,71:// 1..36:gtif_szad
             1..72:// /=; smt(ge1_hp expr_gt0).
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /= /#.
rewrite insubdK.
+ rewrite /valid_adrsidxs valid_xidxvals_idxvals 2:?size_put; 2: smt(Adrs.valP).
  rewrite /valid_xidxvals /valid_xidxvalslp 2?drop_put_out 1,2:// 2?take_put /=.
  rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
  by rewrite ?drop_put_out 1..6:// ?take_put /= ?nth_put ?size_put ?size_take
             1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,
             47,49,51,53,55,57,59,61,63,65,67,69,71,73,75,77,79,81,83://
             1..42:gtif_szad 1..84:// /=; smt(ge1_hp expr_gt0).
by rewrite ?nth_put ?size_put /#.
qed.



(* - Specifications - *)
(* Fixed-Length, StateLess XMSS-MT-TW in Encompassing Structure *)

(* Fixed-Length StateLess FL-SL-XMSS-MT-TW in Encompassing Structure (No PRF) *)



(* - Proof - *)
(* -- Adversary classes -- *)
(* Adversaries against EUF-NAGCMA for FL-SL-XMSS-MT-TW-ES-NPRF *)
module type Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF (OC : Oracle_THFC) = {
  proc choose() : msgFLSLXMSSMTTW list { OC.query }
  proc forge(pk : pkFLSLXMSSMTTW, sigl : sigFLSLXMSSMTTW list) : msgFLSLXMSSMTTW * sigFLSLXMSSMTTW * index {}
}.


(* -- Security notions -- *)
(* EUF-NAGCMA for FL-SL-XMSS-MT-TW-ES-NPRF *)


(* -- Reduction adversaries -- *)
(* Reduction adversary against M-EUF-GCMA of WOTS-TW *)

(* Reduction adversaty against SM-DT-TCR-C of pkco *)

(* Reduction adversary against SM-DT-TCR-C of trh *)


