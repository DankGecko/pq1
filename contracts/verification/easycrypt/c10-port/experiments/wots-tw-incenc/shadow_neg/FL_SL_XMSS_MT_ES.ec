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
const log2_w : { int | log2_w = 2 \/ log2_w = 4 \/ log2_w = 8 } as val_log2w.

(* Winternitz parameter (base/radix) *)
const w = 2 ^ log2_w.

(* Length of the message in base/radix w *)
const len1 : int = ceil ((8 * n)%r / log2 w%r).

(* Length of the checksum in base/radix w *)
const len2 : int = floor (log2 ((len1 * (w - 1))%r) / log2 w%r) + 1.

(* Number of elements (of length n) in private keys, public keys, and signatures *)
const len : int = len1 + len2.


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
    op len1 <- len1,
    op len2 <- len2,
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

  proof ge2_adrslen, ge1_n, val_log2w, ge1_c, dpseed_ll, ddgstblock_ll, valid_widxvals_idxvals.
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
type msgFLXMSSMTTW = msgWOTS.
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
module FL_SL_XMSS_MT_ES = {
  (* Compute (inner tree) leaves from a secret seed, public seed, and address *)
  proc leaves_from_sspsad(ss : sseed, ps : pseed, ad : adrs) : dgstblock list = {
    var skWOTS : skWOTS;
    var pkWOTS : pkWOTS;
    var leaf : dgstblock;
    var leaves : dgstblock list;

    leaves <- [];
    (* For each leaf in the (inner) tree... *)
    while (size leaves < l') {
      (* Generate a WOTS-TW secret key *)
      skWOTS <@ WOTS_TW_ES.gen_skWOTS(ss, ps, set_kpidx (set_typeidx ad chtype) (size leaves));

      (* Compute the WOTS-TW public key from the generated WOTS-TW secret key *)
      pkWOTS <@ WOTS_TW_ES.pkWOTS_from_skWOTS(skWOTS, ps, set_kpidx (set_typeidx ad chtype) (size leaves));

      (* Compute leaf from the computed WOTS-TW public key *)
      leaf <- pkco ps (set_kpidx (set_typeidx ad pkcotype) (size leaves)) (flatten (map DigestBlock.val (val pkWOTS)));

      leaves <- rcons leaves leaf;
    }

    return leaves;
  }

  (* Compute root of hypertree from secret seed, public seed, and address *)
  proc gen_root(ss : sseed, ps : pseed, ad : adrs) : dgstblock = {
    var root : dgstblock;
    var leaves : dgstblock list;

    (* Compute leaves of top-most inner tree *)
    leaves <@ leaves_from_sspsad(ss, ps, set_ltidx ad (d - 1) 0);

    (*
      Compute root (hash value) from the computed leaves, given public seed, and
      given address (after setting the type to tree hashing)
    *)
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhtype) (list2tree leaves);

    return root;
  }

  proc keygen(ss : sseed, ps : pseed, ad : adrs) : pkFLSLXMSSMTTW * skFLSLXMSSMTTW = {
    var root : dgstblock;
    var leaves : dgstblock list;
    var pk : pkFLSLXMSSMTTW;
    var sk : skFLSLXMSSMTTW;

    (* Compute the root of the hypertree *)
    root <@ gen_root(ss, ps, ad);

    pk <- (root, ps, ad);
    sk <- (ss, ps, ad);

    return (pk, sk);
  }

  (*
    Signing procedure.
    Note that, in contrast to the signing procedure of XMSS-MT as a standalone,
    this signing procedure does not update the secret key itself.
    This is assumed to be taken care of by the encompassing structure.
  *)
  proc sign(sk : skFLSLXMSSMTTW, m : msgFLSLXMSSMTTW, idx : index) : sigFLSLXMSSMTTW = {
    var ss : sseed;
    var ps : pseed;
    var ad : adrs;
    var tidx, kpidx : int;
    var skWOTS : skWOTS;
    var sigWOTS : sigWOTS;
    var skWOTSl : skWOTS list;
    var leaves : dgstblock list;
    var ap : apFLXMSSTW;
    var sapl : (sigWOTS * apFLXMSSTW) list;
    var sig : sigFLSLXMSSMTTW;
    var root : dgstblock;

    (* Extract secret seed, public seed, and address from the secret key *)
    (ss, ps, ad) <- sk;

    (* Initialize root (which is repeatedly signed), signature list, tree index, and key pair index *)
    root <- m;
    sapl <- [];
    (tidx, kpidx) <- (val idx, 0);
    while (size sapl < d) {
      (* Update tree and key pair indices *)
      (tidx, kpidx) <- edivz tidx l';

      (* Compute the WOTS-TW signature on the given message *)
      sigWOTS <@ WOTS_TW_ES.sign((ss, ps, set_kpidx (set_typeidx (set_ltidx ad (size sapl) tidx) chtype) kpidx), root);

      (* Compute the list of leaves *)
      leaves <@ leaves_from_sspsad(ss, ps, (set_ltidx ad (size sapl) tidx));

      (* Construct the authentication path from the computed list of leaves *)
      ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves) kpidx;

      (* Compute next message/root to sign *)
      root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves);

      (* Add computed WOTS-TW signature and authentication path  *)
      sapl <- rcons sapl (sigWOTS, ap);
    }

    sig <- insubd sapl;

    return sig;
  }

  proc root_from_sigFLSLXMSSMTTW(m : msgFLSLXMSSMTTW, sig : sigFLSLXMSSMTTW, idx : index, ps : pseed, ad : adrs) : dgstblock = {
    var root : dgstblock;
    var tidx, kpidx : int;
    var i : int;
    var sigWOTS : sigWOTS;
    var ap : apFLXMSSTW;
    var pkWOTS : pkWOTS;
    var leaf : dgstblock;

    (* Initialize loop counter, (supposed) root variable, and tree index *)
    i <- 0;
    root <- m;
    (tidx, kpidx) <- (val idx, 0);
    while (i < d) {
      (* Update tree and key pair indices *)
      (tidx, kpidx) <- edivz tidx l';

      (* Extract WOTS-TW signature and corresponding authentication path for considered tree *)
      (sigWOTS, ap) <- nth witness (val sig) i;

      (* Compute WOTS-TW public key *)
      pkWOTS <@ WOTS_TW_ES.pkWOTS_from_sigWOTS(root, sigWOTS, ps, set_kpidx (set_typeidx (set_ltidx ad i tidx) chtype) kpidx);

      (* Compute leaf from the computed WOTS-TW public key *)
      leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad i tidx) pkcotype) kpidx) (flatten (map DigestBlock.val (val pkWOTS)));

      (* Compute root from computed leaf (and extracted authentication path) *)
      root <- val_ap_trh ps (set_typeidx (set_ltidx ad i tidx) trhtype) ap kpidx leaf;

      (* Increase loop counter *)
      i <- i + 1;
    }

    return root;
  }

  proc verify(pk : pkFLSLXMSSMTTW, m : msgFLSLXMSSMTTW, sig : sigFLSLXMSSMTTW, idx : index) : bool = {
    var root, root' : dgstblock;
    var ps : pseed;
    var ad : adrs;

    (* Extract root (hash) value, public seed, and address from the public key *)
    (root, ps, ad) <- pk;

    (* Compute root value associated with the given message, signature, and index *)
    root' <@ root_from_sigFLSLXMSSMTTW(m, sig, idx, ps, ad);

    return root' = root;
  }
}.

(* Fixed-Length StateLess FL-SL-XMSS-MT-TW in Encompassing Structure (No PRF) *)
module FL_SL_XMSS_MT_ES_NPRF = {
  (* Compute (inner tree) leaves from a WOTS-TW secret key, public seed, and address *)
  proc leaves_from_sklpsad(skWOTSl : skWOTS list, ps : pseed, ad : adrs) : dgstblock list = {
    var skWOTS : skWOTS;
    var pkWOTS : pkWOTS;
    var leaf : dgstblock;
    var leaves : dgstblock list;

    leaves <- [];
    (* For each leaf in the (inner) tree *)
    while (size leaves < l') {
      (* Extract considered WOTS-TW secret key *)
      skWOTS <- nth witness skWOTSl (size leaves);

      (* Compute the WOTS-TW public key from WOTS-TW secret key *)
      pkWOTS <@ WOTS_TW_ES_NPRF.pkWOTS_from_skWOTS(skWOTS, ps, set_kpidx (set_typeidx ad chtype) (size leaves));

      (* Compute leaf from the computed WOTS-TW public key *)
      leaf <- pkco ps (set_kpidx (set_typeidx ad pkcotype) (size leaves)) (flatten (map DigestBlock.val (val pkWOTS)));

      leaves <- rcons leaves leaf;
    }

    return leaves;
  }

  proc keygen(ps : pseed, ad : adrs) : pkFLSLXMSSMTTW * (skWOTS list list list * pseed * adrs) = {
    var root : dgstblock;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;

    (* Sample and store WOTS-TW secret keys *)
    skWOTStd <- [];
    (* For each layer in the hypertree... *)
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      (* For each (inner) tree in this layer... *)
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        (* For each (WOTS-TW instance associated with a) leaf in this (inner) tree... *)
        while (size skWOTSlp < l') {
          skWOTS <- [];
          (* For each chain in this WOTS-TW instance... *)
          while (size skWOTS < len) {
            (* Sample and store a secret key element (that will be used as the first value in this chain) *)
            skWOTS_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS skWOTS_ele;
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
    }

    (*
      Extract secret key of the top-most inner tree in the hyper tree
      and compute the corresponding leaves.
    *)
    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);

    (*
      Compute root (hash value) from the computed list of leaves, given public seed, and
      given address (after setting the type to tree hashing)
    *)
    root <- val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhtype) (list2tree leaves);

    pk <- (root, ps, ad);
    sk <- (skWOTStd, ps, ad);

    return (pk, sk);
  }

  (*
    Signing procedure.
    Note that, in contrast to the signing procedure of XMSS-MT as a standalone,
    this signing procedure does not update the secret key itself.
    This is assumed to be taken care of by the encompassing structure.
  *)
  proc sign(sk : skWOTS list list list * pseed * adrs, m : msgFLSLXMSSMTTW, idx : index) : sigFLSLXMSSMTTW = {
    var ps : pseed;
    var ad : adrs;
    var tidx, kpidx : int;
    var root : dgstblock;
    var skWOTS : skWOTS;
    var sigWOTS : sigWOTS;
    var skWOTSlp : skWOTS list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var ap : apFLXMSSTW;
    var sapl : (sigWOTS * apFLXMSSTW) list;
    var sig : sigFLSLXMSSMTTW;

    (* Extract index, secret key, public seed, and address from the secret key *)
    (skWOTStd, ps, ad) <- sk;

    (* Initialize root, signature list, and tree index *)
    root <- m;
    sapl <- [];
    (tidx, kpidx) <- (val idx, 0);
    while (size sapl < d) {
      (* Update tree and key pair indices *)
      (tidx, kpidx) <- edivz tidx l';

      (*
        Extract FL-SL-XMSS-TW secret key in considered layer (size sapl), and corresponding to
        considered inner tree in this layer (tidx).
      *)
      skWOTSlp <- nth witness (nth witness skWOTStd (size sapl)) tidx;

      (*
        Extract WOTS-TW secret key from secret key of considered inner tree,
        and corresponding to considered key pair in this inner tree (kpidx)
      *)
      skWOTS <- nth witness skWOTSlp kpidx;

      (* Compute the WOTS-TW signature on the given message *)
      sigWOTS <@ WOTS_TW_ES_NPRF.sign((skWOTS, ps, set_kpidx (set_typeidx (set_ltidx ad (size sapl) tidx) chtype) kpidx), root);

      (* Compute the list of leaves *)
      leaves <@ leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (size sapl) tidx);

      (* Construct the authentication path from the computed list of leaves *)
      ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves) kpidx;

      (* Compute next message/root to sign *)
      root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves);

      (* Add computed WOTS-TW signature and authentication path  *)
      sapl <- rcons sapl (sigWOTS, ap);
    }

    sig <- insubd sapl;

    return sig;
  }

  proc verify = FL_SL_XMSS_MT_ES.verify
}.



(* - Proof - *)
(* -- Adversary classes -- *)
(* Adversaries against EUF-NAGCMA for FL-SL-XMSS-MT-TW-ES-NPRF *)
module type Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF (OC : Oracle_THFC) = {
  proc choose() : msgFLSLXMSSMTTW list { OC.query }
  proc forge(pk : pkFLSLXMSSMTTW, sigl : sigFLSLXMSSMTTW list) : msgFLSLXMSSMTTW * sigFLSLXMSSMTTW * index {}
}.


(* -- Security notions -- *)
(* EUF-NAGCMA for FL-SL-XMSS-MT-TW-ES-NPRF *)
module EUF_NAGCMA_FLSLXMSSMTTWESNPRF (A : Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF, OC : Oracle_THFC) = {
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTW list;
    var m, m' : msgFLSLXMSSMTTW;
    var sig, sig' : sigFLSLXMSSMTTW;
    var idx' : index;
    var is_valid, is_fresh : bool;

    (* Intialize address and public seed *)
    ad <- adz;
    ps <$ dpseed;

    (* Initialize collection oracle *)
    OC.init(ps);

    (* Ask adversary to choose a list of messages for which to receive signatures *)
    ml <@ A(OC).choose();

    (* Generate keypair for FL-SL-XMSS-MT-TW-ES-NPRF *)
    (pk, sk) <@ FL_SL_XMSS_MT_ES_NPRF.keygen(ps, ad);

    (* Sign (up to l) messages from list provided by adversary  *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sig <@ FL_SL_XMSS_MT_ES_NPRF.sign(sk, m, Index.insubd (size sigl));

      sigl <- rcons sigl sig;
    }

    (* Ask adversary to forge (given public key and list of signatures) *)
    (m', sig', idx') <@ A(OC).forge(pk, sigl);

    (* Check validity of forgery *)
    is_valid <@ FL_SL_XMSS_MT_ES_NPRF.verify(pk, m', sig', idx');

    (*
      Check freshness of message in forgery; in this context,
      "fresh" means that the message in the forgery does not equal the message
      in the message list (provided by the adversary) at the index in the forgery.
    *)
    is_fresh <- m' <> nth witness ml (val idx');

    return is_valid /\ is_fresh;
  }
}.


(* -- Reduction adversaries -- *)
(* Reduction adversary against M-EUF-GCMA of WOTS-TW *)
module (R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA (A : Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF) : Adv_MEUFGCMA_WOTSTWESNPRF) (O : Oracle_MEUFGCMA_WOTSTWESNPRF, OC : Oracle_THFC) = {
  var ad : adrs
  var ml : msgFLSLXMSSMTTW list
  var pkWOTStd : pkWOTS list list list
  var sigWOTStd : sigWOTS list list list
  var leavestd : dgstblock list list list
  var rootstd : dgstblock list list

  (*
    Collection oracle that wraps given collection oracle,
    allowing to differentiate between queries made by the given
    adversary or the reduction adversary itself (in creating the keypair)
  *)
  module O_THFC : Oracle_THFC = {
    var ads : adrs list
    var xs : dgst list

    proc init(ps : pseed) : unit = {
      ads <- [];
      xs <- [];
    }

    proc query(adq : adrs, x : dgst) : dgstblock = {
      var y : dgstblock;

      y <@ OC.query(adq, x);

      ads <- rcons ads adq;
      xs <- rcons xs x;

      return y;
    }

    proc get_tweaks() : adrs list = {
      return ads;
    }
  }

  proc choose() : unit = {
    var pkWOTS : pkWOTS;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt, pkWOTSntp : pkWOTS list list;
    var sigWOTS : sigWOTS;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt, sigWOTSntp : sigWOTS list list;
    var leaf : dgstblock;
    var leaveslp : dgstblock list;
    var leavesnt, leavesntp : dgstblock list list;
    var root : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var lnode, rnode, node : dgstblock;
    var nodespl, nodescl : dgstblock list;
    var nodes : dgstblock list list;

    (* Initialize (wrapper around) collection oracle *)
    O_THFC.init(witness);

    (* Ask adversary to provide list of messages to sign *)
    ml <@ A(O_THFC).choose();

    (* Initialize address *)
    ad <- adz;

    (*
      Using the provided oracles, compute and store all the
      WOTS-TW public keys, WOTS-TW signatures, (inner tree) leaves, and (inner tree) roots.
    *)
    pkWOTStd <- [];
    sigWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    (* For each layer in the hypertree, starting from the bottom-most layer,... *)
    while (size pkWOTStd < d) {
      pkWOTSnt <- [];
      sigWOTSnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      (* For each tree in the current layer, starting from the left-most tree,... *)
      while (size pkWOTSnt < nr_trees (size pkWOTStd)) {
        pkWOTSlp <- [];
        sigWOTSlp <- [];
        leaveslp <- [];
        (* For each leaf of the current tree, starting from the left-most leaf,... *)
        while (size pkWOTSlp < l') {
          (* Compute the to-be-signed message/root *)
          root <- nth witness rootsntp (size pkWOTSnt * l' + size pkWOTSlp);

          (* Query the challenge oracle on the computed message/root to obtain a (WOTS-TW) signature and public key *)
          (pkWOTS, sigWOTS) <@ O.query(WAddress.insubd (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTStd) (size pkWOTSnt)) chtype) (size pkWOTSlp)),
                                       root);

          (* Query the family oracle to compress the obtained WOTS-TW public key to the corresponding leaf  *)
          leaf <@ OC.query(set_kpidx (set_typeidx (set_ltidx ad (size pkWOTStd) (size pkWOTSnt)) pkcotype) (size pkWOTSlp),
                           flatten (map DigestBlock.val (val pkWOTS)));

          pkWOTSlp <- rcons pkWOTSlp pkWOTS;
          sigWOTSlp <- rcons sigWOTSlp sigWOTS;
          leaveslp <- rcons leaveslp leaf;
        }

        nodes <- [];
        (* For each layer in the current tree, starting from the layer right above the leaves,... *)
        while (size nodes < h') {
          nodespl <- last leaveslp nodes;

          nodescl <- [];
          (* For each (to-be-computed) node in the currently considered layer,... *)
          while (size nodescl < nr_nodes (size nodes + 1)) {
            (* Get the left and right children *)
            lnode <- nth witness nodespl (2 * size nodescl);
            rnode <- nth witness nodespl (2 * size nodescl + 1);

            (* Query the family oracle on the concatenation of the children to obtain the node *)
            node <@ OC.query(set_thtbidx (set_typeidx (set_ltidx ad (size pkWOTStd) (size pkWOTSnt)) trhtype)
                                         (size nodes + 1) (size nodescl),
                             val lnode ++ val rnode);

            nodescl <- rcons nodescl node;
          }
          nodes <- rcons nodes nodescl;
        }
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt (nth witness (nth witness nodes (h' - 1)) 0); (* Root of current tree is the last computed/stored node *)
      }
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }
  }

  proc forge(ps : pseed) : int * msgWOTS * sigWOTS = {
    var m : msgFLSLXMSSMTTW;
    var pk : pkFLSLXMSSMTTW;
    var sigWOTS, sigWOTS' : sigWOTS;
    var pkWOTS, pkWOTS' : pkWOTS;
    var ap, ap' : apFLXMSSTW;
    var sapl, sapl' : (sigWOTS * apFLXMSSTW) list;
    var sig : sigFLSLXMSSMTTW;
    var sigl : sigFLSLXMSSMTTW list;
    var m' : msgFLSLXMSSMTTW;
    var sig' : sigFLSLXMSSMTTW;
    var idx' : index;
    var root, root' : dgstblock;
    var tidx, kpidx : int;
    var tkpidxs : (int * int) list;
    var leaf, leaf' : dgstblock;
    var leaves : dgstblock list;
    var cidx, fidx : int;
    var pkWOTSs, pkWOTSs' : pkWOTS list;
    var rootss, rootss' : dgstblock list;
    var valid_WOTSTWES, valid_TCRPKCO, valid_TCRTRH : bool;

    (* Sign adversary-chosen messages using computed leaves/signatures *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigWOTS <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigWOTS, ap);
      }

      sig <- insubd sapl;
      sigl <- rcons sigl sig;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0; (* Root of hypertree is the last computed root *)

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(O_THFC).forge((root, ps, ad), sigl);

    (tidx, kpidx) <- (val idx', 0);
    root' <- m';
    tkpidxs <- [];
    pkWOTSs <- [];
    rootss <- [];
    pkWOTSs' <- [];
    rootss' <- [];
    (*
      For each WOTS-TW signature/authentication path pair in the forgery, check whether
      the signature is valid on the previous root (first one being the forgery's message),
      then compute the next root using the authentication path and the leaf resulting from
      compressing the WOTS-TW public key derived from the signature.
      Keep track of the intermediate roots, public keys, and tree/keypair indices.
    *)
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigWOTS', ap') <- nth witness (val sig') (size pkWOTSs');

      pkWOTS' <@ WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS(root', sigWOTS', ps,
                                                     (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      pkWOTS <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (val pkWOTS')));

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTS;
      rootss <- rcons rootss root;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      rootss' <- rcons rootss' root';
    }

    (*
      Find (first) index in computed list of roots/WOTS-TW public keys where the elements
      consitute a WOTS-TW (M-EUF-GCMA) forgery
    *)
    cidx <- find (fun (x : ((_ *  _) * _) * _) => x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
                 (zip (zip (zip pkWOTSs' pkWOTSs) (m' :: rootss')) (nth witness ml (val idx') :: rootss));

    (* Get tree and key pair index corresponding to the forgery *)
    (tidx, kpidx) <- nth witness tkpidxs cidx;

    (* Compute index in the challenge oracle's query list corresponding to the forgery *)
    fidx <- bigi predT (fun i => nr_trees i) 0 cidx * l' + tidx * l' + kpidx;

    (* Get actual values (root and WOTS-TW signature) forming the forgery *)
    root' <- nth witness (m' :: rootss') cidx;
    sigWOTS' <- (nth witness (val sig') cidx).`1;

    return (fidx, root', sigWOTS');
  }
}.

(* Reduction adversaty against SM-DT-TCR-C of pkco *)
module (R_SMDTTCRCPKCO_EUFNAGCMA (A : Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF) : PKCOC_TCR.Adv_SMDTTCRC) (O : PKCOC_TCR.Oracle_SMDTTCR, OC : PKCOC.Oracle_THFC) = {
  var ad : adrs
  var ml : msgFLSLXMSSMTTW list
  var skWOTStd : skWOTS list list list
  var pkWOTStd : pkWOTS list list list
  var sigWOTStd : sigWOTS list list list
  var leavestd : dgstblock list list list
  var rootstd : dgstblock list list

  (*
    Collection oracle that wraps given collection oracle,
    allowing to differentiate between queries made by the given
    adversary or the reduction adversary itself (in creating the keypair)
  *)
  module O_THFC : Oracle_THFC = {
    var ads : adrs list
    var xs : dgst list

    proc init(ps : pseed) : unit = {
      ads <- [];
      xs <- [];
    }

    proc query(adq : adrs, x : dgst) : dgstblock = {
      var y : dgstblock;

      y <@ OC.query(adq, x);

      ads <- rcons ads adq;
      xs <- rcons xs x;

      return y;
    }

    proc get_tweaks() : adrs list = {
      return ads;
    }
  }

  proc pick() : unit = {
    var m : msgFLSLXMSSMTTW;
    var em : emsgWOTS;
    var ch_ele : dgstblock;
    var em_ele : int;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt, skWOTSntp : skWOTS list list;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt, pkWOTSntp : pkWOTS list list;
    var sigWOTS : dgstblock list;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt, sigWOTSntp : sigWOTS list list;
    var leaf : dgstblock;
    var leaveslp : dgstblock list;
    var leavesnt, leavesntp : dgstblock list list;
    var root : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var lnode, rnode, node : dgstblock;
    var nodespl, nodescl : dgstblock list;
    var nodes : dgstblock list list;
    var i : int;

    (* Initialize (wrapper around) collection oracle *)
    O_THFC.init(witness);

    (* Ask adversary to provide list of messages to sign *)
    ml <@ A(O_THFC).choose();

    (* Initialize address *)
    ad <- adz;

    (*
      Using the provided oracles, compute and store all the
      WOTS-TW secret keys, WOTS-TW public keys, WOTS-TW signatures,
      (inner tree) leaves, and (inner tree) roots.
    *)
    skWOTStd <- [];
    pkWOTStd <- [];
    sigWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    (* For each layer in the hypertree, starting from the bottom-most layer,... *)
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      sigWOTSnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      (* For each tree in the current layer, starting from the left-most tree,... *)
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        sigWOTSlp <- [];
        leaveslp <- [];
        (* For each leaf of the current tree, starting from the left-most leaf,... *)
        while (size skWOTSlp < l') {
          (* Get the to-be-signed message/root and encode it *)
          root <- nth witness rootsntp (size skWOTSnt * l' + size skWOTSlp);
          em <- encode_msgWOTS root;

          skWOTS <- [];
          pkWOTS <- [];
          sigWOTS <- [];
          (* For each element of the WOTS-TW artifacts... *)
          while (size skWOTS < len) {
            em_ele <- BaseW.val em.[size pkWOTS];

            (* Sample and store a skWOTS element *)
            ch_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS ch_ele;

            if (em_ele = 0) {
              sigWOTS <- rcons sigWOTS ch_ele;
            }

            (* Compute the corresponding signature and public elements *)
            i <- 0;
            while (i < w - 1) {
              ch_ele <@ OC.query(set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype)
                                                                (size skWOTSlp)) (size pkWOTS)) i,
                                 val ch_ele);

              i <- i + 1;

              if (i = em_ele) {
                sigWOTS <- rcons sigWOTS ch_ele;
              }
            }

            pkWOTS <- rcons pkWOTS ch_ele;
          }

          (* Query the challenge oracle to compress the obtained WOTS-TW public key to the corresponding leaf  *)
          leaf <@ O.query(set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp),
                          flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS);
          leaveslp <- rcons leaveslp leaf;
        }

        nodes <- [];
        (* For each layer in the current tree, starting from the layer right above the leaves,... *)
        while (size nodes < h') {
          nodespl <- last leaveslp nodes;

          nodescl <- [];
          (* For each (to-be-computed) node in the currently considered layer,... *)
          while (size nodescl < nr_nodes (size nodes + 1)) {
            (* Get the left and right children *)
            lnode <- nth witness nodespl (2 * size nodescl);
            rnode <- nth witness nodespl (2 * size nodescl + 1);

            (* Query the family oracle on the concatenation of the children to obtain the node *)
            node <@ OC.query(set_thtbidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhtype)
                                         (size nodes + 1) (size nodescl),
                             val lnode ++ val rnode);

            nodescl <- rcons nodescl node;
          }
          nodes <- rcons nodes nodescl;
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt (nth witness (nth witness nodes (h' - 1)) 0); (* Root of current tree is the last computed/stored node *)
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }
  }

  proc find(ps : pseed) : int * dgst = {
    var m : msgFLSLXMSSMTTW;
    var sigWOTS, sigWOTS' : sigWOTS;
    var pkWOTS, pkWOTS' : pkWOTS;
    var ap, ap' : apFLXMSSTW;
    var sapl : (sigWOTS * apFLXMSSTW) list;
    var sig : sigFLSLXMSSMTTW;
    var sigl : sigFLSLXMSSMTTW list;
    var m' : msgFLSLXMSSMTTW;
    var sig' : sigFLSLXMSSMTTW;
    var idx' : index;
    var root, root' : dgstblock;
    var tidx, kpidx : int;
    var tkpidxs : (int * int) list;
    var leaf, leaf' : dgstblock;
    var leaves : dgstblock list;
    var cidx, fidx : int;
    var pkWOTSs, pkWOTSs' : pkWOTS list;
    var leavess, leavess' : dgstblock list;

    (* Sign adversary-chosen messages using computed leaves/signatures *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigWOTS <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigWOTS, ap);
      }

      sig <- insubd sapl;
      sigl <- rcons sigl sig;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0; (* Root of hypertree is the last computed root *)

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(O_THFC).forge((root, ps, ad), sigl);

    (tidx, kpidx) <- (val idx', 0);
    root' <- m';
    tkpidxs <- [];
    pkWOTSs <- [];
    leavess <- [];
    pkWOTSs' <- [];
    leavess' <- [];
    (*
      For each WOTS-TW signature/authentication path pair in the forgery, check whether
      the signature is valid on the previous root (first one being the forgery's message),
      then compute the next root using the authentication path and the leaf resulting from
      compressing the WOTS-TW public key derived from the signature.
      Keep track of the intermediate public keys, leaves, and tree/keypair indices.
    *)
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigWOTS', ap') <- nth witness (val sig') (size pkWOTSs');

      pkWOTS' <@ WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS(root', sigWOTS', ps,
                                                     (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      pkWOTS <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size pkWOTSs')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTS;
      leavess <- rcons leavess leaf;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      leavess' <- rcons leavess' leaf';
    }

    (*
      Find (first) index in computed lists of leaves/WOTS-TW public keys where the elements
      consitute a collision
    *)
    cidx <- find (fun (x : ((_ *  _) * _) * _) => x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
                 (zip (zip (zip leavess' leavess) pkWOTSs') pkWOTSs);

    (* Get tree and key pair index corresponding to first collision *)
    (tidx, kpidx) <- nth witness tkpidxs cidx;

    (* Compute index of the collision in the challenge oracle's query list *)
    fidx <- bigi predT (fun i => nr_trees i) 0 cidx * l' + tidx * l' + kpidx;

    (* Get actual collision value  *)
    pkWOTS' <- nth witness pkWOTSs' cidx;

    return (fidx, flatten (map DigestBlock.val (DBLL.val pkWOTS')));
  }
}.

(* Reduction adversary against SM-DT-TCR-C of trh *)
module (R_SMDTTCRCTRH_EUFNAGCMA (A : Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF) : TRHC_TCR.Adv_SMDTTCRC) (O : TRHC_TCR.Oracle_SMDTTCR, OC : TRHC.Oracle_THFC) = {
  var ad : adrs
  var ml : msgFLSLXMSSMTTW list
  var skWOTStd : skWOTS list list list
  var pkWOTStd : pkWOTS list list list
  var sigWOTStd : sigWOTS list list list
  var leavestd : dgstblock list list list
  var nodestd : dgstblock list list list list
  var rootstd : dgstblock list list

  (*
    Collection oracle that wraps given collection oracle,
    allowing to differentiate between queries made by the given
    adversary or the reduction adversary itself (in creating the keypair)
  *)
  module O_THFC : Oracle_THFC = {
    var ads : adrs list
    var xs : dgst list

    proc init(ps : pseed) : unit = {
      ads <- [];
      xs <- [];
    }

    proc query(adq : adrs, x : dgst) : dgstblock = {
      var y : dgstblock;

      y <@ OC.query(adq, x);

      ads <- rcons ads adq;
      xs <- rcons xs x;

      return y;
    }

    proc get_tweaks() : adrs list = {
      return ads;
    }
  }

  proc pick() : unit = {
    var m : msgFLSLXMSSMTTW;
    var em : emsgWOTS;
    var em_ele : int;
    var ch_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt, skWOTSntp : skWOTS list list;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt, pkWOTSntp : pkWOTS list list;
    var sigWOTS : dgstblock list;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt, sigWOTSntp : sigWOTS list list;
    var leaf : dgstblock;
    var leaveslp : dgstblock list;
    var leavesnt, leavesntp : dgstblock list list;
    var root : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var lnode, rnode, node : dgstblock;
    var nodespl, nodescl : dgstblock list;
    var nodes : dgstblock list list;
    var nodesnt : dgstblock list list list;
    var i : int;

    (* Initialize (wrapper around) collection oracle *)
    O_THFC.init(witness);

    (* Ask adversary to provide list of messages to sign *)
    ml <@ A(O_THFC).choose();

    (* Initialize address *)
    ad <- adz;

    (*
      Using the provided oracles, compute and store all the
      WOTS-TW secret keys, WOTS-TW public keys, WOTS-TW signatures,
      (inner tree) leaves, (inner tree) nodes, and (inner tree) roots.
    *)
    skWOTStd <- [];
    pkWOTStd <- [];
    sigWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    (* For each layer in the hypertree, starting from the bottom-most layer,... *)
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      sigWOTSnt <- [];
      leavesnt <- [];
      (*nodesnt <- [];*)
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      (* For each tree in the current layer, starting from the left-most tree,... *)
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        sigWOTSlp <- [];
        leaveslp <- [];
        (* For each leaf of the current tree, starting from the left-most leaf,... *)
        while (size skWOTSlp < l') {
          (* Get the to-be-signed message/root and encode it *)
          root <- nth witness rootsntp (size skWOTSnt * l' + size skWOTSlp);
          em <- encode_msgWOTS root;

          skWOTS <- [];
          pkWOTS <- [];
          sigWOTS <- [];
          (* For each element of the WOTS-TW artifacts... *)
          while (size skWOTS < len) {
            em_ele <- BaseW.val em.[size pkWOTS];

            (* Sample and store a skWOTS element *)
            ch_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS ch_ele;

            if (em_ele = 0) {
              sigWOTS <- rcons sigWOTS ch_ele;
            }

            (* Compute the corresponding signature and public elements *)
            i <- 0;
            while (i < w - 1) {
              ch_ele <@ OC.query(set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype)
                                                                (size skWOTSlp)) (size pkWOTS)) i,
                                 val ch_ele);

              i <- i + 1;

              if (i = em_ele) {
                sigWOTS <- rcons sigWOTS ch_ele;
              }
            }

            pkWOTS <- rcons pkWOTS ch_ele;
          }

          (* Query the collection oracle to compress the obtained WOTS-TW public key to the corresponding leaf *)
          leaf <@ OC.query(set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp),
                           flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS);
          leaveslp <- rcons leaveslp leaf;
        }

        nodes <- [];
        (* For each layer in the current tree, starting from the layer right above the leaves,... *)
        while (size nodes < h') {
          nodespl <- last leaveslp nodes;

          nodescl <- [];
          (* For each (to-be-computed) node in the currently considered layer,... *)
          while (size nodescl < nr_nodes (size nodes + 1)) {
            (* Get the left and right children *)
            lnode <- nth witness nodespl (2 * size nodescl);
            rnode <- nth witness nodespl (2 * size nodescl + 1);

            (* Query the challenge oracle on the concatenation of the children to obtain the node *)
            node <@ O.query(set_thtbidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhtype)
                                        (size nodes + 1) (size nodescl),
                             val lnode ++ val rnode);

            nodescl <- rcons nodescl node;
          }
          nodes <- rcons nodes nodescl;
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt (nth witness (nth witness nodes (h' - 1)) 0); (* Root of current tree is the last computed/stored node *)
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }
  }

  proc find(ps : pseed) : int * dgst = {
    var m : msgFLSLXMSSMTTW;
    var pk : pkFLSLXMSSMTTW;
    var sigWOTS, sigWOTS' : sigWOTS;
    var pkWOTS, pkWOTS' : pkWOTS;
    var ap, ap' : apFLXMSSTW;
    var sapl, sapl' : (sigWOTS * apFLXMSSTW) list;
    var sig : sigFLSLXMSSMTTW;
    var sigl : sigFLSLXMSSMTTW list;
    var m' : msgFLSLXMSSMTTW;
    var sig' : sigFLSLXMSSMTTW;
    var idx' : index;
    var root, root' : dgstblock;
    var tidx, kpidx, hidx, bidx : int;
    var tkpidxs : (int * int) list;
    var leaf, leaf' : dgstblock;
    var leaves, leaves' : dgstblock list;
    var leavess, leavess' : dgstblock list;
    var rootss, rootss' : dgstblock list;
    var cidx, fidx : int;
    var cr;
    var cnode : dgst;

    (* Sign adversary-chosen messages using computed leaves/signatures *)
    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigWOTS <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigWOTS, ap);
      }

      sig <- insubd sapl;
      sigl <- rcons sigl sig;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0; (* Root of hypertree is the last computed root *)

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(O_THFC).forge((root, ps, ad), sigl);

    (tidx, kpidx) <- (val idx', 0);
    root' <- m';
    tkpidxs <- [];
    leavess <- [];
    rootss <- [];
    leavess' <- [];
    rootss' <- [];
    (*
      For each WOTS-TW signature/authentication path pair in the forgery, check whether
      the signature is valid on the previous root (first one being the forgery's message),
      then compute the next root using the authentication path and the leaf resulting from
      compressing the WOTS-TW public key derived from the signature.
      Keep track of the intermediate leaves, roots, and tree/keypair indices.
    *)
    while (size leavess' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigWOTS', ap') <- nth witness (val sig') (size leavess');

      pkWOTS' <@ WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS(root', sigWOTS', ps,
                                                     (set_kpidx (set_typeidx (set_ltidx ad (size leavess') tidx) chtype) kpidx));

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size leavess') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size leavess')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size leavess') tidx) trhtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size leavess')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      rootss <- rcons rootss root;
      leavess <- rcons leavess leaf;
      rootss' <- rcons rootss' root';
      leavess' <- rcons leavess' leaf';
    }

    (* Get index of the first authentication path (in the forgery) that allows the extraction of a collision *)
    cidx <- find (fun (x : ((_ *  _) * _) * _) => x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2)
                 (zip (zip (zip rootss' rootss) leavess') leavess);


    (* Get authentication path and leaf that allow to extract a collision *)
    (sigWOTS', ap') <- nth witness (val sig') cidx;
    leaf' <- nth witness leavess' cidx;

    (* Get tree and key pair index corresponding to first collision *)
    (tidx, kpidx) <- nth witness tkpidxs cidx;

    (* Get leaves of the tree in which collision occurs *)
    leaves <- nth witness (nth witness leavestd cidx) tidx;

    (* Extract collision information from considered (inner) tree *)
    cr <- extract_coll_bt_ap_trh ps (set_typeidx (set_ltidx ad cidx tidx)  trhtype)
                                 (list2tree leaves) (val ap') (rev (int2bs h' kpidx)) leaf' h' 0;

    (* Get collision and height/breadth indices *)
    cnode <- (val cr.`3) ++ (val cr.`4);
    (hidx, bidx) <- cr.`5;

    (* Compute index in the challenge oracle's query list of the collision *)
    fidx <- bigi predT (fun i => nr_trees i) 0 cidx * (2 ^ h' - 1) + tidx * (2 ^ h' - 1) +
            bigi predT (fun i => nr_nodes i) 1 hidx + bidx;

    return (fidx, cnode);
  }
}.


section Proof_EUF_NAGCMA_FL_SL_XMSS_MT_ES_NPRF.
(* -- Declarations -- *)
declare module A <: Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF {
(* WOTS-TW *)
-WTWES.O_MEUFGCMA_WOTSTWESNPRF,
-WTWES.FC_UD.O_SMDTUD_Default,
-WTWES.FC_TCR.O_SMDTTCR_Default,
-WTWES.FC_PRE.O_SMDTPRE_Default,
-FC.O_THFC_Default,
-WTWES.R_SMDTUDC_Game23WOTSTWES,
-WTWES.R_SMDTTCRC_Game34WOTSTWES,
-WTWES.R_SMDTPREC_Game4WOTSTWES,
(* PKCO/TRH *)
-PKCOC_TCR.O_SMDTTCR_Default,
-PKCOC_TCR.O_SMDTTCR_Default,
-TRHC_TCR.O_SMDTTCR_Default,
-TRHC_TCR.O_SMDTTCR_Default,
-PKCOC.O_THFC_Default,
-TRHC.O_THFC_Default,
(* Local *)
-R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA,
-R_SMDTTCRCPKCO_EUFNAGCMA,
-R_SMDTTCRCTRH_EUFNAGCMA
}.

(* Assuming the given oracle terminates, the adversary's choose procedure terminates as well *)
declare axiom A_choose_ll (OC <: Oracle_THFC{-A}) :
  islossless OC.query => islossless A(OC).choose.

(*
  The adversary's forge procedure terminates as well
  (independent of whether the given oracle terminates, because the adversary is not allowed to
   call any procedures of the given oracle in its forge procedure
*)
declare axiom A_forge_ll (OC <: Oracle_THFC{-A}) :
  islossless A(OC).forge.


(* -- Auxiliary/Local oracles -- *)
(* Import definitions/lemmas to refactor oracles into desired form *)
local clone DMap.DMapSampling as DMS with
  type t1 <- dgstblock list,
  type t2 <- skWOTS.

local clone DList.Program as DLP with
  type t <- dgstblock,
    op d <- ddgstblock.

(* Several incremental refactors of the original (signing) M-EUF-GCMA oracle for WOTS-TW  *)
local module O_MEUFGCMA_WOTSTWESNPRF_DMSDLP = {
  import var O_MEUFGCMA_WOTSTWESNPRF

  proc query_dms(wad : wadrs, m : msgWOTS) : pkWOTS * sigWOTS = {
    var skWOTS : skWOTS;
    var skWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTS_ele : dgstblock;
    var em : emsgWOTS;
    var em_ele : int;

    skWOTS <@ DMS.S.sample(ddgstblockl, DBLL.insubd);

    pkWOTS <- [];
    while (size pkWOTS < len) {
      skWOTS_ele <- nth witness (val skWOTS) (size pkWOTS);
      pkWOTS_ele <- cf ps (set_chidx (val wad) (size pkWOTS)) 0 (w - 1) (val skWOTS_ele);

      pkWOTS <- rcons pkWOTS pkWOTS_ele;
    }

    em <- encode_msgWOTS m;
    sigWOTS <- [];
    while (size sigWOTS < len) {
      skWOTS_ele <- nth witness (val skWOTS) (size sigWOTS);
      em_ele <- val em.[size sigWOTS];
      sigWOTS_ele <- cf ps (set_chidx (val wad) (size sigWOTS)) 0 em_ele (val skWOTS_ele);

      sigWOTS <- rcons sigWOTS sigWOTS_ele;
    }

    qs <- rcons qs (val wad, m, DBLL.insubd pkWOTS, DBLL.insubd sigWOTS);

    return (DBLL.insubd pkWOTS, DBLL.insubd sigWOTS);
  }

  proc query_dlp(wad : wadrs, m : msgWOTS) : pkWOTS * sigWOTS = {
    var skWOTS : dgstblock list;
    var skWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTS_ele : dgstblock;
    var em : emsgWOTS;
    var em_ele : int;

    skWOTS <@ DLP.Sample.sample(len);

    pkWOTS <- [];
    while (size pkWOTS < len) {
      skWOTS_ele <- nth witness skWOTS (size pkWOTS);
      pkWOTS_ele <- cf ps (set_chidx (val wad) (size pkWOTS)) 0 (w - 1) (val skWOTS_ele);

      pkWOTS <- rcons pkWOTS pkWOTS_ele;
    }

    em <- encode_msgWOTS m;
    sigWOTS <- [];
    while (size sigWOTS < len) {
      skWOTS_ele <- nth witness skWOTS (size sigWOTS);
      em_ele <- val em.[size sigWOTS];
      sigWOTS_ele <- cf ps (set_chidx (val wad) (size sigWOTS)) 0 em_ele (val skWOTS_ele);

      sigWOTS <- rcons sigWOTS sigWOTS_ele;
    }

    qs <- rcons qs (val wad, m, DBLL.insubd pkWOTS, DBLL.insubd sigWOTS);

    return (DBLL.insubd pkWOTS, DBLL.insubd sigWOTS);
  }
}.

(* Original (signing) M-EUF-GCMA oracle for WOTS-TW-ES-NPRF, but refactored as to facilitate the proof *)
local module O_MEUFGCMA_WOTSTWESNPRF_V = {
  include var O_MEUFGCMA_WOTSTWESNPRF [-query]

  proc query(wad : wadrs, m : msgWOTS) : pkWOTS * sigWOTS = {
    var skWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTS_ele : dgstblock;
    var em : emsgWOTS;
    var em_ele : int;

    em <- encode_msgWOTS m;

    pkWOTS <- [];
    sigWOTS <- [];
    while (size pkWOTS < len) {
      em_ele <- val em.[size pkWOTS];

      skWOTS_ele <$ ddgstblock;

      sigWOTS_ele <- cf ps (set_chidx (val wad) (size pkWOTS)) 0 em_ele (val skWOTS_ele);
      pkWOTS_ele <- cf ps (set_chidx (val wad) (size pkWOTS)) em_ele (w - 1 - em_ele) (val sigWOTS_ele);

      pkWOTS <- rcons pkWOTS pkWOTS_ele;
      sigWOTS <- rcons sigWOTS sigWOTS_ele;
    }

    qs <- rcons qs (val wad, m, DBLL.insubd pkWOTS, DBLL.insubd sigWOTS);

    return (DBLL.insubd pkWOTS, DBLL.insubd sigWOTS);
  }
}.

(* --- Equivalences related to oracles --- *)
local equiv Eqv_O_MEUFGCMA_WOTSTWESNPRF_query_Orig_V :
   O_MEUFGCMA_WOTSTWESNPRF.query ~ O_MEUFGCMA_WOTSTWESNPRF_V.query :
     ={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, arg} ==> ={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, res}.
proof.
transitivity O_MEUFGCMA_WOTSTWESNPRF_DMSDLP.query_dms
             (={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, arg}
              ==>
              ={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, res})
             (={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, arg}
              ==>
              ={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, res}) => [/# | // | |].
+ proc.
  inline{1} 2; inline{1} 1.
  swap{1} 3 -2.
  seq 1 1 : (#pre /\ skWOTS0{1} = skWOTS{2}) => />.
  - inline{2} 1.
    by wp; rnd; wp; skip.
  inline{1} 3.
  sp 5 0 => />.
  seq 2 2 : (#pre /\ pkWOTS0{1} = pkWOTS{2}) => />.
  - while (#pre /\ #post); 1: by wp.
    by wp.
  sp 8 1; wp => />.
  conseq (: _ ==> sig0{1} = sigWOTS{2}) => //.
  while (#pre /\ #post); 1: by wp.
  by wp.
transitivity O_MEUFGCMA_WOTSTWESNPRF_DMSDLP.query_dlp
             (={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, arg}
              ==>
              ={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, res})
             (={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, arg}
              ==>
              ={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, res}) => [/# | // | |].
+ proc.
  seq 1 1 : (#pre /\ val skWOTS{1} = skWOTS{2}).
  - inline{1} 1; inline{2} 1.
    wp; rnd DBLL.val DBLL.insubd.
    wp; skip => />.
    split => [skl sklin | insdk]; 1: by rewrite insubdK 2://; smt(ge2_len supp_dlist_size).
    split => [skl sklin | eqmu1 sk /supp_dmap [skv [skvin ->]]]; 2: by rewrite insubdK 2://; smt(ge2_len supp_dlist_size).
    move: (insdk skl sklin) => {1}->.
    rewrite (in_dmap1E_can _ _ DBLL.val) 3://; 1: by rewrite insubdK 2://; smt(ge2_len supp_dlist_size).
    by move=> y yin <-; 1: by rewrite insubdK 2://; smt(ge2_len supp_dlist_size).
  wp => /=.
  conseq (: _
            ==>
            ={O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, pkWOTS, sigWOTS}) => // />.
  while (={sigWOTS, em, wad, O_MEUFGCMA_WOTSTWESNPRF.ps} /\ val skWOTS{1} = skWOTS{2}).
  - by wp; skip.
  wp => /=.
  while (={pkWOTS, wad, O_MEUFGCMA_WOTSTWESNPRF.ps} /\ val skWOTS{1} = skWOTS{2}).
  - by wp; skip.
  by wp; skip.
proc.
rewrite equiv[{1} 1 DLP.Sample_LoopSnoc_eq].
inline{1} 1.
seq 5 4 : (   #pre
           /\ em{2} = encode_msgWOTS m{2}
           /\ pkWOTS{2}
              =
              mkseq (fun (i : int) =>
                      cf O_MEUFGCMA_WOTSTWESNPRF.ps{2} (set_chidx (val wad{2}) i) 0 (w - 1) (val (nth witness skWOTS{1} i))) len
           /\ sigWOTS{2}
              =
              mkseq (fun (i : int) =>
                      cf O_MEUFGCMA_WOTSTWESNPRF.ps{2} (set_chidx (val wad{2}) i) 0 (BaseW.val em{2}.[i]) (val (nth witness skWOTS{1} i))) len
           /\ size skWOTS{1} = len).
+ wp => /=.
  while (   i{1} = size pkWOTS{2}
         /\ pkWOTS{2}
            =
            mkseq (fun (i : int) =>
                    cf O_MEUFGCMA_WOTSTWESNPRF.ps{2} (set_chidx (val wad{2}) i) 0 (w - 1) (val (nth witness l{1} i))) (size pkWOTS{2})
         /\ sigWOTS{2}
            =
            mkseq (fun (i : int) =>
                    cf O_MEUFGCMA_WOTSTWESNPRF.ps{2} (set_chidx (val wad{2}) i) 0 (BaseW.val em{2}.[i]) (val (nth witness l{1} i))) (size sigWOTS{2})
         /\ size pkWOTS{2} <= len
         /\ size pkWOTS{2} = size sigWOTS{2}
         /\ size l{1} = size sigWOTS{2}
         /\ n{1} = len).
  - wp; rnd; wp; skip => /> &1 &2 pkwdef sigwdef _ eqszpksig eqszlsig ltlen_szpk sk_ele skelein.
    rewrite ?size_rcons /= ?mkseqS /=; 1,2: smt(size_ge0).
    rewrite andbA; split; 2: smt(size_cat).
    split; congr.
    * rewrite {1}pkwdef &(eq_in_mkseq) => j rng_j /=.
      by rewrite nth_cat (: j < size l{1}) 1:/#.
    * rewrite nth_cat eqszlsig -eqszpksig /= {-1}(: w - 1 = val em{2}.[size pkWOTS{2}] + (w - 1 - val em{2}.[size pkWOTS{2}])) 1:/#.
      rewrite eq_sym /cf ch_comp 3,7:// 2:valP 2:// 4:/#; 2,3: smt(BaseW.valP).
      rewrite /set_chidx /set_idx /valid_wadrs /valid_wadrsidxs; split; 1: smt(Adrs.valP).
      rewrite /valid_widxvals insubdK 1:valid_wadrsidxs_adrsidxs /valid_wadrsidxs; split; 1: smt(size_put Adrs.valP).
      + move: (WAddress.valP (wad{2})).
        rewrite /valid_wadrs /valid_wadrsidxs /valid_widxvals => -[szadl [#]].
        rewrite ?drop_put_out 1:// ?nth_drop 1..8:// /=.
        rewrite drop_drop 1,2:// /= take_put /= => -> -> -> ->  -> /= vallp.
        by rewrite /valid_widxvalslp ?nth_put 1,2:size_take ?szadl 1,3:// /=; smt(ge6_adrslen size_ge0 ge2_len).
      + move: (WAddress.valP (wad{2})).
        rewrite /valid_wadrs /valid_wadrsidxs /valid_widxvals => -[szadl [#]].
        by rewrite ?drop_put_out 1:// ?nth_drop 1..8:// /=.
      move: (WAddress.valP (wad{2})).
      rewrite /valid_wadrs /valid_wadrsidxs /valid_widxvals => -[szadl [#]].
      by rewrite /valid_widxvalslp ?nth_take 1..8:// ?nth_put /=; smt(size_ge0 ge6_adrslen Adrs.valP).
    * rewrite {1}sigwdef &(eq_in_mkseq) => j rng_j /=.
      by rewrite nth_cat (: j < size l{1}) 1:/#.
    by rewrite nth_cat eqszlsig -eqszpksig.
  wp; skip => /> &2.
  by rewrite 2!mkseq0 /=; smt(ge2_len).
wp => /=.
while{1} (sigWOTS{1}
          =
          mkseq (fun (i : int) =>
                  cf O_MEUFGCMA_WOTSTWESNPRF.ps{1} (set_chidx (val wad{1}) i) 0 (BaseW.val em{1}.[i]) (val (nth witness skWOTS{1} i))) (size sigWOTS{1})
          /\ size sigWOTS{1} <= len)
         (len - size sigWOTS{1}).
+ move=> _ z.
  wp; skip => /> &1 sigwdef _ ltlen_szsigw.
  by rewrite ?size_rcons mkseqS 2:{1}sigwdef /=; smt(size_ge0).
wp => /=.
while{1} (pkWOTS{1}
          =
          mkseq (fun (i : int) =>
                  cf O_MEUFGCMA_WOTSTWESNPRF.ps{1} (set_chidx (val wad{1}) i) 0 (w - 1) (val (nth witness skWOTS{1} i))) (size pkWOTS{1})
          /\ size pkWOTS{1} <= len)
         (len - size pkWOTS{1}).
+ move=> _ z.
  wp; skip => /> &1 pkwdef _ ltlen_szpkw.
  by rewrite ?size_rcons mkseqS 2:{1}pkwdef /=; smt(size_ge0).
by wp; skip => /> &1 &2 eqlen_szsk; smt(mkseq0 ge2_len).
qed.

local lemma EqPr_MEUFGCMAWOTSTWESNPRF_Orig_V &m :
  Pr[M_EUF_GCMA_WOTSTWESNPRF(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A), O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
  =
  Pr[M_EUF_GCMA_WOTSTWESNPRF(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A), O_MEUFGCMA_WOTSTWESNPRF_V, FC.O_THFC_Default).main() @ &m : res].
proof.
byequiv => //.
proc.
seq 4 4 : (={glob A, glob R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA, ps, O_MEUFGCMA_WOTSTWESNPRF.qs, FC.O_THFC_Default.tws}); 2: by sim.
inline{1} 4; inline{2} 4.
while (#post /\ ={O_MEUFGCMA_WOTSTWESNPRF.ps, FC.O_THFC_Default.pp}).
+ wp => /=.
  while (={R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad, R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd, O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, FC.O_THFC_Default.pp, FC.O_THFC_Default.tws, rootsnt, rootsntp, leavesnt, sigWOTSnt, pkWOTSnt}).
  - wp => /=.
    while (={R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad, R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd, FC.O_THFC_Default.pp, FC.O_THFC_Default.tws, nodes, pkWOTSnt, pkWOTSlp, leaveslp}).
    * by sim.
    wp => /=.
    while (={R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad, R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd, O_MEUFGCMA_WOTSTWESNPRF.ps, O_MEUFGCMA_WOTSTWESNPRF.qs, FC.O_THFC_Default.pp, FC.O_THFC_Default.tws, pkWOTSnt, rootsntp, leaveslp, sigWOTSlp, pkWOTSlp}).
    * wp => /=.
      call (: ={glob FC.O_THFC_Default}); 1: by sim.
      call Eqv_O_MEUFGCMA_WOTSTWESNPRF_query_Orig_V.
      by wp; skip.
    by wp; skip.
  by wp; skip.
wp => />.
call (: ={R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.xs, R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads, FC.O_THFC_Default.tws, FC.O_THFC_Default.pp}); 1: by sim.
inline *.
by wp; rnd; skip.
qed.

local equiv Eqv_Choose_V_Orig :
  A(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A, O_MEUFGCMA_WOTSTWESNPRF_V, FC.O_THFC_Default).O_THFC).choose
  ~
  A(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).O_THFC).choose :
     ={glob A(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A, O_MEUFGCMA_WOTSTWESNPRF_V, FC.O_THFC_Default).O_THFC)}
    ==>
     ={glob A(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A, O_MEUFGCMA_WOTSTWESNPRF_V, FC.O_THFC_Default).O_THFC)}.
proof.
proc (={R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.xs, R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads, FC.O_THFC_Default.tws, FC.O_THFC_Default.pp}) => //.
proc; inline *.
by wp; skip.
qed.


(* -- Auxiliary/Local security notions -- *)
(*
  EUF-NAGCMA of FL-SL-XMSS-MT-TW-ES-NPRF (using O_THFC_Default), but with inlined key generation and additional checks
  for whether the provided forgery contains a valid WOTS-TW (M-EUF-GCMA) forgery,
  pkco (SM-DT-TCR-C) collision, and trh (SM-DT-TCR-C) collision.
*)
local module EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C = {
  var valid_WOTSTWES, valid_TCRPKCO, valid_TCRTRH : bool

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTW list;
    var m, m' : msgFLSLXMSSMTTW;
    var sig, sig' : sigFLSLXMSSMTTW;
    var idx' : index;
    var is_valid, is_fresh : bool;
    var adsOC : adrs list;
    var em : emsgWOTS;
    var em_ele : int;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt, skWOTSntp : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var pkWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt, pkWOTSntp : pkWOTS list list;
    var pkWOTStd : pkWOTS list list list;
    var sigWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt, sigWOTSntp : sigWOTS list list;
    var sigWOTStd : sigWOTS list list list;
    var leaf, leaf' : dgstblock;
    var leaves, leaves', leaveslp : dgstblock list;
    var leavesnt, leavesntp : dgstblock list list;
    var leavestd : dgstblock list list list;
    var root, root' : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var rootstd : dgstblock list list;
    var sapl : (sigWOTS * apFLXMSSTW) list;
    var ap, ap' : apFLXMSSTW;
    var sigWOTS', sigWOTSins : sigWOTS;
    var pkWOTS', pkWOTSins : pkWOTS;
    var pkWOTStd' : pkWOTS list;
    var leavestd', rootstd' : dgstblock list;
    var tidx, kpidx : int;
    var tkpidxs : (int * int) list;
    var pkWOTSs, pkWOTSs' : pkWOTS list;
    var leavess, leavess' : dgstblock list;
    var rootss, rootss' : dgstblock list;
    var forgeryfs, tclfs, tcrfs : bool list;
    var cidx : int;

    (* Initialize address and public seed *)
    ad <- adz;
    ps <$ dpseed;

    (* Initiliaze collection oracle *)
    O_THFC_Default.init(ps);

    (* Ask adversary for list of messages to sign *)
    ml <@ A(O_THFC_Default).choose();

    (* (pk, sk) <@ FL_SL_XMSS_MT_ES_NPRF.keygen(ps, ad); *)
    (*
      Using the provided oracles, compute and store all the
      WOTS-TW secret keys, WOTS-TW public keys, WOTS-TW signatures,
      (inner tree) leaves, and (inner tree) roots.
    *)
    skWOTStd <- [];
    pkWOTStd <- [];
    sigWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    (* For each layer in the hypertree, starting from the bottom-most layer,... *)
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      sigWOTSnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      (* For each tree in the current layer, starting from the left-most tree,... *)
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        sigWOTSlp <- [];
        leaveslp <- [];
        (* For each leaf of the current tree, starting from the left-most leaf,... *)
        while (size skWOTSlp < l') {
          (* Get the to-be-signed message/root and encode it *)
          root <- nth witness rootsntp (size skWOTSnt * l' + size skWOTSlp);
          em <- encode_msgWOTS root;

          skWOTS <- [];
          pkWOTS <- [];
          sigWOTS <- [];
          (* For each element of the WOTS-TW artifacts... *)
          while (size skWOTS < len) {
            em_ele <- BaseW.val em.[size skWOTS];

            (* Sample a skWOTS element *)
            skWOTS_ele <$ ddgstblock;

            sigWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype)
                                                       (size skWOTSlp)) (size skWOTS))
                              0 em_ele (val skWOTS_ele);

            pkWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS))
                             em_ele (w - 1 - em_ele) (val sigWOTS_ele);

            skWOTS <- rcons skWOTS skWOTS_ele;
            pkWOTS <- rcons pkWOTS pkWOTS_ele;
            sigWOTS <- rcons sigWOTS sigWOTS_ele;
          }

          leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp)) (flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS);
          leaveslp <- rcons leaveslp leaf;
        }

        root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhtype)
                           (list2tree leaveslp);

        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt root;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0; (* Root of hypertree is the last computed root *)

    pk <- (root, ps, ad);

    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigWOTSins <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigWOTSins, ap);
      }

      sig <- insubd sapl;
      sigl <- rcons sigl sig;
    }

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(O_THFC_Default).forge(pk, sigl);

    is_valid <@ FL_SL_XMSS_MT_ES_NPRF.verify(pk, m', sig', idx');

    is_fresh <- m' <> nth witness ml (val idx');

    (tidx, kpidx) <- (val idx', 0);
    root' <- m';
    tkpidxs <- [];
    pkWOTSs <- [];
    leavess <- [];
    rootss <- [];
    pkWOTSs' <- [];
    leavess' <- [];
    rootss' <- [];
    (*
      For each WOTS-TW signature/authentication path pair in the forgery, check whether
      the signature is valid on the previous root (first one being the forgery's message),
      then compute the next root using the authentication path and the leaf resulting from
      compressing the WOTS-TW public key derived from the signature.
      Keep track of the intermediate WOTS-TW public keys, leaves, roots, and tree/keypair indices.
    *)
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigWOTS', ap') <- nth witness (val sig') (size pkWOTSs');

      pkWOTS' <@ WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS(root', sigWOTS', ps,
                                                     (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      pkWOTSins <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size pkWOTSs')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTSins;
      rootss <- rcons rootss root;
      leavess <- rcons leavess leaf;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      rootss' <- rcons rootss' root';
      leavess' <- rcons leavess' leaf';
    }

    valid_WOTSTWES <- exists (i : int), 0 <= i < d /\ nth witness pkWOTSs' i = nth witness pkWOTSs i
                                                   /\ nth witness (m' :: rootss') i <> nth witness (nth witness ml (val idx') :: rootss) i;
    valid_TCRPKCO <- exists (i : int), 0 <= i < d /\ nth witness leavess' i = nth witness leavess i
                                                  /\ nth witness pkWOTSs' i <> nth witness pkWOTSs i;
    valid_TCRTRH <- exists (i : int), 0 <= i < d /\ nth witness (m' :: rootss') (i + 1) = nth witness (nth witness ml (val idx') :: rootss) (i + 1)
                                                 /\ nth witness leavess' i <> nth witness leavess i;

    return is_valid /\ is_fresh;
  }
}.

(*
  EUF-NAGCMA of FL-SL-XMSS-MT-TW-ES-NPRF (using O_THFC_Default), but with inlined key generation and
  validity check, as well as additional checks for whether the provided forgery contains a valid WOTS-TW (M-EUF-GCMA) forgery,
  pkco (SM-DT-TCR-C) collision, and trh (SM-DT-TCR-C) collision. Also removes unnecessary duplication of
  operations due to inlining of procedures and the checks.
*)
local module EUF_NAGCMA_FLSLXMSSMTTWESNPRF_V = {
  import var EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C

  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTW list;
    var m, m' : msgFLSLXMSSMTTW;
    var sig, sig' : sigFLSLXMSSMTTW;
    var idx' : index;
    var is_valid, is_fresh : bool;
    var adsOC : adrs list;
    var em : emsgWOTS;
    var em_ele : int;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt, skWOTSntp : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var pkWOTS_ele : dgstblock;
    var pkWOTS : dgstblock list;
    var pkWOTSlp : pkWOTS list;
    var pkWOTSnt, pkWOTSntp : pkWOTS list list;
    var pkWOTStd : pkWOTS list list list;
    var sigWOTS_ele : dgstblock;
    var sigWOTS : dgstblock list;
    var sigWOTSlp : sigWOTS list;
    var sigWOTSnt, sigWOTSntp : sigWOTS list list;
    var sigWOTStd : sigWOTS list list list;
    var leaf, leaf' : dgstblock;
    var leaves, leaves', leaveslp : dgstblock list;
    var leavesnt, leavesntp : dgstblock list list;
    var leavestd : dgstblock list list list;
    var root, root' : dgstblock;
    var rootsnt, rootsntp : dgstblock list;
    var rootstd : dgstblock list list;
    var sapl : (sigWOTS * apFLXMSSTW) list;
    var ap, ap' : apFLXMSSTW;
    var sigWOTS', sigWOTSins : sigWOTS;
    var pkWOTS', pkWOTSins : pkWOTS;
    var tidx, kpidx : int;
    var tkpidxs : (int * int) list;
    var forgeryfs, tclfs, tcrfs : bool list;
    var pkWOTSs', pkWOTSs : pkWOTS list;
    var leavess', leavess : dgstblock list;
    var rootss', rootss : dgstblock list;
    var pkWOTStd' : pkWOTS list;
    var leavestd', rootstd' : dgstblock list;
    var cidx : int;

    (* Initialize address and public seed *)
    ad <- adz;
    ps <$ dpseed;

    (* Initiliaze collection oracle *)
    O_THFC_Default.init(ps);

    (* Ask adversary for list of messages to sign *)
    ml <@ A(O_THFC_Default).choose();

    (* (pk, sk) <@ FL_SL_XMSS_MT_ES_NPRF.keygen(ps, ad); *)
    (*
      Using the provided oracles, compute and store all the
      WOTS-TW secret keys, WOTS-TW public keys, WOTS-TW signatures,
      (inner tree) leaves, and (inner tree) roots.
    *)
    skWOTStd <- [];
    pkWOTStd <- [];
    sigWOTStd <- [];
    leavestd <- [];
    rootstd <- [];
    (* For each layer in the hypertree, starting from the bottom-most layer,... *)
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      pkWOTSnt <- [];
      sigWOTSnt <- [];
      leavesnt <- [];
      rootsnt <- [];
      rootsntp <- last ml rootstd;
      (* For each tree in the current layer, starting from the left-most tree,... *)
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        pkWOTSlp <- [];
        sigWOTSlp <- [];
        leaveslp <- [];
        (* For each leaf of the current tree, starting from the left-most leaf,... *)
        while (size skWOTSlp < l') {
          (* Get the to-be-signed message/root and encode it *)
          root <- nth witness rootsntp (size skWOTSnt * l' + size skWOTSlp);
          em <- encode_msgWOTS root;

          skWOTS <- [];
          pkWOTS <- [];
          sigWOTS <- [];
          (* For each element of the WOTS-TW artifacts... *)
          while (size skWOTS < len) {
            em_ele <- BaseW.val em.[size skWOTS];

            (* Sample a skWOTS element *)
            skWOTS_ele <$ ddgstblock;

            sigWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype)
                                                       (size skWOTSlp)) (size skWOTS))
                              0 em_ele (val skWOTS_ele);

            pkWOTS_ele <- cf ps (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS))
                             em_ele (w - 1 - em_ele) (val sigWOTS_ele);

            skWOTS <- rcons skWOTS skWOTS_ele;
            pkWOTS <- rcons pkWOTS pkWOTS_ele;
            sigWOTS <- rcons sigWOTS sigWOTS_ele;
          }

          leaf <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) pkcotype) (size skWOTSlp)) (flatten (map DigestBlock.val pkWOTS));

          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
          pkWOTSlp <- rcons pkWOTSlp (DBLL.insubd pkWOTS);
          sigWOTSlp <- rcons sigWOTSlp (DBLL.insubd sigWOTS);
          leaveslp <- rcons leaveslp leaf;
        }

        root <- val_bt_trh ps (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) trhtype)
                           (list2tree leaveslp);

        skWOTSnt <- rcons skWOTSnt skWOTSlp;
        pkWOTSnt <- rcons pkWOTSnt pkWOTSlp;
        sigWOTSnt <- rcons sigWOTSnt sigWOTSlp;
        leavesnt <- rcons leavesnt leaveslp;
        rootsnt <- rcons rootsnt root;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt;
      pkWOTStd <- rcons pkWOTStd pkWOTSnt;
      sigWOTStd <- rcons sigWOTStd sigWOTSnt;
      leavestd <- rcons leavestd leavesnt;
      rootstd <- rcons rootstd rootsnt;
    }

    root <- nth witness (nth witness rootstd (d - 1)) 0; (* Root of hypertree is the last computed root *)
    pk <- (root, ps, ad);

    sigl <- [];
    while (size sigl < l) {
      m <- nth witness ml (size sigl);

      sapl <- [];
      (tidx, kpidx) <- (size sigl, 0);
      while (size sapl < d) {
        (tidx, kpidx) <- edivz tidx l';

        sigWOTSins <- nth witness (nth witness (nth witness sigWOTStd (size sapl)) tidx) kpidx;

        leaves <- nth witness (nth witness leavestd (size sapl)) tidx;

        ap <- cons_ap_trh ps (set_typeidx (set_ltidx ad (size sapl) tidx) trhtype) (list2tree leaves) kpidx;

        sapl <- rcons sapl (sigWOTSins, ap);
      }

      sig <- insubd sapl;
      sigl <- rcons sigl sig;
    }

    (* Ask adversary to provide a forgery (given public key and list of signatures) *)
    (m', sig', idx') <@ A(O_THFC_Default).forge(pk, sigl);

    is_fresh <- m' <> nth witness ml (val idx');

    (tidx, kpidx) <- (val idx', 0);
    root' <- m';
    tkpidxs <- [];
    pkWOTSs <- [];
    leavess <- [];
    rootss <- [];
    pkWOTSs' <- [];
    leavess' <- [];
    rootss' <- [];
    (*
      For each WOTS-TW signature/authentication path pair in the forgery, check whether
      the signature is valid on the previous root (first one being the forgery's message),
      then compute the next root using the authentication path and the leaf resulting from
      compressing the WOTS-TW public key derived from the signature.
      Keep track of the intermediate WOTS-TW public keys, leaves, roots, and tree/keypair indices.
    *)
    while (size pkWOTSs' < d) {
      (tidx, kpidx) <- edivz tidx l';

      (sigWOTS', ap') <- nth witness (val sig') (size pkWOTSs');

      pkWOTS' <@ WOTS_TW_ES_NPRF.pkWOTS_from_sigWOTS(root', sigWOTS', ps,
                                                     (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) chtype) kpidx));
      pkWOTSins <- nth witness (nth witness (nth witness pkWOTStd (size pkWOTSs')) tidx) kpidx;

      leaf' <- pkco ps (set_kpidx (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) pkcotype) kpidx)
                    (flatten (map DigestBlock.val (val pkWOTS')));
      leaf <- nth witness (nth witness (nth witness leavestd (size pkWOTSs')) tidx) kpidx;

      root' <- val_ap_trh ps (set_typeidx (set_ltidx ad (size pkWOTSs') tidx) trhtype) ap' kpidx leaf';
      root <- nth witness (nth witness rootstd (size pkWOTSs')) tidx;

      tkpidxs <- rcons tkpidxs (tidx, kpidx);
      pkWOTSs <- rcons pkWOTSs pkWOTSins;
      rootss <- rcons rootss root;
      leavess <- rcons leavess leaf;
      pkWOTSs' <- rcons pkWOTSs' pkWOTS';
      rootss' <- rcons rootss' root';
      leavess' <- rcons leavess' leaf';
    }

    valid_WOTSTWES <- exists (i : int), 0 <= i < d /\ nth witness pkWOTSs' i = nth witness pkWOTSs i
                                                   /\ nth witness (m' :: rootss') i <> nth witness (nth witness ml (val idx') :: rootss) i;
    valid_TCRPKCO <- exists (i : int), 0 <= i < d /\ nth witness leavess' i = nth witness leavess i
                                                  /\ nth witness pkWOTSs' i <> nth witness pkWOTSs i;
    valid_TCRTRH <- exists (i : int), 0 <= i < d /\ nth witness (m' :: rootss') (i + 1) = nth witness (nth witness ml (val idx') :: rootss) (i + 1)
                                                 /\ nth witness leavess' i <> nth witness leavess i;

    is_valid <- nth witness (m' :: rootss') d = nth witness (nth witness ml (val idx') :: rootss) d;

    return is_valid /\ is_fresh;
  }
}.


(* --- Equivalences between security notions --- *)
local equiv Eqv_EUFNAGCMA_FLSLXMSSMTTWESNPRF_Orig_C :
  EUF_NAGCMA_FLSLXMSSMTTWESNPRF(A, O_THFC_Default).main ~ EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.main :
    ={glob A} ==> ={res}.
proof.
proc.
seq 7 14 : (={glob A, sigl, pk, ml}); last first.
+ wp.
  while{2} (true) (d - size pkWOTSs'{2}).
  - move=> ? z.
    inline *.
    wp.
    while (true) (len - size pkWOTS0).
    - move=> z'.
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  wp.
  call (: true) => /=; 1: by sim.
  call (: true).
  by skip => />; smt(ge1_d).
inline{1} 5.
seq 14 12 : (   ={glob A, ad, ps, ml, root, skWOTStd, pk}
             /\ pk{1} = (root, ps, ad){1}
             /\ sk{1} = (skWOTStd, ps ,ad){1}
             /\ (forall (i j u v : int),
                   0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                     nth witness (val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0 (w - 1)
                     (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
             /\ (forall (i j u : int),
                   0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness (nth witness (nth witness leavestd{2} i) j) u
                     =
                     pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) pkcotype) u)
                     (flatten (map DigestBlock.val (val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)))))
             /\ (forall (i j : int),
                   0 <= i < d => 0 <= j < nr_trees i =>
                     nth witness (nth witness rootstd{2} i) j
                     =
                     val_bt_trh ps{2} (set_typeidx (set_ltidx ad{2} i j) trhtype)
                                (list2tree (nth witness (nth witness leavestd{2} i) j)))
             /\ (forall (i j u v : int),
                   0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                     nth witness (val (nth witness (nth witness (nth witness sigWOTStd{2} i) j) u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0
                     (BaseW.val (encode_msgWOTS
                                   (if i = 0
                                    then nth witness ml{2} (j * l' + u)
                                    else nth witness (nth witness rootstd{2} (i - 1)) (j * l' + u))).[v])
                     (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
             /\ (forall (i j : int),
                   0 <= i < d => 0 <= j < nr_trees i =>
                     size (nth witness (nth witness leavestd{2} i) j) = l')).
+ inline{1} 10.
  wp => /=.
  while{1} (leaves0{1}
            =
            mkseq (fun (i : int) =>
              pkco ps1{1} (set_kpidx (set_typeidx ad1{1} pkcotype) i)
                   (flatten (map DigestBlock.val (mkseq (fun (j : int) =>
                      cf ps1{1} (set_chidx (set_kpidx (set_typeidx ad1{1} chtype) i) j)
                         0 (w - 1) (val (nth witness (val (nth witness skWOTSl{1} i)) j))) len)))) (size leaves0{1})
            /\ 0 <= size leaves0{1} <= l')
           (l' - size leaves0{1}).
  - move=> _ z.
    inline *.
    wp => /=.
    while (pkWOTS0
           =
           mkseq (fun (j : int) =>
             cf ps2 (set_chidx ad2 j) 0 (w - 1) (val (nth witness (val skWOTS1) j))) (size pkWOTS0)
           /\ 0 <= size pkWOTS0 <= len)
          (len - size pkWOTS0).
    - move=> z'.
      by wp; skip => />; smt(size_rcons mkseqS).
    wp; skip => /> *.
    split => [| pkWOTS]; 1: by rewrite mkseq0 /=; smt(ge2_len).
    split => [/# | /lezNgt gelen_szpk *].
    rewrite insubdK 1:/# size_rcons ?mkseqS 1://.
    rewrite -andbA; split; 2: smt(ge2_len).
    by congr => /=; smt(mkseqS).
  wp => /=.
  while (   ={skWOTStd}
         /\ valid_xadrs ad{2}
         /\ (forall (i j u v : int),
               0 <= i < size pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                 nth witness (val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)) v
                 =
                 cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0 (w - 1)
                 (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
         /\ (forall (i j u : int),
               0 <= i < size leavestd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness leavestd{2} i) j) u
                 =
                 pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} i j) pkcotype) u)
                 (flatten (map DigestBlock.val (val (nth witness (nth witness (nth witness pkWOTStd{2} i) j) u)))))
         /\ (forall (i j : int),
               0 <= i < size rootstd{2} => 0 <= j < nr_trees i =>
                 nth witness (nth witness rootstd{2} i) j
                 =
                 val_bt_trh ps{2} (set_typeidx (set_ltidx ad{2} i j) trhtype)
                            (list2tree (nth witness (nth witness leavestd{2} i) j)))
         /\ (forall (i j u v : int),
               0 <= i < size sigWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' => 0 <= v < len =>
                 nth witness (val (nth witness (nth witness (nth witness sigWOTStd{2} i) j) u)) v
                 =
                 cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0
                 (BaseW.val (encode_msgWOTS
                               (if i = 0
                                then nth witness ml{2} (j * l' + u)
                                else nth witness (nth witness rootstd{2} (i - 1)) (j * l' + u))).[v])
                 (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v)))
         /\ (forall (i j : int),
               0 <= i < size leavestd{2} => 0 <= j < nr_trees i =>
                 size (nth witness (nth witness leavestd{2} i) j) = l')
         /\ 0 <= size skWOTStd{2} <= d
         /\ size skWOTStd{2} = size pkWOTStd{2}
         /\ size skWOTStd{2} = size sigWOTStd{2}
         /\ size skWOTStd{2} = size leavestd{2}
         /\ size skWOTStd{2} = size rootstd{2}).
  - wp.
    while (   ={skWOTStd, skWOTSnt}
           /\ valid_xadrs ad{2}
           /\ rootsntp{2} = last ml{2} rootstd{2}
           /\ (forall (j u v : int),
                 0 <= j < size pkWOTSnt{2} => 0 <= u < l' => 0 <= v < len =>
                   nth witness (val (nth witness (nth witness pkWOTSnt{2} j) u)) v
                   =
                   cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size pkWOTStd{2}) j) chtype) u) v) 0 (w - 1)
                   (val (nth witness (val (nth witness (nth witness skWOTSnt{2} j) u)) v)))
           /\ (forall (j u : int),
                 0 <= j < size leavesnt{2} => 0 <= u < l' =>
                   nth witness (nth witness leavesnt{2} j) u
                   =
                   pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size leavestd{2}) j) pkcotype) u)
                   (flatten (map DigestBlock.val (val (nth witness (nth witness pkWOTSnt{2} j) u)))))
           /\ (forall (j : int),
                 0 <= j < size rootsnt{2} =>
                   nth witness rootsnt{2} j
                   =
                   val_bt_trh ps{2} (set_typeidx (set_ltidx ad{2} (size rootstd{2}) j) trhtype)
                              (list2tree (nth witness leavesnt{2} j)))
           /\ (forall (j u v : int),
                 0 <= j < size sigWOTSnt{2} => 0 <= u < l' => 0 <= v < len =>
                   nth witness (val (nth witness (nth witness sigWOTSnt{2} j) u)) v
                   =
                   cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) j) chtype) u) v) 0
                   (BaseW.val (encode_msgWOTS
                                 (if size sigWOTStd{2} = 0
                                  then nth witness ml{2} (j * l' + u)
                                  else nth witness (nth witness rootstd{2} (size sigWOTStd{2} - 1)) (j * l' + u))).[v])
                   (val (nth witness (val (nth witness (nth witness skWOTSnt{2} j) u)) v)))
           /\ (forall (j : int),
                 0 <= j < size leavesnt{2} =>
                   size (nth witness leavesnt{2} j) = l')
           /\ 0 <= size skWOTSnt{2} <= nr_trees (size skWOTStd{2})
           /\ size skWOTSnt{2} = size pkWOTSnt{2}
           /\ size skWOTSnt{2} = size sigWOTSnt{2}
           /\ size skWOTSnt{2} = size leavesnt{2}
           /\ size skWOTSnt{2} = size rootsnt{2}
           /\ 0 <= size skWOTStd{2} < d
           /\ size skWOTStd{2} = size pkWOTStd{2}
           /\ size skWOTStd{2} = size sigWOTStd{2}
           /\ size skWOTStd{2} = size leavestd{2}
           /\ size skWOTStd{2} = size rootstd{2}).
    * wp.
      while (   ={skWOTStd, skWOTSnt, skWOTSlp}
             /\ valid_xadrs ad{2}
             /\ rootsntp{2} = last ml{2} rootstd{2}
             /\ (forall (u v : int),
                   0 <= u < size pkWOTSlp{2} => 0 <= v < len =>
                     nth witness (val (nth witness pkWOTSlp{2} u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size pkWOTStd{2}) (size pkWOTSnt{2})) chtype) u) v) 0 (w - 1)
                     (val (nth witness (val (nth witness skWOTSlp{2} u)) v)))
             /\ (forall (u : int),
                   0 <= u < size leaveslp{2} =>
                     nth witness leaveslp{2} u
                     =
                     pkco ps{2} (set_kpidx (set_typeidx (set_ltidx ad{2} (size leavestd{2}) (size leavesnt{2})) pkcotype) u)
                     (flatten (map DigestBlock.val (val (nth witness pkWOTSlp{2} u)))))
             /\ (forall (u v : int),
                   0 <= u < size sigWOTSlp{2} => 0 <= v < len =>
                     nth witness (val (nth witness sigWOTSlp{2} u)) v
                     =
                     cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) (size sigWOTSnt{2})) chtype) u) v) 0
                     (BaseW.val (encode_msgWOTS
                                   (if size sigWOTStd{2} = 0
                                    then nth witness ml{2} (size sigWOTSnt{2} * l' + u)
                                    else nth witness (nth witness rootstd{2} (size sigWOTStd{2} - 1)) (size sigWOTSnt{2} * l' + u))).[v])
                     (val (nth witness (val (nth witness skWOTSlp{2} u)) v)))
             /\ 0 <= size skWOTSlp{2} <= l'
             /\ size skWOTSlp{2} = size pkWOTSlp{2}
             /\ size skWOTSlp{2} = size sigWOTSlp{2}
             /\ size skWOTSlp{2} = size leaveslp{2}
             /\ 0 <= size skWOTSnt{2} < nr_trees (size skWOTStd{2})
             /\ size skWOTSnt{2} = size pkWOTSnt{2}
             /\ size skWOTSnt{2} = size sigWOTSnt{2}
             /\ size skWOTSnt{2} = size leavesnt{2}
             /\ size skWOTSnt{2} = size rootsnt{2}
             /\ 0 <= size skWOTStd{2} < d
             /\ size skWOTStd{2} = size pkWOTStd{2}
             /\ size skWOTStd{2} = size sigWOTStd{2}
             /\ size skWOTStd{2} = size leavestd{2}
             /\ size skWOTStd{2} = size rootstd{2}).
      + wp.
        while (   ={skWOTStd, skWOTSnt, skWOTSlp, skWOTS}
               /\ valid_xadrs ad{2}
               /\ em{2} = encode_msgWOTS (nth witness (last ml{2} rootstd{2}) (size skWOTSnt{2} * l' + size skWOTSlp{2}))
               /\ (forall (v : int),
                     0 <= v < size pkWOTS{2} =>
                       nth witness pkWOTS{2} v
                       =
                       cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size pkWOTStd{2}) (size pkWOTSnt{2})) chtype) (size pkWOTSlp{2})) v) 0 (w - 1)
                       (val (nth witness skWOTS{2} v)))
               /\ (forall (v : int),
                     0 <= v < size sigWOTS{2} =>
                       nth witness sigWOTS{2} v
                       =
                       cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size sigWOTStd{2}) (size sigWOTSnt{2})) chtype) (size sigWOTSlp{2})) v) 0
                       (BaseW.val (encode_msgWOTS
                                     (if size sigWOTStd{2} = 0
                                      then nth witness ml{2} (size sigWOTSnt{2} * l' + size sigWOTSlp{2})
                                      else nth witness (nth witness rootstd{2} (size sigWOTStd{2} - 1)) (size sigWOTSnt{2} * l' + size sigWOTSlp{2}))).[v])
                       (val (nth witness skWOTS{2} v)))
               /\ 0 <= size skWOTS{2} <= len
               /\ size skWOTS{2} = size pkWOTS{2}
               /\ size skWOTS{2} = size sigWOTS{2}
               /\ 0 <= size skWOTSlp{2} < l'
               /\ size skWOTSlp{2} = size pkWOTSlp{2}
               /\ size skWOTSlp{2} = size sigWOTSlp{2}
               /\ size skWOTSlp{2} = size leaveslp{2}
               /\ 0 <= size skWOTSnt{2} < nr_trees (size skWOTStd{2})
               /\ size skWOTSnt{2} = size pkWOTSnt{2}
               /\ size skWOTSnt{2} = size sigWOTSnt{2}
               /\ size skWOTSnt{2} = size leavesnt{2}
               /\ size skWOTSnt{2} = size rootsnt{2}
               /\ 0 <= size skWOTStd{2} < d
               /\ size skWOTStd{2} = size pkWOTStd{2}
               /\ size skWOTStd{2} = size sigWOTStd{2}
               /\ size skWOTStd{2} = size leavestd{2}
               /\ size skWOTStd{2} = size rootstd{2}).
        - wp; rnd; wp; skip => |> &2 valad nthpk nthsig ge0_szsk _ eqszsp eqszss ge0_szsklp
                                     ltlp_szsklp eqszlpsp eqszlpss eqszlpsl ge0_szsknt
                                     ltnt_szsknt eqszntsp eqszntss eqszntsl eqszntsr
                                     ge0_szsktd ltd_szskts eqsztdsp eqsztdss eqsztdsl
                                     eqsztdsr ltlen_szsk skele skelein.
          rewrite ?size_rcons; split => [v ge0_v ltszpk1_v|].
          * rewrite 2!nth_rcons; case (v = size pkWOTS{2}) => [eqsz | /#].
            rewrite eqsz eqszsp /= eq_sym.
            pose emt := encode_msgWOTS _.
            rewrite (: w - 1 = val emt.[size pkWOTS{2}] + (w - 1 - val emt.[size pkWOTS{2}])) 1:/# /cf.
            rewrite ch_comp 2:valP //=; 2..4: smt(BaseW.valP val_w).
            - by apply validxadrs_validwadrs_setallch => // /#.
            by rewrite eqsztdsp eqszntsp eqszlpsp; congr; ring.
          split => [v ge0_v ltszsig1_v | /#].
          rewrite 2!nth_rcons eqszss; case (v = size sigWOTS{2}) => [eqsz | /#].
          rewrite eqsz /= eq_sym eqsztdss eqszntss eqszlpss.
          do 4! congr.
          by rewrite (last_nth witness) /= -eqsztdsr eqsztdss /#.
        wp; skip => |> &2 valad nthpks nthlfs nthsigs ge0_szsklp ltlp_szsklp eqszlpsp
                          eqszlpss eqszlpsl ge0_szsknt ltnt_szsknt eqszntsp eqszntss
                          eqszntsl eqszntsr ge0_szsktd ltd_szskts eqsztdsp eqsztdss
                          eqsztdsl eqsztdsr ltl_szsklp.
        split => [| pk sig sk /lezNgt gelen_szsk _]; 1: smt(ge2_len).
        move=> nthpkp nthsigp ge0_szsk lelen_szsk eqszspp eqszssp.
        split => [u v |].
        - rewrite size_rcons => ge0_u ltszpk1_u ge0_v ltlen_v.
          rewrite 2!nth_rcons eqszlpsp; case (u = size pkWOTSlp{2}) => [eqsz | /#].
          by rewrite eqsz /= ?insubdK // /#.
        split => [u |].
        - rewrite size_rcons => ge0_u ltszlp1_u.
          rewrite 2!nth_rcons -eqszlpsp eqszlpsl; case (u = size leaveslp{2}) => [eqsz | /#].
          by rewrite eqsz /= insubdK // /#.
        split => [u v |]; 2: smt(size_rcons).
        rewrite size_rcons => ge0_u ltszsig1_u ge0_v ltlen_v.
        rewrite 2!nth_rcons ?eqszlpss; case (u = size sigWOTSlp{2}) => [eqsz | /#].
        by rewrite eqsz /= ?insubdK // /#.
      wp; skip => |> &2 valad nthpks nthlfs nthrs nthsigs nthszlfs ge0_szsknt lent_szsknt eqszntsp
                        eqszntss eqszntsl eqszntsr ge0_szsktd ltd_szsktd eqsztdsp eqsztdss
                        eqsztdsl eqsztdsr ltnrt_szskts.
      split => [| lfs pks sigs sks /lezNgt gelp_szsks _]; 1: by smt(ge2_lp).
      move=> nthpkp nthlfp nthsigp ge0_szsks lelp_szsks eqszspp eqszssp eqszslp.
      split => [j u v |]; 1: smt(nth_rcons size_rcons).
      split => [j u ge0_j |]; 1: rewrite ?size_rcons ?nth_rcons.
      * by move=> *; rewrite -eqszntsp -eqszntsl /#.
      split => [j ge0_j |]; 1: rewrite ?size_rcons ?nth_rcons.
      * by move=> *; rewrite -eqszntsr -eqszntsl /#.
      split => [j u v ge0_j |]; 1: rewrite ?size_rcons ?nth_rcons.
      * by move=> *; rewrite -eqszntss /#.
      split => [j ge0_j |]; 2: by rewrite ?size_rcons /#.      rewrite nth_rcons size_rcons  => ?; case (j < size leavesnt{2}) => [/# | ?].
      by rewrite (: j = size leavesnt{2}) 1:/# /= -eqszslp /#.
    wp; skip => |> &2 valad nthpk nthlf nthrt nthsig sznthlf ge0_szsk _ eqszpk eqszsig eqszlf eqszrt ltd_szsk.
    split => [|lfs pks rts sigs sks /lezNgt genrt_szsk _].
    - by rewrite /nr_trees expr_ge0 /#.
    move=> nthpkp nthlfp nthrtp nthsigp sznthlfp ge0_szskp lenrt_szsk eqszpkp eqszsigp eqszlfp eqszrtp.
    have eqnrt_szsk : size sks = nr_trees (size skWOTStd{2}) by smt().
    rewrite ?size_rcons -andbA; split => [i j u v *|].
    - by rewrite 2!nth_rcons /#.
    split => [i j u *|].
    - by rewrite 2!nth_rcons /#.
    split => [i j *|].
    - by rewrite 2!nth_rcons /#.
    split => [i j u v *|].
    - rewrite 3!nth_rcons.
      case (i = size sigWOTStd{2}) => [eqsz | neqsz].
      * by rewrite eqsz eqszsig /= nthsigp // /#.
      rewrite (: i < size sigWOTStd{2}) 1:/# /=.
      by rewrite nthsig // /#.
    split => [i j *| /#].
    by rewrite nth_rcons /#.
  wp.
  call (: ={O_THFC_Default.pp}); 1: by sim.
  inline *.
  wp; rnd; wp; skip => |> ps psin ml; rewrite valx_adz /=.
  split => [| lfs pks rs sigs sks /lezNgt ged_szsks _]; 1: smt(ge1_d).
  move => nthpks nthlfs nthrs nthsigs nthszlfs ge0_szsknt lent_szsknt
          eqszntsp eqszntss eqszntsl eqszntsr.
  split => [| lfslp]; 1: smt(ge2_lp mkseq0).
  split => [/#| /lezNgt gelp_szlfslp lfslpval ge0_szlfslp lelp_szlfslp].
  split; first rewrite -andaE; split => //.
  - rewrite nthrs; 1,2: smt(ge1_d expr_gt0).
    do 2! congr; rewrite &(eq_from_nth witness); 1: smt(ge1_d expr_gt0).
    move=> i rng_i; rewrite nthlfs; 1,2,3: smt(ge1_d expr_gt0).
    rewrite lfslpval nth_mkseq //=.
    do 3! congr; rewrite &(eq_from_nth witness) 1:size_mkseq 1:valP; 1: smt(ge2_len).
    move=> j; rewrite size_mkseq => rng_j; rewrite nth_mkseq 1:/# /=.
    by rewrite nthpks //; smt(ge1_d expr_gt0).
  by do ? (split; 1: smt()); smt().
conseq (: _ ==> ={sigl}) => //=.
inline *.
while (#pre /\ ={sigl} /\ 0 <= size sigl{1} <= l).
+ wp; sp 5 1 => />.
  conseq (: _ ==> ={sapl}) => />; 1: by smt(size_rcons).
  while (   #pre
         /\ ={sapl, tidx, kpidx}
         /\ root0{1}
            =
            (if size sapl{1} = 0
             then m0{1}
             else val_bt_trh ps1{1} (set_typeidx (set_ltidx ad1{1} (size sapl{1} - 1) tidx{1}) trhtype)
                    (list2tree (mkseq (fun (i : int) =>
                      pkco ps1{1} (set_kpidx (set_typeidx (set_ltidx ad1{1} (size sapl{1} - 1) tidx{1}) pkcotype) i)
                           (flatten (map DigestBlock.val (mkseq (fun (j : int) =>
                             cf ps1{1} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad1{1} (size sapl{1} - 1) tidx{1}) chtype) i) j) 0 (w - 1)
                                (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0{1} (size sapl{1} - 1)) tidx{1}) i)) j))) len)))) l')))
         /\ (size sapl{1} < d =>
                   tidx{1} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl{1}, 0) (size sapl{1})).`1
                /\ kpidx{1} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl{1}, 0) (size sapl{1})).`2)
         /\ (0 < size sapl{1} => tidx{1} < nr_trees (size sapl{1} - 1))
         /\ 0 <= tidx{1}
         /\ 0 <= kpidx{1} < l'
         /\ 0 <= size sapl{1} <= d).
  - wp => /=.
    while{1} ((forall (i : int), 0 <= i < size leaves1{1} =>
                nth witness leaves1{1} i
                =
                pkco ps3{1} (set_kpidx (set_typeidx ad3{1} pkcotype) i)
                     (flatten (map DigestBlock.val (mkseq (fun (j : int) =>
                       cf ps3{1} (set_chidx (set_kpidx (set_typeidx ad3{1} chtype) i) j) 0 (w - 1) (val (nth witness (val (nth witness skWOTSl{1} i)) j))) len))))
              /\ 0 <= size leaves1{1} <= l')
             (l' - size leaves1{1}).
    * move=> &1 z.
      wp => /=.
      while ((forall (i : int), 0 <= i < size pkWOTS0 =>
                nth witness pkWOTS0 i
                =
                cf ps4 (set_chidx ad4 i) 0 (w - 1) (val (nth witness (val skWOTS3) i)))
             /\ 0 <= size pkWOTS0 <= len)
            (len - size pkWOTS0).
      + move=> z'.
        wp; skip => /> &2 nthval ? ? ?.
        rewrite -!andbA; split; 2: by smt(size_rcons).
        move=> i ge0_i; rewrite size_rcons => ltsz1_i.
        rewrite nth_rcons; case (i = size pkWOTS0{2}) => [-> //| neqsz_i].
        by rewrite (: i < size pkWOTS0{2}) 1:/# /= nthval 1:/#.
      wp; skip => /> &2 nthlf ? ? ?.
      split => [| pkWOTS]; 1: smt(ge2_len).
      split => [/# | /lezNgt gelen_szpk nthpk ? ?].
      rewrite -!andbA; split; 2: by smt(size_rcons).
      move=> i ge0_i; rewrite size_rcons => ltsz1_i.
      rewrite nth_rcons; case (i = size leaves1{2}) => [-> //=| neqsz_i].
      + do 3! congr.
        rewrite insubdK 1:/# &(eq_from_nth witness) => [|j rng_j].
        - by rewrite size_mkseq; smt(ge2_len).
        rewrite (nth_map witness) 1:size_iota /=; 1: smt(ge2_len).
        by rewrite nthpk 1:rng_j nth_iota 1:/# //.
      by rewrite (: i < size leaves1{2}) 1:/# /= nthlf 1:/#.
    wp => /=.
    while{1} ((forall (i : int), 0 <= i < size sig1{1} =>
                nth witness sig1{1} i
                =
                cf ps2{1} (set_chidx ad2{1} i) 0 (BaseW.val em{1}.[i]) (val (nth witness (val skWOTS1{1}) i)))
              /\ 0 <= size sig1{1} <= len)
             (len - size sig1{1}).
    * move=> ? z.
      wp; skip => /> &1 nthsig ? ? ?.
      rewrite -!andbA; split => [i ge0_i|]; 2: smt(size_rcons).
      rewrite size_rcons => ltsz1_i; rewrite nth_rcons.
      case (i = size sig1{1}) => [-> // | neqszs_i].
      by rewrite (: i < size sig1{1}) 1:/# /= nthsig 1:/#.
    wp; skip => /> &2 nthpks nthlfs nthrs nthsigs nthszlfs ge0_szsigl _ ltl_szsigl
                      tkpidxsv ltnt_tidx ge0_tidx ge0_kpidx ltlp_kpidx ge0_szsapl
                      _ ltd_szsapl.
    split => [| siglp]; 1: smt(ge2_len).
    split => [/# | /lezNgt gelen_szsiglp nthsiglp _ lelen_szsiglp].
    split => [| lfsp]; 1: smt(ge2_lp).
    split => [/#| /lezNgt gelp_lfsp nthlfsp _ lelp_lfsp].
    have rng_tidxdiv : 0 <= tidx{2} %/ l' && tidx{2} %/ l' < nr_trees (size sapl{2}).
    * case (size sapl{2} = 0) => [eq0 | neq0] /=.
      + move: (tkpidxsv _); 1: smt().
        rewrite eq0 fold0 /= => -[-> _].
        rewrite divz_ge0 2:ge0_szsigl /= 2:ltz_divLR; 1,2: smt(ge2_lp).
        by rewrite (ltr_le_trans l) // /nr_trees /l' -exprD_nneg 1:mulr_ge0; smt(ge1_hp ge1_d).
      rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
      rewrite (: nr_trees (size sapl{2}) * l' = nr_trees (size sapl{2} - 1)).
      + rewrite /nr_trees /l' -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
        by congr; ring.
      by rewrite ge0_tidx /= ltnt_tidx 1:/#.
    have rng_tidxmod : 0 <= tidx{2} %% l' && tidx{2} %% l' < l' by smt(ge2_lp modz_ge0 ltz_pmod).
    rewrite ?size_rcons -!andbA; split.
    * do 2! congr; 1: rewrite &(DBLL.val_inj).
      + rewrite &(eq_from_nth witness) 1:?valP //.
        move=> i; rewrite valP => rng_i; rewrite insubdK 1:/#.
        rewrite nthsiglp 1:/# nthsigs 1:/# //.
        case (size sapl{2} = 0) => [eq0 | neq0] /=; do ? congr.
        - move: (tkpidxsv ltd_szsapl); rewrite eq0 fold0 /=.
          by rewrite -divz_eq => -[-> _].
        rewrite nthrs 1:/# -?divz_eq; 2: do ? congr.
        - by split => [/#|_]; rewrite ltnt_tidx /#.
        rewrite &(eq_from_nth witness) 1:size_mkseq 1:nthszlfs 1..3:/#.
        move=> j; rewrite size_mkseq => rng_j.
        rewrite nth_mkseq 1:/# /= nthlfs 1..3:/# /=; do ? congr.
        rewrite &(eq_from_nth witness) 1:size_mkseq 1:valP 1:/#.
        move=> m; rewrite size_mkseq => rng_m.
        by rewrite nth_mkseq 1:/# /= nthpks // /#.
      do ? congr; rewrite &(eq_from_nth witness) 1:nthszlfs 1,3:/# //.
      move=> i rng_i; rewrite nthlfsp 2:nthlfs // 1:/#.
      do ? congr; rewrite &(eq_from_nth witness) 1:size_mkseq 1:valP; 1: smt(ge2_len).
      move=> m; rewrite size_mkseq => rng_m.
      by rewrite nth_mkseq 1:/# /= nthpks // /#.
    rewrite andbA; split; 2: smt(size_rcons).
    split; 1: rewrite (: size sapl{2} + 1 <> 0) 1:/# /=.
    * do ? congr; rewrite &(eq_from_nth witness) 1:size_mkseq 1:/#.
      by move=> i rng_i; rewrite nthlfsp 2:nth_mkseq // /#.
    by move=> ltd_szsapl1; rewrite 2?foldS /#.
  by wp; skip => />; smt(ge2_lp ge1_d fold0 Index.valP Index.insubdK).
by wp; skip => />; smt(Top.ge2_l).
qed.

local equiv Eqv_EUFNAGCMA_FLSLXMSSMTTWESNPRF_C_V :
  EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.main ~ EUF_NAGCMA_FLSLXMSSMTTWESNPRF_V.main :
    ={glob A} ==> ={res}.
proof.
proc.
swap{1} 16 14.
conseq (: _ ==> ={is_valid, is_fresh}) => //.
swap{1} [11..12] 2; swap{2} [11..12] 2.
seq 12 12 : (={glob A, ps, ad, ml, sigl, rootstd}); 1: by sim.
seq 14 4 : (   ={is_fresh, ps, ad, m', sig', idx'}
            /\ pk{1} = (nth witness (nth witness rootstd (d - 1)) 0, ps, ad){2}).
+ while{1} (true)
           (d - size pkWOTSs'{1}).
  - move => ? z.
    inline 3.
    wp => /=.
    while (true) (len - size pkWOTS0).
    * move=> z'.
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  wp; call (: true).
  by wp; skip => /> /#.
sp 3 0.
inline{1} 1; inline{1} 6 => />.
wp.
while(   i{1} = size pkWOTSs'{2}
      /\ ps1{1} = ps{2}
      /\ ad1{1} = ad{2}
      /\ tidx0{1} = tidx{2}
      /\ kpidx0{1} = kpidx{2}
      /\ sig1{1} = sig'{2}
      /\ root1{1} = root'{2}
      /\ root'{2} = nth witness (m'{2} :: rootss'{2}) (size pkWOTSs'{2})
      /\ 0 <= tidx{2}
      /\ (size pkWOTSs'{2} < d =>
            tidx{2} < nr_nodes_ht (size pkWOTSs'{2}) 0)
      /\ (size pkWOTSs'{2} < d =>
            tidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (size pkWOTSs'{2})).`1)
      /\ (0 < size pkWOTSs'{2} < d =>
             tidx{2} = (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1)
      /\ (0 < size pkWOTSs'{2} =>
           root{2} = nth witness (nth witness rootstd{2} (size pkWOTSs'{2} - 1)) (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1)
      /\ (0 < size pkWOTSs'{2} =>
           nth witness rootss{2} (size pkWOTSs'{2} - 1)
           =
           nth witness (nth witness rootstd{2} (size pkWOTSs'{2} - 1)) (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1)
      /\ (0 < size pkWOTSs'{2} < d =>
             0 <= (nth witness tkpidxs{2} (size pkWOTSs'{2} - 1)).`1 < nr_nodes_ht (size pkWOTSs'{2} - 1) 0)
      /\ (forall (i : int), 0 <= i < size pkWOTSs'{2} =>
            0 <= (nth witness tkpidxs{2} i).`1 < nr_nodes_ht i 0 %/ l')
      /\ (0 < size pkWOTSs'{2} =>
              (nth witness tkpidxs{2} 0).`1 = val idx'{2} %/ l')
      /\ (forall (i : int), 1 <= i < size pkWOTSs'{2} =>
            (nth witness tkpidxs{2} i).`1 = (nth witness tkpidxs{2} (i - 1)).`1 %/ l')
      /\ size rootss{2} = size pkWOTSs'{2}
      /\ size rootss'{2} = size pkWOTSs'{2}
      /\ size tkpidxs{2} = size pkWOTSs'{2}
      /\ size pkWOTSs'{2} <= d).
+ inline{1} 3; inline{2} 3.
  wp => /=.
  while (   ={em0}
         /\ ps2{1} = ps0{2}
         /\ ad2{1} = ad0{2}
         /\ pkWOTS1{1} = pkWOTS0{2}
         /\ sig2{1} = sig0{2}).
  - by wp; skip.
  wp; skip => /> &2 ge0_ti ubti tidef tirel rtrel rtlrel rngtkp rngtkpdv
                    fitkp sqtkp eqszpkrs eqszpkrsp eqsztkppk  _ ltdszpk pk _ /lezNgt geszpk_len.
  rewrite ?nth_rcons ?size_rcons eqsztkppk eqszpkrs eqszpkrsp /=.
  have ge0_tdvl : 0 <= tidx{2} %/ l' by rewrite divz_ge0; 1: smt(ge2_lp).
  rewrite ge0_tdvl (: size pkWOTSs'{2} + 1 <> 0) 2:/=; 1:smt(size_ge0).
  rewrite foldS 1:size_ge0 /=; split => [ltd_pk1 |].
  - rewrite ltz_divLR; 1: smt(ge2_lp).
    move: (ubti _); 1: smt().
    rewrite /nr_nodes_ht /nr_trees /nr_nodes /l'.
    by rewrite /= -?exprD_nneg ?addr_ge0 ?mulr_ge0 ?ge1_hp; smt(ge1_hp size_rcons).
  split => [/#|]; split.
  + move=> gt0_p1 ltd_p1.
    rewrite (StdOrder.IntOrder.ler_lt_trans tidx{2} _ _ _ (ubti _)) => [|/#].
    by rewrite leq_div; smt(ge2_lp).
  split => [i ge0_i ltszpk1_i |].
  - rewrite ?nth_rcons; case (i < size tkpidxs{2}) => [/# | ?].
    rewrite (: i = size tkpidxs{2}) 1:/# ge0_tdvl /=.
    rewrite ltz_divLR 2:divzK; 1,3: smt(ge2_lp).
    by rewrite /nr_nodes_ht /nr_nodes dvdz_mull dvdzz.
  split => [?|]; 1: case (0 < size pkWOTSs'{2}) => [//|?].
  - rewrite (tidef _); 1: smt(ge1_d).
    by rewrite -(: 0 = size pkWOTSs'{2}) 1:/# /= fold0.
  split=> [i ge1_i ltsz1_i /= | /#].
  by rewrite ?nth_rcons; case (i < size tkpidxs{2}) => /#.
wp; skip => /> &2.
split => [| pk r rs ts' tidx tkpi /lezNgt ged_szpk _ ge0_ti rtrel rtsrel rngtkpi fitkpi sqtkpi eqszpkrs eqszpkrsp eqszpktkpi led_szpk].
+ rewrite /nr_nodes_ht /nr_trees /nr_nodes /= -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
  by rewrite mulrDr /= mulrN1 addrAC -addrA subrr /= -/l fold0 /=; smt(ge1_d Index.valP).
have eqd_szpk : size pk = d by smt().
move: rtsrel; rewrite eqd_szpk (: 0 < d) 2:(: d <> 0) 3:/=; 1,2: smt(ge1_d).
move=> ->; do 2! congr.
case (d = 1) => [eq1d | neq1d].
+ by rewrite eq1d /= (fitkpi _) 1:/# pdiv_small 2://; smt(Index.valP).
suff /#: 0 <= (nth witness tkpi (d - 1)).`1 < 1.
move: (rngtkpi (d - 1) _); 1: smt(ge1_d).
move=> -[-> /=]; rewrite (: nr_nodes_ht (d - 1) 0 %/ l' = 1) 2://.
rewrite eq_sym -{1}(expr0 2) /nr_nodes_ht /nr_trees /nr_nodes /=.
rewrite -exprD_nneg 1:mulr_ge0; 1..3: smt(ge1_hp ge1_d).
by rewrite /l' expz_div 2://; smt(ge1_hp).
qed.

(*
  High-level security theorem
  Success probability (of given adversary) against EUF-NAGCMA of FL-SL-XMSS-MT-TW-ES-NPRF
  bounded by advantages/success probabilities (of reduction adversaries)
  against the M-EUF-GCMA property of WOTS-TW and the SM-DT-TCR-C properties of pkco and trh.
*)
local lemma EUFNAGCMA_FLSLXMSSMTTWESNPRF_MEUFGCMAWOTSTWES &m :
  hoare[A(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).O_THFC).choose :
          R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads = []
          ==>
          all (fun (ad : adrs) => get_typeidx ad <> chtype) R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads] =>
  hoare[A(R_SMDTTCRCPKCO_EUFNAGCMA(A, PKCOC_TCR.O_SMDTTCR_Default, PKCOC.O_THFC_Default).O_THFC).choose :
          R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads = []
          ==>
          all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads] =>
  hoare[A(R_SMDTTCRCTRH_EUFNAGCMA(A, TRHC_TCR.O_SMDTTCR_Default, TRHC.O_THFC_Default).O_THFC).choose :
          R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads = []
          ==>
          all (fun (ad : adrs) => get_typeidx ad <> trhtype) R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads] =>
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(A, O_THFC_Default).main() @ &m : res]
  <=
  Pr[M_EUF_GCMA_WOTSTWESNPRF(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A), O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
  +
  Pr[PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_EUFNAGCMA(A), PKCOC_TCR.O_SMDTTCR_Default, PKCOC.O_THFC_Default).main() @ &m : res]
  +
  Pr[TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_EUFNAGCMA(A), TRHC_TCR.O_SMDTTCR_Default, TRHC.O_THFC_Default).main() @ &m : res].
proof.
move=> allnchads allnpkcoads allntrhads.
have ->:
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(A, O_THFC_Default).main() @ &m : res]
  =
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF_V.main() @ &m : res].
+ byequiv (: ={glob A} ==> ={res}) => //.
  transitivity EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.main (={glob A} ==> ={res}) (={glob A} ==> ={res}) => [/# | // | |].
  - by apply Eqv_EUFNAGCMA_FLSLXMSSMTTWESNPRF_Orig_C.
  by apply Eqv_EUFNAGCMA_FLSLXMSSMTTWESNPRF_C_V.
rewrite -RField.addrA Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.valid_WOTSTWES] RealOrder.ler_add.
+ rewrite EqPr_MEUFGCMAWOTSTWESNPRF_Orig_V.
  byequiv=> //.
  proc.
  inline{2} 5; inline{2} 4.
  swap{1} 3.
  inline{1} 2; inline{2} 3; inline{2} 2; inline{2} 8.
  swap{2} 4 7.
  seq 5 10 : (   ={glob A, ps}
              /\ ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
              /\ O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
              /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
              /\ O_THFC_Default.tws{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2}
              /\ ml{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ml{2}
              /\ all (fun (ad : adrs) => get_typeidx ad <> chtype) FC.O_THFC_Default.tws{2}).
  - call (:   ={glob A, arg}
           /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
           /\ O_THFC_Default.tws{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2}
           /\ R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} = FC.O_THFC_Default.tws{2}
           /\ R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} = []
           ==>
              ={glob A, res}
           /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
           /\ O_THFC_Default.tws{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2}
           /\ R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} = FC.O_THFC_Default.tws{2}
           /\ all (fun (ad : adrs) => get_typeidx ad <> chtype) R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2}).
    * conseq (: ={glob A, arg} /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} /\ R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} = FC.O_THFC_Default.tws{2}
                ==>
                ={glob A, res} /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} /\ R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} = FC.O_THFC_Default.tws{2})
             _
             (: R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads = []
                ==>
                all (fun (ad : adrs) => get_typeidx ad <> chtype) R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads) => //.
      + conseq Eqv_Choose_V_Orig allnchads => /#.
      proc (O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} /\ R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads{2} = FC.O_THFC_Default.tws{2}) => //.
      proc; inline{2} 1.
      by wp; skip.
    by wp; rnd; skip.
  seq 7 7 : (   #pre
             /\ ad{1} = adz
             /\ ad{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2}
             /\ pkWOTStd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}
             /\ sigWOTStd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2}
             /\ leavestd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.leavestd{2}
             /\ rootstd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2}
             /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS),
                   admpksig \in O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                   <=>
                   (exists (i j u : int), 0 <= i < d /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     admpksig = (nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))))
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
                    (if i = 0
                     then nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ml{2} (j * l' + u)
                     else nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2} (i - 1)) (j * l' + u)),
                    nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} i) j) u,
                    nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2} i) j) u))
             /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSTWESNPRF.qs{2}
             /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS) => admpksig.`1) O_MEUFGCMA_WOTSTWESNPRF.qs{2})
             /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2} = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d).
  - while (   ={ps}
           /\ ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
           /\ O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
           /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
           /\ ad{1} = adz
           /\ ad{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2}
           /\ ml{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ml{2}
           /\ pkWOTStd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}
           /\ sigWOTStd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2}
           /\ leavestd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.leavestd{2}
           /\ rootstd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2}
           /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS),
                 admpksig \in O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                 <=>
                 (exists (i j u : int), 0 <= i < size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                   admpksig = (nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))))
           /\ (forall (i j u : int), 0 <= i < size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                 =
                 (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
                  (if i = 0
                   then nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ml{2} (j * l' + u)
                   else nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2} (i - 1)) (j * l' + u)),
                  nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} i) j) u,
                  nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2} i) j) u))
           /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
           /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSTWESNPRF.qs{2}
           /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS) => admpksig.`1) O_MEUFGCMA_WOTSTWESNPRF.qs{2})
           /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2} = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2})
           /\ size skWOTStd{1} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}
           /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.leavestd{2}
           /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2}
           /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2}
           /\ size skWOTStd{1} <= d).
    * wp => /=.
      while (   ={ps, pkWOTSnt, sigWOTSnt, leavesnt, rootsnt, rootsntp}
             /\ ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
             /\ O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
             /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
             /\ ad{1} = adz
             /\ ad{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2}
             /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS),
                   admpksig \in O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                   <=>
                   (exists (i j u : int), 0 <= i < size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     admpksig = (nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
                   \/
                   (exists (j u : int), 0 <= j < size pkWOTSnt{2} /\ 0 <= u < l' /\
                     admpksig = (nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                                     (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) * l' + j * l' + u))))
             /\ (forall (i j u : int), 0 <= i < size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
                    (if i = 0
                     then nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ml{2} (j * l' + u)
                     else nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2} (i - 1)) (j * l' + u)),
                    nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} i) j) u,
                    nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2} i) j) u))
             /\ (forall (j u : int), 0 <= j < size pkWOTSnt{2} => 0 <= u < l' =>
                   nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                       (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx adz (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) j) chtype) u,
                    nth witness rootsntp{2} (j * l' + u),
                    nth witness (nth witness pkWOTSnt{2} j) u,
                    nth witness (nth witness sigWOTSnt{2} j) u))
             /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
             /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSTWESNPRF.qs{2}
             /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS) => admpksig.`1) O_MEUFGCMA_WOTSTWESNPRF.qs{2})
             /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                =
                bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2})
                +
                size pkWOTSnt{2} * l'
             /\ size skWOTSnt{1} = size pkWOTSnt{2}
             /\ size pkWOTSnt{2} = size leavesnt{2}
             /\ size pkWOTSnt{2} = size sigWOTSnt{2}
             /\ size pkWOTSnt{2} = size rootsnt{2}
             /\ size skWOTStd{1} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}
             /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.leavestd{2}
             /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2}
             /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2}
             /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
             /\ size skWOTStd{1} < d).
      + wp => /=.
        while{2} (   R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2} = adz
                  /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
                  /\ (forall (i j : int), 0 <= i < size nodes{2} => 0 <= j < nr_nodes (i + 1) =>
                        nth witness (nth witness nodes{2} i) j
                        =
                        let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp{2}) in
                          val_bt_trh_gen FC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2} (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) (size pkWOTSnt{2})) trhtype)
                                         (list2tree leaveslpp) (i + 1) j)
                  /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} < d
                  /\ size pkWOTSnt{2} < nr_trees (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2})
                  /\ size leaveslp{2} = l'
                  /\ size nodes{2} <= h')
                 (h' - size nodes{2}).
        - move => _ z.
          wp => /=.
          while (   R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad = adz
                 /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws
                 /\ nodespl = last leaveslp nodes
                 /\ (forall (i j : int), 0 <= i < size nodes => 0 <= j < nr_nodes (i + 1) =>
                        nth witness (nth witness nodes i) j
                        =
                        let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp) in
                          val_bt_trh_gen FC.O_THFC_Default.pp (set_typeidx (set_ltidx R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd) (size pkWOTSnt)) trhtype)
                                         (list2tree leaveslpp) (i + 1) j)
                 /\ (forall (j : int), 0 <= j < size nodescl =>
                        nth witness nodescl j
                        =
                        let leaveslpp = take (2 ^ (size nodes + 1)) (drop (j * (2 ^ (size nodes + 1))) leaveslp) in
                          val_bt_trh_gen FC.O_THFC_Default.pp (set_typeidx (set_ltidx R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd) (size pkWOTSnt)) trhtype)
                                         (list2tree leaveslpp) (size nodes + 1) j)
                 /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd < d
                 /\ size pkWOTSnt < nr_trees (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd)
                 /\ size leaveslp = l'
                 /\ size nodescl <= nr_nodes (size nodes + 1)
                 /\ size nodes < h')
                (nr_nodes (size nodes + 1) - size nodescl).
          * move=> z'.
            inline 3.
            wp; skip => /> &2 allnchtws nthnds ntndscl ltd_szpktd ltnt_szpknt eqt_szlfslp _ lthp_sznds ltnn_szndscl.
            rewrite size_rcons -cats1 all_cat allnchtws /= -!andbA andbA; split => [| /#].
            rewrite gettype_setalltrh 1:valx_adz; 1..4: smt(size_ge0).
            split => [| j ge0_j ltszndscl1_j]; 1: smt(dist_adrstypes).
            rewrite nth_rcons; case (j < size nodescl{2}) => [/# | neqszj].
            have eqszj : j = size nodescl{2} by smt(size_rcons).
            rewrite eqszj /= size_cat ?valP /= (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})).
            + by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
            rewrite take_take_drop_cat 1,2:expr_ge0 //=.
            rewrite drop_drop 1:expr_ge0 //= 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //=.
            have ge1_2aszn2szncl : 1 <= 2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1.
            + rewrite 2!IntOrder.ler_subr_addr /=.
              rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodes (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
            rewrite -nth_last (list2treeS (size nodes{2})) 1:size_ge0.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqt_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
              pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
              pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:maxrr.
              by rewrite ltr_pmull 1:expr_gt0 // /#.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:addr_ge0 1:expr_ge0 // 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqt_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
              pose sb := ((_ - _ - _) * _)%Int.
              move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
              - by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
              rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
              - rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodes (size nodes{2} + 1) - 1))) 1:/#.
                by rewrite /nr_nodes mulzDr -{1}(expr1 2) -exprD_nneg // /#.
              rewrite (: szn2 < (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.
              by rewrite ltr_pmull 1:expr_gt0.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; congr => [/# |].
            case (size nodes{2} = 0) => [eq0_sz | neq0_sz].
            + rewrite eq0_sz ?expr0 /= (nth_out leaveslp{2}); 1: smt(size_ge0).
              rewrite {4 7}(: 1 = 0 + 1) 1:// ?(take_nth witness) 1,2:size_drop //; 1..4:smt(size_ge0).
              by rewrite ?take0 /= ?list2tree1 /= ?nth_drop //; smt(size_ge0).
            rewrite (nth_change_dfl witness leaveslp{2}); 1: smt(size_ge0).
            rewrite ?nthnds /=; 1,3: smt(size_ge0).
            + split => [| _ @/nr_nodes]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodes (size nodes{2}))) /nr_nodes //.
              rewrite (: 2 ^ (h' - size nodes{2}) = 2 * 2 ^ (h' - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            + split => [| _ @/nr_nodes]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodes (size nodes{2}))) /nr_nodes //.
              rewrite (: 2 ^ (h' - size nodes{2}) = 2 * 2 ^ (h' - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; do 3! congr; 1: smt().
            by do 3! congr; ring.
          by wp; skip => /> &2; smt(expr_ge0 nth_rcons size_rcons).
        wp => /=.
        while (   ={ps, pkWOTSlp, sigWOTSlp, leaveslp, rootsntp}
               /\ ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
               /\ O_THFC_Default.pp{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
               /\ O_THFC_Default.pp{1} = FC.O_THFC_Default.pp{2}
               /\ ad{1} = adz
               /\ ad{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2}
               /\ (forall (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS),
                     admpksig \in O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                     <=>
                     (exists (i j u : int), 0 <= i < size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                       admpksig = (nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
                     \/
                     (exists (j u : int), 0 <= j < size pkWOTSnt{2} /\ 0 <= u < l' /\
                       admpksig = (nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                                       (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) * l' + j * l' + u)))
                     \/
                     (exists (j u : int), 0 <= u < size pkWOTSlp{2} /\
                       admpksig = (nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                                       (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) * l' + size pkWOTSnt{2} * l' + u))))
               /\ (forall (i j u : int), 0 <= i < size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u,
                      (if i = 0
                       then nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ml{2} (j * l' + u)
                       else nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2} (i - 1)) (j * l' + u)),
                      nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} i) j) u,
                      nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2} i) j) u))
               /\ (forall (j u : int), 0 <= j < size pkWOTSnt{2} => 0 <= u < l' =>
                     nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                         (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx adz (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) j) chtype) u,
                      nth witness rootsntp{2} (j * l' + u),
                      nth witness (nth witness pkWOTSnt{2} j) u,
                      nth witness (nth witness sigWOTSnt{2} j) u))
               /\ (forall (u : int), 0 <= u < size pkWOTSlp{2} =>
                     nth witness O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                         (bigi predT (fun (m : int) => nr_trees m) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) * l' + size pkWOTSnt{2} * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx adz (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) (size pkWOTSnt{2})) chtype) u,
                      nth witness rootsntp{2} (size pkWOTSnt{2} * l' + u),
                      nth witness pkWOTSlp{2} u,
                      nth witness sigWOTSlp{2} u))
               /\ all (fun (ad0 : adrs) => get_typeidx ad0 <> chtype) FC.O_THFC_Default.tws{2}
               /\ all (fun (admpksig : _ * _ * _ * _) => get_typeidx admpksig.`1 = chtype) O_MEUFGCMA_WOTSTWESNPRF.qs{2}
               /\ uniq_wgpidxs (map (fun (admpksig : adrs * msgWOTS * pkWOTS * sigWOTS) => admpksig.`1) O_MEUFGCMA_WOTSTWESNPRF.qs{2})
               /\ size O_MEUFGCMA_WOTSTWESNPRF.qs{2}
                  =
                  bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2})
                  +
                  size pkWOTSnt{2} * l'
                  +
                  size pkWOTSlp{2}
               /\ size skWOTSlp{1} = size pkWOTSlp{2}
               /\ size pkWOTSlp{2} = size leaveslp{2}
               /\ size pkWOTSlp{2} = size sigWOTSlp{2}
               /\ size skWOTSnt{1} = size pkWOTSnt{2}
               /\ size pkWOTSnt{2} = size leavesnt{2}
               /\ size pkWOTSnt{2} = size sigWOTSnt{2}
               /\ size pkWOTSnt{2} = size rootsnt{2}
               /\ size skWOTStd{1} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}
               /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.leavestd{2}
               /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.sigWOTStd{2}
               /\ size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2}
               /\ size skWOTSlp{1} <= l'
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTStd{1} < d).
        + inline{2} 3; inline{2} 2.
          wp => /=.
          while (   ={em}
                 /\ ps{1} = O_MEUFGCMA_WOTSTWESNPRF.ps{2}
                 /\ ad{1} = adz
                 /\ ad{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2}
                 /\ val wad{2}
                    =
                    set_kpidx (set_typeidx (set_ltidx R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2} (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) (size pkWOTSnt{2}))
                                           chtype) (size pkWOTSlp{2})
                 /\ sigWOTS{1} = sigWOTS1{2}
                 /\ pkWOTS{1} = pkWOTS2{2}
                 /\ size skWOTS{1} = size pkWOTS2{2}
                 /\ size pkWOTS2{2} = size sigWOTS1{2}
                 /\ size skWOTStd{1} = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}
                 /\ size skWOTSnt{1} = size pkWOTSnt{2}
                 /\ size skWOTSlp{1} = size pkWOTSlp{2}
                 /\ size skWOTS{1} <= len).
          - by wp; rnd; wp; skip => />; smt(size_rcons).
          wp; skip => /> &1 &2 qsdef qsnth qsnth1 qsnth2 allnchtws allchqs uqswgpqs szqs eqszpksklp eqszpklfslp eqszpksiglp
                               eqszpksknt eqszpklfsnt eqszpksignt eqszpkrtsnt eqszpksktd eqszpklfstd eqszpksigtd eqszpkrtstd
                               _ ltnt_szsknt ltd_szsktd ltlp_szsklp ltlp_szpklp.
          split => [| skw pkw sigw /lezNgt gelen_szskw /lezNgt gelen_szpkw eq_em eqadw_ad eqszskpkw eqszpksigw lelen_szskw].
          - by rewrite eqszpksknt eqszpksklp /= insubdK 1:validxadrs_validwadrs_setallboch 1:valx_adz 4:/=; smt(size_ge0 ge2_len).
          rewrite !andbA -6!andbA; split; 2: by rewrite ?size_rcons /#.
          rewrite -!andbA; split.
          - rewrite size_flatten -map_comp sumzE /= big_map /(\o) /predT /= -/predT.
            rewrite (eq_bigr _ _ (fun (_ : DigestBlock.sT) => 8 * n)) 1:/=.
            * by move=> ? _; rewrite valP.
            by rewrite insubdK 1:/# big_constz count_predT /#.
          rewrite /nr_nodes_ht /nr_nodes /= -/l' -mulr_suml in szqs.
          split => [admpksig |]; 1: rewrite mem_rcons size_rcons /=; 1: split.
          - elim => [-> | /qsdef].
            * right; right; exists (size pkWOTSlp{2}).
              by split; [smt(size_ge0) | rewrite nth_rcons /#].
            elim => [[i j u [ir] [jr] [ur adval]]|].
            * by left; exists i j u; rewrite ir jr ur /= nth_rcons szqs ltbignrt_i.
            elim => [[j u [jr] [ur adval]]|].
            * right; left; exists j u; rewrite jr ur /= nth_rcons szqs.
              pose igl := _ + j * l' + _; pose igr := _ + size pkWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2://.
              rewrite -2!addrA ler_lt_add 1://.
              suff /#: j * l' + u < size pkWOTSnt{2} * l' /\ 0 <= size pkWOTSlp{2}.
              by rewrite size_ge0 /= (: size pkWOTSnt{2} = size pkWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
            elim => [u [ur adval]].
            * right; right; exists u; split; 1: smt(size_ge0).
              by rewrite nth_rcons szqs /#.
          - rewrite eqadw_ad; case; 2: case.
            * elim=> i j u [rng_i [rng_j [rng_u]]].
              by rewrite nth_rcons szqs ltbignrt_i 1..5:// /= qsdef /#.
            * elim=> j u [rng_j [rng_u]].
              rewrite nth_rcons szqs.
              pose igl := _ + j * l' + _; pose igr := _ + size pkWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2:/= 2:qsnth1 //.
              + rewrite -2!addrA ler_lt_add 1://.
                suff /#: j * l' + u < size pkWOTSnt{2} * l' /\ 0 <= size pkWOTSlp{2}.
                by rewrite size_ge0 /= (: size pkWOTSnt{2} = size pkWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
              by rewrite qsdef /#.
            by elim=> u [rng_u]; rewrite nth_rcons szqs /#.
          split => [* | ]; 1: by rewrite nth_rcons szqs ltbignrt_i // /= qsnth.
          split => [j u * | ]; 1: rewrite nth_rcons szqs.
          - pose igl := _ + j * l' + _; pose igr := _ + size pkWOTSnt{2} * l' + _.
            rewrite (: igl < igr) /igl /igr 2:/= 2:qsnth1 //.
            rewrite -2!addrA ler_lt_add 1://.
            suff /#: j * l' + u < size pkWOTSnt{2} * l' /\ 0 <= size pkWOTSlp{2}.
            by rewrite size_ge0 /= (: size pkWOTSnt{2} = size pkWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
          split => [u | ]; 1: rewrite size_rcons ?nth_rcons szqs => ge0_u ltsz1_u.
          - rewrite -eqszpksiglp; case (u < size pkWOTSlp{2}) => [ltszpk_u | nltszpk_u].
            + by rewrite qsnth2 // /#.
            by rewrite (: u = size pkWOTSlp{2}) 1:/# /= eqadw_ad.
          rewrite andbA; split; 1: rewrite -2!cats1 2!all_cat allnchtws allchqs /=.
          - rewrite eqadw_ad gettype_setkptypeltchpkco 1:valx_adz 3,4://; 1,2:smt(size_ge0).
            by rewrite gettype_setkptypeltchpkco 1:valx_adz 3,4://; smt(size_ge0 dist_adrstypes).
          rewrite /uniq_wgpidxs -map_comp map_rcons rcons_uniq /(\o) /=.
          split; 2: by move: uqswgpqs => @/uniq_wgpidxs; rewrite map_comp.
          rewrite mapP negb_exists => admpksig /=.
          rewrite negb_and -implybE qsdef eqadw_ad.
          rewrite /get_wgpidxs; case; 2: case.
          - elim=> i j u [rng_i [rng_j [rng_u]]].
            rewrite qsnth 1..3:// => -> /=.
            rewrite (neq_from_nth witness _ _ 3) 2?nth_drop 1..4:// 2:// /=.
            by rewrite neqlidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
          - elim=> j u [rng_j [rng_u]].
            rewrite qsnth1 1..2:// => -> /=.
            rewrite (neq_from_nth witness _ _ 2) 2?nth_drop 1..4:// 2:// /=.
            by rewrite neqtidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
          elim=> u [rng_u].
          rewrite qsnth2 1:// => -> /=.
          rewrite (neq_from_nth witness _ _ 0) 2?nth_drop 1..4:// 2:// /=.
          by rewrite neqkpidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
        wp; skip => /> &1 &2 qsdef qsnth qsnth1 allnchtws allchqs uqswgpqs szqs
                             eqszpksknt eqszpklfsnt eqszpksignt eqszpkrtsnt eqszpksktd
                             eqszpklfstd eqszpksigtd eqszpkrtstd _ ltd_szsktd ltnt_szsknt ltnt_szpknt.
        split=> [| skwlp qs tws lfslp pkwlp sigwlp /lezNgt gelp_szskwlp /lezNgt gelp_szpkwlp]; 1: smt(ge2_lp).
        move=> qspdef qspnth qspnth2 qspnth3 allnchtwsp allchqsp uqwgpqsp szqsp eqszpkskwlp eqszpkwlfslp eqszpksigwlp lelp_szskwlp.
        split=> [| tws' nds]; 1: smt(ge1_hp).
        split=> [/# | /lezNgt gehp_sznds allnchtwspp ndsnth ltd_szpkwtd eqlp_szlfslp lehp_sznds].
        rewrite !andbA -7!andbA; split; 2: by rewrite ?size_rcons /#.
        rewrite -!andbA; split.
        + congr; rewrite ndsnth 2:expr_gt0 2,3:// 2:/=; 1: smt(ge1_hp).
          by rewrite drop0 -/l' -eqlp_szlfslp take_size /#.
        by split; smt(size_ge0 nth_rcons size_rcons).
      wp; skip => /> &1 &2 qsdef qsnth allnchtws allchqs uqswgpqs szqs
                           eqszpksktd eqszpklfstd eqszpksigtd eqszpkrtstd
                           _ ltd_szskwtd ltd_szpkwtd.
      split=> [| skwnt qs tws lfsnt pkwnt rsnt sigwnt /lezNgt gent_szskwnt /lezNgt gent_szpkwnt]; 1: smt(expr_gt0).
      move=> qspdef qspnth qspnth1 allnchtwsp allchqsp uqwgpqsp szqsp eqszpkskwnt eqszpkwlfsnt eqszpksigwnt eqszpkwrsnt lent_szskwnt.
      rewrite !andbA -6!andbA; split; 2: by rewrite ?size_rcons /#.
      split; last first.
      + by rewrite szqsp size_rcons big_int_recr 1:size_ge0 //= /#.
      split => [admpksig | i j u]; last first.
      + rewrite size_rcons ?nth_rcons -eqszpksigtd -eqszpkrtstd => *.
        case (i < size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) => [/#| ?].
        rewrite (: i = size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}) 1:/#.
        rewrite qspnth1 1:/# 1:// -nth_last -eqszpkrtstd .
        case (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} = 0) => szpkwtd /=; 2: smt(nth_change_dfl).
        by rewrite szpkwtd /= (nth_out _ _ (-1)) 1:/#.
      by split => [/qspdef | i j u]; smt(size_ge0 nth_rcons size_rcons).
    wp; skip => /> &2 allnchtws.
    by split; 1: rewrite big_geq 1://; smt(ge1_d).
  swap{1} [1..2] 2.
  sp 0 1.
  seq 2 2 : (#pre /\ ={sigl}); 1: by conseq />; sim.
  inline{2} 23; inline{2} 22; inline{2} 21; inline{2} 20; inline{2} 17.
  wp 15 19 => /=.
  conseq (: is_fresh{1} /\ EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.valid_WOTSTWES{1} =>
              is_valid{2} /\ m'{2} <> m{2} /\ 0 <= i{2} && i{2} < size O_MEUFGCMA_WOTSTWESNPRF.qs{2}).
  - move=> /> &2; rewrite (: d <> 0) 2:/=; 1: smt(ge1_d).
    move=> allnchtws qsmem qsnth allchqs uqwgpqs szqs vw isf rs rs' i isv m m' + eqnthrs isfT vwT.
    rewrite isfT vwT size_ge0 szqs /= => [#] -> -> -> -> /=.
    rewrite lez_eqVlt /= /disj_wgpidxs -map_comp /get_wgpidxs /(\o) /disj_lists hasPn => ls.
    rewrite 2!mapP => -[admpksig] [admpksigin /= lsval].
    rewrite negb_exists => ad /=; rewrite negb_and -implybE => adin.
    rewrite lsval /= &(neq_from_nth witness _ _ 1).
    by rewrite ?nth_drop //=; smt(allP).
  seq 15 18 : (is_fresh{1} /\ EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.valid_WOTSTWES{1} =>
                m'{2} <> m{2} /\ 0 <= i{2} < size O_MEUFGCMA_WOTSTWESNPRF.qs{2} /\
                  pkWOTS{2}
                  =
                  DBLL.insubd (mkseq (fun (i : int) =>
                      cf ps{2} (set_chidx ad{2} i) (BaseW.val (encode_msgWOTS m'{2}).[i])
                               (w - 1 - BaseW.val (encode_msgWOTS m'{2}).[i]) (val (nth witness (val sig'{2}) i))) len)).
  - wp => /=.
    while (   ={pkWOTSs, rootss, pkWOTSs', rootss', tkpidxs, tidx, kpidx, root'}
           /\ ps{1} = ps0{2}
           /\ ad{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2}
           /\ pkWOTStd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2}
           /\ rootstd{1} = R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2}
           /\ sig'{1} = sig'0{2}
           /\ root'{2} = nth witness (m'0{2} :: rootss'{2}) (size rootss'{2})
           /\ 0 <= tidx{2}
           /\ (size pkWOTSs'{2} < d =>
                 tidx{2} < nr_trees (size pkWOTSs'{2}) * l')
           /\ (size pkWOTSs'{2} < d =>
                  tidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (size pkWOTSs'{2})).`1 /\
                  kpidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (size pkWOTSs'{2})).`2)
           /\ (forall (i : int), 0 <= i < size pkWOTSs{2} =>
                 nth witness pkWOTSs{2} i
                 =
                 nth witness (nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd{2} i) (nth witness tkpidxs{2} i).`1) (nth witness tkpidxs{2} i).`2)
           /\ (forall (i : int), 0 <= i < size rootss{2} =>
                 nth witness rootss{2} i
                 =
                 nth witness (nth witness R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.rootstd{2} i) (nth witness tkpidxs{2} i).`1)
           /\ (forall (i : int), 0 <= i < size pkWOTSs'{2} =>
                 nth witness pkWOTSs'{2} i
                 =
                 DBLL.insubd (mkseq (fun (j : int) =>
                      cf ps0{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.ad{2} i (nth witness tkpidxs{2} i).`1)
                                                                  chtype) (nth witness tkpidxs{2} i).`2) j)
                               (BaseW.val (encode_msgWOTS (nth witness (m'0{2} :: rootss'{2}) i)).[j])
                               (w - 1 - BaseW.val (encode_msgWOTS (nth witness (m'0{2} :: rootss'{2}) i)).[j])
                               (val (nth witness (val (nth witness (val sig'0{2}) i).`1) j))) len))
           /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
                 (nth witness tkpidxs{2} i).`1 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (i + 1)).`1 /\
                 (nth witness tkpidxs{2} i).`2 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (i + 1)).`2)
           /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
                 0 <= (nth witness tkpidxs{2} i).`1 < nr_trees i /\
                 0 <= (nth witness tkpidxs{2} i).`2 < l')
           /\ size pkWOTSs'{2} = size pkWOTSs{2}
           /\ size pkWOTSs'{2} = size rootss{2}
           /\ size pkWOTSs'{2} = size rootss'{2}
           /\ size pkWOTSs'{2} = size tkpidxs{2}
           /\ size pkWOTSs'{2} <= d).
    * inline{1} 3; inline{2} 3.
      wp => /=.
      while (   ={ad0}
             /\ ps0{1} = ps2{2}
             /\ pkWOTS0{1} = pkWOTS2{2}
             /\ sig0{1} = sig1{2}
             /\ em0{1} = em{2}
             /\ pkWOTS2{2}
                =
                mkseq (fun (i : int) =>
                    cf ps2{2} (set_chidx ad0{2} i) (BaseW.val em{2}.[i])
                       (w - 1 - BaseW.val em{2}.[i]) (val (nth witness (val sig1{2}) i))) (size pkWOTS2{2})
             /\ size pkWOTS2{2} <= len).
      + wp; skip => /> &2 pkwdef _ ltlen_szpkw.
        by rewrite size_rcons mkseqS 1:size_ge0 /= {1}pkwdef; smt(size_rcons).
      wp; skip => /> &2 ge0_ti ltnt_ti tkpicdef pkwrel rsrel pkwpdef tkpidef tkpirng eqszpkwp eqszpkwprs eqszpkwprsp eqszpkwptkpi _ ltd_szpkwp.
      split => [| pkwc _ /lezNgt ltlen_szpkwc pkwcdef lelen_szpkwc]; 1: by rewrite mkseq0 /=; smt(ge2_len).
      rewrite ?nth_rcons ?size_rcons !andbA -4!andbA; split => [|/#].
      rewrite -!andbA; split => [/= |]; 1: by smt(size_ge0).
      split; 1: by rewrite divz_ge0; smt(ge2_lp).
      split => [ltd_szpk1 |].
      + rewrite ltz_divLR; 1: smt(ge2_lp).
        move: (ltnt_ti _); 1: smt().
        rewrite /nr_nodes_ht /nr_trees /nr_nodes /l'.
        by rewrite /= -?exprD_nneg ?addr_ge0 ?mulr_ge0 ?ge1_hp; smt(ge1_hp).
      split => [ltd_szpk1 |]; 1: by rewrite foldS 1:// /= /#.
      split => [j ge0_j ltsz1_j |].
      + rewrite ?nth_rcons -eqszpkwp -eqszpkwptkpi.
        by case (j < size pkWOTSs'{2}) => /#.
      split => [j ge0_j ltsz1_j |].
      + rewrite ?nth_rcons -eqszpkwprs -eqszpkwptkpi.
        by case (j < size pkWOTSs'{2}) => /#.
      split => [j ge0_j ltsz1_j |].
      + rewrite ?nth_rcons -eqszpkwptkpi.
        case (j < size pkWOTSs'{2}) => [ltszpkj /= | nltszpkj].
        - rewrite pkwpdef 1://; do 2! congr; rewrite fun_ext => k.
          by case (j = 0) => [// | /#].
        rewrite (: j = size pkWOTSs'{2}) 1:/# pkwcdef -eqszpkwprsp /=.
        do 2! congr => [| /#].
        rewrite fun_ext => k.
        by case (size pkWOTSs'{2} = 0) => [// | /#].
      split => j ge0_j ltsz1_j; rewrite ?nth_rcons -eqszpkwptkpi.
      + case (j < size pkWOTSs'{2}) => [/# | nltszpkj].
        by rewrite (: j = size pkWOTSs'{2}) 1:/# /= foldS 1:// /= /#.
      case (j < size pkWOTSs'{2}) => [/# | nltszpkj].
      rewrite (: j = size pkWOTSs'{2}) 1:/# /= divz_ge0 2:modz_ge0 3:ltz_pmod 4:/=; 1..3: smt(ge2_lp).
      by rewrite ge0_ti /= ltz_divLR; smt(ge2_lp).
    wp => /=.
    call (: true).
    wp; skip => /> &2 allnchtws qsdef qsnth allchqs uqwgpqs szqs msigidx.
    split => [| pkw pkw' rs rs' ti tkpi /lezNgt ged_szpkw _ ge0ti].
    * rewrite /nr_trees /= andbA; split; 2: smt(ge1_d fold0).
      split => [| gt0_d]; 1: smt(Index.valP).
      move: (Index.valP (msigidx.`3)) => [_ @/l @/h @/l'].
      by rewrite -exprD_nneg ?mulr_ge0; smt(ge1_hp).
    move=> pkwrel rsrel pkwpdef tkpidef tkpirng eqszpkwp eqszpkwrs eqszpkwrsp eqszpkwtkpi led_szpkw neqm i ge0_i ltd_i eqipkw neqimrs.
    pose zs := zip _ _; pose cidx := find _ _.
    have hascidx :
      has (fun (x : ((pkWOTS * pkWOTS) * msgFLSLXMSSMTTW) * msgFLSLXMSSMTTW) =>
                    x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2) zs.
    * rewrite -(has_nthP _ _ (((witness, witness), witness), witness)) /=.
      exists i; rewrite -(: d = size zs) 1:/zs 1:?size_zip /= 1:/#.
      split => [/#|].
      rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
      by rewrite (: i < size pkw') 1:/# //.
    have ge0_cidx : 0 <= cidx by rewrite find_ge0.
    have ltd_cidx : cidx < d.
    * by rewrite /cidx (: d = size zs) 1:/zs 1:?size_zip /= 1:/# -has_find.
    move /(nth_find (((witness, witness), witness), witness)): (hascidx) => /= @-/cidx.
    rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
    rewrite (: cidx < size pkw') 1:/# /= => -[eqpk neqrs].
    rewrite qsnth 1:// 1,2:tkpirng 1,2:/# /=.
    split; 1: rewrite ?tkpidef 1,2:/# 1:// foldS 1:// /= -divz_eq.
    * case (cidx = 0) => [-> /= | neq0_cidx]; 1: by rewrite fold0.
      move: neqrs; rewrite neq0_cidx /=.
      by rewrite -(tkpidef (cidx - 1) _) 1:/# 1:// /= rsrel 1:/#.
    split; last by rewrite -pkwrel 1:/# -eqpk pkwpdef 1:/#.
    rewrite szqs; split => [| _].
    * by rewrite ?addr_ge0 ?mulr_ge0 ?sumr_ge0 => [j | | | |]; rewrite ?expr_ge0 // /#.
    rewrite mulr_suml /nr_nodes_ht /nr_nodes /= -/l'.
    rewrite (big_cat_int cidx 0 d) 1:// 1:/#.
    rewrite -addrA ltr_add2l (IntOrder.ltr_le_trans (nr_trees cidx * l')).
    * rewrite (: nr_trees cidx * l' = (nr_trees cidx - 1) * l' + l') 1:/#.
      by rewrite ler_lt_add 1:ler_wpmul2r; smt(ge2_lp).
    rewrite (big_cat_int (cidx + 1)) 1,2:/# big_int1 /= ler_addl sumr_ge0 => j _ /=.
    by rewrite mulr_ge0 expr_ge0.
  inline{2} 1; inline{2} 7.
  wp.
  while{2} (pkWOTS3{2}
            =
            mkseq (fun (i : int) =>
                      cf ps3{2} (set_chidx ad1{2} i) (BaseW.val em{2}.[i])
                                (w - 1 - BaseW.val em{2}.[i]) (val (nth witness (val sig2{2}) i))) (size pkWOTS3{2})
            /\ size pkWOTS3{2} <= len)
           (len - size pkWOTS3{2}).
  - move=> ? z.
    by wp; skip => />; smt(size_rcons size_ge0 mkseqS).
  wp; skip => /> &1 &2 opre.
  split => [| pkw]; 1: by rewrite mkseq0; smt(ge2_len).
  split => [/#| /lezNgt gelen_szpkw + lelen_szpkw isf vwT].
  by move: (opre _); [rewrite isf vwT | smt() ].
rewrite Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.valid_TCRPKCO] RealOrder.ler_add.
+ byequiv=> //.
  proc.
  inline{2} 5; inline{2} 4.
  swap{1} 1 3.
  inline{1} 2; inline{2} 3; inline{2} 2; inline{2} 8.
  swap{2} 7 4.
  seq 5 10 : (   ={glob A}
              /\ ps{1} = pp{2}
              /\ ps{1} = O_THFC_Default.pp{1}
              /\ pp{2} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
              /\ pp{2} = PKCOC.O_THFC_Default.pp{2}
              /\ O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2}
              /\ ml{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ml{2}
              /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}).
  - call (:   ={glob A, arg}
           /\ O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2}
           /\ O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2}
           /\ R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}
           /\ R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} = []
           ==>
              ={glob A, res}
           /\ O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2}
           /\ O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2}
           /\ R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}
           /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}).
    * conseq (: ={glob A, arg} /\ O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} /\ R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}
                ==>
                ={glob A, res} /\ O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} /\ R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2})
             _
             (: R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads = []
                ==>
                all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads) => //.
      proc (O_THFC_Default.pp{1} = PKCOC.O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} /\ R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads{2} = PKCOC.O_THFC_Default.tws{2}) => //.
      proc; inline{2} 1.
      by wp; skip.
    by wp; rnd; skip.
  seq 7 8 : (   #pre
             /\ ad{1} = adz
             /\ ad{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ad{2}
             /\ skWOTStd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}
             /\ pkWOTStd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}
             /\ sigWOTStd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.sigWOTStd{2}
             /\ leavestd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2}
             /\ rootstd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.rootstd{2}
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2} i) j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
             /\ (forall (adx : adrs * dgst),
                   adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                   <=>
                   (exists (i j u : int), 0 <= i < d /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
             /\ (forall (i j u : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u,
                    flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
             /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
             /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
             /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2} = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d).
  - while (   ps{1} = pp{2}
           /\ ps{1} = O_THFC_Default.pp{1}
           /\ ps{1} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
           /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
           /\ ad{1} = adz
           /\ ad{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ad{2}
           /\ ml{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ml{2}
           /\ skWOTStd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}
           /\ pkWOTStd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}
           /\ sigWOTStd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.sigWOTStd{2}
           /\ leavestd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2}
           /\ rootstd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.rootstd{2}
           /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2} i) j) u
                 =
                 pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u)
                      (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
           /\ (forall (adx : adrs * dgst),
                 adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                   adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)))
           /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                 nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                 =
                 (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u,
                  flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
           /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
           /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
           /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
           /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2} = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2})
           /\ size skWOTStd{1} = size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}
           /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}
           /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2}
           /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.sigWOTStd{2}
           /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.rootstd{2}
           /\ size skWOTStd{1} <= d).
    * wp => /=.
      while (   ={skWOTSnt, pkWOTSnt, sigWOTSnt, leavesnt, rootsnt, rootsntp}
             /\ ps{1} = pp{2}
             /\ ps{1} = O_THFC_Default.pp{1}
             /\ ps{1} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
             /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
             /\ ad{1} = adz
             /\ ad{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ad{2}
             /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2} i) j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
             /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                   nth witness (nth witness leavesnt{2} j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
             /\ (forall (adx : adrs * dgst),
                   adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                   <=>
                   (exists (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                     adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))
                   \/
                   (exists (j u : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\
                     adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) * l' + j * l' + u)))
             /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u,
                    flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
             /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                   nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) * l' + j * l' + u)
                   =
                   (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) j) pkcotype) u,
                    flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
             /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
             /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
             /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
             /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                =
                bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2})
                +
                size skWOTSnt{2} * l'
             /\ size skWOTSnt{1} = size skWOTSnt{2}
             /\ size skWOTSnt{2} = size pkWOTSnt{2}
             /\ size skWOTSnt{2} = size leavesnt{2}
             /\ size skWOTSnt{2} = size sigWOTSnt{2}
             /\ size skWOTSnt{2} = size rootsnt{2}
             /\ size skWOTStd{1} = size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}
             /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}
             /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2}
             /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.sigWOTStd{2}
             /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.rootstd{2}
             /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
             /\ size skWOTStd{1} < d).
      + wp => /=.
        while{2} (   R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} = adz
                  /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
                  /\ (forall (i j : int), 0 <= i < size nodes{2} => 0 <= j < nr_nodes (i + 1) =>
                        nth witness (nth witness nodes{2} i) j
                        =
                        let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp{2}) in
                          val_bt_trh_gen PKCOC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) trhtype)
                                         (list2tree leaveslpp) (i + 1) j)
                  /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} < d
                  /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2})
                  /\ size leaveslp{2} = l'
                  /\ size nodes{2} <= h')
                 (h' - size nodes{2}).
        - move => _ z.
          wp => /=.
          while (   R_SMDTTCRCPKCO_EUFNAGCMA.ad = adz
                 /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws
                 /\ nodespl = last leaveslp nodes
                 /\ (forall (i j : int), 0 <= i < size nodes => 0 <= j < nr_nodes (i + 1) =>
                        nth witness (nth witness nodes i) j
                        =
                        let leaveslpp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaveslp) in
                          val_bt_trh_gen PKCOC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                         (list2tree leaveslpp) (i + 1) j)
                 /\ (forall (j : int), 0 <= j < size nodescl =>
                        nth witness nodescl j
                        =
                        let leaveslpp = take (2 ^ (size nodes + 1)) (drop (j * (2 ^ (size nodes + 1))) leaveslp) in
                          val_bt_trh_gen PKCOC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                         (list2tree leaveslpp) (size nodes + 1) j)
                 /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd < d
                 /\ size skWOTSnt < nr_trees (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd)
                 /\ size leaveslp = l'
                 /\ size nodescl <= nr_nodes (size nodes + 1)
                 /\ size nodes < h')
                (nr_nodes (size nodes + 1) - size nodescl).
          * move=> z'.
            inline 3.
            wp; skip => /> &2 allnpkcotws nthnds ntndscl ltd_szsktd ltnt_szsknt eqlp_szlfslp _ lthp_sznds ltnn_szndscl.
            rewrite size_rcons -cats1 all_cat allnpkcotws /= -!andbA andbA; split => [| /#].
            rewrite gettype_setalltrh 1:valx_adz; 1..4: smt(size_ge0).
            split => [| j ge0_j ltszndscl1_j]; 1: smt(dist_adrstypes).
            rewrite nth_rcons; case (j < size nodescl{2}) => [/# | neqszj].
            have eqszj : j = size nodescl{2} by smt(size_rcons).
            rewrite eqszj /= size_cat ?valP /= (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})).
            + by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
            rewrite take_take_drop_cat 1,2:expr_ge0 //=.
            rewrite drop_drop 1:expr_ge0 //= 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //=.
            have ge1_2aszn2szncl : 1 <= 2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1.
            + rewrite 2!IntOrder.ler_subr_addr /=.
              rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodes (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
            rewrite -nth_last (list2treeS (size nodes{2})) 1:size_ge0.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
              pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
              pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:maxrr.
              by rewrite ltr_pmull 1:expr_gt0 // /#.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:addr_ge0 1:expr_ge0 // 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}).
              rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
              pose sb := ((_ - _ - _) * _)%Int.
              move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
              - by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
              rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
              - rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodes (size nodes{2} + 1) - 1))) 1:/#.
                by rewrite /nr_nodes mulzDr -{1}(expr1 2) -exprD_nneg // /#.
              rewrite (: szn2 < (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.
              by rewrite ltr_pmull 1:expr_gt0.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; congr => [/# |].
            case (size nodes{2} = 0) => [eq0_sz | neq0_sz].
            + rewrite eq0_sz ?expr0 /= (nth_out leaveslp{2}); 1: smt(size_ge0).
              rewrite {4 7}(: 1 = 0 + 1) 1:// ?(take_nth witness) 1,2:size_drop //; 1..4:smt(size_ge0).
              by rewrite ?take0 /= ?list2tree1 /= ?nth_drop //; smt(size_ge0).
            rewrite (nth_change_dfl witness leaveslp{2}); 1: smt(size_ge0).
            rewrite ?nthnds /=; 1,3: smt(size_ge0).
            + split => [| _ @/nr_nodes]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodes (size nodes{2}))) /nr_nodes //.
              rewrite (: 2 ^ (h' - size nodes{2}) = 2 * 2 ^ (h' - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            + split => [| _ @/nr_nodes]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodes (size nodes{2}))) /nr_nodes //.
              rewrite (: 2 ^ (h' - size nodes{2}) = 2 * 2 ^ (h' - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; do 3! congr; 1: smt().
            by do 3! congr; ring.
          by wp; skip => /> &2; smt(expr_ge0 nth_rcons size_rcons).
        wp => /=.
        while (   ={skWOTSlp, pkWOTSlp, sigWOTSlp, leaveslp, rootsntp}
               /\ ps{1} = PKCOC_TCR.O_SMDTTCR_Default.pp{2}
               /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
               /\ ad{1} = adz
               /\ ad{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ad{2}
               /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                   nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2} i) j) u
                   =
                   pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
               /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                     nth witness (nth witness leavesnt{2} j) u
                     =
                     pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) j) pkcotype) u)
                          (flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
               /\ (forall (u : int), 0 <= u < size skWOTSlp{2} =>
                     nth witness leaveslp{2} u
                     =
                     pkco PKCOC_TCR.O_SMDTTCR_Default.pp{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) pkcotype) u)
                          (flatten (map DigestBlock.val (DBLL.val (nth witness pkWOTSlp{2} u)))))
               /\ (forall (adx : adrs * dgst),
                     adx \in PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                     <=>
                     (exists (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\
                       adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u))
                     \/
                     (exists (j u : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\
                       adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) * l' + j * l' + u))
                     \/
                     (exists (u : int), 0 <= u < size skWOTSlp{2} /\
                       adx = nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) * l'
                             + size skWOTSnt{2} * l' + u)))
               /\ (forall (i j u : int), 0 <= i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < l' =>
                     nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 i * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i j) pkcotype) u,
                      flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) j) u)))))
               /\ (forall (j u : int), 0 <= j < size skWOTSnt{2} => 0 <= u < l' =>
                     nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) * l' + j * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) j) pkcotype) u,
                      flatten (map DigestBlock.val (DBLL.val (nth witness (nth witness pkWOTSnt{2} j) u)))))
               /\ (forall (u : int), 0 <= u < size skWOTSlp{2} =>
                     nth witness PKCOC_TCR.O_SMDTTCR_Default.ts{2} (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) * l' + size skWOTSnt{2} * l' + u)
                     =
                     (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) pkcotype) u,
                      flatten (map DigestBlock.val (DBLL.val (nth witness pkWOTSlp{2} u)))))
               /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = pkcotype) PKCOC_TCR.O_SMDTTCR_Default.ts{2}
               /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
               /\ uniq (unzip1 PKCOC_TCR.O_SMDTTCR_Default.ts{2})
               /\ size PKCOC_TCR.O_SMDTTCR_Default.ts{2}
                  =
                  bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2})
                  +
                  size skWOTSnt{2} * l'
                  +
                  size skWOTSlp{2}
               /\ size skWOTSlp{1} = size skWOTSlp{2}
               /\ size skWOTSlp{2} = size pkWOTSlp{2}
               /\ size skWOTSlp{2} = size leaveslp{2}
               /\ size skWOTSlp{2} = size sigWOTSlp{2}
               /\ size skWOTSnt{1} = size skWOTSnt{2}
               /\ size skWOTSnt{2} = size pkWOTSnt{2}
               /\ size skWOTSnt{2} = size leavesnt{2}
               /\ size skWOTSnt{2} = size sigWOTSnt{2}
               /\ size skWOTSnt{2} = size rootsnt{2}
               /\ size skWOTStd{1} = size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}
               /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}
               /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2}
               /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.sigWOTStd{2}
               /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCPKCO_EUFNAGCMA.rootstd{2}
               /\ size skWOTSlp{1} <= l'
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTStd{1} < d).
        + inline{2} 7.
          wp => /=.
          while (   ={skWOTS, em}
                 /\ ps{1} = PKCOC.O_THFC_Default.pp{2}
                 /\ ad{1} = adz
                 /\ ad{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ad{2}
                 /\ sigWOTS{1} = sigWOTS0{2}
                 /\ pkWOTS{1} = pkWOTS0{2}
                 /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
                 /\ size skWOTS{2} = size pkWOTS0{2}
                 /\ size skWOTS{2} = size sigWOTS0{2}
                 /\ size skWOTStd{1} = size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}
                 /\ size skWOTSnt{1} = size skWOTSnt{2}
                 /\ size skWOTSlp{1} = size skWOTSlp{2}
                 /\ size skWOTS{1} <= len
                 /\ size skWOTSlp{1} < l'
                 /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
                 /\ size skWOTStd{1} < d).
          - wp => /=.
            exists* sigWOTS0{2}; elim* => sigwb.
            while{2} (   R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} = adz
                      /\ em_ele{2} = val em{2}.[size pkWOTS0{2}]
                      /\ ch_ele{2}
                         =
                         cf PKCOC.O_THFC_Default.pp{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) (size pkWOTS0{2})) 0 i0{2} (val (nth witness skWOTS{2} (size pkWOTS0{2})))
                      /\ (if i0{2} < BaseW.val em{2}.[size pkWOTS0{2}]
                          then sigWOTS0{2} = sigwb
                          else sigWOTS0{2}
                               =
                               rcons sigwb
                                     (cf PKCOC.O_THFC_Default.pp{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) (size pkWOTS0{2})) 0 (BaseW.val em{2}.[size pkWOTS0{2}]) (val (nth witness skWOTS{2} (size pkWOTS0{2})))))
                      /\ all (fun (ad : adrs) => get_typeidx ad <> pkcotype) PKCOC.O_THFC_Default.tws{2}
                      /\ size pkWOTS0{2} < len
                      /\ size skWOTSlp{2} < l'
                      /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2})
                      /\ size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2} < d
                      /\ 0 <= i0{2} <= w - 1)
                     (w - 1 - i0{2}).
            * move=> _ z.
              inline 1.
              wp; skip => /> &2 ifsig allnpkcotws ltlen_szpk ltlp_szsklp ltnt_szsknt ltd_szsktd ge0_i _ ltw1_i.
              rewrite valP /=.
              rewrite /cf (chS _ _ _ _ (i0{2} + 1)) 1:validxadrs_validwadrs_setallch 2..5,7:// 1:valx_adz 1:valP 1:// 1,2:/# /f /=.
              split => [eqem_i01 | neqem_i01]; rewrite -!andbA 2!andbA; split => [|/#||/#].
              + split; 2: rewrite -cats1 all_cat allnpkcotws /=; last first.
                - by rewrite gettype_setallch 1:valx_adz 3..5://; smt(size_ge0 dist_adrstypes).
                split => [ltem_i1 /# | /lezNgt geem_i1].
                have ltem_i: i0{2} < val em{2}.[size pkWOTS0{2}] by smt().
                move: ifsig; rewrite ltem_i => -> /=; congr.
                by rewrite -eqem_i01 (chS _ _ _ _ (i0{2} + 1)) 1:validxadrs_validwadrs_setallch 2..5,7:// 1:valx_adz 1:valP 1:// 1,2:/# /f /=.
              split; 2: rewrite -cats1 all_cat allnpkcotws /=; last first.
              + by rewrite gettype_setallch 1:valx_adz 3..5://; smt(size_ge0 dist_adrstypes).
              split => [ltem_i1 /# | /lezNgt geem_i1].
              have nltem_i: ! i0{2} < val em{2}.[size pkWOTS0{2}] by smt().
              by move: ifsig; rewrite nltem_i => -> /=; congr.
            wp; rnd; wp; skip => /> &1 &2 allnpkcotws eqszskpk ezsksig eqszsksktd eqszsksknt eqszsksklp _ ltlp_szsklp ltnt_szsknt ltd_szsktd tllen_szsk skwele skwelein.
            rewrite -eqszskpk; split => [-> /= | neq0_em].
            + rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 5,6://; 1..4: smt(size_ge0).
              rewrite valKd /= ?nth_rcons /=; split; 1: smt(val_w).
              move=> tws i sigw />.
              split => [/#| /lezNgt gew1_i + allnpkcotwsp _ _ _ _ ge0_i lew1_i].
              rewrite (: ! i < 0) 1:/# /= => ->.
              rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 5,6://; 1..4: smt(size_ge0).
              by rewrite valKd /= ?size_rcons /#.
            rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 5,6://; 1..4: smt(size_ge0).
            rewrite valKd /= ?nth_rcons /=; split; 1: smt(BaseW.valP val_w).
            move=> tws i sigw />.
            split => [/#| /lezNgt gew1_i + allnpkcotwsp _ _ _ _ ge0_i lew1_i].
            rewrite (: ! i < val em{2}.[size skWOTS{2}]); 1: smt(BaseW.valP).
            rewrite ?size_rcons eqszsksktd eqszsksknt eqszsksklp => -> /=.
            split; 2: smt(size_rcons).
            congr.
            rewrite (: i = val em{2}.[size skWOTS{2}] + (w - 1 - val em{2}.[size skWOTS{2}])) 1:/#.
            by rewrite (ch_comp _ _ _ 0) 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 4,5://; 1..7: smt(size_ge0 BaseW.valP val_w).
          wp; skip => /> &1 &2 lfsnth lfsnth1 lfsnth2 tsdef tsnth tsnth1 tsnth2 allpkcots allnpkcotws uqunz1ts szts
                               eqszskpklp eqszsklfslp eqszsksiglp eqszsksknt eqszskpknt eqszsklfsnt eqszsksignt eqszskrsnt
                               eqszsksktd eqszskpktd eqszsklfstd eqszsksigtd eqszskrstd _ ltnt_szsknt ltd_szsktd ltlp_szsklp.
          split; 1: by rewrite eqszsksknt; smt(ge2_len).
          move=> tws pkw sigw skw /lezNgt gelen_szskw _ eq_em allnpkcotwsp eqszskpkw eqszpksigw lelen_szskw.
          rewrite !andbA -4!andbA; split; 2: by rewrite ?size_rcons /#.
          rewrite -!andbA; split => [/#|].
          rewrite /nr_nodes_ht /nr_nodes /= -/l' -mulr_suml in szts.
          rewrite ?size_rcons.
          split => [u ge0_i|]; 1: by rewrite ?nth_rcons -eqszskpklp -eqszsklfslp; 1: smt(DBLL.insubdK).
          split => [adx |]; 1: rewrite mem_rcons /=; 1: split.
          - elim => [-> | /tsdef].
            * right; right; exists (size skWOTSlp{2}).
              by split; [smt(size_ge0) | rewrite nth_rcons /#].
            elim => [[i j u [ir] [jr] [ur adval]]|].
            * by left; exists i j u; rewrite ir jr ur /= nth_rcons szts ltbignrt_i.
            elim => [[j u [jr] [ur adval]]|].
            * right; left; exists j u; rewrite jr ur /= nth_rcons szts.
              pose igl := _ + j * l' + _; pose igr := _ + size skWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2://.
              rewrite -2!addrA ler_lt_add 1://.
              suff /#: j * l' + u < size skWOTSnt{2} * l' /\ 0 <= size skWOTSlp{2}.
              by rewrite size_ge0 /= (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
            elim => [u [ur adval]].
            * right; right; exists u; split; 1: smt(size_ge0).
              by rewrite nth_rcons szts /#.
          - case; 2: case.
            * elim=> i j u [rng_i [rng_j [rng_u]]].
              by rewrite nth_rcons szts ltbignrt_i 1..5:// /= tsdef /#.
            * elim=> j u [rng_j [rng_u]].
              rewrite nth_rcons szts.
              pose igl := _ + j * l' + _; pose igr := _ + size skWOTSnt{2} * l' + _.
              rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
              + rewrite -2!addrA ler_lt_add 1://.
                suff /#: j * l' + u < size skWOTSnt{2} * l' /\ 0 <= size skWOTSlp{2}.
                by rewrite size_ge0 /= (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
              by rewrite tsdef /#.
            by elim=> u [rng_u]; rewrite nth_rcons szts /#.
          split => [* | ]; 1: by rewrite nth_rcons szts ltbignrt_i // /= tsnth.
          split => [j u * | ]; 1: rewrite nth_rcons szts.
          - pose igl := _ + j * l' + _; pose igr := _ + size skWOTSnt{2} * l' + _.
            rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
            rewrite -2!addrA ler_lt_add 1://.
            suff /#: j * l' + u < size skWOTSnt{2} * l' /\ 0 <= size skWOTSlp{2}.
            by rewrite size_ge0 /= (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// /#.
          split => [u | ]; 1: rewrite ?nth_rcons szts => ge0_u ltsz1_u.
          - rewrite -eqszskpklp; case (u < size skWOTSlp{2}) => [ltszsk_u | nltszsk_u].
            + by rewrite tsnth2 // /#.
            by rewrite (: u = size skWOTSlp{2}) 1:/# /= insubdK /#.                  split; 1: rewrite -cats1 all_cat allpkcots /=.
          - by rewrite gettype_setkptypeltchpkco 1:valx_adz 3,4://; 1,2:smt(size_ge0).
          rewrite map_rcons rcons_uniq /= uqunz1ts /= mapP negb_exists => adx /=.
          rewrite negb_and -implybE => /tsdef.
          case; 2: case.
          - elim=> i j u [rng_i [rng_j [rng_u]]].
            rewrite tsnth 1..3:// => -> /=.
            rewrite -eq_adrs_idxs (neq_from_nth witness _ _ 5) 2://.
            by rewrite neqlidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
          - elim=> j u [rng_j [rng_u]].
            rewrite tsnth1 1..2:// => -> /=.
            rewrite -eq_adrs_idxs (neq_from_nth witness _ _ 4) 2://.
            by rewrite neqtidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
          elim=> u [rng_u].
          rewrite tsnth2 1:// => -> /=.
          rewrite -eq_adrs_idxs (neq_from_nth witness _ _ 2) 2://.
          by rewrite neqkpidx_setkptypelt 1:valx_adz 4..7,9://; smt(size_ge0).
        wp; skip => /> &1 &2 lfsnth lfsnth1 tsdef tsnth tsnth1 allpkcots allnpkcotws
                             uqunz1ts szts eqszskpknt eqszsklfsnt eqszsksignt eqszskrsnt
                             eqszsksktd eqszskpktd eqszsklfstd eqszsksigtd eqszskrstd _
                             ltd_szsktd ltnt_szsknt _.
        split => [| tws ts lfslp pkwlp sigwlp skwlp /lezNgt gelp_szskwlp _].
        + by split; smt(ge2_lp).
        move=> lfslpdef tspdef tspnth tspnth2 tspnth3 allpkcotsp allnpkcotwsp uqunz1tsp sztsp eqszpkskwlp eqszskwlfslp eqszsksigwlp lelp_szskwlp.
        split=> [| tws' nds]; 1: smt(ge1_hp).
        split=> [/# | /lezNgt gehp_sznds allnpkcotwspp ndsnth ltd_szskwtd eqlp_szlfslp lehp_sznds].
        rewrite !andbA -7!andbA; split; 2: by rewrite ?size_rcons /#.
        rewrite -!andbA; split.
        + congr; rewrite ndsnth 2:expr_gt0 2,3:// 2:/=; 1: smt(ge1_hp).
          by rewrite drop0 -/l' -eqlp_szlfslp take_size /#.
        split => [j u ge0_j | ]; 1: rewrite size_rcons ?nth_rcons.
        + by move=> *; rewrite -eqszsklfsnt -eqszskpknt /#.
        split => [ | j u ge0_j ]; last first.
        + by rewrite size_rcons ?nth_rcons -eqszskpknt /#.
        move=> adx; split => [/tspdef |]; smt(size_rcons size_ge0).
      wp; skip => /> &2 lfsdef tsdef tsnth allpkcots allnpkcotws uqunz1ts szts
                         eqszskpktd eqszsklfstd eqszsksigtd eqszskrtstd
                         _ ltd_szskwtd.
      split=> [| tws ts lfsnt  pkwnt rsnt sigwnt skwnt /lezNgt gent_szskwnt _].
      + by split; smt(expr_ge0).
      move=> lfsntnth tspdef tspnth tspnth1 allpkcotsp allnpkcotwsp uqun1ts sztsp eqszpkskwnt eqszskwlfsnt eqszsksigwnt eqszskwrsnt lent_szskwnt.
      rewrite !andbA -4!andbA; split; 2: by rewrite ?size_rcons /#.
      split; last first.
      + by rewrite sztsp size_rcons big_int_recr 1:size_ge0 //= /#.
      split => [| i j u]; last first.
      + rewrite size_rcons ?nth_rcons => *.
        case (i < size R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}) => [/#| ?].
        rewrite (: i = size R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}) 1:/# /=.
        by rewrite -eqszskpktd tspnth1 1:/#.
      split => [i j u | adx].
      + rewrite size_rcons ?nth_rcons -eqszsklfstd -eqszskpktd => *.
        case (i < size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) => [/#| ?].
        rewrite (: i = size R_SMDTTCRCPKCO_EUFNAGCMA.skWOTStd{2}) 1:/# /=.
        by rewrite lfsntnth 1:/#.
      by split => [/tspdef | i j u]; smt(size_ge0 nth_rcons size_rcons).
    wp; skip => /> &2 allnchtws.
    split => [| *]; 1: rewrite big_geq 1://; 1: smt(ge1_d).
    by split => /#.
  swap{1} [1..2] 2.
  sp 0 1.
  seq 2 2 : (#pre /\ ={sigl}); 1: by conseq />; sim.
  inline{2} 20; inline{2} 19; inline{2} 18; inline{2} 17; inline{2} 16.
  swap{1} 15 1.
  wp 15 17 => /=.
  conseq (:   is_fresh{1}
           /\ EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.valid_TCRPKCO{1}
           =>
              0 <= i{2} < bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d
           /\ 0 <= size PKCOC_TCR.O_SMDTTCR_Default.ts{2} <= bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d
           /\ x'{2} <> x{2}
           /\ pkco pp{2} tw{2} x{2} = pkco pp{2} tw{2} x'{2}).
  - move=> /> &2; rewrite (: d <> 0) 2:/=; 1: smt(ge1_d).
    move=> allnpkcotws lfsnth tsdef tsnth allpkcots uqunz1ts szts
           vTCR idx isf m pkw pkw' rs rs' i tw x x' + eqnthrs isfT neqnthpkws vTCRT.
    rewrite isfT vTCRT szts /= => -[[-> ->] [[-> ->] /= [neqxxp ->]]] /=.
    rewrite eq_sym neqxxp /= hasPn => ad /mapP [adx /= [+ ->]].
    rewrite implybE -negb_and -negP => -[adin adxin].
    by move: allnpkcotws => /allP /(_ adx.`1 adxin) /=; smt(allP).
  wp => /=.
  while (   ={ps, m', sig', idx', pkWOTSs, leavess, pkWOTSs', leavess', tkpidxs, tidx, kpidx, root'}
         /\ ad{1} = R_SMDTTCRCPKCO_EUFNAGCMA.ad{2}
         /\ pkWOTStd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2}
         /\ leavestd{1} = R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2}
         /\ 0 <= tidx{2}
         /\ (size pkWOTSs'{2} < d =>
               tidx{2} < nr_trees (size pkWOTSs'{2}) * l')
         /\ (size pkWOTSs'{2} < d =>
                tidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (size pkWOTSs'{2})).`1 /\
                kpidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (size pkWOTSs'{2})).`2)
         /\ (forall (i : int), 0 <= i < size pkWOTSs'{2} =>
               nth witness pkWOTSs{2} i
               =
               nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.pkWOTStd{2} i) (nth witness tkpidxs{2} i).`1) (nth witness tkpidxs{2} i).`2)
         /\ (forall (i : int), 0 <= i < size pkWOTSs'{2} =>
               nth witness leavess{2} i
               =
               nth witness (nth witness (nth witness R_SMDTTCRCPKCO_EUFNAGCMA.leavestd{2} i) (nth witness tkpidxs{2} i).`1) (nth witness tkpidxs{2} i).`2)
         /\ (forall (i : int), 0 <= i < size pkWOTSs'{2} =>
               nth witness leavess'{2} i
               =
               pkco ps{2} (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCPKCO_EUFNAGCMA.ad{2} i (nth witness tkpidxs{2} i).`1) pkcotype) (nth witness tkpidxs{2} i).`2)
                        (flatten (map DigestBlock.val (DBLL.val (nth witness pkWOTSs'{2} i)))))
         /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
               (nth witness tkpidxs{2} i).`1 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (i + 1)).`1 /\
               (nth witness tkpidxs{2} i).`2 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (i + 1)).`2)
         /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
               0 <= (nth witness tkpidxs{2} i).`1 < nr_trees i /\
               0 <= (nth witness tkpidxs{2} i).`2 < l')
         /\ size pkWOTSs'{2} = size pkWOTSs{2}
         /\ size pkWOTSs'{2} = size leavess{2}
         /\ size pkWOTSs'{2} = size leavess'{2}
         /\ size pkWOTSs'{2} = size tkpidxs{2}
         /\ size pkWOTSs'{2} <= d).
  * wp => /=.
    call (: true); 1: by sim.
    wp; skip => /> &2 ge0_ti ltnt_ti tkpicdef pkwrel lfsrel lfspdef tkpidef tkpirng eqszpkwp
                      eqszpkwplfs eqszpkwplfsp eqszpkwptkpi _ ltd_szpkwp pkwc.
    split; 1: by rewrite divz_ge0; smt(ge2_lp).
    rewrite ?nth_rcons ?size_rcons.
    split => [ltd_szpk1 |].
    + rewrite ltz_divLR; 1: smt(ge2_lp).
      move: (ltnt_ti _); 1: smt().
      rewrite /nr_nodes_ht /nr_trees /nr_nodes /l'.
      by rewrite /= -?exprD_nneg ?addr_ge0 ?mulr_ge0 ?ge1_hp; smt(ge1_hp).
    split => [ltd_szpk1 |]; 1: by rewrite foldS 1:// /= /#.
    split => [j ge0_j ltsz1_j |].
    + rewrite ?nth_rcons -eqszpkwp -eqszpkwptkpi.
      by case (j < size pkWOTSs'{2}) => /#.
    split => [j ge0_j ltsz1_j |].
    + rewrite ?nth_rcons -eqszpkwplfs -eqszpkwptkpi.
      by case (j < size pkWOTSs'{2}) => /#.
    split => [j ge0_j ltsz1_j |].
    + rewrite ?nth_rcons -eqszpkwplfsp -eqszpkwptkpi.
      by case (j < size pkWOTSs'{2}) => /#.
    split => [j ge0_j ltsz1_j |]; rewrite ?nth_rcons -eqszpkwptkpi.
    + case (j < size pkWOTSs'{2}) => [/# | nltszpkj].
      by rewrite (: j = size pkWOTSs'{2}) 1:/# /= foldS 1:// /= /#.
    split => [j ge0_j ltsz1_j |]; 2: smt(size_rcons).
    rewrite ?nth_rcons -eqszpkwptkpi.
    case (j < size pkWOTSs'{2}) => [/# | nltszpkj].
    rewrite (: j = size pkWOTSs'{2}) 1:/# /= divz_ge0 2:modz_ge0 3:ltz_pmod 4:/=; 1..3: smt(ge2_lp).
    by rewrite ge0_ti /= ltz_divLR; smt(ge2_lp).
  wp => /=.
  call (: true).
  wp; skip => /> &2 allnpkcotws lfsdef tsdef tsnth allpkcots uqunz1ts szts msigidx.
  split => [| lfs lfs' pkws pkws' ti tkpi /lezNgt ged_szpkw _ ge0ti].
  * rewrite /nr_trees /= andbA; split; 2: smt(ge1_d fold0).
    split => [| gt0_d]; 1: smt(Index.valP).
    move: (Index.valP (msigidx.`3)) => [_ @/l @/h @/l'].
    by rewrite -exprD_nneg ?mulr_ge0; smt(ge1_hp).
  move=> pkwrel lfsrel lfspdef tkpidef tkpirng eqszpkwp eqszpkwlfs eqszpkwlfsp eqszpkwtkpi led_szpkw neqm i ge0_i ltd_i eqilfs neqipk.
  pose zs := zip _ _; pose cidx := find _ _.
  have hascidx :
    has (fun (x : ((dgstblock * dgstblock) * pkWOTS) * pkWOTS) =>
                  x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2) zs.
  * rewrite -(has_nthP _ _ (((witness, witness), witness), witness)) /=.
    exists i; rewrite -(: d = size zs) 1:/zs 1:?size_zip /= 1:/#.
    split => [/#|].
    rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
    by rewrite (: i < size lfs') 1:/# //.
  have ge0_cidx : 0 <= cidx by rewrite find_ge0.
  have ltd_cidx : cidx < d.
  * by rewrite /cidx (: d = size zs) 1:/zs 1:?size_zip /= 1:/# -has_find.
  move /(nth_find (((witness, witness), witness), witness)): (hascidx) => /= @-/cidx.
  rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
  rewrite (: cidx < size lfs') 1:/# /= => -[eqlfs neqpk].
  rewrite tsnth 1:// 1,2:tkpirng 1,2:/# /=.
  split; 1: split => [| _].
  - rewrite ?addr_ge0 ?mulr_ge0 1:sumr_ge0; 2..5: smt(ge2_lp).
    by move=> ? ?; rewrite expr_ge0.
  - rewrite /nr_nodes_ht /nr_nodes /= -/l' -mulr_suml.
    rewrite -(addr0 (bigi predT nr_trees 0 d * l')) {3}(: 0 = 0 * l' + 0) 1:// addrA.
    by rewrite ltbignrt_i 2,4:/#.
  split; 1: by rewrite szts sumr_ge0 => [? _ /= | //]; rewrite mulr_ge0 expr_ge0.
  rewrite -pkwrel 1:/#; split; 1: rewrite -negP.
  - pose ml := List.map _ _; pose ml' := List.map _ _; move => eqfl.
    move: (eq_from_flatten_nth ml ml' _ _ eqfl); 1: by rewrite ?size_map ?valP.
    * move=> j; rewrite size_map valP => rng_j.
      by rewrite ?(nth_map witness) 1,2:valP 1,2:// ?valP.
    rewrite /ml /ml' => eqmap.
    have: injective (map DigestBlock.val) by rewrite inj_map val_inj.
    rewrite /injective => /(_ (val (nth witness pkws' cidx)) (val (nth witness pkws cidx)) eqmap) eqv.
    by move: (DBLL.val_inj (nth witness pkws' cidx) (nth witness pkws cidx) eqv).
  move: eqlfs; rewrite lfsrel 1:/# lfsdef 1:// 1,2:/# lfspdef 1:/# => -> /=.
  by rewrite pkwrel 1:/#.
rewrite Pr[mu_split EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.valid_TCRTRH] RealOrder.ler_naddr.
+ rewrite RealOrder.ler_eqVlt; left.
  byphoare => //.
  proc.
  swap 16 10.
  wp.
  conseq (: _ ==> false); 2: by hoare.
  move=> _ _ idx' lfs lfs' m' ml pkw pkw' rs rs'.
  rewrite -3!andbA; split => //.
  rewrite negP 2!negb_and -2!implybE.
  move=> + nrs0; have : 0 <= d by smt(ge1_d).
  by elim: d => /#.
byequiv=> //.
proc.
inline{2} 5; inline{2} 4.
swap{1} 3.
inline{1} 2; inline{2} 3; inline{2} 2; inline{2} 8.
swap{2} 7 4.
seq 5 10 : (   ={glob A}
            /\ ps{1} = pp{2}
            /\ ps{1} = O_THFC_Default.pp{1}
            /\ pp{2} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
            /\ pp{2} = O_THFC_Default.pp{2}
            /\ O_THFC_Default.tws{1} = R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2}
            /\ ml{1} = R_SMDTTCRCTRH_EUFNAGCMA.ml{2}
            /\ all (fun (ad : adrs) => get_typeidx ad <> trhtype) O_THFC_Default.tws{2}).
- call (:   ={glob A, arg}
         /\ O_THFC_Default.pp{1} = O_THFC_Default.pp{2}
         /\ O_THFC_Default.tws{1} = R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2}
         /\ R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} = O_THFC_Default.tws{2}
         /\ R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} = []
         ==>
            ={glob A, res}
         /\ O_THFC_Default.pp{1} = O_THFC_Default.pp{2}
         /\ O_THFC_Default.tws{1} = R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2}
         /\ R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} = O_THFC_Default.tws{2}
         /\ all (fun (ad : adrs) => get_typeidx ad <> trhtype) R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2}).
  * conseq (: ={glob A, arg} /\ O_THFC_Default.pp{1} = O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} /\ R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} = O_THFC_Default.tws{2}
              ==>
              ={glob A, res} /\ O_THFC_Default.pp{1} = O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} /\ R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} = O_THFC_Default.tws{2})
           _
           (: R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads = []
              ==>
              all (fun (ad : adrs) => get_typeidx ad <> trhtype) R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads) => //.
    proc (O_THFC_Default.pp{1} = O_THFC_Default.pp{2} /\ O_THFC_Default.tws{1} = R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} /\ R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads{2} = O_THFC_Default.tws{2}) => //.
    proc; inline{2} 1.
    by wp; skip.
  by wp; rnd; skip.
seq 7 8 : (   #pre
           /\ ad{1} = adz
           /\ ad{1} = R_SMDTTCRCTRH_EUFNAGCMA.ad{2}
           /\ skWOTStd{1} = R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}
           /\ pkWOTStd{1} = R_SMDTTCRCTRH_EUFNAGCMA.pkWOTStd{2}
           /\ sigWOTStd{1} = R_SMDTTCRCTRH_EUFNAGCMA.sigWOTStd{2}
           /\ leavestd{1} = R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}
           /\ rootstd{1} = R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2}
           /\ (forall (i j : int), 0 <= i < d => 0 <= j < nr_trees i =>
                 size (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j) = l')
           /\ (forall (i j : int), 0 <= i < d => 0 <= j < nr_trees i =>
                 nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2} i) j
                 =
                 val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                            (list2tree (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j)))
           /\ (forall (adx : adrs * dgst),
                 adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v : int), 0 <= i < d /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                   adx
                   =
                   nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                       (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                        bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)))
           /\ (forall (i j u v : int), 0 <= i < d => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                 =
                 (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype) (u + 1) v,
                  let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j in
                    val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                    ++
                    val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
           /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
           /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2} = bigi predT (fun (d' : int) => nr_trees d') 0 d * (2 ^ h' - 1)).
+ while (   ps{1} = pp{2}
         /\ ps{1} = O_THFC_Default.pp{1}
         /\ ps{1} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
         /\ ps{1} = TRHC.O_THFC_Default.pp{2}
         /\ ad{1} = adz
         /\ ad{1} = R_SMDTTCRCTRH_EUFNAGCMA.ad{2}
         /\ ml{1} = R_SMDTTCRCTRH_EUFNAGCMA.ml{2}
         /\ skWOTStd{1} = R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}
         /\ pkWOTStd{1} = R_SMDTTCRCTRH_EUFNAGCMA.pkWOTStd{2}
         /\ sigWOTStd{1} = R_SMDTTCRCTRH_EUFNAGCMA.sigWOTStd{2}
         /\ leavestd{1} = R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}
         /\ rootstd{1} = R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2}
         /\ (forall (i j : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i =>
                 size (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j) = l')
         /\ (forall (i j : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i =>
               nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2} i) j
               =
               val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                          (list2tree (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j)))
         /\ (forall (adx : adrs * dgst),
               adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
               <=>
               (exists (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                 adx
                 =
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)))
         /\ (forall (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
               nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                   (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                    bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
               =
               (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype) (u + 1) v,
                let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j in
                  val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                      (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                  ++
                  val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                      (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
         /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
         /\ all (fun (ad : adrs) => get_typeidx ad <> trhtype) O_THFC_Default.tws{2}
         /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
         /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2} = bigi predT (fun (d' : int) => nr_trees d') 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1)
         /\ size skWOTStd{1} = size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}
         /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.pkWOTStd{2}
         /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}
         /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.sigWOTStd{2}
         /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2}
         /\ size skWOTStd{1} <= d).
  - wp => /=.
    while (   ={skWOTSnt, pkWOTSnt, sigWOTSnt, leavesnt, rootsnt, rootsntp}
           /\ ps{1} = pp{2}
           /\ ps{1} = O_THFC_Default.pp{1}
           /\ ps{1} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
           /\ ps{1} = TRHC.O_THFC_Default.pp{2}
           /\ ad{1} = adz
           /\ ad{1} = R_SMDTTCRCTRH_EUFNAGCMA.ad{2}
           /\ (forall (i j : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i =>
                 size (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j) = l')
           /\ (forall (j : int), 0 <= j < size skWOTSnt{2} =>
                 size (nth witness leavesnt{2} j) = l')
           /\ (forall (i j : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i =>
                 nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2} i) j
                 =
                 val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                            (list2tree (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j)))
           /\ (forall (j : int), 0 <= j < size skWOTSnt{2} =>
                 nth witness rootsnt{2} j
                 =
                 val_bt_trh TRHC_TCR.O_SMDTTCR_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) j) trhtype)
                            (list2tree (nth witness leavesnt{2} j)))
           /\ (forall (adx : adrs * dgst),
                 adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
                 <=>
                 (exists (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                   adx
                   =
                   nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                       (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                        bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v))
                 \/
                 (exists (j u v : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                   adx
                   =
                   nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                       (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                        bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)))
           /\ (forall (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                 =
                 (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype) (u + 1) v,
                  let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j in
                    val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                    ++
                    val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
           /\ (forall (j u v : int), 0 <= j < size skWOTSnt{2} => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
                 nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                     (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                      bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                 =
                 (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) j) trhtype) (u + 1) v,
                  let leaveslp = nth witness leavesnt{2} j in
                    val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) j) trhtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                    ++
                    val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) j) trhtype)
                                        (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
           /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
           /\ all (fun (ad : adrs) => get_typeidx ad <> trhtype) O_THFC_Default.tws{2}
           /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
           /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2}
              =
              bigi predT (fun (d' : int) => nr_trees d') 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1)
              +
              size skWOTSnt{2} * (2 ^ h' - 1)
           /\ size skWOTSnt{1} = size skWOTSnt{2}
           /\ size skWOTSnt{2} = size pkWOTSnt{2}
           /\ size skWOTSnt{2} = size leavesnt{2}
           /\ size skWOTSnt{2} = size sigWOTSnt{2}
           /\ size skWOTSnt{2} = size rootsnt{2}
           /\ size skWOTStd{1} = size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}
           /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.pkWOTStd{2}
           /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}
           /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.sigWOTStd{2}
           /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2}
           /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
           /\ size skWOTStd{1} < d).
    * wp => /=.
      while{2} (   TRHC_TCR.O_SMDTTCR_Default.pp{2} = O_THFC_Default.pp{2}
                /\ R_SMDTTCRCTRH_EUFNAGCMA.ad{2} = adz
                /\ (forall (adx : adrs * dgst),
                      adx \in TRHC_TCR.O_SMDTTCR_Default.ts{2}
                      <=>
                      (exists (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                        adx
                        =
                        nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                           (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                            bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v))
                      \/
                      (exists (j u v : int), 0 <= j < size skWOTSnt{2} /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                        adx
                        =
                        nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                             bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v))
                      \/
                      (exists (u v : int), 0 <= u < size nodes{2} /\ 0 <= v < nr_nodes (u + 1) /\
                        adx
                        =
                        nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                            (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1) + (size skWOTSnt{2}) * (2 ^ h' - 1) +
                             bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)))
                /\ (forall (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
                      nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                           bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                      =
                      (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype) (u + 1) v,
                       let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) j in
                         val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                             (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                         ++
                         val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i j) trhtype)
                                             (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
                /\ (forall (j u v : int), 0 <= j < size skWOTSnt{2} => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
                      nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                           bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                      =
                      (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) j) trhtype) (u + 1) v,
                       let leaveslp = nth witness leavesnt{2} j in
                         val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) j) trhtype)
                                             (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                         ++
                         val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) j) trhtype)
                                             (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
                /\ (forall (u v : int), 0 <= u < size nodes{2} => 0 <= v < nr_nodes (u + 1) =>
                      nth witness TRHC_TCR.O_SMDTTCR_Default.ts{2}
                          (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1) + (size skWOTSnt{2}) * (2 ^ h' - 1) +
                           bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                      =
                      (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) trhtype) (u + 1) v,
                         val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) trhtype)
                                             (oget (sub_bt (list2tree leaveslp{2}) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                         ++
                         val (val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) trhtype)
                                             (oget (sub_bt (list2tree leaveslp{2}) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
                /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhtype) TRHC_TCR.O_SMDTTCR_Default.ts{2}
                /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts{2})
                /\ size TRHC_TCR.O_SMDTTCR_Default.ts{2}
                   =
                   bigi predT (fun (d' : int) => nr_trees d') 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) * (2 ^ h' - 1)
                   +
                   size skWOTSnt{2} * (2 ^ h' - 1)
                   +
                   bigi predT (fun (m : int) => nr_nodes m) 1 (size nodes{2} + 1)
                /\ (forall (u v : int), 0 <= u < size nodes{2} => 0 <= v < nr_nodes (u + 1) =>
                      nth witness (nth witness nodes{2} u) v
                      =
                      val_bt_trh_gen TRHC.O_THFC_Default.pp{2} (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) trhtype)
                                     (oget (sub_bt (list2tree leaveslp{2}) (rev (int2bs (h' - u - 1) v)))) (u + 1) v)
                /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} < d
                /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2})
                /\ size leaveslp{2} = l'
                /\ size nodes{2} <= h')
               (h' - size nodes{2}).
      + move=> _ z.
        wp => /=.
        while (   TRHC_TCR.O_SMDTTCR_Default.pp = O_THFC_Default.pp
               /\ R_SMDTTCRCTRH_EUFNAGCMA.ad = adz
               /\ (forall (adx : adrs * dgst),
                     adx \in TRHC_TCR.O_SMDTTCR_Default.ts
                     <=>
                     (exists (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd /\ 0 <= j < nr_trees i /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                          (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                           bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v))
                     \/
                     (exists (j u v : int), 0 <= j < size skWOTSnt /\ 0 <= u < h' /\ 0 <= v < nr_nodes (u + 1) /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                           (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                            bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v))
                     \/
                     (exists (u v : int), 0 <= u < size nodes /\ 0 <= v < nr_nodes (u + 1) /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                           (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                            bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v))
                     \/
                     (exists (v : int), 0 <= v < size nodescl /\
                       adx
                       =
                       nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                           (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                            bigi predT (fun (m : int) => nr_nodes m) 1 (size nodes + 1) + v)))
               /\ (forall (i j u v : int), 0 <= i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd => 0 <= j < nr_trees i => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (bigi predT (fun (m : int) => nr_trees m) 0 i * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                          bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad i j) trhtype) (u + 1) v,
                      let leaveslp = nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd i) j in
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad i j) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                        ++
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad i j) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
               /\ (forall (j u v : int), 0 <= j < size skWOTSnt => 0 <= u < h' => 0 <= v < nr_nodes (u + 1) =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) * (2 ^ h' - 1) + j * (2 ^ h' - 1) +
                          bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) j) trhtype) (u + 1) v,
                      let leaveslp = nth witness leavesnt j in
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) j) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                        ++
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) j) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
               /\ (forall (u v : int), 0 <= u < size nodes => 0 <= v < nr_nodes (u + 1) =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                          bigi predT (fun (m : int) => nr_nodes m) 1 (u + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype) (u + 1) v,
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v))))) u (2 * v))
                        ++
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u) (2 * v + 1))))) u (2 * v + 1))))
               /\ (forall (v : int), 0 <= v < size nodescl =>
                     nth witness TRHC_TCR.O_SMDTTCR_Default.ts
                         (bigi predT (fun (m : int) => nr_trees m) 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) * (2 ^ h' - 1) + (size skWOTSnt) * (2 ^ h' - 1) +
                          bigi predT (fun (m : int) => nr_nodes m) 1 (size nodes + 1) + v)
                     =
                     (set_thtbidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype) (size nodes + 1) v,
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - size nodes) (2 * v))))) (size nodes) (2 * v))
                        ++
                        val (val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                            (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - size nodes) (2 * v + 1))))) (size nodes) (2 * v + 1))))
               /\ all (fun (adx : _ * _) => get_typeidx adx.`1 = trhtype) TRHC_TCR.O_SMDTTCR_Default.ts
               /\ uniq (unzip1 TRHC_TCR.O_SMDTTCR_Default.ts)
               /\ size TRHC_TCR.O_SMDTTCR_Default.ts
                  =
                  bigi predT (fun (d' : int) => nr_trees d') 0 (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) * (2 ^ h' - 1)
                  +
                  size skWOTSnt * (2 ^ h' - 1)
                  +
                  bigi predT (fun (m : int) => nr_nodes m) 1 (size nodes + 1)
                  +
                  size nodescl
               /\ (forall (u v : int), 0 <= u < size nodes => 0 <= v < nr_nodes (u + 1) =>
                     nth witness (nth witness nodes u) v
                     =
                     val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                    (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - u - 1) v)))) (u + 1) v)
               /\ (forall (v : int), 0 <= v < size nodescl =>
                     nth witness nodescl v
                     =
                     val_bt_trh_gen TRHC.O_THFC_Default.pp (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd) (size skWOTSnt)) trhtype)
                                    (oget (sub_bt (list2tree leaveslp) (rev (int2bs (h' - size nodes - 1) v)))) (size nodes + 1) v)
               /\ nodespl = last leaveslp nodes
               /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd < d
               /\ size skWOTSnt < nr_trees (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd)
               /\ size leaveslp = l'
               /\ size nodescl <= nr_nodes (size nodes + 1)
               /\ size nodes < h')
              (nr_nodes (size nodes + 1) - size nodescl).
        * move=> z'.
          inline 3.
          wp; skip => /> &2 tsdef tsnth tsnth1 tsnth2 tsnth3 alltrhts uqunz1ts
                            szts nthnds nthndscl ltd_szskw ltnt_szskwnt
                            eqlp_szlfslp _ lthp_sznds ltnn_szndscl.
          rewrite ?size_rcons !andbA -andbA; split => [| /#].
          rewrite -!andbA; split => [adx | ].
          + rewrite mem_rcons /=; split.
            - elim => [-> | /tsdef].
              * right; right; right; exists (size nodescl{2}).
                by split; [smt(size_ge0) | rewrite nth_rcons /#].
              elim => [[i j u v [ir] [jr] [ur [vr adval]]]|].
              * left; exists i j u v; rewrite ir jr ur vr /= nth_rcons szts.
                by rewrite ltbignn_i.
              elim => [[j u v [jr] [ur [vr adval]]]|].
              * right; left; exists j u v; rewrite jr ur vr /= nth_rcons szts.
                pose igl := _ + j * _ + _ + _; pose igr := _ + size skWOTSnt{2} * _ + _ + _.
                rewrite (: igl < igr) /igl /igr 2://.
                rewrite -4!addrA ler_lt_add 1://.
                suff /#:
                  j * (2 ^ h' - 1) + (bigi predT nr_nodes 1 (u + 1) + v) < size skWOTSnt{2} * (2 ^ h' - 1)
                  /\
                  0 <= bigi predT nr_nodes 1 (size nodes{2} + 1) + size nodescl{2}.
                rewrite addr_ge0 3:/= 2:size_ge0 1:sumr_ge0 => [? _ |]; 1: by rewrite expr_ge0.
                rewrite (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// 2:/=.
                + by rewrite ler_pmul2r 1:ltr_subr_addl /= 1:ltzE /= 1:ler_eexpr 2://; smt(ge1_hp).
                by rewrite ltnn1_bignn.
              elim => [[u v [ur] [vr adval]]|].
              * right; right; left.
                exists u v; split; 1: smt(size_ge0).
                rewrite nth_rcons szts.
                pose igl := _ + size skWOTSnt{2} * _ + _ + _; pose igr := _ + size skWOTSnt{2} * _ + _ + _.
                rewrite (: igl < igr) /igl /igr 2://.
                rewrite -addrA -(addrA _ _ (size nodescl{2})) ler_lt_add 1://.
                suff /#:
                  bigi predT nr_nodes 1 (u + 1) + v < bigi predT nr_nodes 1 (size nodes{2} + 1)
                  /\
                  0 <= size nodescl{2}.
                rewrite size_ge0 /= 1:(big_cat_int (u + 1) _ (size nodes{2} + 1)) 1,2:/#.
                rewrite ler_lt_add // (big_cat_int (u + 2)) 1,2:/#.
                rewrite big_int1; suff /#: 0 <= bigi predT nr_nodes (u + 2) (size nodes{2} + 1).
                by rewrite sumr_ge0 => ? _; rewrite expr_ge0.
              elim => [v [vr adval]].
              right; right; right.
              exists v; split; 1: smt(size_ge0).
              by rewrite nth_rcons szts /#.
            case; 2: case; 3: case.
            * elim=> i j u v [rng_i [rng_j [rng_u [rng_v]]]].
              rewrite nth_rcons szts.
              pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
              rewrite (: igl < igr) /igl /igr 2:// /= 1:ltbignn_i 1..7://.
              by rewrite tsnth 1..4:// => ->; right; rewrite tsdef; left; exists i j u v => /#.
            * elim=> j u v [rng_j [rng_u [rng_v]]].
              rewrite nth_rcons szts.
              pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
              rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
              + rewrite -4!addrA ler_lt_add 1://.
                suff /#:
                  j * (2 ^ h' - 1) + (bigi predT nr_nodes 1 (u + 1) + v) < size skWOTSnt{2} * (2 ^ h' - 1)
                  /\
                  0 <= bigi predT nr_nodes 1 (size nodes{2} + 1) + size nodescl{2}.
                rewrite addr_ge0 3:/= 2:size_ge0 1:sumr_ge0 => [? _ |]; 1: by rewrite expr_ge0.
                rewrite (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// 2:/=.
                + by rewrite ler_pmul2r 1:ltr_subr_addl /= 1:ltzE /= 1:ler_eexpr 2://; smt(ge1_hp).
                by rewrite ltnn1_bignn.
              by rewrite tsdef /#.
            * elim=> u v [rng_u [rng_v]].
              rewrite nth_rcons szts.
              pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
              rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth2 //.
              + rewrite -addrA -(addrA _ _ (size nodescl{2})) ler_lt_add 1://.
                suff /#:
                  bigi predT nr_nodes 1 (u + 1) + v < bigi predT nr_nodes 1 (size nodes{2} + 1)
                  /\
                  0 <= size nodescl{2}.
                rewrite size_ge0 /= 1:(big_cat_int (u + 1) _ (size nodes{2} + 1)) 1,2:/#.
                rewrite ler_lt_add // (big_cat_int (u + 2)) 1,2:/#.
                rewrite big_int1; suff /#: 0 <= bigi predT nr_nodes (u + 2) (size nodes{2} + 1).
                by rewrite sumr_ge0 => ? _; rewrite expr_ge0.
              by rewrite tsdef /#.
            by elim=> v [rng_v]; rewrite nth_rcons szts /#.
          split => [i j u v ge0_i ltszsktd_i ge0_j ltnti_j ge0_u lthp_u ge0_v ltnnu1_v|].
          * by rewrite nth_rcons szts ltbignn_i 8:tsnth.
          split => [j u v ge0_j ltnti_j ge0_u lthp_u ge0_v ltnnu1_v|].
          * rewrite nth_rcons szts.
            pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
            rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth1 //.
            rewrite -4!addrA ler_lt_add 1://.
            suff /#:
              j * (2 ^ h' - 1) + (bigi predT nr_nodes 1 (u + 1) + v) < size skWOTSnt{2} * (2 ^ h' - 1)
              /\
              0 <= bigi predT nr_nodes 1 (size nodes{2} + 1) + size nodescl{2}.
            rewrite addr_ge0 3:/= 2:size_ge0 1:sumr_ge0 => [? _ |]; 1: by rewrite expr_ge0.
            rewrite (: size skWOTSnt{2} = size skWOTSnt{2} - 1 + 1) 1:// mulrDl ler_lt_add 2:// 2:/=.
            + by rewrite ler_pmul2r 1:ltr_subr_addl /= 1:ltzE /= 1:ler_eexpr 2://; smt(ge1_hp).
            by rewrite ltnn1_bignn.
          split => [u v ge0_u lthp_u ge0_v ltnnu1_v|].
          * rewrite nth_rcons szts.
            pose igl := (_ + _ + _ + _)%Int; pose igr := (_ + _ + _ + _)%Int.
            rewrite (: igl < igr) /igl /igr 2:/= 2:tsnth2 //.
            suff /#:
              bigi predT nr_nodes 1 (u + 1) + v < bigi predT nr_nodes 1 (size nodes{2} + 1)
              /\
              0 <= size nodescl{2}.
            rewrite size_ge0 /= 1:(big_cat_int (u + 1) _ (size nodes{2} + 1)) 1,2:/#.
            rewrite ler_lt_add // (big_cat_int (u + 2)) 1,2:/#.
            rewrite big_int1; suff /#: 0 <= bigi predT nr_nodes (u + 2) (size nodes{2} + 1).
            by rewrite sumr_ge0 => ? _; rewrite expr_ge0.
          split => [v ge0_v ltnnu1_v|].
          * rewrite nth_rcons szts /=.
            case (v < size nodescl{2}) => [ltszncl_v /# | nltszncl_v].
            rewrite (: v = size nodescl{2}) 1:/# /=.
            have rngszndscl : 0 <= 2 * size nodescl{2} + 1 < nr_nodes (size nodes{2}).
            + split => [|_]; 1: smt(size_ge0).
              rewrite (ler_lt_trans (nr_nodes (size nodes{2}) - 1)) 2:/#.
              rewrite (: nr_nodes (size nodes{2}) = 2 * nr_nodes (size nodes{2} + 1)) 2:/#.
              by rewrite -(expr1 2) /nr_nodes -exprD_nneg 1:// 1,2:/#.
            rewrite -nth_last; case (size nodes{2} = 0) => [eq0_sznds | neq0_sznds].
            + rewrite eq0_sznds /= (nth_out _ _ (-1)) 1://.
              rewrite 2?(subbt_list2tree_idx_leaf witness) 2,5://; 1..4: smt(ge1_hp).
              by rewrite oget_some.
            rewrite -(nth_change_dfl leaveslp{2} witness); 1:smt(size_ge0).
            by rewrite ?nthnds /= 4:// ; smt(size_ge0).
          split; 1: rewrite -cats1 all_cat alltrhts /=.
          * by rewrite gettype_setalltrh 1:valx_adz 1,2,4,5://; smt(size_ge0).
          split; 2: split; 2: by rewrite szts addrA.
          * rewrite map_rcons rcons_uniq /= uqunz1ts /= mapP negb_exists => adx /=.
            rewrite negb_and -implybE => /tsdef.
            case; 2: case.
            - elim=> i j u v [rng_i [rng_j [rng_u [rng_v]]]].
              rewrite tsnth 1..4:// => -> /=.
              rewrite -eq_adrs_idxs (neq_from_nth witness _ _ 5) 2://.
              by rewrite neqlidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
            - elim=> j u v [rng_j [rng_u [rng_v]]].
              rewrite tsnth1 1..3:// => -> /=.
              rewrite -eq_adrs_idxs (neq_from_nth witness _ _ 4) 2://.
              by rewrite neqtidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
            case; elim=> [u v [rng_u [rng_v]] | u [rng_u]].
            - rewrite tsnth2 1,2:// => -> /=.
              rewrite -eq_adrs_idxs (neq_from_nth witness _ _ 1) 2://.
              by rewrite neqthidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
            rewrite tsnth3 1:// => -> /=.
            rewrite -eq_adrs_idxs (neq_from_nth witness _ _ 0) 2://.
            by rewrite neqtbidx_setthtypelt 1:valx_adz 1,3,4,7,8,10://; smt(size_ge0).
          move=> v ge0_v ltsz1_v; rewrite nth_rcons.
          case (v < size nodescl{2}) => [/# | nltszndscl_v].
          rewrite (: v = size nodescl{2}) 1:/# /=.
          have rngszndscl : 0 <= 2 * size nodescl{2} + 1 < nr_nodes (size nodes{2}).
          * split => [|_]; 1: smt(size_ge0).
            rewrite (ler_lt_trans (nr_nodes (size nodes{2}) - 1)) 2:/#.
            rewrite (: nr_nodes (size nodes{2}) = 2 * nr_nodes (size nodes{2} + 1)) 2:/#.
            by rewrite -(expr1 2) /nr_nodes -exprD_nneg 1:// 1,2:/#.
          rewrite -nth_last; case (size nodes{2} = 0) => [eq0_sznds | neq0_sznds].
          * rewrite eq0_sznds /= (nth_out _ _ (-1)) 1://.
            rewrite subbt_list2tree_takedrop 1:ge1_hp 1:// 1:size_ge0 1:/# 1://.
            rewrite expr1 {3}(: 2 = 1 + 1) 1:// take_take_drop_cat 1,2://.
            rewrite drop_drop 1:// 1:/# ?(take1_head witness) 1,2:size_drop 1..4:/#.
            rewrite (list2treeS 0) 1:// 1,2:expr0 1,2://.
            rewrite /val_bt_trh_gen /= /trhi.
            by rewrite 2?list2tree1 /= -2?nth0_head 2?nth_drop 2,4:// /#.
          rewrite -(nth_change_dfl leaveslp{2} witness); 1:smt(size_ge0).
          rewrite ?nthnds /= 4://; 1..3: smt(size_ge0).
          rewrite eq_sym (: h' - size nodes{2} - 1 = h' - (size nodes{2} + 1)) 1:/#.
          rewrite subbt_list2tree_takedrop 2:size_ge0 2:/# 2:eqlp_szlfslp 2://; 1: smt(size_ge0).
          rewrite (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})) 1:exprD_nneg 1,2:// 1:expr1 1:/#.
          rewrite take_take_drop_cat 1,2:expr_ge0 1,2://.
          have ge1_2aszn2szncl : 1 <= 2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1.
          + rewrite 2!IntOrder.ler_subr_addr /=.
            rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodes (size nodes{2} + 1) - 1))) 1:/#.
            by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
          rewrite (list2treeS (size nodes{2})) 1://.
          + rewrite size_take 1:expr_ge0 1:// size_drop 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
            rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
            pose szn2 := 2 ^ (size nodes{2}).
            rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
            pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
            pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:maxrr.
            by rewrite ltr_pmull 1:expr_gt0 // /#.
          + rewrite drop_drop 1:expr_ge0 1:// 1,2:// 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 1,2://.
            rewrite size_take 1:expr_ge0 1:// size_drop 1:addr_ge0 1:expr_ge0 // 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
            rewrite eqlp_szlfslp /l' (: 2 ^ h' = 2 ^ (h' - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
            pose szn2 := 2 ^ (size nodes{2}).
            rewrite (: 2 ^ (h' - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
            pose sb := ((_ - _ - _) * _)%Int.
            move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
            - by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
            rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
            - rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodes (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodes mulzDr -{1}(expr1 2) -exprD_nneg // /#.
            rewrite (: szn2 < (2 ^ (h' - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.
            by rewrite ltr_pmull 1:expr_gt0.
          rewrite /val_bt_trh_gen /= /trhi /=; congr.
          rewrite (: h' - (size nodes{2} - 1) - 1 = h' - (size nodes{2})) 1:/#.
          rewrite 2?subbt_list2tree_takedrop 3,5,6:// 1,3:size_ge0 /= 1..3:/#.
          by rewrite drop_drop 1:expr_ge0 1,2:// 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 1,2:// /#.
        wp; skip => /> &2 tsdef tsnth tsnth1 tsnth2 alltrhts uqunz1ts szts nthnds
                          ltd_szskw ltnt_szskwnt eqlp_szlfslp _ lthp_sznds.
        split => [| ts ndscl]; 1: smt(expr_ge0).
        split => [/# | /lezNgt genn_szndscl].
        move=> tspdef tspnth tspnth1 tspnth2 tspnth3 alltrhtsp uqunz1tsp sztsp ndsclnth lenn_szndscl.
        rewrite ?size_rcons !andbA -andbA; split => [| /#].
        rewrite -!andbA; split => [adx |].
        * rewrite tspdef; split.
          + do 2! (elim => [-> // |]); elim => [/#|].
            elim => v [rng_v ->].
            by right; right; exists (size nodes{2}) v; smt(size_ge0).
          do 2! (elim => [-> // |]).
          elim => u v [rng_u [rng_v ->]].
          case (u < size nodes{2}) => [? | nltszu].
          + by right; right; left; exists u v => /#.
          by right; right; right; exists v => /#.
        split => [u v ge0_u ltsz1_u ge0_v ltnn_v |].
        * case (u < size nodes{2}) => [/# | nltszu].
          by rewrite (: u = size nodes{2}) 1:/# tspnth3 1:/#.
        split => [| u v ge0_u ltsz1_u ge0_v ltnn_vc]; 1: rewrite sztsp -addrA.
        + by congr; rewrite eq_sym big_int_recr; smt(size_ge0).
        rewrite nth_rcons; case (u < size nodes{2}) => [/# | nltszu].
        by rewrite (: u = size nodes{2}) 1:/# /= ndsclnth 1:/#.
      wp => /=.
      while (   ={skWOTSlp, pkWOTSlp, sigWOTSlp, leaveslp, rootsntp}
             /\ ps{1} = TRHC_TCR.O_SMDTTCR_Default.pp{2}
             /\ ps{1} = TRHC.O_THFC_Default.pp{2}
             /\ ad{1} = adz
             /\ ad{1} = R_SMDTTCRCTRH_EUFNAGCMA.ad{2}
             /\ all (fun (ad : adrs) => get_typeidx ad <> trhtype) O_THFC_Default.tws{2}
             /\ size skWOTSlp{1} = size skWOTSlp{2}
             /\ size skWOTSlp{2} = size pkWOTSlp{2}
             /\ size skWOTSlp{2} = size leaveslp{2}
             /\ size skWOTSlp{2} = size sigWOTSlp{2}
             /\ size skWOTSnt{1} = size skWOTSnt{2}
             /\ size skWOTSnt{2} = size pkWOTSnt{2}
             /\ size skWOTSnt{2} = size leavesnt{2}
             /\ size skWOTSnt{2} = size sigWOTSnt{2}
             /\ size skWOTSnt{2} = size rootsnt{2}
             /\ size skWOTStd{1} = size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}
             /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.pkWOTStd{2}
             /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}
             /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.sigWOTStd{2}
             /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} = size R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2}
             /\ size skWOTSlp{1} <= l'
             /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
             /\ size skWOTStd{1} < d).
      + inline{2} 7.
        wp => /=.
        while (   ={skWOTS, em}
               /\ ps{1} = TRHC.O_THFC_Default.pp{2}
               /\ ad{1} = adz
               /\ ad{1} = R_SMDTTCRCTRH_EUFNAGCMA.ad{2}
               /\ sigWOTS{1} = sigWOTS0{2}
               /\ pkWOTS{1} = pkWOTS0{2}
               /\ all (fun (ad : adrs) => get_typeidx ad <> trhtype) TRHC.O_THFC_Default.tws{2}
               /\ size skWOTS{2} = size pkWOTS0{2}
               /\ size skWOTS{2} = size sigWOTS0{2}
               /\ size skWOTStd{1} = size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}
               /\ size skWOTSnt{1} = size skWOTSnt{2}
               /\ size skWOTSlp{1} = size skWOTSlp{2}
               /\ size skWOTS{1} <= len
               /\ size skWOTSlp{1} < l'
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTStd{1} < d).
        - wp => /=.
          exists* sigWOTS0{2}; elim* => sigwb.
          while{2} (   R_SMDTTCRCTRH_EUFNAGCMA.ad{2} = adz
                    /\ em_ele{2} = val em{2}.[size pkWOTS0{2}]
                    /\ ch_ele{2}
                       =
                       cf TRHC.O_THFC_Default.pp{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) (size pkWOTS0{2})) 0 i0{2} (val (nth witness skWOTS{2} (size pkWOTS0{2})))
                    /\ (if i0{2} < BaseW.val em{2}.[size pkWOTS0{2}]
                        then sigWOTS0{2} = sigwb
                        else sigWOTS0{2}
                             =
                             rcons sigwb
                                   (cf TRHC.O_THFC_Default.pp{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx R_SMDTTCRCTRH_EUFNAGCMA.ad{2} (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) (size pkWOTS0{2})) 0 (BaseW.val em{2}.[size pkWOTS0{2}]) (val (nth witness skWOTS{2} (size pkWOTS0{2})))))
                    /\ all (fun (ad : adrs) => get_typeidx ad <> trhtype) TRHC.O_THFC_Default.tws{2}
                    /\ size pkWOTS0{2} < len
                    /\ size skWOTSlp{2} < l'
                    /\ size skWOTSnt{2} < nr_trees (size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2})
                    /\ size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2} < d
                    /\ 0 <= i0{2} <= w - 1)
                   (w - 1 - i0{2}).
          * move => _ z.
            inline 1.
            wp; skip => /> &2 ifsig allntrhtws ltlen_szpk ltlp_szsklp ltnt_szsknt ltd_szsktd ge0_i _ ltw1_i.
            rewrite valP /=.
            rewrite /cf (chS _ _ _ _ (i0{2} + 1)) 1:validxadrs_validwadrs_setallch 2..5,7:// 1:valx_adz 1:valP 1:// 1,2:/# /f /=.
            split => [eqem_i01 | neqem_i01]; rewrite -!andbA 2!andbA; split => [|/#||/#].
            + split; 2: rewrite -cats1 all_cat allntrhtws /=; last first.
              - by rewrite gettype_setallch 1:valx_adz 3..5://; smt(size_ge0 dist_adrstypes).
              split => [ltem_i1 /# | /lezNgt geem_i1].
              have ltem_i: i0{2} < val em{2}.[size pkWOTS0{2}] by smt().
              move: ifsig; rewrite ltem_i => -> /=; congr.
              by rewrite -eqem_i01 (chS _ _ _ _ (i0{2} + 1)) 1:validxadrs_validwadrs_setallch 2..5,7:// 1:valx_adz 1:valP 1:// 1,2:/# /f /=.
            split; 2: rewrite -cats1 all_cat allntrhtws /=; last first.
            + by rewrite gettype_setallch 1:valx_adz 3..5://; smt(size_ge0 dist_adrstypes).
            split => [ltem_i1 /# | /lezNgt geem_i1].
            have nltem_i: ! i0{2} < val em{2}.[size pkWOTS0{2}] by smt().
            by move: ifsig; rewrite nltem_i => -> /=; congr.
          wp; rnd; wp; skip => /> &1 &2 allntrhtws eqszskpk ezsksig eqszsksktd eqszsksknt eqszsksklp _ ltlp_szsklp ltnt_szsknt ltd_szsktd ltlen_szsk skwele skwelein.
          rewrite -eqszskpk; split => [-> /= | neq0_em].
          + rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 5,6://; 1..4: smt(size_ge0).
            rewrite valKd /= ?nth_rcons /=; split; 1: smt(val_w).
            move=> tws i sigw />.
            split => [/#| /lezNgt gew1_i + allntrhtwsp _ _ _ _ ge0_i lew1_i].
            rewrite (: ! i < 0) 1:/# /= => ->.
            rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 5,6://; 1..4: smt(size_ge0).
            by rewrite valKd /= ?size_rcons /#.
          rewrite /cf ch0 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 5,6://; 1..4: smt(size_ge0).
          rewrite valKd /= ?nth_rcons /=; split; 1: smt(BaseW.valP val_w).
          move=> tws i sigw />.
          split => [/#| /lezNgt gew1_i + allnpkcotwsp _ _ _ _ ge0_i lew1_i].
          rewrite (: ! i < val em{2}.[size skWOTS{2}]); 1: smt(BaseW.valP).
          rewrite ?size_rcons eqszsksktd eqszsksknt eqszsksklp => -> /=.
          split; 2: smt(size_rcons).
          congr.
          rewrite (: i = val em{2}.[size skWOTS{2}] + (w - 1 - val em{2}.[size skWOTS{2}])) 1:/#.
          by rewrite (ch_comp _ _ _ 0) 1:validxadrs_validwadrs_setallch 1:valx_adz 5:valP 4,5://; 1..7: smt(size_ge0 BaseW.valP val_w).
        wp; skip => /> &1 &2 allntrhtws eqszskpklp eqszsklfslp eqszsksiglp eqszsksknt eqszskpknt eqszsklfsnt eqszsksignt eqszskrsnt
                             eqszsksktd eqszskpktd eqszsklfstd eqszsksigtd eqszskrstd _ ltnt_szsknt ltd_szsktd ltlp_szsklp.
        split; 1: by rewrite eqszsksknt; smt(ge2_len).
        move=> tws pkw sigw skw /lezNgt gelen_szskw _ eq_em allntrhtwsp eqszskpkw eqszsksigw lelen_szskw.
        rewrite !andbA -3!andbA; split; 2: by rewrite ?size_rcons /#.
        rewrite size_flatten -map_comp sumzE /= big_map /(\o) /predT /= -/predT.
        rewrite (eq_bigr _ _ (fun (_ : DigestBlock.sT) => 8 * n)) 1:/=.
        * by move=> ? _; rewrite valP.
        rewrite big_constz count_predT; split => [/# |].
        rewrite -cats1 all_cat allntrhtwsp /=.
        by rewrite gettype_setkptypeltchpkco 1:valx_adz 3,4://; smt(size_ge0 dist_adrstypes).
       wp; skip => /> &1 &2 lfsszs lfsszs1 rsnth rsnth1 tsdef tsnth tsnth1 alltrhts allntrhtws
                           uqunz1ts szts eqszskpknt eqszsklfsnt eqszsksignt eqszskrsnt
                           eqszsksktd eqszskpktd eqszsklfstd eqszsksigtd eqszskrstd _
                           ltd_szsktd ltnt_szsknt _.
      split => [| tws lfslp pkwlp sigwlp skwlp /lezNgt gelp_szskwlp _]; 1: smt(ge2_lp).
      move=> allntrhtwsp eqszskpkwlp eqszskwlfslp eqszsksigwlp lelp_szskwlp.
      rewrite (range_geq 1 1) 1:// /=.
      split => [| ts nds ]; 1: smt(ge1_hp).
      split=> [/# | /lezNgt gehp_sznds tspdef tspnth tspnth1 tspnth2 alltrhtsp uqunz1tsp sztsp ndsnth ltd_szskwtd eqlp_szlfslp lehp_sznds].
      rewrite !andbA -6!andbA; split; 2: by rewrite ?size_rcons /#.
      rewrite -!andbA; split.
      + congr; rewrite ndsnth 2:expr_gt0 2,3:// 2:/=; 1: smt(ge1_hp).
        rewrite /val_bt_trh /val_bt_trh_gen; congr => [/#|].
        by rewrite (: h' - (h' - 1) - 1 = 0) 1:/# int2bs0s rev_nil subbt_empty oget_some.
      split; 1: smt(size_ge0 nth_rcons size_rcons).
      split => [j ge0_j |]; 1: rewrite ?nth_rcons ?size_rcons => ltsz1_j.
      + rewrite -eqszskrsnt -eqszsklfsnt.
        case (j < size skWOTSnt{2}) => [/#| ?].
        rewrite (: j = size skWOTSnt{2}) 1:/# /= ndsnth 2:expr_gt0 2,3://; 1: smt(ge1_hp).
        by rewrite (: h' - (h' - 1) - 1 = 0) 1:/# int2bs0s rev_nil subbt_empty oget_some.
      rewrite andbA; split; 1: smt(size_ge0 nth_rcons size_rcons).
      rewrite sztsp size_rcons mulrDl /= addrA.
      congr; rewrite (: size nds = h') 1:/# /nr_nodes /=.
      have: 1 <= h' by smt(ge1_hp).
      case (0 <= h') => [ |/#]; elim: h' => [/#| i ge0_i].
      case (i = 0) => [-> /= | neq0_i]; 1: by rewrite rangeS big_seq1 /= expr0 expr1.
      rewrite {1}big_seq => ih ge1_i1; have ge1_i: 1 <= i by smt().
      rewrite big_int_recr 1:/# /= expr0 big_seq /=.
      rewrite (eq_bigr _ _ (fun h'' => 2 ^ (i - h'') * 2)).
      + move=> j /mem_range rng_j /=.
        by rewrite addrAC exprD_nneg 1:/# 1:// expr1.
      by rewrite -mulr_suml ih 1:// mulrDl exprD_nneg 1,2:// expr1.
    wp; skip => /> &2 lfsszs rsdef tsdef tsnth alltrhts allntrhtws uqunz1ts szts
                      eqszskpktd eqszsklfstd eqszsksigtd eqszskrtstd _ ltd_szskw.
    split=> [| tws ts lfsnt pkwnt rsnt sigwnt skwnt /lezNgt gent_szskwnt _].
    * by split; smt(expr_ge0).
    move=> lfsntszs rsntnth tspdef tspnth tspnth1 alltrhtsp allntrhtwsp uqun1ts sztsp eqszpkskwnt eqszskwlfsnt eqszsksigwnt eqszskwrsnt lent_szskwnt.
    rewrite !andbA -4!andbA; split; 2: by rewrite ?size_rcons /#.
    split; last first.
    * by rewrite sztsp size_rcons big_int_recr 1:size_ge0 //= /#.
    split => [| i j u]; last first.
    * rewrite size_rcons ?nth_rcons => *.
      case (i < size R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}) => [/#| ?].
      rewrite (: i = size R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}) 1:/# /=.
      by rewrite -eqszsklfstd tspnth1 1:/#.
    split => [ | adx].
    * split => i j; rewrite size_rcons ?nth_rcons -eqszsklfstd => ge0_i ltsz1i ge0_j ltnt_j.
      + case (i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) => [/#| ?].
        rewrite (: i = size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) 1:/# /=.
        by rewrite lfsntszs 1:/#.
      case (i < size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) => [/#| ?].
      rewrite (: i = size R_SMDTTCRCTRH_EUFNAGCMA.skWOTStd{2}) 1:/# /=.
      by rewrite -eqszskrtstd /= rsntnth 1:/#.
    by split => [/tspdef | i j u]; smt(size_ge0 nth_rcons size_rcons).
  wp; skip => /> &2 allntrhtws.
  split => [| *]; 1: rewrite big_geq 1://; 1: smt(ge1_d).
  by split => /#.
swap{1} [1..2] 2.
sp 0 1.
seq 2 2 : (#pre /\ ={sigl}); 1: by conseq />; sim.
inline{2} 25; inline{2} 24; inline{2} 23; inline{2} 22; inline{2} 21.
swap{1} [15..16] 1.
wp 15 22 => /=.
conseq (:   is_fresh{1}
         /\ EUF_NAGCMA_FLSLXMSSMTTWESNPRF_C.valid_TCRTRH{1}
         =>
            0 <= i{2} < bigi predT nr_trees 0 d * (2 ^ h' - 1)
         /\ 0 <= size TRHC_TCR.O_SMDTTCR_Default.ts{2} <= bigi predT nr_trees 0 d * (2 ^ h' - 1)
         /\ x'{2} <> x{2} /\ trh pp{2} tw{2} x{2} = trh pp{2} tw{2} x'{2}).
+ move=> /> &2; rewrite (: d <> 0) 2:/=; 1: smt(ge1_d).
  move=> allntrhtws lfsnth rsnth tsdef tsnth alltrhts uqunz1ts szts vTCR idx isf lfs lfs' m pkw pkw' rs rs' i tw x x' + eqnthrs isfT ? ? vTCRT.
  rewrite isfT vTCRT szts /= => -[[-> ->] [-> [neqxxp ->]]].
  rewrite eq_sym neqxxp /= hasPn => ad /mapP [adx /= [+ ->]].
  rewrite implybE -negb_and -negP => -[adin adxin].
  by move: allntrhtws => /allP /(_ adx.`1 adxin) /=; smt(allP).
wp => /=.
while (   ={ps, m', sig', idx', leavess, rootss, leavess', rootss', tkpidxs, tidx, kpidx, root'}
       /\ ad{1} = R_SMDTTCRCTRH_EUFNAGCMA.ad{2}
       /\ leavestd{1} = R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2}
       /\ rootstd{1} = R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2}
       /\ 0 <= tidx{2}
       /\ (size leavess'{2} < d =>
             tidx{2} < nr_trees (size leavess'{2}) * l')
       /\ (size leavess'{2} < d =>
              tidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (size leavess'{2})).`1 /\
              kpidx{2} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (size leavess'{2})).`2)
       /\ (forall (i : int), 0 <= i < size leavess'{2} =>
             nth witness leavess{2} i
             =
             nth witness (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} i) (nth witness tkpidxs{2} i).`1) (nth witness tkpidxs{2} i).`2)
       /\ (forall (i : int), 0 <= i < size leavess'{2} =>
             nth witness rootss{2} i
             =
             nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.rootstd{2} i) (nth witness tkpidxs{2} i).`1)
       /\ (forall (i : int), 0 <= i < size leavess'{2} =>
             nth witness rootss'{2} i
             =
             val_ap_trh ps{2} (set_typeidx (set_ltidx  R_SMDTTCRCTRH_EUFNAGCMA.ad{2} i (nth witness tkpidxs{2} i).`1) trhtype) (nth witness (val sig'{2}) i).`2 (nth witness tkpidxs{2} i).`2 (nth witness leavess'{2} i))
       /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
             (nth witness tkpidxs{2} i).`1 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (i + 1)).`1 /\
             (nth witness tkpidxs{2} i).`2 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx'{2}, 0) (i + 1)).`2)
       /\ (forall (i : int), 0 <= i < size tkpidxs{2} =>
             0 <= (nth witness tkpidxs{2} i).`1 < nr_trees i /\
             0 <= (nth witness tkpidxs{2} i).`2 < l')
       /\ size pkWOTSs'{1} = size leavess'{2}
       /\ size leavess'{2} = size leavess{2}
       /\ size leavess'{2} = size rootss{2}
       /\ size leavess'{2} = size rootss'{2}
       /\ size leavess'{2} = size tkpidxs{2}
       /\ size leavess'{2} <= d).
+ wp => /=.
  call (: true); 1: by sim.
  wp; skip => /> &1 &2 ge0_ti ltnt_ti tkpicdef lfsrel rsrel lfspdef tkpidef tkpirng eqszlfsppkwp
                       eqszlfsplfs eqszlfsprs eqszlfsprsp eqszlfsptkpi _ ltd_szpkwp ltd_szlfsp.
  rewrite eqszlfsppkwp /= => pkwc.
  rewrite ?nth_rcons ?size_rcons -!andbA.
  split; 1: by rewrite divz_ge0; smt(ge2_lp).
  split => [ltd_szpk1 |].
  + rewrite ltz_divLR; 1: smt(ge2_lp).
    move: (ltnt_ti _); 1: smt().
    rewrite /nr_nodes_ht /nr_trees /nr_nodes /l'.
    by rewrite /= -?exprD_nneg ?addr_ge0 ?mulr_ge0 ?ge1_hp; smt(ge1_hp).
  split => [ltd_szpk1 |]; 1: by rewrite foldS 1:// /= /#.
  split => [j ge0_j ltsz1_j |].
  + rewrite ?nth_rcons -eqszlfsplfs -eqszlfsptkpi.
    by case (j < size leavess'{2}) => /#.
  split => [j ge0_j ltsz1_j |].
  + rewrite ?nth_rcons -eqszlfsprs -eqszlfsptkpi.
    by case (j < size leavess'{2}) => /#.
  split => [j ge0_j ltsz1_j |].
  + rewrite ?nth_rcons -eqszlfsprsp -eqszlfsptkpi.
    by case (j < size leavess'{2}) => /#.
  split => [j ge0_j ltsz1_j |]; rewrite ?nth_rcons -eqszlfsptkpi.
  + case (j < size leavess'{2}) => [/# | nltszpkj].
    by rewrite (: j = size leavess'{2}) 1:/# /= foldS 1:// /= /#.
  split => [j ge0_j ltsz1_j |]; 2: smt(size_rcons).
  rewrite ?nth_rcons -eqszlfsptkpi.
  case (j < size leavess'{2}) => [/# | nltszpkj].
  rewrite (: j = size leavess'{2}) 1:/# /= divz_ge0 2:modz_ge0 3:ltz_pmod 4:/=; 1..3: smt(ge2_lp).
  by rewrite ge0_ti /= ltz_divLR; smt(ge2_lp).
wp => /=.
call (: true).
wp; skip => /> &2 allntrhtws lfsszs rsdef tsdef tsnth alltrhts uqunz1ts szts msigidx.
split => [| pkws lfs lfs' rs rs' ti tkpi /lezNgt ged_szpkw /lezNgt ged_szlfs ge0ti].
* rewrite andbA; split; 2: smt(ge1_d fold0).
  split => [| gt0_d]; 1: smt(Index.valP).
  move: (Index.valP (msigidx.`3)) => [_ @/l @/h @/l'].
  by rewrite -exprD_nneg ?mulr_ge0; smt(ge1_hp).
move=> lfsrel rsrel rspdef tkpidef tkpirng eqszpkwslfsp eqszlfsp eqszlfsprs eqszlfsprsp eqszlfsptkpi led_szlfsp neqm i ge0_i ltd_i.
rewrite (: i + 1 <> 0) 1:/# /= => eqirs neqilfs.
pose zs := zip _ _; pose cidx := find _ _.
have hascidx :
  has (fun (x : ((dgstblock * dgstblock) * dgstblock) * dgstblock) =>
                x.`1.`1.`1 = x.`1.`1.`2 /\ x.`1.`2 <> x.`2) zs.
* rewrite -(has_nthP _ _ (((witness, witness), witness), witness)) /=.
  exists i; rewrite -(: d = size zs) 1:/zs 1:?size_zip /= 1:/#.
  split => [/#|].
  rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
  by rewrite (: i < size rs') 1:/#.
have ge0_cidx : 0 <= cidx by rewrite find_ge0.
have ltd_cidx : cidx < d.
* by rewrite /cidx (: d = size zs) 1:/zs 1:?size_zip /= 1:/# -has_find.
move /(nth_find (((witness, witness), witness), witness)): (hascidx) => /= @-/cidx.
rewrite /zs ?nth_zip_cond ?size_zip ?lez_minl 1..7:/#.
rewrite (: cidx < size rs') 1:/# /= => -[eqrs neqlfs].
move: (ecbtapP (trhi O_THFC_Default.pp{2} (set_typeidx (set_ltidx adz cidx (nth witness tkpi cidx).`1) trhtype))
               updhbidx
               (list2tree (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} cidx) (nth witness tkpi cidx).`1))
               (val (nth witness (val msigidx.`2) cidx).`2)
               (rev (int2bs h' (nth witness tkpi cidx).`2))
               (nth witness lfs' cidx)
               (nth witness lfs cidx)
               (h', 0)).
move: (ecbtap_vals (trhi O_THFC_Default.pp{2} (set_typeidx (set_ltidx adz cidx (nth witness tkpi cidx).`1) trhtype))
                   updhbidx
                   (list2tree (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} cidx) (nth witness tkpi cidx).`1))
                   (val (nth witness (val msigidx.`2) cidx).`2)
                   (rev (int2bs h' (nth witness tkpi cidx).`2))
                   (nth witness lfs' cidx)
                   (nth witness lfs cidx)
                   (h', 0)).
move: (ecbtabp_props (trhi O_THFC_Default.pp{2} (set_typeidx (set_ltidx adz cidx (nth witness tkpi cidx).`1) trhtype))
                     updhbidx
                     (list2tree (nth witness (nth witness R_SMDTTCRCTRH_EUFNAGCMA.leavestd{2} cidx) (nth witness tkpi cidx).`1))
                     (val (nth witness (val msigidx.`2) cidx).`2)
                     (rev (int2bs h' (nth witness tkpi cidx).`2))
                     (nth witness lfs' cidx)
                     (nth witness lfs cidx)
                     (h', 0)).
rewrite (list2tree_fullybalanced _ h') 3:/=; 1: smt(ge1_hp).
+ by rewrite lfsszs 1:// 1:/#.
rewrite ?valP size_rev size_int2bs -(: h' = max 0 h') 2:/=; 1: smt(ge1_hp).
rewrite (list2tree_height _ h') 2:lfsszs 2,4:// 3:/=; 1,2: smt(ge1_hp).
rewrite neqlfs /=; move: eqrs; rewrite rsrel 2:rspdef 3:rsdef 1..4:/#.
rewrite /val_ap_trh /val_ap_trh_gen /val_bt_trh => -> /=.
rewrite list2tree_lvb; 1..3: smt(ge1_hp).
rewrite (onth_nth witness) 2:lfsrel 1,2:/# /=.
rewrite /extract_coll_bt_ap_trh; pose ec := extract_collision_bt_ap _ _ _ _ _ _ _.
case: ec => /= [x1 x1' x2 x2' hbidx l r bs].
move=> [#] eqhlr eqszhl lthphl lthpszbs.
move=> [#] x1val x1pval x2val x2pval.
rewrite take_rev_int2bs; 1: smt(size_ge0).
rewrite foldlupdhbidx size_int2bs lez_maxr 1:/#.
rewrite (: h' - (h' - size bs - 1) =  size bs + 1) 1:/# /=.
move=> hbidxval lval rval bsval.
move => [#] neqin eqout.
rewrite size_ge0 szts /=.
split; 1: rewrite hbidxval /=; 1: split => [| _].
+ rewrite ?addr_ge0 ?mulr_ge0 1,5:sumr_ge0 3,4:/# 4:bs2int_ge0 => [* | | *]; 1,3: by rewrite expr_ge0.
  by rewrite ler_subr_addr; smt(IntOrder.expr_gt0).
+ rewrite -(addr0 (bigi predT nr_trees 0 d * _)).
  rewrite {3}(: 0 = 0 * (2 ^ h - 1) + bigi predT nr_nodes 1 (0 + 1) + 0) 1:big_geq 1,2://.
  rewrite ?addrA (ltbignn_i _ _ _ 0) 1,3,4,5,7:// 1:/#.
  rewrite bs2int_ge0 /=; pose i2bs := int2bs _ _.
  rewrite (: nr_nodes (size bs + 1) = 2 ^ (size i2bs)) 2:bs2int_le2Xs.
  by rewrite /nr_nodes /i2bs size_int2bs /#.
pose nthtsc := nth _ _ (_ + _ + _ + _)%Int.
move: (tsnth cidx (nth witness tkpi cidx).`1 (hbidx.`1 - 1) hbidx.`2 _ _ _ _); 1..3: smt(size_ge0).
+ rewrite hbidxval /= bs2int_ge0 /nr_nodes /=; pose i2bs := int2bs _ _.
  by rewrite (: h' - (size bs + 1) = size i2bs) 1:size_int2bs 1:/# bs2int_le2Xs.
pose vb := val_bt_trh_gen _ _ _ _ _; pose vb' := val_bt_trh_gen _ _ _ _ _.
suff: x1 = vb /\ x1' = vb'.
+ move => [<- <-]; rewrite /nthtsc => -> /=.
  move: eqout => @/trhi -> /=.
  rewrite eqseq_cat 1:2!valP 1://.
  move: neqin; rewrite 2!negb_and => neqxor.
  by move: neqxor
           (DigestBlock.val_inj x1 x2)
           (DigestBlock.val_inj x1' x2') => + /contra + /contra /#.
rewrite x1val /vb x1pval /vb' hbidxval /val_bt_trh_gen lval rval /=.
split; congr => [| // | | //]; congr; congr.
+ rewrite -rev_cons -{2}(expr1 2) int2bs_mulr_pow2 1:/#.
  rewrite nseq1 cat1s; pose i2bs := int2bs _ (_ %/ _).
  by rewrite (: h' - size bs - 1 = size i2bs) 1:size_int2bs 1:/# bs2intK.
rewrite (int2bs_cat 1 (h' - size bs)) 1:/# {2}/int2bs mkseq1 /= expr0 divz1.
rewrite -modzDm modzMr /= expr1 divzDl 1:dvdz_mulr 1:dvdzz.
rewrite mulrC divMr 1:dvdzz /= rev_cons; pose i2bs := int2bs _ (_ %/ _).
by rewrite (: h' - size bs - 1 = size i2bs) 1:size_int2bs 1:/# bs2intK.
qed.

(*
  Low-level security theorem
  Success probability (of given adversary) against EUF-NAGCMA of FL-SL-XMSS-MT-TW-ES-NPRF
  bounded by advantages/success probabilities (of reduction adversaries)
  against the properties of the employed THFs.
*)
lemma EUFNAGCMA_FLSLXMSSMTTWESNPRF &m :
  hoare[A(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A, O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).O_THFC).choose :
          R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads = []
          ==>
          all (fun (ad : adrs) => get_typeidx ad <> chtype) R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.O_THFC.ads] =>
  hoare[A(R_SMDTTCRCPKCO_EUFNAGCMA(A, PKCOC_TCR.O_SMDTTCR_Default, PKCOC.O_THFC_Default).O_THFC).choose :
          R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads = []
          ==>
          all (fun (ad : adrs) => get_typeidx ad <> pkcotype) R_SMDTTCRCPKCO_EUFNAGCMA.O_THFC.ads] =>
  hoare[A(R_SMDTTCRCTRH_EUFNAGCMA(A, TRHC_TCR.O_SMDTTCR_Default, TRHC.O_THFC_Default).O_THFC).choose :
          R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads = []
          ==>
          all (fun (ad : adrs) => get_typeidx ad <> trhtype) R_SMDTTCRCTRH_EUFNAGCMA.O_THFC.ads] =>
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(A, O_THFC_Default).main() @ &m : res]
  <=
  (w - 2)%r
    * `|Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A)), FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(false) @ &m : res]
        - Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A)), FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(true) @ &m : res]|
  +
  Pr[FC_TCR.SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A)), FC_TCR.O_SMDTTCR_Default, FC.O_THFC_Default).main() @ &m : res]
  +
  Pr[FC_PRE.SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A)), FC_PRE.O_SMDTPRE_Default, FC.O_THFC_Default).main() @ &m : res]
  +
  Pr[PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_EUFNAGCMA(A), PKCOC_TCR.O_SMDTTCR_Default, PKCOC.O_THFC_Default).main() @ &m : res]
  +
  Pr[TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_EUFNAGCMA(A), TRHC_TCR.O_SMDTTCR_Default, TRHC.O_THFC_Default).main() @ &m : res].
proof.
move=> allnchads allnpkcoads allntrhads.
move: (MEUFGCMA_WOTSTWESNPRF (R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(A)) _ _ &m)
      (EUFNAGCMA_FLSLXMSSMTTWESNPRF_MEUFGCMAWOTSTWES &m allnchads allnpkcoads allntrhads); 3: smt().
+ move=> O OC Oll OCll.
  proc; inline *.
  wp.
  while (true) (d - size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd).
  - move=> z.
    wp.
    while (true)
          (nr_trees (size R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA.pkWOTStd) - size pkWOTSnt).
    * move=> z'.
      wp => /=.
      while (true) (h' - size nodes).
      + move=> z''.
        wp => /=.
        while (true) (nr_nodes (size nodes + 1) - size nodescl).
        - move=> z'''.
          by wp; call OCll; wp; skip => />; smt(size_rcons).
        by wp; skip => />; smt(size_rcons).
      wp => /=.
      while (true) (l' - size pkWOTSlp).
      + move=> z''.
        wp => /=.
        call OCll; call Oll.
        by wp; skip => />; smt(size_rcons).
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  wp; call (: true).
  - by move=> OC' OCpll; apply (A_choose_ll OC' OCpll).
  - proc.
    by wp; call OCll.
  by wp; skip => /> /#.
move => O OC.
proc; inline *.
wp => /=.
while (true) (d - size pkWOTSs').
+ move=> z.
  wp.
  while (true) (len - size pkWOTS0).
  - move=> z'.
    by wp; skip => />; smt(size_rcons).
  by wp; skip => />; smt(size_rcons).
wp.
call (: true).
+ by move=> OC'; apply (A_forge_ll OC').
wp => /=.
while (true) (l - size sigl).
+ move=> z.
  wp.
  while (true) (d - size sapl).
  - move=> z'.
    by wp; skip => />; smt(size_rcons).
  by wp; skip => />; smt(size_rcons).
by wp; skip => /> /#.
qed.

end section Proof_EUF_NAGCMA_FL_SL_XMSS_MT_ES_NPRF.
