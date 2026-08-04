(* - Require/Import - *)
(* -- Built-In (Standard Library) -- *)
require import AllCore List Distr FMap IntDiv RealExp StdOrder FinType BitEncoding.
require (*--*) DigitalSignatures.
(*---*) import IntOrder RealOrder.
(*---*) import BS2Int.


(* -- Local -- *)
require import BinaryTrees MerkleTrees.
require (*--*) KeyedHashFunctions TweakableHashFunctions HashAddresses.
require (*--*) FORS_ES FL_SL_XMSS_MT_ES.



(* - Parameters - *)
(* -- General -- *)
(* Length of (integer list corresponding to) addresses used in tweakable hash functions *)
const adrs_len = 6.

(* 
  Length (in bytes) of messages as well as the length of elements of 
  private keys, public keys, and signatures
*)
(* ==========================================================================
   SPECIALISED TO THE DEPLOYED C10 PARAMETER SET (2026-08-01).

   Each parameter was `const x : { int | P x } as ax` -- an ABSTRACT constant
   carrying an AXIOM `ax`.  It is now an abstract constant carrying a VALUE
   axiom instead, with the old bound `ax` DERIVED as a lemma.  So the axiom
   count is UNCHANGED (one traded for one per parameter) while the whole
   development below is now about C10's actual geometry.

   The constants are left OPAQUE (declaration + value axiom) rather than written
   as transparent definitions (`op n = 16`) DELIBERATELY: a transparent value
   makes size side-conditions auto-discharge, which silently shifts goal counts
   and breaks index-based proof scripts throughout MM45's heavily-tuned proofs.
   Opaque + `*_val` gives the identical specialisation with zero perturbation,
   and any proof that needs the number can `rewrite n_val`.
   ========================================================================== *)

(* DEPLOYED: params.rs:19  N = 16 *)
op n : int.
axiom n_val : n = 16.
lemma ge1_n : 1 <= n.
proof. by rewrite n_val. qed.


(* -- FORS-TW -- *)
(* Number of trees in a FORS-TW instance *)
(* DEPLOYED: params.rs:34  K = 13 *)
op k : int.
axiom k_val : k = 13.
lemma ge1_k : 1 <= k.
proof. by rewrite k_val. qed.

(* Height of each FORS-TW tree *)
(* DEPLOYED: C10 a = 11 (t = 2^a = 2048) *)
op a : int.
axiom a_val : a = 11.
lemma ge1_a : 1 <= a.
proof. by rewrite a_val. qed.

(* Number of leaves of each FORS-TW tree *)
const t : int = 2 ^ a.


(* -- WOTS-TW -- *)
(* Base 2 logarithm of the Winternitz parameter w *)
(* F1 EXPERIMENT: mirrors the relaxation in WOTS_TW_ES.ec *)
(* DEPLOYED: params.rs:46  LOG_W = 3 (w = 8) *)
op log2_w : int.
axiom log2_w_val : log2_w = 3.
lemma val_log2w : 2 <= log2_w.
proof. by rewrite log2_w_val. qed.

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
   supplies `ge2_len` (used widely chain-wide; the previous "160x" was an
   unsupported count -- flagged by review, no convention yields it) and dissolves the
   whole checksum chain -- INCLUDING the false `val_len1`. *)
(* DEPLOYED: params.rs:49  L = 43 *)
op len : int.
axiom len_val : len = 43.
lemma ge2_len : 2 <= len.
proof. by rewrite len_val. qed.


(* -- FL-XMSS(-MT)-TW -- *)
(* Height of a single inner tree *)
(* DEPLOYED: C10 h = 18, d = 2 => h' = 9 *)
op h' : int.
axiom hp_val : h' = 9.
lemma ge1_hp : 1 <= h'.
proof. by rewrite hp_val. qed. 

(* Number of WOTS-TW/FORS-TW instances of a single inner tree (i.e., number of leaves) *)
const l' = 2 ^ h'.

(* Number of layers in the hypertree (i.e., height of tree of trees) *)
(* DEPLOYED: C10 d = 2 *)
op d : int.
axiom d_val : d = 2.
lemma ge1_d : 1 <= d.
proof. by rewrite d_val. qed.

(* 
  Height of "flattened" hypertree 
  (i.e., total height of concatenation of inner trees) 
*)
const h : int = h' * d.

(* 
  Number of leaves of "flattened" hypertree
  (i.e., total number of leaves of all inner trees on bottom layer).
  Also, number of FORS-TW instances.
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

(* 
  Address type for tree hashing in the hypertree 
  (used in tweakable hash function calls of inner trees) 
*)
const trhxtype : int.

(* 
  Address type for tree hashing in FORS-TW trees
  (used in tweakable hash function calls of FORS-TW trees)
*)
const trhftype : int.

(* 
  Address type for (FORS-TW) tree root compression
  (used in tweakable hash function calls of FORS-TW tree root compression)
*)
const trcotype : int.


(* -- Properties of parameters -- *)
(* The different address types are distinct *)
axiom dist_adrstypes : uniq [chtype; pkcotype; trhxtype; trhftype; trcotype].

(* l' is greater than or equal to 2 *)
lemma ge2_lp : 2 <= l'.
proof. by rewrite /l IntOrder.ler_eexpr 1:ltzE /= 1:ge1_hp. qed.

(* h is greater than or equal to 1 *)
lemma ge1_h : 1 <= h.
proof. by rewrite /h IntOrder.mulr_ege1 1:ge1_hp ge1_d. qed.

(* l is greater than or equal to 2 *)
lemma ge2_l : 2 <= l.
proof. by rewrite /l IntOrder.ler_eexpr 1:ltzE /= 1:ge1_h. qed.

(* Number of leaves of a FORS-TW tree is greater than or equal to 2 *)
lemma ge2_t : 2 <= t.
proof. by rewrite /t -{1}expr1 ler_weexpn2l 2:ge1_a. qed. 



(* - Types - *)
(* -- General -- *)
(* Index *)
clone import Subtype as Index with
  type T <= int,
    op P i <= 0 <= i < l
    
  proof *.
  realize inhabited by exists 0; smt(ge2_l).

type index = Index.sT.

(* Seeds for message compression key generation function *)
type mseed.

(* Keys for message compression *) 
type mkey.

(* Secret seeds *)
type sseed.

(* Public seeds *)
type pseed.

(* Messages *)
type msg.

(* 
  Digests, i.e., outputs of (tweakable) hash functions.
  In fact, also input of (tweakable) hash functions in this case.
*)
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
    rewrite mem_range bs2int_ge0 /= (: 8 * n = size (DigestBlock.val m)) 1:DigestBlock.valP //. 
    by rewrite bs2intK bs2int_le2Xs.
  qed.


  
(* - Operators - *)
(* -- Auxiliary -- *)
(* Number of nodes in a XMSS binary tree (of total height h') at a particular height h'' *)
op nr_nodesx (h'' : int) = 2 ^ (h' - h'').

(* Number of nodes in a FORS binary tree (of total height a) at a particular height a' *)
op nr_nodesf (a' : int) = 2 ^ (a - a').

(* 
  Number of trees in hypertree (with d layers) at a particular layer d'.
  Note that each "node" (i.e., inner tree) of the hypertree creates 2 ^ h' children, not 2.
  Furthermore, note that the number of layers is always one more than the height.
  This is because the number of layers increases with each level containing nodes, while 
  height increases with each edge between layers. 
  (So, in a sense, the final layer does contribute to the number of layers but 
  does not contribute to the height)
*)
op nr_trees (d' : int) = 2 ^ (h' * (d - d' - 1)).


(* -- Validity checks for (indices corresponding to) SPHINCS+ addresses -- *)
(* Layer index validity check (note: regards hypertree) *)
op valid_lidx (lidx : int) : bool = 
  0 <= lidx < d.

(* 
  Tree index validity check
  (note: regards hypertree, i.e., checks whethers tidx is
   a valid index for pointing to a tree in layer lidx) 
*)
op valid_tidx (lidx tidx : int) : bool = 
  0 <= tidx < nr_trees lidx.

(* Key pair index validity check (note: regards inner tree) *)
op valid_kpidx (kpidx : int) : bool =
  0 <= kpidx < l'.

(* Tree height index validity check (note: regards inner tree) *)
op valid_thxidx (thxidx : int) : bool = 
  0 <= thxidx <= h'.
  
(* Tree breadth index validity check (note: regards inner tree) *)
op valid_tbxidx (thxidx tbxidx : int) : bool = 
  0 <= tbxidx < nr_nodesx thxidx.

(* Tree height index validity check (note: regards FORS-TW tree) *)
op valid_thfidx (thfidx : int) : bool = 
  0 <= thfidx <= a.
  
(* Tree breadth index validity check (note: regards FORS-TW tree) *)
op valid_tbfidx (thfidx tbfidx : int) : bool = 
  0 <= tbfidx < k * nr_nodesf thfidx.

(* Chain index validity check *)
op valid_chidx (chidx : int) : bool =
  0 <= chidx < len.

(* Hash index validity check *)
op valid_hidx (hidx : int) : bool = 
  0 <= hidx < w - 1.

(* Chaining address indices validity check *) 
op valid_idxvalsch (adidxs : int list) : bool =
     valid_hidx (nth witness adidxs 0) 
  /\ valid_chidx (nth witness adidxs 1)
  /\ valid_kpidx (nth witness adidxs 2)
  /\ nth witness adidxs 3 = chtype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ valid_lidx (nth witness adidxs 5).

(* Public-key compression address indices value validity check *)  
op valid_idxvalspkco (adidxs : int list) : bool =
     nth witness adidxs 0 = 0 
  /\ nth witness adidxs 1 = 0
  /\ valid_kpidx (nth witness adidxs 2)
  /\ nth witness adidxs 3 = pkcotype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ valid_lidx (nth witness adidxs 5).

(* Hypertree hashing address indices value validity check *)  
op valid_idxvalstrhx (adidxs : int list) : bool =
     valid_tbxidx (nth witness adidxs 1) (nth witness adidxs 0)
  /\ valid_thxidx (nth witness adidxs 1)
  /\ nth witness adidxs 2 = 0
  /\ nth witness adidxs 3 = trhxtype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ valid_lidx (nth witness adidxs 5).

(* FORS-TW tree hashing address indices value validity check *)  
op valid_idxvalstrhf (adidxs : int list) : bool =
     valid_tbfidx (nth witness adidxs 1) (nth witness adidxs 0)
  /\ valid_thfidx (nth witness adidxs 1)
  /\ valid_kpidx (nth witness adidxs 2)
  /\ nth witness adidxs 3 = trhftype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ nth witness adidxs 5 = 0.

(* FORS-TW root compression address indices value validity check *)  
op valid_idxvalstrco (adidxs : int list) : bool =
     nth witness adidxs 0 = 0
  /\ nth witness adidxs 1 = 0
  /\ valid_kpidx (nth witness adidxs 2)
  /\ nth witness adidxs 3 = trcotype
  /\ valid_tidx (nth witness adidxs 5) (nth witness adidxs 4)
  /\ nth witness adidxs 5 = 0.

(* Overall address indices value validity check *)
op valid_idxvals (adidxs : int list) : bool =
  valid_idxvalsch adidxs \/ valid_idxvalspkco adidxs \/ valid_idxvalstrhx adidxs \/
  valid_idxvalstrhf adidxs \/ valid_idxvalstrco adidxs.

(* Overall address indices validity check *)
op valid_adrsidxs (adidxs : int list) : bool =
  size adidxs = adrs_len /\ valid_idxvals adidxs.



(* - Distributions - *)  
(* Proper distribution over seeds for message compression key generation function *)
op [lossless] dmseed : mseed distr.

(* Proper distribution over randomness for message compression *)
op [lossless] dmkey : mkey distr.

(* Proper distribution over public seeds *)
op [lossless] dpseed : pseed distr.

(* Proper distribution over secret seeds *)
op [lossless] dsseed : sseed distr.

(* Proper distribution over digests of length 1 (block of 8 * n bits) *)
op [lossless] ddgstblock : dgstblock distr.



(* - Types (2/3) - *)
(* Addresses *)
clone import HashAddresses as HA with
  type index <= int,
    op l <- adrs_len,
    op valid_idxvals <- valid_idxvals,
    op valid_adrsidxs <- valid_adrsidxs
    
  proof *. 
  realize ge1_l by trivial.
  realize Adrs.inhabited. 
    exists [0; 0; 0; pkcotype; 0; 0].
    rewrite /valid_adrsidxs /= /adrs_len /= /valid_idxvals. right; left.
    rewrite /valid_idxvalspkco /= /valid_kpidx /valid_tidx /valid_lidx /nr_trees.
    by rewrite ?expr_gt0 //; smt(ge1_d).
  qed.
  
import Adrs.

type adrs = HA.adrs.

(* Initialization ("zero") address *)
const adz : adrs = insubd [0; 0; 0; chtype; 0; 0].



(* - Operators (2/2) - *)
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

            
(* -- Keyed hash functions -- *)
(* Secret key element generation function *)
op skg : sseed -> (pseed * adrs) -> dgstblock.

clone KeyedHashFunctions as SKG with
  type key_t <- sseed,
  type in_t <- pseed * adrs,
  type out_t <- dgstblock,
  
    op f <- skg
    
  proof *.

clone import SKG.PRF as SKG_PRF with
  op dkey <- dsseed,
  op doutm d <- ddgstblock
  
  proof *.
  realize dkey_ll by exact: dsseed_ll.
  realize doutm_ll by move => d; apply ddgstblock_ll. 

op mkg : mseed -> msg -> mkey.

clone KeyedHashFunctions as MKG with
  type key_t <- mseed,
  type in_t <- msg,
  type out_t <- mkey,
  
    op f <- mkg
    
  proof *.

clone import MKG.PRF as MKG_PRF with
    op dkey <- dmseed,
    op doutm x <- dmkey 
  
  proof *.
  realize dkey_ll by exact: dmseed_ll.
  realize doutm_ll by move=> ?; apply dmkey_ll.


(* -- Tweakable Hash Functions -- *)
(* 
  Tweakable hash function collection that contains all tweakable hash functions
  used in SPHINCS+ 
*)
op thfc : int -> pseed -> adrs -> dgst -> dgstblock.

(* 
  Tweakable hash function used for chaining (in WOTS-TW) and for
  producing leaves from secret key values (in FORS-TW).
*)
op f : pseed -> adrs -> dgst -> dgstblock = thfc (8 * n).

(* Tweakable hash function used to construct Merkle trees from leaves *)
op trh : pseed -> adrs -> dgst -> dgstblock = thfc (8 * n * 2).

(* Tweakable hash function used to compress WOTS public keys *)
op pkco : pseed -> adrs -> dgst -> dgstblock = thfc (8 * n * len).

(* Tweakable hash function used to compress FORS-TW tree roots *)
op trco : pseed -> adrs -> dgst -> dgstblock = thfc (8 * n * k).



(* - Underlying schemes - *)
(* -- FORS-TW -- *)
clone import FORS_ES as FTWES with
    op adrs_len <- adrs_len,
    op n <- n,
    op k <- k,
    op a <- a,
    op t <- t,
    op l <- l',
    op s <- nr_trees 0,
    op d <- l,
    op adz <- insubd [0; 0; 0; trhftype; 0; 0],
    
  type mseed <- mseed,
  type mkey <- mkey,
  type sseed <- sseed,
  type pseed <- pseed,
  type msg <- msg,
  type dgst <- dgst,
    
    op nr_nodes <- nr_nodesf,
    op trhtype <- trhftype,
    op trcotype <- trcotype,

    op valid_tidx <- valid_tidx 0,
    op valid_kpidx <- valid_kpidx,
    op valid_thidx <- valid_thfidx,
    op valid_tbidx <- valid_tbfidx,
    op valid_idxvals <- valid_idxvals,
    op valid_adrsidxs <- valid_adrsidxs,
    op valid_fidxvalsgp adidxs <- nth witness adidxs 0 = 0,
  
    op set_tidx <- set_tidx,
    op set_typeidx <- set_typeidx,
    op set_kpidx <- set_kpidx,
    op set_thtbidx <- set_thtbidx,
    
    op get_typeidx <- get_typeidx,
    
    op skg <- skg,
    op mkg <- mkg,
    
    op thfc <- thfc,
    op f <- f,
    op trh <- trh,
    op trco <- trco,
    
    op dmseed <- dmseed,
    op dmkey <- dmkey,  
    op dpseed <- dpseed,
    op ddgstblock <- ddgstblock,
  
  theory DigestBlock <- DigestBlock,
  theory DigestBlockFT <- DigestBlockFT,
  theory Index <- Index,
  theory HA <- HA,
  
  type dgstblock <- dgstblock,
  type index <- index,
  type adrs <- adrs

  proof ge5_adrslen, ge1_n, ge1_k, ge1_a, ge1_l, ge1_s, dval, dist_adrstypes, 
        valid_fidxvals_idxvals, dmseed_ll, dmkey_ll, dpseed_ll, ddgstblock_ll,
        valf_adz.
  realize ge5_adrslen by trivial.
  realize ge1_n by exact: ge1_n.
  realize ge1_k by exact ge1_k.
  realize ge1_a by exact: ge1_a.
  realize ge1_l by smt(ge2_lp).
  realize ge1_s by rewrite /nr_trees -add0r -ltzE expr_gt0.
  realize dval. 
    rewrite /nr_trees /l' /l /h -exprD_nneg /= 1:mulr_ge0; 1..3: smt(ge1_d ge1_hp).
    by congr; ring.
  qed.
  realize dist_adrstypes by smt(dist_adrstypes).
  realize valid_fidxvals_idxvals.
    rewrite /(<=) => ls @/valid_fidxvals @/valid_idxvals @/valid_fidxvalslp.
    by rewrite /valid_fidxvalslptrh /valid_fidxvalslptrco ?nth_drop ?nth_take //= /#.
  qed.
  realize dmseed_ll by exact: dmseed_ll.
  realize dmkey_ll by exact: dmkey_ll.
  realize dpseed_ll by exact: dpseed_ll.
  realize ddgstblock_ll by exact: ddgstblock_ll.
  realize valf_adz.
    rewrite /valid_fadrs /valid_fadrsidxs /valid_fidxvals /valid_fidxvalslp.
    rewrite /valid_fidxvalslptrh ?nth_take // ?nth_drop //.
    by rewrite insubdK; smt(ge1_k ge1_a ge2_lp IntOrder.expr_gt0).
  qed.
   
import DBAL BLKAL DBAPKL DBLLKTL FP_OPRETCRDSPR.


(* -- FL-SL-XMSS-MT-TW -- *)
clone import FL_SL_XMSS_MT_ES as FSSLXMTWES with
    op adrs_len <- adrs_len,
    op n <- n,
    op log2_w <- log2_w,
    op w <- w,
    (* len1/len2 clone bindings dropped: +C has no checksum *)
    op len <- len,
    op h' <- h',
    op l' <- l',
    op d <- d,
    op l <- l,
    op adz <- adz,
    
  type sseed <- sseed,
  type pseed <- pseed,
  type dgst <- dgst,
    
    op nr_nodes <- nr_nodesx,
    op nr_trees <- nr_trees,
    op chtype <- chtype,
    op trhtype <- trhxtype,
    op pkcotype <- pkcotype,

    op valid_lidx <- valid_lidx,
    op valid_tidx <- valid_tidx,
    op valid_kpidx <- valid_kpidx,
    op valid_thidx <- valid_thxidx,
    op valid_tbidx <- valid_tbxidx,
    op valid_chidx <- valid_chidx,
    op valid_hidx <- valid_hidx,
    
    op valid_idxvals <- valid_idxvals,
    op valid_adrsidxs <- valid_adrsidxs,
    op valid_xidxvalsgp <- predT,
    
    op set_lidx <- set_lidx,
    op set_tidx <- set_tidx,
    op set_ltidx <- set_ltidx,
    op set_typeidx <- set_typeidx,
    op set_kpidx <- set_kpidx,
    op set_thtbidx <- set_thtbidx,
    
    op get_typeidx <- get_typeidx,
    
    op thfc <- thfc,
    op trh <- trh,
    op pkco <- pkco,
    op WTWES.f <- f,
    op WTWES.skg <- skg,
    
    op dpseed <- dpseed,
    op ddgstblock <- ddgstblock,
  
  theory DigestBlock <- DigestBlock,
  theory DigestBlockFT <- DigestBlockFT,
  theory Index <- Index,
  theory HA <- HA,
  
  type dgstblock <- dgstblock,
  type index <- index,
  type adrs <- adrs
  
  proof ge6_adrslen, ge1_n, val_log2w, ge1_hp, ge1_d, dist_adrstypes, 
        valid_xidxvals_idxvals, dpseed_ll, ddgstblock_ll, WTWES.WAddress.inhabited,
        valx_adz.
  realize ge6_adrslen by trivial.
  realize ge1_n by exact: ge1_n.
  realize val_log2w by exact: val_log2w.
  realize ge1_hp by exact: ge1_hp.
  realize ge1_d by exact: Top.ge1_d.
  realize dist_adrstypes by smt(Top.dist_adrstypes).
  realize valid_xidxvals_idxvals.
    move => ls @/valid_xidxvals @/valid_xidxvalslp @/predT /=.
    rewrite /valid_xidxvalslpch /valid_xidxvalslppkco /valid_xidxvalslptrh.
    by rewrite ?nth_take //= /#.
  qed.
  realize dpseed_ll by exact: dpseed_ll.
  realize ddgstblock_ll by exact: ddgstblock_ll.
  realize WTWES.WAddress.inhabited.
    exists adz.
    rewrite /valid_wadrs insubdK 1:/valid_adrsidxs /adrs_len /= /valid_idxvals.
    + left; rewrite /valid_idxvalsch /= /valid_kpidx /l' /valid_tidx /nr_trees.
      by rewrite ?expr_gt0 //=; smt(val_w ge2_len Top.ge1_d).
    rewrite /valid_wadrsidxs /adrs_len /= /valid_widxvals /predT /=.
    rewrite /valid_kpidx /valid_tidx /l' ?expr_gt0 //=. 
    by rewrite /valid_widxvalslp; smt(val_w ge2_len Top.ge1_d).
  qed.
  realize valx_adz.
    rewrite /valid_xadrs /valid_xadrsidxs.
    move: (Adrs.valP adz) => @/valid_adrsidxs -[-> /= ?] @/valid_xidxvals @/predT /=.
    suff vch: valid_xidxvalslpch [0; 0; 0; chtype; 0; 0]. 
    + rewrite insubdK 2:/# valid_xadrsidxs_adrsidxs valid_xadrsidxs_xadrschpkcotrhidxs.
      by left => @/valid_xadrschidxs @/adrs_len /= @/valid_xidxchvals /#. 
    rewrite /valid_xidxvalslpch /= /valid_hidx /valid_chidx /valid_kpidx /valid_tidx /valid_lidx.
    rewrite ?expr_gt0 //= andbA; split; 2: smt(Top.ge1_d).
    split; 1: by rewrite subz_gt0 exprn_egt1 //; smt(val_log2w). 
    (* +C GEOMETRY: this block proved `0 < len` by unfolding len = len1 + len2 and
       showing each summand positive -- reasoning that only exists because of the
       CHECKSUM.  With `len` an independent parameter carrying `2 <= len`, the
       fact is immediate.  This is the ONLY site in the whole chain where the
       checksum arithmetic was load-bearing in a PROOF rather than a definition. *)
    smt(ge2_len).
  qed.
  
import DBHPL SAPDL.
import WTWES DBLL EmsgWOTS WAddress FC.



(* - Types (3/3) - *)
(* -- SPHINCS+-TW specific -- *)
(* Public keys *)
type pkSPHINCSPLUSTW = dgstblock * pseed.

(* Secret keys *)
type skSPHINCSPLUSTW = mseed * sseed * pseed.

(* Signatures *)
type sigSPHINCSPLUSTW = mkey * sigFORSTW * sigFLSLXMSSMTTW. 



(* - Definitions and security models for digital signatures  - *)
clone import DigitalSignatures as DSS with
  type pk_t <- pkSPHINCSPLUSTW,
  type sk_t <- skSPHINCSPLUSTW,
  type msg_t <- msg,
  type sig_t <- sigSPHINCSPLUSTW
  
  proof *.

import DSS.Stateless.



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

lemma setallchadz_getchidx  (i j u v : int) :
  valid_lidx i => valid_tidx i j => valid_kpidx u => valid_chidx v =>
  get_idx (set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0) 1 = v.
proof.
move=> vali valj valu valv @/adz @/set_ltidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_typeidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_chidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_hidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladzch_getkpidx (i j u v : int) :
  valid_lidx i => valid_tidx i j => valid_kpidx u => valid_chidx v =>
  get_idx (set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0) 2 = u.
proof.
move=> vali valj valu valv @/adz @/set_ltidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_typeidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_chidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_hidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladzch_gettypeidx (i j u v : int) :
  valid_lidx i => valid_tidx i j => valid_kpidx u => valid_chidx v =>
  get_idx (set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0) 3 = chtype.
proof.
move=> vali valj valu valv @/adz @/set_ltidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_typeidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_chidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_hidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladzch_gettidx (i j u v : int) :
  valid_lidx i => valid_tidx i j => valid_kpidx u => valid_chidx v =>
  get_idx (set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0) 4 = j.
proof.
move=> vali valj valu valv @/adz @/set_ltidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_typeidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_chidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_hidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladzch_getlidx (i j u v : int) :
  valid_lidx i => valid_tidx i j => valid_kpidx u => valid_chidx v =>
  get_idx (set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0) 5 = i.
proof.
move=> vali valj valu valv @/adz @/set_ltidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_typeidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_chidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_hidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by left => @/valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladztrhf_getbidx (i j u v : int) :
  valid_tidx 0 i => valid_kpidx j => valid_tbfidx 0 (u * t + v) =>
  get_idx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)) 0 = u * t + v.
proof.
move=> vali valj valuv @/adz @/set_typeidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_tidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_thtbidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladztrhf_getkpidx (i j u v : int) :
  valid_tidx 0 i => valid_kpidx j => valid_tbfidx 0 (u * t + v) =>
  get_idx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)) 2 = j.
proof.
move=> vali valj valuv @/adz @/set_typeidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_tidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_thtbidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladztrhf_gettypeidx (i j u v : int) :
  valid_tidx 0 i => valid_kpidx j => valid_tbfidx 0 (u * t + v) =>
  get_idx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)) 3 = trhftype.
proof. 
move=> vali valj valuv @/adz @/set_typeidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_tidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_thtbidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma setalladztrhf_gettidx (i j u v : int) :
  valid_tidx 0 i => valid_kpidx j => valid_tbfidx 0 (u * t + v) =>
  get_idx (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)) 4 = i.
proof.
move=> vali valj valuv @/adz @/set_typeidx; rewrite insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_tidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_kpidx /set_idx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_thtbidx insubdK.
+ rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
  by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /get_idx insubdK 2://.
rewrite /valid_adrsidxs /adrs_len /= /valid_idxvals.
by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma eq_dbsettype_adztrhf :
  set_typeidx adz trhftype = set_typeidx (insubd [0; 0; 0; trhftype; 0; 0]) trhftype.
proof. 
rewrite /set_typeidx ?insubdK 3:// /valid_adrsidxs /adrs_len /= /valid_idxvals.
+ by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma eq_settype_adztrhfch :
  adz = set_typeidx (insubd [0; 0; 0; trhftype; 0; 0]) chtype.
proof.
rewrite /set_typeidx insubdK 2:// /valid_adrsidxs /adrs_len /= /valid_idxvals.
by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.

lemma eq_setlttype_adztrhf (i j : int) :
  valid_lidx i => valid_tidx i j => 
  set_typeidx (set_ltidx adz i j) trhxtype 
  =
  set_ltidx (set_typeidx (insubd [0; 0; 0; trhftype; 0; 0]) trhxtype) i j.
proof.
move=> vali valj. 
rewrite {1}/set_ltidx insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals.
+ by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_typeidx ?insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals.
+ by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
+ by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /put /= /set_ltidx insubdK 2:// /valid_adrsidxs /adrs_len /= /valid_idxvals.
by right; right; left => @/valid_idxvalstrhx /=; smt(ge1_d ge1_hp ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.
 
lemma getsettrhf_kpidx (ad : adrs) (i j : int) :
     valid_tidx (nth witness (val ad) 5) (nth witness (val ad) 4) 
  => nth witness (val ad) 5 = 0 
  => valid_tidx 0 i 
  => valid_kpidx j 
  => get_kpidx (set_kpidx (set_tidx (set_typeidx ad trhftype) i) j) = j.
proof.
move => valtidx vallidx vali valj.
have eq6_szad : size (val ad) = 6 by smt(Adrs.valP).
rewrite /get_kpidx /set_kpidx valin_getidx_setidx 1:/adrs_len 1,3://. 
rewrite /set_tidx /set_idx /set_typeidx insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals.
+ split; 1: by rewrite ?size_put eq6_szad.
  right; right; right; left => @/valid_idxvalstrhf /=.
  by rewrite ?nth_put ?size_put ?eq6_szad //=; 1: smt(ge1_d ge1_a ge2_t ge1_k Adrs.valP IntOrder.expr_ge0 IntOrder.expr_gt0).
rewrite /valid_setidx insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals.
+ split; 1: by rewrite ?size_put eq6_szad.
  right; right; right; left => @/valid_idxvalstrhf /=.
  by rewrite ?nth_put ?size_put ?eq6_szad //=; 1: smt(ge1_d ge1_a ge2_t ge1_k Adrs.valP IntOrder.expr_ge0 IntOrder.expr_gt0).
split; 1: by rewrite ?size_put eq6_szad.
right; right; right; left => @/valid_idxvalstrhf /=.
by rewrite ?nth_put ?size_put ?eq6_szad //=; 1: smt(ge1_d ge1_a ge2_t ge1_k Adrs.valP IntOrder.expr_ge0 IntOrder.expr_gt0).
qed.



(* - Specification - *)



(* - Proof - *)
(* -- Reduction adversaries -- *)
(* Reduction adversary against the PRF property of skg (i.e., secret key generation function) *)

(* Reduction adversary against the PRF property of mkg (message key generation function) *)

(* Reduction adversary against the EUFCMA property of M-FORS-TW-ES-NPRF *)

(* Reduction adversary against the NAGCMA property of FL-SL-XMSS-MT-TW-ES-NPRF *)


