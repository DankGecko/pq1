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
const n : { int | 1 <= n } as ge1_n.


(* -- FORS-TW -- *)
(* Number of trees in a FORS-TW instance *)
const k : { int | 1 <= k } as ge1_k.

(* Height of each FORS-TW tree *)
const a : { int | 1 <= a } as ge1_a.

(* Number of leaves of each FORS-TW tree *)
const t : int = 2 ^ a.


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


(* -- FL-XMSS(-MT)-TW -- *)
(* Height of a single inner tree *)
const h' : { int | 1 <= h' } as ge1_hp. 

(* Number of WOTS-TW/FORS-TW instances of a single inner tree (i.e., number of leaves) *)
const l' = 2 ^ h'.

(* Number of layers in the hypertree (i.e., height of tree of trees) *)
const d : { int | 1 <= d } as ge1_d.

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
    op len1 <- len1,
    op len2 <- len2,
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
    rewrite /len /len2 /len1; pose ndv := _ / _.
    suff gt0_ndv : 0%r < ndv.
    + rewrite addr_gt0 1:-lt_fromint; 1: smt(ceil_bound).
      rewrite -from_int_floor ltzS floor_mono divr_ge0 log_ge0 //= le_fromint.
      - rewrite mulr_ege1. smt(ceil_bound). apply IntOrder.ler_subr_addr => /=.
        by rewrite /w IntOrder.ler_eexpr //; smt(val_log2w). 
      by rewrite /w IntOrder.exprn_ege1 //; smt(val_log2w).
    rewrite ltr_pdivl_mulr /w -RField.fromintXn 2:/log2; 1,3,4: smt(val_log2w ge1_n).
    by rewrite -rpow_int // logK //; smt(val_log2w).  
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
module SPHINCS_PLUS : Scheme = {
  proc keygen() : pkSPHINCSPLUSTW * skSPHINCSPLUSTW = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : skSPHINCSPLUSTW;
    
    (* Initialize address *)  
    ad <- adz;
    
    (* Initialize message seed (for message key generation), secret seed, and public seed *)
    ms <$ dmseed;
    ss <$ dsseed;
    ps <$ dpseed;
    
    (* Compute root of hypertree *)
    root <@ FL_SL_XMSS_MT_ES.gen_root(ss, ps, ad);
    
    pk <- (root, ps);
    sk <- (ms, ss, ps);
    
    return (pk, sk);
  }
  
  proc sign(sk : skSPHINCSPLUSTW, m : msg) : sigSPHINCSPLUSTW = {
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var sigFORSTW : sigFORSTW;
    var cm : msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS : pkFORS;
    var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;
    var sig : sigSPHINCSPLUSTW;
    
    (* Extract message seed, secret seed, and public seed from secret key *)
    (ms, ss, ps) <- sk;
    
    (* Initialize address *)
    ad <- adz;
    
    (* Sign the message with multi-instance FORS-TW (M-FORS-TW-ES) *)
    (mk, sigFORSTW) <@ M_FORS_ES.sign((ms, ss, ps, ad), m);
    
    (* Compress message and compute instance index *)
    (cm, idx) <- mco mk m;
    
    (* Compute tree index and keypair index from instance index  *)
    (tidx, kpidx) <- edivz (val idx) l';
    
    (* Compute FORS-TW public key from secret/public seed and tree/keypair index address *)
    pkFORS <@ FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW, cm, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    
    (* Sign the FORS-TW public key with hypertree (FL-SL-XMSS-MT-TW-ES) *)
    sigFLSLXMSSMTTW <@ FL_SL_XMSS_MT_ES.sign((ss, ps, ad), pkFORS, idx);
    
    return (mk, sigFORSTW, sigFLSLXMSSMTTW);
  }
  
  proc verify(pk : pkSPHINCSPLUSTW, m : msg, sig : sigSPHINCSPLUSTW) : bool = {
    var root, root' : dgstblock;
    var ps : pseed;
    var mk : mkey;
    var sigFORSTW : sigFORSTW;
    var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;
    var ad : adrs;
    var cm : msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS : pkFORS;
    
    (* Extract values from public key and signature  *)
    (root, ps) <- pk;
    (mk, sigFORSTW, sigFLSLXMSSMTTW) <- sig;
    
    (* Initialize address *)
    ad <- adz;
    
    (* Compress message and compute instance index *)
    (cm, idx) <- mco mk m;
    
    (* Compute tree index and keypair index from instance index  *)
    (tidx, kpidx) <- edivz (val idx) l';
    
    (* Compute FORS-TW public key from FORS-TW signature, compressed message, public seed, and tree/keypair index address *)
    pkFORS <@ FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW, cm, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    
    (* Compute root from FORS-TW public key, hypertree signature, instance index, public seed, and address *)
    root' <@ FL_SL_XMSS_MT_ES.root_from_sigFLSLXMSSMTTW(pkFORS, sigFLSLXMSSMTTW, idx, ps, ad);
    
    (* Compare computed root with root in public key *)
    return root' = root;
  }
}.



(* - Proof - *)
(* -- Reduction adversaries -- *)
(* Reduction adversary against the PRF property of skg (i.e., secret key generation function) *)
module (R_SKGPRF_EUFCMA (A : Adv_EUFCMA) : SKG_PRF.Adv_PRF) (O : SKG_PRF.Oracle_PRF) = {
  var ms : mseed
  var ps : pseed
  var skFORSnt : skFORS list list
  var skWOTStd : skWOTS list list list
  var qs : msg list
  
  (* 
    Signing oracle provided to given adversary.
    Identical to signing of SPHINCS+-TW, but uses
    secret keys pre-generated with PRF oracle
  *)
  module O_CMA : SOracle_CMA = {
    proc sign(m : msg) : sigSPHINCSPLUSTW = {
      var skFORS : skFORS;
      var pkFORS : pkFORS;
      var skWOTS : skWOTS;
      var ad : adrs;
      var mk : mkey;
      var cm : msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var sigFORSTW : sigFORSTW;
      var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;

      ad <- adz;

      mk <- mkg ms m;

      (cm, idx) <- mco mk m;

      (tidx, kpidx) <- edivz (val idx) l';

      skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

      sigFORSTW <@ FL_FORS_ES_NPRF.sign((skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

      pkFORS <@ FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

      sigFLSLXMSSMTTW <@ FL_SL_XMSS_MT_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);

      qs <- rcons qs m;

      return (mk, sigFORSTW, sigFLSLXMSSMTTW);
    }
  }
  
  proc distinguish() : bool = {
    var ad : adrs;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORS : dgstblock list list;
    var skFORSlp : skFORS list; 
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var is_valid, is_fresh : bool;
    
    (* Initialize module variables (for oracle usage) *)
    skFORSnt <- [];
    skWOTStd <- [];
    qs <- [];
    
    ms <$ dmseed;
    ps <$ dpseed;
    
    ad <- adz;
    
    (* Sample and store FORS-TW secret keys *)
    skFORSnt <- [];
    (* For each (inner) tree in the bottom layer... *)
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      (* For each (FORS-TW instance associated with a) leaf in this (inner) tree... *)
      while (size skFORSlp < l') {
         skFORS <- [];
         (* For each FORS-TW tree in this FORS-TW instance... *)
         while (size skFORS < k) {
          skFORSet <- [];
          (* For each leaf in this FORS-TW tree... *)
          while (size skFORSet < t) {
            (* Get a secret key element associated to this leaf from the oracle and store it *)
            skFORS_ele <@ O.query(ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORS * t + size skFORSet));
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORS <- rcons skFORS skFORSet;  
        }
        skFORSlp <- rcons skFORSlp (insubd skFORS);  
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }
    
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
            (* Get a secret key element (that will be used as the first value in this chain) and store it *)
            skWOTS_ele <@ O.query(ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
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
    leaves <@ FL_SL_XMSS_MT_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    
    (*
      Compute root (hash value) from the computed list of leaves, given public seed, and
      given address (after setting the type to tree hashing)
    *)
    root <- FSSLXMTWES.val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);
    
    pk <- (root, ps);
    
    (* Ask adversary to forge *)
    (m', sig') <@ A(O_CMA).forge(pk);
    
    (* Check whether forgery is valid *)
    is_valid <@ SPHINCS_PLUS.verify(pk, m', sig');
    
    (* Check whether message from forgery is fresh *)
    is_fresh <- ! m' \in qs;
    
    return is_valid /\ is_fresh;
  }
}.

(* Reduction adversary against the PRF property of mkg (message key generation function) *)
module (R_MKGPRF_EUFCMA (A : Adv_EUFCMA) : MKG_PRF.Adv_PRF) (O : MKG_PRF.Oracle_PRF) = {
  var ad : adrs
  var ps : pseed
  var skFORSnt : skFORS list list
  var skWOTStd : skWOTS list list list
  var qs : msg list
  
  (* 
    Signing oracle provided to given adversary.
    Identical to signing of SPHINCS+-TW, but uses
    pre-generated secret keys and obtains message key from
    given PRF oracle
  *)
  module O_CMA : SOracle_CMA = {
    proc sign(m : msg) : sigSPHINCSPLUSTW = {
      var skFORS : skFORS;
      var pkFORS : pkFORS;
      var skWOTS : skWOTS;
      var ad : adrs;
      var mk : mkey;
      var cm : msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var sigFORSTW : sigFORSTW;
      var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;

      ad <- adz;

      mk <@ O.query(m);

      (cm, idx) <- mco mk m;

      (tidx, kpidx) <- edivz (val idx) l';

      skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;

      sigFORSTW <@ FL_FORS_ES_NPRF.sign((skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);

      pkFORS <@ FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);

      sigFLSLXMSSMTTW <@ FL_SL_XMSS_MT_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);

      qs <- rcons qs m;

      return (mk, sigFORSTW, sigFLSLXMSSMTTW);
    }
  }
  
  proc distinguish() : bool = {
    var ss : sseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORS : dgstblock list list;
    var skFORSlp : skFORS list; 
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var is_valid, is_fresh : bool;

    (* Initialize module variables (for oracle usage) *)
    qs <- [];
    ss <$ dsseed;
    ps <$ dpseed;
    
    ad <- adz;
    
    (* Sample and store FORS-TW secret keys  *)
    skFORSnt <- [];
    (* For each (inner) tree in the bottom layer... *)
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      (* For each (FORS-TW instance associated with a) leaf in this (inner) tree... *)
      while (size skFORSlp < l') {
        skFORS <- [];
        (* For each FORS-TW tree in this FORS-TW instance... *)
        while (size skFORS < k) {
          skFORSet <- [];
          (* For each leaf in this FORS-TW tree... *)
          while (size skFORSet < t) {
            (* Sample and store a secret key element associated to this leaf *)
            skFORS_ele <$ ddgstblock;
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORS <- rcons skFORS skFORSet;  
        }
        skFORSlp <- rcons skFORSlp (insubd skFORS);  
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }
    
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
      Extract secret key of the top-most inner tree in the hypertree 
      and compute the corresponding leaves.
    *)
    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    
    (*
      Compute root (hash value) from the computed list of leaves, given public seed, and
      given address (after setting the type to tree hashing)
    *)
    root <- FSSLXMTWES.val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);
    
    pk <- (root, ps);
    
    (* Ask adversary to forge *)
    (m', sig') <@ A(O_CMA).forge(pk);    
    
    (* Check whether forgery is valid *)
    is_valid <@ SPHINCS_PLUS.verify(pk, m', sig');
    
    (* Check whether message from forgery is fresh *)
    is_fresh <- ! m' \in qs;
    
    return is_valid /\ is_fresh;
  }
}.

(* Reduction adversary against the EUFCMA property of M-FORS-TW-ES-NPRF *)
module (R_MFORSTWESNPRFEUFCMA_EUFCMA (A : Adv_EUFCMA) : Adv_EUFCMA_MFORSTWESNPRF) (O : SOracle_CMA_MFORSTWESNPRF) = {
  var pkFORSnt : pkFORS list list
  var skWOTStd : skWOTS list list list
  var ps : pseed
  var ad : adrs
   
  (* 
    Signing oracle provided to given adversary.
    Identical to signing of original SPHINCS+-TW, but uses
    pre-generated secret keys for WOTS-TW instances, uses
    (M-FORS-TW-ES-NPRF) public key provided by game, and obtains
    M-FORS-TW-ES-NPRF signature from given CMA (signing) oracle.
  *)
  module O_CMA : SOracle_CMA = {
    proc sign(m : msg) : sigSPHINCSPLUSTW = {
      var mk : mkey;
      var sigFORSTW : sigFORSTW;
      var cm : msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var pkFORS : pkFORS;
      var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;
      
      (mk, sigFORSTW) <@ O.sign(m);
      
      (cm, idx) <- mco mk m; 
      
      (tidx, kpidx) <- edivz (val idx) l';
      
      pkFORS <- nth witness (nth witness pkFORSnt tidx) kpidx;
      
      sigFLSLXMSSMTTW <@ FL_SL_XMSS_MT_ES_NPRF.sign((skWOTStd, ps, set_typeidx ad chtype), pkFORS, idx);
      
      return (mk, sigFORSTW, sigFLSLXMSSMTTW);
    }
  }
  
  proc forge(pk : pkFORS list list * pseed * adrs) : msg * (mkey * sigFORSTW) = {
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var mk' : mkey;
    var sigFORSTW' : sigFORSTW;
    var sigFLSLXMSSMTTW' : sigFLSLXMSSMTTW; 
        
    (pkFORSnt, ps, ad) <- pk;
    
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
    leaves <@ FL_SL_XMSS_MT_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx (set_typeidx ad chtype) (d - 1) 0);
    
    (*
      Compute root (hash value) from the computed list of leaves, given public seed, and
      given address (after setting the type to tree hashing)
    *)
    root <- FSSLXMTWES.val_bt_trh ps (set_ltidx (set_typeidx ad trhxtype) (d - 1) 0) (list2tree leaves);
    
    (* Ask adversary to forge *)
    (m', sig') <@ A(O_CMA).forge((root, ps));
    
    (mk', sigFORSTW', sigFLSLXMSSMTTW') <- sig';
    
    return (m', (mk', sigFORSTW'));
  }
}.

(* Reduction adversary against the NAGCMA property of FL-SL-XMSS-MT-TW-ES-NPRF *)
module (R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA (A : Adv_EUFCMA) : Adv_EUFNAGCMA_FLSLXMSSMTTWESNPRF) (OC : Oracle_THFC) = {
  var skFORSnt : skFORS list list
  var pkFORSnt : pkFORS list list
  var root : dgstblock
  var ps : pseed
  var ad : adrs
  var sigFLSLXMSSMTTWl : sigFLSLXMSSMTTW list
  var mmap : (msg, mkey) fmap
  
  (* 
    Signing oracle provided to given adversary.
    Identical to signing of original SPHINCS+-TW, but uses
    pre-generated secret and public keys for FORS-TW, uses
    (FL-SL-XMSS-MT-TW-ES-NPRF) public key and signatures provided by game, 
    and uses a random function for message key generation.
  *)
  module O_CMA : SOracle_CMA = {
    proc sign(m : msg) : sigSPHINCSPLUSTW = {
      var mk : mkey;
      var sigFORSTW : sigFORSTW;
      var cm : msgFORSTW;
      var idx : index;
      var tidx, kpidx : int;
      var skFORS : skFORS;
      var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;
      
      if (m \notin mmap) { 
        mk <$ dmkey;
        mmap.[m] <- mk;
      } 
      mk <- oget mmap.[m];
    
      (cm, idx) <- mco mk m; 
      
      (tidx, kpidx) <- edivz (val idx) l';
      
      skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;
      
      sigFORSTW <@ FL_FORS_ES_NPRF.sign((skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm); 
      
      sigFLSLXMSSMTTW <- nth witness sigFLSLXMSSMTTWl (val idx);
      
      return (mk, sigFORSTW, sigFLSLXMSSMTTW);
    }
  }

  proc choose() : msgFLSLXMSSMTTW list = {
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORS : dgstblock list list;
    var skFORSlp : skFORS list; 
    var pkFORS : pkFORS;
    var pkFORSlp : pkFORS list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var roots : dgstblock list;
    var kpidx : int;
    var leaf : dgstblock;
    var nodes : dgstblock list list;
    var nodespl, nodescl : dgstblock list;
    var lnode, rnode, node : dgstblock;
     
    ad <- adz;
    
    (* Sample/compute and store FORS-TW secret/public keys  *)
    skFORSnt <- [];
    pkFORSnt <- [];
    (* For each (inner) tree in the bottom layer... *)
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      pkFORSlp <- [];
      (* For each (FORS-TW instance associated with a) leaf in this (inner) tree... *)
      while (size skFORSlp < l') {
        skFORS <- [];
        roots <- [];
        (* For each FORS-TW tree in this FORS-TW instance... *)
        while (size skFORS < k) {
          skFORSet <- [];
          leaves <- [];
          (* For each leaf in this FORS-TW tree... *)
          while (size skFORSet < t) {
            (* Sample a secret key element, compute the corresponding leaf, and store them  *)
            skFORS_ele <$ ddgstblock;
            leaf <@ OC.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 
                                         0 (size skFORS * t + size skFORSet), 
                             (val skFORS_ele));
            skFORSet <- rcons skFORSet skFORS_ele;
            leaves <- rcons leaves leaf;
          }
          
          (* root <- val_bt_trh ps ad (list2tree leaves) (size roots); *)
          (* Compute the root of this FORS-TW tree (from its leaves computed above)... *)
          nodes <- [];
          (* For each layer in this FORS-TW tree (from bottom to top)... *)
          while (size nodes < a) {
            (* Get the nodes of the previous layer *)
            nodespl <- last leaves nodes;
            
            (* Compute the nodes of the current layer *)
            nodescl <- [];
            (* For each node in this layer... *)
            while (size nodescl < nr_nodesf (size nodes + 1)) {
              (* Get its children (from the previous layer) *)
              lnode <- nth witness nodespl (2 * size nodescl);
              rnode <- nth witness nodespl (2 * size nodescl + 1);
              
              (* Compute the node by hashing (via the given collection oracle) the concatenation of its children *)
              node <@ OC.query(set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 
                                           (size nodes + 1) (size skFORS * nr_nodesf (size nodes + 1) + size nodescl), 
                               val lnode ++ val rnode);
              
              nodescl <- rcons nodescl node;      
            }
            nodes <- rcons nodes nodescl;
          }
          skFORS <- rcons skFORS skFORSet;
          roots <- rcons roots (nth witness (nth witness nodes (a - 1)) 0);
        }
        
        (* 
          Compute the public key of this FORS-TW instance by hashing (via the given collection) 
          oracle the concatenation of the roots of its trees (computed above)
        *)
        pkFORS <@ OC.query(set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) 
                                                             (size skFORSlp)) trcotype) (size skFORSlp), 
                           flatten (map DigestBlock.val roots));
                           
        skFORSlp <- rcons skFORSlp (insubd skFORS);
        pkFORSlp <- rcons pkFORSlp pkFORS;
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
      pkFORSnt <- rcons pkFORSnt pkFORSlp;
    }
    
    return flatten pkFORSnt;
  }
  
  proc forge(pk : pkFLSLXMSSMTTW, sigl : sigFLSLXMSSMTTW list) : msgFLSLXMSSMTTW * sigFLSLXMSSMTTW * index = {
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var mk' : mkey;
    var sigFORSTW' : sigFORSTW;
    var sigFLSLXMSSMTTW' : sigFLSLXMSSMTTW;
    var cm' : msgFORSTW;
    var idx' : index;
    var tidx', kpidx' : int;
    var pkFORS' : pkFORS;
    
    (* Initialize module variables (for usage of oracle) *)
    mmap <- empty;
    (root, ps, ad) <- pk;
    sigFLSLXMSSMTTWl <- sigl;
    
    (* Ask adversary to forge *)
    (m', sig') <@ A(O_CMA).forge((root, ps));
    
    (mk', sigFORSTW', sigFLSLXMSSMTTW') <- sig';
    
    (cm', idx') <- mco mk' m';
     
    (tidx', kpidx') <- edivz (val idx') l';
       
    pkFORS' <@ FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm', ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx') kpidx');
   
    return (pkFORS', sigFLSLXMSSMTTW', idx');
  }
}.


section Proof_SPHINCS_PLUS_EUFCMA.
(* -- Declarations -- *)
declare module A <: Adv_EUFCMA {
(* FORS-TW *)
-FTWES.FP_OPRETCRDSPR.FP_OpenPRE.O_SMDTOpenPRE_Default, 
-FTWES.FP_OPRETCRDSPR.FP_DSPR.O_SMDTDSPR_Default, 
-FTWES.FP_OPRETCRDSPR.R_DSPR_OpenPRE, 
-FTWES.FP_OPRETCRDSPR.R_TCR_OpenPRE, 
-FTWES.FP_OPRETCRDSPR.FP_TCR.O_SMDTTCR_Default,
-FTWES.MCO_ITSR.O_ITSR_Default, 
-FTWES.F_OpenPRE.O_SMDTOpenPRE_Default, 
-FTWES.TRHC_TCR.O_SMDTTCR_Default, 
-FTWES.TRCOC_TCR.O_SMDTTCR_Default, 
-FTWES.TRHC.O_THFC_Default, 
-FTWES.TRCOC.O_THFC_Default,
-FTWES.O_CMA_MFORSTWESNPRF, 
-FTWES.O_CMA_MFORSTWESNPRF_AV, 
-FTWES.R_ITSR_EUFCMA, 
-FTWES.R_FSMDTOpenPRE_EUFCMA, 
-FTWES.R_TRHSMDTTCRC_EUFCMA, 
-FTWES.R_TRCOSMDTTCRC_EUFCMA,
(* FL-SL-XMSS-MT-TW *)
-FSSLXMTWES.WTWES.O_MEUFGCMA_WOTSTWESNPRF, 
-FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default, 
-FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, 
-FSSLXMTWES.WTWES.FC_UD.O_SMDTUD_Default, 
-FSSLXMTWES.WTWES.FC_TCR.O_SMDTTCR_Default, 
-FSSLXMTWES.WTWES.FC_PRE.O_SMDTPRE_Default, 
-FSSLXMTWES.PKCOC.O_THFC_Default, 
-FC.O_THFC_Default, 
-FSSLXMTWES.TRHC.O_THFC_Default, 
-FSSLXMTWES.R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA, 
-FSSLXMTWES.R_SMDTTCRCPKCO_EUFNAGCMA, 
-FSSLXMTWES.R_SMDTTCRCTRH_EUFNAGCMA, 
-FSSLXMTWES.WTWES.R_SMDTUDC_Game23WOTSTWES, 
-FSSLXMTWES.WTWES.R_SMDTTCRC_Game34WOTSTWES, 
-FSSLXMTWES.WTWES.R_SMDTPREC_Game4WOTSTWES,
(* Local *)
-SKG_PRF.O_PRF_Default, 
-MKG_PRF.O_PRF_Default, 
-R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA, 
-O_CMA_Default, 
-R_SKGPRF_EUFCMA, 
-R_MKGPRF_EUFCMA, 
-R_MFORSTWESNPRFEUFCMA_EUFCMA 
}.

(* Assuming the given (signing) CMA oracle terminates, the adversary terminates as well *)
declare axiom A_forge_ll (O <: SOracle_CMA{-A}) :
  islossless O.sign => islossless A(O).forge.

  
(* -- Auxiliary/Local specifications *)
(* SPHINCS+ signing, but generating FORS public key from scratch instead of from FORS signature *)
module SPHINCS_PLUS_S = {
  proc sign(sk : skSPHINCSPLUSTW, m : msg) : sigSPHINCSPLUSTW = {
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var sigFORSTW : sigFORSTW;
    var cm : msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS : pkFORS;
    var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;
    var sig : sigSPHINCSPLUSTW;
    
    (* Extract message seed, secret seed, and public seed from secret key *)
    (ms, ss, ps) <- sk;
    
    (* Initialize address *)
    ad <- adz;
    
    (* Sign the message with multi-instance FORS-TW (M-FORS-TW-ES) *)
    (mk, sigFORSTW) <@ M_FORS_ES.sign((ms, ss, ps, ad), m);
    
    (* Compress message and compute instance index *)
    (cm, idx) <- mco mk m;
    
    (* Compute tree index and keypair index from instance index  *)
    (tidx, kpidx) <- edivz (val idx) l';
    
    (* Compute FORS-TW public key from secret/public seed and tree/keypair index address *)
    pkFORS <@ FL_FORS_ES.gen_pkFORS(ss, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    
    (* Sign the FORS-TW public key with hypertree (FL-SL-XMSS-MT-TW-ES) *)
    sigFLSLXMSSMTTW <@ FL_SL_XMSS_MT_ES.sign((ss, ps, ad), pkFORS, idx);
    
    return (mk, sigFORSTW, sigFLSLXMSSMTTW);
  }
}.

(* SPHINCS+-TW key generations, but uses pregenerated secret keys (with PRF or randomly sampled) *)  
local module SPHINCS_PLUS_FS = {
  proc keygen_prf() : pkSPHINCSPLUSTW * (mseed * skFORS list list * skWOTS list list list * pseed) = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORS : dgstblock list list;
    var skFORSlp : skFORS list; 
    var skFORSnt : skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * skFORS list list * skWOTS list list list * pseed;
    
    ad <- adz;
    
    ms <$ dmseed;
    ss <$ dsseed;
    
    ps <$ dpseed;
    
    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
         skFORS <- [];
         while (size skFORS < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <- skg ss (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORS * t + size skFORSet));
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORS <- rcons skFORS skFORSet;  
        }
        skFORSlp <- rcons skFORSlp (insubd skFORS);  
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }
    
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <- skg ss (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) (size skWOTS)) 0);
            skWOTS <- rcons skWOTS skWOTS_ele;  
          } 
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }  
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt; 
    }

    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    root <- FSSLXMTWES.val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);
    
    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    return (pk, sk);
  }

  proc keygen_nprf() : pkSPHINCSPLUSTW * (mseed * skFORS list list * skWOTS list list list * pseed) = {
    var ad : adrs;
    var ms : mseed;
    var ss : sseed;
    var ps : pseed;
    var skFORS_ele : dgstblock;
    var skFORSet : dgstblock list;
    var skFORS : dgstblock list list;
    var skFORSlp : skFORS list; 
    var skFORSnt : skFORS list list;
    var skWOTS_ele : dgstblock;
    var skWOTS : dgstblock list;
    var skWOTSlp : skWOTS list;
    var skWOTSnt : skWOTS list list;
    var skWOTStd : skWOTS list list list;
    var leaves : dgstblock list;
    var root : dgstblock;
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * skFORS list list * skWOTS list list list * pseed;
    
    ad <- adz;
    
    ms <$ dmseed;
    ss <$ dsseed;
    
    ps <$ dpseed;
    
    skFORSnt <- [];
    while (size skFORSnt < nr_trees 0) {
      skFORSlp <- [];
      while (size skFORSlp < l') {
         skFORS <- [];
         while (size skFORS < k) {
          skFORSet <- [];
          while (size skFORSet < t) {
            skFORS_ele <$ ddgstblock;
            skFORSet <- rcons skFORSet skFORS_ele;
          }
          skFORS <- rcons skFORS skFORSet;  
        }
        skFORSlp <- rcons skFORSlp (insubd skFORS);  
      }
      skFORSnt <- rcons skFORSnt skFORSlp;
    }
    
    skWOTStd <- [];
    while (size skWOTStd < d) {
      skWOTSnt <- [];
      while (size skWOTSnt < nr_trees (size skWOTStd)) {
        skWOTSlp <- [];
        while (size skWOTSlp < l') {
          skWOTS <- [];
          while (size skWOTS < len) {
            skWOTS_ele <$ ddgstblock;
            skWOTS <- rcons skWOTS skWOTS_ele;  
          }
          skWOTSlp <- rcons skWOTSlp (DBLL.insubd skWOTS);
        }
        skWOTSnt <- rcons skWOTSnt skWOTSlp;
      }
      skWOTStd <- rcons skWOTStd skWOTSnt; 
    }

    skWOTSlp <- nth witness (nth witness skWOTStd (d - 1)) 0;
    leaves <@ FL_SL_XMSS_MT_ES_NPRF.leaves_from_sklpsad(skWOTSlp, ps, set_ltidx ad (d - 1) 0);
    
    root <- FSSLXMTWES.val_bt_trh ps (set_typeidx (set_ltidx ad (d - 1) 0) trhxtype) (list2tree leaves);
    
    pk <- (root, ps);
    sk <- (ms, skFORSnt, skWOTStd, ps);

    return (pk, sk);
  }
  
  proc verify = SPHINCS_PLUS.verify
}.


(* --- Equivalences between procedures of specifications --- *)
local equiv Eqv_SPHINCS_PLUS_S_sign :
  SPHINCS_PLUS.sign ~ SPHINCS_PLUS_S.sign : ={sk, m} ==> ={res}.
proof.
proc.
seq 2 2 : (={sk, m, ms, ss, ps, ad} /\ ad{1} = adz).
+ by wp; skip.
seq 1 1 : (   #pre 
           /\ ={mk, sigFORSTW}
           /\ sigFORSTW{1} 
              =
              (insubd (mkseq (fun (i : int) =>
                          let adb = set_kpidx (set_tidx (set_typeidx ad{1} trhftype) (edivz (val (mco mk{1} m{1}).`2) l').`1) 
                                              (edivz (val (mco mk{1} m{1}).`2) l').`2 in
                          let lfidx = bs2int (rev (take a (drop (a * i) (val (mco mk{1} m{1}).`1)))) in
                          let skfele = skg ss{1} (ps{1}, set_thtbidx adb 0 (i * t + lfidx)) in
                          let lvs = mkseq (fun (j : int) =>
                                              f ps{1} (set_thtbidx adb 0 (i * t + j)) 
                                                (val (skg ss{1} (ps{1}, (set_thtbidx adb 0 (i * t + j)))))) t in
                          (skfele, cons_ap_trh ps{1} adb (list2tree lvs) lfidx i)) k))).
+ inline{1} 1; inline{2} 1.
  inline{1} 7; inline{2} 7.
  wp => /=.
  while (   ={sig1, m1, ss1, ps1, ad1}
         /\ size sig1{1} <= k
         /\ sig1{1}
            =
            (mkseq (fun (i : int) =>
                          let lfidx = bs2int (rev (take a (drop (a * i) (val m1{1})))) in
                          let skfele = skg ss1{1} (ps1{1}, set_thtbidx ad1{1} 0 (i * t + lfidx)) in
                          let lvs = mkseq (fun (j : int) =>
                                              f ps1{1} (set_thtbidx ad1{1} 0 (i * t + j)) 
                                                (val (skg ss1{1} (ps1{1}, (set_thtbidx ad1{1} 0 (i * t + j)))))) t in
                          (skfele, cons_ap_trh ps1{1} ad1{1} (list2tree lvs) lfidx i)) (size sig1{1}))).
  - inline{1} 4; inline{2} 4.
    wp => /=.
    while (   ={leaves0, ss2, ps2, ad2, idxt}
           /\ size leaves0{1} <= t
           /\ leaves0{1}
              =
              mkseq (fun (j : int) =>
                      f ps2{1} (set_thtbidx ad2{1} 0 (idxt{1} * t + j)) 
                        (val (skg ss2{1} (ps2{1}, (set_thtbidx ad2{1} 0 (idxt{1} * t + j)))))) (size leaves0{1})).
    * wp; skip => /> &1 _ lvsdef ltt_szlvs.
      rewrite size_rcons mkseqS 1:size_ge0; split => [/#| ].
      by rewrite {1}lvsdef. 
    wp; skip => /> &2 _ sigdef ltk_szsig.
    rewrite mkseq0; split => [| lvs _ /lezNgt get_szlvs let_szlvs lvsdef]; 1: smt(ge2_t).
    rewrite size_rcons mkseqS 1:size_ge0 /=; split => [/# |].
    by do 4! congr => /=; rewrite lvsdef (: size lvs = t) 1:/#.
  wp; skip => /> &2.
  rewrite mkseq0 /=; split => [| sig /lezNgt gek_szsig _ lek_szsig sigdef]; 1: smt(ge1_k).
  by congr; rewrite sigdef (: size sig = k) 1:/#.
call (: true); 1: by sim.
sp 2 2; conseq (: _ ==> ={pkFORS}) => />; 1: smt().
inline{1} 1; inline{2} 1.
seq 6 5 : (={roots, ps0, ad0}).
+ sp 4 3 => /=; conseq (: _ ==> ={roots}) => />; 1: smt().
  while (   #pre
         /\ ={tidx, kpidx, roots}).
  - inline{2} 1.
    wp.
    while{2} (leaves0{2}
              =
              mkseq (fun (j : int) =>
                      f ps1{2} (set_thtbidx ad1{2} 0 (idxt{2} * t + j)) 
                        (val (skg ss1{2} (ps1{2}, (set_thtbidx ad1{2} 0 (idxt{2} * t + j)))))) (size leaves0{2})
              /\ size leaves0{2} <= t)
             (t - size leaves0{2}).
    * move=> _ z.
      wp; skip => /> &2 lvsdef _ ltt_szlvs.
      rewrite size_rcons -andbA; split => [| /#].
      by rewrite mkseqS 1:size_ge0 /=; congr.
    wp; skip => /> &1 &2 <- <- [-> eqidx] tkpidxdef ltk_szrs.
    rewrite mkseq0 /=; split => [| lvs]; 1: smt(ge2_t).
    split => [/# | /lezNgt get_szlvs lvsdef let_szlvs].
    rewrite ?size_rcons /=; congr.
    pose bscm := bs2int (rev (take a (drop (a * size roots{2}) (val cm{2})))).
    pose adb := set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{2}) kpidx{2}.
    have szbslt : bscm < size lvs.
    * rewrite /bscm; pose r := rev _; rewrite (: size lvs = 2 ^ size r) 2:bs2int_le2Xs.
      rewrite size_rev size_take 2:size_drop 3:valP; 1,2: smt(ge1_a size_ge0).
      rewrite mulrC -mulrBr; case (size roots{2} = k - 1) => [-> /= /# | neqk1_szrs].
      
      rewrite ler_maxr 1:mulr_ge0; 1,2: smt(ge1_a).
      rewrite (: a < a * (k - size roots{2})) 2:/#.
      by rewrite ltr_pmulr; smt(ge1_a).
    have fblvs : fully_balanced (list2tree lvs) by rewrite (list2tree_fullybalanced _ a); smt(ge1_a).
    have szrvbs : size (rev (int2bs a bscm)) = a by rewrite size_rev size_int2bs; smt(ge1_a).
    have hlvs : height (list2tree lvs) = a by rewrite (list2tree_height _ a); smt(ge1_a).
    rewrite /val_ap_trh /val_ap_trh_gen /val_bt_trh /val_bt_trh_gen.
    rewrite (eq_valbt_valap (FTWES.trhi ps{2} adb) FTWES.updhbidx (list2tree lvs) 
                            (DBAL.val (cons_ap_trh ps{2} adb (list2tree lvs) bscm (size roots{2})))
                            (rev (int2bs a bscm))
                            (f ps{2} (set_thtbidx adb 0 (size roots{2} * t + bscm)) (val (skg ss{2} (ps{2}, (set_thtbidx adb 0 (size roots{2} * t + bscm))))))
                            (a, size roots{2})) => [//|||||].
    * by rewrite valP hlvs.
    * by rewrite valP szrvbs.
    * rewrite list2tree_lvb 3:bs2int_ge0 3://; 1,2: smt(ge1_a).
      by rewrite (onth_nth witness) 1:bs2int_ge0 1:// lvsdef nth_mkseq 1:bs2int_ge0.
    * move=> i; rewrite valP => rngi; rewrite /cons_ap_trh /cons_ap_trh_gen.
      rewrite insubdK 1:size_consap 1,2,3:// 1:szrvbs 1:hlvs 1://.
      by rewrite nth_consap 1:// 1:szrvbs 1:hlvs 1:// 1:szrvbs.
    rewrite insubdK 1:size_mkseq; 1: smt(ge1_k).
    rewrite nth_mkseq 1:size_ge0 1:// 1:/=.
    by rewrite /bscm; do 2! congr; rewrite {1}lvsdef (: size lvs = t) 1:/#.
  by wp; skip => /> &1 &2 <- /= + [_ ->] => <-.
by wp; skip.
qed.

  
(* -- Auxiliary/Local oracles -- *)
(* SPHINCS+-TW (signing) CMA oracle, but uses pregenerated secret keys  *)
local module O_CMA_SPHINCSPLUSTWFS_PRF : SOracle_CMA = {
  var sk : mseed * skFORS list list * skWOTS list list list * pseed
  var qs : msg list
  
  proc init(sk_init : mseed * skFORS list list * skWOTS list list list * pseed) : unit = {
    sk <- sk_init;
    qs <- [];
  }
  
  proc sign(m : msg) : sigSPHINCSPLUSTW = {
    var ms : mseed;
    var skFORS : skFORS;
    var pkFORS : pkFORS;
    var skFORSnt : skFORS list list;
    var skWOTS : skWOTS;
    var skWOTStd : skWOTS list list list;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var cm : msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var sigFORSTW : sigFORSTW;
    var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;
    
    (ms, skFORSnt, skWOTStd, ps) <- sk;
    
    ad <- adz;
    
    mk <- mkg ms m;
         
    (cm, idx) <- mco mk m;
    
    (tidx, kpidx) <- edivz (val idx) l';
    
    skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;
     
    sigFORSTW <@ FL_FORS_ES_NPRF.sign((skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);
    
    pkFORS <@ FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    
    sigFLSLXMSSMTTW <@ FL_SL_XMSS_MT_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);
    
    qs <- rcons qs m;
    
    return (mk, sigFORSTW, sigFLSLXMSSMTTW);
  }
  
  proc fresh(m : msg) : bool = {
    return ! (m \in qs);
  }
  
  proc nr_queries() : int = {
    return size qs;
  }
}.

(* 
  SPHINCS+-TW (signing) CMA oracle, but uses pregenerated secret keys 
  and uses a random function for message key generation  
*)
local module O_CMA_SPHINCSPLUSTWFS_NPRF : SOracle_CMA = {
  include var O_CMA_SPHINCSPLUSTWFS_PRF [-init, sign]
  var mmap : (msg, mkey) fmap
  
  proc init(sk_init : mseed * skFORS list list * skWOTS list list list * pseed) : unit = {
    sk <- sk_init;
    qs <- [];
    mmap <- empty;
  }

  proc sign(m : msg) : sigSPHINCSPLUSTW = {
    var ms : mseed;
    var skFORS : skFORS;
    var pkFORS : pkFORS;
    var skFORSnt : skFORS list list;
    var skWOTS : skWOTS;
    var skWOTStd : skWOTS list list list;
    var ps : pseed;
    var ad : adrs;
    var mk : mkey;
    var cm : msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var sigFORSTW : sigFORSTW;
    var sigFLSLXMSSMTTW : sigFLSLXMSSMTTW;
    
    (ms, skFORSnt, skWOTStd, ps) <- sk;
    
    ad <- adz;
    
    if (m \notin mmap) { 
      mk <$ dmkey;
      mmap.[m] <- mk;
    } 
    mk <- oget mmap.[m];
    
    (cm, idx) <- mco mk m;
    
    (tidx, kpidx) <- edivz (val idx) l';
    
    skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;
     
    sigFORSTW <@ FL_FORS_ES_NPRF.sign((skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx), cm);
    
    pkFORS <@ FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    
    sigFLSLXMSSMTTW <@ FL_SL_XMSS_MT_ES_NPRF.sign((skWOTStd, ps, ad), pkFORS, idx);
    
    qs <- rcons qs m;

    return (mk, sigFORSTW, sigFLSLXMSSMTTW);
  }
}.


(* -- Auxiliary/Local security properties -- *)
(* --- SPHINCS+-TW --- *)
(* EUF-CMA for SPHINCS+-TW, but with pregenerated secret keys obtained from skg (PRF) *)
local module EUF_CMA_SPHINCSPLUSTWFS_PRFPRF = {
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var is_valid : bool;
    var is_fresh : bool;
    
    (pk, sk) <@ SPHINCS_PLUS_FS.keygen_prf();
    
    O_CMA_SPHINCSPLUSTWFS_PRF.init(sk);
    
    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWFS_PRF).forge(pk);
    
    is_valid <@ SPHINCS_PLUS_FS.verify(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWFS_PRF.fresh(m');
    
    return is_valid /\ is_fresh;
  }
}.

(* EUF-CMA for SPHINCS+-TW, but with pregenerated secret keys obtained by sampling *)
local module EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF = {
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var is_valid : bool;
    var is_fresh : bool;
    
    (pk, sk) <@ SPHINCS_PLUS_FS.keygen_nprf();
    
    O_CMA_SPHINCSPLUSTWFS_PRF.init(sk);
    
    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWFS_PRF).forge(pk);
    
    is_valid <@ SPHINCS_PLUS_FS.verify(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWFS_PRF.fresh(m');
    
    return is_valid /\ is_fresh;
  }
}.

(* 
  EUF-CMA for SPHINCS+-TW, but with pregenerated secret keys obtained by sampling
  and a random function for message key generation
*)
local module EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF = {
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var is_valid : bool;
    var is_fresh : bool;
    
    (pk, sk) <@ SPHINCS_PLUS_FS.keygen_nprf();
    
    O_CMA_SPHINCSPLUSTWFS_NPRF.init(sk);
    
    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWFS_NPRF).forge(pk);
    
    is_valid <@ SPHINCS_PLUS_FS.verify(pk, m', sig');
    is_fresh <@ O_CMA_SPHINCSPLUSTWFS_NPRF.fresh(m');
    
    return is_valid /\ is_fresh;
  }
}.

(* 
  EUF-CMA for SPHINCS+-TW, but with pregenerated secret keys obtained by sampling,
  a random fucntion for message key generation, and additional check for 
  a valid M-FORS-TW-ES-NPRF forgery inside the SPHINCS+-TW forgery
*)
local module EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V = {
  var valid_MFORSTWESNPRF : bool
  
  proc main() : bool = {
    var pk : pkSPHINCSPLUSTW;
    var sk : mseed * skFORS list list * skWOTS list list list * pseed;
    var m' : msg;
    var sig' : sigSPHINCSPLUSTW;
    var is_valid : bool;
    var is_fresh : bool;
    var ad : adrs;
    var skFORSnt : skFORS list list;
    var ps : pseed;
    var mk' : mkey;
    var sigFORSTW' : sigFORSTW;
    var sigFLSLXMSSMTTW' : sigFLSLXMSSMTTW;
    var cm : msgFORSTW;
    var idx : index;
    var tidx, kpidx : int;
    var pkFORS, pkFORS' : pkFORS;
    var skFORS : skFORS;
    var root, root' : dgstblock;
    
    (pk, sk) <@ SPHINCS_PLUS_FS.keygen_nprf();
    
    O_CMA_SPHINCSPLUSTWFS_NPRF.init(sk);
    
    (m', sig') <@ A(O_CMA_SPHINCSPLUSTWFS_NPRF).forge(pk);
    
    (* is_valid <@ SPHINCS_PLUS_FS.verify(pk, m', sig'); *)
    (root, ps) <- pk;
    (mk', sigFORSTW', sigFLSLXMSSMTTW') <- sig';
    ad <- adz;
    skFORSnt <- sk.`2;
    
    (cm, idx) <- mco mk' m';
    
    (tidx, kpidx) <- edivz (val idx) l';
    
    skFORS <- nth witness (nth witness skFORSnt tidx) kpidx;
    pkFORS <@ FL_FORS_ES_NPRF.gen_pkFORS(skFORS, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    
    pkFORS' <@ FL_FORS_ES.pkFORS_from_sigFORSTW(sigFORSTW', cm, ps, set_kpidx (set_tidx (set_typeidx ad trhftype) tidx) kpidx);
    
    valid_MFORSTWESNPRF <- pkFORS' = pkFORS;
    
    root' <@ FL_SL_XMSS_MT_ES.root_from_sigFLSLXMSSMTTW(pkFORS', sigFLSLXMSSMTTW', idx, ps, ad);
    
    is_valid <- root' = root;
    is_fresh <@ O_CMA_SPHINCSPLUSTWFS_NPRF.fresh(m');
        
    return is_valid /\ is_fresh;
  }
}.


(* ---- Equivalences between security properties ---- *)
local equiv Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF :
  EUF_CMA(SPHINCS_PLUS, A, O_CMA_Default).main ~ EUF_CMA_SPHINCSPLUSTWFS_PRFPRF.main : 
    ={glob A} ==> ={res}.
proof.
proc.
seq 3 3 : (   ={pk}
           /\ m{1} = m'{2}
           /\ sig{1} = sig'{2}
           /\ ={qs}(O_CMA_Default, O_CMA_SPHINCSPLUSTWFS_PRF)); 2: by sim.
inline{1} 1; inline{2} 1.
inline{1} 5.
seq 4 8 : (   ={glob A, ad, ms, ss, ps}
           /\ ad{1} = adz
           /\ (forall (i j u v : int),
                 0 <= i && i < nr_trees 0 =>
                 0 <= j && j < l' =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (val (nth witness (nth witness skFORSnt{2} i) j)) u) v =
                 skg ss{1}
                   (ps{1}, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))) 
           /\ (forall (i j u v : int),
                0 <= i && i < d =>
                0 <= j && j < nr_trees i =>
                0 <= u && u < l' =>
                0 <= v && v < len =>
                nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v =
                skg ss{1}
                  (ps{1}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ while{2} (    ad{2} = adz
            /\ (forall (i j u v : int),
                  0 <= i && i < size skWOTStd{2} =>
                  0 <= j && j < nr_trees i =>
                  0 <= u && u < l' =>
                  0 <= v && v < len =>
                  nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} i) j) u)) v =
                  skg ss{2}
                    (ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0)))
           (d - size skWOTStd{2}).
  - move=> _ z.
    wp => /=.
    while (    ad = adz
           /\ (forall (j u v : int),
                 0 <= j && j < size skWOTSnt =>
                 0 <= u && u < l' =>
                 0 <= v && v < len =>
                 nth witness (val (nth witness (nth witness skWOTSnt j) u)) v =
                 skg ss
                     (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) j) chtype) u) v) 0)))
          (nr_trees (size skWOTStd) - size skWOTSnt).
    * move=> z'.
      wp => /=.
      while (    ad = adz
             /\ (forall (u v : int),
                   0 <= u && u < size skWOTSlp =>
                   0 <= v && v < len =>
                   nth witness (val (nth witness skWOTSlp u)) v =
                   skg ss
                       (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) (size skWOTSnt)) chtype) u) v) 0)))
            (l' - size skWOTSlp).
      + move=> z''.
        wp => /=.
        while (    ad = adz
               /\ (forall (v : int),
                     0 <= v && v < size skWOTS =>
                     nth witness skWOTS v =
                     skg ss
                         (ps, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz (size skWOTStd) (size skWOTSnt)) chtype) (size skWOTSlp)) v) 0))
               /\ size skWOTS <= len)
              (len - size skWOTS).
        - move=> z'''.
          by wp; skip => />; smt(nth_rcons size_rcons).
        wp; skip => /> &2 nthsklp ltl_szsklp.
        split => [| skw]; 2: split => [| /lezNgt gelen_szskw]; 1,2: smt(ge2_len).
        move=> nthskw lelen_skw; split; 2: by rewrite size_rcons /#.
        move=> u v ge0_u; rewrite nth_rcons ?size_rcons /= => ltsz1_u ge0_v ltlen_v.
        by case (u < size skWOTSlp{2}); smt(DBLL.insubdK DBLL.valP).
      wp; skip => /> &2 nthsknt ltl_szsknt. 
      split => [/# | skwlp]; split => [/# | /lezNgt gelp_szskwlp ?]. 
      by split; smt(nth_rcons size_rcons).
    wp; skip => /> &2 nthsktd ltd_szsktd.
    split => [/# | skwlp]; split => [/# | /lezNgt gent_szskwnt ?]. 
    by split; smt(nth_rcons size_rcons).
  wp => /=.
  while{2} (    ad{2} = adz
            /\ (forall (i j u v : int),
                 0 <= i && i < size skFORSnt{2} =>
                 0 <= j && j < l' =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (val (nth witness (nth witness skFORSnt{2} i) j)) u) v =
                 skg ss{2}
                   (ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v))))
           (nr_trees 0 - size skFORSnt{2}).
  - move => _ z.
    wp => /=.
    while (   ad = adz
           /\ (forall (j u v : int),
                 0 <= j && j < size skFORSlp =>
                 0 <= u && u < k =>
                 0 <= v && v < t =>
                 nth witness (nth witness (val (nth witness skFORSlp j)) u) v =
                 skg ss
                   (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) j) 0 (u * t + v))))
          (l' - size skFORSlp).
    * move=> z'.
      wp => /=.
      while (   ad = adz
             /\ (forall (u v : int),
                   0 <= u && u < size skFORS =>
                   0 <= v && v < t =>
                   nth witness (nth witness skFORS u) v =
                   skg ss
                     (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) (size skFORSlp)) 0 (u * t + v)))
             /\ all (fun ls => size ls = t) skFORS
             /\ size skFORS <= k)
            (k - size skFORS).
      + move=> z''.
        wp => /=.
        while (   ad = adz
               /\ (forall (v : int),
                     0 <= v && v < size skFORSet =>
                     nth witness skFORSet v =
                     skg ss
                       (ps, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size skFORSnt)) (size skFORSlp)) 0 (size skFORS * t + v)))
               /\ size skFORSet <= t)
            (t - size skFORSet).
        - move=> z'''.
          by wp; skip => />; smt(nth_rcons size_rcons).
        by wp; skip => />; smt(ge2_t nth_rcons size_rcons cats1 all_cat).  
      by wp; skip => />; smt(nth_rcons size_rcons ge1_k DBLLKTL.valP DBLLKTL.insubdK).
    by wp; skip => />; smt(nth_rcons size_rcons).
  wp; do 3! rnd.
  wp; skip => /> ms msin ss ssin ps psin.
  by do 5! (split => [/# | *]) => /#.
call (:   ={qs}(O_CMA_Default, O_CMA_SPHINCSPLUSTWFS_PRF)
       /\ O_CMA_Default.sk{1}.`1 = O_CMA_SPHINCSPLUSTWFS_PRF.sk{2}.`1
       /\ O_CMA_Default.sk{1}.`3 = O_CMA_SPHINCSPLUSTWFS_PRF.sk{2}.`4 
       /\ (forall (i j u v : int),
             0 <= i && i < nr_trees 0 =>
             0 <= j && j < l' =>
             0 <= u && u < k =>
             0 <= v && v < t =>
             nth witness (nth witness (val (nth witness (nth witness O_CMA_SPHINCSPLUSTWFS_PRF.sk{2}.`2 i) j)) u) v =
             skg O_CMA_Default.sk{1}.`2
               (O_CMA_Default.sk{1}.`3, set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)))
       /\ (forall (i j u v : int),
            0 <= i && i < d =>
            0 <= j && j < nr_trees i =>
            0 <= u && u < l' =>
            0 <= v && v < len =>
            nth witness (val (nth witness (nth witness (nth witness O_CMA_SPHINCSPLUSTWFS_PRF.sk{2}.`3 i) j) u)) v =
            skg O_CMA_Default.sk{1}.`2
              (O_CMA_Default.sk{1}.`3, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx adz i j) chtype) u) v) 0))).
+ proc.
  rewrite equiv [{1} 1 Eqv_SPHINCS_PLUS_S_sign].
  inline{1} 1.
  wp.
  conseq (: _ ==> ={mk, sigFORSTW, sigFLSLXMSSMTTW}) => //.
  inline{1} 9; inline{2} 9.
  wp => /=.
  while (   ={sapl, root, tidx0, kpidx0, ps0, ad0}
         /\ O_CMA_Default.sk{1} = (ms, ss0, ps0){1}
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{2} = (ms, skFORSnt, skWOTStd0, ps0){2}
         /\ ad0{1} = adz
         /\ 0 <= tidx0{1} < nr_trees (size sapl{1} - 1)
         /\ 0 <= kpidx0{1} < l'
         /\ size sapl{1} <= d
         /\ #pre).
  - inline{1} 3; inline{2} 5.
    wp => />.
    while (   ={leaves0, ad1, ps1}
           /\ ss1{1} = ss0{1}
           /\ ad1{1} = set_ltidx ad0{1} (size sapl{1}) tidx0{1}
           /\ ps1{1} = ps0{1}
           /\ skWOTSl{2} = nth witness (nth witness skWOTStd0{2} (size sapl{2})) tidx0{2}
           /\ 0 <= tidx0{2} < nr_trees (size sapl{2})
           /\ size leaves0{1} <= l'
           /\ #pre).
    * inline{1} 2; inline{1} 1; inline{2} 2.
      wp => />.
      while (   ={ps2, ad2, pkWOTS0}
             /\ skWOTS1{1} = skWOTS2{2}
             /\ size pkWOTS0{1} <= len).
      - by wp; skip => />; smt(size_rcons).
      wp => />; 1: smt().
      while{1} (   (forall (i : int), 0 <= i < size skWOTS2{1} =>
                     nth witness skWOTS2{1} i 
                     =
                     skg ss2{1} (ps3{1}, set_hidx (set_chidx ad3{1} i) 0))
                /\ size skWOTS2{1} <= len)
           (len - size skWOTS2{1}).
      - move=> _ z.
        by wp; skip => />; smt(nth_rcons size_rcons).
      wp; skip => /> &1 &2 ge0_tidx ltnt_tidx _ _ ltnt1_tidx ge0_kpidx ltlp_kpidx _ nthskf nthskw ltd_szsapl ltlp_szlfs.
      split => [| skw]; 1: smt(ge2_len).
      split => [/# | /lezNgt gelen_szskw nthskwp lelen_szskw].
      split; 2: smt(size_rcons).
      split; 2: smt(ge2_len).
      rewrite &(DBLL.val_inj) &(eq_from_nth witness) ?valP //= => i rng_i.
      by rewrite insubdK 1:/# nthskwp 1:/# nthskw 1:size_ge0.
    inline{1} 2; inline{2} 4.
    wp => /=.
    while (   ={ps2, ad2, em} 
           /\ sig2{1} = sig0{2}
           /\ skWOTS1{1} = skWOTS2{2}
           /\ size sig2{1} <= len).
    * by wp; skip => />; smt(size_rcons).
    inline{1} 8.
    wp => /=.
    while{1} (   (forall (i : int), 0 <= i < size skWOTS2{1} =>
                   nth witness skWOTS2{1} i 
                   =
                   skg ss3{1} (ps3{1}, set_hidx (set_chidx ad3{1} i) 0))
              /\ size skWOTS2{1} <= len)
         (len - size skWOTS2{1}).
    * move=> _ z. 
      by wp; skip => />; smt(nth_rcons size_rcons).
    wp; skip => /> &1 &2 ge0_tidx ltnt1_tidx ge0_kpidx ltlp_kpidx _ nthskf nthskw ltd_szsapl.
    split => [| skw]; 1: smt(ge2_len).
    split => [/# | /lezNgt gelen_szskw nthskwp lelen_szskw].
    split => [| sigw /lezNgt gelen_szsigw _ eqins_skw lelen_szsigw].
    * split; 2: smt(ge2_len).
      rewrite &(DBLL.val_inj) &(eq_from_nth witness) ?valP //= => i rng_i.
      rewrite insubdK 1:/# nthskwp 1:/# nthskw 1:size_ge0 //=.
      + rewrite divz_ge0 2:ge0_tidx 2:ltz_divLR /=; 1,2: smt(ge2_lp).
        by rewrite /nr_trees /l' -exprD_nneg 1:mulr_ge0; smt(ge1_hp ge1_d).
      by rewrite modz_ge0 2:ltz_pmod; smt(ge2_lp).
    split => [| lfs]; 2: smt(size_rcons).
    rewrite modz_ge0 2:ltz_pmod /=; 1,2: smt(ge2_lp).
    rewrite divz_ge0 2:ge0_tidx 2:(: 0 <= l') /=; 1,2: smt(ge2_lp).
    rewrite ltz_divLR 2:(: nr_trees (size sapl{2}) * l' =  nr_trees (size sapl{2} - 1)); 1: smt(ge2_lp).
    - by rewrite /nr_trees /l' -exprD_nneg 1:mulr_ge0; smt(ge1_hp ge1_d).
    by rewrite ltnt1_tidx /= (IntOrder.ler_lt_trans tidx0{2}) //= leq_div //; smt(ge2_lp).
  inline{1} 8; inline{2} 8.
  wp => /=.
  while (   ={roots, ad, ps1, ad1, tidx, kpidx}
         /\ O_CMA_Default.sk{1} = (ms, ss1, ps1){1}
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{2} = (ms, skFORSnt, skWOTStd, ps1){2}
         /\ ad1{1} = set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{1}) kpidx{1}
         /\ skFORS0{2} = nth witness (nth witness skFORSnt{2} tidx{2}) kpidx{2}
         /\ 0 <= tidx{2} < nr_trees 0
         /\ 0 <= kpidx{2} < l'
         /\ size roots{1} <= k
         /\ #pre).
  - inline{1} 1; inline{2} 1.
    wp => />.
    while (   ={leaves1, ps2, ad2, idxt}
           /\ ss2{1} = ss1{1}
           /\ ps2{1} = ps1{1}
           /\ size leaves1{1} <= t
           /\ ad2{2} = ad1{2}
           /\ skFORS1{2} = skFORS0{2}
           /\ 0 <= idxt{1} < k
           /\ #pre).
    * wp; skip => /> &1 &2 _ ge0_idxt ltk_idxt ge0_tidx ltnt_tidx ge0_kpidx ltlp_kpidx _ nthskf nthskw ltk_szrs ltt_szlfs.
      rewrite -!andbA; split; 2: by smt(size_rcons).
      by do 3! congr; rewrite nthskf.    
    by wp; skip => />; smt(ge2_t size_rcons size_ge0).
  inline{1} 5; inline{1} 11; inline{2} 7.
  wp => /=. 
  while (   tidx{2} = (val idx{2}) %/ l'
         /\ kpidx{2} = (val idx{2}) %% l'
         /\ O_CMA_Default.sk{1} = (ms, ss2, ps2){1}
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{2} = (ms, skFORSnt, skWOTStd, ps2){2}
         /\ sig3{1} = sig0{2}
         /\ m3{1} = m1{2}
         /\ idx1{1} = idx{2}
         /\ ad3{1} = ad2{2}
         /\ ps3{1} = ps2{2}
         /\ ss3{1} = ss2{1}
         /\ skFORS1{2} = nth witness (nth witness skFORSnt{2} tidx{2}) kpidx{2}
         /\ ad2{2} = set_kpidx (set_tidx (set_typeidx adz trhftype) tidx{2}) kpidx{2}
         /\ 0 <= tidx{2} < nr_trees 0
         /\ 0 <= kpidx{2} < l'
         /\ size sig3{1} <= k
         /\ #pre).
  - inline{1} 4; inline{2} 4.
    wp => />.
    while (  ={leaves2, idxt}
           /\ idxt{1} = size sig3{1}
           /\ skFORS2{2} = skFORS1{2}
           /\ ss4{1} = ss3{1}
           /\ ps4{1} = ps3{1}
           /\ ps4{1} = ps3{2}
           /\ ad4{1} = ad3{1}
           /\ ad4{1} = ad3{2}
           /\ size leaves2{1} <= t
           /\ #pre).
    * by wp; skip => />; smt(size_ge0 size_rcons).
    wp; skip => /> ? ? ? ? ? ? ? nthskf *.
    split=> [| lfs /lezNgt get_lfs _ let_lfs]; 1: smt(ge2_t).
    rewrite -!andbA; split; 2: smt(size_rcons).
    do 2! congr; rewrite nthskf // bs2int_ge0 /=.
    pose ls := rev _; rewrite (IntOrder.ltr_le_trans (2 ^ size ls)) 1:bs2int_le2Xs //.
    apply IntOrder.ler_weexpn2l => //. 
    rewrite size_ge0 /= /ls size_rev size_take 2:size_drop; 1,2: smt(ge1_a size_ge0). 
    by rewrite ?valP /#. 
  wp; skip => /> &1 &2 ? ? /= nthskf nthskw *.
  split; 2: smt(ge1_k ge2_lp ge1_d Index.valP).
  rewrite !andbA -4!andbA; split => [/#| ].
  rewrite divz_ge0 2:modz_ge0 3:ltz_pmod 4:ltz_divLR /=; 1..4: smt(ge2_lp).
  by rewrite /nr_trees /= /l' -exprD_nneg; smt(ge1_hp ge1_d ge1_k Index.valP).
inline{1} 10; inline{2} 7.
inline{1} 4; inline{2} 2.
sp 6 4; wp => />.
while (   ={leaves0}
       /\ size leaves0{1} <= l'
       /\ #pre).
+ wp; call (: true); 1: by sim.
  inline{1} 1.
  wp => /=.
  while{1} (   (forall (i : int), 0 <= i < size skWOTS0{1} =>
                 nth witness skWOTS0{1} i 
                 =
                 skg ss2{1} (ps2{1}, set_hidx (set_chidx ad2{1} i) 0))
            /\ size skWOTS0{1} <= len)
           (len - size skWOTS0{1}).
  + move=> _ z.
    by wp; skip => />; smt(nth_rcons size_rcons).
  wp; skip => /> &2 _ nthskf nthskw ltlen_szlfs.
  split=> [| skw]; 1: smt(ge2_len). 
  split => [/# |/lezNgt gelen_szskw nthskwp lelen_szskw].
  split; 2: smt(size_rcons).
  rewrite &(DBLL.val_inj) &(eq_from_nth witness) ?valP // => i rng_i. 
  by rewrite insubdK 1:/# 1:nthskwp 1:/# nthskw //; smt(ge1_d IntOrder.expr_gt0).
by wp; skip => />; smt(ge2_lp).
qed.

local equiv Eqv_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V :
  EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF.main ~ EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.main : 
    ={glob A} ==> ={res}.
proof. 
proc.
swap{1} 5 -1; swap{2} 16 -12.
seq 4 4 : (={is_fresh, m', sig', pk, sk}); 1: by sim.
inline{1} 1; inline{2} 8.
wp; sp => />.
conseq (: _ ==> ={root, root'}) => //.
seq 0 1 : (   ={root, ps, idx, cm, ad, tidx, kpidx}
           /\ sigFORSTW{1} = sigFORSTW'{2}
           /\ sigFLSLXMSSMTTW{1} = sigFLSLXMSSMTTW'{2}); 2: by sim.
while{2} (true) (k - size roots{2}).
+ move=> _ z.
  inline 1.
  wp => /=.
  while (true) (t - size leaves0).
  - move=> z0.
    by wp; skip => />; smt(size_rcons).
  by wp; skip => />; smt(size_rcons).     
by wp; skip => /> &1 &2 <- + /= [-> ->] => <- /= [-> ->]; smt(ge1_k).
qed.


(* --- FL-SL-XMSS-MT-TW-ES-NPRF -- *)
(* 
  EUF-NAGCMA for FL-SL-XMSS-MT-TW-ES-NPRF (with specific oracles), 
  but with some local variables as module variables
*)
local module EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV = {
  var skWOTStd : skWOTS list list list
  
  proc main() : bool = {
    var ad : adrs;
    var ps : pseed;
    var pk : pkFLSLXMSSMTTW;
    var sk : skWOTS list list list * pseed * adrs;
    var ml : msgFLSLXMSSMTTW list;
    var sigl : sigFLSLXMSSMTTW list;
    var m : msgFLSLXMSSMTTW;
    var m' : msgFLSLXMSSMTTW;
    var sig : sigFLSLXMSSMTTW;
    var sig' : sigFLSLXMSSMTTW;
    var idx' : index;
    var is_valid : bool;
    var is_fresh : bool;
    var adsOC : adrs list;
    
    ad <- adz;
    ps <$ dpseed;
    FSSLXMTWES.TRHC.O_THFC_Default.init(ps);
    ml <@ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A, FSSLXMTWES.TRHC.O_THFC_Default).choose();
    (pk, sk) <@ FL_SL_XMSS_MT_ES_NPRF.keygen(ps, ad);
    
    skWOTStd <- sk.`1;
     
    sigl <- [];
    while (size sigl < l){
      m <- nth witness ml (size sigl);
      sig <@ FL_SL_XMSS_MT_ES_NPRF.sign((skWOTStd, sk.`2, sk.`3), m, insubd (size sigl));
      sigl <- rcons sigl sig;
    }
    
    (m', sig', idx') <@ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A, FSSLXMTWES.TRHC.O_THFC_Default).forge(pk, sigl);
    is_valid <@ FL_SL_XMSS_MT_ES_NPRF.verify(pk, m', sig', idx');
    is_fresh <- m' <> nth witness ml (val idx');
    
    return is_valid /\ is_fresh;
  }
}.

(* ---- Equivalences between security properties ---- *)
local equiv Eqv_EUF_NAGCMA_FLSLXMSSMTTWESNPRF_Orig_RV :
  EUF_NAGCMA_FLSLXMSSMTTWESNPRF(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A), FSSLXMTWES.TRHC.O_THFC_Default).main
  ~
  EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.main :
    ={glob A} ==> ={res}.
proof.
proc.
seq 7 8 : (={glob A, pk, ml, sigl, R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt}); 2: by sim.
while (={sigl, ml} /\ sk{1} = (EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.skWOTStd, sk.`2, sk.`3){2}).
+ conseq (: _ ==> ={ml, sigl}) => //.
  wp; call (: true); 1: by sim.
  by wp.
swap{2} 6 1; wp 6 6 => /=.
conseq (: _ ==> ={pk, sk, ml, sigl, R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt}); 1: smt().
by sim.
qed.


(* -- Steps -- *)
(* 
  Equality of advantage (of given adversary) against auxiliary EUF-CMA properties for SPHINCS+-TW 
  and advantage (of reduction adversary) against the PRF property of skg  
*)
local lemma EqAdv_EUF_CMA_SPHINCSPLUSTWFS_PRFPRF_NPRFPRF_SKGPRF &m :
  `|  Pr[EUF_CMA_SPHINCSPLUSTWFS_PRFPRF.main() @ &m : res]
    - Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF.main() @ &m : res] |
  =
  `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA(A), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
    - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA(A), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |.
proof.
do 2! congr; 2: congr.
+ byequiv => //.
  proc.
  inline{2} 2; inline{1} 5; wp 6 18.
  seq 3 16 : (   ={pk, m', sig'}
              /\ ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_SKGPRF_EUFCMA)); 2: by sim.
  inline{1} 1; inline{2} 1.
  seq 8 14 : (   ={glob A, ad} 
               /\ ! SKG_PRF.O_PRF_Default.b{2}
               /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
               /\ ms{1} = R_SKGPRF_EUFCMA.ms{2} 
               /\ ps{1} = R_SKGPRF_EUFCMA.ps{2} 
               /\ skFORSnt{1} = R_SKGPRF_EUFCMA.skFORSnt{2}
               /\ skWOTStd{1} = R_SKGPRF_EUFCMA.skWOTStd{2}
               /\ R_SKGPRF_EUFCMA.qs{2} = []).
  - sp 0 2 => />.
    while (   ! SKG_PRF.O_PRF_Default.b{2}
           /\ size skWOTStd{1} <= d
           /\ #post).
    * wp => /=.
      while (   ={skWOTSnt}
             /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})
             /\ #pre).
      + wp => />.
        while (   ={skWOTSlp}
               /\ size skWOTSlp{1} <= l'
               /\ #pre).
        - wp => />.
          while (   ={skWOTS}
                 /\ size skWOTS{1} <= len
                 /\ #pre).
          * inline{2} 1.
            rcondf{2} 2; 1: by auto.
            by wp; skip => />; smt(size_rcons).
          by wp; skip => />; smt(ge2_len size_rcons). 
        by wp; skip => />; smt(ge2_lp size_rcons). 
      by wp; skip => />; smt(size_rcons IntOrder.expr_ge0).
    wp => />.
    while (    ! SKG_PRF.O_PRF_Default.b{2}
            /\ size skFORSnt{1} <= nr_trees 0
            /\ #post).
    * wp => /=.
      while (   ={skFORSlp}
             /\ size skFORSlp{1} <= l'
             /\ #pre).
      + wp => />.
        while (   ={skFORS}
               /\ size skFORS{1} <= k
               /\ #pre).
        - wp => />.
          while (   ={skFORSet}
                 /\ size skFORSet{1} <= t
                 /\ #pre).
          * inline{2} 1.
            rcondf{2} 2; 1: by auto.
            by wp; skip => />; smt(size_rcons).
          by wp; skip => />; smt(ge2_t size_rcons). 
        by wp; skip => />; smt(ge1_k size_rcons). 
      by wp; skip => />; smt(size_rcons IntOrder.expr_ge0).
    wp => /=.
    swap{2} 1 5.
    do 3! rnd.
    by wp; skip => /> *; smt(ge1_d IntOrder.expr_ge0 mem_empty).
  call (:   ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_SKGPRF_EUFCMA)
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1} = (R_SKGPRF_EUFCMA.ms, R_SKGPRF_EUFCMA.skFORSnt, R_SKGPRF_EUFCMA.skWOTStd, R_SKGPRF_EUFCMA.ps){2}).
  - proc.
    sp 1 0; conseq />. 
    by sim.
  inline{1} 7.
  wp => />.
  by sim : (={leaves}).
byequiv => //.
proc.
inline{2} 2; inline{1} 5; wp 6 18.
seq 3 16 : (   ={pk, m', sig'}
            /\ ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_SKGPRF_EUFCMA)); 2: by sim.
inline{1} 1; inline{2} 1.
seq 8 14 : (   ={glob A, ad}
            /\ ad{2} = adz
            /\ SKG_PRF.O_PRF_Default.b{2}
            /\ ss{1} = SKG_PRF.O_PRF_Default.k{2}
            /\ ms{1} = R_SKGPRF_EUFCMA.ms{2} 
            /\ ps{1} = R_SKGPRF_EUFCMA.ps{2} 
            /\ skFORSnt{1} = R_SKGPRF_EUFCMA.skFORSnt{2}
            /\ skWOTStd{1} = R_SKGPRF_EUFCMA.skWOTStd{2}
            /\ R_SKGPRF_EUFCMA.qs{2} = []).
+ sp 0 2 => />.
  while (   SKG_PRF.O_PRF_Default.b{2}
         /\ (forall (psad : pseed * adrs),
              psad \in SKG_PRF.O_PRF_Default.m{2}
              <=>
              ((exists (i j u v : int), 
                  0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                  psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
               \/ 
               (exists (i j u v : int),
                  0 <= i < size R_SKGPRF_EUFCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                  psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))))
         /\ size skWOTStd{1} <= d
         /\ #post).
  - wp => /=.
    while (  ={skWOTSnt}
           /\ ad{2} = adz
           /\ SKG_PRF.O_PRF_Default.b{2}
           /\ skWOTStd{1} = R_SKGPRF_EUFCMA.skWOTStd{2}  
           /\ (forall (psad : pseed * adrs),
                psad \in SKG_PRF.O_PRF_Default.m{2}
                <=>
                ((exists (i j u v : int), 
                    0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                    psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                 \/ 
                 (exists (i j u v : int),
                    0 <= i < size R_SKGPRF_EUFCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                    psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                 \/ (exists (j u v : int),
                     0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                      psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size R_SKGPRF_EUFCMA.skWOTStd{2}) j) chtype) u) v) 0))))
           /\ size skWOTStd{1} < d
           /\ size skWOTSnt{1} <= nr_trees (size skWOTStd{1})).
    * wp => /=.
      while (  ={skWOTSnt, skWOTSlp}
             /\ ad{2} = adz
             /\ SKG_PRF.O_PRF_Default.b{2}
             /\ skWOTStd{1} = R_SKGPRF_EUFCMA.skWOTStd{2}  
             /\ (forall (psad : pseed * adrs),
                  psad \in SKG_PRF.O_PRF_Default.m{2}
                  <=>
                  ((exists (i j u v : int), 
                      0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                      psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                   \/ 
                   (exists (i j u v : int),
                      0 <= i < size R_SKGPRF_EUFCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                      psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                   \/ (exists (j u v : int),
                       0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size R_SKGPRF_EUFCMA.skWOTStd{2}) j) chtype) u) v) 0))
                   \/ (exists (u v : int),
                       0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size R_SKGPRF_EUFCMA.skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))))
             /\ size skWOTStd{1} < d
             /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
             /\ size skWOTSlp{1} <= l').
      + wp => /=.
        while (  ={skWOTSnt, skWOTSlp, skWOTS}
               /\ ad{2} = adz
               /\ SKG_PRF.O_PRF_Default.b{2}
               /\ skWOTStd{1} = R_SKGPRF_EUFCMA.skWOTStd{2}  
               /\ (forall (psad : pseed * adrs),
                    psad \in SKG_PRF.O_PRF_Default.m{2}
                    <=>
                    ((exists (i j u v : int), 
                        0 <= i < nr_trees 0 /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                     \/ 
                     (exists (i j u v : int),
                        0 <= i < size R_SKGPRF_EUFCMA.skWOTStd{2} /\ 0 <= j < nr_trees i /\ 0 <= u < l' /\ 0 <= v < len /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} i j) chtype) u) v) 0))
                     \/ (exists (j u v : int),
                         0 <= j < size skWOTSnt{2} /\ 0 <= u < l' /\ 0 <= v < len /\ 
                          psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size R_SKGPRF_EUFCMA.skWOTStd{2}) j) chtype) u) v) 0))
                     \/ (exists (u v : int),
                         0 <= u < size skWOTSlp{2} /\ 0 <= v < len /\ 
                          psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size R_SKGPRF_EUFCMA.skWOTStd{2}) (size skWOTSnt{2})) chtype) u) v) 0))
                     \/ (exists (v : int),
                         0 <= v < size skWOTS{2} /\ 
                          psad = (R_SKGPRF_EUFCMA.ps{2}, set_hidx (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} (size R_SKGPRF_EUFCMA.skWOTStd{2}) (size skWOTSnt{2})) chtype) (size skWOTSlp{2})) v) 0))))
               /\ size skWOTStd{1} < d
               /\ size skWOTSnt{1} < nr_trees (size skWOTStd{1})
               /\ size skWOTSlp{1} < l'
               /\ size skWOTS{1} <= len).
        - inline{2} 1.
          rcondt{2} 2; 1: by auto.
          rcondt{2} 2.
          * auto => /> &2 bt mdom *.
            pose psad := (_, set_hidx _ _).
            move/iffLR /contra: (mdom psad) => -> //=.
            have adsz : forall (x : adrs), size (val x) = adrs_len by smt(Adrs.valP).  
            rewrite ?negb_or; split.            
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -eq_adrs_idxsq negb_forall /=; exists 3 => @/eq_idx.
              rewrite setalladzch_gettypeidx 1..4:// setalladztrhf_gettypeidx //; 2: smt(Top.dist_adrstypes). 
              rewrite /valid_tbfidx /nr_nodesf /=; split => [/# | _].
              by rewrite (: k = k - 1 + 1) // mulzDl /= -/t ler_lt_add 1:ler_pmul 4://; smt(ge2_t).               
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -eq_adrs_idxsq negb_forall /=; exists 5 => @/eq_idx.
              by rewrite ?setalladzch_getlidx 1..8:// /#. 
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -eq_adrs_idxsq negb_forall /=; exists 4 => @/eq_idx.
              by rewrite ?setalladzch_gettidx 1..8:// /valid_tidx /#.        
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -eq_adrs_idxsq negb_forall /=; exists 2 => @/eq_idx.
              by rewrite ?setalladzch_getkpidx 1..8:// /valid_tidx /#.
            do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
            rewrite -eq_adrs_idxsq negb_forall /=; exists 1 => @/eq_idx.
            by rewrite ?setallchadz_getchidx 1..8:// /valid_tidx /#.  
          wp; rnd; wp; skip => /> &2 bt mdom *.
          rewrite -!andbA andbA; split; 2: smt(size_rcons).
          rewrite get_set_sameE oget_some /= => psad.
          split => [/mem_set [| -> /=]|]; 1,2: smt(size_ge0 size_rcons).
          move=> mdomrc; rewrite mem_set /=.
          pose psad' := (_, set_hidx _ _).
          case (psad \in SKG_PRF.O_PRF_Default.m{2}) => [// | /= ninm].
          move/iffRL /contra: (mdom psad) mdomrc => /(_ ninm) /=.
          rewrite ?negb_or => [#] -> -> -> -> /=; rewrite negb_exists => /= ninskw /=.
          move=> -[v]; rewrite size_rcons => -[rng_v psadval /=].
          case (v = size skWOTS{2}) => [ // | neqszv].
          by move: (ninskw v); rewrite negb_and (: 0 <= v && v < size skWOTS{2}) /#.
        wp; skip => /> &2 *.
        split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_len).
        split => [psad |]; 2: smt(size_rcons).
        by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
      wp; skip => /> &2 *.
      split => [* | psdbmap skw ? _ psdbmapdef ?]; 1: smt(ge2_lp).
      split => [psad |]; 2: smt(size_rcons).
      by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
    wp; skip => /> &2 bT mdef _ ltd_szsktd.
    split => [ * | psdbmap skw ? _ psdbmapdef ?]; 1: rewrite expr_ge0 1:// 1:/=.
    * by move => psad; split => [/mdef |] /#.
    split => [psad |]; 2: smt(size_rcons).
    by split => [/psdbmapdef | ]; smt(size_rcons size_ge0).
  wp => /=.
  while (   SKG_PRF.O_PRF_Default.b{2}
         /\ ad{2} = adz
         /\ skFORSnt{1} = R_SKGPRF_EUFCMA.skFORSnt{2}
         /\ (forall (psad : pseed * adrs),
              psad \in SKG_PRF.O_PRF_Default.m{2}
              <=>
              (exists (i j u v : int), 
                  0 <= i < size R_SKGPRF_EUFCMA.skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                  psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v))))
         /\ size skFORSnt{1} <= nr_trees 0).
  - wp => /=.
    while (   ={skFORSlp} 
           /\ ad{2} = adz
           /\ SKG_PRF.O_PRF_Default.b{2}
           /\ skFORSnt{1} = R_SKGPRF_EUFCMA.skFORSnt{2}
           /\ (forall (psad : pseed * adrs),
                psad \in SKG_PRF.O_PRF_Default.m{2}
                <=>
                ((exists (i j u v : int), 
                    0 <= i < size R_SKGPRF_EUFCMA.skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                    psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                 \/
                 (exists (j u v : int), 
                    0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                    psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size R_SKGPRF_EUFCMA.skFORSnt{2})) j) 0 (u * t + v)))))
           /\ size skFORSnt{1} < nr_trees 0
           /\ size skFORSlp{1} <= l').
    * wp => /=.
      while (   ={skFORSlp, skFORS}
             /\ ad{2} = adz 
             /\ SKG_PRF.O_PRF_Default.b{2}
             /\ skFORSnt{1} = R_SKGPRF_EUFCMA.skFORSnt{2}
             /\ (forall (psad : pseed * adrs),
                  psad \in SKG_PRF.O_PRF_Default.m{2}
                  <=>
                  ((exists (i j u v : int), 
                      0 <= i < size R_SKGPRF_EUFCMA.skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                      psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                   \/
                   (exists (j u v : int), 
                      0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                      psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size R_SKGPRF_EUFCMA.skFORSnt{2})) j) 0 (u * t + v)))
                   \/
                   (exists (u v : int), 
                     0 <= u < size skFORS{2} /\ 0 <= v < t /\ 
                      psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size R_SKGPRF_EUFCMA.skFORSnt{2})) (size skFORSlp{2})) 0 (u * t + v)))))
             /\ size skFORSnt{1} < nr_trees 0
             /\ size skFORSlp{1} < l'
             /\ size skFORS{1} <= k).
      + wp => /=.
        while (   ={skFORSlp, skFORS, skFORSet} 
               /\ ad{2} = adz
               /\ SKG_PRF.O_PRF_Default.b{2}
               /\ skFORSnt{1} = R_SKGPRF_EUFCMA.skFORSnt{2}
               /\ (forall (psad : pseed * adrs),
                    psad \in SKG_PRF.O_PRF_Default.m{2}
                    <=>
                    ((exists (i j u v : int), 
                        0 <= i < size R_SKGPRF_EUFCMA.skFORSnt{2} /\ 0 <= j < l' /\ 0 <= u < k /\ 0 <= v < t /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) i) j) 0 (u * t + v)))
                     \/
                     (exists (j u v : int), 
                        0 <= j < size skFORSlp{2} /\ 0 <= u < k /\ 0 <= v < t /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size R_SKGPRF_EUFCMA.skFORSnt{2})) j) 0 (u * t + v)))
                     \/
                     (exists (u v : int), 
                       0 <= u < size skFORS{2} /\ 0 <= v < t /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size R_SKGPRF_EUFCMA.skFORSnt{2})) (size skFORSlp{2})) 0 (u * t + v)))
                     \/ 
                     (exists (v : int),
                       0 <= v < size skFORSet{2} /\ 
                        psad = (R_SKGPRF_EUFCMA.ps{2}, set_thtbidx (set_kpidx (set_tidx (set_typeidx ad{2} trhftype) (size R_SKGPRF_EUFCMA.skFORSnt{2})) (size skFORSlp{2})) 0 ((size skFORS{2}) * t + v)))))
               /\ size skFORSnt{1} < nr_trees 0
               /\ size skFORSlp{1} < l'
               /\ size skFORS{1} < k
               /\ size skFORSet{1} <= t).
        - inline *.
          rcondt{2} 2; 1: by auto.
          rcondt{2} 2.
          * auto => /> &2 bt mdom *.
            pose psad := (_, set_thtbidx _ _ _).
            move/iffLR /contra: (mdom psad) => -> //=.
            rewrite ?negb_or; split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -eq_adrs_idxsq negb_forall /=; exists 4 => @/eq_idx.
              rewrite ?setalladztrhf_gettidx 1,2,5:// 2,4:/#.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -eq_adrs_idxsq negb_forall /=; exists 2 => @/eq_idx.
              rewrite ?setalladztrhf_getkpidx 1,2,4:// 2,4:/#.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            split.
            + do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
              rewrite -eq_adrs_idxsq negb_forall /=; exists 0 => @/eq_idx.              
              rewrite ?setalladztrhf_getbidx 1,2,4,5://.
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              - rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
                rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
                by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
              rewrite neq_ltz; right.
              rewrite (: size skFORS{m0} = size skFORS{m0} - 1 + 1) 1:// mulzDl /= -addrA.
              rewrite ler_lt_add 1:ler_pmul 4://; 1..3: smt(ge1_a).
              by rewrite -addr0 ltr_le_add; 1: smt(size_ge0).
            do ? (rewrite negb_exists => ? /=); rewrite ?negb_and -?implybE => * @/psad /=.
            rewrite -eq_adrs_idxsq negb_forall /=; exists 0 => @/eq_idx.      
            rewrite ?setalladztrhf_getbidx 1,2,4,5://.
            + rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            + rewrite /valid_tbfidx; split => [| _]; 1: smt(size_ge0).
              rewrite /nr_nodesf /= -/t (: k = k - 1 + 1) 1:// mulzDl /=.
              by rewrite ler_lt_add 1:ler_pmul 4://; smt(size_ge0 ge2_t).
            by rewrite neq_ltz; right; rewrite ler_lt_add 1:// /#.
          wp; rnd; wp; skip => /> *.
          by rewrite get_set_sameE oget_some /=; smt(size_rcons size_ge0 mem_set).
        wp; skip => /> *. 
        split => *; 1: smt(ge2_t).
        by split; smt(size_rcons size_ge0). 
      by wp; skip => />; smt(size_rcons size_ge0 ge1_k).
    by wp; skip => />; smt(size_rcons size_ge0 ge2_lp).
  wp => /=.
  swap{2} 1 5.
  do 3! rnd.
  wp; skip => /> *. 
  split => [| skf psam]; 1: split => [ps |]; 2: by rewrite IntOrder.expr_ge0.
  - by rewrite mem_empty /= => i j u v /#.
  by move/lezNgt => gent0_szskf _ psamdef lent0_szskf; split; smt(ge1_d).
call (:   ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_SKGPRF_EUFCMA)
       /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1} = (R_SKGPRF_EUFCMA.ms, R_SKGPRF_EUFCMA.skFORSnt, R_SKGPRF_EUFCMA.skWOTStd, R_SKGPRF_EUFCMA.ps){2}).
+ proc.
  sp 1 0; conseq />. 
  by sim.
inline{1} 7.
wp => />.
by sim : (={leaves}).
qed.

(* 
  Equality of advantage (of given adversary) against auxiliary EUF-CMA properties for SPHINCS+-TW 
  and advantage (of reduction adversary) against the PRF property of mkg  
*)
local lemma EqAdv_EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF_NPRFNPRF_MKGPRF &m :
  `|  Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF.main() @ &m : res]
    - Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF.main() @ &m : res] |
  =
  `|  Pr[MKG_PRF.PRF(R_MKGPRF_EUFCMA(A), MKG_PRF.O_PRF_Default).main(false) @ &m : res]
    - Pr[MKG_PRF.PRF(R_MKGPRF_EUFCMA(A), MKG_PRF.O_PRF_Default).main(true) @ &m : res] |.
proof.
do 2! congr; 2: congr.
+ byequiv => //.
  proc.
  inline{1} 5; inline{1} 1; inline{2} 2; inline{2} 1.
  seq 8 12 : (   ={glob A}
              /\ ad{1} = R_MKGPRF_EUFCMA.ad{2}
              /\ ps{1} = R_MKGPRF_EUFCMA.ps{2} 
              /\ ms{1} = O_PRF_Default.k{2}
              /\ skFORSnt{1} = R_MKGPRF_EUFCMA.skFORSnt{2}
              /\ skWOTStd{1} = R_MKGPRF_EUFCMA.skWOTStd{2}
              /\ ! O_PRF_Default.b{2}
              /\ O_PRF_Default.m{2} = empty
              /\ R_MKGPRF_EUFCMA.qs{2} = []).
  - swap{2} [4..5] -1; sp 0 4 => />.
    swap{2} 4 -3.
    by sim.  
  wp 11 7.
  seq 8 5 : (   ={pk, m', sig'} 
             /\ ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_MKGPRF_EUFCMA)); 2: by sim.
  call (:   ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_MKGPRF_EUFCMA)
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1} = (O_PRF_Default.k, R_MKGPRF_EUFCMA.skFORSnt, R_MKGPRF_EUFCMA.skWOTStd, R_MKGPRF_EUFCMA.ps){2} 
         /\ ! O_PRF_Default.b{2}).
  - proc.
    inline{2} 2.
    rcondf{2} 3; 1: by auto.
    sp 1 0; wp => />.
    by sim.
  inline{1} 7.
  wp => />.
  by sim : (={leaves}).
byequiv => //.
proc.
inline{1} 5; inline{1} 1; inline{2} 2; inline{2} 1.
seq 8 12 : (   ={glob A}
            /\ ad{1} = R_MKGPRF_EUFCMA.ad{2}
            /\ ps{1} = R_MKGPRF_EUFCMA.ps{2} 
            /\ ms{1} = O_PRF_Default.k{2}
            /\ skFORSnt{1} = R_MKGPRF_EUFCMA.skFORSnt{2}
            /\ skWOTStd{1} = R_MKGPRF_EUFCMA.skWOTStd{2}
            /\ O_PRF_Default.b{2}
            /\ O_PRF_Default.m{2} = empty
            /\ R_MKGPRF_EUFCMA.qs{2} = []).
+ swap{2} [4..5] -1; sp 0 4 => />.
  swap{2} 4 -3.
  by sim.  
wp 11 7.
seq 8 5 : (   ={pk, m', sig'} 
           /\ ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_MKGPRF_EUFCMA)); 2: by sim.
call (:   ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, R_MKGPRF_EUFCMA)
       /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1} = (O_PRF_Default.k, R_MKGPRF_EUFCMA.skFORSnt, R_MKGPRF_EUFCMA.skWOTStd, R_MKGPRF_EUFCMA.ps){2} 
       /\ O_CMA_SPHINCSPLUSTWFS_NPRF.mmap{1} = O_PRF_Default.m{2}
       /\ O_PRF_Default.b{2}).
- proc.
  inline{2} 2.
  rcondt{2} 3; 1: by auto.
  swap{2} 2 - 1.
  sp 1 1; wp => />.
  by sim.
inline{1} 7.
wp => />.
by sim : (={leaves}).
qed.

(* 
  Success probability (of given adversary) against auxiliary EUF-CMA property of SPHINCS+-TW 
  bounded by success probability (of reduction adversary) against EUF-CMA OF M-FORS-TW-ES-NPRF  
*)
local lemma LeqPr_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_VT_MFORSTWESNPRF &m :
  Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.main() @ &m : res /\ EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.valid_MFORSTWESNPRF]
  <=
  Pr[EUF_CMA_MFORSTWESNPRF(R_MFORSTWESNPRFEUFCMA_EUFCMA(A), O_CMA_MFORSTWESNPRF).main() @ &m : res].
proof.
byequiv=> //.
proc.
inline{1} 1; inline{2} 5; inline{2} 4; inline{2} 3.
seq 4 4 : (   ={glob A, ps0}
           /\ ad0{1} = adz
           /\ ad0{2} = insubd [0; 0; 0; trhftype; 0; 0]).
+ wp; rnd.
  do 2! rnd{1}.
  by wp; skip.   
seq 2 3 : (   #pre
           /\ skFORSnt0{1} = skFORSs{2}
           /\ (forall (i j : int),
                 0 <= i < nr_trees 0 => 0 <= j < l' =>
                 let roots 
                     = 
                     mkseq (fun (u : int) => 
                             FTWES.val_bt_trh ps0{2} ((set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) i) j))
                                              (list2tree (mkseq (fun (v : int) => 
                                                            f ps0{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) i) j) 0 (u * t + v)) 
                                                                      (val (nth witness (nth witness (val (nth witness (nth witness skFORSs{2} i) j)) u) v))) t )) u) k in
                  nth witness (nth witness pkFORSs{2} i) j
                  =
                  trco ps0{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) i) j) trcotype) j) 
                       (flatten (map DigestBlock.val roots)))).
+ while(   skFORSnt0{1} = skFORSs{2}
        /\ ad0{2} = insubd [0; 0; 0; trhftype; 0; 0]
        /\ (forall (i j : int),
               0 <= i < size pkFORSs{2} => 0 <= j < l' =>
               let roots 
                   = 
                   mkseq (fun (u : int) => 
                           FTWES.val_bt_trh ps0{2} ((set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) i) j))
                                            (list2tree (mkseq (fun (v : int) => 
                                                          f ps0{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) i) j) 0 (u * t + v)) 
                                                                    (val (nth witness (nth witness (val (nth witness (nth witness skFORSs{2} i) j)) u) v))) t )) u) k in
                nth witness (nth witness pkFORSs{2} i) j
                =
                trco ps0{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) i) j) trcotype) j) 
                     (flatten (map DigestBlock.val roots)))
        /\ size skFORSs{2} = size pkFORSs{2}
        /\ size skFORSs{2} <= nr_trees 0).
  - wp => /=.
    while(   skFORSlp{1} = skFORSl{2}
          /\ skFORSnt0{1} = skFORSs{2}
          /\ ad0{2} = insubd [0; 0; 0; trhftype; 0; 0]
          /\ (forall (j : int),
                 0 <= j < size pkFORSl{2} =>
                 let roots 
                     = 
                     mkseq (fun (u : int) => 
                             FTWES.val_bt_trh ps0{2} ((set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) (size pkFORSs{2})) j))
                                              (list2tree (mkseq (fun (v : int) => 
                                                            f ps0{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) (size pkFORSs{2})) j) 0 (u * t + v)) 
                                                                      (val (nth witness (nth witness (val (nth witness skFORSl{2} j)) u) v))) t )) u) k in
                  nth witness pkFORSl{2} j
                  =
                  trco ps0{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx ad0{2} trhftype) (size pkFORSs{2})) j) trcotype) j) 
                       (flatten (map DigestBlock.val roots)))
          /\ size skFORSs{2} = size pkFORSs{2}
          /\ size skFORSs{2} < nr_trees 0
          /\ size skFORSl{2} = size pkFORSl{2}
          /\ size skFORSl{2} <= l').
    * inline{2} 2; inline{2} 1.
      wp => /=.
      while{2} (roots{2}
                =
                mkseq (fun (u : int) => 
                         FTWES.val_bt_trh ps1{2} ad1{2} (list2tree (mkseq (fun (v : int) => 
                                                            f ps1{2} (set_thtbidx ad1{2} 0 (u * t + v)) 
                                                                     (val (nth witness (nth witness (val skFORS0{2}) u) v))) t)) u) (size roots{2})
                /\ size roots{2} <= k)
               (k - size roots{2}).
      + move=> _ z. 
        inline 1. 
        wp => /=.
        while (leaves1
               =
               mkseq (fun (v : int) => 
                        f ps2 (set_thtbidx ad2 0 (idxt * t + v)) 
                          (val (nth witness (nth witness (val skFORS2) idxt) v))) (size leaves1)
              /\ size roots < k
              /\ size leaves1 <= t)
              (t - size leaves1).
        - move=> z'.
          wp; skip => /> &2 lfsdef ltk_szrs _ ltt_szlfs.
          by rewrite size_rcons mkseqS //=; smt(size_rcons size_ge0). 
        wp; skip => /> &2 rsdef _ ltk_szrs.
        split => [| lfs]; 1: by rewrite mkseq0; smt(ge2_t).
        split => [/#| /lezNgt get_szlfs lfsdef let_szlfs]. 
        rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
        rewrite -andbA; split => [| /#]. 
        by do 3! congr => /#.
      wp => /=. 
      while (   skFORS0{1} = skFORS1{2}
             /\ size skFORS0{1} <= k).
      + wp => /=.
        while (skFORSet{1} = skFORSt{2}).
        - by wp; rnd; skip.
        by wp; skip => />; smt(size_rcons).
      wp; skip => /> &2 nthpkf eqszskpknt ltnt_szsknt eqszskpkl _ ltlp_szskl. 
      split => [ | skf /lezNgt gek_szskf _ lek_szskf]; 1: smt(ge1_k).
      split => [| rs]; 1: by rewrite mkseq0 //; smt(ge1_k).
      split => [/# | /lezNgt gek_szrs rsdef lek_szrs].
      rewrite ?size_rcons; split => [j ge0_j ltsz1_j | /#].
      rewrite ?nth_rcons eqszskpkl; case (j < size pkFORSl{2}) => [ltsz | geqsz].
      + by rewrite nthpkf 1:// /#.
      rewrite (: j = size pkFORSl{2}) 1:/# /= eqszskpknt.
      do 2! congr. 
      + rewrite getsettrhf_kpidx 5://; 3,4: smt(size_ge0).
        - rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
          by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
        rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
        by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
      congr; rewrite rsdef (: size rs = k) 1:/#; congr.
      rewrite fun_ext => u.
      by do 3! congr; rewrite fun_ext => v /#.
    wp; skip => /> &2 nthpkf eqszskpks _ ltnt_szsks.
    split => [| pkl skl /lezNgt gelp_skl _ nthpkl eqszsklpkl lelp_szskl]; 1: smt(ge2_lp).
    split => [i j |]; 2: smt(size_rcons).
    rewrite ?nth_rcons ?size_rcons => ge0_i ltsz1_i ge0_j ltlp_j.
    rewrite eqszskpks; case (i < size pkFORSs{2}) => [ltsz | geqsz].
    * by rewrite nthpkf.
    by rewrite (: i = size pkFORSs{2}) 1:/# /= nthpkl // /#.
  wp; skip => /> &2.
  split => [| pkfs skfs /lezNgt gent_szskfs _ nthpkfs *]; 1: by rewrite expr_ge0 //= /#.
  by rewrite nthpkfs /#. 
swap{2} [1..9] 2.
seq 2 2 : (   skWOTStd{1} = R_MFORSTWESNPRFEUFCMA_EUFCMA.skWOTStd{2}
           /\ #pre). 
+ conseq />.
  by sim.
inline{1} 7.
seq 21 16 : (   ={m'}
             /\ ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, O_CMA_MFORSTWESNPRF)
             /\ EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.valid_MFORSTWESNPRF{1} = is_valid{2}
).
+ inline{2} 16; inline{2} 24.
  wp.
  call (: true); 1: by sim.
  inline{1} 19.
  wp => /=.
  while{1} (roots{1} 
            =  
            mkseq (fun (u : int) => 
                     FTWES.val_bt_trh ps1{1} 
                                      ad1{1}
                                      (list2tree (mkseq (fun (v : int) => 
                                                    f ps1{1} (set_thtbidx ad1{1} 0 (u * t + v)) 
                                                              (val (nth witness (nth witness (val skFORS1{1}) u) v))) t)) u) (size roots{1})
           /\ size roots{1} <= k)
           (k - size roots{1}).
  - move=> _ z.
    inline 1.
    wp => /=.
    while (leaves1
           =
           mkseq (fun (v : int) => 
                    f ps2 (set_thtbidx ad2 0 (idxt * t + v)) 
                      (val (nth witness (nth witness (val skFORS2) idxt) v))) (size leaves1)
          /\ size roots < k
          /\ size leaves1 <= t)
          (t - size leaves1).
    * move=> z'.
      wp; skip => /> *.
      by rewrite size_rcons mkseqS //; smt(size_rcons size_ge0).
    wp; skip => /> *.
    split => [| lfs]; 1: by rewrite mkseq0 //; smt(ge2_t).
    split => [/# | ? lfsdef ?].
    rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
    rewrite -andbA; split; 2: smt(size_rcons). 
    do 3! congr; rewrite lfsdef.
    by congr => /#.
  wp => /=.
  call (:   ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, O_CMA_MFORSTWESNPRF)
         /\ ={mmap}(O_CMA_SPHINCSPLUSTWFS_NPRF, O_CMA_MFORSTWESNPRF)
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1}.`2 = O_CMA_MFORSTWESNPRF.sk{2}.`1
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1}.`4 = O_CMA_MFORSTWESNPRF.sk{2}.`2
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1}.`3 = R_MFORSTWESNPRFEUFCMA_EUFCMA.skWOTStd{2}
         /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1}.`4 = R_MFORSTWESNPRFEUFCMA_EUFCMA.ps{2}
         /\ O_CMA_MFORSTWESNPRF.sk{2}.`3 = insubd [0; 0; 0; trhftype; 0; 0]
         /\ R_MFORSTWESNPRFEUFCMA_EUFCMA.ad{2} = insubd [0; 0; 0; trhftype; 0; 0]
         /\ (forall (i j : int),
               0 <= i < nr_trees 0 => 0 <= j < l' =>
               let roots 
                   = 
                   mkseq (fun (u : int) => 
                           FTWES.val_bt_trh R_MFORSTWESNPRFEUFCMA_EUFCMA.ps{2} ((set_kpidx (set_tidx (set_typeidx R_MFORSTWESNPRFEUFCMA_EUFCMA.ad{2} trhftype) i) j))
                                            (list2tree (mkseq (fun (v : int) => 
                                                          f R_MFORSTWESNPRFEUFCMA_EUFCMA.ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx R_MFORSTWESNPRFEUFCMA_EUFCMA.ad{2} trhftype) i) j) 0 (u * t + v)) 
                                                                    (val (nth witness (nth witness (val (nth witness (nth witness O_CMA_MFORSTWESNPRF.sk{2}.`1 i) j)) u) v))) t )) u) k in
                nth witness (nth witness R_MFORSTWESNPRFEUFCMA_EUFCMA.pkFORSnt{2} i) j
                =
                trco R_MFORSTWESNPRFEUFCMA_EUFCMA.ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx R_MFORSTWESNPRFEUFCMA_EUFCMA.ad{2} trhftype) i) j) trcotype) j) 
                     (flatten (map DigestBlock.val roots)))).
  - proc.
    swap{1} 11 -6.
    conseq />.
    seq 10 4 : (  ={mk, idx, sigFORSTW, pkFORS}
                /\ ={qs}(O_CMA_SPHINCSPLUSTWFS_PRF, O_CMA_MFORSTWESNPRF)
                /\ ={mmap}(O_CMA_SPHINCSPLUSTWFS_NPRF, O_CMA_MFORSTWESNPRF)  
                /\ skWOTStd{1} = R_MFORSTWESNPRFEUFCMA_EUFCMA.skWOTStd{2}
                /\ ps{1} = R_MFORSTWESNPRFEUFCMA_EUFCMA.ps{2}
                /\ ad{1} = adz
                /\ R_MFORSTWESNPRFEUFCMA_EUFCMA.ad{2} = insubd [0; 0; 0; trhftype; 0; 0]).
    * inline{2} 1.
      swap{2} 9 -4.
      sp 2 2 => />.
      seq 6 6 : (   #pre 
                 /\ ={ps, skFORS}
                 /\ mk{1} = mk0{2} 
                 /\ cm{1} = cm0{2} 
                 /\ idx{1} = idx0{2}
                 /\ idx{1} = (mco mk{1} m{1}).`2 
                 /\ tidx{1} = tidx0{2} 
                 /\ kpidx{1} = kpidx0{2}
                 /\ tidx{1} = (val idx{1}) %/ l'
                 /\ kpidx{1} = (val idx{1}) %% l'
                 /\ skFORS{1} = nth witness (nth witness skFORSnt{1} tidx{1}) kpidx{1}).
      + by if => />; auto. 
      seq 1 1 : (#pre /\ sigFORSTW{1} = sigFORSTW0{2}).
      + call (: true); 1: by sim.
        skip => /> &2 nthpkfnt.
        by rewrite eq_dbsettype_adztrhf.
      inline{1} 1.
      wp => /=.
      while{1} (roots{1} 
                =  
                mkseq (fun (u : int) => 
                         FTWES.val_bt_trh ps0{1} 
                                          ad0{1}
                                          (list2tree (mkseq (fun (v : int) => 
                                                        f ps0{1} (set_thtbidx ad0{1} 0 (u * t + v)) 
                                                                  (val (nth witness (nth witness (val skFORS0{1}) u) v))) t)) u) (size roots{1})
               /\ size roots{1} <= k)
               (k - size roots{1}).
      + move=> _ z.
        inline 1.
        wp => /=.
        while (leaves0
               =
               mkseq (fun (v : int) => 
                        f ps1 (set_thtbidx ad1 0 (idxt * t + v)) 
                          (val (nth witness (nth witness (val skFORS1) idxt) v))) (size leaves0)
              /\ size roots < k
              /\ size leaves0 <= t)
              (t - size leaves0).
        - move=> z'.
          wp; skip => /> &1 lfsdef *.
          by rewrite size_rcons mkseqS //=; smt(size_rcons size_ge0).
        wp; skip => /> &1 rsdef *.
        split => [| lfs]; 1: by rewrite mkseq0 /=; smt(ge2_t).
        split => [/# | ? lfsdef *].
        rewrite -andbA; split; 2: smt(size_rcons).
        rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
        by do 3! congr; rewrite lfsdef; congr => /#.
      wp; skip => /> &2 nthpkfnt.
      split => [|rs]; 1: by rewrite mkseq0 /=; smt(ge1_k).
      split => [/# | ? rsdef *].
      move: (Index.valP (mco mk0{2} m{2}).`2) => [ge0_idx @/l lt2h_idx]. 
      rewrite nthpkfnt 2:modz_ge0 3:ltz_pmod 4://; 2,3: smt(ge2_lp).
      + rewrite divz_ge0 2:ltz_divLR 3:ge0_idx 3:/=; 1,2: smt(ge2_lp). 
        by rewrite /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d).
      do 2! congr; 1: by rewrite eq_dbsettype_adztrhf.
      + rewrite getsettrhf_kpidx 5:// /valid_tidx /valid_kpidx.
        - rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
          by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
        - rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
          by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
        - rewrite divz_ge0 2:ltz_divLR /= /nr_trees /l' /=; 1,2: smt(ge2_lp).
          by rewrite -exprD_nneg 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
        by rewrite modz_ge0 /= 2:ltz_pmod; smt(ge2_lp).         
      congr; rewrite rsdef (: size rs = k) 1:/#; congr.
      rewrite fun_ext => u /=; do 3! congr; 1: by rewrite eq_dbsettype_adztrhf.
      by rewrite fun_ext => v /=; rewrite eq_dbsettype_adztrhf.
    call (: true); 1: by sim.
    by skip => />; rewrite eq_settype_adztrhfch.
  inline{1} 2; inline{2} 11.
  wp => /=.
  while (   ={skWOTSl}   
         /\ leaves1{1} = leaves0{2}
         /\ ps2{1} = ps3{2}
         /\ set_typeidx ad2{1} chtype = set_typeidx ad3{2} chtype
         /\ set_typeidx ad2{1} pkcotype = set_typeidx ad3{2} pkcotype
         /\ size leaves1{1} <= l').
  - wp.
    call (: true) => /=; 1: by sim.
    by wp; skip => />; smt(size_rcons).
  wp; skip => /> &2 nthpkf.
  split => [| lfs /lezNgt gelp_szlfs _ eqadch eqadpkco lelp_szlfs].
  - by rewrite -eq_settype_adztrhfch /=; smt(ge2_lp).
  split => [| eqvbt msig].
  - rewrite eq_setlttype_adztrhf 3://; 1: smt(ge1_d).
    by rewrite /valid_tidx /nr_trees expr_gt0.
  split => [| roots]; 1: by rewrite mkseq0 /=; smt(ge1_k).
  split => [/# | /lezNgt gek_szrs valrs lek_szrs].
  split => [| eqadtrhfs pkf]; 1: by rewrite eq_dbsettype_adztrhf.
  pose tad := trco _ _ _; pose npkf := nth _ _ _.
  suff -> //: tad = npkf; rewrite /tad /npkf.
  rewrite nthpkf. 
  - rewrite divz_ge0 2:ltz_divLR /= /nr_trees /l' /=; 1,2: smt(ge2_lp).
    by rewrite -exprD_nneg 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
  - by rewrite modz_ge0 /= 2:ltz_pmod; smt(ge2_lp).   
  congr => //=.
  - rewrite eq_dbsettype_adztrhf getsettrhf_kpidx 5:// /valid_tidx /valid_kpidx.
    * rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
      by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
    * rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
      by right; right; right; left => @/valid_idxvalstrhf /=; smt(ge1_d ge1_a ge2_t ge1_k IntOrder.expr_ge0 IntOrder.expr_gt0).
    * rewrite divz_ge0 2:ltz_divLR /= /nr_trees /l' /=; 1,2: smt(ge2_lp).
      by rewrite -exprD_nneg 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
    by rewrite modz_ge0 /= 2:ltz_pmod; smt(ge2_lp).
  rewrite valrs; do 3! congr => [|/#].
  rewrite fun_ext => u; congr.
  do 2! congr; rewrite fun_ext => v; congr.
  by rewrite eq_dbsettype_adztrhf.
conseq (: _ ==> ={is_fresh}) => //.
seq 2 0 : #pre; [conseq (: _ ==> true) => // | by sim].
inline{1} 1.
wp; sp.
while{1} (true) (d - i{1}).
+ move=> ? z.
  inline 3.
  wp.
  while (true) (len - size pkWOTS0).
  - move=> z'.
    by wp; skip => />; smt(size_rcons).
  by wp; skip => /> /#. 
by skip => /> /#.
qed.

(* 
  Success probability (of given adversary) against auxiliary EUF-CMA property of SPHINCS+-TW 
  bounded by success probability (of reduction adversary) against EUF-NAGCMA OF FL-SL-XMSS-MT-TW-ES-NPRF  
*)
local lemma LeqPr_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_VF_FLSLXMSSMTTWESNPRF &m :
  Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.main() @ &m : res /\ ! EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.valid_MFORSTWESNPRF]
  <=
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A), FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
have ->:
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A), FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res]
  =
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.main() @ &m : res].
+ by byequiv Eqv_EUF_NAGCMA_FLSLXMSSMTTWESNPRF_Orig_RV.
byequiv => //.
proc.
inline{1} 2; inline{1} 1.
inline{2} 4; inline{2} 3; inline{2} 11; inline{2} 24.
seq 8 14 : (   ={glob A, skWOTStd, ad0, ps0}
            /\ ad0{1} = ad{2}
            /\ ps0{1} = ps{2}
            /\ ad0{1} = adz
            /\ TRHC.O_THFC_Default.pp{2} = ps{2}
            /\ skFORSnt0{1} = R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2}
            /\ ml{2} = flatten R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}
            /\ (forall (i j : int),
                 0 <= i < nr_trees 0 => 0 <= j < l' =>
                 let rts 
                     = 
                     mkseq (fun (u : int) => 
                             FTWES.val_bt_trh ps{2} ((set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))
                                              (list2tree (mkseq (fun (v : int) => 
                                                            f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)) 
                                                                     (val (nth witness (nth witness (val (nth witness (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2} i) j)) u) v))) t )) u) k in
                  nth witness (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} i) j
                  =
                  trco ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j) 
                       (flatten (map DigestBlock.val rts)))
            /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} = nr_trees 0
            /\ all ((=) l' \o size) R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}).
+ while (={skWOTStd}); 1: by sim.
  wp => /=.
  while (   skFORSnt0{1} = R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2}
         /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} = adz
         /\ TRHC.O_THFC_Default.pp{2} = ps{2}
         /\ (forall (i j : int),
              0 <= i < size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} => 0 <= j < l' =>
              let rts 
                  = 
                  mkseq (fun (u : int) => 
                          FTWES.val_bt_trh ps{2} ((set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))
                                           (list2tree (mkseq (fun (v : int) => 
                                                         f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)) 
                                                                  (val (nth witness (nth witness (val (nth witness (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2} i) j)) u) v))) t )) u) k in
                nth witness (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} i) j
                =
                trco ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j) 
                     (flatten (map DigestBlock.val rts)))
          /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} <= nr_trees 0
          /\ all ((=) l' \o size) R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}
          /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} = size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2}).
  - wp => /=.
    while (   ={skFORSlp}
           /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} = adz
           /\ TRHC.O_THFC_Default.pp{2} = ps{2}
           /\ (forall (j : int),
              0 <= j < size pkFORSlp{2} =>
              let rts 
                  = 
                  mkseq (fun (u : int) => 
                          FTWES.val_bt_trh ps{2} ((set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) j))
                                           (list2tree (mkseq (fun (v : int) => 
                                                         f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) j) 0 (u * t + v)) 
                                                                  (val (nth witness (nth witness (val (nth witness skFORSlp{2} j)) u) v))) t)) u) k in
                nth witness pkFORSlp{2} j
                =
                trco ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) j) trcotype) j) 
                     (flatten (map DigestBlock.val rts)))
           /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} < nr_trees 0
           /\ size pkFORSlp{2} <= l'
           /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} = size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2}
           /\ size pkFORSlp{2} = size skFORSlp{2}).
    * inline{2} 4.
      wp => /=.
      while (   skFORS0{1} = skFORS{2}
             /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} = adz
             /\ TRHC.O_THFC_Default.pp{2} = ps{2}
             /\ roots{2}
                = 
                mkseq (fun (u : int) => 
                        FTWES.val_bt_trh ps{2} ((set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) (size pkFORSlp{2})))
                                         (list2tree (mkseq (fun (v : int) => 
                                                       f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) (size pkFORSlp{2})) 0 (u * t + v)) 
                                                                (val (nth witness (nth witness skFORS{2} u) v))) t)) u) (size roots{2})
             /\ all (fun (ls : dgstblock list) => size ls = t) skFORS{2}
             /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} < nr_trees 0
             /\ size pkFORSlp{2} < l'
             /\ size roots{2} <= k
             /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} = size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2}
             /\ size pkFORSlp{2} = size skFORSlp{2}
             /\ size roots{2} = size skFORS{2}).
      + wp => /=.
        while{2} (   R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} = adz
                  /\ TRHC.O_THFC_Default.pp{2} = ps{2}
                  /\ (forall (i j : int), 0 <= i < size nodes{2} => 0 <= j < nr_nodesf (i + 1) =>
                        nth witness (nth witness nodes{2} i) j
                        =
                        let leavesp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaves{2}) in
                          FTWES.val_bt_trh_gen ps{2} (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) (size pkFORSlp{2})) 
                                               (list2tree leavesp) (i + 1) (size skFORS{2} * nr_nodesf (i + 1) + j))
                  /\ size leaves{2} = t 
                  /\ size nodes{2} <= a
                  /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} = size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2}
                  /\ size pkFORSlp{2} = size skFORSlp{2})
                 (a - size nodes{2}).
        - move=> ? z.
          wp => /=.
          while (   R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad = adz
                 /\ TRHC.O_THFC_Default.pp = ps
                 /\ nodespl = last leaves nodes
                 /\ (forall (i j : int), 0 <= i < size nodes => 0 <= j < nr_nodesf (i + 1) =>
                        nth witness (nth witness nodes i) j
                        =
                        let leavesp = take (2 ^ (i + 1)) (drop (j * (2 ^ (i + 1))) leaves) in
                          FTWES.val_bt_trh_gen ps (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt)) (size pkFORSlp)) (list2tree leavesp) (i + 1) (size skFORS * nr_nodesf (i + 1) + j))
                 /\ (forall (j : int), 0 <= j < size nodescl =>
                       nth witness nodescl j
                       =
                       let leavesp = take (2 ^ (size nodes + 1)) (drop (j * (2 ^ (size nodes + 1))) leaves) in 
                          FTWES.val_bt_trh_gen ps (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt)) (size pkFORSlp)) (list2tree leavesp) (size nodes + 1) (size skFORS * nr_nodesf (size nodes + 1) + j))                  
                 /\ size leaves = t
                 /\ size nodes < a
                 /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt = size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt
                 /\ size pkFORSlp = size skFORSlp)
                (nr_nodesf (size nodes + 1) - size nodescl).
          * move=> z'.
            inline 3.
            wp; skip => /> &2 nthnds nthndscl eqt_szlfs lta_sznds eqszpksknt eqszpksklp ltnrn_szndscl.
            split => [j|]; 2: by smt(size_rcons).
            rewrite ?nth_rcons ?size_rcons => ge0_j ltsznds1_j.
            case (j < size nodescl{2}) => [?| /lezNgt geszj]; 1: by rewrite nthndscl.
            have eqszj : j = size nodescl{2} by smt(size_rcons).
            rewrite eqszj /= size_cat ?valP /= (: 2 ^ (size nodes{2} + 1) = 2 ^ (size nodes{2}) + 2 ^ (size nodes{2})).
            + by rewrite exprD_nneg 1:size_ge0 //= expr1 /#.
            rewrite take_take_drop_cat 1,2:expr_ge0 //=.
            rewrite drop_drop 1:expr_ge0 //= 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //=.
            have ge1_2aszn2szncl : 1 <= 2 ^ (a - size nodes{2}) - 2 * size nodescl{2} - 1.
            + rewrite 2!IntOrder.ler_subr_addr /=.
              rewrite &(IntOrder.ler_trans (2 + 2 * (nr_nodesf (size nodes{2} + 1) - 1))) 1:/#.
              by rewrite /nr_nodesf mulzDr /= -{1}(expr1 2) -exprD_nneg // /#.
            rewrite -nth_last (list2treeS (size nodes{2})) 1:size_ge0.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}). 
              rewrite (: 2 ^ (a - size nodes{2}) * szn2 - size nodescl{2} * (szn2 + szn2) = (2 ^ (a - size nodes{2}) - 2 * size nodescl{2}) * szn2) 1:/#.
              pose mx := max _ _; rewrite (: 2 ^ (size nodes{2}) < mx) // /mx.
              pose sb := ((_ - _ * _) * _)%Int; rewrite &(IntOrder.ltr_le_trans sb) /sb 2:maxrr.
              by rewrite ltr_pmull 1:expr_gt0 // /#.
            + rewrite size_take 1:expr_ge0 1:// size_drop 1:addr_ge0 1:expr_ge0 // 1:mulr_ge0 1:size_ge0 1:addr_ge0 1,2:expr_ge0 //.
              rewrite eqt_szlfs /t (: 2 ^ a = 2 ^ (a - size nodes{2}) * 2 ^ (size nodes{2})) 1:-exprD_nneg 2:size_ge0 1,2:/#.
              pose szn2 := 2 ^ (size nodes{2}). 
              rewrite (: 2 ^ (a - size nodes{2}) * szn2 - (szn2 + size nodescl{2} * (szn2 + szn2)) = (2 ^ (a - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) 1:/#.
              pose sb := ((_ - _ - _) * _)%Int.
              move: ge1_2aszn2szncl; rewrite lez_eqVlt => -[eq1_2as | gt1_2as].
              - by rewrite /sb -eq1_2as /= lez_maxr 1:expr_ge0.
              rewrite lez_maxr /sb 1:mulr_ge0 2:expr_ge0 //= 1:subr_ge0 1:ler_subr_addr.
              - rewrite &(IntOrder.ler_trans (1 + 2 * (nr_nodesf (size nodes{2} + 1) - 1))) 1:/#.
                by rewrite /nr_nodesf mulzDr -{1}(expr1 2) -exprD_nneg // /#.
              rewrite (: szn2 < (2 ^ (a - size nodes{2}) - 2 * size nodescl{2} - 1) * szn2) //.    
              by rewrite ltr_pmull 1:expr_gt0.
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; congr => [/# | /# |].
            case (size nodes{2} = 0) => [eq0_sz | neq0_sz].
            + rewrite eq0_sz ?expr0 /= (nth_out leaves{2}); 1: smt(size_ge0). 
              rewrite {4 8}(: 1 = 0 + 1) 1:// ?(take_nth witness) 1,2:size_drop //; 1..4:smt(size_ge0).
              by rewrite ?take0 /= ?list2tree1 /= ?nth_drop //; smt(size_ge0).
            rewrite (nth_change_dfl witness leaves{2}); 1: smt(size_ge0).
            rewrite ?nthnds /=; 1,3: smt(size_ge0).
            + split => [| _ @/nr_nodesf]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodesf (size nodes{2}))) /nr_nodesf //.
              rewrite (: 2 ^ (a - size nodes{2}) = 2 * 2 ^ (a - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.
            + split => [| _ @/nr_nodesf]; 1: smt(size_ge0).
              rewrite &(IntOrder.ltr_le_trans (nr_nodesf (size nodes{2}))) /nr_nodesf //.
              rewrite (: 2 ^ (a - size nodes{2}) = 2 * 2 ^ (a - (size nodes{2} + 1))) 2:/#.
              by rewrite -{2}(expr1 2) -exprD_nneg // /#.  
            rewrite /= /val_bt_trh_gen /trhi /trh /updhbidx /=; do 3! congr; 1,3: smt().
            + congr; rewrite mulzDr; congr; rewrite eq_sym {1}(mulrC (size skFORS{2})) -mulzA.
              by rewrite /nr_nodesf -{1}(expr1 2) -exprD_nneg // /#.
            congr; rewrite mulzDr eq_sym -addzA; congr; rewrite {1}(mulrC (size skFORS{2})) -mulzA.
            by rewrite /nr_nodesf -{1}(expr1 2) -exprD_nneg // /#.
          wp; skip => /> &2 nthnds eqt_szlfs _ eqszpksknt eqszpksklp lta_sznds.
          split => [/# | ndscl].
          split => [/# | /lezNgt gent1_szndscl nthndscl].
          rewrite -andbA; split => [i j |]; 2: smt(size_rcons).
          rewrite ?nth_rcons ?size_rcons => ge0_i ltsz1_i ge0_j ltnt1_j.
          case (i < size nodes{2}) => ?; 1: by rewrite nthnds.
          have eqiszn : i = size nodes{2} by smt(size_rcons).
          by rewrite eqiszn /= nthndscl /#.
        wp => /=.
        while (   ={skFORSet}
               /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} = adz
               /\ TRHC.O_THFC_Default.pp{2} = ps{2}
               /\ leaves{2} 
                  =
                  mkseq (fun (i : int) =>
                           f ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) (size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2})) (size skFORSlp{2})) 0 (size skFORS{2} * t + i)) (val (nth witness skFORSet{2} i))) (size leaves{2}) 
               /\ size leaves{2} = size skFORSet{2}
               /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2} < nr_trees 0
               /\ size skFORSlp{2} < l'
               /\ size skFORS{2} < k
               /\ size skFORSet{2} <= t).
        - inline{2} 2.
          wp; rnd; skip => /> &2 lfsdef eqszlfssk ltnt0_szsk ltlp_szsklp ltk_szsk _ ltt_szsket skele skelein.
          split; 2: smt(size_rcons).
          rewrite size_rcons valP /f mkseqS /=; 1: smt(size_ge0).
          congr; 2: by rewrite nth_rcons /#. 
          rewrite {1}lfsdef &(eq_in_mkseq) => u rng_u /=. 
          by rewrite /f; congr; rewrite nth_rcons /#.      
        wp; skip => /> &2 rtsdef allskfszt ltnt0szpkf ltlpszpkflp _ eqszpksknt eqszpksklp eqszrtsskf ltk_szsk. 
        split => [| lfs sfket /lezNgt getszsket _ lfsdef eqszsklfs _ _ let_szskfet]; 1: by rewrite mkseq0 /=; smt(ge2_t).
        split => [| nds]; 1: smt(ge1_a).
        split => [/#| /lezNgt gea_sznds nthnds eqt_szlfs lea_sznds].
        split; 2: smt(size_rcons cats1 all_cat allP ge1_a).
        rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
        rewrite nthnds /=; 1,2: smt(ge1_a IntOrder.expr_gt0).
        rewrite drop0 -/t -eqt_szlfs take_size //=.
        congr; 1: rewrite {1}rtsdef.
        - rewrite &(eq_in_mkseq) => u rng_u /=.
          do 3! congr => [|/#]; rewrite fun_ext => v.
          rewrite nth_rcons (: u < size skFORS{2}) 1:/# //=.
          by rewrite eqt_szlfs.
        rewrite /val_bt_trh; congr => [| @/nr_nodesf /=]; 2: by rewrite expr0 /#.
        congr; rewrite {1}lfsdef; congr; rewrite fun_ext => u.
        by rewrite nth_rcons (: ! size roots{2} < size skFORS{2}) 1:/# eqszrtsskf eqt_szlfs //= /#.
      wp; skip => /> &2 nthpkflp ltnt_szpkfnt _ eqszpksknt eqszpksklp ltlp_szskflp.
      split => [| rts skf /lezNgt gek_szskf _ rtsdef allszt_skf _ lek_szrts eqszrtsskf]; 1: by rewrite mkseq0 /=; smt(ge1_k).
      split => [j |]; 2: smt(size_rcons).
      rewrite ?nth_rcons ?size_rcons -eqszpksklp => *.
      case (j < size pkFORSlp{2}) => [ltszj | nltszj]; 1: by rewrite nthpkflp.
      rewrite (: j = size pkFORSlp{2}) 1:/# /= /trco.
      congr => [| /# |].
      + rewrite size_flatten StdBigop.Bigint.sumzE StdBigop.Bigint.BIA.big_mapT.
        rewrite (StdBigop.Bigint.BIA.eq_big_seq _ (fun _ => 8 * n)).
        - by move=> bs /mapP [x [xin ->]] @/(\o) /=; rewrite valP.
        by rewrite StdBigop.Bigint.big_constz count_predT size_map /#.
      rewrite rtsdef (: size rts = k) 1:/#.
      do 3! congr; rewrite fun_ext => u. 
      do 3! congr; rewrite fun_ext => v. 
      by rewrite insubdK // /#.
    wp; skip => /> &2 nthpkfnt _ allszlp eqszpksknt ltnt_szsknt.
    split => [| pkf skf /lezNgt gelp_szskf _ nthpkflp _ lelp_szpkf eqszpksklp]; 1: smt(ge2_lp).
    split => [i j|]; 2: smt(cats1 all_cat allP size_rcons).
    rewrite ?size_rcons ?nth_rcons -eqszpksknt => *.
    case (i < size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}) => [ltszi | nltszi]; 1: by rewrite nthpkfnt.
    rewrite (: i = size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}) 1:/# /=.
    by rewrite nthpkflp // /#.
  wp; rnd.
  rnd{1}; rnd{1}.
  wp; skip => /> *.
  split => [| pkf skf ? ? nthpkf *]; 1: smt(IntOrder.expr_ge0). 
  split => [i j * | /#].
  by rewrite nthpkf; smt(IntOrder.expr_ge0). 
seq 10 14: (   #pre
            /\ ={root0} 
            /\ pk{1} = (root0, ps0){1}
            /\ pk{2} = (root0, ps0, ad0){2}
            /\ sk{1} = (ms, skFORSnt0, skWOTStd, ps0){1}
            /\ sk{2} = (skWOTStd, ps0, ad0){2}
            /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1} = sk{1}
            /\ O_CMA_SPHINCSPLUSTWFS_PRF.qs{1} = []
            /\ O_CMA_SPHINCSPLUSTWFS_NPRF.mmap{1} = empty
            /\ EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.skWOTStd{2} = sk{2}.`1
            /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.root{2} = pk{2}.`1
            /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} = pk{2}.`2
            /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} = pk{2}.`3
            /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.sigFLSLXMSSMTTWl{2} = sigl{2}
            /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.mmap{2} = empty
            /\ (forall (i j : int), 0 <= i < l => 0 <= j < d =>
                  (nth witness (val (nth witness sigl{2} i)) j).`1
                  =
                  let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`1 in
                  let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`2 in
                  let adlt = set_ltidx ad{2} (j - 1) ti in
                  let rt = (if j = 0
                            then nth witness ml{2} i 
                            else FSSLXMTWES.val_bt_trh ps{2} (set_typeidx adlt trhxtype)
                                                       (list2tree (mkseq (fun (u : int) => 
                                                           pkco ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                                                (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                                                    cf ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                                       (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} (j - 1)) ti) u)) v))) len)))) l'))) in
                    DBLL.insubd (mkseq (fun (v : int) => 
                      cf ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad{2} j (ti %/ l')) chtype) (ti %% l')) v) 0 (BaseW.val (encode_msgWOTS rt).[v]) 
                         (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} j) (ti %/ l')) (ti %% l'))) v))) len))
            /\ (forall (i j : int), 0 <= i < l => 0 <= j < d =>
                  (nth witness (val (nth witness sigl{2} i)) j).`2
                  =
                  let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`1 in
                  let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`2 in
                  let adlt = set_ltidx ad{2} j ti in
                  let lfs = mkseq (fun (u : int) => 
                                      pkco ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                           (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                               cf ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                  (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} j) ti) u)) v))) len)))) l' in
                    FSSLXMTWES.cons_ap_trh ps{2} (set_typeidx (set_ltidx ad{2} j ti) trhxtype) (list2tree lfs) ki)).
+ wp 6 9 => /=.
  while{2} (   skWOTStd{2} = EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.skWOTStd{2}
            /\ (forall (i j : int), 0 <= i < size sigl{2} => 0 <= j < d =>
                (nth witness (val (nth witness sigl{2} i)) j).`1
                =
                let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`1 in
                let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`2 in
                let adlt = set_ltidx sk{2}.`3 (j - 1) ti in
                let rt = (if j = 0
                          then nth witness ml{2} i 
                          else FSSLXMTWES.val_bt_trh sk{2}.`2 (set_typeidx adlt trhxtype)
                                                     (list2tree (mkseq (fun (u : int) => 
                                                         pkco sk{2}.`2 (set_kpidx (set_typeidx adlt pkcotype) u)
                                                              (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                                                  cf sk{2}.`2 (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                                     (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} (j - 1)) ti) u)) v))) len)))) l'))) in
                  DBLL.insubd (mkseq (fun (v : int) => 
                    cf sk{2}.`2 (set_chidx (set_kpidx (set_typeidx (set_ltidx sk{2}.`3 j (ti %/ l')) chtype) (ti %% l')) v) 0 (BaseW.val (encode_msgWOTS rt).[v]) 
                       (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} j) (ti %/ l')) (ti %% l'))) v))) len))
            /\ (forall (i j : int), 0 <= i < size sigl{2} => 0 <= j < d =>
                  (nth witness (val (nth witness sigl{2} i)) j).`2
                  =
                  let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`1 in
                  let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`2 in
                  let adlt = set_ltidx sk{2}.`3 j ti in
                  let lfs = mkseq (fun (u : int) => 
                                      pkco sk{2}.`2 (set_kpidx (set_typeidx adlt pkcotype) u)
                                           (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                               cf sk{2}.`2 (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                  (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd{2} j) ti) u)) v))) len)))) l' in
                    FSSLXMTWES.cons_ap_trh sk{2}.`2 (set_typeidx (set_ltidx sk{2}.`3 j ti) trhxtype) (list2tree lfs) ki)
            /\ size sigl{2} <= l)
           (l - size sigl{2}).
  - move=> ? z.
    inline 2.
    wp => /=.
    while (   (size sapl < d => 
                   tidx = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl, 0) (size sapl)).`1
                /\ kpidx0 = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl, 0) (size sapl)).`2)
           /\ root1
              = 
              (if size sapl = 0
               then nth witness ml (size sigl) 
               else FSSLXMTWES.val_bt_trh ps1 (set_typeidx (set_ltidx ad1 (size sapl - 1) tidx) trhxtype)
                                         (list2tree (mkseq (fun (u : int) => 
                                             pkco ps1 (set_kpidx (set_typeidx (set_ltidx ad1 (size sapl - 1) tidx) pkcotype) u)
                                                  (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                                      cf ps1 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad1 (size sapl - 1) tidx) chtype) u) v) 0 (w - 1) 
                                                         (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0 (size sapl - 1)) tidx) u)) v))) len)))) l')))
           /\ (forall (j : int), 0 <= j < size sapl =>
              (nth witness sapl j).`1
              =
              let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl, 0) j).`1 in
              let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl, 0) j).`2 in
              let adlt = set_ltidx ad1 (j - 1) ti in
              let rt = (if j = 0
                        then nth witness ml (size sigl) 
                        else FSSLXMTWES.val_bt_trh ps1 (set_typeidx adlt trhxtype)
                                                   (list2tree (mkseq (fun (u : int) => 
                                                       pkco ps1 (set_kpidx (set_typeidx adlt pkcotype) u)
                                                            (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                                                cf ps1 (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                                   (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0 (j - 1)) ti) u)) v))) len)))) l'))) in
                DBLL.insubd (mkseq (fun (v : int) => 
                  cf ps1 (set_chidx (set_kpidx (set_typeidx (set_ltidx ad1 j (ti %/ l')) chtype) (ti %% l')) v) 0 (BaseW.val (encode_msgWOTS rt).[v]) 
                     (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0 j) (ti %/ l')) (ti %% l'))) v))) len))
            /\ (forall (j : int), 0 <= j < size sapl =>
                  (nth witness sapl j).`2
                  =
                  let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl, 0) (j + 1)).`1 in
                  let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (size sigl, 0) (j + 1)).`2 in
                  let adlt = set_ltidx ad1 j ti in
                  let lfs = mkseq (fun (u : int) => 
                                      pkco ps1 (set_kpidx (set_typeidx adlt pkcotype) u)
                                           (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                               cf ps1 (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                  (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0 j) ti) u)) v))) len)))) l' in
                    FSSLXMTWES.cons_ap_trh ps1 (set_typeidx (set_ltidx ad1 j ti) trhxtype) (list2tree lfs) ki)
            /\ size sigl < l
            /\ size sapl <= d)
           (d - size sapl).
    * move => z'.
      inline 5.
      wp => /=.
      while (leaves2
             =
             mkseq (fun (u : int) => 
                      pkco ps2 (set_kpidx (set_typeidx ad2 pkcotype) u)
                           (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                               cf ps2 (set_chidx (set_kpidx (set_typeidx ad2 chtype) u) v) 0 (w - 1) 
                                  (val (nth witness (val (nth witness skWOTSl u)) v))) len)))) (size leaves2)
             /\ size leaves2 <= l')
            (l' - size leaves2).
      + move=> z''.
        inline 2.
        wp => /=.
        while (   pkWOTS0
                  =
                  mkseq (fun (v : int) => 
                               cf ps3 (set_chidx ad3 v) 0 (w - 1) 
                                  (val (nth witness (val skWOTS2) v))) (size pkWOTS0)
               /\ size pkWOTS0 <= len)
              (len - size pkWOTS0).
        - move=> z'''.
          by wp; skip => />; smt(size_ge0 size_rcons mkseqS).
        wp; skip => /> &2 lfsdef _ ltlp_szlfs.
        split => [| pkw]; 1: by rewrite mkseq0 /=; smt(ge2_len).
        split => [/#| /lezNgt gelen_szpkw pkwdef lelen_szpkw].
        rewrite -andbA; split; 2: smt(size_rcons).
        rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
        do 4! congr => /=; rewrite insubdK 1:/#.
        by rewrite pkwdef /#.
      inline 4.
      wp => /=.
      while (   sig1
                =
                mkseq (fun (v : int) => 
                         cf ps3 (set_chidx ad3 v) 0 (BaseW.val em.[v]) 
                            (val (nth witness (val skWOTS2) v))) (size sig1)
             /\ size sig1 <= len)
            (len - size sig1).
      + move => z''.
        by wp; skip => />; smt(size_ge0 size_rcons mkseqS).
      wp; skip => /> &2 idxsdef nthsapl1 nthsapl2 ltl_szsigl _ ltd_szsapl.
      split => [| sigw]; 1: by rewrite mkseq0 /=; smt(ge2_len).
      split => [/#| /lezNgt gelen_szsigw sigwdef lelen_szsigw].
      split => [| lfs]; 1: by rewrite mkseq0 /=; smt(ge2_lp).
      split => [/# | /lezNgt gelp_szlfs lfsdef lelp_szlfs].
      rewrite ?size_rcons (: ! size sapl{2} + 1 = 0) /=; 1: smt(size_ge0).
      rewrite foldS 2:/=; 1: smt(size_ge0).
      move: (idxsdef _); 1: smt().
      move=> -[-> _] /=.
      rewrite !andbA -andbA; split; 2: smt().
      split; 1: split.
      + do 2! congr; rewrite {1}lfsdef.
        move: (idxsdef _); 1: smt().
        by move=> -[-> _] /=; congr => /#. 
      + move=> j ge0_j ltsz1_j; rewrite ?nth_rcons.
        case (j < size sapl{2}) => ?; 1: by rewrite nthsapl1.
        rewrite (: j = size sapl{2}) 1:/# /= sigwdef.
        do 2! congr => [|/#]; rewrite fun_ext => v.
        by move: (idxsdef _); 1: smt().
      move=> j ge0_j ltsz1_j; rewrite ?nth_rcons.
      case (j < size sapl{2}) => ?; 1: by rewrite nthsapl2.
      rewrite (: j = size sapl{2}) 1:/# /= foldS /=; 1: smt(size_ge0).
      do 2! congr; rewrite {1}lfsdef.
      move: (idxsdef _); 1: smt().
      by move=> -[-> _] /=; congr => /#.
    wp; skip => /> &2 nthsigl1 nthsigl2 _ ltl_szsigl.
    split => [| kpidx sapl tidx]; 1: by rewrite insubdK 2:?fold0 /=; smt(size_ge0 ge1_d).
    split => [/# | /lezNgt ged_szsapl nthsapl1 nthsapl2 led_szsapl].
    rewrite ?size_rcons !andbA -andbA; split; 2: smt(size_rcons).
    split => i j ge0_i ltsz1_i ge0_j ltd_j; rewrite ?nth_rcons.
    * case (i < size sigl{2}) => ?; 1: by rewrite nthsigl1.
      rewrite (: i = size sigl{2}) /=; 1: smt(size_rcons).
      by rewrite insubdK 1:/# nthsapl1 //= /#.
    case (i < size sigl{2}) => ?; 1: by rewrite nthsigl2.
    rewrite (: i = size sigl{2}) /=; 1: smt(size_rcons).
    by rewrite insubdK 1:/# nthsapl2 //= /#.
  wp => /=.
  call (: true); 1: by sim.
  wp; skip => /> &2 nthpkf szpkf allszpkf.
  split => [| sigl]; 1: smt(ge2_l).
  split => [/# | /lezNgt gel_szsigl nthsigl1 nthsigl2 lel_szsigl].
  by split => *; [rewrite nthsigl1 // | rewrite nthsigl2 //] => // /#.
inline{1} 14; inline{2} 7.  
conseq (: _ 
          ==> 
             ={is_valid} 
         /\ (! EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.valid_MFORSTWESNPRF{1}) = is_fresh{2}); 1: smt().
swap{1} 11 3. 
wp; call(: true) => /=; 1: by sim.
wp => /=.
call (: true); 1: by sim.
inline{1} 9.
wp => /=.
while{1} (roots{1} 
          =  
          mkseq (fun (u : int) => 
                   FTWES.val_bt_trh ps1{1} ad1{1}
                                    (list2tree (mkseq (fun (v : int) => 
                                                  f ps1{1} (set_thtbidx ad1{1} 0 (u * t + v)) 
                                                            (val (nth witness (nth witness (val skFORS1{1}) u) v))) t)) u) (size roots{1})
         /\ size roots{1} <= k)
         (k - size roots{1}).
+ move=> _ z.
  inline 1.
  wp => /=.
  while (leaves1
         =
         mkseq (fun (v : int) => 
                  f ps2 (set_thtbidx ad2 0 (idxt * t + v)) 
                    (val (nth witness (nth witness (val skFORS2) idxt) v))) (size leaves1)
        /\ size roots < k
        /\ size leaves1 <= t)
        (t - size leaves1).
  - move=> z'.
    wp; skip => /> &1 lfsdef *.
    by rewrite size_rcons mkseqS //=; smt(size_rcons size_ge0).
  wp; skip => /> &1 rsdef *.
  split => [| lfs]; 1: by rewrite mkseq0 /=; smt(ge2_t).
  split => [/# | ? lfsdef *].
  rewrite -andbA; split; 2: smt(size_rcons).
  rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
  by do 3! congr; rewrite lfsdef; congr => /#.
wp => /=.
call (:   ={mmap}(O_CMA_SPHINCSPLUSTWFS_NPRF, R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA)
       /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1}.`2 = R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2}
       /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1}.`3 = EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.skWOTStd{2}
       /\ O_CMA_SPHINCSPLUSTWFS_PRF.sk{1}.`4 = R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2}
       /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} = adz
       /\ (forall (i j : int),
             0 <= i < nr_trees 0 => 0 <= j < l' =>
             let rts 
                 = 
                 mkseq (fun (u : int) => 
                         FTWES.val_bt_trh R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} ((set_kpidx (set_tidx (set_typeidx adz trhftype) i) j))
                                          (list2tree (mkseq (fun (v : int) => 
                                                        f R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_thtbidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) 0 (u * t + v)) 
                                                                 (val (nth witness (nth witness (val (nth witness (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt{2} i) j)) u) v))) t )) u) k in
              nth witness (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} i) j
              =
              trco R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_kpidx (set_typeidx (set_kpidx (set_tidx (set_typeidx adz trhftype) i) j) trcotype) j) 
                   (flatten (map DigestBlock.val rts)))
       /\ (forall (i j : int), 0 <= i < l => 0 <= j < d =>
            (nth witness (val (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.sigFLSLXMSSMTTWl{2} i)) j).`1
            =
            let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`1 in
            let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) j).`2 in
            let adlt = set_ltidx R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} (j - 1) ti in
            let rt = (if j = 0
                      then nth witness (flatten R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}) i 
                      else FSSLXMTWES.val_bt_trh R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_typeidx adlt trhxtype)
                                                 (list2tree (mkseq (fun (u : int) => 
                                                     pkco R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                                          (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                                              cf R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                                 (val (nth witness (val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.skWOTStd{2} (j - 1)) ti) u)) v))) len)))) l'))) in
              DBLL.insubd (mkseq (fun (v : int) => 
                cf R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_chidx (set_kpidx (set_typeidx (set_ltidx R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} j (ti %/ l')) chtype) (ti %% l')) v) 0 (BaseW.val (encode_msgWOTS rt).[v]) 
                   (val (nth witness (val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.skWOTStd{2} j) (ti %/ l')) (ti %% l'))) v))) len))
      /\ (forall (i j : int), 0 <= i < l => 0 <= j < d =>
            (nth witness (val (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.sigFLSLXMSSMTTWl{2} i)) j).`2
            =
            let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`1 in
            let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (i, 0) (j + 1)).`2 in
            let adlt = set_ltidx R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} j ti in
            let lfs = mkseq (fun (u : int) => 
                                pkco R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_kpidx (set_typeidx adlt pkcotype) u)
                                     (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                         cf R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                            (val (nth witness (val (nth witness (nth witness (nth witness EUF_NAGCMA_FLSLXMSSMTTWESNPRF_RV.skWOTStd{2} j) ti) u)) v))) len)))) l' in
              FSSLXMTWES.cons_ap_trh R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ps{2} (set_typeidx (set_ltidx R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad{2} j ti) trhxtype) (list2tree lfs) ki)
      /\ size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2} = nr_trees 0
      /\ all ((=) l' \o size) R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}).
+ proc.
  sp 2 0 => /=.
  seq 6 6 : (   #pre
             /\ ={mk, cm, idx, tidx, kpidx, skFORS, sigFORSTW}
             /\ tidx{1} = (val idx{1}) %/ l'
             /\ kpidx{1} = (val idx{1}) %% l'
             /\ skFORS{1} = nth witness (nth witness skFORSnt{1} tidx{1}) kpidx{1}).
  - conseq />.
    call (: true); 1: by sim.
    wp => /=.
    by if => //=; auto.    
  inline{1} 2; inline{1} 1.
  wp => /=.
  while{1} ((size sapl{1} < d => 
                   tidx0{1} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx{1}, 0) (size sapl{1})).`1
                /\ kpidx0{1} = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx{1}, 0) (size sapl{1})).`2)
           /\ root{1}
              = 
              (if size sapl{1} = 0
               then m0{1} 
               else FSSLXMTWES.val_bt_trh ps0{1} (set_typeidx (set_ltidx ad0{1} (size sapl{1} - 1) tidx0{1}) trhxtype)
                                         (list2tree (mkseq (fun (u : int) => 
                                             pkco ps0{1} (set_kpidx (set_typeidx (set_ltidx ad0{1} (size sapl{1} - 1) tidx0{1}) pkcotype) u)
                                                  (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                                      cf ps0{1} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0{1} (size sapl{1} - 1) tidx0{1}) chtype) u) v) 0 (w - 1) 
                                                         (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0{1} (size sapl{1} - 1)) tidx0{1}) u)) v))) len)))) l')))
           /\ (forall (j : int), 0 <= j < size sapl{1} =>
              (nth witness sapl{1} j).`1
              =
              let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx{1}, 0) j).`1 in
              let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx{1}, 0) j).`2 in
              let adlt = set_ltidx ad0{1} (j - 1) ti in
              let rt = (if j = 0
                        then m0{1} 
                        else FSSLXMTWES.val_bt_trh ps0{1} (set_typeidx adlt trhxtype)
                                                   (list2tree (mkseq (fun (u : int) => 
                                                       pkco ps0{1} (set_kpidx (set_typeidx adlt pkcotype) u)
                                                            (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                                                cf ps0{1} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                                                   (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0{1} (j - 1)) ti) u)) v))) len)))) l'))) in
                DBLL.insubd (mkseq (fun (v : int) => 
                  cf ps0{1} (set_chidx (set_kpidx (set_typeidx (set_ltidx ad0{1} j (ti %/ l')) chtype) (ti %% l')) v) 0 (BaseW.val (encode_msgWOTS rt).[v]) 
                     (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0{1} j) (ti %/ l')) (ti %% l'))) v))) len))
        /\ (forall (j : int), 0 <= j < size sapl{1} =>
              (nth witness sapl{1} j).`2
              =
              let ti = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx{1}, 0) (j + 1)).`1 in
              let ki = (fold (fun (idxs : _ * _) => edivz idxs.`1 l') (val idx{1}, 0) (j + 1)).`2 in
              let adlt = set_ltidx ad0{1} j ti in
              let lfs = mkseq (fun (u : int) => 
                                  pkco ps0{1} (set_kpidx (set_typeidx adlt pkcotype) u)
                                       (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                                           cf ps0{1} (set_chidx (set_kpidx (set_typeidx adlt chtype) u) v) 0 (w - 1) 
                                              (val (nth witness (val (nth witness (nth witness (nth witness skWOTStd0{1} j) ti) u)) v))) len)))) l' in
                FSSLXMTWES.cons_ap_trh ps0{1} (set_typeidx (set_ltidx ad0{1} j ti) trhxtype) (list2tree lfs) ki)
        /\ size sapl{1} <= d)
           (d - size sapl{1}).
  - move=> _ z.
    inline 5.
    wp => /=.
    while (leaves1
           =
           mkseq (fun (u : int) => 
                    pkco ps2 (set_kpidx (set_typeidx ad2 pkcotype) u)
                         (flatten (map DigestBlock.val (mkseq (fun (v : int) => 
                             cf ps2 (set_chidx (set_kpidx (set_typeidx ad2 chtype) u) v) 0 (w - 1) 
                                (val (nth witness (val (nth witness skWOTSl u)) v))) len)))) (size leaves1)
           /\ size leaves1 <= l')
          (l' - size leaves1).
    * move=> z''.
      inline 2.
      wp => /=.
      while (   pkWOTS0
                =
                mkseq (fun (v : int) => 
                             cf ps3 (set_chidx ad3 v) 0 (w - 1) 
                                (val (nth witness (val skWOTS2) v))) (size pkWOTS0)
             /\ size pkWOTS0 <= len)
            (len - size pkWOTS0).
      + move=> z'''.
        by wp; skip => />; smt(size_ge0 size_rcons mkseqS).
      wp; skip => /> &2 lfsdef _ ltlp_szlfs.
      split => [| pkw]; 1: by rewrite mkseq0 /=; smt(ge2_len). 
      split => [/# | /lezNgt gelen_szpkw pkwdef lelen_szpkw].
      rewrite size_rcons mkseqS; 1: smt(size_ge0). 
      rewrite insubdK 1:/#. 
      do 2! (split => [| /#]).
      by congr; rewrite {1}pkwdef /=; do 4! congr => /#.
    inline 4.
    wp => /=.
    while (   sig0
              =
              mkseq (fun (v : int) => 
                       cf ps3 (set_chidx ad3 v) 0 (BaseW.val em.[v]) 
                          (val (nth witness (val skWOTS2) v))) (size sig0)
           /\ size sig0 <= len)
          (len - size sig0).
    * move => z''.
      by wp; skip => />; smt(size_ge0 size_rcons mkseqS).
    wp; skip => /> &2 idxsdef nthsapl1 nthsapl2 _ ltd_szsapl.
    split => [| sigw]; 1: by rewrite mkseq0 /=; smt(ge2_len).
    split => [/#| /lezNgt gelen_szsigw sigwdef lelen_szsigw].
    split => [| lfs]; 1: by rewrite mkseq0 /=; smt(ge2_lp).
    split => [/#| /lezNgt gelp_szlfs].
    rewrite ?size_rcons => lfsdef lelp_szlfs.
    rewrite {1}lfsdef; move: (idxsdef _); 1: smt().
    move => -> /=; rewrite foldS //=.
    rewrite (: size sapl{2} + 1 <> 0) /=; 1: smt(size_ge0). 
    rewrite (: size lfs = l') 1:/#.
    rewrite !andbA -andbA; split; 2: smt(size_rcons).
    rewrite -!andbA; split; 1: by congr.
    split => j ge0_j ltsz1_j; rewrite nth_rcons.
    * case (j < size sapl{2}) => ?; 1: by rewrite nthsapl1.
      rewrite (: j = size sapl{2}) /=; 1: smt(size_rcons).
      rewrite sigwdef; congr; move: (idxsdef _); 1: smt().
      by move => -> //=; rewrite (: size sigw = len) 1:/#.
    case (j < size sapl{2}) => ?; 1: by rewrite nthsapl2.
    rewrite (: j = size sapl{2}) /=; 1: smt(size_rcons).
    rewrite foldS //=; congr.
    rewrite lfsdef; move: (idxsdef _); 1: smt().
    by move => -> //=; rewrite (: size lfs = l') 1:/#. 
  wp => /=.
  while{1} (roots{1} 
            =  
            mkseq (fun (u : int) => 
                     FTWES.val_bt_trh ps1{1} ad1{1}
                                      (list2tree (mkseq (fun (v : int) => 
                                                    f ps1{1} (set_thtbidx ad1{1} 0 (u * t + v)) 
                                                              (val (nth witness (nth witness (val skFORS0{1}) u) v))) t)) u) (size roots{1})
           /\ size roots{1} <= k)
           (k - size roots{1}).
  + move=> _ z.
    inline 1.
    wp => /=.
    while (leaves1
           =
           mkseq (fun (v : int) => 
                    f ps2 (set_thtbidx ad2 0 (idxt * t + v)) 
                      (val (nth witness (nth witness (val skFORS1) idxt) v))) (size leaves1)
          /\ size roots < k
          /\ size leaves1 <= t)
          (t - size leaves1).
    - move=> z'.
      wp; skip => /> &1 lfsdef *.
      by rewrite size_rcons mkseqS //=; smt(size_rcons size_ge0).
    wp; skip => /> &1 rsdef *.
    split => [| lfs]; 1: by rewrite mkseq0 /=; smt(ge2_t).
    split => [/# | ? lfsdef *].
    rewrite -andbA; split; 2: smt(size_rcons).
    rewrite size_rcons mkseqS /=; 1: smt(size_ge0).
    by do 3! congr; rewrite lfsdef; congr => /#.
  wp; skip => /> &2 nthpkfnt nthpksigxl1 nthpksigxl2 eqnt0_szpkfnt allszlppkfnt.
  split => [| rts]; 1: by rewrite mkseq0 /=; smt(ge1_k).
  split => [/# | /lezNgt gek_szrts rtsdef lek_szrts].
  split => [| kpidx sapl tidx]; 1: by rewrite fold0 /=; 1: smt(ge1_d).
  split => [/#| /lezNgt ged_szsapl nthsapl1 nthsapl2 led_szsapl].
  rewrite &(SAPDL.val_inj) &(eq_from_nth witness) ?valP 1:// insubdK 1:/# => j rng_j.
  suff /#:
    (nth witness sapl j).`1 = (nth witness (val (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.sigFLSLXMSSMTTWl{2} (val idx{2}))) j).`1
    /\
    (nth witness sapl j).`2 = (nth witness (val (nth witness R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.sigFLSLXMSSMTTWl{2} (val idx{2}))) j).`2.
  split.
  rewrite nthsapl1 1:/# nthpksigxl1 1:valP //.
  do 2! congr; rewrite fun_ext => v /=.
  do 5! congr; rewrite eq_sym.
  have {1}->:
    val idx{2}
    =
    sumz (map size (take (val idx{2} %/ l') R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) + val idx{2} %% l'.
  + rewrite StdBigop.Bigint.sumzE StdBigop.Bigint.BIA.big_mapT /(\o).
    rewrite (StdBigop.Bigint.BIA.eq_big_seq _ (fun _ => l')) => [pkflp /mem_take pkfin /=|].
    - move/allP: allszlppkfnt => /(_ pkflp pkfin) @/(\o) -> //.
    rewrite StdBigop.Bigint.big_constz count_predT /= size_take.
    - by rewrite divz_ge0; smt(ge2_lp Index.valP).
    rewrite (: val idx{2} %/ l' < size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}) 2:/=.
    - rewrite eqnt0_szpkfnt /l' /nr_trees ltz_divLR; 1: smt(ge2_lp).
      by rewrite -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
    by rewrite mulrC -divz_eq.
  rewrite (nth_flatten witness).
  + rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
    by rewrite eqnt0_szpkfnt /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; 1..4: smt(ge1_hp ge1_d Index.valP). 
  + rewrite modz_ge0 /=; 1: smt(ge2_lp). 
    pose nr := nth _ _ _.
    move/allP: allszlppkfnt => /(_ nr) @/nr.
    rewrite /(\o) mem_nth /=.
    rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
    by rewrite eqnt0_szpkfnt /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; 1..4: smt(ge1_hp ge1_d Index.valP).
    move=> <-; rewrite ltz_pmod; smt(ge2_lp).
  rewrite nthpkfnt.
  + rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
    by rewrite /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; 1..4: smt(ge1_hp ge1_d Index.valP).
  + by rewrite modz_ge0 2:ltz_pmod /=; smt(ge2_lp). 
  do 2! congr.
  + rewrite getsettrhf_kpidx /valid_tidx /valid_kpidx 5://.
    - rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
      by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
    - rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
      by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
    - rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
      by rewrite /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
    by rewrite modz_ge0 2:ltz_pmod /=; smt(ge2_lp).  
  rewrite rtsdef.
  by do 2! congr; smt().
  rewrite nthpksigxl2 ?valP // nthsapl2 // /#.
wp; skip => /> &2 nthpkfnt eqnt0_szpkfnt allszlp_pkfnt nthsigl1 nthsigl2 nthpkfntp msig.
split => [| rts]; 1: by rewrite mkseq0 /=; 1: smt(ge1_k).
split => [/# | /lezNgt gek_rts rtsdef lek_szrts].
pose tad := trco _ _ _; pose npkf := nth _ _ _.
suff -> //: tad = npkf; rewrite /tad /npkf.
pose vmco := val (mco _ _).`2; rewrite eq_sym.
have {1}->:
  vmco
  =
  sumz (map size (take (vmco %/ l') R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2})) + vmco %% l'.
+ rewrite StdBigop.Bigint.sumzE StdBigop.Bigint.BIA.big_mapT /(\o).
  rewrite (StdBigop.Bigint.BIA.eq_big_seq _ (fun _ => l')) => [pkflp /mem_take pkfin /=|].
  - move/allP: allszlp_pkfnt => /(_ pkflp pkfin) @/(\o) -> //.
  rewrite StdBigop.Bigint.big_constz count_predT /= size_take.
  - by rewrite divz_ge0; smt(ge2_lp Index.valP).
  rewrite (: vmco %/ l' < size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.pkFORSnt{2}) 2:/=.
  - rewrite eqnt0_szpkfnt /l' /nr_trees ltz_divLR; 1: smt(ge2_lp).
    by rewrite -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
  by rewrite mulrC -divz_eq.
rewrite (nth_flatten witness).
+ rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
  by rewrite eqnt0_szpkfnt /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; 1..4: smt(ge1_hp ge1_d Index.valP). 
+ rewrite modz_ge0 /=; 1: smt(ge2_lp). 
  pose nr := nth _ _ _.
  move/allP: allszlp_pkfnt => /(_ nr) @/nr.
  rewrite /(\o) mem_nth /=.
  rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
  by rewrite eqnt0_szpkfnt /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; 1..4: smt(ge1_hp ge1_d Index.valP).
  move=> <-; rewrite ltz_pmod; smt(ge2_lp).
rewrite nthpkfntp.
+ rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
  by rewrite /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
+ rewrite modz_ge0 2:ltz_pmod; smt(ge2_lp).
congr.
+ rewrite getsettrhf_kpidx /valid_tidx /valid_kpidx 5://.
  - rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
    by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
  - rewrite insubdK /valid_adrsidxs /adrs_len /= /valid_idxvals; 2: smt(IntOrder.expr_gt0).
    by left => @/valid_idxvalsch /=; smt(ge1_d val_w ge2_len ge2_lp IntOrder.expr_ge0 IntOrder.expr_gt0).
  - rewrite divz_ge0 2:ltz_divLR; 1,2: smt(ge2_lp).
    by rewrite /nr_trees /l' -exprD_nneg /= 1:mulr_ge0; smt(ge1_hp ge1_d Index.valP).
  by rewrite modz_ge0 2:ltz_pmod /=; smt(ge2_lp).
do 2! congr.
rewrite rtsdef.
congr; 2: smt().
rewrite fun_ext => u.
do 3! congr; 1,2:smt().
rewrite fun_ext => v.
by congr; 2: congr => /#.
qed.

(* 
  High-level security theorem
  Success probability (of given adversary) against EUF-CMA of SPHINCS+-TW 
  bounded by advantages/success probabilities (of reduction adversaries)
  against the PRF properties of skg and mkg, the EUF-CMA property of M-FORS-TW-ES-NPRF, 
  and the EUF-NAGCMA OF FL-SL-XMSS-MT-TW-ES-NPRF  
*)
local lemma EUFCMA_SPHINCS_PLUS_FX &m :
  Pr[EUF_CMA(SPHINCS_PLUS, A, O_CMA_Default).main() @ &m : res]
  <= 
  `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA(A), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
    - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA(A), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
  +
  `|  Pr[MKG_PRF.PRF(R_MKGPRF_EUFCMA(A), MKG_PRF.O_PRF_Default).main(false) @ &m : res]
    - Pr[MKG_PRF.PRF(R_MKGPRF_EUFCMA(A), MKG_PRF.O_PRF_Default).main(true) @ &m : res] |
  +  
  Pr[EUF_CMA_MFORSTWESNPRF(R_MFORSTWESNPRFEUFCMA_EUFCMA(A), O_CMA_MFORSTWESNPRF).main() @ &m : res]
  +
  Pr[EUF_NAGCMA_FLSLXMSSMTTWESNPRF(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A), FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
have ->:
  Pr[EUF_CMA(SPHINCS_PLUS, A, O_CMA_Default).main() @ &m : res]
  =
  Pr[EUF_CMA_SPHINCSPLUSTWFS_PRFPRF.main() @ &m : res].
+ by byequiv Eqv_EUF_CMA_SPHINCSPLUSTW_Orig_FSPRFPRF.
rewrite -RField.addr0 -(RealOrder.ger0_norm) 1:/= 1:Pr[mu_ge0] //.
rewrite -(RField.subrr Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF.main() @ &m : res]).
rewrite RField.addrCA RField.addrC.
apply (RealOrder.ler_trans (`|Pr[EUF_CMA_SPHINCSPLUSTWFS_PRFPRF.main() @ &m : res] -
                              Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF.main() @ &m : res]| +
                            `|Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF.main() @ &m : res]|)).
+ by apply RealOrder.ler_norm_add.
rewrite EqAdv_EUF_CMA_SPHINCSPLUSTWFS_PRFPRF_NPRFPRF_SKGPRF -!RField.addrA RealOrder.ler_add //.
rewrite -(RField.addr0 Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF.main() @ &m : res]).
rewrite -(RField.subrr Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF.main() @ &m : res]).
rewrite RField.addrCA RField.addrC.
apply (RealOrder.ler_trans (`|Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF.main() @ &m : res] -
                              Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF.main() @ &m : res]| +
                            `|Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF.main() @ &m : res]|)).
+ by apply RealOrder.ler_norm_add.
rewrite EqAdv_EUF_CMA_SPHINCSPLUSTWFS_NPRFPRF_NPRFNPRF_MKGPRF RealOrder.ler_add //.
rewrite RealOrder.ger0_norm 1:Pr[mu_ge0] //.
have ->:
  Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF.main() @ &m : res]
  =
  Pr[EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.main() @ &m : res].
+ by byequiv Eqv_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.
rewrite Pr[mu_split EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_V.valid_MFORSTWESNPRF].
rewrite ler_add 1:LeqPr_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_VT_MFORSTWESNPRF.
by rewrite LeqPr_EUF_CMA_SPHINCSPLUSTWFS_NPRFNPRF_VF_FLSLXMSSMTTWESNPRF.
qed.

(* 
  Low-level security theorem
  Success probability (of given adversary) against EUF-CMA of SPHINCS+-TW 
  bounded by advantages/success probabilities (of reduction adversaries)
  against properties of employed KHFs/THFs.  
*)
lemma EUFCMA_SPHINCS_PLUS &m :
  Pr[EUF_CMA(SPHINCS_PLUS, A, O_CMA_Default).main() @ &m : res]
  <= 
  `|  Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA(A), SKG_PRF.O_PRF_Default).main(false) @ &m : res]
    - Pr[SKG_PRF.PRF(R_SKGPRF_EUFCMA(A), SKG_PRF.O_PRF_Default).main(true) @ &m : res] |
  +
  `|  Pr[MKG_PRF.PRF(R_MKGPRF_EUFCMA(A), MKG_PRF.O_PRF_Default).main(false) @ &m : res]
    - Pr[MKG_PRF.PRF(R_MKGPRF_EUFCMA(A), MKG_PRF.O_PRF_Default).main(true) @ &m : res] |
  +
  Pr[MCO_ITSR.ITSR(R_ITSR_EUFCMA(R_MFORSTWESNPRFEUFCMA_EUFCMA(A)), MCO_ITSR.O_ITSR_Default).main() @ &m : res]
  +
  maxr 0%r 
       (Pr[FP_DSPR.SM_DT_DSPR(R_DSPR_OpenPRE(R_FPOpenPRE_FOpenPRE(R_MFORSTWESNPRFEUFCMA_EUFCMA(A))), FP_DSPR.O_SMDTDSPR_Default).main() @ &m : res]
        -
        Pr[FP_DSPR.SM_DT_SPprob(R_DSPR_OpenPRE(R_FPOpenPRE_FOpenPRE(R_MFORSTWESNPRFEUFCMA_EUFCMA(A))), FP_DSPR.O_SMDTDSPR_Default).main() @ &m : res])
  +
  3%r * Pr[FP_TCR.SM_DT_TCR(R_TCR_OpenPRE(R_FPOpenPRE_FOpenPRE(R_MFORSTWESNPRFEUFCMA_EUFCMA(A))), FP_TCR.O_SMDTTCR_Default).main() @ &m : res]
  + 
  Pr[FTWES.TRHC_TCR.SM_DT_TCR_C(R_TRHSMDTTCRC_EUFCMA(R_MFORSTWESNPRFEUFCMA_EUFCMA(A)), FTWES.TRHC_TCR.O_SMDTTCR_Default, FTWES.TRHC.O_THFC_Default).main() @ &m : res]
  +
  Pr[TRCOC_TCR.SM_DT_TCR_C(R_TRCOSMDTTCRC_EUFCMA(R_MFORSTWESNPRFEUFCMA_EUFCMA(A)), TRCOC_TCR.O_SMDTTCR_Default, TRCOC.O_THFC_Default).main() @ &m : res]  
  +
  (w - 2)%r
    * `|Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A))), FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(false) @ &m : res]
        - Pr[FC_UD.SM_DT_UD_C(R_SMDTUDC_Game23WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A))), FC_UD.O_SMDTUD_Default, FC.O_THFC_Default).main(true) @ &m : res]| 
  + 
  Pr[FC_TCR.SM_DT_TCR_C(R_SMDTTCRC_Game34WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A))), FC_TCR.O_SMDTTCR_Default, FC.O_THFC_Default).main() @ &m : res] 
  + 
  Pr[FC_PRE.SM_DT_PRE_C(R_SMDTPREC_Game4WOTSTWES(R_MEUFGCMAWOTSTWESNPRF_EUFNAGCMA(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A))), FC_PRE.O_SMDTPRE_Default, FC.O_THFC_Default).main() @ &m : res]
  +
  Pr[PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_EUFNAGCMA(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A)), PKCOC_TCR.O_SMDTTCR_Default, PKCOC.O_THFC_Default).main() @ &m : res]
  +
  Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_EUFNAGCMA(R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A)), FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default, FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res].
proof.
have validxsadz : valid_adrsidxs [0; 0; 0; chtype; 0; 0].
  - rewrite /valid_adrsidxs /= /adrs_len /= /valid_idxvals; left.
    by rewrite /valid_idxvalsch /=; smt(val_w ge2_len ge2_lp IntOrder.expr_gt0 ge1_d).
move: (EUFNAGCMA_FLSLXMSSMTTWESNPRF (R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA(A)) _ _ &m _ _ _)
      (EUFCMA_SPHINCS_PLUS_FX &m). 
+ move=> OC OCll.
  proc.
  while (true) (nr_trees 0 - size R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.skFORSnt).
  - move=> z.
    wp.
    while (true) (l' - size skFORSlp).
    * move=> z''.
      wp.
      call OCll.
      while (true) (k - size skFORS).
      + move=> z'''.
        wp.
        while (true) (a - size nodes).
        - move=> z''''.
          wp.
          while (true) (nr_nodesf (size nodes + 1) - size nodescl).
          * move=> z'''''.
            wp.
            call OCll.
            by wp; skip => />; smt(size_rcons).
          by wp; skip => />; smt(size_rcons).
        wp.
        while (true) (t - size skFORSet).
        + move=> z''''.
          wp.
          call OCll.
          rnd.
          wp; skip => /> &2 ltt_szsket.
          by rewrite -(mu_eq _ predT) 2:ddgstblock_ll => [x |]; 1: smt(size_rcons).
        by wp; skip => />; smt(size_rcons). 
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  by wp; skip => />; smt(size_rcons).
+ move=> OC.
  proc; inline *.
  wp.
  while (true) (k - size roots).
  - move=> z. 
    by wp; skip => />; smt(size_rcons).
  wp.
  call (: true). 
  - by move=> O Oll; apply (A_forge_ll O).
  - proc; inline *.
    wp.
    while (true) (k - size sig).
    * move=> z.
      wp => /=.
      while (true) (t - size leaves0).
      + move=> z'.
        by wp; skip => />; smt(size_rcons).
      by wp; skip => />; smt(size_rcons).
    by if => //; auto => />; smt(dmkey_ll).
  by wp; skip => /> /#.
+ proc; inline *.
  while (#post /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad = adz).
  - wp => /=.
    while (#pre).
    * wp => /=.
      while (#pre).
      + wp => /=.
        while (#pre).
        - wp => /=.
          while (#pre).
          * wp; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ltk_szsk lta_sznds ltnnf_szndscl.
            rewrite -cats1 all_cat allnchtws /=.
            rewrite gettype_setthtbkptypetrh ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
            + by rewrite /valid_tidx /= expr_gt0.
            + by rewrite /valid_thfidx; 1: smt(size_ge0).
            + rewrite /valid_tbfidx; split => [| _].
              - rewrite addr_ge0 1:mulr_ge0 1:size_ge0 1:expr_ge0 1,2://.
                rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 2://.
                by rewrite ler_pmul2r 1:expr_gt0 1:// /#.
            by smt(Top.dist_adrstypes).  
          by wp; skip.
        wp=> /=.
        while (#pre).
        - wp; rnd; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ltk_szsk ltt_szsket skfele skfelein.
          rewrite -cats1 all_cat allnchtws /=.
          rewrite gettype_setthtbkptypetrh ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
          * by rewrite /valid_tidx /= expr_gt0.
          * by rewrite /valid_thfidx; smt(ge1_a).
          * rewrite /valid_tbfidx; split => [| _].
            + rewrite addr_ge0 1:mulr_ge0 1:size_ge0 1:expr_ge0 1,2://.
              rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 2://.
              by rewrite ler_pmul2r 1:expr_gt0 1:// /#.
          by smt(Top.dist_adrstypes).
        by wp; skip.
      wp; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ads skf /lezNgt gek_szskf allnchads.
      rewrite -cats1 all_cat allnchads /=.
      rewrite gettype_setkp2type2trhtrco ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
      + by rewrite /valid_tidx /= expr_gt0.
      + by rewrite /valid_kpidx; smt(size_ge0).
      by smt(Top.dist_adrstypes).
    by wp; skip.
  by wp; skip.
+ proc; inline *.
  while (#post /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad = adz).
  - wp => /=.
    while (#pre).
    * wp => /=.
      while (#pre).
      + wp => /=.
        while (#pre).
        - wp => /=.
          while (#pre).
          * wp; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ltk_szsk lta_sznds ltnnf_szndscl.
            rewrite -cats1 all_cat allnchtws /=.
            rewrite gettype_setthtbkptypetrh ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
            + by rewrite /valid_tidx /= expr_gt0.
            + by rewrite /valid_thfidx; 1: smt(size_ge0).
            + rewrite /valid_tbfidx; split => [| _].
              - rewrite addr_ge0 1:mulr_ge0 1:size_ge0 1:expr_ge0 1,2://.
                rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 2://.
                by rewrite ler_pmul2r 1:expr_gt0 1:// /#.
            by smt(Top.dist_adrstypes).  
          by wp; skip.
        wp=> /=.
        while (#pre).
        - wp; rnd; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ltk_szsk ltt_szsket skfele skfelein.
          rewrite -cats1 all_cat allnchtws /=.     
          rewrite gettype_setthtbkptypetrh ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
          * by rewrite /valid_tidx /= expr_gt0.
          * by rewrite /valid_thfidx; smt(ge1_a).
          * rewrite /valid_tbfidx; split => [| _].
            + rewrite addr_ge0 1:mulr_ge0 1:size_ge0 1:expr_ge0 1,2://.
              rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 2://.
              by rewrite ler_pmul2r 1:expr_gt0 1:// /#.
          by smt(Top.dist_adrstypes).
        by wp; skip.
      wp; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ads skf /lezNgt gek_szskf allnchads.
      rewrite -cats1 all_cat allnchads /=.
      rewrite gettype_setkp2type2trhtrco ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
      + by rewrite /valid_tidx /= expr_gt0.
      + by rewrite /valid_kpidx; smt(size_ge0).
      by smt(Top.dist_adrstypes).
    by wp; skip.
  by wp; skip.
proc; inline *.
while (#post /\ R_FLSLXMSSMTTWESNPRFEUFNAGCMA_EUFCMA.ad = adz).
+ wp => /=.
  while (#pre).
  - wp => /=.
    while (#pre).
    * wp => /=.
      while (#pre).
      + wp => /=.
        while (#pre).
        - wp; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ltk_szsk lta_sznds ltnnf_szndscl.
          rewrite -cats1 all_cat allnchtws /=.
          rewrite gettype_setthtbkptypetrh ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
          * by rewrite /valid_tidx /= expr_gt0.
          * by rewrite /valid_thfidx; 1: smt(size_ge0).
          * rewrite /valid_tbfidx; split => [| _].
            + rewrite addr_ge0 1:mulr_ge0 1:size_ge0 1:expr_ge0 1,2://.
              rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 2://.
              by rewrite ler_pmul2r 1:expr_gt0 1:// /#.
          by smt(Top.dist_adrstypes).  
        by wp; skip.
      wp=> /=.
      while (#pre).
      + wp; rnd; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ltk_szsk ltt_szsket skfele skfelein.
        rewrite -cats1 all_cat allnchtws /=.
        rewrite gettype_setthtbkptypetrh ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
        - by rewrite /valid_tidx /= expr_gt0.
        - by rewrite /valid_thfidx; smt(ge1_a).
        - rewrite /valid_tbfidx; split => [| _].
          * rewrite addr_ge0 1:mulr_ge0 1:size_ge0 1:expr_ge0 1,2://.
            rewrite (: k = k - 1 + 1) 1:// mulrDl /= ler_lt_add 2://.
            by rewrite ler_pmul2r 1:expr_gt0 1:// /#.
        by smt(Top.dist_adrstypes).
      by wp; skip.
    wp; skip => /> &2 allnchtws ltnt0_szsknt ltlp_szsklp ads skf /lezNgt gek_szskf allnchads.
    rewrite -cats1 all_cat allnchads /=.
    rewrite gettype_setkp2type2trhtrco ?insubdK 1,3:validxsadz ?nth_drop 1,2,3,5,6://. 
    * by rewrite /valid_tidx /= expr_gt0.
    * by rewrite /valid_kpidx; smt(size_ge0).
    by smt(Top.dist_adrstypes).
  by wp; skip.
by wp; skip.
move: (EUFCMA_MFORSTWESNPRF (R_MFORSTWESNPRFEUFCMA_EUFCMA(A)) _ &m); last smt().
move=> O Oll.
proc; inline *.
wp; call (: true).
+ by apply A_forge_ll.
+ proc; inline *.
  wp => /=.
  while (true) (d - size sapl).
  - move=> z.
    wp => /=.
    while (true) (l' - size leaves0).
    * move=> z'.
      wp => /=.
      while (true) (len - size pkWOTS0).
      * move=> z''.
        by wp; skip => />; smt(size_rcons).
      by wp; skip => />; smt(size_rcons).
    wp => /=.
    while (true) (len - size sig0).
    * move=> z'.
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  wp => /=.
  call Oll.
  by wp; skip => /> /#.
wp => /=.
while (true) (l' - size leaves0).
+ move=> z.
  wp => /=.
  while (true) (len - size pkWOTS0).
  - move=> z'.
    by wp; skip => />; smt(size_rcons).
  by wp; skip => />; smt(size_rcons).
wp => /=.
while (true) (d - size R_MFORSTWESNPRFEUFCMA_EUFCMA.skWOTStd).
+ move=> z. 
  wp => /=.
  while (true) (nr_trees (size R_MFORSTWESNPRFEUFCMA_EUFCMA.skWOTStd) - size skWOTSnt).
  - move=> z'.
    wp => /=.
    while (true) (l' - size skWOTSlp).
    * move=> z''.
      wp => /=.
      while (true) (len - size skWOTS).
      + move=> z'''.
        wp; rnd; skip => /> &2 ltlen_szskw.
       by rewrite -(mu_eq _ predT) 2:ddgstblock_ll => [x |]; 1: smt(size_rcons).
      by wp; skip => />; smt(size_rcons).
    by wp; skip => />; smt(size_rcons).
  by wp; skip => />; smt(size_rcons).
by wp; skip => /> /#.
qed.

end section Proof_SPHINCS_PLUS_EUFCMA.
