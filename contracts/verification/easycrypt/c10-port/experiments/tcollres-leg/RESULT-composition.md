# RESULT — composition/extraction lemma (step 2, partial)

`Composition.ec`, compiled as an explicit target against `base-c10`:
**0 admits, 0 axioms**, atomic negative control `rc=1` (injecting `lemma : false`
FAILS; file restored clean inside the same job, so no race).

## What is proven

| lemma | content |
|---|---|
| `orphan_empty` | the FOURTH, uncharged case is **empty** under the encoder bridge |
| `composition_is_threeway` | every forgery falls into one of exactly **three CHARGED** cases |
| `charges_disjoint_AB/AC/BC` | the charges are **mutually exclusive** — no double-counting |
| `chargeC_feeds_chain` | case C hands the WOTS chain argument exactly its hypothesis |

The three charges, each naming the assumption that pays for it:

* **A** — forgery reconstructs the SAME node. WOTS is not broken; the break is
  LOWER-LAYER (FORS few-time coverage / tree second-preimage). Lands on ITSRC10.
* **B** — different node, `ThC` collides. Address-bound target collision:
  **S-TCR(+C)** (SPHINCS+C Def C.1), whose game the port already reduces to.
* **C** — different node, different CODEWORD. Exactly the hypothesis the weakened
  `nhchwcoll_hchwpre` consumes, so the existing chain argument runs unchanged.

## Why this is not a tautology

`A \/ (¬A /\ B) \/ (¬A /\ ¬B)` proves nothing. The content is that the split is
**THREE-way and not FOUR-way**. The fourth combination —

> different node, `ThC` values DIFFER, yet the codewords AGREE

is charged by **nothing** in the ledger: Def 9 cannot reach it (Def 9 constrains
DISTINCT codewords; here they are equal) and S-TCR(+C) cannot either (the `ThC`
values differ, so there is no target collision to hand the reduction). It is
eliminated by `EncInj` — the encoder bridge — not assumed away. **Remove the
bridge and `composition_is_threeway` is FALSE, not merely unproven.**

## THE FINDING — exhaustiveness and disjointness need DIFFERENT hypotheses

I expected one hypothesis to serve both. The compiler refused, and it was right:

* **Exhaustiveness** needs `EncInj`: *equal codewords ⟹ equal `ThC`*
  (the encoder bridge; `EncoderBridge.ec` proves its core at C10 geometry).
* **Disjointness (B vs C)** needs the CONVERSE, `ThCDeterminesCodeword`:
  *equal `ThC` ⟹ equal codewords* — i.e. the encoding **factors** through `ThC`
  (`encode_msgWOTS_C p a x c = encode_msgWOTS (ThC p a x c)`, recorded at
  `XmssmtCC_All.ec:1178`).

Neither is derivable here: `encode_msgWOTS_C` and `ThC` are ABSTRACT ops
(`WOTS_C_Real.ec:175,220`). Both are stated as explicit premises and deliberately
NOT axiomatised. The failed disjointness proof is what surfaced the distinction —
an honest formalisation earning its keep.

## What this does NOT do — the larger half of step 2

1. **No connection to the SPHINCS+ VERIFY procedure.** `m'` is *taken* as "the
   node the forgery reconstructs to". PROVING that an accepted signature yields
   such an `m'` at a specific address is the FORS->hypertree half, and it must
   handle **attacker-controlled `R` and address grinding** — the verifier
   reconstructs the node entirely from adversary-supplied material
   (`hypertree.rs:378,418`; `fors.rs:92-97` states the verifier never recomputes
   `R`). NOT attempted.
2. **ChargeA is not charged.** It lands on ITSRC10, which has no theorem in the
   literature.
3. **No probability is bounded.** `Pr[G /\ COLL]` is untouched. This is the EVENT
   DECOMPOSITION only.

So step 2 is **partially** done: the decomposition is mechanized and its
hypotheses are exactly identified; the game-level extraction is not.
**C10 remains unproven at deployed parameters.**
