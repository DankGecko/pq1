# RESULT — Composition.ec's premises are (mostly) the chain's, not mine

**Status: GATED, NOT WIRED.** `PremiseReduction.ec` compiles as an explicit
target, **0 admits, 0 axioms declared in file**. It is a standalone leaf. Proving
these implications discharges nothing in the chain — the chain's hops take the
encode bridge as a premise before this file and still do after it. What changes
is the **assumption ledger**, and its honesty.

## The correction to my own bookkeeping

`Composition.ec` states two premises and presents both as newly identified:

```
EncInj                 equal codewords => equal ThC     (exhaustiveness)
ThCDeterminesCodeword  equal ThC => equal codewords     (disjointness)
```

I wrote them as though they were fresh obligations. **One of them is already a
chain premise.** The encode bridge

```
forall p a x cc, encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc)
```

is threaded as an explicit binder through `WOTS_C_Interactive.ec`
(`:1006, 1277, 1346, 1561, 1794, 1916, 1991`), `SPHINCS_C.ec:176`, and the
capstone WIPs. Verified that it is the **same** proposition and not a lookalike:
both `Composition.ec` and `WOTS_C_Interactive.ec` `require` + `import` the same
`WOTS_C_Real`, so `ThC` (`:175`) and `encode_msgWOTS_C` (`:220`) are literally
the same ops, not separately-cloned ones.

## What is proven

| lemma | content |
|---|---|
| `thc_determines_from_bridge` | disjointness is **FREE** — the bridge alone gives it |
| `encinj_from_bridge_and_inj` | exhaustiveness = bridge + injectivity of `encode_msgWOTS` |
| `encinj_from_bridge_and_image_inj` | …and only injectivity **on ThC's image at a fixed address** |
| `image_inj_from_encinj` | the converse: under the bridge these are **EQUIVALENT** |
| `global_inj_implies_image_inj` | global injectivity is strictly more than needed |

So the ledger becomes:

```
ThCDeterminesCodeword  <=  EncodeBridge                        [already carried]
EncInj                 <=  EncodeBridge + EncMsgInjOnThCImage  [carried + ONE property]
```

`EncMsgInjOnThCImage` is the only thing here the chain does not already carry.

## An error I caught in my own statement before compiling

The first draft quantified `EncMsgInjOnThCImage` over **two independent**
`(ps, ad)` pairs. `EncInj` is stated at a **common** `(ps, ad)`
(`Composition.ec:68-71`) because the whole composition is address-bound — that is
what S-TCR(+C) buys. The two-address version is strictly stronger, so the claimed
equivalence would have been **false**. Fixed before the first compile and recorded
in the file so the shape is not "simplified" back later.

## Two failure modes I had been blurring

* **Injectivity at C10 is FINE.** The digit map sends 128-bit digests into a
  129-bit codeword space — `Proj129.c10_enc_inj_129`, exactly tight.
* **The ANTICHAIN half** of MM45's original `two_encodings` is what is
  unsatisfiable at C10 (largest antichain of `{0..7}^43` is `2^123.76 < 2^128`).

Unit 1 removed the antichain demand. It did **not** remove injectivity, and
injectivity was never the thing in trouble. Keeping these apart matters, because
"we removed `two_encodings` because it forced injectivity" would be the wrong
lesson and would make `EncMsgInjOnThCImage` look like a regression. It is not.

## Gate receipt (`gate_premisereduction.sh`)

Controls preserve **arity** — each swaps one hypothesis for a *different op of
the same shape* rather than deleting it, so a failure is semantic and not a
tactic-intro artifact.

```
COPY_IDENTICAL=yes   BASE_RC=0   ADMITS=0   AXIOM_DECLS_IN_FILE=0
MUTATED_A=1  NEGCTL_A_RC=1   inject `lemma : false`                      -> FAILS
MUTATED_B=1  NEGCTL_B_RC=1   EncodeBridge -> EncMsgInj                   -> FAILS
MUTATED_C=1  NEGCTL_C_RC=1   EncMsgInjOnThCImage -> ThCDeterminesCodeword -> FAILS
SRC_UNTOUCHED=yes    FINAL_RC=0
```

**Control C is the decisive one.** Substituting the *converse* premise breaks the
proof, so `EncInj` genuinely costs injectivity **on top of** the bridge — the
reduction is not secretly trivial, and the two directions really are independent.

## What is still owed

`encode_msgWOTS` is **abstract** in `base-c10` (`WOTS_TW_ES.ec:563`), constrained
only by the weakened `two_encodings` (`:579`) and `enc_nonzero` (`:597`). Neither
gives injectivity — deliberately. So `EncMsgInjOnThCImage` is **not derivable
here**.

`Proj129.c10_enc_inj_129` supplies the arithmetic *reason* it holds at C10, but
converting that into this premise requires **identifying `encode_msgWOTS` with the
base-8 digit map, and `ThC`'s output with the deployed 129-bit projection**. That
identification is unwired and is the single outstanding obligation on this path.

`Pr[G /\ COLL]` remains entirely uncharged. **C10 is still not proven at deployed
parameters.**
