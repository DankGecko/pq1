# FINDING — the certified capstone does NOT consume D.1, so gating `WOTS_C_Multi` bought less than I claimed

2026-08-18, after the vendor push. Raised by GPT-5.6; **re-verified independently at
source before accepting it**, because it contradicts a claim I published minutes
earlier.

---

## WHAT I PUBLISHED

> "`c <= p_tgts` is a premise carried by 11 of the closure members, in 48 places.
> The lemma that justifies its *shape* — `D1_reduce` — lived in a file that was in
> neither `closure-c10-split.txt` nor any `cert-*.tsv`. **The gate had never built
> it.**"

The factual half is right. The **inference is wrong**, and it is the part that made
the change sound load-bearing.

## WHAT IS ACTUALLY TRUE — VERIFIED

**The certified capstone never reaches `D1_reduce`.** It discharges the hypertree
term by applying the +C component theorem *directly*:

```
cdrafts-split/SphincsC10CapstoneWired.ec:624
  have hHT := EUFNAGCMA_FLSLXMSSMTTWCESNPRF (R_top_C(F)) &m hc emb_disj_concrete ...
```

`D1_` occurs in that file **exactly once**, in a comment (`:548`), and that comment
names the route that IS taken:

> *"Carried from **`interactive_D1_MA`** up through `XmssmtCC_All` to here."*

**`interactive_D1_MA` is `cdrafts-split/WOTS_C_Interactive.ec:3193`, and that file
has been IN the closure all along.** It carries `c <= p_tgts` as its own explicit
premise (`:3197`), and the "one target per query" rationale is stated in the same
gated file:

```
cdrafts-split/WOTS_C_Interactive.ec:1350
  * `c <= p_tgts`  : one target per query, S-TCR cap >= query cap
```

Every one of the 11 premise-carrying files is on that interactive route.
`WOTS_C_Multi` was **not** among them — it could not be, it was not in the closure.

## SO THE TWO ROUTES ARE PARALLEL, NOT SEQUENTIAL

```
CERTIFIED:  interactive_D1_MA (WOTS_C_Interactive, GATED)
              -> XmssmtCC_All -> SphincsC10CapstoneWired        [GREEN]

PAPER D.1:  D1_reduce -> D1_MEUFNACMA_WOTSC (WOTS_C_Multi, now gated)
              -> D1_bridge_WOTSTW (WOTS_C_Bridge)               [RED]
              -> WOTS_C_EmbDischarge -> SPHINCS_C               [ungated]
```

The second is a **second, independent assembly of the same leg**, following paper
2022/778 App. D. The capstone does not depend on any of it. That is *why* the bridge
being red costs the certified artifact nothing — a fact I stated correctly while
giving the wrong reason for it.

## WHAT THE RE-BASELINE ACTUALLY BOUGHT

**Real, and worth having:** a compiling, zero-admit file is now inside the gate, so
it cannot rot silently the way `WOTS_C_Bridge` did — which is exactly the failure
this same session found and diagnosed. The census machinery proved it added zero
ledger rows.

**Not what I said it was:** it did **not** bring the certified premise's
justification inside the gate. That justification was never outside it.

And a sharper point that survives: **neither route discharges `c <= p_tgts`.** Both
carry it as a hypothesis. "The lemma that justifies its shape" was the wrong phrase
for `D1_reduce` in the first place — `D1_reduce` *uses* the premise, it does not
establish it.

## THE FRAMING ERROR UNDERNEATH

I found a premise in 11 certified files, found a lemma elsewhere that mentions the
same premise, and concluded the second justified the first — **without checking
whether the certified chain reaches it.** A name-level match was read as a
dependency. The check that settles it is one grep of the capstone for `D1_`, which
returns a single comment pointing at a *different* lemma.

Same family as `absence-from-the-wrong-scope`, inverted: **presence in the wrong
scope**, read as relevance.

## CONSEQUENCE FOR THE PLANNED NEXT UNIT

`EXPECT_PINS 111 -> 113` was already deferred on the grounds that pinning the first
link of a chain whose second link is red overstates assurance. This finding makes it
weaker still: the chain being pinned is **not the certified one**. The pins would be
honest drift-hardening on a supplemental development, and must be labelled that way
if they are ever added.
