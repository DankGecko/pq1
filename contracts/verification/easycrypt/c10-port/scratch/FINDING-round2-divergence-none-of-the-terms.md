# FINDING — the two reviewers DIVERGE on the central point, and the sharper one wins

2026-08-18, second half of the review round. GPT-5.6 and Kimi K3 were asked the same
question independently. They **converge** on the verdict and **diverge** on the
mechanism — and the divergence is the whole value of having run both. Everything
below re-verified by me at source.

---

## THE DIVERGENCE

| | claim |
|---|---|
| **GPT-5.6** | "the directly affected generic multi-target term is `S_TCR_C_Int_MA`; its quadratic component degrades from ~96 bits to `96 − 2⌈log₂ C⌉`" |
| **Kimi K3** | "**none** of the four terms degrades, by nothing — the model contains no signing-query parameter at all" |

**Kimi is right.** VERIFIED: the four carried terms appear in the capstone RHS
(`SphincsC10CapstoneWired.ec:595-604`) with **coefficient 1 and no query factor** —
they are bare `Pr[...]` summands. The same holds in the component theorem
(`XmssmtCC_All.ec:8583-8592`). Query counts enter only as win-condition caps keyed to
**hypertree geometry** (`t_smdttcr = c` for PKCOC; `Σ nr_trees × (2^h'−1)` for TRHC),
not to adversary behaviour.

GPT mapped the EasyCrypt term onto Lean's `(q + q²)·2⁻¹²⁸` generic-model arithmetic
for the *same assumption*. Those are two different objects: the EasyCrypt term is a
concrete reduction game's probability; the `q`-arithmetic is a separate, unmechanised
model of how hard that game is. **Nothing in the certified artifact prices `q`.**

So the correct statement is not "the certificate is silently weaker for the bootstrap
key". It is: **the certificate is silent, full stop.** All cross-chain degradation
lives outside it.

## THREE FACTS I DID NOT HAVE, ALL VERIFIED

### 1. A hard structural ceiling that `C · 65536` crosses at **C = 4**

```
base-c10-split/FL_SL_XMSS_MT_ES.ec:73   const l : int = 2 ^ h.
base-c10-split/SPHINCS_PLUS.ec:124      const h : int = h' * d.        (h' = 9, d = 2)
```

So `l = 2^18 = 262144` — the number of messages the hypertree game signs at all. The
bootstrap key's cross-chain budget `C · 65536` reaches it at **C = 4**. This is not a
probability claim; it is the model's capacity. Beyond it the deployment would be
outside the geometry the theorem is stated over.

*(Practically irrelevant — real bootstrap use is tens of signatures, slot rotations
only. But it is a crisp, checkable boundary where the earlier discussion had only
soft arithmetic.)*

### 2. The premise I wanted to protect is **already pinned**

`c <= p_tgts` is pinned where it is load-bearing. VERIFIED two ways: the capstone
statement is pinned (`cert-statements-split.tsv:3`), and `tools/stmt_digest.py:108-113`
digests from `^lemma|theorem <name>` to `^\s*proof\b` — i.e. **the whole statement,
premises included**. Any drift in that premise at the certified boundary already
turns the gate red.

This deflates the deferred `EXPECT_PINS 111 -> 113` unit a third time: it is not
merely on the wrong (supplemental) chain, it **duplicates protection that exists**.

Kimi also caught a mechanical defect: `stmt_digest.py`'s negative lookahead
`(?![A-Za-z0-9_'])` means a pin on `D1_MEUFNACMA_WOTSC` would **not** match
`D1_MEUFNACMA_WOTSC_MM45`. Correct targets, both in the gated file:
`WOTS_C_Multi.ec:523` and `:951`.

### 3. The unbounded-query evidence was outside the repo — and I had looked in the repo

I could not find `DigitalSignatures.ec` and stopped. It is an EasyCrypt **stdlib**
theory, in the opam switch:

```
~/.opam/checkct/lib/easycrypt/theories/crypto/DigitalSignatures.eca:1335
  "... access to a signing oracle that it can query an unlimited number of times"
```

`O_CMA_Default` keeps a query list as a **counter, not a cap**. So the game's
unlimited-query nature is documented in the library, and my Q1(a) conclusion now
rests on the source rather than on inference from the module expression.

**That is `absence-from-the-wrong-scope` for the fourth time in one day** — I searched
the project tree for a file that lives in the toolchain's library path.

## WHAT BOTH REVIEWERS AGREE ON

Single-key role-agnostic game; no scope restriction written anywhere; the question is
documentation, not proof; the pins are busywork; and the capstone does not consume the
D.1/bridge chain (both reached this independently — GPT via `:624`, Kimi via the same
line plus "SPHINCS_C.ec is the older pre-wired assembly").

## THE BETTER NEXT UNIT — Kimi's, and it is better than anything on my list

**Promote the scope-limiting theorems into the closure and pin them, so the gate
certifies what the certificate does NOT say.**

`experiments/ptgts-pin/PTgtsPin.ec` already proves them and **already compiles**
(Kimi compile-tested it: RC=0, ~2 s; it is the artifact from the 2026-08-15 pin work):
`c = 262656`, `! (c <= 65536)` (`c10_usage_cap_is_not_admissible_as_p_tgts`), and
`l = 2^18`. Its own prose already says *"nothing in this model expresses the on-chain
2^16 cap"*.

Turning that prose into **pinned, gated theorems** converts the Q1(c) finding — *the
scope restriction is written nowhere* — from a README paragraph into a machine-checked
artifact. It is the only candidate that changes what can be claimed, and it uses work
that already exists.

Ranking, revised: **(1) pin the negative scope facts** · (2) bridge repair, with eyes
open that the certificate does not need it · (3) the statement pins — busywork.
