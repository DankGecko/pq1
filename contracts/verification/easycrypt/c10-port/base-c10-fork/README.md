# base-c10-fork — the P-relativized MM45 fork  ***VIABLE — my abandonment was WRONG***

**Status: INCOMPLETE but VIABLE.** I abandoned this on 2026-07-28 for a reason
that was WRONG; the retraction and the corrected scope are at the foot of this
file. It still does not build. Deliberately NOT in
`closure-c10.txt`, not referenced by `wire_test.sh` (0 references), and
`base-c10/` is untouched. The green chain is unaffected. Do not cite anything
here as a result.

(This file replaces the copied `base-c10/README.md`; see that file for the
unforked base's own diff-vs-vendored story.)

## What this is for

`cdrafts/LeafWiring.ec` proves that identifying the chain's `encode_msgWOTS` with
the deployed digit map is **inconsistent** with `axiom two_encodings`
(`base-c10/WOTS_TW_ES.ec:579`) — the unrelativized axiom demands an antichain
image, and the digit map's image is not one. The only sound repair is to
relativize `two_encodings` (and `enc_nonzero`) to a predicate `P`, instantiated at
the +C constant-sum gate.

Relativizing **in place** is impossible: `FL_SL_XMSS_MT_ES.ec:6342` consumes
`MEUFGCMA_WOTSTWESNPRF` through a reduction that queries the WOTS-TW oracle on
subtree **roots**, which satisfy no gate. Hence a fork.

## What was done, and what it measured

A full copy of `base-c10/` with `op P : msgWOTS -> bool` and both encoding axioms
relativized to it. At `P := predT` it is `base-c10` verbatim.

| site | change |
|---|---|
| `two_encodings` (:579) | `P m => P m' =>` |
| `enc_nonzero` (:597), `exenc_neq0` (:601) | `P m =>` |
| `nhchwcoll_hchwpre` (:1321) | `P m => P m' =>`; proof passes them to the axiom |
| `nhchwcoll_hchwpre_msg` (:1362) | same; its pre-existing single `admit` is preserved, not multiplied |
| `relcqsadpre_rng` (:1528) | `all (fun q => P q.\`2) qs =>`, discharged pointwise via `allP` |

All five are mechanical hypothesis-threading.

**Measured: roughly 5,000 of 6,358 lines compile unchanged.** The estimate carried
into this work — "~3450 lines to re-prove" — is wrong *in shape*. Nothing needs
re-proving. What is needed is threading **one invariant** through the games.

## THE ONE REMAINING OBSTACLE (exact)

`WOTS_TW_ES.ec:6296`, the forgery site inside
`section Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF`:

```
move/(nhchwcoll_hchwpre_msg ps{2} q.`1 _ _ q.`4 sig'{2}) /(_ _): (neqq2_mp) => //.
```

It needs `P q.\`2` (queried message) and `P m'{2}` (forged message). Neither is
available, because **the game does not guarantee them**. Closing it requires:

1. gating `O_MEUFGCMA_WOTSTWESNPRF.query` (:2470) on `P m`;
2. conjoining `P m'` to the win condition — `is_fresh <- m' <> m` occurs at **six**
   sites (:2434, :2681, :3734, :3787, :3838, :3978): the game and five hop variants;
3. establishing `all (fun q => P q.\`2) O_MEUFGCMA_WOTSTWESNPRF.qs` as a game
   invariant and carrying it through the hops.

Honest remaining cost: **one invariant, six game variants** — not a re-proof.

## THE ARCHITECTURAL QUESTION — MY FIRST ANSWER WAS WRONG (retracted below)

I first answered this **negatively** and abandoned the fork. That answer is
RETRACTED — see "CORRECTION" at the foot. The reasoning below is preserved
because the retraction is only legible against it.

The D.1 hop (`cdrafts/XmssmtCC_All.ec:1186-1190`) bounds the +C game by the
**standard** one:

```
Pr[M_EUF_GCMA_WOTSC_NPRF(..., O_MEUFGCMA_WOTSC_Default, ...)]
  <= Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(...), O_MEUFGCMA_WOTSTWESNPRF, ...)]
   + Pr[S_TCR_C_Int_MA(...)]
```

and that standard term is **live in the capstone bound**
(`cdrafts/SphincsC10CapstoneWired.ec:586`). Meanwhile the SAME game is what
`FL_SL_XMSS_MT_ES.ec:6342` discharges, through a reduction querying the oracle on
subtree **ROOTS**.

So `M_EUF_GCMA_WOTSTWESNPRF` is instantiated by:

| track | messages | gate |
|---|---|---|
| +C, via `R_int_WOTSTW` | `ThC` digests | satisfy `predC` by the grind |
| standard, via `FL_SL`'s reduction | subtree roots | satisfy **no** gate |

A single global `op P` cannot be both. At `P := predC` the FL_SL discharge breaks;
at `P := predT` the axiom is the strong one again, which
`cdrafts/LeafWiring.ec` proves the digit map contradicts. **Forking the base does
not separate these — both instantiations are live in the same capstone bound.**

What would be needed is restructuring so the +C track does not route through the
shared WOTS-TW game at all. That is a redesign of the D.1 hop, not a fork, and
nothing here establishes that it is possible.

## Do not

* Do not add `base-c10-fork` to `closure-c10.txt` or `wire_test.sh` — it does not
  build.
* Do not put it on an include path alongside `base-c10`: EasyCrypt include order
  does **not** shadow, so `-I base-c10-fork -I base-c10` resolves to `base-c10`
  and would silently compile the UNFORKED axiom. Use the fork dir alone.
* Do not cite the ~5,000-line figure as "80% done". It measures how little the
  *axiom relativization* disturbs the file, not how much of the remaining game
  work is finished.


---

# CORRECTION 2026-07-28 — the abandonment was WRONG, and the fork is VIABLE

I claimed the standard WOTS-TW game is instantiated by two tracks with
incompatible message populations, so no single `P` could serve both, and
abandoned the fork. **Two source facts refute that.**

## 1. The +C track queries the standard oracle with GATED DIGESTS

`cdrafts/WOTS_C_Interactive.ec:1700-1712` documents `R_int_WOTSTW`'s wrapper
verbatim: on a +C query `(wad, m)` it

1. grinds a Prop-satisfying counter `c` via `OC.query`,
2. fetches `d = ThC pp ad m c` and calls **`O.query(wad, d)`** — "the honest
   WOTS-TW oracle signs `d`",
3. returns `(pk, (sig_tw, c))`.

So the message reaching the standard oracle is the **digest**, which satisfies
`predC` by construction (`wotsc_grind_targets_predC`). Not the raw message, and
not a root.

## 2. The +C chain never applies FL_SL's ungated theorem

In the capstone the standard-game term appears **carried, with a specific
adversary** (`SphincsC10CapstoneWired.ec:585-587`):

```
Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                           O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
```

and a search of `cdrafts/` for the ungated `EUFNAGCMA_FLSLXMSSMTTWESNPRF` returns
**only comments** ("Mirror of MM45's...", "MM45 analog:"). The +C port uses its
own `EUFNAGCMA_FLSLXMSSMTTWCESNPRF` over `O_MEUFGCMA_WOTSC_Default`. **FL_SL's
root-querying discharge is not on the +C chain's path.**

So the only adversary instantiating the standard game *in this chain* is one that
queries gated digests. A gated theorem would serve it.

## CORRECTED SCOPE

The fork is viable, at this cost:

1. **Gate the game** — as previously measured: oracle `query` (:2470) on `P m`,
   `P m'` into the win condition at six sites (:2434, :2681, :3734, :3787, :3838,
   :3978), and `all (fun q => P q.\`2) qs` as an invariant through the hops.
   **One invariant, six game variants.**
2. **Accept that `FL_SL_XMSS_MT_ES.EUFNAGCMA_FLSLXMSSMTTWESNPRF` (:6306, applied
   at :6342) becomes unprovable in the fork** and admit or delete it. This is the
   step my abandonment mistook for fatal. It is acceptable *precisely because* the
   +C chain never uses that theorem — but it MUST be recorded as a deliberate
   deletion, not a silent break, and anything else depending on it must be traced.
3. **Audit `SPHINCS_PLUS.ec` for the same dependency** — not yet checked.
4. **Re-point the +C chain at the fork**, keeping the vendored dir and `base-c10`
   off the include path (order does not shadow).

## Not established

That (2) is the *only* casualty — the transitive dependants of FL_SL's ungated
theorem inside `base-c10` have not been enumerated. That enumeration is the next
concrete unit, and it is cheap: compile the fork's `FL_SL_XMSS_MT_ES.ec` with the
theorem admitted and read off what else fails.

---

# ENUMERATION + MEASURED GATING COST (2026-07-28)

## 1. What else breaks downstream: NOTHING

With the two gate obligations localized as marked scaffold admits
(`SCAFFOLD-P1/P2/P3`), so the lemma **signatures are unchanged**:

| file | result |
|---|---|
| `base-c10-fork/WOTS_TW_ES.ec` | **rc=0** (4 admits: 3 scaffold + 1 pre-existing) |
| `base-c10-fork/FL_SL_XMSS_MT_ES.ec` | **rc=0** (640s) |
| `base-c10-fork/FORS_ES.ec` | **rc=0** (514s) |

And the decisive check — do downstream base files ever *call* the four
P-carrying lemmas?

```
nhchwcoll_hchwpre_msg / nhchwcoll_hchwpre / relcqsadpre_rng / exenc_neq0
  FL_SL_XMSS_MT_ES : 0    FORS_ES : 0    SPHINCS_PLUS : 0
```

**All four are `WOTS_TW_ES.ec`-LOCAL.** Putting `P` on their signatures costs
nothing downstream. My earlier step 2 — "accept that FL_SL's ungated theorem
becomes unprovable and delete it" — is **not needed**. Nothing has to be deleted.

## 2. Where the cost actually is: gating the winning event

The three scaffold admits can only be discharged if the game guarantees `P` on
the queried and forged messages. Two ways were tried:

* **via `is_fresh`** — `is_fresh <- m' <> m /\ P m /\ P m'` at 6 sites
* **via the return** — extra `/\ P m /\ P m'` conjunct at the 4 matching sites,
  leaving `is_fresh` untouched

**Both fail at the same place** (`:5321` / `:5325`), with
`cannot apply split/None on that goal`. The failing region is

```ec
rewrite eq_iff; split => [[#]| /#].
...
rewrite !andbA andbC -!andbA 2!andbA; split => [|/#].
```

i.e. explicit **conjunction-arity shuffling** of the game postcondition. Any extra
conjunct — wherever it is added — changes that arity.

**Measured scale: ~92 goal-shape-sensitive tactic sites** in
`section Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF` (:2909-:6358), at 2-4 min per compile
with errors surfacing **serially, one per run**.

That is the honest cost of the fork: not a re-proof, not a deletion, but on the
order of **~92 serial tactic-arity repairs**, i.e. many hours of wall clock and
plausibly more than one session. It is mechanical, low-risk work — but it is not
a turn's worth.

## 3. Current state of this directory

`WOTS_TW_ES.ec` **compiles (rc=0)** with:
* both encoding axioms relativized to `P`;
* `SCAFFOLD-P1/P2` inside `nhchwcoll_hchwpre_msg` and `SCAFFOLD-P3` inside
  `relcqsadpre_rng` — the two gate obligations, clearly named;
* the file's one pre-existing admit untouched.

This is a **usable baseline**: the axiom work is done and downstream-clean, and
the remaining job is exactly "discharge the three scaffolds by gating the game,
repairing arity as you go".

`chmod 777 base-c10-fork` is required — the container runs as uid 1001 and cannot
write `.eco` into a host-created directory otherwise. Symptom is a silent `rc=1`
at 100% progress with **no** `[critical]` line.

---

# THREE GATE PLACEMENTS TRIED — ALL RIPPLE (2026-07-28)

`SPHINCS_PLUS.ec` also compiles against the scaffolded fork (**rc=0, 186s**), so
the enumeration is complete: **all three downstream base files build, and none
calls any P-carrying lemma.**

The remaining job is discharging `SCAFFOLD-P1/P2/P3`, which needs the game to
guarantee `P`. Three placements were tried, on the theory that a less invasive
one might avoid the arity problem:

| placement | change | first failure |
|---|---|---|
| `is_fresh` | `is_fresh <- m' <> m /\ P m /\ P m'`, 6 sites | `:5321` `cannot apply split/None` |
| return conjunct | extra `/\ P m /\ P m'`, `is_fresh` untouched | `:5325` `cannot apply split/None` |
| folded into `is_valid` | `is_valid <- is_valid /\ P m /\ P m'` | `:4804` `[by]: cannot close goals` |

The third was the most promising idea — strengthening an *existing* boolean
leaves the return's conjunction arity untouched, so it should dodge the
`rewrite !andbA andbC -!andbA 2!andbA` sites. It does, and then fails earlier
instead, because the hops also *reason about what `is_valid` means*.

**Conclusion: the ripple is not an artifact of where the conjunct goes.** Changing
the game's winning event changes what every hop has to prove, and the section
proves it explicitly. There is no cheap placement.

## Honest status of the fork

**NOT DONE.** What is done, and is solid:

* both encoding axioms relativized to `P`;
* five mechanical use-site edits;
* the three remaining obligations isolated and named (`SCAFFOLD-P1/P2/P3`);
* the whole thing **compiles (rc=0)** as a baseline;
* measured downstream impact: **zero** — `FL_SL` (640s), `FORS_ES` (514s) and
  `SPHINCS_PLUS` (186s) all rc=0, and no downstream file calls any of the four
  P-carrying lemmas.

What remains is the gating, and it is **~92 serial tactic-arity repairs** through
`section Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF` at 2-4 min per compile with one error
surfacing per run. Mechanical and low-risk, but hours of wall clock and more than
one session. It has **not** been attempted beyond the three probes above, and the
fork should not be described as nearly finished.

---

# THE FORK NOW BUILDS (2026-07-28) — with two deliberate concessions

All four base files compile against the **gated** game, `.eco` purged:

| file | rc | admits (fork vs base-c10) | axioms |
|---|---|---|---|
| `WOTS_TW_ES.ec` | 0 | **2** vs 1 | 5 vs 5 |
| `FL_SL_XMSS_MT_ES.ec` | 0 | **1** vs 0 | 2 vs 2 |
| `FORS_ES.ec` | 0 | 0 vs 0 | 2 vs 2 |
| `SPHINCS_PLUS.ec` | 0 | 0 vs 0 | 1 vs 1 |

**No new axioms anywhere.** The relativization is a hypothesis change, not an
assumption.

## Concession 1 — `FL_SL`'s WOTS-TW reduction is ADMITTED (2,202 lines)

`EUFNAGCMA_FLSLXMSSMTTWESNPRF_MEUFGCMAWOTSTWES` is `admit.`-ed. It is **not** an
arity casualty: its adversary queries the WOTS-TW oracle on **subtree roots**,
which do not satisfy `P`, so under the gated game the statement is **false for
that adversary**. It cannot be repaired; it can only be scoped out.

Sound for the +C track because nothing there applies it: it is a **`local`**
lemma (section-scoped, cannot escape the file), and the sole mention in
`cdrafts/` is prose in a comment (`XmssmtCC_All.ec:8438`). The +C track ports
FL_SL separately as `..._TWCESNPRF` over `O_MEUFGCMA_WOTSC_Default`.

**`base-c10-fork` is therefore a +C-ONLY artifact, not a drop-in replacement for
`base-c10`.** Anyone reusing it for a non-+C purpose must restore that proof.

## Concession 2 — SCAFFOLD-P3 remains

`relcqsadpre_rng` still needs `all (fun q => P q.\`2) qs` — **every stored query**
gated, not just the one at the forgery index. The win-condition gate gives only
the latter. Closing it needs the **oracle** gated (or that invariant added to the
win condition), which is unattempted.

## Correction to this file's own earlier claim

An earlier section here says the enumeration showed "nothing downstream breaks".
**That was measured with the SCAFFOLD in place** — lemma signatures unchanged —
so it tested only the axiom relativization, never the gate. With the gate
actually applied, `FL_SL` breaks. The original scope's "step 2" (accept that
FL_SL's reduction becomes unprovable) was RIGHT; retracting it was wrong.

## Remaining to make the fork useful

1. Discharge SCAFFOLD-P3 (oracle gate + invariant).
2. Re-point the +C chain (`cdrafts/`) at `base-c10-fork`, vendored and `base-c10`
   OFF the include path — order does not shadow.
3. Re-run the full closure against the fork and compare receipts.

---

# CORRECTIONS 2026-07-29 — three, from an adversarial adjudication

## 1. My `local` justification for the FL_SL admit was INVALID

I wrote that admitting `EUFNAGCMA_FLSLXMSSMTTWESNPRF_MEUFGCMAWOTSTWES` is sound
"because it is a `local` lemma (section-scoped, cannot escape the file)".
**`local` restricts NAMING, not TRUST PROPAGATION.** The admit propagates:

```
:4083  local lemma …  (admit :4120)
  -> applied :4158 inside :4129 EUFNAGCMA_FLSLXMSSMTTWESNPRF   (NOT local, exported :4213)
  -> applied SPHINCS_PLUS.ec:4379 inside :4342 EUFCMA_SPHINCS_PLUS (NOT local)
```

**Two exported MM45 theorems are admit-backed in this fork, including the
SPHINCS+ headline.** Per-file admit counts cannot see this, and EasyCrypt has no
`#print axioms`, so the table above showing `SPHINCS_PLUS.ec | admits 0` is
STRUCTURALLY BLIND to it. That table is not a soundness receipt.

The conclusion survives, on a different argument: **availability != use.** Both
tainted names are in scope for 12 of 16 closure members, and **no closure member
applies either** — every `cdrafts/` hit is comment prose or the distinct
`_C10`/`_FX`/`_C` lemmas.

## 2. "The statement is FALSE" was an overclaim

At `P := predT` this fork **is** base-c10, which proves the lemma outright — so
the fork cannot refute it. Correct wording: **not derivable without an added
hypothesis.** No falsity witness exists anywhere in the repo. Banner corrected in
place.

## 3. "All four base files compile" was UNBACKED for two of them

`.eco` dependency digests showed `FL_SL_XMSS_MT_ES.eco` and `SPHINCS_PLUS.eco`
both recording `WOTS_TW_ES.ec = b81f46be…` — the **pre-split** file — while the
current source is `87a8bda1…`. They had been built against a stale
`WOTS_TW_ES`. **Trap T2, third occurrence this session.**

Re-measured under purge (`ECO_PURGED=4`), and it holds:

```
WOTS_TW_ES        rc=0  123s
FL_SL_XMSS_MT_ES  rc=0  131s   (fast now: the 2,202-line proof is admitted)
FORS_ES           rc=0  389s
SPHINCS_PLUS      rc=0  171s
```

The claim was true; I did not have grounds for it when I made it.

## Also surfaced

* `enc_nonzero` now has **no live consumer** — its only application was inside
  the (now dead) gated `relcqsadpre_rng`. It can be deleted.
* `_fast.ec` was sitting **inside the include directory** carrying admits; any
  glob compile would have picked it up. Removed.
* **`P` CAN be supplied** — by *defining* it in the fork, which needs no clone
  binding site. And with `P m := digitsum (encode_msgWOTS m) = target_sum` the
  relativised `two_encodings` becomes **provable** via the `constsum_antichain`
  argument, taking the fork from **2 encoding axioms to 0**. "Cannot be
  instantiated at C10" was wrong; it cannot be instantiated *by cdrafts alone*.

---

# BOTH ENCODING AXIOMS RETIRED (2026-07-29) — the fork now has FEWER axioms than base-c10

`P` is no longer abstract. It is **defined**:

```ec
const target_sum : int.                                    (* declaration, not an axiom *)
op digitsum (e : emsgWOTS) : int = bigi predT (fun i => BaseW.val e.[i]) 0 len.
op P (m : msgWOTS) : bool = digitsum (encode_msgWOTS m) = target_sum.
```

On the constant-sum surface the antichain property is a **theorem**, so:

| axiom | before | after |
|---|---|---|
| `two_encodings` | axiom (relativized) | **LEMMA** — proved via `constsum_antichain` |
| `enc_nonzero` | axiom (relativized) | **DELETED** — no live consumer |

`constsum_dominance` / `constsum_antichain` are ported verbatim from
`cdrafts/SphincsC10Content.ec:269-301` (proved there, not re-derived here).

## Axiom census, verified

| file | fork | base-c10 |
|---|---|---|
| `WOTS_TW_ES.ec` | **3** | 5 |
| `FL_SL_XMSS_MT_ES.ec` | 2 | 2 |
| `FORS_ES.ec` | 2 | 2 |
| `SPHINCS_PLUS.ec` | 1 | 1 |

The two removed are exactly `two_encodings` and `enc_nonzero`. **The fork is
strictly weaker in assumptions than the base it forked from.**

## Clean rebuild receipt (`ECO_PURGED=4`)

```
WOTS_TW_ES        rc=0  131s
FL_SL_XMSS_MT_ES  rc=0  145s
FORS_ES           rc=0  389s
SPHINCS_PLUS      rc=0  176s
```

## Three dead objects deleted

`enc_nonzero` (axiom) → its only consumer `exenc_neq0` → whose only consumer was
the gated `relcqsadpre_rng`, left with zero references by the `:6329` split. All
three removed; nothing in the fork or `cdrafts/` referenced any of them.

## What this does NOT change

* **`FL_SL_XMSS_MT_ES.ec:4120` is still admitted**, and per the correction above
  that admit propagates into two EXPORTED MM45 theorems
  (`EUFNAGCMA_FLSLXMSSMTTWESNPRF`, `EUFCMA_SPHINCS_PLUS`). Retiring the encoding
  axioms does not touch that.
* **`target_sum` is unconstrained.** Nothing here says it is 205, or even that it
  is reachable. `P` may be identically false, in which case the gated game is
  trivial — the same vacuity hazard `cdrafts/WOTS_C_Real.ec` documents for its own
  `predC`, now present in the fork too.
* The fork is still **not** built against `cdrafts`, and `predC` is still not tied
  to this `P`.
