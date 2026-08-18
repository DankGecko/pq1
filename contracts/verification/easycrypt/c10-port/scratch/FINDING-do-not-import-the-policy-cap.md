# FINDING — do not import `MAX_SLOT_USES`, and stop quoting `2^-82`

2026-08-15. GPT-5.6's verdict on whether to import the deployment cap. Blunt
answer: **no**, and the reason goes deeper than the query-count arithmetic.

---

## 1. THE STRONGEST OBJECTION, AND IT INVALIDATES THE WHOLE NUMERIC THREAD

> *"A surface cardinality does not prove that `Pr[T_COLL_RES_ENUM]` is bounded by
> a birthday expression."*

`q² / |C_T|` **is not obtained by counting `|C_T|`.** Counting gives the surface
size. Turning that into an advantage bound needs an explicit
distributional/computational assumption about how `ThC` images behave against an
adversary that **holds the keyed collection oracle and chooses its own forged
counter** — and the game file says so itself: nothing bounds
`Pr[T_COLL_RES_ENUM(B)]`.

So `2^-82` (Kimi), `2^-78.09` (mine), and every refinement of them are **heuristic
estimates resting on a model that was never derived**. GPT's phrasing is the one to
keep:

> *"Importing a smaller policy cap would cosmetically improve a number whose
> underlying probability bound has not been established."*

**I spent two rounds refining a number that has no proof under it.** That is the
finding.

## 2. THE QUERY COUNT DOESN'T WORK EITHER — and I verified the load-bearing part myself

GPT's Q3 answer: `c`, signing queries, WOTS uses and registered targets are four
different quantities, and the reduction registers **all** of them eagerly.

**GPT cited `_gamehops_wip.ec` for this — a file absent from `closure-c10-split.txt`
and from all four `cert-*.tsv`.** That is the same non-certified-draft trap that
`Extraction.ec` set for me, so I checked the live file instead.

**VERIFIED on the live closure member** (`XmssmtCC_All.ec:752`, closure entry #8):
`R_MEUFGCMAWOTSC_EUFNAGCMA_C.choose` calls `A(OC).choose()` and then runs
`while (size pkWOTStd < d)` under the comment *"compute and store **all** the
WOTS+C public keys"*. It is **eager**.

*(Note the live `R_int_WOTSTW.choose` at `WOTS_C_Interactive.ec:1802` is by
contrast **lazy** — `O_wrap.init; AA.choose()`. The eagerness is at the hypertree
layer, not the WOTS one. GPT's claim was right about the composition and wrong
about which module does it.)*

Consequences:

* `nrts = c = 262656` **regardless of how many signatures the deployment makes**;
* substituting `q_s = 2^16` is wrong, and `2·q_s = 2^17` is **equally unsupported**;
* a `q_s`-dependent bound needs an **on-demand/lazy reduction** registering only
  the WOTS instances a signing query actually exposes, plus handling of repeated
  indices. That is a substantial rebuild, not a substitution.

## 3. Q2 — the P14 caveat: yes and no, and I had it half wrong

* **YES**: a blanket per-key `q_s = 2^16` is **false for the bootstrap key**. The
  bootstrap signer is global (`domain/src/lib.rs:407`), the cap is enforced
  per-wallet-instance (`PQSmartWallet.sol:449`), and the project's own
  `Quantitative.lean:172` already states the cross-chain budget is `C · 65536`.
  It is valid only for a **chain-bound slot key**, or for the bootstrap key
  restricted to one chain.
* **NO**: this does **not** multiply the target count by `C`. One WOTS cube exists
  per SPHINCS public key; reusing the bootstrap key across chains exposes more
  messages **within the same cube**, it does not create `C` cubes.
* And a conflation of mine: `ad` in `T_COLL_RES_ENUM` is a **SPHINCS/WOTS tweak
  address**, not an Ethereum address or chain identity.

## 4. IF A QUERY-BOUNDED STATEMENT IS EVER MADE, THIS IS ITS SHAPE

Query-bounded EUF-CMA is a legitimate **concrete-security** theorem, not a category
error — but it must be named so nobody reads it as unrestricted:

```
forall A. Time(A) <= t /\ Q_sign(A) <= Q  =>  Adv^EUF-CMA(A) <= eps(t, Q)
```

with the deployment claim **separate**:

```
DeploymentTrace(A) => Q_sign,key(A) <= 65536      (slot key)
                   => Q_sign,key(A) <= C * 65536  (bootstrap, C chains)
```

Call it `EUF-CMA[Q <= 2^16]`, never "EUF-CMA". **Importing `MAX_SLOT_USES` into the
game definition** would collapse that separation and make a reusable cryptographic
theorem depend on one wallet's on-chain policy.

## 5. WHAT I AM RETRACTING

* *"pin `p_tgts` to make `2^-82` quotable"* — already retracted; the pin showed why.
* *"import `MAX_SLOT_USES`"* — retracted before starting, which is the point of
  having asked.
* **`2^-82` and `2^-78.09` should not be quoted at all** until the birthday model
  is an assumption someone has written down and justified.

**Three consecutive proposed next-units have now been refuted on inspection.**
That is a signal about the area, not just about me: the numeric thread has been
chasing precision on an underived quantity. The honest position is that
`Pr[T_COLL_RES_ENUM]` is an **unbounded assumption**, the surface count is a
**theorem**, and there is currently **no derivation connecting them**.

## 6. WHAT WOULD ACTUALLY BE WORTH DOING

Not another number. Either:

* **(i)** write down the collision-hardness assumption explicitly — what
  distribution, against what oracle access — so the birthday step becomes a stated
  premise rather than folklore; or
* **(ii)** rebuild the hypertree reduction lazily so target count tracks signing
  queries, which is what any `q_s`-shaped bound would need; or
* **(iii)** stop here and document the leg as an assumption with a machine-checked
  surface count and no advantage claim.

(iii) is defensible today. (i) is small and honest. (ii) is a real project.

---

## 7. KIMI K3 — CONVERGES, and adds the two sharpest points

**Its run was KILLED mid-delivery**, so this is partial output (49 KB), not a
completed review. Recorded as such: `scratch/review_kimi_policycap_2026_08_15_PARTIAL.md`.
It had, however, already delivered its verdict sections.

### (a) "There is nothing to plug the number into" — VERIFIED by me

`T_COLL_RES_ENUM` **does not appear anywhere in the certified trees.** I checked:
`grep -rn "T_COLL_RES_ENUM" cdrafts-split/ base-c10-split/` returns **nothing**,
and the certified capstone RHS (`SphincsC10CapstoneWired.ec:595-604`) carries
exactly four terms:

```
Pr[M_EUF_GCMA_WOTSTWESNPRF ...]
Pr[S_TCR_C_Int_MA ...]
Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C ...]
Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C ...]
```

Kimi's phrasing: *"You are proposing to import deployment policy to rescue a
constant in a numerator whose denominator — the reduction and the bound — does not
exist."*

This is consistent with everything said about the work being outside the certified
surface, but it sharpens it: the term I have been pricing is **in a proposal, not
in the certified statement**, and `TCollResEnum.ec`'s own header says so
(`:5-7`, `:51-57`).

### (b) `MAX_SLOT_USES` is a MUTABLE GOVERNANCE PARAMETER — the decisive objection

> *"You would be adding TCB and fragility to buy 4 bits on a number that
> currently appears in no theorem."*

It is a contract constant changeable by redeployment/governance **and** a firmware
constant changeable by update. Binding it into the EasyCrypt development turns a
cryptographic theorem into one whose hypothesis is "the current deployment
configuration of PQSigner_OS, plus the firmware gate's correctness (outside
EasyCrypt's TCB), plus — for the bootstrap key — an enforcement that provably does
not exist."

I had not considered the TCB cost at all.

> **CORRECTED by Kimi's own full run — see §8. "Mutable governance parameter" is
> OVERSTATED, and I recorded it too strongly. The TCB point survives in weaker
> form; it is NOT on its own sufficient to decline.**

### (c) A correction to Kimi's OWN earlier claim, which I had carried

Kimi previously said `2^-82` "clears the 96 floor". Its own later note retracts
that as unchecked: `2^-82` is an **advantage of ~82 bits**, i.e. *below* 96, and
the floor is only cleared if the `2^14.9` grind factor is counted as adversary
work (`82 + 14.9 ≈ 96.9`). Flagged INFERRED, not verified against
`forsc_grinding_margin.py`'s actual comparison.

So *"clears the floor"* was never established either. One more reason the number
should not be quoted.

### (d) Q2, refined against my write-up above

Kimi splits it more finely than GPT: **no** for slot keys (chain-bound and
firmware-enforced, so P14 does not degrade the WOTS leg fed by slot keys);
**yes** for the bootstrap key — and *worse* than P14 states, because the
produced-signature escape means **no device-side cap exists at all** for
bootstrap. Whether that matters depends on whether the overall EUF-CMA statement
is meant to cover bootstrap-signed Type-1 authorisations. **That is an open
question I have not resolved.**


---

## 8. KIMI'S FULL RUN CORRECTS KIMI'S PARTIAL RUN — and therefore corrects §7(b)

The killed run was re-run to completion (`scratch/review_kimi_policycap_2026_08_15_FULL.md`,
clean exit). It **walks back its own partial-run objection**, the one I had just
recorded above as "decisive" and "sufficient on its own to decline".

**`MAX_SLOT_USES` is not a mutable governance parameter.** VERIFIED by me:

```
contracts/smart-wallet/src/PQSmartWallet.sol:71
    uint256 public constant MAX_SLOT_USES = PqsignerProto.MAX_SLOT_USES;
```

a compile-time `constant` with **no setter** — consistent with invariant #7 ("no
`reset*` / `increaseMax*` path"), and Rust↔Solidity drift-gated. Changing it means
**redeploy plus firmware update**, not a runtime governance action.

**What survives, in weaker form:** any imported cap still rests on the on-chain
check and the firmware gate (`PQSmartWallet.sol:475-481`,
`aa/src/offchain_gate.rs:151,166`), both **outside EasyCrypt's TCB**. So the
theorem would still depend on deployment configuration — a real cost, but an
ordinary one, not the disqualifier I wrote.

**The verdict is unchanged and does not rest on this.** "Do not import" stands on
three independent legs, two of which I verified myself:

1. the birthday model was never derived (GPT; the game file says so itself);
2. `T_COLL_RES_ENUM` is **not in the certified statement** at all (verified: absent
   from `cdrafts-split/` and `base-c10-split/`; the capstone RHS carries four other
   terms);
3. the reduction is eager, so `nrts = c` regardless of `q_s` (verified on the live
   closure member `XmssmtCC_All.ec:752`).

**The lesson is about my own handling, not Kimi's.** I took a claim from a run I
knew had been *killed mid-delivery*, labelled it "decisive", and committed it
within minutes. A partial review is a draft. The full run existed only because the
owner asked for it — otherwise the overstatement would have gone to the public
README as the headline reason.
