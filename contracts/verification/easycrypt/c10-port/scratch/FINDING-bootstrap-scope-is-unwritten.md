# FINDING — the certified statement is ROLE-AGNOSTIC, and nothing anywhere says which key its numbers are for

> **:white_check_mark: RESOLVED 2026-08-19 — the facts bounding this silence are
> now GATED.** `experiments/ptgts-pin/PTgtsPin.ec` was promoted (by *moving*) to
> `cdrafts-split/C10DeployedScope.ec`, closure 33 -> 34, six statement pins,
> gate GREEN with `ledger` unchanged. §(c) below — "the scope restriction is
> written down NOWHERE" — was true when written and is **no longer current**.
> What has NOT changed: the capstone still has no query parameter, so this
> remains a scope/documentation matter and §(d)'s owner decision is still open.

2026-08-18. The open question I had flagged before the review round — *does the
overall EUF-CMA statement cover bootstrap-signed Type-1 authorisations?* — put to
GPT-5.6. **Every load-bearing claim below re-verified by me at source.**

---

## THE ANSWER: YES IT COVERS THEM, AND THAT IS EXACTLY THE PROBLEM

### (a) The model has no roles. VERIFIED.

```
cdrafts-split/FxChain.ec:255
  module EUFCMA_C10 (F : Adv_EUFCMA_C) =
    DSSC.Stateless.EUF_CMA(SPHINCS_PLUS_C10, F, DSSC.Stateless.O_CMA_Default).
```

The textbook **single-key stateless EUF-CMA game**. One keypair, one adversary, one
signing oracle. There is no chain identifier, no owner index, no wallet, no
bootstrap/slot distinction, and no per-key counter anywhere in it.

**Consequence, and it is the opposite of what I feared:** the theorem is *not*
slot-only. It applies verbatim to the bootstrap key, because the game does not care
what the application does with the keypair. An adversary that collects `C · 2^16`
Type-1 signatures across `C` chains is simply *an adversary in the same game*.
**Nothing becomes unsound.**

### And `c` / `p_tgts` are NOT the signature count. VERIFIED — this was my error.

```
cdrafts-split/WOTS_C_Real.ec:41
  op c : int = bigi predT (fun (d' : int) => nr_nodes_ht d' 0) 0 d.
```

`c` is the **structural number of WOTS-TW instances in the hypertree** — fixed by
geometry (H=18, d=2), which is why it pins to `262656` unconditionally. `c <= p_tgts`
is a **reduction-side target-cap**, not a statement that a wallet key may sign at
most `c` messages. I had been treating it as query-related for weeks. It never was.

### (b) What degrades is the NUMBER, not the theorem

The four carried terms stay what they are: probabilities of concrete reduction games.
What breaks under cross-chain bootstrap reuse is **substituting `q = 2^16`** when
quoting a figure. The generic multi-target contribution is
`(q + q²)·2⁻¹²⁸`, so at `q = C·2^16` the floor is `96 − 2·log₂ C` bits —
below 96 **as soon as `C > 1`**. Verified in the project's own Lean, which already
tabulates it (`Quantitative.lean:193-210`), and which explicitly notes
*"there is no on-chain cap on the number of chains"*.

### (c) THE FINDING: the scope restriction is written down NOWHERE in the EasyCrypt

I checked this as an **absence** claim, which is my documented failure mode, so I
searched the *mechanism* rather than a name: every one of the 33 closure members,
for `bootstrap|chain_id|chainid|slot_index|65536|MAX_SLOT|per-chain|wallet`.

**Exactly two hits. Both are comments. Neither is a statement.**

```
cdrafts-split/WOTS_C_Real.ec:238   a pointer to SPHINCsC10Asm.sol
cdrafts-split/FORS_C10.ec:87       "at C10's 2^16 per-chain cap the reduction's
                                    game has 2^27 registered targets"
```

The second one is worth its own line: **the single place in the certified closure
where the deployment cap appears in a quantitative argument, it uses the PER-CHAIN
`2^16`** — the exact number that does not apply to the bootstrap key. It is prose
justifying why a black-box route was rejected (~102 bits lost), so it moves no
theorem. But it is a certified file reasoning from a cap that is per-chain.

The only honest cross-chain treatment anywhere is on the **Lean** side
(`Quantitative.lean:172-185`, P14), and that is an application-side correction, not a
scope restriction on the EasyCrypt theorem. It was itself corrected by external
review on 2026-07-26 after previously calling cross-chain aggregation non-binding.

### (d) This is a DOCUMENTATION question, not a proof task

A second EUF-CMA theorem for "the bootstrap key" would be the same theorem. The
primitive does not change because the application assigns a role. What is missing is
an explicit **instantiation contract**:

* a slot key instantiates `q` with its own combined per-key count (capped, chain-bound);
* the bootstrap key instantiates `q` with the **aggregate across every chain that
  shares it** — and no cap on the number of chains is enforced anywhere;
* any quoted bit-figure names which of the two it used.

Writing that down is cheap. Proving it — a machine-checked bridge from deployed
reachable states to global per-key counts — is a real project, and the Lean file
already records that even the *single-chain* `Reachable -> q <= C` theorem is not
assembled (`Quantitative.lean:87-95`; reachability currently rests on a Foundry
invariant fuzz test).

## WHY THIS MATTERS MORE THAN THE PROOF WORK AROUND IT

The deployed system invites a concrete 96-bit reading from a per-chain cap, while the
repository's own Lean proves the bootstrap key's generic floor drops below 96 for
**every** `C > 1`. Realistic bootstrap usage is tens of signatures — slot rotations
only — so practical exposure is far below any of this. But *practical exposure* is
not what a security claim states, and the claim currently has no key named in it.

**Owner decision required, and it is a scope decision, not a proof one:** state the
instantiation contract above, or restrict the quoted figures to slot keys explicitly.
