# FINDING — both of my published claims about this leg were wrong, in opposite directions

2026-08-14. GPT-5.6 and Kimi K3, asked independently with C10's parameters frozen.
They **converge** on refuting my premise and **diverge** on the number, and the
divergence is where the information was. Everything below verified at source.

---

## CORRECTION 1 — "the deployment never lets the adversary choose the WOTS message" is FALSE

This is the load-bearing sentence of the "not an attack" classification. It is in
the public README, in `BadEncCountermodel.ec`'s header, in several commits — and
it is **inherited from `FINDING-def11-is-unsound-at-c10.md`**, which reasoned that
`compute_fors_pk` takes no message argument.

**Both models refuted it independently, and I verified it.**

`compute_fors_pk` takes no *message* argument, but **its `roots` argument is
attacker-supplied at verification.** In `sphincs-c10/src/hypertree.rs`:

```
fors_secrets ← read from the signature        (attacker-supplied)
auth_paths   ← read from the signature        (attacker-supplied)
fors_roots   ← reconstruct_fors_root(...)
fors_pk      ← compute_fors_pk(seed, ht_idx, fors_roots)
current_node ← fors_pk                        ← THE WOTS MESSAGE
wots_pk      ← pk_from_sig(..., &current_node, &wots_sigma, count)
```

Nothing validates the secrets before `fors_pk` is formed, and `count` is likewise
read from the signature. Kimi: *"at verification the forger controls R, all 13
FORS secrets, all auth paths, and `count` — the layer-0 WOTS message is a
**grindable 128-bit value at 1–2 hashes per candidate**."*

The honest-signer statement is true (`fors.rs:265-268`, `hypertree.rs:262-291`).
**It does not transfer to the verifier**, and the forgery game is about the
verifier. So *route (b) as "messages are key-determined" is not merely unproven —
it is provably false at source*, which is worse than the R1 it would have replaced.

## CORRECTION 2 — "cannot be usefully bounded, ~2^-72" is ALSO WRONG

Having just been told my premise was too optimistic, the reflex is to assume the
truth is worse. It is not. **My 2^-72 conclusion was too pessimistic, and for a
mundane reason: I conflated the ORACLE'S grinding cost with the ADVERSARY'S work.**

`2^71.95 = 2^57.05 × 2^14.906`. That second factor is the cost of landing one
sample on the constant-sum surface — and in the game **the oracle pays it**
(`ctr <- grindC ps ad m`). So 2^71.95 is *2^57 oracle queries*, not 2^72 of
adversary work.

**And a free offline birthday does not win.** VERIFIED: the win condition reads
`(ad, m, ctr, dg, e) <@ O.get(i)` with `0 <= i < nrts` — **one side of the
collision must be a RECORDED entry.** An adversary can generate 2^57 on-surface
samples offline, but colliding two of *its own* samples wins nothing. It must hit
a recorded one, which is a **target search**, not a birthday.

Consequences, with `n_ad` = signatures observed at the targeted address:

| side | cost |
|---|---|
| query side | advantage `q_s² · 2^-114.09`; at the deployed cap `q_s = 2^16` → **2^-82** |
| offline side | `2^114.09 / n_ad`; multi-target amplification **dies on address-keying** |

Honest signings cannot be steered onto one address — `R` is derived from
`sk_seed` (`fors.rs:94-131`, `grind_r`) — so `n_ad` is small. Even the
adversary-favourable `n_ad = 2^16` gives **2^98**; realistic load gives ~2^112.

**So the leg's honest ceiling is ~2^98–2^114 work, or 2^-82 advantage at the
deployed query cap — at or ABOVE the 96-bit work floor, not 24 bits below it.**

My published *"there is no bound to find; do not spend further effort"* was drawn
from pricing an attack the query budget forbids. It is retracted.

## WHAT THE CORRECT REASON IS

The leg is fine — but **not for the reason I gave**. I said the constraint was on
the *message side* (key-determined). It is on the **target side**: the collision
must involve an honestly-signed, address-bound entry, and those are capped and
scattered. Kimi puts it exactly right: *"your conclusion survives, but for the
opposite reason."*

## WHAT MUST NOW BE PINNED — and it is currently abstract

The bound depends entirely on instantiating `p_tgts` at the deployed usage cap.
**VERIFIED:** `cdrafts-split/WOTS_C_Real.ec:340` —
`const p_tgts : { int | 0 <= p_tgts } as ge0_ptgts.` It is **unpinned**, exactly
like `target_sum`. Quoting 2^-82 without pinning it would be unfounded.

The achievable theorem shape, parameters frozen:

```
for q_s <= 2^16 signing queries and q_h hash queries,
  Adv_T-COLL-RES-ENUM  <=  (q_s^2 + q_h * n_ad_max) * 2^-114.09
```

with the `2^-114.09` already machine-checked (`count/C10SurfaceKernel.ec`).

## THE DIVERGENCE, AND WHY IT MATTERED

* **GPT** — the leg is stuck at 2^72 unless a recursive **node-binding**
  decomposition is proved through FORS and both hypertree layers, removing the
  free-message WOTS term entirely. Structurally right, and expensive.
* **Kimi** — 2^72 was never the right number; price the term against the deployed
  query cap and it clears the floor without new proof structure.

Both refuted my premise. Only Kimi caught that my *conclusion* was also wrong.
Had I asked one model, I would have published a correction that was still wrong.

## HONEST LIMITS ON THIS FINDING

* The `q_s² · 2^-114.09` and `2^114.09 / n_ad` figures are **generic-model
  arithmetic**, the same epistemic class as the ITSR margin table — not theorems.
  Kimi says so itself. Only the count is mechanised.
* `n_ad_max` is not established anywhere; "honest signings scatter" is an argument
  about `grind_r`, not a proved bound.
* The `ThC`-width question (128 vs 129) sits underneath this term and shifts the
  constant.
* **This is not a clean bill of health.** It is a statement that the leg's ceiling
  is set by the target budget, and that the budget has never been pinned.
