# RESULT — encoder bridge: B2's mathematical core is DISCHARGED at C10

`EncoderBridge.ec`, compiled as an explicit target. **0 admits. 1 axiom**
(`gt1_wd : 1 < wd`, radix nondegeneracy — necessary, not incidental).

## What is proven

| lemma | content |
|---|---|
| `int2digK` | `dig2int (int2dig l n) = n` for `0 <= n < wd^l` — the left inverse |
| `int2dig_inj` | the base-`wd` digit map is INJECTIVE on `[0, wd^l)` |
| `enc_inj_from_budget` | injectivity follows from the BIT BUDGET `2^nb <= wd^l` alone |
| `c10_pow` | `8^43 = 2^129` |
| `c10_budget` | `2^128 <= 8^43` |
| `c10_enc_inj` | **at C10 (`wd=8`, 43 digits, 128-bit digests) the digit map IS injective** |

So `B2` — *digests differ but codewords agree* — **is empty at C10 geometry**,
and the single uncharged event left by `Extraction.ec` collapses into `B1`, the
S-TCR(+C) target collision that the existing machinery can charge.

## The margin is ONE BIT, and it is load-bearing

C10 digests are `8*16 = 128` bits; the codeword space is `43*3 = 129` bits.
Injectivity needs `128 <= 129`. **It holds with exactly one bit to spare.**

This is not rhetoric — it is machine-checked by negative control: changing the
digit count `43 -> 42` (budget `2^126 < 2^128`) makes the file **FAIL to
compile** (`BUDGET_NEG_RC=1`). A second control injecting `lemma : false` also
fails (`NEGCTL_RC=1`), and restoring gives `rc=0`. So the proofs are genuinely
checked and the budget genuinely does the work.

Note this is INDEPENDENT of the constant-sum constraint: injectivity comes from
the bit budget, not from `sum = 205`. The constant-sum layer (`2^114.09`) is what
makes the ANTICHAIN half of MM45's `two_encodings` unsatisfiable; it has nothing
to do with the INJECTIVITY half, which the budget settles.

## What is NOT done — two honest gaps

**1. Plumbing to the port's abstract ops.** This discharges B2's MATHEMATICAL
core. It is not yet wired into `Extraction.ec`'s `B2_is_empty`, which is stated
over the port's ABSTRACT `ThC` / `encode_msgWOTS_C` (`WOTS_C_Real.ec:175,220`).
Wiring needs those instantiated at the concrete digit map — and that is blocked
INSIDE the MM45 namespace by `val_log2w : log2_w = 2 \/ 4 \/ 8`
(`shadow/WOTS_TW_ES.ec:31`), which rejects C10's `log2_w = 3`. That is the F1
blocker, still untouched. Hence this file is parametric, exactly as `IncEnc.ec`
is for Def 9.

**2. A model-vs-firmware faithfulness gap, recorded not hidden.** The port models
`ThC` as producing a `dgstblock` = **128 bits**, and on 128 bits the map is
injective. The FIRMWARE computes `wots_digest = SHA-256(...)` = **256 bits** and
extracts digits from the **low 129** (`sphincs-c10/src/wots.rs:16-47`,
`hash.rs:350-365`). At the firmware level two digests differing only in the
unused high 127 bits DO share a codeword, so B2 is **not** empty there.

That gap is harmless for security — what is signed is the codeword, so the
collision probability is `2^-129` either way — but it means the bridge proved
here is a statement about the MODEL, and a faithfulness lemma
(`ThC` faithfully abstracts `wots_digest` modulo the unused bits) is still owed.
Do not report this bridge as "the deployed encoder is injective". It is not; the
deployed encoder is injective ON THE BITS THAT ARE USED, which is what matters
and what the model captures.

## Position in the five-step route

Step 4 (bridge the deployed encoder) is now **mathematically discharged, plumbing
outstanding**. Steps 1-3 (faithful event, composition/extraction lemma with
attacker-controlled `R`, one-canonical-target-per-address) and step 5 (replace
the admit, lift `val_log2w`/checksum geometry) remain.

**C10 is still not proven at deployed parameters.** `Pr[G /\ COLL]` is still
uncharged; what changed is that its residual cause B2 is now known to be empty in
the model, so the charge has a single target instead of two.

---

# UPDATE 2026-07-27 — the "ONE BIT to spare" framing above is WRONG

Kept verbatim above; corrected here. Found by GPT-5.6 in adversarial review.

**The defect.** `c10_enc_inj` quantifies over `[0, 2^128)`. The deployed encoder
consumes **129 bits, not 128**: `sphincs-c10/src/wots.rs:35-46` extracts
`digit[i] = (digest >> 3i) & 7` for `i in 0..42`, i.e. bits 0..128. Digit 42 is
bits 126,127,128. So the lemma above, while true, **does not cover the range the
deployment actually uses**, and the margin narrative attached to it was wrong in
both directions:

* On the full deployed range `[0, 2^129)` the budget is **exactly tight**
  (`8^43 = 2^129`) — there is no spare bit at all, not one.
* The 129th bit is **free in general**. It is pinned only on the **constant-sum
  surface**, because flipping it moves digit 42 by 4 and so moves the digit sum
  by 4, which `sum = 205` forbids.

**The repair** is in `Proj129.ec` (0 admits, same single inherited axiom
`gt1_wd`), with `EncoderBridge.c10_enc_inj` now carrying a SUPERSEDED banner at
the defect site:

* `c10_enc_inj_129` — injectivity on the full `[0, 2^129)`, exactly tight.
* `c10_low128_determines` / `c10_low128_faithful` — on the sum-205 surface the
  low 128 bits determine the value, hence the codeword. This is what makes the
  port's **128-bit** `dgstblock` an honest index for a **129-bit** deployed
  projection, and it is the arithmetic half of the faithfulness obligation that
  "gap 2" above records.
* `negctl_129th_bit_is_NOT_free` — mechanized proof that without `sum = 205` the
  low-128 projection does **not** determine the codeword (`0` and `2^128` are a
  concrete witness pair), so the result above is not a repackaging.
* `c10_target_sum_reachable` — the sum-205 surface is nonempty, so none of this
  is vacuous.

**What did NOT change.** "Gap 2" (model-vs-firmware faithfulness) is narrowed,
not closed: the identification of the model's abstract `ThC` output with the low
128 bits of deployed `wots_digest` is still unwired and still owed. And the
bridge remains a **standalone leaf** — `EncoderBridge` and `Proj129` are absent
from `closure-c10.txt`, so no PQ1 chain file consumes either. **C10 remains
unproven at deployed parameters.**
