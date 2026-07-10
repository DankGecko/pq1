---
surface: fv
run_date: 2026-07-10
reviewer: GPT-5 Codex, single-reviewer executing adversarial pass
scope: C10 EasyCrypt EUF-CMA work at c10-eufcma-port 0eae219, with model-to-production checks against PQSigner_OS 5a8ea6e and the FORS quantitative guardrail
status: resolved-2026-07-10b
catalogue: ../REVIEW_PROVENANCE.md
---

# Adversarial-review findings — C10 EasyCrypt EUF-CMA — 2026-07-10

## Summary

Five confirmed assurance defects: **2 HIGH, 2 MED, 1 LOW**. No deployed forgery or
fund-loss exploit is established. The findings concern what the current C10 formal model and
quantitative gate can support:

- the FORS index-extractor axioms still admit a one-tuple model disguised as a length-`k` list;
- the claimed load-bearing `p_nu` axiom can be removed without affecting any model/game result;
- the advertised 130.6-bit ITSR figure omits its own `(q_h + 1)` union-bound factor;
- the numerical mixture silently discards a positive upper tail; and
- the memoized EasyCrypt oracle suppresses the fresh-`opt_rand` behavior used by production.

This was an **executing** pass. It ran two EasyCrypt mutation builds with r2026.02, the new
`DarkSide.ec` theorem, the FORS margin gate and its self-test, and the Rust `opt_rand` regression
test. The out-of-tree C10 repository was read-only; all EasyCrypt mutations lived under `/tmp`.

## Findings

### F1 — The index-extractor axioms permit `k` copies of one FORS tuple

- **Status:** ✅ RESOLVED 2026-07-10b
- **Mode / severity:** V1 (vacuous coverage) / V9 (model ≠ scheme) · **MED**
- **Location:** `/home/nicola/repos/c10-eufcma-port/drafts/FORS_C10.ec:145-172`, especially
  `size_g`, `neqisvs_g`, and `predC_fors`
- **What:** the four axioms added to exclude `g y = []` do not require `g y` to be `uniq`.
  `neqisvs_g` only distinguishes values `x <> x'`; a list containing `k` copies of the same
  tuple has only one value under membership, so the premise `x <> x'` is never satisfiable.
  Such a model has length `k` but represents only one tree. Coverage and the forced-zero
  predicate can therefore collapse to one leaf while every advertised structural axiom holds.
- **PoC (falsifiable):** append the following mutation before `end FORSC10` and compile the
  full file. All four lemmas checked and EasyCrypt exited 0:

  ```easycrypt
  op dup_g (_ : out_t) : (int * int * int) list = nseq k (0, 0, 0).

  lemma dup_size_g (y : out_t) : size (dup_g y) = k.
  proof. by rewrite /dup_g size_nseq; smt(ge1_k). qed.

  lemma dup_eqiks_g (x x' : int * int * int) (y : out_t) :
    x \in dup_g y => x' \in dup_g y => x.`1 = x'.`1.
  proof. by rewrite /dup_g !mem_nseq; smt(ge1_k). qed.

  lemma dup_neqisvs_g (x x' : int * int * int) (y : out_t) :
    x \in dup_g y => x' \in dup_g y => x <> x' => x.`2 <> x'.`2.
  proof. by rewrite /dup_g !mem_nseq; smt(ge1_k). qed.

  lemma dup_rng_g (y : out_t) (x : int * int * int) :
    x \in dup_g y => 0 <= x.`3 < t.
  proof.
    have ht : 0 < t by rewrite /t StdOrder.IntOrder.expr_gt0.
    rewrite /dup_g mem_nseq; smt(ge1_k).
  qed.
  ```

  Command and result:

  ```text
  bash ec-r2026.sh compile -max-provers 1 -no-eco /tmp/FORS_C10_dup_poc.ec
  EXIT 0
  ```

- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** require and consume `uniq (g y)`, or define `g` concretely as a `mkseq`
  indexed by tree number. Also add `0 <= tree_idx < k` and the missing instance-index range.
  Mutation-gate the exact `nseq k (0,0,0)` model. `hC_nonempty` is not an adequate replacement:
  it proves only one represented tuple, not `k` distinct trees.
- **Resolution:** FIXED — see PQSigner `HEAD` / c10-eufcma-port `25b7d91`. Independently reproduced by the maintainer before fixing; each fix carries a negative control that now fires.

### F2 — `good_pos` is decorative and oracle losslessness is unproved

- **Status:** ✅ RESOLVED 2026-07-10b
- **Mode / severity:** V4 (unused axiom) / V5 (advertised-but-undischarged premise) · **MED**
- **Location:** `/home/nicola/repos/c10-eufcma-port/drafts/FORS_C10.ec:177-182,212-224,296-315`
- **What:** the header and `GATE 0a` say `good_pos` is load-bearing and makes the rejection
  sampler well-defined. In the live file it is consumed only by the standalone `good_exists`
  lemma. Neither `query_targets_good` nor `ITSRC10_le_noC_SAME_ORACLE` uses it, and there is no
  `islossless O_ITSRC10_Default.query` theorem. EasyCrypt probabilities may therefore be taken
  over a subdistribution without the file ever proving that the rejection loop terminates.
- **PoC (falsifiable):** copy `FORS_C10.ec`, delete the `good_pos` axiom and delete only
  `good_exists`, then compile the complete mutated file:

  ```text
  bash ec-r2026.sh compile -max-provers 1 -no-eco /tmp/FORS_C10_goodpos_mutation.ec
  EXIT 0
  ```

  Every other model/game lemma remains green. This is the repository playbook's exact V4
  mutation: remove the advertised premise and observe that no security-facing result reacts.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** prove `islossless O_ITSRC10_Default.query` from `dmkey_ll` and `good_pos`
  (or use a lossless conditioned distribution with the positive-mass obligation), and make the
  future game hop require that result. Add a mutation requiring removal of `good_pos` to fail a
  headline build, rather than merely deleting a witness lemma with it.
- **Resolution:** FIXED — see PQSigner `HEAD` / c10-eufcma-port `25b7d91`. Independently reproduced by the maintainer before fixing; each fix carries a negative control that now fires.

### F3 — The 130.6-bit ITSR guardrail omits the documented `(q_h + 1)` union bound

- **Status:** ✅ RESOLVED 2026-07-10b
- **Mode / severity:** G5 (qualitative/quantitative gap) / V9 (formula ≠ executable gate) · **HIGH**
- **Location:** `contracts/verification/scripts/forsc_grinding_margin.py:65-80,168-211`;
  `contracts/verification/docs/AXIOM_STATUS.json` A5-ITSR evidence
- **What:** the script states the bound
  `(q_h + 1) * (1/t_last) * E[DS_G^(k-1)]`, but `itsr_report` computes
  `real_bits = -log2(b_forsc(qs))`. It has no `q_h` parameter and never applies the multiplier.
  Guardrail 4 therefore compares a **per-candidate** value to the 96-bit project floor while
  printing it as the “ITSR term.” The C10 model itself correctly admits that no concrete
  bit-level bound is statable without `q_h`; the PQ-side gate contradicts that disclosure.
- **PoC (falsifiable):** `make -C contracts/verification verify-forsc-margin` prints
  `FORS+C ... 130.6 bits` and passes. Inspection shows the only executable assignment is:

  ```python
  bd, bp = b_forsc(qs), b_plain(qs)
  real_bits, plain_bits = -math.log2(bd), -math.log2(bp)
  ```

  Applying the script's own formula gives:

  ```text
  per-candidate value                         130.568250 bits
  largest q_h retaining a 96-bit floor       25,472,999,260  (~2^34.57)
  q_h = 2^40                                 90.568250 bits
  q_h = 2^64                                 66.568250 bits
  ```

  Thus the green gate cannot establish 96 bits unless a defensible `q_h < 2^34.57` bound is
  part of the claim and enforcement.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** introduce an explicit, source-owned `Q_H_CAP`; compute
  `win_bound = min(1, (Q_H_CAP + 1) * per_candidate_bound)` for both FORS and FORS+C; enforce
  the floor on `-log2(win_bound)`; and add a negative control that raises `Q_H_CAP` until the
  gate fails. If no operational/PPT query cap is defensible, remove the 130.6-bit ITSR/floor
  claim and label the number per-candidate only.
- **Resolution:** FIXED — see PQSigner `HEAD` / c10-eufcma-port `25b7d91`. Independently reproduced by the maintainer before fixing; each fix carries a negative control that now fires.

### F4 — `_mixture` is a lower approximation, not a cryptographic upper bound

- **Status:** ✅ RESOLVED 2026-07-10b
- **Mode / severity:** G5 (quantitative-bound direction) · **LOW**
- **Location:** `contracts/verification/scripts/forsc_grinding_margin.py:139-153`
- **What:** `_mixture` sums only through
  `mean + 10*sqrt(mean+1) + 40` and silently drops every larger binomial load. Every omitted
  term is non-negative, so the returned number is a lower approximation to the expectation.
  Turning it into `-log2` slightly **overstates** security. The missing tail is tiny at the
  current parameters, so this does not by itself overturn the 96-bit floor; it is nevertheless
  the wrong direction for code presented as a cryptographic bound.
- **PoC (falsifiable):** at `qs=2^16`, the loop stops at `g=51` although the binomial support
  continues to 65,536. The first omitted FORS+C summand (`g=52`) is positive, approximately
  `2^-404.78`; at the `2^22` self-test the first omitted summand is approximately `2^-206.61`.
  Therefore the exact expectation is strictly greater than `_mixture` in both passing and
  failing gate configurations.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** sum the complete support with stable log-sum-exp, or add a mathematically
  justified upper bound for the omitted tail before taking `-log2`. Add a self-test that checks
  the implementation is an upper bound, not just numerically plausible.
- **Resolution:** FIXED — see PQSigner `HEAD` / c10-eufcma-port `25b7d91`. Independently reproduced by the maintainer before fixing; each fix carries a negative control that now fires.

### F5 — The “C10-faithful” model memoizes `R`, but production randomizes it per signing call

- **Status:** ✅ RESOLVED 2026-07-10b
- **Mode / severity:** V9 (model ≠ production artifact) / V8 (restricted oracle) · **HIGH**
- **Location:** `/home/nicola/repos/c10-eufcma-port/drafts/FORS_C10.ec:43-67,198-225`;
  `secure/src/crypto.rs:101-142`; `sphincs-c10/src/fors.rs:86-130`
- **What:** the EasyCrypt oracle caches one `mkey`/`R` per message and returns it on every
  repeated query. Production does the opposite across signing calls: `secure/src/crypto.rs`
  draws a fresh strong `opt_rand` every time, and `grind_r` includes it in the `R` derivation.
  Repeated queries for the same message therefore expose new randomized signatures and FORS
  leaves in production, while the model exposes the same target once. EUF-CMA freshness forbids
  forging the repeated message, but repeated-message signing queries may still accumulate
  information used to forge a different message; suppressing them is an adversary restriction.
  No reduction in the reviewed tree transports security of the memoized oracle to the randomized
  production oracle.
- **PoC (falsifiable):** the model's second `query(m)` takes the cache-hit path and returns
  `oget mmap.[m]` without sampling. Production's existing regression demonstrates the opposite:

  ```text
  cargo test -p sphincs-c10 positive_opt_rand_changes_sig_bytes -- --exact
  test positive_opt_rand_changes_sig_bytes ... ok
  ```

  That test signs the same `MSG` with two `opt_rand` values and asserts the signatures differ.
  The production wrapper documents and implements a fresh `rng_strong::fill(&mut opt_rand_buf)`
  per signing call.
- **Disposition:** CONFIRMED_REAL
- **Proposed fix:** model a fresh `opt_rand`/randomized `R` per signing query while tracking EUF
  freshness on the message alone, then prove the C10 game hop with total-query accounting.
  Alternatively, prove a reduction from the randomized production oracle to the deterministic
  memoized oracle; do not assume it. Add a repeated-message, distinct-`R` correspondence test
  between the scheme model and Rust behavior.
- **Resolution:** FIXED — see PQSigner `HEAD` / c10-eufcma-port `25b7d91`. Independently reproduced by the maintainer before fixing; each fix carries a negative control that now fires.

## Suspicions (unverified — no PoC)

- The WOTS+C stack still leaves `predC`, `encode_msgWOTS_C`, `emb_in`, and the counter type
  abstract. This is disclosed and the current WOTS theorem carries encoding compatibility as a
  premise, so it is not filed as a defect here. A future “C10 instantiated” claim must define
  these from the Rust byte layout/parameters and prove the premise, not inherit the abstract
  form unchanged.
- The direct DarkSide development still needs its disclosed k-fold independence, binomial-mixture,
  query-union, and game-connection steps. No attempt was made to predict whether those proofs close.

## Honest residual

1. **What I tried to break and COULDN'T**
   - `DarkSide.ec` at commit `0eae219` compiled from a `/tmp` copy with EasyCrypt r2026.02,
     exit 0. Its proved claim is honestly limited to the fixed-load coverage identity and
     `DS^(k-1)/t <= DS^k`; the missing game/mixture/union steps are stated as open.
   - The WOTS+C files `WOTS_C_Scheme.ec`, `WOTS_C_Real.ec`, and
     `WOTS_C_EmbDischarge.ec` were traced against their theorem statements. I found no
     falsifiable new hole in the two-term WOTS reduction during this pass. The target-count and
     encoding-compatibility premises are visible in the theorem rather than hidden.
   - A comment-stripped sweep found exactly three live `admit.` tactics, in
     `FORS_C_TreePort.ec`, `FORS_C_TreePort_skel.ec`, and `WOTS_C_Interactive.ec`; none is
     required by the current capstone chain. The live C10 FORS model itself has no `admit`.
   - PQSigner's owner status correctly keeps the FORS+C/A5 literature gap open; I did not find a
     current owner-document claim that the whole C10 EUF-CMA composition is complete.
2. **What I did NOT look at**
   - I did not re-run every one of the 21 EasyCrypt files as a target, MM45's full reference
     tree, or the complete WOTS reduction chain. The WOTS “couldn't break” result is source-read,
     not a fresh full-chain execution.
   - I did not audit the Lean on-chain proof, bytecode bridge, Kani, protocol models, CT/SCA,
     secure elements, trusted UI, or USB surfaces in this round.
   - No independent model or cross-vote was used. The C10 repository was concurrently active;
     this report pins clean commit `0eae219` (the FORS findings apply to its unchanged
     `FORS_C10.ec` from `f41caeb`).
3. **Provenance**
   - Executed: EasyCrypt r2026.02 targeted builds for both mutation PoCs and `DarkSide.ec`;
     `make -C contracts/verification verify-forsc-margin`; the margin self-test; independent
     numerical evaluation of the omitted `q_h` factor/tail; and the Rust `opt_rand` test.
   - Source-read: the remaining WOTS/capstone/model correspondence. No files were written in
     `/home/nicola/repos/c10-eufcma-port`; only this findings report and its PQ-side provenance
     row were filed.


---

## Resolution (2026-07-10b, by the maintainer)

All five findings were **independently reproduced** before being fixed. No false positives.

| # | Sev | Fix | Negative control |
|---|---|---|---|
| F5 | HIGH | oracle no longer memoizes; fresh `dcond dmkey (good m)` draw per query. Production randomizes `opt_rand` per signing call (`secure/src/crypto.rs:130-142`). The memoization was a **regression I introduced on 2026-07-10** in response to an earlier review, without checking the call site. | — (model change; the memoizing form is documented as wrong) |
| F3 | HIGH | `130.6` relabelled a **work factor** (queries needed). Guardrail 4 now asserts a query-work floor, and the report **prints the advantage** `(q_h+1)·B` at q_h ∈ {2^64, 2^96, 2^128} (at 2^128: `Pr[win] ≤ 2^-2.6`). The tie to `Quantitative.lean`'s advantage floor is severed, since no operational cap on offline hashing is defensible. | qs = 2^22 trips the work floor |
| F1 | MED | new `axiom uniq_g`: the k tuples name k **distinct** trees. MM45's own axiom set shares the weakness. | the `g y = nseq k (0,0,0)` clone now **fails to realize** (was EXIT 0) |
| F2 | MED | `good_pos` made load-bearing: `query_ll : islossless query` proved from it via `dcond_ll`. | deleting `good_pos` + `good_exists` now **fails the build** (was EXIT 0) |
| F4 | LOW | `_mixture` adds a rigorous geometric tail bound (ratio ≤ 1/4 beyond `4·μ'`), so it is a genuine **upper** bound. | self-test widens the window and asserts the exact partial sum does not exceed the reported value |

Gates: `make verify-easycrypt` (20/20 compile as targets, pins 8 axioms / 2 orphaned admits),
`make verify-forsc-margin` (5 guardrails, all with negative controls),
`check_ledger_consistency.py` OK.

**Reviewer's F3 framing was right and its proposed `Q_H_CAP` was not adopted:** there is no
defensible operational cap on an offline adversary's hashing, so the honest fix is to relabel the
number and surface the advantage — which is the fallback the report itself offered.
