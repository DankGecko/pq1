# Protocol-Model Query-Body Deep-Dive — Adversarial FV-Soundness Review — 2026-07-02

<!-- EXECUTING round. Scope: the §4 residual of ADVERSARIAL_REVIEW_2026-07-02.md — protocol-model
QUERY BODIES (V2 tautology / anti-vacuity risk across the 17 ProVerif RESULTs + 8 Tamarin lemmas),
the surface that round's header explicitly deferred. proverif + tamarin-prover 1.12.0 RUN on the live
tree. FV soundness only — is a query/model/claim hollow, unenforced, or overstated — NOT a vuln audit.
No fixes applied; this doc is the finding record. Match house style of ADVERSARIAL_REVIEW_2026-07-02.md. -->

## 1. Verdict

**The query bodies are sound; the anti-vacuity *retrofit* and a few model headers overstate.** Every
ProVerif RESULT and Tamarin lemma exercised this round was confirmed **non-vacuous on the current tree** —
injected reachability probes fired every correspondence premise, and no positive result was a tautology.
**No MEDIUM+ finding survived.** The five confirmed items are all LOW/INFO and split into exactly two
shapes, both first named (but not fully swept) by the 2026-07-02 headers PM-2 and PM-3:

- **Anti-vacuity coverage asymmetry (the PM-2 pattern, un-propagated).** The reachability-witness fix that
  landed in `dual_se_unlock.pv` (PM-2) was **never carried to its two sibling handshake models**. Both
  `scp03_handshake.pv` and `optiga_shield_handshake.pv` ship their baseline correspondences and secrecy
  results with **no `query event(...)` witness for the event-bearing baseline legs**. The residual
  "control" each file *does* ship guards only the separate, event-free residual legs (`cardL/hostL`,
  `optigaL/hostL`) over separate secrets — it does **not** attest the baseline legs run. A dead-leg
  regression on the baseline would flip all baseline verdicts vacuously-green while the count-only
  `verify-protocol-models` gate stays green. For `optiga_shield_handshake.pv` this was demonstrated with a
  live mutation (see F1).

- **Header claim-vs-proof gaps (the PM-3 pattern).** Three model docstrings advertise a stronger property
  than the shipped queries syntactically establish: `scp03_handshake.pv` calls its non-injective
  correspondences "injective-agreement"; `optiga_shield_handshake.pv` lists "session-key secrecy" among
  three proven questions but ships no query over the session key `s`; `pin_lockstep.spthy` is named
  `DualSE_PinLockstep` and its README says the counters "move in LOCKSTEP" but no bump rule is modeled.

**Honest bottom line:** nothing here is unsound *today* — every positive result was empirically witnessed
reachable. The defect is durability and labeling: two of the four handshake models lack the tripwire that
would catch a future dead-leg regression, and three headers describe a property the queries don't ask.

## 2. Confirmed findings (survived independent-refuter cross-vote)

No MEDIUM+ finding survived; `confirmed[]` is empty by the medium-floor rule. All five are LOW/INFO.

| ID | Sev | Class | Model | What overstates |
|----|-----|-------|-------|-----------------|
| **F1 · pv-se-1** | LOW | missing anti-vacuity witness (V2/V1) | `optiga_shield_handshake.pv` | No reachability witness for any baseline event (HostAccepted/OptAccepted/OptSent/HostSent) or the halfO release. **Mutation-proven:** breaking the baseline optiga leg leaves the gate's `true=3/false=1` unchanged (GREEN) while both mutual-auth correspondences go vacuously-true and half_O is secret-for-nothing. |
| **F2 · pv-scp03-1** | LOW | missing anti-vacuity witness (V2/V1) | `scp03_handshake.pv` + `scp03_replay.pv` | Baseline `card/host` legs (carrying all four events + `pinB`) ship with zero reachability assertion; the sole control exercises the event-free `cardL/hostL` residual. `scp03_replay.pv`'s `event(Accept)==>event(Send)` likewise has no `Accept` witness. |
| **F3 · pv-se-2** | LOW | claim-vs-proof gap (V11) | `optiga_shield_handshake.pv` | Docstring advertises "session-key secrecy" as one of three proven questions and names `s = prf(pbs,hrnd,ornd)` the session-key, but **no query references `s`** — only the two mutual-auth correspondences and half_O secrecy are asked. Two of three "questions below" are actually queried. |
| **F4 · pv-scp03-2** | INFO | claim-vs-proof gap (V11) | `scp03_handshake.pv` | Header (line 52) calls the result "injective-agreement"; the shipped queries are non-injective `event(A)==>event(B)`. Harmless in the single-session baseline (injective/non-injective coincide) but false labeling the moment the tracked `!`-replication follow-up lands. |
| **F5 · tamarin-1** | INFO | claim-vs-proof gap / scope (V11) | `pin_lockstep.spthy` + README | Theory named `DualSE_PinLockstep` and README says counters "move in LOCKSTEP (every wrong PIN bumps all three)", but the model has **no bump/wrong-PIN rule** — it proves only that reconcile catches an attacker *reset* from an assumed-synced baseline. Bump-induced desync is unrepresentable. Safe-direction (any desync reconciles to Wipe) and partly disclosed at PM-1. |

## 3. Per-finding detail (surviving MEDIUM+)

**None.** No finding cleared the MEDIUM floor. Per-finding claim/defect/PoC/fix for the surviving LOW/INFO
items is recorded below for the fix queue; none blocks and none is a soundness hole on the current tree.

### F1 · pv-se-1 (LOW) — `optiga_shield_handshake.pv` ships no baseline reachability witness

- **Claim.** The file bills itself (lines 4-7) as "the OPTIGA-side companion to `scp03_handshake.pv`", and
  its sibling `dual_se_unlock.pv` was explicitly retrofitted at PM-2 with `query event(ReleasedHalfO/E)`
  (expected `is false`) precisely so a dead honest leg reddens a witness instead of silently passing.
  `optiga_shield_handshake.pv` received no such witness for any baseline event.
- **Defect.** Anti-vacuity coverage asymmetry: the PM-2 fix landed in `dual_se_unlock.pv` but the
  identically-structured sibling was left without witnesses. The residual `attacker(halfOR)` (line 109)
  runs the *separate* event-free `optigaL/hostL` legs over separate secrets `pbsR/halfOR`, so it never
  attests the baseline `optiga/host` legs (lines 54-77) complete. `scripts/check_protocol_models.py` is a
  verdict-**count** tripwire (PROVERIF expects `true=3/false=1`) and cannot tell a genuine proof from a
  vacuous one at the same counts.
- **PoC.** RAN. Temp witnesses confirm the baseline events are reachable today
  (`RESULT not event(HostAccepted(h,c)) is false` / `not event(OptAccepted(h,c)) is false`). Then mutated
  **only** the baseline optiga leg — swap `optcrypto(pbs, hrnd, ornd)` → `optcrypto(pbs, ornd, hrnd)` at
  line 59 so host auth (line 72) can never pass → HostAccepted/OptAccepted unreachable, halfO never output.
  proverif on the mutant still prints the identical 4 lines (`not attacker(halfOB) is true` /
  `HostAccepted==>OptSent is true` / `OptAccepted==>HostSent is true` / `not attacker(halfOR) is false`) —
  3 true / 1 false, gate GREEN — while half_O secrecy is now vacuous and both correspondences are
  vacuously-true.
- **Fix.** Add `query h,c; event(HostAccepted(h,c)).` and `query h,c; event(OptAccepted(h,c)).` (both
  expected `is false`), mirroring the PM-2 pair, and bump the PROVERIF baseline for this file from
  `(true=3,false=1)` to `(3,3)` in `scripts/check_protocol_models.py`.

### F2 · pv-scp03-1 (LOW) — `scp03_handshake.pv` / `scp03_replay.pv` baseline legs unwitnessed

- **Claim.** Both correspondence queries are proven TRUE non-vacuously right now — injected reachability
  probes fire every premise event — but neither model ships a witness, so a future dead-leg regression
  would flip them vacuously-true while the count-only gate stays green.
- **Defect.** `scp03_handshake.pv` has one anti-vacuity control (the residual, lines 139-143) but it
  exercises the event-free `cardL/hostL` legs, NOT the baseline `card/host` legs that carry
  `event(CardSent)/event(HostAccepted)/event(CardAccepted)/event(HostSent)` and output `pinB`. The baseline
  is a **structurally separate process** sharing no events with the residual, so
  `RESULT not attacker(pinR) is false` witnesses nothing about the baseline: a regression that breaks only
  the baseline legs makes `pinB` vacuously-secret AND both correspondences vacuously-true while the residual
  stays false — nothing catches it. `scp03_replay.pv` likewise proves `event(Accept)==>event(Send)` with no
  shipped `Accept` witness.
- **PoC.** RAN. Injected `query h,c; event(HostAccepted(h,c)).` etc. → `RESULT ... is false` (reachable)
  for all four handshake events; `query ctr,cmd; event(Accept(ctr,cmd)).` → `is false` (reachable) for the
  replay model. None of these witness queries exist in the shipped files.
- **Fix.** Add the four handshake reachability queries to `scp03_handshake.pv` and the one `Accept` witness
  to `scp03_replay.pv` (the generalized PM-2 fix), and update the corresponding count baselines.

### F3 · pv-se-2 (LOW) — `optiga_shield_handshake.pv` advertises session-key secrecy it never queries

- **Claim.** The docstring (lines 19-21) says the abstractions are "Faithful for the session-key secrecy,
  mutual authentication, and half_O-confidentiality questions below"; line 33 names `s = prf(pbs,hrnd,ornd)`
  the "session-key"; the assignment inventory lists "4 queries: session-key secrecy + mutual-auth + half_O".
- **Defect.** There is **no session-key secrecy query**. The four queries are `attacker(halfOB)` (half_O
  secrecy), the two mutual-auth correspondences, and `attacker(halfOR)` (the half_O residual/anti-vacuity
  control). No `attacker(s)` or any secrecy query over the derived session key exists. Session-key secrecy
  is advertised as one of three "questions below" but only two are asked; the third is unproven.
- **PoC.** RAN + source-read. `grep -n 'query' optiga_shield_handshake.pv` → only lines 99/100/101/109;
  none reference `s`. proverif output has exactly 4 RESULT lines, none about `s`. The README table
  (README.md lines 153-157) is honest — it lists only the 3 real query families — so the overclaim is
  localized to the model header docstring.
- **Fix.** Either add `query attacker(sB).`-style session-key-secrecy queries (binding `s` to a free
  private name per scenario) or reword the docstring to drop "session-key secrecy" and state only the two
  properties actually queried, matching the honest README.

## 4. Refuted / rediscovery

No finding was refuted by its independent skeptic — all five PoCs held on the live tree. Two scope notes:

- **F4 · pv-scp03-2 (INFO) and F5 · tamarin-1 (INFO)** are retained as LOW-below-floor labeling
  observations, not dropped. **F4** ("injective-agreement" wording over non-injective queries) is harmless
  in the current single-session baseline (no `!` replication, disclosed at PM-3) where injective and
  non-injective coincide, and only bites when the tracked replication follow-up lands. **F5** ("lockstep"
  naming over a reconcile-only model) is safe-direction (any bump-induced desync reconciles to Wipe, no
  fund-drain) and is **a subset/weaker restatement of the already-filed PM-1** (`protocol PM-1`, MED,
  model≠deployed reconcile) — it adds only the observation that the *bump* half of "lockstep" is entirely
  unmodeled, whereas PM-1 covered the reconcile-direction model≠code gap. It is not independent severity;
  fold the naming note into the PM-1 remediation.

- **Rediscovery, not novelty:** F1/F2 are the **PM-2 anti-vacuity-witness pattern** (originally found on
  `dual_se_unlock.pv`) applied to the two handshake siblings the PM-2 fix skipped; F3/F4 sit in the same
  neighborhood as **PM-3** (SCP03/shield handshakes are single-session, so cross-session claims say less).
  This round's contribution is confirming the query bodies themselves are non-vacuous *today* (the V2
  tautology risk the 2026-07-02 header flagged did **not** materialize) and demonstrating with a live
  mutation that F1's gap is a real dead-leg blind spot, not merely a missing nicety.

## 5. What was attacked and HELD

- **No positive result is a tautology.** Every ProVerif correspondence premise across the walked models
  fired under an injected reachability probe (`... is false` = reachable); no `event(A)==>event(B)` was
  vacuously-true on the current tree.
- **Every Tamarin lemma in `pin_lockstep.spthy` is genuinely non-vacuous** — `honest_boot_possible`(6),
  `fresh_synced_means_no_reset`(9), `zero_synced_means_all_reset`(5), `full_reset_bypass`(15) all verified
  with reachable traces; the F5 gap is *scope* (unmodeled bump path), not vacuity.
- **The residual/anti-vacuity controls that DO ship are correctly false** (`attacker(pinR)`,
  `attacker(halfOR)`) — they just guard the wrong (event-free residual) legs, which is exactly F1/F2.
- **README tables are honest** where the model headers overstate (F3/F4): the README lists only the query
  families actually asked, so the overclaim is localized to model docstrings, not the public claim surface.

## 6. What was NOT looked at (next-round targets)

- The **CryptoVerif** models were source-read only in prior rounds and were **not executed** here (this pass
  ran proverif/tamarin); their computational-model query bodies remain execution-unverified.
- **Injective vs non-injective** strength was assessed only where a header claimed it (F4); a systematic
  sweep for other correspondences that *should* be `inj-event` once `!`-replication lands was not done.
- The `!`-**replicated cross-session** variants named in the SCP03/shield headers (PM-3 follow-up) do not
  exist yet — the "would the current queries still hold under replication" question is unanswerable until
  they do.
- **`scripts/check_protocol_models.py` count baselines** were read, not re-derived; the exact
  `(true,false,cannot)` triples per file were taken from the live run, and the assumption that the gate is a
  required status check on `master` is inherited from the 2026-07-02 round's caveat.

## 7. Provenance

**EXECUTING round** — the §4 residual ("protocol-model query bodies beyond the reachability-witness check")
that ADVERSARIAL_REVIEW_2026-07-02.md named and its concurrent executing round explicitly skipped. Four
finders ran the 9 models (ProVerif × handshake/replay/unlock/fw-update, Tamarin × pin_lockstep) on the live
working tree via `proverif` and `tamarin-prover` 1.12.0, injecting reachability probes into working copies
to test each positive result for vacuity and (for F1) mutating a baseline leg to confirm the gate stays
green. Each finding was cross-voted by an independent default-to-refute skeptic; none was refuted; the two
disclosed/safe-direction items were held at INFO. FV-**soundness** pass — every finding is "a query/model/
claim is hollow, unenforced, or overstated", not a vulnerability. No fixes applied.

---

## Fixes applied 2026-07-02 (this round DID remediate — verified by re-running the models)

All five findings closed on the same day (unlike the finding-record-only §2 round). Each verified with proverif 2.05 / tamarin-prover; the count-gate `scripts/check_protocol_models.py` was re-baselined + re-run GREEN.

- **F1 (optiga_shield_handshake.pv):** added 2 reachability witnesses `query event(HostAccepted)` / `event(OptAccepted)` — both report `is false` (reachable). Baseline (3,1)->(3,3). Now a dead baseline leg reddens a witness instead of passing at the same count (the mutation the finder demonstrated is now caught).
- **F2 (scp03_handshake.pv + scp03_replay.pv):** added 4 handshake witnesses (CardSent/HostAccepted/HostSent/CardAccepted) + 1 `Accept` witness; all `is false`. Baselines (3,1)->(3,5) and (1,0)->(1,1).
- **F3 (optiga docstring):** dropped the "session-key secrecy" over-claim — the session key `s` is structurally never leaked (PBS-secrecy) but is NOT a separately-queried result; the docstring now advertises only the mutual-auth + half_O queries actually shipped.
- **F4 (scp03_handshake docstring):** "injective-agreement" -> "NON-injective agreement" (the queries are `event(A)==>event(B)`; injectivity/no-replay is the Tamarin scp03_replay.spthy job).
- **F5 (pin_lockstep.spthy):** added a MODEL-SCOPE note — the model has no wrong-PIN BUMP rule; it abstracts counters to fresh/zeroed and proves reconcile-catches-desync, NOT the "lockstep" bump dynamics the name/README describe.

Post-fix gate: proverif 13 true / 4 false / 0 cannot, tamarin 8 verified / 0 falsified, cryptoverif proved.
