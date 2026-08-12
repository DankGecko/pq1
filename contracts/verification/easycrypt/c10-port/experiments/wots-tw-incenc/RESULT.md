# RESULT — Track B milestone 2a: MM45's injectivity requirement is localized

Companion to `PREDICTION.md` (written BEFORE the compile). Read that first; the
prediction is what makes this falsifiable rather than a post-hoc reading.

## Headline

**Weakening `two_encodings` from message-inequality to Def-9 CODEWORD-inequality
breaks MM45's 6314-line WOTS-TW development in exactly ONE proof step — the
forgery site — and that step is precisely where T-COLL-RES must enter.**

This does **NOT** prove C10 secure, does **NOT** close the deployed-parameter
gap, and does **NOT** port the computational leg. It converts a belief
("injectivity is a modelling artifact") into a machine-checked measurement
("the artifact is one proof step, and here it is").

## Prediction vs. outcome

Prediction, recorded before running:

> Edits 1-3 succeed. Exactly ONE site fails: `:6261`, for want of
> `encode_msgWOTS q.`2 <> encode_msgWOTS m'` where the game supplies only the
> message inequality `neqq2_mp : q.`2 <> m'`. NOTHING ELSE fails.

Outcome of the 3-edit compile (`incenc_compile.log`, 2m31.802s):

```
__EC_RC=1
[critical] [experiments/wots-tw-incenc/WOTS_TW_ES.ec: line 6261 (0-78)] cannot apply view
```

**One error, at the predicted line.** `cannot apply view` is the exact signature
of `move/(nhchwcoll_hchwpre ...): (neqq2_mp)` failing because `neqq2_mp` is a
message inequality where the weakened lemma now demands a codeword inequality.

Everything below `:6261` compiled: the weakened axiom (`:585`), the promoted
`enc_nonzero` (`:603`), `exenc_neq0` (`:607`), the codeword-hypothesis
`nhchwcoll_hchwpre` (`:1327`), and the `exenc_neq0` use site (`:1520`).

### No fourth site — confirmed, not inferred

EasyCrypt aborts at the first error, so the run above establishes only that the
FIRST failure is at the predicted line. To test the "NOTHING ELSE fails" half of
the prediction, `WOTS_TW_ES_probe.ec` bridges that single gap and recompiles:

```
__EC_RC=0        (zero errors; WOTS_TW_ES_probe.eco written, 5934 B)
```

**The whole 6314-line development compiles once the one gap is bridged. The
prediction is confirmed in full: injectivity is needed at exactly ONE site.**

The bridge is `axiom PROBE_enc_inj : m <> m' => encode m <> encode m'` plus a
name-only substitution at the call site, so the tactic line is byte-identical to
the original and the patch itself is not a variable. **`PROBE_enc_inj` IS
injectivity** — the very property the experiment exists to remove. It makes the
probe file VACUOUS at C10 geometry. It is a 4th-site detector, not a result, and
nothing in the repair may cite it.

### Receipt matrix (the permission fix is controlled for)

| run | file | dir perms | result |
|-----|------|-----------|--------|
| 1 | 3 edits | broken (775) | `RC=1`, `[critical] :6261 cannot apply view`, max 98.6% |
| control | 3 edits | **fixed (777)** | `RC=1`, `[critical] :6261 cannot apply view`, max 98.6% — **identical** |
| probe-2 | 3 edits + bridge | broken (775) | `RC=1`, **no** `[critical]`, max 100.0%, no `.eco` — the silent artifact-write failure |
| probe-3 | 3 edits + bridge | **fixed (777)** | **`RC=0`**, no errors, `.eco` 5934 B |

The control run is what makes this airtight: the `:6261` failure reproduces
byte-identically under fixed permissions, so it is a genuine proof obligation,
not an environment artifact. And probe-3 shows that bridging that ONE obligation
compiles the entire development.

## The three edits

| # | site | change |
|---|------|--------|
| 1 | `:585` | `two_encodings` hypothesis `m <> m'` -> `encode_msgWOTS m <> encode_msgWOTS m'`. This IS Def 9 incomparability over codewords; `drafts/IncEnc.ec` proves target-sum satisfies it for ARBITRARY `(v,w,T)`, and that C10's `(43,3,205)` is admissible and non-vacuous. |
| 2 | `:603` | `exenc_neq0` promoted from derived lemma to explicit axiom `enc_nonzero`. Its old proof fed `two_encodings` a constructed `pm <> m`, which under a many-to-one encoding does not give `encode pm <> encode m`. |
| 3 | `:1327` | `nhchwcoll_hchwpre` hypothesis weakened to codeword inequality. Its CONCLUSION already mentioned only encodings, so nothing downstream of the conclusion changed. |

## Census deltas (the honest cost)

- **Admits introduced by the 3 edits: 0.** (Pristine file also 0.)
- **Axioms: +1** — `enc_nonzero`. `two_encodings` was *weakened*, not added to.

Edit 2 is a real NARROWING and is deliberately visible in the census: the
repaired development is no longer parametric in the encoding, it now requires a
code where every codeword has a nonzero digit. C10 satisfies this because
`target_sum = 205 > 0`, but it is not free.

The trade, exactly: one axiom moves from **unsatisfiable at deployed geometry**
(largest antichain of `{0..7}^43` = `2^123.76 < 2^128`) to **satisfiable at any
geometry**, at the cost of one explicit positivity axiom and one relocated proof
obligation.

## Read-only invariant

The vendored third-party tree was **not** edited. `git status FV-SPHINCSPLUS-EC/`
is empty and `WOTS_TW_ES.ec` md5 is `e6165a3bfa17e3d884878714bb80bc9c` before and
after. The experiment compiles a COPY on a shadowing include path. The diff is
the artifact.

## Method notes (traps, and one self-catch)

- **First-error abort.** EasyCrypt stops at the first error, so the 3-edit
  compile establishes "the FIRST failure is at the predicted site", not "the
  ONLY failure". The `_probe` file exists solely to compile PAST that gap and
  expose any fourth site. Its `PROBE_enc_inj` axiom IS injectivity — it makes
  the probe file vacuous at C10 geometry and is not part of the repair.
- **Probe v1 was malformed.** A first probe inserted `have enc_neq ... by admit`
  and failed at `:6267` with `nothing to introduce` — a tactic-shape artifact of
  the patch, NOT a fourth site. Rebuilt as a NAME-ONLY substitution at the call
  site (`nhchwcoll_hchwpre` -> `nhchwcoll_hchwpre_msg`) so the tactic line is
  byte-identical to the original and the patch is not a variable.
- **Self-catch on the admit census.** The sweep regex counted the word
  "admitted" inside a COMMENT, reporting 2 admits where there was 1. Direction
  is fail-CLOSED (false alarm, never a false pass), so no prior certification is
  affected — but `ec-certify.sh` shares this regex and will over-count prose.

## ENVIRONMENT GOTCHA — a silent exit-1 that is not a proof failure

The probe first appeared to fail with **no diagnostic at all**: progress reached
`100.0%` (all 6360 lines), stdout empty, stderr 85 KB of pure spinner, `RC=1`,
no `.eco`. That looks identical to a mysterious proof failure and nearly got
reported as one.

**Actual cause: a filesystem permission, not mathematics.** The `ec-grind`
container runs as `uid=1001(charlie) gid=0(root)`, while the host checkout is
owned by `uid=1000`. `/work` and `/work/drafts` happen to be `drwxrwxrwx`, so
every prior compile in `drafts/` worked. A NEW directory created on the host
(`experiments/`) is `drwxrwxr-x` — so the container could read the `.ec` and
check every proof, then fail writing the `.eco` artifact, exiting 1 silently.

Fix: `chmod 777 experiments experiments/wots-tw-incenc`.

**How to tell the two apart** (both give `RC=1`):

| signal | real proof error | permission failure |
|---|---|---|
| max progress | stops mid-file (98.6% here) | reaches 100.0% |
| `[critical]` in raw log | present | absent |
| `.eco` | absent | absent |

EasyCrypt **aborts at the first error** — confirmed: run 1 stopped at 98.6%
(= line 6261/6342) and printed 8 further lines total. So "reached 100%" is
strong evidence that no proof step failed, and `.eco` absence alone proves
nothing without checking progress and the raw log.

## Scope limits — what this does NOT establish

1. **One file only.** `WOTS_TW_ES.ec` is compiled. Its dependent
   `FL_SL_XMSS_MT_ES.ec`, and the rest of the chain up to the capstone, are NOT
   yet recompiled against the weakened axiom. A downstream site could still
   depend on injectivity.
2. **The gap is not closed, only located.** Supplying the missing codeword
   inequality requires a game hop charging encoding collisions to T-COLL-RES
   (Def 11) BEFORE the case split — case-split-only is UNSOUND. That hop is the
   computational leg, deliberately not started here.
3. **T-COLL-RES advantage at C10 is unproven.** `IncEnc.ec` states Def 11 as an
   executable game with 7 modelling obligations itemised; it bounds nothing yet.

---

# UNIT 2 RESULT — the localization extends to the ENTIRE MM45 chain

Prediction (recorded in `PREDICTION.md` before running): the shadow canary
passes, and `FL_SL_XMSS_MT_ES.ec` / `FORS_ES.ec` / `SPHINCS_PLUS.ec` all compile
against the weakened axiom. **Confirmed.**

## Setup — why this run can produce a negative

`shadow/` is a COMPLETE copy of the MM45 base (7 `.ec` + 4 `.eca`) in which
**only `WOTS_TW_ES.ec` differs** — verified file-by-file against the vendored
tree. It carries the 3 edits plus a bridge exposing the ORIGINAL
message-inequality interface whose single missing obligation is left OPEN as
**exactly one `admit`**, and **NO injectivity axiom anywhere**. So a downstream
site needing injectivity MUST fail; it cannot silently borrow it.

Compiled with `-I shadow -I drafts` — the vendored directory is **not on the
include path at all**.

## Result

```
### WOTS_TW_ES.ec        rc=0   eco: YES
### ShadowCanary.ec      rc=0   eco: YES
### FL_SL_XMSS_MT_ES.ec  rc=0   eco: YES
### FORS_ES.ec           rc=0   eco: YES
### SPHINCS_PLUS.ec      rc=0   eco: YES
```

Census across the whole shadow chain:

- **Total real admits: 1** — the T-COLL-RES gap. Nothing else.
- **Injectivity axioms: 0.**
- The chain carries the **weakened codeword** `two_encodings`.
- The admit is **load-bearing**: `nhchwcoll_hchwpre_msg` is used at `:6261`
  inside the M-EUF-GCMA proof that `SPHINCS_PLUS.ec` depends on. This is not a
  vacuous pass — removing the bridge makes the chain fail (the unit-1 control).

**Conclusion: MM45's entire SPHINCS+ development — WOTS-TW, FL-SL-XMSS-MT,
FORS, and SPHINCS_PLUS — holds under Def-9 codeword-incomparability, with
exactly ONE open obligation: the T-COLL-RES gap at the forgery site.**

## THE SHADOWING TRAP FIRED — and it would have produced a false pass

The first attempt used `-I chain -I FV-SPHINCSPLUS-EC/proofs`, assuming
include-path order shadows. **It does not.** `require WOTS_TW_ES` resolved to
the PRISTINE vendored file:

```
[critical] ShadowCanary.ec: line 9  unknown lemma `nhchwcoll_hchwpre_msg'
```

Had the canary been skipped, `FL_SL_XMSS_MT_ES.ec` would have compiled against
the UNMODIFIED axiom and passed trivially — reported as "the chain works with
the weakened axiom", which would have been **completely wrong and
indistinguishable from success**. The canary works because
`nhchwcoll_hchwpre_msg` exists ONLY in the modified copy, so it compiles iff
EasyCrypt really loaded that copy.

Fix: eliminate the ambiguity (complete shadow tree, vendored dir off the path)
rather than rely on `-I` precedence.

Second gotcha in the same step: the base's support theories are `.eca` abstract
theories (`HashAddresses`, `KeyedHashFunctions`, `TweakableHashFunctions`,
`OpenPRE_From_TCR_DSPR_THF`), so an initial `cp *.ec` silently missed them and
produced `cannot locate theory HashAddresses`.

## Trap T2 handled without disturbing a concurrent session

`drafts/*.eco` were compiled against the PRISTINE base. EasyCrypt does not
invalidate a dependent's `.eco`, so reusing them could replay stale results.
Rather than delete another session's build cache, the capstone run uses
`sdrafts/` — a copy of `drafts/*.ec` with **no** `.eco` — forcing a real
recompile against the weakened axiom.

---

# UNIT 2 FINAL — the chain's injectivity dependence is confined to ONE obligation

> **Headline tightened 2026-07-26 (self-correction).** An earlier draft of this
> section said "PQ1's entire capstone chain HOLDS under Def-9
> codeword-incomparability". That overreaches: the one admit sits INSIDE
> `WOTS_TW_ES`, **upstream of everything**, so the capstone's theorem is
> CONDITIONAL on an unproven obligation — it does not "hold". The precise claim
> is the one now in the heading: *the chain's dependence on injectivity is
> confined to a single obligation, and conditional on that obligation every file
> re-verifies.* Same shape as the unit-1 "exactly" -> "candidate" walk-back.

## Result

**26 files, each compiled as an EXPLICIT target against the weakened axiom.**

MM45 base — all 11 (7 `.ec` + 4 `.eca`) plus the canary, each as a target:
`WOTS_TW_ES`, `FL_SL_XMSS_MT_ES`, `FORS_ES`, `SPHINCS_PLUS`, `BinaryTrees` 8s,
`MerkleTrees` 8s, `PRE_From_SPR_DSPR` 5s, `HashAddresses` 1s,
`KeyedHashFunctions` 0s, `TweakableHashFunctions` 1s,
`OpenPRE_From_TCR_DSPR_THF` 23s, `ShadowCanary` — all `rc=0`.

(The last seven were initially pulled in only via `require` — which this very
unit proved does NOT re-verify — so they were gated explicitly rather than
left as a caveat. None of them references `encode_msgWOTS`/`two_encodings`.)

PQ1 draft closure (14), topological order, with timings that evidence real
re-verification rather than cache hits:

```
Grind 0s · STCR_C 1s · WOTS_C_Real 3s · WOTS_C_Scheme 3s · XMSSMT_C_Scheme 3s
WOTS_C_Reduction 4s · WOTS_C_Interactive 27s · XmssmtCC_All 724s
RtopCSoundness 32s · FxChain 70s · FORS_C10 0s · FORS_C10_Multi 2s
GprocFORSC10 10s · SphincsC10CapstoneWired 4s
GATE_FAILURES=0
```

Census over all 26:

- **TOTAL REAL ADMITS: 1** — `shadow/WOTS_TW_ES.ec:1359`, the T-COLL-RES gap.
  **Zero in all 14 PQ1 draft files.**
- **Injectivity axioms: 0.**
- **CARRIED AXIOMS: +1 — `enc_nonzero`.** The whole 26-file set now carries a
  positivity axiom the pristine base did not (unit-1 edit 2). It is NOT free:
  the development is no longer parametric in the encoding, it requires a code
  whose every codeword has a nonzero digit. C10 satisfies it because
  `target_sum = 205 > 0`. Anyone reading only this section would otherwise get a
  cleaner picture than is true.
- All 14 draft files **byte-identical to `drafts/`** — `WOTS_TW_ES.ec` is the
  sole variable.
- Vendored tree pristine: md5 `e6165a3b…`, `git status` empty.

**CONCLUSION — stated conditionally, which is the honest form.** Conditional on
the single T-COLL-RES obligation, all 26 files re-verify under Def-9
codeword-incomparability, and **no other part of the chain — MM45 base or PQ1
capstone — needs injectivity anywhere.** The deployed-parameter blocker is
therefore confined to exactly ONE open obligation chain-wide: the T-COLL-RES gap
at the forgery site. The capstone theorem does **not** "hold" — it is
conditional on that obligation, which is unproven.

## Controls (this unit produced FOUR false passes; none survived)

1. **Include-path shadowing does NOT work.** `-I chain -I FV-.../proofs` left
   `require WOTS_TW_ES` resolving to the PRISTINE file. Caught by a canary
   referencing `nhchwcoll_hchwpre_msg`, which exists only in the modified copy.
   Without it, `FL_SL_XMSS_MT_ES` would have compiled against the UNMODIFIED
   axiom and passed trivially. Fixed by a complete shadow tree with the vendored
   dir off the include path.
2. **`.eco` caching made a re-run look instant.** Negative control: breaking
   `shadow_neg/WOTS_TW_ES.ec` makes the capstone FAIL with the resolution trace
   `SphincsC10CapstoneWired -> SPHINCS_PLUS -> FL_SL_XMSS_MT_ES -> WOTS_TW_ES`,
   proving the chain is genuinely traversed.
3. **`require` does NOT re-verify (trap T1).** The capstone "compiled" in 3s
   with NO dependency `.eco` — because `require` elaborates declarations without
   re-running proofs. This is why the sound gate compiles EVERY file as an
   explicit target. `XmssmtCC_All` then took 724s.
4. **`while read` silently dropped the last closure entry** (no trailing
   newline), so the capstone was initially NOT gated. Fixed; then gated
   separately with its own negative control: injecting
   `lemma : false. proof. trivial. qed.` makes it FAIL (`cannot save an
   incomplete proof`), proving its own proofs are checked and the 4s is real.

## Census regex — a false NEGATIVE this time

The admit sweep first reported **3** admits (two were the word "admitted" in
COMMENT prose, in the project's own `XMSSMT_C_Scheme.ec` and
`WOTS_C_Interactive.ec`), then **0** after tightening to `^\s*admit\.$` — which
MISSED the real one because it carries a trailing comment. Correct count is 1.

Both directions matter: the over-count is fail-closed (a false alarm), but the
**under-count would have reported the chain as fully proven when it is not**.
`ec-certify.sh` shares the over-counting form; the under-counting form must
never be adopted.

## Scope — unchanged

Still does NOT prove C10 secure at deployed parameters. The single remaining
obligation is real and is the computational leg (T-COLL-RES advantage at C10,
discharged in a game hop BEFORE the case split), deliberately not started.

## Follow-up deliberately NOT done in this pass

`ec-certify.sh`'s admit regex is now characterized in BOTH directions:
over-counts the word "admitted" in comment prose (fail-CLOSED, a false alarm),
and the tightened `^\s*admit\.$` form under-counts an admit carrying a trailing
comment (fail-OPEN — it would report a chain as fully proven when it is not).
**That characterization is the deliverable.** The script is shared with a
concurrent session that may be compiling against it right now; editing it
mid-session is exactly how a fifth false pass gets created. Recorded as a
follow-up. The load-bearing rule: **the under-counting form must never be
adopted.**
