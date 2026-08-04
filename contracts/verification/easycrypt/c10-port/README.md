# C10 (SPHINCS+C) EUF-CMA — certified EasyCrypt artifact

Snapshot of the `c10-eufcma-port` research workspace, taken at its commit
`cceb814` (2026-08-04, "run 24"), at which **both certification gates are
GREEN**.

This directory supersedes the older `../drafts/*.ec` snapshot, which is an
earlier stage of the same work and is retained only as history.

## What is actually proved, and what is not

Read this section before quoting anything from this directory.

The headline theorem is `EUFCMA_SPHINCS_PLUS_C10_GROUNDED`
(`cdrafts-split/SphincsC10CapstoneWired.ec`). It is a real, machine-checked
theorem, and it is **not a numerically meaningful bound**:

* It carries `Q = Pr[EUF_CMA_Gproc_I(R_fors_p(F)) : res /\ !covered]` as an
  UNREDUCED bad-event probability. Nothing in this tree bounds `Q` below 1, so
  the bound is currently compatible with 1. What `Q` buys over the earlier
  free-real formulation is that it is a *named game probability an instantiator
  cannot choose*, where a free real could be set to 1 at will.
* `Pr[M.F.ITSRC10 ...]` is likewise carried unreduced — that is the FORS+C10
  assumption and the honest headline term.
* Each cone contains **two admits**, every one pinned by statement digest:
  * split — `nhchwcoll_hchwpre_msg` (`base-c10-split/WOTS_TW_ES.ec`), inherited
    from MM45; and `extract_op` (`cdrafts-split/FORS_C_TreePort.ec`), the
    OpenPRE branch of the FORS bad-event cascade. `extract_op`'s own comment
    names four un-discharged parts (R-KEY, R-SIM, R-INDEX, R-OPEN) and records
    that closing it needs **exposed randomized leaf keygen** — an upstream
    interface change, not more proof effort.
  * fork — `nhchwcoll_hchwpre_msg` and `EUFNAGCMA_FLSLXMSSMTTWESNPRF`, both
    inherited.
* `FORS_C_TreePort.ec` (1733 lines) is the prior attempt at bounding `Q`. It was
  admitted to the split closure in run 23 *specifically so its real status is
  gate-enforced rather than asserted in its own prose*; certifying it raised the
  split census by 100 rows. Note what it does and does not bound:
  `fors_c_tree_port` bounds `EUF_CMA_FORSC_I`, **not** `EUF_CMA_Gproc_I`.
  Different game. It does not bound `Q`.
* Deployed-parameter and encoder claims are narrower than their names suggest;
  see `cdrafts-fork/C10DeployedGeometry.ec` sections 35-41.

`cdrafts-fork/C10DeployedGeometry.ec` is a ~2900-line dated log of every claim
this artifact has made and every one it has had to withdraw. It is the honest
record and is more useful than any summary, including this one.

## Reproducing the GREEN

Requires EasyCrypt **r2026.02** (the pinned toolchain; r2026.06 fails four
closure files). A container recipe is in `../docker/`.

```sh
export LC_ALL=C          # REQUIRED: identity hashing is collation-sensitive
bash cert_gate_split.sh  # 23 targets, 78 pins, 1156 census rows
bash cert_gate_fork.sh   # 19 targets,  9 pins, 1089 census rows
```

Both must end `RESULT: GREEN` / `CERT_FAILURES=0`. Expected identities are
committed in `cert-identity.tsv`; each gate recomputes and compares, and
recomputes again at the end to catch drift mid-run.

The gates check, in order: input identity, include-path ambiguity, a
concurrency guard, a verified recursive `.eco` purge, compilation of every
closure file **as an explicit target**, that every closure file is
**requirable** (EasyCrypt returns rc=0 for a file that ends mid-proof — this
phase is what catches that), that named results are `lemma` and not `axiom`,
statement digests, a require-cone census compared as a multiset against a
committed baseline with additions *and* removals fatal, two census-regression
canaries, and controls checked for polarity **and declared failure reason**.

## Layout

| path | what |
|---|---|
| `base-c10-split/`, `base-c10-fork/` | MM45 base, locally modified — see LICENSE.MM45 |
| `cdrafts-split/`, `cdrafts-fork/` | the C10 development (two certified trees) |
| `cert_gate_{split,fork}.sh` | the certification gates |
| `cert-*.tsv`, `closure-c10-*.txt` | manifests: baseline census, statement pins, controls, identity |
| `tools/` | `cert_cone.py` (census), `stmt_digest.py` (statement digests) |
| `scratch/` | control and canary fixtures **referenced by the gates only** |
| `experiments/tcollres-leg/` | on the fork gate's include path; carries three FINDING notes |

Two trees exist because route (D) splits the C10 width across two projection
members; `-split` and `-fork` are separately certified and are not
interchangeable.

## Provenance and licence

`base-c10-*` derives from [MM45/FV-SPHINCSPLUS-EC](https://github.com/MM45/FV-SPHINCSPLUS-EC)
(ASIACRYPT 2024), **MIT licensed** — see `LICENSE.MM45`, which is reproduced
here as that licence requires. Those files are **modified**: relative to
upstream, `SPHINCS_PLUS.ec` differs by ~3729 lines and `WOTS_TW_ES.ec` by ~469;
`FORS_ES.ec` is byte-identical to upstream. Everything under `cdrafts-*` is
this project's own work.

The upstream MM45 clone and the source papers are deliberately **not**
redistributed here; `PROVENANCE.md` records how to obtain them.
