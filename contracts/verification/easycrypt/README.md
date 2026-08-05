# SPHINCS+C EUF-CMA — EasyCrypt port

This is the **evidence** behind two axioms in `theft_free`'s closure —
`A5-EUFCMA` and `A5-ITSR` (see `../docs/AXIOM_STATUS.json`). It was developed in a
separate, remote-less repo and vendored here on **2026-07-10** so the citations are
actually spot-checkable, per STATUS.md's rule #1.

> **UPDATE 2026-08-04 — the current artifact is [`c10-port/`](c10-port/), not
> `drafts/`.** `drafts/*.ec` is the 2026-07-10 snapshot and is retained as
> history only. `c10-port/` is the workspace at its commit `16fe480`, at which
> **both certification gates are GREEN** (split: 24 targets / 87 statement pins
> / 1159 census rows; fork: 19 / 9 / 1089), with committed input identities that
> each gate recomputes and compares at start *and* end of every run. Read
> [`c10-port/README.md`](c10-port/README.md) first — in particular the section
> on what is **not** proved: the headline theorem carries an unreduced bad-event
> probability `Q` that nothing bounds below 1, so the bound is currently
> compatible with 1.

## Read this before trusting any "it compiles" claim

**EasyCrypt's `require` does NOT re-verify a dependency's proofs.** It imports the
theory's lemma *statements* and trusts them:

```
Broken.ec: lemma brk : false. proof. trivial. qed.          -> compiles EXIT 1
Uses.ec  : require import Broken.
           lemma e : 1 = 2. proof. have := brk. done. qed.  -> compiles EXIT 0  (!)
```

And **`admit` compiles EXIT 0 with zero output.** So an exit code proves nothing.
The only sound gate is: compile **every file as a target**, plus a
**nesting-aware** admit/axiom sweep (EasyCrypt comments nest, and a naive
`(\*.*?\*)` regex leaks prose like "zero-admit"; a line-anchored `^\s*admit\.`
misses an inline `proof. admit. qed.`). Both bugs were live in our own tooling
until 2026-07-10. That is what `scripts/check_easycrypt.sh` + `scripts/ec_sweep.py` do.

## Running it

The MM45 reference proofs are **not vendored** (large, third-party). Fetch once:

```sh
git clone --depth 1 https://github.com/MM45/FV-SPHINCSPLUS-EC
git clone --depth 1 https://github.com/MM45/FV-XMSS-EC
```

Then, with an opam switch carrying EasyCrypt **r2026.02** + Alt-Ergo **2.6.0**
(see `PROVENANCE.md`; the `checkct` dev switch cannot compile `WOTS_TW_ES.ec`):

```sh
EC_FV_ROOT=<parent-of-the-two-clones> make -C contracts/verification verify-easycrypt
make -C contracts/verification verify-easycrypt-pins   # ledger only, no toolchain
```

Include order matters: **XMSS before SPHINCSPLUS**, else `unknown type diff_t`.

## What is actually proven

| leg | state |
|---|---|
| **WOTS+C** | **unconditional.** `D1_MEUFNACMA_WOTSC_MM45_embthfc` bounds a real game by real games (`S_TCR_C` + MM45's actual `M_EUF_GCMA_WOTSTWESNPRF`). 0 admit, no free reals, no embedding hypothesis. Matches the paper's Thm C.2. |
| **hypertree over WOTS+C** | module + two proven gates (`sign_size_d`, `sign_ll`). `XMSSMT_C_Scheme.ec`. |
| **FORS+C** | C10-faithful model + game (`FORS_C10.ec`); combinatorial core machine-checked (`DarkSide.ec`: `cover_pr`, `forsc_le_fors`). The **tight bound is open** — and note MM45 never bounds ITSR either. |
| **SPHINCS+C composition** | **assumed.** `SPHINCS_C.ec`'s LHS `p_sphincs_c` is an abstract real: there is no SPHINCS+C scheme module, and `hfx` / `hbridge` are premises. It is a conditional theorem, not a security proof. |

**3 admits, all in files that nothing requires** (`FORS_C_TreePort.ec`,
`WOTS_C_Interactive.ec` — the third, an untracked scratch probe, was not vendored).

> **UPDATE 2026-08-04 — this admit inventory is superseded; see
> [`c10-port/`](c10-port/).** Two changes since it was written, both verified
> against the current census (`c10-port/cert-baseline-split.tsv`):
> * `WOTS_C_Interactive.ec` **no longer carries an admit** — it has no admit
>   tactic and no census admit row. (It is also *required* by the capstone,
>   `SphincsC10CapstoneWired.ec:353`, so it was never a file "nothing requires".)
> * `FORS_C_TreePort.ec` still has its one admit — `extract_op` — and nothing
>   requires it, so that half of the sentence holds. What changed is that run 23
>   made it a closure **target**: it is now compiled and gate-enforced, and its
>   admit is a counted ledger row pinned by statement digest, rather than
>   checked by nothing.
>
> Current truth: the split cone carries exactly **two** admits —
> `nhchwcoll_hchwpre_msg` (`base-c10-split/WOTS_TW_ES.ec`, inherited from MM45)
> and `extract_op` — and the fork cone two, both inherited. Every one is pinned.
>
> **The next sentence ("the capstone's dependency chain is admit-free") is NOT
> re-verified and is in tension with the above — treat it as unchecked.**
> `nhchwcoll_hchwpre_msg` is admitted *and used*, at `WOTS_TW_ES.ec:6542`, inside
> a file the capstone requires transitively. Whether the particular result that
> consumes it is itself on the capstone's path is a trace I did not complete, so
> this is flagged rather than corrected. Resolve it before quoting either
> sentence.

The capstone's dependency chain is admit-free. **8 axioms** (refreshed 2026-07-16,
FV review F5 — was "7"; `uniq_g` was added 2026-07-10 and omitted here): `dpp_ll`,
`dmkey_ll` (losslessness), `good_pos` (= the paper's p_ν), and five structural
constraints on the FORS index extractor `g` that mirror MM45's own (`size_g`,
`eqiks_g`, `neqisvs_g`, `rng_g`, `uniq_g`). The exact `(name → statement)` set is
pinned in `axiom_pins.txt` and enforced by `make verify-easycrypt-pins`.

Upstream history and the full dated record: `PROVENANCE.md`, and
`../../../docs/verification/easycrypt-euf-cma-port-feasibility-2026-07.md`.
