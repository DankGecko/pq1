# SPHINCS+C EUF-CMA — EasyCrypt port

This is the **evidence** behind two axioms in `theft_free`'s closure —
`A5-EUFCMA` and `A5-ITSR` (see `../docs/AXIOM_STATUS.json`). It was developed in a
separate, remote-less repo and vendored here on **2026-07-10** so the citations are
actually spot-checkable, per STATUS.md's rule #1.

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
The capstone's dependency chain is admit-free. **7 axioms**: `dpp_ll`, `dmkey_ll`
(losslessness), `good_pos` (= the paper's p_ν), and four structural constraints on
the FORS index extractor `g` that mirror MM45's own.

Upstream history and the full dated record: `PROVENANCE.md`, and
`../../../docs/verification/easycrypt-euf-cma-port-feasibility-2026-07.md`.
