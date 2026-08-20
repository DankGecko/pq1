# FINDING — total statement coverage: two blockers, and a defect in the pins that already existed

2026-08-20. Pinning all top-level statements in the certified closure. Recorded because
the naive version of this task would have been a large amount of work that did not
close the hole it was aimed at, and because two of the three problems were found by
adversarial review rather than by me.

---

## 0. THE TASK, AND WHY THE OBVIOUS VERSION FAILS

A prior review found that a NEW certified statement is structurally invisible to the
gate: nothing forces a lemma to be pinned, so a statement carrying an unwanted
hypothesis can be added with no manifest delta. The fix "pin all the statements" is
the obvious response, and on its own it **does not work**.

**VERIFIED:** `cert_gate_split.sh` PHASE 1c iterates the MANIFEST —
`done < cert-statements-split.tsv`. It checks that every PINNED statement still says
what it said. It never reads the files to ask what statements EXIST. So pinning the
905 that exist today does nothing about a 906th appearing tomorrow: the new one is
simply absent, and absence is invisible to a loop over the manifest.

Both directions are needed, and they catch different things:

```
PHASE 1c   manifest -> files    a pinned statement cannot silently CHANGE
PHASE 1h   files -> manifest    a statement cannot silently APPEAR unpinned
EXPECT_STMTS                    a statement cannot silently be REMOVED
```

Removal deserves its own line: it leaves every surviving pin valid and every remaining
statement pinned, so it is invisible to *both* checks. Only a committed total sees it.

Control **CV1** (add a lemma, expect FAIL) is the control that justifies the whole
exercise. Without PHASE 1h it passes, and 905 pins buy nothing they were meant to buy.

## 1. BLOCKER — `pred` bodies were watched by NOTHING

**VERIFIED at source.** `digest()` matches `lemma|theorem|equiv|hoare|phoare`
(`tools/stmt_digest.py`), and `digest_op()`'s alternation was
`op|const|abbrev|axiom|declare axiom` — **no `pred`**. Both paths returned `NOT-FOUND`
for `cdrafts-split/FORS_C_TreePort.ec::brk_structural`. `cert_cone.py`'s abstract scan
matches `(const|op|type)` and skips bodies, so no census row exists either.

A `pred` body is **pure logical content usable as a lemma hypothesis**, and a statement
naming one digests only the TOKEN. So appending a conjunct to a body installs that
hypothesis into every statement using it with **zero pin, coverage and census delta**.
`FORS_C_TreePort.ec` declares 9 preds, appearing in the statements of 12 results.

That is the exact attack PHASE 1g (the policy-cap quarantine) exists to stop — landing
through a surface no phase watched. The quarantine fences one file; this route needed
no reference to it at all.

**Control CV5 is the discriminating evidence:** after the fix, editing a pred body
moves the PRED pin while the digests of the statements naming it do **not** move. That
gap is precisely why the pred row is load-bearing rather than redundant — and it is
also a measurement of how invisible the body was before.

## 2. BLOCKER — line-anchored scans, in a whitespace-insensitive language

EasyCrypt does not care about newlines. `qed. lemma hidden : 1 = 1. proof. trivial. qed.`
on ONE physical line is a legal, saved, requirable result. Both new scans anchored at
line start, so such a statement is **not counted** (EXPECT_STMTS unmoved), **not
reported unpinned** (PHASE 1h prints full coverage), and **not pinnable** (`digest()`
returns NOT-FOUND, so a manifest row would turn PHASE 1c RED).

**The repo already knew the right idiom and I did not use it:** `tools/cert_cone.py:162`
matches `(?:^|\.)\s*(declare\s+axiom|axiom)`. So a smuggled mid-line AXIOM was caught by
the census, while a smuggled mid-line LEMMA or EQUIV was caught by nothing.

No mid-line statements exist in the tree today, so this fix is **preventive**. Control
CV6 covers it.

## 3. AND A DEFECT IN THE PINS THAT ALREADY EXISTED — 11 over-broad spans

Surfaced by the anchoring fix, not by the review. **11 of the 135 pre-existing pins
digested spans that ran past their own statement.**

Their lemmas have ONE-LINE proofs — `lemma foo : X. proof. by rewrite /foo. qed.` — so
the line-anchored `^\s*proof` terminator found no `proof` at a line start until a much
later lemma. `mem4_f`'s pinned span was **331 characters covering four lemmas and
their proofs**. 11/11 swallowed at least one `qed.`.

Consequence: those pins were not pinning what their key said. Over-broad is "safe" in
the sense that more text moving the digest still fails loudly, but the pin's MEANING
was wrong, and it made the pin brittle against edits to unrelated neighbouring proofs.
Their digests are corrected; that is why 11 committed values move in a change that is
otherwise purely additive.

**A trap this sets for the next person:** the first attempt at the anchoring fix moved
**870 of 923** digests. The cause was not the declaration anchor but the TERMINATOR: I
changed `^\s*proof` to `(?:^|\.)\s*proof`, which then matched at the statement's own
closing period, silently dropping the trailing `.` from every span. Both the
declaration match and the terminator must be re-anchored to their KEYWORD via a capture
group. The 11-vs-870 distinction is the whole signal: 870 means you broke the tool, 11
means you fixed a real defect.

## 4. AND THE COMMENT STRIPPER SPLICED

`strip_comments` removed comments without a separator, so `lemma(* x *)foo` became
`lemmafoo` — the declaration vanished from every regex keyed on `lemma\s+name`. Not a
formatting quirk: an invisible declaration is an unpinned, uncounted one. Now emits a
separator and preserves newlines inside comments.

## RESULT

Gate GREEN: 932/932 pins, `coverage: all 905 top-level statements across 38 root files
are pinned`, cone `added=0`, `ledger=242`, `inputs unchanged across the run`.
Six controls at declared polarity and declared reason.

## WHAT THIS STILL DOES NOT CLOSE

Coverage enumerates the **38 roots**; the certified cone is **45 files**. Statements in
the 7 non-root cone files are pinned by neither check. Also unforced: `abbrev`, which is
pinnable via `digest_op` but which nothing requires to be pinned — the same
pinnable-but-not-forced shape that made `pred` dangerous. Both are named here rather
than left for the next reviewer to rediscover.
