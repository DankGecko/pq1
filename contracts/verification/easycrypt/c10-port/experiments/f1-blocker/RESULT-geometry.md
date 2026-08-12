# RESULT — the +C geometry change: the FULL C10 geometry now compiles

## Headline

**MM45's development accepts C10's deployed geometry.** All four base files
recompile with `log2_w = 3` admissible and `len = 43` flat (no checksum):

```
WOTS_TW_ES        rc=0  120s
FL_SL_XMSS_MT_ES  rc=0  572s
FORS_ES           rc=0  409s
SPHINCS_PLUS      rc=0  173s
```

Census: **1 admit** — the INHERITED T-COLL-RES gap from unit 1, not new — and
**ZERO new axioms**. The false `val_len1` stub from the previous F1 pass was
**dissolved, not carried**: making `len` primitive removed the reason it existed.
So unlike the F1 cost-estimate tree, this one contains no knowingly-false
statement.

## Why the checksum could be removed at all — the structural finding

`len1`/`len2` appear ONLY in the header of each file: defining `len` and deriving
`ge2_len`. They occur **nowhere in the proof body**. The body uses `len` 234x as
an opaque length and `ge2_len` 160x chain-wide, and nothing else.

That is because MM45's `encode_msgWOTS` is **abstract**, constrained solely by
`two_encodings`. **The checksum lives in the LENGTH ARITHMETIC, not the SECURITY
ARGUMENT.** Replace that axiom with Def-9 constant-sum incomparability (unit 1)
and the checksum has nothing left to do.

**Exactly ONE site in the whole chain used the checksum arithmetic inside a
PROOF**: `SPHINCS_PLUS:650`, an eight-line block establishing `0 < len` by
unfolding `len = len1 + len2` and showing each summand positive. With `len` an
independent parameter carrying `2 <= len`, that is `smt(ge2_len)`.

## The complete diff for deployed-C10 geometry

| change | sites |
|---|---|
| `log2_w : {int \| 2 <= log2_w}` (was `= 2 \/ 4 \/ 8`) | 3 declarations |
| `val_w : 4 <= w` (was the trichotomy) | 1 lemma |
| `len : {int \| 2 <= len}` primitive (was `len1 + len2`) | 3 declarations |
| drop `len1`,`len2`,`val_len1`,`val_len1_log{2,4,8}`,`ge1_len1`,`ge1_len2` | header only |
| drop the `len1`/`len2` clone bindings; `realize ge2_len` | 2 clone blocks |
| `0 < len` via `ge2_len` instead of checksum arithmetic | 1 proof site |

`2 <= log2_w` (not `1 <=`) is deliberate: it keeps `4 <= w` provable while
admitting C10's 3 and all of MM45's 2/4/8.

## Honest scope — what this does NOT establish

1. **This is a GEOMETRY result, not a security result.** It shows MM45's
   development is expressible at C10's parameters. It does not prove C10 secure.
2. **`Pr[G /\ COLL]` remains entirely uncharged.** That is steps 1-3 of the
   five-step route (faithful event; composition/extraction lemma with
   attacker-controlled `R`; one-canonical-target-per-address). Untouched.
3. **The one admit is still open** — the T-COLL-RES obligation at the forgery
   site inherited from unit 1.
4. The vendored trees are untouched; this is a shadow copy. Wiring the result
   back into the port (rather than a shadow) is separate work.

**C10 is still not proven at deployed parameters.** What changed: the two
STRUCTURAL blockers named in the unit-2 correction (`log2_w` admissibility and
checksum geometry) are now closed, leaving the probabilistic charge as the
substantive remaining work.
