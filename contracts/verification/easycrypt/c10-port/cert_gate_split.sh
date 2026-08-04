#!/usr/bin/env bash
# Certification gate for the SPLIT tree (base-c10-split + cdrafts-split).
# Added 2026-08-01: the second adversarial review found that cert_gate_fork.sh
# watches ONLY the fork, so every "26/26" result for the split was an ad-hoc run
# with no gate behind it.  A result nothing enforces is not a receipt.
set -u
set -o pipefail
# LOCALE PINNING (added 2026-08-02, found while re-verifying a GREEN receipt).
# INPUTS_SHA256 hashes `sha256sum` lines emitted in `sort -u` order.  glibc
# collation is locale-dependent, so the SAME clean tree hashed to
#   45c4a166... in the container (LC_ALL unset -> POSIX)
#   fa7a6e6f... on the host      (en_US.UTF-8)
# -- identical file SET, different ORDER (STCR_C / XmssmtCC_All / XmssmtCCCharged).
# The identity line was therefore an identity of (tree, locale), not of the tree:
# a third party recomputing it in another locale sees a mismatch and concludes
# drift that does not exist.  I nearly concluded exactly that about this receipt.
# `sort -u` also collapses distinct strings that COLLATE equal in UTF-8 locales,
# which could silently undercount the control inventory (fail-closed, but wrong).
export LC_ALL=C
# CWD GUARD (run 10).  cert_gate_fork.sh does `cd /work`; this one trusted the
# caller's directory, so an invocation from elsewhere would fail every phase
# for a reason unrelated to the tree.  Assert the inputs are actually here.
for f in closure-c10-split.txt cert-baseline-split.tsv cert-statements-split.tsv \
         cert-controls-split.tsv tools/cert_cone.py tools/stmt_digest.py; do
  [ -e "$f" ] || { echo "FAIL wrong working directory: $f not found ($(pwd))"; exit 2; }
done
B=base-c10-split; D=cdrafts-split; INC="-I $B -I $D"
CLOSURE=closure-c10-split.txt; BASELINE=cert-baseline-split.tsv; STMTS=cert-statements-split.tsv
TMPD=$(mktemp -d) || { echo 'FAIL mktemp'; exit 1; }
trap 'rm -rf "$TMPD"' EXIT
# Expected inventory sizes, COMMITTED. A guard that recomputes its expectation
# from the file it is checking cannot detect truncation of that file.
EXPECT_PINS=78
fail=0

# TREE IDENTITY AND TOOLCHAIN, in the receipt itself.  A green receipt that does
# not say WHICH tree and WHICH prover produced it is not reproducible: adversarial
# review run 7 found four closure files failing as targets under r2026.06 while
# this container runs r2026.02, and no gate recorded either fact.
# The run-7 tree-identity line printed UNKNOWN every time.  git IS installed in
# the container; it refuses the bind-mounted /work (ownership/safe.directory), so
# `git rev-parse` never succeeded there.  My first diagnosis said git was absent
# -- wrong, and the sort of guess this log exists to stop.
# Hash the certified inputs themselves instead: that is what actually determines
# the result, and it needs no VCS.
# CONTROL SOURCES AND CANARY FIXTURES ARE NOW HASHED (run 13).  The identity
# covered the control MANIFEST (paths, polarity, declared reasons) and not the
# control .ec FILES, nor the PHASE 2b/2c fixtures.  So `scratch/vac_probe_full.ec`
# -- the two-sided vacuity control that is the ONLY mechanism to have caught a
# real end-to-end attack (run 11's inconsistency kill shot) -- could be rewritten
# to still fail for its declared reason while probing almost nothing: zero census
# delta, zero identity delta, gate green.  Found by two independent legs, run 13.
CTL_SRC=$(awk -F'\t' '!/^#/ && NF{print $1}' cert-controls-split.tsv | sort -u | tr '\n' ' ')
CANARY_SRC="scratch/CANARY_gate_admitted.ec scratch/CANARY_modtype_A.ec scratch/CANARY_modtype_B.ec scratch/CANARY_admit_A.ec scratch/CANARY_admit_B.ec"
ROOTS_ID=""
while read -r n; do case "$n" in ''|\#*) continue;; esac; ROOTS_ID="$ROOTS_ID $D/$n.ec"; done < $CLOSURE
for n in WOTS_TW_ES FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do ROOTS_ID="$ROOTS_ID $B/$n.ec"; done
# Hash the ACTUAL require-cone (32 files), not a hardcoded subset.  The previous
# version omitted the six library files -- BinaryTrees, MerkleTrees,
# HashAddresses.eca, KeyedHashFunctions.eca, OpenPRE_From_TCR_DSPR_THF.eca,
# TweakableHashFunctions.eca -- so an edit inside them that kept census rows
# identical changed the certified artifact with no identity delta.
# THE IDENTITY NOW COVERS THE MACHINERY TOO (run 10).  It used to hash the 32
# cone files plus the two manifests -- so tools/cert_cone.py, tools/stmt_digest.py,
# the control inventory and THIS SCRIPT could all be edited with no identity
# delta.  Blinding the census tool is a strictly easier attack than editing a
# proof, and PHASE 2b/2c only canary two specific behaviours of it.
INPUTS_ID=$( { CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $ROOTS_ID 2>/dev/null \
    | sed -n 's/^#   //p' | sort -u | while read -r f; do [ -f "$f" ] && sha256sum "$f"; done
  sha256sum $CLOSURE $BASELINE $STMTS cert-controls-split.tsv $CTL_SRC $CANARY_SRC tools/cert_cone.py tools/stmt_digest.py cert_gate_split.sh 2>/dev/null; } | sha256sum | cut -c1-32)
echo "### INPUTS_SHA256 $INPUTS_ID"
# AND NOW COMPARE IT.  This line was printed and checked by nothing: an identity
# receipt that no run can fail on is decoration.  The expected value lives in
# cert-identity.tsv, deliberately OUTSIDE the hashed set -- storing it inside
# would reproduce the self-reference claims-log section 35 records.
want_id=$(awk -F'\t' '!/^#/ && $1=="split"{print $2}' cert-identity.tsv 2>/dev/null)
if [ -z "${want_id:-}" ]; then
  echo "FAIL cert-identity.tsv missing or has no split row -- identity unpinned"; fail=$((fail+1))
elif [ "$INPUTS_ID" != "$want_id" ]; then
  echo "FAIL INPUTS_SHA256 DRIFT: committed $want_id, computed $INPUTS_ID"
  echo "     a certified input or the certification machinery changed;"
  echo "     re-baseline deliberately and update cert-identity.tsv in the same commit"
  fail=$((fail+1))
else
  echo "OK   INPUTS_SHA256 matches the committed identity"
fi
echo "### TOOLCHAIN $(easycrypt cli </dev/null 2>&1 | grep -ao 'GIT hash: [^ ]*' | head -1 || echo UNKNOWN)"
# PROVER INVENTORY (added 2026-08-02, run 10).  Every `smt()` in the closure is
# discharged by whatever provers the local why3 config offers, at whatever
# timeout; NOTHING here pins them and the receipt recorded only the EasyCrypt
# git hash.  This container answers with 25 prover configurations (Alt-Ergo
# 2.4.3/2.5.4/2.6.0, CVC4 1.8, CVC5 1.0.9, Z3 4.8.17/4.12.6/4.13.4).  A third
# party with a different set can get a different verdict on the SAME tree.
# Direction of the risk is fail-CLOSED FOR A MISSING PROVER -- it loses a goal,
# it does not invent one.  That is NOT the same as sound: a DIFFERENT prover
# version with a soundness bug does invent one, and this receipt inherits the
# prover-soundness assumption the whole artifact already makes (run 12).  So:
# a reproducibility receipt, under an unchanged trust assumption.
# 2>&1, NOT 2>/dev/null: EasyCrypt prints `known provers:` on STDERR, so the
# first version of this line hashed the EMPTY STRING and printed
# `e3b0c44298fc1c14 0 configurations` -- the SAME empty-input defect run 8
# found in the identity hash, committed again by me two hours later.  A
# receipt field must be checked for its VALUE, never for its presence.
echo "### PROVERS $(easycrypt config 2>&1 | sed -n 's/^known provers: //p' | head -1 | sha256sum | cut -c1-16) $(easycrypt config 2>&1 | sed -n 's/^known provers: //p' | head -1 | tr ',' '\n' | grep -c .) configurations"

# PHASE 0 -- INCLUDE-PATH AMBIGUITY.  resolve() in tools/cert_cone.py tries
# '.ec' then '.eca' and takes the LAST hit, but EasyCrypt's own preference when
# BOTH exist for one theory name is unverified.  Today no name is dual-extension
# (checked), so census and compiler cannot disagree; this guard fails the gate
# the moment that stops being true, instead of silently censusing one file while
# PHASE 1 compiles the other -- the run-7 shadowing defect in a new costume.
dupes=0
for d in $B $D; do
  n=$(ls "$d" 2>/dev/null | grep -E '\.(ec|eca)$' | sed -E 's/\.(ec|eca)$//' | sort | uniq -d | grep -c . || true)
  [ "${n:-0}" -eq 0 ] || { echo "FAIL $d has $n theory name(s) present as BOTH .ec and .eca"; dupes=$((dupes+n)); }
done
[ "$dupes" -eq 0 ] && echo "OK   no dual-extension theory names on the include path" || fail=$((fail+dupes))

# Purge stale .eco. EasyCrypt does not invalidate DEPENDENT .eco files when a
# required theory changes, so a stale cache can make a target "compile" against
# an older version. cert_gate_fork.sh:38-40 documents this; the first version of
# this script dropped the defence. Restored 2026-08-01 (adversarial review, run 3).
# CONCURRENCY GUARD (run 10).  A gate that shares its directories with another
# compile has no receipt: the other process writes .eco underneath it.  This
# is not hypothetical -- stopping a gate task on the host killed the `docker
# exec` client but NOT the in-container script, whose orphaned compile kept
# writing for 13 minutes into the tree the next run was purging.  The purge
# verification caught it (ECO_REMAINING=34); this stops it one step earlier.
others=$(ps -eo cmd 2>/dev/null | grep -c "[e]asycrypt compile.*base-c10-split" || true)
[ "${others:-0}" -eq 0 ] || { echo "FAIL another compile is running against base-c10-split ($others) -- refusing to produce a racy receipt"; exit 3; }
# PURGE MUST BE VERIFIED, NOT ATTEMPTED (run 10).  `|| true` swallowed every
# failure, and a surviving .eco is exactly the stale-cache green this purge
# exists to prevent.  Also covers every directory named by the control
# inventory, which is data-driven while this list used to be hardcoded.
# PURGE AND CHECK MUST HAVE THE SAME SCOPE (fixed 2026-08-02, second defect
# in this guard).  The purge was a GLOB (scratch/*.eco) and the check was a
# recursive FIND, so 33 objects in scratch SUBDIRECTORIES (advprobe, dsn,
# f1probe, f1probe/base3, incenc, audit0725) failed a gate that had never
# tried to delete them.  Both are recursive now.
# REPORT WHAT WAS PURGED, NOT ONLY WHAT SURVIVED (added 2026-08-04, run 22).
# This gate deleted correctly but printed only ECO_REMAINING, while the fork
# gate printed ECO_PURGED too.  ECO_REMAINING=0 is consistent with BOTH "there
# was nothing stale" and "180 stale objects were removed" -- and run 22 began
# with exactly the second case, after an orphaned compile from a killed run
# wrote objects against a tree that had moved under it.  A reader auditing that
# receipt could not tell the two apart from the gate output alone; I had to
# reconstruct it from .eco mtimes after the fact.  The count is a receipt, not
# a check: a nonzero ECO_PURGED is normal and is NOT a failure.  What would be
# alarming is a large ECO_PURGED together with an unexplained short PHASE 1.
ctl_dirs=$(awk -F'\t' '!/^#/ && NF{print $1}' cert-controls-split.tsv | xargs -r -n1 dirname | sort -u)
purged=$(for d in $B $D scratch $ctl_dirs; do [ -d "$d" ] && find "$d" -name '*.eco' -print -delete 2>/dev/null; done | sort -u | grep -c . || true)
left=$(for d in $B $D scratch $ctl_dirs; do [ -d "$d" ] && find "$d" -name '*.eco' 2>/dev/null; done | sort -u | grep -c . || true)
echo "### ECO_PURGED=$purged"
echo "### ECO_REMAINING=$left"
[ "$left" -eq 0 ] || { echo "FAIL stale .eco survived the purge ($left)"; fail=$((fail+1)); }

echo "### PHASE 1 — TARGETS"
for n in WOTS_TW_ES FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do
  if easycrypt compile -I $B $B/$n.ec >/dev/null 2>&1; then echo "OK   base/$n"; else echo "FAIL base/$n"; fail=$((fail+1)); fi
done
n_seen=0
while read -r n || [ -n "$n" ]; do
  case "$n" in ''|\#*) continue;; esac
  n_seen=$((n_seen+1))
  if easycrypt compile $INC $D/$n.ec >/dev/null 2>&1; then echo "OK   $n"; else echo "FAIL $n"; fail=$((fail+1)); fi
done < closure-c10-split.txt
n_exp=$(grep -cve '^[[:space:]]*$' -e '^#' closure-c10-split.txt)
echo "### CLOSURE_COMPILED=$n_seen EXPECTED=$n_exp"
[ "$n_seen" -eq "$n_exp" ] || { echo "FAIL closure truncated"; fail=$((fail+1)); }

echo "### PHASE 1d — EVERY CLOSURE FILE MUST BE REQUIRABLE (not merely compilable)"
# EasyCrypt returns rc=0 for a file that ENDS mid-proof.  Measured 2026-08-03:
# a file whose last proof has no `qed.` compiles silently -- no error, no
# warning -- the lemma is NOT saved, PHASE 1b's text grep for `^lemma NAME`
# still passes, PHASE 1c's statement digest still matches, and no census row
# appears.  (With `qed.` present EasyCrypt does say "cannot save an incomplete
# proof"; the silent case is specifically a file ENDING in an open proof.)
# A downstream `require` DOES fail -- but the capstones are LEAVES that nothing
# requires, so for exactly the files that matter nothing would surface it.
# The probe is GENERATED from $CLOSURE so it cannot drift out of sync with the
# closure list the way a checked-in control file would.
{ echo "require import AllCore."
  while read -r n || [ -n "$n" ]; do
    case "$n" in ''|\#*) continue;; esac
    echo "require import $n."
  done < $CLOSURE
} > "$TMPD/require_all.ec"
if easycrypt compile $INC "$TMPD/require_all.ec" >/dev/null 2>&1; then
  echo "OK   all closure files are requirable"
else
  echo "FAIL a closure file cannot be REQUIRED -- a proof is probably left open at EOF"
  easycrypt compile $INC "$TMPD/require_all.ec" 2>&1 | tr '\r' '\n' | grep -a '^\[critical\]' | head -2 | sed 's/^/       /'
  fail=$((fail+1))
fi

echo "### PHASE 1b — NAMED RESULTS EXIST AS LEMMAS (not axioms)"
# Added 2026-08-01.  Adversarial review observed the gate certified FILENAMES:
# replacing a capstone with `axiom EUFCMA_..._GROUNDED : <same statement>.`
# would still compile and (then) pass.  PHASE 2's cone census now catches the
# axiom, but the gate should also assert the results are actually THERE.
check_lemma() {
  f="$1"; n="$2"
  # Strip (* .. *) first: a declaration inside a comment previously passed.
  # Anchor with a non-name character after $n so NAME' (EasyCrypt prime suffix)
  # is not accepted as NAME.  Both holes found in adversarial review, run 4.
  body=$(python3 - "$f" <<'PY'
import io,sys
s=io.open(sys.argv[1],encoding="utf-8",errors="replace").read()
o=[];d=0;i=0
while i<len(s):
    if s.startswith("(*",i): d+=1;i+=2;continue
    if s.startswith("*)",i) and d>0: d-=1;i+=2;continue
    if d==0: o.append(s[i])
    elif s[i]=="\n": o.append("\n")
    i+=1
sys.stdout.write("".join(o))
PY
)
  if printf '%s' "$body" | grep -qE "^(lemma|theorem)[[:space:]]+$n([[:space:](:]|$)"; then
    echo "OK   $n is a lemma in $f"
  elif printf '%s' "$body" | grep -qE "^[[:space:]]*(declare[[:space:]]+)?axiom[[:space:]]+$n([[:space:](:]|$)"; then
    echo "FAIL $n is an AXIOM in $f (must be a lemma)"; fail=$((fail+1))
  else echo "FAIL $n not found as a lemma in $f"; fail=$((fail+1)); fi
}
check_lemma "$D/SphincsC10CapstoneWired.ec" EUFCMA_SPHINCS_PLUS_C10_GROUNDED
check_lemma "$D/C10DeployedCapstone.ec"     EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS
# TIER 0 (2026-08-03): the encoder-pinned variant must also be a LEMMA.  The
# older lemma stays -- it is not repaired, it is superseded for quotation.
check_lemma "$D/C10DeployedCapstone.ec"     EUFCMA_SPHINCS_PLUS_C10_AT_DEPLOYED_PARAMS_PINNED_ENCODER
check_lemma "$D/C10DeployedCapstone.ec"     EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL_AT_DEPLOYED_ENCODER
check_lemma "$D/SphincsC10CapstoneCharged.ec" EUFCMA_SPHINCS_PLUS_C10_CHARGED

echo "### PHASE 1c — STATEMENT DIGESTS (names are not enough)"
# Added 2026-08-01 (adversarial review, run 4).  The gate pinned NAMES and never
# STATEMENTS.  The deployed capstone has NO CONSUMER anywhere, so its conclusion
# could be weakened to `true` (proof `trivial`) and every other phase would still
# pass.  Verified by negative control: weakening it moves the digest
# 5bd600cb2661b4af2426525bb72e4058 -> 028803b8e5cd6fca33e562cecd495360.
if [ -f cert-statements-split.tsv ]; then
  n_stmt=0
  while IFS=$'\t' read -r key want || [ -n "${key:-}" ]; do
    case "${key:-}" in ''|\#*) continue;; esac
    n_stmt=$((n_stmt+1))
    got=$(python3 tools/stmt_digest.py "$key" | cut -f2)
    # AN UNRESOLVABLE PIN MUST FAIL, NOT AGREE WITH ITSELF (run 13d).  digest()
    # returned None for an `equiv`, the caller printed NOT-FOUND, and a manifest
    # row carrying the literal string NOT-FOUND compared EQUAL -- a pin that
    # looks pinned and targets nothing.  Caught while pinning GprocKg_sk_eq.
    case "$got" in
      NOT-FOUND|AMBIGUOUS-*|ambig*|nostmt)
        echo "FAIL statement pin does not resolve: $key -> $got"; fail=$((fail+1)); continue;;
    esac
    if [ "$got" = "$want" ]; then echo "OK   statement pinned: $key"
    else echo "FAIL statement CHANGED: $key"; echo "       want $want"; echo "       got  $got"; fail=$((fail+1)); fi
  done < cert-statements-split.tsv
  # Row-count guard: deleting a row would silently UNPIN that lemma.
  exp_stmt=$EXPECT_PINS   # COMMITTED CONSTANT, not recomputed from the manifest
  echo "statements pinned=$n_stmt expected=$exp_stmt (manifest rows)"
  [ "${n_stmt:-0}" -eq "${exp_stmt:-0}" ] && [ "${exp_stmt:-0}" -ge 1 ] || { echo "FAIL statement pin file truncated"; fail=$((fail+1)); }
else
  echo "FAIL cert-statements-split.tsv missing -- statements unpinned"; fail=$((fail+1))
fi

echo "### PHASE 2 — CONE CENSUS vs cert-baseline-split.tsv (ADDITIONS FATAL)"
# Rewritten 2026-08-01.  The first version was a flat `admit` regex over the 22
# closure filenames in cdrafts-split ONLY.  It therefore could not see the live
# admit in base-c10-split/WOTS_TW_ES.ec, yet printed an unqualified
# "admit tactics = 0".  It also counted no `axiom` / `declare axiom` and had no
# baseline, so the assumption set could GROW silently -- the exact property
# cert-baseline.tsv exists to prevent.  This now reuses the SAME transitive
# require-cone census the fork gate uses, pointed at the split trees.
ROOTS=""
while read -r n || [ -n "$n" ]; do
  case "$n" in ''|\#*) continue;; esac
  ROOTS="$ROOTS $D/$n.ec"
done < closure-c10-split.txt
for n in WOTS_TW_ES FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do ROOTS="$ROOTS $B/$n.ec"; done
CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $ROOTS 2>/dev/null \
  | grep -v '^#' | grep -v '^[[:space:]]*$' \
  | awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3}' | sort | uniq -c | sed 's/^ *//' | sort > "$TMPD/cone_now.tsv"
if [ ! -s "$TMPD/cone_now.tsv" ]; then echo "FAIL cone census produced nothing"; fail=$((fail+1)); fi
if [ -f cert-baseline-split.tsv ]; then
  # RE-SORT AFTER `uniq -c` (added 2026-08-04, run 23).  `sort | uniq -c` emits
  # lines sorted by KEY but prefixed with a COUNT, so the result is not sorted
  # by WHOLE LINE -- for keys a<b with counts 19 and 1, it emits "19<TAB>a"
  # before "1<TAB>b", yet "1<TAB>b" < "19<TAB>a" lexicographically.  `comm`
  # REQUIRES whole-line-sorted input and warns "input is not in sorted order"
  # on the live baseline (4 of 975 split rows carry two-digit counts).
  # HONEST STATUS: I could NOT construct a case where this produced a WRONG
  # added/removed count -- three attempts, including a hand-built minimal
  # reproduction, all agreed with a correctly-sorted comparison.  So this is
  # latent fragility, NOT a demonstrated defect, and the fix is verified
  # answer-preserving on the live data (added=100 both ways for the TreePort
  # delta).  It is fixed anyway because a spurious sortedness warning on the
  # gate's core anti-drift comparison would mask a real one.
  grep -v '^#' cert-baseline-split.tsv | grep -v '^[[:space:]]*$' \
  | awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3}' | sort | uniq -c | sed 's/^ *//' | sort > "$TMPD/cone_base.tsv"
  add=$(comm -23 "$TMPD/cone_now.tsv" "$TMPD/cone_base.tsv" | wc -l)
  gone=$(comm -13 "$TMPD/cone_now.tsv" "$TMPD/cone_base.tsv" | wc -l)
  echo "cone: keys now=$(wc -l < "$TMPD/cone_now.tsv") baseline=$(wc -l < "$TMPD/cone_base.tsv") | ROWS now=$(awk '{s+=$1} END{print s+0}' "$TMPD/cone_now.tsv") baseline=$(awk '{s+=$1} END{print s+0}' "$TMPD/cone_base.tsv") | added=$add removed=$gone"
  # TWO CLASSES, REPORTED SEPARATELY (run 10).  `module`/`module-type` rows are
  # MEANING-carriers, not assumptions; folding them into the ledger would be a
  # seventh wrong assumption total.  Both classes are equally fatal on change.
  awk '{k=$3; sub(/:.*/,"",k); n[k]+=$1}
       END{ led=n["admit"]+n["axiom"]+n["declare-axiom"]+n["refined-const"]+n["clone-discharge"]+n["op-annotation"]+n["clone-obligation"];
            par=n["abstract-const"]+n["abstract-op"]+n["abstract-type"];
          bind=n["operand"]+n["rename"];
          mean=n["module"]+n["module-type"];
            printf "  ledger=%d  parameters=%d  bindings=%d  meaning=%d  total=%d\n", led, par, bind, mean, led+par+bind+mean }' "$TMPD/cone_now.tsv"
  if [ "$add" -ne 0 ]; then
    echo "FAIL cone census GREW -- new assumption(s) entered the cone:"
    comm -23 "$TMPD/cone_now.tsv" "$TMPD/cone_base.tsv" | sed 's/^/       /'
    fail=$((fail+1))
  fi
  # REMOVALS ARE FATAL TOO (run 5).  A "tightening" is indistinguishable from an
  # assumption being SILENTLY DISCHARGED by weakening -- e.g. turning a refined
  # const into a definition makes its census row vanish while making the premise
  # that mentioned it trivially false.
  if [ "$gone" -ne 0 ]; then
    echo "FAIL cone census SHRANK -- entries disappeared (re-baseline deliberately if intended):"
    comm -13 "$TMPD/cone_now.tsv" "$TMPD/cone_base.tsv" | sed 's/^/       /'
    fail=$((fail+1))
  fi
else
  echo "FAIL cert-baseline-split.tsv missing -- cannot detect assumption growth"; fail=$((fail+1))
fi

echo '### PHASE 2b — CENSUS REGRESSION CANARY (admitted.)'
# scratch/CANARY_gate_admitted.ec has existed since 2026-07-26 and warns that
# EasyCrypt's proof terminator `admitted.` is NOT matched by a regex anchored on
# `admit\\b` -- so `lemma proof_of_false : false. proof. admitted.` sails through.
# The first version of THIS script had exactly that bug. `admitted.` COMPILES
# (it is a warning), so this cannot be a compile control: the CENSUS must catch it.
if [ -f scratch/CANARY_gate_admitted.ec ]; then
  cres=$(CERT_CONE_DIRS="scratch" python3 tools/cert_cone.py scratch/CANARY_gate_admitted.ec 2>/dev/null \
         | grep -v '^#' | awk -F'\t' '$2 ~ /^admit/' | grep -c . )
  if [ "${cres:-0}" -ge 1 ]; then echo "OK   census detects 'admitted.' (canary caught)"
  else echo "FAIL census MISSED 'admitted.' -- admit sweep has regressed"; fail=$((fail+1)); fi
else
  echo "FAIL census regression canary missing"; fail=$((fail+1))
fi

echo "### PHASE 2c — DIGEST DISCRIMINATION CANARY"
# Removal-fatality detects a category VANISHING.  It cannot detect a digest that
# has stopped DISCRIMINATING -- e.g. a _decl_span regression that truncates the
# span before the restriction, after which two different module types hash the
# same and the run-10 bypass becomes invisible again.  The fixtures differ in
# exactly one token (`{ O.sign }` vs `{ }`).  Same argument as PHASE 2b.
if [ -f scratch/CANARY_modtype_A.ec ] && [ -f scratch/CANARY_modtype_B.ec ]; then
  da=$(CERT_CONE_DIRS="scratch" python3 tools/cert_cone.py scratch/CANARY_modtype_A.ec 2>/dev/null \
       | awk -F'\t' '$3=="AdvC" && $2 ~ /^module-type/{print $2}')
  db=$(CERT_CONE_DIRS="scratch" python3 tools/cert_cone.py scratch/CANARY_modtype_B.ec 2>/dev/null \
       | awk -F'\t' '$3=="AdvC" && $2 ~ /^module-type/{print $2}')
  if [ -n "$da" ] && [ -n "$db" ] && [ "$da" != "$db" ]; then
    echo "OK   module-type digest discriminates ($da vs $db)"
  else
    echo "FAIL module-type digest does NOT discriminate (a=$da b=$db)"; fail=$((fail+1))
  fi
else
  echo "FAIL digest discrimination canary missing"; fail=$((fail+1))
fi
# ...and the SAME check for the admit statement digest, which is where the
# round-10 kill shot lived.  The two fixtures differ only in a PREMISE of the
# admitted lemma -- the exact edit that used to leave the census row identical.
if [ -f scratch/CANARY_admit_A.ec ] && [ -f scratch/CANARY_admit_B.ec ]; then
  aa=$(CERT_CONE_DIRS="scratch" python3 tools/cert_cone.py scratch/CANARY_admit_A.ec 2>/dev/null \
       | awk -F'\t' '$3=="canary_admit_stmt"{print $2}')
  ab=$(CERT_CONE_DIRS="scratch" python3 tools/cert_cone.py scratch/CANARY_admit_B.ec 2>/dev/null \
       | awk -F'\t' '$3=="canary_admit_stmt"{print $2}')
  case "${aa:-}${ab:-}" in *nostmt*) echo "FAIL admit digest degraded to the constant 'nostmt' (a=$aa b=$ab)"; fail=$((fail+1));; esac
  if [ -n "$aa" ] && [ -n "$ab" ] && [ "$aa" != "$ab" ]; then
    echo "OK   admit statement digest discriminates ($aa vs $ab)"
  else
    echo "FAIL admit statement digest does NOT discriminate (a=$aa b=$ab)"; fail=$((fail+1))
  fi
else
  echo "FAIL admit digest canary missing"; fail=$((fail+1))
fi
# NO LIVE ROW MAY CARRY THE DEGRADED DIGEST either: `admit:nostmt` means the
# enclosing declaration was not found, i.e. an admitted obligation that LOOKS
# pinned and is not.
# DEGENERATE-DIGEST BLOCKLIST (run 13c).  The run-13 kill shot was a digest that
# was CONSTANT -- sha256(".") -- and it passed because the only check greps for
# the literal string `nostmt`.  A digest is worthless the moment it stops
# depending on the declaration, and the cheapest general guard is to compute what
# the degenerate inputs hash to and refuse to see any of them in a live row.
deg=""
for lit in '' '.' ' ' '}' '{ }'; do
  d=$(printf '%s' "$lit" | sha256sum | cut -c1-12)
  grep -q ":$d" "$TMPD/cone_now.tsv" 2>/dev/null && deg="$deg $d"
done
if [ -n "$deg" ]; then
  echo "FAIL live row(s) carry a DEGENERATE digest (hash of an empty/trivial span):$deg"
  grep -E ":($(echo $deg | tr ' ' '|'))" "$TMPD/cone_now.tsv" | sed 's/^/       /' | head -5
  fail=$((fail+1))
else
  echo "OK   no live row carries a degenerate digest"
fi
if grep -qE 'admit:(nostmt|ambig[0-9]+)' "$TMPD/cone_now.tsv" 2>/dev/null; then
  echo "FAIL a live admit row carries a CONTENT-INDEPENDENT digest (nostmt/ambig) -- that assumption is unpinned"; fail=$((fail+1))
else
  echo "OK   no live admit row degraded to 'nostmt'"
fi

ran=""
echo "### PHASE 3 — CONTROLS (polarity AND declared reason)"
while IFS=$'\t' read -r path kind reason; do
  case "$path" in ''|\#*) continue;; esac
  # No whitelist: this file contains ONLY split controls, and silently
  # skipping unrecognised rows would hide future controls from the gate.
  if [ ! -f "$path" ]; then echo "FAIL control missing: $path"; fail=$((fail+1)); continue; fi
  case "$kind" in MUST-PASS|MUST-FAIL) ;; *) echo "FAIL control $path: bad polarity '$kind'"; fail=$((fail+1)); continue;; esac
  if [ "$kind" = MUST-FAIL ] && { [ -z "${reason:-}" ] || [ "$reason" = "-" ]; }; then
    echo "FAIL control $path: MUST-FAIL with no declared reason (would accept any failure)"; fail=$((fail+1)); continue
  fi
  ran="$ran $path"
  out=$(easycrypt compile $INC "$path" 2>&1); rc=$?
  msg=$(printf '%s' "$out" | tr '\r' '\n' | grep -a '^\[critical\]' | head -1)
  if [ $rc -eq 0 ]; then
    if [ "$kind" = MUST-PASS ]; then echo "OK   control $path (MUST-PASS)"
    else echo "FAIL control $path: MUST-FAIL but COMPILED"; fail=$((fail+1)); fi
  else
    if [ "$kind" = MUST-PASS ]; then echo "FAIL control $path: MUST-PASS but failed -- $msg"; fail=$((fail+1))
    elif printf '%s' "$msg" | grep -qF "$reason"; then
      echo "OK   control $path (MUST-FAIL, rejected for the DECLARED reason)"
    else
      # POLARITY ALONE IS NOT ENOUGH.  A control that fails for a parse error,
      # a missing require, or a typo would otherwise score as OK while proving
      # nothing -- the gate would be theatre.  Added 2026-08-01 after this exact
      # defect was found in the first version of this script.
      echo "FAIL control $path: failed for the WRONG reason"; fail=$((fail+1))
      echo "       declared: $reason"
      echo "       actual  : $msg"
    fi
  fi
done < cert-controls-split.tsv
# FAIL-OPEN GUARD: with an empty or truncated control file the loop runs zero
# controls and the gate still reaches GREEN. Require the expected count.
n_ctl=$(printf '%s\n' $ran | sort -u | grep -c .)
echo "controls executed (unique)=$n_ctl expected>=5"
[ "$n_ctl" -ge 5 ] || { echo "FAIL control file truncated or empty (fail-open guard)"; fail=$((fail+1)); }

# IDENTITY RE-VERIFICATION AT THE END (run 13, GPT-5.6).  The identity was
# computed ONCE, before a compile phase that runs for the better part of an
# hour, and never rechecked.  An edit made after the hash and reverted before
# the census compiles altered sources under a green receipt.  This does not
# close a determined TOCTOU race, but it does mean any edit that PERSISTS
# past the compile is caught, and it costs one second.
INPUTS_ID_END=$( { CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $ROOTS_ID 2>/dev/null \
    | sed -n 's/^#   //p' | sort -u | while read -r f; do [ -f "$f" ] && sha256sum "$f"; done
  sha256sum $CLOSURE $BASELINE $STMTS cert-controls-split.tsv $CTL_SRC $CANARY_SRC tools/cert_cone.py tools/stmt_digest.py cert_gate_split.sh 2>/dev/null; } | sha256sum | cut -c1-32)
if [ "$INPUTS_ID_END" != "$INPUTS_ID" ]; then
  echo "FAIL inputs CHANGED DURING THE RUN: start $INPUTS_ID, end $INPUTS_ID_END"
  fail=$((fail+1))
else
  echo "OK   inputs unchanged across the run ($INPUTS_ID_END)"
fi
echo "### RESULT: $([ $fail -eq 0 ] && echo GREEN || echo "RED ($fail failures)")"
exit $([ $fail -eq 0 ] && echo 0 || echo 1)
