#!/usr/bin/env bash
# ===========================================================================
# cert_gate_fork.sh — THE FORK CERTIFICATION GATE.
#
# Built 2026-07-30 after two independent adversarial reviews (GPT-5.6, Kimi K3)
# converged on the same recommendation: `wire_test_fork.sh` proves each file
# TYPECHECKS, and nothing more.  Three things it cannot see, all with concrete
# instances found that day:
#
#   1. DEPENDENCY-CONE TAINT.  cdrafts-fork/XmssmtCC_All.ec reports 0 admits, yet
#      at :8907 applies MEUFGCMA_WOTSTWESNPRF, whose proof consumes the ADMITTED
#      nhchwcoll_hchwpre_msg (base-c10-fork/WOTS_TW_ES.ec:1444).  EasyCrypt has no
#      `#print axioms` and `require` does not re-verify, so the build is silent.
#   2. `declare axiom`.  A `^axiom` grep misses section-level hypotheses; an
#      earlier hand census of mine missed all 6 in the cone.
#   3. VACUITY.  cdrafts-fork/LeafWiring.ec passed a full wire run while
#      PROVABLY vacuous.  A green compile is not evidence of content.
#
# PHASES
#   1  TARGETS   — every base + closure file compiled as an EXPLICIT target
#                  (required: `require` does not re-verify).
#   2  CONE      — transitive require-cone census of admit/axiom/declare-axiom,
#                  diffed against cert-baseline.tsv.  ADDITIONS ARE FATAL.
#   3  CONTROLS  — must-pass controls must compile; must-fail controls must fail
#                  *FOR THE DECLARED REASON*.  A must-fail control that fails on
#                  an arity slip is testing nothing while reading green — this
#                  actually happened (canary3 vs the added N2 premise).
#
# Exit status is the failure count.  (wire_test_fork.sh once ended on `echo`, so
# its status was always 0; do not reintroduce that.)
# ===========================================================================
set -u
# LOCALE PINNING (added 2026-08-02).  Same defect as cert_gate_split.sh:31 --
# INPUTS_SHA256 hashes `sha256sum` lines in `sort -u` order, and glibc collation
# is locale-dependent, so the identity line was an identity of (tree, locale).
# The container happens to run POSIX, so its recorded hashes are unchanged by
# this pin; the host now reproduces them instead of contradicting them.
export LC_ALL=C
cd /work || { echo "FAIL cannot cd to /work"; exit 1; }
B=base-c10-fork; D=cdrafts-fork; L=experiments/tcollres-leg
# ASSIGNED 2026-08-02.  INPUTS_SHA256 and the identity block reference these and
# NOTHING set them: under `set -u` the script died at the first use, printing
# nothing and running no phase.  A previous "fix" targeted a line pattern that
# does not exist in this file, so the substitution silently did nothing -- and I
# then "verified" it by computing the hash in a HAND-BUILT command with the
# variables set inline, which is not the script.  Verifying a fix by running
# something that is not the fix is how this survived two rounds.
CLOSURE=closure-c10-fork.txt; BASELINE=cert-baseline.tsv; STMTS=cert-statements-fork.tsv
INC="-I $B -I $D -I $L"
TMPD=$(mktemp -d) || { echo 'FAIL mktemp'; exit 1; }
trap 'rm -rf "$TMPD"' EXIT
# Expected inventory sizes, COMMITTED. A guard that recomputes its expectation
# from the file it is checking cannot detect truncation of that file.
EXPECT_PINS=9
EXPECT_CTLS=12
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
# covered the control MANIFEST and not the control .ec FILES nor the PHASE 2b/2c
# fixtures, so scratch/vac_probe_full.ec -- the two-sided vacuity control that is
# the only mechanism to have caught a real end-to-end attack -- could be rewritten
# to still fail for its declared reason while probing almost nothing: zero census
# delta, zero identity delta, gate green.  Found by two independent legs, run 13.
# AND cert-controls.tsv ITSELF, which PHASE 3 reads and nothing hashed.
CTL_SRC=$(awk -F'\t' '!/^#/ && NF{print $1}' cert-controls.tsv 2>/dev/null | sort -u | tr '\n' ' ')
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
# THE IDENTITY MUST RESOLVE THE SAME DIRECTORIES THE GATE COMPILES WITH
# (fixed 2026-08-02, run 12, Kimi K3).  :49 compiles with THREE include dirs
# (-I $B -I $D -I $L) and PHASE 2 censuses with three (cert_cone.py's default),
# but this line hashed TWO.  EasyCrypt resolves a later -I ahead of an earlier
# one -- ahead even of the target file's own directory -- so a file planted in
# experiments/tcollres-leg/ shadows a same-named fork-cone theory in every
# PHASE 1 and PHASE 3 compile while the identity hashes the pristine copy and
# still matches cert-identity.tsv.  Seven fork-cone files carry zero census
# rows (BinaryTrees, MerkleTrees, C10DeployedGeometry, GFailCharged,
# SphincsC10CapstoneCharged, SphincsC10Content, XmssmtCCCharged), and two of
# those are required directly by the charged capstone, so for them the path
# flip moves no row either.  The split gate never had this hole because its
# compile set and hashed set are the same two directories.
INPUTS_ID=$( { CERT_CONE_DIRS="base-c10-fork,cdrafts-fork,experiments/tcollres-leg" python3 tools/cert_cone.py $ROOTS_ID 2>/dev/null \
    | sed -n 's/^#   //p' | sort -u | while read -r f; do [ -f "$f" ] && sha256sum "$f"; done
  sha256sum $CLOSURE $BASELINE $STMTS cert-controls.tsv $CTL_SRC $CANARY_SRC tools/cert_cone.py tools/stmt_digest.py cert_gate_fork.sh 2>/dev/null; } | sha256sum | cut -c1-32)
echo "### INPUTS_SHA256 $INPUTS_ID"
# AND NOW COMPARE IT.  This line was printed and checked by nothing: an identity
# receipt that no run can fail on is decoration.  The expected value lives in
# cert-identity.tsv, deliberately OUTSIDE the hashed set -- storing it inside
# would reproduce the self-reference claims-log section 35 records.
want_id=$(awk -F'\t' '!/^#/ && $1=="fork"{print $2}' cert-identity.tsv 2>/dev/null)
if [ -z "${want_id:-}" ]; then
  echo "FAIL cert-identity.tsv missing or has no fork row -- identity unpinned"; fail=$((fail+1))
elif [ "$INPUTS_ID" != "$want_id" ]; then
  echo "FAIL INPUTS_SHA256 DRIFT: committed $want_id, computed $INPUTS_ID"
  echo "     a certified input or the certification machinery changed;"
  echo "     re-baseline deliberately and update cert-identity.tsv in the same commit"
  fail=$((fail+1))
else
  echo "OK   INPUTS_SHA256 matches the committed identity"
fi
echo "### TOOLCHAIN $(easycrypt cli </dev/null 2>&1 | grep -ao 'GIT hash: [^ ]*' | head -1 || echo UNKNOWN)"
# PROVER INVENTORY + INCLUDE-PATH AMBIGUITY GUARD (run 10) -- rationale in
# cert_gate_split.sh.  The receipt recorded the EasyCrypt git hash and nothing
# about which provers discharged the smt goals.
# 2>&1, NOT 2>/dev/null: EasyCrypt prints `known provers:` on STDERR, so the
# first version of this line hashed the EMPTY STRING and printed
# `e3b0c44298fc1c14 0 configurations` -- the SAME empty-input defect run 8
# found in the identity hash, committed again by me two hours later.  A
# receipt field must be checked for its VALUE, never for its presence.
echo "### PROVERS $(easycrypt config 2>&1 | sed -n 's/^known provers: //p' | head -1 | sha256sum | cut -c1-16) $(easycrypt config 2>&1 | sed -n 's/^known provers: //p' | head -1 | tr ',' '\n' | grep -c .) configurations"
dupes=0
for d in $B $D $L; do
  [ -d "$d" ] || continue
  n=$(ls "$d" 2>/dev/null | grep -E '\.(ec|eca)$' | sed -E 's/\.(ec|eca)$//' | sort | uniq -d | grep -c . || true)
  [ "${n:-0}" -eq 0 ] || { echo "FAIL $d has $n theory name(s) present as BOTH .ec and .eca"; dupes=$((dupes+n)); }
done
[ "$dupes" -eq 0 ] && echo "OK   no dual-extension theory names on the include path" || fail=$((fail+dupes))

# --- cache invalidation: EasyCrypt does NOT invalidate a dependent's .eco when a
#     required theory changes, so a stale object can green over edited source.
# CONCURRENCY GUARD (run 10).  A gate that shares its directories with another
# compile has no receipt: the other process writes .eco underneath it.  This
# is not hypothetical -- stopping a gate task on the host killed the `docker
# exec` client but NOT the in-container script, whose orphaned compile kept
# writing for 13 minutes into the tree the next run was purging.  The purge
# verification caught it (ECO_REMAINING=34); this stops it one step earlier.
others=$(ps -eo cmd 2>/dev/null | grep -c "[e]asycrypt compile.*base-c10-fork" || true)
[ "${others:-0}" -eq 0 ] || { echo "FAIL another compile is running against base-c10-fork ($others) -- refusing to produce a racy receipt"; exit 3; }
purged=$(find $B $D $L -name '*.eco' -print -delete 2>/dev/null | wc -l)
# VERIFY the purge and cover the data-driven control inventory too (run 10):
# the hardcoded dir list cannot see a control added elsewhere, and a purge that
# FAILS is exactly the stale-cache green it exists to prevent.
# PURGE AND CHECK MUST HAVE THE SAME SCOPE (fixed 2026-08-02, second defect in
# this guard).  The purge was a GLOB and the check a recursive FIND, so 33
# objects in scratch SUBDIRECTORIES failed a gate that never tried to delete
# them.  Both are recursive now.
# CORRECTED run 13.  Run 12 said "cert-controls-fork.tsv DOES NOT EXIST -- the
# fork gate's controls are inline".  The first half is true and the conclusion is
# FALSE: the fork gate reads cert-controls.tsv (no -fork suffix) at PHASE 3.  I
# checked for the wrong filename and drew a conclusion from its absence, then
# wrote that conclusion into claims-log section 37.  The purge below now reads
# the file the gate actually uses.
for d in $(awk -F'\t' '!/^#/ && NF{print $1}' cert-controls.tsv 2>/dev/null | xargs -r -n1 dirname | sort -u) scratch; do
  [ -d "$d" ] && find "$d" -name '*.eco' -delete 2>/dev/null
done
eco_left=$(find $B $D $L scratch -name '*.eco' 2>/dev/null | grep -c . || true)
echo "### ECO_REMAINING=$eco_left"
[ "${eco_left:-0}" -eq 0 ] || { echo "FAIL stale .eco survived the purge ($eco_left)"; fail=$((fail+1)); }
echo "### ECO_PURGED=$purged"

# ---------------------------------------------------------------------------
echo "### PHASE 1 — TARGETS"
# ---------------------------------------------------------------------------
for n in WOTS_TW_ES FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do
  st=$(date +%s)
  if easycrypt compile $INC $B/$n.ec >/dev/null 2>&1
    then echo "OK   base/$n $(( $(date +%s)-st ))s"
    else echo "FAIL base/$n"; fail=$((fail+1)); fi
done
n_seen=0
while read -r n || [ -n "$n" ]; do
  case "$n" in ''|\#*) continue;; esac
  n_seen=$((n_seen+1)); st=$(date +%s)
  if out=$(easycrypt compile $INC $D/$n.ec 2>&1)
    then echo "OK   $n $(( $(date +%s)-st ))s"
    else echo "FAIL $n"; fail=$((fail+1))
         printf '%s\n' "$out" | tr '\r' '\n' | grep -aE '^\[critical\]' | head -1 | sed 's/^/       /'
  fi
done < closure-c10-fork.txt
n_exp=$(grep -cve '^[[:space:]]*$' -e '^#' closure-c10-fork.txt)
echo "### CLOSURE_COMPILED=$n_seen EXPECTED=$n_exp"
[ "$n_seen" -eq "$n_exp" ] || { echo "FAIL closure truncated"; fail=$((fail+1)); }

# ---------------------------------------------------------------------------
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

echo "### PHASE 1b/1c — NAMED RESULTS + STATEMENT/DEFINITION DIGESTS"
# Added 2026-08-01.  Commit 9f3466a claimed "FORK-GATE PARITY" while porting only
# the empty-census guard and the scratch purge; the fork gate had NEITHER 1b nor
# 1c, so its capstones could be weakened to `true. trivial.` and stay GREEN.
# That commit message was false; this is the actual port.
if [ -f cert-statements-fork.tsv ]; then
  n_stmt=0
  while IFS=$'\t' read -r key want || [ -n "${key:-}" ]; do
    case "${key:-}" in ''|\#*) continue;; esac
    n_stmt=$((n_stmt+1))
    got=$(python3 tools/stmt_digest.py "$key" | cut -f2)
    # AN UNRESOLVABLE PIN MUST FAIL, NOT AGREE WITH ITSELF (run 13d) -- see
    # cert_gate_split.sh for the instance that produced this guard.
    case "$got" in
      NOT-FOUND|AMBIGUOUS-*|ambig*|nostmt)
        echo "FAIL statement pin does not resolve: $key -> $got"; fail=$((fail+1)); continue;;
    esac
    if [ "$got" = "$want" ]; then echo "OK   pinned: $key"
    else echo "FAIL CHANGED: $key"; echo "       want $want"; echo "       got  $got"; fail=$((fail+1)); fi
  done < cert-statements-fork.tsv
  exp_stmt=$EXPECT_PINS   # COMMITTED CONSTANT, not recomputed from the manifest
  echo "statements pinned=$n_stmt expected=$exp_stmt (manifest rows)"
  [ "${n_stmt:-0}" -eq "${exp_stmt:-0}" ] && [ "${exp_stmt:-0}" -ge 1 ] || { echo "FAIL fork statement pin file truncated"; fail=$((fail+1)); }
else
  echo "FAIL cert-statements-fork.tsv missing -- fork statements unpinned"; fail=$((fail+1))
fi

echo "### PHASE 2 — CONE CENSUS vs cert-baseline.tsv"
# ---------------------------------------------------------------------------
# EMPTY-CENSUS FAIL-OPEN GUARD (added 2026-08-01, parity with the split gate):
# a crashed cert_cone.py under `2>/dev/null` yields an EMPTY census, hence zero
# "new items", hence GREEN with zero coverage.  The split gate fixed this at its
# :62; the fork gate had the identical hole.
# RE-SORT AFTER `uniq -c` (added 2026-08-04, run 23; same fix in the split gate).
# `sort | uniq -c` sorts by KEY then prefixes a COUNT, so the output is not
# sorted by WHOLE LINE: for keys a<b with counts 19 and 1 it emits "19<TAB>a"
# before "1<TAB>b", while "1<TAB>b" < "19<TAB>a".  `comm` requires whole-line
# sorted input and warns on the live baselines.  I could NOT construct a case
# where it produced a wrong added/removed count -- latent fragility, not a
# demonstrated defect -- but a spurious warning here would mask a real one.
python3 tools/cert_cone.py 2>/dev/null | grep -v '^#' | grep -v '^$' \
  | awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3}' | sort | uniq -c | sed 's/^ *//' | sort > "$TMPD/cone_now.tsv"
if [ ! -s "$TMPD/cone_now.tsv" ]; then echo "FAIL cone census produced nothing"; fail=$((fail+1)); fi
grep -v '^#' cert-baseline.tsv | grep -v '^[[:space:]]*$' \
  | awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3}' | sort | uniq -c | sed 's/^ *//' | sort > "$TMPD/cone_base.tsv"

echo "### CONE keys now=$(wc -l < "$TMPD/cone_now.tsv") baseline=$(wc -l < "$TMPD/cone_base.tsv") | ROWS now=$(awk '{s+=$1} END{print s+0}' "$TMPD/cone_now.tsv") baseline=$(awk '{s+=$1} END{print s+0}' "$TMPD/cone_base.tsv")"
# TWO CLASSES, REPORTED SEPARATELY (run 10) -- see cert_gate_split.sh for the why.
awk '{k=$3; sub(/:.*/,"",k); n[k]+=$1}
     END{ led=n["admit"]+n["axiom"]+n["declare-axiom"]+n["refined-const"]+n["clone-discharge"]+n["op-annotation"]+n["clone-obligation"];
          par=n["abstract-const"]+n["abstract-op"]+n["abstract-type"];
          bind=n["operand"]+n["rename"];
          mean=n["module"]+n["module-type"];
          printf "###   ledger=%d  parameters=%d  bindings=%d  meaning=%d  total=%d\n", led, par, bind, mean, led+par+bind+mean }' "$TMPD/cone_now.tsv"
newitems=$(comm -23 "$TMPD/cone_now.tsv" "$TMPD/cone_base.tsv")
goneitems=$(comm -13 "$TMPD/cone_now.tsv" "$TMPD/cone_base.tsv")
if [ -n "$newitems" ]; then
  echo "FAIL NEW ASSUMPTIONS IN THE CONE (not in baseline):"
  printf '%s\n' "$newitems" | sed 's/^/       + /'
  fail=$((fail+1))
else
  echo "OK   no new admits/axioms in the cone"
fi
if [ -n "$goneitems" ]; then
  echo "FAIL cone census SHRANK -- baseline entries no longer in the cone"; fail=$((fail+1))
  printf '%s\n' "$goneitems" | sed 's/^/       - /'
fi
echo "### CONE_ADMITS=$(grep -cP '\tadmit(:[0-9a-f]+)?\t' "$TMPD/cone_now.tsv" || true)"

# ---------------------------------------------------------------------------
echo "### PHASE 2b — CENSUS REGRESSION CANARY (admitted.)"
if [ -f scratch/CANARY_gate_admitted.ec ]; then
  cres_f=$(CERT_CONE_DIRS="scratch" python3 tools/cert_cone.py scratch/CANARY_gate_admitted.ec 2>/dev/null \
           | grep -v '^#' | awk -F'\t' '$2 ~ /^admit/' | grep -c . )
  if [ "${cres_f:-0}" -ge 1 ]; then echo "OK   census detects 'admitted.' (canary caught)"
  else echo "FAIL census MISSED 'admitted.'"; fail=$((fail+1)); fi
else echo "FAIL census regression canary missing"; fail=$((fail+1)); fi


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

echo "### PHASE 3 — CONTROLS (polarity AND reason)"
# ---------------------------------------------------------------------------
# path <TAB> MUST-PASS|MUST-FAIL <TAB> required substring of the failure output
ran_f=""
while IFS=$'\t' read -r path pol want; do
  case "${path:-}" in ''|\#*) continue;; esac
  case "${pol:-}" in MUST-PASS|MUST-FAIL) ;; *) echo "FAIL control $path: bad polarity '${pol:-}'"; fail=$((fail+1)); continue;; esac
  if [ ! -f "$path" ]; then echo "FAIL control missing: $path"; fail=$((fail+1)); continue; fi
  ran_f="$ran_f $path"
  rm -f "${path%.ec}.eco"
  out=$(easycrypt compile $INC -I scratch "$path" 2>&1); rc=$?
  msg=$(printf '%s\n' "$out" | tr '\r' '\n' | grep -aE '^\[critical\]' | head -1)
  if [ "$pol" = "MUST-PASS" ]; then
    if [ $rc -eq 0 ]; then echo "OK   pass-control $path"
    else echo "FAIL pass-control $path rc=$rc"; echo "       $msg"; fail=$((fail+1)); fi
  else
    if [ $rc -eq 0 ]; then
      echo "FAIL fail-control $path COMPILED — this is the regression it exists to catch"
      fail=$((fail+1))
    elif [ -z "${want:-}" ] || [ "$want" = "-" ]; then
      # grep -qF "" matches ANY failure: an empty declared reason accepted
      # everything.  Guarded 2026-08-02 (parity with the split gate).
      echo "FAIL control $path: MUST-FAIL with no declared reason"; fail=$((fail+1))
    elif printf '%s' "$msg" | grep -qF "$want"; then
      echo "OK   fail-control $path (rejected for the declared reason)"
    else
      echo "FAIL fail-control $path failed for the WRONG REASON — it is testing nothing"
      echo "       want: $want"
      echo "       got : $msg"
      fail=$((fail+1))
    fi
  fi
done < cert-controls.tsv
# Fail-open guard (parity with the split gate): an empty or truncated control
# file ran ZERO controls and still reached exit 0.
n_ctl_f=$(printf '%s
' $ran_f | sort -u | grep -c . )
exp_ctl_f=$EXPECT_CTLS
echo "controls executed (unique)=$n_ctl_f expected=$exp_ctl_f"
[ "$n_ctl_f" -eq "$exp_ctl_f" ] || { echo "FAIL fork control file truncated or rows skipped"; fail=$((fail+1)); }

# IDENTITY RE-VERIFICATION AT THE END (run 13, GPT-5.6).  The identity was
# computed ONCE, before a compile phase that runs for the better part of an
# hour, and never rechecked.  An edit made after the hash and reverted before
# the census compiles altered sources under a green receipt.  This does not
# close a determined TOCTOU race, but it does mean any edit that PERSISTS
# past the compile is caught, and it costs one second.
INPUTS_ID_END=$( { CERT_CONE_DIRS="base-c10-fork,cdrafts-fork,experiments/tcollres-leg" python3 tools/cert_cone.py $ROOTS_ID 2>/dev/null \
    | sed -n 's/^#   //p' | sort -u | while read -r f; do [ -f "$f" ] && sha256sum "$f"; done
  sha256sum $CLOSURE $BASELINE $STMTS cert-controls.tsv $CTL_SRC $CANARY_SRC tools/cert_cone.py tools/stmt_digest.py cert_gate_fork.sh 2>/dev/null; } | sha256sum | cut -c1-32)
if [ "$INPUTS_ID_END" != "$INPUTS_ID" ]; then
  echo "FAIL inputs CHANGED DURING THE RUN: start $INPUTS_ID, end $INPUTS_ID_END"
  fail=$((fail+1))
else
  echo "OK   inputs unchanged across the run ($INPUTS_ID_END)"
fi
echo "### CERT_FAILURES=$fail"
echo CERTGATEDONE
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
