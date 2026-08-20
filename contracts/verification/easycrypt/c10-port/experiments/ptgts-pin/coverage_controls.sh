#!/usr/bin/env bash
# MUST-FAIL CONTROLS for TOTAL STATEMENT COVERAGE (PHASE 1c pins + PHASE 1h coverage).
#
# THE CONTROL THAT JUSTIFIES THE WHOLE EXERCISE is CV1: adding a NEW lemma to a
# certified file must FAIL.  Pinning 896 statements without that would have been a lot
# of work that did not close the hole it was aimed at -- PHASE 1c iterates the MANIFEST,
# so an unpinned statement is invisible to it.
set -u
cd "$(dirname "$0")/../.."
VICTIM=cdrafts-split/C10DeployedGeometry.ec
T=$(mktemp -d); trap 'cp "$T/v.ec" "$VICTIM"; cp "$T/m.tsv" cert-statements-split.tsv; rm -rf "$T"' EXIT
cp "$VICTIM" "$T/v.ec"; cp cert-statements-split.tsv "$T/m.tsv"
bad=0

expect_fail () { # name  want-substring  cmd...
  local name="$1" want="$2"; shift 2
  local out rc; out=$("$@" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then echo "FAIL control $name: PASSED but should have failed"; bad=$((bad+1))
  elif printf '%s' "$out" | grep -q "$want"; then echo "OK   control $name: failed for the DECLARED reason ($want)"
  else echo "FAIL control $name: WRONG reason"; printf '%s\n' "$out" | head -4 | sed 's/^/       /'; bad=$((bad+1)); fi
}

echo "### baselines must be GREEN first"
python3 tools/stmt_coverage.py >/dev/null 2>&1 && echo "OK   coverage baseline GREEN" || { echo "FAIL coverage baseline not green"; bad=$((bad+1)); }

# CV1 -- THE POINT OF THE EXERCISE: a NEW statement must not be able to appear unpinned.
printf '\nlemma smuggled_premise : 1 = 1.\nproof. trivial. qed.\n' >> "$VICTIM"
expect_fail "CV1 new lemma appears (coverage)" "UNPINNED statement" python3 tools/stmt_coverage.py
cp "$T/v.ec" "$VICTIM"

# CV2 -- a pin row deleted: the statement it covered becomes unpinned.
grep -v 'C10DeployedGeometry.ec::c10_pow8' "$T/m.tsv" > cert-statements-split.tsv
expect_fail "CV2 pin row deleted (coverage)" "UNPINNED statement" python3 tools/stmt_coverage.py
cp "$T/m.tsv" cert-statements-split.tsv

# CV3 -- EXPECT_STMTS drift: a statement REMOVED keeps every remaining pin valid, so
# only the committed total catches it.  This is the direction a coverage-only check
# would miss.
python3 - "$VICTIM" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p,encoding='utf-8').read()
m=re.search(r'^lemma\s+c10_pow8\b.*?^qed\.\s*$', s, re.M|re.S)
open(p,'w',encoding='utf-8').write(s[:m.start()]+s[m.end():])
PY
expect_fail "CV3 statement removed (EXPECT_STMTS)" "EXPECT_STMTS" python3 tools/stmt_coverage.py
cp "$T/v.ec" "$VICTIM"

# CV4 -- gutted manifest: coverage must scream, not shrug.
grep '^#' "$T/m.tsv" > cert-statements-split.tsv
expect_fail "CV4 gutted manifest (coverage)" "UNPINNED statement" python3 tools/stmt_coverage.py
cp "$T/m.tsv" cert-statements-split.tsv

# CV5 -- THE PRED BLOCKER.  A pred body is pure logical content usable as a lemma
# HYPOTHESIS.  Before 2026-08-20 it was pinnable by NEITHER digest path, so appending
# a conjunct installed that hypothesis in every statement naming the pred while every
# digest stayed identical -- the attack PHASE 1g exists to stop, landing through a
# surface no phase watched.  This control asserts the pred pin MOVES and, crucially,
# that the statements naming it do NOT (they mention only the token), which is what
# makes the pred pin load-bearing rather than redundant.
TP=cdrafts-split/FORS_C_TreePort.ec
cp "$TP" "$T/tp.ec"
before_pred=$(python3 tools/stmt_digest.py "op:$TP::brk_structural" | cut -f2)
before_stmt=$(python3 tools/stmt_digest.py "$TP::fors_c_tree_port" | cut -f2)
python3 - "$TP" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p,encoding='utf-8').read()
m=re.search(r'^pred\s+brk_structural\b.*?\.(?=\s)', s, re.M|re.S)
s=s[:m.end()-1]+' /\\ 65536 = 65536'+s[m.end()-1:]
open(p,'w',encoding='utf-8').write(s)
PY
after_pred=$(python3 tools/stmt_digest.py "op:$TP::brk_structural" | cut -f2)
after_stmt=$(python3 tools/stmt_digest.py "$TP::fors_c_tree_port" | cut -f2)
cp "$T/tp.ec" "$TP"
if [ "$before_pred" = "$after_pred" ]; then
  echo "FAIL control CV5 pred-body edit: pred pin did NOT move -- body is unwatched"; bad=$((bad+1))
elif [ "$before_stmt" != "$after_stmt" ]; then
  echo "OK   control CV5 pred-body edit: pred pin moved (and so did the statement)"
else
  echo "OK   control CV5 pred-body edit: pred pin MOVED while the statement digest did NOT"
  echo "       (that gap is exactly why the pred row is load-bearing)"
fi

# CV6 -- MID-LINE DECLARATION.  EasyCrypt is whitespace-insensitive:
# `qed. lemma hidden : 1 = 1. proof. trivial. qed.` on one line is legal and saved.
# A line-anchored scan neither counts it nor reports it unpinned.
printf 'lemma cv6_visible : 1 = 1.\nproof. trivial. qed. lemma cv6_hidden : 2 = 2.\nproof. trivial. qed.\n' >> "$VICTIM"
expect_fail "CV6 mid-line lemma (coverage)" "UNPINNED statement" python3 tools/stmt_coverage.py
cp "$T/v.ec" "$VICTIM"

echo
echo "coverage controls: failures=$bad"
[ "$bad" -eq 0 ] && { echo "RESULT: OK"; exit 0; } || { echo "RESULT: BAD"; exit 1; }
