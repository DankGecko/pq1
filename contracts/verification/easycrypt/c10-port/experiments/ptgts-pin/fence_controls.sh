#!/usr/bin/env bash
# MUST-FAIL CONTROLS for the POLICY-CAP QUARANTINE fence (tools/policy_cap_fence.py).
#
# Each control DELETES OR ADDS INFORMATION in exactly one direction and asserts the
# fence fails FOR THE DECLARED REASON -- not merely that it fails.  A control graded
# only on exit status would pass if the fence errored for an unrelated reason, which
# is how a control of mine passed vacuously on 2026-08-19 (see pin_discrimination.sh).
set -u
cd "$(dirname "$0")/../.."
F=cdrafts-split/C10DeployedScope.ec
VICTIM=cdrafts-split/C10DeployedGeometry.ec     # an unrelated certified file
T=$(mktemp -d); trap 'cp "$T/scope.ec" "$F"; cp "$T/victim.ec" "$VICTIM"; rm -rf "$T"' EXIT
cp "$F" "$T/scope.ec"; cp "$VICTIM" "$T/victim.ec"
bad=0

check () { # name  expected-substring  -- runs fence, greps its output
  local name="$1" want="$2"
  local out; out=$(python3 tools/policy_cap_fence.py 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then
    echo "FAIL control $name: fence PASSED but should have failed"; bad=$((bad+1))
  elif printf '%s' "$out" | grep -q "$want"; then
    echo "OK   control $name: failed for the DECLARED reason ($want)"
  else
    echo "FAIL control $name: failed for the WRONG reason"; printf '%s\n' "$out" | sed 's/^/       /'
    bad=$((bad+1))
  fi
  cp "$T/scope.ec" "$F"; cp "$T/victim.ec" "$VICTIM"
}

echo "### baseline must be GREEN first (a fence that never passes proves nothing)"
if python3 tools/policy_cap_fence.py >/dev/null 2>&1; then echo "OK   baseline GREEN"
else echo "FAIL baseline is not green -- controls are meaningless"; bad=$((bad+1)); fi

# C0 -- ANTI-VACUITY.  The first version of this fence printed "OK quarantine
# intact" with rc=0 against a manifest gutted to comments only: want_decls and
# want_reqs both came back empty, so Q2 and Q4 silently skipped.  A control suite
# that only ever ADDS things would never have found that -- this leg REMOVES the
# manifest's contents, which is the direction that makes a checker vacuous.
cp cert-quarantine-split.tsv "$T/qman.tsv"
grep '^#' "$T/qman.tsv" > cert-quarantine-split.tsv
out=$(python3 tools/policy_cap_fence.py 2>&1); rc=$?
cp "$T/qman.tsv" cert-quarantine-split.tsv
if [ $rc -eq 0 ]; then
  echo "FAIL control C0 gutted-manifest (Q0): fence PASSED VACUOUSLY"; bad=$((bad+1))
elif printf '%s' "$out" | grep -q "Q0 manifest"; then
  echo "OK   control C0 gutted-manifest (Q0): failed for the DECLARED reason (Q0 manifest)"
else
  echo "FAIL control C0 gutted-manifest: wrong reason"; printf '%s\n' "$out" | sed 's/^/       /'; bad=$((bad+1))
fi

printf '\nrequire import C10DeployedScope.\n' >> "$VICTIM"
check "C1 inbound-require (Q1)" "Q1 inbound require"

sed -i 's/^require import WOTS_C_Real\.$/require import WOTS_C_Real. require import List./' "$F"
check "C2 require-set drift (Q2)" "Q2 require set changed"

printf '\nsection FOO.\ndeclare axiom cap_le : c <= c10_q_s.\nend section FOO.\n' >> "$F"
check "C3 section-hypothesis (Q3)" "Q3 forbidden construct"

printf '\nlemma smuggled_in : c10_q_s <= c10_q_s.\nproof. trivial. qed.\n' >> "$F"
check "C4 declaration added (Q4)" "Q4 DECLARATION ADDED"

printf '\nop sneaky_cap : int = 65536.\n' >> "$VICTIM"
check "C5 magnitude elsewhere (Q5)" "Q5 deployment magnitude"

echo
echo "fence controls: failures=$bad"
[ "$bad" -eq 0 ] && { echo "RESULT: OK"; exit 0; } || { echo "RESULT: BAD"; exit 1; }
