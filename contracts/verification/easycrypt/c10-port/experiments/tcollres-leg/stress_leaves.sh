#!/usr/bin/env bash
# STRESS HARNESS for the experiment leaves.
#
# WHY. On 2026-07-28 `leaf/Proj129` FAILED inside a full-chain run and PASSED
# 5/5 standalone on an idle machine.  The goal (`8 = 2^3 by smt()`) was trivial;
# the PROOF was nondeterministic -- SMT timed out under load.  A receipt that
# green-lights under those conditions is measuring machine load, not the proof.
#
# Classifying the remaining `smt()` calls by eye is how you talk yourself into a
# conclusion.  This measures instead: compile every leaf COLD, repeatedly, while
# the box is deliberately loaded, and count failures per leaf.
#
# Usage: stress_leaves.sh [ROUNDS] [BURNERS]
set -u
cd /work
ROUNDS=${1:-5}
BURNERS=${2:-4}
L=experiments/tcollres-leg
INC="-I base-c10 -I cdrafts -I $L"
LEAVES="EncoderBridge Proj129 Extraction Composition PremiseReduction Identification ThCWidth"

# CPU load only -- deliberately NOT concurrent easycrypt runs, which would race
# on the same .eco files and produce corruption rather than the timing pressure
# we are trying to reproduce.
pids=""
for i in $(seq 1 "$BURNERS"); do
  ( while :; do :; done ) & pids="$pids $!"
done
trap 'kill $pids 2>/dev/null' EXIT
echo "### stress: ROUNDS=$ROUNDS BURNERS=$BURNERS  (nproc=$(nproc 2>/dev/null || echo ?))"

declare -A fails
for n in $LEAVES; do fails[$n]=0; done

for r in $(seq 1 "$ROUNDS"); do
  for n in $LEAVES; do
    rm -f "$L/$n.eco"
    if ! easycrypt compile $INC "$L/$n.ec" >/dev/null 2>&1; then
      fails[$n]=$(( ${fails[$n]} + 1 ))
      echo "  round $r: FAIL $n"
    fi
  done
done

echo "### RESULTS ($ROUNDS rounds under load)"
tot=0
for n in $LEAVES; do
  echo "  $n: ${fails[$n]}/$ROUNDS failures"
  tot=$(( tot + ${fails[$n]} ))
done
echo "### TOTAL_FAILURES=$tot"
echo STRESSDONE
