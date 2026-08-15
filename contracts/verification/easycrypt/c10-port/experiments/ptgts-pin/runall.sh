#!/usr/bin/env bash
# Full receipt for experiments/ptgts-pin/.  Every target is compiled from
# scratch (its own .eco removed first) and its EXPECTED verdict is committed
# here, so a control that flips is a FAILURE of this script, not a silent pass.
#   PASS  = must compile (rc 0 AND a fresh .eco)
#   FAIL  = must NOT compile (rc != 0 AND no .eco)
set -u
cd "$(dirname "$0")/../.."
R=experiments/ptgts-pin
declare -a T=(
  "PASS PTgtsPin"
  "PASS PTgtsPinCapstone"
  "PASS controls/CtlPinIsLive"
  "PASS controls/CtlCapstonePinPlusOne"
  "FAIL controls/CtlPtgtsMinusOne"
  "FAIL controls/CtlPtgtsPlusOneIsLeast"
  "FAIL controls/CtlCValueMinusOne"
  "FAIL controls/CtlUsageCapAsPin"
  "FAIL controls/CtlPinDerivesFalse"
  "FAIL controls/CtlCapstonePinOffByOne"
  "FAIL controls/CtlCapstoneNoPin"
  "FAIL controls/CtlSmtCannotEvaluatePow"
)
bad=0
for row in "${T[@]}"; do
  want=${row%% *}; f=${row#* }
  bash "$R/ec.sh" "$f" >/dev/null 2>&1
  line=$(tr '\r' '\n' < "$R/$f.out" | grep -E '__RC=|__ECO=' | tr '\n' ' ')
  rc=$(printf '%s' "$line" | grep -oE '__RC=[0-9]+' | cut -d= -f2)
  eco=$(printf '%s' "$line" | grep -oE '__ECO=[a-zA-Z]+' | cut -d= -f2)
  if [ "$want" = PASS ]; then
    if [ "$rc" = 0 ] && [ "$eco" = yes ]; then v=OK; else v="BROKEN"; bad=$((bad+1)); fi
  else
    if [ "$rc" != 0 ] && [ "$eco" = NO ]; then v=OK; else v="BROKEN"; bad=$((bad+1)); fi
  fi
  why=$(tr '\r' '\n' < "$R/$f.out" | grep -a '^\[critical\]' | head -1 | cut -c1-140)
  printf '%-6s %-6s %-42s %s\n' "$v" "$want" "$f" "$line"
  [ -n "$why" ] && printf '       %s\n' "$why"
done
echo "### STATEMENT IDENTITY (capstone corollary + its three capstone controls)"
if bash "$R/check_stmt_identity.sh"; then :; else bad=$((bad+1)); fi
echo "### ADMIT/AXIOM SWEEP (code only, comments excluded)"
grep -rnE '^[^(]*\b(admit|admitted|axiom)\b' $R/*.ec $R/controls/*.ec | grep -vE '\(\*|\*\)' | sed 's/^/  /'
echo "  admits+axioms in code: $(grep -rcE '^[[:space:]]*(admit|admitted|axiom)\b' $R/*.ec $R/controls/*.ec | awk -F: '{s+=$2} END{print s+0}')"
echo "### RESULT: $bad broken"
exit $((bad>0))
