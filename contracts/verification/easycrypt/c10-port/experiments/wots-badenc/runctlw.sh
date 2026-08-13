#!/usr/bin/env bash
# MUST-FAIL CONTROL for deployed_qwired_wotscharged_at_witness.
#
# A green anti-vacuity witness is worthless if the `apply` is not actually
# checking the module restriction set.  This makes that set UNSATISFIABLE at
# exactly the module the witness instantiates -- F must be disjoint from
# WitnessF, which WitnessF cannot satisfy -- so the apply MUST fail.
#
# Graded by REASON and SITE, not merely by failing: the expected diagnostic is a
# memory-separation violation naming WitnessF, inside the witness lemma.  A
# failure anywhere else means the control is measuring something other than what
# it claims.
set -u
cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
M="$C/_ctlw.ec"
O=experiments/wots-badenc/ctlw.out
rm -f "$O" "$M" "$C/_ctlw.eco"
sed '0,/^             -R_top,$/s//             -R_top, -WitnessF,/' \
    "$C/GprocQWiredWotsCharged.ec" > "$M"
cmp -s "$C/GprocQWiredWotsCharged.ec" "$M" && { echo "FAIL: mutation was a NO-OP" > "$O"; exit 1; }
easycrypt compile -I "$B" -I "$C" "$M" > "$O" 2>&1
rc=$?
echo "__RC=$rc" >> "$O"
rm -f "$M" "$C/_ctlw.eco"
if [ "$rc" -eq 0 ]; then
  echo "### CONTROL VERDICT: BROKEN -- mutant COMPILED, the witness proves nothing" >> "$O"
else
  echo "### CONTROL VERDICT: OK -- mutant rejected" >> "$O"
fi
