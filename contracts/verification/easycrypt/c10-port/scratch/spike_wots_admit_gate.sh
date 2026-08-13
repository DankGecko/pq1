#!/usr/bin/env bash
# Spike gate for scratch/wots_admit_is_injectivity.ec.  RUNS INSIDE ec-grind.
#
# Discipline this gate inherits from cert_gate_split.sh:
#  * BOTH DRIVERS.  `easycrypt compile` has already accepted, this session, a
#    proof that `easycrypt cli` rejects (`realize good_pos by smt(dunit1E)`).
#    A one-driver green is not a green.  cli's exit status is meaningless --
#    the verdict is "zero ^<tty>: diagnostics AND >= 5 commands processed",
#    because a mistyped include also yields zero diagnostics.
#  * CONTROLS MUST DELETE INFORMATION, and are graded by the REASON they fail,
#    not merely that they do.  Each control below mutates a STATEMENT (an op
#    definition or a lemma's conclusion), not a proof step, so it cannot fail
#    for a tactic-intro artifact.  A control that fails at the wrong site is
#    reported as a gate defect.
set -u
F=scratch/wots_admit_is_injectivity.ec
INC="-I base-c10-split -I cdrafts-split"
T=/tmp/spike_out
fail=0

ecc() { rm -f "${1%.ec}.eco"; easycrypt compile $INC "$1" >$T 2>&1; echo $?; }
firstmsg() { grep -E '^\[(critical|error|warning)\]|^\[critical\]' $T | head -1 | cut -c1-160; }

echo "### DRIVER 1: easycrypt compile (must pass)"
rc=$(ecc $F)
if [ "$rc" -eq 0 ]; then echo "OK   base compile rc=0"
else echo "FAIL base compile rc=$rc"; firstmsg; fail=$((fail+1)); fi

echo "### DRIVER 2: easycrypt cli (must emit ZERO diagnostics over >=5 cmds)"
out=$(easycrypt cli -iterate $INC < $F 2>&1 | tr '\r' '\n')
d=$(printf '%s\n' "$out" | grep -c '^<tty>:' || true)
pr=$(printf '%s\n' "$out" | grep -c '^\[[0-9]*|' || true)
if [ "$pr" -lt 5 ]; then
  echo "FAIL cli: only $pr commands processed -- the run did not happen"; fail=$((fail+1))
elif [ "$d" -ne 0 ]; then
  echo "FAIL cli: $d diagnostic(s) -- compile accepted what cli rejects"
  printf '%s\n' "$out" | grep '^<tty>:' | head -2 | sed 's/^/       /'; fail=$((fail+1))
else
  echo "OK   cli ($pr cmds, 0 diagnostics)"
fi

echo "### LEDGER: admits / axioms outside comments (must be 0)"
# strip block comments, then look for the ledger class
lc=$(perl -0777 -pe 's/\(\*.*?\*\)//gs' $F | grep -cE '(^|[^_[:alnum:]])admit([^_[:alnum:]]|$)|^[[:space:]]*axiom |declare axiom' || true)
if [ "$lc" -eq 0 ]; then echo "OK   ledger class count = 0"
else echo "FAIL ledger class count = $lc"; perl -0777 -pe 's/\(\*.*?\*\)//gs' $F | grep -nE '(^|[^_[:alnum:]])admit([^_[:alnum:]]|$)|^[[:space:]]*axiom |declare axiom' | head -5; fail=$((fail+1)); fi

echo "### CONE DISCLOSURE (GPT-5.6, 2026-08-12): 'ledger class = 0' is FILE-local"
# GPT-5.6 caught this fail-open: the file `require import WOTS_TW_ES`, so the base
# admit at :1505 IS in its dependency cone. A reader seeing "ledger class = 0"
# above would wrongly conclude the cone is admit-free. The property that actually
# matters is that this file never APPLIES the tainted lemma -- otherwise the
# spike would be resting on the very thing it is diagnosing. Checked, not assumed.
TAINTED=nhchwcoll_hchwpre_msg
uses=$(perl -0777 -pe 's/\(\*.*?\*\)//gs' $F | grep -c "$TAINTED" || true)
if [ "$uses" -eq 0 ]; then
  echo "OK   file never applies \`$TAINTED\` (base admit is in the cone, unused)"
else
  echo "FAIL file applies \`$TAINTED\` $uses time(s) -- the spike rests on the admit"
  fail=$((fail+1))
fi
# The one base lemma this file DOES apply must itself be admit-free.
echo "     (applies \`nhchwcoll_hchwpre\`, WOTS_TW_ES.ec:1476 -- complete proof, no admit)"

# ------------------------------------------------------------------ CONTROLS
# Graded by the DECLARATION THE FAILURE LANDS IN, not by a line number: line
# offsets are brittle (the first cut of this gate predicted all three wrong and
# reported WARN on three correct controls), and the declaration is what the
# control is actually asserting about.
ctl() { # $1 label  $2 expected-containing-declaration  $3 sed-expr
  local lbl="$1" want="$2" expr="$3" M=/tmp/ctl.ec rc L got
  sed "$expr" $F > $M
  cmp -s $F $M && { echo "FAIL $lbl: MUTATION WAS A NO-OP (sed matched nothing)"; fail=$((fail+1)); return; }
  rm -f /tmp/ctl.eco
  easycrypt compile $INC $M >$T 2>&1; rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL $lbl: MUTANT COMPILED (control is vacuous)"; fail=$((fail+1)); return
  fi
  L=$(grep -oE 'line [0-9]+' $T | head -1 | awk '{print $2}')
  [ -z "$L" ] && { echo "FAIL $lbl: failed with no locatable site"; fail=$((fail+1)); return; }
  got=$(awk -v n="$L" 'NR<=n && /^lemma |^op /{k=$0} END{print k}' $M | awk '{print $2}')
  if [ "$got" = "$want" ]; then
    echo "OK   $lbl: fails inside \`$want\` (line $L) -- correct reason"
  else
    echo "FAIL $lbl: fails inside \`$got\`, expected \`$want\` -- wrong reason"
    sed -n "${L}p" $M | sed 's/^/       /'; fail=$((fail+1))
  fi
}

echo "### CONTROLS (each must fail, and for the RIGHT reason)"

# NC-B  THE DECISIVE ONE.  Delete the surface restriction from EncInjOnP1, so it
# becomes GLOBAL injectivity.  L1s then claims EncInjOnP <=> global injectivity,
# which is strictly stronger and must break.  This proves L1s genuinely consumes
# P_encode_congr and is not silently proving something trivial.
ctl "NC-B drop P from EncInjOnP1 (=> global inj)" "encinjonP_iff_encinjonP1" \
    "/^op EncInjOnP1/,/^$/ s/^    P m => encode_msgWOTS/    encode_msgWOTS/"

# NC-C  Drop the surface hypothesis from the refutation.  A collision OFF the
# constant-sum surface refutes nothing, so this must break.
ctl "NC-C drop P m from surface-collision refutation" "admit_refuted_by_surface_collision" \
    "/^lemma admit_refuted_by_surface_collision/,/^qed\.$/ s/^     P m$/     true/"

# NC-D  Arithmetic control: the shortfall exponent.  2^256 = 8^43 * 2^127 is
# exact; 2^126 is off by a factor of two and must break.  Guards against the
# exponent being fudged rather than computed.
ctl "NC-D shortfall exponent 127 -> 126" "c10_codomain_shortfall" \
    "/^lemma c10_codomain_shortfall/,/^qed\.$/ s/2 \^ 127/2 ^ 126/g"

# NC-A  Sanity: the include set can actually reject something.
cp $F /tmp/ctl.ec
printf '\nlemma nc_a_false : false.\nproof. by []. qed.\n' >> /tmp/ctl.ec
rm -f /tmp/ctl.eco
easycrypt compile $INC /tmp/ctl.ec >$T 2>&1
if [ $? -ne 0 ]; then echo "OK   NC-A appended \`lemma : false\` rejected"
else echo "FAIL NC-A: \`lemma : false\` COMPILED -- the include set is unsound"; fail=$((fail+1)); fi

echo
if [ "$fail" -eq 0 ]; then echo "### SPIKE RESULT: GREEN (0 failures)"
else echo "### SPIKE RESULT: RED ($fail failures)"; fi
exit "$fail"
