#!/usr/bin/env bash
# Gate for ThCWidth.ec.  Mutations on a container-side COPY, never the tracked
# source; every control prints a MUTATED_* witness so a mutation that fails to
# apply is reported INVALID rather than silently "passing".
#
#   A  inject `lemma : false`                              -> rc!=0
#   B  width_129_not_8n: 129 -> 128.  128 IS 8*16, so the negated existential
#      becomes FALSE.  Checks the arithmetic is genuinely verified rather than
#      smt waving through a shape it likes.                -> rc!=0
#   C  predC_sum's constant 205 -> 302.  Max digit sum is 43*7 = 301, so 302 is
#      UNREACHABLE and `predC_sum_inhabited` becomes false. This is the control
#      that matters: it shows the non-degeneracy result is about a REACHABLE
#      target, not a shape that would hold for any constant.  -> rc!=0
set -u
cd /work
SRC=experiments/tcollres-leg/ThCWidth.ec
W=/tmp/twgate
INC="-I base-c10 -I cdrafts -I experiments/tcollres-leg -I $W"
rm -rf "$W"; mkdir -p "$W"
cp "$SRC" "$W/ThCWidth.ec"
F="$W/ThCWidth.ec"
cp "$F" "$W/orig.ec"

comp() { rm -f "$W/ThCWidth.eco"; easycrypt compile $INC "$F" >/dev/null 2>&1; echo $?; }

echo "### BASELINE"
echo "COPY_IDENTICAL=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
echo "BASE_RC=$(comp)   (must be 0)"

perl -0pe '1 while s/\(\*(?:(?!\(\*|\*\)).)*?\*\)//gs' "$SRC" > "$W/ns.ec"
adm=$(grep -oE '(^|;|\||\+|-|\*|\]|first|last|by|=>|\s)\s*admit(ted)?\b' "$W/ns.ec" | wc -l | tr -d ' ')
ax=$(grep -cE '(^|\n)\s*axiom\s+[A-Za-z_]' "$W/ns.ec" | tr -d ' ')
echo "ADMITS=$adm  AXIOM_DECLS_IN_FILE=$ax   (both must be 0)"

echo "### NEGATIVE CONTROLS"

cp "$W/orig.ec" "$F"
printf '\nlemma _negctl_A : false.\nproof. smt(). qed.\n' >> "$F"
echo "MUTATED_A=$(grep -c '_negctl_A' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_A_RC=$(comp)   (must be NONZERO)"

cp "$W/orig.ec" "$F"
sed -i 's/^lemma width_129_not_8n : ! (exists (k : int), 8 \* k = 129)\./lemma width_129_not_8n : ! (exists (k : int), 8 * k = 128)./' "$F"
echo "MUTATED_B=$(grep -c '8 \* k = 128' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_B_RC=$(comp)   (must be NONZERO)"

cp "$W/orig.ec" "$F"
sed -i 's/^op predC_sum (d : int) : bool = dsum (int2dig 43 d) = 205\./op predC_sum (d : int) : bool = dsum (int2dig 43 d) = 302./' "$F"
echo "MUTATED_C=$(grep -c 'int2dig 43 d) = 302' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_C_RC=$(comp)   (must be NONZERO)"

echo "### TRACKED SOURCE"
echo "SRC_UNTOUCHED=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
cp "$W/orig.ec" "$F"
echo "FINAL_RC=$(comp)   (must be 0)"
echo GATEDONE
