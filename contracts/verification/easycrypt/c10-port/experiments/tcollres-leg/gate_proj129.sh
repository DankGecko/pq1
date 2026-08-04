#!/usr/bin/env bash
# Gate for Proj129.ec.  Runs INSIDE the container.
#
# Mutations are applied to a COPY under /tmp, never to the tracked source.  Two
# controls were voided earlier this session by mutating a tracked file (once by a
# restore racing a concurrent compile, once by a container-uid permission denial
# that silently skipped the mutation while the control still printed a verdict).
# Working on a copy makes both failure modes impossible, and it means a crashed
# run can never leave a poisoned file behind.
#
# EVERY control prints a MUTATED_* witness proving the mutation actually landed.
# A control whose mutation did not apply is reported INVALID, not passed.
#
# Positive controls (theorems IN the file -- stronger than compile-failure tests):
#   negctl_129th_bit_is_NOT_free    -- without sum=205, low-128 does NOT determine
#   negctl_witness_sums_differ_by_4 -- the mechanism (the flip costs exactly 4)
#   c10_target_sum_reachable        -- the sum-205 surface is NONEMPTY (anti-vacuity)
#
# Negative controls (mutations that MUST break the build):
#   A  inject `lemma : false`                  -> rc!=0
#   B  c10_pow43 exponent 43 -> 42             -> rc!=0  (arithmetic really checked)
#   C  drop the two sum hypotheses, SAME ARITY -> rc!=0  (constant-sum load-bearing)
set -u
cd /work
SRC=experiments/tcollres-leg/Proj129.ec
W=/tmp/p129gate
INC="-I base-c10 -I cdrafts -I experiments/tcollres-leg -I $W"
rm -rf "$W"; mkdir -p "$W"
cp "$SRC" "$W/Proj129.ec"
F="$W/Proj129.ec"
cp "$F" "$W/orig.ec"

comp() { rm -f "$W/Proj129.eco"; easycrypt compile $INC "$F" >/dev/null 2>&1; echo $?; }

echo "### BASELINE (compiled from the copy; identical bytes to the tracked file)"
echo "COPY_IDENTICAL=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
echo "BASE_RC=$(comp)   (must be 0)"

perl -0pe '1 while s/\(\*(?:(?!\(\*|\*\)).)*?\*\)//gs' "$SRC" > "$W/ns.ec"
adm=$(grep -oE '(^|;|\||\+|-|\*|\]|first|last|by|=>|\s)\s*admit(ted)?\b' "$W/ns.ec" | wc -l | tr -d ' ')
ax=$(grep -cE '(^|\n)\s*axiom\s+[A-Za-z_]' "$W/ns.ec" | tr -d ' ')
echo "ADMITS=$adm  AXIOM_DECLS_IN_FILE=$ax   (both must be 0)"

echo "### AXIOM CLOSURE (this file + its requires; EC has no Print Assumptions)"
for f in experiments/tcollres-leg/Proj129.ec experiments/tcollres-leg/EncoderBridge.ec; do
  perl -0pe '1 while s/\(\*(?:(?!\(\*|\*\)).)*?\*\)//gs' "$f" \
    | grep -nE '^\s*axiom\s+[A-Za-z_]' | sed "s|^|  ${f##*/}:|"
done

echo "### NEGATIVE CONTROLS"

# A -- inject a false lemma
cp "$W/orig.ec" "$F"
printf '\nlemma _negctl_A : false.\nproof. smt(). qed.\n' >> "$F"
mA=$(grep -c '_negctl_A' "$F")
echo "MUTATED_A=$mA   (must be 1, else INVALID)"
echo "NEGCTL_A_RC=$(comp)   (must be NONZERO)"

# B -- break the exponent arithmetic
cp "$W/orig.ec" "$F"
sed -i 's/^lemma c10_pow43 : 8 \^ 43 = 2 \^ 129\./lemma c10_pow43 : 8 ^ 42 = 2 ^ 129./' "$F"
mB=$(grep -c 'c10_pow43 : 8 \^ 42' "$F")
echo "MUTATED_B=$mB   (must be 1, else INVALID)"
echo "NEGCTL_B_RC=$(comp)   (must be NONZERO)"

# C -- remove the constant-sum hypotheses from c10_low128_determines, KEEPING
#      ARITY so the intro pattern still matches and any failure is SEMANTIC
#      rather than a tactic-arity artifact.
cp "$W/orig.ec" "$F"
perl -0pi -e 's/  => dsum \(int2dig 43 x\) = 205\n  => dsum \(int2dig 43 y\) = 205\n  => x %% 2 \^ 128 = y %% 2 \^ 128\n  => x = y\./  => 0 <= x\n  => 0 <= y\n  => x %% 2 ^ 128 = y %% 2 ^ 128\n  => x = y./s' "$F"
mC=$(grep -c '^  => 0 <= x$' "$F")
echo "MUTATED_C=$mC   (must be 1, else INVALID)"
echo "NEGCTL_C_RC=$(comp)   (must be NONZERO)"

# final: tracked source untouched throughout
echo "### TRACKED SOURCE"
echo "SRC_UNTOUCHED=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
cp "$W/orig.ec" "$F"
echo "FINAL_RC=$(comp)   (must be 0)"
echo GATEDONE
