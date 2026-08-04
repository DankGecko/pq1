#!/usr/bin/env bash
# Gate for Identification.ec.  Same discipline as the other gates: mutations run
# on a container-side COPY, never the tracked source, and every control prints a
# MUTATED_* witness so a mutation that fails to apply is reported INVALID rather
# than silently "passing".
#
#   A  inject `lemma : false`                                   -> rc!=0
#   B  enc_c10_into_code: drop the surface hypothesis at SAME ARITY
#      (`dsum (enc_c10 d) = 205`  ->  `0 <= d`)                 -> rc!=0
#      The digit map only lands in the target-sum code ON the surface.
#   C  digit_map_violates_global_two_encodings: SWAP the domination direction
#      in the second conjunct                                   -> rc!=0
#      This is the sharpest control in the file. The counterexample pair (1,0)
#      is deliberately ASYMMETRIC: no digit of enc_c10 1 is below enc_c10 0
#      (all-zero), but a digit of enc_c10 0 IS below enc_c10 1. If the swapped
#      form also compiled, the "witness" would be proving nothing about
#      incomparability and the whole obstruction claim would be empty.
set -u
cd /work
SRC=experiments/tcollres-leg/Identification.ec
W=/tmp/idgate
INC="-I base-c10 -I cdrafts -I experiments/tcollres-leg -I $W"
rm -rf "$W"; mkdir -p "$W"
cp "$SRC" "$W/Identification.ec"
F="$W/Identification.ec"
cp "$F" "$W/orig.ec"

comp() { rm -f "$W/Identification.eco"; easycrypt compile $INC "$F" >/dev/null 2>&1; echo $?; }

echo "### BASELINE"
echo "COPY_IDENTICAL=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
echo "BASE_RC=$(comp)   (must be 0)"

perl -0pe '1 while s/\(\*(?:(?!\(\*|\*\)).)*?\*\)//gs' "$SRC" > "$W/ns.ec"
adm=$(grep -oE '(^|;|\||\+|-|\*|\]|first|last|by|=>|\s)\s*admit(ted)?\b' "$W/ns.ec" | wc -l | tr -d ' ')
ax=$(grep -cE '(^|\n)\s*axiom\s+[A-Za-z_]' "$W/ns.ec" | tr -d ' ')
echo "ADMITS=$adm  AXIOM_DECLS_IN_FILE=$ax   (both must be 0)"

echo "### AXIOM CLOSURE (inherited; EC has no Print Assumptions)"
for f in experiments/tcollres-leg/Identification.ec experiments/tcollres-leg/Proj129.ec \
         experiments/tcollres-leg/EncoderBridge.ec cdrafts/IncEnc.ec; do
  perl -0pe '1 while s/\(\*(?:(?!\(\*|\*\)).)*?\*\)//gs' "$f" \
    | grep -nE '^\s*axiom\s+[A-Za-z_]' | sed "s|^|  ${f##*/}:|"
done

echo "### NEGATIVE CONTROLS"

cp "$W/orig.ec" "$F"
printf '\nlemma _negctl_A : false.\nproof. smt(). qed.\n' >> "$F"
echo "MUTATED_A=$(grep -c '_negctl_A' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_A_RC=$(comp)   (must be NONZERO)"

cp "$W/orig.ec" "$F"
perl -0pi -e 's/lemma enc_c10_into_code \(d : int\) :\n  wd = 8 => dsum \(enc_c10 d\) = 205 => c10_code \(enc_c10 d\)\./lemma enc_c10_into_code (d : int) :\n  wd = 8 => 0 <= d => c10_code (enc_c10 d)./s' "$F"
echo "MUTATED_B=$(grep -c 'wd = 8 => 0 <= d => c10_code' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_B_RC=$(comp)   (must be NONZERO)"

cp "$W/orig.ec" "$F"
perl -0pi -e 's/\/\\ ! \(exists \(i : int\), 0 <= i < 43 \/\\ nth 0 \(enc_c10 1\) i < nth 0 \(enc_c10 0\) i\)\./\/\\ ! (exists (i : int), 0 <= i < 43 \/\\ nth 0 (enc_c10 0) i < nth 0 (enc_c10 1) i)./s' "$F"
echo "MUTATED_C=$(grep -c 'nth 0 (enc_c10 0) i < nth 0 (enc_c10 1) i' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_C_RC=$(comp)   (must be NONZERO)"

echo "### TRACKED SOURCE"
echo "SRC_UNTOUCHED=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
cp "$W/orig.ec" "$F"
echo "FINAL_RC=$(comp)   (must be 0)"
echo GATEDONE
