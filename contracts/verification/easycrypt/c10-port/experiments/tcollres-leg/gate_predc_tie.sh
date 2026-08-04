#!/usr/bin/env bash
# Gate for the predC TIE installed in cdrafts/WOTS_C_Real.ec.
#
# This gate answers one question: DID THE TIE CHANGE ANYTHING?
# A chain edit that compiles proves nothing on its own -- an edit that added a
# comment would also compile.  The receipt is that a lemma which was NOT STATABLE
# before the tie is provable after it, and STOPS being provable if the tie is
# removed.
#
#   A  inject `lemma : false`                                  -> rc!=0
#   B  revert predC to the ABSTRACT declaration it had before, keeping
#      `predC_iff_sum`                                          -> rc!=0
#      This is the control that matters. Before the tie, predC was
#      `op predC : dgstblock -> bool.` with no axiom anywhere, so
#      `predC d <=> cw_sum (encode_msgWOTS d) = target_sum` was UNPROVABLE.
#      If B still compiled, the "tie" would be decoration.
#
# Mutations run on a container-side COPY; the tracked source is never written.
set -u
cd /work
SRC=cdrafts/WOTS_C_Real.ec
W=/tmp/tiegate
INC="-I base-c10 -I cdrafts -I $W"
rm -rf "$W"; mkdir -p "$W"
cp "$SRC" "$W/WOTS_C_Real.ec"
F="$W/WOTS_C_Real.ec"
cp "$F" "$W/orig.ec"

comp() { rm -f "$W/WOTS_C_Real.eco"; easycrypt compile $INC "$F" >/dev/null 2>&1; echo $?; }

echo "### BASELINE"
echo "COPY_IDENTICAL=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
echo "BASE_RC=$(comp)   (must be 0)"

perl -0pe '1 while s/\(\*(?:(?!\(\*|\*\)).)*?\*\)//gs' "$SRC" > "$W/ns.ec"
adm=$(grep -oE '(^|;|\||\+|-|\*|\]|first|last|by|=>|\s)\s*admit(ted)?\b' "$W/ns.ec" | wc -l | tr -d ' ')
ax=$(grep -cE '(^|\n)\s*axiom\s+[A-Za-z_]' "$W/ns.ec" | tr -d ' ')
echo "ADMITS=$adm  AXIOM_DECLS_IN_FILE=$ax   (both must be 0 -- the tie is a"
echo "                                        DEFINITION, so it adds neither)"

echo "### NEGATIVE CONTROLS"

cp "$W/orig.ec" "$F"
printf '\nlemma _negctl_A : false.\nproof. smt(). qed.\n' >> "$F"
echo "MUTATED_A=$(grep -c '_negctl_A' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_A_RC=$(comp)   (must be NONZERO)"

# B: put predC back the way it was -- abstract, unconstrained.
cp "$W/orig.ec" "$F"
perl -0pi -e 's/^op predC \(d : dgstblock\) : bool = cw_sum \(encode_msgWOTS d\) = target_sum\.$/op predC : dgstblock -> bool./m' "$F"
echo "MUTATED_B=$(grep -c '^op predC : dgstblock -> bool\.$' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_B_RC=$(comp)   (must be NONZERO -- predC_iff_sum must become unprovable)"

# C: put target_sum back to a FREE constant.  `targetSumReachable` must then
#    become unprovable -- reachability is a theorem ONLY because target_sum is
#    defined as a value the encoder attains.  If C still compiled, the lemma
#    would be proving something it does not depend on.
cp "$W/orig.ec" "$F"
perl -0pi -e 's/^op target_sum : int = cw_sum \(encode_msgWOTS tgt_witness\)\.$/const target_sum : int./m' "$F"
echo "MUTATED_C=$(grep -c '^const target_sum : int\.$' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_C_RC=$(comp)   (must be NONZERO -- targetSumReachable must go unprovable)"

echo "### TRACKED SOURCE"
echo "SRC_UNTOUCHED=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
cp "$W/orig.ec" "$F"
echo "FINAL_RC=$(comp)   (must be 0)"
echo GATEDONE
