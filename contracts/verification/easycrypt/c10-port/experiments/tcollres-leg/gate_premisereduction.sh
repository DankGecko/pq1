#!/usr/bin/env bash
# Gate for PremiseReduction.ec.  Same discipline as gate_proj129.sh: mutations
# are applied to a container-side COPY, never the tracked source, and every
# control prints a MUTATED_* witness so a mutation that fails to apply is
# reported INVALID rather than silently "passing".
#
# The controls here are chosen to preserve ARITY, so a failure is SEMANTIC and
# not a tactic-intro artifact.  Each swaps one hypothesis for a DIFFERENT op of
# the same shape rather than deleting it.
#
#   A  inject `lemma : false`                                      -> rc!=0
#   B  thc_determines_from_bridge: EncodeBridge -> EncMsgInj       -> rc!=0
#      (injectivity of encode_msgWOTS does NOT give the factoring)
#   C  encinj_from_bridge_and_image_inj: EncMsgInjOnThCImage
#                                     -> ThCDeterminesCodeword     -> rc!=0
#      (the CONVERSE direction does not give EncInj -- this is the control that
#       shows the reduction is not secretly trivial, i.e. that EncInj genuinely
#       costs injectivity ON TOP OF the bridge the chain already carries)
set -u
cd /work
SRC=experiments/tcollres-leg/PremiseReduction.ec
W=/tmp/prgate
INC="-I base-c10 -I cdrafts -I experiments/tcollres-leg -I $W"
rm -rf "$W"; mkdir -p "$W"
cp "$SRC" "$W/PremiseReduction.ec"
F="$W/PremiseReduction.ec"
cp "$F" "$W/orig.ec"

comp() { rm -f "$W/PremiseReduction.eco"; easycrypt compile $INC "$F" >/dev/null 2>&1; echo $?; }

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
sed -i 's/^lemma thc_determines_from_bridge : EncodeBridge => ThCDeterminesCodeword\./lemma thc_determines_from_bridge : EncMsgInj => ThCDeterminesCodeword./' "$F"
echo "MUTATED_B=$(grep -c 'thc_determines_from_bridge : EncMsgInj' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_B_RC=$(comp)   (must be NONZERO)"

cp "$W/orig.ec" "$F"
perl -0pi -e 's/lemma encinj_from_bridge_and_image_inj :\n  EncodeBridge => EncMsgInjOnThCImage => EncInj\./lemma encinj_from_bridge_and_image_inj :\n  EncodeBridge => ThCDeterminesCodeword => EncInj./s' "$F"
echo "MUTATED_C=$(grep -c 'EncodeBridge => ThCDeterminesCodeword => EncInj' "$F")   (must be 1, else INVALID)"
echo "NEGCTL_C_RC=$(comp)   (must be NONZERO)"

echo "### TRACKED SOURCE"
echo "SRC_UNTOUCHED=$(cmp -s "$SRC" "$W/orig.ec" && echo yes || echo NO)"
cp "$W/orig.ec" "$F"
echo "FINAL_RC=$(comp)   (must be 0)"
echo GATEDONE
