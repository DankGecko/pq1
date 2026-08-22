#!/usr/bin/env bash
# MUST-FAIL CONTROLS for the defined-* census rows (bodied definitions).
#
# THE CONTROL THAT JUSTIFIES THE CHANGE is CD1: before it, redefining the FORS+C gate
# predicate to `true` moved NOTHING -- no pin, no coverage row, no census row.
set -u
cd "$(dirname "$0")/../.."
B=base-c10-split; D=cdrafts-split
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
bad=0

census () {
  local R="" n
  while read -r n; do case "$n" in ''|\#*) continue;; esac; R="$R $D/$n.ec"; done < closure-c10-split.txt
  for n in WOTS_TW_ES FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do R="$R $B/$n.ec"; done
  CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $R 2>/dev/null \
    | awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3}' | sort
}

FC=$D/FORS_C.ec
cp "$FC" "$T/fc.ec"
census > "$T/before.tsv"

# CD1 -- NEUTRALISE THE +C GATE PREDICATE.  Must move a row.
python3 - "$FC" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p,encoding='utf-8').read()
m=re.search(r'^op predC_fors \(y : out_t\) : bool =.*?\.(?=\s)', s, re.M|re.S)
open(p,'w',encoding='utf-8').write(s[:m.start()]+'op predC_fors (y : out_t) : bool = true.'+s[m.end():])
PY
census > "$T/after.tsv"; cp "$T/fc.ec" "$FC"
a=$(comm -13 "$T/before.tsv" "$T/after.tsv" | wc -l); r=$(comm -23 "$T/before.tsv" "$T/after.tsv" | wc -l)
if [ "$a" -ge 1 ] && [ "$r" -ge 1 ]; then
  echo "OK   CD1 predC_fors -> true: census moves ($r removed, $a added) -- PHASE 2 fatal"
else echo "FAIL CD1 predC_fors -> true moved nothing ($r removed, $a added)"; bad=$((bad+1)); fi

# CD2 -- A NEW BODIED DEFINITION must be an ADDED row (forcing, not just catching).
printf '\nop cd2_smuggled (z : int) : bool = z = 65536.\n' >> "$FC"
census > "$T/new.tsv"; cp "$T/fc.ec" "$FC"
a=$(comm -13 "$T/before.tsv" "$T/new.tsv" | wc -l)
[ "$a" -ge 1 ] && echo "OK   CD2 new bodied definition: $a row added -- ADDITIONS ARE FATAL" \
               || { echo "FAIL CD2 new bodied definition added no row"; bad=$((bad+1)); }

# CD3 -- NO-OP LEG.  Internal reformatting must NOT move a row, or the rule fires on
# cosmetic edits, maintainers regenerate the baseline mechanically, and the
# human-review property it exists for is destroyed.
python3 - "$FC" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p,encoding='utf-8').read()
m=re.search(r'^op predC_fors \(y : out_t\) : bool =(.*?)\.(?=\s)', s, re.M|re.S)
b=re.sub(r'(?<=\S) (?=\S)', '    ', m.group(1).strip())
open(p,'w',encoding='utf-8').write(s[:m.start()]+'op predC_fors (y : out_t) : bool =\n\n      '+b+'.'+s[m.end():])
PY
census > "$T/cos.tsv"; cp "$T/fc.ec" "$FC"
c=$(comm -3 "$T/before.tsv" "$T/cos.tsv" | wc -l)
[ "$c" -eq 0 ] && echo "OK   CD3 no-op leg: internal reformatting moves NOTHING (whitespace-immune)" \
              || { echo "FAIL CD3 no-op leg: reformatting moved $c row(s) -- churn surface"; bad=$((bad+1)); }

# CD4 -- PARAMETERISED CLONE OPERAND.  Both the operand matcher and its TERMINATOR
# required the name to sit immediately before `<-`/`<=`, so `op P i <= ...` matched
# NEITHER: the binding carried no row, AND -- worse -- it could not end its PREDECESSOR's
# value, so that predecessor's digest over-reached into it.  21 such bindings in the split
# cone.  This control edits the VALUE of a parameterised binding and asserts a row moves.
FX=base-c10-split/FL_SL_XMSS_MT_ES.ec
cp "$FX" "$T/fx.ec"
census > "$T/p_before.tsv"
python3 - "$FX" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p,encoding='utf-8').read()
# `op valid_widxvalsgp adidxswgp <= <value>` -- perturb the VALUE only
m=re.search(r'(op\s+valid_widxvalsgp\s+adidxswgp\s*<=\s*)([^,\n]*)', s)
open(p,'w',encoding='utf-8').write(s[:m.start(2)]+'(true /\\ '+m.group(2).strip()+')'+s[m.end(2):])
PY
census > "$T/p_after.tsv"; cp "$T/fx.ec" "$FX"
a=$(comm -13 "$T/p_before.tsv" "$T/p_after.tsv" | wc -l); r=$(comm -23 "$T/p_before.tsv" "$T/p_after.tsv" | wc -l)
if [ "$a" -ge 1 ] && [ "$r" -ge 1 ]; then
  echo "OK   CD4 parameterised operand value edited: census moves ($r removed, $a added)"
else
  echo "FAIL CD4 parameterised operand edit moved nothing ($r removed, $a added)"; bad=$((bad+1))
fi

echo
echo "defined-census controls: failures=$bad"
[ "$bad" -eq 0 ] && { echo "RESULT: OK"; exit 0; } || { echo "RESULT: BAD"; exit 1; }
