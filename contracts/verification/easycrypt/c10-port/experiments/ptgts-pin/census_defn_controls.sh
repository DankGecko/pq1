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

echo
echo "defined-census controls: failures=$bad"
[ "$bad" -eq 0 ] && { echo "RESULT: OK"; exit 0; } || { echo "RESULT: BAD"; exit 1; }
