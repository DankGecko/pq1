#!/usr/bin/env bash
# Sweep every proof body in WOTS_TW_ES.ec: keep ONE, gut the rest, compile.
# Records which proof bodies actually FAIL under the gated game.
#
# WHY. EasyCrypt reports ONE error per run, so the naive loop discovers failures
# serially at 2-4 min each. With gut.py a run is ~15s, so the COMPLETE failure
# list costs ~20 min instead of hours -- and knowing the list up front turns an
# open-ended grind into a countable task.
#
# The gutted files are THROWAWAY (full of admits by construction). Nothing here
# is a receipt; fixes are applied to the real file and re-verified there.
set -u
cd /work
SRC=base-c10-fork/WOTS_TW_ES.ec
python3 - "$SRC" > /tmp/bodies.txt <<'PY'
import sys, re
lines = open(sys.argv[1]).read().split("\n")
i, n = 0, len(lines)
while i < n:
    if re.match(r"^\s*proof\.\s*$", lines[i]):
        j = i + 1
        while j < n and not re.match(r"^\s*(qed|abort)\.\s*$", lines[j]):
            j += 1
        if j < n:
            # find the statement name above
            k, name = i - 1, "?"
            while k >= 0 and k > i - 40:
                m = re.match(r"^\s*(lemma|equiv|hoare|local lemma|local equiv)\s+([A-Za-z0-9_']+)", lines[k])
                if m:
                    name = m.group(2); break
                k -= 1
            print(f"{i+1} {j+1} {name}")
        i = j + 1
        continue
    i += 1
PY
tot=$(wc -l < /tmp/bodies.txt)
echo "### $tot proof bodies to sweep"
fails=0
while read -r lo hi name; do
  python3 base-c10-fork/gut.py "$SRC" base-c10-fork/_fast.ec "$lo" "$hi" 2>/dev/null
  if easycrypt compile -I base-c10-fork base-c10-fork/_fast.ec >/dev/null 2>&1; then :; else
    fails=$((fails+1)); echo "FAIL $name  (lines $lo-$hi)"
  fi
done < /tmp/bodies.txt
echo "### FAILING_BODIES=$fails / $tot"
echo SWEEPDONE
