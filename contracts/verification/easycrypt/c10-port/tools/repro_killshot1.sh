#!/usr/bin/env bash
# repro_killshot1.sh -- REPRODUCE run-10 kill shot 1 from a clean checkout.
#
# WHY THIS FILE EXISTS.  Claims-log section 36 said the kill shot was "measured,
# not argued" and cited `_mut_base/WOTS_TW_ES.ec` -- a GITIGNORED scratch copy.
# A receipt whose artifact is not in the tree cannot be reproduced by a reader,
# which is exactly the defect section 25 condemns, committed in the sentence
# that claimed measurement.  Found by adversarial review, run 11 (Kimi K3).
#
# WHAT IT DEMONSTRATES.  Replacing ONE PREMISE of the single admitted lemma
#
#   base-c10-split/WOTS_TW_ES.ec:1509
#     !has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
#   ->  true
#
# (with the proof adapted to a single `admit.`) turns the assumption into
# "a chain preimage exists whenever P m /\ P m' /\ m <> m'" -- almost certainly
# FALSE for the real scheme -- while, BEFORE the run-10b fix, the census row was
# byte-identical (`admit  nhchwcoll_hchwpre_msg`) and all 49 statement pins were
# unchanged.  The whole 22-file closure still compiles.
#
# EXPECTED OUTPUT (run 10 measurement, r2026.02):
#   census row moves      admit:01a2cfed95f4 -> admit:8f1e32428803   [post-fix]
#   whole closure compiles: 22/22 OK
#
# Usage:  bash tools/repro_killshot1.sh            # census evidence only (seconds)
#         bash tools/repro_killshot1.sh --compile  # + full closure compile (~20 min)
set -u
export LC_ALL=C PYTHONDONTWRITEBYTECODE=1
WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT
cp -a base-c10-split "$WORK/base" && rm -f "$WORK"/base/*.eco

python3 - "$WORK/base/WOTS_TW_ES.ec" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
old = """  => !has_chwcoll ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'
  => has_chwpre ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof.
move=> hPm hPmp hne; apply nhchwcoll_hchwpre => //.
admit."""
new = """  => true
  => has_chwpre ps ad (encode_msgWOTS m) (encode_msgWOTS m') sig sig'.
proof.
move=> hPm hPmp hne _.
admit."""
assert s.count(old) == 1, 'the admitted lemma no longer has the shape this receipt describes'
open(p, 'w').write(s.replace(old, new))
print('mutation applied: premise 4 -> true, proof adapted to a single admit.')
PY

echo "--- census row, pristine vs mutated ---"
for d in base-c10-split "$WORK/base"; do
  printf '  %-24s ' "$(basename "$d")"
  CERT_CONE_DIRS="$d" python3 tools/cert_cone.py "$d/WOTS_TW_ES.ec" 2>/dev/null \
    | awk -F'\t' '$3=="nhchwcoll_hchwpre_msg"{print $2}'
done
echo "  (identical kinds => the census is blind; different => run-10b fix is live)"

if [ "${1:-}" = "--compile" ]; then
  cp -a cdrafts-split "$WORK/cdrafts" && rm -f "$WORK"/cdrafts/*.eco
  echo "--- compiling the closure against the mutated base ---"
  for n in WOTS_TW_ES FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do
    easycrypt compile -I "$WORK/base" "$WORK/base/$n.ec" >/dev/null 2>&1 \
      && echo "OK   base/$n" || echo "FAIL base/$n"
  done
  while read -r n; do
    case "$n" in ''|\#*) continue;; esac
    easycrypt compile -I "$WORK/base" -I "$WORK/cdrafts" "$WORK/cdrafts/$n.ec" >/dev/null 2>&1 \
      && echo "OK   $n" || echo "FAIL $n"
  done < closure-c10-split.txt
fi
