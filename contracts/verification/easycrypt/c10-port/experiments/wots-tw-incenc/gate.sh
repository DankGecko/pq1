set -u
cd /work
S=experiments/wots-tw-incenc/shadow
D=experiments/wots-tw-incenc/sdrafts
rm -f "$D"/*.eco
fail=0
while read -r n; do
  [ -z "$n" ] && continue
  st=$(date +%s)
  out=$(easycrypt compile -I "$S" -I "$D" "$D/$n.ec" 2>&1); rc=$?
  el=$(( $(date +%s) - st ))
  if [ "$rc" -eq 0 ]; then
    echo "OK   $n  ${el}s"
  else
    fail=$((fail+1))
    echo "FAIL $n  ${el}s  rc=$rc"
    printf '%s\n' "$out" | tr '\r' '\n' | grep -aE '[A-Za-z]{4}' | grep -vaE '^\[.\] \[' | head -4 | sed 's/^/       /'
  fi
done < "$D/../closure.txt"
echo "### GATE_FAILURES=$fail"
echo "### GATEDONE"
