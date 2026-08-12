set -u
cd /work
S=experiments/wots-tw-incenc/shadow_neg
D=experiments/wots-tw-incenc/sdrafts
rm -f "$D"/*.eco
out=$(easycrypt compile -I "$S" -I "$D" "$D/SphincsC10CapstoneWired.ec" 2>&1); rc=$?
echo "### NEGCTL capstone rc=$rc  (MUST be nonzero if shadow is really used)"
printf '%s\n' "$out" | tr '\r' '\n' | grep -aE '[A-Za-z]{4}' | grep -vaE '^\[.\] \[' | head -5
echo "### NEGDONE"
