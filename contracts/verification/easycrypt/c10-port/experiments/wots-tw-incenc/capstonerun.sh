set -u
cd /work
S=experiments/wots-tw-incenc/shadow
D=experiments/wots-tw-incenc/sdrafts
out=$(easycrypt compile -I "$S" -I "$D" "$D/SphincsC10CapstoneWired.ec" 2>&1); rc=$?
echo "### CAPSTONE rc=$rc"
printf '%s\n' "$out" | tr '\r' '\n' | grep -aE '[A-Za-z]{4}' | grep -vaE '^\[.\] \[' | head -12
[ -f "$D/SphincsC10CapstoneWired.eco" ] && echo "    eco: YES" || echo "    eco: NO"
echo "### CAPDONE"
