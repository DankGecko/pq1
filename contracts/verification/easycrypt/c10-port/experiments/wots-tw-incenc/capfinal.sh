set -u
cd /work
S=experiments/wots-tw-incenc/shadow
D=experiments/wots-tw-incenc/sdrafts
rm -f "$D"/*.eco
echo "sdrafts eco before: $(ls $D/*.eco 2>/dev/null | wc -l)"
start=$(date +%s)
out=$(easycrypt compile -I "$S" -I "$D" "$D/SphincsC10CapstoneWired.ec" 2>&1); rc=$?
end=$(date +%s)
echo "### CAPSTONE rc=$rc elapsed=$((end-start))s"
printf '%s\n' "$out" | tr '\r' '\n' | grep -aE '[A-Za-z]{4}' | grep -vaE '^\[.\] \[' | head -6
echo "### FINDONE"
