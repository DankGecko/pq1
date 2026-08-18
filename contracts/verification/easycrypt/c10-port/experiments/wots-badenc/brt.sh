set -u; cd /work
O=experiments/wots-badenc/bridge_timeout.out
rm -f "$O" cdrafts-split/WOTS_C_Bridge.eco
t0=$(date +%s)
easycrypt compile -timeout 120 -max-provers 8 -I base-c10-split -I cdrafts-split cdrafts-split/WOTS_C_Bridge.ec > "$O" 2>&1
echo "__RC=$? wall=$(( $(date +%s) - t0 ))s" >> "$O"
