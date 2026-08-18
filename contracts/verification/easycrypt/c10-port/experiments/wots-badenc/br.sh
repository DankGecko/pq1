set -u; cd /work
O=experiments/wots-badenc/bridge.out
rm -f "$O" cdrafts-split/WOTS_C_Bridge.eco
easycrypt compile -I base-c10-split -I cdrafts-split cdrafts-split/WOTS_C_Bridge.ec > "$O" 2>&1
echo "__RC=$?" >> "$O"
