set -u; cd /work
O=experiments/wots-badenc/ext.out
rm -f "$O"
easycrypt compile -I base-c10-split -I cdrafts-split -I experiments/tcollres-leg \
  experiments/tcollres-leg/Extraction.ec > "$O" 2>&1
echo "__RC=$?" >> "$O"
