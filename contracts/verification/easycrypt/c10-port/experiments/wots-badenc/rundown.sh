#!/usr/bin/env bash
# Close PREDICTION 3: do the other base files still compile against the CHARGED
# WOTS_TW_ES?  Run against base/ (which now builds clean).
set -u
cd /work
B=experiments/wots-badenc/base
O=experiments/wots-badenc/down.out
rm -f "$O"
for f in FL_SL_XMSS_MT_ES FORS_ES SPHINCS_PLUS; do
  easycrypt compile -I "$B" "$B/$f.ec" > /tmp/d.$f 2>&1
  echo "$f __RC=$?" >> "$O"
  tr '\r' '\n' < /tmp/d.$f | grep -aE '^\[critical\]|^\[error\]' | head -2 >> "$O"
done
echo "__DONE" >> "$O"
