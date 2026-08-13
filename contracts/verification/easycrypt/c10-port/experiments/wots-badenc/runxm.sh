#!/usr/bin/env bash
set -u
cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
O=experiments/wots-badenc/xm.out
rm -f "$O" "$C"/*.eco
easycrypt compile -I "$B" -I "$C" "$C/XmssmtCC_All.ec" > "$O" 2>&1
echo "__RC=$?" >> "$O"
