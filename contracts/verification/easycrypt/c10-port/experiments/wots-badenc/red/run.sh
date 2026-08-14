#!/usr/bin/env bash
set -u
cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
R=experiments/wots-badenc/red
F=${1:-BadEncToTColl}
O=$R/$F.out
rm -f "$O" "$R/$F.eco"
easycrypt compile -I "$B" -I "$C" -I "$T" -I "$R" "$R/$F.ec" > "$O" 2>&1
echo "__RC=$?" >> "$O"
