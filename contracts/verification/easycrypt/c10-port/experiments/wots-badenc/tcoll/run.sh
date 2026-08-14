#!/usr/bin/env bash
# Compile the T_COLL_RES_ENUM game against the charged base/ and the cd/ +C tree.
set -u
cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
O=$T/tcoll.out
rm -f "$O" "$T/TCollResEnum.eco"
easycrypt compile -I "$B" -I "$C" -I "$T" "$T/TCollResEnum.ec" > "$O" 2>&1
echo "__RC=$?" >> "$O"
