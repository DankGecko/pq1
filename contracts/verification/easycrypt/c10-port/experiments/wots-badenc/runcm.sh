#!/usr/bin/env bash
set -u
cd /work
B=experiments/wots-badenc/base
O=experiments/wots-badenc/cm.out
rm -f "$O" "$B/BadEncCountermodel.eco"
easycrypt compile -I "$B" "$B/BadEncCountermodel.ec" > "$O" 2>&1
echo "__RC=$?" >> "$O"
