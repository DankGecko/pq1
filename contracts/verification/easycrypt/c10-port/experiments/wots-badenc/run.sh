#!/usr/bin/env bash
set -u
cd /work
B=experiments/wots-badenc/base
O=experiments/wots-badenc/run.out
rm -f "$B"/*.eco
easycrypt compile -I "$B" "$B/WOTS_TW_ES.ec" > "$O" 2>&1
echo "__RC=$?" >> "$O"
