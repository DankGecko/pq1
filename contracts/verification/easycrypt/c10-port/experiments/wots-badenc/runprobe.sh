#!/usr/bin/env bash
set -u
cd /work
B=experiments/wots-badenc/probe
O=experiments/wots-badenc/probe.out
rm -f "$B"/*.eco "$O"
easycrypt compile -I "$B" "$B/WOTS_TW_ES.ec" > "$O" 2>&1
echo "__RC=$?" >> "$O"
