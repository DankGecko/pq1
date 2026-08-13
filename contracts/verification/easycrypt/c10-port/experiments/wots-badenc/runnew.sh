#!/usr/bin/env bash
set -u
cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
O=experiments/wots-badenc/new.out
rm -f "$O"
easycrypt compile -I "$B" -I "$C" "$C/GprocQWiredWotsCharged.ec" > "$O" 2>&1
echo "__RC=$?" >> "$O"
