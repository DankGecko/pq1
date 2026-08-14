#!/usr/bin/env bash
# Compile one file from experiments/wots-badenc/count/ (or count/controls/).
# Deletes ALL project .eco first so nothing is served from a stale cache.
set -u
cd /work
D=experiments/wots-badenc/count
p="${1:?usage: run.sh <relpath-without-.ec>}"
O="$D/$p.out"
rm -f "$D/$p.eco" "$O"   # full clean is done by the final -check-all receipt run
[ -n "${STK:-}" ] && { ulimit -s "$STK" 2>/dev/null || true; }
t0=$(date +%s%N)
easycrypt compile ${EXTRA:-} -I "$D" -I "$D/controls" "$D/$p.ec" > "$O" 2>&1
rc=$?
t1=$(date +%s%N)
echo "__RC=$rc" >> "$O"
echo "__WALL_MS=$(( (t1 - t0) / 1000000 ))" >> "$O"
if [ -f "$D/$p.eco" ]; then echo "__ECO=yes $(stat -c %s "$D/$p.eco")" >> "$O"; else echo "__ECO=NO" >> "$O"; fi
