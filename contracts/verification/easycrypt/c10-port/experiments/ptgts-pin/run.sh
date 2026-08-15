#!/usr/bin/env bash
# Compile one file from experiments/ptgts-pin/ (or ptgts-pin/controls/) against
# the SPLIT certified trees, READ-ONLY: -I base-c10-split -I cdrafts-split.
# Deletes only the TARGET's .eco so nothing is served from its own stale cache;
# the certified trees' .eco are left alone (they are gitignored build artifacts
# and are NOT rebuilt by this script).
set -u
cd /work
D=experiments/ptgts-pin
p="${1:?usage: run.sh <relpath-without-.ec>}"
O="$D/$p.out"
rm -f "$D/$p.eco" "$O"
[ -n "${STK:-}" ] && { ulimit -s "$STK" 2>/dev/null || true; }
t0=$(date +%s%N)
easycrypt compile ${EXTRA:-} -I base-c10-split -I cdrafts-split -I "$D" -I "$D/controls" "$D/$p.ec" > "$O" 2>&1
rc=$?
t1=$(date +%s%N)
echo "__RC=$rc" >> "$O"
echo "__WALL_MS=$(( (t1 - t0) / 1000000 ))" >> "$O"
if [ -f "$D/$p.eco" ]; then echo "__ECO=yes $(stat -c %s "$D/$p.eco")" >> "$O"; else echo "__ECO=NO" >> "$O"; fi
