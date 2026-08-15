#!/usr/bin/env bash
# host-side wrapper: bash ec.sh <relpath-without-.ec>
set -u
sg docker -c "docker exec ec-grind bash -lc 'eval \$(opam env 2>/dev/null); bash /work/experiments/ptgts-pin/run.sh $1'" >/dev/null 2>&1
d=/home/nicola/repos/c10-eufcma-port/experiments/ptgts-pin
echo "== $1 : $(tr '\r' '\n' < $d/$1.out | grep -E '__RC=|__WALL_MS|__ECO' | tr '\n' ' ')"
tr '\r' '\n' < "$d/$1.out" | grep -vE '^\[[|/\\-]\] \[[0-9]+\]' | grep -vE '^\s*$' | grep -vE '^__' | head -20
