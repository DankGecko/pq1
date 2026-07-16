#!/usr/bin/env bash
# Run the page-123 compaction crash-atomicity TLC pilot (see README.md).
# Needs tla2tools.jar; override its path with TLA2TOOLS=/path/to/tla2tools.jar.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${TLA2TOOLS:-$HOME/tla2tools.jar}"
[ -f "$JAR" ] || { echo "tla2tools.jar not found at $JAR — set TLA2TOOLS=... (fetch: https://github.com/tlaplus/tlaplus/releases)"; exit 2; }
run() {
  local cfg="$1" expect="$2"
  local out; out=$(java -cp "$JAR" tlc2.TLC -config "$HERE/$cfg.cfg" -deadlock "$HERE/Page123Compaction.tla" 2>&1)
  local got
  if echo "$out" | grep -q 'No error has been found'; then got="PASS"; else
     if echo "$out" | grep -q 'is violated'; then got="VIOLATED"; else got="ERROR"; fi; fi
  local mark; [ "$got" = "$expect" ] && mark="ok  " || mark="FAIL"
  printf '  [%s] %-26s expect=%-9s got=%s\n' "$mark" "$cfg" "$expect" "$got"
  [ "$got" = "$expect" ]
}
echo "=== page-123 compaction crash-atomicity — TLC pilot ==="
rc=0
run sigsfirst_skip           PASS     || rc=1   # F3 SIGS-first ordering CONFIRMED (under torn=Skip premise)
run sigslast_skip            VIOLATED || rc=1   # negative control: wrong order breaks it (non-vacuity)
run sigsfirst_mayvalid       VIOLATED || rc=1   # FINDING 1: no per-entry integrity tag; relies on torn-QW=undecodable HW premise
run endtoend_sigsfirst_skip  VIOLATED || rc=1   # FINDING 2: local tally resets on total loss; backstopped by inv-#9 + on-chain cap
run cnt_sigsfirst_skip       VIOLATED || rc=1   # documented SIGS-vs-COUNT asymmetry (non-vacuity)
echo; [ $rc = 0 ] && echo "=== all 5 expected outcomes matched ===" || echo "=== MISMATCH — investigate ==="
exit $rc
