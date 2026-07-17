#!/usr/bin/env bash
# P1.5 combined budget-lifetime composition (closes Finding 2 of the page-123
# crash-atomicity pilot). Self-checking; needs tla2tools.jar (TLA2TOOLS=... or $HOME).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${TLA2TOOLS:-$HOME/tla2tools.jar}"
[ -f "$JAR" ] || { echo "tla2tools.jar not found ($JAR) — set TLA2TOOLS=..."; exit 2; }
run() {
  local cfg="$1" expect="$2"
  local out; out=$(java -cp "$JAR" tlc2.TLC -config "$HERE/$cfg.cfg" -deadlock "$HERE/CombinedBudget.tla" 2>&1)
  local got; if echo "$out"|grep -q 'No error has been found'; then got=HOLD; elif echo "$out"|grep -q 'is violated'; then got=VIOLATED; else got=ERROR; fi
  local mark; [ "$got" = "$expect" ] && mark="ok  " || mark="FAIL"
  printf '  [%s] %-20s expect=%-9s got=%s\n' "$mark" "$cfg" "$expect" "$got"; [ "$got" = "$expect" ]
}
echo "=== P1.5 combined budget-lifetime composition ==="
rc=0
run cb_onchain_cap     HOLD     || rc=1   # on-chain cap = backstop, holds across torn resets
run cb_margin_noreset  HOLD     || rc=1   # NEGATIVE CONTROL: no reset => slot-key margin bounded
run cb_margin_reset    VIOLATED || rc=1   # residual: a torn reset erodes the view-only few-time margin
echo; [ $rc = 0 ] && echo "=== all 3 expected outcomes matched ===" || echo "=== MISMATCH ==="; exit $rc
