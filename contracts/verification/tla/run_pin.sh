#!/usr/bin/env bash
# P1.6 directional PIN-rollback reconcile — faithful model of the DEPLOYED
# `reconcile_pin_attempts` (secure/src/nsc/mod.rs), replacing the overstating
# symmetric tamarin model (pin_lockstep.spthy, finding PM-1).
# Self-checking; needs tla2tools.jar (TLA2TOOLS=... or $HOME/tla2tools.jar).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAR="${TLA2TOOLS:-$HOME/tla2tools.jar}"
[ -f "$JAR" ] || { echo "tla2tools.jar not found ($JAR) — set TLA2TOOLS=..."; exit 2; }
run() {
  local cfg="$1" expect="$2"
  local out; out=$(java -cp "$JAR" tlc2.TLC -config "$HERE/$cfg.cfg" -deadlock "$HERE/PinReconcileDirectional.tla" 2>&1)
  local got; if echo "$out"|grep -q 'No error has been found'; then got=HOLD; elif echo "$out"|grep -q 'is violated'; then got=VIOLATED; else got=ERROR; fi
  local mark; [ "$got" = "$expect" ] && mark="ok  " || mark="FAIL"
  printf '  [%s] %-22s expect=%-9s got=%s\n' "$mark" "$cfg" "$expect" "$got"; [ "$got" = "$expect" ]
}
echo "=== P1.6 directional PIN-rollback reconcile (deployed) ==="
rc=0
echo "-- sanity / anti-vacuity (honest-only) --"
run pin_benign_leads    HOLD     || rc=1   # honest two-phase play keeps mcu >= se (derives the benign invariant)
run pin_alive           VIOLATED || rc=1   # anti-vacuity: a surviving honest boot IS reachable (not always-wipe)
echo "-- deployed positive guarantee + residual #2 --"
run pin_rollback_caught HOLD     || rc=1   # se>mcu (page-124 rollback) with leg up => WIPE (what reconcile is FOR)
run pin_leg_bypass      VIOLATED || rc=1   # residual #2: glitch the leg down => a real rollback goes undetected
echo "-- THE CROSSING (directional vs symmetric negative control) --"
run pin_dir_nofalsewipe HOLD     || rc=1   # directional never false-wipes the mcu==se+1 power-cut state ...
run pin_sym_falsewipe   VIOLATED || rc=1   # ... but symmetric DOES false-wipe it  (availability cost)
run pin_dir_residual    VIOLATED || rc=1   # directional does NOT catch an SE-silicon reset (the residual) ...
run pin_sym_catches     HOLD     || rc=1   # ... but symmetric DOES catch it        (detection benefit)
echo; [ $rc = 0 ] && echo "=== all 8 expected outcomes matched ===" || echo "=== MISMATCH ==="; exit $rc
