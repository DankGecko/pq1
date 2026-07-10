#!/usr/bin/env bash
# =============================================================================
# verify-easycrypt -- compile the SPHINCS+C EasyCrypt port and assert its ledger.
#
# WHY THIS EXISTS
#   Two axioms in `theft_free`'s closure -- A5-EUFCMA and A5-ITSR -- cite this
#   EasyCrypt development as evidence. Until 2026-07-10 that evidence lived in a
#   REMOTE-LESS local repo (`~/repos/c10-eufcma-port`), so nobody but its author
#   could check it. STATUS.md's rule #1 is "every DONE row carries a
#   spot-checkable evidence pointer." This makes it true.
#
# WHAT IT CHECKS (all falsifiable)
#   1. EVERY .ec file compiles AS A TARGET. This is not pedantry: EasyCrypt's
#      `require` does NOT re-verify a dependency's proofs -- it imports its lemma
#      STATEMENTS and trusts them. A file can `require` a theory whose proofs are
#      broken and still compile EXIT 0. Reproduce:
#          Broken.ec: lemma brk : false. proof. trivial. qed.   -> EXIT 1
#          Uses.ec  : require import Broken.
#                     lemma e : 1 = 2. proof. have := brk. done. qed.  -> EXIT 0
#      Also: `admit` compiles EXIT 0 with ZERO output. Exit code proves nothing.
#   2. The comment-stripped admit count matches the pinned ledger, per file.
#      (Grepping `^\s*admit` WITHOUT stripping (* comments *) massively
#      over-counts -- this repo's prose is full of the word "admit".)
#   3. The comment-stripped axiom count matches the pinned ledger.
#
# NOT RUN IN CI. It needs an opam switch with EasyCrypt r2026.02 + Alt-Ergo 2.6.0
# (see ../easycrypt/PROVENANCE.md). Treat it like `verify-kontrol`: a local /
# nightly gate. `--dry-run` checks the pins without a toolchain.
#
# The MM45 reference proofs are NOT vendored (they are large and third-party).
# Fetch them once:
#     git clone --depth 1 https://github.com/MM45/FV-SPHINCSPLUS-EC
#     git clone --depth 1 https://github.com/MM45/FV-XMSS-EC
# and point EC_FV_ROOT at their parent directory (default: ~/repos/c10-eufcma-port).
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EC_DIR="$HERE/../easycrypt"
DRAFTS="$EC_DIR/drafts"
EC_FV_ROOT="${EC_FV_ROOT:-$HOME/repos/c10-eufcma-port}"

# ---- PINNED LEDGER. Any drift here is a FAILURE, not a warning. -------------
# Files permitted to contain an `admit`, with the exact count. Both are ORPHANED
# (required by nothing); the capstone's chain is admit-free.
declare -A EXPECTED_ADMITS=(
  [FORS_C_TreePort.ec]=1      # F-EXTRACT-OP; orphaned
  [WOTS_C_Interactive.ec]=1   # interactive S-TCR(+C) sim; orphaned
)
EXPECTED_TOTAL_AXIOMS=8       # dpp_ll, dmkey_ll, good_pos, size_g, eqiks_g, neqisvs_g, rng_g, uniq_g

# NESTING-AWARE sweep. A naive `perl -0777 -pe 's/\(\*.*?\*\)//gs'` closes at the
# FIRST `*)`, so prose like "zero-admit" leaks out of nested comments; and a
# line-anchored `^\s*admit\.` MISSES an inline `proof. admit. qed.` -- the exact
# form the (deleted) WOTS_C_Encoding.ec used. Both bugs were live here until
# 2026-07-10. See scripts/ec_sweep.py.
sweep()          { python3 "$HERE/ec_sweep.py" "$1"; }
count_admits()   { sweep "$1" | cut -f2; }
count_axioms()   { sweep "$1" | cut -f3; }

fail=0
note() { printf '  %s\n' "$*"; }
bad()  { printf '  FAIL: %s\n' "$*"; fail=1; }

echo "=== verify-easycrypt ==="
[ -d "$DRAFTS" ] || { echo "FAIL: no drafts at $DRAFTS"; exit 1; }

# ---- (2)+(3) ledger pins: no toolchain needed --------------------------------
echo
echo "[pins] comment-stripped admit/axiom sweep"
total_axioms=0
for f in "$DRAFTS"/*.ec; do
  b="$(basename "$f")"
  a="$(count_admits "$f")"
  x="$(count_axioms "$f")"
  total_axioms=$(( total_axioms + x ))
  exp="${EXPECTED_ADMITS[$b]:-0}"
  if [ "$a" != "$exp" ]; then
    bad "$b has $a admit(s), ledger pins $exp"
  fi
done
for b in "${!EXPECTED_ADMITS[@]}"; do
  [ -f "$DRAFTS/$b" ] || bad "ledger pins admits in $b, but the file is gone"
done
if [ "$total_axioms" != "$EXPECTED_TOTAL_AXIOMS" ]; then
  bad "total axioms = $total_axioms, ledger pins $EXPECTED_TOTAL_AXIOMS"
else
  note "axioms: $total_axioms (matches ledger)"
fi
note "admits: pinned to ${#EXPECTED_ADMITS[@]} orphaned file(s)"

if [ "${1:-}" = "--dry-run" ]; then
  echo
  [ "$fail" = 0 ] && echo "=== PINS OK (dry-run; proofs NOT compiled) ===" || echo "=== PINS FAIL ==="
  exit "$fail"
fi

# ---- (1) compile EVERY file as a target --------------------------------------
FV_S="$EC_FV_ROOT/FV-SPHINCSPLUS-EC/proofs"
FV_X="$EC_FV_ROOT/FV-XMSS-EC/proofs"
if [ ! -d "$FV_S" ] || [ ! -d "$FV_X" ]; then
  echo
  echo "SKIP: MM45 reference proofs not found under EC_FV_ROOT=$EC_FV_ROOT"
  echo "  git clone --depth 1 https://github.com/MM45/FV-SPHINCSPLUS-EC"
  echo "  git clone --depth 1 https://github.com/MM45/FV-XMSS-EC"
  echo "  then re-run, or: EC_FV_ROOT=<parent> make verify-easycrypt"
  exit "$fail"
fi
# ALWAYS prefer the PINNED r2026.02 helper. A bare `easycrypt` on PATH may be the
# `checkct` dev switch, which CANNOT compile the FV `WOTS_TW_ES.ec`.
EC_SH="${EC_SH:-$EC_DIR/ec-r2026.sh}"
[ -x "$EC_SH" ] || { echo "SKIP: no $EC_SH (see ../easycrypt/PROVENANCE.md)"; exit "$fail"; }

# include order matters: XMSS BEFORE SPHINCSPLUS, else `unknown type diff_t`
INC=(-I "$FV_X" -I "$FV_S" -I "$DRAFTS")
echo
echo "[compile] every .ec as a TARGET (require does NOT re-verify)"
find "$DRAFTS" -name '*.eco' -delete 2>/dev/null
for f in "$DRAFTS"/*.ec; do
  b="$(basename "$f")"
  if [ -n "${EC_SH:-}" ]; then
    timeout 1800 bash "$EC_SH" compile "${INC[@]}" "$f" >/dev/null 2>&1
  else
    timeout 1800 easycrypt compile "${INC[@]}" "$f" >/dev/null 2>&1
  fi
  rc=$?
  if [ "$rc" != 0 ]; then bad "$b does not compile (exit $rc)"; else note "ok  $b"; fi
done
find "$DRAFTS" -name '*.eco' -delete 2>/dev/null

echo
if [ "$fail" = 0 ]; then echo "=== verify-easycrypt OK ==="; else echo "=== verify-easycrypt FAIL ==="; fi
exit "$fail"
