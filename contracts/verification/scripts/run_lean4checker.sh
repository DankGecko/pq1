#!/usr/bin/env bash
#
# run_lean4checker.sh — EXTERNAL kernel re-check gate for the SphincsCVerify
# Lean development (CLAUDE.md §33 / research recommendation #1).
#
# WHY THIS EXISTS
# ---------------
# lean/ is pinned to Lean v4.22.0, which is inside the pre-PR-8842 (#8840)
# `collectAxioms` under-report window: on that toolchain `#print axioms`
# (and our `verify-audit` / `dump_axioms.lean` gate built on it) can
# UNDER-REPORT the true axiom closure of a theorem — e.g. an "environment
# hack" that injects a declaration with `addDeclCore (doCheck := false)`
# slips past the elaborator's kernel check and past `collectAxioms`.
#
# `lean4checker` closes that gap: it replays the entire compiled environment
# (every `.olean` reachable from the named module) back through the actual
# Lean KERNEL and recomputes the true closure. If any declaration does not
# kernel-check (a bogus `False` proof, a type mismatch, a forged axiom), it
# prints "lean4checker found a problem in ..." and exits non-zero. This is
# the independent re-check that makes "no sorryAx / no false axiom" a kernel
# fact rather than a grep.
#
# WHAT IT DOES
# ------------
#   1. Resolves a version-MATCHED lean4checker (must be built against the
#      same toolchain as lean/lean-toolchain — v4.22.0 oleans are only
#      replayable by a v4.22.0 lean4checker).
#   2. `lake build` lean/ (so every SphincsCVerify .olean is fresh).
#   3. `lake env <lean4checker> SphincsCVerify` — replays the full env
#      through the kernel.
#   4. Exits non-zero on ANY rejection.
#
# CONFIG (env overrides)
# ----------------------
#   LEAN4CHECKER_DIR   — checkout of github.com/leanprover/lean4checker built
#                        at the matching tag (default: $HOME/lean4checker).
#                        Build once with:
#                          git clone https://github.com/leanprover/lean4checker ~/lean4checker
#                          cd ~/lean4checker && git checkout v4.22.0 && lake build
#
# Mirrors lean4checker's own README invocation ("lake env path/to/lean4checker <module>").

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFICATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LEAN_DIR="${VERIFICATION_DIR}/lean"

LAKE="${LAKE:-$(command -v lake 2>/dev/null || echo "${HOME}/.elan/bin/lake")}"
LEAN4CHECKER_DIR="${LEAN4CHECKER_DIR:-${HOME}/lean4checker}"
L4C_EXE="${LEAN4CHECKER_DIR}/.lake/build/bin/lean4checker"

# Module to re-check — the top-level umbrella that imports every sub-namespace,
# so replaying it pulls the whole development through the kernel.
MODULE="${1:-SphincsCVerify}"

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- 0. preflight ----------------------------------------------------------
command -v "${LAKE}" >/dev/null 2>&1 || [ -x "${LAKE}" ] || fail "lake not found (set LAKE=...)"

[ -x "${L4C_EXE}" ] || fail "lean4checker binary not found at ${L4C_EXE}.
  Build a version-matched lean4checker first:
    git clone https://github.com/leanprover/lean4checker ${LEAN4CHECKER_DIR}
    cd ${LEAN4CHECKER_DIR} && git checkout \$(cat ${LEAN_DIR}/lean-toolchain | sed 's#.*:##') && ${LAKE} build
  Or set LEAN4CHECKER_DIR to an existing matched checkout."

# --- 1. toolchain-match guard ---------------------------------------------
# v4.22.0 .oleans are only replayable by a v4.22.0 lean4checker. A mismatch
# is the single most common silent failure mode, so refuse to proceed.
PROJ_TC="$(tr -d '[:space:]' < "${LEAN_DIR}/lean-toolchain")"
L4C_TC="$(tr -d '[:space:]' < "${LEAN4CHECKER_DIR}/lean-toolchain")"
if [ "${PROJ_TC}" != "${L4C_TC}" ]; then
  fail "toolchain mismatch: lean/ is '${PROJ_TC}' but lean4checker is '${L4C_TC}'.
  Rebuild lean4checker at the matching tag (see ${LEAN4CHECKER_DIR})."
fi
echo "[lean4checker] toolchain matched: ${PROJ_TC}"

# --- 2. build lean/ --------------------------------------------------------
echo "[lean4checker] building lean/ (${LEAN_DIR}) ..."
( cd "${LEAN_DIR}" && "${LAKE}" build )

# --- 3. external kernel re-check ------------------------------------------
echo "[lean4checker] replaying '${MODULE}' through the Lean kernel ..."
# Run inside the lean/ project env so the .olean search path is set; -v so a
# CI log shows every module that was replayed. lean4checker exits non-zero on
# the first declaration the kernel rejects.
( cd "${LEAN_DIR}" && "${LAKE}" env "${L4C_EXE}" -v "${MODULE}" )

echo "[lean4checker] OK — kernel re-check ACCEPTED every declaration in '${MODULE}' (exit 0)."
