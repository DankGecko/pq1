#!/usr/bin/env bash
#
# run_halmos.sh — bytecode-level discharge of the A3.* bridge axioms.
#
# 1. Certifies (via Foundry) that the compiled runtime bytecode has the
#    codehashes pinned in test/PinnedCodehashes.t.sol — so the symbolic
#    proof below is against the SAME bytecode the Lean `theft_free` closure
#    names.
# 2. Symbolically executes the deployed bytecode with the patched Halmos.
#    Every `check_*` rule that passes is a proof over ALL inputs (modulo the
#    SMT solver + the SHA-256-as-uninterpreted-function abstraction = A1).
#
# Exit non-zero if any rule fails or errors.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WALLET_DIR="$(cd "${HERE}/../../smart-wallet" && pwd)"
SOLVER="${HALMOS_SOLVER:-z3}"
export PATH="${HOME}/.local/bin:${PATH}"

command -v halmos >/dev/null 2>&1 || { echo "halmos not installed — run setup_halmos.sh"; exit 2; }

cd "${WALLET_DIR}"

echo "==> [1/2] Certifying compiled bytecode == pinned codehashes (Foundry)"
forge test --match-contract PinnedCodehashes --match-test test_codehash_pinned_or_print >/dev/null
echo "    OK: wallet / factory / verifier codehashes match PINNED_CODEHASHES.md"

echo "==> [2/2] Halmos symbolic execution of the deployed bytecode"
forge build --ast >/dev/null 2>&1
halmos --match-contract 'Halmos(ValidateUserOp|Execute|Verifier|Factory)' --solver "${SOLVER}" \
  | tee /tmp/pq1-halmos-run.txt | grep -E "Running|\[PASS\]|\[FAIL\]|\[ERROR\]|Symbolic test result"

if grep -qE "\[FAIL\]|\[ERROR\]" /tmp/pq1-halmos-run.txt; then
  echo "==> FAIL: at least one Halmos rule did not pass"
  exit 1
fi
PASSES=$(grep -c "\[PASS\]" /tmp/pq1-halmos-run.txt || true)
echo "==> PASS: ${PASSES} bytecode rules verified (A3.1 gates / A3.2 / A3.3)"
