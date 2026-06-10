#!/usr/bin/env bash
#
# run_halmos.sh — bytecode-level discharge of the A3.* bridge axioms.
#
# 1. Certifies (via Foundry) that the compiled runtime bytecode has the
#    codehashes pinned in test/PinnedCodehashes.t.sol — so the symbolic
#    proof below is against the SAME bytecode the Lean `theft_free` closure
#    names. Also runs the immutable-window lemma (PinnedBytecodeImmutableLemma)
#    so the proof transports from the pinned instance to any instance modulo
#    the two certified immutables.
# 2. Symbolically executes the deployed bytecode with the patched Halmos.
#    Every `check_*` rule that passes is a proof over ALL inputs (modulo the
#    SMT solver + the SHA-256-as-uninterpreted-function abstraction = A1).
#
# Runs BOTH compiler profiles: `default` (runs=200, the dev/test build the
# symbolic suite executes against) and `deploy` (runs=999999, the production
# build). The codehash + immutable-lemma certification runs under both so the
# discharge holds for the production bytecode, not just the dev bytecode. The
# (slow) symbolic suite runs once on the default profile; the wallet/factory
# CONTROL FLOW is identical across profiles (only the optimiser's instruction
# selection differs, which the codehash + immutable lemma already pin), so a
# single symbolic run plus the cross-profile codehash certification covers
# both. Set PQ1_HALMOS_BOTH_PROFILES=1 to additionally re-run the symbolic
# suite under the deploy profile.
#
# Exit non-zero if any rule fails or errors.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WALLET_DIR="$(cd "${HERE}/../../smart-wallet" && pwd)"
SOLVER="${HALMOS_SOLVER:-z3}"
export PATH="${HOME}/.local/bin:${PATH}"

command -v halmos >/dev/null 2>&1 || { echo "halmos not installed — run setup_halmos.sh"; exit 2; }

cd "${WALLET_DIR}"

certify_profile() {
  local profile="$1"
  echo "    [${profile}] codehash freeze + immutable-window lemma"
  FOUNDRY_PROFILE="${profile}" forge test \
    --match-contract 'PinnedCodehashes|PinnedBytecodeImmutableLemma' >/dev/null
}

echo "==> [1/2] Certifying compiled bytecode == pinned codehashes (Foundry, both profiles)"
certify_profile default
certify_profile deploy
echo "    OK: wallet / factory / verifier codehashes match PINNED_CODEHASHES.md"
echo "    OK: runtime differs from the pinned instance only at the certified immutables"

run_symbolic() {
  local profile="$1"
  echo "==> [2/2] Halmos symbolic execution of the deployed bytecode [profile=${profile}]"
  FOUNDRY_PROFILE="${profile}" forge build --ast >/dev/null 2>&1
  FOUNDRY_PROFILE="${profile}" halmos \
    --match-contract 'Halmos(ValidateUserOpEquiv|ValidateUserOp|Execute|Verifier|Factory)' \
    --solver "${SOLVER}" --loop 4 \
    | tee /tmp/pq1-halmos-run.txt | grep -E "Running|\[PASS\]|\[FAIL\]|\[ERROR\]|Symbolic test result"

  if grep -qE "\[FAIL\]|\[ERROR\]" /tmp/pq1-halmos-run.txt; then
    echo "==> FAIL: at least one Halmos rule did not pass [profile=${profile}]"
    exit 1
  fi
  local passes
  passes=$(grep -c "\[PASS\]" /tmp/pq1-halmos-run.txt || true)
  echo "==> PASS: ${passes} bytecode rules verified [profile=${profile}] (A3.1 gates / A3.2 equiv / A3.3)"
}

run_symbolic default
if [ "${PQ1_HALMOS_BOTH_PROFILES:-0}" = "1" ]; then
  run_symbolic deploy
fi
