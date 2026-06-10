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
# Runs BOTH compiler profiles: `default` (runs=200) and `deploy`
# (runs=999999, the production build). For EACH profile we (1) certify the
# compiled runtime codehashes match PINNED_CODEHASHES.md + the immutable-
# window lemma, then (2) symbolically execute the FULL rule suite against
# that profile's bytecode. So the discharge holds for the production
# bytecode directly — not by a "control flow is identical across profiles"
# argument. (The immutable-window lemma still earns its keep WITHIN a
# profile: it transports each profile's pinned instance to every other
# instance of the same artifact, i.e. across differing constructor
# immutables — the harness verifier/EntryPoint addresses vs a real
# deployment.) Set PQ1_HALMOS_SKIP_DEPLOY_SYMBOLIC=1 to skip the (slow)
# deploy-profile symbolic re-run when iterating locally.
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
    --match-contract 'Halmos(ValidateUserOpEquiv|ValidateUserOp|ExecuteEquiv|Execute|MultiOwnable|Verifier|Factory)' \
    --solver "${SOLVER}" --loop 4 \
    | tee "/tmp/pq1-halmos-run-${profile}.txt" | grep -E "Running|\[PASS\]|\[FAIL\]|\[ERROR\]|Symbolic test result"

  if grep -qE "\[FAIL\]|\[ERROR\]" "/tmp/pq1-halmos-run-${profile}.txt"; then
    echo "==> FAIL: at least one Halmos rule did not pass [profile=${profile}]"
    exit 1
  fi
  local passes
  passes=$(grep -c "\[PASS\]" "/tmp/pq1-halmos-run-${profile}.txt" || true)
  echo "==> PASS: ${passes} bytecode rules verified [profile=${profile}]"
  echo "    (A3.1 verifier gates / A3.2 validate equiv / A3.2-exec execute equiv / A3.3 factory iff / A3.4 owner table)"
}

run_symbolic default
if [ "${PQ1_HALMOS_SKIP_DEPLOY_SYMBOLIC:-0}" = "1" ]; then
  echo "==> NOTE: skipping deploy-profile symbolic re-run (PQ1_HALMOS_SKIP_DEPLOY_SYMBOLIC=1)"
else
  run_symbolic deploy
fi
