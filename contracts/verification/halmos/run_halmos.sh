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
# Exit non-zero if any rule fails or errors, if any expected harness did not
# run, or if the PASS count drops below the pinned rule floor (green-at-zero
# guard — fv-deep-review-2026-07-19 F9).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WALLET_DIR="$(cd "${HERE}/../../smart-wallet" && pwd)"
SOLVER="${HALMOS_SOLVER:-z3}"
export PATH="${HOME}/.local/bin:${PATH}"

# --- Rule-identity floor (fv-deep-review-2026-07-19 F9) ----------------------
# The wired rule set: every `check_*` test function under
# contracts/smart-wallet/test/halmos/. Verified 2026-07-19: 42 rules across 8
# harnesses (prior receipts recorded 38 and predate HalmosIsValidSignature.t.sol,
# the 3 EIP-1271/G8 rules). Bump EXPECTED_RULES + EXPECTED_HALMOS_CONTRACTS when
# adding/removing a harness or rule; fv-deep-review-2026-07-19 F9.
EXPECTED_RULES=42
EXPECTED_HALMOS_CONTRACTS=(
  HalmosValidateUserOpEquiv
  HalmosValidateUserOp
  HalmosExecuteEquiv
  HalmosExecute
  HalmosMultiOwnable
  HalmosVerifier
  HalmosFactory
  HalmosIsValidSignature
)
HALMOS_SRC_DIR="${WALLET_DIR}/test/halmos"

# check_rule_inventory: the pin must match the wired tree BEFORE solver time is
# spent — a harness/rule landing without a pin bump is exactly the F9
# receipt-drift shape.
check_rule_inventory() {
  local wired
  wired=$(grep -hoE "function check_[A-Za-z0-9_]+" "${HALMOS_SRC_DIR}"/*.t.sol | wc -l)
  if [ "${wired}" -ne "${EXPECTED_RULES}" ]; then
    echo "==> FAIL: ${HALMOS_SRC_DIR} wires ${wired} check_* rules but EXPECTED_RULES=${EXPECTED_RULES} — bump the pin (fv-deep-review-2026-07-19 F9)" >&2
    return 1
  fi
}

# assert_pass_floor <halmos-output-file> <profile-label>
# (a) every expected harness produced a `Running N tests for ...:<Contract>`
#     line with N equal to its wired check_* count (identity — a silently
#     unmatched harness cannot go green), and
# (b) total [PASS] lines >= EXPECTED_RULES (count floor — green-at-zero guard).
assert_pass_floor() {
  local outfile="$1" profile="$2"
  local contract want running passes
  for contract in "${EXPECTED_HALMOS_CONTRACTS[@]}"; do
    want=$(grep -cE "function check_[A-Za-z0-9_]+" "${HALMOS_SRC_DIR}/${contract}.t.sol" || true)
    running=$(grep -E "Running [0-9]+ tests for .*:${contract}\b" "${outfile}" | head -1 | grep -oE "Running [0-9]+" | grep -oE "[0-9]+" || true)
    if [ -z "${running}" ]; then
      echo "==> FAIL [${profile}]: harness ${contract} produced no 'Running N tests' line — it was NOT executed (identity floor, F9)" >&2
      return 1
    fi
    if [ "${running}" -ne "${want}" ]; then
      echo "==> FAIL [${profile}]: harness ${contract} ran ${running} tests but wires ${want} check_* rules (identity floor, F9)" >&2
      return 1
    fi
  done
  passes=$(grep -c "\[PASS\]" "${outfile}" || true)
  if [ "${passes}" -lt "${EXPECTED_RULES}" ]; then
    echo "==> FAIL [${profile}]: only ${passes} [PASS] lines; the pinned floor is ${EXPECTED_RULES} (green-at-zero guard, F9)" >&2
    return 1
  fi
  echo "    floor OK [${profile}]: all ${#EXPECTED_HALMOS_CONTRACTS[@]} harnesses executed; ${passes} [PASS] lines >= ${EXPECTED_RULES} pinned"
}

# self_test: positive + negative controls for assert_pass_floor (no solver).
self_test() {
  local d; d="$(mktemp -d /tmp/pq1-halmos-floor-selftest.XXXXXX)"
  local complete="${d}/complete.txt" zero="${d}/zero.txt" missing="${d}/missing.txt"
  : > "${complete}"; : > "${zero}"; : > "${missing}"
  local contract want i rc=0
  for contract in "${EXPECTED_HALMOS_CONTRACTS[@]}"; do
    want=$(grep -cE "function check_[A-Za-z0-9_]+" "${HALMOS_SRC_DIR}/${contract}.t.sol" || true)
    echo "Running ${want} tests for test/halmos/${contract}.t.sol:${contract}" >> "${complete}"
    echo "Running ${want} tests for test/halmos/${contract}.t.sol:${contract}" >> "${zero}"
    if [ "${contract}" != "HalmosIsValidSignature" ]; then
      echo "Running ${want} tests for test/halmos/${contract}.t.sol:${contract}" >> "${missing}"
    fi
  done
  for i in $(seq 1 "${EXPECTED_RULES}"); do
    echo "[PASS] check_synthetic_${i}() (paths: 1, time: 0.01s, bounds: [])" >> "${complete}"
    echo "[PASS] check_synthetic_${i}() (paths: 1, time: 0.01s, bounds: [])" >> "${missing}"
  done
  echo "-- self-test 1/3: complete fixture (all 8 Running lines + ${EXPECTED_RULES} PASS) — must be ACCEPTED"
  if assert_pass_floor "${complete}" selftest >/dev/null 2>&1; then echo "   OK: accepted"; else echo "   CONTROL FAILURE: rejected a complete run" >&2; rc=1; fi
  echo "-- self-test 2/3: zero-PASS fixture (Running lines only, 0 PASS) — must be REJECTED"
  if assert_pass_floor "${zero}" selftest >/dev/null 2>&1; then echo "   CONTROL FAILURE: green-at-zero accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 3/3: missing-one-harness fixture (${EXPECTED_RULES} PASS lines but no HalmosIsValidSignature Running line) — must be REJECTED"
  if assert_pass_floor "${missing}" selftest >/dev/null 2>&1; then echo "   CONTROL FAILURE: missing-harness accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  rm -rf "${d}"
  if [ "${rc}" -eq 0 ]; then
    echo "run_halmos.sh --self-test: all controls behave"
  else
    echo "run_halmos.sh --self-test: CONTROL FAILURE" >&2
  fi
  return "${rc}"
}

case "${1:-}" in
  --self-test)
    self_test
    exit $?
    ;;
  --check-output)
    [ $# -eq 2 ] || { echo "usage: $0 --check-output <halmos-output-file>" >&2; exit 2; }
    check_rule_inventory
    assert_pass_floor "$2" check-only
    exit $?
    ;;
esac

command -v halmos >/dev/null 2>&1 || { echo "halmos not installed — run setup_halmos.sh"; exit 2; }

check_rule_inventory

cd "${WALLET_DIR}"

certify_profile() {
  local profile="$1"
  echo "    [${profile}] codehash freeze + immutable-window lemma + deployed-bytecode repro"
  # DeployedBytecodeReproCheck self-skips off the deploy profile (the live
  # contracts were cut from runs=999999), so it is a no-op under default.
  FOUNDRY_PROFILE="${profile}" forge test \
    --match-contract 'PinnedCodehashes|PinnedBytecodeImmutableLemma|DeployedBytecodeReproCheck' >/dev/null
}

echo "==> [1/2] Certifying compiled bytecode == pinned codehashes (Foundry, both profiles)"
certify_profile default
certify_profile deploy
echo "    OK: wallet / factory / verifier codehashes match PINNED_CODEHASHES.md"
echo "    OK: runtime differs from the pinned instance only at the certified immutables"
echo "    OK: CREATE2 replay reproduces the deployed Base Mainnet impl/factory/verifier (addr+codehash)"

run_symbolic() {
  local profile="$1"
  echo "==> [2/2] Halmos symbolic execution of the deployed bytecode [profile=${profile}]"
  FOUNDRY_PROFILE="${profile}" forge build --ast >/dev/null 2>&1
  # The contract alternation is derived from EXPECTED_HALMOS_CONTRACTS so the
  # identity floor above and the executed set can never drift apart (F9).
  local match_contract
  match_contract="Halmos($(IFS='|'; echo "${EXPECTED_HALMOS_CONTRACTS[*]#Halmos}"))"
  FOUNDRY_PROFILE="${profile}" halmos \
    --match-contract "${match_contract}" \
    --solver "${SOLVER}" --loop 4 \
    | tee "/tmp/pq1-halmos-run-${profile}.txt" | grep -E "Running|\[PASS\]|\[FAIL\]|\[ERROR\]|Symbolic test result"

  if grep -qE "\[FAIL\]|\[ERROR\]" "/tmp/pq1-halmos-run-${profile}.txt"; then
    echo "==> FAIL: at least one Halmos rule did not pass [profile=${profile}]"
    exit 1
  fi
  assert_pass_floor "/tmp/pq1-halmos-run-${profile}.txt" "${profile}" || {
    echo "==> FAIL: Halmos rule-identity floor not met [profile=${profile}]"
    exit 1
  }
  local passes
  passes=$(grep -c "\[PASS\]" "/tmp/pq1-halmos-run-${profile}.txt" || true)
  echo "==> PASS: ${passes} bytecode rules verified [profile=${profile}]"
  echo "    (A3.1 verifier gates / A3.2 validate equiv / A3.2-exec execute equiv / A3.3 factory iff / A3.4 owner table / EIP-1271 isValidSignature G8)"
}

run_symbolic default
if [ "${PQ1_HALMOS_SKIP_DEPLOY_SYMBOLIC:-0}" = "1" ]; then
  echo "==> NOTE: skipping deploy-profile symbolic re-run (PQ1_HALMOS_SKIP_DEPLOY_SYMBOLIC=1)"
else
  run_symbolic deploy
fi
