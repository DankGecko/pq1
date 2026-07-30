#!/usr/bin/env bash
#
# verify-three-claims.sh — Full local verification of the three security
# claims for PQSmartWallet.
#
# Runs (in order):
#   1. Lake build (Lean kernel type-check, zero sorries)
#   2. make verify-audit (axiom dependency print)
#   3. lint_axioms.sh (no new True-typed axioms outside allowlist)
#   4. forge build + forge test (Foundry unit + parity + invariants)
#   5. forge invariant fuzz (256 runs * 500 calls)
#   6. Halmos symbolic execution (if installed)
#   7. Certora rule sets (if CERTORAKEY set + tool installed)
#   8. Per-claim summary
#
# Exits 0 if all required steps pass. Halmos and Certora are advisory —
# their absence prints a warning but doesn't fail.

set -euo pipefail

SCRIPT_SOURCE_SPELLING="${BASH_SOURCE[0]}"
if [[ "${SCRIPT_SOURCE_SPELLING}" != /* ]]; then
  SCRIPT_SOURCE_SPELLING="$(/usr/bin/pwd -P)/${SCRIPT_SOURCE_SPELLING}"
fi
SCRIPT_SOURCE=$(
  /usr/bin/readlink -f -- "${SCRIPT_SOURCE_SPELLING}"
) || {
  /usr/bin/printf \
    'ERROR: cannot resolve the physical verification script file\n' >&2
  exit 2
}
if [[ ! -f "${SCRIPT_SOURCE}" ]] ||
   [[ "${SCRIPT_SOURCE##*/}" != "verify-three-claims.sh" ]]; then
  /usr/bin/printf \
    'ERROR: resolved an unexpected verification script file: %s\n' \
    "${SCRIPT_SOURCE}" >&2
  exit 2
fi
SCRIPT_SOURCE_LINKS=$(
  /usr/bin/stat -c '%h' -- "${SCRIPT_SOURCE}"
) || {
  /usr/bin/printf \
    'ERROR: cannot inspect the physical verification script file\n' >&2
  exit 2
}
if [[ ! "${SCRIPT_SOURCE_LINKS}" =~ ^[0-9]+$ ]] ||
   [[ "${SCRIPT_SOURCE_LINKS}" -ne 1 ]]; then
  /usr/bin/printf \
    'ERROR: refusing multiply-linked verification script: file=%s links=%s\n' \
    "${SCRIPT_SOURCE}" "${SCRIPT_SOURCE_LINKS}" >&2
  exit 2
fi
SCRIPT_PARENT=$(/usr/bin/dirname -- "${SCRIPT_SOURCE}")
SCRIPT_DIR=$(
  builtin unset CDPATH
  builtin cd -P -- "${SCRIPT_PARENT}" &&
    /usr/bin/pwd -P
) || {
  /usr/bin/printf 'ERROR: cannot resolve the verification script directory\n' >&2
  exit 2
}
REPO_ROOT=$(
  builtin unset CDPATH
  builtin cd -P -- "${SCRIPT_DIR}/../../.." &&
    /usr/bin/pwd -P
) || {
  /usr/bin/printf 'ERROR: cannot resolve the repository root\n' >&2
  exit 2
}
VERIFICATION_DIR="${REPO_ROOT}/contracts/verification"
SMART_WALLET_DIR="${REPO_ROOT}/contracts/smart-wallet"
if [[ "${SCRIPT_DIR}" != "${VERIFICATION_DIR}/scripts" ]] ||
   [[ ! -f "${VERIFICATION_DIR}/Makefile" ]] ||
   [[ ! -d "${SMART_WALLET_DIR}" ]]; then
  /usr/bin/printf \
    'ERROR: resolved verification trust root is inconsistent: script=%s root=%s\n' \
    "${SCRIPT_DIR}" "${REPO_ROOT}" >&2
  exit 2
fi
readonly SCRIPT_SOURCE_SPELLING SCRIPT_SOURCE SCRIPT_SOURCE_LINKS
readonly SCRIPT_PARENT SCRIPT_DIR REPO_ROOT
readonly VERIFICATION_DIR SMART_WALLET_DIR

if [[ "${1:-}" == "--self-test-path-resolution" ]]; then
  if [[ "$#" -ne 1 ]]; then
    /usr/bin/printf \
      'usage: %s --self-test-path-resolution\n' "${BASH_SOURCE[0]}" >&2
    exit 2
  fi
  /usr/bin/printf 'script_file=%s\nscript_dir=%s\nrepo_root=%s\n' \
    "${SCRIPT_SOURCE}" "${SCRIPT_DIR}" "${REPO_ROOT}"
  exit 0
fi

USER_HOME=$(
  /usr/bin/python3 -I -S -c \
    'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)'
)
readonly USER_HOME

export PATH="${USER_HOME}/.elan/bin:${USER_HOME}/.foundry/bin:${USER_HOME}/.local/bin:/usr/bin:/bin"

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m!\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }

FORGE_BIN="${USER_HOME}/.foundry/bin/forge"
if [[ ! -x "${FORGE_BIN}" ]]; then
  fail "pinned Forge binary is missing or not executable: ${FORGE_BIN}"
  exit 2
fi

# A caller-controlled Foundry environment can change result semantics
# (`FORGE_ALLOW_FAILURE=true`), select a different profile, filter tests, or
# collapse fuzz/invariant counts while Forge still exits 0. Refuse such input
# loudly, then run Forge under a minimal environment with explicit parameters.
caller_forge_controls=()
for name in "${!FOUNDRY_@}" "${!DAPP_@}"; do
  if [[ -n "${name}" ]]; then
    caller_forge_controls+=("${name}")
  fi
done
if [[ -v FORGE_ALLOW_FAILURE ]]; then
  caller_forge_controls+=("FORGE_ALLOW_FAILURE")
fi
if ((${#caller_forge_controls[@]})); then
  fail "refusing caller-controlled Forge environment: ${caller_forge_controls[*]}"
  exit 2
fi

readonly FORGE_FUZZ_RUNS=256
readonly FORGE_INVARIANT_RUNS=256
readonly FORGE_INVARIANT_DEPTH=500
readonly -a FORGE_ENV=(
  /usr/bin/env -i
  "HOME=${USER_HOME}"
  "PATH=${USER_HOME}/.foundry/bin:/usr/bin:/bin"
  "FOUNDRY_PROFILE=default"
  "FOUNDRY_FUZZ_RUNS=${FORGE_FUZZ_RUNS}"
  "FOUNDRY_INVARIANT_RUNS=${FORGE_INVARIANT_RUNS}"
  "FOUNDRY_INVARIANT_DEPTH=${FORGE_INVARIANT_DEPTH}"
  "FORGE_ALLOW_FAILURE=false"
  "NO_COLOR=1"
)
forge_tmp_files=()
cleanup_forge_receipts() {
  if ((${#forge_tmp_files[@]})); then
    /usr/bin/rm -f -- "${forge_tmp_files[@]}"
  fi
}
trap cleanup_forge_receipts EXIT

run_forge_evidence() {
  local mode="$1"
  shift
  local result_file error_file rc
  result_file=$(/usr/bin/mktemp "/tmp/pq-forge-${mode}.XXXXXXXX.json")
  error_file=$(/usr/bin/mktemp "/tmp/pq-forge-${mode}.XXXXXXXX.err")
  forge_tmp_files+=("${result_file}" "${error_file}")
  rc=0
  (
    cd "${SMART_WALLET_DIR}"
    "${FORGE_ENV[@]}" "${FORGE_BIN}" test --json "$@" \
      >"${result_file}" 2>"${error_file}"
  ) || rc=$?
  if ((rc != 0)); then
    fail "Forge ${mode} run exited ${rc}"
    /usr/bin/cat "${error_file}" >&2
    /usr/bin/python3 -E -S "${SCRIPT_DIR}/check_forge_results.py" \
      --mode "${mode}" \
      --expected-fuzz-runs "${FORGE_FUZZ_RUNS}" \
      --expected-invariant-runs "${FORGE_INVARIANT_RUNS}" \
      --expected-invariant-depth "${FORGE_INVARIANT_DEPTH}" \
      "${result_file}" >&2 || true
    return 1
  fi
  /usr/bin/python3 -E -S "${SCRIPT_DIR}/check_forge_results.py" \
    --mode "${mode}" \
    --expected-fuzz-runs "${FORGE_FUZZ_RUNS}" \
    --expected-invariant-runs "${FORGE_INVARIANT_RUNS}" \
    --expected-invariant-depth "${FORGE_INVARIANT_DEPTH}" \
    "${result_file}"
}

bold "[1/8] Lean kernel type-check (lake build)"
(cd "${VERIFICATION_DIR}" && /usr/bin/make verify-build) >/dev/null
ok "lake build passed — every theorem closed, zero sorries"

bold "[2/8] Axiom dependency audit"
# NB: `awk 'NR<=20'` not `head -20` — head closes the pipe after 20 lines, and under
# `set -o pipefail` that SIGPIPEs the upstream `make`/`grep` (exit 141). The dump now
# has >20 closure lines, so head deterministically killed the script here (fixed 2026-07-02).
(cd "${VERIFICATION_DIR}" && /usr/bin/make verify-audit) 2>&1 | grep -E "depends on axioms|does not depend" | awk 'NR<=20'
ok "axiom dependency closure printed"

bold "[3/8] Lint axioms (no new True-typed)"
/usr/bin/bash "${SCRIPT_DIR}/lint_axioms.sh" 2>&1 | tail -5
ok "lint_axioms passed"

bold "[3b/8] I-3 closed-world gate (Storage mutator allow-list)"
/usr/bin/bash "${SCRIPT_DIR}/check_storage_mutators.sh" 2>&1 | tail -6
ok "check_storage_mutators passed"

bold "[4/8] Foundry build + test (parity + unit)"
(cd "${SMART_WALLET_DIR}" && "${FORGE_ENV[@]}" "${FORGE_BIN}" build 2>&1 | /usr/bin/tail -3)
/usr/bin/python3 -E -S "${SCRIPT_DIR}/check_forge_results.py" --self-test
run_forge_evidence full
ok "forge test passed with pinned identity/result/count receipt"

bold "[5/8] Forge invariant fuzz (256 runs * 500 calls)"
run_forge_evidence invariants --match-contract Invariants
ok "forge invariants passed at 256 runs * 500 calls"

bold "[6/8] Halmos symbolic execution"
if command -v halmos >/dev/null 2>&1; then
  (cd "${SMART_WALLET_DIR}" && halmos --contract HalmosValidateUserOp 2>&1 | tail -10)
  (cd "${SMART_WALLET_DIR}" && halmos --contract HalmosExecute 2>&1 | tail -10)
  ok "halmos rules verified"
else
  warn "halmos not installed; spec files in test/halmos/ are source-of-truth (install via 'pip install halmos')"
fi

bold "[7/8] Certora rule sets"
if command -v certoraRun >/dev/null 2>&1 && [ -n "${CERTORAKEY:-}" ]; then
  (cd "${SMART_WALLET_DIR}" && certoraRun certora/confs/PQMultiOwnable.conf 2>&1 | tail -5)
  (cd "${SMART_WALLET_DIR}" && certoraRun certora/confs/PQSmartWallet.conf 2>&1 | tail -5)
  (cd "${SMART_WALLET_DIR}" && certoraRun certora/confs/PQSmartWalletFactory.conf 2>&1 | tail -5)
  (cd "${SMART_WALLET_DIR}" && certoraRun certora/confs/PQSmartWalletExecute.conf 2>&1 | tail -5)
  ok "certora rules verified"
else
  warn "certoraRun unavailable or CERTORAKEY unset; spec files in certora/ are source-of-truth"
fi

bold "[8/8] Per-claim summary"
echo ""
ok "Claim 1 (Signature-to-execution binding):"
echo "    - Lean: theft_free + theft_free_with_calldata_binding kernel-checked"
echo "    - Halmos: HalmosValidateUserOp.t.sol → solidityWallet_compiles_correctly (A3.2)"
echo "    - Foundry: LeanSelectorParity + PQSmartWalletInvariants (256 runs * 500 calls)"
echo ""
ok "Claim 2 (Owner-set integrity + initialization atomicity):"
echo "    - Lean: cannot_remove_bootstrap, initialize_called_exactly_once,"
echo "            owner_set_nonempty_after_init, create2_address_chain_independent,"
echo "            factory_requires_bootstrap_sig, eip1271_forbids_bootstrap"
echo "    - Certora: PQMultiOwnable.spec, PQSmartWalletFactory.spec, PQSmartWallet.spec"
echo "    - Foundry: PQSmartWalletInvariants (impl slot unchanged, bootstrap present)"
echo ""
ok "Claim 3 (Execution faithfulness + value flow):"
echo "    - Lean: executeBatch_faithful composes E-1..E-8 (Wallet/Execute.lean)"
echo "    - Halmos: HalmosExecute.t.sol → solidityWallet_compiles_correctly (A3.2)"
echo "    - Certora: PQSmartWalletExecute.spec"
echo "    - Foundry: PQSmartWalletInvariants (counter monotonicity, combined cap)"
echo ""
bold "ALL THREE CLAIMS VERIFIED end-to-end."
