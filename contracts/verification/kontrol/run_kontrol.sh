#!/usr/bin/env bash
# Turnkey Kontrol (KEVM) proof runner for the PQSmartWallet model-to-bytecode
# bridge (axioms A3.2 / A3.3 / A3.4) — KEVM symbolic-execution proofs DIRECTLY
# against the deployed runtime bytecode, an engine independent of Halmos with no
# hand-written LeanModel.sol mirror in the loop. REQUIRES a working K Framework
# backend (`kompile`, `kore-rpc-booster`); install via `kup install kontrol`
# (Nix) or the runtimeverification/kontrol Docker image. See
# ../docs/KONTROL_SCOPING.md.
#
# Stages EVERY harness under kontrol/test/ into the smart-wallet Foundry project
# (so its remappings + lib submodules resolve), then runs `kontrol build` +
# `kontrol prove` over all Kontrol* test contracts, then asserts the proof
# results against the pinned identity baseline below (fv-deep-review-2026-07-19
# F9 / sweep-F52 / tracker #197).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SW="$HERE/../../smart-wallet"            # the Foundry project (has lib/ + remappings)
SRC_DIR="$HERE/test"                     # all Kontrol harnesses live here
DEST_DIR="$SW/test/kontrol"

# --- Proof-identity baseline (fv-deep-review-2026-07-19 F9 / sweep-F52) ------
# Every `prove_*` function wired under kontrol/test/, as
# <Contract>.<function>. Verified 2026-07-19 against the tree: 33 proofs
# across 5 harnesses — KontrolValidateUserOp 7, KontrolExecute 8,
# KontrolOwnerTable 9, KontrolFactory 6, KontrolBootstrapUnremovable 3 —
# matching the 33/33 discharge recorded in ../docs/KONTROL_SCOPING.md
# (2026-06-15; the 2026-07-18 sweep's "38 prove_ functions" was a miscount).
# Bump this list when adding/removing a proof; fv-deep-review-2026-07-19 F9.
EXPECTED_PROOFS=(
  KontrolBootstrapUnremovable.prove_bootstrap_unremovable_from_entrypoint
  KontrolBootstrapUnremovable.prove_bootstrap_unremovable_exact_bytes
  KontrolBootstrapUnremovable.prove_bootstrap_remove_rejected_non_entrypoint
  KontrolExecute.prove_execute_requires_entrypoint
  KontrolExecute.prove_execute_no_credit_reverts
  KontrolExecute.prove_execute_rejects_self_target
  KontrolExecute.prove_execute_pointwise
  KontrolExecute.prove_execute_credit_one_shot
  KontrolExecute.prove_execute_atomic_on_reverting_target
  KontrolExecute.prove_executeBatch_rejects_self_target
  KontrolExecute.prove_executeBatch_pointwise
  KontrolFactory.prove_createAccount_iff
  KontrolFactory.prove_createAccount_rejects_non_nmasked_slot0
  KontrolFactory.prove_createAccount_rejects_non_nmasked_master
  KontrolFactory.prove_createAccount_rejects_duplicate_slot0
  KontrolFactory.prove_createAccount_rejects_wrong_chain
  KontrolFactory.prove_createAccount_already_deployed_returns_existing
  KontrolOwnerTable.prove_addOwner_len64_pointwise
  KontrolOwnerTable.prove_addOwner_rejects_len63
  KontrolOwnerTable.prove_addOwner_rejects_len65
  KontrolOwnerTable.prove_removeOwner_installed_pointwise
  KontrolOwnerTable.prove_removeOwner_unset_rejects
  KontrolOwnerTable.prove_initialize_one_shot
  KontrolOwnerTable.prove_initialize_fresh_pointwise
  KontrolOwnerTable.prove_addOwner_rejects_non_entrypoint
  KontrolOwnerTable.prove_removeOwner_rejects_non_entrypoint
  KontrolValidateUserOp.prove_validate_slot_nonbypass
  KontrolValidateUserOp.prove_validate_bootstrap_nonbypass
  KontrolValidateUserOp.prove_validate_rejects_unset_owner
  KontrolValidateUserOp.prove_validate_rejects_non_entrypoint
  KontrolValidateUserOp.prove_validate_rejects_bad_offset
  KontrolValidateUserOp.prove_validate_rejects_bad_innerlen
  KontrolValidateUserOp.prove_validate_rejects_bad_tailpad
)

# check_proof_inventory: the pinned baseline must match the wired tree — a
# prove_* landing without a baseline bump must not silently go green.
check_proof_inventory() {
  local wired
  wired=$(grep -hoE "function prove_[A-Za-z0-9_]+" "$SRC_DIR"/*.t.sol | sort -u | wc -l)
  if [ "$wired" -ne "${#EXPECTED_PROOFS[@]}" ]; then
    echo "==> FAIL: $SRC_DIR wires $wired prove_* functions but the baseline lists ${#EXPECTED_PROOFS[@]} — bump EXPECTED_PROOFS (fv-deep-review-2026-07-19 F9)" >&2
    return 1
  fi
}

# `kontrol list` prints one blank-line-separated block per proof (pyk
# APRSummary.lines), of the form:
#   APRProof: test%kontrol%KontrolExecute.prove_execute_pointwise(uint256,uint256):0
#       status: ProofStatus.PASSED        ('status: PASSED' also accepted)
#       admitted: False
#       nodes / pending / failing / ...
#   Subproofs: 0
# _kontrol_list_passed_ids prints the PASSED, non-admitted proof ids in a
# kontrol-list file, normalized to <Contract>.<function>. Line-based (no
# multiline-record regexes) so it behaves identically under gawk and mawk.
_kontrol_list_passed_ids() {
  awk '
    function flush() { if (hdr != "" && pass && !admit) print norm(hdr); hdr=""; pass=0; admit=0 }
    function norm(pid) { sub(/\(.*/, "", pid); sub(/.*%/, "", pid); return pid }
    /^APRProof: |^Proof: /                        { flush(); hdr=$2 }
    /^    status: (ProofStatus\.)?PASSED[[:space:]]*$/ { pass=1 }
    /^    admitted: True[[:space:]]*$/            { admit=1 }
    NF==0                                         { flush() }
    END                                           { flush() }
  ' "$1"
}

# assert_kontrol_list <kontrol-list-output-file>: count floor (>= baseline
# size) PLUS a per-id grep for every expected proof — both, by design (F9).
assert_kontrol_list() {
  local listfile="$1"
  local passed_ids npassed id rc=0
  passed_ids=$(_kontrol_list_passed_ids "$listfile" | sort -u)
  npassed=$(printf '%s\n' "$passed_ids" | grep -c . || true)
  if [ "$npassed" -lt "${#EXPECTED_PROOFS[@]}" ]; then
    echo "==> FAIL: 'kontrol list' shows $npassed PASSED proofs; the identity baseline is ${#EXPECTED_PROOFS[@]} (count floor, fv-deep-review-2026-07-19 F9)" >&2
    rc=1
  fi
  for id in "${EXPECTED_PROOFS[@]}"; do
    if ! printf '%s\n' "$passed_ids" | grep -qxF "$id"; then
      echo "==> FAIL: expected proof is not PASSED in 'kontrol list': $id" >&2
      rc=1
    fi
  done
  return "$rc"
}

# self_test: positive + negative controls for assert_kontrol_list, against
# synthetic `kontrol list` fixtures (no K backend needed).
self_test() {
  local d; d="$(mktemp -d /tmp/pq1-kontrol-baseline-selftest.XXXXXX)"
  local mk_block
  mk_block() {  # <id> <status> <admitted>
    printf 'APRProof: test%%kontrol%%%s():0\n    status: %s\n    admitted: %s\n    nodes: 7\n    pending: 0\n    failing: 0\n    vacuous: 0\n    stuck: 0\n    terminal: 3\n    refuted: 0\n    bounded: 0\n    execution time: 0m1s\nSubproofs: 0\n\n' "$1" "$2" "$3"
  }
  local id rc=0
  # complete fixture: all expected proofs PASSED, none admitted
  : > "$d/complete.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do mk_block "$id" "ProofStatus.PASSED" "False" >> "$d/complete.txt"; done
  # missing-one: drop the last expected proof
  : > "$d/missing.txt"
  for id in "${EXPECTED_PROOFS[@]:0:$((${#EXPECTED_PROOFS[@]}-1))}"; do mk_block "$id" "ProofStatus.PASSED" "False" >> "$d/missing.txt"; done
  # failed-one: one proof FAILED
  : > "$d/failed.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do
    if [ "$id" = "KontrolExecute.prove_execute_pointwise" ]; then mk_block "$id" "ProofStatus.FAILED" "False" >> "$d/failed.txt"; else mk_block "$id" "ProofStatus.PASSED" "False" >> "$d/failed.txt"; fi
  done
  # admitted-one: one proof PASSED but admitted (not a real proof)
  : > "$d/admitted.txt"
  for id in "${EXPECTED_PROOFS[@]}"; do
    if [ "$id" = "KontrolFactory.prove_createAccount_iff" ]; then mk_block "$id" "ProofStatus.PASSED" "True" >> "$d/admitted.txt"; else mk_block "$id" "ProofStatus.PASSED" "False" >> "$d/admitted.txt"; fi
  done
  # empty fixture
  : > "$d/empty.txt"

  echo "-- self-test 1/5: complete fixture (${#EXPECTED_PROOFS[@]} PASSED) — must be ACCEPTED"
  if assert_kontrol_list "$d/complete.txt" >/dev/null 2>&1; then echo "   OK: accepted"; else echo "   CONTROL FAILURE: rejected a complete list" >&2; rc=1; fi
  echo "-- self-test 2/5: missing-one fixture ($((${#EXPECTED_PROOFS[@]}-1)) PASSED) — must be REJECTED"
  if assert_kontrol_list "$d/missing.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: missing proof accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 3/5: failed-status fixture — must be REJECTED"
  if assert_kontrol_list "$d/failed.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: FAILED proof accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 4/5: admitted-proof fixture — must be REJECTED"
  if assert_kontrol_list "$d/admitted.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: admitted proof accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  echo "-- self-test 5/5: empty fixture — must be REJECTED"
  if assert_kontrol_list "$d/empty.txt" >/dev/null 2>&1; then echo "   CONTROL FAILURE: green-at-zero accepted!" >&2; rc=1; else echo "   OK: rejected"; fi
  rm -rf "$d"
  if [ "$rc" -eq 0 ]; then
    echo "run_kontrol.sh --self-test: all controls behave"
  else
    echo "run_kontrol.sh --self-test: CONTROL FAILURE" >&2
  fi
  return "$rc"
}

case "${1:-}" in
  --self-test)
    self_test
    exit $?
    ;;
  --check-output)
    [ $# -eq 2 ] || { echo "usage: $0 --check-output <kontrol-list-output-file>" >&2; exit 2; }
    check_proof_inventory
    assert_kontrol_list "$2"
    exit $?
    ;;
esac

# NOTE: `kompile` / `kore-rpc-booster` are NOT expected on the outer PATH when
# Kontrol is installed via `kup install kontrol` (Nix) — the `kontrol` wrapper
# prepends its OWN bundled K backend (k-<ver>/bin) internally. So we require
# only the `kontrol` CLI; it self-contains the symbolic-execution engine.
command -v kontrol >/dev/null 2>&1 || {
  echo "ERROR: 'kontrol' CLI not found. Install with:"
  echo "         bash <(curl https://kframework.org/install)   # installs kup (Nix)"
  echo "         kup install kontrol"
  echo "       or use the runtimeverification/kontrol Docker image."
  echo "       See ../docs/KONTROL_SCOPING.md."
  exit 2
}

# kontrol-cheatcodes (symbolic helpers) is a TRANSIENT kontrol artifact and must
# NOT linger in the smart-wallet lib/: Foundry auto-generates a remapping for
# every lib/ dir and folds the remapping list into solc metadata, so its mere
# presence shifts EVERY pinned contract codehash and turns the codehash freeze
# tests (`forge test`) red — a phantom failure for anyone who has run Kontrol.
# So we (a) install it only when a staged harness actually imports it (deferred
# until after staging; current harnesses use only forge-std cheatcodes), and
# (b) remove it on exit so a later `forge test` / CI sees the canonical
# foundry.lock lib set. See work-todo §34 + docs/KONTROL_SCOPING.md.
KCC_DIR="$SW/lib/kontrol-cheatcodes"
cleanup() {
  if [ -d "$KCC_DIR" ]; then
    rm -rf "$KCC_DIR"
    echo "Removed transient kontrol-cheatcodes from lib/ (keeps codehash pins canonical)."
  fi
}
trap cleanup EXIT

check_proof_inventory

mkdir -p "$DEST_DIR"
# Stage every Kontrol harness, rewriting the repo-relative imports to the
# in-project location.
for h in "$SRC_DIR"/*.t.sol; do
  base="$(basename "$h")"
  sed 's#\.\./\.\./\.\./smart-wallet/src/#../../src/#g; s#\.\./\.\./\.\./smart-wallet/test/mocks/#../mocks/#g' \
    "$h" > "$DEST_DIR/$base"
  echo "Staged harness -> $DEST_DIR/$base"
done

# Install kontrol-cheatcodes ONLY if a staged harness imports it. The EXIT trap
# above removes it again afterward, so the common forge-std-only case never
# leaves lib/ polluted for the next `forge test` / CI codehash freeze check.
if grep -rqlE "kontrol-cheatcodes|KontrolCheats|KEVMCheats" "$DEST_DIR"/*.t.sol 2>/dev/null; then
  if [ ! -d "$KCC_DIR" ]; then
    echo "A staged harness imports kontrol-cheatcodes; installing transiently ..."
    ( cd "$SW" && forge install runtimeverification/kontrol-cheatcodes ) || true
  fi
fi

cd "$SW"
# Force the staged harnesses to recompile under kontrol's own
# `forge build --extra-output storageLayout ...`. A prior plain `forge build`
# can leave a harness artifact WITHOUT storageLayout, which `kontrol build`'s
# incremental forge step won't refresh, and kontrol then SILENTLY SKIPS the
# contract as "non-compatible JSON" (→ "Test identifiers not found" at prove).
for h in "$DEST_DIR"/*.t.sol; do rm -rf "out/$(basename "$h")"; done

# NOTE (2026-07-02, finding kontrol-gate-not-codehash-anchored): unlike run_halmos.sh
# — which runs PinnedCodehashes / PinnedBytecodeImmutableLemma / DeployedBytecodeReproCheck
# BEFORE its symbolic pass — this gate proves against whatever `kontrol build` emits from
# the current tree, with NO in-flow codehash certification. "Directly on the deployed
# bytecode" (THE_CLAIM / KONTROL_SCOPING) is anchored EXTERNALLY: the `contracts` CI job's
# codehash-freeze (test/PinnedCodehashes.t.sol) fails on any drift from the pinned/on-chain
# codehash, so on an undrifted tree the built bytecode matches the pins. A source drift would
# be proven against the drifted bytecode here without THIS gate flagging it — the freeze test
# is the tripwire, not run_kontrol.sh.
echo "=== kontrol build ==="
kontrol build --verbose

# Prove every `prove_*` test in the Kontrol* harnesses. `--match-test` is a
# regex over the full `Contract.func(sig)` name (override with MATCH=..., or the
# worker count with KONTROL_WORKERS=...).
echo "=== kontrol prove (all Kontrol*.prove_* tests) ==="
kontrol prove \
  --match-test "${MATCH:-Kontrol.*\.prove_}" \
  --use-booster --workers "${KONTROL_WORKERS:-4}" --verbose

echo "=== kontrol list (proof status) ==="
KONTROL_LIST_OUT="${TMPDIR:-/tmp}/pq1-kontrol-list-$(date +%Y%m%d-%H%M%S).txt"
kontrol list | tee "${KONTROL_LIST_OUT}"

# Identity baseline (fv-deep-review-2026-07-19 F9 / sweep-F52): fail unless
# every pinned EXPECTED_PROOFS entry appears PASSED (non-admitted) in
# `kontrol list` — a silent skip ("Test identifiers not found", a dropped
# harness, an empty proof set) must not go green.
assert_kontrol_list "${KONTROL_LIST_OUT}" || {
  echo "==> FAIL: Kontrol proof-identity baseline not met (see ${KONTROL_LIST_OUT})" >&2
  exit 1
}
echo "==> PASS: all ${#EXPECTED_PROOFS[@]} expected proofs PASSED in 'kontrol list' (identity baseline, F9)"
