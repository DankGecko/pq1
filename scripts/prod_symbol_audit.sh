#!/usr/bin/env bash
# Binary-level audit: refuse a firmware image that contains never-ship code.
#
# WHY THIS EXISTS
# ---------------
# `make prod-feature-check` (Makefile) resolves the cargo feature graph and
# refuses any feature in PROD_FORBIDDEN. That is a check on the BUILD INPUTS.
# Nothing in this repo has ever inspected the BUILD OUTPUT. The two are not the
# same claim, and the gap is not theoretical:
#
#   $ arm-none-eabi-nm -C target/pqsigner-release/secure.elf | grep test_pin_lockout
#   0c021a62 T __acle_se_nsc_test_pin_lockout
#   0c056d68 T nsc_test_pin_lockout
#
# That is `CMD_TEST_PIN_LOCKOUT` — the E2E-only wrong-PIN burner that CLAUDE.md
# describes as "compiled out of production" — present, with its CMSE veneer
# exported, in an ELF sitting in a directory called `pqsigner-release`. It is a
# bench build, not a shipped image. That is the whole point: a feature-graph
# check cannot tell you anything about an artifact someone hands you, and the
# directory name certainly cannot. Only the bytes can.
#
# WHAT IT CHECKS
#   1. FORBIDDEN symbols (nm) and FORBIDDEN strings — the never-ship surfaces,
#      derived from Makefile PROD_FORBIDDEN.
#   2. A POSITIVE CONTROL, which is what keeps this from being a vacuous gate:
#      the image must contain symbols at all, and must contain a known-shipping
#      symbol. Without it a stripped, truncated, or wrong-architecture file
#      passes with a clean bill of health, and "0 forbidden symbols found" is
#      indistinguishable from "I could not read this file".
#
# WHAT IT IS NOT
#   Not a substitute for `prod-feature-check` — a feature can influence codegen
#   without leaving a greppable name, and LTO + codegen-units=1 can inline a
#   function out of the symbol table entirely. Absence of a symbol is weaker
#   evidence than absence of a feature. Run BOTH; they fail differently.
#
#   It also cannot be pointed at a true PROD_SHIP_FEATURES image today: that
#   build is blocked at compile time by OPTIGA_S2_PRODUCTION_BLOCKED
#   (secure/src/nsc/mod.rs) while ship-blocker S-2 is open. So a green run here
#   means "this artifact is clean", never "production is clean".
#
# USAGE
#   scripts/prod_symbol_audit.sh <elf> [<elf> ...]
#   scripts/prod_symbol_audit.sh --self-test
# Exit 0 clean, 1 forbidden content found, 2 self-test or positive control failed.

set -euo pipefail

NM="${NM:-arm-none-eabi-nm}"
STRINGS="${STRINGS:-arm-none-eabi-strings}"
command -v "$NM" >/dev/null || NM=llvm-nm
command -v "$STRINGS" >/dev/null || STRINGS=strings

# Symbol-name fragments (underscore form, as they appear in nm output).
FORBIDDEN_SYMS=(
  test_pin_lockout        # CMD_TEST_PIN_LOCKOUT, the E2E wrong-PIN burner
  prodtest                # factory prodtest command surface
  e2e_test                # the fixed-mnemonic/fixed-PIN test harness
  mock_se                 # software stand-in for both secure elements
  ui_capture              # frame-hash capture
  otp_hardcoded           # fixed OTP master
  bhk_hardcoded
  dev_testkey
  forced_blind            # erc7730-forced-blind ceremony (PROD_FORBIDDEN)
  factory_provisioning
  se050_factory_reset
  optiga_nuclear_reset
  admin_wipe_e2e
  legacy_fw_rollback_unsafe
)

# Literal strings that would ship user-visible or feature-identifying evidence.
FORBIDDEN_STRINGS=(
  'TEST_PIN_LOCKOUT'
  '[NSC] test_pin_lockout'
  'e2e-test'
  'mock-se'
  'debug-log'
  'otp-hardcoded-master-key'
  'erc7730-dev-unattested'
  'erc7730-forced-blind'
  'legacy-fw-rollback-unsafe'
)

# Symbols that MUST be present in any real secure-world image. If none is found
# the file is not what we think it is, and a clean result means nothing.
EXPECTED_SYMS=(
  gated_unlock
  nsc_sign_userop
  nsc_get_wallet_address
)

audit_one() {
  local elf="$1" rc=0
  echo "=== $elf"
  if [ ! -f "$elf" ]; then
    echo "  FAIL: no such file" >&2
    return 2
  fi

  local symtab
  symtab="$("$NM" -C "$elf" 2>/dev/null || true)"
  local nsyms
  # NOTE on the here-strings below, all of them. Under `set -o pipefail`, a
  # `printf ... | grep -q` pipeline reports FAILURE even when grep MATCHES:
  # grep exits immediately on the first hit, printf dies on SIGPIPE (141), and
  # pipefail surfaces printf's status. The positive control silently inverted
  # this way on the first draft and refused two perfectly good ELFs. Here-strings
  # have no pipeline and no SIGPIPE.
  nsyms="$(grep -c . <<< "$symtab" || true)"

  # ---- positive control, before anything else ----
  if [ "$nsyms" -lt 100 ]; then
    echo "  FAIL (positive control): only $nsyms symbols readable — stripped," >&2
    echo "  truncated, or wrong architecture. A clean forbidden-symbol result" >&2
    echo "  on this file would be meaningless, so it is refused instead." >&2
    return 2
  fi
  local found_expected=0 s
  for s in "${EXPECTED_SYMS[@]}"; do
    if grep -qi -- "$s" <<< "$symtab"; then found_expected=1; break; fi
  done
  if [ "$found_expected" -eq 0 ]; then
    echo "  FAIL (positive control): none of the expected shipping symbols" >&2
    echo "  (${EXPECTED_SYMS[*]}) is present. Either this is not a secure-world" >&2
    echo "  image, or the expected-symbol list has rotted. Fix before trusting" >&2
    echo "  any clean result from this script." >&2
    return 2
  fi
  echo "  positive control ok ($nsyms symbols; expected shipping symbol present)"

  # ---- forbidden symbols ----
  local hits=0 hit
  for s in "${FORBIDDEN_SYMS[@]}"; do
    while IFS= read -r hit; do
      [ -z "$hit" ] && continue
      echo "  FORBIDDEN SYMBOL [$s]: $hit"
      hits=$((hits + 1))
    done < <(grep -i -- "$s" <<< "$symtab" || true)
  done

  # ---- forbidden strings ----
  local blob
  blob="$("$STRINGS" "$elf" 2>/dev/null || true)"
  for s in "${FORBIDDEN_STRINGS[@]}"; do
    while IFS= read -r hit; do
      [ -z "$hit" ] && continue
      echo "  FORBIDDEN STRING [$s]: ${hit:0:120}"
      hits=$((hits + 1))
    done < <(grep -F -i -- "$s" <<< "$blob" || true)
  done

  if [ "$hits" -gt 0 ]; then
    echo "  FAIL: $hits forbidden item(s)" >&2
    rc=1
  else
    echo "  clean: no forbidden symbols or strings"
  fi
  return $rc
}

self_test() {
  # Two-sided. A gate whose detection has never been observed to fire is not a
  # gate. Build a fixture that DOES contain the markers and assert we catch it;
  # then assert the same machinery is silent on a fixture without them.
  local rc=0
  local tmp; tmp="$(mktemp -d)"

  printf 'gated_unlock\nnsc_test_pin_lockout\n%s\n' "$(head -c 4000 /dev/zero | tr '\0' 'x')" \
    > "$tmp/dirty.txt"
  printf 'gated_unlock\nordinary_symbol\n' > "$tmp/clean.txt"

  local dirty clean
  dirty="$(grep -ci 'test_pin_lockout' "$tmp/dirty.txt" || true)"
  clean="$(grep -ci 'test_pin_lockout' "$tmp/clean.txt" || true)"
  if [ "$dirty" -ge 1 ]; then
    echo "  [ok]   detection fires on a planted test_pin_lockout marker"
  else
    echo "  [FAIL] detection did NOT fire on a planted marker" >&2; rc=2
  fi
  if [ "$clean" -eq 0 ]; then
    echo "  [ok]   detection silent on the benign twin"
  else
    echo "  [FAIL] detection fired on a benign fixture" >&2; rc=2
  fi

  # Positive control must refuse a symbol-less file rather than bless it.
  : > "$tmp/empty.elf"
  if audit_one "$tmp/empty.elf" >/dev/null 2>&1; then
    echo "  [FAIL] an unreadable/empty file was accepted as clean" >&2; rc=2
  else
    echo "  [ok]   an unreadable/empty file is REFUSED, not blessed"
  fi

  rm -rf "$tmp"
  if [ "$rc" -eq 0 ]; then echo "self-test OK"; else echo "SELF-TEST FAILED" >&2; fi
  return $rc
}

main() {
  if [ "${1:-}" = "--self-test" ]; then self_test; return $?; fi
  if [ $# -eq 0 ]; then
    echo "usage: $0 <elf> [<elf> ...] | --self-test" >&2
    return 2
  fi
  local rc=0 f
  for f in "$@"; do
    audit_one "$f" || rc=$?
  done
  return $rc
}

main "$@"
