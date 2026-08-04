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
#   2. POSITIVE CONTROLS, which keep this from being a vacuous gate: the image
#      must contain symbols, a known-shipping symbol, the cfg-coupled hardware
#      backend receipt, the complete STM32+OPTIGA+SE050 source-set receipt, and
#      the SE050 SCP03 R-MAC duplicate-verifier + R-ENC decrypt-relation
#      receipts (the F-28 / wave-18 fail-initialized authentication gates).
#      Host/incomplete receipts, host RNG symbols, `/dev/urandom`, and the
#      Coldcard fallback name are forbidden.
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
  host_rng               # QEMU semihosting backend, never hardware firmware
  yasmarang               # non-cryptographic MicroPython fallback (Coldcard class)
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
  '/dev/urandom'
  'PQ1_RNG_BACKEND=HOST_URANDOM'
  'PQ1_STRONG_RNG_SOURCES=DEVELOPMENT_OR_INCOMPLETE'
  'yasmarang'
)

# These byte strings live in `.pqsigner.rng_backend` under the exact cfg
# predicates that select `hw::rng` and the complete strong source set.
EXPECTED_RNG_MARKER='PQ1_RNG_BACKEND=STM32U585_TRNG'
EXPECTED_STRONG_RNG_MARKER='PQ1_STRONG_RNG_SOURCES=STM32U585+OPTIGA_TRUST_M+SE050'

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

  local blob
  blob="$("$STRINGS" "$elf" 2>/dev/null || true)"
  local rng_marker_count rng_symbol_count strong_marker_count strong_symbol_count
  local chunk_selector_count progress_initializer_count progress_publisher_count
  local exact_copy_count region_pointer_publisher_count word_progress_publisher_count
  local se050_progress_publisher_count stm32_word_relation_count
  local stm32_fill_bound_count stm32_fill_binding_count strong_history_relation_count
  local optiga_ccm_decrypt_count optiga_ccm_verify_count optiga_ccm_match_count
  local optiga_protected_send_count optiga_sequence_verify_count optiga_sequence_commit_count
  local optiga_sequence_reserve_tx_count scp03_rmac_verify_count scp03_renc_verify_count
  rng_marker_count="$(grep -Fxc -- "$EXPECTED_RNG_MARKER" <<< "$blob" || true)"
  rng_symbol_count="$(grep -Ec '[[:space:]]PQSIGNER_RNG_BACKEND$' <<< "$symtab" || true)"
  strong_marker_count="$(grep -Fxc -- "$EXPECTED_STRONG_RNG_MARKER" <<< "$blob" || true)"
  strong_symbol_count="$(grep -Ec '[[:space:]]PQSIGNER_STRONG_RNG_SOURCES$' <<< "$symtab" || true)"
  chunk_selector_count="$(grep -Ec '[[:space:]]pqsigner_rng_source_chunk_len$' <<< "$symtab" || true)"
  progress_initializer_count="$(grep -Ec 'rng_exact::initialize_exact_progress_into$' <<< "$symtab" || true)"
  exact_copy_count="$(grep -Ec 'rng_exact::copy_exact_into$' <<< "$symtab" || true)"
  region_pointer_publisher_count="$(grep -Ec 'rng_exact::publish_region_pointer_into$' <<< "$symtab" || true)"
  progress_publisher_count="$(grep -Ec 'rng_strong_fold::publish_verified_progress_into$' <<< "$symtab" || true)"
  word_progress_publisher_count="$(grep -Ec 'hw::rng::publish_verified_word_progress_into$' <<< "$symtab" || true)"
  se050_progress_publisher_count="$(grep -Ec 'se050::apdu::publish_verified_get_random_progress_into$' <<< "$symtab" || true)"
  stm32_word_relation_count="$(grep -Ec 'hw::rng::verify_current_word_fragment_into$' <<< "$symtab" || true)"
  stm32_fill_bound_count="$(grep -Ec '[[:space:]]pqsigner_hw_rng_fill_bound$' <<< "$symtab" || true)"
  stm32_fill_binding_count="$(grep -Ec 'hw::rng::verify_fill_region_binding_into$' <<< "$symtab" || true)"
  strong_history_relation_count="$(grep -Ec 'rng_strong_fold::verify_committed_source_history_into$' <<< "$symtab" || true)"
  optiga_ccm_decrypt_count="$(grep -Ec '[[:space:]]pqsigner_optiga_ccm_decrypt_into$' <<< "$symtab" || true)"
  optiga_ccm_verify_count="$(grep -Ec '[[:space:]]pqsigner_optiga_ccm_verify_into$' <<< "$symtab" || true)"
  optiga_ccm_match_count="$(grep -Ec '[[:space:]]pqsigner_optiga_ccm_tag_matches$' <<< "$symtab" || true)"
  optiga_protected_send_count="$(grep -Ec '[[:space:]]pqsigner_optiga_send_command_protected$' <<< "$symtab" || true)"
  optiga_sequence_verify_count="$(grep -Ec '[[:space:]]pqsigner_optiga_sequence_verify_into$' <<< "$symtab" || true)"
  optiga_sequence_commit_count="$(grep -Ec '[[:space:]]pqsigner_optiga_sequence_commit_into$' <<< "$symtab" || true)"
  optiga_sequence_reserve_tx_count="$(grep -Ec '[[:space:]]pqsigner_optiga_sequence_reserve_tx_into$' <<< "$symtab" || true)"
  scp03_rmac_verify_count="$(grep -Ec '[[:space:]]pqsigner_se050_scp03_rmac_verify_into$' <<< "$symtab" || true)"
  scp03_renc_verify_count="$(grep -Ec '[[:space:]]pqsigner_se050_scp03_renc_verify_into$' <<< "$symtab" || true)"
  if [ "$rng_marker_count" -ne 1 ] || [ "$rng_symbol_count" -ne 1 ] \
    || [ "$strong_marker_count" -ne 1 ] || [ "$strong_symbol_count" -ne 1 ] \
    || [ "$chunk_selector_count" -ne 1 ] || [ "$progress_initializer_count" -ne 1 ] \
    || [ "$exact_copy_count" -ne 1 ] || [ "$region_pointer_publisher_count" -ne 1 ] \
    || [ "$progress_publisher_count" -ne 1 ] || [ "$word_progress_publisher_count" -ne 1 ] \
    || [ "$se050_progress_publisher_count" -ne 1 ] || [ "$stm32_word_relation_count" -ne 1 ] \
    || [ "$stm32_fill_bound_count" -ne 1 ] || [ "$stm32_fill_binding_count" -ne 1 ] \
    || [ "$strong_history_relation_count" -ne 1 ] || [ "$optiga_ccm_decrypt_count" -ne 1 ] \
    || [ "$optiga_ccm_verify_count" -ne 1 ] || [ "$optiga_ccm_match_count" -ne 1 ] \
    || [ "$optiga_protected_send_count" -ne 1 ] || [ "$optiga_sequence_verify_count" -ne 1 ] \
    || [ "$optiga_sequence_commit_count" -ne 1 ] || [ "$optiga_sequence_reserve_tx_count" -ne 1 ] \
    || [ "$scp03_rmac_verify_count" -ne 1 ] || [ "$scp03_renc_verify_count" -ne 1 ]; then
    echo "  FAIL (RNG positive control): expected exactly one receipt for" >&2
    echo "  the hardware backend and exactly one complete three-source set" >&2
    echo "  backend_marker=$rng_marker_count backend_symbol=$rng_symbol_count" >&2
    echo "  strong_marker=$strong_marker_count strong_symbol=$strong_symbol_count" >&2
    echo "  generic_chunk_selector=$chunk_selector_count" >&2
    echo "  exact_progress_initializer=$progress_initializer_count" >&2
    echo "  raw_distinct_exact_copy=$exact_copy_count" >&2
    echo "  bound_region_pointer_publisher=$region_pointer_publisher_count" >&2
    echo "  verified_progress_publisher=$progress_publisher_count" >&2
    echo "  stm32_word_progress_publisher=$word_progress_publisher_count" >&2
    echo "  se050_progress_publisher=$se050_progress_publisher_count" >&2
    echo "  stm32_current_word_relation=$stm32_word_relation_count" >&2
    echo "  stm32_duplicated_entry_boundary=$stm32_fill_bound_count" >&2
    echo "  stm32_fill_region_binding=$stm32_fill_binding_count" >&2
    echo "  strong_source_history_relation=$strong_history_relation_count" >&2
    echo "  optiga_ccm_receipt_decrypt=$optiga_ccm_decrypt_count" >&2
    echo "  optiga_ccm_duplicate_verifier=$optiga_ccm_verify_count" >&2
    echo "  optiga_ccm_independent_tag_match=$optiga_ccm_match_count" >&2
    echo "  optiga_protected_only_send=$optiga_protected_send_count" >&2
    echo "  optiga_sequence_window_verifier=$optiga_sequence_verify_count" >&2
    echo "  optiga_sequence_state_commit=$optiga_sequence_commit_count" >&2
    echo "  optiga_sequence_tx_reservation=$optiga_sequence_reserve_tx_count" >&2
    echo "  se050_scp03_rmac_duplicate_verifier=$scp03_rmac_verify_count" >&2
    echo "  se050_scp03_renc_relation_verifier=$scp03_renc_verify_count" >&2
    echo "  The artifact does not prove unique selection of STM32U585 plus" >&2
    echo "  both mandatory secure-element entropy backends." >&2
    return 2
  fi
  echo "  RNG backend receipts, exact relation checks, generic chunk selector, and all verified progress helpers ok ($EXPECTED_RNG_MARKER; $EXPECTED_STRONG_RNG_MARKER)"

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

  printf '%s\n' "$EXPECTED_RNG_MARKER" > "$tmp/hw-marker.txt"
  printf '%s\n' 'PQ1_RNG_BACKEND=HOST_URANDOM' > "$tmp/host-marker.txt"
  printf '%s\n%s\n' "$EXPECTED_RNG_MARKER" "$EXPECTED_RNG_MARKER" \
    > "$tmp/duplicate-marker.txt"
  local hw_count host_count duplicate_count
  hw_count="$(grep -Fxc -- "$EXPECTED_RNG_MARKER" "$tmp/hw-marker.txt" || true)"
  host_count="$(grep -Fxc -- "$EXPECTED_RNG_MARKER" "$tmp/host-marker.txt" || true)"
  duplicate_count="$(grep -Fxc -- "$EXPECTED_RNG_MARKER" "$tmp/duplicate-marker.txt" || true)"
  if [ "$hw_count" -eq 1 ] && [ "$host_count" -eq 0 ] && [ "$duplicate_count" -ne 1 ]; then
    echo "  [ok]   RNG receipt requires exactly one hardware marker"
  else
    echo "  [FAIL] RNG receipt accepted missing, host, or duplicate selection" >&2; rc=2
  fi

  printf '%s\n' "$EXPECTED_STRONG_RNG_MARKER" > "$tmp/strong-marker.txt"
  printf '%s\n' 'PQ1_STRONG_RNG_SOURCES=DEVELOPMENT_OR_INCOMPLETE' \
    > "$tmp/incomplete-strong-marker.txt"
  printf '%s\n%s\n' "$EXPECTED_STRONG_RNG_MARKER" "$EXPECTED_STRONG_RNG_MARKER" \
    > "$tmp/duplicate-strong-marker.txt"
  local strong_count incomplete_count duplicate_strong_count
  strong_count="$(grep -Fxc -- "$EXPECTED_STRONG_RNG_MARKER" "$tmp/strong-marker.txt" || true)"
  incomplete_count="$(grep -Fxc -- "$EXPECTED_STRONG_RNG_MARKER" "$tmp/incomplete-strong-marker.txt" || true)"
  duplicate_strong_count="$(grep -Fxc -- "$EXPECTED_STRONG_RNG_MARKER" "$tmp/duplicate-strong-marker.txt" || true)"
  if [ "$strong_count" -eq 1 ] && [ "$incomplete_count" -eq 0 ] \
    && [ "$duplicate_strong_count" -ne 1 ]; then
    echo "  [ok]   strong-RNG receipt requires STM32U585 + OPTIGA + SE050"
  else
    echo "  [FAIL] strong-RNG receipt accepted an incomplete/duplicate source set" >&2; rc=2
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
