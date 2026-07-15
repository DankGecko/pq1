#!/usr/bin/env bash
#
# Host-side factory ceremony verifier.
#
# Reads the OTP factory sentinel at `0x0BFA_00A0` via probe-rs and
# interprets the result per the encoding in
# `secure/src/hw/otp.rs::FACTORY_SENTINEL_OFFSET`:
#
#   0xFFFFFFFF  — chip never started the ceremony
#   0xFFFFFFFE  — started, halted at failure panel (operator should
#                 read the OLED for the step + error code)
#   0xFFFFFFFC  — legacy rehearsal bits (quarantined receipt)
#   0xFFFFFFFA  — legacy production bits (quarantined receipt)
#   0xFFFFFFF8  — legacy combined bits (quarantined receipt)
#
# Usage:
#   tools/factory-provisioning-verify.sh                # report only
#   tools/factory-provisioning-verify.sh --bump-rdp2    # REFUSED while
#                                                       # factory receipt is
#                                                       # quarantined
#   tools/factory-provisioning-verify.sh \
#       --decode-legacy-sentinel 0xFFFFFFFA              # host-only test
#
# Exit codes:
#   0  — reserved; no legacy receipt grants RDP2 authority
#   1  — any known legacy sentinel state (all non-authoritative)
#   2  — probe-rs read failed (chip not attached, RDP1+, etc.)
#   3  — unexpected sentinel value (high bits cleared — corrupted OTP)
#   4  — --bump-rdp2 was requested (always refused)
#
# This script does NOT flash any firmware. The historical factory flash target
# is refusal-only. Report mode is read-only and every legacy value is
# non-authoritative.

set -euo pipefail

CHIP="${CHIP:-STM32U585AIIx}"
OTP_SENTINEL_ADDR="${OTP_SENTINEL_ADDR:-0x0BFA00A0}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-60}"
POLL_INTERVAL_SECS="${POLL_INTERVAL_SECS:-2}"

read_sentinel() {
    # `probe-rs read 32 ADDR --num-words 1` returns:
    #   <ADDR>: <HEX_VALUE>
    # We parse out the hex value and normalize to 0x-prefixed
    # lowercase 8-digit form.
    local raw
    if ! raw="$(probe-rs read 32 "${OTP_SENTINEL_ADDR}" \
                   --chip "${CHIP}" --num-words 1 2>/dev/null)"; then
        return 1
    fi
    # Extract the value after the ":". probe-rs output formatting
    # varies between versions; this is loose on purpose.
    printf '0x%08x\n' "$(echo "${raw}" | awk -F: 'NR==1{print $NF}' | tr -d ' ')"
}

decode_sentinel() {
    local v="$1"
    case "${v}" in
        0xffffffff)
            echo "DID_NOT_START — chip never reached the legacy ceremony entry point; NOT RDP2 AUTHORITY"
            return 1
            ;;
        0xfffffffe)
            echo "STARTED_FAILED — legacy ceremony entered, halted at failure. Read LCD. NOT RDP2 AUTHORITY."
            return 1
            ;;
        0xfffffffc)
            echo "LEGACY_REHEARSAL_BITS — quarantined receipt; NOT RDP2 AUTHORITY"
            return 1
            ;;
        0xfffffffa)
            echo "LEGACY_PRODUCTION_BITS — quarantined receipt; NOT RDP2 AUTHORITY"
            return 1
            ;;
        0xfffffff8)
            echo "LEGACY_COMBINED_BITS — quarantined receipt; NOT RDP2 AUTHORITY"
            return 1
            ;;
        *)
            echo "CORRUPT — unexpected high bits cleared (raw=${v}); NOT RDP2 AUTHORITY"
            return 3
            ;;
    esac
}

if [[ "${1:-}" == "--bump-rdp2" ]]; then
    echo "REFUSED: --bump-rdp2 is disabled while the factory OTP receipt is quarantined." >&2
    echo "Draft 1.1 is an unapproved rollback research candidate; it grants no irreversible authority." >&2
    exit 4
fi

if [[ "${1:-}" == "--decode-legacy-sentinel" ]]; then
    if [[ $# -ne 2 ]]; then
        echo "usage: $0 --decode-legacy-sentinel 0xNNNNNNNN" >&2
        exit 4
    fi
    set +e
    decode_sentinel "${2,,}"
    decode_exit=$?
    set -e
    exit "${decode_exit}"
fi

echo "==> Polling OTP sentinel at ${OTP_SENTINEL_ADDR} on ${CHIP}"
echo "    Timeout: ${POLL_TIMEOUT_SECS}s, interval: ${POLL_INTERVAL_SECS}s"

deadline=$(( $(date +%s) + POLL_TIMEOUT_SECS ))
last_value=""
stable_count=0

while [[ $(date +%s) -lt ${deadline} ]]; do
    if ! current="$(read_sentinel)"; then
        echo "    [t+0] probe-rs read failed — chip not attached? RDP1+?"
        exit 2
    fi

    elapsed=$(( ${POLL_TIMEOUT_SECS} - (deadline - $(date +%s)) ))
    echo "    [t+${elapsed}s] sentinel = ${current}"

    # If the sentinel has moved past 0xFFFFFFFF AND has any
    # completion bit (1 or 2) cleared, the ceremony is done. We
    # require the value to be stable across 2 successive reads to
    # be sure the chip isn't mid-write.
    case "${current}" in
        0xfffffffc|0xfffffffa|0xfffffff8)
            if [[ "${current}" == "${last_value}" ]]; then
                stable_count=$(( stable_count + 1 ))
                if [[ ${stable_count} -ge 1 ]]; then
                    echo "==> sentinel stable: ${current}"
                    break
                fi
            fi
            last_value="${current}"
            ;;
        *)
            last_value="${current}"
            stable_count=0
            ;;
    esac

    sleep "${POLL_INTERVAL_SECS}"
done

# Final read + decode.
if ! final="$(read_sentinel)"; then
    echo "ERROR: probe-rs read failed on final attempt"
    exit 2
fi

set +e
decoded="$(decode_sentinel "${final}")"
decode_exit=$?
set -e

echo "==> Final state: ${decoded}"

exit ${decode_exit}
