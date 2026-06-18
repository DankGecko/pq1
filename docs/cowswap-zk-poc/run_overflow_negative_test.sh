#!/usr/bin/env bash
#
# Circuit-level negative test for the FormatTrimmedAmount field-overflow
# fix (docs/security/VULN-cowswap-zk-amount-overflow.md).
#
# Asserts that, on the FIXED circuit:
#   1. the PoC forged witness (raw_amount ≈ 2^254) FAILS witness
#      generation — the Num2Bits(190) range check rejects it; and
#   2. a benign witness (honest 0.2000 USDC, small raw_amount) SUCCEEDS
#      — proving the 190-bit bound is lossless for real amounts.
#
# Before the fix, BOTH would succeed (the forgery is a real satisfying
# assignment mod r). After the fix, only the benign one does.
#
# Prereqs: circom 2.x on PATH, `npm ci --prefix circuits` done, python3.
# Run from anywhere:  bash docs/cowswap-zk-poc/run_overflow_negative_test.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CIRCUITS="$REPO/circuits"
SNARKJS="$CIRCUITS/node_modules/.bin/snarkjs"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Generating forged + benign witness inputs"
python3 "$HERE/forge_amount_witness.py" >/dev/null
cp "$HERE/forged_input.json" "$HERE/benign_input.json" "$WORK/"

echo "==> Compiling isolated FormatTrimmedAmount test circuit"
circom "$CIRCUITS/test/format_trimmed_overflow_test.circom" \
    --wasm --prime bls12381 --output "$WORK" -l "$CIRCUITS/node_modules" >/dev/null

WC="$WORK/format_trimmed_overflow_test_js"
gen() { node "$WC/generate_witness.js" "$WC/format_trimmed_overflow_test.wasm" "$1" "$2"; }

echo "==> [1/2] forged witness MUST be rejected"
if gen "$WORK/forged_input.json" "$WORK/forged.wtns" >/dev/null 2>&1; then
    echo "FAIL: forged witness (raw_amount ~2^254) was ACCEPTED — the fix is not biting!"
    exit 1
fi
echo "    OK — forged witness rejected (Num2Bits(190) constraint)"

echo "==> [2/2] benign witness MUST be accepted"
if ! gen "$WORK/benign_input.json" "$WORK/benign.wtns" >/dev/null 2>&1; then
    echo "FAIL: benign witness (honest 0.2000 USDC) was REJECTED — the fix is too tight!"
    exit 1
fi
echo "    OK — benign witness accepted (fix is lossless for real amounts)"

echo
echo "=== PASS: field-overflow forgery rejected, real amounts unaffected ==="
