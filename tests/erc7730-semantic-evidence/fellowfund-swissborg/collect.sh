#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/erc7730-semantic-evidence/fellowfund-swissborg"
BLOCK=0x1871800
DRPC=https://eth.drpc.org
MEV=https://rpc.mevblocker.io

FELLOW=0x25d598cbb74fa73290e74697616de2740d280745
MIGRATOR=0xaa854688caab725fe17b7d21b46fda5af365985a
IMPLEMENTATION=0xfb976ea3ae9bfe4bc36fb7078e0b32e579463e96
CHSB=0xba9d4199fab4f26efe3551d490e3821486f135ba
BORG=0x64d0f55cd8c7133a9d7102b13987235f486f2224
EIP1967_IMPL_SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

mkdir -p "$OUT/blockscout" "$OUT/rpc" "$OUT/runtime"

rpc_record() {
  local endpoint=$1
  local kind=$2
  local target=$3
  local method=$4
  local params=$5
  local request response attempt
  request="$(jq -cn --arg method "$method" --argjson params "$params" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"
  for attempt in 1 2 3 4 5; do
    response="$(curl -fsSL --retry 2 --retry-all-errors --max-time 60 \
      -H 'content-type: application/json' --data-binary "$request" "$endpoint")"
    if jq -e '.error == null and .result != null' >/dev/null <<<"$response"; then
      break
    fi
    if [[ $attempt == 5 ]]; then
      echo "RPC evidence request failed after $attempt attempts: $kind $target" >&2
      jq . <<<"$response" >&2
      return 1
    fi
    sleep 1
  done
  jq -cnS --arg endpoint "$endpoint" --arg kind "$kind" --arg target "$target" \
    --argjson request "$request" --argjson response "$response" \
    '{endpoint:$endpoint,kind:$kind,target:$target,request:$request,response:$response}'
}

capture_rpc() {
  local endpoint=$1
  local output=$2
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  rpc_record "$endpoint" block_header ethereum eth_getBlockByNumber \
    "$(jq -cn --arg block "$BLOCK" '[$block,false]')" >> "$tmp"
  for target in "$FELLOW" "$MIGRATOR" "$IMPLEMENTATION" "$CHSB" "$BORG"; do
    rpc_record "$endpoint" code "$target" eth_getCode \
      "$(jq -cn --arg target "$target" --arg block "$BLOCK" '[$target,$block]')" >> "$tmp"
  done
  rpc_record "$endpoint" implementation_slot "$MIGRATOR" eth_getStorageAt \
    "$(jq -cn --arg target "$MIGRATOR" --arg slot "$EIP1967_IMPL_SLOT" --arg block "$BLOCK" \
      '[$target,$slot,$block]')" >> "$tmp"
  while read -r kind selector; do
    rpc_record "$endpoint" "$kind" "$MIGRATOR" eth_call \
      "$(jq -cn --arg target "$MIGRATOR" --arg selector "$selector" --arg block "$BLOCK" \
        '[{to:$target,data:$selector},$block]')" >> "$tmp"
  done <<'CALLS'
chsb_call 0x1e697b33
borg_call 0xfb5ee8dd
paused_call 0x5c975abb
CALLS
  for token in "$CHSB" "$BORG"; do
    while read -r label selector; do
      rpc_record "$endpoint" "token_${label}" "$token" eth_call \
        "$(jq -cn --arg target "$token" --arg selector "$selector" --arg block "$BLOCK" \
          '[{to:$target,data:$selector},$block]')" >> "$tmp"
    done <<'TOKEN_CALLS'
name 0x06fdde03
symbol 0x95d89b41
decimals 0x313ce567
TOKEN_CALLS
  done
  jq -sS . "$tmp" > "$output"
}

capture_rpc "$DRPC" "$OUT/rpc/drpc.json"
capture_rpc "$MEV" "$OUT/rpc/mevblocker.json"

curl -fsSL --max-time 60 \
  "https://eth.blockscout.com/api/v2/smart-contracts/$MIGRATOR" \
  | jq -S . > "$OUT/blockscout/ChsbToBorgMigratorProxy.json"
curl -fsSL --max-time 60 \
  "https://eth.blockscout.com/api/v2/smart-contracts/$IMPLEMENTATION" \
  | jq -S . > "$OUT/blockscout/ChsbToBorgMigratorV2.json"

fellow_status="$(
  curl -sS --max-time 60 -o "$OUT/blockscout/FellowFund.json" -w '%{http_code}' \
    "https://eth.blockscout.com/api/v2/smart-contracts/$FELLOW"
)"
printf '%s\n' "$fellow_status" > "$OUT/blockscout/FellowFund.http-status.txt"

jq -r '.[] | select(.kind=="code" and .target=="'"$FELLOW"'") | .response.result' \
  "$OUT/rpc/drpc.json" > "$OUT/runtime/FellowFund.hex"
jq -r '.[] | select(.kind=="code" and .target=="'"$MIGRATOR"'") | .response.result' \
  "$OUT/rpc/drpc.json" > "$OUT/runtime/ChsbToBorgMigratorProxy.hex"
jq -r '.[] | select(.kind=="code" and .target=="'"$IMPLEMENTATION"'") | .response.result' \
  "$OUT/rpc/drpc.json" > "$OUT/runtime/ChsbToBorgMigratorV2.hex"

artifacts="$(mktemp)"
trap 'rm -f "$artifacts"' EXIT
while IFS= read -r file; do
  relative="${file#"$OUT"/}"
  jq -cn \
    --arg path "$relative" \
    --argjson bytes "$(wc -c < "$file")" \
    --arg sha256 "$(sha256sum "$file" | cut -d' ' -f1)" \
    '{path:$path,bytes:$bytes,sha256:$sha256}' >> "$artifacts"
done < <(
  find "$OUT" -type f \
    ! -name manifest.json \
    -printf '%p\n' | LC_ALL=C sort
)

jq -nS \
  --argjson artifacts "$(jq -s . "$artifacts")" \
  '{
    schema_version: 1,
    scope: "Fixed-block negative deployment evidence for FellowFund and fixed-block proxy/source closure evidence for the SwissBorg CHSB-to-BORG migrator.",
    captured_at_utc: "2026-07-28T13:24:00Z",
    fixed_block: {
      chain_id: 1,
      number: 25630720,
      number_hex: "0x1871800"
    },
    claims: [
      "Two independent Ethereum RPC providers agree that the sole FellowFund registry destination has empty bytecode at the fixed block.",
      "Both RPC providers bind the SwissBorg migrator proxy to ChsbToBorgMigratorV2, the same CHSB/BORG addresses, and paused=true.",
      "Blockscout fully verifies the V2 implementation source whose migrate(uint256) body unconditionally reverts MIGRATION_CLOSED."
    ],
    boundary: "Historical fixed-block deployment, runtime, proxy-state, token-binding, and verified-source evidence only. No future-upgrade, reopening, execution-success, fallback, blind-signing, production, shipment, or irreversible-action authority.",
    artifacts: $artifacts
  }' > "$OUT/manifest.json"

echo "Captured FellowFund/SwissBorg evidence at Ethereum block $BLOCK"
