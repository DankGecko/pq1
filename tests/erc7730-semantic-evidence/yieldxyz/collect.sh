#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/erc7730-semantic-evidence/yieldxyz"
BLOCK=0x1871800
DRPC=https://eth.drpc.org
MEV=https://rpc.mevblocker.io

POL_IMPL=0xbe63b977abbaa99fc0243e208340c530dd4ee9e8
USDE_PROXY=0x2d152fb171353e70e45322d32bc748f8a61d9971
USDE_IMPL=0xa7249e2902b956e7127df56bf45d58cff610d832
USDE=0x4c9edd5852cd905f086c759e8383e09bff1e68b3
SUSDE=0x9d39a5de30e57443bff2a8307a4256c8797a3497
EIP1967_IMPL_SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

POL_PROXIES=(
  0xb929b89153fc2eed442e81e5a1add4e2fa39028f
  0x56d783ca8e0b998c57a428bf1c26a8baca50524e
  0x857679d69fe50e7b722f94acd2629d80c355163d
  0xf30cf4ed712d3734161fdaab5b1dbb49fd2d0e5c
  0x5a10de50160126a5f936506bd342c541ac44e943
  0x35b1ca0f398905cf752e6fe122b51c88022fca32
  0xd9e6987d77bf2c6d0647b8181fd68a259f838c36
  0xd14a87025109013b0a2354a775cb335f926af65a
  0xa6e768fef2d1af36c0cfdb276422e7881a83e951
  0x467585aaea860f9d8b3b43bb994e4da8a93788a7
  0x06998af8f39ff8630d1fb515d22781da4dc2ca71
  0xc7757805b983ee1b6272c1840c18e66837de858e
  0xe3e9ba8c8c696f8537cf16b23eddf118bbd7f21f
  0x875e901465a639f2e71fcfc10f426ed32f5a909a
  0x2905b3387c9550ea57fa3ee7d4b7e5abf3acd3d2
  0x15c2b3adca66e26b6f230b4023f52a285b7f9995
  0x2ea3c215daeacc1c90b51443ab5d08a9ad816138
)

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

capture_pol() {
  local endpoint=$1
  local output=$2
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  rpc_record "$endpoint" block_header ethereum eth_getBlockByNumber \
    "$(jq -cn --arg block "$BLOCK" '[$block,false]')" >> "$tmp"
  for proxy in "${POL_PROXIES[@]}"; do
    rpc_record "$endpoint" proxy_code "$proxy" eth_getCode \
      "$(jq -cn --arg target "$proxy" --arg block "$BLOCK" '[$target,$block]')" >> "$tmp"
    rpc_record "$endpoint" implementation_call "$proxy" eth_call \
      "$(jq -cn --arg target "$proxy" --arg block "$BLOCK" \
        '[{to:$target,data:"0x5c60da1b"},$block]')" >> "$tmp"
  done
  rpc_record "$endpoint" implementation_code "$POL_IMPL" eth_getCode \
    "$(jq -cn --arg target "$POL_IMPL" --arg block "$BLOCK" '[$target,$block]')" >> "$tmp"
  jq -sS . "$tmp" > "$output"
}

capture_usde() {
  local endpoint=$1
  local output=$2
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  rpc_record "$endpoint" block_header ethereum eth_getBlockByNumber \
    "$(jq -cn --arg block "$BLOCK" '[$block,false]')" >> "$tmp"
  rpc_record "$endpoint" proxy_code "$USDE_PROXY" eth_getCode \
    "$(jq -cn --arg target "$USDE_PROXY" --arg block "$BLOCK" '[$target,$block]')" >> "$tmp"
  rpc_record "$endpoint" implementation_slot "$USDE_PROXY" eth_getStorageAt \
    "$(jq -cn --arg target "$USDE_PROXY" --arg slot "$EIP1967_IMPL_SLOT" --arg block "$BLOCK" \
      '[$target,$slot,$block]')" >> "$tmp"

  while read -r kind selector; do
    rpc_record "$endpoint" "$kind" "$USDE_PROXY" eth_call \
      "$(jq -cn --arg target "$USDE_PROXY" --arg selector "$selector" --arg block "$BLOCK" \
        '[{to:$target,data:$selector},$block]')" >> "$tmp"
  done <<'CALLS'
underlying_call 0x6f307dc3
asset_call 0x38d52e0f
strategy_call 0xa8c62e76
name_call 0x06fdde03
symbol_call 0x95d89b41
decimals_call 0x313ce567
config_call 0x79502c55
CALLS

  rpc_record "$endpoint" implementation_code "$USDE_IMPL" eth_getCode \
    "$(jq -cn --arg target "$USDE_IMPL" --arg block "$BLOCK" '[$target,$block]')" >> "$tmp"
  for token in "$USDE" "$SUSDE"; do
    rpc_record "$endpoint" token_code "$token" eth_getCode \
      "$(jq -cn --arg target "$token" --arg block "$BLOCK" '[$target,$block]')" >> "$tmp"
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
  rpc_record "$endpoint" strategy_asset_call "$SUSDE" eth_call \
    "$(jq -cn --arg target "$SUSDE" --arg block "$BLOCK" \
      '[{to:$target,data:"0x38d52e0f"},$block]')" >> "$tmp"
  jq -sS . "$tmp" > "$output"
}

capture_pol "$DRPC" "$OUT/rpc/pol-drpc.json"
capture_pol "$MEV" "$OUT/rpc/pol-mevblocker.json"
capture_usde "$DRPC" "$OUT/rpc/usde-drpc.json"
capture_usde "$MEV" "$OUT/rpc/usde-mevblocker.json"

curl -fsSL --max-time 60 \
  'https://eth.blockscout.com/api/v2/smart-contracts/0xb929b89153fc2eed442e81e5a1add4e2fa39028f' \
  | jq -S . > "$OUT/blockscout/ValidatorShareProxy.json"
curl -fsSL --max-time 60 \
  'https://eth.blockscout.com/api/v2/smart-contracts/0xbe63b977abbaa99fc0243e208340c530dd4ee9e8' \
  | jq -S . > "$OUT/blockscout/ValidatorShare.json"
curl -fsSL --max-time 60 \
  'https://eth.blockscout.com/api/v2/smart-contracts/0x2d152fb171353e70e45322d32bc748f8a61d9971' \
  | jq -S . > "$OUT/blockscout/AllocatorVaultProxy.json"
curl -fsSL --max-time 60 \
  'https://eth.blockscout.com/api/v2/smart-contracts/0xa7249e2902b956e7127df56bf45d58cff610d832' \
  | jq -S . > "$OUT/blockscout/AllocatorVaultV3.json"

jq -r '.[] | select(.kind=="proxy_code") | .response.result' \
  "$OUT/rpc/pol-drpc.json" | sort -u > "$OUT/runtime/ValidatorShareProxy.hex"
jq -r '.[] | select(.kind=="implementation_code") | .response.result' \
  "$OUT/rpc/pol-drpc.json" > "$OUT/runtime/ValidatorShare.hex"
jq -r '.[] | select(.kind=="proxy_code") | .response.result' \
  "$OUT/rpc/usde-drpc.json" > "$OUT/runtime/AllocatorVaultProxy.hex"
jq -r '.[] | select(.kind=="implementation_code") | .response.result' \
  "$OUT/rpc/usde-drpc.json" > "$OUT/runtime/AllocatorVaultV3.hex"
jq -r '.[] | select(.kind=="token_code" and .target=="'"$USDE"'") | .response.result' \
  "$OUT/rpc/usde-drpc.json" > "$OUT/runtime/USDe.hex"
jq -r '.[] | select(.kind=="token_code" and .target=="'"$SUSDE"'") | .response.result' \
  "$OUT/rpc/usde-drpc.json" > "$OUT/runtime/sUSDe.hex"

echo "Captured Yield.xyz evidence at Ethereum block $BLOCK"
