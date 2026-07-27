#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
workspace="$(CDPATH= cd -- "$root/../../.." && pwd)"
rpc="$root/rpc/raw"
sourcify="$root/verifier/sourcify"
runtime="$root/runtime"
abi="$root/abi"

mkdir -p "$rpc" "$sourcify" "$runtime" "$abi"

tmp="$(mktemp)"
receipts="$(mktemp)"
manifest_tmp="$(mktemp)"
trap 'unlink "$tmp" "$receipts" "$manifest_tmp" 2>/dev/null || true' EXIT

fetch() {
  curl \
    --fail --silent --show-error --location \
    --connect-timeout 15 --max-time 120 \
    --retry 5 --retry-all-errors --retry-delay 1 \
    "$@"
}

fetch_json() {
  local url="$1"
  local destination="$2"
  fetch "$url" >"$tmp"
  jq -S '.' "$tmp" >"$destination"
}

rpc_request() {
  local url="$1"
  local request_path="$2"
  local destination="$3"
  local attempt status

  for attempt in 1 2 3 4 5; do
    status="$(curl \
      --silent --show-error --location \
      --connect-timeout 15 --max-time 120 \
      --retry 2 --retry-all-errors --retry-delay 1 \
      -H 'content-type: application/json' \
      --data-binary "@$request_path" \
      --output "$tmp" --write-out '%{http_code}' \
      "$url")"
    if [[ "$status" == 200 ]] &&
      jq -e '
        if type == "array" then
          length > 0 and all(.[]; (.error? // null) == null and .result != null)
        else
          (.error? // null) == null and .result != null
        end
      ' "$tmp" >/dev/null
    then
      jq -S 'if type == "array" then sort_by(.id) else . end' \
        "$tmp" >"$destination"
      return 0
    fi
    echo "retrying RPC capture ($attempt/5): $url" >&2
  done

  echo "RPC capture failed after five attempts: $url" >&2
  return 1
}

bound_call() {
  local id="$1"
  local to="$2"
  local data="$3"
  local hash="$4"
  jq -nS \
    --arg id "$id" --arg to "$to" --arg data "$data" --arg hash "$hash" \
    '{jsonrpc:"2.0",id:$id,method:"eth_call",params:[
      {to:$to,data:$data},{blockHash:$hash,requireCanonical:true}
    ]}'
}

bound_code() {
  local id="$1"
  local address="$2"
  local hash="$3"
  jq -nS \
    --arg id "$id" --arg address "$address" --arg hash "$hash" \
    '{jsonrpc:"2.0",id:$id,method:"eth_getCode",params:[
      $address,{blockHash:$hash,requireCanonical:true}
    ]}'
}

bound_storage() {
  local id="$1"
  local address="$2"
  local slot="$3"
  local hash="$4"
  jq -nS \
    --arg id "$id" --arg address "$address" --arg slot "$slot" --arg hash "$hash" \
    '{jsonrpc:"2.0",id:$id,method:"eth_getStorageAt",params:[
      $address,$slot,{blockHash:$hash,requireCanonical:true}
    ]}'
}

collect_ethereum_batch() {
  local name="$1"
  local request_path="$rpc/request-ethereum-$name.json"
  rpc_request https://eth.drpc.org \
    "$request_path" "$rpc/response-ethereum-drpc-$name.json"
  rpc_request https://mainnet.gateway.tenderly.co \
    "$request_path" "$rpc/response-ethereum-tenderly-$name.json"
}

eth_block=0x1870100
bsc_block=0x6b3f500
eip1967_slot=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

jq -nS --arg block "$eth_block" \
  '{jsonrpc:"2.0",id:"header",method:"eth_getBlockByNumber",params:[$block,false]}' \
  >"$rpc/request-ethereum-bootstrap.json"
rpc_request https://eth.drpc.org \
  "$rpc/request-ethereum-bootstrap.json" \
  "$rpc/response-ethereum-drpc-bootstrap.json"
eth_hash="$(jq -r '.result.hash' "$rpc/response-ethereum-drpc-bootstrap.json")"

jq -nS --arg hash "$eth_hash" '[
  {jsonrpc:"2.0",id:"chain-id",method:"eth_chainId",params:[]},
  {jsonrpc:"2.0",id:"block",method:"eth_getBlockByHash",params:[$hash,false]}
]' >"$rpc/request-ethereum-identity.json"

jq -sS '.' \
  <(bound_code gm-code 0xf0bc39fc911f6437c84d16188dd8294f7110f451 "$eth_hash") \
  <(bound_code ousg-manager-code 0x93358db73b6cd4b98d89c8f5f230e81a95c2643a "$eth_hash") \
  <(bound_code usdy-manager-code 0xa42613c243b67bf6194ac327795b926b4b491f15 "$eth_hash") \
  >"$rpc/request-ethereum-managers-runtime.json"

jq -sS '.' \
  <(bound_code ousg-token-code 0x1b19c19393e2d034d8ff31ff34c81252fcbbee92 "$eth_hash") \
  <(bound_code usdy-token-code 0x96f6ef951840721adbf46ac996b59e0235cb985c "$eth_hash") \
  <(bound_code rusdy-token-code 0xaf37c1167910ebc994e266949387d2c7c326b879 "$eth_hash") \
  >"$rpc/request-ethereum-token-proxies-runtime.json"

jq -sS '.' \
  <(bound_code ousg-token-implementation-code 0x1ceb44b6e515abf009e0ccb6ddafd723886cf3ff "$eth_hash") \
  <(bound_code usdy-token-implementation-code 0xea0f7eebdc2ae40edfe33bf03d332f8a7f617528 "$eth_hash") \
  <(bound_code rusdy-token-implementation-code 0x58910371d0b52dcf9d2e0a1af4e0078c58436908 "$eth_hash") \
  >"$rpc/request-ethereum-token-implementations-runtime.json"

jq -sS '.' \
  <(bound_storage ousg-token-implementation-slot 0x1b19c19393e2d034d8ff31ff34c81252fcbbee92 "$eip1967_slot" "$eth_hash") \
  <(bound_storage usdy-token-implementation-slot 0x96f6ef951840721adbf46ac996b59e0235cb985c "$eip1967_slot" "$eth_hash") \
  <(bound_storage rusdy-token-implementation-slot 0xaf37c1167910ebc994e266949387d2c7c326b879 "$eip1967_slot" "$eth_hash") \
  >"$rpc/request-ethereum-token-implementation-slots.json"

jq -sS '.' \
  <(bound_call ousg-manager-rwa-token 0x93358db73b6cd4b98d89c8f5f230e81a95c2643a 0x0c5bf351 "$eth_hash") \
  <(bound_call ousg-manager-rousg 0x93358db73b6cd4b98d89c8f5f230e81a95c2643a 0x2404e971 "$eth_hash") \
  >"$rpc/request-ethereum-ousg-manager-bindings.json"

jq -sS '.' \
  <(bound_call usdy-manager-rwa-token 0xa42613c243b67bf6194ac327795b926b4b491f15 0x0c5bf351 "$eth_hash") \
  <(bound_call usdy-manager-rusdy 0xa42613c243b67bf6194ac327795b926b4b491f15 0x10a4f09f "$eth_hash") \
  >"$rpc/request-ethereum-usdy-manager-bindings.json"

for token in \
  "ousg 0x1b19c19393e2d034d8ff31ff34c81252fcbbee92" \
  "usdy 0x96f6ef951840721adbf46ac996b59e0235cb985c" \
  "rusdy 0xaf37c1167910ebc994e266949387d2c7c326b879"
do
  set -- $token
  jq -sS '.' \
    <(bound_call "$1-token-name" "$2" 0x06fdde03 "$eth_hash") \
    <(bound_call "$1-token-symbol" "$2" 0x95d89b41 "$eth_hash") \
    <(bound_call "$1-token-decimals" "$2" 0x313ce567 "$eth_hash") \
    >"$rpc/request-ethereum-$1-token-metadata.json"
done

for batch in \
  identity managers-runtime token-proxies-runtime token-implementations-runtime \
  token-implementation-slots ousg-manager-bindings usdy-manager-bindings \
  ousg-token-metadata usdy-token-metadata rusdy-token-metadata
do
  collect_ethereum_batch "$batch"
done

jq -nS --arg block "$bsc_block" \
  '{jsonrpc:"2.0",id:"header",method:"eth_getBlockByNumber",params:[$block,false]}' \
  >"$rpc/request-bsc-bootstrap.json"
rpc_request \
  https://bsc-mainnet.nodereal.io/v1/64a9df0874fb4a93b9d0a3849de012d3 \
  "$rpc/request-bsc-bootstrap.json" \
  "$rpc/response-bsc-nodereal-bootstrap.json"
bsc_hash="$(jq -r '.result.hash' "$rpc/response-bsc-nodereal-bootstrap.json")"

jq -sS '.' \
  <(jq -nS '{jsonrpc:"2.0",id:"chain-id",method:"eth_chainId",params:[]}') \
  <(jq -nS --arg hash "$bsc_hash" \
    '{jsonrpc:"2.0",id:"block",method:"eth_getBlockByHash",params:[$hash,false]}') \
  <(bound_code gm-code 0x96b525b1a93f31e65f4aaf18c53842ed28525d48 "$bsc_hash") \
  >"$rpc/request-bsc-identity-runtime.json"
rpc_request \
  https://bsc-mainnet.nodereal.io/v1/64a9df0874fb4a93b9d0a3849de012d3 \
  "$rpc/request-bsc-identity-runtime.json" \
  "$rpc/response-bsc-nodereal-identity-runtime.json"
rpc_request https://bsc.meowrpc.com \
  "$rpc/request-bsc-identity-runtime.json" \
  "$rpc/response-bsc-meowrpc-identity-runtime.json"

eth_block_doc="$(
  jq -c '.[] | select(.id == "block") | .result' \
    "$rpc/response-ethereum-drpc-identity.json"
)"
bsc_block_doc="$(
  jq -c '.[] | select(.id == "block") | .result' \
    "$rpc/response-bsc-nodereal-identity-runtime.json"
)"
jq -nS \
  --argjson ethereum "$eth_block_doc" \
  --argjson bsc "$bsc_block_doc" \
  '{
    schema_version:1,
    observations:[
      {
        chain_id:1,
        slug:"ethereum",
        providers:["dRPC","Tenderly"],
        block:{
          number:$ethereum.number,
          hash:$ethereum.hash,
          parent_hash:$ethereum.parentHash,
          state_root:$ethereum.stateRoot,
          timestamp:$ethereum.timestamp
        }
      },
      {
        chain_id:56,
        slug:"bsc",
        providers:["NodeReal","MeowRPC"],
        block:{
          number:$bsc.number,
          hash:$bsc.hash,
          parent_hash:$bsc.parentHash,
          state_root:$bsc.stateRoot,
          timestamp:$bsc.timestamp
        }
      }
    ]
  }' >"$root/rpc/fixed-block-receipt.json"

fields='abi%2Csources%2Ccompilation%2CruntimeBytecode.onchainBytecode%2Cdeployment%2CproxyResolution'
while read -r chain address destination; do
  fetch_json \
    "https://sourcify.dev/server/v2/contract/$chain/$address?fields=$fields" \
    "$sourcify/$destination"
done <<'EOF'
1 0xf0bc39fc911f6437c84d16188dd8294f7110f451 gm-token-limit-order.ethereum.json
56 0x96b525b1a93f31e65f4aaf18c53842ed28525d48 gm-token-limit-order.bsc.json
1 0x93358db73b6cd4b98d89c8f5f230e81a95c2643a ousg-instant-manager.ethereum.json
1 0xa42613c243b67bf6194ac327795b926b4b491f15 usdy-instant-manager.ethereum.json
1 0x1b19c19393e2d034d8ff31ff34c81252fcbbee92 ousg-token-proxy.ethereum.json
1 0x1ceb44b6e515abf009e0ccb6ddafd723886cf3ff ousg-token-implementation.ethereum.json
1 0x96f6ef951840721adbf46ac996b59e0235cb985c usdy-token-proxy.ethereum.json
1 0xea0f7eebdc2ae40edfe33bf03d332f8a7f617528 usdy-token-implementation.ethereum.json
1 0xaf37c1167910ebc994e266949387d2c7c326b879 rusdy-token-proxy.ethereum.json
1 0x58910371d0b52dcf9d2e0a1af4e0078c58436908 rusdy-token-implementation.ethereum.json
EOF

extract_result() {
  local source="$1"
  local id="$2"
  local destination="$3"
  jq -r --arg id "$id" '.[] | select(.id == $id) | .result' \
    "$source" >"$destination"
}

extract_result "$rpc/response-ethereum-drpc-managers-runtime.json" \
  gm-code "$runtime/GMTokenLimitOrder.ethereum.hex"
extract_result "$rpc/response-bsc-nodereal-identity-runtime.json" \
  gm-code "$runtime/GMTokenLimitOrder.bsc.hex"
extract_result "$rpc/response-ethereum-drpc-managers-runtime.json" \
  ousg-manager-code "$runtime/OUSGInstantManager.ethereum.hex"
extract_result "$rpc/response-ethereum-drpc-managers-runtime.json" \
  usdy-manager-code "$runtime/USDYInstantManager.ethereum.hex"
extract_result "$rpc/response-ethereum-drpc-token-proxies-runtime.json" \
  ousg-token-code "$runtime/OUSGTokenProxy.ethereum.hex"
extract_result "$rpc/response-ethereum-drpc-token-proxies-runtime.json" \
  usdy-token-code "$runtime/USDYTokenProxy.ethereum.hex"
extract_result "$rpc/response-ethereum-drpc-token-proxies-runtime.json" \
  rusdy-token-code "$runtime/RUSDYTokenProxy.ethereum.hex"
extract_result "$rpc/response-ethereum-drpc-token-implementations-runtime.json" \
  ousg-token-implementation-code "$runtime/OUSGTokenImplementation.ethereum.hex"
extract_result "$rpc/response-ethereum-drpc-token-implementations-runtime.json" \
  usdy-token-implementation-code "$runtime/USDYTokenImplementation.ethereum.hex"
extract_result "$rpc/response-ethereum-drpc-token-implementations-runtime.json" \
  rusdy-token-implementation-code "$runtime/RUSDYTokenImplementation.ethereum.hex"

jq -cS '[.abi[] | select(.type == "function") | select(
  .name == "cancelOrder" or
  .name == "createBuyOrderExactIn" or
  .name == "createBuyOrderExactOut" or
  .name == "createSellOrderExactIn" or
  .name == "createSellOrderExactOut"
)] | sort_by(.name)' \
  "$sourcify/gm-token-limit-order.ethereum.json" \
  >"$abi/GMTokenLimitOrder.accepted-routes.abi.json"
jq -cS '[.abi[] | select(.type == "function") | select(
  .name == "subscribe" or .name == "redeem"
)] | sort_by(.name)' \
  "$sourcify/ousg-instant-manager.ethereum.json" \
  >"$abi/OUSGInstantManager.accepted-routes.abi.json"
jq -cS '[.abi[] | select(.type == "function") | select(
  .name == "subscribe" or .name == "redeem" or
  .name == "subscribeRebasingUSDY" or .name == "redeemRebasingUSDY"
)] | sort_by(.name)' \
  "$sourcify/usdy-instant-manager.ethereum.json" \
  >"$abi/USDYInstantManager.accepted-routes.abi.json"

for index in 0 1 2; do
  descriptor="$(
    jq -r --argjson index "$index" '.descriptor_inputs[$index].path' \
      "$root/manifest.json"
  )"
  digest="$(sha256sum "$workspace/$descriptor" | awk '{print $1}')"
  jq --argjson index "$index" --arg digest "$digest" \
    '.descriptor_inputs[$index].sha256_at_evidence_freeze = $digest' \
    "$root/manifest.json" >"$manifest_tmp"
  mv "$manifest_tmp" "$root/manifest.json"
done

find "$root" -type f ! -name manifest.json -print0 | sort -z |
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  digest="$(sha256sum "$path" | awk '{print $1}')"
  jq -cn --arg path "$relative" --arg sha256 "$digest" \
    '{path:$path,sha256:$sha256}' >>"$receipts"
done
jq --slurpfile artifacts "$receipts" '.artifacts = $artifacts' \
  "$root/manifest.json" >"$manifest_tmp"
mv "$manifest_tmp" "$root/manifest.json"
