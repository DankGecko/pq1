#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/erc7730-semantic-evidence/p2p-pod-message"

ETH_BLOCK=0x1871b0c
HOODI_BLOCK=0x326c34
ETH_DRPC=https://eth.drpc.org
ETH_MEVBLOCKER=https://rpc.mevblocker.io
HOODI_OFFICIAL=https://rpc.hoodi.ethpandaops.io
HOODI_DRPC=https://hoodi.drpc.org

EIP1967_IMPL_SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

EIGEN_PROXY_ETH=0x91e677b07f7af907ec9a428aafa9fc14a0d3a338
EIGEN_IMPL_ETH=0xd22dd829779adbf3869fb224f703452f7f95e9db
EIGEN_PROXY_HOODI=0xcd1442415fc5c29aa848a49d2e232720be07976c
EIGEN_IMPL_HOODI=0x0f264e714a3c03309f4041db26229ef4e9b00f5c

MESSAGE_ETH=0x4e1224f513048e18e7a1883985b45dc0fe1d917e
MESSAGE_HOODI_A=0x917105cc314c12890d9c8224aee5af9574f871cf
MESSAGE_HOODI_B=0x158f2bbef21cf9f92cf4a294999ba422948c8242
MESSAGE_HOODI_TX_A=0x9b488d7256121e1703a980f116ae70b5f6ec51aaeee32eb6232027158667c1a7
MESSAGE_HOODI_TX_B=0xb559eac23da274e0dcb41e18d7f0c72cc73f2c68ba4f8bb4e2a18d4e6c1b1512

mkdir -p \
  "$OUT/abi" \
  "$OUT/blockscout" \
  "$OUT/compiler" \
  "$OUT/rpc" \
  "$OUT/runtime" \
  "$OUT/source"

rpc_record() {
  local endpoint=$1
  local kind=$2
  local target=$3
  local method=$4
  local params=$5
  local request response attempt
  request="$(jq -cn --arg id "$kind:$target" --arg method "$method" --argjson params "$params" \
    '{jsonrpc:"2.0",id:$id,method:$method,params:$params}')"
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

capture_ethereum() {
  local endpoint=$1
  local output=$2
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  rpc_record "$endpoint" block_header ethereum eth_getBlockByNumber \
    "$(jq -cn --arg block "$ETH_BLOCK" '[$block,false]')" >>"$tmp"
  rpc_record "$endpoint" proxy_code "$EIGEN_PROXY_ETH" eth_getCode \
    "$(jq -cn --arg target "$EIGEN_PROXY_ETH" --arg block "$ETH_BLOCK" '[$target,$block]')" >>"$tmp"
  rpc_record "$endpoint" implementation_slot "$EIGEN_PROXY_ETH" eth_getStorageAt \
    "$(jq -cn --arg target "$EIGEN_PROXY_ETH" --arg slot "$EIP1967_IMPL_SLOT" \
      --arg block "$ETH_BLOCK" '[$target,$slot,$block]')" >>"$tmp"
  rpc_record "$endpoint" implementation_code "$EIGEN_IMPL_ETH" eth_getCode \
    "$(jq -cn --arg target "$EIGEN_IMPL_ETH" --arg block "$ETH_BLOCK" '[$target,$block]')" >>"$tmp"
  while read -r kind selector; do
    rpc_record "$endpoint" "$kind" "$EIGEN_PROXY_ETH" eth_call \
      "$(jq -cn --arg target "$EIGEN_PROXY_ETH" --arg selector "$selector" \
        --arg block "$ETH_BLOCK" '[{to:$target,data:$selector},$block]')" >>"$tmp"
  done <<'EIGEN_CALLS'
eigen_pod_beacon_call 0x292b7b2b
delegation_manager_call 0xea4d3c9b
pauser_registry_call 0x886f1195
EIGEN_CALLS
  rpc_record "$endpoint" message_code "$MESSAGE_ETH" eth_getCode \
    "$(jq -cn --arg target "$MESSAGE_ETH" --arg block "$ETH_BLOCK" '[$target,$block]')" >>"$tmp"
  jq -sS . "$tmp" >"$output"
}

capture_hoodi() {
  local endpoint=$1
  local output=$2
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  rpc_record "$endpoint" block_header hoodi eth_getBlockByNumber \
    "$(jq -cn --arg block "$HOODI_BLOCK" '[$block,false]')" >>"$tmp"
  rpc_record "$endpoint" proxy_code "$EIGEN_PROXY_HOODI" eth_getCode \
    "$(jq -cn --arg target "$EIGEN_PROXY_HOODI" --arg block "$HOODI_BLOCK" '[$target,$block]')" >>"$tmp"
  rpc_record "$endpoint" implementation_slot "$EIGEN_PROXY_HOODI" eth_getStorageAt \
    "$(jq -cn --arg target "$EIGEN_PROXY_HOODI" --arg slot "$EIP1967_IMPL_SLOT" \
      --arg block "$HOODI_BLOCK" '[$target,$slot,$block]')" >>"$tmp"
  rpc_record "$endpoint" implementation_code "$EIGEN_IMPL_HOODI" eth_getCode \
    "$(jq -cn --arg target "$EIGEN_IMPL_HOODI" --arg block "$HOODI_BLOCK" '[$target,$block]')" >>"$tmp"
  while read -r kind selector; do
    rpc_record "$endpoint" "$kind" "$EIGEN_PROXY_HOODI" eth_call \
      "$(jq -cn --arg target "$EIGEN_PROXY_HOODI" --arg selector "$selector" \
        --arg block "$HOODI_BLOCK" '[{to:$target,data:$selector},$block]')" >>"$tmp"
  done <<'EIGEN_CALLS'
eigen_pod_beacon_call 0x292b7b2b
delegation_manager_call 0xea4d3c9b
pauser_registry_call 0x886f1195
EIGEN_CALLS
  for address in "$MESSAGE_HOODI_A" "$MESSAGE_HOODI_B"; do
    rpc_record "$endpoint" message_code "$address" eth_getCode \
      "$(jq -cn --arg target "$address" --arg block "$HOODI_BLOCK" '[$target,$block]')" >>"$tmp"
  done
  for tx in "$MESSAGE_HOODI_TX_A" "$MESSAGE_HOODI_TX_B"; do
    rpc_record "$endpoint" message_creation_tx "$tx" eth_getTransactionByHash \
      "$(jq -cn --arg tx "$tx" '[$tx]')" >>"$tmp"
    rpc_record "$endpoint" message_creation_receipt "$tx" eth_getTransactionReceipt \
      "$(jq -cn --arg tx "$tx" '[$tx]')" >>"$tmp"
  done
  jq -sS . "$tmp" >"$output"
}

capture_ethereum "$ETH_DRPC" "$OUT/rpc/ethereum-drpc.json"
capture_ethereum "$ETH_MEVBLOCKER" "$OUT/rpc/ethereum-mevblocker.json"
capture_hoodi "$HOODI_OFFICIAL" "$OUT/rpc/hoodi-ethpandaops.json"
capture_hoodi "$HOODI_DRPC" "$OUT/rpc/hoodi-drpc.json"

curl -fsSL --max-time 60 \
  "https://eth.blockscout.com/api/v2/smart-contracts/$EIGEN_PROXY_ETH" \
  | jq -S . >"$OUT/blockscout/EigenPodManager.proxy.ethereum.json"
curl -fsSL --max-time 60 \
  "https://eth.blockscout.com/api/v2/smart-contracts/$EIGEN_IMPL_ETH" \
  | jq -S . >"$OUT/blockscout/EigenPodManager.implementation.ethereum.json"
curl -fsSL --max-time 60 \
  "https://eth-hoodi.blockscout.com/api/v2/smart-contracts/$EIGEN_PROXY_HOODI" \
  | jq -S . >"$OUT/blockscout/EigenPodManager.proxy.hoodi.json"
curl -fsSL --max-time 60 \
  "https://eth.blockscout.com/api/v2/smart-contracts/$MESSAGE_ETH" \
  | jq -S . >"$OUT/blockscout/P2pMessageSender.ethereum.json"
for record in \
  "$MESSAGE_HOODI_A:P2pMessageSender.creation.hoodi-a.json" \
  "$MESSAGE_HOODI_B:P2pMessageSender.creation.hoodi-b.json"; do
  address="${record%%:*}"
  name="${record#*:}"
  curl -fsSL --max-time 60 \
    "https://eth-hoodi.blockscout.com/api?module=contract&action=getcontractcreation&contractaddresses=$address" \
    | jq -S . >"$OUT/blockscout/$name"
done

jq -S '.abi' "$OUT/blockscout/EigenPodManager.implementation.ethereum.json" \
  >"$OUT/abi/EigenPodManager.abi.json"
jq -S '.abi' "$OUT/blockscout/P2pMessageSender.ethereum.json" \
  >"$OUT/abi/P2pMessageSender.abi.json"
jq -j '.source_code' "$OUT/blockscout/EigenPodManager.implementation.ethereum.json" \
  >"$OUT/source/EigenPodManager.sol"
jq -j '.source_code' "$OUT/blockscout/P2pMessageSender.ethereum.json" \
  >"$OUT/source/P2pMessageSender.ethereum.sol"

jq -r '.[] | select(.kind=="proxy_code") | .response.result' \
  "$OUT/rpc/ethereum-drpc.json" >"$OUT/runtime/EigenPodManager.proxy.ethereum.hex"
jq -r '.[] | select(.kind=="implementation_code") | .response.result' \
  "$OUT/rpc/ethereum-drpc.json" >"$OUT/runtime/EigenPodManager.implementation.ethereum.hex"
jq -r '.[] | select(.kind=="proxy_code") | .response.result' \
  "$OUT/rpc/hoodi-ethpandaops.json" >"$OUT/runtime/EigenPodManager.proxy.hoodi.hex"
jq -r '.[] | select(.kind=="implementation_code") | .response.result' \
  "$OUT/rpc/hoodi-ethpandaops.json" >"$OUT/runtime/EigenPodManager.implementation.hoodi.hex"
jq -r '.[] | select(.kind=="message_code") | .response.result' \
  "$OUT/rpc/ethereum-drpc.json" >"$OUT/runtime/P2pMessageSender.ethereum.hex"
jq -r '.[] | select(.kind=="message_code") | .response.result' \
  "$OUT/rpc/hoodi-ethpandaops.json" | sort -u >"$OUT/runtime/P2pMessageSender.hoodi.hex"

sed 's/pragma solidity 0\.8\.10;/pragma solidity 0.8.24;/' \
  "$OUT/source/P2pMessageSender.ethereum.sol" \
  >"$OUT/source/P2pMessageSender.hoodi-reference.sol"
SOURCE="$(<"$OUT/source/P2pMessageSender.hoodi-reference.sol")"
jq -nS --arg source "$SOURCE" '{
  language: "Solidity",
  sources: {
    "src/P2pMessageSender.sol": {
      content: $source
    }
  },
  settings: {
    evmVersion: "shanghai",
    optimizer: {
      enabled: true,
      runs: 200
    },
    metadata: {
      bytecodeHash: "ipfs"
    },
    remappings: [],
    viaIR: true,
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "evm.deployedBytecode.object",
          "metadata"
        ]
      }
    }
  }
}' >"$OUT/compiler/P2pMessageSender.hoodi-reference.input.json"
npx -y solc@0.8.24 --standard-json \
  <"$OUT/compiler/P2pMessageSender.hoodi-reference.input.json" \
  | sed '/^>>>/d' \
  | jq -S . >"$OUT/compiler/P2pMessageSender.hoodi-reference.output.json"

echo "Captured P2P pod/message evidence at Ethereum $ETH_BLOCK and Hoodi $HOODI_BLOCK"
