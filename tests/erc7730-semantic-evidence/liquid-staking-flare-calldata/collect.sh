#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/erc7730-semantic-evidence/liquid-staking-flare-calldata"

mkdir -p "$OUT/explorer" "$OUT/rpc" "$OUT/runtime"

capture_batch() {
  local name=$1
  local endpoint=$2
  local request="$OUT/rpc/request-$name.json"
  local response="$OUT/rpc/response-$name.json"
  local expected

  expected="$(jq 'length' "$request")"
  curl -fsSL --retry 3 --retry-all-errors --max-time 90 \
    -H 'content-type: application/json' \
    --data-binary "@$request" \
    "$endpoint" |
    jq -S . >"$response"

  jq -e --argjson expected "$expected" '
    type == "array"
    and length == $expected
    and all(.[]; (.error == null) and (.result != null))
  ' "$response" >/dev/null
}

capture_explorer() {
  local url=$1
  local output=$2
  curl -fsSL --retry 3 --retry-all-errors --max-time 90 "$url" |
    jq -S . >"$OUT/explorer/$output"
}

capture_batch avalanche 'https://api.avax.network/ext/bc/C/rpc'
capture_batch ethereum 'https://ethereum-rpc.publicnode.com'
capture_batch flare 'https://flare-api.flare.network/ext/C/rpc'
capture_batch songbird 'https://songbird-api.flare.network/ext/C/rpc'

ROUTESCAN='https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan/api?module=contract&action=getsourcecode&address='
capture_explorer \
  "${ROUTESCAN}0x2b2c81e08f1af8835a78bb2a90ae924ace0ea4be" \
  'benqi-savax-proxy.json'
capture_explorer \
  "${ROUTESCAN}0xb791c7a42fd0d10f90deaa906a8735f79719fa53" \
  'benqi-savax-implementation.json'

BLOCKSCOUT='https://eth.blockscout.com/api/v2/smart-contracts/'
capture_explorer \
  "${BLOCKSCOUT}0x9d39a5de30e57443bfF2a8307a4256c8797a3497" \
  'ethena-susde.json'
capture_explorer \
  "${BLOCKSCOUT}0xfae103dc9cf190ed75350761e95403b7b8afa6c0" \
  'swell-rsweth-proxy.json'
capture_explorer \
  "${BLOCKSCOUT}0x4796d939b22027c2876d5ce9fde52da9ec4e2362" \
  'swell-rsweth-implementation.json'

FLARE_EXPLORER='https://flare-explorer.flare.network/api/v2/smart-contracts/'
capture_explorer \
  "${FLARE_EXPLORER}0x9c7a4c83842b29bb4a082b0e689cb9474bd938d0" \
  'flare-distribution.json'
capture_explorer \
  "${FLARE_EXPLORER}0xc8294a2335c6c45de827121090ce4ba9977907d2" \
  'flare-polling.json'
capture_explorer \
  "${FLARE_EXPLORER}0xc0cf3aaf93bd978c5bc662564aa73e331f2ec0b5" \
  'flare-validator-reward.json'

capture_explorer \
  'https://songbird-explorer.flare.network/api/v2/smart-contracts/0x79df47237292dbd1477502cff3f61cd535b0face' \
  'songbird-polling.json'

extract_runtime() {
  local response=$1
  local id=$2
  local output=$3
  jq -er --arg id "$id" '.[] | select(.id == $id) | .result' \
    "$OUT/rpc/$response" >"$OUT/runtime/$output"
}

extract_runtime response-avalanche.json savax-proxy-code benqi-savax-proxy.hex
extract_runtime response-avalanche.json savax-implementation-code benqi-savax-implementation.hex
extract_runtime response-ethereum.json susde-code ethena-susde.hex
extract_runtime response-ethereum.json swell-proxy-code swell-rsweth-proxy.hex
extract_runtime response-ethereum.json swell-implementation-code swell-rsweth-implementation.hex
extract_runtime response-flare.json distribution-code flare-distribution.hex
extract_runtime response-flare.json polling-code flare-polling.hex
extract_runtime response-songbird.json polling-code songbird-polling.hex
extract_runtime response-flare.json validator-code flare-validator-reward.hex

echo 'Captured liquid-staking and Flare calldata evidence.'
