#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
blockscout="$root/blockscout"
source_dir="$root/source"
runtime="$root/runtime"
abi="$root/abi"

mkdir -p "$rpc" "$blockscout" "$source_dir" "$runtime" "$abi"

fetch() {
  curl --fail --silent --show-error --max-time 60 "$@"
}

collect_rpc() {
  local name="$1"
  local url="$2"
  local batch attempt tmp
  for batch in identity proxy implementation; do
    tmp="$(mktemp)"
    for attempt in 1 2 3 4 5 6; do
      if fetch \
        -H 'content-type: application/json' \
        --data-binary "@$rpc/request-$batch.json" \
        "$url" >"$tmp" &&
        jq -e 'type == "array" and all(.[]; (.error? // null) == null and .result != null)' \
          "$tmp" >/dev/null
      then
        mv "$tmp" "$rpc/response-$name-$batch.json"
        break
      fi
      if [[ "$attempt" == 6 ]]; then
        rm -f "$tmp"
        echo "RPC capture failed for $name/$batch after $attempt attempts" >&2
        return 1
      fi
    done
  done
}

collect_rpc forno https://forno.celo.org
collect_rpc drpc https://celo.drpc.org
collect_rpc ankr https://rpc.ankr.com/celo

fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0xaEb865bCa93DdC8F47b8e29F40C5399cE34d0C58 \
  >"$blockscout/ValidatorsProxy.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x13B0B89F3242f815C1FC6C9CF56e1Ab5aEA4dC58 \
  >"$blockscout/Validators.implementation.json"

commit=045aa0061b7d0e9655ff3673cbd25a1bf2b4b74a
base="https://raw.githubusercontent.com/celo-org/celo-monorepo/$commit/packages/protocol/contracts"
base8="https://raw.githubusercontent.com/celo-org/celo-monorepo/$commit/packages/protocol/contracts-0.8"
fetch "$base8/governance/Validators.sol" >"$source_dir/Validators.sol"
fetch "$base/common/Accounts.sol" >"$source_dir/Accounts.sol"
fetch "$base/governance/Election.sol" >"$source_dir/Election.sol"
fetch "$base/common/Registry.sol" >"$source_dir/Registry.sol"
fetch "$base8/common/UsingRegistry.sol" >"$source_dir/UsingRegistry.sol"
fetch "$base8/common/linkedlists/AddressLinkedList.sol" >"$source_dir/AddressLinkedList.sol"
fetch "$base8/common/linkedlists/LinkedList.sol" >"$source_dir/LinkedList.sol"

jq -r '.[] | select(.id == "proxy-code") | .result' \
  "$rpc/response-forno-proxy.json" >"$runtime/ValidatorsProxy.celo-mainnet.hex"
jq -r '.[] | select(.id == "implementation-code") | .result' \
  "$rpc/response-forno-implementation.json" \
  >"$runtime/Validators.implementation.celo-mainnet.hex"

jq -cS '[.abi[] | select(.type == "function" and .name == "addFirstMember")]' \
  "$blockscout/Validators.implementation.json" \
  >"$abi/Validators.add-first-member.abi.json"
