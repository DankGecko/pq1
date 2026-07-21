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
  https://celo.blockscout.com/api/v2/smart-contracts/0xD533Ca259b330c7A88f74E000a3FaEa2d63B7972 \
  >"$blockscout/GovernanceProxy.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x40cac0be7e25b14e39f782d5b7e5c3076aa6c57a \
  >"$blockscout/Governance.implementation.json"

commit=045aa0061b7d0e9655ff3673cbd25a1bf2b4b74a
base="https://raw.githubusercontent.com/celo-org/celo-monorepo/$commit/packages/protocol/contracts"
fetch "$base/governance/Governance.sol" >"$source_dir/Governance.sol"
fetch "$base/governance/Proposals.sol" >"$source_dir/Proposals.sol"
fetch "$base/common/Accounts.sol" >"$source_dir/Accounts.sol"
fetch "$base/governance/LockedGold.sol" >"$source_dir/LockedGold.sol"
fetch "$base/common/Registry.sol" >"$source_dir/Registry.sol"
fetch "$base/common/UsingRegistry.sol" >"$source_dir/UsingRegistry.sol"
fetch "$base/common/linkedlists/IntegerSortedLinkedList.sol" \
  >"$source_dir/IntegerSortedLinkedList.sol"
fetch "$base/common/linkedlists/SortedLinkedList.sol" \
  >"$source_dir/SortedLinkedList.sol"

jq -r '.[] | select(.id == "proxy-code") | .result' \
  "$rpc/response-forno-proxy.json" >"$runtime/GovernanceProxy.celo-mainnet.hex"
jq -r '.[] | select(.id == "implementation-code") | .result' \
  "$rpc/response-forno-implementation.json" \
  >"$runtime/Governance.implementation.celo-mainnet.hex"

jq -cS '[.abi[] | select(.type == "function" and (.name == "upvote" or .name == "revokeUpvote" or .name == "vote" or .name == "votePartially"))]' \
  "$blockscout/Governance.implementation.json" \
  >"$abi/Governance.voting-routes.abi.json"
