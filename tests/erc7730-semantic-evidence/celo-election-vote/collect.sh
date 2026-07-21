#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
blockscout="$root/blockscout"
source_dir="$root/source"
runtime="$root/runtime"
abi="$root/abi"
deployment="$root/deployment"

mkdir -p "$rpc" "$blockscout" "$source_dir" "$runtime" "$abi" "$deployment"

fetch() {
  curl --fail --silent --show-error --max-time 60 "$@"
}

collect_rpc() {
  local name="$1"
  local url="$2"
  local batch
  for batch in identity proxy implementation; do
    fetch \
      -H 'content-type: application/json' \
      --data-binary "@$rpc/request-$batch.json" \
      "$url" >"$rpc/response-$name-$batch.json"
  done
}

collect_rpc forno https://forno.celo.org
collect_rpc drpc https://celo.drpc.org
collect_rpc ankr https://rpc.ankr.com/celo

fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x8D6677192144292870907E3Fa8A5527fE55A7ff6 \
  >"$blockscout/ElectionProxy.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x74f9e5ee4071b9b35d127000a20f8e964009cb57 \
  >"$blockscout/Election.implementation.json"

commit=045aa0061b7d0e9655ff3673cbd25a1bf2b4b74a
base="https://raw.githubusercontent.com/celo-org/celo-monorepo/$commit/packages/protocol/contracts"
fetch "$base/governance/Election.sol" >"$source_dir/Election.sol"
fetch "$base/common/Accounts.sol" >"$source_dir/Accounts.sol"
fetch "$base/common/GoldToken.sol" >"$source_dir/GoldToken.sol"
fetch "$base/governance/LockedGold.sol" >"$source_dir/LockedGold.sol"
fetch "$base/common/Registry.sol" >"$source_dir/Registry.sol"
fetch "$base/common/linkedlists/AddressSortedLinkedList.sol" \
  >"$source_dir/AddressSortedLinkedList.sol"
fetch "$base/common/linkedlists/SortedLinkedList.sol" \
  >"$source_dir/SortedLinkedList.sol"

fetch https://docs.celo.org/tooling/contracts/core-contracts.md \
  >"$deployment/core-contracts.md"
fetch https://docs.celo.org/tooling/testnets/celo-sepolia.md \
  >"$deployment/celo-sepolia.md"
fetch \
  https://raw.githubusercontent.com/celo-org/celo-mcp/f398d1de5bdb7c810eeb6c3d225a4ba1a27bc162/src/celo_mcp/config/contracts.py \
  >"$deployment/contracts.py"

jq -r '.[] | select(.id == "proxy-code") | .result' \
  "$rpc/response-forno-proxy.json" >"$runtime/ElectionProxy.celo-mainnet.hex"
jq -r '.[] | select(.id == "implementation-code") | .result' \
  "$rpc/response-forno-implementation.json" \
  >"$runtime/Election.implementation.celo-mainnet.hex"

jq '[.abi[] | select(.type == "function" and .name == "vote")]' \
  "$blockscout/Election.implementation.json" >"$abi/Election.vote.abi.json"
