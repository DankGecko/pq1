#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
blockscout="$root/blockscout"
source_dir="$root/source"
runtime="$root/runtime"
abi="$root/abi"
compiler="$root/compiler"

mkdir -p "$rpc" "$blockscout" "$source_dir/deployed" "$runtime" "$abi" "$compiler"

fetch() {
  curl --fail --silent --show-error --max-time 60 "$@"
}

collect_rpc() {
  local name="$1"
  local url="$2"
  local batch attempt tmp
  for batch in \
    identity proxy implementation dependency-state-a dependency-state-b \
    registry-code accounts-code election-code library-code
  do
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
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x000000000000000000000000000000000000ce10 \
  >"$blockscout/RegistryProxy.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x203fdf86A00999107Df531fa00b4bA81d674cb66 \
  >"$blockscout/Registry.implementation.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x7d21685C17607338b313a7174bAb6620baD0aaB7 \
  >"$blockscout/AccountsProxy.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x907f5c53c0e31db06af45bc58f076563469c525a \
  >"$blockscout/Accounts.implementation.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x8D6677192144292870907E3Fa8A5527fE55A7ff6 \
  >"$blockscout/ElectionProxy.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x74f9e5ee4071b9b35d127000a20f8e964009cb57 \
  >"$blockscout/Election.implementation.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x08a4B5bc1b5aDef0a283C8f0185dEd6169F0Bd29 \
  >"$blockscout/AddressLinkedList.json"
fetch \
  https://celo.blockscout.com/api/v2/smart-contracts/0x0E3E96a0D64B59b46872432f47BeD6A1825A1552 \
  >"$blockscout/AddressSortedLinkedList.json"

commit=045aa0061b7d0e9655ff3673cbd25a1bf2b4b74a
base="https://raw.githubusercontent.com/celo-org/celo-monorepo/$commit/packages/protocol/contracts"
base8="https://raw.githubusercontent.com/celo-org/celo-monorepo/$commit/packages/protocol/contracts-0.8"
fetch "$base8/governance/Validators.sol" >"$source_dir/Validators.sol"
fetch "$base8/common/UsingRegistry.sol" >"$source_dir/UsingRegistry.sol"
fetch "$base8/common/linkedlists/AddressLinkedList.sol" >"$source_dir/AddressLinkedList.sol"
fetch "$base8/common/linkedlists/LinkedList.sol" >"$source_dir/LinkedList.sol"

# Fixed-block dependency sources are fetched independently from official
# upstream revisions and checked against the archived explorer records. The
# Validators linked library predates the 0.8 source imported by the current
# implementation; its exact historical compiler closure reproduces the full
# deployed runtime byte-for-byte after linking the self-address.
accounts_commit=fad3410bdaf159749ace623887caaac7adf753ca
fetch \
  "https://raw.githubusercontent.com/celo-org/celo-monorepo/$accounts_commit/packages/protocol/contracts/common/Accounts.sol" \
  >"$source_dir/deployed/Accounts.sol"
fetch "$base/common/Registry.sol" >"$source_dir/deployed/Registry.sol"
fetch "$base/governance/Election.sol" >"$source_dir/deployed/Election.sol"
fetch "$base/common/linkedlists/AddressSortedLinkedList.sol" \
  >"$source_dir/deployed/AddressSortedLinkedList.sol"
fetch "$base/common/linkedlists/SortedLinkedList.sol" \
  >"$source_dir/deployed/SortedLinkedList.sol"

linked_list_commit=a607b2f504e4aaf998ef1f88fcc893bfb7e7b007
linked_list_base="https://raw.githubusercontent.com/celo-org/celo-monorepo/$linked_list_commit/packages/protocol/contracts/common/linkedlists"
fetch "$linked_list_base/AddressLinkedList.sol" \
  >"$source_dir/deployed/AddressLinkedList.sol"
fetch "$linked_list_base/LinkedList.sol" \
  >"$source_dir/deployed/LinkedList.sol"
openzeppelin_commit=58a3368215581509d05bd3ec4d53cd381c9bb40e
fetch \
  "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/$openzeppelin_commit/contracts/math/SafeMath.sol" \
  >"$source_dir/deployed/SafeMath.sol"

jq -n \
  --rawfile address "$source_dir/deployed/AddressLinkedList.sol" \
  --rawfile linked "$source_dir/deployed/LinkedList.sol" \
  --rawfile safe_math "$source_dir/deployed/SafeMath.sol" \
  '{
    language: "Solidity",
    sources: {
      "project:/contracts/common/linkedlists/AddressLinkedList.sol": {content: $address},
      "project:/contracts/common/linkedlists/LinkedList.sol": {content: $linked},
      "openzeppelin-solidity/contracts/math/SafeMath.sol": {content: $safe_math}
    },
    settings: {
      optimizer: {enabled: false, runs: 200},
      evmVersion: "istanbul",
      metadata: {useLiteralContent: true},
      outputSelection: {"*": {"*": ["evm.deployedBytecode.object", "metadata"]}}
    }
  }' >"$compiler/AddressLinkedList.standard-input.json"
npx --yes solc@0.5.13 --version >"$compiler/solc-0.5.13.version.txt"
npx --yes solc@0.5.13 --standard-json \
  <"$compiler/AddressLinkedList.standard-input.json" \
  >"$compiler/AddressLinkedList.standard-output.json"

jq -r '.[] | select(.id == "proxy-code") | .result' \
  "$rpc/response-forno-proxy.json" >"$runtime/ValidatorsProxy.celo-mainnet.hex"
jq -r '.[] | select(.id == "implementation-code") | .result' \
  "$rpc/response-forno-implementation.json" \
  >"$runtime/Validators.implementation.celo-mainnet.hex"
for id in \
  registry-proxy-code registry-implementation-code \
  accounts-proxy-code accounts-implementation-code \
  election-proxy-code election-implementation-code \
  address-linked-list-code address-sorted-linked-list-code
do
  case "$id" in
    registry-proxy-code) name=RegistryProxy; batch=registry-code ;;
    registry-implementation-code) name=Registry.implementation; batch=registry-code ;;
    accounts-proxy-code) name=AccountsProxy; batch=accounts-code ;;
    accounts-implementation-code) name=Accounts.implementation; batch=accounts-code ;;
    election-proxy-code) name=ElectionProxy; batch=election-code ;;
    election-implementation-code) name=Election.implementation; batch=election-code ;;
    address-linked-list-code) name=AddressLinkedList; batch=library-code ;;
    address-sorted-linked-list-code) name=AddressSortedLinkedList; batch=library-code ;;
  esac
  jq -r --arg id "$id" '.[] | select(.id == $id) | .result' \
    "$rpc/response-forno-$batch.json" \
    >"$runtime/$name.celo-mainnet.hex"
done

jq -cS '[.abi[] | select(.type == "function" and .name == "addFirstMember")]' \
  "$blockscout/Validators.implementation.json" \
  >"$abi/Validators.add-first-member.abi.json"
