#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
blockscout="$root/blockscout"
official="$root/official"
verified_staked="$root/source/verified/staked"
verified_router="$root/source/verified/router"
runtime="$root/runtime"
abi="$root/abi"
compiler="$root/compiler"

mkdir -p "$rpc" "$blockscout" "$official" "$verified_staked" \
  "$verified_router" "$runtime" "$abi" "$compiler"

fetch() {
  curl --fail --silent --show-error --location \
    --connect-timeout 15 --max-time 90 --retry 4 --retry-all-errors "$@"
}

fetch_json() {
  local url="$1"
  local destination="$2"
  local tmp
  tmp="$(mktemp)"
  fetch "$url" >"$tmp"
  jq -S '.' "$tmp" >"$destination"
  rm -f "$tmp"
}

collect_rpc() {
  local name="$1"
  local url="$2"
  local batch attempt tmp
  for batch in identity lbtc-state lbtc-metadata lbtc-configuration router-state router-configuration; do
    tmp="$(mktemp)"
    for attempt in 1 2 3 4 5; do
      if fetch -H 'content-type: application/json' \
          --data-binary "@$rpc/request-$batch.json" "$url" >"$tmp" &&
        jq -e 'type == "array" and length > 0 and all(.[]; (.error? // null) == null and .result != null)' "$tmp" >/dev/null
      then
        jq -S 'sort_by(.id)' "$tmp" >"$rpc/response-$name-$batch.json"
        rm -f "$tmp"
        break
      fi
      if [[ "$attempt" == 5 ]]; then
        rm -f "$tmp"
        echo "RPC capture failed for $name/$batch after $attempt attempts" >&2
        return 1
      fi
    done
  done
}

materialize_sources() {
  local record="$1"
  local destination="$2"
  jq -c '[{path: .file_path, content: .source_code}] + [.additional_sources[] | {path: .file_path, content: .source_code}] | .[]' "$record" |
  while IFS= read -r row; do
    local path
    path="$(jq -r '.path' <<<"$row")"
    case "$path" in
      /*|../*|*/../*|*/..)
        echo "unsafe verified-source path: $path" >&2
        exit 1
        ;;
    esac
    mkdir -p "$(dirname -- "$destination/$path")"
    jq -r '.content | @base64' <<<"$row" | base64 --decode >"$destination/$path"
  done
}

compile_record() {
  local record="$1"
  local source_path="$2"
  local contract_name="$3"
  local stem="$4"
  jq -S --arg source "$source_path" --arg contract "$contract_name" '
    {
      language: "Solidity",
      sources: (
        ([{key: .file_path, value: {content: .source_code}}]
         + [.additional_sources[] | {key: .file_path, value: {content: .source_code}}])
        | from_entries
      ),
      settings: (
        .compiler_settings
        | .outputSelection = {
            ($source): {
              ($contract): ["evm.deployedBytecode.object", "metadata"]
            }
          }
      )
    }
  ' "$record" >"$compiler/$stem.standard-input.json"
  npx --yes solc@0.8.24 --standard-json \
    <"$compiler/$stem.standard-input.json" >"$compiler/$stem.standard-output.json"
  jq -e --arg source "$source_path" --arg contract "$contract_name" \
    'all(.errors[]?; .severity != "error") and .contracts[$source][$contract].evm.deployedBytecode.object != null' \
    "$compiler/$stem.standard-output.json" >/dev/null
}

collect_rpc drpc https://eth.drpc.org
collect_rpc tenderly https://mainnet.gateway.tenderly.co
collect_rpc mevblocker https://rpc.mevblocker.io

fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0x8236a87084f8b84306f72007f36f2618a5634494 "$blockscout/StakedLBTCProxy.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0x072072317469ebb6c340a47e41561c9c3b782bd9 "$blockscout/StakedLBTC.implementation.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0x9ece5fb1ab62d9075c4ec814b321e24d8ea021ac "$blockscout/AssetRouterProxy.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0xb823359367978a28eae71e90f79d95b62348bd80 "$blockscout/AssetRouter.implementation.json"

commit=bfd32248badaa2fb35a453f17f3c181badfb3dd6
raw_base="https://raw.githubusercontent.com/lombard-finance/evm-smart-contracts/$commit"
fetch_json "https://api.github.com/repos/lombard-finance/evm-smart-contracts/git/commits/$commit" "$official/github-git-commit.json"
for path in \
  contracts/LBTC/StakedLBTC.sol \
  contracts/LBTC/BaseLBTC.sol \
  contracts/LBTC/AssetRouter.sol \
  contracts/LBTC/interfaces/IAssetRouter.sol \
  contracts/LBTC/interfaces/IBaseLBTC.sol \
  contracts/LBTC/interfaces/IStakedLBTC.sol \
  contracts/LBTC/libraries/Assets.sol \
  contracts/gmp/libs/GMPUtils.sol \
  contracts/libs/Actions.sol \
  contracts/libs/LChainId.sol
do
  mkdir -p "$(dirname -- "$official/$path")"
  fetch "$raw_base/$path" >"$official/$path"
done

materialize_sources "$blockscout/StakedLBTC.implementation.json" "$verified_staked"
materialize_sources "$blockscout/AssetRouter.implementation.json" "$verified_router"
jq -S '.compiler_settings' "$blockscout/StakedLBTC.implementation.json" >"$compiler/StakedLBTC.settings.json"
jq -S '.compiler_settings' "$blockscout/AssetRouter.implementation.json" >"$compiler/AssetRouter.settings.json"
npx --yes solc@0.8.24 --version >"$compiler/solc-0.8.24.version.txt"
compile_record "$blockscout/StakedLBTC.implementation.json" contracts/LBTC/StakedLBTC.sol StakedLBTC StakedLBTC
compile_record "$blockscout/AssetRouter.implementation.json" contracts/LBTC/AssetRouter.sol AssetRouter AssetRouter

jq -r '.[] | select(.id == "lbtc-proxy-code") | .result' "$rpc/response-drpc-lbtc-state.json" >"$runtime/StakedLBTCProxy.ethereum-mainnet.hex"
jq -r '.[] | select(.id == "lbtc-implementation-code") | .result' "$rpc/response-drpc-lbtc-state.json" >"$runtime/StakedLBTC.implementation.ethereum-mainnet.hex"
jq -r '.[] | select(.id == "router-proxy-code") | .result' "$rpc/response-drpc-router-state.json" >"$runtime/AssetRouterProxy.ethereum-mainnet.hex"
jq -r '.[] | select(.id == "router-implementation-code") | .result' "$rpc/response-drpc-router-state.json" >"$runtime/AssetRouter.implementation.ethereum-mainnet.hex"

jq -cS '[.abi[] | select(.type == "function") | select(
  (.name == "approve" and [.inputs[].type] == ["address", "uint256"]) or
  (.name == "burn" and [.inputs[].type] == ["uint256"]) or
  (.name == "permit" and [.inputs[].type] == ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"]) or
  (.name == "redeem" and [.inputs[].type] == ["uint256"]) or
  (.name == "transfer" and [.inputs[].type] == ["address", "uint256"]) or
  (.name == "transferFrom" and [.inputs[].type] == ["address", "address", "uint256"])
)] | sort_by(.name)' "$blockscout/StakedLBTC.implementation.json" >"$abi/StakedLBTC.accepted-routes.abi.json"

receipts="$(mktemp)"
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  sha256="$(sha256sum "$path" | awk '{print $1}')"
  jq -cn --arg path "$relative" --arg sha256 "$sha256" '{path: $path, sha256: $sha256}' >>"$receipts"
done < <(find "$root" -type f ! -name manifest.json -print0 | sort -z)
manifest_tmp="$(mktemp)"
jq --slurpfile artifacts "$receipts" '.artifacts = $artifacts' "$root/manifest.json" >"$manifest_tmp"
mv "$manifest_tmp" "$root/manifest.json"
rm -f "$receipts"
