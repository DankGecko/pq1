#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc"
blockscout="$root/blockscout"
official="$root/official"
verified="$root/source/verified"
runtime="$root/runtime"
abi="$root/abi"
compiler="$root/compiler"

mkdir -p "$rpc" "$blockscout" "$official/src" "$verified" "$runtime" "$abi" "$compiler"

fetch() {
  curl \
    --fail --silent --show-error --location \
    --connect-timeout 15 --max-time 90 \
    --retry 4 --retry-all-errors \
    "$@"
}

fetch_json() {
  local url="$1"
  local destination="$2"
  local temporary="/tmp/pqsigner-layerswap-fetch-$$-$RANDOM.json"
  fetch "$url" >"$temporary"
  jq -S '.' "$temporary" >"$destination"
}

collect_rpc() {
  local name="$1"
  local url="$2"
  local temporary="/tmp/pqsigner-layerswap-rpc-$$-$name.json"
  fetch \
    -H 'content-type: application/json' \
    --data-binary "@$rpc/request.json" \
    "$url" >"$temporary"
  jq -e '
    type == "array"
    and length == 4
    and all(.[]; (.error? // null) == null and .result != null)
  ' "$temporary" >/dev/null
  jq -S 'sort_by(.id)' "$temporary" >"$rpc/response-$name.json"
}

collect_rpc mevblocker https://rpc.mevblocker.io
collect_rpc tenderly https://mainnet.gateway.tenderly.co
collect_rpc flashbots https://rpc.flashbots.net

fetch_json \
  https://eth.blockscout.com/api/v2/smart-contracts/0xE226E4825CB215aBaFAd98fdd400583eAb6a594f \
  "$blockscout/LayerswapDepository.json"

commit=a7a4ccd89f0fb5046f8d0053283da6e36c6b638c
raw_base="https://raw.githubusercontent.com/layerswap/layerswap-depository/$commit"
fetch_json \
  "https://api.github.com/repos/layerswap/layerswap-depository/git/commits/$commit" \
  "$official/github-git-commit.json"
fetch "$raw_base/README.md" >"$official/README.md"
fetch "$raw_base/src/LayerswapDepository.sol" >"$official/src/LayerswapDepository.sol"

jq -c \
  '[{path: .file_path, content: .source_code}] + [.additional_sources[] | {path: .file_path, content: .source_code}] | .[]' \
  "$blockscout/LayerswapDepository.json" |
while IFS= read -r row; do
  path="$(jq -r '.path' <<<"$row")"
  case "$path" in
    /*|../*|*/../*|*/..)
      printf 'unsafe verified-source path: %s\n' "$path" >&2
      exit 1
      ;;
  esac
  mkdir -p "$(dirname -- "$verified/$path")"
  jq -r '.content | @base64' <<<"$row" | base64 --decode >"$verified/$path"
done

jq -S '
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
          "src/LayerswapDepository.sol": {
            "LayerswapDepository": ["evm.deployedBytecode.object", "metadata"]
          }
        }
    )
  }
' "$blockscout/LayerswapDepository.json" >"$compiler/LayerswapDepository.standard-input.json"
npx --yes solc@0.8.29 --version >"$compiler/solc-0.8.29.version.txt"
npx --yes solc@0.8.29 --standard-json \
  <"$compiler/LayerswapDepository.standard-input.json" \
  >"/tmp/pqsigner-layerswap-solc-$$.raw"
sed '/^>>>/d' "/tmp/pqsigner-layerswap-solc-$$.raw" \
  >"$compiler/LayerswapDepository.standard-output.json"
jq -e '
  all(.errors[]?; .severity != "error")
  and .contracts["src/LayerswapDepository.sol"].LayerswapDepository.evm.deployedBytecode.object != null
' "$compiler/LayerswapDepository.standard-output.json" >/dev/null

jq -r '.[] | select(.id == "accepted-runtime") | .result' \
  "$rpc/response-mevblocker.json" >"$runtime/LayerswapDepository.ethereum-mainnet.hex"

jq -cS '
  [
    .abi[]
    | select(
        .type == "function"
        and (
          (.name == "depositNative" and [.inputs[].type] == ["bytes32", "address"])
          or
          (.name == "depositERC20" and [.inputs[].type] == ["bytes32", "address", "address", "uint256"])
        )
      )
  ]
  | sort_by(.name)
' "$blockscout/LayerswapDepository.json" >"$abi/LayerswapDepository.deposit-routes.abi.json"

receipts="/tmp/pqsigner-layerswap-artifacts-$$.jsonl"
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  sha256="$(sha256sum "$path" | awk '{print $1}')"
  jq -cn --arg path "$relative" --arg sha256 "$sha256" \
    '{path: $path, sha256: $sha256}' >>"$receipts"
done < <(
  find "$root" -type f ! -name manifest.json -print0 |
    sort -z
)

manifest_temporary="/tmp/pqsigner-layerswap-manifest-$$.json"
jq --slurpfile artifacts "$receipts" '.artifacts = $artifacts' \
  "$root/manifest.json" >"$manifest_temporary"
mv "$manifest_temporary" "$root/manifest.json"

