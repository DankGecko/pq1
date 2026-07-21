#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
blockscout="$root/blockscout"
official="$root/official"
verified_source="$root/source/verified"
runtime="$root/runtime"
abi="$root/abi"
compiler="$root/compiler"

mkdir -p \
  "$rpc" "$blockscout" "$official/config/constants" \
  "$official/scripts/deploy/configs" "$official/contracts/abstract" \
  "$official/contracts/interfaces" "$official/contracts/libraries" \
  "$verified_source" "$runtime" "$abi" "$compiler"

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

  for batch in identity vault vault-implementation mtbill-state mtbill-metadata; do
    tmp="$(mktemp)"
    for attempt in 1 2 3 4 5; do
      if fetch \
        -H 'content-type: application/json' \
        --data-binary "@$rpc/request-$batch.json" \
        "$url" >"$tmp" &&
        jq -e \
          'type == "array" and length > 0 and all(.[]; (.error? // null) == null and .result != null)' \
          "$tmp" >/dev/null
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

collect_rpc drpc https://eth.drpc.org
collect_rpc tenderly https://mainnet.gateway.tenderly.co
collect_rpc mevblocker https://rpc.mevblocker.io

fetch_json \
  https://eth.blockscout.com/api/v2/smart-contracts/0xF6e51d24F4793Ac5e71e0502213a9BBE3A6d4517 \
  "$blockscout/RedemptionVaultProxy.json"
fetch_json \
  https://eth.blockscout.com/api/v2/smart-contracts/0x2F1372244CEDCAf8eE1759D2F02435628f14975f \
  "$blockscout/RedemptionVault.implementation.json"
fetch_json \
  https://eth.blockscout.com/api/v2/smart-contracts/0xdd629e5241cbc5919847783e6c96b2de4754e438 \
  "$blockscout/MTBillProxy.json"
fetch_json \
  https://eth.blockscout.com/api/v2/smart-contracts/0xD4998Cc1ba435298C521f250b81856B1F25C8455 \
  "$blockscout/MTBill.implementation.json"

commit=237c56a85e51560a977d9473ce3f939d877f2a4f
raw_base="https://raw.githubusercontent.com/midas-apps/contracts/$commit"
fetch_json \
  "https://api.github.com/repos/midas-apps/contracts/git/commits/$commit" \
  "$official/github-git-commit.json"
fetch "$raw_base/config/constants/addresses.ts" \
  >"$official/config/constants/addresses.ts"
fetch "$raw_base/scripts/deploy/configs/mTBILL.ts" \
  >"$official/scripts/deploy/configs/mTBILL.ts"
fetch "$raw_base/contracts/RedemptionVault.sol" \
  >"$official/contracts/RedemptionVault.sol"
fetch "$raw_base/contracts/abstract/ManageableVault.sol" \
  >"$official/contracts/abstract/ManageableVault.sol"
fetch "$raw_base/contracts/interfaces/IRedemptionVault.sol" \
  >"$official/contracts/interfaces/IRedemptionVault.sol"
fetch "$raw_base/contracts/interfaces/IMToken.sol" \
  >"$official/contracts/interfaces/IMToken.sol"
fetch "$raw_base/contracts/libraries/DecimalsCorrectionLibrary.sol" \
  >"$official/contracts/libraries/DecimalsCorrectionLibrary.sol"

jq -c \
  '[{path: .file_path, content: .source_code}] + [.additional_sources[] | {path: .file_path, content: .source_code}] | .[]' \
  "$blockscout/RedemptionVault.implementation.json" |
while IFS= read -r row; do
  path="$(jq -r '.path' <<<"$row")"
  case "$path" in
    /*|../*|*/../*|*/..)
      echo "unsafe verified-source path: $path" >&2
      exit 1
      ;;
  esac
  mkdir -p "$(dirname -- "$verified_source/$path")"
  jq -r '.content | @base64' <<<"$row" | base64 --decode \
    >"$verified_source/$path"
done

jq -S '.compiler_settings' \
  "$blockscout/RedemptionVault.implementation.json" \
  >"$compiler/RedemptionVault.settings.json"

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
          "contracts/RedemptionVault.sol": {
            "RedemptionVault": ["evm.deployedBytecode.object", "metadata"]
          }
        }
    )
  }
' "$blockscout/RedemptionVault.implementation.json" \
  >"$compiler/RedemptionVault.standard-input.json"
npx --yes solc@0.8.9 --version >"$compiler/solc-0.8.9.version.txt"
npx --yes solc@0.8.9 --standard-json \
  <"$compiler/RedemptionVault.standard-input.json" \
  >"$compiler/RedemptionVault.standard-output.json"
jq -e '
  all(.errors[]?; .severity != "error")
  and .contracts["contracts/RedemptionVault.sol"].RedemptionVault.evm.deployedBytecode.object != null
' "$compiler/RedemptionVault.standard-output.json" >/dev/null

jq -r '.[] | select(.id == "vault-proxy-code") | .result' \
  "$rpc/response-drpc-vault.json" \
  >"$runtime/RedemptionVaultProxy.ethereum-mainnet.hex"
jq -r '.[] | select(.id == "vault-implementation-code") | .result' \
  "$rpc/response-drpc-vault-implementation.json" \
  >"$runtime/RedemptionVault.implementation.ethereum-mainnet.hex"
jq -r '.[] | select(.id == "mtbill-proxy-code") | .result' \
  "$rpc/response-drpc-mtbill-state.json" \
  >"$runtime/MTBillProxy.ethereum-mainnet.hex"
jq -r '.[] | select(.id == "mtbill-implementation-code") | .result' \
  "$rpc/response-drpc-mtbill-state.json" \
  >"$runtime/MTBill.implementation.ethereum-mainnet.hex"

jq -cS '
  [
    .abi[]
    | select(
        .type == "function"
        and (
          (
            .name == "redeemInstant"
            and (
              [.inputs[].type] == ["address", "uint256", "uint256"]
              or [.inputs[].type] == ["address", "uint256", "uint256", "address"]
            )
          )
          or (
            .name == "redeemRequest"
            and (
              [.inputs[].type] == ["address", "uint256"]
              or [.inputs[].type] == ["address", "uint256", "address"]
            )
          )
          or (
            .name == "redeemFiatRequest"
            and [.inputs[].type] == ["uint256"]
          )
        )
      )
  ]
  | sort_by(.name, (.inputs | length))
' "$blockscout/RedemptionVault.implementation.json" \
  >"$abi/RedemptionVault.redeem-routes.abi.json"

receipts="$(mktemp)"
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  sha256="$(sha256sum "$path" | awk '{print $1}')"
  jq -cn --arg path "$relative" --arg sha256 "$sha256" \
    '{path: $path, sha256: $sha256}' >>"$receipts"
done < <(
  find "$root" -type f ! -name manifest.json -print0 |
    sort -z
)

manifest_tmp="$(mktemp)"
jq --slurpfile artifacts "$receipts" '.artifacts = $artifacts' \
  "$root/manifest.json" >"$manifest_tmp"
mv "$manifest_tmp" "$root/manifest.json"
rm -f "$receipts"
