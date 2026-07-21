#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
runtime="$root/runtime"
verifier="$root/verifier"
official="$root/official"
abi="$root/abi"

mkdir -p \
  "$rpc" "$runtime" "$verifier/sourcify" "$verifier/aurora" \
  "$verifier/zksync" "$official/github" "$official/audits" \
  "$official/prerelease-19/contracts/helpers" \
  "$official/prerelease-19/contracts/libraries" \
  "$official/prerelease-19/contracts/interfaces" \
  "$official/v4.0.0/contracts/helpers" \
  "$official/v4.0.0/contracts/libraries" \
  "$official/v4.0.0/contracts/interfaces" "$abi"

tmp="$(mktemp "$root/.collect.XXXXXX")"
receipt_lines="$(mktemp "$root/.receipts.XXXXXX")"
trap 'rm -f "$tmp" "$receipt_lines"' EXIT

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

fetch_expected_status_json() {
  local expected_status="$1"
  local url="$2"
  local destination="$3"
  local status_destination="$4"
  local status

  status="$(curl \
    --silent --show-error --location \
    --connect-timeout 15 --max-time 120 \
    --retry 5 --retry-all-errors --retry-delay 1 \
    --output "$tmp" --write-out '%{http_code}' \
    "$url")"
  if [[ "$status" != "$expected_status" ]]; then
    echo "expected HTTP $expected_status from $url, received $status" >&2
    return 1
  fi
  jq -S '.' "$tmp" >"$destination"
  printf '%s\n' "$status" >"$status_destination"
}

rpc_request() {
  local url="$1"
  local request_path="$2"
  local destination="$3"
  local attempt

  for attempt in 1 2 3 4 5; do
    if fetch \
      -H 'content-type: application/json' \
      --data-binary "@$request_path" \
      "$url" >"$tmp" &&
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

decoded_sha256() {
  sed 's/^0x//' "$1" | tr -d '\n\r ' | xxd -r -p | sha256sum | awk '{print $1}'
}

collect_chain() {
  local chain_id="$1"
  local slug="$2"
  local block_number="$3"
  local address="$4"
  local provider_a_name="$5"
  local provider_a_url="$6"
  local provider_b_name="$7"
  local provider_b_url="$8"
  local block_hex header_request request_path response_a response_b
  local block_hash header_a header_b code_a code_b runtime_path
  local state_root timestamp parent_hash bytes file_sha decoded_sha

  block_hex="$(printf '0x%x' "$block_number")"
  header_request="$rpc/request-$slug-header-bootstrap.json"
  jq -nS \
    --arg id "$slug-header-bootstrap" \
    --arg block "$block_hex" \
    '[{jsonrpc:"2.0", id:$id, method:"eth_getBlockByNumber", params:[$block, false]}]' \
    >"$header_request"
  rpc_request "$provider_a_url" "$header_request" "$tmp.header"
  block_hash="$(jq -r '.[0].result.hash' "$tmp.header")"

  request_path="$rpc/request-$slug.json"
  jq -nS \
    --arg header_id "$slug-header" \
    --arg code_id "$slug-code" \
    --arg block "$block_hex" \
    --arg address "$address" \
    --arg block_hash "$block_hash" \
    '[
      {jsonrpc:"2.0", id:$header_id, method:"eth_getBlockByNumber", params:[$block, false]},
      {jsonrpc:"2.0", id:$code_id, method:"eth_getCode", params:[$address, {blockHash:$block_hash, requireCanonical:true}]}
    ]' >"$request_path"

  response_a="$rpc/response-$slug-$provider_a_name.json"
  response_b="$rpc/response-$slug-$provider_b_name.json"
  rpc_request "$provider_a_url" "$request_path" "$response_a"
  rpc_request "$provider_b_url" "$request_path" "$response_b"

  header_a="$(jq -c --arg id "$slug-header" '.[] | select(.id == $id) | .result' "$response_a")"
  header_b="$(jq -c --arg id "$slug-header" '.[] | select(.id == $id) | .result' "$response_b")"
  code_a="$(jq -r --arg id "$slug-code" '.[] | select(.id == $id) | .result' "$response_a")"
  code_b="$(jq -r --arg id "$slug-code" '.[] | select(.id == $id) | .result' "$response_b")"

  if [[ "$(jq -r '.hash' <<<"$header_a")" != "$block_hash" ]] ||
     [[ "$(jq -r '.hash' <<<"$header_b")" != "$block_hash" ]] ||
     [[ "$(jq -r '.number' <<<"$header_a")" != "$block_hex" ]] ||
     [[ "$(jq -r '.number' <<<"$header_b")" != "$block_hex" ]] ||
     [[ "$code_a" != "$code_b" ]] ||
     [[ "$code_a" == "0x" ]]
  then
    echo "provider disagreement for chain $chain_id ($slug)" >&2
    return 1
  fi

  runtime_path="$runtime/AggregationRouterV6.$slug.hex"
  printf '%s\n' "$code_a" >"$runtime_path"
  state_root="$(jq -r '.stateRoot' <<<"$header_a")"
  timestamp="$(jq -r '.timestamp' <<<"$header_a")"
  parent_hash="$(jq -r '.parentHash' <<<"$header_a")"
  bytes="$(( (${#code_a} - 2) / 2 ))"
  file_sha="$(sha256sum "$runtime_path" | awk '{print $1}')"
  decoded_sha="$(decoded_sha256 "$runtime_path")"

  jq -cn \
    --argjson chain_id "$chain_id" \
    --arg slug "$slug" \
    --arg address "$address" \
    --argjson block_number "$block_number" \
    --arg block_number_hex "$block_hex" \
    --arg block_hash "$block_hash" \
    --arg parent_hash "$parent_hash" \
    --arg state_root "$state_root" \
    --arg timestamp_hex "$timestamp" \
    --arg request_path "rpc/raw/request-$slug.json" \
    --arg provider_a_name "$provider_a_name" \
    --arg provider_a_url "$provider_a_url" \
    --arg response_a_path "rpc/raw/response-$slug-$provider_a_name.json" \
    --arg provider_b_name "$provider_b_name" \
    --arg provider_b_url "$provider_b_url" \
    --arg response_b_path "rpc/raw/response-$slug-$provider_b_name.json" \
    --arg runtime_path "runtime/AggregationRouterV6.$slug.hex" \
    --arg runtime_file_sha256 "$file_sha" \
    --arg runtime_decoded_sha256 "$decoded_sha" \
    --argjson runtime_bytes "$bytes" \
    '{
      chain_id:$chain_id,
      slug:$slug,
      address:$address,
      block:{
        number:$block_number,
        number_hex:$block_number_hex,
        hash:$block_hash,
        parent_hash:$parent_hash,
        state_root:$state_root,
        timestamp_hex:$timestamp_hex
      },
      request_path:$request_path,
      providers:[
        {name:$provider_a_name, url:$provider_a_url, response_path:$response_a_path},
        {name:$provider_b_name, url:$provider_b_url, response_path:$response_b_path}
      ],
      runtime:{
        path:$runtime_path,
        file_sha256:$runtime_file_sha256,
        decoded_sha256:$runtime_decoded_sha256,
        bytes:$runtime_bytes
      }
    }' >>"$receipt_lines"

  # The bootstrap request is only a collection aid. The retained request and
  # both retained responses contain the independently observed header and the
  # EIP-1898 block-hash-bound code query.
  rm -f "$header_request" "$tmp.header"
}

normal_address=0x111111125421cA6dc452d289314280a0f8842A65
zksync_address=0x6fd4383cB451173D5f9304F041C7BCBf27d561fF

# Provider pairs are independently operated and require no repository secret.
# The fixed block numbers are deliberately historical; the checked-in raw
# responses remain the evidence if a public provider later changes retention.
collect_chain 1 ethereum 25581128 "$normal_address" drpc https://eth.drpc.org mevblocker https://rpc.mevblocker.io
collect_chain 10 optimism 154519885 "$normal_address" optimism https://mainnet.optimism.io publicnode https://optimism-rpc.publicnode.com
collect_chain 56 bsc 111287866 "$normal_address" publicnode https://bsc-rpc.publicnode.com pocket https://bsc.api.pocket.network
collect_chain 100 gnosis 47316637 "$normal_address" drpc https://gnosis.drpc.org tenderly https://gnosis.gateway.tenderly.co
collect_chain 137 polygon 90622689 "$normal_address" drpc https://polygon.drpc.org tenderly https://polygon.gateway.tenderly.co
collect_chain 8453 base 48924600 "$normal_address" base https://mainnet.base.org publicnode https://base-rpc.publicnode.com
collect_chain 42161 arbitrum 486191758 "$normal_address" arbitrum https://arb1.arbitrum.io/rpc publicnode https://arbitrum-one-rpc.publicnode.com
collect_chain 59144 linea 31467177 "$normal_address" linea https://rpc.linea.build one-rpc https://1rpc.io/linea
collect_chain 1313161554 aurora 207912504 "$normal_address" aurora https://mainnet.aurora.dev one-rpc https://1rpc.io/aurora
collect_chain 324 zksync 71249090 "$zksync_address" zksync https://mainnet.era.zksync.io one-rpc https://1rpc.io/zksync2-era

jq -sS '{schema_version:1, observations:.}' "$receipt_lines" \
  >"$root/rpc/fixed-block-receipt.json"

sourcify_fields='sources%2Ccompilation%2CruntimeBytecode.onchainBytecode%2CruntimeBytecode.immutableReferences%2Cdeployment%2CproxyResolution'
for chain_id in 1 10 56 100 137 8453 42161 59144; do
  fetch_json \
    "https://sourcify.dev/server/v2/contract/$chain_id/$normal_address?fields=$sourcify_fields" \
    "$verifier/sourcify/$chain_id.json"
done

for chain_id in 146 250 8217 43114; do
  fetch_expected_status_json 404 \
    "https://sourcify.dev/server/v2/contract/$chain_id/$normal_address?fields=$sourcify_fields" \
    "$verifier/sourcify/excluded-$chain_id.json" \
    "$verifier/sourcify/excluded-$chain_id.http-status.txt"
done

fetch_json \
  "https://explorer.mainnet.aurora.dev/api/v2/smart-contracts/$normal_address" \
  "$verifier/aurora/AggregationRouterV6.json"
fetch_json \
  "https://block-explorer-api.mainnet.zksync.io/address/0x6fd4383cb451173d5f9304f041c7bcbf27d561ff" \
  "$verifier/zksync/address.json"
fetch_json \
  "https://block-explorer-api.mainnet.zksync.io/api?module=contract&action=getsourcecode&address=0x6fd4383cb451173d5f9304f041c7bcbf27d561ff" \
  "$verifier/zksync/source.json"

prerelease_commit=1a32e059f78ddcf1fe6294baed6cafb73a04b685
final_commit=c8be9c67247880bd6ec88cf7ad2e040a16a483f2
repository=https://raw.githubusercontent.com/1inch/limit-order-protocol
source_paths=(
  contracts/OrderMixin.sol
  contracts/helpers/SeriesEpochManager.sol
  contracts/libraries/MakerTraitsLib.sol
  contracts/libraries/BitInvalidatorLib.sol
  contracts/libraries/RemainingInvalidatorLib.sol
  contracts/interfaces/IOrderMixin.sol
)

for path in "${source_paths[@]}"; do
  fetch "$repository/$prerelease_commit/$path" \
    >"$official/prerelease-19/$path"
  fetch "$repository/$final_commit/$path" \
    >"$official/v4.0.0/$path"
done
fetch "$repository/$prerelease_commit/README.md" \
  >"$official/prerelease-19/README.md"

fetch_json \
  "https://api.github.com/repos/1inch/limit-order-protocol/git/commits/$prerelease_commit" \
  "$official/github/prerelease-19.commit.json"
fetch_json \
  "https://api.github.com/repos/1inch/limit-order-protocol/git/commits/$final_commit" \
  "$official/github/v4.0.0.commit.json"
fetch_json \
  "https://api.github.com/repos/1inch/limit-order-protocol/git/ref/tags/4.0.0-prerelease-19" \
  "$official/github/prerelease-19.ref.json"
fetch_json \
  "https://api.github.com/repos/1inch/limit-order-protocol/git/ref/tags/4.0.0" \
  "$official/github/v4.0.0.ref.json"

# This pins the official audit catalogue entry for the V6/V4 family. It does
# not claim that every audit finding or scope maps to every deployed wrapper.
audit_commit=1deaa3bca4d3f0637bd0bfac4430e620956dba22
fetch_json \
  "https://api.github.com/repos/1inch/1inch-audits/git/commits/$audit_commit" \
  "$official/audits/github-git-commit.json"
fetch_json \
  "https://api.github.com/repos/1inch/1inch-audits/contents/Aggregation%20Pr.%20V6%20and%20Limit%20Order%20Pr.V4?ref=$audit_commit" \
  "$official/audits/AggregationRouterV6-LimitOrderV4.directory.json"

jq -cS '
  [
    .abi[]
    | select(
        .type == "function"
        and (
          (.name == "cancelOrder" and [.inputs[].type] == ["uint256", "bytes32"])
          or (.name == "cancelOrders" and [.inputs[].type] == ["uint256[]", "bytes32[]"])
          or (.name == "increaseEpoch" and [.inputs[].type] == ["uint96"])
          or (.name == "bitsInvalidateForOrder" and [.inputs[].type] == ["uint256", "uint256"])
          or (.name == "advanceEpoch" and [.inputs[].type] == ["uint96", "uint256"])
        )
      )
  ]
  | sort_by(.name)
' "$verifier/aurora/AggregationRouterV6.json" \
  >"$abi/AggregationRouterV6.cancellation.abi.json"

# Refresh a complete deterministic receipt set after a successful capture.
artifact_lines="$(mktemp "$root/.artifacts.XXXXXX")"
trap 'rm -f "$tmp" "$receipt_lines" "$artifact_lines"' EXIT
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  sha256="$(sha256sum "$path" | awk '{print $1}')"
  jq -cn --arg path "$relative" --arg sha256 "$sha256" \
    '{path:$path, sha256:$sha256}' >>"$artifact_lines"
done < <(
  find "$root" -type f \
    ! -name manifest.json \
    ! -name '.collect.*' \
    ! -name '.receipts.*' \
    ! -name '.artifacts.*' \
    -print0 | sort -z
)

manifest_tmp="$(mktemp "$root/.manifest.XXXXXX")"
trap 'rm -f "$tmp" "$receipt_lines" "$artifact_lines" "$manifest_tmp"' EXIT
jq --arg captured_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --slurpfile artifacts "$artifact_lines" \
  '.captured_at_utc = $captured_at_utc | .artifacts = $artifacts' \
  "$root/manifest.json" >"$manifest_tmp"
mv "$manifest_tmp" "$root/manifest.json"
