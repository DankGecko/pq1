#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

THRESHOLD_REPOSITORY="https://github.com/threshold-network/tbtc-v2"
THRESHOLD_COMMIT="c10e824f68bcda32e7ab1b425ac00344d96a89c9"
THRESHOLD_TREE="16522547b39ddfeab8e5e07fffdaa74e752f732a"
WORMHOLE_REPOSITORY="https://github.com/wormhole-foundation/wormhole-sdk-ts"
WORMHOLE_COMMIT="4f8a03a5ef9b19a5e4af5b972535f16b77842f8d"

IMPLEMENTATION_SLOT="0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT="0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON_SLOT="0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

mkdir -p \
  "$ROOT/official" \
  "$ROOT/rpc" \
  "$ROOT/runtime" \
  "$ROOT/source" \
  "$ROOT/verified"

rpc_result_one() {
  local endpoint="$1"
  local method="$2"
  local params="$3"
  local response
  if ! response="$(
    curl -fsS \
      --connect-timeout 5 \
      --max-time 20 \
      --retry 2 \
      --retry-all-errors \
      --retry-delay 1 \
      -H 'content-type: application/json' \
      --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
      "$endpoint"
  )"; then
    return 1
  fi
  if ! jq -e '
    type == "object" and
    .jsonrpc == "2.0" and
    (.error == null) and
    has("result") and
    .result != null
  ' >/dev/null <<<"$response"; then
    jq -c '{endpoint_error:(.error // "missing or null result")}' \
      <<<"$response" >&2 || true
    return 1
  fi
  jq -c '.result' <<<"$response"
}

rpc_result() {
  local endpoint_set="$1"
  local method="$2"
  local params="$3"
  local endpoint
  local result
  IFS='|' read -r -a endpoints <<<"$endpoint_set"
  for endpoint in "${endpoints[@]}"; do
    if result="$(rpc_result_one "$endpoint" "$method" "$params")"; then
      printf '%s\n' "$result"
      return 0
    fi
  done
  printf 'all bounded RPC endpoints failed for %s\n' "$method" >&2
  return 1
}

decode_address() {
  local word="${1#0x}"
  printf '0x%s' "${word: -40}" | tr '[:upper:]' '[:lower:]'
}

runtime_receipt() {
  local endpoint="$1"
  local block="$2"
  local address="$3"
  local file="$4"
  local path="$ROOT/runtime/$file"
  local code
  local decoded_sha256
  local bytes
  local keccak256

  code="$(rpc_result "$endpoint" eth_getCode "[\"$address\",\"$block\"]" | jq -r .)"
  test "$code" != "0x"
  printf '%s\n' "$code" >"$path"
  decoded_sha256="$(
    tr -d '\n' <"$path" |
      sed 's/^0x//' |
      xxd -r -p |
      sha256sum |
      cut -d' ' -f1
  )"
  bytes="$(((${#code} - 2) / 2))"
  keccak256="$(cast keccak "$code")"

  jq -nc \
    --arg file "runtime/$file" \
    --argjson bytes "$bytes" \
    --arg decoded_sha256 "$decoded_sha256" \
    --arg keccak256 "$keccak256" \
    '{file:$file,bytes:$bytes,decoded_sha256:$decoded_sha256,keccak256:$keccak256}'
}

fixed_block() {
  local endpoint_set="$1"
  local block="$2"
  local header
  local corroborating_header
  local number
  local endpoint
  IFS='|' read -r -a endpoints <<<"$endpoint_set"
  header="$(
    rpc_result_one "${endpoints[0]}" eth_getBlockByNumber "[\"$block\",false]"
  )"
  if ((${#endpoints[@]} < 2)); then
    printf 'fixed block requires an independent corroborating endpoint\n' >&2
    return 1
  fi
  corroborating_header="$(
    rpc_result_one "${endpoints[1]}" eth_getBlockByNumber "[\"$block\",false]"
  )"
  test "$(jq -r '.number' <<<"$header")" = \
    "$(jq -r '.number' <<<"$corroborating_header")"
  test "$(jq -r '.hash' <<<"$header")" = \
    "$(jq -r '.hash' <<<"$corroborating_header")"
  test "$(jq -r '.stateRoot' <<<"$header")" = \
    "$(jq -r '.stateRoot' <<<"$corroborating_header")"
  number="$(cast to-dec "$(jq -r '.number' <<<"$header")")"
  jq -c \
    --argjson number "$number" \
    --arg primary_endpoint "${endpoints[0]}" \
    --arg corroborating_endpoint "${endpoints[1]}" \
    '{
    number:$number,
    number_hex:.number,
    hash:.hash,
    state_root:.stateRoot,
    timestamp:.timestamp,
    independently_corroborated_by:[$primary_endpoint,$corroborating_endpoint]
  }' <<<"$header"
}

call_word() {
  local endpoint="$1"
  local block="$2"
  local address="$3"
  local selector="$4"
  rpc_result "$endpoint" eth_call \
    "[{\"to\":\"$address\",\"data\":\"$selector\"},\"$block\"]" |
    jq -r .
}

token_metadata() {
  local endpoint="$1"
  local block="$2"
  local address="$3"
  local name_raw
  local symbol_raw
  local decimals_raw
  local name
  local symbol
  local decimals

  name_raw="$(call_word "$endpoint" "$block" "$address" 0x06fdde03)"
  symbol_raw="$(call_word "$endpoint" "$block" "$address" 0x95d89b41)"
  decimals_raw="$(call_word "$endpoint" "$block" "$address" 0x313ce567)"
  name="$(cast abi-decode 'f()(string)' "$name_raw" | jq -r .)"
  symbol="$(cast abi-decode 'f()(string)' "$symbol_raw" | jq -r .)"
  decimals="$(cast to-dec "$decimals_raw")"

  jq -nc \
    --arg address "$(printf '%s' "$address" | tr '[:upper:]' '[:lower:]')" \
    --arg name "$name" \
    --arg symbol "$symbol" \
    --argjson decimals "$decimals" \
    --arg name_raw "$name_raw" \
    --arg symbol_raw "$symbol_raw" \
    --arg decimals_raw "$decimals_raw" \
    '{
      address:$address,
      name:$name,
      symbol:$symbol,
      decimals:$decimals,
      raw_calls:{
        "name()":$name_raw,
        "symbol()":$symbol_raw,
        "decimals()":$decimals_raw
      }
    }'
}

collect_gateway() {
  local network="$1"
  local chain_id="$2"
  local endpoint="$3"
  local block="$4"
  local proxy="$5"
  local expected_implementation="$6"
  local slug="$7"
  local block_receipt
  local implementation_word
  local implementation
  local proxy_runtime
  local implementation_runtime
  local tbtc_raw
  local bridge_raw
  local bridge_token_raw
  local tbtc
  local bridge
  local bridge_token
  local metadata

  block_receipt="$(fixed_block "$endpoint" "$block")"
  implementation_word="$(
    rpc_result "$endpoint" eth_getStorageAt \
      "[\"$proxy\",\"$IMPLEMENTATION_SLOT\",\"$block\"]" |
      jq -r .
  )"
  implementation="$(decode_address "$implementation_word")"
  test "$implementation" = "$expected_implementation"

  proxy_runtime="$(
    runtime_receipt "$endpoint" "$block" "$proxy" "gateway-$slug-proxy.hex"
  )"
  implementation_runtime="$(
    runtime_receipt \
      "$endpoint" \
      "$block" \
      "$implementation" \
      "gateway-$slug-implementation.hex"
  )"

  tbtc_raw="$(call_word "$endpoint" "$block" "$proxy" 0xe1308b33)"
  bridge_raw="$(call_word "$endpoint" "$block" "$proxy" 0xe78cea92)"
  bridge_token_raw="$(call_word "$endpoint" "$block" "$proxy" 0xf4734b0c)"
  tbtc="$(decode_address "$tbtc_raw")"
  bridge="$(decode_address "$bridge_raw")"
  bridge_token="$(decode_address "$bridge_token_raw")"
  metadata="$(token_metadata "$endpoint" "$block" "$tbtc")"

  jq -nc \
    --arg network "$network" \
    --argjson chain_id "$chain_id" \
    --arg endpoint_set "$endpoint" \
    --arg proxy "$(printf '%s' "$proxy" | tr '[:upper:]' '[:lower:]')" \
    --arg implementation "$implementation" \
    --arg implementation_word "$implementation_word" \
    --arg tbtc "$tbtc" \
    --arg tbtc_raw "$tbtc_raw" \
    --arg bridge "$bridge" \
    --arg bridge_raw "$bridge_raw" \
    --arg bridge_token "$bridge_token" \
    --arg bridge_token_raw "$bridge_token_raw" \
    --argjson evidence_block "$block_receipt" \
    --argjson proxy_runtime "$proxy_runtime" \
    --argjson implementation_runtime "$implementation_runtime" \
    --argjson token_metadata "$metadata" \
    '{
      network:$network,
      chain_id:$chain_id,
      rpc_endpoints:($endpoint_set | split("|")),
      evidence_block:$evidence_block,
      proxy:$proxy,
      eip1967_implementation_slot:$implementation_word,
      implementation:$implementation,
      proxy_runtime:$proxy_runtime,
      implementation_runtime:$implementation_runtime,
      bindings:{
        tbtc:{address:$tbtc,raw_call:$tbtc_raw},
        bridge:{address:$bridge,raw_call:$bridge_raw},
        bridge_token:{address:$bridge_token,raw_call:$bridge_token_raw}
      },
      tbtc_metadata:$token_metadata
    }'
}

collect_rebate() {
  local endpoint="https://mainnet.gateway.tenderly.co|https://eth.drpc.org"
  local block="0x18703df"
  local proxy="0x0184739C32edc3471D3e4860c8E39a5f3Ff85A45"
  local expected_implementation="0x25aaf04229f77a9ae80430b3c89e3455ab2ec22f"
  local implementation_word
  local implementation
  local token_raw
  local bridge_raw
  local token

  implementation_word="$(
    rpc_result "$endpoint" eth_getStorageAt \
      "[\"$proxy\",\"$IMPLEMENTATION_SLOT\",\"$block\"]" |
      jq -r .
  )"
  implementation="$(decode_address "$implementation_word")"
  test "$implementation" = "$expected_implementation"
  token_raw="$(call_word "$endpoint" "$block" "$proxy" 0xfc0c546a)"
  bridge_raw="$(call_word "$endpoint" "$block" "$proxy" 0xe78cea92)"
  token="$(decode_address "$token_raw")"

  jq -nc \
    --arg endpoint_set "$endpoint" \
    --arg proxy "$(printf '%s' "$proxy" | tr '[:upper:]' '[:lower:]')" \
    --arg implementation "$implementation" \
    --arg implementation_word "$implementation_word" \
    --arg token "$(decode_address "$token_raw")" \
    --arg token_raw "$token_raw" \
    --arg bridge "$(decode_address "$bridge_raw")" \
    --arg bridge_raw "$bridge_raw" \
    --argjson evidence_block "$(fixed_block "$endpoint" "$block")" \
    --argjson proxy_runtime "$(
      runtime_receipt "$endpoint" "$block" "$proxy" rebate-proxy.hex
    )" \
    --argjson implementation_runtime "$(
      runtime_receipt \
        "$endpoint" \
        "$block" \
        "$implementation" \
        rebate-implementation.hex
    )" \
    --argjson token_metadata "$(token_metadata "$endpoint" "$block" "$token")" \
    '{
      network:"ethereum-mainnet",
      chain_id:1,
      rpc_endpoints:($endpoint_set | split("|")),
      evidence_block:$evidence_block,
      proxy:$proxy,
      eip1967_implementation_slot:$implementation_word,
      implementation:$implementation,
      proxy_runtime:$proxy_runtime,
      implementation_runtime:$implementation_runtime,
      bindings:{
        token:{address:$token,raw_call:$token_raw},
        bridge:{address:$bridge,raw_call:$bridge_raw}
      },
      token_metadata:$token_metadata
    }'
}

collect_vault() {
  local network="$1"
  local chain_id="$2"
  local endpoint="$3"
  local block="$4"
  local address="$5"
  local slug="$6"
  local implementation_slot
  local admin_slot
  local beacon_slot

  implementation_slot="$(
    rpc_result "$endpoint" eth_getStorageAt \
      "[\"$address\",\"$IMPLEMENTATION_SLOT\",\"$block\"]" |
      jq -r .
  )"
  admin_slot="$(
    rpc_result "$endpoint" eth_getStorageAt \
      "[\"$address\",\"$ADMIN_SLOT\",\"$block\"]" |
      jq -r .
  )"
  beacon_slot="$(
    rpc_result "$endpoint" eth_getStorageAt \
      "[\"$address\",\"$BEACON_SLOT\",\"$block\"]" |
      jq -r .
  )"

  jq -nc \
    --arg network "$network" \
    --argjson chain_id "$chain_id" \
    --arg endpoint_set "$endpoint" \
    --arg address "$(printf '%s' "$address" | tr '[:upper:]' '[:lower:]')" \
    --arg implementation_slot "$implementation_slot" \
    --arg admin_slot "$admin_slot" \
    --arg beacon_slot "$beacon_slot" \
    --argjson evidence_block "$(fixed_block "$endpoint" "$block")" \
    --argjson runtime "$(
      runtime_receipt "$endpoint" "$block" "$address" "vault-$slug.hex"
    )" \
    '{
      network:$network,
      chain_id:$chain_id,
      rpc_endpoints:($endpoint_set | split("|")),
      evidence_block:$evidence_block,
      address:$address,
      standard_proxy_slots:{
        implementation:$implementation_slot,
        admin:$admin_slot,
        beacon:$beacon_slot
      },
      runtime:$runtime
    }'
}

fetch_verified() {
  local chain_id="$1"
  local address="$2"
  local source_pattern="$3"
  local abi_names="$4"
  local output="$5"
  local response="$TMP/sourcify.json"

  curl -fsS --retry 5 --retry-all-errors --retry-delay 1 \
    "https://sourcify.dev/server/v2/contract/$chain_id/$address?fields=abi,compilation,runtimeMatch,creationMatch,verifiedAt,sourceIds,sources" \
    >"$response"
  jq \
    --arg source_pattern "$source_pattern" \
    --arg abi_names "$abi_names" \
    '($abi_names | split(",")) as $names |
    {
      address,
      chainId,
      match,
      runtimeMatch,
      creationMatch,
      verifiedAt,
      compilation,
      routeAbi:[
        .abi[] |
        select(.type == "function" and (.name as $name | $names | index($name)))
      ],
      sources:(
        .sources |
        with_entries(select(.key | test($source_pattern)))
      )
    }' \
    "$response" >"$ROOT/verified/$output"
}

collect_gateway \
  base-mainnet \
  8453 \
  'https://base.gateway.tenderly.co|https://base.drpc.org' \
  0x2ee9a76 \
  0x09959798B95d00a3183d20FaC298E4594E599eab \
  0x40fa0a360818b04b9975680746dc0b7092105a0c \
  base >"$TMP/gateway-base.json"
collect_gateway \
  base-sepolia \
  84532 \
  'https://base-sepolia.gateway.tenderly.co|https://base-sepolia.drpc.org' \
  0x2aa1977 \
  0xc3D46e0266d95215589DE639cC4E93b79f88fc6C \
  0x9a82be743f0120fa24893b1631b6b2817fd94b1d \
  base-sepolia >"$TMP/gateway-base-sepolia.json"
collect_gateway \
  arbitrum-one \
  42161 \
  'https://arbitrum.gateway.tenderly.co|https://arb-pokt.nodies.app' \
  0x1d1b3a2b \
  0x1293a54e160D1cd7075487898d65266081A15458 \
  0x7ff02bb686658f2d55f28fdf45286f9499beb9a5 \
  arbitrum >"$TMP/gateway-arbitrum.json"
collect_gateway \
  arbitrum-sepolia \
  421614 \
  'https://arbitrum-sepolia.gateway.tenderly.co|https://arbitrum-sepolia.drpc.org' \
  0x1166c919 \
  0xc3D46e0266d95215589DE639cC4E93b79f88fc6C \
  0x9a82be743f0120fa24893b1631b6b2817fd94b1d \
  arbitrum-sepolia >"$TMP/gateway-arbitrum-sepolia.json"
collect_gateway \
  optimism-mainnet \
  10 \
  'https://optimism.gateway.tenderly.co|https://optimism.drpc.org' \
  0x939dc0b \
  0x1293a54e160D1cd7075487898d65266081A15458 \
  0xc08dcc93130ab30987dd7fe64e011402bbe5fda6 \
  optimism >"$TMP/gateway-optimism.json"
collect_gateway \
  optimism-sepolia \
  11155420 \
  'https://optimism-sepolia.gateway.tenderly.co|https://optimism-sepolia.drpc.org' \
  0x2c85b11 \
  0x5FB63D9e076a314023F2D1aB5dBFd7045C281EbA \
  0xc3d46e0266d95215589de639cc4e93b79f88fc6c \
  optimism-sepolia >"$TMP/gateway-optimism-sepolia.json"
collect_gateway \
  polygon-mainnet \
  137 \
  'https://polygon.gateway.tenderly.co|https://polygon.drpc.org' \
  0x56c37f2 \
  0x09959798B95d00a3183d20FaC298E4594E599eab \
  0x04671c72aab5ac02a03c1098314b1bb6b560c197 \
  polygon >"$TMP/gateway-polygon.json"

collect_rebate >"$TMP/rebate.json"
collect_vault \
  ethereum-mainnet \
  1 \
  'https://mainnet.gateway.tenderly.co|https://eth.drpc.org' \
  0x18703df \
  0x9C070027cdC9dc8F82416B2e5314E11DFb4FE3CD \
  ethereum >"$TMP/vault-ethereum.json"
collect_vault \
  ethereum-sepolia \
  11155111 \
  'https://sepolia.gateway.tenderly.co|https://sepolia.drpc.org' \
  0xad62b6 \
  0xB5679dE944A79732A75CE556191DF11F489448d5 \
  sepolia >"$TMP/vault-sepolia.json"

jq -s '.' \
  "$TMP/gateway-base.json" \
  "$TMP/gateway-base-sepolia.json" \
  "$TMP/gateway-arbitrum.json" \
  "$TMP/gateway-arbitrum-sepolia.json" \
  "$TMP/gateway-optimism.json" \
  "$TMP/gateway-optimism-sepolia.json" \
  "$TMP/gateway-polygon.json" >"$TMP/gateways.json"
jq -n \
  --arg captured_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg implementation_slot "$IMPLEMENTATION_SLOT" \
  --arg admin_slot "$ADMIN_SLOT" \
  --arg beacon_slot "$BEACON_SLOT" \
  --slurpfile gateways "$TMP/gateways.json" \
  --slurpfile rebate "$TMP/rebate.json" \
  --slurpfile vault_ethereum "$TMP/vault-ethereum.json" \
  --slurpfile vault_sepolia "$TMP/vault-sepolia.json" \
  '{
    schema_version:1,
    captured_at_utc:$captured_at_utc,
    standard_slots:{
      eip1967_implementation:$implementation_slot,
      eip1967_admin:$admin_slot,
      eip1967_beacon:$beacon_slot
    },
    l2_wormhole_gateways:$gateways[0],
    rebate_staking:$rebate[0],
    tbtc_vaults:[$vault_ethereum[0],$vault_sepolia[0]]
  }' >"$ROOT/rpc/fixed-block-receipt.json"

fetch_verified \
  8453 \
  0x40fa0a360818b04b9975680746dc0b7092105a0c \
  'L2WormholeGateway.sol$|BaseWormholeGatewayUpgraded.sol$' \
  'sendTbtc,receiveTbtc,sendTbtcWithPayloadToNativeChain,tbtc,bridge,bridgeToken' \
  gateway-base.json
fetch_verified \
  84532 \
  0x9a82be743f0120fa24893b1631b6b2817fd94b1d \
  'L2WormholeGateway.sol$' \
  'sendTbtc,receiveTbtc,tbtc,bridge,bridgeToken' \
  gateway-base-sepolia.json
fetch_verified \
  42161 \
  0x7ff02bb686658f2d55f28fdf45286f9499beb9a5 \
  'L2WormholeGateway.sol$|ArbitrumWormholeGatewayUpgraded.sol$' \
  'sendTbtc,receiveTbtc,sendTbtcWithPayloadToNativeChain,tbtc,bridge,bridgeToken' \
  gateway-arbitrum.json
fetch_verified \
  10 \
  0xc08dcc93130ab30987dd7fe64e011402bbe5fda6 \
  'L2WormholeGateway.sol$' \
  'sendTbtc,receiveTbtc,tbtc,bridge,bridgeToken' \
  gateway-optimism.json
fetch_verified \
  11155420 \
  0xc3d46e0266d95215589de639cc4e93b79f88fc6c \
  'L2WormholeGateway.sol$' \
  'sendTbtc,receiveTbtc,tbtc,bridge,bridgeToken' \
  gateway-optimism-sepolia.json
fetch_verified \
  137 \
  0x04671c72aab5ac02a03c1098314b1bb6b560c197 \
  'L2WormholeGateway.sol$' \
  'sendTbtc,receiveTbtc,tbtc,bridge,bridgeToken' \
  gateway-polygon.json
fetch_verified \
  1 \
  0x25aaf04229f77a9ae80430b3c89e3455ab2ec22f \
  'RebateStaking.sol$' \
  'stake,startUnstaking,finalizeUnstaking,setDelegatee,setRebateTreasuryFeeMode,token,bridge' \
  rebate-staking.json
fetch_verified \
  1 \
  0x9c070027cdc9dc8f82416b2e5314e11dfb4fe3cd \
  'TBTCVault.sol$|TBTCOptimisticMinting.sol$' \
  'requestOptimisticMint,finalizeOptimisticMint' \
  vault-ethereum.json
fetch_verified \
  11155111 \
  0xb5679de944a79732a75ce556191df11f489448d5 \
  'TBTCVault.sol$|TBTCOptimisticMinting.sol$' \
  'requestOptimisticMint,finalizeOptimisticMint' \
  vault-sepolia.json

curl -fsS --retry 5 --retry-all-errors --retry-delay 1 \
  "https://raw.githubusercontent.com/wormhole-foundation/wormhole-sdk-ts/$WORMHOLE_COMMIT/core/base/src/constants/chains.ts" \
  >"$ROOT/source/wormhole-chains.ts"

gateway_artifact() {
  local path="$1"
  curl -fsS --retry 5 --retry-all-errors --retry-delay 1 \
    "https://raw.githubusercontent.com/threshold-network/tbtc-v2/$THRESHOLD_COMMIT/$path" |
    jq --arg path "$path" '{
      path:$path,
      address,
      implementation,
      transactionHash,
      deploymentBlock:.receipt.blockNumber,
      routeAbi:[
        .abi[] |
        select(.type == "function" and (
          .name == "sendTbtc" or
          .name == "receiveTbtc" or
          .name == "sendTbtcWithPayloadToNativeChain"
        ))
      ]
    }'
}

gateway_artifact \
  cross-chain/base/deployments/base/BaseWormholeGateway.json \
  >"$TMP/official-gateway-base.json"
gateway_artifact \
  cross-chain/base/deployments/baseSepolia/BaseWormholeGateway.json \
  >"$TMP/official-gateway-base-sepolia.json"
gateway_artifact \
  cross-chain/arbitrum/deployments/arbitrumOne/ArbitrumWormholeGateway.json \
  >"$TMP/official-gateway-arbitrum.json"
gateway_artifact \
  cross-chain/arbitrum/deployments/arbitrumSepolia/ArbitrumWormholeGateway.json \
  >"$TMP/official-gateway-arbitrum-sepolia.json"
gateway_artifact \
  cross-chain/optimism/deployments/optimism/OptimismWormholeGateway.json \
  >"$TMP/official-gateway-optimism.json"
gateway_artifact \
  cross-chain/optimism/deployments/optimismSepolia/OptimismWormholeGateway.json \
  >"$TMP/official-gateway-optimism-sepolia.json"
gateway_artifact \
  cross-chain/polygon/deployments/polygon/PolygonWormholeGateway.json \
  >"$TMP/official-gateway-polygon.json"

curl -fsS --retry 5 --retry-all-errors --retry-delay 1 \
  "https://raw.githubusercontent.com/threshold-network/tbtc-v2/$THRESHOLD_COMMIT/solidity/deployments/mainnet/RebateStaking.json" \
  >"$TMP/rebate-proxy-artifact.json"
curl -fsS --retry 5 --retry-all-errors --retry-delay 1 \
  "https://raw.githubusercontent.com/threshold-network/tbtc-v2/$THRESHOLD_COMMIT/solidity/deployments/mainnet/RebateStakingTIP109HotfixImplementation.json" \
  >"$TMP/rebate-implementation-artifact.json"
curl -fsS --retry 5 --retry-all-errors --retry-delay 1 \
  "https://raw.githubusercontent.com/threshold-network/tbtc-v2/$THRESHOLD_COMMIT/solidity/deployments/mainnet/TBTCVault.json" \
  >"$TMP/vault-mainnet-artifact.json"

jq -n \
  --arg repository "$THRESHOLD_REPOSITORY" \
  --arg commit "$THRESHOLD_COMMIT" \
  --arg tree "$THRESHOLD_TREE" \
  --slurpfile base "$TMP/official-gateway-base.json" \
  --slurpfile base_sepolia "$TMP/official-gateway-base-sepolia.json" \
  --slurpfile arbitrum "$TMP/official-gateway-arbitrum.json" \
  --slurpfile arbitrum_sepolia "$TMP/official-gateway-arbitrum-sepolia.json" \
  --slurpfile optimism "$TMP/official-gateway-optimism.json" \
  --slurpfile optimism_sepolia "$TMP/official-gateway-optimism-sepolia.json" \
  --slurpfile polygon "$TMP/official-gateway-polygon.json" \
  --slurpfile rebate_proxy "$TMP/rebate-proxy-artifact.json" \
  --slurpfile rebate_implementation "$TMP/rebate-implementation-artifact.json" \
  --slurpfile vault_mainnet "$TMP/vault-mainnet-artifact.json" \
  '{
    repository:$repository,
    commit:$commit,
    tree:$tree,
    wormholeGateways:[
      $base[0],
      $base_sepolia[0],
      $arbitrum[0],
      $arbitrum_sepolia[0],
      $optimism[0],
      $optimism_sepolia[0],
      $polygon[0]
    ],
    rebateStaking:{
      proxy:{
        address:$rebate_proxy[0].address,
        implementation:$rebate_proxy[0].implementation,
        transactionHash:$rebate_proxy[0].transactionHash,
        deploymentBlock:$rebate_proxy[0].receipt.blockNumber,
        routeAbi:[
          $rebate_proxy[0].abi[] |
          select(.type == "function" and (
            .name == "stake" or
            .name == "startUnstaking" or
            .name == "finalizeUnstaking" or
            .name == "setDelegatee" or
            .name == "setRebateTreasuryFeeMode" or
            .name == "token" or
            .name == "bridge"
          ))
        ]
      },
      implementation:{
        address:$rebate_implementation[0].address,
        transactionHash:$rebate_implementation[0].transactionHash,
        deploymentBlock:$rebate_implementation[0].receipt.blockNumber,
        deployedBytecode:$rebate_implementation[0].deployedBytecode
      }
    },
    tbtcVaultMainnet:{
      address:$vault_mainnet[0].address,
      transactionHash:$vault_mainnet[0].transactionHash,
      deploymentBlock:$vault_mainnet[0].receipt.blockNumber,
      routeAbi:[
        $vault_mainnet[0].abi[] |
        select(.type == "function" and (
          .name == "requestOptimisticMint" or
          .name == "finalizeOptimisticMint"
        ))
      ]
    }
  }' >"$ROOT/official/threshold-deployments.json"

jq -r '.rebateStaking.implementation.deployedBytecode' \
  "$ROOT/official/threshold-deployments.json" \
  >"$ROOT/runtime/rebate-official-implementation.hex"

printf '%s\n' "$THRESHOLD_COMMIT" >"$ROOT/source/threshold-commit.txt"
printf '%s\n' "$WORMHOLE_COMMIT" >"$ROOT/source/wormhole-sdk-ts-commit.txt"

: >"$TMP/artifacts.jsonl"
while IFS= read -r -d '' artifact; do
  relative="${artifact#"$ROOT/"}"
  jq -nc \
    --arg path "$relative" \
    --argjson bytes "$(stat -c %s "$artifact")" \
    --arg sha256 "$(sha256sum "$artifact" | cut -d' ' -f1)" \
    '{path:$path,bytes:$bytes,sha256:$sha256}' \
    >>"$TMP/artifacts.jsonl"
done < <(
  find "$ROOT" \
    -type f \
    ! -name manifest.json \
    -print0 |
    sort -z
)

jq -s \
  --arg threshold_repository "$THRESHOLD_REPOSITORY" \
  --arg threshold_commit "$THRESHOLD_COMMIT" \
  --arg threshold_tree "$THRESHOLD_TREE" \
  --arg wormhole_repository "$WORMHOLE_REPOSITORY" \
  --arg wormhole_commit "$WORMHOLE_COMMIT" \
  '{
    schema_version:1,
    scope:"Historical deployment/runtime and semantic evidence for the seven admitted L2WormholeGateway sendTbtc leaves, five RebateStaking routes, and two TBTCVault optimistic-mint leaves.",
    upstream:{
      threshold:{
        repository:$threshold_repository,
        commit:$threshold_commit,
        tree:$threshold_tree
      },
      wormhole_sdk_ts:{
        repository:$wormhole_repository,
        commit:$wormhole_commit,
        chain_id_source:"source/wormhole-chains.ts"
      },
      sourcify_api:"https://sourcify.dev/server/v2"
    },
    descriptor_families:[
      {
        source:"threshold/calldata-L2WormholeGateway.json",
        admitted_leaf_count:7,
        admitted_formats:["sendTbtc(uint256 amount, uint16 recipientChain, bytes32 recipient, uint256 arbiterFee, uint32 nonce)"],
        refusal_only_formats:[
          "receiveTbtc(bytes encodedVm)",
          "sendTbtcWithPayloadToNativeChain(uint256 amount, uint16 recipientNativeChain, bytes32 recipient, uint32 nonce, bytes payload)"
        ]
      },
      {
        source:"threshold/calldata-RebateStaking.json",
        admitted_leaf_count:1,
        admitted_formats:[
          "stake(uint96 amount)",
          "startUnstaking(uint96 amount)",
          "finalizeUnstaking(address receiver)",
          "setDelegatee(address _delegatee)",
          "setRebateTreasuryFeeMode(uint8 _rebateTreasuryFeeMode)"
        ]
      },
      {
        source:"threshold/calldata-TBTCVault.json",
        admitted_leaf_count:2,
        admitted_formats:[
          "requestOptimisticMint(bytes32 fundingTxHash, uint32 fundingOutputIndex)",
          "finalizeOptimisticMint(bytes32 fundingTxHash, uint32 fundingOutputIndex)"
        ]
      }
    ],
    claims:[
      "Each admitted deployment is pinned to a fixed block, runtime bytes, and independently corroborated block hash/state root.",
      "Gateway and Rebate proxy implementations are pinned through the EIP-1967 implementation slot; Vault standard proxy slots are zero and exact Sourcify runtime/source matches identify direct TBTCVault deployments.",
      "Gateway tBTC() bindings and token metadata prove tBTC/18 at every admitted fixed block; Rebate token() proves Threshold Network Token/T/18.",
      "Verified implementation sources and route ABIs bind amount normalization, arbiter-fee conditionality, Wormhole field meaning, Rebate state-derived unstake amount and enum meaning, and Vault minter/state-derived mint semantics."
    ],
    boundary:"Historical fixed-block source/runtime and signed-input meaning only. No live state, transaction-success, future proxy-upgrade/deployment, fallback, blind-signing, production, shipment, or irreversible-action authority.",
    artifacts:.
  }' \
  "$TMP/artifacts.jsonl" >"$ROOT/manifest.json"
