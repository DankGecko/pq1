#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
runtime="$root/runtime"
source_dir="$root/source"
verification="$root/verification"
abi="$root/abi"

mkdir -p "$rpc" "$runtime" "$source_dir" "$verification" "$abi"

fetch() {
  curl --fail --silent --show-error --max-time 120 \
    --retry 5 --retry-delay 2 --retry-all-errors "$@"
}

pool=0x794a61358D6845594F94dc1DB02A252b5b4814aD
provider=0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb
borrow_logic=0x52Da0ce88202D1542543598D1e1e27F0d344726A
supply_logic=0x584C7d8c4cb05304FE5Ac7fbc97f20A10Fb07564
implementation_slot=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

collect_chain() {
  local slug="$1"
  local chain_id="$2"
  local block_hash="$3"
  local implementation="$4"
  local provider_a_name="$5"
  local provider_a_url="$6"
  local provider_b_name="$7"
  local provider_b_url="$8"
  local chain_rpc="$rpc/$slug"
  local tag

  mkdir -p "$chain_rpc"
  tag="$(jq -nc --arg hash "$block_hash" '{blockHash:$hash,requireCanonical:true}')"

  jq -n --arg hash "$block_hash" --arg pool "$pool" --arg slot "$implementation_slot" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
      {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]},
      {jsonrpc:"2.0",id:3,method:"eth_getStorageAt",params:[$pool,$slot,$tag]}
    ]' >"$chain_rpc/request-identity.json"
  jq -n --arg pool "$pool" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:4,method:"eth_getCode",params:[$pool,$tag]},
      {jsonrpc:"2.0",id:5,method:"eth_call",params:[{to:$pool,data:"0x0542975c"},$tag]},
      {jsonrpc:"2.0",id:6,method:"eth_call",params:[{to:$pool,data:"0x0148170e"},$tag]}
    ]' >"$chain_rpc/request-proxy.json"
  jq -n --arg pool "$pool" --arg provider "$provider" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:7,method:"eth_call",params:[{to:$pool,data:"0x2be29fa7"},$tag]},
      {jsonrpc:"2.0",id:8,method:"eth_call",params:[{to:$pool,data:"0x870e7744"},$tag]},
      {jsonrpc:"2.0",id:9,method:"eth_call",params:[{to:$provider,data:"0x026b1d5f"},$tag]}
    ]' >"$chain_rpc/request-links.json"
  jq -n --arg implementation "$implementation" --arg borrow "$borrow_logic" --arg supply "$supply_logic" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:10,method:"eth_getCode",params:[$implementation,$tag]},
      {jsonrpc:"2.0",id:11,method:"eth_getCode",params:[$borrow,$tag]},
      {jsonrpc:"2.0",id:12,method:"eth_getCode",params:[$supply,$tag]}
    ]' >"$chain_rpc/request-code.json"
  jq -n --arg pool "$pool" --arg provider "$provider" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:13,method:"eth_call",params:[{from:$provider,to:$pool,data:"0x5c60da1b"},$tag]},
      {jsonrpc:"2.0",id:14,method:"eth_call",params:[{from:$provider,to:$pool,data:"0xf851a440"},$tag]},
      {jsonrpc:"2.0",id:15,method:"eth_getCode",params:[$provider,$tag]}
    ]' >"$chain_rpc/request-admin.json"

  local batch provider_name provider_url
  for batch in identity proxy links code admin; do
    for provider_name in "$provider_a_name" "$provider_b_name"; do
      if [[ "$provider_name" == "$provider_a_name" ]]; then
        provider_url="$provider_a_url"
      else
        provider_url="$provider_b_url"
      fi
      fetch -H 'content-type: application/json' \
        --data-binary "@$chain_rpc/request-$batch.json" \
        "$provider_url" >"$chain_rpc/response-$provider_name-$batch.json"
    done
  done

  jq -r '.[] | select(.id == 4) | .result' \
    "$chain_rpc/response-$provider_a_name-proxy.json" >"$runtime/PoolProxy.$slug.hex"
  jq -r '.[] | select(.id == 10) | .result' \
    "$chain_rpc/response-$provider_a_name-code.json" >"$runtime/PoolImplementation.$slug.hex"
  jq -r '.[] | select(.id == 11) | .result' \
    "$chain_rpc/response-$provider_a_name-code.json" >"$runtime/BorrowLogic.$slug.hex"
  jq -r '.[] | select(.id == 12) | .result' \
    "$chain_rpc/response-$provider_a_name-code.json" >"$runtime/SupplyLogic.$slug.hex"

  printf '%s\n' "$chain_id" >/dev/null
}

collect_chain optimism 10 \
  0xc3f99bbbc76f43852f6ea8ee2e3606f617279ccb565973ff6a3ab4a8348457cf \
  0x66185E53343336d4FaeA5317d1Fcca103Dd4088D \
  publicnode https://optimism-rpc.publicnode.com \
  drpc https://optimism.drpc.org
collect_chain polygon 137 \
  0x2a97804fa59fe15b1ff8fe068997e5a21f15d68d89fb987c38fdd24a46f976d4 \
  0x6030dB989D47cD74FC17bB6F4FcD3A8B29FEe57e \
  tenderly https://polygon.gateway.tenderly.co \
  drpc https://polygon.drpc.org
collect_chain arbitrum 42161 \
  0x0de0b3675691154bc521ab9b3821763b5309f22d76810c43d26f1ccde2bf25c4 \
  0xF05Fd3cC911b4c5E36e53c00354F645E22922C9A \
  publicnode https://arbitrum-one-rpc.publicnode.com \
  tenderly https://arbitrum.gateway.tenderly.co
collect_chain avalanche 43114 \
  0x21bfb1f3a7ede20bfa372e278ec6208717f998dbab172b1f3f9644691a751b09 \
  0x6cddFF90124bA51afac5715314db7C9546b32204 \
  tenderly https://avalanche.gateway.tenderly.co \
  thirdweb https://43114.rpc.thirdweb.com

address_book_commit=7e444a1e73b538fd0b9e093e5156401d6fccca7d
for network in Optimism Polygon Arbitrum Avalanche; do
  fetch "https://raw.githubusercontent.com/aave-dao/aave-address-book/$address_book_commit/src/AaveV3$network.sol" \
    >"$source_dir/AaveV3$network.sol"
done

origin_commit=fd1fbd9150426ca8ace9cee45b4acf912ae84f5b
fetch "https://raw.githubusercontent.com/aave-dao/aave-v3-origin/$origin_commit/src/contracts/instances/PoolInstance.sol" \
  >"$source_dir/PoolInstance.sol"
fetch "https://raw.githubusercontent.com/aave-dao/aave-v3-origin/$origin_commit/src/contracts/instances/L2PoolInstance.sol" \
  >"$source_dir/L2PoolInstance.sol"
fetch "https://raw.githubusercontent.com/aave-dao/aave-v3-origin/$origin_commit/src/contracts/protocol/pool/Pool.sol" \
  >"$source_dir/Pool.sol"
fetch "https://raw.githubusercontent.com/aave-dao/aave-v3-origin/$origin_commit/src/contracts/protocol/pool/L2Pool.sol" \
  >"$source_dir/L2Pool.sol"
fetch "https://raw.githubusercontent.com/aave-dao/aave-v3-origin/$origin_commit/src/contracts/protocol/libraries/logic/BorrowLogic.sol" \
  >"$source_dir/BorrowLogic.sol"
fetch "https://raw.githubusercontent.com/aave-dao/aave-v3-origin/$origin_commit/src/contracts/protocol/libraries/logic/SupplyLogic.sol" \
  >"$source_dir/SupplyLogic.sol"

sourcify_fields='abi,metadata,compilation,runtimeBytecode.onchainBytecode,runtimeBytecode.recompiledBytecode,runtimeBytecode.linkReferences,runtimeBytecode.immutableReferences,runtimeBytecode.transformations,runtimeBytecode.transformationValues'
fetch "https://sourcify.dev/server/v2/contract/10/0x66185E53343336d4FaeA5317d1Fcca103Dd4088D?fields=$sourcify_fields" \
  >"$verification/Sourcify.optimism.json"
fetch "https://sourcify.dev/server/v2/contract/137/0x6030dB989D47cD74FC17bB6F4FcD3A8B29FEe57e?fields=$sourcify_fields" \
  >"$verification/Sourcify.polygon.json"
fetch "https://sourcify.dev/server/v2/contract/42161/0xF05Fd3cC911b4c5E36e53c00354F645E22922C9A?fields=$sourcify_fields" \
  >"$verification/Sourcify.arbitrum.json"
fetch 'https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan/api?module=contract&action=getsourcecode&address=0x6cddFF90124bA51afac5715314db7C9546b32204' \
  >"$verification/Routescan.avalanche.json"

jq '[.abi[] | select(.type == "function" and (.name == "approvePositionManager" or .name == "borrow" or .name == "deposit" or .name == "renouncePositionManagerRole" or .name == "repay" or .name == "repayWithATokens" or .name == "setUserUseReserveAsCollateral" or .name == "setUserUseReserveAsCollateralOnBehalfOf" or .name == "supply" or .name == "withdraw") and ((.inputs | map(.type) | join(",")) != "bytes32"))] | sort_by(.name)' \
  "$verification/Sourcify.polygon.json" >"$abi/Pool.routes.abi.json"
