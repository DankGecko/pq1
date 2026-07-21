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

gateway=0xd01607c3C5eCABa394D8be377a08590149325722
block_hash=0xc764a3327787002b64c36ae2776c0f25a9c9e7fa8e94dc1748c04550adba4bfd
tag="$(jq -nc --arg hash "$block_hash" '{blockHash:$hash,requireCanonical:true}')"

jq -n --arg hash "$block_hash" --arg gateway "$gateway" --argjson tag "$tag" '
  [
    {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
    {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]},
    {jsonrpc:"2.0",id:3,method:"eth_getCode",params:[$gateway,$tag]}
  ]' >"$rpc/request-identity.json"
jq -n --arg gateway "$gateway" --argjson tag "$tag" '
  [
    {jsonrpc:"2.0",id:4,method:"eth_call",params:[{to:$gateway,data:"0xad5c4648"},$tag]},
    {jsonrpc:"2.0",id:5,method:"eth_call",params:[{to:$gateway,data:"0x7535d246"},$tag]},
    {jsonrpc:"2.0",id:6,method:"eth_call",params:[{to:$gateway,data:"0x8da5cb5b"},$tag]}
  ]' >"$rpc/request-immutables.json"

for provider in drpc mevblocker; do
  if [[ "$provider" == drpc ]]; then
    url=https://eth.drpc.org
  else
    url=https://rpc.mevblocker.io
  fi
  for batch in identity immutables; do
    fetch -H 'content-type: application/json' \
      --data-binary "@$rpc/request-$batch.json" \
      "$url" >"$rpc/response-$provider-$batch.json"
  done
done

jq -r '.[] | select(.id == 3) | .result' \
  "$rpc/response-drpc-identity.json" >"$runtime/WrappedTokenGatewayV3.ethereum-mainnet.hex"

address_book_commit=7e444a1e73b538fd0b9e093e5156401d6fccca7d
fetch "https://raw.githubusercontent.com/aave-dao/aave-address-book/$address_book_commit/src/AaveV3Ethereum.sol" \
  >"$source_dir/AaveV3Ethereum.sol"
origin_commit=ea556899f770b5a15567eef766f507ad69c42d8e
fetch "https://raw.githubusercontent.com/aave-dao/aave-v3-origin/$origin_commit/src/contracts/helpers/WrappedTokenGatewayV3.sol" \
  >"$source_dir/WrappedTokenGatewayV3.sol"

sourcify_fields='abi,metadata,compilation,runtimeBytecode.onchainBytecode,runtimeBytecode.recompiledBytecode,runtimeBytecode.immutableReferences,runtimeBytecode.transformations,runtimeBytecode.transformationValues'
fetch "https://sourcify.dev/server/v2/contract/1/$gateway?fields=$sourcify_fields" \
  >"$verification/Sourcify.json"
fetch "https://eth.blockscout.com/api/v2/smart-contracts/$gateway" \
  >"$verification/Blockscout.json"

jq '[.abi[] | select(.type == "function" and (.name == "borrowETH" or .name == "depositETH" or .name == "repayETH" or .name == "withdrawETH" or .name == "withdrawETHWithPermit"))] | sort_by(.name)' \
  "$verification/Sourcify.json" >"$abi/WrappedTokenGatewayV3.routes.abi.json"
