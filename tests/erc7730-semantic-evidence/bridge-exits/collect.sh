#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
blockscout="$root/blockscout"
abi="$root/abi"

mkdir -p "$rpc" "$blockscout" "$abi"

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

collect_batch() {
  local provider="$1"
  local url="$2"
  local request="$3"
  local response="$4"
  local tmp attempt
  tmp="$(mktemp)"
  for attempt in 1 2 3 4 5; do
    if fetch -H 'content-type: application/json' \
        --data-binary "@$request" "$url" >"$tmp" &&
      jq -e 'type == "array" and length > 0 and
        all(.[]; (.error? // null) == null and .result != null)' "$tmp" >/dev/null
    then
      jq -S 'sort_by(.id)' "$tmp" >"$response"
      rm -f "$tmp"
      return 0
    fi
  done
  rm -f "$tmp"
  echo "RPC capture failed for $provider request $(basename "$request")" >&2
  return 1
}

igra_hash=0x0171afba2a066c674b4fff9e25bbbddc34ef159d430de93a5d95478913149d25
sepolia_hash=0xab08b06d380d5fc12e60c1a21407014dcc5251aa8b37690432ba836d00c2bd88
ethereum_hash=0x6ef230ed8c6d2bd0eaf04e8e59953d2dfa035151e666101de3d7195aefec9af7
eip1967=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

jq -n --arg block "$igra_hash" --arg slot "$eip1967" '[
  {jsonrpc:"2.0",id:"chain",method:"eth_chainId",params:[]},
  {jsonrpc:"2.0",id:"block",method:"eth_getBlockByHash",params:[$block,false]},
  {jsonrpc:"2.0",id:"implementation",method:"eth_getStorageAt",params:[
    "0x4bb88c213d3ed9dc4bae694f1bc1bf745903b2d0",$slot,
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"proxy-code",method:"eth_getCode",params:[
    "0x4bb88c213d3ed9dc4bae694f1bc1bf745903b2d0",
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"implementation-code",method:"eth_getCode",params:[
    "0x00d39E05A20b2C4f6D0D6CfC3C5718066B861334",
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-igra-state.json"

jq -n --arg block "$sepolia_hash" '[
  {jsonrpc:"2.0",id:"chain",method:"eth_chainId",params:[]},
  {jsonrpc:"2.0",id:"block",method:"eth_getBlockByHash",params:[$block,false]}
]' >"$rpc/request-sepolia-identity.json"
jq -n --arg block "$sepolia_hash" --arg slot "$eip1967" '[
  {jsonrpc:"2.0",id:"implementation",method:"eth_getStorageAt",params:[
    "0x731eFa688F3679688cf60A3993b8658138953ED6",$slot,
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"proxy-code",method:"eth_getCode",params:[
    "0x731eFa688F3679688cf60A3993b8658138953ED6",
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"implementation-code",method:"eth_getCode",params:[
    "0xfcC108e3E588cb85018aB736091d134f26151670",
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-sepolia-state.json"
jq -n --arg block "$sepolia_hash" '[
  {jsonrpc:"2.0",id:"name",method:"eth_call",params:[
    {to:"0x731eFa688F3679688cf60A3993b8658138953ED6",data:"0x06fdde03"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"symbol",method:"eth_call",params:[
    {to:"0x731eFa688F3679688cf60A3993b8658138953ED6",data:"0x95d89b41"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"decimals",method:"eth_call",params:[
    {to:"0x731eFa688F3679688cf60A3993b8658138953ED6",data:"0x313ce567"},
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-sepolia-metadata.json"
jq -n --arg block "$sepolia_hash" '[
  {jsonrpc:"2.0",id:"asset-router",method:"eth_call",params:[
    {to:"0x731eFa688F3679688cf60A3993b8658138953ED6",data:"0xfe9c6aa6"},
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-sepolia-router.json"

jq -n --arg block "$ethereum_hash" '[
  {jsonrpc:"2.0",id:"chain",method:"eth_chainId",params:[]},
  {jsonrpc:"2.0",id:"block",method:"eth_getBlockByHash",params:[$block,false]}
]' >"$rpc/request-ethereum-identity.json"
jq -n --arg block "$ethereum_hash" '[
  {jsonrpc:"2.0",id:"implementation",method:"eth_call",params:[
    {to:"0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4",data:"0x5c60da1b"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"proxy-code",method:"eth_getCode",params:[
    "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4",
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"implementation-code",method:"eth_getCode",params:[
    "0x6ad74D4B79A06A492C288eF66Ef868Dd981fdC85",
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-ethereum-starkgate.json"
jq -n --arg block "$ethereum_hash" --arg slot "$eip1967" '[
  {jsonrpc:"2.0",id:"implementation",method:"eth_getStorageAt",params:[
    "0x66a28B080918184851774a89aB94850a41f6a1e5",$slot,
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"proxy-code",method:"eth_getCode",params:[
    "0x66a28B080918184851774a89aB94850a41f6a1e5",
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"implementation-code",method:"eth_getCode",params:[
    "0xd048a8D52da402611A0C5eb6f7388ffC41cd1417",
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-ethereum-ntt-state.json"
jq -n --arg block "$ethereum_hash" '[
  {jsonrpc:"2.0",id:"token",method:"eth_call",params:[
    {to:"0x66a28B080918184851774a89aB94850a41f6a1e5",data:"0xfc0c546a"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"mode",method:"eth_call",params:[
    {to:"0x66a28B080918184851774a89aB94850a41f6a1e5",data:"0x295a5212"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"chain-id",method:"eth_call",params:[
    {to:"0x66a28B080918184851774a89aB94850a41f6a1e5",data:"0x9a8a0592"},
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-ethereum-ntt-config.json"
jq -n --arg block "$ethereum_hash" '[
  {jsonrpc:"2.0",id:"manager-token-decimals",method:"eth_call",params:[
    {to:"0x66a28B080918184851774a89aB94850a41f6a1e5",data:"0x3b97e856"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"token-code",method:"eth_getCode",params:[
    "0x64d0f55Cd8C7133a9D7102b13987235F486F2224",
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-ethereum-borg-state.json"
jq -n --arg block "$ethereum_hash" '[
  {jsonrpc:"2.0",id:"name",method:"eth_call",params:[
    {to:"0x64d0f55Cd8C7133a9D7102b13987235F486F2224",data:"0x06fdde03"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"symbol",method:"eth_call",params:[
    {to:"0x64d0f55Cd8C7133a9D7102b13987235F486F2224",data:"0x95d89b41"},
    {blockHash:$block,requireCanonical:true}]},
  {jsonrpc:"2.0",id:"decimals",method:"eth_call",params:[
    {to:"0x64d0f55Cd8C7133a9D7102b13987235F486F2224",data:"0x313ce567"},
    {blockHash:$block,requireCanonical:true}]}
]' >"$rpc/request-ethereum-borg-metadata.json"

collect_batch igra-official https://rpc.igralabs.com:8545 \
  "$rpc/request-igra-state.json" "$rpc/response-igra-official-state.json"

for provider in drpc tenderly; do
  if [[ "$provider" == drpc ]]; then
    url=https://sepolia.drpc.org
  else
    url=https://sepolia.gateway.tenderly.co
  fi
  for batch in identity state metadata router; do
    collect_batch "$provider" "$url" \
      "$rpc/request-sepolia-$batch.json" "$rpc/response-sepolia-$provider-$batch.json"
  done
done

for provider in drpc mevblocker; do
  if [[ "$provider" == drpc ]]; then
    url=https://eth.drpc.org
  else
    url=https://rpc.mevblocker.io
  fi
  for batch in identity starkgate ntt-state ntt-config borg-state borg-metadata; do
    collect_batch "$provider" "$url" \
      "$rpc/request-ethereum-$batch.json" "$rpc/response-ethereum-$provider-$batch.json"
  done
done

fetch_json https://explorer.igralabs.com/api/v2/smart-contracts/0x4bb88c213d3ed9dc4bae694f1bc1bf745903b2d0 \
  "$blockscout/IgraKasExitBridge.proxy.json"
fetch_json https://explorer.igralabs.com/api/v2/smart-contracts/0x00d39E05A20b2C4f6D0D6CfC3C5718066B861334 \
  "$blockscout/IgraKasExitBridge.implementation.json"
fetch_json https://eth-sepolia.blockscout.com/api/v2/smart-contracts/0x731eFa688F3679688cf60A3993b8658138953ED6 \
  "$blockscout/LombardLBTC.proxy.sepolia.json"
fetch_json https://eth-sepolia.blockscout.com/api/v2/smart-contracts/0xfcC108e3E588cb85018aB736091d134f26151670 \
  "$blockscout/LombardLBTC.implementation.sepolia.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4 \
  "$blockscout/StarkGate.proxy.ethereum.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0x6ad74D4B79A06A492C288eF66Ef868Dd981fdC85 \
  "$blockscout/StarkGate.implementation.ethereum.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0x66a28B080918184851774a89aB94850a41f6a1e5 \
  "$blockscout/SwissborgNtt.proxy.ethereum.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0xd048a8D52da402611A0C5eb6f7388ffC41cd1417 \
  "$blockscout/SwissborgNtt.implementation.ethereum.json"
fetch_json https://eth.blockscout.com/api/v2/smart-contracts/0x64d0f55Cd8C7133a9D7102b13987235F486F2224 \
  "$blockscout/SwissborgBorgToken.ethereum.json"

jq -cS '[.abi[] | select(.type == "function") |
  select(.name == "requestExit" and [.inputs[].type] == ["string","uint64"])]' \
  "$blockscout/IgraKasExitBridge.implementation.json" >"$abi/IgraKasExitBridge.routes.json"
jq -cS '[.abi[] | select(.type == "function") | select(
  (.name == "approve" and [.inputs[].type] == ["address","uint256"]) or
  (.name == "burn" and [.inputs[].type] == ["uint256"]) or
  (.name == "mint" and [.inputs[].type] == ["bytes","bytes"]) or
  (.name == "permit" and [.inputs[].type] == ["address","address","uint256","uint256","uint8","bytes32","bytes32"]) or
  (.name == "redeem" and [.inputs[].type] == ["uint256"]) or
  (.name == "redeemForBtc" and [.inputs[].type] == ["bytes","uint256"]) or
  (.name == "transfer" and [.inputs[].type] == ["address","uint256"]) or
  (.name == "transferFrom" and [.inputs[].type] == ["address","address","uint256"])
)] | sort_by(.name, [.inputs[].type])' \
  "$blockscout/LombardLBTC.implementation.sepolia.json" >"$abi/LombardLBTC.routes.sepolia.json"
jq -cS '[.abi[] | select(.type == "function") |
  select(.name == "deposit" and [.inputs[].type] == ["address","uint256","uint256"])]' \
  "$blockscout/StarkGate.implementation.ethereum.json" >"$abi/StarkGate.routes.ethereum.json"
jq -cS '[.abi[] | select(.type == "function") | select(
  .name == "transfer" and
  (([.inputs[].type] == ["uint256","uint16","bytes32"]) or
   ([.inputs[].type] == ["uint256","uint16","bytes32","bytes32","bool","bytes"]))
)] | sort_by([.inputs[].type])' \
  "$blockscout/SwissborgNtt.implementation.ethereum.json" >"$abi/SwissborgNtt.routes.ethereum.json"

receipts="$(mktemp)"
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  sha256="$(sha256sum "$path" | awk '{print $1}')"
  jq -cn --arg path "$relative" --arg sha256 "$sha256" \
    '{path: $path, sha256: $sha256}' >>"$receipts"
done < <(find "$root" -type f ! -name manifest.json -print0 | sort -z)
manifest_tmp="$(mktemp)"
jq --slurpfile artifacts "$receipts" '.artifacts = $artifacts' \
  "$root/manifest.json" >"$manifest_tmp"
mv "$manifest_tmp" "$root/manifest.json"
rm -f "$receipts"
