#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
explorer="$root/explorer"
compiler="$root/compiler"
rpc="$root/rpc/raw"

mkdir -p "$explorer" "$compiler" "$rpc"
rm -f \
  "$rpc/request-ethereum-identity.json" \
  "$rpc/response-ethereum-mevblocker-identity.json" \
  "$rpc/response-ethereum-tenderly-identity.json" \
  "$rpc"/response-ethereum-flashbots-identity-*.json \
  "$rpc/response-ethereum-flashbots-creation-transactions.json" \
  "$rpc/response-ethereum-tenderly-creation-transactions.json"

html_tmp="$(mktemp)"
literal_tmp="$(mktemp)"
compile_input_tmp="$(mktemp)"
compile_output_tmp="$(mktemp)"
artifact_tmp="$(mktemp)"
manifest_tmp="$(mktemp)"
trap 'rm -f "$html_tmp" "$literal_tmp" "$compile_input_tmp" "$compile_output_tmp" "$artifact_tmp" "$manifest_tmp"' EXIT

fetch() {
  curl \
    --fail --silent --show-error --location \
    --connect-timeout 15 --max-time 120 \
    --retry 5 --retry-all-errors --retry-delay 1 \
    "$@"
}

extract_standard_input() {
  local url="$1"
  local destination="$2"

  fetch "$url" >"$html_tmp"
  perl -0777 -ne \
    'if (/var editor_contractJsonData = '\''(.*?)'\''\s*var editor_activeFile/s) { print $1 }' \
    "$html_tmp" >"$literal_tmp"
  test -s "$literal_tmp"

  # Etherscan escapes Markdown backticks for a JavaScript single-quoted string.
  # Remove that one JS-only escape before decoding the remaining JSON string.
  perl -0777 -pe 's/\\`/`/g' "$literal_tmp" |
    awk '{printf "\"%s\"", $0}' |
    jq -r '.' |
    jq -S '.' >"$destination"
}

compile_contract() {
  local standard_input="$1"
  local source_path="$2"
  local contract_name="$3"
  local destination="$4"

  jq '
    .settings = (.sources["settings.json"].content | fromjson)
    | del(.sources["settings.json"])
    | .settings.outputSelection["*"]["*"] += ["storageLayout"]
    | .settings.outputSelection["*"]["*"] |= unique
  ' "$standard_input" >"$compile_input_tmp"

  npx --yes solc@0.8.30 --standard-json \
    <"$compile_input_tmp" >"$compile_output_tmp"
  sed -i '/^>>> /d' "$compile_output_tmp"
  jq -e '[.errors[]? | select(.severity == "error")] | length == 0' \
    "$compile_output_tmp" >/dev/null

  jq -S \
    --arg source "$source_path" \
    --arg contract "$contract_name" '
      .contracts[$source][$contract]
      | {
          abi,
          storageLayout,
          evm: {
            deployedBytecode: {
              object: .evm.deployedBytecode.object,
              immutableReferences: .evm.deployedBytecode.immutableReferences,
              linkReferences: .evm.deployedBytecode.linkReferences
            }
          }
        }
    ' "$compile_output_tmp" >"$destination"
}

rpc_request() {
  local url="$1"
  local request="$2"
  local destination="$3"
  local attempt status

  for attempt in 1 2 3 4 5; do
    status="$(
      curl \
        --silent --show-error --location \
        --connect-timeout 15 --max-time 120 \
        --retry 2 --retry-all-errors --retry-delay 1 \
        -H 'content-type: application/json' \
        --data-binary "@$request" \
        --output "$html_tmp" --write-out '%{http_code}' \
        "$url"
    )"
    if [[ "$status" == 200 ]] &&
      jq -e '
        if type == "array" then
          length > 0
          and all(.[]; (.error? // null) == null and .result != null)
        else
          (.error? // null) == null and .result != null
        end
      ' "$html_tmp" >/dev/null
    then
      jq -S 'if type == "array" then sort_by(.id) else . end' \
        "$html_tmp" >"$destination"
      return 0
    fi
    echo "retrying RPC capture ($attempt/5): $url" >&2
  done

  echo "RPC capture failed after five attempts: $url" >&2
  return 1
}

extract_standard_input \
  "https://www.sonicscan.org/address/0xc55253ea84050700e1efa8878d4a5053b6bf7c5e#code" \
  "$explorer/pft.standard-input.json"
extract_standard_input \
  "https://www.sonicscan.org/address/0x90ae2cac15f8d58a258f7b4a243657754469922a#code" \
  "$explorer/putmanager-current.standard-input.json"
extract_standard_input \
  "https://etherscan.io/address/0x1e4e741e5f0f4f258def137e1968716eddae4bf5#code" \
  "$explorer/putmanager-ethereum.standard-input.json"
extract_standard_input \
  "https://www.sonicscan.org/address/0xbdd1327024b66212bf1f6a6a7f8b21f81b1faca4#code" \
  "$explorer/marketplace.standard-input.json"

compile_contract \
  "$explorer/pft.standard-input.json" \
  "contracts/pFT.sol" "pFT" \
  "$compiler/pft.json"
compile_contract \
  "$explorer/putmanager-current.standard-input.json" \
  "contracts/PutManager.sol" "PutManager" \
  "$compiler/putmanager-current.json"
compile_contract \
  "$explorer/putmanager-ethereum.standard-input.json" \
  "contracts/PutManager.sol" "PutManager" \
  "$compiler/putmanager-ethereum.json"
compile_contract \
  "$explorer/marketplace.standard-input.json" \
  "contracts/pFTMarketplace.sol" "pFTMarketplace" \
  "$compiler/marketplace.json"

jq -nS '{
  schema_version: 1,
  compiler: "0.8.30+commit.73712a01",
  captures: [
    {
      id: "pft",
      url: "https://www.sonicscan.org/address/0xc55253ea84050700e1efa8878d4a5053b6bf7c5e#code",
      standard_input: "explorer/pft.standard-input.json",
      primary_source: "contracts/pFT.sol",
      contract: "pFT",
      compiler_artifact: "compiler/pft.json"
    },
    {
      id: "putmanager-current",
      url: "https://www.sonicscan.org/address/0x90ae2cac15f8d58a258f7b4a243657754469922a#code",
      standard_input: "explorer/putmanager-current.standard-input.json",
      primary_source: "contracts/PutManager.sol",
      contract: "PutManager",
      compiler_artifact: "compiler/putmanager-current.json"
    },
    {
      id: "putmanager-ethereum",
      url: "https://etherscan.io/address/0x1e4e741e5f0f4f258def137e1968716eddae4bf5#code",
      standard_input: "explorer/putmanager-ethereum.standard-input.json",
      primary_source: "contracts/PutManager.sol",
      contract: "PutManager",
      compiler_artifact: "compiler/putmanager-ethereum.json"
    },
    {
      id: "marketplace",
      url: "https://www.sonicscan.org/address/0xbdd1327024b66212bf1f6a6a7f8b21f81b1faca4#code",
      standard_input: "explorer/marketplace.standard-input.json",
      primary_source: "contracts/pFTMarketplace.sol",
      contract: "pFTMarketplace",
      compiler_artifact: "compiler/marketplace.json"
    }
  ]
}' >"$explorer/records.json"

ethereum_hash=0x6ef230ed8c6d2bd0eaf04e8e59953d2dfa035151e666101de3d7195aefec9af7
sonic_hash=0xe8fe0e2243aa3041d4741521601e695498f85cd8212cf1e5fe8cbd06910702cf
eip1967_slot=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

jq -nS \
  --arg hash "$sonic_hash" \
  --arg slot "$eip1967_slot" '
  def bound: {blockHash:$hash, requireCanonical:true};
  [
    {jsonrpc:"2.0",id:"chain-id",method:"eth_chainId",params:[]},
    {jsonrpc:"2.0",id:"block",method:"eth_getBlockByHash",params:[$hash,false]},

    {jsonrpc:"2.0",id:"old-pft-proxy-code",method:"eth_getCode",params:["0xa4215daaf3745e14e96e169e0e7706c479ce04f2",bound]},
    {jsonrpc:"2.0",id:"old-pft-implementation-slot",method:"eth_getStorageAt",params:["0xa4215daaf3745e14e96e169e0e7706c479ce04f2",$slot,bound]},
    {jsonrpc:"2.0",id:"new-pft-proxy-code",method:"eth_getCode",params:["0x1d8051c90076faa5b683a3551ee4369d00f99d67",bound]},
    {jsonrpc:"2.0",id:"new-pft-implementation-slot",method:"eth_getStorageAt",params:["0x1d8051c90076faa5b683a3551ee4369d00f99d67",$slot,bound]},

    {jsonrpc:"2.0",id:"old-put-proxy-code",method:"eth_getCode",params:["0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",bound]},
    {jsonrpc:"2.0",id:"old-put-implementation-slot",method:"eth_getStorageAt",params:["0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",$slot,bound]},
    {jsonrpc:"2.0",id:"new-put-proxy-code",method:"eth_getCode",params:["0xabd838e9977fc76430d637ed35eccfaf178ce071",bound]},
    {jsonrpc:"2.0",id:"new-put-implementation-slot",method:"eth_getStorageAt",params:["0xabd838e9977fc76430d637ed35eccfaf178ce071",$slot,bound]},

    {jsonrpc:"2.0",id:"marketplace-proxy-code",method:"eth_getCode",params:["0x9bb958d459a97e3e37e11becf842e728167d9114",bound]},
    {jsonrpc:"2.0",id:"marketplace-implementation-slot",method:"eth_getStorageAt",params:["0x9bb958d459a97e3e37e11becf842e728167d9114",$slot,bound]},

    {jsonrpc:"2.0",id:"old-pft-implementation-code",method:"eth_getCode",params:["0xc55253ea84050700e1efa8878d4a5053b6bf7c5e",bound]},
    {jsonrpc:"2.0",id:"new-pft-implementation-code",method:"eth_getCode",params:["0xcf047256d5cd7354327213929214e5dad3a83326",bound]},
    {jsonrpc:"2.0",id:"old-put-implementation-code",method:"eth_getCode",params:["0x90ae2cac15f8d58a258f7b4a243657754469922a",bound]},
    {jsonrpc:"2.0",id:"new-put-implementation-code",method:"eth_getCode",params:["0x915220f3845d9d0db7960399c4e5ba0038f1170b",bound]},
    {jsonrpc:"2.0",id:"marketplace-implementation-code",method:"eth_getCode",params:["0xbdd1327024b66212bf1f6a6a7f8b21f81b1faca4",bound]},

    {jsonrpc:"2.0",id:"marketplace-pft-slot",method:"eth_getStorageAt",params:["0x9bb958d459a97e3e37e11becf842e728167d9114","0x0",bound]},
    {jsonrpc:"2.0",id:"old-pft-putmanager",method:"eth_call",params:[{to:"0xa4215daaf3745e14e96e169e0e7706c479ce04f2",data:"0x4f5e8085"},bound]},
    {jsonrpc:"2.0",id:"new-pft-putmanager",method:"eth_call",params:[{to:"0x1d8051c90076faa5b683a3551ee4369d00f99d67",data:"0x4f5e8085"},bound]},
    {jsonrpc:"2.0",id:"old-put-ft",method:"eth_call",params:[{to:"0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",data:"0x0b011758"},bound]},
    {jsonrpc:"2.0",id:"new-put-ft",method:"eth_call",params:[{to:"0xabd838e9977fc76430d637ed35eccfaf178ce071",data:"0x0b011758"},bound]},
    {jsonrpc:"2.0",id:"old-ft-symbol",method:"eth_call",params:[{to:"0x5dd1a7a369e8273371d2dbf9d83356057088082c",data:"0x95d89b41"},bound]},
    {jsonrpc:"2.0",id:"old-ft-decimals",method:"eth_call",params:[{to:"0x5dd1a7a369e8273371d2dbf9d83356057088082c",data:"0x313ce567"},bound]},
    {jsonrpc:"2.0",id:"new-ft-symbol",method:"eth_call",params:[{to:"0x26382a5331ddb46e7c0c101fb53480eb64a94ad9",data:"0x95d89b41"},bound]},
    {jsonrpc:"2.0",id:"new-ft-decimals",method:"eth_call",params:[{to:"0x26382a5331ddb46e7c0c101fb53480eb64a94ad9",data:"0x313ce567"},bound]}
  ]
' >"$rpc/request-sonic-identity.json"

jq -nS \
  --arg hash "$ethereum_hash" \
  --arg slot "$eip1967_slot" '
  def bound: {blockHash:$hash, requireCanonical:true};
  [
    {jsonrpc:"2.0",id:"chain-id",method:"eth_chainId",params:[]},
    {jsonrpc:"2.0",id:"block",method:"eth_getBlockByHash",params:[$hash,false]},
    {jsonrpc:"2.0",id:"old-pft-proxy-code",method:"eth_getCode",params:["0xa4215daaf3745e14e96e169e0e7706c479ce04f2",bound]},
    {jsonrpc:"2.0",id:"old-pft-implementation-slot",method:"eth_getStorageAt",params:["0xa4215daaf3745e14e96e169e0e7706c479ce04f2",$slot,bound]},
    {jsonrpc:"2.0",id:"old-put-proxy-code",method:"eth_getCode",params:["0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",bound]},
    {jsonrpc:"2.0",id:"old-put-implementation-slot",method:"eth_getStorageAt",params:["0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",$slot,bound]},
    {jsonrpc:"2.0",id:"old-pft-implementation-code",method:"eth_getCode",params:["0xc55253ea84050700e1efa8878d4a5053b6bf7c5e",bound]},
    {jsonrpc:"2.0",id:"old-put-implementation-code",method:"eth_getCode",params:["0x1e4e741e5f0f4f258def137e1968716eddae4bf5",bound]},
    {jsonrpc:"2.0",id:"old-pft-putmanager",method:"eth_call",params:[{to:"0xa4215daaf3745e14e96e169e0e7706c479ce04f2",data:"0x4f5e8085"},bound]},
    {jsonrpc:"2.0",id:"old-put-ft",method:"eth_call",params:[{to:"0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",data:"0x0b011758"},bound]},
    {jsonrpc:"2.0",id:"old-ft-symbol",method:"eth_call",params:[{to:"0x5dd1a7a369e8273371d2dbf9d83356057088082c",data:"0x95d89b41"},bound]},
    {jsonrpc:"2.0",id:"old-ft-decimals",method:"eth_call",params:[{to:"0x5dd1a7a369e8273371d2dbf9d83356057088082c",data:"0x313ce567"},bound]}
  ]
' >"$compile_input_tmp"

# Public Ethereum endpoints cap JSON-RPC batches. Keep each frozen request at
# four calls while preserving one logical identity capture.
jq '.[0:4]' "$compile_input_tmp" >"$rpc/request-ethereum-identity-a.json"
jq '.[4:8]' "$compile_input_tmp" >"$rpc/request-ethereum-identity-b.json"
jq '.[8:12]' "$compile_input_tmp" >"$rpc/request-ethereum-identity-c.json"

jq -nS '[
  {jsonrpc:"2.0",id:"pft-old",method:"eth_getTransactionByHash",params:["0x717e02988ed1018f5ad4969575a0f2f0717e2d5f7f5ca6d5eb7c4aa76a0a8941"]},
  {jsonrpc:"2.0",id:"pft-new",method:"eth_getTransactionByHash",params:["0xfac38603ffee6007bb3696c295e6ba918c8341dbcbd7fd8bd35d52a06fa6c4ea"]},
  {jsonrpc:"2.0",id:"put-old",method:"eth_getTransactionByHash",params:["0xcc92885c7af5399e4bf18e6094479aaf461d33636801078917ab38e02bddd4fc"]},
  {jsonrpc:"2.0",id:"put-new",method:"eth_getTransactionByHash",params:["0x8e072d45742f9d11780337e738d5a9b3ec07e159d0d2d811df0532acd5d8a515"]},
  {jsonrpc:"2.0",id:"marketplace",method:"eth_getTransactionByHash",params:["0xf086be09bb409c8fbe7ee1aede49b677080ca374cb33018796c2409903e52f90"]}
]' >"$rpc/request-sonic-creation-transactions.json"

jq -nS '[
  {jsonrpc:"2.0",id:"put-old",method:"eth_getTransactionByHash",params:["0x02503d253171f72e0840151fafe3665cb1866aeba0dbbd51408a69568ff17257"]}
]' >"$rpc/request-ethereum-creation-transactions.json"

rpc_request \
  https://rpc.soniclabs.com \
  "$rpc/request-sonic-identity.json" \
  "$rpc/response-sonic-soniclabs-identity.json"
rpc_request \
  https://sonic-rpc.publicnode.com \
  "$rpc/request-sonic-identity.json" \
  "$rpc/response-sonic-publicnode-identity.json"
rpc_request \
  https://rpc.soniclabs.com \
  "$rpc/request-sonic-creation-transactions.json" \
  "$rpc/response-sonic-soniclabs-creation-transactions.json"
rpc_request \
  https://sonic-rpc.publicnode.com \
  "$rpc/request-sonic-creation-transactions.json" \
  "$rpc/response-sonic-publicnode-creation-transactions.json"

for part in a b c; do
  rpc_request \
    https://rpc.mevblocker.io \
    "$rpc/request-ethereum-identity-$part.json" \
    "$rpc/response-ethereum-mevblocker-identity-$part.json"
  rpc_request \
    https://mainnet.gateway.tenderly.co \
    "$rpc/request-ethereum-identity-$part.json" \
    "$rpc/response-ethereum-tenderly-identity-$part.json"
done
rpc_request \
  https://rpc.mevblocker.io \
  "$rpc/request-ethereum-creation-transactions.json" \
  "$rpc/response-ethereum-mevblocker-creation-transactions.json"
rpc_request \
  https://mainnet.gateway.tenderly.co \
  "$rpc/request-ethereum-creation-transactions.json" \
  "$rpc/response-ethereum-tenderly-creation-transactions.json"

find "$root" -type f ! -name manifest.json -printf '%P\n' |
  LC_ALL=C sort |
  while IFS= read -r path; do
    jq -nS \
      --arg path "$path" \
      --arg sha256 "$(sha256sum "$root/$path" | cut -d' ' -f1)" \
      '{path:$path,sha256:$sha256}'
  done |
  jq -sS '.' >"$artifact_tmp"

jq -nS \
  --argjson artifacts "$(<"$artifact_tmp")" '
  {
    schema_version: 1,
    scope: "Seven FlyingTulip pFT, marketplace, and PutManager leaves; fifteen admitted deployment-format instances",
    issue: "https://github.com/EthereumPhone/PQ1/issues/497",
    captured_at_utc: "2026-07-28T11:10:00Z",
    fixed_blocks: {
      ethereum: {
        chain_id: 1,
        number: 25630720,
        number_hex: "0x1871800",
        hash: "0x6ef230ed8c6d2bd0eaf04e8e59953d2dfa035151e666101de3d7195aefec9af7",
        state_root: "0x56201c1863e551e47e584fbe807a6200b8937e7d62a373a37e1342c0f113e27d",
        timestamp_hex: "0x6a68843b",
        providers: ["MEV Blocker", "Tenderly"]
      },
      sonic: {
        chain_id: 146,
        number: 76644352,
        number_hex: "0x4918000",
        hash: "0xe8fe0e2243aa3041d4741521601e695498f85cd8212cf1e5fe8cbd06910702cf",
        state_root: "0x7c8d728e11af622c3484a0e21de463dbdfd96a10d4fadbb0a4a33d8209d5968a",
        timestamp_hex: "0x6a6885e1",
        providers: ["Sonic Labs", "PublicNode"]
      }
    },
    deployments: [
      {family:"pFT",chain_id:1,proxy:"0xa4215daaf3745e14e96e169e0e7706c479ce04f2",implementation:"0xc55253ea84050700e1efa8878d4a5053b6bf7c5e",put_manager:"0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",accepted_routes:2},
      {family:"pFT",chain_id:146,proxy:"0xa4215daaf3745e14e96e169e0e7706c479ce04f2",implementation:"0xc55253ea84050700e1efa8878d4a5053b6bf7c5e",put_manager:"0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",accepted_routes:2},
      {family:"pFT",chain_id:146,proxy:"0x1d8051c90076faa5b683a3551ee4369d00f99d67",implementation:"0xcf047256d5cd7354327213929214e5dad3a83326",put_manager:"0xabd838e9977fc76430d637ed35eccfaf178ce071",accepted_routes:2},
      {family:"PutManager",chain_id:1,proxy:"0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",implementation:"0x1e4e741e5f0f4f258def137e1968716eddae4bf5",ft:"0x5dd1a7a369e8273371d2dbf9d83356057088082c",pft:"0xa4215daaf3745e14e96e169e0e7706c479ce04f2",accepted_routes:2},
      {family:"PutManager",chain_id:146,proxy:"0xba49d0ac42f4fba4e24a8677a22218a4df75ebaa",implementation:"0x90ae2cac15f8d58a258f7b4a243657754469922a",ft:"0x5dd1a7a369e8273371d2dbf9d83356057088082c",pft:"0xa4215daaf3745e14e96e169e0e7706c479ce04f2",accepted_routes:2},
      {family:"PutManager",chain_id:146,proxy:"0xabd838e9977fc76430d637ed35eccfaf178ce071",implementation:"0x915220f3845d9d0db7960399c4e5ba0038f1170b",ft:"0x26382a5331ddb46e7c0c101fb53480eb64a94ad9",pft:"0x1d8051c90076faa5b683a3551ee4369d00f99d67",accepted_routes:2},
      {family:"pFTMarketplace",chain_id:146,proxy:"0x9bb958d459a97e3e37e11becf842e728167d9114",implementation:"0xbdd1327024b66212bf1f6a6a7f8b21f81b1faca4",pft:"0x1d8051c90076faa5b683a3551ee4369d00f99d67",accepted_routes:3}
    ],
    admitted_routes: {
      pFT: ["approve(address,uint256)","setApprovalForAll(address,bool)"],
      pFTMarketplace: ["addListing(uint256,address,uint256,uint40)","editListing(uint256,address,uint256,uint256)","removeListing(uint256)"],
      PutManager: ["divest(uint256,uint256)","withdrawFT(uint256,uint256)"]
    },
    exact_known_refusals: {
      pFTMarketplace: [
        "buy(uint256,address,uint256,bytes32,(uint256,uint40,bytes))",
        "acceptBuyOffer((address,address,uint96,uint96,uint96,address,uint96,uint256,uint40),uint256,bytes,bytes,uint256,bytes32)"
      ],
      PutManager: ["invest(address,uint256,address,uint256,bytes32[])"]
    },
    boundary: "Historical verified-source, compiler, fixed-block proxy/runtime, immutable, token-metadata, and signed-meaning evidence only. No future-upgrade, live-state, success, fallback, forced-blind, hardware, production, or shipment authority.",
    artifacts: $artifacts
  }
' >"$manifest_tmp"
mv "$manifest_tmp" "$root/manifest.json"
