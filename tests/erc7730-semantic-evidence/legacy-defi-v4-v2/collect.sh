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

implementation_slot=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

collect_aave() {
  local slug="$1"
  local chain_id="$2"
  local block_hash="$3"
  local proxy="$4"
  local implementation="$5"
  local provider="$6"
  local provider_a_name="$7"
  local provider_a_url="$8"
  local provider_b_name="$9"
  local provider_b_url="${10}"
  local chain_rpc="$rpc/aave-$slug"
  local tag

  mkdir -p "$chain_rpc"
  tag="$(jq -nc --arg hash "$block_hash" '{blockHash:$hash,requireCanonical:true}')"

  jq -n --arg hash "$block_hash" --arg proxy "$proxy" --arg slot "$implementation_slot" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
      {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]},
      {jsonrpc:"2.0",id:3,method:"eth_getStorageAt",params:[$proxy,$slot,$tag]}
    ]' >"$chain_rpc/request-identity.json"
  jq -n --arg proxy "$proxy" --arg implementation "$implementation" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:4,method:"eth_getCode",params:[$proxy,$tag]},
      {jsonrpc:"2.0",id:5,method:"eth_getCode",params:[$implementation,$tag]}
    ]' >"$chain_rpc/request-runtime.json"
  jq -n --arg proxy "$proxy" --arg provider "$provider" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:6,method:"eth_call",params:[{to:$proxy,data:"0xfe65acfe"},$tag]},
      {jsonrpc:"2.0",id:7,method:"eth_call",params:[{to:$proxy,data:"0x8afaff02"},$tag]},
      {jsonrpc:"2.0",id:8,method:"eth_call",params:[{to:$provider,data:"0x0261bf8b"},$tag]}
    ]' >"$chain_rpc/request-links.json"

  local batch provider_name provider_url
  for batch in identity runtime links; do
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
    "$chain_rpc/response-$provider_a_name-runtime.json" >"$runtime/AaveV2PoolProxy.$slug.hex"
  jq -r '.[] | select(.id == 5) | .result' \
    "$chain_rpc/response-$provider_a_name-runtime.json" >"$runtime/AaveV2PoolImplementation.$slug.hex"

  printf '%s\n' "$chain_id" >/dev/null
}

collect_aave ethereum 1 \
  0xc764a3327787002b64c36ae2776c0f25a9c9e7fa8e94dc1748c04550adba4bfd \
  0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9 \
  0x02D84abD89Ee9DB409572f19B6e1596c301F3c81 \
  0xB53C1a33016B2DC2fF3653530bfF1848a515c8c5 \
  drpc https://eth.drpc.org mevblocker https://rpc.mevblocker.io
collect_aave polygon 137 \
  0x2a97804fa59fe15b1ff8fe068997e5a21f15d68d89fb987c38fdd24a46f976d4 \
  0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf \
  0x1685D81212580DD4cDA287616C2f6F4794927e18 \
  0xd05e3E715d945B59290df0ae8eF85c1BdB684744 \
  tenderly https://polygon.gateway.tenderly.co drpc https://polygon.drpc.org
collect_aave avalanche 43114 \
  0x21bfb1f3a7ede20bfa372e278ec6208717f998dbab172b1f3f9644691a751b09 \
  0x4F01AeD16D97E3aB5ab2B501154DC9bb0F1A5A2C \
  0x102Bf2C03c1901AdBA191457A8c4A4eF18b40029 \
  0xb6A86025F0FE1862B372cb0ca18CE3EDe02A318f \
  tenderly https://avalanche.gateway.tenderly.co thirdweb https://43114.rpc.thirdweb.com

oneinch_rpc="$rpc/oneinch-ethereum"
mkdir -p "$oneinch_rpc"
oneinch=0x1111111254fb6c44bAC0beD2854e76F90643097d
ethereum_hash=0xc764a3327787002b64c36ae2776c0f25a9c9e7fa8e94dc1748c04550adba4bfd
ethereum_tag="$(jq -nc --arg hash "$ethereum_hash" '{blockHash:$hash,requireCanonical:true}')"
jq -n --arg hash "$ethereum_hash" --arg oneinch "$oneinch" --arg slot "$implementation_slot" --argjson tag "$ethereum_tag" '
  [
    {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
    {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]},
    {jsonrpc:"2.0",id:3,method:"eth_getStorageAt",params:[$oneinch,$slot,$tag]}
  ]' >"$oneinch_rpc/request-identity.json"
jq -n --arg oneinch "$oneinch" --argjson tag "$ethereum_tag" '
  [{jsonrpc:"2.0",id:4,method:"eth_getCode",params:[$oneinch,$tag]}]
  ' >"$oneinch_rpc/request-runtime.json"
for batch in identity runtime; do
  fetch -H 'content-type: application/json' \
    --data-binary "@$oneinch_rpc/request-$batch.json" \
    https://eth.drpc.org >"$oneinch_rpc/response-drpc-$batch.json"
  fetch -H 'content-type: application/json' \
    --data-binary "@$oneinch_rpc/request-$batch.json" \
    https://rpc.mevblocker.io >"$oneinch_rpc/response-mevblocker-$batch.json"
done
jq -r '.[] | select(.id == 4) | .result' \
  "$oneinch_rpc/response-drpc-runtime.json" >"$runtime/AggregationRouterV4.ethereum.hex"

sourcify_fields='compilation,abi,sources,runtimeBytecode.onchainBytecode,deployment,proxyResolution'
fetch "https://sourcify.dev/server/v2/contract/1/$oneinch?fields=$sourcify_fields" \
  >"$verification/Sourcify.oneinch-v4.ethereum.json"

aave_fields='compilation,abi,sources,runtimeBytecode.onchainBytecode,deployment'
fetch "https://sourcify.dev/server/v2/contract/1/0x02D84abD89Ee9DB409572f19B6e1596c301F3c81?fields=$aave_fields" \
  >"$verification/Sourcify.aave-v2.ethereum.implementation.json"
fetch "https://sourcify.dev/server/v2/contract/137/0x1685D81212580DD4cDA287616C2f6F4794927e18?fields=$aave_fields" \
  >"$verification/Sourcify.aave-v2.polygon.implementation.json"
fetch 'https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan/api?module=contract&action=getsourcecode&address=0x102Bf2C03c1901AdBA191457A8c4A4eF18b40029' \
  >"$verification/Routescan.aave-v2.avalanche.implementation.json"

proxy_fields='compilation,proxyResolution,runtimeBytecode.onchainBytecode'
fetch "https://sourcify.dev/server/v2/contract/1/0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9?fields=$proxy_fields" \
  >"$verification/Sourcify.aave-v2.ethereum.proxy.json"
fetch "https://sourcify.dev/server/v2/contract/137/0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf?fields=$proxy_fields" \
  >"$verification/Sourcify.aave-v2.polygon.proxy.json"
fetch "https://sourcify.dev/server/v2/contract/43114/0x4F01AeD16D97E3aB5ab2B501154DC9bb0F1A5A2C?fields=$proxy_fields" \
  >"$verification/Sourcify.aave-v2.avalanche.proxy.json"

address_book_commit=4ae19b95f84b077c28633ca1d0f9a6750a3ea1d4
for network in Ethereum Polygon Avalanche; do
  fetch "https://raw.githubusercontent.com/aave-dao/aave-address-book/$address_book_commit/src/AaveV2$network.sol" \
    >"$source_dir/AaveV2$network.sol"
done

protocol_v2_commit=ce53c4a8c8620125063168620eba0a8a92854eb8
fetch "https://raw.githubusercontent.com/aave/protocol-v2/$protocol_v2_commit/contracts/interfaces/ILendingPool.sol" \
  >"$source_dir/ILendingPool.sol"
fetch "https://raw.githubusercontent.com/aave/protocol-v2/$protocol_v2_commit/contracts/protocol/lendingpool/LendingPool.sol" \
  >"$source_dir/LendingPool.sol"
fetch "https://raw.githubusercontent.com/aave/protocol-v2/$protocol_v2_commit/contracts/protocol/libraries/types/DataTypes.sol" \
  >"$source_dir/DataTypes.sol"

aave_abi_filter='
  [.[] | select(
    .type == "function" and
    (.name == "borrow" or .name == "deposit" or .name == "repay" or
     .name == "setUserUseReserveAsCollateral" or .name == "swapBorrowRateMode" or
     .name == "withdraw")
  )] | sort_by(.name)'
jq '.abi' "$verification/Sourcify.aave-v2.ethereum.implementation.json" |
  jq "$aave_abi_filter" >"$abi/AaveV2.routes.ethereum.abi.json"
jq '.abi' "$verification/Sourcify.aave-v2.polygon.implementation.json" |
  jq "$aave_abi_filter" >"$abi/AaveV2.routes.polygon.abi.json"
jq '.result[0].ABI | fromjson' \
  "$verification/Routescan.aave-v2.avalanche.implementation.json" |
  jq "$aave_abi_filter" >"$abi/AaveV2.routes.avalanche.abi.json"
jq '[.abi[] | select(
      .type == "function" and
      (.name == "clipperSwap" or .name == "clipperSwapTo" or
       .name == "clipperSwapToWithPermit")
    )] | sort_by(.name)' \
  "$verification/Sourcify.oneinch-v4.ethereum.json" \
  >"$abi/AggregationRouterV4.clipper.abi.json"

artifacts_tmp="$(mktemp)"
manifest_tmp="$(mktemp)"
trap 'rm -f "$artifacts_tmp" "$manifest_tmp"' EXIT
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  jq -nc --arg path "$relative" --arg sha256 "$(sha256sum "$path" | cut -d' ' -f1)" \
    '{path:$path,sha256:$sha256}' >>"$artifacts_tmp"
done < <(find "$root" -type f ! -name manifest.json -print0 | sort -z)

jq -n --slurpfile artifacts "$artifacts_tmp" \
  --arg captured_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  {
    schema_version: 1,
    scope: "1inch AggregationRouterV4 Clipper and Aave V2 LendingPool deployed semantics for the exact admitted static routes",
    captured_at_utc: $captured_at_utc,
    issue: "https://github.com/EthereumPhone/PQ1/issues/497",
    boundary: "Historical fixed-block evidence only; no future-upgrade monitoring, token/reserve metadata, quote quality, execution-success, hardware, production, shipment, fallback, or blind-signing authority.",
    eip1967_implementation_slot: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    oneinch: {
      chain_id: 1,
      address: "0x1111111254fb6c44bAC0beD2854e76F90643097d",
      block_number_hex: "0x1863b00",
      block_hash: "0xc764a3327787002b64c36ae2776c0f25a9c9e7fa8e94dc1748c04550adba4bfd",
      parent_hash: "0xd874b44ee0035a420b0bc099fd9d231a6b57f47c9e9d77d1976db1bd9e2327aa",
      state_root: "0x093297f3201225733791d1ea446c4387d94b2fb51f0d49b7311207669c8682b3",
      timestamp_hex: "0x6a5e1eab",
      providers: [
        {name:"drpc",url:"https://eth.drpc.org"},
        {name:"mevblocker",url:"https://rpc.mevblocker.io"}
      ],
      verification: "verification/Sourcify.oneinch-v4.ethereum.json",
      runtime: "runtime/AggregationRouterV4.ethereum.hex",
      admitted_signatures: [
        "clipperSwap(address,address,uint256,uint256)",
        "clipperSwapTo(address,address,address,uint256,uint256)"
      ],
      refused_declared_signatures: [
        "clipperSwapToWithPermit(address,address,address,uint256,uint256,bytes)"
      ]
    },
    aave: {
      address_book: {
        repository: "https://github.com/aave-dao/aave-address-book",
        commit: "4ae19b95f84b077c28633ca1d0f9a6750a3ea1d4",
        tree: "0eaba341a910ce91acc15063ae676eaf480b8290"
      },
      auxiliary_protocol_source: {
        repository: "https://github.com/aave/protocol-v2",
        commit: "ce53c4a8c8620125063168620eba0a8a92854eb8",
        tree: "3a07aba11e970d4e793a1cf7c47728bcbfc93c75",
        load_bearing: false
      },
      admitted_signatures: [
        "borrow(address,uint256,uint256,uint16,address)",
        "deposit(address,uint256,address,uint16)",
        "repay(address,uint256,uint256,address)",
        "setUserUseReserveAsCollateral(address,bool)",
        "swapBorrowRateMode(address,uint256)",
        "withdraw(address,uint256,address)"
      ],
      deployments: [
        {
          slug:"ethereum",chain_id:1,
          proxy:"0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
          implementation:"0x02D84abD89Ee9DB409572f19B6e1596c301F3c81",
          addresses_provider:"0xB53C1a33016B2DC2fF3653530bfF1848a515c8c5",
          revision:5,block_number_hex:"0x1863b00",
          block_hash:"0xc764a3327787002b64c36ae2776c0f25a9c9e7fa8e94dc1748c04550adba4bfd",
          parent_hash:"0xd874b44ee0035a420b0bc099fd9d231a6b57f47c9e9d77d1976db1bd9e2327aa",
          state_root:"0x093297f3201225733791d1ea446c4387d94b2fb51f0d49b7311207669c8682b3",
          timestamp_hex:"0x6a5e1eab",
          providers:[{name:"drpc",url:"https://eth.drpc.org"},{name:"mevblocker",url:"https://rpc.mevblocker.io"}],
          implementation_verification:"verification/Sourcify.aave-v2.ethereum.implementation.json",
          proxy_verification:"verification/Sourcify.aave-v2.ethereum.proxy.json"
        },
        {
          slug:"polygon",chain_id:137,
          proxy:"0x8dFf5E27EA6b7AC08EbFdf9eB090F32ee9a30fcf",
          implementation:"0x1685D81212580DD4cDA287616C2f6F4794927e18",
          addresses_provider:"0xd05e3E715d945B59290df0ae8eF85c1BdB684744",
          revision:3,block_number_hex:"0x566f900",
          block_hash:"0x2a97804fa59fe15b1ff8fe068997e5a21f15d68d89fb987c38fdd24a46f976d4",
          parent_hash:"0xe709a64c01aff1d4d3a1a7dc01885f046f41ea52a498b42374070652a8d64e0e",
          state_root:"0x7ed67b4580567664d2dbaef23cee559fb52bf56ecde41088ee33262916310e9c",
          timestamp_hex:"0x6a5fb365",
          providers:[{name:"tenderly",url:"https://polygon.gateway.tenderly.co"},{name:"drpc",url:"https://polygon.drpc.org"}],
          implementation_verification:"verification/Sourcify.aave-v2.polygon.implementation.json",
          proxy_verification:"verification/Sourcify.aave-v2.polygon.proxy.json"
        },
        {
          slug:"avalanche",chain_id:43114,
          proxy:"0x4F01AeD16D97E3aB5ab2B501154DC9bb0F1A5A2C",
          implementation:"0x102Bf2C03c1901AdBA191457A8c4A4eF18b40029",
          addresses_provider:"0xb6A86025F0FE1862B372cb0ca18CE3EDe02A318f",
          revision:3,block_number_hex:"0x56af2c2",
          block_hash:"0x21bfb1f3a7ede20bfa372e278ec6208717f998dbab172b1f3f9644691a751b09",
          parent_hash:"0xebdb075343c14eabf3b057d340a2963606412b10957aa67ce5f3e612961fb258",
          state_root:"0x7cc66da296163440a0974e76d5374ed20e9ccf870c247250b96edecd4cb77ca8",
          timestamp_hex:"0x6a5fb8c7",
          providers:[{name:"tenderly",url:"https://avalanche.gateway.tenderly.co"},{name:"thirdweb",url:"https://43114.rpc.thirdweb.com"}],
          implementation_verification:"verification/Routescan.aave-v2.avalanche.implementation.json",
          proxy_verification:"verification/Sourcify.aave-v2.avalanche.proxy.json"
        }
      ]
    },
    artifacts: $artifacts
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$root/manifest.json"
