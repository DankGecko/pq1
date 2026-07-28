#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
workspace="$(CDPATH= cd -- "$root/../../.." && pwd)"
rpc="$root/rpc/raw"
runtime="$root/runtime"
verification="$root/verification"
source_dir="$root/source"
abi="$root/abi"

mkdir -p "$rpc" "$runtime" "$verification" "$source_dir" "$abi"

fetch() {
  curl --fail --silent --show-error --max-time 120 \
    --retry 5 --retry-delay 2 --retry-all-errors "$@"
}

post() {
  local request="$1"
  local provider="$2"
  local output="$3"
  fetch -H 'content-type: application/json' --data-binary "@$request" "$provider" >"$output"
}

collect_direct() {
  local slug="$1"
  local chain_id="$2"
  local block_hash="$3"
  local address="$4"
  local provider_a_name="$5"
  local provider_a_url="$6"
  local provider_b_name="$7"
  local provider_b_url="$8"
  local dir="$rpc/$slug"
  local tag

  mkdir -p "$dir"
  tag="$(jq -nc --arg hash "$block_hash" '{blockHash:$hash,requireCanonical:true}')"
  jq -n --arg hash "$block_hash" --argjson tag "$tag" '
    [
      {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
      {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]}
    ]' >"$dir/request-identity.json"
  jq -n --arg address "$address" --argjson tag "$tag" '
    [{jsonrpc:"2.0",id:3,method:"eth_getCode",params:[$address,$tag]}]
    ' >"$dir/request-runtime.json"

  local batch
  for batch in identity runtime; do
    post "$dir/request-$batch.json" "$provider_a_url" \
      "$dir/response-$provider_a_name-$batch.json"
    post "$dir/request-$batch.json" "$provider_b_url" \
      "$dir/response-$provider_b_name-$batch.json"
  done

  jq -r '.[] | select(.id == 3) | .result' \
    "$dir/response-$provider_a_name-runtime.json" >"$runtime/$slug.hex"
  printf '%s\n' "$chain_id" >/dev/null
}

collect_direct \
  kiln-ethereum 1 \
  0x1e512402a8962f765cd38a0da170a33058ab9b10cdf746943517bf7176b688de \
  0x8659EEFF31CFcff580D37AF8e7Af250F8998aA83 \
  drpc https://eth.drpc.org mevblocker https://rpc.mevblocker.io

collect_direct \
  kiln-hoodi 560048 \
  0x6a99d242a4c98750e8e41d1994a9ef01172808ee3d42ae6165a0cd8c9ba4cb29 \
  0x1A76bc69922744807E86375f8B8AB8A7cf18Eb7a \
  drpc https://hoodi.drpc.org ethpandaops https://rpc.hoodi.ethpandaops.io

wallet_dir="$rpc/walletconnect-optimism"
mkdir -p "$wallet_dir"
wallet_hash=0xe10eb45ddbcd0a98add70f7e1932f8ca4b75ceadc072265f6cacbc93d7e26b94
wallet_tag="$(jq -nc --arg hash "$wallet_hash" '{blockHash:$hash,requireCanonical:true}')"
wallet_proxy=0x521B4C065Bbdbe3E20B3727340730936912DfA46
wallet_implementation=0x6845541121e555D1245fe17c6b44273B089C3844
wallet_config=0xd2f149faa66dc4448176123f850c14ff14f978b3
wallet_token=0xeF4461891DfB3AC8572cCf7C794664A8DD927945
implementation_slot=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

jq -n --arg hash "$wallet_hash" --arg proxy "$wallet_proxy" \
  --arg slot "$implementation_slot" --argjson tag "$wallet_tag" '
  [
    {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
    {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]},
    {jsonrpc:"2.0",id:3,method:"eth_getStorageAt",params:[$proxy,$slot,$tag]}
  ]' >"$wallet_dir/request-identity.json"
jq -n --arg proxy "$wallet_proxy" --arg implementation "$wallet_implementation" \
  --arg config "$wallet_config" --arg token "$wallet_token" --argjson tag "$wallet_tag" '
  [
    {jsonrpc:"2.0",id:4,method:"eth_getCode",params:[$proxy,$tag]},
    {jsonrpc:"2.0",id:5,method:"eth_getCode",params:[$implementation,$tag]},
    {jsonrpc:"2.0",id:6,method:"eth_getCode",params:[$config,$tag]},
    {jsonrpc:"2.0",id:7,method:"eth_getCode",params:[$token,$tag]}
  ]' >"$wallet_dir/request-runtime.json"
jq -n --arg proxy "$wallet_proxy" --arg config "$wallet_config" \
  --arg token "$wallet_token" --argjson tag "$wallet_tag" '
  [
    {jsonrpc:"2.0",id:8,method:"eth_call",params:[{to:$proxy,data:"0x79502c55"},$tag]},
    {jsonrpc:"2.0",id:9,method:"eth_call",params:[{to:$config,data:"0xdba8eff3"},$tag]},
    {jsonrpc:"2.0",id:10,method:"eth_call",params:[{to:$token,data:"0x95d89b41"},$tag]},
    {jsonrpc:"2.0",id:11,method:"eth_call",params:[{to:$token,data:"0x313ce567"},$tag]}
  ]' >"$wallet_dir/request-links.json"

for batch in identity runtime links; do
  post "$wallet_dir/request-$batch.json" https://mainnet.optimism.io \
    "$wallet_dir/response-op-$batch.json"
  post "$wallet_dir/request-$batch.json" https://optimism-rpc.publicnode.com \
    "$wallet_dir/response-publicnode-$batch.json"
done

jq -r '.[] | select(.id == 4) | .result' \
  "$wallet_dir/response-op-runtime.json" >"$runtime/StakeWeightProxy.optimism.hex"
jq -r '.[] | select(.id == 5) | .result' \
  "$wallet_dir/response-op-runtime.json" >"$runtime/StakeWeight.implementation.optimism.hex"
jq -r '.[] | select(.id == 6) | .result' \
  "$wallet_dir/response-op-runtime.json" >"$runtime/WalletConnectConfigProxy.optimism.hex"
jq -r '.[] | select(.id == 7) | .result' \
  "$wallet_dir/response-op-runtime.json" >"$runtime/L2WCTProxy.optimism.hex"

sourcify_fields='compilation,abi,sources,runtimeBytecode.onchainBytecode,deployment,proxyResolution'
fetch "https://sourcify.dev/server/v2/contract/1/0x8659EEFF31CFcff580D37AF8e7Af250F8998aA83?fields=$sourcify_fields" \
  >"$verification/Sourcify.kiln-ethereum.json"
fetch "https://sourcify.dev/server/v2/contract/560048/0x1A76bc69922744807E86375f8B8AB8A7cf18Eb7a?fields=$sourcify_fields" \
  >"$verification/Sourcify.kiln-hoodi.json"
fetch "https://sourcify.dev/server/v2/contract/10/$wallet_proxy?fields=$sourcify_fields" \
  >"$verification/Sourcify.stakeweight-proxy-optimism.json"
fetch "https://sourcify.dev/server/v2/contract/10/$wallet_implementation?fields=$sourcify_fields" \
  >"$verification/Sourcify.stakeweight-implementation-optimism.json"

jq -r '.sources["src/Factory.sol"].content' \
  "$verification/Sourcify.kiln-ethereum.json" >"$source_dir/Factory.ethereum.sol"
jq -r '.sources["src/Factory.sol"].content' \
  "$verification/Sourcify.kiln-hoodi.json" >"$source_dir/Factory.hoodi.sol"
jq -r '.sources["src/Operator.sol"].content' \
  "$verification/Sourcify.kiln-ethereum.json" >"$source_dir/Operator.ethereum.sol"
jq -r '.sources["src/StakeWeight.sol"].content' \
  "$verification/Sourcify.stakeweight-implementation-optimism.json" >"$source_dir/StakeWeight.sol"
jq -r '.sources["src/WalletConnectConfig.sol"].content' \
  "$verification/Sourcify.stakeweight-implementation-optimism.json" \
  >"$source_dir/WalletConnectConfig.sol"

kiln_filter='
  [.abi[] | select(
    .type == "function" and
    (.name == "createOperator" or .name == "createSplitter" or
     .name == "createSplitterAndCall" or .name == "transferOwnership")
  )] | sort_by(.name)'
jq "$kiln_filter" "$verification/Sourcify.kiln-ethereum.json" \
  >"$abi/KilnFactory.routes.ethereum.abi.json"
jq "$kiln_filter" "$verification/Sourcify.kiln-hoodi.json" \
  >"$abi/KilnFactory.routes.hoodi.abi.json"
jq '[.abi[] | select(
      .type == "function" and
      (.name == "createLock" or .name == "depositFor" or
       .name == "increaseLockAmount" or .name == "increaseUnlockTime" or
       .name == "updateLock" or .name == "withdrawAll" or .name == "config")
    )] | sort_by(.name)' \
  "$verification/Sourcify.stakeweight-implementation-optimism.json" \
  >"$abi/StakeWeight.routes.optimism.abi.json"

artifacts_tmp="$(mktemp)"
manifest_tmp="$(mktemp)"
trap 'rm -f "$artifacts_tmp" "$manifest_tmp"' EXIT
while IFS= read -r -d '' path; do
  relative="${path#"$root/"}"
  jq -nc --arg path "$relative" --arg sha256 "$(sha256sum "$path" | cut -d' ' -f1)" \
    '{path:$path,sha256:$sha256}' >>"$artifacts_tmp"
done < <(find "$root" -type f ! -name manifest.json -print0 | sort -z)

jq -n --slurpfile artifacts "$artifacts_tmp" \
  --arg captured_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg celo_manifest_sha256 \
    "$(sha256sum "$workspace/tests/erc7730-semantic-evidence/celo-validators-first-member/manifest.json" | cut -d' ' -f1)" '
  {
    schema_version: 1,
    scope: "Celo Accounts, Kiln Factory, and WalletConnect StakeWeight exact admitted route subsets",
    captured_at_utc: $captured_at_utc,
    issue: "https://github.com/EthereumPhone/PQ1/issues/497",
    boundary: "Historical fixed-block deployment/source semantics only; no future-upgrade monitoring, mutable-state or execution-success claims, hardware, production, shipment, fallback, or blind-signing authority.",
    celo_accounts: {
      evidence_manifest: "tests/erc7730-semantic-evidence/celo-validators-first-member/manifest.json",
      evidence_manifest_sha256: $celo_manifest_sha256,
      chain_id: 42220,
      proxy: "0x7d21685C17607338b313a7174bAb6620baD0aaB7",
      implementation: "0x907f5c53c0e31db06af45bc58f076563469c525a",
      admitted_signatures: [
        "authorizeSigner(address,bytes32)",
        "completeSignerAuthorization(address,bytes32)",
        "createAccount()",
        "deletePaymentDelegation()",
        "removeAttestationSigner()",
        "removeDefaultSigner(bytes32)",
        "removeIndexedSigner(bytes32)",
        "removeSigner(address,bytes32)",
        "removeStorageRoot(uint256)",
        "removeValidatorSigner()",
        "removeVoteSigner()",
        "setMetadataURL(string)",
        "setName(string)",
        "setPaymentDelegation(address,uint256)"
      ],
      refused_declared_signatures: [
        "addStorageRoot(bytes)",
        "authorizeAttestationSigner(address,uint8,bytes32,bytes32)",
        "authorizeSignerWithSignature(address,bytes32,uint8,bytes32,bytes32)",
        "authorizeValidatorSigner(address,uint8,bytes32,bytes32)",
        "authorizeValidatorSignerWithPublicKey(address,uint8,bytes32,bytes32,bytes)",
        "authorizeVoteSigner(address,uint8,bytes32,bytes32)"
      ]
    },
    kiln: {
      admitted_signatures: [
        "createOperator(address,string,uint256,uint256,address[],uint256[])",
        "createSplitter(address,bytes32)",
        "transferOwnership(address)"
      ],
      refused_declared_signatures: [
        "createSplitterAndCall(address,bytes32,address,bytes)"
      ],
      deployments: [
        {
          slug:"ethereum",chain_id:1,address:"0x8659EEFF31CFcff580D37AF8e7Af250F8998aA83",
          block_number_hex:"0x187034b",
          block_hash:"0x1e512402a8962f765cd38a0da170a33058ab9b10cdf746943517bf7176b688de",
          providers:[
            {name:"drpc",url:"https://eth.drpc.org"},
            {name:"mevblocker",url:"https://rpc.mevblocker.io"}
          ],
          verification:"verification/Sourcify.kiln-ethereum.json",
          runtime:"runtime/kiln-ethereum.hex"
        },
        {
          slug:"hoodi",chain_id:560048,address:"0x1A76bc69922744807E86375f8B8AB8A7cf18Eb7a",
          block_number_hex:"0x325601",
          block_hash:"0x6a99d242a4c98750e8e41d1994a9ef01172808ee3d42ae6165a0cd8c9ba4cb29",
          providers:[
            {name:"drpc",url:"https://hoodi.drpc.org"},
            {name:"ethpandaops",url:"https://rpc.hoodi.ethpandaops.io"}
          ],
          verification:"verification/Sourcify.kiln-hoodi.json",
          runtime:"runtime/kiln-hoodi.hex"
        }
      ]
    },
    walletconnect: {
      chain_id:10,
      proxy:"0x521B4C065Bbdbe3E20B3727340730936912DfA46",
      implementation:"0x6845541121e555D1245fe17c6b44273B089C3844",
      config:"0xd2f149faa66dc4448176123f850c14ff14f978b3",
      token:"0xeF4461891DfB3AC8572cCf7C794664A8DD927945",
      token_symbol:"WCT",
      token_decimals:18,
      block_number_hex:"0x939db13",
      block_hash:"0xe10eb45ddbcd0a98add70f7e1932f8ca4b75ceadc072265f6cacbc93d7e26b94",
      eip1967_implementation_slot:"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
      providers:[
        {name:"optimism",url:"https://mainnet.optimism.io"},
        {name:"publicnode",url:"https://optimism-rpc.publicnode.com"}
      ],
      proxy_verification:"verification/Sourcify.stakeweight-proxy-optimism.json",
      implementation_verification:"verification/Sourcify.stakeweight-implementation-optimism.json",
      admitted_signatures:[
        "createLock(uint256,uint256)",
        "depositFor(address,uint256)",
        "increaseLockAmount(uint256)",
        "increaseUnlockTime(uint256)",
        "updateLock(uint256,uint256)",
        "withdrawAll()"
      ]
    },
    artifacts:$artifacts
  }' >"$manifest_tmp"

jq . "$manifest_tmp" >"$root/manifest.json"
