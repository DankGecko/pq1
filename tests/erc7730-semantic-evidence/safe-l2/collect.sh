#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source_dir="$root/source"
deployments="$root/deployments"
rpc="$root/rpc/raw"
runtime="$root/runtime"

mkdir -p \
  "$source_dir/v1.3.0" \
  "$source_dir/v1.4.1" \
  "$source_dir/v1.5.0" \
  "$deployments" "$rpc" "$runtime"

fetch() {
  curl --fail --silent --show-error --max-time 120 \
    --retry 5 --retry-delay 2 --retry-all-errors "$@"
}

safe_repo=https://raw.githubusercontent.com/safe-fndn/safe-smart-account
safe_v130=186a21a74b327f17fc41217a927dea7064f74604
safe_v141=bf943f80fec5ac647159d26161446ac5d716a294
safe_v150=dc437e8fba8b4805d76bcbd1c668c9fd3d1e83be

fetch "$safe_repo/$safe_v130/contracts/GnosisSafeL2.sol" \
  >"$source_dir/v1.3.0/GnosisSafeL2.sol"
fetch "$safe_repo/$safe_v130/contracts/GnosisSafe.sol" \
  >"$source_dir/v1.3.0/GnosisSafe.sol"
fetch "$safe_repo/$safe_v130/contracts/base/OwnerManager.sol" \
  >"$source_dir/v1.3.0/OwnerManager.sol"
fetch "$safe_repo/$safe_v141/contracts/SafeL2.sol" \
  >"$source_dir/v1.4.1/SafeL2.sol"
fetch "$safe_repo/$safe_v141/contracts/Safe.sol" \
  >"$source_dir/v1.4.1/Safe.sol"
fetch "$safe_repo/$safe_v141/contracts/base/OwnerManager.sol" \
  >"$source_dir/v1.4.1/OwnerManager.sol"
fetch "$safe_repo/$safe_v150/contracts/SafeL2.sol" \
  >"$source_dir/v1.5.0/SafeL2.sol"
fetch "$safe_repo/$safe_v150/contracts/Safe.sol" \
  >"$source_dir/v1.5.0/Safe.sol"
fetch "$safe_repo/$safe_v150/contracts/base/OwnerManager.sol" \
  >"$source_dir/v1.5.0/OwnerManager.sol"

deploy_repo=https://raw.githubusercontent.com/safe-global/safe-deployments
deploy_commit=06021f40739266f21a9ec083cf19827ab48b5dc7
fetch "$deploy_repo/$deploy_commit/src/assets/v1.3.0/gnosis_safe_l2.json" \
  >"$deployments/v1.3.0-gnosis_safe_l2.json"
fetch "$deploy_repo/$deploy_commit/src/assets/v1.4.1/safe_l2.json" \
  >"$deployments/v1.4.1-safe_l2.json"
fetch "$deploy_repo/$deploy_commit/src/assets/v1.5.0/safe_l2.json" \
  >"$deployments/v1.5.0-safe_l2.json"

block_hash=0x5ceb4e40574ba2b93faf07aaa23587804ac417d25aa6a57174c318438c22c64d
tag="$(jq -nc --arg hash "$block_hash" \
  '{blockHash:$hash,requireCanonical:true}')"

v130_canonical=0x3E5c63644E683549055b9Be8653de26E0B4CD36E
v130_eip155=0xfb1bffC9d739B8D520DaF37dF666da4C687191EA
v141=0x29fcB43b46531BcA003ddC8FCB67FFE91900C762
v150=0xEdd160fEBBD92E350D4D398fb636302fccd67C7e

jq -n --arg hash "$block_hash" '
  [
    {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
    {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]}
  ]' >"$rpc/request-identity.json"
jq -n \
  --arg canonical "$v130_canonical" \
  --arg eip155 "$v130_eip155" \
  --argjson tag "$tag" '
  [
    {jsonrpc:"2.0",id:3,method:"eth_getCode",params:[$canonical,$tag]},
    {jsonrpc:"2.0",id:4,method:"eth_getCode",params:[$eip155,$tag]}
  ]' >"$rpc/request-v1.3.0.json"
jq -n \
  --arg v141 "$v141" \
  --arg v150 "$v150" \
  --argjson tag "$tag" '
  [
    {jsonrpc:"2.0",id:5,method:"eth_getCode",params:[$v141,$tag]},
    {jsonrpc:"2.0",id:6,method:"eth_getCode",params:[$v150,$tag]}
  ]' >"$rpc/request-v1.4.1-v1.5.0.json"

for provider in drpc mevblocker; do
  if [[ "$provider" == drpc ]]; then
    url=https://eth.drpc.org
  else
    url=https://rpc.mevblocker.io
  fi
  for batch in identity v1.3.0 v1.4.1-v1.5.0; do
    fetch -H 'content-type: application/json' \
      --data-binary "@$rpc/request-$batch.json" "$url" \
      >"$rpc/response-$provider-$batch.json"
  done
done

jq -r '.[] | select(.id == 3) | .result' \
  "$rpc/response-drpc-v1.3.0.json" >"$runtime/SafeL2-1.3.0.ethereum.hex"
jq -r '.[] | select(.id == 5) | .result' \
  "$rpc/response-drpc-v1.4.1-v1.5.0.json" >"$runtime/SafeL2-1.4.1.ethereum.hex"
jq -r '.[] | select(.id == 6) | .result' \
  "$rpc/response-drpc-v1.4.1-v1.5.0.json" >"$runtime/SafeL2-1.5.0.ethereum.hex"
