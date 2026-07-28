#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
source_dir="$root/source"
deployments="$root/deployments"
rpc="$root/rpc/raw"
runtime="$root/runtime"

mkdir -p \
  "$source_dir/v1.4.1-2" \
  "$source_dir/v1.5.0" \
  "$deployments/v1.4.1" \
  "$deployments/v1.5.0" \
  "$rpc" "$runtime"

fetch() {
  curl --fail --silent --show-error --max-time 120 \
    --retry 5 --retry-delay 2 --retry-all-errors "$@"
}

safe_repo=https://raw.githubusercontent.com/safe-fndn/safe-smart-account
safe_v141=aa14911666deb13cdbbe37c37253a55918525437
safe_v150=dc437e8fba8b4805d76bcbd1c668c9fd3d1e83be

for source in SafeMigration SafeToL2Setup; do
  fetch "$safe_repo/$safe_v141/contracts/libraries/$source.sol" \
    >"$source_dir/v1.4.1-2/$source.sol"
  fetch "$safe_repo/$safe_v150/contracts/libraries/$source.sol" \
    >"$source_dir/v1.5.0/$source.sol"
done

deploy_repo=https://raw.githubusercontent.com/safe-global/safe-deployments
deploy_commit=06021f40739266f21a9ec083cf19827ab48b5dc7
for version in v1.4.1 v1.5.0; do
  for asset in \
    safe \
    safe_l2 \
    compatibility_fallback_handler \
    safe_migration \
    safe_to_l2_setup
  do
    fetch "$deploy_repo/$deploy_commit/src/assets/$version/$asset.json" \
      >"$deployments/$version/$asset.json"
  done
done

block_hash=0x5ceb4e40574ba2b93faf07aaa23587804ac417d25aa6a57174c318438c22c64d
block_number=0x1870180
canonical_tag="$(jq -nc --arg hash "$block_hash" \
  '{blockHash:$hash,requireCanonical:true}')"

migration_v141=0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6
setup_v141=0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54
migration_v150=0x6439e7ABD8Bb915A5263094784C5CF561c4172AC
setup_v150=0x900C7589200010D6C6eCaaE5B06EBe653bc2D82a

jq -n --arg hash "$block_hash" '
  [
    {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
    {jsonrpc:"2.0",id:2,method:"eth_getBlockByHash",params:[$hash,false]}
  ]' >"$rpc/request-identity.json"
jq -n \
  --arg migration "$migration_v141" \
  --arg setup "$setup_v141" \
  --argjson tag "$canonical_tag" '
  [
    {jsonrpc:"2.0",id:3,method:"eth_getCode",params:[$migration,$tag]},
    {jsonrpc:"2.0",id:4,method:"eth_getCode",params:[$setup,$tag]}
  ]' >"$rpc/request-runtime-v1.4.1.json"
jq -n \
  --arg migration "$migration_v150" \
  --arg setup "$setup_v150" \
  --argjson tag "$canonical_tag" '
  [
    {jsonrpc:"2.0",id:5,method:"eth_getCode",params:[$migration,$tag]},
    {jsonrpc:"2.0",id:6,method:"eth_getCode",params:[$setup,$tag]}
  ]' >"$rpc/request-runtime-v1.5.0.json"
jq -n \
  --arg to "$migration_v141" \
  --arg block "$block_number" '
  [
    {jsonrpc:"2.0",id:7,method:"eth_call",params:[{to:$to,data:"0x72f7a956"},$block]},
    {jsonrpc:"2.0",id:8,method:"eth_call",params:[{to:$to,data:"0xcaa12add"},$block]},
    {jsonrpc:"2.0",id:9,method:"eth_call",params:[{to:$to,data:"0x9bf47d6e"},$block]}
  ]' >"$rpc/request-getters-a.json"
jq -n \
  --arg v141 "$migration_v141" \
  --arg v150 "$migration_v150" \
  --arg block "$block_number" '
  [
    {jsonrpc:"2.0",id:10,method:"eth_call",params:[{to:$v141,data:"0x0d7101f7"},$block]},
    {jsonrpc:"2.0",id:11,method:"eth_call",params:[{to:$v150,data:"0x72f7a956"},$block]},
    {jsonrpc:"2.0",id:12,method:"eth_call",params:[{to:$v150,data:"0xcaa12add"},$block]}
  ]' >"$rpc/request-getters-b.json"
jq -n \
  --arg to "$migration_v150" \
  --arg block "$block_number" '
  [
    {jsonrpc:"2.0",id:13,method:"eth_call",params:[{to:$to,data:"0x9bf47d6e"},$block]},
    {jsonrpc:"2.0",id:14,method:"eth_call",params:[{to:$to,data:"0x0d7101f7"},$block]}
  ]' >"$rpc/request-getters-c.json"

for provider in drpc mevblocker; do
  if [[ "$provider" == drpc ]]; then
    url=https://eth.drpc.org
  else
    url=https://rpc.mevblocker.io
  fi
  for batch in \
    identity \
    runtime-v1.4.1 \
    runtime-v1.5.0 \
    getters-a \
    getters-b \
    getters-c
  do
    fetch -H 'content-type: application/json' \
      --data-binary "@$rpc/request-$batch.json" "$url" \
      >"$rpc/response-$provider-$batch.json"
  done
done

jq -r '.[] | select(.id == 3) | .result' \
  "$rpc/response-drpc-runtime-v1.4.1.json" \
  >"$runtime/SafeMigration-1.4.1.ethereum.hex"
jq -r '.[] | select(.id == 4) | .result' \
  "$rpc/response-drpc-runtime-v1.4.1.json" \
  >"$runtime/SafeToL2Setup-1.4.1.ethereum.hex"
jq -r '.[] | select(.id == 5) | .result' \
  "$rpc/response-drpc-runtime-v1.5.0.json" \
  >"$runtime/SafeMigration-1.5.0.ethereum.hex"
jq -r '.[] | select(.id == 6) | .result' \
  "$rpc/response-drpc-runtime-v1.5.0.json" \
  >"$runtime/SafeToL2Setup-1.5.0.ethereum.hex"
