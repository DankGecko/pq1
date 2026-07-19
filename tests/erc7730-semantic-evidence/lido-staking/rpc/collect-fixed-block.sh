#!/usr/bin/env bash
set -euo pipefail

root=/tmp/pqsigner-lido-rpc-25569139-20260719
block=0x1862773
steth=0xae7ab96520de3a18e5e111b5eaab095312d7fe84
implementation=0x6ca84080381e43938476814be61b779a8bb6a600
staker=0xa88f0329c2c4ce51ba3fc619bbf44efe7120dd0d
wsteth=0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0

query() {
    local endpoint_name=$1
    local endpoint_url=$2
    local name=$3
    local request=$4
    local out="$root/$endpoint_name"
    mkdir -p "$out"
    curl \
        --fail-with-body \
        --silent \
        --show-error \
        --max-time 60 \
        --retry 2 \
        --retry-all-errors \
        -H 'content-type: application/json' \
        --data "$request" \
        --output "$out/$name.json" \
        "$endpoint_url"
}

collect_endpoint() {
    local endpoint_name=$1
    local endpoint_url=$2

    query "$endpoint_name" "$endpoint_url" 01_chain_id \
        '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
    query "$endpoint_name" "$endpoint_url" 02_block_25569139 \
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$block\",false]}"
    query "$endpoint_name" "$endpoint_url" 03_steth_proxy_code \
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_getCode\",\"params\":[\"$steth\",\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 04_steth_implementation_code \
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"eth_getCode\",\"params\":[\"$implementation\",\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 05_wsteth_referral_staker_code \
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"eth_getCode\",\"params\":[\"$staker\",\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 06_proxy_implementation \
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"eth_call\",\"params\":[{\"to\":\"$steth\",\"data\":\"0x5c60da1b\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 07_proxy_type \
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"eth_call\",\"params\":[{\"to\":\"$steth\",\"data\":\"0x4555d5c9\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 08_proxy_kernel \
        "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"eth_call\",\"params\":[{\"to\":\"$steth\",\"data\":\"0xd4aae0c4\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 09_proxy_app_id \
        "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"eth_call\",\"params\":[{\"to\":\"$steth\",\"data\":\"0x80afdea8\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 10_staker_steth \
        "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"eth_call\",\"params\":[{\"to\":\"$staker\",\"data\":\"0xc1fe3e48\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 11_staker_wsteth \
        "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"eth_call\",\"params\":[{\"to\":\"$staker\",\"data\":\"0x4aa07e64\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 12_steth_shares_for_1eth \
        "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"eth_call\",\"params\":[{\"to\":\"$steth\",\"data\":\"0x192084510000000000000000000000000000000000000000000000000de0b6b3a7640000\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 13_steth_pooled_eth_for_1share \
        "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"eth_call\",\"params\":[{\"to\":\"$steth\",\"data\":\"0x7a28fb880000000000000000000000000000000000000000000000000de0b6b3a7640000\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 14_wsteth_for_1steth \
        "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"eth_call\",\"params\":[{\"to\":\"$wsteth\",\"data\":\"0xb0e389000000000000000000000000000000000000000000000000000de0b6b3a7640000\"},\"$block\"]}"
    query "$endpoint_name" "$endpoint_url" 15_steth_for_1wsteth \
        "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"eth_call\",\"params\":[{\"to\":\"$wsteth\",\"data\":\"0xbb2952fc0000000000000000000000000000000000000000000000000de0b6b3a7640000\"},\"$block\"]}"
}

collect_endpoint drpc https://eth.drpc.org
collect_endpoint mevblocker https://rpc.mevblocker.io

for response in "$root"/*/*.json; do
    jq -e 'has("jsonrpc") and has("id") and has("result") and (has("error") | not)' "$response" >/dev/null
done
