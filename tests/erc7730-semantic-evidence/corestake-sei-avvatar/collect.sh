#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT="$ROOT/tests/erc7730-semantic-evidence/corestake-sei-avvatar"

CORE_BLOCK=0x23955b7
SEI_BLOCK=0xd46b000
BASE_BLOCK=0x2ef2800

CORE_PRIMARY=https://core.drpc.org
CORE_SECONDARY=https://rpc.ankr.com/core
SEI_PRIMARY=https://evm-rpc.sei-apis.com
SEI_SECONDARY=https://sei-evm-rpc.publicnode.com
BASE_PRIMARY=https://mainnet.base.org
BASE_SECONDARY=https://base.drpc.org

CORE_AGENT=0x0000000000000000000000000000000000001011
CORE_EARN=0xf5fA1728bABc3f8D2a617397faC2696c958C3409
CORE_EARN_IMPL=0x62c5e03a5bfa0d6af08b81165a9eb87d1c8b8a0b
CORE_STAKE_HUB=0x0000000000000000000000000000000000001010
SEI_DISTRIBUTION=0x0000000000000000000000000000000000001007
SEI_STAKING=0x0000000000000000000000000000000000001005
ALIA_AGENT=0xD5667AcB0Ac8108B45f6CDD4774559264098f8de
ALIA_ASSET=0xfC9cA736d384D482af5d23CC7616765C66244D29
ALIA_SCORE=0x295CCcDE8Fb06148d4FB6Bfc06B6c332E42aCb43

EIP1967_IMPL_SLOT=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
CORE_CHAIN_COMMIT=3dd2b07da5effef7af3c8486df66a873ff2b865c
CORE_GENESIS_COMMIT=7f973185d67cea94518ff6a176d9ffa8e6eaad80
CORE_EARN_COMMIT=4d237f6a366df6a6953cb0abfea4e68cafa9e7d9
SEI_V652_COMMIT=ab134842ce1bd97af73021bcff5850ad6c29e534
SEI_V650_COMMIT=fbc0d9342ca28887958013170e4020d93cacdbfa

mkdir -p \
  "$OUT/blockscout" \
  "$OUT/compiler" \
  "$OUT/rpc" \
  "$OUT/runtime" \
  "$OUT/source/core/core-chain" \
  "$OUT/source/core/core-genesis" \
  "$OUT/source/core/earn/contracts/interface" \
  "$OUT/source/core/earn/contracts/lib" \
  "$OUT/source/sei/v6.5.0/precompiles/distribution" \
  "$OUT/source/sei/v6.5.0/precompiles/staking" \
  "$OUT/source/sei/v6.5.2/app" \
  "$OUT/source/sei/v6.5.2/precompiles/common" \
  "$OUT/source/sei/v6.5.2/precompiles/distribution" \
  "$OUT/source/sei/v6.5.2/precompiles/staking"

rpc_record() {
  local endpoint=$1
  local kind=$2
  local target=$3
  local method=$4
  local params=$5
  local request response attempt
  request="$(jq -cn --arg method "$method" --argjson params "$params" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"
  for attempt in 1 2 3 4 5; do
    response="$(curl -fsSL --retry 2 --retry-all-errors --max-time 60 \
      -H 'content-type: application/json' -H 'user-agent: PQSigner-evidence/1.0' \
      --data-binary "$request" "$endpoint")"
    if jq -e '.error == null and .result != null' >/dev/null <<<"$response"; then
      break
    fi
    if [[ $attempt == 5 ]]; then
      echo "RPC evidence request failed after $attempt attempts: $kind $target" >&2
      jq . <<<"$response" >&2
      return 1
    fi
    sleep 1
  done
  jq -cnS --arg endpoint "$endpoint" --arg kind "$kind" --arg target "$target" \
    --argjson request "$request" --argjson response "$response" \
    '{endpoint:$endpoint,kind:$kind,target:$target,request:$request,response:$response}'
  if [[ "$endpoint" == *publicnode.com* ]]; then
    sleep 1
  fi
}

capture_evm_chain() {
  local endpoint=$1
  local chain=$2
  local block=$3
  local output=$4
  shift 4
  local tmp address
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' RETURN

  rpc_record "$endpoint" chain_id "$chain" eth_chainId '[]' >> "$tmp"
  rpc_record "$endpoint" block_header "$chain" eth_getBlockByNumber \
    "$(jq -cn --arg block "$block" '[$block,false]')" >> "$tmp"
  for address in "$@"; do
    rpc_record "$endpoint" runtime "$address" eth_getCode \
      "$(jq -cn --arg address "$address" --arg block "$block" '[$address,$block]')" >> "$tmp"
    rpc_record "$endpoint" implementation_slot "$address" eth_getStorageAt \
      "$(jq -cn --arg address "$address" --arg slot "$EIP1967_IMPL_SLOT" --arg block "$block" \
        '[$address,$slot,$block]')" >> "$tmp"
  done
  jq -sS . "$tmp" > "$output"
}

capture_sei_secondary_batch() {
  local request response
  request="$(jq -cn --arg block "$SEI_BLOCK" \
    '[
      {jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]},
      {jsonrpc:"2.0",id:2,method:"eth_getBlockByNumber",params:[$block,false]}
    ]')"
  response="$(curl -fsSL --retry 2 --retry-all-errors --max-time 60 \
    -H 'content-type: application/json' -H 'user-agent: PQSigner-evidence/1.0' \
    --data-binary "$request" "$SEI_SECONDARY")"
  jq -e 'length == 2 and all(.[]; .error == null and .result != null)' \
    >/dev/null <<<"$response"
  jq -nS --arg endpoint "$SEI_SECONDARY" --argjson request "$request" \
    --argjson response "$response" \
    '{endpoint:$endpoint,request:$request,response:($response|sort_by(.id))}' \
    > "$OUT/rpc/sei-secondary.json"
}

capture_evm_chain "$CORE_PRIMARY" core "$CORE_BLOCK" "$OUT/rpc/core-primary.json" \
  "$CORE_AGENT" "$CORE_EARN" "$CORE_EARN_IMPL" "$CORE_STAKE_HUB"
capture_evm_chain "$CORE_SECONDARY" core "$CORE_BLOCK" "$OUT/rpc/core-secondary.json" \
  "$CORE_AGENT" "$CORE_EARN" "$CORE_EARN_IMPL" "$CORE_STAKE_HUB"
capture_evm_chain "$SEI_PRIMARY" sei "$SEI_BLOCK" "$OUT/rpc/sei-primary.json" \
  "$SEI_DISTRIBUTION" "$SEI_STAKING"
capture_sei_secondary_batch
capture_evm_chain "$BASE_PRIMARY" base "$BASE_BLOCK" "$OUT/rpc/base-primary.json" \
  "$ALIA_AGENT" "$ALIA_ASSET" "$ALIA_SCORE"
capture_evm_chain "$BASE_SECONDARY" base "$BASE_BLOCK" "$OUT/rpc/base-secondary.json" \
  "$ALIA_AGENT" "$ALIA_ASSET" "$ALIA_SCORE"

curl -fsSL --max-time 60 \
  'https://rest.sei-apis.com/cosmos/base/tendermint/v1beta1/node_info' \
  | jq -S . > "$OUT/rpc/sei-node-v6.5.2.json"
curl -fsSL --max-time 60 \
  'https://sei-rest.publicnode.com/cosmos/base/tendermint/v1beta1/node_info' \
  | jq -S . > "$OUT/rpc/sei-node-v6.5.0.json"
curl -fsSL --max-time 60 \
  'https://rest.sei-apis.com/cosmos/upgrade/v1beta1/applied_plan/v6.5' \
  | jq -S . > "$OUT/rpc/sei-v6.5-upgrade.json"

for entry in \
  "AgentIdentityRegistry:$ALIA_AGENT" \
  "AssetIdentityRegistry:$ALIA_ASSET" \
  "ScoreEngineV2:$ALIA_SCORE"; do
  name=${entry%%:*}
  address=${entry#*:}
  curl -fsSL --max-time 60 \
    "https://base.blockscout.com/api/v2/smart-contracts/$address" \
    | jq -S . > "$OUT/blockscout/$name.json"
  jq -r '.source_code' "$OUT/blockscout/$name.json" > "$OUT/blockscout/$name.sol"
done

github_raw() {
  local repository=$1
  local commit=$2
  local path=$3
  local output=$4
  curl -fsSL --max-time 60 \
    "https://raw.githubusercontent.com/$repository/$commit/$path" > "$output"
}

curl -fsSL --max-time 60 \
  "https://api.github.com/repos/coredao-org/core-chain/commits/$CORE_CHAIN_COMMIT" \
  | jq -S . > "$OUT/source/core/core-chain/commit.json"
github_raw coredao-org/core-chain "$CORE_CHAIN_COMMIT" core/systemcontracts/const.go \
  "$OUT/source/core/core-chain/const.go"
github_raw coredao-org/core-chain "$CORE_CHAIN_COMMIT" core/systemcontracts/upgrade.go \
  "$OUT/source/core/core-chain/upgrade.go"
github_raw coredao-org/core-chain "$CORE_CHAIN_COMMIT" params/config.go \
  "$OUT/source/core/core-chain/config.go"
github_raw coredao-org/core-chain "$CORE_CHAIN_COMMIT" core/systemcontracts/hermes/mainnet/CoreAgentContract \
  "$OUT/source/core/core-chain/CoreAgentContract.hex"
github_raw coredao-org/core-chain "$CORE_CHAIN_COMMIT" core/systemcontracts/hermes/mainnet/StakeHubContract \
  "$OUT/source/core/core-chain/StakeHubContract.hex"

curl -fsSL --max-time 60 \
  "https://api.github.com/repos/coredao-org/core-genesis-contract/commits/$CORE_GENESIS_COMMIT" \
  | jq -S . > "$OUT/source/core/core-genesis/commit.json"
github_raw coredao-org/core-genesis-contract "$CORE_GENESIS_COMMIT" contracts/CoreAgent.sol \
  "$OUT/source/core/core-genesis/CoreAgent.sol"
github_raw coredao-org/core-genesis-contract "$CORE_GENESIS_COMMIT" contracts/StakeHub.sol \
  "$OUT/source/core/core-genesis/StakeHub.sol"

curl -fsSL --max-time 60 \
  "https://api.github.com/repos/coredao-org/Earn/commits/$CORE_EARN_COMMIT" \
  | jq -S . > "$OUT/source/core/earn/commit.json"
for path in \
  contracts/Earn.sol \
  contracts/STCore.sol \
  contracts/interface/ICandidateHub.sol \
  contracts/interface/IErrors.sol \
  contracts/interface/IPledgeAgent.sol \
  contracts/interface/ISTCore.sol \
  contracts/lib/IterableAddressDelegateMapping.sol \
  contracts/lib/Structs.sol \
  hardhat.config.ts \
  package.json; do
  github_raw coredao-org/Earn "$CORE_EARN_COMMIT" "$path" "$OUT/source/core/earn/$path"
done

curl -fsSL --max-time 60 \
  "https://api.github.com/repos/sei-protocol/sei-chain/commits/$SEI_V652_COMMIT" \
  | jq -S . > "$OUT/source/sei/v6.5.2/commit.json"
for path in \
  app/tags \
  app/upgrades.go \
  precompiles/common/precompiles.go \
  precompiles/distribution/Distribution.sol \
  precompiles/distribution/abi.json \
  precompiles/distribution/distribution.go \
  precompiles/distribution/setup.go \
  precompiles/staking/Staking.sol \
  precompiles/staking/abi.json \
  precompiles/staking/setup.go \
  precompiles/staking/staking.go; do
  github_raw sei-protocol/sei-chain "$SEI_V652_COMMIT" "$path" "$OUT/source/sei/v6.5.2/$path"
done

curl -fsSL --max-time 60 \
  "https://api.github.com/repos/sei-protocol/sei-chain/commits/$SEI_V650_COMMIT" \
  | jq -S . > "$OUT/source/sei/v6.5.0/commit.json"
for path in \
  precompiles/distribution/abi.json \
  precompiles/distribution/distribution.go \
  precompiles/staking/abi.json \
  precompiles/staking/staking.go; do
  github_raw sei-protocol/sei-chain "$SEI_V650_COMMIT" "$path" "$OUT/source/sei/v6.5.0/$path"
done

jq -r '.[] | select(.kind=="runtime" and .target=="'"$CORE_AGENT"'") | .response.result' \
  "$OUT/rpc/core-secondary.json" > "$OUT/runtime/CoreAgent.onchain.hex"
jq -r '.[] | select(.kind=="runtime" and .target=="'"$CORE_STAKE_HUB"'") | .response.result' \
  "$OUT/rpc/core-secondary.json" > "$OUT/runtime/StakeHub.onchain.hex"
jq -r '.[] | select(.kind=="runtime" and .target=="'"$CORE_EARN"'") | .response.result' \
  "$OUT/rpc/core-secondary.json" > "$OUT/runtime/EarnProxy.onchain.hex"
jq -r '.[] | select(.kind=="runtime" and .target=="'"$CORE_EARN_IMPL"'") | .response.result' \
  "$OUT/rpc/core-secondary.json" > "$OUT/runtime/EarnImplementation.onchain.hex"
for entry in \
  "AgentIdentityRegistry:$ALIA_AGENT" \
  "AssetIdentityRegistry:$ALIA_ASSET" \
  "ScoreEngineV2:$ALIA_SCORE"; do
  name=${entry%%:*}
  address=${entry#*:}
  jq -r '.[] | select(.kind=="runtime" and .target=="'"$address"'") | .response.result' \
    "$OUT/rpc/base-primary.json" > "$OUT/runtime/$name.onchain.hex"
done

compile_earn() {
  local scratch source_dir
  scratch="$(mktemp -d)"
  trap 'rm -rf "$scratch"' RETURN
  curl -fsSL --max-time 120 \
    "https://codeload.github.com/coredao-org/Earn/tar.gz/$CORE_EARN_COMMIT" \
    | tar -xz -C "$scratch"
  source_dir="$scratch/Earn-$CORE_EARN_COMMIT"
  (
    cd "$source_dir"
    npm install --ignore-scripts --no-audit --no-fund --legacy-peer-deps --no-save \
      solc@0.8.4 @openzeppelin/contracts@4.9.3 @openzeppelin/contracts-upgradeable@4.9.3 \
      >/dev/null
    OUT="$OUT/compiler" EARN_IMPL="$CORE_EARN_IMPL" node <<'NODE'
const fs = require("fs");
const path = require("path");
const solc = require("solc");
const input = {
  language: "Solidity",
  sources: {
    "contracts/Earn.sol": { content: fs.readFileSync("contracts/Earn.sol", "utf8") }
  },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    outputSelection: {
      "*": { "*": ["abi", "metadata", "evm.deployedBytecode.object", "evm.deployedBytecode.immutableReferences"] }
    }
  }
};
function findImports(importPath) {
  for (const candidate of [importPath, path.join("node_modules", importPath)]) {
    if (fs.existsSync(candidate)) return { contents: fs.readFileSync(candidate, "utf8") };
  }
  return { error: `not found: ${importPath}` };
}
const output = JSON.parse(solc.compile(JSON.stringify(input), { import: findImports }));
const errors = (output.errors || []).filter((entry) => entry.severity === "error");
if (errors.length) throw new Error(errors.map((entry) => entry.formattedMessage).join("\n"));
const earn = output.contracts["contracts/Earn.sol"].Earn;
const unlinked = Buffer.from(earn.evm.deployedBytecode.object, "hex");
const linked = Buffer.from(unlinked);
const implementation = Buffer.from(process.env.EARN_IMPL.slice(2).padStart(64, "0"), "hex");
for (const refs of Object.values(earn.evm.deployedBytecode.immutableReferences)) {
  for (const ref of refs) implementation.copy(linked, ref.start, 0, ref.length);
}
fs.writeFileSync(path.join(process.env.OUT, "Earn.unlinked-runtime.hex"), `${unlinked.toString("hex")}\n`);
fs.writeFileSync(path.join(process.env.OUT, "Earn.linked-runtime.hex"), `0x${linked.toString("hex")}\n`);
fs.writeFileSync(path.join(process.env.OUT, "Earn.immutable-references.json"),
  `${JSON.stringify(earn.evm.deployedBytecode.immutableReferences, null, 2)}\n`);
fs.writeFileSync(path.join(process.env.OUT, "Earn.metadata.json"), `${earn.metadata}\n`);
fs.writeFileSync(path.join(process.env.OUT, "Earn.abi.json"), `${JSON.stringify(earn.abi, null, 2)}\n`);
NODE
  )
}

compile_earn
echo "Captured Corestake, Sei, and Avvatar evidence at fixed EVM blocks."
