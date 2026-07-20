#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
blockscout="$root/blockscout"
source_dir="$root/source"
runtime="$root/runtime"
abi="$root/abi"

mkdir -p "$rpc" "$blockscout" "$source_dir" "$runtime" "$abi"

fetch() {
  curl --fail --silent --show-error --max-time 60 "$@"
}

collect_rpc() {
  local name="$1"
  local url="$2"
  local batch
  for batch in identity proxy implementation libraries admin; do
    fetch \
      -H 'content-type: application/json' \
      --data-binary "@$rpc/request-$batch.json" \
      "$url" >"$rpc/response-$name-$batch.json"
  done
}

collect_rpc drpc https://eth.drpc.org
collect_rpc mevblocker https://rpc.mevblocker.io
collect_rpc tenderly https://mainnet.gateway.tenderly.co

fetch \
  https://eth.blockscout.com/api/v2/smart-contracts/0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 \
  >"$blockscout/PoolProxy.json"
fetch \
  https://eth.blockscout.com/api/v2/smart-contracts/0x728a138A4823392C2EFA55e028d434F526fE03CF \
  >"$blockscout/PoolImplementation.json"
fetch \
  https://eth.blockscout.com/api/v2/smart-contracts/0x52Da0ce88202D1542543598D1e1e27F0d344726A \
  >"$blockscout/BorrowLogic.json"
fetch \
  https://eth.blockscout.com/api/v2/smart-contracts/0x584C7d8c4cb05304FE5Ac7fbc97f20A10Fb07564 \
  >"$blockscout/SupplyLogic.json"

fetch \
  https://raw.githubusercontent.com/aave-dao/aave-address-book/7e444a1e73b538fd0b9e093e5156401d6fccca7d/src/AaveV3Ethereum.sol \
  >"$source_dir/AaveV3Ethereum.sol"
fetch \
  https://raw.githubusercontent.com/aave-dao/aave-v3-origin/fd1fbd9150426ca8ace9cee45b4acf912ae84f5b/src/contracts/instances/PoolInstance.sol \
  >"$source_dir/PoolInstance.sol"
fetch \
  https://raw.githubusercontent.com/aave-dao/aave-v3-origin/fd1fbd9150426ca8ace9cee45b4acf912ae84f5b/src/contracts/protocol/pool/Pool.sol \
  >"$source_dir/Pool.sol"
fetch \
  https://raw.githubusercontent.com/aave-dao/aave-v3-origin/fd1fbd9150426ca8ace9cee45b4acf912ae84f5b/src/contracts/protocol/libraries/logic/BorrowLogic.sol \
  >"$source_dir/BorrowLogic.sol"
fetch \
  https://raw.githubusercontent.com/aave-dao/aave-v3-origin/fd1fbd9150426ca8ace9cee45b4acf912ae84f5b/src/contracts/protocol/libraries/logic/SupplyLogic.sol \
  >"$source_dir/SupplyLogic.sol"

jq -r '.[] | select(.id == 4) | .result' \
  "$rpc/response-drpc-proxy.json" >"$runtime/PoolProxy.ethereum-mainnet.hex"
jq -r '.[] | select(.id == 7) | .result' \
  "$rpc/response-drpc-implementation.json" >"$runtime/PoolImplementation.ethereum-mainnet.hex"
jq -r '.[] | select(.id == 10) | .result' \
  "$rpc/response-drpc-libraries.json" >"$runtime/BorrowLogic.ethereum-mainnet.hex"
jq -r '.[] | select(.id == 11) | .result' \
  "$rpc/response-drpc-libraries.json" >"$runtime/SupplyLogic.ethereum-mainnet.hex"

jq '[.abi[] | select(.type == "function" and (.name == "approvePositionManager" or .name == "borrow" or .name == "deposit" or .name == "renouncePositionManagerRole" or .name == "repay" or .name == "repayWithATokens" or .name == "setUserUseReserveAsCollateral" or .name == "setUserUseReserveAsCollateralOnBehalfOf" or .name == "supply" or .name == "withdraw"))] | sort_by(.name)' \
  "$blockscout/PoolImplementation.json" >"$abi/Pool.routes.abi.json"
