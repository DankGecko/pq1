#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
rpc="$root/rpc/raw"
official="$root/official"
verifier="$root/verifier"
abi="$root/abi"
runtime="$root/runtime"

mkdir -p "$rpc" "$official/github" "$verifier" "$abi" "$runtime" \
  "$root/src/interfaces" "$root/src/libraries" "$root/script"

fetch() {
  curl --fail --silent --show-error --max-time 60 "$@"
}

commit=cc306b601f172c51bc04334a109e98340456620b
tag=0x000000000022D473030F116dDEE9F6B43aC78BA3
github_api=https://api.github.com/repos/Uniswap/permit2
github_raw=https://raw.githubusercontent.com/Uniswap/permit2/$commit

fetch "$github_api/git/ref/tags/$tag" >"$official/github/deployment-tag.ref.json"
fetch "$github_api/git/commits/$commit" >"$official/github/deployment-tag.commit.json"
fetch "$github_raw/README.md" >"$official/README.md"

for path in \
  script/DeployPermit2.s.sol \
  src/AllowanceTransfer.sol \
  src/EIP712.sol \
  src/Permit2.sol \
  src/PermitErrors.sol \
  src/SignatureTransfer.sol \
  src/interfaces/IAllowanceTransfer.sol \
  src/interfaces/IERC1271.sol \
  src/interfaces/ISignatureTransfer.sol \
  src/libraries/Allowance.sol \
  src/libraries/PermitHash.sol \
  src/libraries/SignatureVerification.sol
do
  fetch "$github_raw/$path" >"$root/$path"
done

fetch \
  "https://eth.blockscout.com/api/v2/smart-contracts/$tag" \
  >"$verifier/ethereum-blockscout.json"
jq -S '.abi' "$verifier/ethereum-blockscout.json" >"$abi/Permit2.abi.json"

for provider in drpc tenderly
do
  case "$provider" in
    drpc) url=https://eth.drpc.org ;;
    tenderly) url=https://mainnet.gateway.tenderly.co ;;
  esac
  fetch \
    -H 'content-type: application/json' \
    --data-binary "@$rpc/request-ethereum.json" \
    "$url" | jq -S 'sort_by(.id)' >"$rpc/response-$provider-ethereum.json"
done

jq -r '.[] | select(.id == "permit2-code") | .result' \
  "$rpc/response-drpc-ethereum.json" >"$runtime/Permit2.ethereum-mainnet.hex"
