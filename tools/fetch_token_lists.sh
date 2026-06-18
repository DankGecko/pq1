#!/usr/bin/env bash
#
# Fetch the comprehensive set of upstream ERC20 token lists consumed by
# tools/build_erc20_db.py to build the (host-side) ERC-20 metadata DB.
#
# The DB blob is host/companion-side only (the firmware ships just the
# 32-byte ERC20_DB_ROOT), so size is effectively unbounded — we cast a
# WIDE net so clear-signing (transfers + CoW Swap orders) can resolve
# essentially every actively-traded token on the supported chains.
#
# Two source classes, both carrying a per-token `chainId` so the builder
# assigns chains by field, never by filename:
#
#   1. CoinGecko per-platform `all.json` — the exhaustive, listing-vetted
#      universe of tokens CoinGecko tracks on each chain (thousands/chain).
#   2. Curated DEX / aggregator token lists — Uniswap, 1inch, Sushi,
#      PancakeSwap, QuickSwap, Optimism Superchain, Gemini — the
#      actively-traded "top-used" overlay (+ a few tokens CoinGecko omits).
#
# Output: build/token_lists/*.json (every *.json there is ingested by the
# builder; drop in more lists freely). All files overwritten each run.
# Individual fetch failures are NON-FATAL — a transient upstream outage
# must not wipe coverage; the builder works from whatever landed.
#
# Rerun to refresh, then `python3 tools/build_erc20_db.py` to regenerate
# secure/data/erc20.json, then `cargo run -p dbgen` for the blob + root.

set -uo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
out_dir="$repo_root/build/token_lists"
mkdir -p "$out_dir"

ok=0
fail=0

fetch() {
    local name="$1" url="$2"
    if curl -fsSL --retry 3 --retry-delay 2 -m 60 -o "$out_dir/$name.json.tmp" "$url"; then
        mv "$out_dir/$name.json.tmp" "$out_dir/$name.json"
        local bytes
        bytes=$(wc -c <"$out_dir/$name.json")
        printf "    ok   %9d bytes  %s\n" "$bytes" "$name" >&2
        ok=$((ok + 1))
    else
        rm -f "$out_dir/$name.json.tmp"
        printf "    WARN fetch failed: %-26s (%s)\n" "$name" "$url" >&2
        fail=$((fail + 1))
    fi
}

echo "==> Fetching token lists into $out_dir" >&2

# -- 1. CoinGecko per-platform all.json (exhaustive backbone) --------------
# CoinGecko entries already carry the right per-token chainId.
echo "  CoinGecko per-chain all.json:" >&2
for slug in \
    ethereum \
    optimistic-ethereum \
    binance-smart-chain \
    unichain \
    polygon-pos \
    base \
    arbitrum-one \
    avalanche \
    linea \
    hyperevm ; do
    fetch "coingecko_${slug}" "https://tokens.coingecko.com/${slug}/all.json"
done

# -- 2. Curated DEX / aggregator overlays ----------------------------------
echo "  Uniswap / Optimism Superchain / PancakeSwap / QuickSwap / Gemini:" >&2
fetch uniswap        "https://tokens.uniswap.org"
fetch optimism_super "https://static.optimism.io/optimism.tokenlist.json"
# Li.Fi bridge-aggregator multichain list — broad, bridge-supported coverage
# (esp. deep Hyperliquid + Polygon + Arbitrum). Shape: {"tokens":{cid:[...]}}.
fetch lifi           "https://li.quest/v1/tokens"
fetch pancakeswap    "https://tokens.pancakeswap.finance/pancakeswap-extended.json"
fetch quickswap      "https://unpkg.com/quickswap-default-token-list@latest/build/quickswap-default.tokenlist.json"
fetch gemini         "https://www.gemini.com/uniswap/manifest.json"

echo "  1inch per-chain (addr->token maps):" >&2
for cid in 1 10 56 137 8453 42161 43114 59144 ; do
    fetch "1inch_${cid}" "https://tokens.1inch.io/v1.2/${cid}"
done

echo "  Sushi per-chain (bare arrays):" >&2
for slug in ethereum optimism bsc polygon base arbitrum linea ; do
    fetch "sushi_${slug}" \
        "https://raw.githubusercontent.com/sushiswap/list/master/lists/token-lists/default-token-list/tokens/${slug}.json"
done

echo "==> done: $ok ok, $fail failed" >&2
# Succeed as long as the CoinGecko backbone (at least Ethereum) landed.
if [ ! -f "$out_dir/coingecko_ethereum.json" ]; then
    echo "ERROR: CoinGecko Ethereum backbone missing — aborting." >&2
    exit 1
fi
exit 0
