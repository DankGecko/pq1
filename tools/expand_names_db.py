#!/usr/bin/env python3
"""
Expand secure/data/names.json — the address→friendly-name table the trusted UI
uses to render a recognizable label instead of a raw 0x… address (in the
blind-sign / typed-call / Safe / batch render paths).

The existing curated set already covers the famous PROTOCOL contracts (Uniswap,
1inch, CoW, Safe, EntryPoint, Seaport, Aave, …). The gap is breadth: 4 of the
10 supported chains (Linea, Hyperliquid, Avalanche, Unichain) had NO entries,
and the major TOKEN contracts aren't named cross-chain. Naming a token contract
is useful whenever it is the tx target — `approve`, `permit`, or a blind-sign
to the token itself shows e.g. "USD Coin" on the recipient line.

This expansion is DATA-DRIVEN and low-risk: token-contract addresses are taken
verbatim from the already-built, source-vetted `secure/data/erc20.json` (zero
hand-typing ⇒ no typo/mislabel risk), restricted to a curated high-recognition
symbol allowlist, and ONLY when the (chain, symbol) resolves to a SINGLE address
(an ambiguous symbol — multiple addresses — is skipped so we never label a scam
impersonator as a blue chip). A handful of famous chain-agnostic infra constants
(Multicall3, Permit2) round it out.

Existing entries are preserved verbatim (their hand-curated names win on any
(chain, address) collision). Output keeps the same one-entry-per-line JSON
style. Constraints honored (dbgen/src/names.rs + tx/src/names/bundle.rs):
  * name ≤ 32 bytes, printable ASCII 0x20..0x7e
  * keyed by (chain_id, address); chain_id omitted/0 ⇒ chain-agnostic wildcard
  * no duplicate (chain_id, address)

`secure/data/names-e2e.json` is the small fixture for `--features e2e-test`
QEMU builds (kept = the prior curated set) and is NOT touched here.

Run:  python3 tools/expand_names_db.py   then   cargo run -p dbgen
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import defaultdict

REPO = pathlib.Path(__file__).resolve().parent.parent
ERC20_PATH = REPO / "secure" / "data" / "erc20.json"
NAMES_PATH = REPO / "secure" / "data" / "names.json"

NAME_MAX_BYTES = 32  # dbgen/src/names.rs NAMES_MAX_LEN

# The 10 supported chains (token-contract naming is emitted for these).
TARGET_CHAINS = [1, 10, 56, 130, 137, 8453, 42161, 43114, 59144, 999]

# Curated high-recognition tickers worth naming as contracts. This is an
# ALLOWLIST of symbols only — it controls WHICH token contracts get named, but
# NOT the displayed name. The displayed name is always taken from the token's
# OWN row in the vetted ERC-20 DB (see below), so a ticker that a different
# project reuses on another chain (e.g. HYPE = Hyperliquid on HyperEVM but
# "Hyperbolic Protocol" on Ethereum) is labeled with its REAL name, never a
# hardcoded label that would mislabel it. Deliberately conservative: stables,
# wrapped natives, BTC wrappers, major LSTs, and a few blue chips — the
# contracts a user is most likely to target directly (approve/permit).
SYMBOL_ALLOWLIST: set[str] = {
    # Wrapped natives
    "WETH", "WBNB", "WMATIC", "WPOL", "WAVAX", "WHYPE", "WXDAI",
    # USD stablecoins
    "USDC", "USDT", "DAI", "USDC.E", "USDBC", "USDS", "FDUSD", "PYUSD",
    "USDE", "SUSDE", "USDD", "FRAX", "LUSD", "GHO", "CRVUSD", "TUSD",
    "USD1", "GUSD", "USDF", "DOLA",
    # BTC wrappers
    "WBTC", "CBBTC", "TBTC", "LBTC",
    # Major LSTs / LRTs
    "STETH", "WSTETH", "RETH", "CBETH", "WEETH", "EZETH", "RSETH",
    # Blue-chip governance / protocol tokens
    "LINK", "UNI", "AAVE", "ARB", "OP", "LDO", "CRV", "MKR", "SNX",
    "COMP", "ENA", "MORPHO", "PENDLE", "GMX", "CAKE", "AERO", "VELO",
    "CVX", "HYPE",
}

# Famous chain-agnostic infrastructure constants not yet in names.json. Same
# address on every supported chain (deterministic / Nick's-method deploys).
CHAIN_AGNOSTIC_ADDS = [
    {"address": "0xcA11bde05977b3631167028862bE2a173976CA11", "name": "Multicall3"},
    {"address": "0x000000000022D473030F116dDEE9F6B43aC78BA3", "name": "Uniswap Permit2"},
]


def name_ok(name: str) -> bool:
    b = name.encode("ascii", "ignore")
    return 0 < len(b) <= NAME_MAX_BYTES and all(0x20 <= c <= 0x7E for c in b)


def sanitize_name(s: str) -> str:
    """Reduce a token name to ≤32 bytes of printable ASCII (the names-DB
    constraint), collapsing whitespace. Returns '' if nothing renderable
    remains."""
    if not isinstance(s, str):
        return ""
    kept = "".join(c for c in s if 0x20 <= ord(c) <= 0x7E)
    kept = " ".join(kept.split())
    return kept.encode("ascii", "ignore")[:NAME_MAX_BYTES].decode("ascii").strip()


def main() -> int:
    erc20 = json.loads(ERC20_PATH.read_text())
    existing = json.loads(NAMES_PATH.read_text())

    # Index existing entries; (chain_id or 0, addr_lower) is the key.
    existing_keys: set[tuple[int, str]] = set()
    for e in existing:
        cid = int(e.get("chain_id", 0) or 0)
        existing_keys.add((cid, e["address"].lower()))

    # Per (chain, symbol_upper) → list of full ERC-20 rows, from the vetted DB.
    by_chain_symbol: dict[tuple[int, str], list[dict]] = defaultdict(list)
    for t in erc20:
        cid = int(t["chain_id"])
        if cid not in TARGET_CHAINS:
            continue
        by_chain_symbol[(cid, t["symbol"].upper())].append(t)

    additions: list[dict] = []
    skipped_ambiguous = 0
    for cid in TARGET_CHAINS:
        for sym in SYMBOL_ALLOWLIST:
            rows = by_chain_symbol.get((cid, sym))
            if not rows:
                continue
            if len(rows) > 1:
                # Ambiguous ticker on this chain (bridged variant or worse) —
                # don't risk labeling the wrong contract as a blue chip.
                skipped_ambiguous += 1
                continue
            row = rows[0]
            addr = row["address"]
            key = (cid, addr.lower())
            if key in existing_keys:
                continue  # already named (curated entry wins)
            # Name comes from the token's OWN authoritative ERC-20 row, never a
            # hardcoded per-symbol label — so a reused ticker is always labeled
            # with its real token name (no mislabeling).
            name = sanitize_name(row.get("name", "")) or sym
            if not name_ok(name):
                continue
            additions.append({"chain_id": cid, "address": addr, "name": name})
            existing_keys.add(key)

    chain_agnostic_added = 0
    for c in CHAIN_AGNOSTIC_ADDS:
        if (0, c["address"].lower()) in existing_keys:
            continue
        if not name_ok(c["name"]):
            continue
        additions.append({"address": c["address"], "name": c["name"]})
        existing_keys.add((0, c["address"].lower()))
        chain_agnostic_added += 1

    # Emit existing entries verbatim, then the new entries (token-contract
    # names grouped by chain, then chain-agnostic constants).
    def fmt(e: dict) -> str:
        return "  " + json.dumps(e, ensure_ascii=False, separators=(", ", ": "))

    additions.sort(key=lambda a: (a.get("chain_id", 0), a["name"]))
    all_entries = existing + additions
    body = ",\n".join(fmt(e) for e in all_entries)
    NAMES_PATH.write_text("[\n" + body + "\n]\n", encoding="utf-8")

    print(f"existing: {len(existing)}  +token-contracts: {len(additions) - chain_agnostic_added}"
          f"  +chain-agnostic: {chain_agnostic_added}  (skipped {skipped_ambiguous} ambiguous)",
          file=sys.stderr)
    print(f"==> names.json now has {len(all_entries)} entries", file=sys.stderr)
    # Per-chain summary.
    counts: dict[int, int] = defaultdict(int)
    for e in all_entries:
        counts[int(e.get("chain_id", 0) or 0)] += 1
    for cid in sorted(counts):
        label = "chain-agnostic" if cid == 0 else f"chain {cid}"
        print(f"      {label:16s}: {counts[cid]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
