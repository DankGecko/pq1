#!/usr/bin/env python3
"""Triage the Alchemy recent-activity scan into a tiered remove list.

Combines build/alchemy_activity/activity.jsonl (recent transfer counts) with
token provenance from build/token_lists/ (the same curated sources + trust
ranking build_erc20_db.py uses). A 0-transfer count alone is only a lead — a
quiet legit small-cap looks identical to an abandoned scam — so we gate it on
provenance:

  KEEP        active (>= cap) OR has recent transfers OR a blue-chip ticker OR
              CoinGecko-listed. Never dropped on activity alone.
  SAFE_DROP   0 transfers in window AND lowest provenance (only Li.Fi / db-only,
              not CoinGecko, not blue-chip). Dead + barely-sourced = best drops.
  REVIEW      0 transfers but vouched by a curated DEX list (Uniswap/1inch/
              Sushi/...) — probably real but inactive; eyeball before dropping.

Outputs (under --out-dir, default build/alchemy_activity/):
    triage.md               summary + per-chain tier breakdown
    safe_drop.txt           recommended removals  "<chain> <addr>  # ..."
    safe_drop.json          structured
    review.json             dead-but-curated, needs a human look
"""

import argparse
import json
import os
import sys
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_erc20_db as bdb  # noqa: E402

CHAIN_NAMES = {
    1: "Ethereum", 10: "Optimism", 56: "BNB Chain", 130: "Unichain",
    137: "Polygon", 8453: "Base", 42161: "Arbitrum", 43114: "Avalanche",
    59144: "Linea", 999: "Hyperliquid",
}


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_provenance():
    """(chain, addr_lower) -> {'sources': set, 'max_prio': int, 'coingecko': bool}."""
    prov = {}
    for p in sorted(bdb.LISTS_DIR.glob("*.json")):
        stem = p.stem
        prio = bdb._source_priority(stem)
        is_cg = stem.lower().startswith("coingecko")
        try:
            rows = bdb.load_source(p)
        except Exception as e:  # noqa: BLE001
            print(f"  WARN: skipping {stem}: {e}", file=sys.stderr)
            continue
        for (cid, addr, name, sym, dec, source, canon) in rows:
            key = (cid, addr.lower())
            slot = prov.get(key)
            if slot is None:
                prov[key] = {"sources": {stem}, "max_prio": prio, "coingecko": is_cg}
            else:
                slot["sources"].add(stem)
                slot["max_prio"] = max(slot["max_prio"], prio)
                slot["coingecko"] = slot["coingecko"] or is_cg
    return prov


def classify(rec, prov):
    """Return (tier_label, reason, provenance_dict)."""
    cid = rec["chain_id"]
    al = rec["address"].lower()
    sym = str(rec.get("symbol") or "")
    pr = prov.get((cid, al), {"sources": set(), "max_prio": 0, "coingecko": False})

    # Anything with activity is KEEP outright.
    if rec.get("status") != "ok":
        return ("KEEP", "scan-error (not assessed)", pr)
    if rec.get("count", 0) and rec["count"] > 0:
        return ("KEEP", f"{rec['count']} transfers in window", pr)

    # count == 0 below here.
    blue = bdb._tier(sym) < 99
    if blue:
        return ("KEEP", "blue-chip ticker (dead window but protected)", pr)
    if pr["coingecko"]:
        return ("KEEP", "CoinGecko-listed (dead window but protected)", pr)
    if pr["max_prio"] >= 45:
        srcs = ",".join(sorted(pr["sources"]))
        return ("REVIEW", f"0 transfers; curated by {srcs}", pr)
    srcs = ",".join(sorted(pr["sources"])) or "db-only"
    return ("SAFE_DROP", f"0 transfers; low provenance ({srcs})", pr)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--activity", default=None,
                    help="activity.jsonl (default build/alchemy_activity/activity.jsonl)")
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    root = repo_root()
    activity = args.activity or os.path.join(root, "build", "alchemy_activity", "activity.jsonl")
    out_dir = args.out_dir or os.path.dirname(activity)
    os.makedirs(out_dir, exist_ok=True)

    recs = [json.loads(l) for l in open(activity, encoding="utf-8") if l.strip()]
    print(f"Loaded {len(recs)} activity records; building provenance from token lists...")
    prov = build_provenance()

    tiers = defaultdict(list)
    for r in recs:
        tier, reason, pr = classify(r, prov)
        r2 = dict(r)
        r2["reason"] = reason
        r2["sources"] = sorted(pr["sources"])
        r2["max_prio"] = pr["max_prio"]
        r2["coingecko"] = pr["coingecko"]
        tiers[tier].append(r2)

    safe = sorted(tiers["SAFE_DROP"], key=lambda r: (r["chain_id"], r["address"]))
    review = sorted(tiers["REVIEW"], key=lambda r: (r["chain_id"], r["address"]))

    with open(os.path.join(out_dir, "safe_drop.json"), "w") as fh:
        json.dump(safe, fh, indent=2); fh.write("\n")
    with open(os.path.join(out_dir, "review.json"), "w") as fh:
        json.dump(review, fh, indent=2); fh.write("\n")
    with open(os.path.join(out_dir, "safe_drop.txt"), "w") as fh:
        for r in safe:
            fh.write(f'{r["chain_id"]} {r["address"]}  # {r.get("symbol","")} '
                     f'"{r.get("name","")}" {r["reason"]}\n')

    # Summary.
    lines = ["# ERC-20 activity triage", ""]
    lines.append(f"From {len(recs)} tokens (30-day Alchemy transfer screen):")
    lines.append("")
    lines.append(f"- **SAFE_DROP: {len(safe)}** — 0 transfers + low provenance (recommended removals)")
    lines.append(f"- **REVIEW: {len(review)}** — 0 transfers but curated-DEX-listed (eyeball first)")
    lines.append(f"- **KEEP: {len(tiers['KEEP'])}** — active, or blue-chip/CoinGecko-protected")
    lines.append("")
    lines.append("## SAFE_DROP per chain")
    lines.append("")
    lines.append("| chain | safe_drop | review | keep |")
    lines.append("|---|---|---|---|")
    by = lambda lst: Counter(r["chain_id"] for r in lst)
    cs, cr, ck = by(safe), by(review), by(tiers["KEEP"])
    for cid in sorted(set(cs) | set(cr) | set(ck)):
        lines.append(f"| {CHAIN_NAMES.get(cid, cid)} ({cid}) | {cs[cid]} | {cr[cid]} | {ck[cid]} |")
    lines.append("")
    lines.append("`safe_drop.txt` = dead AND only on the least-curated source (Li.Fi/db-only), "
                 "not CoinGecko, not a blue-chip ticker. Highest-confidence removals. "
                 "`review.json` is dead-but-DEX-listed — likely real but inactive.")
    with open(os.path.join(out_dir, "triage.md"), "w") as fh:
        fh.write("\n".join(lines))

    print(f"\nSAFE_DROP {len(safe)} | REVIEW {len(review)} | KEEP {len(tiers['KEEP'])}")
    print(f"Reports in {out_dir}: triage.md, safe_drop.txt, safe_drop.json, review.json")


if __name__ == "__main__":
    main()
