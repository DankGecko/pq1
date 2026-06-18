#!/usr/bin/env python3
"""Screen the PQ1 ERC-20 db for DEAD / inactive tokens via Alchemy.

Signal: a recent-window transfer count. There is no RPC that returns a token's
transfer total (it isn't stored on-chain) — you count Transfer events. We use
alchemy_getAssetTransfers (category erc20, one contract, fromBlock = now - N
days) and read the first page: a dead/abandoned token returns a handful (or
zero) transfers in the window; a live token immediately hits the cap. Low
recent activity is a strong "likely dead/scam" lead (NOT proof — a legit but
quiet small-cap also looks quiet).

Multichain via Alchemy's per-network URL: https://<net>.g.alchemy.com/v2/<key>.
Set the key in the environment:  export ALCHEMY_API_KEY=...

Cost / behavior:
  * One getAssetTransfers call per token (first page, maxCount 1000). A token
    with >= --active-cap transfers in the window is marked ACTIVE without
    paging further — cheap.
  * Rate-limited + 429-backoff; JSON-RPC batched to cut round-trips.
  * Fully RESUMABLE: every token's verdict is appended to a checkpoint JSONL;
    re-running skips what's done.

All 10 PQ1 chains are Alchemy networks (Hyperliquid via hyperliquid-mainnet).

Examples:
    export ALCHEMY_API_KEY=xxxx
    tools/scan_erc20_alchemy_activity.py --probe            # sanity-check key on USDC + a dead token
    tools/scan_erc20_alchemy_activity.py --chain 1 --limit 200 --days 30
    tools/scan_erc20_alchemy_activity.py --days 30          # whole db

Outputs (under --out-dir, default build/alchemy_activity/):
    activity.jsonl            every token + recent count + status   (checkpoint)
    dead.json                 tokens with 0 transfers in the window
    low_activity.json         tokens with < --low-threshold transfers
    activity.md               summary + per-chain distribution
    dead_addresses.txt        drop-candidate list (0 transfers in window)
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict, Counter

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Alchemy network subdomains for the PQ1 db chains (all 10).
SUBDOMAIN = {
    1: "eth-mainnet", 10: "opt-mainnet", 56: "bnb-mainnet",
    130: "unichain-mainnet", 137: "polygon-mainnet", 8453: "base-mainnet",
    42161: "arb-mainnet", 43114: "avax-mainnet", 59144: "linea-mainnet",
    999: "hyperliquid-mainnet",
}
# Approx seconds/block, to turn --days into a block window per chain. Err on the
# low side (=> slightly LARGER window than requested), which is the safe bias
# for a dead-token signal. HyperEVM small-block cadence ~1s.
BLOCK_TIME = {
    1: 12.0, 10: 2.0, 56: 3.0, 130: 1.0, 137: 2.1,
    8453: 2.0, 42161: 0.25, 43114: 2.0, 59144: 3.0, 999: 1.0,
}
CHAIN_NAMES = {
    1: "Ethereum", 10: "Optimism", 56: "BNB Chain", 130: "Unichain",
    137: "Polygon", 8453: "Base", 42161: "Arbitrum", 43114: "Avalanche",
    59144: "Linea", 999: "Hyperliquid",
}


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def alchemy_url(chain_id, api_key):
    return f"https://{SUBDOMAIN[chain_id]}.g.alchemy.com/v2/{api_key}"


def rpc(url, payload, timeout, retries):
    """POST a JSON-RPC payload (single obj or batch list). Returns parsed JSON.
    Retries network errors + HTTP 429/5xx with exponential backoff."""
    data = json.dumps(payload).encode("utf-8")
    backoff = 1.0
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={"Content-Type": "application/json",
                         "User-Agent": "pq1-activity-scan/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in (429, 500, 502, 503, 504):
                raise
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as e:
            last = str(e)
        if attempt < retries:
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
    raise RuntimeError(f"rpc failed after retries: {last}")


def latest_block(url, timeout, retries):
    r = rpc(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber",
                  "params": []}, timeout, retries)
    return int(r["result"], 16)


def transfers_request(req_id, address, from_block_hex, active_cap):
    return {
        "jsonrpc": "2.0", "id": req_id, "method": "alchemy_getAssetTransfers",
        "params": [{
            "fromBlock": from_block_hex,
            "toBlock": "latest",
            "contractAddresses": [address],
            "category": ["erc20"],
            "maxCount": hex(active_cap),
            "excludeZeroValue": False,
            "withMetadata": False,
            "order": "desc",
        }],
    }


def parse_transfers_result(obj, active_cap):
    """Return (count, active, status, message)."""
    if "error" in obj:
        msg = str(obj["error"].get("message", obj["error"]))
        return (None, None, "error", msg)
    res = obj.get("result") or {}
    transfers = res.get("transfers") or []
    count = len(transfers)
    active = bool(res.get("pageKey")) or count >= active_cap
    return (count, active, "ok", None)


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def load_checkpoint(path):
    done = {}
    if not os.path.exists(path):
        return done
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            done[(rec.get("chain_id"), str(rec.get("address", "")).lower())] = rec
    return done


def run_probe(api_key, days, active_cap, timeout, retries):
    print("Probe: USDC (very active) + a random dead address on Ethereum.\n")
    url = alchemy_url(1, api_key)
    latest = latest_block(url, timeout, retries)
    frm = hex(max(0, latest - int(days * 86400 / BLOCK_TIME[1])))
    cases = [("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
             ("zero-ish", "0x000000000000000000000000000000000000dEaD")]
    batch = [transfers_request(i, a, frm, active_cap) for i, (_, a) in enumerate(cases)]
    out = rpc(url, batch, timeout, retries)
    out = sorted(out, key=lambda o: o["id"])
    for (label, addr), o in zip(cases, out):
        count, active, status, msg = parse_transfers_result(o, active_cap)
        print(f"  {label:9s} {addr}")
        print(f"    window={days}d  count={count}  active={active}  status={status}"
              + (f"  msg={msg}" if msg else ""))
    print("\nProbe OK — key works." if all("error" not in o for o in out)
          else "\nProbe had errors — check the key/plan.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=None)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--api-key", default=os.environ.get("ALCHEMY_API_KEY"))
    ap.add_argument("--days", type=float, default=30.0,
                    help="recent window length in days (default 30)")
    ap.add_argument("--active-cap", type=int, default=1000,
                    help="stop counting at this many; >= cap = ACTIVE (Alchemy max 1000)")
    ap.add_argument("--low-threshold", type=int, default=3,
                    help="tokens with < this many transfers in the window go in low_activity.json")
    ap.add_argument("--rps", type=float, default=5.0, help="HTTP POSTs per second (each carries --batch calls)")
    ap.add_argument("--batch", type=int, default=20, help="JSON-RPC calls per HTTP POST")
    ap.add_argument("--chain", type=int, action="append", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=40.0)
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--no-resume", action="store_true")
    args = ap.parse_args()

    if not args.api_key:
        sys.exit("error: no Alchemy key. `export ALCHEMY_API_KEY=...` or pass --api-key.")
    active_cap = max(1, min(args.active_cap, 1000))

    if args.probe:
        run_probe(args.api_key, args.days, active_cap, args.timeout, args.retries)
        return

    root = repo_root()
    input_path = args.input or os.path.join(root, "secure", "data", "erc20.json")
    out_dir = args.out_dir or os.path.join(root, "build", "alchemy_activity")
    os.makedirs(out_dir, exist_ok=True)
    checkpoint_path = os.path.join(out_dir, "activity.jsonl")

    with open(input_path, encoding="utf-8") as fh:
        db = json.load(fh)
    if args.chain:
        chains = set(args.chain)
        db = [t for t in db if t.get("chain_id") in chains]
    if args.limit is not None:
        db = db[:args.limit]

    done = {} if args.no_resume else load_checkpoint(checkpoint_path)
    if done:
        print(f"Resuming: {len(done)} tokens already in checkpoint.")

    by_chain = defaultdict(list)
    skipped_unsupported = 0
    for t in db:
        cid = t.get("chain_id")
        if cid not in SUBDOMAIN:
            skipped_unsupported += 1
            continue
        if (cid, str(t.get("address", "")).lower()) in done:
            continue
        by_chain[cid].append(t)
    if skipped_unsupported:
        print(f"Skipping {skipped_unsupported} tokens on Alchemy-unsupported chains "
              f"(no subdomain mapped).")

    todo = sum(len(v) for v in by_chain.values())
    min_interval = 1.0 / args.rps if args.rps > 0 else 0.0
    est_min = (todo / max(args.batch, 1)) * min_interval / 60.0
    print(f"{todo} tokens to query (~{est_min:.0f} min at {args.rps} posts/s x {args.batch}/post).")

    mode = "w" if args.no_resume else "a"
    ckpt = open(checkpoint_path, mode, encoding="utf-8")
    records = list(done.values())

    next_t = 0.0
    n_dead = sum(1 for r in records if r.get("count") == 0)
    n_done = 0
    try:
        for cid in sorted(by_chain):
            url = alchemy_url(cid, args.api_key)
            try:
                latest = latest_block(url, args.timeout, args.retries)
            except Exception as e:  # noqa: BLE001
                print(f"  chain {cid}: eth_blockNumber failed ({e}); skipping chain.")
                continue
            from_hex = hex(max(0, latest - int(args.days * 86400 / BLOCK_TIME[cid])))
            print(f"  chain {cid} {CHAIN_NAMES.get(cid,'')}: latest={latest}, "
                  f"window from block {int(from_hex,16)} ({args.days}d).")

            for group in chunked(by_chain[cid], args.batch):
                now = time.monotonic()
                if now < next_t:
                    time.sleep(next_t - now)
                next_t = time.monotonic() + min_interval

                batch = [transfers_request(i, t["address"], from_hex, active_cap)
                         for i, t in enumerate(group)]
                try:
                    out = rpc(url, batch, args.timeout, args.retries)
                except Exception as e:  # noqa: BLE001
                    print(f"    batch failed ({e}); marking group as error.")
                    out = [{"id": i, "error": {"message": str(e)}} for i in range(len(group))]
                by_id = {o.get("id"): o for o in out} if isinstance(out, list) else {0: out}

                for i, t in enumerate(group):
                    count, active, status, msg = parse_transfers_result(
                        by_id.get(i, {"error": {"message": "missing"}}), active_cap)
                    rec = {
                        "chain_id": cid, "address": t["address"],
                        "symbol": t.get("symbol"), "name": t.get("name"),
                        "window_days": args.days, "count": count,
                        "active": active, "status": status, "message": msg,
                    }
                    ckpt.write(json.dumps(rec) + "\n")
                    records.append(rec)
                    n_done += 1
                    if count == 0 and status == "ok":
                        n_dead += 1
                ckpt.flush()
                if n_done % 500 == 0:
                    print(f"    ...{n_done}/{todo} done, {n_dead} with 0 transfers in window")
    except KeyboardInterrupt:
        print("\nInterrupted — checkpoint saved; re-run to resume.")
    finally:
        ckpt.close()

    write_reports(records, out_dir, args.days, args.low_threshold)


def write_reports(records, out_dir, days, low_threshold):
    ok = [r for r in records if r.get("status") == "ok"]
    dead = [r for r in ok if r.get("count") == 0]
    low = [r for r in ok if r.get("count") is not None and r["count"] < low_threshold]
    errored = [r for r in records if r.get("status") == "error"]
    dead.sort(key=lambda r: (r["chain_id"], r["address"]))
    low.sort(key=lambda r: (r["chain_id"], r.get("count", 0), r["address"]))

    with open(os.path.join(out_dir, "dead.json"), "w", encoding="utf-8") as fh:
        json.dump(dead, fh, indent=2); fh.write("\n")
    with open(os.path.join(out_dir, "low_activity.json"), "w", encoding="utf-8") as fh:
        json.dump(low, fh, indent=2); fh.write("\n")
    with open(os.path.join(out_dir, "dead_addresses.txt"), "w", encoding="utf-8") as fh:
        for r in dead:
            fh.write(f'{r["chain_id"]} {r["address"]}  # {r.get("symbol","")} '
                     f'"{r.get("name","")}" 0 transfers in {days:g}d\n')

    lines = ["# Alchemy recent-activity screen", ""]
    lines.append(f"Window: last **{days:g} days**. Scanned {len(records)} tokens "
                 f"({len(ok)} ok, {len(errored)} errored).")
    lines.append("")
    lines.append(f"- **{len(dead)}** tokens had **0** transfers in the window (strongest dead signal).")
    lines.append(f"- **{len(low)}** had **< {low_threshold}** transfers.")
    lines.append("")
    lines.append("Per-chain (ok tokens) — 0-transfer / total:")
    lines.append("")
    per = defaultdict(lambda: [0, 0])
    for r in ok:
        per[r["chain_id"]][1] += 1
        if r["count"] == 0:
            per[r["chain_id"]][0] += 1
    lines.append("| chain | 0-transfer | total |")
    lines.append("|---|---|---|")
    for cid in sorted(per):
        d, tot = per[cid]
        lines.append(f"| {CHAIN_NAMES.get(cid, cid)} ({cid}) | {d} | {tot} |")
    lines.append("")
    lines.append("`dead_addresses.txt` is a drop-candidate list — but zero recent "
                 "activity is a LEAD, not proof (a quiet legit small-cap looks the same). "
                 "Review before dropping.")
    with open(os.path.join(out_dir, "activity.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"\nDone. {len(dead)} dead (0 transfers/{days:g}d), {len(low)} low, "
          f"{len(errored)} errored, of {len(records)} scanned.")
    print(f"Reports in {out_dir}: activity.md, dead.json, low_activity.json, dead_addresses.txt")


if __name__ == "__main__":
    main()
