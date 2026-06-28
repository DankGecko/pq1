#!/usr/bin/env python3
"""
verify_erc20_decimals.py — cross-check every token in the ERC-20 metadata DBs
against its on-chain `decimals()` and correct the DB in place.

WHY THIS EXISTS
---------------
`tools/build_erc20_db.py` takes each token's `decimals` VERBATIM from
third-party token lists (CoinGecko / Li.Fi / 1inch / Sushi / Uniswap). When a
list is wrong and the DB `decimals` is LARGER than the true on-chain value,
the firmware renders `amount / 10^decimals` too small — a full-balance drain
shows on the OLED as dust (e.g. FLUX/MEME shipped as 18, real value 8 ⇒
10^10x understatement). See docs/VULN-erc20-decimals-inflation-flux-meme.md.
This tool is the on-chain `decimals()` gate that the DB build never had.

ROBUSTNESS
----------
Each chain has a POOL of public RPC endpoints. A batch that hits a rate-limit
(HTTP 429/503), a forbidden/whitelist error, a timeout, or a connection drop
is transparently retried on the NEXT endpoint in the pool; rate-limited
endpoints cool down, hard-dead ones are dropped for the run. Batches a node
rejects as "too large" are split in half recursively down to single calls.
Tokens still unresolved after the first pass are retried in additional passes.
A `decimals` value is only ever written when an RPC actually returned it.

USAGE
-----
  # report only (no writes), built-in public RPC pools:
  python3 tools/verify_erc20_decimals.py

  # correct BOTH DBs and regenerate the firmware root:
  python3 tools/verify_erc20_decimals.py --fix --all-dbs
  cargo run -p dbgen        # regenerates ERC20_DB_ROOT(_E2E) in db_roots.rs

  # use your own endpoints (overrides/extends the built-in pool):
  python3 tools/verify_erc20_decimals.py --init-rpc-config
  $EDITOR tools/erc20_rpc.json    # chain_id -> URL or [URLs]

Stdlib only (urllib) — no pip deps, matching the other tools/ scripts.
"""

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DB_PATH = REPO / "secure" / "data" / "erc20.json"
E2E_DB_PATH = REPO / "secure" / "data" / "erc20-e2e.json"
RPC_CONFIG_PATH = REPO / "tools" / "erc20_rpc.json"

# decimals()  ->  keccak256("decimals()")[:4]
DECIMALS_SELECTOR = "0x313ce567"
# A selector no real ERC-20 implements. A standards-compliant token REVERTS on
# it (eth_call -> "0x"); a non-standard contract with a constant-returning
# fallback (e.g. the 2016 TheDAO) returns the SAME word it returns for
# decimals(). If a probe selector yields the same value, the decimals() reading
# is a fallback artifact, NOT real metadata — we refuse to trust it.
PROBE_SELECTOR = "0xdeadbeef"

# bundle.rs MAX_DISPLAY_DECIMALS: the on-device verifier REJECTS decimals > 36
# (a rejected entry fails safe to AddrHex/raw, it does not mis-render).
MAX_DISPLAY_DECIMALS = 36
MAX_U8 = 255  # dbgen stores decimals as a single byte

CHAIN_NAMES = {
    1: "ethereum", 10: "optimism", 56: "bnb-chain", 130: "unichain",
    137: "polygon", 999: "hyperevm", 8453: "base", 42161: "arbitrum",
    43114: "avalanche", 59144: "linea",
}

# Built-in pools of keyless public RPC endpoints, multiple per chain so a
# rate-limited or dead node fails over to the next. Dead/whitelist-restricted
# endpoints are dropped automatically at run time.
DEFAULT_RPC_POOL = {
    1: ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com",
        "https://eth-mainnet.public.blastapi.io", "https://eth.drpc.org",
        "https://eth.merkle.io", "https://1rpc.io/eth", "https://rpc.mevblocker.io"],
    10: ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io",
         "https://optimism.llamarpc.com", "https://op-mainnet.public.blastapi.io",
         "https://optimism.drpc.org", "https://1rpc.io/op"],
    56: ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org",
         "https://bsc-dataseed1.defibit.io", "https://bsc-dataseed1.ninicoin.io",
         "https://binance.llamarpc.com", "https://bsc.drpc.org", "https://1rpc.io/bnb"],
    130: ["https://unichain-rpc.publicnode.com", "https://mainnet.unichain.org",
          "https://unichain.drpc.org", "https://0xrpc.io/uni"],
    137: ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com",
          "https://polygon.llamarpc.com", "https://polygon-mainnet.public.blastapi.io",
          "https://polygon.drpc.org", "https://1rpc.io/matic"],
    999: ["https://rpc.hyperliquid.xyz/evm", "https://hyperliquid.drpc.org",
          "https://rpc.hypurrscan.io"],
    8453: ["https://base-rpc.publicnode.com", "https://mainnet.base.org",
           "https://base.llamarpc.com", "https://base-mainnet.public.blastapi.io",
           "https://base.drpc.org", "https://1rpc.io/base"],
    42161: ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc",
            "https://arbitrum.llamarpc.com", "https://arbitrum-one.public.blastapi.io",
            "https://arbitrum.drpc.org", "https://1rpc.io/arb"],
    43114: ["https://avalanche-c-chain-rpc.publicnode.com",
            "https://api.avax.network/ext/bc/C/rpc", "https://avalanche.drpc.org",
            "https://avax.meowrpc.com", "https://1rpc.io/avax"],
    59144: ["https://linea-rpc.publicnode.com", "https://rpc.linea.build",
            "https://linea.drpc.org", "https://1rpc.io/linea"],
}


def rel(p):
    """Path relative to the repo for display, or the bare path if outside it."""
    try:
        return Path(p).resolve().relative_to(REPO)
    except ValueError:
        return Path(p)


# --------------------------------------------------------------------------- #
# RPC config
# --------------------------------------------------------------------------- #
def init_rpc_config():
    template = {"_comment": "chain_id -> JSON-RPC URL or list of URLs. Empty = use "
                            "built-in public pool. Do not commit secret RPC keys."}
    template.update({str(cid): "" for cid in sorted(DEFAULT_RPC_POOL)})
    if RPC_CONFIG_PATH.exists():
        print(f"refusing to overwrite existing {rel(RPC_CONFIG_PATH)}", file=sys.stderr)
        return 1
    RPC_CONFIG_PATH.write_text(json.dumps(template, indent=2) + "\n")
    print(f"wrote template {rel(RPC_CONFIG_PATH)} — fill in URLs (or leave blank "
          f"to use the built-in public pool)")
    return 0


def load_pools(path):
    """chain_id -> [urls]. Starts from the built-in pool; config entries (str or
    list) PREPEND the user's endpoints for that chain."""
    pools = {cid: list(urls) for cid, urls in DEFAULT_RPC_POOL.items()}
    cfg = {}
    if path.exists():
        raw = json.loads(path.read_text())
        for k, v in raw.items():
            try:
                cid = int(k)
            except ValueError:
                continue
            urls = [v] if isinstance(v, str) else list(v)
            urls = [u for u in urls if u]
            if urls:
                cfg[cid] = urls
    for k, v in os.environ.items():
        if k.startswith("ERC20_RPC_") and v:
            try:
                cfg[int(k[len("ERC20_RPC_"):])] = [u for u in v.split(",") if u]
            except ValueError:
                pass
    for cid, urls in cfg.items():
        existing = pools.get(cid, [])
        pools[cid] = urls + [u for u in existing if u not in urls]
    return pools


# --------------------------------------------------------------------------- #
# RPC layer with endpoint failover
# --------------------------------------------------------------------------- #
class RpcError(Exception):
    def __init__(self, cat, msg):
        super().__init__(msg)
        self.cat = cat          # 'ratelimit' | 'toobig' | 'fatal' | 'transient'


class BatchTooBig(Exception):
    pass


class AllEndpointsDown(Exception):
    pass


class Pool:
    """Thread-safe rotating endpoint pool with per-endpoint cooldown / kill."""

    def __init__(self, urls):
        self.urls = list(urls)
        self.lock = threading.Lock()
        self.cool = {}          # url -> monotonic deadline
        self.dead = set()
        self.rr = 0

    def pick(self):
        with self.lock:
            n = len(self.urls)
            now = time.monotonic()
            for _ in range(n):
                url = self.urls[self.rr % n]
                self.rr += 1
                if url in self.dead:
                    continue
                if self.cool.get(url, 0) > now:
                    continue
                return url, 0.0
            live = [u for u in self.urls if u not in self.dead]
            if not live:
                return None, -1.0
            wait = min(self.cool.get(u, 0) for u in live) - now
            return None, max(wait, 0.5)

    def cooldown(self, url, secs):
        with self.lock:
            self.cool[url] = time.monotonic() + secs

    def kill(self, url):
        with self.lock:
            self.dead.add(url)

    def status(self):
        with self.lock:
            return len(self.urls) - len(self.dead), len(self.dead)


def rpc_batch(url, calls, timeout, selector=DECIMALS_SELECTOR):
    """One JSON-RPC batch eth_call. Returns id->result-hex-or-None, or raises
    RpcError(category) on a whole-batch failure."""
    payload = [
        {"jsonrpc": "2.0", "id": cid, "method": "eth_call",
         "params": [{"to": addr, "data": selector}, "latest"]}
        for cid, addr in calls
    ]
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0 erc20-decimals-verify/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (429, 503, 509, 502):
            raise RpcError("ratelimit", f"HTTP {e.code}")
        if e.code in (413, 400):
            raise RpcError("toobig", f"HTTP {e.code}")
        if e.code in (401, 403, 404, 405):
            raise RpcError("fatal", f"HTTP {e.code}")
        raise RpcError("transient", f"HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        raise RpcError("transient", str(e))

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise RpcError("transient", f"bad json: {raw[:100]!r}")

    if isinstance(data, dict):  # node rejected the batch with one error object
        msg = str(data.get("error", data)).lower()
        if any(s in msg for s in ("too large", "batch", "exceed", "limit", "many")):
            raise RpcError("toobig", msg[:120])
        if any(s in msg for s in ("whitelist", "not allowed", "unauthorized", "api key")):
            raise RpcError("fatal", msg[:120])
        raise RpcError("transient", msg[:120])

    out = {}
    err_msgs = []
    for item in data:
        rid = item.get("id")
        if "result" in item and item["result"] not in (None, "0x", ""):
            out[rid] = item["result"]
        else:
            out[rid] = None
            if "error" in item:
                err_msgs.append(str(item["error"]).lower())
    for cid, _ in calls:
        out.setdefault(cid, None)
    # if EVERY element failed and the errors look like rate-limit/whitelist, the
    # endpoint is the problem — fail over instead of marking real tokens dead.
    if err_msgs and all(v is None for v in out.values()):
        joined = " ".join(err_msgs)
        if any(s in joined for s in ("limit", "many", "exceed", "capacity")):
            raise RpcError("ratelimit", joined[:120])
        if any(s in joined for s in ("whitelist", "not allowed", "unauthorized", "api key")):
            raise RpcError("fatal", joined[:120])
    return out


def batch_with_failover(pool, calls, timeout, max_attempts, selector=DECIMALS_SELECTOR):
    attempts = 0
    while True:
        url, wait = pool.pick()
        if url is None:
            if wait < 0:
                raise AllEndpointsDown()
            time.sleep(min(wait, 5.0))
            continue
        try:
            return rpc_batch(url, calls, timeout, selector)
        except BatchTooBig:
            raise
        except RpcError as e:
            if e.cat == "toobig":
                raise BatchTooBig()
            if e.cat == "ratelimit":
                pool.cooldown(url, 20.0)
            elif e.cat == "fatal":
                pool.kill(url)
            else:
                pool.cooldown(url, 4.0)
            attempts += 1
            if attempts >= max_attempts:
                raise AllEndpointsDown()


def decode_decimals(result_hex):
    """Decode a uint return into a decimals int. ABI puts the value in the FIRST
    32-byte word; some non-standard contracts (Curve LP proxies, etc.) return
    extra trailing words, so we must NOT int-parse the whole blob (that yields a
    huge number that we'd wrongly reject). Take the first word only."""
    if not result_hex:
        return None
    h = result_hex[2:] if result_hex.startswith("0x") else result_hex
    if not h:
        return None
    word = h[:64] if len(h) >= 64 else h  # first 32-byte word (or short return)
    try:
        v = int(word, 16)
    except ValueError:
        return None
    return v if 0 <= v <= MAX_U8 else None  # >u8 can't be stored → unresolved


# --------------------------------------------------------------------------- #
# per-chain resolution
# --------------------------------------------------------------------------- #
def resolve_chain(cid, items, pool, batch_size, workers, timeout, progress,
                  selector=DECIMALS_SELECTOR):
    """items: list of (global_index, address). Returns {global_index: decimals|None}."""
    results = {}

    def do(calls):
        try:
            res = batch_with_failover(pool, calls, timeout,
                                      max_attempts=len(pool.urls) * 4 + 8, selector=selector)
        except BatchTooBig:
            if len(calls) == 1:
                return {calls[0][0]: None}
            mid = len(calls) // 2
            r = do(calls[:mid])
            r.update(do(calls[mid:]))
            return r
        except AllEndpointsDown:
            return {c: None for c, _ in calls}
        return {c: decode_decimals(res.get(c)) for c, _ in calls}

    batches = [items[b:b + batch_size] for b in range(0, len(items), batch_size)]
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(do, b): b for b in batches}
        for fut in as_completed(futs):
            results.update(fut.result())
            done += 1
            live, dead = pool.status()
            progress(cid, done, len(batches), live, dead)
    return results


def verify_db(db, pools, args):
    """Returns (matches, mismatches, unresolved). Mutates nothing."""
    by_chain = {}
    for i, t in enumerate(db):
        by_chain.setdefault(t["chain_id"], []).append((i, t))

    onchain = {}  # global_index -> decimals|None
    for cid in sorted(by_chain):
        if args.chains and cid not in args.chains:
            continue
        toks = by_chain[cid]
        urls = pools.get(cid)
        name = CHAIN_NAMES.get(cid, str(cid))
        if not urls:
            print(f"  chain {cid:6d} {name:12s}: SKIP (no endpoints), {len(toks)} tokens",
                  file=sys.stderr)
            for idx, _ in toks:
                onchain[idx] = None
            continue
        pool = Pool(urls)

        def progress(c, done, total, live, dead):
            print(f"\r  chain {c:6d} {name:12s}: {done}/{total} batches  "
                  f"[{live} live / {dead} dead endpoints]   ", end="", file=sys.stderr)

        idx_addr = [(idx, t["address"]) for idx, t in toks]
        res = resolve_chain(cid, idx_addr, pool, args.batch_size, args.workers,
                            args.timeout, progress)
        # extra passes for stragglers (None) — fresh pool, smaller batches
        for p in range(args.passes - 1):
            pending = [(idx, t["address"]) for idx, t in toks if res.get(idx) is None]
            if not pending:
                break
            print(f"\n  chain {cid:6d} {name:12s}: retry pass {p + 2} "
                  f"on {len(pending)} unresolved", file=sys.stderr)
            pool2 = Pool(urls)
            bs = max(10, args.batch_size // (2 * (p + 1)))
            res.update(resolve_chain(cid, pending, pool2, bs, max(2, args.workers // 2),
                                     args.timeout, progress))
        onchain.update(res)
        resolved = sum(1 for idx, _ in toks if res.get(idx) is not None)
        print(f"\n  chain {cid:6d} {name:12s}: resolved {resolved}/{len(toks)}",
              file=sys.stderr)

    matches, mismatches, unresolved = 0, [], []
    for i, t in enumerate(db):
        if args.chains and t["chain_id"] not in args.chains:
            continue
        oc = onchain.get(i)
        if oc is None:
            unresolved.append((i, t))
        elif oc == t["decimals"]:
            matches += 1
        else:
            mismatches.append((i, t, t["decimals"], oc))
    return matches, mismatches, unresolved


def report(label, matches, mismatches, unresolved):
    print(f"\n========== {label} ==========")
    print(f"  matched    : {matches}")
    print(f"  MISMATCHED : {len(mismatches)}")
    print(f"  unresolved : {len(unresolved)}  (left untouched)")
    hiding = sorted([m for m in mismatches if m[2] > m[3]],
                    key=lambda m: m[2] - m[3], reverse=True)
    over = [m for m in mismatches if m[2] < m[3]]
    if mismatches:
        print(f"  of which   : {len(hiding)} magnitude-HIDING (DB>chain, drain risk), "
              f"{len(over)} over-stating (DB<chain)")
        for idx, t, dbd, oc in hiding[:60]:
            flag = "  <-- >MAX_DISPLAY_DECIMALS" if oc > MAX_DISPLAY_DECIMALS else ""
            print(f"    chain {t['chain_id']:<6} {t['symbol']:<14} {t['address']}  "
                  f"DB={dbd:<3} chain={oc:<3} hides 1e{dbd - oc}{flag}")
        if len(hiding) > 60:
            print(f"    ... and {len(hiding) - 60} more hiding")
        for idx, t, dbd, oc in over[:20]:
            print(f"    chain {t['chain_id']:<6} {t['symbol']:<14} {t['address']}  "
                  f"DB={dbd:<3} chain={oc:<3} (over-states)")


def confirm_mismatches(db, mismatches, pools, args):
    """Re-query every would-be-changed token on a FRESH pool and require the
    second reading to agree before we overwrite. Guards against a single flaky
    endpoint corrupting an entry that was actually correct. Returns
    (confirmed, conflicts) where confirmed entries are safe to write."""
    by_chain = {}
    for tup in mismatches:
        by_chain.setdefault(tup[1]["chain_id"], []).append(tup)
    confirmed, conflicts = [], []
    for cid, tups in sorted(by_chain.items()):
        urls = pools.get(cid)
        if not urls:
            conflicts.extend(tups)
            continue
        pool = Pool(urls)
        idx_addr = [(idx, t["address"]) for idx, t, _d, _o in tups]
        print(f"\r  confirming {len(idx_addr)} changes on chain {cid} "
              f"({CHAIN_NAMES.get(cid, cid)})...        ", end="", file=sys.stderr)
        bs, wk = max(10, args.batch_size // 2), max(2, args.workers // 2)
        # 2nd independent decimals() reading
        res = resolve_chain(cid, idx_addr, pool, bs, wk, args.timeout, lambda *a: None)
        # bogus-selector probe: a constant-returning fallback (TheDAO class) yields
        # the same value here; a standards-compliant token reverts -> None.
        probe = resolve_chain(cid, idx_addr, Pool(urls), bs, wk, args.timeout,
                              lambda *a: None, selector=PROBE_SELECTOR)
        for idx, t, dbd, oc in tups:
            again = res.get(idx)
            if again is not None and again == oc and probe.get(idx) != oc:
                confirmed.append((idx, t, dbd, oc))
            else:
                # disagreement OR a probe collision -> do not trust the reading
                tag = again if probe.get(idx) != oc else f"{again}(probe-collision)"
                conflicts.append((idx, t, dbd, tag))
    print(file=sys.stderr)
    return confirmed, conflicts


def write_db(path, db):
    body = [
        "  " + json.dumps(
            {"chain_id": r["chain_id"], "address": r["address"],
             "name": r["name"], "symbol": r["symbol"], "decimals": r["decimals"]},
            ensure_ascii=False, separators=(", ", ": "))
        for r in db
    ]
    path.write_text("[\n" + ",\n".join(body) + "\n]\n", encoding="utf-8")


def process_db(path, pools, args):
    print(f"\n### verifying {rel(path)} ###", file=sys.stderr)
    db = json.loads(path.read_text())
    matches, mismatches, unresolved = verify_db(db, pools, args)
    report(str(rel(path)), matches, mismatches, unresolved)

    if args.report:
        rp = args.report.parent / f"{path.stem}.{args.report.name}"
        rp.write_text(json.dumps({
            "matched": matches,
            "mismatched": [{"chain_id": t["chain_id"], "address": t["address"],
                            "symbol": t["symbol"], "db_decimals": d, "onchain_decimals": o}
                           for _, t, d, o in mismatches],
            "unresolved": [{"chain_id": t["chain_id"], "address": t["address"],
                            "symbol": t["symbol"]} for _, t in unresolved],
        }, indent=2) + "\n")
        print(f"  report -> {rp}")

    if args.fix and mismatches:
        confirmed, conflicts = confirm_mismatches(db, mismatches, pools, args)
        for idx, _t, _d, oc in confirmed:
            db[idx]["decimals"] = oc
        write_db(path, db)
        print(f"  FIXED {len(confirmed)} entries (2-reading-confirmed) -> {rel(path)}")
        if conflicts:
            print(f"  {len(conflicts)} changes NOT applied (2nd reading disagreed / "
                  f"unresolved) — left as-is:")
            for idx, t, dbd, again in conflicts[:30]:
                print(f"    chain {t['chain_id']:<6} {t['symbol']:<14} {t['address']}  "
                      f"DB={dbd} 1st-read≠2nd-read={again}")
            if len(conflicts) > 30:
                print(f"    ... and {len(conflicts) - 30} more")
        return len(confirmed), len(unresolved) + len(conflicts)
    return len(mismatches), len(unresolved)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--init-rpc-config", action="store_true")
    ap.add_argument("--rpc-config", type=Path, default=RPC_CONFIG_PATH)
    ap.add_argument("--db", type=Path, default=DB_PATH)
    ap.add_argument("--all-dbs", action="store_true",
                    help="process both erc20.json and erc20-e2e.json")
    ap.add_argument("--batch-size", type=int, default=60)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--passes", type=int, default=3,
                    help="resolution passes; later passes retry stragglers (default 3)")
    ap.add_argument("--chains", type=str, default="")
    ap.add_argument("--fix", action="store_true")
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    if args.init_rpc_config:
        return init_rpc_config()

    args.chains = {int(c) for c in args.chains.split(",") if c.strip()} if args.chains else None
    pools = load_pools(args.rpc_config)

    paths = [args.db]
    if args.all_dbs:
        paths = [DB_PATH, E2E_DB_PATH]

    total_mis, total_unres = 0, 0
    for p in paths:
        m, u = process_db(p, pools, args)
        total_mis += m
        total_unres += u

    print(f"\n==== TOTAL: {total_mis} mismatched, {total_unres} unresolved ====")
    if args.fix and total_mis:
        print("NEXT: cargo run -p dbgen   # regenerate ERC20_DB_ROOT(_E2E) in db_roots.rs")
    if total_unres:
        print(f"WARNING: {total_unres} entries could not be resolved on-chain and were "
              f"left as-is. Re-run to retry them.")
    # nonzero exit if anything still needs attention
    return 1 if (total_mis and not args.fix) else 0


if __name__ == "__main__":
    sys.exit(main())
