#!/usr/bin/env python3
"""C10-sign FULL FI sweep — naive-parallel, checkpointing, stop-early-safe.

The deferred "full sweep" of `c10_sign_verified_with_progress` that
`fault_sweep_c10_sign.py` doesn't do (it only sweeps the ~30 K-instruction
gate *tail* via one snapshot). This sweeps single-fault injections across the
WHOLE ~6.6 B-instruction real sign+verify+gate, looking for any fault that
releases a FORGEABLE signature.

**Architecture — naive parallel (measured-justified).** `c10_sign_baseline_probe.py`
showed `start_and_fault` runs at native unicorn speed (~73 s/fault, flat across
fault position — no per-instruction Python hook). So each fault is an independent
~73 s emulation from start→RET; we fan them across `mp.Pool` workers, each using a
FRESH emulator per fault (no `context_save`/snapshot reuse → sidesteps the
"100 %-crash trap" the snapshot harness documents). Snapshot-laddering would ~halve
per-fault cost but reintroduces that fragility; naive is robust and the box is fast.

**Stop-early-safe.** Fault positions are emitted in **bit-reversal order** so any
prefix is uniformly spread across the sign timeline — stopping at any time yields a
uniform sweep at the achieved density, not "the first X %". The **skip** model runs
first (canonical FI primitive), then stuck-at-0 / stuck-at-FF. Every result is
flushed to a JSONL checkpoint as it lands, so a hard kill loses nothing — re-run
skips already-covered (model,pos) pairs.

**Outcomes per (model, position):**
  rejected   r0==0           — verify-before-release gate caught it. SAFE.
  clean      r0==1, sig==base— fault had no effect on output. SAFE.
  benign_drop r0==1, 1-byte→0— post-gate sig-write-loop dropped a byte; won't verify. SAFE.
  anomaly    r0==1, sig!=base— NEEDS off-board verify → FORGE (security) or output-corruption (benign).
  crash/hang/short            — not a forge.

**Scope note re the fcee705a FORS-forgery fix (ht_idx binding).** This binary is the
POST-FIX sphincs-c10: the FORS forest is bound to the hypertree leaf position `ht_idx`
(was the ~3000-sig shared-forest key-extraction bug, CWE-347). `ht_idx` is PUBLIC —
it is `read_bits_le(digest, 143, 18)`, a deterministic function of (pk_seed, pk_root, R,
msg), NOT a signature field. A fault that forces `ht_idx→0` in the SIGNER produces FORS
material under the wrong forest; the off-board oracle (`_offboard_verify`, which calls the
UNFAULTED `sca_c10_verify_real`) re-derives the TRUE ht_idx from the digest — exactly as
the on-chain Yul verifier does — so it rejects that sig and the harness correctly classes
it 'rejected'/non-validating, NOT a forge. This is the right verdict: such a sig is equally
unusable on-chain. Consequence: the oracle flags FORGE iff a sig validates under the honest
digest-bound ht_idx, so by construction it cannot MISS a usable ht_idx forgery — but it also
will not (and should not) report a signer-only ht_idx corruption as a finding.
Pre-flight verified GO-WITH-CAVEATS (workflow wf_d0a3640f, 2026-06-02).
Not covered (pre-existing, acceptable for a forgery-release sweep): target uses sk.sign()
not sign_with_shuffle(), and omits the F-18 CFI counter chain — so this audits the
F-1/F-2/F-5 + F-13 gate, not the full production gate.

Run:   donjon-sca run tools/sca/c10_sign_full_sweep.py
Env:   C10_SWEEP_STRIDE (instr between fault positions, default 500_000)
       C10_SWEEP_WORKERS (default cpu_count-2)
       C10_SWEEP_MODELS  (comma list of skip,stuck0,stuckff; default all, skip first)
Out:   tools/sca/out/c10_sign_sweep.jsonl       (per-fault results, append/flush)
       tools/sca/out/c10_sign_sweep_progress.txt(periodic counters)
"""
import os
import sys
import time
import json
import glob
import hashlib
import signal
import multiprocessing as mp

os.environ.setdefault("UC_IGNORE_REG_BREAK", "1")

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(HERE, "c10_sign_target", "target", "thumbv8m.main-none-eabi",
                   "release", "sca-c10-sign-target")
OUT_DIR = os.path.join(HERE, "out")
JSONL = os.path.join(OUT_DIR, "c10_sign_sweep.jsonl")
PROGRESS = os.path.join(OUT_DIR, "c10_sign_sweep_progress.txt")
META = os.path.join(OUT_DIR, "c10_sign_sweep.meta.json")   # binary-provenance sidecar (sha256 guard)

RET = 0xAAAA_AAAA
STACK_TOP = 0x9000_0000
_STACK_LEN = 0x10_000
MSG_ADDR = 0x6000_0000
SIG_ADDR = 0x6000_1000
SIG_LEN = 4008
BUDGET = 10_000_000_000
TEST_MSG = bytes(range(32))
TOTAL_EST = 5_504_700_000          # re-measured 2026-06-22 via bisect against the post-b12d4969
                                   # (R-derivation hardening: grind_r now takes sk_seed) + CT-shuffle
                                   # binary: 5,504,676,080 instr — DOWN 16.9% / -1.12B from the
                                   # pre-hardening 6,622,918,000 (the hash.rs one-shot-sha256 refactor
                                   # + Lemire-shuffle rewrite trimmed the sign). Rounded up so the
                                   # sweep covers the whole function; positions past the true end
                                   # return 'short' (harmless). The .meta.json sha256 guard (below)
                                   # refuses a resume if the target ELF ever changes again.
FN = "sca_c10_sign_verified"

STRIDE = int(os.environ.get("C10_SWEEP_STRIDE", "500000"))
WORKERS = int(os.environ.get("C10_SWEEP_WORKERS", str(max(2, (mp.cpu_count() or 4) - 2))))
MODELS = os.environ.get("C10_SWEEP_MODELS", "skip,stuck0,stuckff").split(",")

# ---- worker globals (set via pool initializer; spawn doesn't inherit) ----
_BASELINE_SIG = None


def _make_model(label):
    # Create the fault-model closure INSIDE the worker, per the harness lesson
    # that module-level stuck-at closures corrupt fault behaviour.
    from rainbow.fault_models import fault_skip, fault_stuck_at
    if label == "skip":
        return fault_skip
    if label == "stuck0":
        return fault_stuck_at(0x0000_0000)
    if label == "stuckff":
        return fault_stuck_at(0xFFFF_FFFF)
    raise ValueError(f"unknown model {label}")


def _fresh():
    from rainbow.generics import rainbow_cortexm
    e = rainbow_cortexm()
    e.load(ELF)
    e.map_space(STACK_TOP - _STACK_LEN, STACK_TOP + 0x20)
    return e


def _setup(e):
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[MSG_ADDR] = TEST_MSG
    e[SIG_ADDR] = b"\x00" * SIG_LEN
    e["r0"] = MSG_ADDR
    e["r1"] = SIG_ADDR
    e["lr"] = RET


def _worker_init(baseline_sig):
    global _BASELINE_SIG
    _BASELINE_SIG = baseline_sig
    # Ignore SIGINT in workers; the parent handles graceful stop.
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _fault_one(task):
    """Independent single-fault emulation. Returns (label, pos, outcome, sighex|None)."""
    from unicorn import UcError
    label, pos = task
    e = _fresh()
    _setup(e)
    model = _make_model(label)
    begin = e.functions[FN][0]
    try:
        e.start_and_fault(model, pos, begin, RET, count=BUDGET)
    except (RuntimeError, UcError):
        return (label, pos, "crash", None)
    except IndexError:
        return (label, pos, "short", None)
    if e["pc"] != RET:
        return (label, pos, "hang", None)
    r0 = e["r0"] & 0xFFFF_FFFF
    if r0 == 0:
        return (label, pos, "rejected", None)
    sig = bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])
    if sig == _BASELINE_SIG:
        return (label, pos, "clean", None)
    diff = [i for i, (a, b) in enumerate(zip(sig, _BASELINE_SIG)) if a != b]
    if len(diff) == 1 and sig[diff[0]] == 0x00:
        return (label, pos, "benign_drop", None)
    return (label, pos, "anomaly", sig.hex())   # ambiguous → parent off-board-verifies


# ---------------------------------------------------------------------------
def _progressive_order(n):
    """Permutation of range(n) whose every prefix is ~uniformly spread, via
    bit-reversal. Lets an early stop still be a uniform sweep."""
    if n <= 1:
        return list(range(n))
    bits = (n - 1).bit_length()
    order, seen = [], set()
    for i in range(1 << bits):
        r = int(format(i, f"0{bits}b")[::-1], 2)
        if r < n and r not in seen:
            seen.add(r)
            order.append(r)
    return order


def _baseline_sig():
    e = _fresh()
    _setup(e)
    begin = e.functions[FN][0]
    e.start(begin, RET, count=BUDGET)
    assert e["pc"] == RET and (e["r0"] & 0xFFFF_FFFF) == 1, "baseline did not cleanly return Ok"
    return bytes(e[SIG_ADDR:SIG_ADDR + SIG_LEN])


def _offboard_verify(sig_bytes):
    """Independent verify of a produced sig via sca_c10_verify_real (same ELF).
    True == the forged sig validates under TEST_MSG → a real forge-release."""
    from unicorn import UcError
    PK_SEED_ADDR, PK_ROOT_ADDR = 0x6010_0000, 0x6010_1000
    MSG_ADDR_OB, SIG_ADDR_OB = 0x6010_2000, 0x6010_3000
    matches = glob.glob(os.path.join(HERE, "c10_sign_target", "target",
                                     "thumbv8m.main-none-eabi", "release", "build",
                                     "sca-c10-sign-target-*", "out", "pk_root.bin"))
    if not matches:
        raise RuntimeError("pk_root.bin not found; rebuild build-c10-sign")
    with open(matches[0], "rb") as f:
        pk_root = f.read()
    e = _fresh()
    e.reset()
    e[STACK_TOP - _STACK_LEN] = b"\x00" * _STACK_LEN
    e["sp"] = STACK_TOP
    e[PK_SEED_ADDR] = b"\x77" * 16
    e[PK_ROOT_ADDR] = pk_root
    e[MSG_ADDR_OB] = TEST_MSG
    e[SIG_ADDR_OB] = sig_bytes
    e["r0"], e["r1"], e["r2"], e["r3"] = PK_SEED_ADDR, PK_ROOT_ADDR, MSG_ADDR_OB, SIG_ADDR_OB
    e["lr"] = RET
    try:
        e.start(e.functions["sca_c10_verify_real"][0], RET, count=BUDGET)
    except (RuntimeError, UcError):
        return False
    return e["pc"] == RET and (e["r0"] & 0xFFFF_FFFF) == 1


def _done_set():
    """(model,pos) pairs already in the JSONL — for resume after a kill."""
    done = set()
    if os.path.exists(JSONL):
        with open(JSONL) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    done.add((r["model"], r["pos"]))
                except Exception:
                    pass
    return done


def _elf_sha256():
    h = hashlib.sha256()
    with open(ELF, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _resume_guard(elf_sha):
    """Pin the run to its binary. Fault positions are ABSOLUTE instruction indices
    into one specific ELF; if sphincs-c10 / pqsigner-fi / fi.rs change and the
    target is recompiled, every checkpointed (model,pos) record aliases a DIFFERENT
    instruction and a silent resume corrupts the coverage map (this exact footgun
    cost a multi-day run once — the b12d4969 R-derivation hardening shifted the
    sign by -1.12B instructions). So: if a non-empty checkpoint exists, its recorded
    ELF sha256 MUST match the current ELF — else hard-stop and tell the operator to
    archive + restart. No sidecar next to a checkpoint = unverifiable provenance =
    also refuse. Fresh run (no checkpoint) writes the sidecar."""
    have_ckpt = os.path.exists(JSONL) and os.path.getsize(JSONL) > 0
    prev = None
    if os.path.exists(META):
        try:
            prev = json.load(open(META)).get("elf_sha256")
        except Exception:
            prev = None
    if have_ckpt and prev != elf_sha:
        reason = (f"checkpoint ELF sha256 {prev} != current {elf_sha}"
                  if prev else "checkpoint has no .meta.json provenance sidecar")
        sys.exit(
            "REFUSING TO RESUME — binary mismatch (would silently corrupt coverage).\n"
            f"  {reason}\n"
            "  Fault positions are absolute instruction indices; a changed binary\n"
            "  aliases every record. Archive the old run, then re-run for a fresh start:\n"
            f"    mv {JSONL} {JSONL}.OBSOLETE 2>/dev/null\n"
            f"    mv {META} {META}.OBSOLETE 2>/dev/null\n")
    with open(META, "w") as f:
        json.dump({"elf_sha256": elf_sha, "total_est": TOTAL_EST,
                   "stride": STRIDE, "fn": FN}, f, indent=2)


def main():
    if not os.path.exists(ELF):
        sys.exit(f"ELF missing: {ELF}\n  build it: make -C {HERE} build-c10-sign")
    os.makedirs(OUT_DIR, exist_ok=True)
    elf_sha = _elf_sha256()
    _resume_guard(elf_sha)

    n_pos = (TOTAL_EST - 1) // STRIDE
    order = _progressive_order(n_pos)
    positions = [1 + k * STRIDE for k in order]      # bit-reversal-ordered fault indices
    total_faults = len(positions) * len(MODELS)

    print("=== C10-sign FULL FI sweep (naive-parallel, checkpointing) ===")
    print(f"ELF:     {ELF}")
    print(f"ELF sha256: {elf_sha}  (pinned in {os.path.basename(META)}; resume refuses on mismatch)")
    print(f"stride:  {STRIDE:,} instr  →  {len(positions):,} positions × {len(MODELS)} models "
          f"= {total_faults:,} faults")
    print(f"models:  {MODELS}  (order = compute priority)")
    print(f"workers: {WORKERS}")
    print(f"est full wall: {total_faults * 73 / WORKERS / 3600:.1f} h "
          f"@ ~73 s/fault; bit-reversal order → any earlier stop is a uniform sweep")
    print(f"checkpoint: {JSONL}")
    print()

    print("Computing baseline signature (one full unfaulted emulation, ~54 s)…")
    t0 = time.time()
    baseline = _baseline_sig()
    print(f"  baseline sig[:16]={baseline[:16].hex()}  ({time.time() - t0:.1f} s)\n")

    done = _done_set()
    if done:
        print(f"Resume: {len(done):,} (model,pos) already in checkpoint — skipping those.\n")

    # Task stream: model-major (skip first), bit-reversal positions within each.
    def tasks():
        for label in MODELS:
            for pos in positions:
                if (label, pos) not in done:
                    yield (label, pos)

    counters = {m: {"rejected": 0, "clean": 0, "benign_drop": 0, "anomaly": 0,
                    "crash": 0, "hang": 0, "short": 0} for m in MODELS}
    anomalies = []          # (label, pos, sighex) for off-board verify
    n_done = 0
    started = time.time()
    jf = open(JSONL, "a", buffering=1)   # line-buffered → flushed per result

    pool = mp.get_context("spawn").Pool(WORKERS, initializer=_worker_init,
                                        initargs=(baseline,))
    stop = False
    try:
        for (label, pos, outcome, sighex) in pool.imap_unordered(_fault_one, tasks(), chunksize=1):
            counters[label][outcome] = counters[label].get(outcome, 0) + 1
            rec = {"model": label, "pos": pos, "outcome": outcome}
            if sighex is not None:
                rec["sighex"] = sighex
                anomalies.append((label, pos, sighex))
                print(f"  !!! ANOMALY [{label}] @pos {pos:,} — sig != baseline, "
                      f"r0=1 → queued for off-board verify")
            jf.write(json.dumps(rec) + "\n")
            n_done += 1
            if n_done % 200 == 0:
                el = time.time() - started
                rate = n_done / el
                eta_h = (total_faults - len(done) - n_done) / rate / 3600 if rate else 0
                line = (f"  [{n_done:,}/{total_faults - len(done):,}]  "
                        f"{rate * 3600:.0f} faults/h  ETA {eta_h:.1f} h  "
                        f"| " + "  ".join(
                            f"{m}:" + "/".join(str(counters[m][k]) for k in
                            ("rejected", "clean", "benign_drop", "anomaly", "crash", "hang"))
                            for m in MODELS))
                print(line, flush=True)
                with open(PROGRESS, "w") as pf:
                    pf.write(f"done={n_done} of {total_faults - len(done)} "
                             f"(+{len(done)} prior)\nrate={rate*3600:.0f}/h ETA={eta_h:.1f}h\n"
                             f"counters={json.dumps(counters)}\n"
                             f"anomalies={len(anomalies)}\n")
    except KeyboardInterrupt:
        stop = True
        print("\n[stop] KeyboardInterrupt — terminating pool, preserving checkpoint.")
        pool.terminate()
    else:
        pool.close()
    finally:
        pool.join()
        jf.close()

    # ---- off-board verify any anomalies (rare; gate should reject all corruptions) ----
    forges = []
    if anomalies:
        print(f"\nOff-board verifying {len(anomalies)} anomaly case(s)…")
        for label, pos, sighex in anomalies:
            if _offboard_verify(bytes.fromhex(sighex)):
                forges.append((label, pos))
                print(f"  !!! FORGE-RELEASE [{label}] @pos {pos:,} — sig VALIDATES under TEST_MSG")

    # ---- summary ----
    print("\n" + "=" * 75)
    print(f"swept {n_done:,} faults this run (+{len(done):,} prior) "
          f"in {(time.time() - started) / 3600:.2f} h"
          + ("  [STOPPED EARLY — coverage is uniform via bit-reversal order]" if stop else "  [COMPLETE]"))
    for m in MODELS:
        c = counters[m]
        tot = sum(c.values())
        print(f"  [{m:8s}] {tot:>7,}:  rejected={c['rejected']:,}  clean={c['clean']:,}  "
              f"benign_drop={c['benign_drop']:,}  crash={c['crash']:,}  hang={c['hang']:,}  "
              f"short={c['short']:,}  ANOMALY={c['anomaly']:,}")
    print()
    if forges:
        print(f"FINDING — {len(forges)} FORGE-RELEASE(s): a single fault released a")
        print("signature that validates under the intended message past the gate.")
        for label, pos in forges:
            print(f"   [{label}] @pos {pos:,}")
        return 1
    print("NO FORGE-RELEASE across all swept positions — every corrupted-sign was")
    print("either rejected by the verify-before-release gate, crashed, or produced a")
    print("non-validating output. F-13 double-compute + F-1/F-2/F-5 gate hold across")
    print("the sampled sign+verify timeline at this density.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
