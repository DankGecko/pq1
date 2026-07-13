# Retired Groth16 fault-sweep receipt (2026-05-19)

> Historical evidence only. The Groth16/BLS12-381 verifier, its detached
> target, and the associated Make targets were removed on 2026-06-30.
> Nothing in this document is a runnable instruction for the current tree.

## Groth16 verifier fault sweep — `fault_sweep_groth16.py` + `groth16_target/`

The `bls12_381_pka` Groth16 verifier (`secure/src/zk/groth16.rs::groth16_verify`)
is invoked from the `CMD_CLEAR_SIGN` path: companion sends a proof + public
signals, the wallet runs the verifier, and only if it returns `true` does
the trusted UI render the decoded Aave/CowSwap/etc. action for the user.
A fault that flips a single reject into an accept lets an attacker bypass
clear-signing — the user sees a forged human-readable summary while
calldata signs whatever the attacker wanted.

`groth16_target/` mirrors the 25-line `groth16_verify` function verbatim
into a `#[no_mangle]` thumbv8m ELF (a drift-watched copy: the imports in
`secure/src/zk/groth16.rs` pull in too many crate-internal modules to
link a detached target against). The sweep loads a **structurally valid**
proof + VK from `secure/src/zk/{test_vectors,vk_data}.rs` paired with a
**pub0-bit-flipped** public-signal vector, so the unfaulted run rejects
(returns 0). A single fault that flips r0 to 1 is FORGE_RELEASE.

```
make groth16          # tight sweep, ~11 min — 164 skip-fault positions
                      # across [bad_total-5000, bad_total-900) at step 25
make groth16-full     # full sweep, ~25-100h — 30K positions × 3 fault models
                      # (skip / stuck-at-0 / stuck-at-FF). Overnight only.
```

`bad_total` (the BAD-path instruction count, ~161.3M) is auto-bisected
to 1K-precision on each run (~75 s). The sweep range is upper-bounded
by `bad_total - SWEEP_LEAD` (default 900) because rainbow's notion of
"end of function" for `sca_groth16_verify_real` sits ~800 instructions
before the bisected `bad_total` — fi values inside that lead throw
`IndexError: reached end of function before faulting` rather than
emulating the fault. The empirical usable window for single-fault
sweeps is `[bad_total-5000, bad_total-900)`.

### F-26 — Groth16 verifier final-compare + return-path is FI-robust against single skip-faults in the last 5K instructions — **NO FINDING (BAD path rejects on every fault, no FORGE_RELEASE)**

Run on 2026-05-19 (commit pre-`fault_sweep_groth16.py` cleanup).

**Setup.**

- Target: `sca_groth16_verify_real(input_ptr) -> u32` in
  `tools/sca/groth16_target/src/main.rs`, ELF size ~315 KB (full
  `bls12_381` pairings).
- Input: VK + proof from `secure/src/zk/test_vectors.rs` and
  `secure/src/zk/vk_data.rs` (real on-chip values for the Aave-v3
  clear-sign circuit), with `pub0` byte 0 bit 0 flipped.
- Baseline: GOOD vector → r0=1 (accept) in 3.3 s, BAD vector →
  r0=0 (reject) in 4.2 s.
- BAD-path instruction count: bisected to **161,346,878** ± 1024.
- Sweep window: `[161,341,878, 161,345,978)` step 25 → 164 positions.
- Fault model: `fault_skip` (single instruction skip).

**Result.**

```
  rejects (correct):  124
  accepts (FORGE!):   0
  crashes:            26
  other anomalies:    14
```

- 124 / 164 positions: r0 stays 0 → verifier still rejects under fault.
- 26 / 164 positions: emulation crashed (Unicorn `RuntimeError` —
  typically a pairing-state load from a corrupted register lands on a
  bad PC). These crashes are *not* exploitable on real silicon (panic
  triggers `panic_halt`); they're an artefact of skipping load
  instructions in the final-exponentiation accumulator.
- 14 / 164 positions: r0 took a value other than 0 or 1 (e.g. partial
  `Gt::identity()` compare returning garbage). The dispatch in
  `cmd_clear_sign` only treats `1` as accept (`groth16_verify(...) as u32
  == 1`), so these are still rejects — but worth noting.
- **0 / 164 positions** produced r0=1. No single instruction-skip in
  the last 5 K instructions of the BAD path forges acceptance.

**Why this is the interesting window.** The last ~5 K instructions of
`groth16_verify` are the `result == Gt::identity()` compare + boolean
return + caller's `as u32` widening — i.e. the spot where the C10
verify-before-release class of bugs (F-1, F-2, F-3) lived. If a forge
exists, it almost certainly sits there: faulting deep inside
`miller_loop_4` or `final_exponentiation` corrupts the pairing
accumulator, which propagates to a still-bogus `Gt` element and a
still-failing compare. Conversely, the compare itself reduces 12 Fp²
limb comparisons into one boolean — a textbook FI target.

**What the sweep does *not* cover.**

- **Wider fault windows.** The 5 K-instruction tail covers the
  compare + return only. The pairing loop, the `vk_x` MSM, the
  deserialise+subgroup checks (`G1Affine::from_uncompressed`,
  `G2Affine::from_uncompressed`) all sit earlier and aren't probed
  here. `make groth16-full` runs the last 30 K instructions × 3 fault
  models for ~25-100 h.
- **Stuck-at-0 and stuck-at-FF.** Skip-only. The other two models are
  in the full sweep.
- **Multi-fault.** Single fault. Two-fault sweeps over this verifier
  are out of scope — the search space (~2.6 × 10¹⁰ position pairs)
  would need a smart prioritiser (e.g. faults inside identified
  comparison instructions only).
- **Drift between mirror and production.** `groth16_target/src/main.rs`
  duplicates `groth16_verify` verbatim from `secure/src/zk/groth16.rs`.
  A future commit that diverges the bodies invalidates the finding.
  The 25-line function is small enough that drift should be obvious in
  review; CI doesn't currently enforce mirror-vs-source equality.

**Disposition.** Accept as a positive result for the tight window.
File `make groth16-full` for the next overnight cycle (the wider
window + stuck-at models are where any real finding would surface
given the negative tight-window result). No code change.

**Deferred overnight sweep — `make groth16-full`.** Configuration:

```
  TAIL_DEPTH=30_000          # last 30K instructions of BAD path
  FULL_LEAD=900              # respect the rainbow past-end boundary
  models: fault_skip, fault_stuck_at(0), fault_stuck_at(0xFFFFFFFF)
  iterations: 3 × (30_000 - 900) = 87,300
  per-iteration cost: ~4 s under snapshot/restore
  estimated wall time: ~25-100 h (run on a dedicated machine, tee to log)
```

The full sweep is intentionally *not* parallelised (see the FW-manifest
parallelisation post-mortem above — single-thread is already fast
enough that the per-worker bls12_381 ELF load + emulator snapshot eats
the wins, and FaultFinder is the right pattern if/when we exceed
500 K iterations).
