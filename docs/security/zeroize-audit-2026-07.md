# Zeroization audit — secret-lifecycle, 2026-07-01

Tool: Trail of Bits `zeroize-audit` skill (source + MIR/LLVM-IR/asm, on host x86-64 with
`cargo +nightly`). Run in support of the rr-1 fault-reset backstop (below): before wiring a
`HardFault` handler to `nsc::zeroize_sensitive_state()`, confirm that wipe path actually wipes.

## TL;DR

- **The zeroize approach is validated.** Every existing `zeroize::Zeroize` wipe in the
  key-derivation crate **survives `-O1`/`-O2`** as volatile stores (no dead-store elimination).
  The secure-world wipe path `rr-1` invokes is sound by construction (see §Secure-crate).
- **8 real findings fixed**: transient SHA-256/HMAC **input buffers** in the derivation path hold
  secret pre-images (BIP-39 seed, `sk_seed`, slot entropy, `master_lo`) and were dropped **unwiped**
  — asm-confirmed retained on the stack frame at `ret`. The prior MEDIUM-2 secret-lifecycle audit
  covered *named* secrets but missed these *un-named* intermediates. Severity **medium /
  defense-in-depth** (physical-extraction / fault-dump threat model; residue not reachable by the
  in-session `zeroize_sensitive_state` since it lives on popped stack frames).
- **2 tool bugs found** (worth reporting upstream to trailofbits — see §Tooling).

## Scope

`pqsigner-domain` (`domain/src/lib.rs`, the BIP-39→C10 derivation core) as the primary target
(builds clean on host; highest density of transient stack secrets), plus `sphincs-c10`
`SigningKey::keygen`/`from_parts`. The `secure` crate itself can't be driven by the audit scripts
(its `compile_error!` backend fences need `--features`), so its wipe path was validated manually.

## Q1 — do the *existing* wipes survive optimization? YES

MIR+LLVM-IR+asm at O0/O1/O2. Volatile-store count rose O0=2 → O1=552 → O2=456 (at O0 each wipe is a
single out-of-line `write_volatile` loop; O1/O2 inline+unroll). All of `bip39_seed`, `master`,
`msg`, `sk_seed`, `sk_seed_32`, `wrap` emit bounded volatile loops at O2. The tool's 256 raw
"optimized-away" candidates all adjudicated to **zero** genuine findings (`[0u8;N]` inits + SSA
re-rolling noise). `ir-findings.json = []`. **`zeroize::Zeroize` is DSE-safe here.**

## Q2 — findings (all FIXED 2026-07-01) — transient secret stack residue

Each buffer below embeds a secret and was dropped unwiped; asm confirmed the bytes sit in the stack
frame at `ret`. Fix = `.zeroize()` the frame copy after its hash is consumed (the *returned* value
is the caller's to wipe, and callers already do). Verified byte-identical: derivation/signing
outputs unchanged → recovery contract + on-chain verifier compatibility intact.

| # | Function (`domain/src/lib.rs`) | Buffer | Secret | Fix |
|---|---|---|---|---|
| 1 | `slhdsa_seed_from_bip39` | `chunk0` | 32-B `sk_seed` | `chunk0.zeroize()` |
| 2 | `bootstrap_seed_from_bip39` | `chunk0` | 32-B bootstrap `sk_seed` | `chunk0.zeroize()` |
| 3 | `slot_master_entropy_from_bip39` | `buf` (85/93 B) | **64-B BIP-39 seed** | `buf.zeroize()` (both branches) |
| 4 | `slot_entropy` | `buf` (56 B) | `master_entropy` | `buf.zeroize()` |
| 5 | `derive_c10_slot_seeds` | `sk_buf`,`pk_buf` (48 B) | `slot_entropy` | both `.zeroize()` |
| 6 | `derive_c10_master_from_bip39_seed` | `sk_buf`,`pk_buf` (39 B) | `master_lo` | both `.zeroize()` |

**Cross-crate (`sphincs-c10/src/lib.rs`):**

| # | Function | Issue | Fix |
|---|---|---|---|
| 7 | `SigningKey::keygen` | `sk_seed: [u8;32]` is `Copy` → the struct field is a *copy*; the **parameter frame slot** retains the secret and the caller's `sk_seed.zeroize()` can't reach it | `mut` param + `sk_seed.zeroize()` after struct construction |
| 8 | `SigningKey::from_parts` | same `Copy`-param residue | same |

`keygen`/`from_parts` change is transparent (wiping a `Copy` param post-copy) — the
`independent_signer_xcheck` release test confirms keygen+sign are **byte-identical** to the reference.

## Secure-crate wipe path (manual validation — the rr-1 dependency)

`nsc::zeroize_sensitive_state()` → `SecureState::zeroize_sensitive()` (`secure/src/nsc/state.rs:153`)
wipes `master_secret:[u8;32]`, `slot_master_entropy:[u8;32]` (`zeroize::Zeroize`, DSE-safe by Q1),
`SLOT_CACHE` (a `SigningKey`, `#[derive(Zeroize, ZeroizeOnDrop)]`), and `FwUpdateCtx`, each followed
by `fi::zeroize_barrier()` = `compiler_fence(SeqCst)` + `dsb()`. **Sound by construction.**

Residual (not fixed here, tracked): findings 1–8 live on *popped stack frames* that
`zeroize_sensitive_state` cannot reach, so an in-session wipe (idle/lock) doesn't scrub them; the
fix above wipes them at their own scope exit instead. A `sys_reset` (see rr-1) clears them via
`.bss` re-init, so the fault path is fully covered; the lock/idle path is now covered by the
per-function wipes.

## rr-1 — HardFault → zeroize + reset (Trezor-port, landed 2026-07-01)

`secure/src/main.rs`: a synchronous CPU fault (the canonical fault-injection glitch symptom)
previously landed in cortex-m-rt's default infinite loop with all SRAM secrets live. New
`#[cfg(all(not(test), feature="stm32u585"))] #[cortex_m_rt::exception] unsafe fn HardFault(...)`
calls `nsc::zeroize_sensitive_state()` + `fi::zeroize_barrier()` then `SCB::sys_reset()`.
**Deliberately not** `tzic::trigger_intrusion_wipe` (destructive dual-SE wipe = a single glitch
would brick the wallet). Pinned by `negative_hardfault_handler_zeroizes_then_resets_and_never_se_wipes`.

## Tooling bugs found (report upstream — trailofbits/zeroize-audit)

1. `semantic_audit.py` reads pre-v45 rustdoc (`item["kind"]`), but the nightly emits
   `format_version 57` (kind nested under `item["inner"]`) → every struct/enum silently skipped
   (returns `[]`, not an error). Findings were recovered via source review.
2. `check_rust_asm.py` returned 0 STACK_RETENTION: (a) descriptive secret names never substring-match
   function symbols; (b) init-time `xorps %xmm0,%xmm0` trips its `has_zero_store` guard. The asm
   findings were hand-authored with exact return-path excerpts (ground truth from `a33a714e.O2.s`).

## Verification

`cargo test -p pqsigner-domain` 109/0 · `cargo test -p sphincs-c10 --lib` 8/0 +
`independent_signer_xcheck --release` 1/0 (byte-identical) · `cargo test -p sphincs-tz-secure`
(mock-se) 2035/0 · thumbv8m `stm32u585,usb` build clean.
