# SCA / FI hardening adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for running an adversarial code-review pass over PQSigner's side-channel-analysis (SCA) and fault-injection (FI) hardening — the FI-hardened signing chain, the FI primitives, the constant-time compares, the DPA countermeasures, and zeroization. The properties everything here defends:

> **A single fault must not release a wrong signature, skip a gate, or roll back a counter; a secret-dependent power/EM trace must not reveal a key bit.** Signing is a double-compute → constant-time byte-compare → verify-before-release chain under a CFI counter with Hamming-distant sentinels (RFC 9814 §A.2 / Genêt TCHES 2023). Verify-after-sign **alone is insufficient** against SPHINCS+ grafting faults — the redundant recomputation is load-bearing and must not be weakened to verify-only.

**How this differs from the bench red-team.** [`docs/security/red-teaming.md`](../red-teaming.md) §4.4 (verify-before-release FI), §6.7 (SCA jitter mask), and §9 (FI primitives coverage map) enumerate the *bench pass-fail bars* — glitch rigs, EM probes, TVLA on real traces. **This playbook is the code-review counterpart**: it walks the *source* of each countermeasure against its FI/SCA property, hunting a gate a single fault skips, a compare that short-circuits, a sentinel pair too Hamming-close, a zeroize the compiler elides, or a counter bump ordered after the compare. Same discipline as the [FV playbook](../../verification/fv-adversarial-review-playbook.md); cross-link red-teaming.md as the bench counterpart, do not re-run its trace captures.

> **Honesty note.** The `Status` column separates **defended** (with the primitive + the FI-sweep target), **by-design-leaky** (the Fisher-Yates shuffle is statistically-hardened, not bitwise-CT — cargo-checkct correctly reports INSECURE, and that is *intended*), and **disclosed residual** (the 2-fault stack-accum bypass, the SRAM reconstruction window). Do not report a by-design-leaky item as a finding; report a *regression* from the documented posture. The FI harness parity matters: the rainbow `_target/` ELFs mirror the production `fi.rs` verbatim via `#[path]`, so a sweep result reflects shipped code.

---

## Part A — The SCA/FI failure catalog (FI1–FI10)

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| FI1 | **Skipped verify-before-release** | one fault skips the final verify and releases the (possibly faulted) sig | **DEFENDED.** Verify gated by `check_true_into_sentinel` + `black_box` (no CSE) + `wait_random()` before, as CFI step 7, fail-closed on `cfi.check != OK_SENTINEL` (`crypto.rs:218-235` ct_eq gate, `:252-262` verify gate, CFI final `:273-281`). F-1 (CSE collapse) fixed; F-2 (call-site glue) sentinel-mitigated | Rainbow `fault_sweep_c10_sign.py` (real sign+verify+gate, snapshot-restore, BYPASS = `Ok` with sig≠baseline) | ✅ FI sweep |
| FI2 | **Single-compute / missing redundant recompute** | the second sign is skipped, or a cfg/feature disables it, leaving verify-only | **DEFENDED (with a test-cfg caveat).** Both signs unconditional (`crypto.rs:200,203`); the redundant-recomputation rationale is documented (`:87-95`). **Caveat**: under `#[cfg(test)]` the OptRand + shuffle-seed draws are skipped (seed stays zero → identity shuffle) — verify no non-test feature disables the second sign | Sweep target for a cfg/feature path that drops sign B; source-shape test that both `sk.sign*` calls are present and unconditional | ⚠ partial (sweep + grep) |
| FI3 | **Non-CT compare / short-circuit** | the double-compute byte-compare short-circuits (data-dependent timing) | **DEFENDED (with disclosed self-warning).** Compare uses `subtle::ConstantTimeEq` `ct_eq` over the 4008-B sigs (`crypto.rs:218`), pinned by source-shape test (sign-shape pins at `secure_crypto_glue_under_test/pure_tests.rs:1163-1167`). The code itself notes the `if !ct_eq {Err}` is a single-skip point → kept as gate 1 of a 2-gate chain with verify | Source-shape CT test; the negative test that `cmd_request_unlock` must NOT contain a PIN `ct_eq`/`==` (SE does the compare, `nsc_small_cmds_pure_tests.rs:787-790`) | ✅ source-shape tests |
| FI4 | **Secret-dependent branch** | a decode/compare branch or table index depends on secret bits | **BY-DESIGN-LEAKY (not a finding).** The Fisher-Yates shuffle uses a secret-indexed swap (`sphincs-c10/src/shuffle.rs:181-184`) — cargo-checkct returns INSECURE **by design**; the defense is 43!/13! statistical trace-misalignment, not bitwise CT (docs/archive/work-todo-retired-2026-07-19.md:3319). The variable-time `UDIV` was already removed (Lemire multiply-shift). F-9 `grind_r` timing leak is on a **public** input (transparent) | cargo-checkct SECURE/INSECURE map (`tools/sca/checkct/`): SECURE for `domain::kdf`, `fors_secret`, `th`; INSECURE only where documented | ✅ cargo-checkct |
| FI5 | **Attempt-counter bump ordered after compare** | a fault skips the decrement/bump so a wrong PIN doesn't count | **DEFENDED.** The page-124 bump is a **pre-commit BEFORE** the SE verify (`nsc/mod.rs:1097`), with a FAIL-IN sentinel requiring the counter advanced by exactly one, refusing to call the SE if not (`:1098-1112`); the counter stays bumped on any downstream inconsistency (`:1194-1199`) — note this means a post-verify `InternalError` also keeps the charge (see SE17-6 in work-todo) | Rainbow `fault_sweep_pin.py`; audit `gated_unlock` ordering (bump → sentinel → SE compare, never the reverse) | ✅ FI sweep |
| FI6 | **CFI sentinel weakness** | Hamming-close sentinels, colliding step magics, or a plain-stack accumulator a fault can overwrite | **DEFENDED (with disclosed 2-fault residual).** `OK/FAIL_SENTINEL` are Hamming-distance-32 (asserted `pqsigner-fi/src/lib.rs:314-318`); per-step magics chosen so no skipped-subset sums collide (`crypto.rs:41-47`); `INIT_VALUE` non-zero non-sentinel; `select_sentinel` branchless (F-29). **Disclosed residual**: `accum` is a plain stack u32 — the doc admits a 2-fault stack-write bypass (`secure/src/fi.rs:186-190`) | FI unit tests (`pqsigner-fi/tests/{positive,negative}.rs`, `fi.rs:337-372`); the 2-fault case is out of the single-fault threat model | ✅ unit tests (single-fault) |
| FI7 | **DPA shuffle seed predictable / correlated** | the shuffle seed is guessable or its entropy narrows | **DEFENDED (with degradation note).** Seed from `rng_strong::fill` (STM32 ⊕ OPTIGA ⊕ SE050, 3-source), fail-closed, fed unchanged to both signs (required for the byte-equality gate) (`crypto.rs:130-143` opt_rand, `:178-198` shuffle seeds — but see FI11: the CFI bumps there are not bound to the draws). **Residual**: if `rng_strong` degrades to STM32-TRNG-only (mock-se / early boot) the seed entropy narrows | Leakage TVLA `tools/sca/leakage_*.py` (`leakage_seed_derivation`, `f9_*`); audit the `rng_strong` degradation paths | ⚠ partial (TVLA + review) |
| FI8 | **Dead-store elimination of a zeroize** | the compiler drops a secret wipe, or a popped stack frame retains residue | **DEFENDED (audited 2026-07).** `docs/security/zeroize-audit-2026-07.md`: existing `zeroize::Zeroize` wipes survive `-O1/-O2` as volatile stores (no DSE); 8 transient-stack-residue findings fixed (`domain/src/lib.rs` ×6, `sphincs-c10/src/lib.rs` keygen/from_parts ×2). `fi::zeroize_barrier()` = `compiler_fence(SeqCst)` + `dsb()` at ~53 secret-path sites | The `zeroize-audit` skill (MIR/LLVM IR + assembly-level DSE detection); re-run on any new secret type | ✅ zeroize-audit skill |
| FI9 | **Consumption mask ineffective** | the mask isn't randomized per-op, or doesn't cover the leaking peripheral | **BY-DESIGN-LIMITED (disclosed, not a finding).** `randomize()` is SysTick-driven / free-running, **not** per-signing-op; PA5 PWM only, explicitly does **not** mask SAES/PKA power draw (`hw/consumption_mask.rs:42-49,141`). Seed fail-closed (F12, panics in `init` on RNG failure or all-zero) | TVLA `leakage_kdf.py` / `leakage_saes_kdf.py` on the actual leaking primitive; the mask is a jitter aid, not the primary CT defense | ⚠ disclosed limit (TVLA) |
| FI11 | **CFI bump not bound to step execution** | an unconditional `cfi.bump(STEP)` runs whether or not the fallible step it stamps actually ran — the counter binds *bump* execution, not *step* execution | **CANDIDATE (2026-07-17 sweep, pre-adjudication).** `crypto.rs:131-143` (`rng_strong::fill` + `cfi.bump(CFI_STEP_OPT_RAND)`), `:180-198` (shuffle seeds), `:83-85` (`pre_sign()?` + bump): skipping the fallible `bl` does not skip the following `bl cfi.bump`, so a skipped draw leaves signing on an all-zero OptRand (Genêt re-use class) or identity shuffle with every gate green. The F-18 comment (`crypto.rs:266-269`, "skipped the step itself, since the bump follows it directly") is false for a single-instruction skip. Today's fail-closure is ABI luck (`r0` holds a nonzero pointer arg before each call, decoding as `Err`), not design — regalloc-fragile. Fix: gate each bump on the step's verified success (post-fill nonzero check outside `fill`, or fold the bump into an `Ok`-only wrapper); correct the comment. Detection: sweep skipping each protected `bl`, not source-reading bump order | Rainbow skip-sweep on each fallible call preceding a bump | ❌ found-this-surface (candidate) |
| FI12 | **Rate/cap counter without FI wrapper** | the per-session sign cap is a plain load/branch/store — one branch-skip signs past the trace budget | **CANDIDATE (2026-07-17 sweep, pre-adjudication, LOW).** `sign_rate.rs:78-94`: `SIGNS_THIS_SESSION` load + `count >= MAX_SIGNS_PER_SESSION` branch + store have no voted read / sentinel — F-19 hardened the *time-wait* (`read_volatile_voted`) but not the *cap*, and the cap is the per-session trace budget F-17 names as the mitigation. Contrast the page-124 PIN counter's pre-commit + FAIL-IN sentinel readback. Fix: `read_volatile_voted` on the load + sentinel'd readback of the store, mirroring `pin_attempts_bump` | Rainbow skip-sweep on the cap compare (sign #251 proceeds = BYPASS) | ❌ found-this-surface (candidate) |
| FI10 | **Compiler proves away / folds an FI check** | LTO folds/elides a volatile FI read, or *algebraically* proves the FI recompute dead, so the check is a no-op in the shipped binary | **PARTIAL — CANDIDATE BREAK (2026-07-17, pre-adjudication; empirically confirmed at IR level by two independent runs).** `fi_min` (`pqsigner-fi/src/lib.rs:233-244`) recomputes only when `r > a \|\| r > b` — algebraically false for `r = min(a,b)` — so LLVM InstCombine deletes the check in **every** optimized build: `rustc -O --emit=llvm-ir` on the verbatim body emits a bare `llvm.umin` + `ret` even with `#[inline(never)]`. Unit tests pass either way (plain `min` satisfies them) — a class-(vi) "tests cover the helper, not the shipped configuration" case. The single-clamp call sites lose their only FI guard: `nonsecure/src/usb/transport.rs:159-160` and `nonsecure/src/usb/commands.rs:791-793` (one fault → heap-linear write past `tx_buf` / `CHUNK_BUF` overflow). The claims "FI-resistant fi_min pattern … Landed" (docs/archive/work-todo-retired-2026-07-19.md:2075 `[x]`), "DEFENDED-by-construction" (usb playbook UC1), and this row's former "`#[inline(never)]` on every primitive" are all wrong for the shipped binary. The volatile-read/`black_box`/`select_sentinel` defenses do hold for the *other* primitives as read. **Fix:** `black_box` the computed `r` (or both inputs) so the post-condition can't be proven; add an LLVM-IR/assembly regression check for `fi_min` — unit tests cannot pin this. **Residual**: confirm the other primitives post-LTO on the shipped M33 binary (cargo-checkct scope note) | cargo-checkct on the machine code; disassemble the shipped binary and confirm the volatile checks survive; per-primitive IR inspection (the volatile-read pattern cannot see algebraic DCE) | ⚠ partial (post-LTO check + IR audit) |

**Read this catalog as the answer to "does one glitch forge a signature, and does one trace leak a key?"** For FI1/FI3/FI5/FI6/FI8/FI10 a single fault is designed to fail closed and each row names the sweep/audit that tests it. **FI4 and FI9 are by-design-leaky/limited** — the shuffle's statistical hardening and the mask's jitter role are the *documented posture*, so report a regression from it, not the posture itself. FI2 (test-cfg skip), FI7 (rng degradation), FI6 (2-fault stack accum), and FI10 (post-LTO) are the disclosed residuals worth re-attacking each pass. **Do not weaken the double-compute chain to verify-only** — that is a known-insufficient FI gate (CLAUDE.md).

---

## Part B — The existing defenses (Layer 1)

1. **The FI-hardened sign chain.** `c10_sign_verified_with_progress` (`secure/src/crypto.rs:49`): the 7-step `CfiCounter`-gated chain — rate-limit → 3-source OptRand → DPA shuffle seed → sign A → `wait_random` → sign B → `ct_eq` compare → verify-before-release → CFI final check. Every error path zeroizes + `zeroize_barrier`.
2. **The FI primitive library.** `pqsigner-fi/src/lib.rs` (core) + `secure/src/fi.rs` (secure shim injecting the STM32 TRNG): Hamming-32 sentinels, `wait_random_loop` (Trezor `i+j==wait` invariant, `halt_on_glitch`), `check_true_into_sentinel`, branchless `select_sentinel` (F-29), `read_volatile_voted` (3× read, all-agree), `CfiCounter`, `zeroize_barrier`, `scrub_sentinel_register` (F-15.r1). Unit tests `pqsigner-fi/tests/{positive,negative}.rs`.
3. **cargo-checkct (machine-code CT proof).** Vendored driver workspace `tools/sca/checkct/` — SECURE proofs for `domain::kdf`, `fors_secret`, `th`; INSECURE **by design** on `fisher_yates`. The authoritative SECURE/INSECURE map for FI4/FI10.
4. **Rainbow FI-sim harnesses.** `tools/sca/fault_sweep_*.py` + `_target/` ELFs mirroring production `fi.rs` verbatim (`#[path]`): `c10_sign`, `c10_verify`, `fi`, `pin`, `dispatch`, `scp03`, `rng_strong`, `flashctr`, `fw_verify`, `ns_ptr`, `optiga_lock`, `cap`. BYPASS-detection semantics per harness (README `tools/sca/README.md`).
5. **Leakage / TVLA.** `tools/sca/leakage_*.py` (lascar/scared/muscat): `kdf`, `saes_kdf`, `scp03`, `seed_derivation`, `wait_random`, `f9_*`. The findings glossary (README `:311+`) tracks F-1/F-2/F-3/F-4/F-9/F-13/F-16/F-28/F-29.
6. **Zeroize audit.** `docs/security/zeroize-audit-2026-07.md` + the `zeroize-audit` skill (source + MIR/LLVM + assembly DSE analysis). `ZeroizeOnDrop` on `ShuffleSeed`, `SigningKey`, `SLOT_CACHE`.

**Cross-linked surfaces.** The FI gates *protect* the boundary and SE surfaces — the `gated_unlock` FI ordering is shared with the [TrustZone playbook](./trustzone-gateway-adversarial-review.md) (TZ7) and the unlock reconstruction window with the [SE playbook](./secure-element-adversarial-review.md) (SE2). Review the FI primitive here; review its *use* at the boundary there.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's SCA/FI hardening. Your job is to
find where a SINGLE FAULT forges a signature / skips a gate / rolls back a counter, or
where a secret-dependent TRACE leaks a key bit — NOT to confirm the hardening. Default to
"this gate is skippable and this compare leaks until I prove otherwise." A passing FI
unit test is a CONSISTENCY signal — the attack surface is the SWEEP result on the shipped
code and the post-LTO machine code.

BY-DESIGN posture (do NOT report these as findings — report REGRESSIONS from them):
the Fisher-Yates shuffle is statistically-hardened, NOT bitwise-CT (cargo-checkct INSECURE
is intended); the consumption mask is a free-running jitter aid, NOT a per-op SAES/PKA mask;
the 2-fault stack-accum bypass and the rng-degradation seed-narrowing are DISCLOSED residuals.
NEVER propose weakening the double-compute chain to verify-only (known-insufficient).

TARGET (read first, in this order):
  - docs/security/adversarial-review/sca-fi-adversarial-review.md §A — FI1–FI10.
  - secure/src/crypto.rs:49 — the 7-step FI-hardened sign chain.
  - pqsigner-fi/src/lib.rs + secure/src/fi.rs — the FI primitives (sentinels, CfiCounter,
    wait_random, select_sentinel, read_volatile_voted, zeroize_barrier).
  - secure/src/nsc/mod.rs:814-988 — gated_unlock ordering (bump BEFORE compare).
  - tools/sca/ — the fault_sweep_*.py + leakage_*.py + checkct SECURE/INSECURE map.
  - docs/security/zeroize-audit-2026-07.md — the zeroize posture.
SCOPE THIS RUN: {{e.g. "the sign chain's single-fault surface" | "the CFI sentinel +
  step-magic collision analysis" | "the gated_unlock counter ordering" | "the cargo-checkct
  SECURE/INSECURE map vs the source" | "the zeroize DSE surface for a new secret type"}}.

ATTACK PROTOCOL — walk EVERY FI1–FI10 mode against each countermeasure in scope:
  FI1 skipped verify-before-release · FI2 single-compute/missing recompute · FI3 non-CT
  compare/short-circuit · FI4 secret-dependent branch (report REGRESSION only) · FI5
  counter-bump-after-compare · FI6 CFI sentinel weakness · FI7 DPA seed predictable ·
  FI8 dead-store-eliminated zeroize · FI9 mask ineffective (report REGRESSION only) ·
  FI10 compiler folds a volatile FI check.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a rainbow fault_sweep BYPASS (Ok with sig≠baseline / gate skipped / counter not bumped);
  - a cargo-checkct INSECURE result on a primitive NOT in the documented by-design set;
  - a step-magic subset that sums to the CFI expected total when a step is skipped;
  - a MIR/LLVM/assembly diff showing a zeroize dropped or a volatile check folded post-LTO;
  - a source path where the second sign is disabled, or the bump is ordered after compare.
  No PoC ⇒ list under "suspicions, unverified".

RULES:
  - Verify against the CURRENT tree; a green FI UNIT test is not a green SWEEP — state which
    you ran. The rainbow _target/ ELFs mirror production fi.rs via #[path]; a sweep on them
    reflects shipped code, a source read does not.
  - cargo-checkct / TVLA on a HOST build is not the shipped M33 binary — flag post-LTO gaps.
  - For each candidate: FI-mode, file:line, PoC, provisional severity, stable
    candidate ID, and proposed fix (flag if
    it would weaken the double-compute chain, remove a sentinel, or regress a checkct proof).
    Do not assign a finding disposition.

OUTPUT — return an external candidate packet to the coordinator. Do not modify
the repository, write a canonical findings report, or update catalogue/status
fields. Include every candidate and the honest residual. The coordinator freezes
the raw packet and gives the complete union to the exact Partner-A/Partner-B
pair; only their symmetric cross-adjudication may assign dispositions. An
authorized maintainer records the adjudicated result afterward.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per countermeasure, the strongest failed sweep.
  2. "What I did NOT look at" — sweeps not run, primitives not checkct'd, TVLA not done,
     post-LTO machine code not disassembled.
  3. "PROVENANCE — did this pass RUN rainbow / cargo-checkct / TVLA, or read source only?"
     A source-only FI pass is especially weak: a folded volatile check or a skippable gate
     is invisible without executing the sweep on the actual binary.
  Never imply "the rest is fine."
```

**Running it as a swarm.** Use ≥3 independent discovery reviewers per scope
across two model backends. Quorum only corroborates/prioritizes discovery; it
does not set a disposition, and sub-quorum variants remain in the packet. Give
every candidate and origin variant to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only their symmetric cross-adjudication may disposition it, with disagreement
preserved. For the FI surface specifically, an *executing* pass (actually
running the rainbow sweep / cargo-checkct) is worth far more than a source read
— prioritize provenance.

---

## Part D — Cadence + honest boundary

- **Per-PR touching `crypto.rs`, `fi.rs`, `pqsigner-fi/`, `gated_unlock`, or a secret type:** the Layer-1 unit tests + cargo-checkct on the touched primitive + the zeroize-audit skill on a new secret type. A change to the sign chain re-runs `fault_sweep_c10_sign.py`.
- **Per-milestone:** the full rainbow sweep matrix + TVLA on the KDF/SAES/SCP03 primitives + a disassembly of the shipped M33 binary to confirm the volatile checks survive LTO (FI10).
- **Pre-ship:** the bench red-team (red-teaming.md §4.4 / §6.7 / §9) — real glitch rig + EM probe, the once-only silicon FI/SCA validation the sim can only approximate.
- **The one-line gut check:** *if I skip this instruction / flip this bit / align a scope to this loop — does the device release a wrong sig, skip a gate, or leak a bit?* If you haven't **run the sweep** (not read the source), you don't know — and for FI, source-reading is the weakest possible pass.

**The boundary, stated on purpose.** This playbook can tell you that no *swept* gate is single-fault-skippable and no *checkct'd* primitive leaks (beyond the documented by-design set) as of the last **executing** pass. It **cannot** tell you a gate you didn't sweep is hardened, that the volatile checks survive LTO on the shipped binary if you didn't disassemble it (FI10), that the free-running mask helps against a real EM probe (FI9 — that is TVLA on silicon, red-teaming.md §6.7), or that the 2-fault stack-accum bypass (FI6) is unreachable. Those are the executing-sweep's + the bench's job.
