# Secure runtime, resources, exceptions, concurrency, and unsafe-code adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for attacking the
behavior of PQSigner's privileged secure runtime *after control has entered it*:
Rust/FFI/MMIO soundness, singleton ownership, interrupt and exception
interleavings, stack/RAM limits, watchdog progress, reset cleanup, initialization
order, peripheral ownership, and worst-case latency. A parser can be logically
correct and a gateway can validate every pointer yet still fail because an ISR
races a `static mut`, the secure stack crosses BSS, a watchdog is fed by false
progress, or a target-only unsafe precondition never executes in host tests.

> **Target claim.** For every supported production execution context, all
> unsafe and shared-state preconditions hold under every permitted exception
> schedule; memory regions and stacks remain disjoint at worst-case nesting;
> each loop/peripheral wait is bounded or reset by a watchdog tied to genuine
> progress; and every panic/fault/reset path revokes authority and clears
> sensitive runtime state before any subsequent sensitive operation.

**Sibling boundaries.** The [TrustZone playbook](./trustzone-gateway-adversarial-review.md)
owns NS pointers, veneers, SAU/GTZC, and the S/NS boundary; the
[USB playbook](./usb-companion-adversarial-review.md) owns transport framing;
the [trusted-UI playbook](./trusted-ui-adversarial-review.md) owns consent and
human timing; the [SCA/FI playbook](./sca-fi-adversarial-review.md) owns
physical glitches/leakage and post-LTO wipe assurance; and the
[lifecycle playbook](./lifecycle-persistent-state-adversarial-review.md) owns
durable transaction recovery. **This playbook owns internal S-world execution,
resource, scheduling, and fault composition.**

> **Architectural posture.** Current secure code is one privileged S-world
> domain; the threat model explicitly records the absence of an internal
> Secure MPU/privilege tier. Treat that as a documented, unratified blast-radius
> posture unless a concrete memory-corruption path or owner requirement makes it
> a finding. Do not, however, use that posture to waive review of `unsafe`,
> W^X, stack limits, or parser-to-key exploit chains.

---

## Part A — The secure-runtime failure catalog (RT1–RT11)

| # | Failure mode | What to try to prove | Status / anchor in this tree | Detection | Auto? |
|---|---|---|---|---|---|
| RT1 | **Unsound unsafe/MMIO/CMSE/FFI abstraction** | Range, alignment, alias, lifetime, volatility, ABI, register-width, or peripheral precondition can be violated by a reachable caller | **PARTIAL.** `unsafe_op_in_unsafe_fn` linting and typed MMIO/pointer helpers help, but much target-only unsafe code cannot execute under Miri. Raw occurrence counts are inventory only. | Miri/UB witness, invalid precondition proof, target disassembly, or on-target negative | ✅ host / ⚠ target |
| RT2 | **Shared-mutable alias or exception race** | `static mut`, singleton drivers, buffers, caches, or counters are concurrently borrowed/torn by a handler and SysTick/PendSV/IRQ | **PARTIAL.** Atomic `HandlerGuard`, single-dispatch assumptions, and explicit guards encode or mitigate documented races; many globals still depend on commented single-writer invariants. | Explicit interleaving/schedule that produces aliasing, stale state, torn update, or double use | ✅ model/Miri where possible |
| RT3 | **Exception nesting, re-entry, or priority inversion** | A blocking PendSV/UI path, unexpected IRQ, TAMP/GTZC handler, or nested fault deadlocks, starves service, or re-enters non-reentrant code | **OPEN CLAIM-VS-CODE TENSION.** Explicit handlers and a PendSV in-flight guard exist, but PendSV performs blocking PIN UI in exception context. `secure/src/main.rs` says PendSV has the lowest priority and cannot block SysTick, yet no SHPR/SCB priority programming was identified. Require a priority-register receipt; otherwise the blocking loop may starve SysTick/watchdog bookkeeping. Unexpected IRQs halt in WFE, and no system-wide nesting proof exists. | Forced IRQ/nesting trace plus SHPR/NVIC receipt showing preemption, deadlock, re-entry, cleanup, and deadlines | ⚠ target/model |
| RT4 | **Stack overflow, collision, or missing exception headroom** | Deep parse/keygen/sign/update plus nested exception frames crosses BSS or another RAM owner; no limit fault catches it | **HIGH-PRIORITY OPEN SURFACE.** Linker scripts set stack tops but no explicit MSPLIM/PSPLIM lower bound. FSBL source records a prior ~24.7-KiB frame against 16 KiB with no MSPLIM, fixed by removing manifest copies. | Static bound + map, canary/high-water test, adversarial nesting, MSPLIM fault test | ⚠ mixed |
| RT5 | **DMA/cache/coherence/volatile/peripheral ownership error** | CPU and peripheral reuse a buffer concurrently, cache/flash transition misses barriers, or a bus master escapes its intended range | **LATENT/PARTIAL.** No general active secure DMA path was found; USB endpoint/static memory, flash/ICACHE transitions, and future DMA require explicit ownership. Volatile alone is not synchronization. | Stale read, early reuse, missing barrier, concurrent owner, or DMA range escape | ⚠ target |
| RT6 | **Watchdog false-progress or false-bite** | A stalled system keeps feeding, a legitimate worst-case operation resets, or S/NS feature/attribution mismatch disables the liveness contract | **SOURCE-CONFIRMED BYPASS AND COVERAGE GAPS.** `secure/src/hw/iwdg.rs` uses the NS alias `0x4000_3000`, explicitly leaves IWDG NS-accessible, and `secure/src/sau.rs::configure_gtzc` does not secure-attribute it. Compromised NS can therefore write `KEY_RELOAD` indefinitely after Secure world stops feeding. Separately, `systick_watch_and_kick` treats `NS_HEARTBEAT_ADDR == 0` as unbounded boot grace; normal boot starts IWDG only after wizard/unlock, and the prodtest early branch never calls `hw::iwdg::init()`. Thresholds still need measured worst-case validation. | Direct NS reload after secure feed stops; never-register and repeated-register heartbeat traces; pre-init/prodtest stalls; frozen heartbeat, leaked guard, max sign/update/UI, and feature mismatch | ✅ host/model + ⚠ HW |
| RT7 | **Panic/fault/NMI cleanup or reset residue** | A fault leaves secrets in globals, stack, registers, SE sessions, or resumes from corrupt state; a panic halts forever with recoverable residue | **PARTIAL.** HardFault wipes global caches and resets; abnormal reset handling exists; panic wipes globals then WFI-halts. No explicit NMI policy or full live-stack/register scrub was found. | Injected fault/reset plus memory/register observation; control-flow proof of wipe-before-use | ⚠ target/asm |
| RT8 | **Unbounded work or resource exhaustion** | Legal hostile input, slow/malicious SE response, flash wait, UI state, or worst-case batch exceeds RAM/deadline and monopolizes S-world | **PARTIAL.** Stack-only/fixed buffers and many explicit timeouts bound local paths. Whole-system SRAM high-water, bus-stall, and worst-case latency are not established for the exact shipping profile. | Input/peripheral transcript exceeding a documented bound or preventing watchdog policy | ✅ fuzz/model + ⚠ HW |
| RT9 | **Initialization, teardown, clock, reset, or lock ordering** | IRQ fires before state is ready; a peripheral is used before clock/security attribution; config is locked too early; partial init leaves stale authority | **PARTIAL, WITH A CURRENT IWDG ORDER TARGET.** Normal `secure/src/main.rs` runs `setup_systick()` before `hw::iwdg::init()`, so SysTick can interleave `kick()` with START/ACCESS/PR/RLR programming; the IWDG is not started until after wizard/unlock. The prodtest early branch starts SysTick but never initializes IWDG. No total state-machine evidence covers clocks, SAU/GTZC locks, IRQ enablement, watchdog, SE sessions, reset causes, and every failure exit. | Force SysTick at every IWDG init write; exercise every pre-init and prodtest stall; otherwise seek use-before-init/wrong-order traces with exact register/state preconditions | ✅ model + ⚠ target |
| RT10 | **Flat privileged S-world blast radius / W^X gap** | A memory bug in display/parser/driver reaches keys, executable data, MMIO, or control-flow because all S code shares authority | **DOCUMENTED ARCHITECTURAL POSTURE; NO OWNER RISK ACCEPTANCE RECORDED.** No internal MPU/`CONTROL.nPRIV` regime is identified. File a concrete exploit chain or violated owner requirement, not merely the absence itself. | Memory-corruption primitive plus reachable cross-domain asset/control target | ❌ adversary |
| RT11 | **Host/model evidence substituted for ARM runtime reality** | Miri/Kani/host/QEMU/default-feature result is cited for CMSE, linker, MMIO, exception, timing, or stack behavior it never executed | **OPEN ASSURANCE SURFACE.** Host tests and target `cargo check` are useful but do not prove the canonical linked production image, exception schedule, or stack high-water. | Evidence/config matrix shows the claimed artifact/path was not built or executed | ✅ audit |

**Catalog rule.** Findings require behavior, not keyword counts. `rg` output for
`unsafe`, `static mut`, loops, or WFI is a review queue. Promote an item only
with a violated precondition, reachable interleaving, exceeded bound, wrong
artifact claim, or target trace. Conversely, do not dismiss RT4/RT6/RT11 as
“availability only”: a reset loop can strand funds, and resource corruption
can become key exposure or control-flow compromise.

---

## Part B — The existing defenses (Layer 1)

1. **Language and wrapper discipline.** `no_std`, fixed buffers, unsafe-op
   linting, typed MMIO registers, CMSE veneers, NS pointer validators, and
   closure-based accessors reduce the raw surface. Target-only preconditions
   still need manual and linked-artifact review.
2. **Scheduling guards.** `nsc::HandlerGuard`, trusted-UI wait guards, atomics,
   non-reentrant dispatch, shared sign-buffer ownership, and interrupt-free
   flash/OTP sections encode several hard-won interleaving constraints. Search
   for callers that touch the same state without the corresponding guard.
3. **Fault/reset handling.** Secure HardFault performs global zeroization then
   system reset; startup classifies abnormal resets; the production profile
   requires a secure-started, SysTick-serviced IWDG whose peripheral
   attribution is currently Non-Secure. Panic and unexpected-IRQ behavior are
   distinct and must not inherit HardFault claims automatically.
4. **Host/model checks.** Unit tests, Kani, fuzzing, Miri, source-text pins, and
   nightly target checks catch important regressions. Record which paths/cfgs
   each actually executes.
5. **Linker/capacity checks.** Hardware linker scripts, FSBL footprint tests,
   and `size-report` constrain sections. They do **not** establish stack
   high-water or exception-frame headroom; RT4 needs separate evidence.
6. **Runtime security configuration.** Explicit SAU/GTZC attribution/locking,
   exception dispatch, reset-cause handling, and peripheral initialization are
   sibling inputs. Cross-link their owners rather than duplicate-file local
   gateway or silicon findings.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS secure runtime behavior.
Break unsafe preconditions, singleton ownership, exception schedules, stack/RAM bounds,
watchdog progress, reset cleanup, initialization order, and target-vs-host assurance.
Do not report keyword counts as vulnerabilities and do not run hardware/destructive tests
without separate authorization.

TARGET (read first, in this order):
  - docs/security/adversarial-review/secure-runtime-resource-adversarial-review.md
    §A — RT1–RT11.
  - secure/src/{main,nsc/mod,nsc/state}.rs and every reachable production `unsafe` site.
  - secure/src/{sau,timeout,reset_cause,boot_ns}.rs and
    nonsecure/src/{main,nsc_api}.rs — attribution, waits, reset, handoff, heartbeat.
  - secure/src/hw/{iwdg,mmio,flash,otp,rng,hash,tamp,tzic}.rs + UI/SE drivers.
  - secure/memory-stm32u585.x, fsbl/memory-stm32u585.x, nonsecure/memory-stm32u585.x,
    linker maps, build scripts, and final linked artifact when available.
  - fsbl/src/{main,manifest,branch}.rs — prior stack-overflow witness and handoff.
  - threat-model §9.9 and sibling TrustZone/SCA-FI/USB/UI/lifecycle playbooks.
SCOPE THIS RUN: {{runtime subsystem, exception family, resource, or exact build profile}}.

ATTACK PROTOCOL — walk EVERY RT1–RT11 mode:
  RT1 unsafe precondition · RT2 shared-state race · RT3 exception nesting · RT4 stack ·
  RT5 DMA/cache/ownership · RT6 watchdog · RT7 fault/reset cleanup · RT8 exhaustion ·
  RT9 init/teardown order · RT10 privilege blast radius · RT11 evidence drift.

Before conclusions, record commit + dirty-tree state, Rust toolchain, target triple, exact
features/profile, linker script/map, artifact digest, and which code paths are cfg-reachable.
Build these inventories, then MANUALLY classify each reachable production site:
  unsafe/FFI/MMIO/volatile; static mut/atomic/critical section; exceptions/IRQ/NVIC;
  WFI/WFE/panic/reset; watchdog feeds/guards; loops/timeouts; stack-heavy buffers;
  DMA/cache/flash transitions; init/lock/teardown operations.

For each candidate finding produce a FALSIFIABLE PoC, one of:
  - Miri/UB failure or a concrete unsafe-precondition counterexample;
  - an explicit thread/ISR/exception interleaving producing bad state;
  - static or measured stack overlap/high-water/MSPLIM exception;
  - a watchdog trace showing feed without progress or reset during valid maximum work;
  - an input/peripheral trace exceeding a stated memory/time bound;
  - fault/reset evidence retaining a named secret or continuing from corrupt state;
  - an evidence matrix proving the cited host/config artifact never exercised the claim.
No PoC => list under “suspicions, unverified.”

REQUIRED EVIDENCE LADDER:
  1. Run applicable host tests/Miri/Kani and preserve failures/skips.
  2. Compile the exact ARM targets/features; distinguish cargo-check from linked execution.
  3. For a linked artifact, inspect size/map/nm/objdump and perform static stack analysis.
  4. Only with explicit authorization: target canary/high-water/MSPLIM, IRQ/watchdog/reset
     testing. Record board identity and build digest.
If production quarantine prevents an exact artifact, report that boundary; do not swap in
a bench build and call it production evidence.

RULES:
  - Cross-link TZ pointer/GTZC, USB framing, UI consent, SCA/FI physical fault/leakage,
    and durable-state findings to their owners. File here only the runtime composition.
  - Treat the flat S-world as posture unless you demonstrate a primitive and blast radius.
  - Do not “fix” liveness by feeding indefinitely or “fix” cleanup with destructive SE wipe
    on every recoverable fault; state availability and asset trade-offs.
  - Cite paths + unique symbols/strings, not line numbers alone.

FIRST-PASS OUTPUT — use the raw-report schema in
docs/planning-and-review-workflow.md §8; do not use the post-cross canonical
docs/security/adversarial-review/findings/TEMPLATE.md:
  Return secure-runtime-resource-<YYYY-MM-DD>-<partner-or-run>.md in external/isolated scratch output; do
  not edit the frozen repository or findings index. After both first passes and
  both cross-reviews freeze, an authorized maintainer may archive byte-for-byte
  copies in a separate reporting commit; only the frozen cross matrix feeds the
  canonical findings catalogue. Each candidate needs RT-mode, exact
  cfg/artifact, interleaving/bound, falsifiable PoC, severity, and proposed minimal
  correction. First-pass discovery must not assign canonical disposition or finding
  Status; the required exact partner pair does that only through symmetric
  cross-adjudication.

FILING — the coordinator files every kept adversarial-review candidate as a
GitHub issue on EthereumPhone/PQ1 (labels `finding`, `priority:*`, `surface:*`;
`ship-blocker` when the candidate gates production). The issue is the
actionable record; any report under findings/ remains the frozen evidence.
Phase-D merge-review outcomes are never filed as issues. Do not file issues
yourself unless the coordinator's brief says so.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. What I tried to break and COULDN'T — strongest schedule/input/stack/watchdog attempt.
  2. What I did NOT inspect — target-only unsafe, exceptions, peripherals, artifact, silicon.
  3. PROVENANCE — host/model/QEMU/cargo-check/linked-target/on-silicon table with cfg parity.
  Never equate section fit with stack safety or target compilation with target execution.
```

**Running it as a swarm.** Use separate adversaries for Rust soundness,
Cortex-M stack/exception scheduling, peripheral/init ordering, and watchdog /
worst-case resources. Cross-adjudicate every finding against the exact cfg and
artifact; many false positives come from reviewing a host-only or excluded arm.
These are supplemental lanes: apply the exact dual-partner, mutually withheld
first-pass, and symmetric cross-adjudication procedure in
[`docs/planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
swarm quorum never replaces either required partner or resolves its blocker.

---

## Part D — Cadence + honest boundary

- **Per-PR adding unsafe/shared state, an IRQ, long loop, large buffer, or
  watchdog exception:** run a scoped RT pass and update the ownership/bound
  comment plus an executable negative.
- **Per-milestone:** link the closest authorized production-shaped ARM image,
  inspect map/stack/resource evidence, and replay adversarial schedules in
  host models and QEMU where meaningful.
- **Before production authority:** obtain exact-profile on-target stack
  high-water/MSPLIM, watchdog, reset, and maximum-latency evidence.
- **The one-line gut check:** *under the worst legal input and worst permitted
  exception timing, what bounds stack, time, singleton ownership, and watchdog
  service—and did the evidence execute that exact target configuration?*

**The boundary, stated on purpose.** This playbook can establish code-level
ownership, scheduling, cleanup, and bounded-resource claims for executed
configurations. It cannot prove physical FI resistance, electrical/silicon
behavior, release provenance, human authorization, or durable transaction
atomicity. Host/Miri/Kani results do not execute CMSE/MMIO/exception reality;
on-target evidence remains necessary for those claims.
