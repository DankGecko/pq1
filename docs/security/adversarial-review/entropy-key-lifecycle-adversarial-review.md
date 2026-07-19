# Entropy, key generation, derivation, nonce, and key-lifecycle adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for reviewing the
entire path from physical random sources to wallet entropy, first-boot salts,
SPHINCS+C10 keys, device-bound KDF outputs, AEAD nonces, OptRand, shuffle
seeds, pairing credentials, and their eventual zeroization. The question is
not “does an RNG API exist?” but **which exact bytes each security claim
depends on, which sources contributed, whether each contribution was complete,
and whether derivation context and lifetime prevent cross-role reuse.**

> **Target claim.** Every cryptographic random consumer has an explicit source,
> length, freshness, failure, and health contract. Security-critical requests
> exact-fill and fail closed over their explicitly required source set, using
> the multi-source path wherever the consumer's security claim requires it; no
> build silently substitutes a mock or weaker RNG. Every derived key/nonce is
> unambiguously bound to its
> role, root, algorithm/version, account, chain, slot, and lifecycle epoch as
> applicable. Secret intermediates are neither exposed nor live longer than
> their stated operation.

**Sibling boundaries.** The [SCA/FI playbook](./sca-fi-adversarial-review.md)
owns physical leakage and fault resistance of signing; the
[secure-element playbook](./secure-element-adversarial-review.md) owns wire/APDU
correctness, local TRNG behavior, and chip key policy, while this playbook owns
whether callers enforce exact returned length and safely compose those bytes; the
[lifecycle playbook](./lifecycle-persistent-state-adversarial-review.md) owns
cross-store commit/recovery; and the
[production-configuration playbook](./production-configuration-prodtest-adversarial-review.md)
owns whether a weak/mock branch can ship. **This playbook owns the end-to-end
entropy and derivation contract that composes those pieces.** Statistical and
instrumented-silicon procedures stay in [`red-teaming.md`](../red-teaming.md).

> **Current EK2 closure.** `optiga::apdu::get_random` now requires the response
> payload length to equal the requested output length before it copies any
> byte. `OptigaTrustM::random_shielded_once` propagates that failure. The host
> regression covers exact, short, and overlong payloads and proves the output
> remains unchanged on rejection. This closes the code-level partial-fill
> defect; a live-chip malformed-response/fault receipt remains hardware
> validation, not a reason to describe the defect as still present.

---

## Part A — The entropy / key-lifecycle failure catalog (EK1–EK11)

| # | Failure mode | What it looks like | Status / anchor in this tree | Detection | Auto? |
|---|---|---|---|---|---|
| EK1 | **Consumer bypasses the required RNG tier** | Key/nonce/salt uses `rng::fill`, `rng::byte_nonsecret`, a deterministic test stream, or host randomness where `rng_strong` is required | **PARTLY DEFENDED, WITH TWO `rng-1` RAW-RNG CONSUMERS.** Source-text tests pin OptRand, shuffle, OTP-master, masking, seed wizard, and mnemonic-display decoys to expected APIs. BHK generation in `secure/src/hw/bhk.rs::provision` and the feature-gated ML-KEM message in `secure/src/pq_wrap.rs::seal_half_hw` use raw `rng::fill`; `docs/archive/work-todo-retired-2026-07-19.md` `rng-1` records the required platform-TRNG hardening. EK3 separately covers raw-RNG duress entropy/PIN behavior, and new consumers can still bypass the inventory. | Generated call-site inventory + policy allowlist by consumer class | ✅ structural |
| EK2 | **Short/partial read accepted as exact-fill** | An SE/APDU returns fewer bytes, the caller ignores the count, and stale/zero bytes are mixed as if the source fully contributed | **DEFENDED IN CODE.** OPTIGA `GetRandom` rejects every non-exact response length before copying; production and the reversible prodtest probe share that exact-length helper. Live-chip malformed-response/fault evidence remains open hardware validation. | Exact/short/overlong payload regression; require `Err` and unchanged output, then repeat on an authorized fixture | ✅ host / ⚠ HW |
| EK3 | **Error, retry, or fallback silently changes security** | Status flags are cleared without complete reconditioning, a retry reuses output/session state, or a “non-secret” fallback reaches a secret consumer | **MIXED, WITH TWO REVIEW TARGETS.** STM32 and SE failures are generally fatal after bounded recovery; `byte_nonsecret` and PIN-pad layout fallback are deliberate limited uses. `provision_duress_wallet` starts with platform RNG, treats `store.random()` failure as optional, and generates a declined-duress PIN from platform RNG only (`docs/archive/work-todo-retired-2026-07-19.md` `rng-2`). The custom STM32 init/recovery must be state-machine-equivalent against RM0456/errata, using CubeU5 HAL as the official implementation reference: local init returns silently on warm-up timeout, while ST reports failure and explicitly waits for conditioning reset. | Failure injection per source/call; taint fallbacks; differential state-machine model against RM0456/errata and CubeU5 | ✅ host + ⚠ HW |
| EK4 | **Stuck, repeated, biased, or correlated sources pass** | All-zero is rejected, but all-FF, repeated words, low Hamming weight, repeated requests, or correlated/cancelling XOR streams pass; source “independence” is asserted rather than tested | **PARTIAL / OPEN `rng-1`.** `rng_strong` has an all-zero aggregate gate and hardware status handling. The open platform-RNG work is post-DR seed-status validation, a nonzero-word check, and a continuous/repetition test. CubeU5 rechecks seed error after the DR read before releasing a word; verify state-machine equivalence against RM0456/errata rather than instruction identity. Statistical/source-independence evidence remains instrumented-bench work, not runtime proof. | Per-source capture on an authorized RDP0 instrumented device; repetition/continuous tests; NIST/AIS-31 analysis | ⚠ HW/statistical |
| EK5 | **XOR fold/packing/aliasing drops a source** | Buffer is overwritten instead of XORed, a temporary is reused uncleared, endian/chunk tails differ, or two logical sources are actually the same stream | **SOURCE-CONFIRMED LATENT CONTRACT DRIFT.** `rng_strong::fill` does not clear its 32-byte `block` between outer chunks, while `DualSecureElement::random` XORs into the supplied buffer rather than overwriting it. For requests over 32 bytes, chunk 2 therefore starts with the previous combined SE block; if the next combined block repeats, it cancels to zero. Current identified callers appear to request at most 32 bytes, so this is latent rather than a demonstrated live key compromise. The historical EK2 tail counterexample is now a closed regression, not a live second defect. | Independent sentinel streams at 33 and 64 bytes must prove each output chunk contains exactly its current source contributions; retain wider boundary/mutation tests | ✅ host |
| EK6 | **Wallet/key-generation or first-boot salt is weak/reused** | Mnemonic entropy is partial, a restore path accidentally generates, a decoy shares entropy, or RDP2-era pairing rotation uses pre-lock/stale/replayed salt | **MIXED; ITEM 36 CANDIDATE LANDED, `rng-3` AND PRODUCTION APPROVAL OPEN.** Seed-wizard entropy and mnemonic-display decoys use `rng_strong`; the duress wallet does not and instead has the EK3/`rng-2` behavior. The candidate post-lock flow draws, journals, and reuses one fresh salt across resumptions, but authenticated handoff/authenticate-before-rotate, old/new/KVN recovery, E140 ordering, and silicon power-cut evidence remain open. Seed creation is entirely device-generated, so it is not independently auditable against a malicious device/manufacturer RNG stack until the `rng-3` design decision is resolved. | Golden new-vs-restore state tests; forced RNG failures; reboot/retry salt uniqueness model; external-entropy commitment/verification design review | ✅ host / ⚠ HW |
| EK7 | **KDF domain/context collision or serialization drift** | Two roles share a label; account/chain/slot widths or endian change; a missing version/root/algorithm field maps distinct identities to the same key | **GOOD LOCAL TEST BASE, NOT EXHAUSTIVE.** `domain/tests/negative_derivation_independence.rs`, recovery KATs, and `hw::secret_keys` labels cover known roles. New labels and configuration branches require a global registry. | Extract label/call inventory; pairwise context-difference tests + cross-version golden vectors | ✅ host/structural |
| EK8 | **Nonce/key reuse across write, retry, restore, or rekey** | Deterministic AEAD nonce is used twice under the same key for different plaintext, session challenges repeat, or a restored root reuses a key/nonce epoch | **REASONED-LATENT REVIEW TARGET.** `domain` intentionally derives deterministic entropy-wrap nonces from the master; safety depends on a one-ciphertext-per-key lifecycle contract. Prove that contract or bind a version/counter/random nonce. | Stateful encrypt/write/reprovision model; compare `(key-id, nonce)` pairs and plaintext changes | ✅ model |
| EK9 | **Per-sign randomness loses freshness or independence** | OptRand is cached/replayed, two separate signing requests reuse it, shuffle A/B share a seed, retry semantics redraw the wrong value, or test cfg replaces draws | **LOCALLY DEFENDED.** The sign path draws one OptRand shared only across its required double-compute and independent shuffle seeds A/B, with zeroization/error tests. Review call-level retries and target builds. | Deterministic RNG transcript asserting exact draw count/order; repeated-sign differential; mutation tests | ✅ host + ⚠ SCA |
| EK10 | **Secret lifetime, diagnostic, or artifact leakage** | RNG source bytes, seed, KDF root/output, nonce-key pair, signing randomness, or test constant survives in stack/static memory, logs, crash state, USB prodtest, build artifacts, or core dumps | **PARTIAL.** Zeroize patterns and audits exist; target-only statics, panic/reset paths, prodtest samples, and compiler-elided wipes require separate evidence. | `zeroize-audit`, assembly inspection, log/string/artifact scan, reset-memory probes | ✅ static/asm + ⚠ HW |
| EK11 | **Root-selection or lifecycle/config downgrade** | A key derives from a hardcoded root, RDP0 shared DHUK, blank/stale BHK, DHUK fallback, legacy OTP root, or test constant under an unexpected feature/lifecycle state | **PARTIAL/OPEN.** Shipping fences reduce known bad combinations, but `derive_into_bhk` deliberately falls back when `bhk` is absent and item 36 changes the root at first boot. Configuration acceptance does not prove the live silicon root is correct. | Cross-product of features × RDP/BHK state with root-selection transcript/KAT and negative fences | ✅ host/config + ⚠ HW |

**Interpret results precisely.** A failure of one XOR contributor is not
automatically a wallet-key compromise; state the remaining sources and the
attacker capabilities needed to control or predict them. Conversely, “another
source was still random” does not make an exact-fill/status contract pass: a
silent degradation can invalidate fault assumptions, audits, or future
single-source configurations.

---

## Part B — The existing defenses (Layer 1)

1. **Strict failure propagation and exact OPTIGA fill, with a wider-chunk exception.**
   `secure/src/rng_strong.rs` fills from the platform RNG, propagates
   production SE failure, wipes its temporary, and rejects an all-zero result;
   `secure/src/dual_se.rs::random` requires OPTIGA and SE050 locally. OPTIGA
   exact-fill is pinned by EK2; wider per-chunk composition remains incomplete
   until EK5 is fixed.
2. **Hardware and transport status checks.** `secure/src/hw/rng.rs` handles
   STM32 RNG seed/clock status and bounded recovery; OPTIGA random traverses
   the Shielded Connection; SE050 random traverses SCP03. Those properties do
   not by themselves prove response length or entropy quality.
   Compare that custom state machine with the official local CubeU5 driver's
   `Drivers/STM32U5xx_HAL_Driver/Src/stm32u5xx_hal_rng.c` (the sibling checkout
   is currently `/home/nicola/repos/STM32CubeU5`),
   especially conditioning-reset completion, seed-error recovery, and the
   post-DR-read seed-error check. A difference is a review lead, not by itself
   proof of predictable output.
3. **Consumer pins.** `secure/src/secure_fi_pin_rng_pure_tests.rs`,
   `secure/src/secure_crypto_glue_under_test/`, and UI/hardware pure tests pin
   several important consumers to `rng_strong`, fail-closed branches, and wipe
   behavior. Treat source-text assertions as change detectors, not semantic
   proof.
4. **Derivation evidence.** `domain/tests/{positive_derivation,negative_derivation_independence}.rs`,
   recovery KATs, CMAC/HKDF tests, and `secure/src/hw/secret_keys.rs` provide a
   strong seed corpus for context-binding and cross-backend differential tests.
5. **Physical/statistical sibling.** [`red-teaming.md`](../red-teaming.md)'s
   entropy section calls for an instrumented RDP0 build with per-source capture
   and statistical analysis. A shielded-bus capture only shows ciphertext and
   cannot establish TRNG quality.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS entropy and key lifecycle.
Trace actual bytes from every physical/host/mock RNG through mixing, key generation,
KDF/nonce derivation, use, persistence, retry/reset, and zeroization. Break the stated
source/length/freshness/domain contract; do not settle for “XOR of three RNGs is safe.”
Do not flash diagnostic/prodtest firmware, collect live entropy, provision roots, or run
instrumented/destructive hardware procedures unless the irreversible-action gate in
docs/planning-and-review-workflow.md is satisfied by a separate owner instruction naming
the exact operation and board/device. Otherwise use synthetic sentinels and host models.

TARGET (read first, in this order):
  - docs/security/adversarial-review/entropy-key-lifecycle-adversarial-review.md
    §A — EK1–EK11 and the EK2 exact-fill regression.
  - secure/src/{rng,rng_strong,dual_se,crypto}.rs; secure/src/hw/{rng,secret_keys,otp}.rs.
  - secure/src/optiga/{mod,apdu}.rs and secure/src/se050/{mod,apdu,scp03}.rs.
  - domain/src/lib.rs + domain/tests/*derivation*.rs; sphincs-c10 signing/shuffle APIs.
  - secure/src/ui/{seed_wizard,pin_entry}.rs and all prodtest/diagnostic RNG consumers.
  - Drivers/STM32U5xx_HAL_Driver/Src/stm32u5xx_hal_rng.c + matching HAL/LL
    headers in the official sibling STM32CubeU5 checkout (currently
    /home/nicola/repos/STM32CubeU5) — official STM reference behavior.
  - docs/security/red-teaming.md entropy/SCA sections and docs/archive/work-todo-retired-2026-07-19.md item 36.
SCOPE THIS RUN: {{consumer family, RNG source, KDF family, lifecycle epoch, or build profile}}.

ATTACK PROTOCOL — walk EVERY EK1–EK11 mode:
  EK1 wrong tier · EK2 short read · EK3 error/retry/fallback · EK4 health/correlation ·
  EK5 mix/packing/alias · EK6 keygen/first-boot salt · EK7 domain/context drift ·
  EK8 nonce/key reuse · EK9 per-sign freshness · EK10 lifetime/leakage ·
  EK11 root/lifecycle/config downgrade.

Start with two machine-readable ledgers:
  (A) consumer -> required byte count, source set, freshness scope, failure behavior,
      allowed build profiles, persistence, zeroization;
  (B) derived output -> root, primitive, exact label/preimage, context widths/endian,
      version, purpose, output length, lifetime.
Flag every call or label missing from those ledgers.

Exercise requested/returned lengths 0, 1, 7, 8, 16, 31, 32, 33, 128, 224, 225,
and 256. Prefill all output and temporary buffers with nonzero sentinels so a short
success or partial-error suffix is visible. For STM RNG, build a state-transition
comparison against CubeU5 for CONDRST completion, SEIS/SECS/CEIS/CECS handling,
timeouts, DRDY, and the status check immediately after reading DR.

For each candidate finding produce a FALSIFIABLE PoC, one of:
  - source stubs returning 0..requested bytes, errors, repeats, all-00/all-FF, or
    identical/cancelling streams, with the exact consumer outcome;
  - a build/config where a secret consumer reaches a mock/weaker/fallback path;
  - two distinct roles/contexts/versions producing the same derivation preimage/output;
  - a state trace reusing `(key-id, nonce)` for different plaintext or freshness epochs;
  - an assembly/log/memory artifact retaining a named secret after its wipe boundary.
No PoC => “suspicion, unverified.” Statistical oddity alone is not a cryptographic break;
record sample size and test.

RULES:
  - Distinguish entropy COMPROMISE, silent DEGRADATION, availability failure, and claim drift.
  - Never log or paste live secret/entropy bytes into the report; use synthetic sentinels,
    hashes, lengths, and pass/fail transcripts.
  - Test odd lengths and chunk boundaries. An API returning Result is not exact-fill unless
    the callee/caller jointly enforce the requested length.
  - Preserve recovery/address compatibility when changing KDF tags. A “better” tag that
    silently changes existing wallet keys is a security regression.
  - Cite paths plus unique symbols/labels; do not rely on stale line numbers.

FIRST-PASS OUTPUT — use the raw-report schema in
docs/planning-and-review-workflow.md §8; do not use the post-cross canonical
docs/security/adversarial-review/findings/TEMPLATE.md:
  Return entropy-key-lifecycle-<YYYY-MM-DD>-<partner-or-run>.md in external/isolated scratch output; do not
  edit the frozen repository or findings index. After both first passes and both
  cross-reviews freeze, an authorized maintainer may archive byte-for-byte copies
  in a separate reporting commit; only the frozen cross matrix feeds the canonical
  findings catalogue. Each candidate needs EK-mode, affected
  consumer/output, source/root and remaining entropy assumptions, synthetic PoC,
  severity, and proposed minimal correction. First-pass discovery must not assign
  canonical disposition or finding Status; the required exact partner pair does that
  only through symmetric cross-adjudication.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. What I tried to break and COULDN'T — strongest stub/vector per consumer or KDF role.
  2. What I did NOT inspect — sources, consumers, labels, configs, compiler output, silicon.
  3. PROVENANCE — tests/audits/statistical suites actually RUN vs source read only; identify
     whether data came from instrumented silicon, QEMU/host, or mocks.
  Never infer physical entropy quality from ciphertext-looking bus traffic.
```

**Running it as a swarm.** Use independent reviewers for (1) source/error
contracts, (2) consumer/freshness inventory, (3) KDF/nonce/context registry,
and (4) lifetime/assembly/diagnostic leakage; then cross-check that every
consumer has exactly one owner in both ledgers. These are supplemental lanes:
apply the exact dual-partner, mutually withheld first-pass, and symmetric
cross-adjudication procedure in
[`docs/planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
swarm quorum never replaces either required partner or resolves its blocker.

---

## Part D — Cadence + honest boundary

- **Per-PR adding an RNG call, key, label, nonce, or secret buffer:** update the
  consumer/derivation ledgers and run boundary-length plus failure-injection tests.
- **Per-PR touching cfg/features:** prove secret consumers cannot reach mock,
  host-only, hardcoded, or non-secret fallback branches in the candidate profile.
- **Per-milestone:** rerun derivation KAT/differential tests, zeroize/assembly
  checks, and an adversarial exact-draw transcript over signing/provisioning.
- **Pre-ship and after silicon/RCC/SE firmware changes:** repeat instrumented
  per-source statistical/health testing under the authorized bench plan.
- **The one-line gut check:** *for this exact output byte, which independent
  sources and context bytes influenced it, what proves every requested byte
  arrived, and what happens if any one source lies or stops?*

**The boundary, stated on purpose.** Code review and deterministic stubs can
prove source-level exact-fill, mixing, failure, domain, nonce, and lifetime
contracts. They
cannot certify physical entropy, independence, or compiler/silicon erasure
without statistical, assembly, and on-device evidence. XOR preserves the
entropy of an independent honest source; it does not establish that such a
source exists.
