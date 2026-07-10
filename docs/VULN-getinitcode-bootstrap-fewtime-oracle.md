# VULN — `CMD_GET_INIT_CODE` is an uncapped, unconfirmed bootstrap few-time-signature oracle

**Severity:** HIGH (master-key few-time-cap bypass; impact-if-exploited = full wallet takeover).
Practical-forgery reachability is bounded by the C10 FORS few-time margin + a keygen-bound
rate limit — see *Exploitation & honest caveat* below. The **invariant violation and the
missing controls are unambiguous**; the residual question is purely the crypto margin.

> **STATUS: ACCEPTED / KNOWN TRADEOFF (per user/owner decision, 2026-06-30). WON'T-FIX — do not
> re-raise.** The owner accepts this as a deliberate tradeoff: `GET_INIT_CODE` stays silent (no
> `confirm()`) so the companion's `eth_estimateUserOperationGas` flow works without a button press,
> and the per-call OptRand randomization stays (SCA / Genêt TCHES-2023 defense), accepting the
> theoretical few-time erosion because the practical forgery threshold (~2^28–2^32 distinct
> bootstrap sigs vs a keygen-bound ~80 sigs/unlock-window) is orders of magnitude beyond reach.
> The fixes below are recorded for completeness only; they are NOT scheduled. Documented so future
> vuln sweeps skip it (same disposition class as the paymaster-unshown WON'T-FIX).

**Status:** ACCEPTED KNOWN TRADEOFF (found 2026-06-30; owner-classified WON'T-FIX same day).
Novel — not in the prior finding ledger.

**Component:** `secure/src/nsc/cmd_get_init_code.rs` (CMD 15) + `secure/src/nsc/factory_calldata.rs`
+ `secure/src/crypto.rs` (`c10_sign_verified_with_progress`).

---

## Invariant violated

CLAUDE.md **Non-Negotiable Invariant #7**: *"Per-chain caps monotonic, unresettable.
`bootstrapUses < 65,536` … No `reset*` or `increaseMax*` path. Exhausted chains stay frozen."*

The bootstrap (master, `ownerIndex == 0`) SPHINCS+C10 key is a **few-time** key. The cap
`MAX_BOOTSTRAP_USES = 65,536` exists precisely to bound how many signatures it ever produces,
so its FORS few-time security holds. `CMD_GET_INIT_CODE` lets a malicious companion drive the
bootstrap key to produce an **unbounded** number of distinct signatures, **off the books** —
no counter, no cap, no user confirmation.

## The defect

`cmd_get_init_code::run` (CMD 15, dispatched unconditionally at `nsc/mod.rs:1230`, present in
every production build) does, on **every** call, after only a `pin_verified` check and with
**no `confirm()` / OLED gate** (`cmd_get_init_code.rs:30-35`, "No OLED confirmation"):

1. Re-derives the **bootstrap** C10 secret key (`cmd_get_init_code.rs:231`).
2. Calls `factory_calldata::build` → `crypto::c10_sign_verified_with_progress(&c10_sk, &factory_digest)`
   (`factory_calldata.rs:77`), producing a **bootstrap signature** over
   `factory_digest = sha256("pqwallet-factory-add-slot" ‖ chain_id ‖ slot0PkSeed ‖ slot0PkRoot)`.
3. Returns the signature to the non-secure world inside the 4280-byte initCode.

There is **no firmware-side bootstrap-use counter** anywhere (grep: the only `reset_bootstrap_uses`
hits are *test assertions that such a function must not exist*; the lone real constant is the
on-chain `MAX_BOOTSTRAP_USES`). The on-chain `bootstrapUses` cap (`PQMultiOwnable.sol`) is bumped
**only** by Type-1 UserOps in `validateUserOp`; these factory-authorisation signatures are never
submitted as Type-1 UserOps, so the on-chain cap **never observes them**. `CMD_GET_INIT_CODE`
also does **not** call `timeout::reset_activity()`, and bumps no page-123 counter.

## Root cause — a randomization regression + a stale "safely reusable" comment

The handler's own doc comment (`cmd_get_init_code.rs:23-28`) asserts the factory signature is
*"identical byte-for-byte to what the eventual real sign will emit"* and *"safely reusable."*
That **was** true when C10 signing was deterministic. It is **no longer true**:
`crypto.rs:101-135` (work-todo #18 / Trezor parity) now draws a **fresh 16-byte OptRand per
signing call** (`rng_strong::fill`, 3-source TRNG XOR) and mixes it into the R-grind, so

> *"re-drawing per sign … would produce divergent sigs"* — `crypto.rs:123-125`.

The randomiser is drawn **once per call** only so the within-call double-compute FI gate
(`sig_a == sig_b`) passes; **across calls it differs**, so every `CMD_GET_INIT_CODE` invocation
yields a **distinct** signature over the **same** `factory_digest`, landing at a fresh,
pseudo-random hypertree leaf (`ht_idx`) and consuming **fresh FORS few-time positions** of the
bootstrap key. The SCA/Genêt randomization (good in itself) silently invalidated the
"deterministic, reusable, one-position" assumption that made an uncapped, unconfirmed
`GET_INIT_CODE` safe — and no counter/cap was added to compensate. The stale doc comment is the
fingerprint of the oversight.

## Exploit chain (theft, if the few-time threshold is reached)

1. Attacker = malicious companion app / compromised USB host. User has unlocked (PIN entered).
2. Companion loops `CMD_GET_INIT_CODE(account_index, chain_id)`. Each call returns a fresh,
   distinct bootstrap signature over `factory_digest`. No confirm, no cap, no counter.
3. After collecting enough distinct signatures to erode the bootstrap key's FORS few-time
   security, perform a SPHINCS+ few-time forgery: produce a bootstrap signature over a **new**
   message — a Type-1 `userOpHash`/`sphincsDigest` whose `callData` is
   `addOwnerBytes(attacker_slot_pubkey)`.
4. Submit that forged Type-1 UserOp. `PQSmartWallet._validateSignature` (ownerIndex 0) accepts
   the forged bootstrap signature → installs the attacker's slot key as a new owner.
5. Attacker signs Type-2 UserOps with the attacker-controlled slot → **drains the wallet**.

The on-chain `bootstrapUses` cap does not help: step 4 is the *first* on-chain bootstrap use; the
thousands–millions of oracle signatures in step 2 never touched the chain.

## Exploitation & honest caveat (why the severity needs a crypto number)

- **Rate limit.** Each call re-derives the bootstrap SK (~1 s) + a double-compute sign (~0.5 s) ⇒
  ~1.5 s/call. `GET_INIT_CODE` does **not** extend the 120 s idle window
  (`timeout.rs:17`, `TIMEOUT_TICKS = 120000`), so a companion gets ~80 signatures per
  *user-initiated* unlock. Reaching the cap (2^16) takes ~800 unlocks; reaching a larger
  few-time-break threshold scales linearly.
- **Few-time margin.** CLAUDE.md says the 2^16 cap is *"well inside the C10 birthday margin."*
  The *actual* forgery threshold is therefore meaningfully above 2^16; if it is ~2^32 the attack
  is centuries-long, if it is closer to ~2^20 it is plausible over a device's multi-year life
  against a persistent companion. **The crypto team should quantify the C10 (k=13, a=11, w=8)
  FORS+C few-time forgery threshold to fix the severity exactly.**
- **What is unambiguous regardless of the number:** a non-negotiable invariant (#7) is violated
  for the *most powerful* key in the system, via a path with **no counter, no cap, and no user
  confirmation**, and the safety assumption it relied on (deterministic, reusable factory sig)
  is provably false in the current code.

## Fix (any one closes it; do (A) regardless)

- **(A) Deterministic factory signature.** Sign `factory_digest` with `opt_rand = None`
  (the R-grind already derives R deterministically from `sk_seed ‖ message ‖ nonce` when
  OptRand is absent — `crypto.rs:118`). Then repeated `GET_INIT_CODE` / counterfactual /
  INCLUDE_INIT_CODE calls return the **identical** signature, consuming exactly **one** few-time
  position — restoring the doc comment's "safely reusable" property and closing the oracle. The
  factory message is a fixed *public* authorisation, so dropping per-call OptRand here costs no
  meaningful SCA protection. **Also fixes the now-false doc comment** and the gas-estimation
  initCode-vs-real-sign divergence.
- **(B) Firmware bootstrap-use counter.** Mirror the per-slot `userop_sigs` page-123 tally with a
  durable per-`(account,chain)` *bootstrap* tally, bumped by **every** bootstrap-signing path
  (`GET_INIT_CODE`, `INCLUDE_INIT_CODE` in `cmd_sign_userop`, the ERC-6492 counterfactual in
  `cmd_sign_offchain`), and refuse past `MAX_BOOTSTRAP_USES`. This is the true firmware analogue
  of the per-slot cap that already backstops the slot keys.
- **(C)** At minimum, gate `GET_INIT_CODE` behind a `confirm()` (it produces master-key
  signatures) — though (A) is strictly better since it removes the few-time consumption entirely.

## Related

- Sibling (MEDIUM, firmware-backstopped): on-chain per-`ownerIndex` cap is resettable via
  `removeOwnerAtIndex` → `addOwnerBytes` re-add of the same slot pubkey at a fresh index
  (`PQMultiOwnable.sol:184/242`). Backstopped by the per-`slot_index` page-123 counter; see the
  memory note. Same class of bug: **on-chain caps key by storage index, not by key identity.**
- The per-*slot* keys are NOT affected by the GET_INIT_CODE oracle (it only signs with the
  bootstrap key). The slot keys are firmware-capped per `(account,chain,slot_index)`.

---

## UPDATE 2026-07-10 — practical-risk quantification (answers the "quantify the threshold" ask in *Exploitation & honest caveat*)

A follow-up USB-HID attack-surface sweep (5-agent adversarial audit + manual review) re-confirmed
this is the **only** USB-reachable, scriptable weakness on the whole surface — framing/reassembly,
command router, NS→S boundary + PIN gating, off-chain parsers, FW-update chunk staging, and the
USB-HID stack itself all came back clean. It also pins the crypto/rate numbers the caveat section
above left open. **Net conclusion: it is practically impossible to steal funds via this path; the
ACCEPTED / WON'T-FIX disposition stands.**

### 1. It is practically infeasible — the harvest is the wall, and it's measured in centuries

Two costs gate a forgery: harvesting the signatures, then the offline grind. The **harvest
dominates** and is throttled by the victim's own PIN cadence:

- **Forgery target:** ~2^28–2^29 distinct bootstrap signatures (FORS saturation for C10 `k=13,
  a=11` ⇒ ~2^18 hypertree instances × ~2^11 leaves ≈ 2^29 for straightforward forgery; somewhat
  fewer if trading signatures for offline hash-grinding). NB this yields **universal forgery**
  (assemble a signature on a chosen message) — **not** extraction of `sk_seed`, which stays behind
  a one-way PRF.
- **Harvest rate:** ~1.5 s/call, inside a **120 s idle window that `GET_INIT_CODE` does not
  reset** (S-only timer; USB/NS traffic cannot extend it) ⇒ **~60–80 signatures per
  *user-initiated* unlock**, then auto-lock. Keys are per-device, so **no cross-device
  parallelism** (forging device A needs device A's signatures).
- **⇒ Wall-clock to reach ~2^28 (~4 million unlock sessions):**
  | Victim behaviour | Time to harvest enough to forge |
  |---|---|
  | Realistic (~5 unlocks/day) | **~2,500 years** |
  | Heavy user (~50 unlocks/day) | **~250 years** |
  | Physically-absurd upper bound (victim unlocks 24/7, nonstop, does nothing else) | **~18 years** |
- The offline grind, once harvested, is comparatively trivial (days–weeks) and **cannot shortcut
  the harvest** (fewer signatures ⇒ grind cost blows back up toward full 2^128 security).

### 2. The unlock precondition makes it moot — anyone who can reach it already has a faster path to the funds

The oracle only fires on an **unlocked** device (correct PIN entered). There are exactly two ways a
device gets unlocked, and in **both** the attacker already holds a faster, more direct route to the
funds than a multi-century signature harvest:

- **Attacker has the PIN + the physical device.** They just unlock and confirm a send-all
  transaction on the trusted display — **instant, total drain**. The oracle grants them nothing
  they don't already have. (I.e. *with the right PIN you can already steal all the funds directly*;
  the oracle is a strictly worse, centuries-long detour to the same outcome.)
- **A compromised host piggybacks on the legitimate user's unlock** (this doc's canonical model).
  The host is capped at ~80 sigs per user unlock, and its *fastest* route to the funds isn't this
  oracle at all — it's social-engineering the user into confirming a malicious transaction on the
  trusted display, an unrelated attack that harvests nothing.

In every position from which the oracle is reachable, the actor already possesses a faster, more
direct path to the funds. **The oracle strictly dominates nothing**, and the harvest wall-clock
means there is **no realistic scenario in which it is exploitable to steal funds.**

### 3. Disposition unchanged; fix (A) remains the clean pre-launch closure

The quantification **supports** the original owner call — recorded here only to close the open
"quantify the C10 few-time threshold" question. The invariant-#7 violation is still real and worth
tidying **before mainnet value is on-chain**, and fix **(A) deterministic factory signature**
(`opt_rand = None`) remains the low-cost closure: it removes the cryptographic target entirely
(every harvested signature collapses to the single one already published on-chain at deploy), so
the safety margin no longer rests **solely** on the idle-lock throttle. Not scheduled; not a
blocker.
