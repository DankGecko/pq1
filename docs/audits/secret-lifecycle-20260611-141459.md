# audit:secret-lifecycle — Security Audit (20260611-141459)

**Auditor:** adversarial secret-lifecycle pass (zeroization, constant-time, side-channel exposure)
**Target:** PQSigner OS firmware — STM32U585 / Cortex-M33 TrustZone secure world, OPTIGA Trust M V3 + SE050, SPHINCS+C10.
**Disposition:** 3 MEDIUM + 1 LOW; **no CRITICAL or HIGH found.** The secret-handling discipline is mature; every finding below is an *incomplete-zeroization / defense-in-depth* gap gated on physical access, not a companion/NS-triggerable extraction.

**Status update:** MEDIUM-1, MEDIUM-2, and MEDIUM-3 were fixed in the same commit that adds this report (search the diff for the `audit secret-lifecycle 20260611` markers). The findings below are retained as the as-discovered record. The LOW (`ShuffleSeed` `Clone`) is left as documented — no live leak — and is a recommended follow-up.

---

## Scope & threat model

In scope: the lifecycle of every secret — PIN, BIP-39 entropy, the two XOR halves (`half_O`/`half_E`), master/slot SPHINCS+C10 keys, derived subkeys (PBS, SCP03, admin PIN), and the per-signature randomizers (`opt_rand`, shuffle seed). The required properties:

- secrets live **only** in TrustZone secure SRAM (invariant #4), never NS, never plaintext on I2C (invariant #3), each chip gets only one XOR half (invariant #1);
- secrets are **zeroized** on lock / tamper / brownout / idle-timeout;
- no secret-dependent timing/power branch; secret comparisons use `subtle`;
- secret types are `!Copy + !Clone` and `ZeroizeOnDrop`.

Threat model per engagement rules: NS world + USB companion fully attacker-controlled and maximally hostile; for physical surfaces, a patient attacker with the device, a logic analyzer on the SE I2C buses, and the ability to desolder/replace a secure element. Severities are wallet-impact (theft / seed-or-key extraction / PIN bypass / forgery / WYSIWYS), not generic CVSS.

## Methodology — what I read and how I hunted

Traced concrete secret data-flow end-to-end across:

- **State + lifecycle:** `nsc/state.rs` (`SecureState`, `SLOT_CACHE`, `zeroize_sensitive`, `mark_unlocked`), `nsc/mod.rs` (`gated_unlock`, `zeroize_sensitive_state`, `HandlerGuard`, the `compile_error!` dev-feature fences), `nsc/cmd_lock.rs`, `timeout.rs`, and the SysTick / PendSV / panic wiring in `main.rs:3640-3850`.
- **KDF chain + wrap:** `domain/src/lib.rs` (BIP-39→C10, slot derivation, AES-GCM blob, `with_bip39_seed`), `secure/src/crypto.rs` (`c10_sign_verified_with_progress`, `provision_from_mnemonic`).
- **Sign hot-paths (where keys live in SRAM):** `cmd_sign_userop.rs` (full, 1628 lines), `cmd_sign_offchain.rs` (full), `cmd_sign_userop_batch.rs` (wipe discipline), `cmd_request_unlock.rs`, `pin.rs`.
- **Hardware secret material:** `hw/secret_keys.rs`, `hw/huk.rs`, `hw/otp.rs`, `hw/saes.rs`, `hw/saes_cmac.rs`, `hw/consumption_mask.rs`, `sign_rate.rs`, `rng_strong.rs`.
- **Dual-SE + drivers:** `dual_se.rs` (entropy reconstruction), `se050/mod.rs`, `se050/scp03.rs`, `optiga/mod.rs`, `optiga/shield.rs`, `secure_element.rs`.
- **UI secret paths:** `ui/secret_text.rs`, `ui/pin_entry.rs`, `ui/seed_wizard.rs` (constant-time blit, `ui-capture` gating).
- **FI primitives:** `fi.rs` (`zeroize_barrier`, `wait_random`, sentinels, `read_volatile_voted`).

Hunting technique: for every secret buffer I located its creation, every consumer, and every exit path (including early-return / error / FI-reject branches), asking "is it wiped, and is the wipe reachable on all paths?" For the cross-cutting questions (consumption-mask cadence, debug-log/ui-capture leak surface, Copy/Clone on secret types, SE-driver half handling) I fanned out read-only sub-agents and then independently re-verified every claim against source before accepting it — several agent claims were over-stated and are corrected in "Surfaces examined and judged clean."

I also hunted specifically for **un-fixed siblings** of the resolved findings in CLAUDE.md/memory: the `account_deployed` FI-OOB (output size chosen by an un-FI-hardened bool → NS-boundary overrun), the raw32 UserOp-forgery oracle, and the WYSIWYS hidden-value class.

---

## Findings (ordered by severity, most severe first)

### [MEDIUM-1] SE channel session keys (SCP03 + Shielded Connection) are never zeroized on lock — they persist in secure SRAM through the entire locked state

- **Location:**
  - `secure/src/se050/scp03.rs:93-103` — `Scp03Session { s_enc, s_mac, s_rmac, mcv, counter }`, **no `Drop`, no `Zeroize`, no `ZeroizeOnDrop`** anywhere in the file.
  - `secure/src/se050/mod.rs:132-152` — `struct Se050 { … scp03: Scp03Session, … }` (the session lives inside the driver).
  - `secure/src/se050/mod.rs:2808-2816` — `zeroize_caches()` wipes `entropy_blob_cache`/`vk_cache`/`bootstrap_vk_cache` but **not** `self.scp03`.
  - `secure/src/optiga/shield.rs:74-103` — `ShieldedConnection { enc_key, dec_key, … }`; `:485-492` — it *does* have a zeroizing `Drop`.
  - `secure/src/optiga/mod.rs:78-90` — `struct OptigaTrustM { … shield: ShieldedConnection, … }`.
  - `secure/src/optiga/mod.rs:2735-2742` — `zeroize_caches_internal()` omits `self.shield`.
  - `secure/src/main.rs:472` / `:476` / `:480` — `static mut SE: …` (the driver is a process-lifetime singleton, so its `Drop` **never runs** in production).
  - `secure/src/nsc/mod.rs:770-781` — `zeroize_sensitive_state()` → `SE.zeroize_caches()` (the only thing lock / idle-wipe / panic / lockout call).

- **Vulnerability class:** Incomplete zeroization of a secret on lock; dead-code `Drop` on a `'static` singleton; secret outliving its need.

- **Attacker & required capability:** Physical. (a) A logic analyzer on one SE's I2C bus during a legitimate unlock; (b) a secure-SRAM read primitive against the *locked* device (cold-boot / debug-port / RDP-downgrade). Not NS/companion-reachable.

- **Exploitation path:**
  1. During unlock, `OptigaTrustM::authenticate_and_read` reads the **raw** `half_O` and the **raw** `master_secret` straight off the chip over the Shielded Connection: `secure/src/optiga/mod.rs:2290-2296` (`read_data_object(OID_ENTROPY …)`, `read_data_object(OID_MASTER_SECRET …)`), only then GCM-wrapping them into the cache (`:2333-2334`). The bus payload is protected **only** by the shield session keys `enc_key`/`dec_key`. SE050/SCP03 is symmetric for `half_E`.
  2. Attacker captures that encrypted I2C transcript with a logic analyzer (in scope per the threat model).
  3. The user locks (CMD_LOCK), the device idles out (SysTick wipe, `main.rs:3683`), or it panics. Each calls `zeroize_sensitive_state` → `SE.zeroize_caches()`, which wipes `master_secret` (in `SecureState`) and the entropy/VK caches — **but leaves `scp03.s_enc/s_mac/s_rmac` and `shield.enc_key/dec_key` intact in SRAM.** They remain until the *next* unlock re-derives over the same fields.
  4. Attacker now extracts secure SRAM (locked state) and recovers the persisted session keys.
  5. Decrypting the captured transcript with those keys yields the raw `half_O` (OPTIGA) or `half_E` (SE050) — and the raw `master_secret` — directly off the wire. Repeating against the other chip yields the second half; `half_O ⊕ half_E` = full BIP-39 entropy = seed extraction (breaks invariants #1 and #4).

- **Invariant / property broken:** "Zeroize on lock/tamper/brownout/inactivity" (lifecycle); invariant #3 (the session keys are the *sole* on-wire protection of the half and master, so their post-lock persistence re-exposes the I2C-plaintext that #3 forbids); ultimately invariants #1/#4.

- **Evidence:**
  ```rust
  // se050/scp03.rs:93   — secret session keys, NO Drop/Zeroize in the whole file
  pub struct Scp03Session {
      pub s_enc: [u8; 16],
      pub s_mac: [u8; 16],
      pub s_rmac: [u8; 16],
      pub mcv: [u8; 16],
      pub counter: [u8; 16],
      pub active: bool,
  }
  // se050/mod.rs:2808   — zeroize_caches() never touches self.scp03
  fn zeroize_caches(&mut self) {
      use zeroize::Zeroize;
      self.entropy_blob_cache.zeroize();
      self.blob_cached.set_false();
      self.vk_cache.zeroize();
      self.vk_cached = false;
      self.bootstrap_vk_cache.zeroize();
      self.bootstrap_vk_cached = false;
  }
  // optiga/shield.rs:485 — Drop zeroizes the shield keys … but SE is `static mut` so this never runs
  impl Drop for ShieldedConnection {
      fn drop(&mut self) {
          self.enc_key.zeroize();
          self.dec_key.zeroize();
          …
      }
  }
  // optiga/mod.rs:2290 — raw half + master cross the channel during unlock
  read_data_object(&mut self.ifx, &mut self.shield, apdu::OID_ENTROPY, 0, 32, &mut entropy …)?;
  read_data_object(&mut self.ifx, &mut self.shield, apdu::OID_MASTER_SECRET, 0, 32, &mut master_secret …)?;
  ```

- **Suggested fix (describe only):** Add an explicit teardown that `zeroize_sensitive_state` invokes on every SE backend: zeroize `Scp03Session.{s_enc,s_mac,s_rmac,mcv}` and `ShieldedConnection.{enc_key,dec_key,enc_nonce_base,dec_nonce_base}` and set `active=false` (forcing re-establishment on next unlock). Mark `Scp03Session` `#[derive(ZeroizeOnDrop)]` (or a manual zeroizing `Drop`) for defense-in-depth, but do **not** rely on the singleton's `Drop` — wire the wipe into `zeroize_caches`/lock. Follow each wipe with `crate::fi::zeroize_barrier()`.

- **Confidence:** confirmed (code paths verified directly). The end-to-end seed-recovery requires two independent physical capabilities and compromise of both chips, which is why this is MEDIUM rather than HIGH — but note its *impact class is seed extraction*, so it sits at the top of the MEDIUM band; if the production SRAM-readout assumption is weaker than expected (RDP2 + TZ not fully closing debug readout of a locked device), it escalates.

---

### [MEDIUM-2] SPHINCS+ secret `sk_seed` transient left un-zeroized on the stack in the shared keypair-derivation helpers

- **Location:**
  - `domain/src/lib.rs:567-578` — `derive_c10_master_keypair_from_entropy_with_progress`: `sk_seed_32` (line 573) is consumed by keygen, **not returned, not zeroized**.
  - `domain/src/lib.rs:674-690` — `derive_c10_slot_keypair_with_progress`: the *slot entropy* IS wiped (`entropy.zeroize()`, line 683) but the derived `sk_seed_32` (line 682) is **not**.
  - `domain/src/lib.rs:284-287` — `derive_signing_key`: `sk_seed` from `split_seed_48` is moved into `SigningKey::keygen` (a `Copy` `[u8;32]`, so the source copy survives) and is not zeroized.
  - Consumers (every sign handler, every keygen): `cmd_sign_userop.rs:1121-1127` (slot) / `:1199-1204` (master); `cmd_sign_offchain.rs:689-695` / `:827-832`; `cmd_sign_userop_batch.rs:892`.

- **Vulnerability class:** Incomplete zeroization of a signing-key-equivalent secret (intermediate KDF buffer / stack copy not wiped). Inconsistent with the same file's own discipline.

- **Attacker & required capability:** Physical — a secure-SRAM read against the (narrow) window after the helper returns and before its popped stack frame is reused. Not NS/companion-reachable.

- **Exploitation path:**
  1. Any sign that triggers a fresh keygen (cross-chain/cross-slot Type-2, or a deploy/rotation/counterfactual master keygen) calls `derive_c10_{slot,master}_keypair_with_progress`.
  2. The helper writes the 32-byte secret `sk_seed_32` to its stack frame, hands it to `SigningKey::keygen`, then returns `(sk, pk_seed_32, pk_root_32)` — **without** zeroizing `sk_seed_32`. The bytes remain in the popped frame.
  3. An attacker who reads that SRAM region before it is overwritten recovers `sk_seed`. Combined with the *public* `pk_seed` (it is published in the on-chain 64-byte owner bytes), `sk_seed` reconstructs the entire `SigningKey` → arbitrary signature forgery for that slot/wallet → fund theft.

- **Invariant / property broken:** Zeroize-after-use of every secret (CLAUDE.md "Code Conventions" — `ZeroizeOnDrop`/compiler-fence on every secret); contributes to the invariant-#4/#5 protection of the single signing primitive.

- **Evidence:**
  ```rust
  // domain/src/lib.rs:567 — master keypair: sk_seed_32 never wiped
  pub fn derive_c10_master_keypair_from_entropy_with_progress(…) -> (SigningKey, [u8; 32], [u8; 32]) {
      progress(0);
      let (pk_seed_32, sk_seed_32) = derive_c10_master_from_entropy(entropy, account_index);
      progress(10);
      let (sk, pk_root_32) = c10_keygen_from_n_masked_seeds(&sk_seed_32, &pk_seed_32);
      progress(100);
      (sk, pk_seed_32, pk_root_32)            // sk_seed_32 dropped un-zeroized
  }
  // domain/src/lib.rs:674 — slot keypair: entropy IS wiped, sk_seed_32 is NOT
  let mut entropy = slot_entropy(master_entropy, chain_id, slot_index);
  let (sk_seed_32, pk_seed_32) = derive_c10_slot_seeds(&entropy);
  entropy.zeroize();                          // good …
  let (sk, pk_root_32) = c10_keygen_from_n_masked_seeds(&sk_seed_32, &pk_seed_32);
  …                                           // … but sk_seed_32 never zeroized
  ```
  Contrast the *correctly* wiped siblings in the same file: `with_bip39_seed` zeroizes `bip39_seed` (`:271`), `derive_signing_key_from_entropy` zeroizes `slh_seed` (`:326`), `derive_c10_master_from_bip39_seed` zeroizes `master` (`:525`).

- **Suggested fix (describe only):** In both `_keypair_with_progress` helpers and in `derive_signing_key`, hold the secret seed in a `zeroize::Zeroizing<[u8;32]>` (or call `.zeroize()` on `sk_seed_32` immediately after `c10_keygen_from_n_masked_seeds` consumes it). These are pure-logic crate fns, so use the `zeroize` crate directly (already a dep); the secure-side `zeroize_barrier` is not available there, which is fine — the goal is dead-store-resistant wipe, which `Zeroizing`/`Zeroize` provide.

- **Confidence:** confirmed. Severity is MEDIUM, not HIGH, because (a) exploitation needs secure-SRAM extraction in a tight pre-clobber window — the immediately-following multi-second C10 keygen+sign hammers the stack and very likely overwrites the region — and (b) an attacker able to read SRAM during the unlock session already holds the live `SigningKey` and `master_secret`. The marginal exposure is real but small; it is reported because it is a clean, easily-closed inconsistency on the most sensitive secret class.

---

### [MEDIUM-3] Power-consumption SCA mask (`consumption-mask`) is implemented correctly but absent from the shipping build recipes — the ~7 s SPHINCS+ window runs unmasked

- **Location:** `secure/src/hw/consumption_mask.rs` (whole module); `secure/src/main.rs:3669-3670` (`randomize()` from SysTick); `secure/Cargo.toml:157-158` (`consumption-mask = ["stm32u585"]`); `Makefile` build recipes (no recipe enables it — default `FEATURES ?= mock-se,debug-log,ui-semihosting`; the OLED-hardware and real-SE recipes likewise omit it).

- **Vulnerability class:** Defense-in-depth not enabled in shipping configuration (the *mechanism* is correct).

- **Attacker & required capability:** Physical — a bench CPA/DPA rig with a power probe near the die, collecting traces over the multi-second SPHINCS+C10 keygen/sign.

- **Exploitation path / analysis:** I confirmed the mechanism works *when enabled*: `randomize()` is driven from the `#[cortex_m_rt::exception] SysTick` handler (`main.rs:3642`, call at `:3670`), which fires ~1 ms; the secure CMSE sign veneer runs with interrupts enabled, so SysTick preempts it and re-jitters the TIM2-CH1 PWM duty thousands of times across the sign window — i.e. the mask is *not* static during signing (this was the specific concern in the mission brief, and it is **not** a defect). The defect is that no observed build recipe turns the feature on, so a device built per the current Makefile presents an *un-diluted* power signature during exactly the window the rate-limiter (`sign_rate.rs`: 250/session, ≥1 s/sign) and the F-16 shuffle are meant to be layered with. CPA against the non-hardened HASH peripheral is the documented threat in the module header.

- **Invariant / property broken:** No formal invariant; this is a HARDENING.md / SCA-defense layer that the firmware ships without.

- **Suggested fix (describe only):** Enable `consumption-mask` (and confirm PA5 is free) in the production build recipe, or document an explicit risk-acceptance. If accepted, ensure the rate-limiter + shuffle are treated as the sole SCA defenses and sized accordingly.

- **Confidence:** needs-confirmation. I reviewed Makefile recipes, not the final factory/production build manifest; if the production recipe enables `consumption-mask`, this finding is moot. Flagging so the production feature set is checked against the SCA threat model.

---

### [LOW] `ShuffleSeed` (a per-signature secret) derives `Clone`, against the `!Copy + !Clone` secret-type convention

- **Location:** `sphincs-c10/src/shuffle.rs:36` — `#[derive(Clone, Zeroize, ZeroizeOnDrop)] pub struct ShuffleSeed(pub [u8; 32]);`

- **Vulnerability class:** Secret-type convention violation (latent footgun).

- **Analysis:** The shuffle seed is per-signature DPA-defense secret material. CLAUDE.md requires secret types be `!Copy + !Clone`. It is correctly `!Copy` and `ZeroizeOnDrop`, but the stray `Clone` derive would let a future caller silently duplicate it into a transient that may outlive the `ZeroizeOnDrop` guarantees of the original. I verified there is **no `.clone()` call site** today (`grep` across `secure/src` and `sphincs-c10/src`), so no transient copy is actually created — this is latent, not a live leak, hence LOW.

- **Suggested fix (describe only):** Drop `Clone` from the derive. In `crypto::c10_sign_verified_with_progress` the seed is constructed once and passed by reference to both double-compute signs, so removing `Clone` does not affect the hot path.

- **Confidence:** confirmed (no exploit; convention hardening).

---

## Surfaces examined and judged clean (with the reason each is safe)

- **Both on-chain sign handlers (`cmd_sign_userop.rs`, `cmd_sign_userop_batch.rs`) and the off-chain handler (`cmd_sign_offchain.rs`):** every stack-local secret (`master_secret`, `entropy_blob`, `entropy`, `slot_master_entropy`, the inner ERC-6492 wrappers) is wrapped in `zeroize::Zeroizing`, so it is wiped on *every* exit including early error/FI-reject returns; explicit `entropy.zeroize() + zeroize_barrier()` is added belt-and-braces on error paths (`cmd_sign_userop.rs:1082, 1166, 1232, …`). The bootstrap `c10_sk` and the slot key are `SigningKey` (ZeroizeOnDrop) and are `drop`-ped / held in `SLOT_CACHE` (replaced via `*ptr = Some(...)`, dropping and zeroizing the prior key). `SNAP_BUF` is wiped on entry *and* exit (`cmd_sign_userop.rs:160-165, 1548-1553`). Output writes are FI-hardened verify-before-release with double `sphincs_c10::verify`.
- **`account_deployed` OOB sibling hunt (the resolved CRITICAL):** in `cmd_sign_userop.rs` the response writes are fixed-size constants gated by `emit_init_code`/`emit_type1`, and the *maximum* possible write equals `MAX_SIGN_RESPONSE_LEN` exactly (`proto/src/lib.rs:1221`: `8 + 4 + PQ_INIT_CODE_LEN + 4 + SIG_TYPE1_LEN + 4 + SIG_TYPE2_LEN`), which was validated against NS up front — so a glitched emit flag cannot drive an out-of-bounds write. `cmd_sign_offchain.rs:797-803` re-validates the full 8616-byte 6492 extent *inside* the `else` branch through a Hamming-distant sentinel (the documented fix). No un-fixed sibling found.
- **`gated_unlock` + `cmd_request_unlock` (PIN path):** PIN is captured in S-world trusted UI and never crosses to NS; the caller's copy is `pin_copy.zeroize()`-d (`cmd_request_unlock.rs:43-44`), PendSV re-unlock zeroizes its `pin` (`main.rs:3803-3804`), `pin_entry.rs` wipes its working buffers on every path (`wipe_pin`, `enter_pin_with_confirm` zeroizes `a/b/f`). `mark_unlocked` zeroizes the prior `master_secret` *before* overwrite (HIGH-6, `state.rs:286-296`). FI sentinels + double-reads throughout.
- **Inactivity / lock / panic zeroize wiring:** SysTick wipes a dialog-less, unlocked-but-idle device (`main.rs:3683-3684`, guarded by `!handler_is_busy()` so it can't race a handler holding stack copies); every blocking dialog returns `IdleWipe → zeroize_sensitive_state`; the panic handler zeroizes (`main.rs:3836`); `HandlerGuard` (`nsc/mod.rs:443-480`) closes the ISR/handler aliasing race. CMD_LOCK → `zeroize_sensitive_state`.
- **Dual-SE entropy reconstruction (`dual_se.rs`):** full entropy exists only transiently in S-SRAM and is `zeroize()`-d + `zeroize_barrier()`-d after the blob is re-encrypted (`:396-397`); `half_o`/`half_e`/`blob_o`/`blob_e`/`master_e` all wiped after use; the two halves are kept per-chip and never crossed; the consistency check uses constant-time `subtle::ConstantTimeEq` with a `wait_random` FI gate (`:379-382`); `xor_32` is branchless/constant-time. No half is ever placed in NS or in a log argument.
- **`entropy_blob_cache` (corrects an over-claim from a sub-agent):** this cache holds the **AES-GCM-encrypted** 60-byte blob (`nonce‖ct‖tag`), *not* plaintext entropy, and it **is** wiped by `zeroize_caches` → `zeroize_sensitive_state` on lock/idle/panic (`dual_se.rs:432-437`, `se050/mod.rs:2810`, `optiga/mod.rs:2736`). Decrypting it requires `master_secret`, which is wiped on lock. Not a finding. The `vk_cache`/`bootstrap_vk_cache` hold **public** verifying keys — also not secret.
- **KDF chain (`domain/src/lib.rs`):** straight-line SHA-256/HMAC-SHA512 with no secret-dependent branches or secret-indexed loads; `with_bip39_seed` zeroizes `bip39_seed`; `Mnemonic` has a zeroizing `Drop`; `master`/`slh_seed`/slot `entropy` are wiped. (The one gap is `sk_seed_32` — MEDIUM-2.)
- **Secret types (Copy/Clone/Zeroize):** `sphincs_c10::SigningKey` is `#[derive(Zeroize, ZeroizeOnDrop)]`, `!Copy`, `!Clone` (`sphincs-c10/src/lib.rs:81`); `bip39::Mnemonic` has a manual zeroizing `Drop`, `!Copy/!Clone`; `CachedSlot` is `!Copy/!Clone` and drops its `SigningKey`; `CachedAccount` derives `Clone` but holds only **public** `pk_seed`/`pk_root` halves. Only `ShuffleSeed` violates the convention (LOW).
- **Debug / log / capture leak surface:** the `secure_log!` no-op arm is an empty expansion `=> {};` (`main.rs:42-45`) — arguments are not evaluated when `debug-log` is off, so a secret passed to it is fully discarded. The DEBUG mnemonic dump (`main.rs:3455-3465`), the VK dump (public), the seed-wizard `ui-capture` frame hash, and the PIN-entry `ui-capture` frame hash are all behind `#[cfg(feature = "debug-log")]` / `#[cfg(feature = "ui-capture")]`, and the `compile_error!` fence at `nsc/mod.rs:93-134` blocks **every** such dev feature on a `stm32u585` non-`debug_assertions` (release) build. `e2e-test` / `otp-hardcoded-master-key` are similarly fenced.
- **Seed display side-channel:** `ui/secret_text.rs` renders the 24 mnemonic words via a **constant-time** 96-entry glyph scan with `black_box` barriers (F-24, TVLA-validated), defeating the font address-channel leak.
- **RNG (`rng_strong.rs`):** 3-source XOR (STM32 ⊕ OPTIGA ⊕ SE050), strict fail-closed on any missing source, per-block buffer `zeroize()`-d, all-zero acceptance gate. `sign_rate.rs` holds only counters (no secret), with `read_volatile_voted` FI hardening on the rate reference.
- **OTP / HUK / SAES / secret_keys:** `otp::burn/ensure_device_master` zeroize every intermediate (`key`, `qw0/qw1`, readback); `secret_keys::derive_into` zeroizes the HKDF `master` and the CMAC `info` buffer; `huk::derive_device_key` zeroizes `uid`/`otp_master`; the production subkey path is `SAES-CMAC(DHUK/BHK)` where the root key never enters CPU-visible registers (KEYSEL); the SAES self-test zeroizes its scratch (`saes.rs:618-621`). The dev `otp-hardcoded`/`bhk-hardcoded` constants are compile-fenced out of production.
- **Consumption-mask cadence:** confirmed `randomize()` fires from SysTick and preempts the sign veneer (so the mask jitters during the SPHINCS window) — the *mechanism* is clean; only its absence from shipping recipes is flagged (MEDIUM-3).

## Open questions / items needing on-hardware confirmation

1. **MEDIUM-1 escalation hinge:** confirm on silicon whether RDP2 + TrustZone actually prevent a secure-SRAM readout of a *locked-but-powered* device. If a debug/cold-boot SRAM read is feasible, MEDIUM-1's seed-extraction chain is fully practical (escalates toward HIGH); if SRAM is genuinely unreadable while locked, MEDIUM-1 is belt-and-braces only. Either way the session-key wipe-on-lock is the correct closure.
2. **MEDIUM-3:** verify the actual production / factory build feature set (not just the Makefile dev recipes) for `consumption-mask`. If production omits it, decide enable-vs-risk-accept against the CPA threat on the unmasked ~7 s sign.
3. **MEDIUM-2 residue window:** on hardware, confirm whether the post-keygen stack region holding `sk_seed_32` is in fact overwritten by the subsequent C10 sign before any plausible readout — would downgrade the practical exposure (the fix is cheap regardless).
4. **Static SCP03 / Shielded pairing keys:** I confirmed by inspection that the *static* pairing keys are re-derived per session (`secret_keys::*`) and are **not** cached in the `Se050`/`OptigaTrustM` structs (only the ephemeral session keys are) — worth a HW trace to confirm no static-key transient lingers in SRAM after `ensure_shield`/SCP03 establishment.
