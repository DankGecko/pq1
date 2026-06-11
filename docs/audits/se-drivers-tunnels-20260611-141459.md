# audit:se-tunnels — Security Audit (20260611-141459)

## Scope & threat model

Target: the secure-element drivers and their encrypted tunnels.

- OPTIGA Trust M: `secure/src/optiga/{mod,ifx_i2c,apdu,shield,i2c,reset,reset_pin}.rs`
- SE050: `secure/src/se050/{mod,scp03,apdu,t1oi2c,i2c}.rs` + the shared `secure/src/{iso7816,scp03_logic}.rs`
- Tropic01 (standalone): `secure/src/tropic01_se.rs`
- Dual-SE reconstruction: `secure/src/dual_se.rs`

Adversaries considered (per the engagement brief):

1. **Bus attacker** — a logic analyzer on the I2C1 SDA/SCL lines. Passive (observe/replay) and active (inject/reorder/forge frames). No knowledge of TrustZone-internal secrets unless they are compile-time constants in the firmware image.
2. **Desolder/replace** — a patient attacker who removes an SE and substitutes a rogue chip that returns maximally hostile responses (any length, any status word, any TLV).
3. **NS / companion** — fully attacker-controlled non-secure world + USB host. Cannot directly drive I2C (the SE drivers live in S-world behind the NSC), but is included to check for any NS-reachable memory bug in the driver surface.

Invariants under test: **#1** (dual-chip XOR seed split, neither chip alone reveals a bit), **#3** (no plaintext secret on I2C — OPTIGA Shielded Connection + SE050 SCP03 only), and the **S-5** status (SCP03 elevated to P1=0x33, `unwrap_response` on the path).

## Methodology — what I read and how I hunted

I traced concrete data/control flow end-to-end for every secret-bearing exchange:

- **Response-before-verify**: confirmed `scp03::unwrap_response` (R-MAC verify + R-ENC decrypt) sits on the path for every secret-bearing SE050 response (`se050/apdu.rs:316`), and `ShieldedConnection::unwrap_response` (CCM verify+decrypt) for every OPTIGA response routed through `send_command` (`optiga/apdu.rs:390`). Checked that all length/SW/TLV reads happen on the *authenticated* plaintext, never the raw wire bytes.
- **SE-controlled-length OOB**: audited every `len`/`Lc`/`Le`/TLV-length parse where the value comes off the wire — `iso7816::tlv_parse`, the SE050 T=1' framing (`t1oi2c::validate_frame`/`read_frame`), the OPTIGA IFX framing (`ifx_i2c::validate_frame`/`receive_response`), `optiga::apdu::parse_response`, and every `copy_from_slice` fed by a chip-supplied length.
- **Downgrade / skip / null-cipher**: checked whether the tunnel can be forced to plaintext or established without mutual auth, on both runtime and build-config axes.
- **Replay / nonce reuse**: traced SCP03 command counter + MAC-chaining and the Shielded-Connection sequence numbers across session boundaries.
- **Key provenance**: traced where the SCP03 static keys and the Shielded-Connection PBS actually come from, per build.
- **Invariants #1/#3**: traced `half_O`/`half_E` from chip read to S-SRAM reconstruction in `dual_se::unlock`.

I cross-checked findings against the compile-time fences in `secure/src/nsc/mod.rs`, the feature graph in `secure/Cargo.toml`, the Makefile build recipes, and `docs/{production-todo,work-todo}.md`.

The runtime crypto/framing is in good shape (see "Surfaces examined and judged clean"). The exploitable gaps are in **key provenance + the missing compile-time enforcement around it**, which is exactly the class the team just fixed for the SCP03 *fallback* (work-todo.md:660) but left open for the *base configuration*.

---

## Findings (most severe first)

### [HIGH-1] SE050 SCP03 tunnel is keyed with PUBLISHED AN12436 factory keys in every build without `se050-derived-scp03` (the default) — bus attacker extracts `half_E`

- **Location:**
  - Key selection: `secure/src/se050/scp03.rs:73-86` (`load_platform_keys`)
  - Published constants: `secure/src/scp03_logic.rs:27-49` (`PLATFORM_ENC/MAC/DEK`)
  - Session-key derivation from them: `secure/src/se050/scp03.rs:171-307` (`establish` / `establish_with_keys`)
  - `half_E` read over that channel: `secure/src/se050/mod.rs:2482-2485` → `secure/src/se050/apdu.rs:316-337`
  - Missing enforcement: `secure/src/nsc/mod.rs:93-134` (the hardware-release fence does **not** list `se050-derived-scp03`)
  - Rotation is a separate halt-firmware, not the boot/provision path: `secure/src/main.rs:1597-1612`; factory provisioning does not rotate: `secure/src/factory_provisioning.rs:619`
  - "Production-shape" recipe ships without the feature: `Makefile:1279-1283` (and falsely claims invariant #3 at `Makefile:1266`)

- **Vulnerability class:** secure-channel keyed with attacker-known shared constants → confidentiality + integrity break of the SE050 tunnel (invariant #3); seed-share extraction (weakens invariant #1). Configuration gap with no compile-time guard.

- **Attacker & required capability:** bus attacker with a logic analyzer on I2C1, against a device whose firmware was built without `se050-derived-scp03`. Passive — a single observed unlock suffices.

- **Exploitation path:**
  1. Obtain a PQ1 unit whose firmware omits `se050-derived-scp03`. This is the **default**: neither `dual-se` (`= ["optiga-trust-m","se050"]`), nor `mode-production`, nor `se050` pulls it in, and **no `compile_error!` fence requires it** (contrast the S-3 `optiga-hw-counter` fence at `nsc/mod.rs:205` and the fallback fence at `nsc/mod.rs:110`). The reference "production-shape" target `build-hw-dual-se-oled-standalone` (`Makefile:1283`) is itself such a build.
  2. With `se050-derived-scp03` off, `load_platform_keys()` returns `(PLATFORM_ENC, PLATFORM_MAC, PLATFORM_DEK)` (`scp03.rs:74-77`) — the **published** SE050E OEF-0xA921 factory keys (`scp03_logic.rs:38-49`). The chip still holds these (never rotated), so `establish_with_keys` succeeds against them (`scp03.rs:207-307`).
  3. Tap I2C1. When the owner unlocks, the SCP03 handshake is on the wire in cleartext: INITIALIZE UPDATE carries the 8-byte `host_challenge` (`scp03.rs:218-224`); the response carries `card_challenge` (`resp[13..21]`) and `card_cryptogram` (`resp[21..29]`) (`scp03.rs:239-242`).
  4. Reconstruct the session keys exactly as the firmware does: `s_enc = kdf(PLATFORM_ENC, dd_enc)`, `s_rmac = kdf(PLATFORM_MAC, dd_rmac)`, where `dd_*` are built from the captured challenges (`scp03.rs:245-251`, `build_derivation_data`/`kdf` in `scp03_logic.rs`). The on-wire `card_cryptogram` lets the attacker confirm the keys are right.
  5. During the same unlock, `authenticate_and_read` reads `half_E` via `read_authed(ENTROPY_OBJ)` (`se050/mod.rs:2482`); the SE returns it R-ENC'd + R-MAC'd (`apdu.rs:316-321`). Capture that response frame off the bus.
  6. Decrypt it with the reconstructed `s_enc` and the response ICV (`response_icv` at `scp03.rs:333-337`, AES-128-CBC at `scp03.rs:615-616`) → recover the 32-byte `half_E` in plaintext.
  7. The attacker now holds `half_E`. `entropy = half_O XOR half_E`; with `half_O` (obtainable via the still-open OPTIGA ship-blockers S-1/S-2/S-3, or trivially in a `dev-testkey`/`optiga-no-shield` build), the full BIP-39 entropy reconstructs → every one of the 256 wallets, all funds.

- **Invariant / property broken:** **#3** ("No plaintext secret on I2C … always Shielded Connection / SCP03"). The SCP03 "encrypted tunnel" provides zero confidentiality against an attacker who holds the (public) static keys — the firmware's own comment says so: *"an SCP03 channel that still uses them is plaintext-equivalent to a bus sniffer with the datasheet"* (`scp03_logic.rs:30-33`). Also collapses **#1**'s dual-chip margin (one share is no longer confidential), and the integrity break additionally lets the attacker forge any R-MAC'd SE050 response.

- **Evidence:**
  ```rust
  // secure/src/se050/scp03.rs:74-77 — default build hands back the public keys
  #[cfg(not(feature = "se050-derived-scp03"))]
  { Ok((PLATFORM_ENC, PLATFORM_MAC, PLATFORM_DEK)) }
  ```
  ```rust
  // secure/src/scp03_logic.rs:30-36 — the authors know these are attacker-known
  // These are *published* — an SCP03 channel that still uses them is plaintext-
  // equivalent to a bus sniffer with the datasheet. They are the *initial*
  // state of a fresh chip; `work-todo #20` rotates them ...
  pub const PLATFORM_ENC: [u8; 16] = [0xD2,0xDB,0x63,0xE7, ...];
  ```
  ```
  # Makefile:1266 + 1283 — the "production-shape" build omits se050-derived-scp03
  #   #3 E2E encrypted tunnels (Shielded Connection + SCP03).   <-- false for SE050
  --features dual-se,optiga-hw-counter,dev-testkey,gpio-buttons,ui-oled,stm32u585,usb
  ```
  `docs/work-todo.md:661` states it plainly: *"the DEFAULT/bring-up build authenticates the SE050 with the published factory keys — fine for bring-up, NOT for ship."* `docs/production-todo.md:743` has "SCP03 keys rotated per device" as an **unchecked** box.

- **Why this is an un-fixed sibling, not a duplicate:** work-todo.md:660 *fixed* the runtime fail-OPEN (the `se050-scp03-allow-factory-fallback` path) by adding it to the `nsc/mod.rs` release fence — explicitly noting *"the original 'CI gates it off' claim was false, there is no firmware CI gate."* The identical reasoning was never applied to the **base** configuration: a release image with `se050-derived-scp03` simply **off** also compiles clean and runs on the published keys. The fence closes the fallback door but not the front door.

- **Suggested fix (describe only):** Add a `compile_error!` in `secure/src/nsc/mod.rs` mirroring the S-3 `optiga-hw-counter` pattern: for a hardware-release (`stm32u585` + `!debug_assertions`) or `mode-production` build with `se050`/`dual-se` enabled and not `e2e-test`/`dev-testkey`, require `se050-derived-scp03`. Belt-and-braces, refuse to ship an image whose SE050 secure-channel root is the published factory keyset. Separately, fix the `build-hw-dual-se-oled-standalone` header comment (`Makefile:1266`) that claims invariant #3 is respected, and close out work-todo.md:661 by wiring rotation into the production ceremony.

- **Resolution (FIXED 2026-06-11):** `compile_error!` fence added in `secure/src/nsc/mod.rs` — a `mode-production` or hardware-release (`stm32u585` + `!debug_assertions`) build with `se050` (and therefore `dual-se`) enabled, lacking `e2e-test`/`dev-testkey`, now **fails to build** unless `se050-derived-scp03` is on. Pinned by source-text test `positive_se_tunnel_ship_blocker_fences_present` (`nsc_core_under_test/pure_tests.rs`). Validated on `thumbv8m`: a production-shaped set (`dual-se,optiga-hw-counter,consumption-mask,saes-dhuk,…`) without the feature is rejected with this exact message and compiles once `se050-derived-scp03` is added; the `dev-testkey` bench target still compiles. Still open (operational, not code): wiring the per-unit PUT KEY rotation into the production ceremony (work-todo.md:661) so the chip actually holds the matching derived keys.
- **Confidence:** confirmed (code/build-config state). The enforcement gap is closed; the remaining item is operational (the factory line must run the rotation ceremony — the fence forces the *build* to opt in, which is the half that lives in this repo).

---

### [MEDIUM-1] `optiga-no-shield` disables the Shielded Connection with no production fence — `half_O` + PIN-auth APDUs transit I2C in plaintext

- **Location:**
  - `ensure_shield` becomes a no-op: `secure/src/optiga/mod.rs:406-412`
  - `send_command` plaintext branch: `secure/src/optiga/apdu.rs:393-394`
  - `half_O` read reaches it: `secure/src/optiga/mod.rs:2288-2291` (`get_data_object(OID_ENTROPY,…)`) → `secure/src/optiga/apdu.rs:689-712`
  - Feature, undocumented-as-fenced: `secure/Cargo.toml:524` ("NOT production-safe")
  - Absent from every fence in `secure/src/nsc/mod.rs:93-408`

- **Vulnerability class:** secure-channel skip → plaintext secret on the bus (invariant #3). Build-config gap with no compile-time guard.

- **Attacker & required capability:** bus attacker, against a device built with `optiga-no-shield`.

- **Exploitation path:**
  1. Firmware is built with `optiga-no-shield`. Nothing prevents this in a release/`mode-production` build — the feature is documented "NOT production-safe" (`Cargo.toml:524`) but, unlike `optiga-reset-oids` (S-2 fence at `nsc/mod.rs:229`) or `optiga-hw-counter` (S-3), has **no** `compile_error!` fence.
  2. `ensure_shield()` returns `Ok(())` without establishing the PRL (`mod.rs:406-412`), so `shield.active` stays false.
  3. On unlock, `authenticate_and_read` calls `get_data_object(OID_ENTROPY, …)` (`mod.rs:2288`), which calls `send_command`; with `shield.active == false` it takes the **plaintext** `ifx.transceive(apdu, resp_buf)` branch (`apdu.rs:393-394`).
  4. The bus attacker reads `half_O` directly off the wire — no crypto required. The PIN-auth HMAC challenge/response (`generate_auth_code`/`hmac_verify`) also travel in plaintext.

- **Invariant / property broken:** **#3** (plaintext secret on I2C); leaks `half_O`, weakening **#1**.

- **Evidence:**
  ```rust
  // secure/src/optiga/apdu.rs:393-394 — plaintext when the shield is down
  } else {
      Ok(ifx.transceive(apdu, resp_buf)?)
  }
  ```
  ```rust
  // secure/src/optiga/mod.rs:406-412 — optiga-no-shield makes ensure_shield a no-op
  #[cfg(feature = "optiga-no-shield")]
  { return Ok(()); }
  ```

- **Severity rationale (MEDIUM, not HIGH):** unlike HIGH-1, the insecure state is **opt-in** to a feature whose name and Cargo doc-comment both scream "NOT production-safe," so the realistic likelihood of it reaching a shipped image is much lower. Impact-if-triggered is the same HIGH-class `half_O` extraction; the rating reflects the precondition, not the blast radius.

- **Suggested fix (describe only):** Add a `compile_error!` fence in `nsc/mod.rs` refusing `optiga-no-shield` in any hardware-release / `mode-production` build (the same shape as the S-2 `optiga-reset-oids` fence), with the usual `e2e-test`/`dev-testkey` escape hatch.

- **Resolution (FIXED 2026-06-11):** `compile_error!` fence added in `secure/src/nsc/mod.rs` (same shape as the S-2 `optiga-reset-oids` fence) — `optiga-no-shield` in a `mode-production`/hardware-release build without `e2e-test`/`dev-testkey` now **fails to build**. Pinned by the same source-text test. Validated on `thumbv8m`: adding `optiga-no-shield` to an otherwise-clean production-shaped set is rejected with this message.
- **Confidence:** confirmed (code state); the plaintext path is unconditional once the feature is on — the fence now blocks that feature from a shipping build.

---

### [LOW / needs-confirmation] `dev-testkey` derives the OPTIGA PBS and SE050 admin secrets from a compile-time constant — combines with HIGH-1 to a full-seed bus sniff on bench-shaped builds

- **Location:** `dev-testkey` substitutes the OTP master with a compile-time constant (used by `hw::secret_keys::optiga_pairing_secret` / `se050_admin_pin`); the reference dual-SE recipe uses it (`Makefile:1283`).
- **Why noted:** in a `dev-testkey` build the Shielded-Connection PBS is no longer device-rooted (DHUK), so a bus attacker who knows the firmware constant can also derive the PBS, break the OPTIGA shield, and read `half_O`. With HIGH-1 supplying `half_E`, that is a **full-seed** bus sniff with no desoldering. `dev-testkey` is a dev feature (escapes the `nsc/mod.rs` fences) and is not a shipping image, so this is not itself a production finding — but it means the only reference dual-SE build is end-to-end bus-readable, which is worth flagging given the comment claims all of invariants #1–#8 hold (`Makefile:1262-1267`).
- **Suggested fix:** none beyond HIGH-1/MEDIUM-1 for production; consider not advertising the bench target as "production-shape … invariants respected."
- **Confidence:** needs-confirmation on operational intent; the key-derivation behaviour of `dev-testkey` is confirmed.

---

## Surfaces examined and judged clean (with the reason each is safe)

- **SCP03 `unwrap_response` (`se050/scp03.rs:514-677`).** R-MAC is verified *before* any body byte is used, and the verify is FI-hardened two ways: a double-evaluated `check_true_into_sentinel` gate (`scp03.rs:582-591`) and an **infective** branchless release mask that garbles every output byte unless a fresh independent R-MAC recompute matches (`scp03.rs:660-670`). Every length is bounds-checked (`body_end ≤ n-10`, `body_end > plain.len()` → `Overflow` at `:610`, `out.len() < plaintext_len+2` → `Overflow` at `:641`). A rogue/replayed/forged response yields garbage, never attacker-chosen `half_E`.
- **SCP03 replay/counter (`se050/scp03.rs:117-124,299-301,674`).** Counter starts at 1 and advances only on a successful unwrap; the R-MAC binds the per-command MAC-chaining value (`mcv`), which changes every command, so a captured response cannot be replayed against a later command. Fresh `host_challenge` from the TRNG each `establish` (`:214-215`) → session keys differ per session, killing cross-session replay.
- **SCP03 downgrade resistance.** EXTERNAL AUTHENTICATE hardcodes P1=0x33 (`:272,280`); a rogue SE cannot negotiate a cleartext level because the host always calls `unwrap_response`, and a cleartext "successful read" (data + SW, no real R-MAC) is rejected at the R-MAC step. The published-factory **fallback** is correctly fenced out of release builds (`nsc/mod.rs:110`). (The *base* factory-key config is HIGH-1 — a different door.)
- **`se050::apdu::send_apdu` (`:241-338`).** Routes every active-session response through `unwrap_response`; SW and `data_len` are read from the authenticated plaintext, and `data_len > resp_buf.len()` → `BufferOverflow` (`:333`). The non-SCP03 branch is reached only by pre-session, non-secret commands (`select_applet`).
- **`iso7816::tlv_parse` (`:73-92`).** Total and panic-free: `end = hdr.checked_add(len)?` then `data.len() < end → None`. Every SE050 caller (`create_session`, `read_authed`, `get_version_ext`, …) checks `value.len() > buf.len()` before copying.
- **SE050 T=1' framing (`t1oi2c.rs`).** `validate_frame` clamps the chip-claimed `inf_len` against the real buffer (`frame.len() < total → Protocol`, `:120`); `read_frame` reads a fixed `MAX_FRAME-1` into a `[u8; MAX_FRAME]` (`:336-337`) — no wire length drives the read size; the receive loop bounds accumulation (`resp_offset + inf.len() > resp.len() → BufferOverflow`, `:266`). WTX is capped (`:249`). (A rogue chip can hang the loop with empty chained frames — a DoS, outside the target impact set.)
- **OPTIGA IFX framing (`ifx_i2c.rs`).** `receive_response` clamps `resp_len` to `[1, MAX_FRAME]` (`:496-500`); `validate_frame` bounds `flen` (`total > frame.len() → BadResponse`, `:278`); output accumulation is checked (`:564`). CRC verified before payload use.
- **OPTIGA Shielded Connection (`shield.rs`).** AES-128-CCM-8 manually implemented but correct (B0 flags 0x5E, A_i flags 0x06, CTR/CBC-MAC per SP 800-38C); tag compared constant-time (`:697-701`). `unwrap_response` bounds `plaintext_len > out.len() → BufferOverflow` (`:308`), rejects non-record SCTR (HIGH-M16, `:279-285`) and replays (`seq < dec_seq → DecryptFailed`, HIGH-10, `:296`), and closes the connection at the nonce-wrap threshold (`:300-303`). Mutual auth rests on the PBS: a replaced chip that does not know the device-rooted PBS cannot produce a valid SlaveFinished, and the host verifies the `random_S` echo (`:476-490`).
- **OPTIGA `send_command` runtime gating (`apdu.rs:371-396`).** The plaintext branch is only reached when `shield.active == false`; every secret read calls `ensure_shield()?` first (e.g. `mod.rs:2081`), which propagates `Err(Shield)` on a failed handshake — so a rogue/PBS-less chip causes unlock to fail rather than leaking plaintext. (The exception is `optiga-no-shield` — MEDIUM-1.)
- **OPTIGA unlock auth (`mod.rs:2063-2353`).** `ensure_shield()?` precedes a fresh per-unlock TRNG challenge fetched over the shield (CRIT-8) and a chip-side HMAC verify; all secret reads (`OID_ENTROPY/MASTER_SECRET/VK/BOOTSTRAP_VK`) go over the shield. Replay-resistant (fresh nonce + shield sequence numbers). `parse_response` bounds `4 + data_len > len → Transport` (`apdu.rs:361`); `parse_pin_ctr` is gated on exactly 8 bytes (`mod.rs:1394,1556`).
- **Dual-SE reconstruction (`dual_se.rs:286-401`).** Requires BOTH chips to succeed; reads both halves over their respective tunnels, XORs in S-SRAM, and FI-checks `kdf("sphincs-master", full) == master_o` with a double `ct_eq` through the sentinel gate (`:378-389`). Neither chip alone reconstructs the seed — invariant #1 holds at the reconstruction layer (the HIGH-1 break is at the SE050 *tunnel*, not here).
- **Tropic01 (`tropic01_se.rs`).** Not in the production config (`tropic01-se` is mutually exclusive with `se050`/`optiga-trust-m`; production is `dual-se`). r-mem reads return upstream-crate GCM-decrypted/authenticated data, copy is bounded (`buf.len() < len → InvalidParameter`, `:308`), and `deserialize_t01_pin_state` is exact-length-checked (`:96`). It has a per-device pairing-key path (`:283`) analogous to `se050-derived-scp03`; the same "is rotation enforced for ship?" question applies but is moot while it is non-production.

## Open questions / items needing on-hardware confirmation

1. **Will the real shipping recipe carry `se050-derived-scp03` + a rotated chip?** HIGH-1 is a missing *enforcement*; the operational answer determines whether shipped units are actually exposed. Recommend: (a) add the fence so the question can't be answered "no" by accident; (b) confirm the production line runs the `se050-rotate-scp03` ceremony per unit and that `provision()`/the factory state machine verifies the chip is on derived keys (work-todo.md:661 is still open; `factory_provisioning.rs:619` does not rotate).
2. **OPTIGA shield nonce hygiene at the handshake→record boundary.** `dec_seq` initialises to 0 after `establish` (`shield.rs:501`), so the first record response may carry any `seq ≥ 0`, including `seq == master_seq` (the value used to CCM-decrypt SlaveFinished). A legitimate chip will not reuse that nonce and a rogue chip cannot forge a valid frame (no PBS), so this is not exploitable — but it is worth a logic-analyzer confirmation that real V3 silicon never re-emits `master_seq` as a record sequence number.
3. **Latent (non-attacker-reachable) TX buffers.** `scp03::wrap_apdu`'s `out[7..7+padded_len]` and `shield::aes128_ccm_encrypt`'s 600-byte internal buffer would overflow for command payloads near ~1 KB. No firmware SE command approaches that size (entropy/VK objects are 32 B; the only large path, `protected_update`, is `optiga-reset-oids`-gated and fenced out of production), so these are unreachable today — but they are unguarded and would become live if a large shielded command were ever added. Recommend an explicit bound at both sites.
4. **DoS via malicious chained frames.** A rogue SE/OPTIGA can hang the receive loop with empty chain-flagged frames. Outside the target impact set (no theft/extraction/bypass/forgery), but worth a frame-count cap if denial-of-service on the unlock path matters.
