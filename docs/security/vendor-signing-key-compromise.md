# Vendor signing-key compromise recovery — design note

> Status: design note, not a specification. Filed under
> [EthereumPhone/PQ1#486](https://github.com/EthereumPhone/PQ1/issues/486)
> (Trezor-parity sweep 2026-07-20, TZP-15). Decision required **before the
> FSBL WRP freeze**; after that freeze option B below ceases to exist.
>
> **See [UPDATE 2026-08-05](#update-2026-08-05--can-the-device-refuse-an-extraction-enabling-update)
> at the end of this note** — the negative result on device-side refusal of an
> extraction-enabling update, three live defects (D1 secrets survive the
> `FW_COMMIT` reset, D2 wipe-to-wizard, D3 doc drift), the finding that WRP is
> never programmed anywhere in the tree (so invariant #10's immutable anchor is
> not implemented), and a second expiring decision — on-chain policy — that
> expires at *wallet launch* rather than at the WRP freeze.
>
> **Then read UPDATE 2026-08-05 (round 2), which corrects it.** Round 1's
> Rice/undecidability argument was wrong; the R-channel argument was right but
> understated ~200×; and there IS a clean affirmative answer for *data* updates.

## Facts

- One 32-byte SPHINCS+C10 vendor pubkey (`pk_seed‖pk_root`) is embedded at
  build time into **both** the secure image
  (`secure/src/fw_update/vendor_pubkey.rs`, `.pqsigner.vendor_pubkey`) and the
  FSBL (`fsbl/src/vendor_pubkey.rs`, same section name, byte-identical
  contents enforced by the release gate against
  `config/production-firmware-vendor-key.sha256`).
- The secure world verifies update manifests at `FW_BEGIN`; the FSBL
  re-verifies at boot. A manifest must pass both.
- The FSBL is planned to ship WRP-protected / immutable. Its embedded key can
  therefore **never change in the field**.
- Changing the compiled-in pubkey is provisioning a new vendor identity:
  every previously-signed release is rejected (`fsbl/src/vendor_pubkey.rs:4-7`).

## Threat

Theft or coercion of the vendor signing key (HSM breach, insider, build-host
compromise) lets an attacker sign firmware that passes **both** verification
stages on **every device ever shipped**. The 4-page fingerprint confirm still
forces user interaction, so this is a targeted-supply-chain weapon, not a
silent mass push — but it is unrecoverable at the fleet level today.

## Why Trezor's answer does not map

Trezor rotates signing keys without a bootloader change via `sigmask` m-of-n
over N provisioned key slots (`core/embed/sec/image/image.c:90-110`, cosi
aggregate). SPHINCS+ has no signature aggregation; N slots means N full
SPHINCS+ verifications at boot (FSBL size and boot-time budget) plus a
revocation-slot store (OTP encoding is unsettled Draft-1.1 research).
**Declined** — the machinery costs more surface than it removes.

## Options

**A. Accept + operational custody (default).** Split-custody HSM ceremony,
air-gapped signing, published key hash. On compromise: permanent line stop,
RMA/recall as the only fleet remediation. Zero firmware change. This is the
honest default because every alternative only narrows — never closes — the
immutable-FSBL window.

**B. Dual-key FSBL (primary + recovery), provisioned before the WRP freeze.**
FSBL accepts manifests signed by either key; the recovery key lives colder
(deeper split, fewer custodians). Recovery flow: recovery key signs a
firmware whose embedded secure-world pubkey is the *new* primary; FSBL boots
it; from then on the secure world accepts only new-primary updates at
`FW_BEGIN`. Residuals, stated honestly:
- the FSBL keeps accepting the **leaked primary forever** (it is immutable);
  the new secure world's `FW_BEGIN` check is what rejects old-primary
  updates — so recovery protects *future* updates on devices already running
  the recovery firmware, and cannot help a device that gets the malicious
  image first;
- one extra 4 kB-class signature verification at boot, FSBL footprint
  impact, and a second key-custody story to get wrong.
Cost is small **now** and impossible **later**: the recovery key must be
compiled in before WRP.

**C. Per-device key diversity.** Rejected: breaks reproducible builds and the
published production key hash.

**D. RMA reflash.** Only full remediation for a leaked primary under an
immutable FSBL; operationally it's option A's fallout, not a design.

## Recommendation

Ship A's custody ceremony now (it is required under every option). Take the
B-vs-A decision explicitly at the FSBL freeze review, with this note as the
record: B is cheap insurance bought exactly once, and its residual (no
revocation of a leaked primary from already-shipped FSBLs) must be stated in
the threat model either way.

## Decision points

- [ ] Vendor key ceremony documented (shards, threshold, HSM, air-gap) —
      ties into #249's SLH-DSA factory-HSM work.
- [ ] B accepted or declined at FSBL WRP freeze review.
- [ ] Threat-model doc updated with the immutable-primary residual.
- [ ] Interaction with Draft 1.1 rollback encoding recorded (none expected:
      key identity ≠ version floor, but the freeze review must confirm).

### Added 2026-08-05 (see UPDATE below for evidence)

- [x] **D1 — FIXED 2026-08-05.** `cmd_fw_commit` now calls
      `super::zeroize_sensitive_state()` after the OTP bump and before both
      reset arms (`sys_reset` and the USB `cc_open_then_reset`), and the boot
      scrub gate moved from `ResetCause::is_abnormal()` to a new
      `ResetCause::requires_secret_scrub()` that also covers `Software`.
      Regression-guarded by
      `nsc_fw_update_pure_tests::negative_commit_zeroizes_session_secrets_before_resetting_into_new_image`
      (pins ordering against BOTH reset arms) and
      `main_sau_pure_tests::{positive_software_reset_requires_secret_scrub,
      positive_reset_cause_drives_abnormal_zeroize}` (the latter carries a
      negative control forbidding a narrowing back to `is_abnormal()`).
      Both source-pinning tests were verified to FAIL against a reverted fix.
      2557/2557 pure tests green; `make build-hw` clean.
- [ ] **D1 belt-and-braces (still open)** — provisioning burns
      `FLASH_OPTR.SRAM2_RST` (erases SRAM2, the *non-secure* bank). The bit
      covering the bank where secrets actually live is `FLASH_OPTR.SRAM_RST`
      ("all SRAMs except SRAM2 and BKPSRAM erase upon system reset",
      `stm32u585xx.h:8848-8850`). Burning it would make the guarantee
      hardware-enforced instead of code-discipline. Not done here because it
      changes the option-byte provisioning recipe for existing boards and
      wants a check that nothing intentionally retains SRAM across a reset.
      The ship profile (`shared/src/lockdown.rs`) does not currently constrain
      either SRAM bit, so there is no `verify_ship_profile` conflict.
- [ ] **D2** — close wipe-to-wizard (needs an owner decision on what happens
      to a legitimately locked-out user). Prerequisite for any PIN- or
      enrollment-gated authority, and for A3/A4 refusal.
- [ ] **D3** — correct the "verified twice" comment at `fw_update/mod.rs:25-29`.
- [ ] **WRP is never programmed anywhere in the tree** — invariant #10's
      immutable anchor is unimplemented. Belongs on `docs/STATUS.md` §A as a
      ship-blocker, not only in this note.
- [ ] Option B **and** an immutable `FSBL_MIN_ACCEPTED_FW_VERSION` floor taken
      as ONE decision at the WRP freeze review (each is near-worthless alone).
- [ ] **On-chain policy decision taken before wallet launch** — a *second*
      expiring deadline, distinct from the WRP freeze: `PQSmartWallet` has no
      upgrade path, so in-wallet spend caps / timelocks / `validUntil` windows
      are now-or-never.
- [ ] Post-personalization secure-update freeze costed, and the outcome
      recorded here even if declined.
- [ ] Widen the FSBL boot fingerprint beyond the secure image, and **publish
      expected fingerprints per release** (detection probability is 0 today).

### Added by round 2 (2026-08-05) — see the second UPDATE

- [ ] **Build the `PQDESC_V1` signed-descriptor-root channel** (already designed
      and deferred in `docs/erc7730-root-rotation-and-update-policy.md`). Highest
      leverage item in either round: it moves the dominant class of post-ship
      updates from undecidable code to provably-inert data.
- [ ] **Count-minimality watchtower** — free, retroactive, no device change.
      Ship as a detector, never as mitigation.
- [ ] **Signer-identity manifest** (`D1-IDENTITY`) for `c10_sign_verified*` +
      argument provenance + deterministic/committed signing — the tractable
      substitute for information-flow analysis on code updates.
- [ ] **Do not fund an MIR taint analyzer as the centerpiece** — it is the
      expensive leg *and* the insufficient one.
- [ ] Run the cheap silicon experiment: does secure-*unprivileged* code actually
      fault on I2C1/I2C2 and a monitor-owned SRAM block? Every register exists in
      CMSIS; nothing in the tree configures any of them; there is no receipt.

---

# UPDATE 2026-08-05 — can the device *refuse* an extraction-enabling update?

**Question asked:** can PQ1 add guardrails so a device refuses a firmware
update that would make it possible to extract the private key, once the seed is
recomposed inside TrustZone?

**Answer, scoped by adversary — this distinction is the whole result:**

- **Against a stolen or coerced vendor key (A1/A2): no, and the impossibility
  is structural, not an engineering gap.** Reasons 1, 2, 5 and 6 below each
  independently suffice. The truthful framing is not "the device refuses the
  update" but **"the update is not sufficient to move the money"** — which
  relocates the guardrail off the die.
- **Against an evil maid with a signed image (A3) or host malware (A4):
  refusal is achievable** — the `outgoing-gatekeeper` design scored
  A3=blocks / A4=blocks — **but only after two prerequisites that are not
  met today**: WRP must actually be programmed (reason 3) and wipe-to-wizard
  must be closed (reason 4, defect D2). Both are fixable. Neither is done.

So "nothing to do here" is the wrong reading: ranked actions 2 and 5 below are
exactly the work that converts A3/A4 refusal from unavailable to available.

Everything below was checked against source; `file:line` citations are the
evidence, and claims that are *reported but not independently re-verified* are
marked (unverified).

Method: nine guardrail families designed and then attacked on two adversarial
lenses each (attack-efficacy, brick/feasibility), plus a repo ground-truth
sweep, a prior-art sweep (Trezor / Ledger / Coldcard / BitBox02, SGX
MRENCLAVE-vs-MRSIGNER sealing, TPM PolicyAuthorize, DICE / Caliptra /
OpenTitan ownership transfer, Titan-M insider-attack resistance, firmware
transparency), and two independent non-Claude reviews (GPT-5.6, Kimi K3).
**Every one of the nine families returned HOLDS=FALSE on at least one lens.**
That is not nine independent failures; it is one structural fact expressed nine
times — all nine put the enforcement decision *on the die*.

## Why no on-die refusal works — six reasons, any one sufficient

1. **Undecidable, and also unobservable.** "Does this image leak the seed" is a
   non-trivial semantic property (Rice), and leakage is non-interference — a
   2-safety hyperproperty. So it is neither statically decidable *nor* visible
   from any single execution, which rules out a runtime monitor as well as a
   static check.
2. **Every derivation root on the die is reproducible by any signed image, and
   that is deliberate.** The OTP master is readable at every RDP level by
   design (`secure/src/hw/otp.rs:43-54`), and DHUK/BHK are reachable through
   SAES by any secure-world code — `docs/security/threat-model.md` §9.9 already
   records "Any S-world code can call `secret_keys::derive_into{,_bhk}`".
   Reflash-survival is the *fix* for the OPTIGA brick; removing it re-creates a
   known permanent brick.
3. **The immutable anchor does not exist today** *(prerequisite, not a
   structural bar — this one is fixable)*. Nothing in the tree ever *programs*
   WRP: `secure/src/hw/flash.rs:437` reads `WRP1AR` through a read-only
   `RoReg32` and there is no write path; `shared/src/lockdown.rs:209` sets
   `WRP1A_MASK_PINNED = false`, so `verify_ship_profile` cannot pass on WRP;
   and `secure/src/flash_policy.rs` `GenericSecurePage::new` admits every
   bank-1 page below 127 for erase — **including the FSBL pages**. A signed
   image can erase the measuring code. Invariant #10 is a plan, not an
   implementation, and every "immutable FSBL enforces X" design is vacuous
   until the WRP ceremony actually lands.
4. **There is no wipe-surviving owner baseline** *(prerequisite, not a
   structural bar — also fixable)*, so every enrollment-based authority is free
   to an attacker with physical possession and *no secrets*. See defect **D2**.
5. **The signature is itself the exfiltration channel.** `R` is parsed straight
   out of the signature and the verifier never recomputes it —
   `sphincs-c10/src/fors.rs:94` says so verbatim; `sphincs-c10/src/hypertree.rs:361-376`
   constrains only `fors_indices[K-1] != 0`. With `n = 16` that leaves ~117
   freely chosen bits per signature, published on-chain *by the victim*, and a
   `grind_r` helper already exists in-tree. Three signatures leak a 256-bit
   seed. This defeats channel-blocking, peripheral isolation, anti-exfil and
   capability-manifest designs *a priori*.
6. **Drain is strictly cheaper than extraction and needs no secret to leave the
   die.** Every decoder, renderer and confirm dialog lives in the mutable
   secure image, and `PQSmartWallet.executeWithOffchainCount` takes an
   arbitrary target. A signed image that renders "Send 0.01 ETH to Alice" and
   signs a drain UserOp requires no covert channel, no R grinding, and no key
   material to exit the chip. **A guardrail scoped to seed confidentiality
   optimises the harder attack while leaving the cheaper one unaddressed.**

### Settled: intra-secure-world isolation (the two external reviews disagreed)

Kimi K3 asserted ARMv8-M has no ring below privileged-secure; that is **wrong**,
and GPT-5.6's contrary claim is right. `CONTROL_S.nPRIV` exists
(`core_cm33.h:452`), and `SYSCFG_CSLCKR` provides `LOCKSMPU` / `LOCKSVTAIRCR` /
`LOCKSAU` (`stm32u585xx.h:19905-19913`, "Disable changes to the secure MPU
registers"). So a privileged immutable monitor running mutable firmware
secure-*unprivileged* behind SVC is architecturally real on this part.
(GPT-5.6 additionally cites `FLASH_PRIVBB`, MPCBB `PRIVCFGR`, GTZC
`TZSC_PRIVCFGR`, and GPDMA privilege locks — unverified.)

**It still does not answer this question.** Per
`docs/architecture/trezor-comparison-critical-port-2026-06.md` §C-1, Trezor's
`secmon` sign surface is digest-in/sig-out — blind signing, which PQ1 exists to
forbid. An immutable core that guards only the *key* is a blind-signing oracle:
hostile updatable code renders a lie and drains the wallet. To avoid that, the
immutable side must own decode + render + confirm — the ERC-7730 walker
(~5k LOC) plus EIP-712/Safe/CoW plus display plus SE drivers plus PIN UI — which
is both far beyond an immutable ~40 KiB region and precisely the code that must
stay updatable. HDP is temporal hiding (denied until reset), so a closed HDP
region cannot be a callable enclave either.

Conclusion: **ship MPU_S privilege separation for bug blast-radius if you ship
it at all, and score it as explicitly A1/A2-vacuous.** It is at zero today (no
MPU register write in `secure/src` or `fsbl/src`).

## Three live defects found during this review

**D1 — wallet secrets survive the `FW_COMMIT` reset into the successor image.**
Secrets live in **SRAM1** (`secure/memory-stm32u585.x:8-9`; SRAM2 is the
non-secure bank), but provisioning burns only `SRAM2_RST=0` (`Makefile:263,275,278`)
— the wrong bank. `cmd_fw_commit.rs:322-330` zeroizes only the `FwUpdateCtx`
(manifest bytes + running hashes), never the wallet secrets, then calls
`SCB::sys_reset()` at `:356`. `secure/src/main.rs:1024-1030` *skips* the
defensive boot-time SRAM scrub for Software resets on the stated assumption
"Software resets always originate from code that zeroized first" — an assumption
this path violates. Since every `FW_*` call requires PIN unlock, secrets are
**guaranteed live** at that moment. The freshly installed image's reset handler
therefore runs before Rust memory init and can read the previous session's
unlocked master secret out of retained SRAM1, with no user interaction.
*Severity framing:* the legacy updater is production-fenced
(`fsbl/src/main.rs:49-55`), and an attacker holding a signed image has other
routes — but this is a documented invariant that a caller breaks, it fires for
benign reasons too, and **it bypasses any guardrail that lives in the updated
image, because the secret survives the transition regardless of what the new
image is permitted to do.** (An immutable privileged monitor that runs first and
scrubs would *fix* D1 rather than be bypassed by it.) Fixing it is a
prerequisite for the authorization-based guardrails below.

**D2 — wipe-to-wizard reaches the install gate with zero secrets.** Ten wrong
PINs → `secure/src/main.rs:1561-1576` runs `factory_reset_admin()` then
`pin_attempts_reset()`, with the in-code comment "so next boot sees
unprovisioned state + blank counter → first-boot wizard, not another lockout
loop" → the wizard runs, the attacker chooses PIN and mnemonic → `:3733` calls
`nsc::unlock_with_master`, which is `state::with_state(|s| s.mark_unlocked(master))`
with **no credential verification and no attempt charge**
(`secure/src/nsc/mod.rs:1046-1048`) → `cmd_fw_begin.rs:44`'s sole gate is
`pin_verified.check_sentinel()`, which now passes. The victim's seed is
destroyed by the wipe, so this is not seed theft; it is **wipe-and-phish** — the
device is handed back looking factory-fresh running attacker firmware, and the
user types their real 24 words into it. Consequence for design: until this is
closed, every ceremony that "proves you hold the recovery phrase" proves only
that you hold the phrase *the attacker just enrolled*, and the existing
`CMD_FW_*` PIN gate is not Titan-M-style insider-attack resistance.

**D3 — doc drift (verified against both the comment text and the code).** The
module header at `secure/src/fw_update/mod.rs:25-29` reads verbatim: *"**No
double-sign.** The vendor signature in the manifest is verified twice: once at
BEGIN … and once at COMMIT (after re-hashing the written images …)"*. COMMIT's
FI-hardened `manifest_gate` (`secure/src/nsc/cmd_fw_commit.rs:271-276`) re-runs
`verify_structural` + `verify_crc` + `verify_digest` + `verify_rollback` and
**nothing else**; `verify_signature` appears only in `verify_manifest`
(`secure/src/fw_update/mod.rs:496-498`), which BEGIN calls. The second signature
verifier is the FSBL at next boot, not COMMIT. The security posture is defensible
— COMMIT binds written bytes to the *signed digest*, and the FI hardening is
real — but the comment overstates it, and the review that trusts that comment
will mis-model the single-verification window.

## What *is* achievable, ranked by value per irreversible commitment

1. **Off-device value controls — the real answer.** PQ1 as one signer of a Safe
   or vault it cannot move alone, plus chain monitoring. Zero firmware change,
   zero irreversible commitment, works today with every silicon gate still open,
   and **it is the only measure that addresses extraction and drain with the
   same mechanism**: under a 2-of-3 Safe a fully extracted seed yields one
   signature of a quorum and moves nothing. The wallet already implements
   EIP-1271 and the Safe/multiSend/CoW decoders already exist.
2. **Close D2**, then **D1**. D2 forces an explicit owner decision on what
   happens to a legitimately locked-out user; that decision is the actual cost.
3. **Publish expected fingerprints.** `CMD_FW_BEGIN` *already* renders the
   incoming image's 8 BIP-39 words and the vendor-key fingerprint
   (`secure/src/fw_update/mod.rs:113-151`). Nobody publishes a value to compare
   against, so **detection probability is 0 today by construction, not for want
   of firmware.** Release-gate + docs change, no firmware. Widen the FSBL
   fingerprint first (verified): `fsbl/src/verify.rs:41-72` computes
   `actual_ns` and gates on it, but returns `Some(actual_secure)`, and
   `fsbl/src/main.rs:135` renders that alone — so the 8 boot words cover the
   **secure image only**, not the NS image, version or vendor key. The NS image
   *is* verified against the signed manifest; it simply is not reflected in the
   value the user is asked to compare. Two builds differing only in the NS image
   display identical words.
4. **MPU_S privilege split**, scored honestly as blast-radius only (see above).
5. **The expiring decisions** (next section).
6. **State the negative result** in `docs/security/threat-model.md` §10.3 and
   here: a valid vendor signature is *authentic, not benign*, and the device
   cannot tell the difference. BitBox02 states this in its own threat model;
   Ledger's 2023 episode is what happens when users are allowed to believe
   otherwise. Stating it plainly is a differentiator, not an admission.

## Now-or-never decisions this research surfaced

- **Option B (dual-key FSBL) and an immutable `FSBL_MIN_ACCEPTED_FW_VERSION`
  floor should be taken as ONE decision at the WRP freeze review.** Each is
  close to worthless alone: an immutable FSBL keeps accepting a leaked primary
  forever, while the OTP rollback floor is silicon-invalid and
  production-fenced, so it reads 0 on every device — meaning *every release the
  vendor has ever signed stays installable*. Together, the floor is
  unlowerable by any signed image and the recovery key provides a path above it.
  Estimated cost ~40 B of FSBL rodata+code plus one extra C10 verification at
  boot (`verify_signature`/`compress256` are already linked) — but note the real
  margin is **52 B against the draft warning limit**, not the 2,100 B ceiling
  headroom (`fw-rollback-fsbl-resource-map-2026-07.md:153-164`).
- **On-chain policy is a launch-time now-or-never that no prior doc names.**
  `PQSmartWallet` has **no upgrade path** — no UUPS, no `_authorizeUpgrade`, no
  `upgradeTo` anywhere in `contracts/smart-wallet/src/*.sol` (verified by grep)
  — and the implementation address is baked into the CREATE2 init-code hash.
  An unused lever exists: EntryPoint v0.6 packs `validationData` as
  `authorizer|validUntil|validAfter`, but PQ1 returns only the 0/1 sentinels
  (`PQSmartWallet.sol:74-75`), so a time-window is expressible with **zero ABI
  change**. A queue-then-execute timelock needs one ERC-7201 word per slot —
  free now, impossible after launch. Honest scope: this is value-of-key
  *reduction*, not extraction refusal, but unlike every on-die family it also
  bites drain. Invariant #5 line: an ECDSA guardian inside the wallet's
  verification path violates it; an address-based veto (`msg.sender == guardian`)
  is not a signer, but does add a liveness counterparty.

## The one option that literally refuses updates — weigh it, don't assume it away

**Post-personalization secure-update freeze.** Both external reviewers reached
this independently (Kimi's "updatability-removal posture", GPT-5.6's
"post-personalization Secure-update freeze"), and it was absent from the nine
families: **after the seed exists, accept no further secure-world image at all.**
Updates become a physical re-verification ceremony in the spirit of the
invariant-#10 verify-once-physically ethos, or a wipe-restore-reflash cycle.

It is the only proposal in the entire run that *literally* answers "refuse the
update", and it is the only one that works against A1/A2 — because there is no
acceptance predicate to subvert. It fits PQ1's positioning as a deliberate
slow-money signer, and nothing has shipped, so it is still a live product
decision rather than a regression.

Honest costs, which are severe and must be costed before anyone adopts it:
the clear-signing stack is exactly the code that needs updating (new ERC-7730
descriptors, new protocols, parser fixes); an unpatchable secure world means a
discovered parser bug is remediated only by RMA or by a wipe-restore cycle the
user must perform; it interacts with the A/B rollback design, which exists to
make updates safe; and it converts every future security fix into a support
event. A narrower variant worth costing separately: **freeze the secure world
but keep the NS image updatable**, which retains USB/companion iteration while
freezing everything that can see the seed — though note that today's
architecture puts the decoders and renderers in the *secure* image precisely to
avoid blind signing, so this variant is a substantial re-architecture, not a
build-flag.

**Recommendation: cost it at the same freeze review, and record the outcome
here even if the decision is "declined".** The record should show it was
weighed.

## Structurally inexpressible — foreclose, do not re-propose

Social recovery and on-chain multi-device **quorum** cannot be built in PQ1 as
designed: `addOwnerBytes` is reachable only with `ownerIndex == 0`, the bootstrap
key is a pure function of the seed, and invariant #6 forbids rotating it — so no
guardian can ever add an owner; and the wallet is strictly 1-of-N
(`_validateSignature` checks exactly one wrapper against one owner). Multi-device
*redundancy* is expressible but **enlarges** the attack surface, since any one
compromised device drains the wallet. Quorum must live outside the wallet.

## Additions to the "do not resurface" list

- **No measurement-bound secrets, in any form.** Beyond the known brick, the
  postmortem §4 already establishes the deeper reason: the binding is computed
  *by the measured code itself*, so malicious firmware simply supplies the
  genuine hash. There is no hardware measurement latch on STM32U585 — no PCR,
  no DICE CDI engine, no SAES measurement register. (Correction to a framing
  used earlier in this review: the 2026-04 brick required *three* concurrent
  causes — irreversible LcsO bump, non-deterministic PBS, and the fw_hash-bound
  wrap — any one of which defuses it, and the damage was one OID, not a dead
  chip. The security argument, not the reliability one, is what kills the idea.)
- **Do not treat the existing PIN gate as insider-attack resistance** (see D2).
- **Do not score "the user compares words" as covering A1/A2.** Both the
  install-time vendor-key fingerprint and the boot-time measurement change only
  if the *key* or the *bytes* change; under a stolen or compelled legitimate key
  the fingerprint is identical and the words match a genuinely published
  release.
- **Do not ship any design whose adversary table claims "blocks" for A1 or A2.**
  On this hardware, nothing does.

---

# UPDATE 2026-08-05 (round 2) — the negative result was over-stated; here is the corrected version

The owner challenged the round-1 negative result. **They were right to.** A second
research round, run with the explicit instruction to seek an affirmative answer
and with OPTIGA reliability out of scope, **substantially narrowed** it. Round 1
answered *"can the device refuse an arbitrary image?"* and reported it as the
answer to *"can the property be determined?"* — those differ, and off-device
determination was always available.

## What round 1 got wrong

**Reason 1 (Rice / "2-safety is unobservable") was simply wrong.** Rice quantifies
over *arbitrary* programs; it says nothing about a regime where you author every
image and a sound-but-incomplete checker is acceptable, because the remedy for a
rejection is to rewrite your own code. And 2-safety is not exotic here:
**`make checkct` (`Makefile:4361-4365`) already drives a relational
constant-time proof (cargo-checkct/BINSEC) over drivers that depend on the real
`pqsigner-domain` and `sphincs-c10` crates** (`tools/sca/checkct/driver_kdf/Cargo.toml:10`,
`driver_th/Cargo.toml:10`), with a by-design-insecure `fisher_yates` negative
control. The repo's own CI refutes the claim. *Honest caveat:* the drivers are
tiny leaf wrappers, so the **capability** is demonstrated and the **coverage** is
minimal — this is a foundation, not a result.

**Reason 6 ("draining is cheaper") was true but misused.** It shows a
seed-confidentiality guardrail is *insufficient*; it is not evidence the export
property is undeterminable. Round 1 used it to dismiss rather than to scope.

**Reason 2 (key roots reachable by any image) is narrowed to a design choice, not
a silicon property.** Every register a confinement design needs exists on this
part; PQ1 simply doesn't use any of them (zero MPU / `CONTROL_S.nPRIV` uses in
`secure/src`).

## What round 1 got right — and understated by ~200×

**Reason 5 (the signature is the exfiltration channel) is CONFIRMED and far worse
than stated.** The ~117-bit figure covered only `R`. The on-chain verifier reads
FORS material **verbatim from calldata** (`SPHINCsC10Asm.sol:93,110`) with no
constraint that it be PRF output. Of 4008 signature bytes, only the 836-byte
layer-1 block is pinned by `pkRoot`; ~3,100 B are free-form, with an unassailable
floor of **208 bytes per signature**. So the whole seed leaks in the *first*
signature. Consequence: **R-canonicalisation plus count-minimality remove roughly
151 of ~25,000 free bits — about 0.6%.** Any "close the subliminal channel"
design is dead on arrival; do not fund one as mitigation.

## The clean YES — and it is real

> **Holding the firmware image fixed and varying only the Merkle-rooted catalogue
> data (ERC-7730 descriptors, ERC-20/names/selector bundles) across everything the
> bundle verifiers admit, no seed-derived output of the device changes.**

Decidable **in seconds**, with no program analysis and no hyperproperty, from two
independently verified facts:

1. `compute_sphincs_digest_v06` (`aa/src/userop.rs:864-884`) hashes only UserOp
   parameters and the calldata digest — **descriptor bytes cannot influence what
   is signed**.
2. The transitive dependency closure of `pqsigner-erc7730`
   (`Cargo.toml:22-27` = proto/tx/tx-core + sha2/sha3/subtle) contains **no crate
   declaring a secret type** — no admissible descriptor can cause the interpreter
   to *name* a secret.

Five limits that must travel with that sentence, or it will be over-read:
(i) it is a **delta** property — a data change cannot *add* export capability; it
says nothing about whether the fixed image already has it; (ii) it is
**conditional on a data-only channel existing, which today it does not** — the
roots are compiled-in `pub static [u8;32]` (`secure/src/db_roots.rs:115`) and
`PQDESC_V1` has zero implementation, so every descriptor update is currently a
full firmware release (see `docs/erc7730-root-rotation-and-update-policy.md:22`
and its deferred §"Roadmapped (NOT v1)"); (iii) it covers **export only** — a
hostile descriptor can still mis-render intent; (iv) it is modulo memory-safety
of the secure-crate glue; (v) **it does not generalise to code.**

Given the observed churn — *4 root rotations in ~2 weeks* — building the
`PQDESC_V1` channel converts the dominant class of post-ship updates from
undecidable code into provably-inert data. That is the single highest-leverage
change surfaced by either round.

## For CODE updates: reject the taint-analyzer framing

An MIR information-flow analyzer is both the **expensive** leg and the
**insufficient** one — 100% of the exfiltration goes through the declassification
hatch it must permit (the signature). Every design that tried it produced a
property that is decidable and *irrelevant*: a conforming image exports the seed
anyway.

The tractable substitute is **signer identity**: pin that the transitive callee
closure of `crypto::c10_sign_verified*` is bit-identical to a locked reference
signer `H0`, plus argument provenance (the `sk` is the derivation ladder's output,
the `msg` is `compute_sphincs_digest_v06` of the confirmed tx), plus deterministic
or committed signing. That reduces *"does image H leak through the signature"* to
*"does H0 leak"* — a **hash comparison** plus a one-time offline review of a fixed,
reproducible artifact. Checked off-device; the device verifies one C10 signature
over "image H matched manifest M", reusing the verifier the FSBL already links, so
invariant #5 is untouched. The residual is bounded release — "one signature per
physical user event" is an assertion *by the code under judgement* until a
privileged monitor owns the release.

## One free, retroactive win

`SPHINCsC10Asm.sol:154-170` reads `count` as a raw `u32` and enforces **only**
`digitSum == 205` — no minimality, no upper bound. The honest signer's
`find_count` (`sphincs-c10/src/wots.rs:54-70`) scans from zero and returns the
**first** hit, i.e. minimal by construction. **Non-minimality is therefore an O(1)
publicly checkable fraud proof**: ~61k SHA-256 per signature off-chain, ~50k gas
on-chain, retroactive over all history, zero device or contract change. Ship it as
a *detector* that empirically tests whether the concern is live. **Never bank it as
mitigation** — see the 0.6% figure above.

## Corrected bottom line

- **Data updates: YES**, cleanly and cheaply — once the data-only channel exists.
- **Code updates: still no, by static analysis** — but for a *different and much
  stronger* reason than round 1 gave: not undecidability, but that the sanctioned
  signing operation is itself a 208-byte-per-signature covert channel. What
  replaces analysis is **signer-identity pinning**, which is a hash comparison.
- **First step is unchanged and still hours of work: fix D1.** Until
  `zeroize_sensitive_state()` is called before `FW_COMMIT`'s `sys_reset()`, every
  guardrail downstream is void.
