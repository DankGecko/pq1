# Supply-Chain Defense — Deep-Research Brief (untrusted-manufacturer provisioning)

Paste-ready brief for a Claude deep-research run. Scoped to PQ1's actual model and
the gaps the 2026-05-29 supply-chain survey established.

> **UPDATE 2026-07-14 (work-todo #36).** The lockdown model changed after this
> brief was written: devices now ship at **RDP-0** (anyone can SWD-verify
> flash/option-bytes/OTP before first power via connect-under-reset) and
> self-lock to RDP-2 on the first field boot, followed by an on-device
> TRNG-salted pairing rotation off factory transport keysets. Read the
> baseline lines "host fixture bumps RDP2" and "a malicious station can flash
> backdoored firmware and self-lock" against that: the station no longer
> locks anything, and every shipped unit is pre-first-power auditable — the
> malicious-station residual becomes detectable by receiving audits and any
> end user with a probe.
>
> **UPDATE 2026-07-17.** The "any end user with a probe" line is now a
> designed consumer procedure, not an expert escape hatch:
> [`user-device-verification.md`](user-device-verification.md) — commodity
> $5 CMSIS-DAP probe on USB-C SBU pins, reset-halt ground-truth dump vs the
> reproducible release, fingerprint-word binding, confirm-gated Phase A.
> Its birth-certificate/transparency-log section is where this brief's #22
> manifest output should land.

```
DEEP RESEARCH BRIEF — State-of-the-art supply-chain-attack defense for a crypto
hardware wallet whose devices are provisioned by an UNTRUSTED contract manufacturer.

CENTRAL OBJECTIVE
We provision at a contract manufacturer (CM) we do NOT trust. Determine the
state-of-the-art way to:
  (1) PREVENT a malicious CM from overbuilding/cloning units, backdooring firmware,
      or weakening the device lockdown; and
  (2) let us CRYPTOGRAPHICALLY VERIFY, REMOTELY (without being physically present),
      that each shipped device was provisioned to the exact intended state by the
      legitimate flow.
Best case: remote verification is sufficient. Fallback: we send staff to supervise
on-site. A KEY deliverable is the boundary — what remote attestation can and cannot
prove, and therefore what residual genuinely requires on-site supervision.

THREAT MODEL — the CM is the adversary
The CM runs OUR provisioning tool, flashes the firmware, performs the lifecycle
lockdown, and handles the chips. Assume it can: keep blank STM32U585 + OPTIGA +
SE050 parts; obtain the (open-source) firmware image; run extra units off-line;
flash a MODIFIED firmware and self-lock it to RDP2; attempt to forge or replay a
provisioning attestation; substitute a counterfeit/different-variant chip; tamper
with the provisioning station. Out of scope: nation-state decap/SEM of the secure-
element dies (we inherit the SEs' CC EAL6+ certification for internal resistance).

FIXED CONSTRAINTS (do NOT re-litigate)
- Firmware is OPEN SOURCE. There is no firmware-confidentiality defense; anti-
  overbuild and anti-backdoor must come from the SECRET / ATTESTATION layer, never
  from obscurity. (So SFI-style firmware ENCRYPTION is not our lever; SFI-style
  HSM LICENSE METERING may still be.)
- Architecture is fixed: STM32U585 (custom FSBL + SPHINCS+C10 secure boot, NOT
  OEMiRoT), dual secure elements (Infineon OPTIGA Trust M V3 + NXP SE050E2),
  BIP-39 entropy XOR-split across the two SEs, user seed generated ON-DEVICE
  post-sale (the factory provisions the PLATFORM, never the user seed).
- The two SEs are CC EAL6+ and carry VENDOR-SIGNED factory attestation keys
  (NXP / Infineon) — a CM cannot forge those signatures even with the firmware.
- On-die roots exist: STM32 DHUK + BHK (per-die, SAES-only, never CPU-readable),
  the 96-bit STM32 UID, the SE UIDs. The provisioning tool derives SE secrets
  on-die from DHUK/BHK (no tool-held master).
- We have reproducible builds + an FSBL-rooted measured-boot fingerprint (8 BIP-39
  words) the END USER compares on first boot (trust-on-first-use firmware-integrity
  anchor).
- Our INTENDED mechanism (designed, ZERO code) is "#22": an SLH-DSA factory
  manifest signed by an HSM-held key (trust anchor baked into the FSBL) + a
  per-device transparency log + triple-UID + firmware-hash device binding.

CURRENT BASELINE (from the 2026-05-29 supply-chain survey — treat as the starting
point, do NOT re-derive)
- IMPLEMENTED: on-die DHUK/BHK roots (no tool-held master); SCP03 key-rotation
  primitive; a 7-step factory ceremony with stage->verify->burn-LAST (host fixture
  bumps RDP2 only after an OTP completion sentinel); foot-gun compile fences on
  irreversible burns; dual-SE XOR at-rest; FSBL SPHINCS+C10 verify + signed
  FW-update chain; reproducible builds + measured-boot fingerprint.
- THE KEYSTONE GAP: anti-overbuild + per-unit cryptographic attestation (= #22)
  have ZERO code. The implemented "post-provisioning verification" is only
  `is_provisioned()==false` + an OTP sentinel flag read over probe-rs — FORGEABLE
  by a malicious station, NOT cryptographic attestation.
- The provisioning STATION is trusted for IMAGE INTEGRITY: pre-RDP2 it controls
  firmware + option bytes; a malicious station can flash backdoored firmware and
  self-lock to RDP2 and nothing in-repo detects it. Clean-room is process-only.

RESEARCH TARGETS
1. THE TRUST ROOT THAT SURVIVES AN UNTRUSTED CM (the crux). An open-source-firmware
   device that self-provisions from on-die roots gives the CM everything to mint a
   self-consistent valid unit — so the ONLY thing distinguishing a genuine OEM-
   authorized device from a CM overbuild is a secret the CM CANNOT forge. Analyze
   the candidate roots and which actually resist an untrusted-CM: (a) the SEs'
   vendor-signed factory attestation keys (NXP EdgeLock / Infineon — CM can't forge
   an NXP/Infineon signature); (b) an OEM-HSM-injected per-unit secret/cert — but
   injection happens AT the CM, so analyze how to inject without the CM learning/
   cloning it (HSM-to-SE secure key-injection, EdgeLock 2GO-style); (c) STM32
   DHUK/BHK + UID (per-die but CM-accessible during provisioning — what do they
   actually prove to a remote verifier?); (d) a measured-boot-gated device-identity
   key. Output: where the remote-verifiable, CM-unforgeable root should live for
   THIS device (dual-SE + STM32).
2. REMOTE PROVISIONING ATTESTATION. Design a cryptographic, remotely-verifiable
   proof that a device reached the intended provisioned state. What to attest:
   firmware hash (== our reproducible build), the lifecycle/lockdown state (RDP2,
   WRP both banks, BOOT_LOCK, HDP, the SE pairing), the per-device UIDs, the SE
   genuineness. The hard sub-problem: a device computes its own state, so a
   BACKDOORED device could LIE — resolve via the SE factory attestation (challenge
   the SE to sign a nonce + attested read-back, verified against the pinned vendor
   root) and/or measured-boot-bound keys, so the attestation is rooted in something
   a backdoored firmware can't produce. Map to DICE/TPM-style layered attestation
   and SPDM device attestation.
3. ANTI-OVERBUILD. How to make extra units impossible or detectable: HSM-metered
   per-unit authorization tokens consumed at provisioning (ST SFI's HSMv2 license-
   count model — minus the firmware-encryption part we don't need); an OEM online
   service the tool must call per device; an append-only TRANSPARENCY LOG of every
   provisioned device's manifest with a genuine-check at activation (a unit not in
   the log is rejected). Given open-source firmware, which of these actually bind
   (the device must present something only the OEM could have issued)?
4. ANTI-BACKDOOR / FIRMWARE INTEGRITY AT AN UNTRUSTED STATION. Can a CM that flashes
   modified firmware + self-locks produce a passing attestation? Resolve: bind the
   firmware hash into the attestation via a root the modified firmware can't reach
   (SE attestation over the measured hash; or the OEM signs the device's identity
   cert only after verifying the attested firmware hash matches the reproducible
   build). Address the end-user measured-boot fingerprint as the last-line TOFU
   check and whether remote attestation makes it redundant or complementary.
5. THE REMOTE-VERIFY vs ON-SITE-SUPERVISE BOUNDARY (a required deliverable).
   Characterize precisely what remote cryptographic attestation PROVES (correct
   provisioned state, genuine SEs, no overbuild beyond authorized tokens, firmware
   hash matches) and what it CANNOT prove remotely (hardware implants added before/
   after provisioning, analog/physical tampering, a CM with chip-level forging
   capability, key-extraction during the provisioning window). Produce a risk-tiered
   decision: which threats are covered by remote attestation alone vs which require
   on-site supervision (and what minimal supervision covers the residual).
6. STATE OF THE ART / PRIOR ART to mine: ST SFI + HSMv2 license metering; NXP
   EdgeLock 2GO secure cloud provisioning (keeps SE secrets off the CM — directly
   relevant to our SE050); Infineon's OPTIGA personalization service; the DICE
   (Device Identifier Composition Engine) layered-attestation model + TCG TPM remote
   attestation + SPDM (DMTF) device attestation; Caliptra / OCP attestation;
   software-supply-chain frameworks (SLSA, in-toto, sigstore/Rekor transparency log)
   for the build+provisioning provenance; and how crypto-hardware-wallet vendors
   (Ledger genuine-check/attestation, Trezor, Coldcard, Keystone) actually attest
   genuineness + defend overbuild. Extract concrete, adoptable mechanisms.
7. EVOLVE OUR #22 PLAN. Given the above, refine the intended #22 design (HSM-signed
   SLH-DSA factory manifest + triple-UID + firmware-hash binding + transparency log)
   toward SOTA: is the manifest signed BY the device (attestation) or ABOUT the
   device (binding), or both? where does the per-unit authorization token fit? how
   does the OEM verify remotely + maintain the log + run the activation genuine-check?

EXCLUDE
- Firmware confidentiality / anti-readout of firmware IP (open source — not a lever).
- Re-deriving PQ1's current-state inventory (the 2026-05-29 survey did this; cite it).
- The secure elements' internal/die-level SCA/FI resistance (vendor CC EAL6+).
- Generic IoT cloud-onboarding that assumes a TRUSTED factory (our CM is untrusted).

OUTPUT FORMAT
- A recommended end-to-end architecture: the trust root, the remote attestation
  protocol (what's signed, by what key, verified how), the anti-overbuild metering,
  and the transparency-log / activation genuine-check — for OUR dual-SE + STM32U585
  + open-source-firmware device.
- The REMOTE-VERIFY vs ON-SITE-SUPERVISE boundary as a risk table (threat -> covered
  remotely? -> residual needing supervision).
- A comparison table of the SOTA mechanisms (SFI/HSM-license, EdgeLock 2GO, DICE,
  SPDM, SLSA/in-toto/Rekor, wallet-vendor practice) mapped to our threats.
- A concrete evolution path from our #22 design to the recommended architecture,
  with what to build first.
```

---

**Note for whoever runs this:** the brief deliberately treats the manufacturer as the adversary and makes *remote cryptographic attestation of correct provisioning* the headline, with the *remote-vs-supervise boundary* as an explicit deliverable — because the honest crux for an open-source-firmware wallet is "where does a trust root live that an untrusted CM can provision *with* but can't *forge*." The dual-vendor SE factory attestation keys (NXP/Infineon-signed) and an OEM-HSM-injected/EdgeLock-2GO root are the two candidates the research should weigh hardest. Current state + the keystone gap are in `docs/archive/provisioning-crosscheck-new-findings.txt` + work-todo #22.
