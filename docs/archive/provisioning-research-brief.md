# Provisioning Research Brief — STM32U585 + OPTIGA Trust M V3 + SE050

State-of-the-art secure **configuration + provisioning** of the three chips in
the PQ1 crypto hardware wallet. Production, one-shot, irreversible, debug-off
final state. This file is the paste-ready brief for a deep-research run.

---

## Primary objective

We flash/provision **on-site at the manufacturer using our own provisioning
tool**, under our supervision (initially). So the dominant risk is **not** a
malicious partner — it is **our own misconfiguration** of the three chips. The
deliverable is the **complete, authoritative, hardened configuration for each
chip for a hardware-wallet use case**: every security-relevant setting →
correct/hardened value → rationale → authoritative source → how to verify it
post-provisioning.

Working assumption: most real-world failures of these chips are
**misconfiguration** (wrong access condition, un-rotated default key,
over-permissive object policy, left-open lock bit, public sample trust anchor) —
**not** exotic exploits. Completeness is the goal: one missed setting is the
hole. The configuration + lockdown must remain **self-enforcing after our on-site
supervision ends**.

## Fixed design constraints (not under research — configure around these)

- **Root of trust = a custom immutable FSBL, NOT ST STiRoT/OEMiRoT.** Our ~18 KB
  WRP-locked first stage verifies the A/B firmware slots with a **SPHINCS+C10**
  (post-quantum, hash-based) signature and renders a measured-boot fingerprint
  before branching. We do **not** use STiRoT (ROM RoT), OEMiRoT (TF-M/MCUboot),
  or their image format / Trusted Package Creator flow. So research the **raw**
  STM32U5 primitives (RDP, WRP, HDP, BOOT_LOCK, TZEN/SAU/GTZC, OTP, OBKeys) and
  how to configure them to anchor a *custom* immutable first stage as the
  hardware RoT — mine the OEMiRoT/STiRoT docs only as a checklist of which
  primitives to set and to what values. **Dedicated sub-question:** how close can
  WRP + RDP2 + HDP + BOOT_LOCK bring a flash-resident FSBL to ROM-equivalent
  immutability, and what is the residual gap vs a true ROM RoT?
- **Both secure elements ship as a coordinated, dual-vendor pair — NOT a
  selection, NOT a primary/secondary split.** The BIP-39 entropy is XOR-split:
  one half on OPTIGA, one on SE050; neither chip alone reveals a single bit. The
  signing keys are derived from the reconstructed entropy **in the MCU TrustZone
  secure world** and live only in SRAM — neither SE stores a signing key; the SEs
  store the entropy halves + enforce PIN. Both enforce silicon PIN + 10-attempt
  lockout (three-way lockstep with an MCU counter) and run encrypted channels
  (OPTIGA Shielded Connection/PBS; SE050 SCP03). Vendor diversity (Infineon +
  NXP) is deliberate so a single-vendor break exposes only one XOR half; the two
  are even rooted on different MCU-intrinsic keys (OPTIGA PBS on DHUK, SE050
  SCP03 on BHK). Configure both, independently hardened to the same bar, as a
  coordinated pair.

## Ground everything in primary sources (explicitly required)

- **Chip-vendor official guidance & provisioning/security app notes:**
  - **ST:** STM32U5 security model + lifecycle/RDP/OBKey/OTP/HDP/Debug-Auth
    guidance, AN5156 (STM32 security intro), RM0456 security chapters, SFI /
    Trusted Package Creator docs, and the OEMiRoT/STiRoT docs (mined only as a
    checklist of which primitives to set and to what values — we do NOT use their
    flow/image format as-is; see Fixed design constraints).
  - **Infineon:** OPTIGA Trust M Solution Reference Manual, the Provisioning
    Guide, datasheet metadata/access-condition tables, Host Library docs,
    security advisories.
  - **NXP:** SE05x AN12413 (APDU spec), AN12436 (config + the **published**
    default SCP03 keys), Plug & Trust middleware docs, EdgeLock 2GO, SE050
    datasheet + variant/AppletConfig docs.
- **Common Criteria secure-configuration guidance (AGD)** for OPTIGA Trust M and
  SE050 — the certified-secure-state config requirements (CC certification
  reports + guidance docs). These are the authoritative "correct config" refs.
- **Third-party security audits / research** on these specific chips and on
  secure elements in hardware wallets, with their concrete recommendations:
  Ledger Donjon, wallet.fail, Kraken Security Labs, Riscure / eShard
  secure-element evaluations, relevant CVEs/advisories, academic SE &
  fault-injection papers, and how shipping wallets (Ledger, Coinbase Wallet HW,
  etc.) configure SEs. Include Trezor's published rationale for **not** using an
  SE as a counter-POV.

## Per-chip hardened configuration (the core deliverable — exhaustive matrix each)

- **STM32U585:** Product State / RDP 0/0.5/1/2 (target final RDP2 or DA-gated);
  TZEN + SAU/GTZC secure/non-secure partition; WRP on the FSBL/immutable pages;
  HDP boot-stage isolation; BOOT_LOCK + nSWBOOT0/nBOOT0; OTP (rollback counter +
  any secrets); OBKeys incl. Debug-Auth keys; brown-out (BOR) level; watchdog /
  SRAM-ECC / option-byte settings; debug fully disabled (or DA-gated). The
  complete option-byte / lock-bit matrix.
- **OPTIGA Trust M V3:** access conditions (Read/Change/Execute) for **every**
  data & key object; LcsO ratcheting (which objects → Operational/immutable vs
  changeable); PBS + Shielded Connection pairing/binding; trust anchor objects
  E0E3..E0E8 — must **not** remain the public Infineon sample cert (replace or
  lock); security monitor + monotonic/linked-use counters; lock unused/spare
  slots; Protected Update (SetObjectProtected) policy.
- **SE050:** per-object policies (read/write/USE/delete bitmask — forbid all but
  what's needed; no ALLOW_WRITE/DELETE except a dedicated provisioning admin
  object); SCP03 — rotate the published default platform keys + set **full**
  security level (C-MAC+C-ENC+R-MAC+R-ENC); UserID/PIN objects, max_attempts, and
  delete/admin-policy hardening; AppletConfig — disable unused applet features;
  attestation (ECKey) config; factory-reset-credential handling; lifecycle /
  persistent-object protection; host binding.
- **For all three:** a post-provisioning **verification** method that reads back
  / challenges every setting and proves the unit is in the exact intended state
  **before** the final irreversible burn.

## Provisioning sequence (correct provisioning includes correct ordering)

- The three chips are **coupled**: our SE secret roots derive from MCU-intrinsic
  keys (ST DHUK/BHK) that only become per-die/final at RDP0→1, so SE secret
  injection (SE050 SCP03 PUT KEY, OPTIGA PBS) is **gated on the MCU lifecycle
  step**.
- Every lock is one-way (STM32 RDP2/OTP; OPTIGA E140 → LcsO=Operational; SE050
  SCP03 rotation). Required ceremony shape: **stage all secrets/config reversibly
  → full verification gate → execute all irreversible burns LAST in dependency
  order**, so any pre-burn failure leaves a recoverable unit, not a brick.
  Validate the whole sequence on **sacrificial parts** first.

## Secondary (note only, not the focus)

- Because we supply + run the tool on-site and supervise initially, partner-trust
  machinery (HSM key custody, anti-overbuild license metering, tool-tamper
  defense) is secondary. Cover briefly: minimum measures so that **after**
  supervision ends the provisioned device is self-protecting and the partner
  cannot extract roots, clone, or weaken a correctly-locked unit.

## Exclude

- Cloud/IoT onboarding and factory-injected identity keys.
- Firmware confidentiality / anti-readout (firmware is fully open source).
- From-scratch CC/SESIP/PSA certification (inherit component certs; but **do**
  mine their CC guidance for config).

## Output format

- **THE primary deliverable:** a per-chip exhaustive hardened-configuration
  matrix (setting → hardened value → rationale → source → verification step).
- A consolidated, ordered provisioning-ceremony step list with every irreversible
  point marked and the stage→verify→burn-last boundaries shown.
- A "known misconfiguration pitfalls" list per chip, drawn from the third-party
  audit literature, each mapped to the setting that prevents it.
- A sources/citations list (vendor docs, CC guidance, audits) so each
  recommendation is traceable.

---

## PQ1-specific context (for whoever runs this — not part of the paste)

Our own already-identified misconfiguration ship blockers are the seed of the
"pitfalls" list the research should complete:

- **OPTIGA S-1:** F1D0 `Change = ALW` lets a desoldered-chip attacker overwrite
  the AuthRef HMAC key. Fix → `Change = Auto(F1D0)` + ratchet LcsO=Op.
- **OPTIGA S-2:** trust anchor at `0xE0E3` is Infineon's **public sample cert** —
  anyone can sign a SetObjectProtected manifest. Must replace/remove + lock
  `0xE0E4..0xE0E8` and the `0xF1D7` spare.
- **OPTIGA S-3:** `optiga-hw-counter` (E120 LUC bound to F1D0) must be mandatory
  in production.
- **SE050 S-5:** SCP03 must negotiate full security level `P1=0x33`
  (C-MAC+C-DEC+R-MAC+R-ENC). (Resolved 2026-05-28.)
- **SE050 S-6:** UserID admin-delete policy must not allow USERID_OBJ
  delete→recreate substitution. (Resolved 2026-05-28.)
- **SE050 S-7:** UserID `max_attempts` handling + status-code mapping.
  (Resolved 2026-05-28; one silicon check open.)

See `docs/production-todo.md` (per-chip one-way lockdown sequences + sacrificial
pre-commit checklists + escape hatches) and `docs/security/HARDENING.md §9` (provisioning
security) for our current plan; this research should produce the authoritative,
vendor-and-audit-sourced version of it.
