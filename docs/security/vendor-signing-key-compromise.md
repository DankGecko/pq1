# Vendor signing-key compromise recovery — design note

> Status: design note, not a specification. Filed under
> [EthereumPhone/PQ1#486](https://github.com/EthereumPhone/PQ1/issues/486)
> (Trezor-parity sweep 2026-07-20, TZP-15). Decision required **before the
> FSBL WRP freeze**; after that freeze option B below ceases to exist.

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
