# A/B rollback Draft 0.9 review receipt

Date: 2026-07-11
Scope: software-interface freeze and open-decision closure only

## Frozen artifact

- Architecture: historical object
  `git show rollback-architecture-v0.9:docs/security/a-b-firmware-rollback-architecture.md`
  (do not follow the mutable repository path, which now contains Draft 1.1)
- SHA-256:
  `f38b90307f15b87a65e9dc9d69583a74775fe4f77385e8b3a84978c34a947336`
- The repository copy was compared byte-for-byte with the reviewed `/tmp`
  artifact before commit.

The digest freezes the interface-contract layer: manifest-v4 bytes and signed
domain, journal/token bytes and transition ordering, the typed marker decoder
and selector, and the typed OTP floor API/semantics. It does **not** approve an
implementation or physical backend.

## Independent adjudication

Two independent Claude Code Opus 4.8 maximum-effort reviews re-hashed the
artifact at the start and immediately before reporting. Both returned:

> **APPROVE ARCHITECTURE FOR SOFTWARE-INTERFACE FREEZE AND OPEN-DECISION
> CLOSURE**

Reviewer A independently reproduced the manifest, token, marker, CRC, and all
three full-page fixtures and closed five accumulated red-lines. Reviewer B
independently reproduced the frozen domains/markers and closed its three
freeze-completeness, resource-contingency, and errata-provenance red-lines.
Two additional local adversarial passes returned GO on the same digest.

Those GO verdicts apply to the frozen specification digest, not to repository
integration. A later integration prosecution correctly returned NO-GO because
the first fence covered only secure `mode-production`, leaving FSBL, direct
release-shaped, factory, and false-green ship-gate paths. The integration was
therefore not committed or pushed in that state. It now carries mirrored
build-script + Rust compile gates, an explicit bench-only
`legacy-fw-rollback-unsafe` feature, factory/rehearsal/RDP2 refusals, an
expected-failure CI ship gate, and executed negative-compilation tests. This
does not raise the authority level of Draft 0.9.

Audit-material digests:

| Artifact | SHA-256 |
|---|---|
| Reviewer-A prompt | `cb5f2d129f14a7729b6d5a490f8ba89c531e483e83f1ead54db511c9cc8e3544` |
| Reviewer-A report | `c42d105e96b28d14ceebd55107e71548f5812dc999d3b84c27b98caa4bb3aaf2` |
| Reviewer-B prompt | `1293cc8a40a2da720dacdcb622b70e74e8a8e9918eb6d7f5801f99ad69e41b91` |
| Reviewer-B report | `bd3bb9489ec0341d96b352c531675354b97caf8efa7f100b966b98e1b26cfb51` |

The full prompt/report artifacts were retained outside the repository during
this review. Their hashes make later substitution detectable.

## Closed red-lines

1. The normalized full-page fixture includes erased, PENDING-only, and
   PENDING+CONFIRMED states and an independent-implementation requirement.
2. A floor-authorized manifest-recovery route is explicitly a new admission
   source and must re-freeze `FROZEN-JRN-IFACE-1`, Section 6.2 and Sections
   7.1/7.2. A changed marker/QW/CRC layout re-freezes `FROZEN-MAN-1`.
3. The 38,860-byte warning proxy is AMBER Draft-0.8-era research logic and
   reservations, not a Draft-0.9 combined implementation. The actual selected
   semantics must meet the 40,960-byte hard ceiling, the candidate's proposed
   38,912-byte final-core target, and the separate `OPEN-RAM-1` static-RAM and
   worst-case-stack gate.
4. ES0499 evidence is keyed by stable erratum titles. A production receipt
   must archive the exact official PDF, revision, SHA-256, title-to-section
   map, exact MCU revision, and applicability; moving section numbers from an
   unarchived review are not evidence.

## Authority deliberately withheld

The following remain blocking and open:

- `OPEN-JRN-HW-1` and `OPEN-JRN-DUR-1`;
- `OPEN-ECC-1` and `OPEN-OTP-1..3`;
- final physical FLASH LOAD-span fit, `OPEN-RAM-1` static-RAM and
  worst-case-stack fit, and the production key/profile link;
- `OPEN-REL-1`, `OPEN-C10-1`, health/timing parameters, and final factory
  policy;
- all sacrificial-silicon, OTP, option-byte, TAMP/BKP, and power-cut receipts.

No hardware was exercised and no OTP cell, flash option byte, or TAMP/BKP
state was changed during this phase. The next implementation phase may use
host models and non-destructive builds, but it must stop before the named-board
authorization gate in Section 13.

## Separate legacy hazard

The review confirmed that the pre-existing `secure/src/hw/otp.rs` bitwise
rollback tally is not a valid STM32U585 OTP design: user OTP is 512 bytes / 32
128-bit quad-words, and a programmed OTP quad-word is not a reusable per-bit
counter. That legacy code is **not** the frozen backend. Production must remain
compile-blocked until it is replaced by an implementation of the reviewed
interface and every physical gate above closes.
