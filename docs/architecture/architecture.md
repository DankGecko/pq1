# PQSigner OS architecture — current index

PQSigner OS is an STM32U585 TrustZone hardware wallet using OPTIGA Trust M
V3 + SE050 and SPHINCS+C10 for both bootstrap and slot signatures. The
authoritative architecture is deliberately split across the sources below so
wire formats, invariants, and production gates stay next to their executable
owners:

- [`../../CLAUDE.md`](../../CLAUDE.md) — invariants, lifecycle, gateway and
  wire formats, derivation, feature flags, and key-file map.
- [`../STATUS.md`](../STATUS.md) — implemented state and open security gates.
- [`../security/HARDENING.md`](../security/HARDENING.md) and
  [`../security/threat-model.md`](../security/threat-model.md) — current
  hardening contract and threat model.
- [`../security/production-security.md`](../security/production-security.md)
  and [`../production-todo.md`](../production-todo.md) — shipping fences and
  factory/silicon work.
- [`../firmware/firmware-update.md`](../firmware/firmware-update.md) — mutable
  firmware, A/B update, and rollback design.
- [`../companion/companion-erc7730-implementation-guide.md`](../companion/companion-erc7730-implementation-guide.md)
  and [`../companion/companion-safe-cowswap-presign.md`](../companion/companion-safe-cowswap-presign.md)
  — native trusted-display clear signing.

Safe, CoW, Aave, ERC-7730, ERC-20, and typed-call semantics are decoded
on-device. This index and the linked live documents define the only supported
clear-signing architecture.
