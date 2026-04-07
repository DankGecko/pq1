# PQSigner OS

Post-quantum hardware wallet firmware using **SLH-DSA (SPHINCS+)** signatures with **ARM TrustZone** isolation on Cortex-M33. Private keys never leave the secure world.

```
  SECURE WORLD (TrustZone)          NON-SECURE WORLD
 +--------------------------+      +-------------------------+
 | SPHINCS+ signing key     |      | USB protocol handler    |
 | AES-256-GCM key wrapping |      | Display / buttons       |
 | PIN verification (MACD)  |      |                         |
 | TROPIC01 e2e encrypted   |<---->| Gateway calls only      |
 |   SPI (Noise_KK1)        |      | (4 commands via shared  |
 |                          |      |  memory + SysTick poll) |
 +--------------------------+      +-------------------------+
    0x10000000 (S flash)              0x00200000 (NS flash)
```

## Features

- **Post-quantum signatures** -- SLH-DSA-SHA2-128f (FIPS 205), 128-bit security level
- **TrustZone isolation** -- signing key, PIN state, and crypto ops confined to secure world
- **TROPIC01 secure element** -- keys encrypted at rest (AES-256-GCM) in hardware, all chip communication e2e encrypted (X25519 Noise_KK1)
- **MAC-and-Destroy PIN** -- 9-attempt limit with hardware-enforced key bricking
- **No heap** -- all `#![no_std]`, stack-only allocation, no allocator attack surface
- **Hardened gateway** -- NS pointer validation, TOCTOU defense, sensitive memory zeroization, custom panic handler that clears secrets

## Prerequisites

- Rust nightly (see `rust-toolchain.toml`)
- `arm-none-eabi-ld` (ARM bare-metal linker)
- QEMU with `mps2-an505` machine support (`qemu-system-arm`)
- For real hardware: TROPIC01 TS1302 devkit connected at `/dev/ttyACM0`

## Quick Start

### Interactive: drive the wallet with your laptop's arrow keys

```bash
make play
```

Maps your two arrow keys to the two physical buttons of the emulated
hardware wallet. Walk through the first-boot wizard, see the 24 BIP-39
words on the OLED, do the spot-check, sign a transaction.

| Key            | Action                                   |
|----------------|------------------------------------------|
| `<-`           | Left button — back / scroll down         |
| `->`           | Right button — next / scroll up          |
| `<-` + `->`    | Confirm (press both arrows together)     |
| `Esc`          | Cancel / back out                        |
| `Ctrl-C`       | Quit                                     |

### Non-interactive smoke test

```bash
make run                # raw single-char protocol, useful for piping inputs
make run-tropic01       # use the real TROPIC01 chip via /dev/ttyACM0
```

Expected end-of-run output:
```
[S] Wallet ready
[NS] Non-secure world started!
[NS] Remaining PIN attempts: 9
[NS] Get pubkey: Ok
[NS] Pubkey[0..4]: [30, 77, d8, 24]
[NS] Unlock: Ok
[NS] Sign: Ok
[NS] Sig len: 17088 bytes
[NS] === All tests passed! ===
```

## Project Structure

```
sphincs_rust/
+-- Cargo.toml              # Workspace root
+-- Makefile                 # Build orchestration (secure -> veneers -> nonsecure -> QEMU)
+-- secure/                  # TrustZone SECURE world firmware
|   +-- src/
|   |   +-- main.rs          # Boot: SAU -> enroll -> SysTick -> boot NS
|   |   +-- nsc.rs           # Secure gateway (4 commands, pointer validation)
|   |   +-- crypto.rs        # KDF, AES-GCM, PIN state, enrollment
|   |   +-- pin.rs           # PIN verification via MAC-and-Destroy
|   |   +-- sau.rs           # SAU + MPC configuration
|   |   +-- tropic01_se.rs   # TROPIC01 e2e encrypted sessions
|   |   +-- secure_element.rs # SecureElement trait + mock impl
|   +-- memory.x             # Linker script (S flash + NSC + S SRAM)
+-- nonsecure/               # TrustZone NON-SECURE world firmware
+-- shared/                  # Shared types (NscStatus, constants)
+-- desktop/                 # Host-side CLI (sphincs-wallet)
+-- docs/
    +-- architecture.md      # Detailed technical architecture
```

## Build Modes

| Feature | Description |
|---------|-------------|
| `mock-se` | Mock secure element in SRAM (default, for QEMU testing) |
| `tropic01-se` | Real TROPIC01 chip via semihosting SPI bridge |
| `debug-log` | Enable semihosting debug output (remove for production) |

Build without debug output for production:
```bash
make FEATURES=tropic01-se all
```

## Security Model

| Layer | Protection |
|-------|------------|
| **Key storage** | AES-256-GCM encrypted in TROPIC01 r-mem slots |
| **Key transport** | Noise_KK1 e2e encrypted sessions (X25519 + AES-256-GCM) |
| **Key in use** | Decrypted only in secure SRAM during signing, zeroized immediately after |
| **PIN** | MAC-and-Destroy chain -- 9 wrong attempts permanently erase key |
| **Memory isolation** | SAU + MPC partition secure/non-secure, NS pointer validation on all gateway calls |
| **Crash safety** | Custom panic handler zeroizes MASTER_SECRET before halting |
| **Build hardening** | LTO, overflow checks, debug info stripped, git deps pinned |

See [docs/architecture.md](docs/architecture.md) for the full technical design.

## Porting to Production Hardware

The firmware targets STM32U585 (Cortex-M33 with TrustZone). Key changes needed:

1. Update `memory.x` with STM32U585 flash/SRAM addresses
2. Replace shared memory gateway with proper CMSE veneers
3. Replace `SemihostingSpi` with Embassy SPI driver
4. Use hardware RNG instead of semihosting `/dev/urandom`
5. Configure PPC to restrict SPI to secure-only access
6. Add NS image signature verification before boot

## License

Copyright (c) 2026 EthereumPhone. All rights reserved.
