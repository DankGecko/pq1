# SPHINCS+ Post-Quantum Hardware Wallet — TrustZone Architecture

## Overview

This project implements a post-quantum hardware wallet using **SLH-DSA (SPHINCS+)** signatures
with **ARM TrustZone** isolation on a Cortex-M33 microcontroller. Private key material never
leaves the secure world. The non-secure world (USB, display, buttons) can only request
signatures through a narrow gateway.

The firmware targets **STM32U585** (production) and runs on **QEMU mps2-an505** (development).
A desktop CLI (`sphincs-wallet`) demonstrates the full TROPIC01 flow over USB.

Two modes of operation:
- **`mock-se`** (default): Mock secure element in SRAM, no hardware needed
- **`tropic01-se`**: Real TROPIC01 chip connected via USB at `/dev/ttyACM0`, bridged to
  QEMU via semihosting file I/O. All chip communication is e2e encrypted (X25519 + AES-256-GCM).

```
┌─────────────────────────────────────────────────────────────┐
│                    QEMU mps2-an505                          │
│  ┌──────────────────────┐   ┌────────────────────────────┐  │
│  │   SECURE WORLD       │   │   NON-SECURE WORLD         │  │
│  │                      │   │                             │  │
│  │  SPHINCS+ keys       │   │  USB protocol handler      │  │
│  │  AES-GCM wrap/unwrap │   │  OLED display driver       │  │
│  │  PIN verification    │   │  Button input               │  │
│  │  TROPIC01 comms ─────│───│──── /dev/ttyACM0 ──► chip  │  │
│  │  (e2e encrypted SPI) │   │                             │  │
│  │                      │   │  Calls secure world ONLY   │  │
│  │  SysTick handler     │◄──│  through gateway            │  │
│  │  polls gateway       │──►│  Reads results              │  │
│  └──────────────────────┘   └────────────────────────────┘  │
│         0x10000000                  0x00200000               │
│       (secure flash)              (NS flash)                │
└─────────────────────────────────────────────────────────────┘
         │ (semihosting SYS_OPEN / SYS_READ / SYS_WRITE)
         ▼
   ┌─────────────┐      USB serial       ┌────────────────┐
   │ /dev/ttyACM0│◄─────────────────────►│ TROPIC01 chip  │
   │ (host)      │  115200 8N1 raw       │ (TS1302 devkit)│
   └─────────────┘                        └────────────────┘
```

## Workspace Structure

```
sphincs_rust/
├── Cargo.toml              # Workspace root
├── Makefile                # Build orchestration (secure → veneers → nonsecure → QEMU)
├── rust-toolchain.toml     # Nightly 2026-04-06, thumbv8m.main-none-eabi
│
├── desktop/                # Original USB CLI (std, runs on host)
│   ├── Cargo.toml          #   sphincs-wallet — talks to real TROPIC01 over USB
│   └── src/
│       ├── main.rs         #   enroll + sign commands
│       └── usb_dongle.rs   #   SPI-over-USB transport (embedded_hal::SpiDevice)
│
├── shared/                 # #![no_std] types shared between worlds
│   ├── Cargo.toml          #   zero dependencies
│   └── src/lib.rs          #   NscStatus, size constants, memory addresses
│
├── secure/                 # TrustZone SECURE world firmware
│   ├── Cargo.toml          #   no_std crypto: slh-dsa, aes-gcm, sha2, hmac
│   ├── memory.x            #   FLASH 0x10000000 + NSC 0x103FF000 + RAM 0x38000000
│   ├── build.rs            #   Patches link.x to place .gnu.sgstubs in NSC region
│   └── src/
│       ├── main.rs         #   Boot: SAU → enroll → SysTick → boot NS
│       ├── sau.rs          #   SAU region config + MPC block config
│       ├── boot_ns.rs      #   VTOR_NS + MSP_NS + BXNS
│       ├── nsc.rs          #   Shared-memory gateway (4 commands)
│       ├── crypto.rs       #   KDF, AES-GCM, PIN state, enrollment
│       ├── pin.rs          #   PIN verify via MAC-and-Destroy chain
│       ├── secure_element.rs  # trait SecureElement + MockSecureElement
│       ├── semihosting_spi.rs # SpiDevice impl via semihosting (tropic01-se)
│       └── tropic01_se.rs     # Tropic01SecureElement with e2e encrypted sessions
│
└── nonsecure/              # TrustZone NON-SECURE world firmware
    ├── Cargo.toml          #   minimal: cortex-m-rt + semihosting
    ├── memory.x            #   FLASH 0x00200000 + RAM 0x28020000
    ├── build.rs
    └── src/
        ├── main.rs         #   Test harness: exercises all 4 gateway commands
        └── nsc_api.rs      #   Shared-memory gateway client
```

## Memory Map (QEMU mps2-an505)

The mps2-an505 has two SSRAM banks. The IDAU uses address bit 28 to distinguish
secure (0x1xxx/0x3xxx) and non-secure (0x0xxx/0x2xxx) aliases of the same physical memory.
The MPC (Memory Protection Controller) provides block-level S/NS attribution within each bank.

### SSRAM-0 (Code, 4 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x10000000-0x101FFFFF` | S     | Secure | Secure world code + rodata   |
| `0x103FF000-0x103FFFFF` | S     | NS     | NSC veneers (.gnu.sgstubs)   |
| `0x00200000-0x003FFFFF` | NS    | NS     | Non-secure world code        |

### SSRAM-1 (Data, 2 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x38000000-0x3801FFFF` | S     | Secure | Secure stack (128 KB)        |
| `0x28020000-0x2803FFFF` | NS    | NS     | Non-secure stack + BSS       |
| `0x2802FF00-0x2802FF14` | NS    | NS     | Shared memory gateway        |

### SAU Regions

| Region | Base         | Limit        | Type | Purpose              |
|--------|-------------|-------------|------|----------------------|
| 0      | `0x00200000` | `0x003FFFFF` | NS   | NS code flash        |
| 1      | veneer_base  | veneer_base+0xFF | NSC  | SG veneers (dynamic) |
| 2      | `0x28020000` | `0x29FFFFFF` | NS   | NS data SRAM         |
| 3      | `0x40000000` | `0x4FFFFFFF` | NS   | NS peripherals       |

Everything not covered by an SAU region defaults to Secure.

### MPC Configuration

| Controller | Register    | Blocks 0-63 | Blocks 64+ |
|-----------|-------------|-------------|------------|
| MPC0      | `0x58007000` | Secure      | NS         |
| MPC1      | `0x58008000` | Secure (0-3) | NS (4+)  |

## Secure Gateway

### Design

The gateway provides 4 operations across the TrustZone boundary:

| Command | ID | NS → S Args | S → NS Result |
|---------|-----|-------------|---------------|
| `GET_REMAINING` | 1 | — | Remaining PIN attempts (u32) |
| `ENTER_PIN` | 2 | ptr to 8-byte PIN | NscStatus |
| `GET_PUBKEY` | 3 | ptr to 32-byte output buf | NscStatus |
| `SIGN` | 4 | ptr to 32-byte hash, ptr to 17088-byte sig buf | NscStatus |

### Implementation (QEMU workaround)

On QEMU mps2-an505, the ARM CMSE `SG` instruction veneers do not work due to a bug
where the SG instruction check reads through the MPC NS alias, failing for S-marked blocks
(see "QEMU Limitations" below). The workaround uses **shared memory + secure SysTick polling**:

```
         NON-SECURE                                SECURE
    ┌───────────────────┐                  ┌──────────────────────┐
    │                   │                  │                      │
    │ 1. Write CMD+args │──────────────►   │                      │
    │    to 0x2802FF00  │  shared memory   │                      │
    │                   │                  │ 2. SysTick fires     │
    │ 3. Spin on DONE   │                  │    poll_gateway()    │
    │    flag           │                  │    reads CMD          │
    │                   │                  │    dispatches         │
    │ 4. Read RESULT    │  ◄──────────────│    writes RESULT     │
    │    from 0x2802FF10│  shared memory   │    sets DONE=1       │
    │                   │                  │                      │
    └───────────────────┘                  └──────────────────────┘
```

Shared memory layout at `0x2802FF00`:

| Offset | Name   | Size | Direction | Description     |
|--------|--------|------|-----------|-----------------|
| +0x00  | CMD    | 4    | NS→S     | Command ID      |
| +0x04  | ARG0   | 4    | NS→S     | Pointer to input data |
| +0x08  | ARG1   | 4    | NS→S     | Pointer to output buffer |
| +0x0C  | ARG2   | 4    | NS→S     | Output buffer length |
| +0x10  | RESULT | 4    | S→NS     | Return value (NscStatus) |
| +0x14  | DONE   | 4    | S→NS     | 1 = result ready |

### On Real Hardware (STM32U585)

Replace the shared memory gateway with proper CMSE veneers:

```rust
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_enter_pin(pin_ptr: u32, pin_len: u32) -> u32;
pub extern "cmse-nonsecure-entry" fn nsc_sign(hash_ptr: u32, sig_ptr: u32, sig_len: u32) -> u32;
pub extern "cmse-nonsecure-entry" fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32;
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32;
```

The `secure/src/nsc.rs` already exports `nsc_get_remaining_attempts` as a CMSE veneer.
The secure `build.rs` generates `veneers.o` via `--cmse-implib`, and the non-secure
build links against it. When the QEMU bug is not present (real hardware), these
veneers work directly.

## TROPIC01 Integration

### Semihosting SPI Bridge

The real TROPIC01 chip (TS1302 devkit) connects to the host laptop via USB serial
at `/dev/ttyACM0`. The firmware accesses it through QEMU's ARM semihosting:

1. **SYS_OPEN**: Opens `/dev/ttyACM0` on the host (the host must pre-configure with `stty`)
2. **SYS_WRITE**: Sends hex-encoded SPI commands (same protocol as `desktop/src/usb_dongle.rs`)
3. **SYS_READ**: Reads hex-encoded SPI responses byte-by-byte until `\n`
4. **SPI protocol**: `"A0B1C2x\n"` → chip processes → `"D3E4F5\r\n"`
5. **CS deassert**: `"CS=0\n"` → `"OK\r\n"`

The `SemihostingSpi` struct (`secure/src/semihosting_spi.rs`) implements
`embedded_hal::spi::SpiDevice`, so the `tropic01` crate works unmodified.

### E2E Encrypted Session

Every TROPIC01 operation establishes a fresh Noise_KK1 encrypted session:

```
Secure World                          TROPIC01 Chip
────────────                          ─────────────
1. startup_req(Reboot)          ───►  Chip resets
2. Generate ephemeral X25519          
   keypair (random from               
   host /dev/urandom)                  
3. session_start(                ───►  X25519 handshake
     shpub=SH0PUB_PROD0,              3x DH exchanges
     shpriv=SH0PRIV_PROD0,            AES-GCM auth verify
     ehpub, ehpriv, slot=0)    ◄───  Session keys derived
                                       (Noise_KK1 protocol)
                                       
   === All further commands encrypted with AES-256-GCM ===
   
4. mac_and_destroy(slot, data)   ─E2E─►  HMAC + destroy
5. r_mem_data_read(slot)         ─E2E─►  Read encrypted
6. r_mem_data_write(slot, data)  ─E2E─►  Write encrypted
7. session_abort()               ───►  Zeroize keys
```

The pre-shared pairing keys (`SH0PUB_PROD0`, `SH0PRIV_PROD0`) are compiled into
the secure world firmware. The ephemeral keys are fresh for each session, generated
from `/dev/urandom` via semihosting.

### Batch Operations

The `Tropic01SecureElement` provides batch methods that perform multiple operations
in a single e2e encrypted session, avoiding the overhead of re-establishing a session
for each individual command:

| Method | Operations per session |
|--------|----------------------|
| `batch_enroll()` | N x mac_and_destroy + 3 x r_mem_write |
| `batch_verify_pin()` | r_mem_read + mac_and_destroy + N x mac_and_destroy (re-init) + r_mem_write |
| `batch_read_key_material()` | 2 x r_mem_read |
| `batch_read_pin_state()` | r_mem_read |

### Running with Real TROPIC01

```bash
# 1. Connect TROPIC01 TS1302 devkit via USB
# 2. Configure serial port + build + run:
make run-tropic01

# Or manually:
stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb
make FEATURES=tropic01-se all
make run
```

## Cryptographic Design

### Key Hierarchy

```
                  ┌──────────────────┐
                  │  master_secret   │  32 bytes, random
                  │  (in TROPIC01)   │  protected by MAC-and-Destroy
                  └────────┬─────────┘
                           │
              ┌────────────┼────────────┐
              ▼                         ▼
      derive_wrap_key()          MACD slot secrets
      SHA256("sphincs-wrap-key"  (for PIN verification)
             || master_secret    
             || 0x00)            
              │                         
              ▼                         
      ┌──────────────┐                 
      │   wrap_key   │ AES-256-GCM key
      └──────┬───────┘                 
             │                         
             ▼                         
      ┌──────────────────────────┐     
      │  encrypted signing key   │ 64 bytes + 12 nonce + 16 tag = 92 bytes
      │  (stored in r-mem slot 0)│     
      └──────────────────────────┘     
```

### PIN Protection (MAC-and-Destroy)

Each PIN attempt consumes one MACD slot (9 slots = 9 attempts max). On correct PIN,
all slots are re-initialized. On 9 wrong PINs, the key is permanently erased ("bricked").

```
Enrollment (per slot j = 0..8):
  1. mac_and_destroy(j, init_input_j)     → initialize slot
  2. mac_and_destroy(j, pin_input_j)      → w_j (slot-specific wrap key)
  3. mac_and_destroy(j, init_input_j)     → re-initialize to known state
  4. encrypted_secrets[j] = AES-GCM(w_j, master_secret)

Verification (slot j = next_index):
  1. mac_and_destroy(j, pin_input_j)      → w_j'
  2. Try AES-GCM decrypt of encrypted_secrets[j] with w_j'
  3. If decrypt succeeds → correct PIN, recover master_secret
  4. If decrypt fails → wrong PIN, increment next_index
```

### SLH-DSA Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | SLH-DSA-SHA2-128f (FIPS 205) |
| Security level | 128-bit (NIST Level 1) |
| Signing key | 64 bytes |
| Verifying key | 32 bytes |
| Signature | 17,088 bytes |
| Stack during signing | ~20-34 KB |

## Secure Element Abstraction

The `SecureElement` trait abstracts the TROPIC01 API subset used by the wallet:

```rust
pub trait SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError>;
    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError>;
    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError>;
    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError>;
}
```

| Implementation | Feature | Backend |
|---------------|---------|---------|
| `MockSecureElement` | `mock-se` (default) | In-memory arrays, HMAC-SHA256 for MACD |
| `Tropic01SecureElement` | `tropic01-se` | Real TROPIC01 chip via semihosting SPI, e2e encrypted |

The mock stores up to 8 r-mem slots (512 bytes each) and 16 MACD slots (32 bytes each).
The real implementation establishes a fresh Noise_KK1 encrypted session per operation batch.

## Build System

### Prerequisites

```bash
rustup toolchain install nightly-2026-04-06
rustup target add thumbv8m.main-none-eabi --toolchain nightly
sudo apt install gcc-arm-none-eabi qemu-system-arm
```

### Build Commands

```bash
# Mock secure element (no hardware needed)
make all                          # Build both worlds with mock SE
make run                          # Build + run in QEMU

# Real TROPIC01 chip (TS1302 devkit at /dev/ttyACM0)
make run-tropic01                 # Configure serial + build + run
make FEATURES=tropic01-se all     # Build only (manual serial setup)
make setup-serial                 # Configure /dev/ttyACM0 only

# Other
make secure                       # Build only secure world
make nonsecure                    # Build only non-secure world
make clean                        # Remove build artifacts
```

### Build Pipeline

```
secure/           arm-none-eabi-ld         nonsecure/
  *.rs  ──────►  --cmse-implib  ──────►    *.rs
  memory.x        --out-implib=             memory.x
                   veneers.o                 +veneers.o
                        │                       │
                        ▼                       ▼
              sphincs-tz-secure.elf    sphincs-tz-nonsecure.elf
                        │                       │
                        └───────────┬───────────┘
                                    ▼
                          qemu-system-arm
                          -M mps2-an505
                          -kernel secure.elf
                          -device loader,file=nonsecure.elf
```

The secure world must build first because the non-secure world links against `veneers.o`
(the CMSE import library containing SG stub addresses). The Makefile uses separate
`--target-dir` for each crate to avoid linker flag conflicts.

### Linker Flags

| Crate | Linker Flags |
|-------|-------------|
| secure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=veneers.o` |
| nonsecure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=veneers.o` |

`arm-none-eabi-ld` is required because Rust's default linker (LLD) does not support CMSE.

## Boot Sequence

```
 1. QEMU starts in secure mode
 2. CPU fetches SP from 0x10000000, reset vector from 0x10000004
 3. cortex-m-rt Reset handler: zero BSS, copy .data
 4. main():
    a. Configure MPC0 (SSRAM-0: blocks 0-63 S, 64+ NS)
    b. Configure MPC1 (SSRAM-1: blocks 0-3 S, 4+ NS)
    c. Configure SAU (4 regions: NS code, NSC veneers, NS data, NS periph)
    d. DSB + ISB barriers
    e. Initialize MockSecureElement
    f. Enroll test SPHINCS+ keypair (deterministic seed, PIN "12345678")
    g. Initialize shared memory gateway (clear command buffer)
    h. Enable secure SysTick (1000-cycle interval)
    i. Set VTOR_NS = 0x00200000
    j. Set MSP_NS from NS vector table[0]
    k. BXNS to NS reset handler
 5. Non-secure world boots via cortex-m-rt
 6. NS main() exercises gateway commands
 7. debug::exit(EXIT_SUCCESS) terminates QEMU
```

## Sign Transaction Flow (End-to-End)

```
NS World                          Secure World
────────                          ────────────
1. Write PIN to NS SRAM
2. CMD=ENTER_PIN, ARG0=&pin  ──►  SysTick fires
                                  Read PIN from NS memory
                                  mac_and_destroy(slot, pin_input)
                                  AES-GCM decrypt master_secret
                                  Re-init all MACD slots
                                  RESULT=Ok, DONE=1
3. Read RESULT=Ok            ◄──

4. Write tx_hash to NS SRAM
5. CMD=SIGN, ARG0=&hash,     ──►  SysTick fires
   ARG1=&sig_buf, ARG2=17088     Read tx_hash from NS memory
                                  Read encrypted SK from SE slot 0
                                  Derive wrap_key from master_secret
                                  AES-GCM decrypt signing key (64 bytes)
                                  slh_dsa::SigningKey::try_sign(tx_hash)
                                  Write 17,088-byte signature to NS sig_buf
                                  Wipe signing key from RAM
                                  RESULT=Ok, DONE=1
6. Read RESULT=Ok            ◄──
   Read 17,088-byte signature
   from sig_buf
```

## QEMU Limitations

### MPC S-Alias Bug (QEMU 8.2.2)

**Symptom:** `SFSR.INVEP` (Invalid Entry Point) SecureFault when NS code branches to
an SG veneer, even though SAU correctly marks the region as NSC and the SG instruction
bytes are verified present.

**Root cause:** QEMU's mps2-an505 model does not allow S-alias reads
(`0x1xxx_xxxx`) of SSRAM blocks marked as NS by the MPC. The SG instruction verification
path reads through this broken path, so it cannot read the SG opcode and reports INVEP.
On real hardware, secure code can access both S and NS memory regardless of MPC settings.

**Workaround:** Shared memory gateway with secure SysTick polling (see "Secure Gateway"
section above). The CMSE veneers are still generated and linked — they will work on
real STM32U585 hardware.

**Note:** Secure code CAN read/write NS memory through the NS alias
(`0x0xxx_xxxx` / `0x2xxx_xxxx`). Only the S-alias of NS-MPC blocks is broken.

## Porting to STM32U585

When the STM32U585 board arrives:

1. **Memory map:** Update `memory.x` files with STM32U585 flash/SRAM addresses.
   The SAU programming model is identical (standard ARMv8-M). The MPC is replaced
   by STM32's GTZC (Global TrustZone Security Controller).

2. **Gateway:** Replace the shared memory gateway with proper CMSE veneers
   (`extern "cmse-nonsecure-entry"`). The veneer generation already works; only the
   NS-side call mechanism changes from shared memory to direct function calls through
   `veneers.o` symbols.

3. **Secure element:** Implement `Tropic01SecureElement` wrapping the `tropic01` crate
   over real SPI. The `tropic01` crate is fully `no_std` and takes any
   `embedded_hal::spi::SpiDevice`. Disable the `mock-se` cargo feature.

4. **RNG:** Replace deterministic test seed with hardware RNG (TROPIC01's TRNG via
   `random_value_get()`, or STM32U585's built-in RNG).

5. **Embassy:** Add `embassy-stm32` for async HAL (USB, SPI, GPIO). Embassy supports
   STM32U585 via feature flag `stm32u585zi`.

6. **Clock:** Replace the 1000-cycle SysTick with proper clock configuration.

## no_std Dependencies

All cryptographic crates run without heap allocation:

| Crate | Version | no_std | Notes |
|-------|---------|--------|-------|
| `slh-dsa` | 0.2.0-rc.4 | `default-features = false` | 17 KB signatures on stack |
| `aes-gcm` | 0.10 | `default-features = false, features = ["aes"]` | In-place encrypt/decrypt |
| `sha2` | 0.10 | `default-features = false` | Used for KDF |
| `hmac` | 0.12 | `default-features = false` | Used for mock MACD |
| `signature` | 3.0.0-rc.10 | `default-features = false` | Signer/Verifier traits |
| `tropic01` | git (libtropic-rs) | `#![no_std]` | TROPIC01 driver (optional, `tropic01-se` feature) |
| `x25519-dalek` | 2.0.1 | `default-features = false` | X25519 for e2e session (optional) |

## Security Considerations

- **Key isolation:** SPHINCS+ signing key exists in secure SRAM only during the signing
  operation. It is wiped (zeroed) immediately after use.

- **PIN bricking:** After `MAX_ATTEMPTS` (9) wrong PINs, the encrypted signing key and
  all MACD state are erased from the secure element. Recovery is impossible by design.

- **Pointer validation:** In the gateway, NS pointers should be validated against
  `NS_SRAM_BASE..NS_SRAM_END` before dereferencing. On real hardware, use the TT
  (Test Target) instruction for proper CMSE address validation.

- **Stack budget:** SPHINCS+ signing requires ~20-34 KB of stack (17 KB for the
  `Signature` struct + working memory). The secure world linker script allocates
  128 KB of SRAM with stack growing from the top.

- **Shared memory:** The gateway command buffer is in NS SRAM and is thus writable
  by the non-secure world at any time. The secure handler treats all data read from
  shared memory as untrusted input.
