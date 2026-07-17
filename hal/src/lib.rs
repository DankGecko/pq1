//! `pqsigner-hal` — trait-only HAL surface for PQSigner OS.
//!
//! Every peripheral the secure world consumes is described here as a
//! trait so future driver impls (`pqsigner-hal-stm32u5`,
//! `pqsigner-hal-mock`, backup-MCU ports) plug in without per-call-site
//! `cfg(feature = "stm32u585")`s. The aggregate [`Platform`] trait
//! collects every per-peripheral trait into a single bound that
//! callers thread as `&mut impl Platform`.
//!
//! This crate is the **specification**. Anyone implementing a new
//! peripheral or a new MCU port must match these signatures verbatim.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// ---------------------------------------------------------------------------
// HalError
// ---------------------------------------------------------------------------

/// HAL-level error. Drivers map their richer per-peripheral errors
/// down to one of these variants at the trait boundary; the secure
/// world rarely cares about the exact peripheral fault, only that
/// "something went wrong on hardware" so it can return a uniform
/// `NscStatus::InternalError` or trigger a tamper response.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum HalError {
    /// I2C / SPI bus NAK, arbitration loss, parity error, …
    BusFault,
    /// Peripheral did not finish in time (HASH/SAES/PKA timeout, etc).
    Timeout,
    /// Caller passed an out-of-range parameter (slot index, page id,
    /// flash offset).
    BadParam,
    /// Caller asked the peripheral to do something its hardware can't —
    /// e.g. SAES with `KEYSEL=BHK` before BHK provisioning, or OTP
    /// burn against an already-burnt fuse.
    Unsupported,
    /// Persistent state inconsistency (TAMP backup register lost, OTP
    /// integrity word mismatched, etc). Treat as tamper.
    Corrupt,
}

// ---------------------------------------------------------------------------
// Random number generator
// ---------------------------------------------------------------------------

/// Hardware true-random / TRNG abstraction. The secure world trusts the output
/// for SPHINCS+ keygen seeds, the signing randomiser `r`, FI sentinels, the RDI
/// mask, and — irreversibly — the OTP device-master burn.
///
/// **Impl contract (what an implementation can actually be held to):** `fill`
/// MUST fail closed. It must surface a health-test / seed / clock error from
/// the underlying entropy source as `Err(HalError::Corrupt)` rather than
/// returning low-entropy bytes, and it must never return `Ok` having filled
/// `buf` partially or from a stalled source. The STM32U585 impl does this by
/// checking the RNG's `SECS`/`CECS` current-status bits on every word and
/// `SEIS`/`CEIS` on entry (`secure/src/hw/rng.rs::fill`), with a bounded
/// `DRDY` timeout.
///
/// **NOT an impl obligation (corrected 2026-07-17, work-todo D3):** this doc
/// previously required every driver impl to satisfy NIST SP 800-90B
/// post-conditioning. No driver can. SP 800-90B conformance is a property of
/// the *entropy source silicon* and its validation, not of the code that reads
/// its data register. Stating it as an impl obligation made the contract assert
/// something no implementation establishes, on a path that feeds an
/// irreversible OTP burn.
///
/// The real premise is a named silicon assumption: **`HW-ASSUME-TRNG-ENTROPY`**
/// — the STM32U585 TRNG meets SP 800-90B in our `RNG_CR` configuration. Status:
/// vendor claim; no ESV certificate naming the U585 was found. Its falsifying
/// test (self-run NIST EA over our own samples) and cost are tracked in
/// `docs/verification/hardware-assumption-boundary-2026-07-17.md` §6.
///
/// Defence in depth: callers on the irreversible paths do not rely on one
/// source — the secure world's `rng_strong::fill` XOR-folds STM32 + OPTIGA +
/// SE050 entropy, so a single broken TRNG does not silently determine a burned
/// key.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), HalError>;
}

// ---------------------------------------------------------------------------
// SHA-256 accelerator
// ---------------------------------------------------------------------------

/// SHA-256 streaming digest. The STM32U585 HASH peripheral is the
/// canonical impl; mock and host impls wrap `sha2::Sha256`.
pub trait Sha256 {
    fn init(&mut self);
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self) -> [u8; 32];
}

// ---------------------------------------------------------------------------
// Secure AES coprocessor (DHUK / BHK key selectors)
// ---------------------------------------------------------------------------

/// Selector for which key the SAES peripheral uses for an operation.
/// `Software` is for development and host-side tests; `Dhuk` is the
/// per-die hardware unique key; `Bhk` is the runtime-provisioned BHK;
/// `DhukXorBhk` is the SAES `KEYSEL=11` mode (cross-keyed).
//
// Intentionally NOT `Debug`: the `Software` variant carries a key
// reference and a derived `Debug` impl would print it.
#[derive(Clone, Copy)]
pub enum KeySelector<'a> {
    Software(&'a [u8; 32]),
    Dhuk,
    Bhk,
    DhukXorBhk,
}

/// SAES driver. `aes256_ecb` runs a single block; `cmac_dhuk` is the
/// SP 800-108 counter-mode CMAC the production secret-keys path uses.
pub trait Saes {
    fn aes256_ecb(
        &mut self,
        sel: KeySelector<'_>,
        in_block: &[u8; 16],
        out_block: &mut [u8; 16],
    ) -> Result<(), HalError>;

    fn cmac_dhuk(&mut self, msg: &[u8], out_tag: &mut [u8; 16]) -> Result<(), HalError>;
}

// ---------------------------------------------------------------------------
// Internal flash
// ---------------------------------------------------------------------------

/// Internal flash.
///
/// **STM32U585 semantics — quad-word, program-once.** The program granularity
/// is one complete 128-bit quad-word, and ECC is computed and latched over the
/// whole quad-word at its first program. A second program of an
/// already-programmed quad-word therefore **faults (PROGERR)** — *including*
/// when the new data would only clear bits that are already 0. Erase
/// granularity is one 8 KiB page on the dual-bank layout.
///
/// Corrected 2026-07-17 (work-todo D2). This doc previously said a program of
/// an already-cleared bit was "a no-op", i.e. a per-*bit* model. That is wrong
/// twice over: `secure/src/hw/flash.rs:723-725` states the quad-word rule, and
/// `flash.rs:1452` records it being hit in the field — writing a partially
/// programmed quad-word "PROGERRs ... and the caller surfaces it as `Sig commit
/// FAIL`" on devices upgraded across the all-C10 cutover. Real designs depend
/// on the quad-word rule and not the per-bit one: page-124 spends a *fresh
/// blank* quad-word per PIN attempt precisely because it cannot rewrite one,
/// and `hw::otp` rejected a unary rollback tally for the same reason.
///
/// The two statements were contradictory and nothing detected it, because
/// `secure/` does not depend on this crate (work-todo M2). A contract nobody
/// links is an axiom nobody checks — model at the granularity the silicon
/// commits at, and wire the seam so drift is a build failure.
///
/// The one-way premise itself (`HW-ASSUME-QW-ATOMIC`, `HW-ASSUME-OTP-ONEWAY`)
/// is a silicon assumption held by ST's documentation and our own field
/// experience, not by anything provable here. See
/// `docs/verification/hardware-assumption-boundary-2026-07-17.md`.
pub trait Flash {
    fn read(&self, page: u16, offset: u16, buf: &mut [u8]);
    fn program(&mut self, page: u16, offset: u16, data: &[u8]) -> Result<(), HalError>;
    fn erase_page(&mut self, page: u16) -> Result<(), HalError>;
}

// ---------------------------------------------------------------------------
// One-Time Programmable fuses
// ---------------------------------------------------------------------------

/// OTP fuse word range. The STM32U585 user-OTP is a flat 512-byte
/// region; this enum names the per-purpose subranges so callers can
/// bound fuse mutations to their concern (anti-rollback,
/// hardcoded-master-key fallback, BHK init-state, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpRange {
    AntiRollback,
    MasterKey,
    BhkProvisioned,
    /// Implementation-defined extra range; reserved for future use.
    Reserved(u8),
}

/// One-Time Programmable fuses. `burn_once` is monotonic: calling it
/// twice for the same fuse word with disagreeing data must return
/// `HalError::Unsupported`.
pub trait Otp {
    fn read(&self, range: OtpRange, buf: &mut [u8]);
    fn burn_once(&mut self, range: OtpRange, data: &[u8]) -> Result<(), HalError>;
}

// ---------------------------------------------------------------------------
// Boot state page (try-once slot tracking, FSBL signalling)
// ---------------------------------------------------------------------------

/// Persistent boot-state record. Used by the FSBL to track A/B slot
/// boot results and by the runtime to surface the prior boot's exit
/// code. Fields are an opaque blob from the trait's perspective; the
/// concrete layout lives in the impl + `secure/src/hw/boot_state.rs`.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootStateData {
    pub raw: [u8; 32],
}

pub trait BootState {
    #[must_use]
    fn read(&self) -> BootStateData;
    fn write(&mut self, data: BootStateData);
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperCause {
    BackupVoltage,
    LseClock,
    CryptoFault,
    DebugWhileLocked,
    Other(u8),
}

pub trait Tamp {
    fn arm(&mut self);
    #[must_use]
    fn check(&mut self) -> Option<TamperCause>;
}

// ---------------------------------------------------------------------------
// Power-side-channel mask
// ---------------------------------------------------------------------------

pub trait ConsumptionMask {
    fn randomize(&mut self);
}

// ---------------------------------------------------------------------------
// Buses (I2C, SPI)
// ---------------------------------------------------------------------------

pub trait I2cBus {
    /// Combined write-then-read transfer. Returns the number of bytes
    /// actually read into `r`.
    fn xfer(&mut self, addr: u8, w: &[u8], r: &mut [u8]) -> Result<usize, HalError>;
}

pub trait SpiBus {
    /// Full-duplex transfer. `w` is clocked out while `r` is clocked
    /// in; impls require `w.len() == r.len()`.
    fn xfer(&mut self, w: &[u8], r: &mut [u8]) -> Result<(), HalError>;
}

// ---------------------------------------------------------------------------
// Buttons (LEFT / RIGHT / etc.)
// ---------------------------------------------------------------------------

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Buttonset {
    pub left: bool,
    pub right: bool,
}

pub trait Buttons {
    #[must_use]
    fn poll(&mut self) -> Buttonset;
}

// ---------------------------------------------------------------------------
// UART
// ---------------------------------------------------------------------------

pub trait Uart {
    fn write(&mut self, buf: &[u8]);
}

// ---------------------------------------------------------------------------
// Platform aggregate
// ---------------------------------------------------------------------------

/// The aggregate platform: every peripheral surface in one trait so
/// the secure world can take `&mut impl Platform` rather than 12
/// individual generic bounds. Each `fn rng()`-style accessor returns a
/// mutable borrow of the per-peripheral driver so the caller can run
/// any of its trait methods on it.
pub trait Platform {
    type Rng: Rng;
    type Sha256: Sha256;
    type Saes: Saes;
    type Flash: Flash;
    type Otp: Otp;
    type BootState: BootState;
    type Tamp: Tamp;
    type ConsumptionMask: ConsumptionMask;
    type I2c: I2cBus;
    type Spi: SpiBus;
    type Buttons: Buttons;
    type Uart: Uart;

    fn rng(&mut self) -> &mut Self::Rng;
    fn sha256(&mut self) -> &mut Self::Sha256;
    fn saes(&mut self) -> &mut Self::Saes;
    fn flash(&mut self) -> &mut Self::Flash;
    fn otp(&mut self) -> &mut Self::Otp;
    fn boot_state(&mut self) -> &mut Self::BootState;
    fn tamp(&mut self) -> &mut Self::Tamp;
    fn consumption_mask(&mut self) -> &mut Self::ConsumptionMask;
    fn i2c(&mut self) -> &mut Self::I2c;
    fn spi(&mut self) -> &mut Self::Spi;
    fn buttons(&mut self) -> &mut Self::Buttons;
    fn uart(&mut self) -> &mut Self::Uart;
}

// ---------------------------------------------------------------------------
// Phased boot
// ---------------------------------------------------------------------------

/// Boot stages, executed in order. Drivers participate in the stages
/// where their peripherals come online; the secure-world entry can
/// drive bring-up as `for stage in BootStage::ALL { … }` instead of a
/// flat init list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootStage {
    /// RCC + clock tree + cache config.
    Clocks,
    /// SAU + GTZC partition + stack pointers + NS-secure RAM region.
    TrustZone,
    /// RNG + SHA-256 + SAES + AES + PKA + boot self-tests.
    Crypto,
    /// I2C / SPI / UART buses.
    Buses,
    /// OLED / semihosting / button GPIO init.
    Ui,
    /// SE provisioning + unlock readiness.
    Se,
}

impl BootStage {
    pub const ALL: [Self; 6] = [
        Self::Clocks,
        Self::TrustZone,
        Self::Crypto,
        Self::Buses,
        Self::Ui,
        Self::Se,
    ];
}
