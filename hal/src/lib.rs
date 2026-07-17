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

impl HalError {
    /// Does this error mean **"I don't know"** rather than an answer the
    /// hardware gave?
    ///
    /// `BusFault` and `Timeout` are the two that carry no information about
    /// whether the operation took effect: the peripheral may never have seen
    /// the command, or may have executed it and lost the reply. `BadParam` and
    /// `Unsupported` are our own bugs, caught before anything happened.
    /// `Corrupt` is an observation.
    ///
    /// The rule this exists for (work-todo D1, learned the hard way in the SE
    /// drivers): **a probe that cannot say "I don't know" says "no", and at
    /// every rotation site "no" was the branch that MUTATED.** Three sites
    /// collapsed a transport fault into an authoritative negative and fell
    /// through to a PUT KEY, a credential write, and an E140 rewrite — the
    /// brick path. Callers whose next step is an irreversible or destructive
    /// mutation MUST fail closed on an inconclusive result. Read-only callers
    /// may treat it as a plain failure.
    ///
    /// Mirrors `Se050Error::is_inconclusive` / `OptigaError::is_inconclusive`
    /// in the secure world, deliberately: one rule, three taxonomies.
    #[must_use]
    pub const fn is_inconclusive(self) -> bool {
        matches!(self, HalError::BusFault | HalError::Timeout)
    }
}

/// What a **mutating** hardware operation actually established.
///
/// `Result<(), HalError>` cannot express the state that matters most on this
/// device: *the command executed and we did not find out*. That is not a
/// pedantic distinction — it is the shape of every open hardware gate we have
/// (`HW-ASSUME-PUTKEY-ATOMIC`, `HW-ASSUME-QW-ATOMIC`, the D4 torn OTP master
/// burn), and a trait that cannot say it forces every implementation to guess
/// on the caller's behalf.
///
/// **This type is why the HAL seam is not yet wired** (work-todo M2). Wiring
/// `secure/src/hw/*` over traits that return `Result<(), E>` would let the
/// drivers be "verified" against a model that structurally cannot represent the
/// failure they actually risk — the proof would launder the optimism. See
/// `docs/verification/hardware-assumption-boundary-2026-07-17.md` §2.1, where
/// exactly that happened: `first_boot`'s crash harness cuts at every durable
/// boundary and is green, because its fake models an SE key rotation as
/// `self.se050_keys_final = true` while the real one is a probe-and-branch.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum MutationOutcome {
    /// The hardware acknowledged the mutation. Note what this does NOT mean:
    /// an ack is not an observation. For anything irreversible, confirm by a
    /// fresh read before treating it as done — `hw::otp::burn_device_master`'s
    /// read-back is the pattern (and D4 is what happens when that read-back is
    /// same-run only and a reset skips it).
    Acked,
    /// **Earned**: the command was never issued, or the hardware gave an
    /// authoritative no-effect rejection. Safe to retry.
    DefinitelyNotApplied(HalError),
    /// The command may or may not have taken effect: a timeout, a lost reply,
    /// a reset mid-operation. **Nothing was learned.** Do not retry a
    /// non-idempotent operation from here, and do not record progress; either
    /// re-probe the hardware for its actual state or fail closed to a terminal
    /// state. On a journal-resumable path, failing closed IS the retry.
    MayHaveApplied(HalError),
}

impl MutationOutcome {
    /// Did this establish that the mutation did NOT happen?
    #[must_use]
    pub const fn is_definitely_not_applied(self) -> bool {
        matches!(self, MutationOutcome::DefinitelyNotApplied(_))
    }

    /// Is the hardware's state now unknown to us?
    #[must_use]
    pub const fn is_ambiguous(self) -> bool {
        matches!(self, MutationOutcome::MayHaveApplied(_))
    }
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
    /// Program `data`. **An `Err` does not mean the flash is unchanged.**
    ///
    /// A reset or brown-out during a quad-word program can leave the line
    /// old, new, or ECC-poisoned (`HW-ASSUME-QW-ATOMIC`), and the quad-word is
    /// then spent — it cannot be re-driven. So an [`HalError::is_inconclusive`]
    /// result means *this quad-word's state is now unknown and it has probably
    /// been consumed*, not "nothing happened, try again". Callers that log
    /// progress on `Ok` and retry on `Err` are wrong on both edges.
    ///
    /// Intended shape once M2 splits the signature: [`MutationOutcome`], so the
    /// third state is representable rather than folded into `Err`.
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
    /// Burn `data`. Irreversible, and **an `Err` does not mean unburnt.**
    ///
    /// This is the sharpest instance of the whole problem, and it is not
    /// hypothetical — it is work-todo D4, fixed 2026-07-17. The device master
    /// spans TWO quad-words and takes two separate programs; a reset between
    /// them left `is_device_master_burned()` returning **true** on a
    /// half-blank master, so the burn was never completed and every SE
    /// transport credential silently rooted in 128 bits instead of 256.
    ///
    /// Consequences for any implementation of this trait:
    /// * a multi-quad-word field is NOT atomic — classify per quad-word, never
    ///   "any bit cleared ⇒ burned";
    /// * a same-run read-back does not survive a reset, so completeness must be
    ///   re-checked at boot, not only after the write;
    /// * an [`HalError::is_inconclusive`] result means the fuse state is
    ///   unknown and may be partially consumed.
    ///
    /// Intended shape once M2 splits the signature: [`MutationOutcome`].
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
    ///
    /// # This signature cannot express the failure that matters
    ///
    /// `xfer` is write-then-read in one call, so an `Err` is **ambiguous by
    /// construction**: it cannot distinguish "the write never reached the
    /// device" from "the device executed the command and the reply was lost".
    /// On this device that second case is the whole problem — it is a consumed
    /// PIN attempt, or a PUT KEY that installed a keyset we then fail to
    /// detect ([`MutationOutcome`], `HW-ASSUME-PUTKEY-ATOMIC`).
    ///
    /// Callers MUST therefore treat `Err(e)` where [`HalError::is_inconclusive`]
    /// as *the device may have acted*, and must not use it to decide that a
    /// mutation did not happen. That is not a style note: three sites in the
    /// production SE drivers made exactly that inference and fell through to an
    /// irreversible write (work-todo D1, fixed 2026-07-17).
    ///
    /// **Do not wire the real drivers over this trait until the signature is
    /// split** (work-todo M2). The intended shape returns
    /// [`MutationOutcome`]-style evidence for the write leg and a separate
    /// result for the read leg, so a driver can be checked against a model that
    /// can represent the ambiguity. Verifying drivers against this signature as
    /// it stands would prove them correct in a world where lost replies do not
    /// exist.
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
