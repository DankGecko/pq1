//! The typed hardware boundary for every flash/OTP quad-word read
//! (FROZEN-OTP-API-3, architecture doc L905–924).
//!
//! No decoder in this crate ever receives a bare `[u8; 16]`. Every read
//! enters as a [`FreshQwRead`], and a [`CleanQw`] — the only read class
//! that carries any authority — is constructible ONLY through the
//! [`FreshArrayProbe`] trait's provided `fresh_probe` method, which binds
//! the exact physical index and absolute address the caller asked to be
//! read. A host-test fake backend implements the trait with scripted
//! storage; nothing else in the dependency graph can mint a `CleanQw`.
//!
//! ECC/durability attribution enters ONLY as explicit typed parameters
//! ([`LaunchAttribution`], [`Durability`]) alongside each read — the same
//! owner-adopted review amendment as fw-manifest's `Attribution`. The
//! still-open real discriminators (`OPEN-JRN-DUR-1`, `OPEN-ECC-1`) are
//! named here and remain future gates; nothing in this crate hardcodes a
//! scripted durability assumption.

#![forbid(unsafe_code)]

/// The typed result of one fresh per-QW read at the hardware boundary.
///
/// `Clean` is the only variant with evidentiary weight. `Corrected` has
/// ZERO quorum weight and is never virgin; `Uncorrectable` and
/// `AmbiguousOrFault` confer no authority (FROZEN-OTP-API-3 L920–923).
/// Boot-scoped: deliberately neither `Copy` nor `Clone`.
pub enum FreshQwRead {
    /// An ECC-clean, fresh, exact-index read.
    Clean(CleanQw),
    /// ECC-corrected (ECCC) read. Zero quorum weight even when the
    /// corrected bytes happen to equal an expected codeword (§10
    /// L3681–3689).
    Corrected { bytes: [u8; 16], index: u16 },
    /// ECC double-bit error (ECCD) at `index`.
    Uncorrectable { index: u16 },
    /// Torn, may-have-launched, or otherwise ambiguous observation.
    AmbiguousOrFault,
}

/// An ECC-clean fresh read. Its typestate binds the physical QW index,
/// absolute address, bytes, probe epoch, and attributed status snapshot;
/// it cannot be reinterpreted at another index. Constructible only inside
/// [`FreshArrayProbe::fresh_probe`] (the constructor is crate-private).
///
/// Boot-scoped: deliberately neither `Copy` nor `Clone`.
pub struct CleanQw {
    index: u16,
    addr: u32,
    bytes: [u8; 16],
    probe_epoch: u32,
}

impl CleanQw {
    pub(crate) fn new(index: u16, addr: u32, bytes: [u8; 16], probe_epoch: u32) -> Self {
        CleanQw {
            index,
            addr,
            bytes,
            probe_epoch,
        }
    }

    /// Physical QW index this read was taken at.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Absolute address this read was taken at.
    pub fn addr(&self) -> u32 {
        self.addr
    }

    /// The exact 16 bytes read.
    pub fn bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// The immutable-entry probe epoch of this read.
    pub fn probe_epoch(&self) -> u32 {
        self.probe_epoch
    }

    /// True iff the bytes are exactly all-`0xFF`. This is NOT a
    /// `BlankVirgin` proof — that additionally requires
    /// [`LaunchAttribution::ProvenNoLaunch`] for the same index
    /// (FROZEN-OTP-API-3 L920–921).
    pub fn is_erased(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0xFF)
    }
}

/// The raw, untyped result a probe implementation reports for one forced
/// fresh read: the bytes read plus the raw attributed status snapshot.
/// Classification of the outcome class is CANONICAL — it happens only in
/// [`FreshArrayProbe::fresh_probe`], so an implementor can never choose
/// (or mislabel) the outcome class.
pub struct RawProbeResult {
    /// The bytes read. Meaningful only when `status` indicates the read
    /// completed; ignored for error classes by the canonical classifier.
    pub bytes: [u8; 16],
    /// The raw attributed status snapshot for this read.
    pub status: ProbeStatus,
}

/// The raw attributed status snapshot for one fresh read (untyped input
/// to the canonical classifier in [`FreshArrayProbe::fresh_probe`]). The
/// real platform implementation — NMI/ESR/cache mechanics behind each
/// variant — remains `OPEN-ECC-1`-gated and silicon-validated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeStatus {
    /// The read completed without any ECC event.
    NoEccEvent,
    /// Single-bit ECC correction was applied by hardware (ECCC).
    EccCorrected,
    /// Double-bit ECC error detected (ECCD).
    EccDoubleError,
    /// The read could not be attributed cleanly (fault, torn,
    /// may-have-launched, NMI ambiguity).
    Unattributable,
}

/// The exact-index fresh-array primitive (FROZEN-OTP-API-3 L916–918).
/// Implementations force one attributed array read per call and report
/// RAW bytes + a raw status snapshot; the provided [`fresh_probe`] method
/// is the ONLY place where the outcome class is derived, and the only
/// [`CleanQw`] constructor available outside this module.
pub trait FreshArrayProbe {
    /// The single immutable-entry probe epoch all reads of this pass bind.
    fn probe_epoch(&self) -> u32;

    /// Force one fresh attributed read at the exact physical `index` /
    /// absolute `addr`, returning raw bytes + the raw status snapshot.
    /// This is the only method implementors write.
    fn fresh_raw_read(&mut self, index: u16, addr: u32) -> RawProbeResult;

    /// The typed boundary. Canonically derives the outcome class from
    /// the raw status and binds exactly the requested index/address and
    /// this pass's probe epoch — a backend can never return a `CleanQw`
    /// for an index it was not asked to read, nor upgrade a corrected or
    /// faulted read to `Clean`.
    fn fresh_probe(&mut self, index: u16, addr: u32) -> FreshQwRead {
        let result = self.fresh_raw_read(index, addr);
        match result.status {
            ProbeStatus::NoEccEvent => {
                FreshQwRead::Clean(CleanQw::new(index, addr, result.bytes, self.probe_epoch()))
            }
            ProbeStatus::EccCorrected => FreshQwRead::Corrected {
                bytes: result.bytes,
                index,
            },
            ProbeStatus::EccDoubleError => FreshQwRead::Uncorrectable { index },
            ProbeStatus::Unattributable => FreshQwRead::AmbiguousOrFault,
        }
    }
}

/// Immutable-entry operation-history attribution for one QW index: may a
/// program/erase operation for THIS index have launched? Required input
/// for every `BlankVirgin` proof (FROZEN-OTP-API-3 L920–921: "Missing or
/// all-`FF` completion bytes alone are not proof"; erased-looking readback
/// never authorizes retry — FROZEN-JRN-IFACE-3 L311–315).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LaunchAttribution {
    /// Operation status, Route-1 reservation/claim, floor stage,
    /// ownership record, and writer launch state jointly prove that no
    /// operation for this exact index may have launched.
    ProvenNoLaunch,
    /// A program may have launched (torn, interrupted, or unknown
    /// history). The cell has zero virgin authority and, outside the
    /// authenticated accountancy map, forces `Unknown`.
    MayHaveLaunched,
}

/// Durability attribution for interpreting a `Clean` read as marker
/// evidence (the second leg of §6.2's "ECC-clean AND durably clean"). The
/// real discriminator is `OPEN-JRN-DUR-1`; until it closes this is an
/// explicit caller-supplied parameter, never a scripted assumption.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Durability {
    /// The observed bytes are durably clean (no torn/interrupted program
    /// ambiguity).
    DurableClean,
    /// Durability is ambiguous: the observation confers no marker
    /// authority.
    Ambiguous,
}

impl Durability {
    pub const fn is_clean(self) -> bool {
        matches!(self, Durability::DurableClean)
    }
}

/// Proof that one exact QW index is canonically virgin: an ECC-clean
/// all-`0xFF` fresh read PLUS proof that no operation may have launched
/// for that index. `Copy` is deliberate: this is an observation fact with
/// no standalone authority, unlike the linear proof capabilities.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlankVirgin {
    index: u16,
}

impl BlankVirgin {
    /// The only construction path: `read` must be `Clean` with all-`0xFF`
    /// bytes AND `launch` must be `ProvenNoLaunch`. A corrected all-`0xFF`
    /// value is neither blank nor virgin (§6.2 L2097–2098).
    pub fn prove(read: &FreshQwRead, launch: LaunchAttribution) -> Option<BlankVirgin> {
        match (read, launch) {
            (FreshQwRead::Clean(qw), LaunchAttribution::ProvenNoLaunch) if qw.is_erased() => {
                Some(BlankVirgin { index: qw.index() })
            }
            _ => None,
        }
    }

    /// The proven-virgin QW index.
    pub fn index(&self) -> u16 {
        self.index
    }
}
