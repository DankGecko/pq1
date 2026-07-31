//! pqsigner-rollback — the pure no_std journal/floor core for the Draft
//! 1.1 A/B rollback architecture (Foundation A slice FA-1.3, issue #540).
//!
//! Frozen authorities implemented here:
//!
//! * **FROZEN-JRN-IFACE-3** (doc L309–489): PENDING/ATTEMPTED composite
//!   representation and the TAMP `BKP8..31` arm token (`arm_token`).
//! * **FROZEN-OTP-API-3** (doc L853–1120): the `FloorView` 4-class
//!   decoder (`floor`), the `FreshQwRead` typed boundary (`qw_read`),
//!   QW accountancy, classification priority, the six frozen entries
//!   (`intents`), and `Aborted` semantics.
//! * **§6.2** (doc L1983–2236): journal codewords (reused from
//!   `fw_manifest::v6`), install-identity rules (`journal`), the arm
//!   token layout + 139-byte `PQFW_A3` binding (`arm_token`),
//!   `ArtifactIdentity`/`ArtifactEvidenceKey` (`evidence`),
//!   `FullTerminalSet`/`SurvivingTerminalSet` (`journal`), the six-row
//!   acceptance table + legal transition chain (`lifecycle`).
//! * **§7/§10** decoder/classification semantics (`floor`, `intents`).
//!
//! ## Hard design rules (owner-adopted review amendments)
//!
//! 1. Durability/ECC attribution enters ONLY as explicit typed
//!    parameters: [`qw_read::FreshQwRead`] with
//!    [`qw_read::CleanQw`] constructible only through
//!    [`qw_read::FreshArrayProbe`]; [`qw_read::Durability`] and
//!    [`qw_read::LaunchAttribution`] on every evidence interpretation.
//!    `OPEN-JRN-DUR-1`/`OPEN-ECC-1` remain the future real
//!    discriminators and are named at each use site.
//! 2. Every proof type is boot-scoped, linear, non-`Copy`, non-`Clone`,
//!    non-serializable; entries consume proofs by value and never return
//!    them.
//! 3. `SurvivingInstallGeneration` requires later-lifecycle evidence as
//!    a REQUIRED parameter; conflicting halves reject; a survivor half
//!    proven `BlankVirgin` after later lifecycle evidence is an
//!    impossible writer-order state and rejects.
//! 4. Terminal-first probing; a surviving terminal replica is
//!    repair-target evidence ONLY.
//! 5. The six-row acceptance table is exact; everything else is
//!    `Malformed`, which has no marker-only outgoing transition.
//! 6. `Aborted` boots only the previously accepted robust exact-`F`
//!    artifact or halts: no new-release path, no floor-write.
//! 7. `T == F` has ZERO mutable-backend effects; `T > F` yields a
//!    read-only receipt; `T < F` fails.
//! 8. QW accountancy: anything outside the authenticated map forces
//!    `Unknown`; no aliasing; no mutable head oracle.
//!
//! There are no physical writers in this crate. Writer ownership
//! (§6.3) constrains only the type shapes.

#![no_std]
#![forbid(unsafe_code)]

// The fake/scripted backend is host-test scaffolding only; enabling it
// for a bare-metal build is a hard error (same fence style as
// secure/src/nsc/mod.rs).
#[cfg(all(feature = "test-backend", target_os = "none"))]
compile_error!(
    "test-backend must never be enabled for bare-metal/production builds"
);

pub mod arm_token;
pub mod backend;
pub mod evidence;
pub mod floor;
pub mod intents;
pub mod journal;
pub mod lifecycle;
pub mod qw_read;
