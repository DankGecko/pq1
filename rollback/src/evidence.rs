//! Artifact identity and evidence-join keys (§6.2 L2100–2140).
//!
//! Every artifact has one stable physical-generation identity
//! ([`ArtifactIdentity`]); proofs from one verification transaction share
//! a private boot-scoped join key ([`ArtifactEvidenceKey`]). Only the
//! immutable decoder/verifier may construct the key — modeled here by
//! [`VerificationPass`], whose host-model constructor stands in for the
//! immutable boot-time allocator (the pass id is never parsed from flash
//! or supplied by mutable code in the real system).
//!
//! Linearity: `VerificationPass`, `VerifiedArtifact`, `AcceptedArtifact`
//! are deliberately neither `Copy` nor `Clone`. `ArtifactIdentity` and
//! `ArtifactEvidenceKey` are plain data (the spec requires byte-for-byte
//! equality comparison between them, so they are `Copy` + `PartialEq`).

use fw_manifest::v6::{self, ManifestV6, PhysicalSlot};
use sha2::{Digest, Sha256};

/// The stable physical-generation identity of one artifact (§6.2
/// L2104–2108). No cross-slot, cross-address, cross-image, cross-snapshot,
/// or old/new-generation join is defined even when `(R,E,T)` matches.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArtifactIdentity {
    pub slot: PhysicalSlot,
    pub manifest_page_start: u32,
    pub pending_qw_address: u32,
    pub confirmed_0_qw_address: u32,
    pub confirmed_1_qw_address: u32,
    pub install_id: [u8; 16],
    pub r: u32,
    pub e: u32,
    pub t: u32,
    pub manifest_digest: [u8; 32],
    pub secure_hash: [u8; 32],
    pub nonsecure_hash: [u8; 32],
}

impl ArtifactIdentity {
    /// Model derivation of the journal QW addresses from the frozen §5
    /// registry: slot A's manifest is bank-1 page 5, slot B's page 6
    /// (`Owner::ManifestA/B`), and the journal QWs sit at the v6 offsets.
    /// NOTE (model choice): the legacy bench layout places manifests at
    /// pages 4/5; this pure core targets the frozen registry layout.
    pub fn manifest_page_start(slot: PhysicalSlot) -> u32 {
        let page = match slot {
            PhysicalSlot::A => 5,
            PhysicalSlot::B => 6,
        };
        pqsigner_geometry::page_addr(pqsigner_geometry::Bank::One, page)
    }

    /// Derive the identity for a verified manifest + install identity.
    pub fn derive(manifest: &ManifestV6, install_id: [u8; 16]) -> ArtifactIdentity {
        let page_start = ArtifactIdentity::manifest_page_start(manifest.slot);
        ArtifactIdentity {
            slot: manifest.slot,
            manifest_page_start: page_start,
            pending_qw_address: page_start + v6::OFF_QW_PENDING as u32,
            confirmed_0_qw_address: page_start + v6::OFF_QW_CONFIRMED_0 as u32,
            confirmed_1_qw_address: page_start + v6::OFF_QW_CONFIRMED_1 as u32,
            install_id,
            r: manifest.release_version,
            e: manifest.security_epoch,
            t: manifest
                .security_epoch
                .checked_sub(1)
                .expect("VerifiedArtifact requires E >= 1 (v6 range check)"),
            manifest_digest: manifest.stored_digest,
            secure_hash: manifest.secure_hash,
            nonsecure_hash: manifest.nonsecure_hash,
        }
    }
}

/// The private boot-scoped join key (§6.2 L2110–2113):
/// `ArtifactIdentity || boot_evidence_epoch || verifier_pass_id ||
/// attributed_ecc_receipt_set_digest`. Plain comparable data; only
/// [`VerificationPass`] can mint one bound to a pass.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArtifactEvidenceKey {
    identity: ArtifactIdentity,
    boot_evidence_epoch: u64,
    verifier_pass_id: u64,
    receipt_set_digest: [u8; 32],
}

impl ArtifactEvidenceKey {
    /// The artifact identity this key joins.
    pub fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Digest of this key for embedding in journal proofs
    /// (`FullTerminalSet`/`SurvivingTerminalSet`).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([self.identity.slot.to_u8()]);
        h.update(self.identity.manifest_page_start.to_be_bytes());
        h.update(self.identity.install_id);
        h.update(self.identity.r.to_be_bytes());
        h.update(self.identity.e.to_be_bytes());
        h.update(self.identity.t.to_be_bytes());
        h.update(self.identity.manifest_digest);
        h.update(self.boot_evidence_epoch.to_be_bytes());
        h.update(self.verifier_pass_id.to_be_bytes());
        h.update(self.receipt_set_digest);
        h.finalize().into()
    }
}

/// One bounded immutable verification transaction. Minted once per
/// boot/floor decode pass; proofs from two different passes cannot join
/// (§6.2 L2130–2133). Boot-scoped: neither `Copy` nor `Clone`.
pub struct VerificationPass {
    boot_evidence_epoch: u64,
    pass_id: u64,
    receipt_set_digest: [u8; 32],
}

impl VerificationPass {
    /// HOST-MODEL constructor: stands in for the immutable boot-time
    /// allocator. In the real system `pass_id` is allocated once per
    /// verification transaction and is unique within its
    /// `boot_evidence_epoch`; it is never parsed from flash or supplied
    /// by mutable code.
    pub fn begin(boot_evidence_epoch: u64, pass_id: u64, receipt_set_digest: [u8; 32]) -> Self {
        VerificationPass {
            boot_evidence_epoch,
            pass_id,
            receipt_set_digest,
        }
    }

    /// Mint the join key for one artifact identity in this pass.
    pub fn mint_key(&self, identity: ArtifactIdentity) -> ArtifactEvidenceKey {
        ArtifactEvidenceKey {
            identity,
            boot_evidence_epoch: self.boot_evidence_epoch,
            verifier_pass_id: self.pass_id,
            receipt_set_digest: self.receipt_set_digest,
        }
    }

    /// Wrap a verified manifest + install identity into a
    /// `VerifiedArtifact` joined to this pass.
    pub fn verify_artifact(
        &self,
        manifest: &ManifestV6,
        install_id: [u8; 16],
    ) -> VerifiedArtifact {
        let identity = ArtifactIdentity::derive(manifest, install_id);
        VerifiedArtifact {
            key: self.mint_key(identity),
        }
    }
}

/// A manifest/artifact that passed the immutable artifact checks
/// (structure, CRC, slot binding, digest binding, vendor signature,
/// install generation, ranges, rollback rule, image bounds; §7.1
/// L2586–2598) under one current join key. The v6-level checks are done
/// by `fw_manifest::v6`; this type binds the result to a
/// [`VerificationPass`]. Boot-scoped: neither `Copy` nor `Clone`.
pub struct VerifiedArtifact {
    key: ArtifactEvidenceKey,
}

impl VerifiedArtifact {
    /// The pass-joined evidence key.
    pub fn key(&self) -> &ArtifactEvidenceKey {
        &self.key
    }

    /// The stable artifact identity.
    pub fn identity(&self) -> &ArtifactIdentity {
        self.key.identity()
    }

    pub fn slot(&self) -> PhysicalSlot {
        self.identity().slot
    }

    pub fn r(&self) -> u32 {
        self.identity().r
    }

    pub fn e(&self) -> u32 {
        self.identity().e
    }

    /// Checked `T = E - 1`.
    pub fn t(&self) -> u32 {
        self.identity().t
    }

    pub fn install_id(&self) -> [u8; 16] {
        self.identity().install_id
    }
}

/// Robust terminal authority (§6.2 L2149–2151). Only a `FullTerminalSet`
/// constructs robust evidence; a `SurvivingTerminalSet` is repair-target
/// evidence only and can NEVER appear here.
pub enum RobustConfirmedEvidence {
    RobustTerminalSet(crate::journal::FullTerminalSet),
}

/// Accepted authority (§6.2 L2144–2147). Constructing it consumes the
/// verified artifact and its robust terminal evidence and requires their
/// keys to be byte-for-byte equal; distinct artifacts retain distinct
/// keys.
pub struct AcceptedArtifact {
    artifact: VerifiedArtifact,
    #[allow(dead_code)]
    evidence: RobustConfirmedEvidence,
}

impl AcceptedArtifact {
    /// Join artifact proof + robust terminal evidence. Returns `None`
    /// when the two do not carry the exact same `ArtifactEvidenceKey`
    /// digest (a cross-pass, cross-slot, or cross-generation join).
    pub fn new(
        artifact: VerifiedArtifact,
        evidence: RobustConfirmedEvidence,
    ) -> Option<AcceptedArtifact> {
        let RobustConfirmedEvidence::RobustTerminalSet(ref set) = evidence;
        if set.evidence_key() != &artifact.key().digest() {
            return None;
        }
        Some(AcceptedArtifact { artifact, evidence })
    }

    /// The accepted artifact.
    pub fn artifact(&self) -> &VerifiedArtifact {
        &self.artifact
    }
}
