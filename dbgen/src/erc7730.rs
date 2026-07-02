//! ERC-7730 clear-signing descriptor compiler.
//!
//! Reads JSON descriptors from a directory (one descriptor per file,
//! conforming to the ERC-7730 v2 schema at
//! <https://github.com/ethereum/clear-signing-erc7730-registry/blob/master/specs/erc7730-v2.schema.json>),
//! enforces the ERC-8176 attestation policy from `policy.toml`, and
//! emits one binary IR per `(chainId, contract)` deployment. The IRs
//! are Merkle-tree-hashed into `ERC7730_DESCRIPTORS_ROOT`, pinned in
//! `secure/src/db_roots.rs`.
//!
//! Wire layouts here match the on-device parser in
//! `pqsigner_erc7730::ir`. The 134-byte IR header uses **big-endian**
//! integers (unlike the LE-encoded ERC20 / Names / Selectors DBs); see
//! `docs/archive/handoff-erc7730-phase2.md` "Endianness flip" gotcha.
//!
//! ## Catalog blob layout (`tools/companion-stub/erc7730_db.bin`)
//!
//! ```text
//!   magic[4]              = "P730"
//!   version_le(4)         = ERC7730_DB_VERSION = 1
//!   flags_le(4)           = reserved (0)
//!   entry_cnt_le(4)
//!   ir_pool_off_le(4)
//!   ir_pool_size_le(4)
//!   proof_depth_le(4)
//!   proofs_off_le(4)
//!   // 32-byte header
//!
//!   entries[entry_cnt] (72 B each):
//!     chain_id_le(8) | contract(20) | primary_type_hash(32)
//!     | context_kind(1) | _pad(3) | ir_off_le(4) | ir_len_le(4)
//!
//!   ir_pool (concatenated IR bytes; ir_off is into this region)
//!
//!   proofs (entry_cnt * proof_depth * 32 bytes)
//! ```
//!
//! Sort order: `(chain_id, contract, primary_type_hash, context_kind)`.
//! Companion does a binary search by `(chain_id, to)` and emits the
//! trailer that `pqsigner_erc7730::bundle::verify_erc7730_bundle`
//! consumes.
//!
//! ## ERC-8176 policy
//!
//! Read from `secure/data/erc7730/policy.toml`. In dev mode
//! (`allow_unattested_dev_descriptors = true`) every descriptor is
//! accepted regardless of attestations; CI MUST reject production
//! builds with that flag on. Production mode requires
//! `min_attesters` ≥ N independent CAIP-2 identities from
//! `trusted_attesters`. Today's seed corpus is hand-pulled from the
//! upstream registry without attestations, so dev mode is on by
//! default. Phase 3+ wires the registry-mirror attestation chain.

use crate::merkle::{node_hash, verify_proof, MerkleTree};
use pqsigner_erc7730::bundle::{leaf_hash, verify_erc7730_bundle};
use pqsigner_erc7730::ir::{
    Erc7730Ir, CONTRACT_NAME_FIELD_LEN, CTX_CONTRACT, CTX_EIP712, HEADER_LEN, MAX_FIELDS_PER_FORMAT,
    MAX_FORMATS, MAX_IR_LEN, MAX_NESTED_MEMBERS, OWNER_FIELD_LEN, SCHEMA_VER,
};
use pqsigner_tx_core::hash::keccak256;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────────────────────────
// Catalog header constants (mirrored from the other on-disk DBs).
// ─────────────────────────────────────────────────────────────────────

pub const ERC7730_DB_MAGIC: [u8; 4] = *b"P730";
pub const ERC7730_DB_VERSION: u32 = 1;
pub const ERC7730_DB_HEADER_LEN: usize = 32;
pub const ERC7730_DB_ENTRY_LEN: usize = 72;

// ─────────────────────────────────────────────────────────────────────
// Pool TLV constants (Phase 5 walker MUST match these byte-for-byte).
// ─────────────────────────────────────────────────────────────────────

const PATHOP_ROOT_STRUCT: u8 = 0x10;
const PATHOP_ROOT_CONTAINER: u8 = 0x11;
const PATHOP_ROOT_METADATA: u8 = 0x12;
const PATHOP_FIELD_IDX: u8 = 0x20;
// Wire constants for the device-side path bytecode (canonical wire space shared
// with the on-device `PathOp` enum). In a rendered-VALUE path dbgen emits only
// ArrayAll (render-all of a sole dynamic array) — single-index / slice / last are
// refused there (they would hide an array's other elements). ArrayIdx / ArraySlice
// / ArrayLast ARE emitted, but ONLY inside a `tokenAmount`'s `PARAM_TOKEN_PATH`
// TLV (token-IDENTITY extraction from a dynamic swap leg — Tier B, see
// `compile_token_path_extraction`), never in a rendered-value program. Encoding:
// ArrayIdx = op + u16 BE index; ArraySlice = op + u16 BE start + u16 BE len(=20) +
// 1 B from_end; ArrayLast = op. Device: `render::resolve::resolve_token_address`.
const PATHOP_ARRAY_IDX: u8 = 0x21;
const PATHOP_ARRAY_SLICE: u8 = 0x22;
const PATHOP_ARRAY_LAST: u8 = 0x23;
const PATHOP_ARRAY_ALL: u8 = 0x24;
/// Follow the ABI offset word at the current head slot into the calldata tail
/// (C1 dynamic `bytes`/`string`; C2 dynamic-tuple descent). Device:
/// `render::resolve::resolve_structured`.
const PATHOP_FOLLOW_OFFSET: u8 = 0x25;

const FMT_RAW: u8 = 0x01;
const FMT_AMOUNT: u8 = 0x02;
const FMT_TOKEN_AMOUNT: u8 = 0x03;
const FMT_NFT_NAME: u8 = 0x04;
const FMT_DATE: u8 = 0x05;
const FMT_DURATION: u8 = 0x06;
const FMT_ADDRESS_NAME: u8 = 0x07;
const FMT_ENUM: u8 = 0x08;
const FMT_UNIT: u8 = 0x09;
const FMT_CALLDATA: u8 = 0x0A;
const FMT_CHAIN_ID: u8 = 0x0B;
const FMT_TOKEN_TICKER: u8 = 0x0C;
const FMT_INTEROP_ADDR_NAME: u8 = 0x0D;
const FMT_ENCRYPTED: u8 = 0x0E;

const PARAM_TOKEN_PATH: u8 = 0x30;
const PARAM_TOKEN: u8 = 0x31;
const PARAM_THRESHOLD: u8 = 0x32;
const PARAM_MESSAGE: u8 = 0x33;
const PARAM_ADDR_TYPES: u8 = 0x34;
const PARAM_ADDR_SOURCES: u8 = 0x35;
const PARAM_DATE_ENCODING: u8 = 0x36;
const PARAM_ENUM_REF: u8 = 0x37;
const PARAM_DECIMALS: u8 = 0x38;
const PARAM_BASE: u8 = 0x39;
const PARAM_PREFIX: u8 = 0x3A;
const PARAM_SUFFIX: u8 = 0x3B;
const PARAM_NESTED_SELECTOR: u8 = 0x3C;
const PARAM_NESTED_CALLEE: u8 = 0x3D;
const PARAM_FALLBACK_LABEL: u8 = 0x3E;
const PARAM_VISIBILITY: u8 = 0x3F;
/// Constant annotation string for a path-less ERC-7730 field
/// (`{ "value": "...", "label": "...", "format": "raw" }`). The field is
/// not bound to calldata — it renders the literal (attested) string. Used
/// pervasively by the ERC-4626 / ERC-7540 vault templates.
const PARAM_CONST_VALUE: u8 = 0x40;

/// Format-level flag (parked on an EIP-712 format's first field) marking
/// that the primary type carries at least one nested struct member — a
/// single opaque `hashStruct` word the on-device renderer cannot expand.
/// The device declines the whole format to blind-sign on seeing it, so a
/// nested member (and any `address` inside it) is never partially
/// clear-signed or rendered as a garbage word
/// (`VULN-erc7730-eip712-nested-struct-address-hide`, on-device belt). The
/// build-time visibility gate is the primary defense; this is the
/// defense-in-depth backstop that survives a gate regression and is where
/// the future Phase-5 nested renderer will hook faithful expansion.
const PARAM_NESTED_STRUCT: u8 = 0x41;

/// Maximum EIP-712 struct nesting the gate will walk before failing closed.
/// Matches the on-device `ir::MAX_NESTING`; a type deeper than this (or a
/// malformed cyclic one) is refused rather than reasoned about.
const MAX_STRUCT_DEPTH: usize = 8;

// Visibility byte values (matching `pqsigner_erc7730::ir::Visibility`).
const VIS_ALWAYS: u8 = 0x00;
const VIS_NEVER: u8 = 0x01;
const VIS_OPTIONAL: u8 = 0x02;
const VIS_IF_NOT_IN: u8 = 0x03;
const VIS_MUST_MATCH: u8 = 0x04;

// Address-type bitset (PARAM_ADDR_TYPES payload).
const ADDR_TYPE_WALLET: u8 = 0x01;
const ADDR_TYPE_EOA: u8 = 0x02;
const ADDR_TYPE_CONTRACT: u8 = 0x04;
const ADDR_TYPE_NFT_COLLECTION: u8 = 0x08;
const ADDR_TYPE_TOKEN: u8 = 0x10;
const ADDR_TYPE_COLLECTION: u8 = 0x20;

// Address-source bitset (PARAM_ADDR_SOURCES payload).
const ADDR_SRC_LOCAL: u8 = 0x01;
const ADDR_SRC_ENS: u8 = 0x02;
const ADDR_SRC_ETHERSCAN: u8 = 0x04;
const ADDR_SRC_REGISTRY: u8 = 0x08;

// Date-encoding (PARAM_DATE_ENCODING payload).
const DATE_ENC_TIMESTAMP: u8 = 0x00;
const DATE_ENC_BLOCKHEIGHT: u8 = 0x01;

// Maximum bytes per pool TLV payload — same cap the on-device walker
// uses (Phase 5 will enforce).
const MAX_POOL_TLV_PAYLOAD: usize = 254;
// Maximum bytes per path program. Single byte length prefix → 255.
const MAX_PATH_PROGRAM_LEN: usize = 255;

// ─────────────────────────────────────────────────────────────────────
// JSON shapes (subset of the ERC-7730 v2 schema we ingest today).
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(rename = "$schema")]
    _schema: Option<String>,
    /// `includes` reference. Phase 2 rejects descriptors that use this
    /// field — the registry's templated permit / common-EIP712 entries
    /// land in Phase 3 once we wire the registry-mirror submodule.
    #[serde(default)]
    includes: Option<String>,
    context: Context,
    metadata: Metadata,
    display: Display,
}

#[derive(Debug, Deserialize)]
struct Context {
    #[serde(rename = "$id", default)]
    id: Option<String>,
    #[serde(default)]
    contract: Option<ContractContext>,
    #[serde(default)]
    eip712: Option<Eip712Context>,
}

#[derive(Debug, Deserialize)]
struct ContractContext {
    deployments: Vec<Deployment>,
    // `abi` field is deprecated in v2 — parameter names live in the
    // format key strings now. We deliberately ignore it.
}

#[derive(Debug, Deserialize)]
struct Eip712Context {
    #[serde(default)]
    deployments: Option<Vec<Deployment>>,
    #[serde(default)]
    domain: Option<Eip712Domain>,
    #[serde(rename = "domainSeparator", default)]
    domain_separator: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct Eip712Domain {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(rename = "chainId", default)]
    chain_id: Option<u64>,
    #[serde(rename = "verifyingContract", default)]
    verifying_contract: Option<String>,
    #[serde(default)]
    salt: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Deployment {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
}

#[derive(Debug, Deserialize, Default)]
struct Metadata {
    #[serde(default)]
    owner: Option<String>,
    /// Free-form `info` block (URL, deploymentDate, legalName, …). We
    /// surface it on the review file only; the on-device IR doesn't
    /// carry it.
    #[serde(default)]
    _info: Option<serde_json::Value>,
    #[serde(default)]
    constants: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    enums: Option<serde_json::Map<String, serde_json::Value>>,
    /// Per-descriptor token metadata used by the v2 spec to default
    /// `tokenAmount` decimals/symbol when no `tokenPath` is supplied.
    /// Phase 2 doesn't depend on this since the seed corpus carries
    /// explicit `tokenPath` everywhere.
    #[serde(default)]
    _token: Option<serde_json::Value>,
    #[serde(rename = "contractName", default)]
    contract_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Display {
    formats: BTreeMap<String, Format>,
    /// `$.display.definitions` — reusable field-format specs referenced by
    /// `fields[].$ref`. A definition is a format spec (label/format/params),
    /// never a path-bound field. Populated from the descriptor OR from an
    /// `includes` common file (the include deep-merge runs at the JSON layer
    /// before this deserializes, so both sources land here). See
    /// [`resolve_display_refs`]. (review finding 1.1)
    #[serde(default)]
    definitions: Option<BTreeMap<String, FieldDef>>,
}

#[derive(Debug, Deserialize)]
struct Format {
    #[serde(rename = "$id", default)]
    _id: Option<String>,
    #[serde(default)]
    intent: Option<String>,
    fields: Vec<FieldDef>,
    /// v2 `interpolatedIntent` — valid but unrendered (we show `intent`);
    /// modelled (ignored) so it doesn't trip the 1.3 unknown-key gate.
    #[serde(rename = "interpolatedIntent", default)]
    _interpolated_intent: Option<serde_json::Value>,
    /// Catch-all for unmodelled top-level format keys (finding 1.3).
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
struct FieldDef {
    /// Absent for a constant-annotation field (see `value`).
    #[serde(default)]
    path: Option<String>,
    /// Constant annotation string for a path-less field. Mutually
    /// exclusive with `path`. ERC-7730 allows `{ value, label, format }`
    /// with no path — a fixed (attested) string, not bound to calldata.
    #[serde(default)]
    value: Option<serde_json::Value>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    params: Option<serde_json::Value>,
    #[serde(default)]
    visible: Option<String>,
    /// `$ref` into `$.display.definitions.*` — a reference to a reusable
    /// format spec. The reference object carries its own `path`/`value`,
    /// and MAY override `label`/`visible`/`params` (params merge per-key,
    /// field wins); `format` always comes from the definition. Resolved by
    /// [`resolve_display_refs`] BEFORE flatten/compile so the completeness
    /// lint + compiler see the referenced format/params. Was silently
    /// dropped pre-fix → the field degraded to unlabeled raw hex (finding
    /// 1.1). Distinct from the `params.$ref` enum namespace
    /// (`$.metadata.enums.*`), which is resolved separately.
    #[serde(rename = "$ref", default)]
    ref_def: Option<String>,
    /// Nested field GROUP (ERC-7730 struct/tuple display). A field with a
    /// `fields` sub-array is a GROUP whose own `path` (e.g. `#.marketParams`)
    /// anchors its children's relative paths (e.g. `loanToken`); it carries no
    /// leaf `format`. [`flatten_field_groups`] expands a group into per-member
    /// leaf fields with combined paths (`#.marketParams.loanToken`) BEFORE any
    /// completeness / visibility / compile gate runs, so the on-device renderer
    /// (which addresses each ABI head-word slot individually) never sees the
    /// group node. Morpho Blue's `marketParams((address,address,address,address,
    /// uint256))` is the canonical case.
    #[serde(default)]
    fields: Option<Vec<FieldDef>>,
    /// `$id` — cosmetic field/group id; deserialize-and-ignore (modelled so it
    /// doesn't trip the 1.3 gate below).
    #[serde(rename = "$id", default)]
    _id: Option<serde_json::Value>,
    /// `separator` — cosmetic digit-group separator. dbgen renders numbers
    /// ungrouped, so this is deserialize-and-ignore (same value, no grouping).
    /// Modelled (not gated): a purely cosmetic key must not drop a descriptor
    /// to blind-sign.
    #[serde(rename = "separator", default)]
    _separator: Option<serde_json::Value>,
    /// Catch-all for any field key NOT modelled above. A non-empty map means
    /// the descriptor uses a construct dbgen doesn't understand — historically
    /// that was silently dropped (e.g. `$ref` before it was modelled → the
    /// field degraded to unlabeled raw, finding 1.1). Now surfaced: the format
    /// is skipped-with-reason (tolerant) / hard-errors (strict) so an unmodelled
    /// key can't silently change what a trusted clear-sign renders (finding
    /// 1.3). The valid-but-SEMANTIC keys `encryption` (field is encrypted) and
    /// `iteration` (fieldGroup array display) are DELIBERATELY not modelled so
    /// they land here and skip-loud — dbgen implements neither, and rendering
    /// as if they were absent would mis-represent the signed data. params
    /// SUB-keys are still tolerated for forward-compat (a narrower surface).
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────
// Policy.toml shape.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub min_attesters: usize,
    #[serde(default)]
    pub trusted_attesters: Vec<String>,
    #[serde(default)]
    pub allow_unattested_dev_descriptors: bool,
    /// WYSIWYS visibility allowlist (`VULN-erc7730-visible-never-noparam-
    /// clearsign`). Each entry re-permits ONE otherwise-refused hidden
    /// `address` argument on ONE function, after human review. Empty by
    /// default: with no entries, every `visible:"never"` fund-routing address
    /// drops the format to loud blind-sign. See [`check_field_visibility`].
    #[serde(default)]
    pub hidden_address_allow: Vec<HiddenAddressAllow>,
}

/// One reviewed exemption to the WYSIWYS hidden-address rule
/// ([`check_field_visibility`]). Re-permits a specific hidden `address`
/// argument on a specific function — e.g. a router `executor` whose economic
/// effect is bounded by a shown min-return, a relayer/fee-collector, or a
/// linked-list `lesser`/`greater` hint that routes no funds. Honoured ONLY
/// when `rationale` is non-empty, so a reviewer must record WHY the hide is
/// safe; an entry without a rationale fails safe (ignored → blind-sign).
#[derive(Debug, Deserialize, Default, Clone)]
pub struct HiddenAddressAllow {
    /// Exact format key (function signature WITH parameter names), matched
    /// verbatim against the descriptor's format key. A verbatim match means
    /// an upstream rename silently retires the exemption (fails safe).
    pub signature: String,
    /// The hidden argument's descriptor path (e.g. `executor` or
    /// `order.executor`), matched against the offending argument (a leading
    /// `#.` is optional).
    pub path: String,
    /// Human rationale — REQUIRED. An entry with an empty rationale is
    /// ignored (fails safe → the format blind-signs).
    #[serde(default)]
    pub rationale: String,
}

pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Compile every `*.json` under `input_dir` with the policy at
/// `policy_path` BUT override `allow_unattested_dev_descriptors` per
/// `force_production`. When `force_production = true`, the override
/// forces production attestation enforcement regardless of the TOML
/// file's value — this is what `dbgen --policy production` wires.
///
/// `force_production = false` keeps the TOML value as-is (which today
/// means dev mode — no attestation requirement). Production CI must
/// build with `force_production = true` and assert the corpus rebuilds
/// clean: a CI matrix entry runs `cargo run -p dbgen -- --policy
/// production` and fails loudly if any descriptor lacks the required
/// attestations.
pub fn build_db_with_policy_override(
    input_dir: &Path,
    policy_path: &Path,
    force_production: bool,
    registry_root: Option<&Path>,
) -> Result<Erc7730BuildResult, String> {
    let mut policy = load_policy(policy_path)?;
    if force_production {
        policy.allow_unattested_dev_descriptors = false;
    }
    build_db_inner(input_dir, &policy, registry_root, false, &mut Vec::new())
}

// ─────────────────────────────────────────────────────────────────────
// Public build result.
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Emitted {
    pub source: PathBuf,
    pub descriptor_id: String,
    pub descriptor_hash: [u8; 32],
    /// ERC-8176 `descriptorHash` = keccak256(RFC-8785 JCS(resolved descriptor)).
    /// The EAS attestation binding (host-only; not in the device IR).
    pub erc8176_hash: [u8; 32],
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub context_kind: u8,
    pub primary_type_hash: [u8; 32],
    pub ir_bytes: Vec<u8>,
    pub leaf_index: usize,
}

pub struct Erc7730BuildResult {
    pub blob: Vec<u8>,
    pub root: [u8; 32],
    pub entries: Vec<Emitted>,
    pub review_text: String,
    pub leaf_count: usize,
}

// ─────────────────────────────────────────────────────────────────────
// Top-level build.
// ─────────────────────────────────────────────────────────────────────

/// Compile every `*.json` under `input_dir` against `policy_path` and
/// emit the catalog blob + Merkle root. Caller is expected to also
/// run `round_trip_check` before writing the artifacts to disk.
pub fn build_db(
    input_dir: &Path,
    policy_path: &Path,
) -> Result<Erc7730BuildResult, String> {
    let policy = load_policy(policy_path)?;
    build_db_inner(input_dir, &policy, None, false, &mut Vec::new())
}

/// Compile a SINGLE descriptor file, tolerantly. Returns the emitted IR
/// entries on success, or a descriptive reason on failure. Unlike
/// [`build_db`] this does NOT build a Merkle tree and does NOT hard-fail
/// the caller — it is the per-descriptor primitive behind the registry
/// coverage scan (`xtask scan-registry`), which tallies how much of the
/// upstream ERC-7730 registry the on-device renderer can clear-sign today
/// and groups the rest by why it was skipped. `registry_root` resolves
/// any `includes` templates (the registry repo root).
pub fn try_compile_one(
    path: &Path,
    policy: &Policy,
    registry_root: Option<&Path>,
) -> Result<Vec<Emitted>, String> {
    // The coverage scan reports whole-descriptor compilability (strict).
    compile_descriptor(path, policy, registry_root, false)
}

/// A descriptor (or sub-tree) the tolerant build skipped, with why.
#[derive(Debug, Clone)]
pub struct SkipReport {
    pub source: PathBuf,
    pub reason: String,
}

/// Tolerant variant of [`build_db`] for the registry import (the corpus
/// switch). Recursively compiles every `calldata-*.json` / `eip712-*.json`
/// descriptor under `input_dir`, SKIPPING (with a [`SkipReport`]) any
/// descriptor that fails to compile or whose (chain,contract,type) leaf
/// duplicates an earlier one, instead of hard-failing the whole build. The
/// surviving leaves are Merkle-tree-hashed exactly as the strict build, so
/// the resulting root is a faithful catalog of "everything the on-device
/// renderer can clear-sign from this registry". `registry_root` resolves
/// `includes` templates.
pub fn build_db_tolerant(
    input_dir: &Path,
    policy_path: &Path,
    registry_root: Option<&Path>,
) -> Result<(Erc7730BuildResult, Vec<SkipReport>), String> {
    let policy = load_policy(policy_path)?;
    let mut skips: Vec<SkipReport> = Vec::new();
    let result = build_db_inner(input_dir, &policy, registry_root, true, &mut skips)?;
    Ok((result, skips))
}

/// Recursively collect standalone ERC-7730 descriptor files (the same
/// `calldata-*` / `eip712-*` filter the scanner uses), skipping `tests/`
/// fixture dirs and `common-*` / `*.tests.*` include-templates.
fn collect_descriptors(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            collect_descriptors(&p, out);
        } else if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".json")
                && !name.contains(".tests.")
                && (name.starts_with("calldata-") || name.starts_with("eip712-"))
            {
                out.push(p);
            }
        }
    }
}

fn build_db_inner(
    input_dir: &Path,
    policy: &Policy,
    registry_root: Option<&Path>,
    tolerant: bool,
    skips: &mut Vec<SkipReport>,
) -> Result<Erc7730BuildResult, String> {
    // The strict path keeps its flat, name-agnostic read (our hand-authored
    // corpus is a flat dir of `*.json`); the tolerant path walks the
    // registry's nested `registry/<project>/` tree and filters to real
    // descriptor files.
    let mut sources: Vec<PathBuf> = if tolerant {
        let mut v = Vec::new();
        collect_descriptors(input_dir, &mut v);
        v
    } else {
        fs::read_dir(input_dir)
            .map_err(|e| format!("read_dir {}: {e}", input_dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect()
    };
    sources.sort();

    if sources.is_empty() {
        return Err(format!(
            "no .json descriptors found under {}",
            input_dir.display()
        ));
    }

    let mut emitted: Vec<Emitted> = Vec::with_capacity(sources.len() * 2);
    for src in &sources {
        match compile_descriptor(src, policy, registry_root, tolerant) {
            Ok(entries) => emitted.extend(entries),
            Err(e) if tolerant => skips.push(SkipReport {
                source: src.clone(),
                reason: e,
            }),
            Err(e) => return Err(format!("{}: {e}", src.display())),
        }
    }

    if emitted.is_empty() {
        return Err("no IR entries emitted (every descriptor rejected by policy)".to_string());
    }

    // 1. Sort by (chain_id, contract, primary_type_hash, context_kind).
    emitted.sort_by(|a, b| {
        (a.chain_id, a.contract, a.primary_type_hash, a.context_kind).cmp(
            &(b.chain_id, b.contract, b.primary_type_hash, b.context_kind),
        )
    });

    // 2. Handle (chain_id, contract, primary_type_hash, ctx) duplicates.
    //    Byte-identical IRs are benign — the registry legitimately ships the
    //    same token/contract across projects, or a file lists a deployment
    //    twice — so drop the later one (record a skip in tolerant mode).
    //    NON-identical IRs are a trust hazard (review 2.2): the two descriptors
    //    render DIFFERENTLY for the SAME on-chain (chain, contract), and the
    //    survivor was being chosen by lexicographic source-path order — so an
    //    upstream PR adding an alphabetically-earlier file could silently swap
    //    which descriptor the device trusts on the next re-vendor. Refuse in
    //    BOTH modes: force a deliberate human resolution (curate one out) at
    //    build/re-vendor time rather than trusting a filename-order winner. We
    //    vendor the registry, so this fails at re-vendor review, never in prod.
    let mut deduped: Vec<Emitted> = Vec::with_capacity(emitted.len());
    for e in emitted {
        if let Some(prev) = deduped.last() {
            if prev.chain_id == e.chain_id
                && prev.contract == e.contract
                && prev.primary_type_hash == e.primary_type_hash
                && prev.context_kind == e.context_kind
            {
                let key = format!(
                    "chain_id={}, contract=0x{}, primary_type_hash=0x{}, ctx={}",
                    prev.chain_id,
                    hex::encode(prev.contract),
                    hex::encode(prev.primary_type_hash),
                    prev.context_kind,
                );
                if prev.ir_bytes == e.ir_bytes {
                    // Benign byte-identical dup.
                    if tolerant {
                        skips.push(SkipReport {
                            source: e.source.clone(),
                            reason: format!(
                                "duplicate ({key}) byte-identical to {} — deduped",
                                prev.source.display(),
                            ),
                        });
                        continue;
                    }
                    // Strict corpus: even an identical dup is a curation bug.
                    return Err(format!(
                        "duplicate ({key}) — sources: {} vs {}",
                        prev.source.display(),
                        e.source.display(),
                    ));
                }
                return Err(format!(
                    "CONFLICT: non-identical duplicate leaf ({key}) — sources {} vs {} compile \
                     to DIFFERENT IR. The device would trust whichever sorts first by source \
                     path (a silent trust-swap on re-vendor). Resolve by curating one descriptor \
                     out of the vendored tree, or — if both are legitimately needed — ensure they \
                     target distinct deployments.",
                    prev.source.display(),
                    e.source.display(),
                ));
            }
        }
        deduped.push(e);
    }
    let mut emitted = deduped;

    // 3. Assign leaf indices, compute leaf hashes, build the tree.
    for (i, e) in emitted.iter_mut().enumerate() {
        e.leaf_index = i;
    }
    let leaf_hashes: Vec<[u8; 32]> = emitted.iter().map(|e| leaf_hash(&e.ir_bytes)).collect();
    let tree = MerkleTree::build(leaf_hashes.clone());
    let root = tree.root();
    let proof_depth = tree.depth();

    // 4. Lay out the catalog blob.
    let entry_cnt = emitted.len();
    let entries_size = entry_cnt * ERC7730_DB_ENTRY_LEN;
    let ir_pool_off = ERC7730_DB_HEADER_LEN + entries_size;
    let ir_pool_size: usize = emitted.iter().map(|e| e.ir_bytes.len()).sum();
    let proofs_off = ir_pool_off + ir_pool_size;
    let proofs_size = entry_cnt * proof_depth * 32;
    let total_size = proofs_off + proofs_size;

    let mut blob: Vec<u8> = Vec::with_capacity(total_size);

    // ── Header (32 B) ────────────────────────────────────────────────
    blob.extend_from_slice(&ERC7730_DB_MAGIC);
    write_u32_le(&mut blob, ERC7730_DB_VERSION);
    write_u32_le(&mut blob, 0); // flags reserved
    write_u32_le(
        &mut blob,
        entry_cnt
            .try_into()
            .map_err(|_| "entry_cnt > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        ir_pool_off
            .try_into()
            .map_err(|_| "ir_pool_off > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        ir_pool_size
            .try_into()
            .map_err(|_| "ir_pool_size > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proof_depth
            .try_into()
            .map_err(|_| "proof_depth > u32::MAX".to_string())?,
    );
    write_u32_le(
        &mut blob,
        proofs_off
            .try_into()
            .map_err(|_| "proofs_off > u32::MAX".to_string())?,
    );
    assert_eq!(blob.len(), ERC7730_DB_HEADER_LEN);

    // ── Entries (72 B each) ──────────────────────────────────────────
    let mut current_ir_off = 0u32;
    for e in &emitted {
        let entry_start = blob.len();
        blob.extend_from_slice(&e.chain_id.to_le_bytes()); // 8
        blob.extend_from_slice(&e.contract); // 20
        blob.extend_from_slice(&e.primary_type_hash); // 32
        blob.push(e.context_kind); // 1
        blob.extend_from_slice(&[0u8; 3]); // 3 pad
        write_u32_le(&mut blob, current_ir_off); // 4
        write_u32_le(
            &mut blob,
            e.ir_bytes
                .len()
                .try_into()
                .map_err(|_| "ir_len > u32::MAX".to_string())?,
        ); // 4
        debug_assert_eq!(blob.len() - entry_start, ERC7730_DB_ENTRY_LEN);
        current_ir_off = current_ir_off
            .checked_add(e.ir_bytes.len() as u32)
            .ok_or("ir_off overflow")?;
    }
    assert_eq!(blob.len(), ir_pool_off);

    // ── IR pool ──────────────────────────────────────────────────────
    for e in &emitted {
        blob.extend_from_slice(&e.ir_bytes);
    }
    assert_eq!(blob.len(), proofs_off);

    // ── Proofs ───────────────────────────────────────────────────────
    for i in 0..entry_cnt {
        let proof = tree.proof(i);
        debug_assert_eq!(proof.len(), proof_depth);
        for sib in &proof {
            blob.extend_from_slice(sib);
        }
    }
    assert_eq!(blob.len(), total_size);

    let review_text = render_review(&emitted, skips, policy, &root);

    Ok(Erc7730BuildResult {
        blob,
        root,
        entries: emitted,
        review_text,
        leaf_count: entry_cnt,
    })
}

/// Round-trip every emitted IR back through the on-device parser +
/// Merkle verifier. Catches every shape of format drift between the
/// host compiler and `pqsigner_erc7730::bundle::verify_erc7730_bundle`.
pub fn round_trip_check(result: &Erc7730BuildResult) -> Result<(), String> {
    for e in &result.entries {
        // Parse the IR via the canonical on-device parser.
        let ir = Erc7730Ir::parse(&e.ir_bytes).map_err(|err| {
            format!(
                "round-trip parse failed for {}: {err:?}",
                e.source.display()
            )
        })?;
        if ir.chain_id != e.chain_id {
            return Err(format!(
                "round-trip chain_id mismatch in {}: wrote {} read {}",
                e.source.display(),
                e.chain_id,
                ir.chain_id
            ));
        }
        if ir.contract != e.contract {
            return Err(format!(
                "round-trip contract mismatch in {}: wrote 0x{} read 0x{}",
                e.source.display(),
                hex::encode(e.contract),
                hex::encode(ir.contract)
            ));
        }
        if ir.descriptor_hash != e.descriptor_hash {
            return Err(format!(
                "round-trip descriptor_hash mismatch in {}",
                e.source.display()
            ));
        }

        // Walk the proof region back to the root.
        let proof = extract_proof(&result.blob, e.leaf_index, result_proof_depth(&result.blob)?)?;
        if !verify_proof_via_dbgen(&e.ir_bytes, e.leaf_index, &proof, &result.root) {
            return Err(format!(
                "round-trip dbgen-Merkle proof failed for {}",
                e.source.display()
            ));
        }

        // Also exercise the on-device bundle verifier with a synthetic
        // trailer.
        let bundle = synth_bundle(&e.ir_bytes, e.leaf_index as u32, &proof);
        verify_erc7730_bundle(&bundle, &result.root).map_err(|err| {
            format!(
                "round-trip on-device bundle verify failed for {}: {err:?}",
                e.source.display()
            )
        })?;
    }
    Ok(())
}

fn result_proof_depth(blob: &[u8]) -> Result<usize, String> {
    if blob.len() < ERC7730_DB_HEADER_LEN {
        return Err("blob too small for header".to_string());
    }
    let pd = u32::from_le_bytes(blob[24..28].try_into().unwrap()) as usize;
    Ok(pd)
}

fn extract_proof(
    blob: &[u8],
    leaf_index: usize,
    proof_depth: usize,
) -> Result<Vec<[u8; 32]>, String> {
    let entry_cnt = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
    let proofs_off = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    if leaf_index >= entry_cnt {
        return Err(format!("leaf_index {leaf_index} >= entry_cnt {entry_cnt}"));
    }
    let base = proofs_off + leaf_index * proof_depth * 32;
    if base + proof_depth * 32 > blob.len() {
        return Err("proof region out of bounds".to_string());
    }
    let mut out = Vec::with_capacity(proof_depth);
    for j in 0..proof_depth {
        let off = base + j * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&blob[off..off + 32]);
        out.push(h);
    }
    Ok(out)
}

fn verify_proof_via_dbgen(
    ir_bytes: &[u8],
    leaf_index: usize,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    // Wraps `dbgen::merkle::verify_proof`, whose canonical input is
    // the raw leaf bytes (and which then prefixes 0x00 internally — the
    // same scheme as `pqsigner_erc7730::bundle::leaf_hash`).
    verify_proof(ir_bytes, leaf_index, proof, root)
}

fn synth_bundle(ir: &[u8], leaf_index: u32, proof: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + ir.len() + 4 + 4 + proof.len() * 32);
    buf.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    buf.extend_from_slice(ir);
    buf.extend_from_slice(&leaf_index.to_be_bytes());
    buf.extend_from_slice(&(proof.len() as u32).to_be_bytes());
    for h in proof {
        buf.extend_from_slice(h);
    }
    buf
}

// ─────────────────────────────────────────────────────────────────────
// Per-descriptor compilation.
// ─────────────────────────────────────────────────────────────────────

fn compile_descriptor(
    path: &Path,
    policy: &Policy,
    registry_root: Option<&Path>,
    tolerant: bool,
) -> Result<Vec<Emitted>, String> {
    let raw = fs::read(path).map_err(|e| format!("read: {e}"))?;
    let mut json: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| format!("parse: {e}"))?;

    // ERC-8176 policy gate.
    enforce_policy(&json, policy)?;

    // Phase 5: resolve top-level `includes` references against the
    // local registry mirror at `--registry-root`. The reference can
    // be a relative path (`./templates/erc2612-permit.json`) or a
    // github.com URL whose path segment after the repo name is
    // joined with `registry_root`. We deep-merge the referenced
    // JSON into the current document (current keys win) and recurse
    // until no `includes` remains.
    let mut depth = 0usize;
    while let Some(inc) = json
        .get("includes")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        depth += 1;
        if depth > 8 {
            return Err("includes recursion depth > 8 — refusing".to_string());
        }
        let root = registry_root.ok_or_else(|| {
            format!(
                "`includes: \"{inc}\"` requires `--registry-root <dir>`. \
                 See secure/data/erc7730/REGISTRY_MIRROR.md."
            )
        })?;
        let inc_path = resolve_include_path(root, path, &inc)?;
        let inc_raw = fs::read(&inc_path)
            .map_err(|e| format!("read include {}: {e}", inc_path.display()))?;
        let inc_json: serde_json::Value = serde_json::from_slice(&inc_raw)
            .map_err(|e| format!("parse include {}: {e}", inc_path.display()))?;
        // Remove the `includes` key from current json before merge so
        // the loop terminates if the include itself has no further
        // `includes`.
        if let Some(obj) = json.as_object_mut() {
            obj.remove("includes");
        }
        json = merge_descriptors(inc_json, json);
    }

    let descriptor: Descriptor =
        serde_json::from_value(json.clone()).map_err(|e| format!("schema: {e}"))?;

    // After include-resolution `descriptor.includes` must be empty.
    if let Some(inc) = descriptor.includes.as_deref() {
        return Err(format!(
            "post-merge: residual `includes: \"{inc}\"` (recursion didn't reach a leaf)"
        ));
    }

    // Compute the descriptor hashes once over the canonical (RFC-8785 JCS)
    // JSON. Two different hashes over the SAME canonical bytes:
    //   - `descriptor_hash` (SHA-256) — the INTERNAL IR/leaf identifier, baked
    //     into the firmware-pinned Merkle tree (SHA-256 per the PQ-stack
    //     convention: "SHA-256 inside the PQ stack, keccak only for EVM").
    //   - `erc8176_hash` (keccak-256) — the ERC-8176 `descriptorHash`: the value
    //     an auditor attests on the Ethereum Attestation Service (EAS schema
    //     0xe023ee…, `bytes32 descriptorHash`). EVM/keccak, HOST-ONLY (the device
    //     never computes it); surfaced in the review file so an auditor can look
    //     each descriptor up on EAS. See `docs/erc8176-attestation-status.md`.
    let jcs = jcs_canonicalize(&json)?;
    let descriptor_hash = sha256_of(&jcs);
    let erc8176_hash = pqsigner_tx_core::hash::keccak256(&jcs);

    // Extract the descriptor ID (used for the review file).
    let descriptor_id = descriptor
        .context
        .id
        .clone()
        .or_else(|| descriptor.metadata.contract_name.clone())
        .or_else(|| descriptor.metadata.owner.clone())
        .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().to_string());

    let owner = clean_ascii_truncated(
        descriptor.metadata.owner.as_deref().unwrap_or(""),
        OWNER_FIELD_LEN - 1,
    );
    let contract_name = clean_ascii_truncated(
        descriptor
            .metadata
            .contract_name
            .as_deref()
            .or(descriptor.context.id.as_deref())
            .unwrap_or(""),
        CONTRACT_NAME_FIELD_LEN - 1,
    );

    // Resolve constants and enums into the IR pool (lazily, only
    // entries actually referenced get emitted).
    let mut ctx = CompileCtx {
        constants: descriptor.metadata.constants.unwrap_or_default(),
        enums: descriptor.metadata.enums.unwrap_or_default(),
        descriptor_hash,
        owner: owner.clone(),
        contract_name: contract_name.clone(),
        hidden_address_allow: policy.hidden_address_allow.clone(),
    };

    // Decide context kind + collect deployment tuples.
    let (context_kind, deployments) =
        resolve_deployments(&descriptor.context).map_err(|e| format!("deployments: {e}"))?;

    let (formats_section, pool_initial) =
        compile_formats(&descriptor.display, context_kind, &mut ctx, tolerant)?;

    // For each deployment we emit a distinct IR (same body, different
    // header bytes). The pool/format bytes are byte-identical between
    // deployments — the leaf-level differences live entirely in the
    // 134-byte header.
    let mut out = Vec::with_capacity(deployments.len());
    for dep in deployments {
        let (chain_id, contract_addr, domain_separator, primary_type_hash) =
            resolve_per_deployment(context_kind, &descriptor.context, &descriptor.display, &dep)?;

        let ir_bytes =
            build_ir(context_kind, chain_id, contract_addr, &domain_separator, &ctx, &pool_initial, &formats_section)?;

        if ir_bytes.len() > MAX_IR_LEN {
            return Err(format!(
                "IR {} exceeds MAX_IR_LEN ({} > {})",
                descriptor_id,
                ir_bytes.len(),
                MAX_IR_LEN
            ));
        }

        out.push(Emitted {
            source: path.to_path_buf(),
            descriptor_id: descriptor_id.clone(),
            descriptor_hash,
            erc8176_hash,
            chain_id,
            contract: contract_addr,
            context_kind,
            primary_type_hash,
            ir_bytes,
            leaf_index: 0, // filled in by build_db after sorting
        });
    }

    Ok(out)
}

fn resolve_deployments(ctx: &Context) -> Result<(u8, Vec<Deployment>), String> {
    if let Some(c) = &ctx.contract {
        if c.deployments.is_empty() {
            return Err("contract.deployments is empty".to_string());
        }
        Ok((
            CTX_CONTRACT,
            c.deployments.iter().map(|d| Deployment {
                chain_id: d.chain_id,
                address: d.address.clone(),
            }).collect(),
        ))
    } else if let Some(e) = &ctx.eip712 {
        let from_deployments = e.deployments.clone().unwrap_or_default();
        let from_domain = match (&e.domain, &e.domain_separator) {
            (
                Some(Eip712Domain {
                    chain_id: Some(cid),
                    verifying_contract: Some(addr),
                    ..
                }),
                _,
            ) => vec![Deployment {
                chain_id: *cid,
                address: addr.clone(),
            }],
            _ => Vec::new(),
        };
        let merged: Vec<Deployment> = if !from_deployments.is_empty() {
            from_deployments
        } else if !from_domain.is_empty() {
            from_domain
        } else {
            return Err(
                "eip712 context lacks both `deployments` and a fully-specified `domain.{chainId,verifyingContract}`"
                    .to_string(),
            );
        };
        Ok((CTX_EIP712, merged))
    } else {
        Err("context has neither `contract` nor `eip712`".to_string())
    }
}

fn resolve_per_deployment(
    context_kind: u8,
    ctx: &Context,
    display: &Display,
    dep: &Deployment,
) -> Result<(u64, [u8; 20], [u8; 32], [u8; 32]), String> {
    let contract = parse_address(&dep.address)?;
    if context_kind == CTX_CONTRACT {
        return Ok((dep.chain_id, contract, [0u8; 32], [0u8; 32]));
    }
    // EIP-712 path: compute domain_separator + primary_type_hash.
    let eip = ctx
        .eip712
        .as_ref()
        .ok_or_else(|| "expected eip712 context".to_string())?;
    let domain_sep: [u8; 32] = if let Some(s) = &eip.domain_separator {
        parse_hex32(s)?
    } else {
        let mut domain = eip.domain.clone().unwrap_or_default();
        // Pin the per-deployment values.
        domain.chain_id = Some(dep.chain_id);
        domain.verifying_contract = Some(dep.address.clone());
        compute_domain_separator(&domain)?
    };

    // Use the *first* format's primary type as the catalog
    // discriminator. The IR's formats table carries the full set so
    // the walker can still dispatch on the actual signed typehash.
    let primary_type_hash = display
        .formats
        .keys()
        .next()
        .map(|sig| keccak256(sig.as_bytes()))
        .unwrap_or([0u8; 32]);

    Ok((dep.chain_id, contract, domain_sep, primary_type_hash))
}

// ─────────────────────────────────────────────────────────────────────
// Format / field compilation.
// ─────────────────────────────────────────────────────────────────────

/// Side-table the compiler builds while walking a single descriptor.
struct CompileCtx {
    constants: serde_json::Map<String, serde_json::Value>,
    enums: serde_json::Map<String, serde_json::Value>,
    #[allow(dead_code)]
    descriptor_hash: [u8; 32],
    #[allow(dead_code)]
    owner: String,
    #[allow(dead_code)]
    contract_name: String,
    /// Reviewed WYSIWYS hidden-address exemptions from the active policy
    /// (see [`check_field_visibility`]). Cloned in per descriptor so the
    /// per-format gate can consult it without re-threading `Policy`.
    hidden_address_allow: Vec<HiddenAddressAllow>,
}

/// Pool-with-cache used while compiling a single descriptor. Interns
/// repeated paths / param blobs to keep the IR compact (the seed
/// corpus has plenty of repeated `"@.to"` / `["eoa","contract"]`
/// addressName params).
struct Pool {
    buf: Vec<u8>,
    interned: BTreeMap<Vec<u8>, u16>,
}

impl Pool {
    fn new() -> Self {
        // Reserve offset 0 with a 1-byte filler so it can never be the
        // address of a real interned entry. The on-device walker
        // (`pqsigner_erc7730::walker::path_bytes`) and renderer
        // (`secure/src/tx/display/erc7730/formatters::resolve_path` +
        // `secure/src/tx/erc7730_render/params::parse_params`) all treat
        // `path_off == 0` / `param_off == 0` as "no path" / "default
        // params" sentinels. Without this filler, the first interned
        // path program would collide with the sentinel and the renderer
        // would fall through to blind-sign with a "7730 missing path"
        // banner.
        Self {
            buf: vec![0xFFu8],
            interned: BTreeMap::new(),
        }
    }

    /// Push raw bytes (no interning). Returns the offset, or an error
    /// if the resulting offset would overflow u16.
    fn push_raw(&mut self, bytes: &[u8]) -> Result<u16, String> {
        let off = self.buf.len();
        if off + bytes.len() > u16::MAX as usize {
            return Err(format!(
                "IR pool overflow ({} + {} > {})",
                off,
                bytes.len(),
                u16::MAX
            ));
        }
        self.buf.extend_from_slice(bytes);
        Ok(off as u16)
    }

    /// Intern a byte slice — returns the existing offset if already
    /// present, otherwise pushes and returns the new offset.
    fn intern(&mut self, bytes: &[u8]) -> Result<u16, String> {
        if let Some(&off) = self.interned.get(bytes) {
            return Ok(off);
        }
        let off = self.push_raw(bytes)?;
        self.interned.insert(bytes.to_vec(), off);
        Ok(off)
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// First unmodelled top-level key across `fields` (recursing into field
/// GROUPS), or `None`. Feeds the 1.3 gate: a `fields[]`-element key dbgen
/// doesn't model would otherwise be silently dropped, changing what a trusted
/// clear-sign renders (the `$ref` failure class, finding 1.1).
fn first_unmodeled_field_key(fields: &[FieldDef]) -> Option<String> {
    for f in fields {
        if let Some(k) = f.unknown.keys().next() {
            return Some(k.clone());
        }
        if let Some(children) = &f.fields {
            if let Some(inner) = first_unmodeled_field_key(children) {
                return Some(inner);
            }
        }
    }
    None
}

fn compile_formats(
    display: &Display,
    context_kind: u8,
    ctx: &mut CompileCtx,
    tolerant: bool,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let n = display.formats.len();
    if n == 0 {
        return Err("display.formats is empty".to_string());
    }
    if !tolerant && n > MAX_FORMATS {
        return Err(format!("format count {n} > MAX_FORMATS ({MAX_FORMATS})"));
    }

    let mut pool = Pool::new();

    // Flatten nested field GROUPS (ERC-7730 `fields` sub-arrays, e.g. Morpho's
    // `marketParams` tuple) into per-member leaf fields with combined paths
    // ONCE, up front, so the enum pre-pass AND the compile loop see identical
    // fields. A malformed group (no anchoring path / too deeply nested) drops
    // that one format in tolerant mode — exactly as a compile failure would —
    // and hard-errors in strict mode. See [`flatten_field_groups`].
    // Per-format blockers, surfaced in the "no compilable formats" skip reason
    // (review 1.4). Populated by BOTH the resolve/flatten pass here and the
    // compile loop below.
    let mut format_errs: Vec<String> = Vec::new();
    let mut flat: Vec<(&str, Format)> = Vec::with_capacity(n);
    for (sig, fmt) in display.formats.iter() {
        let fn_name = sig.split('(').next().unwrap_or(sig);
        // 1.3: an unmodelled top-level format/field key would be silently
        // dropped — exactly how `$ref` shipped degraded raw (finding 1.1).
        // Refuse the format instead of guessing. params SUB-keys are still
        // tolerated for forward-compat (a separate, narrower surface).
        if let Some(key) = fmt
            .unknown
            .keys()
            .next()
            .cloned()
            .or_else(|| first_unmodeled_field_key(&fmt.fields))
        {
            let msg = format!(
                "{fn_name}: unmodeled descriptor key `{key}` — dbgen does not act on it and \
                 would silently drop it; refusing (finding 1.3)"
            );
            if tolerant {
                format_errs.push(msg);
                continue;
            }
            return Err(format!("format `{sig}`: {msg}"));
        }
        // Resolve field-level `$.display.definitions` `$ref`s BEFORE flatten +
        // compile, so the completeness lint and the field compiler both see the
        // referenced format/params (finding 1.1). Resolution failure drops the
        // one format to blind-sign in tolerant mode (recorded), hard-errors in
        // strict mode.
        let resolved = match resolve_display_refs(&fmt.fields, display.definitions.as_ref()) {
            Ok(r) => r,
            Err(e) if tolerant => {
                format_errs.push(format!("{fn_name}: {e}"));
                continue;
            }
            Err(e) => return Err(format!("format `{sig}`: {e}")),
        };
        match flatten_field_groups(&resolved) {
            Ok(fields) => flat.push((
                sig.as_str(),
                Format {
                    _id: fmt._id.clone(),
                    intent: fmt.intent.clone(),
                    fields,
                    _interpolated_intent: None,
                    unknown: BTreeMap::new(),
                },
            )),
            // Was a silent drop; record it so the skip report shows why.
            Err(e) if tolerant => format_errs.push(format!("{fn_name}: {e}")),
            Err(e) => return Err(format!("format `{sig}`: {e}")),
        }
    }

    // Pre-intern referenced enum tables so $ref resolution can emit pool
    // offsets without re-walking. In tolerant mode a bad / undefined enum is
    // skipped here (the format(s) referencing it then fail to compile and are
    // themselves skipped below); strict mode hard-errors.
    let mut enum_offsets: BTreeMap<String, u16> = BTreeMap::new();
    for (_sig, fmt) in flat.iter() {
        for field in &fmt.fields {
            let Some(params) = &field.params else { continue };
            let Some(refstr) = params
                .get("$ref")
                .and_then(|v| v.as_str())
                .or_else(|| params.get("ref").and_then(|v| v.as_str()))
            else {
                continue;
            };
            let Some(name) = refstr.strip_prefix("$.metadata.enums.") else {
                continue;
            };
            if enum_offsets.contains_key(name) {
                continue;
            }
            let encoded = match ctx
                .enums
                .get(name)
                .ok_or_else(|| format!("enum `{name}` referenced but not defined"))
                .and_then(|table| {
                    encode_enum_table(table).map_err(|e| format!("enum `{name}` encoding: {e}"))
                }) {
                Ok(enc) => enc,
                Err(_) if tolerant => continue,
                Err(e) => return Err(e),
            };
            let off = pool.push_raw(&encoded)?;
            enum_offsets.insert(name.to_string(), off);
        }
    }

    // Compile each format. Tolerant mode keeps the compilable formats and
    // SKIPS the rest — a partially-supported descriptor (e.g. an aggregator
    // whose `approve` compiles but whose dynamic `swap` does not) still
    // clear-signs its renderable functions; the dropped functions blind-sign
    // exactly as if the descriptor were absent. Strict mode `?`-fails the
    // whole descriptor on the first bad format (a curation bug in our corpus).
    let mut survivors: Vec<Vec<u8>> = Vec::with_capacity(n);
    for &(sig, ref fmt) in flat.iter() {
        if tolerant && survivors.len() >= MAX_FORMATS {
            break; // bound the IR; remaining functions blind-sign
        }
        let mut one: Vec<u8> = Vec::new();
        match compile_one_format(sig, fmt, context_kind, ctx, &mut pool, &enum_offsets, &mut one) {
            Ok(()) => survivors.push(one),
            Err(e) if tolerant => {
                // Record `funcName: reason` (drop the arg list from the sig for
                // readability; the reason is what matters for triage).
                let fn_name = sig.split('(').next().unwrap_or(sig);
                format_errs.push(format!("{fn_name}: {e}"));
            }
            Err(e) => return Err(e),
        }
    }

    if survivors.is_empty() {
        return Err(if format_errs.is_empty() {
            "no compilable formats in descriptor".to_string()
        } else {
            format!("no compilable formats in descriptor — {}", format_errs.join("; "))
        });
    }

    // [count][format…] — count is the SURVIVOR count (== n in strict mode, so
    // the strict catalog is byte-identical).
    let body_len: usize = survivors.iter().map(Vec::len).sum();
    let mut formats_buf: Vec<u8> = Vec::with_capacity(1 + body_len);
    formats_buf.push(survivors.len() as u8);
    for one in &survivors {
        formats_buf.extend_from_slice(one);
    }

    Ok((formats_buf, pool.into_bytes()))
}

/// Maximum nesting depth for ERC-7730 field GROUPS (`fields` sub-arrays).
/// Morpho's `marketParams` is one level; a real descriptor never needs many.
/// Bounding the recursion keeps a pathological (or hostile) descriptor from
/// blowing the host stack during flattening.
const MAX_FIELD_GROUP_DEPTH: usize = 4;

/// Resolve field-level `$ref` references into `$.display.definitions.*`
/// (ERC-7730 v2 `#/$display/reference`), recursively — including refs nested
/// inside a struct-display field GROUP. Merge rule (per the v2 schema + spec
/// prose, cross-checked against the 1inch / paraswap corpus):
///   - `format`   — ALWAYS from the definition (a reference object cannot
///                  carry `format`);
///   - `label`/`visible` — field-local if present, else the definition's;
///   - `params`   — per-key deep-merge with the reference winning
///                  (`merge_descriptors(def, field)`): e.g. a `tokenAmount`
///                  definition contributes `nativeCurrencyAddress` while the
///                  field contributes `tokenPath` — both must survive;
///   - `path`/`value` — from the reference object.
/// One level only: the schema forbids a definition from itself carrying a
/// display `$ref`, so a transitive ref hard-errors rather than recursing.
///
/// Unresolvable refs (missing definition) and non-`$.display.definitions`
/// field-level refs hard-error — the pre-fix behaviour silently dropped the
/// `$ref` key, defaulting the field to unlabeled `raw` and discarding its
/// `tokenPath`, so a labeled DEX-swap leg rendered as a blank 64-hex dump
/// under a trusted "Swap" banner (review finding 1.1). Fail loud instead.
fn resolve_display_refs(
    fields: &[FieldDef],
    defs: Option<&BTreeMap<String, FieldDef>>,
) -> Result<Vec<FieldDef>, String> {
    const REF_PREFIX: &str = "$.display.definitions.";
    let mut out = Vec::with_capacity(fields.len());
    for field in fields {
        // GROUP node (struct/tuple display): recurse into children, keep the
        // group's own path/label. Schema makes group and reference mutually
        // exclusive; guard anyway.
        if let Some(children) = &field.fields {
            if field.ref_def.is_some() {
                return Err("field is both a `$ref` and a field group".to_string());
            }
            let resolved_children = resolve_display_refs(children, defs)?;
            let mut g = field.clone();
            g.fields = Some(resolved_children);
            out.push(g);
            continue;
        }
        let Some(refstr) = &field.ref_def else {
            out.push(field.clone());
            continue;
        };
        // A field-level `$ref` must target a display definition. (Enum refs
        // live in `params.$ref` = `$.metadata.enums.*` and are resolved by the
        // separate enum pre-intern pass; a field-level ref there is malformed.)
        let name = refstr.strip_prefix(REF_PREFIX).ok_or_else(|| {
            format!(
                "field `$ref: \"{refstr}\"` is not a `$.display.definitions.*` reference \
                 (only display-definition refs are supported at the field level)"
            )
        })?;
        let def = defs.and_then(|d| d.get(name)).ok_or_else(|| {
            format!("unresolved $ref `{refstr}` — no such display definition `{name}`")
        })?;
        if def.ref_def.is_some() {
            return Err(format!(
                "display definition `{name}` itself carries a `$ref` — transitive \
                 display-definition references are not permitted"
            ));
        }
        let params = match (def.params.clone(), field.params.clone()) {
            (None, None) => None,
            (Some(b), None) => Some(b),
            (None, Some(o)) => Some(o),
            (Some(b), Some(o)) => Some(merge_descriptors(b, o)),
        };
        out.push(FieldDef {
            path: field.path.clone(),
            value: field.value.clone(),
            label: field.label.clone().or_else(|| def.label.clone()),
            format: def.format.clone(),
            params,
            visible: field.visible.clone().or_else(|| def.visible.clone()),
            ref_def: None,
            // Definitions are leaf format specs; carry a group definition
            // through if one ever appears (flatten then expands it).
            fields: def.fields.clone(),
            _id: None,
            // Cosmetic separator: reference-local else definition (unemitted).
            _separator: field._separator.clone().or_else(|| def._separator.clone()),
            unknown: BTreeMap::new(),
        });
    }
    Ok(out)
}

/// Expand ERC-7730 nested field GROUPS into a flat field list with combined
/// paths. A field that carries a non-empty `fields` sub-array is a GROUP: its
/// own `path` (e.g. `#.marketParams`) prefixes each child's relative `path`
/// (e.g. `loanToken`) → `#.marketParams.loanToken`, recursively; leaf fields
/// pass through unchanged (with `fields` cleared).
///
/// This is purely syntactic path rewriting. The combined paths are compiled by
/// the SAME width-aware [`compile_structured_contract_path`] and filtered by the
/// SAME completeness / visibility / two-level-descent gates as a hand-authored
/// flat path, so flattening can only PRODUCE candidate paths — it bypasses no
/// safety gate. A group over a dynamic tuple / array / more than two levels
/// compiles to a path the existing gates reject, so the whole format drops to
/// loud blind-sign (tolerant corpus) rather than mis-rendering. Running it once
/// up front means the enum pre-pass and the compile loop see identical fields.
fn flatten_field_groups(fields: &[FieldDef]) -> Result<Vec<FieldDef>, String> {
    let mut out = Vec::with_capacity(fields.len());
    flatten_field_groups_into(fields, None, 0, &mut out)?;
    Ok(out)
}

fn flatten_field_groups_into(
    fields: &[FieldDef],
    prefix: Option<&str>,
    depth: usize,
    out: &mut Vec<FieldDef>,
) -> Result<(), String> {
    if depth > MAX_FIELD_GROUP_DEPTH {
        return Err(format!(
            "field group nesting exceeds MAX_FIELD_GROUP_DEPTH ({MAX_FIELD_GROUP_DEPTH})"
        ));
    }
    for field in fields {
        let combined = combine_field_path(prefix, field.path.as_deref());
        match field.fields.as_deref() {
            Some(children) if !children.is_empty() => {
                // GROUP node: must carry a `path` to anchor its children (a
                // group with no path has nothing for the members to be relative
                // to). It contributes no leaf itself.
                let group_prefix = combined.ok_or_else(|| {
                    "field group has a `fields` sub-array but no `path` to anchor its members"
                        .to_string()
                })?;
                flatten_field_groups_into(children, Some(&group_prefix), depth + 1, out)?;
            }
            _ => {
                // Leaf field: emit a copy carrying the combined path, no
                // sub-`fields`. Everything else (format/params/label/visible/
                // value) is preserved verbatim.
                let mut leaf = field.clone();
                leaf.path = combined;
                leaf.fields = None;
                out.push(leaf);
            }
        }
    }
    Ok(())
}

/// Combine a group `prefix` path with a child's relative `path`.
/// `#.marketParams` + `loanToken` → `#.marketParams.loanToken`. A child that
/// is itself absolute (`#`/`@`/`$`) is taken verbatim (spec-noncompliant under
/// a group, but we never fabricate a nonsensical double-rooted path); a leading
/// `.` on the child is absorbed.
fn combine_field_path(prefix: Option<&str>, child: Option<&str>) -> Option<String> {
    match (prefix, child) {
        (None, c) => c.map(str::to_string),
        (Some(p), None) => Some(p.to_string()),
        (Some(p), Some(c)) => {
            let c = c.trim();
            if c.starts_with('#') || c.starts_with('@') || c.starts_with('$') {
                Some(c.to_string())
            } else {
                Some(format!(
                    "{}.{}",
                    p.trim_end_matches('.'),
                    c.trim_start_matches('.')
                ))
            }
        }
    }
}

fn compile_one_format(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let parsed = parse_format_key(sig).map_err(|e| format!("format `{sig}`: {e}"))?;

    // Audit H-3: refuse to pin a contract-context descriptor that leaves
    // any calldata argument unaccounted for. The on-device renderer can't
    // reconstruct ABI arity, so completeness is enforced here — where the
    // full signature is known — at build time.
    if context_kind == CTX_CONTRACT {
        check_contract_field_completeness(sig, fmt, &parsed)?;
    } else {
        // Audit 2026-06-25 HIGH-1: the typed-data sibling of H-3. Every
        // EIP-712 member is folded into the signed `structHash =
        // keccak(primary_type_hash || encoded_data)`, and each top-level
        // member occupies exactly one head word (struct refs and dynamic
        // types hash to a single word). The on-device exact-length gate
        // forces `encoded_data` to the full member arity but does NOT check
        // that every word reaches a page, so an under-declared descriptor
        // could sign an effect-bearing member (e.g. a Permit2 `spender`)
        // that the trusted display never shows. Enforce per-member coverage
        // here at build time, exactly as the contract path does.
        check_eip712_field_completeness(sig, fmt, &parsed)?;
    }

    // WYSIWYS visibility gate (`VULN-erc7730-visible-never-noparam-
    // clearsign`). Completeness above only proves every argument is
    // *declared* (rendered OR `visible:"never"`); it deliberately blesses an
    // explicit hide. This gate proves the effect-bearing arguments are
    // *shown* — refusing a format that surfaces NONE of its arguments, or
    // that hides a fund-routing `address` behind a trusted clear-sign. A
    // refused format drops to loud blind-sign (tolerant corpus) or hard-
    // errors a hand-authored strict descriptor so we fix it — never a
    // reassuring parameter-less clear-sign.
    check_field_visibility(sig, fmt, &parsed, context_kind, &ctx.hidden_address_allow)?;

    // Selector / discriminator slot — 4 bytes. For EIP-712 we also keep
    // the FULL 32-byte primary-type hash so the on-device renderer can
    // bind all 32 bytes (audit M-5), not just the 4-byte prefix it
    // selects the display template by.
    let eip712_type_hash: Option<[u8; 32]> = if context_kind == CTX_CONTRACT {
        None
    } else {
        // The EIP-712 format key IS the typed-data `encodeType` string
        // (e.g. `Permit(address owner,address spender,uint256 value,
        // uint256 nonce,uint256 deadline)`); its keccak256 is the
        // primary-type hash the dapp/companion supplies at sign time.
        Some(keccak256(sig.as_bytes()))
    };
    let selector: [u8; 4] = if context_kind == CTX_CONTRACT {
        // keccak256 of the types-only signature (the 4-byte function
        // selector).
        let h = keccak256(parsed.types_signature.as_bytes());
        [h[0], h[1], h[2], h[3]]
    } else {
        let h = eip712_type_hash.expect("eip712 type hash computed above");
        [h[0], h[1], h[2], h[3]]
    };

    // Sanity: field count.
    if fmt.fields.len() > MAX_FIELDS_PER_FORMAT {
        return Err(format!(
            "format `{sig}`: field count {} > MAX_FIELDS_PER_FORMAT ({MAX_FIELDS_PER_FORMAT})",
            fmt.fields.len()
        ));
    }

    let intent_raw = fmt.intent.as_deref().unwrap_or("Sign");
    let intent = clean_ascii_truncated(intent_raw, 254);
    if intent.is_empty() {
        return Err(format!(
            "format `{sig}`: empty / non-printable `intent` (was {intent_raw:?})"
        ));
    }

    // Static ABI head width — the device uses this to bound every field's
    // calldata read to the static head (defence-in-depth behind the
    // width-aware path slots; see `format_static_head_words`).
    let static_head_words = format_static_head_words(context_kind, &parsed)
        .map_err(|e| format!("format `{sig}`: {e}"))?;

    // On-device belt for `VULN-erc7730-eip712-nested-struct-address-hide`:
    // an EIP-712 primary type with a nested struct member carries an opaque
    // `hashStruct` word the device cannot expand. Flag it here (parked on the
    // first field, since the header schema has no spare byte) so the device
    // declines the whole format to blind-sign rather than partially
    // clear-signing it or painting a struct word as a garbage value. The
    // build-time visibility gate above is the primary defense; this is the
    // defense-in-depth backstop. Only meaningful for EIP-712 (contract keys
    // have no `struct_defs`).
    let has_nested_struct = context_kind == CTX_EIP712
        && parsed.top_types.iter().any(|ty| {
            let (base, _) = split_array_suffix(ty);
            type_is_struct(base, &parsed)
        });

    // Compile every field's path + params first (so offsets are stable before
    // we emit the format header). An EIP-712 format with a nested-struct member
    // is restructured into the v0x03 recursive-IR shape — each supported nested
    // member becomes ONE anchor field carrying `PARAM_NESTED_STRUCT` with its
    // visible children as LOCAL sub-fields (Phase 5,
    // `docs/erc7730-nested-eip712-render-design.md`). An unsupported nested
    // shape (array / depth>1 / uncompilable child / uncovered address) falls
    // back to flat fields + the bare `[0x01]` belt marker so the device
    // declines the whole format to blind-sign. `nested_descent_count` is the E1
    // reconciliation pin: the number of nested descent points the device MUST
    // bind, derived HERE (independent of the render traversal).
    let (compiled, nested_descent_count): (Vec<CompiledFieldOut>, u8) = if has_nested_struct {
        match try_compile_eip712_nested(sig, fmt, &parsed, ctx, pool, enum_offsets)? {
            Some(res) => res,
            None => (
                compile_flat_fields(sig, fmt, context_kind, &parsed, ctx, pool, enum_offsets, true)?,
                0,
            ),
        }
    } else {
        (
            compile_flat_fields(sig, fmt, context_kind, &parsed, ctx, pool, enum_offsets, false)?,
            0,
        )
    };

    // Emit format header.
    out.extend_from_slice(&selector); // 4 B
    out.push(compiled.len() as u8); // 1 B field_count
    out.push(intent.len() as u8); // 1 B intent_len
    out.extend_from_slice(&static_head_words.to_be_bytes()); // 2 B static_head_words
    // Schema v3: E1 reconciliation pin — the count of nested-EIP-712 struct
    // descent points (`PARAM_NESTED_STRUCT` v0x03 anchors) the device MUST bind
    // before signing. Independent of the render traversal, so a regression that
    // makes descent conditional under-consumes and declines. `0` until the
    // nested-anchor emission lands (next increment) and for every non-nested /
    // contract format.
    out.push(nested_descent_count); // 1 B nested_descent_count
    out.extend_from_slice(intent.as_bytes()); // intent_len B
    // EIP-712 only: full 32-byte primary-type hash (audit M-5). Contract
    // formats omit this so their on-wire bytes are unchanged.
    if let Some(th) = eip712_type_hash {
        out.extend_from_slice(&th); // 32 B
    }

    // Emit fields.
    for cf in &compiled {
        out.push(cf.format_op); // 1 B
        out.push(cf.label.len() as u8); // 1 B
        out.extend_from_slice(&cf.label); // label_len B
        out.extend_from_slice(&cf.path_off.to_be_bytes()); // 2 B
        out.extend_from_slice(&cf.param_off.to_be_bytes()); // 2 B
    }

    Ok(())
}

struct CompiledFieldOut {
    format_op: u8,
    label: Vec<u8>,
    path_off: u16,
    param_off: u16,
}

fn compile_one_field(
    sig: &str,
    field_idx: usize,
    field: &FieldDef,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    emit_nested_marker: bool,
) -> Result<CompiledFieldOut, String> {
    // 1. Compile the path bytecode — OR, for a path-less constant
    //    annotation field, capture its literal string.
    let (path_off, const_value): (u16, Option<String>) = match field.path.as_deref() {
        Some(path) => {
            let path_program = compile_path(path, context_kind, parsed)
                .map_err(|e| format!("format `{sig}` field[{field_idx}] path `{path}`: {e}"))?;
            if path_program.len() > MAX_PATH_PROGRAM_LEN {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] path program too long ({} > {MAX_PATH_PROGRAM_LEN})",
                    path_program.len()
                ));
            }
            let mut path_blob = Vec::with_capacity(1 + path_program.len());
            path_blob.push(path_program.len() as u8);
            path_blob.extend_from_slice(&path_program);
            (pool.intern(&path_blob)?, None)
        }
        None => {
            // Constant-annotation field: a string `value`, no path. Renders
            // the literal attested string (e.g. the ERC-4626 vault note).
            let v = field.value.as_ref().ok_or_else(|| {
                format!("format `{sig}` field[{field_idx}] has neither `path` nor `value`")
            })?;
            let raw = v.as_str().ok_or_else(|| {
                format!("format `{sig}` field[{field_idx}] constant `value` must be a string")
            })?;
            let resolved = resolve_string_or_const(raw, ctx)
                .map_err(|e| format!("format `{sig}` field[{field_idx}] constant `value`: {e}"))?;
            let s = clean_ascii_truncated(&resolved, MAX_POOL_TLV_PAYLOAD);
            if s.is_empty() {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] constant `value` is empty / non-printable"
                ));
            }
            (0u16, Some(s))
        }
    };

    // 2. Decide formatter opcode. A constant field renders its literal
    //    string regardless of the descriptor's `format`, so pin it to raw.
    let format_op = if const_value.is_some() {
        FMT_RAW
    } else {
        parse_format_name(field.format.as_deref().unwrap_or("raw"))?
    };

    // 3. Compile params + visibility into a single TLV blob.
    let mut param_blob = compile_params(
        sig,
        field_idx,
        format_op,
        field.params.as_ref(),
        field.visible.as_deref(),
        context_kind,
        parsed,
        ctx,
        enum_offsets,
    )?;
    if let Some(cv) = &const_value {
        push_tlv(&mut param_blob, PARAM_CONST_VALUE, cv.as_bytes())?;
    }
    // Format-level nested-struct marker (see `has_nested_struct` in
    // `compile_one_format`). Parked on the first field; the device rejects
    // the whole format on encountering it. Payload is a single `0x01` so the
    // TLV is self-describing and a zero-length variant can be reserved later.
    if emit_nested_marker {
        push_tlv(&mut param_blob, PARAM_NESTED_STRUCT, &[0x01])?;
    }
    let param_off = if param_blob.is_empty() {
        0u16
    } else {
        let mut blob_with_len = Vec::with_capacity(1 + param_blob.len());
        if param_blob.len() > MAX_POOL_TLV_PAYLOAD {
            return Err(format!(
                "format `{sig}` field[{field_idx}] param blob too long ({} > {MAX_POOL_TLV_PAYLOAD})",
                param_blob.len()
            ));
        }
        blob_with_len.push(param_blob.len() as u8);
        blob_with_len.extend_from_slice(&param_blob);
        pool.intern(&blob_with_len)?
    };

    // 4. Label.
    let label_raw = field.label.as_deref().unwrap_or("");
    let label = clean_ascii_truncated(label_raw, 254);
    if label.is_empty() && format_op != FMT_RAW {
        // A blank label on a *visible* field would render as a header-
        // less value page. Allow it on raw because some descriptors
        // (Aave's `referralCode` set to visible=never) intentionally
        // skip labels.
    }

    Ok(CompiledFieldOut {
        format_op,
        label: label.into_bytes(),
        path_off,
        param_off,
    })
}

/// Compile a format's fields as flat top-level records (the pre-Phase-5
/// behaviour). `emit_bare_marker` parks the bare `[0x01]` `PARAM_NESTED_STRUCT`
/// belt marker on the first field so the device declines the whole format —
/// used for an EIP-712 format whose nested-struct shape is not v1-supported.
#[allow(clippy::too_many_arguments)]
fn compile_flat_fields(
    sig: &str,
    fmt: &Format,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
    emit_bare_marker: bool,
) -> Result<Vec<CompiledFieldOut>, String> {
    let mut compiled: Vec<CompiledFieldOut> = Vec::with_capacity(fmt.fields.len());
    for (i, field) in fmt.fields.iter().enumerate() {
        let cf = compile_one_field(
            sig,
            i,
            field,
            context_kind,
            parsed,
            ctx,
            pool,
            enum_offsets,
            emit_bare_marker && i == 0,
        )?;
        compiled.push(cf);
    }
    Ok(compiled)
}

/// One planned output record for an EIP-712 nested-struct format.
enum NestedPlan {
    /// A flat top-level field (its index into `fmt.fields`).
    Flat(usize),
    /// A nested-struct anchor: the struct top-member name, its word position in
    /// the parent `encodeData`, its struct base type, whether it is an ARRAY of
    /// that struct (v2), and the `fmt.fields` indices of its visible children (in
    /// descriptor order).
    Anchor {
        top: String,
        word_pos: u16,
        base: String,
        is_array: bool,
        children: Vec<usize>,
    },
}

/// Strip the nested-member prefix from a descriptor path, returning the single
/// elementary child segment. `top.child` (v1) → `child`; `top.[].child` (v2
/// array) → `child`. Returns `None` if the path doesn't match, has an unexpected
/// array bracket, or names more than one further segment (deeper nesting = v3).
fn strip_nested_child<'a>(path: &'a str, top: &str, is_array: bool) -> Option<&'a str> {
    let rest = path.trim().strip_prefix(top)?.strip_prefix('.')?;
    let rest = if is_array {
        rest.strip_prefix("[].")?
    } else {
        rest
    };
    if rest.is_empty() || rest.contains('.') || rest.contains('[') {
        return None;
    }
    Some(rest)
}

/// Try to compile an EIP-712 format that has ≥1 nested-struct member into the
/// v0x03 recursive-IR shape (§4 + §10 + §11 of the design doc). Returns
/// `Some((records, nested_descent_count))` on a supported shape, or `Ok(None)`
/// to fall back to the bare-marker belt (the caller then emits flat fields +
/// `[0x01]` so the device declines the WHOLE format). `Err` only on a genuine
/// build error.
///
/// Supported subset — anything outside it returns `Ok(None)`:
///   * a single-level nested struct member (v1, `details.amount`) OR a
///     single-level ARRAY of a struct (v2, `details.[].amount`, `flags` bit0=1);
///     the `.[]` is stripped so local ordinals are identical either way;
///   * children are single-level (`a.b.c` / `a.[].b.c` → v3);
///   * the element/struct members are ELEMENTARY (a nested struct or deeper
///     array inside → v3);
///   * children use only the {raw, amount, tokenAmount(local tokenPath), date}
///     formats with the v1 param vocabulary;
///   * every address-typed local word is covered by a visible child (E2).
///
/// NOTE: v2 array anchors are EMITTED here (the wire is ready), but the on-device
/// ARRAY render is a separate, adversarial-review-gated commit — until then the
/// device declines any `is_array` anchor.
fn try_compile_eip712_nested(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    pool: &mut Pool,
    enum_offsets: &BTreeMap<String, u16>,
) -> Result<Option<(Vec<CompiledFieldOut>, u8)>, String> {
    let mut plan: Vec<NestedPlan> = Vec::new();
    // top-member name -> index into `plan` of its anchor (first appearance).
    let mut anchor_at: BTreeMap<String, usize> = BTreeMap::new();

    for (i, field) in fmt.fields.iter().enumerate() {
        // Const-annotation / path-less fields are always flat top-level.
        let Some(path) = field.path.as_deref() else {
            plan.push(NestedPlan::Flat(i));
            continue;
        };
        let top = path.split('.').next().unwrap_or("").trim();
        let Some(pos) = parsed.top_names.iter().position(|n| n == top) else {
            // Unknown top member — let the flat path surface the real error, but
            // an array op on an unknown/non-struct member is not a shape we model.
            return Ok(None);
        };
        let (base, is_array) = split_array_suffix(&parsed.top_types[pos]);
        if !type_is_struct(base, parsed) {
            // Non-struct top member → flat field (unless it carries an array op
            // we don't model as a nested descent).
            if path.contains('[') {
                return Ok(None);
            }
            plan.push(NestedPlan::Flat(i));
            continue;
        }
        // Struct top member. v2 supports a single-level array of an
        // elementary-member struct; anything deeper → defer (belt-decline).
        if is_array && !array_element_is_v2_supported(base, parsed) {
            return Ok(None);
        }
        // The single elementary child segment: `top.child` (v1) or
        // `top.[].child` (v2 array). Anything else (whole-struct render,
        // `a.b.c`, indexed `[0]`) → defer.
        if strip_nested_child(path, top, is_array).is_none() {
            return Ok(None);
        }
        let word_pos =
            u16::try_from(pos).map_err(|_| format!("format `{sig}`: too many top members"))?;
        if let Some(&ai) = anchor_at.get(top) {
            if let NestedPlan::Anchor { children, .. } = &mut plan[ai] {
                children.push(i);
            }
        } else {
            anchor_at.insert(top.to_string(), plan.len());
            plan.push(NestedPlan::Anchor {
                top: top.to_string(),
                word_pos,
                base: base.to_string(),
                is_array,
                children: std::vec![i],
            });
        }
    }

    // Second pass — compile each planned record.
    let mut compiled: Vec<CompiledFieldOut> = Vec::with_capacity(plan.len());
    let mut descent_count: u16 = 0;
    for item in &plan {
        match item {
            NestedPlan::Flat(i) => {
                let cf = compile_one_field(
                    sig,
                    *i,
                    &fmt.fields[*i],
                    CTX_EIP712,
                    parsed,
                    ctx,
                    pool,
                    enum_offsets,
                    false,
                )?;
                compiled.push(cf);
            }
            NestedPlan::Anchor {
                top,
                word_pos,
                base,
                is_array,
                children,
            } => match compile_nested_anchor(
                sig, fmt, parsed, top, *word_pos, base, *is_array, children, pool,
            )? {
                Some(cf) => {
                    compiled.push(cf);
                    descent_count += 1;
                }
                // A child we couldn't compile → belt-decline the WHOLE format.
                None => return Ok(None),
            },
        }
    }

    let descent_count = u8::try_from(descent_count)
        .map_err(|_| format!("format `{sig}`: too many nested descents"))?;
    Ok(Some((compiled, descent_count)))
}

/// Compile one nested-struct anchor into a `PARAM_NESTED_STRUCT` v0x03 record.
/// Returns `Ok(None)` (→ caller belt-declines the format) on any shape outside
/// the v1 subset. Pins `type_hash` from `struct_defs` (never companion-supplied),
/// the `member_count` = the NESTED struct's own word count, an `addr_word_bitmap`
/// (E2), and the visible children as LOCAL sub-fields (E5 local ordinals).
#[allow(clippy::too_many_arguments)]
fn compile_nested_anchor(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    top: &str,
    word_pos: u16,
    base: &str,
    is_array: bool,
    children: &[usize],
    pool: &mut Pool,
) -> Result<Option<CompiledFieldOut>, String> {
    let Some(members) = parsed.struct_defs.get(base) else {
        return Ok(None);
    };
    let member_count = members.len();
    if member_count == 0 || member_count > MAX_NESTED_MEMBERS {
        return Ok(None);
    }
    // type_hash = keccak(encodeType(nested)) — dbgen-PINNED (rule 3). A failure
    // to build the canonical `encodeType` (malformed / undefined referenced
    // struct) is NOT a hard error: fall back to the bare-marker belt so the
    // format still survives compilation (declined), exactly as it did before
    // Phase 5, rather than being dropped from the corpus.
    let type_hash = match eip712_nested_type_hash(base, &parsed.struct_defs) {
        Ok(th) => th,
        Err(_) => return Ok(None),
    };

    // address-word bitmap (E2): bit i set iff local member i is address-typed.
    let bmp_len = member_count.div_ceil(8);
    let mut addr_bmp = std::vec![0u8; bmp_len];
    for (i, (_name, ty)) in members.iter().enumerate() {
        if eip712_member_word_is_address(ty) {
            addr_bmp[i / 8] |= 1u8 << (i % 8);
        }
    }

    // Compile each visible child into a SubField record; `covered[w]` tracks the
    // local words a child binds to a page (render path OR tokenPath) for E2.
    let mut covered = std::vec![false; member_count];
    let mut sub_fields: Vec<u8> = Vec::new();
    let mut sub_field_cnt: u8 = 0;
    for &fi in children {
        let field = &fmt.fields[fi];
        let path = field.path.as_deref().unwrap_or("");
        // child = the single elementary segment after `top.` (v1) or `top.[].`
        // (v2 array). Local ordinals are identical either way (each array element
        // is one `base` struct).
        let Some(child) = strip_nested_child(path, top, is_array) else {
            return Ok(None);
        };
        let Some(local_ord) = members.iter().position(|(n, _)| n == child) else {
            return Ok(None);
        };
        let local_ord = u16::try_from(local_ord).expect("member_count ≤ MAX_NESTED_MEMBERS");
        covered[local_ord as usize] = true; // the render path reads this word

        // Child's format_op + LOCAL param blob (v1 vocabulary only).
        let Some((format_op, param_blob)) =
            compile_nested_subfield_params(field, top, is_array, members, &mut covered)?
        else {
            return Ok(None);
        };

        // Local render path: RootStructured + FieldIdx(local_ord).
        let render_prog = [
            PATHOP_ROOT_STRUCT,
            PATHOP_FIELD_IDX,
            (local_ord >> 8) as u8,
            (local_ord & 0xff) as u8,
        ];
        let path_off = intern_path_program(pool, &render_prog)?;
        let param_off = if param_blob.is_empty() {
            0u16
        } else {
            intern_param_blob(pool, &param_blob)?
        };

        // SubField record: format_op | label_len | label | path_off | param_off
        // (byte-identical to a top-level field record — the device reuses the
        // same per-field renderer with `nested_ed` as the body).
        let label = clean_ascii_truncated(field.label.as_deref().unwrap_or(""), 254);
        sub_fields.push(format_op);
        sub_fields.push(label.len() as u8);
        sub_fields.extend_from_slice(label.as_bytes());
        sub_fields.extend_from_slice(&path_off.to_be_bytes());
        sub_fields.extend_from_slice(&param_off.to_be_bytes());
        sub_field_cnt = sub_field_cnt
            .checked_add(1)
            .ok_or_else(|| format!("format `{sig}`: too many nested sub-fields"))?;
    }

    // E2 self-check: every address-typed local word must be covered by a visible
    // child. The device enforces this independently, but a dbgen that emitted an
    // uncovered-address block would produce a dead (always-declined) descriptor,
    // so bail to the bare-marker belt here.
    for i in 0..member_count {
        if (addr_bmp[i / 8] >> (i % 8)) & 1 == 1 && !covered[i] {
            return Ok(None);
        }
    }

    // Assemble the v0x03 PARAM_NESTED_STRUCT payload.
    let mut payload: Vec<u8> = Vec::new();
    payload.push(0x03); // version byte: structured block (vs bare `0x01` belt)
    payload.extend_from_slice(&word_pos.to_be_bytes());
    payload.extend_from_slice(&type_hash);
    payload.extend_from_slice(&(member_count as u16).to_be_bytes());
    payload.push(u8::from(is_array)); // flags: bit0 = is_array (v2); rest reserved 0
    payload.extend_from_slice(&addr_bmp);
    payload.push(sub_field_cnt);
    payload.extend_from_slice(&sub_fields);
    // The payload is wrapped in a `push_tlv` (2-byte header) then interned with a
    // 1-byte length prefix, so it must leave room: `2 + payload.len() ≤
    // MAX_POOL_TLV_PAYLOAD`. Overflow → belt-decline rather than truncate.
    if payload.len() > MAX_POOL_TLV_PAYLOAD - 2 {
        return Ok(None);
    }

    let mut param_blob: Vec<u8> = Vec::new();
    push_tlv(&mut param_blob, PARAM_NESTED_STRUCT, &payload)?;
    let param_off = intern_param_blob(pool, &param_blob)?;

    // The anchor record renders nothing itself (the device descends on the
    // marker, ignoring `format_op`/`path_off`); the label carries the member
    // name for `erc7730.review.txt` readability.
    let label = clean_ascii_truncated(top, 254);
    Ok(Some(CompiledFieldOut {
        format_op: FMT_RAW,
        label: label.into_bytes(),
        path_off: 0,
        param_off,
    }))
}

/// Build a nested sub-field's format_op + LOCAL param TLV blob (v1 vocabulary:
/// visibility + tokenAmount local `tokenPath` + date encoding). Returns
/// `Ok(None)` for any param shape outside v1 (→ caller belt-declines the format).
/// Marks `covered[w]` for the local word a `tokenPath` IDs (E2 coverage).
fn compile_nested_subfield_params(
    field: &FieldDef,
    top: &str,
    is_array: bool,
    members: &[(String, String)],
    covered: &mut [bool],
) -> Result<Option<(u8, Vec<u8>)>, String> {
    let format_op = parse_format_name(field.format.as_deref().unwrap_or("raw"))?;
    let mut out: Vec<u8> = Vec::new();

    // Visibility — encode only if not the default `always`.
    if let Some(v) = field.visible.as_deref() {
        let byte = match v {
            "always" => VIS_ALWAYS,
            "never" => VIS_NEVER,
            "optional" => VIS_OPTIONAL,
            "if_not_in" | "ifNotIn" => VIS_IF_NOT_IN,
            "must_match" | "mustMatch" => VIS_MUST_MATCH,
            _ => return Ok(None),
        };
        if byte != VIS_ALWAYS {
            push_tlv(&mut out, PARAM_VISIBILITY, &[byte])?;
        }
    }

    let params = field.params.as_ref().and_then(|p| p.as_object());

    match format_op {
        FMT_RAW | FMT_AMOUNT => {
            // Elementary: no path-bearing params modelled in v1. If the
            // descriptor attaches params we don't understand, defer.
            if params.is_some_and(|o| !o.is_empty()) {
                return Ok(None);
            }
        }
        FMT_TOKEN_AMOUNT => {
            let Some(params) = params else { return Ok(None) };
            // v1 supports ONLY a local `tokenPath` (`top.child`) — no fixed
            // token, threshold, or message.
            if params.keys().any(|k| k != "tokenPath") {
                return Ok(None);
            }
            let Some(tp) = params.get("tokenPath").and_then(|v| v.as_str()) else {
                return Ok(None);
            };
            // Strip the `top.` (v1) or `top.[].` (v2 array) prefix; the remaining
            // single segment is the local token member.
            let Some(tok_child) = strip_nested_child(tp, top, is_array) else {
                return Ok(None); // cross-struct / indexed / deep tokenPath → v3
            };
            let Some(tok_ord) = members.iter().position(|(n, _)| n == tok_child) else {
                return Ok(None);
            };
            let tok_ord = u16::try_from(tok_ord).expect("member_count ≤ MAX_NESTED_MEMBERS");
            covered[tok_ord as usize] = true; // the token address word is bound
            let tok_prog = [
                PATHOP_ROOT_STRUCT,
                PATHOP_FIELD_IDX,
                (tok_ord >> 8) as u8,
                (tok_ord & 0xff) as u8,
            ];
            push_tlv(&mut out, PARAM_TOKEN_PATH, &tok_prog)?;
        }
        FMT_DATE => {
            if let Some(params) = params {
                if params.keys().any(|k| k != "encoding") {
                    return Ok(None);
                }
                if let Some(enc) = params.get("encoding").and_then(|v| v.as_str()) {
                    let b = match enc {
                        "timestamp" => DATE_ENC_TIMESTAMP,
                        "blockheight" => DATE_ENC_BLOCKHEIGHT,
                        _ => return Ok(None),
                    };
                    push_tlv(&mut out, PARAM_DATE_ENCODING, &[b])?;
                }
            }
        }
        _ => return Ok(None), // any other nested format → v2+/unsupported
    }

    Ok(Some((format_op, out)))
}

/// Intern a path program into the pool (length-prefixed). Mirrors the inline
/// idiom in `compile_one_field`.
fn intern_path_program(pool: &mut Pool, prog: &[u8]) -> Result<u16, String> {
    if prog.len() > MAX_PATH_PROGRAM_LEN {
        return Err(format!(
            "nested path program too long ({} > {MAX_PATH_PROGRAM_LEN})",
            prog.len()
        ));
    }
    let mut blob = Vec::with_capacity(1 + prog.len());
    blob.push(prog.len() as u8);
    blob.extend_from_slice(prog);
    pool.intern(&blob)
}

/// Intern a param TLV blob into the pool (length-prefixed). Mirrors the inline
/// idiom in `compile_one_field`.
fn intern_param_blob(pool: &mut Pool, param_blob: &[u8]) -> Result<u16, String> {
    if param_blob.len() > MAX_POOL_TLV_PAYLOAD {
        return Err(format!(
            "nested param blob too long ({} > {MAX_POOL_TLV_PAYLOAD})",
            param_blob.len()
        ));
    }
    let mut blob = Vec::with_capacity(1 + param_blob.len());
    blob.push(param_blob.len() as u8);
    blob.extend_from_slice(param_blob);
    pool.intern(&blob)
}

fn compile_params(
    sig: &str,
    field_idx: usize,
    format_op: u8,
    params: Option<&serde_json::Value>,
    visible: Option<&str>,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    ctx: &mut CompileCtx,
    enum_offsets: &BTreeMap<String, u16>,
) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();

    // Visibility — encode only if not the default `always`.
    if let Some(v) = visible {
        let byte = match v {
            "always" => VIS_ALWAYS,
            "never" => VIS_NEVER,
            "optional" => VIS_OPTIONAL,
            "if_not_in" | "ifNotIn" => VIS_IF_NOT_IN,
            "must_match" | "mustMatch" => VIS_MUST_MATCH,
            other => {
                return Err(format!(
                    "format `{sig}` field[{field_idx}] unknown `visible`: {other:?}"
                ))
            }
        };
        if byte != VIS_ALWAYS {
            push_tlv(&mut out, PARAM_VISIBILITY, &[byte])?;
        }
    }

    let Some(params) = params else {
        return Ok(out);
    };
    let params = params.as_object().ok_or_else(|| {
        format!("format `{sig}` field[{field_idx}] `params` is not an object")
    })?;

    // Per-formatter param dispatch.
    match format_op {
        FMT_TOKEN_AMOUNT => {
            if let Some(tp) = params.get("tokenPath").and_then(|v| v.as_str()) {
                let prog = compile_token_path(tp, context_kind, parsed)
                    .map_err(|e| format!("tokenPath `{tp}`: {e}"))?;
                push_tlv(&mut out, PARAM_TOKEN_PATH, &prog)?;
            }
            if let Some(t) = params.get("token").and_then(|v| v.as_str()) {
                let bytes = resolve_address_or_const(t, ctx)?;
                push_tlv(&mut out, PARAM_TOKEN, &bytes)?;
            }
            if let Some(th) = params.get("threshold") {
                let raw = match th {
                    serde_json::Value::String(s) => resolve_u256_or_const(s, ctx)?,
                    serde_json::Value::Number(n) => {
                        let mut b = [0u8; 32];
                        let v = n
                            .as_u64()
                            .ok_or_else(|| format!("threshold {n} not representable as u64"))?;
                        b[24..32].copy_from_slice(&v.to_be_bytes());
                        b
                    }
                    _ => return Err("threshold must be string or number".to_string()),
                };
                push_tlv(&mut out, PARAM_THRESHOLD, &raw)?;
            }
            if let Some(msg) = params.get("message").and_then(|v| v.as_str()) {
                let s = clean_ascii_truncated(msg, MAX_POOL_TLV_PAYLOAD);
                push_tlv(&mut out, PARAM_MESSAGE, s.as_bytes())?;
            }
        }
        FMT_ADDRESS_NAME | FMT_INTEROP_ADDR_NAME => {
            if let Some(arr) = params.get("types").and_then(|v| v.as_array()) {
                let mut bits = 0u8;
                for kind in arr {
                    let k = kind.as_str().ok_or_else(|| {
                        "addressName `types` entry must be a string".to_string()
                    })?;
                    bits |= match k {
                        "wallet" => ADDR_TYPE_WALLET,
                        "eoa" => ADDR_TYPE_EOA,
                        "contract" => ADDR_TYPE_CONTRACT,
                        "nft_collection" | "nftCollection" => ADDR_TYPE_NFT_COLLECTION,
                        "token" => ADDR_TYPE_TOKEN,
                        "collection" => ADDR_TYPE_COLLECTION,
                        other => {
                            return Err(format!(
                                "addressName: unknown type `{other}`"
                            ))
                        }
                    };
                }
                push_tlv(&mut out, PARAM_ADDR_TYPES, &[bits])?;
            }
            if let Some(arr) = params.get("sources").and_then(|v| v.as_array()) {
                let mut bits = 0u8;
                for src in arr {
                    let s = src.as_str().ok_or_else(|| {
                        "addressName `sources` entry must be a string".to_string()
                    })?;
                    bits |= match s {
                        "local" => ADDR_SRC_LOCAL,
                        "ens" => ADDR_SRC_ENS,
                        "etherscan" => ADDR_SRC_ETHERSCAN,
                        "registry" => ADDR_SRC_REGISTRY,
                        other => {
                            return Err(format!(
                                "addressName: unknown source `{other}`"
                            ))
                        }
                    };
                }
                push_tlv(&mut out, PARAM_ADDR_SOURCES, &[bits])?;
            }
        }
        FMT_DATE => {
            if let Some(enc) = params.get("encoding").and_then(|v| v.as_str()) {
                let b = match enc {
                    "timestamp" => DATE_ENC_TIMESTAMP,
                    "blockheight" => DATE_ENC_BLOCKHEIGHT,
                    other => return Err(format!("date.encoding: unknown `{other}`")),
                };
                push_tlv(&mut out, PARAM_DATE_ENCODING, &[b])?;
            }
        }
        FMT_DURATION => {
            // No params today; the renderer always reads the value as
            // seconds. Reserved for future use.
        }
        FMT_ENUM => {
            let refstr = params
                .get("$ref")
                .and_then(|v| v.as_str())
                .or_else(|| params.get("ref").and_then(|v| v.as_str()))
                .ok_or_else(|| "enum format requires `$ref`".to_string())?;
            let name = refstr
                .strip_prefix("$.metadata.enums.")
                .ok_or_else(|| format!("enum $ref must start with $.metadata.enums.: `{refstr}`"))?;
            let off = enum_offsets
                .get(name)
                .copied()
                .ok_or_else(|| format!("enum `{name}` was not pre-interned"))?;
            push_tlv(&mut out, PARAM_ENUM_REF, &off.to_be_bytes())?;
        }
        FMT_UNIT => {
            if let Some(d) = params.get("decimals").and_then(|v| v.as_u64()) {
                if d > 255 {
                    return Err("unit.decimals > 255".to_string());
                }
                push_tlv(&mut out, PARAM_DECIMALS, &[d as u8])?;
            }
            if let Some(b) = params.get("base").and_then(|v| v.as_str()) {
                let s = clean_ascii_truncated(b, MAX_POOL_TLV_PAYLOAD);
                push_tlv(&mut out, PARAM_BASE, s.as_bytes())?;
            }
            if let Some(p) = params.get("prefix").and_then(|v| v.as_bool()) {
                push_tlv(&mut out, PARAM_PREFIX, &[u8::from(p)])?;
            }
            if let Some(s) = params.get("suffix").and_then(|v| v.as_str()) {
                let s = clean_ascii_truncated(s, MAX_POOL_TLV_PAYLOAD);
                push_tlv(&mut out, PARAM_SUFFIX, s.as_bytes())?;
            }
        }
        FMT_CALLDATA => {
            if let Some(sel) = params.get("selector").and_then(|v| v.as_str()) {
                let sel = parse_hex_fixed::<4>(sel)?;
                push_tlv(&mut out, PARAM_NESTED_SELECTOR, &sel)?;
            }
            if let Some(callee) = params.get("calleePath").and_then(|v| v.as_str()) {
                let prog = compile_path(callee, context_kind, parsed)
                    .map_err(|e| format!("calleePath `{callee}`: {e}"))?;
                push_tlv(&mut out, PARAM_NESTED_CALLEE, &prog)?;
            }
        }
        FMT_ENCRYPTED => {
            let label = params
                .get("fallbackLabel")
                .and_then(|v| v.as_str())
                .unwrap_or("[encrypted]");
            let s = clean_ascii_truncated(label, MAX_POOL_TLV_PAYLOAD);
            push_tlv(&mut out, PARAM_FALLBACK_LABEL, s.as_bytes())?;
        }
        FMT_RAW | FMT_AMOUNT | FMT_NFT_NAME | FMT_CHAIN_ID | FMT_TOKEN_TICKER => {
            // No formatter-specific params on the seed corpus today.
            // Any unrecognized keys are ignored — keeps us forward-
            // compatible with future spec extensions.
        }
        _ => return Err(format!("unknown format opcode: 0x{:02x}", format_op)),
    }

    Ok(out)
}

fn parse_format_name(name: &str) -> Result<u8, String> {
    Ok(match name {
        "raw" => FMT_RAW,
        "amount" => FMT_AMOUNT,
        "tokenAmount" => FMT_TOKEN_AMOUNT,
        "nftName" => FMT_NFT_NAME,
        "date" => FMT_DATE,
        "duration" => FMT_DURATION,
        "addressName" => FMT_ADDRESS_NAME,
        "enum" => FMT_ENUM,
        "unit" => FMT_UNIT,
        "calldata" => FMT_CALLDATA,
        "chainId" => FMT_CHAIN_ID,
        "tokenTicker" => FMT_TOKEN_TICKER,
        "interoperableAddressName" => FMT_INTEROP_ADDR_NAME,
        // WYSIWYS (audit 2026-06-29): `encrypted` is REFUSED. There is no
        // honest way to clear-sign a value the format says to hide — the
        // firmware renderer would commit the field's path to the signed
        // digest while showing only a benign "[ENCRYPTED]" label, a
        // signed-but-not-shown operand on a page that looks like a normal
        // confirmation. A field that genuinely must not be displayed has to
        // be `visible:"never"` (excluded from the signed-and-shown set), not
        // rendered as `encrypted`. The firmware `render_encrypted` also
        // declines-to-blind as a runtime safety net.
        "encrypted" => {
            return Err(
                "format `encrypted` is refused: it hides a signed operand \
                 (WYSIWYS). Use `visible:\"never\"` for fields that must not \
                 be displayed."
                    .to_string(),
            )
        }
        other => return Err(format!("unknown format `{other}`")),
    })
}

// ─────────────────────────────────────────────────────────────────────
// Path compiler.
// ─────────────────────────────────────────────────────────────────────

/// Parsed view of a format key like
/// `"exactInputSingle((address tokenIn,address tokenOut,...) params)"`.
/// We strip parameter names for the keccak selector but keep them
/// indexed for path resolution.
#[derive(Debug)]
struct ParsedFormatKey {
    /// Types-only signature, e.g. `"exactInputSingle((address,address,...))"`.
    types_signature: String,
    /// The top-level argument names (root-level of `#.`).
    top_names: Vec<String>,
    /// The top-level argument *types*, positionally aligned with
    /// [`top_names`](Self::top_names). Needed to compute each field's ABI
    /// static head width so a calldata path resolves to the correct
    /// 32-byte head word and not a logical ordinal (see
    /// [`compile_structured_contract_path`] — closes the walker
    /// slot-confusion forgery class).
    top_types: Vec<String>,
    /// For tuple-typed top args, the inner names by top-arg name.
    /// e.g. `"params" -> ["tokenIn","tokenOut",...]`.
    /// For non-tuple top args this map is empty.
    inner_names: BTreeMap<String, Vec<String>>,
    /// Inner member *types* for tuple-typed top args, positionally aligned
    /// with [`inner_names`](Self::inner_names).
    inner_types: BTreeMap<String, Vec<String>>,
    /// EIP-712 referenced struct definitions parsed from the trailing
    /// `Struct(member…)Struct2(member…)` tail of an `encodeType` format key
    /// (`struct_name -> [(member_name, member_type)]`). Empty for contract
    /// format keys (which carry no such tail) and for EIP-712 primary types
    /// that reference no sub-structs. Needed to descend into nested typed-
    /// data members: a top-level member whose type is a struct name is a
    /// single opaque `hashStruct` word on the wire, so a fund-routing
    /// `address` nested inside it is committed to the signature yet invisible
    /// unless the visibility gate walks these definitions
    /// (`VULN-erc7730-eip712-nested-struct-address-hide`).
    struct_defs: BTreeMap<String, Vec<(String, String)>>,
}

/// Audit H-3 — contract-context field-completeness lint.
///
/// A clear-sign descriptor that silently omits an effect-bearing calldata
/// argument renders a benign-looking page while the signature still
/// commits to the hidden word (the canonical break: a
/// `transfer(address,uint256)` descriptor that declares only the amount
/// and never the recipient). The on-device renderer cannot reconstruct
/// ABI arity to catch the gap, so completeness is enforced HERE — where
/// every parameter of the function signature is known — and an
/// incomplete descriptor is refused at build time rather than pinned.
///
/// Every top-level parameter MUST be accounted for by at least one of:
///   * a field whose path resolves to it, at ANY visibility — an explicit
///     `visible:"never"` is a conscious author decision to hide a
///     non-effect-bearing field (nonce / deadline / referral / permit);
///   * a `tokenAmount` field's `tokenPath`, which surfaces the parameter
///     as the token whose symbol labels the amount (e.g. Aave's `asset`).
///
/// Parameters reached only through `@`-container or `$`-metadata roots are
/// envelope / constant references, not calldata arguments, so they never
/// need their own coverage.
///
/// Granularity matches what the on-device renderer can address. The
/// renderer resolves a calldata path by SUMMING `FieldIdx` head-word slots
/// (`secure/src/tx/display/erc7730/formatters.rs::resolve_path`), so it
/// addresses each member of a *plain* static tuple individually. Coverage
/// is therefore enforced per static-tuple MEMBER, not merely per top-level
/// argument: a descriptor that walks `order.amount` but omits
/// `order.recipient` would render a benign page while the signature still
/// commits to the hidden recipient. Static arrays and array-of-tuple
/// arguments are NOT element-addressable on device (the renderer refuses
/// `ArrayIdx`), so they stay at top-level granularity. Nested tuples are
/// covered one level deep — the format-key parser captures a single inner
/// level, so a deeper member rides on its parent member's coverage.
fn check_contract_field_completeness(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
) -> Result<(), String> {
    if parsed.top_names.is_empty() {
        return Ok(()); // zero-argument function, e.g. `deposit()`.
    }

    // Every descriptor path that surfaces a calldata word: each field's
    // own path, plus any `tokenPath` param (which renders the word as the
    // token whose symbol labels an amount). `visible:"never"` fields are
    // included — an explicit hide is a conscious author decision.
    let mut paths: Vec<&str> = Vec::with_capacity(fmt.fields.len() * 2);
    for field in &fmt.fields {
        // Constant-annotation fields (no `path`) surface no calldata word.
        if let Some(p) = field.path.as_deref() {
            paths.push(p);
        }
        if let Some(tp) = field
            .params
            .as_ref()
            .and_then(|p| p.get("tokenPath"))
            .and_then(|v| v.as_str())
        {
            paths.push(tp);
        }
    }

    for (idx, top_name) in parsed.top_names.iter().enumerate() {
        // A *plain* static tuple — type `(...)` with no trailing `[]` array
        // suffix — has members the renderer addresses individually by ABI
        // head-word slot, so each member needs its own coverage.
        let top_ty = &parsed.top_types[idx];
        let plain_tuple_members = if top_ty.starts_with('(') && top_ty.ends_with(')') {
            parsed.inner_names.get(top_name).filter(|m| !m.is_empty())
        } else {
            None
        };

        match plain_tuple_members {
            Some(members) => {
                for member in members {
                    if !paths
                        .iter()
                        .any(|p| path_covers_tuple_member(p, top_name, member))
                    {
                        return Err(format!(
                            "format `{sig}`: tuple member `{top_name}.{member}` is neither \
                             rendered, explicitly hidden (`visible:\"never\"`), nor used as a \
                             `tokenPath`. The on-device renderer addresses static-tuple members \
                             individually, so every member must be accounted for or the trusted \
                             display can omit an effect-bearing field (audit H-3, tuple-member \
                             granularity)"
                        ));
                    }
                }
            }
            None => {
                if !paths
                    .iter()
                    .any(|p| path_top_param_index(p, parsed) == Some(idx as u16))
                {
                    return Err(format!(
                        "format `{sig}`: parameter #{idx} (`{}`) is neither rendered, explicitly \
                         hidden (`visible:\"never\"`), nor used as a `tokenPath` — every \
                         contract-call argument must be accounted for so the trusted display \
                         cannot omit an effect-bearing field (audit H-3)",
                        parsed.top_names[idx]
                    ));
                }
            }
        }
    }
    Ok(())
}

/// EIP-712 (typed-data) completeness lint — the typed-data sibling of
/// [`check_contract_field_completeness`] (audit 2026-06-25 HIGH-1).
///
/// The signed value is `structHash = keccak256(primary_type_hash ||
/// encoded_data)`, where `encoded_data` is the 32-bytes-per-member encoding
/// of the primary type's top-level members in declaration order. Each
/// top-level member is exactly ONE head word: value types encode inline,
/// `bytes`/`string` encode as their keccak, and a nested struct member
/// encodes as its `hashStruct` — one word regardless. So, for the *signed-
/// word coverage* purpose, there is no static-tuple-member granularity to
/// chase here: a per-top-member coverage check accounts for every top-level
/// word (which is what this lint proves).
///
/// The distinct hazard of an `address` hidden *inside* a nested struct
/// member's `hashStruct` word (committed to the signature yet invisible) is
/// NOT a coverage gap — the top-level member is still one declared word — so
/// it is handled where it belongs: [`check_field_visibility`] descends the
/// parsed `struct_defs` and requires every nested address to be shown, and
/// the on-device `PARAM_NESTED_STRUCT` belt declines any nested-struct format
/// to blind-sign (`VULN-erc7730-eip712-nested-struct-address-hide`). Keeping
/// this lint at top-level granularity avoids over-refusing a benign
/// address-free hidden sub-struct.
///
/// Refuse to pin a descriptor unless every member is accounted for by a
/// field of its own (rendered or `visible:"never"`) or as another field's
/// `tokenPath`. Without this, an honest-but-incomplete descriptor (the
/// Permit/Permit2 approval shape is the canonical risk) would let the
/// firmware sign a member such as `spender` that never reaches a page —
/// exactly the signed-but-not-shown gap the contract lint already closes.
fn check_eip712_field_completeness(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
) -> Result<(), String> {
    if parsed.top_names.is_empty() {
        return Ok(()); // zero-member type (degenerate; nothing to sign).
    }

    // Same coverage set as the contract path: each field's own path plus any
    // `tokenPath` param. `visible:"never"` fields are included — an explicit
    // hide is a conscious author decision.
    let mut paths: Vec<&str> = Vec::with_capacity(fmt.fields.len() * 2);
    for field in &fmt.fields {
        // Constant-annotation fields (no `path`) surface no calldata word.
        if let Some(p) = field.path.as_deref() {
            paths.push(p);
        }
        if let Some(tp) = field
            .params
            .as_ref()
            .and_then(|p| p.get("tokenPath"))
            .and_then(|v| v.as_str())
        {
            paths.push(tp);
        }
    }

    for (idx, top_name) in parsed.top_names.iter().enumerate() {
        if !paths
            .iter()
            .any(|p| path_top_param_index(p, parsed) == Some(idx as u16))
        {
            return Err(format!(
                "EIP-712 format `{sig}`: member #{idx} (`{top_name}`) is neither rendered, \
                 explicitly hidden (`visible:\"never\"`), nor used as a `tokenPath`. Every \
                 typed-data member is folded into the signed structHash, so the trusted \
                 display must account for each one or it can omit an effect-bearing field \
                 such as an approval `spender` (audit 2026-06-25 HIGH-1, EIP-712 completeness)"
            ));
        }
    }
    Ok(())
}

/// Does descriptor `path` surface the calldata word for tuple member
/// `(tuple_name, member_name)`? True when the path's first segment is
/// `tuple_name` and its second segment — an explicit `.member` access — is
/// `member_name`. Paths rooted at `@`-container / `$`-metadata cover no
/// calldata member. A bare-tuple path (`tuple_name` with no member) or an
/// array-indexed first hop covers no specific member, matching the
/// renderer, which reads exactly one head word per resolved path.
fn path_covers_tuple_member(path: &str, tuple_name: &str, member_name: &str) -> bool {
    let path = path.trim();
    let rest = if let Some(r) = path.strip_prefix('#') {
        r.trim_start_matches('.')
    } else if path.starts_with('@') || path.starts_with('$') {
        return false;
    } else {
        path
    };
    let end0 = rest.find(['.', '[']).unwrap_or(rest.len());
    if rest[..end0].trim() != tuple_name {
        return false;
    }
    // The member hop must be an explicit `.<member>` access (not `[i]`).
    let after = match rest[end0..].strip_prefix('.') {
        Some(a) => a,
        None => return false,
    };
    let end1 = after.find(['.', '[']).unwrap_or(after.len());
    after[..end1].trim() == member_name
}

/// Resolve the top-level function-argument index a descriptor `path`
/// touches, or `None` when the path roots at the `@`-container /
/// `$`-metadata namespace (no calldata argument) or names an argument the
/// format key does not declare.
fn path_top_param_index(path: &str, parsed: &ParsedFormatKey) -> Option<u16> {
    let path = path.trim();
    let rest = if let Some(r) = path.strip_prefix('#') {
        r.trim_start_matches('.')
    } else if path.starts_with('@') || path.starts_with('$') {
        return None;
    } else {
        path
    };
    let end = rest.find(['.', '[']).unwrap_or(rest.len());
    let seg = rest[..end].trim();
    if seg.is_empty() {
        return None;
    }
    parsed
        .top_names
        .iter()
        .position(|nm| nm == seg)
        .map(|p| p as u16)
}

/// True when the ABI type string (parameter names already stripped by
/// [`parse_format_key`]) carries at least one `address` component:
/// `address`, `address[]`, `address[3]`, or a tuple / tuple-array containing
/// an address. ABI has no other type whose token is `address`, so a
/// token-exact scan is precise — `uint256` / `bytes32` / `bool` / `string`
/// never false-hit.
fn type_contains_address(ty: &str) -> bool {
    ty.split(|c: char| matches!(c, '(' | ')' | '[' | ']' | ',') || c.is_whitespace())
        .any(|tok| tok == "address")
}

/// A field is *hidden* iff it is explicitly `visible:"never"`. Every other
/// visibility (`always` / absent / `optional` / `ifNotIn`) is potentially
/// shown, and `mustMatch` makes the on-device renderer reject the WHOLE
/// format (→ blind-sign), so none of them can leave an argument signed-but-
/// silently-hidden behind a clear-sign.
fn field_is_hidden(field: &FieldDef) -> bool {
    field.visible.as_deref() == Some("never")
}

/// The `tokenPath` param of a `tokenAmount`-style field, if any. A shown
/// amount whose `tokenPath` points at an address argument surfaces that
/// address's identity (name/symbol/decimals) to the user, which counts as
/// showing the address for the WYSIWYS rule.
fn field_token_path(field: &FieldDef) -> Option<&str> {
    field
        .params
        .as_ref()
        .and_then(|p| p.get("tokenPath"))
        .and_then(|v| v.as_str())
}

/// A field path that surfaces the transaction's native value (`msg.value`)
/// via the `@`-envelope. Showing the native value is a meaningful,
/// effect-bearing thing to render (a payable `submit` / stake whose ETH IS
/// the intent), so a visible native-value field satisfies rule 1 even when
/// every calldata argument is a deliberately-hidden tag.
fn path_is_native_value(path: &str) -> bool {
    matches!(path.trim(), "@.value" | "@value")
}

/// An INERT top-level parameter role: it tells the user WHO signs or WHEN the
/// call is valid, never WHAT the call does. Showing only inert fields is the
/// hole `VULN-erc7730-rule1-inert-field-nonaddr-action-hide` drives through —
/// a `MetaTransaction(nonce, from, bytes functionSignature)` descriptor that
/// renders `from`+`nonce` (both inert) while hiding `functionSignature` (the
/// entire meta-executed action) paints a reassuring banner over a blind-sign.
///
/// Deliberately NARROW: self-identity (`from`/`sender`/`owner`/`holder`) and
/// replay/time roles (`nonce`/`salt`/`deadline`/`valid*`/`expiry`). It does
/// NOT include `signer`/`to`/`spender`/`recipient`/`target`/`account` — those
/// name the address a call ACTS ON (Celo `authorizeVoteSigner(address signer)`
/// shows exactly `signer`, a genuine effect), so treating them as inert would
/// wrongly refuse legitimate clear-signs. Case-insensitive; a single leading
/// `_` (common Solidity arg style) is stripped before matching.
///
/// NOTE — this is a RULE 1 refinement (require a shown EFFECT-BEARING field),
/// NOT a rule-3 hidden-value gate. The deliberate "no rule-3 structural gate
/// for hidden non-address values" decision recorded at the tail of
/// [`check_field_visibility`] (2026-07-01) stands; rule 1 asks a different
/// question — is anything effect-bearing SHOWN — and closes the live Rarible
/// meta-tx witness (shows only `from`+`nonce`) that the residual analysis does
/// not, with zero corpus false positives.
fn is_inert_role_name(name: &str) -> bool {
    let n = name.trim().trim_start_matches('_').to_ascii_lowercase();
    matches!(
        n.as_str(),
        "from"
            | "sender"
            | "owner"
            | "holder"
            | "nonce"
            | "salt"
            | "deadline"
            | "validafter"
            | "validuntil"
            | "validbefore"
            | "expiry"
            | "expiration"
    )
}

/// Does the reviewed policy allowlist re-permit hiding argument `arg_path`
/// on function `sig`? Only entries WITH a non-empty rationale count (a
/// rationale-less entry fails safe → ignored). Leading `#.` on either side
/// is normalised away.
fn visibility_allowlisted(allow: &[HiddenAddressAllow], sig: &str, arg_path: &str) -> bool {
    fn norm(p: &str) -> &str {
        p.trim().trim_start_matches('#').trim_start_matches('.')
    }
    let want = norm(arg_path);
    allow.iter().any(|e| {
        !e.rationale.trim().is_empty() && e.signature == sig && norm(&e.path) == want
    })
}

/// WYSIWYS visibility gate — the sibling of the completeness lints
/// ([`check_contract_field_completeness`] /
/// [`check_eip712_field_completeness`]) that closes
/// `VULN-erc7730-visible-never-noparam-clearsign`.
///
/// Completeness proves every calldata / typed-data word is *declared* by
/// some field (rendered OR `visible:"never"`), so nothing is signed the
/// descriptor never mentions. It deliberately treats an explicit hide as a
/// conscious author decision — correct for a nonce / deadline / referral,
/// but exactly the hole a hostile-or-careless (auto-vendored) descriptor
/// drives through: mark the recipient / target `visible:"never"` and the
/// device clear-signs a reassuring banner with the fund-routing argument
/// invisible.
///
/// This gate adds the missing invariant — a clear-signed known shape must
/// SHOW its effect-bearing arguments — via two fail-safe rules (a refused
/// format drops to loud blind-sign in the tolerant corpus, or hard-errors a
/// hand-authored strict descriptor so we fix it):
///
///  1. **No parameter-less clear-sign.** A function that takes ≥1 argument
///     must surface at least one of them (a visible field whose path
///     resolves to a calldata / typed argument). Refuses the all-
///     `visible:"never"` witness (`setAllowedTarget`, `transferOwnership`,
///     …) that renders banner + envelope + confirm and nothing else.
///  2. **No hidden fund-routing address.** Every `address`-typed argument
///     (top-level, and — for the contract path — each individually-
///     addressable static-tuple member) must be shown, either directly or
///     as the `tokenPath` of a shown amount. A hidden address is refused
///     unless a reviewed [`HiddenAddressAllow`] policy entry re-permits it
///     with a written rationale (router-executor-behind-min-output /
///     relayer / linked-list hint). This is what stops the *next* corpus
///     resync from silently shipping a recipient-hiding transfer/withdraw
///     descriptor.
///
/// The on-device renderer carries a coarse structural backstop for rule 1
/// (a contract format that declares fields but renders none falls through to
/// blind-sign), but rule 2 has no cheap on-device analogue — the device
/// can't reconstruct which hidden field was an `address` — so this build-
/// time gate is the load-bearing guarantee against partial hides.
fn check_field_visibility(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    context_kind: u8,
    allow: &[HiddenAddressAllow],
) -> Result<(), String> {
    if parsed.top_names.is_empty() {
        return Ok(()); // zero-argument function / degenerate type — nothing to hide.
    }

    // Rule 1 — the trusted screen must surface a genuinely EFFECT-BEARING
    // field, not merely SOME argument. A visible field satisfies rule 1 when
    // it resolves to a calldata argument that is NOT an inert self-identity /
    // replay role (a `tokenAmount`'s `path` resolves to the amount argument; a
    // routing/target address resolves to its param) OR to the native tx value
    // (a payable `submit`/stake whose ETH is the intent).
    //
    // Counting ANY shown argument (the pre-fix behaviour) let a descriptor
    // render only `from`+`nonce` — both inert — while hiding its sole
    // effect-bearing operand, painting a reassuring banner over a blind-sign
    // (`VULN-erc7730-rule1-inert-field-nonaddr-action-hide`; live witness the
    // Rarible `MetaTransaction` meta-tx forwarder). Requiring a non-inert
    // shown field refuses that shape while still passing Celo
    // `authorizeVoteSigner(address signer)` (the shown `signer` IS the effect).
    let any_shown_effect = fmt.fields.iter().any(|f| {
        !field_is_hidden(f)
            && f.path.as_deref().is_some_and(|p| {
                path_is_native_value(p)
                    || path_top_param_index(p, parsed).is_some_and(|idx| {
                        parsed
                            .top_names
                            .get(idx as usize)
                            .is_some_and(|nm| !is_inert_role_name(nm))
                    })
            })
    });
    if !any_shown_effect {
        return Err(format!(
            "format `{sig}`: every shown field is an inert self-identity / replay role \
             (`from`/`owner`/`nonce`/`salt`/`deadline`/…) or the format is parameter-less, and \
             the native value is not shown — a clear-signed known shape must surface at least one \
             EFFECT-BEARING field (an amount, a routing/target address, or a state-changing \
             operand), else the trusted display shows only a reassuring banner while the user \
             blind-signs the call (WYSIWYS; VULN-erc7730-rule1-inert-field-nonaddr-action-hide / \
             VULN-erc7730-visible-never-noparam-clearsign). Drop the format or make an \
             effect-bearing field visible."
        ));
    }

    // Rule 2 — no hidden `address` argument (unless reviewed-allowlisted).
    for (idx, top_name) in parsed.top_names.iter().enumerate() {
        let top_ty = &parsed.top_types[idx];

        // Contract static-tuple members are addressed individually by the
        // renderer (mirrors the completeness lint) — descend one level.
        let members = if context_kind == CTX_CONTRACT
            && top_ty.starts_with('(')
            && top_ty.ends_with(')')
        {
            parsed
                .inner_names
                .get(top_name)
                .zip(parsed.inner_types.get(top_name))
                .filter(|(names, _)| !names.is_empty())
        } else {
            None
        };

        // EIP-712 typed-data member whose type is a nested struct: its
        // `address`es live behind an opaque `hashStruct` word, so descend
        // through the parsed struct definitions and require each nested
        // address to be shown — the fix for
        // `VULN-erc7730-eip712-nested-struct-address-hide`. Scalar EIP-712
        // members (and contract members) fall through to the checks below.
        if context_kind == CTX_EIP712 {
            let (base, is_array) = split_array_suffix(top_ty);
            if type_is_struct(base, parsed) {
                let mut visited: Vec<String> = Vec::new();
                check_eip712_member_addresses(
                    sig, fmt, parsed, allow, top_name, top_ty, is_array, 0, &mut visited,
                )?;
                continue;
            }
        }

        match members {
            Some((member_names, member_types)) => {
                for (m_idx, member) in member_names.iter().enumerate() {
                    let m_ty = member_types.get(m_idx).map(String::as_str).unwrap_or("");
                    if !type_contains_address(m_ty) {
                        continue;
                    }
                    let shown = fmt.fields.iter().any(|f| {
                        !field_is_hidden(f)
                            && (f
                                .path
                                .as_deref()
                                .is_some_and(|p| path_covers_tuple_member(p, top_name, member))
                                || field_token_path(f)
                                    .is_some_and(|tp| path_covers_tuple_member(tp, top_name, member)))
                    });
                    if !shown {
                        let arg_path = format!("{top_name}.{member}");
                        if !visibility_allowlisted(allow, sig, &arg_path) {
                            return Err(hidden_address_err(sig, &arg_path));
                        }
                    }
                }
            }
            None => {
                if !type_contains_address(top_ty) {
                    continue;
                }
                let shown = fmt.fields.iter().any(|f| {
                    !field_is_hidden(f)
                        && (f
                            .path
                            .as_deref()
                            .is_some_and(|p| path_top_param_index(p, parsed) == Some(idx as u16))
                            || field_token_path(f)
                                .is_some_and(|tp| path_top_param_index(tp, parsed) == Some(idx as u16)))
                });
                if !shown && !visibility_allowlisted(allow, sig, top_name) {
                    return Err(hidden_address_err(sig, top_name));
                }
            }
        }
    }

    // NOTE (non-address hidden-value residual, 2026-07-01): there is deliberately
    // NO rule-3 structural gate for hidden NON-address values. An empirical pass
    // (both a `bytes`/`string`/array variant and an arrays-only variant, measured
    // against the live corpus) found 0 true positives and only false positives:
    // the corpus hides non-address values legitimately at scale (deadlines /
    // tickets / hints as `uint`; attestation signatures as `bytes`; gas-hint /
    // order-trait / packed-data-length batches as `uint256[]`), always alongside
    // the effect-bearing fields being shown. Unlike an `address` (rare-to-hide and
    // always fund-routing → rule 2), a hidden non-address value is
    // type-indistinguishable from a benign one, so a structural gate over-fires
    // with no security benefit. The two highest-severity cases are covered
    // elsewhere (native `@.value` is always spliced on-device by
    // `enforce_native_value_page`; bare ERC-20 transfer/approve render via the
    // native decoder). The remaining residual — a descriptor that hides an
    // effect-bearing scalar value/payload while the recipient/intent IS shown — is
    // bounded / MEDIUM and attestation-backstopped. See
    // `docs/VULN-erc7730-visible-never-noparam-clearsign.md` § non-address residual.
    Ok(())
}

/// Recursively require every `address` reachable through an EIP-712 nested
/// struct `member` (at descriptor path `member_path`, ABI/struct type
/// `member_ty`) to be shown by a visible field — or re-permitted by a
/// reviewed [`HiddenAddressAllow`]. The fix for
/// `VULN-erc7730-eip712-nested-struct-address-hide`.
///
/// * A struct member (`member_ty` names a struct in the parsed tail) is
///   descended: each of its members is checked at path
///   `member_path.<inner>`. An *array*-of-struct member is not individually
///   addressable on device, so if it (transitively) reaches any address the
///   whole member must be allowlisted, else it is refused.
/// * A scalar `address` member must be covered by a visible field whose
///   `path` (or shown-amount `tokenPath`) resolves to exactly `member_path`.
///
/// Bounded by [`MAX_STRUCT_DEPTH`] and a `visited` set; a type too deep or
/// (malformed) cyclic is refused rather than reasoned about.
#[allow(clippy::too_many_arguments)]
fn check_eip712_member_addresses(
    sig: &str,
    fmt: &Format,
    parsed: &ParsedFormatKey,
    allow: &[HiddenAddressAllow],
    member_path: &str,
    member_ty: &str,
    is_array: bool,
    depth: usize,
    visited: &mut Vec<String>,
) -> Result<(), String> {
    let (base, _) = split_array_suffix(member_ty);

    if type_is_struct(base, parsed) {
        if is_array {
            // Array-of-struct. v2 renders EVERY element (`M.[].child`), so an
            // address inside CAN be shown — for a v2-supported element (a struct
            // of ELEMENTARY members: no nested struct, no deeper array) descend
            // and apply the SAME per-element coverage check as the non-array
            // case, with `M.[].child` paths. An element that itself reaches a
            // nested struct or a deeper array is NOT v2-renderable → keep the
            // original refuse-if-reaches-address (fail-closed; v3 territory).
            if array_element_is_v2_supported(base, parsed) {
                let members = parsed.struct_defs.get(base).cloned().unwrap_or_default();
                for (m_name, m_ty) in &members {
                    let child_path = format!("{member_path}.[].{m_name}");
                    let (_, child_is_array) = split_array_suffix(m_ty);
                    check_eip712_member_addresses(
                        sig, fmt, parsed, allow, &child_path, m_ty, child_is_array, depth + 1,
                        visited,
                    )?;
                }
                return Ok(());
            }
            let mut probe: Vec<String> = Vec::new();
            if struct_reaches_address(base, parsed, depth, &mut probe)
                && !visibility_allowlisted(allow, sig, member_path)
            {
                return Err(hidden_address_err(sig, member_path));
            }
            return Ok(());
        }
        if depth >= MAX_STRUCT_DEPTH || visited.iter().any(|v| v == base) {
            // Too deep / cyclic to reason about: fail closed on any address.
            let mut probe: Vec<String> = Vec::new();
            if struct_reaches_address(base, parsed, depth, &mut probe)
                && !visibility_allowlisted(allow, sig, member_path)
            {
                return Err(hidden_address_err(sig, member_path));
            }
            return Ok(());
        }
        visited.push(base.to_string());
        // Clone the member list so the recursive borrow of `parsed` is
        // immutable-only (host build; not perf-critical).
        let members = parsed.struct_defs.get(base).cloned().unwrap_or_default();
        for (m_name, m_ty) in &members {
            let child_path = format!("{member_path}.{m_name}");
            let (_, child_is_array) = split_array_suffix(m_ty);
            check_eip712_member_addresses(
                sig, fmt, parsed, allow, &child_path, m_ty, child_is_array, depth + 1, visited,
            )?;
        }
        visited.pop();
        return Ok(());
    }

    // Scalar (non-struct) member: only `address`-bearing types matter.
    if !type_contains_address(base) {
        return Ok(());
    }
    let shown = fmt.fields.iter().any(|f| {
        !field_is_hidden(f)
            && (f
                .path
                .as_deref()
                .is_some_and(|p| path_matches_member(p, member_path))
                || field_token_path(f).is_some_and(|tp| path_matches_member(tp, member_path)))
    });
    if !shown && !visibility_allowlisted(allow, sig, member_path) {
        return Err(hidden_address_err(sig, member_path));
    }
    Ok(())
}

/// Does descriptor `path` resolve to exactly the dotted typed-data member
/// `member_path` (e.g. `details.token`, `details.[].token`, `witness.info.reactor`)?
/// A leading `#`/`.` is normalised away; `@`-container / `$`-metadata roots cover
/// no message member. The whole-array WILDCARD segment `[]` IS matchable — v2
/// renders EVERY element of a `T[]`, so a per-element field/tokenPath
/// `M.[].child` covers `M.[].child` for every element. An INDEXED / sliced
/// segment (`[0]`, `[-1]`, `[0:20]`) names a specific element the gate cannot
/// reason about per-element and is rejected. Segments are compared literally, so
/// `[]` matches only `[]` (never a named member), keeping the address-coverage
/// decision exact.
fn path_matches_member(path: &str, member_path: &str) -> bool {
    let p = path.trim();
    let rest = if let Some(r) = p.strip_prefix('#') {
        r.trim_start_matches('.')
    } else if p.starts_with('@') || p.starts_with('$') {
        return false;
    } else {
        p
    };
    // Reject INDEXED/sliced array segments (a specific element); allow the
    // whole-array wildcard `[]`.
    if rest
        .split('.')
        .any(|seg| seg.contains('[') && seg.trim() != "[]")
    {
        return false;
    }
    // Compare dot-separated segments, trimming incidental whitespace. `[]`
    // compares literally, so it matches only another `[]` wildcard segment.
    let mut a = rest.split('.').map(str::trim);
    let mut b = member_path.split('.').map(str::trim);
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) if x == y => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn hidden_address_err(sig: &str, arg_path: &str) -> String {
    format!(
        "format `{sig}`: address argument `{arg_path}` is `visible:\"never\"` and never shown \
         (nor surfaced as a shown amount's `tokenPath`) — a hidden fund-routing address behind a \
         trusted clear-sign is a WYSIWYS break (VULN-erc7730-visible-never-noparam-clearsign). \
         Show it, or add a reviewed `hidden_address_allow` policy entry with a rationale if the \
         address routes no funds (e.g. a router executor bounded by a shown min-return)."
    )
}

/// The first name that appears more than once in `names` (empty names —
/// which no path can address — are ignored). A duplicate name defeats the
/// NAME-keyed tuple-member coverage/visibility gates
/// (`check_contract_field_completeness` + `check_field_visibility` rule 2 both
/// test membership with the position-blind `path_covers_tuple_member`): one
/// field would "cover" two distinct ABI slots, so an aliased effect-bearing
/// member (e.g. a duplicated `collateralToken` address that co-defines a
/// Morpho market) is signed but never rendered — a WYSIWYS break behind a
/// reassuring clear-sign. `parse_format_key` rejects it fail-closed. A real
/// Solidity function signature / struct never has duplicate parameter names,
/// so this refuses only malformed / crafted descriptors (→ loud blind-sign).
fn first_duplicate_name(names: &[String]) -> Option<&str> {
    for (i, n) in names.iter().enumerate() {
        if n.is_empty() {
            continue;
        }
        if names[..i].iter().any(|m| m == n) {
            return Some(n);
        }
    }
    None
}

fn parse_format_key(sig: &str) -> Result<ParsedFormatKey, String> {
    let sig = sig.trim();
    let name_end = sig
        .find('(')
        .ok_or_else(|| format!("missing '(' in format key `{sig}`"))?;
    let fname = &sig[..name_end];
    let rest = &sig[name_end..];

    let (args_str, types_args_str) = split_arg_list(rest)?;

    // Anything after the primary type's argument list is the EIP-712
    // `encodeType` tail: zero or more referenced struct definitions
    // (`Struct(member…)Struct2(member…)`). `split_arg_list` matched only the
    // FIRST paren group, so `rest[args_str.len()..]` is exactly this tail
    // (empty for a contract selector or a struct-free typed-data type). The
    // gate walks these to reach `address`es nested inside struct members.
    let struct_defs = parse_struct_defs(&rest[args_str.len()..])?;

    let types_signature = format!("{fname}{types_args_str}");

    // Now parse the top-level args of `args_str` (which includes the
    // surrounding parens).
    let inner = &args_str[1..args_str.len() - 1]; // strip outer ()
    let top_args = split_top_args(inner);

    let mut top_names = Vec::with_capacity(top_args.len());
    let mut top_types = Vec::with_capacity(top_args.len());
    let mut inner_names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut inner_types: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for arg in top_args {
        let arg = arg.trim();
        if arg.is_empty() {
            continue;
        }
        if let Some(stripped) = arg.strip_prefix('(') {
            // Tuple-typed argument: `(inner_types... innerN names...) outer_name`.
            let close = find_matching_paren(arg.as_bytes(), 0)
                .ok_or_else(|| format!("unbalanced tuple in `{arg}`"))?;
            let tuple_body = &arg[1..close];
            let after = arg[close + 1..].trim();
            let outer_name = first_ident_or_empty(after);
            if outer_name.is_empty() {
                return Err(format!(
                    "top-level tuple arg has no name (need `(...types...) name`): `{arg}`"
                ));
            }
            top_names.push(outer_name.to_string());
            // Type string with all parameter names stripped (e.g.
            // `(address,address,uint24,...)` or `(...)[2]`).
            top_types.push(strip_one_arg(arg));
            // Parse inner field names + types.
            let inner_args = split_top_args(tuple_body);
            let mut names = Vec::with_capacity(inner_args.len());
            let mut types = Vec::with_capacity(inner_args.len());
            for inner_arg in inner_args {
                let inner_arg = inner_arg.trim();
                names.push(last_ident(inner_arg).to_string());
                types.push(strip_one_arg(inner_arg));
            }
            // WYSIWYS: the completeness + visibility gates resolve tuple members
            // by NAME (position-blind `path_covers_tuple_member`). A duplicate
            // member name would let ONE field cover TWO distinct ABI slots, so an
            // aliased effect-bearing member (e.g. a duplicated `collateralToken`
            // address that co-defines a Morpho market) is signed but never shown.
            // Reject fail-closed (a real Solidity struct has no dup member names).
            if let Some(dup) = first_duplicate_name(&names) {
                return Err(format!(
                    "tuple `{outer_name}` has duplicate member name `{dup}`; the on-device \
                     renderer and the completeness/visibility gates address tuple members by \
                     name, so a duplicate would hide the aliased member behind a trusted \
                     clear-sign (WYSIWYS). Refused."
                ));
            }
            inner_names.insert(outer_name.to_string(), names);
            inner_types.insert(outer_name.to_string(), types);
            let _ = stripped; // silence unused
        } else {
            top_names.push(last_ident(arg).to_string());
            top_types.push(strip_one_arg(arg));
        }
    }

    // Symmetric top-level guard. `path_top_param_index` IS position-aware, so a
    // duplicate top-level name is already caught downstream by completeness —
    // but reject it here too, fail-closed, so the rule is uniform with the
    // tuple-member guard above and a crafted descriptor never reaches the gates.
    if let Some(dup) = first_duplicate_name(&top_names) {
        return Err(format!(
            "format key has duplicate top-level argument name `{dup}`; a real function \
             signature has no duplicate parameter names. Refused."
        ));
    }

    Ok(ParsedFormatKey {
        types_signature,
        top_names,
        top_types,
        inner_names,
        inner_types,
        struct_defs,
    })
}

/// Parse the trailing struct-definition list of an EIP-712 `encodeType`
/// string — the part after the primary type's own argument list. The
/// canonical encoding appends every referenced struct, sorted, as
/// `Name(type name,type name,…)`; e.g. the tail of
/// `PermitSingle(PermitDetails details,…)PermitDetails(address token,…)`
/// is `PermitDetails(address token,…)`. Returns `name -> [(member_name,
/// member_type)]`. Names may be forward-referenced (a struct member whose
/// type is defined later in the tail), so callers must parse the whole tail
/// before resolving any member type.
///
/// Fails closed: a malformed tail (missing `(`, unbalanced parens, a
/// non-identifier name, or a duplicate definition) is an error, so a
/// hand-authored descriptor is rejected and a tolerant-corpus one drops to
/// blind-sign rather than silently under-parsing (which is what let the
/// nested-address hide slip the gate in the first place).
fn parse_struct_defs(tail: &str) -> Result<BTreeMap<String, Vec<(String, String)>>, String> {
    let mut defs: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut rest = tail.trim();
    while !rest.is_empty() {
        let open = rest
            .find('(')
            .ok_or_else(|| format!("malformed EIP-712 struct-def tail (no `(`): `{rest}`"))?;
        let name = rest[..open].trim();
        if name.is_empty() || first_ident_or_empty(name) != name {
            return Err(format!("bad EIP-712 struct name in tail: `{name}`"));
        }
        let close = find_matching_paren(rest.as_bytes(), open)
            .ok_or_else(|| format!("unbalanced parens in EIP-712 struct def `{name}`"))?;
        let body = &rest[open + 1..close];
        let mut members: Vec<(String, String)> = Vec::new();
        for m in split_top_args(body) {
            let m = m.trim();
            if m.is_empty() {
                continue;
            }
            members.push((last_ident(m).to_string(), strip_one_arg(m)));
        }
        if defs.insert(name.to_string(), members).is_some() {
            return Err(format!("duplicate EIP-712 struct def `{name}`"));
        }
        rest = rest[close + 1..].trim_start();
    }
    Ok(defs)
}

/// Split an ABI/typed-data type into its base type and whether it carries
/// any array suffix: `"DutchOutput[]"` → `("DutchOutput", true)`,
/// `"address"` → `("address", false)`, `"uint256[3][]"` → `("uint256",
/// true)`. Array elements are never individually addressable on device, so
/// the `is_array` flag gates the nested-address descent.
fn split_array_suffix(ty: &str) -> (&str, bool) {
    match ty.find('[') {
        Some(i) => (ty[..i].trim(), true),
        None => (ty.trim(), false),
    }
}

/// True when `base` (an array-stripped type name) is an EIP-712 struct
/// defined in the format key's tail.
fn type_is_struct(base: &str, parsed: &ParsedFormatKey) -> bool {
    parsed.struct_defs.contains_key(base)
}

/// A v2-renderable array element: a struct ALL of whose members are ELEMENTARY
/// (no member is itself a struct or an array). Deeper element shapes (a nested
/// struct or an array-in-element) are v3, so the address gate keeps its
/// fail-closed refuse for them. Kept in lockstep with the on-device array render
/// + emission, which only handle a single-level array of an elementary-member
/// struct.
fn array_element_is_v2_supported(base: &str, parsed: &ParsedFormatKey) -> bool {
    let Some(members) = parsed.struct_defs.get(base) else {
        return false;
    };
    members.iter().all(|(_n, ty)| {
        let (b, is_array) = split_array_suffix(ty);
        !is_array && !type_is_struct(b, parsed)
    })
}

/// True when the EIP-712 struct `base` transitively reaches an `address`
/// (directly, through a nested struct, or through an array-of-struct). Used
/// to decide whether an array-of-struct member — whose elements the device
/// cannot address individually — hides a fund-routing address. Bounded by
/// `MAX_STRUCT_DEPTH` and a visited set, so a (malformed) cyclic type is
/// treated as "contains an address" (fail-safe: refuse to clear-sign).
fn struct_reaches_address(base: &str, parsed: &ParsedFormatKey, depth: usize, visited: &mut Vec<String>) -> bool {
    if depth > MAX_STRUCT_DEPTH || visited.iter().any(|v| v == base) {
        return true; // fail safe — cannot prove address-free
    }
    let Some(members) = parsed.struct_defs.get(base) else {
        return false; // unknown non-struct base carries no address token here
    };
    visited.push(base.to_string());
    let reaches = members.iter().any(|(_, mty)| {
        let (mbase, _is_array) = split_array_suffix(mty);
        if type_is_struct(mbase, parsed) {
            struct_reaches_address(mbase, parsed, depth + 1, visited)
        } else {
            type_contains_address(mbase)
        }
    });
    visited.pop();
    reaches
}

// ─────────────────────────────────────────────────────────────────────
// Nested-EIP-712 (Phase 5) — per-struct metadata derivation.
//
// The device binds a nested-struct member by re-hashing
// `keccak(typeHash(nested) ‖ nested_ed)` and requiring equality with the
// committed parent word (see `docs/erc7730-nested-eip712-render-design.md`).
// `typeHash(nested)` must be dbgen-PINNED and canonical, so these functions
// rebuild the EIP-712 `encodeType` string from the parsed `struct_defs` and
// hash it. Pure host logic; unit-tested against foundry `cast keccak`.
// ─────────────────────────────────────────────────────────────────────

#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
type StructDefs = BTreeMap<String, Vec<(String, String)>>;

/// Reconstruct a single struct's canonical `encodeType` component:
/// `Name(type1 name1,type2 name2,…)` — the exact form the registry's format
/// key uses (space between type and name, comma between members, no other
/// whitespace), so `keccak` of the assembled string matches the on-chain
/// `typeHash`.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_struct_def_string(name: &str, defs: &StructDefs) -> Result<String, String> {
    let members = defs
        .get(name)
        .ok_or_else(|| format!("EIP-712 struct `{name}` has no definition"))?;
    let mut s = String::with_capacity(name.len() + 2 + members.len() * 16);
    s.push_str(name);
    s.push('(');
    for (i, (mname, mty)) in members.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(mty);
        s.push(' ');
        s.push_str(mname);
    }
    s.push(')');
    Ok(s)
}

/// Transitively collect the struct types `name` references (array suffixes
/// stripped), EXCLUDING `name` itself. Bounded by `MAX_STRUCT_DEPTH`; a cyclic
/// / too-deep type errors (fail-closed — the format then drops to blind-sign).
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_collect_struct_deps(
    name: &str,
    defs: &StructDefs,
    out: &mut std::collections::BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_STRUCT_DEPTH {
        return Err(format!("EIP-712 struct `{name}` nests deeper than {MAX_STRUCT_DEPTH}"));
    }
    let Some(members) = defs.get(name) else {
        return Ok(());
    };
    for (_, mty) in members {
        let (base, _is_array) = split_array_suffix(mty);
        if defs.contains_key(base) && out.insert(base.to_string()) {
            eip712_collect_struct_deps(base, defs, out, depth + 1)?;
        }
    }
    Ok(())
}

/// Canonical EIP-712 `encodeType(name)` = `name`'s own def followed by the defs
/// of every transitively-referenced struct, sorted alphabetically (the EIP-712
/// rule). `BTreeSet` iterates in sorted order, so the concatenation is canonical.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_encode_type(name: &str, defs: &StructDefs) -> Result<String, String> {
    let mut deps: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    eip712_collect_struct_deps(name, defs, &mut deps, 0)?;
    deps.remove(name); // a self-referential type keeps only one copy of its own def
    let mut out = eip712_struct_def_string(name, defs)?;
    for dep in &deps {
        out.push_str(&eip712_struct_def_string(dep, defs)?);
    }
    Ok(out)
}

/// `typeHash(nested)` = `keccak256(encodeType(nested))` — dbgen-pinned, emitted
/// into the IR so the device can bind `keccak(typeHash ‖ nested_ed) == committed`.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_nested_type_hash(name: &str, defs: &StructDefs) -> Result<[u8; 32], String> {
    Ok(keccak256(eip712_encode_type(name, defs)?.as_bytes()))
}

/// The NESTED struct's OWN member count — the number of 32-byte words in its
/// `encodeData`, which pins the exact `nested_ed` length (`member_count × 32`)
/// the device consumes and hashes (design rule 1 / E5).
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_member_count(name: &str, defs: &StructDefs) -> Result<usize, String> {
    defs.get(name)
        .map(Vec::len)
        .ok_or_else(|| format!("EIP-712 struct `{name}` has no definition"))
}

/// Whether a nested member's OWN 32-byte word is an `address` (so it must be
/// covered by a visible sub-field — the E2 standalone belt backstop). A member
/// whose type is itself a struct is a `hashStruct` word (its interior addresses
/// are covered by that struct's own descent + bitmap), not an address; an
/// array member is an offset/hash word (v2). So v1 marks only bare `address`.
#[allow(dead_code)] // Phase-5 nested-EIP-712: wired into IR emission in the next increment
fn eip712_member_word_is_address(mty: &str) -> bool {
    mty.trim() == "address"
}

/// `arg_list` starts with `(`. Returns the original substring plus a
/// types-only version (parameter names stripped).
fn split_arg_list(s: &str) -> Result<(String, String), String> {
    if !s.starts_with('(') {
        return Err(format!("expected '(' at start of `{s}`"));
    }
    let close = find_matching_paren(s.as_bytes(), 0)
        .ok_or_else(|| format!("unbalanced parens in `{s}`"))?;
    let args = &s[..=close];

    // Build types-only version by stripping the trailing identifier
    // from each comma-separated argument at every nesting depth.
    let types_only = strip_param_names(args);
    Ok((args.to_string(), types_only))
}

/// Strip parameter names from a type signature like `(address foo, uint256 bar)`
/// → `(address,uint256)`. Recurses into nested parentheses.
fn strip_param_names(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut depth = 0;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '(' => {
                if depth == 0 {
                    out.push('(');
                    start = i + 1;
                }
                depth += 1;
                i += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let inner = &s[start..i];
                    out.push_str(&strip_names_in_arg_list(inner));
                    out.push(')');
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    out
}

fn strip_names_in_arg_list(inner: &str) -> String {
    let parts = split_top_args(inner);
    let mut out = String::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&strip_one_arg(p.trim()));
    }
    out
}

fn strip_one_arg(arg: &str) -> String {
    if arg.starts_with('(') {
        // Nested tuple: keep parens, recurse into body, then drop the
        // trailing identifier (and any `[]` array suffix on it).
        let close = find_matching_paren(arg.as_bytes(), 0).unwrap();
        let inner = &arg[1..close];
        let after = arg[close + 1..].trim();
        // `after` may have an array suffix like `[]` before the name.
        let array_suffix = collect_array_suffix(after);
        let mut s = String::new();
        s.push('(');
        s.push_str(&strip_names_in_arg_list(inner));
        s.push(')');
        s.push_str(array_suffix);
        s
    } else {
        // Type can be `address`, `uint256`, `uint256[]`, `bytes32`, etc.
        // Drop any trailing identifier preceded by whitespace.
        let mut ty_end = arg.len();
        for (i, ch) in arg.char_indices() {
            if ch.is_whitespace() {
                ty_end = i;
                break;
            }
        }
        arg[..ty_end].to_string()
    }
}

fn collect_array_suffix(after_close: &str) -> &str {
    let trimmed = after_close.trim_start();
    // Look for `[...]` immediately following.
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b'[' {
        // Find matching ]
        let mut depth = 1;
        i += 1;
        while i < bytes.len() && depth > 0 {
            if bytes[i] == b'[' {
                depth += 1;
            } else if bytes[i] == b']' {
                depth -= 1;
            }
            i += 1;
        }
    }
    &trimmed[..i]
}

fn find_matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

fn split_top_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(s[start..].to_string());
    }
    out
}

fn first_ident_or_empty(s: &str) -> &str {
    let s = s.trim_start();
    let mut end = 0;
    for (i, c) in s.char_indices() {
        if c.is_ascii_alphanumeric() || c == '_' {
            end = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[..end]
}

fn last_ident(s: &str) -> &str {
    // Walk from the end, skipping `[]` suffixes, to find the trailing
    // identifier. If the entire string is a type (no name), return "".
    let s = s.trim();
    // Drop trailing array suffix(es).
    let bytes = s.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b']' {
        let mut depth = 1;
        end -= 1;
        while end > 0 && depth > 0 {
            end -= 1;
            if bytes[end] == b']' {
                depth += 1;
            } else if bytes[end] == b'[' {
                depth -= 1;
            }
        }
    }
    let cut = &s[..end].trim_end();
    let start = cut
        .rfind(|c: char| c.is_whitespace())
        .map(|p| p + 1)
        .unwrap_or(0);
    let candidate = &cut[start..];
    // If candidate is a known Solidity type prefix, treat as no-name.
    if candidate.is_empty() || candidate.starts_with(|c: char| c.is_ascii_digit()) {
        return "";
    }
    candidate
}

/// Compile a single ERC-7730 path string into the on-device opcode
/// sequence (without the leading length prefix; caller adds that).
/// ABI static head width of a type, in 32-byte words. `Dynamic` for
/// `bytes` / `string` / dynamic arrays / tuples containing a dynamic
/// member — their head slot holds only a 32-byte offset; the value lives
/// in the tail and is NOT readable from the static head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadWidth {
    Words(u32),
    Dynamic,
}

/// Words a type contributes to the ABI *head* (where the value — or, for
/// a dynamic type, its 32-byte tail offset — physically sits). A dynamic
/// predecessor still occupies exactly one head word, so summing this over
/// preceding siblings yields the correct head-word index of a later
/// static field.
fn head_slot_words(ty: &str) -> Result<u32, String> {
    Ok(match static_head_words(ty)? {
        HeadWidth::Words(n) => n,
        HeadWidth::Dynamic => 1,
    })
}

/// Recursively compute a type's ABI static head width. The crux of the
/// walker slot-confusion fix: a fixed array `T[N]` occupies `N ×
/// width(T)` head words and a static tuple the sum of its members, so a
/// calldata path that crosses one must advance by the true width, not by
/// one logical ordinal.
fn static_head_words(ty: &str) -> Result<HeadWidth, String> {
    let ty = ty.trim();
    if ty.is_empty() {
        return Err("empty ABI type".to_string());
    }
    // Trailing array suffix (innermost-last in Solidity) — peel from the
    // right so `T[2][3]` = 3 outer elements of `T[2]`.
    if let Some(open) = find_last_array_open(ty) {
        let base = &ty[..open];
        let suffix = &ty[open..];
        return match parse_fixed_array_len(suffix)? {
            None => Ok(HeadWidth::Dynamic), // `[]` — dynamic array.
            Some(count) => match static_head_words(base)? {
                // Fixed array of a dynamic type is itself dynamic.
                HeadWidth::Dynamic => Ok(HeadWidth::Dynamic),
                HeadWidth::Words(w) => Ok(HeadWidth::Words(w.saturating_mul(count))),
            },
        };
    }
    // Tuple.
    if ty.starts_with('(') {
        let close = find_matching_paren(ty.as_bytes(), 0)
            .ok_or_else(|| format!("unbalanced tuple type `{ty}`"))?;
        if close != ty.len() - 1 {
            return Err(format!("malformed tuple type `{ty}`"));
        }
        let mut total = 0u32;
        for member in split_top_args(&ty[1..close]) {
            let member = member.trim();
            if member.is_empty() {
                continue;
            }
            match static_head_words(member)? {
                HeadWidth::Dynamic => return Ok(HeadWidth::Dynamic),
                HeadWidth::Words(w) => total = total.saturating_add(w),
            }
        }
        return Ok(HeadWidth::Words(total));
    }
    // Elementary type.
    if ty == "bytes" || ty == "string" {
        return Ok(HeadWidth::Dynamic);
    }
    match elementary_static_words(ty) {
        Some(w) => Ok(HeadWidth::Words(w)),
        None => Err(format!("unknown / unsupported ABI type `{ty}`")),
    }
}

/// Head words of an elementary (non-array, non-tuple) static type, or
/// `None` if `ty` is not a recognised single-word static type. `bytes` /
/// `string` are handled by the caller as dynamic.
fn elementary_static_words(ty: &str) -> Option<u32> {
    if ty == "address" || ty == "bool" || ty == "function" {
        return Some(1);
    }
    if let Some(rest) = ty.strip_prefix("uint").or_else(|| ty.strip_prefix("int")) {
        // `uint`/`int` (== 256) or `uintN`/`intN`, N a multiple of 8 ≤ 256.
        return if rest.is_empty() || rest.bytes().all(|b| b.is_ascii_digit()) {
            Some(1)
        } else {
            None
        };
    }
    if let Some(rest) = ty.strip_prefix("bytes") {
        // `bytes1..32` is static one-word; bare `bytes` was handled above.
        return if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            Some(1)
        } else {
            None
        };
    }
    None
}

/// Byte index of the `[` that opens the trailing array suffix of `ty`, or
/// `None` if `ty` does not end in an array suffix.
fn find_last_array_open(ty: &str) -> Option<usize> {
    let b = ty.as_bytes();
    if b.last() != Some(&b']') {
        return None;
    }
    let mut depth = 0i32;
    for i in (0..b.len()).rev() {
        match b[i] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse an array suffix `[N]` → `Some(N)`, `[]` → `None` (dynamic).
fn parse_fixed_array_len(suffix: &str) -> Result<Option<u32>, String> {
    let inner = suffix
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("bad array suffix `{suffix}`"))?
        .trim();
    if inner.is_empty() {
        return Ok(None);
    }
    inner
        .parse::<u32>()
        .map(Some)
        .map_err(|_| format!("bad fixed-array length in `{suffix}`"))
}

/// Compile a rendered-VALUE path (the field's own `path`). Array index / byte
/// slice ops are REFUSED here — showing one element/slice of a value hides the
/// rest (the array-tail-hiding WYSIWYS hazard). This is the load-bearing half of
/// the tokenPath-only-slice invariant: only [`compile_token_path`] may emit an
/// extraction op, so a slice can never reach a shown value.
fn compile_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<Vec<u8>, String> {
    compile_path_inner(path, context_kind, parsed, false)
}

/// Compile a `tokenPath` (a `tokenAmount`'s token-IDENTIFICATION address).
/// Unlike [`compile_path`] this MAY end in a single byte-slice / array-index
/// extraction op (`params.path.[0:20]`, `path.[-1]`) resolving the token address
/// packed inside a dynamic swap leg. The 20 bytes feed only an ERC-20 decimals/
/// symbol lookup — never a shown address — so a wrong extraction degrades an
/// amount to raw + `! raw, dec=?` (audit M-4), never a wrong recipient. See the
/// device resolver `render::resolve::resolve_token_address`.
fn compile_token_path(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
) -> Result<Vec<u8>, String> {
    compile_path_inner(path, context_kind, parsed, true)
}

fn compile_path_inner(
    path: &str,
    context_kind: u8,
    parsed: &ParsedFormatKey,
    is_token_path: bool,
) -> Result<Vec<u8>, String> {
    let path = path.trim();
    if path.is_empty() {
        return Err("empty path".to_string());
    }

    // 1. Determine root.
    let (root, rest) = if let Some(r) = path.strip_prefix('#') {
        (PATHOP_ROOT_STRUCT, r.trim_start_matches('.'))
    } else if let Some(r) = path.strip_prefix('@') {
        (PATHOP_ROOT_CONTAINER, r.trim_start_matches('.'))
    } else if let Some(r) = path.strip_prefix('$') {
        (PATHOP_ROOT_METADATA, r.trim_start_matches('.'))
    } else {
        // Default root: structured (calldata for contract context;
        // typed-data message for EIP-712 — both addressed by name
        // through the same opcode).
        (PATHOP_ROOT_STRUCT, path)
    };

    let mut out = Vec::with_capacity(8);
    out.push(root);

    // 2a. Contract-calldata structured paths emit *ABI head-word slots*
    //     (width-aware), not logical ordinals. This is the fix for the
    //     walker slot-confusion forgery: with logical ordinals a field
    //     preceded by a multi-word static type (fixed array / non-leading
    //     static tuple) resolved to the wrong calldata word, so the
    //     trusted display showed one value while the contract executed on
    //     another. See `compile_structured_contract_path` +
    //     `docs/security/VULN-erc7730-walker-slot-confusion.md`.
    if root == PATHOP_ROOT_STRUCT && context_kind == CTX_CONTRACT {
        compile_structured_contract_path(&tokenize_path(rest)?, parsed, &mut out, is_token_path)?;
        return Ok(out);
    }

    // 2b. Container (`@`) / metadata (`$`) roots, and EIP-712 message
    //     roots, keep the existing encoding: container/metadata field
    //     names resolve to keccak-prefix discriminators the on-device
    //     envelope resolver matches, and EIP-712 `encodeData` lays out
    //     every member as exactly one 32-byte word so the logical ordinal
    //     IS the word slot. Do NOT apply ABI widths here.
    let mut cur_top: Option<&str> = None;
    for seg in tokenize_path(rest)? {
        match seg {
            PathSeg::Name(name) => {
                let idx = resolve_field_index(parsed, cur_top, name)?;
                out.push(PATHOP_FIELD_IDX);
                out.extend_from_slice(&idx.to_be_bytes());
                cur_top = Some(name);
            }
            // Array ops have no meaning on the `@`/`$` envelope roots or in
            // EIP-712 `encodeData` (every member is exactly one word, no
            // dynamic tail). Refuse them here so a hazardous descriptor is
            // never EMITTED — making the device-side `render_array` decline
            // (which it does anyway) a SECOND line of defence, not the only
            // one. (The contract-calldata `#` root handles `[]` via the gated
            // `compile_array_all_path`.)
            PathSeg::ArrayIdx(_)
            | PathSeg::ArrayLast
            | PathSeg::ArrayAll
            | PathSeg::ArraySlice(_, _)
            | PathSeg::ArraySliceLast(_) => {
                return Err(
                    "array op (`[i]`/`[-1]`/`[]`/slice) is only supported as `<arg>.[]` on a \
                     contract-calldata (`#`) dynamic array — not on `@`/`$` envelope roots or \
                     EIP-712 typed-data members"
                        .to_string(),
                )
            }
        }
    }
    Ok(out)
}

/// Compile a contract-calldata `#.<field>[.<member>]` path into
/// `FieldIdx` ops whose **summed** args equal the field's ABI head-word
/// index. Each emitted `FieldIdx` is the head-word offset of the named
/// field among its siblings (top level, then optionally one static-tuple
/// level); the on-device walker sums them and reads that word.
///
/// Refuses — at build time, so a hazardous descriptor can never be pinned
/// — any path that:
///   * uses array indexing / slices (a dynamic-tail op the static-head
///     walker cannot follow);
///   * descends into a dynamic tuple (members live in the tail);
///   * terminates on a non-single-word type (dynamic, or a multi-word
///     array/tuple the renderer would misread as one 32-byte word);
///   * names a field absent from the function signature.
fn compile_structured_contract_path(
    segs: &[PathSeg<'_>],
    parsed: &ParsedFormatKey,
    out: &mut Vec<u8>,
    is_token_path: bool,
) -> Result<(), String> {
    // A trailing `[]` (ArrayAll) renders EVERY element of a top-level dynamic
    // array — the only array op the renderer supports. Single-index `[i]` /
    // `[-1]` / slices stay refused below: showing one element hides the rest
    // (the array-tail-hiding WYSIWYS hazard). See the dynamic-array-walker
    // design doc for the safety argument.
    if matches!(segs.last(), Some(PathSeg::ArrayAll)) {
        return compile_array_all_path(&segs[..segs.len() - 1], parsed, out);
    }

    // tokenPath ONLY: a trailing extraction op (`[i]` / `[-1]` / `[a:b]` /
    // `[-N:]`) pulls a token IDENTIFICATION address out of a dynamic swap leg
    // (packed `bytes path`, or an `address[]`). For a rendered VALUE path this
    // is refused — the names loop below hits its `_ => reject` arm — which is
    // the load-bearing half of the tokenPath-only-slice invariant.
    if is_token_path {
        if let Some(last) = segs.last() {
            if matches!(
                last,
                PathSeg::ArrayIdx(_)
                    | PathSeg::ArrayLast
                    | PathSeg::ArraySlice(_, _)
                    | PathSeg::ArraySliceLast(_)
            ) {
                return compile_token_path_extraction(&segs[..segs.len() - 1], last, parsed, out);
            }
        }
    }

    let mut names: Vec<&str> = Vec::with_capacity(segs.len());
    for seg in segs {
        match seg {
            PathSeg::Name(n) => names.push(n),
            _ => {
                return Err(
                    "contract calldata path uses array index/slice — unsupported \
                     (dynamic-tail access; only `<arg>.[]` render-all of a sole \
                      dynamic array is supported)"
                        .to_string(),
                )
            }
        }
    }
    if names.is_empty() {
        return Err("contract calldata path names no field".to_string());
    }
    if names.len() > 2 {
        return Err(format!(
            "contract calldata path `{}` descends {} levels; only top-level and \
             one static-tuple level are supported",
            names.join("."),
            names.len()
        ));
    }

    let mut level_names: &[String] = &parsed.top_names;
    let mut level_types: &[String] = &parsed.top_types;
    for (depth, &name) in names.iter().enumerate() {
        let terminal = depth == names.len() - 1;
        let pos = level_names
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| format!("path field `{name}` is not in the function signature"))?;

        // Head-word offset of this field among its preceding siblings.
        let mut slot: u32 = 0;
        for ty in &level_types[..pos] {
            slot = slot.saturating_add(head_slot_words(ty)?);
        }
        let arg: u16 = slot
            .try_into()
            .map_err(|_| format!("head slot {slot} for `{name}` overflows u16"))?;
        out.push(PATHOP_FIELD_IDX);
        out.extend_from_slice(&arg.to_be_bytes());

        let this_ty = &level_types[pos];
        if terminal {
            match static_head_words(this_ty)? {
                HeadWidth::Words(1) => {}
                HeadWidth::Words(n) => {
                    return Err(format!(
                        "path field `{name}` has static type `{this_ty}` spanning {n} words; \
                         the trusted renderer reads a single 32-byte word — refusing to pin a \
                         descriptor that would display only part of it"
                    ))
                }
                HeadWidth::Dynamic => {
                    // C1: a dynamic `bytes`/`string` leaf. Its head slot holds an
                    // ABI offset word; emit FollowOffset so the device follows it
                    // to the length-prefixed blob in the tail (reading the SAME
                    // position the contract decodes). Dynamic ARRAYS are rendered
                    // via the `<arg>.[]` (`compile_array_all_path`) route, not
                    // here; a bare dynamic tuple is not a displayable leaf.
                    let t = this_ty.trim();
                    if t == "bytes" || t == "string" {
                        out.push(PATHOP_FOLLOW_OFFSET);
                    } else {
                        return Err(format!(
                            "path field `{name}` is dynamic (`{this_ty}`) and not a `bytes`/`string` \
                             leaf; dynamic arrays render via `<arg>.[]`, dynamic tuples are not a leaf"
                        ));
                    }
                }
            }
        } else {
            // Descend into a tuple. A STATIC tuple inlines its members in the
            // head, so the member's `FieldIdx` simply sums onto the tuple's head
            // slot (no FollowOffset — the legacy behaviour). C2: a DYNAMIC tuple
            // (one with a dynamic member) places its data in the tail; emit
            // `FollowOffset` after the tuple's head-slot `FieldIdx` so the device
            // jumps to the tuple's data region and reads the member relative to
            // it — the same position the contract's decoder uses.
            if static_head_words(this_ty)? == HeadWidth::Dynamic {
                out.push(PATHOP_FOLLOW_OFFSET);
            }
            let inner = parsed.inner_types.get(name).ok_or_else(|| {
                format!("path descends into `{name}`, which is not a parsed tuple argument")
            })?;
            level_names = parsed
                .inner_names
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            level_types = inner.as_slice();
        }
    }
    Ok(())
}

/// Compile a `tokenPath` that ends in an extraction op, resolving a token
/// address packed inside a dynamic swap leg. `name_segs` navigates to the
/// dynamic container (all `Name`s, ≤ 2 levels, same width-aware head-slot walk
/// as a normal path); `extract` is its terminal `[i]` / `[-1]` / `[a:b]` /
/// `[-N:]` op. Emits `FieldIdx… + FollowOffset + <extraction op>`.
///
/// Type discipline (build-time — a hazardous descriptor never compiles):
///   * `[a:b]` / `[-N:]` require the container to be dynamic `bytes`/`string`
///     and the slice width to be **exactly 20** (an address). Uniswap
///     `params.path.[0:20]` (input token) / `[-20:]` (output token). This
///     rejects paraswap's 32-byte word slices (`#.data.[292:324]`).
///   * `[i]` / `[-1]` require a dynamic `address[]` (element read as an
///     address). Uniswap V2 `swapExactTokensForTokens` `path.[0]` / `[-1]`.
/// The device resolver (`render::resolve::resolve_token_address`) re-validates
/// every bound at runtime and degrades any failure to raw-amount.
fn compile_token_path_extraction(
    name_segs: &[PathSeg<'_>],
    extract: &PathSeg<'_>,
    parsed: &ParsedFormatKey,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    const ADDR_SLICE_LEN: u32 = 20;

    let mut names: Vec<&str> = Vec::with_capacity(name_segs.len());
    for seg in name_segs {
        match seg {
            PathSeg::Name(n) => names.push(n),
            _ => {
                return Err(
                    "tokenPath extraction op (`[i]`/`[-1]`/slice) must be the terminal segment"
                        .to_string(),
                )
            }
        }
    }
    if names.is_empty() {
        return Err("tokenPath extraction names no field".to_string());
    }
    if names.len() > 2 {
        return Err(format!(
            "tokenPath `{}` descends {} levels; only top-level and one tuple level are supported",
            names.join("."),
            names.len()
        ));
    }

    let mut level_names: &[String] = &parsed.top_names;
    let mut level_types: &[String] = &parsed.top_types;
    for (depth, &name) in names.iter().enumerate() {
        let terminal = depth == names.len() - 1;
        let pos = level_names
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| format!("tokenPath field `{name}` is not in the function signature"))?;
        let mut slot: u32 = 0;
        for ty in &level_types[..pos] {
            slot = slot.saturating_add(head_slot_words(ty)?);
        }
        let arg: u16 = slot
            .try_into()
            .map_err(|_| format!("head slot {slot} for `{name}` overflows u16"))?;
        out.push(PATHOP_FIELD_IDX);
        out.extend_from_slice(&arg.to_be_bytes());

        let this_ty = level_types[pos].trim();
        if !terminal {
            // Descend a tuple (dynamic tuple → FollowOffset), same as the value path.
            if static_head_words(this_ty)? == HeadWidth::Dynamic {
                out.push(PATHOP_FOLLOW_OFFSET);
            }
            let inner = parsed.inner_types.get(name).ok_or_else(|| {
                format!("tokenPath descends into `{name}`, which is not a parsed tuple argument")
            })?;
            level_names = parsed
                .inner_names
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            level_types = inner.as_slice();
            continue;
        }

        // Terminal: the container the extraction reads. Must be dynamic; follow
        // its head-slot offset to the tail region, then emit the extraction op.
        match extract {
            PathSeg::ArraySlice(_, _) | PathSeg::ArraySliceLast(_) => {
                if this_ty != "bytes" && this_ty != "string" {
                    return Err(format!(
                        "tokenPath byte-slice needs a dynamic `bytes`/`string` container, got `{this_ty}`"
                    ));
                }
                let (start, from_end) = match extract {
                    PathSeg::ArraySlice(a, b) => {
                        let len = b.checked_sub(*a).filter(|l| *l > 0).ok_or_else(|| {
                            format!("tokenPath slice `[{a}:{b}]` is empty or reversed")
                        })?;
                        if len != ADDR_SLICE_LEN {
                            return Err(format!(
                                "tokenPath slice `[{a}:{b}]` is {len} bytes; only a 20-byte address \
                                 slice is accepted (packed-path token id)"
                            ));
                        }
                        (*a, false)
                    }
                    PathSeg::ArraySliceLast(n) => {
                        if *n != ADDR_SLICE_LEN {
                            return Err(format!(
                                "tokenPath tail slice `[-{n}:]` is {n} bytes; only a 20-byte address \
                                 slice is accepted"
                            ));
                        }
                        (0u32, true)
                    }
                    _ => unreachable!(),
                };
                let start_u16: u16 = start
                    .try_into()
                    .map_err(|_| format!("tokenPath slice start {start} overflows u16"))?;
                out.push(PATHOP_FOLLOW_OFFSET);
                out.push(PATHOP_ARRAY_SLICE);
                out.extend_from_slice(&start_u16.to_be_bytes());
                out.extend_from_slice(&(ADDR_SLICE_LEN as u16).to_be_bytes());
                out.push(u8::from(from_end));
            }
            PathSeg::ArrayIdx(_) | PathSeg::ArrayLast => {
                // Dynamic `address[]` — element read as a 32-byte word, low 20 =
                // address. Reject fixed-length arrays and non-address elements.
                let open = find_last_array_open(this_ty).ok_or_else(|| {
                    format!("tokenPath index needs a dynamic `address[]`, got `{this_ty}`")
                })?;
                if parse_fixed_array_len(&this_ty[open..])?.is_some() {
                    return Err(format!(
                        "tokenPath index needs a DYNAMIC array (`T[]`), got fixed `{this_ty}`"
                    ));
                }
                let base = this_ty[..open].trim();
                if base != "address" {
                    return Err(format!(
                        "tokenPath index element is `{base}`, not `address` — refusing to read a \
                         non-address word as a token id"
                    ));
                }
                out.push(PATHOP_FOLLOW_OFFSET);
                match extract {
                    PathSeg::ArrayIdx(i) => {
                        let i_u16: u16 = (*i)
                            .try_into()
                            .map_err(|_| format!("tokenPath index {i} overflows u16"))?;
                        out.push(PATHOP_ARRAY_IDX);
                        out.extend_from_slice(&i_u16.to_be_bytes());
                    }
                    PathSeg::ArrayLast => out.push(PATHOP_ARRAY_LAST),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!("extract is one of the four op variants"),
        }
    }
    Ok(())
}

/// Compile a `<arg>.[]` path that renders EVERY element of a top-level
/// dynamic array of static primitives. Emits `FieldIdx(offset-word-slot) +
/// ArrayAll`. Refuses unless the array is a top-level `T[]` (T a static
/// primitive) AND the SOLE dynamic argument of the function — the on-device
/// renderer then enforces EXACT tail placement (offset == head-end, array ==
/// the whole tail), which is what makes following the dynamic tail WYSIWYS-
/// safe without a full ABI walk. Single-index `[i]` / `[-1]` / slices stay
/// refused (they would hide the array's other elements).
fn compile_array_all_path(
    name_segs: &[PathSeg<'_>],
    parsed: &ParsedFormatKey,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    // The element selector applies to a single TOP-LEVEL argument only.
    let name = match name_segs {
        [PathSeg::Name(n)] => *n,
        _ => {
            return Err(
                "array `[]` path must be a single top-level argument (e.g. `amounts.[]`)"
                    .to_string(),
            )
        }
    };
    let pos = parsed
        .top_names
        .iter()
        .position(|n| n == name)
        .ok_or_else(|| format!("array `[]` path field `{name}` is not in the function signature"))?;
    let this_ty = &parsed.top_types[pos];
    if dynamic_array_static_elem(this_ty).is_none() {
        return Err(format!(
            "array `[]` path field `{name}` (`{this_ty}`) must be a dynamic array of a static \
             primitive (uintN/intN/address/bool/bytesN); nested / dynamic / tuple element arrays \
             are unsupported"
        ));
    }
    // The array's own offset word lives in the static head (its slot is
    // computed below). If it is the SOLE dynamic arg the device uses the
    // maximally-pinned exact-placement resolver; with ≥2 dynamic args the array
    // is only one tail object, so we emit a FollowOffset marker (below) that
    // routes the device to the relaxed `resolve_array_multi` (still WYSIWYS: the
    // offset word is at the array's signature-fixed slot).
    let dyn_count = parsed
        .top_types
        .iter()
        .filter(|t| matches!(static_head_words(t), Ok(HeadWidth::Dynamic)))
        .count();
    if dyn_count == 0 {
        // Unreachable: `dynamic_array_static_elem` already proved the array is a
        // dynamic `T[]`. Defensive.
        return Err("array `[]` path on a function with no dynamic argument".to_string());
    }
    // Offset-word slot = sum of preceding args' head widths (the array's one
    // offset word lives here, in the static head).
    let mut slot: u32 = 0;
    for ty in &parsed.top_types[..pos] {
        slot = slot.saturating_add(head_slot_words(ty)?);
    }
    let arg: u16 = slot
        .try_into()
        .map_err(|_| format!("head slot {slot} for `{name}` overflows u16"))?;
    out.push(PATHOP_FIELD_IDX);
    out.extend_from_slice(&arg.to_be_bytes());
    if dyn_count > 1 {
        // Multi-dynamic: route the device to the relaxed placement resolver.
        out.push(PATHOP_FOLLOW_OFFSET);
    }
    out.push(PATHOP_ARRAY_ALL);
    Ok(())
}

/// `Some(elem_type)` iff `ty` is a dynamic array `T[]` whose element `T` is a
/// static primitive (one 32-byte word, not a tuple or nested array).
fn dynamic_array_static_elem(ty: &str) -> Option<&str> {
    let ty = ty.trim();
    let base = ty.strip_suffix("[]")?;
    if base.is_empty() || base.starts_with('(') || base.contains('[') {
        return None; // tuple element or nested array
    }
    match static_head_words(base) {
        Ok(HeadWidth::Words(1)) => Some(base),
        _ => None,
    }
}

/// Total ABI static head width of a format, in 32-byte words — the number
/// of head words the on-device renderer must see before it walks any
/// field. For contract calldata this is the sum of every top-level
/// argument's head width (dynamic args contribute their one offset word);
/// for EIP-712 `encodeData` every top-level member is exactly one word.
/// The device truncates the body to this many words so an out-of-head
/// slot (a malformed descriptor's read into the dynamic tail) is rejected
/// rather than silently rendered.
fn format_static_head_words(context_kind: u8, parsed: &ParsedFormatKey) -> Result<u16, String> {
    let words: u32 = if context_kind == CTX_CONTRACT {
        let mut total = 0u32;
        for ty in &parsed.top_types {
            total = total.saturating_add(head_slot_words(ty)?);
        }
        total
    } else {
        parsed.top_names.len() as u32
    };
    u16::try_from(words).map_err(|_| format!("static head {words} words overflows u16"))
}

/// Map a name segment to a 2-byte BE field-index opcode arg. For the
/// first name after the root we look it up in `parsed.top_names`;
/// subsequent names use `parsed.inner_names[prev_top]`. If the name
/// isn't found in the parsed format key (e.g. a nested struct we
/// didn't parse), we encode the name's hash as a fall-back so Phase 5
/// can resolve it via the runtime ABI shape table.
fn resolve_field_index(
    parsed: &ParsedFormatKey,
    cur_top: Option<&str>,
    name: &str,
) -> Result<u16, String> {
    let names: &[String] = if let Some(top) = cur_top {
        parsed
            .inner_names
            .get(top)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    } else {
        &parsed.top_names
    };
    if let Some(pos) = names.iter().position(|n| n == name) {
        return u16::try_from(pos).map_err(|_| format!("field index {pos} > u16::MAX"));
    }
    // Fall-back: ABI hash. Compress to 16-bit so it fits the slot.
    // Phase 5 walker resolves this via runtime introspection — for
    // Phase 2 we just need to round-trip parse.
    let h = keccak256(name.as_bytes());
    Ok(u16::from_be_bytes([h[0], h[1]]))
}

enum PathSeg<'a> {
    Name(&'a str),
    // Array index / slice ops. For a rendered VALUE path these are still
    // REFUSED (single-index / slice would hide an array's other elements — the
    // array-tail-hiding WYSIWYS hazard). They are accepted ONLY as the terminal
    // op of a `tokenPath` (token IDENTIFICATION, not a shown value) — see
    // `compile_structured_contract_path`'s `is_token_path` branch.
    ArrayIdx(u32),        // `[i]`   — element i of a `T[]`
    ArrayLast,            // `[-1]`  — last element of a `T[]`
    ArrayAll,             // `[]`    — render every element (value path)
    ArraySlice(u32, u32), // `[a:b]` — byte slice `[a, b)` of a dynamic `bytes`
    ArraySliceLast(u32),  // `[-N:]` — last N bytes of a dynamic `bytes`
}

fn tokenize_path(rest: &str) -> Result<Vec<PathSeg<'_>>, String> {
    let mut out = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
            }
            b'[' => {
                // Find matching ].
                let close = bytes[i..]
                    .iter()
                    .position(|&b| b == b']')
                    .ok_or_else(|| format!("unmatched '[' in path `{rest}`"))?;
                let body = &rest[i + 1..i + close];
                let body_trim = body.trim();
                if body_trim.is_empty() {
                    out.push(PathSeg::ArrayAll);
                } else if body_trim == "-1" || body_trim == "last" {
                    out.push(PathSeg::ArrayLast);
                } else if let Some((a, b)) = body_trim.split_once(':') {
                    let a = a.trim();
                    let b = b.trim();
                    if let Some(neg) = a.strip_prefix('-') {
                        // `[-N:]` — last N bytes of a dynamic `bytes` (the tail
                        // must be open; `[-N:M]` is not a shape any descriptor uses).
                        if !b.is_empty() {
                            return Err(format!(
                                "negative-start slice `[{body_trim}]` must be open-ended (`[-N:]`)"
                            ));
                        }
                        let n: u32 = neg
                            .parse()
                            .map_err(|_| format!("slice tail count `{neg}` not u32"))?;
                        out.push(PathSeg::ArraySliceLast(n));
                    } else {
                        let a: u32 = a.parse().map_err(|_| format!("slice start `{a}` not u32"))?;
                        let b: u32 = b.parse().map_err(|_| format!("slice end `{b}` not u32"))?;
                        out.push(PathSeg::ArraySlice(a, b));
                    }
                } else if let Ok(n) = body_trim.parse::<u32>() {
                    out.push(PathSeg::ArrayIdx(n));
                } else {
                    return Err(format!(
                        "unrecognized array segment `[{body_trim}]` in `{rest}`"
                    ));
                }
                i += close + 1;
            }
            b if (b.is_ascii_alphanumeric() || b == b'_') => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                {
                    i += 1;
                }
                out.push(PathSeg::Name(&rest[start..i]));
            }
            other => {
                return Err(format!(
                    "unexpected byte 0x{:02x} ({:?}) in path `{rest}`",
                    other, other as char
                ))
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// IR builder.
// ─────────────────────────────────────────────────────────────────────

fn build_ir(
    context_kind: u8,
    chain_id: u64,
    contract: [u8; 20],
    domain_separator: &[u8; 32],
    ctx: &CompileCtx,
    pool: &[u8],
    formats: &[u8],
) -> Result<Vec<u8>, String> {
    let pool_len = pool.len();
    let formats_len = formats.len();
    if pool_len > u16::MAX as usize {
        return Err(format!("pool_len {pool_len} > u16::MAX"));
    }
    if formats_len > u16::MAX as usize {
        return Err(format!("formats_len {formats_len} > u16::MAX"));
    }
    let metadata_off = HEADER_LEN as u16;
    let formats_off = (HEADER_LEN + pool_len) as u16;

    let mut buf = vec![0u8; HEADER_LEN];
    buf[0] = SCHEMA_VER;
    buf[1] = context_kind;
    buf[2..10].copy_from_slice(&chain_id.to_be_bytes());
    buf[10..30].copy_from_slice(&contract);
    buf[30..62].copy_from_slice(&ctx.descriptor_hash);
    buf[62..94].copy_from_slice(domain_separator);

    // Owner + contract_name: NUL-padded, ≤ 15 + NUL.
    write_padded_ascii(&mut buf[94..94 + OWNER_FIELD_LEN], &ctx.owner)?;
    write_padded_ascii(
        &mut buf[110..110 + CONTRACT_NAME_FIELD_LEN],
        &ctx.contract_name,
    )?;

    buf[126..128].copy_from_slice(&metadata_off.to_be_bytes());
    buf[128..130].copy_from_slice(&formats_off.to_be_bytes());
    buf[130..132].copy_from_slice(&(pool_len as u16).to_be_bytes());
    buf[132..134].copy_from_slice(&(formats_len as u16).to_be_bytes());

    buf.extend_from_slice(pool);
    buf.extend_from_slice(formats);

    Ok(buf)
}

fn write_padded_ascii(slot: &mut [u8], s: &str) -> Result<(), String> {
    let bytes = s.as_bytes();
    if bytes.len() >= slot.len() {
        return Err(format!(
            "ASCII field too long ({} >= {} including NUL)",
            bytes.len(),
            slot.len()
        ));
    }
    if !bytes.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return Err(format!("ASCII field has non-printable byte(s): {s:?}"));
    }
    slot.fill(0);
    slot[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Enum tables.
// ─────────────────────────────────────────────────────────────────────

fn encode_enum_table(table: &serde_json::Value) -> Result<Vec<u8>, String> {
    let map = table
        .as_object()
        .ok_or_else(|| "enum table must be an object".to_string())?;
    if map.len() > 255 {
        return Err(format!("enum has {} entries > 255", map.len()));
    }
    let mut entries: Vec<(u64, String)> = Vec::with_capacity(map.len());
    for (k, v) in map {
        let key: u64 = k
            .parse()
            .map_err(|_| format!("enum key `{k}` must be a non-negative integer"))?;
        let val = v
            .as_str()
            .ok_or_else(|| format!("enum value for `{k}` must be a string"))?;
        let val = clean_ascii_truncated(val, 254);
        if val.is_empty() {
            return Err(format!("enum value for `{k}` is empty / non-printable"));
        }
        entries.push((key, val));
    }
    entries.sort_by_key(|(k, _)| *k);

    let mut out = Vec::with_capacity(1 + entries.len() * 12);
    out.push(entries.len() as u8);
    for (k, v) in entries {
        out.extend_from_slice(&k.to_be_bytes()); // 8 B BE
        out.push(v.len() as u8);
        out.extend_from_slice(v.as_bytes());
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// EIP-712 domain separator.
// ─────────────────────────────────────────────────────────────────────

fn compute_domain_separator(d: &Eip712Domain) -> Result<[u8; 32], String> {
    // EIP-712 §`EIP712Domain` typehash is computed from only the
    // *present* fields. We assemble the field list and the
    // corresponding encoded values, then keccak both.
    let mut typestr = String::from("EIP712Domain(");
    let mut encoded: Vec<u8> = Vec::new();
    let mut first = true;
    let push_field = |t: &str, name: &str, encoded_value: [u8; 32], typestr: &mut String, encoded: &mut Vec<u8>, first: &mut bool| {
        if !*first {
            typestr.push(',');
        }
        typestr.push_str(t);
        typestr.push(' ');
        typestr.push_str(name);
        encoded.extend_from_slice(&encoded_value);
        *first = false;
    };
    if let Some(name) = &d.name {
        push_field("string", "name", keccak256(name.as_bytes()), &mut typestr, &mut encoded, &mut first);
    }
    if let Some(version) = &d.version {
        push_field("string", "version", keccak256(version.as_bytes()), &mut typestr, &mut encoded, &mut first);
    }
    if let Some(cid) = d.chain_id {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&cid.to_be_bytes());
        push_field("uint256", "chainId", buf, &mut typestr, &mut encoded, &mut first);
    }
    if let Some(addr) = &d.verifying_contract {
        let a = parse_address(addr)?;
        let mut buf = [0u8; 32];
        buf[12..32].copy_from_slice(&a);
        push_field("address", "verifyingContract", buf, &mut typestr, &mut encoded, &mut first);
    }
    if let Some(salt) = &d.salt {
        let s = parse_hex32(salt)?;
        push_field("bytes32", "salt", s, &mut typestr, &mut encoded, &mut first);
    }
    typestr.push(')');

    let typehash = keccak256(typestr.as_bytes());
    let mut preimage = Vec::with_capacity(32 + encoded.len());
    preimage.extend_from_slice(&typehash);
    preimage.extend_from_slice(&encoded);
    Ok(keccak256(&preimage))
}

// ─────────────────────────────────────────────────────────────────────
// JCS canonicalization (RFC 8785 subset — integers / strings only).
// ─────────────────────────────────────────────────────────────────────

fn jcs_canonicalize(v: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut out = String::with_capacity(256);
    jcs_render(v, &mut out)?;
    Ok(out.into_bytes())
}

fn jcs_render(v: &serde_json::Value, out: &mut String) -> Result<(), String> {
    match v {
        serde_json::Value::Null => {
            out.push_str("null");
            Ok(())
        }
        serde_json::Value::Bool(b) => {
            out.push_str(if *b { "true" } else { "false" });
            Ok(())
        }
        serde_json::Value::Number(n) => {
            // JCS requires shortest IEEE-754 form for floats. Real
            // ERC-7730 descriptors use only integers and ASCII-coded
            // string values; allow integers + reject finite floats.
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                return Err(format!(
                    "JCS: float numbers not supported in Phase 2 (got {n})"
                ));
            }
            Ok(())
        }
        serde_json::Value::String(s) => {
            jcs_render_string(s, out);
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_render(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        serde_json::Value::Object(map) => {
            // RFC 8785 sorts object keys by UTF-16 code units. For pure
            // ASCII keys this is identical to byte order, which is what
            // our seed corpus uses. We collect & sort by UTF-16 in case
            // a future descriptor ships non-ASCII keys.
            let mut keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
            keys.sort_by(|a, b| utf16_codeunit_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_render_string(k, out);
                out.push(':');
                jcs_render(&map[*k], out)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

fn jcs_render_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn utf16_codeunit_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let ai = a.encode_utf16();
    let bi = b.encode_utf16();
    ai.cmp(bi)
}

// ─────────────────────────────────────────────────────────────────────
// Policy enforcement.
// ─────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────
// `includes` resolution (Phase 5, item 2).
//
// The ERC-7730 registry uses `"includes"` references so the
// templated permit / EIP-712 common entries don't duplicate the
// boilerplate. We resolve these against a local mirror of the
// registry passed in via `--registry-root <dir>`. Three forms are
// supported:
//
//   1. Relative file path           — `./templates/permit.json`
//   2. Registry-relative path       — `registry/templates/permit.json`
//   3. GitHub URL                   — `https://github.com/ethereum/
//      clear-signing-erc7730-registry/blob/<sha>/templates/permit.json`
//      → strip the host + branch prefix and resolve as a relative
//      path under `registry_root`.
//
// Any include that resolves OUTSIDE `registry_root` (e.g. via `..`
// escapes) is rejected — this prevents a hostile descriptor from
// pulling in arbitrary files on the host build machine.
// ─────────────────────────────────────────────────────────────────────

fn resolve_include_path(
    registry_root: &Path,
    descriptor_path: &Path,
    include_ref: &str,
) -> Result<PathBuf, String> {
    let registry_root = registry_root.canonicalize().map_err(|e| {
        format!("canonicalize registry-root {}: {e}", registry_root.display())
    })?;

    let candidate: PathBuf = if let Some(stripped) =
        include_ref.strip_prefix("https://github.com/")
    {
        // `<owner>/<repo>/blob/<ref>/<path>` or
        // `<owner>/<repo>/raw/<ref>/<path>` — strip the first four
        // segments to get the path inside the registry.
        let parts: Vec<&str> = stripped.splitn(5, '/').collect();
        if parts.len() < 5 {
            return Err(format!(
                "github URL include `{include_ref}` has too few path segments"
            ));
        }
        registry_root.join(parts[4])
    } else {
        // Any other reference (`./foo.json`, `../foo.json`, or a bare
        // sibling filename like `common-AggregationRouterV4.json` — the
        // registry's actual convention) resolves against the descriptor's
        // OWN directory. The outside-registry-root guard below still bounds
        // the result, so a `../../../etc/passwd` include is refused.
        descriptor_path
            .parent()
            .ok_or_else(|| "descriptor path has no parent".to_string())?
            .join(include_ref)
    };

    let canonical = candidate.canonicalize().map_err(|e| {
        format!("canonicalize include {}: {e}", candidate.display())
    })?;
    if !canonical.starts_with(&registry_root) {
        return Err(format!(
            "include `{include_ref}` resolves to {} which is outside registry-root {} — refusing",
            canonical.display(),
            registry_root.display()
        ));
    }
    Ok(canonical)
}

/// Deep-merge `over` on top of `base`. For object-typed leaves the
/// keys merge recursively; for any non-object leaf `over` wins. This
/// matches the semantics that the ERC-7730 registry expects from its
/// `includes` resolution (the descriptor is the "over" document; the
/// template is the "base").
fn merge_descriptors(
    base: serde_json::Value,
    over: serde_json::Value,
) -> serde_json::Value {
    use serde_json::Value;
    match (base, over) {
        (Value::Object(mut b), Value::Object(o)) => {
            for (k, v) in o {
                let merged = if let Some(existing) = b.remove(&k) {
                    merge_descriptors(existing, v)
                } else {
                    v
                };
                b.insert(k, merged);
            }
            Value::Object(b)
        }
        // For non-objects, `over` wins.
        (_, over) => over,
    }
}

/// LEGACY / dev-mode-only attestation gate. This models an OUTDATED shape —
/// an embedded `attestations` array with an `attester` string — that predates
/// the finalized ERC-8176. Real ERC-8176 attestations are NOT embedded in the
/// descriptor: they are Ethereum Attestation Service (EAS) records (mainnet
/// schema 0xe023ee…, `bytes32 descriptorHash`) that an auditor signs, keyed by
/// `descriptorHash = keccak256(JCS(descriptor))` (our `erc8176_hash`). So this
/// identity-only check is inert against the real corpus (no descriptor carries
/// such an array) and stays gated behind `allow_unattested_dev_descriptors`.
///
/// The production-flip readiness is measured OUT OF BAND by
/// `tools/erc8176_eas_coverage.py` (`make erc8176-coverage`), which computes
/// each descriptor's `erc8176_hash` and queries EAS for real attestations. As
/// of 2026-07 the EAS schema has ~0 real attestations, so the flip is blocked
/// on the attestation ecosystem populating — NOT on this code. See
/// `docs/erc8176-attestation-status.md`.
fn enforce_policy(json: &serde_json::Value, policy: &Policy) -> Result<(), String> {
    if policy.allow_unattested_dev_descriptors {
        return Ok(());
    }
    let atts = json.get("attestations").and_then(|v| v.as_array());
    let atts = atts.ok_or_else(|| {
        "policy requires attestations but descriptor has none".to_string()
    })?;
    let mut hits: Vec<String> = Vec::new();
    for a in atts {
        if let Some(s) = a.get("attester").and_then(|v| v.as_str()) {
            let s_norm = s.to_ascii_lowercase();
            if policy
                .trusted_attesters
                .iter()
                .any(|t| t.to_ascii_lowercase() == s_norm)
                && !hits.iter().any(|h| h == &s_norm)
            {
                hits.push(s_norm);
            }
        }
    }
    if hits.len() < policy.min_attesters {
        return Err(format!(
            "policy: only {} trusted attestation(s); need {}",
            hits.len(),
            policy.min_attesters
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Review file (vendor-readable summary).
// ─────────────────────────────────────────────────────────────────────

/// Short display name for a `FormatOp` discriminant, for the review file's
/// per-field breakdown. Mirrors `pqsigner_erc7730::ir::FormatOp` — kept as a
/// flat table (not `FormatOp::try_from(..).map(|o| format!("{o:?}"))`) so an
/// unknown/out-of-range op renders visibly as `?<hex>` rather than eliding.
fn fmt_op_name(op: u8) -> &'static str {
    match op {
        0x01 => "raw",
        0x02 => "amount",
        0x03 => "tokenAmount",
        0x04 => "nftName",
        0x05 => "date",
        0x06 => "duration",
        0x07 => "addressName",
        0x08 => "enum",
        0x09 => "unit",
        0x0A => "calldata",
        0x0B => "chainId",
        0x0C => "tokenTicker",
        0x0D => "interopAddressName",
        0x0E => "encrypted",
        _ => "?unknown",
    }
}

/// Bucket a tolerant-build skip reason into a coarse category, for the
/// committed review file's skip roll-up. Mirrors (and corrects) the xtask
/// scanner's `skip_category`: the completeness lint is checked **before**
/// the attestation/policy bucket, because a completeness message that names
/// a `visible:"never"` / hidden field would otherwise be mis-bucketed as an
/// attestation-policy skip (review finding, xtask/src/main.rs:1417).
fn review_skip_category(msg: &str) -> &'static str {
    let m = msg;
    if m.contains("duplicate (chain_id=") {
        "duplicate leaf (deduped)"
    } else if m.contains("no compilable formats") {
        // Umbrella reason when EVERY format in a descriptor failed; the
        // per-format blocker is not surfaced today (see the note in
        // `compile_descriptor`). Bucketed separately so it doesn't swamp
        // "other" and so a resync that flips a whole descriptor dead is
        // visible.
        "whole-descriptor dead (all formats blocked)"
    } else if m.contains("completeness")
        || m.contains("not covered")
        || m.contains("must cover")
        || m.contains("uncovered")
        || m.contains("hidden")
        || m.contains("visible")
    {
        "completeness lint (un-displayed field)"
    } else if m.contains("array index") || m.contains("array slice") || m.contains("ArrayIdx") {
        "array-path (needs value-path slice/index resolver)"
    } else if m.contains("dynamic tuple") || m.contains("is dynamic") || m.contains("calldata tail") {
        "dynamic-ABI-type (needs walker)"
    } else if m.contains("spanning") && m.contains("words") {
        "multi-word static field (>32B)"
    } else if m.contains("includes") {
        "includes-unresolved"
    } else if m.contains("unresolved $ref") || m.contains("definition") {
        "unresolved $ref / definition"
    } else if m.contains("nested calldata") || m.contains("encrypted") {
        "unsupported formatter (nested-calldata / encrypted)"
    } else if m.contains("nft") {
        "unsupported formatter (nft)"
    } else if m.contains("enum") {
        "enum issue"
    } else if m.contains("MAX_IR_LEN") || m.contains("exceeds") || m.contains("too large") || m.contains("too long") {
        "IR too large (>4KiB)"
    } else if m.contains("unconsumed") || m.contains("unknown key") || m.contains("unrecognized") {
        "unmodeled descriptor key"
    } else if m.contains("policy") || m.contains("attest") {
        "attestation policy"
    } else if m.starts_with("schema") || m.starts_with("parse") || m.contains("schema:") || m.contains("missing field") {
        "schema / parse"
    } else if m.contains("selector") || m.contains("signature") || m.contains("encodeType") || m.contains("primary") {
        "selector / type-signature"
    } else {
        "other"
    }
}

/// Decode one leaf's IR into a per-field breakdown (op + label) plus a count
/// of *degraded* fields — `raw`-op fields with an empty label, the signature
/// of a descriptor whose author-intended formatting was silently lost (e.g. a
/// dropped `$ref`; review finding 1.1). Returns `(lines, field_count,
/// degraded_count)`. Never panics: a parse failure yields a single visible
/// error line so the catalogue still reconciles.
fn review_field_breakdown(ir_bytes: &[u8]) -> (Vec<String>, usize, usize) {
    let mut lines = Vec::new();
    let mut n_fields = 0usize;
    let mut n_degraded = 0usize;
    let ir = match Erc7730Ir::parse(ir_bytes) {
        Ok(ir) => ir,
        Err(e) => {
            lines.push(format!("         · <IR PARSE ERROR: {e:?}>"));
            return (lines, 0, 0);
        }
    };
    for fmt in ir.format_iter() {
        let Ok(fmt) = fmt else {
            lines.push("         · <malformed format entry>".to_string());
            break;
        };
        for field in fmt.fields() {
            let Ok(field) = field else {
                lines.push("         · <malformed field entry>".to_string());
                break;
            };
            n_fields += 1;
            let label = String::from_utf8_lossy(field.label);
            let degraded = field.format_op == 0x01 && field.label.is_empty();
            if degraded {
                n_degraded += 1;
            }
            lines.push(format!(
                "         · [0x{}] op={:<12} label='{}'{}",
                hex::encode(fmt.selector),
                fmt_op_name(field.format_op),
                label,
                if degraded { "  <-- DEGRADED (raw, no label)" } else { "" },
            ));
        }
    }
    (lines, n_fields, n_degraded)
}

fn render_review(
    entries: &[Emitted],
    skips: &[SkipReport],
    policy: &Policy,
    root: &[u8; 32],
) -> String {
    let mut s = String::with_capacity(2048);
    s.push_str("# ERC-7730 descriptor catalogue\n");
    s.push_str("# Generated by `cargo run -p dbgen`. DO NOT EDIT BY HAND.\n");
    s.push_str("#\n");
    s.push_str("# Each row is one entry in the firmware-pinned Merkle tree at\n");
    s.push_str("# ERC7730_DESCRIPTORS_ROOT, followed by its per-field breakdown\n");
    s.push_str("# (op + label, decoded from the emitted IR — i.e. what actually\n");
    s.push_str("# RENDERS on-device, not what the JSON claims). A `degraded` count\n");
    s.push_str("# flags raw-op fields with no label: author-intended formatting\n");
    s.push_str("# that was silently lost. Auditors should reconcile every row\n");
    s.push_str("# against the source JSON and the upstream attestation chain.\n");
    s.push_str("# The trailing `## skips` section lists every descriptor the\n");
    s.push_str("# tolerant build dropped (compile failure or dedup), by reason.\n");
    s.push_str(&format!("# Root: 0x{}\n", hex::encode(root)));
    s.push_str(&format!(
        "# Policy: min_attesters={} allow_unattested_dev_descriptors={}\n",
        policy.min_attesters, policy.allow_unattested_dev_descriptors
    ));
    s.push_str(&format!("# Trusted attesters ({}):\n", policy.trusted_attesters.len()));
    for t in &policy.trusted_attesters {
        s.push_str(&format!("#   - {t}\n"));
    }
    if policy.allow_unattested_dev_descriptors {
        s.push_str("#\n");
        s.push_str("# WARNING: dev mode is on — attestations were NOT enforced.\n");
        s.push_str("# CI MUST reject production builds in this mode.\n");
    }
    s.push('\n');

    let mut total_degraded = 0usize;
    for e in entries {
        let ctx = if e.context_kind == CTX_CONTRACT {
            "contract"
        } else {
            "eip712"
        };
        let (field_lines, n_fields, n_degraded) = review_field_breakdown(&e.ir_bytes);
        total_degraded += n_degraded;
        s.push_str(&format!(
            "[{:04}] ctx={ctx} chain_id={} contract=0x{} \
             primary_type=0x{} descriptor_hash=0x{} erc8176_hash=0x{} ir_len={} \
             fields={} degraded={} source={}\n",
            e.leaf_index,
            e.chain_id,
            hex::encode(e.contract),
            hex::encode(e.primary_type_hash),
            hex::encode(e.descriptor_hash),
            hex::encode(e.erc8176_hash),
            e.ir_bytes.len(),
            n_fields,
            n_degraded,
            e.source.file_name().unwrap().to_string_lossy(),
        ));
        for line in field_lines {
            s.push_str(&line);
            s.push('\n');
        }
    }

    // ── Skip roll-up ─────────────────────────────────────────────────
    // Committed + drift-gated, so a resync that drops descriptors to
    // blind-sign shows up as a reviewable diff with reasons (finding 1.4).
    s.push_str("\n## skips (");
    s.push_str(&skips.len().to_string());
    s.push_str(" total)\n");
    if total_degraded > 0 {
        s.push_str(&format!(
            "## WARNING: {total_degraded} DEGRADED field(s) across accepted leaves \
             (raw-op, no label — silently lost formatting; see finding 1.1)\n"
        ));
    }
    if !skips.is_empty() {
        // Category counts (sorted by category name for stable diffs).
        let mut by_cat: BTreeMap<&'static str, usize> = BTreeMap::new();
        for sk in skips {
            *by_cat.entry(review_skip_category(&sk.reason)).or_insert(0) += 1;
        }
        s.push_str("#\n# by category:\n");
        for (cat, n) in &by_cat {
            s.push_str(&format!("#   {n:>4}  {cat}\n"));
        }
        s.push('\n');
        // Per-skip detail, sorted by source path for stable diffs.
        let mut sorted: Vec<&SkipReport> = skips.iter().collect();
        sorted.sort_by(|a, b| a.source.cmp(&b.source));
        for sk in sorted {
            s.push_str(&format!(
                "{} — {}\n",
                sk.source.display(),
                sk.reason.replace('\n', " "),
            ));
        }
    }
    s
}

// ─────────────────────────────────────────────────────────────────────
// Helpers.
// ─────────────────────────────────────────────────────────────────────

fn push_tlv(out: &mut Vec<u8>, kind: u8, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_POOL_TLV_PAYLOAD {
        return Err(format!(
            "param TLV 0x{:02x}: payload too long ({} > {})",
            kind,
            payload.len(),
            MAX_POOL_TLV_PAYLOAD
        ));
    }
    out.push(kind);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    Ok(())
}

fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return Err(format!("address must be 40 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() > 64 {
        return Err(format!("hex32 too long: {}", s.len()));
    }
    let padded = format!("{:0>64}", s);
    let bytes = hex::decode(&padded).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_address_or_const(s: &str, ctx: &CompileCtx) -> Result<[u8; 20], String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        let hex = v
            .as_str()
            .ok_or_else(|| format!("constant `{c}` is not a string"))?;
        return parse_address(hex);
    }
    parse_address(s)
}

fn resolve_u256_or_const(s: &str, ctx: &CompileCtx) -> Result<[u8; 32], String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        let hex = v
            .as_str()
            .ok_or_else(|| format!("constant `{c}` is not a string"))?;
        return parse_hex32(hex);
    }
    parse_hex32(s)
}

/// Resolve a constant-annotation field's `value`: either a literal string,
/// or a `$.metadata.constants.X` reference into the descriptor's metadata
/// constants (the ERC-4626 / ERC-7540 vault templates reference
/// `vaultTicker` / `underlyingTicker` this way).
fn resolve_string_or_const(s: &str, ctx: &CompileCtx) -> Result<String, String> {
    if let Some(c) = s.strip_prefix("$.metadata.constants.") {
        let v = ctx
            .constants
            .get(c)
            .ok_or_else(|| format!("constant `{c}` not defined"))?;
        return v
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("constant `{c}` is not a string"));
    }
    Ok(s.to_string())
}

/// Transliterate non-printable / non-ASCII bytes to '?', then trim to
/// `max_len` bytes. The on-device IR header forbids non-printable
/// bytes outright; the host pipeline replaces them rather than
/// rejecting wholesale, which mirrors the spec's "transliterate or
/// reject" guidance (see handoff §"Common gotchas" #3).
fn clean_ascii_truncated(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max_len));
    for c in s.chars() {
        if out.len() >= max_len {
            break;
        }
        let mut buf = [0u8; 4];
        let enc = c.encode_utf8(&mut buf);
        if enc.len() == 1 && (0x20..0x7f).contains(&(enc.as_bytes()[0])) {
            out.push_str(enc);
        } else {
            out.push('?');
        }
    }
    out
}

fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// Keep clippy happy about the `node_hash` import — we use it
// indirectly via `MerkleTree::build`.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = node_hash;
}

// ─────────────────────────────────────────────────────────────────────
// Tests.
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_param_names_basic() {
        assert_eq!(
            strip_param_names("(address _to, uint256 _value)"),
            "(address,uint256)"
        );
    }

    // The v2 array gate hinges on `path_matches_member` correctly resolving the
    // `.[]` whole-array wildcard (advisor review target): a per-element field
    // `M.[].addr` must COVER the element address `M.[].addr` (else PermitBatch/
    // Rarible false-refuse), while an INDEXED/sliced segment must NOT match (it
    // names one element the gate can't reason about → a hidden-address risk).
    #[test]
    fn path_matches_member_array_wildcard() {
        // v2 whole-array wildcard: a per-element field covers the element member.
        assert!(path_matches_member("details.[].token", "details.[].token"));
        assert!(path_matches_member("creators.[].account", "creators.[].account"));
        // Different member under the same array → NOT covered.
        assert!(!path_matches_member("details.[].amount", "details.[].token"));
        // A non-array field must NOT cover an array member, and vice-versa.
        assert!(!path_matches_member("details.token", "details.[].token"));
        assert!(!path_matches_member("details.[].token", "details.token"));
        // INDEXED / sliced segments name a specific element → rejected (the
        // security-critical case: they must never satisfy per-element coverage).
        assert!(!path_matches_member("details.[0].token", "details.[].token"));
        assert!(!path_matches_member("details.[-1].token", "details.[].token"));
        assert!(!path_matches_member("details.[0:20].token", "details.[].token"));
        // v1 (non-array) matching is unchanged.
        assert!(path_matches_member("details.token", "details.token"));
        assert!(!path_matches_member("details.token", "details.amount"));
        assert!(path_matches_member("#.details.token", "details.token"));
        assert!(!path_matches_member("@.to", "details.token"));
    }

    #[test]
    fn strip_nested_child_v1_and_v2() {
        // v1 (non-array): `top.child`.
        assert_eq!(strip_nested_child("details.amount", "details", false), Some("amount"));
        // v2 (array): `top.[].child`.
        assert_eq!(strip_nested_child("details.[].amount", "details", true), Some("amount"));
        assert_eq!(strip_nested_child("creators.[].account", "creators", true), Some("account"));
        // Mismatched array-ness → None.
        assert_eq!(strip_nested_child("details.[].amount", "details", false), None);
        assert_eq!(strip_nested_child("details.amount", "details", true), None);
        // Deeper (`a.b.c`) or indexed → None (v3 / unsupported).
        assert_eq!(strip_nested_child("details.[].a.b", "details", true), None);
        assert_eq!(strip_nested_child("details.[0].amount", "details", true), None);
        assert_eq!(strip_nested_child("other.amount", "details", false), None);
    }

    #[test]
    fn strip_param_names_nested_tuple() {
        assert_eq!(
            strip_param_names("((address tokenIn,address tokenOut,uint24 fee) params)"),
            "((address,address,uint24))"
        );
    }

    #[test]
    fn parse_format_key_simple() {
        let p = parse_format_key("transfer(address _to, uint256 _value)").unwrap();
        assert_eq!(p.types_signature, "transfer(address,uint256)");
        assert_eq!(p.top_names, vec!["_to".to_string(), "_value".to_string()]);
    }

    #[test]
    fn parse_format_key_nested_tuple() {
        let p = parse_format_key(
            "exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
        )
        .unwrap();
        assert_eq!(
            p.types_signature,
            "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        );
        assert_eq!(p.top_names, vec!["params".to_string()]);
        let inner = &p.inner_names["params"];
        assert_eq!(inner.len(), 7);
        assert_eq!(inner[0], "tokenIn");
        assert_eq!(inner[4], "amountIn");
    }

    // ── Duplicate-member-name WYSIWYS guard (adversarial-review finding 2026-07-01) ──

    /// A crafted descriptor with a DUPLICATE tuple-member name is refused. The
    /// Morpho `supply` witness: inner member #1 (`collateralToken`) renamed to a
    /// DUPLICATE of member #0 (`loanToken`). Types are identical (both `address`)
    /// so `strip_param_names` yields the real selector and the descriptor would
    /// dispatch on genuine `supply()` calls — but the name-keyed gates would let
    /// the single `loanToken` field cover BOTH slots, hiding the effect-bearing
    /// `collateralToken` (part of the Morpho market id) behind a trusted clear-sign.
    #[test]
    fn parse_format_key_rejects_duplicate_tuple_member_name() {
        let err = parse_format_key(
            "supply((address loanToken, address loanToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, bytes data)",
        )
        .expect_err("duplicate tuple-member name must be refused");
        assert!(err.contains("duplicate member name"), "err names the cause: {err}");
        assert!(err.contains("loanToken"), "err names the dup: {err}");
        // The real, distinct-named Morpho signature still parses.
        assert!(parse_format_key(
            "supply((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, bytes data)",
        )
        .is_ok());
    }

    /// Symmetric guard: a duplicate TOP-LEVEL argument name is refused too.
    #[test]
    fn parse_format_key_rejects_duplicate_top_level_name() {
        let err = parse_format_key("f(address to, uint256 to)")
            .expect_err("duplicate top-level name must be refused");
        assert!(err.contains("duplicate top-level argument name"), "{err}");
    }

    /// Proves the parse_format_key guard is LOAD-BEARING: if a duplicate-named
    /// tuple ever reached the gates, BOTH `check_contract_field_completeness` and
    /// `check_field_visibility` (name-keyed, position-blind) would WRONGLY accept
    /// it — one `loanToken` field "covers" both inner slots, so the aliased
    /// address at slot 1 is deemed both covered and shown. The gates are
    /// insufficient alone; rejecting duplicates in the parser is what closes it.
    #[test]
    fn dup_member_gates_are_insufficient_without_parse_guard() {
        // Hand-build the ParsedFormatKey the OLD parser produced (dup `loanToken`
        // at inner slots 0 AND 1), bypassing the new guard.
        let s = |x: &str| x.to_string();
        let mut inner_names = BTreeMap::new();
        inner_names.insert(
            s("marketParams"),
            vec![s("loanToken"), s("loanToken"), s("oracle"), s("irm"), s("lltv")],
        );
        let mut inner_types = BTreeMap::new();
        inner_types.insert(
            s("marketParams"),
            vec![s("address"), s("address"), s("address"), s("address"), s("uint256")],
        );
        let parsed = ParsedFormatKey {
            types_signature: s("supply((address,address,address,address,uint256),uint256,uint256,address,bytes)"),
            top_names: vec![s("marketParams"), s("assets"), s("shares"), s("onBehalf"), s("data")],
            top_types: vec![
                s("(address,address,address,address,uint256)"),
                s("uint256"),
                s("uint256"),
                s("address"),
                s("bytes"),
            ],
            inner_names,
            inner_types,
            struct_defs: BTreeMap::new(), // contract-context: no EIP-712 struct defs
        };
        // The malicious descriptor shows one loanToken field but NO collateralToken.
        let fmt = fmt_from_fields(
            r##"[
              {"path":"#.marketParams.loanToken","label":"Loan","format":"addressName"},
              {"path":"#.marketParams.oracle","label":"Oracle","format":"addressName"},
              {"path":"#.marketParams.irm","label":"Irm","format":"addressName"},
              {"path":"#.marketParams.lltv","label":"Lltv","format":"raw"},
              {"path":"#.assets","label":"Assets","format":"raw"},
              {"path":"#.shares","label":"Shares","format":"raw"},
              {"path":"#.onBehalf","label":"On Behalf","format":"addressName"},
              {"path":"#.data","label":"Data","format":"raw"}
            ]"##,
        );
        // BOTH gates WRONGLY accept — the hole the parse guard closes.
        assert!(
            check_contract_field_completeness("supply(...)", &fmt, &parsed).is_ok(),
            "completeness is name-keyed → one loanToken field covers both slots"
        );
        assert!(
            check_field_visibility("supply(...)", &fmt, &parsed, CTX_CONTRACT, &[]).is_ok(),
            "visibility rule 2 is name-keyed → aliased address deemed shown"
        );
    }

    #[test]
    fn compile_path_simple() {
        let p = parse_format_key("transfer(address _to, uint256 _value)").unwrap();
        let prog = compile_path("#._value", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 1);
    }

    #[test]
    fn compile_path_nested() {
        let p = parse_format_key(
            "exactInputSingle((address tokenIn,address tokenOut,uint24 fee,address recipient,uint256 amountIn,uint256 amountOutMinimum,uint160 sqrtPriceLimitX96) params)",
        )
        .unwrap();
        let prog = compile_path("params.amountIn", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 0); // "params"
        assert_eq!(prog[4], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[5], prog[6]]), 4); // "amountIn"
    }

    // ── Walker slot-confusion fix (head-word slots, not logical ordinals) ──

    /// Sum the `FieldIdx` args of a compiled `#`-rooted program — the
    /// absolute ABI head-word slot the on-device walker resolves to.
    fn head_slot_of(prog: &[u8]) -> u32 {
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        let mut p = 1usize;
        let mut sum = 0u32;
        while p < prog.len() {
            assert_eq!(prog[p], PATHOP_FIELD_IDX, "only FieldIdx ops expected");
            sum += u16::from_be_bytes([prog[p + 1], prog[p + 2]]) as u32;
            p += 3;
        }
        sum
    }

    #[test]
    fn static_head_words_elementary_and_arrays() {
        assert_eq!(static_head_words("address").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("uint256").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("uint8").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("int").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("bytes32").unwrap(), HeadWidth::Words(1));
        assert_eq!(static_head_words("bool").unwrap(), HeadWidth::Words(1));
        // Fixed arrays multiply; arrays-of-arrays compound.
        assert_eq!(static_head_words("uint256[3]").unwrap(), HeadWidth::Words(3));
        assert_eq!(static_head_words("address[2]").unwrap(), HeadWidth::Words(2));
        assert_eq!(static_head_words("uint256[2][3]").unwrap(), HeadWidth::Words(6));
        // Static tuple = sum of members.
        assert_eq!(
            static_head_words("(uint256,address,bytes32)").unwrap(),
            HeadWidth::Words(3)
        );
        assert_eq!(
            static_head_words("((uint256,uint256),address)").unwrap(),
            HeadWidth::Words(3)
        );
        // Dynamic types and anything containing them.
        assert_eq!(static_head_words("bytes").unwrap(), HeadWidth::Dynamic);
        assert_eq!(static_head_words("string").unwrap(), HeadWidth::Dynamic);
        assert_eq!(static_head_words("uint256[]").unwrap(), HeadWidth::Dynamic);
        assert_eq!(static_head_words("(uint256,bytes)").unwrap(), HeadWidth::Dynamic);
        assert!(static_head_words("notatype").is_err());
    }

    #[test]
    fn compile_path_multiword_array_predecessor() {
        // The canonical forgery shape: `to` is preceded by a 3-word
        // static array, so its head-word slot is 3 (not logical ordinal 1).
        let p = parse_format_key("f(uint256[3] arr, address to)").unwrap();
        let prog = compile_path("#.to", CTX_CONTRACT, &p).unwrap();
        assert_eq!(head_slot_of(&prog), 3, "to lands at ABI head word 3");
    }

    #[test]
    fn compile_path_non_leading_static_tuple() {
        // `to` follows a 2-word static tuple → head word 2; and a member
        // inside the tuple resolves to its absolute head word.
        let p =
            parse_format_key("h((uint256 x, uint256 y) s, address to)").unwrap();
        assert_eq!(head_slot_of(&compile_path("#.to", CTX_CONTRACT, &p).unwrap()), 2);
        assert_eq!(head_slot_of(&compile_path("#.s.y", CTX_CONTRACT, &p).unwrap()), 1);
        assert_eq!(head_slot_of(&compile_path("#.s.x", CTX_CONTRACT, &p).unwrap()), 0);
    }

    // ── Nested field-GROUP flattening (Morpho Blue `marketParams`) ──

    /// The Morpho Blue `marketParams` GROUP (a static tuple of 4 addresses +
    /// lltv) flattens to per-member combined paths, and every field — including
    /// the scalars/addresses that land AFTER the 5-word tuple — compiles to its
    /// absolute ABI head-word slot. This is the exact non-leading-static-tuple
    /// slot-confusion case at 5-word width: `assets` MUST resolve to head word
    /// 5, not logical ordinal 1.
    #[test]
    fn flatten_morpho_static_tuple_group_slots() {
        let sig = "borrow((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, address receiver)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r##"[
              {"path":"#.marketParams","fields":[
                {"path":"loanToken","label":"Loan","format":"addressName"},
                {"path":"collateralToken","label":"Collat","format":"addressName"},
                {"path":"oracle","label":"Oracle","format":"addressName"},
                {"path":"irm","label":"Irm","format":"addressName"},
                {"path":"lltv","label":"Lltv","format":"raw"}
              ]},
              {"path":"#.assets","label":"Assets","format":"raw"},
              {"path":"#.shares","label":"Shares","format":"raw"},
              {"path":"#.onBehalf","label":"On Behalf","format":"addressName"},
              {"path":"#.receiver","label":"Receiver","format":"addressName"}
            ]"##,
        );
        let flat = flatten_field_groups(&fmt.fields).expect("flatten ok");
        let paths: Vec<&str> = flat.iter().map(|f| f.path.as_deref().unwrap()).collect();
        assert_eq!(
            paths,
            vec![
                "#.marketParams.loanToken",
                "#.marketParams.collateralToken",
                "#.marketParams.oracle",
                "#.marketParams.irm",
                "#.marketParams.lltv",
                "#.assets",
                "#.shares",
                "#.onBehalf",
                "#.receiver",
            ],
            "group expands in place, preserving declaration order"
        );
        let slot = |p: &str| head_slot_of(&compile_path(p, CTX_CONTRACT, &parsed).unwrap());
        assert_eq!(slot("#.marketParams.loanToken"), 0);
        assert_eq!(slot("#.marketParams.collateralToken"), 1);
        assert_eq!(slot("#.marketParams.oracle"), 2);
        assert_eq!(slot("#.marketParams.irm"), 3);
        assert_eq!(slot("#.marketParams.lltv"), 4);
        assert_eq!(slot("#.assets"), 5, "assets lands AFTER the 5-word tuple");
        assert_eq!(slot("#.shares"), 6);
        assert_eq!(slot("#.onBehalf"), 7);
        assert_eq!(slot("#.receiver"), 8);
    }

    /// Morpho `supply(... marketParams, assets, shares, onBehalf, bytes data)`:
    /// the dynamic `bytes data` sits at head word 8 (after the 5-word tuple +
    /// three scalars). C1 emits `FieldIdx(8) + FollowOffset` so the device reads
    /// the SAME tail blob the contract decodes — the tuple-width accounting and
    /// the C1 follow must compose correctly.
    #[test]
    fn flatten_morpho_bytes_after_tuple_follows_offset() {
        let sig = "supply((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, bytes data)";
        let parsed = parse_format_key(sig).unwrap();
        let prog = compile_path("#.data", CTX_CONTRACT, &parsed).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(
            u16::from_be_bytes([prog[2], prog[3]]),
            8,
            "bytes `data` at head word 8 (5-word tuple + assets + shares + onBehalf)"
        );
        assert_eq!(prog[4], PATHOP_FOLLOW_OFFSET, "dynamic bytes → FollowOffset");
        assert_eq!(prog.len(), 5, "no trailing ops");
    }

    /// Flatten runs BEFORE the completeness + visibility gates (the ordering
    /// that makes the feature real): the flattened Morpho `borrow` fields cover
    /// every marketParams member and surface every address, so both gates pass.
    /// If the ORIGINAL (unflattened) `#.marketParams` group reached the gates,
    /// completeness would reject (`marketParams.loanToken` uncovered) and the
    /// format would blind-sign.
    #[test]
    fn flatten_morpho_borrow_passes_completeness_and_visibility() {
        let sig = "borrow((address loanToken, address collateralToken, address oracle, address irm, uint256 lltv) marketParams, uint256 assets, uint256 shares, address onBehalf, address receiver)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r##"[
              {"path":"#.marketParams","fields":[
                {"path":"loanToken","label":"Loan","format":"addressName"},
                {"path":"collateralToken","label":"Collat","format":"addressName"},
                {"path":"oracle","label":"Oracle","format":"addressName"},
                {"path":"irm","label":"Irm","format":"addressName"},
                {"path":"lltv","label":"Lltv","format":"raw"}
              ]},
              {"path":"#.assets","label":"Assets","format":"raw"},
              {"path":"#.shares","label":"Shares","format":"raw"},
              {"path":"#.onBehalf","label":"On Behalf","format":"addressName"},
              {"path":"#.receiver","label":"Receiver","format":"addressName"}
            ]"##,
        );
        let flat = Format {
            _id: None,
            intent: Some("Borrow".to_string()),
            fields: flatten_field_groups(&fmt.fields).unwrap(),
            _interpolated_intent: None,
            unknown: BTreeMap::new(),
        };
        check_contract_field_completeness(sig, &flat, &parsed)
            .expect("every marketParams member is covered after flatten");
        check_field_visibility(sig, &flat, &parsed, CTX_CONTRACT, &[])
            .expect("every address argument is shown after flatten");
    }

    /// Flatten is the identity on a flat (non-nested) field list — proves the
    /// feature is purely ADDITIVE: a descriptor without groups is byte-for-byte
    /// unchanged, so the corpus delta is exactly the nested-group additions.
    #[test]
    fn flatten_flat_fields_unchanged() {
        let fmt = fmt_from_fields(
            r##"[{"path":"#.to","label":"To","format":"addressName"},
                {"path":"#.amount","label":"Amt","format":"raw"}]"##,
        );
        let flat = flatten_field_groups(&fmt.fields).unwrap();
        let paths: Vec<Option<String>> = flat.iter().map(|f| f.path.clone()).collect();
        assert_eq!(
            paths,
            vec![Some("#.to".to_string()), Some("#.amount".to_string())]
        );
    }

    /// A GROUP anchored on a dynamic array-of-tuples flattens (syntactically) to
    /// `#.orders.[].maker`, but the width-aware compiler REFUSES it — a
    /// per-element tuple-member read is not a static-head access. The flatten
    /// smuggles nothing past the gate; the whole format drops to blind-sign.
    #[test]
    fn flatten_array_of_tuple_group_rejected_by_compiler() {
        // (1) Flatten is purely SYNTACTIC: a GROUP anchored on a dynamic array
        // `#.orders.[]` with a `maker` subfield flattens to the combined
        // per-element path `#.orders.[].maker`.
        let fmt = fmt_from_fields(
            r##"[{"path":"#.orders.[]","fields":[
                  {"path":"maker","label":"Maker","format":"addressName"},
                  {"path":"amount","label":"Amount","format":"raw"}
            ]}]"##,
        );
        let flat = flatten_field_groups(&fmt.fields).expect("flatten is syntactic");
        assert!(
            flat.iter()
                .any(|f| f.path.as_deref() == Some("#.orders.[].maker")),
            "flatten produced the combined per-element path"
        );
        // (2) ...but the width-aware compiler REFUSES an array op in the MIDDLE
        // of a path (a per-element tuple-member read is a dynamic-tail access,
        // not a static-head read), so the format drops to blind-sign — the
        // flatten smuggles nothing past the gate. (An array-of-tuple SIGNATURE
        // is additionally rejected earlier by `parse_format_key`; this pins the
        // compile-level defense that holds even for a parseable outer type.)
        let parsed = parse_format_key("fill(uint256[] orders)").unwrap();
        assert!(
            compile_path("#.orders.[].maker", CTX_CONTRACT, &parsed).is_err(),
            "array op mid-path (per-element member) must be refused by the compiler"
        );
    }

    /// A group with a `fields` sub-array but no anchoring `path` is refused
    /// (nothing for the members to be relative to) — fail-closed.
    #[test]
    fn flatten_group_without_path_rejected() {
        let fmt = fmt_from_fields(
            r#"[{"fields":[{"path":"x","label":"X","format":"raw"}]}]"#,
        );
        let err = flatten_field_groups(&fmt.fields).expect_err("group needs a path");
        assert!(err.contains("no `path`"), "error explains the anchor: {err}");
    }

    /// Pathologically deep group nesting is refused, not silently flattened —
    /// a host-stack-safety bound on hostile/malformed descriptors.
    #[test]
    fn flatten_depth_bound_enforced() {
        let mut inner = r#"{"path":"leaf","label":"L","format":"raw"}"#.to_string();
        for _ in 0..(MAX_FIELD_GROUP_DEPTH + 2) {
            inner = format!(r#"{{"path":"g","fields":[{inner}]}}"#);
        }
        let fmt = fmt_from_fields(&format!("[{inner}]"));
        let err = flatten_field_groups(&fmt.fields).expect_err("too-deep nest refused");
        assert!(
            err.contains("MAX_FIELD_GROUP_DEPTH"),
            "error cites the depth bound: {err}"
        );
    }

    #[test]
    fn compile_path_dynamic_bytes_ok_bare_array_rejected() {
        // C1 (FollowOffset resolver): a dynamic `bytes` / `string` field IS now
        // clear-signable — its value sits in the calldata tail and the device
        // follows the offset word to render it (celo `addStorageRoot(bytes url)`
        // / `send(string)`). Was a hard reject before C1.
        let p = parse_format_key("f(bytes data)").unwrap();
        assert!(
            compile_path("#.data", CTX_CONTRACT, &p).is_ok(),
            "C1: dynamic bytes field is clear-signable"
        );
        // A BARE whole dynamic array (no `.[]` render-all) is still rejected — an
        // array is not a single displayable word; use `<arg>.[]` to render its
        // elements (see `compile_array_all_gate`).
        let p = parse_format_key("f(uint256[] xs)").unwrap();
        assert!(
            compile_path("#.xs", CTX_CONTRACT, &p).is_err(),
            "bare whole-array target has no single-word rendering"
        );
    }

    #[test]
    fn compile_path_rejects_multiword_static_target() {
        // A field that is itself multi-word static can't be displayed as a
        // single 32-byte word — refuse rather than show part of it.
        let p = parse_format_key("f(uint256[2] pair, address to)").unwrap();
        assert!(compile_path("#.pair", CTX_CONTRACT, &p).is_err());
    }

    #[test]
    fn compile_path_rejects_array_index_and_unknown_name() {
        let p = parse_format_key("f(uint256[] xs, address to)").unwrap();
        assert!(compile_path("#.xs[0]", CTX_CONTRACT, &p).is_err(), "array index");
        assert!(compile_path("#.nope", CTX_CONTRACT, &p).is_err(), "unknown name");
    }

    // ── Tier B: tokenPath byte-slice / array-index (tokenPath-ONLY) ──────────
    #[test]
    fn token_path_slice_ops_are_tokenpath_only() {
        // The load-bearing invariant: a slice / index op compiles as a
        // `tokenPath` (token id inside a dynamic leg) but is REFUSED in a
        // rendered VALUE path — showing one element/slice of a value hides the
        // rest (array-tail-hiding WYSIWYS hazard) and for an address would be a
        // wrong recipient. This is exactly what keeps paraswap `pools.[-1]` /
        // `beneficiaryAndApproveFlag.[-20:]` (rendered ADDRESS values) declined
        // even after Tier B enabled slice parsing.
        let p = parse_format_key("exactInput(bytes path, uint256 amountIn)").unwrap();
        assert!(compile_token_path("path.[0:20]", CTX_CONTRACT, &p).is_ok(), "tokenPath [0:20]");
        assert!(compile_token_path("path.[-20:]", CTX_CONTRACT, &p).is_ok(), "tokenPath [-20:]");
        assert!(compile_path("path.[0:20]", CTX_CONTRACT, &p).is_err(), "VALUE slice refused");
        assert!(compile_path("path.[-20:]", CTX_CONTRACT, &p).is_err(), "VALUE tail slice refused");

        let a = parse_format_key("swap(uint256 amountIn, address[] path)").unwrap();
        assert!(compile_token_path("path.[0]", CTX_CONTRACT, &a).is_ok(), "tokenPath [0]");
        assert!(compile_token_path("path.[-1]", CTX_CONTRACT, &a).is_ok(), "tokenPath [-1]");
        assert!(compile_path("path.[0]", CTX_CONTRACT, &a).is_err(), "VALUE index refused");
        assert!(compile_path("path.[-1]", CTX_CONTRACT, &a).is_err(), "VALUE last refused");
    }

    #[test]
    fn token_path_slice_width_and_type_guards() {
        // Only a 20-byte ADDRESS slice — rejects paraswap's 32-byte word slices
        // (`#.data.[292:324]`) and 1inch's 4-byte timestamp tail (`goodUntil.[-4:]`).
        let b = parse_format_key("f(bytes data)").unwrap();
        assert!(compile_token_path("data.[0:20]", CTX_CONTRACT, &b).is_ok(), "20-byte slice ok");
        assert!(compile_token_path("data.[292:324]", CTX_CONTRACT, &b).is_err(), "32-byte word slice refused");
        assert!(compile_token_path("data.[0:16]", CTX_CONTRACT, &b).is_err(), "non-20 slice refused");
        assert!(compile_token_path("data.[-4:]", CTX_CONTRACT, &b).is_err(), "4-byte tail refused");

        // Container-type discipline: slice needs dynamic `bytes`, index needs
        // dynamic `address[]` (not a scalar, not `uint256[]`, not a fixed array).
        let s = parse_format_key("g(uint256 x)").unwrap();
        assert!(compile_token_path("x.[0:20]", CTX_CONTRACT, &s).is_err(), "slice on scalar refused");
        let u = parse_format_key("h(uint256[] xs)").unwrap();
        assert!(compile_token_path("xs.[0]", CTX_CONTRACT, &u).is_err(), "non-address element refused");
        let fx = parse_format_key("k(address[3] fixd)").unwrap();
        assert!(compile_token_path("fixd.[0]", CTX_CONTRACT, &fx).is_err(), "fixed array refused");
    }

    #[test]
    fn token_path_slice_emits_terminal_extraction_op() {
        let p = parse_format_key("exactInput(bytes path, uint256 amountIn)").unwrap();
        let prog = compile_token_path("path.[0:20]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert!(prog.contains(&PATHOP_FOLLOW_OFFSET), "FollowOffset into the bytes region");
        assert!(prog.contains(&PATHOP_ARRAY_SLICE), "ArraySlice op emitted");
        assert_eq!(*prog.last().unwrap(), 0x00, "[0:20] from_end flag = 0");
        let progl = compile_token_path("path.[-20:]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(*progl.last().unwrap(), 0x01, "[-20:] from_end flag = 1");

        let a = parse_format_key("swap(uint256 amountIn, address[] path)").unwrap();
        assert!(compile_token_path("path.[0]", CTX_CONTRACT, &a).unwrap().contains(&PATHOP_ARRAY_IDX));
        assert_eq!(
            *compile_token_path("path.[-1]", CTX_CONTRACT, &a).unwrap().last().unwrap(),
            PATHOP_ARRAY_LAST
        );
    }

    // Byte-exact compile→device round-trip on the FROZEN tokenPath wire format.
    // dbgen `compile_token_path` and the device `resolve::resolve_token_address`
    // are two halves of one on-chain-adjacent contract: any one-sided wire edit
    // (reorder ArraySlice start/len, flip from_end, change ArrayIdx width) is a
    // confirm-vs-execute desync. This test compiles the real shapes and resolves
    // the SAME bytes on the device side against a hand-built body, asserting the
    // extracted 20-byte address — so a one-sided edit fails here even if both the
    // dbgen-shape tests and the device unit tests still pass on their own.
    #[test]
    fn token_path_compile_device_round_trip() {
        use pqsigner_erc7730::render::resolve::resolve_token_address;

        fn word(bytes32: [u8; 32]) -> [u8; 32] {
            bytes32
        }
        fn u(n: u64) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            w
        }
        fn addr_word(a: [u8; 20]) -> [u8; 32] {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&a);
            w
        }
        // Resolve a compiled program (strip the RootStructured byte) on the device.
        fn resolve(prog: &[u8], body: &[u8]) -> [u8; 20] {
            assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
            resolve_token_address(&prog[1..], body).expect("device resolves the compiled program")
        }

        let t_in = [0x11u8; 20];
        let t_out = [0x22u8; 20];
        let t_mid = [0xABu8; 20];

        // exactInput: params (dynamic tuple) → path (dynamic bytes) → [0:20]/[-20:].
        let p = parse_format_key(
            "exactInput((bytes path, address recipient, uint256 amountIn, uint256 amountOutMinimum) params)",
        )
        .unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&u(32)); // [0]   offset to params tuple
        body.extend_from_slice(&u(128)); // [32]  offset to path (rel. to tuple start)
        body.extend_from_slice(&addr_word([0x33; 20])); // [64]  recipient
        body.extend_from_slice(&u(1)); // [96]  amountIn
        body.extend_from_slice(&u(2)); // [128] amountOutMinimum
        body.extend_from_slice(&u(43)); // [160] path len = 20+3+20
        let mut packed = Vec::new();
        packed.extend_from_slice(&t_in);
        packed.extend_from_slice(&[0x00, 0x0b, 0xb8]); // fee
        packed.extend_from_slice(&t_out);
        while packed.len() % 32 != 0 {
            packed.push(0);
        }
        body.extend_from_slice(&packed); // [192] packed path

        let prog_in = compile_token_path("params.path.[0:20]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(resolve(&prog_in, &body), t_in, "[0:20] → input token");
        let prog_out = compile_token_path("params.path.[-20:]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(resolve(&prog_out, &body), t_out, "[-20:] → output token");

        // swapExactTokensForTokens: address[] path → [0] / [-1] (3-hop).
        let s =
            parse_format_key("swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to)")
                .unwrap();
        let mut sbody = Vec::new();
        sbody.extend_from_slice(&u(1)); // [0]  amountIn
        sbody.extend_from_slice(&u(2)); // [32] amountOutMin
        sbody.extend_from_slice(&u(128)); // [64] offset to path array
        sbody.extend_from_slice(&addr_word([0x33; 20])); // [96] to
        sbody.extend_from_slice(&u(3)); // [128] count = 3
        sbody.extend_from_slice(&addr_word(t_in)); // [160] path[0]
        sbody.extend_from_slice(&addr_word(t_mid)); // [192] path[1]
        sbody.extend_from_slice(&addr_word(t_out)); // [224] path[2]

        let prog_first = compile_token_path("path.[0]", CTX_CONTRACT, &s).unwrap();
        assert_eq!(resolve(&prog_first, &sbody), t_in, "[0] → first element");
        let prog_last = compile_token_path("path.[-1]", CTX_CONTRACT, &s).unwrap();
        assert_eq!(resolve(&prog_last, &sbody), t_out, "[-1] → last element (3-hop, not middle)");

        // Static tokenPath (no extraction op): a plain `address` argument.
        let f = parse_format_key("g(address token)").unwrap();
        let gbody = word(addr_word(t_in));
        let prog_static = compile_token_path("token", CTX_CONTRACT, &f).unwrap();
        assert_eq!(resolve(&prog_static, &gbody), t_in, "static address word");
    }

    #[test]
    fn compile_array_all_gate() {
        // ACCEPT: `<arg>.[]` render-all on a SOLE top-level dynamic array of a
        // static primitive → FieldIdx(offset-slot) + ArrayAll.
        let p = parse_format_key("requestWithdrawals(uint256[] _amounts, address _owner)").unwrap();
        let prog = compile_path("_amounts.[]", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(prog[1], PATHOP_FIELD_IDX);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 0, "_amounts is arg 0");
        assert_eq!(prog[4], PATHOP_ARRAY_ALL);
        assert_eq!(prog.len(), 5, "Root + one FieldIdx + ArrayAll");

        // REFUSE: single-index / last (array-tail-hiding — would show a subset).
        assert!(compile_path("_amounts[0]", CTX_CONTRACT, &p).is_err(), "single index");
        assert!(compile_path("_amounts[-1]", CTX_CONTRACT, &p).is_err(), "last");

        // ACCEPT (C3): an array that is NOT the sole dynamic arg. The device's
        // `resolve_array_multi` relaxes the two exact-tail-placement equalities
        // to bounds (offset >= head_end, offset+32+count*32 <= len), so a
        // multi-dynamic array still renders every element from its
        // signature-fixed head slot (`batchTransfer(uint256[] a, address[] r)`).
        // dbgen emits a FollowOffset marker for this case; still WYSIWYS.
        let two_dyn = parse_format_key("f(uint256[] a, bytes b)").unwrap();
        assert!(compile_path("a.[]", CTX_CONTRACT, &two_dyn).is_ok(), "C3: multi-dynamic array");

        // REFUSE: dynamic element type (`string[]`) and nested array (`uint256[][]`).
        let dyn_elem = parse_format_key("f(string[] xs)").unwrap();
        assert!(compile_path("xs.[]", CTX_CONTRACT, &dyn_elem).is_err(), "dynamic element");
        let nested = parse_format_key("f(uint256[][] xs)").unwrap();
        assert!(compile_path("xs.[]", CTX_CONTRACT, &nested).is_err(), "nested array");

        // REFUSE: array op in EIP-712 / envelope context (gate-hardening — `[]`
        // is contract-calldata-only; EIP-712 encodeData has no dynamic tail).
        assert!(compile_path("xs.[]", CTX_EIP712, &dyn_elem).is_err(), "eip712 array");
        let any = parse_format_key("Order(uint256[] notes, address owner)").unwrap();
        assert!(compile_path("notes.[]", CTX_EIP712, &any).is_err(), "eip712 array (uint)");
    }

    #[test]
    fn per_format_tolerance_keeps_compilable_drops_unrenderable() {
        use serde_json::json;
        // `transfer(...)` compiles; the `swap` format's single-index array
        // path does NOT (single index is refused — array-tail-hiding).
        let display: Display = serde_json::from_value(json!({
            "formats": {
                "transfer(address to, uint256 value)": {
                    "intent": "Send",
                    "fields": [
                        { "path": "to", "label": "To", "format": "raw" },
                        { "path": "value", "label": "Amount", "format": "raw" }
                    ]
                },
                "swap(uint256[] amounts)": {
                    "intent": "Swap",
                    "fields": [ { "path": "amounts[0]", "label": "Amt", "format": "raw" } ]
                }
            }
        }))
        .unwrap();
        let mut ctx = CompileCtx {
            constants: serde_json::Map::new(),
            enums: serde_json::Map::new(),
            descriptor_hash: [0u8; 32],
            owner: String::new(),
            contract_name: String::new(),
            hidden_address_allow: Vec::new(),
        };
        // STRICT: the unrenderable `swap` fails the WHOLE descriptor.
        assert!(compile_formats(&display, CTX_CONTRACT, &mut ctx, false).is_err());
        // TOLERANT: keep the renderable `transfer`, drop `swap` → 1 format.
        let (buf, _pool) = compile_formats(&display, CTX_CONTRACT, &mut ctx, true).unwrap();
        assert_eq!(buf[0], 1, "exactly one surviving format (transfer)");
    }

    #[test]
    fn compile_path_dynamic_predecessor_still_resolves_static_target() {
        // A dynamic predecessor occupies exactly one head (offset) word, so
        // a later static field sits at a fixed head slot and is readable.
        let p = parse_format_key("f(bytes blob, address to)").unwrap();
        assert_eq!(head_slot_of(&compile_path("#.to", CTX_CONTRACT, &p).unwrap()), 1);
    }

    #[test]
    fn format_static_head_words_contract_and_eip712() {
        let p = parse_format_key("f(uint256[3] arr, address to)").unwrap();
        assert_eq!(format_static_head_words(CTX_CONTRACT, &p).unwrap(), 4);
        // EIP-712: every top-level member is one encodeData word.
        let p = parse_format_key("Order(address maker, uint256[3] nums, address taker)").unwrap();
        assert_eq!(format_static_head_words(CTX_EIP712, &p).unwrap(), 3);
    }

    #[test]
    fn eip712_path_keeps_logical_ordinal() {
        // EIP-712 `encodeData` is one word per member regardless of ABI
        // width, so the message-root path stays a logical ordinal — the
        // width-aware contract logic must NOT apply here.
        let p = parse_format_key("Order(address maker, uint256[3] nums, address taker)").unwrap();
        let prog = compile_path("#.taker", CTX_EIP712, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_STRUCT);
        assert_eq!(u16::from_be_bytes([prog[2], prog[3]]), 2, "ordinal 2, not width 4");
    }

    #[test]
    fn container_path_keeps_keccak_discriminator() {
        // `@.value` must still encode the keccak-prefix discriminator the
        // on-device envelope resolver matches — the width logic only
        // governs `#` calldata roots, and envelope field names (`value`,
        // `to`, …) are not calldata args here so the discriminator fires.
        let p = parse_format_key("deposit()").unwrap();
        let prog = compile_path("@.value", CTX_CONTRACT, &p).unwrap();
        assert_eq!(prog[0], PATHOP_ROOT_CONTAINER);
        let disc = u16::from_be_bytes([prog[2], prog[3]]);
        let h = keccak256(b"value");
        assert_eq!(disc, u16::from_be_bytes([h[0], h[1]]));
    }

    #[test]
    fn jcs_object_keys_sorted() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":2,"c":[1,2]}"#).unwrap();
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#"{"a":2,"b":1,"c":[1,2]}"#);
    }

    #[test]
    fn jcs_string_escapes() {
        let v: serde_json::Value = serde_json::Value::String("a\"b\\c\n".to_string());
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#""a\"b\\c\n""#);
    }

    #[test]
    fn jcs_array_in_doc_order() {
        let v: serde_json::Value =
            serde_json::from_str(r#"[3,1,2]"#).unwrap();
        let out = jcs_canonicalize(&v).unwrap();
        assert_eq!(out, br#"[3,1,2]"#);
    }

    /// ERC-8176 `descriptorHash` = keccak256(RFC-8785 JCS(descriptor)). Golden
    /// vectors whose keccak values were computed INDEPENDENTLY (foundry
    /// `cast keccak` over the canonical JCS string) — so this locks our JCS +
    /// keccak against a third-party implementation, which is what makes our hash
    /// byte-match what an auditor attests on EAS. (Additionally cross-validated
    /// end-to-end on a real registry descriptor: `ledgerquest/eip712-ledgerquest`
    /// → 0x16a312e2…acad… via both dbgen and python-JCS+`cast keccak`.)
    #[test]
    fn erc8176_hash_golden_vectors() {
        use pqsigner_tx_core::hash::keccak256;
        // Key sort (b→a becomes a,b), array order preserved, integers.
        let v: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":[1,"x"]}"#).unwrap();
        let jcs = jcs_canonicalize(&v).unwrap();
        assert_eq!(jcs, br#"{"a":[1,"x"],"b":2}"#);
        assert_eq!(
            hex::encode(keccak256(&jcs)),
            "6fc0cf5686e5292611ba7b595e551c0e49fe88c20fc60a5820e22acdb010beb1"
        );
        // String escaping: value a"b\c → "a\"b\\c".
        let v2: serde_json::Value = serde_json::from_str(r#"{"s":"a\"b\\c"}"#).unwrap();
        let jcs2 = jcs_canonicalize(&v2).unwrap();
        assert_eq!(jcs2, br#"{"s":"a\"b\\c"}"#);
        assert_eq!(
            hex::encode(keccak256(&jcs2)),
            "8cd0880e152d264b68eecb43ff71f6978922ea7234ca7b5fde387f68b744ee2a"
        );
    }

    #[test]
    fn build_db_seed_corpus() {
        // Find the repo's secure/data/erc7730 directory relative to
        // CARGO_MANIFEST_DIR (dbgen/).
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let dir = root.join("secure/data/erc7730");
        let policy = dir.join("policy.toml");
        let res = build_db(&dir, &policy).expect("build seed corpus");
        // `secure/data/erc7730/` is now a synthetic-only render-test corpus
        // (the protocol fixtures were duplicates of the vendored registry —
        // the PROD corpus built tolerantly elsewhere), so the floor is ≥1.
        assert!(res.leaf_count >= 1, "expected ≥1 leaf, got {}", res.leaf_count);
        round_trip_check(&res).expect("round-trip");
    }

    // ── Audit H-3 — field-completeness lint (clear-sign forgery class) ──
    //
    // A descriptor that silently omits an effect-bearing calldata word
    // renders a benign page while the signature still commits to the
    // hidden value. These pin both the top-level rule and the tuple-member
    // tightening (the renderer addresses static-tuple members individually,
    // so per-member coverage is required — not "tuple touched once").

    /// Build a throwaway `Format` from a JSON `fields` array.
    fn fmt_from_fields(fields_json: &str) -> Format {
        serde_json::from_str(&format!(r#"{{"fields": {fields_json}}}"#))
            .expect("valid test Format JSON")
    }

    // ── review finding 1.1: field-level $ref → $.display.definitions ─────
    // Direct unit tests of the resolver's merge rule + its fail-loud error
    // paths (the render-level proof lives in the secure crate's render tests).

    fn resolve_fmt_refs(display_json: &str, fmt_key: &str) -> Result<Vec<FieldDef>, String> {
        let display: Display = serde_json::from_str(display_json).expect("valid display JSON");
        let fmt = display.formats.get(fmt_key).expect("format present");
        resolve_display_refs(&fmt.fields, display.definitions.as_ref())
    }

    #[test]
    fn ref_resolution_merges_format_from_def_and_params_field_wins() {
        let display = r#"{
            "definitions": {
                "sendAmount": { "label": "Amount to Send", "format": "tokenAmount",
                                "params": { "nativeCurrencyAddress": ["0xeee"] } }
            },
            "formats": { "swap(uint256 a)": { "fields": [
                { "$ref": "$.display.definitions.sendAmount", "path": "a",
                  "params": { "tokenPath": "src" } }
            ] } }
        }"#;
        let out = resolve_fmt_refs(display, "swap(uint256 a)").expect("resolves");
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.format.as_deref(), Some("tokenAmount"), "format ALWAYS from def");
        assert_eq!(f.label.as_deref(), Some("Amount to Send"), "label inherited from def");
        assert_eq!(f.path.as_deref(), Some("a"), "path from the reference");
        let p = f.params.as_ref().expect("merged params");
        assert!(p.get("nativeCurrencyAddress").is_some(), "def param survives merge");
        assert_eq!(
            p.get("tokenPath").and_then(|v| v.as_str()),
            Some("src"),
            "field param survives merge (per-key, field wins)"
        );
        assert!(f.ref_def.is_none(), "the $ref key is consumed");
    }

    #[test]
    fn ref_resolution_field_label_overrides_definition() {
        let display = r#"{
            "definitions": { "amt": { "label": "Amount to Receive", "format": "tokenAmount" } },
            "formats": { "f(uint256 a)": { "fields": [
                { "$ref": "$.display.definitions.amt", "path": "a", "label": "Min Out" }
            ] } }
        }"#;
        let out = resolve_fmt_refs(display, "f(uint256 a)").expect("resolves");
        assert_eq!(out[0].label.as_deref(), Some("Min Out"), "field label overrides def");
        assert_eq!(out[0].format.as_deref(), Some("tokenAmount"));
    }

    #[test]
    fn ref_resolution_unresolvable_ref_hard_errors() {
        // No such definition → fail LOUD (never silently degrade to raw).
        let display = r#"{
            "definitions": { "other": { "format": "tokenAmount" } },
            "formats": { "f(uint256 a)": { "fields": [
                { "$ref": "$.display.definitions.missing", "path": "a" }
            ] } }
        }"#;
        let err = resolve_fmt_refs(display, "f(uint256 a)").unwrap_err();
        assert!(err.contains("unresolved $ref"), "got: {err}");
    }

    #[test]
    fn ref_resolution_non_display_definition_ref_hard_errors() {
        // A field-level $ref must target $.display.definitions.* — an enum
        // ($.metadata.enums.*) ref at the field level is malformed → error,
        // not a silent drop.
        let display = r#"{
            "formats": { "f(uint256 a)": { "fields": [
                { "$ref": "$.metadata.enums.mode", "path": "a" }
            ] } }
        }"#;
        let err = resolve_fmt_refs(display, "f(uint256 a)").unwrap_err();
        assert!(err.contains("not a `$.display.definitions"), "got: {err}");
    }

    #[test]
    fn ref_resolution_no_ref_is_identity() {
        let display = r#"{
            "formats": { "f(uint256 a)": { "fields": [
                { "path": "a", "label": "A", "format": "raw" }
            ] } }
        }"#;
        let out = resolve_fmt_refs(display, "f(uint256 a)").expect("resolves");
        assert_eq!(out[0].format.as_deref(), Some("raw"));
        assert_eq!(out[0].label.as_deref(), Some("A"));
    }

    // ── VULN-erc7730-rule1-inert-field-nonaddr-action-hide (Rule 1) ──────

    #[test]
    fn rule1_inert_only_meta_tx_rejected() {
        // THE LIVE WITNESS: Rarible `MetaTransaction` renders `from`+`nonce`
        // (both inert) and hides `functionSignature` (the entire executed
        // action). Rule 1 must refuse — a reassuring banner over a blind-sign.
        let sig = "MetaTransaction(uint256 nonce, address from, bytes functionSignature)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"from","label":"User Address","format":"raw"},
              {"path":"nonce","label":"Meta Transaction Nonce","format":"raw"},
              {"path":"functionSignature","label":"Function Signature","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &[])
            .expect_err("inert-only clear-sign must be refused");
        assert!(err.contains("inert"), "rule-1 message names inert roles: {err}");
    }

    #[test]
    fn rule1_shown_effect_address_ok() {
        // Celo `authorizeVoteSigner(address signer, ...)` shows `signer` — the
        // address being granted authority IS the effect. Must NOT be treated
        // as inert (the false-positive a naive inert list would trip).
        let sig = "authorizeVoteSigner(address signer, uint8 v, bytes32 r, bytes32 s)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"signer","label":"Signer","format":"addressName"},
              {"path":"r","label":"r","visible":"never"},
              {"path":"s","label":"s","visible":"never"}
            ]"#,
        );
        assert!(
            check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[]).is_ok(),
            "a shown non-inert address (`signer`) satisfies rule 1"
        );
    }

    #[test]
    fn rule1_shown_amount_ok() {
        // A shown amount alongside a hidden inert `from` satisfies rule 1.
        let sig = "pay(address from, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"from","label":"From","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[]).is_ok());
    }

    #[test]
    fn completeness_flat_param_omitted_rejected() {
        // The canonical break: a `transfer` descriptor that shows only the
        // amount and never the recipient.
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[{"path":"amount","label":"Amount","format":"tokenAmount","params":{"token":"0x0000000000000000000000000000000000000000"}}]"#,
        );
        let err = check_contract_field_completeness(sig, &fmt, &parsed)
            .expect_err("omitted recipient must be rejected");
        assert!(err.contains("`to`"), "error names the hidden param: {err}");
    }

    #[test]
    fn completeness_flat_all_covered_accepted() {
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        assert!(check_contract_field_completeness(sig, &fmt, &parsed).is_ok());
    }

    #[test]
    fn completeness_tuple_member_omitted_rejected() {
        // Uniswap exactInputSingle shape: every member but
        // `sqrtPriceLimitX96` is surfaced. Top-level granularity would call
        // the tuple "covered"; member granularity correctly rejects, because
        // the renderer can (and the attacker-set word would be) signed but
        // not shown.
        let sig = "swap((address tokenIn, address tokenOut, uint256 amountIn, uint160 sqrtPriceLimitX96) params)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"params.amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"params.tokenIn"}},
              {"path":"params.tokenOut","label":"To token","format":"addressName"}
            ]"#,
        );
        let err = check_contract_field_completeness(sig, &fmt, &parsed)
            .expect_err("omitted tuple member must be rejected");
        assert!(
            err.contains("sqrtPriceLimitX96"),
            "error names the hidden member: {err}"
        );
    }

    #[test]
    fn completeness_tuple_member_hidden_via_never_accepted() {
        // Same shape, but the omitted member is an explicit `visible:"never"`
        // author decision — accepted (a conscious hide, what the lint forces).
        let sig = "swap((address tokenIn, address tokenOut, uint256 amountIn, uint160 sqrtPriceLimitX96) params)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"params.amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"params.tokenIn"}},
              {"path":"params.tokenOut","label":"To token","format":"addressName"},
              {"path":"params.sqrtPriceLimitX96","label":"Price limit","visible":"never"}
            ]"#,
        );
        assert!(check_contract_field_completeness(sig, &fmt, &parsed).is_ok());
    }

    #[test]
    fn completeness_tuple_all_members_covered_accepted() {
        // tokenIn covered via `tokenPath`, amountIn via its own field path.
        let sig = "swap((address tokenIn, uint256 amountIn) params)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[{"path":"params.amountIn","label":"Send","format":"tokenAmount","params":{"tokenPath":"params.tokenIn"}}]"#,
        );
        assert!(check_contract_field_completeness(sig, &fmt, &parsed).is_ok());
    }

    #[test]
    fn path_covers_tuple_member_matches_and_rejects() {
        assert!(path_covers_tuple_member("params.amountIn", "params", "amountIn"));
        assert!(path_covers_tuple_member("#.params.amountIn", "params", "amountIn"));
        assert!(path_covers_tuple_member("params.order.x", "params", "order")); // nested, one level
        // wrong member / wrong tuple / bare tuple / array hop / envelope root.
        assert!(!path_covers_tuple_member("params.amountIn", "params", "tokenIn"));
        assert!(!path_covers_tuple_member("other.amountIn", "params", "amountIn"));
        assert!(!path_covers_tuple_member("params", "params", "amountIn"));
        assert!(!path_covers_tuple_member("params[0]", "params", "amountIn"));
        assert!(!path_covers_tuple_member("@.value", "params", "amountIn"));
        assert!(!path_covers_tuple_member("$.metadata", "params", "amountIn"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // WYSIWYS visibility gate — VULN-erc7730-visible-never-noparam-clearsign.
    // Completeness (above) blesses `visible:"never"`; these guard that the
    // effect-bearing arguments are actually SHOWN.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn type_contains_address_is_token_exact() {
        assert!(type_contains_address("address"));
        assert!(type_contains_address("address[]"));
        assert!(type_contains_address("address[3]"));
        assert!(type_contains_address("(address,uint256)"));
        assert!(type_contains_address("(uint256,address)[]"));
        // No false positives on non-address ABI types.
        assert!(!type_contains_address("uint256"));
        assert!(!type_contains_address("bytes32"));
        assert!(!type_contains_address("bool"));
        assert!(!type_contains_address("string"));
        assert!(!type_contains_address("(uint256,bytes32)"));
    }

    #[test]
    fn visibility_all_hidden_rejected() {
        // The live witness: `setAllowedTarget` hides BOTH params → the device
        // would clear-sign banner + envelope + confirm with nothing shown.
        let sig = "setAllowedTarget(address target, bool allowed)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"target","label":"Target","visible":"never"},
              {"path":"allowed","label":"Allowed","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[])
            .expect_err("all-hidden format must be refused");
        assert!(err.contains("surface at least one"), "rule-1 message: {err}");
    }

    #[test]
    fn visibility_hidden_recipient_rejected() {
        // The canonical future-drain: recipient hidden, amount shown.
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName","visible":"never"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[])
            .expect_err("hidden recipient must be refused");
        assert!(err.contains("`to`"), "names the hidden address: {err}");
    }

    #[test]
    fn visibility_all_shown_transfer_ok() {
        let sig = "transfer(address to, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[]).is_ok());
    }

    #[test]
    fn visibility_zero_arg_ok() {
        let sig = "deposit()";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields("[]");
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[]).is_ok());
    }

    #[test]
    fn visibility_hidden_nonaddress_ok() {
        // A hidden non-address (nonce) is fine — only fund-routing addresses
        // are load-bearing for rule 2, and the shown recipient satisfies rule 1.
        let sig = "bump(address to, uint256 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"to","label":"To","format":"addressName"},
              {"path":"nonce","label":"Nonce","visible":"never"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[]).is_ok());
    }

    #[test]
    fn visibility_tokenpath_surfaced_address_ok() {
        // Ondo pattern: the token address is hidden as its own field but is the
        // `tokenPath` of a SHOWN amount, so its identity reaches the user.
        let sig = "subscribe(address depositToken, uint256 depositAmount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"depositAmount","label":"Deposit","format":"tokenAmount","params":{"tokenPath":"depositToken"}},
              {"path":"depositToken","label":"Token","visible":"never"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[]).is_ok());
    }

    #[test]
    fn visibility_tuple_member_hidden_address_rejected() {
        // A static-tuple member the renderer addresses individually.
        let sig = "exec((address recipient, uint256 amount) order)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"order.recipient","label":"To","format":"addressName","visible":"never"},
              {"path":"order.amount","label":"Amount","format":"raw"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[])
            .expect_err("hidden tuple-member address must be refused");
        assert!(err.contains("order.recipient"), "names the member: {err}");
    }

    #[test]
    fn visibility_allowlist_requires_rationale() {
        // Router-executor pattern: `executor` hidden, output recipient shown.
        let sig = "swap(address executor, address dstReceiver, uint256 amount)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"executor","label":"Executor","visible":"never"},
              {"path":"dstReceiver","label":"To","format":"addressName"},
              {"path":"amount","label":"Amount","format":"raw"}
            ]"#,
        );
        // Refused with no allowlist.
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &[]).is_err());
        // A rationale-less entry fails safe (still refused).
        let no_rationale = [HiddenAddressAllow {
            signature: sig.to_string(),
            path: "executor".to_string(),
            rationale: String::new(),
        }];
        assert!(
            check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &no_rationale).is_err(),
            "an allowlist entry without a rationale must not re-permit the hide"
        );
        // A reviewed entry with a rationale re-permits it.
        let reviewed = [HiddenAddressAllow {
            signature: sig.to_string(),
            path: "executor".to_string(),
            rationale: "router executor; effect bounded by shown min-return".to_string(),
        }];
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_CONTRACT, &reviewed).is_ok());
        // The exemption is scoped to (signature, path): a different function
        // with the same param name is NOT covered.
        let other_sig = "drain(address executor)";
        let other_parsed = parse_format_key(other_sig).unwrap();
        let other_fmt =
            fmt_from_fields(r#"[{"path":"executor","label":"x","visible":"never"}]"#);
        assert!(
            check_field_visibility(other_sig, &other_fmt, &other_parsed, CTX_CONTRACT, &reviewed)
                .is_err(),
            "allowlist entry must not leak across signatures"
        );
    }

    #[test]
    fn visibility_eip712_hidden_address_member_rejected() {
        // The typed-data analogue: a Permit `spender` set `visible:"never"`
        // signs an off-chain approval to an unseen address.
        let sig = "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"owner","label":"Owner","format":"addressName"},
              {"path":"spender","label":"Spender","format":"addressName","visible":"never"},
              {"path":"value","label":"Value","format":"raw"},
              {"path":"nonce","label":"Nonce","visible":"never"},
              {"path":"deadline","label":"Deadline","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &[])
            .expect_err("hidden typed-data spender must be refused");
        assert!(err.contains("spender"), "names the hidden member: {err}");
    }

    // ─────────────────────────────────────────────────────────────────────
    // EIP-712 nested-struct fund-routing address hide
    // (VULN-erc7730-eip712-nested-struct-address-hide). The visible:"never"
    // gate above only walked TOP-LEVEL members; an `address` nested inside a
    // struct member's opaque `hashStruct` word escaped it. These guard the
    // struct-def parse, the descent, and the on-device belt marker.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn parse_struct_defs_from_encodetype_tail() {
        // Canonical two-level.
        let p =
            parse_format_key("Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)")
                .unwrap();
        assert_eq!(p.top_names, ["info", "amount"]);
        assert_eq!(p.top_types, ["Meta", "uint256"]);
        assert_eq!(
            p.struct_defs.get("Meta").expect("Meta parsed"),
            &vec![
                ("spender".to_string(), "address".to_string()),
                ("flags".to_string(), "uint256".to_string()),
            ]
        );

        // Real Uniswap Permit2 single.
        let p = parse_format_key(
            "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
        )
        .unwrap();
        assert_eq!(p.top_types[0], "PermitDetails");
        assert_eq!(
            p.struct_defs.get("PermitDetails").unwrap()[0],
            ("token".to_string(), "address".to_string())
        );

        // Forward-referenced structs (UniswapX ExclusiveDutchOrder — a member
        // whose struct type is defined LATER in the tail; canonical EIP-712
        // sorts struct defs, so forward refs are the norm).
        let p = parse_format_key(
            "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,\
             uint256 deadline,ExclusiveDutchOrder witness)DutchOutput(address token,\
             uint256 startAmount,uint256 endAmount,address recipient)ExclusiveDutchOrder(\
             OrderInfo info,uint256 decayStartTime,uint256 decayEndTime,address exclusiveFiller,\
             uint256 exclusivityOverrideBps,address inputToken,uint256 inputStartAmount,\
             uint256 inputEndAmount,DutchOutput[] outputs)OrderInfo(address reactor,address swapper,\
             uint256 nonce,uint256 deadline,address additionalValidationContract,\
             bytes additionalValidationData)TokenPermissions(address token,uint256 amount)",
        )
        .unwrap();
        for s in ["ExclusiveDutchOrder", "OrderInfo", "DutchOutput", "TokenPermissions"] {
            assert!(p.struct_defs.contains_key(s), "parsed {s}");
        }
        let edo = p.struct_defs.get("ExclusiveDutchOrder").unwrap();
        assert!(edo.iter().any(|(n, t)| n == "outputs" && t == "DutchOutput[]"));
    }

    #[test]
    fn eip712_nested_type_hash_matches_foundry() {
        // v1 targets — foundry `cast keccak` of the exact `encodeType`.
        let p = parse_format_key(
            "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)",
        )
        .unwrap();
        assert_eq!(
            hex::encode(eip712_nested_type_hash("PermitDetails", &p.struct_defs).unwrap()),
            "65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678",
        );
        assert_eq!(eip712_member_count("PermitDetails", &p.struct_defs).unwrap(), 4);

        let p2 = parse_format_key(
            "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,\
             uint256 deadline)TokenPermissions(address token,uint256 amount)",
        )
        .unwrap();
        assert_eq!(
            hex::encode(eip712_nested_type_hash("TokenPermissions", &p2.struct_defs).unwrap()),
            "618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1",
        );

        // Transitive + alphabetical sort + dedup (de-risks v2). encodeType(A) =
        // def(A) ‖ sorted[def(B), def(C)].
        let mut defs: StructDefs = BTreeMap::new();
        defs.insert(
            "A".into(),
            vec![("b".into(), "B".into()), ("x".into(), "address".into())],
        );
        defs.insert(
            "B".into(),
            vec![("y".into(), "address".into()), ("c".into(), "C".into())],
        );
        defs.insert("C".into(), vec![("z".into(), "uint256".into())]);
        assert_eq!(
            eip712_encode_type("A", &defs).unwrap(),
            "A(B b,address x)B(address y,C c)C(uint256 z)",
        );
        assert_eq!(
            hex::encode(eip712_nested_type_hash("A", &defs).unwrap()),
            "a8b08b15aeb75ef0b731673e33d2e8b4523c703d6ecebbbd56975cd9af217ad4",
        );

        // Address-word predicate (E2 bitmap source): only a bare `address`
        // member's own word is an address; a struct member is a hashStruct word.
        assert!(eip712_member_word_is_address("address"));
        assert!(!eip712_member_word_is_address("uint160"));
        assert!(!eip712_member_word_is_address("PermitDetails"));
    }

    #[test]
    fn visibility_eip712_nested_hidden_address_rejected() {
        // THE canonical exploit: a benign `amount` renders while `info` (a
        // Meta struct hiding `spender`) is `visible:"never"`. Pre-fix the
        // gate blessed it (Meta is not the `address` token); post-fix the
        // descent reaches `info.spender`.
        let sig = "Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info","label":"Info","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &[])
            .expect_err("hidden nested spender must be refused");
        assert!(err.contains("info.spender"), "names the nested member: {err}");
    }

    #[test]
    fn visibility_eip712_nested_address_shown_accepted() {
        // Same shape, but `info.spender` is surfaced by a visible field →
        // no hidden fund-routing address, gate passes.
        let sig = "Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info.spender","label":"Spender","format":"addressName"}
            ]"#,
        );
        assert!(
            check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &[]).is_ok(),
            "shown nested address should pass"
        );
    }

    #[test]
    fn visibility_eip712_permit_single_hidden_token_rejected() {
        // Real Uniswap Permit2: hiding `details` hides `details.token`, the
        // token being approved — a nested fund-routing address.
        let sig = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"spender","label":"Spender","format":"addressName"},
              {"path":"details","label":"Details","visible":"never"},
              {"path":"sigDeadline","label":"Deadline","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &[])
            .expect_err("hidden Permit2 token must be refused");
        assert!(err.contains("details.token"), "names nested token: {err}");
    }

    #[test]
    fn visibility_eip712_nested_no_address_accepted() {
        // A nested struct with NO address is not a fund-routing hazard;
        // hiding it (while showing a top-level effect field) passes the build
        // gate. The on-device marker still declines it to blind-sign, but the
        // gate must not over-refuse an address-free hidden sub-struct.
        let sig = "Order(Meta info,uint256 amount)Meta(uint256 a,uint256 b)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info","label":"Info","visible":"never"}
            ]"#,
        );
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &[]).is_ok());
    }

    #[test]
    fn visibility_eip712_array_of_struct_address_rejected() {
        // `details` is `PermitDetails[]` — array-of-struct with a nested
        // `token` address. Elements aren't individually addressable on
        // device, so a nested address can't be shown → refuse.
        let sig = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)\
             PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"spender","label":"Spender","format":"addressName"},
              {"path":"details","label":"Details","visible":"never"},
              {"path":"sigDeadline","label":"Deadline","visible":"never"}
            ]"#,
        );
        let err = check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &[])
            .expect_err("array-of-struct nested address must be refused");
        assert!(err.contains("details"), "names the array member: {err}");
    }

    #[test]
    fn visibility_eip712_nested_address_allowlisted() {
        // A reviewed allowlist entry (with rationale) re-permits ONE hidden
        // nested address, exactly like the top-level rule.
        let sig = "Order(Meta info,uint256 amount)Meta(address spender,uint256 flags)";
        let parsed = parse_format_key(sig).unwrap();
        let fmt = fmt_from_fields(
            r#"[
              {"path":"amount","label":"Amount","format":"raw"},
              {"path":"info","label":"Info","visible":"never"}
            ]"#,
        );
        let allow = vec![HiddenAddressAllow {
            signature: sig.to_string(),
            path: "info.spender".to_string(),
            rationale: "test: routes no funds".to_string(),
        }];
        assert!(check_field_visibility(sig, &fmt, &parsed, CTX_EIP712, &allow).is_ok());
    }

    #[test]
    fn nested_struct_marker_emitted_on_first_field() {
        // A nested-struct EIP-712 format that PASSES the gate (no nested
        // address) is pinned with the PARAM_NESTED_STRUCT belt on field[0].
        let sig = "Order(Meta info,uint256 amount)Meta(uint256 a,uint256 b)";
        let parsed = parse_format_key(sig).unwrap();
        let field0: FieldDef =
            serde_json::from_str(r#"{"path":"amount","label":"Amount","format":"raw"}"#).unwrap();
        let mut ctx = CompileCtx {
            constants: serde_json::Map::new(),
            enums: serde_json::Map::new(),
            descriptor_hash: [0u8; 32],
            owner: String::new(),
            contract_name: String::new(),
            hidden_address_allow: Vec::new(),
        };
        let mut pool = Pool::new();
        let cf = compile_one_field(
            sig,
            0,
            &field0,
            CTX_EIP712,
            &parsed,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            true,
        )
        .unwrap();
        let bytes = pool.into_bytes();
        let off = cf.param_off as usize;
        assert!(off != 0, "marker forces a non-empty param blob");
        let len = bytes[off] as usize;
        let blob = &bytes[off + 1..off + 1 + len];
        // Walk the TLV blob and assert PARAM_NESTED_STRUCT (0x41 / [0x01]).
        let mut found = false;
        let mut c = 0;
        while c + 2 <= blob.len() {
            let tag = blob[c];
            let l = blob[c + 1] as usize;
            if tag == PARAM_NESTED_STRUCT {
                assert_eq!(&blob[c + 2..c + 2 + l], &[0x01]);
                found = true;
            }
            c += 2 + l;
        }
        assert!(found, "PARAM_NESTED_STRUCT emitted on field[0]");
    }

    #[test]
    fn nested_struct_marker_not_emitted_without_nested_struct() {
        // A struct-free EIP-712 primary type gets no marker (has_nested_struct
        // is false → the belt only fires for genuinely un-expandable types).
        let sig = "Permit(address owner,address spender,uint256 value)";
        let parsed = parse_format_key(sig).unwrap();
        assert!(parsed.struct_defs.is_empty());
        let has_nested = parsed.top_types.iter().any(|ty| {
            let (base, _) = split_array_suffix(ty);
            type_is_struct(base, &parsed)
        });
        assert!(!has_nested, "no nested struct → no marker");
    }

    #[test]
    fn path_matches_member_exact() {
        assert!(path_matches_member("info.spender", "info.spender"));
        assert!(path_matches_member("#.info.spender", "info.spender"));
        assert!(path_matches_member("witness.info.reactor", "witness.info.reactor"));
        // Parent alone does NOT cover a nested member.
        assert!(!path_matches_member("info", "info.spender"));
        // A deeper path is not the member.
        assert!(!path_matches_member("info.spender.x", "info.spender"));
        // Array hop / envelope roots never match a scalar member.
        assert!(!path_matches_member("info.outputs[0].recipient", "info.outputs.recipient"));
        assert!(!path_matches_member("@.value", "info.spender"));
        assert!(!path_matches_member("$.x", "info.spender"));
    }

    #[test]
    fn visibility_gate_runs_inside_compile_one_format() {
        // Integration: the witness format is refused by the full compile path,
        // not just the standalone checker — so the tolerant corpus drops it to
        // blind-sign and it can never ship as a trusted clear-sign.
        let sig = "setAllowedTarget(address target, bool allowed)";
        let fmt = fmt_from_fields(
            r#"[
              {"path":"target","label":"Target","visible":"never"},
              {"path":"allowed","label":"Allowed","visible":"never"}
            ]"#,
        );
        let mut ctx = CompileCtx {
            constants: serde_json::Map::new(),
            enums: serde_json::Map::new(),
            descriptor_hash: [0u8; 32],
            owner: String::new(),
            contract_name: String::new(),
            hidden_address_allow: Vec::new(),
        };
        let mut pool = Pool::new();
        let mut out = Vec::new();
        let res = compile_one_format(
            sig,
            &fmt,
            CTX_CONTRACT,
            &mut ctx,
            &mut pool,
            &BTreeMap::new(),
            &mut out,
        );
        assert!(res.is_err(), "compile_one_format must refuse the all-hidden witness");
    }

    // Audit 2026-06-25 HIGH-1 — EIP-712 completeness lint regression guards.

    /// Build an in-memory `Format` from a list of field paths.
    fn fmt_with_paths(paths: &[&str]) -> Format {
        let fields: Vec<serde_json::Value> = paths
            .iter()
            .map(|p| serde_json::json!({ "path": p, "format": "raw" }))
            .collect();
        serde_json::from_value(serde_json::json!({ "fields": fields }))
            .expect("synthetic format deserializes")
    }

    const PERMIT2_KEY: &str =
        "PermitTransferFrom(address token,address spender,uint256 amount,uint256 nonce,uint256 deadline)";

    #[test]
    fn eip712_completeness_rejects_omitted_member() {
        // Renders only `token` + `amount`; `spender`/`nonce`/`deadline`
        // are signed (folded into structHash) but never shown — the exact
        // HIGH-1 Permit2 drain shape. The lint must refuse to pin it.
        let parsed = parse_format_key(PERMIT2_KEY).unwrap();
        let fmt = fmt_with_paths(&["token", "amount"]);
        let err = check_eip712_field_completeness(PERMIT2_KEY, &fmt, &parsed)
            .expect_err("incomplete EIP-712 descriptor must be rejected");
        assert!(err.contains("spender"), "error should name the first omitted member: {err}");
    }

    #[test]
    fn eip712_completeness_accepts_full_coverage() {
        // Every member has a field — passes (mirrors the shipped
        // circle-usdc-{rwa,twa} authorization descriptors).
        let parsed = parse_format_key(PERMIT2_KEY).unwrap();
        let fmt = fmt_with_paths(&["token", "spender", "amount", "nonce", "deadline"]);
        assert!(check_eip712_field_completeness(PERMIT2_KEY, &fmt, &parsed).is_ok());
    }

    #[test]
    fn eip712_completeness_accepts_tokenpath_coverage() {
        // A member surfaced only as another field's `tokenPath` counts as
        // covered (parity with the contract lint): here `token` rides on
        // the `amount` field's tokenPath, and the rest have their own
        // fields. `spender`/`nonce`/`deadline` still need fields.
        let parsed = parse_format_key(PERMIT2_KEY).unwrap();
        let fields = serde_json::json!({
            "fields": [
                { "path": "amount", "format": "tokenAmount", "params": { "tokenPath": "token" } },
                { "path": "spender", "format": "addressName" },
                { "path": "nonce", "format": "raw", "visible": "never" },
                { "path": "deadline", "format": "raw" },
            ]
        });
        let fmt: Format = serde_json::from_value(fields).unwrap();
        assert!(check_eip712_field_completeness(PERMIT2_KEY, &fmt, &parsed).is_ok());
    }
}
