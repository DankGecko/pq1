//! Offline source-to-descriptor evidence for Uniswap Permit2 EIP-712 permits.
//!
//! This test intentionally makes no RPC request and no deployed-runtime claim.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::{try_compile_one, Emitted, Policy};
use pqsigner_erc7730::ir::{ContextKind, Erc7730Ir, Visibility};
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

const UPSTREAM_COMMIT: &str = "cc306b601f172c51bc04334a109e98340456620b";
const UPSTREAM_TREE: &str = "0d35aeb758e99510961089df8f7dfd94b256e58f";
const DEPLOYMENT_TAG: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const DESCRIPTOR_SHA256: &str = "585cda2929c5e88e35d6c98aa6b8edd38e01a03288123d1d6bc60635c2119204";
const INCLUDE_SHA256: &str = "42308b598001e669b81aeb2a29d37bb28d7f422aed9ff5c44b443ce963f4b8ab";
const UINT160_MAX_WORD: &str = "0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff";
const UINT256_MAX_WORD: &str = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

const DOMAIN_TYPE: &str = "EIP712Domain(string name,uint256 chainId,address verifyingContract)";
const PERMIT_DETAILS_TYPE: &str =
    "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const PERMIT_SINGLE_TYPE: &str = "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const PERMIT_BATCH_TYPE: &str = "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)";
const TOKEN_PERMISSIONS_TYPE: &str = "TokenPermissions(address token,uint256 amount)";
const PERMIT_TRANSFER_FROM_TYPE: &str = "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)";

const TYPE_RECEIPTS: [(&str, &str, &str); 5] = [
    (
        "PermitDetails",
        PERMIT_DETAILS_TYPE,
        "0x65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678",
    ),
    (
        "PermitSingle",
        PERMIT_SINGLE_TYPE,
        "0xf3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0",
    ),
    (
        "PermitBatch",
        PERMIT_BATCH_TYPE,
        "0xaf1b0d30d2cab0380e68f0689007e3254993c596f2fdd0aaa7f4d04f79440863",
    ),
    (
        "TokenPermissions",
        TOKEN_PERMISSIONS_TYPE,
        "0x618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1",
    ),
    (
        "PermitTransferFrom",
        PERMIT_TRANSFER_FROM_TYPE,
        "0x939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106",
    ),
];

const SOURCE_RECEIPTS: [(&str, &str); 11] = [
    (
        "script/DeployPermit2.s.sol",
        "d1085fa275e065bc50af25389a5cc7f6b16b9cd5e947126ef677871bf46fb09f",
    ),
    (
        "src/AllowanceTransfer.sol",
        "e8755950225a256cd458c02433958a9e614083b4e334bb9853ec4075bcb8ab92",
    ),
    (
        "src/EIP712.sol",
        "195ebab17589ed34e23de94eb9238bd099acaba88cc64b49c2763c72083bec98",
    ),
    (
        "src/Permit2.sol",
        "a19dd81d4edafe3bba0178abfc9063886c2981b4711a4cbbf3fac19370defc9a",
    ),
    (
        "src/SignatureTransfer.sol",
        "b7a210d7349fd12b75e556a4d0d7ea5a7ea61b39264d53ea1299b03323f62991",
    ),
    (
        "src/interfaces/IAllowanceTransfer.sol",
        "aeecef7ca9a72ee02f1ef8edfb44599339c5dc758cf382455c2f72fb77dffc74",
    ),
    (
        "src/interfaces/IERC1271.sol",
        "ba35907d098ef8b6c6c967d522026d09c92c7e2344cc81e4ee89db8955fa4ca8",
    ),
    (
        "src/interfaces/ISignatureTransfer.sol",
        "0a5d6ac59da350987693f40f0ff0a833f31b37e057645f8e6ed9a1dad691e45c",
    ),
    (
        "src/libraries/Allowance.sol",
        "6c7d1edc74a9dca9940fa835db09302ed1a35019d69f4188351466e9a3fff458",
    ),
    (
        "src/libraries/PermitHash.sol",
        "23f89633dbd02d8b52a33de3a915af5af73ff25e31f88b6cf994358f802efa60",
    ),
    (
        "src/libraries/SignatureVerification.sol",
        "1804b3d7b1183225419ec8ee45daf89174ff3668315d71d28111d5fcc179f8e4",
    ),
];

const CHAINS: [u64; 15] = [
    1, 10, 56, 137, 146, 8_453, 42_161, 42_220, 43_114, 80_001, 81_457, 84_532, 421_614,
    11_155_111, 11_155_420,
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/uniswap-permit2")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("field {key} is a string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments_in_order(source: &str, fragments: &[&str], context: &str) {
    let normalized = normalized_whitespace(source);
    let mut cursor = 0usize;
    for fragment in fragments {
        let offset = normalized[cursor..]
            .find(fragment)
            .unwrap_or_else(|| panic!("{context} lost semantic fragment: {fragment}"));
        cursor += offset + fragment.len();
    }
}

fn collect_files(root: &Path, directory: &Path, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let path = entry.expect("evidence directory entry").path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("evidence file is below evidence root")
                .to_str()
                .expect("evidence path is UTF-8")
                .replace('\\', "/");
            if relative != "README.md" && relative != "manifest.json" {
                assert!(files.insert(relative), "duplicate evidence file");
            }
        }
    }
}

fn descriptor_field<'a>(format: &'a Value, path: &str) -> &'a Value {
    format["fields"]
        .as_array()
        .expect("format fields")
        .iter()
        .find(|field| field["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("missing descriptor field {path}"))
}

fn display_coverage(format: &Value) -> BTreeSet<String> {
    let mut coverage = BTreeSet::new();
    for field in format["fields"].as_array().expect("format fields") {
        coverage.insert(required_str(field, "path").to_owned());
        if let Some(token_path) = field["params"]["tokenPath"].as_str() {
            coverage.insert(token_path.to_owned());
        }
    }
    coverage
}

fn manifest_string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("manifest string array")
        .iter()
        .map(|item| item.as_str().expect("manifest string").to_owned())
        .collect()
}

fn compiled_snapshot(entries: &[Emitted]) -> Vec<(u64, [u8; 20], Vec<u8>)> {
    let mut snapshot: Vec<_> = entries
        .iter()
        .map(|entry| (entry.chain_id, entry.contract, entry.ir_bytes.clone()))
        .collect();
    snapshot.sort_by_key(|(chain_id, contract, _)| (*chain_id, *contract));
    snapshot
}

fn eip712_domain_separator(chain_id: u64, contract: &[u8; 20]) -> [u8; 32] {
    let mut encoded = [0u8; 128];
    encoded[..32].copy_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    encoded[32..64].copy_from_slice(&keccak256(b"Permit2"));
    encoded[88..96].copy_from_slice(&chain_id.to_be_bytes());
    encoded[108..128].copy_from_slice(contract);
    keccak256(&encoded)
}

#[test]
fn official_deployment_tag_source_archive_is_complete_and_hash_pinned() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        required_str(&manifest["upstream"], "commit"),
        UPSTREAM_COMMIT
    );
    assert_eq!(required_str(&manifest["upstream"], "tree"), UPSTREAM_TREE);
    assert_eq!(
        required_str(&manifest["upstream"], "deployment_tag"),
        DEPLOYMENT_TAG
    );
    assert_eq!(
        required_str(&manifest["upstream"], "tag_kind"),
        "lightweight"
    );
    assert_eq!(
        manifest["deployment_runtime"]["archived"].as_bool(),
        Some(false)
    );
    assert_eq!(
        manifest["deployment_runtime"]["fixed_block_evidence"].as_bool(),
        Some(false)
    );
    assert_eq!(
        required_str(&manifest["deployment_runtime"], "claim"),
        "none"
    );

    let receipts: BTreeMap<_, _> = manifest["upstream"]["files"]
        .as_array()
        .expect("source receipts")
        .iter()
        .map(|receipt| {
            (
                required_str(receipt, "path").to_owned(),
                required_str(receipt, "sha256").to_owned(),
            )
        })
        .collect();
    let expected_receipts: BTreeMap<_, _> = SOURCE_RECEIPTS
        .into_iter()
        .map(|(path, hash)| (path.to_owned(), hash.to_owned()))
        .collect();
    assert_eq!(receipts, expected_receipts, "source receipts drifted");

    let mut archived = BTreeSet::new();
    collect_files(&root, &root, &mut archived);
    assert_eq!(archived, receipts.keys().cloned().collect());
    for (path, expected_hash) in receipts {
        let bytes =
            fs::read(root.join(&path)).unwrap_or_else(|error| panic!("read {path}: {error}"));
        assert_eq!(
            sha256_hex(&bytes),
            expected_hash,
            "archived source drift: {path}"
        );
    }

    let deploy = fs::read_to_string(root.join("script/DeployPermit2.s.sol"))
        .expect("read deployment script");
    assert!(deploy.contains("permit2 = new Permit2{salt: SALT}();"));
    let permit2 = fs::read_to_string(root.join("src/Permit2.sol")).expect("read Permit2 source");
    assert!(permit2.contains("contract Permit2 is SignatureTransfer, AllowanceTransfer"));
}

#[test]
fn official_source_fixes_domain_typehash_approval_and_signature_semantics() {
    let root = evidence_root();
    let manifest = read_json(&root.join("manifest.json"));
    assert_eq!(
        required_str(&manifest["eip712"], "domain_type"),
        DOMAIN_TYPE
    );
    assert_eq!(
        required_str(&manifest["eip712"], "domain_typehash"),
        keccak_hex(DOMAIN_TYPE.as_bytes())
    );
    assert_eq!(required_str(&manifest["eip712"], "name"), "Permit2");
    assert_eq!(
        required_str(&manifest["eip712"], "name_hash"),
        keccak_hex(b"Permit2")
    );
    assert_eq!(
        manifest_string_set(&manifest["eip712"]["domain_fields"]),
        ["name", "chainId", "verifyingContract"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    let manifest_types: BTreeMap<_, _> = manifest["eip712"]["types"]
        .as_array()
        .expect("type receipts")
        .iter()
        .map(|receipt| (required_str(receipt, "name"), receipt))
        .collect();
    assert_eq!(manifest_types.len(), TYPE_RECEIPTS.len());
    for (name, type_string, expected_hash) in TYPE_RECEIPTS {
        let receipt = manifest_types
            .get(name)
            .unwrap_or_else(|| panic!("missing {name}"));
        assert_eq!(required_str(receipt, "type_string"), type_string);
        assert_eq!(required_str(receipt, "typehash"), expected_hash);
        assert_eq!(keccak_hex(type_string.as_bytes()), expected_hash);
    }

    let eip712 = fs::read_to_string(root.join("src/EIP712.sol")).expect("read EIP712 source");
    assert_fragments_in_order(
        &eip712,
        &[
            "bytes32 private constant _HASHED_NAME = keccak256(\"Permit2\");",
            "keccak256(\"EIP712Domain(string name,uint256 chainId,address verifyingContract)\");",
            "_CACHED_CHAIN_ID = block.chainid;",
            "return block.chainid == _CACHED_CHAIN_ID",
            "return keccak256(abi.encode(typeHash, nameHash, block.chainid, address(this)));",
        ],
        "Permit2 EIP-712 domain",
    );
    assert!(!eip712.contains("string version"));
    assert!(!eip712.contains("_HASHED_VERSION"));

    let permit_hash = fs::read_to_string(root.join("src/libraries/PermitHash.sol"))
        .expect("read PermitHash source");
    for (_, type_string, _) in TYPE_RECEIPTS {
        assert!(
            permit_hash.contains(type_string),
            "PermitHash lost {type_string}"
        );
    }
    assert!(permit_hash.contains(
        "abi.encode(_PERMIT_TRANSFER_FROM_TYPEHASH, tokenPermissionsHash, msg.sender, permit.nonce, permit.deadline)"
    ));

    let allowance_interface =
        fs::read_to_string(root.join("src/interfaces/IAllowanceTransfer.sol"))
            .expect("read IAllowanceTransfer");
    assert_fragments_in_order(
        &allowance_interface,
        &[
            "struct PermitDetails {",
            "address token;",
            "uint160 amount;",
            "uint48 expiration;",
            "uint48 nonce;",
            "struct PermitSingle {",
            "PermitDetails details;",
            "address spender;",
            "uint256 sigDeadline;",
            "struct PermitBatch {",
            "PermitDetails[] details;",
            "address spender;",
            "uint256 sigDeadline;",
        ],
        "Permit2 allowance structs",
    );
    assert!(allowance_interface
        .contains("Setting amount to type(uint160).max sets an unlimited approval"));

    let allowance =
        fs::read_to_string(root.join("src/AllowanceTransfer.sol")).expect("read AllowanceTransfer");
    assert!(allowance.contains("if (maxAmount != type(uint160).max)"));
    assert_fragments_in_order(
        &allowance,
        &[
            "signature.verify(_hashTypedData(permitSingle.hash()), owner);",
            "_updateApproval(permitSingle.details, owner, permitSingle.spender);",
            "if (allowed.nonce != nonce) revert InvalidNonce();",
            "allowed.updateAll(amount, expiration, nonce);",
        ],
        "Permit2 single approval",
    );
    let allowance_lib = fs::read_to_string(root.join("src/libraries/Allowance.sol"))
        .expect("read Allowance library");
    assert_fragments_in_order(
        &allowance_lib,
        &[
            "storedNonce = nonce + 1;",
            "uint48 storedExpiration = expiration == BLOCK_TIMESTAMP_EXPIRATION ? uint48(block.timestamp) : expiration;",
            "uint256 word = pack(amount, storedExpiration, storedNonce);",
        ],
        "Permit2 allowance state update",
    );

    let signature_interface =
        fs::read_to_string(root.join("src/interfaces/ISignatureTransfer.sol"))
            .expect("read ISignatureTransfer");
    assert_fragments_in_order(
        &signature_interface,
        &[
            "struct PermitTransferFrom {",
            "TokenPermissions permitted;",
            "uint256 nonce;",
            "uint256 deadline;",
            "struct SignatureTransferDetails {",
            "address to;",
            "uint256 requestedAmount;",
        ],
        "Permit2 signed permit versus unsigned transfer details",
    );
    let signature_transfer =
        fs::read_to_string(root.join("src/SignatureTransfer.sol")).expect("read SignatureTransfer");
    assert_fragments_in_order(
        &signature_transfer,
        &[
            "uint256 requestedAmount = transferDetails.requestedAmount;",
            "if (requestedAmount > permit.permitted.amount) revert InvalidAmount(permit.permitted.amount);",
            "signature.verify(_hashTypedData(dataHash), owner);",
            "safeTransferFrom(owner, transferDetails.to, requestedAmount);",
        ],
        "Permit2 one-time transfer execution",
    );

    let verification = fs::read_to_string(root.join("src/libraries/SignatureVerification.sol"))
        .expect("read SignatureVerification");
    assert_fragments_in_order(
        &verification,
        &[
            "if (claimedSigner.code.length == 0) {",
            "address signer = ecrecover(hash, v, r, s);",
            "if (signer != claimedSigner) revert InvalidSigner();",
            "} else {",
            "bytes4 magicValue = IERC1271(claimedSigner).isValidSignature(hash, signature);",
            "if (magicValue != IERC1271.isValidSignature.selector) revert InvalidContractSignature();",
        ],
        "Permit2 EOA/ERC-1271 dispatch",
    );
    assert!(
        !verification.to_ascii_lowercase().contains("6492"),
        "the pinned verifier must not silently gain an ERC-6492 unwrap path"
    );
}

#[test]
fn production_descriptor_copies_exactly_expose_the_source_bound_semantics() {
    let workspace = workspace_root();
    let evidence = read_json(&evidence_root().join("manifest.json"));
    let vendored_path = workspace.join(required_str(&evidence["descriptors"], "vendored"));
    let curated_path = workspace.join(required_str(&evidence["descriptors"], "curated"));
    let include_path = workspace.join(required_str(&evidence["descriptors"], "include"));
    let vendored = fs::read(&vendored_path).expect("read vendored Permit2 descriptor");
    let curated = fs::read(&curated_path).expect("read curated Permit2 descriptor");
    let include = fs::read(&include_path).expect("read Permit2 descriptor include");
    assert_eq!(
        vendored, curated,
        "the two production descriptor copies drifted"
    );
    assert_eq!(sha256_hex(&vendored), DESCRIPTOR_SHA256);
    assert_eq!(
        sha256_hex(&vendored),
        required_str(&evidence["descriptors"], "sha256")
    );
    assert_eq!(sha256_hex(&include), INCLUDE_SHA256);
    assert_eq!(
        sha256_hex(&include),
        required_str(&evidence["descriptors"], "include_sha256")
    );

    let descriptor: Value = serde_json::from_slice(&vendored).expect("parse Permit2 descriptor");
    assert_eq!(
        descriptor["includes"].as_str(),
        Some("uniswap-common-eip712.json")
    );
    let formats = descriptor["display"]["formats"]
        .as_object()
        .expect("Permit2 formats");
    assert_eq!(
        formats.keys().cloned().collect::<BTreeSet<_>>(),
        [
            PERMIT_SINGLE_TYPE,
            PERMIT_BATCH_TYPE,
            PERMIT_TRANSFER_FROM_TYPE
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    let single = &formats[PERMIT_SINGLE_TYPE];
    let batch = &formats[PERMIT_BATCH_TYPE];
    let transfer = &formats[PERMIT_TRANSFER_FROM_TYPE];
    assert_eq!(
        single["intent"].as_str(),
        Some("Authorize spending of token")
    );
    assert_eq!(
        batch["intent"].as_str(),
        Some("Authorize spending of tokens")
    );
    assert_eq!(
        transfer["intent"].as_str(),
        Some("Authorize one-time token pull")
    );
    assert!(transfer.get("interpolatedIntent").is_none());

    for (format, amount_path, expiration_path, nonce_path) in [
        (
            single,
            "details.amount",
            "details.expiration",
            "details.nonce",
        ),
        (
            batch,
            "details.[].amount",
            "details.[].expiration",
            "details.[].nonce",
        ),
    ] {
        let amount = descriptor_field(format, amount_path);
        assert_eq!(amount["label"].as_str(), Some("Allowance"));
        assert_eq!(
            amount["params"]["threshold"].as_str(),
            Some(UINT160_MAX_WORD)
        );
        assert_eq!(amount["params"]["message"].as_str(), Some("Unlimited"));
        let expiration = descriptor_field(format, expiration_path);
        assert_eq!(expiration["label"].as_str(), Some("Expiry (0=now)"));
        assert_eq!(expiration["format"].as_str(), Some("raw"));
        assert_eq!(
            descriptor_field(format, nonce_path)["visible"].as_str(),
            Some("always")
        );
        assert_eq!(
            descriptor_field(format, "sigDeadline")["visible"].as_str(),
            Some("always")
        );
    }

    let maximum = descriptor_field(transfer, "permitted.amount");
    assert_eq!(maximum["label"].as_str(), Some("Maximum transfer"));
    assert_eq!(
        maximum["params"]["threshold"].as_str(),
        Some(UINT256_MAX_WORD)
    );
    assert_eq!(maximum["params"]["message"].as_str(), Some("Any amount"));
    for field in formats
        .values()
        .flat_map(|format| format["fields"].as_array().expect("format fields"))
    {
        assert_eq!(field["visible"].as_str(), Some("always"));
    }

    for (format, semantics) in [
        (single, &evidence["semantics"]["permit_single"]),
        (batch, &evidence["semantics"]["permit_batch"]),
        (transfer, &evidence["semantics"]["permit_transfer_from"]),
    ] {
        assert_eq!(
            display_coverage(format),
            manifest_string_set(&semantics["signed_terminals"]),
            "descriptor must cover each source-bound signed terminal exactly once"
        );
    }
    assert_eq!(
        manifest_string_set(
            &evidence["semantics"]["permit_transfer_from"]["unsigned_execution_fields"]
        ),
        ["transferDetails.to", "transferDetails.requestedAmount"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    let common: Value = serde_json::from_slice(&include).expect("parse Permit2 include");
    assert_eq!(
        common["context"]["eip712"]["domain"]["name"].as_str(),
        Some("Permit2")
    );
    let expected_chains: BTreeSet<_> = CHAINS.into_iter().collect();
    let mut actual_chains = BTreeSet::new();
    for deployment in common["context"]["eip712"]["deployments"]
        .as_array()
        .expect("Permit2 deployments")
    {
        assert_eq!(
            required_str(deployment, "address").to_ascii_lowercase(),
            DEPLOYMENT_TAG.to_ascii_lowercase()
        );
        assert!(
            actual_chains.insert(deployment["chainId"].as_u64().expect("chain id")),
            "duplicate Permit2 chain"
        );
    }
    assert_eq!(actual_chains, expected_chains);
}

#[test]
fn both_descriptor_copies_compile_to_identical_domain_and_type_bound_ir() {
    let workspace = workspace_root();
    let registry_root = workspace.join("secure/data/erc7730-registry");
    let vendored_path = registry_root.join("registry/uniswap/eip712-uniswap-permit2.json");
    let curated_path = workspace
        .join("secure/data/erc7730/curations/files/registry/uniswap/eip712-uniswap-permit2.json");
    let include_path = registry_root.join("registry/uniswap/uniswap-common-eip712.json");
    let policy = Policy::default();

    let vendored = try_compile_one(&vendored_path, &policy, Some(&registry_root))
        .expect("vendored Permit2 descriptor compiles");

    let temp = tempfile::tempdir().expect("temporary curation mirror");
    let temp_uniswap = temp.path().join("registry/uniswap");
    fs::create_dir_all(&temp_uniswap).expect("create temporary registry path");
    let staged_descriptor = temp_uniswap.join("eip712-uniswap-permit2.json");
    fs::write(
        &staged_descriptor,
        fs::read(&curated_path).expect("read curated descriptor"),
    )
    .expect("stage curated descriptor");
    fs::write(
        temp_uniswap.join("uniswap-common-eip712.json"),
        fs::read(&include_path).expect("read vendored include"),
    )
    .expect("stage descriptor include");
    let curated = try_compile_one(&staged_descriptor, &policy, Some(temp.path()))
        .expect("curated Permit2 descriptor compiles against its vendored include");

    assert_eq!(compiled_snapshot(&vendored), compiled_snapshot(&curated));
    assert_eq!(vendored.len(), CHAINS.len());
    let expected_type_hashes: BTreeSet<[u8; 32]> = [
        keccak256(PERMIT_SINGLE_TYPE.as_bytes()),
        keccak256(PERMIT_BATCH_TYPE.as_bytes()),
        keccak256(PERMIT_TRANSFER_FROM_TYPE.as_bytes()),
    ]
    .into_iter()
    .collect();
    for entry in vendored {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("Permit2 IR parses on-device");
        assert_eq!(ir.context_kind, ContextKind::Eip712);
        assert_eq!(ir.chain_id, entry.chain_id);
        assert_eq!(ir.contract, entry.contract);
        assert_eq!(
            ir.domain_separator,
            eip712_domain_separator(entry.chain_id, &entry.contract)
        );
        assert_eq!(
            ir.format_iter()
                .map(|format| format.expect("valid format").type_hash)
                .collect::<BTreeSet<_>>(),
            expected_type_hashes
        );
        for format in ir.format_iter() {
            let format = format.expect("valid format");
            for field in format.fields() {
                let field = field.expect("valid field");
                assert_eq!(
                    parse_params(&ir, field.param_off)
                        .expect("valid field params")
                        .visibility,
                    Visibility::Always
                );
            }
        }
    }
}
