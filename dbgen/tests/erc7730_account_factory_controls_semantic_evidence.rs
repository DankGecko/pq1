//! Offline deployment and semantic evidence for the bounded account/factory slice.
//!
//! This binds the exact Celo Accounts, Kiln Factory, and WalletConnect
//! StakeWeight subsets admitted by PQ1. It grants no authority for future
//! upgrades, mutable-state claims, omitted routes, or blind signing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::cross_check_contract;
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp};
use pqsigner_erc7730::known_calls::may_contain as known_call_may_contain;
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx_core::hash::keccak256;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CELO_DESCRIPTOR: &str = "registry/celo/calldata-celo_accounts.json";
const KILN_DESCRIPTOR: &str = "registry/kiln/calldata-kiln-fee-splitter-factory.json";
const WALLET_DESCRIPTOR: &str = "registry/walletconnect/calldata-stakeweight.json";
const CELO_EXTERNAL_EVIDENCE: &str = "tests/erc7730-semantic-evidence/celo-validators-first-member";
const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

const CELO_NAMED_ROUTES: [&str; 14] = [
    "authorizeSigner(address signer, bytes32 role)",
    "completeSignerAuthorization(address account, bytes32 role)",
    "createAccount()",
    "deletePaymentDelegation()",
    "removeAttestationSigner()",
    "removeDefaultSigner(bytes32 role)",
    "removeIndexedSigner(bytes32 role)",
    "removeSigner(address signer, bytes32 role)",
    "removeStorageRoot(uint256 index)",
    "removeValidatorSigner()",
    "removeVoteSigner()",
    "setMetadataURL(string metadataURL)",
    "setName(string name)",
    "setPaymentDelegation(address beneficiary, uint256 fraction)",
];
const CELO_CANONICAL_ROUTES: [&str; 14] = [
    "authorizeSigner(address,bytes32)",
    "completeSignerAuthorization(address,bytes32)",
    "createAccount()",
    "deletePaymentDelegation()",
    "removeAttestationSigner()",
    "removeDefaultSigner(bytes32)",
    "removeIndexedSigner(bytes32)",
    "removeSigner(address,bytes32)",
    "removeStorageRoot(uint256)",
    "removeValidatorSigner()",
    "removeVoteSigner()",
    "setMetadataURL(string)",
    "setName(string)",
    "setPaymentDelegation(address,uint256)",
];
const CELO_REFUSAL_NAMED: [&str; 6] = [
    "addStorageRoot(bytes url)",
    "authorizeAttestationSigner(address signer, uint8 v, bytes32 r, bytes32 s)",
    "authorizeSignerWithSignature(address signer, bytes32 role, uint8 v, bytes32 r, bytes32 s)",
    "authorizeValidatorSigner(address signer, uint8 v, bytes32 r, bytes32 s)",
    "authorizeValidatorSignerWithPublicKey(address signer, uint8 v, bytes32 r, bytes32 s, bytes ecdsaPublicKey)",
    "authorizeVoteSigner(address signer, uint8 v, bytes32 r, bytes32 s)",
];
const CELO_REFUSAL_CANONICAL: [&str; 6] = [
    "addStorageRoot(bytes)",
    "authorizeAttestationSigner(address,uint8,bytes32,bytes32)",
    "authorizeSignerWithSignature(address,bytes32,uint8,bytes32,bytes32)",
    "authorizeValidatorSigner(address,uint8,bytes32,bytes32)",
    "authorizeValidatorSignerWithPublicKey(address,uint8,bytes32,bytes32,bytes)",
    "authorizeVoteSigner(address,uint8,bytes32,bytes32)",
];

const KILN_NAMED_ROUTES: [&str; 3] = [
    "createOperator(address _owner, string _name, uint256 _operatorFee, uint256 _maximumOperatorFee, address[] _recipients, uint256[] _percents)",
    "createSplitter(address operator, bytes32 salt)",
    "transferOwnership(address newOwner)",
];
const KILN_CANONICAL_ROUTES: [&str; 3] = [
    "createOperator(address,string,uint256,uint256,address[],uint256[])",
    "createSplitter(address,bytes32)",
    "transferOwnership(address)",
];
const KILN_REFUSAL_NAMED: &str =
    "createSplitterAndCall(address operator, bytes32 salt, address callAddress, bytes data)";
const KILN_REFUSAL_CANONICAL: &str = "createSplitterAndCall(address,bytes32,address,bytes)";

const WALLET_NAMED_ROUTES: [&str; 6] = [
    "createLock(uint256 amount, uint256 unlockTime)",
    "depositFor(address for_, uint256 amount)",
    "increaseLockAmount(uint256 amount)",
    "increaseUnlockTime(uint256 newUnlockTime)",
    "updateLock(uint256 amount, uint256 unlockTime)",
    "withdrawAll()",
];
const WALLET_CANONICAL_ROUTES: [&str; 6] = [
    "createLock(uint256,uint256)",
    "depositFor(address,uint256)",
    "increaseLockAmount(uint256)",
    "increaseUnlockTime(uint256)",
    "updateLock(uint256,uint256)",
    "withdrawAll()",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/account-factory-controls")
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

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid archived hex")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn address(text: &str) -> [u8; 20] {
    decode_hex(text)
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("address has {} bytes", bytes.len()))
}

fn abi_word_address(value: &Value) -> [u8; 20] {
    let word = decode_hex(value.as_str().expect("ABI address word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..12], &[0u8; 12], "address word has nonzero padding");
    word[12..].try_into().expect("address width")
}

fn abi_word_u64(value: &Value) -> u64 {
    let word = decode_hex(value.as_str().expect("ABI integer word"));
    assert_eq!(word.len(), 32);
    assert_eq!(&word[..24], &[0u8; 24], "integer exceeds u64");
    u64::from_be_bytes(word[24..].try_into().expect("u64 word"))
}

fn abi_string(value: &Value) -> String {
    let bytes = decode_hex(value.as_str().expect("ABI string"));
    assert!(bytes.len() >= 64, "ABI string has head and length");
    assert_eq!(
        abi_word_u64(&Value::String(format!("0x{}", hex::encode(&bytes[..32])))),
        32
    );
    let len = abi_word_u64(&Value::String(format!("0x{}", hex::encode(&bytes[32..64])))) as usize;
    assert!(bytes.len() >= 64 + len, "ABI string body is complete");
    String::from_utf8(bytes[64..64 + len].to_vec()).expect("UTF-8 token symbol")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("selector width")
}

fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn collect_files(root: &Path, directory: &Path, out: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let entry = entry.expect("evidence entry");
        let path = entry.path();
        let ty = entry.file_type().expect("evidence file type");
        assert!(!ty.is_symlink(), "evidence may not contain symlinks");
        if ty.is_dir() {
            collect_files(root, &path, out);
        } else {
            assert!(ty.is_file(), "unsupported evidence entry");
            let relative = path
                .strip_prefix(root)
                .expect("path stays below evidence root")
                .to_str()
                .expect("UTF-8 evidence path")
                .replace('\\', "/");
            if relative != "manifest.json" {
                assert!(out.insert(relative), "duplicate evidence path");
            }
        }
    }
}

fn rpc_results(path: &Path) -> BTreeMap<u64, Value> {
    let mut results = BTreeMap::new();
    for item in read_json(path).as_array().expect("RPC response array") {
        assert!(
            item.get("error").is_none() || item["error"].is_null(),
            "RPC error in {}",
            path.display()
        );
        let id = item["id"].as_u64().expect("numeric RPC id");
        assert!(
            results.insert(id, item["result"].clone()).is_none(),
            "duplicate RPC id"
        );
    }
    results
}

fn response(root: &Path, directory: &str, provider: &str, batch: &str) -> BTreeMap<u64, Value> {
    rpc_results(
        &root
            .join("rpc/raw")
            .join(directory)
            .join(format!("response-{provider}-{batch}.json")),
    )
}

fn assert_fixed_request(path: &Path, block_hash: &str) {
    for item in read_json(path).as_array().expect("RPC request array") {
        let method = required_str(item, "method");
        let params = item["params"].as_array().expect("RPC params");
        if method == "eth_getBlockByHash" {
            assert_eq!(params[0], block_hash);
            assert_eq!(params[1], false);
        } else if matches!(method, "eth_getCode" | "eth_getStorageAt" | "eth_call") {
            let tag = params.last().expect("fixed-block tag");
            assert_eq!(tag["blockHash"], block_hash);
            assert_eq!(tag["requireCanonical"], true);
            assert_eq!(tag.as_object().expect("EIP-1898 tag").len(), 2);
        }
    }
}

fn abi_signatures(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("ABI array")
        .iter()
        .map(|entry| {
            let types = entry["inputs"]
                .as_array()
                .expect("ABI inputs")
                .iter()
                .map(|input| required_str(input, "type"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{}({types})", required_str(entry, "name"))
        })
        .collect()
}

fn build_registry() -> dbgen::erc7730::Erc7730BuildResult {
    let root = workspace_root();
    let registry_root = root.join("secure/data/erc7730-registry");
    let capabilities = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("production ERC20 capability corpus");
    build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &capabilities.capabilities,
    )
    .expect("build curated registry")
    .0
}

#[test]
fn account_factory_evidence_is_complete_and_cross_provider_bound() {
    let root = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        required_str(&manifest, "issue"),
        "https://github.com/EthereumPhone/PQ1/issues/497"
    );

    let receipts = manifest["artifacts"].as_array().expect("artifact receipts");
    let receipted = receipts
        .iter()
        .map(|receipt| required_str(receipt, "path").to_string())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    collect_files(&evidence, &evidence, &mut actual);
    assert_eq!(receipted, actual, "evidence inventory changed");
    for receipt in receipts {
        let path = evidence.join(required_str(receipt, "path"));
        assert_eq!(
            sha256_hex(&fs::read(&path).expect("read receipted artifact")),
            required_str(receipt, "sha256"),
            "evidence hash changed: {}",
            path.display()
        );
    }

    let external_path = root.join(CELO_EXTERNAL_EVIDENCE).join("manifest.json");
    assert_eq!(
        sha256_hex(&fs::read(&external_path).expect("Celo evidence manifest")),
        required_str(&manifest["celo_accounts"], "evidence_manifest_sha256")
    );
    let celo_manifest = read_json(&external_path);
    assert_eq!(
        celo_manifest["contracts"]["accounts_proxy"],
        manifest["celo_accounts"]["proxy"]
    );
    assert_eq!(
        celo_manifest["contracts"]["accounts_implementation"],
        manifest["celo_accounts"]["implementation"]
    );
    assert_eq!(
        celo_manifest["blockscout"]["accounts_implementation"]["verification"],
        "full"
    );
    let celo_source = normalized(
        &fs::read_to_string(
            root.join(CELO_EXTERNAL_EVIDENCE)
                .join("source/deployed/Accounts.sol"),
        )
        .expect("verified Celo Accounts source"),
    );
    for fragment in [
        "function createAccount() public returns (bool)",
        "function setMetadataURL(string calldata metadataURL) external",
        "function setPaymentDelegation(address beneficiary, uint256 fraction) public",
        "function deletePaymentDelegation() public",
        "function authorizeSigner(address signer, bytes32 role) public",
        "function completeSignerAuthorization(address account, bytes32 role) public",
        "authorizedBy[msg.sender] = account;",
        "function removeDefaultSigner(bytes32 role) public",
        "function removeIndexedSigner(bytes32 role) public",
        "function removeSigner(address signer, bytes32 role) public",
        "function removeStorageRoot(uint256 index) external",
    ] {
        assert!(
            celo_source.contains(fragment),
            "verified Celo Accounts source lost `{fragment}`"
        );
    }

    let mut reference_factory_source: Option<String> = None;
    let mut reference_factory_abi: Option<Value> = None;
    for deployment in manifest["kiln"]["deployments"]
        .as_array()
        .expect("Kiln deployments")
    {
        let slug = required_str(deployment, "slug");
        let providers = deployment["providers"].as_array().expect("providers");
        let first = required_str(&providers[0], "name");
        let second = required_str(&providers[1], "name");
        let directory = format!("kiln-{slug}");
        let identity_a = response(&evidence, &directory, first, "identity");
        let identity_b = response(&evidence, &directory, second, "identity");
        assert_eq!(identity_a, identity_b, "{slug} identity providers disagree");
        assert_eq!(
            identity_a[&1].as_str().map(|text| u64::from_str_radix(
                text.trim_start_matches("0x"),
                16
            )
            .unwrap()),
            deployment["chain_id"].as_u64()
        );
        assert_eq!(
            identity_a[&2]["number"],
            required_str(deployment, "block_number_hex")
        );
        assert_eq!(
            identity_a[&2]["hash"],
            required_str(deployment, "block_hash")
        );
        assert_fixed_request(
            &evidence.join(format!("rpc/raw/{directory}/request-identity.json")),
            required_str(deployment, "block_hash"),
        );
        assert_fixed_request(
            &evidence.join(format!("rpc/raw/{directory}/request-runtime.json")),
            required_str(deployment, "block_hash"),
        );

        let runtime_a = response(&evidence, &directory, first, "runtime");
        let runtime_b = response(&evidence, &directory, second, "runtime");
        assert_eq!(runtime_a, runtime_b, "{slug} runtime providers disagree");
        let runtime = read_hex(&evidence.join(required_str(deployment, "runtime")));
        assert_eq!(decode_hex(runtime_a[&3].as_str().unwrap()), runtime);

        let verified = read_json(&evidence.join(required_str(deployment, "verification")));
        assert_eq!(verified["match"], "exact_match");
        assert_eq!(verified["proxyResolution"]["isProxy"], false);
        assert_eq!(
            decode_hex(required_str(
                &verified["runtimeBytecode"],
                "onchainBytecode"
            )),
            runtime
        );
        let source = required_str(&verified["sources"]["src/Factory.sol"], "content").to_string();
        assert_eq!(
            source.trim_end(),
            fs::read_to_string(evidence.join(format!("source/Factory.{slug}.sol")))
                .expect("archived Factory source")
                .trim_end()
        );
        let normalized_source = normalized(&source);
        for fragment in [
            "function createOperator(",
            "new Operator(_owner, _name, _operatorFee, _maximumOperatorFee, _recipients, _percents)",
            "function createSplitter(Operator operator, bytes32 salt)",
            "function createSplitterAndCall(Operator operator, bytes32 salt, address callAddress, bytes calldata data)",
            "callAddress.call{value: msg.value}(data)",
            "newSplitter.init(operator, msg.sender);",
        ] {
            assert!(
                normalized_source.contains(fragment),
                "verified {slug} Factory source lost `{fragment}`"
            );
        }
        let route_abi =
            read_json(&evidence.join(format!("abi/KilnFactory.routes.{slug}.abi.json")));
        assert_eq!(
            abi_signatures(&route_abi),
            BTreeSet::from([
                KILN_CANONICAL_ROUTES[0].to_string(),
                KILN_CANONICAL_ROUTES[1].to_string(),
                KILN_CANONICAL_ROUTES[2].to_string(),
                KILN_REFUSAL_CANONICAL.to_string(),
            ])
        );
        if let Some(reference) = &reference_factory_source {
            assert_eq!(&source, reference, "Kiln deployment source diverged");
        } else {
            reference_factory_source = Some(source);
        }
        if let Some(reference) = &reference_factory_abi {
            assert_eq!(&route_abi, reference, "Kiln route ABI diverged");
        } else {
            reference_factory_abi = Some(route_abi);
        }
    }

    let operator_source = normalized(
        &fs::read_to_string(evidence.join("source/Operator.ethereum.sol"))
            .expect("Operator source"),
    );
    for fragment in [
        "uint256 internal constant MAX_BPS = 10000;",
        "if (_maximumOperatorFee > MAX_BPS)",
        "if (_operatorFee > maximumOperatorFee)",
        "if (totalPercentsBps != MAX_BPS)",
    ] {
        assert!(
            operator_source.contains(fragment),
            "verified Operator source lost `{fragment}`"
        );
    }

    let wallet = &manifest["walletconnect"];
    assert_eq!(
        required_str(wallet, "eip1967_implementation_slot"),
        IMPLEMENTATION_SLOT
    );
    for request in ["identity", "runtime", "links"] {
        assert_fixed_request(
            &evidence.join(format!(
                "rpc/raw/walletconnect-optimism/request-{request}.json"
            )),
            required_str(wallet, "block_hash"),
        );
    }
    let identity_a = response(&evidence, "walletconnect-optimism", "op", "identity");
    let identity_b = response(
        &evidence,
        "walletconnect-optimism",
        "publicnode",
        "identity",
    );
    assert_eq!(
        identity_a, identity_b,
        "Optimism identity providers disagree"
    );
    assert_eq!(identity_a[&1], "0xa");
    assert_eq!(
        identity_a[&2]["number"],
        required_str(wallet, "block_number_hex")
    );
    assert_eq!(identity_a[&2]["hash"], required_str(wallet, "block_hash"));
    assert_eq!(
        abi_word_address(&identity_a[&3]),
        address(required_str(wallet, "implementation"))
    );

    let runtimes_a = response(&evidence, "walletconnect-optimism", "op", "runtime");
    let runtimes_b = response(&evidence, "walletconnect-optimism", "publicnode", "runtime");
    assert_eq!(
        runtimes_a, runtimes_b,
        "Optimism runtime providers disagree"
    );
    let proxy_runtime = read_hex(&evidence.join("runtime/StakeWeightProxy.optimism.hex"));
    let implementation_runtime =
        read_hex(&evidence.join("runtime/StakeWeight.implementation.optimism.hex"));
    assert_eq!(decode_hex(runtimes_a[&4].as_str().unwrap()), proxy_runtime);
    assert_eq!(
        decode_hex(runtimes_a[&5].as_str().unwrap()),
        implementation_runtime
    );
    assert_eq!(
        decode_hex(runtimes_a[&6].as_str().unwrap()),
        read_hex(&evidence.join("runtime/WalletConnectConfigProxy.optimism.hex"))
    );
    assert_eq!(
        decode_hex(runtimes_a[&7].as_str().unwrap()),
        read_hex(&evidence.join("runtime/L2WCTProxy.optimism.hex"))
    );

    let links_a = response(&evidence, "walletconnect-optimism", "op", "links");
    let links_b = response(&evidence, "walletconnect-optimism", "publicnode", "links");
    assert_eq!(links_a, links_b, "Optimism link providers disagree");
    assert_eq!(
        abi_word_address(&links_a[&8]),
        address(required_str(wallet, "config"))
    );
    assert_eq!(
        abi_word_address(&links_a[&9]),
        address(required_str(wallet, "token"))
    );
    assert_eq!(
        abi_string(&links_a[&10]),
        required_str(wallet, "token_symbol")
    );
    assert_eq!(
        abi_word_u64(&links_a[&11]),
        wallet["token_decimals"].as_u64().unwrap()
    );

    let proxy_verified = read_json(&evidence.join(required_str(wallet, "proxy_verification")));
    assert_eq!(proxy_verified["proxyResolution"]["isProxy"], true);
    assert_eq!(
        proxy_verified["proxyResolution"]["proxyType"],
        "EIP1967Proxy"
    );
    assert_eq!(
        required_str(
            &proxy_verified["proxyResolution"]["implementations"][0],
            "address"
        ),
        required_str(wallet, "implementation")
    );
    assert_eq!(
        decode_hex(required_str(
            &proxy_verified["runtimeBytecode"],
            "onchainBytecode"
        )),
        proxy_runtime
    );
    let implementation_verified =
        read_json(&evidence.join(required_str(wallet, "implementation_verification")));
    assert_eq!(
        decode_hex(required_str(
            &implementation_verified["runtimeBytecode"],
            "onchainBytecode"
        )),
        implementation_runtime
    );
    let stake_source = required_str(
        &implementation_verified["sources"]["src/StakeWeight.sol"],
        "content",
    );
    assert_eq!(
        stake_source.trim_end(),
        fs::read_to_string(evidence.join("source/StakeWeight.sol"))
            .expect("archived StakeWeight source")
            .trim_end()
    );
    let stake_source = normalized(stake_source);
    for fragment in [
        "function createLock(uint256 amount, uint256 unlockTime) external nonReentrant",
        "function depositFor(address for_, uint256 amount) external nonReentrant",
        "function increaseLockAmount(uint256 amount) external nonReentrant",
        "function increaseUnlockTime(uint256 newUnlockTime) external nonReentrant",
        "function updateLock(uint256 amount, uint256 unlockTime) external nonReentrant",
        "function withdrawAll() external nonReentrant",
        "unlockTime = _timestampToFloorWeek(unlockTime);",
        "newUnlockTime = _timestampToFloorWeek(newUnlockTime);",
        "return (timestamp / 1 weeks) * 1 weeks;",
        "IERC20(s.config.getL2wct()).safeTransferFrom(msg.sender, address(this), amount);",
    ] {
        assert!(
            stake_source.contains(fragment),
            "verified StakeWeight source lost `{fragment}`"
        );
    }
    assert_eq!(
        abi_signatures(&read_json(
            &evidence.join("abi/StakeWeight.routes.optimism.abi.json")
        )),
        WALLET_CANONICAL_ROUTES
            .iter()
            .chain(["config()"].iter())
            .map(|route| route.to_string())
            .collect()
    );
}

#[test]
fn account_factory_curations_admit_only_evidenced_routes_and_keep_refusals_known() {
    let root = workspace_root();
    let curation_manifest = read_json(&root.join("secure/data/erc7730/curations/manifest.json"));
    for relative in [CELO_DESCRIPTOR, KILN_DESCRIPTOR, WALLET_DESCRIPTOR] {
        let installed = fs::read(root.join("secure/data/erc7730-registry").join(relative))
            .expect("installed descriptor");
        let curated = fs::read(
            root.join("secure/data/erc7730/curations/files")
                .join(relative),
        )
        .expect("curated descriptor");
        assert_eq!(
            installed, curated,
            "installed curation diverged: {relative}"
        );
        let replacement = curation_manifest["replacements"]
            .as_array()
            .expect("curation replacements")
            .iter()
            .find(|entry| entry["path"].as_str() == Some(relative))
            .unwrap_or_else(|| panic!("missing replacement receipt: {relative}"));
        assert_eq!(
            required_str(replacement, "replacement_sha256"),
            sha256_hex(&curated)
        );
        assert_eq!(
            replacement["replacement_bytes"].as_u64(),
            Some(curated.len() as u64)
        );
    }

    let celo = read_json(
        &root
            .join("secure/data/erc7730-registry")
            .join(CELO_DESCRIPTOR),
    );
    assert_eq!(
        celo["_pqsigner"]["deploymentFormats"][0]["formats"],
        json!(CELO_NAMED_ROUTES)
    );
    assert_eq!(
        celo["_pqsigner"]["refusalOnlyFormats"],
        json!(CELO_REFUSAL_NAMED)
    );
    assert_eq!(
        celo["display"]["formats"]["removeAttestationSigner()"]["intent"],
        "Remove Attestation Signer"
    );
    assert_eq!(
        celo["display"]["formats"]["removeValidatorSigner()"]["intent"],
        "Remove Validator Signer"
    );
    let completing_fields = celo["display"]["formats"]
        ["completeSignerAuthorization(address account, bytes32 role)"]["fields"]
        .as_array()
        .expect("completion fields");
    assert!(completing_fields
        .iter()
        .any(|field| field["path"] == "@.from" && field["label"] == "Completing Signer"));

    let kiln = read_json(
        &root
            .join("secure/data/erc7730-registry")
            .join(KILN_DESCRIPTOR),
    );
    let kiln_admissions = kiln["_pqsigner"]["deploymentFormats"]
        .as_array()
        .expect("Kiln deployment formats");
    assert_eq!(kiln_admissions.len(), 2);
    for admission in kiln_admissions {
        assert_eq!(admission["formats"], json!(KILN_NAMED_ROUTES));
    }
    assert_eq!(
        kiln["_pqsigner"]["refusalOnlyFormats"],
        json!([KILN_REFUSAL_NAMED])
    );

    let wallet = read_json(
        &root
            .join("secure/data/erc7730-registry")
            .join(WALLET_DESCRIPTOR),
    );
    assert_eq!(
        wallet["_pqsigner"]["deploymentFormats"][0]["formats"],
        json!(WALLET_NAMED_ROUTES)
    );
    const FLOOR_WARNING: &str = "Requested time rounded down to whole weeks";
    for signature in [
        "createLock(uint256 amount, uint256 unlockTime)",
        "increaseUnlockTime(uint256 newUnlockTime)",
        "updateLock(uint256 amount, uint256 unlockTime)",
    ] {
        let fields = wallet["display"]["formats"][signature]["fields"]
            .as_array()
            .expect("WalletConnect time fields");
        assert!(fields.iter().any(|field| {
            field["label"] == "Requested unlock"
                && field["format"] == "date"
                && field["visible"] == "always"
        }));
        assert!(fields.iter().any(|field| {
            field.get("path").is_none()
                && field["label"] == "Effective unlock"
                && field["value"] == FLOOR_WARNING
                && field["format"] == "raw"
                && field["visible"] == "always"
        }));
    }
    for signature in [
        "createLock(uint256 amount, uint256 unlockTime)",
        "depositFor(address for_, uint256 amount)",
        "increaseLockAmount(uint256 amount)",
        "updateLock(uint256 amount, uint256 unlockTime)",
    ] {
        for field in wallet["display"]["formats"][signature]["fields"]
            .as_array()
            .expect("WalletConnect fields")
            .iter()
            .filter(|field| field["format"] == "tokenAmount")
        {
            assert_eq!(
                field["params"]["token"],
                "0xeF4461891DfB3AC8572cCf7C794664A8DD927945"
            );
        }
    }

    let catalogue = build_registry();
    let families = [
        (
            "calldata-celo_accounts.json",
            1usize,
            CELO_CANONICAL_ROUTES.as_slice(),
        ),
        (
            "calldata-kiln-fee-splitter-factory.json",
            2usize,
            KILN_CANONICAL_ROUTES.as_slice(),
        ),
        (
            "calldata-stakeweight.json",
            1usize,
            WALLET_CANONICAL_ROUTES.as_slice(),
        ),
    ];
    for (file_name, expected_leaves, routes) in families {
        let entries = catalogue
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(file_name)
            })
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), expected_leaves, "{file_name} leaf count");
        let expected_selectors = routes
            .iter()
            .map(|route| selector(route))
            .collect::<BTreeSet<_>>();
        for entry in entries {
            let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("curated IR");
            assert_eq!(
                cross_check_contract(&ir, entry.chain_id, &entry.contract),
                Ok(())
            );
            assert_eq!(
                ir.format_iter()
                    .map(|format| format.expect("format").selector)
                    .collect::<BTreeSet<_>>(),
                expected_selectors
            );
            for route in routes {
                let route_selector = selector(route);
                assert!(
                    catalogue.known_calls.contains(&(
                        entry.chain_id,
                        entry.contract,
                        route_selector
                    )),
                    "{file_name} admitted route left known-call inventory: {route}"
                );
            }
        }
    }

    let celo_mainnet = address("0x7d21685C17607338b313a7174bAb6620baD0aaB7");
    let celo_alfajores = address("0xed7f51A34B4e71fbE69B3091FcF879cD14bD73A9");
    for contract in [celo_mainnet, celo_alfajores] {
        for route in CELO_REFUSAL_CANONICAL {
            let route_selector = selector(route);
            assert!(
                catalogue.known_calls.contains(&(
                    if contract == celo_mainnet {
                        42_220
                    } else {
                        44_787
                    },
                    contract,
                    route_selector
                )),
                "Celo refusal left exact known-call inventory: {route}"
            );
            assert!(known_call_may_contain(
                &catalogue.known_calls_bloom,
                if contract == celo_mainnet {
                    42_220
                } else {
                    44_787
                },
                &contract,
                &route_selector
            ));
        }
    }
    assert!(
        !catalogue.entries.iter().any(|entry| {
            entry.chain_id == 44_787
                && entry.contract == celo_alfajores
                && entry.source.file_name().and_then(|name| name.to_str())
                    == Some("calldata-celo_accounts.json")
        }),
        "unevidenced Alfajores Accounts leaf must not render"
    );

    for (chain_id, contract) in [
        (1, address("0x8659EEFF31CFcff580D37AF8e7Af250F8998aA83")),
        (
            560_048,
            address("0x1A76bc69922744807E86375f8B8AB8A7cf18Eb7a"),
        ),
    ] {
        let refused_selector = selector(KILN_REFUSAL_CANONICAL);
        assert!(
            catalogue
                .known_calls
                .contains(&(chain_id, contract, refused_selector)),
            "Kiln nested-call refusal left known-call inventory"
        );
        assert!(known_call_may_contain(
            &catalogue.known_calls_bloom,
            chain_id,
            &contract,
            &refused_selector
        ));
    }

    let wallet_entry = catalogue
        .entries
        .iter()
        .find(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-stakeweight.json")
        })
        .expect("WalletConnect leaf");
    let wallet_ir = Erc7730Ir::parse(&wallet_entry.ir_bytes).expect("WalletConnect IR");
    let token = address("0xeF4461891DfB3AC8572cCf7C794664A8DD927945");
    for route in [
        "createLock(uint256,uint256)",
        "depositFor(address,uint256)",
        "increaseLockAmount(uint256)",
        "updateLock(uint256,uint256)",
    ] {
        let format = wallet_ir
            .find_format_by_selector(&selector(route))
            .expect("format table")
            .expect("WalletConnect route");
        for field in format.fields().map(|field| field.expect("field")) {
            if FormatOp::try_from(field.format_op) == Ok(FormatOp::TokenAmount) {
                let params = parse_params(&wallet_ir, field.param_off).expect("token params");
                assert_eq!(params.token, Some(&token));
            }
        }
    }
    for route in [
        "createLock(uint256,uint256)",
        "increaseUnlockTime(uint256)",
        "updateLock(uint256,uint256)",
    ] {
        let format = wallet_ir
            .find_format_by_selector(&selector(route))
            .expect("format table")
            .expect("WalletConnect time route");
        let fields = format
            .fields()
            .map(|field| field.expect("WalletConnect time field"))
            .collect::<Vec<_>>();
        assert!(fields.iter().any(|field| field.label == b"Requested unlock"));
        let warning = fields
            .iter()
            .find(|field| field.label == b"Effective unlock")
            .expect("compiled whole-week warning");
        assert_eq!(warning.path_off, 0);
        assert_eq!(
            FormatOp::try_from(warning.format_op),
            Ok(FormatOp::Raw)
        );
        let params =
            parse_params(&wallet_ir, warning.param_off).expect("whole-week warning params");
        assert_eq!(params.terminal_kind, Some(TerminalKind::ConstantText));
        assert_eq!(params.const_value, Some(FLOOR_WARNING.as_bytes()));
    }
}
