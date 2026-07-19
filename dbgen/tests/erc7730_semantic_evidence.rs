//! Offline provenance checks for externally audited ERC-7730 semantics.
//!
//! These tests deliberately do not contact RPC or explorer services. They
//! authenticate the fixed-block inputs archived under
//! tests/erc7730-semantic-evidence and bind them back to the production
//! descriptor deployments.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::binding::{cross_check_contract, BindingError};
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, Visibility};
use pqsigner_erc7730::render::params::parse as parse_params;
use pqsigner_erc7730::render::policy::TerminalKind;
use pqsigner_tx_core::hash::keccak256;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dbgen has a workspace parent")
        .to_path_buf()
}

fn stakewise_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/stakewise-claim-exited-assets")
}

fn lido_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/lido-wsteth-permit")
}

fn uniswap_evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/uniswap-router02-single-hop")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn decode_hex_text(text: &str) -> Vec<u8> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    hex::decode(compact.strip_prefix("0x").unwrap_or(&compact)).expect("valid hex evidence")
}

fn read_hex(path: &Path) -> Vec<u8> {
    decode_hex_text(
        &fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
}

fn required_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("manifest field {key} is a string"))
}

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_fragments_in_order(haystack: &str, fragments: &[&str]) {
    let mut remainder = haystack;
    for fragment in fragments {
        let offset = remainder
            .find(fragment)
            .unwrap_or_else(|| panic!("missing ordered source fragment: {fragment}"));
        remainder = &remainder[offset + fragment.len()..];
    }
}

fn decode_abi_string_result(text: &str) -> String {
    let bytes = decode_hex_text(text);
    assert!(bytes.len() >= 64, "ABI string result is truncated");
    assert_eq!(&bytes[..31], &[0u8; 31]);
    assert_eq!(bytes[31], 32, "ABI string data offset changed");
    assert_eq!(&bytes[32..63], &[0u8; 31]);
    let length = bytes[63] as usize;
    assert!(
        64 + length <= bytes.len(),
        "ABI string payload is truncated"
    );
    String::from_utf8(bytes[64..64 + length].to_vec()).expect("ABI string is UTF-8")
}

fn eip712_domain_separator(
    name: &str,
    version: &str,
    chain_id: u64,
    contract: &[u8; 20],
) -> [u8; 32] {
    let mut encoded = [0u8; 160];
    encoded[..32].copy_from_slice(&keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ));
    encoded[32..64].copy_from_slice(&keccak256(name.as_bytes()));
    encoded[64..96].copy_from_slice(&keccak256(version.as_bytes()));
    encoded[120..128].copy_from_slice(&chain_id.to_be_bytes());
    encoded[140..160].copy_from_slice(contract);
    keccak256(&encoded)
}

#[test]
fn stakewise_fixed_block_runtimes_match_the_archived_receipt() {
    let evidence = stakewise_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let signature = required_str(&manifest, "canonical_signature");
    assert_eq!(
        required_str(&manifest, "selector"),
        format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4]))
    );

    let artifacts = manifest["runtime_artifacts"]
        .as_object()
        .expect("runtime_artifacts object");
    let mut decoded = BTreeMap::<String, Vec<u8>>::new();
    for (name, spec) in artifacts {
        let bytes = read_hex(&evidence.join(required_str(spec, "file")));
        assert_eq!(
            bytes.len() as u64,
            spec["bytes"].as_u64().expect("runtime byte count"),
            "{name} byte count drifted"
        );
        assert_eq!(
            keccak_hex(&bytes),
            required_str(spec, "keccak256"),
            "{name} code hash drifted"
        );
        decoded.insert(name.clone(), bytes);
    }

    let slot = decode_hex_text(required_str(&manifest, "eip1967_implementation_slot"));
    let proxy = decoded.get("proxy").expect("proxy runtime");
    assert!(
        proxy.windows(slot.len()).any(|window| window == slot),
        "archived proxy runtime must embed the EIP-1967 implementation slot"
    );

    let implementation = decode_hex_text(required_str(&manifest, "implementation_address"));
    assert_eq!(implementation.len(), 20);
    let deployments = manifest["deployments"]
        .as_array()
        .expect("deployments array");
    assert_eq!(deployments.len(), 3);
    for deployment in deployments {
        let word = decode_hex_text(required_str(deployment, "implementation_slot_value"));
        assert_eq!(word.len(), 32);
        assert_eq!(&word[..12], &[0u8; 12]);
        assert_eq!(&word[12..], implementation.as_slice());
        assert!(decoded.contains_key(required_str(deployment, "implementation_runtime")));
    }

    let blocks = manifest["blocks"].as_array().expect("blocks array");
    assert_eq!(blocks.len(), 2);
    for block in blocks {
        assert_eq!(
            block["rpc_endpoints"]
                .as_array()
                .expect("RPC endpoint array")
                .len(),
            2,
            "each fixed block must have two independent observations"
        );
        assert_eq!(decode_hex_text(required_str(block, "hash")).len(), 32);
        assert_eq!(decode_hex_text(required_str(block, "state_root")).len(), 32);
    }

    let mut mainnet = decoded
        .get("implementation_mainnet")
        .expect("mainnet implementation")
        .clone();
    let mut hoodi = decoded
        .get("implementation_hoodi")
        .expect("Hoodi implementation")
        .clone();
    assert_eq!(mainnet.len(), hoodi.len());

    let ranges = manifest["cross_chain_runtime"]["variant_ranges"]
        .as_array()
        .expect("variant range array");
    assert_eq!(ranges.len(), 22, "variant-range inventory changed");
    let mut prior_end = 0usize;
    let mut label_counts = BTreeMap::<String, usize>::new();
    for range in ranges {
        let offset = range["offset"].as_u64().expect("range offset") as usize;
        let length = range["length"].as_u64().expect("range length") as usize;
        let end = offset.checked_add(length).expect("range end");
        assert!(
            offset >= prior_end,
            "variant ranges overlap or are unsorted"
        );
        assert!(end <= mainnet.len(), "variant range exceeds runtime");

        let expected_mainnet = decode_hex_text(required_str(range, "mainnet_hex"));
        let expected_hoodi = decode_hex_text(required_str(range, "hoodi_hex"));
        assert_eq!(expected_mainnet.len(), length);
        assert_eq!(expected_hoodi.len(), length);
        assert_eq!(&mainnet[offset..end], expected_mainnet.as_slice());
        assert_eq!(&hoodi[offset..end], expected_hoodi.as_slice());

        mainnet[offset..end].fill(0);
        hoodi[offset..end].fill(0);
        prior_end = end;
        *label_counts
            .entry(required_str(range, "label").to_owned())
            .or_default() += 1;
    }
    assert_eq!(
        label_counts,
        BTreeMap::from([
            ("chainId".to_owned(), 1),
            ("depositDataRegistry".to_owned(), 2),
            ("keeper".to_owned(), 5),
            ("osTokenConfig".to_owned(), 3),
            ("osTokenVaultController".to_owned(), 7),
            ("osTokenVaultEscrow".to_owned(), 1),
            ("sharedMevEscrow".to_owned(), 2),
            ("vaultsRegistry".to_owned(), 1),
        ])
    );
    assert_eq!(
        mainnet, hoodi,
        "implementation instruction bytes differ outside declared chain/address immutables"
    );
}

#[test]
fn stakewise_claim_source_abi_and_descriptors_agree_on_caller_semantics() {
    let root = workspace_root();
    let evidence = stakewise_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    let verified_source = &manifest["verified_source"];
    assert_eq!(verified_source["upstream_release"].as_str(), Some("v4.0.1"));
    assert_eq!(
        verified_source["upstream_commit"].as_str(),
        Some("c511cd912cb881f60cf2a32d6c5d5f533e5d04b5")
    );
    assert_eq!(
        verified_source["upstream_tree"].as_str(),
        Some("6185defc0ea2c9d5e72f02bd3e1411e13684b7fc")
    );
    assert_eq!(
        verified_source["openzeppelin_submodule_commit"].as_str(),
        Some("60b305a8f3ff0c7688f02ac470417b6bbf1c4d27")
    );
    assert_eq!(
        verified_source["archived_files_match_verified_explorer_sources"].as_bool(),
        Some(true)
    );

    let mut archived_sources = BTreeMap::<String, String>::new();
    for source in verified_source["files"]
        .as_array()
        .expect("verified source file array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read archived source");
        assert_eq!(sha256_hex(&bytes), required_str(source, "sha256"));
        archived_sources.insert(
            archive_file.to_owned(),
            String::from_utf8(bytes).expect("Solidity source is UTF-8"),
        );
    }
    let eth_vault = &archived_sources["source/EthVault.sol"];
    assert!(eth_vault.contains("VaultEnterExit"));
    assert!(
        !eth_vault.contains("function claimExitedAssets"),
        "the concrete EthVault must inherit, not override, the audited claim semantics"
    );

    let module = &archived_sources["source/VaultEnterExit.sol"];
    let semantics = manifest["claim_semantics"]
        .as_object()
        .expect("claim semantics object");
    for key in [
        "request_lookup",
        "request_delete",
        "residual_request_key",
        "transfer_recipient",
        "event_recipient",
    ] {
        assert!(
            module.contains(required_str(&Value::Object(semantics.clone()), key)),
            "archived implementation lost the {key} msg.sender binding"
        );
    }

    let interface: String = archived_sources["source/IVaultEnterExit.sol"]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(interface.contains(
        "function claimExitedAssets(uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex) external;"
    ));

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse route ABI");
    let entries = abi.as_array().expect("ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(entry["outputs"].as_array().map(Vec::len), Some(0));
    let input_types: Vec<_> = entry["inputs"]
        .as_array()
        .expect("ABI inputs")
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect();
    assert_eq!(input_types, ["uint256", "uint256", "uint256"]);
    let signature = format!(
        "{}({})",
        entry["name"].as_str().expect("ABI function name"),
        input_types.join(",")
    );
    assert_eq!(signature, required_str(&manifest, "canonical_signature"));

    let mut expected_by_descriptor = BTreeMap::<String, BTreeSet<(u64, String)>>::new();
    for deployment in manifest["deployments"]
        .as_array()
        .expect("deployment array")
    {
        expected_by_descriptor
            .entry(required_str(deployment, "descriptor").to_owned())
            .or_default()
            .insert((
                deployment["chain_id"].as_u64().expect("deployment chain"),
                required_str(deployment, "address").to_ascii_lowercase(),
            ));
    }
    assert_eq!(expected_by_descriptor.len(), 2);

    for (descriptor_path, expected_deployments) in expected_by_descriptor {
        let descriptor_bytes =
            fs::read(root.join(&descriptor_path)).expect("read curated descriptor");
        let registry_suffix = descriptor_path
            .strip_prefix("secure/data/erc7730/curations/files/")
            .expect("curation descriptor prefix");
        assert_eq!(
            descriptor_bytes,
            fs::read(
                root.join("secure/data/erc7730-registry")
                    .join(registry_suffix)
            )
            .expect("read vendored descriptor"),
            "curation and production descriptor copies diverged"
        );
        let descriptor: Value = serde_json::from_slice(&descriptor_bytes).expect("descriptor JSON");
        let actual_deployments: BTreeSet<_> = descriptor["context"]["contract"]["deployments"]
            .as_array()
            .expect("descriptor deployments")
            .iter()
            .map(|deployment| {
                (
                    deployment["chainId"].as_u64().expect("descriptor chain"),
                    deployment["address"]
                        .as_str()
                        .expect("descriptor address")
                        .to_ascii_lowercase(),
                )
            })
            .collect();
        assert_eq!(actual_deployments, expected_deployments);

        let format = &descriptor["display"]["formats"]
            ["claimExitedAssets(uint256 positionTicket, uint256 timestamp, uint256 exitQueueIndex)"];
        let fields = format["fields"].as_array().expect("claim display fields");
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0]["label"].as_str(), Some("Claim receiver"));
        assert_eq!(fields[0]["path"].as_str(), Some("@.from"));
        assert_eq!(fields[0]["format"].as_str(), Some("addressName"));
        assert_eq!(fields[0]["visible"].as_str(), Some("always"));
        assert_eq!(fields[1]["path"].as_str(), Some("#.positionTicket"));
        assert_eq!(fields[2]["path"].as_str(), Some("#.timestamp"));
        assert_eq!(fields[3]["path"].as_str(), Some("#.exitQueueIndex"));
        assert!(fields.iter().all(|field| field["visible"] == "always"));
    }
}

#[test]
fn stakewise_deposit_and_exit_source_abi_descriptors_and_ir_agree() {
    let root = workspace_root();
    let evidence = stakewise_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let additional = &manifest["additional_routes"];
    let routes = additional["routes"]
        .as_array()
        .expect("StakeWise additional routes array");
    let expected_routes = BTreeMap::from([
        ("deposit", ("deposit(address,address)", "0xf9609f08")),
        (
            "enterExitQueue",
            ("enterExitQueue(uint256,address)", "0x8ceab9aa"),
        ),
    ]);
    assert_eq!(
        routes
            .iter()
            .map(|route| required_str(route, "key"))
            .collect::<BTreeSet<_>>(),
        expected_routes.keys().copied().collect(),
        "StakeWise route inventory drifted"
    );

    let verified_source = &manifest["verified_source"];
    let mut archived_sources = BTreeMap::<String, String>::new();
    for source in verified_source["files"]
        .as_array()
        .expect("verified source file array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read archived source");
        assert_eq!(
            sha256_hex(&bytes),
            required_str(source, "sha256"),
            "archived source hash drifted for {archive_file}"
        );
        archived_sources.insert(
            archive_file.to_owned(),
            normalized_whitespace(&String::from_utf8(bytes).expect("Solidity source is UTF-8")),
        );
    }

    let staking = &archived_sources["source/VaultEthStaking.sol"];
    assert!(staking.contains(
        "function deposit(address receiver, address referrer) public payable virtual override returns (uint256 shares) { return _deposit(receiver, msg.value, referrer); }"
    ));
    assert!(staking.contains(
        "function _vaultAssets() internal view virtual override returns (uint256) { return address(this).balance; }"
    ));
    assert!(staking.contains(
        "function _transferVaultAssets(address receiver, uint256 assets) internal virtual override nonReentrant { return Address.sendValue(payable(receiver), assets); }"
    ));

    let interface = &archived_sources["source/IVaultEthStaking.sol"];
    assert!(interface.contains(
        "function deposit(address receiver, address referrer) external payable returns (uint256 shares);"
    ));

    let enter_exit = &archived_sources["source/VaultEnterExit.sol"];
    assert_fragments_in_order(
        enter_exit,
        &[
            "function _deposit(address to, uint256 assets, address referrer)",
            "if (to == address(0)) revert Errors.ZeroAddress();",
            "if (assets == 0) revert Errors.InvalidAssets();",
            "if (totalAssetsAfter > capacity()) revert Errors.CapacityExceeded();",
            "shares = _convertToShares(assets, Math.Rounding.Ceil);",
            "_mintShares(to, shares);",
            "emit Deposited(msg.sender, to, assets, shares, referrer);",
        ],
    );
    assert_fragments_in_order(
        enter_exit,
        &[
            "function _enterExitQueue(address user, uint256 shares, address receiver)",
            "if (shares == 0) revert Errors.InvalidShares();",
            "if (receiver == address(0)) revert Errors.ZeroAddress();",
            "if (!_isCollateralized())",
            "uint256 assets = convertToAssets(shares);",
            "_burnShares(user, shares);",
            "_transferVaultAssets(receiver, assets);",
            "return type(uint256).max;",
            "positionTicket = _exitQueue.getLatestTotalTickets() + _totalExitingTickets + queuedShares;",
            "_exitRequests[keccak256(abi.encode(receiver, block.timestamp, positionTicket))] = shares;",
            "_balances[user] -= shares;",
            "_queuedShares = SafeCast.toUint128(queuedShares + shares);",
            "emit ExitQueueEntered(user, receiver, positionTicket, shares);",
        ],
    );

    let eth_vault = &archived_sources["source/EthVault.sol"];
    assert!(eth_vault.contains(
        "function enterExitQueue(uint256 shares, address receiver) public virtual override(IVaultEnterExit, VaultEnterExit, VaultOsToken) returns (uint256 positionTicket) { return super.enterExitQueue(shares, receiver); }"
    ));
    let os_token = &archived_sources["source/VaultOsToken.sol"];
    assert_fragments_in_order(
        os_token,
        &[
            "function enterExitQueue(uint256 shares, address receiver)",
            "positionTicket = super.enterExitQueue(shares, receiver);",
            "_checkOsTokenPosition(msg.sender);",
            "function _checkOsTokenPosition(address user) internal view",
            "if (position.shares == 0) return;",
            "_checkHarvested();",
            "if (_calcMaxOsTokenShares(convertToAssets(_balances[user])) < position.shares)",
            "revert Errors.LowLtv();",
        ],
    );
    let state = &archived_sources["source/VaultState.sol"];
    assert!(state.contains("mapping(address => uint256) internal _balances;"));
    assert!(state.contains(
        "function getShares(address account) external view override returns (uint256) { return _balances[account]; }"
    ));
    assert!(state.contains(
        "function convertToAssets(uint256 shares) public view override returns (uint256 assets)"
    ));
    assert!(state.contains(
        "function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256 shares)"
    ));
    let immutables = &archived_sources["source/VaultImmutables.sol"];
    assert!(immutables.contains(
        "function _isCollateralized() internal view virtual returns (bool) { return IKeeperRewards(_keeper).isCollateralized(address(this)); }"
    ));

    let abi_spec = &additional["abi"];
    let abi_bytes = fs::read(evidence.join(required_str(abi_spec, "archive_file")))
        .expect("read StakeWise additional-route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    assert_eq!(
        required_str(abi_spec, "source_full_verified_abi_canonical_sha256"),
        required_str(&manifest["abi"], "full_verified_abi_canonical_sha256"),
        "additional-route ABI subset lost its pinned full-ABI receipt"
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse additional-route ABI");
    let abi_entries = abi.as_array().expect("additional-route ABI array");
    assert_eq!(abi_entries.len(), routes.len());

    let mut expected_by_descriptor = BTreeMap::<String, BTreeSet<(u64, String)>>::new();
    for deployment in manifest["deployments"]
        .as_array()
        .expect("deployment array")
    {
        expected_by_descriptor
            .entry(required_str(deployment, "descriptor").to_owned())
            .or_default()
            .insert((
                deployment["chain_id"].as_u64().expect("deployment chain"),
                required_str(deployment, "address").to_ascii_lowercase(),
            ));
    }

    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &root.join("secure/data/erc7730-registry/registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&root.join("secure/data/erc7730-registry")),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");

    for runtime_key in ["implementation_mainnet", "implementation_hoodi"] {
        let runtime_spec = &manifest["runtime_artifacts"][runtime_key];
        let runtime = read_hex(&evidence.join(required_str(runtime_spec, "file")));
        for route in routes {
            let selector = decode_hex_text(required_str(route, "selector"));
            let mut push4 = vec![0x63];
            push4.extend_from_slice(&selector);
            assert_eq!(
                runtime
                    .windows(push4.len())
                    .filter(|window| *window == push4.as_slice())
                    .count(),
                1,
                "{runtime_key} must retain exactly one PUSH4 dispatcher entry for {}",
                required_str(route, "canonical_signature")
            );
        }
    }

    let canonicalize = |authored: &str| {
        let (name, tail) = authored.split_once('(').expect("authored signature");
        let params = tail.strip_suffix(')').expect("signature close");
        let types: Vec<_> = params
            .split(',')
            .filter(|param| !param.trim().is_empty())
            .map(|param| {
                param
                    .split_ascii_whitespace()
                    .next()
                    .expect("authored input type")
            })
            .collect();
        format!("{name}({})", types.join(","))
    };

    for (descriptor_path, expected_deployments) in expected_by_descriptor {
        let descriptor_bytes =
            fs::read(root.join(&descriptor_path)).expect("read curated StakeWise descriptor");
        let registry_suffix = descriptor_path
            .strip_prefix("secure/data/erc7730/curations/files/")
            .expect("curation descriptor prefix");
        assert_eq!(
            descriptor_bytes,
            fs::read(
                root.join("secure/data/erc7730-registry")
                    .join(registry_suffix)
            )
            .expect("read vendored StakeWise descriptor"),
            "curation and production descriptor copies diverged"
        );
        let descriptor: Value =
            serde_json::from_slice(&descriptor_bytes).expect("StakeWise descriptor JSON");
        let actual_deployments: BTreeSet<_> = descriptor["context"]["contract"]["deployments"]
            .as_array()
            .expect("descriptor deployments")
            .iter()
            .map(|deployment| {
                (
                    deployment["chainId"].as_u64().expect("descriptor chain"),
                    deployment["address"]
                        .as_str()
                        .expect("descriptor address")
                        .to_ascii_lowercase(),
                )
            })
            .collect();
        assert_eq!(actual_deployments, expected_deployments);
        let formats = descriptor["display"]["formats"]
            .as_object()
            .expect("descriptor formats");

        let source_name = Path::new(registry_suffix)
            .file_name()
            .and_then(|name| name.to_str())
            .expect("descriptor file name");
        let matching_entries: Vec<_> = registry
            .entries
            .iter()
            .filter(|entry| {
                entry.source.file_name().and_then(|name| name.to_str()) == Some(source_name)
            })
            .collect();
        assert_eq!(matching_entries.len(), expected_deployments.len());

        for route in routes {
            let key = required_str(route, "key");
            let signature = required_str(route, "canonical_signature");
            let (_, expected_selector) = expected_routes
                .get(key)
                .unwrap_or_else(|| panic!("unexpected StakeWise route {key}"));
            assert_eq!(required_str(route, "selector"), *expected_selector);
            assert_eq!(
                format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4])),
                *expected_selector
            );

            let abi_matches: Vec<_> = abi_entries
                .iter()
                .filter(|entry| {
                    let Some(name) = entry["name"].as_str() else {
                        return false;
                    };
                    let Some(inputs) = entry["inputs"].as_array() else {
                        return false;
                    };
                    let types: Vec<_> = inputs
                        .iter()
                        .filter_map(|input| input["type"].as_str())
                        .collect();
                    format!("{name}({})", types.join(",")) == signature
                })
                .collect();
            assert_eq!(abi_matches.len(), 1, "exact additional-route ABI match");
            let abi_entry = abi_matches[0];
            assert_eq!(abi_entry["type"].as_str(), Some("function"));
            assert_eq!(
                abi_entry["stateMutability"].as_str(),
                Some(if key == "deposit" {
                    "payable"
                } else {
                    "nonpayable"
                })
            );
            assert_eq!(abi_entry["outputs"][0]["type"].as_str(), Some("uint256"));

            let descriptor_matches: Vec<_> = formats
                .iter()
                .filter(|(authored, _)| canonicalize(authored) == signature)
                .collect();
            assert_eq!(descriptor_matches.len(), 1, "exact descriptor route match");
            let (_, descriptor_format) = descriptor_matches[0];
            let descriptor_fields = descriptor_format["fields"]
                .as_array()
                .expect("descriptor fields");
            let displayed_paths: BTreeSet<_> = route["displayed_operand_paths"]
                .as_array()
                .expect("displayed operand paths")
                .iter()
                .map(|path| path.as_str().expect("displayed operand path"))
                .collect();
            assert_eq!(
                descriptor_fields
                    .iter()
                    .map(|field| field["path"].as_str().expect("descriptor field path"))
                    .collect::<BTreeSet<_>>(),
                displayed_paths,
                "{key} displayed operand inventory drifted"
            );
            if key == "enterExitQueue" {
                assert_eq!(descriptor_format["intent"].as_str(), Some("Exit vault"));
                assert_eq!(descriptor_fields.len(), 2);
                assert_eq!(
                    descriptor_fields[0]["label"].as_str(),
                    Some("Shares to exit")
                );
                assert_eq!(descriptor_fields[0]["format"].as_str(), Some("raw"));
                assert!(descriptor_fields[0]["params"].is_null());
                assert_eq!(
                    descriptor_fields[1]["label"].as_str(),
                    Some("Exit receiver")
                );
                assert_eq!(descriptor_fields[1]["format"].as_str(), Some("addressName"));
            }

            let selector: [u8; 4] = decode_hex_text(*expected_selector)
                .try_into()
                .expect("selector width");
            for entry in &matching_entries {
                let deployment = (entry.chain_id, format!("0x{}", hex::encode(entry.contract)));
                assert!(expected_deployments.contains(&deployment));
                let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("generated StakeWise IR parses");
                assert_eq!(
                    cross_check_contract(&ir, entry.chain_id, &entry.contract),
                    Ok(())
                );
                let ir_format = ir
                    .find_format_by_selector(&selector)
                    .expect("StakeWise format table parses")
                    .unwrap_or_else(|| panic!("{signature} remains admitted"));
                let ir_fields: Vec<_> = ir_format
                    .fields()
                    .map(|field| field.expect("generated StakeWise field parses"))
                    .collect();
                assert_eq!(ir_fields.len(), descriptor_fields.len());
                for (descriptor_field, ir_field) in descriptor_fields.iter().zip(ir_fields) {
                    let op = match descriptor_field["format"].as_str() {
                        Some("addressName") => FormatOp::AddressName,
                        Some("amount") => FormatOp::Amount,
                        Some("raw") => FormatOp::Raw,
                        other => panic!("unexpected StakeWise field formatter {other:?}"),
                    };
                    assert_eq!(
                        ir_field.label,
                        descriptor_field["label"].as_str().unwrap().as_bytes()
                    );
                    assert_eq!(FormatOp::try_from(ir_field.format_op), Ok(op));
                    let params = parse_params(&ir, ir_field.param_off).expect("field params parse");
                    assert_eq!(params.visibility, Visibility::Always);
                    let path = descriptor_field["path"]
                        .as_str()
                        .expect("descriptor field path");
                    assert_eq!(
                        params.terminal_kind,
                        Some(
                            if path.ends_with("receiver") || path.ends_with("referrer") {
                                TerminalKind::Address
                            } else {
                                TerminalKind::Unsigned
                            }
                        )
                    );
                    if key == "enterExitQueue" && path == "#.shares" {
                        assert!(params.token.is_none());
                        assert!(params.token_path.is_none());
                    }
                }
            }

            let effect = required_str(route, "successful_effect").to_ascii_lowercase();
            let residual = required_str(route, "state_residual").to_ascii_lowercase();
            if key == "deposit" {
                for needle in ["signed transaction value", "receiver", "referrer"] {
                    assert!(effect.contains(needle));
                }
                for needle in ["live", "share", "neither signed calldata nor displayed"] {
                    assert!(residual.contains(needle));
                }
            } else {
                for needle in ["msg.sender", "shares", "receiver", "collateralized"] {
                    assert!(effect.contains(needle));
                }
                for needle in ["collateralization", "ticket", "exchange rate", "live state"] {
                    assert!(residual.contains(needle));
                }
            }
        }
    }
}

#[test]
fn lido_wsteth_fixed_block_runtime_and_state_match_receipt() {
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    let signature = required_str(&manifest, "canonical_signature");
    let selector = &keccak256(signature.as_bytes())[..4];
    assert_eq!(
        required_str(&manifest, "selector"),
        format!("0x{}", hex::encode(selector))
    );
    assert_eq!(selector, [0xd5, 0x05, 0xac, 0xcf]);

    let deployment = &manifest["deployment"];
    assert_eq!(deployment["chain_id"].as_u64(), Some(1));
    let contract_bytes = decode_hex_text(required_str(deployment, "address"));
    let contract: [u8; 20] = contract_bytes.try_into().expect("wstETH address width");
    assert_eq!(
        hex::encode(contract),
        "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0"
    );
    assert_eq!(deployment["block_number"].as_u64(), Some(11_888_477));
    assert_eq!(deployment["deployer_nonce"].as_u64(), Some(4));
    assert_eq!(deployment["receipt_status"].as_u64(), Some(1));
    assert_eq!(
        required_str(deployment, "receipt_contract_address"),
        required_str(deployment, "address")
    );
    assert_eq!(deployment["creation_input_bytes"].as_u64(), Some(7_277));
    assert_eq!(
        decode_hex_text(required_str(deployment, "transaction_hash")).len(),
        32
    );
    assert_eq!(
        decode_hex_text(required_str(deployment, "creation_input_keccak256")).len(),
        32
    );
    assert_eq!(
        required_str(deployment, "constructor_argument_steth"),
        "0xae7ab96520de3a18e5e111b5eaab095312d7fe84"
    );

    for receipt in [deployment, &manifest["evidence_block"]] {
        let endpoints: BTreeSet<_> = receipt["rpc_endpoints"]
            .as_array()
            .expect("RPC endpoint array")
            .iter()
            .map(|endpoint| endpoint.as_str().expect("RPC endpoint string"))
            .collect();
        assert_eq!(
            endpoints.len(),
            2,
            "each receipt needs two independent RPC observations"
        );
        let hash_key = if receipt.get("block_hash").is_some() {
            "block_hash"
        } else {
            "hash"
        };
        assert_eq!(decode_hex_text(required_str(receipt, hash_key)).len(), 32);
    }
    let fixed_block = &manifest["evidence_block"];
    assert_eq!(fixed_block["number"].as_u64(), Some(25_566_776));
    assert_eq!(decode_hex_text(required_str(fixed_block, "hash")).len(), 32);
    assert_eq!(
        decode_hex_text(required_str(fixed_block, "state_root")).len(),
        32
    );

    let runtime_spec = &manifest["runtime"];
    let runtime = read_hex(&evidence.join(required_str(runtime_spec, "file")));
    assert_eq!(
        runtime.len() as u64,
        runtime_spec["bytes"].as_u64().expect("runtime byte count")
    );
    assert_eq!(
        keccak_hex(&runtime),
        required_str(runtime_spec, "keccak256")
    );
    assert!(
        runtime
            .windows(selector.len())
            .any(|window| window == selector),
        "archived runtime lost the permit selector"
    );
    assert_eq!(
        runtime_spec["explorer_deployed_bytecode_matches_artifact"].as_bool(),
        Some(true)
    );
    assert_eq!(
        decode_hex_text(required_str(runtime_spec, "eip1967_implementation_slot")).len(),
        32
    );
    assert_eq!(
        decode_hex_text(required_str(
            runtime_spec,
            "eip1967_implementation_slot_value"
        )),
        [0u8; 32],
        "fixed-block wstETH unexpectedly became an ERC-1967 proxy"
    );

    let calls = &manifest["fixed_block_calls"];
    for (name, canonical_signature) in [
        ("name", "name()"),
        ("symbol", "symbol()"),
        ("decimals", "decimals()"),
        ("steth", "stETH()"),
        ("domain_separator", "DOMAIN_SEPARATOR()"),
    ] {
        assert_eq!(
            required_str(&calls[name], "selector"),
            format!(
                "0x{}",
                hex::encode(&keccak256(canonical_signature.as_bytes())[..4])
            ),
            "{name} selector drifted"
        );
    }
    let token_name = decode_abi_string_result(required_str(&calls["name"], "result"));
    let token_symbol = decode_abi_string_result(required_str(&calls["symbol"], "result"));
    assert_eq!(token_name, required_str(&calls["name"], "decoded"));
    assert_eq!(token_symbol, required_str(&calls["symbol"], "decoded"));
    assert_eq!(token_name, "Wrapped liquid staked Ether 2.0");
    assert_eq!(token_symbol, "wstETH");

    let decimals = decode_hex_text(required_str(&calls["decimals"], "result"));
    assert_eq!(decimals.len(), 32);
    assert_eq!(&decimals[..31], &[0u8; 31]);
    assert_eq!(
        decimals[31] as u64,
        calls["decimals"]["decoded"]
            .as_u64()
            .expect("decoded decimals")
    );
    assert_eq!(decimals[31], 18);

    let steth_word = decode_hex_text(required_str(&calls["steth"], "result"));
    assert_eq!(steth_word.len(), 32);
    assert_eq!(&steth_word[..12], &[0u8; 12]);
    assert_eq!(
        &steth_word[12..],
        decode_hex_text(required_str(&calls["steth"], "decoded")).as_slice()
    );
    assert_eq!(
        required_str(&calls["steth"], "decoded"),
        required_str(deployment, "constructor_argument_steth")
    );

    let domain = decode_hex_text(required_str(&calls["domain_separator"], "result"));
    assert_eq!(
        domain,
        eip712_domain_separator(&token_name, "1", 1, &contract),
        "fixed-block domain separator does not bind the archived name, version, chain, and contract"
    );
}

#[test]
fn lido_wsteth_source_abi_descriptor_and_metadata_agree_on_permit_semantics() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let source_spec = &manifest["verified_source"];

    assert_eq!(
        source_spec["compiler"].as_str(),
        Some("0.6.12+commit.27d51765")
    );
    assert_eq!(source_spec["evm_version"].as_str(), Some("istanbul"));
    assert_eq!(source_spec["optimizer_enabled"].as_bool(), Some(true));
    assert_eq!(source_spec["optimizer_runs"].as_u64(), Some(200));
    assert_eq!(
        source_spec["upstream_commit"].as_str(),
        Some("2b46615a11dee77d4d22066f942f6c6afab9b87a")
    );
    assert_eq!(
        source_spec["upstream_tree"].as_str(),
        Some("b4e0ba7c36530d279ff0c4f18b1ae6e68a272da7")
    );
    assert_eq!(source_spec["openzeppelin_version"].as_str(), Some("3.4.0"));
    assert_eq!(
        source_spec["openzeppelin_tag_commit"].as_str(),
        Some("fa64a1ced0b70ab89073d5d0b6e01b0778f7e7d6")
    );
    assert_eq!(
        source_spec["archived_upstream_lines_present_in_verified_flattened_source"].as_bool(),
        Some(true)
    );

    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let upstream_bytes = fs::read(evidence.join(required_str(source_spec, "upstream_file")))
        .expect("read archived Lido source");
    assert_eq!(
        sha256_hex(&upstream_bytes),
        required_str(source_spec, "upstream_file_sha256")
    );
    let openzeppelin_bytes =
        fs::read(evidence.join(required_str(source_spec, "openzeppelin_file")))
            .expect("read archived OpenZeppelin source");
    assert_eq!(
        sha256_hex(&openzeppelin_bytes),
        required_str(source_spec, "openzeppelin_file_sha256")
    );

    let flattened = String::from_utf8(flattened_bytes).expect("flattened source is UTF-8");
    let flattened_lines: BTreeSet<_> = flattened.lines().map(str::trim).collect();
    for (label, source_bytes) in [
        ("official Lido WstETH", upstream_bytes),
        ("OpenZeppelin ERC20Permit", openzeppelin_bytes),
    ] {
        let source = String::from_utf8(source_bytes).expect("archived source is UTF-8");
        for line in source.lines().map(str::trim).filter(|line| {
            !line.is_empty() && !line.starts_with("// SPDX") && !line.starts_with("import ")
        }) {
            assert!(
                flattened_lines.contains(line),
                "{label} line is absent from the verified flattened source: {line}"
            );
        }
    }

    let permit_signature =
        "function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual override {";
    let permit_start = flattened
        .find(permit_signature)
        .expect("deployed permit implementation");
    let permit_tail = &flattened[permit_start..];
    let permit_end = permit_tail
        .find("function nonces(address owner)")
        .expect("permit implementation end");
    let permit = normalized_whitespace(&permit_tail[..permit_end]);
    assert_fragments_in_order(
        &permit,
        &[
            r#"require(block.timestamp <= deadline, "ERC20Permit: expired deadline");"#,
            "_PERMIT_TYPEHASH, owner, spender, value, _nonces[owner].current(), deadline",
            "bytes32 hash = _hashTypedDataV4(structHash);",
            "address signer = ECDSA.recover(hash, v, r, s);",
            r#"require(signer == owner, "ERC20Permit: invalid signature");"#,
            "_nonces[owner].increment();",
            "_approve(owner, spender, value);",
        ],
    );
    let flattened_normalized = normalized_whitespace(&flattened);
    assert!(flattened_normalized
        .contains(r#"constructor(string memory name) internal EIP712(name, "1") { }"#));
    assert_fragments_in_order(
        &flattened_normalized,
        &[
            "contract WstETH is ERC20Permit",
            r#"constructor(IStETH _stETH) public ERC20Permit("Wrapped liquid staked Ether 2.0") ERC20("Wrapped liquid staked Ether 2.0", "wstETH")"#,
            "stETH = _stETH;",
        ],
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read permit ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse permit ABI");
    let entries = abi.as_array().expect("permit ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["name"].as_str(), Some("permit"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    assert_eq!(entry["outputs"].as_array().map(Vec::len), Some(0));
    let inputs = entry["inputs"].as_array().expect("permit ABI inputs");
    let input_names: Vec<_> = inputs
        .iter()
        .map(|input| input["name"].as_str().expect("ABI input name"))
        .collect();
    let input_types: Vec<_> = inputs
        .iter()
        .map(|input| input["type"].as_str().expect("ABI input type"))
        .collect();
    assert_eq!(
        input_names,
        ["owner", "spender", "value", "deadline", "v", "r", "s"]
    );
    assert_eq!(
        input_types,
        ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"]
    );
    let abi_signature = format!("permit({})", input_types.join(","));
    assert_eq!(
        abi_signature,
        required_str(&manifest, "canonical_signature")
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor"),
        "curated and installed Lido descriptors diverged"
    );
    let descriptor: Value = serde_json::from_slice(&curated_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor deployment address")
            .to_ascii_lowercase(),
        required_str(&manifest["deployment"], "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["wstETHaddress"]
            .as_str()
            .expect("wstETH token constant")
            .to_ascii_lowercase(),
        required_str(&manifest["deployment"], "address")
    );

    let formats = descriptor["display"]["formats"]
        .as_object()
        .expect("descriptor formats");
    let permits: Vec<_> = formats
        .iter()
        .filter(|(signature, _)| signature.starts_with("permit("))
        .collect();
    assert_eq!(permits.len(), 1);
    let fields = permits[0].1["fields"]
        .as_array()
        .expect("permit display fields");
    let expected_fields = [
        ("Owner", "#.owner", "addressName"),
        ("Spender", "#.spender", "addressName"),
        ("Amount", "#.value", "tokenAmount"),
        ("Deadline", "#.deadline", "date"),
        ("V", "#.v", "raw"),
        ("R", "#.r", "raw"),
        ("S", "#.s", "raw"),
    ];
    assert_eq!(fields.len(), expected_fields.len());
    for (field, (label, path, format)) in fields.iter().zip(expected_fields) {
        assert_eq!(field["label"].as_str(), Some(label));
        assert_eq!(field["path"].as_str(), Some(path));
        assert_eq!(field["format"].as_str(), Some(format));
        assert_eq!(field["visible"].as_str(), Some("always"));
    }
    let manifest_paths: Vec<_> = descriptor_spec["permit_operand_paths"]
        .as_array()
        .expect("manifest operand paths")
        .iter()
        .map(|path| path.as_str().expect("manifest operand path"))
        .collect();
    let descriptor_paths: Vec<_> = fields
        .iter()
        .map(|field| field["path"].as_str().expect("descriptor field path"))
        .collect();
    assert_eq!(descriptor_paths, manifest_paths);

    let records = dbgen::load_erc20_records(&root.join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let metadata: Vec<_> = records
        .iter()
        .filter(|record| {
            record.chain_id == 1
                && record
                    .address
                    .eq_ignore_ascii_case(required_str(&manifest["deployment"], "address"))
        })
        .collect();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].name, "Wrapped liquid staked Ether 2.0");
    assert_eq!(metadata[0].symbol, "wstETH");
    assert_eq!(metadata[0].decimals, 18);

    let registry_root = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &policy,
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    assert_eq!(
        (registry_entry.chain_id, registry_entry.contract),
        (1, {
            let mut address = [0u8; 20];
            address.copy_from_slice(&decode_hex_text(required_str(
                &manifest["deployment"],
                "address",
            )));
            address
        })
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated Lido IR");
    assert_eq!(
        cross_check_contract(&ir, 1, &registry_entry.contract),
        Ok(())
    );
    assert_eq!(
        cross_check_contract(&ir, 10, &registry_entry.contract),
        Err(BindingError::ChainIdMismatch)
    );
    let mut wrong_contract = registry_entry.contract;
    wrong_contract[19] ^= 1;
    assert_eq!(
        cross_check_contract(&ir, 1, &wrong_contract),
        Err(BindingError::ContractMismatch)
    );
    let permit_selector: [u8; 4] =
        keccak256(required_str(&manifest, "canonical_signature").as_bytes())[..4]
            .try_into()
            .expect("permit selector width");
    let format = ir
        .find_format_by_selector(&permit_selector)
        .expect("Lido format table parses")
        .expect("Lido permit remains admitted");
    assert_eq!(format.fields().count(), 7);

    assert!(manifest["residuals"]
        .as_array()
        .expect("residual array")
        .iter()
        .any(|residual| residual
            .as_str()
            .is_some_and(|text| text.contains("nonce") && text.contains("not signed calldata"))));
}

#[test]
fn lido_wsteth_wrap_source_abi_descriptor_and_metadata_agree_on_input_semantics() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let deployment = &manifest["deployment"];
    let source_spec = &manifest["verified_source"];
    let wrap_spec = &manifest["additional_routes"]["wrap"];
    let signature = required_str(wrap_spec, "canonical_signature");

    assert_eq!(signature, "wrap(uint256)");
    let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("wrap selector width");
    assert_eq!(selector, [0xea, 0x59, 0x8c, 0xb0]);
    assert_eq!(required_str(wrap_spec, "selector"), "0xea598cb0");

    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let upstream_bytes = fs::read(evidence.join(required_str(source_spec, "upstream_file")))
        .expect("read archived official Lido source");
    assert_eq!(
        sha256_hex(&upstream_bytes),
        required_str(source_spec, "upstream_file_sha256")
    );

    for (label, source_bytes) in [
        ("verified flattened", flattened_bytes),
        ("official Lido", upstream_bytes),
    ] {
        let source = String::from_utf8(source_bytes).expect("wrap source is UTF-8");
        let wrap_start = source
            .find("function wrap(uint256 _stETHAmount) external returns (uint256) {")
            .unwrap_or_else(|| panic!("{label} wrap implementation"));
        let wrap_tail = &source[wrap_start..];
        let wrap_end = wrap_tail
            .find("function unwrap(uint256 _wstETHAmount)")
            .unwrap_or_else(|| panic!("{label} wrap implementation end"));
        let wrap = normalized_whitespace(&wrap_tail[..wrap_end]);
        assert_fragments_in_order(
            &wrap,
            &[
                r#"require(_stETHAmount > 0, "wstETH: can't wrap zero stETH");"#,
                "uint256 wstETHAmount = stETH.getSharesByPooledEth(_stETHAmount);",
                "_mint(msg.sender, wstETHAmount);",
                "stETH.transferFrom(msg.sender, address(this), _stETHAmount);",
                "return wstETHAmount;",
            ],
        );
    }

    let abi_spec = &wrap_spec["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read wrap ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse wrap ABI");
    let entries = abi.as_array().expect("wrap ABI array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["type"].as_str(), Some("function"));
    assert_eq!(entry["name"].as_str(), Some("wrap"));
    assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
    let inputs = entry["inputs"].as_array().expect("wrap ABI inputs");
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0]["name"].as_str(), Some("_stETHAmount"));
    assert_eq!(inputs[0]["type"].as_str(), Some("uint256"));
    let outputs = entry["outputs"].as_array().expect("wrap ABI outputs");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["type"].as_str(), Some("uint256"));
    assert_eq!(
        format!(
            "{}({})",
            entry["name"].as_str().unwrap(),
            inputs[0]["type"].as_str().unwrap()
        ),
        signature
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor"),
        "curated and installed Lido descriptors diverged"
    );
    let descriptor: Value = serde_json::from_slice(&curated_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor address")
            .to_ascii_lowercase(),
        required_str(deployment, "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["stETHaddress"]
            .as_str()
            .expect("stETH constant")
            .to_ascii_lowercase(),
        required_str(deployment, "constructor_argument_steth")
    );

    let format = &descriptor["display"]["formats"]["wrap(uint256 _stETHAmount)"];
    assert_eq!(format["intent"].as_str(), Some("Wrap stETH"));
    let fields = format["fields"].as_array().expect("wrap display fields");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0]["label"].as_str(), Some("stETH amount"));
    assert_eq!(fields[0]["path"].as_str(), Some("#._stETHAmount"));
    assert_eq!(fields[0]["format"].as_str(), Some("tokenAmount"));
    assert_eq!(fields[0]["visible"].as_str(), Some("always"));
    assert_eq!(
        fields[0]["params"]["token"].as_str(),
        Some("$.metadata.constants.stETHaddress")
    );
    let displayed_paths: Vec<_> = wrap_spec["displayed_operand_paths"]
        .as_array()
        .expect("wrap displayed paths")
        .iter()
        .map(|path| path.as_str().expect("wrap displayed path"))
        .collect();
    assert_eq!(displayed_paths, ["#._stETHAmount"]);

    let records = dbgen::load_erc20_records(&root.join("secure/data/erc20.json"))
        .expect("load production ERC20 metadata");
    let steth: Vec<_> = records
        .iter()
        .filter(|record| {
            record.chain_id == 1
                && record
                    .address
                    .eq_ignore_ascii_case(required_str(deployment, "constructor_argument_steth"))
        })
        .collect();
    assert_eq!(steth.len(), 1);
    assert_eq!(steth[0].name, "Liquid staked Ether 2.0");
    assert_eq!(steth[0].symbol, "stETH");
    assert_eq!(steth[0].decimals, 18);

    let registry_root = root.join("secure/data/erc7730-registry");
    let policy = root.join("secure/data/erc7730/policy.toml");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &policy,
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    assert_eq!(registry_entry.chain_id, 1);
    assert_eq!(
        hex::encode(registry_entry.contract),
        required_str(deployment, "address").trim_start_matches("0x")
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated Lido IR");
    let format = ir
        .find_format_by_selector(&selector)
        .expect("Lido format table parses")
        .expect("Lido wrap remains admitted");
    let fields: Vec<_> = format
        .fields()
        .map(|field| field.expect("generated wrap field parses"))
        .collect();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].label, b"stETH amount");
    assert_eq!(
        FormatOp::try_from(fields[0].format_op),
        Ok(FormatOp::TokenAmount)
    );
    let params = parse_params(&ir, fields[0].param_off).expect("wrap field params parse");
    assert_eq!(params.visibility, Visibility::Always);
    assert_eq!(params.terminal_kind, Some(TerminalKind::Unsigned));
    assert_eq!(params.integer_width_bytes, Some(32));
    assert_eq!(
        params.token.map(hex::encode),
        Some(
            required_str(deployment, "constructor_argument_steth")
                .trim_start_matches("0x")
                .to_owned()
        )
    );

    let output_residual = required_str(wrap_spec, "output_residual");
    assert!(output_residual.contains("live stETH share state"));
    assert!(output_residual.contains("not signed calldata"));
}

#[test]
fn lido_wsteth_remaining_routes_source_abi_descriptor_and_ir_agree() {
    let root = workspace_root();
    let evidence = lido_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    let deployment = &manifest["deployment"];
    let remaining = &manifest["additional_routes"]["remaining"];
    let routes = remaining["routes"]
        .as_array()
        .expect("remaining routes array");

    let expected_routes = BTreeMap::from([
        ("approve", "0x095ea7b3"),
        ("decreaseAllowance", "0xa457c2d7"),
        ("increaseAllowance", "0x39509351"),
        ("transfer", "0xa9059cbb"),
        ("transferFrom", "0x23b872dd"),
        ("unwrap", "0xde0e9a3e"),
    ]);
    let actual_keys: BTreeSet<_> = routes
        .iter()
        .map(|route| required_str(route, "key"))
        .collect();
    assert_eq!(
        actual_keys,
        expected_routes.keys().copied().collect(),
        "remaining route inventory drifted"
    );

    let source_spec = &manifest["verified_source"];
    let flattened_bytes =
        fs::read(evidence.join(required_str(source_spec, "archived_flattened_file")))
            .expect("read archived flattened source");
    assert_eq!(
        sha256_hex(&flattened_bytes),
        required_str(source_spec, "archived_flattened_sha256")
    );
    let flattened = normalized_whitespace(
        &String::from_utf8(flattened_bytes).expect("flattened source is UTF-8"),
    );
    for helper_semantics in [
        r#"function _transfer(address sender, address recipient, uint256 amount) internal virtual { require(sender != address(0), "ERC20: transfer from the zero address"); require(recipient != address(0), "ERC20: transfer to the zero address"); _beforeTokenTransfer(sender, recipient, amount); _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance"); _balances[recipient] = _balances[recipient].add(amount); emit Transfer(sender, recipient, amount); }"#,
        r#"function _burn(address account, uint256 amount) internal virtual { require(account != address(0), "ERC20: burn from the zero address"); _beforeTokenTransfer(account, address(0), amount); _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance"); _totalSupply = _totalSupply.sub(amount); emit Transfer(account, address(0), amount); }"#,
        r#"function _approve(address owner, address spender, uint256 amount) internal virtual { require(owner != address(0), "ERC20: approve from the zero address"); require(spender != address(0), "ERC20: approve to the zero address"); _allowances[owner][spender] = amount; emit Approval(owner, spender, amount); }"#,
    ] {
        assert!(flattened.contains(helper_semantics));
    }
    assert_eq!(
        flattened
            .matches("function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }")
            .count(),
        1,
        "wstETH must retain the single empty inherited transfer hook"
    );

    let runtime = read_hex(&evidence.join(required_str(&manifest["runtime"], "file")));
    let abi_spec = &remaining["abi"];
    let abi_bytes = fs::read(evidence.join(required_str(abi_spec, "archive_file")))
        .expect("read remaining-route ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    assert_eq!(
        required_str(abi_spec, "source_full_verified_abi_canonical_sha256"),
        required_str(&manifest["abi"], "full_verified_abi_canonical_sha256"),
        "remaining-route ABI subset lost its pinned full-ABI source receipt"
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse remaining-route ABI");
    let abi_entries = abi.as_array().expect("remaining-route ABI array");
    assert_eq!(abi_entries.len(), routes.len());

    let descriptor_spec = &manifest["descriptor"];
    let descriptor_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Lido descriptor");
    assert_eq!(
        descriptor_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Lido descriptor")
    );
    let descriptor: Value =
        serde_json::from_slice(&descriptor_bytes).expect("parse Lido descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert_eq!(deployments.len(), 1);
    assert_eq!(deployments[0]["chainId"].as_u64(), Some(1));
    assert_eq!(
        deployments[0]["address"]
            .as_str()
            .expect("descriptor deployment")
            .to_ascii_lowercase(),
        required_str(deployment, "address")
    );
    assert_eq!(
        descriptor["metadata"]["constants"]["wstETHaddress"]
            .as_str()
            .expect("wstETH token constant")
            .to_ascii_lowercase(),
        required_str(deployment, "address")
    );
    let descriptor_formats = descriptor["display"]["formats"]
        .as_object()
        .expect("descriptor formats");

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str()) == Some("calldata-wstETH.json")
        })
        .collect();
    assert_eq!(entries.len(), 1);
    let registry_entry = entries[0];
    let contract: [u8; 20] = decode_hex_text(required_str(deployment, "address"))
        .try_into()
        .expect("wstETH contract width");
    assert_eq!(
        (registry_entry.chain_id, registry_entry.contract),
        (1, contract)
    );
    let ir = Erc7730Ir::parse(&registry_entry.ir_bytes).expect("parse generated wstETH IR");
    assert_eq!(cross_check_contract(&ir, 1, &contract), Ok(()));

    let canonicalize = |authored: &str| {
        let (name, tail) = authored.split_once('(').expect("authored signature");
        let params = tail.strip_suffix(')').expect("signature close");
        let types: Vec<_> = params
            .split(',')
            .filter(|param| !param.trim().is_empty())
            .map(|param| {
                param
                    .split_ascii_whitespace()
                    .next()
                    .expect("authored input type")
            })
            .collect();
        format!("{name}({})", types.join(","))
    };

    for route in routes {
        let key = required_str(route, "key");
        let signature = required_str(route, "canonical_signature");
        let expected_selector = expected_routes
            .get(key)
            .unwrap_or_else(|| panic!("unexpected remaining route {key}"));
        assert_eq!(required_str(route, "selector"), *expected_selector);
        let selector: [u8; 4] = keccak256(signature.as_bytes())[..4]
            .try_into()
            .expect("selector width");
        assert_eq!(
            format!("0x{}", hex::encode(selector)),
            *expected_selector,
            "{key} selector drifted"
        );
        assert!(
            runtime
                .windows(selector.len())
                .any(|candidate| candidate == selector),
            "runtime lost {signature}"
        );

        let source_semantics = match key {
            "approve" => "function approve(address spender, uint256 amount) public virtual override returns (bool) { _approve(_msgSender(), spender, amount); return true; }",
            "decreaseAllowance" => r#"function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) { _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero")); return true; }"#,
            "increaseAllowance" => "function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) { _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue)); return true; }",
            "transfer" => "function transfer(address recipient, uint256 amount) public virtual override returns (bool) { _transfer(_msgSender(), recipient, amount); return true; }",
            "transferFrom" => r#"function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) { _transfer(sender, recipient, amount); _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance")); return true; }"#,
            "unwrap" => r#"function unwrap(uint256 _wstETHAmount) external returns (uint256) { require(_wstETHAmount > 0, "wstETH: zero amount unwrap not allowed"); uint256 stETHAmount = stETH.getPooledEthByShares(_wstETHAmount); _burn(msg.sender, _wstETHAmount); stETH.transfer(msg.sender, stETHAmount); return stETHAmount; }"#,
            _ => unreachable!("route inventory checked above"),
        };
        assert!(
            flattened.contains(source_semantics),
            "verified source semantics drifted for {signature}"
        );

        let descriptor_matches: Vec<_> = descriptor_formats
            .iter()
            .filter(|(authored, _)| canonicalize(authored) == signature)
            .collect();
        assert_eq!(descriptor_matches.len(), 1, "descriptor route match");
        let (authored_signature, descriptor_format) = descriptor_matches[0];
        let (_, tail) = authored_signature
            .split_once('(')
            .expect("authored signature");
        let authored_inputs: Vec<_> = tail
            .strip_suffix(')')
            .expect("signature close")
            .split(',')
            .map(|param| {
                let mut parts = param.split_ascii_whitespace();
                let input_type = parts.next().expect("descriptor input type");
                let name = parts.next().expect("descriptor input name");
                assert!(parts.next().is_none(), "unexpected descriptor input token");
                (name, input_type)
            })
            .collect();

        let abi_matches: Vec<_> = abi_entries
            .iter()
            .filter(|entry| {
                let Some(name) = entry["name"].as_str() else {
                    return false;
                };
                let Some(inputs) = entry["inputs"].as_array() else {
                    return false;
                };
                let types: Vec<_> = inputs
                    .iter()
                    .filter_map(|input| input["type"].as_str())
                    .collect();
                format!("{name}({})", types.join(",")) == signature
            })
            .collect();
        assert_eq!(abi_matches.len(), 1, "exact ABI route match");
        let abi_entry = abi_matches[0];
        assert_eq!(abi_entry["type"].as_str(), Some("function"));
        assert_eq!(abi_entry["stateMutability"].as_str(), Some("nonpayable"));
        let abi_inputs: Vec<_> = abi_entry["inputs"]
            .as_array()
            .expect("ABI inputs")
            .iter()
            .map(|input| {
                (
                    input["name"].as_str().expect("ABI input name"),
                    input["type"].as_str().expect("ABI input type"),
                )
            })
            .collect();
        assert_eq!(abi_inputs, authored_inputs, "{key} ABI operands drifted");
        let outputs = abi_entry["outputs"].as_array().expect("ABI outputs");
        assert_eq!(outputs.len(), 1);
        assert_eq!(
            outputs[0]["type"].as_str(),
            Some(if key == "unwrap" { "uint256" } else { "bool" })
        );

        let descriptor_fields = descriptor_format["fields"]
            .as_array()
            .expect("descriptor fields");
        let displayed_paths: Vec<_> = route["displayed_operand_paths"]
            .as_array()
            .expect("displayed operand paths")
            .iter()
            .map(|path| path.as_str().expect("displayed operand path"))
            .collect();
        assert_eq!(
            displayed_paths,
            descriptor_fields
                .iter()
                .map(|field| field["path"].as_str().expect("descriptor field path"))
                .collect::<Vec<_>>(),
            "{key} operand coverage drifted"
        );

        let ir_format = ir
            .find_format_by_selector(&selector)
            .expect("wstETH format table parses")
            .expect("remaining wstETH route remains admitted");
        let ir_fields: Vec<_> = ir_format
            .fields()
            .map(|field| field.expect("generated route field parses"))
            .collect();
        assert_eq!(ir_fields.len(), descriptor_fields.len());

        for (descriptor_field, ir_field) in descriptor_fields.iter().zip(ir_fields) {
            let path = descriptor_field["path"]
                .as_str()
                .expect("descriptor field path");
            let (label, op, kind) = match path {
                "#.spender" => ("Spender", FormatOp::AddressName, TerminalKind::Address),
                "#.recipient" => ("Recipient", FormatOp::AddressName, TerminalKind::Address),
                "#.sender" => ("Sender", FormatOp::AddressName, TerminalKind::Address),
                "#.amount" | "#.addedValue" | "#.subtractedValue" => {
                    ("Amount", FormatOp::TokenAmount, TerminalKind::Unsigned)
                }
                "#._wstETHAmount" => (
                    "wstETH amount",
                    FormatOp::TokenAmount,
                    TerminalKind::Unsigned,
                ),
                _ => panic!("unexpected remaining-route operand path {path}"),
            };
            assert_eq!(descriptor_field["label"].as_str(), Some(label));
            assert_eq!(descriptor_field["visible"].as_str(), Some("always"));
            assert_eq!(
                descriptor_field["format"].as_str(),
                Some(if op == FormatOp::AddressName {
                    "addressName"
                } else {
                    "tokenAmount"
                })
            );
            assert_eq!(ir_field.label, label.as_bytes());
            assert_eq!(FormatOp::try_from(ir_field.format_op), Ok(op));
            let params = parse_params(&ir, ir_field.param_off).expect("route params parse");
            assert_eq!(params.visibility, Visibility::Always);
            assert_eq!(params.terminal_kind, Some(kind));
            if op == FormatOp::TokenAmount {
                assert_eq!(params.integer_width_bytes, Some(32));
                assert_eq!(
                    descriptor_field["params"]["token"].as_str(),
                    Some("$.metadata.constants.wstETHaddress")
                );
                assert_eq!(params.token.map(hex::encode), Some(hex::encode(contract)));
                let threshold_expected = matches!(
                    (key, path),
                    ("approve", "#.amount") | ("increaseAllowance", "#.addedValue")
                );
                if threshold_expected {
                    let mut threshold = [0u8; 32];
                    threshold[0] = 0x80;
                    assert_eq!(
                        descriptor_field["params"]["threshold"].as_str(),
                        Some("0x8000000000000000000000000000000000000000000000000000000000000000")
                    );
                    assert_eq!(
                        descriptor_field["params"]["message"].as_str(),
                        Some("Unlimited")
                    );
                    assert_eq!(
                        params.threshold.map(|value| value.as_slice()),
                        Some(threshold.as_slice())
                    );
                    assert_eq!(params.message, Some(b"Unlimited".as_slice()));
                } else {
                    assert!(params.threshold.is_none());
                    assert!(params.message.is_none());
                }
            } else {
                assert!(params.token.is_none());
            }
        }

        let (effect_needles, residual_needles): (&[&str], &[&str]) = match key {
            "approve" => (
                &["sets", "allowance", "signed amount"],
                &["prior allowance", "ordering"],
            ),
            "decreaseAllowance" => (
                &["allowance", "minus", "signed subtractedvalue"],
                &["resulting allowances", "live state", "not signed calldata"],
            ),
            "increaseAllowance" => (
                &["allowance", "plus", "signed addedvalue"],
                &["resulting allowances", "live state", "not signed calldata"],
            ),
            "transfer" => (
                &["exactly", "msg.sender", "recipient"],
                &["balance", "success"],
            ),
            "transferFrom" => (
                &["sender", "recipient", "reduces", "allowance"],
                &[
                    "allowance",
                    "live state",
                    "neither signed calldata",
                    "nor displayed",
                ],
            ),
            "unwrap" => (
                &["burn", "wsteth", "steth"],
                &["live", "steth", "not signed calldata"],
            ),
            _ => unreachable!("route inventory checked above"),
        };
        for (field, needles) in [
            ("successful_effect", effect_needles),
            ("state_residual", residual_needles),
        ] {
            let text = required_str(route, field).to_ascii_lowercase();
            for needle in needles {
                assert!(
                    text.contains(needle),
                    "{key} {field} must record {needle:?}"
                );
            }
        }
    }
}

#[test]
fn uniswap_router02_evidence_binds_fail_closed_single_hop_exclusion() {
    let root = workspace_root();
    let evidence = uniswap_evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));

    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        manifest["policy"]["outcome"].as_str(),
        Some("fail_closed_exclusion")
    );
    assert_eq!(
        manifest["verified_source"]["upstream_release"].as_str(),
        Some("v1.1.0")
    );
    assert_eq!(
        manifest["verified_source"]["annotated_tag_object"].as_str(),
        Some("535ee984afa8e32a0206d372ecbc5f6186360f27")
    );
    assert_eq!(
        manifest["verified_source"]["upstream_commit"].as_str(),
        Some("8fe4f086cee7c08f0bdb6ebe20c9ab615921c65f")
    );
    assert_eq!(
        manifest["verified_source"]["upstream_tree"].as_str(),
        Some("84ed2b9297023bf6fce8ae90b057abf030d8c65f")
    );
    assert_eq!(
        manifest["verified_source"]
            ["archived_files_match_official_release_and_verified_explorer_sources"]
            .as_bool(),
        Some(true)
    );

    let deployment = &manifest["deployment"];
    assert_eq!(deployment["chain_id"].as_u64(), Some(1));
    assert_eq!(deployment["block_number"].as_u64(), Some(13_804_681));
    assert_eq!(deployment["deployer_nonce"].as_u64(), Some(14));
    assert_eq!(deployment["receipt_status"].as_u64(), Some(1));
    assert_eq!(
        required_str(deployment, "receipt_contract_address"),
        required_str(deployment, "address")
    );
    assert_eq!(deployment["creation_input_bytes"].as_u64(), Some(25_013));
    for receipt in [deployment, &manifest["evidence_block"]] {
        assert_eq!(
            receipt["rpc_endpoints"]
                .as_array()
                .expect("RPC endpoint array")
                .len(),
            2
        );
        let hash_key = if receipt.get("block_hash").is_some() {
            "block_hash"
        } else {
            "hash"
        };
        assert_eq!(decode_hex_text(required_str(receipt, hash_key)).len(), 32);
        assert_eq!(
            decode_hex_text(required_str(receipt, "state_root")).len(),
            32
        );
    }

    let contract: [u8; 20] = decode_hex_text(required_str(deployment, "address"))
        .try_into()
        .expect("Router02 address width");
    assert_eq!(
        hex::encode(contract),
        "68b3465833fb72a70ecdf485e0e4c7bd8665fc45"
    );

    let route_specs = manifest["policy"]["excluded_routes"]
        .as_array()
        .expect("excluded route array");
    assert_eq!(route_specs.len(), 2);
    let mut expected_routes = BTreeMap::<String, [u8; 4]>::new();
    for route in route_specs {
        let signature = required_str(route, "canonical_signature");
        let selector: [u8; 4] = decode_hex_text(required_str(route, "selector"))
            .try_into()
            .expect("selector width");
        assert_eq!(&keccak256(signature.as_bytes())[..4], selector.as_slice());
        expected_routes.insert(signature.to_owned(), selector);
    }
    assert_eq!(
        expected_routes,
        BTreeMap::from([
            (
                "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"
                    .to_owned(),
                [0x04, 0xe4, 0x5a, 0xaf],
            ),
            (
                "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))"
                    .to_owned(),
                [0x50, 0x23, 0xb4, 0xdf],
            ),
        ])
    );

    let runtime_spec = &manifest["runtime"];
    let runtime = read_hex(&evidence.join(required_str(runtime_spec, "file")));
    assert_eq!(
        runtime.len() as u64,
        runtime_spec["bytes"].as_u64().expect("runtime byte count")
    );
    assert_eq!(sha256_hex(&runtime), required_str(runtime_spec, "sha256"));
    assert_eq!(
        keccak_hex(&runtime),
        required_str(runtime_spec, "keccak256")
    );
    for (signature, selector) in &expected_routes {
        assert!(
            runtime
                .windows(selector.len())
                .any(|window| window == selector),
            "archived runtime lost {signature}"
        );
    }
    for (slot_key, value_key) in [
        (
            "eip1967_implementation_slot",
            "eip1967_implementation_slot_value",
        ),
        ("eip1967_beacon_slot", "eip1967_beacon_slot_value"),
    ] {
        assert_eq!(
            decode_hex_text(required_str(runtime_spec, slot_key)).len(),
            32
        );
        assert_eq!(
            decode_hex_text(required_str(runtime_spec, value_key)),
            [0u8; 32]
        );
    }

    let source_spec = &manifest["verified_source"];
    let mut archived_sources = BTreeMap::<String, String>::new();
    for source in source_spec["files"]
        .as_array()
        .expect("verified source file array")
    {
        let archive_file = required_str(source, "archive_file");
        let bytes = fs::read(evidence.join(archive_file)).expect("read archived source");
        assert_eq!(sha256_hex(&bytes), required_str(source, "sha256"));
        archived_sources.insert(
            archive_file.to_owned(),
            String::from_utf8(bytes).expect("Solidity source is UTF-8"),
        );
    }
    assert_eq!(archived_sources.len(), 4);

    let concrete = normalized_whitespace(&archived_sources["source/SwapRouter02.sol"]);
    assert!(concrete.contains(
        "contract SwapRouter02 is ISwapRouter02, V2SwapRouter, V3SwapRouter, ApproveAndCall, MulticallExtended, SelfPermit"
    ));

    let constants = normalized_whitespace(&archived_sources["source/Constants.sol"]);
    assert!(constants.contains("uint256 internal constant CONTRACT_BALANCE = 0;"));
    assert!(constants.contains("address internal constant MSG_SENDER = address(1);"));
    assert!(constants.contains("address internal constant ADDRESS_THIS = address(2);"));

    let interface = normalized_whitespace(&archived_sources["source/IV3SwapRouter.sol"]);
    assert!(interface
        .contains("Setting `amountIn` to 0 will cause the contract to look up its own balance"));
    assert!(interface.contains(
        "function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);"
    ));
    assert!(interface.contains(
        "function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn);"
    ));

    let router = normalized_whitespace(&archived_sources["source/V3SwapRouter.sol"]);
    assert!(router.matches(
        "if (recipient == Constants.MSG_SENDER) recipient = msg.sender; else if (recipient == Constants.ADDRESS_THIS) recipient = address(this);"
    ).count() >= 2);
    assert_fragments_in_order(
        &router,
        &[
            "function exactInputSingle(ExactInputSingleParams memory params)",
            "if (params.amountIn == Constants.CONTRACT_BALANCE) {",
            "params.amountIn = IERC20(params.tokenIn).balanceOf(address(this));",
            "payer: hasAlreadyPaid ? address(this) : msg.sender",
            "require(amountOut >= params.amountOutMinimum, 'Too little received');",
        ],
    );
    assert_fragments_in_order(
        &router,
        &[
            "function exactOutputInternal(",
            "uint256 amountOutReceived;",
            "(amountIn, amountOutReceived) =",
            "if (sqrtPriceLimitX96 == 0) require(amountOutReceived == amountOut);",
            "function exactOutputSingle(ExactOutputSingleParams calldata params)",
            "require(amountIn <= params.amountInMaximum, 'Too much requested');",
        ],
    );

    let abi_spec = &manifest["abi"];
    let abi_bytes =
        fs::read(evidence.join(required_str(abi_spec, "archive_file"))).expect("read Router02 ABI");
    assert_eq!(
        sha256_hex(&abi_bytes),
        required_str(abi_spec, "archive_file_sha256")
    );
    let abi: Value = serde_json::from_slice(&abi_bytes).expect("parse Router02 ABI");
    let entries = abi.as_array().expect("Router02 ABI array");
    assert_eq!(entries.len(), 2);
    let mut abi_signatures = BTreeSet::new();
    for entry in entries {
        assert_eq!(entry["type"].as_str(), Some("function"));
        assert_eq!(entry["stateMutability"].as_str(), Some("payable"));
        let inputs = entry["inputs"].as_array().expect("route ABI inputs");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["name"].as_str(), Some("params"));
        assert_eq!(inputs[0]["type"].as_str(), Some("tuple"));
        let component_types: Vec<_> = inputs[0]["components"]
            .as_array()
            .expect("tuple components")
            .iter()
            .map(|component| component["type"].as_str().expect("component type"))
            .collect();
        assert_eq!(
            component_types,
            ["address", "address", "uint24", "address", "uint256", "uint256", "uint160"]
        );
        let signature = format!(
            "{}(({}))",
            entry["name"].as_str().expect("function name"),
            component_types.join(",")
        );
        assert!(expected_routes.contains_key(&signature));
        abi_signatures.insert(signature);
        let outputs = entry["outputs"].as_array().expect("route ABI outputs");
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["type"].as_str(), Some("uint256"));
    }
    assert_eq!(
        abi_signatures,
        expected_routes.keys().cloned().collect::<BTreeSet<_>>()
    );

    let descriptor_spec = &manifest["descriptor"];
    let curated_bytes = fs::read(root.join(required_str(descriptor_spec, "curated_file")))
        .expect("read curated Router02 descriptor");
    assert_eq!(
        sha256_hex(&curated_bytes),
        required_str(descriptor_spec, "sha256")
    );
    assert_eq!(
        curated_bytes,
        fs::read(root.join(required_str(descriptor_spec, "vendored_file")))
            .expect("read vendored Router02 descriptor"),
        "curated and installed Router02 descriptors diverged"
    );
    let descriptor: Value =
        serde_json::from_slice(&curated_bytes).expect("parse Router02 descriptor");
    let deployments = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("descriptor deployments");
    assert!(deployments.iter().any(|candidate| {
        candidate["chainId"].as_u64() == Some(1)
            && candidate["address"].as_str().is_some_and(|address| {
                address.eq_ignore_ascii_case(required_str(deployment, "address"))
            })
    }));
    let sentinel = required_str(descriptor_spec, "sender_address_sentinel");
    for route in route_specs {
        let format_key = required_str(route, "descriptor_format_key");
        let fields = descriptor["display"]["formats"][format_key]["fields"]
            .as_array()
            .expect("single-hop display fields");
        let recipients: Vec<_> = fields
            .iter()
            .filter(|field| field["path"].as_str() == Some("params.recipient"))
            .collect();
        assert_eq!(recipients.len(), 1);
        let sender_addresses = recipients[0]["params"]["senderAddress"]
            .as_array()
            .expect("senderAddress annotation");
        assert_eq!(sender_addresses.len(), 1);
        assert_eq!(sender_addresses[0].as_str(), Some(sentinel));
    }

    let registry_root = root.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&root.join("secure/data/erc20.json"))
        .expect("build production ERC20 capability corpus");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &root.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    assert!(
        registry.entries.iter().all(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                != Some("calldata-UniswapV3Router02.json")
        }),
        "Router02 must emit no production descriptor leaf"
    );
    for (signature, selector) in expected_routes {
        assert!(
            registry.known_calls.contains(&(1, contract, selector)),
            "{signature} must remain an exact known-call tuple"
        );
    }
}
