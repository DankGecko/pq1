//! Offline provenance and semantic checks for the PQ1-admitted Morpho Blue routes.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use dbgen::erc7730::build_db_tolerant_with_erc20_capabilities;
use pqsigner_erc7730::ir::{Erc7730Ir, FormatOp, PathOp, Visibility};
use pqsigner_erc7730::render::params::{parse as parse_params, DYNAMIC_KIND_BYTES};
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

fn evidence_root() -> PathBuf {
    workspace_root().join("tests/erc7730-semantic-evidence/morpho-blue")
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
        .unwrap_or_else(|| panic!("manifest field {key} is a string"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(bytes)))
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

fn normalized_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalized_solidity_function(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("missing Solidity signature: {signature}"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("function body opens");
    let mut depth = 0usize;
    let mut end = None;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("balanced Solidity braces");
                if depth == 0 {
                    end = Some(open + offset + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let code = source[start..end.expect("complete Solidity function")]
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    normalized_whitespace(&code)
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

#[test]
fn morpho_blue_deployments_build_and_rendered_semantics_are_exactly_bound() {
    let workspace = workspace_root();
    let evidence = evidence_root();
    let manifest = read_json(&evidence.join("manifest.json"));
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(
        required_str(&manifest["upstream"], "repository"),
        "https://github.com/morpho-org/morpho-blue"
    );
    assert_eq!(
        required_str(&manifest["upstream"], "commit"),
        "55d2d99304fb3fb930c688462ae2ccabb1d533ad"
    );
    assert_eq!(
        required_str(&manifest["upstream"], "tree"),
        "d965742101dfb21cd22ec262324a016184f0bfb2"
    );

    for artifact in manifest["upstream"]["source_files"]
        .as_array()
        .expect("Morpho source file array")
    {
        let path = evidence.join(required_str(artifact, "path"));
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(sha256_hex(&bytes), required_str(artifact, "sha256"));
    }
    for (section, path_key, hash_key) in [
        (&manifest["abi"], "path", "sha256"),
        (&manifest["fixed_block_receipt"], "path", "sha256"),
    ] {
        let path = evidence.join(required_str(section, path_key));
        assert_eq!(
            sha256_hex(&fs::read(path).expect("read receipted Morpho artifact")),
            required_str(section, hash_key)
        );
    }
    let metadata_path = evidence.join(required_str(&manifest["build"], "metadata_file"));
    assert_eq!(
        sha256_hex(&fs::read(metadata_path).expect("read forge metadata")),
        required_str(&manifest["build"], "metadata_file_sha256")
    );

    let descriptor_path = workspace.join(required_str(&manifest["descriptor"], "vendored_file"));
    let descriptor_bytes = fs::read(&descriptor_path).expect("read curated Morpho descriptor");
    assert_eq!(
        sha256_hex(&descriptor_bytes),
        required_str(&manifest["descriptor"], "sha256")
    );
    let descriptor: Value =
        serde_json::from_slice(&descriptor_bytes).expect("parse curated Morpho descriptor");
    let descriptor_deployments: BTreeSet<_> = descriptor["context"]["contract"]["deployments"]
        .as_array()
        .expect("Morpho descriptor deployments")
        .iter()
        .map(|deployment| {
            (
                deployment["chainId"].as_u64().expect("Morpho chain id"),
                deployment["address"]
                    .as_str()
                    .expect("Morpho address")
                    .trim_start_matches("0x")
                    .to_ascii_lowercase(),
            )
        })
        .collect();
    assert_eq!(
        descriptor_deployments,
        BTreeSet::from([
            (1u64, "bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb".to_owned()),
            (
                8_453u64,
                "bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb".to_owned(),
            ),
        ])
    );

    let abi = read_json(&evidence.join(required_str(&manifest["abi"], "path")));
    let abi_entries = abi.as_array().expect("Morpho ABI array");
    assert_eq!(abi_entries.len(), 6);
    assert_eq!(
        abi_entries
            .iter()
            .map(|entry| entry["name"].as_str().expect("ABI function name"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "borrow",
            "repay",
            "supply",
            "supplyCollateral",
            "withdraw",
            "withdrawCollateral",
        ])
    );
    for entry in abi_entries {
        assert_eq!(entry["stateMutability"].as_str(), Some("nonpayable"));
        let market = &entry["inputs"][0];
        assert_eq!(market["name"].as_str(), Some("marketParams"));
        assert_eq!(market["type"].as_str(), Some("tuple"));
        assert_eq!(
            market["components"]
                .as_array()
                .expect("market components")
                .iter()
                .map(|component| component["name"].as_str().expect("market member"))
                .collect::<Vec<_>>(),
            ["loanToken", "collateralToken", "oracle", "irm", "lltv"]
        );
    }

    let build_spec = &manifest["build"]["deployed_runtime"];
    let build_path = evidence.join(required_str(build_spec, "file"));
    let build_file = fs::read(&build_path).expect("read official build runtime");
    assert_eq!(
        sha256_hex(&build_file),
        required_str(build_spec, "file_sha256")
    );
    let build_runtime = read_hex(&build_path);
    assert_eq!(
        build_runtime.len() as u64,
        build_spec["bytes"].as_u64().expect("build bytes")
    );
    assert_eq!(
        sha256_hex(&build_runtime),
        required_str(build_spec, "decoded_sha256")
    );
    assert_eq!(
        keccak_hex(&build_runtime),
        required_str(build_spec, "keccak256")
    );
    let immutable_refs: Vec<(usize, usize)> = manifest["build"]["immutable_references"]
        .as_array()
        .expect("immutable references")
        .iter()
        .map(|reference| {
            (
                reference["start"].as_u64().expect("immutable start") as usize,
                reference["length"].as_u64().expect("immutable length") as usize,
            )
        })
        .collect();
    assert_eq!(immutable_refs, [(6282, 32), (9401, 32)]);

    let receipt = read_json(&evidence.join(required_str(&manifest["fixed_block_receipt"], "path")));
    let zero_slot = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let mut domain_separators = Vec::new();
    for deployment in manifest["deployments"]
        .as_array()
        .expect("Morpho deployment evidence")
    {
        let chain_id = deployment["chain_id"].as_u64().expect("deployment chain");
        let runtime_spec = &deployment["runtime"];
        let runtime_path = evidence.join(required_str(runtime_spec, "file"));
        let runtime_file = fs::read(&runtime_path).expect("read deployed runtime");
        assert_eq!(
            sha256_hex(&runtime_file),
            required_str(runtime_spec, "file_sha256")
        );
        let runtime = read_hex(&runtime_path);
        assert_eq!(
            runtime.len() as u64,
            runtime_spec["bytes"].as_u64().expect("runtime bytes")
        );
        assert_eq!(
            sha256_hex(&runtime),
            required_str(runtime_spec, "decoded_sha256")
        );
        assert_eq!(
            keccak_hex(&runtime),
            required_str(runtime_spec, "keccak256")
        );

        let domain_separator = decode_hex_text(required_str(deployment, "domain_separator"));
        assert_eq!(domain_separator.len(), 32);
        let mut masked = runtime.clone();
        for &(start, length) in &immutable_refs {
            assert_eq!(&runtime[start..start + length], domain_separator);
            masked[start..start + length].fill(0);
        }
        assert_eq!(
            masked, build_runtime,
            "chain {chain_id} differs outside forge-declared immutables"
        );
        domain_separators.push(domain_separator);

        let network = receipt["networks"]
            .as_array()
            .expect("RPC networks")
            .iter()
            .find(|network| network["chain_id"].as_u64() == Some(chain_id))
            .unwrap_or_else(|| panic!("missing RPC network {chain_id}"));
        assert_eq!(
            network["block"].as_str(),
            deployment["evidence_block"]["number_hex"].as_str()
        );
        assert_eq!(
            network["runtime"]["keccak256"].as_str(),
            runtime_spec["keccak256"].as_str()
        );
        let observations = network["observations"]
            .as_array()
            .expect("RPC observations");
        assert_eq!(observations.len(), 2);
        assert_ne!(
            observations[0]["endpoint"].as_str(),
            observations[1]["endpoint"].as_str()
        );
        for observation in observations {
            assert_eq!(
                observation["header"]["hash"].as_str(),
                deployment["evidence_block"]["hash"].as_str()
            );
            assert_eq!(
                observation["header"]["state_root"].as_str(),
                deployment["evidence_block"]["state_root"].as_str()
            );
            assert_eq!(
                observation["code"]["keccak256"].as_str(),
                runtime_spec["keccak256"].as_str()
            );
            for slot in ["implementation", "admin", "beacon"] {
                assert_eq!(
                    observation["proxy_slot_results"][slot].as_str(),
                    Some(zero_slot)
                );
            }
        }
    }
    assert_eq!(domain_separators.len(), 2);
    assert_ne!(domain_separators[0], domain_separators[1]);

    let utils = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/UtilsLib.sol")).expect("read UtilsLib"),
    );
    assert!(utils.contains("z := xor(iszero(x), iszero(y))"));
    let market_params = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/MarketParamsLib.sol"))
            .expect("read MarketParamsLib"),
    );
    assert!(market_params.contains("MARKET_PARAMS_BYTES_LENGTH = 5 * 32"));
    assert!(market_params
        .contains("marketParamsId := keccak256(marketParams, MARKET_PARAMS_BYTES_LENGTH)"));
    let shares_math = normalized_whitespace(
        &fs::read_to_string(evidence.join("source/SharesMathLib.sol")).expect("read SharesMathLib"),
    );
    for conversion in ["toSharesDown", "toAssetsDown", "toSharesUp", "toAssetsUp"] {
        assert!(shares_math.contains(&format!("function {conversion}(")));
    }

    let morpho = fs::read_to_string(evidence.join("source/Morpho.sol")).expect("read Morpho");
    let borrow = normalized_solidity_function(&morpho, "function borrow(");
    assert_fragments_in_order(
        &borrow,
        &[
            "require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);",
            "require(_isSenderAuthorized(onBehalf), ErrorsLib.UNAUTHORIZED);",
            "if (assets > 0) shares = assets.toSharesUp(market[id].totalBorrowAssets, market[id].totalBorrowShares);",
            "else assets = shares.toAssetsDown(market[id].totalBorrowAssets, market[id].totalBorrowShares);",
            "position[id][onBehalf].borrowShares += shares.toUint128();",
            "require(_isHealthy(marketParams, id, onBehalf), ErrorsLib.INSUFFICIENT_COLLATERAL);",
            "IERC20(marketParams.loanToken).safeTransfer(receiver, assets);",
        ],
    );
    let withdraw = normalized_solidity_function(&morpho, "function withdraw(");
    assert_fragments_in_order(
        &withdraw,
        &[
            "require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);",
            "require(_isSenderAuthorized(onBehalf), ErrorsLib.UNAUTHORIZED);",
            "if (assets > 0) shares = assets.toSharesUp(market[id].totalSupplyAssets, market[id].totalSupplyShares);",
            "else assets = shares.toAssetsDown(market[id].totalSupplyAssets, market[id].totalSupplyShares);",
            "position[id][onBehalf].supplyShares -= shares;",
            "IERC20(marketParams.loanToken).safeTransfer(receiver, assets);",
        ],
    );
    let withdraw_collateral = normalized_solidity_function(&morpho, "function withdrawCollateral(");
    assert_fragments_in_order(
        &withdraw_collateral,
        &[
            "require(assets != 0, ErrorsLib.ZERO_ASSETS);",
            "require(_isSenderAuthorized(onBehalf), ErrorsLib.UNAUTHORIZED);",
            "position[id][onBehalf].collateral -= assets.toUint128();",
            "require(_isHealthy(marketParams, id, onBehalf), ErrorsLib.INSUFFICIENT_COLLATERAL);",
            "IERC20(marketParams.collateralToken).safeTransfer(receiver, assets);",
        ],
    );
    let authorized = normalized_solidity_function(&morpho, "function _isSenderAuthorized(");
    assert!(
        authorized.contains("return msg.sender == onBehalf || isAuthorized[onBehalf][msg.sender];")
    );
    let supply = normalized_solidity_function(&morpho, "function supply(");
    assert_fragments_in_order(
        &supply,
        &[
            "require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);",
            "require(onBehalf != address(0), ErrorsLib.ZERO_ADDRESS);",
            "if (assets > 0) shares = assets.toSharesDown(market[id].totalSupplyAssets, market[id].totalSupplyShares);",
            "else assets = shares.toAssetsUp(market[id].totalSupplyAssets, market[id].totalSupplyShares);",
            "position[id][onBehalf].supplyShares += shares;",
            "if (data.length > 0) IMorphoSupplyCallback(msg.sender).onMorphoSupply(assets, data);",
            "IERC20(marketParams.loanToken).safeTransferFrom(msg.sender, address(this), assets);",
        ],
    );
    let repay = normalized_solidity_function(&morpho, "function repay(");
    assert_fragments_in_order(
        &repay,
        &[
            "require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);",
            "require(onBehalf != address(0), ErrorsLib.ZERO_ADDRESS);",
            "if (assets > 0) shares = assets.toSharesDown(market[id].totalBorrowAssets, market[id].totalBorrowShares);",
            "else assets = shares.toAssetsUp(market[id].totalBorrowAssets, market[id].totalBorrowShares);",
            "position[id][onBehalf].borrowShares -= shares.toUint128();",
            "if (data.length > 0) IMorphoRepayCallback(msg.sender).onMorphoRepay(assets, data);",
            "IERC20(marketParams.loanToken).safeTransferFrom(msg.sender, address(this), assets);",
        ],
    );
    let supply_collateral = normalized_solidity_function(&morpho, "function supplyCollateral(");
    assert_fragments_in_order(
        &supply_collateral,
        &[
            "require(assets != 0, ErrorsLib.ZERO_ASSETS);",
            "require(onBehalf != address(0), ErrorsLib.ZERO_ADDRESS);",
            "position[id][onBehalf].collateral += assets.toUint128();",
            "if (data.length > 0) IMorphoSupplyCollateralCallback(msg.sender).onMorphoSupplyCollateral(assets, data);",
            "IERC20(marketParams.collateralToken).safeTransferFrom(msg.sender, address(this), assets);",
        ],
    );

    let routes = manifest["routes"].as_array().expect("Morpho routes");
    assert_eq!(routes.len(), 6);
    assert_eq!(
        routes
            .iter()
            .map(|route| required_str(route, "name"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "borrow",
            "repay",
            "supply",
            "supplyCollateral",
            "withdraw",
            "withdrawCollateral",
        ])
    );
    for route in routes {
        let signature = required_str(route, "canonical_signature");
        assert_eq!(
            format!("0x{}", hex::encode(&keccak256(signature.as_bytes())[..4])),
            required_str(route, "selector")
        );
    }
    let callback_policy = &manifest["callback_policy"];
    assert_eq!(required_str(callback_policy, "display"), "Callback: none");
    assert!(
        required_str(callback_policy, "admitted_condition").contains("length word is exactly zero")
    );
    assert!(required_str(callback_policy, "admitted_condition")
        .contains("padded end is exactly calldata EOF"));
    assert!(required_str(callback_policy, "refusal").contains("non-empty callback payload"));
    assert!(required_str(callback_policy, "refusal").contains("refuses before signing pages"));
    let callback_routes = callback_policy["routes"]
        .as_array()
        .expect("Morpho exact-empty callback routes");
    assert_eq!(callback_routes.len(), 3);
    assert_eq!(
        callback_routes
            .iter()
            .map(|route| (required_str(route, "name"), required_str(route, "selector")))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ("repay", "0x20b76e81"),
            ("supply", "0xa99aad89"),
            ("supplyCollateral", "0x238d6579"),
        ])
    );

    let registry_root = workspace.join("secure/data/erc7730-registry");
    let erc20 = dbgen::erc20::build_db(&workspace.join("secure/data/erc20.json"))
        .expect("build production ERC20 capabilities");
    let (registry, _) = build_db_tolerant_with_erc20_capabilities(
        &registry_root.join("registry"),
        &workspace.join("secure/data/erc7730/policy.toml"),
        Some(&registry_root),
        &erc20.capabilities,
    )
    .expect("build production ERC-7730 registry");
    let entries: Vec<_> = registry
        .entries
        .iter()
        .filter(|entry| {
            entry.source.file_name().and_then(|name| name.to_str())
                == Some("calldata-MorphoBlue.json")
        })
        .collect();
    assert_eq!(entries.len(), 2);
    for entry in entries {
        let ir = Erc7730Ir::parse(&entry.ir_bytes).expect("parse generated Morpho IR");
        for route in routes {
            let route_name = required_str(route, "name");
            let selector: [u8; 4] = decode_hex_text(required_str(route, "selector"))
                .try_into()
                .expect("Morpho selector width");
            let format = ir
                .find_format_by_selector(&selector)
                .expect("Morpho format table parses")
                .expect("evidenced Morpho route remains admitted");
            assert_eq!(
                format.static_head_words,
                if matches!(route_name, "supplyCollateral" | "withdrawCollateral") {
                    8
                } else {
                    9
                }
            );
            let fields = format
                .fields()
                .map(|field| field.expect("Morpho field parses"))
                .collect::<Vec<_>>();
            let labels = fields
                .iter()
                .map(|field| field.label)
                .collect::<BTreeSet<_>>();
            for required_label in [
                &b"Loan Token"[..],
                &b"Collateral Token"[..],
                &b"Oracle"[..],
                &b"Irm"[..],
                &b"Lltv"[..],
                &b"Assets"[..],
                &b"On Behalf"[..],
            ] {
                assert!(
                    labels.contains(required_label),
                    "{route_name} omits the signed {required_label:?} field"
                );
            }
            let assets = fields
                .iter()
                .find(|field| field.label == b"Assets")
                .copied()
                .expect("Morpho Assets field");
            assert_eq!(
                FormatOp::try_from(assets.format_op),
                Ok(FormatOp::TokenAmount)
            );
            let params = parse_params(&ir, assets.param_off).expect("Morpho params parse");
            let member = u8::from(matches!(
                route_name,
                "supplyCollateral" | "withdrawCollateral"
            ));
            assert_eq!(
                params.token_path,
                Some(
                    &[
                        PathOp::RootStructured as u8,
                        PathOp::FieldIdx as u8,
                        0,
                        0,
                        PathOp::FieldIdx as u8,
                        0,
                        member,
                    ][..]
                )
            );

            if matches!(route_name, "borrow" | "repay" | "supply" | "withdraw") {
                let shares = fields
                    .iter()
                    .find(|field| field.label == b"Shares")
                    .copied()
                    .expect("Morpho Shares field");
                assert_eq!(FormatOp::try_from(shares.format_op), Ok(FormatOp::Raw));
            } else {
                assert!(!labels.contains(&b"Shares"[..]));
            }

            let callback = fields
                .iter()
                .find(|field| field.label == b"Callback")
                .copied();
            if matches!(route_name, "repay" | "supply" | "supplyCollateral") {
                let callback = callback.expect("exact-empty Morpho Callback field");
                assert_eq!(FormatOp::try_from(callback.format_op), Ok(FormatOp::Raw));
                let callback_slot = if route_name == "supplyCollateral" {
                    7
                } else {
                    8
                };
                assert_eq!(
                    ir.path_bytes(callback.path_off)
                        .expect("Morpho Callback path parses"),
                    &[
                        PathOp::RootStructured as u8,
                        PathOp::FieldIdx as u8,
                        0,
                        callback_slot,
                        PathOp::FollowOffset as u8,
                    ]
                );
                let params =
                    parse_params(&ir, callback.param_off).expect("Morpho Callback params parse");
                assert_eq!(params.visibility, Visibility::Always);
                assert_eq!(params.dynamic_kind, Some(DYNAMIC_KIND_BYTES));
                assert_eq!(params.terminal_kind, Some(TerminalKind::DynamicBytes));
                assert!(params.exact_empty_bytes);
            } else {
                assert!(callback.is_none());
            }
        }
    }
}
