#!/usr/bin/env python3
"""Advisory ERC-7730 proxy implementation drift monitor.

The checked-in watch rows are historical semantic-evidence receipts.  Live
JSON-RPC observations can warn that one of those historical facts changed;
they can never create, refresh, remove, or otherwise modify descriptor or
signing authority.  In particular, ``MATCH`` means only "the configured live
facts still equal the archived facts".  It is not an attestation, catalogue
admission, release approval, or production verdict.

The command is intentionally read-only apart from an explicitly requested
report path::

    python3 tools/erc7730_proxy_drift.py \
        --rpc 1=https://ethereum.example.invalid \
        --output target/erc7730-proxy-drift.json

Valid monitoring runs return zero even when a row is ``DRIFT`` or ``UNKNOWN``;
the result is advisory.  Invalid watch manifests and invalid command-line
inputs return non-zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests/erc7730-semantic-evidence/proxy-watch.v1.json"

WATCH_SCHEMA = "pq1-erc7730-proxy-watch-v1"
REPORT_SCHEMA = "pq1-erc7730-proxy-drift-report-v1"

IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
MAX_RPC_RESPONSE = 2 * 1024 * 1024

ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
EVIDENCE_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH32_RE = re.compile(r"^0x[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_DATA_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")

ZERO_ADDRESS = "0x" + "00" * 20

RpcCall = Callable[[str, list[Any]], Any]

# These paths bind each watch field to its reviewed semantic location in the
# corresponding evidence format.  Do not accept watch-supplied paths here: a
# repeated scalar elsewhere in a large evidence manifest is not proof that the
# intended field still agrees with the watch row.
EVIDENCE_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "tests/erc7730-semantic-evidence/aave-v3-ethereum-pool/manifest.json": {
        "chain id": ("descriptor", "chain_id"),
        "proxy": ("contracts", "pool_proxy"),
        "implementation": ("contracts", "pool_implementation"),
        "fixed block number": ("fixed_block", "number"),
        "fixed block hash": ("fixed_block", "hash"),
    },
    "tests/erc7730-semantic-evidence/lombard-lbtc/manifest.json": {
        "chain id": ("fixed_block", "chain_id"),
        "proxy": ("contracts", "lbtc_proxy"),
        "implementation": ("contracts", "lbtc_implementation"),
        "fixed block number": ("fixed_block", "number"),
        "fixed block hash": ("fixed_block", "hash"),
    },
    "tests/erc7730-semantic-evidence/midas-mtbill-deposit-vault/manifest.json": {
        "chain id": ("fixed_block", "chain_id"),
        "proxy": ("contracts", "deposit_vault_proxy"),
        "implementation": ("contracts", "deposit_vault_implementation"),
        "fixed block number": ("fixed_block", "number"),
        "fixed block hash": ("fixed_block", "hash"),
    },
    "tests/erc7730-semantic-evidence/midas-mtbill-redemption-vault/manifest.json": {
        "chain id": ("fixed_block", "chain_id"),
        "proxy": ("contracts", "redemption_vault_proxy"),
        "implementation": ("contracts", "redemption_vault_implementation"),
        "fixed block number": ("fixed_block", "number"),
        "fixed block hash": ("fixed_block", "hash"),
    },
}

EVIDENCE_SCHEMA_VERSIONS = {
    "tests/erc7730-semantic-evidence/aave-v3-ethereum-pool/manifest.json": 1,
    "tests/erc7730-semantic-evidence/lombard-lbtc/manifest.json": 2,
    "tests/erc7730-semantic-evidence/midas-mtbill-deposit-vault/manifest.json": 2,
    "tests/erc7730-semantic-evidence/midas-mtbill-redemption-vault/manifest.json": 2,
}

# Aave's schema records runtime identity directly.  Bind the two monitored
# semantic roles to their exact record keys; accepting any other runtime row
# (for example BorrowLogic) would make a beside-manifest file substitution look
# like evidence for the Pool proxy.
AAVE_RUNTIME_KEYS = {
    "tests/erc7730-semantic-evidence/aave-v3-ethereum-pool/manifest.json": {
        "proxy": "pool_proxy",
        "implementation": "pool_implementation",
    },
}

# The schema-v2 bundles list runtime files in ``artifacts`` rather than carrying
# a decoded Keccak field.  These reviewed paths bind each monitored role to one
# exact artifact record; its SHA-256 then binds the bytes whose Keccak is
# compared with the watch row.
ARTIFACT_RUNTIME_PATHS = {
    "tests/erc7730-semantic-evidence/lombard-lbtc/manifest.json": {
        "proxy": "runtime/StakedLBTCProxy.ethereum-mainnet.hex",
        "implementation": "runtime/StakedLBTC.implementation.ethereum-mainnet.hex",
    },
    "tests/erc7730-semantic-evidence/midas-mtbill-deposit-vault/manifest.json": {
        "proxy": "runtime/DepositVaultProxy.ethereum-mainnet.hex",
        "implementation": "runtime/DepositVault.implementation.ethereum-mainnet.hex",
    },
    "tests/erc7730-semantic-evidence/midas-mtbill-redemption-vault/manifest.json": {
        "proxy": "runtime/RedemptionVaultProxy.ethereum-mainnet.hex",
        "implementation": "runtime/RedemptionVault.implementation.ethereum-mainnet.hex",
    },
}


class ManifestError(ValueError):
    """The watch input is malformed or no longer matches archived evidence."""


class RpcError(RuntimeError):
    """A transport or JSON-RPC response was unavailable or malformed."""


@dataclass(frozen=True)
class Watch:
    name: str
    chain_id: int
    proxy: str
    expected_kind: str
    expected_implementation: str
    expected_proxy_code_keccak256: str | None
    expected_implementation_code_keccak256: str | None
    evidence_manifest: str
    evidence_manifest_sha256: str
    evidence_block_number: int
    evidence_block_hash: str
    proxy_runtime_file: str | None
    implementation_runtime_file: str | None


# Round constants and rotation offsets for Keccak-f[1600].  This is Ethereum's
# Keccak-256 padding (0x01), not standardized SHA3-256 padding (0x06).
_KECCAK_RC = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_KECCAK_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK64 = (1 << 64) - 1


def _rol64(value: int, count: int) -> int:
    if count == 0:
        return value & _MASK64
    return ((value << count) | (value >> (64 - count))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    for rc in _KECCAK_RC:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [columns[(x - 1) % 5] ^ _rol64(columns[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]

        moved = [0] * 25
        for y in range(5):
            for x in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rol64(
                    state[x + 5 * y], _KECCAK_RHO[x][y]
                )

        for y in range(5):
            row = moved[5 * y : 5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                state[x + 5 * y] &= _MASK64
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Dependency-free Ethereum Keccak-256."""

    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - len(padded) % rate) % rate))
    padded[-1] |= 0x80

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            start = lane * 8
            state[lane] ^= int.from_bytes(block[start : start + 8], "little")
        _keccak_f1600(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_path(relative: str, *, evidence_dir: Path | None = None) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ManifestError(f"path must be repository-relative without '..': {relative!r}")
    resolved = (ROOT / candidate).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as error:
        raise ManifestError(f"path escapes repository: {relative!r}") from error
    if evidence_dir is not None:
        try:
            resolved.relative_to(evidence_dir)
        except ValueError as error:
            raise ManifestError(
                f"runtime evidence must stay beside its evidence manifest: {relative!r}"
            ) from error
    return resolved


def _decode_code_file(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise ManifestError(f"read runtime evidence {path}: {error}") from error
    try:
        return decode_hex_data(text, field=f"runtime evidence {path}")
    except RpcError as error:
        raise ManifestError(str(error)) from error


def _evidence_value(evidence: Any, path: tuple[str, ...], *, label: str) -> object:
    value = evidence
    for component in path:
        if not isinstance(value, dict) or component not in value:
            dotted = ".".join(path)
            raise ManifestError(f"evidence field {label!r} is missing at {dotted}")
        value = value[component]
    return value


def _evidence_equal(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if (
        isinstance(actual, str)
        and isinstance(expected, str)
        and actual.startswith("0x")
        and expected.startswith("0x")
    ):
        return actual.lower() == expected.lower()
    return actual == expected


def _index_evidence_records(
    evidence: dict[str, Any], section: str, identity_field: str
) -> dict[str, dict[str, Any]]:
    records = evidence.get(section)
    if not isinstance(records, list):
        raise ManifestError(f"evidence {section!r} must be a list")
    indexed: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ManifestError(f"evidence {section}[{index}] must be an object")
        identity = record.get(identity_field)
        if not isinstance(identity, str) or not identity:
            raise ManifestError(
                f"evidence {section}[{index}].{identity_field} must be a non-empty string"
            )
        if identity in indexed:
            raise ManifestError(
                f"duplicate evidence {section} record {identity_field}={identity!r}"
            )
        indexed[identity] = record
    return indexed


def _runtime_repo_path(
    watch: Watch,
    manifest_path: Path,
    relative: object,
    *,
    label: str,
) -> tuple[str, Path]:
    if not isinstance(relative, str) or not relative:
        raise ManifestError(f"{watch.name}: {label} evidence runtime path is malformed")
    candidate = Path(relative)
    if (
        candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.as_posix() != relative
    ):
        raise ManifestError(
            f"{watch.name}: {label} evidence runtime path is not canonical"
        )
    repository_relative = (Path(watch.evidence_manifest).parent / candidate).as_posix()
    runtime_path = _repo_path(
        repository_relative, evidence_dir=manifest_path.parent.resolve()
    )
    return repository_relative, runtime_path


def _verify_runtime_file(
    watch: Watch,
    manifest_path: Path,
    *,
    label: str,
    relative: object,
    record_sha256: object,
    record_keccak256: object | None,
) -> None:
    if label == "proxy":
        watched_relative = watch.proxy_runtime_file
        watched_keccak = watch.expected_proxy_code_keccak256
    elif label == "implementation":
        watched_relative = watch.implementation_runtime_file
        watched_keccak = watch.expected_implementation_code_keccak256
    else:  # Internal invariant: only the two semantic runtime roles are supported.
        raise AssertionError(f"unsupported runtime label: {label}")

    if watched_relative is None or watched_keccak is None:
        raise ManifestError(f"{watch.name}: {label} runtime binding is missing")
    expected_relative, runtime_path = _runtime_repo_path(
        watch, manifest_path, relative, label=label
    )
    if watched_relative != expected_relative:
        raise ManifestError(
            f"{watch.name}: {label} runtime path differs from its bound evidence record"
        )
    if not isinstance(record_sha256, str) or SHA256_RE.fullmatch(record_sha256) is None:
        raise ManifestError(
            f"{watch.name}: {label} evidence runtime SHA-256 is malformed"
        )
    if record_keccak256 is not None:
        if (
            not isinstance(record_keccak256, str)
            or HASH32_RE.fullmatch(record_keccak256) is None
        ):
            raise ManifestError(
                f"{watch.name}: {label} evidence runtime Keccak is malformed"
            )
        if watched_keccak != record_keccak256:
            raise ManifestError(
                f"{watch.name}: {label} expected Keccak differs from its bound evidence record"
            )
    if not runtime_path.is_file():
        raise ManifestError(f"{watch.name}: {label} runtime evidence is missing")
    actual_file_sha256 = _sha256_file(runtime_path)
    if actual_file_sha256 != record_sha256:
        raise ManifestError(
            f"{watch.name}: {label} runtime file SHA-256 drift: "
            f"expected {record_sha256}, got {actual_file_sha256}"
        )
    actual_keccak = "0x" + keccak256(_decode_code_file(runtime_path)).hex()
    if actual_keccak != watched_keccak:
        raise ManifestError(
            f"{watch.name}: {label} runtime Keccak drift: "
            f"expected {watched_keccak}, got {actual_keccak}"
        )


def _verify_runtime_bindings(
    watch: Watch, evidence: dict[str, Any], manifest_path: Path
) -> None:
    aave_keys = AAVE_RUNTIME_KEYS.get(watch.evidence_manifest)
    if aave_keys is not None:
        records = _index_evidence_records(evidence, "runtimes", "key")
        for label, record_key in aave_keys.items():
            record = records.get(record_key)
            if record is None:
                raise ManifestError(
                    f"{watch.name}: missing evidence runtimes record key={record_key!r}"
                )
            address = record.get("address")
            expected_address = (
                watch.proxy if label == "proxy" else watch.expected_implementation
            )
            if (
                not isinstance(address, str)
                or EVIDENCE_ADDRESS_RE.fullmatch(address) is None
            ):
                raise ManifestError(
                    f"{watch.name}: {label} evidence runtime address is malformed"
                )
            if not _evidence_equal(address, expected_address):
                raise ManifestError(
                    f"{watch.name}: {label} runtime address differs from its bound evidence record"
                )
            _verify_runtime_file(
                watch,
                manifest_path,
                label=label,
                relative=record.get("path"),
                record_sha256=record.get("file_sha256"),
                record_keccak256=record.get("keccak256"),
            )
        return

    runtime_paths = ARTIFACT_RUNTIME_PATHS.get(watch.evidence_manifest)
    if runtime_paths is None:
        raise ManifestError(
            f"{watch.name}: evidence manifest has no reviewed runtime layout"
        )
    records = _index_evidence_records(evidence, "artifacts", "path")
    for label, relative in runtime_paths.items():
        record = records.get(relative)
        if record is None:
            raise ManifestError(
                f"{watch.name}: missing evidence artifact path={relative!r}"
            )
        _verify_runtime_file(
            watch,
            manifest_path,
            label=label,
            relative=relative,
            record_sha256=record.get("sha256"),
            record_keccak256=None,
        )


def _verify_evidence_semantics(
    watch: Watch, evidence: Any, manifest_path: Path
) -> None:
    if not isinstance(evidence, dict):
        raise ManifestError(f"{watch.name}: evidence manifest must be an object")
    expected_schema = EVIDENCE_SCHEMA_VERSIONS.get(watch.evidence_manifest)
    field_paths = EVIDENCE_FIELDS.get(watch.evidence_manifest)
    if expected_schema is None or field_paths is None:
        raise ManifestError(
            f"{watch.name}: evidence manifest has no reviewed semantic layout"
        )
    schema = evidence.get("schema_version")
    if type(schema) is not int or schema != expected_schema:
        raise ManifestError(
            f"{watch.name}: evidence schema_version must be exact integer "
            f"{expected_schema}, got {schema!r}"
        )
    for label, expected in (
        ("chain id", watch.chain_id),
        ("proxy", watch.proxy),
        ("implementation", watch.expected_implementation),
        ("fixed block number", watch.evidence_block_number),
        ("fixed block hash", watch.evidence_block_hash),
    ):
        actual = _evidence_value(evidence, field_paths[label], label=label)
        if not _evidence_equal(actual, expected):
            raise ManifestError(
                f"{watch.name}: {label} differs from the bound evidence manifest"
            )
    _verify_runtime_bindings(watch, evidence, manifest_path)


def _required_string(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise ManifestError(f"watch row {key!r} must be a non-empty string")
    return value


def _optional_hash(row: dict[str, Any], key: str) -> str | None:
    value = row.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or HASH32_RE.fullmatch(value) is None:
        raise ManifestError(f"watch row {key!r} must be null or canonical lowercase bytes32")
    return value


def _optional_path(row: dict[str, Any], key: str) -> str | None:
    value = row.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ManifestError(f"watch row {key!r} must be null or a non-empty path")
    return value


def _parse_watch(row: Any) -> Watch:
    if not isinstance(row, dict):
        raise ManifestError("every watch row must be an object")
    allowed = {
        "name",
        "chain_id",
        "proxy",
        "expected_kind",
        "expected_implementation",
        "expected_proxy_code_keccak256",
        "expected_implementation_code_keccak256",
        "evidence_manifest",
        "evidence_manifest_sha256",
        "evidence_block_number",
        "evidence_block_hash",
        "proxy_runtime_file",
        "implementation_runtime_file",
    }
    extra = sorted(set(row) - allowed)
    missing = sorted(allowed - set(row))
    if extra or missing:
        raise ManifestError(f"watch row key mismatch: missing={missing}, extra={extra}")

    name = _required_string(row, "name")
    chain_id = row["chain_id"]
    block_number = row["evidence_block_number"]
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise ManifestError(f"{name}: chain_id must be a positive integer")
    if isinstance(block_number, bool) or not isinstance(block_number, int) or block_number <= 0:
        raise ManifestError(f"{name}: evidence_block_number must be a positive integer")

    proxy = _required_string(row, "proxy")
    implementation = _required_string(row, "expected_implementation")
    block_hash = _required_string(row, "evidence_block_hash")
    manifest_sha256 = _required_string(row, "evidence_manifest_sha256")
    if ADDRESS_RE.fullmatch(proxy) is None or proxy == ZERO_ADDRESS:
        raise ManifestError(f"{name}: proxy must be a non-zero canonical lowercase address")
    if ADDRESS_RE.fullmatch(implementation) is None or implementation == ZERO_ADDRESS:
        raise ManifestError(
            f"{name}: expected_implementation must be a non-zero canonical lowercase address"
        )
    if HASH32_RE.fullmatch(block_hash) is None:
        raise ManifestError(f"{name}: evidence_block_hash must be canonical lowercase bytes32")
    if re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is None:
        raise ManifestError(f"{name}: evidence_manifest_sha256 must be lowercase SHA-256")
    if row["expected_kind"] != "eip1967-direct":
        raise ManifestError(f"{name}: expected_kind must be eip1967-direct")

    proxy_hash = _optional_hash(row, "expected_proxy_code_keccak256")
    implementation_hash = _optional_hash(row, "expected_implementation_code_keccak256")
    proxy_runtime = _optional_path(row, "proxy_runtime_file")
    implementation_runtime = _optional_path(row, "implementation_runtime_file")
    if (proxy_hash is None) != (proxy_runtime is None):
        raise ManifestError(f"{name}: proxy code hash and runtime evidence must appear together")
    if (implementation_hash is None) != (implementation_runtime is None):
        raise ManifestError(
            f"{name}: implementation code hash and runtime evidence must appear together"
        )

    return Watch(
        name=name,
        chain_id=chain_id,
        proxy=proxy,
        expected_kind=row["expected_kind"],
        expected_implementation=implementation,
        expected_proxy_code_keccak256=proxy_hash,
        expected_implementation_code_keccak256=implementation_hash,
        evidence_manifest=_required_string(row, "evidence_manifest"),
        evidence_manifest_sha256=manifest_sha256,
        evidence_block_number=block_number,
        evidence_block_hash=block_hash,
        proxy_runtime_file=proxy_runtime,
        implementation_runtime_file=implementation_runtime,
    )


def _verify_evidence(watch: Watch) -> None:
    manifest_path = _repo_path(watch.evidence_manifest)
    semantic_root = (ROOT / "tests/erc7730-semantic-evidence").resolve()
    try:
        manifest_path.relative_to(semantic_root)
    except ValueError as error:
        raise ManifestError(
            f"{watch.name}: evidence manifest must be under tests/erc7730-semantic-evidence"
        ) from error
    if manifest_path.name != "manifest.json" or not manifest_path.is_file():
        raise ManifestError(f"{watch.name}: evidence manifest is missing: {manifest_path}")
    actual_manifest_sha256 = _sha256_file(manifest_path)
    if actual_manifest_sha256 != watch.evidence_manifest_sha256:
        raise ManifestError(
            f"{watch.name}: evidence manifest SHA-256 drift: "
            f"expected {watch.evidence_manifest_sha256}, got {actual_manifest_sha256}"
        )
    try:
        evidence = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"{watch.name}: parse evidence manifest: {error}") from error
    _verify_evidence_semantics(watch, evidence, manifest_path)


def load_watch_manifest(path: Path = DEFAULT_MANIFEST) -> list[Watch]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError(f"read watch manifest {path}: {error}") from error
    if not isinstance(parsed, dict) or set(parsed) != {"schema", "authority", "watches"}:
        raise ManifestError("watch manifest must contain exactly schema, authority, and watches")
    if parsed["schema"] != WATCH_SCHEMA:
        raise ManifestError(f"unsupported watch schema: {parsed['schema']!r}")
    if parsed["authority"] != "advisory-only; never grants or changes signing authority":
        raise ManifestError("watch manifest advisory-only authority sentence drifted")
    rows = parsed["watches"]
    if not isinstance(rows, list) or not rows:
        raise ManifestError("watch manifest must contain at least one watch row")
    watches = [_parse_watch(row) for row in rows]
    names = [watch.name for watch in watches]
    identities = [(watch.chain_id, watch.proxy) for watch in watches]
    if len(names) != len(set(names)):
        raise ManifestError("duplicate watch name")
    if len(identities) != len(set(identities)):
        raise ManifestError("duplicate (chain_id, proxy) watch identity")
    for watch in watches:
        _verify_evidence(watch)
    return sorted(watches, key=lambda watch: (watch.chain_id, watch.proxy, watch.name))


def decode_hex_data(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or HEX_DATA_RE.fullmatch(value) is None:
        raise RpcError(f"{field} is not canonical even-length 0x hex")
    return bytes.fromhex(value[2:])


def parse_quantity(value: Any, *, field: str) -> int:
    if not isinstance(value, str) or QUANTITY_RE.fullmatch(value) is None:
        raise RpcError(f"{field} is not a canonical JSON-RPC quantity")
    return int(value, 16)


def _address_word(value: Any, *, field: str) -> tuple[str, bool]:
    raw = decode_hex_data(value, field=field)
    if len(raw) != 32:
        raise RpcError(f"{field} must be exactly 32 bytes")
    return "0x" + raw[-20:].hex(), raw[:12] == bytes(12)


class JsonRpcHttp:
    """Minimal JSON-RPC client that never exposes its URL in a report."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 15.0,
        opener: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("RPC URL must be absolute http(s)")
        self._url = url
        self._timeout = timeout
        self._opener = opener
        self._request_id = 0

    def __call__(self, method: str, params: list[Any]) -> Any:
        self._request_id += 1
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": params,
            },
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "PQSigner-ERC7730-Proxy-Drift/1",
            },
            method="POST",
        )
        try:
            with self._opener(request, timeout=self._timeout) as response:
                raw = response.read(MAX_RPC_RESPONSE + 1)
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            raise RpcError(f"transport unavailable: {type(error).__name__}") from error
        if len(raw) > MAX_RPC_RESPONSE:
            raise RpcError("RPC response exceeds size limit")
        try:
            decoded = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RpcError("RPC returned malformed JSON") from error
        if not isinstance(decoded, dict):
            raise RpcError("RPC response is not an object")
        if decoded.get("jsonrpc") != "2.0" or decoded.get("id") != self._request_id:
            raise RpcError("RPC response envelope/id mismatch")
        if decoded.get("error") is not None:
            raise RpcError("RPC returned an error")
        if "result" not in decoded:
            raise RpcError("RPC response has no result")
        return decoded["result"]


def _block_snapshot(rpc: RpcCall, tag: str = "latest") -> dict[str, object]:
    result = rpc("eth_getBlockByNumber", [tag, False])
    if not isinstance(result, dict):
        raise RpcError("latest block response is not an object")
    number_hex = result.get("number")
    block_hash = result.get("hash")
    number = parse_quantity(number_hex, field="latest block number")
    if not isinstance(block_hash, str):
        raise RpcError("latest block hash is missing")
    block_hash = block_hash.lower()
    if HASH32_RE.fullmatch(block_hash) is None:
        raise RpcError("latest block hash is not bytes32")
    return {"number": number, "number_hex": number_hex.lower(), "hash": block_hash}


def _block_revalidation_reason(
    rpc: RpcCall, initial: dict[str, object]
) -> str | None:
    try:
        tag = initial["number_hex"]
        assert isinstance(tag, str)
        latest = _block_snapshot(rpc, tag)
    except RpcError as error:
        return f"observation-block-revalidation-failed: {error}"
    if latest["number"] != initial["number"]:
        return "observation-block-number-changed-during-monitoring"
    if latest["hash"] != initial["hash"]:
        return "observation-block-hash-changed-during-monitoring"
    return None


def _verify_rpc_chain(rpc: RpcCall, expected_chain_id: int) -> None:
    actual_chain_id = parse_quantity(rpc("eth_chainId", []), field="RPC chain id")
    if actual_chain_id != expected_chain_id:
        raise RpcError(
            f"RPC chain id mismatch: expected {expected_chain_id}, got {actual_chain_id}"
        )


def _unknown_result(watch: Watch, reason: str, block: dict[str, object] | None = None) -> dict[str, Any]:
    return _base_result(watch, block) | {
        "status": "UNKNOWN",
        "reasons": [reason],
        "observed": {},
    }


def _base_result(watch: Watch, block: dict[str, object] | None) -> dict[str, Any]:
    return {
        "name": watch.name,
        "chain_id": watch.chain_id,
        "proxy": watch.proxy,
        "expected": {
            "kind": watch.expected_kind,
            "implementation": watch.expected_implementation,
            "proxy_code_keccak256": watch.expected_proxy_code_keccak256,
            "implementation_code_keccak256": watch.expected_implementation_code_keccak256,
        },
        "evidence": {
            "manifest": watch.evidence_manifest,
            "manifest_sha256": watch.evidence_manifest_sha256,
            "block_number": watch.evidence_block_number,
            "block_hash": watch.evidence_block_hash,
        },
        "observation_block": block,
    }


def observe_watch(watch: Watch, rpc: RpcCall, block: dict[str, object]) -> dict[str, Any]:
    """Observe one proxy at one already-frozen latest block."""

    tag = block["number_hex"]
    assert isinstance(tag, str)
    try:
        implementation_word = rpc(
            "eth_getStorageAt", [watch.proxy, IMPLEMENTATION_SLOT, tag]
        )
        beacon_word = rpc("eth_getStorageAt", [watch.proxy, BEACON_SLOT, tag])
        implementation, implementation_canonical = _address_word(
            implementation_word, field="implementation slot"
        )
        beacon, beacon_canonical = _address_word(beacon_word, field="beacon slot")
    except RpcError as error:
        return _unknown_result(watch, str(error), block)

    observed: dict[str, Any] = {
        "implementation_slot": {
            "word": implementation_word.lower(),
            "address": implementation,
        },
        "beacon_slot": {"word": beacon_word.lower(), "address": beacon},
    }
    reasons: list[str] = []
    if not implementation_canonical:
        reasons.append("implementation-slot-high-bits-nonzero")
    if not beacon_canonical:
        reasons.append("beacon-slot-high-bits-nonzero")
    if reasons:
        return _base_result(watch, block) | {
            "status": "DRIFT",
            "reasons": reasons,
            "observed": observed,
        }

    if beacon != ZERO_ADDRESS:
        observed["proxy_kind"] = "eip1967-beacon"
        return _base_result(watch, block) | {
            "status": "DRIFT",
            "reasons": ["proxy-kind-changed"],
            "observed": observed,
        }
    if implementation == ZERO_ADDRESS and beacon == ZERO_ADDRESS:
        return _base_result(watch, block) | {
            "status": "UNKNOWN",
            "reasons": ["no-standard-eip1967-implementation-or-beacon"],
            "observed": observed,
        }

    resolved_implementation = implementation
    observed["proxy_kind"] = "eip1967-direct"
    observed["resolved_implementation"] = resolved_implementation
    if resolved_implementation != watch.expected_implementation:
        return _base_result(watch, block) | {
            "status": "DRIFT",
            "reasons": ["implementation-address-changed"],
            "observed": observed,
        }

    try:
        proxy_code_raw = rpc("eth_getCode", [watch.proxy, tag])
        implementation_code_raw = rpc("eth_getCode", [resolved_implementation, tag])
        proxy_code = decode_hex_data(proxy_code_raw, field="proxy runtime code")
        implementation_code = decode_hex_data(
            implementation_code_raw, field="implementation runtime code"
        )
    except RpcError as error:
        return _unknown_result(watch, str(error), block)

    proxy_code_hash = "0x" + keccak256(proxy_code).hex()
    implementation_code_hash = "0x" + keccak256(implementation_code).hex()
    observed["proxy_code_bytes"] = len(proxy_code)
    observed["proxy_code_keccak256"] = proxy_code_hash
    observed["implementation_code_bytes"] = len(implementation_code)
    observed["implementation_code_keccak256"] = implementation_code_hash

    if not proxy_code:
        reasons.append("proxy-code-empty")
    if not implementation_code:
        reasons.append("implementation-code-empty")
    if (
        watch.expected_proxy_code_keccak256 is not None
        and proxy_code_hash != watch.expected_proxy_code_keccak256
    ):
        reasons.append("proxy-code-changed")
    if (
        watch.expected_implementation_code_keccak256 is not None
        and implementation_code_hash != watch.expected_implementation_code_keccak256
    ):
        reasons.append("implementation-code-changed")

    return _base_result(watch, block) | {
        "status": "DRIFT" if reasons else "MATCH",
        "reasons": reasons,
        "observed": observed,
    }


def run_monitor(
    watches: Iterable[Watch],
    rpc_by_chain: dict[int, RpcCall],
    *,
    observed_at_utc: str,
) -> dict[str, Any]:
    ordered = sorted(watches, key=lambda watch: (watch.chain_id, watch.proxy, watch.name))
    blocks: dict[int, dict[str, object] | RpcError] = {}
    results: list[dict[str, Any]] = []
    for watch in ordered:
        rpc = rpc_by_chain.get(watch.chain_id)
        if rpc is None:
            results.append(_unknown_result(watch, "rpc-not-configured"))
            continue
        if watch.chain_id not in blocks:
            try:
                _verify_rpc_chain(rpc, watch.chain_id)
                blocks[watch.chain_id] = _block_snapshot(rpc)
            except RpcError as error:
                blocks[watch.chain_id] = error
        block = blocks[watch.chain_id]
        if isinstance(block, RpcError):
            results.append(_unknown_result(watch, str(block)))
        else:
            results.append(observe_watch(watch, rpc, block))

    # Historical state reads stay tagged by the one initial block number shared
    # by every watch on a chain.  Re-read that numeric tag only after all of the
    # chain's observations: a wrong number, changed hash, or unavailable check
    # invalidates every classification that depended on the initial hash.
    for chain_id, block in blocks.items():
        if isinstance(block, RpcError):
            continue
        rpc = rpc_by_chain[chain_id]
        reason = _block_revalidation_reason(rpc, block)
        if reason is None:
            continue
        for index, watch in enumerate(ordered):
            if watch.chain_id == chain_id:
                results[index] = _unknown_result(watch, reason, block)

    summary = {status: 0 for status in ("MATCH", "DRIFT", "UNKNOWN")}
    for result in results:
        summary[result["status"]] += 1
    return {
        "schema": REPORT_SCHEMA,
        "observed_at_utc": observed_at_utc,
        "authority": {
            "advisory_only": True,
            "signing_authority": False,
            "catalogue_authority": False,
            "release_authority": False,
            "production_authority": False,
            "match_meaning": "live observations equal archived facts only",
            "drift_action": "collect new fixed-block evidence; never auto-update authority",
        },
        "summary": {"total": len(results)} | summary,
        "results": results,
    }


def parse_rpc_specs(specs: list[str], *, timeout: float) -> dict[int, RpcCall]:
    clients: dict[int, RpcCall] = {}
    for spec in specs:
        chain_text, separator, url = spec.partition("=")
        if not separator or not chain_text.isascii() or not chain_text.isdigit() or not url:
            raise ValueError("--rpc must be CHAIN_ID=http(s)://URL")
        chain_id = int(chain_text)
        if chain_id <= 0 or chain_id in clients:
            raise ValueError(f"duplicate or invalid RPC chain id: {chain_text!r}")
        clients[chain_id] = JsonRpcHttp(url, timeout=timeout)
    return clients


def emit_report(report: dict[str, Any], output: Path | None) -> None:
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(encoded)
        return
    resolved = output.resolve()
    try:
        relative = resolved.relative_to(ROOT)
    except ValueError:
        relative = None
    if relative is not None and (not relative.parts or relative.parts[0] != "target"):
        raise ValueError("repository-local reports may be written only under target/")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(encoded, encoding="utf-8")


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--rpc", action="append", default=[], metavar="CHAIN_ID=URL")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not (0 < args.timeout <= 120):
        parser.error("--timeout must be in (0, 120]")
    try:
        watches = load_watch_manifest(args.manifest)
        clients = parse_rpc_specs(args.rpc, timeout=args.timeout)
        report = run_monitor(watches, clients, observed_at_utc=_now_utc())
        emit_report(report, args.output)
    except (ManifestError, OSError, ValueError) as error:
        print(f"erc7730-proxy-drift: FAIL: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
