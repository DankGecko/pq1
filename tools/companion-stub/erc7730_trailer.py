#!/usr/bin/env python3
"""Companion-stub: build an ERC-7730 sign-input trailer from a
catalog blob (`tools/companion-stub/erc7730_db.bin`).

Usage:

    python3 tools/companion-stub/erc7730_trailer.py \\
        --db tools/companion-stub/erc7730_db.bin \\
        --known-calls-bloom secure/data/erc7730-known-calls.bloom \\
        --bundle release.pqfw --pubkey vendor.pub \\
        --fwsign-bin target/release/fwsign \\
        --expected-firmware-version 42 --minimum-firmware-version 42 \\
        --chain 1 \\
        --contract 0xdAC17F958D2ee523a2206206994597C13D831ec7 \\
        --out /tmp/usdt_mainnet_trailer.bin

For EIP-712, select the exact context and complete primary type hash. The
catalog entry's `primary_type_hash` is only a sorting/diagnostic hint (one IR
can contain several formats), so lookup parses the authenticated IR format
table and compares all 32 bytes:

    python3 tools/companion-stub/erc7730_trailer.py \\
        --db tools/companion-stub/erc7730_db.bin \\
        --known-calls-bloom secure/data/erc7730-known-calls.bloom \\
        --bundle release.pqfw --pubkey vendor.pub \\
        --fwsign-bin target/release/fwsign \\
        --expected-firmware-version 42 --minimum-firmware-version 42 \\
        --chain 1 \\
        --contract 0x8236a87084f8b84306f72007f36f2618a5634494 \\
        --context eip712 \\
        --domain-separator \\
          0x2c437c69596d3cb0d046c1b65cd31dee6005447683107eb67b1cf385d850284f \\
        --primary-type-hash \\
          0x40ac9f6aa27075e64c1ed1ea2e831b20b8c25efdeb6b79fd0cf683c9a9c50725 \\
        --out /tmp/lbtc_network_fee_authorization.bin

Writes the byte-for-byte payload the secure-world dispatcher expects
inside the `[u16 BE len][payload]` trailer envelope on
`CMD_SIGN_USEROP` / `CMD_SIGN_USEROP_BATCH` / `CMD_SIGN_OFFCHAIN`.

The output buffer is the *inner* bundle (no length prefix). The
caller wraps it as `len.to_bytes(2, 'big') + payload` when splicing
into a sign-input wire payload.

Wire layout produced (matches `pqsigner_erc7730::bundle`):

    ir_len(2 BE) || ir || leaf_index(4 BE) || proof_depth(4 BE) || proof

Catalog blob layout (header is little-endian; entry array is sorted
by `(chain_id, contract, primary_type_hash, context_kind)` so binary
search works):

    "P730" || ver_le(4) || flags_le(4) || entry_cnt_le(4) ||
    ir_pool_off_le(4) || ir_pool_size_le(4) || proof_depth_le(4) ||
    proofs_off_le(4)
    [entries: each 72 B = chain_id_le(8) | contract(20) |
     primary_type_hash(32) | ctx_kind(1) | pad(3) | ir_off_le(4) |
     ir_len_le(4)]
    [ir_pool: concatenated IRs]
    [proofs: entry_cnt × proof_depth × 32 bytes]

Contract lookup defaults to exact `(context=Contract, chain_id, contract)` for
backward compatibility and rejects ambiguity. EIP-712 lookup additionally
requires the exact `--domain-separator` and `--primary-type-hash`; it validates
every IR's lookup-relevant header, layout, and complete format table, then
matches both authenticated values. Zero or multiple matches are errors. The
firmware remains authoritative for rendering-policy semantics after Merkle
verification.

Pure Python 3, no third-party deps — runs on any host the dev test
loop can already reach.

The normal command-line path never emits, lists, or reports from an unverified
release/catalogue pair. It invokes `fwsign erc7730-release-metadata` to verify
the C10 manifest, exact image hashes, version policy, and embedded/sidecar
P73S/P73K binding in a private temporary directory. It then binds the exact
P730 and known-call Bloom bytes to that P73S V1 status, reconstructs the
complete Merkle tree, byte-compares every stored proof, and, when authenticated
P73K is present, proves the exact `K = C ⊎ F` partition. A deliberately loud
`--unverified-status-for-test` escape exists only for deterministic dbgen/unit
fixtures and cannot emit a compatibility report.
For legacy/feature-off releases without P73K, the tuple-set SHA in P73S remains
a release-identity receipt: the Bloom is not invertible, so this helper does not
pretend it can reconstruct the exact registry-known superset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


HEADER_MAGIC = b"P730"
HEADER_LEN = 32
ENTRY_LEN = 72
IR_HEADER_LEN = 134
IR_SCHEMA_VERSION = 6
IR_MAX_LEN = 4096
IR_MAX_FORMATS = 32
IR_MAX_FIELDS = 24
CTX_CONTRACT = 1
CTX_EIP712 = 2

STATUS_MAGIC = b"P73S"
STATUS_SCHEMA_VERSION = 1
STATUS_LEN = 256
CATALOGUE_VERSION = 1
PROVENANCE_DEV_UNATTESTED = 0
PROVENANCE_ERC8176_VERIFIED = 1
KNOWN_CALLS_BLOOM_BYTES = 16 * 1024
KNOWN_CALLS_BLOOM_BITS = KNOWN_CALLS_BLOOM_BYTES * 8
KNOWN_CALLS_BLOOM_HASHES = 7
KNOWN_CALL_DOMAIN = b"pqsigner/erc7730-known-call-v1"
KNOWN_CALL_SET_DOMAIN = b"pqsigner/erc7730-known-call-set-v1"

FORCED_ELIGIBLE_MAGIC = b"P73K"
FORCED_ELIGIBLE_SCHEMA_VERSION = 1
FORCED_ELIGIBLE_HEADER_LEN = 16
FORCED_ELIGIBLE_GROUP_LEN = 36
FORCED_ELIGIBLE_SELECTOR_LEN = 4
U32_MAX = (1 << 32) - 1


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _canonical_nul_padded_ascii(raw: bytes, label: str) -> str:
    """Decode one fixed-width, canonically NUL-padded ASCII field."""
    try:
        end = raw.index(0)
    except ValueError as exc:
        raise ValueError(f"{label} is not NUL terminated") from exc
    if any(raw[end:]):
        raise ValueError(f"{label} has non-zero bytes after its first NUL")
    body = raw[:end]
    if any(byte < 0x20 or byte >= 0x7F for byte in body):
        raise ValueError(f"{label} is not printable ASCII")
    return body.decode("ascii")


def parse_catalogue_status(raw: bytes) -> dict:
    """Strictly parse the fixed 256-byte, big-endian P73S V1 receipt."""
    if len(raw) != STATUS_LEN:
        raise ValueError(f"catalogue status length mismatch: {len(raw)} != {STATUS_LEN}")
    if raw[:4] != STATUS_MAGIC:
        raise ValueError(f"bad catalogue status magic: {raw[:4]!r}")

    schema_version = int.from_bytes(raw[4:6], "big")
    encoded_len = int.from_bytes(raw[6:8], "big")
    if schema_version != STATUS_SCHEMA_VERSION:
        raise ValueError(f"unknown catalogue status schema: {schema_version}")
    if encoded_len != STATUS_LEN:
        raise ValueError(f"catalogue status encoded length mismatch: {encoded_len}")

    provenance = raw[13]
    if provenance not in (
        PROVENANCE_DEV_UNATTESTED,
        PROVENANCE_ERC8176_VERIFIED,
    ):
        raise ValueError(f"unknown catalogue provenance: {provenance}")
    if raw[14:16] != b"\x00\x00":
        raise ValueError("catalogue status reserved bytes are non-zero")

    tool_version = _canonical_nul_padded_ascii(
        bytes(raw[224:256]), "catalogue status tool version"
    )
    if not tool_version:
        raise ValueError("catalogue status tool version is empty")

    return {
        "schema_version": schema_version,
        "encoded_len": encoded_len,
        "catalogue_version": int.from_bytes(raw[8:12], "big"),
        "ir_schema_version": raw[12],
        "provenance": provenance,
        "leaf_count": int.from_bytes(raw[16:20], "big"),
        "catalogue_size": int.from_bytes(raw[20:24], "big"),
        "known_call_count": int.from_bytes(raw[24:28], "big"),
        "bloom_size": int.from_bytes(raw[28:32], "big"),
        "descriptor_root": bytes(raw[32:64]),
        "catalogue_sha256": bytes(raw[64:96]),
        "known_call_set_sha256": bytes(raw[96:128]),
        "bloom_sha256": bytes(raw[128:160]),
        "policy_sha256": bytes(raw[160:192]),
        "curation_sha256": bytes(raw[192:224]),
        "tool_version": tool_version,
    }


def _catalogue_status_report(status: dict, status_raw: bytes) -> dict:
    provenance = {
        PROVENANCE_DEV_UNATTESTED: "dev-unattested",
        PROVENANCE_ERC8176_VERIFIED: "erc8176-verified",
    }[status["provenance"]]
    return {
        "status_schema": status["schema_version"],
        "encoded_length": status["encoded_len"],
        "status_sha256": _sha256(status_raw).hex(),
        "catalogue_format_version": status["catalogue_version"],
        "ir_schema_version": status["ir_schema_version"],
        "provenance": provenance,
        "provenance_code": status["provenance"],
        "leaf_count": status["leaf_count"],
        "catalogue_blob_size": status["catalogue_size"],
        "known_call_count": status["known_call_count"],
        "bloom_size": status["bloom_size"],
        "descriptor_root": status["descriptor_root"].hex(),
        "catalogue_sha256": status["catalogue_sha256"].hex(),
        "known_call_set_sha256": status["known_call_set_sha256"].hex(),
        "bloom_sha256": status["bloom_sha256"].hex(),
        "policy_sha256": status["policy_sha256"].hex(),
        "curation_input_sha256": status["curation_sha256"].hex(),
        "tool_version": status["tool_version"],
    }


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in release-metadata JSON: {key!r}")
        result[key] = value
    return result


def _validate_release_metadata(
    report: object,
    status_raw: bytes,
    expected_version: int,
    minimum_version: int,
) -> dict:
    """Cross-check fwsign's report against the exact extracted P73S bytes."""
    if not isinstance(report, dict):
        raise ValueError("release-metadata output is not a JSON object")
    if report.get("report_kind") != "authenticated-release-metadata":
        raise ValueError("unexpected release-metadata report kind")
    if report.get("erc8176_attestation") is not False:
        raise ValueError("release metadata must not claim ERC-8176 attestation")
    if report.get("production_authority") is not False:
        raise ValueError("release metadata must not claim production authority")
    if report.get("device_rollback_verified") is not False:
        raise ValueError("release metadata must not claim device rollback verification")

    version_policy = report.get("version_policy")
    if not isinstance(version_policy, dict) or version_policy != {
        "expected": expected_version,
        "minimum": minimum_version,
    }:
        raise ValueError("release-metadata version policy does not match the request")
    firmware = report.get("firmware")
    if not isinstance(firmware, dict):
        raise ValueError("release metadata has no firmware object")
    if firmware.get("firmware_version") != expected_version:
        raise ValueError("release metadata did not authenticate the expected firmware version")
    for field in (
        "slot_authenticated_by_legacy_signature",
        "build_id_authenticated_by_legacy_signature",
        "manifest_sha256_authenticated_by_legacy_signature",
    ):
        if firmware.get(field) is not False:
            raise ValueError(f"legacy release metadata must mark {field} false")
    for field in ("secure_hash", "nonsecure_hash", "build_id", "manifest_sha256"):
        value = firmware.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise ValueError(f"release metadata has malformed firmware {field}")

    parsed_status = parse_catalogue_status(status_raw)
    expected_status = _catalogue_status_report(parsed_status, status_raw)
    if report.get("catalogue_status") != expected_status:
        raise ValueError(
            "release-metadata catalogue status does not equal the exact extracted P73S"
        )
    if "forced_eligible" not in report:
        raise ValueError("release metadata omits the forced_eligible boundary")
    _validate_forced_release_metadata(report.get("forced_eligible"))
    return report


def _validate_forced_release_metadata(value: object) -> dict | None:
    """Validate fwsign's optional P73K summary before trusting extraction."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "format",
        "schema",
        "encoded_length",
        "group_count",
        "tuple_count",
        "set_sha256",
    }:
        raise ValueError("release metadata has malformed forced_eligible object")
    if value.get("format") != "P73K" or value.get("schema") != 1:
        raise ValueError("release metadata has unsupported forced-eligible format")
    encoded_length = value.get("encoded_length")
    group_count = value.get("group_count")
    tuple_count = value.get("tuple_count")
    if any(
        not isinstance(field, int) or isinstance(field, bool) or not 0 <= field <= U32_MAX
        for field in (encoded_length, group_count, tuple_count)
    ):
        raise ValueError("release metadata has invalid forced-eligible counts")
    expected_length = (
        FORCED_ELIGIBLE_HEADER_LEN
        + group_count * FORCED_ELIGIBLE_GROUP_LEN
        + tuple_count * FORCED_ELIGIBLE_SELECTOR_LEN
    )
    if encoded_length != expected_length:
        raise ValueError("release metadata has inconsistent forced-eligible length")
    if (group_count == 0) != (tuple_count == 0) or group_count > tuple_count:
        raise ValueError("release metadata has inconsistent forced-eligible cardinality")
    set_sha256 = value.get("set_sha256")
    if (
        not isinstance(set_sha256, str)
        or len(set_sha256) != 64
        or set_sha256 != set_sha256.lower()
    ):
        raise ValueError("release metadata has malformed forced-eligible SHA-256")
    try:
        bytes.fromhex(set_sha256)
    except ValueError as exc:
        raise ValueError("release metadata has malformed forced-eligible SHA-256") from exc
    return value


def _validate_extracted_forced_eligible(raw: bytes, metadata: dict) -> None:
    parsed = parse_forced_eligible(raw)
    if (
        len(raw) != metadata["encoded_length"]
        or parsed["group_count"] != metadata["group_count"]
        or parsed["tuple_count"] != metadata["tuple_count"]
        or _sha256(raw).hex() != metadata["set_sha256"]
    ):
        raise ValueError(
            "extracted P73K does not equal the authenticated release-metadata identity"
        )


def _authenticated_release_status(
    *,
    fwsign_bin: str,
    bundle: str,
    pubkey: str,
    expected_version: int,
    minimum_version: int,
    require_erc8176_verified: bool,
) -> tuple[bytes, bytes | None, dict]:
    """Run fwsign privately and consume its exact authenticated P73S/P73K."""
    with tempfile.TemporaryDirectory(prefix="pqsigner-erc7730-status-") as temp_dir:
        status_path = Path(temp_dir) / "authenticated-status.bin"
        base_command = [
            fwsign_bin,
            "erc7730-release-metadata",
            "--bundle",
            bundle,
            "--pubkey",
            pubkey,
            "--expected-version",
            str(expected_version),
            "--minimum-version",
            str(minimum_version),
        ]
        if require_erc8176_verified:
            base_command.append("--require-erc8176-verified")

        def invoke(extra_args: list[str]) -> dict:
            try:
                completed = subprocess.run(
                    base_command + extra_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    text=True,
                )
            except OSError as exc:
                raise ValueError(
                    f"cannot execute fwsign release authentication: {exc}"
                ) from exc
            if completed.returncode != 0:
                detail = completed.stderr.strip() or "no diagnostic"
                raise ValueError(f"authenticated firmware release rejected: {detail}")
            try:
                parsed = json.loads(
                    completed.stdout,
                    object_pairs_hook=_reject_duplicate_json_keys,
                )
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(
                    f"invalid fwsign release-metadata JSON: {exc}"
                ) from exc
            if not isinstance(parsed, dict):
                raise ValueError("fwsign release-metadata JSON is not an object")
            return parsed

        report = invoke(["--status-out", str(status_path)])
        try:
            status_raw = status_path.read_bytes()
        except OSError as exc:
            raise ValueError(f"fwsign did not emit authenticated P73S status: {exc}") from exc
        if (
            require_erc8176_verified
            and parse_catalogue_status(status_raw)["provenance"]
            != PROVENANCE_ERC8176_VERIFIED
        ):
            raise ValueError(
                "authenticated ERC-7730 catalogue provenance is dev-unattested; "
                "--require-erc8176-verified requires erc8176-verified"
            )
        validated = _validate_release_metadata(
            report,
            status_raw,
            expected_version,
            minimum_version,
        )
        forced_metadata = _validate_forced_release_metadata(
            validated.get("forced_eligible")
        )
        forced_raw = None
        if forced_metadata is not None:
            forced_path = Path(temp_dir) / "authenticated-forced-eligible.bin"
            extraction_report = invoke(
                ["--forced-eligible-out", str(forced_path)]
            )
            _validate_release_metadata(
                extraction_report,
                status_raw,
                expected_version,
                minimum_version,
            )
            if extraction_report != validated:
                raise ValueError(
                    "fwsign release identity changed between status and P73K extraction"
                )
            try:
                forced_raw = forced_path.read_bytes()
            except OSError as exc:
                raise ValueError(
                    f"fwsign did not emit authenticated P73K set: {exc}"
                ) from exc
            _validate_extracted_forced_eligible(forced_raw, forced_metadata)
        return status_raw, forced_raw, validated


def _compatibility_report(release: dict, verified: dict, status_raw: bytes) -> str:
    status = verified["status"]
    catalogue = _catalogue_status_report(status, status_raw)
    catalogue.update(
        {
            "proof_depth": verified["header"]["proof_depth"],
            "proofs_verified": verified["header"]["entry_cnt"],
            "compiled_known_call_count": verified["compiled_known_call_count"],
            "clear_known_call_count": verified["clear_known_call_count"],
            "forced_known_call_count": verified["forced_known_call_count"],
            "forced_eligible_bound": verified["forced_eligible_bound"],
        }
    )
    report = {
        "report_kind": "compatibility",
        "ready": True,
        "erc8176_attestation": False,
        "production_authority": False,
        "device_rollback_verified": False,
        "authenticated_release": release,
        "catalogue": catalogue,
    }
    return json.dumps(report, sort_keys=True, separators=(",", ":"))


def _parse_address(s: str) -> bytes:
    s = s.lower().strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 40:
        raise ValueError(f"bad address (expected 40 hex chars): {s!r}")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError(f"bad address hex: {s!r}") from exc


def _parse_hash32(s: str) -> bytes:
    original = s
    s = s.lower().strip()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64:
        raise argparse.ArgumentTypeError(
            f"bad 32-byte hash (expected 64 hex chars): {original!r}"
        )
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"bad 32-byte hash hex: {original!r}"
        ) from exc


def _slice(blob: bytes, start: int, length: int, label: str) -> bytes:
    end = start + length
    if start < 0 or length < 0 or end < start or end > len(blob):
        raise ValueError(
            f"truncated catalog: {label} [{start}:{end}] exceeds {len(blob)} bytes"
        )
    return bytes(blob[start:end])


def _read_header(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ValueError(f"catalog too short: {len(blob)} < {HEADER_LEN}")
    if blob[:4] != HEADER_MAGIC:
        raise ValueError(f"bad magic: {blob[:4]!r} != {HEADER_MAGIC!r}")
    (version,) = struct.unpack_from("<I", blob, 4)
    (flags,) = struct.unpack_from("<I", blob, 8)
    (entry_cnt,) = struct.unpack_from("<I", blob, 12)
    (ir_pool_off,) = struct.unpack_from("<I", blob, 16)
    (ir_pool_size,) = struct.unpack_from("<I", blob, 20)
    (proof_depth,) = struct.unpack_from("<I", blob, 24)
    (proofs_off,) = struct.unpack_from("<I", blob, 28)
    if version != CATALOGUE_VERSION:
        raise ValueError(f"unknown catalog version: {version}")
    if flags != 0:
        raise ValueError(f"unsupported catalog flags: 0x{flags:08x}")
    if entry_cnt == 0:
        raise ValueError("catalog contains no entries")
    entries_end = HEADER_LEN + entry_cnt * ENTRY_LEN
    if entries_end > len(blob):
        raise ValueError(
            f"entry table exceeds catalog: {entries_end} > {len(blob)}"
        )
    if ir_pool_off != entries_end:
        raise ValueError(
            f"non-canonical IR pool offset: {ir_pool_off} != {entries_end}"
        )
    ir_pool_end = ir_pool_off + ir_pool_size
    if ir_pool_end < ir_pool_off or ir_pool_end > len(blob):
        raise ValueError("IR pool exceeds catalog bounds")
    if proofs_off != ir_pool_end:
        raise ValueError(
            f"non-canonical proofs offset: {proofs_off} != {ir_pool_end}"
        )
    if proof_depth > 32:
        raise ValueError(f"proof depth exceeds firmware cap: {proof_depth} > 32")
    expected_end = proofs_off + entry_cnt * proof_depth * 32
    if expected_end != len(blob):
        raise ValueError(
            f"catalog proof region/trailing bytes mismatch: {expected_end} != {len(blob)}"
        )
    return {
        "version": version,
        "flags": flags,
        "entry_cnt": entry_cnt,
        "ir_pool_off": ir_pool_off,
        "ir_pool_size": ir_pool_size,
        "proof_depth": proof_depth,
        "proofs_off": proofs_off,
    }


def _entry(blob: bytes, i: int) -> dict:
    """Decode entry `i` from the catalog."""
    hdr = _read_header(blob)
    if i < 0 or i >= hdr["entry_cnt"]:
        raise ValueError(f"catalog entry index out of range: {i}")
    base = HEADER_LEN + i * ENTRY_LEN
    _slice(blob, base, ENTRY_LEN, f"entry {i}")
    (chain_id,) = struct.unpack_from("<Q", blob, base)
    contract = bytes(blob[base + 8 : base + 28])
    primary_type_hash = bytes(blob[base + 28 : base + 60])
    ctx_kind = blob[base + 60]
    if ctx_kind not in (CTX_CONTRACT, CTX_EIP712):
        raise ValueError(f"entry {i}: bad context kind {ctx_kind}")
    if blob[base + 61 : base + 64] != b"\x00\x00\x00":
        raise ValueError(f"entry {i}: non-zero reserved padding")
    (ir_off,) = struct.unpack_from("<I", blob, base + 64)
    (ir_len,) = struct.unpack_from("<I", blob, base + 68)
    if ir_len == 0 or ir_len > IR_MAX_LEN:
        raise ValueError(f"entry {i}: invalid IR length {ir_len}")
    if ir_off + ir_len < ir_off or ir_off + ir_len > hdr["ir_pool_size"]:
        raise ValueError(f"entry {i}: IR slice exceeds the declared IR pool")
    return {
        "leaf_index": i,
        "chain_id": chain_id,
        "contract": contract,
        "primary_type_hash": primary_type_hash,
        "ctx_kind": ctx_kind,
        "ir_off": ir_off,
        "ir_len": ir_len,
    }


def _parse_ir(ir: bytes) -> dict:
    """Parse and validate the complete authenticated IR format table."""
    if len(ir) < IR_HEADER_LEN or len(ir) > IR_MAX_LEN:
        raise ValueError(f"IR length outside [{IR_HEADER_LEN}, {IR_MAX_LEN}]: {len(ir)}")
    if ir[0] != IR_SCHEMA_VERSION:
        raise ValueError(f"unsupported IR schema version: {ir[0]}")
    context_kind = ir[1]
    if context_kind not in (CTX_CONTRACT, CTX_EIP712):
        raise ValueError(f"bad IR context kind: {context_kind}")
    chain_id = int.from_bytes(ir[2:10], "big")
    contract = bytes(ir[10:30])
    domain_separator = bytes(ir[62:94])
    if context_kind == CTX_CONTRACT and any(domain_separator):
        raise ValueError("contract-context IR carries a non-zero domain separator")
    _canonical_nul_padded_ascii(bytes(ir[94:110]), "IR owner")
    _canonical_nul_padded_ascii(bytes(ir[110:126]), "IR contract name")

    metadata_off = int.from_bytes(ir[126:128], "big")
    formats_off = int.from_bytes(ir[128:130], "big")
    pool_len = int.from_bytes(ir[130:132], "big")
    formats_len = int.from_bytes(ir[132:134], "big")
    if metadata_off != IR_HEADER_LEN:
        raise ValueError(f"bad IR metadata offset: {metadata_off}")
    if formats_off != metadata_off + pool_len:
        raise ValueError("IR metadata and format regions overlap or have a gap")
    if formats_off + formats_len != len(ir):
        raise ValueError("IR format region does not consume the complete IR")
    pool = bytes(ir[metadata_off:formats_off])
    formats = bytes(ir[formats_off:])
    if not formats:
        return {
            "context_kind": context_kind,
            "chain_id": chain_id,
            "contract": contract,
            "domain_separator": domain_separator,
            "selectors": (),
            "type_hashes": (),
        }

    count = formats[0]
    if count > IR_MAX_FORMATS:
        raise ValueError(f"IR format count exceeds cap: {count}")
    cursor = 1
    selectors: set[bytes] = set()
    selector_order: list[bytes] = []
    type_hashes: list[bytes] = []
    for format_index in range(count):
        if cursor + 10 > len(formats):
            raise ValueError(f"IR format {format_index} header is truncated")
        selector = bytes(formats[cursor : cursor + 4])
        field_count = formats[cursor + 4]
        intent_len = formats[cursor + 5]
        nested_descent_count = formats[cursor + 8]
        string_preimage_count = formats[cursor + 9]
        if field_count > IR_MAX_FIELDS:
            raise ValueError(f"IR format {format_index} field count exceeds cap")
        if string_preimage_count > 2:
            raise ValueError(
                f"IR format {format_index} string-preimage count exceeds cap"
            )
        if context_kind == CTX_CONTRACT and string_preimage_count:
            raise ValueError(
                f"IR contract format {format_index} carries string-preimage evidence"
            )
        if context_kind == CTX_CONTRACT and nested_descent_count:
            raise ValueError(
                f"IR contract format {format_index} carries nested-descent evidence"
            )
        cursor += 10  # selector, counts, static-head words, nested/string counts
        if cursor + intent_len > len(formats):
            raise ValueError(f"IR format {format_index} intent is truncated")
        intent = formats[cursor : cursor + intent_len]
        if any(b < 0x20 or b >= 0x7F for b in intent):
            raise ValueError(f"IR format {format_index} intent is not printable ASCII")
        cursor += intent_len

        if selector in selectors:
            raise ValueError(f"IR format {format_index} duplicates selector 0x{selector.hex()}")
        selectors.add(selector)
        selector_order.append(selector)
        if context_kind == CTX_EIP712:
            if cursor + 32 > len(formats):
                raise ValueError(f"IR format {format_index} type hash is truncated")
            type_hash = bytes(formats[cursor : cursor + 32])
            cursor += 32
            if selector != type_hash[:4]:
                raise ValueError(f"IR format {format_index} selector/type-hash mismatch")
            type_hashes.append(type_hash)

        for field_index in range(field_count):
            if cursor + 2 > len(formats):
                raise ValueError(
                    f"IR format {format_index} field {field_index} header is truncated"
                )
            format_op = formats[cursor]
            label_len = formats[cursor + 1]
            if not 0x01 <= format_op <= 0x0F:
                raise ValueError(
                    f"IR format {format_index} field {field_index} has bad format opcode"
                )
            cursor += 2
            if cursor + label_len + 4 > len(formats):
                raise ValueError(
                    f"IR format {format_index} field {field_index} is truncated"
                )
            label = formats[cursor : cursor + label_len]
            if any(b < 0x20 or b >= 0x7F for b in label):
                raise ValueError(
                    f"IR format {format_index} field {field_index} label is not printable ASCII"
                )
            cursor += label_len
            path_off = int.from_bytes(formats[cursor : cursor + 2], "big")
            param_off = int.from_bytes(formats[cursor + 2 : cursor + 4], "big")
            cursor += 4
            if param_off == 0:
                raise ValueError(
                    f"IR format {format_index} field {field_index} has no parameter block"
                )
            for offset, label_name in ((path_off, "path"), (param_off, "parameter")):
                if offset:
                    if offset >= len(pool):
                        raise ValueError(f"IR {label_name} offset is outside the pool")
                    payload_len = pool[offset]
                    if offset + 1 + payload_len > len(pool):
                        raise ValueError(f"IR {label_name} pool entry is truncated")

    if cursor != len(formats):
        raise ValueError(f"IR format table has {len(formats) - cursor} trailing bytes")
    return {
        "context_kind": context_kind,
        "chain_id": chain_id,
        "contract": contract,
        "domain_separator": domain_separator,
        "selectors": tuple(selector_order),
        "type_hashes": tuple(type_hashes),
    }


def _parsed_entry(blob: bytes, hdr: dict, i: int) -> tuple[dict, bytes, dict]:
    entry = _entry(blob, i)
    ir_start = hdr["ir_pool_off"] + entry["ir_off"]
    ir = _slice(blob, ir_start, entry["ir_len"], f"IR for leaf {i}")
    parsed = _parse_ir(ir)
    # These index fields are lookup accelerators only; the IR is the Merkle-
    # authenticated source of truth. A mismatch is malformed catalog data.
    if (
        entry["chain_id"] != parsed["chain_id"]
        or entry["contract"] != parsed["contract"]
        or entry["ctx_kind"] != parsed["context_kind"]
    ):
        raise ValueError(f"entry {i}: catalog index disagrees with authenticated IR")
    return entry, ir, parsed


def _entry_sort_key(entry: dict) -> tuple[int, bytes, bytes, int]:
    return (
        entry["chain_id"],
        entry["contract"],
        entry["primary_type_hash"],
        entry["ctx_kind"],
    )


def _leaf_hash(ir: bytes) -> bytes:
    return _sha256(b"\x00" + ir)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + left + right)


def _merkle_levels(irs: list[bytes]) -> list[list[bytes]]:
    if not irs:
        raise ValueError("cannot build a Merkle tree without catalogue leaves")
    leaves = [_leaf_hash(ir) for ir in irs]
    padded_count = 1 << (len(leaves) - 1).bit_length()
    leaves.extend([leaves[-1]] * (padded_count - len(leaves)))
    levels = [leaves]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append(
            [_node_hash(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        )
    return levels


def _known_call_may_contain(
    bloom: bytes, chain_id: int, contract: bytes, selector: bytes
) -> bool:
    digest = _sha256(
        KNOWN_CALL_DOMAIN
        + chain_id.to_bytes(8, "big")
        + contract
        + selector
    )
    h1 = int.from_bytes(digest[0:8], "big")
    h2 = int.from_bytes(digest[8:16], "big") | 1
    for probe in range(KNOWN_CALLS_BLOOM_HASHES):
        bit = (h1 + probe * h2) % KNOWN_CALLS_BLOOM_BITS
        if bloom[bit // 8] & (1 << (bit & 7)) == 0:
            return False
    return True


def _known_call_set_hash(tuples: set[tuple[int, bytes, bytes]]) -> bytes:
    """Hash one exact canonical known-call tuple set like dbgen."""
    digest = hashlib.sha256()
    digest.update(KNOWN_CALL_SET_DOMAIN)
    digest.update(len(tuples).to_bytes(8, "big"))
    for chain_id, contract, selector in sorted(tuples):
        digest.update(chain_id.to_bytes(8, "big"))
        digest.update(contract)
        digest.update(selector)
    return digest.digest()


def parse_forced_eligible(raw: bytes) -> dict:
    """Strictly parse one complete canonical big-endian P73K V1 artifact."""
    if len(raw) < FORCED_ELIGIBLE_HEADER_LEN:
        raise ValueError(
            "forced-eligible set is shorter than its fixed header: "
            f"{len(raw)} < {FORCED_ELIGIBLE_HEADER_LEN}"
        )
    if raw[:4] != FORCED_ELIGIBLE_MAGIC:
        raise ValueError(f"bad forced-eligible magic: {raw[:4]!r}")

    schema_version = int.from_bytes(raw[4:6], "big")
    header_len = int.from_bytes(raw[6:8], "big")
    group_count = int.from_bytes(raw[8:12], "big")
    tuple_count = int.from_bytes(raw[12:16], "big")
    if schema_version != FORCED_ELIGIBLE_SCHEMA_VERSION:
        raise ValueError(f"unknown forced-eligible schema: {schema_version}")
    if header_len != FORCED_ELIGIBLE_HEADER_LEN:
        raise ValueError(
            "forced-eligible header length mismatch: "
            f"{header_len} != {FORCED_ELIGIBLE_HEADER_LEN}"
        )

    groups_len = group_count * FORCED_ELIGIBLE_GROUP_LEN
    selectors_len = tuple_count * FORCED_ELIGIBLE_SELECTOR_LEN
    selector_pool_off = FORCED_ELIGIBLE_HEADER_LEN + groups_len
    expected_len = selector_pool_off + selectors_len
    if (
        groups_len > U32_MAX
        or selectors_len > U32_MAX
        or selector_pool_off > U32_MAX
        or expected_len > U32_MAX
    ):
        raise ValueError("forced-eligible count-derived length overflows u32")
    if len(raw) != expected_len:
        raise ValueError(
            "forced-eligible exact length mismatch: "
            f"{len(raw)} != {expected_len}"
        )

    groups: list[dict] = []
    tuples: list[tuple[int, bytes, bytes]] = []
    previous_group: tuple[int, bytes] | None = None
    selector_cursor = 0
    for group_index in range(group_count):
        base = FORCED_ELIGIBLE_HEADER_LEN + group_index * FORCED_ELIGIBLE_GROUP_LEN
        chain_id = int.from_bytes(raw[base : base + 8], "big")
        target = bytes(raw[base + 8 : base + 28])
        selector_start = int.from_bytes(raw[base + 28 : base + 32], "big")
        selector_count = int.from_bytes(raw[base + 32 : base + 34], "big")
        reserved = int.from_bytes(raw[base + 34 : base + 36], "big")

        group_key = (chain_id, target)
        if previous_group is not None and group_key <= previous_group:
            relation = "duplicates" if group_key == previous_group else "is out of order with"
            raise ValueError(
                f"forced-eligible group {group_index} {relation} group {group_index - 1}"
            )
        previous_group = group_key
        if reserved != 0:
            raise ValueError(
                f"forced-eligible group {group_index} has non-zero reserved bytes"
            )
        if selector_count == 0:
            raise ValueError(f"forced-eligible group {group_index} is empty")

        selector_end = selector_start + selector_count
        if selector_end > U32_MAX:
            raise ValueError(
                f"forced-eligible group {group_index} selector range overflows u32"
            )
        if selector_start > tuple_count or selector_end > tuple_count:
            raise ValueError(
                f"forced-eligible group {group_index} selector range is out of bounds"
            )
        if selector_start != selector_cursor:
            raise ValueError(
                f"forced-eligible group {group_index} selector range is not contiguous: "
                f"{selector_start} != {selector_cursor}"
            )

        selectors: list[bytes] = []
        previous_selector: bytes | None = None
        for selector_index in range(selector_start, selector_end):
            offset = selector_pool_off + selector_index * FORCED_ELIGIBLE_SELECTOR_LEN
            selector = bytes(raw[offset : offset + FORCED_ELIGIBLE_SELECTOR_LEN])
            if previous_selector is not None and selector <= previous_selector:
                relation = (
                    "duplicates" if selector == previous_selector else "is out of order with"
                )
                raise ValueError(
                    f"forced-eligible selector {selector_index} {relation} "
                    f"selector {selector_index - 1} in group {group_index}"
                )
            previous_selector = selector
            selectors.append(selector)
            tuples.append((chain_id, target, selector))

        groups.append(
            {
                "chain_id": chain_id,
                "target": target,
                "selector_start": selector_start,
                "selector_count": selector_count,
                "selectors": tuple(selectors),
            }
        )
        selector_cursor = selector_end

    if selector_cursor != tuple_count:
        raise ValueError(
            "forced-eligible group ranges do not cover the selector pool: "
            f"{selector_cursor} != {tuple_count}"
        )
    return {
        "schema_version": schema_version,
        "header_len": header_len,
        "group_count": group_count,
        "tuple_count": tuple_count,
        "groups": tuple(groups),
        "tuples": tuple(tuples),
    }


def verify_catalogue(
    status_raw: bytes,
    blob: bytes,
    bloom: bytes,
    forced_eligible: bytes | None = None,
) -> dict:
    """Bind and fully preflight one immutable P730/Bloom byte snapshot.

    Relative to the caller-authenticated status, this proves the compiled leaf
    set and every stored proof agree, and that every compiled contract selector
    is present in the bound omission Bloom. It cannot recover the exact
    registry-declared tuple superset from that non-invertible Bloom when no
    P73K is supplied. With `forced_eligible`, it independently parses the exact
    refused-known set F, recovers C from the already strict P730 contract IRs,
    and proves their disjoint union reproduces the P73S-bound K identity. This
    function does not verify a firmware signature or authenticate P73K's image
    placement; callers of the optional path must supply bytes extracted from
    the same authenticated secure image as P73S.
    """
    status = parse_catalogue_status(status_raw)
    if status["catalogue_version"] != CATALOGUE_VERSION:
        raise ValueError(
            f"unsupported P730 catalogue version in status: {status['catalogue_version']}"
        )
    if status["ir_schema_version"] != IR_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported ERC-7730 IR schema in status: {status['ir_schema_version']}"
        )
    if status["leaf_count"] == 0:
        raise ValueError("catalogue status declares zero leaves")
    if status["catalogue_size"] != len(blob):
        raise ValueError(
            "catalogue byte-size mismatch: "
            f"{len(blob)} != {status['catalogue_size']}"
        )
    if status["bloom_size"] != KNOWN_CALLS_BLOOM_BYTES:
        raise ValueError(
            "unsupported known-call Bloom size in status: "
            f"{status['bloom_size']} != {KNOWN_CALLS_BLOOM_BYTES}"
        )
    if len(bloom) != status["bloom_size"]:
        raise ValueError(
            f"known-call Bloom byte-size mismatch: {len(bloom)} != {status['bloom_size']}"
        )
    if _sha256(blob) != status["catalogue_sha256"]:
        raise ValueError("catalogue SHA-256 does not match authenticated status")
    if _sha256(bloom) != status["bloom_sha256"]:
        raise ValueError("known-call Bloom SHA-256 does not match authenticated status")

    hdr = _read_header(blob)
    if hdr["version"] != status["catalogue_version"]:
        raise ValueError(
            "P730 header/status version mismatch: "
            f"{hdr['version']} != {status['catalogue_version']}"
        )
    if hdr["entry_cnt"] != status["leaf_count"]:
        raise ValueError(
            "P730 entry/status leaf-count mismatch: "
            f"{hdr['entry_cnt']} != {status['leaf_count']}"
        )
    expected_depth = (status["leaf_count"] - 1).bit_length()
    if hdr["proof_depth"] != expected_depth:
        raise ValueError(
            "non-canonical P730 proof depth: "
            f"{hdr['proof_depth']} != {expected_depth}"
        )

    entries: list[dict] = []
    parsed_irs: list[dict] = []
    irs: list[bytes] = []
    compiled_known_calls: set[tuple[int, bytes, bytes]] = set()
    previous_key: tuple[int, bytes, bytes, int] | None = None
    next_ir_off = 0
    for i in range(hdr["entry_cnt"]):
        entry, ir, parsed = _parsed_entry(blob, hdr, i)
        if ir[0] != status["ir_schema_version"]:
            raise ValueError(
                f"entry {i}: IR/status schema mismatch: "
                f"{ir[0]} != {status['ir_schema_version']}"
            )

        if entry["ctx_kind"] == CTX_CONTRACT:
            expected_primary_type_hash = bytes(32)
        else:
            if not parsed["type_hashes"]:
                raise ValueError(f"entry {i}: EIP-712 IR has no authenticated formats")
            expected_primary_type_hash = parsed["type_hashes"][0]
        if entry["primary_type_hash"] != expected_primary_type_hash:
            raise ValueError(
                f"entry {i}: primary-type-hash index disagrees with authenticated IR"
            )

        key = _entry_sort_key(entry)
        if previous_key is not None and key <= previous_key:
            relation = "duplicates" if key == previous_key else "is out of order with"
            raise ValueError(f"entry {i}: catalogue sort key {relation} entry {i - 1}")
        previous_key = key

        if entry["ir_off"] != next_ir_off:
            raise ValueError(
                f"entry {i}: non-contiguous IR offset "
                f"{entry['ir_off']} != {next_ir_off}"
            )
        next_ir_off += entry["ir_len"]

        if entry["ctx_kind"] == CTX_CONTRACT:
            for selector in parsed["selectors"]:
                compiled_known_calls.add(
                    (entry["chain_id"], entry["contract"], selector)
                )

        entries.append(entry)
        parsed_irs.append(parsed)
        irs.append(ir)

    if next_ir_off != hdr["ir_pool_size"]:
        raise ValueError(
            "IR slices do not consume the complete pool: "
            f"{next_ir_off} != {hdr['ir_pool_size']}"
        )
    if len(compiled_known_calls) > status["known_call_count"]:
        raise ValueError(
            "compiled known-call count exceeds authenticated registry tuple count: "
            f"{len(compiled_known_calls)} > {status['known_call_count']}"
        )
    if forced_eligible is None:
        # Preserve the original validation path and failure ordering when the
        # optional exact refused-known set is absent.
        for chain_id, contract, selector in sorted(compiled_known_calls):
            if not _known_call_may_contain(bloom, chain_id, contract, selector):
                raise ValueError(
                    "authenticated known-call Bloom omits compiled tuple "
                    f"chain={chain_id} contract=0x{contract.hex()} "
                    f"selector=0x{selector.hex()}"
                )
    levels = _merkle_levels(irs)
    root = levels[-1][0]
    if root != status["descriptor_root"]:
        raise ValueError("reconstructed descriptor root does not match authenticated status")
    for i in range(hdr["entry_cnt"]):
        proof = []
        index = i
        for level in levels[:-1]:
            proof.append(level[index ^ 1])
            index >>= 1
        expected_proof = b"".join(proof)
        proof_base = hdr["proofs_off"] + i * hdr["proof_depth"] * 32
        stored_proof = _slice(
            blob,
            proof_base,
            hdr["proof_depth"] * 32,
            f"proof for leaf {i}",
        )
        if stored_proof != expected_proof:
            raise ValueError(f"stored Merkle proof disagrees for leaf {i}")

    parsed_forced = None
    forced_known_calls: set[tuple[int, bytes, bytes]] | None = None
    if forced_eligible is not None:
        parsed_forced = parse_forced_eligible(forced_eligible)
        forced_known_calls = set(parsed_forced["tuples"])
        overlap = compiled_known_calls & forced_known_calls
        if overlap:
            chain_id, contract, selector = min(overlap)
            raise ValueError(
                "clear/refused-known partition overlaps at "
                f"chain={chain_id} contract=0x{contract.hex()} "
                f"selector=0x{selector.hex()}"
            )
        known_calls = compiled_known_calls | forced_known_calls
        if len(known_calls) != status["known_call_count"]:
            raise ValueError(
                "clear/refused-known union count does not match authenticated status: "
                f"{len(known_calls)} != {status['known_call_count']}"
            )
        if _known_call_set_hash(known_calls) != status["known_call_set_sha256"]:
            raise ValueError(
                "clear/refused-known union SHA-256 does not match authenticated status"
            )
        for chain_id, contract, selector in sorted(known_calls):
            if not _known_call_may_contain(bloom, chain_id, contract, selector):
                raise ValueError(
                    "authenticated known-call Bloom omits partition tuple "
                    f"chain={chain_id} contract=0x{contract.hex()} "
                    f"selector=0x{selector.hex()}"
                )

    return {
        "status": status,
        "header": hdr,
        "entries": tuple(entries),
        "parsed_irs": tuple(parsed_irs),
        "compiled_known_call_count": len(compiled_known_calls),
        "clear_known_call_count": len(compiled_known_calls),
        "forced_known_call_count": (
            len(forced_known_calls) if forced_known_calls is not None else None
        ),
        "known_call_count": status["known_call_count"],
        "forced_eligible_bound": forced_known_calls is not None,
        "forced_eligible": parsed_forced,
    }


def _select_entry(
    blob: bytes,
    hdr: dict,
    chain_id: int,
    contract: bytes,
    context: str,
    domain_separator: bytes | None,
    primary_type_hash: bytes | None,
) -> tuple[int, dict, bytes]:
    context_kind = {"contract": CTX_CONTRACT, "eip712": CTX_EIP712}[context]
    if context_kind == CTX_EIP712:
        if domain_separator is None:
            raise ValueError("--domain-separator is required for --context eip712")
        if primary_type_hash is None:
            raise ValueError("--primary-type-hash is required for --context eip712")
    elif domain_separator is not None or primary_type_hash is not None:
        raise ValueError(
            "--domain-separator and --primary-type-hash are only valid for --context eip712"
        )

    matches: list[tuple[int, dict, bytes]] = []
    for i in range(hdr["entry_cnt"]):
        entry, ir, parsed = _parsed_entry(blob, hdr, i)
        if (
            parsed["context_kind"] != context_kind
            or parsed["chain_id"] != chain_id
            or parsed["contract"] != contract
        ):
            continue
        if context_kind == CTX_EIP712:
            if parsed["domain_separator"] != domain_separator:
                continue
            if primary_type_hash not in parsed["type_hashes"]:
                continue
        matches.append((i, entry, ir))

    label = (
        f"EIP-712 descriptor for chain={chain_id} contract=0x{contract.hex()} "
        f"domainSeparator=0x{domain_separator.hex()} typeHash=0x{primary_type_hash.hex()}"
        if primary_type_hash is not None
        else f"contract descriptor for chain={chain_id} contract=0x{contract.hex()}"
    )
    if not matches:
        raise ValueError(f"no {label}")
    if len(matches) != 1:
        leaves = ", ".join(str(match[0]) for match in matches)
        raise ValueError(f"ambiguous {label}: matching leaves {leaves}")
    return matches[0]


def build_trailer(
    blob: bytes,
    chain_id: int,
    contract: bytes,
    *,
    context: str = "contract",
    domain_separator: bytes | None = None,
    primary_type_hash: bytes | None = None,
) -> bytes:
    """Produce one exact contract- or EIP-712-context trailer payload.

    Callers must first pass the same immutable `blob` to `verify_catalogue`.
    The command-line path enforces that ordering before it calls this pure
    assembler.
    """
    hdr = _read_header(blob)
    if context not in ("contract", "eip712"):
        raise ValueError(f"unknown lookup context: {context!r}")
    if primary_type_hash is not None and len(primary_type_hash) != 32:
        raise ValueError("primary_type_hash must be exactly 32 bytes")
    if domain_separator is not None and len(domain_separator) != 32:
        raise ValueError("domain_separator must be exactly 32 bytes")
    idx, entry, ir_bytes = _select_entry(
        blob,
        hdr,
        chain_id,
        contract,
        context,
        domain_separator,
        primary_type_hash,
    )
    proof_depth = hdr["proof_depth"]

    proof_base = hdr["proofs_off"] + idx * proof_depth * 32
    proof_bytes = _slice(blob, proof_base, proof_depth * 32, f"proof for leaf {idx}")

    out = bytearray()
    out += struct.pack(">H", len(ir_bytes))
    out += ir_bytes
    out += struct.pack(">I", idx)
    out += struct.pack(">I", proof_depth)
    out += proof_bytes
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--db",
        default="tools/companion-stub/erc7730_db.bin",
        help="path to the ERC-7730 catalog blob",
    )
    identity = ap.add_mutually_exclusive_group(required=True)
    identity.add_argument(
        "--bundle",
        help="signed .pqfw whose authenticated P73S must bind this catalogue",
    )
    identity.add_argument(
        "--unverified-status-for-test",
        help=(
            "TEST ONLY: loose P73S path for deterministic dbgen/unit fixtures; "
            "never enables a compatibility report"
        ),
    )
    ap.add_argument(
        "--pubkey",
        help="vendor public key required with --bundle",
    )
    ap.add_argument(
        "--fwsign-bin",
        help="path to the reviewed fwsign binary required with --bundle",
    )
    ap.add_argument(
        "--expected-firmware-version",
        type=int,
        help="exact signed firmware version required with --bundle",
    )
    ap.add_argument(
        "--minimum-firmware-version",
        type=int,
        help="minimum accepted firmware version required with --bundle",
    )
    ap.add_argument(
        "--require-erc8176-verified",
        action="store_true",
        help=(
            "require the authenticated P73S to carry erc8176-verified provenance; "
            "refuses dev-unattested releases before catalogue use"
        ),
    )
    ap.add_argument(
        "--known-calls-bloom",
        required=True,
        help="path to the exact firmware-pinned known-call Bloom bytes",
    )
    ap.add_argument("--chain", type=int, help="EIP-155 chain id")
    ap.add_argument("--contract", help="0x-prefixed contract address")
    ap.add_argument(
        "--context",
        choices=("contract", "eip712"),
        default="contract",
        help="exact descriptor context (default: contract)",
    )
    ap.add_argument(
        "--domain-separator",
        type=_parse_hash32,
        help="exact 32-byte EIP-712 domain separator; required for --context eip712",
    )
    ap.add_argument(
        "--primary-type-hash",
        type=_parse_hash32,
        help="full 32-byte hash; required for --context eip712",
    )
    ap.add_argument(
        "--out",
        help="optional output file; default stdout (binary)",
    )
    ap.add_argument(
        "--list",
        action="store_true",
        help="instead of emitting, print the (chain, contract) pairs in the catalog",
    )
    ap.add_argument(
        "--compatibility-report",
        action="store_true",
        help=(
            "after signed-release and full-catalogue verification, emit compact "
            "compatibility JSON instead of listing or building a trailer"
        ),
    )
    args = ap.parse_args()

    release_args = {
        "--pubkey": args.pubkey,
        "--fwsign-bin": args.fwsign_bin,
        "--expected-firmware-version": args.expected_firmware_version,
        "--minimum-firmware-version": args.minimum_firmware_version,
    }
    if args.bundle:
        missing = [name for name, value in release_args.items() if value is None]
        if missing:
            ap.error(f"{', '.join(missing)} required with --bundle")
        if args.expected_firmware_version < 0 or args.minimum_firmware_version < 0:
            ap.error("firmware versions must be non-negative u32 values")
        if args.expected_firmware_version > 0xFFFF_FFFF:
            ap.error("--expected-firmware-version exceeds u32")
        if args.minimum_firmware_version > 0xFFFF_FFFF:
            ap.error("--minimum-firmware-version exceeds u32")
    else:
        supplied_release_args = [
            name for name, value in release_args.items() if value is not None
        ]
        if supplied_release_args:
            ap.error(
                f"{', '.join(supplied_release_args)} may only be used with --bundle"
            )
        if args.compatibility_report:
            ap.error(
                "--compatibility-report requires authenticated --bundle mode; "
                "test-only loose status has no release authority"
            )
        if args.require_erc8176_verified:
            ap.error("--require-erc8176-verified may only be used with --bundle")
    if args.compatibility_report and args.list:
        ap.error("--compatibility-report and --list are mutually exclusive")

    try:
        if args.bundle:
            status_raw, forced_eligible, release = _authenticated_release_status(
                fwsign_bin=args.fwsign_bin,
                bundle=args.bundle,
                pubkey=args.pubkey,
                expected_version=args.expected_firmware_version,
                minimum_version=args.minimum_firmware_version,
                require_erc8176_verified=args.require_erc8176_verified,
            )
        else:
            # Explicitly test-only: production/list/trailer callers must start
            # from the signed bundle path above.
            status_raw = Path(args.unverified_status_for_test).read_bytes()
            forced_eligible = None
            release = None

        # Each catalogue file is read exactly once. All selection, listing,
        # reporting, and bundle assembly use these immutable byte snapshots.
        blob = Path(args.db).read_bytes()
        bloom = Path(args.known_calls_bloom).read_bytes()
        verified = verify_catalogue(status_raw, blob, bloom, forced_eligible)
    except (OSError, ValueError) as exc:
        ap.error(str(exc))

    if args.compatibility_report:
        # Test-only mode was rejected above, so release cannot be None here.
        print(_compatibility_report(release, verified, status_raw))
        return 0

    if args.list:
        hdr = verified["header"]
        print(
            f"# {hdr['entry_cnt']} entries, "
            f"proof_depth={hdr['proof_depth']}, "
            f"ir_pool={hdr['ir_pool_size']} B"
        )
        for i in range(hdr["entry_cnt"]):
            e, _ir, parsed = _parsed_entry(blob, hdr, i)
            ctx = {CTX_CONTRACT: "Contract", CTX_EIP712: "EIP712"}[
                parsed["context_kind"]
            ]
            hashes = ",".join(f"0x{h.hex()}" for h in parsed["type_hashes"])
            print(
                f"  [{i:3d}] chain={e['chain_id']:>5} "
                f"contract=0x{e['contract'].hex()} "
                f"ctx={ctx} ir_len={e['ir_len']}"
                + (
                    f" domain_separator=0x{parsed['domain_separator'].hex()}"
                    if parsed["context_kind"] == CTX_EIP712
                    else ""
                )
                + (f" type_hashes={hashes}" if hashes else "")
            )
        return 0

    if args.chain is None or args.contract is None:
        ap.error("--chain and --contract are required unless --list is given")
    contract = _parse_address(args.contract)
    try:
        trailer = build_trailer(
            blob,
            args.chain,
            contract,
            context=args.context,
            domain_separator=args.domain_separator,
            primary_type_hash=args.primary_type_hash,
        )
    except ValueError as exc:
        ap.error(str(exc))

    if args.out:
        Path(args.out).write_bytes(trailer)
        print(
            f"wrote {len(trailer)} B trailer (chain={args.chain} "
            f"contract=0x{contract.hex()} context={args.context}) to {args.out}",
            file=sys.stderr,
        )
    else:
        sys.stdout.buffer.write(trailer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
