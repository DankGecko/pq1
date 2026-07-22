#!/usr/bin/env python3
"""Focused tests for the companion P73S/P730 preflight."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("erc7730_trailer.py")
SPEC = importlib.util.spec_from_file_location("erc7730_trailer", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
trailer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trailer)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(ir: bytes) -> bytes:
    return sha256(b"\x00" + ir)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def make_ir(chain_id: int, contract: bytes, selector: bytes) -> bytes:
    intent = b"Test"
    formats = bytearray([1])
    formats += selector
    formats += bytes([0, len(intent)])  # no fields, intent length
    formats += (1).to_bytes(2, "big")  # one static-head word
    formats += b"\x00\x00"  # nested descents, string preimages
    formats += intent

    ir = bytearray(trailer.IR_HEADER_LEN)
    ir[0] = trailer.IR_SCHEMA_VERSION
    ir[1] = trailer.CTX_CONTRACT
    ir[2:10] = chain_id.to_bytes(8, "big")
    ir[10:30] = contract
    ir[126:128] = trailer.IR_HEADER_LEN.to_bytes(2, "big")
    ir[128:130] = trailer.IR_HEADER_LEN.to_bytes(2, "big")
    ir[132:134] = len(formats).to_bytes(2, "big")
    ir += formats
    return bytes(ir)


def add_bloom_tuple(
    bloom: bytearray, chain_id: int, contract: bytes, selector: bytes
) -> None:
    digest = sha256(
        trailer.KNOWN_CALL_DOMAIN
        + chain_id.to_bytes(8, "big")
        + contract
        + selector
    )
    h1 = int.from_bytes(digest[:8], "big")
    h2 = int.from_bytes(digest[8:16], "big") | 1
    for probe in range(trailer.KNOWN_CALLS_BLOOM_HASHES):
        bit = (h1 + probe * h2) % trailer.KNOWN_CALLS_BLOOM_BITS
        bloom[bit // 8] |= 1 << (bit & 7)


def known_call_set_hash(tuples: list[tuple[int, bytes, bytes]]) -> bytes:
    encoded = bytearray(b"pqsigner/erc7730-known-call-set-v1")
    encoded += len(tuples).to_bytes(8, "big")
    for chain_id, contract, selector in sorted(tuples):
        encoded += chain_id.to_bytes(8, "big") + contract + selector
    return sha256(bytes(encoded))


def make_fixture(variant: int = 0) -> tuple[bytes, bytes, bytes]:
    tuples = [
        (
            1 + variant * 10,
            bytes([0x11 + variant]) * 20,
            bytes([1 + variant, 2, 3, 4]),
        ),
        (
            2 + variant * 10,
            bytes([0x22 + variant]) * 20,
            bytes([5 + variant, 6, 7, 8]),
        ),
    ]
    irs = [make_ir(*known_call) for known_call in tuples]
    leaves = [leaf_hash(ir) for ir in irs]
    root = node_hash(leaves[0], leaves[1])

    entry_count = len(irs)
    ir_pool_off = trailer.HEADER_LEN + entry_count * trailer.ENTRY_LEN
    ir_pool_size = sum(map(len, irs))
    proofs_off = ir_pool_off + ir_pool_size
    blob = bytearray()
    blob += trailer.HEADER_MAGIC
    blob += trailer.CATALOGUE_VERSION.to_bytes(4, "little")
    blob += (0).to_bytes(4, "little")
    blob += entry_count.to_bytes(4, "little")
    blob += ir_pool_off.to_bytes(4, "little")
    blob += ir_pool_size.to_bytes(4, "little")
    blob += (1).to_bytes(4, "little")
    blob += proofs_off.to_bytes(4, "little")

    ir_off = 0
    for (chain_id, contract, _selector), ir in zip(tuples, irs):
        blob += chain_id.to_bytes(8, "little")
        blob += contract
        blob += bytes(32)  # Contract-context diagnostic primary-type hash.
        blob += bytes([trailer.CTX_CONTRACT, 0, 0, 0])
        blob += ir_off.to_bytes(4, "little")
        blob += len(ir).to_bytes(4, "little")
        ir_off += len(ir)
    blob += b"".join(irs)
    blob += leaves[1] + leaves[0]

    bloom = bytearray(trailer.KNOWN_CALLS_BLOOM_BYTES)
    for known_call in tuples:
        add_bloom_tuple(bloom, *known_call)

    status = bytearray(trailer.STATUS_LEN)
    status[:4] = trailer.STATUS_MAGIC
    status[4:6] = trailer.STATUS_SCHEMA_VERSION.to_bytes(2, "big")
    status[6:8] = trailer.STATUS_LEN.to_bytes(2, "big")
    status[8:12] = trailer.CATALOGUE_VERSION.to_bytes(4, "big")
    status[12] = trailer.IR_SCHEMA_VERSION
    status[13] = trailer.PROVENANCE_DEV_UNATTESTED
    status[16:20] = entry_count.to_bytes(4, "big")
    status[20:24] = len(blob).to_bytes(4, "big")
    status[24:28] = len(tuples).to_bytes(4, "big")
    status[28:32] = len(bloom).to_bytes(4, "big")
    status[32:64] = root
    status[64:96] = sha256(bytes(blob))
    status[96:128] = known_call_set_hash(tuples)
    status[128:160] = sha256(bytes(bloom))
    status[224:231] = b"test/1\x00"
    return bytes(status), bytes(blob), bytes(bloom)


def rebind_catalogue_hash(status: bytearray, blob: bytes) -> None:
    status[20:24] = len(blob).to_bytes(4, "big")
    status[64:96] = sha256(blob)


def make_release_report(status_raw: bytes, version: int, minimum: int) -> dict:
    status = trailer.parse_catalogue_status(status_raw)
    return {
        "report_kind": "authenticated-release-metadata",
        "erc8176_attestation": False,
        "production_authority": False,
        "device_rollback_verified": False,
        "version_policy": {"expected": version, "minimum": minimum},
        "firmware": {
            "manifest_version": 2,
            "firmware_version": version,
            "slot": "A",
            "slot_authenticated_by_legacy_signature": False,
            "secure_hash": "11" * 32,
            "secure_len": 1024,
            "nonsecure_hash": "22" * 32,
            "nonsecure_len": 2048,
            "build_id": "33" * 32,
            "build_id_authenticated_by_legacy_signature": False,
            "manifest_sha256": "44" * 32,
            "manifest_sha256_authenticated_by_legacy_signature": False,
        },
        "catalogue_status": trailer._catalogue_status_report(status, status_raw),
    }


class CatalogueVerificationTests(unittest.TestCase):
    def test_valid_status_catalogue_bloom_and_every_proof(self) -> None:
        status, blob, bloom = make_fixture()
        verified = trailer.verify_catalogue(status, blob, bloom)
        self.assertEqual(verified["status"]["tool_version"], "test/1")
        self.assertEqual(verified["compiled_known_call_count"], 2)
        self.assertEqual(verified["header"]["proof_depth"], 1)

    def test_status_parser_rejects_noncanonical_fields(self) -> None:
        good, _blob, _bloom = make_fixture()
        cases = {
            "magic": (0, ord("X"), "magic"),
            "schema": (5, 2, "schema"),
            "length": (6, 0, "length"),
            "provenance": (13, 2, "provenance"),
            "reserved": (14, 1, "reserved"),
            "tool_suffix": (240, ord("X"), "after its first NUL"),
        }
        for label, (offset, value, expected) in cases.items():
            with self.subTest(label=label):
                malformed = bytearray(good)
                malformed[offset] = value
                with self.assertRaisesRegex(ValueError, expected):
                    trailer.parse_catalogue_status(bytes(malformed))

        unterminated = bytearray(good)
        unterminated[224:256] = b"A" * 32
        with self.assertRaisesRegex(ValueError, "not NUL terminated"):
            trailer.parse_catalogue_status(bytes(unterminated))

        empty = bytearray(good)
        empty[224:256] = bytes(32)
        with self.assertRaisesRegex(ValueError, "tool version is empty"):
            trailer.parse_catalogue_status(bytes(empty))

    def test_catalogue_and_bloom_hash_mismatches_fail_before_output(self) -> None:
        status, blob, bloom = make_fixture()
        changed_blob = bytearray(blob)
        changed_blob[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "catalogue SHA-256"):
            trailer.verify_catalogue(status, bytes(changed_blob), bloom)

        changed_bloom = bytearray(bloom)
        changed_bloom[0] ^= 1
        with self.assertRaisesRegex(ValueError, "Bloom SHA-256"):
            trailer.verify_catalogue(status, blob, bytes(changed_bloom))

    def test_authenticated_but_wrong_accelerator_and_proof_are_rejected(self) -> None:
        status_raw, blob_raw, bloom = make_fixture()

        wrong_accelerator = bytearray(blob_raw)
        wrong_accelerator[trailer.HEADER_LEN + 28] = 1
        status = bytearray(status_raw)
        rebind_catalogue_hash(status, bytes(wrong_accelerator))
        with self.assertRaisesRegex(ValueError, "index disagrees"):
            trailer.verify_catalogue(bytes(status), bytes(wrong_accelerator), bloom)

        wrong_padding = bytearray(blob_raw)
        wrong_padding[trailer.HEADER_LEN + 61] = 1
        status = bytearray(status_raw)
        rebind_catalogue_hash(status, bytes(wrong_padding))
        with self.assertRaisesRegex(ValueError, "non-zero reserved padding"):
            trailer.verify_catalogue(bytes(status), bytes(wrong_padding), bloom)

        wrong_proof = bytearray(blob_raw)
        wrong_proof[-1] ^= 1
        status = bytearray(status_raw)
        rebind_catalogue_hash(status, bytes(wrong_proof))
        with self.assertRaisesRegex(ValueError, "stored Merkle proof"):
            trailer.verify_catalogue(bytes(status), bytes(wrong_proof), bloom)

    def test_authenticated_bloom_must_contain_every_compiled_selector(self) -> None:
        status_raw, blob, _bloom = make_fixture()
        empty_bloom = bytes(trailer.KNOWN_CALLS_BLOOM_BYTES)
        status = bytearray(status_raw)
        status[128:160] = sha256(empty_bloom)
        with self.assertRaisesRegex(ValueError, "omits compiled tuple"):
            trailer.verify_catalogue(bytes(status), blob, empty_bloom)

    def test_catalogue_transition_matrix_accepts_only_matching_status(self) -> None:
        status_a, blob_a, bloom_a = make_fixture(0)
        status_b, blob_b, bloom_b = make_fixture(1)
        self.assertEqual(trailer.verify_catalogue(status_a, blob_a, bloom_a)["header"]["entry_cnt"], 2)
        self.assertEqual(trailer.verify_catalogue(status_b, blob_b, bloom_b)["header"]["entry_cnt"], 2)
        with self.assertRaisesRegex(ValueError, "catalogue SHA-256"):
            trailer.verify_catalogue(status_a, blob_b, bloom_b)
        with self.assertRaisesRegex(ValueError, "catalogue SHA-256"):
            trailer.verify_catalogue(status_b, blob_a, bloom_a)

    def test_release_metadata_status_transition_matrix_and_version_policy(self) -> None:
        status_a, _blob_a, _bloom_a = make_fixture(0)
        status_b, _blob_b, _bloom_b = make_fixture(1)
        release_a = make_release_report(status_a, 17, 16)
        release_b = make_release_report(status_b, 18, 17)

        self.assertIs(
            trailer._validate_release_metadata(release_a, status_a, 17, 16),
            release_a,
        )
        self.assertIs(
            trailer._validate_release_metadata(release_b, status_b, 18, 17),
            release_b,
        )
        with self.assertRaisesRegex(ValueError, "does not equal"):
            trailer._validate_release_metadata(release_a, status_b, 17, 16)
        with self.assertRaisesRegex(ValueError, "does not equal"):
            trailer._validate_release_metadata(release_b, status_a, 18, 17)
        with self.assertRaisesRegex(ValueError, "version policy"):
            trailer._validate_release_metadata(release_a, status_a, 18, 17)
        with self.assertRaisesRegex(ValueError, "report kind"):
            trailer._validate_release_metadata({}, status_a, 17, 16)

    def test_compact_compatibility_report_is_explicitly_non_authoritative(self) -> None:
        status, blob, bloom = make_fixture()
        verified = trailer.verify_catalogue(status, blob, bloom)
        release = make_release_report(status, 17, 16)
        report = json.loads(trailer._compatibility_report(release, verified, status))
        self.assertEqual(report["report_kind"], "compatibility")
        self.assertIs(report["ready"], True)
        self.assertIs(report["erc8176_attestation"], False)
        self.assertIs(report["production_authority"], False)
        self.assertIs(report["device_rollback_verified"], False)
        self.assertEqual(report["catalogue"]["proofs_verified"], 2)
        self.assertEqual(
            report["catalogue"]["status_sha256"], sha256(status).hex()
        )

    def test_cli_combined_release_mode_uses_exact_private_status_output(self) -> None:
        status, blob, bloom = make_fixture()
        release = make_release_report(status, 17, 16)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            status_source = root / "source-status.bin"
            db = root / "catalogue.bin"
            bloom_path = root / "known-calls.bloom"
            fake_bundle = root / "release.pqfw"
            fake_pubkey = root / "vendor.pub"
            fake_fwsign = root / "fake-fwsign"
            status_source.write_bytes(status)
            db.write_bytes(blob)
            bloom_path.write_bytes(bloom)
            fake_bundle.write_bytes(b"fixture")
            fake_pubkey.write_bytes(bytes(32))
            fake_fwsign.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                f"status = pathlib.Path({str(status_source)!r}).read_bytes()\n"
                "out = pathlib.Path(sys.argv[sys.argv.index('--status-out') + 1])\n"
                "out.write_bytes(status)\n"
                f"print(json.dumps({release!r}, sort_keys=True, separators=(',', ':')))\n",
                encoding="utf-8",
            )
            fake_fwsign.chmod(0o755)

            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--db",
                    str(db),
                    "--known-calls-bloom",
                    str(bloom_path),
                    "--bundle",
                    str(fake_bundle),
                    "--pubkey",
                    str(fake_pubkey),
                    "--fwsign-bin",
                    str(fake_fwsign),
                    "--expected-firmware-version",
                    "17",
                    "--minimum-firmware-version",
                    "16",
                    "--compatibility-report",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        combined = json.loads(result.stdout)
        self.assertEqual(combined["report_kind"], "compatibility")
        self.assertIs(combined["ready"], True)
        self.assertEqual(
            combined["authenticated_release"]["firmware"]["firmware_version"],
            17,
        )

    def test_cli_requires_release_identity_and_bloom_even_for_list(self) -> None:
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"--bundle", result.stderr)
        self.assertIn(b"--unverified-status-for-test", result.stderr)
        self.assertIn(b"--known-calls-bloom", result.stderr)

    def test_test_only_status_cannot_emit_readiness_report(self) -> None:
        status, blob, bloom = make_fixture()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            status_path = root / "status.bin"
            db_path = root / "db.bin"
            bloom_path = root / "bloom.bin"
            status_path.write_bytes(status)
            db_path.write_bytes(blob)
            bloom_path.write_bytes(bloom)
            result = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--db",
                    str(db_path),
                    "--known-calls-bloom",
                    str(bloom_path),
                    "--unverified-status-for-test",
                    str(status_path),
                    "--compatibility-report",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires authenticated --bundle mode", result.stderr)


if __name__ == "__main__":
    unittest.main()
