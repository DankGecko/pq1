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


def fixture_clear_tuples(variant: int = 0) -> list[tuple[int, bytes, bytes]]:
    return [
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


def fixture_forced_tuples(variant: int = 0) -> list[tuple[int, bytes, bytes]]:
    return [
        (
            3 + variant * 10,
            bytes([0x33 + variant]) * 20,
            bytes([9 + variant, 10, 11, 12]),
        ),
        (
            3 + variant * 10,
            bytes([0x33 + variant]) * 20,
            bytes([10 + variant, 11, 12, 13]),
        ),
        (
            4 + variant * 10,
            bytes([0x44 + variant]) * 20,
            bytes([13 + variant, 14, 15, 16]),
        ),
    ]


def make_forced_eligible(tuples: list[tuple[int, bytes, bytes]]) -> bytes:
    canonical = sorted(tuples)
    if len(canonical) != len(set(canonical)):
        raise ValueError("test fixture P73K tuples must be unique")

    groups: list[tuple[int, bytes, list[bytes]]] = []
    for chain_id, target, selector in canonical:
        if groups and groups[-1][0:2] == (chain_id, target):
            groups[-1][2].append(selector)
        else:
            groups.append((chain_id, target, [selector]))

    out = bytearray(trailer.FORCED_ELIGIBLE_MAGIC)
    out += trailer.FORCED_ELIGIBLE_SCHEMA_VERSION.to_bytes(2, "big")
    out += trailer.FORCED_ELIGIBLE_HEADER_LEN.to_bytes(2, "big")
    out += len(groups).to_bytes(4, "big")
    out += len(canonical).to_bytes(4, "big")
    selector_start = 0
    selector_pool = bytearray()
    for chain_id, target, selectors in groups:
        out += chain_id.to_bytes(8, "big")
        out += target
        out += selector_start.to_bytes(4, "big")
        out += len(selectors).to_bytes(2, "big")
        out += b"\x00\x00"
        selector_start += len(selectors)
        selector_pool += b"".join(selectors)
    out += selector_pool
    return bytes(out)


def make_fixture(
    variant: int = 0,
    forced_tuples: tuple[tuple[int, bytes, bytes], ...] = (),
    provenance: int = trailer.PROVENANCE_DEV_UNATTESTED,
) -> tuple[bytes, bytes, bytes]:
    clear_tuples = fixture_clear_tuples(variant)
    known_tuples = clear_tuples + list(forced_tuples)
    irs = [make_ir(*known_call) for known_call in clear_tuples]
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
    for (chain_id, contract, _selector), ir in zip(clear_tuples, irs):
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
    for known_call in known_tuples:
        add_bloom_tuple(bloom, *known_call)

    status = bytearray(trailer.STATUS_LEN)
    status[:4] = trailer.STATUS_MAGIC
    status[4:6] = trailer.STATUS_SCHEMA_VERSION.to_bytes(2, "big")
    status[6:8] = trailer.STATUS_LEN.to_bytes(2, "big")
    status[8:12] = trailer.CATALOGUE_VERSION.to_bytes(4, "big")
    status[12] = trailer.IR_SCHEMA_VERSION
    status[13] = provenance
    status[16:20] = entry_count.to_bytes(4, "big")
    status[20:24] = len(blob).to_bytes(4, "big")
    status[24:28] = len(known_tuples).to_bytes(4, "big")
    status[28:32] = len(bloom).to_bytes(4, "big")
    status[32:64] = root
    status[64:96] = sha256(bytes(blob))
    status[96:128] = known_call_set_hash(known_tuples)
    status[128:160] = sha256(bytes(bloom))
    status[224:231] = b"test/1\x00"
    return bytes(status), bytes(blob), bytes(bloom)


def rebind_catalogue_hash(status: bytearray, blob: bytes) -> None:
    status[20:24] = len(blob).to_bytes(4, "big")
    status[64:96] = sha256(blob)


def make_release_report(
    status_raw: bytes,
    version: int,
    minimum: int,
    forced_eligible: bytes | None = None,
) -> dict:
    status = trailer.parse_catalogue_status(status_raw)
    forced_metadata = None
    if forced_eligible is not None:
        parsed = trailer.parse_forced_eligible(forced_eligible)
        forced_metadata = {
            "format": "P73K",
            "schema": parsed["schema_version"],
            "encoded_length": len(forced_eligible),
            "group_count": parsed["group_count"],
            "tuple_count": parsed["tuple_count"],
            "set_sha256": sha256(forced_eligible).hex(),
        }
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
        "forced_eligible": forced_metadata,
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

    def test_forced_eligible_parser_accepts_canonical_empty_and_nonempty_sets(self) -> None:
        empty = trailer.parse_forced_eligible(make_forced_eligible([]))
        self.assertEqual(empty["group_count"], 0)
        self.assertEqual(empty["tuple_count"], 0)
        self.assertEqual(empty["tuples"], ())

        expected = fixture_forced_tuples()
        parsed = trailer.parse_forced_eligible(make_forced_eligible(expected))
        self.assertEqual(parsed["schema_version"], 1)
        self.assertEqual(parsed["header_len"], 16)
        self.assertEqual(parsed["group_count"], 2)
        self.assertEqual(parsed["tuple_count"], 3)
        self.assertEqual(parsed["tuples"], tuple(expected))
        self.assertEqual(parsed["groups"][0]["selector_start"], 0)
        self.assertEqual(parsed["groups"][0]["selector_count"], 2)
        self.assertEqual(parsed["groups"][1]["selector_start"], 2)

    def test_forced_eligible_parser_rejects_header_length_and_arithmetic_faults(self) -> None:
        good = make_forced_eligible(fixture_forced_tuples())
        cases: list[tuple[str, bytes, str]] = []

        malformed = bytearray(good)
        malformed[0] ^= 1
        cases.append(("magic", bytes(malformed), "magic"))
        malformed = bytearray(good)
        malformed[5] = 2
        cases.append(("schema", bytes(malformed), "schema"))
        malformed = bytearray(good)
        malformed[7] = 15
        cases.append(("header_len", bytes(malformed), "header length"))
        cases.append(("short_header", good[:15], "shorter than"))
        cases.append(("truncated", good[:-1], "exact length"))
        cases.append(("trailing", good + b"\x00", "exact length"))

        group_overflow = bytearray(16)
        group_overflow[:4] = trailer.FORCED_ELIGIBLE_MAGIC
        group_overflow[4:6] = (1).to_bytes(2, "big")
        group_overflow[6:8] = (16).to_bytes(2, "big")
        group_overflow[8:12] = (0xFFFF_FFFF).to_bytes(4, "big")
        cases.append(("group_overflow", bytes(group_overflow), "overflows u32"))
        tuple_overflow = bytearray(group_overflow)
        tuple_overflow[8:12] = bytes(4)
        tuple_overflow[12:16] = (0xFFFF_FFFF).to_bytes(4, "big")
        cases.append(("tuple_overflow", bytes(tuple_overflow), "overflows u32"))

        for label, raw, expected in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, expected):
                    trailer.parse_forced_eligible(raw)

    def test_forced_eligible_parser_rejects_group_and_range_faults(self) -> None:
        good = make_forced_eligible(fixture_forced_tuples())
        cases: list[tuple[str, bytes, str]] = []

        malformed = bytearray(good)
        malformed[51] = 1
        cases.append(("reserved", bytes(malformed), "reserved"))
        malformed = bytearray(good)
        malformed[48:50] = bytes(2)
        cases.append(("empty", bytes(malformed), "is empty"))
        malformed = bytearray(good)
        malformed[52:60] = bytes(8)
        cases.append(("group_order", bytes(malformed), "out of order"))
        malformed = bytearray(good)
        malformed[52:80] = malformed[16:44]
        cases.append(("group_duplicate", bytes(malformed), "duplicates"))
        malformed = bytearray(good)
        malformed[44:48] = (0xFFFF_FFFF).to_bytes(4, "big")
        cases.append(("range_overflow", bytes(malformed), "overflows u32"))
        malformed = bytearray(good)
        malformed[44:48] = (3).to_bytes(4, "big")
        cases.append(("range_bounds", bytes(malformed), "out of bounds"))
        malformed = bytearray(good)
        malformed[44:48] = (1).to_bytes(4, "big")
        cases.append(("initial_gap", bytes(malformed), "not contiguous"))
        malformed = bytearray(good)
        malformed[80:84] = (1).to_bytes(4, "big")
        cases.append(("overlap", bytes(malformed), "not contiguous"))

        for label, raw, expected in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, expected):
                    trailer.parse_forced_eligible(raw)

        uncovered = bytearray(trailer.FORCED_ELIGIBLE_MAGIC)
        uncovered += (1).to_bytes(2, "big")
        uncovered += (16).to_bytes(2, "big")
        uncovered += bytes(4)
        uncovered += (1).to_bytes(4, "big")
        uncovered += b"\x01\x02\x03\x04"
        with self.assertRaisesRegex(ValueError, "do not cover"):
            trailer.parse_forced_eligible(bytes(uncovered))

    def test_forced_eligible_parser_rejects_selector_duplicates_and_order(self) -> None:
        good = make_forced_eligible(fixture_forced_tuples())
        selector_pool_off = 16 + 2 * 36

        duplicate = bytearray(good)
        duplicate[selector_pool_off + 4 : selector_pool_off + 8] = duplicate[
            selector_pool_off : selector_pool_off + 4
        ]
        with self.assertRaisesRegex(ValueError, "duplicates"):
            trailer.parse_forced_eligible(bytes(duplicate))

        out_of_order = bytearray(good)
        first = bytes(out_of_order[selector_pool_off : selector_pool_off + 4])
        second = bytes(out_of_order[selector_pool_off + 4 : selector_pool_off + 8])
        out_of_order[selector_pool_off : selector_pool_off + 4] = second
        out_of_order[selector_pool_off + 4 : selector_pool_off + 8] = first
        with self.assertRaisesRegex(ValueError, "out of order"):
            trailer.parse_forced_eligible(bytes(out_of_order))

    def test_catalogue_partition_preserves_legacy_mode_and_binds_empty_f(self) -> None:
        status, blob, bloom = make_fixture()
        legacy = trailer.verify_catalogue(status, blob, bloom)
        self.assertEqual(legacy["compiled_known_call_count"], 2)
        self.assertEqual(legacy["clear_known_call_count"], 2)
        self.assertIsNone(legacy["forced_known_call_count"])
        self.assertEqual(legacy["known_call_count"], 2)
        self.assertIs(legacy["forced_eligible_bound"], False)
        self.assertIsNone(legacy["forced_eligible"])

        bound = trailer.verify_catalogue(
            status, blob, bloom, make_forced_eligible([])
        )
        self.assertEqual(bound["clear_known_call_count"], 2)
        self.assertEqual(bound["forced_known_call_count"], 0)
        self.assertEqual(bound["known_call_count"], 2)
        self.assertIs(bound["forced_eligible_bound"], True)

    def test_catalogue_partition_binds_nonempty_f_and_all_known_bloom(self) -> None:
        forced = fixture_forced_tuples()
        status, blob, bloom = make_fixture(forced_tuples=tuple(forced))
        verified = trailer.verify_catalogue(
            status, blob, bloom, make_forced_eligible(forced)
        )
        self.assertEqual(verified["clear_known_call_count"], 2)
        self.assertEqual(verified["forced_known_call_count"], 3)
        self.assertEqual(verified["known_call_count"], 5)
        self.assertIs(verified["forced_eligible_bound"], True)
        self.assertEqual(verified["forced_eligible"]["tuples"], tuple(forced))

        clear_only_bloom = bytearray(trailer.KNOWN_CALLS_BLOOM_BYTES)
        for known_call in fixture_clear_tuples():
            add_bloom_tuple(clear_only_bloom, *known_call)
        status_without_forced_bloom = bytearray(status)
        status_without_forced_bloom[128:160] = sha256(bytes(clear_only_bloom))
        with self.assertRaisesRegex(ValueError, "Bloom omits partition tuple"):
            trailer.verify_catalogue(
                bytes(status_without_forced_bloom),
                blob,
                bytes(clear_only_bloom),
                make_forced_eligible(forced),
            )

    def test_catalogue_partition_rejects_overlap_omission_and_substitution(self) -> None:
        forced = fixture_forced_tuples()
        status, blob, bloom = make_fixture(forced_tuples=tuple(forced))

        overlap = [fixture_clear_tuples()[0], *forced]
        with self.assertRaisesRegex(ValueError, "partition overlaps"):
            trailer.verify_catalogue(
                status, blob, bloom, make_forced_eligible(overlap)
            )

        with self.assertRaisesRegex(ValueError, "union count"):
            trailer.verify_catalogue(
                status, blob, bloom, make_forced_eligible(forced[:-1])
            )

        substituted = list(forced)
        substituted[-1] = (
            substituted[-1][0],
            substituted[-1][1],
            b"\xfe\xed\xfa\xce",
        )
        with self.assertRaisesRegex(ValueError, "union SHA-256"):
            trailer.verify_catalogue(
                status, blob, bloom, make_forced_eligible(substituted)
            )

    def test_catalogue_partition_rejects_prod_e2e_p73k_mismatch(self) -> None:
        prod_forced = fixture_forced_tuples(0)
        e2e_forced = fixture_forced_tuples(1)
        status, blob, bloom = make_fixture(
            variant=0, forced_tuples=tuple(prod_forced)
        )
        with self.assertRaisesRegex(ValueError, "union SHA-256"):
            trailer.verify_catalogue(
                status, blob, bloom, make_forced_eligible(e2e_forced)
            )

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

        missing_boundary = dict(release_a)
        del missing_boundary["forced_eligible"]
        with self.assertRaisesRegex(ValueError, "omits the forced_eligible"):
            trailer._validate_release_metadata(missing_boundary, status_a, 17, 16)

        malformed_boundary = dict(release_a)
        malformed_boundary["forced_eligible"] = {
            "format": "P73K",
            "schema": 1,
            "encoded_length": 17,
            "group_count": 0,
            "tuple_count": 0,
            "set_sha256": "00" * 32,
        }
        with self.assertRaisesRegex(ValueError, "inconsistent forced-eligible length"):
            trailer._validate_release_metadata(
                malformed_boundary, status_a, 17, 16
            )

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
        self.assertIs(report["catalogue"]["forced_eligible_bound"], False)
        self.assertIsNone(report["catalogue"]["forced_known_call_count"])
        self.assertEqual(
            report["catalogue"]["status_sha256"], sha256(status).hex()
        )

    def test_cli_combined_release_mode_uses_exact_private_status_output(self) -> None:
        status, blob, bloom = make_fixture(
            provenance=trailer.PROVENANCE_ERC8176_VERIFIED
        )
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
                "assert '--require-erc8176-verified' in sys.argv\n"
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
                    "--require-erc8176-verified",
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

    def test_authenticated_release_independently_refuses_dev_provenance(self) -> None:
        status, _blob, _bloom = make_fixture()
        release = make_release_report(status, 17, 16)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            status_source = root / "source-status.bin"
            fake_fwsign = root / "fake-fwsign"
            status_source.write_bytes(status)
            fake_fwsign.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                f"status = pathlib.Path({str(status_source)!r}).read_bytes()\n"
                "assert '--require-erc8176-verified' in sys.argv\n"
                "out = pathlib.Path(sys.argv[sys.argv.index('--status-out') + 1])\n"
                "out.write_bytes(status)\n"
                f"print(json.dumps({release!r}, sort_keys=True, separators=(',', ':')))\n",
                encoding="utf-8",
            )
            fake_fwsign.chmod(0o755)

            with self.assertRaisesRegex(ValueError, "requires erc8176-verified"):
                trailer._authenticated_release_status(
                    fwsign_bin=str(fake_fwsign),
                    bundle="ignored-bundle",
                    pubkey="ignored-pubkey",
                    expected_version=17,
                    minimum_version=16,
                    require_erc8176_verified=True,
                )

    def test_cli_authenticated_release_extracts_and_proves_p73k_partition(self) -> None:
        forced_tuples = fixture_forced_tuples()
        forced = make_forced_eligible(forced_tuples)
        status, blob, bloom = make_fixture(forced_tuples=tuple(forced_tuples))
        release = make_release_report(status, 17, 16, forced)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            status_source = root / "source-status.bin"
            forced_source = root / "source-forced.bin"
            db = root / "catalogue.bin"
            bloom_path = root / "known-calls.bloom"
            fake_bundle = root / "release.pqfw"
            fake_pubkey = root / "vendor.pub"
            fake_fwsign = root / "fake-fwsign"
            status_source.write_bytes(status)
            forced_source.write_bytes(forced)
            db.write_bytes(blob)
            bloom_path.write_bytes(bloom)
            fake_bundle.write_bytes(b"fixture")
            fake_pubkey.write_bytes(bytes(32))
            fake_fwsign.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                f"status = pathlib.Path({str(status_source)!r}).read_bytes()\n"
                f"forced = pathlib.Path({str(forced_source)!r}).read_bytes()\n"
                "if '--status-out' in sys.argv:\n"
                "    pathlib.Path(sys.argv[sys.argv.index('--status-out') + 1]).write_bytes(status)\n"
                "if '--forced-eligible-out' in sys.argv:\n"
                "    pathlib.Path(sys.argv[sys.argv.index('--forced-eligible-out') + 1]).write_bytes(forced)\n"
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
        self.assertIs(combined["catalogue"]["forced_eligible_bound"], True)
        self.assertEqual(
            combined["catalogue"]["forced_known_call_count"], len(forced_tuples)
        )
        self.assertEqual(
            combined["authenticated_release"]["forced_eligible"]["set_sha256"],
            sha256(forced).hex(),
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
