#!/usr/bin/env python3
"""Deterministic offline tests for ERC-8176 threshold coverage reporting."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


CHECKER_PATH = Path(__file__).with_name("erc8176_eas_coverage.py")
SPEC = importlib.util.spec_from_file_location("erc8176_eas_coverage", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


HASH_A = "0x" + "aa" * 32
HASH_B = "0x" + "bb" * 32
ATTESTER_X = "0x" + "ab" * 20
ATTESTER_Y = "0x" + "cd" * 20
UNTRUSTED_Z = "0x" + "ef" * 20
ATTESTER_X_MIXED = "0x" + "Ab" * 20
ATTESTER_Y_MIXED = "0x" + "Cd" * 20


def corpus(*hashes: str) -> dict[str, list[tuple[str, str]]]:
    return {
        descriptor_hash: [("0x" + f"{index:040x}", f"descriptor-{index}.json")]
        for index, descriptor_hash in enumerate(hashes, start=1)
    }


def eas_record(
    descriptor_hash: str,
    attester: str,
    *,
    schema_id: object = checker.ERC8176_SCHEMA_UID,
    expiration_time: int | str = 0,
    revoked: bool = False,
) -> dict[str, object]:
    decoded = [
        {
            "name": "descriptorHash",
            "type": "bytes32",
            "signature": "bytes32 descriptorHash",
            "value": {
                "name": "descriptorHash",
                "type": "bytes32",
                "value": descriptor_hash,
            },
        }
    ]
    return {
        "schemaId": schema_id,
        "attester": attester,
        "decodedDataJson": json.dumps(decoded),
        "revoked": revoked,
        "time": 100,
        "expirationTime": expiration_time,
    }


class ThresholdCoverageTests(unittest.TestCase):
    def test_policy_derives_two_attester_threshold(self) -> None:
        self.assertEqual(checker.policy_min_attesters(), 2)

    def test_policy_missing_threshold_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / "policy.toml"
            policy.write_text("allow_unattested_dev_descriptors = true\n")
            with self.assertRaises(SystemExit):
                checker.policy_min_attesters(policy)

    def test_a_only_x_b_only_y_cannot_false_green(self) -> None:
        summary = checker.coverage_summary(
            corpus(HASH_A, HASH_B),
            [(HASH_A, ATTESTER_X), (HASH_B, ATTESTER_Y)],
            {ATTESTER_X, ATTESTER_Y},
            min_attesters=2,
        )

        self.assertEqual(summary["our_descriptors_with_any_trusted_attestation"], 2)
        self.assertEqual(summary["our_descriptors_meeting_trusted_threshold"], 0)
        self.assertEqual(len(summary["descriptor_shortfalls"]), 2)
        self.assertTrue(
            all(detail["shortfall"] == 1 for detail in summary["descriptor_shortfalls"])
        )
        verdict = checker.readiness_verdict(summary, {ATTESTER_X, ATTESTER_Y})
        self.assertNotIn("Safe to flip", verdict)
        self.assertIn("ZERO descriptors meet", verdict)

        report = checker.json_report(summary, {ATTESTER_X, ATTESTER_Y})
        self.assertEqual(report["min_attesters"], 2)
        self.assertEqual(report["our_descriptors_trusted_attested"], 0)
        self.assertEqual(len(report["descriptor_shortfalls"]), 2)

    def test_duplicate_records_from_one_attester_count_once(self) -> None:
        summary = checker.coverage_summary(
            corpus(HASH_A),
            [(HASH_A, ATTESTER_X), (HASH_A, ATTESTER_X), (HASH_A, ATTESTER_X)],
            {ATTESTER_X, ATTESTER_Y},
            min_attesters=2,
        )

        detail = summary["details"][0]
        self.assertEqual(detail["trusted_attesters"], [ATTESTER_X])
        self.assertEqual(detail["trusted_attesters_found"], 1)
        self.assertEqual(detail["shortfall"], 1)
        self.assertFalse(detail["meets_threshold"])
        self.assertNotIn(
            "Safe to flip",
            checker.readiness_verdict(summary, {ATTESTER_X, ATTESTER_Y}),
        )

    def test_two_distinct_trusted_attesters_per_descriptor_meet_threshold(self) -> None:
        summary = checker.coverage_summary(
            corpus(HASH_A, HASH_B),
            [
                (HASH_A, ATTESTER_X),
                (HASH_A, ATTESTER_Y),
                (HASH_B, ATTESTER_X),
                (HASH_B, ATTESTER_Y),
            ],
            {ATTESTER_X, ATTESTER_Y},
            min_attesters=2,
        )

        self.assertEqual(summary["our_descriptors_meeting_trusted_threshold"], 2)
        self.assertEqual(summary["descriptor_shortfalls"], [])
        verdict = checker.readiness_verdict(summary, {ATTESTER_X, ATTESTER_Y})
        self.assertIn("coverage prerequisite is met", verdict)
        self.assertIn("DO NOT flip", verdict)
        self.assertNotIn("Safe to flip", verdict)
        report = checker.json_report(summary, {ATTESTER_X, ATTESTER_Y})
        self.assertFalse(report["production_flip_authorized"])
        self.assertEqual(report["trust_input"], "command-line advisory set")

    def test_no_trusted_attesters_reports_full_shortfall(self) -> None:
        summary = checker.coverage_summary(
            corpus(HASH_A),
            [(HASH_A, UNTRUSTED_Z)],
            set(),
            min_attesters=2,
        )

        self.assertEqual(summary["our_descriptors_attested"], 1)
        self.assertEqual(summary["our_descriptors_with_any_trusted_attestation"], 0)
        self.assertEqual(summary["our_descriptors_meeting_trusted_threshold"], 0)
        self.assertEqual(summary["descriptor_shortfalls"][0]["shortfall"], 2)
        verdict = checker.readiness_verdict(summary, set())
        self.assertIn("give --trusted", verdict)
        self.assertNotIn("Safe to flip", verdict)

    def test_live_query_selects_per_row_schema_identity(self) -> None:
        response = json.dumps({"data": {"attestations": []}})
        completed = checker.subprocess.CompletedProcess(
            args=[], returncode=0, stdout=response, stderr=""
        )
        with mock.patch.object(checker.subprocess, "run", return_value=completed) as run:
            eligible, stats = checker.eas_attestations(as_of_unix=1_000)

        self.assertEqual(eligible, [])
        self.assertEqual(stats["records_returned"], 0)
        argv = run.call_args.args[0]
        body = json.loads(argv[argv.index("-d") + 1])
        query = body["query"]
        self.assertIn(
            f'where:{{schemaId:{{equals:"{checker.ERC8176_SCHEMA_UID}"}}}}',
            query,
        )
        self.assertIn(
            "){schemaId attester decodedDataJson revoked time expirationTime}",
            query,
        )

    def test_eas_parser_requires_exact_per_row_schema_identity(self) -> None:
        missing = eas_record(HASH_A, ATTESTER_X)
        missing.pop("schemaId")
        uppercase_uid = checker.ERC8176_SCHEMA_UID.upper().replace("0X", "0x")
        records = [
            eas_record(HASH_A, ATTESTER_X),
            eas_record(HASH_A, ATTESTER_Y, schema_id="0x" + "de" * 32),
            eas_record(HASH_B, ATTESTER_X, schema_id=uppercase_uid),
            missing,
        ]

        eligible, stats = checker.parse_eas_attestations(records, as_of_unix=1_000)
        self.assertEqual(eligible, [(HASH_A, ATTESTER_X)])
        self.assertEqual(stats["records_eligible"], 1)
        self.assertEqual(stats["records_malformed"], 3)

    def test_eas_parser_excludes_expired_revoked_and_malformed_rows(self) -> None:
        as_of = 1_000
        malformed = eas_record(HASH_A, ATTESTER_X)
        malformed.pop("expirationTime")
        malformed_field = eas_record(HASH_A, ATTESTER_X)
        malformed_field["decodedDataJson"] = "[7]"
        records = [
            eas_record(HASH_A, ATTESTER_X, expiration_time=0),
            eas_record(HASH_B, ATTESTER_Y, expiration_time="1001"),
            eas_record(HASH_A, ATTESTER_Y, expiration_time=1_000),
            eas_record(HASH_B, ATTESTER_X, expiration_time=999),
            eas_record(HASH_A, ATTESTER_X, revoked=True),
            malformed,
            malformed_field,
            "not-an-attestation-object",
        ]

        eligible, stats = checker.parse_eas_attestations(records, as_of)
        self.assertEqual(eligible, [(HASH_A, ATTESTER_X), (HASH_B, ATTESTER_Y)])
        self.assertEqual(
            stats,
            {
                "records_returned": 8,
                "records_eligible": 2,
                "records_expired": 2,
                "records_revoked": 1,
                "records_malformed": 3,
            },
        )

    def test_expired_matching_attesters_cannot_false_green(self) -> None:
        records = [
            eas_record(HASH_A, ATTESTER_X, expiration_time=999),
            eas_record(HASH_A, ATTESTER_Y, expiration_time=999),
        ]
        eligible, stats = checker.parse_eas_attestations(records, as_of_unix=1_000)
        summary = checker.coverage_summary(
            corpus(HASH_A),
            eligible,
            {ATTESTER_X, ATTESTER_Y},
            min_attesters=2,
            source_stats=stats,
        )

        self.assertEqual(summary["eas_attestations_expired"], 2)
        self.assertEqual(summary["our_descriptors_meeting_trusted_threshold"], 0)
        self.assertIn(
            "ZERO descriptors meet",
            checker.readiness_verdict(summary, {ATTESTER_X, ATTESTER_Y}),
        )

    def test_mixed_case_normalization_is_pinned_at_each_layer(self) -> None:
        records = [
            eas_record(HASH_A, ATTESTER_X_MIXED),
            eas_record(HASH_A, ATTESTER_Y_MIXED),
        ]
        eligible, stats = checker.parse_eas_attestations(records, as_of_unix=1_000)
        trusted = checker.normalize_trusted_addresses(
            [ATTESTER_X_MIXED, ATTESTER_Y_MIXED]
        )

        # These intermediate assertions are deliberate mutation controls:
        # deleting normalization in either parser or trust-input handling must
        # fail before summary normalization can conceal the regression.
        self.assertEqual(eligible, [(HASH_A, ATTESTER_X), (HASH_A, ATTESTER_Y)])
        self.assertEqual(trusted, {ATTESTER_X, ATTESTER_Y})
        self.assertEqual(stats["records_eligible"], 2)

        end_to_end = checker.coverage_summary(
            corpus(HASH_A), eligible, trusted, min_attesters=2, source_stats=stats
        )
        self.assertEqual(end_to_end["our_descriptors_meeting_trusted_threshold"], 1)

        # Feed mixed-case identities directly to isolate the summary layer.
        # Removing its `.lower()` must make this threshold assertion fail.
        summary_control = checker.coverage_summary(
            corpus(HASH_A),
            [(HASH_A, ATTESTER_X_MIXED), (HASH_A, ATTESTER_Y_MIXED)],
            {ATTESTER_X, ATTESTER_Y},
            min_attesters=2,
        )
        self.assertEqual(summary_control["our_descriptors_meeting_trusted_threshold"], 1)

    def test_trusted_addresses_are_validated_and_normalized(self) -> None:
        self.assertEqual(
            checker.normalize_trusted_addresses([ATTESTER_X.upper().replace("0X", "0x")]),
            {ATTESTER_X},
        )
        with self.assertRaises(SystemExit):
            checker.normalize_trusted_addresses(["not-an-address"])


if __name__ == "__main__":
    unittest.main()
