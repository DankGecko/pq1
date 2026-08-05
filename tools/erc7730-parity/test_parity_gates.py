#!/usr/bin/env python3
"""Focused fail-closed tests for the ERC-7730 parity receipt binding."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/cross_parity_erc7730.py"
SPEC = importlib.util.spec_from_file_location("cross_parity_erc7730_under_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {MODULE_PATH}")
PARITY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PARITY
SPEC.loader.exec_module(PARITY)


class ReviewReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.review_bytes = PARITY.REVIEW.read_bytes()
        cls.review = cls.review_bytes.decode("utf-8")
        cls.root, cls.count = PARITY.parse_production_descriptor_receipt(
            PARITY.ROOTS_SOURCE.read_text(encoding="utf-8")
        )
        cls.curation_sha256 = hashlib.sha256(PARITY.CURATION_MANIFEST.read_bytes()).hexdigest()

    def parse(self, text: str):
        return PARITY.parse_review(
            text,
            expected_root=self.root,
            expected_count=self.count,
            expected_curation_sha256=self.curation_sha256,
        )

    def validate(self, text: str):
        return self.validate_bytes(text.encode("utf-8"))

    def validate_bytes(self, receipt_bytes: bytes):
        return PARITY.validate_generated_review(
            receipt_bytes,
            expected_root=self.root,
            expected_count=self.count,
            expected_curation_sha256=self.curation_sha256,
        )

    def interior_truncation_accepted_by_structural_parser(self) -> str:
        """Model the reviewed attack: remove entry 0000's final format."""

        lines = self.review.splitlines()
        entry_start = next(
            index for index, line in enumerate(lines) if line.startswith("[0000] ")
        )
        next_entry = next(
            index for index, line in enumerate(lines) if line.startswith("[0001] ")
        )
        final_format = max(
            index
            for index in range(entry_start + 1, next_entry)
            if "· format " in lines[index]
        )
        lines[entry_start] = lines[entry_start].replace(" fields=10 ", " fields=6 ", 1)
        truncated = "\n".join([*lines[:final_format], *lines[next_entry:]]) + "\n"

        # This is deliberately structurally valid. The exact generator
        # round-trip, rather than duplicating dbgen semantics here, binds the
        # omitted bytes to the generated catalogue.
        self.assertEqual(len(self.parse(truncated)), self.count)
        return truncated

    def test_full_checked_in_receipt_is_bound_and_complete(self) -> None:
        entries = self.parse(self.review)
        self.assertEqual(len(entries), self.count)
        self.assertEqual([entry.index for entry in entries], list(range(self.count)))

    def test_truncated_prefix_with_forged_skips_marker_is_rejected(self) -> None:
        lines = self.review.splitlines()
        cutoff = next(index for index, line in enumerate(lines) if line.startswith("[0108] "))
        forged = "\n".join([*lines[:cutoff], "", "## skips (0 total)", ""])
        with self.assertRaisesRegex(ValueError, "expected production count"):
            self.parse(forged)

    def test_wrong_root_is_rejected(self) -> None:
        wrong = self.review.replace(
            f"# Root: {self.root}", f"# Root: 0x{'00' * 32}", 1
        )
        with self.assertRaisesRegex(ValueError, "Root: header does not match"):
            self.parse(wrong)

    def test_nonsequential_entry_index_is_rejected(self) -> None:
        wrong = self.review.replace("[0001] ctx=", "[0002] ctx=", 1)
        with self.assertRaisesRegex(ValueError, "entry index 0002, expected 0001"):
            self.parse(wrong)

    def test_exact_generator_roundtrip_command_is_load_bearing(self) -> None:
        with mock.patch.object(PARITY.subprocess, "run") as run:
            PARITY.run_exact_descriptor_roundtrip()

        run.assert_called_once_with(
            [
                "cargo",
                "run",
                "--locked",
                "-q",
                "-p",
                "pqsigner-xtask",
                "--features",
                "nested-calldata-test-fixture",
                "--",
                "gen-erc7730-descriptors",
                "--check",
            ],
            cwd=PARITY.ROOT,
            check=True,
        )

    def test_interior_truncation_differs_from_freshly_checked_receipt(self) -> None:
        truncated = self.interior_truncation_accepted_by_structural_parser()

        with mock.patch.object(PARITY, "run_exact_descriptor_roundtrip") as roundtrip:
            with self.assertRaisesRegex(
                ValueError, "receipt changed or differs during exact generator round-trip"
            ):
                self.validate(truncated)

        roundtrip.assert_called_once_with()

    def test_crlf_lf_swap_is_not_byte_identical(self) -> None:
        crlf_receipt = self.review.replace("\n", "\r\n").encode("utf-8")
        self.assertNotEqual(crlf_receipt, self.review_bytes)

        with tempfile.TemporaryDirectory() as directory:
            review_path = Path(directory) / "erc7730.review.txt"
            review_path.write_bytes(crlf_receipt)
            with mock.patch.object(PARITY, "REVIEW", review_path):
                with mock.patch.object(
                    PARITY, "run_exact_descriptor_roundtrip"
                ) as roundtrip:
                    with self.assertRaisesRegex(
                        ValueError,
                        "receipt changed or differs during exact generator round-trip",
                    ):
                        self.validate_bytes(self.review_bytes)

        roundtrip.assert_called_once_with()

    def test_malformed_utf8_is_rejected_before_roundtrip(self) -> None:
        malformed = self.review_bytes.replace(b"# Root", b"# R\xffot", 1)
        self.assertNotEqual(malformed, self.review_bytes)

        with mock.patch.object(PARITY, "run_exact_descriptor_roundtrip") as roundtrip:
            with self.assertRaisesRegex(ValueError, "review receipt is not UTF-8"):
                self.validate_bytes(malformed)

        roundtrip.assert_not_called()

    def test_terminal_metadata_parser_rejects_inconsistent_values(self) -> None:
        mutations = (
            "visibility=unknown,terminalKind=unsigned(0x01),integerWidthBytes=32",
            "visibility=always,terminalKind=unsigned(0x03),integerWidthBytes=32",
            "visibility=always,terminalKind=unsigned(0x01),integerWidthBytes=0",
        )
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(ValueError):
                PARITY.parse_review_field_parameters(value)


class OfficialSemanticParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        review = PARITY.REVIEW.read_text(encoding="utf-8")
        root, count = PARITY.parse_production_descriptor_receipt(
            PARITY.ROOTS_SOURCE.read_text(encoding="utf-8")
        )
        curation_sha256 = hashlib.sha256(PARITY.CURATION_MANIFEST.read_bytes()).hexdigest()
        cls.entries = PARITY.parse_review(
            review,
            expected_root=root,
            expected_count=count,
            expected_curation_sha256=curation_sha256,
        )
        cls.sources = {}
        cls.resolved = {}
        for relative in PARITY.DESCRIPTORS:
            path = PARITY.REGISTRY / relative
            cls.sources[relative] = json.loads(path.read_text(encoding="utf-8"))
            cls.resolved[relative] = PARITY.resolve_official(path)

    def compare(self, relative: str, entries):
        return PARITY.compare_resolved_descriptor(
            relative,
            self.sources[relative],
            self.resolved[relative],
            entries,
        )

    def mutate_field_param(
        self,
        relative: str,
        selector: str,
        field_index: int,
        parameter: str,
        value,
    ):
        entries = copy.deepcopy(self.entries)
        basename = Path(relative).name
        entry = next(candidate for candidate in entries if candidate.source == basename)
        field = entry.formats[selector].fields[field_index]
        entry.formats[selector].fields[field_index] = replace(
            field, params=replace(field.params, **{parameter: value})
        )
        return entries

    def test_selected_lido_semantics_match_completely(self) -> None:
        totals = [self.compare(relative, self.entries) for relative in PARITY.DESCRIPTORS]
        self.assertEqual(totals, [(3, 6), (8, 20)])

    def test_each_official_semantic_parameter_mutation_is_rejected(self) -> None:
        steth = "registry/lido/calldata-stETH.json"
        wsteth = "registry/lido/calldata-wstETH.json"
        cases = [
            ("token", steth, "0x095ea7b3", 1, "token", "0x" + "00" * 20),
            ("threshold", steth, "0x095ea7b3", 1, "threshold", "0x" + "00" * 32),
            ("message", steth, "0x095ea7b3", 1, "message", "Mutated"),
            ("address types", steth, "0x095ea7b3", 0, "address_types", 0x03),
            ("address sources", steth, "0x095ea7b3", 0, "address_sources", 0x03),
            ("date encoding", wsteth, "0xd505accf", 3, "date_encoding", 1),
            ("visibility", steth, "0x095ea7b3", 0, "visibility", "optional"),
            ("terminal kind", steth, "0x095ea7b3", 0, "terminal_kind", "unsigned"),
            ("integer width", wsteth, "0xd505accf", 4, "integer_width_bytes", 2),
            (
                "supported interpolation",
                wsteth,
                "0xea598cb0",
                0,
                "interpolated_intent",
                PARITY.InterpolatedIntent(1, ("Wrap exactly ", ""), (0,)),
            ),
            (
                "fallback interpolation",
                steth,
                "0xa9059cbb",
                0,
                "interpolated_intent",
                PARITY.InterpolatedIntent(1, ("Send ", ""), (1,)),
            ),
        ]
        for name, relative, selector, index, parameter, value in cases:
            with self.subTest(name=name):
                mutated = self.mutate_field_param(
                    relative, selector, index, parameter, value
                )
                with self.assertRaisesRegex(ValueError, "field mismatch"):
                    self.compare(relative, mutated)


if __name__ == "__main__":
    unittest.main()
