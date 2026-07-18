#!/usr/bin/env python3
"""Offline unit tests for the fast Kani census manifest checks."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kani_census


class ManifestRotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "crate/src/lib.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(
            "#[kani::proof]\nfn binds_value() {\n    let guarded = true;\n}\n",
            encoding="utf-8",
        )
        self.census = {
            "_file_harnesses": {"crate/src/lib.rs": ["binds_value"]},
        }
        self.entry = {
            "id": "guard",
            "file": "crate/src/lib.rs",
            "harness": "binds_value",
            "find": "let guarded = true;",
            "replace": "let guarded = false;",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def failures(self, entry: dict) -> list[str]:
        return kani_census.manifest_rot(
            self.census,
            manifest={"mutations": [entry]},
            repo_root=self.root,
        )

    def test_accepts_one_material_mutation_bound_to_existing_harness(self) -> None:
        self.assertEqual(self.failures(self.entry), [])

    def test_rejects_missing_file_or_harness(self) -> None:
        missing_file = dict(self.entry, file="crate/src/missing.rs")
        missing_harness = dict(self.entry, harness="renamed")
        self.assertIn("does not exist", self.failures(missing_file)[0])
        self.assertIn("no `#[kani::proof] fn renamed`", self.failures(missing_harness)[0])

    def test_rejects_empty_absent_or_ambiguous_find_string(self) -> None:
        self.assertIn("missing or empty", self.failures(dict(self.entry, find=""))[0])
        self.assertIn("occurs 0x", self.failures(dict(self.entry, find="not present"))[0])

        self.source.write_text(
            "#[kani::proof]\nfn binds_value() {\n"
            "    let guarded = true;\n    let guarded = true;\n}\n",
            encoding="utf-8",
        )
        self.assertIn("occurs 2x", self.failures(self.entry)[0])

    def test_rejects_noop_or_non_string_replacement(self) -> None:
        noop = dict(self.entry, replace=self.entry["find"])
        non_string = dict(self.entry, replace=None)
        self.assertIn("replace == find", self.failures(noop)[0])
        self.assertIn("replacement must be a string", self.failures(non_string)[0])

    def test_harness_census_ignores_commented_proof_attribute(self) -> None:
        text = """\
// Kani `#[kani::proof]` harnesses do not execute under cargo test.
fn ordinary_test() {}
"""
        self.assertEqual(kani_census.harnesses_in(text), [])

    def test_harness_census_binds_normal_standalone_attribute(self) -> None:
        text = """\
    #[kani::proof]
    #[kani::unwind(8)]
    // The function may be separated from the proof attribute.

    fn panic_free() {}
"""
        self.assertEqual(kani_census.harnesses_in(text), ["panic_free"])


if __name__ == "__main__":
    unittest.main()
