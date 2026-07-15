#!/usr/bin/env python3
"""Pure-stdlib regression tests for discovery-only swarm aggregation."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace


KIT_DIR = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("run_review", KIT_DIR / "run_review.py")
assert SPEC is not None and SPEC.loader is not None
RUN_REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN_REVIEW)

CANNED_PROMPT_COMMAND = (
    "sh -c 'cat \"$1\" >/dev/null && cat tests/canned_findings.json' "
    "sh {prompt_file}"
)
NORMAL_PROMPT_COMMAND = (
    "sh -c 'cat \"$1\" >/dev/null && "
    "sed s/canned-example-finding/normal-example-finding/ "
    "tests/canned_findings.json' sh {prompt_file}"
)


def finding(identifier: str, title: str, confidence: float, target: str = "x/Foo.lean:L1") -> dict:
    return {
        "id": identifier,
        "v_class": "V1",
        "severity": "medium",
        "target": target,
        "title": title,
        "claim": "claim",
        "defect": "defect",
        "poc": "poc",
        "confidence": confidence,
        "suggested_fix": "fix",
    }


def single_output(base: str | Path, name: str) -> Path:
    matches = list(Path(base).rglob(name))
    if len(matches) != 1:
        raise AssertionError(f"expected one {name}, found {matches}")
    return matches[0]


def receipt(namespace: str, marker: str) -> dict:
    invocation = hashlib.sha256(namespace.encode("utf-8")).hexdigest()
    return RUN_REVIEW.raw_payload(
        {
            "angle-a": RUN_REVIEW.annotate_reviews(
                "angle-a",
                [
                    {
                        "findings": [finding(marker, f"Candidate {marker}", 0.7)],
                        "honest_residual": f"residual {marker}",
                    }
                ],
                namespace,
            )
        },
        {
            "angle-a": [
                {
                    "reviewer_index": 0,
                    "returncode": 0,
                    "parse_status": "validated",
                    "parse_error": None,
                    "stdout": f"stdout {marker}",
                    "stderr": f"stderr {marker}",
                }
            ]
        },
        {
            "namespace": namespace,
            "run_id": marker,
            "backend": "generic",
            "invocation_sha256": invocation,
            "settings": {"self_test": False},
        },
    )


def write_completed_receipt(base: Path, directory: str, payload: dict) -> Path:
    run_dir = base / directory
    run_dir.mkdir()
    raw_bytes = RUN_REVIEW._json_bytes(payload)
    raw_path = run_dir / "raw.json"
    raw_path.write_bytes(raw_bytes)
    run = payload["_meta"]["run"]
    outcome = {
        "status": "succeeded",
        "failure_codes": [],
        "failed_passes": 0,
        "finding_count": 1,
    }
    completion = RUN_REVIEW.completion_payload(
        run,
        RUN_REVIEW.DISCOVERY_PURPOSE,
        outcome,
        {"raw.json": raw_bytes},
    )
    (run_dir / "completion.json").write_bytes(RUN_REVIEW._json_bytes(completion))
    return raw_path


def run_payload_review(payload: bytes, base: Path) -> tuple[subprocess.CompletedProcess, Path]:
    response = base / "response.json"
    response.write_bytes(payload)
    out = base / "out"
    command = (
        "python3 -c 'import pathlib,sys; "
        "pathlib.Path(sys.argv[1]).read_bytes(); "
        "sys.stdout.buffer.write(pathlib.Path(sys.argv[2]).read_bytes())' "
        f"{{prompt_file}} {shlex.quote(str(response))}"
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(KIT_DIR / "run_review.py"),
            "--backend",
            "generic",
            "--cmd",
            command,
            "--angle",
            "lean-vacuity",
            "--reviewers",
            "1",
            "--quorum",
            "1",
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed, out


class DiscoveryAggregationTests(unittest.TestCase):
    def test_extract_json_accepts_brace_inside_string_only_when_unwrapped(self) -> None:
        answer = {
            "findings": [
                finding("brace", "Brace in PoC", 0.7)
                | {"poc": "replace the unmatched { token"}
            ],
            "honest_residual": "residual",
        }
        encoded = json.dumps(answer)
        self.assertEqual(json.loads(encoded), answer)
        self.assertEqual(RUN_REVIEW.extract_json(f" \r\n{encoded}\t"), answer)
        parsed, error = RUN_REVIEW.extract_json_diagnostic(
            f"runtime log with {{ noise\n{encoded}\nfinished"
        )
        self.assertIsNone(parsed)
        self.assertIn("not exactly one JSON value", error)

    def test_extract_json_rejects_nested_findings_object(self) -> None:
        answer = {
            "findings": [finding("nested", "Nested candidate", 0.7)],
            "honest_residual": "nested residual",
        }
        for wrapped in ({"result": answer}, [answer]):
            parsed, error = RUN_REVIEW.extract_json_diagnostic(json.dumps(wrapped))
            self.assertIsNone(parsed)
            self.assertIsNotNone(error)

    def test_extract_json_rejects_valid_then_malformed_answer(self) -> None:
        valid = {
            "findings": [finding("valid-answer", "Valid candidate", 0.7)],
            "honest_residual": "residual",
        }
        malformed_later = {"findings": [{"id": "missing-fields"}]}
        noisy = f"first:\n{json.dumps(valid)}\nlater:\n{json.dumps(malformed_later)}"
        parsed, error = RUN_REVIEW.extract_json_diagnostic(noisy)
        self.assertIsNone(parsed)
        self.assertIn("not exactly one JSON value", error)

        for incomplete in ('{"findings":', '{"wrapper":'):
            parsed, error = RUN_REVIEW.extract_json_diagnostic(
                f"{json.dumps(valid)}\n{incomplete}"
            )
            self.assertIsNone(parsed)
            self.assertIn("not exactly one JSON value", error)

    def test_extract_json_rejects_malformed_wrapper_and_duplicate_keys(self) -> None:
        answer = {
            "findings": [finding("answer", "Candidate", 0.7)],
            "honest_residual": "residual",
        }
        malformed_wrapper = f'{{"wrapper": {json.dumps(answer)}'
        parsed, error = RUN_REVIEW.extract_json_diagnostic(malformed_wrapper)
        self.assertIsNone(parsed)
        self.assertIn("not exactly one JSON value", error)

        duplicate = (
            '{"findings":[],"findings":'
            + json.dumps(answer["findings"])
            + ',"honest_residual":"residual"}'
        )
        parsed, error = RUN_REVIEW.extract_json_diagnostic(duplicate)
        self.assertIsNone(parsed)
        self.assertIsNotNone(error)

        parsed, error = RUN_REVIEW.extract_json_diagnostic(
            "[" + json.dumps(answer)
        )
        self.assertIsNone(parsed)
        self.assertIn("not exactly one JSON value", error)

    def test_extract_json_rejects_additional_top_level_json_log(self) -> None:
        answer = {
            "findings": [finding("answer", "Candidate", 0.7)],
            "honest_residual": "residual",
        }
        parsed, error = RUN_REVIEW.extract_json_diagnostic(
            json.dumps({"runtime": "started"}) + "\n" + json.dumps(answer)
        )
        self.assertIsNone(parsed)
        self.assertIn("not exactly one JSON value", error)

    def test_extract_json_rejects_multiple_valid_answers(self) -> None:
        first = {
            "findings": [finding("first", "First candidate", 0.7)],
            "honest_residual": "first residual",
        }
        second = {
            "findings": [finding("second", "Second candidate", 0.8)],
            "honest_residual": "second residual",
        }
        parsed, error = RUN_REVIEW.extract_json_diagnostic(
            f"{json.dumps(first)}\n{json.dumps(second)}"
        )
        self.assertIsNone(parsed)
        self.assertIn("not exactly one JSON value", error)

    def test_extract_json_rejects_all_non_whitespace_wrappers_and_trailers(self) -> None:
        answer = {
            "findings": [finding("strict", "Strict candidate", 0.7)],
            "honest_residual": "residual",
        }
        encoded = json.dumps(answer)
        variants = (
            f"log\n{encoded}",
            f"{encoded}\nlog",
            f"```json\n{encoded}\n```",
            f"{{\"wrapper\":{encoded}}}",
            f"[{encoded}]",
            f"{encoded}\n{{\"findings\":",
            f"{encoded}\n42",
        )
        for candidate in variants:
            with self.subTest(candidate=candidate[:24]):
                parsed, error = RUN_REVIEW.extract_json_diagnostic(candidate)
                self.assertIsNone(parsed)
                self.assertIsNotNone(error)

    def test_extract_json_rejects_missing_or_malformed_schema(self) -> None:
        missing_residual = {"findings": [finding("a", "Candidate", 0.7)]}
        null_findings = {"findings": None, "honest_residual": "residual"}
        malformed_finding = {
            "findings": [{"id": "only-an-id"}],
            "honest_residual": "residual",
        }
        for answer in (missing_residual, null_findings, malformed_finding):
            parsed, error = RUN_REVIEW.extract_json_diagnostic(json.dumps(answer))
            self.assertIsNone(parsed)
            self.assertIn("schema validation failed", error)

    def test_schema_rejects_unknown_authority_fields(self) -> None:
        unknown_finding = finding("unknown", "Candidate", 0.7) | {
            "disposition": "CONFIRMED",
            "status": "approved",
        }
        answers = (
            {
                "findings": [unknown_finding],
                "honest_residual": "residual",
            },
            {
                "findings": [finding("known", "Candidate", 0.7)],
                "honest_residual": "residual",
                "stage_verdict": "GO",
            },
        )
        for answer in answers:
            parsed, error = RUN_REVIEW.extract_json_diagnostic(json.dumps(answer))
            self.assertIsNone(parsed)
            self.assertIn("unknown field", error)

    def test_schema_rejects_invalid_classes_duplicate_ids_and_missing_poc(self) -> None:
        bad_class = finding("bad-class", "Candidate", 0.7) | {"v_class": "G9"}
        duplicate = [
            finding("duplicate", "Candidate one", 0.7),
            finding("duplicate", "Candidate two", 0.8),
        ]
        no_poc = finding("no-poc", "Candidate", 0.7) | {
            "severity": "critical",
            "poc": "NONE",
        }
        bad_slug = finding("Not A Slug", "Candidate", 0.7)
        for findings in ([bad_class], duplicate, [no_poc], [bad_slug]):
            answer = {"findings": findings, "honest_residual": "residual"}
            parsed, error = RUN_REVIEW.extract_json_diagnostic(json.dumps(answer))
            self.assertIsNone(parsed)
            self.assertIn("schema validation failed", error)

        for index, placeholder in enumerate(
            ("NONE.", " none:", "NoNe—unverified", "NONE (not reproduced)")
        ):
            answer = {
                "findings": [
                    finding(f"placeholder-{index}", "Candidate", 0.7)
                    | {"severity": "medium", "poc": placeholder}
                ],
                "honest_residual": "residual",
            }
            parsed, error = RUN_REVIEW.extract_json_diagnostic(json.dumps(answer))
            self.assertIsNone(parsed)
            self.assertIn("poc is NONE", error)

    def test_schema_rejects_lone_surrogates_but_accepts_unicode_scalars(self) -> None:
        invalid_payloads = (
            r'{"findings":[],"honest_residual":"\ud800"}',
            r'{"findings":[],"honest_residual":"ok","\udc00":0}',
        )
        for payload in invalid_payloads:
            parsed, error = RUN_REVIEW.extract_json_diagnostic(payload)
            self.assertIsNone(parsed)
            self.assertIn("non-Unicode-scalar", error)

        valid = {"findings": [], "honest_residual": "emoji 😀"}
        parsed, error = RUN_REVIEW.extract_json_diagnostic(
            json.dumps(valid, ensure_ascii=True)
        )
        self.assertEqual(parsed, valid)
        self.assertIsNone(error)

    def test_origin_ids_are_deterministic_unique_and_raw_answers_are_not_mutated(self) -> None:
        original = {
            "findings": [
                finding("same-id", "Same title", 0.5),
                finding("same-id", "Same title", 0.5),
            ],
            "honest_residual": "residual",
        }
        first = RUN_REVIEW.annotate_reviews("angle-a", [original])
        second = RUN_REVIEW.annotate_reviews("angle-a", [original])

        first_ids = [item["_origin_id"] for item in first[0]["findings"]]
        second_ids = [item["_origin_id"] for item in second[0]["findings"]]
        self.assertEqual(first_ids, second_ids)
        self.assertEqual(len(first_ids), len(set(first_ids)))
        self.assertNotIn("_origin_id", original["findings"][0])
        self.assertEqual(first[0]["_reviewer_index"], 0)
        grouped = RUN_REVIEW.aggregate(first, quorum=2)
        self.assertEqual(grouped["corroborated"], [])
        self.assertEqual(len(grouped["sub_quorum"]), 1)
        self.assertEqual(grouped["sub_quorum"][0]["_votes"], 1)
        self.assertEqual(len(grouped["sub_quorum"][0]["_variants"]), 2)

    def test_quorum_only_partitions_and_retains_every_variant(self) -> None:
        answers = [
            {
                "findings": [finding("a", "Shared title details", 0.6)],
                "honest_residual": "r0",
            },
            {
                "findings": [finding("b", "Shared title details", 0.9)],
                "honest_residual": "r1",
            },
            {
                "findings": [
                    finding("c", "Solo candidate", 0.8, "y/Bar.lean:L2")
                ],
                "honest_residual": "r2",
            },
        ]
        result = RUN_REVIEW.aggregate(
            RUN_REVIEW.annotate_reviews("lean-vacuity", answers), quorum=2
        )

        self.assertEqual(set(result), {"corroborated", "sub_quorum", "residuals"})
        self.assertEqual(len(result["corroborated"]), 1)
        self.assertEqual(len(result["sub_quorum"]), 1)
        group = result["corroborated"][0]
        self.assertEqual(group["_votes"], 2)
        self.assertEqual(len(group["_variants"]), 2)
        self.assertEqual(len(group["_origin_ids"]), 2)
        self.assertEqual(
            group["_origin_ids"],
            [variant["_origin_id"] for variant in group["_variants"]],
        )

    def test_group_representative_preserves_highest_severity(self) -> None:
        critical = finding("critical-variant", "Shared candidate", 0.5) | {
            "severity": "critical"
        }
        low = finding("low-variant", "Shared candidate", 0.9) | {
            "severity": "low"
        }
        answers = [
            {"findings": [critical], "honest_residual": "r0"},
            {"findings": [low], "honest_residual": "r1"},
        ]
        result = RUN_REVIEW.aggregate(
            RUN_REVIEW.annotate_reviews("angle-a", answers), quorum=2
        )
        self.assertEqual(result["corroborated"][0]["severity"], "critical")
        self.assertEqual(len(result["corroborated"][0]["_variants"]), 2)

    def test_raw_receipt_and_report_reserve_disposition_to_exact_pair(self) -> None:
        annotated = RUN_REVIEW.annotate_reviews(
            "angle-a",
            [{"findings": [finding("a", "Candidate", 0.7)], "honest_residual": "r"}],
        )
        payload = RUN_REVIEW.raw_payload({"angle-a": annotated})
        serialized = json.dumps(payload)
        self.assertEqual(payload["_meta"]["purpose"], "discovery_only")
        self.assertIn("exact dual-review partners", payload["_meta"]["authority"])
        self.assertIn("_origin_id", serialized)

        result = RUN_REVIEW.aggregate(annotated, quorum=1)
        report = RUN_REVIEW.render_report(
            {"name": "test", "version": 2}, {"angle-a": result}, 1, 1
        )
        self.assertIn("Discovery-only output", report)
        self.assertIn("exact Partner-A/Partner-B protocol", report)
        self.assertIn("corroborated discovery candidate", report)
        self.assertNotIn("### confirmed findings", report)

    def test_raw_receipt_preserves_pass_diagnostics(self) -> None:
        stdout = RUN_REVIEW.stream_receipt(b"partial\r\n")
        stderr = RUN_REVIEW.stream_receipt(b"backend failed")
        diagnostics = {
            "angle-a": [
                {
                    "reviewer_index": 0,
                    "returncode": 7,
                    "parse_status": "rejected",
                    "parse_error": "bad schema",
                    "timed_out": False,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            ]
        }
        receipt = {"backend": "generic", "run_id": "receipt-test"}
        payload = RUN_REVIEW.raw_payload({"angle-a": [None]}, diagnostics, receipt)
        self.assertEqual(payload["_meta"]["run"], receipt)
        self.assertEqual(payload["diagnostics"], diagnostics)
        self.assertEqual(payload["_meta"]["format_version"], 4)
        self.assertEqual(stdout["length"], 9)
        self.assertEqual(
            RUN_REVIEW.base64.b64decode(stdout["base64"]), b"partial\r\n"
        )

    def test_stream_receipt_preserves_invalid_utf8_and_crlf_exactly(self) -> None:
        data = b"before\r\n\xffafter"
        receipt = RUN_REVIEW.stream_receipt(data)
        self.assertEqual(receipt["length"], len(data))
        self.assertEqual(receipt["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(RUN_REVIEW.base64.b64decode(receipt["base64"]), data)
        self.assertFalse(receipt["utf8"]["valid"])
        decoded, error = RUN_REVIEW._decode_utf8(data)
        self.assertIsNone(decoded)
        self.assertIn("strict UTF-8", error)

    def test_run_backend_preserves_timeout_partial_bytes(self) -> None:
        command = (
            "exec python3 -c 'import sys,time; "
            'sys.stdout.buffer.write(b"partial\\r\\n"); '
            "sys.stdout.buffer.flush(); time.sleep(5)'"
        )
        stdout, stderr, returncode, timed_out = RUN_REVIEW.run_backend(
            command, "prompt", 1
        )
        self.assertEqual(stdout, b"partial\r\n")
        self.assertEqual(stderr, b"")
        self.assertEqual(returncode, 124)
        self.assertTrue(timed_out)

    def test_run_backend_shell_quotes_prompt_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            unusual = Path(directory) / "prompt dir ' ; false"
            unusual.mkdir()
            prior_tempdir = RUN_REVIEW.tempfile.tempdir
            RUN_REVIEW.tempfile.tempdir = str(unusual)
            try:
                stdout, stderr, returncode, timed_out = RUN_REVIEW.run_backend(
                    "cat {prompt_file}", "quoted prompt", 5
                )
            finally:
                RUN_REVIEW.tempfile.tempdir = prior_tempdir
        self.assertEqual(stdout, b"quoted prompt")
        self.assertEqual(stderr, b"")
        self.assertEqual(returncode, 0)
        self.assertFalse(timed_out)

    def test_run_backend_timeout_kills_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            marker = base / "late-marker"
            backend = base / "backend.py"
            child_code = (
                "import pathlib,signal,time;"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                "print('child-ready', flush=True);"
                "time.sleep(2);"
                f"pathlib.Path({str(marker)!r}).write_text('escaped');"
                "time.sleep(10)"
            )
            backend.write_text(
                "import subprocess,sys,time\n"
                f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
                "print(f'child-pid={child.pid}', flush=True)\n"
                "time.sleep(10)\n",
                encoding="utf-8",
            )
            command = (
                f"{shlex.quote(sys.executable)} {shlex.quote(str(backend))} "
                "{prompt_file}"
            )
            started = time.monotonic()
            stdout, _stderr, returncode, timed_out = RUN_REVIEW.run_backend(
                command, "prompt", 1
            )
            elapsed = time.monotonic() - started
            time.sleep(2.2)
            marker_created = marker.exists()

        self.assertTrue(timed_out)
        self.assertEqual(returncode, 124)
        self.assertIn(b"child-pid=", stdout)
        self.assertIn(b"child-ready", stdout)
        self.assertLess(elapsed, 3.0)
        self.assertFalse(marker_created)

    def test_raw_union_is_deterministic_lossless_and_never_revotes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            payload_a = receipt("claude/round-a-111", "a")
            payload_b = receipt("codex/round-b-222", "b")
            path_a = write_completed_receipt(base, "a", payload_a)
            path_b = write_completed_receipt(base, "b", payload_b)

            union_ab, digest_ab = RUN_REVIEW.build_raw_union([path_a, path_b])
            union_ba, digest_ba = RUN_REVIEW.build_raw_union([path_b, path_a])

        self.assertEqual(union_ab, union_ba)
        self.assertEqual(digest_ab, digest_ba)
        self.assertEqual(
            [entry["payload"] for entry in union_ab["runs"]],
            [payload_a, payload_b],
        )
        serialized = json.dumps(union_ab)
        self.assertIn("stdout a", serialized)
        self.assertIn("stderr b", serialized)
        self.assertNotIn("corroborated", union_ab["_meta"])
        self.assertIn("no cross-run voting", union_ab["_meta"]["authority"])

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first = write_completed_receipt(base, "first", payload_a)
            second = write_completed_receipt(base, "second", payload_a)
            with self.assertRaisesRegex(ValueError, "duplicate run namespace"):
                RUN_REVIEW.build_raw_union([first, second])

    def test_raw_union_rejects_duplicate_json_keys(self) -> None:
        raw = (
            '{"_meta":{"format_version":2,"purpose":"discovery_only",'
            '"run":{"namespace":"generic/r"}},'
            '"angles":{"lost":{"marker":"FIRST"}},'
            '"angles":{"kept":[]},"diagnostics":{}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.json"
            path.write_text(raw, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                RUN_REVIEW.build_raw_union([path])

    def test_raw_union_rejects_self_test_receipts(self) -> None:
        payload = RUN_REVIEW.raw_payload(
            {"angle-a": []},
            {},
            {"namespace": "generic/self-test"},
            purpose=RUN_REVIEW.SELF_TEST_PURPOSE,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "discovery-only"):
                RUN_REVIEW.build_raw_union([path])

    def test_raw_union_rejects_legacy_receipts_and_completion_mismatch(self) -> None:
        payload = receipt("generic/current", "current")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            legacy = json.loads(json.dumps(payload))
            legacy["_meta"]["format_version"] = 3
            legacy_path = write_completed_receipt(base, "legacy", legacy)
            with self.assertRaisesRegex(ValueError, "supported discovery-only"):
                RUN_REVIEW.build_raw_union([legacy_path])

            current_path = write_completed_receipt(base, "current", payload)
            completion_path = current_path.with_name("completion.json")
            completion = json.loads(completion_path.read_text(encoding="utf-8"))
            completion["artifacts"]["raw.json"]["sha256"] = "0" * 64
            completion_path.write_text(json.dumps(completion), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "binding mismatch"):
                RUN_REVIEW.build_raw_union([current_path])

    def test_raw_union_rejects_reserved_fixture_even_if_labeled_discovery(self) -> None:
        payload = receipt("generic/canned", "ordinary")
        payload["angles"]["angle-a"][0]["findings"][0]["id"] = (
            RUN_REVIEW.RESERVED_SELF_TEST_FINDING_ID
        )
        with tempfile.TemporaryDirectory() as directory:
            path = write_completed_receipt(Path(directory), "canned", payload)
            with self.assertRaisesRegex(ValueError, "reserved self-test fixture"):
                RUN_REVIEW.build_raw_union([path])

    def test_raw_union_rejects_excessive_fixture_scan_nesting_cleanly(self) -> None:
        payload = receipt("generic/deep-union", "ordinary")
        nested: object = {}
        for _ in range(1_500):
            nested = {"angles": {"nested": [nested]}}
        payload["angles"] = {"angle-a": [nested]}

        with self.assertRaisesRegex(ValueError, "fixture-scan limit"):
            RUN_REVIEW._validate_raw_discovery_payload(payload)

    def test_run_namespace_is_deterministic_and_separates_backends_and_runs(self) -> None:
        proto = {"name": "test-protocol", "version": 2}
        common = ("cat {prompt_file}", proto, KIT_DIR, 2, 2, 1)
        claude_1 = RUN_REVIEW.make_run_receipt("claude", "round-1", *common)
        claude_1_again = RUN_REVIEW.make_run_receipt("claude", "round-1", *common)
        claude_2 = RUN_REVIEW.make_run_receipt("claude", "round-2", *common)
        codex_1 = RUN_REVIEW.make_run_receipt("codex", "round-1", *common)
        self.assertEqual(claude_1, claude_1_again)
        namespaces = {
            claude_1["namespace"],
            claude_2["namespace"],
            codex_1["namespace"],
        }
        self.assertEqual(len(namespaces), 3)

        answer = [{"findings": [finding("a", "Candidate", 0.7)], "honest_residual": "r"}]
        origin_ids = {
            RUN_REVIEW.annotate_reviews("angle-a", answer, receipt["namespace"])[0]
            ["findings"][0]["_origin_id"]
            for receipt in (claude_1, claude_2, codex_1)
        }
        self.assertEqual(len(origin_ids), 3)

        angle = {"id": "angle-a", "title": "A", "targets": ["x"]}
        bound_a = RUN_REVIEW.make_run_receipt(
            "generic",
            "bound",
            "cat {prompt_file}",
            proto,
            KIT_DIR,
            2,
            2,
            1,
            angles=[angle],
            prompts={"angle-a": "prompt-a"},
            max_file_bytes=100,
            timeout=30,
            target_initial={"snapshot_sha256": "a" * 64},
        )
        bound_b = RUN_REVIEW.make_run_receipt(
            "generic",
            "bound",
            "cat {prompt_file}",
            proto,
            KIT_DIR,
            2,
            2,
            1,
            angles=[angle],
            prompts={"angle-a": "prompt-a"},
            max_file_bytes=101,
            timeout=30,
            target_initial={"snapshot_sha256": "a" * 64},
        )
        bound_c = RUN_REVIEW.make_run_receipt(
            "generic",
            "bound",
            "cat {prompt_file}",
            proto,
            KIT_DIR,
            2,
            2,
            1,
            angles=[angle],
            prompts={"angle-a": "prompt-a"},
            max_file_bytes=100,
            timeout=30,
            target_initial={"snapshot_sha256": "b" * 64},
        )
        self.assertEqual(len({bound_a["namespace"], bound_b["namespace"], bound_c["namespace"]}), 3)
        self.assertEqual(bound_a["review_selectors"]["angle_ids"], ["angle-a"])
        self.assertEqual(bound_a["settings"]["max_file_bytes"], 100)
        self.assertFalse(bound_a["settings"]["self_test"])

    def test_angle_selection_is_exact_ordered_and_deduplicated(self) -> None:
        configured = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        selected = RUN_REVIEW.select_angles(configured, ["b", "a", "b"])
        self.assertEqual([angle["id"] for angle in selected], ["b", "a"])
        with self.assertRaisesRegex(ValueError, "unknown angle.*missing"):
            RUN_REVIEW.select_angles(configured, ["b", "missing", "a"])

    def test_run_outcome_classifies_drift_and_empty_self_test_before_publish(self) -> None:
        diagnostics = {"a": [{"parse_status": "validated"}]}
        empty_results = {
            "a": {"corroborated": [], "sub_quorum": [], "residuals": []}
        }
        drifted = RUN_REVIEW.classify_run(
            diagnostics,
            target_drift=True,
            self_test=False,
            results=empty_results,
        )
        self.assertEqual(drifted["status"], "failed")
        self.assertEqual(drifted["failure_codes"], ["target_drift"])

        empty_self_test = RUN_REVIEW.classify_run(
            diagnostics,
            target_drift=False,
            self_test=True,
            results=empty_results,
        )
        self.assertEqual(empty_self_test["status"], "failed")
        self.assertEqual(empty_self_test["failure_codes"], ["self_test_empty"])

    def test_cli_rejects_mixed_known_and_unknown_angles(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(KIT_DIR / "run_review.py"),
                "--dry-run",
                "--angle",
                "lean-vacuity",
                "--angle",
                "not-an-angle",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("unknown angle", completed.stderr)

    def test_review_snapshot_binds_target_content_head_tree_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("first", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "target.txt"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Runner Test",
                    "-c",
                    "user.email=runner@example.invalid",
                    "commit",
                    "-qm",
                    "initial",
                ],
                cwd=root,
                check=True,
            )
            angles = [{"id": "angle-a", "targets": ["target.txt"]}]
            prompts = {"angle-a": "prompt"}
            before = RUN_REVIEW.capture_review_snapshot(root, angles, prompts)
            target.write_text("second", encoding="utf-8")
            after = RUN_REVIEW.capture_review_snapshot(root, angles, prompts)

        self.assertEqual(before["head"], after["head"])
        self.assertEqual(before["head_tree"], after["head_tree"])
        self.assertNotEqual(before["target_manifest_sha256"], after["target_manifest_sha256"])
        self.assertNotEqual(before["git_status"]["sha256"], after["git_status"]["sha256"])
        self.assertNotEqual(before["snapshot_sha256"], after["snapshot_sha256"])

    def test_cli_numeric_bounds_fail_closed(self) -> None:
        valid = SimpleNamespace(
            reviewers=2,
            quorum=2,
            jobs=1,
            max_file_bytes=1,
            timeout=1,
            run_id="run",
        )
        self.assertIsNone(RUN_REVIEW.validate_cli_bounds(valid))
        invalid = (
            valid.__dict__ | {"reviewers": 0},
            valid.__dict__ | {"quorum": 0},
            valid.__dict__ | {"quorum": 3},
            valid.__dict__ | {"jobs": 0},
            valid.__dict__ | {"max_file_bytes": 0},
            valid.__dict__ | {"timeout": 0},
            valid.__dict__ | {"run_id": ""},
        )
        for values in invalid:
            self.assertIsNotNone(RUN_REVIEW.validate_cli_bounds(SimpleNamespace(**values)))

    def test_cli_rejects_zero_reviewers(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT_DIR / "run_review.py"),
                    "--backend",
                    "generic",
                    "--cmd",
                    CANNED_PROMPT_COMMAND,
                    "--angle",
                    "lean-vacuity",
                    "--reviewers",
                    "0",
                    "--out",
                    out,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("--reviewers must be >= 1", completed.stderr)

    def test_cli_requires_external_output(self) -> None:
        common = [
            sys.executable,
            str(KIT_DIR / "run_review.py"),
            "--backend",
            "generic",
            "--cmd",
            CANNED_PROMPT_COMMAND,
            "--angle",
            "lean-vacuity",
        ]
        missing = subprocess.run(
            common, capture_output=True, text=True, check=False
        )
        self.assertEqual(missing.returncode, 2)
        self.assertIn("--out is required", missing.stderr)

        in_repo = KIT_DIR / "out-test-must-not-exist"
        self.assertFalse(in_repo.exists())
        local = subprocess.run(
            common + ["--out", str(in_repo)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(local.returncode, 2)
        self.assertIn("outside the repository", local.stderr)
        self.assertFalse(in_repo.exists())

    def test_normal_cli_requires_prompt_file_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT_DIR / "run_review.py"),
                    "--backend",
                    "generic",
                    "--cmd",
                    "cat tests/canned_findings.json",
                    "--angle",
                    "lean-vacuity",
                    "--reviewers",
                    "1",
                    "--quorum",
                    "1",
                    "--out",
                    out,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(list(Path(out).iterdir()), [])
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must contain {prompt_file}", completed.stderr)

    def test_self_test_receipt_is_labeled_terminal_and_non_unionable(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT_DIR / "run_review.py"),
                    "--backend",
                    "generic",
                    "--cmd",
                    "cat tests/canned_findings.json",
                    "--self-test-ok",
                    "--angle",
                    "lean-vacuity",
                    "--reviewers",
                    "1",
                    "--quorum",
                    "1",
                    "--run-id",
                    "self-test",
                    "--out",
                    out,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            raw_path = single_output(out, "raw.json")
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            completion = json.loads(
                single_output(out, "completion.json").read_text(encoding="utf-8")
            )
            run_files = {path.name for path in raw_path.parent.iterdir()}
            with self.assertRaisesRegex(ValueError, "discovery-only"):
                RUN_REVIEW.build_raw_union([raw_path])
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(run_files, {"raw.json", "completion.json"})
        self.assertEqual(raw["_meta"]["purpose"], RUN_REVIEW.SELF_TEST_PURPOSE)
        self.assertTrue(raw["_meta"]["run"]["settings"]["self_test"])
        self.assertEqual(completion["review_purpose"], RUN_REVIEW.SELF_TEST_PURPOSE)
        self.assertEqual(completion["outcome"]["status"], "succeeded")
        self.assertEqual(set(completion["artifacts"]), {"raw.json"})

    def test_canned_fixture_cannot_publish_as_normal_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT_DIR / "run_review.py"),
                    "--backend",
                    "generic",
                    "--cmd",
                    CANNED_PROMPT_COMMAND,
                    "--angle",
                    "lean-vacuity",
                    "--reviewers",
                    "2",
                    "--quorum",
                    "2",
                    "--run-id",
                    "canned-misuse",
                    "--out",
                    out,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            raw_path = single_output(out, "raw.json")
            completion = json.loads(
                single_output(out, "completion.json").read_text(encoding="utf-8")
            )
            run_files = {path.name for path in raw_path.parent.iterdir()}
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(run_files, {"raw.json", "completion.json"})
        self.assertEqual(completion["outcome"]["status"], "failed")
        self.assertEqual(
            completion["outcome"]["failure_codes"], ["backend_pass_invalid"]
        )
        self.assertIn("reserved self-test fixture", completed.stderr)

    def test_namespaced_output_rejects_symlink_back_into_repo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_repo = base / "repo"
            output = base / "external"
            fake_repo.mkdir()
            output.mkdir()
            (output / "generic").symlink_to(fake_repo, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "not a real directory"):
                RUN_REVIEW.prepare_run_output_dir(
                    output, "generic/round-1", fake_repo
                )
            self.assertFalse((fake_repo / "round-1").exists())

    def test_artifact_writes_reject_preexisting_symlink_hardlink_and_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_repo = base / "repo"
            fake_repo.mkdir()
            output = RUN_REVIEW.prepare_run_output_dir(
                base / "external", "generic/race-test", fake_repo
            )
            outside = base / "outside"
            outside.write_bytes(b"outside")
            (output.path / "symlink.json").symlink_to(outside)
            (output.path / "hardlink.json").hardlink_to(outside)
            (output.path / "existing.json").write_bytes(b"existing")
            try:
                for name in ("symlink.json", "hardlink.json", "existing.json"):
                    with self.subTest(name=name):
                        with self.assertRaises(FileExistsError):
                            RUN_REVIEW.safe_write_bytes(output, name, b"replacement")
                self.assertEqual(outside.read_bytes(), b"outside")
            finally:
                output.close()

    def test_artifact_write_rejects_replaced_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_repo = base / "repo"
            fake_repo.mkdir()
            output = RUN_REVIEW.prepare_run_output_dir(
                base / "external", "generic/replaced", fake_repo
            )
            original = output.path.with_name("retained-original")
            output.path.rename(original)
            output.path.mkdir()
            try:
                with self.assertRaisesRegex(ValueError, "replaced"):
                    RUN_REVIEW.safe_write_bytes(output, "raw.json", b"evidence")
                self.assertFalse((original / "raw.json").exists())
                self.assertFalse((output.path / "raw.json").exists())
            finally:
                output.close()

    def test_namespaced_output_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            command = [
                sys.executable,
                str(KIT_DIR / "run_review.py"),
                "--backend",
                "generic",
                "--cmd",
                NORMAL_PROMPT_COMMAND,
                "--angle",
                "lean-vacuity",
                "--reviewers",
                "1",
                "--quorum",
                "1",
                "--run-id",
                "stable-run",
                "--out",
                out,
            ]
            first = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            raw_path = single_output(out, "raw.json")
            raw_receipt = json.loads(raw_path.read_text(encoding="utf-8"))
            before = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            second = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            after = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            completion = json.loads(
                single_output(raw_path.parent, "completion.json").read_text(
                    encoding="utf-8"
                )
            )
            artifact_bytes = {
                name: (raw_path.parent / name).read_bytes()
                for name in completion["artifacts"]
            }

        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 2)
        self.assertIn("cannot create run output directory", second.stderr)
        self.assertEqual(before, after)
        self.assertIn("generic", raw_path.parts)
        run = raw_receipt["_meta"]["run"]
        self.assertFalse(run["target_drift"])
        self.assertEqual(
            run["target_initial"]["snapshot_sha256"],
            run["target_final"]["snapshot_sha256"],
        )
        self.assertTrue(run["target_initial"]["target_manifest"])
        self.assertEqual(run["review_selectors"]["angle_ids"], ["lean-vacuity"])
        self.assertEqual(run["settings"]["reviewers"], 1)
        self.assertEqual(completion["outcome"]["status"], "succeeded")
        self.assertEqual(
            set(completion["artifacts"]),
            {"raw.json", "findings.json", "report.md"},
        )
        for name, artifact in completion["artifacts"].items():
            data = artifact_bytes[name]
            self.assertEqual(artifact["length"], len(data))
            self.assertEqual(artifact["sha256"], hashlib.sha256(data).hexdigest())

    def test_union_cli_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path_a = write_completed_receipt(
                base,
                "a",
                receipt("claude/round-a-111", "a"),
            )
            path_b = write_completed_receipt(
                base,
                "b",
                receipt("codex/round-b-222", "b"),
            )
            output = base / "union-output"
            command = [
                sys.executable,
                str(KIT_DIR / "run_review.py"),
                "--union-raw",
                str(path_a),
                str(path_b),
                "--out",
                str(output),
            ]
            first = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            union_path = single_output(output, "union-*.json")
            before = hashlib.sha256(union_path.read_bytes()).hexdigest()
            second = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            after = hashlib.sha256(union_path.read_bytes()).hexdigest()

        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 2)
        self.assertIn("cannot write raw union", second.stderr)
        self.assertEqual(before, after)

    def test_union_cli_rejects_deep_raw_and_completion_without_artifact(self) -> None:
        deep_json = (b"[" * 50_000) + (b"]" * 50_000)

        for corrupted_name in ("raw.json", "completion.json"):
            with self.subTest(corrupted_name=corrupted_name):
                with tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    if corrupted_name == "raw.json":
                        run_dir = base / "deep-raw"
                        run_dir.mkdir()
                        raw_path = run_dir / "raw.json"
                        raw_path.write_bytes(deep_json)
                    else:
                        raw_path = write_completed_receipt(
                            base,
                            "deep-completion",
                            receipt("generic/deep-completion", "ordinary"),
                        )
                        raw_path.with_name("completion.json").write_bytes(deep_json)

                    output = base / "union-output"
                    completed = subprocess.run(
                        [
                            sys.executable,
                            str(KIT_DIR / "run_review.py"),
                            "--union-raw",
                            str(raw_path),
                            "--out",
                            str(output),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                    self.assertEqual(completed.returncode, 2)
                    self.assertIn("nesting exceeds parser limit", completed.stderr)
                    self.assertNotIn("Traceback", completed.stderr)
                    self.assertFalse(
                        output.exists() and any(output.glob("union-*.json"))
                    )

    def test_nonzero_backend_cannot_vote_and_fails_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT_DIR / "run_review.py"),
                    "--backend",
                    "generic",
                    "--cmd",
                    (
                        "sh -c 'cat \"$1\" >/dev/null; "
                        "cat tests/canned_findings.json; exit 7' sh {prompt_file}"
                    ),
                    "--angle",
                    "lean-vacuity",
                    "--reviewers",
                    "2",
                    "--quorum",
                    "2",
                    "--out",
                    out,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            raw_path = single_output(out, "raw.json")
            raw = json.loads(raw_path.read_text())
            completion = json.loads(
                single_output(out, "completion.json").read_text()
            )
            run_files = {path.name for path in raw_path.parent.iterdir()}
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(run_files, {"raw.json", "completion.json"})
        self.assertEqual(completion["outcome"]["status"], "failed")
        self.assertIn("backend_pass_invalid", completion["outcome"]["failure_codes"])
        diagnostics = raw["diagnostics"]["lean-vacuity"]
        self.assertEqual([item["returncode"] for item in diagnostics], [7, 7])
        self.assertTrue(all(item["parse_status"] == "rejected" for item in diagnostics))

    def test_invalid_utf8_backend_is_rejected_but_raw_bytes_are_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as out:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT_DIR / "run_review.py"),
                    "--backend",
                    "generic",
                    "--cmd",
                    (
                        "python3 -c 'import pathlib,sys; "
                        "pathlib.Path(sys.argv[1]).read_bytes(); "
                        "sys.stdout.buffer.write(bytes([255]))' {prompt_file}"
                    ),
                    "--angle",
                    "lean-vacuity",
                    "--reviewers",
                    "1",
                    "--quorum",
                    "1",
                    "--out",
                    out,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            raw_path = single_output(out, "raw.json")
            raw = json.loads(raw_path.read_text())
            completion = json.loads(
                single_output(out, "completion.json").read_text()
            )
            run_files = {path.name for path in raw_path.parent.iterdir()}
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(run_files, {"raw.json", "completion.json"})
        self.assertEqual(completion["outcome"]["status"], "failed")
        diagnostic = raw["diagnostics"]["lean-vacuity"][0]
        self.assertEqual(diagnostic["parse_status"], "rejected")
        self.assertIn("strict UTF-8", diagnostic["parse_error"])
        self.assertFalse(diagnostic["stdout"]["utf8"]["valid"])
        self.assertEqual(
            RUN_REVIEW.base64.b64decode(diagnostic["stdout"]["base64"]), b"\xff"
        )

    def test_escaped_lone_surrogate_is_rejected_and_raw_bytes_are_receipted(self) -> None:
        payload = b'{"findings":[],"honest_residual":"\\ud800"}'
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            response = base / "response.json"
            response.write_bytes(payload)
            out = base / "out"
            command = (
                "python3 -c 'import pathlib,sys; "
                "pathlib.Path(sys.argv[1]).read_bytes(); "
                "sys.stdout.buffer.write(pathlib.Path(sys.argv[2]).read_bytes())' "
                f"{{prompt_file}} {shlex.quote(str(response))}"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(KIT_DIR / "run_review.py"),
                    "--backend",
                    "generic",
                    "--cmd",
                    command,
                    "--angle",
                    "lean-vacuity",
                    "--reviewers",
                    "1",
                    "--quorum",
                    "1",
                    "--out",
                    str(out),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            raw_path = single_output(out, "raw.json")
            raw = json.loads(raw_path.read_text())
            completion = json.loads(
                single_output(out, "completion.json").read_text()
            )
            run_files = {path.name for path in raw_path.parent.iterdir()}
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(run_files, {"raw.json", "completion.json"})
        self.assertEqual(completion["outcome"]["status"], "failed")
        diagnostic = raw["diagnostics"]["lean-vacuity"][0]
        self.assertIn("non-Unicode-scalar", diagnostic["parse_error"])
        self.assertEqual(
            RUN_REVIEW.base64.b64decode(diagnostic["stdout"]["base64"]), payload
        )

    def test_duplicate_surrogate_key_still_publishes_terminal_failure(self) -> None:
        payload = (
            b'{"findings":[],"honest_residual":"x",'
            b'"\\ud800":1,"\\ud800":2}'
        )
        with tempfile.TemporaryDirectory() as directory:
            completed, out = run_payload_review(payload, Path(directory))
            raw_path = single_output(out, "raw.json")
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            completion = json.loads(
                single_output(out, "completion.json").read_text(encoding="utf-8")
            )
            run_files = {path.name for path in raw_path.parent.iterdir()}
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(run_files, {"raw.json", "completion.json"})
        self.assertEqual(completion["outcome"]["status"], "failed")
        diagnostic = raw["diagnostics"]["lean-vacuity"][0]
        self.assertIn("duplicate JSON key", diagnostic["parse_error"])
        self.assertEqual(
            RUN_REVIEW.base64.b64decode(diagnostic["stdout"]["base64"]), payload
        )

    def test_excessive_json_nesting_still_publishes_terminal_failure(self) -> None:
        payload = (
            b'{"findings":[],"honest_residual":'
            + b"[" * 1500
            + b'"x"'
            + b"]" * 1500
            + b"}"
        )
        with tempfile.TemporaryDirectory() as directory:
            completed, out = run_payload_review(payload, Path(directory))
            raw_path = single_output(out, "raw.json")
            raw = json.loads(raw_path.read_text(encoding="utf-8"))
            completion = json.loads(
                single_output(out, "completion.json").read_text(encoding="utf-8")
            )
            run_files = {path.name for path in raw_path.parent.iterdir()}
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(run_files, {"raw.json", "completion.json"})
        self.assertEqual(completion["outcome"]["status"], "failed")
        diagnostic = raw["diagnostics"]["lean-vacuity"][0]
        self.assertIn("nesting exceeds", diagnostic["parse_error"])
        self.assertEqual(
            RUN_REVIEW.base64.b64decode(diagnostic["stdout"]["base64"]), payload
        )


if __name__ == "__main__":
    unittest.main()
