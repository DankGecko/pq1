#!/usr/bin/env python3
"""Offline tests for the advisory ERC-7730 proxy drift monitor."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


CHECKER_PATH = Path(__file__).with_name("erc7730_proxy_drift.py")
SPEC = importlib.util.spec_from_file_location("erc7730_proxy_drift", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


BLOCK = {
    "number": 30_000_000,
    "number_hex": "0x1c9c380",
    "hash": "0x" + "44" * 32,
}
BEACON = "0x" + "be" * 20


def word(address: str, *, high: bytes = bytes(12)) -> str:
    return "0x" + high.hex() + address[2:]


class FakeRpc:
    def __init__(
        self,
        watch: checker.Watch,
        *,
        implementation: str | None = None,
        beacon: str = checker.ZERO_ADDRESS,
        proxy_code: bytes | None = None,
        implementation_code: bytes | None = None,
    ) -> None:
        self.watch = watch
        self.implementation = implementation or watch.expected_implementation
        self.beacon = beacon
        self.proxy_code = proxy_code if proxy_code is not None else b"proxy-code"
        self.implementation_code = (
            implementation_code if implementation_code is not None else b"implementation-code"
        )
        self.calls: list[tuple[str, list[object]]] = []

    def __call__(self, method: str, params: list[object]) -> object:
        self.calls.append((method, params))
        if method == "eth_chainId":
            return hex(self.watch.chain_id)
        if method == "eth_getBlockByNumber":
            return {"number": BLOCK["number_hex"], "hash": BLOCK["hash"]}
        if method == "eth_getStorageAt":
            slot = params[1]
            if slot == checker.IMPLEMENTATION_SLOT:
                return word(self.implementation)
            if slot == checker.BEACON_SLOT:
                return word(self.beacon)
            raise AssertionError(f"unexpected slot: {slot}")
        if method == "eth_getCode":
            address = params[0]
            if address == self.watch.proxy:
                return "0x" + self.proxy_code.hex()
            if address == self.implementation:
                return "0x" + self.implementation_code.hex()
            raise AssertionError(f"unexpected code address: {address}")
        raise AssertionError(f"unexpected method: {method}")


def synthetic_watch() -> checker.Watch:
    proxy_code = b"proxy-code"
    implementation_code = b"implementation-code"
    return checker.Watch(
        name="synthetic",
        chain_id=1,
        proxy="0x" + "11" * 20,
        expected_kind="eip1967-direct",
        expected_implementation="0x" + "22" * 20,
        expected_proxy_code_keccak256="0x" + checker.keccak256(proxy_code).hex(),
        expected_implementation_code_keccak256=(
            "0x" + checker.keccak256(implementation_code).hex()
        ),
        evidence_manifest="tests/erc7730-semantic-evidence/example/manifest.json",
        evidence_manifest_sha256="33" * 32,
        evidence_block_number=1,
        evidence_block_hash="0x" + "33" * 32,
        proxy_runtime_file=None,
        implementation_runtime_file=None,
    )


class KeccakAndManifestTests(unittest.TestCase):
    def test_ethereum_keccak_kats(self) -> None:
        self.assertEqual(
            checker.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            checker.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_eip1967_constants_are_exact(self) -> None:
        for label, constant in (
            (b"eip1967.proxy.implementation", checker.IMPLEMENTATION_SLOT),
            (b"eip1967.proxy.beacon", checker.BEACON_SLOT),
        ):
            derived = (int.from_bytes(checker.keccak256(label), "big") - 1).to_bytes(
                32, "big"
            )
            self.assertEqual(constant, "0x" + derived.hex())

    def test_checked_in_manifest_binds_four_exact_evidence_rows(self) -> None:
        watches = checker.load_watch_manifest()
        self.assertEqual(len(watches), 4)
        self.assertEqual({watch.chain_id for watch in watches}, {1})
        self.assertEqual(
            {watch.name for watch in watches},
            {
                "aave-v3-ethereum-pool",
                "lombard-staked-lbtc-mainnet",
                "midas-mtbill-deposit-vault-mainnet",
                "midas-mtbill-redemption-vault-mainnet",
            },
        )

    def _checked_manifest(self) -> dict[str, object]:
        return json.loads(checker.DEFAULT_MANIFEST.read_text())

    def _semantic_fixture(self, name: str):
        watch_manifest = self._checked_manifest()
        row = next(row for row in watch_manifest["watches"] if row["name"] == name)
        watch = checker._parse_watch(row)
        evidence_path = checker.ROOT / watch.evidence_manifest
        evidence = json.loads(evidence_path.read_text())
        return watch, evidence_path, evidence

    def _load_modified(self, mutate) -> None:
        manifest = self._checked_manifest()
        mutate(manifest)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "watch.json"
            path.write_text(json.dumps(manifest))
            checker.load_watch_manifest(path)

    def test_duplicate_identity_is_rejected(self) -> None:
        def mutate(manifest):
            manifest["watches"][1]["proxy"] = manifest["watches"][0]["proxy"]

        with self.assertRaises(checker.ManifestError):
            self._load_modified(mutate)

    def test_unknown_key_and_noncanonical_address_are_rejected(self) -> None:
        with self.assertRaises(checker.ManifestError):
            self._load_modified(lambda manifest: manifest["watches"][0].update(extra=True))
        with self.assertRaises(checker.ManifestError):
            self._load_modified(
                lambda manifest: manifest["watches"][0].update(
                    proxy=manifest["watches"][0]["proxy"].upper()
                )
            )

    def test_evidence_manifest_digest_and_runtime_hash_drift_are_rejected(self) -> None:
        with self.assertRaisesRegex(checker.ManifestError, "manifest SHA-256 drift"):
            self._load_modified(
                lambda manifest: manifest["watches"][0].update(
                    evidence_manifest_sha256="00" * 32
                )
            )
        with self.assertRaisesRegex(checker.ManifestError, "expected Keccak differs"):
            self._load_modified(
                lambda manifest: manifest["watches"][0].update(
                    expected_proxy_code_keccak256="0x" + "00" * 32
                )
            )

    def test_evidence_schema_version_is_exact_per_reviewed_layout(self) -> None:
        watch, evidence_path, original = self._semantic_fixture(
            "aave-v3-ethereum-pool"
        )
        for label, invalid in (
            ("missing", None),
            ("bool", True),
            ("wrong", 2),
            ("unknown", 999),
        ):
            with self.subTest(label=label):
                evidence = copy.deepcopy(original)
                if invalid is None:
                    del evidence["schema_version"]
                else:
                    evidence["schema_version"] = invalid
                with self.assertRaisesRegex(
                    checker.ManifestError, "schema_version must be exact integer 1"
                ):
                    checker._verify_evidence_semantics(
                        watch, evidence, evidence_path
                    )

    def test_unrelated_runtime_substitution_is_rejected_by_semantic_role(self) -> None:
        aave, aave_path, aave_evidence = self._semantic_fixture(
            "aave-v3-ethereum-pool"
        )
        borrow = next(
            record
            for record in aave_evidence["runtimes"]
            if record["key"] == "borrow_logic"
        )
        aave_substitution = replace(
            aave,
            proxy_runtime_file=(
                Path(aave.evidence_manifest).parent / borrow["path"]
            ).as_posix(),
            expected_proxy_code_keccak256=borrow["keccak256"],
        )

        lombard, lombard_path, lombard_evidence = self._semantic_fixture(
            "lombard-staked-lbtc-mainnet"
        )
        router_relative = "runtime/AssetRouterProxy.ethereum-mainnet.hex"
        router_path = lombard_path.parent / router_relative
        lombard_substitution = replace(
            lombard,
            proxy_runtime_file=(
                Path(lombard.evidence_manifest).parent / router_relative
            ).as_posix(),
            expected_proxy_code_keccak256=(
                "0x" + checker.keccak256(checker._decode_code_file(router_path)).hex()
            ),
        )

        for label, watch, evidence_path, evidence in (
            ("aave-borrow-logic", aave_substitution, aave_path, aave_evidence),
            (
                "lombard-asset-router",
                lombard_substitution,
                lombard_path,
                lombard_evidence,
            ),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                checker.ManifestError,
                "proxy runtime path differs from its bound evidence record",
            ):
                checker._verify_evidence_semantics(watch, evidence, evidence_path)

    def test_runtime_records_reject_missing_duplicate_and_malformed_binding(self) -> None:
        watch, evidence_path, original = self._semantic_fixture(
            "aave-v3-ethereum-pool"
        )

        missing = copy.deepcopy(original)
        missing["runtimes"] = [
            record for record in missing["runtimes"] if record["key"] != "pool_proxy"
        ]
        with self.assertRaisesRegex(checker.ManifestError, "missing evidence runtimes"):
            checker._verify_evidence_semantics(watch, missing, evidence_path)

        duplicate = copy.deepcopy(original)
        duplicate["runtimes"].append(copy.deepcopy(duplicate["runtimes"][2]))
        with self.assertRaisesRegex(checker.ManifestError, "duplicate evidence runtimes"):
            checker._verify_evidence_semantics(watch, duplicate, evidence_path)

        malformed = copy.deepcopy(original)
        next(
            record
            for record in malformed["runtimes"]
            if record["key"] == "pool_proxy"
        )["file_sha256"] = True
        with self.assertRaisesRegex(
            checker.ManifestError, "evidence runtime SHA-256 is malformed"
        ):
            checker._verify_evidence_semantics(watch, malformed, evidence_path)

    def test_evidence_uses_exact_semantic_paths(self) -> None:
        with self.assertRaisesRegex(checker.ManifestError, "chain id differs"):
            self._load_modified(
                lambda manifest: manifest["watches"][0].update(chain_id=11)
            )

    def test_watch_parser_rejects_beacon_authority(self) -> None:
        with self.assertRaisesRegex(
            checker.ManifestError, "expected_kind must be eip1967-direct"
        ):
            self._load_modified(
                lambda manifest: manifest["watches"][0].update(
                    expected_kind="eip1967-beacon"
                )
            )

    def test_evidence_path_escape_is_rejected(self) -> None:
        with self.assertRaises(checker.ManifestError):
            self._load_modified(
                lambda manifest: manifest["watches"][0].update(
                    proxy_runtime_file="../outside.hex"
                )
            )


class ClassificationTests(unittest.TestCase):
    def test_direct_proxy_exact_match(self) -> None:
        watch = synthetic_watch()
        rpc = FakeRpc(watch)
        result = checker.observe_watch(watch, rpc, BLOCK)
        self.assertEqual(result["status"], "MATCH")
        self.assertEqual(result["reasons"], [])
        self.assertEqual(result["observed"]["proxy_kind"], "eip1967-direct")
        self.assertEqual(result["observed"]["resolved_implementation"], watch.expected_implementation)
        self.assertTrue(
            all(
                call[1][-1] == BLOCK["number_hex"]
                for call in rpc.calls
                if call[0] != "eth_chainId"
            )
        )

    def test_implementation_address_change_is_drift(self) -> None:
        watch = synthetic_watch()
        result = checker.observe_watch(
            watch, FakeRpc(watch, implementation="0x" + "99" * 20), BLOCK
        )
        self.assertEqual(result["status"], "DRIFT")
        self.assertEqual(result["reasons"], ["implementation-address-changed"])

    def test_proxy_and_implementation_code_changes_are_independent_drift(self) -> None:
        watch = synthetic_watch()
        proxy = checker.observe_watch(watch, FakeRpc(watch, proxy_code=b"changed"), BLOCK)
        implementation = checker.observe_watch(
            watch, FakeRpc(watch, implementation_code=b"changed"), BLOCK
        )
        self.assertEqual(proxy["status"], "DRIFT")
        self.assertIn("proxy-code-changed", proxy["reasons"])
        self.assertNotIn("implementation-code-changed", proxy["reasons"])
        self.assertEqual(implementation["status"], "DRIFT")
        self.assertIn("implementation-code-changed", implementation["reasons"])
        self.assertNotIn("proxy-code-changed", implementation["reasons"])

    def test_empty_code_is_drift_not_unknown(self) -> None:
        watch = synthetic_watch()
        result = checker.observe_watch(
            watch, FakeRpc(watch, implementation_code=b""), BLOCK
        )
        self.assertEqual(result["status"], "DRIFT")
        self.assertIn("implementation-code-empty", result["reasons"])
        self.assertIn("implementation-code-changed", result["reasons"])

    def test_beacon_transition_is_drift_without_resolution(self) -> None:
        watch = synthetic_watch()
        rpc = FakeRpc(
            watch,
            implementation=checker.ZERO_ADDRESS,
            beacon=BEACON,
        )

        def rpc_with_matching_beacon_implementation(method, params):
            if method == "eth_call":
                rpc.calls.append((method, params))
                return word(watch.expected_implementation)
            return rpc(method, params)

        result = checker.observe_watch(
            watch,
            rpc_with_matching_beacon_implementation,
            BLOCK,
        )
        self.assertEqual(result["status"], "DRIFT")
        self.assertEqual(result["reasons"], ["proxy-kind-changed"])
        self.assertEqual(result["observed"]["proxy_kind"], "eip1967-beacon")
        self.assertNotIn("resolved_implementation", result["observed"])
        self.assertNotIn("eth_call", [method for method, _params in rpc.calls])

    def test_nonzero_beacon_is_kind_drift_but_both_zero_is_unknown(self) -> None:
        watch = synthetic_watch()
        both = checker.observe_watch(watch, FakeRpc(watch, beacon=BEACON), BLOCK)
        neither = checker.observe_watch(
            watch,
            FakeRpc(watch, implementation=checker.ZERO_ADDRESS),
            BLOCK,
        )
        self.assertEqual(both["status"], "DRIFT")
        self.assertEqual(both["reasons"], ["proxy-kind-changed"])
        self.assertEqual(neither["status"], "UNKNOWN")
        self.assertEqual(
            neither["reasons"], ["no-standard-eip1967-implementation-or-beacon"]
        )

    def test_nonzero_high_slot_bits_are_drift(self) -> None:
        watch = synthetic_watch()
        rpc = FakeRpc(watch)
        original = rpc.__call__

        def malformed(method, params):
            if method == "eth_getStorageAt" and params[1] == checker.IMPLEMENTATION_SLOT:
                return word(watch.expected_implementation, high=b"\x01" + bytes(11))
            return original(method, params)

        result = checker.observe_watch(watch, malformed, BLOCK)
        self.assertEqual(result["status"], "DRIFT")
        self.assertIn("implementation-slot-high-bits-nonzero", result["reasons"])

    def test_malformed_rpc_and_transport_failure_are_unknown(self) -> None:
        watch = synthetic_watch()
        rpc = FakeRpc(watch)
        original = rpc.__call__

        def malformed(method, params):
            if method == "eth_getStorageAt":
                return "not-hex"
            return original(method, params)

        malformed_result = checker.observe_watch(watch, malformed, BLOCK)
        self.assertEqual(malformed_result["status"], "UNKNOWN")

        def offline(_method, _params):
            raise checker.RpcError("transport unavailable: TimeoutError")

        offline_result = checker.observe_watch(watch, offline, BLOCK)
        self.assertEqual(offline_result["status"], "UNKNOWN")
        self.assertEqual(
            offline_result["reasons"], ["transport unavailable: TimeoutError"]
        )


class ReportAndTransportTests(unittest.TestCase):
    def _same_chain_fixture(
        self,
        *,
        revalidation_block=BLOCK,
        revalidation_error: checker.RpcError | None = None,
    ):
        one = synthetic_watch()
        two = copy.copy(one)
        object.__setattr__(two, "name", "synthetic-two")
        object.__setattr__(two, "proxy", "0x" + "12" * 20)
        rpc = FakeRpc(one)
        original = rpc.__call__
        block_reads = 0

        def shared(method, params):
            nonlocal block_reads
            if method == "eth_getBlockByNumber":
                rpc.calls.append((method, params))
                block_reads += 1
                if block_reads == 1:
                    block = BLOCK
                elif block_reads == 2:
                    if revalidation_error is not None:
                        raise revalidation_error
                    block = revalidation_block
                else:
                    raise AssertionError("unexpected third latest-block read")
                return {"number": block["number_hex"], "hash": block["hash"]}
            if method == "eth_getCode" and params[0] == two.proxy:
                return "0x" + rpc.proxy_code.hex()
            if method == "eth_getStorageAt" and params[0] == two.proxy:
                rewritten = [one.proxy, *params[1:]]
                return original(method, rewritten)
            return original(method, params)

        return [two, one], rpc, shared

    def _assert_all_revalidation_unknown(self, report, reason: str) -> None:
        self.assertEqual(
            report["summary"], {"total": 2, "MATCH": 0, "DRIFT": 0, "UNKNOWN": 2}
        )
        for result in report["results"]:
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertEqual(result["reasons"], [reason])
            self.assertEqual(result["observed"], {})
            self.assertEqual(result["observation_block"], BLOCK)

    def test_one_frozen_block_is_shared_then_revalidated_for_same_chain(self) -> None:
        watches, rpc, shared = self._same_chain_fixture()

        report = checker.run_monitor(
            watches, {1: shared}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        block_calls = [call for call in rpc.calls if call[0] == "eth_getBlockByNumber"]
        chain_calls = [call for call in rpc.calls if call[0] == "eth_chainId"]
        block_indices = [
            index
            for index, call in enumerate(rpc.calls)
            if call[0] == "eth_getBlockByNumber"
        ]
        state_indices = [
            index
            for index, call in enumerate(rpc.calls)
            if call[0] in {"eth_getStorageAt", "eth_getCode"}
        ]
        self.assertEqual(len(block_calls), 2)
        self.assertEqual(
            [call[1][0] for call in block_calls], ["latest", BLOCK["number_hex"]]
        )
        self.assertEqual(len(chain_calls), 1)
        self.assertTrue(
            all(rpc.calls[index][1][-1] == BLOCK["number_hex"] for index in state_indices)
        )
        self.assertLess(block_indices[0], min(state_indices))
        self.assertGreater(block_indices[1], max(state_indices))
        self.assertEqual(report["summary"], {"total": 2, "MATCH": 2, "DRIFT": 0, "UNKNOWN": 0})
        self.assertEqual([row["name"] for row in report["results"]], ["synthetic", "synthetic-two"])

    def test_same_height_hash_change_invalidates_every_chain_row(self) -> None:
        changed = BLOCK | {"hash": "0x" + "55" * 32}
        watches, _rpc, shared = self._same_chain_fixture(
            revalidation_block=changed
        )
        report = checker.run_monitor(
            watches, {1: shared}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self._assert_all_revalidation_unknown(
            report, "observation-block-hash-changed-during-monitoring"
        )

    def test_height_change_invalidates_every_chain_row(self) -> None:
        changed = BLOCK | {
            "number": BLOCK["number"] + 1,
            "number_hex": hex(BLOCK["number"] + 1),
        }
        watches, _rpc, shared = self._same_chain_fixture(
            revalidation_block=changed
        )
        report = checker.run_monitor(
            watches, {1: shared}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self._assert_all_revalidation_unknown(
            report, "observation-block-number-changed-during-monitoring"
        )

    def test_block_revalidation_failure_invalidates_every_chain_row(self) -> None:
        watches, _rpc, shared = self._same_chain_fixture(
            revalidation_error=checker.RpcError("RPC returned malformed JSON")
        )
        report = checker.run_monitor(
            watches, {1: shared}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self._assert_all_revalidation_unknown(
            report,
            "observation-block-revalidation-failed: RPC returned malformed JSON",
        )

    def test_wrong_rpc_chain_is_unknown_without_proxy_queries(self) -> None:
        watch = synthetic_watch()
        calls = []

        def wrong_chain(method, params):
            calls.append((method, params))
            if method == "eth_chainId":
                return "0x2"
            raise AssertionError(f"unexpected method after chain mismatch: {method}")

        report = checker.run_monitor(
            [watch], {1: wrong_chain}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self.assertEqual(report["summary"]["UNKNOWN"], 1)
        self.assertEqual(
            report["results"][0]["reasons"],
            ["RPC chain id mismatch: expected 1, got 2"],
        )
        self.assertEqual(calls, [("eth_chainId", [])])

    def test_missing_rpc_and_latest_block_failure_are_unknown(self) -> None:
        watch = synthetic_watch()
        missing = checker.run_monitor(
            [watch], {}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self.assertEqual(missing["summary"]["UNKNOWN"], 1)
        self.assertEqual(missing["results"][0]["reasons"], ["rpc-not-configured"])

        def bad_block(_method, _params):
            raise checker.RpcError("RPC returned malformed JSON")

        bad = checker.run_monitor(
            [watch], {1: bad_block}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self.assertEqual(bad["summary"]["UNKNOWN"], 1)
        self.assertEqual(bad["results"][0]["observation_block"], None)

    def test_authority_is_always_advisory_even_for_match(self) -> None:
        watch = synthetic_watch()
        report = checker.run_monitor(
            [watch], {1: FakeRpc(watch)}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self.assertTrue(report["authority"]["advisory_only"])
        for key in (
            "signing_authority",
            "catalogue_authority",
            "release_authority",
            "production_authority",
        ):
            self.assertFalse(report["authority"][key])
        self.assertEqual(report["results"][0]["status"], "MATCH")

    def test_fixed_timestamp_report_is_deterministic(self) -> None:
        watch = synthetic_watch()
        first = checker.run_monitor(
            [watch], {1: FakeRpc(watch)}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        second = checker.run_monitor(
            [watch], {1: FakeRpc(watch)}, observed_at_utc="2026-08-05T00:00:00Z"
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )

    def test_emit_report_writes_only_requested_path(self) -> None:
        report = {"schema": checker.REPORT_SCHEMA, "authority": {"advisory_only": True}}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "nested" / "report.json"
            checker.emit_report(report, output)
            self.assertEqual(
                [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()],
                ["nested/report.json"],
            )
            self.assertEqual(json.loads(output.read_text()), report)

    def test_emit_report_cannot_overwrite_repository_authority_inputs(self) -> None:
        report = {"schema": checker.REPORT_SCHEMA}
        with self.assertRaisesRegex(ValueError, "only under target"):
            checker.emit_report(report, checker.DEFAULT_MANIFEST)

    def test_json_rpc_http_validates_envelope_and_hides_url_from_error(self) -> None:
        class Response:
            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, size=-1):
                return self.payload if size < 0 else self.payload[:size]

        requests = []

        def opener(request, *, timeout):
            requests.append((request, timeout))
            return Response(b'{"jsonrpc":"2.0","id":1,"result":"0x2a"}')

        client = checker.JsonRpcHttp(
            "https://secret.example.invalid/rpc?token=do-not-report",
            timeout=3,
            opener=opener,
        )
        self.assertEqual(client("eth_chainId", []), "0x2a")
        sent = json.loads(requests[0][0].data)
        self.assertEqual(sent["method"], "eth_chainId")
        self.assertEqual(
            requests[0][0].headers["User-agent"],
            "PQSigner-ERC7730-Proxy-Drift/1",
        )
        self.assertEqual(requests[0][1], 3)

        def malformed(_request, *, timeout):
            self.assertEqual(timeout, 3)
            return Response(b"not-json")

        bad = checker.JsonRpcHttp(
            "https://secret.example.invalid/rpc?token=do-not-report",
            timeout=3,
            opener=malformed,
        )
        with self.assertRaises(checker.RpcError) as raised:
            bad("eth_chainId", [])
        self.assertNotIn("secret.example.invalid", str(raised.exception))
        self.assertNotIn("do-not-report", str(raised.exception))

    def test_cli_no_rpc_is_a_successful_unknown_advisory_report(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(checker.sys, "stdout", stdout), mock.patch.object(
            checker.sys, "stderr", stderr
        ), mock.patch.object(checker, "_now_utc", return_value="2026-08-05T00:00:00Z"):
            return_code = checker.main([])
        self.assertEqual(return_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["summary"], {"total": 4, "MATCH": 0, "DRIFT": 0, "UNKNOWN": 4})
        self.assertFalse(report["authority"]["signing_authority"])


if __name__ == "__main__":
    unittest.main()
