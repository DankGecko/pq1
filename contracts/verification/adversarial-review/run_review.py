#!/usr/bin/env python3
"""run_review.py — backend-AGNOSTIC orchestrator for the PQSigner FV adversarial
review. Drives any CLI/agent that reads a prompt and emits JSON (Claude Code,
Codex, a raw LLM, a future system). The portable primitive is:

    (PROMPT.md persona)  +  (protocol.json angles/schema)  +  (pipe to $CMD)

It is intentionally THIN — the linchpin is the strict findings schema in
PROMPT.md/protocol.json, not this orchestrator. For each review angle it
assembles the prompt (persona + angle instructions + resolved target paths),
runs N independent reviewer passes through the chosen backend, parses the JSON
answers, and uses quorum only to separate corroborated discovery candidates
from sub-quorum candidates. Successful discovery runs write report.md,
findings.json, annotated raw.json, and a terminal completion.json. Failed runs
write byte-faithful raw evidence plus the terminal failure receipt only. This
discovery swarm never assigns a review disposition: the exact
Partner-A/Partner-B pair in docs/planning-and-review-workflow.md owns the
subsequent reproduce/refute/narrow cross-adjudication.

Usage:
    run_review.py --backend claude --run-id a --out /external/reviews
    run_review.py --backend codex --angle lean-vacuity --run-id b --out /external/reviews
    run_review.py --backend generic --cmd 'codex exec - < {prompt_file}' --out /external/reviews
    run_review.py --backend claude --reviewers 3 --quorum 2 --out /external/reviews
    run_review.py --union-raw /external/a/raw.json /external/b/raw.json --out /external/reviews
    run_review.py --dry-run --angle ledger-honesty       # print the prompt, no call
    run_review.py --backend generic --cmd 'cat tests/canned_findings.json' --self-test-ok --out /tmp/review-test
        # SELF-TEST: proves orchestration end-to-end without burning an LLM call

Exit: 0 = ran (findings may be non-empty — this tool REPORTS, it does not gate);
      2 = orchestration/setup error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

KIT_DIR = Path(__file__).resolve().parent
PROTOCOL = KIT_DIR / "protocol.json"
PROMPT_MD = KIT_DIR / "PROMPT.md"


def load_protocol() -> dict:
    return json.loads(PROTOCOL.read_text(encoding="utf-8"))


def resolve_targets(root: Path, globs: list[str]) -> list[Path]:
    out: list[Path] = []
    for g in globs:
        for p in sorted(root.glob(g)):
            if p.is_file():
                out.append(p)
    return out


def assemble_prompt(proto: dict, angle: dict, root: Path, inline: bool, max_bytes: int) -> str:
    persona = PROMPT_MD.read_text(encoding="utf-8")
    files = resolve_targets(root, angle["targets"])
    lines = [persona, "\n\n---\n\n## THIS REVIEW",
             f"ROOT (absolute): {root}",
             f"ANGLE: {angle['id']} — {angle['title']}",
             "",
             angle["instructions"],
             "",
             "### Targets to review (read these in full if you have file tools):"]
    for f in files:
        lines.append(f"- {f}")
    if not files:
        lines.append("- (no files matched this angle's globs under ROOT — report that as honest_residual)")
    if inline:
        lines.append("\n### INLINED-FILES (your runtime may lack file tools):")
        for f in files:
            try:
                data = f.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                lines.append(f"\n----- {f} (unreadable: {e}) -----")
                continue
            truncated = data[:max_bytes]
            tag = "" if len(data) <= max_bytes else f" [TRUNCATED to {max_bytes} bytes of {len(data)}]"
            lines.append(f"\n----- {f}{tag} -----\n{truncated}")
    lines.append("\n\nNow emit the STRICT JSON object (findings + honest_residual) for THIS angle only.")
    return "\n".join(lines)


# JSON extraction: require one validated, unambiguous top-level answer.
REQUIRED_FINDING_STRINGS = (
    "id",
    "v_class",
    "severity",
    "target",
    "title",
    "claim",
    "defect",
    "poc",
)
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_V_CLASSES = {
    *(f"V{i}" for i in range(1, 12)),
    *(f"G{i}" for i in range(1, 6)),
    "FW",
    "NA",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
TOP_LEVEL_ANSWER_FIELDS = {"findings", "honest_residual"}
FINDING_FIELDS = {
    *REQUIRED_FINDING_STRINGS,
    "confidence",
    "suggested_fix",
}
DISCOVERY_PURPOSE = "discovery_only"
SELF_TEST_PURPOSE = "self_test_only"
RAW_FORMAT_VERSION = 4
RESERVED_SELF_TEST_FINDING_ID = "canned-example-finding"
BACKEND_TERMINATION_GRACE_SECONDS = 0.5


class DuplicateJsonKey(ValueError):
    """Raised when a model answer contains an ambiguous duplicate JSON key."""


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            # ``ensure_ascii=True`` keeps the diagnostic serializable even if
            # the duplicate key itself contains an escaped lone surrogate.
            safe_key = json.dumps(key, ensure_ascii=True)
            raise DuplicateJsonKey(f"duplicate JSON key: {safe_key}")
        obj[key] = value
    return obj


def _validate_unicode_scalars(value: object, path: str = "$") -> str | None:
    """Reject strings that cannot be encoded as Unicode scalar values.

    Python's JSON decoder deliberately preserves an escaped lone surrogate as
    a ``str``.  Such a value passes ordinary type checks but later makes an
    ``ensure_ascii=False`` evidence write fail before the raw bytes can be
    receipted.  Paths use only container indexes so an invalid key is never
    interpolated into the diagnostic itself.
    """
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            return f"{path} contains a non-Unicode-scalar string"
        return None
    if isinstance(value, list):
        for index, item in enumerate(value):
            error = _validate_unicode_scalars(item, f"{path}[{index}]")
            if error is not None:
                return error
        return None
    if isinstance(value, dict):
        for index, (key, item) in enumerate(value.items()):
            error = _validate_unicode_scalars(key, f"{path}.key[{index}]")
            if error is not None:
                return error
            error = _validate_unicode_scalars(item, f"{path}.value[{index}]")
            if error is not None:
                return error
    return None


def validate_answer(obj: object) -> str | None:
    """Return a concise schema error, or ``None`` for a usable answer.

    This is the pure-stdlib enforcement subset of protocol.json's output
    schema. Keeping it here prevents a malformed model response from either
    crashing aggregation or silently dropping the mandatory honest residual.
    """
    if not isinstance(obj, dict):
        return "top-level answer is not an object"
    unicode_error = _validate_unicode_scalars(obj)
    if unicode_error is not None:
        return unicode_error
    unknown_top_level = set(obj) - TOP_LEVEL_ANSWER_FIELDS
    if unknown_top_level:
        return (
            "top-level answer contains unknown field(s): "
            + ", ".join(sorted(unknown_top_level))
        )
    findings = obj.get("findings")
    if not isinstance(findings, list):
        return "findings is not an array"
    residual = obj.get("honest_residual")
    if not isinstance(residual, str) or not residual.strip():
        return "honest_residual is missing or empty"
    seen_ids: set[str] = set()
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            return f"findings[{index}] is not an object"
        unknown_finding = set(finding) - FINDING_FIELDS
        if unknown_finding:
            return (
                f"findings[{index}] contains unknown field(s): "
                + ", ".join(sorted(unknown_finding))
            )
        for field in REQUIRED_FINDING_STRINGS:
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                return f"findings[{index}].{field} is missing or empty"
        if finding["severity"] not in ALLOWED_SEVERITIES:
            return f"findings[{index}].severity is invalid"
        if finding["v_class"] not in ALLOWED_V_CLASSES:
            return f"findings[{index}].v_class is invalid"
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", finding["id"]):
            return f"findings[{index}].id is not a kebab-case slug"
        if finding["id"] in seen_ids:
            return f"findings[{index}].id duplicates an earlier finding"
        seen_ids.add(finding["id"])
        if (
            finding["severity"] not in {"low", "info"}
            and re.match(r"^\s*NONE\b", finding["poc"], re.IGNORECASE)
        ):
            return (
                f"findings[{index}].poc is NONE but severity is not low/info"
            )
        confidence = finding.get("confidence")
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= confidence <= 1.0
        ):
            return f"findings[{index}].confidence is not a number in [0,1]"
        if "suggested_fix" in finding and not isinstance(finding["suggested_fix"], str):
            return f"findings[{index}].suggested_fix is not a string"
    return None


def extract_json_diagnostic(text: str) -> tuple[dict | None, str | None]:
    """Parse one unwrapped top-level JSON object, allowing whitespace only.

    Backend logs belong on stderr. Accepting prose, Markdown fences, wrappers,
    or trailing values on stdout makes the evidence boundary ambiguous and can
    hide a second or truncated answer.
    """
    stripped = text.strip()
    if not stripped:
        return None, "stdout is empty"
    try:
        answer = json.loads(stripped, object_pairs_hook=_strict_object)
    except RecursionError:
        return None, "invalid JSON: nesting exceeds parser limit"
    except DuplicateJsonKey as error:
        return None, f"invalid JSON: {error}"
    except json.JSONDecodeError as error:
        return None, f"stdout is not exactly one JSON value: {error.msg}"
    try:
        error = validate_answer(answer)
    except RecursionError:
        return None, "schema validation failed: nesting exceeds validation limit"
    if error is not None:
        return None, f"schema validation failed: {error}"
    return answer, None


def extract_json(text: str) -> dict | None:
    """Compatibility wrapper returning only a validated answer."""
    answer, _error = extract_json_diagnostic(text)
    return answer


def run_backend(
    template: str, prompt: str, timeout: int
) -> tuple[bytes, bytes, int, bool]:
    """Run one backend and terminate its whole process group on timeout."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".prompt.md", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(prompt)
        prompt_path = tf.name
    cmd = template.replace("{prompt_file}", shlex.quote(prompt_path))
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            cwd=str(KIT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return stdout, stderr, process.returncode, False
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=BACKEND_TERMINATION_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass

            # The shell leader may have exited while a descendant remains in
            # the session and still owns the output pipes.  Kill the group even
            # when wait() returned, then reap and collect the complete partial
            # streams exactly once (concatenating TimeoutExpired.output can
            # duplicate bytes returned by communicate()).
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            return stdout, stderr, 124, True
    finally:
        try:
            Path(prompt_path).unlink()
        except OSError:
            pass


def _slug(value: object) -> str:
    slug = "-".join(re.findall(r"[a-z0-9]+", str(value).lower()))
    return slug or "unnamed"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )


def stream_receipt(data: bytes) -> dict:
    """Return a byte-faithful, JSON-safe stream receipt."""
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        utf8 = {
            "valid": False,
            "error_start": error.start,
            "error_end": error.end,
            "reason": error.reason,
        }
    else:
        utf8 = {"valid": True}
    return {
        "length": len(data),
        "sha256": _sha256(data),
        "base64": base64.b64encode(data).decode("ascii"),
        "utf8": utf8,
    }


def _decode_utf8(data: bytes) -> tuple[str | None, str | None]:
    try:
        return data.decode("utf-8", errors="strict"), None
    except UnicodeDecodeError as error:
        return None, (
            "stdout is not strict UTF-8: "
            f"bytes {error.start}..{error.end}: {error.reason}"
        )


def _git_output(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-c", "core.quotepath=false", *args],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout


def _target_manifest(root: Path, angles: list[dict]) -> list[dict]:
    files = {
        path.resolve()
        for angle in angles
        for path in resolve_targets(root, angle["targets"])
    }
    manifest = []
    for path in sorted(files):
        data = path.read_bytes()
        manifest.append(
            {
                "path": path.relative_to(root).as_posix(),
                "length": len(data),
                "sha256": _sha256(data),
            }
        )
    return manifest


def capture_review_snapshot(
    root: Path, angles: list[dict], prompts: dict[str, str]
) -> dict:
    """Capture the target and repository facts that define this review run."""
    head = _git_output(root, "rev-parse", "HEAD").decode("ascii").strip()
    head_tree = _git_output(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    status = _git_output(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
    )
    manifest = _target_manifest(root, angles)
    snapshot = {
        "head": head,
        "head_tree": head_tree,
        "git_status": stream_receipt(status),
        "target_manifest": manifest,
        "target_manifest_sha256": _canonical_sha256(manifest),
        "prompt_md_sha256": _sha256(PROMPT_MD.read_bytes()),
        "protocol_sha256": _sha256(PROTOCOL.read_bytes()),
        "assembled_prompt_sha256": {
            angle_id: _sha256(prompt.encode("utf-8"))
            for angle_id, prompt in sorted(prompts.items())
        },
    }
    snapshot["snapshot_sha256"] = _canonical_sha256(snapshot)
    return snapshot


def make_run_receipt(
    backend: str,
    run_id: str,
    template: str,
    proto: dict,
    root: Path,
    reviewers: int,
    quorum: int,
    jobs: int,
    *,
    angles: list[dict] | None = None,
    prompts: dict[str, str] | None = None,
    inline_files: bool = False,
    max_file_bytes: int = 60000,
    timeout: int = 1200,
    target_initial: dict | None = None,
    self_test: bool = False,
) -> dict:
    """Create the deterministic namespace and receipt for one invocation.

    ``run_id`` is explicit because no deterministic local fact can distinguish
    two otherwise-identical repeated invocations. Coordinators combining such
    runs must give each one a distinct ID.
    """
    selected_angles = angles or []
    assembled_prompts = prompts or {}
    template_sha256 = _sha256(template.encode("utf-8"))
    protocol_sha256 = _sha256(PROTOCOL.read_bytes())
    receipt = {
        "run_id": run_id,
        "backend": backend,
        "template_sha256": template_sha256,
        "review_selectors": {
            "angle_ids": [angle["id"] for angle in selected_angles],
            "angle_configs_sha256": {
                angle["id"]: _canonical_sha256(angle) for angle in selected_angles
            },
        },
        "protocol_name": proto["name"],
        "protocol_version": proto["version"],
        "protocol_sha256": protocol_sha256,
        "prompt_md_sha256": _sha256(PROMPT_MD.read_bytes()),
        "assembled_prompt_sha256": {
            angle_id: _sha256(prompt.encode("utf-8"))
            for angle_id, prompt in sorted(assembled_prompts.items())
        },
        "root": str(root),
        "settings": {
            "reviewers": reviewers,
            "quorum": quorum,
            "jobs": jobs,
            "inline_files": inline_files,
            "max_file_bytes": max_file_bytes,
            "timeout_seconds": timeout,
            "self_test": self_test,
        },
        "target_initial": target_initial or {},
    }
    invocation_digest = _canonical_sha256(receipt)
    namespace_digest = invocation_digest[:12]
    namespace = f"{_slug(backend)}/{_slug(run_id)}-{namespace_digest}"
    receipt["invocation_sha256"] = invocation_digest
    receipt["namespace"] = namespace
    return receipt


def annotate_reviews(
    angle_id: str,
    per_reviewer: list[dict | None],
    run_namespace: str = "standalone",
) -> list[dict | None]:
    """Copy raw answers and assign deterministic origin IDs to every variant.

    The index components preserve duplicate findings emitted by one reviewer;
    the canonical-content digest makes an origin auditable without trusting the
    model-provided ``id``. The returned objects are what raw.json records and
    what aggregate() consumes.
    """
    annotated: list[dict | None] = []
    for ridx, answer in enumerate(per_reviewer):
        if answer is None:
            annotated.append(None)
            continue
        copied = dict(answer)
        findings = []
        for fidx, finding in enumerate(answer.get("findings", [])):
            variant = dict(finding)
            canonical = json.dumps(
                finding, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            digest = hashlib.sha256(canonical).hexdigest()[:12]
            variant["_origin_id"] = (
                f"{run_namespace}/{_slug(angle_id)}/reviewer-{ridx}/finding-{fidx}-"
                f"{_slug(finding.get('id', 'unnamed'))}-{digest}"
            )
            findings.append(variant)
        copied["findings"] = findings
        copied["_reviewer_index"] = ridx
        annotated.append(copied)
    return annotated


def aggregate(per_reviewer: list[dict | None], quorum: int) -> dict:
    """Group discovery variants without assigning a finding disposition.

    A group is ``corroborated`` when at least ``quorum`` distinct reviewer
    passes raised the fuzzy-matching candidate. Otherwise it is ``sub_quorum``.
    Every raw variant and deterministic origin ID remains attached to the group.
    """
    groups: dict[tuple, dict] = {}
    residuals: list[str] = []
    for ridx, ans in enumerate(per_reviewer):
        if ans is None:
            residuals.append(f"[reviewer {ridx}] produced no parseable JSON.")
            continue
        residuals.append(f"[reviewer {ridx}] {ans.get('honest_residual', '(no honest_residual!)')}")
        for f in ans.get("findings", []):
            tgt = str(f.get("target", "")).split("/")[-1].split(":")[0]
            stem = "-".join(re.findall(r"[a-z0-9]+", str(f.get("title", "")).lower())[:5])
            key = (tgt, f.get("v_class", "?"), stem)
            g = groups.setdefault(key, {"voters": set(), "items": []})
            g["voters"].add(ridx)
            g["items"].append(f)
    corroborated, sub_quorum = [], []
    for key, g in groups.items():
        rep = min(
            g["items"],
            key=lambda x: (
                SEVERITY_RANK.get(x.get("severity", "info"), 9),
                -x.get("confidence", 0),
            ),
        )
        rep = dict(rep)
        rep["_votes"] = len(g["voters"])
        variants = sorted(
            (dict(item) for item in g["items"]),
            key=lambda item: item.get("_origin_id", ""),
        )
        rep["_origin_ids"] = [item.get("_origin_id", "") for item in variants]
        rep["_variants"] = variants
        (corroborated if len(g["voters"]) >= quorum else sub_quorum).append(rep)
    keyf = lambda x: (
        SEVERITY_RANK.get(x.get("severity", "info"), 9),
        -x.get("confidence", 0),
    )
    corroborated.sort(key=keyf)
    sub_quorum.sort(key=keyf)
    return {
        "corroborated": corroborated,
        "sub_quorum": sub_quorum,
        "residuals": residuals,
    }


def raw_payload(
    raw_dump: dict[str, list[dict | None]],
    diagnostics: dict[str, list[dict]] | None = None,
    run_receipt: dict | None = None,
    purpose: str = DISCOVERY_PURPOSE,
) -> dict:
    """Build the annotated raw-review receipt written as raw.json."""
    if purpose not in {DISCOVERY_PURPOSE, SELF_TEST_PURPOSE}:
        raise ValueError(f"unsupported raw receipt purpose: {purpose}")
    if purpose == SELF_TEST_PURPOSE:
        authority = (
            "Self-test fixture output only. This receipt is not discovery "
            "evidence and cannot be included in a discovery union."
        )
    else:
        authority = (
            "Quorum corroborates discovery only. Finding dispositions are "
            "reserved to the exact dual-review partners and symmetric "
            "cross-adjudication in docs/planning-and-review-workflow.md."
        )
    return {
        "_meta": {
            "format_version": RAW_FORMAT_VERSION,
            "purpose": purpose,
            "authority": authority,
            "origin_id_field": "_origin_id",
            "run": run_receipt or {},
        },
        "angles": raw_dump,
        "diagnostics": diagnostics or {},
    }


def resolve_external_output_base(value: str | None, repo_root: Path) -> Path:
    """Resolve an explicit output base and reject repository-local paths."""
    if value is None or not value.strip():
        raise ValueError("--out is required and must name an external directory")
    output_base = Path(value).expanduser().resolve()
    resolved_root = repo_root.resolve()
    if output_base == resolved_root or resolved_root in output_base.parents:
        raise ValueError("--out must resolve outside the repository")
    return output_base


class SecureOutputDir:
    """An opened output directory pinned to one device/inode."""

    def __init__(self, path: Path, fd: int, device: int, inode: int) -> None:
        self.path = path
        self.fd = fd
        self.device = device
        self.inode = inode

    def verify(self) -> None:
        try:
            path_stat = os.lstat(self.path)
            fd_stat = os.fstat(self.fd)
        except OSError as error:
            raise ValueError(f"output directory identity unavailable: {error}") from error
        if not stat.S_ISDIR(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode):
            raise ValueError("output directory path is no longer a real directory")
        expected = (self.device, self.inode)
        if (path_stat.st_dev, path_stat.st_ino) != expected:
            raise ValueError("output directory path was replaced")
        if (fd_stat.st_dev, fd_stat.st_ino) != expected:
            raise ValueError("retained output directory descriptor changed identity")

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def _open_directory(path: Path) -> SecureOutputDir:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        descriptor_stat = os.fstat(fd)
        path_stat = os.lstat(path)
        if not stat.S_ISDIR(descriptor_stat.st_mode):
            raise ValueError(f"output path is not a directory: {path}")
        if stat.S_ISLNK(path_stat.st_mode):
            raise ValueError(f"output path is a symlink: {path}")
        if (descriptor_stat.st_dev, descriptor_stat.st_ino) != (
            path_stat.st_dev,
            path_stat.st_ino,
        ):
            raise ValueError(f"output directory changed while opening: {path}")
        return SecureOutputDir(
            path,
            fd,
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
        )
    except Exception:
        os.close(fd)
        raise


def _open_or_create_output_base(path: Path) -> SecureOutputDir:
    path.mkdir(parents=True, exist_ok=True)
    return _open_directory(path)


def prepare_run_output_dir(
    output_base: Path, run_namespace: str, repo_root: Path
) -> SecureOutputDir:
    """Create and retain a no-follow descriptor for the run directory."""
    components = run_namespace.split("/")
    if not components or any(
        not component or component in {".", ".."} or "/" in component
        for component in components
    ):
        raise ValueError("invalid output namespace")
    current = _open_or_create_output_base(output_base)
    cursor = output_base
    try:
        for index, component in enumerate(components):
            is_leaf = index == len(components) - 1
            try:
                os.mkdir(component, mode=0o700, dir_fd=current.fd)
            except FileExistsError:
                if is_leaf:
                    raise
            try:
                child_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current.fd,
                )
            except OSError as error:
                raise ValueError(
                    f"output namespace component is not a real directory: {component}"
                ) from error
            try:
                child_stat = os.fstat(child_fd)
                entry_stat = os.stat(
                    component, dir_fd=current.fd, follow_symlinks=False
                )
                if not stat.S_ISDIR(entry_stat.st_mode):
                    raise ValueError(
                        f"output namespace component is not a directory: {component}"
                    )
                if (child_stat.st_dev, child_stat.st_ino) != (
                    entry_stat.st_dev,
                    entry_stat.st_ino,
                ):
                    raise ValueError(
                        f"output namespace component changed while opening: {component}"
                    )
            except Exception:
                os.close(child_fd)
                raise
            current.close()
            cursor = cursor / component
            current = SecureOutputDir(
                cursor,
                child_fd,
                child_stat.st_dev,
                child_stat.st_ino,
            )
        current.verify()
    except Exception:
        current.close()
        raise

    resolved_run = current.path.resolve()
    resolved_base = output_base.resolve()
    resolved_root = repo_root.resolve()
    if resolved_run != resolved_base and resolved_base not in resolved_run.parents:
        current.close()
        raise ValueError("resolved run directory escaped the external output base")
    if resolved_run == resolved_root or resolved_root in resolved_run.parents:
        current.close()
        raise ValueError("resolved run directory entered the repository")
    return current


def safe_write_bytes(output: SecureOutputDir, name: str, data: bytes) -> Path:
    """Create one regular, single-link artifact relative to the retained fd."""
    if not name or name in {".", ".."} or "/" in name or os.sep in name:
        raise ValueError(f"invalid artifact name: {name!r}")
    output.verify()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    fd = os.open(name, flags, 0o600, dir_fd=output.fd)
    try:
        initial_stat = os.fstat(fd)
        if not stat.S_ISREG(initial_stat.st_mode) or initial_stat.st_nlink != 1:
            raise ValueError(f"artifact is not a private regular file: {name}")
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise OSError(f"short write for artifact {name}")
            written += count
        os.fsync(fd)
        final_stat = os.fstat(fd)
        entry_stat = os.stat(name, dir_fd=output.fd, follow_symlinks=False)
        if not stat.S_ISREG(entry_stat.st_mode):
            raise ValueError(f"artifact directory entry is not regular: {name}")
        if final_stat.st_nlink != 1 or entry_stat.st_nlink != 1:
            raise ValueError(f"artifact acquired an unexpected hard link: {name}")
        if (final_stat.st_dev, final_stat.st_ino) != (
            entry_stat.st_dev,
            entry_stat.st_ino,
        ):
            raise ValueError(f"artifact directory entry was replaced: {name}")
    finally:
        os.close(fd)
    os.fsync(output.fd)
    output.verify()
    return output.path / name


def safe_write_text(output: SecureOutputDir, name: str, text: str) -> Path:
    return safe_write_bytes(output, name, text.encode("utf-8"))


def _contains_reserved_self_test_fixture(payload: object) -> bool:
    """Return true when a parsed answer/receipt contains the canned fixture.

    A generic backend is operator-supplied and cannot be proven to have used
    its prompt.  The built-in fixture is nevertheless an unambiguous reserved
    value and must never acquire discovery authority outside ``--self-test-ok``.
    """
    if not isinstance(payload, dict):
        return False
    findings = payload.get("findings")
    if isinstance(findings, list):
        return any(
            isinstance(finding, dict)
            and finding.get("id") == RESERVED_SELF_TEST_FINDING_ID
            for finding in findings
        )
    angles = payload.get("angles")
    if not isinstance(angles, dict):
        return False
    for reviews in angles.values():
        if not isinstance(reviews, list):
            continue
        for review in reviews:
            if isinstance(review, dict) and _contains_reserved_self_test_fixture(review):
                return True
    return False


def _validate_raw_discovery_payload(payload: object) -> tuple[str, dict]:
    if not isinstance(payload, dict):
        raise ValueError("raw receipt is not an object")
    meta = payload.get("_meta")
    if not isinstance(meta, dict):
        raise ValueError("raw receipt has no _meta object")
    if (
        meta.get("format_version") != RAW_FORMAT_VERSION
        or meta.get("purpose") != DISCOVERY_PURPOSE
    ):
        raise ValueError("raw receipt is not a supported discovery-only format")
    run = meta.get("run")
    if not isinstance(run, dict):
        raise ValueError("raw receipt has no run metadata")
    namespace = run.get("namespace")
    if not isinstance(namespace, str) or not namespace.strip():
        raise ValueError("raw receipt has no run namespace")
    if not isinstance(payload.get("angles"), dict):
        raise ValueError("raw receipt has no angles object")
    if not isinstance(payload.get("diagnostics"), dict):
        raise ValueError("raw receipt has no diagnostics object")
    settings = run.get("settings")
    if not isinstance(settings, dict) or settings.get("self_test") is not False:
        raise ValueError("raw receipt lacks an explicit non-self-test setting")
    try:
        contains_reserved_fixture = _contains_reserved_self_test_fixture(payload)
    except RecursionError as error:
        raise ValueError(
            "raw receipt nesting exceeds the fixture-scan limit"
        ) from error
    if contains_reserved_fixture:
        raise ValueError("raw receipt contains the reserved self-test fixture")
    return namespace, run


def _validate_completion_for_raw(
    raw_path: Path,
    raw_bytes: bytes,
    namespace: str,
    run: dict,
) -> None:
    """Require the terminal sibling receipt to bind this exact raw artifact."""
    if raw_path.name != "raw.json":
        raise ValueError(f"{raw_path}: union input must be named raw.json")
    completion_path = raw_path.with_name("completion.json")
    try:
        completion_bytes = completion_path.read_bytes()
        completion = json.loads(completion_bytes, object_pairs_hook=_strict_object)
    except FileNotFoundError as error:
        raise ValueError(f"{raw_path}: missing sibling completion.json") from error
    except RecursionError as error:
        raise ValueError(
            f"{completion_path}: invalid JSON: nesting exceeds parser limit"
        ) from error
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKey) as error:
        raise ValueError(f"{completion_path}: invalid JSON: {error}") from error
    if not isinstance(completion, dict):
        raise ValueError(f"{completion_path}: completion receipt is not an object")
    meta = completion.get("_meta")
    if not isinstance(meta, dict) or (
        meta.get("format_version") != 1
        or meta.get("purpose") != "review_run_completion"
        or meta.get("terminal_marker") is not True
    ):
        raise ValueError(f"{completion_path}: invalid terminal marker")
    if completion.get("namespace") != namespace:
        raise ValueError(f"{completion_path}: namespace does not match raw.json")
    if completion.get("invocation_sha256") != run.get("invocation_sha256"):
        raise ValueError(f"{completion_path}: invocation does not match raw.json")
    if completion.get("review_purpose") != DISCOVERY_PURPOSE:
        raise ValueError(f"{completion_path}: completion is not discovery-only")
    artifacts = completion.get("artifacts")
    raw_artifact = artifacts.get("raw.json") if isinstance(artifacts, dict) else None
    expected = {
        "length": len(raw_bytes),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }
    if raw_artifact != expected:
        raise ValueError(f"{completion_path}: raw.json binding mismatch")


def build_raw_union(raw_paths: list[Path]) -> tuple[dict, str]:
    """Build a deterministic, lossless envelope without cross-run re-voting."""
    if not raw_paths:
        raise ValueError("at least one raw.json receipt is required")
    entries: list[dict] = []
    seen_namespaces: set[str] = set()
    for raw_path in raw_paths:
        raw_bytes = raw_path.read_bytes()
        try:
            payload = json.loads(raw_bytes, object_pairs_hook=_strict_object)
        except RecursionError as error:
            raise ValueError(
                f"{raw_path}: invalid JSON: nesting exceeds parser limit"
            ) from error
        except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKey) as error:
            raise ValueError(f"{raw_path}: invalid JSON: {error}") from error
        namespace, run = _validate_raw_discovery_payload(payload)
        _validate_completion_for_raw(raw_path, raw_bytes, namespace, run)
        if namespace in seen_namespaces:
            raise ValueError(f"duplicate run namespace: {namespace}")
        seen_namespaces.add(namespace)
        entries.append(
            {
                "namespace": namespace,
                "source_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "payload": payload,
            }
        )
    entries.sort(key=lambda entry: entry["namespace"])
    content = {
        "purpose": "lossless_discovery_union",
        "authority": (
            "This envelope preserves discovery receipts only. It performs no "
            "cross-run voting and assigns no finding or stage disposition."
        ),
        "runs": entries,
    }
    canonical = json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    union_id = hashlib.sha256(canonical).hexdigest()
    return {
        "_meta": {
            "format_version": 1,
            "purpose": content["purpose"],
            "authority": content["authority"],
            "union_id": union_id,
            "run_count": len(entries),
        },
        "runs": entries,
    }, union_id


def write_raw_union(raw_paths: list[Path], output_base: Path) -> Path:
    """Write a content-addressed union without overwriting prior evidence."""
    payload, union_id = build_raw_union(raw_paths)
    output = _open_or_create_output_base(output_base)
    try:
        encoded = (
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        return safe_write_bytes(output, f"union-{union_id[:12]}.json", encoded)
    finally:
        output.close()


def validate_cli_bounds(args: argparse.Namespace) -> str | None:
    if args.reviewers < 1:
        return "--reviewers must be >= 1"
    if args.quorum < 1 or args.quorum > args.reviewers:
        return "--quorum must satisfy 1 <= quorum <= reviewers"
    if args.jobs < 1:
        return "--jobs must be >= 1"
    if args.max_file_bytes < 1:
        return "--max-file-bytes must be >= 1"
    if args.timeout < 1:
        return "--timeout must be >= 1"
    if not args.run_id.strip():
        return "--run-id must be non-empty"
    return None


def select_angles(configured: list[dict], requested: list[str] | None) -> list[dict]:
    """Select exact angle IDs, preserving first-request order and rejecting drift."""
    if not requested:
        return list(configured)
    by_id: dict[str, dict] = {}
    for angle in configured:
        angle_id = angle["id"]
        if angle_id in by_id:
            raise ValueError(f"protocol contains duplicate angle id: {angle_id}")
        by_id[angle_id] = angle

    unknown: list[str] = []
    selected: list[dict] = []
    seen: set[str] = set()
    for angle_id in requested:
        if angle_id not in by_id:
            if angle_id not in unknown:
                unknown.append(angle_id)
            continue
        if angle_id not in seen:
            selected.append(by_id[angle_id])
            seen.add(angle_id)
    if unknown:
        raise ValueError(
            "unknown angle(s): "
            + ", ".join(unknown)
            + "; known: "
            + ", ".join(by_id)
        )
    return selected


def classify_run(
    diagnostics: dict[str, list[dict]],
    *,
    target_drift: bool,
    self_test: bool,
    results: dict[str, dict],
) -> dict:
    """Return the terminal outcome before any success-shaped publication."""
    failed_passes = sum(
        diagnostic.get("parse_status") != "validated"
        for angle_diagnostics in diagnostics.values()
        for diagnostic in angle_diagnostics
    )
    finding_count = sum(
        len(result["corroborated"]) + len(result["sub_quorum"])
        for result in results.values()
    )
    failure_codes: list[str] = []
    if failed_passes:
        failure_codes.append("backend_pass_invalid")
    if target_drift:
        failure_codes.append("target_drift")
    if self_test and finding_count == 0:
        failure_codes.append("self_test_empty")
    return {
        "status": "failed" if failure_codes else "succeeded",
        "failure_codes": failure_codes,
        "failed_passes": failed_passes,
        "finding_count": finding_count,
    }


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def completion_payload(
    run_receipt: dict,
    purpose: str,
    outcome: dict,
    artifacts: dict[str, bytes],
) -> dict:
    """Build the terminal marker that is written after every other artifact."""
    return {
        "_meta": {
            "format_version": 1,
            "purpose": "review_run_completion",
            "terminal_marker": True,
        },
        "namespace": run_receipt["namespace"],
        "invocation_sha256": run_receipt["invocation_sha256"],
        "review_purpose": purpose,
        "outcome": outcome,
        "artifacts": {
            name: {"length": len(data), "sha256": _sha256(data)}
            for name, data in sorted(artifacts.items())
        },
    }


def render_report(proto: dict, results: dict[str, dict], reviewers: int, quorum: int) -> str:
    out = ["# FV adversarial-review report", "",
           f"protocol: {proto['name']} v{proto['version']} | "
           f"reviewers={reviewers} quorum={quorum}", ""]
    total_corroborated = sum(len(r["corroborated"]) for r in results.values())
    total_sub_quorum = sum(len(r["sub_quorum"]) for r in results.values())
    out += [
        "**Discovery-only output.** Quorum prioritizes/corroborates candidates; "
        "it does not confirm, refute, narrow, accept, or otherwise disposition a finding. "
        "Those actions are reserved to the exact Partner-A/Partner-B protocol in "
        "`docs/planning-and-review-workflow.md`.",
        "",
        f"**{total_corroborated} corroborated discovery candidate(s)** "
        f"(≥{quorum} reviewers) | {total_sub_quorum} sub-quorum candidate(s) | "
        f"across {len(results)} angle(s)",
        "",
    ]
    for angle_id, r in results.items():
        out += [f"## angle: {angle_id}", ""]
        if r["corroborated"]:
            out.append("### corroborated discovery candidates")
            for f in r["corroborated"]:
                out += _fmt_finding(f)
        if r["sub_quorum"]:
            out.append("### sub-quorum discovery candidates (triage; do not discard)")
            for f in r["sub_quorum"]:
                out += _fmt_finding(f)
        if not r["corroborated"] and not r["sub_quorum"]:
            out.append("_no findings parsed for this angle._")
        out.append("")
        out.append("#### honest residuals (the tracked defeaters — read these)")
        for res in r["residuals"]:
            out.append(f"- {res}")
        out.append("")
    out += ["---",
            "_This swarm surfaces discovery candidates; it does not gate or disposition. "
            "Send every candidate and every retained variant/origin ID to both exact "
            "review partners for symmetric cross-adjudication. V7 (latent-false axiom) "
            "and V11 (wrong spec) survive any single pass. Treat the honest residuals as "
            "the live to-verify list, not as reassurance._"]
    return "\n".join(out)


def _fmt_finding(f: dict) -> list[str]:
    lines = [
        f"- **[{f.get('severity','?')}/{f.get('v_class','?')}] {f.get('title','')}** "
        f"(votes={f.get('_votes',1)}, conf={f.get('confidence','?')})",
        f"  - origins: {', '.join(f.get('_origin_ids', []))}",
        f"  - target: `{f.get('target','')}`",
        f"  - claim: {f.get('claim','')}",
        f"  - defect: {f.get('defect','')}",
        f"  - poc: {f.get('poc','')}",
        f"  - fix: {f.get('suggested_fix','')}",
    ]
    variants = f.get("_variants", [])
    if len(variants) > 1:
        lines.append("  - retained variants:")
        for variant in variants:
            lines.append(
                f"    - `{variant.get('_origin_id', '')}`: "
                f"[{variant.get('severity', '?')}/{variant.get('v_class', '?')}] "
                f"{variant.get('target', '')} — {variant.get('title', '')} "
                f"(conf={variant.get('confidence', '?')})"
            )
    return lines


def main() -> int:
    proto = load_protocol()
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="claude", help="key in protocol.backends, or 'generic' with --cmd")
    ap.add_argument("--cmd", default=None, help="command template for --backend generic (may use {prompt_file})")
    ap.add_argument("--angle", action="append", help="angle id (repeatable); default = all")
    ap.add_argument("--reviewers", type=int, default=proto["defaults"]["reviewers"])
    ap.add_argument("--quorum", type=int, default=proto["defaults"]["quorum"])
    ap.add_argument("--jobs", type=int, default=proto["defaults"]["jobs"])
    ap.add_argument(
        "--run-id",
        default="default",
        help=(
            "deterministic invocation ID used in origin IDs; choose a distinct "
            "value when unioning repeated runs of the same backend"
        ),
    )
    ap.add_argument(
        "--out",
        default=None,
        help=(
            "required external output base; normal runs create a no-clobber "
            "backend/run-id directory beneath it"
        ),
    )
    ap.add_argument(
        "--union-raw",
        nargs="+",
        metavar="RAW_JSON",
        help=(
            "write a deterministic lossless union of discovery raw.json "
            "receipts; performs no cross-run voting"
        ),
    )
    ap.add_argument("--inline-files", action="store_true", help="embed file contents (tool-less backends)")
    ap.add_argument("--max-file-bytes", type=int, default=60000)
    ap.add_argument("--timeout", type=int, default=1200)
    ap.add_argument("--dry-run", action="store_true", help="print one assembled prompt and exit")
    ap.add_argument("--self-test-ok", action="store_true", help="assert >=1 finding parsed (for CI self-test)")
    args = ap.parse_args()

    bounds_error = validate_cli_bounds(args)
    if bounds_error is not None:
        print(f"ERROR: {bounds_error}", file=sys.stderr)
        return 2

    root = (KIT_DIR / proto["root"]).resolve()
    if not root.is_dir():
        print(f"ERROR: root {root} not a directory", file=sys.stderr)
        return 2

    if args.union_raw:
        incompatible = []
        if args.dry_run:
            incompatible.append("--dry-run")
        if args.angle:
            incompatible.append("--angle")
        if args.cmd:
            incompatible.append("--cmd")
        if args.inline_files:
            incompatible.append("--inline-files")
        if args.self_test_ok:
            incompatible.append("--self-test-ok")
        if incompatible:
            print(
                "ERROR: --union-raw is incompatible with "
                + ", ".join(incompatible),
                file=sys.stderr,
            )
            return 2
        try:
            output_base = resolve_external_output_base(args.out, root)
            destination = write_raw_union(
                [Path(value) for value in args.union_raw], output_base
            )
        except (OSError, ValueError) as error:
            print(f"ERROR: cannot write raw union: {error}", file=sys.stderr)
            return 2
        print(f"[lossless raw union written to {destination}]", file=sys.stderr)
        return 0

    if args.backend == "generic":
        if not args.cmd:
            print("ERROR: --backend generic requires --cmd", file=sys.stderr)
            return 2
        template = args.cmd
    else:
        template = proto["backends"].get(args.backend)
        if not template:
            print(f"ERROR: unknown backend {args.backend!r}; known: {list(proto['backends'])}", file=sys.stderr)
            return 2

    try:
        angles = select_angles(proto["angles"], args.angle)
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(assemble_prompt(proto, angles[0], root, args.inline_files, args.max_file_bytes))
        return 0

    if "{prompt_file}" not in template and not args.self_test_ok:
        print(
            "ERROR: executing backend templates must contain {prompt_file}; "
            "only --self-test-ok may use a canned no-prompt command",
            file=sys.stderr,
        )
        return 2

    try:
        prompts = {
            angle["id"]: assemble_prompt(
                proto, angle, root, args.inline_files, args.max_file_bytes
            )
            for angle in angles
        }
        first_snapshot = capture_review_snapshot(root, angles, prompts)
        verified_prompts = {
            angle["id"]: assemble_prompt(
                proto, angle, root, args.inline_files, args.max_file_bytes
            )
            for angle in angles
        }
        verified_snapshot = capture_review_snapshot(root, angles, verified_prompts)
    except (OSError, ValueError, UnicodeError) as error:
        print(f"ERROR: cannot freeze review target: {error}", file=sys.stderr)
        return 2
    if prompts != verified_prompts or first_snapshot != verified_snapshot:
        print("ERROR: review target changed while freezing", file=sys.stderr)
        return 2
    prompts = verified_prompts
    target_initial = verified_snapshot

    results: dict[str, dict] = {}
    raw_dump: dict[str, list] = {}
    diagnostics_dump: dict[str, list[dict]] = {}
    run_receipt = make_run_receipt(
        args.backend,
        args.run_id,
        template,
        proto,
        root,
        args.reviewers,
        args.quorum,
        args.jobs,
        angles=angles,
        prompts=prompts,
        inline_files=args.inline_files,
        max_file_bytes=args.max_file_bytes,
        timeout=args.timeout,
        target_initial=target_initial,
        self_test=args.self_test_ok,
    )
    try:
        output_base = resolve_external_output_base(args.out, root)
        output = prepare_run_output_dir(
            output_base, run_receipt["namespace"], root
        )
    except (OSError, ValueError) as error:
        print(f"ERROR: cannot create run output directory: {error}", file=sys.stderr)
        return 2

    try:
        for angle in angles:
            prompt = prompts[angle["id"]]
            print(f"==> angle {angle['id']}: {args.reviewers} reviewer pass(es) via `{args.backend}`…",
                  file=sys.stderr)

            def one_pass(_i):
                out, err, returncode, timed_out = run_backend(
                    template, prompt, args.timeout
                )
                stdout_text, decode_error = _decode_utf8(out)
                if decode_error is None:
                    assert stdout_text is not None
                    parsed, parse_error = extract_json_diagnostic(stdout_text)
                else:
                    parsed, parse_error = None, decode_error
                stdout_parse_error = parse_error
                if (
                    parsed is not None
                    and not args.self_test_ok
                    and _contains_reserved_self_test_fixture(parsed)
                ):
                    parsed = None
                    parse_error = (
                        "reserved self-test fixture is invalid outside "
                        "--self-test-ok"
                    )
                obj = parsed if returncode == 0 and not timed_out else None
                if returncode != 0 or timed_out:
                    parse_error = (
                        f"backend {'timed out' if timed_out else 'exited'} with "
                        f"status {returncode}; stdout schema was "
                        f"{'valid' if parsed is not None else 'invalid'}"
                    )
                if obj is None:
                    detail = parse_error or "unknown parse failure"
                    print(f"    reviewer {_i}: {detail}", file=sys.stderr)
                if err:
                    display_err = err.decode("utf-8", errors="replace").strip()[:200]
                    print(f"    reviewer {_i} stderr: {display_err}", file=sys.stderr)
                diagnostic = {
                    "reviewer_index": _i,
                    "returncode": returncode,
                    "timed_out": timed_out,
                    "parse_status": "validated" if obj is not None else "rejected",
                    "parse_error": parse_error,
                    "stdout_parse_error": stdout_parse_error,
                    "stdout": stream_receipt(out),
                    "stderr": stream_receipt(err),
                }
                return obj, diagnostic

            if args.jobs > 1:
                with ThreadPoolExecutor(max_workers=args.jobs) as ex:
                    passes = list(ex.map(one_pass, range(args.reviewers)))
            else:
                passes = [one_pass(i) for i in range(args.reviewers)]

            per = [answer for answer, _diagnostic in passes]
            diagnostics_dump[angle["id"]] = [
                diagnostic for _answer, diagnostic in passes
            ]
            annotated = annotate_reviews(angle["id"], per, run_receipt["namespace"])
            results[angle["id"]] = aggregate(annotated, args.quorum)
            raw_dump[angle["id"]] = annotated

        final_prompts = {
            angle["id"]: assemble_prompt(
                proto, angle, root, args.inline_files, args.max_file_bytes
            )
            for angle in angles
        }
        target_final = capture_review_snapshot(root, angles, final_prompts)
        target_drift = target_final != target_initial or final_prompts != prompts
        run_receipt["target_final"] = target_final
        run_receipt["target_drift"] = target_drift
        outcome = classify_run(
            diagnostics_dump,
            target_drift=target_drift,
            self_test=args.self_test_ok,
            results=results,
        )
        run_receipt["outcome"] = outcome
        purpose = SELF_TEST_PURPOSE if args.self_test_ok else DISCOVERY_PURPOSE

        # Invalid runs preserve their byte-faithful raw evidence, but never
        # publish or print success-shaped findings/report artifacts. Self-test
        # fixtures are likewise kept out of normal discovery artifacts.
        artifacts: dict[str, bytes] = {
            "raw.json": _json_bytes(
                raw_payload(
                    raw_dump,
                    diagnostics_dump,
                    run_receipt,
                    purpose=purpose,
                )
            )
        }
        report: str | None = None
        if outcome["status"] == "succeeded" and not args.self_test_ok:
            report = render_report(proto, results, args.reviewers, args.quorum)
            artifacts["findings.json"] = _json_bytes(results)
            artifacts["report.md"] = (report + "\n").encode("utf-8")

        for name, data in artifacts.items():
            safe_write_bytes(output, name, data)
        # Terminal marker is deliberately written last. A directory without it
        # is an incomplete publication, regardless of any preceding file.
        safe_write_bytes(
            output,
            "completion.json",
            _json_bytes(completion_payload(run_receipt, purpose, outcome, artifacts)),
        )
        output.verify()

        if outcome["status"] != "succeeded":
            if "self_test_empty" in outcome["failure_codes"]:
                print(
                    "SELF-TEST FAIL: orchestration produced 0 parsed findings.",
                    file=sys.stderr,
                )
            print(
                "ERROR: review run failed: "
                + ", ".join(outcome["failure_codes"])
                + f"; raw evidence and terminal receipt are in {output.path}",
                file=sys.stderr,
            )
            return 2

        if args.self_test_ok:
            print(
                "SELF-TEST OK: orchestration parsed/aggregated "
                f"{outcome['finding_count']} finding(s) end-to-end; "
                "receipt is self_test_only.",
                file=sys.stderr,
            )
        else:
            assert report is not None
            print(report)
            print(
                f"\n[completed in {output.path}; completion.json written last]",
                file=sys.stderr,
            )
        return 0
    except (OSError, ValueError, UnicodeError) as error:
        print(f"ERROR: review run failed closed: {error}", file=sys.stderr)
        return 2
    finally:
        output.close()


if __name__ == "__main__":
    sys.exit(main())
