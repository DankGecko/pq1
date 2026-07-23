#!/usr/bin/env python3
"""Fail-closed comparison of a complete Charon/Aeneas regeneration.

The extract-* targets historically compared only the transformed `Funs.lean`.
That allowed a generated `Types.lean` or external-template interface to drift
while `make verify-extraction-regen` stayed green. This checker consumes one
fresh, clean Aeneas output directory and enforces:

* the exact expected raw `*.lean` filename set (no omitted/unexpected module);
* byte-for-byte equality for generated Funs/Types after the target's existing
  deterministic Funs transform;
* exact `rust_fun`/`rust_const`/`rust_type` interface equality between generated
  `*External_Template.lean` files and their deliberately hand-completed
  committed `*External.lean` counterparts.

FormatDecimal's generated `Types.lean` is intentionally deduplicated into the
canonical U256Mul Types module, so that one raw file is compared there.
"""
from __future__ import annotations

import collections
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path

VERIF_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[3]
REGISTRY = VERIF_DIR / "extraction_registry.json"
ATTR_RE = re.compile(
    r'(?m)^[ \t]*@\[\s*(rust_(?:fun|const|type))\s+"((?:\\.|[^"\\])*)"\s*\]',
    re.DOTALL,
)
IMPORT_RE = re.compile(r"(?m)^[ \t]*import[ \t]+(Extracted(?:\.[A-Za-z0-9_']+)+)[ \t]*$")
DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:axiom|structure|inductive|opaque|abbrev|"
    r"(?:noncomputable[ \t]+)?def)"
    r"[ \t\r\n]+([A-Za-z0-9_'.]+)"
)


def external_attributes(text: str) -> collections.Counter[tuple[str, str]]:
    return collections.Counter(ATTR_RE.findall(text))


def declaration_names(text: str) -> collections.Counter[str]:
    return collections.Counter(DECL_RE.findall(text))


def extracted_import_path(module: str) -> Path:
    return VERIF_DIR / "extracted" / (module.replace(".", "/") + ".lean")


def imported_text_closure(start: Path) -> list[str]:
    """Read a committed external module and its recursive `Extracted.*` imports."""
    pending = [start]
    seen: set[Path] = set()
    texts: list[str] = []
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        text = path.read_text(encoding="utf-8")
        texts.append(text)
        for module in IMPORT_RE.findall(text):
            imported = extracted_import_path(module)
            if imported.is_file():
                pending.append(imported)
    return texts


def compare_exact(label: str, committed: Path, regenerated: Path) -> list[str]:
    if not committed.is_file():
        return [f"{label}: committed file missing: {committed}"]
    if not regenerated.is_file():
        return [f"{label}: regenerated file missing: {regenerated}"]
    if committed.read_bytes() != regenerated.read_bytes():
        try:
            committed_label = committed.relative_to(REPO_ROOT)
        except ValueError:
            committed_label = committed
        return [
            f"{label}: regenerated content differs: "
            f"{committed_label} vs {regenerated}"
        ]
    return []


def raw_output_errors(
    output_dir: Path, pins: dict[str, str], ignored: set[str]
) -> list[str]:
    actual = {
        path.name for path in output_dir.glob("*.lean") if path.name not in ignored
    }
    expected = set(pins)
    errors = []
    if actual != expected:
        errors.append(
            "raw generated module inventory drift; "
            f"missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )
    for name in sorted(actual & expected):
        digest = hashlib.sha256((output_dir / name).read_bytes()).hexdigest()
        if digest != pins[name]:
            errors.append(
                f"raw generated file {name} hash drift; "
                f"expected {pins[name]}, got {digest}"
            )
    return errors


def compare_external_interface(
    label: str, committed: Path, template: Path
) -> list[str]:
    if not committed.is_file() or not template.is_file():
        return [
            f"{label}: external interface file missing "
            f"(committed={committed.is_file()}, template={template.is_file()})"
        ]
    template_text = template.read_text(encoding="utf-8")
    closure = imported_text_closure(committed)
    expected_attrs = external_attributes(template_text)
    actual_attrs: collections.Counter[tuple[str, str]] = collections.Counter()
    actual_decls: collections.Counter[str] = collections.Counter()
    for text in closure:
        actual_attrs.update(external_attributes(text))
        actual_decls.update(declaration_names(text))
    expected_decls = declaration_names(template_text)
    missing_attrs = sorted((expected_attrs - actual_attrs).elements())
    missing_decls = sorted((expected_decls - actual_decls).elements())
    if missing_attrs or missing_decls:
        return [
            f"{label}: hand-completed/imported external interface does not cover "
            f"the regenerated template; missing_attributes={missing_attrs}, "
            f"missing_declarations={missing_decls}"
        ]
    return []


def check_target(target: str, output_dir: Path, transformed_funs: Path | None) -> list[str]:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    entry = next((e for e in registry["entries"] if e["target"] == target), None)
    if entry is None:
        return [f"unknown extraction target {target!r}"]
    if not output_dir.is_dir():
        return [f"Aeneas output directory missing: {output_dir}"]

    errors: list[str] = []
    for rel in entry["generated_lean"]:
        committed = REPO_ROOT / rel
        name = committed.name
        if name == "FunsExternal.lean":
            raw_name = "FunsExternal_Template.lean"
            errors.extend(
                compare_external_interface(
                    f"{target} FunsExternal",
                    committed,
                    output_dir / raw_name,
                )
            )
        elif name == "TypesExternal.lean":
            raw_name = "TypesExternal_Template.lean"
            errors.extend(
                compare_external_interface(
                    f"{target} TypesExternal",
                    committed,
                    output_dir / raw_name,
                )
            )
        elif name == "Funs.lean":
            candidate = transformed_funs or (output_dir / name)
            errors.extend(compare_exact(f"{target} Funs", committed, candidate))
        else:
            fixed_candidate = output_dir / name.replace(".lean", ".fixed.lean")
            candidate = fixed_candidate if fixed_candidate.is_file() else output_dir / name
            errors.extend(
                compare_exact(f"{target} {name}", committed, candidate)
            )

    # FormatDecimal deliberately shares the byte-identical generated U256 type
    # with U256Mul instead of committing a duplicate declaration.
    if target == "extract-format-decimal":
        errors.extend(
            compare_exact(
                f"{target} deduplicated Types",
                VERIF_DIR / "extracted/Extracted/U256Mul/Types.lean",
                output_dir / "Types.lean",
            )
        )

    ignored = {
        path.name for path in output_dir.glob("*.fixed.lean")
    }
    if transformed_funs is not None:
        ignored.add(transformed_funs.name)
    errors.extend(
        f"{target}: {message}"
        for message in raw_output_errors(
            output_dir, entry["raw_generated_sha256"], ignored
        )
    )
    return errors


def self_test() -> int:
    ok = True
    with tempfile.TemporaryDirectory(prefix="pq-extraction-output-selftest-") as tmp:
        root = Path(tmp)
        committed = root / "committed.lean"
        regenerated = root / "regenerated.lean"
        committed.write_text("def value := 1\n", encoding="utf-8")
        regenerated.write_text("def value := 1\n", encoding="utf-8")
        if compare_exact("clean", committed, regenerated):
            print("FAIL: exact generated-file clean control was rejected")
            ok = False
        regenerated.write_text("def value := 2\n", encoding="utf-8")
        if compare_exact("mutant", committed, regenerated):
            print("  ok: generated Types/content drift is CAUGHT")
        else:
            print("FAIL: generated Types/content drift escaped")
            ok = False

        template = root / "FunsExternal_Template.lean"
        external = root / "FunsExternal.lean"
        template.write_text(
            '@[rust_const "crate::LIMIT"]\naxiom crate.LIMIT : Nat\n',
            encoding="utf-8",
        )
        external.write_text(
            '@[rust_const "crate::LIMIT"]\ndef crate.LIMIT : Nat := 10\n',
            encoding="utf-8",
        )
        if compare_external_interface("clean external", external, template):
            print("FAIL: matching hand-completed external interface was rejected")
            ok = False
        external.write_text("def crate.LIMIT : Nat := 10\n", encoding="utf-8")
        if compare_external_interface("mutant external", external, template):
            print("  ok: dropped generated external-template identity is CAUGHT")
        else:
            print("FAIL: dropped external-template identity escaped")
            ok = False

        raw = root / "raw"
        raw.mkdir()
        (raw / "Funs.lean").write_text("def f := 1\n", encoding="utf-8")
        (raw / "Types.lean").write_text("def T := Nat\n", encoding="utf-8")
        pins = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in raw.glob("*.lean")
        }
        if raw_output_errors(raw, pins, set()):
            print("FAIL: clean raw-output hash/inventory control was rejected")
            ok = False
        (raw / "Unexpected.lean").write_text("def decoy := 0\n", encoding="utf-8")
        if raw_output_errors(raw, pins, set()):
            print("  ok: unexpected generated module inventory is CAUGHT")
        else:
            print("FAIL: unexpected generated module escaped")
            ok = False
        (raw / "Unexpected.lean").unlink()
        (raw / "Types.lean").unlink()
        if raw_output_errors(raw, pins, set()):
            print("  ok: missing generated Types module is CAUGHT")
        else:
            print("FAIL: missing generated Types module escaped")
            ok = False
        (raw / "Types.lean").write_text("def T := Bool\n", encoding="utf-8")
        if raw_output_errors(raw, pins, set()):
            print("  ok: raw generated Types/template signature drift is CAUGHT")
        else:
            print("FAIL: raw generated content/hash drift escaped")
            ok = False
    print("check_extraction_regen_output --self-test PASS" if ok else
          "check_extraction_regen_output --self-test FAILED")
    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if len(args) not in (2, 3):
        print(
            "usage: check_extraction_regen_output.py "
            "<extract-target> <aeneas-output-dir> [transformed-Funs.lean]",
            file=sys.stderr,
        )
        return 2
    target = args[0]
    output_dir = Path(args[1]).resolve()
    transformed = Path(args[2]).resolve() if len(args) == 3 else None
    errors = check_target(target, output_dir, transformed)
    if errors:
        print(f"FAIL: incomplete/drifted Aeneas output for {target}:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {target} complete Aeneas output matches committed generated surface")
    return 0


if __name__ == "__main__":
    sys.exit(main())
