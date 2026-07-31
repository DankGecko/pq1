#!/usr/bin/env python3
"""Refuse invisible/direction-controlling Unicode in tracked text files.

WHY THIS GATE EXISTS
--------------------
Two distinct attacks share one mechanism: a codepoint that renders as nothing,
or that reorders what follows it, so the bytes a reviewer sees are not the bytes
the machine consumes.

1.  **AI-instruction poisoning.** `CLAUDE.md`, `AGENTS.md`, `.claude/` and
    `.cursorrules` are executed-as-instructions by every coding agent that
    touches this repo. The May-2026 TrapDoor campaign shipped poisoned
    `CLAUDE.md`/`.cursorrules` through ordinary pull requests to major projects,
    using zero-width runs to hide the payload from human diff review. The
    payload is not code, so it survives review that only reads `.rs`/`.sol`.

2.  **Trojan Source (CVE-2021-42574).** Bidirectional overrides (U+202A..U+202E,
    U+2066..U+2069) make source display in an order different from how it
    compiles — the canonical demonstration is a comment that visually contains
    the closing of a security check while the compiler sees it inside a string.

Both are invisible to `git diff`, to code review, and to every other gate in
this repo. This one costs milliseconds and closes the class.

WHAT IS FORBIDDEN
-----------------
  U+200B..U+200F  zero-width space/joiner/non-joiner, LRM/RLM
  U+202A..U+202E  bidi embedding + OVERRIDE (Trojan Source)
  U+2066..U+2069  bidi isolates (Trojan Source, the isolate variant)
  U+FEFF          BOM/zero-width no-break space appearing mid-file

DELIBERATELY NOT FORBIDDEN: ordinary non-ASCII. This repo's own docs use arrows,
section signs, box drawing and em dashes throughout, and CLAUDE.md/AGENTS.md are
full of them. A "reject non-ASCII" rule would be red on day one and disabled by
the end of the week, leaving a registered-but-neutered gate that
`scripts/gate_enforcement.json` would then vouch for. Narrow beats disabled.

Separately: strings that reach the TRUSTED DISPLAY are held to a much stricter
rule — printable ASCII only, enforced in `tx/src/wire.rs` and
`pqsigner-erc7730/src/ir.rs`, because a homoglyph on the confirm screen is a
signing decision. That is a different gate for a different surface; this one is
about what humans and agents read in the repo.

BASELINE (2026-07-31): 3840 tracked text files, and after two source fixes in
the same commit, ZERO hits — so this gate has NO allowlist. That is deliberate.
An allowlist here is a place to hide exactly the payload the gate exists to
find. The two pre-existing hits were fixed rather than exempted:
  * `contracts/verification/docs/AXIOM_STATUS.json` — a stray U+200B pasted
    inside a quoted paper phrase; removed.
  * `secure/src/ui_under_test/pure_tests.rs` — a REAL zero-width joiner used as
    homoglyph test data (`"U<ZWJ>SDC"`); rewritten as the escape `\\u{200d}`, so
    the test asserts the same thing while the file holds no invisible byte.
If you need such a character, write it as an escape. If you think you need a
literal, you are writing the thing this gate is looking for.

USAGE
    python3 scripts/check_invisible_unicode.py            # scan tracked files
    python3 scripts/check_invisible_unicode.py --self-test  # prove it can fail
Exit 0 clean, 1 on a finding, 2 on a self-test failure.
"""

from __future__ import annotations

import subprocess
import sys
import unicodedata
from pathlib import Path

FORBIDDEN: dict[int, str] = {}
for _cp in range(0x200B, 0x2010):
    FORBIDDEN[_cp] = "zero-width / directional mark"
for _cp in range(0x202A, 0x202F):
    FORBIDDEN[_cp] = "bidi embedding/override (Trojan Source)"
for _cp in range(0x2066, 0x206A):
    FORBIDDEN[_cp] = "bidi isolate (Trojan Source)"
FORBIDDEN[0xFEFF] = "BOM / zero-width no-break space"

# Vendored trees we do not author. Their contents are pinned by hash elsewhere
# (foundry.lock, lake-manifest), and a finding there is not ours to fix.
SKIP_PREFIXES = (
    "contracts/smart-wallet/lib/",
    "contracts/verification/extracted/.lake/",
    "docs/SE050/",
)


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, text=True, check=True
    ).stdout
    return [f for f in out.split("\0") if f]


def scan_text(name: str, text: str) -> list[tuple[int, int, int, str]]:
    """Return (line, col, codepoint, why) for each forbidden character."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for col, ch in enumerate(line, start=1):
            why = FORBIDDEN.get(ord(ch))
            if why is not None:
                findings.append((lineno, col, ord(ch), why))
    return findings


def scan_repo() -> int:
    findings = 0
    scanned = 0
    for f in tracked_files():
        if f.startswith(SKIP_PREFIXES):
            continue
        p = Path(f)
        try:
            raw = p.read_bytes()
        except (OSError, IsADirectoryError):
            continue
        if b"\0" in raw[:8192]:  # binary
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        for lineno, col, cp, why in scan_text(f, text):
            name = unicodedata.name(chr(cp), "<unnamed>")
            print(
                f"{f}:{lineno}:{col}: forbidden invisible codepoint "
                f"U+{cp:04X} ({name}) — {why}"
            )
            findings += 1
    if findings:
        print(
            f"\nFAIL: {findings} invisible/bidi codepoint(s) in {scanned} tracked "
            f"text files.\nThese are invisible to `git diff` and to code review. "
            f"Write the character as an\nescape (e.g. \\u{{200d}}) if it is "
            f"genuinely test data; do not add an allowlist.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: no invisible/bidi codepoints in {scanned} tracked text files.")
    return 0


def self_test() -> int:
    """Two-sided control: the scanner must FIRE on a planted payload and stay
    silent on the benign twin. A gate nobody has watched fail is a gate nobody
    knows works."""
    # NOTE: every payload is built from ESCAPES, never literals. This file is
    # itself a tracked text file, so a literal here would make the scanner flag
    # its own self-test — the exact mistake the docstring tells everyone else
    # not to make. Caught by running the gate on the working tree before
    # committing it.
    ZWSP, ZWJ, RLO, PDF = "\u200b", "\u200d", "\u202e", "\u202c"
    LRI, PDI, BOM = "\u2066", "\u2069", "\ufeff"
    cases = [
        ("zero-width space", f"hello{ZWSP}world", 1),
        ("zero-width joiner (homoglyph splice)", f"U{ZWJ}SDC", 1),
        ("bidi override (Trojan Source)", f"if (admin) {{{RLO}}} // {PDF}", 2),
        ("bidi isolate", f"x{LRI}y{PDI}z", 2),
        ("BOM mid-file", f"a{BOM}b", 1),
        ("benign non-ASCII (must NOT fire)", "\u2192 \u00a7 \u2014 \u2713 caf\u00e9", 0),
        ("escaped form in source (must NOT fire)", r'"U\u{200d}SDC"', 0),
        ("plain ASCII (must NOT fire)", "the quick brown fox", 0),
    ]
    failures = 0
    for name, payload, expected in cases:
        got = len(scan_text("<self-test>", payload))
        ok = got == expected
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: expected {expected}, got {got}")
        if not ok:
            failures += 1
    if failures:
        print(f"\nSELF-TEST FAILED ({failures} case(s))", file=sys.stderr)
        return 2
    print("self-test OK (fires on all 5 payload classes, silent on all 3 benign)")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(scan_repo())
