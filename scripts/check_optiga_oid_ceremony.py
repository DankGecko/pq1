#!/usr/bin/env python3
"""Fail closed if a live doc carries a stale OPTIGA S-2 ceremony instruction.

OPTIGA `LcsO` transitions are IRREVERSIBLE. A document that tells an operator to
install a trust anchor at `0xE0E3`, or to neutralize "the TA pool
`0xE0E4..0xE0E8`", is not a harmless no-op:

* `0xE0E3` is a device certificate (`DataType=0x12`), already full -- the chip
  refuses to *retype* it, so it never becomes an anchor;
* `0xE0E4..0xE0E7` hold no objects at all (GetDataObject errors, SRM Table 68);
* the stale range's only real member, `0xE0E8`, is ONE OF THREE type-`0x11`
  anchors.

So a fill-and-lock pass over that range junk-overwrites the `0xE0E3` device
certificate, aborts at the absent `0xE0E4`, never reaches `0xE0E9`/`0xE0EF`, and
reports done -- destructive AND false-closing. See the F8 finding
(`docs/security/adversarial-review/findings/full-project-sweep-2026-07-14.md`)
and the CORRECTION 2026-07-26 block in
`docs/provisioning/first-boot-provisioning.md`.

This gate exists because that conflict survived for months in four documents at
once: the responsibility split is deliberately MIRRORED across several files,
and only some copies were corrected. Nothing mechanically compared docs to code.

What this checks:

1. the authoritative pool in `secure/src/optiga/mod.rs` is exactly
   `{0xE0E8, 0xE0E9, 0xE0EF}` (if the code inventory ever changes, this gate
   must be re-reviewed rather than silently tracking it);
2. every occurrence of a stale range token in a LIVE doc appears in the
   allowlist below, each with a reason. A new occurrence in a new file fails,
   forcing a reviewable decision instead of silent drift.

Archived history (`docs/archive/`) and verbatim research inputs
(`docs/security/research-bundles/`) are out of scope: this repo deliberately
preserves its honest history.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The authoritative type-0x11 Protected-Update anchor pool, pinned in code and
# already asserted by
# `optiga_under_test::pure_tests::negative_ta_pool_lockdown_is_exact_and_emits_no_apdu`.
EXPECTED_POOL = ("0xE0E8", "0xE0E9", "0xE0EF")
POOL_RE = re.compile(
    r"const\s+TA_POOL:\s*\[u16;\s*3\]\s*=\s*\[\s*"
    r"(0x[0-9A-Fa-f]{4})\s*,\s*(0x[0-9A-Fa-f]{4})\s*,\s*(0x[0-9A-Fa-f]{4})\s*\]"
)

# Two shapes encode the DISPROVEN inventory. A bare mention of `0xE0E3` is
# legitimate (it is a real device-cert object), so matching stays narrow:
#
#   A. the range token -- `0xE0E4..0xE0E8` and friends. The `0x` prefix is
#      OPTIONAL: the bare `E0E3..E0E8` form already occurs in-tree, and an
#      earlier revision of this gate missed it, so its PASS was weaker than it
#      read. Do not re-tighten this without a negative control.
#   B. the anchor-at-E0E3 claim -- "trust-anchor cert at 0xE0E3", "TA cert at
#      OID 0xE0E3". This is the shape that survives with no range token at all,
#      which is how `tools/optiga_reset/gen_reset_manifests.py` stayed stale
#      after every .md was corrected.
STALE_PATTERNS = (
    (
        "range",
        re.compile(r"(?:0?x)?E0E[34]\s*\.\.=?\s*(?:0?x)?E0E[78]", re.IGNORECASE),
    ),
    (
        "anchor-at-E0E3",
        re.compile(
            r"(?:trust[\s-]?anchor|\bTA\b)\s+cert\w*\s+(?:at|to)\s+"
            r"(?:OID\s+)?(?:0?x)?E0E3",
            re.IGNORECASE,
        ),
    ),
)


def first_stale_match(line: str):
    """Return (kind, matched_text) for the first stale shape on `line`, else None."""
    for kind, pattern in STALE_PATTERNS:
        found = pattern.search(line)
        if found:
            return kind, found.group(0)
    return None

# Every LIVE-doc occurrence must be listed here with the reason it is allowed.
# Correction blocks necessarily quote the stale text in order to refute it.
ALLOWLIST: dict[str, str] = {
    "docs/provisioning/first-boot-provisioning.md":
        "CORRECTION 2026-07-26 block quotes the stale text to refute it",
    "docs/provisioning/first-boot-requirements.md":
        "mirror doc points at the canonical correction, naming the stale range",
    "docs/provisioning/factory-provisioning.md":
        "operator manual carries the explicit NOT-this qualifier",
    "docs/security/security-review-2026-05.md":
        "dated audit record: C-5 premise preserved verbatim under a correction "
        "banner; steps 1-2 struck as SUPERSEDED",
    "docs/security/adversarial-review/findings/full-project-sweep-2026-07-14.md":
        "F8 finding: the record that established the range is destructive",
    "secure/src/optiga/mod.rs":
        "lockdown_ta_pool docstring: states the CORRECT inventory, naming "
        "0xE0E4..=0xE0E7 as non-members. This file is the source of truth the "
        "gate pins against",
    "tools/optiga_reset/gen_reset_manifests.py":
        "retired generator: RETIRED 2026-07-26 banner preserves the disproven "
        "premise verbatim under a 'Historical description:' lead",
    "docs/secure-elements/OPTIGATRUSTM/commands-and-oids.md":
        "OID reference: inventory note names 0xE0E4..0xE0E7 as holding no "
        "objects, after the anchor table was found short by 0xE0E9",
}

# This gate necessarily spells out every stale shape it hunts for.
SELF = Path(__file__).resolve().relative_to(ROOT).as_posix()

SKIP_PREFIXES = (
    "docs/archive/",
    "docs/security/research-bundles/",
)

SCAN_SUFFIXES = {".md", ".py", ".rs", ".toml", ".sh"}
SCAN_NAMES = {"Makefile"}


def check_code_inventory(failures: list[str]) -> None:
    src = ROOT / "secure" / "src" / "optiga" / "mod.rs"
    match = POOL_RE.search(src.read_text(encoding="utf-8"))
    if match is None:
        failures.append(
            f"{src.relative_to(ROOT)}: could not find `const TA_POOL: [u16; 3]`. "
            "The authoritative anchor inventory moved or was renamed; re-review "
            "this gate against the new source of truth."
        )
        return
    found = tuple(g.upper().replace("0X", "0x") for g in match.groups())
    if found != EXPECTED_POOL:
        failures.append(
            f"{src.relative_to(ROOT)}: TA_POOL is {found}, expected "
            f"{EXPECTED_POOL}. S-2's anchor inventory changed -- update the "
            "provisioning docs and this gate together, deliberately."
        )


def iter_live_files():
    """Live docs AND the tooling/source that can carry the same claim.

    `.md`-only scanning is how `tools/optiga_reset/gen_reset_manifests.py` kept
    asserting the disproven belief as operative fact after every document was
    corrected. Provenance references under the unconditional compile fences are
    fine -- they are allowlisted individually, not skipped wholesale.
    """
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in SCAN_SUFFIXES and path.name not in SCAN_NAMES:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel == SELF or rel.startswith(SKIP_PREFIXES):
            continue
        if "/target/" in f"/{rel}" or rel.startswith(("lib/", "target/")):
            continue
        yield rel, path


def check_docs(failures: list[str]) -> int:
    seen: set[str] = set()
    for rel, path in iter_live_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            hit = first_stale_match(line)
            if hit is None:
                continue
            kind, matched = hit
            seen.add(rel)
            if rel not in ALLOWLIST:
                failures.append(
                    f"{rel}:{lineno}: stale OPTIGA ceremony claim "
                    f"({kind}) {matched!r} in a live file.\n"
                    f"    {line.strip()}\n"
                    "    The candidate type-0x11 pool is "
                    "{0xE0E8, 0xE0E9, 0xE0EF}; 0xE0E3 is a device cert the chip "
                    "will not retype, and 0xE0E4..0xE0E7 hold no objects. A "
                    "fill-and-lock pass over that range junk-overwrites the "
                    "0xE0E3 device cert, aborts at the absent 0xE0E4, and never "
                    "reaches 0xE0E9/0xE0EF -- destructive AND false-closing.\n"
                    "    Correct the text, or add this file to ALLOWLIST in "
                    "scripts/check_optiga_oid_ceremony.py with a reason."
                )
    for rel, reason in ALLOWLIST.items():
        if rel not in seen:
            failures.append(
                f"{rel}: allowlisted for {reason!r} but no stale token remains. "
                "Drop the entry so the allowlist stays exact (this is a prune, "
                "not a breakage)."
            )
    return len(seen)


def main() -> int:
    failures: list[str] = []
    check_code_inventory(failures)
    count = check_docs(failures)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print(
        "optiga-oid-ceremony: PASS "
        f"(TA_POOL pinned {{{', '.join(EXPECTED_POOL)}}}; "
        f"{count} allowlisted correction/history references, no live stale instruction)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
