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

# Range tokens that encode the DISPROVEN inventory. Matching is deliberately
# narrow: a bare mention of `0xE0E3` is legitimate (it is a real device-cert
# object), but these ranges only ever appear in the stale ceremony claim.
STALE_RANGE_RE = re.compile(r"0?xE0E[34]\s*\.\.=?\s*0?xE0E[78]", re.IGNORECASE)

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
}

SKIP_PREFIXES = (
    "docs/archive/",
    "docs/security/research-bundles/",
)


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


def iter_live_docs():
    for path in sorted(ROOT.rglob("*.md")):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith(SKIP_PREFIXES):
            continue
        if "/target/" in f"/{rel}" or rel.startswith("lib/"):
            continue
        yield rel, path


def check_docs(failures: list[str]) -> int:
    seen: set[str] = set()
    for rel, path in iter_live_docs():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not STALE_RANGE_RE.search(line):
                continue
            seen.add(rel)
            if rel not in ALLOWLIST:
                failures.append(
                    f"{rel}:{lineno}: stale OPTIGA ceremony range "
                    f"{STALE_RANGE_RE.search(line).group(0)!r} in a live doc.\n"
                    f"    {line.strip()}\n"
                    "    The real type-0x11 pool is {0xE0E8, 0xE0E9, 0xE0EF}; "
                    "0xE0E3 is a device cert and 0xE0E4..0xE0E7 hold no objects. "
                    "Executing that range is destructive and false-closing. "
                    "Correct the text, or add this file to ALLOWLIST in "
                    "scripts/check_optiga_oid_ceremony.py with a reason."
                )
    for rel, reason in ALLOWLIST.items():
        if rel not in seen:
            failures.append(
                f"{rel}: allowlisted for {reason!r} but no stale range token "
                "remains. Drop the stale entry so the allowlist stays exact."
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
