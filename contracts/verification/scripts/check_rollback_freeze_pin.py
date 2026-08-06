#!/usr/bin/env python3
"""
check_rollback_freeze_pin.py — byte-pin for the frozen Draft 1.1 + Draft 1.2
rollback/lock architecture pair.

`docs/security/fw-rollback-freeze-receipt-2026-07-26.md` records a composite
freeze identity for two documents that are reviewed at an EXACT DIGEST. Its
owner ratification (2026-07-26, condition 3) says:

    "Any byte change to either draft document reopens the gate."

That condition had no enforcement. On 2026-07-31 commit `fb66a1e5` renamed one
token (`HW-CONFIRM-PUTKEY-KCV-RESP` -> `HW-ASSUME-PUTKEY-KCV-RESP`) inside
non-normative prose in Draft 1.2, silently reopening a ratified gate; it went
unnoticed for six days and was found only by hand-hashing during an unrelated
review. THIS SCRIPT closes that hole.

## What it checks

The receipt's "## Frozen pair" table is the SINGLE SOURCE OF TRUTH: each row
names a path and its pinned SHA-256. This script re-reads that table and
recomputes each file's digest. Any drift fails.

Because the expectation lives in the receipt rather than in this script, the
gate and the receipt cannot disagree, and RE-PINNING IS A DELIBERATE, REVIEWABLE
EDIT TO THE RECEIPT rather than an invisible side effect of editing a draft.

## Fail-safe behaviour

The table is anchored, not merely regex-scraped, and the scanner is
FENCE-AWARE with CommonMark opening AND closing rules (the fence opener may
be indented at most three spaces — deeper indentation is an indented code
block, not a fence — and the closing run must match the opener's character,
be at least as long, and carry only ASCII spaces/tabs), so headings, rows,
or markers inside ``` / ~~~ code blocks are treated as documentation, never
as the live pin. Container-NESTED fences (inside blockquotes or lists) are
refused outright, as is any HTML-tag-shaped line outside a fence: matching
a renderer across CommonMark's HTML block types, inline HTML, and container
state is unbounded, so those shapes fail closed and the parser always sees
exactly what a renderer shows. The receipt is LF-only: any CR byte fails at
read (a bare CR could hide renderer-visible structure mid-parser-line, and
--write's newline="" I/O can never rewrite line endings behind a
digest-cell edit). Lines are split on LF only (str.splitlines() would
invent phantom lines at U+2028/VT/FF/NEL). The script asserts it found
EXACTLY ONE full-line `## Frozen pair` heading (0-3 leading spaces
permitted) outside fences, and NO other level-2 heading carrying the
reserved prefix in any form — spaced, tabbed, colonned, parenthesised,
hyphenated, pluralised, or indented look-alikes all fail. It then parses
the section's table STRUCTURALLY: the first `|` line must be the exact
canonical `| document | path | SHA-256 |` header, followed IMMEDIATELY by
exactly one three-dash-cell separator row (renamed cells, missing/
duplicated separators, and empty-cell look-alikes like `| | | |` fail), and
the data rows must be well-formed 64-hex rows CONTIGUOUS with the separator
— the first non-row line ends the table, and any later table-looking
content fails; any pipe-bearing line not starting with `|` also fails (GFM
renders rows without a leading pipe too) — a malformed, hidden, duplicated,
or additional row fails instead of being silently ignored. It then requires
exactly EXPECTED_ROWS rows, that the parsed path set
equals the hardcoded EXPECTED_PATHS (a receipt edit re-pointing a row at any
other file — or duplicating one draft's row so the other goes unchecked —
fails HERE, not in review), and that every named path exists. A re-layout of
the receipt therefore fails HERE rather than silently pinning nothing (the
vacuity failure mode this repo cares about: a green gate that checks zero
files). `--write` rewrites ONLY the drifted rows' digest CELLS by exact
capture span, so narrative occurrences of the same digest and the historical
approved/superseded records elsewhere in the receipt can never be silently
rewritten to falsely attribute approval to new bytes. Section termination
is ATX level-1/2 only, and any bare =/- underline line inside the section
is REFUSED rather than classified (this receipt uses ATX headings only;
distinguishing Setext underlines from thematic breaks needs full block
parsing, which is unbounded), and fence closers accept only ASCII
spaces/tabs after the run (Python's str.strip() eats \u00a0 where
CommonMark does not). Headings nested in blockquotes or lists render as
real headings in CommonMark, so container-nested reserved-prefix variants
fail the anchor check too. Beyond the table, the
script pins the ATTRIBUTION record: if the live pins differ from the
hardcoded APPROVED_PAIR (the digests the 2026-07-26 dual APPROVE actually
covered), the Frozen pair section must carry exactly one VISIBLE
'> **GATE STATE: REOPENED' blockquote marker — a literal inside a fenced
exhibit or a self-referential mention elsewhere in the receipt does not
count — or the gate fails, because a green build must never assert
approval over unreviewed bytes. All receipt I/O uses newline="" so a CRLF
receipt fails closed at parse and `--write` can never rewrite every line
ending behind a digest-cell edit.

## After a LEGITIMATE draft change

Re-pinning is a governance act, not a chore. `--write` updates the table, but
the gate is only half the story: per the ratification, changing the bytes
REOPENS the review gate, and re-closing Milestone 0 needs either both
exact-digest review legs re-run plus owner ratification, or a de-minimis owner
acceptance naming the delta. `--write` prints that reminder and is deliberately
not wired into any build target.

Exit 0 = every pinned file matches; non-zero = drift (or a broken anchor).
"""
from __future__ import annotations

import argparse
import hashlib
import html
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
RECEIPT = REPO / "docs" / "security" / "fw-rollback-freeze-receipt-2026-07-26.md"

HEADING = "## Frozen pair"
# The receipt pins exactly two documents. If this number ever legitimately
# changes, change it here in the same commit as the receipt — a mismatch is a
# hard failure, never a silent skip.
EXPECTED_ROWS = 2
# The identity of the pinned set is as load-bearing as the row count: without
# it, a receipt edit could point both rows at any other pair of files (or list
# one draft twice) and this gate would pass while a frozen draft drifts.
EXPECTED_PATHS = frozenset(
    {
        "docs/security/a-b-firmware-rollback-architecture.md",
        "docs/security/fw-rollback-draft12-candidate-2026-07-21.md",
    }
)

# | label | `path` | `sha256` |
# All structural whitespace is ASCII space/tab ONLY: Python's \s matches
# NBSP and friends where CommonMark/GFM does not, so a "separator" or
# "row" padded with NBSP would parse here while a renderer shows prose.
# The label cell is captured too: it must carry the canonical draft label
# for its path (a swap or a blank cell misattributes the pin to readers).
ROW = re.compile(
    r"^\|[ \t]*([^|]*?)[ \t]*\|[ \t]*`([^`]+)`[ \t]*\|[ \t]*`([0-9a-fA-F]{64})`[ \t]*\|[ \t]*$"
)
EXPECTED_LABEL = {
    # EXACT full labels, annotation included: a re-pin updates these in the
    # same commit as the receipt's rows, so a swapped, blank, contradictory,
    # or free-annotated label fails instead of misattributing the pin.
    "docs/security/a-b-firmware-rollback-architecture.md": "Draft 1.1 (post-errata-4, unchanged)",
    "docs/security/fw-rollback-draft12-candidate-2026-07-21.md": "Draft 1.2 (post-BLOCKER-1, post-`fb66a1e5`)",
}

# The anchor must be a full-line COLUMN-ZERO level-2 heading, found
# EXACTLY ONCE outside fenced code blocks. No indentation is permitted:
# an indented '## Frozen pair' after a list item is a list-NESTED H2 in
# CommonMark, and tracking list containers is unbounded — the canonical
# anchor (and every section boundary below) is column-zero only, and
# indented H1/H2 forms are refused. A substring check would accept a
# renamed heading that merely contains the anchor text ("## Frozen pair
# (old)"), a duplicated anchor is a re-layout this gate must fail on, and
# a heading inside a ``` / ~~~ fence is documentation, not the live pin.
# Any OTHER level-2 heading carrying the reserved literal prefix —
# whether spaced, tabbed, colonned, parenthesised, hyphenated,
# pluralised, indented, entity-encoded, code-spanned, emphasised, or
# CONTAINER-NESTED inside a blockquote or list — is rejected too, so a
# look-alike section cannot coexist with the live one.
ANCHOR = re.compile(r"^##[ \t]+Frozen pair[ \t]*$")
ANCHOR_PREFIX = re.compile(r"^ {0,3}##[ \t]+Frozen pair")
CONTAINER_ANCHOR = re.compile(
    r"^ {0,3}(?:(?:>[ \t]*)+|(?:[-+*]|\d+[.)])[ \t]+)+##[ \t]+Frozen pair"
)
# A 4-space-indented or ANY tab-carrying indentation (including mixed
# space+tab in any order) before a reserved-prefix line is a list
# CONTINUATION heading in CommonMark after a list item (and indented code
# elsewhere) — never the live anchor, always a look-alike this gate
# refuses.
INDENTED_ANCHOR = re.compile(r"^(?:[ \t]*\t| {4,})[ \t]*##[ \t]+Frozen pair")

# The table header is the exact canonical three-cell row, followed by
# exactly one separator row ON THE IMMEDIATELY NEXT VISIBLE LINE (no prose
# or blank line between). The separator must have exactly THREE dash-bearing
# cells matching the header's columns, each carrying AT LEAST THREE hyphens
# as GFM requires ("|-|-|-|" is not a rendered table): renamed cells (a
# substring trap like "not-a-path" still CONTAINS "path"), short cells,
# one/two/four-cell delimiters, a missing or duplicated separator, and
# empty-cell look-alikes without dashes ("| | | |") all fail the parse
# instead of passing as a non-table receipt.
HEADER = re.compile(r"^\|[ \t]*document[ \t]*\|[ \t]*path[ \t]*\|[ \t]*SHA-256[ \t]*\|[ \t]*$")
SEPARATOR = re.compile(r"^\|[ \t]*:?-{3,}:?[ \t]*\|[ \t]*:?-{3,}:?[ \t]*\|[ \t]*:?-{3,}:?[ \t]*\|[ \t]*$")

# A level-1 or level-2 ATX heading AT COLUMN ZERO ends the Frozen pair
# section for a renderer (one-or-more spaces/tabs after the marks, or bare
# marks). An INDENTED H1/H2 line inside the scanned section is refused:
# after a list item it is a list-nested heading in CommonMark, and
# tracking list containers is unbounded. Level-3+ headings stay
# in-section.
SECTION_END_ATX = re.compile(r"^#{1,2}(?:[ \t]|$)")
INDENTED_HEADING = re.compile(r"^ {1,3}#{1,2}(?:[ \t]|$)")

# A bare line of = or - characters anywhere inside the scanned section is
# REFUSED, not classified. Distinguishing a Setext underline from a
# thematic break requires full block parsing (paragraphs, list items,
# indented code, link-reference definitions, containers), which is
# unbounded — this receipt uses ATX headings only, so any underline form
# fails closed instead of risking a false section boundary.
SETEXT_OR_HR = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")

# The authoritative reopening notice, in its blockquote form, must appear
# exactly once among the VISIBLE lines INSIDE the Frozen pair section when
# the live pins differ from APPROVED_PAIR. A raw-text search is defeated
# twice over: a literal inside a fenced exhibit satisfies it (fence-filtered
# lines never reach this check), and a self-referential narrative mention
# elsewhere in the receipt satisfies it after the authoritative blockquote
# is deleted (this pattern anchors the blockquote form, in-section).
REOPENED_MARKER = re.compile(r"^> \*\*GATE STATE: REOPENED")

# The pair the 2026-07-26 dual APPROVE + owner ratification actually covered.
# If the live table names anything else, the receipt MUST carry a literal
# "GATE STATE: REOPENED" note recording that the approval does not carry —
# otherwise a green build would assert an approval over bytes no reviewer
# ran against (the misattribution class, one level up from the --write
# splice guard). After a legitimate re-ratification, update this map in the
# same commit as the receipt's new approval record.
APPROVED_PAIR = {
    "docs/security/a-b-firmware-rollback-architecture.md": "abc058b1667d76cecf73f563340d24da17af4a35af61312e7abe61ee86da6284",
    "docs/security/fw-rollback-draft12-candidate-2026-07-21.md": "6173fe598d43ec7ac597f7ab843142bebe3456d63a63653cebc0ed369ad964ee",
}

# The canonical approval record keys each draft LABEL to its approved
# digest in order — an unordered digest pair cannot catch a label swap,
# and the affirmative '**DUAL APPROVAL over' first-line form distinguishes
# a genuine record from a negation or a mere mention.
EXPECTED_RECORD = {
    "Draft 1.1": "docs/security/a-b-firmware-rollback-architecture.md",
    "Draft 1.2": "docs/security/fw-rollback-draft12-candidate-2026-07-21.md",
}

# The exact ordered affirmative record grammar — the 2026-07-26 record's
# form, mandatory for any re-ratification record, matched with FULLMATCH
# against the whole paragraph: the record is a CLOSED paragraph (the
# explanatory prose lives in a separate paragraph), so no negation,
# revocation, heading, or prose insertion of any kind can ride along.
RECORD_GRAMMAR = re.compile(
    r"^ {0,3}\*\*(?i:dual approval over one digest pair), \d{4}-\d{2}-\d{2}:\*\*"
    r"[ \t]+Draft 1\.1\n"
    r"[ \t]*`([0-9a-f]{64})`[ \t]*\+[ \t]*\n"
    r"[ \t]*Draft 1\.2[ \t]+`([0-9a-f]{64})`[ \t]*\.[ \t]*\n?$"
)

# Raw HTML is REFUSED, not modeled: CommonMark has seven raw-HTML block
# types (comments, declarations, processing instructions, CDATA, and
# tag-opened blocks) plus inline HTML, and matching a renderer exactly is
# an unbounded problem. The receipt is a controlled governance document
# and legitimately contains no HTML-tag-shaped text; any such line outside
# a fence fails the gate closed. Exhibits belong inside fences.
HTML_TAG = re.compile(r"<[A-Za-z!/?]")

# Container-nested fences are REFUSED too: CommonMark permits fences inside
# blockquotes and lists ("> ```"), and a REOPENED marker or table nested
# there renders as CODE, not live structure. Modeling container state is
# out of scope — refuse the shape; the receipt nests no fences.
CONTAINER_FENCE = re.compile(r"^ {0,3}(?:(?:>[ \t]*)+|(?:[-+*]|\d+[.)])[ \t]+)(`{3,}|~{3,})")

# A fenced code block opens on a line indented AT MOST THREE SPACES
# (CommonMark; deeper indentation is an indented code block, not a fence)
# starting with >=3 backticks or tildes; per CommonMark a BACKTICK opener's
# info string may not itself contain a backtick (such a line is a
# paragraph, not a fence). The closing run must use the SAME character, be
# AT LEAST as long as the opener, and carry only ASCII spaces/tabs — a
# 4-backtick fence is NOT closed by a 3-backtick line, and a trailing
# non-breaking space does NOT make a line a closer (Python's str.strip()
# eats \u00a0 where CommonMark does not).
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def visible_lines(text: str) -> list[tuple[str, int]]:
    """Return (line, offset) pairs for lines OUTSIDE fenced code blocks.

    Lines are split on LF ONLY: CommonMark recognises LF/CR/CRLF endings,
    but str.splitlines() also breaks on U+2028/U+2029/VT/FF/NEL, which
    would let the parser see a "line" — and its ^-anchored anchor, row, or
    marker matches — that a renderer displays as mid-paragraph text.

    Fence lines and fenced content are excluded, so neither the anchor regex
    nor the table parser can ever match documentation exhibits. Any line
    carrying HTML-tag-shaped text outside a fence is REFUSED, not modeled:
    CommonMark has seven raw-HTML block types, inline HTML, and comment
    processing rules, and matching a renderer exactly is an unbounded
    problem — this gate parses a strict Markdown subset so it always sees
    exactly what a renderer shows. The receipt is a controlled governance
    document and legitimately contains no HTML; exhibits belong in fences.
    Refusal is fail-closed: it can only make the gate FAIL, never pass.
    """
    out: list[tuple[str, int]] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    offset = 0
    # Split on LF ONLY: CommonMark recognises LF/CR/CRLF line endings, but
    # str.splitlines() also breaks on U+2028/U+2029/VT/FF/NEL and friends,
    # letting the parser see a "line" (and its ^-anchored matches) that a
    # renderer shows as mid-paragraph text. Splitting on LF alone keeps
    # parser and renderer aligned; trailing CR is handled downstream.
    for seg in text.split("\n"):
        line = seg + "\n" if offset + len(seg) < len(text) else seg
        if not line:
            break
        m = FENCE.match(line)
        if m:
            # ASCII-only strip: CommonMark closers accept spaces/tabs after
            # the run; str.strip() would also eat \u00a0 and friends.
            run, rest = m.group(1), m.group(2).strip(" \t")
            if not in_fence:
                # CommonMark: a backtick opener's info string may not itself
                # contain a backtick — such a line is a paragraph, not a
                # fence, and stays visible.
                if run[0] == "`" and "`" in m.group(2):
                    out.append((line, offset))
                else:
                    in_fence, fence_char, fence_len = True, run[0], len(run)
            elif run[0] == fence_char and len(run) >= fence_len and not rest:
                in_fence = False
        elif not in_fence:
            if CONTAINER_FENCE.match(line):
                sys.exit(
                    "UNMODELLED CONTENT: container-nested fence "
                    f"(blockquote/list): {line.strip()!r}\n"
                    "A fence nested in a blockquote or list renders its "
                    "content as code, never as live structure — refused, "
                    "not modeled."
                )
            if HTML_TAG.search(line):
                sys.exit(
                    "UNMODELLED CONTENT: HTML-tag-shaped text outside a "
                    f"fenced code block: {line.strip()!r}\n"
                    "This gate parses a strict Markdown subset and refuses "
                    "raw HTML (including <!-- --> comments) rather than "
                    "risking a renderer/parser divergence — fence exhibits."
                )
            out.append((line, offset))
        offset += len(line)
    return out


def parse_pins(
    receipt_text: str,
) -> tuple[list[tuple[str, str]], dict[str, tuple[int, int]], int]:
    """Extract (path, digest) from the '## Frozen pair' table only.

    Fence-aware, and scoped to that section so the 'Superseded pair' /
    'Approved-but-superseded' digests recorded elsewhere in the receipt are
    never mistaken for live pins. Returns the pins; per path, the absolute
    (start, end) span of its digest CELL in receipt_text, so `--write`
    rewrites exactly that capture and nothing else; and the count of
    authoritative REOPENED blockquote markers among the section's visible
    lines, for main()'s attribution guard.
    """
    lines = visible_lines(receipt_text)

    def _normalized(line: str) -> str:
        # CommonMark renders emphasis, inline code, links, and entities
        # inside headings: '## **Frozen pair**', '## `Frozen pair`', '##
        # [Frozen pair](#shadow)', '## ~~Frozen pair~~', '##
        # Frozen&#32;pair', and '## Frozen&numsp;pair' are all Frozen-pair
        # H2s. html.unescape covers the FULL HTML5 named/numeric reference
        # table — no hand-maintained entity list to under-cover. Normalize
        # before the look-alike check (the live anchor itself must stay
        # the canonical raw form).
        line = re.sub(r"!?\[([^\]]+)\]\([^)]*\)", r"\1", line)
        line = re.sub(r"!?\[([^\]]+)\]\[[^\]]*\]", r"\1", line)
        line = re.sub(r"!?\[([^\]]+)\](?!\()", r"\1", line)
        line = html.unescape(line)
        # A renderer collapses heading whitespace (any Unicode space) into
        # display-identical gaps: collapse before matching.
        line = re.sub(r"\s+", " ", line)
        return line.replace("*", "").replace("_", "").replace("`", "").replace("~", "")

    anchor_idx = [i for i, (line, _) in enumerate(lines) if ANCHOR.match(line)]
    variant_idx = [
        i
        for i, (line, _) in enumerate(lines)
        if ANCHOR_PREFIX.match(_normalized(line))
        or CONTAINER_ANCHOR.match(_normalized(line))
        or INDENTED_ANCHOR.match(_normalized(line))
    ]
    if len(anchor_idx) != 1 or len(variant_idx) != 1:
        sys.exit(
            f"ANCHOR BROKEN: expected exactly one full-line '{HEADING}' "
            f"heading (and no look-alike '## Frozen pair ...' variant) outside "
            f"fenced code blocks in {RECEIPT.name}, found {len(anchor_idx)} "
            f"exact and {len(variant_idx)} prefix-carrying.\n"
            "The receipt was re-laid-out; re-sync this script in the same commit."
        )

    # Section = visible lines after the anchor, up to the next visible
    # level-1/2 ATX heading AT COLUMN ZERO. A bare =/- underline line or
    # an indented H1/H2 anywhere inside is refused rather than classified
    # (ATX-only, column-zero receipt).
    section: list[tuple[str, int]] = []
    for line, off in lines[anchor_idx[0] + 1 :]:
        if SECTION_END_ATX.match(line):
            break
        if INDENTED_HEADING.match(line):
            sys.exit(
                "ANCHOR BROKEN: indented H1/H2 heading inside the "
                f"'{HEADING}' section: {line.strip()!r}\n"
                "Section boundaries are column-zero only; an indented "
                "heading can be list-nested in CommonMark — refused."
            )
        if SETEXT_OR_HR.match(line):
            sys.exit(
                "ANCHOR BROKEN: bare underline/thematic-break line inside "
                f"the '{HEADING}' section: {line.strip()!r}\n"
                "This receipt uses ATX headings only; a =/- underline form "
                "is refused rather than classified."
            )
        section.append((line, off))

    pins: list[tuple[str, str]] = []
    cells: dict[str, tuple[int, int]] = {}
    table_lines: list[tuple[str, int]] = []
    seen_header = False
    seen_separator = False
    table_closed = False
    for idx, (line, off) in enumerate(section):
        body = line.rstrip("\n")
        if seen_header and not seen_separator:
            # The separator must be the IMMEDIATELY NEXT visible line after
            # the header — prose or a blank line between them means this is
            # not a table, and empty-cell look-alikes without dashes
            # ("| | | |") do not count as separators.
            if not SEPARATOR.match(body):
                sys.exit(
                    f"ANCHOR BROKEN: the header under '{HEADING}' is not "
                    f"followed immediately by a separator row: {body!r}"
                )
            seen_separator = True
            table_lines.append((line, off))
            continue
        if seen_separator:
            if table_closed:
                # The table ended at its first non-row line; anything that
                # looks like a row afterwards is a NEW structure this gate
                # does not model — data rows must be contiguous.
                if "|" in body and body.strip(" \t"):
                    sys.exit(
                        f"ANCHOR BROKEN: table content appears after the "
                        f"table's end under '{HEADING}' (data rows must be "
                        f"contiguous and immediately follow the separator): "
                        f"{body!r}"
                    )
                continue
            if not body.lstrip().startswith("|"):
                if "|" in body and body.strip(" \t"):
                    # A pipe-bearing line right after the separator is a
                    # RENDERED (malformed/extra) row, not a table end —
                    # GFM keeps the table open while lines carry pipes.
                    sys.exit(
                        f"ANCHOR BROKEN: malformed or extra rendered row "
                        f"under '{HEADING}': {body!r}"
                    )
                # A blank or pipe-free prose line ends the GFM table.
                table_closed = True
                continue
            m = ROW.match(body)
            if not m:
                sys.exit(
                    f"ANCHOR BROKEN: malformed or unexpected table row under "
                    f"'{HEADING}': {body!r}\nRefusing to guess — fix the row or "
                    "re-sync this script in the same commit."
                )
            label, rel, digest = m.group(1).strip(" \t"), m.group(2), m.group(3).lower()
            if rel in cells:
                sys.exit(
                    f"ANCHOR BROKEN: duplicate table row for {rel} under '{HEADING}'."
                )
            if label != EXPECTED_LABEL.get(rel):
                sys.exit(
                    f"ANCHOR BROKEN: the row for {rel} must carry exactly "
                    f"the label {EXPECTED_LABEL.get(rel, '<unknown>')!r}, "
                    f"found {label!r} — a swapped, blank, contradictory, or "
                    "re-annotated label misattributes the pin to readers "
                    "(update both in the same commit at a legitimate re-pin)."
                )
            pins.append((rel, digest))
            cells[rel] = (off + m.start(3), off + m.end(3))
            table_lines.append((line, off))
            continue
        if not body.lstrip().startswith("|"):
            # GFM also renders table rows WITHOUT a leading pipe, so a
            # pipe-bearing non-canonical line is a hidden extra row, not
            # prose — fail instead of skipping it.
            if "|" in body and body.strip(" \t"):
                sys.exit(
                    f"ANCHOR BROKEN: non-canonical table row under "
                    f"'{HEADING}' (rows must start with '|'): {body!r}"
                )
            continue
        seen_header = True
        if idx > 0:
            prev_line, prev_off = section[idx - 1]
            prev_blank = not prev_line.strip(" \t\n")
            # Filtered content between the previous visible line and the
            # header (e.g. a fence) is itself a block boundary.
            block_gap = prev_off + len(prev_line) != off
            if not prev_blank and not block_gap:
                sys.exit(
                    f"ANCHOR BROKEN: the table header under '{HEADING}' does "
                    "not start a new block — with neither a blank line nor a "
                    "block boundary before it, CommonMark reads these lines "
                    "as a lazy continuation of the preceding paragraph or "
                    "blockquote, not as a table."
                )
        if not HEADER.match(body):
            sys.exit(
                f"ANCHOR BROKEN: the first table line under '{HEADING}' "
                "is not the canonical '| document | path | SHA-256 |' "
                f"header: {body!r}"
            )
        table_lines.append((line, off))

    # The table must be one contiguous SOURCE block: filtered content (a
    # fenced exhibit sits between header/rows in the raw text) ends the
    # rendered table even though the filtered stream looks adjacent.
    for (la, oa), (lb, ob) in zip(table_lines, table_lines[1:]):
        if ob != oa + len(la):
            sys.exit(
                f"ANCHOR BROKEN: the table under '{HEADING}' is not one "
                "contiguous source block — hidden content (e.g. a fenced "
                "block) separates table lines, which ends the rendered table."
            )

    paths = {rel for rel, _ in pins}
    if len(pins) != EXPECTED_ROWS or paths != EXPECTED_PATHS:
        sys.exit(
            f"ANCHOR BROKEN: expected {EXPECTED_ROWS} pinned rows under "
            f"'{HEADING}' naming exactly {sorted(EXPECTED_PATHS)}, found "
            f"{len(pins)} row(s) naming {sorted(paths)}.\n"
            "Refusing to pass vacuously — a gate that checks nothing, or "
            "checks the wrong files, is worse than no gate."
        )

    reopened = sum(
        1
        for line, _ in section
        if REOPENED_MARKER.match(line.rstrip("\n").rstrip("\r"))
    )
    return pins, cells, reopened


def _approval_records(receipt_text: str) -> set[frozenset[str]]:
    """Collect the digest pairs of all canonical approval records.

    A canonical approval record is a PARAGRAPH whose first line carries
    the bold '**DUAL APPROV…' marker (the form the immutable 2026-07-26
    record uses, and the form a re-ratification record must reuse): a
    negated or mid-sentence 'dual APPROVE' mention is prose, not a
    record. The search text is rebuilt WITH block-boundary sentinels:
    filtered content (a fenced exhibit) sits between visible lines in
    the raw source, and flattening without sentinels would splice a
    phrase in one rendered block and digests in another into a phantom
    record.
    """
    visible = visible_lines(receipt_text)
    visible_text = ""
    prev: tuple[str, int] | None = None
    for line, off in visible:
        if prev is not None and off != prev[1] + len(prev[0]):
            visible_text += "\n"
        visible_text += line
        prev = (line, off)
    records: set[frozenset[str]] = set()
    for paragraph in re.split(r"\n[ \t]*\n", visible_text):
        if not paragraph.strip(" \t"):
            continue
        # Strip leading NEWLINES only (never spaces): a paragraph indented
        # four-plus spaces is an indented CODE block, not a live record —
        # the canonical form's own 0-3 space allowance must see the raw
        # indentation.
        first = paragraph.lstrip("\n").splitlines()[0]
        # A record paragraph is one coherent plain block: no ATX heading
        # line, no Setext/thematic-break underline (it would turn the
        # marker line into a rendered heading and detach the digests), no
        # container block (blockquote or list item), and no indented-code
        # line — all interrupt a CommonMark paragraph without a blank line.
        if any(
            re.match(r"^ {0,3}(?:#{1,6}(?:[ \t]|$)|>|[-+*][ \t]|\d+[.)][ \t])", block_line)
            or SETEXT_OR_HR.match(block_line)
            or block_line.startswith(("    ", "\t"))
            for block_line in paragraph.splitlines()
        ):
            continue
        # The EXACT ordered affirmative grammar (the 2026-07-26 record's
        # form; a re-ratification record must reuse it) matched with
        # FULLMATCH against the whole paragraph: the record is a CLOSED
        # paragraph — marker line ending ':** Draft 1.1', then '`d1` +',
        # then 'Draft 1.2 `d2`.' — so nothing (negation, revocation,
        # heading, prose) can ride along after the terminal full stop.
        # Each label must bind to exactly its APPROVED_PAIR digest.
        m = RECORD_GRAMMAR.fullmatch(paragraph.lstrip("\n"))
        if not m:
            continue
        if (
            m.group(1) == APPROVED_PAIR[EXPECTED_RECORD["Draft 1.1"]]
            and m.group(2) == APPROVED_PAIR[EXPECTED_RECORD["Draft 1.2"]]
        ):
            records.add(frozenset((m.group(1), m.group(2))))
    return records


def self_test() -> int:
    """In-repo negative controls for the parser itself (the F1 class: a
    green gate that checks nothing). Runs entirely in memory against
    parse_pins: one good fixture must parse, and every mutation must fail
    closed. Prepended to the Make target, mirroring verify-hw-assumptions.
    """
    good = (
        "## Frozen pair\n"
        "\n"
        "> **GATE STATE: REOPENED (2026-08-06).** Marker.\n"
        "\n"
        "| document | path | SHA-256 |\n"
        "|---|---|---|\n"
        "| Draft 1.1 (post-errata-4, unchanged) | `docs/security/a-b-firmware-rollback-architecture.md` "
        "| `" + "a" * 64 + "` |\n"
        "| Draft 1.2 (post-BLOCKER-1, post-`fb66a1e5`) | `docs/security/fw-rollback-draft12-candidate-2026-07-21.md` "
        "| `" + "b" * 64 + "` |\n"
    )
    pins, cells, reopened = parse_pins(good)
    if len(pins) != 2 or {p for p, _ in pins} != EXPECTED_PATHS or reopened != 1:
        raise AssertionError("self-test: the good fixture did not parse cleanly")

    rows = [l for l in good.splitlines() if l.startswith("| Draft 1.")]
    rogue_table = (
        "\n---\n\n| document | path | SHA-256 |\n|---|---|---|\n" + "\n".join(rows) + "\n"
    )
    mutations = {
        "renamed anchor": good.replace("## Frozen pair", "## Frozen pears"),
        "fenced heading exhibit + renamed live anchor": good.replace(
            "## Frozen pair", "## Archived layout"
        )
        + "\n## Appendix\n\n```\n## Frozen pair\n\n| document | path | SHA-256 |\n|---|---|---|\n"
        + "\n".join(rows)
        + "\n```\n",
        "dropped row": good.replace(rows[1] + "\n", ""),
        "re-pointed row": good.replace(
            "docs/security/fw-rollback-draft12-candidate-2026-07-21.md",
            "docs/security/vendor-signing-key-compromise.md",
        ),
        "63-hex digest cell": good.replace("b" * 64, "b" * 63),
        "thematic break + rogue table": good + rogue_table,
        "list item as Setext predecessor": good.replace(
            "## Frozen pair\n", "## Frozen pair\n\n- item\n---\n"
        ),
        "pipe-bearing extra row": good + "Draft extra | `README.md` | `" + "0" * 64 + "` |\n",
        "malformed extra row": good + rows[1].replace("b" * 64, "b" * 63) + "\n",
        "missing separator": good.replace("|---|---|---|\n", ""),
        "fence-spliced table": good.replace(
            "|---|---|---|\n" + rows[0], "|---|---|---|\n```\nfiller\n```\n" + rows[0]
        ),
        "indented code as Setext predecessor": good.replace(
            rows[0] + "\n", "    indented code\n---\n\n" + rows[0] + "\n"
        ),
        "link-reference as Setext predecessor": good.replace(
            rows[0] + "\n", "[ref]: /x\n---\n\n" + rows[0] + "\n"
        ),
        "blockquote-nested duplicate anchor": good + "\n> ## Frozen pair\n",
        "list-nested duplicate anchor": good + "\n- ## Frozen pair (duplicate)\n",
        "mixed-container duplicate anchor": good + "\n> - ## Frozen pair (duplicate)\n",
        "list-continuation anchor": good + "\n- item\n\n    ## Frozen pair\n",
        "mixed space+tab indented anchor": good + "\n- item\n\n \t## Frozen pair\n",
        "tab-then-spaces indented anchor": good + "\n- item\n\n\t    ## Frozen pair\n",
        "NBSP-only line before header": good.replace(
            "| document | path | SHA-256 |", "\u00a0\n| document | path | SHA-256 |"
        ),
        "emphasized duplicate anchor": good + "\n## **Frozen pair**\n",
        "inline-code duplicate anchor": good + "\n## `Frozen pair`\n",
        "entity-space duplicate anchor": good + "\n## Frozen&#32;pair\n",
        "entity-letter duplicate anchor": good + "\n## &#70;rozen pair\n",
        "link-wrapped duplicate anchor": good + "\n## [Frozen pair](#shadow)\n",
        "strikethrough duplicate anchor": good + "\n## ~~Frozen pair~~\n",
        "tab-internal duplicate anchor": good + "\n## Frozen\tpair\n",
        "doubled-space duplicate anchor": good + "\n## Frozen  pair\n",
        "uppercase-X entity anchor": good + "\n## Frozen&#X20;pair\n",
        "numsp entity anchor": good + "\n## Frozen&numsp;pair\n",
        "wrong-document label": good.replace("(post-errata-4, unchanged)", "(wrong document)", 1),
        "named-entity-space anchor": good + "\n## Frozen&ensp;pair\n",
        "contradictory label": good.replace(rows[0], rows[0].replace("Draft 1.1", "Draft 1.1 (this is Draft 1.2)", 1), 1),
        "list-nested retained anchor": good.replace("## Frozen pair", "## Archived pair")
        + "\n- retained anchor\n\n  ## Frozen pair\n",
        "indented heading inside section": good.replace(
            "| document | path | SHA-256 |", "  ## Interlude\n\n| document | path | SHA-256 |"
        ),
        "label-swapped rows": good.replace(rows[0], rows[0].replace("Draft 1.1", "Draft 1.2"), 1),
        "blank label cell": good.replace(rows[0], rows[0].replace("Draft 1.1", "", 1), 1),
        "NBSP in separator": good.replace("|---|---|---|", "|\u00a0|---|---|"),
    }
    for name, text in mutations.items():
        try:
            parse_pins(text)
        except SystemExit:
            continue
        raise AssertionError(f"self-test: mutation '{name}' did not fail closed")

    # Attribution level: canonical records register; records split by a
    # thematic break, a blockquote, or an ATX heading do not.
    d1 = APPROVED_PAIR["docs/security/a-b-firmware-rollback-architecture.md"]
    d2 = APPROVED_PAIR["docs/security/fw-rollback-draft12-candidate-2026-07-21.md"]
    canonical = (
        "\n**DUAL APPROVAL over one digest pair, 2026-07-26:** Draft 1.1\n`"
        + d1
        + "` +\nDraft 1.2 `"
        + d2
        + "`.\n"
    )
    pair = frozenset({d1, d2})
    if pair not in _approval_records(canonical):
        raise AssertionError("self-test: canonical approval record not found")
    for name, variant in {
        "thematic break inside record": canonical.replace("Draft 1.1\n", "Draft 1.1\n---\n"),
        "blockquote inside record": canonical.replace("` +\nDraft 1.2", "` +\n> Draft 1.2"),
        "ATX heading inside record": canonical.replace("` +\nDraft 1.2", "` +\n### Interlude\nDraft 1.2"),
        "negated record": canonical.replace("**DUAL APPROVAL over", "**No DUAL APPROVAL over"),
        "post-prefix negated record": canonical.replace(
            "**DUAL APPROVAL over one digest pair, 2026-07-26:**",
            "**DUAL APPROVAL over was explicitly NOT granted.**",
        ),
        "trailing negated record": canonical.replace(
            "**DUAL APPROVAL over one digest pair, 2026-07-26:** Draft 1.1",
            "**DUAL APPROVAL over one digest pair, 2026-07-26:** NO APPROVAL WAS GRANTED.\nDraft 1.1",
        ),
        "negation after terminal digest": canonical.replace(
            "`" + d2 + "`.", "`" + d2 + "` \u2014 NO APPROVAL WAS GRANTED."
        ),
        "revocation prose appended": canonical.replace(
            "`" + d2 + "`.\n", "`" + d2 + "`. This approval is hereby revoked.\n"
        ),
        "indented-code record": canonical.replace(
            "**DUAL APPROVAL over", "    **DUAL APPROVAL over"
        ),
        "label-swapped record": canonical.replace(
            "`" + d1 + "`", "`X`"
        ).replace("`" + d2 + "`", "`" + d1 + "`").replace("`X`", "`" + d2 + "`"),
    }.items():
        if pair in _approval_records(variant):
            raise AssertionError(f"self-test: '{name}' accepted as an approval record")
    print(
        f"check_rollback_freeze_pin --self-test: 1 good + {len(mutations)} parser "
        "mutations + 11 attribution controls ok"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--write",
        action="store_true",
        help="rewrite the receipt's pins to the files' current digests "
        "(governance act — see the module docstring)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the in-memory negative controls for the parser itself",
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if not RECEIPT.is_file():
        sys.exit(f"MISSING: {RECEIPT}")
    # newline="" disables universal-newline translation: a CRLF receipt
    # fails closed at the anchor parse (loud, never silent), and --write
    # below can never rewrite every line's endings behind a digest-cell edit.
    with RECEIPT.open("r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    if "\r" in text:
        sys.exit(
            "UNMODELLED LINE ENDING: CR byte found. This gate is LF-only "
            "by design — a bare CR is a CommonMark line ending that could "
            "hide renderer-visible structure mid-parser-line, and CRLF "
            "would need offset-preserving CR handling the parser "
            "deliberately does not implement. Convert the receipt to LF."
        )
    pins, cells, reopened = parse_pins(text)

    if dict(pins) != APPROVED_PAIR and reopened != 1:
        sys.exit(
            "ATTRIBUTION BROKEN: the live pins differ from the 2026-07-26 "
            "approved pair, but the Frozen pair section does not carry "
            "exactly one visible '> **GATE STATE: REOPENED' blockquote "
            f"marker (found {reopened}) recording that the approval does "
            "not carry.\n"
            "A green gate must never assert approval over bytes no reviewer "
            "ran against. Restore the marker, or record the new approval and "
            "update APPROVED_PAIR in this script in the same commit."
        )
    if dict(pins) == APPROVED_PAIR and reopened != 0:
        sys.exit(
            "ATTRIBUTION BROKEN: the live pins EQUAL the approved pair, but "
            "the Frozen pair section still carries a '> **GATE STATE: "
            "REOPENED' marker telling readers the gate is reopened.\n"
            "A green gate must not contradict the receipt it validates — "
            "remove the marker (or honestly re-open the gate) in the same "
            "commit."
        )

    # The guard's hardcoded APPROVED_PAIR must itself agree with an
    # approval record in the receipt: a one-line SCRIPT-side edit
    # re-pointing the constant at the current digests would otherwise make
    # the attribution guard vacuous with zero receipt change — the exact
    # misattribution class this gate exists to close. Historical records
    # stay immutable: at re-ratification a NEW record naming the new pair
    # is added and the constant updates in the same commit.
    records = _approval_records(text)
    if frozenset(APPROVED_PAIR.values()) not in records:
        sys.exit(
            "ATTRIBUTION BROKEN: no canonical '**DUAL APPROV…' approval "
            "paragraph in the receipt carries exactly the digests hardcoded "
            "in APPROVED_PAIR.\n"
            "The script's approval constant and a receipt approval record "
            "must agree; at re-ratification add the new record (same "
            "canonical form) and update the constant in the same commit."
        )

    drift: list[tuple[str, str, str]] = []
    for rel, pinned in pins:
        target = REPO / rel
        # lstat, not is_file(): a pinned Git blob is a REGULAR file.
        # is_file()/open() follow symlinks, so a symlink re-pointed at an
        # unchanged-byte copy (or at a system binary) would pass while the
        # tree's blob and mode drifted — reject anything non-regular.
        try:
            st = target.lstat()
        except FileNotFoundError:
            sys.exit(f"MISSING PINNED FILE: {rel}")
        if not stat.S_ISREG(st.st_mode):
            sys.exit(
                f"PINNED FILE IS NOT A REGULAR FILE: {rel} "
                f"(mode {oct(st.st_mode)}) — the frozen pair is pinned as "
                "regular-file blobs; symlinks and other modes fail closed."
            )
        actual = sha256_of(target)
        status = "OK  " if actual == pinned else "DRIFT"
        print(f"  [{status}] {rel}\n           pinned {pinned}\n           actual {actual}")
        if actual != pinned:
            drift.append((rel, pinned, actual))

    if not drift:
        print(f"check_rollback_freeze_pin: {len(pins)} document(s) match the frozen pair.")
        return 0

    if args.write:
        # Rewrite EXACTLY the drifted rows' digest cells by capture span. The
        # same 64-hex string may occur as narrative inside this section or in
        # the historical approved/superseded records outside it; both are
        # records, not pins, and must stay byte-identical.
        splices: list[tuple[int, int, str]] = []
        for rel, pinned, actual in drift:
            start, end = cells[rel]
            # Case-insensitive compare: ROW accepts uppercase hex and the
            # parse lowercases it, so the raw cell may differ only in case
            # — the splice then normalizes it to the computed digest.
            if text[start:end].lower() != pinned:
                sys.exit(
                    f"INTERNAL: digest cell for {rel} no longer matches its "
                    "parse — refusing to write."
                )
            splices.append((start, end, actual))
        for start, end, actual in sorted(splices, reverse=True):
            text = text[:start] + actual + text[end:]
        # newline="" — write back exactly what was read, so a digest-cell
        # edit can never silently rewrite the whole file's line endings.
        with RECEIPT.open("w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(
            "\nRE-PINNED. This is only half the job:\n"
            "  Per the 2026-07-26 owner ratification (condition 3), ANY byte change\n"
            "  to either draft REOPENS the review gate. Milestone 0 is NOT closed at\n"
            "  the new digests until either (a) both exact-digest review legs re-run\n"
            "  plus owner ratification, or (b) a de-minimis owner acceptance naming\n"
            "  the exact delta is recorded in the receipt.\n"
            "  Update the receipt's gate-state note in this same commit."
        )
        return 0

    print(
        "\nFROZEN-PAIR DRIFT — a document reviewed at an exact digest has changed.\n",
        file=sys.stderr,
    )
    for rel, pinned, actual in drift:
        print(f"  {rel}\n    pinned {pinned}\n    actual {actual}", file=sys.stderr)
    print(
        "\nPer the 2026-07-26 owner ratification (condition 3), this REOPENS the\n"
        "review gate — the dual APPROVE does not carry to the new bytes.\n"
        "If the change is intended: re-pin with\n"
        "    python3 contracts/verification/scripts/check_rollback_freeze_pin.py --write\n"
        "and record the gate state + what re-closing Milestone 0 requires in\n"
        f"    {RECEIPT.relative_to(REPO)}\n"
        "If it is NOT intended (e.g. a repo-wide rename swept these docs up),\n"
        "revert the edit to these files instead.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
