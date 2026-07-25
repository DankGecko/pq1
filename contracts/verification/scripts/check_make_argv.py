#!/usr/bin/env python3
"""Fail-closed parser for explicit GNU Make makefile options.

GNU Make's ``MAKEFILE_LIST`` is mutable by a later makefile, so it cannot be
the sole authority for deciding whether more than one ``-f``/``--file`` input
was supplied.  The verification Makefile invokes this helper while that main
file is still being parsed and passes the parent Make process's procfs cmdline.

Output is deliberately one fixed token:

* ``ok`` when zero or one explicit makefile was supplied;
* ``multiple-makefiles:N`` when two or more were supplied; or
* ``invalid-argv`` when the process argv cannot be parsed safely.
"""

from __future__ import annotations

import pathlib
import sys


_SHORT_OPTIONS_WITH_REQUIRED_ARGUMENT = frozenset("CIfWo")
_SHORT_OPTIONS_WITH_OPTIONAL_ARGUMENT = frozenset("jlO")


def _is_file_long_option(name: str) -> bool:
    """Recognize GNU getopt_long's accepted prefixes for the two aliases."""
    return bool(name) and ("file".startswith(name) or "makefile".startswith(name))


def count_explicit_makefiles(argv: list[str]) -> int | None:
    """Return the explicit makefile-option count, or ``None`` on bad argv."""
    count = 0
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            break

        if arg.startswith("--") and len(arg) > 2:
            option, separator, value = arg[2:].partition("=")
            if _is_file_long_option(option):
                count += 1
                if separator:
                    if not value:
                        return None
                else:
                    i += 1
                    if i >= len(argv):
                        return None
            i += 1
            continue

        if arg.startswith("-") and arg != "-":
            short = arg[1:]
            pos = 0
            while pos < len(short):
                option = short[pos]
                if option == "f":
                    count += 1
                    if pos + 1 == len(short):
                        i += 1
                        if i >= len(argv):
                            return None
                    break
                if option in _SHORT_OPTIONS_WITH_REQUIRED_ARGUMENT:
                    if pos + 1 == len(short):
                        i += 1
                        if i >= len(argv):
                            return None
                    break
                if option in _SHORT_OPTIONS_WITH_OPTIONAL_ARGUMENT:
                    break
                pos += 1

        i += 1
    return count


def self_test() -> int:
    cases = (
        (["make"], 0),
        (["make", "-f", "Makefile"], 1),
        (["make", "-fMakefile"], 1),
        (["make", "--file=Makefile"], 1),
        (["make", "--makefile", "Makefile"], 1),
        (["make", "-kfMakefile", "--file", "/dev/null"], 2),
        (["make", "--fil=Makefile", "--makef", "/dev/null"], 2),
        (["make", "-Ifoo", "--", "-f", "not-an-option"], 0),
        (["make", "-f"], None),
        (["make", "--file="], None),
    )
    for argv, expected in cases:
        actual = count_explicit_makefiles(argv)
        if actual != expected:
            print(f"FAIL: argv {argv!r}: got {actual!r}, expected {expected!r}", file=sys.stderr)
            return 1
    print("check_make_argv.py --self-test: all controls behave")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) != 2:
        print("invalid-argv")
        return 0
    try:
        raw = pathlib.Path(sys.argv[1]).read_bytes()
        if not raw.endswith(b"\0"):
            raise ValueError("unterminated procfs argv")
        argv = [part.decode(errors="surrogateescape") for part in raw[:-1].split(b"\0")]
        if not argv or not argv[0]:
            raise ValueError("empty procfs argv")
        count = count_explicit_makefiles(argv)
    except (OSError, ValueError):
        print("invalid-argv")
        return 0

    if count is None:
        print("invalid-argv")
    elif count <= 1:
        print("ok")
    else:
        print(f"multiple-makefiles:{count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
