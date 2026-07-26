#!/usr/bin/env python3
"""Fail-closed parser for explicit GNU Make makefile and no-execute options.

GNU Make's ``MAKEFILE_LIST`` is mutable by a later makefile, so it cannot be
the sole authority for deciding whether more than one ``-f``/``--file`` input
was supplied.  The verification Makefile invokes this helper while that main
file is still being parsed and passes the parent Make process's procfs
cmdline.  Recipe-suppression options travel the same route — and they can
also arrive through the environment: an environment-injected ``MAKEFLAGS``
or ``GNUMAKEFLAGS`` (e.g. ``o <target>``) is consumed and stripped before
the in-Make MAKEFLAGS value is rebuilt, so only the at-exec environment
still shows it.  That is why the parent's procfs environ is inspected
alongside its argv, and why both flag variables are scanned.

Two option families are rejected:

* multiple explicit makefiles (``-f``/``--file``); and
* no-execute / recipe-suppression modes: ``-n``/``--just-print``/
  ``--dry-run``/``--recon``, ``-q``/``--question``, ``-t``/``--touch``,
  ``-i``/``--ignore-errors``, ``-o``/``--old-file``/``--assume-old``, and
  ``-W``/``--what-if``/``--new-file``/``--assume-new``.  Each can retire an
  evidence target while Make still exits 0 without producing evidence
  (``make -o <target> <target>`` prints "Nothing to be done"; ``-n`` merely
  prints the recipes).

Output is deliberately one fixed token:

* ``ok`` when zero or one explicit makefile and no suppression mode;
* ``multiple-makefiles:N`` when two or more were supplied;
* ``no-execute-mode:<option>`` when a suppression option is present; or
* ``invalid-argv`` when the process argv/environ cannot be parsed safely.
"""

from __future__ import annotations

import pathlib
import sys


_SHORT_OPTIONS_WITH_REQUIRED_ARGUMENT = frozenset("CIfWo")
_SHORT_OPTIONS_WITH_OPTIONAL_ARGUMENT = frozenset("jlO")
_SUPPRESSION_SHORT = frozenset("inoqtW")
_SUPPRESSION_LONG_NOARG = ("just-print", "dry-run", "recon", "question", "touch", "ignore-errors")
_SUPPRESSION_LONG_ARG = ("old-file", "assume-old", "new-file", "assume-new", "what-if")


def _prefix_match(name: str, options: tuple[str, ...]) -> bool:
    """Recognize GNU getopt_long's accepted unambiguous prefixes."""
    return bool(name) and any(opt.startswith(name) for opt in options)


def _is_file_long_option(name: str) -> bool:
    """Recognize GNU getopt_long's accepted prefixes for the two aliases."""
    return bool(name) and ("file".startswith(name) or "makefile".startswith(name))


def scan_argv_options(words: list[str]) -> tuple[int, list[str]] | None:
    """Scan Make argv (excluding argv[0]); ``None`` on unparseable argv.

    Returns ``(explicit-makefile count, suppression-option hits)``.  Bare
    words are targets or variable assignments and are skipped — their
    letters are not options.  (A command-line ``MAKEFLAGS=...`` assignment
    is rejected by the Makefile's origin guard, a separate layer.)
    """
    count = 0
    hits: list[str] = []
    i = 0
    while i < len(words):
        arg = words[i]
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
                    if i >= len(words):
                        return None
            elif _prefix_match(option, _SUPPRESSION_LONG_NOARG):
                hits.append(f"--{option}")
            elif _prefix_match(option, _SUPPRESSION_LONG_ARG):
                hits.append(f"--{option}")
                if not separator:
                    i += 1  # skip the option's argument
            i += 1
            continue

        if arg.startswith("-") and arg != "-":
            short = arg[1:]
            pos = 0
            while pos < len(short):
                option = short[pos]
                if option in _SUPPRESSION_SHORT:
                    hits.append(f"-{option}")
                if option == "f":
                    count += 1
                    if pos + 1 == len(short):
                        i += 1
                        if i >= len(words):
                            return None
                    break
                if option in _SHORT_OPTIONS_WITH_REQUIRED_ARGUMENT:
                    if pos + 1 == len(short):
                        i += 1
                        if i >= len(words):
                            return None
                    break
                if option in _SHORT_OPTIONS_WITH_OPTIONAL_ARGUMENT:
                    break
                pos += 1

        i += 1
    return count, hits


def scan_makeflags_value(value: str) -> list[str]:
    """Scan an environment-injected MAKEFLAGS value for suppression modes.

    MAKEFLAGS grammar: a first word without dashes is a bundle of
    single-letter options (``n``, ``nw``); an argument-taking option
    consumes the following word (``o <target>``, ``C <dir>``); everything
    after a bare ``--`` word is a command-line variable assignment passed
    through for sub-makes (``-- FOO=bar``), not an option.  GNU Make strips
    the argument-taking options from the value it propagates, so only the
    at-exec environ shows them.
    """
    hits: list[str] = []
    words = value.split()
    i = 0
    while i < len(words):
        word = words[i]
        if word == "--":
            break
        if word.startswith("--") and len(word) > 2:
            option, separator, _ = word[2:].partition("=")
            if _prefix_match(option, _SUPPRESSION_LONG_NOARG):
                hits.append(f"--{option}")
            elif _prefix_match(option, _SUPPRESSION_LONG_ARG):
                hits.append(f"--{option}")
                if not separator:
                    i += 1
        else:
            bundle = word.lstrip("-")
            for option in bundle:
                if option in _SUPPRESSION_SHORT:
                    hits.append(f"-{option}")
                if option in _SHORT_OPTIONS_WITH_OPTIONAL_ARGUMENT:
                    # jlO take an ATTACHED optional argument: the rest of the
                    # word is that argument (e.g. `-Otarget` is --output-sync,
                    # not the letters t/a/r/g/e/t), not more options.
                    break
            if bundle and bundle[0] in _SHORT_OPTIONS_WITH_REQUIRED_ARGUMENT:
                i += 1  # the option's argument is the following word
        i += 1
    return hits


def count_explicit_makefiles(argv: list[str]) -> int | None:
    """Return the explicit makefile-option count, or ``None`` on bad argv."""
    scanned = scan_argv_options(argv[1:])
    return None if scanned is None else scanned[0]


def _read_procfs_list(path: str) -> list[str]:
    raw = pathlib.Path(path).read_bytes()
    if not raw.endswith(b"\0"):
        raise ValueError("unterminated procfs list")
    return [part.decode(errors="surrogateescape") for part in raw[:-1].split(b"\0")]


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

    argv_suppression_cases = (
        (["make", "-n", "verify"], ["-n"]),
        (["make", "-ni", "verify"], ["-n", "-i"]),
        (["make", "-q", "verify"], ["-q"]),
        (["make", "-o", "verify", "verify"], ["-o"]),
        (["make", "--assume-old=verify", "verify"], ["--assume-old"]),
        (["make", "--old", "verify", "verify"], ["--old"]),
        (["make", "--jus", "verify"], ["--jus"]),
        (["make", "-W", "Makefile", "verify"], ["-W"]),
        (["make", "--assume-new", "Makefile", "verify"], ["--assume-new"]),
        (["make", "-C", "sub", "verify"], []),
        (["make", "-fMakefile", "verify"], []),
        (["make", "-j4", "verify"], []),
        (["make", "-ks", "verify"], []),
        (["make", "verify-ledger-consistency"], []),
        (["make", "MAKEFLAGS=-n"], []),
    )
    for argv, expected in argv_suppression_cases:
        scanned = scan_argv_options(argv[1:])
        hits = None if scanned is None else scanned[1]
        if hits != expected:
            print(f"FAIL: suppression argv {argv!r}: got {hits!r}, expected {expected!r}",
                  file=sys.stderr)
            return 1

    makeflags_cases = (
        ("n", ["-n"]),
        ("-n", ["-n"]),
        ("nt", ["-n", "-t"]),
        ("o verify-ledger-consistency", ["-o"]),
        ("W Makefile", ["-W"]),
        ("--assume-old=verify", ["--assume-old"]),
        ("--dry-run", ["--dry-run"]),
        ("--no-print-directory", []),
        ("--jobserver-auth=3,4", []),
        ("w", []),
        ("j4", []),
        ("C sub", []),
        ("", []),
        ("w --no-print-directory -- FOO=production", []),
        ("n -- FOO=production", ["-n"]),
        ("-- _FV_EXTRACTION_INNER=1", []),
        ("-Otarget", []),
        ("-Oline", []),
        ("nOtarget", ["-n"]),
        ("-j4", []),
    )
    for value, expected in makeflags_cases:
        hits = scan_makeflags_value(value)
        if hits != expected:
            print(f"FAIL: MAKEFLAGS {value!r}: got {hits!r}, expected {expected!r}",
                  file=sys.stderr)
            return 1

    print("check_make_argv.py --self-test: all controls behave")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if len(sys.argv) not in (2, 3):
        print("invalid-argv")
        return 0
    try:
        argv = _read_procfs_list(sys.argv[1])
        if not argv or not argv[0]:
            raise ValueError("empty procfs argv")
        scanned = scan_argv_options(argv[1:])
        if scanned is None:
            raise ValueError("unparseable procfs argv")
        count, hits = scanned
        if len(sys.argv) == 3:
            # BOTH flag variables: GNU Make >= 4.4 additionally decodes
            # GNUMAKEFLAGS into switches (filename-argument forms like
            # `o <target>` included), so scanning MAKEFLAGS alone leaves a
            # silent exit-0 suppression channel on the documented bare-`make`
            # invocation wherever the caller's make binary is 4.4+.
            for entry in _read_procfs_list(sys.argv[2]):
                for var in ("MAKEFLAGS=", "GNUMAKEFLAGS="):
                    if entry.startswith(var):
                        hits += scan_makeflags_value(entry[len(var):])
                        break
    except (OSError, ValueError):
        print("invalid-argv")
        return 0

    if count > 1:
        print(f"multiple-makefiles:{count}")
    elif hits:
        print(f"no-execute-mode:{hits[0]}")
    else:
        print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
