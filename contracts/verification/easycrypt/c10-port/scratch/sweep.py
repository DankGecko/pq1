#!/usr/bin/env python3
"""Comment-stripped admit/axiom sweep.  USE WORD BOUNDARIES.

An earlier ad-hoc version of this used the pattern `.admit.`, and `.` does not
match a newline in Python: the moment an `admit.` sat on its own line it
stopped being counted.  That under-reports -- the dangerous direction -- and it
put a wrong count in a commit message before it was caught (2026-08-07).
Counting gates must fail LOUD, so this one also asserts comment balance."""
import re, sys, pathlib

def strip_comments(t):
    out, d, i = [], 0, 0
    while i < len(t) - 1:
        if t[i:i+2] == "(*": d += 1; i += 2; continue
        if t[i:i+2] == "*)": d -= 1; i += 2; continue
        if d == 0: out.append(t[i])
        i += 1
    if d == 0: out.append(t[-1])
    return "".join(out), d

rc = 0
for f in sys.argv[1:]:
    s, d = strip_comments(pathlib.Path(f).read_text())
    if d != 0:
        print(f"{f}: UNBALANCED COMMENTS (depth {d})"); rc = 1; continue
    n = {w: len(re.findall(rf'\b{w}\b', s)) for w in ("admit", "axiom", "sorry")}
    print(f"{f}: admit={n['admit']} axiom={n['axiom']} sorry={n['sorry']}")
sys.exit(rc)
