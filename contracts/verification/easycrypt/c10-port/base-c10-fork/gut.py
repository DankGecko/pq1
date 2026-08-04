#!/usr/bin/env python3
"""Gut every proof body EXCEPT the ones overlapping a target line range.

WHY. Repairing the gated game needs ~92 tactic-arity fixes inside
`section Proof_M_EUF_GCMA_WOTS_TW_ES_NPRF` (:2909-:6358). A full compile of
WOTS_TW_ES.ec is 2-4 minutes, and EasyCrypt reports ONE error per run, so the
naive loop is hours of mostly-waiting.

`ec-goal.sh`'s own header documents the fix: replace every OTHER proof body with
`admit.` -- "goal states inside your target proof stay byte-identical, and it
compiles in seconds". This is that, scripted.

Usage:  gut.py SRC DST KEEP_FROM KEEP_TO
Keeps proof bodies that overlap [KEEP_FROM, KEEP_TO]; guts all others.

SAFETY. The output is a THROWAWAY fast-loop artifact and must never be compiled
as a receipt -- it is full of admits by construction. Fixes found on it are
applied to the real file and re-verified there.
"""
import sys, re

def main():
    src, dst = sys.argv[1], sys.argv[2]
    lo, hi = int(sys.argv[3]), int(sys.argv[4])
    lines = open(src).read().split("\n")
    out, i, n, gutted, kept = [], 0, len(lines), 0, 0
    while i < n:
        ln = lines[i]
        # a proof body opens on a line that is exactly `proof.` (possibly indented)
        if re.match(r"^\s*proof\.\s*$", ln):
            start = i
            j = i + 1
            depth_ok = True
            while j < n and not re.match(r"^\s*(qed|abort)\.\s*$", lines[j]):
                j += 1
            if j >= n:
                out.append(ln); i += 1; continue
            # 1-indexed line numbers of the body
            body_lo, body_hi = start + 1, j + 1
            overlaps = not (body_hi < lo or body_lo > hi)
            if overlaps:
                out.extend(lines[start:j + 1]); kept += 1
            else:
                out.append(ln)
                out.append("admit.")
                out.append(lines[j])
                gutted += 1
            i = j + 1
            continue
        out.append(ln); i += 1
    open(dst, "w").write("\n".join(out))
    sys.stderr.write(f"gutted={gutted} kept={kept}\n")

main()
