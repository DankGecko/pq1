#!/usr/bin/env python3
"""Regenerate lean/SphincsCVerify/CavpVectors.lean from the NIST CAVP corpus.

Source of truth: contracts/verification/cavp/SHA256{Short,Long}Msg.rsp +
SHA256Monte.rsp — the official NIST CAVP "SHA Test Vectors for Hashing
Byte-Oriented Messages" (CAVS 11.0/11.1; see cavp/README.md for provenance).

This embeds ALL ShortMsg + LongMsg (Len, Msg, MD) vectors plus the Monte
Carlo seed and its 100 checkpoint digests into a Lean module consumed by the
`verify-cavp` executable (lean/CavpMain.lean), which replays every vector
through the executable FIPS 180-4 spec `Spec.Sha256Impl.sha256Bytes` and the
SHAVS MCT procedure. This pins the SHA-256 transcription to the official
NIST suite instead of only the 10 project KATs.

.rsp parsing notes (empirically validated against hashlib before embedding):
  * Lines are CRLF-terminated — strip every line.
  * `Len` is the message length in BITS (always a multiple of 8 here; the
    suite is byte-oriented).
  * `Len = 0` means the EMPTY message: the `Msg` field still reads `00` but
    must be treated as zero bytes, not one.
  * SHA256Monte.rsp holds one `Seed` plus 100 `COUNT/MD` checkpoints of the
    SHAVS MCT: per checkpoint, MD[0..2] := seed; 1000 iterations of
    MD[i] = SHA-256(MD[i-3] || MD[i-2] || MD[i-1]); checkpoint = MD[1002];
    seed := checkpoint.

The generated file is deterministic: vectors are emitted in .rsp order
(which is ascending in Len), hex is lowercased, and the header carries no
timestamps.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CAVP = os.path.normpath(os.path.join(HERE, "../cavp"))
OUT = os.path.normpath(os.path.join(
    HERE, "../lean/SphincsCVerify/CavpVectors.lean"))


def parse_msg_rsp(path):
    """Parse a ShortMsg/LongMsg .rsp into [(len_bits, msg_hex, md_hex)]."""
    vectors = []
    length = msg = None
    for raw in open(path):
        line = raw.strip()
        if line.startswith("Len = "):
            length = int(line[len("Len = "):])
        elif line.startswith("Msg = "):
            msg = line[len("Msg = "):].lower()
        elif line.startswith("MD = "):
            md = line[len("MD = "):].lower()
            assert length is not None and msg is not None
            assert length % 8 == 0, "byte-oriented suite expects whole bytes"
            # Len = 0 means EMPTY message; the Msg field reads "00" but
            # must contribute zero bytes.
            if length == 0:
                msg = ""
            assert len(msg) == 2 * (length // 8), \
                "Msg hex length disagrees with Len at Len=%d" % length
            vectors.append((length, msg, md))
            length = msg = None
    return vectors


def parse_monte_rsp(path):
    """Parse SHA256Monte.rsp into (seed_hex, [checkpoint_md_hex; 100])."""
    txt = open(path).read()
    seed = re.search(r"Seed = ([0-9a-fA-F]+)", txt).group(1).lower()
    mds = []
    for count, md in re.findall(
            r"COUNT = (\d+)\s*\r?\nMD = ([0-9a-fA-F]+)", txt):
        assert int(count) == len(mds), "non-sequential COUNT in Monte rsp"
        mds.append(md.lower())
    assert len(mds) == 100, "expected 100 Monte checkpoints, got %d" % len(mds)
    return seed, mds


def emit_msg_list(out, name, doc, vectors):
    out.append("/-- %s -/" % doc)
    out.append("def %s : List CavpVector := [" % name)
    n = len(vectors)
    for i, (length, msg, md) in enumerate(vectors):
        comma = "," if i < n - 1 else ""
        out.append("  { lenBits := %d," % length)
        out.append('    msgHex := "%s",' % msg)
        out.append('    mdHex := "%s" }%s' % (md, comma))
    out.append("]")
    out.append("")


def main():
    short = parse_msg_rsp(os.path.join(CAVP, "SHA256ShortMsg.rsp"))
    long_ = parse_msg_rsp(os.path.join(CAVP, "SHA256LongMsg.rsp"))
    seed, monte = parse_monte_rsp(os.path.join(CAVP, "SHA256Monte.rsp"))

    out = []
    out.append("/- AUTO-GENERATED from contracts/verification/cavp/"
               "SHA256{Short,Long}Msg.rsp + SHA256Monte.rsp")
    out.append("   (NIST CAVP byte-oriented SHA-256 suite, CAVS 11.0/11.1 — "
               "see cavp/README.md).")
    out.append("   Do not edit by hand; regenerate via "
               "scripts/gen_cavp_vectors.py. -/")
    out.append("namespace SphincsCVerify.CavpVectors")
    out.append("")
    out.append("/-- One CAVP message/digest vector. `msgHex` is plain "
               "lowercase hex with NO")
    out.append("    `0x` prefix; empty string for the `Len = 0` vector. -/")
    out.append("structure CavpVector where")
    out.append("  /-- Message length in bits (multiple of 8). -/")
    out.append("  lenBits : Nat")
    out.append("  msgHex : String")
    out.append("  mdHex : String")
    out.append("  deriving Inhabited")
    out.append("")
    emit_msg_list(out, "shortMsgVectors",
                  "SHA256ShortMsg.rsp — %d vectors, Len 0..%d bits."
                  % (len(short), short[-1][0]), short)
    emit_msg_list(out, "longMsgVectors",
                  "SHA256LongMsg.rsp — %d vectors, Len %d..%d bits."
                  % (len(long_), long_[0][0], long_[-1][0]), long_)
    out.append("/-- SHA256Monte.rsp seed (lowercase hex, no prefix). -/")
    out.append('def monteSeedHex : String := "%s"' % seed)
    out.append("")
    out.append("/-- SHA256Monte.rsp — the %d checkpoint digests "
               "(COUNT = 0..%d)." % (len(monte), len(monte) - 1))
    out.append("    SHAVS MCT: per checkpoint, MD[0..2] := seed; 1000 "
               "iterations of")
    out.append("    MD[i] = SHA-256(MD[i-3] ‖ MD[i-2] ‖ MD[i-1]); "
               "checkpoint = MD[1002];")
    out.append("    seed := checkpoint. -/")
    out.append("def monteCheckpoints : List String := [")
    for i, md in enumerate(monte):
        comma = "," if i < len(monte) - 1 else ""
        out.append('  "%s"%s' % (md, comma))
    out.append("]")
    out.append("")
    out.append("end SphincsCVerify.CavpVectors")
    open(OUT, "w").write("\n".join(out) + "\n")
    print("wrote %s (%d short + %d long + %d monte checkpoints)"
          % (OUT, len(short), len(long_), len(monte)))


if __name__ == "__main__":
    main()
