import re, sys
# Replace a pinned LEMMA with an AXIOM of the same name and conclusion.
#
# FIXED 2026-08-19: `qed.` was matched with `^\s*qed\.` under re.M, which does not
# match this file's ONE-LINE proofs (`proof. by rewrite ... qed.`).  The helper
# then threw, the shell's `> "$T/ax.ec"` left an EMPTY file, that empty file was
# copied over the target, and stmt_digest returned NOT-FOUND -- the exact verdict
# the control tests for.  The control PASSED FOR THE WRONG REASON.  Both the
# unanchored match and the assertions below exist because of that.
path, name = sys.argv[1], sys.argv[2]
s = open(path, encoding='utf-8').read()
m = re.search(r'^lemma\s+' + re.escape(name) + r"(?![A-Za-z0-9_'])", s, re.M)
assert m, f'lemma {name} not found in {path}'
q = re.search(r'\bqed\.', s[m.start():])
assert q, f'no qed. after lemma {name} -- refusing to emit a truncated file'
out = s[:m.start()] + 'axiom ' + name + ' : ! (c <= c10_q_s).\n' + s[m.start() + q.end():]
assert len(out) > 0.8 * len(s), 'mutation lost >20% of the file -- refusing to emit'
sys.stdout.write(out)
