#!/usr/bin/env bash
# Checks the "extracted mechanically, one premise replaced" claim in
# PTgtsPinCapstone.ec / controls/CtlCapstone*.ec.
#
# WHY.  The generator asserted only that the OLD premise was PRESENT before it
# was replaced -- it could not detect drift anywhere ELSE in the 115-line
# statement, and a later edit to either side would break the claim silently.
# This re-derives the slice from the certified file and DIFFS it.
set -u
cd "$(dirname "$0")/../.."
python3 - "$@" <<'PY'
import sys, difflib

SRC   = 'cdrafts-split/C10DeployedCapstone.ec'
LO,HI = 280, 394                      # 1-indexed, inclusive: the lemma statement
OLD   = "    (* ---- the capstone's OWN premises, verbatim ---- *)\n    c <= p_tgts =>"

# (target file, new lemma name, replacement text for OLD)
CASES = [
 ('experiments/ptgts-pin/PTgtsPinCapstone.ec',
  'EUFCMA_SPHINCS_PLUS_C10_AT_PINNED_PTGTS',                     'p_tgts = c10_p_tgts =>'),
 ('experiments/ptgts-pin/controls/CtlCapstonePinOffByOne.ec',
  'CTL_EUFCMA_SPHINCS_PLUS_C10_AT_OFFBYONE_PIN',                 'p_tgts = ctl_p_tgts_lo =>'),
 ('experiments/ptgts-pin/controls/CtlCapstonePinPlusOne.ec',
  'CTL_EUFCMA_SPHINCS_PLUS_C10_AT_PIN_PLUS_ONE',                 'p_tgts = ctl_p_tgts_hi =>'),
 ('experiments/ptgts-pin/controls/CtlCapstoneNoPin.ec',
  'CTL_EUFCMA_SPHINCS_PLUS_C10_WITH_NO_PIN',                     None),   # premise deleted
]

ref = '\n'.join(open(SRC).read().split('\n')[LO-1:HI])
assert ref.startswith('lemma EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL_AT_DEPLOYED_ENCODER'), \
       'slice moved: %s:%d is no longer the lemma head' % (SRC, LO)
assert OLD in ref, 'the premise line is no longer where the generator found it'

bad = 0
for path, newname, repl in CASES:
    txt = open(path).read().split('\n')
    try:
        i = next(j for j, l in enumerate(txt) if l.startswith('lemma ' + newname))
        k = next(j for j, l in enumerate(txt) if j > i and l.rstrip() == 'proof.')
    except StopIteration:
        print('BROKEN %-52s lemma head or `proof.` not found' % path); bad += 1; continue
    got = '\n'.join(txt[i:k])
    # rebuild what it SHOULD be, from the certified source
    want = ref.replace('lemma EUFCMA_SPHINCS_PLUS_C10_CONTENTFUL_AT_DEPLOYED_ENCODER',
                       'lemma ' + newname, 1)
    if repl is None:
        # premise deleted outright: drop the whole OLD block
        want = want.replace(OLD + '\n', '', 1)
        # the control keeps a one-line marker comment in its place
        want = want.replace('lemma ' + newname,
                            'lemma ' + newname, 1)
        got  = '\n'.join(l for l in got.split('\n')
                         if 'CONTROL DELTA' not in l)
    else:
        want = want.replace(OLD, '    ' + repl, 1)
        got  = '\n'.join(l for l in got.split('\n')
                         if 'CONTROL DELTA' not in l and 'THE ONLY DELTA' not in l
                            and not l.strip().startswith('capstone corollary')
                            and 'PTgtsPin.c10_c_le_p_tgts_at_pin' not in l
                            and 'other premise, and the entire conclusion' not in l
                            and 'C10DeployedCapstone.ec:280-394 -- extracted' not in l
                            and 'retyped. ---- *)' not in l)
        want = '\n'.join(l for l in want.split('\n') if l.strip())
        got  = '\n'.join(l for l in got.split('\n')  if l.strip())
    want = '\n'.join(l for l in want.split('\n') if l.strip())
    got  = '\n'.join(l for l in got.split('\n')  if l.strip())
    if want == got:
        print('OK     %-52s statement matches the certified slice' % path)
    else:
        bad += 1
        print('BROKEN %-52s statement DRIFTED from the certified slice' % path)
        for d in list(difflib.unified_diff(want.split('\n'), got.split('\n'),
                                           'expected', 'found', lineterm=''))[:24]:
            print('       ' + d)
print('### STATEMENT-IDENTITY: %d broken' % bad)
sys.exit(1 if bad else 0)
PY
