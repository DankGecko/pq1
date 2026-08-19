#!/usr/bin/env bash
# CONTROL — do the six C10DeployedScope statement pins actually DISCRIMINATE?
#
# WHY THIS CONTROL AND NOT A COMPILE CONTROL.  These six lemmas have NO CONSUMER
# in the closure: weakening one to `true` leaves the file compiling and every
# other gate phase passing.  That is exactly the hole PHASE 1c exists to close,
# so the control has to attack the PIN, not the compile.  For each pinned lemma
# we replace its CONCLUSION with `true` -- an edit that DELETES information --
# and assert the digest MOVES.  A pin whose digest did not move would be
# decoration.
#
# Self-tested in the other direction too: a NO-OP edit (whitespace only) must
# leave the digest UNCHANGED, otherwise "the digest moved" would prove nothing.
set -u
cd "$(dirname "$0")/../.."
F=cdrafts-split/C10DeployedScope.ec
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cp "$F" "$T/orig.ec"
bad=0

pins="c10_c_closed c10_p_tgts_is_least c10_c_le_p_tgts_at_pin \
      c10_usage_cap_is_not_admissible_as_p_tgts c10_ht_capacity \
      c10_ht_capacity_vs_usage_cap"

for name in $pins; do
  base=$(python3 tools/stmt_digest.py "$F::$name" | cut -f2)
  # replace this lemma's statement body with `true` (conclusion deleted)
  python3 - "$F" "$name" <<'PY' > "$T/mut.ec"
import re,sys
path,name=sys.argv[1],sys.argv[2]
s=open(path,encoding='utf-8').read()
m=re.search(r'^(?:lemma|theorem)\s+'+re.escape(name)+r'(?![A-Za-z0-9_\'])',s,re.M)
p=re.search(r'^\s*proof\b',s[m.start():],re.M)
sys.stdout.write(s[:m.start()]+'lemma '+name+' : true.\n'+s[m.start()+p.start():])
PY
  cp "$T/mut.ec" "$F"
  mut=$(python3 tools/stmt_digest.py "$F::$name" | cut -f2)
  cp "$T/orig.ec" "$F"
  if [ "$base" = "$mut" ]; then
    echo "FAIL pin does NOT discriminate: $name ($base unchanged under conclusion deletion)"; bad=$((bad+1))
  else
    echo "OK   pin discriminates: $name  $base -> $mut"
  fi
done

# LEMMA -> AXIOM DOWNGRADE.  A statement pin defends against more than rewording.
# stmt_digest.py matches only `lemma|theorem|equiv|hoare|phoare`, so turning a
# pinned lemma into an `axiom` -- ASSUMING what was proved, the single most
# valuable edit available here -- cannot silently keep the digest.  It fails to
# resolve, and cert_gate_split.sh treats NOT-FOUND as a HARD FAIL ("statement pin
# does not resolve"), a rule added in run 13d precisely because a manifest row
# carrying the literal string NOT-FOUND once compared EQUAL to itself.
axname=c10_usage_cap_is_not_admissible_as_p_tgts
if ! python3 "$(dirname "$0")/_mutate_to_axiom.py" "$F" "$axname" > "$T/ax.ec"; then
  echo "FAIL axiom-downgrade: mutation helper errored -- control cannot run"; bad=$((bad+1))
fi
# SIZE GUARD.  Without this the control passes for the WRONG REASON: a helper
# that throws leaves an EMPTY $T/ax.ec, an empty .ec digests to NOT-FOUND, and
# NOT-FOUND is exactly the verdict being tested for.  Observed 2026-08-19.
osz=$(wc -c < "$T/orig.ec"); msz=$(wc -c < "$T/ax.ec")
if [ "$msz" -lt $(( osz * 8 / 10 )) ]; then
  echo "FAIL axiom-downgrade: mutant is $msz B vs original $osz B -- truncated, not downgraded"; bad=$((bad+1))
fi
cp "$T/ax.ec" "$F"
ax=$(python3 tools/stmt_digest.py "$F::$axname" | cut -f2)
cp "$T/orig.ec" "$F"
if [ "$ax" = "NOT-FOUND" ]; then
  echo "OK   axiom-downgrade: lemma -> axiom yields NOT-FOUND (gate hard-fails)"
else
  echo "FAIL axiom-downgrade: lemma -> axiom still resolved to $ax"; bad=$((bad+1))
fi

# NO-OP direction: trailing whitespace must NOT move any digest (the digest
# normalises whitespace, so if this moved, "it moved" would carry no signal).
base=$(python3 tools/stmt_digest.py "$F::c10_c_closed" | cut -f2)
sed 's/[[:space:]]*$//; s/$/ /' "$T/orig.ec" > "$F"
noop=$(python3 tools/stmt_digest.py "$F::c10_c_closed" | cut -f2)
cp "$T/orig.ec" "$F"
if [ "$base" = "$noop" ]; then echo "OK   no-op control: whitespace does NOT move the digest"
else echo "FAIL no-op control: whitespace moved the digest -- discrimination is meaningless"; bad=$((bad+1)); fi

echo "pin-discrimination: $((6-bad>6?0:6)) checked, failures=$bad"
[ "$bad" -eq 0 ] && echo "RESULT: OK" || echo "RESULT: BAD"
exit $bad
