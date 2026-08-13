#!/usr/bin/env bash
# Does the FULL closure still build against the charged, admit-free base and the
# threaded XmssmtCC_All?  This is the completeness check for the mechanical part:
# XmssmtCC_All alone compiling proves nothing about files that REQUIRE it.
set -u
cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
O=experiments/wots-badenc/closure.out
rm -f "$O"
fail=0; n=0
while read -r f; do
  case "$f" in ''|\#*) continue;; esac
  n=$((n+1))
  easycrypt compile -I "$B" -I "$C" "$C/$f.ec" > /tmp/c.$f 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "OK   $f" >> "$O"
  else
    fail=$((fail+1))
    echo "FAIL $f rc=$rc" >> "$O"
    tr '\r' '\n' < /tmp/c.$f | grep -aE '^\[critical\]|^\[error\]' | head -2 | sed 's/^/       /' >> "$O"
  fi
done < closure-c10-split.txt
echo "### CLOSURE_FILES=$n FAILURES=$fail" >> "$O"
echo "__DONE" >> "$O"
