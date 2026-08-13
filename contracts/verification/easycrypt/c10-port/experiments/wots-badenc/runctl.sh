set -u; cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/controls
for f in CtlA CtlB CtlC CtlD; do
  rm -f "$C/$f.eco"
  easycrypt compile -I "$B" -I "$C" "$C/$f.ec" > "$C/$f.out" 2>&1
  echo "__RC_$f=$?" >> "$C/$f.out"
done
