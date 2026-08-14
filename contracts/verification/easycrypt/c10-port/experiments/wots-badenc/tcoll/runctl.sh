set -u; cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
K=$T/controls
for f in CtlA CtlB CtlC CtlD CtlE CtlF; do
  rm -f "$K/$f.eco"
  easycrypt compile -I "$B" -I "$C" -I "$T" -I "$K" "$K/$f.ec" > "$K/$f.out" 2>&1
  echo "__RC_$f=$?" >> "$K/$f.out"
done
