set -u; cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
R=experiments/wots-badenc/red
K=$R/controls
for f in "$@"; do
  rm -f "$K/$f.eco"
  easycrypt compile -I "$B" -I "$C" -I "$T" -I "$R" -I "$K" "$K/$f.ec" > "$K/$f.out" 2>&1
  echo "__RC_$f=$?" >> "$K/$f.out"
done
