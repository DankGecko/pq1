set -u; cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
R=experiments/wots-badenc/red
printf 'require import BadEncStep4.\nprint badenc_le_tcoll.\nprint query_eq_badenc.\n' \
  | easycrypt cli -I "$B" -I "$C" -I "$T" -I "$R" 2>&1 | tr '\r' '\n' > "$R/printstmt.out"
