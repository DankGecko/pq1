set -u; cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
R=experiments/wots-badenc/red
F=${1:-BadEncToTColl}
easycrypt cli -iterate -I "$B" -I "$C" -I "$T" -I "$R" < "$R/$F.ec" 2>&1 | tr '\r' '\n' > "$R/$F.dump"
