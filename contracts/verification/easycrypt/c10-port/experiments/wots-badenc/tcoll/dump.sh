set -u; cd /work
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
easycrypt cli -iterate -I "$B" -I "$C" -I "$T" < "$T/${1:-Dump1}.ec" 2>&1 | tr '\r' '\n' > "$T/dump.out"
