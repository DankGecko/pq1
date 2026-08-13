set -u; cd /work
B=experiments/wots-badenc/base
easycrypt cli -iterate -I "$B" < "$B/BadEncCountermodel.ec" 2>&1 | tr '\r' '\n' > experiments/wots-badenc/dump.out
