set -u; cd /work
B=experiments/wots-badenc/base
rm -f "$B/BadEncCountermodel.eco"
easycrypt compile -I "$B" "$B/BadEncCountermodel.ec" > experiments/wots-badenc/cm.out 2>&1
echo "__RC=$?" >> experiments/wots-badenc/cm.out
