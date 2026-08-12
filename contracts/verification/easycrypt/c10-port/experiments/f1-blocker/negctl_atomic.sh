set -u
cd /work
S=experiments/f1-blocker/shadowF1
cp $S/SPHINCS_PLUS.ec /tmp/spx_in.ec
printf '\nlemma NEGCTL_ATOMIC : false.\nproof. trivial. qed.\n' >> $S/SPHINCS_PLUS.ec
rm -f $S/SPHINCS_PLUS.eco
easycrypt compile -I $S -I drafts $S/SPHINCS_PLUS.ec >/dev/null 2>&1
rc=$?
cp /tmp/spx_in.ec $S/SPHINCS_PLUS.ec       # restore only AFTER the compile finished
rm -f $S/SPHINCS_PLUS.eco
echo "NEGCTL_ATOMIC_RC=$rc   (MUST be nonzero)"
echo "restored, NEGCTL present: $(grep -c NEGCTL_ATOMIC $S/SPHINCS_PLUS.ec)"
echo ATOMICDONE
