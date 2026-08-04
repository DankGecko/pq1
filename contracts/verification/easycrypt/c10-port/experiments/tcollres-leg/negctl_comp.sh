set -u
cd /work
F=experiments/tcollres-leg/Composition.ec
cp $F /tmp/comp_in.ec
printf '\nlemma NEGCTL_COMP : false.\nproof. trivial. qed.\n' >> $F
rm -f ${F%.ec}.eco
easycrypt compile -I base-c10 -I cdrafts -I experiments/tcollres-leg $F >/dev/null 2>&1
rc=$?
cp /tmp/comp_in.ec $F
rm -f ${F%.ec}.eco
echo "NEGCTL_COMP_RC=$rc  (MUST be nonzero)"
echo "restored clean: $(grep -c NEGCTL_COMP $F)"
