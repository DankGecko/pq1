set -u
cd /work
eval $(opam env 2>/dev/null) || true
easycrypt compile -I base-c10-split -I cdrafts-split cdrafts-split/WOTS_C_Bridge.ec > /work/scratch/wcm/Bridge2.log 2>&1
echo "RERUN RC=$?" >> /work/scratch/wcm/summary.txt
