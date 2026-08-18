set -u
cd /work
eval $(opam env 2>/dev/null) || true
for f in WOTS_C_Multi WOTS_C_Bridge; do
  echo "=== $f ==="
  easycrypt compile -I base-c10-split -I cdrafts-split cdrafts-split/$f.ec > /work/scratch/wcm/$f.log 2>&1
  echo "RC=$? $f" | tee -a /work/scratch/wcm/summary.txt
done
echo DONE >> /work/scratch/wcm/summary.txt
