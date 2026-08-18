set -u; cd /work
R=""; while read -r n; do case "$n" in ''|\#*) continue;; esac; R="$R cdrafts-split/$n.ec"; done < closure-c10-split.txt
B=$(CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $R 2>/dev/null | wc -l)
A=$(CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $R cdrafts-split/WOTS_C_Multi.ec 2>/dev/null | wc -l)
echo "cone rows BEFORE: $B"
echo "cone rows AFTER : $A"
echo "delta           : $((A-B))"
