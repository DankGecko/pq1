set -u; cd /work
R=""; while read -r n; do case "$n" in ''|\#*) continue;; esac; R="$R cdrafts-split/$n.ec"; done < closure-c10-split.txt
CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $R 2>/dev/null | sort > /tmp/b.txt
CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $R cdrafts-split/WOTS_C_Multi.ec 2>/dev/null | sort > /tmp/a.txt
echo "=== THE 15 NEW ROWS ==="
comm -13 /tmp/b.txt /tmp/a.txt
echo "=== any ledger-class among them? ==="
comm -13 /tmp/b.txt /tmp/a.txt | grep -icE "admit|axiom" || echo 0
