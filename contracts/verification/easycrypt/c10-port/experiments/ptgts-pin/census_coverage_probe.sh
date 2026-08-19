# Does the CONE CENSUS actually cover cdrafts-split/C10DeployedScope.ec?
# "added=0" is ambiguous between "nothing new" and "never looked". This settles it.
set -u; cd /home/nicola/repos/c10-eufcma-port
ROOTS=$(while read -r n; do case "$n" in ''|\#*) continue;; esac; echo "cdrafts-split/$n.ec"; done < closure-c10-split.txt | tr '\n' ' ')
census () { CERT_CONE_DIRS="base-c10-split,cdrafts-split" python3 tools/cert_cone.py $ROOTS 2>/dev/null \
  | awk -F'\t' 'NF>=3{print $1"\t"$2"\t"$3}' | sort | uniq -c | sed 's/^ *//' \
  | awk '{k=$3; sub(/:.*/,"",k); n[k]+=$1}
         END{ printf "ledger=%d\n", n["admit"]+n["axiom"]+n["declare-axiom"]+n["refined-const"]+n["clone-discharge"]+n["op-annotation"]+n["clone-obligation"] }'; }
F=cdrafts-split/C10DeployedScope.ec
cp "$F" /tmp/scope_orig.ec
echo "BEFORE: $(census)"
printf '\naxiom census_probe_injected : 1 = 1.\n' >> "$F"
echo "WITH INJECTED AXIOM: $(census)"
cp /tmp/scope_orig.ec "$F"; rm -f /tmp/scope_orig.ec
echo "RESTORED: $(census)"
