set -u
cd /work
S=experiments/wots-tw-incenc/shadow
run() {
  f="$1"
  out=$(easycrypt compile -I "$S" -I drafts "$S/$f" 2>&1)
  rc=$?
  echo "### $f rc=$rc"
  printf '%s\n' "$out" | tr '\r' '\n' | grep -aE '[A-Za-z]{4}' | grep -vaE '^\[.\] \[' | head -6
  if [ -f "${S}/${f%.ec}.eco" ]; then echo "    eco: YES"; else echo "    eco: NO"; fi
}
run WOTS_TW_ES.ec
run ShadowCanary.ec
run FL_SL_XMSS_MT_ES.ec
run FORS_ES.ec
run SPHINCS_PLUS.ec
echo "### ALLDONE"
