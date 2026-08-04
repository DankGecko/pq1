#!/usr/bin/env bash
# ec-certify.sh <file.ec> — TRUE 0-admit cert: compile EXIT 0 AND (nested-comment-stripped) no admit
# TACTIC / axiom decl. EasyCrypt: admit is a WARNING (compile EXIT 0 even with admits); comments contain
# "admit" prose AND nest, so use an ITERATIVE nested-comment strip then match admit at a TACTIC position.
f="$1"
if bash scratch-ecc.sh "$f" >/dev/null 2>&1; then comp=OK; else comp=FAIL; fi
perl -0pe '1 while s/\(\*(?:(?!\(\*|\*\)).)*?\*\)//gs' "$f" > /tmp/_ecc_ns.ec 2>/dev/null
adm=$(grep -oE '(^|;|\||\+|-|\*|\]|first|last|by|=>|\s)\s*admit(ted)?\b' /tmp/_ecc_ns.ec | wc -l | tr -d ' ')
ax=$(grep -cE '(^|\n)\s*axiom\s+[A-Za-z_]' /tmp/_ecc_ns.ec | tr -d ' ')
echo "compile=$comp  admit-tactics=$adm  axiom-decls=$ax"
[ "$comp" = OK ] && [ "$adm" -eq 0 ] && [ "$ax" -eq 0 ] && echo "CERTIFIED-0-ADMIT" || echo "NOT-CERTIFIED"
