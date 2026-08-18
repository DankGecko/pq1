kimi version 0.36.0
• This is a research/analysis task. Read-only. I need to read actual source files in `/home/nicola/repos/c10-eufcma-port` (EasyCrypt files, experiments/, etc.) and `/home/nicola/repos/PQSigner_OS` (CLAUDE.md, params.rs). Mark claims VERIFIED (file:line) or INFERRED. Compile-test anything cited from experiments/.

  This is a big investigation. I should delegate heavy exploration to subagents, but I also need to do the reasoning myself. Let me plan:

  1. Read `experiments/ptgts-pin/PTgtsPin.ec` — the c = 262656 pin.
  2. Read `experiments/wots-badenc/count/` — the surface count.
  3. Read `PQSigner_OS/CLAUDE.md` — P14 caveat, MAX_SLOT_USES.
  4. Read `params.rs` — H=18 D=2 SUBTREE_H=9.
  5. Find where T_COLL_RES_ENUM is defined in the main proof tree, what q means in it (signatures, WOTS instances, S-TCR targets).
  6. Check which key feeds the term — slot keys chain-bound vs bootstrap key.

  Also compile-test anything cited from experiments/. That's heavy — six files are stale and Extraction.ec doesn't compile. The user says compile-test anything I cite from experiments/. Running EasyCrypt could be slow. Maybe I can check which files compile with a quick easycrypt invocation if easycrypt is installed. But the user says do not run cert_gate_split.sh (container-only). Running easycrypt directly on specific files may be feasible.

  Let me delegate: spawn explore agents in parallel:

  - Agent A: PQSigner_OS — CLAUDE.md P14, params.rs, MAX_SLOT_USES, slot key vs bootstrap key, which key feeds WOTS/TCR targets, chain-binding. VERIFIED file:line.
  - Agent B: c10-eufcma-port — T_COLL_RES_ENUM definition, where q/q_s appears, what it counts, the advantage bound expression, experiments/ptgts-pin/PTgtsPin.ec, experiments/wots-badenc/count.

  Then I do the cryptographic reasoning and possibly compile tests.

  Actually compile-testing: I should check if easycrypt is available on host. Let me do that myself quickly.

  Let me start with parallel explore agents plus a quick Bash check for easycrypt.

  The reasoning questions (Q1, Q4) are crypto judgment — I do that myself.

  Let me write detailed prompts.

  Agent B needs to answer: what does T_COLL_RES_ENUM quantify over, what is q in the term, how many targets per signature (d=2 WOTS instances? S-TCR targets), where the q_s² · 2^-114.09 expression comes from, what PTgtsPin.ec pins, the wots-badenc count.

  Also check: is the term's q the adversary's signing query count to the EUF-CMA oracle? In the proof, the WOTS leg likely bounds Pr[T_COLL_RES_ENUM] ≤ (something with number of recorded targets)² / 2^114... Actually "q_s² · 2^-114.09" — collision among q_s targets? Need source.

  Let me launch two explore agents in parallel, plus check easycrypt availability.

• I'll attack this by reading the actual sources in both repos first, then doing the crypto reasoning. Launching two parallel investigations plus an environment check./home/nicola/.opam/checkct/bin/easycrypt
Error: easycrypt: unknown option '-version'.

Usage: easycrypt [command] [options...] [args...]
f1-blocker
ptgts-pin
tcollres-leg
wots-badenc
wots-tw-incenc


• The explore agents did a thorough job. Now I need to compile-test anything I cite from experiments/. The user said: "Compile-test anything you cite from `experiments/`". The files I'd cite:

  - `experiments/ptgts-pin/PTgtsPin.ec` (and PTgtsPinCapstone.ec)
  - `experiments/wots-badenc/count/` files (C10SurfaceKernel.ec, C10Surface.ec, CountDS.ec)
  - `experiments/wots-badenc/tcoll/TCollResEnum.ec`
  - `experiments/wots-badenc/red/BadEncStep4.ec`

  Six files there are stale and Extraction.ec doesn't compile. So I should try compiling the ones I cite. That could take a while — C10SurfaceKernel took 41s compute per the note. Let me compile-test the key ones I lean on: PTgtsPin.ec, and the count files, and TCollResEnum.ec. BadEncStep4 might be one of the stale six.

  How do these compile? They probably require the EasyCrypt library path and maybe the repo's own files. Check for an easycrypt.project or how they're normally compiled. There may be a script. Let me check what's in experiments/ dirs and if there's a known compile command (maybe in PROVENANCE.md or the gate script, which I must not run but can read).

  Let me read the gate script to learn the compile invocation (read-only is fine), and PROVENANCE.md, then run easycrypt on specific files in background.

  Also I want to verify key quotes myself — but the agents gave file:line. I should spot-check a few load-bearing lines myself? The user demands marking claims VERIFIED (file:line) — the subagent verification counts, but for the strongest claims I might quickly Read a few key spots: PTgtsPin.ec section 5, TCollResEnum.ec main, XmssmtCC_All.ec eager choose. Given time constraints, spot-check the most load-bearing ones: PTgtsPin.ec:247-307 (section 5), and the eager reduction claim at XmssmtCC_All.ec:772-856, since "eager reduction makes nrts = c" is my strongest objection. Also TCollResEnum.ec:265-301.

  Plan:
  1. Read gate script header for compile invocation + PROVENANCE.md.
  2. Spot-read PTgtsPin.ec section 5, XmssmtCC_All.ec eager loop, TCollResEnum main.
  3. Kick off compile tests in background for the experiments files I cite.
  4. Compose the answer.

  The crypto reasoning (Q1, Q4, Q5) is mine.

  Let me start: find how files are compiled.#!/usr/bin/env bash
# Certification gate for the SPLIT tree (base-c10-split + cdrafts-split).
# Added 2026-08-01: the second adversarial review found that cert_gate_fork.sh
# watches ONLY the fork, so every "26/26" result for the split was an ad-hoc run
# with no gate behind it.  A result nothing enforces is not a receipt.
set -u
set -o pipefail
# LOCALE PINNING (added 2026-08-02, found while re-verifying a GREEN receipt).
# INPUTS_SHA256 hashes `sha256sum` lines emitted in `sort -u` order.  glibc
# collation is locale-dependent, so the SAME clean tree hashed to
#   45c4a166... in the container (LC_ALL unset -> POSIX)
#   fa7a6e6f... on the host      (en_US.UTF-8)
# -- identical file SET, different ORDER (STCR_C / XmssmtCC_All / XmssmtCCCharged).
# The identity line was therefore an identity of (tree, locale), not of the tree:
# a third party recomputing it in another locale sees a mismatch and concludes
# drift that does not exist.  I nearly concluded exactly that about this receipt.
# `sort -u` also collapses distinct strings that COLLATE equal in UTF-8 locales,
# which could silently undercount the control inventory (fail-closed, but wrong).
export LC_ALL=C
# CWD GUARD (run 10).  cert_gate_fork.sh does `cd /work`; this one trusted the
# caller's directory, so an invocation from elsewhere would fail every phase
# for a reason unrelated to the tree.  Assert the inputs are actually here.
for f in closure-c10-split.txt cert-baseline-split.tsv cert-statements-split.tsv \
         cert-controls-split.tsv tools/cert_cone.py tools/stmt_digest.py; do
  [ -e "$f" ] || { echo "FAIL wrong working directory: $f not found ($(pwd))"; exit 2; }
done
B=base-c10-split; D=cdrafts-split; INC="-I $B -I $D"
CLOSURE=closure-c10-split.txt; BASELINE=cert-baseline-split.tsv; STMTS=cert-statements-split.tsv
TMPD=$(mktemp -d) || { echo 'FAIL mktemp'; exit 1; }
trap 'rm -rf "$TMPD"' EXIT
# Expected inventory sizes, COMMITTED. A guard that recomputes its expectation
# from the file it is checking cannot detect truncation of that file.
EXPECT_PINS=111
# COMMITTED WATCHED-ROW COUNT (2026-08-10).  This replaced a `-ge 3` floor when
# T1/T2/T3 were PROMOTED into closure-c10-split.txt: a floor cannot express
# "there are deliberately none left", so retiring the last watched row would
# have read as manifest truncation and failed the gate.  An exact committed
# count is strictly STRONGER than the floor it replaces -- it catches an
# unexpected ADDITION as well as a truncation -- and it keeps the anti-fail-open
# intent in a number that has to be moved on purpose.
# Editing this script is the cheapest possible way to weaken the gate, and
# PHASE 2b/2c canary the census tool, not this guard.  So the replacement was
# tested before being committed -- but state the test HONESTLY: it was an
# ISOLATED-LOGIC test of these two lines against doctored row counts, NOT a
# full gate run with a bogus manifest row.  Results: 0 rows -> passes; 1 row ->
# fires; 3 rows -> fires, which is exactly the case the old `-ge 3` floor would
# have let through.  What that does NOT cover is the integration -- that
# `w_run` is still incremented as this phase's loop expects.  A full run with a
# deliberately re-added row is the check that would close that, and it has not
# been done.
EXPECT_WATCHED=0
fail=0

# TREE IDENTITY AND TOOLCHAIN, in the receipt itself.  A green receipt that does
# not say WHICH tree and WHICH prover produced it is not reproducible: adversarial
# review run 7 found four closure files failing as targets under r2026.06 while
# this container runs r2026.02, and no gate recorded either fact.
# The run-7 tree-identity line printed UNKNOWN every time.  git IS installed in
# the container; it refuses the bind-mounted /work (ownership/safe.directory), so
# `git rev-parse` never succeeded there.  My first diagnosis said git was absent
experiments/ptgts-pin:
check_stmt_identity.sh
controls
ec.sh
gate_after.out
PTgtsPinCapstone.ec
PTgtsPinCapstone.eco
PTgtsPinCapstone.out
PTgtsPin.ec
PTgtsPin.eco
PTgtsPin.out
receipt.txt
runall.sh
run.sh

experiments/wots-badenc:
base
cd
closure.out
cm.out
controls
count
ctlw.out
down.out
dump.out
dump.sh
ext.out
ext.sh
mkctl.sh
new.out
PREDICTION.md
probe
probe.out
red
RESULT.md
runclosure.sh
runcm.sh
runctl.sh
runctlw.sh
rundown.sh
runnew.sh
run.out
runprobe.sh
run.sh
runxm.sh
setup.sh
tcoll
xm.out

experiments/wots-badenc/count:
C10Surface.ec
C10Surface.eco
C10SurfaceKernel.ec
C10SurfaceKernel.eco
C10SurfaceKernel.out
C10Surface.out
controls
CountDS.ec
CountDS.eco
CountDS.out
ec.sh
README.md
receipt.txt
runall.sh
run.sh
ScriptProbe.ec
ScriptProbe.eco
ScriptProbe.out
VecDP.ec
VecDP.eco
VecDP.out
verify.out
PTgtsPin.ec section 5 confirmed. Now compile-test the experiments files I cite. There are ec.sh / run.sh scripts in those dirs. Let me check ec.sh to see invocation, then run compile tests in background for: PTgtsPin.ec, count files (C10Surface.ec, C10SurfaceKernel.ec, CountDS.ec), TCollResEnum.ec, BadEncStep4.ec. Note six files in experiments are stale — I should find which. Maybe just try compiling all cited ones.

  Also spot-check the eager reduction at cdrafts-split/XmssmtCC_All.ec:772-856 (certified tree, not experiments — no compile test needed, but verify claim). And TCollResEnum.ec main win condition.

  Let me look at ec.sh files first.

• PTgtsPin section 5 confirmed verbatim. Now the compile harness and the two remaining spot-checks.#!/usr/bin/env bash
# host-side wrapper: bash ec.sh <relpath-without-.ec>
set -u
sg docker -c "docker exec ec-grind bash -lc 'eval \$(opam env 2>/dev/null); bash /work/experiments/ptgts-pin/run.sh $1'" >/dev/null 2>&1
d=/home/nicola/repos/c10-eufcma-port/experiments/ptgts-pin
echo "== $1 : $(tr '\r' '\n' < $d/$1.out | grep -E '__RC=|__WALL_MS|__ECO' | tr '\n' ' ')"
tr '\r' '\n' < "$d/$1.out" | grep -vE '^\[[|/\\-]\] \[[0-9]+\]' | grep -vE '^\s*$' | grep -vE '^__' | head -20
#!/usr/bin/env bash
# Compile one file from experiments/ptgts-pin/ (or ptgts-pin/controls/) against
# the SPLIT certified trees, READ-ONLY: -I base-c10-split -I cdrafts-split.
# Deletes only the TARGET's .eco so nothing is served from its own stale cache;
# the certified trees' .eco are left alone (they are gitignored build artifacts
# and are NOT rebuilt by this script).
set -u
cd /work
D=experiments/ptgts-pin
p="${1:?usage: run.sh <relpath-without-.ec>}"
O="$D/$p.out"
rm -f "$D/$p.eco" "$O"
[ -n "${STK:-}" ] && { ulimit -s "$STK" 2>/dev/null || true; }
t0=$(date +%s%N)
easycrypt compile ${EXTRA:-} -I base-c10-split -I cdrafts-split -I "$D" -I "$D/controls" "$D/$p.ec" > "$O" 2>&1
rc=$?
t1=$(date +%s%N)
echo "__RC=$rc" >> "$O"
echo "__WALL_MS=$(( (t1 - t0) / 1000000 ))" >> "$O"
if [ -f "$D/$p.eco" ]; then echo "__ECO=yes $(stat -c %s "$D/$p.eco")" >> "$O"; else echo "__ECO=NO" >> "$O"; fi
===
#!/usr/bin/env bash
# Compile one file from experiments/wots-badenc/count/ (or count/controls/).
# Deletes ALL project .eco first so nothing is served from a stale cache.
set -u
cd /work
D=experiments/wots-badenc/count
p="${1:?usage: run.sh <relpath-without-.ec>}"
O="$D/$p.out"
rm -f "$D/$p.eco" "$O"   # full clean is done by the final -check-all receipt run
[ -n "${STK:-}" ] && { ulimit -s "$STK" 2>/dev/null || true; }
t0=$(date +%s%N)
easycrypt compile ${EXTRA:-} -I "$D" -I "$D/controls" "$D/$p.ec" > "$O" 2>&1
rc=$?
t1=$(date +%s%N)
echo "__RC=$rc" >> "$O"
echo "__WALL_MS=$(( (t1 - t0) / 1000000 ))" >> "$O"
if [ -f "$D/$p.eco" ]; then echo "__ECO=yes $(stat -c %s "$D/$p.eco")" >> "$O"; else echo "__ECO=NO" >> "$O"; fi
===
experiments/wots-badenc/red:
BadEncSplit.ec
BadEncSplit.eco
BadEncSplit.out
BadEncStep4.dump
BadEncStep4.ec
BadEncStep4.eco
BadEncStep4.out
BadEncToTColl.dump
BadEncToTColl.ec
BadEncToTColl.eco
BadEncToTColl.out
controls
dump.sh
mkctl4.sh
mkctl.sh
printstmt.out
printstmt.sh
runctl.sh
run.sh
Smoke.ec
Smoke.eco
Smoke.out
Step4Probe.dump
Step4Probe.ec
Step4Probe.goal
Step4Probe.out

experiments/wots-badenc/tcoll:
controls
dump.out
dump.sh
mkctl.sh
runctl.sh
run.sh
tcoll.out
TCollResEnum.ec
TCollResEnum.eco


• Eager reduction confirmed: `choose` loops over all d layers, all trees, all l' leaves, calling `O.query` per leaf — registering all c = 2^18+2^9 targets regardless of adversary's signing requests. VERIFIED at XmssmtCC_All.ec:801-855.

  Now compile-test the experiments files I cite. The harness uses docker (`ec-grind` container, `/work`). ec.sh runs via `sg docker -c "docker exec ec-grind ..."`. User said do not run cert_gate_split.sh (container-only) — but running easycrypt compile on individual experiment files via docker exec should be OK? The user said "Compile-test anything you cite from experiments/". The prohibition was specifically on cert_gate_split.sh. The host also has easycrypt at ~/.opam/checkct/bin/easycrypt. But host easycrypt version may differ (r2026.06 vs container r2026.02; the gate notes four closure files fail under r2026.06). For experiments files, the receipts were generated in the container. Using the container via docker exec matches how these .out files were made.

  Hmm — is docker available and container running? Let me check. Actually the user said "Compile-test anything you cite" — so they expect me to run compiles. The ec.sh wrapper is exactly for that. But ec.sh deletes the target's .eco (run.sh does `rm -f "$D/$p.eco" "$O"`) — that's a modification of files in the repo! READ-ONLY constraint: "Do not modify any file." Deleting .eco and rewriting .out files modifies files. Hmm. .eco/.out are build artifacts, gitignored. But strictly, running run.sh would delete and recreate them. Risky under "READ-ONLY. Do not modify any file."

  Safer: compile to a different output location without touching the repo. easycrypt compile writes .eco next to the source by default. Can I avoid that? Options: copy the source tree? That's huge. Or compile with the source file but .eco goes alongside... Actually easycrypt writes the .eco in the same directory as the .ec file being compiled. To be strictly read-only, I could copy the experiments dir to /tmp and compile there with -I pointing at the repo's base-c10-split and cdrafts-split (read-only include paths; but easycrypt may also write .eco for dependencies in those include dirs if they're stale/missing... they exist already, so it would just read them).

  Actually careful: if the -I dirs' .eco files are present and fresh, easycrypt reads them, doesn't rewrite. The compiled target in /tmp writes its .eco in /tmp. That keeps the repo untouched.

  Let me check docker availability first: `docker ps` to see ec-grind. But `sg docker` — the user may not be in docker group in my shell context. Let me test.

  Which files do I actually cite from experiments/?
  - experiments/ptgts-pin/PTgtsPin.ec — core.
  - experiments/wots-badenc/count/C10SurfaceKernel.ec, C10Surface.ec, CountDS.ec — the count.
  - experiments/wots-badenc/tcoll/TCollResEnum.ec — the term definition.
  - experiments/wots-badenc/red/BadEncStep4.ec — the reduction badenc_le_tcoll.
  - scratch findings are not in experiments/, no compile needed.

  The user says six files in experiments are stale and Extraction.ec doesn't compile. So some of these may fail. I should compile-test and report which pass/fail. If BadEncStep4.ec is stale, I need to note that.

  Plan: create /tmp/ec-compile-test, copy the specific .ec files preserving relative layout? The count files compile standalone with -I count dir. PTgtsPin needs -I base-c10-split -I cdrafts-split. TCollResEnum and BadEncStep4 need their own -I sets (check their run.sh).

  Let me read the run.sh for tcoll and red dirs, and check docker.

• Eager reduction confirmed at `XmssmtCC_All.ec:801-855`. Now compile-testing — but strictly read-only, so I'll compile from `/tmp` copies rather than letting `run.sh` delete/rewrite `.eco`/`.out` artifacts in the repo.easycrypt compile -I "$B" -I "$C" -I "$T" "$T/TCollResEnum.ec" > "$O" 2>&1
easycrypt compile -I "$B" -I "$C" -I "$T" -I "$R" "$R/$F.ec" > "$O" 2>&1
===
ec-grind
===
ec-grind


B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
B=experiments/wots-badenc/base
C=experiments/wots-badenc/cd
T=experiments/wots-badenc/tcoll
R=experiments/wots-badenc/red
experiments/wots-badenc/tcoll/run.sh:B=experiments/wots-badenc/base
experiments/wots-badenc/tcoll/run.sh:C=experiments/wots-badenc/cd
experiments/wots-badenc/tcoll/run.sh:T=experiments/wots-badenc/tcoll
experiments/wots-badenc/tcoll/run.sh:O=$T/tcoll.out
experiments/wots-badenc/tcoll/run.sh:echo "__RC=$?" >> "$O"
experiments/wots-badenc/red/run.sh:B=experiments/wots-badenc/base
experiments/wots-badenc/red/run.sh:C=experiments/wots-badenc/cd
experiments/wots-badenc/red/run.sh:T=experiments/wots-badenc/tcoll
experiments/wots-badenc/red/run.sh:R=experiments/wots-badenc/red
experiments/wots-badenc/red/run.sh:F=${1:-BadEncToTColl}
• tcoll/red compile against experiments-local base/cd copies, not the certified split trees. Interesting — TCollResEnum compiles against experiments/wots-badenc/base and cd. BadEncStep4 also uses those plus tcoll.

  Now set up the read-only compile in the container: copy needed source dirs to /tmp inside the container? The container has /work bind-mounted to the repo. I can copy within container to /tmp: `docker exec ec-grind bash -lc 'cp -r /work/experiments /tmp/xp ...'`. But the -I include dirs (base-c10-split, cdrafts-split, experiments/wots-badenc/base, cd) — if I compile with -I pointing to /work dirs (read-only bind mount? check if /work is mounted read-only). If /work is rw, easycrypt might write .eco into include dirs if stale. Their .eco exist and are presumably fresh. To be safe, copy everything needed to /tmp in the container and compile there. Size? Let me check du of those dirs. Probably fine (text files).

  Plan in container:
  ```
  rm -rf /tmp/ectest && mkdir -p /tmp/ectest
  cd /work
  cp -r base-c10-split cdrafts-split /tmp/ectest/
  mkdir -p /tmp/ectest/experiments/{ptgts-pin,wots-badenc}
  cp -r experiments/ptgts-pin /tmp/ectest/experiments/
  cp -r experiments/wots-badenc/{base,cd,tcoll,red,count} /tmp/ectest/experiments/wots-badenc/
  ```
  Then compile each target, deleting its .eco first inside /tmp copy only.

  Targets:
  1. experiments/ptgts-pin/PTgtsPin.ec with -I base-c10-split -I cdrafts-split -I dir -I controls
  2. experiments/wots-badenc/count/{CountDS,C10SurfaceKernel,C10Surface}.ec with -I count dir (+controls). Note C10SurfaceKernel takes ~41s+ compute. Order: CountDS, then C10SurfaceKernel, then C10Surface (may require the others).
  3. experiments/wots-badenc/tcoll/TCollResEnum.ec with -I base -I cd -I tcoll.
  4. experiments/wots-badenc/red/BadEncStep4.ec and BadEncToTColl.ec with -I base -I cd -I tcoll -I red.

  These might be among the "six stale files". Run in background with generous timeout. Use `sg docker -c "docker exec ec-grind bash -lc '...'"`.

  Note: cp -r includes .eco files — fine, they serve as cache for includes; for targets I'll rm the .eco first.

  Let me write the script and run in background.

• Container is up. Setting up a `/tmp` mirror inside it so the repo stays untouched, then compiling every `experiments/` file I cite.16M	/tmp/ectest
SETUP_OK


• While compiles run, let me spot-check TCollResEnum.ec main win condition and the count README gap statement, plus the certified capstone RHS (four terms, no T-COLL). Also scratch/FINDING-do-not-import-the-policy-cap.md since it's directly on-topic (not in experiments/, no compile needed).          R_top_C(F).  This is a PROVEN upper bound on the UNCHANGED LHS; the four
          terms are a DIFFERENT concrete RHS from a hypothetical R_top(F) one, not
          claimed numerically equal (see header (1)).  LeqPr_VF_C already lands on
          R_top_C(F), so the sole reconciliation is the FC.O<->TRHC.O oracle-clone
          hop, discharged by RtopCSoundness.oracle_clone_hop_C. ITSRC10 stays fg). *)
       + ( Pr[M_EUF_GCMA_WOTSTWESNPRF(R_int_WOTSTW(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                                      O_MEUFGCMA_WOTSTWESNPRF, FC.O_THFC_Default).main() @ &m : res]
           + Pr[S_TCR_C_Int_MA(R_int_STCRC(R_MEUFGCMAWOTSC_EUFNAGCMA_C(R_top_C(F))),
                               STCRC_WC.O_STCRC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.PKCOC_TCR.SM_DT_TCR_C(R_SMDTTCRCPKCO_C(R_top_C(F)),
                  FSSLXMTWES.PKCOC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.PKCOC.O_THFC_Default).main() @ &m : res]
           + Pr[FSSLXMTWES.TRHC_TCR.SM_DT_TCR_C(R_SMDTTCRCTRH_C(R_top_C(F)),
                  FSSLXMTWES.TRHC_TCR.O_SMDTTCR_Default,
                  FSSLXMTWES.TRHC.O_THFC_Default).main() @ &m : res] ).
proof.
  move=> hc hmkg hencb hN2 hdf8n hdflen hdf2 hdfnk htree.
  (* ---- member axes at A_ht := R_top_C(F): ALL FOUR DISCHARGED via the PROVEN
     ports (RtopCSoundness, 2026-07-24 hop6b closure).  A_wf_ht (member/dfC0 axis) via
     R_top_C_A_wf_ht (= R_top_C_members4 collapsed by all_in_thfc4_neq_dfC); the
     chtype/pkco/trh axes via R_top_C_allnchads/_allnpkcoads/_allntrhads.  Each is a
====
`2^-14.9059`) written as integer inequalities, so no reals are involved. The
powers are evaluated with the same reducible-structural trick (`powl` + `powlE`).

---

## What is **NOT** proved — the `emsgWOTS` gap, enumerated

The counted objects here are `int list`s. **They are not WOTS codewords, and this
directory must not be cited as counting codewords.** To turn
`count_ds 43 8 205 = |C_T|` into a statement about `WOTS_TW_ES.ec`'s
constant-sum surface, all five of the following would have to be supplied:

1. **`len` is abstract.** `WOTS_TW_ES.ec:74` declares `const len : { int | 2 <= len }`.
   Nothing links it to `C10DeployedGeometry.ec:69`'s `c10_len = 43`.
2. **`w` is abstract.** `WOTS_TW_ES.ec:97` gives only `val_w : 4 <= w`. Nothing
   links it to `c10_w = 8`, and nothing establishes that `BaseW.val` ranges
   bijectively over `[0,8)`.
3. **`target_sum` is not 205.** `WOTS_TW_ES.ec:647` *defines*
   `target_sum = digitsum (encode_msgWOTS tgt_witness)` — deliberately, so the
   gate is non-vacuous. `C10DeployedGeometry.ec:101-104` says in as many words
   that "205 is attainable" is proved while "the deployed encoder reaches 205" is
   **not** claimed.
4. **No bridge from `emsgWOTS` to `int list`.** `emsgWOTS` is a `Word` clone
   (`WOTS_TW_ES.ec:275-284`) over the `baseW` subtype with
   `Alphabet.enum = map (oget \o BaseW.insub) (range 0 w)`. Connecting it needs a
   `FinType`/enumeration for `emsgWOTS`, a bijection with length-`len` digit
   lists, and `digitsum e = sumz (that list)` — none of which exists here.
5. **Surface size is not fibre size.** Even fully bridged, `|C_T|` counts
   *codewords*. `T_COLL_RES_ENUM`'s B2 branch is about *messages* colliding
   through `encode_msgWOTS`; the ~2^127-wide fibres are a separate object.

An honest one-line summary: **the number is now a theorem; its identification
with the codeword surface is still prose.**

Likewise, the `~2^71.95` birthday figure in the FINDING is **not** mechanised
here — it needs `sqrt` over reals. T4 gives the two integer facts that figure is
computed from (`2^114 < |C_T| < 2^115`, `2^-15 < p < 2^-14`); the square root is
still arithmetic done outside.

---

Everything checks out. Now let me also quickly verify the scratch finding doc (do-not-import-the-policy-cap) key section since it's directly the predecessor analysis, and the eager reduction count claim — already verified visually. Also verify `WOTS_C_Scheme.ec:214` (nrqs <= c). Quick greps. Also confirm T_COLL_RES_ENUM appears nowhere in certified trees (agent claimed grep returns nothing).RC=0
    dist_wgpidxs <@ O.dist_addresses();
    adlO <@ O.get_addresses();
    adlOC <@ OC.get_tweaks();

    return 0 <= nrqs <= c /\ 0 <= i < nrqs /\
           is_valid /\ is_fresh /\ dist_wgpidxs /\ disj_wgpidxs adlO adlOC;
  }
}.

====
and from all four `cert-*.tsv`.** That is the same non-certified-draft trap that
`Extraction.ec` set for me, so I checked the live file instead.

**VERIFIED on the live closure member** (`XmssmtCC_All.ec:752`, closure entry #8):
`R_MEUFGCMAWOTSC_EUFNAGCMA_C.choose` calls `A(OC).choose()` and then runs
`while (size pkWOTStd < d)` under the comment *"compute and store **all** the
WOTS+C public keys"*. It is **eager**.

*(Note the live `R_int_WOTSTW.choose` at `WOTS_C_Interactive.ec:1802` is by
contrast **lazy** — `O_wrap.init; AA.choose()`. The eagerness is at the hypertree
layer, not the WOTS one. GPT's claim was right about the composition and wrong
about which module does it.)*

Consequences:

* `nrts = c = 262656` **regardless of how many signatures the deployment makes**;
* substituting `q_s = 2^16` is wrong, and `2·q_s = 2^17` is **equally unsupported**;
* a `q_s`-dependent bound needs an **on-demand/lazy reduction** registering only
  the WOTS instances a signing query actually exposes, plus handling of repeated
  indices. That is a substantial rebuild, not a substitution.

## 3. Q2 — the P14 caveat: yes and no, and I had it half wrong

* **YES**: a blanket per-key `q_s = 2^16` is **false for the bootstrap key**. The
  bootstrap signer is global (`domain/src/lib.rs:407`), the cap is enforced
  per-wallet-instance (`PQSmartWallet.sol:449`), and the project's own
  `Quantitative.lean:172` already states the cross-chain budget is `C · 65536`.
  It is valid only for a **chain-bound slot key**, or for the bootstrap key
  restricted to one chain.
* **NO**: this does **not** multiply the target count by `C`. One WOTS cube exists
  per SPHINCS public key; reusing the bootstrap key across chains exposes more
  messages **within the same cube**, it does not create `C` cubes.
* And a conflation of mine: `ad` in `T_COLL_RES_ENUM` is a **SPHINCS/WOTS tweak
  address**, not an Ethereum address or chain identity.

Very good — a prior review doc `scratch/FINDING-do-not-import-the-policy-cap.md` already addressed exactly this question and concluded "do not import." Let me read the whole file to make sure I represent and can build on/attack it. Also there's an interesting nuance in §3: P14 caveat "does not multiply target count by C" — one WOTS cube per SPHINCS key; reusing across chains exposes more messages within the same cube. That's an important subtlety for Q2: the multi-chain issue for the *enumeration* term is about the number of queries/messages (q grows to C·2^16), not the target cube count. But also for the bootstrap key, q_s = C·65536 signatures → WOTS uses = ... still bounded by c structurally. Hmm wait — bootstrap key budget C×65536 could exceed... C·2^16 vs c=262656≈2^18.006. At C≥5, C·2^16 > c. But signatures also consume hypertree leaves — can't actually sign more than 2^18 messages with one hypertree (each signature needs a fresh leaf? In this scheme with counters/grinding, leaf reuse... actually XMSS-style requires distinct leaves). Anyway.

  Let me read the full finding doc — it's the direct predecessor and I should engage with it (attack or confirm). It's in scratch/, not experiments/, so no compile requirement.The finding doc is a prior review (dated today, 2026-08-15) — it contains claims attributed to "Kimi" (me, a prior session) and GPT. I should not just parrot it; I should verify its load-bearing claims independently, which I've largely done: T_COLL_RES_ENUM absent from certified trees (verified by my own grep — empty output before RC=0... wait, the grep printed nothing then "RC=0"? Actually `grep ... | head; echo RC=$?` — RC is of head, not grep. The output shows no matches, then RC=0 (head succeeded). Fine — no matches in certified trees, consistent with capstone read showing 4 terms).

  One claim in that doc I should scrutinize: §7(d) mentions "the produced-signature escape means no device-side cap exists at all for bootstrap" — attributed to prior Kimi partial review. And §7(b) claims MAX_SLOT_USES is "a contract constant changeable by redeployment/governance and a firmware constant changeable by update." Is that verified? The Rust agent said invariant #7: "No reset* or increaseMax* path" and a drift gate pins Rust↔Solidity equality. It's a constant in the contract (`uint256 internal constant`), so change requires redeployment — that's inherent to any contract constant. The "mutable governance parameter" framing is somewhat overstated: it's not governance-mutable at runtime; it's an immutable constant, changeable only by deploying a new contract (which changes the wallet/address... actually the wallet is a proxy? CREATE2 salt depends on master keys). Let me not over-claim. I'll mark the TCB point as INFERRED/partly contested: the constant is hard-coded, drift-gated between Rust and Solidity, and changing it means redeploying + firmware update — so the theorem would depend on deployment config, which is true, but "mutable governance parameter" is too strong phrasing. I verified `uint256 internal constant MAX_SLOT_USES = 65536;` — it's a compile-time constant, no setter (invariant #7: no reset/increaseMax path). So the "governance" claim is INFERRED/overstated; the TCB-dependency point stands in weaker form.

  Also §7(c): "2^-82 clears the 96 floor" — the user's situation statement says "At q_s=2^16 that is 2^-82, which clears the project's WORK_FLOOR_BITS=96 guardrail." The doc says this is wrong unless you count the 2^14.9 grind factor as adversary work (82+14.9≈96.9). That's a claim about forsc_grinding_margin.py, flagged INFERRED in the doc. Do I need to resolve it? The user asks Q5 where is my framing wrong — this is one spot: whether 2^-82 clears a 96-bit work floor depends on whether the guardrail compares advantage bits or work bits. Let me check tools/forsc_grinding_margin.py quickly for WORK_FLOOR_BITS and how the comparison is done. It's in tools/, not experiments/, no compile needed.

  Also check the background compile task status later.

  Let me check forsc_grinding_margin.py for WORK_FLOOR_BITS.3:FORS+C grinding margin for C10 — is the +C variant ever WEAKER than plain FORS?
9:SPHINCS+**. We ship SPHINCS+C10, whose FORS+C variant grinds the randomizer `R`
51:plain ITSR. For C10 (which grinds the KEY `R`, not a counter) such a reduction EXISTS
98:F3. `-log2(B)` is a WORK FACTOR (hash queries needed), NOT an advantage. The old
104:    PRINTS the advantage at representative q_h. There is no operational cap on
105:    offline hashing, so no `Q_H_CAP` is asserted. Read the printed advantage line
136:# adversary needs. Comparing a work factor to an advantage floor conflates two
143:WORK_FLOOR_BITS = 96
221:def itsr_report(qs: int, work_floor_bits: int) -> tuple[float, float, list[str]]:
257:    # factor (queries needed), not an advantage. Print the advantage explicitly.
258:    print("  advantage Pr[win] <= (q_h + 1) * B, at representative q_h:")
303:        _, _, fails = itsr_report(2 ** 22, WORK_FLOOR_BITS)
337:    print("=== FORS+C grinding margin — C10 ===")
392:    real_bits, red_bits, itsr_fail = itsr_report(QS_CAP, WORK_FLOOR_BITS)
====
./experiments/tcollres-leg/FINDING-def11-is-unsound-at-c10.md:129:   `WORK_FLOOR_BITS = 96` is a **WORK floor** (its own :130-143 note);
./tools/forsc_grinding_margin.py:143:WORK_FLOOR_BITS = 96
./tools/forsc_grinding_margin.py:303:        _, _, fails = itsr_report(2 ** 22, WORK_FLOOR_BITS)
./tools/forsc_grinding_margin.py:392:    real_bits, red_bits, itsr_fail = itsr_report(QS_CAP, WORK_FLOOR_BITS)

TWO CORRECTIONS, 2026-07-10b (adversarial review, findings F3 + F4)
-------------------------------------------------------------------
F3. `-log2(B)` is a WORK FACTOR (hash queries needed), NOT an advantage. The old
    guardrail compared it to a floor named after `Crypto/Quantitative.lean`, whose
    convention puts the query count INSIDE the term
    (`queryTerm_le_of_le : q * 2^t <= 2^SecurityBits`). Two different objects. The
    docstring stated `Pr[win] <= (q_h+1)*B` while the code never applied the
    multiplier. Now the floor is explicitly a QUERY-WORK floor and the report
    PRINTS the advantage at representative q_h. There is no operational cap on
    offline hashing, so no `Q_H_CAP` is asserted. Read the printed advantage line
    before quoting "130.6 bits" as a security level.
F4. `_mixture` truncated the binomial support and so UNDER-estimated the
    expectation, making `-log2` OVERSTATE security. It now adds a rigorous
    geometric tail bound (see its docstring).
"""
from __future__ import annotations

import math
import sys

# --- C10 parameters (must mirror sphincs-c10/src/params.rs) -------------------
N = 16   # bytes of hash output kept
H = 18   # hypertree height  -> 2**H FORS instances
D = 2    # hypertree layers
K = 13   # FORS trees
A = 11   # log2(leaves per FORS tree)

T = 2 ** A          # leaves per FORS tree
T_LAST = 2 ** A     # size of the REMOVED (forced-zero) tree. C10: same as T.

N_INST = 2 ** H     # one FORS instance per hypertree leaf

# Per-chain signature cap (MAX_SLOT_USES / MAX_BOOTSTRAP_USES, see CLAUDE.md).
QS_CAP = 2 ** 16
# QUERY-WORK floor, in bits of adversary HASH QUERIES.
#
# F3 FIX (2026-07-10b, adversarial review). This is NOT `Crypto/Quantitative.lean`'s
# floor. That one bounds an ADVANTAGE and has the query count INSIDE the term
# (`queryTerm_le_of_le : q * 2^t <= 2^SecurityBits`). This script's `-log2(B)` is a
# per-candidate probability, i.e. a WORK FACTOR: the number of hash queries an
# adversary needs. Comparing a work factor to an advantage floor conflates two
# different objects -- the previous version did exactly that while its own docstring
# stated `Pr[win] <= (q_h+1)*B`, a formula the code never applied.
#
# So: guardrail 4 now asserts a WORK floor (>= 2^96 hash queries), and the report
# prints the ADVANTAGE `(q_h+1)*B` at representative q_h so nobody has to infer it.
# There is no operational cap on offline hashing, so no `Q_H_CAP` is asserted.
WORK_FLOOR_BITS = 96

def darkside(gamma: int, t: int = T) -> float:
All seven cited experiments files compile clean in the container (r2026.02): PTgtsPin.ec, CountDS.ec, C10SurfaceKernel.ec (40s, as documented), C10Surface.ec, TCollResEnum.ec, BadEncStep4.ec, BadEncToTColl.ec. Good — none of the ones I cite are among the six stale ones. I should note which ones are stale? I don't know which six; not needed unless I cite them. I'll state I compile-tested everything I cite.

  WORK_FLOOR_BITS: confirmed it's a *query-work* floor (bits of adversary hash queries), not an advantage floor (tools/forsc_grinding_margin.py:136-143, F3 note). So the user's claim "2^-82 clears the WORK_FLOOR_BITS=96 guardrail" is a category mix: 82 is advantage bits; the floor counts work. Whether it clears depends on counting the grind factor 2^14.9 as work: 82+14.9 ≈ 96.9. That matches the FINDING's §7(c). Mark: VERIFIED that the floor is a work floor (file:line); INFERRED that 82+14.9 is the right addition (the grind factor 2^14.9059 surface fraction is machine-checked as 2^-15 < p < 2^-14 per count README T4, VERIFIED; adding it to get work is INFERRED heuristic).

  One more thing to verify for Q3: the claim that BadEncStep4 makes "one recorded target per committed WOTS+C query" with size ts = size qs, size qs <= c — agent cited BadEncStep4.ec:692-699 and WOTS_C_Scheme.ec:214. I verified WOTS_C_Scheme.ec:214 myself. Good enough.

  For Q2, the key question: which key feeds T_COLL_RES_ENUM? Model has a single ps; no slot/bootstrap distinction. The term is generic per-SPHINCS-key. So P14 applies depending on which deployed key the model is instantiated to: for slot keys (chain-bound), per-key budget = 2^16 per chain and keys differ per chain → each key is a separate cube, separate target set, per-key q_s = 2^16 holds. For bootstrap key: same key across C chains, per-chain cap 2^16 → per-key q_s = C·2^16. So IF the WOTS leg is meant to cover bootstrap-signed Type-1 ops, q_s=2^16 is wrong. The model itself doesn't distinguish — VERIFIED.

  But note the subtlety from FINDING §3: cross-chain reuse doesn't multiply the target cube count; it multiplies the number of messages/queries within the same cube. For a q_s²-shaped birthday term, what matters is number of recorded targets/queries. But per the eager reduction, nrts = c regardless. So the q_s discussion is moot for the current model anyway.

  Also for Q3: d*q_s = 2^17 WOTS uses vs c = 2^18+2^9. But tighter: distinct instances touched by q_s signatures ≤ q_s + l' = 66048 (PTgtsPin.ec:262-269, 321-322) — because all signatures share the same 512 top-tree instances. So the "2^17 vs 2^18" comparison in the user's Q3 is loose; the honest distinct-instance count is q_s + 512. But even that is irrelevant because the reduction registers all c eagerly.

  Now the answers:

  **Q1**: Query-bounded EUF-CMA is legitimate concrete security, not a category error. Standard: concrete security statements always are functions of (t, q_s, q_h). Precedent: every concrete-security treatment (Bellare; SPHINCS+ paper's own bounds are stated with q_s; NIST submissions quote "security at q_s = 2^64"). The accepted way: state the theorem as ∀A with Q_sign(A) ≤ Q: Adv ≤ ε(t,Q), name it EUF-CMA[Q ≤ 2^16], and keep the deployment claim (chain enforcement ⇒ Q_sign,key ≤ 65536) as a separate lemma outside the crypto theorem. Importing the constant into the game definition is what would be the category error — it makes a reusable theorem depend on one deployment's policy.

  But — bigger point — in this repo there's nothing to plug it into: T_COLL_RES_ENUM is not in the certified trees, no bound on Pr[T_COLL_RES_ENUM] exists anywhere, and the q_s²·2^-114.09 shape was never derived (the count is a theorem; the birthday formula is not). So importing q_s would be polishing a numerator with no denominator.

  **Q2**: Verdict: the P14 caveat does not break q_s=2^16 for slot keys (chain-bound: distinct key material per chain, VERIFIED domain/src/lib.rs:705-715), but it does for the bootstrap key (chain-independent, same hypertree signing on every chain, budget C·2^16, VERIFIED Quantitative.lean:174-184). Which feeds the term: the model has one ps and no slot/bootstrap distinction (VERIFIED TCollResEnum.ec:277-285, grep for bootstrap/slot in certified trees = nothing). So the question only matters if the EUF-CMA statement is meant to cover Type-1 bootstrap signatures — currently unresolved in the project. Also the target-set subtlety: multi-chain reuse exposes more messages within the same cube, not C cubes.

  **Q3**: Yes, conflated. Four quantities: q_s (signatures, 2^16, deployment, absent from model), WOTS uses (≤ q_s + 512 distinct instances, not d·q_s = 2^17 — top-tree sharing), c (structural 262656, machine-checked), nrts/p_tgts (recorded targets — and the certified hypertree reduction registers all c = 262656 eagerly regardless of signatures, VERIFIED XmssmtCC_All.ec:801-855). The term's q in q²·2^-114.09 was never defined by a derivation — the shape itself is heuristic. And the reduction registers targets eagerly at the hypertree layer, so even a correct q_s can't enter without rebuilding the reduction lazily.

  **Q4**: Carry q_s symbolically — yes, that's the right move and it's also the standard one. Third option: the FINDING's option (i): write down the explicit distributional assumption making the birthday step a stated premise; or (iii): document the leg as assumption + machine-checked count, no advantage claim. Given nothing bounds Pr[T_COLL_RES_ENUM], the symbolic-q_s formulation is necessary but not sufficient.

  **Q5 / strongest objection**: There is no theorem to import into. T_COLL_RES_ENUM appears nowhere in the certified trees (grep empty; capstone RHS has four terms, none T-COLL, SphincsC10CapstoneWired.ec:595-604); TCollResEnum.ec's own header says it's "NOT A PROVED REDUCTION" and "nothing here bounds Pr[T_COLL_RES_ENUM(B)]" (:5-7, :58); the q_s²/2^114.09 shape was never derived from the count (count/README.md: the counted objects are int lists, five unbridged gaps; "the number is now a theorem; its identification with the codeword surface is still prose"). And the eager reduction makes nrts = c independent of deployment. So importing MAX_SLOT_USES would add TCB (firmware gate correctness, deployment config) to cosmetically improve a constant in a numerator whose denominator doesn't exist.

  Also correct the user's "clears WORK_FLOOR_BITS=96": that floor is a query-work floor, not an advantage floor (VERIFIED tools/forsc_grinding_margin.py:130-143 F3 note). 2^-82 is an advantage; comparing it to a work floor conflates objects — the very mistake F3 corrected. With the grind factor counted as work you get ≈96.9 (INFERRED arithmetic).

  Also Q1 precedent: SPHINCS+ specification itself states security bounds as functions of q_s (e.g., bounds with q_s = 2^64). I can state this as INFERRED/general knowledge — the SPHINCS+ submission's security analysis is parameterized by the number of signing queries. That's standard and safe to assert as INFERRED.

  One more check on the "mutable governance parameter" claim in the FINDING §7(b) — I should dampen it: MAX_SLOT_USES is a compile-time `internal constant` in Solidity (VERIFIED PqsignerProto.sol:30) with no setter (invariant #7, VERIFIED CLAUDE.md:28), drift-gated to the Rust constant. Changing it = new deployment + firmware update. So it's not runtime-governance-mutable; but the TCB point (theorem would depend on firmware gate + contract enforcement, both outside EasyCrypt's TCB) stands. I'll present that nuance.

  Deliverable format: blunt, structured by the four deliverables. Mark VERIFIED (file:line) / INFERRED. Include compile receipts. Write in English (user's language).

  Also mention: six stale files / Extraction.ec — I didn't cite them; everything I cite compiled rc=0. List the compile results.

  Length: this needs to be thorough but tight. Let me write it.

• All seven `experiments/` files I rely on compiled clean in the container (`ec-grind`, repo mounted read-only at `/work`, sources mirrored to `/tmp` so no repo file was touched):

  - `PTgtsPin.ec` rc=0 (2s) · `CountDS.ec` rc=0 (2s) · `C10SurfaceKernel.ec` rc=0 (40s) · `C10Surface.ec` rc=0 (1s) · `TCollResEnum.ec` rc=0 (2s) · `BadEncStep4.ec` rc=0 (6s) · `BadEncToTColl.ec` rc=0 (3s)

  None of the six stale files is among my citations. Now the verdicts.

  ---

  ## (1) Q1 — Sound, but must be stated differently — and here it doesn't arise yet

  Query-bounded EUF-CMA is **not a category error**. It is what concrete security always is: every real bound is a function ε(t, q_s, q_h), and the SPHINCS+ submission's own security analysis is parameterized by the number of signing queries (INFERRED — standard practice, not re-verified against the submission PDF this round). The shape I would accept:

  ```
  forall A.  Time(A) <= t  /\  Q_sign,key(A) <= Q   =>   Adv_EUF-CMA(A) <= eps(t, Q)
  ```

  with the deployment claim as a **separate** theorem, outside the crypto statement:

  ```
  DeploymentTrace  =>  Q_sign,key(A) <= 65536        (slot key, one chain)
                   =>  Q_sign,key(A) <= C * 65536    (bootstrap key, C chains)
  ```

  named `EUF-CMA[Q ≤ 2^16]`, never "EUF-CMA". **Importing the constant into the game or the theorem statement** is the actual category error: it makes a reusable cryptographic theorem depend on one wallet's deployment configuration.

  But the prior question is: import it *into what*? **VERIFIED: `T_COLL_RES_ENUM` appears nowhere in the certified trees** — `grep -rn "T_COLL_RES_ENUM\|TCollResEnum" base-c10-split cdrafts-split` returns nothing (my run), and the certified capstone RHS carries exactly four terms, none of them T-COLL (`cdrafts-split/SphincsC10CapstoneWired.ec:595-604`). The game file itself says it is "A DEFINITION PLUS EVIDENCE. IT IS NOT A PROVED REDUCTION" and "nothing here bounds `Pr[T_COLL_RES_ENUM(B)]`" (`experiments/wots-badenc/tcoll/TCollResEnum.ec:5-7,58`). You'd be importing policy to rescue a constant in a numerator whose denominator does not exist.

  ## (2) Q2 — P14 breaks `q_s = 2^16` for the bootstrap key, not for slot keys; and the model can't tell the difference

  - **Slot keys are chain-bound.** `slot_entropy` folds `chain_id` into the derivation (`domain/src/lib.rs:705-715`), confirmed by a negative test that chains 1 vs 137 give different `(pk_seed, pk_root)` (`domain/tests/negative_derivation_independence.rs:58-59`). Per-chain cap ⇒ per-key budget 65,536 with distinct cubes per chain. P14 does **not** degrade a WOTS leg fed by slot keys. VERIFIED.
  - **Bootstrap key is chain-independent.** Master derivation takes `(bip39_seed, account_index)` only, no chain_id (`domain/src/lib.rs:546-548,563-567`); the project's own Lean caveat states the cross-chain budget is `C · MaxBootstrapUses` (`Quantitative.lean:174-184`). For this key `q_s = 2^16` is false; the honest figure is `C·2^16`. VERIFIED.
  - **Which feeds the term:** the model has exactly one `ps`, sampled once (`TCollResEnum.ec:277-285`); there is no slot/bootstrap distinction anywhere in the development (grep for `bootstrap|slot key` in the certified trees: nothing). So the model as written is generic per-SPHINCS-key, and whether P14 applies is decided by *which deployed key you claim the model covers* — an instantiation question the project has not resolved (the open Type-1 coverage question). VERIFIED that the ambiguity exists; INFERRED that it's unresolved.
  - One refinement worth keeping: cross-chain reuse of the bootstrap key exposes more messages **within the same WOTS cube**, it does not create C cubes (`scratch/FINDING-do-not-import-the-policy-cap.md:65-67` — VERIFIED as reasoning, consistent with the single-`ps` model). And a correction to that finding's §7(b): `MAX_SLOT_USES` is a compile-time `internal constant` with no setter and a Rust↔Solidity drift gate (`PqsignerProto.sol:30`, `CLAUDE.md:28`, `xtask/src/main.rs:3340-3342` — VERIFIED), so "mutable governance parameter" is overstated; it's redeploy-plus-firmware-update. The TCB point survives in weaker form: any imported cap rests on the on-chain check and the firmware gate (`PQSmartWallet.sol:475-481`, `aa/src/offchain_gate.rs:151,166`), both outside EasyCrypt's TCB.

  ## (3) Q3 — Yes: `c`, `q_s`, WOTS uses, and target count are four quantities, and they've been interchanged

  - `q_s` = signatures = 2^16. Deployment policy, **absent from the model** (`PTgtsPin.ec:287-289`, VERIFIED, compiled).
  - WOTS uses per signature = 2 (`hypertree.rs:268,290-293`, VERIFIED). But your `d·q_s = 2^17` is the *loose* count: all signatures share the same 512 top-tree instances, so distinct instances touched under the cap ≤ `q_s + l' = 66048`, proved as `c10_distinct_instances_under_usage_cap` (`PTgtsPin.ec:262-269,321-322`, VERIFIED).
  - `c` = 262656 = 2^18+2^9, structural WOTS-instance count, theorem `c10_c_closed` with no premises (`PTgtsPin.ec:119-127`; matches `params.rs:22-31` + `hypertree.rs:27-31`, VERIFIED).
  - `nrts`/`p_tgts` = recorded targets. And here is the killer: the certified hypertree reduction is **eager** — `R_MEUFGCMAWOTSC_EUFNAGCMA_C.choose` loops all `d` layers × all trees × all `l'` leaves, calling `O.query` per leaf "to compute and store **all** the WOTS+C public keys" (`cdrafts-split/XmssmtCC_All.ec:794-855`, VERIFIED by direct read). So the reduction registers **all c = 262656 targets no matter how few signatures anyone ever makes**. No deployment cap can enter the target count without rebuilding this reduction lazily — and `PTgtsPin.ec` already proves the convenient substitution is forbidden: `c10_usage_cap_is_not_admissible_as_p_tgts : !(c <= 65536)` (:326).

  And one level deeper: the `q` in `q²·2^-114.09` was never defined by a derivation at all. The count is a theorem (`C10SurfaceKernel.ec:25`, recompiled, rc=0); the birthday shape around it is "generic-model arithmetic … not theorems" (`PTgtsPin.ec:304-306`), and the count's own README enumerates five unbridged gaps between `int list`s and codeword fibres (`count/README.md:100-127`: "the number is now a theorem; its identification with the codeword surface is still prose").

  ## (4) Q4 — Carry `q_s` symbolically. And my strongest objection

  Yes — symbolic `q_s` with the policy claim pushed to the point of quotation is strictly better, and it's also just the standard concrete-security form, so it costs nothing in generality. But it is **necessary, not sufficient**, because of the strongest objection:

  > **There is currently no derivation connecting the machine-checked count to any bound on `Pr[T_COLL_RES_ENUM]`, and the term appears in no certified statement.** A surface cardinality does not yield a birthday bound; you need an explicit distributional/computational assumption about `ThC` images against an adversary holding the keyed collection oracle and choosing its own counter (the game's C1/C3 constraints, `TCollResEnum.ec:279-299`). Importing `MAX_SLOT_USES` would add deployment TCB to cosmetically improve a constant in a numerator whose denominator does not exist.

  So: **do not import it. Carry `q_s` symbolically and stop chasing a number** — and before even that, either (i) write down the collision-hardness assumption explicitly so the `q²/|C_T|` step is a stated premise, or (iii) document the leg as an unbounded assumption plus a machine-checked surface count with no advantage claim. (ii), the lazy reduction, is the only route by which a `q_s`-shaped bound could ever be real, and it's a substantial rebuild.

  ## (5) Q5 — framing errors found this round

  - *"`2^-82` clears the `WORK_FLOOR_BITS = 96` guardrail"* — that floor is explicitly a **query-work** floor (bits of adversary hash queries), not an advantage floor; the script's own F3 correction exists because a previous version made exactly this conflation (`tools/forsc_grinding_margin.py:98-105,130-143`, VERIFIED). 82 is advantage bits. It "clears" only if you count the 2^14.9 grind factor as adversary work (82 + 14.9 ≈ 96.9) — the fraction is machine-checked as `2^-15 < p < 2^-14` (`count/README.md` T4, VERIFIED), the addition is INFERRED heuristic arithmetic.
  - *"Using `c` gives `2^-78.09`"* — true arithmetic (`PTgtsPin.ec:292-293`, VERIFIED theorem), but quoting either number implies a derived bound exists. Neither `2^-82` nor `2^-78.09` should be quoted at all until the birthday model is written down as a premise.
  - The whole premise of the unit — that importing policy is the next thing to do — inherits the two earlier refuted units' mistake: it optimizes the constant before the term exists in the certified statement. The repo's own finding file reached this conclusion today (`scratch/FINDING-do-not-import-the-policy-cap.md`); I re-verified its load-bearing claims independently rather than trusting it, and they hold, with the two corrections noted above (governance-mutability overstated; the rest stands).

To resume this session: kimi -r session_c58155c6-5eb8-49a9-8766-0cb2ce90444f
