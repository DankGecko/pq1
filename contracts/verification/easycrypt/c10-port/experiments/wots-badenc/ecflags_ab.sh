#!/usr/bin/env bash
# CONTROLLED A/B: what does -timeout 60 actually cost on the two legs I applied it to
# beyond the compile driver?  Same machine, same files, ALTERNATING arms so that any
# drift in ambient load is shared between them rather than loaded onto one.
#
# WHY THIS AND NOT A CROSS-RUN COMPARISON: I have already asserted this cost twice from
# a measurement taken on ONE file, and been wrong both times.  Comparing two full gate
# runs would confound the flag with everything else that differs between runs.
set -u; cd /work
B=base-c10-split; D=cdrafts-split; INC="-I $B -I $D"

t() { local t0=$(date +%s%N); "$@" >/dev/null 2>&1; echo $(( ($(date +%s%N)-t0)/1000000 )); }

echo "=== LEG 1: PHASE 3 controls (mostly MUST-FAIL -- a bigger budget only delays failure) ==="
tot_off=0; tot_on=0
for rep in 1 2; do
  while IFS=$'\t' read -r path kind reason; do
    case "$path" in ''|\#*) continue;; esac
    off=$(t easycrypt compile $INC "$path")
    on=$(t easycrypt compile -timeout 60 $INC "$path")
    tot_off=$((tot_off+off)); tot_on=$((tot_on+on))
    [ $rep -eq 1 ] && printf "  %-46s %-10s default=%6sms  -timeout60=%6sms\n" "$path" "$kind" "$off" "$on"
  done < cert-controls-split.tsv
done
echo "  CONTROLS TOTAL (2 reps): default=${tot_off}ms  -timeout60=${tot_on}ms  delta=$((tot_on-tot_off))ms"

echo
echo "=== LEG 2: PHASE 1e cli, on a sample of closure members ==="
c_off=0; c_on=0
for n in GprocT1Opre GprocQBound DarkSideC10 C10DeployedGeometry; do
  off=$(bash -c "easycrypt cli -iterate $INC < $D/$n.ec" >/dev/null 2>&1; echo 0)
  t0=$(date +%s%N); easycrypt cli -iterate $INC < $D/$n.ec >/dev/null 2>&1; off=$(( ($(date +%s%N)-t0)/1000000 ))
  t0=$(date +%s%N); easycrypt cli -iterate -timeout 60 $INC < $D/$n.ec >/dev/null 2>&1; on=$(( ($(date +%s%N)-t0)/1000000 ))
  c_off=$((c_off+off)); c_on=$((c_on+on))
  printf "  %-26s default=%7sms  -timeout60=%7sms\n" "$n" "$off" "$on"
done
echo "  CLI SAMPLE TOTAL: default=${c_off}ms  -timeout60=${c_on}ms  delta=$((c_on-c_off))ms"
echo "AB_DONE"
