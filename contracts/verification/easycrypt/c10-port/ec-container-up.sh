#!/usr/bin/env bash
# ec-container-up.sh -- ensure the `ec-grind` EasyCrypt container exists, is running,
# and is configured with --init.  IDEMPOTENT: safe to run any time.
#
# WHY --init MATTERS (real incident, 2026-07-25):
#   The container ran `sleep infinity` as PID 1.  `sleep` is not an init system: it never
#   calls wait(), so every process orphaned inside the container became a PERMANENT ZOMBIE
#   instead of being reaped.  EasyCrypt spawns why3server per prover call, and Why3 spawns
#   sh/basename helpers per goal, so this leaks fast: it reached **53,839 zombies** over ~6
#   days.  Zombies cannot be killed (they are already dead) and are only cleared by the
#   parent reaping them or by the container being replaced.  The visible symptom was a
#   ~100x system slowdown -- htop/ps stat every /proc/<pid>, so ~54,500 directory scans
#   instead of ~500 (one htop refresh took 17.9s; a plain `ps -e` took 0.84s vs ~0.02s).
#   `--init` makes docker-init (tini) PID 1, which reaps orphans, and the leak cannot happen.
#   Verified after the fix: 300 orphans spawned -> 0 zombies.
#
# NOTE: `docker restart` CLEARS existing zombies but does NOT add --init -- the leak resumes.
#       The container must be RECREATED (this script) to fix it permanently.
#
# Data safety: /work is a BIND MOUNT of this repo, and the container has no filesystem state
# outside /work and /tmp, so recreating it loses nothing.

set -u
NAME=ec-grind
IMAGE=ghcr.io/easycrypt/ec-test-box:r2026.02
REPO=/home/nicola/repos/c10-eufcma-port

d() { sg docker -c "docker $*"; }

exists=$(d "ps -a --filter name=^${NAME}$ --format '{{.Names}}'" 2>/dev/null)
if [ -n "$exists" ]; then
  init=$(d "inspect ${NAME} --format '{{.HostConfig.Init}}'" 2>/dev/null)
  state=$(d "inspect ${NAME} --format '{{.State.Status}}'" 2>/dev/null)
  if [ "$init" = "true" ]; then
    if [ "$state" != "running" ]; then
      echo "ec-container-up: ${NAME} exists with --init but is ${state}; starting."
      d "start ${NAME}" >/dev/null
    fi
    echo "ec-container-up: OK -- ${NAME} running with --init (PID 1 = docker-init/tini)."
    exit 0
  fi
  echo "ec-container-up: ${NAME} exists WITHOUT --init (Init=${init}) -- it WILL leak zombies."
  echo "ec-container-up: checking for in-container state before recreating..."
  extra=$(d "diff ${NAME} 2>/dev/null | grep -vcE '^. /(work|tmp|proc|sys|run|dev)'" 2>/dev/null)
  if [ "${extra:-0}" -gt 0 ]; then
    echo "ec-container-up: REFUSING to recreate -- ${extra} filesystem change(s) outside /work,/tmp"
    echo "                 would be lost.  Inspect with: sg docker -c 'docker diff ${NAME}'"
    echo "                 If they are disposable, remove the container yourself and re-run."
    exit 1
  fi
  running=$(d "exec ${NAME} bash -lc 'ps -eo cmd | grep -c \"[e]asycrypt compile\"'" 2>/dev/null)
  if [ "${running:-0}" -gt 0 ]; then
    echo "ec-container-up: REFUSING to recreate -- ${running} easycrypt compile(s) IN FLIGHT."
    echo "                 Wait for them to finish (a recreate would kill them) and re-run."
    exit 1
  fi
  echo "ec-container-up: no state outside /work,/tmp and no compile in flight -- recreating."
  d "rm -f ${NAME}" >/dev/null
fi

d "run -d --init --name ${NAME} -u charlie -w /work -v ${REPO}:/work ${IMAGE} sleep infinity" >/dev/null
init=$(d "inspect ${NAME} --format '{{.HostConfig.Init}}'" 2>/dev/null)
pid1=$(d "exec ${NAME} bash -lc 'ps -p 1 -o comm --no-headers'" 2>/dev/null)
echo "ec-container-up: created ${NAME}  Init=${init}  PID1=${pid1}"
[ "$init" = "true" ] || { echo "ec-container-up: FAILED to set --init"; exit 1; }
echo "ec-container-up: OK."
