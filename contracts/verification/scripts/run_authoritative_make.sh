#!/usr/bin/bash
# Authoritative caller boundary for the ledger-consistency Make target.
#
# Invoke only through the documented setuid-sudo -> `/usr/bin/env -i` command.
# The environment must be cleared across a trusted pre-exec boundary BEFORE a
# normal dynamically linked process starts: invoking `/usr/bin/env -i` directly
# is too late when `LD_TRACE_LOADED_OBJECTS=1` or `LD_DEBUG=help` can suppress
# `env`, Bash, or Make itself while returning success.  An in-shell
# `builtin exec -c` is also insufficient when an exported function named
# `builtin` can intercept that command.  Sudo immediately drops back to the
# caller's same numeric UID; it supplies secure-execution startup, not elevated
# gate authority.
#
# The make-shaped argument vector is intentional.  It keeps the target visible
# to gate-enforcement lint while this script rejects every other target/option.
set -euo pipefail

fail_usage() {
  builtin printf 'ERROR: %s\n' "$1" >&2
  exit 2
}

if (($# != 4)) \
    || [[ "$1" != "make" ]] \
    || [[ "$2" != "-C" ]] \
    || [[ "$3" != "contracts/verification" ]] \
    || [[ "$4" != "verify-ledger-consistency" ]]; then
  fail_usage \
    "expected: make -C contracts/verification verify-ledger-consistency"
fi

# Enforce the outer boundary instead of merely documenting it.  A Bash started
# by `env -i` exports only these bootstrap variables on this platform; any
# caller-carried variable means the required environment-clearing boundary was
# omitted.  In particular, removing `env -i` from CI cannot stay green under an
# otherwise benign environment and silently re-open the loader surface.
unexpected_env=()
while IFS= read -r env_name; do
  case "${env_name}" in
    PWD|SHLVL|_) ;;
    *) unexpected_env+=("${env_name}") ;;
  esac
done < <(builtin compgen -e)
if ((${#unexpected_env[@]})); then
  fail_usage \
    "pre-exec environment was not empty (unexpected: ${unexpected_env[*]})"
fi
if ((UID == 0 || EUID != UID)); then
  fail_usage \
    "authoritative launcher requires one unchanged non-root numeric UID"
fi
parent_name=""
parent_real_uid=""
parent_effective_uid=""
parent_saved_uid=""
while IFS=$' \t' read -r field value1 value2 value3 _; do
  case "${field}" in
    Name:)
      parent_name="${value1}"
      ;;
    Uid:)
      parent_real_uid="${value1}"
      parent_effective_uid="${value2}"
      parent_saved_uid="${value3}"
      ;;
  esac
done <"/proc/${PPID}/status"
readonly parent_name parent_real_uid parent_effective_uid parent_saved_uid
if [[ "${parent_name}" != "sudo" ]] \
    || [[ "${parent_real_uid}" != "${UID}" ]] \
    || [[ "${parent_effective_uid}" != "0" ]] \
    || [[ "${parent_saved_uid}" != "0" ]]; then
  fail_usage \
    "authoritative launcher requires its same-UID setuid-sudo parent"
fi

# Rebuild the small environment needed by the fixed tools.  The Makefile
# derives HOME/ELAN_HOME from the password database and pins its own evidence
# tools; no caller environment is carried across this boundary.
export PATH=/usr/bin:/bin
export LC_ALL=C.UTF-8
builtin unset CDPATH BASH_ENV ENV

launcher_path=$(
  /usr/bin/readlink -f -- "${BASH_SOURCE[0]}"
) || fail_usage "cannot resolve the physical authoritative launcher file"
readonly launcher_path
# Resolve the file, not merely its lexical parent.  Otherwise a symlink to this
# trusted script inside an attacker-controlled lookalike tree makes every
# adjacent Makefile/checker presence test self-consistent.  A hard link has the
# same ambiguity because readlink cannot distinguish which directory owns the
# inode, so authoritative launchers must be single-linked.
if [[ ! -f "${launcher_path}" ]] \
    || [[ "${launcher_path##*/}" != "run_authoritative_make.sh" ]]; then
  fail_usage "resolved authoritative launcher identity is invalid"
fi
launcher_links=$(/usr/bin/stat -c '%h' -- "${launcher_path}")
readonly launcher_links
if [[ "${launcher_links}" != "1" ]]; then
  fail_usage \
    "authoritative launcher must have exactly one hard link"
fi

script_dir="$(
  builtin unset CDPATH
  builtin cd -P -- "$(/usr/bin/dirname -- "${launcher_path}")"
  /usr/bin/pwd -P
)"
readonly script_dir
if [[ "${launcher_path}" != \
      "${script_dir}/run_authoritative_make.sh" ]]; then
  fail_usage "authoritative launcher path did not canonicalize exactly"
fi
verification_dir="$(
  builtin cd -P -- "${script_dir}/.."
  /usr/bin/pwd -P
)"
readonly verification_dir
repo_root="$(
  builtin cd -P -- "${verification_dir}/../.."
  /usr/bin/pwd -P
)"
readonly repo_root
caller_root=$(/usr/bin/pwd -P)
readonly caller_root

if [[ "${caller_root}" != "${repo_root}" ]]; then
  fail_usage \
    "run the authoritative ledger gate from the physical repository root"
fi
if [[ ! -f "${verification_dir}/Makefile" ]] \
    || [[ ! -f "${script_dir}/check_ledger_consistency.py" ]]; then
  fail_usage "resolved verification trust root is incomplete"
fi

receipt_dir=$(/usr/bin/mktemp -d \
  /tmp/pq-ledger-completion.XXXXXXXX)
readonly receipt_dir
case "${receipt_dir}" in
  /tmp/pq-ledger-completion.*) ;;
  *) fail_usage "mktemp returned an unexpected completion-receipt path" ;;
esac
receipt="${receipt_dir}/verify-ledger-consistency.log"
readonly receipt

cleanup() {
  /usr/bin/rm -f -- "${receipt}"
  /usr/bin/rmdir -- "${receipt_dir}" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

gate_status=0
/usr/bin/make -C "${verification_dir}" verify-ledger-consistency \
  >"${receipt}" 2>&1 || gate_status=$?
/usr/bin/cat -- "${receipt}"
if ((gate_status != 0)); then
  builtin printf \
    'ERROR: verify-ledger-consistency exited %d\n' "${gate_status}" >&2
  exit 1
fi

readonly expected_completion='OK: every advertised closure, exact full-ledger/row/artifact schema and value, count, status/method tally, and headline-statement pin matches the live Lean truth.'
completion_count=$(
  /usr/bin/grep -Fxc -- "${expected_completion}" "${receipt}" || :
)
readonly completion_count
if [[ "${completion_count}" != "1" ]]; then
  builtin printf \
    'ERROR: expected exactly one ledger completion marker, found %s\n' \
    "${completion_count}" >&2
  exit 1
fi

builtin printf \
  'OK: authoritative verify-ledger-consistency completion receipt matched\n'
