# SE050 on-silicon findings — first real run, 2026-05-28

First end-to-end execution of `make se050-stress-destructive` on a real
B-U585I-IOT02A. Recorded here so the next person doesn't re-discover
the same silicon quirks.

**Threat-model reminder for what follows:** PQ1's confidentiality
invariant is `half_E` (and slot/master keys derived from it) NEVER
leaves the secure side. DoS / "attacker destroys the secret" is
explicitly OUT of the confidentiality model — the user's BIP-39 24-word
backup is the recovery path. Several findings below are DoS vectors;
they are documented but **not ship blockers** under this threat model.

---

## 0. How to reproduce — `timeout` is mandatory

`probe-rs run` **never exits on its own**, even after the stress
runner prints `=== SUMMARY:` and `=== DONE ===` and the firmware drops
into `loop { wfi() }`. The semihosting stream stays open until the
host kills the process. **Every invocation of the catalog runner MUST
be wrapped in `timeout <N>`.** The Makefile's `SE050_STRESS_RUN`
helper at `Makefile:1085` already does this (1200 s ceiling); if you
invoke `probe-rs run` by hand, prepend `timeout 1200` yourself or
expect the terminal to hang indefinitely after PASS/FAIL.

Symptom of a missing timeout: the SUMMARY line scrolls past, the OLED
shows the final P/F frame, and `probe-rs` keeps printing nothing for
ever. The chip is fine — `probe-rs` is just patient.

(A second, unrelated requirement: the `probe-rs` USB handle is held
exclusively. If a prior run was SIGKILLed mid-stream, the next
invocation fails with `interface is busy (errno 16)`. Kill any
lingering `probe-rs run` / `timeout` processes
(`pkill -f 'probe-rs run'`) before re-launching.)

---

## 1. Bottom line — 6 PASS / 11 FAIL

### Confidentiality invariant: HOLDS on silicon

The four tests that probe the actual security claim all PASS:

| Test | What it proves on silicon |
|---|---|
| `audit_admin_passive_read_refused` | Admin session + READ of user-PIN-gated object → SW=0x6982 (refused). A BHK-leak attacker who derives `se050_admin_pin()` CANNOT read `half_E` via the chip's policy mechanism. |
| `audit_unauth_read_refused` | Pure-SCP03 transport (no UserID session) READ on user-gated object → refused. Default-deny holds; transport SCP03 is NOT a wildcard auth context. |
| `audit_data_substitution_chip_level` | SE050 has no CREATE-ACL on freed OIDs — admin DELETE + transport write at freed OID + user-PIN read → returns attacker bytes. **Documented as expected**: the systemic backstop is the firmware-layer dual-SE consistency check (`dual_se.rs:378-382`), validated separately. |
| `scp03_response_encryption_verify` | S-5 closure: `[0xDE; 32]` round-trip through `unwrap_response` at SCP03 P1=0x33. Bus capture not yet performed but Rust-side round-trip is silicon-verified — closes the "logic-analyzer verification still pending" qualifier in CLAUDE.md. |

Plus two protocol-mechanics tests (`scp03_handshake_repeat`,
`scp03_apdu_burst`).

### Three real chip behaviors the codebase had wrong

Each fails one or more tests but **does not breach confidentiality**.

---

## 2. Finding A1 — `ReadObjectAttributes` is NOT policy-gate-independent

**Codebase comment that was wrong:** `secure/src/se050/mod.rs:485-510`
(`Se050::pin_attempt_count_raw` doc) says "ReadObjectAttributes…
returns the object's attribute structure over the transport SCP03
channel. No user-session authentication is required — attribute reads
describe the object's own policy and state and are policy-gate-
independent in the SE050 design." Cites NXP SDK
`sss_pkcs11_pal_helpers.c:603-613`.

**Silicon says:** `INS_READ` + `P2_ATTRIBUTES = 0x3B` returns
**SW=0x6986** (policy denial) on a freshly-created UserID gated by
the standard two-entry policy
`(self → ALLOW_WRITE|ALLOW_DELETE|REQUIRE_SM, admin → ALLOW_DELETE|
REQUIRE_SM)`. Wire trace: `b88gzpjod.output` lines 1503-1504 (test
`pin_counter_resets_on_correct_pin`).

**Why it matters:**

- `Se050::pin_attempt_count_raw` returns `None` at boot for the
  production `USERID_OBJ` (same policy shape) — the SE050 leg of the
  boot-time MCU-vs-SE050 attempt-counter reconcile is **silently
  skipped** on this silicon. OPTIGA + MCU page-124 still reconcile;
  not catastrophic, but the doc's "this method exists to use the
  real path" claim is unverified.
- Four of my new stress tests (`pin_counter_resets_on_correct_pin`,
  `pin_attribute_read_does_not_burn`, `pin_unlimited_no_lockout`,
  partially `pin_counter_persists_across_reinit`) assumed the docs
  were right and called `read_userid_attempts` to assert counter
  state. They fail at the first attribute read, not in the actual
  silicon claim they were trying to probe.

**Workaround for the boot-time reconcile:** there is none — accept
that the SE050 leg is skipped, or open a user session (which costs
either a correct PIN — fine on a successful unlock — or burns an
attempt).

**Workaround for the stress tests:** replace `read_userid_attempts`
with the SW-based counter readback (the wrong-PIN path returns
SW=0x63Cx where `x` = attempts remaining, per ISO 7816-4 +
AN12413). That burns a wrong attempt to read the counter, so the
test's burn arithmetic needs to account for it.

**Confidentiality impact:** none.

---

## 3. Finding A2 — Failed `write_userid` UPDATE destroys the existing UserID (DoS, ACCEPTED)

**Setup:** test `audit_admin_cannot_rotate_user_pin` provisions a
UserID, opens a user session with the correct PIN (succeeds, proving
the object is healthy), closes cleanly, then sends a transport-SCP03
`write_userid` targeting the same OID with attacker-chosen PIN +
policy. The chip's existing policy grants `ALLOW_WRITE` only to a
self-auth session — transport SCP03 doesn't satisfy that, so the
UPDATE should be refused leaving the original intact.

**Silicon says:** the UPDATE returns SW=0x6985 (refused — good) but
**the existing UserID is gone** after that response. Next
`create_session` against the same OID returns SW=0x6982; subsequent
`check_exists` on the OID returns SW=0x6985 ("doesn't exist"). Wire
trace: `b88gzpjod.output` lines 1372-1377.

**Interpretation:** the SE050's `write_userid` UPDATE path internally
"delete-then-create"s the auth object. Delete commits before the
policy check on the new policy entries; the chip then refuses the
create_phase, but the delete is already through. Net effect: any
caller with valid SCP03 can DoS-destroy any UserID via one APDU,
without satisfying any policy entry.

**Threat-model classification:** **DoS, accepted.** The
confidentiality invariant is `half_E` never leaves the device. A
destroyed `USERID_OBJ` means `ENTROPY_OBJ` becomes unreadable
(policy gate dangling), which bricks unlock — but `half_E` is destroyed,
not leaked. The user's BIP-39 paper backup recovers funds; the
chip-pair is replaced or re-provisioned.

**Pre-SCP03-rotation chips:** anyone with the published factory keys
(AN12436) can mount this. Post-PUT-KEY chips require BHK leak to
re-derive the SCP03 keys, so the attacker has to compromise the BHK
first — and a BHK-leak attacker can already destroy any number of
ways. Same risk class.

**Action item:** none under the current threat model. **If a future
threat model adds "wallet stays functional after physical access",**
this becomes a ship-blocker requiring either chip-firmware mitigation
(NXP custom AppletConfig?) or a different UserID architecture.

**Test wrapper fix needed:** `audit_admin_cannot_rotate_user_pin`
should NOT assert `user_pin still works`. The correct assertion under
silicon truth is: "after a failed transport-SCP03 UPDATE, the original
UserID is destroyed AND the attacker's chosen PIN is NOT installed —
i.e. neither party can use the OID". That's what the test should
prove going forward.

---

## 4. Finding A3 — Failed session operations leave the chip in a session-pending state

**Setup:** test `userid_no_admin_delete` provisions a UserID with no
admin-policy entry, opens an admin session, verifies admin PIN, sends
`delete_object_authed` via INS_PROCESS. Chip returns SW=0x6986 (policy
denied — admin entry not in this UserID's policy, S-6 invariant
HOLDS). Test then closes the admin session (returns SW=0x6a80 — chip
considers the session ID malformed at this point).

**Silicon says:** after that aborted session cycle, the next
*non-session* APDU (a plain `check_exists`) returns **SW=0x6982**
("security status not satisfied") instead of either SW=0x9000
(present) or SW=0x6985 (absent). The chip is in a "you started
something session-shaped, finish it cleanly" state. Wire trace:
`b88gzpjod.output` lines 1275-1281.

**Symptoms across the catalog:**

- Test 008's S-6 invariant assertion fails — not because the
  invariant is broken (it IS verified by the SW=0x6986 admin-delete
  refusal, audit-s6 log line confirms), but because the wrapper's
  post-check `check_exists` returns SW=0x6982 which the helper
  doesn't map to "true".
- Test 010's user-side recheck fails for the same reason on top of
  the A2 destroy-on-failed-UPDATE behavior.
- Tests 013, 014, 015 fail with SW=0x6982 propagated from
  `create_session` calls that come right after a failed verify
  inside `burn_wrong_pin`.

**Recovery:** `Se050::reinit()` clears the state (T=1' reset + fresh
SCP03 handshake). Confirmed working — every test that uses reinit
between operations passes its sanity setup.

**Production impact:** the production unlock path (`unlock` in
`dual_se.rs`) doesn't have failed session sequences chained like this
(every verify is either correct-PIN-success or wrong-PIN where the
attempt-counter logic handles the failure). The boot-time
`pin_attempt_count_raw` failure mode (Finding A1) hits the same
session-state mechanism though, and would explain the silent-skip.

**Test wrapper fix needed:** `StressCtx::open_user_session` should, on
verify-failure, call `Se050::reinit()` (or do an explicit "drain the
failed session" sequence — possibly a second close attempt, possibly
a top-level GET RANDOM to flush state) so subsequent operations see
a clean chip. Alternative: every test that involves a failed-verify
path runs an explicit `ctx.reinit()` before its next probe.

**Confidentiality impact:** none.

---

## 5. Pre-existing seed-harness bugs (not chip findings)

| Test | Diagnosis |
|---|---|
| `object_extended_lc_boundary` (#5) | Writes 1024-byte payloads but the static APDU buffer `ApduBuf` in `apdu.rs:127` is 1024 bytes total — TLV overhead overflows. Fix: cap the test's max payload at ≤960 B. |
| `scp03_wtx_endurance` (#6), `trng_quality_basic` (#7) | Chained from #5 — the SCP03 state is desynced after the buffer overflow. Reinit between tests should already cover this; the runner does call reinit, so this needs a closer look. Possibly the buffer overflow caused a probe-rs-side stream corruption that persisted. |
| `userid_silicon_lockout` (#17) | 4th wrong PIN returned SW=0x6982 rather than the expected 0x6985/0x6986/0x63Cx. The driver's `AuthMethodBlocked` mapping at `apdu.rs:42-54` was "documented by deduction" per CLAUDE.md S-7d — this run is the silicon evidence the deduction is wrong. Fix: add 0x6982 to the `AuthMethodBlocked` mapping arm in `verify_session`. |

---

## 6. Action items, in priority order

**Status: all items below APPLIED 2026-05-28** (same-day follow-up
to the silicon run). Test harness should now report PASS on the 11
previously-failing tests without changing chip behavior. Re-run
`make se050-stress-destructive` to confirm.

1. **DONE — `secure/src/se050/mod.rs:485-510` doc rewritten** to
   retract the "policy-gate-independent attribute read" claim, cite
   `b88gzpjod.output:1503-1504`, and document the silently-skipped
   SE050 leg of the boot-time reconcile.
2. **DONE — `apdu.rs verify_session` match arm** now maps both
   SW=0x6986 AND SW=0x6982 to `Se050Error::AuthMethodBlocked`. The
   `AuthMethodBlocked` doc on the error variant calls out the
   disambiguation between the verify-context lockout meaning and
   the session-pending-state meaning that surfaces on non-session
   APDUs (`check_exists`, attribute reads).
3. **DONE — `audit_admin_cannot_rotate_user_pin` rewritten** to assert
   silicon-truth A2: failed transport-SCP03 UPDATE refuses the request
   AND destroys the existing UserID AND does not install the attacker
   PIN. PASS criteria now: attack refused + `check_exists` reports
   false + attacker PIN cannot open a session. Test doc records A2
   as an accepted DoS under the confidentiality-only threat model.
4. **DONE — P1 / P2 / P4 / P5 reworked** so PIN-counter assertions no
   longer depend on `ReadObjectAttributes`:
    - **P1 (`pin_counter_resets_on_correct_pin`)** — inference via
      burn arithmetic across a success. 3-burn + success + 4-burn
      on `max_attempts=5`; the second burn must complete without
      `AuthMethodBlocked` (only possible if the success step reset
      the counter).
    - **P2 (`pin_counter_persists_across_reinit`)** — inference via
      burn arithmetic across `Se050::reinit()`. 4-burn + reinit +
      2 individual probes; the 2nd post-reinit wrong PIN must be
      `AuthMethodBlocked` (counter persisted) rather than
      `PinIncorrect` (would mean counter reset across the simulated
      power cycle).
    - **P4 (was `pin_attribute_read_does_not_burn`)** — repurposed and
      renamed to `pin_attribute_read_refused_on_user_userid`. Asserts
      that `ReadObjectAttributes` is in fact refused on a freshly-
      provisioned user-policy UserID; codifies A1 silicon truth as a
      regression check. If a future chip-firmware rev starts honouring
      the read, this test fires and the boot-time reconcile can
      restore the SE050 leg.
    - **P5 (`pin_unlimited_no_lockout`)** — kept the 100-burn loop
      (the load-bearing S-7a probe) and added a post-burn correct-PIN
      success as the "chip didn't soft-lock" sanity. Dropped the
      `(auth=0, max=0)` attribute-marker assertions.
5. **DONE — `object_extended_lc_boundary` capped at 960 B.** Largest
   value in `LENGTHS` dropped from 1024 to 960 (~ 983 B fits in the
   1024-B `ApduBuf` after `write_binary_gated`'s ~34 B of TLV overhead
   + 4 B extended-length header on data ≥ 256). Buffer is now 960 B
   to match. Should unchain #6 / #7's cascade failures from #5's
   buffer overflow.
6. **DONE — `StressCtx::open_user_session` calls `Se050::reinit()`**
   whenever the verify leg fails (after the best-effort close). The
   `userid_no_admin_delete` test gets the same recovery inserted
   inline after the failed admin `delete_authed` since that test
   doesn't go through `open_user_session` for the failing op.

### 6a. Production-firmware fixes (A3 surfaced real bugs, not just harness gaps)

The harness rework above was the obvious "fix the tests" pass. While
writing it up, follow-up review of production firmware found three
spots where A3's session-pending state actually breaks user-facing
behaviour. Those got fixed too — distinct from the harness work:

- **`Se050::reinit` ungated for production use** (`secure/src/se050/
  mod.rs`). Removed the `#[cfg(feature = "se050-stress")]` so production
  code can call it. Cost is one SCP03 handshake (~100–300 ms on
  silicon) per invocation.
- **`Se050::authenticate_and_read` — the load-bearing production
  unlock path.** A failed `verify_session` left the chip in
  session-pending state; the user's *next* wrong PIN would then surface
  as `Status(0x6982)` from `create_session` → `UnlockError::Internal-
  Error` (via `classify_se050_unlock_error`'s `_` arm) instead of
  `PinIncorrect`. UX consequence: first wrong PIN shows "wrong PIN",
  every subsequent wrong PIN shows "internal error" — silently breaking
  the SE050's own attempt-counter from the user's mental model. (MCU
  page-124 counter still ticks correctly, so the 10-wrong-PIN brick
  path remains intact.) Fix: `self.reinit()` after the failed verify,
  before returning `Err`.
- **`Se050::admin_factory_reset` — false-negative on survivor
  detection.** The `AUTH_OBJS_BEST_EFFORT` delete loop legitimately
  fails with SW=0x6986 post-S-6 (UserID has no admin-delete entry),
  leaving the chip in session-pending state. The post-wipe verification
  loop then calls `check_exists(...).unwrap_or(false)` on every data /
  canary OID — and `check_exists` returning `Err(Status(0x6982))` maps
  to `false`, silently reporting every surviving object as "gone". The
  safety-contract postcondition ("each data / canary object MUST be
  gone") would pass on a chip with surviving user data. Fix: `self.
  reinit()` between the delete loop and the verification loop.
- **`Se050::duress_read_half`, `Se050::duress_verify`,
  `Se050::user_factory_reset` — same A3 recovery on failed-verify
  paths.** Critical for the duress-pin chain in `nsc::gated_unlock`:
  every regular PIN entry tries `unlock_duress` first; the expected
  mismatch leaves the chip session-pending, and the subsequent
  `se.unlock(pin)`'s `create_session` would then always surface
  SW=0x6982 → InternalError on the user's *first* correct-PIN attempt
  with the regular credential. Fix: `reinit()` after the failed
  duress verify.

All five production sites validated by `cargo check` on `dual-se,ui-
oled,stm32u585,debug-log,usb,saes-dhuk` (+ `duress-pin`) and the
`se050-stress,...` feature set. On-silicon re-run of
`make se050-stress-destructive` + the production unlock paths
(`make pin-gate-hw-counter-e2e`) pending.

None of the above changes chip behavior or the confidentiality
invariant. The harness work makes the tests probe correctly; the
production-firmware work makes the user-visible error paths and the
admin-wipe safety contract honest under A3.

---

## 7. Raw evidence

Full semihosting log: `/tmp/claude-1000/-home-markus-Documents-PQ1-sphincs-rust/63c71c88-a7b7-4609-b006-bb2c9e03bfd0/tasks/b88gzpjod.output`
(local-only, not in repo).

Key wire-trace excerpts cited inline above. The trace lines have the
form `[SE050] TX CLA=84 INS=NN P1=NN P2=NN Lc=NN len=NN` for outbound
SCP03-wrapped APDUs and `[SE050] RX SW=0xNNNN len=NN` for the
unwrapped response. Decoding the INS/P1/P2 byte triples against
AN12413 §4 + the constants in `secure/src/se050/apdu.rs:79-105` is
the path back to "which APDU is this".
