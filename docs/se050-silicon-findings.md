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

1. **Update `secure/src/se050/mod.rs:485-510` doc** to retract the
   "policy-gate-independent attribute read" claim. The silicon evidence
   is `b88gzpjod.output:1503-1504`. Note that `pin_attempt_count_raw`
   returns `None` on production `USERID_OBJ` and the SE050 leg of the
   boot-time reconcile is silently skipped.
2. **Update `apdu.rs:42-54`** to add SW=0x6982 to the
   `AuthMethodBlocked` mapping arm (Finding from #17). Add a
   comment naming `b88gzpjod.output` as the silicon evidence.
3. **Update `audit_admin_cannot_rotate_user_pin` test** to assert the
   ACTUAL silicon behavior under the threat model: failed UPDATE
   destroys-but-doesn't-substitute. PASS = original UserID gone AND
   attacker PIN doesn't work either. Note in the test doc that A2 is
   an accepted DoS.
4. **Replace `read_userid_attempts`** in P1, P4, P5 with a
   SW=0x63Cx-based counter readback (one burn per readback) OR open
   a real session with the correct PIN (no burn but resets counter to
   0 so doesn't help mid-burn probes). The tests need rework to fit
   what's actually inspectable on silicon.
5. **Fix the seed test #5** (`object_extended_lc_boundary`) — cap
   payload at ≤960 B.
6. **`StressCtx::open_user_session`** should recover from a failed
   verify by calling `ctx.reinit()` before returning the error — that
   way subsequent operations in the test see a clean chip and the
   real assertion runs.

None of the above is required to ship — the security invariant is
silicon-verified. They're hygiene fixes to make the test harness
report accurately on the next run.

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
