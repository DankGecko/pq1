# USB stack + compromised-companion adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code-review pass over PQSigner's outermost attack surface — the NS-side USB stack (`nonsecure/src/usb/`, `shared/src/apdu_framing.rs`) and the **compromised-companion / malicious-web-extension threat model**. This is the *outer-attacker anchor*: it enumerates what a fully-hostile host can attempt across **every** flow and maps each to its on-device defense.

> **The threat, stated once.** The USB host, the companion app (browser WebHID extension / desktop), and every APDU byte on the wire are **fully adversarial**. The NS-world USB stack is itself untrusted (a TrustZone-NS blob) — the only boundary that matters is the NSC gateway into the secure world. So a NS crash is a **DoS-class** finding (no secret exposure — NS never holds a secret); the real severity bar is reserved for anything that **crosses the gateway** or induces a **wrong-but-valid signature**. The device is **origin-blind** — it sees only bytes, never a web origin — so it *cannot* rely on the browser's per-origin WebHID grant; every defense must be on-device.

**How this differs from the bench red-team + the sibling playbooks.** [`docs/security/red-teaming.md`](../red-teaming.md) §8 covers the bench view of the NS gateway / USB / counters. This playbook is the *code-review* of the NS transport **and** the cross-cutting companion-trust map. It deliberately **cross-links rather than duplicates** the per-flow defenses — each hostile-companion attack lands in another playbook's catalog. What *this* playbook owns exclusively is the **NS-transport-specific** surface: HID framing/reassembly bounds, channel-ID isolation, APDU-chaining confusion, the idle-timeout scrubbers, IWDG USB-loop liveness, the USB-C warm-reset DoS surface, and the origin-blindness posture.

> **Honesty note.** The NS transport is *defended-by-construction* (every copy is bounds-checked + FI-clamped + proptest-fuzzed), so most rows are "closed, here is the fuzz/clamp." The live value is the **map** (Part A2) — because a reader must know that "the companion is assumed hostile" is the *design*, and which on-device mechanism carries each attack. The one reasoned-latent hot spot for a fresh pass is the stateless-slot-selection abuse (UC6).

---

## Part A — The NS-transport failure catalog (UC1–UC5, transport-owned)

The failure modes this playbook **owns** (the cross-cutting companion attacks are Part A2). NS-side, so severity is DoS unless it crosses the gateway.

| # | Failure mode | What it looks like | Status (this tree) | Detection | Auto? |
|---|---|---|---|---|---|
| UC1 | **Frame-length not bounded before a copy** | an attacker USB frame overruns the reassembly / TX buffer | **DEFENDED-by-construction (DoS-class if any residual).** Every copy is preceded by a bounds check + a **doubled `fi_min` FI clamp** (defends the O'Flynn EMFI-on-`min` class): first/continuation frame (`apdu_framing.rs:379-409`), TX (`transport.rs:152`), chunked response (`commands.rs:760`); `MAX_APDU_RX=4096`; `checked_add` re-check even after the clamp | proptest fuzz `apdu_framing.rs:441-594` (`hid_frame_random_input_never_panics`, `parse_apdu_header_never_panics`, `hid_frame_oversize_n_dropped`) | ✅ proptest fuzz |
| UC2 | **A command reaches the gateway without S-side validation** | the NS router hands the secure world an unvalidated pointer/length | **DEFENDED (cross-link gateway).** NS passes `(ptr, ptr, len)` raw (`nsc_api.rs:421-423`); the **secure side** validates via `validate_ns_{read,write}_ptr` + the `TT` instruction *before* any deref. NS does not (and must not) validate | Walk the newer veneers (`nsc_sign_userop_batch`, prodtest, `nsc_register_heartbeat`) for a deref-before-validate — **[trustzone-gateway playbook](./trustzone-gateway-adversarial-review.md) TZ1–TZ8** owns this | ✅ via gateway playbook |
| UC3 | **APDU-chaining / channel confusion** | a cross-tab confused-deputy interleaves frames, or an INS-swap mid-chain smuggles bytes | **DEFENDED.** Channel-ID isolation (`apdu_framing.rs:386`, regression-pinned `:754-831`); seq monotonicity; INS-swap-mid-chain → reset (`:182-186`); a fresh seq=0 interrupting a partial reassembly aborts + scrubs (`:350-357`); INS allowlist *before* `chain.step` accepts bytes so a bogus INS can't burn 8 KB (`commands.rs:292-300`, `per_cmd_chain_bound:99-112`) | proptest `chain_step_sequence_pos_within_capacity`; channel-isolation regression tests | ✅ proptest + regression |
| UC4 | **Idle / stalled-reassembly secret residue** | a host declares a large APDU then stalls, leaving a half-assembled buffer | **DEFENDED.** Reassembly 5 s timeout scrubs a half-assembled buffer (`transport.rs:123-136`); GET_RESPONSE 30 s inter-chunk drain timeout (`commands.rs:794-812`); pending-buffer scrub on any non-GET_RESPONSE while a chunked drain is live (`commands.rs:213-217`) | Timeout unit tests; NS is untrusted so this is defense-in-depth | ✅ (defense-in-depth) |
| UC5 | **DoS via USB-C warm-reset / hung loop** | a host wedges the transport or PRL so the device stops responding | **DEFENDED (DoS-only).** IWDG hang-reset (NS heartbeat bump per loop `main.rs:195-199` → `nsc_register_heartbeat` → secure SysTick stops feeding IWDG on a hung loop); OTG hardening forces `FDMOD=1` + masks the SOF timing side-channel (`usb_hw.rs:harden_otg`); documented USB-C warm-reset recipes (`cc_open_then_reset`) | `fwup-transport-hw-iwdg` HW e2e (wipe-trigger + warm-reset validation) | ✅ HW e2e |

---

## Part A2 — The compromised-companion map (what a hostile host attempts → its on-device defense)

This is the anchor: every remote attack a malicious companion / web-extension can mount, and the **on-device** mechanism that stops it. Cross-links, not re-derivations.

| Companion attack | On-device defense (anchor) | Owning playbook |
|---|---|---|
| **Lie about calldata** (show benign, sign malicious) | on-device clear-sign decode + trusted-display render; the C10 sig commits to the *decoded* bytes | [clear-signing](./clear-signing-adversarial-review.md) — CS1–CS10 (WYSIWYS) |
| **Send malformed pointers / lengths** across the gateway | S-side `TT`-instruction NS-range validation *before* any deref (`ptr_validate.rs`) | [trustzone-gateway](./trustzone-gateway-adversarial-review.md) — TZ1–TZ8 |
| **Deliver a malicious firmware image** | signed-preimage verify in S-world before any destructive write; NS is pure transport | [firmware-update + secure-boot](./firmware-update-secure-boot-adversarial-review.md) — FW1–FW10 |
| **Request a signature forgery / off-chain drain** | firmware — never the companion — does the `replaySafeHash` nesting; per-slot counter/gap/combined-cap; bootstrap key forbidden off-chain | [off-chain signing](./offchain-signing-adversarial-review.md) — OC1–OC9 |
| **Pick a wrong slot/chain to force key reuse** | **the slot key is *derived* from `(master_entropy, chain_id, slot_index)`** — a lie derives a *different* key, not a reuse; the sig validates only for that (chain, slot) and on-chain `validateUserOp` binds it. The FI risk (a glitch flipping `REGISTER_SLOT`) is swept by `fault_sweep_dispatch.py` | derivation-binding (`cmd_sign_userop.rs`) + [sca-fi](./sca-fi-adversarial-review.md) |
| **Substitute a hash the user didn't see** | the device never accepts a companion-supplied hash for known shapes; it re-derives the EIP-712/1271 final hash on-device | [clear-signing](./clear-signing-adversarial-review.md) + [off-chain](./offchain-signing-adversarial-review.md) |
| **Spam wrong PINs** | three-way per-attempt consumption; directional MCU-page124/OPTIGA-E120 boot check; independent SE050 lockout | [secure-element](./secure-element-adversarial-review.md) — SE3/SE4 |
| **Suppress / spoof a confirm** | confirm is driven by the S-world trusted display + physical buttons (secure-owned GPIO); NS/companion has **no code path** to it | [trusted-UI](./trusted-ui-adversarial-review.md) — UI4/UI6 |
| **Web-extension origin-confusion** | the device is **origin-blind** (no origin field on the wire) — defense is entirely on-device clear-sign + confirm; the browser's per-origin grant is a host-side control the device does not rely on | (posture — this playbook) |
| **DoS the transport** | timeouts + IWDG + NS-is-untrusted (a crash exposes no secret) | UC1/UC4/UC5 (this playbook) |

**The one reasoned-latent hot spot (UC6, worth a fresh Part-C pass):** the 22-bit `slot_index` + 8-bit `account_index` are fully attacker-chosen (`webhid_test.html`); the defense chain is derivation-binding + the `INCLUDE_INIT_CODE ⊕ REGISTER_SLOT` mutex whose FI-robustness is F-11-hardened (double-read flags) and swept by `fault_sweep_dispatch.py`. It is *bounded* (a lie yields a different key, not a reuse), but it is the richest spot to re-attack.

---

## Part B — The existing defenses (Layer 1)

1. **Shared framing crate (production == fuzz harness).** All attacker-facing state machines live in dependency-free `shared/src/apdu_framing.rs` so the production path and the proptest fuzz are byte-identical: `HidFrameAssembler::process_frame` (the single choke point), `parse_apdu_header` (`checked_add` Lc), `ChainState::step` (INS-swap reset, overflow-safe accumulation). FI-clamped with doubled `pqsigner_fi::fi_min`.
2. **NS router with dual INS allowlists.** `nonsecure/src/usb/commands.rs` — `dispatch`/`route_v2` + `execute_chain`, per-command payload caps, `per_cmd_chain_bound`, response-buffer locking, chunked-response FI clamp.
3. **OTG hardening + liveness.** `secure/src/hw/usb_hw.rs` (`FDMOD=1`, SOF-mask, secure clock/GPIO setup before NS starts, only the needed pins un-secured); IWDG USB-loop watch via `nsc_register_heartbeat`.
4. **FI sweep on dispatch.** `tools/sca/fault_sweep_dispatch.py` — instruction-skip / stuck-at over the Type-1/2 flag decode (the `REGISTER_SLOT`/`INCLUDE_INIT_CODE` mutex). Owned by [sca-fi](./sca-fi-adversarial-review.md).
5. **HW e2e.** `make play-hw-display`, `e2e-hw`, `fwup-transport-hw{,-iwdg}`, `test-update-hw`. Wire protocol pinned in `docs/companion/usb-protocol-v2.md`; browser client `tools/webhid_test.html`.

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial reviewer of PQSigner_OS's USB stack + the compromised-companion
threat model. Assume the USB host, the companion app, and every byte on the wire are FULLY
HOSTILE, and the device is ORIGIN-BLIND. Your job is to find (a) an NS-transport bug that
crosses the gateway or induces a wrong-but-valid signature — NOT a mere NS crash (that is
DoS; NS holds no secret) — and (b) a hostile-companion attack whose on-device defense is
missing or bypassable. Default to "the companion can make the device do X until I prove the
on-device mechanism stops it."

TARGET (read first, in this order):
  - docs/security/adversarial-review/usb-companion-adversarial-review.md §A + §A2 — UC1–UC5
    (transport-owned) + the compromised-companion map.
  - shared/src/apdu_framing.rs — HID framing/reassembly + chain state machine (+ its proptest).
  - nonsecure/src/usb/{commands,transport,hid,mod}.rs + nonsecure/src/nsc_api.rs + main.rs.
  - secure/src/hw/usb_hw.rs — OTG hardening + warm-reset.
  - docs/companion/usb-protocol-v2.md + tools/webhid_test.html — the wire protocol + client.
SCOPE THIS RUN: {{e.g. "the HID reassembly bounds + FI clamps" | "APDU-chaining/channel
  isolation" | "the stateless-slot-selection abuse (UC6)" | "the compromised-companion map —
  is every attack's defense actually present?"}}.

ATTACK PROTOCOL:
  - Transport (UC1–UC5): find a copy not bounds-checked before it runs; a chain/channel
    confusion; a stall that leaves secret-bearing residue; a DoS with no timeout/IWDG backstop.
  - Companion map (§A2): pick an attack, follow its cross-link, and verify the on-device
    defense EXISTS and is not bypassable — if the linked playbook's mechanism is missing or
    weaker than claimed, that is a finding HERE (a broken map entry).

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a frame/APDU sequence the fuzz harness would panic or overrun on (or that crosses the
    gateway with an unvalidated pointer/length);
  - a chain/channel interleaving that mixes two hosts' data or smuggles bytes;
  - a companion request whose on-device defense is absent (cite the missing mechanism);
  - a slot/chain lie that yields key REUSE (not just a different key) or a cross-chain replay.
  No PoC ⇒ list under "suspicions, unverified". An NS-only crash is DoS — label it so.

RULES:
  - Verify against the CURRENT tree; NS is untrusted BY DESIGN — do not report "NS trusts the
    host" as a vuln; report where a hostile input crosses the gateway or defeats an on-device
    defense.
  - The device is origin-blind — "the extension can be malicious" is the assumed model, not a
    finding; the finding is a missing on-device defense.
  - For each candidate: UC-mode or map-entry, file:line, PoC, provisional
    severity (DoS vs gateway-crossing vs wrong-sig), stable candidate ID, and
    proposed fix. Do not assign a finding disposition.

OUTPUT — return an external candidate packet to the coordinator. Do not modify
the repository, write a canonical findings report, or update catalogue/status
fields. Include every candidate and the honest residual. The coordinator freezes
the raw packet and gives the complete union to the exact Partner-A/Partner-B
pair; only their symmetric cross-adjudication may assign dispositions. An
authorized maintainer records the adjudicated result afterward.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per transport stage + per map entry.
  2. "What I did NOT look at" — flows not walked, map entries not verified end-to-end.
  3. "PROVENANCE — did this pass RUN the framing proptest / fault_sweep_dispatch / the HW
     e2e, or read source only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** Use ≥3 independent discovery reviewers per scope
across two model backends. Quorum only corroborates/prioritizes discovery; it
does not set a disposition, and sub-quorum variants remain in the packet. Give
every candidate and origin variant to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only their symmetric cross-adjudication may disposition it, with disagreement
preserved. The map (§A2) is best split one-entry-per-reviewer so each
independently verifies the linked defense exists.

---

## Part D — Cadence + honest boundary

- **Per-PR touching `usb/`, `apdu_framing.rs`, or `nsc_api.rs`:** the framing proptest + a scoped Part-C pass; a change to a companion-facing command re-verifies the §A2 map entry for that flow.
- **Per-milestone:** full-scope Part-C swarm (transport + map) + `fault_sweep_dispatch.py` + the HW e2e matrix.
- **The one-line gut check:** *for each thing a hostile companion can send, is the defense ON THE DEVICE (not "the browser wouldn't do that")?* If a defense lives only in the companion or relies on origin, it does not exist.

**The boundary, stated on purpose.** This playbook can tell you that the NS transport is bounds-safe and that every mapped companion attack has an on-device defense, as of the last executing pass. It **cannot** tell you the linked defense is itself sound (that is the owning playbook's job — follow the link), that an NS crash you found is truly DoS-only (confirm no secret transits NS), or that a flow you didn't map is defended. Those are the sibling playbooks' + the next round's job.
