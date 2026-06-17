# Tamarin — three-way PIN-attempt lockstep model

Stateful symbolic proof that the three-way PIN-attempt reconcile (MCU page-124
+ OPTIGA F1E1 + SE050 UserID) catches any single/double counter reset, so the
per-counter "≤10 attempts" silicon cap cannot be reset-bypassed without
resetting **all three** counters. This is the **stateful** companion to the
ProVerif secrecy model (`../proverif/`): ProVerif proves the message-level
secrecy/authentication, Tamarin proves the reachable-state counter property
ProVerif (and the impl-proofs / SCA-FI sweeps) cannot.

## Run

```sh
make tamarin                                  # from the repo root
# or directly:
tamarin-prover --prove contracts/verification/tamarin/pin_lockstep.spthy
```

Install (no sudo, no GHC build): drop the prebuilt **tamarin-prover** linux64
binary and the **maude** backend binary into `~/.local/bin`:

```sh
# tamarin-prover (the GitHub release ships a static linux64 binary)
curl -fsSL https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz | tar xz
cp tamarin-prover ~/.local/bin/
# maude (Tamarin's rewriting backend)
curl -fsSL -o maude.zip https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip
unzip maude.zip && cp maude ~/.local/bin/   # + the *.maude prelude files alongside
```

## What is proven (all four lemmas verified)

| Lemma | Kind | Result | Meaning |
|---|---|---|---|
| `honest_boot_possible` | exists-trace | verified | anti-vacuity: a provisioned device boots and survives — the model is not trivially always-wipe |
| `fresh_synced_means_no_reset` | all-traces | **verified** | a surviving "fresh" boot ⟹ **no** counter was ever reset before it |
| `zero_synced_means_all_reset` | all-traces | **verified** | a surviving "zero" boot ⟹ **all three** counters were reset before it |
| `full_reset_bypass` | exists-trace | verified | the residual: resetting all three together survives a boot |

The two all-traces lemmas **together** are the security property: a surviving
boot is reachable *only* via **no reset** or **all-three reset**, so a **partial
reset (one or two of the three counters) can never survive a boot** — the
un-reset counter(s) desync the reset one and reconcile wipes. A single-side
reset (the **S-1** OPTIGA glitch alone, an **SE050 delete** alone, or a TZ-bypass
**MCU erase** alone) is therefore always caught.

### Maps to the threat model

- This is **Claim 3** (`threat-model.md §6.2`) at the protocol level: every PIN
  attack is online, and the three-way lockstep makes a counter rewind detectable.
- The `full_reset_bypass` residual is exactly the documented limitation in
  `reconcile_pin_attempts` ("the attacker can reset at most two sides per
  campaign"). The **hardware-monotonic OPTIGA counter** (work-todo #24 /
  ship-blocker **S-3**) closes it by making `Reset_OPT` impossible — dropping the
  attacker to "reset 1 of 3", which `fresh_synced_means_no_reset` catches. So
  this model also *quantifies the value of S-3*.

## Out of frame (deliberate — stated, not discovered)

- **Exact ≤10 count**: each counter's value is abstracted to a STATUS — `fresh`
  (in lockstep) or `zeroed` (reset). Faithful for the reconcile property
  (lockstep counters agree; a reset desyncs one), but it does NOT prove the
  numeric "10" cap — that is enforced inside each SE's silicon and is the
  per-counter premise this model's reconcile *defends*, not re-proves.
- **One boot per trace**: the boot rule is terminal, so the state space is
  finite and the safety lemmas are decidable. reconcile runs at *every* boot, so
  the per-boot guarantee proven here is the operative one; the model does not
  chain multiple boots in a single trace.
- **Tunnel crypto / message secrecy**: that is the ProVerif model's job
  (`../proverif/`). This model is purely about the counter/reconcile state.

---

# `scp03_replay.spthy` — SCP03 in-session anti-replay (counter)

The stateful half of the SCP03 replay-window proof (the ProVerif companion
`../proverif/scp03_replay.pv` proves the no-forgery trace property). Models the
in-session command counter: the card accepts only the expected next counter and
advances, so a captured wrapped command cannot be replayed/reordered.

| Lemma | Kind | Result |
|---|---|---|
| `can_accept` | exists-trace | **verified** — a command can be accepted (anti-vacuity) |
| `no_replay` | all-traces | **verified** — each counter is accepted at most once (injective anti-replay) |

`no_replay` is exactly the injective property ProVerif over-approximates;
Tamarin's explicit linear `Expected` counter token (consumed on accept) proves it
directly. The MAC check is an equality `restriction` (not a pattern match) to
avoid a partial deconstruction — so it needs no `--auto-sources`. `no_forgery`
lives in the ProVerif companion (Tamarin's automated prover does not auto-close
it — the `Expected`-token loop, same class as `pin_lockstep`).
