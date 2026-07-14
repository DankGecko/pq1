# Tamarin — idealized symmetric three-counter PIN research model

This model proves a property of an **idealized symmetric reconcile** over MCU
page-124, OPTIGA E120, and an abstract SE050 counter. It is useful as a research
contrast model: under that stronger predicate, a single/double counter reset is
caught and only an all-three reset survives. It is not evidence for the deployed
boot policy, which reads page-124 and E120 directionally and has no SE050
attempt-count input. The model complements the ProVerif secrecy model
(`../proverif/`); it does not certify deployed PIN reconciliation.

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

The two all-traces lemmas **together** are the security property **of this
idealized SYMMETRIC model**: a surviving boot is reachable *only* via **no
reset** or **all-three reset**, so a partial reset can never survive a boot *in
the model*.

> **⚠ MODEL ≠ DEPLOYED CODE (2026-07-02, finding PM-1).** The shipped
> `reconcile_pin_attempts` (`secure/src/nsc/mod.rs`) is **DIRECTIONAL**
> (`tamper = (se_count > mcu) || se_split`), not symmetric, and catches
> **strictly less** than these lemmas assert: a coordinated reset of **both** SE
> counters (optiga = se050 = 0) is **NOT** wiped by the deployed code (se_count=0,
> se_split=false, 0 > mcu = false), and in the shipping config (SE050 counter
> read = None) even a single OPTIGA reset is undetected by reconcile. So the
> "a single-side reset is always caught" claim holds **only in the model**, not
> for the deployed directional check. Reconcile is a defense-in-depth cross-check;
> the attacker is still bounded by the primary per-SE silicon lockout + the MCU
> page-124 pre-commit, so this is an overstated-model / false-README defect, not a
> fund-drain. Re-modeling the directional predicate (the both-SE reset then
> surfaces as a NEW residual) is the tracked follow-up.

### Relationship to the threat model

- This is an idealized research hypothesis adjacent to Claim 3
  (`threat-model.md §6.2`), not a proof of that deployed claim.
- `full_reset_bypass` identifies the symmetric model's residual. The deployed
  directional page124/E120 policy has a different state space and must be
  modeled and validated separately. Hardware-monotonic E120 remains a primary
  per-attempt control, not a theorem imported from this model.

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
