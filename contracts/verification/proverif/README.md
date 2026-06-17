# ProVerif — dual-SE seed-unlock protocol model

Symbolic-model (Dolev-Yao) proof that the dual-SE seed-reconstruction unlock
keeps the seed secret under partial compromise, and that the PIN gate is
orthogonal to the tunnel crypto. This is the **protocol-level** assurance layer:
it complements the implementation proofs (Lean/Aeneas, Kani/Miri) and the
side-channel/fault sweeps (`tools/sca`), neither of which reason about the
message-level protocol against a network attacker.

## Run

```sh
make proverif            # from the repo root
# or directly:
proverif contracts/verification/proverif/dual_se_unlock.pv
```

ProVerif CLI install: `opam install --assume-depexts proverif`, or build the CLI
from source (the GUI's `lablgtk2`/GTK2 dep is NOT needed for the CLI).

## What is proven — each query maps to a threat-model S-tier → Claim

| Query (model) | Attacker capability | Expected | Maps to |
|---|---|---|---|
| `scenarioBaseline` | Dolev-Yao on the I2C bus only | seed **secret** | warm-up (tunnels hold) |
| `scenarioClaim1` | bus + **one** entropy half extracted (one S4) | seed **secret** | **Claim 1** — dual residency (*structural* need-both-inputs; see note) |
| `scenarioClaim2` | bus + **both channel keys** (S2 / DHUK-PBS leak), **no PIN**, **fresh** (no captured session) | seed **secret** | **Claim 2** — channel access ≠ read access (see replay caveat) |
| `scenarioPositiveControl` | bus + **both** halves extracted | seed **NOT secret** | anti-vacuity control (see below) |
| `ReleasedHalfO/E ==> PresentedPinO/E` | — | **true** | §6.2 — no half released without a correct PIN ("every PIN attack is online") |

Run output (all six lines must appear):

```
RESULT not attacker(reconstruct(hoB[],heB[])) is true.    # baseline secret
RESULT not attacker(reconstruct(ho1[],he1[])) is true.    # Claim 1 secret
RESULT not attacker(reconstruct(ho2[],he2[])) is true.    # Claim 2 secret
RESULT not attacker(reconstruct(hoP[],heP[])) is false.   # positive control: NOT secret
RESULT event(ReleasedHalfO(h,p)) ==> event(PresentedPinO(p)) is true.
RESULT event(ReleasedHalfE(h,p)) ==> event(PresentedPinE(p)) is true.
```

### The positive control is load-bearing

A ProVerif `secret` result is worthless if the model is *vacuously* safe (seed
never computed, an over-abstraction, etc.). `scenarioPositiveControl` leaks
**both** halves and asserts the seed is derivable — ProVerif must report it
**NOT secret**. If that query ever flips to `is true`, the model is broken and
every other PASS is meaningless. It is the protocol-model analogue of the F-9
positive control in the SCA harnesses.

### The PIN gate is load-bearing (per-mechanism control)

The global positive control proves the seed is *derivable at all*; it does not by
itself prove that `scenarioClaim2` passes **because of** the PIN gate rather than
because the halves merely never leave the SEs in that scenario. To earn that:
disable the silicon gate (`if p = realpin then` → `if p = p then`) and re-run —
Claim 2 flips from `secret` to **NOT secret** (a channel-key attacker then reads
both halves). Gate on → `secret`; gate off → `not secret`. So the gate is the
mechanism doing the work, verified rather than argued:

```sh
sed 's/if p = realpin then/if p = p then/' dual_se_unlock.pv > /tmp/gate_off.pv
proverif /tmp/gate_off.pv   # RESULT ... reconstruct(ho2,he2) ... is false
```

## Out of frame (deliberate — stated, not discovered)

- **Replay / session freshness**: `scenarioClaim2` models a **fresh** key-holding
  attacker with *no captured session*. A deployment-realistic attacker may have
  snooped a prior unlock's `senc(pin, k)` off the bus and, once it holds the
  channel key, replay it. This model cannot see that (no `sworld` in that
  scenario), and the auth correspondence is **non-injective** by choice, so
  `ReleasedHalf ⇒ PresentedPin` proves "a correct PIN was presented at least
  once", NOT "this release maps to a *fresh* presentation". Replay / anti-replay
  is therefore **out of frame, not proven safe** — it folds into the deferred
  key-establishment handshake model.
- **Claim 1 is *structural*, not information-theoretic**: symbolic `reconstruct`
  with no equational theory proves the attacker needs *both inputs* to form the
  seed. It does NOT prove the math-statement "one half is uniformly random /
  statistically independent of the seed" (Claim 1's information-theoretic flavor)
  — that is the cryptographic argument's job, not ProVerif's.

- **Counting bound** (≤10 PIN attempts, Claim 3): ProVerif is the wrong tool for
  monotonic-counter properties (Tamarin/GSVerif territory). What ProVerif proves
  here is the *qualitative* gate — no offline grind — not the count. (Claim 3 is
  also currently provisional, partially violated by ship-blocker S-1.)
- **Key-establishment handshakes**: `dual_se_unlock.pv` abstracts the per-channel
  key as pre-shared. The SE050 **SCP03** handshake that establishes it is now
  modelled separately in `scp03_handshake.pv` (see below), which justifies that
  abstraction for the no-leak case. The OPTIGA Shielded Connection (TLS-PRF/CCM-8)
  handshake remains a future model.
- **Quantum-harvest residual** (Claim 7): perfect symbolic crypto cannot express
  it; it stays a documented open item (ML-KEM inner wrap).
- **XOR-malleability / bit-flip**: `reconstruct` has no equational theory, so
  this model cannot express it — that surface is the FI track (F-28/F-29 R-MAC
  tamper).

---

# `scp03_handshake.pv` — SE050 SCP03 key-establishment handshake

Fills the handshake gap `dual_se_unlock.pv` leaves abstract. Models the
GlobalPlatform SCP03 mutual-auth + session-key derivation (`INITIALIZE UPDATE`
→ `EXTERNAL AUTHENTICATE`, session key = `KDF(static, host_chal, card_chal)`,
PIN VERIFY wrapped under the session key) and pins down exactly when the channel
protects the PIN. `make proverif` runs it after the seed-unlock model.

## What is proven

| Query | Attacker | Result | Meaning |
|---|---|---|---|
| `attacker(pinB)` | pure bus (Dolev-Yao), no key leak | **secret** | the channel protects the PIN — justifies the pre-shared-key abstraction in `dual_se_unlock.pv` |
| `HostAccepted ⟹ CardSent` | — | **true** | host authenticates the card (no impersonation without `static`) |
| `CardAccepted ⟹ HostSent` | — | **true** | card authenticates the host |
| `attacker(pinR)` | holds `static` (DHUK/PBS leak, S2) **and** captured a session | **NOT secret** | static-key leak + session capture recovers the PIN |

```
RESULT not attacker(pinB[]) is true.                                  # baseline PIN secret
RESULT event(HostAccepted(h,c)) ==> event(CardSent(h,c)) is true.     # card authenticated
RESULT event(CardAccepted(h,c)) ==> event(HostSent(h,c)) is true.     # host authenticated
RESULT not attacker(pinR[]) is false.                                 # residual: PIN recovered
```

### The residual is the documented Claim-7 item — and the anti-vacuity control

`attacker(pinR)` coming back **NOT secret** is the formal statement of
`threat-model.md` Claim 7's residual: an adversary who has the device's static
channel keys (a DHUK/PBS extraction) **and** captured a legitimate unlock session
re-derives that session's key from `KDF(static, captured challenges)` and
decrypts the PIN VERIFY. This is exactly what the planned **ML-KEM inner wrap**
closes (its PQ secret is not recoverable from the static keys). It is NOT a newly
found break — fresh per-session challenges already stop a *pure bus* attacker
(the `pinB` = secret result) — and it doubles as the model's anti-vacuity
control: ProVerif must be able to recover the PIN here, else the `secret` results
would be vacuous.

## Out of frame (scp03_handshake.pv)

- S-ENC / S-MAC collapsed to one `static` (a DHUK leak gives both).
- KDF / cryptograms / AES-CCM/CBC are symbolic functions (perfect crypto).
- The SCP03 command counter + MAC-chaining replay window is not modelled.
- The OPTIGA Shielded Connection (TLS-PRF/CCM-8) handshake is a separate model.
