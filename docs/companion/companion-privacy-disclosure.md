# What the companion can see

**Status:** disclosure document, accurate as of 2026-07-31. This describes what
is *architecturally* true of the device and the companion protocol. It is not a
privacy policy for any particular companion build, and it makes no promise about
a third-party companion you did not build yourself.

Your funds are protected by the device. Your **privacy is not**, and this
document exists because that distinction is easy to miss when a product's
security story is as strong as this one's.

---

## The short version

The device never lets the companion see a secret. The companion necessarily sees
almost everything else.

| The companion can see | The companion can never see |
|---|---|
| Every address you use, and that they belong to one device | Your BIP-39 seed or either of its two XOR halves |
| The full contents of every transaction it helps you build — recipient, amount, token, contract, calldata | Your PIN. It is entered on the device's own buttons and compared inside secure-element silicon; no PIN byte ever crosses USB |
| When you sign, how often, and in what order | Any signing key. Slot keys are re-derived in Secure SRAM on demand and never leave it |
| Which chains you use | Your duress/decoy state, if that feature is enabled — a coercer watching USB traffic sees an ordinary session |
| Your balances, if it queries them | Anything about a transaction you *rejected* on the device beyond the fact that you rejected it |

That first column is not a defect. It is what "the companion builds the
UserOperation and the device signs it" means. The device's job is to make sure
the bytes you approved are the bytes that got signed; it is not, and cannot be,
to hide from the companion what those bytes were.

## Why the device cannot fix this for you

Signing requires knowing what is being signed. Something has to construct the
transaction, query balances, and talk to the chain, and on this architecture
that something is the companion running on your computer or phone. A device
with no network interface cannot fetch a nonce.

So the honest framing is: **the companion is a privacy dependency even though it
is not a security dependency.** The threat model treats it as untrusted for
custody (`docs/security/threat-model.md` §7.13) and correctly refuses to trust it
with anything that could move funds. Privacy is tracked separately as asset
**S7**, with the on-chain correlation half accepted as a residual in §10.8.

## The specific exposures, and what you can do

**1. Address correlation across chains.** The same 24 words produce the same
wallet address on every chain — that is invariant #6, and it exists so recovery
works everywhere without per-chain bookkeeping. The privacy cost is real: a
passive on-chain observer can link your activity across chains from the address
alone, with no help from the companion. *What you can do:* the derivation
supports 256 accounts (`account_index` 0..255) from one seed at no cost. Use
different account indexes for activities you do not want linked. This does not
help against the companion, which sees all of them, but it does help against
on-chain observers and counterparties.

**2. The companion learns your transaction graph.** It builds every UserOp, so
it sees recipients, amounts, tokens and timing. *What you can do:* run a
companion you trust and can inspect. The protocol is documented
(`docs/companion/usb-protocol-v2.md`) precisely so a companion is replaceable.

**3. Network-level observation.** The companion talks to RPC endpoints; those
endpoints see your IP alongside your queries. This is entirely outside the
device. *What you can do:* the device speaks USB-HID and carries no network
identity of any kind, so a companion is free to route through Tor or a VPN
without the device knowing or caring. Nothing in the device protocol defeats
that.

**4. Physical observation of the screen.** The trusted display shows what you
are signing — that is its purpose — and anyone who can see the screen can read
it. PIN entry does not echo digits at a distance-readable size, but the module
that implements it is explicit that an attacker with camera-grade visibility of
the screen and your hands sees the digit
(`secure/src/ui/pin_entry.rs`). Our two-button hardware cannot do Trezor's
scrambled 3×3 grid.

## Commitments

These are properties of the device and this repository, and they are checkable:

* **No telemetry of any kind in the firmware.** There is no analytics code, no
  usage counter that leaves the device, and no network stack — the device
  exposes USB-HID and nothing else, mounts no storage, and trusts no host input.
* **No account system.** The device has no notion of a user identity, no
  registration, and no server.
* **Local-first by construction.** Everything the device needs to sign arrives
  over USB from the companion. It never originates a request.
* **The protocol is documented and the firmware is open**, so "does it phone
  home" is a question you can answer by reading, not by trusting.

## What this document is not

It is not a claim that using this device makes you anonymous. It is not a claim
about any companion's behaviour — including ours — beyond what the device
protocol forces. If a companion chooses to send your transaction graph to a
server, the device cannot tell and cannot stop it. That is why the companion's
own distribution and integrity are tracked as a security surface in their own
right (threat model §7.13, companion-distribution row).

---

*Cross-references:* `docs/security/threat-model.md` §2 (asset S7), §7.13 (host
boundary), §10.8 (accepted correlation residual); `docs/companion/usb-protocol-v2.md`
(the complete wire protocol); `docs/security/HARDENING.md` §2 (secret residency).
