# Deployed-bytecode ↔ pinned-codehash caveat (for the smart-contract maintainer)

**Date:** 2026-06-13. **Audience:** whoever owns `contracts/smart-wallet/`
deployment + the formal-verification pin discipline. **Decision needed:**
one of the two options in [§5](#5-decision-needed). **TL;DR:** the deployed
Base Mainnet **wallet + factory** bytecode is **not reproducible** from the
current repo (the libs it was built with were never recorded in
`foundry.lock` and are lost), so the Halmos `solidity{Wallet,Factory}_*`
discharges are **not byte-bound to the live contracts** — they're bound to a
reproducible *re-build* of the same source. The **verifier is byte-identical
to the deployed contract** and fully bound. Pick A (recover the deploy-time
libs) or B (accept logic-level discharge for wallet/factory) so the pin
ledger states the truth.

---

## 1. How this surfaced

Adding Foundry to the dev env (it had been absent) exposed that
`contracts/smart-wallet/foundry.lock` pinned **account-abstraction v0.7.0**
(`7af70c8`), which **does not compile** — the code imports
`account-abstraction/legacy/v06/{IAccount06,IEntryPoint06,UserOperation06}.sol`,
a path that only exists in **v0.8.0+**. The lock had been stale w.r.t. the
code since the EntryPoint v0.9→v0.6 retarget (`074fcbb`); a later
supply-chain commit (`bc616a0`, 2026-04-20) then "tidied" the pin to the
non-compiling v0.7.0 tag and bumped solady/OZ/forge-std.

Repairing the lock to AA **v0.8.0** (`4cbc060`) makes a clean checkout
compile (`forge test` 108/108). But the wallet/factory **codehash pins**
then no longer matched a clean build — which led to the investigation below.

## 2. What is proven by construction (no ambiguity)

| Fact | How established |
|------|-----------------|
| The **verifier** (`SPHINCsC10Asm`) deployed at Base Mainnet `0xdDE4D290…` has runtime codehash **`0xeb1e3fcd…`** | `cast code` + `cast keccak` against `https://mainnet.base.org` |
| A local **deploy-profile** (`runs=999999`) build of the verifier has codehash **`0xeb1e3fcd…`** — **byte-identical to chain** | `make verify-bytecode` certify step |
| ⇒ the **solc 0.8.28 / via_ir toolchain is deployment-faithful**, and the verifier (which imports no libraries) is fully reproducible and its pin is byte-bound to the live contract | follows from the two rows above |

So for the **C10 verifier** — the security-critical signature checker — the
pin, the Halmos input-gate discharge, and the deployed bytecode all coincide.
Nothing below weakens that.

## 3. The wallet/factory finding (conclusive)

The wallet impl carries two **immutables** baked into its runtime bytecode —
`_entryPoint` and `c10Verifier` (`PQSmartWallet.sol:49-50`,
constructor `:156`) — so its codehash depends on those addresses, not just on
the source + libs. To remove that variable, the deployed bytecode was
reproduced **with the exact deployed immutables**:

* `_entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` (EntryPoint v0.6)
* `c10Verifier = 0xdDE4D290d646097ECeEA1e33Bf8C9Fa6dd589cbB` (deployed verifier)
* `FOUNDRY_PROFILE=deploy` (`runs=999999`, the production profile)
* the repaired lock (AA v0.8.0 `4cbc060` + solady `90db92ce`)

Result (immutables now identical to chain, so any difference is **purely
library bytecode**):

| Contract | On-chain (Base Mainnet) | Local rebuild, deployed immutables | Match? |
|----------|-------------------------|------------------------------------|--------|
| PQSmartWallet impl `0x31e49D24…` | `0xdc9a082f…836994` | `0x1333ed8a…1c0a86` | **NO** |
| PQSmartWalletFactory `0xe8CE78CD…` | `0x045bb5e4…55ba9a` | `0x23a69d2e…5e467a` | **NO** |

**Conclusion:** the deployed wallet/factory were built with **different
library versions** (solady and/or account-abstraction `legacy/v06`) than
anything currently in the repo. Those exact commits were never written to
`foundry.lock` and are not recoverable from public solady history (the
relevant solady files — `accounts/ERC1271.sol`, `utils/LibClone.sol` — froze
2025-12-04, so no current public commit reproduces the original pins either).
The deploy (2026-06-12) and the original pinning (2026-06-10) are two days
apart, so the deployed contract almost certainly used the **original** pin's
(now-lost) libs.

## 4. What this means for the formal-verification claims

The Halmos `solidity*_compiles_correctly` axioms (A3.2 wallet validate,
A3.2-exec execute, A3.3 factory, A3.4 owner-table) are stated as
"deployed-bytecode == Lean model" and pinned to a specific codehash.

* **Verifier (A3.1 gates):** byte-bound to the live contract. ✓
* **Wallet / factory (A3.2 / A3.3 / A3.4):** the symbolic rules **PASS**
  (38/38, both profiles, re-run 2026-06-13 against the re-pinned reproducible
  build), but they execute the **reproducible re-build**, whose
  wallet/factory bytecode is **not** the bytecode at `0x31e49D24…` /
  `0xe8CE78CD…`. The connection that was supposed to bridge pin→deployment —
  `PinnedBytecodeImmutableLemma` (runtime differs only in immutable windows)
  — holds **only within one library set**, and the deployed libs differ, so
  it does **not** transport these proofs to the live wallet/factory.
* **What still genuinely holds for the live contracts:** the A3.* rules are
  control-flow proofs over **PQSigner's own** `validateUserOp` / factory /
  owner-table logic with the verifier modeled as an uninterpreted function.
  That logic is in `src/*.sol` (unchanged) and is **independent of the solady
  ERC1271/LibClone code regions**, which is where the deployed-vs-rebuild
  bytecode differs. So the *logic-level* correctness argument applies to the
  deployed contract; what is **not** established is a *byte-level* equality
  to the live wallet/factory bytecode.

This is a real reduction in strength vs. what `PINNED_CODEHASHES.md`
historically implied ("symbolically discharged on the deployed bytecode").
It is **not** an on-chain vulnerability — the deployed contracts are whatever
they are; this is about how tightly the proofs bind to them.

## 5. Decision needed

Re-deploying from the reproducible lock is **off the table**: the wallet
address is CREATE2-derived and baked into the firmware (`proxyInitCodeHash`
`0xac0c44b6…`, invariant #6) — changing the bytecode changes the address.
So the choice is:

### Option A — recover the deploy-time libs, re-pin + re-discharge to them
If the deploy machine / CI cache / your local checkout from ~2026-06-12 still
has the exact **solady** (and account-abstraction `legacy/v06`) commits,
record them in `foundry.lock`, rebuild with the **deployed immutables**, and
confirm the rebuild's wallet/factory codehashes equal the on-chain
`0xdc9a08…` / `0x045bb5…`. Then re-pin (test-harness instances) +
re-run `make verify-bytecode`. This **restores byte-level discharge of the
live contracts** (modulo immutables via the lemma) AND makes the lock
reproducible. **Preferred if the commits are recoverable.**

> How to confirm a candidate lib set: build with the deployed immutables
> (`_entryPoint = 0x5FF1…`, `c10Verifier = 0xdDE4…`, `FOUNDRY_PROFILE=deploy`)
> and check the impl codehash == `0xdc9a082f…836994` and factory ==
> `0x045bb5e4…55ba9a`. (Procedure used for §3 is reproducible; ask and it can
> be scripted as a permanent `test/DeployedReproCheck.t.sol`.)

### Option B — accept logic-level discharge for wallet/factory
If the deploy-time commits are unrecoverable: keep the **2026-06-13 re-pin**
to the reproducible build (already done — lock compiles, 38/38 rules pass),
and update the claim language to state plainly that the wallet/factory
bytecode discharge is against a **reproducible re-build of the source**, not
the deployed bytecode; the deployed wallet/factory differ only in
audited-upstream solady library regions, and the live-contract guarantee is
**logic-level** (control-flow over PQSigner's source) plus the **byte-level
verifier**. `THE_CLAIM.md` already trends conservative; this would add one
explicit sentence.

## 6. Current repo state (as left 2026-06-13)

* `foundry.lock` → AA v0.8.0 (`4cbc060`); clean checkout compiles; `forge
  test` 108/108.
* Wallet/factory codehashes **re-pinned** to the reproducible build (default
  `0xaa85…`/`0xa2cfb8…`, deploy `0x8c6baad3…`/`0x4d1e1edf…`); verifier pins
  unchanged. `PinnedCodehashes` + `PinnedBytecodeImmutableLemma` pass under
  both profiles.
* Halmos discharge **re-run**: 38/38 rules pass on both profiles
  (`make -C contracts/verification verify-bytecode`).
* This is **Option B as the interim default**. Switching to Option A only
  needs the deploy-time `foundry.lock` lib commits + a re-pin/re-run.

See also: `PINNED_CODEHASHES.md` (the build-reproducibility banner),
`THE_CLAIM.md`, `AXIOM_STATUS.json` (A3.2/A3.3/A3.4).
