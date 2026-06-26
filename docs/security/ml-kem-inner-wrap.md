# ML-KEM-1024 inner wrap — design + status

**Invariant #3 (PQ confidentiality of SE traffic). Closes the documented
Harvest-Now-Decrypt-Later (HNDL) residual.**

## Threat

The dual-SE entropy halves (`half_O` on OPTIGA, `half_E` on SE050) cross I²C
under the secure elements' *classical* channels — OPTIGA Shielded Connection
(AES-128-CCM-8) and SE050 SCP03 (AES-CMAC/CBC). Those channels' session keys
derive from classical primitives (ECDH / static AES). A **Harvest-Now,
Decrypt-Later** adversary records the bus today and decrypts once a CRQC exists
— and for a wallet holding long-term funds, need not be present at decryption
time. This is the dominant PQ residual (README §threat-model): *"until the
inner wrap lands, the SE channels carry plaintext halves under the classical
SE-vendor AE layers."*

## Why HYBRID, not ML-KEM-only

The MCU seals AND opens — this is encrypt-**to-self**, i.e. symmetric encryption
where the KEM degenerates to "encrypt to my own public key." For self-sealed
data, ML-KEM-only would be *strictly weaker* than AES-256-GCM under a HUK key.
Walk the HNDL adversary through both:

| construction | recover a harvested half by … |
|---|---|
| AES-256-GCM-to-self (key=KDF(HUK)) | break AES-256 (~2¹²⁸ Grover) **or** extract the die's HUK (physical) |
| ML-KEM-only-to-self | break **ML-KEM** (ct→shared secret, **no physical access**) **or** extract HUK |

ML-KEM-only *adds* a recovery path — "break ML-KEM" — that needs no physical
access and rests on the exact lattice assumption the project distrusts
everywhere else (it's *why* the signing key is SPHINCS+/SHA-256: hashes have a
longer cryptanalytic track record — README §"why hash-based signatures"). The
README's own bar is *"a NIST PQC standard **or** a Grover-resistant symmetric
primitive"* — AES-256 qualifies. So we bind **both** secrets into the AEAD key:

```
K = HMAC-SHA256(key = huk_secret, msg = mlkem_shared_secret ‖ aad ‖ tag)
```

- **Break ML-KEM alone** (recover the shared secret from `ct`) → still needs
  `huk_secret` to form `K`. Useless without physically extracting *this* die's HUK.
- **Extract HUK alone** → still needs the ML-KEM shared secret (the lattice).

`K` can therefore **never drop below the AES-256/HUK floor**, while ML-KEM keeps
the NIST-PQC confidentiality layer for defence-in-depth + crypto-agility + the
PQ1 brand. (Decision: hybrid, after the 2026-06-26 design review flagged the
self-seal equivalence; the user picked hybrid over plain AES-256-to-self to
retain the PQ layer.)

## Construction — KEM-DEM with a hybrid key

The MCU holds ONE ML-KEM-1024 (FIPS 203) keypair derived from the HUK-bound seed:

```
seal(seed, m, huk, aad, pt):              open(seed, huk, aad, ct‖aead):
  dk = ML-KEM.from_seed(seed)              dk = ML-KEM.from_seed(seed)
  (ct, ss) = Encaps(dk.ek; m)              ss = Decaps(dk, ct)
  K = HMAC(huk, ss ‖ aad ‖ tag)            K  = HMAC(huk, ss ‖ aad ‖ tag)
  n = SHA256("…nonce" ‖ ct ‖ aad)[..12]    n  = SHA256("…nonce" ‖ ct ‖ aad)[..12]
  aead = AES-256-GCM(K, n, aad, pt)        pt = AES-256-GCM.open(K, n, aad, aead)
  store ct ‖ aead on the SE                return pt
```

A fresh shared secret `ss` is produced for **every** seal (the encapsulation
message `m` is fresh TRNG), so `(K, n)` is unique. ML-KEM decapsulation uses
*implicit rejection* (never errors — a bad ciphertext yields a pseudo-random
`ss`); the **GCM tag** is the authenticator, so a tampered `ct`/`aead`, the
wrong `seed`, the wrong `huk`, or the wrong `aad` all fail at `open`. The nonce
is bound to `ct ‖ aad` (recomputed at open, not transmitted). The caller binds
**`aad` = (chip-id ‖ half-id ‖ account_index)** so a blob can never be replayed
as the other half or another account.

Wire layout of the stored blob: `ct (1568) ‖ gcm_ct (pt_len) ‖ tag (16)`. For a
32-byte half: **1616 bytes**.

### Key derivation — refinement of the "stored sk" plan

The README originally framed this as *"factory generates + HUK-SAES-wraps the
ML-KEM keypair, sk stored in secure flash."* We instead **derive the keypair
deterministically from a HUK-bound 64-byte seed each boot** (`ml-kem`'s
`DecapsulationKey::from_seed`, the FIPS-203 `d‖z` seed = the canonical sk
serialization). This is strictly stronger: nothing lattice-secret is *stored* in
plaintext, on a bus, or on an SE — the "sk" is `hw::huk::derive_device_key`
output, per-die and deterministic across boots (exactly the "seal-at-write,
unseal-at-read" property HUK already guarantees). Recovering a half therefore
requires physical extraction of the *specific* U585 die + a working RDP-2 break
+ HUK extraction — and even then only one half, the other being on the other SE
under a different ciphertext gated by that SE's retry counter.

## Crypto agility

ML-KEM protects only the *confidentiality of stored halves*. The signing key
never depends on lattices (SPHINCS+C10, SHA-256 only). If ML-KEM is ever broken,
only this inner-wrap layer migrates — signatures and firmware verification are
unaffected (README §"why hash-based signatures for the actual money").

## Implementation status (pieces)

| # | Piece | Status |
|---|-------|--------|
| 1 | **`pqsigner-pq-seal` primitive (hybrid)** — ML-KEM-1024 + HMAC(HUK) + AES-256-GCM `seal`/`open`, deterministic keypair from a 64-byte seed, ct-bound nonce, context AAD, no_std/thumbv8m-clean, clippy-pedantic-clean, 9 KATs (round-trip, no-leak, **hybrid-floor wrong-HUK**, wrong-seed, **wrong-AAD no-cross-replay**, tamper-ct/aead, determinism, fresh-randomness, bounds) | ✅ **done** |
| 2 | Firmware wiring — derive `seed` + `huk_secret` via two `hw::huk` labels, draw `m` from the TRNG, build `aad` = chip‖half‖account, `seal`/`open` at the dual-SE store/read boundary (`secure/src/dual_se.rs`) | ⏳ next |
| — | README/CLAUDE.md #3 hybrid-framing update (line 143 table + line 175 HNDL para now also rest on the HUK floor, not the ML-KEM sk alone) — coordinated with piece 2 (README untouched while "not yet wired" stays accurate + avoids agent-branch churn) | ⏳ with piece 2 |
| 3 | SE object sizing + provisioning — **RESOLVED (see Storage layout): the blob does NOT fit OPTIGA, so split it — ct → MCU flash, aead → SE.** | ⏳ |
| 4 | Migrate OPTIGA/SE050 reads onto the wrap; trace-verify the seed never appears in plaintext on either bus | ⏳ |

## Storage layout — the blob does NOT fit on the SE (resolved 2026-06-26)

The naive "store the whole 1616 B sealed blob on the SE" is **infeasible** on
OPTIGA (`docs/secure-elements/OPTIGATRUSTM/commands-and-oids.md`,
`hardware-specs.md`):

| limit | value | vs the 1616 B blob |
|---|---|---|
| `0xF1D1` (today's `half_O` slot, Type-3 arbitrary data) | **140 B** | ✗ way over |
| largest OPTIGA Type-2 arbitrary-data object | **1500 B** | ✗ over |
| OPTIGA I2C buffer `TRUSTX_I2C_MAX_BUF_LEN` | **1557 B** | ✗ can't even transit in one APDU |

So the ML-KEM ciphertext (1568 B) cannot live on OPTIGA. **Resolution — split
the sealed blob:**

- **`ct` (1568 B, ML-KEM ciphertext) → MCU secure flash** (a per-(chip,half,
  account) slot). It is not a secret on its own — IND-CCA says `ct` reveals
  nothing about `ss` without the `dk` (the HUK-derived seed). Keeping it on the
  MCU means **the bus never even sees it.**
- **`aead` (`gcm_ct ‖ tag`, 48 B for a 32 B half) → the SE** (fits F1D1's 140 B
  with room to spare; SE050 binary object likewise). This is the "stored half":
  opaque without `K = HMAC(huk, Decaps(dk, ct) ‖ aad)`, i.e. without the MCU's
  `ct` **and** `huk` **and** `dk`-seed.

**Dual-SE property preserved** (invariant #1 — neither chip alone reveals a
half): the SE holds only `aead` (needs the MCU's `ct`+`huk` to open); the MCU
holds `ct`+`huk`+`dk`-seed but NOT `aead` (on the SE) — so a full MCU flash dump
still cannot recover a half without the SE's `aead` (and its retry-counter +
PIN gate). And the XOR split stands: `half_O`/`half_E` are sealed independently
with distinct `aad`, each on its own SE. `seal`/`open` already return/accept the
`ct ‖ aead` concatenation, so piece 2 just slices it at `CT_LEN` for the two
stores. This *strengthens* HNDL: the harvested bus traffic is now only the 48 B
`aead`, never the ML-KEM ciphertext.

## Follow-ups (hardware / acceptance)

- **Binary size:** `ml-kem` pulls `sha3 0.11` (Keccak) — a *second* hash stack
  alongside the firmware's SHA-256. Measure the flash delta in piece 2; if it
  matters, evaluate sharing the U585 HASH peripheral / a no-sha3 path.
- **Constant-time / SCA:** `ml-kem` is RustCrypto-ACVP-validated but not
  formally CT. On-target NIST-vector validation + a constant-time inspection of
  the Decaps inner loops + an FI-lab pass on Decaps remain (README §acceptance,
  work-todo). `cargo-checkct` / `haybale-pitchfork` over the Decaps path is the
  host-side leg.
- **Zeroization:** `seal`/`open` zeroize the shared secret `K` and (on tag
  failure) the output buffer; the `ml-kem` `zeroize` feature is enabled so the
  `dk` material zeroizes on drop.
