# Ledger Donjon Rust SCA/CT tooling — cargo-checkct + Muscat

Two Ledger-Donjon tools brought up 2026-06-16 to complement the in-tree
`rainbow`/`lascar`/`scared` SCA workflow. Both proven on **real** PQ-Signer data.

- **`cargo-checkct`** — constant-time *verifier*. Compiles a driver to a bare-metal
  ELF and runs **binsec** relational symbolic execution to *prove* (for all secret
  values) that no conditional branch and no memory-access address depends on a
  secret. The only tool we found that targets the shipped **thumbv8m** ISA (Binsec/Rel
  alone has no ARMv8-M decoder; `ct_analyzer` is a source/asm-pattern pre-filter).
- **Muscat** — multithreaded Rust SCA *analysis* library (CPA / DPA / SNR / NICV /
  Welch-T-test / elastic alignment). Donjon's successor to `lascar` (now "legacy").
  Consumes `.npy` trace tensors — same data the `tools/sca` rainbow harnesses emit.

See `docs/verification/security-tooling-sota-2026-06.md` §1/§4 + work-todo §18b/§34.

---

## 1. cargo-checkct

### Install (one-time; binsec is the heavy part)

binsec is OCaml (not on crates.io / nixpkgs), built from source via opam. On a host
with `sudo apt`, the upstream README's `opam install … ; dune build` is simplest. On
this host (no sudo) it was installed via nix + a local opam root — full recipe in
`~/checkct_env.sh` (sourceable; sets nix PATH, OPAMROOT, the `checkct` opam switch, and
the gmp store paths). Summary:

```bash
# the tool itself (pure Rust)
git clone https://github.com/Ledger-Donjon/cargo-checkct ~/repos/cargo-checkct
cd ~/repos/cargo-checkct && cargo build --release      # -> target/release/cargo-checkct

# backend: binsec 0.10.0 + unisim_archisec 0.0.10 (OCaml 4.14.2 opam switch + bitwuzla SMT)
#   opam switch create checkct ocaml-base-compiler.4.14.2
#   opam install dune dune-site menhir grain_dypgen ocamlgraph zarith toml bitwuzla
#   (clone+`dune build @install && dune install` unisim_archisec @0.0.10 then binsec @0.10.0)
# pinned nightly driver toolchain:
rustup component add rust-src --toolchain nightly-2026-04-06
rustup target add thumbv8m.main-none-eabi --toolchain nightly-2026-04-06
```

> **Upstream bug (worked around in `.cargo/config.toml`):** recent nightlies turned
> `panic_immediate_abort` from a build-std *feature* into a panic strategy. The template
> still lists it as a feature and fails to build `core`. Fix applied here: drop the
> feature, add `rustflags = ["-Zunstable-options", "-Cpanic=immediate-abort"]`. Worth a PR.

### Run

```bash
source ~/checkct_env.sh && export PATH="$HOME/.cargo/bin:$PATH"
cd <repo-root>
cargo-checkct run --dir tools/sca --timeout 300     # finds tools/sca/checkct/
```

`--dir` is the directory *containing* a folder literally named `checkct/`. The vendored
workspace `tools/sca/checkct/` path-deps `sphincs-c10` (repo-relative) and
`checkct_macros` (assumes `~/repos/cargo-checkct` is a sibling of this repo — adjust the
path in `driver/Cargo.toml` otherwise).

> **In-repo cargo-config gotcha (fixed in `.cargo/config.toml`):** because this workspace
> lives inside the PQSigner repo, cargo merges the repo-root `.cargo/config.toml`. The root
> sets `target.thumbv8m.main-none-eabi.rustflags`, which cargo uses **instead of** (never
> merged with) a `[build] rustflags` — so the required `-Cpanic=immediate-abort` would be
> silently dropped, bloating `.text` with panic machinery and crashing binsec with
> `Fatal error: exception Not_found`. The flags are therefore defined under
> `[target.thumbv8m.main-none-eabi]` here (closer config wins) and carry the inherited
> `--build-id=none` forward. Verified: with the fix the in-repo build's `.text` (0x26c4)
> and verdict are byte-identical to a standalone build.

### How secrets are marked

No attributes/config on the crate under test — it's a **driver harness**
(`driver/src/driver.rs`): one `#[checkct]` fn, fill buffers with `PrivateRng` (SECRET) or
`PublicRng` (PUBLIC), then call the function under test. `cargo-checkct add -n <name>`
scaffolds more drivers (one per function/scenario). Output: `SECURE` (exit 0) or
`INSECURE` with the exact leaking instruction address(es).

### Verified result — `fisher_yates` (thumbv8m), the CT-1 cross-check

```
[checkct:result] Instruction 0x00020376 has control flow leak
[checkct:result] Instruction 0x000206da has memory access leak
[checkct:result] Instruction 0x000206e4 has memory access leak
Program status is : insecure   (517/518 control-flow + 5359/5361 memory-access checks pass)
```

**Interpretation (the INSECURE verdict is BY DESIGN, not a failure):**
- It **confirms the CT-1 fix**: the disasm at the swap is pure `lsrs/cmp` (`lsrs r3,#0x10`
  = the Lemire `>>16`) — **no `UDIV`, no new secret-dependent branch**. CT-1's goal
  (kill the variable-latency divider) holds at the machine level.
- The 3 flagged instructions are the *inherent* leaks of any in-place Fisher-Yates:
  `0x206da/0x206e4` = the `buf[j]` swap (secret-indexed memory **address**), and
  `0x20376` = the zero-seed identity fast-path branch (`if nonzero==0`, on an OR-fold of
  the seed — never taken in production since the TRNG seed is non-zero).
- The shuffle **deliberately** uses the address channel and relies on *statistical*
  trace-misalignment (43!/13! search space), **not** bitwise constant-time — so a strict
  checkct proof of the shuffle will always be INSECURE. A green run would require an
  oblivious/sort-based shuffle, which we explicitly chose not to build.

### Machine-checked CT proofs — SECURE (the green-run drivers, DONE 2026-06-16; +saes 2026-06-18)
Four drivers mark a real secret and prove (for **all** secret values) that the function
leaks nothing via control flow or memory address on thumbv8m. All **SECURE**:

| Driver | Function (secret marked) | Verdict | Checks pass |
|---|---|---|---|
| `driver_kdf`  | `pqsigner_domain::kdf` (secret keying material) | **SECURE** | 117/117 CF · 750/750 mem |
| `driver_fors` | `sphincs_c10::sim_internals::fors_secret` (secret `sk_seed`) | **SECURE** | 52/52 · 575/575 |
| `driver_th`   | `sphincs_c10::sim_internals::th` (secret hash input) | **SECURE** | 141/141 · 1290/1290 |
| `driver_saes` | `secure/src/cmac.rs::cmac_generic` framing — secret = the SAES/DHUK AES *output* (L, CBC states); coproc modelled data-oblivious | **SECURE** | 105/105 CF · 50/50 mem |

So the SHA-256 KDF, the FORS secret-key PRF, the core tweakable hash, **and the Tier-1
SAES-CMAC(DHUK) KDF framing** are machine-proven constant-time over their secret inputs —
exactly the secret-touching primitives. Notably `driver_saes` proves `double_l`'s GF(2^128)
reduction (`if (input[0] & 0x80) { out[15] ^= 0x87 }` — a branch on the secret MSB of
`L = AES(DHUK, 0)`) compiles **branchless** on thumbv8m, so the CMAC framing leaks nothing
about the secret AES outputs. `driver_saes` `#[path]`-includes the production `cmac.rs`
verbatim (no copy drift; the `#[cfg(test)]` vector module is gated out of the release build).
(Run all five drivers with `cargo-checkct run --dir tools/sca`; the suite exits non-zero only
because `driver` = the by-design-INSECURE shuffle. `sim_internals` needs the `sim-internals`
feature, already set in the driver Cargo.tomls.)

**Not attempted (binsec scope):** `verify` / `keygen` symbolically execute the full
hypertree (≫ millions of instructions) and would time out — binsec's sweet spot is a single
primitive / chain, not the whole scheme. The **SAES/HASH/PKA hardware** is invisible to
binsec (it models only the CPU); for the CMAC/KDF *hardware* path use the software mirror
(`tools/sca/saes_kdf_target` mirrors `secure/src/cmac.rs::cmac_generic` under software AES)
as a driver — same scope the rainbow harnesses already accept.

**Scope limit:** checkct catches secret-dependent **branches** and **addresses**, *not*
variable-latency instructions (e.g. it would not by itself have caught CT-1's `UDIV`
timing — `ct_analyzer` + the M33 divider knowledge did). It is complementary to the
rainbow timing/DPA sweeps, not a replacement.

---

## 2. Muscat

### Build + run

```bash
cd ~/repos/muscat && cargo build --release --examples     # ~10s, no extra system deps
# harness (vendored copy in tools/sca/muscat/pqsigner_tvla_cpa.rs — keep a copy in
# ~/repos/muscat/examples/ to build it as an example):
cp tools/sca/muscat/pqsigner_tvla_cpa.rs ~/repos/muscat/examples/    # + the [[example]] stanza
TRACES_DIR=<dir-with-traces.npy> cargo run --release --example pqsigner_tvla_cpa
#   env knobs: CPA_TARGET_BYTE, T_THRESHOLD (default 4.5), BATCH_SIZE
```

The harness reads `traces.npy` (uint8 `[n, samples]`, the rainbow `mem_address`
Hamming-weight channel), `classes.npy` (bool/uint8 `[n]`, the fixed/random TVLA flag),
`plaintexts.npy` (uint8 `[n, k]`, the msg bytes); runs **Welch's T-test (TVLA)** then a
**CPA** pass. No gnuplot dependency (unlike the bundled examples).

### Feeding it the existing rainbow traces

```bash
# 1. (re)generate the shuffle trace set with the EXISTING tooling:
make -C tools/sca f9-scared-collect          # -> tools/sca/out/f9_traces.npz
# 2. convert .npz -> the 3 .npy Muscat reads (mmap-streamed, multi-GB safe):
python3 tools/sca/muscat/npz_to_npy.py tools/sca/out/f9_traces.npz /tmp/f9_muscat
# 3. run:
cd ~/repos/muscat && TRACES_DIR=/tmp/f9_muscat cargo run --release --example pqsigner_tvla_cpa
```

`tools/sca/muscat/gen_pqsigner_shape.py` synthesises a PQ-Signer-shaped trace set (with a
ground-truth leaky-S-box) to self-test the harness without running rainbow (CI smoke).

### Verified results
- Synthetic ground truth: TVLA `max|t|=62.8` fires on the injected samples; CPA recovers
  the injected key `0x2b`.
- **Full-10M TVLA cross-check (DONE 2026-06-16): `max|t| = 4.931 @ sample 6,802,705`** over
  the real `f9_traces.npz` (sca_c10_sign_shuffled, 600 × 10M, post-F-16/CT-1) — **reproduces
  the lascar baseline (≈4.93) exactly** on identical data. The peak is in the grind_r tail
  (~6.8M), which is why the earlier first-200k window read flat (3.24). So Muscat is a
  validated drop-in for the "legacy" lascar TVLA. The residual leak is the known F-9
  grind_r msg-dependent iteration count — a PUBLIC-input effect (grind_r never touches
  `sk_seed`), already analysed/accepted (see §F-9 above). Run with
  `SKIP_CPA=1 TRACES_DIR=<full> cargo run --release --example pqsigner_tvla_cpa` (the
  `SKIP_CPA` env skips the 256-guess CPA, which is large on 10M-wide traces).

### Red-teaming the shuffle — first-order CPA (DONE: flat / no recovery)
Ran a first-order CPA over the **random-group** traces windowed around the TVLA peak
(`6.7M–6.9M`): best guess corr `0.355` with the top-5 clustered `0.29–0.36` and **no
separated spike** — i.e. the 300-trace noise floor, **not** a recovered key. So a first-order
address-channel CPA recovers nothing. This is the expected, corroborating result: (a) C10 is
SHA-256-based with **no secret-indexed table** (unlike AES) — `cargo-checkct` *proves*
`th`/`fors_secret`/`kdf` have no secret-dependent addresses (§1); (b) the F-16 shuffle
randomises temporal order. A meaningful attack would need a register-*value* power/EM channel
+ higher-order / shuffle-permutation hypotheses — on-silicon SCA territory (ChipWhisperer),
not this emulated address channel.

**Scope limit:** this is the emulated `mem_address` (access-address Hamming-weight)
channel. A flat TVLA rules out data-dependent memory *addresses* at audit-grade
emulation; it does **not** rule out register-*value* power/EM leakage or the SAES analog
surface — those need on-silicon SCA with a scope (ChipWhisperer, §SOTA-report §4).

---

## Vendored files
- `tools/sca/checkct/` — the cargo-checkct driver workspace (fisher_yates driver). `target/` gitignored.
- `tools/sca/muscat/pqsigner_tvla_cpa.rs` — the TVLA+CPA harness (also lives in `~/repos/muscat/examples/`).
- `tools/sca/muscat/npz_to_npy.py` — `f9_traces.npz` → `traces/classes/plaintexts.npy` converter.
- `tools/sca/muscat/gen_pqsigner_shape.py` — synthetic-trace generator for CI self-test.
