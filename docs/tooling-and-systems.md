# Tooling & Systems Manifest — what an agent working on this repo can use

> **Audience: an AI agent (or new dev) orienting in this repo.** "What tools and systems do I have,
> how do I invoke each, where's the source of truth, and what's *missing* that I might reach for."
> Verified by live probe on **2026-06-17** (`docs-reorg-inventory` workflow). The **Makefile and the
> skills are the source of truth**; this is the categorized index, not a copy — when in doubt, run the
> command and read the Makefile.
>
> **PATH note:** installed tools are spread across **five** dirs — a fresh shell needs all of them:
> `~/.foundry/bin` · `~/.cargo/bin` · `~/.local/bin` · `~/.nix-profile/bin` · `~/.elan/bin`.

---

## A. HAVE — installed & usable

### Build / test / run
| Tool | Invoke | Source of truth |
|------|--------|-----------------|
| **make** (144 top-level targets) | `make play` (interactive QEMU) · `run` (QEMU smoke, mock-SE) · `e2e` (unified-sign QEMU) · `e2e-hw` (probe-rs on real U585) · `measure` (8 BIP-39 words) · `test` = `test-unit test-solidity e2e` | `Makefile` |
| ~80 HW/flash/SE variants | `make *-hw`, `make flash-*`, `make *-e2e` | `Makefile` (read it) |

### Contract / EVM verification
| Tool | Installed | Invoke | Source of truth |
|------|-----------|--------|-----------------|
| **Foundry** (forge/cast/anvil) | ✅ `~/.foundry/bin` (not on PATH) | `cd contracts/smart-wallet && forge test -vv`; `make test-solidity` | `contracts/smart-wallet/` |
| **halmos** (symbolic EVM) | ✅ `~/.local/bin` | `make halmos` (→ `verify-halmos` → `halmos/run_halmos.sh`); direct: `halmos --contract Halmos...` in `contracts/smart-wallet` | `contracts/verification/halmos/run_halmos.sh` |
| **Kontrol + kup** (KEVM) | ✅ `~/.nix-profile/bin` | `make kontrol` (→ `verify-kontrol` → `kontrol/run_kontrol.sh`) | `contracts/verification/kontrol/run_kontrol.sh` |

### Rust verification
| Tool | Installed | Invoke | Source of truth |
|------|-----------|--------|-----------------|
| **Kani** (bounded MC) | ✅ `~/.cargo/bin` | `make kani` | `Makefile:3545` |
| **Miri** (UB) | ✅ `~/.cargo/bin` (via `cargo +nightly miri`) | `make miri` | `Makefile:3557` |
| **cargo-fuzz** (16 targets) | ✅ `~/.cargo/bin` | `make fuzz-all` / `make fuzz-list` | `Makefile:2895+` |

### Proof (Lean)
| Tool | Installed | Invoke | Source of truth |
|------|-----------|--------|-----------------|
| **Lean 4 + Lake** | ✅ `~/.elan/bin` | `make test-formal-verification` · `make verify-theft-free` · the `contracts/verification/Makefile` `verify-*` targets | `contracts/verification/{lean,extracted}` |
| **lean-lsp MCP** | ✅ (sole MCP server) | `mcp__lean-lsp__*` (lean_goal/diagnostic/verify/loogle/…); `uvx lean-lsp-mcp`, `LEAN_PROJECT_PATH=contracts/verification/extracted` | `.mcp.json` |
| **lean4checker** | ⚠ build-on-demand | `contracts/verification/scripts/run_lean4checker.sh` builds it version-matched at runtime (no pre-built binary) | that script |

### Protocol verification
| Tool | Installed | Invoke | Source of truth |
|------|-----------|--------|-----------------|
| **ProVerif** | ✅ `~/.local/bin` | `make proverif` over `contracts/verification/proverif/*.pv` | `Makefile:3572` |
| **Tamarin + Maude** | ✅ `~/.local/bin` (+ `*.maude` prelude) | `make tamarin` over `contracts/verification/tamarin/*.spthy` | `Makefile:3588` |

### Constant-time / SCA / FI
| Tool | Installed | Invoke | Source of truth |
|------|-----------|--------|-----------------|
| **cargo-checkct + binsec** (thumbv8m CT proof) | ✅ off-PATH | `make checkct` (sources `~/checkct_env.sh`, runs `cargo-checkct run --dir tools/sca`; binary `~/repos/cargo-checkct`, binsec `~/.opam/checkct/bin`). Exits non-zero by design — the kdf/fors/th drivers are SECURE, the shuffle driver is INSECURE-by-design | `tools/sca/DONJON-RUST-TOOLING.md §1` |
| **Muscat** (Donjon SCA: CPA/TVLA/SNR) | ✅ `~/repos/muscat` | `make muscat` (no arg → synthetic self-test; `TRACES_DIR=<dir> make muscat` → real `.npy` traces) | `tools/sca/DONJON-RUST-TOOLING.md §2` |
| **rainbow** (Unicorn FI/SCA emu) | ✅ skill | Skill `rainbow`; drives `tools/sca/fault_sweep_*.py` + leakage harnesses | `~/.claude/skills/rainbow` |
| **lascar** (Ledger SCA, TVLA baseline) | ✅ skill | Skill `lascar` | `~/.claude/skills/lascar` |
| **scared** (eShard) + `scared-sca` CLI | ✅ skill + `~/.local/bin/scared-sca` | Skill `scared`; `make -C tools/sca f9-scared-collect` | `~/.claude/skills/scared` |
| **donjon-sca** CLI | ✅ `~/.local/bin` | `donjon-sca run tools/sca/<harness>.py` | `~/.local/bin/donjon-sca` |
| **tools/sca harness suite** (~40 targets) | ✅ | `make -C tools/sca <target>` (fi, c10, c10-sign, c10v, kdf, scp03-fi, cap, …) | `tools/sca/Makefile` |

### Supply chain
| Tool | Installed | Invoke | Source of truth |
|------|-----------|--------|-----------------|
| **cargo-deny** | ✅ `~/.cargo/bin` | `make invariant-gates` (`cargo deny check advisories bans sources`) | `deny.toml`, `Makefile:3515` |
| **cargo-cyclonedx** (SBOM) | ✅ `~/.cargo/bin` | `make sbom` | `Makefile:3529` |

### Hardware
| Tool | Installed | Invoke | Source of truth |
|------|-----------|--------|-----------------|
| **probe-rs** 0.31.0 (+ cargo-flash/embed) | ✅ `~/.cargo/bin` | `make *-hw`. ⚠ GOTCHA: `probe-rs reset` halts the core + no semihosting `SYS_READC` → use `probe-rs run` or power-cycle | `CLAUDE.md` HW gotcha |
| **B-U585I-IOT02A + TRUSTMV3SHIELD + SE050** | board (physical) | the `*-hw` targets; verify pins via `pin_diag::header_sweep()` (silkscreen off-by-one) | `CLAUDE.md`, `MEMORY.md` |
| **Kingst LA1010 logic analyzer** | ✅ `sigrok-cli` (kingst-la2016) + skill | Skill `la1010`; digital UART/SPI/I²C/SWD capture (e.g. S-5 SCP03 bus check) — ⚠ **digital only, no power/EM SCA** | `~/.claude/skills/la1010` |

### Web research & skills
| Capability | Status | Notes |
|-----------|--------|-------|
| **WebSearch / WebFetch** | ✅ reachable | Deferred tools — load via `ToolSearch query "select:WebSearch,WebFetch"`. **Probed live 2026-06-17: reachable from a *workflow subagent*, not just the main loop.** |
| **`deep-research` skill** | ✅ installed | Fan-out web search → fetch → adversarial-verify → cited report. Invoke via Skill tool. |
| Other skills | ✅ | `rainbow`, `lascar`, `scared`, `la1010`, `leanloop`, plus harness skills (`verify`, `code-review`, `simplify`, `run`). `~/.claude/skills` → `~/repos/my-claude-skills`. |

---

## B. GAPS — referenced/wanted but absent (or undiscoverable)

| Tool | Status | Why it's wanted |
|------|--------|-----------------|
| **hevm** (bytecode equivalence) | absent | sota §2 adopt-now: prove `SPHINCsC10Asm` ≡ a reference Solidity verifier. Halmos/Kontrol partly overlap but no equivalence-checking substitute. |
| **cargo-vet** | absent | dependency audit/attestation (complements cargo-deny + SBOM); supply-chain-defense brief in tree. |
| **dudect** | absent | statistical timing-leak tester — the empirical complement to cargo-checkct's *symbolic* CT; catches variable-latency instructions checkct cannot. Needs the board. |
| **ChipWhisperer / ChipSHOUTER** | absent (hardware) | on-silicon power/EM SCA + glitch — the LA1010 is digital-only and can't do this; emulated rainbow/Muscat can't rule out register-value leakage. |
| **ClusterFuzzLite** | absent | continuous/CI fuzzing with corpus persistence over the 16 cargo-fuzz targets (currently ad-hoc only). |
| **standalone lean4checker binary** | build-on-demand | a pinned pre-built binary would harden the kernel-recheck gate (cold runs pay a Lean-build cost). |

### Discoverability gaps (installed but an agent won't find them)
- **RESOLVED 2026-06-18:** `make checkct` / `make muscat` / `make kontrol` / `make halmos` now exist (root `Makefile`, appended after the `tamarin` target) — the full verification surface is discoverable from the Makefile alone, matching kani/miri/proverif/tamarin. `kontrol`/`halmos` delegate to `contracts/verification/{kontrol,halmos}/run_*.sh` via `verify-kontrol`/`verify-halmos`. The wrapper targets encapsulate the env/PATH bootstrap (`checkct` sources `~/checkct_env.sh` + prepends the off-PATH `cargo-checkct`; `muscat` defaults to a synthetic self-test needing no rainbow run).

---

---

## C. AGENTIC / EGRESS HARDENING (SOTA 2026-06 §7) — audited 2026-06-18

A key-holding repo: the controls that keep a compromised dependency / tool / prompt from
exfiltrating secrets or the firmware diff.

| Control | Status | Where / how |
|---------|--------|-------------|
| **`.mcp.json` minimal surface** | ✅ audited clean | Sole MCP server = `lean-lsp` (local stdio Lean-LSP proxy — no network tool, no repo-secret read). **gitignored** so it stays user-local and can't accidentally commit absolute paths or a future network+secret-bearing server. **RULE:** never add an MCP server that has BOTH repo-secret read AND a network tool. |
| **Net-isolation for fuzz/SCA tools** | ✅ `tools/sca/run-isolated.sh` | Runs any command with the network namespace dropped (unprivileged `bwrap --unshare-net`; **fails closed** if no sandbox is available). Wrap the binary/fuzz/SCA tools, which have no business reaching the network: `tools/sca/run-isolated.sh make -C tools/sca c10-sign`, `… make fuzz-all`. Validated: FS + cargo cache stay read-write, network is unreachable. |
| **CI Action egress** | ✅ the 2026-06-18 workflows | `security-review.yml` runs on `pull_request` (NOT `pull_request_target`), is fork-guarded, no-ops without the key, and the action is **pinned to a reviewed SHA**; ClusterFuzzLite + nightly use only the scoped `GITHUB_TOKEN`. No workflow holds both repo-secret read and an unpinned network action. |
| Per-subagent MCP allowlists | partial (low-pri) | The single local lean-lsp server is harmless, so there is no formal per-subagent allowlist yet. Revisit if a network/secret MCP server is ever added. |

---

*Maintenance: re-probe with the `docs-reorg-inventory` workflow (or just re-run the commands) when tools are added/moved. Linked from `docs/STATUS.md`. The Makefile + skills remain the source of truth; this file is the map.*
