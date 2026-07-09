# Leanstral as a Claude Code Lean-prover subagent

**Status:** integration wired + smoke-tested 2026-07-07. Chosen path: **local on this laptop**
(§4). Remaining = a one-time setup requiring sudo + one reboot: free the ext4 reserve →
upgrade Ollama → GTT kernel tweak → pull the 67 GiB GGUF. (Free-API path §3 stays documented
as a fallback.)

**What this is.** [Leanstral 1.5](https://huggingface.co/mistralai/Leanstral-1.5-119B-A6B)
(`mistralai/Leanstral-1.5-119B-A6B`) is Mistral's Apache-2.0 **Lean 4 proof-engineering**
model — a Lean-specialized fine-tune of Mistral Small 4 (119B MoE, 6.5B active, 128 experts×4,
256k ctx, MLA attention). It saturates miniF2F and solves 587/672 PutnamBench. We use it to
**draft** Lean proofs for the verification track (`contracts/verification/extracted`, the
A3.1 / EUF-CMA / SphincsCVerify work), with the real Lean compiler (via `lean-lsp`) as the
ground-truth verifier.

## 1. Architecture — why a tool, not a "real" subagent

Claude Code's native subagents (`.claude/agents/*.md`) can **only** run Anthropic models —
the `model:` field takes `sonnet`/`opus`/`haiku`/`fable`/`inherit`, never a provider/base_url
(confirmed: [sub-agents docs](https://code.claude.com/docs/en/sub-agents),
[model-config](https://code.claude.com/docs/en/model-config); per-provider routing is the
still-open [claude-code#38698](https://github.com/anthropics/claude-code/issues/38698)). So
"Leanstral as a subagent" is realized as:

```
  lean-prover  (a CLAUDE subagent — the orchestrator/brain)
      │  carries as tools:
      ├── mcp__leanstral__leanstral_prove   ← Leanstral drafts the proof   (THIS integration)
      └── mcp__lean-lsp__lean_goal / _diagnostic_messages / _verify / …     (ground-truth compiler)
      loop:  lean_goal → leanstral_prove → Edit → lean_diagnostic/lean_verify → refine
```

Claude drives; **Leanstral is a tool it calls**; lean-lsp verifies. The proof loop lives in
the subagent, *not* inside the MCP server (which stays a thin one-shot completion wrapper).

**Files in this repo:**
| File | Role |
|------|------|
| `tools/leanstral_mcp.py` | ~90-line endpoint-agnostic MCP server (FastMCP + openai). Runs via `uv run` with PEP-723 inline deps — no venv. Exposes one tool, `leanstral_prove`. |
| `.mcp.json` → `leanstral` | Registers the server (stdio) next to `lean-lsp`. Endpoint chosen by `LEANSTRAL_*` env. |
| `.claude/agents/lean-prover.md` | The Claude subagent that carries the tool + lean-lsp tools and runs the draft→verify→refine loop. |

The server is **endpoint-agnostic**: local Ollama, local llama.cpp, or the free Mistral API
all speak OpenAI `/v1/chat/completions`, so you switch by editing env in `.mcp.json` only.

## 2. Serving options — the recommendation

| Option | Cost | Setup | When |
|--------|------|-------|------|
| **A. Free Mistral Labs API** | **$0** (rate-limited; may retire ~2026-09-30) | 1 API key + reload | **Best "now" path.** Full 119B quality, zero local RAM/disk. Proofs leave the machine (fine — Lean goals are public math; device secrets never touch this). |
| **B. Local — Ollama (Vulkan/ROCm iGPU)** | free after 1× ~67 GB download | upgrade Ollama + raise GTT + pull GGUF | **Best durable path.** Private, offline, no rate limit. ~10–16 tok/s. |
| **C. Local — llama.cpp Vulkan** | free | build llama.cpp + download GGUF | Robust fallback with full knobs (`-fa`, ctx, KV quant) if Ollama misbehaves on `mistral4`/MLA. |
| ~~vLLM~~ | — | — | **Not viable here.** No Vulkan backend; gfx1150 ROCm is compile-only; 119B needs all experts resident; designed for `--tensor-parallel-size 4` (4 discrete GPUs). |

**Recommended: hybrid.** Use **A** today (wire it, prove the loop end-to-end), stand up **B**
as the durable primary, keep the same `.mcp.json` and just flip the endpoint env. The
`lean-prover` subagent and LeanLoop wiring are identical either way.

## 3. Path A — free Mistral Labs API (ready now, needs a key)

1. Get a key at **console.mistral.ai** → API keys.
2. Edit the `leanstral` block in `.mcp.json`:
   ```jsonc
   "env": {
     "LEANSTRAL_BASE_URL": "https://api.mistral.ai/v1",
     "LEANSTRAL_MODEL": "labs-leanstral-1-5",   // if 404: try "leanstral-1-5"
     "LEANSTRAL_API_KEY": "sk-...your key...",
     "LEANSTRAL_MAX_TOKENS": "8192",
     "MAX_MCP_OUTPUT_TOKENS": "50000",
     "PATH": "/home/nicola/.local/bin:/usr/local/bin:/usr/bin:/bin"
   }
   ```
   > Keep secrets out of git if `.mcp.json` is committed — prefer exporting `LEANSTRAL_API_KEY`
   > in your shell/`.env` and dropping it from the JSON, or use a `.mcp.json` git-ignore.
3. One-line sanity check before relying on it (verifies key + model id):
   ```bash
   curl -s https://api.mistral.ai/v1/chat/completions \
     -H "Authorization: Bearer $LEANSTRAL_API_KEY" -H "Content-Type: application/json" \
     -d '{"model":"labs-leanstral-1-5","temperature":1.0,"reasoning_effort":"high",
          "messages":[{"role":"user","content":"Prove in Lean 4: theorem t (a b : Nat) : a+b=b+a := by sorry"}]}'
   ```
4. Reload Claude Code (new session picks up `.mcp.json`; approve the `leanstral` server when
   prompted). `reasoning_effort` and `lean_run_code` tool-calling pass straight through the API.

**Caveats (verify in-console):** free "Experiment" tier ≈ ~1B tok/month, ~5 RPS (Mistral no
longer publishes exact numbers — check Admin Console → Limits); Labs retirement flagged for
~2026-09-30 → wire the local fallback before depending on it for a batch campaign.

## 4. Path B — local on this laptop (ThinkPad P14s Gen 6 AMD, Ryzen AI 9 HX 370 / Radeon 890M)

Your box is a **Strix Point APU**: iGPU shares the 90 GB system RAM (UMA/GTT), no discrete VRAM.
The 6.5B-active MoE is an ideal shape for it. Three one-time gates:

### 4.0 Disk — free the ext4 root-reserve (one command)
The sole filesystem (`/dev/mapper/ubuntu--vg-ubuntu--lv`, 3.6 TB) has **236 GiB free as root/
GNOME-Disks sees it**, but **only ~50 GiB available to non-root writers** — the other ~186 GiB
is ext4's default 5% root-reserve (`statvfs`: `f_bfree`=236 GiB vs `f_bavail`=50 GiB). Ollama
runs as the **unprivileged `ollama` user (uid 997)**, so a 67 GiB `ollama pull` into
`/usr/share/ollama/.ollama/models` **fails ~17 GiB short** despite the space existing.

**Fix (live, no unmount, no reboot):** drop the reserve on `/` from 5% → 1%, recovering ~148 GiB:
```bash
sudo tune2fs -m 1 /dev/mapper/ubuntu--vg-ubuntu--lv
df -h /        # 'Avail' should jump from ~50 GiB to ~198 GiB
```
(1% still leaves ~37 GiB reserved so a runaway process can't wedge `/`.) Then `OLLAMA_MODELS`
can stay at its default. *Alternative:* keep the reserve and set
`Environment="OLLAMA_MODELS=/some/root-writable/dir"` via `sudo systemctl edit ollama` — but the
`ollama` user still can't use reserved blocks, so `tune2fs -m 1` is the clean fix.

### 4.1 Upgrade Ollama (current 0.24.0 is too old)
The `mistral4` architecture landed in llama.cpp in **March 2026** (PR
[#20649](https://github.com/ggml-org/llama.cpp/pull/20649)); Ollama **0.24.0 predates it and
will reject the model** with "unknown architecture." Upgrade (also installs the Vulkan backend):
```bash
curl -fsSL https://ollama.com/install.sh | sh    # → 0.31.x+
ollama --version
```
**⚠ Two Ollama service-env settings are mandatory on this box (empirically confirmed 2026-07-07):**

1. **`OLLAMA_IGPU_ENABLE=1`** — Ollama 0.31.x *drops integrated GPUs by default*
   (`"dropping integrated GPU; to enable, set OLLAMA_IGPU_ENABLE=1"`) and falls back to CPU.
2. **Force the Vulkan backend, not ROCm** (`ROCR_VISIBLE_DEVICES=` + `HIP_VISIBLE_DEVICES=-1`).
   This is the load-bearing fix. **ROCm on the 890M (gfx1150) under-reports device memory** — the
   llama.cpp runner sees only ~47 GiB free (not the 88 GiB GTT), so forcing `num_gpu 99` (68.5 GiB)
   over-commits and the model **hangs on first inference** (loads to the ROCm buffer, then
   `gpu_busy≈1%`, no tokens, request times out; llama.cpp APU-memory bug #18159). **Vulkan (RADV)
   sees the full pool** — `Vulkan0: AMD Radeon 890M (RADV GFX1150) (94208 MiB, 93133 MiB free)` —
   and computes fine (verified: goedel-8B ran on the GPU via Vulkan, `/dev/dri/renderD128` open +
   VRAM allocated, 8.4 tok/s). Ollama prefers ROCm when both are present, so hide ROCm.

Non-interactive service override:
```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null <<'EOF'
[Service]
Environment="OLLAMA_IGPU_ENABLE=1"
Environment="ROCR_VISIBLE_DEVICES="
Environment="HIP_VISIBLE_DEVICES=-1"
EOF
sudo systemctl daemon-reload && sudo systemctl restart ollama
```
Confirm GPU (not CPU) after loading a model: `ollama ps` shows `100% GPU`, and
`ls -l /proc/$(pgrep -x llama-server)/fd | grep renderD128` is non-empty with
`grep drm-total-vram /proc/$(pgrep -x llama-server)/fdinfo/*` showing GiB allocated.

**Standalone-Vulkan fallback (no Ollama, no sudo)** if Ollama's Vulkan path misbehaves: run
Ollama's bundled `llama-server` directly, with a dir of symlinked backends as the CWD so ggml
discovers `libggml-vulkan.so`:
```bash
mkdir -p ~/vkbe && cd ~/vkbe
ln -sf /usr/local/lib/ollama/libggml-base.so /usr/local/lib/ollama/libggml-cpu-*.so \
       /usr/local/lib/ollama/vulkan/libggml-vulkan.so /usr/local/lib/ollama/vulkan/libvulkan.so.1 .
ROCR_VISIBLE_DEVICES= HIP_VISIBLE_DEVICES=-1 LD_LIBRARY_PATH=~/vkbe:/usr/local/lib/ollama \
  /usr/local/lib/ollama/llama-server -m <blob.gguf> --alias leanstral -ngl 99 -c 32768 -fa off \
  --host 127.0.0.1 --port 8088
# then point .mcp.json LEANSTRAL_BASE_URL at http://localhost:8088/v1
```

### 4.2 Raise the GPU memory ceiling (GTT) — mandatory
Default GTT ≈ 50% of RAM (~45 GiB) < the 67 GiB model, so the iGPU can't hold it. On kernel
6.17 use the `ttm` params. Edit `/etc/default/grub` → `GRUB_CMDLINE_LINUX_DEFAULT`, append:
```
amdgpu.gttsize=90112 ttm.pages_limit=23068672 ttm.page_pool_size=23068672
```
(`23068672 × 4 KiB = 88 GiB`.) Then `sudo update-grub && sudo reboot`. After reboot the loader
should report ~80+ GiB of Vulkan/GPU memory. Ref: [Jeff Geerling — APU VRAM on
Linux](https://www.jeffgeerling.com/blog/2025/increasing-vram-allocation-on-amd-ai-apus-under-linux/).

### 4.3 Pull + run the GGUF
Preferred quant repo: **[`GZGavinZhao/Leanstral-1.5-119B-A6B-GGUF`](https://huggingface.co/GZGavinZhao/Leanstral-1.5-119B-A6B-GGUF)**
`Q4_K_M` (67.2 GiB — the *only* quant that fits with headroom; it also fixed a
`deepseek2`→`mistral4` GGUF-label bug, so prefer it). Skip the `mmproj` file — that's the
vision tower; Lean proving is text-only.
```bash
# Ollama (simplest; needs the 0.31.x upgrade above):
ollama run hf.co/GZGavinZhao/Leanstral-1.5-119B-A6B-GGUF:Q4_K_M   # first run downloads ~67 GB

# then register a friendly tag matching .mcp.json's LEANSTRAL_MODEL=leanstral:
cat > /tmp/Modelfile <<'EOF'
FROM hf.co/GZGavinZhao/Leanstral-1.5-119B-A6B-GGUF:Q4_K_M
PARAMETER num_gpu 99
PARAMETER num_ctx 32768
PARAMETER temperature 1.0
EOF
ollama create leanstral -f /tmp/Modelfile
```
Requires `OLLAMA_IGPU_ENABLE=1` in the service env (§4.1) or it runs on CPU. Keep
`OLLAMA_FLASH_ATTENTION` at its default (off) to start — MLA flash-attn is fragile here.
Confirm GPU offload after `ollama run`: `ollama ps` should show `100% GPU` (not `100% CPU`).

**llama.cpp fallback (Path C)** — more control, sidesteps Ollama's bundled-runtime version risk:
```bash
sudo apt install -y libvulkan-dev vulkan-tools glslc cmake build-essential git
git clone https://github.com/ggml-org/llama.cpp && cd llama.cpp
cmake -B build -DGGML_VULKAN=ON -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
hf download GZGavinZhao/Leanstral-1.5-119B-A6B-GGUF --include "*Q4_K_M*" --local-dir ./leanstral-gguf
./build/bin/llama-server -m ./leanstral-gguf/*Q4_K_M*.gguf \
  --alias leanstral -ngl 99 -c 32768 -fa off --no-mmap -ctk q8_0 -ctv q8_0 \
  -b 2048 -ub 512 -t 12 --host 127.0.0.1 --port 8080 --jinja
# → then in .mcp.json: LEANSTRAL_BASE_URL=http://localhost:8080/v1  LEANSTRAL_MODEL=leanstral
```

**Two things to verify at first load (they flip parts of the plan):**
1. **`-fa off` to start.** Flash-attention is the fragile part of this MLA arch (llama.cpp
   [#20748](https://github.com/ggml-org/llama.cpp/issues/20748),
   [#20710](https://github.com/ggml-org/llama.cpp/issues/20710) — crashes / halves speed). Get
   it running with FA off, then A/B test FA on.
2. **`KV self size` ≈ 1 GiB @ 32k** in the load log ⇒ MLA compression is active (good — makes
   long context cheap). Tens of GB ⇒ MLA fell back; rebuild llama.cpp / re-quant with a current
   `convert_hf_to_gguf.py`.

**Expected:** ~10–16 tok/s generation, ~150–350 tok/s prompt-eval (best analog:
Qwen3-Next-80B-A3B → 10.9 tok/s on the same HX 370). RAM ledger at Q4_K_M/32k ≈ 67 (weights) +
~1 (KV) + ~3 (compute) + OS ≈ **~74 GiB used**, leaving ~15 GiB — tight but workable; don't run
a second large model alongside.

## 5. Switching endpoints (one place)

Edit the `leanstral` env in `.mcp.json`, then reload Claude Code:

| Target | `LEANSTRAL_BASE_URL` | `LEANSTRAL_MODEL` | `LEANSTRAL_API_KEY` |
|--------|----------------------|-------------------|---------------------|
| Ollama (local) | `http://localhost:11434/v1` | `leanstral` | `ollama` |
| llama.cpp (local) | `http://localhost:8080/v1` | `leanstral` | `x` |
| Mistral Labs (free API) | `https://api.mistral.ai/v1` | `labs-leanstral-1-5` | *(real key)* |

## 6. LeanLoop (batch campaigns) — same endpoint, TOML only

LeanLoop (separate repo `~/repos/LeanLoop`) has a pluggable prover backend. Point its
`[prover.local]` (or add an `[[prover.ensemble]]` member alongside `goedel-prover-v2-8b/32b`)
at the **same** endpoint — `base_url = "http://localhost:11434/v1"`, `model = "leanstral"` — and
keep `frontier.backend = "claude_cli"`. Split of duties: **MCP tool = interactive, mid-session**
delegation from Claude Code; **LeanLoop = autonomous batch** over a goal queue. One server, both.

## 7. "Is it working?" checklist

- [x] MCP plumbing (server start, `tools/list`, `tools/call` → endpoint) — **verified 2026-07-07**
      against `goedel-prover-v2-8b` (`tmp/mcp_smoke.py`). Independent of Leanstral being served.
- [x] **Leanstral served on GPU + full draft→verify→refine loop proven 2026-07-09.** 67 GiB GGUF
      pulled + `leanstral` model created; served via standalone Vulkan `llama-server` (renderD128 +
      68.5 GiB VRAM, 14.6 tok/s); a Leanstral proof was drafted, `lean_run_code` caught the error,
      Leanstral refined to `by omega`, `lean_run_code` returned `success:true`. Model + serving +
      the loop all work on this hardware.
- [x] **Persistent `:11434` wiring COMPLETE 2026-07-09.** Ollama→Vulkan override applied
      (`ROCR_VISIBLE_DEVICES=` + `HIP_VISIBLE_DEVICES=-1`); `ollama ps` → `leanstral 100% GPU`,
      14.5 tok/s, loads in ~141 s. The loaded `mcp__leanstral__leanstral_prove` tool reaches it,
      and the **`lean-prover` subagent ran a full autonomous draft→verify loop** (`Nat.add_comm a b`
      → `lean_run_code` `success:true`). Nothing left to configure — cold-boot safe (systemd service
      + GTT kernel cmdline persist; Ollama auto-loads/unloads on demand).

## Sources
- Model: [HF card](https://huggingface.co/mistralai/Leanstral-1.5-119B-A6B) ·
  [Mistral docs](https://docs.mistral.ai/models/model-cards/leanstral-1-5) ·
  [announcement](https://mistral.ai/news/leanstral-1-5/)
- GGUF/arch: [GZGavinZhao GGUF](https://huggingface.co/GZGavinZhao/Leanstral-1.5-119B-A6B-GGUF) ·
  [llama.cpp mistral4 PR #20649](https://github.com/ggml-org/llama.cpp/pull/20649) ·
  FA issues [#20748](https://github.com/ggml-org/llama.cpp/issues/20748)/[#20710](https://github.com/ggml-org/llama.cpp/issues/20710)
- APU serving: [ROCm-GTT-OOM #19818](https://github.com/ggml-org/llama.cpp/issues/19818) ·
  [Qwen3-Next on HX370 #19396](https://github.com/ggml-org/llama.cpp/issues/19396) ·
  [Framework 13 benchmarks](https://msf.github.io/blogpost/local-llm-performance-framework13.html) ·
  [GTT tuning](https://www.jeffgeerling.com/blog/2025/increasing-vram-allocation-on-amd-ai-apus-under-linux/)
- Integration: [sub-agents](https://code.claude.com/docs/en/sub-agents) ·
  [MCP](https://code.claude.com/docs/en/mcp) ·
  [per-provider routing FR #38698](https://github.com/anthropics/claude-code/issues/38698)
