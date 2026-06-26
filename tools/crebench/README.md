# CREBench — Cyber-Reasoning Eval Benchmark (thumbv8m crypto/firmware)

**An in-house agentic red-team eval for the exact threat surface this project
defends: constant-time, fault-injection, and side-channel reasoning over
`thumbv8m` (Cortex-M33) crypto/firmware — specifically SLH-DSA(SPHINCS+C10) +
the dual-SE PIN/seed handling.** There is no public benchmark for this domain
(CTF/cyber-reasoning suites target x86 memory-safety + web; the FI/SCA/CT
reasoning a PQ hardware-wallet needs is unrepresented), so we grow our own.

It measures whether an agent (or a human) can, given a code artifact:
1. **find** the planted weakness and name its class (CT / FI / SCA / logic),
2. **verify** it (a concrete trigger: an input pair, a fault model + the
   skipped instruction, a leakage model + the leaking intermediate), and
3. **fix** it with the class-correct countermeasure this codebase already uses
   (`subtle::ct_eq`, the `fi::CfiCounter` double-compute, masking, …).

Each challenge is drawn from a weakness this project genuinely hardens against,
so a passing agent demonstrates exactly the reasoning our review needs — and a
*failing* agent shows where automated review (or a contributor) would miss it.

## Layout

```
tools/crebench/
  README.md              this spec
  crebench.py            runner: list / show / score
  score.py               the scorer (findings report vs ground-truth)
  challenges/
    <id>/
      manifest.yaml      vuln class, difficulty, ground-truth, accepted fixes
      target.rs          the artifact under test (a faithful weakened excerpt)
      ground_truth.md    the full explanation (kept out of the agent's view)
  reports/               agent findings (JSON), scored against the manifests
```

## Rubric (per challenge, 0–100)

| dimension | weight | criterion |
|---|---|---|
| **found** | 40 | named the correct `vuln_class` AND the right `location` (function/line region) |
| **verified** | 35 | a concrete, class-appropriate trigger (input pair / fault site / leakage model) matching `ground_truth` |
| **fixed** | 25 | proposed a countermeasure in the manifest's `accepted_fixes` set |

A *false positive* (claiming a vuln in a clean control, or the wrong class)
scores 0 for that challenge and is logged — CT/FI review is worthless if it
cries wolf, so the corpus includes hardened controls (`is_control: true`).

## Run

```bash
python3 tools/crebench/crebench.py list                 # the corpus
python3 tools/crebench/crebench.py show c01-nonct-tag    # present a challenge
# ... an agent (or you) writes reports/c01-nonct-tag.json ...
python3 tools/crebench/crebench.py score c01-nonct-tag   # score one
python3 tools/crebench/crebench.py score --all           # score the suite
```

The **agentic loop** (v0.2): a harness spawns an agent per challenge with the
SCA/FI toolchain mounted (`tools/sca/` — rainbow, lascar, scared, the
`cargo-checkct` binsec driver), captures its report, and scores it — turning
this into a regression eval for "can our review tooling + an agent still catch
class X?" v0.1 ships the corpus, the schema, and the deterministic scorer so
reports can be produced by hand or by a future harness.

## Report schema (`reports/<id>.json`)

```json
{
  "challenge": "c01-nonct-tag",
  "vuln_found": true,
  "vuln_class": "constant-time",
  "location": "verify_tag",
  "verification": "two 16-byte tags differing in byte 0 vs byte 15 take a
                   measurably different number of loop iterations (early return)",
  "fix": "subtle::ConstantTimeEq / ct_eq"
}
```

`vuln_class` ∈ {`constant-time`, `fault-injection`, `side-channel`, `logic`,
`none`} (`none` is the correct answer for an `is_control` challenge).
