#!/usr/bin/env python3
"""CREBench runner — list / show / score challenges.

  crebench.py list                 the corpus
  crebench.py show <id>            present a challenge to an agent (no ground truth)
  crebench.py score <id> | --all   grade reports/<id>.json
"""
import subprocess
import sys

from score import HERE, parse_manifest


def cmd_list():
    for d in sorted((HERE / "challenges").iterdir()):
        if not d.is_dir():
            continue
        m = parse_manifest(d / "manifest.yaml")
        ctl = " [CONTROL]" if str(m.get("is_control", "")).lower() == "true" else ""
        print(f"{m['id']:<20} d{m.get('difficulty', '?')}  "
              f"{m['vuln_class']:<16} {m['title']}{ctl}")


def cmd_show(cid):
    d = HERE / "challenges" / cid
    m = parse_manifest(d / "manifest.yaml")
    print(f"# CREBench challenge: {m['id']} — {m['title']}\n")
    print("## Task")
    print("Review the code below. If it has a security weakness, identify its CLASS")
    print("(constant-time / fault-injection / side-channel / logic), the LOCATION, a")
    print("concrete VERIFICATION (trigger input / fault site / leakage model), and a")
    print("class-correct FIX. If the code is already hardened, say so (class 'none').")
    print(f"Write findings to reports/{cid}.json (schema in README).\n")
    print(f"## Target — {cid}/target.rs\n```rust")
    print((d / "target.rs").read_text().rstrip())
    print("```")
    hint = m.get("trigger_hint", "").strip()
    if hint:
        print(f"\n## Hint\n{hint}")


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: crebench.py {list | show <id> | score <id> | score --all}")
    cmd = sys.argv[1]
    if cmd == "list":
        cmd_list()
    elif cmd == "show":
        cmd_show(sys.argv[2])
    elif cmd == "score":
        subprocess.run([sys.executable, str(HERE / "score.py"), *sys.argv[2:]], check=False)
    else:
        sys.exit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
