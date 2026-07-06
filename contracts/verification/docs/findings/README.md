# FV adversarial-review findings

This folder holds the **formal-verification** adversarial-review reports (kept separate from the firmware/hardware reports in `docs/security/adversarial-review/findings/`, since the FV surface has its own claims inventory + ledger).

**The authoritative catalogue is [`../REVIEW_PROVENANCE.md`](../REVIEW_PROVENANCE.md)** — the FV provenance ledger, one row per review round (date · surface · depth · findings · verdict · doc). Do **not** duplicate that table here; this README is just the folder's signpost. For the per-finding status convention (🔲 OPEN → ✅ FIXED / ☑️ ACCEPTED / 🚫 INVALID / ⏸ DEFERRED) and the report template, see [`../../../../docs/security/adversarial-review/findings/README.md`](../../../../docs/security/adversarial-review/findings/README.md) + [`TEMPLATE.md`](../../../../docs/security/adversarial-review/findings/TEMPLATE.md).

**Filing a new FV pass:** write the report here (`<surface>-<YYYY-MM-DD>.md`), give it frontmatter `status:` + each finding its own `Status:` line, and add a row to `../REVIEW_PROVENANCE.md`. The FV playbook ([`docs/verification/fv-adversarial-review-playbook.md`](../../../../docs/verification/fv-adversarial-review-playbook.md)) points its OUTPUT here.

Reports here are historical passes filed under this convention on 2026-07-06; their per-round verdict + handled-state live in `../REVIEW_PROVENANCE.md`, and confirmed findings are tracked in `AXIOM_STATUS.json` / `STATUS.md` / `docs/work-todo.md`.
