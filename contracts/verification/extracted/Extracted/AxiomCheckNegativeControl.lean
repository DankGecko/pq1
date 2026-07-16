/- PERMANENT NEGATIVE CONTROL for the §33 extracted axiom-closure gate (F3, 2026-07-16).

   This module deliberately consumes a bogus `axiom Evil : False`. `make
   verify-extracted` runs its `#print axioms` dump through
   `check_axiom_closure.py --manifest` and asserts the checker REJECTS it
   (exit 1). A green here means the closure gate has lost its teeth — the exact
   failure the old `grep sorryAx` gate could not catch, since a consumed
   `axiom Evil : False` prints `depends on axioms: [Evil]` with no `sorryAx`
   substring.

   `evil_consumed` is NOT in axiom_closure_manifest.txt, so the manifest gate
   fails on BOTH counts: an unlisted headline AND a disallowed `Evil` axiom.

   This file is intentionally NOT imported by `Extracted.lean`, so `lake build`
   never elaborates it and it can never enter any real headline's closure —
   zero pollution. It is only ever elaborated standalone by the gate's
   negative-control step (`lake env lean Extracted/AxiomCheckNegativeControl.lean`). -/
namespace NegativeControl

axiom Evil : False

theorem evil_consumed : False := Evil

#print axioms NegativeControl.evil_consumed

end NegativeControl
