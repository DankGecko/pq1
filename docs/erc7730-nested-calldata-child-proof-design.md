# ERC-7730 nested calldata with authenticated child semantics

> **UPDATE 2026-08-05 — implemented, production enrollment still dormant.**
> The bounded N1–N4 mechanism landed on `master` at
> `3b1b3dfd9c8ed66d1b618029d2cff57a57d5595b` (tree
> `f81df48ff788dbe3212a23172938ce6d9a33a07a`) and #346 is closed. The source
> below remains the frozen Phase-B design record. The one-level proof-set
> engine is active, but `PRODUCTION_NESTED_CALLDATA_ENROLLMENTS` remains empty
> and the current production catalogue contains zero `op=calldata` formats;
> this grants no real-descriptor admission, recursion, or fallback authority.

**Status:** Phase-B candidate freeze for
[#346](https://github.com/EthereumPhone/PQ1/issues/346). This document
authorizes no production descriptor admission, merge, release, or hardware
action. Implementation starts only after the required architecture review and
the recorded maintainer decision.

## 1. Objective and observable outcome

PQ1 may render one embedded contract call as clear signing only when the
firmware independently authenticates both the parent descriptor and the exact
child semantics. The first slice is complete when:

- the legacy one-bundle ERC-7730 trailer remains byte-compatible;
- a versioned proof-set trailer can carry one independently Merkle-proven child
  descriptor in addition to the parent;
- the device derives the child target, selector, and exact calldata interval
  from the signed parent bytes and authenticated parent IR;
- the child descriptor binds to that derived chain and target and contains the
  derived selector;
- the selected child format passes the same head-bound, canonical ABI framing,
  and format-wide word-guard preflight over that exact interval before any
  child page is published;
- a one-level scoped child render composes atomically into the parent's single
  31-page transcript, with one outer envelope and one final confirmation;
- every missing, ambiguous, malformed, recursive, non-`CALL`, or over-budget
  case hard-refuses; and
- a synthetic parent/child fixture exercises the full path while the
  production catalogue continues to contain **zero** `op=calldata` fields.

This is signing-eligibility and trust-boundary work. A hash of opaque child
bytes is not a successful clear-sign render.

## 2. Baseline and sources of truth

The recorded baseline is the clean isolated worktree branch
`erc7730/nested-calldata-346-20260721` at
`f995d667357900675b903bf663031d2d0d9dc150`. The primary checkout is not an
implementation input and must not be moved or cleaned.

Active owner inputs at freeze:

| Input | Identity / scope |
|---|---|
| `CLAUDE.md` | SHA-256 `67b5af91b3a8f203e7d1668fb23a4f8efa36ee67702c0447f214d69f43439ac1`; project and trusted-display invariants |
| `docs/STATUS.md` | SHA-256 `c911c8661af564523158e6a0ce60522789efc3318f31b7eb88874b087cf9094b`; evidence/ship frontier router |
| planning workflow | SHA-256 `0eb26cafe1829e4f8f0f5bf3e9f048840bf76e6789ca2e55c68bb6e922e758f3`; Phase A-E and three-reviewer gates |
| companion guide §12.3/§12.5 | SHA-256 `6c4c56fddac8ec61ab821f1b7938e1b8f9da758ae2609a15ae8d9b0c972b2adc`; current refusal and sole-C1 framing |
| generated review | SHA-256 `d66ad6f7a27b744d6aaac15a98d7e6498a04e34cc4e317f62f90b26ccf6a2f3b`; exact included/omitted catalogue state |
| curation manifest | SHA-256 `a758495eccdd5fc9583f957cb4eed04cb50681f830666682e591d98a74601268`; upstream registry commit `784c87c925e8438e7b4736b2af85a501f8d2a265`, tree `8da8dba78c3e581bbd06c15cc681d07e570dcfb1` |
| Ambire comparison | local `ambire-common` commit `348591fb`; control-flow reference only, never device authority |

The current vendored corpus has 14 source `format:"calldata"` fields (22
concrete descriptors after include expansion), but the generated production
catalogue emits no `op=calldata` field. There is no conflict among the active
owner inputs: all require refusal until a child semantic proof exists. The
clear-signing, compromised-companion, TrustZone, FI, and resource playbooks are
intersecting later assurance lenses; their combined owner-triggered sweep
remains deferred under the project workflow and existing tracker items.

## 3. Invariants and concrete threats

| Invariant | Failure without it | Required mechanism |
|---|---|---|
| Child semantics are rooted | Host supplies a friendly decoder for attacker calldata | Every distinct child IR carries its own proof under the firmware-pinned root |
| Parent bytes select the child | Proof describes a different call than the signed tail | Device derives interval, target, chain, and selector; host supplies none of those as facts |
| Exact ABI ownership | Gaps, aliases, padding, or suffixes carry hidden signed bytes | Reuse the sole-C1 exact-whole-tail resolver before any page publication |
| Child ABI is canonical | A rooted child format paints selected fields while malformed head/tails, hidden fields, or failed guards retain different signed meaning | Run the complete contract head-bound, format-framing, and word-guard preflight on the exact child interval before its boundary or intent page |
| Execution meaning is enrolled | A `delegatecall` is presented as a call to the library address | Only exact, source-evidenced parent descriptor/deployment/selector/path enrollments with ordinary zero-value `CALL` semantics may compile and render; the device does not derive execution mode from calldata |
| Child context is not invented | Child `@.value`, `@.from`, or nonce displays synthetic zero/identity | First slice exposes only inherited chain, resolved `@.to`, and enrolled zero call value; `@.from`/nonce use rejects |
| Composition is complete | Child pages truncate or replace parent facts | One atomic page buffer, global cap 31, one outer envelope/final confirmation |
| Native authority cannot hide below the parent | A Safe/CoW/MultiSend child selector bypasses the outer-only native dispatch ladder | Before child descriptor selection, a selector-reservation gate hard-refuses every selector claimed by the current native decoders; outer native precedence and fatal failed claims also remain unchanged |
| Faulted binding cannot publish | A skipped target/selector check still reaches confirm | Duplicate pure binding derivation, child bundle binding proof, and the existing two-pass exact transcript receipt all include the nested binding |

## 4. Selected wire and proof model

### 4.1 Backward-compatible proof set

An existing payload remains exactly one legacy bundle:

```text
ir_len:u16 BE || ir || leaf_index:u32 BE || proof_depth:u32 BE || proof
```

A distinct-child request uses this envelope:

```text
magic:u16 BE = 0xe773
version:u8 = 1
count:u8 = 2
repeat count times: bundle_len:u16 BE || legacy_bundle[bundle_len]
```

Bundle zero is the outer descriptor and bundle one is the only distinct child.
The maximum is `4 + 2 * (2 + 5130) = 10,268` bytes. The magic exceeds the
legacy 4-KiB IR cap, so old firmware rejects it rather than misparsing it.
Truncation, zero/other counts, duplicate/trailing bytes, over-cap lengths, or a
non-canonical leaf index reject the complete request. Both bundles use the
unchanged verifier, root, and real leaf-count bound.

When the derived target equals the outer descriptor contract and the outer IR
already contains the child selector, the authenticated outer bundle may be
reused as the child semantic proof. This same-descriptor case stays on the
legacy one-bundle wire and avoids sending a duplicate proof. It preserves a
possible route for same-contract multicall descriptors, but does not establish
their execution semantics or admit Aave: source and deployment evidence may
instead require a separate delegatecall/same-context model. Selection must be
unique in both dimensions: exactly one descriptor in the verified set must
bind to the derived `(chain,target)`, and exactly one format inside the selected
IR must match the derived selector. Either ambiguity rejects, including on the
one-bundle reuse path.

The wrapper `version = 1` is only its envelope-syntax version. It is not the
existing `ERC7730_TRAILER_VERSION` and is not a discoverable device feature by
itself. Add a shared `CAP_ERC7730_PROOF_SET = 1 << 2` bit to the
`GET_DEVICE_INFO` capability bitmap (bit 1 remains retired). A companion sends
the wrapper only when this exact bit is present; otherwise it may send a legacy
single bundle or must refuse a distinct-child request. Tests pin old/new
negotiation and prove that firmware-version placeholder bytes are never used
for this decision. Single and batch payload caps are updated, but the batch
aggregate trailer budget remains 24 KiB and refuses combinations that do not
fit.

### 4.2 Fixed first-slice semantics

No generic interpretation is inferred from an upstream field. A shared exact
enrollment table, consumed by both `dbgen` and the device preflight, binds:

- descriptor hash, chain, parent deployment, canonical parent signature and
  selector;
- the single calldata field ordinal and exact canonical C1 `bytes` path;
- the canonical static-address `calleePath` (or frozen `@.to` path);
- ordinary `CALL` semantics; and
- an enrolled zero child call value.

Every table row carries the exact source/deployment evidence identity used to
justify those execution facts (repository and immutable revision, deployment,
and code identity or proxy-resolution evidence). These are source-evidenced
firmware policy facts, not facts derived from the signed child bytes, and no UI
wording may imply otherwise. The Phase-C fixture row is explicitly test-only;
the production table stays empty.

The selected format must contain exactly one `Calldata` field. Its terminal
kind is `DynamicBytes`, its visibility is `always`, `calleePath` is mandatory,
and its field path is exactly
`RootStructured / FieldIdx(slot) / FollowOffset`. The existing `Calldata`
opcode and nested-callee TLV are sufficient; activation of this formerly
reserved opcode does not create a second decoder or reinterpret any currently
admitted leaf. `selector`, `selectorPath`, constant callees, `amount*`,
`spender*`, cross-chain overrides, nonzero value, arrays, and deeper paths
remain compile-time and runtime refusals.

The compiler uses an address-typed callee-path compiler. The device separately
requires either `@.to` or one canonical static address word with twelve zero
prefix bytes. A generic one-word path is not callee authority.

### 4.3 Exact child binding

Before pages are touched, the device:

1. selects the parent format from the signed outer selector;
2. runs the existing whole-format framing preflight;
3. resolves the enrolled nested field's offset, requiring it to equal the
   authenticated static-head end;
4. reads its length with checked arithmetic, requires zero ABI right-padding,
   and requires the padded end to equal the parent body end;
5. records the exact half-open child-data interval relative to the signed outer
   calldata;
6. resolves the enrolled callee path as a canonical address;
7. requires at least four child bytes and derives the selector from bytes
   `[0..4]` (no host-supplied selector);
8. applies a child-only selector-reservation gate before descriptor selection,
   rejecting selector collisions with Safe `approveHash`, Safe
   `execTransaction`, CoW `setPreSignature`, and `multiSend` regardless of
   target (a deliberately conservative first-slice rule);
9. uniquely selects a verified descriptor for the inherited chain and target,
   then uniquely selects one format inside it for the derived selector;
10. rejects if the selected child format itself contains `Calldata`; and
11. before publishing the child boundary or intent, runs the same
    `head_bounded_body`, complete contract-calldata framing, and format-wide
    word-guard checks used by a top-level contract render over exactly the
    derived child interval.

The shared preflight is parameterized over an explicit contract container
context; it must not fabricate an `Eip1559Tx` from the parent. For the child it
contains inherited chain, resolved target, and the enrolled zero call value.
Use of `@.from` or `@.nonce` is rejected during deep validation/preflight, so
neither value can be synthesized accidentally.

The secure caller derives this binding twice around a randomized gap, requires
an exact match, and performs the existing FI-hardened membership/context proof
for a distinct child bundle. Each renderer pass recomputes and compares the
same binding. The transcript receipt commits to a domain-separated nested
record containing the parent leaf identity and selector, field ordinal/path,
exact interval, child target and selector, call/value policy, and child leaf
identity. A faulted or skipped publication retains the existing fail-in state.

## 5. Render composition and bounds

The child uses a scoped contract renderer, not the top-level renderer:

1. retain the parent intent and every ordinary parent field in descriptor
   order;
2. at the nested field, paint an unmistakable child-call boundary containing
   the parent field label and the complete 20-byte target address;
3. paint the authenticated child intent and every visible child field;
4. do not append child gas, nonce, fingerprint, confirmation, or another
   outer-style envelope;
5. resume remaining parent fields, then append the outer envelope and final
   confirmation once.

The same `Pages` object is used throughout. `MAX_PAGES = 31` is absolute and
every append remains fallible; overflow leaves no confirmable transcript. The
implementation has one child level (`MAX_CALLDATA_DEPTH = 1`) and consumes at
most two descriptor bundles. Because a child format containing `Calldata`
rejects, recursion and cycles are structurally unreachable in this slice. No
recursive heap or second page buffer is introduced.

The child render context exposes inherited chain, resolved target, and the
enrolled zero call value. It passes no signer/`@.from` authority and rejects
child use of `@.from` or `@.nonce`; it must not synthesize those values. Names
and an independently verified ERC-20 metadata capability may still be reused
under their existing exact chain/address checks.

Native CoW, Safe `approveHash`, Safe `execTransaction`, and MultiSend keep their
current higher-priority dispatch. A payload that claims a native Safe shape but
fails its native verifier cannot retry through this generic path. That outer
ordering is not considered protection for a derived child: the child-only
selector-reservation gate is evaluated in the shared nested-binding path used
by both single and batch signing, before proof selection and again before child
page publication under the duplicated binding receipt.

## 6. Scope, alternatives, and deletion candidates

Included Phase-C slices:

1. **N1 — proof-set transport:** parser/verifier, capability/cap constants,
   `GET_DEVICE_INFO` negotiation, single/batch routing, legacy compatibility,
   and FI-bound raw bundle handles.
2. **N2 — authenticated parent policy:** shared exact enrollment, address-only
   callee compiler, host/device field policy, and dormant production catalogue.
3. **N3 — binding and scoped render:** exact interval derivation, unique child
   descriptor/format selection, full child preflight, child-native reservation,
   FI binding, nested boundary/child semantics, transcript receipt, and
   page/depth/outer-native-precedence gates.
4. **N4 — executable evidence and integration:** synthetic two-contract
   catalogue fixture, host render/dispatcher tests, malformed proof/framing
   tests, companion helper/docs, generated drift checks, target link and
   resource receipt.

Explicit non-goals are real production descriptor admission; multiple child
calls; `bytes[]`/array-of-tuple topology; multi-tail ABI; selector-outside-data;
amount/spender propagation; nonzero child value; cross-chain calls; generic
delegatecall/staticcall/create; recursive depth above one; and hash/raw
fallback. #347 owns authenticated multi-tail/partition work. Any real
descriptor needs a new exact semantic enrollment backed by deployment/source
evidence and its own catalogue slice.

Rejected alternatives:

- **Embed child IR in the parent leaf:** duplicates semantics, creates
  parent-by-child catalogue growth, consumes the 4-KiB IR/pool bounds, and is
  unusable for runtime-selected callees.
- **Carry only a child index/hash:** firmware pins the root, not the catalogue;
  bytes plus a Merkle proof are still required, reducing to the selected model.
- **Accept a host-decoded child or selector-only label:** not rooted semantics
  and violates the hostile-companion model.
- **Hash-only child display:** non-injective and falsely reassuring; it remains
  a refusal, not clear signing.
- **General recursion now:** no production leaf can use it safely, while it
  multiplies wire, stack, cycle, and page-accounting risk.

Deletion test: if the distinct-child proof-set path cannot fit the linked
resource envelope, retain same-descriptor one-bundle support only and bank
distinct targets rather than raising the batch/SRAM budgets in this phase.

## 7. Compatibility and resource envelope

- Legacy single bundles and Merkle proofs remain byte-identical.
- The proof-set wrapper is a compatible authenticated extension, but updated
  firmware/companion capability negotiation is mandatory before it is sent.
- Per-IR 4-KiB, proof-depth 32, canonical leaf count, format/field/path caps,
  signed calldata maximum, and 31-page cap remain unchanged.
- The batch aggregate trailer budget remains 24 KiB. A batch may therefore
  carry fewer maximum proof sets; overflow refuses instead of enlarging secure
  SRAM.
- Proof-set bytes stay in the existing TOCTOU snapshot/static command buffers;
  they must not be copied onto the secure stack. Final Thumb links record
  secure FLASH span, nonsecure static command-buffer growth, secure static RAM,
  and the unchanged stack/call-depth bound.
- No persistent state, migration, network write, deployment, flashing,
  lifecycle mutation, key use, or irreversible action is authorized.

## 8. Validation matrix

Mandatory merge evidence for the combined candidate:

| Cut / requirement | Executable evidence |
|---|---|
| Legacy wire compatibility | old one-bundle positive vectors and exact byte round trips |
| Capability negotiation | proof-set bit reported exactly; old/no-bit companion path never sends wrapper; firmware placeholder version bytes have no effect |
| Proof-set exactness | success plus bad magic/version/count/order/root/index/length/truncation/trailing/duplicate/over-cap cases |
| Parent interval ownership | flips covering offset, length, head overlap, gap, alias, padding, suffix, short selector, and child data |
| Target/selector/chain binding | dirty address, wrong target/chain/selector/descriptor, ambiguous descriptor set, duplicate selector format, and field/callee-path mutations refuse |
| Child ABI canonicality | child short head, static suffix, dynamic gap/alias/dirty padding/trailing bytes, hidden malformed field, and failed word guard all refuse before the child boundary |
| Fixed execution policy | unenrolled parent, non-address callee, selector/amount/spender params, nonzero/delegate/unknown call modes refuse |
| Native child exclusion | all four reserved child selectors refuse with valid generic evidence in single and batch paths; one-byte selector misses continue through ordinary binding |
| No recursion/cycle | child format containing `Calldata`, extra child evidence, and repeated/deeper attempts refuse |
| Container honesty | child `@.from`/`@.nonce` refuse; zero value and inherited chain/target controls render exactly |
| Complete transcript | parent/child signed-byte flip changes exact pages or refuses; page 31 succeeds where intended and page 32 refuses atomically |
| Native precedence | valid generic evidence beside Safe still yields native pages; malformed Safe/MultiSend claim remains fatal |
| Single/batch routing | correct member only, aggregate byte 24,577 refusal, batch banners/final commitment unchanged |
| Catalogue honesty | production review still has zero `op=calldata`; generated skips say unsupported real shapes honestly |
| Integration/resources | focused crates, secure host suite, descriptor drift, synthetic QEMU path if available, Thumb S/NS links and size receipts |

The clear-signing Layer-1 gate requires behavior-bound flip-to-decline tests for
the new decoder. Kani/fuzz targets are extended where the touched pure parser or
interval kernel is already modeled; no unrelated formal or hardware campaign
is pulled into this phase. Kani runner availability is reported honestly and
does not convert a missing verdict into a pass.

## 9. Review, convergence, landing, and rollback

Architecture boundary: the first simultaneous GPT-5.6 SOL / Opus 4.8 / Kimi
K3 wave reviewed commit `08ce92c1983ea7ff0cd5e2879e5a4cb6a449d959`,
tree `b7a290d469a211493fa4220134501cc2e0d70cd8`. Coordinator reproduction retained
the child-preflight, derived-child native-reservation, explicit-capability,
source-evidence wording, and same-IR selector-uniqueness corrections above;
duplicate or unsupported concerns were not expanded into new work. Freeze this
combined remediation and run the one required fresh architecture re-review.
The user's instruction to complete the ordered ERC-7730 roadmap supplies the
maintainer direction to enter the bounded N1-N4 Phase-C campaign when that
review has no reproduced blocker; it does not authorize a real descriptor,
incompatible expansion, or external action.

Phase-D stopping point and closed checklist:

1. stop all writers and freeze the combined N1-N4 commit/tree;
2. run the mandatory validation rows above once on that exact candidate;
3. record resource and generated-artifact identities;
4. run one simultaneous short three-reviewer merge wave;
5. reproduce and remediate only stage blockers, then re-freeze/re-review once
   if behavior changed materially;
6. confirm the existing combined owner-triggered playbook GitHub issue covers
   the new clear-signing/wire/FI/resource surface (update it only if it does
   not);
7. fast-forward land, re-run drift/identity checks, update/close tracker issues,
   and record residual production/hardware evidence honestly.

The branch/worktree is isolated. Each slice remains buildable and fail-closed.
If the experiment fails, revert its commits or delete the isolated branch; do
not reset, clean, or move the user's primary checkout. A new signing authority,
fallback, persistent state, incompatible ecosystem migration, real catalogue
admission, or failed resource envelope returns the work to Phase B.
