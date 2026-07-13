# Vulnerability write-ups (`VULN-*`)

Per-finding vulnerability write-ups for PQSigner_OS — each is a self-contained
analysis of one concrete bug: the mechanism, a falsifiable PoC / repro, the
fix, and the regression that pins it closed. These are the **findings**; the
reusable review *recipes* that surface this class live in
[`../adversarial-review/`](../adversarial-review/README.md), and the
consolidated status of open/closed security work is in
[`../../STATUS.md`](../../STATUS.md).

> Consolidated here 2026-07-02 (was split across `docs/` root and
> `docs/security/`). Reference these by their `docs/security/vulns/VULN-*.md`
> path.

## Clear-signing / WYSIWYS (native on-device decoders)

The trusted-display invariant (Claim 9): the page the user confirms must
commit to the bytes that get signed. Each of these is a way a signed value
diverged from — or hid behind — what was rendered.

| Write-up | The break |
|----------|-----------|
| [approvehash-gate-length-bypass](./VULN-approvehash-gate-length-bypass.md) | Safe `approveHash` mandatory-clear-sign gate bypassed by a trailing calldata byte |
| [erc20-decimals-inflation-flux-meme](./VULN-erc20-decimals-inflation-flux-meme.md) | ERC-20 `decimals` inflation ships a magnitude-hiding drain (HIGH) |
| [erc7730-eip712-nested-struct-address-hide](./VULN-erc7730-eip712-nested-struct-address-hide.md) | EIP-712 nested-struct fund-routing address escapes the WYSIWYS build gate |
| [erc7730-rule1-inert-field-nonaddr-action-hide](./VULN-erc7730-rule1-inert-field-nonaddr-action-hide.md) | Rule-1 "effect-bearing field" accepted INERT fields → banner over a fully-hidden action |
| [erc7730-visible-never-noparam-clearsign](./VULN-erc7730-visible-never-noparam-clearsign.md) | `visible:"never"` lets a shipping descriptor clear-sign with NO parameters shown |
| [erc7730-walker-slot-confusion](./VULN-erc7730-walker-slot-confusion.md) | Phase-4 calldata-walker slot-confusion (renders one field, signs another) |

## Availability / durable-brick (state machines + provisioning)

Not confidentiality breaks — paths where a hostile companion or a mis-ordered
write leaves the device permanently unable to sign (or half-provisioned).

| Write-up | The break |
|----------|-----------|
| [fwcommit-otp-before-commit-brick](./VULN-fwcommit-otp-before-commit-brick.md) | FW-COMMIT raises the anti-rollback floor before the new image is committable (HIGH availability) |
| [offchain-sync-page123-exhaustion-brick](./VULN-offchain-sync-page123-exhaustion-brick.md) | `CMD_OFFCHAIN_SYNC` page-123 exhaustion → permanent unrecoverable signing brick |
| [offchain-sync-value-inflation-slot-brick](./VULN-offchain-sync-value-inflation-slot-brick.md) | Unbounded `target_count` → consent-free durable slot brick |
| [page126-bhk-fwfail-collision-brick](./VULN-page126-bhk-fwfail-collision-brick.md) | FW-update COMMIT erases the BHK store on page 126 → SE050 unpairing brick |
| [provision-halfwrite-softbrick](./VULN-provision-halfwrite-softbrick.md) | Half-written provisioning soft-bricks the device at first-boot setup |
