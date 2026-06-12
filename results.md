# Results — PFC Connector Gateway proof

Run: 2026-06-12T00:22:31.875Z · Node v22.22.3 · verifier pfc-verifier/0.13.0 · ledger: file-backed JSONL with hash chaining

## Scenario outcomes

### happy-path

```
✔ 1-scrape: PRE_EFFECT → executed → ExecutionResultReceipt exr_45ed011b-f5a2-466c-b969-f487b16ecf35 (result receipt verifies: valid=true, chainIntact=true)
✔ 2-crm-write: PRE_EFFECT → executed → ExecutionResultReceipt exr_20310600-d082-40a0-9aed-967a6a67bcce (result receipt verifies: valid=true, chainIntact=true)
✔ 3-email-draft: PRE_EFFECT → executed → ExecutionResultReceipt exr_a6d81b84-1a0b-4abe-b7cf-13ccf9cc6d8b (result receipt verifies: valid=true, chainIntact=true)
```

### mid-run-revocation

```
✔ 1-scrape: PRE_EFFECT → executed → ExecutionResultReceipt exr_03c27e2c-abb8-405f-b85a-23dd0926fdba (result receipt verifies: valid=true, chainIntact=true)
✔ 2-crm-write: PRE_EFFECT → executed → ExecutionResultReceipt exr_3ff79b93-cff4-42dd-83ee-7f7688c2a04d (result receipt verifies: valid=true, chainIntact=true)
⚠ token dtk_7793920b-6453-4ce8-888c-5d941a8e0513 REVOKED before 3-email-draft (ledger seq 15)
✘ 3-email-draft: BLOCKED fail-closed — codes [TOKEN_REVOKED], valid=false, chainIntact=true, freshnessSatisfied=true; signed refusal receipt bnd_ed6d386f-c42c-4741-916f-6e767e9ae680
```

## Per-boundary-check latency (stub adapters, simulated latency)

> **Measurement caveat:** adapter latencies below are produced by stub
> connectors with simulated, jittered delays approximating typical MCP
> round-trips — they are not live-connector measurements. The boundary
> verification and receipt issuance columns are real measured costs of the
> governance layer itself. Re-running against live HubSpot / Gmail /
> Firecrawl MCP adapters is future work.

Verification = evaluating the 16 boundary invariants (signatures, hash bindings,
key lifecycle via isActiveAt(), revocation, nonce/idempotency, scope, freshness).
Receipt issuance = signing the BoundaryReceipt + hash-chained ledger append.
Adapter = simulated connector latency (absent on BLOCKED calls — fail-closed).

| step | connector:tool | op | status | verification (ms) | receipt issuance (ms) | adapter (ms) |
|---|---|---|---|---:|---:|---:|
| happy-path/1-scrape | firecrawl:firecrawl_scrape | scrape | PRE_EFFECT | 0.285 | 0.225 | 508.142 |
| happy-path/2-crm-write | hubspot:manage_crm_objects | create | PRE_EFFECT | 0.483 | 0.518 | 337.028 |
| happy-path/3-email-draft | gmail:create_draft | create | PRE_EFFECT | 0.998 | 0.356 | 223.570 |
| mid-run-revocation/1-scrape | firecrawl:firecrawl_scrape | scrape | PRE_EFFECT | 0.415 | 0.232 | 435.242 |
| mid-run-revocation/2-crm-write | hubspot:manage_crm_objects | create | PRE_EFFECT | 0.828 | 0.530 | 243.746 |
| mid-run-revocation/3-email-draft | gmail:create_draft | create | BLOCKED | 0.846 | 0.299 | — |

## Aggregates

| metric | n | mean (ms) | p50 (ms) | p95 (ms) | max (ms) |
|---|---:|---:|---:|---:|---:|
| boundary verification | 6 | 0.642 | 0.828 | 0.998 | 0.998 |
| receipt issuance | 6 | 0.360 | 0.356 | 0.530 | 0.530 |

Governance overhead per call (verification + receipt issuance) averages **1.002 ms**, against a mean *simulated* connector latency of **349.546 ms** — the chain check is noise relative to network-bound MCP calls. Live-connector measurements are future work.

## ChainVerificationError coverage

Honest accounting of what the test suite actively falsifies: a code is
**tested** only if a test asserts its emission on a failing path. Untested
codes have implemented verifier paths but no falsifying test yet.

| code | status | falsified by |
|---|---|---|
| `INVALID_SIGNATURE` | ⬜ untested | — |
| `UNKNOWN_KEY` | ⬜ untested | — |
| `MALFORMED_ARTIFACT` | ⬜ untested | — |
| `CHAIN_INTEGRITY_VIOLATION` | ⬜ untested | — |
| `KEY_OWNER_MISMATCH` | ⬜ untested | — |
| `ISSUER_KEY_REVOKED` | ⬜ untested | — |
| `ISSUER_KEY_EXPIRED` | ⬜ untested | — |
| `DELEGATEE_KEY_REVOKED` | ⬜ untested | — |
| `DELEGATEE_KEY_EXPIRED` | ⬜ untested | — |
| `EXECUTING_AGENT_KEY_REVOKED` | ⬜ untested | — |
| `EXECUTING_AGENT_KEY_EXPIRED` | ⬜ untested | — |
| `KEY_NOT_YET_ACTIVE` | ⬜ untested | — |
| `ROOT_RECEIPT_NOT_FOUND` | ⬜ untested | — |
| `ROOT_RECEIPT_EXPIRED` | ⬜ untested | — |
| `ROOT_RECEIPT_REVOKED` | ⬜ untested | — |
| `TOKEN_NOT_FOUND` | ⬜ untested | — |
| `TOKEN_EXPIRED` | ⬜ untested | — |
| `TOKEN_REVOKED` | ✅ tested | revoked mid-run (gateway block + retroactive replay) |
| `USAGE_LIMIT_EXCEEDED` | ⬜ untested | — |
| `AGENT_MISMATCH` | ⬜ untested | — |
| `ACTION_NOT_PERMITTED` | ✅ tested | out-of-scope tool call (and out-of-scope operation) |
| `TARGET_NOT_PERMITTED` | ✅ tested | out-of-scope tool call |
| `SCOPE_EXCEEDS_PARENT` | ✅ tested | scope containment at issuance |
| `PARENT_HASH_MISMATCH` | ⬜ untested | — |
| `PAYLOAD_HASH_MISMATCH` | ⬜ untested | — |
| `OBSERVED_REQUEST_MISMATCH` | ⬜ untested | — |
| `NONCE_ALREADY_SEEN` | ⬜ untested | — |
| `IDEMPOTENCY_CONFLICT` | ⬜ untested | — |
| `RESULT_WITHOUT_VALID_BOUNDARY` | ⬜ untested | — |
| `RESULT_FOR_BLOCKED_BOUNDARY` | ✅ tested | store refuses forged result for BLOCKED boundary |
| `TIMING_VIOLATION` | ⬜ untested | — |
| `FRESHNESS_VIOLATION` | ✅ tested | expired freshness bound (stale head + sequence regression) |
| `POLICY_NOT_FOUND` | ⬜ untested | — |
| `VERIFIER_VERSION_MISMATCH` | ⬜ untested | — |

Coverage: 6/34 codes actively falsified.

## Ledger audit

Hash-chain verification over 17 entries: **INTACT**.

## Notable receipts (scenario 2)

Step `mid-run-revocation/3-email-draft` was refused fail-closed: the boundary check observed the
REVOCATION ledger entry and issued a signed `BLOCKED` BoundaryReceipt with
`verification.result: "FAIL"` and error code `TOKEN_REVOKED`. The verification
result preserved the v0.13 distinction: `chainIntact: true` (nothing
cryptographically broken) while `valid: false` (not authorized to proceed).
