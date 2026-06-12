# pfc-connector-gateway-proof

Reference implementation for governing MCP connector calls with the PFC
(Prime Form Calculus) delegation chain, v0.13. Companion to
`pfc-execution-boundary-proof` and `pfc-delegation-chain-proof`: same artifact
vocabulary, same verifier semantics, applied to the boundary where an agent
touches the outside world — the MCP connector call.

## Thesis

Every MCP connector call an agent makes can carry a verifiable delegation
chain from the original human authorization to the execution boundary, such
that (a) the call is checked against explicit tool-scope boundaries *before*
any side effect, (b) authority can be revoked mid-execution and the very next
boundary check fails closed, and (c) every decision — including refusals —
produces a signed receipt that any party can verify without trusting the
gateway that produced it.

## Four-artifact chain at the connector boundary

```
HumanAuthReceipt                 signed by governance-layer
  └─► DelegationToken            signed by Agent A (orchestrator)
        │    carries tool scope: connector:tool targets, tool.operation
        │    actions, and a risk-classed FreshnessBound
        └─► BoundaryReceipt      signed by Agent B (gateway) — PRE-EFFECT,
              │                  status fixed at issuance (PRE_EFFECT|BLOCKED)
              │ ┌──────────────────────────────────────────────┐
              │ │  MCP connector call (only on PRE_EFFECT)     │
              │ │  firecrawl_scrape · manage_crm_objects ·     │
              │ │  create_draft                                │
              │ └──────────────────────────────────────────────┘
              └─► ExecutionResultReceipt   signed by Agent B — POST-EFFECT
```

All four artifacts append to a file-backed, hash-chained ledger
(`ledger.jsonl`); revocations land on the same ledger, so the head a boundary
check anchors its freshness to also commits to every revocation it must have
seen.

## Tool-scope model

A connector call `{connector, tool, operation, payload}` maps onto the spec's
scope checks (boundary invariants 14–15):

| spec field | encoding | example |
|---|---|---|
| `permittedTargets` | `connector:tool` | `hubspot:manage_crm_objects` |
| `permittedActions` | `tool.operation` | `manage_crm_objects.create` |

Operation constraints are therefore *inside* the verifier's scope-containment
checks, not a side channel: a token delegating `manage_crm_objects.create`
but not `.update` blocks an update with `ACTION_NOT_PERMITTED`, and scope can
only narrow down the chain (`SCOPE_EXCEEDS_PARENT` at token issuance).

## What this proves

- **Pre-effect gating.** The 16 boundary invariants (hash bindings, Ed25519
  signatures over JCS/RFC 8785, key lifecycle via `isActiveAt()`, revocation,
  nonce/idempotency, scope, freshness) run before any connector adapter is
  invoked. A `BLOCKED` boundary never reaches the adapter.
- **Mid-run revocation fails closed.** Scenario 2 revokes the token between
  steps 2 and 3 through the `RevocationLog` write path (a hash-committed
  ledger entry). Step 3 is refused with `TOKEN_REVOKED` and a signed,
  independently verifiable `BLOCKED` receipt.
- **`chainIntact` vs `valid` is preserved.** A revoked or out-of-scope call
  yields `valid: false, chainIntact: true` — correctly blocked, not
  cryptographically broken. Per v0.13, `chainIntact` excludes scope, expiry,
  revocation, nonce, and authorization outcome.
- **Freshness is a distinct failure mode.** A stale ledger view or a
  `sequenceNumber` regression (rollback attack) produces
  `FRESHNESS_VIOLATION` with `freshnessSatisfied: false` while the chain
  remains intact.
- **Receipts outlive the gateway's word.** `verifyFullChain()` re-derives
  every link from the `ArtifactStore` + `KeyRegistry` alone; the
  `PolicySnapshot` hash recorded at issuance supports the replay-time policy
  check (`POLICY_NOT_FOUND` / `VERIFIER_VERSION_MISMATCH`).

## What this does not prove

- No real network effects: connector adapters are latency-realistic stubs.
- Single-process atomicity: ledger atomicity is by synchronous append in one
  process, not a distributed consensus claim.
- Key custody, transport security, and the governance layer's own
  authentication of the human are out of scope, as in the sibling proofs.

## Repo layout

```
src/types.ts       v0.13 canonical types (transcribed from the spec, cited inline)
src/crypto.ts      JCS (RFC 8785) canonicalization, Ed25519, SHA-256/JCS hashing
src/ledger.ts      file-backed hash-chained append-only ledger (JSONL)
src/ledgers.ts     KeyRegistry(isActiveAt) · RevocationLog · UsageLedger ·
                   NonceLog · IdempotencyLog · ArtifactStore (ledger-backed)
src/chain.ts       verifier: 13 token invariants, 16 boundary invariants,
                   8 result invariants, PolicySnapshot, ChainVerificationResult
src/issuance.ts    fail-closed issuance of HumanAuthReceipt / DelegationToken
src/gateway.ts     ConnectorGateway (Agent B) — the wrap around MCP calls
src/connectors.ts  stub adapters: firecrawl_scrape · manage_crm_objects · create_draft
src/harness.ts     shared environment (keys, ledgers, scopes) for demo + tests
src/demo.ts        scripted scenarios → results.md
test/chain.test.ts falsifiable chain verification tests
results.md         scenario outcomes + per-boundary-check latency (generated)
```

## Running

Requires Node ≥ 22.18 (native TypeScript type-stripping; zero dependencies).

```sh
node src/demo.ts            # scenarios 1–2, writes results.md
node --test test/chain.test.ts
```

## Test matrix

| scenario | expected result |
|---|---|
| happy path (scrape → CRM write → email draft) | `valid` ∧ `chainIntact` ∧ `freshnessSatisfied`; full chain re-verifies |
| revoked mid-run | `TOKEN_REVOKED`, `BLOCKED` receipt, `valid:false`, `chainIntact:true` |
| retroactive revocation (replay of an earlier PRE_EFFECT receipt) | `valid:false` + `TOKEN_REVOKED` on re-verification, `chainIntact:true` — revocation asymmetry |
| expired freshness bound / seq regression | `FRESHNESS_VIOLATION`, `freshnessSatisfied:false`, `chainIntact:true` |
| out-of-scope tool call (and out-of-scope operation) | `ACTION_NOT_PERMITTED` / `TARGET_NOT_PERMITTED`, adapter never invoked |
| forged result for a BLOCKED boundary | `putExecutionResultReceipt` **throws** (`RESULT_FOR_BLOCKED_BOUNDARY`), no ledger append; verifier surfaces the same code with `chainIntact:false` |
| token exceeding parent scope at issuance | refused, `SCOPE_EXCEEDS_PARENT` |

`results.md` carries a full ChainVerificationError coverage table marking every
v0.13 code as tested or untested — the suite is explicit about what it does
not yet falsify.

## Swapping in real MCP adapters

Each stub mirrors its real MCP tool's shape. To go live, implement
`ConnectorAdapter` with an actual MCP client call and pass it to
`createEnv()` / the `ConnectorGateway` constructor:

```ts
const hubspot: ConnectorAdapter = {
  connector: "hubspot",
  tool: "manage_crm_objects",
  invoke: (operation, payload) =>
    mcpClient.callTool("manage_crm_objects", { operation, ...payload }),
};
```

Nothing else changes: scope strings, receipts, verification, and the ledger
are adapter-agnostic by construction.

## Spec grounding

Every type and verification decision is grounded in the canonical v0.13.1
spec from the `pfc-delegation-chain` skill (core rules, artifact invariants,
`VerifierConfig`, `ChainVerificationResult`, and the full
`ChainVerificationError` vocabulary), with the governing rule cited in a
comment at each implementation site. One provenance note: the skill's
`references/types.ts` file was absent from the installed skill cache at build
time, so the SKILL.md v0.13 text itself was the canonical source for the
initial build; the two fields whose *placement* the text leaves open
(`verification.policyHash`, `verification.freshnessBound` on
`BoundaryReceipt`) are flagged as such in `src/types.ts`. The skill has since
been repackaged (v0.13.1) with `references/types.ts` sourced from this repo's
`src/types.ts`, and the v0.13.1 clarification codifies this verifier's
`chainIntact` classification of boundary/result consistency violations
(`RESULT_FOR_BLOCKED_BOUNDARY`, `RESULT_WITHOUT_VALID_BOUNDARY`,
`OBSERVED_REQUEST_MISMATCH`) as chain-integrity failures.
