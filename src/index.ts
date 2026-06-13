/**
 * Public package entry point — packaging only, no behavioral changes.
 *
 * Surface (v0.3.0): the issue-and-verify contract an external consumer needs,
 * and no more. Crypto primitives and the verifier's internal sub-functions
 * stay in their source modules but are deliberately NOT re-exported — an
 * infrastructure package should expose the entry points, not its internals.
 *
 *   - All v0.13 types (types.ts), including the runtime
 *     CHAIN_VERIFICATION_ERROR_CODES vocabulary and the connector-call
 *     mapping helpers (callAction / callTarget).
 *   - The chain verifier entry points: verifyFullChain, also re-exported
 *     under the spec-facing name verifyChain.
 *   - The chain-issuance builders: issueHumanAuthReceipt, issueDelegationToken,
 *     and the ConnectorGateway (which issues BoundaryReceipt +
 *     ExecutionResultReceipt at the boundary).
 *   - The harness builders: key-pair generation, the in-memory KeyRegistry,
 *     the four mutable-state ledgers, the append-only ArtifactStore, the
 *     file-backed hash-chained ledger, the stub connector adapters, and the
 *     createEnv / authorizeWorkflow convenience builders.
 *   - Minimal crypto helpers a consumer needs when building artifacts:
 *     newId and nowIso only.
 *
 * This lets an external consumer both *issue* and *verify* a full delegation
 * chain from the public package alone, without reaching into internal module
 * paths. No source logic changed — these are re-exports only; verifier
 * behavior is unchanged.
 */

// --- v0.13 types + runtime vocabulary + connector-call helpers --------------
export * from "./types.ts";

// --- Chain verifier entry points --------------------------------------------
export { verifyFullChain, verifyFullChain as verifyChain } from "./chain.ts";

// --- Key-pair generation + minimal crypto helpers (IDs / timestamps) --------
export { generateEd25519Key, newId, nowIso } from "./crypto.ts";

// --- Chain-issuance builders (HumanAuthReceipt, DelegationToken) -------------
export { issueHumanAuthReceipt, issueDelegationToken } from "./issuance.ts";
export type { ToolScope } from "./issuance.ts";

// --- Connector gateway (issues BoundaryReceipt + ExecutionResultReceipt) ----
export { ConnectorGateway } from "./gateway.ts";
export type {
  ConnectorAdapter,
  GatewayExecution,
  GatewayRefusal,
  GatewayOutcome,
  BoundaryCheckMetric,
} from "./gateway.ts";

// --- File-backed, hash-chained, append-only ledger --------------------------
export { FileLedger } from "./ledger.ts";
export type { LedgerEntry, LedgerEntryKind } from "./ledger.ts";

// --- KeyRegistry, mutable-state ledgers, ArtifactStore ----------------------
export {
  InMemoryKeyRegistry,
  LedgerBackedRevocationLog,
  InMemoryUsageLedger,
  InMemoryNonceLog,
  InMemoryIdempotencyLog,
  LedgerBackedArtifactStore,
} from "./ledgers.ts";

// --- Stub connector adapters ------------------------------------------------
export {
  defaultStubs,
  FirecrawlScrapeStub,
  HubSpotCrmStub,
  GmailDraftStub,
} from "./connectors.ts";
export type { StubOptions } from "./connectors.ts";

// --- Convenience environment harness (keys + config + gateway, workflow) ----
export {
  createEnv,
  authorizeWorkflow,
  FRESHNESS_DEFAULTS,
  WORKFLOW_SCOPE,
  GOVERNANCE,
  AGENT_A,
  AGENT_B,
  VERIFIER_VERSION,
} from "./harness.ts";
export type { Env } from "./harness.ts";
