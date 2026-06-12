/**
 * PFC v0.13 canonical types — Connector Gateway proof.
 *
 * Grounding: every type below is transcribed from the pfc-delegation-chain
 * skill (v0.13 SKILL.md): the Four-Artifact Chain, Core Rules, Artifact
 * Invariants, VerifierConfig, ChainVerificationResult, and the
 * ChainVerificationError vocabulary. Nothing here is reconstructed from
 * memory; where the SKILL.md leaves a field's placement open (noted inline),
 * the choice is documented against the rule it serves.
 */

export type Hex = string; // lowercase hex encoding (spec: "Encoding: hex")
export type ISODateTime = string; // RFC 3339 / ISO 8601 UTC timestamp

// ---------------------------------------------------------------------------
// Key registry — "Every key is bound to an owner in KeyRegistry."
// isActiveAt(): registeredAt ≤ T, expiresAt > T, revokedAt undefined or > T.
// ---------------------------------------------------------------------------

export interface KeyRecord {
  keyId: string;
  owner: string; // checked on every artifact (Key ownership core rule)
  publicKeyPem: string; // Ed25519 (spec: "Algorithm: Ed25519")
  registeredAt: ISODateTime;
  expiresAt: ISODateTime;
  revokedAt?: ISODateTime; // key revocation is NON-RETROACTIVE
}

/** Reason isActiveAt() returned false; verifier maps to role-prefixed codes
 *  (KEY_NOT_YET_ACTIVE, *_KEY_EXPIRED, *_KEY_REVOKED). */
export type KeyInactiveReason =
  | "KEY_NOT_YET_ACTIVE"
  | "KEY_EXPIRED"
  | "KEY_REVOKED"
  | "UNKNOWN_KEY";

export interface KeyRegistry {
  get(keyId: string): KeyRecord | undefined;
  /** Core rule: never read key.status directly for historical checks. */
  isActiveAt(
    keyId: string,
    timestamp: ISODateTime,
  ): { active: boolean; reason?: KeyInactiveReason };
}

// ---------------------------------------------------------------------------
// Freshness — boundary invariant 16:
// (verification.verifiedAt − verification.ledgerHead.capturedAt) ≤
// freshnessBound.maxAgeMs; sequenceNumber ≥ last accepted.
// ---------------------------------------------------------------------------

export type RiskClass = "HIGH" | "MEDIUM" | "LOW";

export interface FreshnessBound {
  maxAgeMs: number;
  riskClass: RiskClass;
}

/** Verifier's view of the ledger head at verification time. */
export interface LedgerHeadRef {
  sequenceNumber: number;
  headHash: Hex;
  capturedAt: ISODateTime;
}

// ---------------------------------------------------------------------------
// Artifact 1 — HumanAuthReceipt (signed by governance layer)
// Invariants: isActiveAt(issuerKeyId, issuedAt); maxUses absent when
// usagePolicy === "SINGLE_USE" (else MALFORMED_ARTIFACT);
// authority.issuedAt ≤ issuedAt (else TIMING_VIOLATION);
// issuerKeyId.owner === "governance-layer".
// ---------------------------------------------------------------------------

export type UsagePolicy = "SINGLE_USE" | "MULTI_USE";

export interface HumanAuthReceipt {
  artifactType: "HumanAuthReceipt";
  receiptId: string;
  /** Agent the human authorized; DelegationToken.issuer.agentId must equal it. */
  authorizedAgent: string;
  authority: {
    grantedBy: string; // human principal identifier
    issuedAt: ISODateTime; // must be ≤ receipt issuedAt → TIMING_VIOLATION
  };
  permittedActions: string[]; // superset bounding all delegated scope
  permittedTargets: string[];
  usagePolicy: UsagePolicy;
  maxUses?: number; // MUST be absent when SINGLE_USE → MALFORMED_ARTIFACT
  issuedAt: ISODateTime;
  expiresAt: ISODateTime;
  issuerKeyId: string; // owner must be "governance-layer"
  signature: Hex; // Ed25519 over JCS(body \ signature)
}

// ---------------------------------------------------------------------------
// Artifact 2 — DelegationToken (signed by Agent A) — 13 invariants.
// Tool-scope encoding for the connector gateway:
//   permittedTargets — "connector:tool" (e.g. "hubspot:manage_crm_objects")
//   permittedActions — "tool.operation" (e.g. "manage_crm_objects.create")
// Operation constraints therefore live inside the spec's scope-containment
// checks (invariants 14–15 / ACTION_NOT_PERMITTED, TARGET_NOT_PERMITTED)
// rather than in a side channel the verifier could not see.
// ---------------------------------------------------------------------------

export interface DelegationToken {
  artifactType: "DelegationToken";
  tokenId: string;
  issuer: {
    agentId: string; // must === parent HumanAuthReceipt.authorizedAgent
    keyId: string; // owner must === issuer.agentId
    parentReceiptId: string; // boundary invariant 1 binds root to this
    parentReceiptHash: Hex; // must match stored receipt → PARENT_HASH_MISMATCH
  };
  delegatee: {
    agentId: string; // must === BoundaryReceipt.executingAgent
    keyId: string; // owner must === delegatee.agentId
  };
  permittedActions: string[]; // ⊆ parent → else SCOPE_EXCEEDS_PARENT
  permittedTargets: string[]; // ⊆ parent → else SCOPE_EXCEEDS_PARENT
  /** Risk-classed freshness requirement checked at every boundary (inv. 16). */
  freshnessBound: FreshnessBound;
  issuedAt: ISODateTime; // ≥ parent issuedAt
  expiresAt: ISODateTime; // ≤ parent expiresAt
  signature: Hex;
}

// ---------------------------------------------------------------------------
// Artifact 3 — BoundaryReceipt (signed by Agent B, PRE-EFFECT) — 16 invariants.
// "status fixed at issuance"; status/verification consistency:
//   PRE_EFFECT ⇒ verification.result === "PASS"
//   BLOCKED    ⇒ verification.result === "FAIL"
//   anything else ⇒ MALFORMED_ARTIFACT
// ---------------------------------------------------------------------------

export type BoundaryStatus = "PRE_EFFECT" | "BLOCKED";
export type VerificationOutcome = "PASS" | "FAIL";

export interface BoundaryVerification {
  result: VerificationOutcome;
  verifiedAt: ISODateTime;
  ledgerHead: LedgerHeadRef; // freshness anchor (invariant 16)
  freshnessBound: FreshnessBound; // bound that was applied
  /** PolicySnapshot hash recorded at issuance; checked on replay only
   *  (policyHash core rule). Placement on verification block documented:
   *  SKILL.md specifies the check, not the field's host artifact. */
  policyHash: Hex;
  errors: ChainVerificationErrorCode[]; // empty when result === "PASS"
}

export interface BoundaryReceipt {
  artifactType: "BoundaryReceipt";
  receiptId: string;
  root: { receiptId: string; receiptHash: Hex }; // invariants 1–2
  delegation: { tokenId: string; tokenHash: Hex }; // invariant 3
  executingAgent: string; // invariant 4: === token.delegatee.agentId
  executingAgentKeyId: string; // invariant 5: owner === executingAgent
  requestedAction: string; // invariant 14
  requestedTarget: string; // invariant 15
  payloadHash: Hex; // SHA-256/JCS of the connector-call payload
  nonce: string; // invariant 12: atomic NonceLog.record
  idempotencyKey?: string; // invariant 13
  status: BoundaryStatus;
  verification: BoundaryVerification;
  issuedAt: ISODateTime;
  signature: Hex;
}

// ---------------------------------------------------------------------------
// Artifact 4 — ExecutionResultReceipt (signed by Agent B, POST-EFFECT) —
// 8 invariants.
// ---------------------------------------------------------------------------

export interface ExecutionResultReceipt {
  artifactType: "ExecutionResultReceipt";
  receiptId: string;
  boundaryReceiptId: string; // invariant 1: must resolve, status PRE_EFFECT
  boundaryReceiptHash: Hex; // invariant 8: must match stored receipt
  executingAgent: string; // invariant 2
  executingAgentKeyId: string; // invariants 3–5
  /** invariant 7: must match the boundary receipt exactly
   *  (else OBSERVED_REQUEST_MISMATCH). */
  observedRequest: { action: string; target: string; payloadHash: Hex };
  outcome: "SUCCESS" | "FAILURE";
  resultHash: Hex; // SHA-256/JCS of the connector response
  startedAt: ISODateTime;
  completedAt: ISODateTime; // invariant 6: ≥ boundaryReceipt.issuedAt
  signature: Hex;
}

export type ChainArtifact =
  | HumanAuthReceipt
  | DelegationToken
  | BoundaryReceipt
  | ExecutionResultReceipt;

// ---------------------------------------------------------------------------
// ChainVerificationError vocabulary — transcribed verbatim from v0.13.
// ---------------------------------------------------------------------------

export type ChainVerificationErrorCode =
  // Cryptographic
  | "INVALID_SIGNATURE"
  | "UNKNOWN_KEY"
  // Structural
  | "MALFORMED_ARTIFACT"
  | "CHAIN_INTEGRITY_VIOLATION"
  // Key ownership
  | "KEY_OWNER_MISMATCH"
  // Key lifecycle
  | "ISSUER_KEY_REVOKED"
  | "ISSUER_KEY_EXPIRED"
  | "DELEGATEE_KEY_REVOKED"
  | "DELEGATEE_KEY_EXPIRED"
  | "EXECUTING_AGENT_KEY_REVOKED"
  | "EXECUTING_AGENT_KEY_EXPIRED"
  | "KEY_NOT_YET_ACTIVE"
  // Receipt/token lifecycle
  | "ROOT_RECEIPT_NOT_FOUND"
  | "ROOT_RECEIPT_EXPIRED"
  | "ROOT_RECEIPT_REVOKED"
  | "TOKEN_NOT_FOUND"
  | "TOKEN_EXPIRED"
  | "TOKEN_REVOKED"
  | "USAGE_LIMIT_EXCEEDED"
  // Agent binding
  | "AGENT_MISMATCH"
  // Scope
  | "ACTION_NOT_PERMITTED"
  | "TARGET_NOT_PERMITTED"
  | "SCOPE_EXCEEDS_PARENT"
  // Hash/tamper
  | "PARENT_HASH_MISMATCH"
  | "PAYLOAD_HASH_MISMATCH"
  | "OBSERVED_REQUEST_MISMATCH"
  // Replay
  | "NONCE_ALREADY_SEEN"
  | "IDEMPOTENCY_CONFLICT"
  // Boundary/result
  | "RESULT_WITHOUT_VALID_BOUNDARY"
  | "RESULT_FOR_BLOCKED_BOUNDARY"
  | "TIMING_VIOLATION"
  | "FRESHNESS_VIOLATION"
  // Policy
  | "POLICY_NOT_FOUND"
  | "VERIFIER_VERSION_MISMATCH";

/** Runtime mirror of the full v0.13 vocabulary (single source for the
 *  results.md coverage table — keep in sync with the union above). */
export const CHAIN_VERIFICATION_ERROR_CODES: readonly ChainVerificationErrorCode[] = [
  "INVALID_SIGNATURE", "UNKNOWN_KEY",
  "MALFORMED_ARTIFACT", "CHAIN_INTEGRITY_VIOLATION",
  "KEY_OWNER_MISMATCH",
  "ISSUER_KEY_REVOKED", "ISSUER_KEY_EXPIRED", "DELEGATEE_KEY_REVOKED",
  "DELEGATEE_KEY_EXPIRED", "EXECUTING_AGENT_KEY_REVOKED",
  "EXECUTING_AGENT_KEY_EXPIRED", "KEY_NOT_YET_ACTIVE",
  "ROOT_RECEIPT_NOT_FOUND", "ROOT_RECEIPT_EXPIRED", "ROOT_RECEIPT_REVOKED",
  "TOKEN_NOT_FOUND", "TOKEN_EXPIRED", "TOKEN_REVOKED", "USAGE_LIMIT_EXCEEDED",
  "AGENT_MISMATCH",
  "ACTION_NOT_PERMITTED", "TARGET_NOT_PERMITTED", "SCOPE_EXCEEDS_PARENT",
  "PARENT_HASH_MISMATCH", "PAYLOAD_HASH_MISMATCH", "OBSERVED_REQUEST_MISMATCH",
  "NONCE_ALREADY_SEEN", "IDEMPOTENCY_CONFLICT",
  "RESULT_WITHOUT_VALID_BOUNDARY", "RESULT_FOR_BLOCKED_BOUNDARY",
  "TIMING_VIOLATION", "FRESHNESS_VIOLATION",
  "POLICY_NOT_FOUND", "VERIFIER_VERSION_MISMATCH",
];

export interface ChainVerificationError {
  code: ChainVerificationErrorCode;
  message: string;
  artifactId?: string;
}

// ---------------------------------------------------------------------------
// ChainVerificationResult — verbatim semantics from v0.13:
//   valid          — authorized and may proceed
//   chainIntact    — crypto sound + hash bindings hold + artifacts resolvable;
//                    EXCLUDES scope, expiry, revocation, nonce, authorization
//                    outcome. Distinguishes "correctly blocked" from
//                    "cryptographically broken."
//   freshnessSatisfied — ledger view within declared freshness bound and no
//                    sequenceNumber regression (rollback detection). A chain
//                    can be intact and valid:false on freshness alone.
//   errors         — always present, empty on success.
// ---------------------------------------------------------------------------

export interface ChainVerificationResult {
  valid: boolean;
  chainIntact: boolean;
  freshnessSatisfied: boolean;
  chain?: {
    humanAuthReceipt?: HumanAuthReceipt;
    delegationToken?: DelegationToken;
    boundaryReceipt?: BoundaryReceipt;
    executionResultReceipt?: ExecutionResultReceipt;
  };
  errors: ChainVerificationError[];
}

// ---------------------------------------------------------------------------
// Ledgers — "Mutable state lives in ledgers only." Atomicity requirements
// per v0.13 Ledger Atomicity Requirements section.
// ---------------------------------------------------------------------------

export interface RevocationEntry {
  artifactId: string;
  revokedAt: ISODateTime;
  reason: string;
  revokedBy: string;
}

/** Artifact revocation is RETROACTIVE — invalidates all downstream chains
 *  regardless of issuance time (Revocation asymmetry core rule). */
export interface RevocationLog {
  revoke(entry: RevocationEntry): void;
  isRevoked(artifactId: string): RevocationEntry | undefined;
}

export interface UsageLedger {
  /** Atomic check-and-increment; pass maxUses: 1 for SINGLE_USE receipts.
   *  Returns false when the limit would be exceeded. */
  record(receiptId: string, maxUses: number | undefined): boolean;
  /** Diagnostic only — never use for the atomic check. */
  countFor(receiptId: string): number;
}

export interface NonceLog {
  /** Atomic check-and-insert; false if nonce already seen.
   *  Skip on idempotent retry. */
  record(nonce: string, seenAt: ISODateTime): boolean;
}

export type IdempotencyOutcome = "NEW" | "SAFE_RETRY" | "CONFLICT";

export interface IdempotencyLog {
  /** Atomic check-and-insert. Same key + same payload = safe retry;
   *  same key + different payload = IDEMPOTENCY_CONFLICT. */
  record(key: string, payloadHash: Hex): IdempotencyOutcome;
}

/** Append-only; put* must throw on failure (fail-closed core rule). */
export interface ArtifactStore {
  putHumanAuthReceipt(r: HumanAuthReceipt): void;
  putDelegationToken(t: DelegationToken): void;
  putBoundaryReceipt(r: BoundaryReceipt): void;
  putExecutionResultReceipt(r: ExecutionResultReceipt): void;
  getHumanAuthReceipt(id: string): HumanAuthReceipt | undefined;
  getDelegationToken(id: string): DelegationToken | undefined;
  getBoundaryReceipt(id: string): BoundaryReceipt | undefined;
  getExecutionResultReceipt(id: string): ExecutionResultReceipt | undefined;
  /** SHA-256/JCS hash of the stored (signed) artifact. */
  getHash(id: string): Hex | undefined;
}

// ---------------------------------------------------------------------------
// VerifierConfig — verbatim shape from v0.13.
// ---------------------------------------------------------------------------

export interface VerifierConfig {
  version: string;
  clockSkewToleranceMs: number; // recommended: 5000
  keyRegistry: KeyRegistry;
  revocationLog: RevocationLog;
  nonceLog: NonceLog;
  usageLedger: UsageLedger;
  artifactStore: ArtifactStore;
  idempotencyLog: IdempotencyLog;
  clockSource?: "roughtime" | "ntp-trusted" | "sequence-only";
  freshnessDefaults?: {
    HIGH: FreshnessBound;
    MEDIUM: FreshnessBound;
    LOW: FreshnessBound;
  };
}

// ---------------------------------------------------------------------------
// PolicySnapshot — per-chain, from DelegationToken.permittedActions/Targets
// (sorted), VerifierConfig.version, VerifierConfig.clockSkewToleranceMs,
// HumanAuthReceipt.receiptId, DelegationToken.tokenId.
// Hash = SHA-256/JCS of JCS-canonicalized PolicySnapshot.
// ---------------------------------------------------------------------------

export interface PolicySnapshot {
  permittedActions: string[]; // sorted
  permittedTargets: string[]; // sorted
  verifierVersion: string;
  clockSkewToleranceMs: number;
  rootReceiptId: string;
  tokenId: string;
}

// ---------------------------------------------------------------------------
// Gateway-facing call shape (this repo's contribution — not a chain artifact).
// Maps an MCP connector call onto the spec's action/target scope model.
// ---------------------------------------------------------------------------

export interface ConnectorCall {
  connector: string; // e.g. "hubspot"
  tool: string; // e.g. "manage_crm_objects"
  operation: string; // e.g. "create"
  payload: unknown; // tool arguments — hashed into payloadHash
  idempotencyKey?: string;
}

export const callAction = (c: ConnectorCall): string =>
  `${c.tool}.${c.operation}`;
export const callTarget = (c: ConnectorCall): string =>
  `${c.connector}:${c.tool}`;
