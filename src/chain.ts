/**
 * PFC v0.13 chain verifier.
 *
 * Implements the boundary pre-effect check (16 invariants, hash checks
 * before content checks), HumanAuthReceipt verification, DelegationToken
 * issuance verification (13 invariants), and ExecutionResultReceipt
 * verification (8 invariants).
 *
 * ChainVerificationResult semantics (v0.13):
 *   chainIntact excludes scope, expiry, revocation, nonce, and authorization
 *   outcome — only crypto soundness + hash bindings + artifact resolution.
 *   freshnessSatisfied is false on a stale ledger view or sequenceNumber
 *   regression. valid is true only when errors is empty.
 */
import {
  canonicalize,
  hashArtifact,
  sha256Hex,
  verifyArtifactSignature,
} from "./crypto.ts";
import type {
  BoundaryReceipt,
  ChainVerificationError,
  ChainVerificationErrorCode,
  ChainVerificationResult,
  ConnectorCall,
  DelegationToken,
  ExecutionResultReceipt,
  FreshnessBound,
  Hex,
  HumanAuthReceipt,
  ISODateTime,
  LedgerHeadRef,
  PolicySnapshot,
  VerifierConfig,
} from "./types.ts";
import { callAction, callTarget } from "./types.ts";

// ---------------------------------------------------------------------------
// chainIntact classification.
// Per v0.13: "chainIntact excludes scope, expiry, revocation, nonce, and
// authorization outcome — only crypto + structural resolution." Codes below
// are precisely those that mean the chain is cryptographically or
// structurally broken (signatures, key/agent bindings, hash bindings,
// unresolvable artifacts, malformed artifacts).
// ---------------------------------------------------------------------------
const INTACT_BREAKING = new Set<ChainVerificationErrorCode>([
  "INVALID_SIGNATURE",
  "UNKNOWN_KEY",
  "MALFORMED_ARTIFACT",
  "CHAIN_INTEGRITY_VIOLATION",
  "KEY_OWNER_MISMATCH",
  "AGENT_MISMATCH",
  "ROOT_RECEIPT_NOT_FOUND",
  "TOKEN_NOT_FOUND",
  "PARENT_HASH_MISMATCH",
  "PAYLOAD_HASH_MISMATCH",
  "OBSERVED_REQUEST_MISMATCH",
  "RESULT_WITHOUT_VALID_BOUNDARY",
  "RESULT_FOR_BLOCKED_BOUNDARY",
]);

export function toResult(
  errors: ChainVerificationError[],
  chain?: ChainVerificationResult["chain"],
): ChainVerificationResult {
  return {
    valid: errors.length === 0,
    chainIntact: !errors.some((e) => INTACT_BREAKING.has(e.code)),
    freshnessSatisfied: !errors.some((e) => e.code === "FRESHNESS_VIOLATION"),
    ...(chain ? { chain } : {}),
    errors,
  };
}

function err(
  code: ChainVerificationErrorCode,
  message: string,
  artifactId?: string,
): ChainVerificationError {
  return { code, message, ...(artifactId ? { artifactId } : {}) };
}

const ms = (t: ISODateTime) => Date.parse(t);

/** Map an isActiveAt() failure to the role-prefixed v0.13 error code. */
function keyLifecycleError(
  cfg: VerifierConfig,
  keyId: string,
  at: ISODateTime,
  role: "ISSUER" | "DELEGATEE" | "EXECUTING_AGENT",
  artifactId: string,
): ChainVerificationError | undefined {
  const { active, reason } = cfg.keyRegistry.isActiveAt(keyId, at);
  if (active) return undefined;
  switch (reason) {
    case "UNKNOWN_KEY":
      return err("UNKNOWN_KEY", `key ${keyId} not in KeyRegistry`, artifactId);
    case "KEY_NOT_YET_ACTIVE":
      return err("KEY_NOT_YET_ACTIVE", `key ${keyId} not yet active at ${at}`, artifactId);
    case "KEY_EXPIRED":
      return err(`${role}_KEY_EXPIRED` as ChainVerificationErrorCode, `key ${keyId} expired at ${at}`, artifactId);
    case "KEY_REVOKED":
      return err(`${role}_KEY_REVOKED` as ChainVerificationErrorCode, `key ${keyId} revoked at ${at}`, artifactId);
    default:
      return err("UNKNOWN_KEY", `key ${keyId} inactive for unknown reason`, artifactId);
  }
}

function checkSignature(
  cfg: VerifierConfig,
  artifact: Record<string, unknown> & { signature: string },
  keyId: string,
  expectedOwner: string,
  artifactId: string,
): ChainVerificationError[] {
  const errors: ChainVerificationError[] = [];
  const key = cfg.keyRegistry.get(keyId);
  if (!key) {
    errors.push(err("UNKNOWN_KEY", `key ${keyId} not in KeyRegistry`, artifactId));
    return errors;
  }
  if (key.owner !== expectedOwner) {
    errors.push(
      err("KEY_OWNER_MISMATCH", `key ${keyId} owned by ${key.owner}, expected ${expectedOwner}`, artifactId),
    );
  }
  if (!verifyArtifactSignature(artifact, key.publicKeyPem)) {
    errors.push(err("INVALID_SIGNATURE", `signature check failed for ${artifactId}`, artifactId));
  }
  return errors;
}

// ---------------------------------------------------------------------------
// PolicySnapshot — per v0.13 PolicySnapshot Construction section.
// ---------------------------------------------------------------------------

export function buildPolicySnapshot(
  token: DelegationToken,
  cfg: VerifierConfig,
): PolicySnapshot {
  return {
    permittedActions: [...token.permittedActions].sort(),
    permittedTargets: [...token.permittedTargets].sort(),
    verifierVersion: cfg.version,
    clockSkewToleranceMs: cfg.clockSkewToleranceMs,
    rootReceiptId: token.issuer.parentReceiptId,
    tokenId: token.tokenId,
  };
}

export function policySnapshotHash(snapshot: PolicySnapshot): Hex {
  return sha256Hex(canonicalize(snapshot)); // SHA-256/JCS per spec
}

// ---------------------------------------------------------------------------
// HumanAuthReceipt verification.
// ---------------------------------------------------------------------------

export function verifyHumanAuthReceipt(
  receipt: HumanAuthReceipt,
  cfg: VerifierConfig,
): ChainVerificationError[] {
  const errors: ChainVerificationError[] = [];
  const id = receipt.receiptId;

  // Governance-layer signature + ownership.
  const key = cfg.keyRegistry.get(receipt.issuerKeyId);
  if (!key) {
    errors.push(err("UNKNOWN_KEY", `issuer key ${receipt.issuerKeyId} unknown`, id));
  } else {
    if (key.owner !== "governance-layer") {
      errors.push(err("KEY_OWNER_MISMATCH", `issuerKeyId.owner must be "governance-layer", got ${key.owner}`, id));
    }
    if (!verifyArtifactSignature(receipt as unknown as Record<string, unknown> & { signature: string }, key.publicKeyPem)) {
      errors.push(err("INVALID_SIGNATURE", "HumanAuthReceipt signature invalid", id));
    }
  }

  // isActiveAt(issuerKeyId, issuedAt).
  const kerr = keyLifecycleError(cfg, receipt.issuerKeyId, receipt.issuedAt, "ISSUER", id);
  if (kerr && kerr.code !== "UNKNOWN_KEY") errors.push(kerr);

  // maxUses must be absent when SINGLE_USE → MALFORMED_ARTIFACT.
  if (receipt.usagePolicy === "SINGLE_USE" && receipt.maxUses !== undefined) {
    errors.push(err("MALFORMED_ARTIFACT", "maxUses must be absent when usagePolicy is SINGLE_USE", id));
  }

  // authority.issuedAt ≤ issuedAt → TIMING_VIOLATION.
  if (ms(receipt.authority.issuedAt) > ms(receipt.issuedAt) + cfg.clockSkewToleranceMs) {
    errors.push(err("TIMING_VIOLATION", "authority.issuedAt is after receipt issuedAt", id));
  }

  return errors;
}

// ---------------------------------------------------------------------------
// DelegationToken issuance verification — 13 invariants.
// Called by the issuing agent BEFORE the token is stored (fail-closed) and
// re-runnable by any later verifier.
// ---------------------------------------------------------------------------

export function verifyDelegationToken(
  token: DelegationToken,
  cfg: VerifierConfig,
  opts: { consumeUsage?: boolean } = {},
): ChainVerificationResult {
  const errors: ChainVerificationError[] = [];
  const id = token.tokenId;

  // Resolve parent receipt — hash checks before content checks.
  const parent = cfg.artifactStore.getHumanAuthReceipt(token.issuer.parentReceiptId);
  if (!parent) {
    errors.push(err("ROOT_RECEIPT_NOT_FOUND", `parent receipt ${token.issuer.parentReceiptId} unresolvable`, id));
    return toResult(errors, { delegationToken: token });
  }
  if (cfg.artifactStore.getHash(parent.receiptId) !== token.issuer.parentReceiptHash) {
    errors.push(err("PARENT_HASH_MISMATCH", "issuer.parentReceiptHash does not match stored receipt", id));
    return toResult(errors, { delegationToken: token, humanAuthReceipt: parent });
  }

  // Parent receipt itself must verify.
  errors.push(...verifyHumanAuthReceipt(parent, cfg));

  // Token signature by issuer key; ownership both sides.
  errors.push(
    ...checkSignature(
      cfg,
      token as unknown as Record<string, unknown> & { signature: string },
      token.issuer.keyId,
      token.issuer.agentId,
      id,
    ),
  );
  const delegateeKey = cfg.keyRegistry.get(token.delegatee.keyId);
  if (!delegateeKey) {
    errors.push(err("UNKNOWN_KEY", `delegatee key ${token.delegatee.keyId} unknown`, id));
  } else if (delegateeKey.owner !== token.delegatee.agentId) {
    errors.push(err("KEY_OWNER_MISMATCH", "delegatee.keyId.owner !== delegatee.agentId", id));
  }

  // Agent binding: issuer.agentId === parent.authorizedAgent.
  if (token.issuer.agentId !== parent.authorizedAgent) {
    errors.push(err("AGENT_MISMATCH", `issuer ${token.issuer.agentId} is not the authorized agent ${parent.authorizedAgent}`, id));
  }

  // Scope containment: permittedActions/Targets ⊆ parent.
  for (const a of token.permittedActions) {
    if (!parent.permittedActions.includes(a)) {
      errors.push(err("SCOPE_EXCEEDS_PARENT", `action "${a}" not in parent scope`, id));
    }
  }
  for (const t of token.permittedTargets) {
    if (!parent.permittedTargets.includes(t)) {
      errors.push(err("SCOPE_EXCEEDS_PARENT", `target "${t}" not in parent scope`, id));
    }
  }

  // Temporal containment.
  if (ms(token.expiresAt) > ms(parent.expiresAt)) {
    errors.push(err("TIMING_VIOLATION", "token.expiresAt exceeds parent expiresAt", id));
  }
  if (ms(token.issuedAt) + cfg.clockSkewToleranceMs < ms(parent.issuedAt)) {
    errors.push(err("TIMING_VIOLATION", "token.issuedAt precedes parent issuedAt", id));
  }

  // Parent not expired / revoked at token issuance.
  if (ms(parent.expiresAt) <= ms(token.issuedAt)) {
    errors.push(err("ROOT_RECEIPT_EXPIRED", "parent receipt expired at token issuance", id));
  }
  if (cfg.revocationLog.isRevoked(parent.receiptId)) {
    errors.push(err("ROOT_RECEIPT_REVOKED", "parent receipt revoked", id)); // retroactive
  }

  // Key lifecycle at token issuance.
  const issuerKeyErr = keyLifecycleError(cfg, token.issuer.keyId, token.issuedAt, "ISSUER", id);
  if (issuerKeyErr) errors.push(issuerKeyErr);
  const delegateeKeyErr = keyLifecycleError(cfg, token.delegatee.keyId, token.issuedAt, "DELEGATEE", id);
  if (delegateeKeyErr) errors.push(delegateeKeyErr);

  // Usage within limits — atomic UsageLedger.record(); only consume when the
  // caller is actually issuing (not on replay verification).
  if (opts.consumeUsage) {
    const maxUses = parent.usagePolicy === "SINGLE_USE" ? 1 : parent.maxUses;
    if (!cfg.usageLedger.record(parent.receiptId, maxUses)) {
      errors.push(err("USAGE_LIMIT_EXCEEDED", `usage limit reached for ${parent.receiptId}`, id));
    }
  }

  // De-duplicate identical codes from overlapping checks.
  const seen = new Set<string>();
  const deduped = errors.filter((e) => {
    const k = e.code + "|" + e.message;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return toResult(deduped, { delegationToken: token, humanAuthReceipt: parent });
}

// ---------------------------------------------------------------------------
// Boundary pre-effect check — the 16 BoundaryReceipt invariants, run by the
// gateway BEFORE any side effect, in spec order (hash checks before content
// checks). The outcome is frozen into the BoundaryReceipt at issuance.
// ---------------------------------------------------------------------------

export interface PreEffectContext {
  token: DelegationToken;
  call: ConnectorCall;
  payloadHash: Hex;
  executingAgent: string;
  executingAgentKeyId: string;
  nonce: string;
  issuedAt: ISODateTime; // intended BoundaryReceipt.issuedAt
  verifiedAt: ISODateTime;
  ledgerHead: LedgerHeadRef;
  /** Highest ledger sequenceNumber this verifier has previously accepted —
   *  regression means rollback attack → FRESHNESS_VIOLATION. */
  lastAcceptedSequenceNumber: number;
}

export function preEffectCheck(
  ctx: PreEffectContext,
  cfg: VerifierConfig,
): ChainVerificationResult {
  const errors: ChainVerificationError[] = [];
  const { token, call } = ctx;
  const requestedAction = callAction(call);
  const requestedTarget = callTarget(call);

  // --- Structural resolution / hash bindings (invariants 1–3) ---
  const root = cfg.artifactStore.getHumanAuthReceipt(token.issuer.parentReceiptId);
  if (!root) {
    errors.push(err("ROOT_RECEIPT_NOT_FOUND", `root ${token.issuer.parentReceiptId} unresolvable`));
    return toResult(errors, { delegationToken: token });
  }
  // Invariant 1 — root.receiptId === token.issuer.parentReceiptId. The
  // gateway constructs root from the token, so a mismatch here means a
  // tampered binding on a stored receipt → CHAIN_INTEGRITY_VIOLATION.
  if (root.receiptId !== token.issuer.parentReceiptId) {
    errors.push(err("CHAIN_INTEGRITY_VIOLATION", "root.receiptId does not match token.issuer.parentReceiptId"));
  }
  // Invariant 2 — root.receiptHash matches stored HumanAuthReceipt.
  if (cfg.artifactStore.getHash(root.receiptId) !== token.issuer.parentReceiptHash) {
    errors.push(err("PARENT_HASH_MISMATCH", "stored root hash differs from token.issuer.parentReceiptHash"));
    return toResult(errors, { delegationToken: token, humanAuthReceipt: root });
  }
  // Invariant 3 — delegation.tokenHash matches stored DelegationToken.
  const storedToken = cfg.artifactStore.getDelegationToken(token.tokenId);
  if (!storedToken) {
    errors.push(err("TOKEN_NOT_FOUND", `token ${token.tokenId} not in ArtifactStore`));
    return toResult(errors, { delegationToken: token, humanAuthReceipt: root });
  }
  if (cfg.artifactStore.getHash(token.tokenId) !== hashArtifact(token)) {
    errors.push(err("PARENT_HASH_MISMATCH", "presented token differs from stored token"));
    return toResult(errors, { delegationToken: token, humanAuthReceipt: root });
  }

  // Crypto soundness of upstream artifacts.
  errors.push(...verifyHumanAuthReceipt(root, cfg));
  errors.push(
    ...checkSignature(
      cfg,
      token as unknown as Record<string, unknown> & { signature: string },
      token.issuer.keyId,
      token.issuer.agentId,
      token.tokenId,
    ),
  );

  // --- Invariant 4 — delegatee.agentId === executingAgent ---
  if (token.delegatee.agentId !== ctx.executingAgent) {
    errors.push(err("AGENT_MISMATCH", `token delegates to ${token.delegatee.agentId}, executing agent is ${ctx.executingAgent}`));
  }

  // --- Invariant 5 — executingAgentKeyId.owner === executingAgent ---
  const execKey = cfg.keyRegistry.get(ctx.executingAgentKeyId);
  if (!execKey) {
    errors.push(err("UNKNOWN_KEY", `executing agent key ${ctx.executingAgentKeyId} unknown`));
  } else if (execKey.owner !== ctx.executingAgent) {
    errors.push(err("KEY_OWNER_MISMATCH", "executingAgentKeyId.owner !== executingAgent"));
  }

  // --- Invariant 6 — isActiveAt(executingAgentKeyId, issuedAt) ---
  const execKeyErr = keyLifecycleError(cfg, ctx.executingAgentKeyId, ctx.issuedAt, "EXECUTING_AGENT", token.tokenId);
  if (execKeyErr && execKeyErr.code !== "UNKNOWN_KEY") errors.push(execKeyErr);

  // --- Invariants 7–11 — timing, token/root expiry + revocation ---
  if (ms(ctx.issuedAt) + cfg.clockSkewToleranceMs < ms(token.issuedAt)) {
    errors.push(err("TIMING_VIOLATION", "boundary issuedAt precedes token issuedAt"));
  }
  if (ms(token.expiresAt) <= ms(ctx.issuedAt)) {
    errors.push(err("TOKEN_EXPIRED", `token expired at ${token.expiresAt}`));
  }
  if (cfg.revocationLog.isRevoked(token.tokenId)) {
    errors.push(err("TOKEN_REVOKED", `token ${token.tokenId} revoked`, token.tokenId)); // retroactive
  }
  if (ms(root.expiresAt) <= ms(ctx.issuedAt)) {
    errors.push(err("ROOT_RECEIPT_EXPIRED", `root receipt expired at ${root.expiresAt}`));
  }
  if (cfg.revocationLog.isRevoked(root.receiptId)) {
    errors.push(err("ROOT_RECEIPT_REVOKED", `root receipt ${root.receiptId} revoked`, root.receiptId));
  }

  // --- Invariants 12–13 — nonce + idempotency (atomic; nonce skipped on
  // idempotent safe retry per spec) ---
  let idempotency: "NEW" | "SAFE_RETRY" | "CONFLICT" = "NEW";
  if (ctx.call.idempotencyKey !== undefined) {
    idempotency = cfg.idempotencyLog.record(ctx.call.idempotencyKey, ctx.payloadHash);
    if (idempotency === "CONFLICT") {
      errors.push(err("IDEMPOTENCY_CONFLICT", `idempotency key ${ctx.call.idempotencyKey} reused with different payload`));
    }
  }
  if (idempotency !== "SAFE_RETRY") {
    if (!cfg.nonceLog.record(ctx.nonce, ctx.verifiedAt)) {
      errors.push(err("NONCE_ALREADY_SEEN", `nonce ${ctx.nonce} replayed`));
    }
  }

  // --- Invariants 14–15 — scope (action/target within permitted) ---
  if (!token.permittedActions.includes(requestedAction)) {
    errors.push(err("ACTION_NOT_PERMITTED", `action "${requestedAction}" not in token scope`));
  }
  if (!token.permittedTargets.includes(requestedTarget)) {
    errors.push(err("TARGET_NOT_PERMITTED", `target "${requestedTarget}" not in token scope`));
  }

  // --- Invariant 16 — freshness ---
  const age = ms(ctx.verifiedAt) - ms(ctx.ledgerHead.capturedAt);
  if (age > token.freshnessBound.maxAgeMs) {
    errors.push(
      err(
        "FRESHNESS_VIOLATION",
        `ledger head is ${age}ms old; ${token.freshnessBound.riskClass} bound is ${token.freshnessBound.maxAgeMs}ms`,
      ),
    );
  }
  if (ctx.ledgerHead.sequenceNumber < ctx.lastAcceptedSequenceNumber) {
    errors.push(
      err(
        "FRESHNESS_VIOLATION",
        `ledger sequenceNumber regressed (${ctx.ledgerHead.sequenceNumber} < ${ctx.lastAcceptedSequenceNumber}) — possible rollback`,
      ),
    );
  }

  const seen = new Set<string>();
  const deduped = errors.filter((e) => {
    const k = e.code + "|" + e.message;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return toResult(deduped, { delegationToken: token, humanAuthReceipt: root });
}

// ---------------------------------------------------------------------------
// Stored BoundaryReceipt verification (independent verifier / replay path).
// Includes the status-consistency rule and the policyHash replay check
// (POLICY_NOT_FOUND / VERIFIER_VERSION_MISMATCH).
// ---------------------------------------------------------------------------

export function verifyBoundaryReceipt(
  receipt: BoundaryReceipt,
  cfg: VerifierConfig,
): ChainVerificationResult {
  const errors: ChainVerificationError[] = [];
  const id = receipt.receiptId;

  // Signature + ownership + key lifecycle (invariants 5–6).
  errors.push(
    ...checkSignature(
      cfg,
      receipt as unknown as Record<string, unknown> & { signature: string },
      receipt.executingAgentKeyId,
      receipt.executingAgent,
      id,
    ),
  );
  const kerr = keyLifecycleError(cfg, receipt.executingAgentKeyId, receipt.issuedAt, "EXECUTING_AGENT", id);
  if (kerr && kerr.code !== "UNKNOWN_KEY") errors.push(kerr);

  // Boundary status consistency core rule.
  const consistent =
    (receipt.status === "PRE_EFFECT" && receipt.verification.result === "PASS") ||
    (receipt.status === "BLOCKED" && receipt.verification.result === "FAIL");
  if (!consistent) {
    errors.push(err("MALFORMED_ARTIFACT", `status ${receipt.status} inconsistent with verification.result ${receipt.verification.result}`, id));
  }

  // Hash bindings (invariants 1–3).
  const token = cfg.artifactStore.getDelegationToken(receipt.delegation.tokenId);
  if (!token) {
    errors.push(err("TOKEN_NOT_FOUND", `token ${receipt.delegation.tokenId} unresolvable`, id));
    return toResult(errors, { boundaryReceipt: receipt });
  }
  if (cfg.artifactStore.getHash(token.tokenId) !== receipt.delegation.tokenHash) {
    errors.push(err("PARENT_HASH_MISMATCH", "delegation.tokenHash mismatch", id));
  }
  if (receipt.root.receiptId !== token.issuer.parentReceiptId) {
    errors.push(err("CHAIN_INTEGRITY_VIOLATION", "root.receiptId !== token.issuer.parentReceiptId", id));
  }
  const root = cfg.artifactStore.getHumanAuthReceipt(receipt.root.receiptId);
  if (!root) {
    errors.push(err("ROOT_RECEIPT_NOT_FOUND", `root ${receipt.root.receiptId} unresolvable`, id));
  } else if (cfg.artifactStore.getHash(root.receiptId) !== receipt.root.receiptHash) {
    errors.push(err("PARENT_HASH_MISMATCH", "root.receiptHash mismatch", id));
  }

  // Invariant 4 — agent binding.
  if (token.delegatee.agentId !== receipt.executingAgent) {
    errors.push(err("AGENT_MISMATCH", "token.delegatee.agentId !== executingAgent", id));
  }

  // Revocation asymmetry core rule: artifact revocation is RETROACTIVE —
  // it invalidates all downstream chains regardless of issuance time. A
  // receipt that was PRE_EFFECT when issued therefore verifies valid:false
  // after its token (or root) is revoked, while chainIntact stays true:
  // revocation is an authorization outcome, not a cryptographic break.
  if (cfg.revocationLog.isRevoked(token.tokenId)) {
    errors.push(err("TOKEN_REVOKED", `token ${token.tokenId} revoked (retroactive)`, id));
  }
  if (root && cfg.revocationLog.isRevoked(root.receiptId)) {
    errors.push(err("ROOT_RECEIPT_REVOKED", `root receipt ${root.receiptId} revoked (retroactive)`, id));
  }

  // policyHash — checked on replay only (v0.13 core rule): reconstruct
  // PolicySnapshot from chain + VerifierConfig and compare hashes.
  // Any other mismatch or unresolvable snapshot → POLICY_NOT_FOUND;
  // checkPolicyOnReplay() discriminates VERIFIER_VERSION_MISMATCH when the
  // recorded verifier version is known.
  const expectedHash = policySnapshotHash(buildPolicySnapshot(token, cfg));
  if (expectedHash !== receipt.verification.policyHash) {
    errors.push(
      err(
        "POLICY_NOT_FOUND",
        "reconstructed PolicySnapshot hash does not match receipt.verification.policyHash",
        id,
      ),
    );
  }

  const result = toResult(errors, {
    boundaryReceipt: receipt,
    delegationToken: token,
    ...(root ? { humanAuthReceipt: root } : {}),
  });
  return result;
}

/** Replay-time policy check with explicit verifier-version discrimination:
 *  if the snapshot matches under the receipt's recorded version but not the
 *  current one → VERIFIER_VERSION_MISMATCH (v0.13 policyHash rule). */
export function checkPolicyOnReplay(
  receipt: BoundaryReceipt,
  token: DelegationToken,
  cfg: VerifierConfig,
  recordedVerifierVersion: string,
): ChainVerificationError | undefined {
  const current = policySnapshotHash(buildPolicySnapshot(token, cfg));
  if (current === receipt.verification.policyHash) return undefined;
  const underRecorded = policySnapshotHash({
    ...buildPolicySnapshot(token, cfg),
    verifierVersion: recordedVerifierVersion,
  });
  if (underRecorded === receipt.verification.policyHash) {
    return err("VERIFIER_VERSION_MISMATCH", `policy matches under verifier ${recordedVerifierVersion}, not ${cfg.version}`, receipt.receiptId);
  }
  return err("POLICY_NOT_FOUND", "policy snapshot unresolvable under any known verifier version", receipt.receiptId);
}

// ---------------------------------------------------------------------------
// ExecutionResultReceipt verification — 8 invariants.
// ---------------------------------------------------------------------------

export function verifyExecutionResultReceipt(
  result: ExecutionResultReceipt,
  cfg: VerifierConfig,
): ChainVerificationResult {
  const errors: ChainVerificationError[] = [];
  const id = result.receiptId;

  // Invariant 1 — boundary resolves with status PRE_EFFECT / result PASS.
  const boundary = cfg.artifactStore.getBoundaryReceipt(result.boundaryReceiptId);
  if (!boundary) {
    errors.push(err("RESULT_WITHOUT_VALID_BOUNDARY", `boundary ${result.boundaryReceiptId} unresolvable`, id));
    return toResult(errors, { executionResultReceipt: result });
  }
  if (boundary.status === "BLOCKED") {
    errors.push(err("RESULT_FOR_BLOCKED_BOUNDARY", "execution result issued for a BLOCKED boundary", id));
  } else if (boundary.status !== "PRE_EFFECT" || boundary.verification.result !== "PASS") {
    errors.push(err("RESULT_WITHOUT_VALID_BOUNDARY", "boundary is not a passing PRE_EFFECT receipt", id));
  }

  // Invariants 2–3 — executingAgent / key match the boundary.
  if (result.executingAgent !== boundary.executingAgent) {
    errors.push(err("AGENT_MISMATCH", "executingAgent differs from boundary", id));
  }
  if (result.executingAgentKeyId !== boundary.executingAgentKeyId) {
    errors.push(err("KEY_OWNER_MISMATCH", "executingAgentKeyId differs from boundary", id));
  }

  // Invariant 4 — ownership; signature.
  errors.push(
    ...checkSignature(
      cfg,
      result as unknown as Record<string, unknown> & { signature: string },
      result.executingAgentKeyId,
      result.executingAgent,
      id,
    ),
  );

  // Invariant 5 — isActiveAt(executingAgentKeyId, completedAt).
  const kerr = keyLifecycleError(cfg, result.executingAgentKeyId, result.completedAt, "EXECUTING_AGENT", id);
  if (kerr && kerr.code !== "UNKNOWN_KEY") errors.push(kerr);

  // Invariant 6 — completedAt ≥ boundaryReceipt.issuedAt.
  if (ms(result.completedAt) + cfg.clockSkewToleranceMs < ms(boundary.issuedAt)) {
    errors.push(err("TIMING_VIOLATION", "completedAt precedes boundary issuedAt", id));
  }

  // Invariant 7 — observedRequest matches boundary exactly.
  if (
    result.observedRequest.action !== boundary.requestedAction ||
    result.observedRequest.target !== boundary.requestedTarget ||
    result.observedRequest.payloadHash !== boundary.payloadHash
  ) {
    errors.push(err("OBSERVED_REQUEST_MISMATCH", "observedRequest differs from boundary receipt", id));
  }

  // Invariant 8 — boundaryReceiptHash matches stored receipt.
  if (cfg.artifactStore.getHash(boundary.receiptId) !== result.boundaryReceiptHash) {
    errors.push(err("PARENT_HASH_MISMATCH", "boundaryReceiptHash mismatch", id));
  }

  return toResult(errors, { executionResultReceipt: result, boundaryReceipt: boundary });
}

// ---------------------------------------------------------------------------
// Full-chain verification — resolve all four artifacts from a boundary
// receipt id and verify each link. This is the "independently verifiable
// without trusting the agent that produced it" property from the thesis.
// ---------------------------------------------------------------------------

export function verifyFullChain(
  boundaryReceiptId: string,
  cfg: VerifierConfig,
  executionResultReceiptId?: string,
): ChainVerificationResult {
  const boundary = cfg.artifactStore.getBoundaryReceipt(boundaryReceiptId);
  if (!boundary) {
    return toResult([err("ROOT_RECEIPT_NOT_FOUND", `boundary ${boundaryReceiptId} unresolvable`)]);
  }
  const boundaryResult = verifyBoundaryReceipt(boundary, cfg);
  const errors = [...boundaryResult.errors];
  let chain = { ...boundaryResult.chain };

  if (executionResultReceiptId) {
    const exec = cfg.artifactStore.getExecutionResultReceipt(executionResultReceiptId);
    if (!exec) {
      errors.push(err("RESULT_WITHOUT_VALID_BOUNDARY", `execution result ${executionResultReceiptId} unresolvable`));
    } else {
      const execResult = verifyExecutionResultReceipt(exec, cfg);
      errors.push(...execResult.errors);
      chain = { ...chain, executionResultReceipt: exec };
    }
  }

  return toResult(errors, chain);
}
