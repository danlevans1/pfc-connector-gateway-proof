/**
 * Artifact issuance: governance layer (HumanAuthReceipt) and Agent A
 * (DelegationToken). Both fail closed — an artifact that does not verify
 * at issuance is never stored.
 */
import { hashArtifact, newId, nowIso, signBody, type SigningKey } from "./crypto.ts";
import { verifyDelegationToken } from "./chain.ts";
import type {
  DelegationToken,
  FreshnessBound,
  HumanAuthReceipt,
  ISODateTime,
  UsagePolicy,
  VerifierConfig,
} from "./types.ts";

export interface ToolScope {
  /** "connector:tool" entries, e.g. "hubspot:manage_crm_objects". */
  permittedTargets: string[];
  /** "tool.operation" entries, e.g. "manage_crm_objects.create". */
  permittedActions: string[];
}

export function issueHumanAuthReceipt(opts: {
  governanceKey: SigningKey;
  grantedBy: string;
  authorizedAgent: string;
  scope: ToolScope;
  usagePolicy: UsagePolicy;
  maxUses?: number;
  ttlMs: number;
  cfg: VerifierConfig;
}): HumanAuthReceipt {
  const issuedAt = nowIso();
  if (opts.usagePolicy === "SINGLE_USE" && opts.maxUses !== undefined) {
    throw new Error("MALFORMED_ARTIFACT: maxUses must be absent for SINGLE_USE");
  }
  const body = {
    artifactType: "HumanAuthReceipt" as const,
    receiptId: newId("har"),
    authorizedAgent: opts.authorizedAgent,
    authority: { grantedBy: opts.grantedBy, issuedAt },
    permittedActions: opts.scope.permittedActions,
    permittedTargets: opts.scope.permittedTargets,
    usagePolicy: opts.usagePolicy,
    ...(opts.maxUses !== undefined ? { maxUses: opts.maxUses } : {}),
    issuedAt,
    expiresAt: new Date(Date.now() + opts.ttlMs).toISOString(),
    issuerKeyId: opts.governanceKey.keyId,
  };
  const receipt: HumanAuthReceipt = {
    ...body,
    signature: signBody(body, opts.governanceKey),
  };
  opts.cfg.artifactStore.putHumanAuthReceipt(receipt); // throws on failure
  return receipt;
}

export function issueDelegationToken(opts: {
  issuerAgentId: string;
  issuerKey: SigningKey;
  delegateeAgentId: string;
  delegateeKeyId: string;
  parent: HumanAuthReceipt;
  scope: ToolScope; // must be ⊆ parent scope (verified, fail-closed)
  freshnessBound: FreshnessBound;
  ttlMs: number;
  cfg: VerifierConfig;
  issuedAt?: ISODateTime; // injectable for tests
}): DelegationToken {
  const issuedAt = opts.issuedAt ?? nowIso();
  const parentHash = opts.cfg.artifactStore.getHash(opts.parent.receiptId);
  if (!parentHash) throw new Error("ROOT_RECEIPT_NOT_FOUND: parent not in ArtifactStore");

  const expiresAt = new Date(
    Math.min(Date.parse(issuedAt) + opts.ttlMs, Date.parse(opts.parent.expiresAt)),
  ).toISOString();

  const body = {
    artifactType: "DelegationToken" as const,
    tokenId: newId("dtk"),
    issuer: {
      agentId: opts.issuerAgentId,
      keyId: opts.issuerKey.keyId,
      parentReceiptId: opts.parent.receiptId,
      parentReceiptHash: parentHash,
    },
    delegatee: { agentId: opts.delegateeAgentId, keyId: opts.delegateeKeyId },
    permittedActions: opts.scope.permittedActions,
    permittedTargets: opts.scope.permittedTargets,
    freshnessBound: opts.freshnessBound,
    issuedAt,
    expiresAt,
  };
  const token: DelegationToken = { ...body, signature: signBody(body, opts.issuerKey) };

  // Fail-closed issuance: run the 13 token invariants (consuming one use of
  // the parent receipt) BEFORE storing.
  const result = verifyDelegationToken(token, opts.cfg, { consumeUsage: true });
  if (!result.valid) {
    throw new Error(
      `DelegationToken issuance refused: ${result.errors.map((e) => e.code).join(", ")}`,
    );
  }
  opts.cfg.artifactStore.putDelegationToken(token);
  return token;
}

export { hashArtifact };
