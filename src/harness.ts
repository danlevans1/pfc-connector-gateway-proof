/**
 * Shared environment harness for the demo and tests: keys, registry,
 * ledgers, VerifierConfig, gateway, and the standard 3-step workflow scope.
 *
 * Agents:
 *   governance-layer  — signs HumanAuthReceipt
 *   agent-orchestrator (Agent A) — issues DelegationToken
 *   agent-gateway      (Agent B) — the connector gateway / executing agent
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateEd25519Key, nowIso, type SigningKey } from "./crypto.ts";
import { ConnectorGateway, type ConnectorAdapter } from "./gateway.ts";
import { FileLedger } from "./ledger.ts";
import {
  InMemoryIdempotencyLog,
  InMemoryKeyRegistry,
  InMemoryNonceLog,
  InMemoryUsageLedger,
  LedgerBackedArtifactStore,
  LedgerBackedRevocationLog,
} from "./ledgers.ts";
import { issueHumanAuthReceipt, issueDelegationToken, type ToolScope } from "./issuance.ts";
import type {
  DelegationToken,
  FreshnessBound,
  HumanAuthReceipt,
  VerifierConfig,
} from "./types.ts";

export const GOVERNANCE = "governance-layer";
export const AGENT_A = "agent-orchestrator";
export const AGENT_B = "agent-gateway";

export const VERIFIER_VERSION = "pfc-verifier/0.13.0";

/** v0.13 freshnessDefaults — risk-classed bounds. */
export const FRESHNESS_DEFAULTS: { HIGH: FreshnessBound; MEDIUM: FreshnessBound; LOW: FreshnessBound } = {
  HIGH: { maxAgeMs: 2_000, riskClass: "HIGH" },
  MEDIUM: { maxAgeMs: 10_000, riskClass: "MEDIUM" },
  LOW: { maxAgeMs: 60_000, riskClass: "LOW" },
};

/** Full workflow scope: scrape → CRM write → email draft. */
export const WORKFLOW_SCOPE: ToolScope = {
  permittedTargets: [
    "firecrawl:firecrawl_scrape",
    "hubspot:manage_crm_objects",
    "gmail:create_draft",
  ],
  permittedActions: [
    "firecrawl_scrape.scrape",
    "manage_crm_objects.create",
    "manage_crm_objects.update",
    "create_draft.create",
  ],
};

export interface Env {
  cfg: VerifierConfig;
  ledger: FileLedger;
  ledgerPath: string;
  registry: InMemoryKeyRegistry;
  revocationLog: LedgerBackedRevocationLog;
  keys: { governance: SigningKey; agentA: SigningKey; agentB: SigningKey };
  gateway: ConnectorGateway;
}

export function createEnv(adapters: ConnectorAdapter[], ledgerDir?: string): Env {
  const dir = ledgerDir ?? mkdtempSync(join(tmpdir(), "pfc-ledger-"));
  const ledgerPath = join(dir, "ledger.jsonl");
  const ledger = new FileLedger(ledgerPath);

  const registry = new InMemoryKeyRegistry();
  const registeredAt = new Date(Date.now() - 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();
  const keys = {
    governance: generateEd25519Key("key-governance-1"),
    agentA: generateEd25519Key("key-agent-a-1"),
    agentB: generateEd25519Key("key-agent-b-1"),
  };
  registry.register({ keyId: keys.governance.keyId, owner: GOVERNANCE, publicKeyPem: keys.governance.publicKeyPem, registeredAt, expiresAt });
  registry.register({ keyId: keys.agentA.keyId, owner: AGENT_A, publicKeyPem: keys.agentA.publicKeyPem, registeredAt, expiresAt });
  registry.register({ keyId: keys.agentB.keyId, owner: AGENT_B, publicKeyPem: keys.agentB.publicKeyPem, registeredAt, expiresAt });

  const revocationLog = new LedgerBackedRevocationLog(ledger);
  const cfg: VerifierConfig = {
    version: VERIFIER_VERSION,
    clockSkewToleranceMs: 5_000,
    keyRegistry: registry,
    revocationLog,
    nonceLog: new InMemoryNonceLog(),
    usageLedger: new InMemoryUsageLedger(),
    artifactStore: new LedgerBackedArtifactStore(ledger),
    idempotencyLog: new InMemoryIdempotencyLog(),
    clockSource: "ntp-trusted",
    freshnessDefaults: FRESHNESS_DEFAULTS,
  };

  const gateway = new ConnectorGateway({
    agentId: AGENT_B,
    key: keys.agentB,
    cfg,
    ledger,
    adapters,
  });

  return { cfg, ledger, ledgerPath, registry, revocationLog, keys, gateway };
}

export function authorizeWorkflow(
  env: Env,
  opts: { tokenScope?: ToolScope; freshness?: FreshnessBound; tokenTtlMs?: number } = {},
): { receipt: HumanAuthReceipt; token: DelegationToken } {
  const receipt = issueHumanAuthReceipt({
    governanceKey: env.keys.governance,
    grantedBy: "human:dan@example.com",
    authorizedAgent: AGENT_A,
    scope: WORKFLOW_SCOPE,
    usagePolicy: "MULTI_USE",
    maxUses: 10,
    ttlMs: 3600_000,
    cfg: env.cfg,
  });
  const token = issueDelegationToken({
    issuerAgentId: AGENT_A,
    issuerKey: env.keys.agentA,
    delegateeAgentId: AGENT_B,
    delegateeKeyId: env.keys.agentB.keyId,
    parent: receipt,
    scope: opts.tokenScope ?? WORKFLOW_SCOPE,
    freshnessBound: opts.freshness ?? FRESHNESS_DEFAULTS.MEDIUM,
    ttlMs: opts.tokenTtlMs ?? 600_000,
    cfg: env.cfg,
  });
  return { receipt, token };
}

export { nowIso };
