/**
 * Minimal external consumer for pfc-connector-gateway-proof.
 *
 * Proves the public API surface resolves through the package's `exports` map
 * with working type declarations, on two levels:
 *
 *   A. Verify-only (fail-closed): the v0.13 types, the chain verifier
 *      (verifyChain / verifyFullChain), and CHAIN_VERIFICATION_ERROR_CODES.
 *      An empty config must make an unknown boundary receipt verify
 *      `valid: false` — never throw, never `valid: true`.
 *
 *   B. Full round-trip (v0.3.0): using ONLY the public surface, build a
 *      KeyRegistry + VerifierConfig, issue a full
 *      HumanAuthReceipt -> DelegationToken -> BoundaryReceipt chain
 *      authorizing a sample action+target, then call verifyChain and assert
 *      `valid: true`. This proves an external consumer can both *issue* and
 *      *verify* without reaching into internal module paths.
 *
 * The dependency uses `file:../..` so the example works from a fresh clone.
 * From a real external project, install via git URL instead:
 *
 *   npm install git+https://github.com/danlevans1/pfc-connector-gateway-proof.git
 *
 * The `prepare` script builds dist/ automatically on install.
 *
 * Run: npm install && npm run check
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  // verifier
  CHAIN_VERIFICATION_ERROR_CODES,
  verifyChain,
  verifyFullChain,
  // crypto / key-pair generation
  generateEd25519Key,
  // registry + mutable-state ledgers + append-only store
  InMemoryKeyRegistry,
  InMemoryNonceLog,
  InMemoryUsageLedger,
  InMemoryIdempotencyLog,
  LedgerBackedRevocationLog,
  LedgerBackedArtifactStore,
  FileLedger,
  // chain-issuance builders
  issueHumanAuthReceipt,
  issueDelegationToken,
  // gateway (issues Boundary + ExecutionResult) + stub adapters
  ConnectorGateway,
  defaultStubs,
  // freshness defaults
  FRESHNESS_DEFAULTS,
  type ChainVerificationResult,
  type ConnectorCall,
  type ToolScope,
  type VerifierConfig,
} from "pfc-connector-gateway-proof";

const checks: Array<[string, boolean]> = [];

// ---------------------------------------------------------------------------
// A. Verify-only, fail-closed.
// ---------------------------------------------------------------------------

// Empty fail-closed config: every ledger denies, the artifact store is
// empty. Verifying an unknown boundary receipt must produce a structured
// failure — never a throw and never `valid: true`.
const emptyCfg: VerifierConfig = {
  version: "v0.13",
  clockSkewToleranceMs: 5000,
  keyRegistry: {
    get: () => undefined,
    isActiveAt: () => ({ active: false, reason: "UNKNOWN_KEY" }),
  },
  revocationLog: { revoke: () => {}, isRevoked: () => undefined },
  nonceLog: { record: () => false },
  usageLedger: { record: () => false, countFor: () => 0 },
  idempotencyLog: { record: () => "CONFLICT" },
  artifactStore: {
    putHumanAuthReceipt: () => { throw new Error("append-only store stub"); },
    putDelegationToken: () => { throw new Error("append-only store stub"); },
    putBoundaryReceipt: () => { throw new Error("append-only store stub"); },
    putExecutionResultReceipt: () => { throw new Error("append-only store stub"); },
    getHumanAuthReceipt: () => undefined,
    getDelegationToken: () => undefined,
    getBoundaryReceipt: () => undefined,
    getExecutionResultReceipt: () => undefined,
    getHash: () => undefined,
  },
};

const failClosed: ChainVerificationResult = verifyChain("no-such-boundary", emptyCfg);

checks.push(
  ["verifyChain is the verifier", typeof verifyChain === "function"],
  ["verifyChain aliases verifyFullChain", verifyChain === verifyFullChain],
  ["error vocabulary present", CHAIN_VERIFICATION_ERROR_CODES.length > 0],
  ["fail-closed: unresolvable boundary is invalid", failClosed.valid === false],
  [
    "fail-closed: structured error code from the vocabulary",
    failClosed.errors.some((e) => CHAIN_VERIFICATION_ERROR_CODES.includes(e.code)),
  ],
);

// ---------------------------------------------------------------------------
// B. Full issue -> verify round-trip, public surface only.
// ---------------------------------------------------------------------------

async function roundTrip(): Promise<void> {
  const GOVERNANCE = "governance-layer";
  const AGENT_A = "agent-orchestrator";
  const AGENT_B = "agent-gateway";

  // Build a real VerifierConfig from the public builders.
  const dir = mkdtempSync(join(tmpdir(), "pfc-external-consumer-"));
  const ledger = new FileLedger(join(dir, "ledger.jsonl"));

  const registry = new InMemoryKeyRegistry();
  const registeredAt = new Date(Date.now() - 60_000).toISOString();
  const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();
  const keys = {
    governance: generateEd25519Key("ext-key-governance-1"),
    agentA: generateEd25519Key("ext-key-agent-a-1"),
    agentB: generateEd25519Key("ext-key-agent-b-1"),
  };
  registry.register({ keyId: keys.governance.keyId, owner: GOVERNANCE, publicKeyPem: keys.governance.publicKeyPem, registeredAt, expiresAt });
  registry.register({ keyId: keys.agentA.keyId, owner: AGENT_A, publicKeyPem: keys.agentA.publicKeyPem, registeredAt, expiresAt });
  registry.register({ keyId: keys.agentB.keyId, owner: AGENT_B, publicKeyPem: keys.agentB.publicKeyPem, registeredAt, expiresAt });

  const cfg: VerifierConfig = {
    version: "pfc-verifier/0.13.0",
    clockSkewToleranceMs: 5_000,
    keyRegistry: registry,
    revocationLog: new LedgerBackedRevocationLog(ledger),
    nonceLog: new InMemoryNonceLog(),
    usageLedger: new InMemoryUsageLedger(),
    artifactStore: new LedgerBackedArtifactStore(ledger),
    idempotencyLog: new InMemoryIdempotencyLog(),
    clockSource: "ntp-trusted",
    freshnessDefaults: FRESHNESS_DEFAULTS,
  };

  // Sample action+target the chain authorizes.
  const scope: ToolScope = {
    permittedTargets: ["firecrawl:firecrawl_scrape"],
    permittedActions: ["firecrawl_scrape.scrape"],
  };
  const scrapeCall: ConnectorCall = {
    connector: "firecrawl",
    tool: "firecrawl_scrape",
    operation: "scrape",
    payload: { url: "https://example.test" },
  };

  // Issue HumanAuthReceipt -> DelegationToken (chain-issuance builders).
  const receipt = issueHumanAuthReceipt({
    governanceKey: keys.governance,
    grantedBy: "human:consumer@example.com",
    authorizedAgent: AGENT_A,
    scope,
    usagePolicy: "MULTI_USE",
    maxUses: 10,
    ttlMs: 3_600_000,
    cfg,
  });
  const token = issueDelegationToken({
    issuerAgentId: AGENT_A,
    issuerKey: keys.agentA,
    delegateeAgentId: AGENT_B,
    delegateeKeyId: keys.agentB.keyId,
    parent: receipt,
    scope,
    freshnessBound: FRESHNESS_DEFAULTS.MEDIUM,
    ttlMs: 600_000,
    cfg,
  });

  // Issue the BoundaryReceipt (+ ExecutionResultReceipt) at the gateway.
  const gateway = new ConnectorGateway({
    agentId: AGENT_B,
    key: keys.agentB,
    cfg,
    ledger,
    adapters: defaultStubs({ latencyScale: 0 }),
  });
  const outcome = await gateway.execute(token, scrapeCall);

  checks.push([
    "round-trip: in-scope call passes the boundary (PRE_EFFECT)",
    outcome.ok === true,
  ]);
  if (!outcome.ok) return;

  // Verify the full chain from the boundary receipt id alone — valid:true.
  const verified: ChainVerificationResult = verifyChain(outcome.boundaryReceipt.receiptId, cfg);
  checks.push(
    ["round-trip: verifyChain resolves the issued chain", verified.valid === true],
    ["round-trip: chain is cryptographically intact", verified.chainIntact === true],
    ["round-trip: freshness satisfied", verified.freshnessSatisfied === true],
    [
      "round-trip: full chain resolved (HumanAuth + Delegation present)",
      Boolean(verified.chain?.humanAuthReceipt && verified.chain?.delegationToken),
    ],
  );
}

// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  await roundTrip();

  let failed = 0;
  for (const [name, ok] of checks) {
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
    if (!ok) failed++;
  }
  console.log(
    failed === 0
      ? `\nexternal-consumer: all ${checks.length} checks passed`
      : `\nexternal-consumer: ${failed} check(s) FAILED`,
  );
  process.exit(failed === 0 ? 0 : 1);
}

await main();
