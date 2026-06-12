/**
 * PFC Connector Gateway — wraps every MCP connector call in the four-artifact
 * delegation chain:
 *
 *   HumanAuthReceipt ─► DelegationToken ─► BoundaryReceipt (PRE-EFFECT)
 *                                            └─► ExecutionResultReceipt
 *
 * The gateway is Agent B (the executing agent). For each call it:
 *   1. captures the ledger head (freshness anchor),
 *   2. runs the 16 boundary invariants (preEffectCheck) — measured,
 *   3. issues a signed BoundaryReceipt whose status is FIXED at issuance
 *      (PRE_EFFECT on PASS, BLOCKED on FAIL — status consistency rule),
 *   4. only on PRE_EFFECT invokes the connector adapter,
 *   5. issues a signed ExecutionResultReceipt (POST-EFFECT).
 *
 * Fail-closed: a BLOCKED boundary returns a refusal carrying the receipt and
 * the ChainVerificationResult; the connector adapter is never reached.
 */
import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import {
  buildPolicySnapshot,
  policySnapshotHash,
  preEffectCheck,
} from "./chain.ts";
import {
  hashArtifact,
  hashPayload,
  newId,
  nowIso,
  signBody,
  type SigningKey,
} from "./crypto.ts";
import type { FileLedger } from "./ledger.ts";
import type {
  BoundaryReceipt,
  ChainVerificationResult,
  ConnectorCall,
  DelegationToken,
  ExecutionResultReceipt,
  ISODateTime,
  LedgerHeadRef,
  VerifierConfig,
} from "./types.ts";
import { callAction, callTarget } from "./types.ts";

// --- Connector adapter interface -------------------------------------------
// Real MCP adapters implement this 1:1: `invoke` issues the MCP tool call
// (e.g. HubSpot manage_crm_objects, Gmail create_draft, Firecrawl
// firecrawl_scrape) and returns the tool result. Stubs in connectors.ts.

export interface ConnectorAdapter {
  readonly connector: string;
  readonly tool: string;
  invoke(operation: string, payload: unknown): Promise<unknown>;
}

// --- Gateway result shapes ---------------------------------------------------

export interface BoundaryCheckMetric {
  step: string;
  connector: string;
  tool: string;
  operation: string;
  verificationMs: number; // boundary invariant evaluation only
  receiptIssuanceMs: number; // signing + ledger append
  adapterMs?: number; // connector latency (absent when BLOCKED)
  status: "PRE_EFFECT" | "BLOCKED";
}

export interface GatewayExecution {
  ok: true;
  boundaryReceipt: BoundaryReceipt;
  executionResultReceipt: ExecutionResultReceipt;
  verification: ChainVerificationResult;
  result: unknown;
  metric: BoundaryCheckMetric;
}

export interface GatewayRefusal {
  ok: false;
  boundaryReceipt: BoundaryReceipt; // verifiable evidence of the refusal
  verification: ChainVerificationResult;
  metric: BoundaryCheckMetric;
}

export type GatewayOutcome = GatewayExecution | GatewayRefusal;

// --- Gateway -----------------------------------------------------------------

export class ConnectorGateway {
  readonly agentId: string;
  private readonly key: SigningKey;
  private readonly cfg: VerifierConfig;
  private readonly ledger: FileLedger;
  private readonly adapters = new Map<string, ConnectorAdapter>();
  private lastAcceptedSequenceNumber = 0;
  readonly metrics: BoundaryCheckMetric[] = [];

  /** Test seams — injectable clock and ledger-head capture so freshness
   *  failures can be exercised deterministically. */
  now: () => ISODateTime = nowIso;
  captureLedgerHead: () => LedgerHeadRef;

  constructor(opts: {
    agentId: string;
    key: SigningKey;
    cfg: VerifierConfig;
    ledger: FileLedger;
    adapters: ConnectorAdapter[];
  }) {
    this.agentId = opts.agentId;
    this.key = opts.key;
    this.cfg = opts.cfg;
    this.ledger = opts.ledger;
    for (const a of opts.adapters) {
      this.adapters.set(`${a.connector}:${a.tool}`, a);
    }
    this.captureLedgerHead = () => this.ledger.head();
  }

  async execute(
    token: DelegationToken,
    call: ConnectorCall,
    step = "step",
  ): Promise<GatewayOutcome> {
    const payloadHash = hashPayload(call.payload);
    const nonce = randomBytes(16).toString("hex");
    const issuedAt = this.now();

    // 1. Freshness anchor.
    const ledgerHead = this.captureLedgerHead();

    // 2. Boundary invariants 1–16 — the measured pre-effect check.
    const t0 = performance.now();
    const verifiedAt = this.now();
    const verification = preEffectCheck(
      {
        token,
        call,
        payloadHash,
        executingAgent: this.agentId,
        executingAgentKeyId: this.key.keyId,
        nonce,
        issuedAt,
        verifiedAt,
        ledgerHead,
        lastAcceptedSequenceNumber: this.lastAcceptedSequenceNumber,
      },
      this.cfg,
    );
    const verificationMs = performance.now() - t0;
    if (verification.valid) {
      this.lastAcceptedSequenceNumber = Math.max(
        this.lastAcceptedSequenceNumber,
        ledgerHead.sequenceNumber,
      );
    }

    // 3. BoundaryReceipt — status fixed at issuance; PRE_EFFECT⇔PASS,
    //    BLOCKED⇔FAIL (boundary status consistency core rule).
    const t1 = performance.now();
    const policyHash = policySnapshotHash(buildPolicySnapshot(token, this.cfg));
    const boundaryBody = {
      artifactType: "BoundaryReceipt" as const,
      receiptId: newId("bnd"),
      root: {
        receiptId: token.issuer.parentReceiptId,
        receiptHash: token.issuer.parentReceiptHash,
      },
      delegation: { tokenId: token.tokenId, tokenHash: hashArtifact(token) },
      executingAgent: this.agentId,
      executingAgentKeyId: this.key.keyId,
      requestedAction: callAction(call),
      requestedTarget: callTarget(call),
      payloadHash,
      nonce,
      ...(call.idempotencyKey !== undefined ? { idempotencyKey: call.idempotencyKey } : {}),
      status: (verification.valid ? "PRE_EFFECT" : "BLOCKED") as "PRE_EFFECT" | "BLOCKED",
      verification: {
        result: (verification.valid ? "PASS" : "FAIL") as "PASS" | "FAIL",
        verifiedAt,
        ledgerHead,
        freshnessBound: token.freshnessBound,
        policyHash,
        errors: verification.errors.map((e) => e.code),
      },
      issuedAt,
    };
    const boundaryReceipt: BoundaryReceipt = {
      ...boundaryBody,
      signature: signBody(boundaryBody, this.key),
    };
    this.cfg.artifactStore.putBoundaryReceipt(boundaryReceipt); // throws on failure
    const receiptIssuanceMs = performance.now() - t1;

    const metricBase = {
      step,
      connector: call.connector,
      tool: call.tool,
      operation: call.operation,
      verificationMs,
      receiptIssuanceMs,
    };

    // 4. Fail closed on BLOCKED — adapter is never invoked.
    if (!verification.valid) {
      const metric: BoundaryCheckMetric = { ...metricBase, status: "BLOCKED" };
      this.metrics.push(metric);
      return { ok: false, boundaryReceipt, verification, metric };
    }

    // 5. Effect — connector adapter call.
    const adapter = this.adapters.get(callTarget(call));
    const startedAt = this.now();
    const t2 = performance.now();
    let outcome: "SUCCESS" | "FAILURE" = "SUCCESS";
    let result: unknown;
    try {
      if (!adapter) throw new Error(`no adapter for ${callTarget(call)}`);
      result = await adapter.invoke(call.operation, call.payload);
    } catch (e) {
      outcome = "FAILURE";
      result = { error: e instanceof Error ? e.message : String(e) };
    }
    const adapterMs = performance.now() - t2;

    // 6. ExecutionResultReceipt (POST-EFFECT).
    const resultBody = {
      artifactType: "ExecutionResultReceipt" as const,
      receiptId: newId("exr"),
      boundaryReceiptId: boundaryReceipt.receiptId,
      boundaryReceiptHash: this.cfg.artifactStore.getHash(boundaryReceipt.receiptId)!,
      executingAgent: this.agentId,
      executingAgentKeyId: this.key.keyId,
      observedRequest: {
        action: boundaryReceipt.requestedAction,
        target: boundaryReceipt.requestedTarget,
        payloadHash: boundaryReceipt.payloadHash,
      },
      outcome,
      resultHash: hashPayload(result),
      startedAt,
      completedAt: this.now(),
    };
    const executionResultReceipt: ExecutionResultReceipt = {
      ...resultBody,
      signature: signBody(resultBody, this.key),
    };
    this.cfg.artifactStore.putExecutionResultReceipt(executionResultReceipt);

    const metric: BoundaryCheckMetric = { ...metricBase, status: "PRE_EFFECT", adapterMs };
    this.metrics.push(metric);
    return { ok: true, boundaryReceipt, executionResultReceipt, verification, result, metric };
  }
}
