/**
 * Chain verification tests — falsifiable checks of the thesis against the
 * v0.13 spec. Four required scenarios:
 *
 *   1. happy path                 — valid, chainIntact, freshnessSatisfied
 *   2. revoked mid-run            — fail-closed BLOCKED receipt, TOKEN_REVOKED,
 *                                   chainIntact stays true (the v0.13
 *                                   "correctly blocked ≠ broken" distinction)
 *   3. expired freshness bound    — FRESHNESS_VIOLATION, freshnessSatisfied
 *                                   false, chainIntact true, valid false
 *   4. out-of-scope tool call     — ACTION_NOT_PERMITTED / TARGET_NOT_PERMITTED,
 *                                   adapter never invoked
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  verifyBoundaryReceipt,
  verifyExecutionResultReceipt,
  verifyFullChain,
} from "../src/chain.ts";
import { hashPayload, newId, signBody } from "../src/crypto.ts";
import { defaultStubs } from "../src/connectors.ts";
import {
  authorizeWorkflow,
  createEnv,
  FRESHNESS_DEFAULTS,
  nowIso,
} from "../src/harness.ts";
import type { ConnectorCall } from "../src/types.ts";

const fastStubs = () => defaultStubs({ latencyScale: 0 });

const scrapeCall: ConnectorCall = {
  connector: "firecrawl",
  tool: "firecrawl_scrape",
  operation: "scrape",
  payload: { url: "https://acmerobotics.example" },
};
const crmCall: ConnectorCall = {
  connector: "hubspot",
  tool: "manage_crm_objects",
  operation: "create",
  payload: { objectType: "contacts", properties: { email: "j@acme.example" } },
};
const draftCall: ConnectorCall = {
  connector: "gmail",
  tool: "create_draft",
  operation: "create",
  payload: { to: "j@acme.example", subject: "hi", body: "..." },
};

// ---------------------------------------------------------------------------

test("happy path: 3-step workflow, all receipts verify, ledger intact", async () => {
  const env = createEnv(fastStubs());
  const { token } = authorizeWorkflow(env);

  for (const call of [scrapeCall, crmCall, draftCall]) {
    const out = await env.gateway.execute(token, call);
    assert.equal(out.ok, true, `expected PRE_EFFECT for ${call.tool}`);
    if (!out.ok) continue;

    // Gateway-side verification result.
    assert.equal(out.verification.valid, true);
    assert.equal(out.verification.chainIntact, true);
    assert.equal(out.verification.freshnessSatisfied, true);
    assert.deepEqual(out.verification.errors, []);

    // Boundary status consistency: PRE_EFFECT ⇔ PASS.
    assert.equal(out.boundaryReceipt.status, "PRE_EFFECT");
    assert.equal(out.boundaryReceipt.verification.result, "PASS");

    // Independent post-hoc verification (no trust in the gateway).
    const replay = verifyBoundaryReceipt(out.boundaryReceipt, env.cfg);
    assert.equal(replay.chainIntact, true);
    assert.equal(replay.valid, true, JSON.stringify(replay.errors));

    const execCheck = verifyExecutionResultReceipt(out.executionResultReceipt, env.cfg);
    assert.equal(execCheck.valid, true, JSON.stringify(execCheck.errors));

    // Full chain resolution from the boundary receipt id alone.
    const full = verifyFullChain(out.boundaryReceipt.receiptId, env.cfg, out.executionResultReceipt.receiptId);
    assert.equal(full.valid, true, JSON.stringify(full.errors));
    assert.ok(full.chain?.humanAuthReceipt && full.chain?.delegationToken);
  }

  // File-backed ledger hash chain holds end-to-end.
  assert.deepEqual(env.ledger.verifyChain(), { ok: true });
  // 2 artifacts (receipt, token) + 3×(boundary+result) + genesis = 9 entries.
  assert.equal(env.ledger.entries().length, 9);
});

// ---------------------------------------------------------------------------

test("revoked mid-run: next boundary check fails closed with TOKEN_REVOKED, chainIntact preserved", async () => {
  const env = createEnv(fastStubs());
  const { token } = authorizeWorkflow(env);

  // Steps 1–2 succeed. Capture step 1's PRE_EFFECT boundary for the
  // retroactivity assertion below.
  const step1 = await env.gateway.execute(token, scrapeCall);
  assert.equal(step1.ok, true);
  const step1BoundaryId = step1.boundaryReceipt.receiptId;
  // Pre-revocation baseline: the stored receipt verifies clean.
  const before = verifyFullChain(step1BoundaryId, env.cfg);
  assert.equal(before.valid, true, JSON.stringify(before.errors));
  assert.equal((await env.gateway.execute(token, crmCall)).ok, true);

  // Mid-run revocation through the RevocationLog write path — lands a
  // hash-committed REVOCATION entry on the ledger.
  const seqBefore = env.ledger.head().sequenceNumber;
  env.revocationLog.revoke({
    artifactId: token.tokenId,
    revokedAt: nowIso(),
    reason: "operator pulled authorization",
    revokedBy: "human:dan@example.com",
  });
  assert.equal(env.ledger.head().sequenceNumber, seqBefore + 1);
  assert.equal(env.ledger.entries().at(-1)!.kind, "REVOCATION");

  // Step 3 must be refused fail-closed.
  const out = await env.gateway.execute(token, draftCall);
  assert.equal(out.ok, false, "revoked token must not execute");
  if (out.ok) return;

  // Error code + the chainIntact vs valid distinction (v0.13: revocation is
  // an authorization outcome, NOT a chain-integrity failure).
  assert.ok(out.verification.errors.some((e) => e.code === "TOKEN_REVOKED"));
  assert.equal(out.verification.valid, false);
  assert.equal(out.verification.chainIntact, true);
  assert.equal(out.verification.freshnessSatisfied, true);

  // The refusal is itself a verifiable, signed receipt: BLOCKED ⇔ FAIL.
  assert.equal(out.boundaryReceipt.status, "BLOCKED");
  assert.equal(out.boundaryReceipt.verification.result, "FAIL");
  assert.ok(out.boundaryReceipt.verification.errors.includes("TOKEN_REVOKED"));
  const replay = verifyBoundaryReceipt(out.boundaryReceipt, env.cfg);
  assert.equal(replay.chainIntact, true, JSON.stringify(replay.errors));

  // --- Revocation asymmetry (v0.13): artifact revocation is RETROACTIVE ---
  // Re-verify step 1's boundary receipt — which was PRE_EFFECT/PASS when
  // issued, before the revocation existed. It must now verify valid:false
  // with TOKEN_REVOKED, while chainIntact remains true: the receipt is
  // still cryptographically sound and fully resolvable, it is the
  // authorization that has been retroactively withdrawn.
  const after = verifyFullChain(step1BoundaryId, env.cfg);
  assert.equal(after.valid, false, "revocation must retroactively invalidate earlier receipts");
  assert.ok(
    after.errors.some((e) => e.code === "TOKEN_REVOKED"),
    `expected TOKEN_REVOKED, got [${after.errors.map((e) => e.code).join(", ")}]`,
  );
  assert.equal(after.chainIntact, true, "retroactive revocation must not break chain intactness");
  assert.equal(after.freshnessSatisfied, true);

  // The stored BLOCKED receipt for step 3 also remains resolvable
  // (immutability) — and an ExecutionResultReceipt may never be attached
  // to it (see the RESULT_FOR_BLOCKED_BOUNDARY test).
  const stored = env.cfg.artifactStore.getBoundaryReceipt(out.boundaryReceipt.receiptId);
  assert.ok(stored);
});

// ---------------------------------------------------------------------------

test("expired freshness bound: FRESHNESS_VIOLATION with freshnessSatisfied=false, chainIntact=true", async () => {
  const env = createEnv(fastStubs());
  const { token } = authorizeWorkflow(env, { freshness: FRESHNESS_DEFAULTS.HIGH }); // 2s bound

  // Inject a stale ledger-head capture: older than maxAgeMs relative to
  // verifiedAt. (Test seam — production captures the live head.)
  const realCapture = env.gateway.captureLedgerHead.bind(env.gateway);
  env.gateway.captureLedgerHead = () => ({
    ...realCapture(),
    capturedAt: new Date(Date.now() - 10_000).toISOString(), // 10s stale > 2s bound
  });

  const out = await env.gateway.execute(token, scrapeCall);
  assert.equal(out.ok, false, "stale ledger view must fail closed");
  if (out.ok) return;

  assert.ok(out.verification.errors.some((e) => e.code === "FRESHNESS_VIOLATION"));
  assert.equal(out.verification.freshnessSatisfied, false);
  // v0.13: "A chain can be intact and valid:false due to freshness alone."
  assert.equal(out.verification.chainIntact, true);
  assert.equal(out.verification.valid, false);
  assert.equal(out.boundaryReceipt.status, "BLOCKED");

  // Rollback detection: sequenceNumber regression is also FRESHNESS_VIOLATION.
  env.gateway.captureLedgerHead = () => ({ ...realCapture(), sequenceNumber: -1 });
  const rolledBack = await env.gateway.execute(token, scrapeCall);
  assert.equal(rolledBack.ok, false);
  if (!rolledBack.ok) {
    assert.ok(rolledBack.verification.errors.some((e) => e.code === "FRESHNESS_VIOLATION"));
    assert.equal(rolledBack.verification.freshnessSatisfied, false);
  }
});

// ---------------------------------------------------------------------------

test("out-of-scope tool call: ACTION_NOT_PERMITTED / TARGET_NOT_PERMITTED, adapter never reached", async () => {
  const env = createEnv(fastStubs());
  // Token narrowed to scrape-only — a strict subset of the parent receipt.
  const { token } = authorizeWorkflow(env, {
    tokenScope: {
      permittedTargets: ["firecrawl:firecrawl_scrape"],
      permittedActions: ["firecrawl_scrape.scrape"],
    },
  });

  // In-scope call still works.
  assert.equal((await env.gateway.execute(token, scrapeCall)).ok, true);

  // CRM write is outside the token's tool scope → both action and target out.
  const out = await env.gateway.execute(token, crmCall);
  assert.equal(out.ok, false, "out-of-scope call must fail closed");
  if (out.ok) return;
  const codes = out.verification.errors.map((e) => e.code);
  assert.ok(codes.includes("ACTION_NOT_PERMITTED"), codes.join(","));
  assert.ok(codes.includes("TARGET_NOT_PERMITTED"), codes.join(","));
  assert.equal(out.verification.chainIntact, true); // scope excluded from intactness
  assert.equal(out.boundaryReceipt.status, "BLOCKED");

  // Same tool, unpermitted operation: update vs create distinction
  // (operation constraints carried in permittedActions).
  const env2 = createEnv(fastStubs());
  const { token: t2 } = authorizeWorkflow(env2, {
    tokenScope: {
      permittedTargets: ["hubspot:manage_crm_objects"],
      permittedActions: ["manage_crm_objects.create"], // update NOT delegated
    },
  });
  const updateCall: ConnectorCall = { ...crmCall, operation: "update" };
  const blocked = await env2.gateway.execute(t2, updateCall);
  assert.equal(blocked.ok, false);
  if (!blocked.ok) {
    const c2 = blocked.verification.errors.map((e) => e.code);
    assert.ok(c2.includes("ACTION_NOT_PERMITTED"), c2.join(","));
    assert.ok(!c2.includes("TARGET_NOT_PERMITTED"), "target itself is in scope");
  }

  // No ExecutionResultReceipt exists for any BLOCKED boundary.
  for (const e of env.ledger.entries()) {
    if (e.kind === "ARTIFACT_PUT") {
      const payload = e.payload as { artifactType: string };
      if (payload.artifactType === "ExecutionResultReceipt") {
        const r = env.cfg.artifactStore.getExecutionResultReceipt(e.refId)!;
        assert.notEqual(r.boundaryReceiptId, out.boundaryReceipt.receiptId);
      }
    }
  }
});

// ---------------------------------------------------------------------------

test("RESULT_FOR_BLOCKED_BOUNDARY: store refuses (throws) and verification surfaces the code", async () => {
  const env = createEnv(fastStubs());
  // Scrape-only token → the CRM call is BLOCKED, producing a signed
  // BLOCKED boundary receipt in the store.
  const { token } = authorizeWorkflow(env, {
    tokenScope: {
      permittedTargets: ["firecrawl:firecrawl_scrape"],
      permittedActions: ["firecrawl_scrape.scrape"],
    },
  });
  const blocked = await env.gateway.execute(token, crmCall);
  assert.equal(blocked.ok, false);
  if (blocked.ok) return;
  const boundary = blocked.boundaryReceipt;
  assert.equal(boundary.status, "BLOCKED");

  // Adversarial move: a (correctly signed) ExecutionResultReceipt claiming
  // an effect happened behind the BLOCKED boundary.
  const body = {
    artifactType: "ExecutionResultReceipt" as const,
    receiptId: newId("exr"),
    boundaryReceiptId: boundary.receiptId,
    boundaryReceiptHash: env.cfg.artifactStore.getHash(boundary.receiptId)!,
    executingAgent: boundary.executingAgent,
    executingAgentKeyId: boundary.executingAgentKeyId,
    observedRequest: {
      action: boundary.requestedAction,
      target: boundary.requestedTarget,
      payloadHash: boundary.payloadHash,
    },
    outcome: "SUCCESS" as const,
    resultHash: hashPayload({ smuggled: true }),
    startedAt: nowIso(),
    completedAt: nowIso(),
  };
  const forged = { ...body, signature: signBody(body, env.keys.agentB) };

  // Fail-closed core rule: put* must THROW on failure — never silently
  // return void — so the forged receipt never reaches the ledger.
  const entriesBefore = env.ledger.entries().length;
  assert.throws(
    () => env.cfg.artifactStore.putExecutionResultReceipt(forged),
    /RESULT_FOR_BLOCKED_BOUNDARY/,
  );
  assert.equal(env.ledger.entries().length, entriesBefore, "no ledger append on refused put");
  assert.equal(env.cfg.artifactStore.getExecutionResultReceipt(forged.receiptId), undefined);

  // The verifier independently surfaces the same code (ExecutionResultReceipt
  // invariant 1) — chainIntact false: a result behind a blocked boundary is a
  // structural violation, not a mere authorization outcome.
  const verdict = verifyExecutionResultReceipt(forged, env.cfg);
  assert.equal(verdict.valid, false);
  assert.ok(
    verdict.errors.some((e) => e.code === "RESULT_FOR_BLOCKED_BOUNDARY"),
    `expected RESULT_FOR_BLOCKED_BOUNDARY, got [${verdict.errors.map((e) => e.code).join(", ")}]`,
  );
  assert.equal(verdict.chainIntact, false);
});

// ---------------------------------------------------------------------------

test("scope containment at issuance: token exceeding parent scope is refused (SCOPE_EXCEEDS_PARENT)", async () => {
  const env = createEnv(fastStubs());
  assert.throws(
    () =>
      authorizeWorkflow(env, {
        tokenScope: {
          permittedTargets: ["salesforce:sobject_write"], // not granted by the human
          permittedActions: ["sobject_write.create"],
        },
      }),
    /SCOPE_EXCEEDS_PARENT/,
  );
});
