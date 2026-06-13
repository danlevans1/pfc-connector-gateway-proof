/**
 * Minimal external consumer for pfc-connector-gateway-proof.
 *
 * Proves the public API surface — the v0.13 types, the chain verifier
 * (verifyChain / verifyFullChain), and CHAIN_VERIFICATION_ERROR_CODES —
 * resolves through the package's `exports` map with working type
 * declarations.
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
import {
  CHAIN_VERIFICATION_ERROR_CODES,
  verifyChain,
  verifyFullChain,
  type ChainVerificationResult,
  type VerifierConfig,
} from "pfc-connector-gateway-proof";

// Empty fail-closed config: every ledger denies, the artifact store is
// empty. Verifying an unknown boundary receipt must produce a structured
// failure — never a throw and never `valid: true`.
const cfg: VerifierConfig = {
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

const result: ChainVerificationResult = verifyChain("no-such-boundary", cfg);

const checks: Array<[string, boolean]> = [
  ["verifyChain is the verifier", typeof verifyChain === "function"],
  ["verifyChain aliases verifyFullChain", verifyChain === verifyFullChain],
  ["error vocabulary present", CHAIN_VERIFICATION_ERROR_CODES.length > 0],
  ["fail-closed: unresolvable boundary is invalid", result.valid === false],
  [
    "structured error code from the vocabulary",
    result.errors.some((e) => CHAIN_VERIFICATION_ERROR_CODES.includes(e.code)),
  ],
];

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
