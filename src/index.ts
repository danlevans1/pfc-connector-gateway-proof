/**
 * Public package entry point — packaging only, no behavioral changes.
 *
 * Surface:
 *   - All v0.13 types (types.ts), including the runtime
 *     CHAIN_VERIFICATION_ERROR_CODES vocabulary and the connector-call
 *     mapping helpers (callAction / callTarget).
 *   - The chain verifier: verifyFullChain, also re-exported under the
 *     spec-facing name verifyChain.
 */
export * from "./types.ts";
export { verifyFullChain, verifyFullChain as verifyChain } from "./chain.ts";
