/**
 * Crypto primitives per v0.13 Signing core rule:
 * "All signatures are over the JCS-canonicalized (RFC 8785) artifact body
 *  with the signature field excluded before serialization.
 *  Algorithm: Ed25519. Encoding: hex."
 */
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  randomUUID,
  type KeyObject,
} from "node:crypto";

// --- RFC 8785 (JCS) canonicalization -------------------------------------
// Sufficient subset for chain artifacts: objects, arrays, strings, finite
// numbers, booleans, null. Property sorting uses UTF-16 code-unit order
// (Array.prototype.sort default), which is what RFC 8785 §3.2.3 specifies.
// `undefined` members are omitted, matching JSON.stringify semantics — this
// is what makes "maxUses absent" representable.
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
    case "boolean":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new Error("JCS: non-finite number");
      return JSON.stringify(value); // ES serialization === RFC 8785 numbers
    case "object":
      if (Array.isArray(value)) {
        return "[" + value.map((v) => canonicalize(v ?? null)).join(",") + "]";
      }
      return (
        "{" +
        Object.keys(value as Record<string, unknown>)
          .filter((k) => (value as Record<string, unknown>)[k] !== undefined)
          .sort()
          .map(
            (k) =>
              JSON.stringify(k) +
              ":" +
              canonicalize((value as Record<string, unknown>)[k]),
          )
          .join(",") +
        "}"
      );
    default:
      throw new Error(`JCS: unsupported type ${typeof value}`);
  }
}

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256/JCS hash of a full (signed) artifact — used for receiptHash,
 *  tokenHash, parentReceiptHash, boundaryReceiptHash bindings. */
export function hashArtifact(artifact: unknown): string {
  return sha256Hex(canonicalize(artifact));
}

/** SHA-256/JCS hash of an arbitrary payload (payloadHash, resultHash). */
export function hashPayload(payload: unknown): string {
  return sha256Hex(canonicalize(payload ?? null));
}

export interface SigningKey {
  keyId: string;
  privateKey: KeyObject;
  publicKeyPem: string;
}

export function generateEd25519Key(keyId: string): SigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId,
    privateKey,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/** Sign JCS(body) where body excludes the signature field. */
export function signBody(
  body: Record<string, unknown>,
  key: SigningKey,
): string {
  if ("signature" in body) throw new Error("signBody: body must exclude signature");
  return edSign(null, Buffer.from(canonicalize(body), "utf8"), key.privateKey).toString("hex");
}

/** Verify an artifact's Ed25519 signature against a registered public key. */
export function verifyArtifactSignature(
  artifact: Record<string, unknown> & { signature: string },
  publicKeyPem: string,
): boolean {
  const { signature, ...body } = artifact;
  try {
    return edVerify(
      null,
      Buffer.from(canonicalize(body), "utf8"),
      createPublicKey(publicKeyPem),
      Buffer.from(signature, "hex"),
    );
  } catch {
    return false; // malformed signature bytes → fail closed
  }
}

export function newId(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}
