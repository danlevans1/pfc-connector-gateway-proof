/**
 * Mutable-state ledgers + ArtifactStore, per v0.13:
 * "All artifacts are immutable once signed. Mutable state lives in ledgers
 *  only: RevocationLog, UsageLedger, NonceLog, IdempotencyLog. ArtifactStore
 *  is append-only."
 *
 * RevocationLog and ArtifactStore write through the hash-chained FileLedger,
 * so a revocation is itself an auditable, hash-committed event — this is the
 * RevocationLog *write path* the mid-run revocation scenario exercises.
 */
import { hashArtifact, nowIso } from "./crypto.ts";
import type { FileLedger } from "./ledger.ts";
import type {
  ArtifactStore,
  BoundaryReceipt,
  ChainArtifact,
  DelegationToken,
  ExecutionResultReceipt,
  Hex,
  HumanAuthReceipt,
  IdempotencyLog,
  IdempotencyOutcome,
  ISODateTime,
  KeyInactiveReason,
  KeyRecord,
  KeyRegistry,
  NonceLog,
  RevocationEntry,
  RevocationLog,
  UsageLedger,
} from "./types.ts";

// --- KeyRegistry -----------------------------------------------------------

export class InMemoryKeyRegistry implements KeyRegistry {
  private keys = new Map<string, KeyRecord>();

  register(record: KeyRecord): void {
    if (this.keys.has(record.keyId)) throw new Error(`duplicate keyId ${record.keyId}`);
    this.keys.set(record.keyId, record);
  }

  /** Key revocation — NON-RETROACTIVE (revocation asymmetry core rule). */
  revokeKey(keyId: string, revokedAt: ISODateTime = nowIso()): void {
    const k = this.keys.get(keyId);
    if (!k) throw new Error(`unknown keyId ${keyId}`);
    this.keys.set(keyId, { ...k, revokedAt });
  }

  get(keyId: string): KeyRecord | undefined {
    return this.keys.get(keyId);
  }

  /** v0.13: registeredAt ≤ T, expiresAt > T, revokedAt undefined or > T. */
  isActiveAt(keyId: string, timestamp: ISODateTime): { active: boolean; reason?: KeyInactiveReason } {
    const k = this.keys.get(keyId);
    if (!k) return { active: false, reason: "UNKNOWN_KEY" };
    const t = Date.parse(timestamp);
    if (Date.parse(k.registeredAt) > t) return { active: false, reason: "KEY_NOT_YET_ACTIVE" };
    if (Date.parse(k.expiresAt) <= t) return { active: false, reason: "KEY_EXPIRED" };
    if (k.revokedAt !== undefined && Date.parse(k.revokedAt) <= t) {
      return { active: false, reason: "KEY_REVOKED" };
    }
    return { active: true };
  }
}

// --- RevocationLog (artifact revocation — RETROACTIVE) ----------------------

export class LedgerBackedRevocationLog implements RevocationLog {
  private revoked = new Map<string, RevocationEntry>();
  private ledger: FileLedger;

  constructor(ledger: FileLedger) {
    this.ledger = ledger;
    // Rehydrate from the ledger so a restarted gateway still fails closed.
    for (const e of ledger.entries()) {
      if (e.kind === "REVOCATION") {
        const entry = e.payload as RevocationEntry;
        this.revoked.set(entry.artifactId, entry);
      }
    }
  }

  revoke(entry: RevocationEntry): void {
    if (this.revoked.has(entry.artifactId)) return; // idempotent
    // Write path: hash-committed ledger append FIRST, then the in-memory
    // index. If the append throws, the revocation is not acknowledged.
    this.ledger.append("REVOCATION", entry.artifactId, hashArtifact(entry), entry);
    this.revoked.set(entry.artifactId, entry);
  }

  isRevoked(artifactId: string): RevocationEntry | undefined {
    return this.revoked.get(artifactId);
  }
}

// --- UsageLedger -------------------------------------------------------------

export class InMemoryUsageLedger implements UsageLedger {
  private counts = new Map<string, number>();

  /** Atomic check-and-increment (single-threaded JS: no interleaving). */
  record(receiptId: string, maxUses: number | undefined): boolean {
    const current = this.counts.get(receiptId) ?? 0;
    if (maxUses !== undefined && current + 1 > maxUses) return false;
    this.counts.set(receiptId, current + 1);
    return true;
  }

  countFor(receiptId: string): number {
    return this.counts.get(receiptId) ?? 0; // diagnostic only
  }
}

// --- NonceLog ----------------------------------------------------------------

export class InMemoryNonceLog implements NonceLog {
  private seen = new Map<string, ISODateTime>();

  record(nonce: string, seenAt: ISODateTime): boolean {
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, seenAt);
    return true;
  }
}

// --- IdempotencyLog ------------------------------------------------------------

export class InMemoryIdempotencyLog implements IdempotencyLog {
  private entries = new Map<string, Hex>();

  record(key: string, payloadHash: Hex): IdempotencyOutcome {
    const existing = this.entries.get(key);
    if (existing === undefined) {
      this.entries.set(key, payloadHash);
      return "NEW";
    }
    return existing === payloadHash ? "SAFE_RETRY" : "CONFLICT";
  }
}

// --- ArtifactStore (append-only, writes through the hash-chained ledger) -----

export class LedgerBackedArtifactStore implements ArtifactStore {
  private artifacts = new Map<string, ChainArtifact>();
  private hashes = new Map<string, Hex>();
  private ledger: FileLedger;

  constructor(ledger: FileLedger) {
    this.ledger = ledger;
  }

  private put(id: string, artifact: ChainArtifact): void {
    if (this.artifacts.has(id)) {
      // Append-only: identical re-put is a no-op; divergent re-put throws.
      if (this.hashes.get(id) === hashArtifact(artifact)) return;
      throw new Error(`ArtifactStore: refusing to overwrite ${id}`);
    }
    const hash = hashArtifact(artifact);
    // Ledger append throws on failure → put* throws (fail-closed core rule).
    this.ledger.append("ARTIFACT_PUT", id, hash, { artifactType: artifact.artifactType });
    this.artifacts.set(id, artifact);
    this.hashes.set(id, hash);
  }

  putHumanAuthReceipt(r: HumanAuthReceipt): void {
    if (r.artifactType !== "HumanAuthReceipt") throw new Error("MALFORMED_ARTIFACT");
    this.put(r.receiptId, r);
  }
  putDelegationToken(t: DelegationToken): void {
    if (t.artifactType !== "DelegationToken") throw new Error("MALFORMED_ARTIFACT");
    this.put(t.tokenId, t);
  }
  putBoundaryReceipt(r: BoundaryReceipt): void {
    if (r.artifactType !== "BoundaryReceipt") throw new Error("MALFORMED_ARTIFACT");
    this.put(r.receiptId, r);
  }
  putExecutionResultReceipt(r: ExecutionResultReceipt): void {
    if (r.artifactType !== "ExecutionResultReceipt") throw new Error("MALFORMED_ARTIFACT");
    // Fail-closed core rule: put* must throw on failure, never return void
    // silently. A result receipt for a BLOCKED boundary is a spec violation
    // at the storage layer itself (ExecutionResultReceipt invariant 1 —
    // RESULT_FOR_BLOCKED_BOUNDARY), so the append is refused outright.
    const boundary = this.getBoundaryReceipt(r.boundaryReceiptId);
    if (!boundary) {
      throw new Error(`RESULT_WITHOUT_VALID_BOUNDARY: boundary ${r.boundaryReceiptId} unresolvable`);
    }
    if (boundary.status === "BLOCKED") {
      throw new Error(`RESULT_FOR_BLOCKED_BOUNDARY: refusing to store result for BLOCKED boundary ${boundary.receiptId}`);
    }
    this.put(r.receiptId, r);
  }

  getHumanAuthReceipt(id: string): HumanAuthReceipt | undefined {
    const a = this.artifacts.get(id);
    return a?.artifactType === "HumanAuthReceipt" ? a : undefined;
  }
  getDelegationToken(id: string): DelegationToken | undefined {
    const a = this.artifacts.get(id);
    return a?.artifactType === "DelegationToken" ? a : undefined;
  }
  getBoundaryReceipt(id: string): BoundaryReceipt | undefined {
    const a = this.artifacts.get(id);
    return a?.artifactType === "BoundaryReceipt" ? a : undefined;
  }
  getExecutionResultReceipt(id: string): ExecutionResultReceipt | undefined {
    const a = this.artifacts.get(id);
    return a?.artifactType === "ExecutionResultReceipt" ? a : undefined;
  }
  getHash(id: string): Hex | undefined {
    return this.hashes.get(id);
  }
}
