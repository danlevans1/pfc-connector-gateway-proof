/**
 * File-backed, hash-chained, append-only ledger.
 *
 * Every governance event (artifact stored, revocation recorded) becomes a
 * ledger entry whose entryHash covers {sequenceNumber, prevHash, kind, refId,
 * refHash, recordedAt, payload}. prevHash links each entry to its predecessor,
 * so the head (sequenceNumber, headHash) commits to the entire history —
 * this is the LedgerHeadRef that boundary invariant 16 checks freshness
 * against, and sequenceNumber regression is the rollback-attack signal that
 * flips freshnessSatisfied to false.
 *
 * Writes are synchronous appends (appendFileSync) so a crash cannot leave a
 * partially acknowledged entry: ArtifactStore.put* throws if the append
 * throws (fail-closed core rule).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalize, sha256Hex, nowIso } from "./crypto.ts";
import type { Hex, ISODateTime, LedgerHeadRef } from "./types.ts";

export type LedgerEntryKind =
  | "GENESIS"
  | "ARTIFACT_PUT"
  | "REVOCATION";

export interface LedgerEntry {
  sequenceNumber: number;
  prevHash: Hex;
  kind: LedgerEntryKind;
  refId: string; // artifactId the entry refers to
  refHash: Hex; // SHA-256/JCS of the referenced artifact / payload
  recordedAt: ISODateTime;
  payload?: unknown; // e.g. RevocationEntry
  entryHash: Hex; // SHA-256/JCS over the entry minus entryHash
}

const GENESIS_PREV = "0".repeat(64);

function computeEntryHash(e: Omit<LedgerEntry, "entryHash">): Hex {
  return sha256Hex(canonicalize(e));
}

export class FileLedger {
  readonly path: string;
  private entriesList: LedgerEntry[] = [];

  constructor(path: string) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
      this.entriesList = lines.map((l) => JSON.parse(l) as LedgerEntry);
    }
    if (this.entriesList.length === 0) {
      this.append("GENESIS", "genesis", sha256Hex("pfc-connector-gateway-proof"));
    }
  }

  append(kind: LedgerEntryKind, refId: string, refHash: Hex, payload?: unknown): LedgerEntry {
    const prev = this.entriesList.at(-1);
    const body: Omit<LedgerEntry, "entryHash"> = {
      sequenceNumber: prev ? prev.sequenceNumber + 1 : 0,
      prevHash: prev ? prev.entryHash : GENESIS_PREV,
      kind,
      refId,
      refHash,
      recordedAt: nowIso(),
      ...(payload !== undefined ? { payload } : {}),
    };
    const entry: LedgerEntry = { ...body, entryHash: computeEntryHash(body) };
    // Synchronous append — throws on failure, satisfying fail-closed.
    appendFileSync(this.path, JSON.stringify(entry) + "\n", "utf8");
    this.entriesList.push(entry);
    return entry;
  }

  head(): LedgerHeadRef {
    const h = this.entriesList.at(-1)!;
    return {
      sequenceNumber: h.sequenceNumber,
      headHash: h.entryHash,
      capturedAt: nowIso(),
    };
  }

  entries(): readonly LedgerEntry[] {
    return this.entriesList;
  }

  /** Recompute every hash link; used by tests and the demo's audit step. */
  verifyChain(): { ok: boolean; brokenAtSequence?: number } {
    let prevHash = GENESIS_PREV;
    for (const e of this.entriesList) {
      const { entryHash, ...body } = e;
      if (e.prevHash !== prevHash || computeEntryHash(body) !== entryHash) {
        return { ok: false, brokenAtSequence: e.sequenceNumber };
      }
      prevHash = entryHash;
    }
    return { ok: true };
  }
}
