/**
 * Stub connector adapters with realistic latency profiles.
 *
 * Each stub mirrors a real MCP tool's call shape so the real adapter is a
 * drop-in swap — same ConnectorAdapter interface, same connector/tool names,
 * same operation vocabulary; only `invoke` changes from a simulated response
 * to an actual MCP tool call:
 *
 *   firecrawl : firecrawl_scrape    (operation "scrape")
 *   hubspot   : manage_crm_objects  (operations "create" | "update")
 *   gmail     : create_draft        (operation "create")
 */
import { setTimeout as sleep } from "node:timers/promises";
import { newId } from "./crypto.ts";
import type { ConnectorAdapter } from "./gateway.ts";

function jitter(baseMs: number, spreadMs: number): number {
  return baseMs + Math.random() * spreadMs;
}

export interface StubOptions {
  /** Scale latency (e.g. 0 for tests, 1 for the demo). */
  latencyScale?: number;
}

export class FirecrawlScrapeStub implements ConnectorAdapter {
  readonly connector = "firecrawl";
  readonly tool = "firecrawl_scrape";
  private opts: StubOptions;
  constructor(opts: StubOptions = {}) {
    this.opts = opts;
  }

  async invoke(operation: string, payload: unknown): Promise<unknown> {
    if (operation !== "scrape") throw new Error(`unsupported operation ${operation}`);
    const { url } = payload as { url: string };
    await sleep(jitter(380, 240) * (this.opts.latencyScale ?? 1)); // ~0.4–0.6s
    return {
      url,
      markdown:
        `# Acme Robotics\n\nAcme Robotics builds warehouse automation. ` +
        `Contact: Jordan Lee, VP Operations (jordan.lee@acmerobotics.example).`,
      metadata: { statusCode: 200, title: "Acme Robotics — Home" },
    };
  }
}

export class HubSpotCrmStub implements ConnectorAdapter {
  readonly connector = "hubspot";
  readonly tool = "manage_crm_objects";
  private opts: StubOptions;
  constructor(opts: StubOptions = {}) {
    this.opts = opts;
  }

  async invoke(operation: string, payload: unknown): Promise<unknown> {
    if (operation !== "create" && operation !== "update") {
      throw new Error(`unsupported operation ${operation}`);
    }
    const { objectType, properties } = payload as {
      objectType: string;
      properties: Record<string, string>;
    };
    await sleep(jitter(220, 160) * (this.opts.latencyScale ?? 1)); // ~0.2–0.4s
    return {
      objectType,
      id: newId("hs"),
      properties,
      createdAt: new Date().toISOString(),
    };
  }
}

export class GmailDraftStub implements ConnectorAdapter {
  readonly connector = "gmail";
  readonly tool = "create_draft";
  private opts: StubOptions;
  constructor(opts: StubOptions = {}) {
    this.opts = opts;
  }

  async invoke(operation: string, payload: unknown): Promise<unknown> {
    if (operation !== "create") throw new Error(`unsupported operation ${operation}`);
    const { to, subject } = payload as { to: string; subject: string; body: string };
    await sleep(jitter(160, 120) * (this.opts.latencyScale ?? 1)); // ~0.15–0.3s
    return { draftId: newId("draft"), to, subject, status: "DRAFT" };
  }
}

export function defaultStubs(opts: StubOptions = {}): ConnectorAdapter[] {
  return [new FirecrawlScrapeStub(opts), new HubSpotCrmStub(opts), new GmailDraftStub(opts)];
}
