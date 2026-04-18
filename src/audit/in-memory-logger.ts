import type { AuditEvent, AuditLogger } from "./types.js";

export class InMemoryAuditLogger implements AuditLogger {
  private readonly entries: AuditEvent[] = [];

  record(event: AuditEvent): Promise<void> {
    this.entries.push({ ...event });
    return Promise.resolve();
  }

  get events(): readonly AuditEvent[] {
    return this.entries;
  }

  clear(): void {
    this.entries.length = 0;
  }
}
