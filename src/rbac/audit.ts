import type { AccessControl, AccessControlEventPayload } from 'accesscontrol';
import type { Db } from '../db/index.ts';
import type { AuditEntry } from '../domain/types.ts';
import { id, nowIso } from '../util/ids.ts';
import { currentRequest } from '../util/requestStore.ts';

/**
 * The access log.
 *
 * Rather than sprinkling `log.info('denied…')` through the route handlers, it
 * subscribes to the engine's own `access` event, which fires for **every**
 * resolved check — granted and denied, including the ones a handler never
 * looks at. That is the difference between an audit trail and a habit.
 *
 * The event payload carries the full check context, which can hold PII (whole
 * records, emails). It is deliberately reduced here to the record id and the
 * decision itself before anything is written to disk.
 */
export class AuditLog {
    private readonly db: Db;
    private readonly limit: number;
    /** Writes are fire-and-forget from sync listeners; `flush()` awaits them. */
    private pending: Promise<unknown> = Promise.resolve();

    constructor(db: Db, limit: number) {
        this.db = db;
        this.limit = limit;
    }

    attach(ac: AccessControl): void {
        ac.on('access', (event) => this.onAccess(event));
        ac.on('change', (event) => this.onChange(event));
        ac.on('error', (event) => this.onError(event));
    }

    private onAccess(event: AccessControlEventPayload): void {
        if (event.name !== 'access') return;
        const context = (event.context ?? {}) as Record<string, unknown>;
        // Per-row checks of a collection scan opt out; the scan logs a summary.
        if (context.__audit === false) return;
        const record = context.record as { id?: unknown } | undefined;
        this.write({
            kind: 'access',
            resource: event.resource,
            action: event.action,
            possession: event.possession ?? null,
            granted: event.granted,
            reason: event.reason ?? null,
            roles: event.roles,
            attributes: event.attributes,
            recordId: typeof record?.id === 'string' ? record.id : null,
        });
    }

    private onChange(event: AccessControlEventPayload): void {
        if (event.name !== 'change') return;
        this.write({
            kind: 'policy',
            granted: true,
            detail: { type: event.type, ...(event.detail ?? {}) },
        });
    }

    private onError(event: AccessControlEventPayload): void {
        if (event.name !== 'error') return;
        this.write({
            kind: 'access',
            granted: false,
            reason: 'engine_error',
            resource: event.resource ?? null,
            action: event.action ?? null,
            detail: { operation: event.operation, message: event.error.message },
        });
    }

    /** Records something the engine cannot see, e.g. a failed login. */
    record(entry: Partial<AuditEntry> & { kind: AuditEntry['kind']; granted: boolean }): void {
        this.write(entry);
    }

    private write(entry: Partial<AuditEntry> & { kind: AuditEntry['kind']; granted: boolean }): void {
        const request = currentRequest();
        const row: AuditEntry = {
            id: id('aud'),
            at: nowIso(),
            kind: entry.kind,
            requestId: entry.requestId ?? request?.requestId ?? null,
            route: entry.route ?? request?.route ?? null,
            actorId: entry.actorId ?? request?.actorId ?? null,
            roles: entry.roles ?? [],
            resource: entry.resource ?? null,
            action: entry.action ?? null,
            possession: entry.possession ?? null,
            granted: entry.granted,
            reason: entry.reason ?? null,
            recordId: entry.recordId ?? null,
            attributes: entry.attributes ?? null,
            detail: entry.detail ?? null,
        };
        this.pending = this.pending
            .then(() => this.db.audit.append(row, this.limit))
            .catch(() => undefined);
    }

    /** Awaits queued writes — call before reading the log back. */
    async flush(): Promise<void> {
        await this.pending;
    }
}
