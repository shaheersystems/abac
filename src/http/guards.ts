import type { Session, User } from '../domain/types.ts';
import type { CheckRequest } from '../rbac/authz.ts';
import { HttpError } from '../util/errors.ts';
import type { Ctx } from './router.ts';

/** Narrows a request to an authenticated one (401 otherwise). */
export function requireUser(ctx: Ctx): { user: User; session: Session } {
    const { user, session } = ctx.identity;
    if (!user || !session) throw HttpError.unauthenticated();
    return { user, session };
}

/**
 * Loads a record or 404s — *before* the permission check, because the
 * alternative leaks existence: "403 on a record that exists, 404 on one that
 * does not" is an enumeration oracle. Here every caller who may not see a
 * record gets the same 403 whether or not it exists… except that a 404 for a
 * genuinely missing id is still the honest answer for an id the caller could
 * have read. This ordering (load → authorize) keeps the policy in charge.
 */
export async function loadOr404<T>(loader: Promise<T | null>, what: string): Promise<T> {
    const record = await loader;
    if (!record) throw HttpError.notFound(what);
    return record;
}

/**
 * Builds the response body for a record the caller has just written.
 *
 * Write access does not imply read access — a role may be allowed to file an
 * invoice it cannot read back, and a freshly created draft may fall outside
 * the caller's conditional read rule. Re-checking `read` here (without
 * throwing) is what keeps a 201 from leaking fields the policy would never
 * return from `GET`. When the record is not readable the caller still gets its
 * id, plus an honest flag saying so.
 */
export function representation(
    ctx: Ctx,
    resource: string,
    record: Record<string, unknown>,
): { data: Record<string, unknown>; meta?: { readable: false; reason: string } } {
    const decision = ctx.can({ action: 'read', resource, record });
    if (decision.granted) {
        return { data: ctx.services.authz.project(decision, record) as Record<string, unknown> };
    }
    return {
        data: { id: record.id },
        meta: { readable: false, reason: decision.reason ?? 'no_grant' },
    };
}

/**
 * Runs a row-level read scan over a collection and writes one summary audit
 * row for the whole request.
 */
export function listReadable<T extends Record<string, unknown>>(
    ctx: Ctx,
    request: CheckRequest,
    records: T[],
): Partial<T>[] {
    const { visible, scanned } = ctx.services.authz.readable(
        ctx.actor,
        { ...request, now: ctx.now },
        records,
    );
    ctx.services.audit.record({
        kind: 'access',
        granted: true,
        resource: request.resource,
        action: request.action,
        possession: 'any',
        roles: ctx.actor.roles,
        detail: { scan: true, scanned, visible: visible.length },
    });
    return visible;
}
