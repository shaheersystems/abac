import { AccessControl, type ISnapshot, type UnknownObject } from 'accesscontrol';
import { CUSTOM_ACTIONS, ownerFieldFor, RESOURCES, ROLES } from './registry.ts';

/**
 * Creates the engine instance every check goes through.
 *
 * Three knobs matter here, and they are the difference between "RBAC that
 * looks right in a demo" and "RBAC you can defend in a review":
 *
 * - `policy.owner` — teaches the engine how ownership works in this domain, so
 *   an `*:own` grant is *enforced* (the record must belong to the caller)
 *   rather than merely selecting an attribute set.
 * - `policy.strict` — unknown role / action / resource names throw instead of
 *   silently denying. Paired with `tryCan()` on the request path (which never
 *   throws), typos surface in tests and boot checks, never as a stray allow.
 * - `engine.safeErrors` — keeps caller-supplied values out of error messages so
 *   request data does not leak into logs.
 */
export function createAccessControl(snapshot?: ISnapshot): AccessControl {
    const ac = new AccessControl(undefined, {
        engine: {
            // Regex conditions are a ReDoS surface and this policy needs none.
            allowRegex: false,
            safeErrors: true,
        },
        policy: {
            owner: isOwner,
            strict: { checks: true, roles: true, actions: true, resources: true },
        },
    });

    ac.setup({
        roles: [...ROLES],
        resources: [...RESOURCES],
        actions: [...CUSTOM_ACTIONS],
    });

    if (snapshot) ac.restore(snapshot);
    return ac;
}

/**
 * Ownership resolver. Receives the merged check context and answers the only
 * question `own` really asks: does this record belong to this caller?
 *
 * Returning `false` when either side is missing is deliberate — with
 * `strict.checks` on, an `own` check without a record is denied rather than
 * quietly waved through.
 */
export function isOwner(context: UnknownObject): boolean {
    const subject = context.subject as { id?: string } | undefined;
    const record = context.record as Record<string, unknown> | undefined;
    const resource = typeof context.resourceName === 'string' ? context.resourceName : '';
    if (!subject?.id || !record) return false;
    const field = ownerFieldFor(resource);
    const owner = record[field];
    return typeof owner === 'string' && owner === subject.id;
}
