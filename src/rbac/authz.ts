import {
    AccessControl,
    type DenyReason,
    type IGrantsListItem,
    type Permission,
    type UnknownObject,
} from 'accesscontrol';
import { HttpError } from '../util/errors.ts';
import { isOwner } from './accessControl.ts';
import { ANONYMOUS_ROLE, ownerFieldFor } from './registry.ts';

/** The authenticated (or anonymous) caller, as the policy layer sees them. */
export interface Actor {
    id: string | null;
    roles: string[];
    enabled: boolean;
    mfaVerified: boolean;
    sessionId: string | null;
    isAuthenticated: boolean;
}

/**
 * Context keys the engine and this layer own. A resource whose name collides
 * with one of these does not get its convenience alias — the record stays
 * reachable as `$.record`.
 */
const RESERVED_CONTEXT_KEYS = new Set([
    'subject',
    'record',
    'resourceName',
    'input',
    'actorEnabled',
    'mfa',
    'authenticated',
    'now',
    'tz',
    '__audit',
]);

export const ANONYMOUS: Actor = {
    id: null,
    roles: [ANONYMOUS_ROLE],
    enabled: true,
    mfaVerified: false,
    sessionId: null,
    isAuthenticated: false,
};

export interface CheckRequest {
    action: string;
    resource: string;
    /** The record being acted on. Required for any `own` decision. */
    record?: Record<string, unknown> | null;
    /** The request body, readable from conditions as `$.input.*`. */
    input?: Record<string, unknown> | undefined;
    /** Overrides the instant time-based grants are evaluated against. */
    now?: Date | undefined;
    /** Extra context keys merged into the check (rarely needed). */
    extra?: UnknownObject | undefined;
    /**
     * Set to `false` for the per-row checks of a collection scan, which would
     * otherwise write one audit row per record. The scan logs a single summary
     * row instead.
     */
    audit?: boolean | undefined;
}

export interface Decision {
    granted: boolean;
    action: string;
    resource: string;
    possession: 'own' | 'any';
    attributes: string[];
    reason: DenyReason | undefined;
    permission: Permission;
}

/** A flattened rule, as exposed by `/me/permissions`. */
export interface EffectiveRule {
    role: string;
    resource: string;
    action: string;
    possession: 'own' | 'any';
    attributes: string[];
    condition?: unknown;
    effect: 'grant' | 'deny';
}

/**
 * Everything the application asks the policy engine, in one place.
 *
 * Route handlers never talk to `AccessControl` directly: they call `assert()`
 * or `scope()` and then use the returned `Decision` to filter data. That keeps
 * the "any vs own" resolution and the fail-closed behaviour in exactly one
 * spot, which is the only way an RBAC layer stays reviewable as it grows.
 */
export class Authz {
    readonly ac: AccessControl;
    /** Flattened rules per role-set; invalidated whenever the policy changes. */
    private readonly ruleCache = new Map<string, EffectiveRule[]>();

    constructor(ac: AccessControl) {
        this.ac = ac;
        this.ac.on('change', () => this.ruleCache.clear());
    }

    /**
     * Assembles the check context. The record is exposed twice — as `record`
     * (read by the ownership resolver) and under its resource name (read by
     * conditions such as `$.article.status`) — plus the ambient facts gates
     * rely on (`$.actorEnabled`, `$.mfa`).
     */
    buildContext(actor: Actor, request: CheckRequest): UnknownObject {
        const record = request.record ?? undefined;
        // The caller lives under `subject`, never `user`: the record is also
        // exposed under its resource name, and for the `user` resource that
        // alias would otherwise overwrite the caller — quietly turning every
        // `own` rule on users into an `any` rule.
        const alias =
            record && !RESERVED_CONTEXT_KEYS.has(request.resource) ? { [request.resource]: record } : {};
        return {
            subject: { id: actor.id, roles: actor.roles },
            resourceName: request.resource,
            ...(record ? { record, ...alias } : {}),
            input: request.input ?? {},
            actorEnabled: actor.enabled,
            mfa: actor.mfaVerified,
            authenticated: actor.isAuthenticated,
            ...(request.now ? { now: request.now } : {}),
            ...(request.audit === false ? { __audit: false } : {}),
            ...request.extra,
        };
    }

    /**
     * Resolves a single permission check — widest scope first.
     *
     * The order is deliberate. An `any` grant satisfies an `own` query (any ⊇
     * own), so a single `:own` query would appear to cover both cases — but
     * `deny` rules do *not* cascade across possession, and an `:own` query can
     * therefore be satisfied by an `any` grant whose matching `deny x:any` rule
     * was never consulted. A read-only role built by denying an inherited
     * role's writes would silently keep them.
     *
     * So: ask for `any` first (with the record in context, so conditions can
     * still be evaluated). Only if that fails, and the caller genuinely owns
     * the record, fall back to the `own` query. Ownership is verified here with
     * the same resolver the engine uses, which means the fallback can never
     * reach a rule the caller was not entitled to.
     *
     * Uses `tryCan()`, never `can()`: on the request path a thrown error must
     * resolve to a denial, never bubble up as a 500 that someone later "fixes"
     * by widening a grant.
     */
    check(actor: Actor, request: CheckRequest): Decision {
        const context = this.buildContext(actor, request);
        const hasRecord = request.record !== undefined && request.record !== null;
        const owned = hasRecord && isOwner(context);
        const query = (possession: 'own' | 'any'): Permission =>
            this.ac.tryCan(actor.roles, context).do(`${request.action}:${possession}`, request.resource);

        const denied = {
            own: this.blockedByDeny(actor.roles, request.resource, request.action, 'own'),
            any: this.blockedByDeny(actor.roles, request.resource, request.action, 'any'),
        };

        // The `own` query is the richer one — the engine unions the caller's
        // own-scoped and any-scoped rules, so an owner sees every field either
        // rule grants. It is only asked when the caller really owns the record
        // *and* no `deny …:any` rule could be laundered through it.
        let ownPermission: Permission | undefined;
        if (owned && !denied.own && this.ownQueryIsSafe(actor.roles, request.resource, request.action)) {
            ownPermission = query('own');
            if (ownPermission.granted) return this.decisionOf(request, ownPermission);
        }

        const anyPermission = query('any');
        if (anyPermission.granted && !denied.any) return this.decisionOf(request, anyPermission);

        if (denied.any && anyPermission.granted) {
            // The engine let an inherited grant through a matching deny rule
            // (see `blockedByDeny`). Deny-overrides wins here regardless.
            return {
                ...this.decisionOf(request, anyPermission),
                granted: false,
                attributes: [],
                reason: 'no_grant',
            };
        }

        const decision = this.decisionOf(request, ownPermission ?? anyPermission);
        return {
            ...decision,
            possession: ownPermission ? 'own' : decision.possession,
            reason: this.explainDenial(actor, request, anyPermission, ownPermission, hasRecord, owned),
        };
    }

    /**
     * Enforces deny-overrides from the grants model, independently of the
     * engine's own evaluation.
     *
     * accesscontrol 3.1.0 applies a `deny` rule to a directly inherited grant,
     * but lets a **conditional** grant inherited two or more levels up slip
     * past it — so a role like `auditor` (deny writes, inherit `manager` which
     * inherits `accountant`) keeps exactly the capabilities it was supposed to
     * lose. Authorization is the wrong place to trust a subtle upstream
     * behaviour, so the rule is re-checked here: a full, unconditional deny
     * (`attributes: ['*']`) for this role-set, resource, action and possession
     * always denies.
     *
     * Narrower denies — a field carve-out like `deny(...).readAny('post',
     * ['secret'])` — are left to the engine, which subtracts them from the
     * attribute set correctly. Conditional denies are likewise left alone:
     * whether they apply depends on the check context.
     */
    private blockedByDeny(
        roles: string[],
        resource: string,
        action: string,
        possession: 'own' | 'any',
    ): boolean {
        return this.rulesFor(roles).some(
            (rule) =>
                rule.effect === 'deny' &&
                rule.resource === resource &&
                rule.action === action &&
                rule.possession === possession &&
                rule.condition === undefined &&
                rule.attributes.includes('*'),
        );
    }

    /**
     * Picks the most useful of the reasons a denial produced. A failed
     * mandatory gate or a closed schedule explains the whole request; "you do
     * not own this" only matters once neither of those applies.
     */
    private explainDenial(
        actor: Actor,
        request: CheckRequest,
        anyPermission: Permission,
        ownPermission: Permission | undefined,
        hasRecord: boolean,
        owned: boolean,
    ): DenyReason | undefined {
        const reasons = [ownPermission?.reason, anyPermission.reason];
        if (reasons.includes('require_failed')) return 'require_failed';
        if (reasons.includes('out_of_schedule')) return 'out_of_schedule';
        if (hasRecord && !owned && this.hasOwnRule(actor.roles, request.resource, request.action)) {
            return 'ownership_failed';
        }
        return ownPermission?.reason ?? anyPermission.reason;
    }

    /**
     * Guards the `own`-query shortcut against a sharp edge in the engine: a
     * `deny x:any` rule is not consulted when the query asks for `own`, so an
     * `own` query can be satisfied by the very `any` grant that was denied.
     *
     * The shortcut is therefore only taken when no any-scoped deny exists for
     * this action, or the role has a genuine own-scoped grant of its own. This
     * is what keeps "read-only role built by denying an inherited role's
     * writes" actually read-only.
     */
    private ownQueryIsSafe(roles: string[], resource: string, action: string): boolean {
        const rules = this.rulesFor(roles).filter(
            (rule) => rule.resource === resource && rule.action === action,
        );
        if (!rules.some((rule) => rule.effect === 'deny' && rule.possession === 'any')) return true;
        return rules.some((rule) => rule.effect === 'grant' && rule.possession === 'own');
    }

    private decisionOf(request: CheckRequest, permission: Permission): Decision {
        return {
            granted: permission.granted,
            action: request.action,
            resource: request.resource,
            possession: permission.possession,
            attributes: permission.attributes,
            reason: permission.reason,
            permission,
        };
    }

    /** Whether any `own`-scoped rule exists — used only to explain denials. */
    private hasOwnRule(roles: string[], resource: string, action: string): boolean {
        return this.rulesFor(roles).some(
            (rule) =>
                rule.resource === resource &&
                rule.action === action &&
                rule.possession === 'own' &&
                rule.effect === 'grant',
        );
    }

    /** `check()`, but a denial throws the right HTTP error. */
    assert(actor: Actor, request: CheckRequest): Decision {
        const decision = this.check(actor, request);
        if (!decision.granted) throw denialToHttpError(actor, decision);
        return decision;
    }

    /**
     * Decides how much of a collection the caller may see, without a record in
     * hand: `any` (everything), `own` (their rows only) or `null` (nothing).
     *
     * The `own` probe passes a synthetic record owned by the caller, which is
     * precisely the question being asked — "could you act on a record you own?"
     * — and keeps the ownership resolver in play instead of bypassing it.
     *
     * Use this to narrow a query (`WHERE owner_id = ?`) only when a single rule
     * can answer for the whole collection. It cannot replace `readable()` where
     * several rules overlap: an author reads their own drafts *and* everyone's
     * published articles, and no single scope describes that set.
     */
    scope(actor: Actor, request: CheckRequest): { scope: 'any' | 'own' | null; decision: Decision } {
        const anyDecision = this.check(actor, { ...request, record: null });
        if (anyDecision.granted) return { scope: 'any', decision: anyDecision };

        if (!actor.id) return { scope: null, decision: anyDecision };

        const probe = { [ownerFieldFor(request.resource)]: actor.id, ...(request.record ?? {}) };
        const ownDecision = this.check(actor, { ...request, record: probe });
        if (ownDecision.granted) return { scope: 'own', decision: ownDecision };

        return { scope: null, decision: ownDecision };
    }

    /**
     * Row-level filtering for collection endpoints.
     *
     * A list cannot be authorized in one shot: a rule like "readable while
     * `status == published`" is a statement about *rows*, and no amount of
     * squinting at the grants model answers it without the row in hand. So the
     * decision is made per record, and each surviving record is projected
     * through the attributes of the rule that let it through — two callers can
     * receive the same row with different fields on it.
     *
     * Two coarse checks run first so that "you may not read invoices at all"
     * and "verify your second factor" come back as errors instead of a
     * misleading empty list:
     * 1. the grants model must contain *some* read rule for these roles;
     * 2. a record-less probe must not fail on a mandatory gate.
     */
    readable<T extends Record<string, unknown>>(
        actor: Actor,
        request: CheckRequest,
        records: T[],
    ): { visible: Partial<T>[]; scanned: number } {
        if (!this.hasAnyRule(actor.roles, request.resource, request.action)) {
            throw denialToHttpError(actor, this.check(actor, { ...request, record: null, audit: false }));
        }

        const gateProbe = this.check(actor, { ...request, record: null, audit: false });
        if (!gateProbe.granted && gateProbe.reason === 'require_failed') {
            throw denialToHttpError(actor, gateProbe);
        }

        const visible: Partial<T>[] = [];
        for (const record of records) {
            const decision = this.check(actor, { ...request, record, audit: false });
            if (decision.granted) visible.push(this.project(decision, record));
        }
        return { visible, scanned: records.length };
    }

    /**
     * Whether the grants model contains any rule at all for these roles on this
     * resource+action. A declarative capability probe — no record, no context,
     * no conditions — used to fail fast before scanning a collection.
     */
    hasAnyRule(roles: string[], resource: string, action: string): boolean {
        return this.rulesFor(roles).some(
            (rule) => rule.resource === resource && rule.action === action && rule.effect === 'grant',
        );
    }

    /**
     * Projects a record (or a list) down to the attributes the decision
     * granted. This is the half of RBAC that most implementations skip, and the
     * reason `passwordHash` cannot leak through a route that forgot to `delete`
     * it: the policy, not the handler, decides which fields exist.
     */
    project<T extends Record<string, unknown>>(decision: Decision, data: T): Partial<T>;
    project<T extends Record<string, unknown>>(decision: Decision, data: T[]): Partial<T>[];
    project<T extends Record<string, unknown>>(
        decision: Decision,
        data: T | T[],
    ): Partial<T> | Partial<T>[] {
        return decision.permission.filter(data as UnknownObject | UnknownObject[]) as
            | Partial<T>
            | Partial<T>[];
    }

    /**
     * Validates an incoming body against the *write* attributes of a decision
     * and fails loudly on anything else.
     *
     * Silently dropping ungranted fields is the common alternative; it is worse.
     * A client that believes it changed `roles` and got a 200 back has been
     * told a lie by the API.
     */
    sanitize(decision: Decision, body: Record<string, unknown>): Record<string, unknown> {
        const allowed = AccessControl.filter(body, decision.attributes) as Record<string, unknown>;
        const rejected = Object.keys(body).filter((key) => !(key in allowed));
        if (rejected.length > 0) {
            throw HttpError.forbidden(
                `Not allowed to write: ${rejected.join(', ')}.`,
                'field_forbidden',
                {
                    resource: decision.resource,
                    action: decision.action,
                    deniedFields: rejected,
                    writableFields: decision.attributes,
                },
            );
        }
        return allowed;
    }

    /**
     * The caller's full capability list, assembled from the grants model rather
     * than by brute-forcing checks — so conditions and attribute lists come
     * along for the ride. Handy for rendering a UI that hides what the user
     * cannot do.
     */
    rulesFor(roles: string[]): EffectiveRule[] {
        const cacheKey = roles.join('|');
        const cached = this.ruleCache.get(cacheKey);
        if (cached) return cached;

        const known = new Set(this.ac.getRoles());
        const expanded = new Set<string>();
        for (const role of roles) {
            if (!known.has(role)) continue;
            expanded.add(role);
            for (const inherited of this.ac.getInheritedRolesOf(role)) expanded.add(inherited);
        }

        const rules: EffectiveRule[] = [];
        for (const row of this.ac.getGrantsList() as IGrantsListItem[]) {
            if (!row.resource || !row.action || !expanded.has(row.role)) continue;
            const [action = row.action, suffix] = row.action.split(':');
            rules.push({
                role: row.role,
                resource: row.resource,
                action,
                possession: (row.possession ?? (suffix as 'own' | 'any' | undefined) ?? 'any'),
                attributes: toArray(row.attributes),
                ...(row.condition === undefined ? {} : { condition: row.condition }),
                effect: row.effect ?? 'grant',
            });
        }
        rules.sort(
            (a, b) =>
                a.resource.localeCompare(b.resource) ||
                a.action.localeCompare(b.action) ||
                a.possession.localeCompare(b.possession),
        );
        // Frozen: the cached array is shared with every caller of this method.
        Object.freeze(rules);
        this.ruleCache.set(cacheKey, rules);
        return rules;
    }
}

function toArray(attributes: string | string[] | undefined): string[] {
    if (Array.isArray(attributes)) return attributes;
    if (typeof attributes === 'string') return attributes.split(/[,;]\s*/).filter(Boolean);
    return [];
}

/**
 * Maps a denial onto the response the client deserves.
 *
 * The distinctions matter operationally: a missing session is a 401 (log in and
 * retry), a missing step-up is a 403 the client can *resolve*, and a schedule
 * denial means "come back later" rather than "you are not allowed".
 */
export function denialToHttpError(actor: Actor, decision: Decision): HttpError {
    if (!actor.isAuthenticated) {
        return HttpError.unauthenticated(
            `Authentication required to ${decision.action} ${decision.resource}.`,
        );
    }

    const base = {
        resource: decision.resource,
        action: decision.action,
        possession: decision.possession,
        reason: decision.reason ?? 'no_grant',
        roles: actor.roles,
    };

    switch (decision.reason) {
        case 'require_failed':
            // The only gate a client can act on is the step-up one.
            return actor.mfaVerified
                ? HttpError.forbidden('A mandatory policy gate rejected this request.', 'gate_failed', base)
                : HttpError.forbidden(
                      'This resource requires a step-up verified session. Verify at POST /auth/mfa/verify.',
                      'step_up_required',
                      base,
                  );
        case 'out_of_schedule':
            return HttpError.forbidden(
                'Granted, but not right now — this action is outside its permitted schedule.',
                'out_of_schedule',
                base,
            );
        case 'ownership_failed':
            return HttpError.forbidden(
                `You may only ${decision.action} your own ${decision.resource} records.`,
                'not_owner',
                base,
            );
        case 'condition_failed':
            return HttpError.forbidden(
                `The policy condition for ${decision.action}:${decision.possession} on ${decision.resource} was not met.`,
                'condition_failed',
                base,
            );
        default:
            return HttpError.forbidden(
                `Your roles (${actor.roles.join(', ')}) may not ${decision.action} ${decision.resource}.`,
                'forbidden',
                base,
            );
    }
}
