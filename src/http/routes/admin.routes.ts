import { AccessControl, type IGrantsListItem } from 'accesscontrol';
import { CUSTOM_ACTIONS, RESOURCES } from '../../rbac/registry.ts';
import { HttpError } from '../../util/errors.ts';
import { json, noContent } from '../responses.ts';
import { Router, type Ctx } from '../router.ts';
import { optionalStringArray, requireEnum, requireString } from '../validate.ts';

const CRUD = ['create', 'read', 'update', 'delete'] as const;
const KNOWN_ACTIONS = [...CRUD, ...CUSTOM_ACTIONS] as const;
const POSSESSIONS = ['own', 'any'] as const;
const EFFECTS = ['grant', 'deny'] as const;

/**
 * Policy administration.
 *
 * The grants model lives in `data/policy.json` as an AccessControl snapshot,
 * so roles and rules are **data**: they can be edited by an authorized operator
 * at runtime and survive a restart, with no deploy and no code change. The
 * policy resource is itself guarded by the same engine — editing authorization
 * requires an authorization check, which is the property that makes this safe
 * to expose at all.
 */
export function adminRoutes(): Router {
    const router = new Router();

    /** The whole model: grants, `require()` gates and declared vocabulary. */
    router.get('/admin/policy', (ctx: Ctx) => {
        ctx.authorize({ action: 'read', resource: 'policy' });
        const ac = ctx.services.authz.ac;
        return json({
            locked: ac.isLocked,
            roles: ac.getRoles(),
            resources: ac.getResources(),
            actions: ac.getActions(),
            requirements: ac.getRequirements(),
            vocabulary: ac.getVocabulary(),
            grants: ac.getGrantsList(),
        });
    });

    /** Flattened, inheritance-expanded rules for one role. */
    router.get('/admin/policy/roles/:role', (ctx: Ctx) => {
        ctx.authorize({ action: 'read', resource: 'policy' });
        const role = ctx.params.role ?? '';
        const ac = ctx.services.authz.ac;
        if (!ac.hasRole(role)) throw HttpError.notFound(`Role "${role}"`);
        return json({
            role,
            inherits: ac.getInheritedRolesOf(role),
            rules: ctx.services.authz.rulesFor([role]),
        });
    });

    /** Creates a role, optionally inheriting from existing ones. */
    router.post('/admin/policy/roles', async (ctx: Ctx) => {
        ctx.authorize({ action: 'create', resource: 'policy' });
        assertUnlocked(ctx);
        const body = await ctx.body();
        const role = requireString(body, 'role', { max: 60 });
        const extend = optionalStringArray(body, 'extend') ?? [];

        const ac = ctx.services.authz.ac;
        if (ac.hasRole(role)) throw HttpError.conflict(`Role "${role}" already exists.`);
        if (extend.length === 0) {
            throw HttpError.unprocessable('"extend" must list at least one existing role to inherit from.');
        }
        for (const parent of extend) {
            if (!ac.hasRole(parent)) throw HttpError.unprocessable(`Unknown role "${parent}".`);
        }

        await mutatePolicy(ctx, () => {
            ac.grant(role).extend(extend);
        });
        return json({ role, inherits: ac.getInheritedRolesOf(role) }, { status: 201 });
    });

    router.delete('/admin/policy/roles/:role', async (ctx: Ctx) => {
        ctx.authorize({ action: 'delete', resource: 'policy' });
        assertUnlocked(ctx);
        const role = ctx.params.role ?? '';
        const ac = ctx.services.authz.ac;
        if (!ac.hasRole(role)) throw HttpError.notFound(`Role "${role}"`);

        const holders = await ctx.services.db.users.count((user) => user.roles.includes(role));
        if (holders > 0) {
            throw HttpError.conflict(`${holders} user(s) still hold the role "${role}".`, { holders });
        }
        await mutatePolicy(ctx, () => {
            ac.removeRoles(role);
        });
        return noContent();
    });

    /**
     * Adds a rule. `effect: "deny"` writes a deny rule, which beats any
     * inherited grant — the supported way to carve a capability back out of a
     * role that inherits it.
     */
    router.post('/admin/policy/rules', async (ctx: Ctx) => {
        ctx.authorize({ action: 'update', resource: 'policy' });
        assertUnlocked(ctx);
        const body = await ctx.body();

        const role = requireString(body, 'role', { max: 60 });
        const resource = requireString(body, 'resource', { max: 60 });
        const action = requireEnum(body, 'action', KNOWN_ACTIONS);
        const possession = requireEnum(body, 'possession', POSSESSIONS);
        const effect = body.effect === undefined ? 'grant' : requireEnum(body, 'effect', EFFECTS);
        const attributes = optionalStringArray(body, 'attributes') ?? ['*'];
        const condition = body.condition;

        const ac = ctx.services.authz.ac;
        if (!ac.hasRole(role)) throw HttpError.unprocessable(`Unknown role "${role}".`);
        if (!(RESOURCES as readonly string[]).includes(resource) && !ac.hasResource(resource)) {
            throw HttpError.unprocessable(
                `Unknown resource "${resource}". Declare it in the vocabulary first.`,
                { knownResources: ac.getResources() },
            );
        }

        await mutatePolicy(ctx, () => {
            const access = effect === 'deny' ? ac.deny(role) : ac.grant(role);
            if (condition !== undefined && effect === 'grant') {
                access.where(condition as never);
            }
            access.action(`${action}:${possession}`, resource, attributes);
        });

        return json({ role, resource, action, possession, effect, attributes }, { status: 201 });
    });

    /** Removes matching rules. Narrow the match with `action` / `possession`. */
    router.delete('/admin/policy/rules', async (ctx: Ctx) => {
        ctx.authorize({ action: 'delete', resource: 'policy' });
        assertUnlocked(ctx);
        const body = await ctx.body();
        const role = requireString(body, 'role', { max: 60 });
        const resource = requireString(body, 'resource', { max: 60 });
        const action = body.action === undefined ? undefined : requireEnum(body, 'action', KNOWN_ACTIONS);
        const possession =
            body.possession === undefined ? undefined : requireEnum(body, 'possession', POSSESSIONS);

        const ac = ctx.services.authz.ac;
        const rows = ac.getGrantsList() as IGrantsListItem[];
        const keep = rows.filter((row) => !matchesRule(row, { role, resource, action, possession }));
        const removed = rows.length - keep.length;
        if (removed === 0) throw HttpError.notFound('Matching rule');

        await mutatePolicy(ctx, () => {
            ac.setGrants(keep);
        });
        return json({ removed });
    });

    /** The access log, newest first. */
    router.get('/admin/audit', async (ctx: Ctx) => {
        ctx.authorize({ action: 'read', resource: 'audit' });
        await ctx.services.audit.flush();

        const params = ctx.url.searchParams;
        const limit = Math.min(Number(params.get('limit') ?? 100) || 100, 1000);
        const grantedFilter = params.get('granted');
        const actorFilter = params.get('actor');
        const resourceFilter = params.get('resource');

        const rows = await ctx.services.db.audit.find(
            (entry) =>
                (!grantedFilter || String(entry.granted) === grantedFilter) &&
                (!actorFilter || entry.actorId === actorFilter) &&
                (!resourceFilter || entry.resource === resourceFilter),
        );
        const data = rows.slice(-limit).reverse();
        return json({ data, count: data.length });
    });

    return router;
}

function matchesRule(
    row: IGrantsListItem,
    filter: { role: string; resource: string; action?: string; possession?: string },
): boolean {
    if (row.role !== filter.role || row.resource !== filter.resource) return false;
    const [rowAction, suffix] = (row.action ?? '').split(':');
    const rowPossession = row.possession ?? suffix ?? 'any';
    if (filter.action && rowAction !== filter.action) return false;
    if (filter.possession && rowPossession !== filter.possession) return false;
    return true;
}

function assertUnlocked(ctx: Ctx): void {
    if (ctx.services.authz.ac.isLocked) {
        throw HttpError.conflict(
            'The policy is locked (POLICY_LOCKED=true). Restart with it unset to edit grants.',
        );
    }
}

/**
 * Applies a policy edit and persists the new snapshot. The in-memory model and
 * `data/policy.json` move together: if the engine rejects the edit, nothing is
 * written; if it accepts, the next boot sees the same model.
 */
async function mutatePolicy(ctx: Ctx, mutate: () => void): Promise<void> {
    const before = ctx.services.authz.ac.snapshot();
    try {
        mutate();
    } catch (error) {
        if (AccessControl.isACError(error)) {
            // Roll back, so a rejected edit cannot leave a half-applied model.
            ctx.services.authz.ac.restore(before);
            throw HttpError.unprocessable((error as Error).message, { code: 'policy_rejected' });
        }
        throw error;
    }
    await ctx.services.db.policy.write(ctx.services.authz.ac.snapshot());
}
