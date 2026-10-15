import { hashPassword, verifyPassword } from '../../auth/passwords.ts';
import type { User } from '../../domain/types.ts';
import { HttpError } from '../../util/errors.ts';
import { id, nowIso } from '../../util/ids.ts';
import { listReadable, loadOr404, representation, requireUser } from '../guards.ts';
import { json, noContent } from '../responses.ts';
import { Router, type Ctx } from '../router.ts';
import { optionalString, optionalStringArray, requireString } from '../validate.ts';

export function userRoutes(): Router {
    const router = new Router();

    /** Row-level read scan: `user` sees themselves, `manager`+ sees everyone. */
    router.get('/users', async (ctx: Ctx) => {
        const users = await ctx.services.db.users.list();
        const visible = listReadable(ctx, { action: 'read', resource: 'user' }, asRecords(users));
        return json({ data: visible, count: visible.length });
    });

    router.get('/users/:id', async (ctx: Ctx) => {
        const user = await loadOr404(ctx.services.db.users.get(ctx.params.id ?? ''), 'User');
        const decision = ctx.authorize({ action: 'read', resource: 'user', record: asRecord(user) });
        return json({ data: ctx.services.authz.project(decision, asRecord(user)) });
    });

    /** Admin-only in the seed policy — but that is the policy's call, not this handler's. */
    router.post('/users', async (ctx: Ctx) => {
        const body = await ctx.body();
        const draft: User = {
            id: id('usr'),
            email: '',
            name: '',
            passwordHash: '',
            roles: ['user'],
            department: '',
            bio: '',
            disabled: false,
            mfaEnabled: false,
            mfaSecret: null,
            createdAt: nowIso(),
            updatedAt: nowIso(),
        };

        const decision = ctx.authorize({
            action: 'create',
            resource: 'user',
            record: asRecord(draft),
            input: body,
        });
        const input = ctx.services.authz.sanitize(decision, body);

        const email = requireString(input, 'email', { max: 200 }).toLowerCase();
        const password = requireString(input, 'password', { min: 10, max: 200 });
        await assertEmailFree(ctx, email);

        const roles = optionalStringArray(input, 'roles') ?? ['user'];
        assertKnownRoles(ctx, roles);

        const user: User = {
            ...draft,
            email,
            name: requireString(input, 'name', { max: 120 }),
            passwordHash: await hashPassword(password),
            roles,
            department: optionalString(input, 'department', 120) ?? '',
            bio: optionalString(input, 'bio', 2000) ?? '',
        };
        await ctx.services.db.users.insert(user);

        const view = representation(ctx, 'user', asRecord(user));
        return json(view, { status: 201 });
    });

    /**
     * Field-level authorization in action: everyone with an `update` grant hits
     * this handler, and the *attribute list* of their grant decides whether
     * `roles` or `disabled` may be in the body. A `user` patching their own
     * `roles` gets a 403 naming the field, not a silent no-op.
     */
    router.patch('/users/:id', async (ctx: Ctx) => {
        const target = await loadOr404(ctx.services.db.users.get(ctx.params.id ?? ''), 'User');
        const body = await ctx.body();
        const decision = ctx.authorize({
            action: 'update',
            resource: 'user',
            record: asRecord(target),
            input: body,
        });
        const input = ctx.services.authz.sanitize(decision, body);
        if ('password' in input) {
            throw HttpError.badRequest('Change passwords via POST /users/:id/password.');
        }

        const patch: Partial<User> = { updatedAt: nowIso() };
        const email = optionalString(input, 'email', 200);
        if (email !== undefined) {
            await assertEmailFree(ctx, email.toLowerCase(), target.id);
            patch.email = email.toLowerCase();
        }
        const name = optionalString(input, 'name', 120);
        if (name !== undefined) patch.name = name;
        const bio = optionalString(input, 'bio', 2000);
        if (bio !== undefined) patch.bio = bio;
        const department = optionalString(input, 'department', 120);
        if (department !== undefined) patch.department = department;

        const roles = optionalStringArray(input, 'roles');
        if (roles !== undefined) {
            assertKnownRoles(ctx, roles);
            patch.roles = roles;
        }
        if (typeof input.disabled === 'boolean') patch.disabled = input.disabled;

        const updated = await ctx.services.db.users.update(target.id, patch);
        if (!updated) throw HttpError.notFound('User');

        // A privilege change must not wait for a token to expire: any session
        // still holding the old roles is revoked immediately.
        if (patch.roles !== undefined || patch.disabled === true) {
            await ctx.services.sessions.revokeAllForUser(target.id);
            ctx.services.audit.record({
                kind: 'auth',
                granted: true,
                actorId: ctx.actor.id,
                resource: 'user',
                recordId: target.id,
                detail: { event: 'sessions_revoked', reason: 'privilege_change' },
            });
        }

        const view = representation(ctx, 'user', asRecord(updated));
        return json(view);
    });

    /**
     * Password change. The *same* permission check serves both cases; the
     * resolved possession decides the business rule: `own` must prove the
     * current password, `any` (an administrative reset) need not.
     */
    router.post('/users/:id/password', async (ctx: Ctx) => {
        requireUser(ctx);
        const target = await loadOr404(ctx.services.db.users.get(ctx.params.id ?? ''), 'User');
        const body = await ctx.body();
        const newPassword = requireString(body, 'newPassword', { min: 10, max: 200 });

        const decision = ctx.authorize({
            action: 'update',
            resource: 'user',
            record: asRecord(target),
            input: { password: newPassword },
        });
        ctx.services.authz.sanitize(decision, { password: newPassword });

        if (decision.possession === 'own') {
            const current = requireString(body, 'currentPassword');
            if (!(await verifyPassword(current, target.passwordHash))) {
                throw new HttpError(401, 'invalid_credentials', 'Current password is incorrect.');
            }
        }

        await ctx.services.db.users.update(target.id, {
            passwordHash: await hashPassword(newPassword),
            updatedAt: nowIso(),
        });
        await ctx.services.sessions.revokeAllForUser(target.id);
        ctx.services.audit.record({
            kind: 'auth',
            granted: true,
            actorId: ctx.actor.id,
            resource: 'user',
            recordId: target.id,
            detail: { event: 'password_changed', possession: decision.possession },
        });
        return noContent();
    });

    router.delete('/users/:id', async (ctx: Ctx) => {
        const target = await loadOr404(ctx.services.db.users.get(ctx.params.id ?? ''), 'User');
        ctx.authorize({ action: 'delete', resource: 'user', record: asRecord(target) });
        if (target.id === ctx.actor.id) {
            throw HttpError.conflict('You cannot delete the account you are signed in with.');
        }
        await ctx.services.sessions.revokeAllForUser(target.id);
        await ctx.services.db.users.remove(target.id);
        return noContent();
    });

    return router;
}

async function assertEmailFree(ctx: Ctx, email: string, exceptId?: string): Promise<void> {
    const existing = await ctx.services.db.users.findOne(
        (user) => user.email.toLowerCase() === email && user.id !== exceptId,
    );
    if (existing) throw HttpError.conflict('That email address is already registered.');
}

/** Roles are data; assigning one that no rule mentions is almost always a typo. */
function assertKnownRoles(ctx: Ctx, roles: string[]): void {
    const known = new Set(ctx.services.authz.ac.getRoles());
    const unknown = roles.filter((role) => !known.has(role));
    if (unknown.length > 0) {
        throw HttpError.unprocessable(`Unknown role(s): ${unknown.join(', ')}.`, {
            unknownRoles: unknown,
            knownRoles: [...known],
        });
    }
}

function asRecord(user: User): Record<string, unknown> {
    return user as unknown as Record<string, unknown>;
}

function asRecords(users: User[]): Record<string, unknown>[] {
    return users as unknown as Record<string, unknown>[];
}
