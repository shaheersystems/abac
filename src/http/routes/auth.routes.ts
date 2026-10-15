import type { User } from '../../domain/types.ts';
import type { Actor } from '../../rbac/authz.ts';
import { HttpError } from '../../util/errors.ts';
import { requireUser } from '../guards.ts';
import { json, noContent } from '../responses.ts';
import { Router, type Ctx } from '../router.ts';
import { requireString } from '../validate.ts';

export function authRoutes(): Router {
    const router = new Router();

    /** Exchange credentials for a bearer token. */
    router.post('/auth/login', async (ctx: Ctx) => {
        const body = await ctx.body();
        const email = requireString(body, 'email');
        const password = requireString(body, 'password');

        const { token, session, user } = await ctx.services.auth.login(email, password, {
            ip: ctx.ip,
            userAgent: ctx.request.headers.get('user-agent') ?? 'unknown',
        });

        return json(
            {
                token,
                tokenType: 'Bearer',
                expiresAt: session.expiresAt,
                mfaVerified: session.mfaVerified,
                user: selfView(ctx, user, session.mfaVerified),
            },
            { status: 201 },
        );
    });

    /** Revoke the current session. */
    router.post('/auth/logout', async (ctx: Ctx) => {
        const { session } = requireUser(ctx);
        await ctx.services.sessions.revoke(session.id);
        return noContent();
    });

    /**
     * Step-up verification. The `invoice` resource carries a `require()` gate
     * on `$.mfa`, so this endpoint is what turns a normal session into one that
     * can touch billing at all — without a single `if` in the invoice routes.
     */
    router.post('/auth/mfa/verify', async (ctx: Ctx) => {
        const { session, user } = requireUser(ctx);
        const body = await ctx.body();
        const code = requireString(body, 'code');
        if (!user.mfaEnabled) {
            throw HttpError.badRequest('This account does not have a second factor enrolled.');
        }
        const updated = await ctx.services.auth.verifyStepUp(session, code);
        return json({ mfaVerified: updated.mfaVerified, expiresAt: updated.expiresAt });
    });

    /** The caller's own profile, filtered by the policy like any other read. */
    router.get('/auth/me', (ctx: Ctx) => {
        const { user, session } = requireUser(ctx);
        return json({
            user: selfView(ctx, user, session.mfaVerified),
            session: {
                id: session.id,
                createdAt: session.createdAt,
                expiresAt: session.expiresAt,
                mfaVerified: session.mfaVerified,
            },
            roles: ctx.actor.roles,
        });
    });

    /**
     * The caller's effective capabilities, read straight out of the grants
     * model — inherited rules, conditions and attribute lists included. A
     * front-end can drive its entire "what do I render" logic off this instead
     * of hard-coding role names in components.
     */
    router.get('/auth/permissions', (ctx: Ctx) => {
        const rules = ctx.services.authz.rulesFor(ctx.actor.roles);
        return json({
            roles: ctx.actor.roles,
            inherited: [...new Set(ctx.actor.roles.flatMap((role) => inheritedOf(ctx, role)))],
            mfaVerified: ctx.actor.mfaVerified,
            rules,
        });
    });

    return router;
}

function inheritedOf(ctx: Ctx, role: string): string[] {
    try {
        return ctx.services.authz.ac.getInheritedRolesOf(role);
    } catch {
        return [];
    }
}

/** Projects a user through their *own* `read:own user` grant. */
function selfView(ctx: Ctx, user: User, mfaVerified: boolean): Partial<User> {
    const actor: Actor = {
        id: user.id,
        roles: user.roles,
        enabled: !user.disabled,
        mfaVerified,
        sessionId: null,
        isAuthenticated: true,
    };
    const decision = ctx.services.authz.check(actor, {
        action: 'read',
        resource: 'user',
        record: user as unknown as Record<string, unknown>,
        now: ctx.now,
    });
    return ctx.services.authz.project(decision, user as unknown as Record<string, unknown>) as Partial<User>;
}
