import { randomUUID } from 'node:crypto';
import type { AppConfig } from '../config.ts';
import { AuthService } from '../auth/authService.ts';
import { SessionService } from '../auth/sessions.ts';
import type { Db } from '../db/index.ts';
import { createAccessControl } from '../rbac/accessControl.ts';
import { AuditLog } from '../rbac/audit.ts';
import { Authz } from '../rbac/authz.ts';
import { buildSeedPolicy } from '../rbac/policy.ts';
import { HttpError } from '../util/errors.ts';
import { runWithRequestStore, setActor } from '../util/requestStore.ts';
import { ANONYMOUS_IDENTITY } from '../auth/authService.ts';
import { errorResponse, json } from './responses.ts';
import { parseJsonBody, Router, type Ctx, type Services } from './router.ts';
import { adminRoutes } from './routes/admin.routes.ts';
import { articleRoutes } from './routes/articles.routes.ts';
import { authRoutes } from './routes/auth.routes.ts';
import { commentRoutes } from './routes/comments.routes.ts';
import { invoiceRoutes } from './routes/invoices.routes.ts';
import { userRoutes } from './routes/users.routes.ts';

export interface App {
    fetch: (request: Request) => Promise<Response>;
    services: Services;
}

/**
 * Wires the application together.
 *
 * Note what boot does with the policy: it loads the snapshot from the database
 * if there is one and seeds it from code only on an empty database. The
 * running model is therefore always the stored model — the same one the admin
 * API edits — and never a code constant that silently diverges from what
 * operators changed last month.
 */
export async function createApp(config: AppConfig, db: Db): Promise<App> {
    const stored = await db.policy.read();
    const snapshot = stored ?? buildSeedPolicy();
    if (!stored) await db.policy.write(snapshot);

    const ac = createAccessControl(snapshot);
    const audit = new AuditLog(db, config.auditLimit);
    audit.attach(ac);
    if (config.policyLocked) ac.lock();

    const sessions = new SessionService(db, config);
    const services: Services = {
        config,
        db,
        authz: new Authz(ac),
        audit,
        sessions,
        auth: new AuthService(db, sessions, audit, config),
    };

    const router = new Router()
        .use(authRoutes())
        .use(userRoutes())
        .use(articleRoutes())
        .use(commentRoutes())
        .use(invoiceRoutes())
        .use(adminRoutes());

    router.get('/health', () =>
        json({
            status: 'ok',
            env: config.env,
            policy: { locked: ac.isLocked, roles: ac.getRoles().length },
        }),
    );
    router.get('/', () => json(apiIndex()));

    async function fetch(request: Request): Promise<Response> {
        const requestId = request.headers.get('x-request-id') ?? randomUUID();
        const url = new URL(request.url);
        const ip = clientIp(request);
        const matched = router.match(request.method, url.pathname);

        if (matched === null) {
            return errorResponse(HttpError.notFound(`Route ${request.method} ${url.pathname}`), requestId);
        }
        if (matched === 'method_not_allowed') {
            return errorResponse(
                new HttpError(405, 'method_not_allowed', `${request.method} is not allowed on ${url.pathname}.`),
                requestId,
            );
        }

        const route = `${request.method} ${matched.pattern}`;
        return runWithRequestStore({ requestId, route, actorId: null, ip }, async () => {
            try {
                const identity = await services.auth.identify(request);
                setActor(identity.actor.id);

                let cachedBody: Record<string, unknown> | null = null;
                const ctx: Ctx = {
                    services,
                    request,
                    url,
                    params: matched.params,
                    requestId,
                    route,
                    identity,
                    actor: identity.actor,
                    ip,
                    now: simulatedNow(request, config),
                    async body() {
                        cachedBody ??= await parseJsonBody(request);
                        return cachedBody;
                    },
                    authorize: (check) =>
                        services.authz.assert(identity.actor, { ...check, now: ctx.now }),
                    can: (check) => services.authz.check(identity.actor, { ...check, now: ctx.now }),
                };

                const response = await matched.handler(ctx);
                response.headers.set('x-request-id', requestId);
                return response;
            } catch (error) {
                return errorResponse(error, requestId);
            }
        });
    }

    return { fetch, services };
}

/** Anonymous identity, exported for tooling that needs a starting point. */
export const anonymous = ANONYMOUS_IDENTITY;

function clientIp(request: Request): string {
    const forwarded = request.headers.get('x-forwarded-for');
    return forwarded?.split(',')[0]?.trim() || '127.0.0.1';
}

/**
 * Lets a client pin the instant that time-based grants are evaluated against,
 * so the business-hours rule is demonstrable (and testable) at 03:00 on a
 * Sunday. Disabled unless `ALLOW_TIME_TRAVEL` is on, and never in production.
 */
function simulatedNow(request: Request, config: AppConfig): Date | undefined {
    if (!config.allowTimeTravel || config.env === 'production') return undefined;
    const header = request.headers.get('x-simulated-now');
    if (!header) return undefined;
    const parsed = new Date(header);
    return Number.isNaN(parsed.getTime()) ? undefined : parsed;
}

function apiIndex(): Record<string, unknown> {
    return {
        name: 'RBAC reference API',
        engine: 'accesscontrol v3',
        endpoints: {
            auth: [
                'POST /auth/login',
                'POST /auth/logout',
                'POST /auth/mfa/verify',
                'GET /auth/me',
                'GET /auth/permissions',
            ],
            users: [
                'GET /users',
                'POST /users',
                'GET /users/:id',
                'PATCH /users/:id',
                'POST /users/:id/password',
                'DELETE /users/:id',
            ],
            articles: [
                'GET /articles',
                'POST /articles',
                'GET /articles/:id',
                'PATCH /articles/:id',
                'DELETE /articles/:id',
                'POST /articles/:id/publish',
            ],
            comments: [
                'GET /articles/:id/comments',
                'POST /articles/:id/comments',
                'PATCH /comments/:id',
                'DELETE /comments/:id',
            ],
            invoices: [
                'GET /invoices',
                'POST /invoices',
                'GET /invoices/:id',
                'PATCH /invoices/:id',
                'POST /invoices/:id/approve',
                'DELETE /invoices/:id',
            ],
            admin: [
                'GET /admin/policy',
                'GET /admin/policy/roles/:role',
                'POST /admin/policy/roles',
                'DELETE /admin/policy/roles/:role',
                'POST /admin/policy/rules',
                'DELETE /admin/policy/rules',
                'GET /admin/audit',
            ],
        },
    };
}
