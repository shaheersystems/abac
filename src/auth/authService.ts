import type { AppConfig } from '../config.ts';
import type { Db } from '../db/index.ts';
import type { Session, User } from '../domain/types.ts';
import { ANONYMOUS, type Actor } from '../rbac/authz.ts';
import type { AuditLog } from '../rbac/audit.ts';
import { HttpError } from '../util/errors.ts';
import { RateLimiter } from './rateLimit.ts';
import { verifyPassword } from './passwords.ts';
import type { SessionService } from './sessions.ts';

export interface Identity {
    actor: Actor;
    user: User | null;
    session: Session | null;
}

export const ANONYMOUS_IDENTITY: Identity = { actor: ANONYMOUS, user: null, session: null };

/**
 * Authentication — who the caller is. Authorization (what they may do) lives
 * entirely in `Authz`; the only thing this layer contributes to a policy
 * decision is the `Actor` it produces.
 */
export class AuthService {
    private readonly db: Db;
    private readonly sessions: SessionService;
    private readonly audit: AuditLog;
    private readonly config: AppConfig;
    private readonly loginLimiter: RateLimiter;

    constructor(db: Db, sessions: SessionService, audit: AuditLog, config: AppConfig) {
        this.db = db;
        this.sessions = sessions;
        this.audit = audit;
        this.config = config;
        this.loginLimiter = new RateLimiter(config.loginMaxAttempts, config.loginWindowMs);
    }

    async login(
        email: string,
        password: string,
        meta: { ip: string; userAgent: string },
    ): Promise<{ token: string; session: Session; user: User }> {
        const key = `${email.toLowerCase()}|${meta.ip}`;
        const limit = this.loginLimiter.check(key);
        if (!limit.allowed) {
            this.audit.record({ kind: 'auth', granted: false, reason: 'rate_limited', detail: { email } });
            throw HttpError.tooManyRequests('Too many login attempts.', limit.retryAfterSeconds);
        }

        const user = await this.db.users.findOne(
            (candidate) => candidate.email.toLowerCase() === email.toLowerCase(),
        );
        // Same error and roughly the same work for "no such user" and "wrong
        // password", so the endpoint cannot be used to enumerate accounts.
        const ok = user ? await verifyPassword(password, user.passwordHash) : false;
        if (!user || !ok) {
            this.audit.record({
                kind: 'auth',
                granted: false,
                reason: 'invalid_credentials',
                detail: { email },
            });
            throw new HttpError(401, 'invalid_credentials', 'Invalid email or password.');
        }
        if (user.disabled) {
            this.audit.record({
                kind: 'auth',
                granted: false,
                reason: 'account_disabled',
                actorId: user.id,
                detail: { email },
            });
            throw new HttpError(403, 'account_disabled', 'This account is disabled.');
        }

        this.loginLimiter.reset(key);
        const { token, session } = await this.sessions.create(user, meta);
        this.audit.record({
            kind: 'auth',
            granted: true,
            actorId: user.id,
            roles: user.roles,
            detail: { event: 'login', sessionId: session.id },
        });
        return { token, session, user };
    }

    async verifyStepUp(session: Session, code: string): Promise<Session> {
        if (code !== this.config.mfaCode) {
            this.audit.record({
                kind: 'auth',
                granted: false,
                reason: 'invalid_mfa_code',
                actorId: session.userId,
            });
            throw new HttpError(401, 'invalid_mfa_code', 'Invalid verification code.');
        }
        const updated = await this.sessions.markMfaVerified(session.id);
        if (!updated) throw HttpError.unauthenticated('Session no longer exists.');
        this.audit.record({
            kind: 'auth',
            granted: true,
            actorId: session.userId,
            detail: { event: 'step_up_verified', sessionId: session.id },
        });
        return updated;
    }

    /**
     * Turns an incoming request into an `Identity`. No credentials means the
     * anonymous actor holding the `guest` role — not an error. Bad or stale
     * credentials, on the other hand, are a 401: failing closed beats silently
     * degrading an expired admin session to `guest`.
     */
    async identify(request: Request): Promise<Identity> {
        const header = request.headers.get('authorization');
        if (!header) return ANONYMOUS_IDENTITY;

        const [scheme, token] = header.split(' ');
        if (scheme?.toLowerCase() !== 'bearer' || !token) {
            throw HttpError.unauthenticated('Expected an "Authorization: Bearer <token>" header.');
        }

        const session = await this.sessions.resolve(token);
        if (!session) throw HttpError.unauthenticated('Session expired or invalid.');

        const user = await this.db.users.get(session.userId);
        if (!user) {
            await this.sessions.revoke(session.id);
            throw HttpError.unauthenticated('Session expired or invalid.');
        }
        if (user.disabled) {
            await this.sessions.revokeAllForUser(user.id);
            throw new HttpError(403, 'account_disabled', 'This account is disabled.');
        }

        return {
            user,
            session,
            actor: {
                id: user.id,
                roles: user.roles,
                enabled: !user.disabled,
                mfaVerified: session.mfaVerified,
                sessionId: session.id,
                isAuthenticated: true,
            },
        };
    }
}
