import { createHash, timingSafeEqual } from 'node:crypto';
import type { AppConfig } from '../config.ts';
import type { Db } from '../db/index.ts';
import type { Session, User } from '../domain/types.ts';
import { id, nowIso, secureToken } from '../util/ids.ts';

function hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
}

/**
 * Server-side sessions.
 *
 * Opaque bearer tokens rather than self-contained JWTs, because this system
 * needs two things stateless tokens make awkward: immediate revocation
 * (logout, disabled account) and step-up state that changes mid-session. Only
 * the SHA-256 of each token is stored, so a leaked `sessions.json` cannot be
 * replayed against the API.
 */
export class SessionService {
    private readonly db: Db;
    private readonly config: AppConfig;

    constructor(db: Db, config: AppConfig) {
        this.db = db;
        this.config = config;
    }

    async create(user: User, meta: { ip: string; userAgent: string }): Promise<{ token: string; session: Session }> {
        const token = secureToken();
        const now = Date.now();
        const session: Session = {
            id: id('ses'),
            userId: user.id,
            tokenHash: hashToken(token),
            createdAt: new Date(now).toISOString(),
            expiresAt: new Date(now + this.config.sessionTtlMs).toISOString(),
            lastSeenAt: new Date(now).toISOString(),
            mfaVerified: false,
            ip: meta.ip,
            userAgent: meta.userAgent,
        };
        await this.db.sessions.insert(session);
        return { token, session };
    }

    /** Returns the live session for a bearer token, or null. */
    async resolve(token: string): Promise<Session | null> {
        const wanted = hashToken(token);
        const session = await this.db.sessions.findOne((candidate) =>
            constantTimeEquals(candidate.tokenHash, wanted),
        );
        if (!session) return null;
        if (Date.parse(session.expiresAt) <= Date.now()) {
            await this.db.sessions.remove(session.id);
            return null;
        }
        return this.db.sessions.update(session.id, { lastSeenAt: nowIso() });
    }

    /** Marks a session as step-up verified (the `invoice` gate depends on it). */
    async markMfaVerified(sessionId: string): Promise<Session | null> {
        return this.db.sessions.update(sessionId, { mfaVerified: true });
    }

    async revoke(sessionId: string): Promise<boolean> {
        return this.db.sessions.remove(sessionId);
    }

    /** Revokes every session of a user — on disable, role change or password reset. */
    async revokeAllForUser(userId: string): Promise<number> {
        return this.db.sessions.removeWhere((session) => session.userId === userId);
    }

    async purgeExpired(): Promise<number> {
        const now = Date.now();
        return this.db.sessions.removeWhere((session) => Date.parse(session.expiresAt) <= now);
    }
}

function constantTimeEquals(a: string, b: string): boolean {
    const left = Buffer.from(a, 'utf8');
    const right = Buffer.from(b, 'utf8');
    if (left.length !== right.length) return false;
    return timingSafeEqual(left, right);
}
