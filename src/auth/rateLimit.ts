/**
 * A fixed-window counter for login attempts. In-memory on purpose: a real
 * deployment would put this in Redis, but throttling credential stuffing is
 * table stakes even for a reference implementation, and the interface is the
 * part worth getting right.
 */
export class RateLimiter {
    private readonly max: number;
    private readonly windowMs: number;
    private readonly hits = new Map<string, { count: number; resetAt: number }>();

    constructor(max: number, windowMs: number) {
        this.max = max;
        this.windowMs = windowMs;
    }

    /** Records an attempt. Returns `retryAfterSeconds` when the key is blocked. */
    check(key: string): { allowed: boolean; retryAfterSeconds: number } {
        const now = Date.now();
        const entry = this.hits.get(key);
        if (!entry || entry.resetAt <= now) {
            this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
            return { allowed: true, retryAfterSeconds: 0 };
        }
        entry.count += 1;
        if (entry.count > this.max) {
            return { allowed: false, retryAfterSeconds: Math.ceil((entry.resetAt - now) / 1000) };
        }
        return { allowed: true, retryAfterSeconds: 0 };
    }

    /** Clears the counter after a successful authentication. */
    reset(key: string): void {
        this.hits.delete(key);
    }
}
