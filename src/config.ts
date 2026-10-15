import { resolve } from 'node:path';

export interface AppConfig {
    env: 'development' | 'test' | 'production';
    host: string;
    port: number;
    /** Directory holding the JSON files that stand in for a database. */
    dataDir: string;
    /** Session lifetime in milliseconds. */
    sessionTtlMs: number;
    /** Demo step-up code. A real system would verify a TOTP against `mfaSecret`. */
    mfaCode: string;
    /** Max access-log rows kept in `audit.json` (it is a file, after all). */
    auditLimit: number;
    /** Failed logins allowed per email+IP inside `loginWindowMs`. */
    loginMaxAttempts: number;
    loginWindowMs: number;
    /**
     * Allows `X-Simulated-Now` to override the instant that time-based grants
     * (`.during(...)`) are evaluated against. Never enable in production.
     */
    allowTimeTravel: boolean;
    /**
     * Freezes the grants model after boot (`ac.lock()`): the policy admin API
     * becomes read-only. Recommended once a policy is settled.
     */
    policyLocked: boolean;
}

function num(value: string | undefined, fallback: number): number {
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function bool(value: string | undefined, fallback: boolean): boolean {
    if (value === undefined) return fallback;
    return value === '1' || value.toLowerCase() === 'true';
}

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
    const env = (process.env.NODE_ENV ?? 'development') as AppConfig['env'];
    return {
        env,
        host: process.env.HOST ?? '127.0.0.1',
        port: num(process.env.PORT, 3000),
        dataDir: resolve(process.env.DATA_DIR ?? 'data'),
        sessionTtlMs: num(process.env.SESSION_TTL_MS, 12 * 60 * 60 * 1000),
        mfaCode: process.env.MFA_CODE ?? '123456',
        auditLimit: num(process.env.AUDIT_LIMIT, 2000),
        loginMaxAttempts: num(process.env.LOGIN_MAX_ATTEMPTS, 5),
        loginWindowMs: num(process.env.LOGIN_WINDOW_MS, 5 * 60 * 1000),
        allowTimeTravel: bool(process.env.ALLOW_TIME_TRAVEL, env !== 'production'),
        policyLocked: bool(process.env.POLICY_LOCKED, false),
        ...overrides,
    };
}
