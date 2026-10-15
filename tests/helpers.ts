import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, type AppConfig } from '../src/config.ts';
import { createDb, type Db } from '../src/db/index.ts';
import { DEMO_PASSWORD, seedDatabase } from '../src/db/seed.ts';
import type { App } from '../src/http/app.ts';
import { createApp } from '../src/http/app.ts';
import type { Actor } from '../src/rbac/authz.ts';

export { DEMO_PASSWORD };

/** Monday 10:00 UTC — inside the editors' publishing window. */
export const MONDAY_10 = '2026-01-05T10:00:00.000Z';
/** Sunday 10:00 UTC — outside it. */
export const SUNDAY_10 = '2026-01-04T10:00:00.000Z';

export interface TestHarness {
    app: App;
    db: Db;
    config: AppConfig;
    dataDir: string;
    dispose(): Promise<void>;
    request(method: string, path: string, options?: RequestOptions): Promise<TestResponse>;
    login(email: string, password?: string): Promise<string>;
    /** Logs in and completes step-up verification. */
    loginVerified(email: string): Promise<string>;
}

export interface RequestOptions {
    token?: string | undefined;
    body?: unknown;
    now?: string | undefined;
    headers?: Record<string, string>;
}

export interface TestResponse {
    status: number;
    // Test code reads a lot of dynamic shapes; typing each one adds noise.
    body: any;
    headers: Headers;
}

/** Spins up the real app over a throwaway, freshly seeded JSON database. */
export async function createHarness(overrides: Partial<AppConfig> = {}): Promise<TestHarness> {
    const dataDir = await mkdtemp(join(tmpdir(), 'rbac-test-'));
    const config = loadConfig({ dataDir, env: 'test', allowTimeTravel: true, ...overrides });
    const db = createDb(dataDir);
    await seedDatabase(db);
    const app = await createApp(config, db);

    async function request(
        method: string,
        path: string,
        options: RequestOptions = {},
    ): Promise<TestResponse> {
        const headers: Record<string, string> = {
            'content-type': 'application/json',
            ...options.headers,
        };
        if (options.token) headers.authorization = `Bearer ${options.token}`;
        if (options.now) headers['x-simulated-now'] = options.now;

        const response = await app.fetch(
            new Request(`http://test.local${path}`, {
                method,
                headers,
                ...(options.body === undefined
                    ? {}
                    : { body: typeof options.body === 'string' ? options.body : JSON.stringify(options.body) }),
            }),
        );
        const text = await response.text();
        return {
            status: response.status,
            body: text ? JSON.parse(text) : null,
            headers: response.headers,
        };
    }

    async function login(email: string, password = DEMO_PASSWORD): Promise<string> {
        const response = await request('POST', '/auth/login', { body: { email, password } });
        if (response.status !== 201) {
            throw new Error(`login failed for ${email}: ${JSON.stringify(response.body)}`);
        }
        return response.body.token as string;
    }

    async function loginVerified(email: string): Promise<string> {
        const token = await login(email);
        const verified = await request('POST', '/auth/mfa/verify', {
            token,
            body: { code: config.mfaCode },
        });
        if (verified.status !== 200) {
            throw new Error(`step-up failed for ${email}: ${JSON.stringify(verified.body)}`);
        }
        return token;
    }

    return {
        app,
        db,
        config,
        dataDir,
        request,
        login,
        loginVerified,
        dispose: async () => {
            await app.services.audit.flush();
            await rm(dataDir, { recursive: true, force: true });
        },
    };
}

/** Builds an actor without going through the HTTP layer. */
export function actor(overrides: Partial<Actor> & { roles: string[] }): Actor {
    return {
        id: 'usr_test',
        enabled: true,
        mfaVerified: false,
        sessionId: 'ses_test',
        isAuthenticated: true,
        ...overrides,
    };
}
