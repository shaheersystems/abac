import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHarness, DEMO_PASSWORD, MONDAY_10, SUNDAY_10, type TestHarness } from './helpers.ts';

/**
 * End-to-end tests over the real request pipeline: router → authentication →
 * policy → JSON store. They assert the *observable contract* — status codes,
 * error codes and which fields come back — because that is what a client
 * depends on, and what a policy change might silently break.
 */

let api: TestHarness;

beforeAll(async () => {
    api = await createHarness();
});

afterAll(async () => {
    await api.dispose();
});

describe('authentication', () => {
    test('valid credentials return a bearer token', async () => {
        const response = await api.request('POST', '/auth/login', {
            body: { email: 'aria@example.com', password: DEMO_PASSWORD },
        });
        expect(response.status).toBe(201);
        expect(response.body.token).toBeString();
        expect(response.body.user.email).toBe('aria@example.com');
        // Secrets are stripped by the policy, not by the handler.
        expect(response.body.user.passwordHash).toBeUndefined();
        expect(response.body.user.mfaSecret).toBeUndefined();
    });

    test('wrong password is indistinguishable from an unknown account', async () => {
        const wrongPassword = await api.request('POST', '/auth/login', {
            body: { email: 'aria@example.com', password: 'nope-nope-nope' },
        });
        const unknownUser = await api.request('POST', '/auth/login', {
            body: { email: 'ghost@example.com', password: 'nope-nope-nope' },
        });
        expect(wrongPassword.status).toBe(401);
        expect(unknownUser.status).toBe(401);
        expect(wrongPassword.body.error.code).toBe(unknownUser.body.error.code);
    });

    test('a disabled account cannot sign in', async () => {
        const response = await api.request('POST', '/auth/login', {
            body: { email: 'dana@example.com', password: DEMO_PASSWORD },
        });
        expect(response.status).toBe(403);
        expect(response.body.error.code).toBe('account_disabled');
    });

    test('an invalid token is 401, and a missing one is anonymous', async () => {
        const bad = await api.request('GET', '/auth/me', { token: 'not-a-real-token' });
        expect(bad.status).toBe(401);
        expect(bad.headers.get('www-authenticate')).toContain('Bearer');

        const anonymous = await api.request('GET', '/articles');
        expect(anonymous.status).toBe(200);
    });

    test('logging out revokes the session immediately', async () => {
        const token = await api.login('uma@example.com');
        expect((await api.request('GET', '/auth/me', { token })).status).toBe(200);
        expect((await api.request('POST', '/auth/logout', { token })).status).toBe(204);
        expect((await api.request('GET', '/auth/me', { token })).status).toBe(401);
    });

    test('repeated failures are rate limited', async () => {
        const attempt = () =>
            api.request('POST', '/auth/login', {
                body: { email: 'rate@example.com', password: 'wrong-password-here' },
            });
        const statuses: number[] = [];
        for (let i = 0; i < api.config.loginMaxAttempts + 1; i += 1) {
            statuses.push((await attempt()).status);
        }
        expect(statuses.at(-1)).toBe(429);
    });
});

describe('guests', () => {
    test('see published articles without editorial fields', async () => {
        const response = await api.request('GET', '/articles');
        expect(response.status).toBe(200);
        expect(response.body.count).toBe(2);
        for (const article of response.body.data) {
            expect(article.status).toBe('published');
            expect(article.internalNotes).toBeUndefined();
        }
    });

    test('are refused unpublished articles with a 401, inviting them to log in', async () => {
        const response = await api.request('GET', '/articles/art_draft');
        expect(response.status).toBe(401);
    });

    test('cannot reach the policy or the audit log', async () => {
        expect((await api.request('GET', '/admin/policy')).status).toBe(401);
        expect((await api.request('GET', '/admin/audit')).status).toBe(401);
    });
});

describe('authors', () => {
    let token: string;

    beforeAll(async () => {
        token = await api.login('aria@example.com');
    });

    test('see their own drafts alongside published articles', async () => {
        const response = await api.request('GET', '/articles', { token });
        const ids = (response.body.data as { id: string }[]).map((article) => article.id).sort();
        expect(ids).toEqual(['art_draft', 'art_editorial', 'art_published', 'art_review']);
    });

    test('can create and then edit their own article', async () => {
        const created = await api.request('POST', '/articles', {
            token,
            body: { title: 'Fresh draft', body: 'Contents', tags: ['rbac'] },
        });
        expect(created.status).toBe(201);
        expect(created.body.data.authorId).toBe('usr_author');
        expect(created.body.data.status).toBe('draft');

        const patched = await api.request('PATCH', `/articles/${created.body.data.id}`, {
            token,
            body: { title: 'Fresh draft, revised' },
        });
        expect(patched.status).toBe(200);
        expect(patched.body.data.title).toBe('Fresh draft, revised');
    });

    test('cannot set fields their grant does not list', async () => {
        const response = await api.request('PATCH', '/articles/art_draft', {
            token,
            body: { title: 'ok', internalNotes: 'sneaking this in' },
        });
        expect(response.status).toBe(403);
        expect(response.body.error.code).toBe('field_forbidden');
        expect(response.body.error.details.deniedFields).toEqual(['internalNotes']);
    });

    test('cannot publish by patching status', async () => {
        const response = await api.request('PATCH', '/articles/art_draft', {
            token,
            body: { status: 'published' },
        });
        expect(response.status).toBe(403);
        expect(response.body.error.details.reason).toBe('condition_failed');
    });

    test('cannot touch another author\'s draft', async () => {
        const response = await api.request('PATCH', '/articles/art_foreign_draft', {
            token,
            body: { title: 'not mine' },
        });
        expect(response.status).toBe(403);
        expect(response.body.error.code).toBe('not_owner');
    });

    test('publish their own article only after review', async () => {
        const tooEarly = await api.request('POST', '/articles/art_draft/publish', { token });
        expect(tooEarly.status).toBe(403);

        const toReview = await api.request('PATCH', '/articles/art_draft', {
            token,
            body: { status: 'review' },
        });
        expect(toReview.status).toBe(200);

        const published = await api.request('POST', '/articles/art_draft/publish', { token });
        expect(published.status).toBe(200);
        expect(published.body.data.status).toBe('published');
        expect(published.body.data.publishedAt).toBeString();
    });

    test('cannot edit another account through their own-profile grant', async () => {
        const response = await api.request('PATCH', '/users/usr_admin', {
            token,
            body: { name: 'Pwned' },
        });
        expect(response.status).toBe(403);
        expect(response.body.error.code).toBe('not_owner');
    });

    test('cannot grant themselves a role', async () => {
        const response = await api.request('PATCH', '/users/usr_author', {
            token,
            body: { name: 'Aria A.', roles: ['admin'] },
        });
        expect(response.status).toBe(403);
        expect(response.body.error.details.deniedFields).toEqual(['roles']);

        const unchanged = await api.request('GET', '/auth/me', { token });
        expect(unchanged.body.user.roles).toEqual(['author']);
    });
});

describe('editors', () => {
    test('publish anything, but only during business hours', async () => {
        const token = await api.login('eddie@example.com');

        const sunday = await api.request('POST', '/articles/art_review/publish', {
            token,
            now: SUNDAY_10,
        });
        expect(sunday.status).toBe(403);
        expect(sunday.body.error.code).toBe('out_of_schedule');

        const monday = await api.request('POST', '/articles/art_review/publish', {
            token,
            now: MONDAY_10,
        });
        expect(monday.status).toBe(200);
    });

    test('see editorial fields that readers never receive', async () => {
        const token = await api.login('eddie@example.com');
        const editorView = await api.request('GET', '/articles/art_published', { token });
        const guestView = await api.request('GET', '/articles/art_published');
        expect(editorView.body.data.internalNotes).toBeString();
        expect(guestView.body.data.internalNotes).toBeUndefined();
    });
});

describe('billing and the step-up gate', () => {
    test('invoices are unreachable until the session is verified', async () => {
        const token = await api.login('cara@example.com');
        const blocked = await api.request('GET', '/invoices', { token });
        expect(blocked.status).toBe(403);
        expect(blocked.body.error.code).toBe('step_up_required');

        const verified = await api.request('POST', '/auth/mfa/verify', {
            token,
            body: { code: api.config.mfaCode },
        });
        expect(verified.status).toBe(200);

        const allowed = await api.request('GET', '/invoices', { token });
        expect(allowed.status).toBe(200);
        expect(allowed.body.count).toBeGreaterThan(0);
    });

    test('a wrong verification code does not elevate the session', async () => {
        const token = await api.login('cara@example.com');
        const rejected = await api.request('POST', '/auth/mfa/verify', {
            token,
            body: { code: '000000' },
        });
        expect(rejected.status).toBe(401);
        expect((await api.request('GET', '/invoices', { token })).status).toBe(403);
    });

    test('the same list shows owners more fields than non-owners', async () => {
        const token = await api.loginVerified('cara@example.com');
        const response = await api.request('GET', '/invoices', { token });
        const rows = response.body.data as Record<string, unknown>[];
        const own = rows.find((row) => row.id === 'inv_small');
        const foreign = rows.find((row) => row.id === 'inv_approved');
        expect(own?.internalNotes).toBeString();
        expect(foreign).toBeDefined();
        expect(foreign?.internalNotes).toBeUndefined();
    });

    test('approval limits separate managers from admins', async () => {
        const manager = await api.loginVerified('mia@example.com');
        const small = await api.request('POST', '/invoices/inv_small/approve', { token: manager });
        expect(small.status).toBe(200);
        expect(small.body.data.status).toBe('approved');

        const large = await api.request('POST', '/invoices/inv_large/approve', { token: manager });
        expect(large.status).toBe(403);
        expect(large.body.error.details.reason).toBe('condition_failed');

        const admin = await api.loginVerified('admin@example.com');
        expect((await api.request('POST', '/invoices/inv_large/approve', { token: admin })).status).toBe(200);
    });

    test('a read-only auditor keeps every read and loses every write', async () => {
        const token = await api.loginVerified('rita@example.com');
        const created = await api.request('POST', '/invoices', {
            token: await api.loginVerified('cara@example.com'),
            body: { customer: 'Umbrella', amount: 900 },
        });
        expect(created.status).toBe(201);

        expect((await api.request('GET', '/invoices', { token })).status).toBe(200);
        expect((await api.request('GET', '/admin/audit', { token })).status).toBe(200);

        const approve = await api.request('POST', `/invoices/${created.body.data.id}/approve`, { token });
        expect(approve.status).toBe(403);

        const update = await api.request('PATCH', `/invoices/${created.body.data.id}`, {
            token,
            body: { amount: 1 },
        });
        expect(update.status).toBe(403);

        const create = await api.request('POST', '/invoices', {
            token,
            body: { customer: 'Nope', amount: 10 },
        });
        expect(create.status).toBe(403);
    });
});

describe('passwords', () => {
    test('changing your own password requires the current one', async () => {
        const token = await api.login('uma@example.com');
        const withoutCurrent = await api.request('POST', '/users/usr_reader/password', {
            token,
            body: { newPassword: 'a-brand-new-password' },
        });
        expect(withoutCurrent.status).toBe(422);

        const wrongCurrent = await api.request('POST', '/users/usr_reader/password', {
            token,
            body: { currentPassword: 'wrong-password-value', newPassword: 'a-brand-new-password' },
        });
        expect(wrongCurrent.status).toBe(401);

        const changed = await api.request('POST', '/users/usr_reader/password', {
            token,
            body: { currentPassword: DEMO_PASSWORD, newPassword: 'a-brand-new-password' },
        });
        expect(changed.status).toBe(204);
        // The change revokes every session of that user.
        expect((await api.request('GET', '/auth/me', { token })).status).toBe(401);
        await api.login('uma@example.com', 'a-brand-new-password');
    });

    test('an admin resets a password without knowing it', async () => {
        const token = await api.loginVerified('admin@example.com');
        const reset = await api.request('POST', '/users/usr_reader/password', {
            token,
            body: { newPassword: DEMO_PASSWORD },
        });
        expect(reset.status).toBe(204);
        await api.login('uma@example.com');
    });

    test('nobody may reset someone else\'s password without an any-grant', async () => {
        const token = await api.login('aria@example.com');
        const response = await api.request('POST', '/users/usr_reader/password', {
            token,
            body: { newPassword: 'another-new-password' },
        });
        expect(response.status).toBe(403);
    });
});

describe('policy administration', () => {
    test('roles and rules can be added at runtime, and take effect at once', async () => {
        const admin = await api.loginVerified('admin@example.com');

        const before = await api.request('POST', '/articles', {
            token: await api.login('uma@example.com'),
            body: { title: 'Before', body: 'Contents' },
        });
        expect(before.status).toBe(403);

        expect(
            (
                await api.request('POST', '/admin/policy/roles', {
                    token: admin,
                    body: { role: 'contributor', extend: ['user'] },
                })
            ).status,
        ).toBe(201);

        for (const rule of [
            { action: 'create', possession: 'own', attributes: ['title', 'body', 'tags'] },
            { action: 'read', possession: 'own', attributes: ['*', '!internalNotes'] },
        ]) {
            const response = await api.request('POST', '/admin/policy/rules', {
                token: admin,
                body: { role: 'contributor', resource: 'article', ...rule },
            });
            expect(response.status).toBe(201);
        }

        const assigned = await api.request('PATCH', '/users/usr_reader', {
            token: admin,
            body: { roles: ['contributor'] },
        });
        expect(assigned.status).toBe(200);

        const after = await api.request('POST', '/articles', {
            token: await api.login('uma@example.com'),
            body: { title: 'After', body: 'Contents' },
        });
        expect(after.status).toBe(201);
    });

    test('the edited policy is persisted, not just held in memory', async () => {
        const stored = await api.db.policy.read();
        expect(Object.keys(stored?.grants ?? {})).toContain('contributor');
    });

    test('a rule can be removed again', async () => {
        const admin = await api.loginVerified('admin@example.com');
        const removed = await api.request('DELETE', '/admin/policy/rules', {
            token: admin,
            body: { role: 'contributor', resource: 'article', action: 'create' },
        });
        expect(removed.status).toBe(200);
        expect(removed.body.removed).toBe(1);

        const blocked = await api.request('POST', '/articles', {
            token: await api.login('uma@example.com'),
            body: { title: 'Blocked now', body: 'Contents' },
        });
        expect(blocked.status).toBe(403);
    });

    test('a role still held by users cannot be deleted', async () => {
        const admin = await api.loginVerified('admin@example.com');
        const response = await api.request('DELETE', '/admin/policy/roles/contributor', { token: admin });
        expect(response.status).toBe(409);
        expect(response.body.error.details.holders).toBe(1);
    });

    test('non-admins cannot read or edit the policy', async () => {
        const token = await api.login('eddie@example.com');
        expect((await api.request('GET', '/admin/policy', { token })).status).toBe(403);
        expect(
            (
                await api.request('POST', '/admin/policy/roles', {
                    token,
                    body: { role: 'superuser', extend: ['admin'] },
                })
            ).status,
        ).toBe(403);
    });

    test('changing a user\'s roles revokes their sessions', async () => {
        const admin = await api.loginVerified('admin@example.com');
        const victim = await api.login('uma@example.com');
        expect((await api.request('GET', '/auth/me', { token: victim })).status).toBe(200);

        await api.request('PATCH', '/users/usr_reader', { token: admin, body: { roles: ['user'] } });
        expect((await api.request('GET', '/auth/me', { token: victim })).status).toBe(401);
    });

    test('unknown roles are rejected when assigning', async () => {
        const admin = await api.loginVerified('admin@example.com');
        const response = await api.request('PATCH', '/users/usr_reader', {
            token: admin,
            body: { roles: ['wizard'] },
        });
        expect(response.status).toBe(422);
        expect(response.body.error.details.unknownRoles).toEqual(['wizard']);
    });
});

describe('the audit trail', () => {
    test('records granted and denied decisions with a reason', async () => {
        const token = await api.loginVerified('admin@example.com');
        await api.request('GET', '/articles/art_review', { token: await api.login('uma@example.com') });
        await api.app.services.audit.flush();

        const log = await api.request('GET', '/admin/audit?limit=200', { token });
        expect(log.status).toBe(200);
        const rows = log.body.data as { granted: boolean; reason: string | null; resource: string | null }[];
        expect(rows.length).toBeGreaterThan(5);
        expect(rows.some((row) => row.granted)).toBe(true);
        expect(rows.some((row) => !row.granted && row.reason)).toBe(true);
    });

    test('can be filtered, and never contains secrets', async () => {
        const token = await api.loginVerified('admin@example.com');
        const log = await api.request('GET', '/admin/audit?limit=500&resource=invoice', { token });
        const rows = log.body.data as { resource: string }[];
        expect(rows.every((row) => row.resource === 'invoice')).toBe(true);
        expect(JSON.stringify(rows)).not.toContain('argon2');
        expect(JSON.stringify(rows)).not.toContain('seed-secret');
    });
});

describe('transport basics', () => {
    test('unknown routes 404 and wrong methods 405', async () => {
        expect((await api.request('GET', '/nope')).status).toBe(404);
        expect((await api.request('DELETE', '/auth/login')).status).toBe(405);
    });

    test('malformed JSON is a 400, not a 500', async () => {
        const response = await api.request('POST', '/auth/login', { body: '{oops' });
        expect(response.status).toBe(400);
        expect(response.body.error.code).toBe('bad_request');
    });

    test('every response carries a correlation id', async () => {
        const response = await api.request('GET', '/health');
        expect(response.status).toBe(200);
        expect(response.headers.get('x-request-id')).toBeString();
    });

    test('the permissions endpoint describes what the caller may do', async () => {
        const token = await api.login('eddie@example.com');
        const response = await api.request('GET', '/auth/permissions', { token });
        expect(response.status).toBe(200);
        expect(response.body.inherited).toContain('author');
        expect(
            (response.body.rules as { resource: string; action: string }[]).some(
                (rule) => rule.resource === 'article' && rule.action === 'publish',
            ),
        ).toBe(true);
    });
});
