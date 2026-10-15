import { describe, expect, test } from 'bun:test';
import { createAccessControl } from '../src/rbac/accessControl.ts';
import { Authz } from '../src/rbac/authz.ts';
import { APPROVAL_LIMIT, buildSeedPolicy } from '../src/rbac/policy.ts';
import { HttpError } from '../src/util/errors.ts';
import { actor, MONDAY_10, SUNDAY_10 } from './helpers.ts';

/**
 * Decision-level tests. These talk to the policy engine directly — no HTTP, no
 * database — which is where a policy should be tested: one fact per case, and
 * a failure points at a rule rather than at a route.
 */

const snapshot = buildSeedPolicy();
const authz = new Authz(createAccessControl(snapshot));

const guest = { id: null, roles: ['guest'], enabled: true, mfaVerified: false, sessionId: null, isAuthenticated: false };
const aria = actor({ id: 'usr_author', roles: ['author'] });
const alex = actor({ id: 'usr_author2', roles: ['author'] });
const eddie = actor({ id: 'usr_editor', roles: ['editor'] });
const cara = actor({ id: 'usr_accountant', roles: ['accountant'], mfaVerified: true });
const mia = actor({ id: 'usr_manager', roles: ['manager'], mfaVerified: true });
const rita = actor({ id: 'usr_auditor', roles: ['auditor'], mfaVerified: true });
const ada = actor({ id: 'usr_admin', roles: ['admin'], mfaVerified: true });

const article = (overrides: Record<string, unknown> = {}) => ({
    id: 'art_1',
    authorId: 'usr_author',
    title: 'Title',
    body: 'Body',
    summary: 'Summary',
    tags: [],
    status: 'draft',
    publishedAt: null,
    internalNotes: 'secret editorial notes',
    ...overrides,
});

const invoice = (overrides: Record<string, unknown> = {}) => ({
    id: 'inv_1',
    ownerId: 'usr_accountant',
    customer: 'Northwind',
    amount: 5_000,
    currency: 'EUR',
    status: 'draft',
    internalNotes: 'margin notes',
    approvedBy: null,
    ...overrides,
});

describe('guest', () => {
    test('reads published articles only', () => {
        const published = authz.check(guest, {
            action: 'read',
            resource: 'article',
            record: article({ status: 'published' }),
        });
        expect(published.granted).toBe(true);
        expect(published.possession).toBe('any');

        const draft = authz.check(guest, { action: 'read', resource: 'article', record: article() });
        expect(draft.granted).toBe(false);
        expect(draft.reason).toBe('condition_failed');
    });

    test('never sees editorial fields', () => {
        const decision = authz.check(guest, {
            action: 'read',
            resource: 'article',
            record: article({ status: 'published' }),
        });
        const view = authz.project(decision, article({ status: 'published' }));
        expect(view.title).toBe('Title');
        expect('internalNotes' in view).toBe(false);
    });

    test('cannot write anything', () => {
        expect(authz.check(guest, { action: 'create', resource: 'article', record: article() }).granted).toBe(false);
        expect(authz.check(guest, { action: 'read', resource: 'invoice', record: invoice() }).granted).toBe(false);
    });
});

describe('ownership', () => {
    test('an author edits their own draft but not a colleague\'s', () => {
        const own = authz.check(aria, { action: 'update', resource: 'article', record: article(), input: {} });
        expect(own.granted).toBe(true);
        expect(own.possession).toBe('own');

        const foreign = authz.check(aria, {
            action: 'update',
            resource: 'article',
            record: article({ authorId: alex.id }),
            input: {},
        });
        expect(foreign.granted).toBe(false);
        expect(foreign.reason).toBe('ownership_failed');
    });

    test('own rules do not apply once the record is published', () => {
        const decision = authz.check(aria, {
            action: 'update',
            resource: 'article',
            record: article({ status: 'published' }),
            input: {},
        });
        expect(decision.granted).toBe(false);
        expect(decision.reason).toBe('condition_failed');
    });

    test('an any-grant covers records the caller does not own', () => {
        const decision = authz.check(eddie, {
            action: 'update',
            resource: 'article',
            record: article({ authorId: alex.id }),
            input: {},
        });
        expect(decision.granted).toBe(true);
        expect(decision.possession).toBe('any');
    });

    test('owners get the union of their own and any rules', () => {
        const ownInvoice = authz.check(cara, { action: 'read', resource: 'invoice', record: invoice() });
        const foreignInvoice = authz.check(cara, {
            action: 'read',
            resource: 'invoice',
            record: invoice({ ownerId: 'usr_manager' }),
        });
        expect('internalNotes' in authz.project(ownInvoice, invoice())).toBe(true);
        expect('internalNotes' in authz.project(foreignInvoice, invoice())).toBe(false);
    });
});

describe('subject and record stay separate', () => {
    // Regression: the record is also exposed under its resource name, which for
    // the `user` resource collided with the caller. Ownership then compared the
    // record against itself and every `own` rule on users behaved like `any`.
    test('a user cannot edit another user through their own-grant', () => {
        const reader = actor({ id: 'usr_reader', roles: ['user'] });
        const self = authz.check(reader, {
            action: 'update',
            resource: 'user',
            record: { id: 'usr_reader', name: 'Uma' },
            input: { name: 'Uma U.' },
        });
        expect(self.granted).toBe(true);
        expect(self.possession).toBe('own');

        const other = authz.check(reader, {
            action: 'update',
            resource: 'user',
            record: { id: 'usr_admin', name: 'Ada' },
            input: { name: 'Pwned' },
        });
        expect(other.granted).toBe(false);
        expect(other.reason).toBe('ownership_failed');
    });

    test('an own read of a user record does not expose other accounts', () => {
        const reader = actor({ id: 'usr_reader', roles: ['user'] });
        expect(authz.check(reader, { action: 'read', resource: 'user', record: { id: 'usr_reader' } }).granted).toBe(true);
        expect(authz.check(reader, { action: 'read', resource: 'user', record: { id: 'usr_admin' } }).granted).toBe(false);
    });
});

describe('conditions', () => {
    test('a condition may read the request body, not just the record', () => {
        const toReview = authz.check(aria, {
            action: 'update',
            resource: 'article',
            record: article(),
            input: { status: 'review' },
        });
        expect(toReview.granted).toBe(true);

        const toPublished = authz.check(aria, {
            action: 'update',
            resource: 'article',
            record: article(),
            input: { status: 'published' },
        });
        expect(toPublished.granted).toBe(false);
        expect(toPublished.reason).toBe('condition_failed');
    });

    test('authors publish their own article only after review', () => {
        expect(
            authz.check(aria, { action: 'publish', resource: 'article', record: article() }).granted,
        ).toBe(false);
        expect(
            authz.check(aria, {
                action: 'publish',
                resource: 'article',
                record: article({ status: 'review' }),
            }).granted,
        ).toBe(true);
    });

    test('approval limits are enforced by value, and admins are exempt', () => {
        const big = invoice({ amount: APPROVAL_LIMIT + 1 });
        const small = invoice({ amount: APPROVAL_LIMIT });

        expect(authz.check(mia, { action: 'approve', resource: 'invoice', record: small }).granted).toBe(true);

        const denied = authz.check(mia, { action: 'approve', resource: 'invoice', record: big });
        expect(denied.granted).toBe(false);
        expect(denied.reason).toBe('condition_failed');

        expect(authz.check(ada, { action: 'approve', resource: 'invoice', record: big }).granted).toBe(true);
    });
});

describe('schedules', () => {
    test('editors publish during business hours only', () => {
        const record = article({ authorId: alex.id, status: 'review' });
        const monday = authz.check(eddie, {
            action: 'publish',
            resource: 'article',
            record,
            now: new Date(MONDAY_10),
        });
        expect(monday.granted).toBe(true);

        const sunday = authz.check(eddie, {
            action: 'publish',
            resource: 'article',
            record,
            now: new Date(SUNDAY_10),
        });
        expect(sunday.granted).toBe(false);
        expect(sunday.reason).toBe('out_of_schedule');
    });
});

describe('mandatory gates', () => {
    test('invoices require a step-up verified session', () => {
        const unverified = actor({ id: 'usr_accountant', roles: ['accountant'], mfaVerified: false });
        const denied = authz.check(unverified, { action: 'read', resource: 'invoice', record: invoice() });
        expect(denied.granted).toBe(false);
        expect(denied.reason).toBe('require_failed');

        expect(authz.check(cara, { action: 'read', resource: 'invoice', record: invoice() }).granted).toBe(true);
    });

    test('a disabled account is denied everywhere, including by its own rules', () => {
        const disabled = actor({ id: 'usr_admin', roles: ['admin'], enabled: false, mfaVerified: true });
        const decision = authz.check(disabled, { action: 'read', resource: 'user', record: { id: 'usr_admin' } });
        expect(decision.granted).toBe(false);
        expect(decision.reason).toBe('require_failed');
    });
});

describe('deny-overrides', () => {
    test('the auditor inherits every read', () => {
        expect(authz.check(rita, { action: 'read', resource: 'invoice', record: invoice() }).granted).toBe(true);
        expect(authz.check(rita, { action: 'read', resource: 'article', record: article() }).granted).toBe(true);
        expect(authz.check(rita, { action: 'read', resource: 'audit', record: null }).granted).toBe(true);
    });

    test('and is denied every mutation — including on records it owns', () => {
        const ownInvoice = invoice({ ownerId: rita.id });
        for (const action of ['create', 'update', 'delete', 'approve']) {
            expect(
                authz.check(rita, { action, resource: 'invoice', record: ownInvoice, input: {} }).granted,
            ).toBe(false);
        }
        for (const action of ['update', 'delete', 'publish']) {
            expect(
                authz.check(rita, {
                    action,
                    resource: 'article',
                    record: article({ authorId: rita.id, status: 'review' }),
                    input: {},
                }).granted,
            ).toBe(false);
        }
    });
});

describe('attribute-level authorization', () => {
    test('secrets are unreachable through any read rule', () => {
        const user = {
            id: 'usr_admin',
            email: 'admin@example.com',
            name: 'Ada',
            passwordHash: 'argon2id$leak',
            mfaSecret: 'totp-seed',
            roles: ['admin'],
        };
        for (const who of [ada, mia, actor({ id: 'usr_admin', roles: ['user'] })]) {
            const decision = authz.check(who, { action: 'read', resource: 'user', record: user });
            const view = authz.project(decision, user);
            expect('passwordHash' in view).toBe(false);
            expect('mfaSecret' in view).toBe(false);
        }
    });

    test('writing an ungranted field is refused, not silently dropped', () => {
        const decision = authz.check(actor({ id: 'usr_reader', roles: ['user'] }), {
            action: 'update',
            resource: 'user',
            record: { id: 'usr_reader' },
            input: { roles: ['admin'] },
        });
        expect(decision.granted).toBe(true);
        expect(() => authz.sanitize(decision, { name: 'New name', roles: ['admin'] })).toThrow(HttpError);

        try {
            authz.sanitize(decision, { name: 'New name', roles: ['admin'] });
        } catch (error) {
            const httpError = error as HttpError;
            expect(httpError.status).toBe(403);
            expect(httpError.code).toBe('field_forbidden');
            expect(httpError.details?.deniedFields).toEqual(['roles']);
        }
    });

    test('granted fields pass through untouched', () => {
        const decision = authz.check(actor({ id: 'usr_reader', roles: ['user'] }), {
            action: 'update',
            resource: 'user',
            record: { id: 'usr_reader' },
            input: {},
        });
        expect(authz.sanitize(decision, { name: 'New name' })).toEqual({ name: 'New name' });
    });
});

describe('collection scope', () => {
    test('resolves how much of a collection each role may see', () => {
        expect(authz.scope(mia, { action: 'read', resource: 'user' }).scope).toBe('any');
        expect(authz.scope(actor({ id: 'usr_reader', roles: ['user'] }), { action: 'read', resource: 'user' }).scope).toBe('own');
        expect(authz.scope(guest, { action: 'read', resource: 'user' }).scope).toBe(null);
    });

    test('row-level filtering returns only the readable rows', () => {
        const rows = [
            article({ id: 'a1', status: 'published' }),
            article({ id: 'a2', status: 'draft', authorId: aria.id }),
            article({ id: 'a3', status: 'draft', authorId: alex.id }),
        ];
        expect(authz.readable(guest, { action: 'read', resource: 'article' }, rows).visible.map((r) => r.id)).toEqual(['a1']);
        expect(authz.readable(aria, { action: 'read', resource: 'article' }, rows).visible.map((r) => r.id)).toEqual(['a1', 'a2']);
        expect(authz.readable(eddie, { action: 'read', resource: 'article' }, rows).visible.map((r) => r.id)).toEqual(['a1', 'a2', 'a3']);
    });
});

describe('the engine fails closed', () => {
    test('an unknown role denies instead of throwing', () => {
        const stranger = actor({ id: 'usr_x', roles: ['wizard'] });
        expect(() => authz.check(stranger, { action: 'read', resource: 'article', record: article() })).not.toThrow();
        expect(authz.check(stranger, { action: 'read', resource: 'article', record: article() }).granted).toBe(false);
    });

    test('unknown resources and actions deny instead of throwing', () => {
        expect(authz.check(ada, { action: 'read', resource: 'dragon', record: null }).granted).toBe(false);
        expect(authz.check(ada, { action: 'teleport', resource: 'article', record: article() }).granted).toBe(false);
    });
});

describe('the policy survives serialization', () => {
    test('a snapshot round-trip reproduces the same decisions', () => {
        const restored = new Authz(createAccessControl(JSON.parse(JSON.stringify(snapshot))));
        const cases = [
            [guest, { action: 'read', resource: 'article', record: article({ status: 'published' }) }],
            [aria, { action: 'update', resource: 'article', record: article(), input: {} }],
            [rita, { action: 'approve', resource: 'invoice', record: invoice() }],
            [mia, { action: 'approve', resource: 'invoice', record: invoice({ amount: 999_999 }) }],
        ] as const;

        for (const [who, request] of cases) {
            expect(restored.check(who, request).granted).toBe(authz.check(who, request).granted);
        }
        expect(restored.ac.getRequirements()).toEqual(authz.ac.getRequirements());
    });

    test('inherited rules are visible in the effective rule list', () => {
        const rules = authz.rulesFor(['manager']);
        expect(rules.some((rule) => rule.role === 'guest')).toBe(true);
        expect(rules.some((rule) => rule.role === 'editor' && rule.action === 'publish')).toBe(true);
        expect(authz.ac.getInheritedRolesOf('manager')).toContain('author');
    });
});
