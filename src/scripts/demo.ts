/**
 * A scripted tour of the policy, run against the real HTTP handler in-process.
 *
 *   bun run demo
 *
 * Every line is a real request through `app.fetch` — same routes, same engine,
 * same audit log as the served API. The database is a throwaway directory so
 * the demo never touches `data/`.
 */
import { rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { loadConfig } from '../config.ts';
import { createDb } from '../db/index.ts';
import { DEMO_PASSWORD, seedDatabase } from '../db/seed.ts';
import { createApp } from '../http/app.ts';

const dataDir = resolve(process.env.DEMO_DATA_DIR ?? 'data-demo');
await rm(dataDir, { recursive: true, force: true });

const config = loadConfig({ dataDir, env: 'development', allowTimeTravel: true });
const db = createDb(dataDir);
await seedDatabase(db);
const app = await createApp(config, db);

const MONDAY_10 = '2026-01-05T10:00:00.000Z';
const SUNDAY_10 = '2026-01-04T10:00:00.000Z';

interface CallOptions {
    token?: string | undefined;
    body?: unknown;
    now?: string | undefined;
}

interface CallResult {
    status: number;
    body: any;
}

async function call(method: string, path: string, options: CallOptions = {}): Promise<CallResult> {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (options.token) headers.authorization = `Bearer ${options.token}`;
    if (options.now) headers['x-simulated-now'] = options.now;
    const response = await app.fetch(
        new Request(`http://demo.local${path}`, {
            method,
            headers,
            ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
        }),
    );
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function login(email: string): Promise<string> {
    const result = await call('POST', '/auth/login', {
        body: { email, password: DEMO_PASSWORD },
    });
    if (result.status !== 201) throw new Error(`Login failed for ${email}: ${JSON.stringify(result.body)}`);
    return result.body.token as string;
}

function section(title: string): void {
    console.log(`\n\x1b[1m── ${title} ${'─'.repeat(Math.max(0, 62 - title.length))}\x1b[0m`);
}

function show(label: string, result: CallResult, note: string): void {
    const ok = result.status < 400;
    const status = `${ok ? '\x1b[32m' : '\x1b[31m'}${result.status}\x1b[0m`;
    const code = ok ? '' : `\x1b[2m${result.body?.error?.code ?? ''}\x1b[0m`;
    console.log(`  ${label.padEnd(46)} ${status} ${code.padEnd(28)} ${note}`);
}

// ── 1. Anonymous ──────────────────────────────────────────────────────────
section('1 · Anonymous callers hold the "guest" role');

const guestArticles = await call('GET', '/articles');
show('GET /articles', guestArticles, `${guestArticles.body.count} of 5 rows — published only`);
console.log(
    `     fields returned: ${Object.keys(guestArticles.body.data[0] ?? {}).join(', ')}` +
        `\n     \x1b[2m(internalNotes was removed by the grant's attribute list, not by the handler)\x1b[0m`,
);
show('GET /articles/art_draft', await call('GET', '/articles/art_draft'), 'unpublished → condition fails → 401');
show('POST /articles', await call('POST', '/articles', { body: { title: 'x', body: 'y' } }), 'no credentials → 401, not 403');

// ── 2. Author ─────────────────────────────────────────────────────────────
section('2 · author — ownership, conditions and field-level writes');
const author = await login('aria@example.com');

const authorArticles = await call('GET', '/articles', { token: author });
show('GET /articles', authorArticles, `${authorArticles.body.count} rows — published + own drafts`);
show(
    'PATCH /articles/art_draft (own draft)',
    await call('PATCH', '/articles/art_draft', { token: author, body: { title: 'Revised title' } }),
    'own + status=draft → allowed',
);
show(
    'PATCH /articles/art_draft {status:published}',
    await call('PATCH', '/articles/art_draft', { token: author, body: { status: 'published' } }),
    'condition reads $.input.status → denied',
);
show(
    'PATCH /articles/art_foreign_draft',
    await call('PATCH', '/articles/art_foreign_draft', { token: author, body: { title: 'nope' } }),
    "another author's draft → not owner",
);
show(
    'POST /articles/art_draft/publish',
    await call('POST', '/articles/art_draft/publish', { token: author }),
    'publish:own requires status=review',
);
show(
    'PATCH /articles/art_draft {status:review}',
    await call('PATCH', '/articles/art_draft', { token: author, body: { status: 'review' } }),
    'draft → review is allowed',
);
show(
    'POST /articles/art_draft/publish',
    await call('POST', '/articles/art_draft/publish', { token: author }),
    'now in review → author may publish',
);
const escalation = await call('PATCH', '/users/usr_author', {
    token: author,
    body: { name: 'Aria', roles: ['admin'] },
});
show('PATCH /users/usr_author {roles:[admin]}', escalation, `${escalation.body?.error?.details?.deniedFields}`);

// ── 3. Editor ─────────────────────────────────────────────────────────────
section('3 · editor — inherited rules plus a scheduled action');
const editor = await login('eddie@example.com');

show(
    'POST /articles/art_foreign_draft/publish (Sun)',
    await call('POST', '/articles/art_foreign_draft/publish', { token: editor, now: SUNDAY_10 }),
    'outside T0900:1800 E1:5 → "not now"',
);
show(
    'POST /articles/art_foreign_draft/publish (Mon)',
    await call('POST', '/articles/art_foreign_draft/publish', { token: editor, now: MONDAY_10 }),
    'inside business hours → allowed',
);
const editorRead = await call('GET', '/articles/art_review', { token: editor });
show('GET /articles/art_review', editorRead, `sees internalNotes: ${'internalNotes' in editorRead.body.data}`);

// ── 4. Billing ────────────────────────────────────────────────────────────
section('4 · accountant — a require() gate the client can resolve');
const accountant = await login('cara@example.com');

show('GET /invoices (no step-up)', await call('GET', '/invoices', { token: accountant }), 'gate: $.mfa == true');
show(
    'POST /auth/mfa/verify',
    await call('POST', '/auth/mfa/verify', { token: accountant, body: { code: config.mfaCode } }),
    'session is elevated',
);
const created = await call('POST', '/invoices', {
    token: accountant,
    body: { customer: 'Umbrella Corp', amount: 9_900, internalNotes: 'Renewal, 30 days' },
});
show('POST /invoices', created, 'create:own — the row is stamped with the caller');
const freshInvoiceId = created.body?.data?.id as string;

const invoices = await call('GET', '/invoices', { token: accountant });
const own = invoices.body.data.find((i: any) => i.id === 'inv_small');
const foreign = invoices.body.data.find((i: any) => i.id === 'inv_approved');
show('GET /invoices (after step-up)', invoices, `${invoices.body.count} rows`);
console.log(
    `     own invoice fields    : ${Object.keys(own ?? {}).length} (internalNotes: ${'internalNotes' in (own ?? {})})` +
        `\n     foreign invoice fields: ${Object.keys(foreign ?? {}).length} (internalNotes: ${'internalNotes' in (foreign ?? {})})` +
        `\n     \x1b[2m(same list, same request — read:own and read:any grant different fields)\x1b[0m`,
);

// ── 5. Approval limits ────────────────────────────────────────────────────
section('5 · manager vs admin — a value ceiling on a custom action');
const manager = await login('mia@example.com');
await call('POST', '/auth/mfa/verify', { token: manager, body: { code: config.mfaCode } });

show(
    'POST /invoices/inv_small/approve',
    await call('POST', '/invoices/inv_small/approve', { token: manager }),
    '4 500 ≤ 100 000 → allowed',
);
show(
    'POST /invoices/inv_large/approve',
    await call('POST', '/invoices/inv_large/approve', { token: manager }),
    '250 000 > limit → condition fails',
);

const admin = await login('admin@example.com');
await call('POST', '/auth/mfa/verify', { token: admin, body: { code: config.mfaCode } });
show(
    'POST /invoices/inv_large/approve (admin)',
    await call('POST', '/invoices/inv_large/approve', { token: admin }),
    'admin holds an unconditional rule',
);

// ── 6. Deny-overrides ─────────────────────────────────────────────────────
section('6 · auditor — inherits everything, denied every mutation');
const auditor = await login('rita@example.com');
await call('POST', '/auth/mfa/verify', { token: auditor, body: { code: config.mfaCode } });

const auditorInvoices = await call('GET', '/invoices', { token: auditor });
show('GET /invoices', auditorInvoices, `${auditorInvoices.body.count} rows — inherited read from manager`);
show(
    `POST /invoices/${freshInvoiceId}/approve`,
    await call('POST', `/invoices/${freshInvoiceId}/approve`, { token: auditor }),
    'a manager could approve this one',
);

// ── 7. Runtime policy changes ─────────────────────────────────────────────
section('7 · admin — the policy itself is editable data');

show(
    'POST /admin/policy/roles {contributor}',
    await call('POST', '/admin/policy/roles', {
        token: admin,
        body: { role: 'contributor', extend: ['user'] },
    }),
    'new role, inherits user',
);
show(
    'POST /admin/policy/rules',
    await call('POST', '/admin/policy/rules', {
        token: admin,
        body: {
            role: 'contributor',
            resource: 'article',
            action: 'create',
            possession: 'own',
            attributes: ['title', 'body', 'tags'],
        },
    }),
    'contributor may now draft articles',
);
show(
    'POST /admin/policy/rules',
    await call('POST', '/admin/policy/rules', {
        token: admin,
        body: {
            role: 'contributor',
            resource: 'article',
            action: 'read',
            possession: 'own',
            attributes: ['*', '!internalNotes'],
        },
    }),
    '…and read their own drafts back',
);

const reader = await login('uma@example.com');
show(
    'POST /articles (as plain user)',
    await call('POST', '/articles', { token: reader, body: { title: 'Hi', body: 'There' } }),
    'user has no create rule',
);
show(
    'PATCH /users/usr_reader {roles:[contributor]}',
    await call('PATCH', '/users/usr_reader', { token: admin, body: { roles: ['contributor'] } }),
    'admin assigns the new role',
);
const readerAgain = await login('uma@example.com');
show(
    'POST /articles (as contributor)',
    await call('POST', '/articles', { token: readerAgain, body: { title: 'Hi', body: 'There' } }),
    'same user, no redeploy',
);

// ── 8. Audit ──────────────────────────────────────────────────────────────
section('8 · every decision was logged by the engine itself');
await app.services.audit.flush();
const audit = await call('GET', '/admin/audit?limit=8', { token: admin });
for (const row of audit.body.data as any[]) {
    const verdict = row.granted ? '\x1b[32mallow\x1b[0m' : `\x1b[31mdeny \x1b[0m`;
    console.log(
        `  ${verdict} ${String(row.action ?? '-').padEnd(8)} ${String(row.resource ?? '-').padEnd(9)}` +
            ` ${String(row.possession ?? '-').padEnd(4)} ${String(row.reason ?? '').padEnd(17)}` +
            ` ${String(row.actorId ?? 'anonymous').padEnd(14)} ${row.route ?? ''}`,
    );
}
const total = await db.audit.count();
console.log(`\n  ${total} audit rows written to ${dataDir}/audit.json`);
console.log(`  policy snapshot (now including "contributor") in ${dataDir}/policy.json\n`);
