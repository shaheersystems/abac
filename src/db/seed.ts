import { hashPassword } from '../auth/passwords.ts';
import type { Db } from './index.ts';
import type { Article, Comment, Invoice, User } from '../domain/types.ts';
import { buildSeedPolicy } from '../rbac/policy.ts';

/** Shared demo password. Long enough to satisfy the create-user rules. */
export const DEMO_PASSWORD = 'correct-horse-battery-staple';

export interface SeedAccount {
    key: string;
    email: string;
    name: string;
    roles: string[];
    department: string;
    mfaEnabled: boolean;
    disabled?: boolean;
}

/** The cast. One account per interesting position in the policy. */
export const SEED_ACCOUNTS: SeedAccount[] = [
    { key: 'admin', email: 'admin@example.com', name: 'Ada Admin', roles: ['admin'], department: 'platform', mfaEnabled: true },
    { key: 'manager', email: 'mia@example.com', name: 'Mia Manager', roles: ['manager'], department: 'editorial', mfaEnabled: true },
    { key: 'editor', email: 'eddie@example.com', name: 'Eddie Editor', roles: ['editor'], department: 'editorial', mfaEnabled: false },
    { key: 'author', email: 'aria@example.com', name: 'Aria Author', roles: ['author'], department: 'editorial', mfaEnabled: false },
    { key: 'author2', email: 'alex@example.com', name: 'Alex Author', roles: ['author'], department: 'editorial', mfaEnabled: false },
    { key: 'accountant', email: 'cara@example.com', name: 'Cara Accountant', roles: ['accountant'], department: 'billing', mfaEnabled: true },
    { key: 'auditor', email: 'rita@example.com', name: 'Rita Auditor', roles: ['auditor'], department: 'risk', mfaEnabled: true },
    { key: 'reader', email: 'uma@example.com', name: 'Uma User', roles: ['user'], department: 'sales', mfaEnabled: false },
    { key: 'disabled', email: 'dana@example.com', name: 'Dana Disabled', roles: ['editor'], department: 'editorial', mfaEnabled: false, disabled: true },
];

export interface SeedResult {
    users: Record<string, User>;
    articles: Record<string, Article>;
    invoices: Record<string, Invoice>;
}

/**
 * Rebuilds the JSON database from scratch: accounts, content, billing data and
 * the policy snapshot. Ids are deterministic (`usr_admin`, `art_published`) so
 * the seeded files stay diffable and the demo script can reference them.
 */
export async function seedDatabase(db: Db): Promise<SeedResult> {
    const now = new Date('2026-01-06T09:00:00.000Z').toISOString();
    const passwordHash = await hashPassword(DEMO_PASSWORD);

    const users: Record<string, User> = {};
    for (const account of SEED_ACCOUNTS) {
        users[account.key] = {
            id: `usr_${account.key}`,
            email: account.email,
            name: account.name,
            passwordHash,
            roles: account.roles,
            department: account.department,
            bio: `${account.name} — seeded ${account.roles.join('/')} account.`,
            disabled: account.disabled ?? false,
            mfaEnabled: account.mfaEnabled,
            mfaSecret: account.mfaEnabled ? `seed-secret-${account.key}` : null,
            createdAt: now,
            updatedAt: now,
        };
    }

    const article = (
        key: string,
        authorKey: string,
        title: string,
        status: Article['status'],
    ): Article => ({
        id: `art_${key}`,
        authorId: `usr_${authorKey}`,
        title,
        body: `Body of "${title}". Seeded content for the ${status} state.`,
        summary: `${title} — ${status}`,
        tags: ['seed', status],
        status,
        publishedAt: status === 'published' ? now : null,
        internalNotes: `Editorial notes for "${title}" — not visible to readers.`,
        createdAt: now,
        updatedAt: now,
    });

    const articles: Record<string, Article> = {
        published: article('published', 'author', 'Role-based access control, explained', 'published'),
        draft: article('draft', 'author', 'Attribute conditions in practice', 'draft'),
        review: article('review', 'author', 'Ownership is not a role', 'review'),
        foreignDraft: article('foreign_draft', 'author2', 'Draft by another author', 'draft'),
        editorial: article('editorial', 'editor', 'House style guide', 'published'),
    };

    const comments: Comment[] = [
        {
            id: 'cmt_reader',
            articleId: 'art_published',
            authorId: 'usr_reader',
            body: 'Clearest explanation of own vs any I have read.',
            flagged: false,
            createdAt: now,
            updatedAt: now,
        },
        {
            id: 'cmt_flagged',
            articleId: 'art_published',
            authorId: 'usr_author2',
            body: 'Off-topic comment that an editor has flagged.',
            flagged: true,
            createdAt: now,
            updatedAt: now,
        },
    ];

    const invoice = (
        key: string,
        customer: string,
        amount: number,
        status: Invoice['status'],
        ownerKey = 'accountant',
    ): Invoice => ({
        id: `inv_${key}`,
        ownerId: `usr_${ownerKey}`,
        customer,
        amount,
        currency: 'EUR',
        status,
        internalNotes: `Margin notes for ${customer} — billing eyes only.`,
        approvedBy: status === 'approved' ? 'usr_manager' : null,
        createdAt: now,
        updatedAt: now,
    });

    const invoices: Record<string, Invoice> = {
        small: invoice('small', 'Northwind Ltd', 4_500, 'draft'),
        large: invoice('large', 'Globex Corporation', 250_000, 'draft'),
        // Owned by someone else, so an accountant sees it through their
        // `read:any` rule (no `internalNotes`) rather than their `read:own` one.
        approved: invoice('approved', 'Initech', 12_000, 'approved', 'manager'),
    };

    await db.users.replaceAll(Object.values(users));
    await db.articles.replaceAll(Object.values(articles));
    await db.comments.replaceAll(comments);
    await db.invoices.replaceAll(Object.values(invoices));
    await db.sessions.replaceAll([]);
    await db.audit.replaceAll([]);
    await db.policy.write(buildSeedPolicy());

    return { users, articles, invoices };
}
