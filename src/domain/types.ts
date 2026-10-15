/**
 * Domain entities. Everything here is persisted as JSON documents by the
 * `JsonCollection` store in `src/db` — the stand-in for a real database.
 */

/** Role names shipped with the seed policy. Roles are data, not code: */
/** new ones can be created at runtime through `/admin/policy/roles`. */
export type RoleName =
    | 'guest'
    | 'user'
    | 'author'
    | 'editor'
    | 'accountant'
    | 'manager'
    | 'auditor'
    | 'admin';

export interface BaseDocument {
    id: string;
    createdAt: string;
    updatedAt: string;
}

export interface User extends BaseDocument {
    email: string;
    name: string;
    /** Argon2id hash. Never leaves the process: no grant includes this field. */
    passwordHash: string;
    roles: string[];
    department: string;
    bio: string;
    disabled: boolean;
    /** Simulated second factor; `mfaSecret` is likewise never granted. */
    mfaEnabled: boolean;
    mfaSecret: string | null;
}

export type ArticleStatus = 'draft' | 'review' | 'published';

export interface Article extends BaseDocument {
    /** Ownership field for the `article` resource (see `OWNER_FIELDS`). */
    authorId: string;
    title: string;
    body: string;
    summary: string;
    tags: string[];
    status: ArticleStatus;
    publishedAt: string | null;
    /** Editorial-only field, carved out of the reader-facing grants. */
    internalNotes: string;
}

export interface Comment extends BaseDocument {
    articleId: string;
    authorId: string;
    body: string;
    flagged: boolean;
}

export type InvoiceStatus = 'draft' | 'approved' | 'paid' | 'void';

export interface Invoice extends BaseDocument {
    /** Ownership field for the `invoice` resource. */
    ownerId: string;
    customer: string;
    amount: number;
    currency: string;
    status: InvoiceStatus;
    internalNotes: string;
    approvedBy: string | null;
}

export interface Session {
    id: string;
    userId: string;
    /** Only the SHA-256 of the bearer token is stored, never the token itself. */
    tokenHash: string;
    createdAt: string;
    expiresAt: string;
    lastSeenAt: string;
    /** Step-up state: the `invoice` resource is gated on this being true. */
    mfaVerified: boolean;
    ip: string;
    userAgent: string;
}

/** One row of the access log — written for every resolved permission check. */
export interface AuditEntry {
    id: string;
    at: string;
    kind: 'access' | 'policy' | 'auth';
    requestId: string | null;
    route: string | null;
    actorId: string | null;
    roles: string[];
    resource: string | null;
    action: string | null;
    possession: 'own' | 'any' | null;
    granted: boolean;
    /** `no_grant`, `condition_failed`, `out_of_schedule`, `require_failed`, … */
    reason: string | null;
    recordId: string | null;
    attributes: string[] | null;
    detail: Record<string, unknown> | null;
}
