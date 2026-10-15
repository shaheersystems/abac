/**
 * The authorization vocabulary: every role, resource and action the system
 * knows about. Declaring it (rather than letting strings float around the
 * codebase) is what makes `strict` mode useful — a typo in a route becomes a
 * loud denial instead of a silent `granted: false`.
 */

export const ROLES = [
    'guest',
    'user',
    'author',
    'editor',
    'accountant',
    'manager',
    'auditor',
    'admin',
] as const;

export const RESOURCES = [
    'user',
    'article',
    'comment',
    'invoice',
    'policy',
    'audit',
] as const;

/** CRUD is built in; these are the domain verbs this app adds on top. */
export const CUSTOM_ACTIONS = ['publish', 'approve'] as const;

export type ResourceName = (typeof RESOURCES)[number];
export type ActionName = 'create' | 'read' | 'update' | 'delete' | (typeof CUSTOM_ACTIONS)[number];

/**
 * How ownership is determined per resource. The AccessControl instance is
 * configured with a resolver that consults this map, which is what makes
 * `*:own` grants actually enforce ownership instead of merely selecting an
 * attribute set.
 */
export const OWNER_FIELDS: Record<ResourceName, string> = {
    user: 'id',
    article: 'authorId',
    comment: 'authorId',
    invoice: 'ownerId',
    policy: 'id',
    audit: 'actorId',
};

/** The role handed to unauthenticated callers. */
export const ANONYMOUS_ROLE = 'guest';

export function ownerFieldFor(resource: string): string {
    return OWNER_FIELDS[resource as ResourceName] ?? 'ownerId';
}
