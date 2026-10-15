import type { AccessControl, ISnapshot } from 'accesscontrol';
import { createAccessControl } from './accessControl.ts';

/** Invoices above this amount need a role with an unconditional grant. */
export const APPROVAL_LIMIT = 100_000;

/** dtrexp expression: Monday–Friday, 09:00–18:00 (see https://dtrexp.org). */
export const BUSINESS_HOURS = 'T0900:1800 E1:5';

/** Fields no grant may ever expose, kept in one place so reviews are cheap. */
const USER_SECRETS = ['!passwordHash', '!mfaSecret'] as const;

/**
 * The seed policy — the single source of truth for who may do what.
 *
 * It is expressed once, in code, and then **persisted as data**
 * (`data/policy.json`) so it can be edited at runtime through the admin API
 * and reloaded on boot. Code here is the bootstrap, not the runtime authority.
 *
 * Conventions used throughout:
 * - `*:own` rules rely on the ownership resolver (`isOwner`) — the caller must
 *   actually own the record.
 * - Attribute lists are the second half of every grant: *what* is readable or
 *   writable, not just *whether*. `['*', '!internalNotes']` is a field-level
 *   deny that survives inheritance.
 * - `.where()` conditions may read the record (`$.article.status`), the
 *   incoming request body (`$.input.*`) or the environment (`$.mfa`).
 */
export function definePolicy(ac: AccessControl): AccessControl {
    // ----------------------------------------------------------------------
    // Mandatory gates. `.require()` can only restrict: a check is granted when
    // a rule matches AND every applicable gate passes. Gates are the right
    // place for cross-cutting, non-negotiable conditions.
    // ----------------------------------------------------------------------

    // Nobody — no matter how privileged — acts through a disabled account.
    // Written in the positive form so a missing context value fails closed.
    ac.require(['$.actorEnabled', '==', true]);

    // Everything about invoices requires a step-up-verified session.
    ac.resource('invoice').require(['$.mfa', '==', true]);

    // ----------------------------------------------------------------------
    // guest — unauthenticated callers
    // ----------------------------------------------------------------------
    ac.grant('guest')
        .where(['$.article.status', '==', 'published'])
        .readAny('article', ['*', '!internalNotes']);
    ac.grant('guest').readAny('comment', ['*', '!flagged']);

    // ----------------------------------------------------------------------
    // user — any authenticated account
    // ----------------------------------------------------------------------
    ac.grant('user')
        .extend('guest')
        .readOwn('user', ['*', ...USER_SECRETS])
        // Self-service profile edits. `roles` and `disabled` are absent by
        // design: privilege escalation is a field-level concern here.
        // `password` is a write-only virtual field consumed by
        // `POST /users/:id/password`.
        .updateOwn('user', ['name', 'email', 'bio', 'department', 'password'])
        .createOwn('comment', ['articleId', 'body'])
        .updateOwn('comment', ['body'])
        .deleteOwn('comment');

    // ----------------------------------------------------------------------
    // author — writes articles
    // ----------------------------------------------------------------------
    ac.grant('author')
        .extend('user')
        .createOwn('article', ['title', 'body', 'summary', 'tags'])
        .readOwn('article', ['*', '!internalNotes']);

    // Editable only while unpublished, and the body of the request may never
    // set `status: published` — the negative comparison is intentional: it
    // passes when the field is absent (i.e. the patch does not touch status).
    ac.grant('author')
        .where({
            and: [
                {
                    or: [
                        ['$.article.status', '==', 'draft'],
                        ['$.article.status', '==', 'review'],
                    ],
                },
                ['$.input.status', '!=', 'published'],
            ],
        })
        .updateOwn('article', ['title', 'body', 'summary', 'tags', 'status']);

    ac.grant('author').where(['$.article.status', '==', 'draft']).deleteOwn('article');

    // An author may publish their own article once it has cleared review.
    ac.grant('author')
        .where(['$.article.status', '==', 'review'])
        .action('publish:own', 'article', ['*']);

    // ----------------------------------------------------------------------
    // editor — owns the editorial pipeline
    // ----------------------------------------------------------------------
    ac.grant('editor')
        .extend('author')
        .readAny('article', ['*'])
        .updateAny('article', ['*', '!id', '!authorId'])
        .deleteAny('article')
        .updateAny('comment', ['flagged'])
        .deleteAny('comment')
        .readAny('user', ['id', 'name', 'email', 'department', 'roles']);

    // Publishing is a business-hours operation. A denial outside the window
    // reports `out_of_schedule`, so the UI can say "not now" instead of "no".
    ac.grant('editor').during(BUSINESS_HOURS).action('publish:any', 'article', ['*']);

    // ----------------------------------------------------------------------
    // accountant — billing back office
    // ----------------------------------------------------------------------
    ac.grant('accountant')
        .extend('user')
        .readAny('invoice', ['*', '!internalNotes'])
        .createOwn('invoice', ['customer', 'amount', 'currency', 'internalNotes'])
        .readOwn('invoice', ['*']);

    ac.grant('accountant')
        .where(['$.invoice.status', '==', 'draft'])
        .updateOwn('invoice', ['customer', 'amount', 'currency', 'internalNotes']);

    // ----------------------------------------------------------------------
    // manager — editorial + billing authority
    // ----------------------------------------------------------------------
    ac.grant('manager')
        .extend(['editor', 'accountant'])
        .readAny('invoice', ['*'])
        .readAny('user', ['*', ...USER_SECRETS]);

    ac.grant('manager')
        .where(['$.invoice.amount', '<=', APPROVAL_LIMIT])
        .updateAny('invoice', ['customer', 'amount', 'currency', 'internalNotes', 'status']);

    ac.grant('manager')
        .where({
            and: [
                ['$.invoice.amount', '<=', APPROVAL_LIMIT],
                ['$.invoice.status', '==', 'draft'],
            ],
        })
        .action('approve:any', 'invoice', ['*']);

    // ----------------------------------------------------------------------
    // auditor — read-only manager. Demonstrates deny-overrides: the role
    // inherits everything a manager can do, then has every mutation carved
    // back out.
    //
    // Every deny is written for **both** possessions on purpose. A `deny` does
    // not cascade across possession — `deny update:any` deliberately leaves
    // `update:own` intact — so a read-only role has to say both, or it keeps
    // the half nobody thought to revoke.
    // ----------------------------------------------------------------------
    ac.grant('auditor').extend('manager').readAny('audit', ['*']);
    ac.deny('auditor')
        .createAny('invoice')
        .updateAny('invoice')
        .deleteAny('invoice')
        .action('approve:any', 'invoice')
        .createAny('article')
        .updateAny('article')
        .deleteAny('article')
        .action('publish:any', 'article')
        .createAny('comment')
        .updateAny('comment')
        .deleteAny('comment')
        .createAny('user')
        .updateAny('user')
        .deleteAny('user');
    ac.deny('auditor')
        .createOwn('invoice')
        .updateOwn('invoice')
        .deleteOwn('invoice')
        .createOwn('article')
        .updateOwn('article')
        .deleteOwn('article')
        .action('publish:own', 'article')
        .createOwn('comment')
        .updateOwn('comment')
        .deleteOwn('comment')
        .updateOwn('user')
        .action('approve:own', 'invoice');

    // ----------------------------------------------------------------------
    // admin — user administration and the policy itself
    // ----------------------------------------------------------------------
    ac.grant('admin')
        .extend('manager')
        .createAny('user', ['email', 'name', 'roles', 'department', 'bio', 'password'])
        .readAny('user', ['*', ...USER_SECRETS])
        .updateAny('user', ['name', 'email', 'bio', 'department', 'roles', 'disabled', 'password'])
        .deleteAny('user')
        .readAny('audit', ['*'])
        .createAny('policy')
        .readAny('policy')
        .updateAny('policy')
        .deleteAny('policy')
        // Unconditional approval rights: rules are additive, so this sits
        // alongside the manager's capped rule rather than replacing it.
        .action('approve:any', 'invoice', ['*'])
        .createAny('invoice', ['customer', 'amount', 'currency', 'internalNotes'])
        .updateAny('invoice', ['*', '!id', '!ownerId'])
        .deleteAny('invoice');

    return ac;
}

/** Builds the seed policy and returns it in serializable form. */
export function buildSeedPolicy(): ISnapshot {
    return definePolicy(createAccessControl()).snapshot();
}
