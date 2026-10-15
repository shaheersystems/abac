import { join } from 'node:path';
import type { ISnapshot } from 'accesscontrol';
import type { Article, AuditEntry, Comment, Invoice, Session, User } from '../domain/types.ts';
import { JsonCollection, JsonDocument } from './jsonStore.ts';

export interface Db {
    readonly dataDir: string;
    readonly users: JsonCollection<User>;
    readonly articles: JsonCollection<Article>;
    readonly comments: JsonCollection<Comment>;
    readonly invoices: JsonCollection<Invoice>;
    readonly sessions: JsonCollection<Session>;
    readonly audit: JsonCollection<AuditEntry>;
    /** The AccessControl snapshot: grants + require() gates + vocabulary. */
    readonly policy: JsonDocument<ISnapshot>;
}

export function createDb(dataDir: string): Db {
    const file = (name: string): string => join(dataDir, `${name}.json`);
    return {
        dataDir,
        users: new JsonCollection<User>('users', file('users')),
        articles: new JsonCollection<Article>('articles', file('articles')),
        comments: new JsonCollection<Comment>('comments', file('comments')),
        invoices: new JsonCollection<Invoice>('invoices', file('invoices')),
        sessions: new JsonCollection<Session>('sessions', file('sessions')),
        audit: new JsonCollection<AuditEntry>('audit', file('audit')),
        policy: new JsonDocument<ISnapshot>(file('policy')),
    };
}

export { JsonCollection, JsonDocument };
