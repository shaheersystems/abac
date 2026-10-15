import { randomBytes, randomUUID } from 'node:crypto';

/** Prefixed, sortable-enough identifiers (`usr_3f2a…`) for readable JSON files. */
export function id(prefix: string): string {
    return `${prefix}_${randomUUID().replaceAll('-', '').slice(0, 16)}`;
}

/** 256 bits of entropy, url-safe. Used for bearer tokens. */
export function secureToken(): string {
    return randomBytes(32).toString('base64url');
}

export function nowIso(): string {
    return new Date().toISOString();
}
