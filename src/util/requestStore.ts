import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Ambient per-request data. The AccessControl `access` event fires deep inside
 * the library with no way to pass a correlation id through, so the audit sink
 * reads it from here instead of threading it through every call.
 */
export interface RequestStore {
    requestId: string;
    route: string;
    actorId: string | null;
    ip: string;
}

const storage = new AsyncLocalStorage<RequestStore>();

export function runWithRequestStore<T>(store: RequestStore, fn: () => T): T {
    return storage.run(store, fn);
}

export function currentRequest(): RequestStore | undefined {
    return storage.getStore();
}

/** Mutates the active store — used once the bearer token resolves to a user. */
export function setActor(actorId: string | null): void {
    const store = storage.getStore();
    if (store) store.actorId = actorId;
}
