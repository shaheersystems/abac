import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

let tmpCounter = 0;

/**
 * Writes a file atomically: full content to a unique temporary file, then a
 * rename over the target.
 *
 * The retry loop is not paranoia — on Windows a rename can transiently fail
 * with EPERM/EBUSY while a virus scanner or search indexer holds the freshly
 * created file. Retrying briefly is the documented remedy; writing in place as
 * a last resort keeps the system available at the cost of that one write's
 * atomicity.
 */
async function writeFileAtomic(file: string, contents: string): Promise<void> {
    await mkdir(dirname(file), { recursive: true });
    tmpCounter += 1;
    const tmp = `${file}.${process.pid}.${tmpCounter}.tmp`;
    await writeFile(tmp, contents, 'utf8');

    for (let attempt = 0; attempt < 6; attempt += 1) {
        try {
            await rename(tmp, file);
            return;
        } catch (err) {
            const code = (err as NodeJS.ErrnoException).code;
            if (code !== 'EPERM' && code !== 'EACCES' && code !== 'EBUSY') throw err;
            await new Promise((resolve) => setTimeout(resolve, 10 * (attempt + 1)));
        }
    }
    await writeFile(file, contents, 'utf8');
    await rm(tmp, { force: true });
}

/**
 * A minimal document store backed by one JSON file per collection.
 *
 * It is deliberately small, but it behaves like a real repository in the ways
 * that matter for this project:
 *
 * - reads and writes are serialized through a promise chain, so two concurrent
 *   requests can never interleave a read-modify-write and lose an update;
 * - writes are atomic (`write tmp` → `rename`), so a crash mid-write cannot
 *   leave a truncated file behind;
 * - documents handed out are deep copies, so callers cannot mutate the cache.
 *
 * Swapping this for Postgres/Mongo means reimplementing this class only — no
 * route or policy code touches the filesystem.
 */
export class JsonCollection<T extends { id: string }> {
    readonly name: string;
    private readonly file: string;
    private cache: T[] | null = null;
    /** Serializes every operation; each call chains onto the previous one. */
    private queue: Promise<unknown> = Promise.resolve();

    constructor(name: string, file: string) {
        this.name = name;
        this.file = file;
    }

    private async readFromDisk(): Promise<T[]> {
        if (this.cache) return this.cache;
        try {
            const raw = await readFile(this.file, 'utf8');
            const parsed: unknown = JSON.parse(raw);
            if (!Array.isArray(parsed)) {
                throw new Error(`Collection "${this.name}" is not a JSON array.`);
            }
            this.cache = parsed as T[];
        } catch (err) {
            if ((err as NodeJS.ErrnoException).code === 'ENOENT') this.cache = [];
            else throw err;
        }
        return this.cache ?? [];
    }

    private async flush(docs: T[]): Promise<void> {
        this.cache = docs;
        await writeFileAtomic(this.file, `${JSON.stringify(docs, null, 2)}\n`);
    }

    /** Runs `fn` once every previously queued operation has settled. */
    private run<R>(fn: (docs: T[]) => Promise<R> | R): Promise<R> {
        const result = this.queue.then(async () => {
            const docs = await this.readFromDisk();
            return fn(docs);
        });
        // Keep the chain alive even if this operation rejects.
        this.queue = result.catch(() => undefined);
        return result;
    }

    async list(): Promise<T[]> {
        return this.run((docs) => structuredClone(docs));
    }

    async find(predicate: (doc: T) => boolean): Promise<T[]> {
        return this.run((docs) => structuredClone(docs.filter(predicate)));
    }

    async findOne(predicate: (doc: T) => boolean): Promise<T | null> {
        return this.run((docs) => {
            const found = docs.find(predicate);
            return found ? structuredClone(found) : null;
        });
    }

    async get(id: string): Promise<T | null> {
        return this.findOne((doc) => doc.id === id);
    }

    async count(predicate: (doc: T) => boolean = () => true): Promise<number> {
        return this.run((docs) => docs.filter(predicate).length);
    }

    async insert(doc: T): Promise<T> {
        return this.run(async (docs) => {
            if (docs.some((existing) => existing.id === doc.id)) {
                throw new Error(`Duplicate id "${doc.id}" in collection "${this.name}".`);
            }
            const next = [...docs, structuredClone(doc)];
            await this.flush(next);
            return structuredClone(doc);
        });
    }

    async update(id: string, patch: Partial<T>): Promise<T | null> {
        return this.run(async (docs) => {
            const index = docs.findIndex((doc) => doc.id === id);
            if (index === -1) return null;
            const current = docs[index] as T;
            const updated = { ...current, ...structuredClone(patch), id: current.id };
            const next = [...docs];
            next[index] = updated;
            await this.flush(next);
            return structuredClone(updated);
        });
    }

    async remove(id: string): Promise<boolean> {
        return this.run(async (docs) => {
            const next = docs.filter((doc) => doc.id !== id);
            if (next.length === docs.length) return false;
            await this.flush(next);
            return true;
        });
    }

    async removeWhere(predicate: (doc: T) => boolean): Promise<number> {
        return this.run(async (docs) => {
            const next = docs.filter((doc) => !predicate(doc));
            const removed = docs.length - next.length;
            if (removed > 0) await this.flush(next);
            return removed;
        });
    }

    /** Appends and trims to `limit` rows — used by the capped audit log. */
    async append(doc: T, limit: number): Promise<void> {
        await this.run(async (docs) => {
            const next = [...docs, structuredClone(doc)];
            await this.flush(next.length > limit ? next.slice(next.length - limit) : next);
        });
    }

    async replaceAll(docs: T[]): Promise<void> {
        await this.run(async () => {
            await this.flush(structuredClone(docs));
        });
    }
}

/** A single JSON document (not a collection) — used for the policy snapshot. */
export class JsonDocument<T> {
    private readonly file: string;
    private queue: Promise<unknown> = Promise.resolve();

    constructor(file: string) {
        this.file = file;
    }

    async read(): Promise<T | null> {
        const result = this.queue.then(async () => {
            try {
                return JSON.parse(await readFile(this.file, 'utf8')) as T;
            } catch (err) {
                if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
                throw err;
            }
        });
        this.queue = result.catch(() => undefined);
        return result;
    }

    async write(value: T): Promise<void> {
        const result = this.queue.then(() =>
            writeFileAtomic(this.file, `${JSON.stringify(value, null, 2)}\n`),
        );
        this.queue = result.catch(() => undefined);
        return result;
    }
}
