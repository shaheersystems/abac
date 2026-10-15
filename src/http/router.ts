import type { AppConfig } from '../config.ts';
import type { Db } from '../db/index.ts';
import type { Identity } from '../auth/authService.ts';
import type { AuthService } from '../auth/authService.ts';
import type { SessionService } from '../auth/sessions.ts';
import type { AuditLog } from '../rbac/audit.ts';
import type { Authz, Actor, CheckRequest, Decision } from '../rbac/authz.ts';
import { HttpError } from '../util/errors.ts';

export interface Services {
    config: AppConfig;
    db: Db;
    authz: Authz;
    audit: AuditLog;
    auth: AuthService;
    sessions: SessionService;
}

/** Everything a route handler gets. */
export interface Ctx {
    services: Services;
    request: Request;
    url: URL;
    params: Record<string, string>;
    requestId: string;
    route: string;
    identity: Identity;
    actor: Actor;
    ip: string;
    /** Simulated clock (dev only) — threaded into every time-based check. */
    now: Date | undefined;
    /** Parsed JSON body, cached. Non-objects are rejected. */
    body(): Promise<Record<string, unknown>>;
    /** Authorize or throw. The route's one line of policy. */
    authorize(request: CheckRequest): Decision;
    /** Non-throwing check, for "can they also…?" questions. */
    can(request: CheckRequest): Decision;
}

export type Handler = (ctx: Ctx) => Promise<Response> | Response;

interface Route {
    method: string;
    segments: string[];
    pattern: string;
    handler: Handler;
}

export interface RouteMatch {
    handler: Handler;
    params: Record<string, string>;
    pattern: string;
}

/**
 * A ~60-line path router. Express would do, but a dependency-free one keeps the
 * interesting part of this project — the policy layer — free of framework
 * ceremony, and makes the request lifecycle readable end to end.
 */
export class Router {
    private readonly routes: Route[] = [];

    add(method: string, pattern: string, handler: Handler): this {
        this.routes.push({
            method: method.toUpperCase(),
            pattern,
            segments: split(pattern),
            handler,
        });
        return this;
    }

    get(pattern: string, handler: Handler): this {
        return this.add('GET', pattern, handler);
    }
    post(pattern: string, handler: Handler): this {
        return this.add('POST', pattern, handler);
    }
    patch(pattern: string, handler: Handler): this {
        return this.add('PATCH', pattern, handler);
    }
    delete(pattern: string, handler: Handler): this {
        return this.add('DELETE', pattern, handler);
    }

    /** Merges another router's routes (used to compose the route modules). */
    use(other: Router): this {
        this.routes.push(...other.export());
        return this;
    }

    export(): Route[] {
        return this.routes;
    }

    match(method: string, pathname: string): RouteMatch | 'method_not_allowed' | null {
        const parts = split(pathname);
        let pathMatched = false;

        for (const route of this.routes) {
            const params = matchSegments(route.segments, parts);
            if (!params) continue;
            pathMatched = true;
            if (route.method === method.toUpperCase()) {
                return { handler: route.handler, params, pattern: route.pattern };
            }
        }
        return pathMatched ? 'method_not_allowed' : null;
    }
}

function split(path: string): string[] {
    return path.split('/').filter((segment) => segment.length > 0);
}

function matchSegments(pattern: string[], parts: string[]): Record<string, string> | null {
    if (pattern.length !== parts.length) return null;
    const params: Record<string, string> = {};
    for (let i = 0; i < pattern.length; i += 1) {
        const expected = pattern[i] as string;
        const actual = parts[i] as string;
        if (expected.startsWith(':')) params[expected.slice(1)] = decodeURIComponent(actual);
        else if (expected !== actual) return null;
    }
    return params;
}

/** Parses a JSON body, rejecting anything that is not a JSON object. */
export async function parseJsonBody(request: Request): Promise<Record<string, unknown>> {
    const raw = await request.text();
    if (raw.trim().length === 0) return {};
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw HttpError.badRequest('Request body is not valid JSON.');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw HttpError.badRequest('Request body must be a JSON object.');
    }
    return parsed as Record<string, unknown>;
}
