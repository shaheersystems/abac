/**
 * Transport-neutral error type. The HTTP layer turns these into the JSON error
 * envelope; everything else just throws them.
 */
export class HttpError extends Error {
    readonly status: number;
    readonly code: string;
    readonly details: Record<string, unknown> | undefined;
    readonly headers: Record<string, string> | undefined;

    constructor(
        status: number,
        code: string,
        message: string,
        details?: Record<string, unknown>,
        headers?: Record<string, string>,
    ) {
        super(message);
        this.name = 'HttpError';
        this.status = status;
        this.code = code;
        this.details = details;
        this.headers = headers;
    }

    static badRequest(message: string, details?: Record<string, unknown>): HttpError {
        return new HttpError(400, 'bad_request', message, details);
    }

    /** No (valid) credentials were presented — the client may retry with some. */
    static unauthenticated(message = 'Authentication required.'): HttpError {
        return new HttpError(401, 'unauthenticated', message, undefined, {
            'WWW-Authenticate': 'Bearer realm="api"',
        });
    }

    /** Credentials were understood, but the policy says no. */
    static forbidden(
        message: string,
        code = 'forbidden',
        details?: Record<string, unknown>,
    ): HttpError {
        return new HttpError(403, code, message, details);
    }

    static notFound(what = 'Resource'): HttpError {
        return new HttpError(404, 'not_found', `${what} not found.`);
    }

    static conflict(message: string, details?: Record<string, unknown>): HttpError {
        return new HttpError(409, 'conflict', message, details);
    }

    static unprocessable(message: string, details?: Record<string, unknown>): HttpError {
        return new HttpError(422, 'unprocessable_entity', message, details);
    }

    static tooManyRequests(message: string, retryAfterSeconds: number): HttpError {
        return new HttpError(429, 'too_many_requests', message, { retryAfterSeconds }, {
            'Retry-After': String(retryAfterSeconds),
        });
    }

    static internal(message = 'Internal server error.'): HttpError {
        return new HttpError(500, 'internal_error', message);
    }
}
