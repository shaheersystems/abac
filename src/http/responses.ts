import { HttpError } from '../util/errors.ts';

export function json(data: unknown, init: ResponseInit = {}): Response {
    return new Response(JSON.stringify(data, null, 2), {
        status: init.status ?? 200,
        headers: { 'content-type': 'application/json; charset=utf-8', ...init.headers },
    });
}

export function noContent(): Response {
    return new Response(null, { status: 204 });
}

/**
 * One error envelope for the whole API. Authorization failures carry their
 * `reason` and the `resource`/`action` that was checked — enough for a client
 * to tell "log in", "verify your second factor" and "you will never be allowed
 * to do this" apart.
 */
export function errorResponse(error: unknown, requestId: string): Response {
    const httpError =
        error instanceof HttpError
            ? error
            : HttpError.internal(
                  error instanceof Error ? `Unexpected error: ${error.message}` : 'Unexpected error.',
              );

    if (!(error instanceof HttpError)) {
        console.error(`[${requestId}]`, error);
    }

    return json(
        {
            error: {
                code: httpError.code,
                message: httpError.message,
                ...(httpError.details ? { details: httpError.details } : {}),
                requestId,
            },
        },
        { status: httpError.status, headers: { ...httpError.headers, 'x-request-id': requestId } },
    );
}
