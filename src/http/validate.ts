import { HttpError } from '../util/errors.ts';

/**
 * Input validation, kept strictly separate from authorization: this layer
 * decides whether a value is *well formed*, never whether the caller is allowed
 * to send it. Mixing the two is how policies end up half in the engine and half
 * in a pile of `if (user.role === 'admin')`.
 */

export function requireString(
    body: Record<string, unknown>,
    key: string,
    options: { min?: number; max?: number } = {},
): string {
    const value = body[key];
    if (typeof value !== 'string' || value.trim().length === 0) {
        throw HttpError.unprocessable(`"${key}" is required and must be a non-empty string.`, { field: key });
    }
    const trimmed = value.trim();
    if (options.min !== undefined && trimmed.length < options.min) {
        throw HttpError.unprocessable(`"${key}" must be at least ${options.min} characters.`, { field: key });
    }
    if (options.max !== undefined && trimmed.length > options.max) {
        throw HttpError.unprocessable(`"${key}" must be at most ${options.max} characters.`, { field: key });
    }
    return trimmed;
}

export function optionalString(body: Record<string, unknown>, key: string, max = 20_000): string | undefined {
    if (body[key] === undefined) return undefined;
    const value = body[key];
    if (typeof value !== 'string') {
        throw HttpError.unprocessable(`"${key}" must be a string.`, { field: key });
    }
    if (value.length > max) {
        throw HttpError.unprocessable(`"${key}" must be at most ${max} characters.`, { field: key });
    }
    return value;
}

export function requireNumber(body: Record<string, unknown>, key: string, min = 0): number {
    const value = body[key];
    if (typeof value !== 'number' || !Number.isFinite(value) || value < min) {
        throw HttpError.unprocessable(`"${key}" must be a number >= ${min}.`, { field: key });
    }
    return value;
}

export function optionalStringArray(body: Record<string, unknown>, key: string): string[] | undefined {
    if (body[key] === undefined) return undefined;
    const value = body[key];
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
        throw HttpError.unprocessable(`"${key}" must be an array of strings.`, { field: key });
    }
    return value as string[];
}

export function requireEnum<T extends string>(
    body: Record<string, unknown>,
    key: string,
    allowed: readonly T[],
): T {
    const value = body[key];
    if (typeof value !== 'string' || !allowed.includes(value as T)) {
        throw HttpError.unprocessable(`"${key}" must be one of: ${allowed.join(', ')}.`, { field: key });
    }
    return value as T;
}

export function optionalEnum<T extends string>(
    body: Record<string, unknown>,
    key: string,
    allowed: readonly T[],
): T | undefined {
    if (body[key] === undefined) return undefined;
    return requireEnum(body, key, allowed);
}
