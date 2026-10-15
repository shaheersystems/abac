/**
 * Password hashing. Argon2id with Bun's built-in bindings — no plaintext, no
 * home-grown crypto, and `verify` reads the algorithm out of the stored hash so
 * parameters can be raised later without invalidating existing accounts.
 */
export async function hashPassword(password: string): Promise<string> {
    return Bun.password.hash(password, { algorithm: 'argon2id' });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
        return await Bun.password.verify(password, hash);
    } catch {
        // A malformed stored hash must read as "wrong password", not as a crash.
        return false;
    }
}
