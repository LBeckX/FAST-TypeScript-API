import * as argon2 from "argon2";

export async function comparePassword(hash: string, password: string) {
    try {
        return await argon2.verify(hash, password);
    } catch (err) {
        return false;
    }
}