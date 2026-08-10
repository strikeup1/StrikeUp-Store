import { randomBytes, scryptSync, timingSafeEqual, createHmac } from "node:crypto";

const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("hex");
}

export function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64, SCRYPT_OPTS).toString("hex");
  return { salt, hash };
}

export function verifyPassword(password, salt, expectedHash) {
  try {
    const actual = scryptSync(password, salt, 64, SCRYPT_OPTS);
    const expected = Buffer.from(expectedHash, "hex");
    if (actual.length !== expected.length) return false;
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

export function hmacToken(token, secret) {
  return createHmac("sha256", secret).update(String(token)).digest("hex");
}

export function timingSafeStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
