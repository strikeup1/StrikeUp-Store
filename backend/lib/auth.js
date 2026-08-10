import { randomToken, hmacToken, timingSafeStr } from "./crypto.js";
import { SESSION_TTL_MS, SESSION_ABS_MAX_MS, PRUNE_EVERY_MS } from "./config.js";

export const SESSION_COOKIE = "strike_store_session";

const serverSecret = randomToken(32);

export class SessionStore {
  constructor() {
    this.sessions = new Map(); // tokenHash -> { userId, csrf, createdAt, lastSeen }
    this.pruneTimer = setInterval(() => this.prune(), PRUNE_EVERY_MS);
    this.pruneTimer.unref?.();
  }

  create(userId) {
    const token = randomToken(32);
    const tokenHash = this.#hash(token);
    const now = Date.now();
    this.sessions.set(tokenHash, {
      userId,
      csrf: randomToken(16),
      createdAt: now,
      lastSeen: now
    });
    return token;
  }

  get(token) {
    if (!token) return null;
    const tokenHash = this.#hash(token);
    const session = this.sessions.get(tokenHash);
    if (!session) return null;
    const now = Date.now();
    if (now - session.createdAt > SESSION_ABS_MAX_MS || now - session.lastSeen > SESSION_TTL_MS) {
      this.sessions.delete(tokenHash);
      return null;
    }
    session.lastSeen = now;
    return { token, tokenHash, ...session };
  }

  destroy(token) {
    if (!token) return;
    this.sessions.delete(this.#hash(token));
  }

  destroyByUser(userId, keepTokenHash = null) {
    for (const [tokenHash, s] of this.sessions) {
      if (s.userId === userId && tokenHash !== keepTokenHash) {
        this.sessions.delete(tokenHash);
      }
    }
  }

  prune() {
    const now = Date.now();
    for (const [tokenHash, s] of this.sessions) {
      if (now - s.createdAt > SESSION_ABS_MAX_MS || now - s.lastSeen > SESSION_TTL_MS) {
        this.sessions.delete(tokenHash);
      }
    }
  }

  #hash(token) {
    return hmacToken(token, serverSecret);
  }
}

export class LoginLimiter {
  constructor(max = 5, windowMs = 15 * 60 * 1000) {
    this.max = max;
    this.windowMs = windowMs;
    this.buckets = new Map(); // key -> { count, resetAt }
    this.pruneTimer = setInterval(() => this.prune(), PRUNE_EVERY_MS);
    this.pruneTimer.unref?.();
  }

  key(ip, username) {
    return `${ip}:${username}`;
  }

  status(key) {
    const b = this.buckets.get(key);
    if (!b) return { allowed: true, remaining: this.max, retryInMs: 0 };
    const now = Date.now();
    if (now >= b.resetAt) {
      this.buckets.delete(key);
      return { allowed: true, remaining: this.max, retryInMs: 0 };
    }
    const retryInMs = b.resetAt - now;
    if (b.count >= this.max) return { allowed: false, remaining: 0, retryInMs };
    return { allowed: true, remaining: this.max - b.count, retryInMs };
  }

  recordFailure(key) {
    const now = Date.now();
    const b = this.buckets.get(key);
    if (!b || now >= b.resetAt) {
      this.buckets.set(key, { count: 1, resetAt: now + this.windowMs });
    } else {
      b.count += 1;
    }
  }

  clear(key) {
    this.buckets.delete(key);
  }

  prune() {
    const now = Date.now();
    for (const [key, b] of this.buckets) {
      if (now >= b.resetAt) this.buckets.delete(key);
    }
  }
}

export function csrfOk(session, headerToken) {
  return !!(session && session.csrf && timingSafeStr(session.csrf, headerToken));
}
