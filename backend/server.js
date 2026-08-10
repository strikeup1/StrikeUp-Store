import http from "node:http";
import path from "node:path";
import zlib from "node:zlib";
import { promises as fs, createReadStream } from "node:fs";

import {
  PORT,
  FRONTEND_DIR,
  FRONTEND_INDEX,
  ADMIN_INDEX,
  ADMIN_PATH,
  UPLOADS_DIR,
  JSON_BODY_LIMIT,
  ROLES,
  LOGIN_RATE,
  TRACK_RATE,
  EVENT_UA_MAX
} from "./lib/config.js";
import { Store } from "./lib/store.js";
import { SessionStore, LoginLimiter, csrfOk } from "./lib/auth.js";
import { hashPassword, verifyPassword, randomToken } from "./lib/crypto.js";
import {
  sanitizeApp,
  sanitizeCategory,
  sanitizeUsername,
  validatePassword,
  cleanRole,
  cleanText,
  cleanMultiLine
} from "./lib/sanitize.js";
import { saveUpload, deleteUploadFile } from "./lib/uploads.js";
import { SITE } from "./lib/defaults.js";

/* ------------------------------------------------------------------ */
/* Setup                                                               */
/* ------------------------------------------------------------------ */

const store = new Store();
const sessions = new SessionStore();
const limiter = new LoginLimiter(LOGIN_RATE.max, LOGIN_RATE.windowMs);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".apk": "application/vnd.android.package-archive",
  ".map": "application/json; charset=utf-8"
};

const BLOCKED_SEGMENTS = new Set(["server.js", "lib", "data", ".git", "node_modules", "uploads", "test"]);

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function isHttps(req) {
  return (
    (req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https" ||
    req.socket.encrypted === true
  );
}

function securityHeaders(req) {
  const h = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy":
      "default-src 'self'; " +
      "script-src 'self' https://pagead2.googlesyndication.com https://*.googlesyndication.com https://googleads.g.doubleclick.net; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https://*.googlesyndication.com https://*.g.doubleclick.net; " +
      "frame-src https://googleads.g.doubleclick.net https://*.googlesyndication.com; " +
      "connect-src 'self' https://pagead2.googlesyndication.com https://*.google.com https://*.g.doubleclick.net; " +
      "font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
  };
  if (isHttps(req)) h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
  return h;
}

function sendJson(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  sendRaw(res, status, body, "application/json; charset=utf-8", { "Cache-Control": "no-store", ...headers });
}

function sendText(res, status, text, headers = {}) {
  sendRaw(res, status, text, "text/plain; charset=utf-8", { "Cache-Control": "no-cache", ...headers });
}

const GZIP_TYPES = new Set([
  "text/html",
  "text/css",
  "text/plain",
  "text/javascript",
  "application/javascript",
  "application/json",
  "application/xml",
  "image/svg+xml",
  "font/woff2",
  "application/manifest+json"
]);
const GZIP_MAX_BYTES = 2 * 1024 * 1024;

function wantsGzip(req, type, size) {
  if (!GZIP_TYPES.has(type)) return false;
  if (size !== null && size > GZIP_MAX_BYTES) return false;
  return /\bgzip\b/.test((req.headers["accept-encoding"] || "").toLowerCase());
}

function sendRaw(res, status, body, contentType, extraHeaders = {}) {
  const buf = Buffer.from(body);
  const type = contentType.split(";")[0];
  if (wantsGzip(res.req, type, buf.length)) {
    zlib.gzip(buf, (gzipErr, gz) => {
      if (gzipErr) return sendPlain(res, status, buf, contentType, extraHeaders);
      res.writeHead(status, {
        "Content-Type": contentType,
        "Content-Encoding": "gzip",
        "Content-Length": gz.length,
        "Vary": "Accept-Encoding",
        ...extraHeaders
      });
      res.end(gz);
    });
    return;
  }
  sendPlain(res, status, buf, contentType, extraHeaders);
}

function sendPlain(res, status, buf, contentType, extraHeaders) {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": buf.length,
    ...extraHeaders
  });
  res.end(buf);
}

function sendNoContent(res) {
  res.writeHead(204, { "Cache-Control": "no-cache" });
  res.end();
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > -1) {
      try {
        out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
      } catch {
        out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
      }
    }
  }
  return out;
}

function setSessionCookie(res, token, req) {
  const secure = isHttps(req) || process.env.SECURE_COOKIE === "1" ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `strike_store_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${7 * 24 * 60 * 60}` + secure
  );
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", `strike_store_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress || "0.0.0.0";
}

function originOk(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const host = req.headers.host;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

async function readJsonBody(req) {
  const len = Number(req.headers["content-length"] || 0);
  if (len > JSON_BODY_LIMIT) return { status: 413, body: null };
  let raw = "";
  try {
    for await (const chunk of req) {
      raw += chunk;
      if (Buffer.byteLength(raw) > JSON_BODY_LIMIT) return { status: 413, body: null };
    }
  } catch {
    return { status: 400, body: null };
  }
  if (!raw) return { status: 400, body: null };
  try {
    return { status: 200, body: JSON.parse(raw) };
  } catch {
    return { status: 400, body: null };
  }
}

/** Read a JSON body or send a 4xx error. Returns null on error. */
async function readJson(req, res) {
  const { status, body } = await readJsonBody(req);
  if (status !== 200) {
    sendJson(res, status === 413 ? 413 : 400, { error: "Invalid request body" });
    return null;
  }
  return body;
}

/** Drain an unread request body (used when rejecting a large upload early). */
function drain(req) {
  return new Promise((resolve) => {
    req.resume();
    req.on("end", resolve);
    req.on("error", resolve);
    setTimeout(resolve, 3000);
  });
}

function rank(user) {
  return user && ROLES[user.role] ? ROLES[user.role] : 0;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    active: user.active,
    createdAt: user.createdAt,
    lastLogin: user.lastLogin
  };
}

async function requireSession(req, res) {
  const token = parseCookies(req)["strike_store_session"];
  if (!token) {
    sendJson(res, 401, { error: "Not authenticated" });
    return null;
  }
  const session = sessions.get(token);
  if (!session) {
    sendJson(res, 401, { error: "Not authenticated" });
    return null;
  }
  const users = await store.users();
  const user = users.find((u) => u.id === session.userId);
  if (!user || !user.active) {
    sessions.destroy(token);
    sendJson(res, 401, { error: "Not authenticated" });
    return null;
  }
  return { session, user };
}

function requireCsrf(req, res, session) {
  if (!csrfOk(session, req.headers["x-csrf-token"])) {
    sendJson(res, 403, { error: "Invalid or missing CSRF token" });
    return false;
  }
  return true;
}

/* ------------------------------------------------------------------ */
/* Rate limiting for download tracking                                 */
/* ------------------------------------------------------------------ */

const trackHits = new Map();
function trackAllowed(ip) {
  const now = Date.now();
  const rec = trackHits.get(ip);
  if (!rec || now > rec.reset) {
    trackHits.set(ip, { n: 1, reset: now + TRACK_RATE.windowMs });
    return true;
  }
  rec.n += 1;
  return rec.n <= TRACK_RATE.max;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of trackHits) if (now > rec.reset) trackHits.delete(ip);
}, TRACK_RATE.windowMs).unref?.();

/* ------------------------------------------------------------------ */
/* Rate limiting for public reviews                                     */
/* ------------------------------------------------------------------ */

const REVIEW_RATE = { max: 5, windowMs: 10 * 60 * 1000 };
const reviewHits = new Map();
function reviewAllowed(ip) {
  const now = Date.now();
  const rec = reviewHits.get(ip);
  if (!rec || now > rec.reset) {
    reviewHits.set(ip, { n: 1, reset: now + REVIEW_RATE.windowMs });
    return true;
  }
  rec.n += 1;
  return rec.n <= REVIEW_RATE.max;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of reviewHits) if (now > rec.reset) reviewHits.delete(ip);
}, REVIEW_RATE.windowMs).unref?.();

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

function publicApp(app, category, rating) {
  return {
    id: app.id,
    name: app.name,
    slug: app.slug,
    tagline: app.tagline,
    iconUrl: app.iconUrl,
    apkUrl: app.apkUrl,
    downloadUrl: app.downloadUrl || "",
    version: app.version,
    changelog: app.changelog,
    minAndroid: app.minAndroid,
    fileSizeMb: app.fileSizeMb,
    downloadCount: app.downloadCount || 0,
    viewCount: app.viewCount || 0,
    updatedAt: app.updatedAt,
    featured: !!app.featured,
    hasFile: !!app.apkUrl,
    rating: rating || { avg: 0, count: 0 },
    category: category
      ? { id: category.id, name: category.name, slug: category.slug, color: category.color }
      : null
  };
}

async function ratingLookup() {
  const reviews = await store.reviews();
  const out = {};
  for (const appId of Object.keys(reviews)) {
    out[appId] = store.ratingFor(reviews[appId]);
  }
  return out;
}

function publicAds(s) {
  return {
    enabled: !!(s.adsEnabled && (s.adMode === "adsense" ? s.adClient : true)),
    mode: s.adMode === "adsense" ? "adsense" : "dummy",
    client: s.adClient || "",
    leaderboard: s.adSlotLeaderboard || "",
    native: s.adSlotNative || "",
    detail: s.adSlotDetail || "",
    interstitial: s.adSlotInterstitial || "",
    sticky: s.adSlotSticky || ""
  };
}

async function categoryWithCounts() {
  const apps = await store.apps();
  const categories = await store.categories();
  return categories.map((c) => {
    const count = apps.filter((a) => a.status === "published" && a.categoryId === c.id).length;
    return { id: c.id, name: c.name, slug: c.slug, color: c.color, count };
  });
}

async function apiHome(req, res) {
  const apps = await store.apps();
  const published = apps.filter((a) => a.status === "published");
  const categories = await store.categories();
  const ratings = await ratingLookup();

  const featured = published
    .filter((a) => a.featured)
    .sort(
      (a, b) =>
        (a.featuredOrder ?? 999) - (b.featuredOrder ?? 999) || b.updatedAt.localeCompare(a.updatedAt)
    )
    .map((a) => publicApp(a, categories.find((c) => c.id === a.categoryId), ratings[a.id]));

  const latest = [...published]
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    .slice(0, 8)
    .map((a) => publicApp(a, categories.find((c) => c.id === a.categoryId), ratings[a.id]));

  const settings = await store.settings();
  sendJson(res, 200, {
    site: settings,
    ads: publicAds(settings),
    stats: {
      totalApps: published.length,
      totalDownloads: published.reduce((s, a) => s + (a.downloadCount || 0), 0)
    },
    categories: await categoryWithCounts(),
    featured,
    latest
  });
}

async function apiListApps(req, res, url) {
  const q = cleanText(url.searchParams.get("q"), 100).toLowerCase();
  const categorySlug = cleanText(url.searchParams.get("category"), 60);
  const sort = ["newest", "popular", "az"].includes(url.searchParams.get("sort"))
    ? url.searchParams.get("sort")
    : "newest";
  const page = Math.max(1, Math.floor(Number(url.searchParams.get("page")) || 1));
  const perPage = Math.min(48, Math.max(1, Math.floor(Number(url.searchParams.get("perPage")) || 12)));

  const apps = await store.apps();
  const categories = await store.categories();
  let list = apps.filter((a) => a.status === "published");

  let category = null;
  if (categorySlug) {
    category = categories.find((c) => c.slug === categorySlug) || null;
    if (!category) return sendJson(res, 200, { apps: [], total: 0, page, pages: 0, perPage, category: null });
    list = list.filter((a) => a.categoryId === category.id);
  }
  if (q) {
    list = list.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.tagline.toLowerCase().includes(q) ||
        (a.description || "").toLowerCase().includes(q)
    );
  }

  if (sort === "popular") list.sort((a, b) => (b.downloadCount || 0) - (a.downloadCount || 0));
  else if (sort === "az") list.sort((a, b) => a.name.localeCompare(b.name));
  else list.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

  const total = list.length;
  const pages = Math.max(1, Math.ceil(total / perPage));
  const slice = list.slice((page - 1) * perPage, page * perPage);
  const ratings = await ratingLookup();

  sendJson(res, 200, {
    apps: slice.map((a) => publicApp(a, categories.find((c) => c.id === a.categoryId), ratings[a.id])),
    total,
    page,
    pages,
    perPage,
    category: category ? { id: category.id, name: category.name, slug: category.slug, color: category.color } : null
  });
}

async function apiAppDetail(req, res, slug) {
  const apps = await store.apps();
  const categories = await store.categories();
  const app = apps.find((a) => a.slug === slug && a.status === "published");
  if (!app) return sendJson(res, 404, { error: "App not found" });

  app.viewCount = (app.viewCount || 0) + 1;
  await store.saveApps(apps);

  const category = categories.find((c) => c.id === app.categoryId);
  const related = apps
    .filter((a) => a.status === "published" && a.id !== app.id && a.categoryId === app.categoryId)
    .slice(0, 4)
    .map((a) => publicApp(a, category));

  const reviews = (await store.reviews())[app.id] || [];
  const recentReviews = [...reviews].sort((a, b) => b.created.localeCompare(a.created)).slice(0, 30);
  const topReviews = [...reviews]
    .sort((a, b) => (Number(b.rating) || 0) - (Number(a.rating) || 0) || b.created.localeCompare(a.created))
    .slice(0, 2)
    .map((r) => ({ ...r, top: true }));

  sendJson(res, 200, {
    app: {
      ...publicApp(app, category, store.ratingFor(reviews)),
      description: app.description,
      screenshots: app.screenshots || [],
      reviews: recentReviews,
      topReviews
    },
    related
  });
}

async function apiCategories(req, res) {
  sendJson(res, 200, { categories: await categoryWithCounts() });
}

async function apiTrackDownload(req, res) {
  if (!trackAllowed(clientIp(req))) {
    return sendJson(res, 429, { error: "Too many requests. Try again shortly." });
  }
  const body = await readJson(req, res);
  if (!body) return;
  const slug = cleanText(body?.slug, 80);
  if (!slug) return sendJson(res, 400, { error: "Missing app slug" });

  const apps = await store.apps();
  const app = apps.find((a) => a.slug === slug && a.status === "published");
  if (!app) return sendJson(res, 404, { error: "App not found" });

  app.downloadCount = (app.downloadCount || 0) + 1;
  await store.saveApps(apps);
  await store.appendEvent({
    id: randomToken(8),
    appId: app.id,
    ts: new Date().toISOString(),
    ua: cleanText(req.headers["user-agent"], EVENT_UA_MAX)
  });

  sendJson(res, 200, { ok: true, downloadCount: app.downloadCount });
}

async function apiSubmitReview(req, res, slug) {
  if (!reviewAllowed(clientIp(req))) {
    return sendJson(res, 429, { error: "Too many reviews — try again later." });
  }
  const body = await readJson(req, res);
  if (!body) return;

  // Honeypot — bots fill the hidden "website" field
  if (typeof body.website === "string" && body.website.trim() !== "") {
    return sendJson(res, 201, { ok: true });
  }

  const apps = await store.apps();
  const app = apps.find((a) => a.slug === slug && a.status === "published");
  if (!app) return sendJson(res, 404, { error: "App not found" });

  const rating = Math.floor(Number(body.rating));
  if (!Number.isFinite(rating) || rating < 1 || rating > 5) {
    return sendJson(res, 400, { error: "Rating must be between 1 and 5 stars" });
  }
  const text = cleanMultiLine(body.text, 1000);
  if (!text) return sendJson(res, 400, { error: "Review text is required" });

  const review = {
    id: randomToken(10),
    rating,
    name: cleanText(body.name, 40) || "Anonymous",
    text,
    created: new Date().toISOString()
  };
  await store.addReview(app.id, review);
  sendJson(res, 201, { ok: true, review });
}

async function apiLegal(req, res) {
  const s = await store.settings();
  sendJson(res, 200, {
    terms: s.terms || "",
    privacy: s.privacy || "",
    siteName: s.name,
    updated: new Date().toISOString()
  });
}

/* ------------------------------------------------------------------ */
/* Admin — apps                                                        */
/* ------------------------------------------------------------------ */

async function adminListApps(req, res) {
  const apps = await store.apps();
  const categories = await store.categories();
  const list = apps
    .map((a) => ({
      ...publicApp(a, categories.find((c) => c.id === a.categoryId)),
      status: a.status,
      description: a.description,
      screenshots: a.screenshots || [],
      createdAt: a.createdAt
    }))
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  sendJson(res, 200, { apps: list });
}

async function adminCreateApp(req, res, body) {
  const parsed = sanitizeApp(body);
  if (!parsed.name) return sendJson(res, 400, { error: "App name is required" });
  if (!parsed.slug) return sendJson(res, 400, { error: "A valid slug is required" });

  const apps = await store.apps();
  if (apps.some((a) => a.slug === parsed.slug)) {
    return sendJson(res, 409, { error: "That slug is already in use" });
  }
  const now = new Date().toISOString();
  const app = { id: randomToken(8), ...parsed, createdAt: now, updatedAt: now };
  apps.push(app);
  await store.saveApps(apps);
  sendJson(res, 201, { app });
}

async function adminUpdateApp(req, res, body, id) {
  const apps = await store.apps();
  const idx = apps.findIndex((a) => a.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "App not found" });

  const existing = apps[idx];
  const parsed = sanitizeApp({ ...existing, ...body }, existing);
  if (!parsed.name) return sendJson(res, 400, { error: "App name is required" });
  if (!parsed.slug) return sendJson(res, 400, { error: "A valid slug is required" });
  if (apps.some((a) => a.id !== id && a.slug === parsed.slug)) {
    return sendJson(res, 409, { error: "That slug is already in use" });
  }

  const updated = { ...existing, ...parsed, updatedAt: new Date().toISOString() };
  apps[idx] = updated;
  await store.saveApps(apps);
  sendJson(res, 200, { app: updated });
}

/** Soft delete — archived apps vanish from the public site (counters preserved). */
async function adminArchiveApp(req, res, id) {
  const apps = await store.apps();
  const idx = apps.findIndex((a) => a.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "App not found" });
  apps[idx] = { ...apps[idx], status: "archived", updatedAt: new Date().toISOString() };
  await store.saveApps(apps);
  sendJson(res, 200, { ok: true, app: apps[idx] });
}

/* ------------------------------------------------------------------ */
/* Admin — categories                                                  */
/* ------------------------------------------------------------------ */

async function adminListCategories(req, res) {
  sendJson(res, 200, { categories: await store.categories() });
}

async function adminCreateCategory(req, res, body) {
  const parsed = sanitizeCategory(body);
  if (!parsed.name) return sendJson(res, 400, { error: "Category name is required" });
  if (!parsed.slug) return sendJson(res, 400, { error: "A valid slug is required" });
  const categories = await store.categories();
  if (categories.some((c) => c.slug === parsed.slug)) {
    return sendJson(res, 409, { error: "That slug is already in use" });
  }
  const category = { id: randomToken(8), ...parsed };
  categories.push(category);
  await store.saveCategories(categories);
  sendJson(res, 201, { category });
}

async function adminUpdateCategory(req, res, body, id) {
  const categories = await store.categories();
  const idx = categories.findIndex((c) => c.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "Category not found" });
  const parsed = sanitizeCategory(body, categories[idx]);
  if (!parsed.name) return sendJson(res, 400, { error: "Category name is required" });
  if (!parsed.slug) return sendJson(res, 400, { error: "A valid slug is required" });
  if (categories.some((c) => c.id !== id && c.slug === parsed.slug)) {
    return sendJson(res, 409, { error: "That slug is already in use" });
  }
  categories[idx] = { ...categories[idx], ...parsed };
  await store.saveCategories(categories);
  sendJson(res, 200, { category: categories[idx] });
}

async function adminDeleteCategory(req, res, id) {
  const categories = await store.categories();
  const idx = categories.findIndex((c) => c.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "Category not found" });
  const apps = await store.apps();
  const usedBy = apps.filter((a) => a.categoryId === id && a.status !== "archived").length;
  if (usedBy > 0) {
    return sendJson(res, 400, { error: `Cannot delete — used by ${usedBy} active app${usedBy === 1 ? "" : "s"}` });
  }
  categories.splice(idx, 1);
  await store.saveCategories(categories);
  sendJson(res, 200, { ok: true });
}

/* ------------------------------------------------------------------ */
/* Admin — uploads                                                     */
/* ------------------------------------------------------------------ */

async function adminUpload(req, res, kind) {
  const result = await saveUpload(kind, req);
  if (result.error) {
    return sendJson(res, result.error, { error: result.message }, { Connection: "close" });
  }
  sendJson(res, 201, { url: result.url, bytes: result.bytes, mime: result.mime });
}

async function adminDeleteUpload(req, res, body) {
  const result = await deleteUploadFile(body?.path);
  if (result.error) return sendJson(res, result.error, { error: result.message });
  sendJson(res, 200, { ok: true });
}

/* ------------------------------------------------------------------ */
/* Admin — stats                                                       */
/* ------------------------------------------------------------------ */

async function adminStats(req, res) {
  const apps = await store.apps();
  const events = await store.events();
  const published = apps.filter((a) => a.status === "published");

  const totalDownloads = apps.reduce((s, a) => s + (a.downloadCount || 0), 0);
  const totalViews = apps.reduce((s, a) => s + (a.viewCount || 0), 0);
  const mostDownloaded = [...apps].sort((a, b) => (b.downloadCount || 0) - (a.downloadCount || 0))[0] || null;

  const perApp = apps
    .map((a) => ({
      id: a.id,
      name: a.name,
      slug: a.slug,
      status: a.status,
      downloads: a.downloadCount || 0,
      views: a.viewCount || 0
    }))
    .sort((a, b) => b.downloads - a.downloads);

  const days = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - i);
    days.push(d);
  }
  const byDay = days.map((d) => ({ day: d.toISOString().slice(0, 10), count: 0 }));
  for (const ev of events) {
    const key = String(ev.ts || "").slice(0, 10);
    const row = byDay.find((b) => b.day === key);
    if (row) row.count += 1;
  }

  const recent = events
    .slice(-30)
    .reverse()
    .map((ev) => {
      const app = apps.find((a) => a.id === ev.appId);
      return { id: ev.id, appId: ev.appId, appName: app ? app.name : "Unknown", ts: ev.ts, ua: ev.ua || "" };
    });

  sendJson(res, 200, {
    totals: { apps: apps.length, published: published.length, downloads: totalDownloads, views: totalViews },
    mostDownloaded: mostDownloaded
      ? { name: mostDownloaded.name, slug: mostDownloaded.slug, downloads: mostDownloaded.downloadCount || 0 }
      : null,
    perApp,
    byDay,
    recent
  });
}

/* ------------------------------------------------------------------ */
/* Admin — users (ported from Strike Up backend)                       */
/* ------------------------------------------------------------------ */

async function adminListUsers(req, res) {
  const users = (await store.users()).map(publicUser);
  sendJson(res, 200, { users });
}

async function adminCreateUser(req, res, body, actor) {
  const username = sanitizeUsername(body?.username);
  const password = String(body?.password ?? "");
  const role = cleanRole(body?.role, rank(actor) === 3);
  if (!username) return sendJson(res, 400, { error: "Username must be 3–64 letters, numbers, or . _ + @ -" });
  if (!validatePassword(password)) return sendJson(res, 400, { error: "Password must be 8–128 characters" });
  if (!role) return sendJson(res, 400, { error: "Invalid role" });
  if (role === "owner" && rank(actor) !== 3) {
    return sendJson(res, 403, { error: "Only owners can grant the owner role" });
  }
  const users = await store.users();
  if (users.some((u) => u.username === username)) {
    return sendJson(res, 409, { error: "Username already exists" });
  }
  const { salt, hash } = hashPassword(password);
  const user = {
    id: randomToken(8),
    username,
    role,
    active: true,
    salt,
    passwordHash: hash,
    createdAt: new Date().toISOString(),
    lastLogin: null
  };
  users.push(user);
  await store.saveUsers(users);
  sendJson(res, 201, { user: publicUser(user) });
}

async function adminUpdateUser(req, res, body, id, actor) {
  const users = await store.users();
  const user = users.find((u) => u.id === id);
  if (!user) return sendJson(res, 404, { error: "User not found" });
  const isSelf = user.id === actor.id;
  const actorRank = rank(actor);

  if (rank(user) === 3 && actorRank !== 3) {
    return sendJson(res, 403, { error: "Only owners can modify owner accounts" });
  }

  if (body.active !== undefined && typeof body.active === "boolean") {
    if (isSelf) return sendJson(res, 400, { error: "You cannot deactivate your own account" });
    if (body.active) {
      user.active = true;
    } else {
      if (rank(user) === 3 && users.filter((u) => u.role === "owner" && u.active).length <= 1) {
        return sendJson(res, 400, { error: "Cannot deactivate the last owner" });
      }
      user.active = false;
      sessions.destroyByUser(user.id);
    }
  }

  if (body.role !== undefined) {
    if (isSelf) return sendJson(res, 400, { error: "You cannot change your own role" });
    const role = cleanRole(body.role, actorRank === 3);
    if (!role) return sendJson(res, 400, { error: "Invalid role" });
    if (role === "owner" && actorRank !== 3) return sendJson(res, 403, { error: "Only owners can grant the owner role" });
    if (rank(user) === 3 && role !== "owner" && users.filter((u) => u.role === "owner").length <= 1) {
      return sendJson(res, 400, { error: "Cannot remove the last owner" });
    }
    user.role = role;
  }

  if (body.password !== undefined && body.password !== "") {
    if (isSelf) return sendJson(res, 400, { error: "Change your own password in Settings" });
    if (!validatePassword(body.password)) return sendJson(res, 400, { error: "Password must be 8–128 characters" });
    const { salt, hash } = hashPassword(body.password);
    user.salt = salt;
    user.passwordHash = hash;
    sessions.destroyByUser(user.id);
  }

  await store.saveUsers(users);
  sendJson(res, 200, { user: publicUser(user) });
}

async function adminDeleteUser(req, res, id, actor) {
  if (rank(actor) < 3) return sendJson(res, 403, { error: "Forbidden" });
  const users = await store.users();
  const idx = users.findIndex((u) => u.id === id);
  if (idx === -1) return sendJson(res, 404, { error: "User not found" });
  const user = users[idx];
  if (user.id === actor.id) return sendJson(res, 400, { error: "You cannot delete your own account" });
  if (user.role === "owner" && users.filter((u) => u.role === "owner").length <= 1) {
    return sendJson(res, 400, { error: "Cannot delete the last owner" });
  }
  sessions.destroyByUser(user.id);
  users.splice(idx, 1);
  await store.saveUsers(users);
  sendJson(res, 200, { ok: true });
}

/* ------------------------------------------------------------------ */
/* Auth handlers                                                       */
/* ------------------------------------------------------------------ */

async function apiLogin(req, res) {
  const body = await readJson(req, res);
  if (!body) return;
  const username = sanitizeUsername(body?.username);
  const password = String(body?.password ?? "");
  if (!username || !password) {
    return sendJson(res, 400, { error: "Username and password are required" });
  }

  const ip = clientIp(req);
  const key = limiter.key(ip, username);
  const pre = limiter.status(key);
  if (!pre.allowed) {
    return sendJson(res, 429, {
      error: "Too many failed attempts. Try again later.",
      retryInMinutes: Math.ceil(pre.retryInMs / 60000)
    });
  }

  const users = await store.users();
  const user = users.find((u) => u.username === username);
  const ok = user && user.active && verifyPassword(password, user.salt, user.passwordHash);

  if (!ok) {
    limiter.recordFailure(key);
    return sendJson(res, 401, { error: "Invalid username or password" });
  }

  limiter.clear(key);
  user.lastLogin = new Date().toISOString();
  await store.saveUsers(users);

  const token = sessions.create(user.id);
  setSessionCookie(res, token, req);
  sendJson(res, 200, {
    user: publicUser(user),
    csrf: sessions.get(token).csrf,
    canManageUsers: rank(user) >= 2
  });
}

async function apiMe(req, res) {
  const auth = await requireSession(req, res);
  if (!auth) return;
  sendJson(res, 200, {
    user: publicUser(auth.user),
    csrf: auth.session.csrf,
    canManageUsers: rank(auth.user) >= 2
  });
}

function apiLogout(req, res) {
  const token = parseCookies(req)["strike_store_session"];
  if (token) sessions.destroy(token);
  clearSessionCookie(res);
  sendJson(res, 200, { ok: true });
}

async function apiPassword(req, res) {
  const auth = await requireSession(req, res);
  if (!auth) return;
  if (!requireCsrf(req, res, auth.session)) return;
  const body = await readJson(req, res);
  if (!body) return;
  const { current, password, confirm } = body || {};

  if (!verifyPassword(String(current ?? ""), auth.user.salt, auth.user.passwordHash)) {
    return sendJson(res, 400, { error: "Current password is incorrect" });
  }
  if (!validatePassword(password)) return sendJson(res, 400, { error: "New password must be 8–128 characters" });
  if (password !== confirm) return sendJson(res, 400, { error: "Passwords do not match" });

  const { salt, hash } = hashPassword(password);
  const users = await store.users();
  const me = users.find((u) => u.id === auth.user.id);
  if (!me) return sendJson(res, 401, { error: "Account not found" });
  me.salt = salt;
  me.passwordHash = hash;
  await store.saveUsers(users);
  sessions.destroyByUser(auth.user.id, auth.session.tokenHash);
  sendJson(res, 200, { ok: true });
}

/* ------------------------------------------------------------------ */
/* Routers                                                             */
/* ------------------------------------------------------------------ */

async function handlePublicApi(req, res, segments, method) {
  const is = (...expected) => {
    if (segments.length !== expected.length) return false;
    return expected.every((e, i) => (e.startsWith(":") ? true : e === segments[i]));
  };

  if (method === "GET" && is("api", "home")) return apiHome(req, res);
  if (method === "GET" && is("api", "apps")) return apiListApps(req, res, new URL(req.url, "http://localhost"));
  if (method === "GET" && is("api", "apps", ":slug")) return apiAppDetail(req, res, segments[2]);
  if (method === "GET" && is("api", "categories")) return apiCategories(req, res);
  if (method === "GET" && is("api", "legal")) return apiLegal(req, res);
  if (method === "POST" && is("api", "track-download")) return apiTrackDownload(req, res);
  if (method === "POST" && is("api", "apps", ":slug", "review")) return apiSubmitReview(req, res, segments[2]);

  const KNOWN_PUBLIC = new Set(["home", "apps", "categories", "legal", "track-download"]);
  if (segments.length >= 2 && KNOWN_PUBLIC.has(segments[1])) {
    return sendJson(res, 405, { error: "Method Not Allowed" });
  }
  return sendJson(res, 404, { error: "Not found" });
}

async function handleAdminApi(req, res, segments, method) {
  const is = (...expected) => {
    if (segments.length !== expected.length) return false;
    return expected.every((e, i) => (e.startsWith(":") ? true : e === segments[i]));
  };
  const id = segments.length === 4 ? segments[3] : null;

  if (is("api", "admin", "login") && method === "POST") return apiLogin(req, res);
  if (is("api", "admin", "me") && method === "GET") return apiMe(req, res);
  if (is("api", "admin", "logout") && method === "POST") return apiLogout(req, res);
  if (is("api", "admin", "password") && method === "PUT") return apiPassword(req, res);

  // ---- everything below requires a session ----
  const auth = await requireSession(req, res);
  if (!auth) return;

  if (is("api", "admin", "apps") && method === "GET") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    return adminListApps(req, res);
  }
  if (is("api", "admin", "apps") && method === "POST") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminCreateApp(req, res, await readJson(req, res));
  }
  if (is("api", "admin", "apps", ":id") && method === "PUT") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminUpdateApp(req, res, await readJson(req, res), id);
  }
  if (is("api", "admin", "apps", ":id") && method === "DELETE") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Only admins can delete apps" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminArchiveApp(req, res, id);
  }

  if (is("api", "admin", "categories") && method === "GET") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    return adminListCategories(req, res);
  }
  if (is("api", "admin", "categories") && method === "POST") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Only admins can create categories" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminCreateCategory(req, res, await readJson(req, res));
  }
  if (is("api", "admin", "categories", ":id") && method === "PUT") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Only admins can edit categories" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminUpdateCategory(req, res, await readJson(req, res), id);
  }
  if (is("api", "admin", "categories", ":id") && method === "DELETE") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Only admins can delete categories" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminDeleteCategory(req, res, id);
  }

  if (is("api", "admin", "upload", "apk") && method === "POST") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) {
      await drain(req);
      return;
    }
    return adminUpload(req, res, "apk");
  }
  if (is("api", "admin", "upload", "image") && method === "POST") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) {
      await drain(req);
      return;
    }
    return adminUpload(req, res, "image");
  }
  if (is("api", "admin", "uploads") && method === "DELETE") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminDeleteUpload(req, res, await readJson(req, res));
  }

  if (is("api", "admin", "stats") && method === "GET") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    return adminStats(req, res);
  }

  if (is("api", "admin", "settings") && method === "GET") {
    if (rank(auth.user) < 1) return sendJson(res, 403, { error: "Forbidden" });
    return adminGetSettings(req, res);
  }
  if (is("api", "admin", "settings") && method === "PUT") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Only admins can change site settings" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminSaveSettings(req, res, await readJson(req, res));
  }

  if (is("api", "admin", "reviews") && method === "GET") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Forbidden" });
    return adminListReviews(req, res);
  }
  if (is("api", "admin", "reviews", ":id") && method === "DELETE") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminDeleteReview(req, res, id);
  }

  if (is("api", "admin", "users") && method === "GET") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Forbidden" });
    return adminListUsers(req, res);
  }
  if (is("api", "admin", "users") && method === "POST") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminCreateUser(req, res, await readJson(req, res), auth.user);
  }
  if (is("api", "admin", "users", ":id") && method === "PUT") {
    if (rank(auth.user) < 2) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminUpdateUser(req, res, await readJson(req, res), id, auth.user);
  }
  if (is("api", "admin", "users", ":id") && method === "DELETE") {
    if (rank(auth.user) < 3) return sendJson(res, 403, { error: "Forbidden" });
    if (!requireCsrf(req, res, auth.session)) return;
    return adminDeleteUser(req, res, id, auth.user);
  }

  const KNOWN_ADMIN = new Set(["login", "me", "logout", "password", "apps", "categories", "upload", "uploads", "stats", "settings", "reviews", "users"]);
  if (segments.length >= 3 && KNOWN_ADMIN.has(segments[2])) {
    return sendJson(res, 405, { error: "Method Not Allowed" });
  }
  return sendJson(res, 404, { error: "Not found" });
}

async function adminGetSettings(req, res) {
  sendJson(res, 200, { settings: await store.settings() });
}

async function adminSaveSettings(req, res, body) {
  const current = await store.settings();
  const name = cleanText(body.name, 60) || SITE.name;
  const tagline = cleanText(body.tagline, 200);
  const about = cleanMultiLine(body.about, 4000);
  const heroTitle = cleanText(body.heroTitle, 160) || SITE.heroTitle;
  const heroSub = cleanText(body.heroSub, 400) || SITE.heroSub;
  const terms = cleanMultiLine(body.terms, 20000) || SITE.terms;
  const privacy = cleanMultiLine(body.privacy, 20000) || SITE.privacy;
  let logoUrl = "";
  if (typeof body.logoUrl === "string") {
    const m = body.logoUrl.match(/^\/uploads\/images\/([a-z0-9][a-z0-9._-]*)$/i);
    if (m && !m[1].includes("..")) logoUrl = body.logoUrl;
  }
  // Ads — adClient must be ca-pub-…, slot ids numeric
  const adClient = /^ca-pub-[0-9]{10,20}$/i.test(cleanText(body.adClient, 60)) ? cleanText(body.adClient, 60) : "";
  const slot = (v) => (/^[0-9]{7,16}$/.test(cleanText(v, 40)) ? cleanText(v, 40) : "");
  const adsEnabled = body.adsEnabled === true || body.adsEnabled === 1 || body.adsEnabled === "true" || body.adsEnabled === "1" || body.adsEnabled === "on";
  const adMode = body.adMode === "adsense" ? "adsense" : "dummy";
  const next = {
    ...current,
    name, tagline, about, logoUrl,
    heroTitle, heroSub,
    terms, privacy,
    adClient, adsEnabled, adMode,
    adSlotLeaderboard: slot(body.adSlotLeaderboard),
    adSlotNative: slot(body.adSlotNative),
    adSlotDetail: slot(body.adSlotDetail),
    adSlotInterstitial: slot(body.adSlotInterstitial),
    adSlotSticky: slot(body.adSlotSticky)
  };
  await store.saveSettings(next);
  sendJson(res, 200, { settings: next });
}

async function adminListReviews(req, res) {
  const reviews = await store.reviews();
  const apps = await store.apps();
  const nameById = Object.fromEntries(apps.map((a) => [a.id, a.name]));
  const flat = [];
  for (const appId of Object.keys(reviews)) {
    for (const r of reviews[appId]) {
      flat.push({ ...r, appId, appName: nameById[appId] || appId });
    }
  }
  flat.sort((a, b) => b.created.localeCompare(a.created));
  const recent = flat.slice(0, 200);
  const totals = await (async () => {
    const out = {};
    for (const appId of Object.keys(reviews)) out[appId] = store.ratingFor(reviews[appId]);
    return out;
  })();
  sendJson(res, 200, { reviews: recent, total: flat.length, ratings: totals });
}

async function adminDeleteReview(req, res, reviewId) {
  const removed = await store.deleteReview(reviewId);
  if (!removed) return sendJson(res, 404, { error: "Review not found" });
  sendJson(res, 200, { ok: true });
}

/* ------------------------------------------------------------------ */
/* Static + SEO-aware HTML serving                                     */
/* ------------------------------------------------------------------ */

let indexShell = null;
const FALLBACK_SHELL = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="theme-color" content="#0a0a0f" />
<meta name="robots" content="index, follow" />
<title>__TITLE__</title>
<meta name="description" content="__DESCRIPTION__" />
<meta property="og:site_name" content="__OG_SITE_NAME__" />
<meta property="og:title" content="__OG_TITLE__" />
<meta property="og:description" content="__OG_DESCRIPTION__" />
<meta property="og:image" content="__OG_IMAGE__" />
<meta property="og:url" content="__OG_URL__" />
<link rel="stylesheet" href="/assets/css/style.css" />
</head>
<body>
<div id="app" class="site-shell"><section class="section fade-up" style="padding:4rem 0;"><div class="container" style="text-align:center;">StrikeUp Store is loading…</div></section></div>
<script type="module" src="/assets/js/main.js"></script>
</body>
</html>`;
async function getIndexShell() {
  if (indexShell) return indexShell;
  try {
    indexShell = await fs.readFile(FRONTEND_INDEX, "utf8");
  } catch {
    indexShell = FALLBACK_SHELL;
  }
  return indexShell;
}

function escHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fillMeta(shell, { title, description, image, path: urlPath, siteName }) {
  const t = escHtml(title || SITE.name);
  const d = escHtml(description || SITE.tagline);
  const i = escHtml(image || "");
  const openGraphSite = escHtml(siteName || SITE.name);
  return shell
    .replace(/__TITLE__/g, t)
    .replace(/__DESCRIPTION__/g, d)
    .replace(/__OG_SITE_NAME__/g, openGraphSite)
    .replace(/__OG_TITLE__/g, t)
    .replace(/__OG_DESCRIPTION__/g, d)
    .replace(/__OG_IMAGE__/g, i)
    .replace(/__OG_URL__/g, escHtml(urlPath || "/"));
}

async function renderIndex(req, res, pathname) {
  const shell = await getIndexShell();
  const site = await store.settings();
  let meta = { title: site.name, description: site.tagline, image: site.logoUrl || "", path: pathname, siteName: site.name };

  const appMatch = pathname.match(/^\/app\/([^/]+)$/);
  const catMatch = pathname.match(/^\/category\/([^/]+)$/);

  if (appMatch) {
    const apps = await store.apps();
    const categories = await store.categories();
    const app = apps.find((a) => a.slug === appMatch[1] && a.status === "published");
    if (app) {
      const cat = categories.find((c) => c.id === app.categoryId);
      meta = {
        title: `${app.name} — ${site.name}`,
        description: app.tagline || site.tagline,
        image: app.iconUrl || site.logoUrl || "",
        path: pathname,
        siteName: site.name
      };
    }
  } else if (catMatch) {
    const categories = await store.categories();
    const cat = categories.find((c) => c.slug === catMatch[1]);
    if (cat) {
      meta = { title: `${cat.name} — ${site.name}`, description: site.tagline, image: site.logoUrl || "", path: pathname, siteName: site.name };
    }
  } else if (pathname === "/about") {
    meta = { title: `About — ${site.name}`, description: site.tagline, image: site.logoUrl || "", path: pathname, siteName: site.name };
  } else if (pathname === "/apps") {
    meta = { title: `Apps — ${site.name}`, description: site.tagline, image: site.logoUrl || "", path: pathname, siteName: site.name };
  } else if (pathname === "/terms") {
    meta = { title: `Terms & Conditions — ${site.name}`, description: site.tagline, image: site.logoUrl || "", path: pathname, siteName: site.name };
  } else if (pathname === "/privacy") {
    meta = { title: `Privacy Policy — ${site.name}`, description: site.tagline, image: site.logoUrl || "", path: pathname, siteName: site.name };
  }

  const html = fillMeta(shell, meta);
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": Buffer.byteLength(html),
    "Cache-Control": "no-cache"
  });
  res.end(html);
}

async function serveFile(res, req, target, asDownload = false) {
  let stat;
  try {
    stat = await fs.stat(target);
  } catch {
    return sendText(res, 404, "Not Found");
  }
  if (!stat.isFile()) return sendText(res, 404, "Not Found");
  const ext = path.extname(target).toLowerCase();
  const type = MIME[ext] || "application/octet-stream";
  const isHtml = ext === ".html";
  const headers = {
    "Content-Type": type,
    "Cache-Control": isHtml ? "no-cache" : asDownload ? "private, max-age=300" : "public, max-age=3600"
  };
  if (asDownload || ext === ".apk") {
    headers["Content-Disposition"] = `attachment; filename="${path.basename(target)}"`;
  }

  // Small text assets: serve gzip-encoded when the client supports it (fastest loads).
  if (wantsGzip(req, type.split(";")[0], stat.size)) {
    let buf;
    try {
      buf = await fs.readFile(target);
    } catch {
      return sendText(res, 404, "Not Found");
    }
    zlib.gzip(buf, (gzipErr, gz) => {
      if (gzipErr) {
        res.writeHead(200, { ...headers, "Content-Length": stat.size });
        if (req.method === "HEAD") return res.end();
        return res.end(buf);
      }
      res.writeHead(200, { ...headers, "Content-Encoding": "gzip", "Content-Length": gz.length, "Vary": "Accept-Encoding" });
      if (req.method === "HEAD") return res.end();
      res.end(gz);
    });
    return;
  }

  res.writeHead(200, { ...headers, "Content-Length": stat.size });
  if (req.method === "HEAD") return res.end();
  createReadStream(target).pipe(res);
}

async function serveStatic(req, res, pathname) {
  if (pathname.includes("\0")) return sendText(res, 400, "Bad Request");

  // Uploaded files (APKs + images) — only inside UPLOADS_DIR
  if (pathname === "/uploads" || pathname.startsWith("/uploads/")) {
    const rel = pathname.slice("/uploads".length).replace(/^\/+/, "");
    if (!rel) return sendText(res, 404, "Not Found");
    if (rel.includes("..")) return sendText(res, 404, "Not Found");
    const target = path.resolve(UPLOADS_DIR, rel);
    if (target !== UPLOADS_DIR && !target.startsWith(UPLOADS_DIR + path.sep)) {
      return sendText(res, 404, "Not Found");
    }
    return serveFile(res, req, target, rel.toLowerCase().endsWith(".apk"));
  }

  // Admin shell — ONLY at the obscured path; /admin must 404
  if (pathname === "/admin" || pathname.startsWith("/admin/")) return sendText(res, 404, "Not Found");
  if (pathname === ADMIN_PATH || pathname.startsWith(ADMIN_PATH + "/")) {
    return serveFile(res, req, ADMIN_INDEX);
  }

  // Explicit assets — never anything outside public/
  const rel = pathname === "/" ? "/index.html" : pathname;
  const target = path.resolve(FRONTEND_DIR, "." + rel);
  if (target !== FRONTEND_DIR && !target.startsWith(FRONTEND_DIR + path.sep)) {
    return sendText(res, 404, "Not Found");
  }
  const segs = rel.split("/").filter(Boolean);
  if (segs.some((s) => BLOCKED_SEGMENTS.has(s))) return sendText(res, 404, "Not Found");

  try {
    const stat = await fs.stat(target);
    if (stat.isFile()) return serveFile(res, req, target);
  } catch {
    /* fall through to SPA */
  }

  // SPA routes — /, /apps, /app/:slug, /category/:slug, /about (unknown → client-side 404)
  return renderIndex(req, res, pathname);
}

/* ------------------------------------------------------------------ */
/* Server                                                              */
/* ------------------------------------------------------------------ */

async function handler(req, res) {
  const headers = securityHeaders(req);
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);

  if (!originOk(req)) return sendJson(res, 403, { error: "Cross-origin request rejected" });

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch {
    return sendJson(res, 400, { error: "Bad request" });
  }
  const method = req.method.toUpperCase();

  try {
    await ensureSeeded();
    if (method === "GET" && pathname === "/health") return sendJson(res, 200, { ok: true });
    if ((method === "GET" || method === "HEAD") && pathname === "/favicon.ico") return sendNoContent(res);

    if (pathname === "/api" || pathname.startsWith("/api/")) {
      const segments = pathname.split("/").filter(Boolean);
      if (segments[1] === "admin") return await handleAdminApi(req, res, segments, method);
      return await handlePublicApi(req, res, segments, method);
    }

    if (method !== "GET" && method !== "HEAD") {
      return sendJson(res, 405, { error: "Method Not Allowed" });
    }
    return await serveStatic(req, res, pathname);
  } catch (err) {
    console.error("[server] unhandled error:", err);
    if (!res.headersSent) sendJson(res, 500, { error: "Internal server error" });
  }
}

const server = http.createServer(handler);

let seedPromise = null;
function ensureSeeded() {
  if (!seedPromise) {
    seedPromise = store.ensureSeed().catch((err) => {
      seedPromise = null;
      throw err;
    });
  }
  return seedPromise;
}

if (!process.env.VERCEL) {
  server.listen(PORT, () => {
    console.log(`StrikeUp Store server listening on :${PORT}`);
    console.log(`  Public site: http://localhost:${PORT}/`);
    console.log(`  Admin panel: http://localhost:${PORT}${ADMIN_PATH}`);
  });
}

export default handler;
