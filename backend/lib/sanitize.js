import { APP_STATUSES, MAX_SCREENSHOTS, ROLES, EVENTS_CAP } from "./config.js";

const MAX = {
  name: 60,
  tagline: 160,
  description: 12000,
  version: 40,
  changelog: 4000,
  minAndroid: 60,
  categoryName: 60,
  slug: 80,
  color: 24,
  short: 120
};

function stripControlChars(s) {
  // eslint-disable-next-line no-control-regex
  return String(s ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "");
}

export function cleanText(value, max = MAX.short) {
  const s = stripControlChars(value).replace(/\s+/g, " ").trim();
  return s.slice(0, max);
}

export function cleanMultiLine(value, max = MAX.description) {
  return stripControlChars(value).replace(/[ \t]+/g, " ").trim().slice(0, max);
}

export function cleanUrl(value) {
  const s = stripControlChars(value).trim().slice(0, 1000);
  if (/^https?:\/\/\S+/i.test(s)) return s;
  if (/^\/(?!\/)[^\s]*$/i.test(s) && !s.includes("..")) return s;
  return "";
}

export function cleanHttpUrl(value) {
  const s = stripControlChars(value).trim().slice(0, 1000);
  return /^https?:\/\/\S+$/i.test(s) ? s : "";
}

export function cleanSlug(value) {
  const s = stripControlChars(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, MAX.slug);
  return s;
}

/** Server-controlled path: only /uploads/... paths are ever accepted for files. */
export function safeUploadPath(value) {
  if (typeof value !== "string") return "";
  const s = stripControlChars(value).trim().slice(0, 300);
  if (!/^\/uploads\/[A-Za-z0-9/._-]+$/.test(s)) return "";
  if (s.includes("..")) return "";
  return s;
}

export function cleanEmail(value) {
  const s = cleanText(value, 120).toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s) ? s : "";
}

export function cleanPhone(value) {
  return cleanText(value, 30).replace(/[^\d+\-() ]/g, "");
}

export function cleanWhatsapp(value) {
  const s = cleanText(value, 20).replace(/[^\d]/g, "");
  return s.slice(0, 16);
}

export function sanitizeUsername(value) {
  const s = stripControlChars(value).trim().toLowerCase().slice(0, 64);
  if (!/^[a-z0-9._+@-]{3,64}$/.test(s)) return "";
  return s;
}

export function validatePassword(value) {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}

export function cleanRole(value, allowOwner = true) {
  if (value === "editor" || value === "admin") return value;
  if (allowOwner && value === "owner") return "owner";
  return "";
}

export function cleanColor(value) {
  const s = cleanText(value, MAX.color);
  return /^#[0-9a-fA-F]{3,8}$/.test(s) ? s.toLowerCase() : "";
}

/* ------------------------------------------------------------------ */
/* Apps                                                                */
/* ------------------------------------------------------------------ */

export function sanitizeApp(raw, existing = {}) {
  if (!raw || typeof raw !== "object") raw = {};

  const name = cleanText(raw.name, MAX.name);
  const slug = cleanSlug(raw.slug) || cleanSlug(name);

  const status = APP_STATUSES.includes(raw.status) ? raw.status : existing.status || "draft";

  const hasFeaturedOrder = raw.featuredOrder !== undefined && raw.featuredOrder !== null && raw.featuredOrder !== "";
  const featuredOrder = hasFeaturedOrder
    ? Number.isFinite(Number(raw.featuredOrder))
      ? Math.max(0, Math.floor(Number(raw.featuredOrder)))
      : null
    : existing.featuredOrder ?? null;

  const hasSize = raw.fileSizeMb !== undefined && raw.fileSizeMb !== null && raw.fileSizeMb !== "";
  const fileSizeMb = hasSize
    ? Number.isFinite(Number(raw.fileSizeMb))
      ? Math.max(0, Math.round(Number(raw.fileSizeMb) * 10) / 10)
      : null
    : existing.fileSizeMb ?? null;

  const screenshots = Array.isArray(raw.screenshots)
    ? raw.screenshots.map(safeUploadPath).filter(Boolean).slice(0, MAX_SCREENSHOTS)
    : Array.isArray(existing.screenshots)
      ? existing.screenshots.slice(0, MAX_SCREENSHOTS)
      : [];

  return {
    name,
    slug,
    tagline: cleanText(raw.tagline, MAX.tagline),
    description: cleanMultiLine(raw.description, MAX.description),
    categoryId: cleanText(raw.categoryId, 60),
    iconUrl: raw.iconUrl === undefined || raw.iconUrl === null ? existing.iconUrl || "" : safeUploadPath(raw.iconUrl),
    screenshots,
    apkUrl: raw.apkUrl === undefined || raw.apkUrl === null ? existing.apkUrl || "" : safeUploadPath(raw.apkUrl),
    downloadUrl: cleanHttpUrl(raw.downloadUrl),
    version: cleanText(raw.version, MAX.version),
    changelog: cleanMultiLine(raw.changelog, MAX.changelog),
    minAndroid: cleanText(raw.minAndroid, MAX.minAndroid),
    fileSizeMb,
    status,
    featured: !!raw.featured,
    featuredOrder,
    downloadCount:
      typeof raw.downloadCount === "number" && Number.isFinite(raw.downloadCount)
        ? Math.max(0, Math.floor(raw.downloadCount))
        : existing.downloadCount ?? 0,
    viewCount:
      typeof raw.viewCount === "number" && Number.isFinite(raw.viewCount)
        ? Math.max(0, Math.floor(raw.viewCount))
        : existing.viewCount ?? 0
  };
}

/* ------------------------------------------------------------------ */
/* Categories                                                          */
/* ------------------------------------------------------------------ */

export function sanitizeCategory(raw, existing = {}) {
  if (!raw || typeof raw !== "object") raw = {};
  const name = cleanText(raw.name, MAX.categoryName);
  return {
    name,
    slug: cleanSlug(raw.slug) || cleanSlug(name),
    color: cleanColor(raw.color) || existing.color || ""
  };
}

export { ROLES, EVENTS_CAP };
