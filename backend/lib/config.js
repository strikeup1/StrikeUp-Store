import path from "node:path";
import { fileURLToPath } from "node:url";

const BACKEND_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const PROJECT_ROOT = path.resolve(BACKEND_ROOT, "..");

export const PORT = Number(process.env.PORT || 8788);

// Serverless (Vercel) runtimes only persist within /tmp per function instance.
export const IS_VERCEL = !!process.env.VERCEL;
const VOLATILE_ROOT = IS_VERCEL ? "/tmp" : path.join(BACKEND_ROOT, "var");

export const DATA_DIR =
  process.env.STRIKEUP_STORE_DATA_DIR ||
  (IS_VERCEL ? path.join(VOLATILE_ROOT, "strikeup-data") : path.join(BACKEND_ROOT, "data"));
export const UPLOADS_DIR =
  process.env.STRIKEUP_STORE_UPLOADS_DIR ||
  (IS_VERCEL ? path.join(VOLATILE_ROOT, "strikeup-uploads") : path.join(BACKEND_ROOT, "uploads"));
export const APKS_DIR = path.join(UPLOADS_DIR, "apks");
export const IMAGES_DIR = path.join(UPLOADS_DIR, "images");

export const FRONTEND_DIR = path.join(PROJECT_ROOT, "public");
export const FRONTEND_INDEX = path.join(FRONTEND_DIR, "index.html");
export const ADMIN_INDEX = path.join(FRONTEND_DIR, "admin", "index.html");

// Obscured admin path — /admin and /admin/* intentionally 404.
export const ADMIN_PATH = "/0301560/admin";

export const SESSION_COOKIE = "strike_store_session";
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 1 day sliding
export const SESSION_ABS_MAX_MS = 7 * 24 * 60 * 60 * 1000; // 7 days absolute
export const PRUNE_EVERY_MS = 15 * 60 * 1000;

export const JSON_BODY_LIMIT = 256 * 1024; // 256 KB for JSON bodies
export const APK_MAX_BYTES = 300 * 1024 * 1024; // 300 MB
export const IMAGE_MAX_BYTES = 8 * 1024 * 1024; // 8 MB per image
export const MAX_SCREENSHOTS = 8;

export const ROLES = { editor: 1, admin: 2, owner: 3 };

export const LOGIN_RATE = { max: 5, windowMs: 15 * 60 * 1000 };
export const TRACK_RATE = { max: 30, windowMs: 60 * 1000 };
export const EVENT_UA_MAX = 200;

export const EVENTS_CAP = 20000; // newest N download events kept for analytics

export const APP_STATUSES = ["draft", "published", "archived"];
export const APP_SORTS = ["newest", "popular", "az"];

export const UPLOAD_ALLOW_EXT = new Set([".apk", ".png", ".jpg", ".jpeg", ".webp", ".gif"]);
