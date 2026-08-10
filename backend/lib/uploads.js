import { promises as fs, createWriteStream } from "node:fs";
import path from "node:path";
import { APKS_DIR, IMAGES_DIR, UPLOADS_DIR, APK_MAX_BYTES, IMAGE_MAX_BYTES } from "./config.js";
import { randomToken } from "./crypto.js";

const NEEDED_HEAD = 12; // longest magic we check (webp: RIFF....WEBP)

function startsWith(buf, bytes) {
  if (buf.length < bytes.length) return false;
  return bytes.every((b, i) => buf[i] === b);
}

/** Detect type from magic bytes. Returns { ext, mime } or null. */
export function sniff(buf) {
  if (buf.length >= 4 && startsWith(buf, [0x50, 0x4b, 0x03, 0x04])) {
    return { ext: "apk", mime: "application/vnd.android.package-archive" };
  }
  // empty / split zips (PK\x05\x06, PK\x07\x08) — still valid APKs
  if (buf.length >= 4 && startsWith(buf, [0x50, 0x4b, 0x05, 0x06])) {
    return { ext: "apk", mime: "application/vnd.android.package-archive" };
  }
  if (buf.length >= 4 && startsWith(buf, [0x50, 0x4b, 0x07, 0x08])) {
    return { ext: "apk", mime: "application/vnd.android.package-archive" };
  }
  if (buf.length >= 8 && startsWith(buf, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return { ext: "png", mime: "image/png" };
  }
  if (buf.length >= 3 && startsWith(buf, [0xff, 0xd8, 0xff])) {
    return { ext: "jpg", mime: "image/jpeg" };
  }
  if (buf.length >= 12 && startsWith(buf, [0x52, 0x49, 0x46, 0x46]) && startsWith(buf.slice(8), [0x57, 0x45, 0x42, 0x50])) {
    return { ext: "webp", mime: "image/webp" };
  }
  if (buf.length >= 4 && (startsWith(buf, [0x47, 0x49, 0x46, 0x38]) || startsWith(buf.slice(0, 4), [0x47, 0x49, 0x46, 0x38]))) {
    return { ext: "gif", mime: "image/gif" };
  }
  return null;
}

/**
 * Stream a raw request body to disk with size cap + magic-byte validation.
 * kind: "apk" | "image". Returns { url, bytes } or { error, message }.
 */
export async function saveUpload(kind, req) {
  const maxBytes = kind === "apk" ? APK_MAX_BYTES : IMAGE_MAX_BYTES;
  const dir = kind === "apk" ? APKS_DIR : IMAGES_DIR;

  const contentLength = Number(req.headers["content-length"] || 0);
  if (contentLength > maxBytes) {
    return { error: 413, message: `File too large (max ${Math.round(maxBytes / 1048576)} MB).` };
  }

  await fs.mkdir(dir, { recursive: true });
  const tmp = path.join(dir, `.tmp-${randomToken(8)}`);

  let total = 0;
  let head = Buffer.alloc(0);

  try {
    await new Promise((resolve, reject) => {
      const ws = createWriteStream(tmp);
      req.on("data", (chunk) => {
        total += chunk.length;
        if (total > maxBytes) {
          req.destroy();
          reject({ code: 413 });
          return;
        }
        if (head.length < NEEDED_HEAD) {
          head = Buffer.concat([head, chunk.slice(0, NEEDED_HEAD - head.length)]);
        }
        if (!ws.write(chunk)) req.pause();
      });
      ws.on("drain", () => req.resume());
      req.on("end", () => ws.end(resolve));
      ws.on("error", reject);
      req.on("error", reject);
    });
  } catch (err) {
    await fs.rm(tmp, { force: true }).catch(() => {});
    if (err && err.code === 413) return { error: 413, message: `File too large (max ${Math.round(maxBytes / 1048576)} MB).` };
    return { error: 400, message: "Upload interrupted." };
  }

  if (total === 0) {
    await fs.rm(tmp, { force: true }).catch(() => {});
    return { error: 400, message: "Empty file." };
  }

  const detected = sniff(head);
  if (!detected) {
    await fs.rm(tmp, { force: true }).catch(() => {});
    return {
      error: 400,
      message: kind === "apk" ? "File is not a valid APK." : "File is not a valid PNG/JPEG/WebP/GIF image."
    };
  }
  if (kind === "apk" && detected.ext !== "apk") {
    await fs.rm(tmp, { force: true }).catch(() => {});
    return { error: 400, message: "Uploaded file is not an APK." };
  }
  if (kind === "image" && detected.ext === "apk") {
    await fs.rm(tmp, { force: true }).catch(() => {});
    return { error: 400, message: "Uploaded file is not an image." };
  }

  const name = `${randomToken(12)}.${detected.ext}`;
  const rel = `${kind === "apk" ? "apks" : "images"}/${name}`;
  await fs.rename(tmp, path.join(UPLOADS_DIR, rel));
  return { url: `/uploads/${rel}`, bytes: total, ext: detected.ext, mime: detected.mime };
}

/** Resolve a /uploads/... path (or uploads-relative path) to a safe absolute path. */
export function resolveUploadPath(rel) {
  let decoded = decodeURIComponent(rel).replace(/^\/+/, "");
  if (decoded.startsWith("uploads/")) decoded = decoded.slice("uploads/".length);
  if (decoded.includes("\0") || decoded.includes("..") || !decoded) return null;
  const target = path.resolve(UPLOADS_DIR, decoded);
  if (target !== UPLOADS_DIR && !target.startsWith(UPLOADS_DIR + path.sep)) return null;
  return target;
}

/** Delete a previously uploaded file. Returns { ok } or { error, message }. */
export async function deleteUploadFile(rel) {
  if (!/^\/uploads\/[A-Za-z0-9/._-]+$/.test(rel) || rel.includes("..")) {
    return { error: 400, message: "Invalid file path." };
  }
  const target = resolveUploadPath(rel);
  if (!target) return { error: 400, message: "Invalid file path." };
  try {
    await fs.rm(target, { force: true });
    return { ok: true };
  } catch {
    return { error: 500, message: "Could not delete file." };
  }
}
