import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EVENTS_CAP } from "./config.js";
import { SITE, SEED_CATEGORIES, SEED_APPS } from "./defaults.js";
import { hashPassword, randomToken } from "./crypto.js";

// Read from env directly (not the cached config export) so tests can point
// this module at a temp dir via a cache-busted import.
const DATA_DIR = process.env.STRIKEUP_STORE_DATA_DIR || path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), "data");

function deepMerge(base, override) {
  if (override === undefined || override === null) return base;
  if (typeof base !== "object" || typeof override !== "object") return override;
  if (Array.isArray(base) || Array.isArray(override)) {
    return Array.isArray(override) ? override : base;
  }
  const out = { ...base };
  for (const key of Object.keys(override)) {
    out[key] = deepMerge(base[key], override[key]);
  }
  return out;
}

async function readJson(file) {
  try {
    const raw = await fs.readFile(file, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === "ENOENT") return null;
    console.error(`[store] failed to read ${file}:`, err.message);
    return null;
  }
}

async function writeJson(file, data) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(data, null, 2), "utf8");
  await fs.rename(tmp, file);
}

export class Store {
  async apps() {
    const stored = await readJson(this.#file("apps.json"));
    return stored && Array.isArray(stored) ? stored : [];
  }

  async saveApps(apps) {
    await writeJson(this.#file("apps.json"), apps);
  }

  async categories() {
    const stored = await readJson(this.#file("categories.json"));
    return stored && Array.isArray(stored) ? stored : [];
  }

  async saveCategories(categories) {
    await writeJson(this.#file("categories.json"), categories);
  }

  async users() {
    const stored = await readJson(this.#file("users.json"));
    return stored && Array.isArray(stored) ? stored : [];
  }

  async saveUsers(users) {
    await writeJson(this.#file("users.json"), users);
  }

  async events() {
    const stored = await readJson(this.#file("events.json"));
    return stored && Array.isArray(stored) ? stored : [];
  }

  async saveEvents(events) {
    if (events.length > EVENTS_CAP) {
      events = events.slice(events.length - EVENTS_CAP);
    }
    await writeJson(this.#file("events.json"), events);
  }

  async appendEvent(event) {
    const events = await this.events();
    events.push(event);
    await this.saveEvents(events);
  }

  async settings() {
    const stored = await readJson(this.#file("settings.json"));
    return deepMerge(SITE, stored || {});
  }

  async saveSettings(settings) {
    await writeJson(this.#file("settings.json"), settings);
  }

  async reviews() {
    const stored = await readJson(this.#file("reviews.json"));
    return stored && typeof stored === "object" && !Array.isArray(stored) ? stored : {};
  }

  async saveReviews(reviews) {
    await writeJson(this.#file("reviews.json"), reviews);
  }

  async addReview(appId, review) {
    const reviews = await this.reviews();
    if (!Array.isArray(reviews[appId])) reviews[appId] = [];
    reviews[appId].push(review);
    reviews[appId] = reviews[appId].slice(-100);
    await this.saveReviews(reviews);
    return review;
  }

  async deleteReview(reviewId) {
    const reviews = await this.reviews();
    for (const appId of Object.keys(reviews)) {
      const before = reviews[appId].length;
      reviews[appId] = reviews[appId].filter((r) => r.id !== reviewId);
      if (reviews[appId].length !== before) {
        if (reviews[appId].length === 0) delete reviews[appId];
        await this.saveReviews(reviews);
        return true;
      }
    }
    return false;
  }

  ratingFor(reviews) {
    const list = Array.isArray(reviews) ? reviews : [];
    if (list.length === 0) return { avg: 0, count: 0, distribution: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 } };
    const dist = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    const sum = list.reduce((s, r) => {
      const star = Math.max(1, Math.min(5, Number(r.rating) || 0));
      dist[star] = (dist[star] || 0) + 1;
      return s + star;
    }, 0);
    return { avg: Math.round((sum / list.length) * 10) / 10, count: list.length, distribution: dist };
  }

  /* -------------------------------------------------------------- */

  async ensureSeed() {
    const users = await this.users();
    if (users.length === 0) {
      const username = (process.env.STRIKEUP_STORE_ADMIN_USER || "owner").toLowerCase();
      const password = process.env.STRIKEUP_STORE_ADMIN_PASSWORD || "StrikeUp@2026";
      const { salt, hash } = hashPassword(password);
      const now = new Date().toISOString();
      await this.saveUsers([
        {
          id: randomToken(8),
          username,
          role: "owner",
          active: true,
          salt,
          passwordHash: hash,
          createdAt: now,
          lastLogin: null
        }
      ]);
      if (!process.env.STRIKEUP_STORE_ADMIN_PASSWORD) {
        console.warn(
          `[seed] Created default owner account — username: "${username}", password: "${password}". ` +
            "Change it in the admin panel and set STRIKEUP_STORE_ADMIN_PASSWORD for production."
        );
      } else {
        console.log(`[seed] Created owner account "${username}" from environment.`);
      }
    }

    const categories = await this.categories();
    if (categories.length === 0) {
      await this.saveCategories(SEED_CATEGORIES);
      console.log("[seed] Created default categories.");
    }

    const apps = await this.apps();
    if (apps.length === 0) {
      const now = new Date().toISOString();
      await this.saveApps(
        SEED_APPS.map((a) => ({ ...a, createdAt: now, updatedAt: now }))
      );
      console.log("[seed] Created sample app listing.");
    }
  }

  #file(name) {
    return path.join(DATA_DIR, name);
  }
}
