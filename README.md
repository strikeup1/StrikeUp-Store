# StrikeUp Store

A zero-dependency Node.js app store: public storefront, Play-store-style app pages (ratings, reviews, top review, additional info), external download links, social sharing, and a full admin panel (apps, categories, users, reviews, settings, ads, uploads).

- **Backend:** pure Node.js `http` server - **no npm dependencies** (Node >= 20.11)
- **Frontend:** fast static SPA, fully responsive (mobile / tablet / desktop), no frameworks
- **Storage:** JSON files (back up by copying `backend/data/`)

## Quick start (local)

```bash
cd backend
npm start        # or: node server.js
```

Then open:

- Storefront: http://localhost:8788/
- Admin panel: http://localhost:8788/0301560/admin (login: `owner`, password from env)

> The admin URL is intentionally obscured. Change `ADMIN_PATH` in `backend/lib/config.js` before production and always set `STRIKEUP_STORE_ADMIN_PASSWORD`.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8788` | HTTP port |
| `STRIKEUP_STORE_ADMIN_USER` | `owner` | Admin username on first seed |
| `STRIKEUP_STORE_ADMIN_PASSWORD` | dev default | Admin password (set a strong one) |
| `STRIKEUP_STORE_DATA_DIR` | `./backend/data` | JSON data location (persistent volume; `/tmp` on Vercel) |
| `STRIKEUP_STORE_UPLOADS_DIR` | `./backend/uploads` | Uploaded APK / image location (`/tmp` on Vercel) |

Pass them via environment, `.env` with `node --env-file=.env server.js`, or your hosting control panel.

## Deploying

This is a **Node.js app, not a static site** - the storefront, admin API, uploads and meta-tags are all served by `backend/server.js`. Use any host that runs Node 20.11+.

### Docker / VPS / Railway / Render / Fly.io

Build the included image (or deploy this folder directly):

```bash
docker build -t strikeup-store .
docker run -p 8788:8788 -e STRIKEUP_STORE_ADMIN_PASSWORD=strong-pass \
  -v store-data:/app/backend/data -v store-uploads:/app/backend/uploads strikeup-store
```

- Heroku/Render/Railway: set `PORT`, keep `Procfile` (`web: node backend/server.js`).
- Keep `backend/data` and `backend/uploads` on persistent volumes so apps/reviews/uploads survive restarts.

### cPanel (Node.js App)

1. Upload the extracted folder; create a Node.js app pointing at `backend/server.js`, application root = `backend`, node version 20.11+, startup file `server.js`.
2. Set the environment variables above in the cPanel Node.js app settings.
3. If cPanel proxies from a subpath, the storefront assumes it is served at the domain root.

### Vercel (serverless)

The repo ships with first-class Vercel support:

```bash
npx vercel
```

- The whole app — API **and** storefront SPA — runs in a single serverless function (`api/[...all].js` imports `backend/server.js`). `vercel.json` rewrites all non-asset routes into it, while `public/` assets are served straight from the CDN.
- Set `STRIKEUP_STORE_ADMIN_PASSWORD` (and the other variables above) in Vercel > Project > Settings > Environment Variables. The admin panel stays reachable at your `*.vercel.app` URL via the obscured admin path.
- Serverless caveats: `backend/data` and `backend/uploads` live under `/tmp` on Vercel and are **volatile** — apps, reviews, uploads and analytics do not persist across cold starts, and large APK uploads may exceed the function duration cap. If you need durable storage or multi-GB uploads, use the Docker/Node deployment above.

## Performance notes

- CSS/JS are minified (`public/assets/*`).
- The server gzips HTML/CSS/JS/JSON/SVG responses automatically for gzip-capable clients.
- Nothing is rendered server-side per request on the storefront; the SPA fetches `/api/*` JSON.

## Secret / URL notes

- Default admin path `/0301560/admin` - change `ADMIN_PATH` in `backend/lib/config.js`.
- Ads run in "dummy" (placeholder) mode by default; switch to AdSense in Admin > Settings > Ads when you have an approved account.