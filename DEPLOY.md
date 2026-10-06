# Beginner Deployment Guide

## 1. Local
1. Install Node.js 20+.
2. Open a terminal in `backend/`.
3. Run `npm install`.
4. Check `backend/.env`.
5. Run `npm start`.
6. Open `http://localhost:3000`.
7. Test `http://localhost:3000/api/health`.

## 2. PostgreSQL
Set `DATABASE_URL` in `backend/.env` to your PostgreSQL/Neon connection string. The app supports a local JSON fallback when it is absent.

## 3. Separate frontend/backend hosting
Edit `frontend/config.js`:
```js
window.FINVISION_API_URL = 'https://YOUR-BACKEND-DOMAIN';
```
Then host `frontend/` as static files and `backend/` as the Node service.

## 4. Render
Build command:
```bash
npm --prefix backend install --omit=dev
```
Start command:
```bash
node backend/server.js
```
Health check:
```text
/api/health
```
Add the variables from `backend/.env` in Render's Environment settings rather than uploading the `.env` file.

## 5. Security
This ZIP does **not** contain `backend/.env`. Your real settings are delivered as a separate `.env` file.
- Local / VPS: put that file at `backend/.env`.
- Docker: put it next to `docker-compose.yml` and run `docker compose up -d --build`.
- Render/Railway/etc.: copy each `KEY=value` into the host's Environment settings (do not upload the file).
- `NODE_ENV=production` requires `DATABASE_URL`, both JWT secrets, an email provider and an `ADMIN_PASSWORD` of 12+ characters.
- The Neon password and EmailJS keys were shared in chat: rotate them in Neon / EmailJS and update `.env`.

## 6. Troubleshooting "Failed to fetch"
1. Run `cd backend && npm run env:check`. Fix every `[MISSING]` line.
2. Start with `npm start` and read the console. You must see `FinVision server running on port 3000`. If you see `[startup] Failed to initialize`, fix `DATABASE_URL` (Neon project paused/deleted, password rotated).
3. Open `http://localhost:3000/api/health`. Expect `{"status":"ok",...,"admin":"ready"}`. If it does not load, the server is not running.
4. Open the app from `http://localhost:3000` (not VS Code Live Server, not a double-clicked file).
5. Separate hosting: set `window.FINVISION_API_URL` in `frontend/config.js` and `CORS_ORIGIN` on the backend to the frontend URL.
6. Production (Render): `ADMIN_PASSWORD` needs 12+ characters, and an email provider must be set for sign-up/reset.

## 7. ERR_CONNECTION_REFUSED on localhost:3000 (v2.3.4 fix)
This error means **the server is not running**, so nothing is listening on port 3000.
1. Start it: `cd backend`, `npm install`, `npm start` (or double-click `start-windows.bat`).
2. Keep that terminal open. Wait for `FinVision server running on port 3000` (can take up to ~30s if Neon is waking up), then open `http://localhost:3000`.
3. Earlier versions exited when the Neon database was unreachable, which also caused this error. From v2.3.4, outside production the server falls back to the local JSON store and still starts (the console says so). Set `DB_STRICT=1` to disable that. In production it still refuses to start without a working database.
4. If port 3000 is busy, set `PORT=3001` in `backend/.env` and open `http://localhost:3001`.
