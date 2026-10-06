# FinVision AI — Full-Stack Release

This release separates the existing application into `frontend/` and `backend/` while preserving the existing application features and keeping the supplied environment credentials in `backend/.env` as requested.

## Local start

```bash
cd backend
npm install
npm start
```

Open http://localhost:3000

## Important

Secrets are **not** included in this ZIP. Use the separate `.env` file (place it at `backend/.env`, or set the same values in your host's dashboard). See `DEPLOY.md`.

## What's new in 2.3.1 (fix for admin login "Failed to fetch")
- The browser message "Failed to fetch" means the app could not reach the API at all (it is not a wrong-password error). The app now says which address it tried and shows a red banner when the server is unreachable.
- Server stays up in production even if `ADMIN_PASSWORD` is under 12 characters (before, it exited and the site went down). Admin login stays disabled until you set a stronger one; `/api/health` reports `admin` status.
- `channel_binding=require` is stripped from `DATABASE_URL` so the Neon handshake cannot crash startup.
- Opening the page from disk (`file://`) falls back to `http://localhost:3000`; `config.js` now loads with a relative path.
- New `npm run env:check` lists missing/weak `.env` values and tests the database. Startup also prints an `[env]` report.
- `.env`, `.env.example` and `render.yaml` now include the previously missing EmailJS, `CORS_ORIGIN`, `DB_INIT_RETRIES` and `PG_POOL_MAX` keys.
- All existing features are unchanged.

## What's new in 2.3.0
- Database: the SSL-mode warning is gone for any `sslmode=` spelling, and the first connection retries while a sleeping Neon database wakes up.
- Security: baseline security headers, optional `CORS_ORIGIN` lock-down, tighter rate limit on one-time-code endpoints, no `.env` baked into Docker images, production refuses weak admin passwords / missing JWT secrets.
- Reports: PDF now prints the rupee sign correctly (it used to render garbage); Excel savings % is a real number with `%` formatting and frozen headers.
- Admin console loads much faster (per-user queries run in parallel).
- All existing features are unchanged.

## Admin password
The administrator password always comes from `ADMIN_PASSWORD` in `backend/.env` and is re-applied on every start. "Forgot password" does not work for the admin account by design: edit `.env` and restart instead.

## v2.3.3
- `EMAILJS_TEMPLATE_ID` is now `template_g0uyfde` in `backend/.env`. Set the same value in the Render dashboard for production.
