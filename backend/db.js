// Storage selector.
//  - DATABASE_URL set  -> PostgreSQL (Neon), see db-pg.js
//  - DATABASE_URL unset -> local JSON file store, see db-file.js (original behaviour)
//
// NEW in 2.3.4: if PostgreSQL cannot be reached at startup (Neon paused, wrong
// password, no internet) and NODE_ENV is not "production", the server now falls
// back to the local JSON store instead of exiting. Previously the process exited,
// which showed up in the browser as ERR_CONNECTION_REFUSED on localhost:3000.
// Set DB_STRICT=1 to restore the old "refuse to start" behaviour.
const file = require('./db-file');
const usePg = !!process.env.DATABASE_URL;
const strictMode = process.env.NODE_ENV === 'production' || process.env.DB_STRICT === '1';
// In development, do not spend a minute retrying a dead database before the site comes up.
if (!strictMode && !process.env.DB_INIT_RETRIES) process.env.DB_INIT_RETRIES = '2';
const INIT_TIMEOUT_MS = Number(process.env.DB_INIT_TIMEOUT_MS || 30000);
let pg = null;
let current = file;
let backend = 'file';
if (usePg) {
  pg = require('./db-pg');
  current = pg;
  backend = 'postgres';
}

const strict = strictMode;

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('database did not answer within ' + Math.round(ms / 1000) + 's')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const api = new Proxy({}, {
  get(_t, prop) {
    if (prop === 'backend') return backend;
    if (prop === 'init') {
      return async (...args) => {
        try {
          const guarded = usePg && backend === 'postgres' && !strict;
          if (guarded) console.log('[db] Connecting to PostgreSQL (up to ' + Math.round(INIT_TIMEOUT_MS / 1000) + 's). Wait for "FinVision server running" before opening the browser...');
          return await (guarded ? withTimeout(current.init(...args), INIT_TIMEOUT_MS) : current.init(...args));
        } catch (err) {
          if (!usePg || backend !== 'postgres' || strict) throw err;
          console.error('[db] PostgreSQL unreachable: ' + (err && err.message));
          console.error('[db] Falling back to the LOCAL JSON file store so the app can start.');
          console.error('[db] Data saved now will NOT appear in Neon. Fix DATABASE_URL (or run "npm run db:check") and restart to use PostgreSQL.');
          current = file;
          backend = 'file';
          return await current.init(...args);
        }
      };
    }
    const v = current[prop];
    return typeof v === 'function' ? v.bind(current) : v;
  },
});

module.exports = api;
