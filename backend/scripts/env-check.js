// Checks backend/.env without starting the server.  Usage: npm run env:check
// Prints which settings are missing/weak, then tests the database and admin login data.
require('dotenv').config();
const { mailMode } = require('../mailer');
const env = process.env;
const ok = m => console.log('  [ok]      ' + m);
const warn = m => console.log('  [WARN]    ' + m);
const bad = m => { console.log('  [MISSING] ' + m); problems++; };
let problems = 0;

console.log('\nFinVision environment check\n');
env.DATABASE_URL ? ok('DATABASE_URL set (PostgreSQL)') : warn('DATABASE_URL empty -> local JSON file store');
['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET'].forEach(k => (env[k] && env[k].length >= 32) ? ok(k) : bad(k + ' (set a 96-character random value)'));
env.ADMIN_EMAIL ? ok('ADMIN_EMAIL = ' + env.ADMIN_EMAIL) : bad('ADMIN_EMAIL');
if (!env.ADMIN_PASSWORD) bad('ADMIN_PASSWORD');
else if (env.ADMIN_PASSWORD.length < 12) (env.NODE_ENV === 'production' ? bad : warn)('ADMIN_PASSWORD is under 12 characters' + (env.NODE_ENV === 'production' ? ' -> admin login is disabled in production' : ' (ok locally, refused in production)'));
else ok('ADMIN_PASSWORD length');
const mode = mailMode();
if (mode === 'emailjs' || mode === 'smtp') {
  ok('Email provider: ' + mode);
  if (mode === 'smtp' && !env.MAIL_FROM) warn('MAIL_FROM is empty');
} else (env.NODE_ENV === 'production' ? bad : warn)('No email provider (SMTP_USER/SMTP_PASS/MAIL_FROM or EMAILJS_*). ' + (mode === 'console' ? 'Codes print in the server console.' : 'Sign-up/reset return 503.'));
env.CORS_ORIGIN ? ok('CORS_ORIGIN = ' + env.CORS_ORIGIN) : warn('CORS_ORIGIN empty (fine when the backend serves the frontend)');
console.log('  [info]    NODE_ENV = ' + (env.NODE_ENV || '(not set -> development)') + ', PORT = ' + (env.PORT || 3000));

(async () => {
  try {
    const db = require('../db');
    await db.init();
    ok('Database connection (' + db.backend + ')');
    if (env.ADMIN_EMAIL) {
      const u = await db.getUserByEmail(env.ADMIN_EMAIL);
      u ? ok('Admin row exists, role=' + u.role + ', status=' + u.status) : warn('Admin row not created yet (created on first server start)');
    }
  } catch (e) { bad('Database connection failed: ' + e.message); }
  console.log(problems ? `\n${problems} problem(s) found.\n` : '\nAll required settings look good.\n');
  process.exit(problems ? 1 : 0);
})();
