require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const db = require('./db');
const {
  hashPassword,
  verifyPassword,
  signAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashRefreshToken,
  refreshExpiryDate,
  generateOtp,
  hashOtp,
  otpMatches
} = require('./auth');
const { sendOtpEmail, mailReady, mailMode } = require('./mailer');

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function isStrongPassword(password) {
  return typeof password === 'string' && password.length >= 8 && /[A-Za-z]/.test(password) && /[0-9]/.test(password);
}

// Wraps an async route handler so a thrown/rejected error becomes a
// clean JSON 500 instead of crashing the process or hanging the request.
function asyncRoute(handler) {
  return (req, res) => {
    Promise.resolve(handler(req, res)).catch(err => {
      console.error(`[error] ${req.method} ${req.originalUrl}:`, err.message);
      if (!res.headersSent) res.status(500).json({ error: 'Something went wrong on the server. Please try again.' });
    });
  };
}

if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
  console.warn('[security] JWT_ACCESS_SECRET / JWT_REFRESH_SECRET are not set; using random temporary secrets (all logins reset on every restart). Set both in .env before deploying.');
}

if (process.env.NODE_ENV === 'production' && (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET)) {
  console.error('[startup] NODE_ENV=production requires JWT_ACCESS_SECRET and JWT_REFRESH_SECRET to be set.');
  process.exit(1);
}

process.on('unhandledRejection', reason => console.error('[unhandledRejection]', reason && reason.message ? reason.message : reason));

const app = express();
app.disable('x-powered-by');
// Behind Render/Railway/Vercel/nginx the real client IP is in X-Forwarded-For;
// without this the rate limiter sees every user as one IP (and logs warnings).
if (process.env.TRUST_PROXY) app.set('trust proxy', /^\d+$/.test(process.env.TRUST_PROXY) ? Number(process.env.TRUST_PROXY) : process.env.TRUST_PROXY);
// Baseline security headers (no extra dependency needed). The app relies on CDN
// scripts/styles, so a strict CSP is intentionally not set here.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});
// CORS stays fully open by default (so a separately hosted frontend keeps working).
// Optionally lock it down: CORS_ORIGIN=https://app.example.com,https://www.example.com
const corsOrigins = (process.env.CORS_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);
app.use(corsOrigins.length ? cors({ origin: corsOrigins }) : cors());
app.use(express.json({ limit: '2mb' }));
// CORS stays open (cors() with no options) so the finvision-ai-frontend
// project can still be hosted completely separately and call this API
// cross-origin if you choose to deploy it that way — nothing below removes
// that ability.
//
// This server also serves a static copy of the frontend from ./public
// (see public/index.html), so visiting the server's own URL (e.g.
// http://localhost:3000/) shows the app instead of "Cannot GET /". All
// API routes remain under /api and are unaffected.
const FRONTEND_DIR = path.join(__dirname, '..', 'frontend');
app.use(express.static(FRONTEND_DIR, {
  maxAge: '1h',
  setHeaders(res, filePath) {
    // Always revalidate the app shell and config so a new deploy is picked up immediately.
    if (/\.(html|js)$/i.test(filePath)) res.setHeader('Cache-Control', 'no-cache');
  },
}));

// Rate limiting: throttles login/register/refresh so a script can't
// brute-force passwords, and a looser general limit on the rest of the
// API so nothing can be hammered. Generous enough that a real user never
// notices it in normal use.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
});
// One-time-code endpoints get a tighter limit on top of the per-code attempt cap,
// so a bot can't keep requesting fresh codes to keep guessing.
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many code requests. Please wait a few minutes and try again.' },
});
app.use(['/api/auth/verify-email', '/api/auth/resend-otp', '/api/auth/forgot-password', '/api/auth/reset-password'], otpLimiter);
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

// Persistent data store: every read/write goes through db.js. The application
// now uses its own server-side local data store and does not require Supabase.
// Sensitive credentials and user data never belong in the frontend.

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  Promise.resolve().then(async () => {
    const tokenUser = verifyAccessToken(token);
    const currentUser = await db.getUserById(tokenUser.sub);
    if (!currentUser) return res.status(403).json({ error: 'Account no longer exists' });
    if (currentUser.status !== 'active') return res.status(403).json({ error: 'Your account is suspended. Contact an administrator.' });
    req.user = { ...tokenUser, name: currentUser.name, email: currentUser.email, role: currentUser.role, status: currentUser.status };
    next();
  }).catch(err => {
    if (res.headersSent) return;
    return res.status(401).json({ error: 'Invalid or expired access token', code: err.message === 'jwt expired' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID' });
  });
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(403).json({ error: 'Administrator access required' });
  Promise.resolve(db.getUserById(req.user.sub)).then(user => {
    // Check the current database role as well as the JWT claim so a role
    // change takes effect without waiting for an old access token to expire.
    if (!user || user.role !== 'admin' || user.status !== 'active') return res.status(403).json({ error: 'Administrator access required' });
    req.adminUser = user;
    next();
  }).catch(() => res.status(500).json({ error: 'Could not verify administrator access' }));
}

// Routes
// ---- One-time passcodes: email verification + password reset ----
const OTP_EXPIRES_MINUTES = Number(process.env.OTP_EXPIRES_MINUTES || 10);
const OTP_RESEND_SECONDS = Number(process.env.OTP_RESEND_SECONDS || 60);
const OTP_MAX_ATTEMPTS = 5;
const UNVERIFIED_ACCOUNT_TTL_MS = 24 * 60 * 60 * 1000;
const MAIL_UNAVAILABLE = { error: 'Email service is not configured on the server. Please contact the administrator.' };

function isValidOtpFormat(otp) { return typeof otp === 'string' && /^\d{6}$/.test(otp.trim()); }

// Creates and emails a fresh code. Returns { sent } or { cooldown } (seconds left).
async function sendOtp(user, purpose) {
  const existing = await db.getOtp(user.email, purpose);
  if (existing) {
    const waitMs = OTP_RESEND_SECONDS * 1000 - (Date.now() - new Date(existing.createdAt).getTime());
    if (waitMs > 0) return { cooldown: Math.ceil(waitMs / 1000) };
  }
  const otp = generateOtp();
  await db.saveOtp({
    email: user.email,
    purpose,
    codeHash: hashOtp(user.email, purpose, otp),
    expiresAt: new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000),
  });
  try {
    await sendOtpEmail({ to: user.email, name: user.name, otp, purpose, expiresMinutes: OTP_EXPIRES_MINUTES });
  } catch (err) {
    await db.deleteOtp(user.email, purpose); // don't leave a cooldown for a mail that never left
    throw err;
  }
  return { sent: true };
}

// Validates a submitted code. Wrong guesses are counted; after OTP_MAX_ATTEMPTS the code is burned.
async function checkOtp(email, purpose, otp) {
  const record = await db.getOtp(email, purpose);
  if (!record) return { error: 'Invalid or expired code. Please request a new one.' };
  if (new Date(record.expiresAt).getTime() <= Date.now()) {
    await db.deleteOtp(email, purpose);
    return { error: 'This code has expired. Please request a new one.' };
  }
  if (record.attempts >= OTP_MAX_ATTEMPTS) {
    await db.deleteOtp(email, purpose);
    return { error: 'Too many incorrect attempts. Please request a new code.' };
  }
  if (!otpMatches(record.codeHash, email, purpose, otp.trim())) {
    const attempts = await db.incrementOtpAttempts(email, purpose);
    const left = OTP_MAX_ATTEMPTS - attempts;
    if (left <= 0) {
      await db.deleteOtp(email, purpose);
      return { error: 'Too many incorrect attempts. Please request a new code.' };
    }
    return { error: `Incorrect code. ${left} attempt${left === 1 ? '' : 's'} left.` };
  }
  return { ok: true };
}

app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing required fields' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Please enter a valid email address' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters and include both letters and numbers' });
  if (!mailReady()) return res.status(503).json(MAIL_UNAVAILABLE);

  const cleanName = String(name).trim().slice(0, 100);
  const passwordHash = await hashPassword(password);
  let user = await db.getUserByEmail(email);
  if (user && user.emailVerified) return res.status(400).json({ error: 'User already exists' });

  if (user) {
    // Earlier sign-up was never verified: let them start over with the new details.
    user = await db.updateUnverifiedRegistration(user.id, { name: cleanName, passwordHash });
  } else {
    try {
      user = await db.createUser({ name: cleanName, email, passwordHash, role: 'user', emailVerified: false });
    } catch (err) {
      if (err.code === 'DUPLICATE_EMAIL') return res.status(400).json({ error: 'User already exists' });
      throw err;
    }
  }

  let emailSent = true;
  try { await sendOtp(user, 'verify'); } catch (err) {
    emailSent = false;
    console.error('[mail] Could not send verification code:', err.message);
  }
  res.json({
    needsVerification: true,
    email: user.email,
    emailSent,
    resendIn: OTP_RESEND_SECONDS,
    message: emailSent
      ? `We sent a 6-digit verification code to ${user.email}. It expires in ${OTP_EXPIRES_MINUTES} minutes.`
      : 'Your account was created, but we could not send the email just now. Tap "Resend code" to try again.',
  });
}));

app.post('/api/auth/verify-email', asyncRoute(async (req, res) => {
  const { email, otp } = req.body || {};
  if (!isValidEmail(email) || !isValidOtpFormat(otp)) return res.status(400).json({ error: 'Enter the 6-digit code from your email.' });
  const user = await db.getUserByEmail(email);
  if (!user) return res.status(400).json({ error: 'Invalid or expired code. Please request a new one.' });
  if (user.emailVerified) return res.status(400).json({ error: 'This email is already verified. Please log in.' });
  if (user.status !== 'active') return res.status(403).json({ error: 'This account is suspended. Contact an administrator.' });

  const result = await checkOtp(user.email, 'verify', otp);
  if (result.error) return res.status(400).json({ error: result.error });
  await db.deleteOtp(user.email, 'verify');
  const verified = await db.markEmailVerified(user.id);
  await issueSession(verified, res); // verified users are signed straight in
}));

app.post('/api/auth/resend-otp', asyncRoute(async (req, res) => {
  const { email, purpose } = req.body || {};
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Please enter a valid email address' });
  if (!['verify', 'reset'].includes(purpose)) return res.status(400).json({ error: 'Invalid request' });
  if (!mailReady()) return res.status(503).json(MAIL_UNAVAILABLE);
  const user = await db.getUserByEmail(email);
  // Same answer whether or not the account exists, so this can't be used to probe for emails.
  const eligible = user && user.status === 'active' && (purpose === 'verify' ? !user.emailVerified : user.role !== 'admin');
  if (eligible) {
    try { await sendOtp(user, purpose); } catch (err) { console.error('[mail] Could not send code:', err.message); }
  }
  res.json({ message: 'If that email can receive a code, a new one is on its way.', resendIn: OTP_RESEND_SECONDS });
}));

app.post('/api/auth/forgot-password', asyncRoute(async (req, res) => {
  const { email } = req.body || {};
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Please enter a valid email address' });
  if (!mailReady()) return res.status(503).json(MAIL_UNAVAILABLE);
  const user = await db.getUserByEmail(email);
  // Administrator passwords are managed through ADMIN_PASSWORD in .env, so they are not resettable here.
  if (user && user.status === 'active' && user.role !== 'admin') {
    try { await sendOtp(user, 'reset'); } catch (err) { console.error('[mail] Could not send reset code:', err.message); }
  }
  res.json({
    message: 'If an account exists for that email, a 6-digit reset code has been sent. It expires in ' + OTP_EXPIRES_MINUTES + ' minutes.',
    resendIn: OTP_RESEND_SECONDS,
  });
}));

app.post('/api/auth/reset-password', asyncRoute(async (req, res) => {
  const { email, otp, newPassword } = req.body || {};
  if (!isValidEmail(email) || !isValidOtpFormat(otp)) return res.status(400).json({ error: 'Enter the 6-digit code from your email.' });
  if (!isStrongPassword(newPassword)) return res.status(400).json({ error: 'Password must be at least 8 characters and include both letters and numbers' });
  const user = await db.getUserByEmail(email);
  if (!user || user.status !== 'active' || user.role === 'admin') return res.status(400).json({ error: 'Invalid or expired code. Please request a new one.' });

  const result = await checkOtp(user.email, 'reset', otp);
  if (result.error) return res.status(400).json({ error: result.error });

  const passwordHash = await hashPassword(newPassword);
  await db.setUserPasswordHash(user.id, passwordHash); // also signs out every existing session
  await db.markEmailVerified(user.id);                 // they just proved they own the mailbox
  await db.deleteOtp(user.email, 'reset');
  res.json({ message: 'Password updated. Please log in with your new password.' });
}));

async function issueSession(user, res) {
  const accessToken = signAccessToken(user);
  const refreshToken = generateRefreshToken();
  const tokenHash = hashRefreshToken(refreshToken);
  await db.createRefreshToken({ userId: user.id, tokenHash, expiresAt: refreshExpiryDate() });
  res.json({ accessToken, refreshToken, user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status } });
}

async function authenticateCredentials(email, password) {
  const user = await db.getUserByEmail(email);
  if (!user) return { error: 'Invalid credentials', status: 401 };
  const valid = await verifyPassword(String(password), user.passwordHash);
  if (!valid) return { error: 'Invalid credentials', status: 401 };
  if (user.status !== 'active') return { error: user.status === 'suspended' ? 'This account is suspended. Contact an administrator.' : 'This account is unavailable.', status: 403 };
  if (!user.emailVerified) return { error: 'Please verify your email to continue. Enter the code we sent to your inbox.', status: 403, code: 'EMAIL_NOT_VERIFIED', user };
  return { user };
}

// Unverified accounts that log in correctly get a fresh code and are pointed at the verify screen.
async function respondAuthError(result, res) {
  if (result.code === 'EMAIL_NOT_VERIFIED') {
    let emailSent = true;
    try { await sendOtp(result.user, 'verify'); } catch (err) { emailSent = false; console.error('[mail] Could not send verification code:', err.message); }
    return res.status(result.status).json({ error: result.error, code: result.code, email: result.user.email, emailSent, resendIn: OTP_RESEND_SECONDS });
  }
  return res.status(result.status).json({ error: result.error });
}

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing required fields' });
  const result = await authenticateCredentials(email, password);
  if (result.error) return respondAuthError(result, res);
  if (result.user.role === 'admin') {
    return res.status(403).json({ error: 'Administrator account detected. Please switch to Admin Access on the login page.' });
  }
  await issueSession(result.user, res);
}));

app.post('/api/auth/admin-login', asyncRoute(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Administrator email and password are required.' });
  const result = await authenticateCredentials(email, password);
  if (result.error) return respondAuthError(result, res);
  if (result.user.role !== 'admin') return res.status(403).json({ error: 'This account does not have administrator access.' });
  await issueSession(result.user, res);
}));

app.post('/api/auth/refresh', asyncRoute(async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });

  const incomingHash = hashRefreshToken(refreshToken);
  const tokenRecord = await db.findValidRefreshToken(incomingHash);
  if (!tokenRecord) return res.status(403).json({ error: 'Invalid or expired refresh token' });

  const user = await db.getUserById(tokenRecord.userId);
  if (!user) return res.status(403).json({ error: 'User not found' });
  if (user.status !== 'active') { await db.deleteRefreshTokenByHash(incomingHash); return res.status(403).json({ error: 'This account is suspended or unavailable.' }); }

  // Rotate Refresh Token
  await db.deleteRefreshTokenByHash(incomingHash);
  const newAccessToken = signAccessToken(user);
  const newRefreshToken = generateRefreshToken();
  const newTokenHash = hashRefreshToken(newRefreshToken);
  await db.createRefreshToken({ userId: user.id, tokenHash: newTokenHash, expiresAt: refreshExpiryDate() });

  res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
}));

app.post('/api/auth/logout', asyncRoute(async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    const incomingHash = hashRefreshToken(refreshToken);
    await db.deleteRefreshTokenByHash(incomingHash);
  }
  res.json({ message: 'Logged out successfully' });
}));

// ---- Administrator console ----
// Admin APIs are deliberately separate from normal user APIs and never return
// password hashes or refresh tokens. They can inspect account/profile data for
// support and administration, while ordinary users remain isolated by user id.
app.get('/api/admin/overview', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const users = await db.listUsers();
  let profiles = 0, accounts = 0, recurring = 0;
  const parts = await Promise.all(users.map(async user => {
    const [profile, accs, rec] = await Promise.all([db.getProfile(user.id), db.listAccounts(user.id), db.listRecurring(user.id)]);
    return { hasProfile: !!profile, accounts: accs.length, recurring: rec.length };
  }));
  parts.forEach(p => { if (p.hasProfile) profiles++; accounts += p.accounts; recurring += p.recurring; });
  res.json({ totals: { users: users.length, profiles, accounts, recurring }, generatedAt: new Date().toISOString() });
}));

app.get('/api/admin/users', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const users = await db.listUsers();
  const result = await Promise.all(users.map(async user => {
    const [profile, accounts, recurring] = await Promise.all([db.getProfile(user.id), db.listAccounts(user.id), db.listRecurring(user.id)]);
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      status: user.status || 'active',
      emailVerified: user.emailVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      stats: {
        savedMonths: profile ? Object.keys(profile.records || {}).length : 0,
        goals: profile ? (profile.goals || []).length : 0,
        investments: profile ? (profile.investments || []).length : 0,
        debts: profile ? (profile.debts || []).length : 0,
        accounts: accounts.length,
        recurring: recurring.length,
      },
    };
  }));
  res.json({ users: result });
}));

app.get('/api/admin/users/:id', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const details = await db.getUserAdminDetails(req.params.id);
  if (!details) return res.status(404).json({ error: 'User not found' });
  res.json(details);
}));

app.patch('/api/admin/users/:id/role', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const role = req.body && req.body.role;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Role must be user or admin' });
  if (req.params.id === req.user.sub && role !== 'admin') return res.status(400).json({ error: 'You cannot remove your own administrator access.' });
  if (role === 'user') {
    const users = await db.listUsers();
    const adminCount = users.filter(u => u.role === 'admin').length;
    const target = users.find(u => u.id === req.params.id);
    if (target && target.role === 'admin' && adminCount <= 1) {
      return res.status(400).json({ error: 'At least one administrator account must remain active.' });
    }
  }
  const updated = await db.updateUserRole(req.params.id, role);
  if (!updated) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: updated.id, name: updated.name, email: updated.email, role: updated.role } });
}));

app.patch('/api/admin/users/:id/status', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const status = req.body && req.body.status;
  const reason = req.body && req.body.reason;
  if (!['active', 'suspended'].includes(status)) return res.status(400).json({ error: 'Status must be active or suspended' });
  if (req.params.id === req.user.sub && status !== 'active') return res.status(400).json({ error: 'You cannot suspend your own administrator account.' });
  const target = await db.getUserById(req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found' });
  const updated = await db.updateUserStatus(req.params.id, status);
  await db.addAuditLog({ adminId: req.user.sub, action: status === 'suspended' ? 'suspend_user' : 'restore_user', targetUserId: req.params.id, reason });
  res.json({ user: { id: updated.id, name: updated.name, email: updated.email, role: updated.role, status: updated.status } });
}));

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const targetId = req.params.id;
  const reason = req.body && req.body.reason;
  if (targetId === req.user.sub) return res.status(400).json({ error: 'You cannot delete your own administrator account.' });
  const target = await db.getUserById(targetId);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.role === 'admin') {
    const admins = (await db.listUsers()).filter(u => u.role === 'admin' && u.status === 'active');
    if (admins.length <= 1) return res.status(400).json({ error: 'At least one active administrator account must remain.' });
  }
  await db.deleteUser(targetId);
  await db.addAuditLog({ adminId: req.user.sub, action: 'delete_user', targetUserId: targetId, reason: reason || 'Administrative account removal' });
  res.json({ message: 'User account and associated financial data were permanently removed.' });
}));

app.get('/api/admin/audit-logs', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  res.json({ logs: await db.listAuditLogs(100) });
}));

app.get('/api/protected-data', authenticateToken, (req, res) => {
  res.json({ message: `Hello ${req.user.name}, this is secured data from FinVision server!` });
});

// ---- Financial profile persistence ----
// This is what makes the dashboard's saved months, budget plan and goals
// survive a logout: they're stored server-side per-account (keyed by the
// user's id from their JWT), not just in the browser tab.
//
// `records` holds one entry per saved month, e.g. { "2026-08": {...} }.
// Only the most recent MAX_HISTORY_MONTHS are kept (oldest evicted first)
// so a user's "Previous Data" history never grows unbounded — this mirrors
// the same trim the frontend does client-side.
const MAX_HISTORY_MONTHS = 12;
function trimRecordsToMaxMonths(records) {
  const keys = Object.keys(records).sort(); // "YYYY-MM" sorts chronologically as a string
  while (keys.length > MAX_HISTORY_MONTHS) {
    delete records[keys.shift()];
  }
  return records;
}

app.get('/api/profile', authenticateToken, asyncRoute(async (req, res) => {
  const profile = await db.getProfile(req.user.sub);
  res.json({
    records: profile ? profile.records : {},
    budgetPlan: profile ? profile.budgetPlan : null,
    goals: profile ? profile.goals : [],
    customCategories: profile ? profile.customCategories : [],
    categoryLabels: profile ? profile.categoryLabels : {},
    currency: profile ? profile.currency : null,
    investments: profile ? profile.investments : [],
    debts: profile ? profile.debts : [],
    otherAssets: profile ? profile.otherAssets : 0,
    otherLiabilities: profile ? profile.otherLiabilities : 0,
    updatedAt: profile ? profile.updatedAt : null,
  });
}));

app.put('/api/profile', authenticateToken, asyncRoute(async (req, res) => {
  const { records, budgetPlan, goals, customCategories, categoryLabels, currency, investments, debts, otherAssets, otherLiabilities } = req.body || {};

  const patch = {};
  if (records && typeof records === 'object') patch.records = trimRecordsToMaxMonths({ ...records });
  if (budgetPlan && typeof budgetPlan === 'object') patch.budgetPlan = budgetPlan;
  if (Array.isArray(goals)) patch.goals = goals;
  if (Array.isArray(customCategories)) patch.customCategories = customCategories;
  if (categoryLabels && typeof categoryLabels === 'object') patch.categoryLabels = categoryLabels;
  if (typeof currency === 'string') patch.currency = currency;
  if (Array.isArray(investments)) patch.investments = investments;
  if (Array.isArray(debts)) patch.debts = debts;
  if (typeof otherAssets === 'number' && !Number.isNaN(otherAssets)) patch.otherAssets = otherAssets;
  if (typeof otherLiabilities === 'number' && !Number.isNaN(otherLiabilities)) patch.otherLiabilities = otherLiabilities;

  const profile = await db.upsertProfile(req.user.sub, patch);
  res.json({ message: 'Profile saved', updatedAt: profile.updatedAt });
}));

// ---- Multi-account balances (Net Worth tab) ----
const ACCOUNT_TYPES = ['bank', 'cash', 'credit_card', 'wallet', 'investment', 'other'];

app.get('/api/accounts', authenticateToken, asyncRoute(async (req, res) => {
  const accounts = await db.listAccounts(req.user.sub);
  res.json({ accounts });
}));
app.post('/api/accounts', authenticateToken, asyncRoute(async (req, res) => {
  const { name, type, balance, currency } = req.body || {};
  if (!name || typeof name !== 'string') return res.status(400).json({ error: 'Account name is required' });
  const account = await db.createAccount({
    userId: req.user.sub,
    name: name.trim(),
    type: ACCOUNT_TYPES.includes(type) ? type : 'other',
    balance: Number(balance) || 0,
    currency: typeof currency === 'string' ? currency : '₹',
  });
  res.status(201).json({ account });
}));
app.put('/api/accounts/:id', authenticateToken, asyncRoute(async (req, res) => {
  const existing = await db.getAccount(req.params.id, req.user.sub);
  if (!existing) return res.status(404).json({ error: 'Account not found' });
  const { name, type, balance, currency } = req.body || {};
  const patch = {};
  if (typeof name === 'string' && name.trim()) patch.name = name.trim();
  if (ACCOUNT_TYPES.includes(type)) patch.type = type;
  if (balance !== undefined && !Number.isNaN(Number(balance))) patch.balance = Number(balance);
  if (typeof currency === 'string') patch.currency = currency;
  const account = await db.updateAccount(req.params.id, req.user.sub, patch);
  res.json({ account });
}));
app.delete('/api/accounts/:id', authenticateToken, asyncRoute(async (req, res) => {
  const deleted = await db.deleteAccount(req.params.id, req.user.sub);
  if (!deleted) return res.status(404).json({ error: 'Account not found' });
  await db.clearRecurringAccountRef(req.user.sub, req.params.id);
  res.json({ message: 'Account deleted' });
}));

// ---- Recurring transactions (rent, subscriptions, salary, SIPs...) ----
const RECURRING_FREQUENCIES = ['weekly', 'monthly', 'yearly'];
function monthlyEquivalent(r) {
  if (r.frequency === 'weekly') return r.amount * 52 / 12;
  if (r.frequency === 'yearly') return r.amount / 12;
  return r.amount;
}
app.get('/api/recurring', authenticateToken, asyncRoute(async (req, res) => {
  const recurring = await db.listRecurring(req.user.sub);
  res.json({ recurring });
}));
// NOTE: this specific route must be registered before '/:id' routes below
// it would otherwise be shadowed by the '/:id' delete/put matchers.
app.get('/api/recurring/projection', authenticateToken, asyncRoute(async (req, res) => {
  const all = await db.listRecurring(req.user.sub);
  const items = all.filter(r => r.active);
  const income = items.filter(r => r.type === 'income').reduce((sum, r) => sum + monthlyEquivalent(r), 0);
  const byCategory = {};
  items.filter(r => r.type === 'expense').forEach(r => { byCategory[r.category] = (byCategory[r.category] || 0) + monthlyEquivalent(r); });
  res.json({ monthlyIncome: Math.round(income), monthlyExpensesByCategory: byCategory });
}));
app.post('/api/recurring', authenticateToken, asyncRoute(async (req, res) => {
  const { accountId, type, category, label, amount, frequency, dayOfMonth, startDate } = req.body || {};
  if (!label || typeof label !== 'string') return res.status(400).json({ error: 'A label/name is required' });
  if (type !== 'income' && type !== 'expense') return res.status(400).json({ error: "type must be 'income' or 'expense'" });
  const amt = Number(amount);
  if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'amount must be a positive number' });

  const recurring = await db.createRecurring({
    userId: req.user.sub,
    accountId: accountId || null,
    type,
    category: typeof category === 'string' ? category : 'others',
    label: label.trim(),
    amount: amt,
    frequency: RECURRING_FREQUENCIES.includes(frequency) ? frequency : 'monthly',
    dayOfMonth: Number.isInteger(dayOfMonth) ? Math.min(28, Math.max(1, dayOfMonth)) : 1,
    startDate: startDate || new Date().toISOString().slice(0, 10),
  });
  res.status(201).json({ recurring });
}));
app.put('/api/recurring/:id', authenticateToken, asyncRoute(async (req, res) => {
  const existing = await db.getRecurring(req.params.id, req.user.sub);
  if (!existing) return res.status(404).json({ error: 'Recurring transaction not found' });
  const { accountId, type, category, label, amount, frequency, dayOfMonth, active } = req.body || {};
  const patch = {};
  if (accountId !== undefined) patch.accountId = accountId || null;
  if (type === 'income' || type === 'expense') patch.type = type;
  if (typeof category === 'string') patch.category = category;
  if (typeof label === 'string' && label.trim()) patch.label = label.trim();
  if (amount !== undefined && Number.isFinite(Number(amount)) && Number(amount) > 0) patch.amount = Number(amount);
  if (RECURRING_FREQUENCIES.includes(frequency)) patch.frequency = frequency;
  if (Number.isInteger(dayOfMonth)) patch.dayOfMonth = Math.min(28, Math.max(1, dayOfMonth));
  if (typeof active === 'boolean') patch.active = active;
  const recurring = await db.updateRecurring(req.params.id, req.user.sub, patch);
  res.json({ recurring });
}));
app.delete('/api/recurring/:id', authenticateToken, asyncRoute(async (req, res) => {
  const deleted = await db.deleteRecurring(req.params.id, req.user.sub);
  if (!deleted) return res.status(404).json({ error: 'Recurring transaction not found' });
  res.json({ message: 'Recurring transaction deleted' });
}));

// ---- PDF / Excel reports (Reports tab) ----
function monthLabel(key) {
  const [y, m] = key.split('-');
  const d = new Date(Number(y), Number(m) - 1, 1);
  return d.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
}
function sortedRecordEntries(records) {
  return Object.entries(records || {}).sort(([a], [b]) => a.localeCompare(b));
}
// PDFKit's built-in Helvetica only covers WinAnsi, so symbols such as ₹ or ₩ would
// print as garbage. Map them to safe text; € £ ¥ $ are WinAnsi and pass through.
const PDF_CURRENCY_FALLBACK = { '₹': 'Rs. ', '₩': 'KRW ', '₽': 'RUB ', '₺': 'TRY ', '₦': 'NGN ', '₫': 'VND ', '₱': 'PHP ', '฿': 'THB ' };
function pdfSafeCurrency(symbol) {
  const s = String(symbol || '');
  if (PDF_CURRENCY_FALLBACK[s]) return PDF_CURRENCY_FALLBACK[s];
  return /^[\x20-\x7E\u00A0-\u00FF\u20AC]*$/.test(s) ? s : (s.replace(/[^\x20-\x7E]/g, '').trim() + ' ');
}
app.get('/api/reports/pdf', authenticateToken, asyncRoute(async (req, res) => {
  const profile = await db.getProfile(req.user.sub);
  const records = sortedRecordEntries(profile ? profile.records : {});
  const currency = pdfSafeCurrency((profile && profile.currency) || '₹');
  const goals = (profile && profile.goals) || [];

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="finvision-report.pdf"');

  const doc = new PDFDocument({ margin: 40 });
  doc.on('error', err => { console.error('[pdf]', err.message); res.end(); });
  doc.pipe(res);

  doc.fontSize(20).fillColor('#4338ca').text('FinVision AI — Financial Report', { align: 'left' });
  doc.fontSize(9).fillColor('#64748b').text(`Generated ${new Date().toLocaleString()}`);
  doc.moveDown(1.2);

  if (records.length === 0) {
    doc.fontSize(11).fillColor('#1e293b').text('No saved months yet. Save a month from the dashboard to see it here.');
  }
  records.forEach(([key, rec]) => {
    const expenseKeys = Object.keys(rec).filter(k => k !== 'income');
    const totalExpenses = expenseKeys.reduce((sum, k) => sum + (Number(rec[k]) || 0), 0);
    const income = Number(rec.income) || 0;
    const net = income - totalExpenses;

    doc.moveDown(0.6);
    doc.fontSize(13).fillColor('#312e81').text(monthLabel(key));
    doc.moveDown(0.2);
    doc.fontSize(10).fillColor('#1e293b');
    doc.text(`Income: ${currency}${income.toLocaleString('en-IN')}`);
    doc.text(`Total Expenses: ${currency}${totalExpenses.toLocaleString('en-IN')}`);
    doc.fillColor(net >= 0 ? '#047857' : '#be123c').text(`Net Savings: ${currency}${net.toLocaleString('en-IN')}`);
    doc.fillColor('#1e293b');
    expenseKeys.forEach(k => doc.fontSize(9).fillColor('#475569').text(`   • ${k}: ${currency}${Number(rec[k] || 0).toLocaleString('en-IN')}`));
    doc.moveDown(0.3);
    doc.strokeColor('#e2e8f0').moveTo(doc.x, doc.y).lineTo(555, doc.y).stroke();
  });

  if (goals.length > 0) {
    doc.addPage();
    doc.fontSize(16).fillColor('#4338ca').text('Savings Goals');
    doc.moveDown(0.5);
    goals.forEach(g => {
      doc.fontSize(10).fillColor('#1e293b').text(`${g.item}: target ${currency}${Number(g.cost || 0).toLocaleString('en-IN')} in ${g.months} month(s) — ${g.feasible ? 'On track' : 'Needs adjustment'}`);
    });
  }
  doc.end();
}));
app.get('/api/reports/excel', authenticateToken, asyncRoute(async (req, res) => {
  const profile = await db.getProfile(req.user.sub);
  const records = sortedRecordEntries(profile ? profile.records : {});
  const currency = (profile && profile.currency) || '₹';

  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'FinVision AI';
  workbook.created = new Date();

  const summary = workbook.addWorksheet('Summary');
  summary.columns = [
    { header: 'Month', key: 'month', width: 14 }, { header: 'Income', key: 'income', width: 14 },
    { header: 'Total Expenses', key: 'expenses', width: 16 }, { header: 'Net Savings', key: 'net', width: 14 },
    { header: 'Savings %', key: 'pct', width: 12 },
  ];
  summary.getRow(1).font = { bold: true };

  const detail = workbook.addWorksheet('Category Detail');
  const categorySet = new Set();
  records.forEach(([, rec]) => Object.keys(rec).filter(k => k !== 'income').forEach(k => categorySet.add(k)));
  const categories = [...categorySet];
  detail.columns = [{ header: 'Month', key: 'month', width: 14 }, ...categories.map(c => ({ header: c, key: c, width: 14 }))];
  detail.getRow(1).font = { bold: true };

  records.forEach(([key, rec]) => {
    const expenseKeys = Object.keys(rec).filter(k => k !== 'income');
    const totalExpenses = expenseKeys.reduce((sum, k) => sum + (Number(rec[k]) || 0), 0);
    const income = Number(rec.income) || 0;
    const net = income - totalExpenses;
    summary.addRow({ month: monthLabel(key), income, expenses: totalExpenses, net, pct: income > 0 ? net / income : 0 });
    const row = { month: monthLabel(key) };
    categories.forEach(c => { row[c] = Number(rec[c]) || 0; });
    detail.addRow(row);
  });

  summary.getColumn('income').numFmt = `"${currency}"#,##0`;
  summary.getColumn('expenses').numFmt = `"${currency}"#,##0`;
  summary.getColumn('net').numFmt = `"${currency}"#,##0`;
  summary.getColumn('pct').numFmt = '0.0%';
  summary.views = [{ state: 'frozen', ySplit: 1 }];
  detail.views = [{ state: 'frozen', xSplit: 1, ySplit: 1 }];

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="finvision-report.xlsx"');
  await workbook.xlsx.write(res);
  res.end();
}));

// Health check must be registered before the generic /api fallback.
app.get('/api/health', asyncRoute(async (req, res) => {
  try {
    if (typeof db.ping === 'function') await db.ping();
    res.json({ status: 'ok', storage: db.backend, admin: adminStatus, mail: mailMode() });
  } catch (err) {
    res.status(503).json({ status: 'degraded', storage: db.backend, admin: adminStatus, mail: mailMode() });
  }
}));

// Catch-all for unmatched /api/* routes: always return JSON.
app.use('/api', (req, res) => {
  res.status(404).json({ error: `No API route: ${req.method} ${req.originalUrl}` });
});

// SPA fallback: any other GET (e.g. a refresh on a client-side route, or
// just "/") resolves to the app shell instead of a bare "Cannot GET" page.
app.get('*', (req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
});

const PORT = process.env.PORT || 3000;
let adminStatus = 'unknown';

// Prints which settings are missing/weak so startup problems are obvious in the console.
function reportEnvironment() {
  const missing = [], advice = [];
  if (!process.env.DATABASE_URL) advice.push('DATABASE_URL is empty -> using the local JSON file store (data is NOT shared/persistent on hosts like Render).');
  if (!process.env.JWT_ACCESS_SECRET) missing.push('JWT_ACCESS_SECRET');
  if (!process.env.JWT_REFRESH_SECRET) missing.push('JWT_REFRESH_SECRET');
  if (!process.env.ADMIN_EMAIL) missing.push('ADMIN_EMAIL');
  if (!process.env.ADMIN_PASSWORD) missing.push('ADMIN_PASSWORD');
  if (mailMode() !== 'emailjs' && mailMode() !== 'smtp') {
    advice.push('No email provider: set SMTP_HOST/SMTP_USER/SMTP_PASS/MAIL_FROM (or all four EMAILJS_*). Without it, sign-up OTP codes only print to this console' + (process.env.NODE_ENV === 'production' ? ' and sign-up/reset return 503.' : '.'));
  } else if (mailMode() === 'smtp' && !process.env.MAIL_FROM) {
    advice.push('MAIL_FROM is empty: set it (e.g. FinVision <you@gmail.com>) so the From address is valid.');
  }
  if (!process.env.CORS_ORIGIN) advice.push('CORS_ORIGIN is empty (API open to any website). Set it to your frontend URL when hosting the frontend separately.');
  if (missing.length) console.warn('[env] Missing required values: ' + missing.join(', '));
  advice.forEach(a => console.warn('[env] ' + a));
}

async function bootstrap() {
  reportEnvironment();
  const store = await db.init();
  console.log(`[db] Storage backend: ${store.backend}${store.backend === 'postgres' ? ' (Neon/PostgreSQL)' : ' (local JSON file - set DATABASE_URL to use PostgreSQL)'}`);
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminEmail && adminPassword) {
    const weakAdmin = adminPassword.length < 12 || /^(1234|password|admin|qwerty)/i.test(adminPassword);
    if (weakAdmin && process.env.NODE_ENV === 'production') {
      // Previously the process exited here, so the site went down and the browser
      // only showed "Failed to fetch". Keep the API up, refuse to apply the weak
      // password, and say exactly what to fix.
      adminStatus = 'disabled-weak-password';
      console.error('[startup] ADMIN_PASSWORD must be at least 12 characters and not a common pattern when NODE_ENV=production. Admin login is DISABLED until you set a stronger ADMIN_PASSWORD and restart.');
    } else {
      if (weakAdmin) console.warn('[security] ADMIN_PASSWORD should be at least 12 characters (this will be refused when NODE_ENV=production).');
      const passwordHash = await hashPassword(adminPassword);
      const admin = await db.ensureAdminUser({
        name: process.env.ADMIN_NAME || 'FinVision Administrator',
        email: adminEmail,
        passwordHash,
      });
      if (admin && !(await verifyPassword(adminPassword, admin.passwordHash))) {
        await db.setUserPasswordHash(admin.id, passwordHash);
        console.log('[security] Administrator password updated from .env');
      }
      adminStatus = 'ready';
      console.log(`[security] Administrator account ready: ${adminEmail}`);
    }
  } else {
    adminStatus = 'not-configured';
    console.warn('[security] ADMIN_EMAIL/ADMIN_PASSWORD are not configured; admin mode is disabled until they are set.');
  }

  const housekeeping = () => db.purgeStaleData(UNVERIFIED_ACCOUNT_TTL_MS).catch(err => console.error('[housekeeping]', err.message));
  await housekeeping();
  setInterval(housekeeping, 60 * 60 * 1000).unref();
  const mode = mailMode();
  if (mode === 'none') console.warn('[mail] NODE_ENV=production but neither EMAILJS_* nor SMTP_* is configured: sign-up and password reset will be unavailable.');
  else if (mode === 'console') console.warn('[mail] No email provider configured: verification/reset codes will be printed in this console (development mode).');
  else console.log(`[mail] Email provider: ${mode}`);

  const server = app.listen(PORT, () => {
    console.log(`FinVision server running on port ${PORT}`);
  });
  // Graceful shutdown so hosts can redeploy without dropped requests.
  const shutdown = sig => {
    console.log(`[server] ${sig} received, shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

bootstrap().catch(error => {
  console.error('[startup] Failed to initialize FinVision:', error);
  console.error('[startup] The server could not start, so the browser will show "Failed to fetch". Most common cause: DATABASE_URL in backend/.env is wrong, expired, or the Neon project is paused/deleted. Run "npm run db:check" to test it.');
  process.exit(1);
});
