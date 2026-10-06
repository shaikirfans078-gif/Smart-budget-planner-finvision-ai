// PostgreSQL (Neon) persistence for FinVision.
// Same exported API as db-file.js, so server.js is unchanged.
// Connection string comes ONLY from DATABASE_URL (never hard-code it).

const crypto = require('crypto');
const { Pool } = require('pg');

// Neon (and most managed Postgres) requires TLS. Newer versions of `pg` warn that
// sslmode=require/prefer/verify-ca will change meaning, so we normalise the URL
// to the strict `verify-full` behaviour that is in effect today. This silences the
// SECURITY WARNING without weakening anything, and works with either spelling in .env.
function normalizeConnectionString(raw) {
  if (!raw) return raw;
  try {
    const url = new URL(raw);
    const mode = url.searchParams.get('sslmode');
    if (mode && ['require', 'prefer', 'verify-ca'].includes(mode) && !url.searchParams.has('uselibpqcompat')) {
      url.searchParams.set('sslmode', 'verify-full');
    }
    // Neon's copy-paste string includes channel_binding=require. Some pg/pgbouncer
    // combinations fail the handshake because of it, which crashes startup and the
    // browser then shows "Failed to fetch". TLS (verify-full) already protects the
    // connection, so the parameter is dropped.
    url.searchParams.delete('channel_binding');
    return url.toString();
  } catch (_) {
    return raw; // not a parseable URL: let pg report the real problem
  }
}

const pool = new Pool({
  connectionString: normalizeConnectionString(process.env.DATABASE_URL),
  ssl: { rejectUnauthorized: true },
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
  keepAlive: true,
});
pool.on('error', err => console.error('[db] idle client error:', err.message));

const q = (text, params) => pool.query(text, params);
const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const normalizeEmail = e => String(e || '').trim().toLowerCase();
const iso = v => (v instanceof Date ? v.toISOString() : v);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role text NOT NULL DEFAULT 'user',
  status text NOT NULL DEFAULT 'active',
  email_verified boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_hash_idx ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx ON refresh_tokens(user_id);
CREATE TABLE IF NOT EXISTS profiles (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  records jsonb NOT NULL DEFAULT '{}',
  budget_plan jsonb,
  goals jsonb NOT NULL DEFAULT '[]',
  custom_categories jsonb NOT NULL DEFAULT '[]',
  category_labels jsonb NOT NULL DEFAULT '{}',
  currency text,
  investments jsonb NOT NULL DEFAULT '[]',
  debts jsonb NOT NULL DEFAULT '[]',
  other_assets numeric NOT NULL DEFAULT 0,
  other_liabilities numeric NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS accounts (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name text NOT NULL,
  type text,
  balance numeric NOT NULL DEFAULT 0,
  currency text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS accounts_user_idx ON accounts(user_id);
CREATE TABLE IF NOT EXISTS recurring_transactions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_id text,
  type text,
  category text,
  label text,
  amount numeric NOT NULL DEFAULT 0,
  frequency text,
  day_of_month integer,
  start_date text,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS recurring_user_idx ON recurring_transactions(user_id);
CREATE TABLE IF NOT EXISTS audit_logs (
  id uuid PRIMARY KEY,
  admin_id uuid,
  action text NOT NULL,
  target_user_id uuid,
  reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS otps (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  purpose text NOT NULL,
  code_hash text NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (email, purpose)
);
`;

// Neon scales idle databases to zero, so the very first connection after a quiet
// period can time out while the compute wakes up. Retry a few times before giving up.
async function init() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not set');
  const attempts = Number(process.env.DB_INIT_RETRIES || 4);
  let lastErr;
  for (let i = 1; i <= attempts; i++) {
    try {
      await q(SCHEMA);
      await q('SELECT 1');
      return { backend: 'postgres' };
    } catch (err) {
      lastErr = err;
      if (i < attempts) {
        const waitMs = 1500 * i;
        console.warn(`[db] connection attempt ${i}/${attempts} failed (${err.message}); retrying in ${waitMs / 1000}s...`);
        await new Promise(r => setTimeout(r, waitMs));
      }
    }
  }
  throw lastErr;
}

// ---------------- Users ----------------
function mapUser(r) {
  if (!r) return null;
  return {
    id: r.id, name: r.name, email: r.email, passwordHash: r.password_hash,
    role: r.role || 'user', status: r.status || 'active', emailVerified: r.email_verified !== false,
    createdAt: iso(r.created_at), updatedAt: iso(r.updated_at),
  };
}
const one = async (text, params) => (await q(text, params)).rows[0] || null;

async function getUserByEmail(email) {
  return mapUser(await one('SELECT * FROM users WHERE email=$1', [normalizeEmail(email)]));
}
async function getUserById(userId) {
  if (!/^[0-9a-f-]{36}$/i.test(String(userId))) return null;
  return mapUser(await one('SELECT * FROM users WHERE id=$1', [userId]));
}
async function createUser({ name, email, passwordHash, role = 'user', emailVerified = false }) {
  try {
    const r = await one(
      `INSERT INTO users (id,name,email,password_hash,role,status,email_verified)
       VALUES ($1,$2,$3,$4,$5,'active',$6) RETURNING *`,
      [id(), String(name).trim(), normalizeEmail(email), passwordHash, role, !!emailVerified]);
    return mapUser(r);
  } catch (e) {
    if (e.code === '23505') { const err = new Error('User already exists'); err.code = 'DUPLICATE_EMAIL'; throw err; }
    throw e;
  }
}
async function updateUserRole(userId, role) {
  return mapUser(await one(`UPDATE users SET role=$2, updated_at=now() WHERE id=$1 RETURNING *`, [userId, role === 'admin' ? 'admin' : 'user']));
}
async function ensureAdminUser({ name, email, passwordHash }) {
  if (!email || !passwordHash) return null;
  const normalized = normalizeEmail(email);
  const existing = await getUserByEmail(normalized);
  if (!existing) {
    return mapUser(await one(
      `INSERT INTO users (id,name,email,password_hash,role,status,email_verified)
       VALUES ($1,$2,$3,$4,'admin','active',true)
       ON CONFLICT (email) DO UPDATE SET role='admin', status='active', email_verified=true, updated_at=now()
       RETURNING *`,
      [id(), name || 'FinVision Administrator', normalized, passwordHash]));
  }
  if (existing.role !== 'admin' || existing.status !== 'active' || existing.emailVerified === false) {
    return mapUser(await one(`UPDATE users SET role='admin', status='active', email_verified=true, updated_at=now() WHERE id=$1 RETURNING *`, [existing.id]));
  }
  return existing;
}
async function setUserPasswordHash(userId, passwordHash) {
  const r = await one(`UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1 RETURNING *`, [userId, passwordHash]);
  if (!r) return null;
  await q('DELETE FROM refresh_tokens WHERE user_id=$1', [userId]);
  return mapUser(r);
}
async function listUsers() {
  return (await q('SELECT * FROM users ORDER BY created_at ASC')).rows.map(mapUser);
}
async function getUserAdminDetails(userId) {
  const user = await getUserById(userId);
  if (!user) return null;
  const profile = await getProfile(userId);
  const accounts = await listAccounts(userId);
  const recurring = await listRecurring(userId);
  return {
    user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status || 'active', emailVerified: user.emailVerified, createdAt: user.createdAt, updatedAt: user.updatedAt },
    profile, accounts, recurring,
    stats: {
      savedMonths: profile ? Object.keys(profile.records || {}).length : 0,
      goals: profile ? (profile.goals || []).length : 0,
      investments: profile ? (profile.investments || []).length : 0,
      debts: profile ? (profile.debts || []).length : 0,
      accounts: accounts.length,
      recurring: recurring.length,
    },
  };
}

// ---------------- Account security / administration ----------------
async function updateUserStatus(userId, status) {
  if (!['active', 'suspended'].includes(status)) return null;
  const r = await one(`UPDATE users SET status=$2, updated_at=now() WHERE id=$1 RETURNING *`, [userId, status]);
  if (!r) return null;
  if (status === 'suspended') await q('DELETE FROM refresh_tokens WHERE user_id=$1', [userId]);
  return mapUser(r);
}
async function deleteUser(userId) {
  const target = await getUserById(userId);
  if (!target) return false;
  await q('DELETE FROM otps WHERE email=$1', [target.email]);
  await q('DELETE FROM users WHERE id=$1', [userId]); // cascades tokens/profile/accounts/recurring
  return true;
}

// ---------------- Email verification & OTP ----------------
async function markEmailVerified(userId) {
  return mapUser(await one(`UPDATE users SET email_verified=true, updated_at=now() WHERE id=$1 RETURNING *`, [userId]));
}
async function updateUnverifiedRegistration(userId, { name, passwordHash }) {
  return mapUser(await one(
    `UPDATE users SET name=$2, password_hash=$3, updated_at=now() WHERE id=$1 AND email_verified=false RETURNING *`,
    [userId, String(name).trim(), passwordHash]));
}
async function saveOtp({ email, purpose, codeHash, expiresAt }) {
  await q(
    `INSERT INTO otps (id,email,purpose,code_hash,attempts,expires_at,created_at)
     VALUES ($1,$2,$3,$4,0,$5,now())
     ON CONFLICT (email,purpose) DO UPDATE SET id=EXCLUDED.id, code_hash=EXCLUDED.code_hash, attempts=0, expires_at=EXCLUDED.expires_at, created_at=now()`,
    [id(), normalizeEmail(email), purpose, codeHash, new Date(expiresAt).toISOString()]);
}
async function getOtp(email, purpose) {
  const r = await one('SELECT * FROM otps WHERE email=$1 AND purpose=$2', [normalizeEmail(email), purpose]);
  return r ? { id: r.id, email: r.email, purpose: r.purpose, codeHash: r.code_hash, attempts: r.attempts, expiresAt: iso(r.expires_at), createdAt: iso(r.created_at) } : null;
}
async function incrementOtpAttempts(email, purpose) {
  const r = await one('UPDATE otps SET attempts=attempts+1 WHERE email=$1 AND purpose=$2 RETURNING attempts', [normalizeEmail(email), purpose]);
  return r ? r.attempts : 0;
}
async function deleteOtp(email, purpose) {
  await q('DELETE FROM otps WHERE email=$1 AND purpose=$2', [normalizeEmail(email), purpose]);
}
async function purgeStaleData(unverifiedMaxAgeMs) {
  await q('DELETE FROM otps WHERE expires_at <= now()');
  const cutoff = new Date(Date.now() - unverifiedMaxAgeMs).toISOString();
  const stale = (await q(
    `DELETE FROM users WHERE email_verified=false AND role<>'admin' AND created_at < $1 RETURNING email`, [cutoff])).rows;
  if (stale.length) await q('DELETE FROM otps WHERE email = ANY($1)', [stale.map(r => r.email)]);
  return stale.length;
}

// ---------------- Audit log ----------------
async function addAuditLog({ adminId, action, targetUserId, reason }) {
  await q('INSERT INTO audit_logs (id,admin_id,action,target_user_id,reason) VALUES ($1,$2,$3,$4,$5)',
    [id(), adminId || null, action, targetUserId || null, String(reason || '').trim().slice(0, 500)]);
  await q(`DELETE FROM audit_logs WHERE id IN (SELECT id FROM audit_logs ORDER BY created_at DESC OFFSET 1000)`);
}
async function listAuditLogs(limit = 100) {
  const n = Math.max(1, Math.min(Number(limit) || 100, 500));
  return (await q('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1', [n])).rows.map(r => ({
    id: r.id, adminId: r.admin_id, action: r.action, targetUserId: r.target_user_id, reason: r.reason, createdAt: iso(r.created_at),
  }));
}

// ---------------- Refresh tokens ----------------
async function createRefreshToken({ userId, tokenHash, expiresAt }) {
  await q('DELETE FROM refresh_tokens WHERE expires_at <= now()');
  await q('INSERT INTO refresh_tokens (id,user_id,token_hash,expires_at) VALUES ($1,$2,$3,$4)',
    [id(), userId, tokenHash, new Date(expiresAt).toISOString()]);
}
async function findValidRefreshToken(tokenHash) {
  const r = await one('SELECT * FROM refresh_tokens WHERE token_hash=$1 AND expires_at > now()', [tokenHash]);
  return r ? { id: r.id, userId: r.user_id, tokenHash: r.token_hash, expiresAt: iso(r.expires_at) } : null;
}
async function deleteRefreshTokenByHash(tokenHash) {
  await q('DELETE FROM refresh_tokens WHERE token_hash=$1', [tokenHash]);
}

// ---------------- Financial profile ----------------
function mapProfile(r) {
  if (!r) return null;
  return {
    userId: r.user_id,
    records: r.records || {},
    budgetPlan: r.budget_plan || null,
    goals: r.goals || [],
    customCategories: r.custom_categories || [],
    categoryLabels: r.category_labels || {},
    currency: r.currency || null,
    investments: r.investments || [],
    debts: r.debts || [],
    otherAssets: r.other_assets != null ? Number(r.other_assets) : 0,
    otherLiabilities: r.other_liabilities != null ? Number(r.other_liabilities) : 0,
    updatedAt: iso(r.updated_at),
  };
}
async function getProfile(userId) {
  return mapProfile(await one('SELECT * FROM profiles WHERE user_id=$1', [userId]));
}
async function upsertProfile(userId, fields) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO profiles (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
    const map = {
      records: ['records', v => JSON.stringify(v ?? {})],
      budgetPlan: ['budget_plan', v => (v == null ? null : JSON.stringify(v))],
      goals: ['goals', v => JSON.stringify(v ?? [])],
      customCategories: ['custom_categories', v => JSON.stringify(v ?? [])],
      categoryLabels: ['category_labels', v => JSON.stringify(v ?? {})],
      currency: ['currency', v => v],
      investments: ['investments', v => JSON.stringify(v ?? [])],
      debts: ['debts', v => JSON.stringify(v ?? [])],
      otherAssets: ['other_assets', v => Number(v) || 0],
      otherLiabilities: ['other_liabilities', v => Number(v) || 0],
    };
    const sets = []; const vals = [userId];
    for (const [key, [col, fn]] of Object.entries(map)) {
      if (fields[key] !== undefined) { vals.push(fn(fields[key])); sets.push(`${col}=$${vals.length}`); }
    }
    sets.push('updated_at=now()');
    const res = await client.query(`UPDATE profiles SET ${sets.join(', ')} WHERE user_id=$1 RETURNING *`, vals);
    await client.query('COMMIT');
    return mapProfile(res.rows[0]);
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally { client.release(); }
}

// ---------------- Accounts ----------------
function mapAccount(r) {
  if (!r) return null;
  return { id: r.id, userId: r.user_id, name: r.name, type: r.type, balance: Number(r.balance), currency: r.currency, createdAt: iso(r.created_at) };
}
const isUuid = v => /^[0-9a-f-]{36}$/i.test(String(v));
async function listAccounts(userId) {
  return (await q('SELECT * FROM accounts WHERE user_id=$1 ORDER BY created_at ASC', [userId])).rows.map(mapAccount);
}
async function getAccount(accountId, userId) {
  if (!isUuid(accountId)) return null;
  return mapAccount(await one('SELECT * FROM accounts WHERE id=$1 AND user_id=$2', [accountId, userId]));
}
async function createAccount({ userId, name, type, balance, currency }) {
  return mapAccount(await one(
    'INSERT INTO accounts (id,user_id,name,type,balance,currency) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [id(), userId, name, type, Number(balance) || 0, currency]));
}
async function updateAccount(accountId, userId, fields) {
  if (!isUuid(accountId)) return null;
  const allowed = { name: 'name', type: 'type', balance: 'balance', currency: 'currency' };
  const sets = []; const vals = [accountId, userId];
  for (const [k, col] of Object.entries(allowed)) {
    if (fields[k] !== undefined) { vals.push(k === 'balance' ? Number(fields[k]) || 0 : fields[k]); sets.push(`${col}=$${vals.length}`); }
  }
  if (!sets.length) return getAccount(accountId, userId);
  return mapAccount(await one(`UPDATE accounts SET ${sets.join(', ')} WHERE id=$1 AND user_id=$2 RETURNING *`, vals));
}
async function deleteAccount(accountId, userId) {
  if (!isUuid(accountId)) return false;
  return (await q('DELETE FROM accounts WHERE id=$1 AND user_id=$2', [accountId, userId])).rowCount > 0;
}

// ---------------- Recurring transactions ----------------
function mapRecurring(r) {
  if (!r) return null;
  return {
    id: r.id, userId: r.user_id, accountId: r.account_id, type: r.type, category: r.category, label: r.label,
    amount: Number(r.amount), frequency: r.frequency, dayOfMonth: r.day_of_month, startDate: r.start_date,
    active: r.active, createdAt: iso(r.created_at),
  };
}
async function listRecurring(userId) {
  return (await q('SELECT * FROM recurring_transactions WHERE user_id=$1 ORDER BY created_at ASC', [userId])).rows.map(mapRecurring);
}
async function getRecurring(recurringId, userId) {
  if (!isUuid(recurringId)) return null;
  return mapRecurring(await one('SELECT * FROM recurring_transactions WHERE id=$1 AND user_id=$2', [recurringId, userId]));
}
async function createRecurring(item) {
  return mapRecurring(await one(
    `INSERT INTO recurring_transactions (id,user_id,account_id,type,category,label,amount,frequency,day_of_month,start_date,active)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true) RETURNING *`,
    [id(), item.userId, item.accountId || null, item.type, item.category, item.label, Number(item.amount) || 0,
     item.frequency, item.dayOfMonth ?? null, item.startDate ?? null]));
}
async function updateRecurring(recurringId, userId, fields) {
  if (!isUuid(recurringId)) return null;
  const allowed = { accountId: 'account_id', type: 'type', category: 'category', label: 'label', amount: 'amount',
    frequency: 'frequency', dayOfMonth: 'day_of_month', startDate: 'start_date', active: 'active' };
  const sets = []; const vals = [recurringId, userId];
  for (const [k, col] of Object.entries(allowed)) {
    if (fields[k] !== undefined) { vals.push(k === 'amount' ? Number(fields[k]) || 0 : fields[k]); sets.push(`${col}=$${vals.length}`); }
  }
  if (!sets.length) return getRecurring(recurringId, userId);
  return mapRecurring(await one(`UPDATE recurring_transactions SET ${sets.join(', ')} WHERE id=$1 AND user_id=$2 RETURNING *`, vals));
}
async function deleteRecurring(recurringId, userId) {
  if (!isUuid(recurringId)) return false;
  return (await q('DELETE FROM recurring_transactions WHERE id=$1 AND user_id=$2', [recurringId, userId])).rowCount > 0;
}
async function clearRecurringAccountRef(userId, accountId) {
  if (!isUuid(accountId)) return;
  await q('UPDATE recurring_transactions SET account_id=NULL WHERE user_id=$1 AND account_id=$2', [userId, accountId]);
}

async function ping() { await q('SELECT 1'); return true; }

module.exports = {
  init, ping, normalizeConnectionString,
  getUserByEmail, getUserById, createUser, updateUserRole, ensureAdminUser, setUserPasswordHash,
  markEmailVerified, updateUnverifiedRegistration, saveOtp, getOtp, incrementOtpAttempts, deleteOtp, purgeStaleData,
  listUsers, getUserAdminDetails, updateUserStatus, deleteUser, addAuditLog, listAuditLogs,
  createRefreshToken, findValidRefreshToken, deleteRefreshTokenByHash,
  getProfile, upsertProfile,
  listAccounts, getAccount, createAccount, updateAccount, deleteAccount,
  listRecurring, getRecurring, createRecurring, updateRecurring, deleteRecurring, clearRecurringAccountRef,
};
