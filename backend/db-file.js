// Local file-backed persistence for FinVision (fallback used when DATABASE_URL is not set).
// No Supabase or external database credentials are required.
// The JSON store is kept outside the frontend and written atomically.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'finvision.json');

const DEFAULT_STATE = {
  users: [],
  refreshTokens: [],
  profiles: [],
  accounts: [],
  recurringTransactions: [],
  auditLogs: [],
  otps: [],
};

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify(DEFAULT_STATE, null, 2), { mode: 0o600 });

function loadState() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      refreshTokens: Array.isArray(parsed.refreshTokens) ? parsed.refreshTokens : [],
      profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [],
      accounts: Array.isArray(parsed.accounts) ? parsed.accounts : [],
      recurringTransactions: Array.isArray(parsed.recurringTransactions) ? parsed.recurringTransactions : [],
      auditLogs: Array.isArray(parsed.auditLogs) ? parsed.auditLogs : [],
      otps: Array.isArray(parsed.otps) ? parsed.otps : [],
    };
  } catch (error) {
    throw new Error(`[db] Could not read ${DATA_FILE}: ${error.message}`);
  }
}

let state = loadState();
let writeQueue = Promise.resolve();

function saveState() {
  const snapshot = JSON.stringify(state, null, 2);
  const tmp = `${DATA_FILE}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  // Each write runs after the previous one finished (success OR failure), so
  // one failed write can never block every later save.
  const run = writeQueue.catch(() => {}).then(async () => {
    try {
      await fs.promises.writeFile(tmp, snapshot, { mode: 0o600 });
      await fs.promises.rename(tmp, DATA_FILE);
    } catch (error) {
      try { fs.unlinkSync(tmp); } catch (_) {}
      throw new Error(`[db] Could not persist data: ${error.message}`);
    }
  });
  writeQueue = run.catch(() => {});
  return run;
}

function id() { return crypto.randomUUID(); }
function now() { return new Date().toISOString(); }
function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }

// ---------------- Users ----------------
function mapUser(row) {
  if (!row) return null;
  return { id: row.id, name: row.name, email: row.email, passwordHash: row.passwordHash, role: row.role || 'user', status: row.status || 'active', emailVerified: row.emailVerified !== false, createdAt: row.createdAt, updatedAt: row.updatedAt };
}

async function getUserByEmail(email) {
  return mapUser(state.users.find(u => u.email === normalizeEmail(email)) || null);
}

async function getUserById(userId) {
  return mapUser(state.users.find(u => u.id === userId) || null);
}

async function createUser({ name, email, passwordHash, role = 'user', emailVerified = false }) {
  const normalized = normalizeEmail(email);
  if (state.users.some(u => u.email === normalized)) {
    const error = new Error('User already exists');
    error.code = 'DUPLICATE_EMAIL';
    throw error;
  }
  const timestamp = now();
  const user = { id: id(), name: String(name).trim(), email: normalized, passwordHash, role, status: 'active', emailVerified: !!emailVerified, createdAt: timestamp, updatedAt: timestamp };
  state.users.push(user);
  await saveState();
  return mapUser(user);
}

async function updateUserRole(userId, role) {
  const user = state.users.find(u => u.id === userId);
  if (!user) return null;
  user.role = role === 'admin' ? 'admin' : 'user';
  user.updatedAt = now();
  await saveState();
  return mapUser(user);
}

async function ensureAdminUser({ name, email, passwordHash }) {
  if (!email || !passwordHash) return null;
  const normalized = normalizeEmail(email);
  let user = state.users.find(u => u.email === normalized);
  if (!user) {
    const timestamp = now();
    user = { id: id(), name: name || 'FinVision Administrator', email: normalized, passwordHash, role: 'admin', status: 'active', emailVerified: true, createdAt: timestamp, updatedAt: timestamp };
    state.users.push(user);
    await saveState();
  } else {
    let changed = false;
    if (user.role !== 'admin') { user.role = 'admin'; changed = true; }
    if (user.status !== 'active') { user.status = 'active'; changed = true; }
    if (user.emailVerified === false) { user.emailVerified = true; changed = true; }
    if (changed) { user.updatedAt = now(); await saveState(); }
  }
  return mapUser(user);
}

// Used at startup so changing ADMIN_PASSWORD in .env really changes the login.
async function setUserPasswordHash(userId, passwordHash) {
  const user = state.users.find(u => u.id === userId);
  if (!user) return null;
  user.passwordHash = passwordHash;
  user.updatedAt = now();
  state.refreshTokens = state.refreshTokens.filter(t => t.userId !== userId);
  await saveState();
  return mapUser(user);
}

async function listUsers() {
  return state.users.map(mapUser).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
}

async function getUserAdminDetails(userId) {
  const user = await getUserById(userId);
  if (!user) return null;
  const profile = await getProfile(userId);
  const accounts = await listAccounts(userId);
  const recurring = await listRecurring(userId);
  return {
    user: { id: user.id, name: user.name, email: user.email, role: user.role, status: user.status || 'active', emailVerified: user.emailVerified, createdAt: user.createdAt, updatedAt: user.updatedAt },
    profile,
    accounts,
    recurring,
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
  const user = state.users.find(u => u.id === userId);
  if (!user) return null;
  user.status = status;
  user.updatedAt = now();
  if (status === 'suspended') {
    state.refreshTokens = state.refreshTokens.filter(t => t.userId !== userId);
  }
  await saveState();
  return mapUser(user);
}

async function deleteUser(userId) {
  const target = state.users.find(u => u.id === userId);
  if (!target) return false;
  state.otps = state.otps.filter(o => o.email !== target.email);
  state.users = state.users.filter(u => u.id !== userId);
  state.refreshTokens = state.refreshTokens.filter(t => t.userId !== userId);
  state.profiles = state.profiles.filter(p => p.userId !== userId);
  state.accounts = state.accounts.filter(a => a.userId !== userId);
  state.recurringTransactions = state.recurringTransactions.filter(r => r.userId !== userId);
  await saveState();
  return true;
}

// ---------------- Email verification & one-time passcodes ----------------
async function markEmailVerified(userId) {
  const user = state.users.find(u => u.id === userId);
  if (!user) return null;
  if (user.emailVerified !== true) {
    user.emailVerified = true;
    user.updatedAt = now();
    await saveState();
  }
  return mapUser(user);
}

// Lets someone retry sign-up with an email whose first attempt was never verified.
async function updateUnverifiedRegistration(userId, { name, passwordHash }) {
  const user = state.users.find(u => u.id === userId);
  if (!user || user.emailVerified !== false) return null;
  user.name = String(name).trim();
  user.passwordHash = passwordHash;
  user.updatedAt = now();
  await saveState();
  return mapUser(user);
}

async function saveOtp({ email, purpose, codeHash, expiresAt }) {
  const normalized = normalizeEmail(email);
  state.otps = state.otps.filter(o => !(o.email === normalized && o.purpose === purpose));
  state.otps.push({ id: id(), email: normalized, purpose, codeHash, attempts: 0, expiresAt: new Date(expiresAt).toISOString(), createdAt: now() });
  await saveState();
}

async function getOtp(email, purpose) {
  const normalized = normalizeEmail(email);
  const otp = state.otps.find(o => o.email === normalized && o.purpose === purpose);
  return otp ? { ...otp } : null;
}

async function incrementOtpAttempts(email, purpose) {
  const normalized = normalizeEmail(email);
  const otp = state.otps.find(o => o.email === normalized && o.purpose === purpose);
  if (!otp) return 0;
  otp.attempts = (otp.attempts || 0) + 1;
  await saveState();
  return otp.attempts;
}

async function deleteOtp(email, purpose) {
  const normalized = normalizeEmail(email);
  const before = state.otps.length;
  state.otps = state.otps.filter(o => !(o.email === normalized && o.purpose === purpose));
  if (state.otps.length !== before) await saveState();
}

// Housekeeping: drop expired codes and sign-ups that were never verified.
async function purgeStaleData(unverifiedMaxAgeMs) {
  const nowMs = Date.now();
  const beforeOtps = state.otps.length;
  state.otps = state.otps.filter(o => new Date(o.expiresAt).getTime() > nowMs);
  const stale = state.users.filter(u => u.emailVerified === false && u.role !== 'admin' && nowMs - new Date(u.createdAt).getTime() > unverifiedMaxAgeMs);
  if (stale.length) {
    const ids = new Set(stale.map(u => u.id));
    const emails = new Set(stale.map(u => u.email));
    state.users = state.users.filter(u => !ids.has(u.id));
    state.refreshTokens = state.refreshTokens.filter(t => !ids.has(t.userId));
    state.profiles = state.profiles.filter(p => !ids.has(p.userId));
    state.accounts = state.accounts.filter(a => !ids.has(a.userId));
    state.recurringTransactions = state.recurringTransactions.filter(r => !ids.has(r.userId));
    state.otps = state.otps.filter(o => !emails.has(o.email));
  }
  if (stale.length || state.otps.length !== beforeOtps) await saveState();
  return stale.length;
}

async function addAuditLog({ adminId, action, targetUserId, reason }) {
  state.auditLogs.push({ id: id(), adminId, action, targetUserId: targetUserId || null, reason: String(reason || '').trim().slice(0, 500), createdAt: now() });
  if (state.auditLogs.length > 1000) state.auditLogs = state.auditLogs.slice(-1000);
  await saveState();
}

async function listAuditLogs(limit = 100) {
  return state.auditLogs.slice(-Math.max(1, Math.min(Number(limit) || 100, 500))).reverse();
}

// ---------------- Refresh tokens ----------------
async function createRefreshToken({ userId, tokenHash, expiresAt }) {
  state.refreshTokens = state.refreshTokens.filter(t => new Date(t.expiresAt) > new Date());
  state.refreshTokens.push({ id: id(), userId, tokenHash, expiresAt: new Date(expiresAt).toISOString(), createdAt: now() });
  await saveState();
}

async function findValidRefreshToken(tokenHash) {
  const token = state.refreshTokens.find(t => t.tokenHash === tokenHash && new Date(t.expiresAt) > new Date());
  return token ? { id: token.id, userId: token.userId, tokenHash: token.tokenHash, expiresAt: token.expiresAt } : null;
}

async function deleteRefreshTokenByHash(tokenHash) {
  const before = state.refreshTokens.length;
  state.refreshTokens = state.refreshTokens.filter(t => t.tokenHash !== tokenHash);
  if (state.refreshTokens.length !== before) await saveState();
}

// ---------------- Financial profile ----------------
function defaultProfile(userId) {
  const timestamp = now();
  return {
    userId,
    records: {},
    budgetPlan: null,
    goals: [],
    customCategories: [],
    categoryLabels: {},
    currency: null,
    investments: [],
    debts: [],
    otherAssets: 0,
    otherLiabilities: 0,
    updatedAt: timestamp,
  };
}

function mapProfile(row) {
  if (!row) return null;
  return {
    userId: row.userId,
    records: row.records || {},
    budgetPlan: row.budgetPlan || null,
    goals: row.goals || [],
    customCategories: row.customCategories || [],
    categoryLabels: row.categoryLabels || {},
    currency: row.currency || null,
    investments: row.investments || [],
    debts: row.debts || [],
    otherAssets: row.otherAssets != null ? Number(row.otherAssets) : 0,
    otherLiabilities: row.otherLiabilities != null ? Number(row.otherLiabilities) : 0,
    updatedAt: row.updatedAt,
  };
}

async function getProfile(userId) {
  return mapProfile(state.profiles.find(p => p.userId === userId) || null);
}

async function upsertProfile(userId, fields) {
  let profile = state.profiles.find(p => p.userId === userId);
  if (!profile) {
    profile = defaultProfile(userId);
    state.profiles.push(profile);
  }
  if (fields.records !== undefined) profile.records = fields.records;
  if (fields.budgetPlan !== undefined) profile.budgetPlan = fields.budgetPlan;
  if (fields.goals !== undefined) profile.goals = fields.goals;
  if (fields.customCategories !== undefined) profile.customCategories = fields.customCategories;
  if (fields.categoryLabels !== undefined) profile.categoryLabels = fields.categoryLabels;
  if (fields.currency !== undefined) profile.currency = fields.currency;
  if (fields.investments !== undefined) profile.investments = fields.investments;
  if (fields.debts !== undefined) profile.debts = fields.debts;
  if (fields.otherAssets !== undefined) profile.otherAssets = fields.otherAssets;
  if (fields.otherLiabilities !== undefined) profile.otherLiabilities = fields.otherLiabilities;
  profile.updatedAt = now();
  await saveState();
  return mapProfile(profile);
}

// ---------------- Accounts ----------------
function mapAccount(row) {
  if (!row) return null;
  return { id: row.id, userId: row.userId, name: row.name, type: row.type, balance: Number(row.balance), currency: row.currency, createdAt: row.createdAt };
}

async function listAccounts(userId) {
  return state.accounts.filter(a => a.userId === userId).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt))).map(mapAccount);
}

async function getAccount(accountId, userId) {
  return mapAccount(state.accounts.find(a => a.id === accountId && a.userId === userId) || null);
}

async function createAccount({ userId, name, type, balance, currency }) {
  const account = { id: id(), userId, name, type, balance: Number(balance) || 0, currency, createdAt: now() };
  state.accounts.push(account);
  await saveState();
  return mapAccount(account);
}

async function updateAccount(accountId, userId, fields) {
  const account = state.accounts.find(a => a.id === accountId && a.userId === userId);
  if (!account) return null;
  Object.assign(account, fields);
  account.balance = Number(account.balance) || 0;
  await saveState();
  return mapAccount(account);
}

async function deleteAccount(accountId, userId) {
  const before = state.accounts.length;
  state.accounts = state.accounts.filter(a => !(a.id === accountId && a.userId === userId));
  if (state.accounts.length === before) return false;
  await saveState();
  return true;
}

// ---------------- Recurring transactions ----------------
function mapRecurring(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.userId,
    accountId: row.accountId,
    type: row.type,
    category: row.category,
    label: row.label,
    amount: Number(row.amount),
    frequency: row.frequency,
    dayOfMonth: row.dayOfMonth,
    startDate: row.startDate,
    active: row.active,
    createdAt: row.createdAt,
  };
}

async function listRecurring(userId) {
  return state.recurringTransactions.filter(r => r.userId === userId).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt))).map(mapRecurring);
}

async function getRecurring(recurringId, userId) {
  return mapRecurring(state.recurringTransactions.find(r => r.id === recurringId && r.userId === userId) || null);
}

async function createRecurring(item) {
  const recurring = {
    id: id(),
    userId: item.userId,
    accountId: item.accountId || null,
    type: item.type,
    category: item.category,
    label: item.label,
    amount: Number(item.amount) || 0,
    frequency: item.frequency,
    dayOfMonth: item.dayOfMonth,
    startDate: item.startDate,
    active: true,
    createdAt: now(),
  };
  state.recurringTransactions.push(recurring);
  await saveState();
  return mapRecurring(recurring);
}

async function updateRecurring(recurringId, userId, fields) {
  const recurring = state.recurringTransactions.find(r => r.id === recurringId && r.userId === userId);
  if (!recurring) return null;
  Object.assign(recurring, fields);
  if (fields.amount !== undefined) recurring.amount = Number(fields.amount) || 0;
  await saveState();
  return mapRecurring(recurring);
}

async function deleteRecurring(recurringId, userId) {
  const before = state.recurringTransactions.length;
  state.recurringTransactions = state.recurringTransactions.filter(r => !(r.id === recurringId && r.userId === userId));
  if (state.recurringTransactions.length === before) return false;
  await saveState();
  return true;
}

async function clearRecurringAccountRef(userId, accountId) {
  let changed = false;
  state.recurringTransactions.forEach(r => {
    if (r.userId === userId && r.accountId === accountId) {
      r.accountId = null;
      changed = true;
    }
  });
  if (changed) await saveState();
}

async function init() { return { backend: 'file' }; }

module.exports = {
  init,
  getUserByEmail,
  getUserById,
  createUser,
  updateUserRole,
  ensureAdminUser,
  setUserPasswordHash,
  markEmailVerified,
  updateUnverifiedRegistration,
  saveOtp,
  getOtp,
  incrementOtpAttempts,
  deleteOtp,
  purgeStaleData,
  listUsers,
  getUserAdminDetails,
  updateUserStatus,
  deleteUser,
  addAuditLog,
  listAuditLogs,
  createRefreshToken,
  findValidRefreshToken,
  deleteRefreshTokenByHash,
  getProfile,
  upsertProfile,
  listAccounts,
  getAccount,
  createAccount,
  updateAccount,
  deleteAccount,
  listRecurring,
  getRecurring,
  createRecurring,
  updateRecurring,
  deleteRecurring,
  clearRecurringAccountRef,
};
