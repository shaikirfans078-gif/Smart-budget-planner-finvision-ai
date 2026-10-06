// One-time import of data/finvision.json (old file store) into PostgreSQL.
// Safe to re-run: existing rows are skipped.  Usage: npm run migrate:file-to-pg
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const file = path.join(__dirname, '..', 'data', 'finvision.json');
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set.'); process.exit(1); }
if (!fs.existsSync(file)) { console.log('No data/finvision.json found - nothing to migrate.'); process.exit(0); }

(async () => {
  const db = require('../db');
  await db.init();
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: true } });
  const s = JSON.parse(fs.readFileSync(file, 'utf8'));
  const n = { users: 0, profiles: 0, accounts: 0, recurring: 0, audit: 0 };
  const j = v => JSON.stringify(v);
  try {
    for (const u of s.users || []) {
      const r = await pool.query(
        `INSERT INTO users (id,name,email,password_hash,role,status,email_verified,created_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
        [u.id, u.name, u.email, u.passwordHash, u.role || 'user', u.status || 'active', u.emailVerified !== false, u.createdAt, u.updatedAt]);
      n.users += r.rowCount;
    }
    for (const p of s.profiles || []) {
      const r = await pool.query(
        `INSERT INTO profiles (user_id,records,budget_plan,goals,custom_categories,category_labels,currency,investments,debts,other_assets,other_liabilities,updated_at)
         SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 WHERE EXISTS (SELECT 1 FROM users WHERE id=$1) ON CONFLICT DO NOTHING`,
        [p.userId, j(p.records || {}), p.budgetPlan ? j(p.budgetPlan) : null, j(p.goals || []), j(p.customCategories || []),
         j(p.categoryLabels || {}), p.currency || null, j(p.investments || []), j(p.debts || []),
         Number(p.otherAssets) || 0, Number(p.otherLiabilities) || 0, p.updatedAt]);
      n.profiles += r.rowCount;
    }
    for (const a of s.accounts || []) {
      const r = await pool.query(
        `INSERT INTO accounts (id,user_id,name,type,balance,currency,created_at)
         SELECT $1,$2,$3,$4,$5,$6,$7 WHERE EXISTS (SELECT 1 FROM users WHERE id=$2) ON CONFLICT DO NOTHING`,
        [a.id, a.userId, a.name, a.type, Number(a.balance) || 0, a.currency, a.createdAt]);
      n.accounts += r.rowCount;
    }
    for (const x of s.recurringTransactions || []) {
      const r = await pool.query(
        `INSERT INTO recurring_transactions (id,user_id,account_id,type,category,label,amount,frequency,day_of_month,start_date,active,created_at)
         SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 WHERE EXISTS (SELECT 1 FROM users WHERE id=$2) ON CONFLICT DO NOTHING`,
        [x.id, x.userId, x.accountId || null, x.type, x.category, x.label, Number(x.amount) || 0, x.frequency,
         x.dayOfMonth ?? null, x.startDate ?? null, x.active !== false, x.createdAt]);
      n.recurring += r.rowCount;
    }
    for (const l of s.auditLogs || []) {
      const r = await pool.query(
        `INSERT INTO audit_logs (id,admin_id,action,target_user_id,reason,created_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
        [l.id, l.adminId || null, l.action, l.targetUserId || null, l.reason || '', l.createdAt]);
      n.audit += r.rowCount;
    }
    console.log('Migrated:', n);
  } finally { await pool.end(); }
  process.exit(0);
})().catch(e => { console.error('Migration failed:', e.message); process.exit(1); });
