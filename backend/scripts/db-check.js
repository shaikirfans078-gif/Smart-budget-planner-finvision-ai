// Verifies the Neon/PostgreSQL connection and creates the tables.  Usage: npm run db:check
require('dotenv').config();
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set (put it in .env).'); process.exit(1); }
const db = require('../db');
db.init()
  .then(async () => {
    const users = await db.listUsers();
    console.log(`OK - connected to PostgreSQL, tables ready, ${users.length} user(s).`);
    process.exit(0);
  })
  .catch(e => { console.error('FAILED:', e.message); process.exit(1); });
