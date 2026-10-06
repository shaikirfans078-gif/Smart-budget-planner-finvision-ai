const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || crypto.randomBytes(48).toString('hex');
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(48).toString('hex');
const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '15m';
const REFRESH_EXPIRES_DAYS = Number(process.env.JWT_REFRESH_EXPIRES_DAYS || 30);
const SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 12);

function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function signAccessToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role, name: user.name }, ACCESS_SECRET, {
    expiresIn: ACCESS_EXPIRES,
  });
}

function verifyAccessToken(token) {
  return jwt.verify(token, ACCESS_SECRET);
}

function generateRefreshToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(token + REFRESH_SECRET).digest('hex');
}

// ---- One-time passcodes (email verification / password reset) ----
// Codes are 6 digits from a CSPRNG and are only ever stored as an HMAC, so a
// leaked data file does not reveal live codes.
function generateOtp() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function hashOtp(email, purpose, otp) {
  return crypto.createHmac('sha256', REFRESH_SECRET).update(`${email}|${purpose}|${otp}`).digest('hex');
}

function otpMatches(expectedHash, email, purpose, otp) {
  const a = Buffer.from(String(expectedHash || ''), 'hex');
  const b = Buffer.from(hashOtp(email, purpose, otp), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function refreshExpiryDate() {
  return new Date(Date.now() + REFRESH_EXPIRES_DAYS * 24 * 60 * 60 * 1000);
}

module.exports = {
  hashPassword,
  verifyPassword,
  signAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashRefreshToken,
  refreshExpiryDate,
  generateOtp,
  hashOtp,
  otpMatches,
  REFRESH_EXPIRES_DAYS,
};
