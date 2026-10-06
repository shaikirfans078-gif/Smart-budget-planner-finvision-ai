// Outgoing email for FinVision (verification + password-reset one-time codes).
//
// Two providers are supported (EmailJS takes priority when fully configured):
//   1. EmailJS  - EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, EMAILJS_PUBLIC_KEY, EMAILJS_PRIVATE_KEY
//   2. SMTP     - SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM
// If neither is configured and NODE_ENV is not "production", codes are printed
// to the server console instead, so you can develop and test locally without a
// mail account. In production, missing SMTP settings are treated as an error.

let transporter = null;

function smtpConfigured() {
  return !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function emailjsConfigured() {
  return !!(process.env.EMAILJS_SERVICE_ID && process.env.EMAILJS_TEMPLATE_ID &&
    process.env.EMAILJS_PUBLIC_KEY && process.env.EMAILJS_PRIVATE_KEY);
}

// 'emailjs' | 'smtp' | 'console' (dev only) | 'none' (production without a provider)
function mailMode() {
  if (emailjsConfigured()) return 'emailjs';
  if (smtpConfigured()) return 'smtp';
  return process.env.NODE_ENV !== 'production' ? 'console' : 'none';
}

// True when we can deliver a code somehow (real SMTP, or console fallback in dev).
function mailReady() {
  return mailMode() !== 'none';
}

// EmailJS REST API (server-side). Requires "Allow EmailJS API for non-browser
// applications" to be enabled in the EmailJS dashboard (Account > Security).
async function sendViaEmailJs({ to, name, otp, purpose, expiresMinutes }, message) {
  const res = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      service_id: process.env.EMAILJS_SERVICE_ID,
      template_id: process.env.EMAILJS_TEMPLATE_ID,
      user_id: process.env.EMAILJS_PUBLIC_KEY,
      accessToken: process.env.EMAILJS_PRIVATE_KEY,
      template_params: {
        to_email: to,
        to_name: name,
        email: to,
        name,
        otp,
        passcode: otp,
        purpose,
        subject: message.subject,
        message: message.text,
        expires_minutes: String(expiresMinutes),
        time: `${expiresMinutes} minutes`,
        app_name: 'FinVision AI',
      },
    }),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) {
    const body = (await res.text().catch(() => '')).slice(0, 200);
    const err = new Error(`EmailJS ${res.status}: ${body}`);
    err.code = 'EMAILJS_FAILED';
    throw err;
  }
}

function getTransporter() {
  if (transporter) return transporter;
  const nodemailer = require('nodemailer');
  const port = Number(process.env.SMTP_PORT || 587);
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : port === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  return transporter;
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function buildMessage({ name, otp, purpose, expiresMinutes }) {
  const isReset = purpose === 'reset';
  const subject = isReset ? 'FinVision AI — your password reset code' : 'FinVision AI — verify your email';
  const intro = isReset
    ? 'We received a request to reset your FinVision AI password. Use this code to continue:'
    : 'Welcome to FinVision AI! Use this code to verify your email address and finish creating your account:';
  const outro = isReset
    ? 'If you did not request a password reset, you can safely ignore this email — your password will not change.'
    : 'If you did not create a FinVision AI account, you can safely ignore this email.';
  const text = `Hi ${name},\n\n${intro}\n\n    ${otp}\n\nThis code expires in ${expiresMinutes} minutes. Never share it with anyone.\n\n${outro}\n\n— FinVision AI`;
  const html = `<div style="font-family:Segoe UI,Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e2e8f0;border-radius:16px;color:#1e293b">
  <h2 style="margin:0 0 4px;color:#4338ca">FinVision AI</h2>
  <p style="margin:0 0 16px;color:#64748b;font-size:13px">${isReset ? 'Password reset' : 'Email verification'}</p>
  <p>Hi ${escapeHtml(name)},</p><p>${intro}</p>
  <div style="font-size:32px;letter-spacing:10px;font-weight:800;text-align:center;background:#eef2ff;color:#312e81;padding:16px;border-radius:12px;margin:18px 0">${otp}</div>
  <p style="font-size:13px;color:#475569">This code expires in <b>${expiresMinutes} minutes</b>. Never share it with anyone.</p>
  <p style="font-size:12px;color:#94a3b8">${outro}</p></div>`;
  return { subject, text, html };
}

async function sendOtpEmail({ to, name, otp, purpose, expiresMinutes }) {
  const message = buildMessage({ name: name || 'there', otp, purpose, expiresMinutes });
  const mode = mailMode();
  if (mode === 'emailjs') {
    await sendViaEmailJs({ to, name: name || 'there', otp, purpose, expiresMinutes }, message);
    return { dev: false };
  }
  if (mode !== 'smtp') {
    if (mode === 'none') {
      const err = new Error('No email provider is configured (set EMAILJS_* or SMTP_*)');
      err.code = 'MAIL_NOT_CONFIGURED';
      throw err;
    }
    console.log(`\n[mail:dev] no mail provider configured — would email ${to}\n[mail:dev] ${message.subject}\n[mail:dev] >>> CODE: ${otp}  (valid ${expiresMinutes} min)\n`);
    return { dev: true };
  }
  const from = process.env.MAIL_FROM || `FinVision AI <${process.env.SMTP_USER}>`;
  await getTransporter().sendMail({ from, to, subject: message.subject, text: message.text, html: message.html });
  return { dev: false };
}

module.exports = { sendOtpEmail, mailReady, smtpConfigured, emailjsConfigured, mailMode };
