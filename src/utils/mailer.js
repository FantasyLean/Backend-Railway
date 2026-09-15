import nodemailer from "nodemailer";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { pool } from "../db/pool.js";

const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

export async function sendMail(to, subject, html) {
  if (!smtpConfigured) {
    console.log(`\n[mail:henüz-yapılandırılmadı] Kime: ${to}\n[mail] Konu: ${subject}\n[mail] İçerik: ${html}\n`);
    return;
  }
  try {
    await transporter.sendMail({ from: process.env.MAIL_FROM, to, subject, html });
  } catch (err) {
    console.error(`[mail:hata] "${to}" adresine gönderilemedi:`, err.message);
  }
}

function genSixDigitCode() {
  return crypto.randomInt(100000, 999999).toString();
}

export async function createVerificationCode(userId, purpose, target = null, ttlMinutes = 5) {
  const code = genSixDigitCode();
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + ttlMinutes * 60_000);
  await pool.query(
    `INSERT INTO verification_codes (user_id, purpose, code_hash, target, expires_at)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, purpose, codeHash, target, expiresAt]
  );
  return code;
}

const DUMMY_HASH = "$2b$10$C6UzMDM.H6dfI/f/IKcEeO/dpv2C/JWNfBK/9NRIQY8LWc1JLIfoi";

export async function verifyCode(userId, purpose, inputCode) {
  const { rows } = await pool.query(
    `SELECT * FROM verification_codes
     WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
     ORDER BY created_at DESC LIMIT 1`,
    [userId, purpose]
  );
  const record = rows[0];

  const matches = await bcrypt.compare(inputCode || "", record?.code_hash || DUMMY_HASH);
  if (!record || !matches) return { valid: false, reason: !record ? "expired_or_missing" : "wrong_code" };

  await pool.query(`UPDATE verification_codes SET consumed_at = now() WHERE id = $1`, [record.id]);
  return { valid: true, target: record.target };
}
