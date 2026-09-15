import express from "express";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { createVerificationCode, verifyCode, sendMail } from "../utils/mailer.js";
import { checkBan, recordFailure, clearFailures } from "../utils/rateLimit.js";
import { isValidEmail, isNonEmptyString } from "../utils/validate.js";
import { sanitizeText } from "../utils/sanitize.js";
import { hashPassword, verifyPassword, validatePassword } from "../utils/password.js";

export const accountRouter = express.Router();

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

function isValidDisplayName(name) {
  const letters = name.replace(/[^A-Za-zÇĞİÖŞÜçğıöşü]/g, "");
  return letters.length >= 2;
}

// ---------- GÜVENLİ ÇIKIŞ — token_version'ı artırır, eski token'lar anında ölür ----------
accountRouter.post("/account/logout", requireAuth, async (req, res) => {
  await pool.query(`UPDATE users SET token_version = token_version + 1 WHERE id = $1`, [req.user.sub]);
  res.json({ ok: true });
});

// ---------- ŞİFRE DEĞİŞTİR (oturum açıkken) — eski şifreyi doğrular ----------
accountRouter.post("/account/change-password", requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!isNonEmptyString(oldPassword, 200)) return res.status(400).json({ error: "Lütfen mevcut şifrenizi giriniz." });
  if (!isNonEmptyString(newPassword, 200)) return res.status(400).json({ error: "Lütfen yeni şifrenizi giriniz." });

  const { rows } = await pool.query(`SELECT full_name, username, email, password_hash FROM users WHERE id = $1`, [req.user.sub]);
  const user = rows[0];
  if (!(await verifyPassword(oldPassword, user.password_hash))) {
    return res.status(401).json({ error: "Mevcut şifreniz yanlış." });
  }

  const passwordError = validatePassword(newPassword, user.full_name, user.username);
  if (passwordError) return res.status(400).json({ error: passwordError });

  const newHash = await hashPassword(newPassword);
  // Şifre değişince, o ana kadar açık olan TÜM oturumlar (bu cihaz dahil)
  // geçersiz hale gelir — bu yüzden token_version da birlikte artırılır.
  await pool.query(
    `UPDATE users SET password_hash = $2, token_version = token_version + 1 WHERE id = $1`,
    [req.user.sub, newHash]
  );

  await sendMail(user.email, "Alpeptide — Şifreniz Değiştirildi",
    "Hesabınızın şifresi az önce değiştirildi. Bu işlemi siz yapmadıysanız lütfen hemen bizimle iletişime geçin.");

  res.json({ ok: true, message: "Şifreniz değiştirildi. Güvenlik nedeniyle yeniden giriş yapmanız gerekiyor." });
});

// ---------- AD SOYAD: adım 1 — uygunluk + onay kodu ----------
accountRouter.post("/account/request-name-change", requireAuth, async (req, res) => {
  const newName = sanitizeText(req.body.newName || "");
  if (!isValidDisplayName(newName) || newName.length > 100) {
    return res.status(400).json({ error: "Lütfen geçerli bir ad soyad giriniz." });
  }

  const { rows } = await pool.query(`SELECT email, last_name_change_at FROM users WHERE id = $1`, [req.user.sub]);
  const user = rows[0];
  if (user.last_name_change_at && Date.now() - new Date(user.last_name_change_at).getTime() < THIRTY_DAYS_MS) {
    const daysLeft = Math.ceil((THIRTY_DAYS_MS - (Date.now() - new Date(user.last_name_change_at).getTime())) / 86400000);
    return res.status(429).json({ error: `Tekrar değiştirebilmeniz için ${daysLeft} gün beklemeniz gerekiyor.` });
  }

  const code = await createVerificationCode(req.user.sub, "name_change", newName, 5);
  await sendMail(user.email, "Alpeptide — İsim Değişikliği Onayı", `"${newName}" olarak isim değişikliğini onaylamak için kodunuz: <b>${code}</b>`);
  res.json({ message: "Onay kodu e-posta adresinize gönderildi." });
});

// ---------- AD SOYAD: adım 2 — kodu doğrula, uygula ----------
accountRouter.post("/account/confirm-name-change", requireAuth, async (req, res) => {
  const { code } = req.body;
  const identifier = `name-change:${req.user.sub}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(req.user.sub, "name_change", code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }
  await clearFailures(identifier, "verification_code");

  await pool.query(
    `UPDATE users SET full_name = $2, last_name_change_at = now() WHERE id = $1`,
    [req.user.sub, result.target]
  );
  res.json({ ok: true, fullName: result.target });
});

// ---------- E-POSTA: adım 1 — hem eski hem yeni adrese bildirim ----------
accountRouter.post("/account/request-email-change", requireAuth, async (req, res) => {
  const newEmail = (req.body.newEmail || "").trim().toLowerCase();
  if (!isValidEmail(newEmail)) return res.status(400).json({ error: "Lütfen geçerli bir e-posta adresi giriniz." });

  const { rows } = await pool.query(`SELECT email FROM users WHERE id = $1`, [req.user.sub]);
  const currentEmail = rows[0].email;
  if (newEmail === currentEmail) return res.status(400).json({ error: "Bu zaten mevcut e-posta adresiniz." });

  const taken = await pool.query(`SELECT id FROM users WHERE email = $1`, [newEmail]);
  if (taken.rows.length > 0) return res.status(409).json({ error: "Bu e-posta adresi başka bir hesap tarafından kullanılıyor." });

  const code = await createVerificationCode(req.user.sub, "email_change", newEmail, 5);

  // İstenen kural: eski adrese "değişiklik talep edildi" bilgisi, yeni adrese doğrulama kodu.
  await sendMail(currentEmail, "Alpeptide — E-posta Değişikliği Talebi",
    `Hesabınız için ${newEmail} adresine e-posta değişikliği talep edildi. Bu işlemi siz yapmadıysanız lütfen bizimle iletişime geçin.`);
  await sendMail(newEmail, "Alpeptide — E-posta Doğrulama", `Yeni e-posta adresinizi doğrulamak için kodunuz: <b>${code}</b>`);

  res.json({ message: "Onay bildirimi hem mevcut hem yeni e-posta adresinize gönderildi." });
});

// ---------- E-POSTA: adım 2 — kodu doğrula, uygula ----------
accountRouter.post("/account/confirm-email-change", requireAuth, async (req, res) => {
  const { code } = req.body;
  const identifier = `email-change:${req.user.sub}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(req.user.sub, "email_change", code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }
  await clearFailures(identifier, "verification_code");

  await pool.query(`UPDATE users SET email = $2 WHERE id = $1`, [req.user.sub, result.target]);
  res.json({ ok: true, email: result.target });
});
