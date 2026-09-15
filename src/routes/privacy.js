import express from "express";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { verifyPassword } from "../utils/password.js";
import { createVerificationCode, verifyCode, sendMail } from "../utils/mailer.js";
import { checkBan, recordFailure, clearFailures } from "../utils/rateLimit.js";
import { isNonEmptyString } from "../utils/validate.js";

export const privacyRouter = express.Router();

/**
 * KVKK md. 11 — kullanıcı kendisiyle ilgili tüm veriyi indirebilir.
 * Hassas alanlar (şifre hash'i, TOTP gizli anahtarı, yedek kodlar) asla dahil edilmez.
 */
privacyRouter.get("/me/export", requireAuth, async (req, res) => {
  const userId = req.user.sub;

  const [user, addresses, orders, tickets, loginHistory] = await Promise.all([
    pool.query(`SELECT id, full_name, username, email, created_at FROM users WHERE id = $1`, [userId]),
    pool.query(`SELECT * FROM addresses WHERE user_id = $1`, [userId]),
    pool.query(`SELECT * FROM orders WHERE user_id = $1`, [userId]),
    pool.query(`SELECT * FROM tickets WHERE user_id = $1 AND deleted_at IS NULL`, [userId]),
    pool.query(`SELECT ip_address, user_agent, created_at FROM login_history WHERE user_id = $1`, [userId]),
  ]);

  res.setHeader("Content-Disposition", "attachment; filename=alpeptide-verilerim.json");
  res.json({
    exportedAt: new Date().toISOString(),
    profile: user.rows[0],
    addresses: addresses.rows,
    orders: orders.rows,
    tickets: tickets.rows,
    loginHistory: loginHistory.rows,
  });
});

// ---------- hesabı sil: adım 1 — şifre doğrula, onay kodu gönder ----------
privacyRouter.post("/me/request-delete", requireAuth, async (req, res) => {
  const { password } = req.body;
  if (!isNonEmptyString(password, 200)) return res.status(400).json({ error: "Lütfen şifrenizi giriniz." });

  const { rows } = await pool.query(`SELECT email, password_hash FROM users WHERE id = $1`, [req.user.sub]);
  const user = rows[0];
  if (!(await verifyPassword(password, user.password_hash))) {
    return res.status(401).json({ error: "Şifre yanlış." });
  }

  const code = await createVerificationCode(req.user.sub, "delete_account", null, 5);
  await sendMail(user.email, "Alpeptide — Hesap Silme Onayı",
    `Hesabınızı kalıcı olarak silmek için kodunuz: <b>${code}</b>. Bu işlem geri alınamaz.`);
  res.json({ message: "Onay kodu e-posta adresinize gönderildi." });
});

// ---------- hesabı sil: adım 2 — kodu doğrula, KALICI olarak sil ----------
privacyRouter.post("/me/confirm-delete", requireAuth, async (req, res) => {
  const { code } = req.body;
  const identifier = `delete-account:${req.user.sub}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(req.user.sub, "delete_account", code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }
  await clearFailures(identifier, "verification_code");

  // ON DELETE CASCADE ile tanımlı tablolar (addresses, login_history, tickets,
  // ticket_messages) otomatik silinir. Siparişler ise MUHASEBE/yasal kayıt
  // amacıyla saklanır — sadece kullanıcı bağlantısı koparılır (anonimleştirilir).
  await pool.query(`UPDATE orders SET user_id = NULL WHERE user_id = $1`, [req.user.sub]);
  await pool.query(`DELETE FROM users WHERE id = $1`, [req.user.sub]);

  res.json({ ok: true, message: "Hesabınız kalıcı olarak silindi." });
});
