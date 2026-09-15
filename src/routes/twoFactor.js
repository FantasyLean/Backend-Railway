import express from "express";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { createVerificationCode, verifyCode, sendMail } from "../utils/mailer.js";
import { checkBan, recordFailure, clearFailures } from "../utils/rateLimit.js";
import { encrypt, decrypt } from "../utils/crypto.js";

export const twoFactorRouter = express.Router();

function genBackupCodes(count = 8) {
  return Array.from({ length: count }, () => crypto.randomInt(100000, 999999).toString());
}

// ---------- adım 1: e-postaya onay kodu gönder ----------
twoFactorRouter.post("/2fa/request-toggle", requireAuth, async (req, res) => {
  const { rows } = await pool.query(`SELECT email, totp_enabled FROM users WHERE id = $1`, [req.user.sub]);
  const user = rows[0];
  const action = user.totp_enabled ? "devre dışı bırakma" : "etkinleştirme";

  const code = await createVerificationCode(req.user.sub, "2fa_toggle", null, 5);
  await sendMail(user.email, "Alpeptide — Google Authenticator Onayı", `2FA ${action} işlemini onaylamak için kodunuz: <b>${code}</b>`);
  res.json({ message: "Onay kodu e-posta adresinize gönderildi." });
});

// ---------- adım 2: kodu doğrula, TOTP'yi aç/kapat ----------
twoFactorRouter.post("/2fa/confirm-toggle", requireAuth, async (req, res) => {
  const { code } = req.body;
  const identifier = `2fa-toggle:${req.user.sub}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(req.user.sub, "2fa_toggle", code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }
  await clearFailures(identifier, "verification_code");

  const { rows } = await pool.query(`SELECT totp_enabled FROM users WHERE id = $1`, [req.user.sub]);
  const currentlyEnabled = rows[0].totp_enabled;

  if (currentlyEnabled) {
    // devre dışı bırak
    await pool.query(
      `UPDATE users SET totp_enabled = false, totp_secret = NULL, backup_codes = NULL WHERE id = $1`,
      [req.user.sub]
    );
    return res.json({ enabled: false });
  }

  // etkinleştir: gizli anahtar + QR kod + yedek kodlar üret
  const secret = authenticator.generateSecret();
  const backupCodes = genBackupCodes();
  const hashedBackupCodes = await Promise.all(backupCodes.map((c) => bcrypt.hash(c, 10)));

  // Gizli anahtar veritabanında ASLA düz metin saklanmaz — veritabanı sızsa
  // bile, şifreleme anahtarı (ENCRYPTION_KEY) olmadan hiçbir işe yaramaz.
  await pool.query(
    `UPDATE users SET totp_enabled = true, totp_secret = $2, backup_codes = $3 WHERE id = $1`,
    [req.user.sub, encrypt(secret), hashedBackupCodes]
  );

  const otpUrl = authenticator.keyuri(req.user.sub, "Alpeptide", secret);
  const qrDataUrl = await QRCode.toDataURL(otpUrl);

  res.json({ enabled: true, qrDataUrl, backupCodes }); // backupCodes SADECE bu an gösterilir, bir daha geri getirilemez
});

// ---------- girişte TOTP kodu doğrulama (isteğe bağlı ekstra adım) ----------
twoFactorRouter.post("/2fa/verify-totp", requireAuth, async (req, res) => {
  const { token } = req.body;
  const identifier = `2fa-verify:${req.user.sub}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const { rows } = await pool.query(`SELECT totp_secret FROM users WHERE id = $1`, [req.user.sub]);
  if (!rows[0]?.totp_secret) return res.status(400).json({ error: "2FA etkin değil." });

  const isValid = authenticator.check(token, decrypt(rows[0].totp_secret));
  if (!isValid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ valid: false, ...outcome });
  }

  await clearFailures(identifier, "verification_code");
  res.json({ valid: true });
});
