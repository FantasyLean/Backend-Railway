import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { authenticator } from "otplib";
import { pool } from "../db/pool.js";
import { hashPassword, verifyPassword, validatePassword, validateUsername } from "../utils/password.js";
import { createVerificationCode, verifyCode, sendMail } from "../utils/mailer.js";
import { verifyRecaptcha } from "../utils/recaptcha.js";
import { checkBan, recordFailure, clearFailures, recordLoginPasswordFailure } from "../utils/rateLimit.js";
import { requireAuth } from "../middleware/auth.js";
import { isValidEmail, isNonEmptyString, requireFields } from "../utils/validate.js";
import { decrypt } from "../utils/crypto.js";
import { sanitizeText } from "../utils/sanitize.js";

export const authRouter = express.Router();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SIX_DIGIT_RE = /^\d{6}$/;

function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, tv: user.token_version }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "7d",
  });
}

// ---------- KAYIT: adım 1 — bilgileri doğrula, kod gönder ----------
authRouter.post("/register", async (req, res) => {
  const { fullName, username, email, password, recaptchaToken, kvkkAccepted, aboutAccepted } = req.body;

  const missing = requireFields(req.body, ["fullName", "username", "email", "password"]);
  if (missing) return res.status(400).json({ error: `Lütfen tüm alanları doldurun (${missing}).` });
  if (!isValidEmail(email)) return res.status(400).json({ error: "Lütfen geçerli bir e-posta adresi giriniz." });
  if (fullName.length > 100 || username.length > 40) {
    return res.status(400).json({ error: "Girilen alanlar çok uzun." });
  }
  if (!(await verifyRecaptcha(recaptchaToken))) {
    return res.status(400).json({ error: "Lütfen robot olmadığınızı doğrulayın." });
  }
  if (!kvkkAccepted || !aboutAccepted) {
    return res.status(400).json({ error: "KVKK metnini ve Hakkımızda kısmını onaylamanız gerekir." });
  }
  const usernameError = validateUsername(username);
  if (usernameError) return res.status(400).json({ error: usernameError });

  const passwordError = validatePassword(password, fullName, username);
  if (passwordError) return res.status(400).json({ error: passwordError });

  const existing = await pool.query(
    `SELECT id FROM users WHERE email = $1 OR username = $2`,
    [email.trim().toLowerCase(), username.trim().toLowerCase()]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({
      error: "Bu e-posta adresi zaten sisteme kayıtlı. Lütfen giriş yapınız veya şifrenizi sıfırlayınız.",
    });
  }

  const passwordHash = await hashPassword(password);
  const { rows } = await pool.query(
    `INSERT INTO users (full_name, username, email, password_hash)
     VALUES ($1, $2, $3, $4) RETURNING id, email`,
    [sanitizeText(fullName), username.trim().toLowerCase(), email.trim().toLowerCase(), passwordHash]
  );
  const user = rows[0];

  const code = await createVerificationCode(user.id, "register", null, 5);
  await sendMail(user.email, "Alpeptide — E-posta Doğrulama", `Doğrulama kodunuz: <b>${code}</b> (5 dakika geçerlidir)`);

  res.json({ userId: user.id, message: "Doğrulama kodu e-posta adresinize gönderildi." });
});

// ---------- KAYIT: adım 2 — kodu doğrula, hesabı etkinleştir ----------
authRouter.post("/register/verify", async (req, res) => {
  const { userId, code } = req.body;
  if (!UUID_RE.test(userId || "") || !SIX_DIGIT_RE.test(code || "")) {
    return res.status(400).json({ error: "Geçersiz istek." });
  }
  const identifier = `register:${userId}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(userId, "register", code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }

  await clearFailures(identifier, "verification_code");
  const { rows } = await pool.query(
    `UPDATE users SET email_verified_at = now() WHERE id = $1 RETURNING id, email, username, role, token_version`,
    [userId]
  );
  const user = rows[0];
  if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
  const { token_version, ...publicUser } = user; // istemciye iç detay sızdırılmaz
  res.json({ token: signToken(user), user: publicUser });
});

// ---------- GİRİŞ: adım 1 — kullanıcı adı/e-posta + şifre ----------
authRouter.post("/login", async (req, res) => {
  const { identifier: loginId, password, recaptchaToken } = req.body;
  const ip = req.ip;

  if (!isNonEmptyString(loginId, 254) || !isNonEmptyString(password, 200)) {
    return res.status(400).json({ error: "Lütfen tüm alanları doldurun." });
  }
  if (!(await verifyRecaptcha(recaptchaToken))) {
    return res.status(400).json({ error: "Lütfen robot olmadığınızı doğrulayın." });
  }

  const normalizedId = loginId.trim().toLowerCase();
  const accountIdentifier = `account:${normalizedId}`;

  const pwBan = await checkBan(ip, "login_password");
  if (pwBan.banned) return res.status(429).json({ error: "banned", bannedUntil: pwBan.bannedUntil });
  // Hesap bazlı ayrı bir ban da kontrol edilir — bir saldırgan çok sayıda
  // farklı IP kullansa bile (dağıtık saldırı), TEK bir hesabı hedef alıyorsa
  // bu ikinci katman onu durdurur.
  const accountBan = await checkBan(accountIdentifier, "login_password");
  if (accountBan.banned) return res.status(429).json({ error: "banned", bannedUntil: accountBan.bannedUntil });

  const { rows } = await pool.query(
    `SELECT * FROM users WHERE email = $1 OR username = $1`,
    [normalizedId]
  );
  const user = rows[0];
  // Kullanıcı bulunamasa bile bcrypt.compare'e benzer bir gecikme yaşanması için
  // sahte bir hash ile karşılaştırma yapılır — bu, "kullanıcı var mı yok mu" bilgisinin
  // yanıt süresinden (timing) sızmasını önler.
  const passwordOk = user
    ? await verifyPassword(password, user.password_hash)
    : await verifyPassword(password, "$2b$12$C6UzMDM.H6dfI/f/IKcEeO/dpv2C/JWNfBK/9NRIQY8LWc1JLIfoi");

  if (!passwordOk) {
    const outcome = await recordLoginPasswordFailure(ip);
    await recordLoginPasswordFailure(accountIdentifier);
    return res.status(401).json({ error: "invalid_credentials", ...outcome });
  }

  await pool.query(`DELETE FROM rate_limit_state WHERE identifier IN ($1, $2) AND action = 'login_password'`, [ip, accountIdentifier]);

  if (!user.email_verified_at) {
    // Hesap hiç doğrulanmamış — tam girişe İZİN VERİLMEZ. Bunun yerine
    // kullanıcıyı kayıt doğrulama akışına geri gönderiyoruz ve YENİ bir kod
    // veriyoruz. Bu, eski kodu süresi dolan bir kullanıcının sonsuza kadar
    // takılı kalmasını da otomatik olarak çözer — tekrar giriş denemesi,
    // doğrulamayı tamamlamanın yolu haline gelir.
    const registerCode = await createVerificationCode(user.id, "register", null, 5);
    await sendMail(user.email, "Alpeptide — E-posta Doğrulama", `Doğrulama kodunuz: <b>${registerCode}</b> (5 dakika geçerlidir)`);
    return res.json({
      userId: user.id,
      secondFactor: "register_verify",
      message: "Hesabınız henüz e-posta ile doğrulanmamış. Yeni bir doğrulama kodu gönderildi.",
    });
  }

  if (user.totp_enabled) {
    // Google Authenticator etkinse, ikinci faktör olarak e-posta kodu YERİNE
    // TOTP (veya yedek kod) istenir — ikisi birden istenmez, kullanıcı hangisini
    // kurduysa o kullanılır.
    return res.json({ userId: user.id, secondFactor: "totp" });
  }

  const code = await createVerificationCode(user.id, "login_2fa", null, 5);
  await sendMail(user.email, "Alpeptide — Giriş Doğrulama Kodu", `Giriş kodunuz: <b>${code}</b> (5 dakika geçerlidir)`);
  res.json({ userId: user.id, secondFactor: "email", message: "Doğrulama kodu e-posta adresinize gönderildi." });
});

// ---------- GİRİŞ: adım 2a — e-posta koduyla tamamla (2FA kapalıysa) ----------
authRouter.post("/login/verify", async (req, res) => {
  const { userId, code } = req.body;
  if (!UUID_RE.test(userId || "") || !SIX_DIGIT_RE.test(code || "")) {
    return res.status(400).json({ error: "Geçersiz istek." });
  }
  const identifier = `login:${userId}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(userId, "login_2fa", code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }

  await clearFailures(identifier, "verification_code");
  res.json(await finishLogin(req, userId));
});

// ---------- GİRİŞ: adım 2b — TOTP veya yedek kodla tamamla (2FA açıksa) ----------
authRouter.post("/login/verify-totp", async (req, res) => {
  const { userId, token } = req.body;
  if (!UUID_RE.test(userId || "") || !isNonEmptyString(token, 20)) {
    return res.status(400).json({ error: "Geçersiz istek." });
  }
  const identifier = `login-totp:${userId}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const { rows } = await pool.query(`SELECT totp_secret, backup_codes FROM users WHERE id = $1`, [userId]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });

  const isTotpValid = SIX_DIGIT_RE.test(token) && user.totp_secret && authenticator.check(token, decrypt(user.totp_secret));

  let usedBackupIndex = -1;
  if (!isTotpValid && Array.isArray(user.backup_codes)) {
    for (let i = 0; i < user.backup_codes.length; i++) {
      if (await bcrypt.compare(token, user.backup_codes[i])) {
        usedBackupIndex = i;
        break;
      }
    }
  }

  if (!isTotpValid && usedBackupIndex === -1) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }

  if (usedBackupIndex !== -1) {
    // Kullanılan yedek kod bir daha kullanılamaz — listeden çıkarılır.
    const remaining = user.backup_codes.filter((_, i) => i !== usedBackupIndex);
    await pool.query(`UPDATE users SET backup_codes = $2 WHERE id = $1`, [userId, remaining]);
  }

  await clearFailures(identifier, "verification_code");
  res.json(await finishLogin(req, userId));
});

async function finishLogin(req, userId) {
  const { rows } = await pool.query(`SELECT id, email, username, role, token_version FROM users WHERE id = $1`, [userId]);
  const user = rows[0];
  await pool.query(
    `INSERT INTO login_history (user_id, ip_address, user_agent) VALUES ($1, $2, $3)`,
    [user.id, req.ip, req.headers["user-agent"]]
  );
  const { token_version, ...publicUser } = user; // istemciye iç detay sızdırılmaz
  return { token: signToken(user), user: publicUser };
}

// ---------- ŞİFREMİ UNUTTUM: adım 1 — kod gönder ----------
authRouter.post("/forgot-password", async (req, res) => {
  const { identifier: loginId, recaptchaToken } = req.body;
  if (!isNonEmptyString(loginId, 254)) {
    return res.status(400).json({ error: "Lütfen kullanıcı adı veya e-posta adresinizi giriniz." });
  }
  if (!(await verifyRecaptcha(recaptchaToken))) {
    return res.status(400).json({ error: "Lütfen robot olmadığınızı doğrulayın." });
  }
  const { rows } = await pool.query(
    `SELECT * FROM users WHERE email = $1 OR username = $1`,
    [loginId.trim().toLowerCase()]
  );
  const user = rows[0];
  if (!user) return res.json({ result: "not_found" });

  const code = await createVerificationCode(user.id, "password_reset", null, 5);
  await sendMail(user.email, "Alpeptide — Şifre Sıfırlama", `Şifre sıfırlama kodunuz: <b>${code}</b> (5 dakika geçerlidir)`);
  res.json({ result: "sent", userId: user.id });
});

// ---------- ŞİFREMİ UNUTTUM: adım 2 — kodu doğrula VE yeni şifreyi kaydet ----------
authRouter.post("/reset-password", async (req, res) => {
  const { userId, code, newPassword } = req.body;
  if (!UUID_RE.test(userId || "") || !SIX_DIGIT_RE.test(code || "") || !isNonEmptyString(newPassword, 200)) {
    return res.status(400).json({ error: "Geçersiz istek." });
  }
  const identifier = `reset:${userId}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(userId, "password_reset", code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }

  const { rows } = await pool.query(`SELECT full_name, username, email FROM users WHERE id = $1`, [userId]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });

  const passwordError = validatePassword(newPassword, user.full_name, user.username);
  if (passwordError) return res.status(400).json({ error: passwordError });

  await clearFailures(identifier, "verification_code");
  const passwordHash = await hashPassword(newPassword);
  await pool.query(
    `UPDATE users SET password_hash = $2, token_version = token_version + 1 WHERE id = $1`,
    [userId, passwordHash]
  );

  // Şifre değişti — güvenlik amacıyla kullanıcıya bilgilendirme e-postası gönderilir.
  // Bu şekilde, şifresini kendisi değiştirmeyen biri en azından haberdar olur.
  await sendMail(user.email, "Alpeptide — Şifreniz Değiştirildi",
    "Hesabınızın şifresi az önce değiştirildi. Bu işlemi siz yapmadıysanız lütfen hemen bizimle iletişime geçin.");

  res.json({ ok: true });
});

// ---------- Oturum gerektiren: profil bilgisi ----------
authRouter.get("/me", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, full_name, username, email, totp_enabled, created_at FROM users WHERE id = $1`,
    [req.user.sub]
  );
  res.json(rows[0]);
});
