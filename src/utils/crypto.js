import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";

function getKey() {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw || raw.length < 32) {
    throw new Error("ENCRYPTION_KEY tanımsız veya çok kısa (en az 32 karakter olmalı).");
  }
  // Anahtarı tam 32 byte'a (AES-256) sabitlemek için hash'liyoruz —
  // kullanıcı .env'ye herhangi bir uzunlukta bir metin koyabilsin.
  return crypto.createHash("sha256").update(raw).digest();
}

/** Şifreler — TOTP gizli anahtarı gibi, daha sonra GERİ OKUNMASI gereken veriler için. */
export function encrypt(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // iv + authTag + şifreli veri, tek bir base64 metin olarak saklanır
  return Buffer.concat([iv, authTag, encrypted]).toString("base64");
}

export function decrypt(stored) {
  const buf = Buffer.from(stored, "base64");
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}
