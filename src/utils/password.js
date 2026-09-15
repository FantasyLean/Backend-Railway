import bcrypt from "bcrypt";

const SALT_ROUNDS = 12;

export async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

export async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function hasSequentialDigits(str) {
  const digits = (str.match(/\d+/g) || []).join("");
  for (let i = 0; i + 2 < digits.length; i++) {
    const a = +digits[i], b = +digits[i + 1], c = +digits[i + 2];
    if ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1)) return true;
  }
  return false;
}

function isRelatedToIdentity(pw, fullName, username) {
  const pwLower = pw.trim().toLowerCase();
  const parts = [username, ...(fullName || "").split(" ")].filter((p) => p && p.trim().length >= 3);
  return parts.some((part) => {
    const p = part.trim().toLowerCase();
    return pwLower.includes(p) || p.includes(pwLower);
  });
}

/** Sunucu tarafında parola kurallarını uygular. Geçersizse bir hata mesajı, geçerliyse null döner. */
export function validatePassword(pw, fullName, username) {
  if (pw.length < 8) return "Şifreniz en az 8 karakter olmalıdır.";
  if (!/[a-zA-Z]/.test(pw)) return "Şifreniz en az 1 harf içermelidir.";
  if (!/[!"#$%&'()*+,\-./:;<=>?@[\]^_`{|}~]/.test(pw)) return "Şifreniz en az 1 noktalama işareti içermelidir.";
  if (hasSequentialDigits(pw)) return "Şifrenizde ardışık sayılar kullanılamaz.";
  if (isRelatedToIdentity(pw, fullName, username)) return "Şifreniz kullanıcı adınız veya adınızla bağlantılı olamaz.";
  return null;
}

export function validateUsername(username) {
  if (/\s/.test(username)) return "Kullanıcı adı birleşik olmalıdır, boşluk içeremez.";
  if (/[çÇğĞıİöÖşŞüÜ]/.test(username)) return "Kullanıcı adı Türkçe karakter içeremez.";
  return null;
}
