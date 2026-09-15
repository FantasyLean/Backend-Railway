const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email) {
  return typeof email === "string" && email.length <= 254 && EMAIL_RE.test(email.trim());
}

export function isNonEmptyString(value, maxLen = 500) {
  return typeof value === "string" && value.trim().length > 0 && value.length <= maxLen;
}

/** İstek gövdesindeki alanları kontrol eder; eksik/hatalı olan ilk alanın adını döner, hepsi geçerliyse null. */
export function requireFields(body, fields) {
  for (const field of fields) {
    if (!isNonEmptyString(body[field])) return field;
  }
  return null;
}
