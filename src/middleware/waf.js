import { pool } from "../db/pool.js";

// Basit bir "web application firewall" katmanı. Parametrize sorgular SQL
// enjeksiyonunu, sanitizeText() ise saklı XSS'i zaten engelliyor — bu katman
// EK bir güvenlik önlemi: belirgin saldırı imzalarını erken fark edip
// isteği hiç route'a ulaştırmadan reddeder, loglar VE tekrar edilirse o
// IP'yi kalıcı olarak banlar.
//
// ÖNEMLİ: Bu filtre SADECE query/path parametrelerine uygulanır, istek
// GÖVDESİNE (body) uygulanmaz. Çünkü şifre alanları kuralımız gereği
// noktalama işareti İÇERMEK ZORUNDA (örn. "--", "#" içeren bir şifre
// tamamen geçerlidir) — body'yi taramak, geçerli şifreleri/mesajları
// yanlışlıkla reddedebilir. Body zaten parametrize sorgular ve
// sanitizeText() ile ayrıca korunuyor.

const SQLI_PATTERNS = [
  /(\bunion\b.{0,20}\bselect\b)/i,
  /(\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+)/i, // OR 1=1
  /(;\s*drop\s+table)/i,
];

const XSS_PATTERNS = [
  /<script[\s>]/i,
  /on\w+\s*=\s*["'].*["']/i, // onerror="...", onclick="..." vb.
  /javascript:/i,
];

const PATH_TRAVERSAL_PATTERNS = [/\.\.\//, /\.\.\\/];

// Bir IP, kısa sürede kaç kez saldırı imzası tetiklerse kalıcı olarak banlanır
const WAF_STRIKE_LIMIT = 5;
const WAF_BAN_MS = 24 * 60 * 60 * 1000; // 24 saat

function containsAttackSignature(value) {
  if (typeof value !== "string") return false;
  const allPatterns = [...SQLI_PATTERNS, ...XSS_PATTERNS, ...PATH_TRAVERSAL_PATTERNS];
  return allPatterns.some((pattern) => pattern.test(value));
}

function scanObject(obj, depth = 0) {
  if (depth > 5 || obj == null) return false; // çok derin nesnelerle DoS denemesine karşı sınır
  if (typeof obj === "string") return containsAttackSignature(obj);
  if (Array.isArray(obj)) return obj.some((item) => scanObject(item, depth + 1));
  if (typeof obj === "object") return Object.values(obj).some((v) => scanObject(v, depth + 1));
  return false;
}

export async function attackSignatureFilter(req, res, next) {
  try {
    // Önce: bu IP zaten WAF ihlalleri yüzünden banlı mı?
    const { rows } = await pool.query(
      `SELECT banned_until FROM rate_limit_state WHERE identifier = $1 AND action = 'waf_violation'`,
      [req.ip]
    );
    if (rows[0]?.banned_until && new Date(rows[0].banned_until) > new Date()) {
      return res.status(403).json({ error: "Bu IP adresi güvenlik ihlalleri nedeniyle geçici olarak engellendi." });
    }

    const suspicious = scanObject(req.query) || scanObject(req.params);
    if (!suspicious) return next();

    console.warn(`[waf] Şüpheli istek engellendi: ${req.method} ${req.path} — IP: ${req.ip}`);

    const { rows: strikeRows } = await pool.query(
      `INSERT INTO rate_limit_state (identifier, action, fail_count, updated_at)
       VALUES ($1, 'waf_violation', 1, now())
       ON CONFLICT (identifier, action)
       DO UPDATE SET fail_count = rate_limit_state.fail_count + 1, updated_at = now()
       RETURNING fail_count`,
      [req.ip]
    );
    if (strikeRows[0].fail_count >= WAF_STRIKE_LIMIT) {
      await pool.query(
        `UPDATE rate_limit_state SET banned_until = $2 WHERE identifier = $1 AND action = 'waf_violation'`,
        [req.ip, new Date(Date.now() + WAF_BAN_MS)]
      );
      console.warn(`[waf] IP kalıcı olarak banlandı (24 saat): ${req.ip}`);
    }

    return res.status(400).json({ error: "Geçersiz istek içeriği." });
  } catch (err) {
    // Veritabanı bu kontrol sırasında ulaşılamaz olursa, isteği tamamen
    // reddetmek yerine (kullanılabilirliği bozmamak için) devam ettiriyoruz —
    // ama durumu logluyoruz ki fark edilsin.
    console.error("[waf] Kontrol sırasında hata, istek engellenmeden devam ediyor:", err.message);
    next();
  }
}
