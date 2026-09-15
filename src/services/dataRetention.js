import cron from "node-cron";
import { pool } from "../db/pool.js";

// KVKK/GDPR "veri minimizasyonu" ilkesi: bir verinin saklanma amacı sona
// erdiyse (örn. bir doğrulama kodunun süresi çoktan doldu), o veri
// sonsuza kadar veritabanında tutulmamalıdır. Bu servis, artık hiçbir
// amaca hizmet etmeyen kayıtları düzenli olarak temizler.

async function cleanup() {
  try {
    // Süresi dolmuş doğrulama kodları — zaten kullanılamazlar, saklamanın
    // hiçbir faydası yok, sadece gereksiz veri birikimi.
    const codes = await pool.query(`DELETE FROM verification_codes WHERE expires_at < now() - interval '1 day'`);

    // Giriş geçmişi 1 yıldan eskiyse silinir (güvenlik incelemesi için makul
    // bir süre, ama sonsuza kadar tutulmaz).
    const logins = await pool.query(`DELETE FROM login_history WHERE created_at < now() - interval '1 year'`);

    // Ban/deneme sayaçları — banı çoktan bitmiş ve son 30 gündür hiç
    // tetiklenmemiş kayıtlar temizlenir.
    const rateLimits = await pool.query(
      `DELETE FROM rate_limit_state WHERE updated_at < now() - interval '30 days' AND (banned_until IS NULL OR banned_until < now())`
    );

    // Denetim kaydı (audit_log) 2 yıl saklanır — hesap verebilirlik için
    // gerekli, ama süresiz değil.
    const audit = await pool.query(`DELETE FROM audit_log WHERE created_at < now() - interval '2 years'`);

    console.log(
      `[data-retention] Temizlendi: ${codes.rowCount} kod, ${logins.rowCount} giriş kaydı, ` +
      `${rateLimits.rowCount} ban kaydı, ${audit.rowCount} denetim kaydı.`
    );
  } catch (err) {
    console.error("[data-retention] Temizlik sırasında hata:", err.message);
  }
}

/** Sunucu başlarken çağrılır — her gün gece yarısı çalışacak şekilde zamanlar. */
export function startDataRetentionJob() {
  console.log("[data-retention] Başlatıldı — her gün 03:00'te eski veriler temizlenecek.");
  cron.schedule("0 3 * * *", cleanup);
}
