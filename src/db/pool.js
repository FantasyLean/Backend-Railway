import pg from "pg";
import dotenv from "dotenv";

dotenv.config();

const isProduction = process.env.NODE_ENV === "production";

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,

  // Üretimde veritabanı trafiği şifrelenmeden gitmemeli — aksi halde araya
  // giren biri (MITM) sorguları/şifre hash'lerini görebilir. Çoğu barındırma
  // servisi (Railway dahil) kendi sertifikasını kullanır, bu yüzden
  // rejectUnauthorized:false makul bir orta yoldur (yine de trafik şifreli
  // akar — sadece sertifika zincirini tam doğrulamaz).
  ssl: isProduction ? { rejectUnauthorized: false } : false,

  // Havuzdaki maksimum bağlantı sayısı — sınırsız bağlantı açılması,
  // veritabanını kolayca tüketebilecek bir kaynak-bitirme (DoS) vektörüdür.
  max: 20,

  // Bir bağlantı bu kadar süre boşta kalırsa kapatılır — kaynakları gereksiz
  // yere tutmaz.
  idleTimeoutMillis: 30_000,

  // Bir sorgu bu süreden uzun sürerse otomatik iptal edilir — yavaş/kötü
  // niyetli bir sorgunun bağlantıyı sonsuza kadar kilitlemesini engeller.
  statement_timeout: 10_000,

  // Yeni bir bağlantı kurmak bu süreden uzun sürerse hata verir, sonsuza
  // kadar beklemez.
  connectionTimeoutMillis: 5_000,
});

pool.on("error", (err) => {
  console.error("[db] Beklenmeyen havuz hatası:", err);
});
