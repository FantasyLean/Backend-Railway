import express from "express";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import slowDown from "express-slow-down";

import { authRouter } from "./routes/auth.js";
import { twoFactorRouter } from "./routes/twoFactor.js";
import { ordersRouter } from "./routes/orders.js";
import { addressesRouter } from "./routes/addresses.js";
import { ticketsRouter } from "./routes/tickets.js";
import { adminRouter } from "./routes/admin.js";
import { productsRouter } from "./routes/products.js";
import { uploadRouter } from "./routes/upload.js";
import { privacyRouter } from "./routes/privacy.js";
import { accountRouter } from "./routes/account.js";
import { attackSignatureFilter } from "./middleware/waf.js";
import { startCryptoWatcher } from "./services/cryptoWatcher.js";
import { startDataRetentionJob } from "./services/dataRetention.js";

dotenv.config();

// ---------- Açılışta kritik ortam değişkenlerini kontrol et ----------
// Bunlardan biri eksikse sunucu YANLIŞLIKLA güvensiz bir şekilde ayağa
// kalkmasın diye hemen durduruyoruz — geç fark etmek yerine hemen görelim.
const REQUIRED_ENV = ["DATABASE_URL", "JWT_SECRET", "ENCRYPTION_KEY"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[startup] Kritik ortam değişkeni eksik: ${key}. Sunucu başlatılamıyor.`);
    process.exit(1);
  }
}
if (process.env.JWT_SECRET.length < 32) {
  console.error("[startup] JWT_SECRET çok kısa/zayıf (en az 32 karakter olmalı). Sunucu başlatılamıyor.");
  process.exit(1);
}
if (process.env.ENCRYPTION_KEY.length < 32) {
  console.error("[startup] ENCRYPTION_KEY çok kısa/zayıf (en az 32 karakter olmalı). Sunucu başlatılamıyor.");
  process.exit(1);
}
if (process.env.ENCRYPTION_KEY === process.env.JWT_SECRET) {
  console.error("[startup] ENCRYPTION_KEY, JWT_SECRET ile aynı olamaz — ayrı, bağımsız bir anahtar kullanın.");
  process.exit(1);
}
if (process.env.NODE_ENV === "production" && !process.env.FRONTEND_URL) {
  console.error("[startup] Prod ortamda FRONTEND_URL tanımlı olmalı (CORS için).");
  process.exit(1);
}

const app = express();

// Railway/Render/Netlify gibi bir ters proxy'nin arkasında çalışırken,
// req.ip'nin gerçek istemci IP'sini göstermesi için gerekli — aksi halde
// ban sistemi herkesi proxy'nin TEK IP'si üzerinden aynı kişi sanır.
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"], // bu bir API sunucusu — hiçbir içerik render etmez
        frameAncestors: ["'none'"],
      },
    },
    // Tarayıcıya "bu siteye bir daha ASLA http:// ile bağlanma" der —
    // bir saldırganın araya girip trafiği şifresiz http'ye düşürmesini
    // (downgrade saldırısı) engeller.
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  })
);
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(compression());
app.use(express.json({ limit: "100kb" })); // aşırı büyük istek gövdelerine karşı
app.use(attackSignatureFilter); // query/path parametrelerinde açık saldırı imzalarını erkenden reddeder

// Genel bir istek sınırlaması — tüm rotalar için taban seviye koruma
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Sert bir "limit aşıldı, reddet" yerine, tekrarlayan isteklerde yanıtı
// kademeli olarak yavaşlatır — otomatik saldırı script'lerini pahalı hale
// getirir, gerçek kullanıcıları neredeyse hiç etkilemez.
app.use(
  slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 100,
    delayMs: (hits) => hits * 100,
    maxDelayMs: 5000,
  })
);

// Kimlik doğrulama uçları çok daha hassas — kaba kuvvet denemelerini
// veritabanına ulaşmadan, ağ seviyesinde de yavaşlatıyoruz.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla istek gönderildi. Lütfen biraz sonra tekrar deneyin." },
});
app.use("/api/auth", authLimiter);

// Admin uçları da ayrı ve daha sıkı bir sınırlamaya tabi — bir admin
// hesabının ele geçirilmiş bir token'la kitlesel işlem yapması zorlaşır.
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/admin", adminLimiter);

app.use("/api/auth", authRouter);
app.use("/api", twoFactorRouter);
app.use("/api", ordersRouter);
app.use("/api", addressesRouter);
app.use("/api", ticketsRouter);
app.use("/api/admin", adminRouter);
app.use("/api", productsRouter); // /api/products (herkese açık) + /api/admin/products (admin)
app.use("/api", uploadRouter);   // /api/upload/ticket-attachment
app.use("/api", privacyRouter);  // /api/me/export, /api/me/request-delete, /api/me/confirm-delete
app.use("/api", accountRouter);  // /api/account/request-name-change, /api/account/request-email-change vb.

app.get("/api/health", (req, res) => res.json({ ok: true }));

// 404 — tanımsız rotalar için
app.use((req, res) => res.status(404).json({ error: "Bulunamadı." }));

// Genel hata yakalayıcı — HİÇBİR ZAMAN ham hata/stack trace istemciye
// sızdırılmaz, sadece sunucu loguna yazılır.
app.use((err, req, res, next) => {
  console.error("[unhandled]", err);
  res.status(500).json({ error: "Sunucu tarafında bir hata oluştu." });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`[server] Alpeptide backend http://localhost:${PORT} üzerinde çalışıyor`);
  startCryptoWatcher();
  startDataRetentionJob();
});
