import express from "express";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { fileTypeFromBuffer } from "file-type";
import { requireAuth } from "../middleware/auth.js";

export const uploadRouter = express.Router();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Sadece bu üçü kabul edilir — istek ne derse desin, gerçek dosya içeriği bununla eşleşmeli.
const ALLOWED_MIME = ["application/pdf", "image/png", "image/jpeg"];
const MAX_SIZE_BYTES = 8 * 1024 * 1024; // 8 MB

const upload = multer({
  storage: multer.memoryStorage(), // diske yazmadan, doğrudan Cloudinary'ye aktarılır
  limits: { fileSize: MAX_SIZE_BYTES },
  fileFilter: (req, file, cb) => {
    // Bu ön kontrol sadece istemcinin BEYAN ETTİĞİ tipe bakar — asıl güvenlik
    // kontrolü aşağıda, dosyanın gerçek baytlarını okuyarak yapılır.
    if (!ALLOWED_MIME.includes(file.mimetype)) {
      return cb(new Error("Desteklenmeyen dosya türü. Sadece PDF, PNG veya JPEG kabul edilir."));
    }
    cb(null, true);
  },
});

/**
 * Ticket eklerini (görsel/belge) kabul eder. requireAuth ile korunur — giriş
 * yapmamış kimse dosya yükleyemez. Dosya diske hiç yazılmadan, doğrudan
 * bellekten Cloudinary'ye aktarılır.
 *
 * ÖNEMLİ: Bir istemci, gerçekte çalıştırılabilir bir dosyayı "image/png" gibi
 * göstererek fileFilter'ı atlatabilir — çünkü Content-Type istemci tarafından
 * beyan edilir, doğrulanmaz. Bu yüzden dosya buffer'ının GERÇEK baytlarını
 * (magic number / dosya imzası) okuyup, beyan edilen tipin doğru olduğunu
 * ayrıca teyit ediyoruz. Bu iki katmanlı kontrolden biri bile atlatılamaz.
 */
uploadRouter.post("/upload/ticket-attachment", requireAuth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Dosya bulunamadı." });

  const detected = await fileTypeFromBuffer(req.file.buffer);
  if (!detected || !ALLOWED_MIME.includes(detected.mime)) {
    return res.status(400).json({
      error: "Dosya içeriği beyan edilen türle uyuşmuyor veya desteklenmiyor. Sadece PDF, PNG veya JPEG kabul edilir.",
    });
  }

  try {
    const uploaded = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: "alpeptide/tickets", resource_type: "auto" },
        (err, result) => (err ? reject(err) : resolve(result))
      );
      stream.end(req.file.buffer);
    });
    res.json({ url: uploaded.secure_url });
  } catch (err) {
    console.error("[upload] Cloudinary hatası:", err.message);
    res.status(502).json({ error: "Dosya yüklenirken bir sorun oluştu." });
  }
});

// multer'ın kendi hataları (dosya boyutu/tipi) için özel yakalayıcı
uploadRouter.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message?.includes("Desteklenmeyen")) {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});
