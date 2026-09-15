import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { pool } from "./pool.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function seed() {
  const sql = readFileSync(join(__dirname, "seed.sql"), "utf8");
  console.log("[seed] Başlangıç verisi ekleniyor...");
  await pool.query(sql);
  console.log("[seed] Tamamlandı.");
  await pool.end();
}

seed().catch((err) => {
  console.error("[seed] Hata:", err);
  process.exit(1);
});
