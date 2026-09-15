import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { pool } from "./pool.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function migrate() {
  const sql = readFileSync(join(__dirname, "schema.sql"), "utf8");
  console.log("[migrate] Şema uygulanıyor...");
  await pool.query(sql);
  console.log("[migrate] Tamamlandı.");
  await pool.end();
}

migrate().catch((err) => {
  console.error("[migrate] Hata:", err);
  process.exit(1);
});
