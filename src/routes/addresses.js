import express from "express";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { isNonEmptyString } from "../utils/validate.js";
import { sanitizeText } from "../utils/sanitize.js";

export const addressesRouter = express.Router();

const VALID_TYPES = ["Ev", "İş Yeri", "Arkadaş", "Eş"];

addressesRouter.get("/addresses", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM addresses WHERE user_id = $1 ORDER BY created_at ASC`,
    [req.user.sub]
  );
  res.json(rows);
});

addressesRouter.post("/addresses", requireAuth, async (req, res) => {
  const { type, fullName, phone, country, city, district, postalCode, line1, line2 } = req.body;

  if (!VALID_TYPES.includes(type)) return res.status(400).json({ error: "Geçersiz adres tipi." });
  if (!isNonEmptyString(fullName, 100) || !isNonEmptyString(line1, 200)) {
    return res.status(400).json({ error: "Ad soyad ve adres satırı 1 zorunludur." });
  }

  const { rows } = await pool.query(
    `INSERT INTO addresses (user_id, type, full_name, phone, country, city, district, postal_code, line1, line2)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [req.user.sub, type, sanitizeText(fullName), sanitizeText(phone) || null, sanitizeText(country) || null, sanitizeText(city) || null, sanitizeText(district) || null, sanitizeText(postalCode) || null, sanitizeText(line1), sanitizeText(line2) || null]
  );
  res.status(201).json(rows[0]);
});

addressesRouter.put("/addresses/:id", requireAuth, async (req, res) => {
  const { type, fullName, phone, country, city, district, postalCode, line1, line2 } = req.body;
  if (!VALID_TYPES.includes(type)) return res.status(400).json({ error: "Geçersiz adres tipi." });
  if (!isNonEmptyString(fullName, 100) || !isNonEmptyString(line1, 200)) {
    return res.status(400).json({ error: "Ad soyad ve adres satırı 1 zorunludur." });
  }

  // WHERE'de user_id de kontrol edilir — başka bir kullanıcının adresini
  // düzenlemeye çalışmak sessizce hiçbir satırı etkilemez.
  const { rows } = await pool.query(
    `UPDATE addresses SET type=$1, full_name=$2, phone=$3, country=$4, city=$5, district=$6, postal_code=$7, line1=$8, line2=$9
     WHERE id = $10 AND user_id = $11 RETURNING *`,
    [type, sanitizeText(fullName), sanitizeText(phone) || null, sanitizeText(country) || null, sanitizeText(city) || null, sanitizeText(district) || null, sanitizeText(postalCode) || null, sanitizeText(line1), sanitizeText(line2) || null, req.params.id, req.user.sub]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Adres bulunamadı." });
  res.json(rows[0]);
});

addressesRouter.delete("/addresses/:id", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `DELETE FROM addresses WHERE id = $1 AND user_id = $2 RETURNING id`,
    [req.params.id, req.user.sub]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Adres bulunamadı." });
  res.json({ ok: true });
});
