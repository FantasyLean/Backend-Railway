import express from "express";
import { pool } from "../db/pool.js";
import { requireAuth, requireAdmin } from "../middleware/auth.js";
import { isNonEmptyString } from "../utils/validate.js";
import { sanitizeText } from "../utils/sanitize.js";

export const productsRouter = express.Router();

async function logAudit(req, action, targetType, targetId, details = {}) {
  await pool.query(
    `INSERT INTO audit_log (actor_id, action, target_type, target_id, details, ip_address)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [req.user.sub, action, targetType, targetId, JSON.stringify(details), req.ip]
  );
}

// ---------- HERKESE AÇIK: ürünleri listele/filtrele ----------
productsRouter.get("/products", async (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=60"); // 1 dakika — sık değişmeyen bir liste için makul
  const { category, form, purpose, featured, page = 1, pageSize = 12 } = req.query;

  const conditions = [];
  const params = [];
  if (category && category !== "Tümü") { params.push(category); conditions.push(`category = $${params.length}`); }
  if (form && form !== "Tümünü Gör") { params.push(form); conditions.push(`form = $${params.length}`); }
  if (purpose && purpose !== "Tümü") { params.push(purpose); conditions.push(`purpose = $${params.length}`); }
  if (featured === "true") conditions.push(`is_featured = true`);

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = Math.min(50, Number(pageSize) || 12);
  const offset = (Math.max(1, Number(page) || 1) - 1) * limit;

  const { rows } = await pool.query(
    `SELECT * FROM products ${where} ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, limit, offset]
  );
  const count = await pool.query(`SELECT COUNT(*) FROM products ${where}`, params);

  res.json({ items: rows, total: Number(count.rows[0].count) });
});

productsRouter.get("/products/:id", async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM products WHERE id = $1 OR sku = $1`, [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Ürün bulunamadı." });
  res.json(rows[0]);
});

// ---------- ADMIN: ürün ekle/güncelle/sil ----------
productsRouter.post("/admin/products", requireAuth, requireAdmin, async (req, res) => {
  const { sku, name, description, price, category, form, purpose, color, batchNumber, stockStatus, isFeatured } = req.body;

  if (!isNonEmptyString(sku, 40) || !isNonEmptyString(name, 200)) {
    return res.status(400).json({ error: "SKU ve ürün adı zorunludur." });
  }
  if (typeof price !== "number" || price <= 0) {
    return res.status(400).json({ error: "Geçerli bir fiyat giriniz." });
  }

  const { rows } = await pool.query(
    `INSERT INTO products (sku, name, description, price, category, form, purpose, color, batch_number, stock_status, is_featured)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10,'in'),COALESCE($11,false)) RETURNING *`,
    [sanitizeText(sku), sanitizeText(name), description ? sanitizeText(description) : null, price, category || null, form || null, purpose || null, color || null, batchNumber || null, stockStatus, isFeatured]
  );
  await logAudit(req, "product_create", "product", rows[0].id, { sku, name });
  res.status(201).json(rows[0]);
});

productsRouter.put("/admin/products/:id", requireAuth, requireAdmin, async (req, res) => {
  const { name, description, price, category, form, purpose, color, batchNumber, stockStatus, isFeatured } = req.body;
  if (!isNonEmptyString(name, 200)) return res.status(400).json({ error: "Ürün adı zorunludur." });
  if (typeof price !== "number" || price <= 0) return res.status(400).json({ error: "Geçerli bir fiyat giriniz." });

  const { rows } = await pool.query(
    `UPDATE products SET name=$1, description=$2, price=$3, category=$4, form=$5, purpose=$6, color=$7,
       batch_number=$8, stock_status=$9, is_featured=$10, updated_at=now()
     WHERE id = $11 RETURNING *`,
    [sanitizeText(name), description ? sanitizeText(description) : null, price, category || null, form || null, purpose || null, color || null, batchNumber || null, stockStatus, isFeatured, req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Ürün bulunamadı." });
  await logAudit(req, "product_update", "product", req.params.id, { name, price });
  res.json(rows[0]);
});

productsRouter.delete("/admin/products/:id", requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`DELETE FROM products WHERE id = $1 RETURNING id`, [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Ürün bulunamadı." });
  await logAudit(req, "product_delete", "product", req.params.id);
  res.json({ ok: true });
});
