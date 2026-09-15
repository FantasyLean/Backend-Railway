import express from "express";
import { pool } from "../db/pool.js";
import { requireAuth, requireAdmin } from "../middleware/auth.js";
import { isNonEmptyString } from "../utils/validate.js";
import { sanitizeText } from "../utils/sanitize.js";

export const adminRouter = express.Router();

// Bu router'daki HER rota önce giriş, sonra admin rolü ister.
adminRouter.use(requireAuth, requireAdmin);

const VALID_ORDER_STATUSES = [
  "pending", "payment_review", "payment_confirmed", "preparing", "shipped", "delivered", "flagged",
];

async function logAudit(req, action, targetType, targetId, details = {}) {
  await pool.query(
    `INSERT INTO audit_log (actor_id, action, target_type, target_id, details, ip_address)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [req.user.sub, action, targetType, targetId, JSON.stringify(details), req.ip]
  );
}

adminRouter.get("/users", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, full_name, username, email, email_verified_at, role, created_at FROM users ORDER BY created_at DESC LIMIT 200`
  );
  res.json(rows); // password_hash, totp_secret, backup_codes ASLA burada dönmez
});

adminRouter.get("/orders", async (req, res) => {
  const { status } = req.query;
  const { rows } = status
    ? await pool.query(`SELECT * FROM orders WHERE status = $1 ORDER BY created_at DESC LIMIT 200`, [status])
    : await pool.query(`SELECT * FROM orders ORDER BY created_at DESC LIMIT 200`);
  res.json(rows);
});

adminRouter.patch("/orders/:id/status", async (req, res) => {
  const { status, trackingNumber } = req.body;
  if (!VALID_ORDER_STATUSES.includes(status)) return res.status(400).json({ error: "Geçersiz durum." });

  const { rows } = await pool.query(
    `UPDATE orders SET status = $1, tracking_number = COALESCE($2, tracking_number), updated_at = now()
     WHERE id = $3 RETURNING *`,
    [status, trackingNumber || null, req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Sipariş bulunamadı." });

  await logAudit(req, "order_status_change", "order", req.params.id, { newStatus: status, trackingNumber });
  res.json(rows[0]);
});

adminRouter.get("/tickets", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT t.*, u.email, u.username FROM tickets t JOIN users u ON u.id = t.user_id
     WHERE t.deleted_at IS NULL ORDER BY t.created_at DESC LIMIT 200`
  );
  res.json(rows);
});

adminRouter.get("/tickets/:id", async (req, res) => {
  const ticket = await pool.query(`SELECT * FROM tickets WHERE id = $1`, [req.params.id]);
  if (ticket.rows.length === 0) return res.status(404).json({ error: "Ticket bulunamadı." });
  const messages = await pool.query(`SELECT * FROM ticket_messages WHERE ticket_id = $1 ORDER BY created_at ASC`, [req.params.id]);
  res.json({ ...ticket.rows[0], messages: messages.rows });
});

// ---------- KUPONLAR ----------
adminRouter.get("/coupons", async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM coupons ORDER BY created_at DESC`);
  res.json(rows);
});

adminRouter.post("/coupons", async (req, res) => {
  const { code, discountRate, expiresAt, maxUses } = req.body;
  if (!isNonEmptyString(code, 30)) return res.status(400).json({ error: "Kupon kodu zorunludur." });
  if (typeof discountRate !== "number" || discountRate <= 0 || discountRate > 1) {
    return res.status(400).json({ error: "İndirim oranı 0 ile 1 arasında olmalıdır (örn. 0.10 = %10)." });
  }
  const { rows } = await pool.query(
    `INSERT INTO coupons (code, discount_rate, expires_at, max_uses) VALUES ($1,$2,$3,$4) RETURNING *`,
    [code.trim().toUpperCase(), discountRate, expiresAt || null, maxUses || null]
  );
  await logAudit(req, "coupon_create", "coupon", rows[0].id, { code });
  res.status(201).json(rows[0]);
});

adminRouter.patch("/coupons/:id", async (req, res) => {
  const { active, expiresAt, maxUses } = req.body;
  const { rows } = await pool.query(
    `UPDATE coupons SET active = COALESCE($1, active), expires_at = COALESCE($2, expires_at), max_uses = COALESCE($3, max_uses)
     WHERE id = $4 RETURNING *`,
    [active, expiresAt, maxUses, req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Kupon bulunamadı." });
  await logAudit(req, "coupon_update", "coupon", req.params.id, req.body);
  res.json(rows[0]);
});

adminRouter.delete("/coupons/:id", async (req, res) => {
  const { rows } = await pool.query(`DELETE FROM coupons WHERE id = $1 RETURNING id`, [req.params.id]);
  if (rows.length === 0) return res.status(404).json({ error: "Kupon bulunamadı." });
  await logAudit(req, "coupon_delete", "coupon", req.params.id);
  res.json({ ok: true });
});

adminRouter.post("/tickets/:id/reply", async (req, res) => {
  const { message, attachmentUrl } = req.body;
  if (!isNonEmptyString(message, 4000)) return res.status(400).json({ error: "Mesaj boş olamaz." });

  const ticket = await pool.query(`SELECT id FROM tickets WHERE id = $1`, [req.params.id]);
  if (ticket.rows.length === 0) return res.status(404).json({ error: "Ticket bulunamadı." });

  const { rows } = await pool.query(
    `INSERT INTO ticket_messages (ticket_id, from_role, body, attachment_url) VALUES ($1, 'support', $2, $3) RETURNING *`,
    [req.params.id, sanitizeText(message), attachmentUrl || null]
  );
  await pool.query(`UPDATE tickets SET status = 'answered' WHERE id = $1`, [req.params.id]);

  await logAudit(req, "ticket_reply", "ticket", req.params.id, {});
  res.status(201).json(rows[0]);
});
