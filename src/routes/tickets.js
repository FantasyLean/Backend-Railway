import express from "express";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";
import { isNonEmptyString } from "../utils/validate.js";
import { sanitizeText } from "../utils/sanitize.js";
import { createVerificationCode, verifyCode, sendMail } from "../utils/mailer.js";
import { checkBan, recordFailure, clearFailures } from "../utils/rateLimit.js";

export const ticketsRouter = express.Router();

const ASK_TOPICS = ["Ürün Seçimi ve Kullanımı", "Ürün Problemleri", "Kargo Sorunları", "Teknik Destek", "Diğer"];
const PAYMENT_TOPICS = ["Ödemeyi Tamamladım", "Ödeme Aşamasında Sorun Yaşadım", "Kripto Adresini Bulamıyorum", "Diğer"];

// ---------- listele (silinmiş olanlar hariç) ----------
ticketsRouter.get("/tickets", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM tickets WHERE user_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC`,
    [req.user.sub]
  );
  res.json(rows);
});

ticketsRouter.get("/tickets/:id", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM tickets WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
    [req.params.id, req.user.sub]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Ticket bulunamadı." });

  const messages = await pool.query(
    `SELECT * FROM ticket_messages WHERE ticket_id = $1 ORDER BY created_at ASC`,
    [req.params.id]
  );
  res.json({ ...rows[0], messages: messages.rows });
});

// ---------- yeni ticket oluştur (konu ve mesaj zorunlu) ----------
ticketsRouter.post("/tickets", requireAuth, async (req, res) => {
  const { mode, subject, message, orderId, attachmentUrl } = req.body;

  if (mode !== "ask" && mode !== "payment") return res.status(400).json({ error: "Geçersiz ticket türü." });
  const validTopics = mode === "ask" ? ASK_TOPICS : PAYMENT_TOPICS;
  if (!validTopics.includes(subject)) return res.status(400).json({ error: "Lütfen listeden bir konu seçin." });
  if (!isNonEmptyString(message, 4000)) return res.status(400).json({ error: "Mesaj zorunludur." });
  if (mode === "payment" && !orderId) return res.status(400).json({ error: "Lütfen bir sipariş seçin." });

  if (orderId) {
    const orderCheck = await pool.query(`SELECT id FROM orders WHERE id = $1 AND user_id = $2`, [orderId, req.user.sub]);
    if (orderCheck.rows.length === 0) return res.status(404).json({ error: "Sipariş bulunamadı." });
  }

  const ticketNumber = `T-${Math.floor(1000 + Math.random() * 9000)}`;
  const { rows } = await pool.query(
    `INSERT INTO tickets (ticket_number, user_id, mode, subject, order_id, status)
     VALUES ($1,$2,$3,$4,$5,'open') RETURNING *`,
    [ticketNumber, req.user.sub, mode, subject, orderId || null]
  );
  const ticket = rows[0];

  await pool.query(
    `INSERT INTO ticket_messages (ticket_id, from_role, body, attachment_url) VALUES ($1, 'user', $2, $3)`,
    [ticket.id, sanitizeText(message), attachmentUrl || null]
  );

  res.status(201).json(ticket);
});

// ---------- mevcut ticket'a mesaj ekle ----------
ticketsRouter.post("/tickets/:id/messages", requireAuth, async (req, res) => {
  const { message, attachmentUrl } = req.body;
  if (!isNonEmptyString(message, 4000)) return res.status(400).json({ error: "Mesaj boş olamaz." });

  const ticket = await pool.query(
    `SELECT id FROM tickets WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
    [req.params.id, req.user.sub]
  );
  if (ticket.rows.length === 0) return res.status(404).json({ error: "Ticket bulunamadı." });

  const { rows } = await pool.query(
    `INSERT INTO ticket_messages (ticket_id, from_role, body, attachment_url) VALUES ($1, 'user', $2, $3) RETURNING *`,
    [req.params.id, sanitizeText(message), attachmentUrl || null]
  );
  res.status(201).json(rows[0]);
});

// ---------- çözüldü olarak işaretle ----------
ticketsRouter.post("/tickets/:id/resolve", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `UPDATE tickets SET status = 'closed' WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL RETURNING *`,
    [req.params.id, req.user.sub]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Ticket bulunamadı." });
  res.json(rows[0]);
});

// ---------- silme: adım 1 — onay kodu gönder ----------
ticketsRouter.post("/tickets/:id/request-delete", requireAuth, async (req, res) => {
  const ticket = await pool.query(
    `SELECT t.ticket_number, u.email FROM tickets t JOIN users u ON u.id = t.user_id
     WHERE t.id = $1 AND t.user_id = $2 AND t.deleted_at IS NULL`,
    [req.params.id, req.user.sub]
  );
  if (ticket.rows.length === 0) return res.status(404).json({ error: "Ticket bulunamadı." });

  const code = await createVerificationCode(req.user.sub, `delete_ticket:${req.params.id}`, req.params.id, 5);
  await sendMail(ticket.rows[0].email, "Alpeptide — Ticket Silme Onayı",
    `${ticket.rows[0].ticket_number} numaralı ticket'ı silmek için kodunuz: <b>${code}</b>`);
  res.json({ message: "Onay kodu e-posta adresinize gönderildi." });
});

// ---------- silme: adım 2 — kodu doğrula, soft-delete uygula ----------
ticketsRouter.post("/tickets/:id/confirm-delete", requireAuth, async (req, res) => {
  const { code } = req.body;
  const identifier = `delete-ticket:${req.user.sub}`;

  const ban = await checkBan(identifier, "verification_code");
  if (ban.requiresRecovery) return res.status(403).json({ error: "requires_recovery" });
  if (ban.banned) return res.status(429).json({ error: "banned", bannedUntil: ban.bannedUntil });

  const result = await verifyCode(req.user.sub, `delete_ticket:${req.params.id}`, code);
  if (!result.valid) {
    const outcome = await recordFailure(identifier, "verification_code");
    return res.status(400).json({ error: "wrong_code", ...outcome });
  }
  await clearFailures(identifier, "verification_code");

  const { rows } = await pool.query(
    `UPDATE tickets SET deleted_at = now() WHERE id = $1 AND user_id = $2 RETURNING id`,
    [req.params.id, req.user.sub]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Ticket bulunamadı." });
  res.json({ ok: true });
});
