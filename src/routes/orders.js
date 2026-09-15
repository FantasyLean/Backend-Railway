import express from "express";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/auth.js";

export const ordersRouter = express.Router();

function makeUniqueAmount(baseAmount) {
  const base = Math.floor(Number(baseAmount));
  const noise = Math.floor(Math.random() * 900000) + 100000;
  return Number(`${base}.${noise}`);
}

ordersRouter.post("/orders", requireAuth, async (req, res) => {
  const { items, couponCode, addressId } = req.body;
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: "Sepet boş." });
  }
  if (items.length > 50) {
    return res.status(400).json({ error: "Tek siparişte en fazla 50 farklı ürün olabilir." });
  }

  // --- Her ürünü veritabanından tek tek doğrula. İstemcinin gönderdiği
  //     fiyat/isim/tutar HİÇBİR ZAMAN kullanılmaz — sadece "hangi ürün,
  //     kaç adet" bilgisi alınır, gerçek fiyat sunucudan okunur. ---
  const verifiedItems = [];
  for (const { productId, qty } of items) {
    const quantity = Number(qty);
    if (!productId || !Number.isInteger(quantity) || quantity < 1 || quantity > 99) {
      return res.status(400).json({ error: "Geçersiz ürün veya miktar." });
    }
    const { rows } = await pool.query(`SELECT id, name, price, stock_status FROM products WHERE id = $1`, [productId]);
    const product = rows[0];
    if (!product) return res.status(404).json({ error: `Ürün bulunamadı: ${productId}` });
    if (product.stock_status !== "in") return res.status(409).json({ error: `${product.name} şu anda stokta yok.` });

    verifiedItems.push({ productId, name: product.name, price: Number(product.price), qty: quantity });
  }

  const rawSubtotal = verifiedItems.reduce((sum, i) => sum + i.price * i.qty, 0);

  // --- Kupon veritabanından doğrulanır (aktif mi, süresi dolmuş mu,
  //     kullanım limiti dolmuş mu) ve UYGULANIR. İstemcinin "bu kuponun
  //     oranı %50" demesi hiçbir şekilde kabul edilmez. ---
  let discountRate = 0;
  let appliedCoupon = null;
  if (couponCode) {
    const normalized = String(couponCode).trim().toUpperCase();
    const { rows: couponRows } = await pool.query(
      `SELECT * FROM coupons WHERE code = $1 AND active = true
         AND (expires_at IS NULL OR expires_at > now())
         AND (max_uses IS NULL OR used_count < max_uses)`,
      [normalized]
    );
    if (couponRows[0]) {
      discountRate = Number(couponRows[0].discount_rate);
      appliedCoupon = normalized;
      await pool.query(`UPDATE coupons SET used_count = used_count + 1 WHERE id = $1`, [couponRows[0].id]);
    }
    // Geçersiz/süresi dolmuş kupon kodu sessizce yok sayılır — sipariş kupon olmadan devam eder.
  }
  const subtotal = Math.round(rawSubtotal * (1 - discountRate) * 100) / 100;

  // --- Adres, GERÇEKTEN bu kullanıcıya ait mi? ---
  if (addressId) {
    const addrCheck = await pool.query(`SELECT id FROM addresses WHERE id = $1 AND user_id = $2`, [addressId, req.user.sub]);
    if (addrCheck.rows.length === 0) return res.status(404).json({ error: "Adres bulunamadı." });
  }

  const orderNumber = `ALP-${Math.floor(6000 + Math.random() * 900)}`;
  const expectedAmount = makeUniqueAmount(subtotal.toFixed(2));

  const { rows } = await pool.query(
    `INSERT INTO orders (order_number, user_id, address_id, items, coupon_code, subtotal, expected_amount, currency, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'USDT-TRC20', 'pending')
     RETURNING *`,
    [orderNumber, req.user.sub, addressId || null, JSON.stringify(verifiedItems), appliedCoupon, subtotal, expectedAmount]
  );

  res.json({
    order: rows[0],
    paymentInstructions: {
      walletAddress: process.env.TRON_WALLET_ADDRESS,
      exactAmount: expectedAmount,
      currency: "USDT (TRC20)",
      note: "Lütfen tam olarak belirtilen tutarı gönderin — ödemenizin otomatik eşleşmesi için bu gereklidir.",
    },
  });
});

ordersRouter.get("/orders", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC`,
    [req.user.sub]
  );
  res.json(rows);
});

ordersRouter.post("/orders/clear-history", requireAuth, async (req, res) => {
  await pool.query(
    `UPDATE orders SET history_cleared = true WHERE user_id = $1 AND status = 'delivered'`,
    [req.user.sub]
  );
  res.json({ ok: true });
});
