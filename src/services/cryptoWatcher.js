import axios from "axios";
import cron from "node-cron";
import { pool } from "../db/pool.js";

const USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"; // resmi USDT (TRC20) kontrat adresi
const MIN_CONFIRMATIONS = Number(process.env.MIN_CONFIRMATIONS || 19);
// Kripto tutarları ondalık hassasiyet nedeniyle bit farklılık gösterebilir —
// beklenen tutarla küçük bir tolerans içinde eşleştiriyoruz.
const AMOUNT_TOLERANCE = 0.000005;

/**
 * TronGrid'den cüzdanımıza gelen son USDT-TRC20 işlemlerini çeker.
 * Dokümantasyon: https://developers.tron.network/reference/get-trc20-transaction-info-by-account-address
 */
async function fetchIncomingTransactions() {
  const url = `https://api.trongrid.io/v1/accounts/${process.env.TRON_WALLET_ADDRESS}/transactions/trc20`;
  const { data } = await axios.get(url, {
    params: { limit: 50, contract_address: USDT_TRC20_CONTRACT, only_to: true },
    headers: { "TRON-PRO-API-KEY": process.env.TRONGRID_API_KEY },
  });
  return data.data || [];
}

/** Bir işlemin kaç blok onayı aldığını hesaplar (basitleştirilmiş yaklaşım). */
async function getConfirmationCount(txHash) {
  const url = `https://api.trongrid.io/wallet/gettransactioninfobyid`;
  const { data } = await axios.post(url, { value: txHash }, {
    headers: { "TRON-PRO-API-KEY": process.env.TRONGRID_API_KEY },
  });
  if (!data?.blockNumber) return 0;
  const { data: nowBlock } = await axios.post("https://api.trongrid.io/wallet/getnowblock", {}, {
    headers: { "TRON-PRO-API-KEY": process.env.TRONGRID_API_KEY },
  });
  const currentHeight = nowBlock?.block_header?.raw_data?.number || 0;
  return Math.max(0, currentHeight - data.blockNumber);
}

async function processTransaction(tx) {
  const amount = Number(tx.value) / 1e6; // USDT 6 ondalıklı çalışır
  const txHash = tx.transaction_id;

  // Bu işlem zaten işlenmiş mi?
  const already = await pool.query(`SELECT id FROM orders WHERE tx_hash = $1`, [txHash]);
  if (already.rows.length > 0) return;

  // Tutara göre bekleyen bir sipariş bul
  const { rows } = await pool.query(
    `SELECT * FROM orders
     WHERE status = 'pending'
       AND ABS(expected_amount - $1) < $2
     ORDER BY created_at ASC
     LIMIT 1`,
    [amount, AMOUNT_TOLERANCE]
  );
  const order = rows[0];
  if (!order) {
    console.log(`[crypto-watcher] Eşleşmeyen gelen işlem: ${amount} USDT (${txHash}) — eşleşen sipariş yok, göz ardı edildi.`);
    return;
  }

  const confirmations = await getConfirmationCount(txHash);

  if (confirmations < MIN_CONFIRMATIONS) {
    // Henüz yeterli onay yok — "ödeme onaylama aşamasında" olarak işaretle, bir sonraki taramada tekrar kontrol edilir
    await pool.query(
      `UPDATE orders SET status = 'payment_review', tx_hash = $2, confirmations = $3, updated_at = now() WHERE id = $1`,
      [order.id, txHash, confirmations]
    );
    return;
  }

  // Yeterli onay var → otomatik onayla
  await pool.query(
    `UPDATE orders SET status = 'payment_confirmed', tx_hash = $2, confirmations = $3, updated_at = now() WHERE id = $1`,
    [order.id, txHash, confirmations]
  );
  console.log(`[crypto-watcher] ✅ ${order.order_number} otomatik onaylandı (${amount} USDT, ${confirmations} onay).`);

  // TODO: burada kullanıcıya "ödemeniz onaylandı" bildirimi / e-postası gönderilebilir.
}

async function checkPendingPayments() {
  try {
    const transactions = await fetchIncomingTransactions();
    for (const tx of transactions) {
      await processTransaction(tx);
    }
  } catch (err) {
    console.error("[crypto-watcher] Kontrol sırasında hata:", err.message);
  }
}

/** Sunucu başlarken çağrılır — periyodik taramayı zamanlar. */
export function startCryptoWatcher() {
  const minutes = Number(process.env.PAYMENT_CHECK_INTERVAL_MINUTES || 2);
  console.log(`[crypto-watcher] Başlatıldı — her ${minutes} dakikada bir zincir kontrol edilecek.`);
  cron.schedule(`*/${minutes} * * * *`, checkPendingPayments);
  checkPendingPayments(); // sunucu açılışında bir kez de hemen çalıştır
}
