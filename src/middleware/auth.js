import jwt from "jsonwebtoken";
import { pool } from "../db/pool.js";

export async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Giriş yapmanız gerekiyor." });
  }
  try {
    const token = header.slice("Bearer ".length);
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Token'ın kendisi geçerli olsa bile, kullanıcı çıkış yaptıysa veya
    // şifresini değiştirdiyse token_version artmış olur ve bu eski token
    // artık İŞE YARAMAZ hale gelir — JWT'lerin normalde sahip olmadığı bir
    // "iptal edilebilirlik" özelliğini bu şekilde kazanıyoruz.
    const { rows } = await pool.query(`SELECT token_version FROM users WHERE id = $1`, [payload.sub]);
    if (!rows[0] || rows[0].token_version !== payload.tv) {
      return res.status(401).json({ error: "Oturum geçersiz veya süresi dolmuş." });
    }

    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Oturum geçersiz veya süresi dolmuş." });
  }
}

/**
 * Admin yetkisi çok hassas bir işlem olduğu için, JWT içindeki (login anında
 * damgalanmış, en fazla JWT_EXPIRES_IN kadar bayatlayabilen) role bilgisine
 * güvenmek yerine veritabanından O ANKİ rolü tekrar okuyoruz. Bu sayede bir
 * admin yetkisi geri alındığında, eski token hâlâ geçerli olsa bile etki
 * anında sona erer.
 */
export async function requireAdmin(req, res, next) {
  try {
    const { rows } = await pool.query(`SELECT role FROM users WHERE id = $1`, [req.user?.sub]);
    if (rows[0]?.role !== "admin") {
      return res.status(403).json({ error: "Bu işlem için yetkiniz yok." });
    }
    next();
  } catch (err) {
    console.error("[requireAdmin]", err);
    res.status(500).json({ error: "Sunucu tarafında bir hata oluştu." });
  }
}
