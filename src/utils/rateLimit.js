import { pool } from "../db/pool.js";

// 1) 5 dk  2) 30 dk  3) 1 saat  4) 6 saat  5) zorunlu hesap kurtarma
const BAN_LADDER_MS = [5 * 60_000, 30 * 60_000, 60 * 60_000, 6 * 60 * 60_000];
export const LOGIN_PASSWORD_MAX_ATTEMPTS = 5;
export const LOGIN_PASSWORD_BAN_MS = 12 * 60 * 60_000;

/**
 * Bir eylemin (giriş şifresi denemesi veya doğrulama kodu denemesi) şu an
 * yasaklı olup olmadığını kontrol eder. `identifier` genelde IP veya user_id'dir.
 */
export async function checkBan(identifier, action) {
  const { rows } = await pool.query(
    `SELECT * FROM rate_limit_state WHERE identifier = $1 AND action = $2`,
    [identifier, action]
  );
  const state = rows[0];
  if (!state) return { banned: false, requiresRecovery: false };

  if (state.requires_recovery) return { banned: true, requiresRecovery: true };
  if (state.banned_until && new Date(state.banned_until) > new Date()) {
    return { banned: true, requiresRecovery: false, bannedUntil: state.banned_until };
  }
  return { banned: false, requiresRecovery: false };
}

/** Başarısız bir denemeyi kaydeder ve gerekiyorsa ban/kurtarma uygular. */
export async function recordFailure(identifier, action, ladder = BAN_LADDER_MS) {
  const { rows } = await pool.query(
    `INSERT INTO rate_limit_state (identifier, action, fail_count, updated_at)
     VALUES ($1, $2, 1, now())
     ON CONFLICT (identifier, action)
     DO UPDATE SET fail_count = rate_limit_state.fail_count + 1, updated_at = now()
     RETURNING fail_count`,
    [identifier, action]
  );
  const failCount = rows[0].fail_count;

  if (failCount >= ladder.length + 1) {
    await pool.query(
      `UPDATE rate_limit_state SET requires_recovery = true WHERE identifier = $1 AND action = $2`,
      [identifier, action]
    );
    return { requiresRecovery: true };
  }

  const banMs = ladder[failCount - 1];
  const bannedUntil = new Date(Date.now() + banMs);
  await pool.query(
    `UPDATE rate_limit_state SET banned_until = $3 WHERE identifier = $1 AND action = $2`,
    [identifier, action, bannedUntil]
  );
  return { bannedUntil };
}

/** Login şifre denemeleri için ayrı sabit süreli ban (5 hak → 12 saat). */
export async function recordLoginPasswordFailure(identifier) {
  const { rows } = await pool.query(
    `INSERT INTO rate_limit_state (identifier, action, fail_count, updated_at)
     VALUES ($1, 'login_password', 1, now())
     ON CONFLICT (identifier, action)
     DO UPDATE SET fail_count = rate_limit_state.fail_count + 1, updated_at = now()
     RETURNING fail_count`,
    [identifier]
  );
  const failCount = rows[0].fail_count;
  if (failCount >= LOGIN_PASSWORD_MAX_ATTEMPTS) {
    const bannedUntil = new Date(Date.now() + LOGIN_PASSWORD_BAN_MS);
    await pool.query(
      `UPDATE rate_limit_state SET banned_until = $2 WHERE identifier = $1 AND action = 'login_password'`,
      [identifier, bannedUntil]
    );
    return { banned: true, bannedUntil };
  }
  return { banned: false, remaining: LOGIN_PASSWORD_MAX_ATTEMPTS - failCount };
}

export async function clearFailures(identifier, action) {
  await pool.query(`DELETE FROM rate_limit_state WHERE identifier = $1 AND action = $2`, [identifier, action]);
}
