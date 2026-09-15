-- Frontend'de daha önce sabit kodlu olan kuponlar — geçiş sorunsuz olsun diye.
-- Çalıştırmak için: psql "$DATABASE_URL" -f src/db/seed.sql
INSERT INTO coupons (code, discount_rate) VALUES
  ('ALP10', 0.10),
  ('HIRO20', 0.20),
  ('USDT5', 0.05)
ON CONFLICT (code) DO NOTHING;
