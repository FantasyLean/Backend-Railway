-- Alpeptide — PostgreSQL şeması
-- Çalıştırmak için: psql "$DATABASE_URL" -f src/db/schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- gen_random_uuid() için

-- ============ KULLANICILAR ============
CREATE TABLE users (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name         TEXT NOT NULL,
  username          TEXT UNIQUE NOT NULL,
  email             TEXT UNIQUE NOT NULL,
  password_hash     TEXT NOT NULL,               -- bcrypt hash — asla düz metin
  email_verified_at TIMESTAMPTZ,                  -- NULL ise hesap henüz onaylanmamış
  last_name_change_at TIMESTAMPTZ,                -- ayda 1 kural kontrolü için
  role              TEXT NOT NULL DEFAULT 'user', -- 'user' | 'admin'
  token_version     INT NOT NULL DEFAULT 0,        -- artınca TÜM eski JWT'ler anında geçersiz olur (güvenli çıkış / şifre değişince)
  totp_secret       TEXT,                         -- Google Authenticator gizli anahtarı (şifreli saklanmalı)
  totp_enabled      BOOLEAN NOT NULL DEFAULT false,
  backup_codes      TEXT[],                       -- 2FA yedek kodları (hash'lenmiş şekilde saklanmalı)
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============ E-POSTA / GİRİŞ DOĞRULAMA KODLARI ============
-- Kayıt, giriş 2FA'sı, email/şifre değişikliği, hesap kurtarma — hepsi bu tabloyu kullanır
CREATE TABLE verification_codes (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL,      -- 'register' | 'login_2fa' | 'email_change' | 'password_change' | 'password_reset'
  code_hash   TEXT NOT NULL,      -- kodun kendisi değil, hash'i saklanır
  target      TEXT,               -- örn. yeni e-posta adresi (email_change için)
  expires_at  TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Bu tablo HER giriş/kayıt/2FA adımında sorgulanır — en sık çalışan
-- sorgumuz tam olarak bu üç sütuna göre filtreliyor.
CREATE INDEX idx_verification_codes_lookup ON verification_codes(user_id, purpose, consumed_at, expires_at);

-- ============ BRUTE-FORCE / BAN TAKİBİ ============
CREATE TABLE rate_limit_state (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier    TEXT NOT NULL,     -- IP adresi veya user_id, duruma göre
  action        TEXT NOT NULL,     -- 'login_password' | 'verification_code'
  fail_count    INT NOT NULL DEFAULT 0,
  banned_until  TIMESTAMPTZ,
  requires_recovery BOOLEAN NOT NULL DEFAULT false,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (identifier, action)
);

-- ============ OTURUM / GİRİŞ GEÇMİŞİ ============
CREATE TABLE login_history (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip_address  TEXT,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_login_history_user ON login_history(user_id);

-- ============ ADRESLER ============
CREATE TABLE addresses (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type        TEXT NOT NULL,   -- 'Ev' | 'İş Yeri' | 'Arkadaş' | 'Eş'
  full_name   TEXT NOT NULL,
  phone       TEXT,
  country     TEXT,
  city        TEXT,
  district    TEXT,
  postal_code TEXT,
  line1       TEXT NOT NULL,
  line2       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_addresses_user ON addresses(user_id);

-- ============ SİPARİŞLER ============
CREATE TABLE orders (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_number    TEXT UNIQUE NOT NULL,        -- örn. ALP-5521
  user_id         UUID REFERENCES users(id) ON DELETE SET NULL, -- hesap silinirse anonimleştirilir, sipariş kaydı kalır (muhasebe/yasal)
  address_id      UUID REFERENCES addresses(id) ON DELETE SET NULL,
  items           JSONB NOT NULL,              -- [{name, qty, price}]
  coupon_code     TEXT,
  subtotal        NUMERIC(12,4) NOT NULL,
  expected_amount NUMERIC(12,6) NOT NULL,      -- benzersiz eşleştirme tutarı (örn. 150.0037)
  currency        TEXT NOT NULL DEFAULT 'USDT-TRC20',
  status          TEXT NOT NULL DEFAULT 'pending',
    -- 'pending' | 'payment_review' | 'payment_confirmed' | 'preparing' | 'shipped' | 'delivered' | 'flagged'
  tx_hash         TEXT,                        -- eşleşen zincir işlemi bulununca doldurulur
  confirmations   INT,
  tracking_number TEXT,
  history_cleared BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_expected_amount ON orders(expected_amount) WHERE status = 'pending';
CREATE INDEX idx_orders_user ON orders(user_id); -- "Siparişlerim" sorgusu için

-- ============ KUPONLAR ============
CREATE TABLE coupons (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code          TEXT UNIQUE NOT NULL,
  discount_rate NUMERIC(4,3) NOT NULL CHECK (discount_rate > 0 AND discount_rate <= 1), -- 0.10 = %10
  active        BOOLEAN NOT NULL DEFAULT true,
  expires_at    TIMESTAMPTZ,                   -- NULL = süresiz
  max_uses      INT,                            -- NULL = sınırsız
  used_count    INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============ ÜRÜNLER ============
CREATE TABLE products (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sku           TEXT UNIQUE NOT NULL,      -- örn. "ALP-A" — frontend'de kısa referans için
  name          TEXT NOT NULL,
  description   TEXT,
  price         NUMERIC(12,2) NOT NULL,
  category      TEXT,                      -- 'Peptidler' | 'Reaktifler' vb.
  form          TEXT,                      -- 'Tablet' | 'Enjeksiyon' | 'Koruyucular'
  purpose       TEXT,                      -- 'Yağ Yakıcı' | 'Cilt Sağlığı' vb.
  color         TEXT,                      -- kart görselinde kullanılan renk kodu
  batch_number  TEXT,
  stock_status  TEXT NOT NULL DEFAULT 'in', -- 'in' | 'out'
  rating        NUMERIC(3,2) DEFAULT 4.5,
  review_count  INT DEFAULT 0,
  is_featured   BOOLEAN NOT NULL DEFAULT false, -- Ana Sayfa "Öne Çıkan Ürünler"
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_products_category ON products(category);
CREATE INDEX idx_products_featured ON products(is_featured) WHERE is_featured = true;

-- ============ DENETİM KAYDI (kim ne zaman ne yaptı) ============
CREATE TABLE audit_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
  action      TEXT NOT NULL,        -- örn. 'order_status_change', 'ticket_reply'
  target_type TEXT,                 -- 'order' | 'ticket' | 'user' | 'product'
  target_id   TEXT,
  details     JSONB,
  ip_address  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_log_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at); -- temizlik işi (data retention) için
-- ============ TICKET SİSTEMİ ============
CREATE TABLE tickets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_number TEXT UNIQUE NOT NULL,      -- örn. T-1042
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mode        TEXT NOT NULL,               -- 'ask' | 'payment'
  subject     TEXT NOT NULL,
  order_id    UUID REFERENCES orders(id) ON DELETE SET NULL,  -- payment modunda ilgili sipariş
  status      TEXT NOT NULL DEFAULT 'open', -- 'open' | 'answered' | 'closed'
  deleted_at  TIMESTAMPTZ,                  -- soft-delete: kalıcı silme yerine işaretlenir
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tickets_user ON tickets(user_id);

CREATE TABLE ticket_messages (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_id   UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  from_role   TEXT NOT NULL,   -- 'user' | 'support'
  body        TEXT NOT NULL,
  attachment_url TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ticket_messages_ticket ON ticket_messages(ticket_id);
