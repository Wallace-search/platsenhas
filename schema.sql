-- Execute no Supabase: SQL Editor → New query → Run

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS users (
  id         UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  username   TEXT UNIQUE NOT NULL,   -- email
  full_name  TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL,
  role       TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin'))
);

-- Códigos OTP para login (expiram em 10 minutos, uso único)
CREATE TABLE IF NOT EXISTS otp_codes (
  id         UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  email      TEXT NOT NULL,
  code       TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used       BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tabela de senhas
CREATE TABLE IF NOT EXISTS password_entries (
  id                 UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name               TEXT NOT NULL,
  username           TEXT,
  url                TEXT,
  category           TEXT NOT NULL,
  notes              TEXT,
  encrypted_password TEXT NOT NULL,
  iv                 TEXT NOT NULL
);

-- Tabela de logs de auditoria
CREATE TABLE IF NOT EXISTS audit_logs (
  id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  username    TEXT,
  full_name   TEXT,
  squad       TEXT,
  reason      TEXT,
  operation   TEXT,
  target      TEXT,
  access_code TEXT,
  timestamp   TIMESTAMPTZ DEFAULT NOW(),
  ip          TEXT
);

-- Tabela de categorias (gerenciada pelo admin)
CREATE TABLE IF NOT EXISTS categories (
  id         UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name       TEXT UNIQUE NOT NULL,
  sort_order INTEGER DEFAULT 99,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Categorias padrão
INSERT INTO categories (name, sort_order) VALUES
  ('Email',           1),
  ('Redes Sociais',   2),
  ('Ads',             3),
  ('SEO & Analytics', 4),
  ('Automacao',       5),
  ('Design & Midia',  6),
  ('IA',              7),
  ('Armazenamento',   8),
  ('Educacao',        9),
  ('Outros',          10)
ON CONFLICT (name) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_otp_email      ON otp_codes(email);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);
