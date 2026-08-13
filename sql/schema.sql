CREATE TABLE IF NOT EXISTS user_roles (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO user_roles (code, name, description) VALUES
  ('SUPER_ADMIN', 'SuperAdmin', 'Acceso total a la plataforma'),
  ('ADMINISTRADOR', 'Administrador', 'Administra empresas, licencias y usuarios de un tenant'),
  ('OPERATIVO', 'Operativo', 'Opera funciones del tenant')
ON CONFLICT (code) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  external_id TEXT,
  username VARCHAR(50) NOT NULL,
  email VARCHAR(255) NOT NULL,
  email_normalized VARCHAR(255) NOT NULL,
  tenant_id UUID NOT NULL,
  role TEXT NOT NULL DEFAULT 'OPERATIVO' REFERENCES user_roles(code),
  status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
  is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  is_phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
  last_login_at TIMESTAMPTZ,
  password_changed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users (LOWER(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_normalized ON users (email_normalized) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users (deleted_at);

CREATE TABLE IF NOT EXISTS user_credentials (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  failed_login_count INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ,
  last_failed_login_at TIMESTAMPTZ,
  last_failed_login_ip INET,
  last_success_login_ip INET,
  must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
  password_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_profiles (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  first_name TEXT,
  last_name TEXT,
  full_name TEXT,
  phone_number VARCHAR(20),
  avatar_url TEXT,
  locale VARCHAR(10) NOT NULL DEFAULT 'es-CO',
  timezone VARCHAR(50) NOT NULL DEFAULT 'America/Bogota',
  bio TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_preferences (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  theme VARCHAR(20) NOT NULL DEFAULT 'system',
  language VARCHAR(10) NOT NULL DEFAULT 'es',
  email_notifications BOOLEAN NOT NULL DEFAULT TRUE,
  sms_notifications BOOLEAN NOT NULL DEFAULT FALSE,
  push_notifications BOOLEAN NOT NULL DEFAULT TRUE,
  marketing_opt_in BOOLEAN NOT NULL DEFAULT FALSE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_password_history (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_password_history_user_id ON user_password_history (user_id);

CREATE TABLE IF NOT EXISTS user_audit_logs (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  event_type VARCHAR(50) NOT NULL,
  event_result VARCHAR(20) NOT NULL,
  ip_address INET,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_audit_logs_user_id ON user_audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_user_audit_logs_event_type ON user_audit_logs (event_type);

CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash TEXT NOT NULL,
  device_info TEXT,
  ip_address INET,
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_user_sessions_revoked_at ON user_sessions (revoked_at);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);
