-- Native Social Connection accounts (master accounts)
CREATE TABLE IF NOT EXISTS native_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Social media accounts linked to native accounts
CREATE TABLE IF NOT EXISTS social_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  native_account_id INTEGER NOT NULL,
  platform TEXT NOT NULL, -- 'github', 'instagram', etc.
  platform_id TEXT NOT NULL, -- GitHub ID, Instagram ID, etc.
  platform_username TEXT,
  platform_name TEXT,
  avatar_url TEXT,
  profile_url TEXT,
  access_token TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (native_account_id) REFERENCES native_accounts(id),
  UNIQUE(platform, platform_id)
);

-- Sessions table for native account authentication
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_token TEXT NOT NULL UNIQUE,
  native_account_id INTEGER NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (native_account_id) REFERENCES native_accounts(id)
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_native_accounts_username ON native_accounts(username);
CREATE INDEX IF NOT EXISTS idx_native_accounts_email ON native_accounts(email);
CREATE INDEX IF NOT EXISTS idx_social_accounts_native_id ON social_accounts(native_account_id);
CREATE INDEX IF NOT EXISTS idx_social_accounts_platform ON social_accounts(platform, platform_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_native_account ON sessions(native_account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at); 