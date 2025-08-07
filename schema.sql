-- Native account system
CREATE TABLE IF NOT EXISTS native_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Social media account linking
CREATE TABLE IF NOT EXISTS social_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  native_account_id INTEGER NOT NULL,
  platform TEXT NOT NULL, -- 'github', 'spotify', etc.
  platform_id TEXT NOT NULL,
  platform_username TEXT,
  platform_name TEXT,
  avatar_url TEXT,
  profile_url TEXT,
  access_token TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (native_account_id) REFERENCES native_accounts (id),
  UNIQUE(platform, platform_id)
);

-- Session management
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_token TEXT UNIQUE NOT NULL,
  native_account_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (native_account_id) REFERENCES native_accounts (id)
);

-- Bubble communities
CREATE TABLE IF NOT EXISTS bubbles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  creator_id INTEGER NOT NULL,
  is_public BOOLEAN DEFAULT TRUE,
  invite_code TEXT UNIQUE,
  max_members INTEGER DEFAULT 50,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (creator_id) REFERENCES native_accounts (id)
);

-- Bubble memberships
CREATE TABLE IF NOT EXISTS bubble_memberships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bubble_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  role TEXT DEFAULT 'member', -- 'creator', 'admin', 'member'
  joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (bubble_id) REFERENCES bubbles (id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES native_accounts (id) ON DELETE CASCADE,
  UNIQUE(bubble_id, user_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_social_accounts_native_id ON social_accounts(native_account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_bubble_memberships_bubble ON bubble_memberships(bubble_id);
CREATE INDEX IF NOT EXISTS idx_bubble_memberships_user ON bubble_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_bubbles_creator ON bubbles(creator_id);
CREATE INDEX IF NOT EXISTS idx_bubbles_public ON bubbles(is_public); 