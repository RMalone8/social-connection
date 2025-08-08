export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle privacy policy route
    if (url.pathname === "/privacy") {
      return handlePrivacyPolicy();
    }

    // Handle API routes first
    if (url.pathname.startsWith("/api/")) {
      return handleApiRoutes(request, env, url);
    }

    // For non-API routes, let the assets handler deal with it
    // This will serve the built React app from the dist directory
    return env.ASSETS.fetch(request);
  },
};

let coreSchemaReady = false;
async function ensureCoreSchema(env) {
  if (coreSchemaReady) return;
  try {
    // native_accounts
    await env.DB.exec(
      "CREATE TABLE IF NOT EXISTS native_accounts (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "username TEXT UNIQUE NOT NULL, " +
        "email TEXT UNIQUE NOT NULL, " +
        "password_hash TEXT NOT NULL, " +
        "display_name TEXT, " +
        "avatar_url TEXT, " +
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP" +
      ")"
    );
    // social_accounts
    await env.DB.exec(
      "CREATE TABLE IF NOT EXISTS social_accounts (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "native_account_id INTEGER NOT NULL, " +
        "platform TEXT NOT NULL, " +
        "platform_id TEXT NOT NULL, " +
        "platform_username TEXT, " +
        "platform_name TEXT, " +
        "avatar_url TEXT, " +
        "profile_url TEXT, " +
        "access_token TEXT, " +
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP, " +
        "updated_at TEXT DEFAULT CURRENT_TIMESTAMP, " +
        "FOREIGN KEY (native_account_id) REFERENCES native_accounts (id), " +
        "UNIQUE(platform, platform_id)" +
      ")"
    );
    // sessions
    await env.DB.exec(
      "CREATE TABLE IF NOT EXISTS sessions (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "session_token TEXT UNIQUE NOT NULL, " +
        "native_account_id INTEGER NOT NULL, " +
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP, " +
        "expires_at TEXT NOT NULL, " +
        "FOREIGN KEY (native_account_id) REFERENCES native_accounts (id)" +
      ")"
    );
    // bubbles
    await env.DB.exec(
      "CREATE TABLE IF NOT EXISTS bubbles (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "name TEXT NOT NULL, " +
        "description TEXT, " +
        "creator_id INTEGER NOT NULL, " +
        "is_public INTEGER DEFAULT 1, " +
        "invite_code TEXT UNIQUE, " +
        "max_members INTEGER DEFAULT 50, " +
        "created_at TEXT DEFAULT CURRENT_TIMESTAMP, " +
        "updated_at TEXT DEFAULT CURRENT_TIMESTAMP, " +
        "FOREIGN KEY (creator_id) REFERENCES native_accounts (id)" +
      ")"
    );
    // bubble_memberships
    await env.DB.exec(
      "CREATE TABLE IF NOT EXISTS bubble_memberships (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
        "bubble_id INTEGER NOT NULL, " +
        "user_id INTEGER NOT NULL, " +
        "role TEXT DEFAULT 'member', " +
        "joined_at TEXT DEFAULT CURRENT_TIMESTAMP, " +
        "FOREIGN KEY (bubble_id) REFERENCES bubbles (id) ON DELETE CASCADE, " +
        "FOREIGN KEY (user_id) REFERENCES native_accounts (id) ON DELETE CASCADE, " +
        "UNIQUE(bubble_id, user_id)" +
      ")"
    );
    coreSchemaReady = true;
  } catch (e) {
    console.error('Schema ensure error:', e);
  }
}

async function handleApiRoutes(request, env, url) {
  // Native account authentication
  if (url.pathname === "/api/auth/register") {
    return handleRegister(request, env);
  }

  if (url.pathname === "/api/auth/login") {
    return handleLogin(request, env);
  }

  if (url.pathname === "/api/auth/logout") {
    return handleLogout(request, env);
  }

  // Admin-only routes
  if (url.pathname === "/api/admin/bubbles" && request.method === "GET") {
    return handleAdminGetAllBubbles(request, env);
  }

  if (url.pathname === "/api/admin/users" && request.method === "GET") {
    return handleAdminGetAllUsers(request, env);
  }

  if (url.pathname === "/api/admin/stats" && request.method === "GET") {
    return handleAdminGetStats(request, env);
  }

  // Social media linking (requires native login first)
  if (url.pathname === "/api/link/github") {
    return handleGitHubLink(request, env);
  }

  if (url.pathname === "/api/link/github/callback") {
    return handleGitHubLinkCallback(request, env);
  }

  if (url.pathname === "/api/link/spotify") {
    return handleSpotifyLink(request, env);
  }

  if (url.pathname === "/api/link/spotify/logout") {
    return handleSpotifyLogout(request, env);
  }

  if (url.pathname === "/api/link/spotify/callback") {
    return handleSpotifyLinkCallback(request, env);
  }

  if (url.pathname === "/api/link/spotify/success") {
    return handleSpotifySuccess(request, env);
  }

  if (url.pathname === "/api/user") {
    return handleUserInfo(request, env);
  }

  if (url.pathname === "/api/user/delete" && request.method === "DELETE") {
    return handleDeleteAccount(request, env);
  }

  if (url.pathname === "/api/users/all") {
    return handleGetAllUsers(request, env);
  }

  // Bubble management routes
  if (url.pathname === "/api/bubbles" && request.method === "GET") {
    return handleGetUserBubbles(request, env);
  }

  if (url.pathname === "/api/bubbles" && request.method === "POST") {
    return handleCreateBubble(request, env);
  }

  if (url.pathname.startsWith("/api/bubbles/") && url.pathname.endsWith("/join") && request.method === "POST") {
    return handleJoinBubble(request, env);
  }

  if (url.pathname.startsWith("/api/bubbles/") && url.pathname.endsWith("/leave") && request.method === "POST") {
    return handleLeaveBubble(request, env);
  }

  if (url.pathname.startsWith("/api/bubbles/") && url.pathname.endsWith("/delete") && request.method === "DELETE") {
    return handleDeleteBubble(request, env);
  }

  if (url.pathname.startsWith("/api/bubbles/") && url.pathname.endsWith("/members") && request.method === "GET") {
    return handleGetBubbleMembers(request, env);
  }

  if (url.pathname === "/api/bubbles/public" && request.method === "GET") {
    return handleGetPublicBubbles(request, env);
  }

  if (url.pathname.startsWith("/api/bubbles/") && url.pathname.endsWith("/kick") && request.method === "POST") {
    return handleKickMember(request, env);
  }

  if (url.pathname.startsWith("/api/bubbles/") && url.pathname.endsWith("/promote") && request.method === "POST") {
    return handlePromoteMember(request, env);
  }

  if (url.pathname === "/api/followers") {
    return listFollowers(request, env);
  }

  if (url.pathname === "/api/session") {
    return handleSession(request, env);
  }

  if (url.pathname === "/api/github/follow") {
    return handleGithubFollow(request, env);
  }

  if (url.pathname === "/api/github/get-followers") {
    return getGithubFollowers(request, env);
  }

  if (url.pathname === "/api/github/follow-everyone") {
    return followEveryoneOnGithub(request, env);
  }

  if (url.pathname === "/api/spotify/follow-everyone") {
    return followEveryoneOnSpotify(request, env);
  }

  if (url.pathname === "/api/spotify/get-followers") {
    return getSpotifyFollowers(request, env);
  }

  if (url.pathname === "/api/link/github/unlink" && request.method === 'POST') {
    return handleGitHubUnlink(request, env);
  }

  if (url.pathname === "/api/auth/request-password-reset" && request.method === 'POST') {
    return handlePasswordResetRequest(request, env);
  }

  if (url.pathname === "/api/auth/reset-password" && request.method === 'POST') {
    return handlePasswordResetSubmit(request, env);
  }

  if (url.pathname === "/api/user/profile" && (request.method === 'POST' || request.method === 'PATCH')) {
    return handleUpdateProfile(request, env);
  }

  return new Response(null, { status: 404 });
}

// Password hashing utilities (PBKDF2 with per-user salt)
const PASSWORD_SCHEME_PREFIX = 'pbkdf2';
const PBKDF2_ITERATIONS = 60000; // Tuned for Workers CPU budget; increase if stable
const PBKDF2_KEYLEN_BYTES = 32;   // 256-bit

function toBase64(bytes) {
  let binary = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.byteLength; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary);
}

function fromBase64(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function hashPasswordPBKDF2(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    keyMaterial,
    PBKDF2_KEYLEN_BYTES * 8
  );
  const saltB64 = toBase64(salt);
  const hashB64 = toBase64(derivedBits);
  // Format: pbkdf2$iterations$salt$hash
  return `${PASSWORD_SCHEME_PREFIX}$${PBKDF2_ITERATIONS}$${saltB64}$${hashB64}`;
}

async function verifyPasswordFlexible(password, stored) {
  // New PBKDF2 format
  if (stored && stored.startsWith(`${PASSWORD_SCHEME_PREFIX}$`)) {
    const parts = stored.split('$');
    if (parts.length !== 4) return false;
    const iterations = parseInt(parts[1], 10);
    const salt = new Uint8Array(fromBase64(parts[2]));
    const expectedB64 = parts[3];

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      keyMaterial,
      PBKDF2_KEYLEN_BYTES * 8
    );
    const actualB64 = toBase64(derivedBits);
    return actualB64 === expectedB64;
  }

  // Legacy SHA-256 hex fallback
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  const normalizedStored = (stored || '').trim().toLowerCase();
  if (hex === normalizedStored) return true;

  // Worst-case legacy: stored as plaintext; allow once for migration
  if ((stored || '').trim() === password) return true;
  return false;
}

// Database helper functions
async function createNativeAccount(env, username, email, password, display_name) {
  const passwordHash = await hashPasswordPBKDF2(password);
  
  const result = await env.DB.prepare(`
    INSERT INTO native_accounts (username, email, password_hash, display_name)
    VALUES (?, ?, ?, ?)
  `).bind(username, email, passwordHash, display_name).run();

  return await env.DB.prepare(
    "SELECT id, username, email, display_name, created_at FROM native_accounts WHERE id = ?"
  ).bind(result.meta.last_row_id).first();
}

async function getNativeAccountByUsername(env, username) {
  return await env.DB.prepare(
    "SELECT * FROM native_accounts WHERE username = ?"
  ).bind(username).first();
}

async function getNativeAccountByUsernameOrEmail(env, identifier) {
  return await env.DB.prepare(
    "SELECT * FROM native_accounts WHERE username = ? OR email = ?"
  ).bind(identifier, identifier).first();
}

async function linkSocialAccount(env, nativeAccountId, platform, platformData, accessToken) {
  console.log('Linking social account:', { platform, platformData, nativeAccountId });
  
  // Helper function to handle undefined values
  const safeValue = (value) => value || null;
  
  // Check if this social account is already linked
  const existing = await env.DB.prepare(
    "SELECT * FROM social_accounts WHERE platform = ? AND platform_id = ?"
  ).bind(platform, platformData.id.toString()).first();

  if (existing) {
    // Check if this social account is already linked to a different native account
    if (existing.native_account_id !== nativeAccountId) {
      console.log(`Social account ${platform}:${platformData.id} already linked to different native account ${existing.native_account_id}, current user is ${nativeAccountId}`);
      throw new Error(`This ${platform} account is already linked to a different Bubbly account. Please use a different ${platform} account or contact support.`);
    }
    
    // Update existing social account (same user, just refreshing tokens/info)
    await env.DB.prepare(`
      UPDATE social_accounts 
      SET platform_username = ?, platform_name = ?, 
          avatar_url = ?, profile_url = ?, access_token = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      safeValue(platformData.login || platformData.username),
      safeValue(platformData.name || platformData.full_name),
      safeValue(platformData.avatar_url),
      safeValue(platformData.html_url || platformData.profile_url),
      safeValue(accessToken),
      existing.id
    ).run();
    
    return existing;
  } else {
    // Create new social account link
    const result = await env.DB.prepare(`
      INSERT INTO social_accounts (native_account_id, platform, platform_id, platform_username, 
                                 platform_name, avatar_url, profile_url, access_token)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      nativeAccountId,
      platform,
      platformData.id.toString(),
      safeValue(platformData.login || platformData.username),
      safeValue(platformData.name || platformData.full_name),
      safeValue(platformData.avatar_url),
      safeValue(platformData.html_url || platformData.profile_url),
      safeValue(accessToken)
    ).run();

    return await env.DB.prepare(
      "SELECT * FROM social_accounts WHERE id = ?"
    ).bind(result.meta.last_row_id).first();
  }
}

async function createSession(env, nativeAccountId) {
  const sessionToken = generateSessionToken();
  const expiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

  // Delete any existing sessions for this user (single session per user)
  await env.DB.prepare(
    "DELETE FROM sessions WHERE native_account_id = ?"
  ).bind(nativeAccountId).run();

  // Create new session
  await env.DB.prepare(`
    INSERT INTO sessions (session_token, native_account_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(sessionToken, nativeAccountId, expiresAt.toISOString()).run();

  return sessionToken;
}

async function getSessionUser(env, sessionToken) {
  if (!sessionToken) return null;

  const result = await env.DB.prepare(`
    SELECT s.*, n.id as account_id, n.username, n.email, n.display_name, n.avatar_url, n.role
    FROM sessions s
    JOIN native_accounts n ON s.native_account_id = n.id
    WHERE s.session_token = ? AND s.expires_at > datetime('now')
  `).bind(sessionToken).first();

  if (!result) return null;

  // Get linked social accounts
  const socialAccounts = await env.DB.prepare(`
    SELECT platform, platform_username, platform_name, avatar_url, profile_url, access_token
    FROM social_accounts 
    WHERE native_account_id = ?
  `).bind(result.account_id).all();

  return {
    ...result,
    social_accounts: socialAccounts.results || []
  };
}

async function deleteSession(env, sessionToken) {
  if (!sessionToken) return;

  await env.DB.prepare(
    "DELETE FROM sessions WHERE session_token = ?"
  ).bind(sessionToken).run();
}

// Generate a random state parameter for OAuth security
function generateState() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Generate session token
function generateSessionToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Basic server-side email validation
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length === 0 || trimmed.length > 254) return false;
  // Simple pragmatic regex; avoids catastrophic backtracking
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(trimmed);
}

// Handle native account registration
async function handleRegister(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const requestData = await request.json();
    console.log('Registration attempt with data:', requestData);
    
    const { username, email, password, display_name } = requestData;

    if (!username || !email || !password) {
      console.log('Registration failed: Missing required fields', { username, email, password: !!password, display_name });
      return new Response(JSON.stringify({ error: 'Username, email, and password are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Normalize and validate email
    const normalizedEmail = String(email).trim().toLowerCase();
    if (!isValidEmail(normalizedEmail)) {
      return new Response(JSON.stringify({ error: 'Invalid email address' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if username or email already exists
    const existingUser = await env.DB.prepare(
      "SELECT id FROM native_accounts WHERE username = ? OR email = ?"
    ).bind(username, normalizedEmail).first();

    if (existingUser) {
      console.log('Registration failed: Username or email already exists', { username, email });
      return new Response(JSON.stringify({ error: 'Username or email already exists' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Create new account
    console.log('Creating new account for:', { username, email: normalizedEmail, display_name });
    const newAccount = await createNativeAccount(env, username, normalizedEmail, password, display_name?.trim?.() || null);
    console.log('Account created successfully:', newAccount);
    
    // Create session
    const sessionToken = await createSession(env, newAccount.id);
    console.log('Session created for new account');

    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    headers.append('Set-Cookie', `session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${7 * 24 * 60 * 60}`);

    return new Response(JSON.stringify({
      success: true,
      user: {
        id: newAccount.id,
        username: newAccount.username,
        email: newAccount.email,
        display_name: newAccount.display_name
      }
    }), { status: 201, headers });

  } catch (error) {
    console.error('Registration error:', error);
    return new Response(JSON.stringify({ error: 'Registration failed', details: String(error?.message || error) }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Handle native account login
async function handleLogin(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return new Response(JSON.stringify({ error: 'Username and password are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Get user account
    const account = await getNativeAccountByUsernameOrEmail(env, username);
    if (!account) {
      return new Response(JSON.stringify({ error: 'Invalid username or password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify password (supports legacy SHA-256 and PBKDF2)
    const isValidPassword = await verifyPasswordFlexible(password, account.password_hash);
    if (!isValidPassword) {
      return new Response(JSON.stringify({ error: 'Invalid username or password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Upgrade legacy hashes to PBKDF2 on successful login
    if (!account.password_hash?.startsWith(`${PASSWORD_SCHEME_PREFIX}$`)) {
      try {
        const newHash = await hashPasswordPBKDF2(password);
        await env.DB.prepare('UPDATE native_accounts SET password_hash = ? WHERE id = ?')
          .bind(newHash, account.id)
          .run();
      } catch (e) {
        console.warn('Password rehash (upgrade) failed:', e);
      }
    }

    // Create session
    const sessionToken = await createSession(env, account.id);

    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    headers.append('Set-Cookie', `session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${7 * 24 * 60 * 60}`);

    return new Response(JSON.stringify({
      success: true,
      user: {
        username: account.username,
        email: account.email,
        displayName: account.display_name
      }
    }), { status: 200, headers });

  } catch (error) {
    console.error('Login error:', error);
    return new Response(JSON.stringify({ error: 'Login failed' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Handle GitHub account linking
function handleGitHubLink(request, env) {
  const state = generateState();
  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: env.GITHUB_REDIRECT_URI,
    scope: 'user:email, user:follow',
    state: state,
    allow_signup: 'true',
    // Add timestamp to bust GitHub's OAuth cache and force fresh auth
    t: Date.now().toString()
  });

  const authUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
  
  // Create redirect response with headers included from the start
  const headers = new Headers();
  headers.set('Location', authUrl);
  headers.append('Set-Cookie', `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`);
  
  return new Response(null, {
    status: 302,
    headers: headers
  });
}

// Handle GitHub account linking callback
async function handleGitHubLinkCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  if (!code || !state) {
    return new Response('Missing code or state parameter', { status: 400 });
  }

  // Verify state parameter
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  if (cookies.oauth_state !== state) {
    return new Response('Invalid state parameter', { status: 400 });
  }

  // Check if user is logged in to native account
  const sessionUser = await getSessionUser(env, cookies.session);
  if (!sessionUser) {
    return new Response('Must be logged in to link accounts', { status: 401 });
  }

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code: code,
      }),
    });

    const tokenData = await tokenResponse.json();
    
    if (!tokenData.access_token) {
      throw new Error('Failed to get access token');
    }

    // Get user info from GitHub
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'User-Agent': 'Social-Connection-App',
      },
    });

    const userData = await userResponse.json();

    // Link GitHub account to native account
    await linkSocialAccount(env, sessionUser.account_id, 'github', userData, tokenData.access_token);

    // Redirect back to the main page with success indicator
    const redirectUrl = new URL('/', request.url);
    redirectUrl.searchParams.set('linked', 'github');
    
    const headers = new Headers();
    headers.set('Location', redirectUrl.toString());
    headers.append('Set-Cookie', `oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`); // Clear state cookie
    
    return new Response(null, {
      status: 302,
      headers: headers
    });
  } catch (error) {
    console.error('GitHub linking error:', error);
    return new Response('GitHub linking failed', { status: 500 });
  }
}

// Handle Spotify account linking  
function handleSpotifyLink(request, env) {
  const state = generateState();
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: env.SPOTIFY_CLIENT_ID,
    redirect_uri: env.SPOTIFY_REDIRECT_URI,
    scope: 'user-read-private user-read-email user-follow-modify user-follow-read',
    state: state,
    show_dialog: 'true', // Force Spotify to show login dialog even if user is logged in
  });

  console.log('Spotify OAuth params:', params.toString())
  console.log('Spotify Client ID:', env.SPOTIFY_CLIENT_ID)
  console.log('Spotify Redirect URI:', env.SPOTIFY_REDIRECT_URI)

  const authUrl = `https://accounts.spotify.com/authorize?${params.toString()}`;
  console.log('Full Spotify auth URL:', authUrl)

  // Redirect directly to Spotify auth (logout happens after successful linking)
  const headers = new Headers();
  headers.set('Location', authUrl);
  headers.append('Set-Cookie', `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`);

  return new Response(null, {
    status: 302,
    headers: headers
  });
}

// Handle Spotify logout intermediate page
function handleSpotifyLogout(request, env) {
  const url = new URL(request.url);
  const authUrl = url.searchParams.get('auth_url');
  const state = url.searchParams.get('state');
  
  if (!authUrl || !state) {
    return new Response('Missing parameters', { status: 400 });
  }

  // Create an HTML page that logs out of Spotify then redirects
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Linking Spotify Account...</title>
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }
        .container {
          text-align: center;
          padding: 2rem;
          background: rgba(255, 255, 255, 0.1);
          border-radius: 20px;
          backdrop-filter: blur(10px);
        }
        .spinner {
          width: 40px;
          height: 40px;
          border: 4px solid rgba(255, 255, 255, 0.3);
          border-top: 4px solid white;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin: 0 auto 1rem;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="spinner"></div>
        <h2>🎵 Preparing Spotify Connection</h2>
        <p>Please wait while we prepare a fresh login...</p>
      </div>
      
      <script>
        // First, try to logout from Spotify by loading logout URL in hidden iframe
        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.src = 'https://accounts.spotify.com/logout';
        document.body.appendChild(iframe);
        
        // Wait a moment for logout, then redirect to auth
        setTimeout(() => {
          window.location.href = '${authUrl}';
        }, 2000);
      </script>
    </body>
    </html>
  `;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Handle Spotify account linking callback
async function handleSpotifyLinkCallback(request, env) {
  console.log('=== Spotify Callback Hit ===')
  console.log('Full callback URL:', request.url)
  
  const url = new URL(request.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');
    const errorDescription = url.searchParams.get('error_description');

    console.log('Callback params:', { code, state, error, errorDescription })
    
    if (!code || !state) {
      console.log('Missing code or state parameter');
      return new Response('Missing code or state parameter', { status: 400 });
    }

    // Verify state parameter
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    console.log('Cookies received:', cookies);
    
    if (cookies.oauth_state !== state) {
      console.log('State parameter mismatch:', { received: state, expected: cookies.oauth_state });
      return new Response('Invalid state parameter', { status: 400 });
    }

    // Check if user is logged in to native account
    console.log('Checking session user...');
    const sessionUser = await getSessionUser(env, cookies.session);
    console.log('Session user result:', sessionUser);
    
    if (!sessionUser) {
      console.log('No session user found, returning 401');
      return new Response('Must be logged in to link accounts', { status: 401 });
    }

  try {
    console.log('Exchanging code for Spotify token...')
    
    // Create base64 encoded credentials for Spotify
    const credentials = btoa(`${env.SPOTIFY_CLIENT_ID}:${env.SPOTIFY_CLIENT_SECRET}`);
    console.log('Spotify credentials created for client ID:', env.SPOTIFY_CLIENT_ID);
    
    const tokenResponse = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${credentials}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: env.SPOTIFY_REDIRECT_URI,
      }),
    });

    const tokenData = await tokenResponse.json();
    console.log('Spotify token response:', tokenData);

    if (!tokenData.access_token) {
      console.error('No access token in Spotify response:', tokenData);
      throw new Error('Failed to get access token: ' + JSON.stringify(tokenData));
    }

    console.log('Getting user info from Spotify...')
    // Get user info from Spotify
    const userResponse = await fetch('https://api.spotify.com/v1/me', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
      },
    });
    const userData = await userResponse.json();
    console.log('Spotify user data:', userData);

    // Transform Spotify data to match our expected format
    const transformedData = {
      id: userData.id,
      name: userData.display_name || userData.id,
      login: userData.id,
      avatar_url: userData.images && userData.images.length > 0 ? userData.images[0].url : null
    };

    console.log('Linking Spotify account to native account...')
    // Link Spotify account to native account
    await linkSocialAccount(env, sessionUser.account_id, 'spotify', transformedData, tokenData.access_token);
    console.log('Spotify account linked successfully!')

    // Redirect to intermediate success page that clears Spotify session
    const successUrl = new URL('/api/link/spotify/success', request.url);
    successUrl.searchParams.set('linked', 'spotify');
    
    const headers = new Headers();
    headers.set('Location', successUrl.toString());
    headers.append('Set-Cookie', `oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`); // Clear state cookie
    
    return new Response(null, {
      status: 302,
      headers: headers
    });
  } catch (error) {
    console.error('Spotify linking error:', error);
    console.error('Error stack:', error.stack);
    
    // Create an error page with more details
    const errorHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Spotify Linking Failed</title>
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
          }
          .container {
            text-align: center;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            max-width: 500px;
          }
          .error-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
          }
          .btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 2px solid white;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            margin-top: 1rem;
            transition: all 0.3s ease;
          }
          .btn:hover {
            background: white;
            color: #ff6b6b;
          }
          .error-details {
            background: rgba(0, 0, 0, 0.3);
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
            font-family: monospace;
            font-size: 0.8rem;
            text-align: left;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="error-icon">❌</div>
          <h2>🎵 Spotify Linking Failed</h2>
          <p>There was an error connecting your Spotify account.</p>
          <div class="error-details">
            Error: ${error.message || 'Unknown error'}
          </div>
          <button class="btn" onclick="window.location.href='/'">Return to Bubbly</button>
        </div>
      </body>
      </html>
    `;
    
    return new Response(errorHtml, { 
      status: 500,
      headers: { 'Content-Type': 'text/html' }
    });
  }
}

// Handle Spotify success page that clears Spotify session for next user
function handleSpotifySuccess(request, env) {
  const url = new URL(request.url);
  const linked = url.searchParams.get('linked');
  
  // Create an HTML page that shows success and clears Spotify session
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Spotify Linked Successfully!</title>
      <style>
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #1DB954 0%, #1ed760 100%);
          color: white;
        }
        .container {
          text-align: center;
          padding: 2rem;
          background: rgba(255, 255, 255, 0.1);
          border-radius: 20px;
          backdrop-filter: blur(10px);
          max-width: 400px;
        }
        .success-icon {
          font-size: 4rem;
          margin-bottom: 1rem;
        }
        .btn {
          background: rgba(255, 255, 255, 0.2);
          color: white;
          border: 2px solid white;
          padding: 12px 24px;
          border-radius: 25px;
          cursor: pointer;
          font-size: 1rem;
          font-weight: 600;
          margin-top: 1rem;
          transition: all 0.3s ease;
        }
        .btn:hover {
          background: white;
          color: #1DB954;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="success-icon">🎉</div>
        <h2>🎵 Spotify Linked Successfully!</h2>
        <p>Your Spotify account has been connected to your Bubbly profile.</p>
        <button class="btn" onclick="goHome()">Return to Bubbly</button>
      </div>
      
      <!-- Hidden logout iframe to clear Spotify session for next user -->
      <iframe id="logout-frame" style="display: none;" src="https://accounts.spotify.com/logout"></iframe>
      
      <script>
        function goHome() {
          // Add the success parameter for the frontend to show success message
          window.location.href = '/?linked=${linked}';
        }
        
        // Auto-redirect after 3 seconds if user doesn't click
        setTimeout(goHome, 3000);
      </script>
    </body>
    </html>
  `;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// Handle user info request
async function handleUserInfo(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;

  const sessionUser = await getSessionUser(env, sessionToken);
  
  if (!sessionUser) {
    return new Response('Not authenticated', { status: 401 });
  }

  // Return user data with linked social accounts
  return Response.json({
    id: sessionUser.account_id,
    username: sessionUser.username,
    email: sessionUser.email,
    display_name: sessionUser.display_name,
    avatar_url: sessionUser.avatar_url || null,
    role: sessionUser.role || 'user',
    social_accounts: sessionUser.social_accounts.map(account => ({
      platform: account.platform,
      platform_username: account.platform_username,
      platform_name: account.platform_name,
      avatar_url: account.avatar_url,
      profile_url: account.profile_url
    }))
  });
}

// Handle get all users for bubble display
async function handleGetAllUsers(request, env) {
  try {
    const users = await env.DB.prepare(`
      SELECT 
        na.id,
        na.username,
        na.display_name,
        sa.platform,
        sa.platform_username,
        sa.avatar_url
      FROM native_accounts na
      LEFT JOIN social_accounts sa ON na.id = sa.native_account_id
      ORDER BY na.created_at DESC
    `).all();

    // Group social accounts by user
    const userMap = new Map();
    
    users.results.forEach(row => {
      if (!userMap.has(row.id)) {
        userMap.set(row.id, {
          id: row.id,
          username: row.username,
          display_name: row.display_name,
          social_accounts: []
        });
      }
      
      if (row.platform) {
        userMap.get(row.id).social_accounts.push({
          platform: row.platform,
          platform_username: row.platform_username,
          avatar_url: row.avatar_url
        });
      }
    });

    const allUsers = Array.from(userMap.values());
    
    return new Response(JSON.stringify(allUsers), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error getting all users:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Handle logout - Keep tokens but clear browser session
async function handleLogout(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;

  // Don't delete session from database - keep the GitHub token!
  // Just clear the browser cookie so user appears "logged out"
  console.log(`User logged out but keeping their GitHub token for offline use`);

  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
    }
  });
}

async function handleSession(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;

  const sessionUser = await getSessionUser(env, sessionToken);
  
  return Response.json({
    authenticated: !!sessionUser,
    user: sessionUser ? {
      id: sessionUser.github_id,
      login: sessionUser.login,
      name: sessionUser.name
    } : null
  });
}

async function listFollowers(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;

  //console.log("sessionToken", sessionToken) 

  if (!sessionToken) {
    return new Response('Not authenticated', { status: 401 });
  }

  try {
    const sessionUser = await getSessionUser(env, sessionToken);
    
    if (!sessionUser) {
      return new Response('Invalid session', { status: 401 });
    }

    //console.log("sessionData", sessionUser)

    const followers = await fetch(`https://api.github.com/user/followers`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${sessionUser.github_token}`,
        'User-Agent': 'Social-Connection-App',
      },
    });

    const followersData = await followers.json();

    //console.log("followersData", followersData)

    return new Response(JSON.stringify({ followers: followersData }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      }
    });
  } catch (error) {
    console.error('Error in listFollowers:', error);
    return new Response('Invalid session', { status: 401 });
  }
}

async function handleGithubFollow(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;

  if (!sessionToken) {
    return new Response('Not authenticated', { status: 401 });
  }

  try {
    const sessionUser = await getSessionUser(env, sessionToken);
    
    if (!sessionUser) {
      return new Response('Invalid session', { status: 401 });
    }

    // Get all users with tokens (including offline users)
    const usersWithTokens = await env.DB.prepare(`
      SELECT s.*, u.login as github_login, u.github_id 
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE u.github_id != ? AND s.github_token IS NOT NULL AND s.github_token != ''
    `).bind(sessionUser.github_id).all();

    console.log(`Found ${usersWithTokens.results.length} users with tokens to follow (including offline users)`);

    const followResults = [];

    // Follow each user with token
    for (const session of usersWithTokens.results) {
      try {
        console.log(`Attempting to follow: ${session.github_login}`);
        
        const followResponse = await fetch(`https://api.github.com/user/following/${session.github_login}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${sessionUser.github_token}`,
            'User-Agent': 'Social-Connection-App',
            'Content-Length': '0',
          },
        });

        const result = {
          username: session.github_login,
          status: followResponse.status,
          success: followResponse.status === 204
        };

        followResults.push(result);
        console.log(`Follow result for ${session.github_login}:`, result);

      } catch (error) {
        console.error(`Error following ${session.github_login}:`, error);
        followResults.push({
          username: session.github_login,
          error: error.message,
          success: false
        });
      }
    }

    console.log("All follow attempts completed:", followResults);

    return new Response(JSON.stringify({ 
      message: "Follow attempts completed",
      results: followResults,
      total_attempts: followResults.length,
      successful: followResults.filter(r => r.success).length
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      }
    });
  } catch (error) {
    console.error('Error in handleFollow:', error);
    return new Response(JSON.stringify({ error: error.message }), { 
      status: 500,
      headers: {
        'Content-Type': 'application/json',
      }
    });
  }
}

async function getGithubFollowers(request, env) {
  console.log('=== Making Everyone Follow Me (Multi-Platform) ===');
  
  try {
    // Get current user
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    // Expect bubbleId to scope the operation
    const { bubbleId } = await request.json().catch(() => ({ }));
    if (!bubbleId) {
      return Response.json({ error: 'bubbleId is required' }, { status: 400 });
    }

    // Get current user's social accounts to know who they are on each platform
    const currentUserAccounts = sessionUser.social_accounts || [];
    const currentGitHub = currentUserAccounts.find(acc => acc.platform === 'github');
    if (!currentGitHub) {
      return new Response('No GitHub account linked', { status: 400 });
    }

    // Get other bubble members' GitHub tokens (excluding current user)
    const otherAccounts = await env.DB.prepare(`
      SELECT sa.access_token, sa.platform, sa.platform_username, na.username as native_username
      FROM social_accounts sa
      JOIN native_accounts na ON sa.native_account_id = na.id
      JOIN bubble_memberships bm ON bm.user_id = na.id
      WHERE sa.platform = 'github' AND sa.access_token IS NOT NULL AND na.id != ? AND bm.bubble_id = ?
    `).bind(sessionUser.account_id, bubbleId).all();

    console.log(`Found ${otherAccounts.results.length} social accounts to make follow you`);

    const followResults = [];

    for (const account of otherAccounts.results) {
      try {
        console.log(`Making GitHub user ${account.platform_username} follow ${currentGitHub.platform_username}...`);

        const followResponse = await fetch(`https://api.github.com/user/following/${currentGitHub.platform_username}`, {
          method: 'PUT',
          headers: {
            'Authorization': `token ${account.access_token}`,
            'User-Agent': 'Bubbly-Social-App',
            'Accept': 'application/vnd.github.v3+json'
          }
        });

        followResults.push({
          platform: 'github',
          follower: account.platform_username,
          target: currentGitHub.platform_username,
          status: followResponse.status,
          success: followResponse.status === 204
        });

      } catch (error) {
        console.error(`Error making ${account.platform_username} follow on ${account.platform}:`, error);
        followResults.push({
          platform: account.platform,
          follower: account.platform_username,
          error: error.message,
          success: false
        });
      }
    }

    console.log("All follow attempts completed:", followResults);

    const successful = followResults.filter(r => r.success).length;
    return Response.json({ 
      message: `Made ${successful}/${followResults.length} members follow you on GitHub`,
      results: followResults,
      total_attempts: followResults.length,
      successful: successful
    });

  } catch (error) {
    console.error('Error in getGithubFollowers:', error);
    return new Response('Failed to make everyone follow you', { status: 500 });
  }
}

// Make current user follow everyone else on all platforms
async function followEveryoneOnGithub(request, env) {
  console.log('=== Following Everyone (Multi-Platform) ===');
  
  try {
    // Get current user
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    // Get current user's social accounts
    const currentUserAccounts = sessionUser.social_accounts || [];
    const currentGitHub = currentUserAccounts.find(acc => acc.platform === 'github');
    if (!currentGitHub) {
      return new Response('No GitHub account linked', { status: 400 });
    }

    // Expect bubbleId to scope the operation
    const { bubbleId } = await request.json().catch(() => ({ }));
    if (!bubbleId) {
      return Response.json({ error: 'bubbleId is required' }, { status: 400 });
    }

    // Get other members' GitHub usernames (excluding current user)
    const otherAccounts = await env.DB.prepare(`
      SELECT sa.platform, sa.platform_username
      FROM social_accounts sa
      JOIN native_accounts na ON sa.native_account_id = na.id
      JOIN bubble_memberships bm ON bm.user_id = na.id
      WHERE sa.platform = 'github' AND na.id != ? AND sa.platform_username IS NOT NULL AND bm.bubble_id = ?
    `).bind(sessionUser.account_id, bubbleId).all();

    console.log(`Found ${otherAccounts.results.length} other social accounts to follow`);

    const followResults = [];

    for (const account of otherAccounts.results) {
      try {
        console.log(`Following GitHub user ${account.platform_username}...`);

        const followResponse = await fetch(`https://api.github.com/user/following/${account.platform_username}`, {
          method: 'PUT',
          headers: {
            'Authorization': `token ${currentGitHub.access_token}`,
            'User-Agent': 'Bubbly-Social-App',
            'Accept': 'application/vnd.github.v3+json'
          }
        });

        followResults.push({
          platform: 'github',
          target: account.platform_username,
          status: followResponse.status,
          success: followResponse.status === 204
        });

      } catch (error) {
        console.error(`Error following ${account.platform_username} on ${account.platform}:`, error);
        followResults.push({
          platform: account.platform,
          target: account.platform_username,
          error: error.message,
          success: false
        });
      }
    }

    const successful = followResults.filter(r => r.success).length;
    return Response.json({
      message: `You are now following ${successful}/${followResults.length} members on GitHub`,
      results: followResults,
      total_attempts: followResults.length,
      successful: successful
    });

  } catch (error) {
    console.error('Error in followEveryoneOnGithub:', error);
    return new Response('Failed to follow everyone', { status: 500 });
  }
}

async function getSpotifyFollowers(request, env) {
  console.log('=== Making Everyone Follow Me (Spotify) ===');
  
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    // Get current user's Spotify account
    const currentSpotify = sessionUser.social_accounts?.find(acc => acc.platform === 'spotify');
    
    if (!currentSpotify || !currentSpotify.access_token) {
      return Response.json({ 
        error: 'No Spotify account linked',
        message: 'You need to link your Spotify account first'
      }, { status: 400 });
    }

    // Get ALL other users' social accounts with tokens (excluding current user)
    const otherAccounts = await env.DB.prepare(`
      SELECT sa.access_token, sa.platform, sa.platform_username, na.username as native_username
      FROM social_accounts sa
      JOIN native_accounts na ON sa.native_account_id = na.id
      WHERE sa.access_token IS NOT NULL AND na.id != ?
    `).bind(sessionUser.account_id).all();

    console.log(`Found ${otherAccounts.results.length} social accounts to make follow you`);

    if (otherAccounts.results.length === 0) {
      return Response.json({
        message: 'No other users with linked accounts found',
        results: [],
        total_attempts: 0,
        successful: 0,
        info: 'Other Bubbly users need to link their social accounts first!'
      });
    }

    const followResults = [];

    for (const account of otherAccounts.results) {
      try {
        if (account.platform === 'spotify') {
          console.log(`Making Spotify user ${account.platform_username} follow ${currentSpotify.platform_username}...`);

          const followResponse = await fetch(`https://api.spotify.com/v1/me/following?type=user&ids=${currentSpotify.platform_username}`, {
            method: 'PUT',
            headers: {
              'Authorization': `Bearer ${account.access_token}`,
              'Content-Type': 'application/json'
            }
          });

          const responseText = await followResponse.text();
          console.log(`Follow response:`, followResponse.status, responseText);

          followResults.push({
            platform: 'spotify',
            follower: account.platform_username,
            follower_bubbly_user: account.native_username,
            target: currentSpotify.platform_username,
            status: followResponse.status,
            success: followResponse.status === 204,
            response: responseText
          });
        }

      } catch (error) {
        console.error(`Error making ${account.platform_username} follow on ${account.platform}:`, error);
        followResults.push({
          platform: account.platform,
          follower: account.platform_username,
          follower_bubbly_user: account.native_username,
          error: error.message,
          success: false
        });
      }
    }

    const successful = followResults.filter(r => r.success).length;
    return Response.json({ 
      message: `Made ${successful}/${followResults.length} users follow you across all platforms`,
      results: followResults,
      total_attempts: followResults.length,
      successful: successful,
      platforms: {
        spotify: followResults.filter(r => r.platform === 'spotify').length
      }
    });

  } catch (error) {
    console.error('Error in getSpotifyFollowers:', error);
    return Response.json({ 
      error: 'Failed to make everyone follow you',
      details: error.message 
    }, { status: 500 });
  }
}

async function followEveryoneOnSpotify(request, env) {
  console.log('=== Following Everyone on Spotify ===');

  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);

    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    // Get current user's Spotify token from social_accounts
    const currentSpotify = sessionUser.social_accounts?.find(acc => acc.platform === 'spotify');
    
    if (!currentSpotify || !currentSpotify.access_token) {
      return Response.json({ 
        error: 'No Spotify account linked',
        message: 'You need to link your Spotify account first'
      }, { status: 400 });
    }

    // Get all other users' Spotify accounts (excluding current user)
    const otherAccounts = await env.DB.prepare(`
      SELECT sa.platform, sa.platform_username, na.username as native_username
      FROM social_accounts sa
      JOIN native_accounts na ON sa.native_account_id = na.id
      WHERE na.id != ? AND sa.platform = 'spotify' AND sa.platform_username IS NOT NULL
    `).bind(sessionUser.account_id).all();

    console.log(`Found ${otherAccounts.results.length} other Spotify accounts to follow`);

    if (otherAccounts.results.length === 0) {
      return Response.json({
        message: 'No other Spotify accounts found to follow',
        results: [],
        total_attempts: 0,
        successful: 0,
        info: 'Other Bubbly users need to link their Spotify accounts first!'
      });
    }

    const followResults = [];

    for (const account of otherAccounts.results) {
      try {
        console.log(`Following Spotify user ${account.platform_username}...`);

        const followResponse = await fetch(`https://api.spotify.com/v1/me/following?type=user&ids=${account.platform_username}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${currentSpotify.access_token}`,
            'Content-Type': 'application/json'
          }
        });

        const responseText = await followResponse.text();
        console.log(`Follow response for ${account.platform_username}:`, followResponse.status, responseText);

        followResults.push({
          platform: 'spotify',
          target: account.platform_username,
          bubbly_user: account.native_username,
          status: followResponse.status,
          success: followResponse.status === 204,
          response: responseText
        });

      } catch (error) {
        console.error(`Error following ${account.platform_username} on Spotify:`, error);
        followResults.push({
          platform: 'spotify',
          target: account.platform_username,
          bubbly_user: account.native_username,
          error: error.message,
          success: false
        });
      }
    }

    const successful = followResults.filter(r => r.success).length;
    return Response.json({
      message: `You are now following ${successful}/${followResults.length} users on Spotify`,
      results: followResults,
      total_attempts: followResults.length,
      successful: successful,
    });
    
  } catch (error) {
    console.error('Error in followEveryoneOnSpotify:', error);
    return Response.json({ 
      error: 'Failed to follow everyone',
      details: error.message 
    }, { status: 500 });
  }
}

// Utility function to parse cookies
function parseCookies(cookieHeader) {
  const cookies = {};
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
  }
  return cookies;
}

// Privacy Policy handler
function handlePrivacyPolicy() {
  const privacyPolicyHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - Social Connection</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
            line-height: 1.6;
            color: #333;
        }
        h1 {
            color: #2563eb;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }
        h2 {
            color: #1f2937;
            margin-top: 30px;
        }
        .last-updated {
            color: #6b7280;
            font-style: italic;
            margin-bottom: 30px;
        }
        .contact {
            background: #f9fafb;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <h1>Privacy Policy</h1>
    <p class="last-updated">Last updated: ${new Date().toLocaleDateString()}</p>

    <h2>1. Information We Collect</h2>
    <p>Bubbly collects the following information:</p>
    <ul>
        <li><strong>Account Information:</strong> Username, email address, and display name when you create an account</li>
        <li><strong>Social Media Data:</strong> When you link social media accounts (GitHub, Spotify), we collect your profile information including username, display name, and avatar</li>
        <li><strong>Authentication Tokens:</strong> We securely store access tokens to perform actions on your behalf on linked social media platforms</li>
        <li><strong>Usage Data:</strong> Basic analytics about how you use our service</li>
    </ul>

    <h2>2. How We Use Your Information</h2>
    <p>We use your information to:</p>
    <ul>
        <li>Provide and maintain the Bubbly service</li>
        <li>Authenticate your identity and manage your account</li>
        <li>Connect and manage your linked social media accounts</li>
        <li>Perform social media actions on your behalf (with your explicit consent)</li>
        <li>Improve our service and user experience</li>
    </ul>

    <h2>3. Information Sharing</h2>
    <p>We do not sell, trade, or rent your personal information to third parties. We may share information only in these circumstances:</p>
    <ul>
        <li>With your explicit consent</li>
        <li>To comply with legal obligations</li>
        <li>To protect our rights and prevent fraud</li>
    </ul>

    <h2>4. Data Security</h2>
    <p>We implement appropriate security measures to protect your personal information, including:</p>
    <ul>
        <li>Encrypted data transmission (HTTPS)</li>
        <li>Secure token storage</li>
        <li>Regular security audits</li>
        <li>Access controls and authentication</li>
    </ul>

    <h2>5. Your Rights</h2>
    <p>You have the right to:</p>
    <ul>
        <li>Access your personal data</li>
        <li>Correct inaccurate information</li>
        <li>Delete your account and associated data</li>
        <li>Unlink social media accounts at any time</li>
        <li>Withdraw consent for data processing</li>
    </ul>

    <h2>6. Data Retention</h2>
    <p>We retain your information as long as your account is active. When you delete your account, we will delete your personal information within 30 days, except where required by law.</p>

    <h2>7. Third-Party Services</h2>
    <p>Bubbly integrates with third-party services (GitHub, Spotify). Please review their privacy policies:</p>
    <ul>
        <li><a href="https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement">GitHub Privacy Policy</a></li>
        <li><a href="https://www.spotify.com/us/legal/privacy-policy/">Spotify Privacy Policy</a></li>
    </ul>

    <h2>8. Changes to This Policy</h2>
    <p>We may update this privacy policy from time to time. We will notify you of any changes by posting the new policy on this page with an updated "Last updated" date.</p>

    <div class="contact">
        <h2>9. Contact Us</h2>
        <p>If you have any questions about this Privacy Policy, please contact us at:</p>
        <p><strong>Email:</strong> privacy@socialconnection.app</p>
        <p><strong>Address:</strong> Bubbly Privacy Team</p>
    </div>

    <p style="margin-top: 40px; text-align: center; color: #6b7280;">
        <a href="/" style="color: #2563eb;">← Back to Bubbly</a>
    </p>
</body>
</html>
  `;

  console.log(privacyPolicyHTML)

  return new Response(privacyPolicyHTML, {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'public, max-age=3600' // Cache for 1 hour
    }
  });
}

// Bubble Management Functions

// Get user's bubbles (created and joined)
async function handleGetUserBubbles(request, env) {
  try {
    console.log('=== GET USER BUBBLES DEBUG START ===');
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    console.log('Cookies received:', cookies);
    const sessionUser = await getSessionUser(env, cookies.session);
    console.log('Session user result:', sessionUser);
    
    if (!sessionUser) {
      console.log('No session user - returning 401');
      return new Response('Not authenticated', { status: 401 });
    }

    // Get bubbles the user is a member of
    console.log('Querying user bubbles for account_id:', sessionUser.account_id);
    const bubbles = await env.DB.prepare(`
      SELECT 
        b.id,
        b.name,
        b.description,
        b.is_public,
        b.invite_code,
        b.max_members,
        b.created_at,
        bm.role,
        COUNT(bm2.user_id) as member_count,
        na.display_name as creator_name
      FROM bubbles b
      JOIN bubble_memberships bm ON b.id = bm.bubble_id
      JOIN native_accounts na ON b.creator_id = na.id
      LEFT JOIN bubble_memberships bm2 ON b.id = bm2.bubble_id
      WHERE bm.user_id = ?
      GROUP BY b.id, b.name, b.description, b.is_public, b.invite_code, b.max_members, b.created_at, bm.role, na.display_name
      ORDER BY b.created_at DESC
    `).bind(sessionUser.account_id).all();
    console.log('Bubbles query result:', bubbles);
    console.log('Number of bubbles found:', bubbles.results?.length || 0);

    console.log('=== GET USER BUBBLES SUCCESS ===');
    return Response.json(bubbles.results);
  } catch (error) {
    console.error('=== GET USER BUBBLES ERROR ===');
    console.error('Error getting user bubbles:', error);
    console.error('Error stack:', error.stack);
    console.error('Error message:', error.message);
    return new Response('Server error', { status: 500 });
  }
}

// Create a new bubble
async function handleCreateBubble(request, env) {
  try {
    console.log('=== CREATE BUBBLE DEBUG START ===');
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    console.log('Cookies received:', cookies);
    const sessionUser = await getSessionUser(env, cookies.session);
    console.log('Session user result:', sessionUser);
    
    if (!sessionUser) {
      console.log('No session user - returning 401');
      return new Response('Not authenticated', { status: 401 });
    }

    console.log('Parsing request body...');
    const { name, description, isPublic, maxMembers } = await request.json();
    console.log('Request data:', { name, description, isPublic, maxMembers });
    
    if (!name || name.trim().length === 0) {
      console.log('Invalid name - returning 400');
      return Response.json({ error: 'Bubble name is required' }, { status: 400 });
    }

    // Generate invite code
    const inviteCode = Math.random().toString(36).substring(2, 10).toUpperCase();
    console.log('Generated invite code:', inviteCode);

    // Create bubble
    console.log('Creating bubble in database...');
    console.log('Bubble data to insert:', {
      name: name.trim(),
      description: description?.trim() || null,
      creator_id: sessionUser.account_id,
      is_public: isPublic !== false,
      invite_code: inviteCode,
      max_members: maxMembers || 50
    });
    const bubbleResult = await env.DB.prepare(`
      INSERT INTO bubbles (name, description, creator_id, is_public, invite_code, max_members)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      name.trim(),
      description?.trim() || null,
      sessionUser.account_id,
      isPublic !== false, // Default to true
      inviteCode,
      maxMembers || 50
    ).run();
    console.log('Bubble creation result:', bubbleResult);

    // Add creator as member with creator role
    console.log('Adding creator as member...');
    await env.DB.prepare(`
      INSERT INTO bubble_memberships (bubble_id, user_id, role)
      VALUES (?, ?, 'creator')
    `).bind(bubbleResult.meta.last_row_id, sessionUser.account_id).run();
    console.log('Creator membership added successfully');

    // Return the created bubble
    console.log('Fetching created bubble data...');
    const bubble = await env.DB.prepare(`
      SELECT 
        b.id,
        b.name,
        b.description,
        b.is_public,
        b.invite_code,
        b.max_members,
        b.created_at,
        'creator' as role,
        1 as member_count,
        ? as creator_name
      FROM bubbles b
      WHERE b.id = ?
    `).bind(sessionUser.display_name, bubbleResult.meta.last_row_id).first();
    console.log('Final bubble data:', bubble);

    console.log('=== CREATE BUBBLE SUCCESS ===');
    return Response.json(bubble);
  } catch (error) {
    console.error('=== CREATE BUBBLE ERROR ===');
    console.error('Error creating bubble:', error);
    console.error('Error stack:', error.stack);
    console.error('Error message:', error.message);
    console.error('Error name:', error.name);
    return new Response('Server error', { status: 500 });
  }
}

// Join a bubble by ID or invite code
async function handleJoinBubble(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    const url = new URL(request.url);
    const bubbleId = url.pathname.split('/')[3];
    const { inviteCode } = await request.json();

    let bubble;
    
    if (inviteCode) {
      // Join by invite code
      bubble = await env.DB.prepare(`
        SELECT * FROM bubbles WHERE invite_code = ?
      `).bind(inviteCode).first();
    } else {
      // Join by ID (only if public)
      bubble = await env.DB.prepare(`
        SELECT * FROM bubbles WHERE id = ? AND is_public = TRUE
      `).bind(bubbleId).first();
    }

    if (!bubble) {
      return Response.json({ error: 'Bubble not found or not accessible' }, { status: 404 });
    }

    // Check if already a member
    const existingMembership = await env.DB.prepare(`
      SELECT id FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubble.id, sessionUser.account_id).first();

    if (existingMembership) {
      return Response.json({ error: 'Already a member of this bubble' }, { status: 400 });
    }

    // Check member limit
    const memberCount = await env.DB.prepare(`
      SELECT COUNT(*) as count FROM bubble_memberships WHERE bubble_id = ?
    `).bind(bubble.id).first();

    if (memberCount.count >= bubble.max_members) {
      return Response.json({ error: 'Bubble is full' }, { status: 400 });
    }

    // Add user to bubble
    await env.DB.prepare(`
      INSERT INTO bubble_memberships (bubble_id, user_id, role)
      VALUES (?, ?, 'member')
    `).bind(bubble.id, sessionUser.account_id).run();

    return Response.json({ message: 'Successfully joined bubble', bubble_name: bubble.name });
  } catch (error) {
    console.error('Error joining bubble:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Leave a bubble
async function handleLeaveBubble(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    const url = new URL(request.url);
    const bubbleId = url.pathname.split('/')[3];

    // Check if user is a member
    const membership = await env.DB.prepare(`
      SELECT role FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, sessionUser.account_id).first();

    if (!membership) {
      return Response.json({ error: 'Not a member of this bubble' }, { status: 400 });
    }

    if (membership.role === 'creator') {
      return Response.json({ error: 'Creator cannot leave bubble. Delete it instead.' }, { status: 400 });
    }

    // Remove membership
    await env.DB.prepare(`
      DELETE FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, sessionUser.account_id).run();

    return Response.json({ message: 'Successfully left bubble' });
  } catch (error) {
    console.error('Error leaving bubble:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Delete a bubble (creator only)
async function handleDeleteBubble(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    const url = new URL(request.url);
    const bubbleId = url.pathname.split('/')[3];

    // Check if user is the creator
    const bubble = await env.DB.prepare(`
      SELECT creator_id FROM bubbles WHERE id = ?
    `).bind(bubbleId).first();

    if (!bubble) {
      return Response.json({ error: 'Bubble not found' }, { status: 404 });
    }

    if (bubble.creator_id !== sessionUser.account_id) {
      return Response.json({ error: 'Only the creator can delete this bubble' }, { status: 403 });
    }

    // Delete bubble (memberships will be deleted due to CASCADE)
    await env.DB.prepare(`
      DELETE FROM bubbles WHERE id = ?
    `).bind(bubbleId).run();

    return Response.json({ message: 'Bubble deleted successfully' });
  } catch (error) {
    console.error('Error deleting bubble:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Get bubble members
async function handleGetBubbleMembers(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    const url = new URL(request.url);
    const bubbleId = url.pathname.split('/')[3];
    
    console.log('Getting bubble members for bubbleId:', bubbleId, 'user:', sessionUser.account_id);

    // Check if user is a member of this bubble
    const membership = await env.DB.prepare(`
      SELECT id FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, sessionUser.account_id).first();

    if (!membership) {
      console.log('User is not a member of bubble:', bubbleId);
      return Response.json({ error: 'Not a member of this bubble' }, { status: 403 });
    }

    // Get bubble info and members, plus current user's role
    const bubble = await env.DB.prepare(`
      SELECT b.id, b.name, b.description, b.invite_code, bm.role as user_role 
      FROM bubbles b
      JOIN bubble_memberships bm ON b.id = bm.bubble_id 
      WHERE b.id = ? AND bm.user_id = ?
    `).bind(bubbleId, sessionUser.account_id).first();

    const members = await env.DB.prepare(`
      SELECT 
        na.id,
        na.username,
        na.display_name,
        bm.role,
        bm.joined_at,
        sa.platform,
        sa.platform_username,
        sa.avatar_url
      FROM bubble_memberships bm
      JOIN native_accounts na ON bm.user_id = na.id
      LEFT JOIN social_accounts sa ON na.id = sa.native_account_id
      WHERE bm.bubble_id = ?
      ORDER BY 
        CASE bm.role 
          WHEN 'creator' THEN 1 
          WHEN 'admin' THEN 2 
          ELSE 3 
        END,
        bm.joined_at ASC
    `).bind(bubbleId).all();

    // Group social accounts by user
    const userMap = new Map();
    
    members.results.forEach(row => {
      if (!userMap.has(row.id)) {
        userMap.set(row.id, {
          id: row.id,
          username: row.username,
          display_name: row.display_name,
          role: row.role,
          joined_at: row.joined_at,
          social_accounts: []
        });
      }
      
      if (row.platform) {
        userMap.get(row.id).social_accounts.push({
          platform: row.platform,
          platform_username: row.platform_username,
          avatar_url: row.avatar_url
        });
      }
    });

    const membersData = Array.from(userMap.values());
    
    console.log('Returning bubble data:', bubble);
    console.log('Returning members count:', membersData.length);

    return Response.json({
      bubble: bubble,
      members: membersData
    });
  } catch (error) {
    console.error('Error getting bubble members:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Get public bubbles for discovery
async function handleGetPublicBubbles(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    // Get public bubbles that user is not already a member of
    const bubbles = await env.DB.prepare(`
      SELECT 
        b.id,
        b.name,
        b.description,
        b.max_members,
        b.created_at,
        COUNT(bm.user_id) as member_count,
        na.display_name as creator_name
      FROM bubbles b
      JOIN native_accounts na ON b.creator_id = na.id
      LEFT JOIN bubble_memberships bm ON b.id = bm.bubble_id
      WHERE b.is_public = TRUE 
        AND b.id NOT IN (
          SELECT bubble_id FROM bubble_memberships WHERE user_id = ?
        )
      GROUP BY b.id, b.name, b.description, b.max_members, b.created_at, na.display_name
      ORDER BY b.created_at DESC
      LIMIT 20
    `).bind(sessionUser.account_id).all();

    return Response.json(bubbles.results);
  } catch (error) {
    console.error('Error getting public bubbles:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Kick a member from bubble (creator/admin only)
async function handleKickMember(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    const url = new URL(request.url);
    const bubbleId = url.pathname.split('/')[3];
    const { userId } = await request.json();

    // Check if current user is creator or admin
    const userMembership = await env.DB.prepare(`
      SELECT role FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, sessionUser.account_id).first();

    if (!userMembership || (userMembership.role !== 'creator' && userMembership.role !== 'admin')) {
      return Response.json({ error: 'Only creators and admins can kick members' }, { status: 403 });
    }

    // Check target user's role - creators can kick anyone, admins can't kick creators or other admins
    const targetMembership = await env.DB.prepare(`
      SELECT role FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, userId).first();

    if (!targetMembership) {
      return Response.json({ error: 'User is not a member of this bubble' }, { status: 400 });
    }

    if (userMembership.role === 'admin') {
      if (targetMembership.role === 'creator' || targetMembership.role === 'admin') {
        return Response.json({ error: 'Admins cannot kick creators or other admins' }, { status: 403 });
      }
    }

    // Can't kick yourself
    if (userId === sessionUser.account_id) {
      return Response.json({ error: 'You cannot kick yourself' }, { status: 400 });
    }

    // Remove the member
    await env.DB.prepare(`
      DELETE FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, userId).run();

    return Response.json({ message: 'Member kicked successfully' });
  } catch (error) {
    console.error('Error kicking member:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Promote member to admin (creator only)
async function handlePromoteMember(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    
    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    const url = new URL(request.url);
    const bubbleId = url.pathname.split('/')[3];
    const { userId, action } = await request.json(); // action: 'promote' or 'demote'

    // Check if current user is creator
    const userMembership = await env.DB.prepare(`
      SELECT role FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, sessionUser.account_id).first();

    if (!userMembership || userMembership.role !== 'creator') {
      return Response.json({ error: 'Only creators can promote/demote members' }, { status: 403 });
    }

    // Check target user exists
    const targetMembership = await env.DB.prepare(`
      SELECT role FROM bubble_memberships WHERE bubble_id = ? AND user_id = ?
    `).bind(bubbleId, userId).first();

    if (!targetMembership) {
      return Response.json({ error: 'User is not a member of this bubble' }, { status: 400 });
    }

    // Can't promote/demote yourself
    if (userId === sessionUser.account_id) {
      return Response.json({ error: 'You cannot change your own role' }, { status: 400 });
    }

    const newRole = action === 'promote' ? 'admin' : 'member';
    
    // Update the member's role
    await env.DB.prepare(`
      UPDATE bubble_memberships SET role = ? WHERE bubble_id = ? AND user_id = ?
    `).bind(newRole, bubbleId, userId).run();

    return Response.json({ 
      message: `Member ${action === 'promote' ? 'promoted to admin' : 'demoted to member'} successfully`,
      newRole: newRole
    });
  } catch (error) {
    console.error('Error promoting member:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Handle delete account - permanently remove user and related data
async function handleDeleteAccount(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);

    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    const userId = sessionUser.account_id;

    // 1) Remove memberships for this user
    await env.DB.prepare(`
      DELETE FROM bubble_memberships WHERE user_id = ?
    `).bind(userId).run();

    // 2) Delete bubbles created by this user (will cascade remove memberships)
    await env.DB.prepare(`
      DELETE FROM bubbles WHERE creator_id = ?
    `).bind(userId).run();

    // 3) Delete social accounts linked to this user
    await env.DB.prepare(`
      DELETE FROM social_accounts WHERE native_account_id = ?
    `).bind(userId).run();

    // 4) Delete sessions for this user
    await env.DB.prepare(`
      DELETE FROM sessions WHERE native_account_id = ?
    `).bind(userId).run();

    // 5) Finally delete the native account
    await env.DB.prepare(`
      DELETE FROM native_accounts WHERE id = ?
    `).bind(userId).run();

    return new Response(JSON.stringify({ success: true, message: 'Account deleted' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
      }
    });
  } catch (error) {
    console.error('Error deleting account:', error);
    return new Response(JSON.stringify({ error: 'Failed to delete account' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Unlink GitHub from current user
async function handleGitHubUnlink(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);

    if (!sessionUser) {
      return new Response('Not authenticated', { status: 401 });
    }

    await env.DB.prepare(`
      DELETE FROM social_accounts WHERE native_account_id = ? AND platform = 'github'
    `).bind(sessionUser.account_id).run();

    return Response.json({ success: true, message: 'GitHub account unlinked' });
  } catch (error) {
    console.error('Error unlinking GitHub:', error);
    return Response.json({ error: 'Failed to unlink GitHub' }, { status: 500 });
  }
}

// Ensure password_resets table exists
async function ensurePasswordResetsTable(env) {
  const sql = "CREATE TABLE IF NOT EXISTS password_resets (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
    "user_id INTEGER NOT NULL, " +
    "code_salt TEXT NOT NULL, " +
    "code_hash TEXT NOT NULL, " +
    "expires_at TEXT NOT NULL, " +
    "attempts INTEGER DEFAULT 0, " +
    "used INTEGER DEFAULT 0, " +
    "created_at TEXT DEFAULT CURRENT_TIMESTAMP, " +
    "FOREIGN KEY (user_id) REFERENCES native_accounts (id)" +
  ")";
  await env.DB.exec(sql);
}

function generateSixDigitCode() {
  const num = Math.floor(100000 + Math.random() * 900000);
  return String(num);
}

async function hashResetCode(code, salt) {
  const enc = new TextEncoder();
  const data = enc.encode(code + ':' + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(hashBuffer);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

async function sendEmail(env, to, subject, text) {
  try {
    if (env.RESEND_API_KEY) {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.RESEND_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: env.EMAIL_FROM || 'no-reply@bubbly.app',
          to: [to],
          subject,
          text
        })
      });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        console.error('Resend API error:', res.status, body);
      }
      return res.ok;
    }
  } catch (e) {
    console.error('Email send error:', e);
  }
  console.log('DEV EMAIL (no provider):', { to, subject, text });
  return true;
}

async function handlePasswordResetRequest(request, env) {
  try {
    const { email } = await request.json();
    if (!email) return Response.json({ message: 'If the account exists, a code has been sent' });

    await ensurePasswordResetsTable(env);

    const user = await env.DB.prepare('SELECT id, email FROM native_accounts WHERE email = ?')
      .bind(email).first();

    // Always respond the same to avoid user enumeration
    const genericResponse = Response.json({ message: 'If the account exists, a code has been sent' });
    if (!user) return genericResponse;

    // Create code
    const code = generateSixDigitCode();
    const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
    const codeHash = await hashResetCode(code, salt);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    // Invalidate previous codes for this user
    await env.DB.prepare('DELETE FROM password_resets WHERE user_id = ? OR expires_at < datetime("now")')
      .bind(user.id).run();

    await env.DB.prepare(`
      INSERT INTO password_resets (user_id, code_salt, code_hash, expires_at)
      VALUES (?, ?, ?, ?)
    `).bind(user.id, salt, codeHash, expiresAt).run();

    await sendEmail(env, user.email, 'Your Bubbly reset code', `Your reset code is: ${code}. It expires in 10 minutes.`);

    return genericResponse;
  } catch (error) {
    console.error('Password reset request error:', error);
    return Response.json({ message: 'If the account exists, a code has been sent' });
  }
}

async function handlePasswordResetSubmit(request, env) {
  try {
    const { email, code, new_password } = await request.json();
    if (!email || !code || !new_password) {
      return Response.json({ error: 'Missing fields' }, { status: 400 });
    }

    await ensurePasswordResetsTable(env);
    const user = await env.DB.prepare('SELECT id FROM native_accounts WHERE email = ?')
      .bind(email).first();
    if (!user) return Response.json({ error: 'Invalid code' }, { status: 400 });

    const pr = await env.DB.prepare(`
      SELECT * FROM password_resets WHERE user_id = ? AND used = 0 AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1
    `).bind(user.id).first();
    if (!pr) return Response.json({ error: 'Invalid or expired code' }, { status: 400 });

    // Increment attempts and check
    const attempts = pr.attempts || 0;
    if (attempts >= 5) return Response.json({ error: 'Too many attempts. Request a new code.' }, { status: 429 });

    const computedHash = await hashResetCode(code, pr.code_salt);
    if (computedHash !== pr.code_hash) {
      await env.DB.prepare('UPDATE password_resets SET attempts = attempts + 1 WHERE id = ?').bind(pr.id).run();
      return Response.json({ error: 'Invalid code' }, { status: 400 });
    }

    // Valid: update password and mark used
    const newHash = await hashPasswordPBKDF2(new_password);
    await env.DB.prepare('UPDATE native_accounts SET password_hash = ? WHERE id = ?')
      .bind(newHash, user.id).run();
    await env.DB.prepare('UPDATE password_resets SET used = 1 WHERE id = ?').bind(pr.id).run();

    return Response.json({ success: true });
  } catch (error) {
    console.error('Password reset submit error:', error);
    return Response.json({ error: 'Failed to reset password' }, { status: 500 });
  }
}

async function ensureAvatarColumn(env) {
  try {
    await env.DB.exec("ALTER TABLE native_accounts ADD COLUMN avatar_url TEXT");
  } catch (e) {
    // ignore if exists
  }
}

function isValidHttpUrl(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

async function handleUpdateProfile(request, env) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionUser = await getSessionUser(env, cookies.session);
    if (!sessionUser) return new Response('Not authenticated', { status: 401 });

    await ensureAvatarColumn(env);

    const body = await request.json().catch(() => ({}));
    let { display_name, avatar_url } = body;

    const updates = [];
    const binds = [];

    if (typeof display_name === 'string') {
      const dn = display_name.trim();
      if (dn.length < 1 || dn.length > 60) {
        return Response.json({ error: 'Display name must be 1-60 characters' }, { status: 400 });
      }
      updates.push('display_name = ?');
      binds.push(dn);
    }

    if (avatar_url !== undefined) {
      if (avatar_url === null || avatar_url === '') {
        updates.push('avatar_url = NULL');
      } else {
        if (!isValidHttpUrl(String(avatar_url))) {
          return Response.json({ error: 'Invalid avatar URL' }, { status: 400 });
        }
        updates.push('avatar_url = ?');
        binds.push(String(avatar_url));
      }
    }

    if (updates.length === 0) {
      return Response.json({ error: 'No changes provided' }, { status: 400 });
    }

    binds.push(sessionUser.account_id);
    const sql = `UPDATE native_accounts SET ${updates.join(', ')} WHERE id = ?`;
    await env.DB.prepare(sql).bind(...binds).run();

    // Return updated user info
    const refreshed = await getSessionUser(env, cookies.session);
    return Response.json({
      id: refreshed.account_id,
      username: refreshed.username,
      email: refreshed.email,
      display_name: refreshed.display_name,
      avatar_url: refreshed.avatar_url || null
    });
  } catch (error) {
    console.error('Update profile error:', error);
    return Response.json({ error: 'Failed to update profile' }, { status: 500 });
  }
}

// Admin Authorization Helper
async function requireAdmin(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionUser = await getSessionUser(env, cookies.session);
  
  if (!sessionUser) {
    return { error: new Response('Not authenticated', { status: 401 }), user: null };
  }
  
  if (sessionUser.role !== 'admin') {
    return { error: new Response('Admin access required', { status: 403 }), user: null };
  }
  
  return { error: null, user: sessionUser };
}

// Admin: Get all bubbles (public and private)
async function handleAdminGetAllBubbles(request, env) {
  try {
    const { error, user } = await requireAdmin(request, env);
    if (error) return error;

    console.log(`Admin ${user.username} accessing all bubbles`);

    const bubbles = await env.DB.prepare(`
      SELECT 
        b.id,
        b.name,
        b.description,
        b.is_public,
        b.invite_code,
        b.max_members,
        b.created_at,
        b.updated_at,
        COUNT(bm.user_id) as member_count,
        na.username as creator_username,
        na.display_name as creator_name
      FROM bubbles b
      JOIN native_accounts na ON b.creator_id = na.id
      LEFT JOIN bubble_memberships bm ON b.id = bm.bubble_id
      GROUP BY b.id, b.name, b.description, b.is_public, b.invite_code, b.max_members, b.created_at, b.updated_at, na.username, na.display_name
      ORDER BY b.created_at DESC
    `).all();

    return Response.json({
      bubbles: bubbles.results,
      total: bubbles.results.length
    });
  } catch (error) {
    console.error('Admin get all bubbles error:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Admin: Get all users
async function handleAdminGetAllUsers(request, env) {
  try {
    const { error, user } = await requireAdmin(request, env);
    if (error) return error;

    console.log(`Admin ${user.username} accessing all users`);

    const users = await env.DB.prepare(`
      SELECT 
        na.id,
        na.username,
        na.email,
        na.display_name,
        na.role,
        na.created_at,
        COUNT(DISTINCT bm.bubble_id) as bubbles_joined,
        COUNT(DISTINCT b.id) as bubbles_created,
        GROUP_CONCAT(DISTINCT sa.platform) as linked_platforms
      FROM native_accounts na
      LEFT JOIN bubble_memberships bm ON na.id = bm.user_id
      LEFT JOIN bubbles b ON na.id = b.creator_id
      LEFT JOIN social_accounts sa ON na.id = sa.native_account_id
      GROUP BY na.id, na.username, na.email, na.display_name, na.role, na.created_at
      ORDER BY na.created_at DESC
    `).all();

    return Response.json({
      users: users.results,
      total: users.results.length
    });
  } catch (error) {
    console.error('Admin get all users error:', error);
    return new Response('Server error', { status: 500 });
  }
}

// Admin: Get platform stats
async function handleAdminGetStats(request, env) {
  try {
    const { error, user } = await requireAdmin(request, env);
    if (error) return error;

    console.log(`Admin ${user.username} accessing platform stats`);

    // Get various stats
    const totalUsers = await env.DB.prepare('SELECT COUNT(*) as count FROM native_accounts').first();
    const totalBubbles = await env.DB.prepare('SELECT COUNT(*) as count FROM bubbles').first();
    const publicBubbles = await env.DB.prepare('SELECT COUNT(*) as count FROM bubbles WHERE is_public = 1').first();
    const privateBubbles = await env.DB.prepare('SELECT COUNT(*) as count FROM bubbles WHERE is_public = 0').first();
    const totalMemberships = await env.DB.prepare('SELECT COUNT(*) as count FROM bubble_memberships').first();
    const activeSessions = await env.DB.prepare("SELECT COUNT(*) as count FROM sessions WHERE datetime(expires_at) > datetime('now')").first();
    
    // Platform breakdown
    const platformStats = await env.DB.prepare(`
      SELECT platform, COUNT(*) as count 
      FROM social_accounts 
      GROUP BY platform 
      ORDER BY count DESC
    `).all();

    // Recent activity
    const recentUsers = await env.DB.prepare(`
      SELECT username, display_name, created_at 
      FROM native_accounts 
      ORDER BY created_at DESC 
      LIMIT 10
    `).all();

    const recentBubbles = await env.DB.prepare(`
      SELECT b.name, b.is_public, b.created_at, na.username as creator 
      FROM bubbles b 
      JOIN native_accounts na ON b.creator_id = na.id 
      ORDER BY b.created_at DESC 
      LIMIT 10
    `).all();

    return Response.json({
      stats: {
        total_users: totalUsers.count,
        total_bubbles: totalBubbles.count,
        public_bubbles: publicBubbles.count,
        private_bubbles: privateBubbles.count,
        total_memberships: totalMemberships.count,
        active_sessions: activeSessions.count
      },
      platform_stats: platformStats.results,
      recent_users: recentUsers.results,
      recent_bubbles: recentBubbles.results
    });
  } catch (error) {
    console.error('Admin get stats error:', error);
    return new Response('Server error', { status: 500 });
  }
}