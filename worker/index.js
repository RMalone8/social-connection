export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle API routes first
    if (url.pathname.startsWith("/api/")) {
      return handleApiRoutes(request, env, url);
    }

    // For non-API routes, let the assets handler deal with it
    // This will serve the built React app from the dist directory
    return env.ASSETS.fetch(request);
  },
};

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

  // Social media linking (requires native login first)
  if (url.pathname === "/api/link/github") {
    return handleGitHubLink(request, env);
  }

  if (url.pathname === "/api/link/github/callback") {
    return handleGitHubLinkCallback(request, env);
  }

  if (url.pathname === "/api/link/instagram") {
    return handleInstagramLink(request, env);
  }

  if (url.pathname === "/api/link/instagram/callback") {
    return handleInstagramLinkCallback(request, env);
  }

  if (url.pathname === "/api/user") {
    return handleUserInfo(request, env);
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

  // Original API endpoint - now with database logging
  if (url.pathname.startsWith("/api/")) {
    return logDatabaseContents(env);
  }

  return new Response(null, { status: 404 });
}

// Password hashing utilities
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hash) {
  const hashedPassword = await hashPassword(password);
  return hashedPassword === hash;
}

// Database helper functions
async function createNativeAccount(env, username, email, password, displayName) {
  const passwordHash = await hashPassword(password);
  
  const result = await env.DB.prepare(`
    INSERT INTO native_accounts (username, email, password_hash, display_name)
    VALUES (?, ?, ?, ?)
  `).bind(username, email, passwordHash, displayName).run();

  return await env.DB.prepare(
    "SELECT id, username, email, display_name, created_at FROM native_accounts WHERE id = ?"
  ).bind(result.meta.last_row_id).first();
}

async function getNativeAccountByUsername(env, username) {
  return await env.DB.prepare(
    "SELECT * FROM native_accounts WHERE username = ?"
  ).bind(username).first();
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
    // Update existing social account
    await env.DB.prepare(`
      UPDATE social_accounts 
      SET native_account_id = ?, platform_username = ?, platform_name = ?, 
          avatar_url = ?, profile_url = ?, access_token = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      nativeAccountId,
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
    SELECT s.*, n.id as account_id, n.username, n.email, n.display_name
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

async function logDatabaseContents(env) {
  try {
    console.log("=== DATABASE CONTENTS ===");
    
    // Query all users
    const users = await env.DB.prepare("SELECT * FROM users").all();
    console.log("\n--- USERS TABLE ---");
    console.log(`Found ${users.results.length} users:`);
    users.results.forEach((user, index) => {
      console.log(`User ${index + 1}:`, {
        id: user.id,
        github_id: user.github_id,
        login: user.login,
        name: user.name,
        avatar_url: user.avatar_url,
        created_at: user.created_at,
        updated_at: user.updated_at
      });
    });

    // Query all sessions
    const sessions = await env.DB.prepare("SELECT * FROM sessions").all();
    console.log("\n--- SESSIONS TABLE ---");
    console.log(`Found ${sessions.results.length} sessions:`);
    sessions.results.forEach((session, index) => {
      console.log(`Session ${index + 1}:`, {
        id: session.id,
        session_token: session.session_token.substring(0, 16) + "...", // Only show first 16 chars for security
        user_id: session.user_id,
        expires_at: session.expires_at,
        created_at: session.created_at
      });
    });

    // Query active sessions (not expired)
    const activeSessions = await env.DB.prepare(`
      SELECT s.*, u.login as user_login FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.expires_at > datetime('now')
    `).all();
    console.log("\n--- ACTIVE SESSIONS (Currently Logged In) ---");
    console.log(`Found ${activeSessions.results.length} active sessions:`);
    activeSessions.results.forEach((session, index) => {
      console.log(`Active Session ${index + 1}:`, {
        user_login: session.user_login,
        expires_at: session.expires_at,
        created_at: session.created_at
      });
    });

    // Query all sessions with tokens (including offline users)
    const tokensAvailable = await env.DB.prepare(`
      SELECT s.*, u.login as user_login FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.github_token IS NOT NULL AND s.github_token != ''
    `).all();
    console.log("\n--- ALL AVAILABLE TOKENS (Including Offline Users) ---");
    console.log(`Found ${tokensAvailable.results.length} stored tokens:`);
    tokensAvailable.results.forEach((session, index) => {
      const isActive = new Date(session.expires_at) > new Date();
      console.log(`Token ${index + 1}:`, {
        user_login: session.user_login,
        status: isActive ? 'ONLINE' : 'OFFLINE',
        expires_at: session.expires_at,
        created_at: session.created_at
      });
    });

    console.log("\n=== END DATABASE CONTENTS ===\n");

    // Return the original response so the frontend still works
    return Response.json({
      name: "Ryan",
      database_logged: true,
      users_count: users.results.length,
      sessions_count: sessions.results.length,
      active_sessions_count: activeSessions.results.length,
      available_tokens_count: tokensAvailable.results.length,
      offline_tokens_count: tokensAvailable.results.length - activeSessions.results.length
    });

  } catch (error) {
    console.error("Error logging database contents:", error);
      return Response.json({
        name: "Ryan",
      database_error: error.message
      });
    }
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

// Handle native account registration
async function handleRegister(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const { username, email, password, displayName } = await request.json();

    if (!username || !email || !password) {
      return new Response(JSON.stringify({ error: 'Username, email, and password are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if username or email already exists
    const existingUser = await env.DB.prepare(
      "SELECT id FROM native_accounts WHERE username = ? OR email = ?"
    ).bind(username, email).first();

    if (existingUser) {
      return new Response(JSON.stringify({ error: 'Username or email already exists' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Create new account
    const newAccount = await createNativeAccount(env, username, email, password, displayName);
    
    // Create session
    const sessionToken = await createSession(env, newAccount.id);

    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    headers.append('Set-Cookie', `session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`);

    return new Response(JSON.stringify({
      success: true,
      user: {
        username: newAccount.username,
        email: newAccount.email,
        displayName: newAccount.display_name
      }
    }), { status: 201, headers });

  } catch (error) {
    console.error('Registration error:', error);
    return new Response(JSON.stringify({ error: 'Registration failed' }), {
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
    const account = await getNativeAccountByUsername(env, username);
    if (!account) {
      return new Response(JSON.stringify({ error: 'Invalid username or password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, account.password_hash);
    if (!isValidPassword) {
      return new Response(JSON.stringify({ error: 'Invalid username or password' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Create session
    const sessionToken = await createSession(env, account.id);

    const headers = new Headers();
    headers.set('Content-Type', 'application/json');
    headers.append('Set-Cookie', `session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`);

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

    // Redirect back to the main page
    const headers = new Headers();
    headers.set('Location', new URL('/', request.url).toString());
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

// Handle Instagram account linking  
function handleInstagramLink(request, env) {
  const state = generateState();
  const params = new URLSearchParams({
    client_id: env.INSTAGRAM_CLIENT_ID,
    redirect_uri: env.INSTAGRAM_REDIRECT_URI,
    scope: 'user_profile,user_media',
    state: state,
  });

  const authUrl = `https://api.instagram.com/oauth/authorize?${params.toString()}`;

  const headers = new Headers();
  headers.set('Location', authUrl);
  headers.append('Set-Cookie', `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`);

  return new Response(null, {
    status: 302,
    headers: headers
  });
}

// Handle Instagram account linking callback
async function handleInstagramLinkCallback(request, env) {
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
    const tokenResponse = await fetch('https://api.instagram.com/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: env.INSTAGRAM_CLIENT_ID,
        client_secret: env.INSTAGRAM_CLIENT_SECRET,
        grant_type: 'authorization_code',
        redirect_uri: env.INSTAGRAM_REDIRECT_URI,
        code: code,
      }),
    });

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error('Failed to get access token');
    }

    // Get user info from Instagram
    const userResponse = await fetch(`https://graph.instagram.com/me?fields=id,username&access_token=${tokenData.access_token}`);
    const userData = await userResponse.json();

    // Link Instagram account to native account
    await linkSocialAccount(env, sessionUser.account_id, 'instagram', userData, tokenData.access_token);

    // Redirect back to the main page
    const headers = new Headers();
    headers.set('Location', new URL('/', request.url).toString());
    headers.append('Set-Cookie', `oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`); // Clear state cookie
    
    return new Response(null, {
      status: 302,
      headers: headers
    });
  } catch (error) {
    console.error('Instagram linking error:', error);
    return new Response('Instagram linking failed', { status: 500 });
  }
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
    username: sessionUser.username,
    email: sessionUser.email,
    displayName: sessionUser.display_name,
    socialAccounts: sessionUser.social_accounts.map(account => ({
      platform: account.platform,
      username: account.platform_username,
      name: account.platform_name,
      avatarUrl: account.avatar_url,
      profileUrl: account.profile_url
    }))
  });
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

    const currentUsername = sessionUser.login;
    console.log(`Making everyone follow: ${currentUsername}`);

    // Get ALL other users with tokens (including offline/logged out users)
    const otherSessions = await env.DB.prepare(`
      SELECT s.*, u.login as github_login, u.github_id 
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE u.github_id != ? AND s.github_token IS NOT NULL AND s.github_token != ''
    `).bind(sessionUser.github_id).all();

    console.log(`Found ${otherSessions.results.length} users with tokens to make follow you (including offline users)`);

    const followResults = [];

    // Make each other user follow the current user
    for (const otherSession of otherSessions.results) {
      try {
        console.log(`Making ${otherSession.github_login} follow ${currentUsername}`);
        
        const followResponse = await fetch(`https://api.github.com/user/following/${currentUsername}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${otherSession.github_token}`,
            'User-Agent': 'Social-Connection-App',
            'Content-Length': '0',
          },
        });

        const result = {
          follower: otherSession.github_login,
          target: currentUsername,
          status: followResponse.status,
          success: followResponse.status === 204
        };

        followResults.push(result);
        console.log(`Follow result - ${otherSession.github_login} -> ${currentUsername}:`, result);

      } catch (error) {
        console.error(`Error making ${otherSession.github_login} follow ${currentUsername}:`, error);
        followResults.push({
          follower: otherSession.github_login,
          target: currentUsername,
          error: error.message,
          success: false
        });
      }
    }

    console.log("All follow attempts completed:", followResults);

    return new Response(JSON.stringify({ 
      message: `Attempted to make everyone follow ${currentUsername}`,
      target_user: currentUsername,
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
    console.error('Error in getFollowers:', error);
    return new Response(JSON.stringify({ error: error.message }), { 
      status: 500,
      headers: {
        'Content-Type': 'application/json',
      }
    });
  }
}

async function getInstagramFollowers(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;

  if (!sessionToken) {
    return new Response('Not authenticated', { status: 401 });
  }

  try {
    const sessionUser = await getSessionUser(env, sessionToken);
    
    if (!sessionUser || !sessionUser.instagram_token) {
      return new Response('Instagram not connected', { status: 401 });
    }

    // Note: Instagram Basic Display API has limited follower access
    // This is a placeholder - actual implementation depends on your Instagram app permissions
    const followers = await fetch(`https://graph.instagram.com/me`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${sessionUser.instagram_token}`,
      },
    });

    const followersData = await followers.json();

    return new Response(JSON.stringify({ 
      instagram_user: followersData,
      message: "Instagram Basic Display API has limited access to follower data" 
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      }
    });
  } catch (error) {
    console.error('Error in getInstagramFollowers:', error);
    return new Response(JSON.stringify({ error: error.message }), { 
      status: 500,
      headers: {
        'Content-Type': 'application/json',
      }
    });
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