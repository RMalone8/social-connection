export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    console.log("Here is the pathname: ", url.pathname)

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
    return handleGitHubLogin(env);
  }

  if (url.pathname === "/api/auth/callback") {
    return handleGitHubCallback(request, env);
  }

  if (url.pathname === "/api/user") {
    return handleUserInfo(request, env);
  }

  if (url.pathname === "/api/auth/logout") {
    return handleLogout();
  }

  if (url.pathname === "/api/followers") {
    return listFollowers(request);
  }

  // Original API endpoint
  if (url.pathname.startsWith("/api/")) {
    return Response.json({
      name: "Ryan",
    });
  }

  return new Response(null, { status: 404 });
}

// Generate a random state parameter for OAuth security
function generateState() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Handle GitHub login redirect
function handleGitHubLogin(env) {
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

    // Create a simple session token (in production, use proper JWT with signing)
    const sessionData = {
      user: userData,
      token: tokenData.access_token,
      expires: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
    };

    const sessionToken = btoa(JSON.stringify(sessionData));

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

  if (!sessionToken) {
    return new Response('Not authenticated', { status: 401 });
  }

  try {
    const sessionData = JSON.parse(atob(sessionToken));
    
    // Check if session is expired
    if (Date.now() > sessionData.expires) {
      return new Response('Session expired', { status: 401 });
    }

    return Response.json(sessionData.user);
  } catch (error) {
    return new Response('Invalid session', { status: 401 });
  }
}

// Handle logout
function handleLogout() {
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
    }
  });
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

async function listFollowers(request) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;

  console.log("sessionToken", sessionToken) 

  if (!sessionToken) {
    return new Response('Not authenticated', { status: 401 });
  }

  try {
    const sessionData = JSON.parse(atob(sessionToken));
    console.log("sessionData", sessionData)

    const userData = sessionData.user;

    const following = await fetch(`https://api.github.com/user/following/ericahinkleRH`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${sessionData.token}`,
        'User-Agent': 'Social-Connection-App',
        'Content-Length': '0',
      },
    });

    return new Response(JSON.stringify({ following: following }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      }
    });
  } catch (error) {
    return new Response('Invalid session', { status: 401 });
  }
}