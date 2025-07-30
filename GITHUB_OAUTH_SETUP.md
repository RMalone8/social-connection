# GitHub OAuth Setup Guide

This guide will help you set up GitHub login for your Social Connection app.

## Step 1: Create a GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill out the form:
   - **Application name**: `Social Connection App` (or any name you prefer)
   - **Homepage URL**: 
     - For development: `http://localhost:8788`
     - For production: `https://your-domain.com`
   - **Authorization callback URL**:
     - For development: `http://localhost:8788/api/auth/callback`
     - For production: `https://your-domain.com/api/auth/callback`
   - **Application description**: (optional) "A social connection application with GitHub login"

4. Click "Register application"
5. Note down your **Client ID** and generate a **Client Secret**

## Step 2: Configure Environment Variables

### For Local Development

1. Update the `.dev.vars` file with your GitHub OAuth credentials:

```env
GITHUB_CLIENT_ID=your-actual-client-id-here
GITHUB_CLIENT_SECRET=your-actual-client-secret-here
GITHUB_REDIRECT_URI=http://localhost:8788/api/auth/callback
```

### For Production Deployment

1. Update `wrangler.jsonc` with your production values:

```json
"vars": {
  "GITHUB_CLIENT_ID": "your-actual-client-id-here",
  "GITHUB_REDIRECT_URI": "https://your-domain.com/api/auth/callback"
}
```

2. Set the secret using Wrangler CLI:

```bash
wrangler secret put GITHUB_CLIENT_SECRET
# Enter your client secret when prompted
```

## Step 3: Run the Application

### Development

```bash
# Install dependencies
pnpm install

# Start development server
pnpm dev
```

The app will be available at `http://localhost:8788`

### Production Deployment

```bash
# Build and deploy to Cloudflare Workers
pnpm deploy
```

## Step 4: Test the GitHub Login

1. Open your application in a browser
2. Click the "Login with GitHub" button
3. You'll be redirected to GitHub for authorization
4. After granting permission, you'll be redirected back to your app
5. Your GitHub profile information should be displayed

## Security Notes

- **Never commit your `.dev.vars` file** to version control (it's already in `.gitignore`)
- Use Wrangler secrets for production environment variables
- The current implementation uses simple base64 encoding for sessions - consider implementing proper JWT signing for production use
- HTTPS is required for production OAuth callbacks

## Troubleshooting

### Common Issues

1. **"Invalid state parameter" error**
   - Make sure cookies are enabled in your browser
   - Check that your redirect URI matches exactly in GitHub settings

2. **"Not authenticated" errors**
   - Verify your environment variables are set correctly
   - Check browser developer tools for any console errors

3. **OAuth app configuration issues**
   - Ensure callback URLs match exactly (including protocol and port)
   - Verify your Client ID and Secret are correct

### Development vs Production URLs

Make sure to create separate OAuth apps or update the callback URLs when switching between development and production environments.

## Next Steps

With GitHub login working, you can now:
- Access user's GitHub profile data
- Implement user-specific features
- Store user preferences
- Build social features using GitHub connections

The authenticated user data is available in the frontend through the `/api/user` endpoint and includes:
- `login`: GitHub username
- `name`: User's display name
- `avatar_url`: Profile picture URL
- `html_url`: GitHub profile URL
- And other GitHub user API fields 