import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loginForm, setLoginForm] = useState(true) // true for login, false for register
  const [allUsers, setAllUsers] = useState([])
  const [isLoadingUsers, setIsLoadingUsers] = useState(false)
  const [fetchUsersTimeout, setFetchUsersTimeout] = useState(null) // All users for bubble display
  
  useEffect(() => {
    checkAuthStatus()
    
    // Check for linking success in URL parameters
    const urlParams = new URLSearchParams(window.location.search)
    const linkedPlatform = urlParams.get('linked')
    if (linkedPlatform) {
      // Show success message and refresh data after a short delay
      setTimeout(async () => {
        alert(`🎉 ${linkedPlatform.charAt(0).toUpperCase() + linkedPlatform.slice(1)} account linked successfully!`)
        
        console.log('=== LINKING SUCCESS: Refreshing data ===')
        // Only refresh user data - the useEffect will handle fetchAllUsers
        await checkAuthStatus()
        console.log('=== LINKING SUCCESS: User data refreshed ===')
      }, 800)
      
      // Clean up URL
      const newUrl = window.location.pathname
      window.history.replaceState({}, '', newUrl)
    }
  }, [])

  useEffect(() => {
    console.log('=== USER EFFECT: User state changed ===', user)
    if (user) {
      console.log('=== USER EFFECT: User exists, fetching all users immediately ===')
      fetchAllUsers(true) // Immediate fetch when user changes
    } else {
      console.log('=== USER EFFECT: No user, clearing allUsers ===')
      setAllUsers([])
    }
  }, [user])

  // Refresh data when user comes back to the page (after OAuth redirect)
  useEffect(() => {
    const handleFocus = async () => {
      if (user) {
        console.log('=== FOCUS: Page focused, refreshing data ===')
        await checkAuthStatus() // Refresh user data
        console.log('=== FOCUS: checkAuthStatus completed ===')
        // Small delay to ensure backend is updated
        setTimeout(() => {
          console.log('=== FOCUS: Calling fetchAllUsers after delay ===')
          fetchAllUsers() // Refresh all users
        }, 300)
      }
    }

    window.addEventListener('focus', handleFocus)
    return () => window.removeEventListener('focus', handleFocus)
  }, [user])

  const checkAuthStatus = async () => {
    try {
      const response = await fetch('/api/user')
      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
      }
    } catch (error) {
      console.error('Error checking auth status:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchAllUsers = async (immediate = false) => {
    // Clear any pending timeout
    if (fetchUsersTimeout) {
      clearTimeout(fetchUsersTimeout)
      setFetchUsersTimeout(null)
    }

        const doFetch = async () => {
      try {
        setIsLoadingUsers(true)
        console.log('=== FETCH: Starting fetchAllUsers ===')
        const response = await fetch('/api/users/all')
        if (response.ok) {
          const users = await response.json()
          console.log('=== FETCH: Fetched users count:', users.length, 'users:', users)
          console.log('=== FETCH: Setting allUsers to:', users)
          setAllUsers(users)
          console.log('=== FETCH: allUsers state should now be updated ===')
        } else {
          console.error('=== FETCH: Failed to fetch users, response not ok:', response.status)
          // Don't clear existing users on error
        }
      } catch (error) {
        console.error('=== FETCH: Failed to fetch users:', error)
        // Don't clear existing users on error
      } finally {
        setIsLoadingUsers(false)
        console.log('=== FETCH: Completed fetchAllUsers ===')
      }
    }

    if (immediate) {
      await doFetch()
    } else {
      // Debounce the fetch to prevent rapid calls
      const timeout = setTimeout(doFetch, 200)
      setFetchUsersTimeout(timeout)
    }
  }

  const handleRegister = async (e) => {
    e.preventDefault()
    const formData = new FormData(e.target)
    
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: formData.get('username'),
          email: formData.get('email'),
          password: formData.get('password'),
          display_name: formData.get('display_name')
        })
      })
      
      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
      } else {
        const error = await response.text()
        alert('Registration failed: ' + error)
      }
    } catch (error) {
      console.error('Registration error:', error)
      alert('Registration failed')
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    const formData = new FormData(e.target)
    
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: formData.get('username'),
          password: formData.get('password')
        })
      })
      
      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
      } else {
        const error = await response.text()
        alert('Login failed: ' + error)
      }
    } catch (error) {
      console.error('Login error:', error)
      alert('Login failed')
    }
  }

  const linkGitHub = async () => {
    window.location.assign("/api/link/github")
  }

  const linkSpotify = async () => {
    window.location.assign("/api/link/spotify")
  }

  const refreshUserData = async () => {
    try {
      const response = await fetch('/api/user')
      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
      }
    } catch (error) {
      console.error('Failed to refresh user data:', error)
    }
  }

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      setUser(null)
      setAllUsers([])
    } catch (error) {
      console.error('Logout error:', error)
    }
  }

  const makeEveryoneFollowMe = async () => {
    try {
      const githubResponse = await fetch('/api/github/get-followers', { method: 'POST' })
      if (githubResponse.ok) {
        alert('🎉 Everyone is now following you on GitHub!')
      } else {
        alert('Failed to make everyone follow you')
      }
    } catch (error) {
      console.error('Follow action failed:', error)
      alert('Follow action failed')
    }

    try {
      const spotifyResponse = await fetch('/api/spotify/follow-everyone', { method: 'POST' })
      if (spotifyResponse.ok) {
        alert('🎉 Everyone is now following you on Spotify!')
      } else {
        alert('Failed to follow everyone')
      }
    } catch (error) {
      console.error('Follow action failed:', error)
      alert('Follow action failed')
    }
  }

  const followEveryone = async () => {
    try {
      const githubResponse = await fetch('/api/github/follow-everyone', { method: 'POST' })
      if (githubResponse.ok) {
        alert('🎉 You are now following everyone on GitHub!')
      } else {
        alert('Failed to follow everyone')
      }
    } catch (error) {
      console.error('Follow action failed:', error)
      alert('Follow action failed')
    }

    try {
      const spotifyResponse = await fetch('/api/spotify/follow-everyone', { method: 'POST' })
      if (spotifyResponse.ok) {
        alert('🎉 You are now following everyone on Spotify!')
      } else {
        alert('Failed to follow everyone')
      } 
    } catch (error) {
      console.error('Follow action failed:', error)
      alert('Follow action failed')
    }
  }

  if (loading) {
    return (
      <div className="bubbly-container">
        <div className="tropical-loading">
          <div className="bubble-loader"></div>
          <p>🏝️ Loading Bubbly...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return (
      <div className="bubbly-container">
        <div className="tropical-header">
          <h1>🫧 Welcome to Bubbly</h1>
          <p>🏝️ Your tropical social connection paradise</p>
        </div>
        
        <div className="auth-container">
          <div className="auth-toggle">
            <button 
              className={loginForm ? 'active' : ''} 
              onClick={() => setLoginForm(true)}
            >
              Login
            </button>
            <button 
              className={!loginForm ? 'active' : ''} 
              onClick={() => setLoginForm(false)}
            >
              Register
            </button>
          </div>

          {loginForm ? (
            <form onSubmit={handleLogin} className="auth-form">
              <h2>🌺 Login to Bubbly</h2>
              <input type="text" name="username" placeholder="Username" required />
              <input type="password" name="password" placeholder="Password" required />
              <button type="submit" className="tropical-btn">🏄‍♂️ Dive In</button>
              <button type="button" className="forgot-password-btn" onClick={() => alert('🏝️ Forgot password feature coming soon! Contact support for now.')}>
                🤔 Forgot Password?
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="auth-form">
              <h2>🌴 Join Bubbly</h2>
              <input type="text" name="username" placeholder="Username" required />
              <input type="email" name="email" placeholder="Email" required />
              <input type="text" name="display_name" placeholder="Display Name" required />
              <input type="password" name="password" placeholder="Password" required />
              <button type="submit" className="tropical-btn">🌊 Create Account</button>
            </form>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="bubbly-container">
      <div className="tropical-header">
        <h1>🫧 Bubbly</h1>
        <div className="user-info">
          <span>🌺 Welcome, {user.display_name || user.username}!</span>
          <button onClick={logout} className="logout-btn">🏖️ Logout</button>
        </div>
      </div>

      {/* Social Account Linking */}
      <div className="link-social-container">
        <p>🔗 Link your social accounts to join the bubble party!</p>
        <div className="link-buttons">
          {/* GitHub Button */}
          {user.social_accounts?.find(acc => acc.platform === 'github') ? (
            <button className="github-link-btn linked" disabled>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.30 3.297-1.30.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              ✅ GitHub Linked
            </button>
          ) : (
            <button onClick={linkGitHub} className="github-link-btn">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.30 3.297-1.30.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              🐙 Link GitHub
            </button>
          )}

          {/* Spotify Button */}
          {user.social_accounts?.find(acc => acc.platform === 'spotify') ? (
            <button className="spotify-link-btn linked" disabled>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.42 1.56-.299.421-1.02.599-1.559.3z"/>
              </svg>
              ✅ Spotify Linked
            </button>
          ) : (
            <button onClick={linkSpotify} className="spotify-link-btn">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.66 0 12 0zm5.521 17.34c-.24.359-.66.48-1.021.24-2.82-1.74-6.36-2.101-10.561-1.141-.418.122-.779-.179-.899-.539-.12-.421.18-.78.54-.9 4.56-1.021 8.52-.6 11.64 1.32.42.18.479.659.301 1.02zm1.44-3.3c-.301.42-.841.6-1.262.3-3.239-1.98-8.159-2.58-11.939-1.38-.479.12-1.02-.12-1.14-.6-.12-.48.12-1.021.6-1.141C9.6 9.9 15 10.561 18.72 12.84c.361.181.54.78.241 1.2zm.12-3.36C15.24 8.4 8.82 8.16 5.16 9.301c-.6.179-1.2-.181-1.38-.721-.18-.601.18-1.2.72-1.381 4.26-1.26 11.28-1.02 15.721 1.621.539.3.719 1.02.42 1.56-.299.421-1.02.599-1.559.3z"/>
              </svg>
              🎵 Link Spotify
            </button>
          )}
        </div>
      </div>

      {/* User Bubbles - Always Visible */}
      <div className="bubble-ocean">
        <h2>🌊 Bubble Ocean - All Bubbly Users</h2>
        <div className="bubbles-container">
          {console.log('Rendering bubbles - isLoadingUsers:', isLoadingUsers, 'allUsers.length:', allUsers.length, 'allUsers:', allUsers)}
          
          {/* Always show users if we have them */}
          {allUsers.map((bubbleUser, index) => {
            console.log('Rendering bubble for user:', bubbleUser.display_name, bubbleUser)
            return (
              <div 
                key={bubbleUser.id || index} 
                className={`user-bubble ${bubbleUser.id === user.id ? 'current-user' : ''}`}
                style={{
                  animationDelay: `${index * 0.2}s`
                }}
              >
                {bubbleUser.social_accounts && bubbleUser.social_accounts.length > 0 ? (
                  <img 
                    src={bubbleUser.social_accounts[0].avatar_url} 
                    alt={bubbleUser.display_name || bubbleUser.username}
                    className="bubble-avatar"
                    onError={(e) => {
                      console.log('Image failed to load, showing placeholder')
                      e.target.style.display = 'none';
                      e.target.nextSibling.style.display = 'flex';
                    }}
                  />
                ) : null}
                <div 
                  className="bubble-avatar-placeholder" 
                  style={{
                    display: bubbleUser.social_accounts && bubbleUser.social_accounts.length > 0 ? 'none' : 'flex'
                  }}
                >
                  {(bubbleUser.display_name || bubbleUser.username).charAt(0).toUpperCase()}
                </div>
                <div className="bubble-name">
                  {bubbleUser.display_name || bubbleUser.username}
                </div>
                {bubbleUser.id === user.id && (
                  <div className="current-user-indicator">👑</div>
                )}
              </div>
            )
          })}
          
          {/* Show loading only when no users and loading */}
          {allUsers.length === 0 && isLoadingUsers && (
            <div className="bubble-loading">
              <div className="bubble-loader"></div>
              <p>Loading bubbly friends...</p>
            </div>
          )}
          
          {/* Show empty state only when no users and not loading */}
          {allUsers.length === 0 && !isLoadingUsers && (
            <div className="bubble-loading">
              <div className="bubble-avatar-placeholder">🏝️</div>
              <p>You're the first bubble! Invite friends to join! 🫧</p>
            </div>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="action-buttons">
        <button onClick={makeEveryoneFollowMe} className="action-btn follow-me-btn">
          🌟 Everyone Follow Me
        </button>
        <button onClick={followEveryone} className="action-btn follow-all-btn">
          🤝 I'll Follow Everyone
        </button>
      </div>
    </div>
  )
}

export default App
