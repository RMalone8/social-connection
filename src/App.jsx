import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loginForm, setLoginForm] = useState(true) // true for login, false for register
  const [allUsers, setAllUsers] = useState([]) // All users for bubble display
  
  useEffect(() => {
    checkAuthStatus()
  }, [])

  useEffect(() => {
    if (user) {
      fetchAllUsers()
    }
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

  const fetchAllUsers = async () => {
    try {
      const response = await fetch('/api/users/all')
      if (response.ok) {
        const users = await response.json()
        setAllUsers(users)
      }
    } catch (error) {
      console.error('Failed to fetch users:', error)
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

  const linkGitHub = () => {
    window.location.assign("/api/link/github")
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
      const response = await fetch('/api/github/get-followers', { method: 'POST' })
      if (response.ok) {
        alert('🎉 Everyone is now following you on GitHub!')
      } else {
        alert('Failed to make everyone follow you')
      }
    } catch (error) {
      console.error('Follow action failed:', error)
      alert('Follow action failed')
    }
  }

  const followEveryone = async () => {
    try {
      const response = await fetch('/api/github/follow-everyone', { method: 'POST' })
      if (response.ok) {
        alert('🎉 You are now following everyone on GitHub!')
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
      {(!user.social_accounts || user.social_accounts.length === 0) && (
        <div className="link-social-container">
          <p>🔗 Link your social accounts to join the bubble party!</p>
          <button onClick={linkGitHub} className="github-link-btn">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.30.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            🐙 Link GitHub
          </button>
        </div>
      )}

      {/* User Bubbles */}
      <div className="bubble-ocean">
        <h2>🌊 Bubble Ocean - All Bubbly Users</h2>
        <div className="bubbles-container">
          {allUsers.map((bubbleUser, index) => (
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
                  alt={bubbleUser.display_name}
                  className="bubble-avatar"
                />
              ) : (
                <div className="bubble-avatar-placeholder">
                  🏝️
                </div>
              )}
              <div className="bubble-name">
                {bubbleUser.display_name || bubbleUser.username}
              </div>
              {bubbleUser.id === user.id && (
                <div className="current-user-indicator">👑</div>
              )}
            </div>
          ))}
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
