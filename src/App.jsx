import { useState, useEffect } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import cloudflareLogo from './assets/Cloudflare_Logo.svg'
import './App.css'

function App() {
  const [count, setCount] = useState(0)
  const [name, setName] = useState('unknown')
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  // Check if user is already logged in when component mounts
  useEffect(() => {
    checkAuthStatus()
  }, [])

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

  const loginWithGitHub = () => {
    console.log("loginWithGitHub")
    //window.location.href = '/api/auth/github'
    window.location.assign("/api/auth/github")
    console.log("loginWithGitHub done")
  }

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      setUser(null)
    } catch (error) {
      console.error('Error logging out:', error)
    }
  }

  const testFollowers = async () => {
    try {
      const response = await fetch('/api/followers')
      console.log('Response status:', response.status)
      console.log('Response headers:', [...response.headers.entries()])
      
      if (response.ok) {
        const data = await response.json()
        console.log('Followers data:', data)
      } else {
        console.log('Error response:', await response.text())
      }
    } catch (error) {
      console.error('Error calling followers:', error)
    }
  }

  if (loading) {
    return (
      <div className="loading">
        <p>Loading...</p>
      </div>
    )
  }

  return (
    <>
      <div>
        <a href='https://vite.dev' target='_blank'>
          <img src={viteLogo} className='logo' alt='Vite logo' />
        </a>
        <a href='https://react.dev' target='_blank'>
          <img src={reactLogo} className='logo react' alt='React logo' />
        </a>
        <a href='https://workers.cloudflare.com/' target='_blank'>
          <img src={cloudflareLogo} className='logo cloudflare' alt='Cloudflare logo' />
        </a>
      </div>
      <h1>Vite + React + Cloudflare</h1>
      
      {/* Authentication Section */}
      <div className='card'>
        {user ? (
          <div className="user-info">
            <img 
              src={user.avatar_url} 
              alt={`${user.login}'s avatar`}
              className="avatar"
              width="50"
              height="50"
            />
            <p>Welcome, <strong>{user.name || user.login}</strong>!</p>
            <p>GitHub: <a href={user.html_url} target="_blank" rel="noopener noreferrer">@{user.login}</a></p>
            <button onClick={logout} className="logout-btn">
              Logout
            </button>
          </div>
        ) : (
          <div className="login-section">
            <p>Connect with GitHub to get started</p>
            <button onClick={loginWithGitHub} className="github-login-btn">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              Login with GitHub
            </button>
          </div>
        )}
      </div>

      <div className='card'>
        <button
          onClick={testFollowers}
          aria-label='increment'
        >
          Test Followers Endpoint
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <div className='card'>
        <button
          onClick={() => {
            fetch('/api/')
              .then((res) => res.json())
              .then((data) => setName(data.name))
          }}
          aria-label='get name'
        >
          Name from API is: {name}
        </button>
        <p>
          Edit <code>worker/index.js</code> to change the name
        </p>
      </div>
      <p className='read-the-docs'>
        Click on the Vite and React logos to learn more
      </p>
    </>
  )
}

export default App
