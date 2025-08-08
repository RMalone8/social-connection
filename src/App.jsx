import { useState, useEffect } from 'react'
import './App.css'
import { useRef } from 'react'

function App() {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loginForm, setLoginForm] = useState(true)
  
  // Dashboard states
  const [currentView, setCurrentView] = useState('dashboard') // 'dashboard', 'bubble', 'discover'
  const [profileDisplayName, setProfileDisplayName] = useState('')
  const [profileAvatarUrl, setProfileAvatarUrl] = useState('')
  const [userBubbles, setUserBubbles] = useState([])
  const [publicBubbles, setPublicBubbles] = useState([])
  const [selectedBubble, setSelectedBubble] = useState(null)
  const [bubbleMembers, setBubbleMembers] = useState([])
  const containerRef = useRef(null)
  
  // Modal states
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showJoinModal, setShowJoinModal] = useState(false)
  const [inviteCode, setInviteCode] = useState('')
  const [showResetModal, setShowResetModal] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [resetStep, setResetStep] = useState('request') // 'request' | 'verify'
  const [resetCode, setResetCode] = useState('')
  const [resetNewPassword, setResetNewPassword] = useState('')

  // Bubble positioning states
  const [isFloatingEnabled, setIsFloatingEnabled] = useState(true)
  const [bubblePositions, setBubblePositions] = useState(new Map())
  const physicsRef = useRef({ running: false, nodes: new Map(), rafId: 0, radius: 60 })

  // Admin state
  const [adminBubbles, setAdminBubbles] = useState([]);
  const [adminUsers, setAdminUsers] = useState([]);
  const [adminStats, setAdminStats] = useState(null);

  useEffect(() => {
    checkAuthStatus()
    
    // Check for linking success in URL parameters
    const urlParams = new URLSearchParams(window.location.search)
    const linkedPlatform = urlParams.get('linked')
    if (linkedPlatform) {
      // Show success message
      setTimeout(() => {
        alert(`🎉 ${linkedPlatform.charAt(0).toUpperCase() + linkedPlatform.slice(1)} account linked successfully!`)
      }, 500)
      
      // Clean up URL
      const newUrl = window.location.pathname
      window.history.replaceState({}, '', newUrl)
    }
  }, [])

  useEffect(() => {
    if (user) {
      fetchUserBubbles()
    }
  }, [user])

  // Physics engine for floating bubbles (avoid overlap)
  useEffect(() => {
    if (!isFloatingEnabled || !selectedBubble || bubbleMembers.length === 0) {
      stopPhysics()
      return
    }
    startPhysics()
    return stopPhysics
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isFloatingEnabled, selectedBubble?.id, bubbleMembers.length])

  const startPhysics = () => {
    const container = containerRef.current
    if (!container) return
    const rect = container.getBoundingClientRect()
    const width = rect.width
    const height = rect.height || 400
    const radius = 60 // matches 120px diameter
    physicsRef.current.radius = radius
    const nodes = new Map()
    // Initialize positions and velocities
    bubbleMembers.forEach((member, index) => {
      let x = Math.random() * (width - 2 * radius) + radius
      let y = Math.random() * (height - 2 * radius) + radius
      // Ensure not exactly overlapping initial
      for (let tries = 0; tries < 50; tries++) {
        let overlap = false
        for (const [, n] of nodes) {
          const dx = x - n.x
          const dy = y - n.y
          const dist = Math.hypot(dx, dy)
          if (dist < radius * 2) { overlap = true; break }
        }
        if (!overlap) break
        x = Math.random() * (width - 2 * radius) + radius
        y = Math.random() * (height - 2 * radius) + radius
      }
      const speed = 0.4 + (index % 3) * 0.1
      const angle = Math.random() * Math.PI * 2
      const vx = Math.cos(angle) * speed
      const vy = Math.sin(angle) * speed
      nodes.set(member.id, { x, y, vx, vy })
    })
    physicsRef.current.nodes = nodes
    physicsRef.current.running = true
    const tick = () => {
      stepPhysics(width, height)
      updatePositionsFromPhysics(width, height)
      physicsRef.current.rafId = requestAnimationFrame(tick)
    }
    physicsRef.current.rafId = requestAnimationFrame(tick)
  }

  const stopPhysics = () => {
    physicsRef.current.running = false
    if (physicsRef.current.rafId) cancelAnimationFrame(physicsRef.current.rafId)
  }

  const stepPhysics = (width, height) => {
    const nodes = physicsRef.current.nodes
    const r = physicsRef.current.radius
    const damping = 0.999
    // Move
    for (const [, n] of nodes) {
      n.x += n.vx
      n.y += n.vy
      // Walls
      if (n.x < r) { n.x = r; n.vx *= -1 }
      if (n.x > width - r) { n.x = width - r; n.vx *= -1 }
      if (n.y < r) { n.y = r; n.vy *= -1 }
      if (n.y > height - r) { n.y = height - r; n.vy *= -1 }
      n.vx *= damping
      n.vy *= damping
    }
    // Collisions (naive O(n^2))
    const arr = Array.from(nodes.values())
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        const a = arr[i], b = arr[j]
        const dx = b.x - a.x
        const dy = b.y - a.y
        const dist = Math.hypot(dx, dy)
        const minDist = r * 2
        if (dist > 0 && dist < minDist) {
          // Separate
          const overlap = (minDist - dist) / 2
          const nx = dx / dist
          const ny = dy / dist
          a.x -= nx * overlap
          a.y -= ny * overlap
          b.x += nx * overlap
          b.y += ny * overlap
          // Basic elastic response along normal
          const va = a.vx * nx + a.vy * ny
          const vb = b.vx * nx + b.vy * ny
          const exchange = vb - va
          a.vx += nx * exchange
          a.vy += ny * exchange
          b.vx -= nx * exchange
          b.vy -= ny * exchange
        }
      }
    }
  }

  const updatePositionsFromPhysics = (width, height) => {
    const nodes = physicsRef.current.nodes
    const newMap = new Map(bubblePositions)
    nodes.forEach((n, id) => {
      newMap.set(id, { x: n.x, y: n.y })
    })
    setBubblePositions(newMap)
  }

  const checkAuthStatus = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/user');
      if (response.ok) {
        const userData = await response.json();
        console.log('User data received:', userData);
        setUser(userData);
        setProfileDisplayName(userData.display_name || '');
        setProfileAvatarUrl(userData.avatar_url || '');
        fetchUserBubbles();
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const fetchUserBubbles = async () => {
    try {
      const response = await fetch('/api/bubbles')
      if (response.ok) {
        const bubbles = await response.json()
        setUserBubbles(bubbles)
      }
    } catch (error) {
      console.error('Failed to fetch bubbles:', error)
    }
  }

  const fetchPublicBubbles = async () => {
    try {
      const response = await fetch('/api/bubbles/public')
      if (response.ok) {
        const bubbles = await response.json()
        setPublicBubbles(bubbles)
      }
    } catch (error) {
      console.error('Failed to fetch public bubbles:', error)
    }
  }

  const fetchBubbleMembers = async (bubbleId, preservePositions = false) => {
    try {
      const response = await fetch(`/api/bubbles/${bubbleId}/members`)
      if (response.ok) {
        const data = await response.json()
        console.log('Bubble data received:', data.bubble)
        console.log('User role:', data.bubble?.user_role)
        
        // If preserving positions, keep existing positions for current members
        if (preservePositions && bubblePositions.size > 0) {
          // Only update member data, keep existing positions
          setBubbleMembers(data.members)
        } else {
          // Generate positions; physics will refine continuously
          generateBubblePositions(data.members)
          setBubbleMembers(data.members)
        }
        setSelectedBubble(data.bubble)
      }
    } catch (error) {
      console.error('Failed to fetch bubble members:', error)
    }
  }

  const generateBubblePositions = (members) => {
    const newPositions = new Map()
    const containerPadding = 60
    
    members.forEach((member, index) => {
      // Initialize in percent; physics will convert to px
      const randomX = Math.random() * (100 - containerPadding) + containerPadding/2
      const randomY = Math.random() * (100 - containerPadding) + containerPadding/2
      newPositions.set(member.id, { xPercent: randomX, yPercent: randomY })
    })
    
    setBubblePositions(newPositions)
  }

  const toggleFloating = () => {
    if (isFloatingEnabled) {
      // Disable floating - move to grid positions
      setIsFloatingEnabled(false)
    } else {
      // Enable floating - restore original positions
      setIsFloatingEnabled(true)
    }
  }

  const requestPasswordReset = async (e) => {
    e.preventDefault()
    try {
      await fetch('/api/auth/request-password-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resetEmail })
      })
      alert('If the account exists, a code has been sent to your email')
      setResetStep('verify')
    } catch (err) {
      alert('If the account exists, a code has been sent to your email')
      setResetStep('verify')
    }
  }

  const submitPasswordReset = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resetEmail, code: resetCode, new_password: resetNewPassword })
      })
      if (res.ok) {
        alert('Password reset! Please log in with your new password.')
        setShowResetModal(false)
        setResetEmail('')
        setResetCode('')
        setResetNewPassword('')
        setResetStep('request')
        setLoginForm(true)
      } else {
        const ejson = await res.json().catch(() => ({}))
        alert(ejson.error || 'Reset failed')
      }
    } catch (err) {
      alert('Reset failed')
    }
  }

  const handleKickMember = async (bubbleId, userId, displayName) => {
    if (!confirm(`Are you sure you want to kick ${displayName} from this bubble?`)) return
    
    try {
      const response = await fetch(`/api/bubbles/${bubbleId}/kick`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId })
      })
      
      if (response.ok) {
        alert(`${displayName} has been kicked from the bubble`)
        fetchBubbleMembers(bubbleId, true) // Refresh members, preserve positions
      } else {
        const error = await response.json()
        alert('Failed to kick member: ' + error.error)
      }
    } catch (error) {
      console.error('Kick member error:', error)
      alert('Failed to kick member')
    }
  }

  const handlePromoteMember = async (bubbleId, userId, displayName, action) => {
    const actionText = action === 'promote' ? 'promote to admin' : 'demote to member'
    if (!confirm(`Are you sure you want to ${actionText} ${displayName}?`)) return
    
    try {
      const response = await fetch(`/api/bubbles/${bubbleId}/promote`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, action })
      })
      
      if (response.ok) {
        const result = await response.json()
        alert(result.message)
        fetchBubbleMembers(bubbleId, true) // Refresh members, preserve positions
      } else {
        const error = await response.json()
        alert('Failed to change member role: ' + error.error)
      }
    } catch (error) {
      console.error('Promote member error:', error)
      alert('Failed to change member role')
    }
  }

  const copyInviteCode = async (inviteCode) => {
    try {
      // Try modern clipboard API first
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(inviteCode)
        alert(`✅ Invite code ${inviteCode} copied to clipboard! 📋`)
      } else {
        // Fallback for older browsers or non-HTTPS
        const textArea = document.createElement('textarea')
        textArea.value = inviteCode
        textArea.style.position = 'fixed'
        textArea.style.left = '-999999px'
        textArea.style.top = '-999999px'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        
        const successful = document.execCommand('copy')
        document.body.removeChild(textArea)
        
        if (successful) {
          alert(`✅ Invite code ${inviteCode} copied to clipboard! 📋`)
        } else {
          throw new Error('Copy command failed')
        }
      }
    } catch (error) {
      console.error('Failed to copy invite code:', error)
      // Show the code in a prompt as final fallback
      prompt('Copy this invite code manually:', inviteCode)
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
          username: formData.get('username'), // username or email
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

  const handleCreateBubble = async (e) => {
    e.preventDefault()
    const formData = new FormData(e.target)
    
    try {
      const response = await fetch('/api/bubbles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.get('name'),
          description: formData.get('description'),
          isPublic: formData.get('isPublic') === 'on',
          maxMembers: parseInt(formData.get('maxMembers')) || 50
        })
      })
      
      if (response.ok) {
        const newBubble = await response.json()
        setUserBubbles([newBubble, ...userBubbles])
        setShowCreateModal(false)
        alert(`🫧 Bubble "${newBubble.name}" created! Invite code: ${newBubble.invite_code}`)
      } else {
        const error = await response.json()
        alert('Failed to create bubble: ' + error.error)
      }
    } catch (error) {
      console.error('Create bubble error:', error)
      alert('Failed to create bubble')
    }
  }

  const handleJoinBubble = async (bubbleId = null) => {
    try {
      const url = bubbleId ? `/api/bubbles/${bubbleId}/join` : `/api/bubbles/0/join`
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bubbleId ? {} : { inviteCode })
      })
      
      if (response.ok) {
        const result = await response.json()
        alert(`🎉 ${result.message}`)
        fetchUserBubbles()
        setShowJoinModal(false)
        setInviteCode('')
        if (currentView === 'discover') {
          fetchPublicBubbles()
        }
      } else {
        const error = await response.json()
        alert('Failed to join bubble: ' + error.error)
      }
    } catch (error) {
      console.error('Join bubble error:', error)
      alert('Failed to join bubble')
    }
  }

  const handleLeaveBubble = async (bubbleId) => {
    if (!confirm('Are you sure you want to leave this bubble?')) return
    
    try {
      const response = await fetch(`/api/bubbles/${bubbleId}/leave`, {
        method: 'POST'
      })
      
      if (response.ok) {
        alert('Left bubble successfully')
        fetchUserBubbles()
        if (currentView === 'bubble' && selectedBubble?.id === bubbleId) {
          setCurrentView('dashboard')
        }
      } else {
        const error = await response.json()
        alert('Failed to leave bubble: ' + error.error)
      }
    } catch (error) {
      console.error('Leave bubble error:', error)
      alert('Failed to leave bubble')
    }
  }

  const handleDeleteBubble = async (bubbleId) => {
    if (!confirm('Are you sure you want to delete this bubble? This cannot be undone!')) return
    
    try {
      const response = await fetch(`/api/bubbles/${bubbleId}/delete`, {
        method: 'DELETE'
      })
      
      if (response.ok) {
        alert('Bubble deleted successfully')
        fetchUserBubbles()
        if (currentView === 'bubble' && selectedBubble?.id === bubbleId) {
          setCurrentView('dashboard')
        }
      } else {
        const error = await response.json()
        alert('Failed to delete bubble: ' + error.error)
      }
    } catch (error) {
      console.error('Delete bubble error:', error)
      alert('Failed to delete bubble')
    }
  }

  const handleFollowInBubble = async (action) => {
    // This will follow/be followed by all members in the current bubble
    try {
      const endpoint = action === 'follow' ? '/api/github/follow-everyone' : '/api/github/get-followers'
      const response = await fetch(endpoint, { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bubbleId: selectedBubble?.id })
      })
      
      if (response.ok) {
        const result = await response.json()
        alert(`🎉 ${result.message}`)
      } else {
        alert('Action failed')
      }
    } catch (error) {
      console.error('Follow action error:', error)
      alert('Action failed')
    }
  }

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' })
      setUser(null)
      setUserBubbles([])
      setCurrentView('dashboard')
    } catch (error) {
      console.error('Logout error:', error)
    }
  }

  const deleteAccount = async () => {
    if (!confirm('Are you sure you want to delete your account? This will remove your data and leave all bubbles. This cannot be undone.')) return
    try {
      const res = await fetch('/api/user/delete', { method: 'DELETE' })
      if (res.ok) {
        alert('Your account has been deleted. Goodbye!')
        setUser(null)
        setUserBubbles([])
        setPublicBubbles([])
        setSelectedBubble(null)
        setBubbleMembers([])
        setCurrentView('dashboard')
      } else {
        const err = await res.json().catch(() => ({}))
        alert('Failed to delete account' + (err.error ? `: ${err.error}` : ''))
      }
    } catch (e) {
      console.error('Delete account error:', e)
      alert('Failed to delete account')
    }
  }

  const linkGitHub = () => {
    window.location.assign("/api/link/github")
  }

  const saveProfile = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch('/api/user/profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ display_name: profileDisplayName, avatar_url: profileAvatarUrl })
      })
      if (res.ok) {
        const updated = await res.json()
        setUser(prev => ({ ...prev, display_name: updated.display_name, avatar_url: updated.avatar_url }))
        alert('Profile updated')
      } else {
        const err = await res.json().catch(() => ({}))
        alert(err.error || 'Failed to update profile')
      }
    } catch (e) {
      alert('Failed to update profile')
    }
  }

  const unlinkGitHub = async () => {
    if (!confirm('Unlink your GitHub account from Bubbly?')) return
    try {
      const res = await fetch('/api/link/github/unlink', { method: 'POST' })
      if (res.ok) {
        // Refresh user to reflect unlinked state
        await checkAuthStatus()
        alert('GitHub account unlinked')
      } else {
        alert('Failed to unlink GitHub')
      }
    } catch (e) {
      console.error('Unlink GitHub error:', e)
      alert('Failed to unlink GitHub')
    }
  }

  // Admin functions
  const fetchAdminBubbles = async () => {
    try {
      const response = await fetch('/api/admin/bubbles');
      if (response.ok) {
        const data = await response.json();
        setAdminBubbles(data.bubbles);
      } else {
        alert('Failed to fetch admin bubbles');
      }
    } catch (error) {
      alert('Failed to fetch admin bubbles');
    }
  };

  const fetchAdminUsers = async () => {
    try {
      const response = await fetch('/api/admin/users');
      if (response.ok) {
        const data = await response.json();
        setAdminUsers(data.users);
      } else {
        alert('Failed to fetch admin users');
      }
    } catch (error) {
      alert('Failed to fetch admin users');
    }
  };

  const fetchAdminStats = async () => {
    try {
      const response = await fetch('/api/admin/stats');
      if (response.ok) {
        const data = await response.json();
        setAdminStats(data);
      } else {
        alert('Failed to fetch admin stats');
      }
    } catch (error) {
      alert('Failed to fetch admin stats');
    }
  };

  const adminDeleteUser = async (userId, username) => {
    if (!confirm(`Are you sure you want to permanently delete user "${username}"? This will remove them from all bubbles and cannot be undone.`)) {
      return;
    }
    
    try {
      const response = await fetch(`/api/admin/users/${userId}/delete`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        const data = await response.json();
        alert(data.message);
        // Refresh the users list
        fetchAdminUsers();
      } else {
        const error = await response.json();
        alert(`Failed to delete user: ${error.error}`);
      }
    } catch (error) {
      alert('Failed to delete user');
    }
  };

  const adminKickUserFromBubble = async (bubbleId, userId, username, bubbleName) => {
    if (!confirm(`Are you sure you want to kick "${username}" from bubble "${bubbleName}"?`)) {
      return;
    }
    
    try {
      const response = await fetch(`/api/admin/bubbles/${bubbleId}/kick/${userId}`, {
        method: 'POST'
      });
      
      if (response.ok) {
        const data = await response.json();
        alert(data.message);
        // Refresh the bubbles list
        fetchAdminBubbles();
      } else {
        const error = await response.json();
        alert(`Failed to kick user: ${error.error}`);
      }
    } catch (error) {
      alert('Failed to kick user');
    }
  };

  if (loading) {
    return (
      <div className="bubbly-container">
        <div className="tropical-loading">
          <div className="bubble-loader"></div>
          <p>Loading your bubbly world...</p>
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
              <input type="text" name="username" placeholder="Username or Email" required />
              <input type="password" name="password" placeholder="Password" required />
              <button type="submit" className="tropical-btn">🏄‍♂️ Dive In</button>
              <button type="button" className="forgot-password-btn" onClick={() => setShowResetModal(true)}>
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

        <div className="about-section">
          <h2>What is Bubbly?</h2>
          <p>Bubbly lets you create and join social “bubbles” to connect accounts and take group actions in one place.</p>
          <h3>How it works</h3>
          <ul>
            <li>Create or join a bubble with an invite code</li>
            <li>Link GitHub to enable group actions</li>
            <li>Follow everyone in your bubble or have everyone follow you</li>
            <li>Bubble creators can manage members and roles</li>
          </ul>
        </div>

        {showResetModal && (
          <div className="modal-overlay" onClick={() => setShowResetModal(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              {resetStep === 'request' ? (
                <>
                  <h3>Reset your password</h3>
                  <form onSubmit={requestPasswordReset}>
                    <input type="email" placeholder="Your email" value={resetEmail} onChange={(e) => setResetEmail(e.target.value)} required />
                    <div className="modal-actions">
                      <button type="button" onClick={() => setShowResetModal(false)}>Cancel</button>
                      <button type="submit" className="tropical-btn">Send Code</button>
                    </div>
                  </form>
                </>
              ) : (
                <>
                  <h3>Enter the code we emailed you</h3>
                  <form onSubmit={submitPasswordReset}>
                    <input type="text" placeholder="6-digit code" value={resetCode} onChange={(e) => setResetCode(e.target.value)} required />
                    <input type="password" placeholder="New password" value={resetNewPassword} onChange={(e) => setResetNewPassword(e.target.value)} required />
                    <div className="modal-actions">
                      <button type="button" onClick={() => { setShowResetModal(false); setResetStep('request') }}>Cancel</button>
                      <button type="submit" className="tropical-btn">Reset Password</button>
                    </div>
                  </form>
                </>
              )}
            </div>
          </div>
        )}

      </div>
    )
  }

  // Main Dashboard
  return (
    <div className="bubbly-container">
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <h1>🫧 Bubbly Dashboard</h1>
          <div className="user-info">
            <span>Welcome, {user.display_name || user.username}!</span>
            <button onClick={logout} className="logout-btn">Logout</button>
            <button onClick={deleteAccount} className="logout-btn" title="Permanently delete your account">Delete Account</button>
          </div>
        </div>
        
        {/* Navigation */}
        <nav className="dashboard-nav">
          <button 
            onClick={() => setCurrentView('dashboard')} 
            className={`nav-btn ${currentView === 'dashboard' ? 'active' : ''}`}
          >
            🏠 My Bubbles
          </button>
                      <button 
              onClick={() => {
                setCurrentView('discover');
                fetchPublicBubbles();
              }} 
              className={`nav-btn ${currentView === 'discover' ? 'active' : ''}`}
            >
              🔍 Discover
            </button>
          <button 
            onClick={() => setCurrentView('profile')} 
            className={`nav-btn ${currentView === 'profile' ? 'active' : ''}`}
          >
            👤 Profile
          </button>
          {user.role === 'admin' && (
            <button 
              onClick={() => setCurrentView('admin')} 
              className={`nav-btn ${currentView === 'admin' ? 'active' : ''}`}
              style={{ backgroundColor: '#ff6b6b', color: 'white' }}
            >
              🛡️ Admin
            </button>
          )}
          <button onClick={() => setShowCreateModal(true)} className="create-btn">
            ➕ Create Bubble
          </button>
          <button onClick={() => setShowJoinModal(true)} className="join-btn">
            🎫 Join by Code
          </button>
        </nav>
      </div>

      {/* Main Content */}
      <div className="dashboard-content">
        {currentView === 'profile' && (
          <div className="profile-section">
            <h2>👤 Profile Settings</h2>
            <div className="profile-form">
              <div className="form-group">
                <label>Display Name:</label>
                <input
                  type="text"
                  value={profileDisplayName}
                  onChange={(e) => setProfileDisplayName(e.target.value)}
                  placeholder="Your display name"
                  maxLength="60"
                />
              </div>
              <div className="form-group">
                <label>Avatar URL:</label>
                <input
                  type="url"
                  value={profileAvatarUrl}
                  onChange={(e) => setProfileAvatarUrl(e.target.value)}
                  placeholder="https://example.com/avatar.jpg"
                />
              </div>
              <button onClick={saveProfile} className="tropical-btn">
                💾 Save Profile
              </button>
            </div>
          </div>
        )}

        {currentView === 'admin' && user.role === 'admin' && (
          <div className="admin-section">
            <h2>🛡️ Admin Panel</h2>
            <div className="admin-tabs">
              <button onClick={fetchAdminStats} className="admin-tab-btn">
                📊 Platform Stats
              </button>
              <button onClick={fetchAdminBubbles} className="admin-tab-btn">
                🌊 All Bubbles
              </button>
              <button onClick={fetchAdminUsers} className="admin-tab-btn">
                👥 All Users
              </button>
            </div>

            {adminStats && (
              <div className="admin-stats">
                <h3>📊 Platform Statistics</h3>
                <div className="stats-grid">
                  <div className="stat-card">
                    <h4>👥 Total Users</h4>
                    <p>{adminStats.stats.total_users}</p>
                  </div>
                  <div className="stat-card">
                    <h4>🌊 Total Bubbles</h4>
                    <p>{adminStats.stats.total_bubbles}</p>
                  </div>
                  <div className="stat-card">
                    <h4>🌍 Public Bubbles</h4>
                    <p>{adminStats.stats.public_bubbles}</p>
                  </div>
                  <div className="stat-card">
                    <h4>🔒 Private Bubbles</h4>
                    <p>{adminStats.stats.private_bubbles}</p>
                  </div>
                  <div className="stat-card">
                    <h4>🔗 Active Sessions</h4>
                    <p>{adminStats.stats.active_sessions}</p>
                  </div>
                  <div className="stat-card">
                    <h4>👥 Total Memberships</h4>
                    <p>{adminStats.stats.total_memberships}</p>
                  </div>
                </div>
                
                <div className="recent-activity">
                  <div className="recent-section">
                    <h4>🆕 Recent Users</h4>
                    <ul>
                      {adminStats.recent_users.map(user => (
                        <li key={user.username}>
                          <strong>{user.display_name}</strong> (@{user.username}) - {new Date(user.created_at).toLocaleDateString()}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="recent-section">
                    <h4>🌊 Recent Bubbles</h4>
                    <ul>
                      {adminStats.recent_bubbles.map((bubble, index) => (
                        <li key={index}>
                          <strong>{bubble.name}</strong> by @{bubble.creator} - {bubble.is_public ? '🌍' : '🔒'} - {new Date(bubble.created_at).toLocaleDateString()}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {adminBubbles.length > 0 && (
              <div className="admin-bubbles">
                <h3>🌊 All Bubbles ({adminBubbles.length})</h3>
                {adminBubbles.map(bubble => (
                  <div key={bubble.id} className="admin-bubble-section">
                    <div className="bubble-header-admin">
                      <h4>
                        {bubble.name} 
                        <span className="bubble-type">{bubble.is_public ? '🌍 Public' : '🔒 Private'}</span>
                      </h4>
                      <div className="bubble-meta">
                        <span>by @{bubble.creator_username}</span>
                        <span>Code: <code>{bubble.invite_code}</code></span>
                        <span>{new Date(bubble.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                    
                    <div className="bubble-members-admin">
                      <h5>👥 Members ({bubble.member_count}/{bubble.max_members})</h5>
                      <div className="members-grid">
                        {bubble.members && bubble.members.map(member => (
                          <div key={member.id} className="member-card">
                            <div className="member-info">
                              <strong>@{member.username}</strong>
                              <span className="member-name">{member.display_name}</span>
                              <span className={`role-badge ${member.role}`}>
                                {member.role === 'creator' ? '👑' : member.role === 'admin' ? '🛡️' : '👤'} {member.role}
                              </span>
                            </div>
                            {member.role !== 'creator' && (
                              <button 
                                onClick={() => adminKickUserFromBubble(bubble.id, member.id, member.username, bubble.name)}
                                className="admin-kick-btn"
                                title={`Kick ${member.username} from ${bubble.name}`}
                              >
                                👢 Kick
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {adminUsers.length > 0 && (
              <div className="admin-users">
                <h3>👥 All Users ({adminUsers.length})</h3>
                <div className="admin-table">
                  <table>
                    <thead>
                      <tr>
                        <th>Username</th>
                        <th>Display Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Bubbles Created</th>
                        <th>Bubbles Joined</th>
                        <th>Linked Platforms</th>
                        <th>Joined</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {adminUsers.map(user => (
                        <tr key={user.id}>
                          <td><strong>@{user.username}</strong></td>
                          <td>{user.display_name}</td>
                          <td>{user.email}</td>
                          <td>
                            <span className={`role-badge ${user.role}`}>
                              {user.role === 'admin' ? '🛡️' : '👤'} {user.role}
                            </span>
                          </td>
                          <td>{user.bubbles_created}</td>
                          <td>{user.bubbles_joined}</td>
                          <td>{user.linked_platforms || 'None'}</td>
                          <td>{new Date(user.created_at).toLocaleDateString()}</td>
                          <td>
                            {user.role !== 'admin' && (
                              <button 
                                onClick={() => adminDeleteUser(user.id, user.username)}
                                className="admin-delete-btn"
                                title="Delete User Account"
                              >
                                🗑️ Delete
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {currentView === 'dashboard' && (
          <div className="bubbles-grid">
            <h2>🌊 Your Bubble Communities</h2>
            {userBubbles.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">🫧</div>
                <p>You haven't joined any bubbles yet!</p>
                <button onClick={() => setShowCreateModal(true)} className="tropical-btn">
                  Create Your First Bubble
                </button>
              </div>
            ) : (
              <div className="bubbles-container">
                {userBubbles.map(bubble => (
                  <div 
                    key={bubble.id} 
                    className="bubble-card"
                    style={{
                      width: `${Math.min(700, Math.max(450, 300 + (bubble.member_count || 0) * 25))}px`
                    }}
                  >
                    <div className="bubble-header">
                      <h3>{bubble.name}</h3>
                      <div className="bubble-role">{bubble.role}</div>
                    </div>
                    <p className="bubble-description">{bubble.description || 'No description'}</p>
                                         <div className="bubble-stats">
                       <span>👥 {bubble.member_count} members</span>
                       <span>{bubble.is_public ? '🌍 Public' : '🔒 Private'}</span>
                     </div>
                     <div className="bubble-invite">
                       <span className="invite-label">Invite Code:</span>
                       <button 
                         className="invite-code-btn"
                         onClick={() => copyInviteCode(bubble.invite_code)}
                         title="Click to copy invite code"
                       >
                         {bubble.invite_code} 📋
                       </button>
                     </div>
                    <div className="bubble-actions">
                      <button 
                        onClick={() => {
                          setCurrentView('bubble')
                          fetchBubbleMembers(bubble.id)
                        }}
                        className="view-btn"
                      >
                        👁️ View
                      </button>
                      {bubble.role === 'creator' ? (
                        <button 
                          onClick={() => handleDeleteBubble(bubble.id)}
                          className="delete-btn"
                        >
                          🗑️ Delete
                        </button>
                      ) : (
                        <button 
                          onClick={() => handleLeaveBubble(bubble.id)}
                          className="leave-btn"
                        >
                          👋 Leave
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {currentView === 'discover' && (
          <div className="discover-section">
            <h2>🔍 Discover Public Bubbles</h2>
            {publicBubbles.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">🔍</div>
                <p>No public bubbles available to join right now.</p>
              </div>
            ) : (
              <div className="bubbles-container">
                {publicBubbles.map(bubble => (
                  <div 
                    key={bubble.id} 
                    className="bubble-card"
                                         style={{
                       width: `${Math.min(700, Math.max(450, 300 + (bubble.member_count || 0) * 25))}px`
                     }}
                  >
                    <div className="bubble-header">
                      <h3>{bubble.name}</h3>
                      <div className="bubble-creator">by {bubble.creator_name}</div>
                    </div>
                    <p className="bubble-description">{bubble.description || 'No description'}</p>
                    <div className="bubble-stats">
                      <span>👥 {bubble.member_count}/{bubble.max_members}</span>
                      <span>🌍 Public</span>
                    </div>
                    <div className="bubble-actions">
                      <button 
                        onClick={() => handleJoinBubble(bubble.id)}
                        className="join-btn"
                        disabled={bubble.member_count >= bubble.max_members}
                      >
                        {bubble.member_count >= bubble.max_members ? '🚫 Full' : '🎯 Join'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {currentView === 'bubble' && selectedBubble && (
          <div className="bubble-view">
                         <div className="bubble-view-header">
               <button onClick={() => setCurrentView('dashboard')} className="back-btn">
                 ← Back to Dashboard
               </button>
               <h2>🫧 {selectedBubble.name}</h2>
               <p>{selectedBubble.description}</p>
               <div className="bubble-invite-section">
                 <span className="invite-label">Invite Code:</span>
                 <button 
                   className="invite-code-btn large"
                   onClick={() => copyInviteCode(selectedBubble.invite_code)}
                   title="Click to copy invite code"
                 >
                   {selectedBubble.invite_code} 📋
                 </button>
               </div>
             </div>

            {/* Social Account Linking for Bubble Actions */}
            <div className="bubble-social-section">
              <h3>🔗 Link Social Accounts for Bubble Actions</h3>
              <div className="social-links">
                {user.social_accounts?.find(acc => acc.platform === 'github') ? (
                  <button className="github-link-btn linked" onClick={unlinkGitHub} title="Unlink GitHub">✅ GitHub Linked (click to unlink)</button>
                ) : (
                  <button onClick={linkGitHub} className="github-link-btn">
                    🐙 Link GitHub
                  </button>
                )}
              </div>
            </div>

            {/* Bubble Actions */}
            <div className="bubble-actions-section">
              <h3>🎯 Bubble Social Actions</h3>
              <div className="action-buttons">
                <button onClick={() => handleFollowInBubble('be-followed')} className="follow-me-btn">
                  🌟 Everyone in Bubble Follow Me
                </button>
                <button onClick={() => handleFollowInBubble('follow')} className="follow-all-btn">
                  🤝 I'll Follow Everyone in Bubble
                </button>
              </div>
            </div>

                         {/* Members */}
             <div className="bubble-members">
               <div className="members-header">
                 <h3>👥 Members ({bubbleMembers.length})</h3>
                 <button 
                   onClick={toggleFloating}
                   className={`floating-toggle-btn ${isFloatingEnabled ? 'enabled' : 'disabled'}`}
                   title={isFloatingEnabled ? 'Disable floating (line up bubbles)' : 'Enable floating'}
                 >
                   {isFloatingEnabled ? '🌊 Floating' : '📋 Lined Up'}
                 </button>
               </div>
               <div ref={containerRef} className={`floating-bubbles ${isFloatingEnabled ? 'floating' : 'lined-up'}`}>
                 {bubbleMembers.map((member, index) => {
                   const position = bubblePositions.get(member.id)
                   
                   // Calculate grid position for lined-up mode
                   const gridCols = Math.ceil(Math.sqrt(bubbleMembers.length))
                   const gridX = (index % gridCols) * (100 / gridCols) + (50 / gridCols)
                   const gridY = Math.floor(index / gridCols) * 25 + 15
                   
                   const bubbleStyle = isFloatingEnabled ? {
                     left: position?.x !== undefined ? `${position.x - 60}px` : '50%',
                     top: position?.y !== undefined ? `${position.y - 60}px` : '50%',
                     animation: 'none',
                     transition: 'transform 0s'
                   } : {
                     left: `${gridX}%`,
                     top: `${gridY}%`,
                     animation: 'none',
                     transition: 'all 0.8s cubic-bezier(0.4, 0, 0.6, 1)'
                   }
                   
                   return (
                     <div 
                       key={member.id} 
                       className={`floating-bubble ${member.id === user.id ? 'current-user' : ''} ${isFloatingEnabled ? '' : 'lined-up'}`}
                       style={bubbleStyle}
                     >
                     <div className="bubble-avatar">
                       {member.social_accounts && member.social_accounts.length > 0 ? (
                         <img 
                           src={member.social_accounts[0].avatar_url} 
                           alt={member.display_name}
                           onError={(e) => {
                             e.target.style.display = 'none';
                             e.target.nextSibling.style.display = 'flex';
                           }}
                         />
                       ) : null}
                       <div 
                         className="bubble-avatar-placeholder" 
                         style={{
                           display: member.social_accounts && member.social_accounts.length > 0 ? 'none' : 'flex'
                         }}
                       >
                         {member.display_name.charAt(0).toUpperCase()}
                       </div>
                     </div>
                     
                     <div className="bubble-info">
                       <div className="bubble-name">{member.display_name}</div>
                       <div className="bubble-role">{member.role}</div>
                       {member.social_accounts && member.social_accounts.length > 0 && (
                         <div className="bubble-social">
                           {member.social_accounts
                             .filter(acc => acc.platform === 'github')
                             .map((acc, idx) => (
                               <span key={idx} className={`social-badge ${acc.platform}`}>
                                 🐙
                               </span>
                             ))}
                         </div>
                       )}
                     </div>

                     {/* Management Actions for Creator/Admin - Don't show for current user */}
                     {member.id !== user.id && (selectedBubble?.user_role === 'creator' || selectedBubble?.user_role === 'admin') && (
                       <div className="bubble-actions">
                         {/* Kick action - Creators can kick anyone, Admins can only kick members */}
                         {(selectedBubble.user_role === 'creator' || 
                           (selectedBubble.user_role === 'admin' && member.role === 'member')) && (
                           <button 
                             className="kick-btn"
                             onClick={() => handleKickMember(selectedBubble.id, member.id, member.display_name)}
                             title="Kick member"
                           >
                             👢
                           </button>
                         )}
                         
                         {/* Promote/Demote actions (creator only) */}
                         {selectedBubble.user_role === 'creator' && member.role !== 'creator' && (
                           <button 
                             className="promote-btn"
                             onClick={() => handlePromoteMember(
                               selectedBubble.id, 
                               member.id, 
                               member.display_name, 
                               member.role === 'admin' ? 'demote' : 'promote'
                             )}
                             title={member.role === 'admin' ? 'Demote to member' : 'Promote to admin'}
                           >
                             {member.role === 'admin' ? '👇' : '👆'}
                           </button>
                         )}
                       </div>
                     )}

                     {/* Current user indicator */}
                     {member.id === user.id && (
                       <div className="current-user-indicator">👑</div>
                     )}
                   </div>
                   );
                 })}
               </div>
             </div>
          </div>
        )}
      </div>

      {/* Create Bubble Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>🫧 Create New Bubble</h3>
            <form onSubmit={handleCreateBubble}>
              <input type="text" name="name" placeholder="Bubble Name" required />
              <textarea name="description" placeholder="Description (optional)" rows="3"></textarea>
              <div className="form-row">
                <label>
                  <input type="checkbox" name="isPublic" defaultChecked />
                  Make this bubble public
                </label>
              </div>
              <div className="form-row">
                <label>
                  Max Members:
                  <input type="number" name="maxMembers" defaultValue="50" min="2" max="100" />
                </label>
              </div>
              <div className="modal-actions">
                <button type="button" onClick={() => setShowCreateModal(false)}>Cancel</button>
                <button type="submit" className="tropical-btn">Create Bubble</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Join by Code Modal */}
      {showJoinModal && (
        <div className="modal-overlay" onClick={() => setShowJoinModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>🎫 Join Bubble by Invite Code</h3>
            <form onSubmit={(e) => { e.preventDefault(); handleJoinBubble(); }}>
              <input 
                type="text" 
                placeholder="Enter invite code" 
                value={inviteCode}
                onChange={(e) => setInviteCode(e.target.value.toUpperCase())}
                required 
              />
              <div className="modal-actions">
                <button type="button" onClick={() => setShowJoinModal(false)}>Cancel</button>
                <button type="submit" className="tropical-btn">Join Bubble</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default App

