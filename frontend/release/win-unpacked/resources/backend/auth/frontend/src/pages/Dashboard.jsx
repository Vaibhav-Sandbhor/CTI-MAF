import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { LogOut, User, Mail, Calendar, Loader, AlertCircle } from 'lucide-react'
import { authAPI } from '../services/api'
import { useAuth } from '../context/AuthContext'
import '../styles/auth.css'

function Dashboard() {
  const navigate = useNavigate()
  const { logout, user: authUser } = useAuth()
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const response = await authAPI.getProfile()
        setUser(response.data)
        setLoading(false)
      } catch (err) {
        const errorMessage = err.response?.data?.detail || 'Failed to load profile'
        setError(errorMessage)
        setLoading(false)
      }
    }

    if (authUser) {
      setUser(authUser)
      setLoading(false)
    } else {
      fetchProfile()
    }
  }, [authUser])

  const handleLogout = async () => {
    try {
      await authAPI.logout()
    } catch (err) {
      console.error('Logout error:', err)
    } finally {
      logout()
      navigate('/login')
    }
  }

  if (loading) {
    return (
      <div className="auth-container">
        <div className="loading-container">
          <Loader size={40} className="spinner-large" />
          <p>Loading your profile...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="auth-container">
        <div className="error-container">
          <AlertCircle size={40} />
          <h2>Error</h2>
          <p>{error}</p>
          <button className="submit-btn" onClick={() => navigate('/login')}>
            Back to Login
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="auth-container">
      <div className="dashboard-card">
        <div className="dashboard-header">
          <h1>Welcome to CyberSIEM</h1>
          <p>Your Cybersecurity Intelligence Platform</p>
        </div>

        {user && (
          <div className="profile-section">
            <div className="welcome-message">
              <h2>Hello, {user.name}! 👋</h2>
              <p>You successfully logged in to CyberSIEM Authentication System</p>
            </div>

            <div className="profile-info">
              <div className="info-card">
                <div className="info-icon">
                  <User size={24} />
                </div>
                <div className="info-content">
                  <label>Full Name</label>
                  <p>{user.name}</p>
                </div>
              </div>

              <div className="info-card">
                <div className="info-icon">
                  <Mail size={24} />
                </div>
                <div className="info-content">
                  <label>Email Address</label>
                  <p>{user.email}</p>
                </div>
              </div>

              <div className="info-card">
                <div className="info-icon">
                  <Calendar size={24} />
                </div>
                <div className="info-content">
                  <label>Account Created</label>
                  <p>{new Date(user.created_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                  })}</p>
                </div>
              </div>
            </div>

            <div className="dashboard-actions">
              <div className="feature-info">
                <h3>🔒 Security Features</h3>
                <ul>
                  <li>✓ JWT Token-based Authentication</li>
                  <li>✓ Bcrypt Password Hashing</li>
                  <li>✓ Secure Session Management</li>
                  <li>✓ Protected API Endpoints</li>
                </ul>
              </div>

              <button className="logout-btn" onClick={handleLogout}>
                <LogOut size={18} />
                Logout
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default Dashboard
