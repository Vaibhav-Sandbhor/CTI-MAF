import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import { getCurrentUser, getUserSessions, updateProfile, changePassword } from "../services/api.js";
import "../styles/profile.css";

function Profile() {
  const navigate = useNavigate();
  const { user: authUser, logout } = useAuth();
  const [user, setUser] = useState(null);
  const [stats, setStats] = useState({
    totalSessions: 0,
    totalThreats: 0,
    lastScanTime: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  
  // Modal states
  const [showEditModal, setShowEditModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  
  // Edit profile form
  const [editName, setEditName] = useState("");
  const [editRole, setEditRole] = useState("");
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState("");
  const [editSuccess, setEditSuccess] = useState("");
  
  // Change password form
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordError, setPasswordError] = useState("");
  const [passwordSuccess, setPasswordSuccess] = useState("");

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        setLoading(true);
        setError("");
        
        // Fetch user profile with timeout
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error("Request timed out")), 10000)
        );
        
        const userData = await Promise.race([
          getCurrentUser(),
          timeoutPromise
        ]);
        
        if (userData.detail) {
          throw new Error(userData.detail);
        }
        setUser(userData);
        setEditName(userData.name || "");
        setEditRole(userData.role || "Analyst");

        // Fetch session stats (non-blocking)
        try {
          const sessionsData = await getUserSessions();
          if (sessionsData.sessions) {
            const sessions = sessionsData.sessions;
            setStats({
              totalSessions: sessions.length,
              totalThreats: sessions.reduce((acc, s) => acc + (s.threat_count || 0), 0),
              lastScanTime: sessions[0]?.end_time || sessions[0]?.start_time || null,
            });
          }
        } catch (sessionErr) {
          console.log("Could not fetch session stats:", sessionErr);
        }

      } catch (err) {
        console.error("Profile fetch error:", err);
        setError(err.message || "Failed to load profile");
      } finally {
        setLoading(false);
      }
    };

    fetchUserData();
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate("/", { replace: true });
  };

  const handleEditProfile = async (e) => {
    e.preventDefault();
    setEditError("");
    setEditSuccess("");
    setEditLoading(true);
    
    try {
      const updated = await updateProfile({ name: editName, role: editRole });
      setUser(updated);
      setEditSuccess("Profile updated successfully!");
      setTimeout(() => {
        setShowEditModal(false);
        setEditSuccess("");
      }, 1500);
    } catch (err) {
      setEditError(err.message);
    } finally {
      setEditLoading(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPasswordError("");
    setPasswordSuccess("");
    
    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords do not match");
      return;
    }
    
    if (newPassword.length < 6) {
      setPasswordError("New password must be at least 6 characters");
      return;
    }
    
    setPasswordLoading(true);
    
    try {
      await changePassword(currentPassword, newPassword);
      setPasswordSuccess("Password changed successfully!");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setTimeout(() => {
        setShowPasswordModal(false);
        setPasswordSuccess("");
      }, 1500);
    } catch (err) {
      setPasswordError(err.message);
    } finally {
      setPasswordLoading(false);
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return "Never";
    try {
      const date = new Date(dateStr);
      return date.toLocaleString("en-US", {
        weekday: "short",
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return dateStr;
    }
  };

  const getInitials = (name) => {
    if (!name) return "?";
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  if (loading) {
    return (
      <div className="profile-container">
        <div className="profile-loading">
          <div className="loading-spinner"></div>
          <p>Loading profile...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="profile-container">
        <div className="profile-error">
          <span className="error-icon">⚠️</span>
          <p>{error}</p>
          <button onClick={() => window.location.reload()}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div className="profile-container">
      {/* Back to Dashboard Button */}
      <button 
        className="back-to-dashboard-btn"
        onClick={() => navigate("/", { replace: true })}
        style={{
          position: "absolute",
          top: "20px",
          left: "20px",
          display: "flex",
          alignItems: "center",
          gap: "8px",
          padding: "10px 18px",
          background: "linear-gradient(135deg, #2a2a4a 0%, #1a1a2e 100%)",
          border: "1px solid #3a3a5a",
          borderRadius: "8px",
          color: "#7c83fd",
          fontSize: "14px",
          fontWeight: "600",
          cursor: "pointer",
          transition: "all 0.2s ease",
          zIndex: 10,
        }}
        onMouseEnter={(e) => {
          e.target.style.background = "linear-gradient(135deg, #3a3a5a 0%, #2a2a4a 100%)";
          e.target.style.borderColor = "#7c83fd";
        }}
        onMouseLeave={(e) => {
          e.target.style.background = "linear-gradient(135deg, #2a2a4a 0%, #1a1a2e 100%)";
          e.target.style.borderColor = "#3a3a5a";
        }}
      >
        <span style={{ fontSize: "16px" }}>←</span>
        Back to Dashboard
      </button>

      {/* Header Section */}
      <div className="profile-header">
        <div className="profile-avatar">
          <span className="avatar-initials">{getInitials(user?.name)}</span>
        </div>
        <h1 className="profile-name">{user?.name || "Unknown User"}</h1>
        <p className="profile-role">{user?.role || "Security Analyst"}</p>
      </div>

      {/* User Info Card */}
      <div className="profile-section">
        <h2 className="section-title">
          <span className="section-icon">👤</span>
          Account Information
        </h2>
        <div className="profile-card">
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">Full Name</span>
              <span className="info-value">{user?.name || "N/A"}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Email Address</span>
              <span className="info-value">{user?.email || "N/A"}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Role</span>
              <span className="info-value role-badge">{user?.role || "Analyst"}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Last Login</span>
              <span className="info-value">{formatDate(user?.last_login)}</span>
            </div>
            <div className="info-item">
              <span className="info-label">Account Created</span>
              <span className="info-value">{formatDate(user?.created_at)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Account Stats */}
      <div className="profile-section">
        <h2 className="section-title">
          <span className="section-icon">📊</span>
          Activity Statistics
        </h2>
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon">📋</div>
            <div className="stat-value">{stats.totalSessions}</div>
            <div className="stat-label">Total Sessions</div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">🛡️</div>
            <div className="stat-value">{stats.totalThreats}</div>
            <div className="stat-label">Threats Monitored</div>
          </div>
          <div className="stat-card">
            <div className="stat-icon">🕐</div>
            <div className="stat-value stat-time">
              {stats.lastScanTime ? formatDate(stats.lastScanTime).split(",")[0] : "N/A"}
            </div>
            <div className="stat-label">Last Scan</div>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="profile-section">
        <h2 className="section-title">
          <span className="section-icon">⚙️</span>
          Account Actions
        </h2>
        <div className="actions-grid">
          <button className="action-btn" onClick={() => setShowPasswordModal(true)}>
            <span className="btn-icon">🔑</span>
            Change Password
          </button>
          <button className="action-btn" onClick={() => setShowEditModal(true)}>
            <span className="btn-icon">✏️</span>
            Edit Profile
          </button>
          <button className="action-btn logout-action" onClick={handleLogout}>
            <span className="btn-icon">🚪</span>
            Logout
          </button>
        </div>
      </div>

      {/* Edit Profile Modal */}
      {showEditModal && (
        <div className="modal-overlay" onClick={() => setShowEditModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>✏️ Edit Profile</h3>
              <button className="modal-close" onClick={() => setShowEditModal(false)}>×</button>
            </div>
            <form onSubmit={handleEditProfile}>
              <div className="form-group">
                <label>Full Name</label>
                <input
                  type="text"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  placeholder="Enter your name"
                  required
                />
              </div>
              <div className="form-group">
                <label>Role</label>
                <select value={editRole} onChange={(e) => setEditRole(e.target.value)}>
                  <option value="Analyst">Analyst</option>
                  <option value="Senior Analyst">Senior Analyst</option>
                  <option value="SOC Manager">SOC Manager</option>
                  <option value="Security Engineer">Security Engineer</option>
                  <option value="Administrator">Administrator</option>
                </select>
              </div>
              {editError && <div className="form-error">{editError}</div>}
              {editSuccess && <div className="form-success">{editSuccess}</div>}
              <div className="form-actions">
                <button type="button" className="btn-cancel" onClick={() => setShowEditModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-submit" disabled={editLoading}>
                  {editLoading ? "Saving..." : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Change Password Modal */}
      {showPasswordModal && (
        <div className="modal-overlay" onClick={() => setShowPasswordModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>🔑 Change Password</h3>
              <button className="modal-close" onClick={() => setShowPasswordModal(false)}>×</button>
            </div>
            <form onSubmit={handleChangePassword}>
              <div className="form-group">
                <label>Current Password</label>
                <input
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  placeholder="Enter current password"
                  required
                />
              </div>
              <div className="form-group">
                <label>New Password</label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password (min 6 chars)"
                  required
                  minLength={6}
                />
              </div>
              <div className="form-group">
                <label>Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  required
                />
              </div>
              {passwordError && <div className="form-error">{passwordError}</div>}
              {passwordSuccess && <div className="form-success">{passwordSuccess}</div>}
              <div className="form-actions">
                <button type="button" className="btn-cancel" onClick={() => setShowPasswordModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn-submit" disabled={passwordLoading}>
                  {passwordLoading ? "Changing..." : "Change Password"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default Profile;
