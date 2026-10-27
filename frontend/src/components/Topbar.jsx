import React from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

function Topbar({ viewMode, onSwitchToLive }) {
  const { user } = useAuth();
  const navigate = useNavigate();

  const handleProfileClick = () => {
    navigate("/profile");
  };

  return (
    <header className="topbar">
      {/* LEFT BRAND */}
      <div className="topbar-left">
        <img src="/icons/icon.png" alt="SentraX" className="topbar-logo-img" />
        <span className="brand-name">SentraX</span>
        {viewMode === "history" && (
          <span className="mode-badge history-mode">
            📜 HISTORY MODE
            <button
              className="btn-exit-history"
              onClick={onSwitchToLive}
              title="Return to live dashboard"
            >
              ✕
            </button>
          </span>
        )}
      </div>

      {/* CENTER MESSAGE */}
      <div className="topbar-center">
        Welcome back, <b>{user?.name || "User"}</b>
      </div>

      {/* RIGHT ICONS */}
      <div className="topbar-right">
        <span className="top-icon">🔔</span>
        <span className="top-icon">⚙️</span>

        {/* USER AVATAR WITH INITIAL */}
        <div
          className="user-avatar"
          onClick={handleProfileClick}
          title={`${user?.name || "User"} - Click to view profile`}
        >
          {user?.name?.charAt(0).toUpperCase() || "U"}
        </div>
      </div>
    </header>
  );
}

export default Topbar;
