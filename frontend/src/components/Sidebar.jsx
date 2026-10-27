import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

function Sidebar() {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/", { replace: true });
  };

  return (
    <aside className="sidebar">
      {/* TOP SECTION - Scrollable */}
      <div className="sidebar-top">
        <h2 className="logo">SentraX</h2>
        <ul>
          <li><Link to="/">Dashboard</Link></li>
          <li className="divider"></li>
          <li className="history-item"><Link to="/sessions">📊 Sessions</Link></li>
        </ul>
      </div>

      {/* BOTTOM SECTION - Fixed, Always Visible */}
      <div className="sidebar-bottom">
        <Link to="/profile" className="sidebar-footer-link">
          👤 Profile
        </Link>
        <button className="logout-btn" onClick={handleLogout}>
          🚪 Logout
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
