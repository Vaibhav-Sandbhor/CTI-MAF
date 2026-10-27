import React from "react";
import { Link } from "react-router-dom";
import "../styles/landing.css";

function LandingPage() {
  return (
    <div className="landing-page">
      {/* Top Navbar */}
      <nav className="landing-nav">
        <div className="landing-nav-left">
          <img src="/icons/icon.png" alt="SentraX" className="landing-logo-img" />
          <span className="landing-brand">SentraX</span>
        </div>
        <div className="landing-nav-right">
          <Link to="/login" className="nav-btn nav-btn-login">
            Login
          </Link>
          <Link to="/register" className="nav-btn nav-btn-register">
            Register
          </Link>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="landing-hero">
        <div className="hero-content">
          <div className="hero-logo-container">
            <img src="/icons/icon.png" alt="SentraX" className="hero-logo" />
          </div>
          <h1 className="hero-title">SentraX</h1>
          <p className="hero-subtitle">
            Cyber Threat Intelligence Using Multi-Agent FrameWork
          </p>
          <p className="hero-description">
            AI-powered multi-agent system for real-time ransomware detection, port scanning analysis, and honeypot-based threat intelligence.
          </p>

          <div className="hero-cta">
            <Link to="/login" className="cta-btn cta-primary">
              Get Started
            </Link>
            <Link to="/register" className="cta-btn cta-secondary">
              Create Account
            </Link>
          </div>
        </div>

        {/* Feature Cards */}
        <div className="features-grid">
          <div className="feature-card">
            <div className="feature-icon">🔒</div>
            <h3 className="feature-title">AI Ransomware Detection</h3>
            <p className="feature-desc">
              LSTM-based ransomware detection using behavioral analysis
              and real-time process monitoring.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🌐</div>
            <h3 className="feature-title">Port Scan Monitoring</h3>
            <p className="feature-desc">
              Continuous network surveillance with CVSS-based risk scoring and
              vulnerability prioritization.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🍯</div>
            <h3 className="feature-title">Honeypot System</h3>
            <p className="feature-desc">
              Decoy file monitoring to detect and analyze malicious file access
              patterns and intrusion attempts.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="landing-footer">
        <p>© 2026 SentraX - Real-Time Cyber Threat Intelligence</p>
      </footer>
    </div>
  );
}

export default LandingPage;
