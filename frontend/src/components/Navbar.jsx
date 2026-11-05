
import { useState } from "react";
import {
  Search,
  Bell,
  ChevronDown,
  ShieldCheck,
  Menu,
  User,
  Settings,
  LogOut,
  X,
  CheckCircle
} from "lucide-react";

function Navbar() {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  const toggleNotifications = () => {
    setShowNotifications(!showNotifications);
    setShowProfile(false);
  };

  const toggleProfile = () => {
    setShowProfile(!showProfile);
    setShowNotifications(false);
  };

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button className="mobile-menu" aria-label="Open navigation">
          <Menu size={21} />
        </button>

        <div>
          <div className="breadcrumb">
            <span>VulnX</span>
            <span>/</span>
            <span className="breadcrumb-active">Overview</span>
          </div>
          <h1 className="page-title">Security Dashboard</h1>
        </div>
      </div>

      <div className="topbar-right">
        <div className="global-search">
          <Search size={17} />
          <input
            type="text"
            placeholder="Search CVEs, assets, findings..."
            aria-label="Search"
          />
          <kbd>⌘ K</kbd>
        </div>

        <div className="topbar-status">
          <span className="status-dot" />
          <span>All systems operational</span>
        </div>

        {/* Notifications */}
        <div className="navbar-dropdown-wrapper">
          <button
            className="icon-button notification-button"
            aria-label="Notifications"
            aria-expanded={showNotifications}
            onClick={toggleNotifications}
          >
            <Bell size={19} />
            <span className="notification-dot" />
          </button>

          {showNotifications && (
            <div className="navbar-dropdown notification-dropdown">
              <div className="dropdown-header">
                <strong>Notifications</strong>
                <button
                  className="dropdown-close"
                  onClick={() => setShowNotifications(false)}
                  aria-label="Close notifications"
                >
                  <X size={16} />
                </button>
              </div>

              <div className="notification-empty">
                <CheckCircle size={28} />
                <strong>You're all caught up</strong>
                <span>No new notifications available.</span>
              </div>

              <div className="dropdown-footer">
                VulnX Security Notifications
              </div>
            </div>
          )}
        </div>

        {/* Administrator Profile */}
        <div className="navbar-dropdown-wrapper">
          <button
            className="profile-menu"
            onClick={toggleProfile}
            aria-expanded={showProfile}
            aria-label="Open administrator profile"
          >
            <div className="profile-avatar">
              <ShieldCheck size={19} />
            </div>

            <div className="profile-info">
              <strong>Security Admin</strong>
              <span>Administrator</span>
            </div>

            <ChevronDown size={16} />
          </button>

          {showProfile && (
            <div className="navbar-dropdown profile-dropdown">
              <div className="profile-dropdown-header">
                <div className="profile-avatar">
                  <ShieldCheck size={22} />
                </div>
                <div>
                  <strong>Security Admin</strong>
                  <span>Administrator</span>
                </div>
              </div>

              <div className="profile-detail">
                <User size={16} />
                <span>Account: Security Administrator</span>
              </div>

              <div className="profile-detail">
                <CheckCircle size={16} />
                <span>Status: Active</span>
              </div>

              <div className="profile-divider" />

              <button
                className="profile-action"
                onClick={() => {
                  setShowProfile(false);
                  window.location.hash = "settings";
                }}
              >
                <Settings size={16} />
                Settings
              </button>

              <div className="profile-detail">
                <LogOut size={16} />
                <span>Sign out unavailable</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

export default Navbar;
