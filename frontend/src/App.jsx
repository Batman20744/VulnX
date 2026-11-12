
import { useState } from "react";
import {
  Settings as SettingsIcon,
  User,
  Bell,
  Palette,
  ScanSearch,
  ShieldCheck,
  Server,
  Save,
} from "lucide-react";

import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Scans from "./pages/Scans";
import Findings from "./pages/Findings";
import CVEIntelligence from "./pages/CVEIntelligence";
import Reports from "./pages/Reports";

import "./styles/theme.css";
import "./App.css";

function SettingsPage() {
  const [preferences, setPreferences] = useState({
    securityAlerts: true,
    scanNotifications: true,
    emailNotifications: false,
    autoRefresh: true,
    compactLayout: false,
    includeLowSeverity: true,
  });

  const [saved, setSaved] = useState(false);

  const updatePreference = (key) => {
    setPreferences((previous) => ({
      ...previous,
      [key]: !previous[key],
    }));
    setSaved(false);
  };

  const Toggle = ({ label, description, setting }) => (
    <div className="settings-option">
      <div>
        <strong>{label}</strong>
        <p>{description}</p>
      </div>

      <button
        type="button"
        role="switch"
        aria-checked={preferences[setting]}
        className={`settings-toggle ${
          preferences[setting] ? "enabled" : ""
        }`}
        onClick={() => updatePreference(setting)}
      >
        <span />
      </button>
    </div>
  );

  return (
    <section className="dashboard-content settings-page">
      <div className="dashboard-heading">
        <div>
          <p className="eyebrow">VULNX CONFIGURATION</p>
          <h2>Settings</h2>
          <p className="dashboard-description">
            Manage your security platform preferences.
          </p>
        </div>
      </div>

      {/* Account */}
      <div className="chart-card settings-card">
        <div className="settings-card-heading">
          <User size={19} />
          <div>
            <h3>Account Settings</h3>
            <p>Administrator account information</p>
          </div>
        </div>

        <div className="settings-info">
          <span>Account name</span>
          <strong>Security Admin</strong>
        </div>

        <div className="settings-info">
          <span>Role</span>
          <strong>Administrator</strong>
        </div>

        <div className="settings-info">
          <span>Account status</span>
          <strong className="settings-active">Active</strong>
        </div>
      </div>

      {/* Appearance */}
      <div className="chart-card settings-card">
        <div className="settings-card-heading">
          <Palette size={19} />
          <div>
            <h3>Appearance</h3>
            <p>Dashboard display preferences</p>
          </div>
        </div>

        <div className="settings-option">
          <div>
            <strong>Dashboard theme</strong>
            <p>Current VulnX black and teal theme</p>
          </div>
          <span className="settings-theme-label">
            Dark / Teal
          </span>
        </div>

        <Toggle
          label="Compact layout"
          description="Use a more compact dashboard layout."
          setting="compactLayout"
        />
      </div>

      {/* Notifications */}
      <div className="chart-card settings-card">
        <div className="settings-card-heading">
          <Bell size={19} />
          <div>
            <h3>Notifications</h3>
            <p>Manage security notification preferences</p>
          </div>
        </div>

        <Toggle
          label="Security alerts"
          description="Enable security alert notifications."
          setting="securityAlerts"
        />

        <Toggle
          label="Scan notifications"
          description="Enable notifications for completed scans."
          setting="scanNotifications"
        />

        <Toggle
          label="Email notifications"
          description="Email delivery preference (requires email integration)."
          setting="emailNotifications"
        />
      </div>

      {/* Scan Preferences */}
      <div className="chart-card settings-card">
        <div className="settings-card-heading">
          <ScanSearch size={19} />
          <div>
            <h3>Scan Preferences</h3>
            <p>Configure vulnerability scan preferences</p>
          </div>
        </div>

        <Toggle
          label="Include low severity findings"
          description="Display low severity findings in scan results."
          setting="includeLowSeverity"
        />

        <Toggle
          label="Automatic dashboard refresh"
          description="Enable automatic dashboard refresh preference."
          setting="autoRefresh"
        />
      </div>

      {/* System Information */}
      <div className="chart-card settings-card">
        <div className="settings-card-heading">
          <Server size={19} />
          <div>
            <h3>System Information</h3>
            <p>VulnX platform information</p>
          </div>
        </div>

        <div className="settings-info">
          <span>Platform</span>
          <strong>VulnX</strong>
        </div>

        <div className="settings-info">
          <span>Version</span>
          <strong>1.0.0</strong>
        </div>

        <div className="settings-info">
          <span>Backend API</span>
          <strong className="settings-active">
            http://127.0.0.1:8001
          </strong>
        </div>
      </div>

      <div className="settings-save-area">
        <span>
          {saved ? "Preferences saved for this session." : ""}
        </span>

        <button
          className="settings-save-button"
          onClick={() => setSaved(true)}
        >
          <Save size={16} />
          Save Preferences
        </button>
      </div>
    </section>
  );
}

function App() {
  const [activePage, setActivePage] = useState("Dashboard");

  return (
    <div className="app-layout">
      <Sidebar
        activePage={activePage}
        onNavigate={setActivePage}
      />

      <main className="main-area">
        <Navbar onNavigate={setActivePage} />

    {activePage === "Dashboard" ? (
  <Dashboard />
) : activePage === "Assets" ? (
  <Assets />
) : activePage === "Vulnerability Scans" ? (
  <Scans />
) : activePage === "Findings" ? (
  <Findings />
) : activePage === "CVE Intelligence" ? (
  <CVEIntelligence />
  ) : activePage === "Reports" ? (
  <Reports />
) : activePage === "Settings" ? (
  <SettingsPage />
) : (
          <section className="dashboard-content">
            <div className="dashboard-heading">
              <div>
                <p className="eyebrow">VULNX MANAGEMENT</p>
                <h2>{activePage}</h2>
                <p className="dashboard-description">
                  {activePage} management in VulnX v1.0.0.
                </p>
              </div>
            </div>

            <div className="chart-card">
              <h3>{activePage}</h3>
              <p className="dashboard-description">
                Navigation is working. This section will be
                connected to its dedicated interface next.
              </p>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
