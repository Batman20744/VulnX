
import {
  LayoutDashboard,
  Server,
  Radar,
  ShieldAlert,
  Database,
  FileBarChart,
  Settings,
  ShieldCheck,
} from "lucide-react";

const navigation = [
  {
    title: "OVERVIEW",
    items: [
      { label: "Dashboard", icon: LayoutDashboard },
    ],
  },
  {
    title: "VULNERABILITY MANAGEMENT",
    items: [
      { label: "Assets", icon: Server },
      { label: "Vulnerability Scans", icon: Radar },
      { label: "Findings", icon: ShieldAlert },
      { label: "CVE Intelligence", icon: Database },
    ],
  },
  {
    title: "REPORTING",
    items: [
      { label: "Reports", icon: FileBarChart },
    ],
  },
];

function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">
          <ShieldCheck size={25} />
        </div>

        <div className="brand-info">
          <h2>VulnX</h2>
          <span>INTELLIGENCE PLATFORM</span>
        </div>
      </div>

      <div className="sidebar-version">
        <span>VERSION 1.0.0</span>
        <span className="version-status">● SYSTEM ACTIVE</span>
      </div>

      <nav className="sidebar-navigation">
        {navigation.map((section) => (
          <div className="nav-section" key={section.title}>
            <p className="nav-section-title">
              {section.title}
            </p>

            {section.items.map((item) => {
              const Icon = item.icon;
              const active = activePage === item.label;

              return (
                <button
                  key={item.label}
                  type="button"
                  onClick={() => onNavigate(item.label)}
                  className={`nav-item ${active ? "active" : ""}`}
                  aria-current={active ? "page" : undefined}
                >
                  <Icon size={18} strokeWidth={1.8} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <button
          type="button"
          onClick={() => onNavigate("Settings")}
          className={`nav-item ${
            activePage === "Settings" ? "active" : ""
          }`}
        >
          <Settings size={18} />
          <span>Settings</span>
        </button>

        <div className="sidebar-footer">
          <div className="footer-indicator" />
          <span>VulnX Security Engine</span>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
