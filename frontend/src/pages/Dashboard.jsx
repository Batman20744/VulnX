
import { useEffect, useState } from "react";

import {
  ShieldAlert,
  Server,
  ShieldCheck,
  Activity,
  RefreshCw,
  AlertTriangle,
} from "lucide-react";

import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
} from "recharts";

import StatCard from "../components/StatCard";
import ChartCard from "../components/ChartCard";
import SecurityCharts from "../components/SecurityCharts";
import api from "../services/api";

// Official VulnX emerald chart palette
const SEVERITY_COLORS = {
  CRITICAL: "#176B60",
  HIGH: "#218675",
  MEDIUM: "#2A9D8F",
  LOW: "#74C7B8",
};

function Dashboard() {
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);
  const [riskSummary, setRiskSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Fetch live VulnX backend data
  async function loadDashboard() {
    setLoading(true);
    setError("");

    try {
      const [
        assetData,
        findingData,
        riskData,
        scanData,
      ] = await Promise.all([
        api.getAssets(),
        api.getFindings(),
        api.getRiskSummary(),
        api.getScans(),
      ]);

      setAssets(
        Array.isArray(assetData) ? assetData : []
      );

      setFindings(
        Array.isArray(findingData) ? findingData : []
      );

      setRiskSummary(riskData);

      setScans(
        Array.isArray(scanData) ? scanData : []
      );
    } catch (err) {
      setError(
        "Unable to load dashboard data. Check the VulnX backend."
      );

      console.error("Dashboard loading error:", err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();
  }, []);

  // Severity distribution
  const severityData = riskSummary
    ? [
        {
          name: "Critical",
          value: riskSummary.critical ?? 0,
        },
        {
          name: "High",
          value: riskSummary.high ?? 0,
        },
        {
          name: "Medium",
          value: riskSummary.medium ?? 0,
        },
        {
          name: "Low",
          value: riskSummary.low ?? 0,
        },
      ].filter((item) => item.value > 0)
    : [];

  // Highest-risk findings first
  const recentFindings = [...findings]
    .sort(
      (a, b) =>
        (b.risk_score ?? 0) -
        (a.risk_score ?? 0)
    )
    .slice(0, 5);

  // Latest scans first
  const recentScans = [...scans]
    .sort(
      (a, b) =>
        new Date(b.started_at) -
        new Date(a.started_at)
    )
    .slice(0, 5);

  return (
    <div className="dashboard-content">

      {/* Dashboard heading */}

      <div className="dashboard-heading">
        <div>
          <p className="eyebrow">
            SECURITY OVERVIEW
          </p>

          <h2>
            Threat Intelligence Overview
          </h2>

          <p className="dashboard-description">
            Monitor assets, vulnerabilities and security
            risk across your environment.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadDashboard}
          disabled={loading}
        >
          <RefreshCw size={16} />
          {loading ? "Refreshing..." : "Refresh data"}
        </button>
      </div>

      {/* API error */}

      {error && (
        <div className="dashboard-error">
          <AlertTriangle size={18} />
          {error}
        </div>
      )}

      {/* KPI cards */}

      <div className="stats-grid">

        <StatCard
          title="Total Assets"
          value={loading ? "..." : assets.length}
          subtitle="Registered assets"
          icon={Server}
        />

        <StatCard
          title="Total Findings"
          value={
            loading
              ? "..."
              : riskSummary?.total_findings ?? 0
          }
          subtitle="Recorded findings"
          icon={ShieldAlert}
          variant="warning"
        />

        <StatCard
          title="Critical Findings"
          value={
            loading
              ? "..."
              : riskSummary?.critical ?? 0
          }
          subtitle="Critical risk priority"
          icon={AlertTriangle}
          variant="critical"
        />

        <StatCard
          title="KEV Findings"
          value={
            loading
              ? "..."
              : riskSummary?.kev_findings ?? 0
          }
          subtitle="Known exploited vulnerabilities"
          icon={ShieldCheck}
          variant="success"
        />

      </div>

      {/* Advanced security visualizations */}

      <SecurityCharts
        assets={assets}
        findings={findings}
        scans={scans}
      />

      {/* Severity and risk overview */}

      <div className="dashboard-grid">

        <ChartCard
          title="Vulnerability Severity"
          subtitle="Distribution of recorded findings"
          className="severity-panel"
        >

          {loading ? (
            <div className="empty-state">
              Loading severity data...
            </div>
          ) : severityData.length > 0 ? (

            <div className="severity-chart">

              <ResponsiveContainer
                width="100%"
                height={230}
              >
                <PieChart>

                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={62}
                    outerRadius={88}
                    paddingAngle={4}
                    stroke="#0A0F0E"
                    strokeWidth={2}
                  >

                    {severityData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={
                          SEVERITY_COLORS[
                            entry.name.toUpperCase()
                          ]
                        }
                      />
                    ))}

                  </Pie>

                  <Tooltip
                    contentStyle={{
                      background: "#111B19",
                      border: "1px solid #1F332F",
                      borderRadius: "8px",
                      color: "#E6EEEA",
                    }}
                  />

                </PieChart>
              </ResponsiveContainer>

              <div className="severity-legend">

                {severityData.map((item) => (
                  <div
                    className="legend-item"
                    key={item.name}
                  >

                    <span
                      className="legend-dot"
                      style={{
                        background:
                          SEVERITY_COLORS[
                            item.name.toUpperCase()
                          ],
                      }}
                    />

                    <span>{item.name}</span>

                    <strong>{item.value}</strong>

                  </div>
                ))}

              </div>

            </div>

          ) : (
            <div className="empty-state">
              No findings recorded yet.
            </div>
          )}

        </ChartCard>

        {/* Risk score */}

        <ChartCard
          title="Risk Score Overview"
          subtitle="Average calculated finding risk"
          className="risk-panel"
        >

          <div className="risk-overview">

            <div className="risk-score">

              <span className="risk-number">
                {loading
                  ? "--"
                  : riskSummary?.average_risk_score ?? 0}
              </span>

              <span className="risk-out-of">
                / 100
              </span>

            </div>

            <div className="risk-progress">

              <div
                className="risk-progress-fill"
                style={{
                  width: `${Math.min(
                    riskSummary?.average_risk_score ?? 0,
                    100
                  )}%`,
                }}
              />

            </div>

            <p>
              <Activity size={15} />
              Average risk score across recorded findings
            </p>

          </div>

          <div className="risk-breakdown">

            <div>
              <span>Critical</span>
              <strong>
                {riskSummary?.critical ?? 0}
              </strong>
            </div>

            <div>
              <span>High</span>
              <strong>
                {riskSummary?.high ?? 0}
              </strong>
            </div>

            <div>
              <span>Medium</span>
              <strong>
                {riskSummary?.medium ?? 0}
              </strong>
            </div>

            <div>
              <span>Low</span>
              <strong>
                {riskSummary?.low ?? 0}
              </strong>
            </div>

          </div>

        </ChartCard>

      </div>

      {/* Recent findings and scans */}

      <div className="dashboard-grid">

        <ChartCard
          title="Recent Vulnerability Findings"
          subtitle="Highest calculated risk scores first"
          className="findings-panel"
        >

          {loading ? (
            <div className="empty-state">
              Loading findings...
            </div>
          ) : recentFindings.length > 0 ? (

            <div className="table-wrapper">

              <table className="data-table">

                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Severity</th>
                    <th>Risk Score</th>
                    <th>Status</th>
                  </tr>
                </thead>

                <tbody>

                  {recentFindings.map((finding) => (
                    <tr key={finding.id}>

                      <td>
                        <strong>
                          {finding.cve_id}
                        </strong>

                        {finding.cve_id?.startsWith(
                          "CVE-2099-"
                        ) && (
                          <span className="test-label">
                            TEST
                          </span>
                        )}
                      </td>

                      <td>
                        <span
                          className={`severity-badge ${
                            finding.severity?.toLowerCase()
                          }`}
                        >
                          {finding.severity}
                        </span>
                      </td>

                      <td>
                        {finding.risk_score ?? "--"}
                      </td>

                      <td>
                        {finding.status}
                      </td>

                    </tr>
                  ))}

                </tbody>

              </table>

            </div>

          ) : (
            <div className="empty-state">
              No findings available.
            </div>
          )}

        </ChartCard>

        {/* Recent scans */}

        <ChartCard
          title="Recent Scans"
          subtitle="Latest vulnerability assessment activity"
          className="scans-panel"
        >

          {loading ? (
            <div className="empty-state">
              Loading scans...
            </div>
          ) : recentScans.length > 0 ? (

            <div className="scan-list">

              {recentScans.map((scan) => (
                <div
                  className="scan-item"
                  key={scan.id}
                >

                  <div className="scan-icon">
                    <Activity size={17} />
                  </div>

                  <div className="scan-info">

                    <strong>
                      {scan.target}
                    </strong>

                    <span>
                      Scan #{scan.id} ·{" "}
                      {scan.total_findings} findings
                    </span>

                  </div>

                  <span className="scan-status">
                    {scan.status}
                  </span>

                </div>
              ))}

            </div>

          ) : (
            <div className="empty-state">
              No scans recorded.
            </div>
          )}

        </ChartCard>

      </div>

      {/* Footer */}

      <footer className="dashboard-footer">

        <span>
          VulnX v1.0.0
        </span>

        <span>
          <span className="footer-dot" />
          Security intelligence engine
        </span>

      </footer>

    </div>
  );
}

export default Dashboard;
