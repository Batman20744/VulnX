
import { useEffect, useState } from "react";
import {
  FileText,
  FileSpreadsheet,
  Download,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Server,
  Activity,
  AlertTriangle,
  Clock,
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
import api from "../services/api";

const SEVERITY_COLORS = {
  CRITICAL: "#176B60",
  HIGH: "#218675",
  MEDIUM: "#2A9D8F",
  LOW: "#74C7B8",
  UNKNOWN: "#71827B",
};

function Reports() {
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);
  const [riskSummary, setRiskSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState("");

  async function loadReports() {
    setLoading(true);
    setError("");

    try {
      const [assetData, findingData, riskData, scanData] =
        await Promise.all([
          api.getAssets(),
          api.getFindings(),
          api.getRiskSummary(),
          api.getScans(),
        ]);

      setAssets(Array.isArray(assetData) ? assetData : []);
      setFindings(Array.isArray(findingData) ? findingData : []);
      setRiskSummary(riskData);
      setScans(Array.isArray(scanData) ? scanData : []);
    } catch (err) {
      console.error("Reports loading error:", err);
      setError("Unable to load report data. Check the backend.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReports();
  }, []);

  async function downloadReport(type) {
    setDownloading(type);
    setError("");

    try {
      const blob =
        type === "pdf"
          ? await api.downloadSecurityPdf()
          : await api.downloadVulnerabilityCsv();

      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");

      link.href = url;
      link.download =
        type === "pdf"
          ? "VulnX_Security_Report.pdf"
          : "VulnX_Vulnerability_Report.csv";

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Report download error:", err);
      setError(`Unable to download ${type.toUpperCase()} report.`);
    } finally {
      setDownloading("");
    }
  }

  const severityData = riskSummary
    ? [
        { name: "CRITICAL", value: riskSummary.critical ?? 0 },
        { name: "HIGH", value: riskSummary.high ?? 0 },
        { name: "MEDIUM", value: riskSummary.medium ?? 0 },
        { name: "LOW", value: riskSummary.low ?? 0 },
      ].filter((item) => item.value > 0)
    : [];

  const recentScans = [...scans]
    .sort(
      (a, b) =>
        new Date(b.started_at) - new Date(a.started_at)
    )
    .slice(0, 8);

  function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value);

    return Number.isNaN(date.getTime())
      ? "—"
      : date.toLocaleString();
  }

  return (
    <div className="dashboard-content reports-page">
      <div className="dashboard-heading">
        <div>
          <p className="eyebrow">SECURITY REPORTING</p>
          <h2>Security Assessment Reports</h2>
          <p className="dashboard-description">
            Review security posture, vulnerability distribution,
            scan activity and export assessment reports.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadReports}
          disabled={loading}
        >
          <RefreshCw size={16} />
          {loading ? "Refreshing..." : "Refresh data"}
        </button>
      </div>

      {error && (
        <div className="dashboard-error">
          <AlertTriangle size={18} />
          {error}
        </div>
      )}

      <div className="stats-grid">
        <StatCard
          title="Total Assets"
          value={loading ? "..." : assets.length}
          subtitle="Registered assets"
          icon={Server}
        />

        <StatCard
          title="Total Findings"
          value={loading ? "..." : riskSummary?.total_findings ?? 0}
          subtitle="Recorded vulnerabilities"
          icon={ShieldAlert}
          variant="warning"
        />

        <StatCard
          title="Critical Findings"
          value={loading ? "..." : riskSummary?.critical ?? 0}
          subtitle="Critical severity"
          icon={AlertTriangle}
          variant="critical"
        />

        <StatCard
          title="KEV Findings"
          value={loading ? "..." : riskSummary?.kev_findings ?? 0}
          subtitle="Known exploited vulnerabilities"
          icon={ShieldCheck}
          variant="success"
        />
      </div>

      <div className="reports-download-grid">
        <div className="report-download-card">
          <div className="report-download-icon">
            <FileText size={25} />
          </div>

          <div className="report-download-content">
            <h3>Executive Security Report</h3>
            <p>
              PDF assessment containing security overview,
              severity distribution, risk statistics and
              vulnerability details.
            </p>
          </div>

          <button
            className="report-download-button"
            onClick={() => downloadReport("pdf")}
            disabled={Boolean(downloading)}
          >
            <Download size={16} />
            {downloading === "pdf" ? "Generating..." : "Download PDF"}
          </button>
        </div>

        <div className="report-download-card">
          <div className="report-download-icon">
            <FileSpreadsheet size={25} />
          </div>

          <div className="report-download-content">
            <h3>Technical Vulnerability Export</h3>
            <p>
              CSV spreadsheet containing CVEs, severity,
              CVSS, EPSS, risk scores, affected assets,
              status and remediation.
            </p>
          </div>

          <button
            className="report-download-button"
            onClick={() => downloadReport("csv")}
            disabled={Boolean(downloading)}
          >
            <Download size={16} />
            {downloading === "csv" ? "Generating..." : "Download CSV"}
          </button>
        </div>
      </div>

      <div className="dashboard-grid">
        <ChartCard
          title="Severity Distribution"
          subtitle="Recorded vulnerability findings"
          className="severity-panel"
        >
          {loading ? (
            <div className="empty-state">
              Loading severity data...
            </div>
          ) : severityData.length > 0 ? (
            <div className="severity-chart">
              <ResponsiveContainer width="100%" height={230}>
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
                        fill={SEVERITY_COLORS[entry.name]}
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
                  <div className="legend-item" key={item.name}>
                    <span
                      className="legend-dot"
                      style={{
                        background: SEVERITY_COLORS[item.name],
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
              No findings available.
            </div>
          )}
        </ChartCard>

        <ChartCard
          title="Risk Assessment"
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
              <span className="risk-out-of">/ 100</span>
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
              Average risk across recorded findings
            </p>
          </div>

          <div className="risk-breakdown">
            <div>
              <span>Critical</span>
              <strong>{riskSummary?.critical ?? 0}</strong>
            </div>
            <div>
              <span>High</span>
              <strong>{riskSummary?.high ?? 0}</strong>
            </div>
            <div>
              <span>Medium</span>
              <strong>{riskSummary?.medium ?? 0}</strong>
            </div>
            <div>
              <span>Low</span>
              <strong>{riskSummary?.low ?? 0}</strong>
            </div>
          </div>
        </ChartCard>
      </div>

      <ChartCard
        title="Recent Scan History"
        subtitle="Latest vulnerability assessment activity"
      >
        <div className="reports-scan-table-wrapper">
          <table className="data-table reports-scan-table">
            <thead>
              <tr>
                <th>Scan</th>
                <th>Target</th>
                <th>Type</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Started</th>
              </tr>
            </thead>

            <tbody>
              {recentScans.map((scan) => (
                <tr key={scan.id}>
                  <td>#{scan.id}</td>
                  <td>{scan.target || "—"}</td>
                  <td>{scan.scan_type || "—"}</td>
                  <td>
                    <span
                      className={`scan-status ${
                        (scan.status || "").toLowerCase()
                      }`}
                    >
                      {scan.status || "Unknown"}
                    </span>
                  </td>
                  <td>{scan.total_findings ?? 0}</td>
                  <td>{formatDate(scan.started_at)}</td>
                </tr>
              ))}

              {!loading && recentScans.length === 0 && (
                <tr>
                  <td colSpan="6" className="empty-state">
                    No scan history available.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </ChartCard>

      <p className="reports-footer-note">
        <Clock size={14} />
        Report data reflects the latest information stored in VulnX.
      </p>
    </div>
  );
}

export default Reports;
