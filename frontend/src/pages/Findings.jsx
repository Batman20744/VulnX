
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  Search,
  ShieldAlert,
  ShieldCheck,
  Activity,
  XCircle,
  RefreshCw,
  ExternalLink,
  Filter,
} from "lucide-react";
import api from "../services/api";

function StatCard({ title, value, subtitle, icon: Icon, tone }) {
  return (
    <div className="stat-card">
      <div className="stat-card-top">
        <span className="stat-title">{title}</span>
        <div className="stat-icon" style={{ color: tone }}>
          <Icon size={19} />
        </div>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-card-bottom">
        <span className="stat-subtitle">{subtitle}</span>
      </div>
    </div>
  );
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString();
}

function Findings() {
  const [findings, setFindings] = useState([]);
  const [assets, setAssets] = useState([]);
  const [riskSummary, setRiskSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const isSyntheticFinding = selectedFinding?.description
  ?.toLowerCase()
  .includes("synthetic");

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [findingData, assetData, summaryData] =
        await Promise.all([
          api.getFindings(),
          api.getAssets(),
          api.getRiskSummary(),
        ]);

      if (!Array.isArray(findingData) || !Array.isArray(assetData)) {
        throw new Error("Unexpected API response.");
      }

      setFindings(findingData);
      setAssets(assetData);
      setRiskSummary(summaryData);
    } catch (err) {
      setError(err.message || "Unable to load vulnerability findings.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const assetMap = useMemo(
    () => new Map(assets.map((asset) => [
      String(asset.id),
      asset,
    ])),
    [assets]
  );

  const filteredFindings = useMemo(() => {
    const query = search.trim().toLowerCase();

    return findings.filter((finding) => {
      const asset = assetMap.get(String(finding.asset_id));

      const matchesSearch =
        !query ||
        [
          finding.cve_id,
          finding.title,
          finding.description,
          finding.severity,
          finding.status,
          asset?.asset_name,
          asset?.software_name,
        ]
          .filter(Boolean)
          .some((value) =>
            String(value).toLowerCase().includes(query)
          );

      const matchesSeverity =
        severityFilter === "all" ||
        finding.severity?.toLowerCase() === severityFilter;

      const matchesStatus =
        statusFilter === "all" ||
        finding.status?.toLowerCase() === statusFilter;

     const isSynthetic = finding.description
  ?.toLowerCase()
  .includes("synthetic");

const matchesKev =
  !kevOnly || (finding.is_kev === true && !isSynthetic);

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesStatus &&
        matchesKev
      );
    });
  }, [
    findings,
    assetMap,
    search,
    severityFilter,
    statusFilter,
    kevOnly,
  ]);

  const criticalCount = riskSummary?.critical ?? 0;
  const verifiedKevCount = findings.filter(
  (finding) =>
    finding.is_kev === true &&
    !finding.description?.toLowerCase().includes("synthetic")
).length;
  const highCount = riskSummary?.high ?? 0;
  const mediumCount = riskSummary?.medium ?? 0;
  const lowCount = riskSummary?.low ?? 0;

  const selectedAsset = selectedFinding
    ? assetMap.get(String(selectedFinding.asset_id))
    : null;

  return (
    <section className="dashboard-content findings-page">

      <div className="dashboard-heading">
        <div>
          <p className="eyebrow">VULNERABILITY INTELLIGENCE</p>
          <h2>Security Findings</h2>
          <p className="dashboard-description">
            Identify, prioritize and manage detected software vulnerabilities.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadData}
          disabled={loading}
        >
          <RefreshCw size={15} />
          Refresh Findings
        </button>
      </div>

      {error && (
        <div className="dashboard-error">
          <AlertCircle size={17} />
          {error}
        </div>
      )}

      <div className="stats-grid">
        <StatCard
          title="Total Findings"
          value={loading ? "—" : riskSummary?.total_findings ?? findings.length}
          subtitle="Recorded vulnerabilities"
          icon={ShieldAlert}
          tone="#74C7B8"
        />

        <StatCard
          title="Critical Findings"
          value={loading ? "—" : criticalCount}
          subtitle="Highest severity"
          icon={AlertTriangle}
          tone="#E05252"
        />

        <StatCard
  title="KEV Findings"
  value={loading ? "—" : verifiedKevCount}
  subtitle="Known exploited vulnerabilities"
  icon={Activity}
  tone="#E5A45B"
        />

        <StatCard
          title="Average Risk Score"
          value={
            loading
              ? "—"
              : riskSummary?.average_risk_score?.toFixed(2) ?? "—"
          }
          subtitle="Overall risk assessment"
          icon={ShieldCheck}
          tone="#74C7B8"
        />
      </div>

      <div className="findings-severity-grid">
        {[
          { label: "Critical", value: criticalCount, color: "#E05252" },
          { label: "High", value: highCount, color: "#E58A52" },
          { label: "Medium", value: mediumCount, color: "#DCC77A" },
          { label: "Low", value: lowCount, color: "#74C7B8" },
        ].map((item) => (
          <div className="chart-card severity-card" key={item.label}>
            <div className="severity-card-label">
              <span style={{ background: item.color }} />
              {item.label}
            </div>
            <strong>{loading ? "—" : item.value}</strong>
          </div>
        ))}
      </div>

      <div className="chart-card findings-history-card">
        <div className="chart-card-header findings-history-header">
          <div>
            <h3>Vulnerability Inventory</h3>
            <p>
              Showing {filteredFindings.length} of {findings.length} findings
            </p>
          </div>
        </div>

        <div className="findings-filters">

          <div className="assets-search">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search CVE, asset or vulnerability..."
            />
          </div>

          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="accepted">Accepted</option>
          </select>

          <button
            className={`kev-filter-button ${kevOnly ? "active" : ""}`}
            onClick={() => setKevOnly((value) => !value)}
          >
            <Filter size={14} />
            KEV Only
          </button>
        </div>

        {loading ? (
          <div className="empty-state">Loading vulnerability findings...</div>
        ) : filteredFindings.length === 0 ? (
          <div className="empty-state">
            No matching vulnerability findings found.
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="data-table findings-table">
              <thead>
                <tr>
                  <th>CVE / FINDING</th>
                  <th>ASSET</th>
                  <th>SEVERITY</th>
                  <th>CVSS</th>
                  <th>RISK SCORE</th>
                  <th>KEV</th>
                  <th>STATUS</th>
                  <th>DETECTED</th>
                  <th>ACTION</th>
                </tr>
              </thead>

              <tbody>
                {filteredFindings.map((finding) => {
                  const asset = assetMap.get(String(finding.asset_id));

                  return (
                    <tr key={finding.id}>
                      <td>
                        <div className="finding-title-cell">
                          <strong>{finding.cve_id || "—"}</strong>
                          <span>{finding.title || "Untitled finding"}</span>
                          {finding.description?.includes("Synthetic") && (
                            <span className="test-label">TEST DATA</span>
                          )}
                        </div>
                      </td>

                      <td>
                        <div className="finding-asset-cell">
                          <strong>{asset?.asset_name || `Asset #${finding.asset_id}`}</strong>
                          <span>{asset?.software_name || "—"}</span>
                        </div>
                      </td>

                      <td>
                        <span
                          className={`finding-severity ${String(
                            finding.severity || "unknown"
                          ).toLowerCase()}`}
                        >
                          {finding.severity || "Unknown"}
                        </span>
                      </td>

                      <td>{finding.cvss_score ?? "—"}</td>

                      <td>
                        <strong className="finding-risk-score">
                          {finding.risk_score ?? "—"}
                        </strong>
                      </td>

                      <td>
                       {finding.description?.toLowerCase().includes("synthetic") ? (
  <span className="kev-no">DEMO</span>
) : finding.is_kev ? (
  <span className="kev-badge">YES</span>
) : (
  <span className="kev-no">NO</span>
)}
                      </td>

                      <td>
                        <span className={`finding-status ${String(
                          finding.status || "unknown"
                        ).toLowerCase()}`}>
                          {finding.status || "Unknown"}
                        </span>
                      </td>

                      <td>{formatDate(finding.detected_at)}</td>

                      <td>
                        <button
                          className="finding-view-button"
                          onClick={() => setSelectedFinding(finding)}
                        >
                          View
                          <ExternalLink size={12} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedFinding && (
        <div
          className="assets-modal-overlay"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSelectedFinding(null);
            }
          }}
        >
          <div className="assets-modal finding-details-modal">

            <div className="assets-modal-header">
              <div>
                <p className="eyebrow">VULNERABILITY DETAILS</p>
                <h3>{selectedFinding.cve_id || "Finding Details"}</h3>
                {isSyntheticFinding && (
  <span className="test-label">TEST DATA</span>
)}
                <p>Finding ID: #{selectedFinding.id}</p>
              </div>

              <button
                className="assets-modal-close"
                onClick={() => setSelectedFinding(null)}
                aria-label="Close finding details"
              >
                <XCircle size={19} />
              </button>
            </div>

            <div className="finding-detail-grid">
              <div>
                <span>Severity</span>
                <strong>{selectedFinding.severity || "—"}</strong>
              </div>
              <div>
                <span>CVSS Score{isSyntheticFinding ? " (Demo)" : ""}</span>
                <strong>{selectedFinding.cvss_score ?? "—"}</strong>
              </div>
              <div>
                <span>EPSS Score{isSyntheticFinding ? " (Demo)" : ""}</span>
                <strong>{selectedFinding.epss_score ?? "—"}</strong>
              </div>
              <div>
                <span>Risk Score{isSyntheticFinding ? " (Demo)" : ""}</span>
                <strong>{selectedFinding.risk_score ?? "—"}</strong>
              </div>
              <div>
                <span>Risk Priority</span>
                <strong>{selectedFinding.risk_priority || "—"}</strong>
              </div>
              <div>
                <span>KEV Status</span>
               <strong>
  {isSyntheticFinding
    ? "DEMO VALUE"
    : selectedFinding.is_kev
      ? "Known Exploited"
      : "Not Listed"}
</strong>
              </div>
              <div>
                <span>Finding Status</span>
                <strong>{selectedFinding.status || "—"}</strong>
              </div>
              <div>
                <span>Asset</span>
                <strong>{selectedAsset?.asset_name || `Asset #${selectedFinding.asset_id}`}</strong>
              </div>
              <div>
                <span>Scan ID</span>
                <strong>#{selectedFinding.scan_id ?? "—"}</strong>
              </div>
              <div>
                <span>Detected At</span>
                <strong>{formatDate(selectedFinding.detected_at)}</strong>
              </div>
            </div>

            <div className="finding-description-section">
              <h4>Vulnerability Description</h4>
              <p>{selectedFinding.description || "No description available."}</p>
            </div>

            <div className="finding-description-section remediation-section">
              <h4>Recommended Remediation</h4>
              <p>
                {selectedFinding.remediation ||
                  "No remediation guidance available."}
              </p>
            </div>

          </div>
        </div>
      )}

    </section>
  );
}

export default Findings;
