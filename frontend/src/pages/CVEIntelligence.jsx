import { useEffect, useMemo, useState } from "react";
import {
  Search,
  RefreshCw,
  ShieldAlert,
  Database,
  X,
  ExternalLink,
  Calendar,
  Activity,
} from "lucide-react";

import { api } from "../services/api";

function CVEIntelligence() {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [selectedCve, setSelectedCve] = useState(null);
  const [refreshing, setRefreshing] = useState(null);
  const [notice, setNotice] = useState("");

  const loadCves = async () => {
    try {
      setLoading(true);
      setError("");
      const data = await api.getCves();
      setCves(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || "Unable to load CVE intelligence.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCves();
  }, []);

  const filteredCves = useMemo(() => {
    return cves.filter((cve) => {
      const query = search.toLowerCase();

      const matchesSearch =
        cve.cve_id?.toLowerCase().includes(query) ||
        cve.description?.toLowerCase().includes(query);

      const matchesSeverity =
        severity === "ALL" ||
        cve.severity?.toUpperCase() === severity;

      return matchesSearch && matchesSeverity;
    });
  }, [cves, search, severity]);

  const isSynthetic = (cve) =>
    cve.source?.toLowerCase().includes("test") ||
    cve.description?.toLowerCase().includes("synthetic");

  const realCves = cves.filter((cve) => !isSynthetic(cve));

  const severityCounts = {
    CRITICAL: realCves.filter(
      (cve) => cve.severity?.toUpperCase() === "CRITICAL"
    ).length,
    HIGH: realCves.filter(
      (cve) => cve.severity?.toUpperCase() === "HIGH"
    ).length,
    MEDIUM: realCves.filter(
      (cve) => cve.severity?.toUpperCase() === "MEDIUM"
    ).length,
    LOW: realCves.filter(
      (cve) => cve.severity?.toUpperCase() === "LOW"
    ).length,
  };

  const refreshCve = async (cveId) => {
    try {
      setRefreshing(cveId);
      setNotice("");
      await api.refreshCve(cveId);
      await loadCves();
      setNotice(`${cveId} refreshed successfully from NVD.`);

      if (selectedCve?.cve_id === cveId) {
        const updated = await api.getCve(cveId);
        setSelectedCve(updated);
      }
    } catch (err) {
      setNotice(err.message || `Unable to refresh ${cveId}.`);
    } finally {
      setRefreshing(null);
    }
  };

  const getSeverityClass = (value) => {
    switch (value?.toUpperCase()) {
      case "CRITICAL":
        return "cve-severity critical";
      case "HIGH":
        return "cve-severity high";
      case "MEDIUM":
        return "cve-severity medium";
      case "LOW":
        return "cve-severity low";
      default:
        return "cve-severity unknown";
    }
  };

  const formatDate = (value) => {
    if (!value) return "Not available";

    const date = new Date(value);

    return Number.isNaN(date.getTime())
      ? "Not available"
      : date.toLocaleDateString();
  };

  return (
    <section className="dashboard-content cve-page">
      <div className="dashboard-heading">
        <div>
          <p className="eyebrow">VULNERABILITY INTELLIGENCE</p>
          <h2>CVE Intelligence</h2>
          <p className="dashboard-description">
            Centralized vulnerability intelligence powered by NVD.
          </p>
        </div>

        <button
          className="settings-save-button"
          onClick={loadCves}
          disabled={loading}
        >
          <RefreshCw size={16} />
          Refresh Inventory
        </button>
      </div>

      {notice && (
        <div className="cve-notice" role="status">
          {notice}
        </div>
      )}

      {error && (
        <div className="cve-error" role="alert">
          {error}
          <button onClick={loadCves}>Retry</button>
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">
            <Database size={20} />
          </div>
          <div>
            <p>Total CVE Records</p>
            <h3>{loading ? "—" : cves.length}</h3>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <ShieldAlert size={20} />
          </div>
          <div>
            <p>Critical</p>
            <h3>{loading ? "—" : severityCounts.CRITICAL}</h3>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <Activity size={20} />
          </div>
          <div>
            <p>High</p>
            <h3>{loading ? "—" : severityCounts.HIGH}</h3>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">
            <Database size={20} />
          </div>
          <div>
            <p>Verified NVD Records</p>
            <h3>{loading ? "—" : realCves.length}</h3>
          </div>
        </div>
      </div>

      <div className="chart-card cve-inventory-card">
        <div className="cve-toolbar">
          <div className="cve-search">
            <Search size={17} />
            <input
              type="text"
              placeholder="Search CVE ID or description..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>

          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            <option value="ALL">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </div>

        <div className="cve-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>SEVERITY</th>
                <th>CVSS</th>
                <th>CVSS VERSION</th>
                <th>SOURCE</th>
                <th>PUBLISHED</th>
                <th>ACTION</th>
              </tr>
            </thead>

            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7">Loading CVE intelligence...</td>
                </tr>
              ) : filteredCves.length === 0 ? (
                <tr>
                  <td colSpan="7">No matching CVE records found.</td>
                </tr>
              ) : (
                filteredCves.map((cve) => (
                  <tr key={cve.id}>
                    <td>
                      <div className="cve-id-cell">
                        <strong>{cve.cve_id}</strong>
                        {isSynthetic(cve) && (
                          <span className="test-label">TEST DATA</span>
                        )}
                      </div>
                    </td>

                    <td>
                      <span className={getSeverityClass(cve.severity)}>
                        {cve.severity || "UNKNOWN"}
                      </span>
                    </td>

                    <td>
                      <strong>
                        {cve.cvss_score ?? "N/A"}
                      </strong>
                    </td>

                    <td>{cve.cvss_version || "N/A"}</td>
                    <td>{cve.source || "Unknown"}</td>
                    <td>{formatDate(cve.published)}</td>

                    <td>
                      <button
                        className="cve-view-button"
                        onClick={() => setSelectedCve(cve)}
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="cve-table-footer">
          Showing {filteredCves.length} of {cves.length} CVE records
        </div>
      </div>

      {selectedCve && (
        <div
          className="modal-overlay"
          onClick={() => setSelectedCve(null)}
        >
          <div
            className="modal-content cve-detail-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="modal-header">
              <div>
                <p className="eyebrow">VULNERABILITY DETAILS</p>
                <h3>{selectedCve.cve_id}</h3>
                {isSynthetic(selectedCve) && (
                  <span className="test-label">TEST DATA</span>
                )}
              </div>

              <button
                className="modal-close"
                onClick={() => setSelectedCve(null)}
              >
                <X size={20} />
              </button>
            </div>

            <div className="cve-detail-grid">
              <div>
                <span>Severity</span>
                <strong className={getSeverityClass(selectedCve.severity)}>
                  {selectedCve.severity || "UNKNOWN"}
                </strong>
              </div>

              <div>
                <span>CVSS Score</span>
                <strong>{selectedCve.cvss_score ?? "N/A"}</strong>
              </div>

              <div>
                <span>CVSS Version</span>
                <strong>{selectedCve.cvss_version || "N/A"}</strong>
              </div>

              <div>
                <span>Source</span>
                <strong>{selectedCve.source || "Unknown"}</strong>
              </div>

              <div>
                <span>Published</span>
                <strong>{formatDate(selectedCve.published)}</strong>
              </div>

              <div>
                <span>Last Modified</span>
                <strong>{formatDate(selectedCve.last_modified)}</strong>
              </div>
            </div>

            <div className="cve-description">
              <h4>Description</h4>
              <p>
                {selectedCve.description || "No description available."}
              </p>
            </div>

            <div className="cve-modal-actions">
              <button
                className="settings-save-button"
                onClick={() => refreshCve(selectedCve.cve_id)}
                disabled={refreshing === selectedCve.cve_id}
              >
                <RefreshCw size={16} />
                {refreshing === selectedCve.cve_id
                  ? "Refreshing..."
                  : "Refresh from NVD"}
              </button>

              <a
                className="cve-external-link"
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(
                  selectedCve.cve_id
                )}`}
                target="_blank"
                rel="noreferrer"
              >
                NVD Reference
                <ExternalLink size={15} />
              </a>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

export default CVEIntelligence;