
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertCircle,
  Clock,
  CheckCircle2,
  RefreshCw,
  Search,
  ShieldCheck,
  Target,
  XCircle,
} from "lucide-react";
import api from "../services/api";

function StatCard({ title, value, subtitle, icon: Icon }) {
  return (
    <div className="stat-card">
      <div className="stat-card-top">
        <span className="stat-title">{title}</span>
        <div className="stat-icon">
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
  if (Number.isNaN(date.getTime())) return "—";

  return date.toLocaleString();
}

function Scans() {
  const [scans, setScans] = useState([]);
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const scanLock = useRef(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [selectedAsset, setSelectedAsset] = useState("");
  const [details, setDetails] = useState(null);
  const [scanFindings, setScanFindings] = useState([]);
  const [detailsLoading, setDetailsLoading] = useState(false);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const [scanData, assetData] = await Promise.all([
        api.getScans(),
        api.getAssets(),
      ]);

      if (!Array.isArray(scanData) || !Array.isArray(assetData)) {
        throw new Error("Unexpected response received from the API.");
      }

      setScans(scanData);
      setAssets(assetData);

      setSelectedAsset((current) => {
        if (current && assetData.some((asset) => String(asset.id) === current)) {
          return current;
        }
        return assetData.length ? String(assetData[0].id) : "";
      });
    } catch (err) {
      setError(err.message || "Unable to load scan information.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const completedScans = scans.filter(
    (scan) => scan.status?.toLowerCase() === "completed"
  ).length;

  const runningScans = scans.filter(
    (scan) => scan.status?.toLowerCase() === "running"
  ).length;

  const totalFindings = scans.reduce(
    (total, scan) => total + (Number(scan.total_findings) || 0),
    0
  );

  const filteredScans = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) return scans;

    return scans.filter((scan) =>
      [
        scan.scan_name,
        scan.target,
        scan.scan_type,
        scan.status,
        scan.id,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))
    );
  }, [scans, search]);

  const startScan = async () => {
  if (!selectedAsset || scanLock.current || starting) return;

  const asset = assets.find(
    (item) => String(item.id) === selectedAsset
  );

  if (!asset) return;

  scanLock.current = true;

  try {
    setStarting(true);
    setError("");

    await api.startAssetScan(asset.id);
    await loadData();
  } catch (err) {
    setError(err.message || "Unable to start asset scan.");
  } finally {
    scanLock.current = false;
    setStarting(false);
  }
};

  const openScanDetails = async (scan) => {
    try {
      setDetails(scan);
      setDetailsLoading(true);
      setScanFindings([]);

      const [scanData, findingsData] = await Promise.all([
        api.getScanDetails(scan.id),
        api.getScanFindings(scan.id),
      ]);

      setDetails(scanData);
      setScanFindings(
        Array.isArray(findingsData)
          ? findingsData
          : findingsData?.items || []
      );
    } catch (err) {
      setError(err.message || "Unable to load scan details.");
    } finally {
      setDetailsLoading(false);
    }
  };

  const closeDetails = () => {
    setDetails(null);
    setScanFindings([]);
  };

  return (
    <section className="dashboard-content scans-page">
      <div className="dashboard-heading">
        <div>
          <p className="eyebrow">VULNERABILITY MANAGEMENT</p>
          <h2>Vulnerability Scans</h2>
          <p className="dashboard-description">
            Execute and monitor software vulnerability assessments.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={loadData}
          disabled={loading}
        >
          <RefreshCw size={15} />
          Refresh Scans
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
          title="Total Scans"
          value={loading ? "—" : scans.length}
          subtitle="Recorded scan operations"
          icon={Activity}
        />
        <StatCard
          title="Completed Scans"
          value={loading ? "—" : completedScans}
          subtitle="Successfully completed"
          icon={CheckCircle2}
        />
        <StatCard
          title="Running Scans"
          value={loading ? "—" : runningScans}
          subtitle="Currently processing"
          icon={Clock}
        />
        <StatCard
          title="Recorded Findings"
          value={loading ? "—" : totalFindings}
          subtitle="Across scan history"
          icon={ShieldCheck}
        />
      </div>

      <div className="chart-card scan-launch-card">
        <div className="chart-card-header">
          <div>
            <h3>Start Vulnerability Scan</h3>
            <p>
              Select a registered asset to assess its software version
              against the VulnX CVE database.
            </p>
          </div>
          <Target size={20} color="#74C7B8" />
        </div>

        <div className="scan-launch-controls">
          <select
            value={selectedAsset}
            onChange={(event) => setSelectedAsset(event.target.value)}
            disabled={loading || assets.length === 0 || starting}
          >
            {assets.length === 0 ? (
              <option value="">No registered assets</option>
            ) : (
              assets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.asset_name} — {asset.software_name}{" "}
                  {asset.software_version}
                </option>
              ))
            )}
          </select>

          <button
            className="assets-add-button"
            onClick={startScan}
            disabled={!selectedAsset || starting || loading}
          >
            <Activity size={16} />
            {starting ? "Scanning..." : "Start Scan"}
          </button>
        </div>
      </div>

      <div className="chart-card scans-history-card">
        <div className="chart-card-header scans-history-header">
          <div>
            <h3>Scan History</h3>
            <p>
              Showing {filteredScans.length} of {scans.length} scans
            </p>
          </div>

          <div className="assets-search">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search scan history..."
            />
          </div>
        </div>

        {loading ? (
          <div className="empty-state">Loading scan history...</div>
        ) : filteredScans.length === 0 ? (
          <div className="empty-state">No matching scans found.</div>
        ) : (
          <div className="table-wrapper">
            <table className="data-table scans-table">
              <thead>
                <tr>
                  <th>SCAN ID</th>
                  <th>SCAN NAME</th>
                  <th>TARGET</th>
                  <th>TYPE</th>
                  <th>STATUS</th>
                  <th>ASSETS</th>
                  <th>FINDINGS</th>
                  <th>STARTED AT</th>
                  <th>ACTION</th>
                </tr>
              </thead>

              <tbody>
                {filteredScans.map((scan) => (
                  <tr key={scan.id}>
                    <td>#{scan.id}</td>
                    <td>
                      <strong>{scan.scan_name}</strong>
                      {scan.scan_type === "demo" && (
                        <span className="test-label">DEMO</span>
                      )}
                    </td>
                    <td>{scan.target}</td>
                    <td>{scan.scan_type}</td>
                    <td>
                      <span
                        className={`scan-status-badge ${String(
                          scan.status || "unknown"
                        ).toLowerCase()}`}
                      >
                        {scan.status || "Unknown"}
                      </span>
                    </td>
                    <td>{scan.total_assets ?? 0}</td>
                    <td>{scan.total_findings ?? 0}</td>
                    <td>{formatDate(scan.started_at)}</td>
                    <td>
                      <button
                        className="scan-view-button"
                        onClick={() => openScanDetails(scan)}
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {details && (
        <div className="assets-modal-overlay" onMouseDown={(event) => {
          if (event.target === event.currentTarget) closeDetails();
        }}>
          <div className="assets-modal scan-details-modal">
            <div className="assets-modal-header">
              <div>
                <p className="eyebrow">SCAN DETAILS</p>
                <h3>{details.scan_name}</h3>
                <p>Scan ID: #{details.id}</p>
              </div>
              <button
                className="assets-modal-close"
                onClick={closeDetails}
                aria-label="Close scan details"
              >
                <XCircle size={19} />
              </button>
            </div>

            {detailsLoading ? (
              <div className="empty-state">Loading scan details...</div>
            ) : (
              <>
                <div className="scan-detail-grid">
                  <div>
                    <span>Target</span>
                    <strong>{details.target || "—"}</strong>
                  </div>
                  <div>
                    <span>Status</span>
                    <strong>{details.status || "—"}</strong>
                  </div>
                  <div>
                    <span>Total Assets</span>
                    <strong>{details.total_assets ?? 0}</strong>
                  </div>
                  <div>
                    <span>Total Findings</span>
                    <strong>{details.total_findings ?? 0}</strong>
                  </div>
                  <div>
                    <span>Started</span>
                    <strong>{formatDate(details.started_at)}</strong>
                  </div>
                  <div>
                    <span>Completed</span>
                    <strong>{formatDate(details.completed_at)}</strong>
                  </div>
                </div>

                <div className="scan-findings-section">
                  <h4>Scan Findings</h4>
                  {scanFindings.length === 0 ? (
                    <div className="empty-state">
                      No findings returned for this scan.
                    </div>
                  ) : (
                    <div className="table-wrapper">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>CVE ID</th>
                            <th>SEVERITY</th>
                            <th>CVSS</th>
                            <th>STATUS</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanFindings.map((finding) => (
                            <tr key={finding.id}>
                              <td>
                                <strong>
                                  {finding.cve_id || finding.cve?.cve_id || "—"}
                                </strong>
                              </td>
                              <td>
                                {finding.severity || finding.cve?.severity || "—"}
                              </td>
                              <td>
                                {finding.cvss_score ??
                                  finding.cve?.cvss_score ??
                                  "—"}
                              </td>
                              <td>{finding.status || "—"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

export default Scans;
