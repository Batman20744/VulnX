
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Boxes,
  Package,
  RefreshCw,
  Search,
  Server,
  AlertCircle,
  Database,
  Plus,
  Pencil,
  Trash2,
  X,
  Save,
} from "lucide-react";

import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  Bar,
  BarChart,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

import api from "../services/api";

const CHART_COLORS = [
  "#2A9D8F",
  "#74C7B8",
  "#397F73",
  "#A5D6C9",
  "#547E75",
  "#1D655A",
  "#8FB9AC",
];

const EMPTY_FORM = {
  asset_name: "",
  software_name: "",
  software_version: "",
  vendor: "",
  operating_system: "",
  asset_type: "software",
  description: "",
};

function distribution(items, field) {
  const counts = items.reduce((result, item) => {
    const value = item[field] || "Not specified";
    result[value] = (result[value] || 0) + 1;
    return result;
  }, {});

  return Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
}

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

function ChartTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;

  return (
    <div className="assets-chart-tooltip">
      <strong>{payload[0].name}</strong>
      <p>{payload[0].value} assets</p>
    </div>
  );
}

function Assets() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const [modalOpen, setModalOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");

  const loadAssets = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const data = await api.getAssets();

      if (!Array.isArray(data)) {
        throw new Error("Unexpected response from assets API.");
      }

      setAssets(data);
    } catch (err) {
      setError(err.message || "Unable to load assets.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const softwareDistribution = useMemo(
    () => distribution(assets, "software_name"),
    [assets]
  );

  const osDistribution = useMemo(
    () => distribution(assets, "operating_system").slice(0, 7),
    [assets]
  );

  const vendors = useMemo(
    () => new Set(assets.map((a) => a.vendor).filter(Boolean)).size,
    [assets]
  );

  const operatingSystems = useMemo(
    () =>
      new Set(assets.map((a) => a.operating_system).filter(Boolean)).size,
    [assets]
  );

  const filteredAssets = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) return assets;

    return assets.filter((asset) =>
      [
        asset.asset_name,
        asset.software_name,
        asset.software_version,
        asset.vendor,
        asset.operating_system,
        asset.asset_type,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))
    );
  }, [assets, search]);

  const openAddModal = () => {
    setEditingAsset(null);
    setForm(EMPTY_FORM);
    setFormError("");
    setModalOpen(true);
  };

  const openEditModal = (asset) => {
    setEditingAsset(asset);
    setForm({
      asset_name: asset.asset_name || "",
      software_name: asset.software_name || "",
      software_version: asset.software_version || "",
      vendor: asset.vendor || "",
      operating_system: asset.operating_system || "",
      asset_type: asset.asset_type || "software",
      description: asset.description || "",
    });
    setFormError("");
    setModalOpen(true);
  };

  const closeModal = () => {
    if (saving) return;
    setModalOpen(false);
    setEditingAsset(null);
    setForm(EMPTY_FORM);
    setFormError("");
  };

  const handleFormChange = (event) => {
    const { name, value } = event.target;
    setForm((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setFormError("");

    if (
      !form.asset_name.trim() ||
      !form.software_name.trim() ||
      !form.software_version.trim()
    ) {
      setFormError(
        "Asset name, software name and software version are required."
      );
      return;
    }

    const payload = {
      ...form,
      asset_name: form.asset_name.trim(),
      software_name: form.software_name.trim(),
      software_version: form.software_version.trim(),
      vendor: form.vendor.trim() || null,
      operating_system: form.operating_system.trim() || null,
      description: form.description.trim() || null,
    };

    try {
      setSaving(true);

      if (editingAsset) {
        await api.updateAsset(editingAsset.id, payload);
      } else {
        await api.createAsset(payload);
      }

      setModalOpen(false);
      setEditingAsset(null);
      setForm(EMPTY_FORM);

      await loadAssets();
    } catch (err) {
      setFormError(err.message || "Unable to save asset.");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (asset) => {
    const confirmed = window.confirm(
      `Are you sure you want to delete "${asset.asset_name}"?`
    );

    if (!confirmed) return;

    try {
      setError("");
      await api.deleteAsset(asset.id);
      await loadAssets();
    } catch (err) {
      setError(err.message || "Unable to delete asset.");
    }
  };

  return (
    <section className="dashboard-content assets-page">
      <div className="dashboard-heading">
        <div>
          <p className="eyebrow">VULNERABILITY MANAGEMENT</p>
          <h2>Asset Inventory</h2>
          <p className="dashboard-description">
            Discover, manage and monitor your registered software assets.
          </p>
        </div>

        <div className="assets-heading-actions">
          <button
            className="refresh-button"
            onClick={loadAssets}
            disabled={loading}
          >
            <RefreshCw size={15} />
            Refresh
          </button>

          <button
            className="assets-add-button"
            onClick={openAddModal}
          >
            <Plus size={17} />
            Add Asset
          </button>
        </div>
      </div>

      {error && (
        <div className="dashboard-error">
          <AlertCircle size={17} />
          {error}
          <button onClick={loadAssets}>Retry</button>
        </div>
      )}

      <div className="stats-grid">
        <StatCard
          title="Total Assets"
          value={loading ? "—" : assets.length}
          subtitle="Registered assets"
          icon={Server}
        />

        <StatCard
          title="Unique Software"
          value={loading ? "—" : softwareDistribution.length}
          subtitle="Distinct software products"
          icon={Package}
        />

        <StatCard
          title="Operating Systems"
          value={loading ? "—" : operatingSystems}
          subtitle="Identified platforms"
          icon={Database}
        />

        <StatCard
          title="Software Vendors"
          value={loading ? "—" : vendors}
          subtitle="Distinct vendors"
          icon={Boxes}
        />
      </div>

      <div className="dashboard-grid assets-chart-grid">
        <div className="chart-card">
          <div className="chart-card-header">
            <div>
              <h3>Software Distribution</h3>
              <p>Registered software across your inventory</p>
            </div>
            <Activity size={18} color="#74C7B8" />
          </div>

          {loading ? (
            <div className="empty-state">Loading software data...</div>
          ) : softwareDistribution.length === 0 ? (
            <div className="empty-state">No software data available.</div>
          ) : (
            <div className="assets-pie-layout">
              <div className="assets-pie-chart">
                <ResponsiveContainer width="100%" height={245}>
                  <PieChart>
                    <Pie
                      data={softwareDistribution}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={95}
                      paddingAngle={3}
                      stroke="none"
                    >
                      {softwareDistribution.map((entry, index) => (
                        <Cell
                          key={entry.name}
                          fill={CHART_COLORS[index % CHART_COLORS.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip content={<ChartTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="assets-chart-legend">
                {softwareDistribution.slice(0, 7).map((item, index) => (
                  <div className="legend-item" key={item.name}>
                    <span
                      className="legend-dot"
                      style={{
                        backgroundColor:
                          CHART_COLORS[index % CHART_COLORS.length],
                      }}
                    />
                    <span>{item.name}</span>
                    <strong>{item.value}</strong>
                  </div>
                ))}

                {softwareDistribution.length > 7 && (
                  <p className="assets-chart-note">
                    + {softwareDistribution.length - 7} more products
                  </p>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="chart-card">
          <div className="chart-card-header">
            <div>
              <h3>Operating System Distribution</h3>
              <p>Assets grouped by operating system</p>
            </div>
            <Server size={18} color="#74C7B8" />
          </div>

          {loading ? (
            <div className="empty-state">Loading OS data...</div>
          ) : osDistribution.length === 0 ? (
            <div className="empty-state">No operating system data available.</div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart
                data={osDistribution}
                layout="vertical"
                margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
              >
                <CartesianGrid
                  stroke="#1F332F"
                  strokeDasharray="3 3"
                  horizontal={false}
                />
                <XAxis
                  type="number"
                  allowDecimals={false}
                  stroke="#71827B"
                  tick={{ fontSize: 10 }}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={105}
                  stroke="#71827B"
                  tick={{ fontSize: 9 }}
                />
                <Tooltip content={<ChartTooltip />} />
                <Bar
                  dataKey="value"
                  fill="#2A9D8F"
                  radius={[0, 5, 5, 0]}
                  barSize={17}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="chart-card assets-inventory-card">
        <div className="chart-card-header assets-inventory-header">
          <div>
            <h3>Registered Assets</h3>
            <p>
              Showing {filteredAssets.length} of {assets.length} registered
              assets
            </p>
          </div>

          <div className="assets-search">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search assets..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
        </div>

        {loading ? (
          <div className="empty-state">Loading asset inventory...</div>
        ) : filteredAssets.length === 0 ? (
          <div className="empty-state">
            {assets.length === 0
              ? "No assets registered yet."
              : "No assets match your search."}
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="data-table assets-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>ASSET NAME</th>
                  <th>SOFTWARE</th>
                  <th>VERSION</th>
                  <th>VENDOR</th>
                  <th>OPERATING SYSTEM</th>
                  <th>TYPE</th>
                  <th>ACTIONS</th>
                </tr>
              </thead>

              <tbody>
                {filteredAssets.map((asset) => (
                  <tr key={asset.id}>
                    <td>#{asset.id}</td>
                    <td>
                      <strong>{asset.asset_name}</strong>
                    </td>
                    <td>{asset.software_name}</td>
                    <td>{asset.software_version}</td>
                    <td>{asset.vendor || "—"}</td>
                    <td>{asset.operating_system || "—"}</td>
                    <td>
                      <span className="assets-type-badge">
                        {asset.asset_type || "software"}
                      </span>
                    </td>
                    <td>
                      <div className="assets-row-actions">
                        <button
                          type="button"
                          title="Edit asset"
                          onClick={() => openEditModal(asset)}
                        >
                          <Pencil size={15} />
                        </button>

                        <button
                          type="button"
                          title="Delete asset"
                          onClick={() => handleDelete(asset)}
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {modalOpen && (
        <div
          className="assets-modal-overlay"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) closeModal();
          }}
        >
          <div
            className="assets-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="asset-modal-title"
          >
            <div className="assets-modal-header">
              <div>
                <p className="eyebrow">ASSET MANAGEMENT</p>
                <h3 id="asset-modal-title">
                  {editingAsset ? "Edit Asset" : "Register New Asset"}
                </h3>
                <p>
                  Enter the software and system information below.
                </p>
              </div>

              <button
                type="button"
                className="assets-modal-close"
                onClick={closeModal}
                disabled={saving}
                aria-label="Close modal"
              >
                <X size={19} />
              </button>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="assets-form-grid">
                <label>
                  Asset Name <span>*</span>
                  <input
                    name="asset_name"
                    value={form.asset_name}
                    onChange={handleFormChange}
                    placeholder="e.g. Production Web Server"
                    maxLength={150}
                    required
                  />
                </label>

                <label>
                  Software Name <span>*</span>
                  <input
                    name="software_name"
                    value={form.software_name}
                    onChange={handleFormChange}
                    placeholder="e.g. OpenSSL"
                    maxLength={200}
                    required
                  />
                </label>

                <label>
                  Software Version <span>*</span>
                  <input
                    name="software_version"
                    value={form.software_version}
                    onChange={handleFormChange}
                    placeholder="e.g. 1.1.1k"
                    maxLength={100}
                    required
                  />
                </label>

                <label>
                  Vendor
                  <input
                    name="vendor"
                    value={form.vendor}
                    onChange={handleFormChange}
                    placeholder="e.g. OpenSSL"
                  />
                </label>

                <label>
                  Operating System
                  <input
                    name="operating_system"
                    value={form.operating_system}
                    onChange={handleFormChange}
                    placeholder="e.g. Ubuntu 22.04"
                  />
                </label>

                <label>
                  Asset Type
                  <select
                    name="asset_type"
                    value={form.asset_type}
                    onChange={handleFormChange}
                  >
                    <option value="software">Software</option>
                    <option value="hardware">Hardware</option>
                    <option value="server">Server</option>
                    <option value="application">Application</option>
                    <option value="network">Network Device</option>
                  </select>
                </label>

                <label className="assets-description-field">
                  Description
                  <textarea
                    name="description"
                    value={form.description}
                    onChange={handleFormChange}
                    placeholder="Additional asset information..."
                    rows={3}
                  />
                </label>
              </div>

              {formError && (
                <div className="assets-form-error">
                  <AlertCircle size={15} />
                  {formError}
                </div>
              )}

              <div className="assets-modal-footer">
                <button
                  type="button"
                  className="assets-cancel-button"
                  onClick={closeModal}
                  disabled={saving}
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  className="assets-add-button"
                  disabled={saving}
                >
                  <Save size={16} />
                  {saving
                    ? "Saving..."
                    : editingAsset
                    ? "Update Asset"
                    : "Register Asset"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}

export default Assets;
