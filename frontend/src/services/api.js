
const API_BASE_URL = "https://vulnx-gjks.onrender.com/api/v1";

async function apiRequest(endpoint, options = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers,
      },
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        errorBody || `API request failed: ${response.status} ${response.statusText}`
      );
    }

    // DELETE endpoints may return HTTP 204 with no response body.
    if (response.status === 204) {
      return null;
    }

    return await response.json();
  } catch (error) {
    console.error(`VulnX API error (${endpoint}):`, error);
    throw error;
  }
}

export const api = {
  // Existing GET methods
  getAssets: () => apiRequest("/assets/"),
  getFindings: () => apiRequest("/findings/"),
  getRiskSummary: () => apiRequest("/findings/risk-summary"),
  getScans: () => apiRequest("/scans/"),
  startAssetScan: (assetId) =>
  apiRequest(`/scans/assets/${assetId}`, {
    method: "POST",
  }),

getScanDetails: (scanId) =>
  apiRequest(`/scans/${scanId}`),

getScanFindings: (scanId) =>
  apiRequest(`/findings/scan/${scanId}`),
  getCves: () => apiRequest("/cves/"),
  // Report downloads
downloadSecurityPdf: async () => {
  const response = await fetch(`${API_BASE_URL}/reports/pdf`);

  if (!response.ok) {
    throw new Error("Failed to download security PDF");
  }

  return await response.blob();
},

downloadVulnerabilityCsv: async () => {
  const response = await fetch(`${API_BASE_URL}/reports/csv`);

  if (!response.ok) {
    throw new Error("Failed to download vulnerability CSV");
  }

  return await response.blob();
},
  getCve: (cveId) =>
  apiRequest(`/cves/${encodeURIComponent(cveId)}`),

refreshCve: (cveId) =>
  apiRequest(`/cves/${encodeURIComponent(cveId)}/refresh`, {
    method: "POST",
  }),

  // Asset management
  createAsset: (asset) =>
    apiRequest("/assets/", {
      method: "POST",
      body: JSON.stringify(asset),
    }),

  updateAsset: (assetId, asset) =>
    apiRequest(`/assets/${assetId}`, {
      method: "PUT",
      body: JSON.stringify(asset),
    }),

  deleteAsset: (assetId) =>
    apiRequest(`/assets/${assetId}`, {
      method: "DELETE",
    }),
};

export default api;

