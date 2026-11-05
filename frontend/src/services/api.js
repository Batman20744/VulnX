
const API_BASE_URL = "http://127.0.0.1:8001/api/v1";

async function apiRequest(endpoint) {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`);

    if (!response.ok) {
      throw new Error(
        `API request failed: ${response.status} ${response.statusText}`
      );
    }

    return await response.json();
  } catch (error) {
    console.error(`VulnX API error (${endpoint}):`, error);
    throw error;
  }
}

export const api = {
  getAssets: () => apiRequest("/assets/"),

  getFindings: () => apiRequest("/findings/"),

  getRiskSummary: () => apiRequest("/findings/risk-summary"),

  getScans: () => apiRequest("/scans/"),

  getCves: () => apiRequest("/cves/"),
};

export default api;
