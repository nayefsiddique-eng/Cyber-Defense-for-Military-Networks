const API_BASE = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${text}`);
  }
  return response.status === 204 ? null : response.json();
}

export const api = {
  baseUrl: API_BASE,
  health: () => request('/api/v1/pipeline/health'),
  snapshot: () => request('/api/v1/dashboard/snapshot'),
  incidents: () => request('/api/v1/incidents'),
  incident: (id) => request(`/api/v1/incidents/${encodeURIComponent(id)}`),
  alerts: () => request('/api/v1/alerts'),
  assets: () => request('/api/v1/assets'),
  topology: () => request('/api/v1/topology'),
  startSimulation: (payload) => request('/api/v1/simulation/start', { method: 'POST', body: JSON.stringify(payload) }),
  simulationStatus: (id) => request(`/api/v1/simulation/${encodeURIComponent(id)}/status`),
  stopSimulation: (id) => request(`/api/v1/simulation/${encodeURIComponent(id)}/stop`, { method: 'POST' }),
  simulateResponse: (payload) => request('/api/v1/response/simulate', { method: 'POST', body: JSON.stringify(payload) }),
};
