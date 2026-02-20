import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for error handling and normalizing responses
api.interceptors.response.use(
  (response) => {
    // Normalize API responses - backend returns inconsistent formats
    // Some endpoints return direct arrays, some return { success, data, error }
    // Only unwrap if it has the specific wrapped format (not token responses, etc.)
    if (response.data && typeof response.data === 'object') {
      // Check if it's a wrapped response with success/data/error structure
      // Must have 'success' as a boolean and 'data' field to unwrap
      if (response.data.success === true && 'data' in response.data && response.data.data !== undefined) {
        // Return a new response object with data unwrapped
        return {
          ...response,
          data: response.data.data
        };
      }
    }
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// ==================== Auth API ====================
export const authApi = {
  login: (credentials) => api.post('/api/v1/auth/login', credentials),
  logout: () => api.post('/api/v1/auth/logout'),
  refreshToken: () => api.post('/api/v1/auth/refresh'),
};

// ==================== Users API ====================
export const usersApi = {
  list: () => api.get('/api/v1/users'),
  get: (id) => api.get(`/api/v1/users/${id}`),
  create: (userData) => api.post('/api/v1/users', userData),
  update: (id, userData) => api.put(`/api/v1/users/${id}`, userData),
  delete: (id) => api.delete(`/api/v1/users/${id}`),
  changePassword: (id, passwords) => api.post(`/api/v1/users/${id}/password`, passwords),
};

// ==================== Zones API ====================
export const zonesApi = {
  list: () => api.get('/api/v1/zones'),
  get: (id) => api.get(`/api/v1/zones/${id}`),
  create: (zoneData) => api.post('/api/v1/zones', zoneData),
  update: (id, zoneData) => api.put(`/api/v1/zones/${id}`, zoneData),
  delete: (id) => api.delete(`/api/v1/zones/${id}`),
  getRecords: (zoneId) => api.get(`/api/v1/zones/${zoneId}/records`),
  createRecord: (zoneId, recordData) => api.post(`/api/v1/zones/${zoneId}/records`, recordData),
  updateRecord: (zoneId, recordId, recordData) => api.put(`/api/v1/zones/${zoneId}/records/${recordId}`, recordData),
  deleteRecord: (zoneId, recordId) => api.delete(`/api/v1/zones/${zoneId}/records/${recordId}`),
  importZone: (zoneId, data) => api.post(`/api/v1/zones/${zoneId}/import`, data),
  exportZone: (zoneId) => api.get(`/api/v1/zones/${zoneId}/export`),
};

// ==================== Servers API ====================
export const serversApi = {
  list: () => api.get('/api/v1/servers'),
  get: (id) => api.get(`/api/v1/servers/${id}`),
  create: (serverData) => api.post('/api/v1/servers', serverData),
  update: (id, serverData) => api.put(`/api/v1/servers/${id}`, serverData),
  delete: (id) => api.delete(`/api/v1/servers/${id}`),
  start: (id) => api.post(`/api/v1/servers/${id}/start`),
  stop: (id) => api.post(`/api/v1/servers/${id}/stop`),
  restart: (id) => api.post(`/api/v1/servers/${id}/restart`),
  getStatus: (id) => api.get(`/api/v1/servers/${id}/status`),
};

// ==================== DNS Control API ====================
export const dnsApi = {
  start: (config) => api.post('/api/v1/dns/start', config),
  stop: (serverId) => api.post('/api/v1/dns/stop', { id: serverId }),
  reload: (serverId) => api.post('/api/v1/dns/reload', { id: serverId }),
  status: () => api.get('/api/v1/dns/status'),
};

// ==================== Agents API ====================
export const agentsApi = {
  list: () => api.get('/api/v1/agents'),
  get: (id) => api.get(`/api/v1/agents/${id}`),
  register: (agentData) => api.post('/api/v1/agents/register', agentData),
  heartbeat: (agentData) => api.post('/api/v1/agents/heartbeat', agentData),
  getConfig: (id) => api.get(`/api/v1/agents/${id}/config`),
  rotateToken: (id) => api.post(`/api/v1/agents/${id}/token/rotate`),
  delete: (id) => api.delete(`/api/v1/agents/${id}`),
  pushConfig: (agentId, config) => api.post('/api/v1/agents/push-config', { agentId, config }),
};

// ==================== GeoRules API ====================
export const geoRulesApi = {
  list: () => api.get('/api/v1/georules'),
  get: (id) => api.get(`/api/v1/georules/${id}`),
  create: (ruleData) => api.post('/api/v1/georules', ruleData),
  update: (id, ruleData) => api.put(`/api/v1/georules/${id}`, ruleData),
  delete: (id) => api.delete(`/api/v1/georules/${id}`),
  test: (testData) => api.post('/api/v1/georules/resolve', testData),
  getStats: () => api.get('/api/v1/georules/stats'),
};

// ==================== SSL Certificates API ====================
export const certificatesApi = {
  list: () => api.get('/api/v1/certificates'),
  get: (id) => api.get(`/api/v1/certificates/${id}`),
  create: (certData) => api.post('/api/v1/certificates', certData),
  renew: (id) => api.post(`/api/v1/certificates/${id}/renew`),
  revoke: (id) => api.post(`/api/v1/certificates/${id}/revoke`),
  delete: (id) => api.delete(`/api/v1/certificates/${id}`),
  getStatus: (id) => api.get(`/api/v1/certificates/${id}/status`),
};

// ==================== Metrics API ====================
export const metricsApi = {
  get: () => api.get('/metrics'),
  getPrometheus: () => api.get('/api/v1/metrics'),
  getQueryRate: () => api.get('/api/v1/metrics/queries'),
  getCacheStats: () => api.get('/api/v1/metrics/cache'),
  getGeoStats: () => api.get('/api/v1/metrics/geo'),
  getAgentStats: () => api.get('/api/v1/metrics/agents'),
};

// ==================== Audit Logs API ====================
export const auditApi = {
  list: (params) => api.get('/api/v1/audit/logs', { params }),
  get: (id) => api.get(`/api/v1/audit/logs/${id}`),
};

// ==================== Health Check API ====================
export const healthApi = {
  check: () => api.get('/health'),
  ready: () => api.get('/ready'),
};

// Helper function to set token
export const setAuthToken = (token) => {
  if (token) {
    localStorage.setItem('token', token);
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    localStorage.removeItem('token');
    delete api.defaults.headers.common.Authorization;
  }
};

// Alias for setToken compatibility
api.setToken = setAuthToken;

// Helper to get stored token
export const getAuthToken = () => localStorage.getItem('token');

export default api;
