// src/services/api.ts
const API_BASE_URL = 'http://localhost:8000';

export const api = {
  // Auth endpoints
  auth: {
    login: `${API_BASE_URL}/api/auth/token`,
    logout: `${API_BASE_URL}/api/auth/logout`,
    verify: `${API_BASE_URL}/api/auth/verify`
  },
  
  // Scan endpoints
  scans: {
    start: `${API_BASE_URL}/api/scan/start`,
    status: (jobId: string) => `${API_BASE_URL}/api/scan/status/${jobId}`
  },
  
  // Report endpoints
  reports: {
    list: `${API_BASE_URL}/api/reports`,
    detail: (reportId: string) => `${API_BASE_URL}/api/report/${reportId}`,
    upload: `${API_BASE_URL}/api/report/upload`
  },
  
  // Attack path endpoints
  attackPath: {
    detail: (reportId: string) => `${API_BASE_URL}/api/attackpath/${reportId}`
  },
  
  // Chat endpoints
  chat: {
    query: `${API_BASE_URL}/api/chat/query`
  },
  
  // Threat intel endpoints
  intel: {
    cve: (cve: string) => `${API_BASE_URL}/api/intel/cve/${cve}`
  }
};