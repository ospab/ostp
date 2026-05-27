export interface UserStatsSnapshot {
  access_key: string;
  bytes_up: number;
  bytes_down: number;
  connections: number;
  limit_bytes: number | null;
  online: boolean;
  name?: string | null;
}

export interface ServerStatus {
  version: string;
  uptime_seconds: number;
  active_users: number;
  total_users: number;
}

export interface ApiResponse<T> {
  ok: boolean;
  data?: T;
  error?: string;
}

export interface DnsConfig {
  enabled: boolean;
  doh_upstream: string;
  adblock_urls: string[];
  custom_domains: Record<string, string>;
}

export interface DnsQueryLog {
  timestamp: number;
  domain: string;
  client_ip: string;
  blocked: boolean;
}

const API_TOKEN_KEY = 'ostp_api_token';

export function getApiSettings() {
  // Use relative path for embedded panel, fallback to localhost for dev
  const isDev = import.meta.env?.DEV || window.location.hostname === 'localhost' && window.location.port === '5173';
  const url = isDev ? 'http://localhost:9090' : window.location.pathname.replace(/\/$/, '');
  const token = localStorage.getItem(API_TOKEN_KEY) || '';
  return { url, token };
}

export function saveApiToken(token: string) {
  localStorage.setItem(API_TOKEN_KEY, token.trim());
}

export function clearApiAuth() {
  localStorage.removeItem(API_TOKEN_KEY);
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const { url, token } = getApiSettings();
  const headers = new Headers(options.headers || {});
  
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${url}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    throw new Error('Unauthorized API Token');
  }

  const json: ApiResponse<T> = await response.json();
  if (!json.ok) {
    throw new Error(json.error || 'API Request failed');
  }

  return json.data!;
}

export const api = {
  login: async (username: string, password?: string): Promise<string> => {
    const { url } = getApiSettings();
    const response = await fetch(`${url}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (response.status === 401) throw new Error('Invalid credentials');
    const json = await response.json();
    if (!json.ok) throw new Error(json.error || 'Login failed');
    saveApiToken(json.data.token);
    return json.data.token;
  },

  getServerStatus: () => request<ServerStatus>('/api/server/status'),
  getServerConfig: () => request<any>('/api/server/config'),
  updateServerConfig: (config: any) => request<boolean>('/api/server/config', {
    method: 'PUT',
    body: JSON.stringify(config),
  }),
  
  listUsers: () => request<UserStatsSnapshot[]>('/api/users'),
  
  createUser: (name: string | null, limitBytes: number | null, accessKey?: string) => 
    request<string>('/api/users', {
      method: 'POST',
      body: JSON.stringify({ name, limit_bytes: limitBytes, access_key: accessKey }),
    }),
  
  updateUser: (key: string, name: string | null, limitBytes: number | null) =>
    request<string>(`/api/users/${key}`, {
      method: 'PUT',
      body: JSON.stringify({ name, limit_bytes: limitBytes }),
    }),
  
  deleteUser: (key: string) =>
    request<string>(`/api/users/${key}`, {
      method: 'DELETE',
    }),
  
  resetUserStats: (key: string) =>
    request<boolean>(`/api/users/${key}/reset`, {
      method: 'POST',
    }),

  getSubscriptionLink: async (key: string): Promise<string> => {
    const { url } = getApiSettings();
    const response = await fetch(`${url}/api/subscribe/${key}`, {
      headers: {
        'Accept': 'text/plain',
      }
    });
    const json = await response.json();
    if (json.ok && json.data) {
      return json.data;
    }
    throw new Error(json.error || 'Failed to fetch subscription link');
  },

  getDnsConfig: () => request<DnsConfig>('/api/dns/config'),
  
  updateDnsConfig: (config: DnsConfig) => request<boolean>('/api/dns/config', {
    method: 'POST',
    body: JSON.stringify(config),
  }),

  getDnsQueries: () => request<DnsQueryLog[]>('/api/dns/queries'),

  refreshDnsBlocklists: () => request<boolean>('/api/dns/blocklists/refresh', {
    method: 'POST',
  }),
};
