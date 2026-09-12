// Minimal typed fetch wrapper. Sessions are cookies, so nothing to attach.
export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) throw new ApiError(res.status, data?.error ?? res.statusText)
  return data as T
}

export const api = {
  get: <T>(url: string) => request<T>('GET', url),
  post: <T>(url: string, body?: unknown) => request<T>('POST', url, body ?? {}),
  put: <T>(url: string, body: unknown) => request<T>('PUT', url, body),
  del: <T>(url: string) => request<T>('DELETE', url),
}

export type Mode = 'local' | 'managed'
export interface Me { username: string; version: string; mode: Mode; fixed: string }

export interface TLS { mode: number; server_name?: string; alpn?: string[]; auto_cert?: boolean; acme?: string; reality?: { private_key: string; public_key?: string; short_ids?: string[]; handshake_server?: string; handshake_port?: number } }
export interface Transport { type: string; path?: string; host?: string; service_name?: string; mode?: string }
export interface Inbound {
  tag: string; protocol: string; listen?: string; port: number; core?: string
  tls?: TLS; transport?: Transport; multiplex?: { enabled: boolean; padding?: boolean }
  flow?: string; cipher?: string; server_key?: string; obfs?: string; obfs_password?: string; up_mbps?: number; down_mbps?: number
  congestion_control?: string; mieru_transport?: string; traffic_pattern?: string
  remark?: string; enabled: boolean; display_host?: string; display_port?: number
  assigned_core?: string
}
export interface User {
  id: number; name: string; uuid: string; password: string; sub_token: string; enabled: boolean
  quota_bytes: number; expires_at: string | null; up: number; down: number; created_at: string; inbound_tags?: string[]
  online: string[]; usable: boolean
}
export interface Forward { tag: string; listen?: string; port: number; protocol: string; target: string; status: ForwardStatus | null }
export interface ForwardStatus { tag: string; up: boolean; rtt_ms: number; last_error?: string; active_conn: number; total_conn: number; bytes_in: number; bytes_out: number }
export interface Host { cpu_percent?: number; mem_total?: number; mem_used?: number; swap_total?: number; swap_used?: number; disk_total?: number; disk_used?: number }
export interface AgentStatus { panel: string; ready: boolean; inbounds: number; users: number; last_pull: string; last_apply: string; last_error?: string; core_running: Record<string, boolean>; core_inbounds: Record<string, number>; assign: Record<string, string>; skipped?: Record<string, string> }
export interface Status {
  version: string; uptime_seconds: number; mode: Mode; fixed: string; managed: { url: string; paired_at: string } | null; has_snapshot: boolean
  agent: AgentStatus | null; host: Host; forwards: ForwardStatus[]; online_users: number; users: number; inbounds: number
  total_up: number; total_down: number; history: { day: number; up: number; down: number }[]; last_report: string
  certs: CertStatus[]
}
export interface Settings { public_host: string; node_name: string; acme_email: string; cloudflare_token: string; panel_domain: string; panel_acme: string }
export interface CertStatus { domain: string; method: string; not_after: string; error?: string; updated: string }
export interface Link { tag: string; name: string; uri: string }
export interface CoreRelease { Core: string; Version: string; Status: string; Note: string; Installed: boolean }
export interface UpdateInfo {
  current: string; latest: string; has_update: boolean; release_build: boolean; in_container: boolean
  notes?: string; published_at?: string; url?: string; checked_at: string; cached: boolean; warning?: string
  has_backup: boolean; backup_version?: string
}
export interface LogEntry { time: string; level: string; msg: string; attrs?: string }
