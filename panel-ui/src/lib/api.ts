export interface Stats {
  total_up: number
  total_down: number
  active: number
  pending: number
  banned: number
  kicked: number
  expired: number
  total: number
  blocked: number
  online: number
  kill_switch: boolean
  countries: Record<string, number>
}

export interface Peer {
  token: string
  device_name: string
  fingerprint: string
  status: string
  created_at: string
  last_seen: string
  bytes_up: number
  bytes_down: number
  kick_reason?: string
  ban_reason?: string
  last_ip?: string
  country?: string
}

export interface EventItem {
  kind: string
  detail: string
  at: string
}

export interface Category {
  category: string
  enabled: boolean
  domains: number
}

export interface BlockEntry {
  domain: string
  reason: string
}

export interface PeerLimits {
  schedule: string
  max_bps: number
  quota_bytes: number
}

export interface DeviceHealth {
  token: string
  device_name: string
  status: string
  version: string
  os: string
  arch: string
  cpu_pct: number
  mem_pct: number
  temp_c: number
  uptime_s: number
  latency_ms: number
  jitter_ms: number
  probe_loss_pct: number
  last_ip?: string
  country?: string
  at: string
}

export interface AlertItem {
  id: number
  severity: "info" | "warning" | "critical"
  kind: string
  message: string
  acked: boolean
  at: string
}

export interface ServerHealth {
  version: string
  process_uptime_s: number
  goroutines: number
  heap_mb: number
  active_sessions: number
  kill_switch: boolean
  mem_total_mb?: number
  mem_used_pct?: number
  load_1m?: number
  load_5m?: number
  load_15m?: number
  cpu_cores?: number
  cpu_pct?: number
  host_uptime_s?: number
  os?: string
  platform?: string
  kernel?: string
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", ...init })
  if (res.status === 401 || res.status === 403) {
    if (!path.startsWith("/admin/api/login")) window.location.href = "/admin/login"
    throw new Error("unauthorized")
  }
  if (!res.ok) throw new Error(await res.text())
  return res.json() as Promise<T>
}

const post = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
})

export const api = {
  stats: () => req<Stats>("/admin/api/stats"),
  peers: () => req<Peer[]>("/admin/api/peers"),
  events: () => req<EventItem[]>("/admin/api/events"),
  categories: () => req<Category[]>("/admin/api/categories"),
  blocklist: () => req<BlockEntry[]>("/admin/api/blocklist"),
  settings: () => req<{ kill_switch: boolean }>("/admin/api/settings"),
  visits: () => req<{ domain: string; hits: number; last: string }[]>("/admin/api/visits"),
  report: () => req<{ day: string; up: number; down: number }[]>("/admin/api/report"),
  devices: () => req<DeviceHealth[]>("/admin/api/devices"),
  alerts: () => req<{ alerts: AlertItem[]; unacked: number }>("/admin/api/alerts"),
  ackAlert: (id: number) => req<{ ok: boolean }>("/admin/api/alerts", post({ id, ack: true })),
  serverHealth: () => req<ServerHealth>("/admin/api/server-health"),
  peerAction: (token: string, action: string, body?: unknown) =>
    req<{ ok: boolean }>(`/admin/api/peers/${token}/${action}`, body !== undefined ? post(body) : { method: "POST" }),
  peerLimits: (token: string) => req<PeerLimits>(`/admin/api/peers/${token}/limits`),
  setPeerLimits: (token: string, limits: PeerLimits) =>
    req<{ ok: boolean }>(`/admin/api/peers/${token}/limits`, post(limits)),
  setCategory: (category: string, enabled: boolean) =>
    req<{ ok: boolean }>("/admin/api/categories", post({ category, enabled })),
  addBlock: (domain: string, reason: string) =>
    req<{ ok: boolean }>("/admin/api/blocklist", post({ domain, reason })),
  removeBlock: (domain: string) =>
    req<{ ok: boolean }>("/admin/api/blocklist", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    }),
  setKillSwitch: (on: boolean) => req<{ ok: boolean }>("/admin/api/settings", post({ kill_switch: on })),
}
