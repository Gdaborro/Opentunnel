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
  update_channel?: string
  update_state?: string
  channel_authentication?: boolean
}

export interface SettingsPolicy {
  kill_switch: boolean
  kill_switch_reason: string
  kill_switch_allow: string[]
  auto_accept_until?: string
  auto_accept_active: boolean
  ssh_tier_max_bps: number
  ssh_tier_daily_mb: number
  ssh_tier_trickle_kbps: number
}

export interface SettingsMutation {
  kill_switch?: boolean
  kill_switch_reason?: string
  kill_switch_allow?: string[]
  auto_accept_minutes?: number
  ssh_tier_max_bps?: number
  ssh_tier_daily_mb?: number
  ssh_tier_trickle_kbps?: number
}

export interface PrivacyPolicy {
  mode: "preserve" | "minimal"
  visit_retention_days: number
  health_retention_days: number
  peer_ip_retention_days: number
}

export interface RelayNodeHealth {
  node: string
  online: boolean
  age_seconds: number
  snapshot: {
    version: string
    active_sessions: number
    heap_mb: number
    goroutines: number
    guard_dropped_sources?: number
    sentinel_dropped_subjects?: number
  }
}

export interface HardeningStatus {
  privacy: PrivacyPolicy
  relay_nodes: RelayNodeHealth[]
  channel_verified_current_identities: number
  device_count: number
  managed_ssh_desired: number
  managed_ssh_revoked: number
  ssh_apply_status: string
  release_acceptance: string
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
  relay_online?: boolean
  metrics_age_s?: number
  panel_version?: string
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
    throw new Error("unauthorized")
  }
  if (!res.ok) throw new Error(await res.text())
  return res.json() as Promise<T>
}

// Session gate for the SPA shell: authenticated, needs-login, or fresh box.
export async function authState(): Promise<"authenticated" | "login" | "setup"> {
  try {
    await req<unknown>("/admin/api/stats")
    return "authenticated"
  } catch (e) {
    if (String(e).includes("unauthorized")) {
      const s = await req<{ needs_setup: boolean }>("/admin/api/setup-status")
      return s.needs_setup ? "setup" : "login"
    }
    throw e
  }
}

const post = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
})

export const api = {
  privacy: () => req<PrivacyPolicy>("/admin/api/privacy"),
  hardeningStatus: () => req<HardeningStatus>("/admin/api/hardening-status"),
  setPrivacy: (policy: PrivacyPolicy, applyRetentionNow: boolean) =>
    req<{ ok: boolean }>("/admin/api/privacy", post({
      policy,
      apply_retention_now: applyRetentionNow,
      confirm_retention_purge: applyRetentionNow,
    })),
  stats: () => req<Stats>("/admin/api/stats"),
  peers: () => req<Peer[]>("/admin/api/peers"),
  events: () => req<EventItem[]>("/admin/api/events"),
  categories: () => req<Category[]>("/admin/api/categories"),
  blocklist: () => req<BlockEntry[]>("/admin/api/blocklist"),
  settings: () => req<SettingsPolicy>("/admin/api/settings"),
  setSettings: (policy: SettingsMutation) => req<{ ok: boolean }>("/admin/api/settings", post(policy)),
  visits: () => req<{ domain: string; hits: number; last: string }[]>("/admin/api/visits"),
  report: () => req<{ day: string; up: number; down: number }[]>("/admin/api/report"),
  devices: () => req<DeviceHealth[]>("/admin/api/devices"),
  alerts: () => req<{ alerts: AlertItem[]; unacked: number }>("/admin/api/alerts"),
  ackAlert: (id: number) => req<{ ok: boolean }>("/admin/api/alerts", post({ id, ack: true })),
  serverHealth: () => req<ServerHealth>("/admin/api/server-health"),
  peerAction: (token: string, action: string, body?: unknown) =>
    req<{ ok: boolean; ssh_reconcile_pending?: boolean }>(`/admin/api/peers/${token}/${action}`, body !== undefined ? post(body) : { method: "POST" }),
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
  setAutoAccept: (minutes: number) =>
    req<{ ok: boolean }>("/admin/api/settings", post({ auto_accept_minutes: minutes })),
}
