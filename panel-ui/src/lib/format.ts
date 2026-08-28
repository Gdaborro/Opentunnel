export function formatBytes(n: number): string {
  if (!n || n <= 0) return "0 B"
  const units = ["B", "KB", "MB", "GB", "TB", "PB"]
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

export function timeAgo(s: string): string {
  if (!s) return "never"
  const t = s.includes("T") ? new Date(s).getTime() : new Date(s.replace(" ", "T") + "Z").getTime()
  if (isNaN(t)) return s
  const secs = Math.max(0, (Date.now() - t) / 1000)
  if (secs < 60) return `${Math.floor(secs)}s ago`
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`
  return `${Math.floor(secs / 86400)}d ago`
}

export function formatDuration(totalSeconds: number): string {
  if (!totalSeconds || totalSeconds <= 0) return "—"
  const d = Math.floor(totalSeconds / 86400)
  const h = Math.floor((totalSeconds % 86400) / 3600)
  const m = Math.floor((totalSeconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

export function shortToken(token: string): string {
  return token.slice(0, 8)
}
