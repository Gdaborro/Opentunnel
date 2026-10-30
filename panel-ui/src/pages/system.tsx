import { useCallback, useEffect, useState } from "react"
import { api, type ServerHealth } from "@/lib/api"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { Badge } from "@/components/ui/badge"
import { PowerIcon, ShieldAlertIcon, InfoIcon, GaugeIcon } from "lucide-react"
import { formatDuration } from "@/lib/format"

type KillDetail = {
  kill_switch_reason?: string
  kill_switch_allow?: string[]
}

type SshTierDetail = {
  ssh_tier_max_bps?: number
  ssh_tier_daily_mb?: number
  ssh_tier_trickle_kbps?: number
}

export function SystemPage() {
  const [kill, setKill] = useState(false)
  const [health, setHealth] = useState<ServerHealth | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [reason, setReason] = useState("")
  const [allow, setAllow] = useState("")
  const [devices, setDevices] = useState<{ token: string; device_name?: string }[]>([])
  const [saved, setSaved] = useState("")
  // ssh-tier containment controls (bytes/sec cap stored, Mbps shown).
  const [sshMaxMbps, setSshMaxMbps] = useState("0")
  const [sshDailyMB, setSshDailyMB] = useState("0")
  const [sshTrickleKbps, setSshTrickleKbps] = useState("0")
  const [sshSaved, setSshSaved] = useState("")

  const load = useCallback(() => {
    api
      .settings()
      .then((s) => {
        setKill(s.kill_switch)
        const d = s as KillDetail
        setReason(d.kill_switch_reason ?? "")
        setAllow((d.kill_switch_allow ?? []).join("\n"))
        const t = s as SshTierDetail
        const mbps = ((t.ssh_tier_max_bps ?? 0) * 8) / 1e6
        setSshMaxMbps(mbps ? String(+mbps.toFixed(3)) : "0")
        setSshDailyMB(String(t.ssh_tier_daily_mb ?? 0))
        setSshTrickleKbps(String(t.ssh_tier_trickle_kbps ?? 0))
        setLoaded(true)
      })
      .catch(() => {})
    api.serverHealth().then(setHealth).catch(() => {})
    fetch("/admin/api/devices")
      .then((r) => r.json())
      .then((list) => setDevices(list || []))
      .catch(() => {})
  }, [])
  useEffect(load, [load])

  const toggleKill = (on: boolean) => {
    setKill(on)
    api.setKillSwitch(on).catch(() => setKill(!on))
  }

  const saveKillDetail = () => {
    fetch("/admin/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kill_switch: kill,
        kill_switch_reason: reason,
        kill_switch_allow: allow.split("\n").map((t) => t.trim()).filter(Boolean),
      }),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        setSaved("saved")
        setTimeout(() => setSaved(""), 3000)
      })
      .catch((e) => setSaved(`save failed: ${e.message}`))
  }

  const addAllowed = (token: string) => {
    const cur = allow.split("\n").map((t) => t.trim()).filter(Boolean)
    if (!cur.includes(token)) setAllow([...cur, token].join("\n"))
  }

  const saveSshTier = () => {
    fetch("/admin/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ssh_tier_max_bps: Math.max(0, Math.round((parseFloat(sshMaxMbps) || 0) * 1e6 / 8)),
        ssh_tier_daily_mb: Math.max(0, Math.round(parseFloat(sshDailyMB) || 0)),
        ssh_tier_trickle_kbps: Math.max(0, Math.round(parseFloat(sshTrickleKbps) || 0)),
      }),
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        setSshSaved("saved")
        setTimeout(() => setSshSaved(""), 3000)
      })
      .catch((e) => setSshSaved(`save failed: ${e.message}`))
  }

  return (
    <div className="space-y-4">
      <Card className="border-destructive/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <PowerIcon className="size-4 text-destructive" />
            Global Kill Switch
          </CardTitle>
          <CardDescription>
            Suspends all tunnel traffic instantly — new connections are refused
            and existing streams are blocked. Devices stay registered and
            approved; flip it off to resume.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldAlertIcon
              className={kill ? "size-8 text-destructive" : "size-8 text-muted-foreground"}
            />
            <p className={kill ? "font-medium text-destructive" : "font-medium text-muted-foreground"}>
              {kill ? "SUSPENDED — all traffic blocked" : "Traffic flowing normally"}
            </p>
          </div>
          {loaded && <Switch checked={kill} onCheckedChange={toggleKill} />}
        </CardContent>
        <CardContent className="flex flex-col gap-3 border-t border-border/50 pt-4 text-sm">
          <div className="flex flex-col gap-1.5">
            <span className="font-medium">Reason shown to every client while down</span>
            <textarea
              className="min-h-14 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              placeholder="Shut down till further notice"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="font-medium">Allowed devices keep browsing (one token per line)</span>
            <textarea
              className="min-h-11 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
              value={allow}
              onChange={(e) => setAllow(e.target.value)}
            />
          </div>
          {devices.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {devices.slice(0, 12).map((d) => (
                <Button
                  key={d.token}
                  variant="outline"
                  size="sm"
                  onClick={() => addAllowed(d.token)}
                  title={d.token}
                >
                  {d.device_name || d.token.slice(0, 8)} +
                </Button>
              ))}
            </div>
          )}
          <div className="flex items-center gap-3">
            <Button onClick={saveKillDetail}>Save reason + allowlist</Button>
            <span className="text-xs text-muted-foreground">{saved}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <GaugeIcon className="size-4 text-primary" />
            SSH-tier containment
          </CardTitle>
          <CardDescription>
            Keeps the ssh transport — the only tier that survives TLS
            interception with blocked UDP — from reading as a media relay:
            cap each device's sustained rate and give it a daily byte budget.
            After the budget is spent, new streams degrade to the post-budget
            rate (pages keep loading, video cannot).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm">
          <div className="grid gap-3 sm:grid-cols-3">
            <label className="flex flex-col gap-1.5">
              <span className="font-medium">Sustained cap (Mbps, 0 = off)</span>
              <input
                type="number"
                min={0}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                value={sshMaxMbps}
                onChange={(e) => setSshMaxMbps(e.target.value)}
              />
              <span className="text-xs text-muted-foreground">
                Per device, ssh ingress only
              </span>
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="font-medium">Daily budget (MB, 0 = off)</span>
              <input
                type="number"
                min={0}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                value={sshDailyMB}
                onChange={(e) => setSshDailyMB(e.target.value)}
              />
              <span className="text-xs text-muted-foreground">
                Per device; resets at UTC midnight
              </span>
            </label>
            <label className="flex flex-col gap-1.5">
              <span className="font-medium">Post-budget rate (kbps, 0 = 200)</span>
              <input
                type="number"
                min={0}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                value={sshTrickleKbps}
                onChange={(e) => setSshTrickleKbps(e.target.value)}
              />
              <span className="text-xs text-muted-foreground">
                Once the daily budget is spent
              </span>
            </label>
          </div>
          <div className="flex items-center gap-3">
            <Button onClick={saveSshTier}>Save containment policy</Button>
            <span className="text-xs text-muted-foreground">{sshSaved}</span>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <InfoIcon className="size-4 text-primary" />
            Relay Configuration
          </CardTitle>
          <CardDescription>
            Enforcement is server-side: schedules, quotas, category blocks and
            the kill switch apply at the relay, so clients cannot bypass them
            locally
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Relay version</span>
            <Badge variant="secondary">{health?.version ?? "—"}</Badge>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Process uptime</span>
            <span className="tabular-nums">
              {health ? formatDuration(health.process_uptime_s) : "—"}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">Client delivery</span>
            <span>GitHub Releases (auto-update, sha256-verified)</span>
          </div>
          <Separator />
          <p className="text-xs text-muted-foreground">
            Devices authenticate with per-device credentials; the shared master
            secret is not present in client binaries. Banned identities
            (fingerprint + SSH key) are refused at the handshake.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
