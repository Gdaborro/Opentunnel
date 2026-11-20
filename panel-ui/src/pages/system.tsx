import { useCallback, useEffect, useState } from "react"
import { api, type ServerHealth, type SettingsPolicy } from "@/lib/api"
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
import { HardeningControls } from "@/components/hardening-controls"

export function SystemPage() {
  const [kill, setKill] = useState(false)
  const [health, setHealth] = useState<ServerHealth | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [toggleBusy, setToggleBusy] = useState(false)
  const [reason, setReason] = useState("")
  const [allow, setAllow] = useState("")
  const [devices, setDevices] = useState<{ token: string; device_name?: string }[]>([])
  const [saved, setSaved] = useState("")
  // ssh-tier containment controls (bytes/sec cap stored, Mbps shown).
  const [sshMaxMbps, setSshMaxMbps] = useState("0")
  const [sshDailyMB, setSshDailyMB] = useState("0")
  const [sshTrickleKbps, setSshTrickleKbps] = useState("0")
  const [sshSaved, setSshSaved] = useState("")
  const [policyMessage, setPolicyMessage] = useState("")

  const applySettings = useCallback((s: SettingsPolicy) => {
    setKill(s.kill_switch)
    setReason(s.kill_switch_reason)
    setAllow(s.kill_switch_allow.join("\n"))
    const mbps = (s.ssh_tier_max_bps * 8) / 1e6
    setSshMaxMbps(String(mbps))
    setSshDailyMB(String(s.ssh_tier_daily_mb))
    setSshTrickleKbps(String(s.ssh_tier_trickle_kbps))
    setLoaded(true)
  }, [])

  const load = useCallback(() => {
    api
      .settings()
      .then((value) => {
        applySettings(value)
        setPolicyMessage("")
      })
      .catch(() => {
        setLoaded(false)
        setPolicyMessage("Policy status unavailable. No defaults were substituted; refresh before editing.")
      })
    api.serverHealth().then(setHealth).catch(() => setHealth(null))
    api.devices().then(setDevices).catch(() => setDevices([]))
  }, [applySettings])
  useEffect(load, [load])

  const toggleKill = async (on: boolean) => {
    if (toggleBusy || !loaded) return
    setToggleBusy(true)
    setPolicyMessage("")
    try {
      await api.setKillSwitch(on)
      const verified = await api.settings()
      if (verified.kill_switch !== on) throw new Error("concurrent policy change")
      setKill(verified.kill_switch)
      setPolicyMessage("Kill-switch state committed and read back. Relay policy refresh still applies.")
    } catch {
      setLoaded(false)
      setPolicyMessage("Kill-switch update or read-back failed. State is unconfirmed; refresh before retrying.")
    } finally { setToggleBusy(false) }
  }

  const saveKillDetail = async () => {
    if (toggleBusy || !loaded) return
    const requestedAllow = [...new Set(allow.split("\n").map((t) => t.trim()).filter(Boolean))].sort()
    const requestedReason = reason.trim()
    setToggleBusy(true)
    setSaved("")
    try {
      await api.setSettings({ kill_switch_reason: requestedReason, kill_switch_allow: requestedAllow })
      const verified = await api.settings()
      if (verified.kill_switch_reason !== requestedReason || JSON.stringify([...verified.kill_switch_allow].sort()) !== JSON.stringify(requestedAllow)) throw new Error("concurrent policy change")
      setKill(verified.kill_switch)
      setReason(verified.kill_switch_reason)
      setAllow(verified.kill_switch_allow.join("\n"))
      setSaved("Saved and verified; a concurrent kill-switch toggle was preserved.")
    } catch {
      setLoaded(false)
      setSaved("Save or read-back failed. Policy state is unconfirmed; refresh before retrying.")
    } finally { setToggleBusy(false) }
  }

  const addAllowed = (token: string) => {
    const cur = allow.split("\n").map((t) => t.trim()).filter(Boolean)
    if (!cur.includes(token)) setAllow([...cur, token].join("\n"))
  }

  const saveSshTier = async () => {
    if (toggleBusy || !loaded) return
    const values = [sshMaxMbps, sshDailyMB, sshTrickleKbps]
    if (values.some((value) => !value.trim() || !Number.isFinite(Number(value)) || Number(value) < 0)) {
      setSshSaved("Enter explicit nonnegative numbers. Invalid or empty fields are not treated as zero.")
      return
    }
    const requested = {
      ssh_tier_max_bps: Math.round(Number(sshMaxMbps) * 1e6 / 8),
      ssh_tier_daily_mb: Math.round(Number(sshDailyMB)),
      ssh_tier_trickle_kbps: Math.round(Number(sshTrickleKbps)),
    }
    if (Object.values(requested).some((value) => !Number.isSafeInteger(value))) {
      setSshSaved("Containment values are outside safe numeric limits.")
      return
    }
    setToggleBusy(true)
    setSshSaved("")
    try {
      await api.setSettings(requested)
      const verified = await api.settings()
      if (verified.ssh_tier_max_bps !== requested.ssh_tier_max_bps || verified.ssh_tier_daily_mb !== requested.ssh_tier_daily_mb || verified.ssh_tier_trickle_kbps !== requested.ssh_tier_trickle_kbps) throw new Error("concurrent policy change")
      setKill(verified.kill_switch)
      setSshSaved("Containment policy saved and verified.")
    } catch {
      setLoaded(false)
      setSshSaved("Save or read-back failed. Containment state is unconfirmed; refresh before retrying.")
    } finally { setToggleBusy(false) }
  }

  return (
    <div className="space-y-4">
      <HardeningControls />
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" disabled={toggleBusy} onClick={load}>Refresh system policy</Button>
        <p role="status" aria-live="polite" className="text-sm">{policyMessage}</p>
      </div>
      <Card className="border-destructive/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <PowerIcon className="size-4 text-destructive" />
            Global Kill Switch
          </CardTitle>
          <CardDescription>
            Suspends non-allowlisted traffic after the relay policy refresh — new connections are refused
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
              {!loaded ? "Policy status unavailable" : kill ? "SUSPENDED — operator allowlist applies" : "Traffic flowing normally"}
            </p>
          </div>
          {loaded && <Switch aria-label="Global Kill Switch" checked={kill} disabled={toggleBusy} onCheckedChange={toggleKill} />}
        </CardContent>
        <CardContent className="flex flex-col gap-3 border-t border-border/50 pt-4 text-sm">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="kill-reason" className="font-medium">Reason shown to every client while down</label>
            <textarea
              id="kill-reason"
              maxLength={500}
              disabled={!loaded || toggleBusy}
              className="min-h-14 w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              placeholder="Shut down till further notice"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="kill-allowlist" className="font-medium">Allowed devices keep browsing (one token per line)</label>
            <textarea
              id="kill-allowlist"
              disabled={!loaded || toggleBusy}
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
                  disabled={!loaded || toggleBusy}
                  onClick={() => addAllowed(d.token)}
                  title={d.token}
                >
                  {d.device_name || d.token.slice(0, 8)} +
                </Button>
              ))}
            </div>
          )}
          <div className="flex items-center gap-3">
            <Button disabled={!loaded || toggleBusy} onClick={saveKillDetail}>Save reason + allowlist</Button>
            <span role="status" aria-live="polite" className="text-xs text-muted-foreground">{saved}</span>
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
            Applies an aggregate per-device rate cap and daily byte budget
            on SSH ingress. After the budget is spent, traffic is paced at
            the post-budget rate. This is resource containment, not proof
            of undetectability or guaranteed page/video behavior.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 text-sm">
          <div className="grid gap-3 sm:grid-cols-3">
            <label className="flex flex-col gap-1.5">
              <span className="font-medium">Sustained cap (Mbps, 0 = off)</span>
              <input
                type="number"
                min={0}
                step="any"
                aria-label="SSH sustained cap in Mbps"
                disabled={!loaded || toggleBusy}
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
                aria-label="SSH daily budget in MB"
                disabled={!loaded || toggleBusy}
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
                aria-label="SSH post-budget rate in kbps"
                disabled={!loaded || toggleBusy}
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
            <Button disabled={!loaded || toggleBusy} onClick={saveSshTier}>Save containment policy</Button>
            <span role="status" aria-live="polite" className="text-xs text-muted-foreground">{sshSaved}</span>
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
            <span>GitHub Releases (signed targets, supervised replacement)</span>
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
