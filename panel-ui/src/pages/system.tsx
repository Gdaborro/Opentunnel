import { useCallback, useEffect, useState } from "react"
import { api, type ServerHealth } from "@/lib/api"
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
import { PowerIcon, ShieldAlertIcon, InfoIcon } from "lucide-react"
import { formatDuration } from "@/lib/format"

export function SystemPage() {
  const [kill, setKill] = useState(false)
  const [health, setHealth] = useState<ServerHealth | null>(null)
  const [loaded, setLoaded] = useState(false)

  const load = useCallback(() => {
    api
      .settings()
      .then((s) => {
        setKill(s.kill_switch)
        setLoaded(true)
      })
      .catch(() => {})
    api.serverHealth().then(setHealth).catch(() => {})
  }, [])
  useEffect(load, [load])

  const toggleKill = (on: boolean) => {
    setKill(on)
    api.setKillSwitch(on).catch(() => setKill(!on))
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
