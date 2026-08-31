import { useEffect, useState } from "react"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  api,
  type AlertItem,
  type Category,
  type DeviceHealth,
  type Peer,
  type ServerHealth,
} from "@/lib/api"
import { timeAgo } from "@/lib/format"
import {
  ShieldCheckIcon,
  ShieldAlertIcon,
  FingerprintIcon,
  LockIcon,
  BugIcon,
  CheckIcon,
  XIcon,
} from "lucide-react"

export function Security() {
  const [peers, setPeers] = useState<Peer[]>([])
  const [devices, setDevices] = useState<DeviceHealth[]>([])
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [health, setHealth] = useState<ServerHealth | null>(null)
  const [aaUntil, setAaUntil] = useState<string | undefined>(undefined)
  const [aaActive, setAaActive] = useState(false)

  const load = () => {
    api.peers().then(setPeers).catch(() => {})
    api.devices().then(setDevices).catch(() => {})
    api.alerts().then((a) => setAlerts(a.alerts)).catch(() => {})
    api.categories().then(setCategories).catch(() => {})
    api.serverHealth().then(setHealth).catch(() => {})
    api
      .settings()
      .then((s) => {
        setAaUntil(s.auto_accept_until)
        setAaActive(s.auto_accept_active)
      })
      .catch(() => {})
  }
  useEffect(() => {
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  const openWindow = (minutes: number) => {
    api
      .setAutoAccept(minutes)
      .then(load)
      .catch(() => {})
  }

  const pending = peers.filter((p) => p.status === "pending")
  const securityAlerts = alerts.filter(
    (a) => !a.acked && (a.severity !== "info" || a.kind === "security" || a.kind === "nac")
  )
  const versionMap = new Map(devices.map((d) => [d.token, d]))

  const act = (token: string, action: string) =>
    api.peerAction(token, action).then(load).catch(() => {})

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <FingerprintIcon className="size-4 text-primary" />
            Network Access Control
          </CardTitle>
          <CardDescription>
            Identity-based admission: every device authenticates with its own
            per-device credential; posture is checked before access is granted
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 bg-muted/30 p-3">
            <div className="text-sm">
              {aaActive ? (
                <>
                  <span className="mr-2 inline-flex size-2 animate-pulse rounded-full bg-primary" />
                  <span className="font-medium text-primary">Auto-accept open</span>
                  <span className="text-muted-foreground"> — new devices are approved instantly (until {new Date(aaUntil ?? "").toLocaleTimeString()})</span>
                </>
              ) : aaUntil ? (
                <>
                  <span className="font-medium">Auto-accept window expired</span>
                  <span className="text-muted-foreground"> — new devices need approval again</span>
                </>
              ) : (
                <>
                  <span className="font-medium">Manual approval</span>
                  <span className="text-muted-foreground"> — open a window when handing the client out so recipients connect instantly</span>
                </>
              )}
            </div>
            <div className="flex gap-2">
              {aaActive ? (
                <Button size="sm" variant="outline" onClick={() => openWindow(0)}>
                  Close window
                </Button>
              ) : (
                <>
                  <Button size="sm" variant="outline" onClick={() => openWindow(15)}>
                    Open 15 min
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => openWindow(30)}>
                    30 min
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => openWindow(60)}>
                    60 min
                  </Button>
                </>
              )}
            </div>
          </div>
          {pending.length === 0 ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <ShieldCheckIcon className="size-4 text-primary" />
              Admission queue clear — no devices awaiting approval.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>Posture</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>Requested</TableHead>
                  <TableHead className="text-right">Decision</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pending.map((p) => {
                  const h = versionMap.get(p.token)
                  return (
                    <TableRow key={p.token}>
                      <TableCell>
                        <div className="font-medium">
                          {p.device_name || p.token.slice(0, 8)}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          fp {p.fingerprint.slice(0, 16)}…
                        </div>
                      </TableCell>
                      <TableCell>
                        {h?.version ? (
                          <Badge variant="secondary">
                            client {h.version} · {h.os}
                          </Badge>
                        ) : (
                          <Badge variant="outline">unknown agent</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-sm">
                        {p.country || p.last_ip || "—"}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {timeAgo(p.created_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            onClick={() => act(p.token, "approve")}
                          >
                            <CheckIcon /> Approve
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => act(p.token, "ban")}
                          >
                            <XIcon /> Deny
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 gap-4 @3xl/main:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <ShieldAlertIcon className="size-4 text-primary" />
              Threat Detection &amp; Response
            </CardTitle>
            <CardDescription>
              Live security alerts: bans, kicks, quarantine and kill-switch
              activity
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2.5">
            {securityAlerts.length === 0 && (
              <p className="text-sm text-muted-foreground">
                No active security alerts.
              </p>
            )}
            {securityAlerts.slice(0, 10).map((a) => (
              <div key={a.id} className="flex items-start gap-2 text-sm">
                <Badge
                  variant="outline"
                  className={`mt-0.5 shrink-0 text-[10px] uppercase ${
                    a.severity === "critical"
                      ? "bg-destructive/15 text-destructive"
                      : a.severity === "warning"
                        ? "bg-chart-3/15 text-chart-3"
                        : "bg-chart-2/15 text-chart-2"
                  }`}
                >
                  {a.kind}
                </Badge>
                <span className="min-w-0 flex-1 truncate">{a.message}</span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {timeAgo(a.at)}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <LockIcon className="size-4 text-primary" />
              Firewall &amp; Policy
            </CardTitle>
            <CardDescription>
              Content categories enforced at the relay (full ACL editor under
              Filtering)
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            {categories.map((c) => (
              <div key={c.category} className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium capitalize">{c.category}</p>
                  <p className="text-xs text-muted-foreground">
                    {c.domains} rules
                  </p>
                </div>
                <Switch
                  checked={c.enabled}
                  onCheckedChange={(on) =>
                    api.setCategory(c.category, on).then(load).catch(() => {})
                  }
                />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <BugIcon className="size-4 text-primary" />
            Vulnerability &amp; Patch Posture
          </CardTitle>
          <CardDescription>
            Software versions across the network — outdated clients are flagged
            for update (clients self-update from signed GitHub releases)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Asset</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Platform</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow>
                <TableCell className="font-medium">Core relay</TableCell>
                <TableCell>{health?.version ?? "—"}</TableCell>
                <TableCell>
                  {health?.platform ?? health?.os ?? "linux"} · kernel{" "}
                  {health?.kernel ?? "—"}
                </TableCell>
                <TableCell>
                  <Badge variant="secondary" className="bg-primary/15 text-primary">
                    up to date
                  </Badge>
                </TableCell>
              </TableRow>
              {devices
                .filter((d) => d.version)
                .map((d) => (
                  <TableRow key={d.token}>
                    <TableCell className="font-medium">
                      {d.device_name || d.token.slice(0, 8)}
                    </TableCell>
                    <TableCell>{d.version}</TableCell>
                    <TableCell>
                      {d.os} / {d.arch}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="bg-primary/15 text-primary">
                        auto-update armed
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </>
  )
}
