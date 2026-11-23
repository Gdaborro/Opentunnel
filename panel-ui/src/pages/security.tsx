import { useCallback, useEffect, useRef, useState } from "react"
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
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const [readFailures, setReadFailures] = useState<string[]>([])
  const [loaded, setLoaded] = useState(false)
  const busyRef = useRef(false)

  const load = useCallback(async () => {
    if (busyRef.current) return
    const results = await Promise.allSettled([
      api.peers().then(setPeers),
      api.devices().then(setDevices),
      api.alerts().then((a) => setAlerts(a.alerts)),
      api.categories().then(setCategories),
      api.serverHealth().then(setHealth),
      api.settings().then((s) => {
        setAaUntil(s.auto_accept_until)
        setAaActive(s.auto_accept_active)
      }),
    ])
    const names = ["device admission", "device telemetry", "security alerts", "filtering categories", "relay health", "admission policy"]
    setReadFailures(results.flatMap((result, index) => result.status === "rejected" ? [names[index]] : []))
    setLoaded(true)
  }, [])
  useEffect(() => {
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [load])

  const mutate = async (action: () => Promise<void>) => {
    if (busyRef.current || !loaded || readFailures.length > 0) return
    busyRef.current = true
    setBusy(true)
    setMessage("")
    try { await action() }
    catch { setMessage("Operation or read-back failed. State is unconfirmed; refresh before retrying.") }
    finally {
      busyRef.current = false
      setBusy(false)
      await load()
    }
  }

  const openWindow = (minutes: number) => {
    if (minutes > 0 && !window.confirm(`Open default-operator auto-accept for ${minutes} minutes? Trusted-pool enrollment still requires separate administrator approval.`)) return
    void mutate(async () => {
      await api.setAutoAccept(minutes)
      const verified = await api.settings()
      if (verified.auto_accept_active !== (minutes > 0)) throw new Error("concurrent admission change")
      setAaUntil(verified.auto_accept_until)
      setAaActive(verified.auto_accept_active)
      setMessage("Admission window committed and read back. Pool-account login still does not approve devices.")
    })
  }

  const pending = peers.filter((p) => p.status === "pending")
  const securityAlerts = alerts.filter(
    (a) => !a.acked && (a.severity !== "info" || a.kind === "security" || a.kind === "nac")
  )
  const versionMap = new Map(devices.map((d) => [d.token, d]))

  const act = (token: string, action: string) => {
    void mutate(async () => {
      const result = await api.peerAction(token, action)
      const verified = await api.peers()
      const expected = action === "approve" ? "approved" : "banned"
      if (verified.find((peer) => peer.token === token)?.status !== expected) throw new Error("concurrent admission change")
      setPeers(verified)
      setMessage(result.ssh_reconcile_pending
        ? "Admission policy committed, but SSH reconciliation is pending. The authority will retry; do not assume the SSH file is applied."
        : "Admission action committed and read back.")
    })
  }

  const toggleCategory = (category: string, enabled: boolean) => {
    void mutate(async () => {
      await api.setCategory(category, enabled)
      const verified = await api.categories()
      if (verified.find((item) => item.category === category)?.enabled !== enabled) throw new Error("concurrent filter change")
      setCategories(verified)
      setMessage("Filtering choice committed and read back.")
    })
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" disabled={busy} onClick={() => { void load() }}>Refresh security status</Button>
        <p role="status" aria-live="polite" className="text-sm">{message}</p>
        {!loaded && <p role="status" className="text-sm">Reading security status…</p>}
        {readFailures.length > 0 && <p role="alert" className="text-sm text-destructive">Unavailable: {readFailures.join(", ")}. Previously shown data may be stale; not an all-clear.</p>}
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <FingerprintIcon className="size-4 text-primary" />
            Network Access Control
          </CardTitle>
          <CardDescription>
            Identity-based admission: every device authenticates with its own
            per-device key; telemetry is self-reported, not hardware attestation
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 bg-muted/30 p-3">
            <div className="text-sm">
              {!loaded || readFailures.includes("admission policy") ? <span>Admission policy unavailable</span> : aaActive ? (
                <>
                  <span className="mr-2 inline-flex size-2 animate-pulse rounded-full bg-primary" />
                  <span className="font-medium text-primary">Auto-accept open</span>
                  <span className="text-muted-foreground"> — default-operator bootstrap devices may be approved until {new Date(aaUntil ?? "").toLocaleTimeString()}. Pool-account devices still need administrator approval.</span>
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
                <Button size="sm" variant="outline" disabled={busy || !loaded || readFailures.length > 0} onClick={() => openWindow(0)}>
                  Close window
                </Button>
              ) : (
                <>
                  <Button size="sm" variant="outline" disabled={busy || !loaded || readFailures.length > 0} onClick={() => openWindow(15)}>
                    Open 15 min
                  </Button>
                  <Button size="sm" variant="outline" disabled={busy || !loaded || readFailures.length > 0} onClick={() => openWindow(30)}>
                    30 min
                  </Button>
                  <Button size="sm" variant="outline" disabled={busy || !loaded || readFailures.length > 0} onClick={() => openWindow(60)}>
                    60 min
                  </Button>
                </>
              )}
            </div>
          </div>
          {pending.length === 0 ? (
            <p className="flex items-center gap-2 text-sm text-muted-foreground">
              <ShieldCheckIcon className="size-4 text-primary" />
              {!loaded || readFailures.includes("device admission") ? "Admission queue unavailable — not confirmed clear." : "Admission queue clear — no devices awaiting approval."}
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
                             disabled={busy || !loaded || readFailures.length > 0}
                            onClick={() => act(p.token, "approve")}
                          >
                            <CheckIcon /> Approve
                          </Button>
                          <Button
                            size="sm"
                             variant="destructive"
                             disabled={busy || !loaded || readFailures.length > 0}
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
                {!loaded || readFailures.includes("security alerts") ? "Security alerts unavailable — not confirmed clear." : "No active security alerts."}
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
                   aria-label={`Block ${c.category}`}
                   disabled={busy || !loaded || readFailures.length > 0}
                   checked={c.enabled}
                   onCheckedChange={(on) => toggleCategory(c.category, on)}
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
            for update (clients self-update from Ed25519-signed GitHub
            releases; the signature key is baked into every binary)
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
                    reported version
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
                        self-reported
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
