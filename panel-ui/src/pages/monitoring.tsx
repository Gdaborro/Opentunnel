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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  ChartAreaInteractive,
  type TrafficPoint,
} from "@/components/chart-area-interactive"
import {
  api,
  type AlertItem,
  type DeviceHealth,
  type ServerHealth,
} from "@/lib/api"
import { timeAgo } from "@/lib/format"
import {
  ActivityIcon,
  GaugeIcon,
  TimerIcon,
  WifiIcon,
  CheckIcon,
  BellRingIcon,
} from "lucide-react"

export function Monitoring() {
  const [devices, setDevices] = useState<DeviceHealth[]>([])
  const [health, setHealth] = useState<ServerHealth | null>(null)
  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [visits, setVisits] = useState<{ domain: string; hits: number; last: string }[]>([])
  const [report, setReport] = useState<TrafficPoint[]>([])
  const [readFailures, setReadFailures] = useState<string[]>([])
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const busyRef = useRef(false)

  const load = useCallback(async () => {
    if (busyRef.current) return
    const results = await Promise.allSettled([
      api.devices().then(setDevices),
      api.serverHealth().then(setHealth),
      api.alerts().then((a) => setAlerts(a.alerts)),
      api.visits().then(setVisits),
      api.report().then((r) => setReport(r.map((p) => ({ date: p.day, up: p.up, down: p.down })))),
    ])
    const names = ["device telemetry", "relay health", "alerts", "visits", "traffic history"]
    setReadFailures(results.flatMap((result, index) => result.status === "rejected" ? [names[index]] : []))
    setLoaded(true)
  }, [])
  useEffect(() => {
    void load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [load])

  const acknowledge = async (id: number) => {
    if (busyRef.current || !loaded || readFailures.includes("alerts")) return
    busyRef.current = true
    setBusy(true)
    setMessage("")
    try {
      await api.ackAlert(id)
      const verified = await api.alerts()
      if (!verified.alerts.find((item) => item.id === id)?.acked) throw new Error("acknowledgement not confirmed")
      setAlerts(verified.alerts)
      setMessage("Alert acknowledgement committed and read back.")
    } catch {
      setMessage("Acknowledgement or read-back failed. Alert state is unconfirmed; refresh before retrying.")
    } finally {
      busyRef.current = false
      setBusy(false)
      await load()
    }
  }

  const reporting = devices.filter((d) => d.latency_ms > 0 || d.cpu_pct > 0)
  const avg = (f: (d: DeviceHealth) => number) =>
    reporting.length === 0
      ? 0
      : reporting.reduce((s, d) => s + f(d), 0) / reporting.length
  const avgLatency = avg((d) => d.latency_ms)
  const avgJitter = avg((d) => d.jitter_ms)
  const avgLoss = avg((d) => d.probe_loss_pct)

  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" disabled={busy} onClick={() => { void load() }}>Refresh monitoring status</Button>
        <p role="status" aria-live="polite" className="text-sm">{message}</p>
        {!loaded && <p role="status" className="text-sm">Reading monitoring status…</p>}
        {readFailures.length > 0 && <p role="alert" className="text-sm text-destructive">Unavailable: {readFailures.join(", ")}. Previously shown data may be stale; not an all-clear.</p>}
      </div>
      <div className="grid grid-cols-1 gap-4 @xl/main:grid-cols-2 @4xl/main:grid-cols-4">
        <QualityCard
          icon={<TimerIcon />}
          label="Tunnel Latency"
          value={!readFailures.includes("device telemetry") && reporting.length ? `${avgLatency.toFixed(0)} ms` : "—"}
          hint={`avg across ${reporting.length} reporting device${reporting.length === 1 ? "" : "s"}`}
        />
        <QualityCard
          icon={<ActivityIcon />}
          label="Jitter"
          value={!readFailures.includes("device telemetry") && reporting.length ? `${avgJitter.toFixed(1)} ms` : "—"}
          hint="mean inter-probe variance"
        />
        <QualityCard
          icon={<WifiIcon />}
          label="Probe Loss"
          value={!readFailures.includes("device telemetry") && reporting.length ? `${avgLoss.toFixed(1)}%` : "—"}
          hint="failed tunnel probes, 20-probe window"
        />
        <QualityCard
          icon={<GaugeIcon />}
          label="Active Sessions"
          value={!readFailures.includes("relay health") && health?.relay_online ? String(health.active_sessions) : "—"}
          hint={
            health?.load_1m !== undefined
              ? `relay load ${health.load_1m.toFixed(2)} · ${health.cpu_cores ?? "?"} cores`
              : "live smux sessions on the relay"
          }
        />
      </div>

      <div className="grid grid-cols-1 gap-4 @3xl/main:grid-cols-3">
        <div className="@3xl/main:col-span-2">
          <ChartAreaInteractive
            data={report}
            title="Historical Traffic"
            description="Capacity planning: daily relayed volume vs. baseline"
          />
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <BellRingIcon className="size-4 text-primary" />
              Alerts &amp; Notifications
            </CardTitle>
            <CardDescription>
              Threshold breaches, faults and security events
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2.5">
            {alerts.length === 0 && loaded && (
              <p className="text-sm text-muted-foreground">{readFailures.includes("alerts") ? "Alerts unavailable — not confirmed clear." : "No alerts recorded."}</p>
            )}
            {alerts.slice(0, 10).map((a) => (
              <div key={a.id} className="flex items-start gap-2 text-sm">
                <Badge
                  variant="outline"
                  className={`mt-0.5 shrink-0 text-[10px] uppercase ${sevTone(a.severity)}`}
                >
                  {a.severity}
                </Badge>
                <div className="min-w-0 flex-1">
                  <p className={`truncate ${a.acked ? "text-muted-foreground line-through" : ""}`}>
                    {a.message}
                  </p>
                  <p className="text-xs text-muted-foreground">{timeAgo(a.at)}</p>
                </div>
                {!a.acked && (
                  <Button
                    size="icon"
                    variant="ghost"
                    className="size-6 shrink-0"
                     title="Acknowledge"
                     aria-label={`Acknowledge alert ${a.id}`}
                     disabled={busy || !loaded || readFailures.includes("alerts")}
                     onClick={() => { void acknowledge(a.id) }}
                  >
                    <CheckIcon className="size-3.5" />
                  </Button>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Top Talkers</CardTitle>
          <CardDescription>
            Most visited destinations through the tunnel (traffic analysis)
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Destination</TableHead>
                <TableHead className="text-right">Hits</TableHead>
                <TableHead className="text-right">Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visits.length === 0 && loaded && (
                <TableRow>
                  <TableCell colSpan={3} className="text-muted-foreground">
                    {readFailures.includes("visits") ? "Visit inventory unavailable — no empty inventory substituted." : "No traffic recorded yet."}
                  </TableCell>
                </TableRow>
              )}
              {visits.slice(0, 15).map((v) => (
                <TableRow key={v.domain}>
                  <TableCell className="font-medium">{v.domain}</TableCell>
                  <TableCell className="text-right tabular-nums">{v.hits}</TableCell>
                  <TableCell className="text-right text-muted-foreground">
                    {timeAgo(v.last)}
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

function QualityCard({
  icon,
  label,
  value,
  hint,
}: {
  icon: React.ReactNode
  label: string
  value: string
  hint: string
}) {
  return (
    <Card className="@container/card">
      <CardHeader>
        <CardDescription className="flex items-center gap-1.5">
          <span className="[&>svg]:size-3.5 [&>svg]:text-primary">{icon}</span>
          {label}
        </CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
          {value}
        </CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">{hint}</CardContent>
    </Card>
  )
}

function sevTone(sev: string): string {
  switch (sev) {
    case "critical":
      return "bg-destructive/15 text-destructive"
    case "warning":
      return "bg-chart-3/15 text-chart-3"
    default:
      return "bg-chart-2/15 text-chart-2"
  }
}
