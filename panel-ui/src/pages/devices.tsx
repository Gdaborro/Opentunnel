import { useEffect, useState } from "react"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { api, type DeviceHealth, type ServerHealth } from "@/lib/api"
import { formatDuration, timeAgo } from "@/lib/format"
import { ServerIcon, CpuIcon, MemoryStickIcon, ThermometerIcon, MapPinIcon } from "lucide-react"

export function Devices() {
  const [devices, setDevices] = useState<DeviceHealth[]>([])
  const [health, setHealth] = useState<ServerHealth | null>(null)

  useEffect(() => {
    const load = () => {
      api.devices().then(setDevices).catch(() => {})
      api.serverHealth().then(setHealth).catch(() => {})
    }
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ServerIcon className="size-4 text-primary" />
            Core Relay
          </CardTitle>
          <CardDescription>
            OLT-equivalent aggregation point: hardware health, load and uptime
          </CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm @2xl/main:grid-cols-4 @4xl/main:grid-cols-6">
          <Metric label="Status" value={health ? "online" : "—"} good={!!health} />
          <Metric
            label="Host uptime"
            value={health?.host_uptime_s ? formatDuration(health.host_uptime_s) : "—"}
          />
          <Metric
            label="CPU load (1m)"
            value={
              health?.load_1m !== undefined
                ? `${health.load_1m.toFixed(2)} / ${health.cpu_cores ?? "?"} cores`
                : health?.cpu_pct !== undefined
                  ? `${health.cpu_pct.toFixed(0)}%`
                  : "—"
            }
          />
          <Metric
            label="Memory"
            value={
              health?.mem_used_pct !== undefined
                ? `${health.mem_used_pct.toFixed(0)}% of ${((health.mem_total_mb ?? 0) / 1024).toFixed(1)} GB`
                : "—"
            }
          />
          <Metric
            label="Platform"
            value={`${health?.platform ?? "—"} ${health?.kernel ?? ""}`}
          />
          <Metric label="Relay version" value={health?.version ?? "—"} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <CpuIcon className="size-4 text-primary" />
            Device Inventory
          </CardTitle>
          <CardDescription>
            All subscriber devices (CPE) with real-time status, hardware
            health and location
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>
                  <span className="flex items-center gap-1">
                    <CpuIcon className="size-3.5" /> CPU
                  </span>
                </TableHead>
                <TableHead>
                  <span className="flex items-center gap-1">
                    <MemoryStickIcon className="size-3.5" /> Mem
                  </span>
                </TableHead>
                <TableHead>
                  <span className="flex items-center gap-1">
                    <ThermometerIcon className="size-3.5" /> Temp
                  </span>
                </TableHead>
                <TableHead>Uptime</TableHead>
                <TableHead>
                  <span className="flex items-center gap-1">
                    <MapPinIcon className="size-3.5" /> Location
                  </span>
                </TableHead>
                <TableHead className="text-right">Telemetry</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {devices.length === 0 && (
                <TableRow>
                  <TableCell colSpan={9} className="text-muted-foreground">
                    No devices registered.
                  </TableCell>
                </TableRow>
              )}
              {devices.map((d) => (
                <TableRow key={d.token}>
                  <TableCell>
                    <div className="font-medium">
                      {d.device_name || d.token.slice(0, 8)}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {d.last_ip || "no address recorded"}
                    </div>
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={d.status} />
                  </TableCell>
                  <TableCell className="text-sm">
                    {d.version ? (
                      <>
                        {d.version}
                        <span className="text-muted-foreground"> · {d.os}</span>
                      </>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {d.version ? `${d.cpu_pct.toFixed(0)}%` : "—"}
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {d.version ? `${d.mem_pct.toFixed(0)}%` : "—"}
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {d.temp_c > 0 ? `${d.temp_c.toFixed(0)}°C` : "—"}
                  </TableCell>
                  <TableCell>{d.uptime_s ? formatDuration(d.uptime_s) : "—"}</TableCell>
                  <TableCell className="text-sm">
                    {d.country || "—"}
                  </TableCell>
                  <TableCell className="text-right text-sm text-muted-foreground">
                    {d.at ? timeAgo(d.at) : "never"}
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

function Metric({
  label,
  value,
  good,
}: {
  label: string
  value: string
  good?: boolean
}) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="flex items-center gap-1.5 font-medium">
        {good && <span className="size-2 rounded-full bg-primary" />}
        {value}
      </span>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "approved"
      ? "bg-primary/15 text-primary"
      : status === "banned"
        ? "bg-destructive/15 text-destructive"
        : status === "pending"
          ? "bg-chart-3/15 text-chart-3"
          : "bg-muted text-muted-foreground"
  return <Badge variant="outline" className={tone}>{status}</Badge>
}
