import { useEffect, useState } from "react"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { SectionCards } from "@/components/section-cards"
import {
  ChartAreaInteractive,
  type TrafficPoint,
} from "@/components/chart-area-interactive"
import { api, type EventItem, type ServerHealth, type Stats } from "@/lib/api"
import { timeAgo } from "@/lib/format"
import { GlobeIcon, RadioTowerIcon } from "lucide-react"

const eventTone: Record<string, string> = {
  ban: "bg-destructive/15 text-destructive",
  kick: "bg-chart-3/15 text-chart-3",
  "kill-switch": "bg-destructive/15 text-destructive",
  approve: "bg-primary/15 text-primary",
  register: "bg-chart-2/15 text-chart-2",
}

export function Overview() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [health, setHealth] = useState<ServerHealth | null>(null)
  const [events, setEvents] = useState<EventItem[]>([])
  const [report, setReport] = useState<TrafficPoint[]>([])
  const [unacked, setUnacked] = useState(0)

  useEffect(() => {
    const load = () => {
      api.stats().then(setStats).catch(() => {})
      api.serverHealth().then(setHealth).catch(() => {})
      api.events().then(setEvents).catch(() => {})
      api.alerts().then((a) => setUnacked(a.unacked)).catch(() => {})
    }
    api
      .report()
      .then((r) => setReport(r.map((p) => ({ date: p.day, up: p.up, down: p.down }))))
      .catch(() => {})
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  const countries = stats?.countries ?? {}
  const countryList = Object.entries(countries).sort((a, b) => b[1] - a[1])

  return (
    <>
      <SectionCards
        online={stats?.online ?? 0}
        total={stats?.total ?? 0}
        bytesUp={stats?.total_up ?? 0}
        bytesDown={stats?.total_down ?? 0}
        unacked={unacked}
        uptimeLabel={
          health ? formatUptime(health.process_uptime_s) : "—"
        }
        version={health?.version ?? ""}
      />

      <div className="grid grid-cols-1 gap-4 @3xl/main:grid-cols-3">
        <div className="@3xl/main:col-span-2">
          <ChartAreaInteractive
            data={report}
            title="Network Traffic"
            description="Relayed volume per day across all subscribers"
          />
        </div>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <GlobeIcon className="size-4 text-primary" />
                Subscriber Locations
              </CardTitle>
              <CardDescription>By public IP (GeoIP)</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {countryList.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  No location data yet.
                </p>
              )}
              {countryList.map(([country, count]) => (
                <div
                  key={country}
                  className="flex items-center justify-between text-sm"
                >
                  <span>{country || "Unknown"}</span>
                  <Badge variant="secondary" className="tabular-nums">
                    {count}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="flex-1">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <RadioTowerIcon className="size-4 text-primary" />
                Live Event Feed
              </CardTitle>
              <CardDescription>Registrations, bans, policy changes</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-2.5">
              {events.length === 0 && (
                <p className="text-sm text-muted-foreground">No events yet.</p>
              )}
              {events.slice(0, 12).map((e, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <Badge
                    variant="outline"
                    className={`mt-0.5 shrink-0 text-[10px] uppercase ${eventTone[e.kind] ?? ""}`}
                  >
                    {e.kind}
                  </Badge>
                  <span className="min-w-0 flex-1 truncate">{e.detail}</span>
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {timeAgo(e.at)}
                  </span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}

function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}
