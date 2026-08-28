import { useEffect, useState } from "react"
import { api, type Stats } from "@/lib/api"
import { KpiCard } from "@/components/kpi"
import { EventFeed } from "@/components/event-feed"
import { CountryCard } from "@/components/country-card"
import { Sparkline } from "@/components/sparkline"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { formatBytes } from "@/lib/utils"
import { ArrowDown, ArrowUp, Monitor, ShieldAlert, Users, Ban } from "lucide-react"

export function Overview() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [report, setReport] = useState<{ day: string; up: number; down: number }[]>([])
  useEffect(() => {
    let alive = true
    const load = () => {
      api.stats().then((s) => alive && setStats(s)).catch(() => {})
      api.report().then((r) => alive && setReport(Array.isArray(r) ? r : [])).catch(() => {})
    }
    load()
    const id = setInterval(load, 5000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])

  const series = [...report].reverse().map((d) => (d?.down ?? 0) + (d?.up ?? 0))

  if (!stats) return <p className="text-sm text-muted-foreground">Loading…</p>

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          title="Online now"
          value={stats.online}
          hint={`of ${stats.active} approved devices`}
          icon={<Monitor className="h-4 w-4" />}
          accent="text-emerald-400"
        />
        <KpiCard
          title="Pending approval"
          value={stats.pending}
          hint="waiting for review"
          icon={<Users className="h-4 w-4" />}
          accent={stats.pending > 0 ? "text-amber-400" : undefined}
        />
        <KpiCard
          title="Data transferred"
          value={stats.total_up + stats.total_down}
          format={formatBytes}
          hint={`↑ ${formatBytes(stats.total_up)} · ↓ ${formatBytes(stats.total_down)}`}
          icon={<ArrowUp className="h-4 w-4" />}
        />
        <KpiCard
          title="Blocked / banned"
          value={stats.blocked + stats.banned}
          hint={`${stats.blocked} domains · ${stats.banned} devices`}
          icon={<Ban className="h-4 w-4" />}
          accent="text-red-400"
        />
      </div>

      {stats.kill_switch && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          <ShieldAlert className="h-4 w-4" /> Kill switch is ON — all tunnel traffic is suspended.
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="fade-up lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-base">
              <ArrowDown className="h-4 w-4 text-emerald-400" /> Traffic — last 7 days
            </CardTitle>
          </CardHeader>
          <CardContent>
            {series.length > 0 ? (
              <Sparkline data={series} />
            ) : (
              <p className="py-8 text-center text-sm text-muted-foreground">Not enough traffic history yet.</p>
            )}
          </CardContent>
        </Card>
        <CountryCard countries={stats.countries ?? {}} />
      </div>

      <EventFeed />
    </div>
  )
}
