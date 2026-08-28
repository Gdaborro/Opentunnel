import { useEffect, useState } from "react"
import { api, type EventItem } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { timeAgo } from "@/lib/utils"
import { Activity } from "lucide-react"

const kindVariant: Record<string, "success" | "warning" | "destructive" | "secondary"> = {
  ban: "destructive",
  kick: "warning",
  "kill-switch": "destructive",
  approve: "success",
  register: "secondary",
  blocklist: "warning",
  category: "warning",
  unban: "success",
}

export function EventFeed({ limit = 14 }: { limit?: number }) {
  const [events, setEvents] = useState<EventItem[]>([])
  useEffect(() => {
    let alive = true
    const load = () => api.events().then((e) => alive && setEvents(e)).catch(() => {})
    load()
    const id = setInterval(load, 10000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])
  return (
    <Card className="fade-up h-full">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Activity className="h-4 w-4 text-emerald-400" /> Live events
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {events.length === 0 && <p className="text-sm text-muted-foreground">No events yet.</p>}
        {events.slice(0, limit).map((e, i) => (
          <div key={i} className="flex items-start justify-between gap-3 text-sm">
            <div className="flex min-w-0 items-center gap-2">
              <Badge variant={kindVariant[e.kind] ?? "secondary"} className="shrink-0 capitalize">
                {e.kind}
              </Badge>
              <span className="truncate text-foreground/90">{e.detail}</span>
            </div>
            <span className="shrink-0 text-xs tabular-nums text-muted-foreground">{timeAgo(e.at)}</span>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
