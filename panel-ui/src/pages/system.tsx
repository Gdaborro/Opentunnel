import { useCallback, useEffect, useState } from "react"
import { api } from "@/lib/api"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Separator } from "@/components/ui/separator"
import { Power, Eye, ShieldAlert } from "lucide-react"

export function SystemPage() {
  const [kill, setKill] = useState(false)
  const [visits, setVisits] = useState<{ domain: string; hits: number; last: string }[]>([])
  const [loaded, setLoaded] = useState(false)

  const load = useCallback(() => {
    api.settings().then((s) => { setKill(s.kill_switch); setLoaded(true) }).catch(() => {})
    api.visits().then(setVisits).catch(() => {})
  }, [])
  useEffect(load, [load])

  const toggleKill = (on: boolean) => {
    setKill(on)
    api.setKillSwitch(on).catch(() => setKill(!on))
  }

  return (
    <div className="space-y-4">
      <Card className="fade-up border-red-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Power className="h-4 w-4 text-red-400" /> Global kill switch
          </CardTitle>
          <CardDescription>
            Suspends all tunnel traffic instantly — new connections are refused and existing streams are blocked.
            Devices stay registered and approved; flip it off to resume.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldAlert className={kill ? "h-8 w-8 text-red-400" : "h-8 w-8 text-muted-foreground"} />
            <p className={kill ? "font-medium text-red-300" : "font-medium text-muted-foreground"}>
              {kill ? "SUSPENDED — all traffic blocked" : "Traffic flowing normally"}
            </p>
          </div>
          {loaded && <Switch checked={kill} onCheckedChange={toggleKill} />}
        </CardContent>
      </Card>

      <Card className="fade-up">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Eye className="h-4 w-4 text-emerald-400" /> Top visited domains
          </CardTitle>
          <CardDescription>Aggregated across devices — domain only, no URLs.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead className="text-right">Hits</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visits.length === 0 && (
                <TableRow>
                  <TableCell colSpan={2} className="py-6 text-center text-muted-foreground">
                    No visits recorded yet.
                  </TableCell>
                </TableRow>
              )}
              {visits.slice(0, 25).map((v) => (
                <TableRow key={v.domain}>
                  <TableCell className="font-mono text-sm">{v.domain}</TableCell>
                  <TableCell className="text-right tabular-nums">{v.hits.toLocaleString()}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Separator className="my-4" />
          <p className="text-xs text-muted-foreground">
            Enforcement is server-side: schedules, quotas, category blocks and the kill switch apply at the relay, so
            clients cannot bypass them locally.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
