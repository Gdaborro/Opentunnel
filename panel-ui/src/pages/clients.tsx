import { useCallback, useEffect, useState } from "react"
import { api, type Peer, type PeerLimits } from "@/lib/api"
import { Card, CardContent } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { formatBytes, timeAgo } from "@/lib/utils"
import { Check, Footprints, Gauge, Ban, Trash2, RotateCcw, Timer } from "lucide-react"

const statusVariant: Record<string, "success" | "warning" | "destructive" | "secondary"> = {
  approved: "success",
  pending: "warning",
  banned: "destructive",
  kicked: "warning",
  expired: "secondary",
}

export function Clients() {
  const [peers, setPeers] = useState<Peer[]>([])
  const [limitsPeer, setLimitsPeer] = useState<Peer | null>(null)
  const [limits, setLimits] = useState<PeerLimits>({ schedule: "", max_bps: 0, quota_bytes: 0 })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  const load = useCallback(() => {
    api.peers().then(setPeers).catch(() => {})
  }, [])
  useEffect(() => {
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [load])

  const act = (token: string, action: string, body?: unknown) => {
    setBusy(true)
    api
      .peerAction(token, action, body)
      .then(load)
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(false))
  }

  const openLimits = (p: Peer) => {
    setLimitsPeer(p)
    setError("")
    api
      .peerLimits(p.token)
      .then(setLimits)
      .catch(() => setLimits({ schedule: "", max_bps: 0, quota_bytes: 0 }))
  }

  const saveLimits = () => {
    if (!limitsPeer) return
    setBusy(true)
    api
      .setPeerLimits(limitsPeer.token, limits)
      .then(() => {
        setLimitsPeer(null)
        load()
      })
      .catch((e) => setError(String(e)))
      .finally(() => setBusy(false))
  }

  return (
    <Card className="fade-up">
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">Device</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Location</TableHead>
              <TableHead>Usage</TableHead>
              <TableHead>Seen</TableHead>
              <TableHead className="text-right pr-4">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {peers.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                  No devices registered yet.
                </TableCell>
              </TableRow>
            )}
            {peers.map((p) => (
              <TableRow key={p.token}>
                <TableCell className="pl-4">
                  <div className="font-medium">{p.device_name || "unknown device"}</div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {p.token.slice(0, 8)}…{p.last_ip ? ` · ${p.last_ip}` : ""}
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant={statusVariant[p.status] ?? "secondary"} className="capitalize">
                    {p.status}
                  </Badge>
                  {p.status === "kicked" && p.kick_reason && (
                    <div className="mt-1 max-w-40 truncate text-xs text-muted-foreground" title={p.kick_reason}>
                      {p.kick_reason}
                    </div>
                  )}
                  {p.status === "banned" && p.ban_reason && (
                    <div className="mt-1 max-w-40 truncate text-xs text-muted-foreground" title={p.ban_reason}>
                      {p.ban_reason}
                    </div>
                  )}
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">{p.country || "—"}</TableCell>
                <TableCell className="tabular-nums text-sm">
                  ↑ {formatBytes(p.bytes_up)}
                  <br />↓ {formatBytes(p.bytes_down)}
                </TableCell>
                <TableCell className="tabular-nums text-sm text-muted-foreground">{timeAgo(p.last_seen)}</TableCell>
                <TableCell className="pr-4">
                  <div className="flex items-center justify-end gap-1">
                    {p.status === "pending" && (
                      <Button size="icon" variant="ghost" title="Approve" disabled={busy} onClick={() => act(p.token, "approve")}>
                        <Check className="text-emerald-400" />
                      </Button>
                    )}
                    <Button size="icon" variant="ghost" title="Schedule & caps" onClick={() => openLimits(p)}>
                      <Gauge />
                    </Button>
                    {p.status !== "kicked" && p.status !== "banned" && (
                      <Button
                        size="icon"
                        variant="ghost"
                        title="Kick (10 min grace)"
                        disabled={busy}
                        onClick={() => act(p.token, "kick", { reason: "manual kick by admin" })}
                      >
                        <Footprints />
                      </Button>
                    )}
                    {p.status !== "banned" ? (
                      <Button
                        size="icon"
                        variant="ghost"
                        title="Ban device (fingerprint + key)"
                        disabled={busy}
                        onClick={() => act(p.token, "ban", { reason: "banned by admin", duration: "permanent" })}
                      >
                        <Ban className="text-red-400" />
                      </Button>
                    ) : (
                      <Button size="icon" variant="ghost" title="Unban" disabled={busy} onClick={() => act(p.token, "unban")}>
                        <RotateCcw className="text-emerald-400" />
                      </Button>
                    )}
                    <Button
                      size="icon"
                      variant="ghost"
                      title="Delete device"
                      disabled={busy}
                      onClick={() => {
                        if (confirm(`Delete ${p.device_name || p.token.slice(0, 8)}?`)) act(p.token, "delete")
                      }}
                    >
                      <Trash2 className="text-red-400" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>

      <Dialog open={!!limitsPeer} onOpenChange={(o) => !o && setLimitsPeer(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Timer className="h-4 w-4 text-emerald-400" />
              {limitsPeer?.device_name || limitsPeer?.token.slice(0, 8)} — access controls
            </DialogTitle>
            <DialogDescription>Schedule, bandwidth cap and data quota for this device.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="sched">Access schedule</Label>
              <Input
                id="sched"
                placeholder="e.g. Mon-Fri 0800-1800 (empty = always)"
                value={limits.schedule}
                onChange={(e) => setLimits({ ...limits, schedule: e.target.value })}
              />
              <p className="text-xs text-muted-foreground">
                Formats: “0800-1800”, “0800-1200,1300-1800”, “Mon-Fri 0800-1800”, “Sat,Sun 1000-1600”. Server local time.
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="bps">Bandwidth cap (KB/s, 0 = unlimited)</Label>
                <Input
                  id="bps"
                  type="number"
                  min={0}
                  value={limits.max_bps ? Math.round(limits.max_bps / 1024) : 0}
                  onChange={(e) => setLimits({ ...limits, max_bps: Math.max(0, Number(e.target.value)) * 1024 })}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="quota">Data quota (MB, 0 = unlimited)</Label>
                <Input
                  id="quota"
                  type="number"
                  min={0}
                  value={limits.quota_bytes ? Math.round(limits.quota_bytes / (1024 * 1024)) : 0}
                  onChange={(e) =>
                    setLimits({ ...limits, quota_bytes: Math.max(0, Number(e.target.value)) * 1024 * 1024 })
                  }
                />
              </div>
            </div>
            {error && <p className="text-sm text-red-400">{error}</p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setLimitsPeer(null)}>
              Cancel
            </Button>
            <Button onClick={saveLimits} disabled={busy}>
              Save controls
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  )
}
