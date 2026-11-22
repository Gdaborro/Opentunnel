import { useCallback, useEffect, useRef, useState } from "react"
import { BellRingIcon, FingerprintIcon, ShieldAlertIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { api, type SentinelMode, type SentinelSnapshot } from "@/lib/api"
import { timeAgo } from "@/lib/format"

const modes: { id: SentinelMode; label: string; detail: string }[] = [
  { id: "off", label: "Off", detail: "No Sentinel findings" },
  { id: "alert", label: "Alert only", detail: "Findings without automated flood response" },
  { id: "respond", label: "Alert + auto-respond", detail: "Ordinary auth-failure floods may ban a source IP" },
]

export function Sentinel() {
  const [snapshot, setSnapshot] = useState<SentinelSnapshot | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [readFailed, setReadFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const busyRef = useRef(false)

  const load = useCallback(async () => {
    if (busyRef.current) return
    try {
      const next = await api.sentinel()
      setSnapshot(next)
      setReadFailed(false)
    } catch {
      setReadFailed(true)
    } finally {
      setLoaded(true)
    }
  }, [])

  useEffect(() => {
    void load()
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [load])

  const changeMode = async (mode: SentinelMode) => {
    if (busyRef.current || !loaded || readFailed) return
    if (mode === "respond" && !window.confirm("Allow ordinary authentication-failure floods to ban a source IP? Identity-spoof findings remain alert-only and never authorize an automatic identity reset, rekey, or ban.")) return
    busyRef.current = true
    setBusy(true)
    setMessage("")
    try {
      await api.setSentinelMode(mode)
      const verified = await api.sentinel()
      if (verified.mode !== mode) throw new Error("concurrent Sentinel policy change")
      setSnapshot(verified)
      setReadFailed(false)
      setMessage("Sentinel policy committed and read back. Identity-spoof findings remain review-only.")
    } catch {
      setMessage("Mode change or read-back failed. Policy is unconfirmed; refresh before retrying.")
    } finally {
      busyRef.current = false
      setBusy(false)
      await load()
    }
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" disabled={busy} onClick={() => { void load() }}>Refresh Sentinel</Button>
        <p role="status" aria-live="polite" className="text-sm">{message}</p>
        {!loaded && <p role="status" className="text-sm">Reading Sentinel status…</p>}
        {readFailed && <p role="alert" className="text-sm text-destructive">Sentinel data is unavailable. Previously shown findings may be stale; this is not an all-clear.</p>}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldAlertIcon className="size-4 text-primary" />
            Detection policy
          </CardTitle>
          <CardDescription>
            Identity anomalies are review-only: no automatic identity reset, rekey, device ban, or HWID-based restoration.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-2">
            {modes.map((item) => (
              <Button
                key={item.id}
                size="sm"
                variant={snapshot?.mode === item.id ? "default" : "outline"}
                disabled={busy || !loaded || readFailed}
                title={item.detail}
                onClick={() => { void changeMode(item.id) }}
              >
                {item.label}
              </Button>
            ))}
          </div>
          <div className="rounded-lg border border-border/60 bg-muted/30 p-3 text-sm">
            <span className="font-medium">Current mode: </span>
            <span>{snapshot?.mode ?? "unavailable"}</span>
            <p className="mt-1 text-muted-foreground">
              {modes.find((item) => item.id === snapshot?.mode)?.detail ?? "Read the authoritative policy before changing it."}
            </p>
          </div>
          <div className="flex items-start gap-2 text-sm text-muted-foreground">
            <FingerprintIcon className="mt-0.5 size-4 shrink-0 text-primary" />
            <p>Fingerprints, hostnames and hardware-derived signals are risk evidence, not hardware attestation. Preserve the last-known-good cryptographic identity and review replacements out of band.</p>
          </div>
          <div>
            <a className="text-sm text-primary underline underline-offset-4" href="/admin/ssh-keys">Review device keys and deliberate recovery</a>
            <p className="mt-1 text-xs text-muted-foreground">Administrator rekey preserves the token and accounting, requires the expected current public key and out-of-band confirmation, and returns the replacement to pending for separate approval.</p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <BellRingIcon className="size-4 text-primary" />
            Recent findings
          </CardTitle>
          <CardDescription>
            {loaded && !readFailed ? `${snapshot?.alerts_24h ?? 0} Sentinel/security findings in the last 24 hours` : "Authoritative finding count unavailable"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loaded && !readFailed && snapshot?.recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">No findings recorded. Detection state is not a guarantee that no spoofing occurred.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Observed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshot?.recent.map((finding, index) => (
                  <TableRow key={`${finding.at}-${index}`}>
                    <TableCell>
                      <Badge variant="outline" className={finding.severity === "critical" ? "text-destructive" : finding.severity === "warning" ? "text-amber-500" : "text-muted-foreground"}>
                        {finding.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[42rem] whitespace-normal">{finding.message}</TableCell>
                    <TableCell className="whitespace-nowrap text-sm text-muted-foreground">{timeAgo(finding.at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  )
}
