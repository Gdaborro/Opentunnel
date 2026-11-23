import { useEffect, useState, type FormEvent } from "react"
import { api, type HardeningStatus, type PrivacyPolicy } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

export function HardeningControls() {
  const [policy, setPolicy] = useState<PrivacyPolicy | null>(null)
  const [status, setStatus] = useState<HardeningStatus | null>(null)
  const [purge, setPurge] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")

  useEffect(() => {
    let active = true
    Promise.all([api.privacy(), api.hardeningStatus()])
      .then(([privacy, hardening]) => {
        if (active) { setPolicy(privacy); setStatus(hardening) }
      })
      .catch(() => { if (active) setMessage("Privacy and hardening status unavailable. No policy was changed.") })
    return () => { active = false }
  }, [])

  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (!policy || busy) return
    if (purge && !window.confirm("Delete telemetry older than the selected retention limits? Device identities, bans, approvals, filtering and quota accounting will remain.")) return
    const requested = policy
    setBusy(true)
    setMessage("")
    try {
      await api.setPrivacy(policy, purge)
      const [verified, hardening] = await Promise.all([api.privacy(), api.hardeningStatus()])
      if (verified.mode !== requested.mode || verified.visit_retention_days !== requested.visit_retention_days || verified.health_retention_days !== requested.health_retention_days || verified.peer_ip_retention_days !== requested.peer_ip_retention_days) throw new Error("concurrent privacy change")
      setPolicy(verified)
      setStatus(hardening)
      setPurge(false)
      setMessage("Saved and verified. Approval, bans, filtering and accounting remain enforced.")
    } catch {
      setPolicy(null)
      setMessage("Save or read-back failed. Policy state is not confirmed; refresh before retrying.")
    } finally {
      setBusy(false)
    }
  }

  const retention = (key: keyof Omit<PrivacyPolicy, "mode">, value: string) => {
    if (policy) setPolicy({ ...policy, [key]: Number(value) })
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Privacy and retention</CardTitle>
          <CardDescription>
            Existing fleet monitoring is preserved unless you explicitly change it. Minimal mode stops new domain visits,
            IP history and hardware posture storage. Operator approval, bans, abuse protection and aggregate accounting remain.
            Relay operators can still observe traffic; this is not anonymity or a no-logs certification.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={save} className="space-y-4">
            <div className="flex flex-col gap-1.5 text-sm">
              <label className="font-medium" htmlFor="telemetry-mode">Telemetry storage</label>
              <select id="telemetry-mode" className="rounded-md border bg-background p-2" value={policy?.mode ?? "preserve"}
                disabled={!policy || busy} onChange={(event) => policy && setPolicy({ ...policy, mode: event.target.value as PrivacyPolicy["mode"] })}>
                <option value="preserve">Preserve fleet monitoring (default)</option>
                <option value="minimal">Minimal (explicit opt-in)</option>
              </select>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              {([
                ["visit_retention_days", "Visit retention days", 0, 90],
                ["health_retention_days", "Health retention days", 0, 90],
                ["peer_ip_retention_days", "IP history retention days", 1, 30],
              ] as const).map(([key, label, min, max]) => (
                <div className="flex flex-col gap-1.5 text-sm" key={key}>
                  <label className="font-medium" htmlFor={`privacy-${key}`}>{label}</label>
                  <input id={`privacy-${key}`} type="number" min={min} max={max} step={1} required
                    className="rounded-md border bg-background p-2" disabled={!policy || busy}
                    aria-describedby={`privacy-${key}-hint`}
                    value={policy?.[key] ?? min} onChange={(event) => retention(key, event.target.value)} />
                  <span id={`privacy-${key}-hint`} className="text-xs text-muted-foreground">{min === 0 ? "0 preserves existing age-based retention behavior" : "1–30 days; not an identity-ban expiry"}</span>
                </div>
              ))}
            </div>
            <label className="flex items-start gap-2 text-sm" htmlFor="privacy-apply-now">
              <input id="privacy-apply-now" type="checkbox" checked={purge} disabled={!policy || busy} onChange={(event) => setPurge(event.target.checked)} />
              <span>Apply these age limits to existing telemetry now (confirmation required). Changing telemetry mode alone does not erase existing records.</span>
            </label>
            <Button type="submit" disabled={!policy || busy}>{busy ? "Saving and verifying…" : "Save explicit privacy policy"}</Button>
          </form>
          <p role="status" aria-live="polite" className="mt-3 text-sm">{message}</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Authentication and authority diagnostics</CardTitle>
          <CardDescription>Current local/runtime evidence, not stable-release certification. Old or missing node heartbeats are shown as unavailable.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>{status ? `${status.channel_verified_current_identities} of ${status.device_count} identities verified with connection-bound authentication in their current generation.` : "Authentication status unavailable."}</p>
          {status?.relay_nodes.map((node) => (
            <div key={node.node} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3">
              <span className="font-medium">{node.node}</span>
              <Badge variant={node.online ? "secondary" : "outline"}>{node.online ? "Recent authenticated heartbeat" : "Stale / offline"}</Badge>
              <span>{node.online ? `${node.snapshot.version} · ${node.snapshot.active_sessions} active sessions` : `Last heartbeat ${node.age_seconds}s ago`}</span>
            </div>
          ))}
          {status && status.relay_nodes.length === 0 && <p className="text-muted-foreground">No central-authority node heartbeats recorded. Local single-host relay status appears below.</p>}
          {status && <p>Managed SSH desired: {status.managed_ssh_desired}; revoked ownership retained: {status.managed_ssh_revoked}. {status.ssh_apply_status}</p>}
          <p className="text-xs text-muted-foreground">The client protects configured HTTP/SOCKS applications, not system-wide VPN routing. Direct bypass hosts, applications ignoring proxies and system-wide DNS/IPv6/UDP routing remain outside scope. Use the client’s standalone <code>--status</code> for a private credential-free summary.</p>
        </CardContent>
      </Card>
    </>
  )
}
