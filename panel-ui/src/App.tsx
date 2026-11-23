import { lazy, Suspense, useCallback, useEffect, useState } from "react"
import { TooltipProvider } from "@/components/ui/tooltip"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { AppSidebar, type PageKey } from "@/components/app-sidebar"
import { SiteHeader } from "@/components/site-header"
import { AuthPage } from "@/pages/auth"
import { api, authState } from "@/lib/api"

const Overview = lazy(() => import("@/pages/overview").then((m) => ({ default: m.Overview })))
const Monitoring = lazy(() => import("@/pages/monitoring").then((m) => ({ default: m.Monitoring })))
const Security = lazy(() => import("@/pages/security").then((m) => ({ default: m.Security })))
const Sentinel = lazy(() => import("@/pages/sentinel").then((m) => ({ default: m.Sentinel })))
const Devices = lazy(() => import("@/pages/devices").then((m) => ({ default: m.Devices })))
const Clients = lazy(() => import("@/pages/clients").then((m) => ({ default: m.Clients })))
const Filtering = lazy(() => import("@/pages/filtering").then((m) => ({ default: m.Filtering })))
const SystemPage = lazy(() => import("@/pages/system").then((m) => ({ default: m.SystemPage })))

const subtitles: Record<PageKey, string> = {
  Overview: "Network operations at a glance",
  Monitoring: "Real-time performance, trends and alerting",
  Security: "Access control, threats and policy",
  Sentinel: "Identity anomalies, detection and deliberate recovery",
  Devices: "Infrastructure inventory and health",
  Clients: "Subscriber devices and service limits",
  Filtering: "Firewall rules and content policy",
  System: "Relay controls and configuration",
}

type AuthState = "checking" | "login" | "setup" | "authenticated"

export default function App() {
  const [auth, setAuth] = useState<AuthState>("checking")
  const [page, setPage] = useState<PageKey>(() => window.location.hash === "#sentinel" ? "Sentinel" : "Overview")
  const [pending, setPending] = useState(0)
  const [unacked, setUnacked] = useState(0)
  const [kill, setKill] = useState(false)

  const navigate = useCallback((next: PageKey) => {
    setPage(next)
    const url = new URL(window.location.href)
    url.hash = next === "Sentinel" ? "sentinel" : ""
    window.history.replaceState(null, "", url)
  }, [])

  useEffect(() => {
    const followSentinelLink = () => {
      if (window.location.hash === "#sentinel") setPage("Sentinel")
    }
    window.addEventListener("hashchange", followSentinelLink)
    return () => window.removeEventListener("hashchange", followSentinelLink)
  }, [])

  // Session gate: probe once on load, then poll only when authenticated.
  useEffect(() => {
    if (auth === "checking") {
      authState()
        .then(setAuth)
        .catch(() => setAuth("login"))
    }
  }, [auth])

  const load = useCallback(() => {
    api
      .stats()
      .then((s) => {
        setPending(s.pending)
        setKill(s.kill_switch)
      })
      .catch((err) => {
        if (String(err).includes("unauthorized")) setAuth("login")
      })
    api
      .alerts()
      .then((a) => setUnacked(a.unacked))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (auth !== "authenticated") return
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [auth, load])

  if (auth === "checking") return null

  if (auth === "login" || auth === "setup") {
    return (
      <AuthPage
        initialMode={auth}
        onDone={() => {
          setAuth("checking")
        }}
      />
    )
  }

  return (
    <TooltipProvider>
      <SidebarProvider>
        <AppSidebar
          page={page}
          pending={pending}
          unacked={unacked}
          onNavigate={navigate}
        />
        <SidebarInset>
          <SiteHeader
            title={page}
            subtitle={subtitles[page]}
            killSwitch={kill}
            pending={pending}
          />
          <main key={page} className="@container/main flex flex-1 flex-col gap-4 p-4 lg:p-6">
            <Suspense fallback={<p className="p-4 text-sm text-muted-foreground">Loading page…</p>}>
            {page === "Overview" && <Overview />}
            {page === "Monitoring" && <Monitoring />}
            {page === "Security" && <Security />}
            {page === "Sentinel" && <Sentinel />}
            {page === "Devices" && <Devices />}
            {page === "Clients" && <Clients />}
            {page === "Filtering" && <Filtering />}
            {page === "System" && <SystemPage />}
            </Suspense>
          </main>
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}
