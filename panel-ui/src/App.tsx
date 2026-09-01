import { useCallback, useEffect, useState } from "react"
import { TooltipProvider } from "@/components/ui/tooltip"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { AppSidebar, type PageKey } from "@/components/app-sidebar"
import { SiteHeader } from "@/components/site-header"
import { AuthPage } from "@/pages/auth"
import { Overview } from "@/pages/overview"
import { Monitoring } from "@/pages/monitoring"
import { Security } from "@/pages/security"
import { Devices } from "@/pages/devices"
import { Clients } from "@/pages/clients"
import { Filtering } from "@/pages/filtering"
import { SystemPage } from "@/pages/system"
import { api, authState } from "@/lib/api"

const subtitles: Record<PageKey, string> = {
  Overview: "Network operations at a glance",
  Monitoring: "Real-time performance, trends and alerting",
  Security: "Access control, threats and policy",
  Devices: "Infrastructure inventory and health",
  Clients: "Subscriber devices and service limits",
  Filtering: "Firewall rules and content policy",
  System: "Relay controls and configuration",
}

type AuthState = "checking" | "login" | "setup" | "authenticated"

export default function App() {
  const [auth, setAuth] = useState<AuthState>("checking")
  const [page, setPage] = useState<PageKey>("Overview")
  const [pending, setPending] = useState(0)
  const [unacked, setUnacked] = useState(0)
  const [kill, setKill] = useState(false)

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
          onNavigate={setPage}
        />
        <SidebarInset>
          <SiteHeader
            title={page}
            subtitle={subtitles[page]}
            killSwitch={kill}
            pending={pending}
          />
          <main key={page} className="@container/main flex flex-1 flex-col gap-4 p-4 lg:p-6">
            {page === "Overview" && <Overview />}
            {page === "Monitoring" && <Monitoring />}
            {page === "Security" && <Security />}
            {page === "Devices" && <Devices />}
            {page === "Clients" && <Clients />}
            {page === "Filtering" && <Filtering />}
            {page === "System" && <SystemPage />}
          </main>
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}
