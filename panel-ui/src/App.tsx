import { useEffect, useState } from "react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Overview } from "@/pages/overview"
import { Clients } from "@/pages/clients"
import { Filtering } from "@/pages/filtering"
import { SystemPage } from "@/pages/system"
import { api } from "@/lib/api"
import { Network, LogOut } from "lucide-react"

export default function App() {
  const [pending, setPending] = useState(0)
  const [kill, setKill] = useState(false)
  useEffect(() => {
    const load = () =>
      api
        .stats()
        .then((s) => {
          setPending(s.pending)
          setKill(s.kill_switch)
        })
        .catch(() => {})
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-40 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <Network className="h-5 w-5 text-emerald-400" />
            <span className="font-semibold tracking-tight">Network Control</span>
            {kill && <Badge variant="destructive">kill switch on</Badge>}
            {!kill && pending > 0 && (
              <Badge variant="warning">
                {pending} pending
              </Badge>
            )}
          </div>
          <a
            href="/admin/logout"
            className="flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            <LogOut className="h-4 w-4" /> Sign out
          </a>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        <Tabs defaultValue="overview">
          <TabsList className="mb-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="clients">
              Clients{pending > 0 ? ` (${pending})` : ""}
            </TabsTrigger>
            <TabsTrigger value="filtering">Filtering</TabsTrigger>
            <TabsTrigger value="system">System</TabsTrigger>
          </TabsList>
          <TabsContent value="overview">
            <Overview />
          </TabsContent>
          <TabsContent value="clients">
            <Clients />
          </TabsContent>
          <TabsContent value="filtering">
            <Filtering />
          </TabsContent>
          <TabsContent value="system">
            <SystemPage />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  )
}
