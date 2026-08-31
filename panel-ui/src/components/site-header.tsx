import { useEffect, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { OctagonXIcon, ClockIcon } from "lucide-react"

export function SiteHeader({
  title,
  subtitle,
  killSwitch,
  pending,
}: {
  title: string
  subtitle?: string
  killSwitch: boolean
  pending: number
}) {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  return (
    <header className="sticky top-0 z-30 flex h-(--header-height) shrink-0 items-center gap-2 border-b border-border/60 bg-background/70 backdrop-blur-xl transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)">
      <div className="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator
          orientation="vertical"
          className="mx-2 data-[orientation=vertical]:h-4"
        />
        <div className="flex items-baseline gap-2.5">
          <h1 className="gradient-text text-base font-semibold tracking-tight">
            {title}
          </h1>
          {subtitle && (
            <span className="hidden text-sm text-muted-foreground md:inline">
              {subtitle}
            </span>
          )}
        </div>
        <div className="ml-auto flex items-center gap-2.5">
          {killSwitch && (
            <Badge variant="destructive" className="gap-1">
              <OctagonXIcon className="size-3" />
              Kill switch engaged
            </Badge>
          )}
          {!killSwitch && pending > 0 && (
            <Badge variant="secondary" className="gap-1">
              <ClockIcon className="size-3" />
              {pending} awaiting approval
            </Badge>
          )}
          {!killSwitch && pending === 0 && (
            <Badge
              variant="outline"
              className="hidden gap-1.5 border-primary/25 bg-primary/5 sm:inline-flex"
            >
              <span className="glow-dot size-1.5 rounded-full bg-primary" />
              All systems nominal
            </Badge>
          )}
          <span className="hidden text-xs font-medium tabular-nums text-muted-foreground lg:inline">
            {now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
          </span>
        </div>
      </div>
    </header>
  )
}
