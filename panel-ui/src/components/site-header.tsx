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
  return (
    <header className="flex h-(--header-height) shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)">
      <div className="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator
          orientation="vertical"
          className="mx-2 data-[orientation=vertical]:h-4"
        />
        <div className="flex items-baseline gap-2">
          <h1 className="text-base font-medium">{title}</h1>
          {subtitle && (
            <span className="hidden text-sm text-muted-foreground sm:inline">
              {subtitle}
            </span>
          )}
        </div>
        <div className="ml-auto flex items-center gap-2">
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
        </div>
      </div>
    </header>
  )
}
