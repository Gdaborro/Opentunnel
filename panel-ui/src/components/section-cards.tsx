"use client"

import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { TrendingUpIcon, AlertTriangleIcon, ArrowUpIcon, ArrowDownIcon } from "lucide-react"
import { formatBytes } from "@/lib/format"

export function SectionCards({
  online,
  total,
  bytesUp,
  bytesDown,
  unacked,
  uptimeLabel,
  version,
}: {
  online: number
  total: number
  bytesUp: number
  bytesDown: number
  unacked: number
  uptimeLabel: string
  version: string
}) {
  return (
    <div className="grid grid-cols-1 gap-4 *:data-[slot=card]:bg-gradient-to-t *:data-[slot=card]:from-primary/5 *:data-[slot=card]:to-card *:data-[slot=card]:shadow-xs @xl/main:grid-cols-2 @5xl/main:grid-cols-4 dark:*:data-[slot=card]:bg-card">
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Devices Online</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {online}
            <span className="text-lg text-muted-foreground"> / {total}</span>
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <TrendingUpIcon />
              live
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            Approved subscribers on the network
          </div>
          <div className="text-muted-foreground">Updated every 5 seconds</div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Total Traffic</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {formatBytes(bytesUp + bytesDown)}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <TrendingUpIcon />
              all time
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            <span className="flex items-center gap-1">
              <ArrowUpIcon className="size-3.5" /> {formatBytes(bytesUp)}
            </span>
            <span className="flex items-center gap-1">
              <ArrowDownIcon className="size-3.5" /> {formatBytes(bytesDown)}
            </span>
          </div>
          <div className="text-muted-foreground">Relayed up / down</div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Unacked Alerts</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {unacked}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              {unacked > 0 ? <AlertTriangleIcon /> : <TrendingUpIcon />}
              {unacked > 0 ? "attention" : "clear"}
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            {unacked > 0
              ? "Security & fault alerts need review"
              : "No alerts awaiting acknowledgement"}
          </div>
          <div className="text-muted-foreground">See Monitoring alerts</div>
        </CardFooter>
      </Card>
      <Card className="@container/card">
        <CardHeader>
          <CardDescription>Relay Uptime</CardDescription>
          <CardTitle className="text-2xl font-semibold tabular-nums @[250px]/card:text-3xl">
            {uptimeLabel}
          </CardTitle>
          <CardAction>
            <Badge variant="outline">
              <TrendingUpIcon />
              {version}
            </Badge>
          </CardAction>
        </CardHeader>
        <CardFooter className="flex-col items-start gap-1.5 text-sm">
          <div className="line-clamp-1 flex gap-2 font-medium">
            Core relay process continuous run
          </div>
          <div className="text-muted-foreground">Core relay</div>
        </CardFooter>
      </Card>
    </div>
  )
}
