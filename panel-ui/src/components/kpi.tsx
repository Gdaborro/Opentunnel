import { useEffect, useRef, useState } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"

function useCountUp(target: number, duration = 800) {
  const [value, setValue] = useState(0)
  const fromRef = useRef(0)
  useEffect(() => {
    const from = fromRef.current
    const start = performance.now()
    let raf = 0
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      setValue(Math.round(from + (target - from) * eased))
      if (t < 1) raf = requestAnimationFrame(tick)
      else fromRef.current = target
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])
  return value
}

export function KpiCard({
  title,
  value,
  suffix,
  hint,
  icon,
  accent,
  format,
}: {
  title: string
  value: number
  suffix?: string
  hint?: string
  icon?: React.ReactNode
  accent?: string
  format?: (n: number) => string
}) {
  const animated = useCountUp(value)
  const display = format ? format(animated) : animated.toLocaleString()
  return (
    <Card className="fade-up">
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">{title}</p>
          {icon && <div className={cn("text-muted-foreground", accent)}>{icon}</div>}
        </div>
        <p className={cn("mt-2 text-3xl font-semibold tracking-tight tabular-nums", accent)}>
          {display}
          {suffix && <span className="ml-1 text-base font-normal text-muted-foreground">{suffix}</span>}
        </p>
        {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
      </CardContent>
    </Card>
  )
}
