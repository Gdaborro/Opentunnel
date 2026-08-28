import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Globe } from "lucide-react"

const flags: Record<string, string> = {
  Australia: "🇦🇺", "United States": "🇺🇸", "United Kingdom": "🇬🇧",
  Germany: "🇩🇪", France: "🇫🇷", Japan: "🇯🇵", Singapore: "🇸🇬",
  Netherlands: "🇳🇱", Canada: "🇨🇦", "New Zealand": "🇳🇿", India: "🇮🇳",
  Brazil: "🇧🇷", China: "🇨🇳", Russia: "🇷🇺", Spain: "🇪🇸", Italy: "🇮🇹",
}

export function CountryCard({ countries }: { countries: Record<string, number> }) {
  const entries = Object.entries(countries).sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...entries.map(([, n]) => n))
  return (
    <Card className="fade-up h-full">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Globe className="h-4 w-4 text-emerald-400" /> Sessions by country
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {entries.length === 0 && (
          <p className="text-sm text-muted-foreground">No GeoIP data yet — connects once devices report in.</p>
        )}
        {entries.map(([name, n]) => (
          <div key={name} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <span>
                {flags[name] ?? "🌐"} {name}
              </span>
              <span className="tabular-nums text-muted-foreground">
                {n} device{n === 1 ? "" : "s"}
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full bg-emerald-500/70 transition-all duration-700"
                style={{ width: `${(n / max) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
