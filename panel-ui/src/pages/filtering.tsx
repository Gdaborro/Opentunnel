import { useCallback, useEffect, useState } from "react"
import { api, type BlockEntry, type Category } from "@/lib/api"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { PlusIcon, Trash2Icon, ShieldIcon, ListFilterIcon } from "lucide-react"

const categoryLabels: Record<string, string> = {
  social: "Social media",
  streaming: "Streaming & video",
  adult: "Adult content",
  ads: "Advertising & trackers",
  gambling: "Gambling",
}

export function Filtering() {
  const [entries, setEntries] = useState<BlockEntry[]>([])
  const [categories, setCategories] = useState<Category[]>([])
  const [domain, setDomain] = useState("")
  const [reason, setReason] = useState("")
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    api.blocklist().then(setEntries).catch(() => {})
    api.categories().then(setCategories).catch(() => {})
  }, [])
  useEffect(load, [load])

  const add = () => {
    const d = domain.trim().toLowerCase()
    if (!d) return
    setBusy(true)
    api
      .addBlock(d, reason.trim() || "manual block")
      .then(() => {
        setDomain("")
        setReason("")
        load()
      })
      .finally(() => setBusy(false))
  }

  const toggleCat = (c: Category, enabled: boolean) => {
    setCategories(categories.map((x) => (x.category === c.category ? { ...x, enabled } : x)))
    api.setCategory(c.category, enabled).then(load).catch(load)
  }

  return (
    <div className="grid gap-4 @xl/main:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldIcon className="size-4 text-primary" />
            Category Blocking
          </CardTitle>
          <CardDescription>
            Centrally deployed content policy — enforced at the relay for every
            subscriber device
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {categories.map((c) => (
            <div key={c.category} className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">
                  {categoryLabels[c.category] ?? c.category}
                </p>
                <p className="text-xs text-muted-foreground">
                  {c.domains} known domains, suffix-matched
                </p>
              </div>
              <Switch checked={c.enabled} onCheckedChange={(v) => toggleCat(c, v)} />
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ListFilterIcon className="size-4 text-primary" />
            Custom Blocklist (ACL)
          </CardTitle>
          <CardDescription>
            Extra domains blocked for all devices — subdomains included
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
            />
            <Input
              placeholder="reason (optional)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
            />
            <Button onClick={add} disabled={busy || !domain.trim()}>
              <PlusIcon /> Add
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {entries.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} className="py-6 text-center text-muted-foreground">
                    No custom blocks.
                  </TableCell>
                </TableRow>
              )}
              {entries.map((e) => (
                <TableRow key={e.domain}>
                  <TableCell className="font-mono text-sm">{e.domain}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{e.reason}</TableCell>
                  <TableCell>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => api.removeBlock(e.domain).then(load)}
                      title="Remove"
                    >
                      <Trash2Icon className="text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
