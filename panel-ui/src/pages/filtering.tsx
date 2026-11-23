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
  const [categoryError, setCategoryError] = useState("")
  const [blockError, setBlockError] = useState("")
  const [categoriesReady, setCategoriesReady] = useState(false)
  const [blocksReady, setBlocksReady] = useState(false)

  const loadCategories = useCallback(async () => {
    try {
      const values = await api.categories()
      setCategories(values)
      setCategoriesReady(true)
      setCategoryError("")
      return values
    } catch (error) {
      setCategoriesReady(false)
      setCategoryError("Filtering categories unavailable. Previously shown choices may be stale; no policy was changed by this read.")
      throw error
    }
  }, [])
  const loadBlocks = useCallback(async () => {
    try {
      const values = await api.blocklist()
      setEntries(values)
      setBlocksReady(true)
      setBlockError("")
    } catch (error) {
      setBlocksReady(false)
      setBlockError("Blocklist unavailable. Previously shown entries may be stale; no empty policy was substituted.")
      throw error
    }
  }, [])
  const load = useCallback(() => Promise.allSettled([loadBlocks(), loadCategories()]), [loadBlocks, loadCategories])
  useEffect(() => { void load() }, [load])

  const add = async () => {
    const d = domain.trim().toLowerCase()
    if (!d || busy || !blocksReady) return
    setBusy(true)
    try {
      await api.addBlock(d, reason.trim() || "manual block")
      await loadBlocks()
      setDomain("")
      setReason("")
    } catch {
      setBlocksReady(false)
      setBlockError("Blocklist update or read-back failed. Policy state is unconfirmed; refresh before retrying.")
    } finally { setBusy(false) }
  }

  const toggleCat = async (c: Category, enabled: boolean) => {
    if (busy || !categoriesReady) return
    setBusy(true)
    try {
      await api.setCategory(c.category, enabled)
      const verified = await loadCategories()
      if (verified.find((item) => item.category === c.category)?.enabled !== enabled) throw new Error("concurrent policy change")
    } catch {
      setCategoriesReady(false)
      setCategoryError("Category update or read-back failed. Policy state is unconfirmed; refresh before retrying.")
    } finally { setBusy(false) }
  }

  const remove = async (domain: string) => {
    if (busy || !blocksReady) return
    setBusy(true)
    try {
      await api.removeBlock(domain)
      await loadBlocks()
    } catch {
      setBlocksReady(false)
      setBlockError("Block removal or read-back failed. Policy state is unconfirmed; refresh before retrying.")
    } finally { setBusy(false) }
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
          {categoryError && <p role="alert" className="text-sm text-destructive">{categoryError}</p>}
          {!categoriesReady && !categoryError && <p role="status" className="text-sm">Reading filtering categories…</p>}
          <Button variant="outline" disabled={busy} onClick={() => { void load() }}>Refresh filtering policy</Button>
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
              <Switch aria-label={`Block ${categoryLabels[c.category] ?? c.category}`} checked={c.enabled} disabled={busy || !categoriesReady} onCheckedChange={(v) => { void toggleCat(c, v) }} />
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
          {blockError && <p role="alert" className="text-sm text-destructive">{blockError}</p>}
          <div className="flex gap-2">
            <Input
              placeholder="example.com"
              aria-label="Domain to block"
              disabled={busy || !blocksReady}
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
            />
            <Input
              placeholder="reason (optional)"
              aria-label="Block reason"
              disabled={busy || !blocksReady}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
            />
            <Button onClick={() => { void add() }} disabled={busy || !blocksReady || !domain.trim()}>
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
              {entries.length === 0 && blocksReady && (
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
                      disabled={busy || !blocksReady}
                      onClick={() => { void remove(e.domain) }}
                      aria-label={`Remove block for ${e.domain}`}
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
