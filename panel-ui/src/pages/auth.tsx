import { useState } from "react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Toaster, toast } from "sonner"
import { LoaderIcon, ShieldCheckIcon } from "lucide-react"

type Mode = "login" | "setup"

async function api(path: string, body: unknown): Promise<boolean> {
  try {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body),
    })
    if (res.ok) return true
    if (res.status === 403 && path === "/admin/api/setup") {
      toast.error("Setup is already complete — sign in instead")
    } else if (res.status === 401 || res.status === 403) {
      toast.error("Invalid credentials")
    } else {
      toast.error((await res.text()) || "Request failed")
    }
    return false
  } catch {
    toast.error("Network error — is the server reachable?")
    return false
  }
}

export function AuthPage({
  initialMode,
  onDone,
}: {
  initialMode: Mode
  onDone: () => void
}) {
  const [mode, setMode] = useState<Mode>(initialMode)
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [confirm, setConfirm] = useState("")
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (busy) return
    if (mode === "setup" && password !== confirm) {
      toast.error("Passwords do not match")
      return
    }
    setBusy(true)
    const ok =
      mode === "login"
        ? await api("/admin/api/login", { username, password })
        : await api("/admin/api/setup", { username, password })
    setBusy(false)
    if (ok) onDone()
  }

  return (
    <div className="flex min-h-svh w-full items-center justify-center p-4">
      <Toaster position="top-center" richColors />
      <div className={cn("flex flex-col gap-6 w-full max-w-md")}>
        <Card className="overflow-hidden p-0">
          <CardContent className="grid p-0 md:grid-cols-2">
            <form className="p-6 md:p-8" onSubmit={submit}>
              <FieldGroup>
                <div className="flex flex-col items-center gap-2 text-center">
                  <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                    <ShieldCheckIcon className="size-5" />
                  </span>
                  <h1 className="text-xl font-bold">
                    {mode === "login" ? "Welcome back" : "Create admin"}
                  </h1>
                  <p className="text-balance text-muted-foreground">
                    {mode === "login"
                      ? "Sign in to the otu network panel"
                      : "One-time setup — this panel has no admin yet"}
                  </p>
                </div>
                <Field>
                  <FieldLabel htmlFor="username">Username</FieldLabel>
                  <Input
                    id="username"
                    autoComplete="username"
                    placeholder="admin"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="password">Password</FieldLabel>
                  <Input
                    id="password"
                    type="password"
                    autoComplete={
                      mode === "login" ? "current-password" : "new-password"
                    }
                    required
                    minLength={mode === "setup" ? 8 : undefined}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </Field>
                {mode === "setup" && (
                  <Field>
                    <FieldLabel htmlFor="confirm">Confirm password</FieldLabel>
                    <Input
                      id="confirm"
                      type="password"
                      autoComplete="new-password"
                      required
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                    />
                    <FieldDescription>
                      Minimum 8 characters. Only this login will work
                      afterwards — keep it safe.
                    </FieldDescription>
                  </Field>
                )}
                <Field>
                  <Button type="submit" disabled={busy}>
                    {busy && <LoaderIcon className="size-4 animate-spin" />}
                    {mode === "login" ? "Login" : "Create admin"}
                  </Button>
                </Field>
                {mode === "setup" && (
                  <FieldDescription className="text-center">
                    <a
                      href="#"
                      className="underline-offset-2 hover:underline"
                      onClick={(e) => {
                        e.preventDefault()
                        setMode("login")
                        setConfirm("")
                      }}
                    >
                      Already have an admin? Sign in
                    </a>
                  </FieldDescription>
                )}
              </FieldGroup>
            </form>
            {/* On-origin panel art: an external stock-photo CDN used to
                receive a request (admin IP + panel existence) on every
                login page view. A pure-CSS gradient makes the same
                visual shape with zero third-party traffic. */}
            <div className="relative hidden bg-muted md:block">
              <div
                aria-hidden="true"
                className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,oklch(0.35_0.12_260)_0%,oklch(0.16_0.03_260)_55%,oklch(0.12_0.02_260)_100%)] dark:brightness-[0.7]"
              />
              <div
                aria-hidden="true"
                className="absolute inset-0 opacity-30 bg-[repeating-linear-gradient(115deg,transparent_0px,transparent_54px,oklch(0.9_0_0/0.05)_54px,oklch(0.9_0_0/0.05)_55px)]"
              />
            </div>
          </CardContent>
        </Card>
        <FieldDescription className="px-6 text-center">
          otu network operations — authorized personnel only.
        </FieldDescription>
      </div>
    </div>
  )
}
