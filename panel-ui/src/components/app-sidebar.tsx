import * as React from "react"

import { NavMain } from "@/components/nav-main"
import { NavSecondary } from "@/components/nav-secondary"
import { NavUser } from "@/components/nav-user"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import {
  LayoutDashboardIcon,
  ActivityIcon,
  ShieldIcon,
  ServerIcon,
  UsersIcon,
  FilterIcon,
  Settings2Icon,
  FileTextIcon,
  SparklesIcon,
} from "lucide-react"

export type PageKey =
  | "Overview"
  | "Monitoring"
  | "Security"
  | "Devices"
  | "Clients"
  | "Filtering"
  | "System"

const navMain: { title: PageKey; url: string; icon: React.ReactNode }[] = [
  { title: "Overview", url: "#", icon: <LayoutDashboardIcon /> },
  { title: "Monitoring", url: "#", icon: <ActivityIcon /> },
  { title: "Security", url: "#", icon: <ShieldIcon /> },
  { title: "Devices", url: "#", icon: <ServerIcon /> },
  { title: "Clients", url: "#", icon: <UsersIcon /> },
  { title: "Filtering", url: "#", icon: <FilterIcon /> },
  { title: "System", url: "#", icon: <Settings2Icon /> },
]

const navSecondary = [
  {
    title: "Service Status",
    url: "/status",
    icon: <FileTextIcon />,
  },
]

export function AppSidebar({
  page,
  pending,
  unacked,
  onNavigate,
  ...props
}: {
  page: PageKey
  pending: number
  unacked: number
  onNavigate: (page: PageKey) => void
} & Omit<React.ComponentProps<typeof Sidebar>, "onSelect">) {
  const items = navMain.map((item) => ({
    ...item,
    badge:
      item.title === "Clients" && pending > 0
        ? String(pending)
        : item.title === "Security" && unacked > 0
          ? String(unacked)
          : undefined,
  }))

  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              asChild
              className="data-[slot=sidebar-menu-button]:p-1.5!"
            >
              <a href="#">
                <span className="relative flex size-8 items-center justify-center rounded-xl bg-gradient-to-br from-chart-5 via-primary to-chart-2 shadow-lg shadow-primary/25">
                  <SparklesIcon className="!size-4 text-primary-foreground" />
                </span>
                <span className="text-base font-bold tracking-tight">
                  otu
                  <span className="ml-1.5 align-middle text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
                    network
                  </span>
                </span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={items} active={page} onSelect={(t) => onNavigate(t as PageKey)} />
        <NavSecondary items={navSecondary} className="mt-auto" />
      </SidebarContent>
      <SidebarFooter>
        <NavUser
          user={{
            name: "Network Operator",
            email: "otu admin",
            avatar: "",
          }}
        />
      </SidebarFooter>
    </Sidebar>
  )
}
