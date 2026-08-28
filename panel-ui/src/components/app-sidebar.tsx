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
  GlobeIcon,
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
  {
    title: "Aborro.dev",
    url: "/",
    icon: <GlobeIcon />,
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
                <GlobeIcon className="size-5! text-primary" />
                <span className="text-base font-semibold">Aborro Network</span>
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
            email: "noc@aborro.dev",
            avatar: "",
          }}
        />
      </SidebarFooter>
    </Sidebar>
  )
}
