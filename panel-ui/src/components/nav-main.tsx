import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

export function NavMain({
  items,
  active,
  onSelect,
}: {
  items: {
    title: string
    url: string
    icon?: React.ReactNode
    badge?: string
  }[]
  active: string
  onSelect: (title: string) => void
}) {
  return (
    <SidebarGroup>
      <SidebarGroupContent className="flex flex-col gap-2">
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                tooltip={item.title}
                isActive={active === item.title}
                onClick={() => onSelect(item.title)}
              >
                {item.icon}
                <span>{item.title}</span>
                {item.badge && (
                  <span className="ml-auto inline-flex size-5 items-center justify-center rounded-md bg-primary/15 text-xs font-medium tabular-nums text-primary">
                    {item.badge}
                  </span>
                )}
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}
