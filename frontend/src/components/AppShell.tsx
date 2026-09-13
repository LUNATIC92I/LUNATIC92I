import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { can } from "@/types/auth";

interface NavItem {
  label: string;
  to: string;
  /** Hidden entirely when the caller lacks this — cosmetic only (spec §19);
   * the destination route and every API call under it are still gated
   * server-side regardless of what shows in this list. */
  requires?: { resource: string; action: string };
}

const NAV_ITEMS: NavItem[] = [
  { label: "SOC Overview", to: "/" },
  { label: "Alerts", to: "/alerts", requires: { resource: "alert", action: "read" } },
  { label: "Incidents", to: "/incidents", requires: { resource: "incident", action: "read" } },
  // Event Explorer has no API of its own — it browses events through
  // POST /hunting/search like Threat Hunting does, so it needs the same
  // `hunt:execute` permission that endpoint is gated on, not `event:read`
  // (a role can hold one without the other — READ_ONLY is exactly that
  // case: `event:read` but no `hunt:execute`).
  { label: "Event Explorer", to: "/events", requires: { resource: "hunt", action: "execute" } },
  { label: "Threat Hunting", to: "/hunting", requires: { resource: "hunt", action: "read" } },
  { label: "MITRE ATT&CK", to: "/mitre", requires: { resource: "mitre", action: "read" } },
  { label: "Threat Intelligence", to: "/threat-intel", requires: { resource: "ioc", action: "read" } },
  { label: "Assets", to: "/assets", requires: { resource: "asset", action: "read" } },
  { label: "Users", to: "/users", requires: { resource: "user", action: "read" } },
  { label: "Detection Rules", to: "/rules", requires: { resource: "rule", action: "read" } },
  { label: "Playbooks", to: "/playbooks", requires: { resource: "playbook", action: "read" } },
  { label: "Reports", to: "/reports" },
  { label: "Audit", to: "/audit", requires: { resource: "audit", action: "read" } },
  { label: "Administration", to: "/administration", requires: { resource: "organization", action: "read" } },
];

export function AppShell() {
  const { user, logout } = useAuth();
  const visibleItems = NAV_ITEMS.filter(
    (item) => !item.requires || can(user, item.requires.resource, item.requires.action),
  );

  return (
    <div className="min-h-screen bg-surface text-slate-100 flex">
      <aside className="w-64 shrink-0 border-r border-slate-800 bg-surface-raised flex flex-col">
        <div className="p-4 border-b border-slate-800">
          <p className="font-semibold tracking-tight">LUNATIC-IT SIEM</p>
          <p className="text-xs text-slate-500">Detect. Investigate. Respond.</p>
        </div>
        <nav className="flex-1 overflow-y-auto py-2">
          {visibleItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `block px-4 py-2 text-sm rounded-none border-l-2 ${
                  isActive
                    ? "border-l-blue-500 bg-surface text-slate-50"
                    : "border-l-transparent text-slate-400 hover:text-slate-100 hover:bg-surface/60"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-slate-800 text-sm">
          <p className="truncate text-slate-300">{user?.full_name}</p>
          <p className="truncate text-xs text-slate-500">{user?.roles.join(", ")}</p>
          <button
            type="button"
            onClick={() => void logout()}
            className="mt-2 text-xs text-slate-400 hover:text-slate-100 underline"
          >
            Sign out
          </button>
        </div>
      </aside>
      <main className="flex-1 min-w-0 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
