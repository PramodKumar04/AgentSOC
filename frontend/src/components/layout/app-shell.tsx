import { useQuery } from "@tanstack/react-query";
import {
  Activity, BrainCircuit, Cable, ChevronRight, Database, FileSearch, LayoutDashboard, LogOut, Menu,
  PanelLeftClose, PanelLeftOpen, ShieldAlert, ShieldCheck, UserRound, Users, X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router";

import { ProvenanceBadge } from "@/components/domain";
import { Select } from "@/components/ui/form";
import { ErrorState, LoadingBlock } from "@/components/ui/states";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";
import { useSource } from "./source-context";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/investigations", label: "Investigations", icon: BrainCircuit },
  { to: "/evidence", label: "Evidence Explorer", icon: FileSearch },
  { to: "/data-sources", label: "Data Sources", icon: Database },
  { to: "/activity", label: "System Activity", icon: Activity },
  { to: "/admin/connections", label: "Database Connections", icon: Cable, adminOnly: true },
  { to: "/admin/users", label: "Users", icon: Users, adminOnly: true },
];
const OTHER_SECTIONS: Record<string, string> = { account: "Your account", admin: "Administration" };

const COLLAPSE_KEY = "agentsoc.sidebar.collapsed";

function useHealth() {
  return useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 30_000, retry: 1 });
}

function Sidebar({ collapsed, onToggle, mobileOpen, onClose }: {
  collapsed: boolean; onToggle: () => void; mobileOpen: boolean; onClose: () => void;
}) {
  const health = useHealth();
  const { session, signOut } = useAuth();
  const nav = NAV.filter((n) => !n.adminOnly || session?.user.role === "admin");
  return (
    <>
      {mobileOpen && <div className="fixed inset-0 z-30 bg-ink/40 lg:hidden" onClick={onClose} aria-hidden />}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex flex-col bg-sidebar text-sidebar-text transition-[width,transform] duration-200",
          collapsed ? "lg:w-16" : "lg:w-60", "w-64",
          mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0",
        )}
        aria-label="Sidebar"
      >
        <div className="flex h-14 items-center gap-2.5 border-b border-sidebar-line px-4">
          <div className="flex size-8 shrink-0 items-center justify-center rounded-md bg-brand/15 text-blue-400">
            <ShieldCheck className="size-5" aria-hidden />
          </div>
          {!collapsed && (
            <div className="min-w-0 leading-tight">
              <div className="text-[15px] font-semibold tracking-tight text-white">AgentSOC</div>
              <div className="truncate text-[11px] text-sidebar-muted">Incident Investigation</div>
            </div>
          )}
          <button className="ml-auto rounded p-1 text-sidebar-muted hover:text-white lg:hidden" onClick={onClose} aria-label="Close navigation">
            <X className="size-4" />
          </button>
        </div>

        <nav aria-label="Primary" className="flex-1 space-y-0.5 px-2.5 py-4">
          {nav.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to} to={to} end={end} onClick={onClose} title={collapsed ? label : undefined}
              className={({ isActive }) => cn(
                "group relative flex h-9 items-center gap-3 rounded-md px-2.5 text-[13px] font-medium transition-colors",
                isActive ? "bg-sidebar-2 text-white" : "text-sidebar-text/85 hover:bg-sidebar-2/60 hover:text-white",
                collapsed && "lg:justify-center lg:px-0",
              )}
            >
              {({ isActive }) => (
                <>
                  {isActive && <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-blue-400" aria-hidden />}
                  <Icon className={cn("size-[18px] shrink-0", isActive ? "text-blue-400" : "text-sidebar-muted group-hover:text-sidebar-text")} aria-hidden />
                  <span className={cn(collapsed && "lg:sr-only")}>{label}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-sidebar-line p-2.5">
          <div className={cn("flex items-center gap-2.5 rounded-md px-2 py-2", collapsed && "lg:justify-center lg:px-0")}>
            <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-sidebar-2 text-sidebar-text">
              <UserRound className="size-4" aria-hidden />
            </div>
            {!collapsed && (
              <Link to="/account" onClick={onClose} className="min-w-0 flex-1 leading-tight hover:underline">
                <div className="truncate text-[13px] font-medium text-white">{session?.user.username}</div>
                <div className="truncate text-[11px] text-sidebar-muted">{session?.user.role === "admin" ? "Administrator" : "Analyst"}</div>
              </Link>
            )}
            <button type="button" onClick={() => void signOut()} title="Sign out" aria-label="Sign out"
              className="rounded p-1 text-sidebar-muted hover:text-white">
              <LogOut className="size-4" aria-hidden />
            </button>
          </div>
          <div className={cn("mt-1 flex items-center justify-between px-2 text-[11px] text-sidebar-muted", collapsed && "lg:justify-center")}>
            {!collapsed && <span>v{health.data?.version ?? "—"}</span>}
            <button
              onClick={onToggle}
              className="hidden rounded p-1 hover:text-white lg:inline-flex"
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}

function crumbsFor(pathname: string) {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 0) return [{ label: "Overview" }];
  const section = NAV.find((n) => n.to === `/${parts[0]}`) ?? NAV.find((n) => n.to === pathname);
  if (section && section.to === pathname && parts.length > 1) return [{ label: section.label }];
  const label = section?.label ?? OTHER_SECTIONS[parts[0]] ?? "Not found";
  const crumbs: { label: string; to?: string }[] = [{ label, to: parts.length > 1 ? `/${parts[0]}` : undefined }];
  if (parts[1]) crumbs.push({ label: decodeURIComponent(parts[1]) });
  return crumbs;
}

function StatusIndicator() {
  const health = useHealth();
  const state = health.isError ? "offline" : !health.data ? "checking"
    : health.data.analysis === "available" ? "operational" : "limited";
  const meta = {
    operational: { dot: "bg-ok", text: "Operational", hint: "API reachable; automated analysis configured." },
    limited: { dot: "bg-medium", text: "Limited analysis", hint: "API reachable; investigations use deterministic analysis." },
    offline: { dot: "bg-critical", text: "Service offline", hint: "The AgentSOC API is not responding." },
    checking: { dot: "bg-faint", text: "Checking…", hint: "Contacting the AgentSOC API." },
  }[state];
  return (
    <div className="flex items-center gap-2 text-xs text-muted" title={meta.hint} role="status">
      <span className={cn("size-2 rounded-full", meta.dot)} aria-hidden />
      <span className="hidden sm:inline">{meta.text}</span>
    </div>
  );
}

function Header({ onMenu }: { onMenu: () => void }) {
  const { pathname } = useLocation();
  const { sources, source, setSource } = useSource();
  const crumbs = crumbsFor(pathname);
  return (
    <header className="sticky top-0 z-20 flex h-14 min-w-0 items-center gap-3 border-b border-border bg-surface/95 px-4 backdrop-blur lg:px-6">
      <button className="rounded p-1.5 text-muted hover:bg-subtle lg:hidden" onClick={onMenu} aria-label="Open navigation">
        <Menu className="size-5" />
      </button>
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
        {crumbs.map((c, i) => (
          <span key={i} className="flex min-w-0 items-center gap-1.5">
            {i > 0 && <ChevronRight className="size-3.5 shrink-0 text-faint" aria-hidden />}
            {c.to ? (
              <Link to={c.to} className="text-muted hover:text-ink">{c.label}</Link>
            ) : (
              <span className="max-w-[40vw] truncate font-semibold text-ink sm:max-w-none" aria-current="page">{c.label}</span>
            )}
          </span>
        ))}
      </nav>
      <div className="ml-auto flex items-center gap-4">
        {source && (
          <div className="hidden items-center gap-2 md:flex">
            <ProvenanceBadge provenance={source.provenance} />
            <label className="sr-only" htmlFor="source-select">Data source</label>
            <Select id="source-select" value={source.key} onChange={(e) => setSource(e.target.value)} className="h-8 max-w-[15rem] text-xs sm:max-w-xs">
              {sources.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
            </Select>
          </div>
        )}
        <StatusIndicator />
      </div>
    </header>
  );
}

export function AppShell() {
  const [collapsed, setCollapsed] = useState(() => {
    try { return window.localStorage.getItem(COLLAPSE_KEY) === "1"; } catch { return false; }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const { source, isLoading, error, refetch } = useSource();
  const { pathname } = useLocation();
  useEffect(() => setMobileOpen(false), [pathname]);

  const toggle = () => setCollapsed((c) => {
    try { window.localStorage.setItem(COLLAPSE_KEY, c ? "0" : "1"); } catch { /* ignore */ }
    return !c;
  });

  return (
    <div className="min-h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">
        Skip to content
      </a>
      <Sidebar collapsed={collapsed} onToggle={toggle} mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />
      <div className={cn("transition-[padding] duration-200", collapsed ? "lg:pl-16" : "lg:pl-60")}>
        <Header onMenu={() => setMobileOpen(true)} />
        <main id="main" className="mx-auto max-w-[1400px] px-4 py-6 lg:px-8">
          {isLoading ? <LoadingBlock label="Connecting to AgentSOC…" />
            : error || !source ? <ErrorState error={error} onRetry={refetch} />
            : <Outlet />}
        </main>
      </div>
    </div>
  );
}

export function PageHeader({ title, description, actions }: {
  title: string; description?: React.ReactNode; actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted">{description}</p>}
      </div>
      {actions}
    </div>
  );
}
