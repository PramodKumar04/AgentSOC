import { AlertTriangle, Inbox, Loader2, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";

import { ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button } from "./button";

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded-md bg-border/60", className)} aria-hidden />;
}

export function LoadingBlock({ label = "Loading…", className }: { label?: string; className?: string }) {
  return (
    <div role="status" className={cn("flex items-center justify-center gap-2 py-12 text-sm text-muted", className)}>
      <Loader2 className="size-4 animate-spin" aria-hidden />
      {label}
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: {
  error: unknown; onRetry?: () => void; className?: string;
}) {
  const offline = error instanceof ApiError && error.status === 0;
  const message = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div role="alert" className={cn("flex flex-col items-center gap-3 py-12 text-center", className)}>
      <AlertTriangle className="size-6 text-warn" aria-hidden />
      <div>
        <p className="font-medium text-ink">{offline ? "AgentSOC service unavailable" : "Could not load data"}</p>
        <p className="mt-1 max-w-md text-sm text-muted">
          {offline ? "The backend API is not responding. Start it and try again." : message}
        </p>
      </div>
      {onRetry && (
        <Button size="sm" onClick={onRetry}><RefreshCw aria-hidden />Retry</Button>
      )}
    </div>
  );
}

export function EmptyState({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-center">
      {icon ?? <Inbox className="size-6 text-faint" aria-hidden />}
      <p className="font-medium text-ink">{title}</p>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}
