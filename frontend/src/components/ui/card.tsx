import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/utils";

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("rounded-[var(--radius-card)] border border-border bg-surface shadow-[var(--shadow-card)]", className)}
      {...props}
    />
  );
}

export function CardHeader({ title, description, action, className }: {
  title: ReactNode; description?: ReactNode; action?: ReactNode; className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-4 border-b border-border px-5 py-3.5", className)}>
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {description && <p className="mt-0.5 text-xs text-muted">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function CardBody({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 py-4", className)} {...props} />;
}
