import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-semibold leading-4 tracking-wide whitespace-nowrap",
  {
    variants: {
      tone: {
        critical: "border-critical/25 bg-critical-soft text-critical",
        high: "border-high/25 bg-high-soft text-high",
        medium: "border-medium/30 bg-medium-soft text-medium",
        low: "border-low/25 bg-low-soft text-low",
        ok: "border-ok/25 bg-ok-soft text-ok",
        warn: "border-warn/25 bg-warn-soft text-warn",
        brand: "border-brand/20 bg-brand-soft text-brand",
        synthetic: "border-synthetic/25 bg-synthetic-soft text-synthetic",
        real: "border-real/25 bg-real-soft text-real",
        neutral: "border-border bg-subtle text-ink-2",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
