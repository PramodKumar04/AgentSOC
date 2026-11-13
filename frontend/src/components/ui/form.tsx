import { forwardRef, type InputHTMLAttributes, type SelectHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

const field =
  "h-9 rounded-md border border-border bg-surface px-3 text-sm text-ink placeholder:text-faint focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 focus-visible:border-brand";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => <input ref={ref} className={cn(field, className)} {...props} />,
);
Input.displayName = "Input";

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...props }, ref) => (
    <select ref={ref} className={cn(field, "pr-8", className)} {...props}>
      {children}
    </select>
  ),
);
Select.displayName = "Select";
